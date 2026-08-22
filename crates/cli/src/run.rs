use crate::args::Args;
use crate::telegram;
use anyhow::{Context, Result};
use futures::stream::{FuturesUnordered, StreamExt};
use remnawave_healthcheck_core::model::{CheckResult, Severity, Snapshot};
use remnawave_healthcheck_core::{checks, report, state, topology};
use remnawave_healthcheck_panel::{short_uuid_from_url, PanelClient};
use remnawave_healthcheck_probe as probe;
use remnawave_healthcheck_ssh as node_ssh;
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

pub async fn run(args: Args) -> Result<i32> {
    if args.test_alert {
        return test_alert(&args).await;
    }
    validate_socks_port_range(&args)?;

    let short_uuid = short_uuid_from_url(&args.subscription_url)
        .context("subscription URL has no shortUuid in its last path segment")?;
    let client = PanelClient::new(&args.panel_url, &args.api_token)?;
    let snapshot = client
        .snapshot(&short_uuid)
        .await
        .context("reading the panel")?;

    let mut results = Vec::new();
    results.extend(checks::node_status(&snapshot.nodes));
    results.push(checks::subscription_coverage(&snapshot));
    results.extend(checks::monitoring_coverage(&snapshot));
    results.push(checks::xray_version_drift(&snapshot.nodes));

    let mut egress: HashMap<String, String> = HashMap::new();
    if !args.no_ssh {
        let (node_results, addresses) = node_checks(&args, &snapshot).await;
        results.extend(node_results);
        egress = addresses;
    }

    if !args.no_channels {
        results.extend(channel_checks(&args, &snapshot, &egress).await);
    }

    print!("{}", report::render(&results));

    // A partial run (some check family skipped) must not touch history: `results` here is not
    // "everything is fine", it is "everything we looked at is fine". Writing it as the new state
    // would erase the skipped family's problems from the problem set, and the diff would report
    // them as recovered even though nothing about them actually changed — and the following full
    // run would then report them as new all over again. Diagnostic runs (`--no-ssh`,
    // `--no-channels`) still print the report and carry the right exit code; they just leave
    // state and Telegram alone.
    if args.no_ssh || args.no_channels {
        eprintln!(
            "[state] partial run (--no-ssh or --no-channels given): state file and Telegram notification skipped"
        );
        return Ok(report::exit_code(&results));
    }

    let current = state::problem_set(&results);
    let previous_raw =
        match classify_state_read(std::fs::read_to_string(&args.state_file), &args.state_file) {
            StateFileRead::Content(s) => s,
            StateFileRead::FirstRun => String::new(),
            StateFileRead::Unreadable(msg) => {
                eprintln!("[state] {msg}");
                String::new()
            }
        };
    let previous = state::from_json(&previous_raw);
    let diff = state::diff(&current, &previous);
    if !diff.is_empty() {
        notify(&args, &diff).await;
    }
    std::fs::write(&args.state_file, state::to_json(&current))
        .with_context(|| format!("writing {}", args.state_file.display()))?;

    Ok(report::exit_code(&results))
}

/// `socks_base_port + concurrency` must fit under the last TCP port, or two channels probed in
/// the same batch would be handed the same SOCKS port. The second xray would then fail to bind
/// and the channel would report a misleading "no exit (tunnel dead)" instead of the real cause.
fn validate_socks_port_range(args: &Args) -> Result<()> {
    let concurrency = args.concurrency.max(1);
    // u64 throughout: concurrency is usize and could in principle exceed u32::MAX, and this must
    // never panic on overflow — it exists to turn a bad combination into a clear error, not a crash.
    let span = u64::try_from(concurrency).unwrap_or(u64::MAX);
    let highest = u64::from(args.socks_base_port)
        .saturating_add(span)
        .saturating_sub(1);
    anyhow::ensure!(
        highest <= u64::from(u16::MAX),
        "--socks-base-port {} plus --concurrency {} would need a port above 65535 ({highest}); lower one of them",
        args.socks_base_port,
        args.concurrency
    );
    Ok(())
}

/// Content of the previous run's state file, read result classified. Distinguishing "no file
/// yet" from "file exists but could not be read" matters: a corrupt or permission-denied state
/// file must not look identical to a first run in the logs, it deserves a stderr line.
#[derive(Debug)]
enum StateFileRead {
    FirstRun,
    Unreadable(String),
    Content(String),
}

fn classify_state_read(result: std::io::Result<String>, path: &Path) -> StateFileRead {
    match result {
        Ok(s) => StateFileRead::Content(s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => StateFileRead::FirstRun,
        Err(e) => StateFileRead::Unreadable(format!("could not read {}: {e}", path.display())),
    }
}

/// Node-side checks; also returns each node's own egress address, which is what channel exits
/// are compared against.
async fn node_checks(
    args: &Args,
    snapshot: &Snapshot,
) -> (Vec<CheckResult>, HashMap<String, String>) {
    let now = chrono::Utc::now();
    let mut pending = FuturesUnordered::new();
    for node in snapshot.nodes.iter().filter(|n| !n.is_disabled) {
        pending.push(async move {
            // An address that is not an IP is also the TLS endpoint worth inspecting.
            let domain = node
                .address
                .parse::<std::net::IpAddr>()
                .err()
                .map(|_| node.address.as_str());
            let facts = node_ssh::gather(&node.address, domain).await;
            (node, facts)
        });
    }

    let mut results = Vec::new();
    let mut egress = HashMap::new();
    while let Some((node, facts)) = pending.next().await {
        if let Some(ip) = node_ssh::egress_ip(&facts) {
            egress.insert(node.name.clone(), ip);
        }
        results.extend(node_ssh::check_host(
            node,
            &facts,
            now,
            args.cert_warn_days,
            args.config_warn_days,
        ));
    }
    (results, egress)
}

/// Probe every channel the monitoring user can see. Channels of a node the panel reports as
/// disabled are skipped: `node_status` already said why, and a pile of red would only bury it.
///
/// Never propagates an error out of the run: a setup failure here (no node reported an Xray
/// version, or the binary could not be downloaded) becomes one `Fail` result instead of aborting
/// before the report is printed and before Telegram is notified. A mass infra outage is exactly
/// the moment nodes disagree on their version or GitHub is unreachable — the report must still
/// go out for everything else that was already checked (node status, subscription coverage,
/// monitoring coverage, version drift, all SSH results).
async fn channel_checks(
    args: &Args,
    snapshot: &Snapshot,
    egress: &HashMap<String, String>,
) -> Vec<CheckResult> {
    let setup_fail = |detail: String| {
        vec![CheckResult::new(
            "channels:setup",
            "channel probing setup",
            Severity::Fail,
            detail,
        )]
    };

    let Some(version) = required_xray_version(snapshot) else {
        return setup_fail(
            "no node reported an Xray version, so no binary can be chosen".to_string(),
        );
    };
    let binary = match probe::xray::ensure(&version, &args.xray_cache).await {
        Ok(b) => b,
        Err(e) => return setup_fail(format!("obtaining xray {version}: {e:#}")),
    };
    let disabled: Vec<&str> = snapshot
        .nodes
        .iter()
        .filter(|n| n.is_disabled)
        .map(|n| n.name.as_str())
        .collect();

    let mut results = Vec::new();
    let timeout = Duration::from_secs(args.probe_timeout_secs);

    for chunk in snapshot.channels.chunks(args.concurrency.max(1)) {
        let mut pending = FuturesUnordered::new();
        // Borrow, not move: `async move` would otherwise consume the list in the first future.
        let disabled = &disabled;
        for (i, channel) in chunk.iter().enumerate() {
            let binary = binary.clone();
            let port = args.socks_base_port.saturating_add(i as u16);
            pending.push(async move {
                let expect = match topology::resolve_exit(channel, snapshot) {
                    Ok(node) => node,
                    Err(e) => {
                        return CheckResult::new(
                            format!("channel:{}", channel.remark),
                            channel.remark.clone(),
                            Severity::Fail,
                            format!("cannot tell where this channel should exit: {e}"),
                        )
                    }
                };
                if disabled.contains(&expect.as_str()) {
                    return CheckResult::new(
                        format!("channel:{}", channel.remark),
                        channel.remark.clone(),
                        Severity::Warn,
                        format!("expected exit '{expect}' is disabled in the panel"),
                    );
                }

                let config = probe::config::build(&channel.outbound, port);
                let mut outcome = probe::probe(&binary, &config, port, timeout).await;
                // Retry only a dead tunnel: no exit at all is the common single blip. A wrong
                // exit is deterministic — the outbound config does not change between the two
                // calls — so retrying it would only double the timeout on infra that is
                // genuinely broken, without ever changing the answer.
                if outcome.exit_ip.is_none() {
                    outcome = probe::probe(&binary, &config, port, timeout).await;
                }
                probe::classify(
                    &channel.remark,
                    &expect,
                    egress.get(&expect).map(String::as_str),
                    &outcome,
                )
            });
        }
        while let Some(result) = pending.next().await {
            results.push(result);
        }
    }
    results
}

/// The version the nodes are actually running. When they disagree, `xray:version-drift` has
/// already warned; probing uses the most common one so the client side matches the majority.
fn required_xray_version(snapshot: &Snapshot) -> Option<String> {
    let mut tally: HashMap<&str, usize> = HashMap::new();
    for version in snapshot
        .nodes
        .iter()
        .filter(|n| !n.is_disabled)
        .filter_map(|n| n.xray_version.as_deref())
    {
        *tally.entry(version).or_default() += 1;
    }
    tally
        .into_iter()
        .max_by_key(|(v, count)| (*count, v.to_string()))
        .map(|(v, _)| v.to_string())
}

async fn notify(args: &Args, diff: &state::Diff) {
    let message = state::format_message(diff, args.run_url.as_deref());
    match (&args.telegram_bot_token, &args.telegram_chat_id) {
        (Some(token), Some(chat)) => {
            let sent =
                telegram::send(token, chat, &message, args.telegram_thread_id.as_deref()).await;
            eprintln!(
                "[alert] {} new / {} worse / {} recovered → telegram {}",
                diff.new.len(),
                diff.escalated.len(),
                diff.recovered.len(),
                if sent {
                    "sent"
                } else {
                    "FAILED (see the line above)"
                }
            );
        }
        _ => eprintln!(
            "[alert] {} new / {} worse / {} recovered, but no Telegram credentials were given",
            diff.new.len(),
            diff.escalated.len(),
            diff.recovered.len()
        ),
    }
}

async fn test_alert(args: &Args) -> Result<i32> {
    let (Some(token), Some(chat)) = (&args.telegram_bot_token, &args.telegram_chat_id) else {
        eprintln!("[alert] TEST: no Telegram bot token or chat id given");
        return Ok(2);
    };
    let sent = telegram::send(
        token,
        chat,
        "\u{2705} healthcheck: alert delivery test (safe to ignore)",
        args.telegram_thread_id.as_deref(),
    )
    .await;
    eprintln!(
        "[alert] TEST: delivery {}",
        if sent { "OK" } else { "FAILED" }
    );
    Ok(if sent { 0 } else { 1 })
}

#[cfg(test)]
mod tests {
    use super::*;
    use remnawave_healthcheck_core::model::Node;
    use std::io::{Error, ErrorKind};

    fn node(name: &str, disabled: bool, version: Option<&str>) -> Node {
        Node {
            name: name.into(),
            address: "192.0.2.1".into(),
            profile_uuid: Some("p".into()),
            inbound_tags: vec![],
            inbound_ports: vec![],
            is_disabled: disabled,
            is_connected: true,
            last_status_message: None,
            xray_version: version.map(String::from),
        }
    }

    fn snapshot(nodes: Vec<Node>) -> Snapshot {
        Snapshot {
            nodes,
            profiles: HashMap::new(),
            channels: vec![],
            served_channel_count: 0,
        }
    }

    fn test_args() -> Args {
        Args {
            panel_url: "https://panel.example.com".into(),
            api_token: "token".into(),
            subscription_url: "https://sub.example.com/abc".into(),
            telegram_bot_token: None,
            telegram_chat_id: None,
            telegram_thread_id: None,
            run_url: None,
            state_file: ".healthcheck-state.json".into(),
            xray_cache: ".xray-cache".into(),
            cert_warn_days: 14,
            config_warn_days: 7,
            no_ssh: false,
            no_channels: false,
            test_alert: false,
            concurrency: 8,
            probe_timeout_secs: 22,
            socks_base_port: 10800,
        }
    }

    #[test]
    fn no_nodes_reporting_a_version_gives_none() {
        assert_eq!(required_xray_version(&snapshot(vec![])), None);
        assert_eq!(
            required_xray_version(&snapshot(vec![node("alpha", false, None)])),
            None
        );
    }

    #[test]
    fn disabled_nodes_are_excluded_from_the_tally() {
        let snap = snapshot(vec![node("alpha", true, Some("26.6.27"))]);
        assert_eq!(required_xray_version(&snap), None);
    }

    #[test]
    fn the_more_common_version_wins_over_a_lone_dissenter() {
        let snap = snapshot(vec![
            node("alpha", false, Some("26.6.27")),
            node("beta", false, Some("26.6.27")),
            node("gamma", false, Some("26.3.27")),
        ]);
        assert_eq!(required_xray_version(&snap).as_deref(), Some("26.6.27"));
    }

    #[test]
    fn missing_state_file_is_a_first_run_not_an_error() {
        let err = Error::new(ErrorKind::NotFound, "nope");
        assert!(matches!(
            classify_state_read(Err(err), Path::new("state.json")),
            StateFileRead::FirstRun
        ));
    }

    #[test]
    fn unreadable_state_file_is_distinguished_from_a_first_run() {
        let err = Error::new(ErrorKind::PermissionDenied, "denied");
        match classify_state_read(Err(err), Path::new("state.json")) {
            StateFileRead::Unreadable(msg) => {
                assert!(msg.contains("state.json"));
                assert!(msg.contains("denied"));
            }
            other => panic!("expected Unreadable, got {other:?}"),
        }
    }

    #[test]
    fn existing_state_file_content_passes_through() {
        let got = classify_state_read(Ok("{}".to_string()), Path::new("state.json"));
        assert!(matches!(got, StateFileRead::Content(s) if s == "{}"));
    }

    #[test]
    fn socks_port_range_within_u16_is_accepted() {
        let mut args = test_args();
        args.socks_base_port = 60000;
        args.concurrency = 100;
        assert!(validate_socks_port_range(&args).is_ok());
    }

    #[test]
    fn socks_port_range_overflowing_u16_is_rejected() {
        let mut args = test_args();
        args.socks_base_port = 65530;
        args.concurrency = 100;
        let err = validate_socks_port_range(&args).unwrap_err();
        assert!(err.to_string().contains("65535"));
    }
}
