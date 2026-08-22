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
use std::time::Duration;

pub async fn run(args: Args) -> Result<i32> {
    if args.test_alert {
        return test_alert(&args).await;
    }

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
        results.extend(channel_checks(&args, &snapshot, &egress).await?);
    }

    print!("{}", report::render(&results));

    let current = state::problem_set(&results);
    let previous = state::from_json(&std::fs::read_to_string(&args.state_file).unwrap_or_default());
    let diff = state::diff(&current, &previous);
    if !diff.is_empty() {
        notify(&args, &diff).await;
    }
    std::fs::write(&args.state_file, state::to_json(&current))
        .with_context(|| format!("writing {}", args.state_file.display()))?;

    Ok(report::exit_code(&results))
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
async fn channel_checks(
    args: &Args,
    snapshot: &Snapshot,
    egress: &HashMap<String, String>,
) -> Result<Vec<CheckResult>> {
    let version = required_xray_version(snapshot)
        .context("no node reported an Xray version, so no binary can be chosen")?;
    let binary = probe::xray::ensure(&version, &args.xray_cache)
        .await
        .with_context(|| format!("obtaining xray {version}"))?;
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
                let mut result = probe::classify(
                    &channel.remark,
                    &expect,
                    egress.get(&expect).map(String::as_str),
                    &outcome,
                );
                // One retry inside the run: single blips are common and not worth an alert.
                if result.severity == Severity::Fail {
                    outcome = probe::probe(&binary, &config, port, timeout).await;
                    result = probe::classify(
                        &channel.remark,
                        &expect,
                        egress.get(&expect).map(String::as_str),
                        &outcome,
                    );
                }
                result
            });
        }
        while let Some(result) = pending.next().await {
            results.push(result);
        }
    }
    Ok(results)
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
