use crate::args::Args;
use crate::ports::SocksPorts;
use crate::telegram::Notifier;
use anyhow::{Context, Result};
use futures::stream::{FuturesUnordered, StreamExt};
use remnawave_healthcheck_core::keys::CheckKey;
use remnawave_healthcheck_core::model::{Channel, CheckResult, Node, Severity, Snapshot};
use remnawave_healthcheck_core::report::Outcome;
use remnawave_healthcheck_core::{checks, report, state, topology};
use remnawave_healthcheck_panel::{short_uuid_from_url, PanelClient};
use remnawave_healthcheck_probe as probe;
use remnawave_healthcheck_ssh as node_ssh;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

pub async fn run(args: Args) -> Result<Outcome> {
    // Answered before a run is built at all: this mode sends one message and exits, so holding
    // it to the flags a run needs — a port range that adds up, above all — would refuse the one
    // command whose whole purpose is to work when the rest of the configuration does not.
    if args.test_alert {
        return test_alert(&args).await;
    }
    Run::new(args)?.execute().await
}

/// One run of the tool, with the flag combinations that cannot work already ruled out.
///
/// Everything here is settled once, at construction: nothing further down asks again whether the
/// ports fit or whether Telegram is configured, because neither question can still be open by
/// then — a `Run` that exists is one whose flags agreed with each other.
struct Run {
    args: Args,
    ports: SocksPorts,
    notifier: Option<Notifier>,
}

impl Run {
    fn new(args: Args) -> Result<Self> {
        let ports = SocksPorts::new(args.socks_base_port, args.concurrency)?;
        let notifier = Notifier::new(
            args.telegram_bot_token.as_deref(),
            args.telegram_chat_id.as_deref(),
            args.telegram_thread_id.as_deref(),
        );
        Ok(Self {
            args,
            ports,
            notifier,
        })
    }

    async fn execute(&self) -> Result<Outcome> {
        let args = &self.args;
        let short_uuid = short_uuid_from_url(&args.subscription_url)
            .context("subscription URL has no shortUuid in its last path segment")?;
        let client = PanelClient::new(&args.panel_url, &args.api_token)?;
        let snapshot = match client
            .snapshot(short_uuid)
            .await
            .context("reading the panel")
        {
            Ok(snapshot) => snapshot,
            Err(e) => return self.panel_unreadable(e).await,
        };

        let mut results = Vec::new();
        results.extend(checks::node_status(&snapshot.nodes));
        results.push(checks::subscription_coverage(&snapshot));
        results.extend(checks::monitoring_coverage(&snapshot));
        results.push(checks::xray_version_drift(&snapshot.nodes));

        let mut egress: HashMap<String, IpAddr> = HashMap::new();
        if !args.no_ssh {
            let (node_results, addresses) = self.node_checks(&snapshot).await;
            results.extend(node_results);
            egress = addresses;
        }

        if !args.no_channels {
            results.extend(self.channel_checks(&snapshot, &egress).await);
        }

        print!("{}", report::render(&results));

        // A partial run (some check family was not evaluated) must not touch history: `results`
        // here is not "everything is fine", it is "everything we looked at is fine". Writing it
        // as the new state would erase the unevaluated family's problems from the problem set,
        // and the diff would report them as recovered even though nothing about them actually
        // changed — and the following full run would then report them as new all over again.
        // Such runs still print the report and carry the right exit code; they just leave state
        // and Telegram alone.
        if let Some(reason) = self.partial_run_reason(&results) {
            eprintln!("[state] {reason}: state file and Telegram notification skipped");
            return Ok(report::outcome(&results));
        }

        let current = state::problem_set(&results);
        let previous_raw = match classify_state_read(
            std::fs::read_to_string(&args.state_file),
            &args.state_file,
        ) {
            StateFileRead::Content(s) => s,
            StateFileRead::FirstRun => String::new(),
            StateFileRead::Unreadable(msg) => {
                eprintln!("[state] {msg}");
                String::new()
            }
        };
        let previous = state::from_json(&previous_raw);
        let diff = state::diff(&current, &previous);
        if !diff.is_empty() && self.notify(&diff).await == Delivery::Failed {
            // The change was detected but nobody was told. Writing it into the state file now
            // would mark it "already known" and it would never appear in a diff again — one
            // network blip would swallow the alert for good. Leaving the file alone costs a
            // repeated alert next run, which is the harmless direction of the trade.
            eprintln!(
                "[state] the alert could not be delivered: state file left untouched so the change is reported again next run"
            );
            return Ok(report::outcome(&results));
        }
        std::fs::write(&args.state_file, state::to_json(&current))
            .with_context(|| format!("writing {}", args.state_file.display()))?;

        Ok(report::outcome(&results))
    }
}

impl Run {
    /// Why this run must not be treated as a full picture of the installation, if it must not.
    ///
    /// Skipping a family by flag is one way; the other is `channel_checks` failing before it
    /// could probe anything, which leaves a single `channels:setup` failure in place of every
    /// `channel:*` result. Both look identical to the state file — a pile of keys that simply
    /// are not there — and both would otherwise be written as the new truth, turning every
    /// previously failing channel into a RECOVERED notification about a channel nobody looked
    /// at.
    fn partial_run_reason(&self, results: &[CheckResult]) -> Option<&'static str> {
        if self.args.no_ssh || self.args.no_channels {
            return Some("partial run (--no-ssh or --no-channels given)");
        }
        let setup_failed = results
            .iter()
            .any(|r| r.key == CheckKey::ChannelSetup.key() && r.severity == Severity::Fail);
        setup_failed
            .then_some("partial run (channel probing could not start, so no channel was checked)")
    }
}

impl Run {
    /// The panel is the only source of truth this tool has, so a failure to read it means
    /// nothing at all was checked — and it is the loudest failure there is: panel down, token
    /// revoked, DNS gone. Letting it end the process on stderr alone would silence the alerting
    /// channel at exactly the moment it matters, so the reason goes to Telegram directly,
    /// bypassing the diff. State is left untouched: overwriting it here would make the next
    /// successful run announce every still-broken check as RECOVERED.
    async fn panel_unreadable(&self, err: anyhow::Error) -> Result<Outcome> {
        let Some(notifier) = &self.notifier else {
            // Nowhere to send it — behave exactly as before and let `main` report on stderr.
            return Err(err);
        };
        let mut text = format!(
            "\u{1F534} <b>Healthcheck</b>\nthe panel could not be read, so nothing was checked\n{}",
            state::escape_html(&format!("{err:#}"))
        );
        if let Some(url) = self.args.run_url.as_deref() {
            text.push_str(&format!("\n\n{url}"));
        }
        let sent = notifier.send(&text).await;
        eprintln!("healthcheck failed: {err:#}");
        eprintln!(
            "[alert] panel unreadable → telegram {}",
            delivery_label(sent)
        );
        Ok(Outcome::Aborted)
    }
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

impl Run {
    /// Node-side checks; also returns each node's own egress address, which is what channel exits
    /// are compared against.
    async fn node_checks(
        &self,
        snapshot: &Snapshot,
    ) -> (Vec<CheckResult>, HashMap<String, IpAddr>) {
        let args = &self.args;
        let now = chrono::Utc::now();
        let mut pending = FuturesUnordered::new();
        for node in snapshot.nodes.iter().filter(|n| n.is_enabled()) {
            pending.push(async move {
                // An address that is not an IP is also the TLS endpoint worth inspecting.
                let domain = node
                    .address
                    .parse::<IpAddr>()
                    .is_err()
                    .then_some(node.address.as_str());
                let facts = node_ssh::gather(&node.address, domain, &args.echo_url).await;
                (node, facts)
            });
        }

        let mut results = Vec::new();
        let mut egress = HashMap::new();
        while let Some((node, facts)) = pending.next().await {
            if let Some(ip) = facts.egress_address() {
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
}

impl Run {
    /// Probe every channel the monitoring user can see. Channels of a node the panel reports as
    /// disabled are skipped: `node_status` already said why, and a pile of red would only bury it.
    ///
    /// Never propagates an error out of the run: a setup failure here (no node reported an Xray
    /// version, or the binary could not be downloaded) becomes one `Fail` result instead of
    /// aborting before the report is printed and before Telegram is notified. A mass infra
    /// outage is exactly the moment nodes disagree on their version or GitHub is unreachable —
    /// the report must still go out for everything else that was already checked (node status,
    /// subscription coverage, monitoring coverage, version drift, all SSH results).
    async fn channel_checks(
        &self,
        snapshot: &Snapshot,
        egress: &HashMap<String, IpAddr>,
    ) -> Vec<CheckResult> {
        let args = &self.args;
        let Some(version) = required_xray_version(snapshot) else {
            return setup_failed("no node reported an Xray version, so no binary can be chosen");
        };
        let binary = match probe::xray::ensure(&version, &args.xray_cache).await {
            Ok(b) => b,
            Err(e) => return setup_failed(format!("obtaining xray {version}: {e:#}")),
        };
        let mut results = Vec::new();
        let timeout = Duration::from_secs(args.probe_timeout_secs);

        for chunk in snapshot.channels.chunks(self.ports.concurrency()) {
            let mut pending = FuturesUnordered::new();
            // One port per slot, straight from the range that was proven to hold them: a
            // batch is cut to exactly as many channels as there are ports, so neither side of
            // this can run out.
            for (channel, port) in chunk.iter().zip(self.ports.iter()) {
                let binary = binary.clone();
                let echo_url = args.echo_url.as_str();
                pending.push(async move {
                    // Once per channel: the key identifies this check in the state file, and having
                    // two places build it is how the two spellings drift apart.
                    let key = channel.check_key();
                    let expect = match channel_precheck(&key, channel, snapshot) {
                        Precheck::Probe(expect) => expect,
                        Precheck::Decided(decided) => return decided,
                    };

                    let config = probe::config::build(&channel.outbound, port);
                    let mut outcome = probe::probe(&binary, &config, port, timeout, echo_url).await;
                    // Retry only a dead tunnel: no exit at all is the common single blip. A wrong
                    // exit is deterministic — the outbound config does not change between the two
                    // calls — so retrying it would only double the timeout on infra that is
                    // genuinely broken, without ever changing the answer.
                    if outcome.exit_ip.is_none() {
                        outcome = probe::probe(&binary, &config, port, timeout, echo_url).await;
                    }
                    probe::classify(
                        &key,
                        &channel.remark,
                        &expect.name,
                        egress.get(&expect.name).copied(),
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
}

/// The one result that stands in for every channel when probing could not be set up.
fn setup_failed(detail: impl Into<String>) -> Vec<CheckResult> {
    vec![CheckResult::new(
        CheckKey::ChannelSetup.key(),
        "channel probing setup",
        Severity::Fail,
        detail,
    )]
}

/// Everything about a channel that can be settled before xray is started: the name of the node it
/// is supposed to exit through, or the finished check result explaining why it cannot be probed.
///
/// The last of those reasons is a channel the panel resolved but the subscription never served.
/// Its outbound is `Value::Null`, and handing that to the config builder produces a config xray
/// refuses to start — the channel would then be reported as "no exit (tunnel dead)", after two
/// full probe timeouts, pointing the reader at the tunnel instead of at the subscription.
fn channel_precheck<'a>(key: &str, channel: &Channel, snapshot: &'a Snapshot) -> Precheck<'a> {
    let decided = |severity, detail: String| {
        Precheck::Decided(CheckResult::new(
            key,
            channel.remark.clone(),
            severity,
            detail,
        ))
    };

    let expect = match topology::Resolver::new(snapshot).exit_of(channel) {
        Ok(expect) => expect,
        Err(e) => {
            return decided(
                Severity::Fail,
                format!("cannot tell where this channel should exit: {e}"),
            )
        }
    };
    if !expect.is_enabled() {
        return decided(
            Severity::Warn,
            format!("expected exit '{}' is disabled in the panel", expect.name),
        );
    }
    if channel.outbound.is_null() {
        return decided(
            Severity::Fail,
            "the panel resolved this channel but the subscription served no config for it, so there is nothing to probe".to_string(),
        );
    }
    Precheck::Probe(expect)
}

/// The two ways a channel's pre-probe examination can end. Not a `Result`: neither outcome is an
/// error, and a reader who sees `Err` here would look for one.
#[derive(Debug)]
enum Precheck<'a> {
    /// Nothing stands in the way. Carries the node the channel must exit through.
    Probe(&'a Node),
    /// The channel is not to be probed, and this is the finished result saying why.
    Decided(CheckResult),
}

/// The version the nodes are actually running. When they disagree, `xray:version-drift` has
/// already warned; probing uses the most common one so the client side matches the majority.
fn required_xray_version(snapshot: &Snapshot) -> Option<String> {
    let mut tally: HashMap<&str, usize> = HashMap::new();
    for version in snapshot
        .nodes
        .iter()
        .filter(|n| n.is_enabled())
        .filter_map(|n| n.xray_version.as_deref())
    {
        *tally.entry(version).or_default() += 1;
    }
    tally
        .into_iter()
        .max_by_key(|&(version, count)| (count, version))
        .map(|(version, _)| version.to_string())
}

/// How a delivery attempt reads on stderr. The parenthetical points at the line `telegram::send`
/// printed just above, which carries the API's own reason for the refusal.
fn delivery_label(sent: bool) -> &'static str {
    if sent {
        "sent"
    } else {
        "FAILED (see the line above)"
    }
}

/// What became of an alert. `NotConfigured` is not a failure: running without Telegram
/// credentials is a deliberate configuration, and it must not hold the state file hostage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Delivery {
    Sent,
    Failed,
    NotConfigured,
}

impl Run {
    async fn notify(&self, diff: &state::Diff) -> Delivery {
        // Counted once: the two branches below report the same three numbers, and only differ in
        // whether there was anywhere to send them.
        let counted = format!(
            "{} new / {} worse / {} recovered",
            diff.new.len(),
            diff.escalated.len(),
            diff.recovered.len()
        );
        let Some(notifier) = &self.notifier else {
            eprintln!("[alert] {counted}, but no Telegram credentials were given");
            return Delivery::NotConfigured;
        };
        let message = state::format_message(diff, self.args.run_url.as_deref());
        let sent = notifier.send(&message).await;
        eprintln!("[alert] {counted} → telegram {}", delivery_label(sent));
        if sent {
            Delivery::Sent
        } else {
            Delivery::Failed
        }
    }
}

async fn test_alert(args: &Args) -> Result<Outcome> {
    let Some(notifier) = Notifier::new(
        args.telegram_bot_token.as_deref(),
        args.telegram_chat_id.as_deref(),
        args.telegram_thread_id.as_deref(),
    ) else {
        eprintln!("[alert] TEST: no Telegram bot token or chat id given");
        return Ok(Outcome::Aborted);
    };
    let sent = notifier
        .send("\u{2705} healthcheck: alert delivery test (safe to ignore)")
        .await;
    eprintln!(
        "[alert] TEST: delivery {}",
        if sent { "OK" } else { "FAILED" }
    );
    Ok(if sent { Outcome::Ok } else { Outcome::Failed })
}

#[cfg(test)]
mod tests {
    use super::*;
    use remnawave_healthcheck_core::model::Profile;
    use serde_json::json;
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
            is_connecting: false,
            last_status_message: None,
            xray_version: version.map(String::from),
        }
    }

    fn snapshot(nodes: Vec<Node>) -> Snapshot {
        Snapshot {
            nodes,
            profiles: HashMap::new(),
            channels: vec![],
            served_remarks: Vec::new(),
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
            echo_url: "https://echo.example.com".parse().unwrap(),
        }
    }

    /// One exit node with a plain freedom profile, plus one channel pointing at it.
    fn resolvable_snapshot(outbound: serde_json::Value) -> Snapshot {
        let mut node = node("beta", false, Some("26.6.27"));
        node.address = "beta.example.com".into();
        node.inbound_tags = vec!["in-exit".into()];
        node.profile_uuid = Some("p-exit".into());
        let profile = Profile {
            uuid: "p-exit".into(),
            name: "exit".into(),
            config: json!({
                "inbounds": [{"tag": "in-exit", "port": 443}],
                "outbounds": [{"tag": "direct", "protocol": "freedom"}]
            }),
        };
        Snapshot {
            nodes: vec![node],
            profiles: HashMap::from([("p-exit".to_string(), profile)]),
            channels: vec![Channel {
                remark: "beta direct".into(),
                inbound_tag: "in-exit".into(),
                profile_uuid: Some("p-exit".into()),
                address: "beta.example.com".into(),
                port: 443,
                outbound,
            }],
            served_remarks: vec!["beta direct".to_string()],
        }
    }

    /// Name of the expected exit node of a channel that is to be probed.
    fn expected_exit(precheck: Precheck<'_>) -> String {
        match precheck {
            Precheck::Probe(expect) => expect.name.clone(),
            Precheck::Decided(decided) => {
                panic!("expected a probeable channel, got {decided:?}")
            }
        }
    }

    /// The finished result of a channel that is not to be probed.
    fn decided(precheck: Precheck<'_>) -> CheckResult {
        match precheck {
            Precheck::Decided(result) => result,
            Precheck::Probe(expect) => panic!("expected a decided channel, got exit {expect:?}"),
        }
    }

    fn precheck_of(snap: &Snapshot) -> Precheck<'_> {
        let channel = &snap.channels[0];
        channel_precheck(&channel.check_key(), channel, snap)
    }

    #[test]
    fn a_probeable_channel_precheck_yields_its_expected_exit() {
        let snap = resolvable_snapshot(json!({"protocol": "vless"}));
        assert_eq!(expected_exit(precheck_of(&snap)), "beta");
    }

    #[test]
    fn a_channel_the_subscription_never_served_fails_without_being_probed() {
        // outbound == null: building a config out of it would make xray refuse to start and the
        // channel would be blamed for a dead tunnel after two full timeouts.
        let snap = resolvable_snapshot(serde_json::Value::Null);
        // A channel with no config must not reach the probe.
        let decided = decided(precheck_of(&snap));
        assert_eq!(decided.severity, Severity::Fail);
        assert!(
            decided.detail.contains("subscription"),
            "the reason must point at the subscription, not at the tunnel: {}",
            decided.detail
        );
        assert!(!decided.detail.contains("tunnel"), "{}", decided.detail);
    }

    #[test]
    fn a_channel_whose_exit_is_disabled_only_warns() {
        // Whether the exit is disabled is now asked of the node the resolver returned, so the
        // node itself is what the test switches off.
        let mut snap = resolvable_snapshot(json!({"protocol": "vless"}));
        snap.nodes[0].is_disabled = true;
        let decided = decided(precheck_of(&snap));
        assert_eq!(decided.severity, Severity::Warn);
        assert!(decided.detail.contains("beta"), "{}", decided.detail);
    }

    #[test]
    fn precheck_results_carry_the_channels_unique_key_and_plain_title() {
        let snap = resolvable_snapshot(serde_json::Value::Null);
        let decided = decided(precheck_of(&snap));
        assert_eq!(decided.key, snap.channels[0].check_key());
        assert_eq!(decided.title, "beta direct");

        // Two channels sharing a remark must not share a key, or one of them would silently
        // disappear from the problem set and therefore from the alert.
        let mut other = snap.channels[0].clone();
        other.address = "gamma.example.com".into();
        assert_ne!(decided.key, other.check_key());
    }

    #[test]
    fn a_failed_probe_setup_makes_the_run_partial() {
        let run = Run::new(test_args()).expect("the test flags agree with each other");
        assert!(run.partial_run_reason(&[]).is_none());

        let setup_failed = vec![CheckResult::new(
            CheckKey::ChannelSetup.key(),
            "channel probing setup",
            Severity::Fail,
            "obtaining xray 26.6.27: connection refused",
        )];
        let reason = run
            .partial_run_reason(&setup_failed)
            .expect("a run that probed no channel is not a full picture");
        assert!(reason.contains("no channel was checked"), "{reason}");
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
    fn a_run_cannot_be_built_from_flags_that_would_share_a_port() {
        // The refusal is the constructor's, and it is the last moment it can be made: past it,
        // nothing in the run has to ask whether a port is real.
        let mut args = test_args();
        args.socks_base_port = 65530;
        args.concurrency = 100;
        let Err(err) = Run::new(args) else {
            panic!("a base port and a concurrency that overlap the end of the port range");
        };
        assert!(err.to_string().contains("65535"), "{err}");
    }

    #[test]
    fn a_run_without_telegram_credentials_simply_has_no_notifier() {
        let run = Run::new(test_args()).unwrap();
        assert!(run.notifier.is_none());

        let mut args = test_args();
        args.telegram_bot_token = Some("token".into());
        args.telegram_chat_id = Some("chat".into());
        assert!(Run::new(args).unwrap().notifier.is_some());
    }
}
