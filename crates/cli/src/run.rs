//! One run: panel → panel checks → (geocheck ∥ ssh ∥ tls ∥ xhttp ∥ tunnels)
//! → classify → report → deliver. Families run concurrently; the tunnels
//! need geocheck's egress addresses only at classification time.

use crate::config::Config;
use crate::telegram::Notifier;
use anyhow::Result;
use chrono::{DateTime, Utc};
use remnawave_healthcheck_core::checks::{self, channel::Precheck};
use remnawave_healthcheck_core::model::{
    CheckResult, GeoOutcome, ProbeOutcome, Snapshot, SshOutcome, TlsFacts,
    XhttpFacts,
};
use remnawave_healthcheck_core::report::{self, Outcome, Report};
use remnawave_healthcheck_io::{PanelClient, SshRunner, probe, tls, xhttp};
use std::collections::HashMap;
use std::io::Write as _;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tracing::{error, info, warn};

pub async fn run(config: Config) -> Result<Outcome> {
    let notifier = config
        .telegram
        .as_ref()
        .map(|t| Notifier::new(&t.bot_token, &t.chat_id, t.thread_id))
        .transpose()?;
    let panel = Arc::new(PanelClient::new(
        &config.panel_url,
        &config.api_token,
        config.panel_timeout,
        config.hwid.clone(),
    )?);
    let snapshot = match panel.snapshot(config.user_id).await {
        Ok(s) => s,
        Err(e) => {
            return panel_unreadable(
                &e,
                notifier.as_ref(),
                config.run_url.as_deref(),
            )
            .await;
        }
    };
    info!(
        nodes = snapshot.nodes.len(),
        channels = snapshot.channels.len(),
        served = snapshot.served_remarks.len(),
        hwid_stub = snapshot.hwid_stub,
        "panel read"
    );
    let now = Utc::now();

    let (geo, ssh, tls, xhttp, probes) = tokio::join!(
        geocheck_all(&panel, &snapshot, &config),
        ssh_all(&snapshot, &config),
        tls_all(&snapshot, &config),
        xhttp_all(&snapshot, &config),
        probe_all(&snapshot, &config),
    );
    let collected = Collected {
        geo,
        ssh,
        tls,
        xhttp,
        probes,
    };
    let results = judge(&snapshot, now, collected, &config);

    let report = Report::of(&results);
    print!("{}", report.table());
    write_step_summary(&results);
    let outcome = report.outcome();
    info!(overall = %report.overall(), checks = results.len(), "run complete");

    match &notifier {
        None => info!("telegram: not configured"),
        Some(n) => {
            let text = report.telegram(config.run_url.as_deref());
            if let Err(e) = n.send(&text).await {
                error!("telegram: {e}");
                return Ok(Outcome::Aborted);
            }
            info!("telegram: sent");
        }
    }
    Ok(outcome)
}

/// Facts of every family, keyed so `judge` can pair them with the snapshot.
struct Collected {
    geo: HashMap<String, GeoOutcome>,
    ssh: HashMap<String, SshOutcome>,
    tls: Vec<(String, TlsFacts)>,
    xhttp: Vec<(usize, XhttpFacts)>,
    probes: ProbeStage,
}

enum ProbeStage {
    Skipped,
    SetupFailed(String),
    Done(Vec<(usize, ProbeResult)>),
}

enum ProbeResult {
    Decided(CheckResult),
    Probed {
        expect: String,
        outcome: ProbeOutcome,
    },
}

/// The address a completed geocheck saw the node leave from. A job that never
/// completed contributes nothing rather than an absent address.
fn done_egress(outcome: &GeoOutcome) -> Option<IpAddr> {
    match outcome {
        GeoOutcome::Done(facts) => facts.egress,
        GeoOutcome::Failed(_) => None,
    }
}

/// Pure: turn the snapshot and the collected facts into results.
fn judge(
    snapshot: &Snapshot,
    now: DateTime<Utc>,
    c: Collected,
    config: &Config,
) -> Vec<CheckResult> {
    let mut results = config.panel_checker.all(snapshot);
    let mut egress: HashMap<&str, IpAddr> = HashMap::new();
    for node in snapshot.nodes.iter().filter(|n| n.is_enabled()) {
        if let Some(out) = c.geo.get(&node.name) {
            if let Some(ip) = done_egress(out) {
                egress.insert(node.name.as_str(), ip);
            }
            results.extend(config.geo_checker.check_node(node, out));
        }
        if let Some(out) = c.ssh.get(&node.name) {
            results.extend(config.ssh_checker.check_node(node, out, now));
        }
    }
    for (host, facts) in &c.tls {
        results.push(checks::tls::check(
            host,
            facts,
            now,
            config.cert_warn_days,
        ));
    }
    for (idx, facts) in &c.xhttp {
        results.push(checks::channel::xhttp(&snapshot.channels[*idx], facts));
    }
    match c.probes {
        ProbeStage::Skipped => {}
        ProbeStage::SetupFailed(detail) => {
            results.push(checks::channel::setup_failed(detail));
        }
        ProbeStage::Done(list) => {
            for (idx, r) in list {
                match r {
                    ProbeResult::Decided(r) => results.push(r),
                    ProbeResult::Probed { expect, outcome } => {
                        let node = snapshot
                            .nodes
                            .iter()
                            .find(|n| n.name == expect)
                            .expect(
                                "the expected exit came out of this snapshot",
                            );
                        let want = egress.get(expect.as_str()).copied();
                        results.push(checks::channel::classify(
                            &snapshot.channels[idx],
                            node,
                            want,
                            &outcome,
                        ));
                    }
                }
            }
        }
    }
    results
}

async fn collect<T: Send + 'static>(mut set: JoinSet<T>) -> Vec<T> {
    let mut out = Vec::new();
    while let Some(r) = set.join_next().await {
        match r {
            Ok(v) => out.push(v),
            // A panicked check must fail the run loudly: a silently
            // missing result would read as green.
            Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
            Err(e) => error!("a task was cancelled: {e}"),
        }
    }
    out
}

async fn geocheck_all(
    panel: &Arc<PanelClient>,
    snapshot: &Snapshot,
    config: &Config,
) -> HashMap<String, GeoOutcome> {
    if config.no_geocheck {
        return HashMap::new();
    }
    let mut set = JoinSet::new();
    for node in snapshot.nodes.iter().filter(|n| n.is_enabled()) {
        let (panel, uuid, name, timeout) = (
            Arc::clone(panel),
            node.uuid.clone(),
            node.name.clone(),
            config.geocheck_timeout,
        );
        set.spawn(async move {
            let started = Instant::now();
            let out = panel.geocheck(&uuid, timeout).await;
            match &out {
                GeoOutcome::Done(_) => info!(node = %name, elapsed = ?started.elapsed(), "geocheck: done"),
                GeoOutcome::Failed(e) => warn!(node = %name, "geocheck: {e}"),
            }
            (name, out)
        });
    }
    collect(set).await.into_iter().collect()
}

async fn ssh_all(
    snapshot: &Snapshot,
    config: &Config,
) -> HashMap<String, SshOutcome> {
    if config.no_ssh {
        return HashMap::new();
    }
    let runner = match SshRunner::new(config.ssh.clone()) {
        Ok(r) => Arc::new(r),
        Err(e) => {
            error!("ssh: {e:#}");
            return HashMap::new();
        }
    };
    let mut set = JoinSet::new();
    for node in snapshot.nodes.iter().filter(|n| n.is_enabled()) {
        let (runner, name, address) =
            (Arc::clone(&runner), node.name.clone(), node.address.clone());
        let domain = node.domain().map(str::to_string);
        set.spawn(async move {
            let started = Instant::now();
            let out = runner.gather(&address, domain.as_deref()).await;
            match &out {
                SshOutcome::Reached(_) => {
                    info!(node = %name, elapsed = ?started.elapsed(), "ssh: ok");
                }
                SshOutcome::Unreachable(e) => warn!(node = %name, "ssh: {e}"),
            }
            (name, out)
        });
    }
    collect(set).await.into_iter().collect()
}

async fn tls_all(
    snapshot: &Snapshot,
    config: &Config,
) -> Vec<(String, TlsFacts)> {
    let mut hosts = vec![snapshot.panel_host.clone()];
    hosts.extend(snapshot.sub_host.clone());
    let mut set = JoinSet::new();
    for host in hosts {
        let timeout = config.tls_timeout;
        set.spawn(async move {
            let facts = tls::inspect(&host, 443, timeout).await;
            info!(%host, ?facts, "tls");
            (host, facts)
        });
    }
    collect(set).await
}

async fn xhttp_all(
    snapshot: &Snapshot,
    config: &Config,
) -> Vec<(usize, XhttpFacts)> {
    if config.no_xhttp {
        return Vec::new();
    }
    let mut set = JoinSet::new();
    for (idx, channel) in snapshot.channels.iter().enumerate() {
        if !channel.is_xhttp() || channel.outbound.is_null() {
            continue;
        }
        if !matches!(
            checks::channel::precheck(channel, snapshot),
            Precheck::Probe(_)
        ) {
            continue;
        }
        let (channel, timeout) = (channel.clone(), config.xhttp_timeout);
        set.spawn(async move { (idx, xhttp::probe(&channel, timeout).await) });
    }
    collect(set).await
}

async fn probe_all(snapshot: &Snapshot, config: &Config) -> ProbeStage {
    if config.no_channels {
        return ProbeStage::Skipped;
    }
    if snapshot.hwid_stub {
        return ProbeStage::SetupFailed(checks::HWID_STUB_DETAIL.to_string());
    }
    let Some(version) = checks::channel::required_xray_version(snapshot) else {
        return ProbeStage::SetupFailed(
            "no node reported an Xray version, so no binary can be chosen"
                .to_string(),
        );
    };
    let binary = match probe::ensure_xray(&version, &config.xray_cache).await {
        Ok(b) => b,
        Err(e) => {
            return ProbeStage::SetupFailed(format!(
                "obtaining xray {version}: {e:#}"
            ));
        }
    };
    info!(%version, "xray ready");
    let limit = Arc::new(Semaphore::new(config.concurrency));
    let mut list = Vec::new();
    let mut set = JoinSet::new();
    for (idx, channel) in snapshot.channels.iter().enumerate() {
        match checks::channel::precheck(channel, snapshot) {
            Precheck::Decided(r) => list.push((idx, ProbeResult::Decided(r))),
            Precheck::Probe(expect) => {
                let limit = Arc::clone(&limit);
                let binary = binary.clone();
                let outbound = channel.outbound.clone();
                let expect = expect.name.clone();
                let (timeout, echo) =
                    (config.probe_timeout, config.echo_url.clone());
                set.spawn(async move {
                    let _permit = limit
                        .acquire_owned()
                        .await
                        .expect("the semaphore is never closed");
                    let outcome =
                        probe_retrying(&binary, &outbound, timeout, &echo)
                            .await;
                    (idx, ProbeResult::Probed { expect, outcome })
                });
            }
        }
    }
    list.extend(collect(set).await);
    info!(channels = list.len(), "probe: done");
    ProbeStage::Done(list)
}

/// One tunnel, retried once when it came up dead. A wrong exit is
/// deterministic and re-running would only report the same address, so a
/// missing one is the only outcome worth a second attempt.
async fn probe_retrying(
    binary: &std::path::Path,
    outbound: &serde_json::Value,
    timeout: std::time::Duration,
    echo: &str,
) -> ProbeOutcome {
    let outcome = probe::probe(binary, outbound, timeout, echo).await;
    if outcome.exit_ip.is_some() {
        return outcome;
    }
    probe::probe(binary, outbound, timeout, echo).await
}

/// The panel is the only source of truth: failing to read it means nothing
/// was checked, and that must reach Telegram directly.
async fn panel_unreadable(
    err: &anyhow::Error,
    notifier: Option<&Notifier>,
    run_url: Option<&str>,
) -> Result<Outcome> {
    error!("the panel could not be read, so nothing was checked: {err:#}");
    if let Some(n) = notifier {
        let mut text = format!(
            "\u{1F534} <b>Healthcheck</b>\nthe panel could not be read, so nothing was checked\n{}",
            report::escape_html(&format!("{err:#}"))
        );
        if let Some(u) = run_url {
            text.push_str("\n\n");
            text.push_str(u);
        }
        if let Err(e) = n.send(&text).await {
            error!("telegram: {e}");
        }
    }
    Ok(Outcome::Aborted)
}

/// GitHub's job summary, when the runner offers one.
fn write_step_summary(results: &[CheckResult]) {
    let Some(path) = std::env::var_os("GITHUB_STEP_SUMMARY") else {
        return;
    };
    let written = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(&path)
        .and_then(|mut f| {
            f.write_all(Report::of(results).markdown().as_bytes())
        });
    if let Err(e) = written {
        warn!("step summary: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{by_name, config};
    use remnawave_healthcheck_core::model::{
        Channel, GeoFacts, HostFacts, Node, Profile, Severity, parse_ip,
    };
    use serde_json::json;

    fn snapshot() -> Snapshot {
        let node = Node {
            uuid: "u-beta".into(),
            name: "beta".into(),
            address: "beta.example.com".into(),
            country_code: "DE".into(),
            is_connected: true,
            users_online: 3,
            xray_uptime_secs: 3600,
            xray_version: Some("26.6.27".into()),
            node_version: Some("3.3.2".into()),
            profile_uuid: Some("p".into()),
            inbound_tags: vec!["in".into()],
            inbound_ports: vec![443],
            ..Default::default()
        };
        let profile = Profile {
            uuid: "p".into(),
            name: "p".into(),
            config: json!({"inbounds": [{"tag": "in", "port": 443}], "outbounds": [{"tag": "direct", "protocol": "freedom"}]}),
        };
        Snapshot {
            nodes: vec![node],
            profiles: HashMap::from([("p".to_string(), profile)]),
            channels: vec![Channel {
                remark: "beta direct".into(),
                inbound_tag: "in".into(),
                profile_uuid: Some("p".into()),
                address: "beta.example.com".into(),
                port: 443,
                transport: Some("xhttp".into()),
                path: Some("/p".into()),
                outbound: json!({"protocol": "vless"}),
                ..Default::default()
            }],
            served_remarks: vec!["beta direct".into()],
            panel_host: "panel.example.com".into(),
            sub_host: Some("sub.example.com".into()),
            ..Default::default()
        }
    }

    fn healthy_ssh() -> SshOutcome {
        SshOutcome::Reached(HostFacts {
            docker_ps: "remnanode\trunning\n".into(),
            listening: "LISTEN 0 4096 0.0.0.0:443 0.0.0.0:*\n".into(),
            cert: Some("notAfter=Nov 20 10:00:00 2036 GMT\n".into()),
            renewal: "PORT80=open\n".into(),
            ..Default::default()
        })
    }

    /// A geocheck that completed, in the shape the panel stores it.
    fn healthy_geo() -> GeoOutcome {
        GeoOutcome::Done(GeoFacts {
            egress: parse_ip("192.0.2.20"),
            report: json!({"schema": 1, "identity": {"ipv4": "192.0.2.20"}}),
        })
    }

    fn probed(exit: &str) -> ProbeStage {
        ProbeStage::Done(vec![(
            0,
            ProbeResult::Probed {
                expect: "beta".into(),
                outcome: ProbeOutcome {
                    exit_ip: parse_ip(exit),
                    stderr_tail: String::new(),
                },
            },
        )])
    }

    #[test]
    fn judge_pairs_every_family_with_the_snapshot() {
        let s = snapshot();
        let now = Utc::now();
        let collected = Collected {
            geo: HashMap::from([("beta".to_string(), healthy_geo())]),
            ssh: HashMap::from([("beta".to_string(), healthy_ssh())]),
            tls: vec![(
                "panel.example.com".into(),
                TlsFacts {
                    not_after: Some(now + chrono::Duration::days(60)),
                    error: None,
                },
            )],
            xhttp: vec![(
                0,
                XhttpFacts {
                    without_slash: Ok(400),
                    with_slash: Ok(400),
                },
            )],
            probes: probed("192.0.2.20"),
        };

        let results = judge(&s, now, collected, &config());

        for name in [
            "node beta / panel status",
            "node beta / users online",
            "node beta / egress address",
            "node beta / containers",
            "tls panel.example.com",
            "channel beta direct / xhttp path",
            "channel beta direct (beta.example.com:443)",
        ] {
            let result = by_name(&results, name);
            assert_eq!(
                result.severity,
                Severity::Ok,
                "{name}: {}",
                result.detail
            );
        }
        let report = Report::of(&results);
        assert_eq!(report.overall(), Severity::Ok, "{}", report.table());
    }

    #[test]
    fn a_setup_failure_and_an_unreachable_host_degrade_without_hiding_the_rest()
    {
        let s = snapshot();
        let collected = Collected {
            geo: HashMap::from([(
                "beta".to_string(),
                GeoOutcome::Failed("timeout".into()),
            )]),
            ssh: HashMap::from([(
                "beta".to_string(),
                SshOutcome::Unreachable("Connection refused".into()),
            )]),
            tls: vec![],
            xhttp: vec![],
            probes: ProbeStage::SetupFailed("obtaining xray: boom".into()),
        };

        let results = judge(&s, Utc::now(), collected, &config());

        assert_eq!(
            by_name(&results, "node beta / geocheck").severity,
            Severity::Warn
        );
        assert_eq!(
            by_name(&results, "node beta / ssh").severity,
            Severity::Warn
        );
        assert_eq!(
            by_name(&results, "channels setup").severity,
            Severity::Fail
        );
        assert!(results.iter().all(|r| r.name != "node beta / containers"));
        assert_eq!(Report::of(&results).outcome(), Outcome::Failed);
    }

    /// Without geocheck there is no address to compare the tunnel's exit
    /// against, and an unverified exit is not a passing one.
    #[test]
    fn a_probe_without_a_known_egress_is_unverified_not_green() {
        let s = snapshot();
        let collected = Collected {
            geo: HashMap::new(),
            ssh: HashMap::new(),
            tls: vec![],
            xhttp: vec![],
            probes: probed("192.0.2.20"),
        };

        let results = judge(&s, Utc::now(), collected, &config());

        assert_eq!(
            by_name(&results, "channel beta direct (beta.example.com:443)")
                .severity,
            Severity::Warn
        );
    }

    #[tokio::test]
    #[should_panic(expected = "boom")]
    async fn a_panicked_family_task_fails_the_run_loudly() {
        let mut set = JoinSet::new();
        set.spawn(async { panic!("boom") });

        let _: Vec<()> = collect(set).await;
    }

    #[tokio::test]
    async fn xhttp_probes_skip_channels_whose_exit_is_disabled() {
        let mut s = snapshot();
        s.nodes[0].is_disabled = true;

        let facts = xhttp_all(&s, &config()).await;

        assert!(facts.is_empty());
    }
}
