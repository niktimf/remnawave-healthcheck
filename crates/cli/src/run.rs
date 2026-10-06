//! One run: panel → panel checks → (geocheck ∥ ssh ∥ tls ∥ xhttp ∥ tunnels)
//! → services → classify → report → deliver. Families run concurrently; the
//! tunnels need geocheck's egress addresses only at classification time. The
//! services stage waits for both: it asks through a tunnel already shown to
//! come out at its exit's egress address.

use crate::config::Config;
use crate::judge::{self, Collected, ProbeResult, ProbeStage, SshStage};
use crate::telegram::Notifier;
use anyhow::Result;
use chrono::Utc;
use remnawave_healthcheck_core::checks::services::{
    self as service_checks, ExitPlan, ExitServices,
};
use remnawave_healthcheck_core::checks::{self, channel::Precheck};
use remnawave_healthcheck_core::model::{
    CheckResult, GeoOutcome, ProbeOutcome, Reported, Snapshot, SshOutcome,
    TlsFacts, XhttpFacts,
};
use remnawave_healthcheck_core::report::{self, Outcome, Report};
use remnawave_healthcheck_io::{
    PanelClient, SshRunner, probe, services, tls, upstream, xhttp,
};
use std::collections::HashMap;
use std::io::Write as _;
use std::path::PathBuf;
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

    let (geo, ssh, tls, xhttp, probes, upstream) = tokio::join!(
        geocheck_all(&panel, &snapshot, &config),
        ssh_all(&snapshot, &config),
        tls_all(&snapshot, &config),
        xhttp_all(&snapshot, &config),
        probe_all(&snapshot, &config),
        upstream_release(&config),
    );
    let services = services_all(&snapshot, &config, &probes, &geo).await;
    let collected = Collected {
        geo,
        ssh,
        tls,
        xhttp,
        probes,
        upstream,
        services,
    };
    let results = config.judge.verdicts(&snapshot, now, collected);

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

async fn ssh_all(snapshot: &Snapshot, config: &Config) -> SshStage {
    if config.no_ssh {
        return SshStage::Skipped;
    }
    let runner = match SshRunner::new(config.ssh.clone()) {
        Ok(r) => Arc::new(r),
        Err(e) => {
            error!("ssh: {e:#}");
            return SshStage::SetupFailed(format!("{e:#}"));
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
    SshStage::Done(collect(set).await.into_iter().collect())
}

async fn tls_all(
    snapshot: &Snapshot,
    config: &Config,
) -> Vec<(String, TlsFacts)> {
    let endpoints =
        std::iter::once(snapshot.panel.clone()).chain(snapshot.sub.clone());
    let mut set = JoinSet::new();
    for endpoint in endpoints {
        let timeout = config.tls_timeout;
        set.spawn(async move {
            let facts =
                tls::inspect(&endpoint.host, endpoint.port, timeout).await;
            let label = endpoint.label();
            info!(%label, ?facts, "tls");
            (label, facts)
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
        if !channel.is_xhttp() || channel.served.outbound().is_none() {
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

/// The newest stable panel release, from GitHub. The only request that leaves
/// for anything but the panel and its nodes, so it is skippable and its failure
/// is a verdict rather than the end of the run.
async fn upstream_release(config: &Config) -> Reported {
    if config.no_upstream {
        return Reported::NotRead;
    }
    let reported = upstream::latest_release(
        upstream::GITHUB_API,
        upstream::PANEL_REPO,
        config.github_token.as_deref(),
        config.panel_timeout,
    )
    .await;
    match &reported {
        Reported::Known(tag) => info!(latest = %tag, "upstream release"),
        Reported::Failed(why) => warn!("upstream release: {why}"),
        Reported::NotRead => {}
    }
    reported
}

async fn probe_all(snapshot: &Snapshot, config: &Config) -> ProbeStage {
    if config.no_channels {
        return ProbeStage::Skipped;
    }
    if snapshot.hwid_stub {
        return ProbeStage::SetupFailed(checks::HWID_STUB_DETAIL.to_string());
    }
    let binary = match xray_binary(snapshot, config).await {
        Ok(b) => b,
        Err(why) => return ProbeStage::SetupFailed(why),
    };
    let limit = Arc::new(Semaphore::new(config.concurrency));
    let mut list = Vec::new();
    let mut set = JoinSet::new();
    for (idx, channel) in snapshot.channels.iter().enumerate() {
        match checks::channel::precheck(channel, snapshot) {
            Precheck::Decided(r) => list.push((idx, ProbeResult::Decided(r))),
            // A selector has no tunnel of its own; its verdict is the
            // balancer check, once the candidates' tunnels are in.
            Precheck::Selector => {}
            Precheck::Probe(expect) => {
                let limit = Arc::clone(&limit);
                let binary = binary.clone();
                let outbound = channel
                    .served
                    .outbound()
                    .cloned()
                    .expect("a probeable channel carries an outbound");
                let expect = expect.name.clone();
                let (timeout, echo, download) = (
                    config.probe_timeout,
                    config.echo_url.clone(),
                    config.download.clone(),
                );
                set.spawn(async move {
                    let _permit = limit
                        .acquire_owned()
                        .await
                        .expect("the semaphore is never closed");
                    let outcome = probe_retrying(
                        &binary,
                        &outbound,
                        timeout,
                        &echo,
                        download.as_ref(),
                    )
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

/// The Xray the nodes run, downloaded on first use. The services stage asks
/// again after the tunnels, and is answered from the cache.
async fn xray_binary(
    snapshot: &Snapshot,
    config: &Config,
) -> Result<PathBuf, String> {
    let Some(version) = checks::channel::required_xray_version(snapshot) else {
        return Err(
            "no node reported an Xray version, so no binary can be chosen"
                .to_string(),
        );
    };
    let binary = probe::ensure_xray(&version, &config.xray_cache)
        .await
        .map_err(|e| format!("obtaining xray {version}: {e:#}"))?;
    info!(%version, "xray ready");
    Ok(binary)
}

/// Every exit asked about the services, each through its own Xray, the exits
/// in parallel. Runs only once the tunnels are in: which tunnel an exit is
/// asked through depends on where they came out. Nothing when no tunnel ran.
async fn services_all(
    snapshot: &Snapshot,
    config: &Config,
    probes: &ProbeStage,
    geo: &HashMap<String, GeoOutcome>,
) -> Vec<(String, ExitServices)> {
    let Some(tunnels) = judge::tunnel_exits(probes) else {
        return Vec::new();
    };
    let egress = judge::egress_by_node(snapshot, geo);
    let plans = service_checks::plan(snapshot, &tunnels, &egress);
    if config.no_services {
        return plans
            .iter()
            .map(|p| (p.exit().name.clone(), ExitServices::Disabled))
            .collect();
    }
    let mut out = Vec::new();
    let mut asked = Vec::new();
    for plan in plans {
        match plan {
            ExitPlan::Skip { exit, why } => {
                out.push((exit.name.clone(), ExitServices::Skipped(why)));
            }
            ExitPlan::Probe { exit, channel } => asked.push((exit, channel)),
        }
    }
    if asked.is_empty() {
        return out;
    }
    let binary = match xray_binary(snapshot, config).await {
        Ok(b) => b,
        Err(reason) => {
            out.extend(asked.into_iter().map(|(exit, channel)| {
                let via = channel.remark.clone();
                let failed = ExitServices::TunnelFailed {
                    via,
                    reason: reason.clone(),
                };
                (exit.name.clone(), failed)
            }));
            return out;
        }
    };
    let limit = Arc::new(Semaphore::new(config.concurrency));
    let mut set = JoinSet::new();
    for (exit, channel) in asked {
        let outbound = channel
            .served
            .outbound()
            .cloned()
            .expect("a channel whose tunnel came out carries an outbound");
        let (limit, binary, timeout) =
            (Arc::clone(&limit), binary.clone(), config.service_timeout);
        let (exit, via) = (exit.name.clone(), channel.remark.clone());
        set.spawn(async move {
            let _permit = limit
                .acquire_owned()
                .await
                .expect("the semaphore is never closed");
            let started = Instant::now();
            let outcome =
                match services::check(&binary, &outbound, timeout).await {
                    Ok(answers) => ExitServices::Checked { via, answers },
                    Err(reason) => {
                        warn!(node = %exit, "services: {reason}");
                        ExitServices::TunnelFailed { via, reason }
                    }
                };
            info!(node = %exit, elapsed = ?started.elapsed(), "services: done");
            (exit, outcome)
        });
    }
    out.extend(collect(set).await);
    out
}

/// One tunnel, retried once when it came up dead. A wrong exit is
/// deterministic and re-running would only report the same address, so a
/// missing one is the only outcome worth a second attempt. A download that
/// went wrong behind a live exit is a finding, not a reason to retry.
async fn probe_retrying(
    binary: &std::path::Path,
    outbound: &serde_json::Value,
    timeout: std::time::Duration,
    echo: &str,
    download: Option<&probe::DownloadTarget>,
) -> ProbeOutcome {
    let outcome = probe::probe(binary, outbound, timeout, echo, download).await;
    if outcome.exit_ip.is_some() {
        return outcome;
    }
    probe::probe(binary, outbound, timeout, echo, download).await
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
    use crate::test_util::{config, snapshot};
    use remnawave_healthcheck_core::checks::services::Skip;
    use remnawave_healthcheck_core::model::{
        Download, GeoFacts, ProbeOutcome, parse_ip,
    };

    #[tokio::test]
    #[should_panic(expected = "boom")]
    async fn a_panicked_family_task_fails_the_run_loudly() {
        let mut set = JoinSet::new();
        set.spawn(async { panic!("boom") });

        let _: Vec<()> = collect(set).await;
    }

    fn tunnel_out_at(exit: &str) -> ProbeStage {
        ProbeStage::Done(vec![(
            0,
            ProbeResult::Probed {
                expect: "beta".into(),
                outcome: ProbeOutcome {
                    exit_ip: parse_ip(exit),
                    stderr_tail: String::new(),
                    download: Download::NotRun,
                },
            },
        )])
    }

    fn geo_at(egress: &str) -> HashMap<String, GeoOutcome> {
        HashMap::from([(
            "beta".to_string(),
            GeoOutcome::Done(GeoFacts {
                egress: parse_ip(egress),
                report: serde_json::Value::Null,
            }),
        )])
    }

    /// `--no-services` keeps the rows in the report, so switching the stage
    /// off is visible rather than read as a clean bill.
    #[tokio::test]
    async fn switched_off_services_still_name_every_exit() {
        let mut config = config();
        config.no_services = true;

        let out = services_all(
            &snapshot(),
            &config,
            &tunnel_out_at("192.0.2.20"),
            &geo_at("192.0.2.20"),
        )
        .await;

        assert_eq!(out, [("beta".to_string(), ExitServices::Disabled)]);
    }

    /// No tunnel out at the exit's egress address means no Xray is started
    /// for it: the row says why instead.
    #[tokio::test]
    async fn an_exit_no_tunnel_reached_is_skipped_without_starting_xray() {
        let out = services_all(
            &snapshot(),
            &config(),
            &tunnel_out_at("198.51.100.7"),
            &geo_at("192.0.2.20"),
        )
        .await;

        assert_eq!(
            out,
            [("beta".to_string(), ExitServices::Skipped(Skip::NoTunnel))]
        );
    }

    #[tokio::test]
    async fn without_tunnels_the_services_stage_has_nothing_to_say() {
        let out = services_all(
            &snapshot(),
            &config(),
            &ProbeStage::Skipped,
            &geo_at("192.0.2.20"),
        )
        .await;

        assert_eq!(out, Vec::<(String, ExitServices)>::new());
    }

    #[tokio::test]
    async fn xhttp_probes_skip_channels_whose_exit_is_disabled() {
        let mut s = snapshot();
        s.nodes[0].is_disabled = true;

        let facts = xhttp_all(&s, &config()).await;

        assert_eq!(facts, Vec::<(usize, XhttpFacts)>::new());
    }
}
