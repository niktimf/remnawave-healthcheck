//! Turning collected facts into verdicts. Nothing here opens a socket: the
//! whole module is a function of the snapshot and what the families gathered.

use chrono::{DateTime, Utc};
use remnawave_healthcheck_core::checks::channel;
use remnawave_healthcheck_core::checks::geo::GeoChecker;
use remnawave_healthcheck_core::checks::panel::PanelChecker;
use remnawave_healthcheck_core::checks::ssh::{self, SshChecker};
use remnawave_healthcheck_core::checks::tls;
use remnawave_healthcheck_core::model::{
    CheckResult, GeoOutcome, ProbeOutcome, Snapshot, SshOutcome, TlsFacts,
    XhttpFacts,
};
use std::collections::HashMap;
use std::net::IpAddr;

/// Facts of every family, keyed so `judge` can pair them with the snapshot.
pub struct Collected {
    pub geo: HashMap<String, GeoOutcome>,
    pub ssh: SshStage,
    pub tls: Vec<(String, TlsFacts)>,
    pub xhttp: Vec<(usize, XhttpFacts)>,
    pub probes: ProbeStage,
}

/// Why a family produced nothing is worth a line in the report, so the stages
/// it can end in are spelled out rather than collapsed into an empty map.
pub enum SshStage {
    Skipped,
    SetupFailed(String),
    Done(HashMap<String, SshOutcome>),
}

impl SshStage {
    /// What each node's run produced, when the family got to run at all.
    fn reached(&self) -> Option<&HashMap<String, SshOutcome>> {
        match self {
            Self::Done(reached) => Some(reached),
            Self::Skipped | Self::SetupFailed(_) => None,
        }
    }
}

pub enum ProbeStage {
    Skipped,
    SetupFailed(String),
    Done(Vec<(usize, ProbeResult)>),
}

pub enum ProbeResult {
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

/// Everything needed to turn facts into verdicts, and nothing else. `Config`
/// carries two dozen settings — panel URL, tokens, timeouts, Telegram — of
/// which exactly these four decide a verdict.
#[derive(Debug, Clone)]
pub struct Judge {
    pub panel: PanelChecker,
    pub geo: GeoChecker,
    pub ssh: SshChecker,
    pub cert_warn_days: u32,
}

impl Judge {
    /// Pure: pair the snapshot with the collected facts.
    pub fn verdicts(
        &self,
        snapshot: &Snapshot,
        now: DateTime<Utc>,
        c: Collected,
    ) -> Vec<CheckResult> {
        let egress = egress_by_node(snapshot, &c.geo);
        let mut results = self.panel.all(snapshot);
        results.extend(ssh_setup(&c.ssh));
        results.extend(self.per_node(snapshot, now, &c));
        results.extend(c.tls.iter().map(|(host, facts)| {
            tls::check(host, facts, now, self.cert_warn_days)
        }));
        results.extend(c.xhttp.iter().map(|(idx, facts)| {
            channel::xhttp(&snapshot.channels[*idx], facts)
        }));
        results.extend(channels(snapshot, c.probes, &egress));
        results
    }

    /// What geocheck and ssh found on each enabled node, in node order.
    fn per_node(
        &self,
        snapshot: &Snapshot,
        now: DateTime<Utc>,
        c: &Collected,
    ) -> Vec<CheckResult> {
        let reached = c.ssh.reached();
        let mut out = Vec::new();
        for node in snapshot.nodes.iter().filter(|n| n.is_enabled()) {
            if let Some(outcome) = c.geo.get(&node.name) {
                out.extend(self.geo.check_node(node, outcome));
            }
            if let Some(outcome) = reached.and_then(|r| r.get(&node.name)) {
                out.extend(self.ssh.check_node(node, outcome, now));
            }
        }
        out
    }
}

/// A family that could not start is one result, not a silence.
fn ssh_setup(stage: &SshStage) -> Option<CheckResult> {
    match stage {
        SshStage::SetupFailed(detail) => {
            Some(ssh::setup_failed(detail.as_str()))
        }
        SshStage::Skipped | SshStage::Done(_) => None,
    }
}

/// One verdict per channel: what the tunnel did, or why none was run.
fn channels(
    snapshot: &Snapshot,
    probes: ProbeStage,
    egress: &HashMap<&str, IpAddr>,
) -> Vec<CheckResult> {
    match probes {
        ProbeStage::Skipped => Vec::new(),
        ProbeStage::SetupFailed(detail) => vec![channel::setup_failed(detail)],
        ProbeStage::Done(list) => list
            .into_iter()
            .map(|(idx, result)| channel_verdict(snapshot, idx, result, egress))
            .collect(),
    }
}

/// The exit a tunnel came out of, against the egress its expected node was
/// seen at.
fn channel_verdict(
    snapshot: &Snapshot,
    idx: usize,
    result: ProbeResult,
    egress: &HashMap<&str, IpAddr>,
) -> CheckResult {
    match result {
        ProbeResult::Decided(decided) => decided,
        ProbeResult::Probed { expect, outcome } => {
            let node = snapshot
                .nodes
                .iter()
                .find(|n| n.name == expect)
                .expect("the expected exit came out of this snapshot");
            let want = egress.get(expect.as_str()).copied();
            channel::classify(&snapshot.channels[idx], node, want, &outcome)
        }
    }
}

/// The address each enabled node's completed geocheck saw it leave from. A job
/// that never completed contributes nothing rather than an absent address.
fn egress_by_node<'a>(
    snapshot: &'a Snapshot,
    geo: &HashMap<String, GeoOutcome>,
) -> HashMap<&'a str, IpAddr> {
    snapshot
        .nodes
        .iter()
        .filter(|n| n.is_enabled())
        .filter_map(|n| {
            let ip = done_egress(geo.get(&n.name)?)?;
            Some((n.name.as_str(), ip))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{by_name, judge, snapshot};
    use remnawave_healthcheck_core::model::{
        GeoFacts, HostFacts, Severity, parse_ip,
    };
    use remnawave_healthcheck_core::report::{Outcome, Report};
    use serde_json::json;

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
    fn every_family_is_paired_with_the_snapshot() {
        let s = snapshot();
        let now = Utc::now();
        let collected = Collected {
            geo: HashMap::from([("beta".to_string(), healthy_geo())]),
            ssh: SshStage::Done(HashMap::from([(
                "beta".to_string(),
                healthy_ssh(),
            )])),
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
        let sut = judge();

        let results = sut.verdicts(&s, now, collected);

        for name in [
            "node beta / panel status",
            "node beta / users online",
            "node beta / egress address",
            "node beta / containers",
            "tls panel.example.com",
            "channel beta direct (beta.example.com:443) / xhttp path",
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
            ssh: SshStage::Done(HashMap::from([(
                "beta".to_string(),
                SshOutcome::Unreachable("Connection refused".into()),
            )])),
            tls: vec![],
            xhttp: vec![],
            probes: ProbeStage::SetupFailed("obtaining xray: boom".into()),
        };
        let sut = judge();

        let results = sut.verdicts(&s, Utc::now(), collected);

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

    /// A local misconfiguration must not make a whole family disappear: the
    /// run was asked for node-side checks and produced none.
    #[test]
    fn an_ssh_setup_failure_is_reported_rather_than_dropped() {
        let s = snapshot();
        let collected = Collected {
            geo: HashMap::new(),
            ssh: SshStage::SetupFailed(
                "writing the key file: permission denied".into(),
            ),
            tls: vec![],
            xhttp: vec![],
            probes: ProbeStage::Skipped,
        };
        let sut = judge();

        let results = sut.verdicts(&s, Utc::now(), collected);

        let setup = by_name(&results, "ssh setup");
        assert_eq!(setup.severity, Severity::Fail);
        assert!(setup.detail.contains("permission denied"), "{}", setup.detail);
    }

    /// Without geocheck there is no address to compare the tunnel's exit
    /// against, and an unverified exit is not a passing one.
    #[test]
    fn a_probe_without_a_known_egress_is_unverified_not_green() {
        let s = snapshot();
        let collected = Collected {
            geo: HashMap::new(),
            ssh: SshStage::Skipped,
            tls: vec![],
            xhttp: vec![],
            probes: probed("192.0.2.20"),
        };
        let sut = judge();

        let results = sut.verdicts(&s, Utc::now(), collected);

        assert_eq!(
            by_name(&results, "channel beta direct (beta.example.com:443)")
                .severity,
            Severity::Warn
        );
    }
}
