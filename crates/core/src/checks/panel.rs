use super::commas;
use crate::model::{
    CheckResult, Node, PanelState, Severity, Snapshot, node_check,
};
use crate::topology::Resolver;
use std::collections::{BTreeMap, BTreeSet};

/// What the panel itself thinks of each node. Costs no SSH and no tunnels.
fn node_status(nodes: &[Node]) -> Vec<CheckResult> {
    nodes
        .iter()
        .map(|n| {
            // Which state a node is in is the node's question; what it is worth
            // in a report is this module's. A reconnecting node warns rather
            // than fails because the panel retries on its own, and carries no
            // reason: the message the panel left is about the attempt before.
            let (severity, detail) = match n.panel_state() {
                PanelState::Disabled => {
                    (Severity::Warn, "disabled by an administrator".to_string())
                }
                PanelState::Connecting => {
                    (Severity::Warn, "connecting".to_string())
                }
                PanelState::Disconnected { reason } => (
                    Severity::Fail,
                    format!(
                        "not connected: {}",
                        reason.unwrap_or("no reason given")
                    ),
                ),
                PanelState::Connected => {
                    (Severity::Ok, "connected".to_string())
                }
            };
            CheckResult::new(
                node_check(&n.name, "panel status"),
                severity,
                detail,
            )
        })
        .collect()
}

/// Whether the subscription served exactly the channels the panel resolved.
///
/// The join by remark is what gives every channel its outbound, so a mismatch
/// means channels are probed with the wrong config or not at all while the
/// panel still looks healthy. Sets and not counts: one channel dropped and
/// another duplicated leaves the counts equal.
fn subscription_coverage(snapshot: &Snapshot) -> CheckResult {
    if snapshot.hwid_stub {
        return CheckResult::fail(
            "subscription coverage",
            super::HWID_STUB_DETAIL,
        );
    }
    let coverage = Coverage::of(snapshot);
    // Asked for once and used for both: a run is healthy exactly when there is
    // nothing to report.
    let gaps = coverage.gaps();
    let (severity, detail) = if gaps.is_empty() {
        (
            Severity::Ok,
            format!(
                "subscription served all {} resolved channels",
                coverage.resolved
            ),
        )
    } else {
        (Severity::Fail, gaps.join("; "))
    };
    CheckResult::new("subscription coverage", severity, detail)
}

/// How the channels the panel resolved and the remarks the subscription served
/// failed to line up.
///
/// Ordered sets, not lists: a remark can be missing, unexpected or duplicated
/// only once, and the order should not depend on how the snapshot was built.
/// Both hold today because these come out of a `BTree*`; keeping them in the
/// types stops a rewrite from quietly reporting a name twice.
struct Coverage<'a> {
    /// How many channels the panel resolved, for the healthy message.
    resolved: usize,
    /// Resolved by the panel, never served by the subscription.
    missing: BTreeSet<&'a str>,
    /// Served by the subscription, never resolved by the panel.
    unexpected: BTreeSet<&'a str>,
    /// Served more than once, with how many. The count says which mistake this
    /// is: twice is one duplicated host, a dozen is a remark template
    /// collapsing that many hosts onto one name.
    duplicated: BTreeMap<&'a str, usize>,
}

impl<'a> Coverage<'a> {
    fn of(snapshot: &'a Snapshot) -> Self {
        // A host another entry's balancer carries is rendered inside that
        // entry, not as one of its own, so it is neither missing here nor
        // unexpected there.
        let resolved: BTreeSet<&str> = snapshot
            .channels
            .iter()
            .filter(|c| !c.served.is_candidate())
            .map(|c| c.remark.as_str())
            .collect();
        // One pass: the served set and the ones served more than once come out
        // of the same tally.
        let mut tally: BTreeMap<&str, usize> = BTreeMap::new();
        for remark in &snapshot.served_remarks {
            *tally.entry(remark.as_str()).or_default() += 1;
        }
        let served: BTreeSet<&str> = tally.keys().copied().collect();

        Self {
            resolved: resolved.len(),
            missing: resolved.difference(&served).copied().collect(),
            unexpected: served.difference(&resolved).copied().collect(),
            // A remark served twice makes the join ambiguous: both channels
            // would be probed with whichever outbound won, so one is reported
            // on evidence that is not its own.
            duplicated: tally
                .into_iter()
                .filter(|(_, times)| *times > 1)
                .collect(),
        }
    }

    /// Every way the two sides disagree, one description apiece.
    ///
    /// The only place that enumerates the kinds of disagreement: a fourth kind
    /// is a row here and nothing else.
    fn gaps(&self) -> Vec<String> {
        let named = |remarks: &BTreeSet<&str>| commas(remarks.iter().copied());
        let counted = commas(
            self.duplicated
                .iter()
                .map(|(remark, times)| format!("{remark} \u{00d7}{times}")),
        );

        // An empty rendering is an absent gap.
        [
            ("not served", named(&self.missing)),
            ("served but not resolved by the panel", named(&self.unexpected)),
            (
                "served more than once, so their configs cannot be told apart",
                counted,
            ),
        ]
        .into_iter()
        .filter(|(_, remarks)| !remarks.is_empty())
        .map(|(what, remarks)| format!("{what}: {remarks}"))
        .collect()
    }
}

/// Inbounds that run on a node and serve no channel of the monitoring user.
/// The panel knows why in each case, and the reasons are not the same fault:
/// a cascade's receiving end is unreachable by any client and belongs to no
/// subscription by construction, while an inbound nothing at all leads to is a
/// node listening on a port for nobody.
fn monitoring_coverage(snapshot: &Snapshot) -> Vec<CheckResult> {
    let covered: BTreeSet<&str> = snapshot
        .channels
        .iter()
        .map(|c| c.inbound_tag.as_str())
        .collect();
    let resolver = Resolver::new(snapshot);
    let mut seen: BTreeSet<&str> = BTreeSet::new();

    snapshot
        .nodes
        .iter()
        .filter(|n| n.is_enabled())
        .flat_map(|node| node.inbound_tags.iter().map(move |tag| (node, tag)))
        .filter(|(_, tag)| {
            !covered.contains(tag.as_str()) && seen.insert(tag.as_str())
        })
        .filter_map(|(node, tag)| uncovered(snapshot, resolver, node, tag))
        .collect()
}

/// Why one inbound serves no channel here, when that is worth reporting.
fn uncovered(
    snapshot: &Snapshot,
    resolver: Resolver<'_>,
    node: &Node,
    tag: &str,
) -> Option<CheckResult> {
    let name = format!("inbound {tag} monitored");
    if let Some(host) = snapshot.excluded.iter().find(|h| h.inbound_tag == tag)
    {
        return Some(CheckResult::warn(
            name,
            format!(
                "inbound '{tag}' on node '{}' is served by host '{}', which the panel keeps out of this subscription type and no balancer carries: nothing here checks that channel",
                node.name, host.remark
            ),
        ));
    }
    // A cascade's receiving end: clients never dial it, so no host points at
    // it and none can. The cascade itself is checked end to end by the
    // channel that enters it.
    if resolver.is_cascade_target(node, tag) {
        return None;
    }
    Some(CheckResult::warn(
        name,
        format!(
            "inbound '{tag}' on node '{}' is in no subscription and no cascade routes into it: the node is listening for nobody",
            node.name
        ),
    ))
}

/// Whether the enabled nodes agree on one version of `what`.
fn version_drift(
    name: &str,
    nodes: &[Node],
    version: impl Fn(&Node) -> Option<&str>,
) -> CheckResult {
    let versions: Vec<&str> = nodes
        .iter()
        .filter(|n| n.is_enabled())
        .filter_map(&version)
        .collect::<BTreeSet<&str>>()
        .into_iter()
        .collect();
    match versions.as_slice() {
        [] => CheckResult::ok(name, "no versions reported"),
        [only] => CheckResult::ok(name, format!("all nodes on {only}")),
        several => CheckResult::warn(
            name,
            format!("nodes disagree: {}", several.join(", ")),
        ),
    }
}

/// Client and node must agree on Xray features; drift has broken channels before.
fn xray_version_drift(nodes: &[Node]) -> CheckResult {
    version_drift("xray version drift", nodes, |n| n.xray_version.as_deref())
}

/// The node agent (`remnanode`) drifting is the same signal one layer up.
fn remnanode_version_drift(nodes: &[Node]) -> CheckResult {
    version_drift("remnanode version drift", nodes, |n| {
        n.node_version.as_deref()
    })
}

/// Reads what the panel API said and turns it into verdicts. Carries the
/// judgement calls the operator gets to make, so they stop travelling as an
/// argument through every check.
#[derive(Debug, Clone, Copy)]
pub struct PanelChecker {
    pub config_warn_days: u32,
    /// WARN when the 1-minute load exceeds `factor × cpus`.
    pub load_warn_factor: f64,
    pub mem_free_warn_pct: u8,
}

const DAY_SECS: u64 = 86_400;

/// Nobody online on a node the panel calls connected. Worth looking at, but not
/// a failure: every node is hosting space that can legitimately be idle — a
/// fresh node, a quiet hour — and the panel itself keeps `node_status` and
/// `node_online_users` as separate metrics rather than deriving one from the
/// other.
fn users_online(nodes: &[Node]) -> Vec<CheckResult> {
    nodes
        .iter()
        .filter(|n| n.is_active())
        .map(|n| {
            let name = node_check(&n.name, "users online");
            if n.users_online == 0 {
                CheckResult::warn(name, "0 users online on a connected node")
            } else {
                CheckResult::ok(name, format!("{} online", n.users_online))
            }
        })
        .collect()
}

impl PanelChecker {
    /// A config push restarts xray, so xray's uptime is the age of the
    /// applied config.
    fn config_age(self, nodes: &[Node]) -> Vec<CheckResult> {
        nodes
            .iter()
            .filter(|n| n.is_active())
            .map(|n| {
                let name = node_check(&n.name, "config age");
                let days = n.xray_uptime_secs / DAY_SECS;
                if n.xray_uptime_secs == 0 {
                    CheckResult::fail(
                        name,
                        "xray uptime is 0 on a connected node: the core did not start",
                    )
                } else if days > u64::from(self.config_warn_days) {
                    CheckResult::warn(
                        name,
                        format!("{days}d since the last config push"),
                    )
                } else {
                    CheckResult::ok(
                        name,
                        format!("{days}d since the last config push"),
                    )
                }
            })
            .collect()
    }

    /// Load and memory as the agent reports them. Nodes without `system`
    /// are skipped.
    #[allow(clippy::cast_precision_loss)]
    fn host(self, nodes: &[Node]) -> Vec<CheckResult> {
        nodes
            .iter()
            .filter(|n| n.is_active())
            .filter_map(|n| {
                let s = n.system.as_ref()?;
                let name = node_check(&n.name, "host");
                let load1 = s.load_avg.first().copied().unwrap_or(0.0);
                let cpus = s.cpus.max(1);
                let mem_free_pct = if s.memory_total == 0 {
                    100.0
                } else {
                    s.memory_free as f64 * 100.0 / s.memory_total as f64
                };
                let overloaded = load1 > self.load_warn_factor * f64::from(cpus);
                let short_on_memory =
                    mem_free_pct < f64::from(self.mem_free_warn_pct);
                let problems: Vec<String> = [
                    overloaded
                        .then(|| format!("load {load1:.2} on {cpus} cpu(s)")),
                    short_on_memory
                        .then(|| format!("{mem_free_pct:.0}% memory free")),
                ]
                .into_iter()
                .flatten()
                .collect();
                let summary = format!(
                    "load {load1:.2}/{cpus} cpu, {mem_free_pct:.0}% mem free, up {}d",
                    s.uptime_secs / DAY_SECS
                );
                Some(if problems.is_empty() {
                    CheckResult::ok(name, summary)
                } else {
                    CheckResult::warn(
                        name,
                        format!("{}; {summary}", problems.join(", ")),
                    )
                })
            })
            .collect()
    }

    /// Every panel-derived check, in report order.
    pub fn all(self, snapshot: &Snapshot) -> Vec<CheckResult> {
        let nodes = &snapshot.nodes;
        node_status(nodes)
            .into_iter()
            .chain(users_online(nodes))
            .chain(self.config_age(nodes))
            .chain(self.host(nodes))
            .chain([
                xray_version_drift(nodes),
                remnanode_version_drift(nodes),
                subscription_coverage(snapshot),
            ])
            .chain(monitoring_coverage(snapshot))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Channel, ExcludedHost, HostStats, Profile, Served};
    use rstest::rstest;
    use serde_json::json;
    use std::collections::HashMap;

    fn node(
        name: &str,
        disabled: bool,
        connected: bool,
        version: &str,
        tags: &[&str],
    ) -> Node {
        Node {
            name: name.into(),
            address: format!("192.0.2.{}", name.len()),
            profile_uuid: Some("p".into()),
            inbound_tags: tags
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
            inbound_ports: vec![443],
            is_disabled: disabled,
            is_connected: connected,
            last_status_message: Some("boom".into()),
            xray_version: Some(version.into()),
            node_version: Some("3.3.2".into()),
            ..Default::default()
        }
    }

    fn snap(
        nodes: Vec<Node>,
        channel_tags: &[&str],
        served: &[&str],
    ) -> Snapshot {
        Snapshot {
            nodes,
            channels: channel_tags
                .iter()
                .map(|t| Channel {
                    remark: format!("ch-{t}"),
                    inbound_tag: (*t).to_string(),
                    profile_uuid: Some("p".into()),
                    address: "edge.example.com".into(),
                    port: 443,
                    ..Default::default()
                })
                .collect(),
            served_remarks: served
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
            ..Default::default()
        }
    }

    fn checker() -> PanelChecker {
        PanelChecker {
            config_warn_days: 7,
            load_warn_factor: 2.0,
            mem_free_warn_pct: 10,
        }
    }

    fn active(name: &str) -> Node {
        Node {
            name: name.into(),
            address: "192.0.2.10".into(),
            is_connected: true,
            users_online: 12,
            xray_uptime_secs: 3 * 86_400,
            ..Default::default()
        }
    }

    #[rstest]
    #[case::disabled(true, true, Severity::Warn)]
    #[case::disconnected(false, false, Severity::Fail)]
    #[case::healthy(false, true, Severity::Ok)]
    fn the_panel_state_decides_the_node_status(
        #[case] disabled: bool,
        #[case] connected: bool,
        #[case] expected: Severity,
    ) {
        let nodes = [node("alpha", disabled, connected, "26.6.27", &["in-a"])];

        let results = node_status(&nodes);

        assert_eq!(results[0].name, "node alpha / panel status");
        assert_eq!(results[0].severity, expected, "{}", results[0].detail);
    }

    #[test]
    fn a_disconnected_node_carries_the_panels_own_message() {
        let nodes = [node("beta", false, false, "26.6.27", &["in-b"])];

        let results = node_status(&nodes);

        assert!(
            results[0].detail.contains("boom"),
            "the panel's own message must reach the report: {}",
            results[0].detail
        );
    }

    /// `node` leaves a "boom" in `last_status_message`, as the panel does: it
    /// sets `isConnecting` without clearing the reason of the attempt before.
    #[test]
    fn a_reconnecting_node_warns_without_repeating_a_stale_reason() {
        let mut reconnecting =
            node("alpha", false, false, "26.6.27", &["in-a"]);
        reconnecting.is_connecting = true;

        let results = node_status(&[reconnecting]);

        assert_eq!(results[0].name, "node alpha / panel status");
        assert_eq!(results[0].severity, Severity::Warn);
        assert_eq!(results[0].detail, "connecting");
    }

    #[test]
    fn subscription_coverage_is_ok_when_the_two_sets_match() {
        let snapshot = snap(vec![], &["in-a", "in-b"], &["ch-in-a", "ch-in-b"]);

        let result = subscription_coverage(&snapshot);

        assert_eq!(result.severity, Severity::Ok);
    }

    #[test]
    fn a_subscription_that_served_nothing_fails_naming_every_channel() {
        let snapshot = snap(vec![], &["in-a", "in-b"], &[]);

        let result = subscription_coverage(&snapshot);

        assert_eq!(result.severity, Severity::Fail);
        assert!(
            result.detail.contains("ch-in-a")
                && result.detail.contains("ch-in-b")
        );
    }

    #[test]
    fn subscription_coverage_names_the_channel_the_subscription_dropped() {
        let snapshot = snap(vec![], &["in-a", "in-b"], &["ch-in-a"]);

        let result = subscription_coverage(&snapshot);

        assert_eq!(result.severity, Severity::Fail);
        assert!(result.detail.contains("ch-in-b"), "{}", result.detail);
        assert!(!result.detail.contains("ch-in-a"), "{}", result.detail);
    }

    /// The counts match — two resolved, two served — but the join is broken.
    #[test]
    fn one_channel_dropped_and_another_duplicated_no_longer_cancels_out() {
        let snapshot = snap(vec![], &["in-a", "in-b"], &["ch-in-a", "ch-in-a"]);

        let result = subscription_coverage(&snapshot);

        assert_eq!(result.severity, Severity::Fail);
        assert!(result.detail.contains("ch-in-b"), "{}", result.detail);
        assert!(result.detail.contains("more than once"), "{}", result.detail);
        // The count is part of the reason: two is a duplicated host, a dozen is
        // a remark template collapsing that many hosts onto one name.
        assert!(
            result.detail.contains("ch-in-a \u{00d7}2"),
            "{}",
            result.detail
        );
    }

    #[test]
    fn a_remark_served_but_never_resolved_also_fails() {
        let snapshot = snap(vec![], &["in-a"], &["ch-in-a", "ch-ghost"]);

        let result = subscription_coverage(&snapshot);

        assert_eq!(result.severity, Severity::Fail);
        assert!(result.detail.contains("ch-ghost"), "{}", result.detail);
    }

    /// The subscription renders such a host inside the auto-select entry, so
    /// expecting an entry of its own would report a gap that is not one.
    #[test]
    fn a_channel_a_balancer_carries_is_not_expected_as_an_entry_of_its_own() {
        let mut snapshot = snap(vec![], &["in-a"], &["ch-in-a"]);
        let mut carried = snapshot.channels[0].clone();
        carried.remark = "ch-private".into();
        carried.served = Served::Candidate(json!({"protocol": "vless"}));
        snapshot.channels.push(carried);

        let result = subscription_coverage(&snapshot);

        assert_eq!(result.severity, Severity::Ok, "{}", result.detail);
    }

    #[test]
    fn the_hwid_stub_fails_coverage_with_the_fix_in_the_detail() {
        let mut snapshot = snap(vec![], &["in-a"], &[]);
        snapshot.hwid_stub = true;

        let result = subscription_coverage(&snapshot);

        assert_eq!(result.severity, Severity::Fail);
        assert!(result.detail.contains("REMNAWAVE_HWID"), "{}", result.detail);
    }

    #[test]
    fn an_inbound_nothing_leads_to_warns() {
        let snapshot = snap(
            vec![node(
                "alpha",
                false,
                true,
                "26.6.27",
                &["in-a", "in-lonely"],
            )],
            &["in-a"],
            &["ch-in-a"],
        );

        let results = monitoring_coverage(&snapshot);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "inbound in-lonely monitored");
        assert_eq!(results[0].severity, Severity::Warn);
        assert!(
            results[0].detail.contains("listening for nobody"),
            "{}",
            results[0].detail
        );
    }

    /// The receiving end of a cascade. No host points at it and none can:
    /// traffic arrives from the node before it, not from a client.
    #[test]
    fn an_inbound_a_cascade_routes_into_is_not_reported() {
        let mut snapshot = snap(
            vec![
                node("alpha", false, true, "26.6.27", &["in-a"]),
                node("beta", false, true, "26.6.27", &["in-bridge"]),
            ],
            &["in-a"],
            &["ch-in-a"],
        );
        snapshot.nodes[1].profile_uuid = Some("p-exit".into());
        snapshot.profiles = HashMap::from([
            (
                "p".to_string(),
                Profile {
                    uuid: "p".into(),
                    name: "gateway".into(),
                    config: json!({
                        "inbounds": [{"tag": "in-a", "port": 443}],
                        "outbounds": [{"tag": "to-beta", "protocol": "vless",
                            "settings": {"vnext": [{"address": snapshot.nodes[1].address, "port": 8443}]}}]
                    }),
                },
            ),
            (
                "p-exit".to_string(),
                Profile {
                    uuid: "p-exit".into(),
                    name: "exit".into(),
                    config: json!({
                        "inbounds": [{"tag": "in-bridge", "port": 8443}],
                        "outbounds": [{"tag": "direct", "protocol": "freedom"}]
                    }),
                },
            ),
        ]);

        let results = monitoring_coverage(&snapshot);

        assert!(results.is_empty(), "{results:?}");
    }

    /// The host exists and works; the panel simply never renders it in this
    /// subscription type, so the channel is checked by nothing here. Naming
    /// the host is what makes that actionable.
    #[test]
    fn an_inbound_whose_host_is_kept_out_of_this_subscription_names_it() {
        let mut snapshot = snap(
            vec![node("alpha", false, true, "26.6.27", &["in-private"])],
            &[],
            &[],
        );
        snapshot.excluded = vec![ExcludedHost {
            remark: "Россия-1".into(),
            inbound_tag: "in-private".into(),
        }];

        let results = monitoring_coverage(&snapshot);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].severity, Severity::Warn);
        assert!(
            results[0].detail.contains("Россия-1"),
            "{}",
            results[0].detail
        );
    }

    #[test]
    fn disabled_nodes_do_not_produce_coverage_warnings() {
        let snapshot = snap(
            vec![node("alpha", true, true, "26.6.27", &["in-lonely"])],
            &[],
            &[],
        );

        let results = monitoring_coverage(&snapshot);

        assert!(results.is_empty());
    }

    #[test]
    fn one_xray_version_across_the_fleet_is_no_drift() {
        let nodes = [
            node("alpha", false, true, "26.6.27", &[]),
            node("beta", false, true, "26.6.27", &[]),
        ];

        let result = xray_version_drift(&nodes);

        assert_eq!(result.severity, Severity::Ok);
    }

    #[test]
    fn xray_version_drift_names_both_versions() {
        let nodes = [
            node("alpha", false, true, "26.6.27", &[]),
            node("beta", false, true, "26.3.27", &[]),
        ];

        let result = xray_version_drift(&nodes);

        assert_eq!(result.severity, Severity::Warn);
        assert!(
            result.detail.contains("26.3.27")
                && result.detail.contains("26.6.27")
        );
    }

    #[test]
    fn remnanode_version_drift_reads_the_agent_version() {
        let mut alpha = node("alpha", false, true, "26.6.27", &[]);
        let mut beta = node("beta", false, true, "26.6.27", &[]);
        alpha.node_version = Some("3.3.2".into());
        beta.node_version = Some("3.2.3".into());

        let result = remnanode_version_drift(&[alpha, beta]);

        assert_eq!(result.name, "remnanode version drift");
        assert_eq!(result.severity, Severity::Warn);
        assert!(
            result.detail.contains("3.2.3") && result.detail.contains("3.3.2"),
            "{}",
            result.detail
        );
    }

    #[rstest]
    #[case::connected_with_users(false, true, 12, Some(Severity::Ok))]
    #[case::connected_with_nobody(false, true, 0, Some(Severity::Warn))]
    #[case::disconnected_is_skipped(false, false, 0, None)]
    #[case::disabled_is_skipped(true, true, 0, None)]
    fn users_online_judges_only_active_nodes(
        #[case] disabled: bool,
        #[case] connected: bool,
        #[case] online: u64,
        #[case] expected: Option<Severity>,
    ) {
        let mut node = active("alpha");
        node.is_disabled = disabled;
        node.is_connected = connected;
        node.users_online = online;

        let results = users_online(&[node]);

        assert_eq!(results.first().map(|r| r.severity), expected);
        if let Some(result) = results.first() {
            assert_eq!(result.name, "node alpha / users online");
        }
    }

    #[rstest]
    #[case::core_never_started(0, Severity::Fail)]
    #[case::fresh(3 * 86_400, Severity::Ok)]
    #[case::stale(9 * 86_400, Severity::Warn)]
    fn config_age_reads_xray_uptime(
        #[case] uptime: u64,
        #[case] expected: Severity,
    ) {
        let mut node = active("alpha");
        node.xray_uptime_secs = uptime;
        let sut = checker();

        let results = sut.config_age(&[node]);

        assert_eq!(results[0].name, "node alpha / config age");
        assert_eq!(results[0].severity, expected, "{}", results[0].detail);
    }

    #[rstest]
    #[case::calm(0.5, 2, 50, Severity::Ok)]
    #[case::overloaded(5.0, 2, 50, Severity::Warn)]
    #[case::out_of_memory(0.5, 2, 5, Severity::Warn)]
    fn host_warns_on_load_or_memory(
        #[case] load1: f64,
        #[case] cpus: u32,
        #[case] mem_free_pct: u64,
        #[case] expected: Severity,
    ) {
        let mut node = active("alpha");
        node.system = Some(HostStats {
            cpus,
            memory_total: 1_000,
            memory_free: mem_free_pct * 10,
            load_avg: vec![load1, load1, load1],
            uptime_secs: 40 * 86_400,
        });
        let sut = checker();

        let results = sut.host(&[node]);

        assert_eq!(results[0].name, "node alpha / host");
        assert_eq!(results[0].severity, expected, "{}", results[0].detail);
        assert!(results[0].detail.contains("40d"), "{}", results[0].detail);
    }

    #[test]
    fn a_node_without_system_stats_has_no_host_result() {
        let nodes = [active("alpha")];
        let sut = checker();

        let results = sut.host(&nodes);

        assert!(results.is_empty());
    }

    #[test]
    fn all_runs_every_panel_family_in_report_order() {
        let snapshot = snap(vec![active("alpha")], &["in-a"], &["ch-in-a"]);
        let sut = checker();

        let results = sut.all(&snapshot);

        let names: Vec<String> = results.into_iter().map(|r| r.name).collect();
        assert_eq!(
            names,
            vec![
                "node alpha / panel status",
                "node alpha / users online",
                "node alpha / config age",
                "xray version drift",
                "remnanode version drift",
                "subscription coverage",
            ]
        );
    }
}
