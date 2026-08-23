use crate::keys::{CheckKey, NodeAspect};
use crate::model::{CheckResult, Node, PanelState, Severity, Snapshot};
use std::collections::{BTreeMap, BTreeSet};

/// What the panel itself thinks of each node. Costs no SSH and no tunnels.
pub fn node_status(nodes: &[Node]) -> Vec<CheckResult> {
    nodes
        .iter()
        .map(|n| {
            // Which state a node is in is the node's own question; what that state is worth in a
            // report is this module's. A reconnecting node is a warning rather than a failure
            // because the panel retries on its own, and it carries no reason: the message the
            // panel left behind is about the attempt before this one.
            let (severity, detail) = match n.panel_state() {
                PanelState::Disabled => {
                    (Severity::Warn, "disabled by an administrator".to_string())
                }
                PanelState::Connecting => (Severity::Warn, "connecting".to_string()),
                PanelState::Disconnected { reason } => (
                    Severity::Fail,
                    format!("not connected: {}", reason.unwrap_or("no reason given")),
                ),
                PanelState::Connected => (Severity::Ok, "connected".to_string()),
            };
            let aspect = NodeAspect::Panel;
            CheckResult::new(
                CheckKey::Node {
                    node: &n.name,
                    aspect,
                }
                .key(),
                format!("{} {}", n.name, aspect.title()),
                severity,
                detail,
            )
        })
        .collect()
}

/// The panel resolved a set of channels for the monitoring user; the rendered subscription served
/// a set of remarks. The two must be the same set — that join by remark is what gives every
/// channel its outbound, so a mismatch means channels are being probed with the wrong config or
/// not at all, while the panel still looks healthy.
///
/// Sets, not counts: one channel dropped and another one duplicated leaves the counts equal and
/// would have made a broken join look green.
pub fn subscription_coverage(snapshot: &Snapshot) -> CheckResult {
    let coverage = Coverage::of(snapshot);
    // The gaps are what decides the severity, so they are asked for once and the answer is used
    // for both: a run is healthy exactly when there is nothing to report, and the two can no
    // longer disagree about what "nothing" means.
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
    CheckResult::new(
        CheckKey::SubscriptionCoverage.key(),
        "subscription coverage",
        severity,
        detail,
    )
}

/// How the channels the panel resolved and the remarks the subscription served failed to line up.
///
/// Ordered sets rather than lists: a remark can be missing, unexpected or duplicated only once,
/// and the order these are reported in should not depend on which way the snapshot happened to be
/// built. Both properties hold today because every one of them comes out of a `BTree*`; keeping
/// them in the types is what stops a later rewrite from quietly reporting a name twice.
struct Coverage<'a> {
    /// How many channels the panel resolved — the number the healthy message reports.
    resolved: usize,
    /// Resolved by the panel, never served by the subscription.
    missing: BTreeSet<&'a str>,
    /// Served by the subscription, never resolved by the panel.
    unexpected: BTreeSet<&'a str>,
    /// Served more than once, with how many times. The count is kept because it says which
    /// mistake this is: twice is usually one host duplicated, while a dozen is a remark template
    /// in the panel collapsing that many hosts onto a single name.
    duplicated: BTreeMap<&'a str, usize>,
}

impl<'a> Coverage<'a> {
    fn of(snapshot: &'a Snapshot) -> Self {
        let resolved: BTreeSet<&str> = snapshot
            .channels
            .iter()
            .map(|c| c.remark.as_str())
            .collect();
        // Counted in one pass: both the set of served remarks and the ones served more than once
        // come out of the same tally.
        let mut tally: BTreeMap<&str, usize> = BTreeMap::new();
        for remark in &snapshot.served_remarks {
            *tally.entry(remark.as_str()).or_default() += 1;
        }
        let served: BTreeSet<&str> = tally.keys().copied().collect();

        Self {
            resolved: resolved.len(),
            missing: resolved.difference(&served).copied().collect(),
            unexpected: served.difference(&resolved).copied().collect(),
            // A remark served twice makes the join ambiguous: both channels would be probed with
            // whichever outbound happened to win, so one of them would be reported on evidence
            // that is not its own.
            duplicated: tally.into_iter().filter(|(_, times)| *times > 1).collect(),
        }
    }

    /// Every way the two sides disagree, one description apiece.
    ///
    /// One list, and the only place that enumerates the kinds of disagreement there are. A fourth
    /// kind is a row here and nothing else — which is the point: the old shape stated the same
    /// enumeration twice, once to render it and once to decide whether the check was green, and
    /// they could drift apart without a word from the compiler.
    fn gaps(&self) -> Vec<String> {
        let named = |remarks: &BTreeSet<&str>| commas(remarks.iter().copied());
        let counted = commas(
            self.duplicated
                .iter()
                .map(|(remark, times)| format!("{remark} \u{00d7}{times}")),
        );

        // An empty rendering is an absent gap: each of these lists is empty exactly when that
        // kind of disagreement did not happen.
        [
            ("not served", named(&self.missing)),
            (
                "served but not resolved by the panel",
                named(&self.unexpected),
            ),
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

/// Comma-separated list, the way every detail line in this module writes one.
fn commas(items: impl IntoIterator<Item = impl std::fmt::Display>) -> String {
    items
        .into_iter()
        .map(|item| item.to_string())
        .collect::<Vec<String>>()
        .join(", ")
}

/// Inbounds that are live on a node but never reach the monitoring user — typically the user was
/// not added to the squad, so the channel silently drops out of every check.
pub fn monitoring_coverage(snapshot: &Snapshot) -> Vec<CheckResult> {
    let covered: BTreeSet<&str> = snapshot
        .channels
        .iter()
        .map(|c| c.inbound_tag.as_str())
        .collect();
    let mut out = Vec::new();
    let mut seen: BTreeSet<&str> = BTreeSet::new();

    for node in snapshot.nodes.iter().filter(|n| n.is_enabled()) {
        for tag in &node.inbound_tags {
            if covered.contains(tag.as_str()) || !seen.insert(tag.as_str()) {
                continue;
            }
            out.push(CheckResult::new(
                CheckKey::MonitoringCoverage { inbound: tag }.key(),
                format!("inbound {tag} monitored"),
                Severity::Warn,
                format!(
                    "inbound '{tag}' on node '{}' is not in the monitoring user's subscription",
                    node.name
                ),
            ));
        }
    }
    out
}

/// Nodes running different Xray versions have broken channels for us before (client and node must
/// agree on features such as sessionIDTable). There is no configured expectation — the drift itself
/// is the signal.
pub fn xray_version_drift(nodes: &[Node]) -> CheckResult {
    let versions: Vec<&str> = nodes
        .iter()
        .filter(|n| n.is_enabled())
        .filter_map(|n| n.xray_version.as_deref())
        .collect::<BTreeSet<&str>>()
        .into_iter()
        .collect();

    let key = CheckKey::XrayVersionDrift.key();
    let title = "xray version drift";
    match versions.as_slice() {
        [] => CheckResult::new(key, title, Severity::Ok, "no versions reported"),
        [only] => CheckResult::new(key, title, Severity::Ok, format!("all nodes on {only}")),
        several => CheckResult::new(
            key,
            title,
            Severity::Warn,
            format!("nodes disagree: {}", several.join(", ")),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Channel;
    use serde_json::json;
    use std::collections::HashMap;

    fn node(name: &str, disabled: bool, connected: bool, version: &str, tags: &[&str]) -> Node {
        Node {
            name: name.into(),
            address: format!("192.0.2.{}", name.len()),
            profile_uuid: Some("p".into()),
            inbound_tags: tags.iter().map(|s| s.to_string()).collect(),
            inbound_ports: vec![443],
            is_disabled: disabled,
            is_connected: connected,
            is_connecting: false,
            last_status_message: Some("boom".into()),
            xray_version: Some(version.into()),
        }
    }

    fn snap(nodes: Vec<Node>, channel_tags: &[&str], served: &[&str]) -> Snapshot {
        Snapshot {
            nodes,
            profiles: HashMap::new(),
            channels: channel_tags
                .iter()
                .map(|t| Channel {
                    remark: format!("ch-{t}"),
                    inbound_tag: t.to_string(),
                    profile_uuid: Some("p".into()),
                    address: "edge.example.com".into(),
                    port: 443,
                    outbound: json!({}),
                })
                .collect(),
            served_remarks: served.iter().map(|r| r.to_string()).collect(),
        }
    }

    #[test]
    fn disabled_node_warns_and_disconnected_node_fails() {
        let results = node_status(&[
            node("alpha", true, true, "26.6.27", &["in-a"]),
            node("beta", false, false, "26.6.27", &["in-b"]),
            node("gamma", false, true, "26.6.27", &["in-c"]),
        ]);
        let by_key = |k: &str| results.iter().find(|r| r.key == k).unwrap().severity;
        assert_eq!(by_key("node:alpha:panel"), Severity::Warn);
        assert_eq!(by_key("node:beta:panel"), Severity::Fail);
        assert_eq!(by_key("node:gamma:panel"), Severity::Ok);
        let beta = results.iter().find(|r| r.key == "node:beta:panel").unwrap();
        assert!(
            beta.detail.contains("boom"),
            "panel's own message must reach the report"
        );
    }

    #[test]
    fn a_reconnecting_node_warns_without_repeating_a_stale_reason() {
        // `node` leaves a "boom" in `last_status_message`, which is what the panel does too: it
        // sets `isConnecting` without clearing the reason of the attempt before.
        let mut reconnecting = node("alpha", false, false, "26.6.27", &["in-a"]);
        reconnecting.is_connecting = true;
        let results = node_status(&[reconnecting]);
        assert_eq!(results[0].severity, Severity::Warn);
        assert_eq!(results[0].detail, "connecting");
        assert_eq!(results[0].key, "node:alpha:panel");
    }

    #[test]
    fn subscription_coverage_is_ok_only_when_the_two_sets_match() {
        let ok = subscription_coverage(&snap(vec![], &["in-a", "in-b"], &["ch-in-a", "ch-in-b"]));
        assert_eq!(ok.severity, Severity::Ok);
        let bad = subscription_coverage(&snap(vec![], &["in-a", "in-b"], &[]));
        assert_eq!(bad.severity, Severity::Fail);
        assert!(bad.detail.contains("ch-in-a") && bad.detail.contains("ch-in-b"));
    }

    #[test]
    fn subscription_coverage_names_the_channel_the_subscription_dropped() {
        let r = subscription_coverage(&snap(vec![], &["in-a", "in-b"], &["ch-in-a"]));
        assert_eq!(r.severity, Severity::Fail);
        assert!(r.detail.contains("ch-in-b"), "{}", r.detail);
        assert!(!r.detail.contains("ch-in-a"), "{}", r.detail);
    }

    #[test]
    fn one_channel_dropped_and_another_duplicated_no_longer_cancels_out() {
        // The counts match (two resolved, two served) but the join is broken: the old count-based
        // check reported this as green.
        let r = subscription_coverage(&snap(vec![], &["in-a", "in-b"], &["ch-in-a", "ch-in-a"]));
        assert_eq!(r.severity, Severity::Fail);
        assert!(r.detail.contains("ch-in-b"), "{}", r.detail);
        assert!(r.detail.contains("more than once"), "{}", r.detail);
        // How many times it was served is part of the reason: two is a duplicated host, a dozen
        // is a remark template collapsing that many hosts onto one name.
        assert!(r.detail.contains("ch-in-a \u{00d7}2"), "{}", r.detail);
    }

    #[test]
    fn a_remark_served_but_never_resolved_also_fails() {
        let r = subscription_coverage(&snap(vec![], &["in-a"], &["ch-in-a", "ch-ghost"]));
        assert_eq!(r.severity, Severity::Fail);
        assert!(r.detail.contains("ch-ghost"), "{}", r.detail);
    }

    #[test]
    fn inbound_not_covered_by_the_monitoring_user_warns() {
        let s = snap(
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
        let results = monitoring_coverage(&s);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].severity, Severity::Warn);
        assert!(results[0].detail.contains("in-lonely"));
        assert_eq!(results[0].key, "monitoring:coverage:in-lonely");
    }

    #[test]
    fn disabled_nodes_do_not_produce_coverage_warnings() {
        let s = snap(
            vec![node("alpha", true, true, "26.6.27", &["in-lonely"])],
            &[],
            &[],
        );
        assert!(monitoring_coverage(&s).is_empty());
    }

    #[test]
    fn xray_version_drift_warns_only_when_versions_differ() {
        let same = xray_version_drift(&[
            node("alpha", false, true, "26.6.27", &[]),
            node("beta", false, true, "26.6.27", &[]),
        ]);
        assert_eq!(same.severity, Severity::Ok);

        let drifted = xray_version_drift(&[
            node("alpha", false, true, "26.6.27", &[]),
            node("beta", false, true, "26.3.27", &[]),
        ]);
        assert_eq!(drifted.severity, Severity::Warn);
        assert!(drifted.detail.contains("26.3.27") && drifted.detail.contains("26.6.27"));
    }
}
