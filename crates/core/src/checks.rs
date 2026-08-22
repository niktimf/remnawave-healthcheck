use crate::model::{CheckResult, Node, Severity, Snapshot};
use std::collections::{BTreeMap, BTreeSet};

/// What the panel itself thinks of each node. Costs no SSH and no tunnels.
pub fn node_status(nodes: &[Node]) -> Vec<CheckResult> {
    nodes
        .iter()
        .map(|n| {
            let key = format!("node:{}:panel", n.name);
            let title = format!("{} panel status", n.name);
            if n.is_disabled {
                CheckResult::new(key, title, Severity::Warn, "disabled by an administrator")
            } else if !n.is_connected {
                let reason = n
                    .last_status_message
                    .as_deref()
                    .unwrap_or("no reason given");
                CheckResult::new(
                    key,
                    title,
                    Severity::Fail,
                    format!("not connected: {reason}"),
                )
            } else {
                CheckResult::new(key, title, Severity::Ok, "connected")
            }
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
    let resolved: BTreeSet<&str> = snapshot
        .channels
        .iter()
        .map(|c| c.remark.as_str())
        .collect();
    // Counted in one pass: both the set of served remarks and the ones served more than once come
    // out of the same tally.
    let mut tally: BTreeMap<&str, usize> = BTreeMap::new();
    for remark in &snapshot.served_remarks {
        *tally.entry(remark.as_str()).or_default() += 1;
    }
    let served: BTreeSet<&str> = tally.keys().copied().collect();

    let missing: Vec<&str> = resolved.difference(&served).copied().collect();
    let unexpected: Vec<&str> = served.difference(&resolved).copied().collect();
    // A remark served twice makes the join ambiguous: both channels would be probed with whichever
    // outbound happened to win, so one of them would be reported on evidence that is not its own.
    let duplicated: Vec<&str> = tally
        .iter()
        .filter(|(_, count)| **count > 1)
        .map(|(remark, _)| *remark)
        .collect();

    let key = "subscription:coverage";
    let title = "subscription coverage";
    if missing.is_empty() && unexpected.is_empty() && duplicated.is_empty() {
        return CheckResult::new(
            key,
            title,
            Severity::Ok,
            format!(
                "subscription served all {} resolved channels",
                resolved.len()
            ),
        );
    }

    let mut parts = Vec::new();
    if !missing.is_empty() {
        parts.push(format!("not served: {}", missing.join(", ")));
    }
    if !unexpected.is_empty() {
        parts.push(format!(
            "served but not resolved by the panel: {}",
            unexpected.join(", ")
        ));
    }
    if !duplicated.is_empty() {
        parts.push(format!(
            "served more than once, so their configs cannot be told apart: {}",
            duplicated.join(", ")
        ));
    }
    CheckResult::new(key, title, Severity::Fail, parts.join("; "))
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

    for node in snapshot.nodes.iter().filter(|n| !n.is_disabled) {
        for tag in &node.inbound_tags {
            if covered.contains(tag.as_str()) || !seen.insert(tag.as_str()) {
                continue;
            }
            out.push(CheckResult::new(
                format!("monitoring:coverage:{tag}"),
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
        .filter(|n| !n.is_disabled)
        .filter_map(|n| n.xray_version.as_deref())
        .collect::<BTreeSet<&str>>()
        .into_iter()
        .collect();

    let key = "xray:version-drift";
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
