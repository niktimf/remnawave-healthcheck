//! Everything about one channel that is decided without opening a tunnel, and
//! the verdict once the tunnel has answered.

use crate::model::{
    Channel, CheckResult, Node, ProbeOutcome, Snapshot, XhttpFacts,
};
use crate::topology::Resolver;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

/// The three ways a pre-probe examination ends: probe it, here is the result,
/// or it is a selector and its verdict waits for the other channels.
#[derive(Debug)]
pub enum Precheck<'a> {
    Probe(&'a Node),
    Decided(CheckResult),
    Selector,
}

/// Resolve the expected exit and rule out channels that must not be probed:
/// an unresolvable route, a disabled exit node, a config the subscription never
/// served (probing `Null` would blame the tunnel after two full timeouts).
pub fn precheck<'a>(channel: &Channel, snapshot: &'a Snapshot) -> Precheck<'a> {
    let name = channel.name();
    if channel.served.is_selector() {
        return Precheck::Selector;
    }
    let expect = match Resolver::new(snapshot).exit_of(channel) {
        Ok(expect) => expect,
        Err(e) => {
            return Precheck::Decided(CheckResult::fail(
                name,
                format!("cannot tell where this channel should exit: {e}"),
            ));
        }
    };
    if !expect.is_enabled() {
        return Precheck::Decided(CheckResult::warn(
            name,
            format!("expected exit '{}' is disabled in the panel", expect.name),
        ));
    }
    if channel.served.outbound().is_none() {
        return Precheck::Decided(CheckResult::fail(
            name,
            "the panel resolved this channel but the subscription served no config for it, so there is nothing to probe",
        ));
    }
    Precheck::Probe(expect)
}

/// Compare where the tunnel came out with where the exit node says it leaves.
/// An unknown expected address downgrades to WARN: the report never claims a
/// verification it did not perform.
pub fn classify(
    channel: &Channel,
    expect: &Node,
    expect_ip: Option<IpAddr>,
    outcome: &ProbeOutcome,
) -> CheckResult {
    let name = channel.name();
    match (outcome.exit_ip, expect_ip) {
        (None, _) => {
            let xray = if outcome.stderr_tail.is_empty() {
                String::new()
            } else {
                format!(" | xray: {}", outcome.stderr_tail)
            };
            CheckResult::fail(name, format!("no exit (tunnel dead){xray}"))
        }
        (Some(got), None) => CheckResult::warn(
            name,
            format!(
                "exit {got}, but the egress address of expected node '{}' is unknown",
                expect.name
            ),
        ),
        (Some(got), Some(want)) if got == want => {
            CheckResult::ok(name, format!("exit {got} ({})", expect.name))
        }
        (Some(got), Some(want)) => CheckResult::fail(
            name,
            format!("wrong exit {got} (want {want} = {})", expect.name),
        ),
    }
}

/// What the tunnels found, when they were run at all. Without them a
/// balancer's size is all that can be verified, and the verdict says so.
#[derive(Debug, Clone, Copy)]
pub enum Liveness<'a> {
    NotRun,
    /// Indices, into `Snapshot::channels`, of the channels whose tunnel came
    /// out somewhere.
    Alive(&'a HashSet<usize>),
}

/// The candidates of a selector, as indices of the channels they were injected
/// from. The injector copies a host's outbound and only renames its tag, so
/// that is what the two are compared by; a candidate matching nothing is left
/// out rather than counted as dead.
fn matched_candidates(channel: &Channel, snapshot: &Snapshot) -> Vec<usize> {
    let same = |a: &Value, b: &Value| {
        let untagged = |v: &Value| {
            let mut v = v.clone();
            v.as_object_mut().map(|o| o.remove("tag"));
            v
        };
        untagged(a) == untagged(b)
    };
    channel
        .served
        .candidates()
        .iter()
        .filter_map(|candidate| {
            snapshot.channels.iter().position(|c| {
                c.served.outbound().is_some_and(|o| same(o, candidate))
            })
        })
        .collect()
}

/// A selector routes through a balancer over other channels, so what it can
/// break in is its own way: the injector selecting nobody, or every channel it
/// selected being dead. Its own `address:port` is a placeholder and there is no
/// tunnel of its own to run.
pub fn selector(
    channel: &Channel,
    snapshot: &Snapshot,
    liveness: Liveness<'_>,
) -> CheckResult {
    let name = format!("{} / balancer", channel.name());
    let total = channel.served.candidates().len();
    if total == 0 {
        return CheckResult::fail(
            name,
            "the subscription served a balancer with no candidates: the injector's selector matched no host, so this channel routes nowhere",
        );
    }
    let unjudged = |why: &str| {
        let detail = format!("balancer over {total} candidates, {why}");
        if total == 1 {
            CheckResult::warn(
                name.clone(),
                format!(
                    "{detail}; a balancer over one candidate has nothing to choose between"
                ),
            )
        } else {
            CheckResult::ok(name.clone(), detail)
        }
    };
    let Liveness::Alive(alive) = liveness else {
        return unjudged("their tunnels were not run");
    };
    let matched = matched_candidates(channel, snapshot);
    if matched.is_empty() {
        return unjudged(
            "none of them could be matched to a channel of this subscription, so their tunnels were not judged",
        );
    }
    let live = matched.iter().filter(|i| alive.contains(i)).count();
    match live {
        0 => CheckResult::fail(
            name,
            format!(
                "no live candidate out of {total}: every channel this selector routes through is dead, so auto-select is dead"
            ),
        ),
        1 => CheckResult::warn(
            name,
            format!(
                "only one live candidate out of {total}: auto-select has nothing to choose between"
            ),
        ),
        _ => CheckResult::ok(
            name,
            format!("balancer over {total} candidates, {live} of {total} live"),
        ),
    }
}

/// The one result that stands in for every channel when probing could not be
/// set up at all.
pub fn setup_failed(detail: impl Into<String>) -> CheckResult {
    CheckResult::fail("channels setup", detail)
}

/// Both path forms of an xhttp inbound must answer 400 (path accepted, session
/// invalid). 404 without the slash is xray #6307: node and client versions skew.
/// What a live xhttp inbound answers a probe that is not a real client: xray
/// read the request and refused its contents. Both path forms must give this,
/// so here it is the healthy status rather than a complaint.
const XHTTP_ALIVE: u16 = 400;

/// What a node running xray from before XTLS/Xray-core#6307 answers for the
/// form without the trailing slash, while the slash form still works.
const XHTTP_STALE_PATH: u16 = 404;

/// The path configured on the inbound that serves `channel`.
///
/// xray matches an xhttp request by prefix. With `sessionID` and `seq` left in
/// the path — the default — it appends a slash to that prefix itself, so an
/// inbound configured as `/p` answers `404` to a bare `/p` and `400` to `/p/`:
/// correct, not a fault. An inbound whose configured path already ends in a
/// slash takes both forms, and a `404` there is the skew of xray #6307.
fn inbound_xhttp_path<'a>(
    channel: &Channel,
    snapshot: &'a Snapshot,
) -> Option<&'a str> {
    let profile = snapshot.profiles.get(channel.profile_uuid.as_deref()?)?;
    profile.config["inbounds"]
        .as_array()?
        .iter()
        .find(|i| {
            i.get("tag").and_then(Value::as_str) == Some(&channel.inbound_tag)
        })?
        .pointer("/streamSettings/xhttpSettings/path")?
        .as_str()
}

pub fn xhttp(
    channel: &Channel,
    facts: &XhttpFacts,
    snapshot: &Snapshot,
) -> CheckResult {
    // The full channel name, not just the remark: a remark template can
    // collapse several hosts onto one name, and two such rows would otherwise
    // be indistinguishable in the report.
    let name = format!("{} / xhttp path", channel.name());
    let slash_is_part_of_the_prefix = inbound_xhttp_path(channel, snapshot)
        .is_some_and(|path| !path.ends_with('/'));
    match (&facts.without_slash, &facts.with_slash) {
        (Ok(XHTTP_ALIVE), Ok(XHTTP_ALIVE)) => CheckResult::ok(
            name,
            format!("both path forms answer {XHTTP_ALIVE}"),
        ),
        (Ok(XHTTP_STALE_PATH), Ok(XHTTP_ALIVE))
            if slash_is_part_of_the_prefix =>
        {
            CheckResult::ok(
                name,
                format!(
                    "{XHTTP_ALIVE} with the trailing slash; the inbound keeps the session in the path, so xray takes that slash as part of its prefix and {XHTTP_STALE_PATH} without it is expected"
                ),
            )
        }
        (Ok(XHTTP_STALE_PATH), Ok(XHTTP_ALIVE)) => CheckResult::fail(
            name,
            format!(
                "{XHTTP_STALE_PATH} without the trailing slash, {XHTTP_ALIVE} with it, though the inbound path is a prefix that should take both: xray #6307 (client/node version skew), update xray on the node"
            ),
        ),
        (Ok(a), Ok(b)) => CheckResult::fail(
            name,
            format!(
                "unexpected statuses: {a} without slash, {b} with slash (want {XHTTP_ALIVE}/{XHTTP_ALIVE})"
            ),
        ),
        (Err(e), _) | (_, Err(e)) => {
            CheckResult::fail(name, format!("request failed: {e}"))
        }
    }
}

/// The version the enabled nodes run, most common one when they disagree —
/// `xray version drift` has already warned about that.
pub fn required_xray_version(snapshot: &Snapshot) -> Option<String> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Profile, Served, Severity, parse_ip};
    use rstest::rstest;
    use serde_json::{Value, json};
    use std::collections::HashSet;

    fn snapshot(outbound: Value) -> Snapshot {
        let served = if outbound.is_null() {
            Served::Nothing
        } else {
            Served::Direct(outbound)
        };
        let node = Node {
            name: "beta".into(),
            address: "beta.example.com".into(),
            inbound_tags: vec!["in-exit".into()],
            profile_uuid: Some("p-exit".into()),
            is_connected: true,
            xray_version: Some("26.6.27".into()),
            ..Default::default()
        };
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
                served,
                ..Default::default()
            }],
            served_remarks: vec!["beta direct".into()],
            ..Default::default()
        }
    }

    /// A snapshot whose nodes carry the given xray versions, the first one
    /// being the channel's exit.
    fn fleet(versions: &[(&str, &str, bool)]) -> Snapshot {
        let mut s = snapshot(json!({}));
        let template = s.nodes[0].clone();
        s.nodes.clear();
        for (name, version, disabled) in versions {
            let mut node = template.clone();
            node.name = (*name).to_string();
            node.xray_version = Some((*version).to_string());
            node.is_disabled = *disabled;
            s.nodes.push(node);
        }
        s
    }

    fn decided(p: Precheck<'_>) -> CheckResult {
        match p {
            Precheck::Decided(r) => r,
            Precheck::Probe(n) => {
                panic!("expected a decided channel, got exit {}", n.name)
            }
            Precheck::Selector => panic!("expected a decided channel"),
        }
    }

    /// A snapshot whose second channel is a selector over the given candidate
    /// outbounds. The first channel stays an ordinary one, so a candidate can
    /// be matched back to it.
    fn snapshot_with_selector(candidates: Vec<Value>) -> Snapshot {
        let mut s = snapshot(json!({"tag": "proxy", "protocol": "vless"}));
        let mut auto = s.channels[0].clone();
        auto.remark = "auto".into();
        auto.address = "auto.wifi.host.com".into();
        auto.port = 1234;
        auto.served = Served::Selector(candidates);
        s.channels.push(auto);
        s
    }

    /// The injector copies a host's outbound and only renames its tag, so the
    /// candidate below is the first channel of the snapshot.
    fn candidate_of_the_first_channel() -> Value {
        json!({"tag": "cand-1", "protocol": "vless"})
    }

    #[test]
    fn a_selector_has_no_exit_of_its_own_and_is_not_probed() {
        let s = snapshot_with_selector(vec![candidate_of_the_first_channel()]);

        let precheck = precheck(&s.channels[1], &s);

        assert!(matches!(precheck, Precheck::Selector), "{precheck:?}");
    }

    /// The selector matched no host — the tag it selects on was renamed, say.
    /// Every channel stays green and the auto-select entry routes nowhere.
    #[test]
    fn a_balancer_over_no_candidates_fails() {
        let s = snapshot_with_selector(vec![]);

        let result = selector(&s.channels[1], &s, Liveness::NotRun);

        assert_eq!(
            result.name,
            "channel auto (auto.wifi.host.com:1234) / balancer"
        );
        assert_eq!(result.severity, Severity::Fail);
        assert!(result.detail.contains("no candidates"), "{}", result.detail);
    }

    #[rstest]
    #[case::several_live(2, Severity::Ok, "2 of 2 live")]
    #[case::one_live(1, Severity::Warn, "only one live candidate")]
    #[case::none_live(0, Severity::Fail, "no live candidate")]
    fn balancer_table(
        #[case] live: usize,
        #[case] expected: Severity,
        #[case] mentions: &str,
    ) {
        let mut s = snapshot_with_selector(vec![]);
        let mut second = s.channels[0].clone();
        second.remark = "gamma direct".into();
        second.served =
            Served::Direct(json!({"tag": "proxy", "protocol": "trojan"}));
        s.channels.insert(1, second);
        s.channels[2].served = Served::Selector(vec![
            candidate_of_the_first_channel(),
            json!({"tag": "cand-2", "protocol": "trojan"}),
        ]);
        let alive: HashSet<usize> = (0..live).collect();

        let result = selector(&s.channels[2], &s, Liveness::Alive(&alive));

        assert_eq!(result.severity, expected, "{}", result.detail);
        assert!(result.detail.contains(mentions), "{}", result.detail);
    }

    /// Without tunnels the size of the balancer is all that was verified, and
    /// the verdict says so rather than implying the candidates answered.
    #[test]
    fn a_balancer_judged_without_tunnels_reports_only_its_size() {
        let s = snapshot_with_selector(vec![candidate_of_the_first_channel()]);

        let result = selector(&s.channels[1], &s, Liveness::NotRun);

        assert!(result.detail.contains("not run"), "{}", result.detail);
    }

    /// A candidate that matches no channel cannot be judged live or dead;
    /// counting it as dead would turn a matching bug into a fleet-wide alarm.
    #[test]
    fn candidates_that_match_no_channel_leave_liveness_unjudged() {
        let s = snapshot_with_selector(vec![
            json!({"tag": "cand-1", "protocol": "trojan"}),
            json!({"tag": "cand-2", "protocol": "trojan"}),
        ]);
        let alive = HashSet::new();

        let result = selector(&s.channels[1], &s, Liveness::Alive(&alive));

        assert_eq!(result.severity, Severity::Ok, "{}", result.detail);
        assert!(result.detail.contains("matched"), "{}", result.detail);
    }

    #[test]
    fn a_probeable_channel_yields_its_expected_exit() {
        let s = snapshot(json!({"protocol": "vless"}));

        let precheck = precheck(&s.channels[0], &s);

        match precheck {
            Precheck::Probe(node) => assert_eq!(node.name, "beta"),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn a_channel_the_subscription_never_served_fails_without_a_probe() {
        let s = snapshot(Value::Null);

        let result = decided(precheck(&s.channels[0], &s));

        assert_eq!(result.name, "channel beta direct (beta.example.com:443)");
        assert_eq!(result.severity, Severity::Fail);
        assert!(
            result.detail.contains("subscription")
                && !result.detail.contains("tunnel"),
            "{}",
            result.detail
        );
    }

    #[test]
    fn a_channel_whose_exit_is_disabled_only_warns() {
        let mut s = snapshot(json!({"protocol": "vless"}));
        s.nodes[0].is_disabled = true;

        let result = decided(precheck(&s.channels[0], &s));

        assert_eq!(result.severity, Severity::Warn);
        assert!(result.detail.contains("beta"), "{}", result.detail);
    }

    #[test]
    fn an_unresolvable_route_fails_with_the_resolver_reason() {
        let mut s = snapshot(json!({"protocol": "vless"}));
        s.channels[0].profile_uuid = None;

        let result = decided(precheck(&s.channels[0], &s));

        assert_eq!(result.severity, Severity::Fail);
        assert!(
            result.detail.contains("cannot tell where"),
            "{}",
            result.detail
        );
    }

    #[rstest]
    #[case::matching(
        Some("192.0.2.20"),
        Some("192.0.2.20"),
        "",
        Severity::Ok,
        "exit 192.0.2.20 (beta)"
    )]
    #[case::wrong(
        Some("203.0.113.7"),
        Some("192.0.2.20"),
        "",
        Severity::Fail,
        "wrong exit 203.0.113.7 (want 192.0.2.20 = beta)"
    )]
    #[case::dead(
        None,
        Some("192.0.2.20"),
        "failed to dial",
        Severity::Fail,
        "no exit (tunnel dead) | xray: failed to dial"
    )]
    #[case::unverified(
        Some("203.0.113.7"),
        None,
        "",
        Severity::Warn,
        "exit 203.0.113.7, but the egress address of expected node 'beta' is unknown"
    )]
    fn classify_table(
        #[case] got: Option<&str>,
        #[case] want: Option<&str>,
        #[case] stderr: &str,
        #[case] expected: Severity,
        #[case] detail: &str,
    ) {
        let s = snapshot(json!({"protocol": "vless"}));
        let outcome = ProbeOutcome {
            exit_ip: got.and_then(parse_ip),
            stderr_tail: stderr.into(),
        };

        let result = classify(
            &s.channels[0],
            &s.nodes[0],
            want.and_then(parse_ip),
            &outcome,
        );

        assert_eq!(result.name, "channel beta direct (beta.example.com:443)");
        assert_eq!(result.severity, expected);
        assert_eq!(result.detail, detail);
    }

    /// A snapshot whose exit inbound declares an xhttp path.
    fn snapshot_with_xhttp_path(inbound_path: &str) -> Snapshot {
        let mut s = snapshot(json!({"protocol": "vless"}));
        let profile = s.profiles.get_mut("p-exit").unwrap();
        profile.config["inbounds"][0]["streamSettings"] = json!({
            "network": "xhttp",
            "xhttpSettings": {"path": inbound_path, "mode": "auto"}
        });
        s
    }

    /// With sessionID and seq in the path — the default — xray appends the
    /// slash to its own prefix, so the bare form cannot match it and 404 is
    /// what a healthy inbound answers.
    #[test]
    fn a_bare_path_404_is_expected_when_the_inbound_path_has_no_slash() {
        let s = snapshot_with_xhttp_path("/api/v1/vless/de");
        let facts = XhttpFacts {
            without_slash: Ok(404),
            with_slash: Ok(400),
        };

        let result = xhttp(&s.channels[0], &facts, &s);

        assert_eq!(result.severity, Severity::Ok, "{}", result.detail);
    }

    /// A prefix path ending in a slash accepts both forms, so a 404 there is
    /// the skew of xray #6307 and breaks clients that omit the slash.
    #[test]
    fn a_bare_path_404_is_a_failure_when_the_inbound_path_ends_in_a_slash() {
        let s = snapshot_with_xhttp_path("/api/v1/traces/");
        let facts = XhttpFacts {
            without_slash: Ok(404),
            with_slash: Ok(400),
        };

        let result = xhttp(&s.channels[0], &facts, &s);

        assert_eq!(result.severity, Severity::Fail);
        assert!(result.detail.contains("#6307"), "{}", result.detail);
    }

    #[rstest]
    #[case::healthy(
        Ok(400),
        Ok(400),
        Severity::Ok,
        "both path forms answer 400"
    )]
    #[case::bug_6307(Ok(404), Ok(400), Severity::Fail, "xray #6307")]
    #[case::something_else(Ok(200), Ok(200), Severity::Fail, "want 400/400")]
    #[case::unreachable_without(
        Err("connect timeout".to_string()),
        Ok(400),
        Severity::Fail,
        "request failed: connect timeout"
    )]
    #[case::unreachable_with(
        Ok(400),
        Err("reset".to_string()),
        Severity::Fail,
        "request failed: reset"
    )]
    fn xhttp_table(
        #[case] without_slash: Result<u16, String>,
        #[case] with_slash: Result<u16, String>,
        #[case] expected: Severity,
        #[case] mentions: &str,
    ) {
        let s = snapshot(json!({"protocol": "vless"}));
        let facts = XhttpFacts {
            without_slash,
            with_slash,
        };

        let result = xhttp(&s.channels[0], &facts, &s);

        assert_eq!(
            result.name,
            "channel beta direct (beta.example.com:443) / xhttp path"
        );
        assert_eq!(result.severity, expected, "{}", result.detail);
        assert!(
            result.detail.contains(mentions),
            "detail missing '{}': {}",
            mentions,
            result.detail
        );
    }

    #[test]
    fn a_disabled_node_does_not_vote_on_the_xray_version() {
        let s = fleet(&[
            ("beta", "26.6.27", false),
            ("gamma", "26.3.27", false),
            ("delta", "26.3.27", true),
        ]);

        let version = required_xray_version(&s);

        assert_eq!(version.as_deref(), Some("26.6.27"));
    }

    #[test]
    fn a_true_majority_beats_a_lexicographically_larger_minority() {
        let s = fleet(&[
            ("beta", "24.0.0", false),
            ("gamma", "24.0.0", false),
            ("delta", "30.0.0", false),
        ]);

        let version = required_xray_version(&s);

        assert_eq!(version.as_deref(), Some("24.0.0"));
    }

    #[test]
    fn a_fleet_that_reports_no_version_pins_nothing() {
        let mut s = fleet(&[("beta", "26.6.27", false)]);
        s.nodes.iter_mut().for_each(|n| n.xray_version = None);

        let version = required_xray_version(&s);

        assert_eq!(version, None);
    }

    #[test]
    fn setup_failure_is_the_channels_setup_result() {
        let result = setup_failed("obtaining xray: connection refused");

        assert_eq!(result.name, "channels setup");
        assert_eq!(result.severity, Severity::Fail);
    }
}
