//! Everything about one channel that is decided without opening a tunnel, and
//! the verdict once the tunnel has answered.

use crate::model::{
    Channel, CheckResult, Node, ProbeOutcome, Snapshot, XhttpFacts,
};
use crate::topology::Resolver;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::net::IpAddr;

/// The two ways a pre-probe examination ends: probe it, or here is the result.
#[derive(Debug)]
pub enum Precheck<'a> {
    Probe(&'a Node),
    Decided(CheckResult),
}

/// Resolve the expected exit and rule out channels that must not be probed:
/// an unresolvable route, a disabled exit node, a config the subscription never
/// served (probing `Null` would blame the tunnel after two full timeouts).
pub fn precheck<'a>(channel: &Channel, snapshot: &'a Snapshot) -> Precheck<'a> {
    let name = channel.name();
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
    if channel.outbound.is_null() {
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
            let mut detail = "no exit (tunnel dead)".to_string();
            if !outcome.stderr_tail.is_empty() {
                let _ = write!(detail, " | xray: {}", outcome.stderr_tail);
            }
            CheckResult::fail(name, detail)
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

/// The one result that stands in for every channel when probing could not be
/// set up at all.
pub fn setup_failed(detail: impl Into<String>) -> CheckResult {
    CheckResult::fail("channels setup", detail)
}

/// Both path forms of an xhttp inbound must answer 400 (path accepted, session
/// invalid). 404 without the slash is xray #6307: node and client versions skew.
pub fn xhttp(channel: &Channel, facts: &XhttpFacts) -> CheckResult {
    let name = format!("channel {} / xhttp path", channel.remark);
    match (&facts.without_slash, &facts.with_slash) {
        (Ok(400), Ok(400)) => {
            CheckResult::ok(name, "both path forms answer 400")
        }
        (Ok(404), Ok(400)) => CheckResult::fail(
            name,
            "404 without the trailing slash, 400 with it: xray #6307 (client/node version skew), update xray on the node",
        ),
        (Ok(a), Ok(b)) => CheckResult::fail(
            name,
            format!(
                "unexpected statuses: {a} without slash, {b} with slash (want 400/400)"
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
    use crate::model::{Profile, Severity, parse_ip};
    use rstest::rstest;
    use serde_json::{Value, json};

    fn snapshot(outbound: Value) -> Snapshot {
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
                outbound,
                ..Default::default()
            }],
            served_remarks: vec!["beta direct".into()],
            ..Default::default()
        }
    }

    fn decided(p: Precheck<'_>) -> CheckResult {
        match p {
            Precheck::Decided(r) => r,
            Precheck::Probe(n) => {
                panic!("expected a decided channel, got exit {}", n.name)
            }
        }
    }

    #[test]
    fn a_probeable_channel_yields_its_expected_exit() {
        let s = snapshot(json!({"protocol": "vless"}));
        match precheck(&s.channels[0], &s) {
            Precheck::Probe(n) => assert_eq!(n.name, "beta"),
            Precheck::Decided(r) => panic!("unexpected {r:?}"),
        }
    }

    #[test]
    fn a_channel_the_subscription_never_served_fails_without_a_probe() {
        let s = snapshot(Value::Null);
        let r = decided(precheck(&s.channels[0], &s));
        assert_eq!(r.severity, Severity::Fail);
        assert_eq!(r.name, "channel beta direct (beta.example.com:443)");
        assert!(
            r.detail.contains("subscription") && !r.detail.contains("tunnel"),
            "{}",
            r.detail
        );
    }

    #[test]
    fn a_channel_whose_exit_is_disabled_only_warns() {
        let mut s = snapshot(json!({"protocol": "vless"}));
        s.nodes[0].is_disabled = true;
        let r = decided(precheck(&s.channels[0], &s));
        assert_eq!(r.severity, Severity::Warn);
        assert!(r.detail.contains("beta"), "{}", r.detail);
    }

    #[test]
    fn an_unresolvable_route_fails_with_the_resolver_reason() {
        let mut s = snapshot(json!({"protocol": "vless"}));
        s.channels[0].profile_uuid = None;
        let r = decided(precheck(&s.channels[0], &s));
        assert_eq!(r.severity, Severity::Fail);
        assert!(r.detail.contains("cannot tell where"), "{}", r.detail);
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
        let r = classify(
            &s.channels[0],
            &s.nodes[0],
            want.and_then(parse_ip),
            &outcome,
        );
        assert_eq!(r.severity, expected);
        assert_eq!(r.detail, detail);
        assert_eq!(r.name, "channel beta direct (beta.example.com:443)");
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
        let r = xhttp(
            &s.channels[0],
            &XhttpFacts {
                without_slash,
                with_slash,
            },
        );
        assert_eq!(r.severity, expected, "{}", r.detail);
        assert!(
            r.detail.contains(mentions),
            "detail missing '{}': {}",
            mentions,
            r.detail
        );
        assert_eq!(r.name, "channel beta direct / xhttp path");
    }

    #[test]
    fn the_most_common_xray_version_wins_and_disabled_nodes_do_not_vote() {
        let mut s = snapshot(json!({}));
        let mut b = s.nodes[0].clone();
        b.name = "gamma".into();
        b.xray_version = Some("26.3.27".into());
        let mut c = b.clone();
        c.name = "delta".into();
        c.is_disabled = true;
        s.nodes.push(b);
        s.nodes.push(c);
        assert_eq!(required_xray_version(&s).as_deref(), Some("26.6.27"));
        s.nodes.iter_mut().for_each(|n| n.xray_version = None);
        assert_eq!(required_xray_version(&s), None);
    }

    #[test]
    fn a_true_majority_beats_a_lexicographically_larger_minority() {
        let mut s = snapshot(json!({}));
        s.nodes[0].xray_version = Some("24.0.0".into());
        let mut b = s.nodes[0].clone();
        b.name = "gamma".into();
        b.xray_version = Some("24.0.0".into());
        let mut c = b.clone();
        c.name = "delta".into();
        c.xray_version = Some("30.0.0".into());
        s.nodes.push(b);
        s.nodes.push(c);
        assert_eq!(required_xray_version(&s).as_deref(), Some("24.0.0"));
    }

    #[test]
    fn setup_failure_is_the_channels_setup_result() {
        let r = setup_failed("obtaining xray: connection refused");
        assert_eq!(r.name, "channels setup");
        assert_eq!(r.severity, Severity::Fail);
    }
}
