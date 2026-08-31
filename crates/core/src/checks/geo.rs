//! Verdicts over a geocheck report. The panel types `rawReport` as an opaque
//! object, so every field is read defensively: absent data is "no data".

use crate::model::{CheckResult, GeoFacts, GeoOutcome, Node, node_check};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt::Write;

#[derive(Debug, Clone, Copy)]
pub struct GeoThresholds {
    /// WARN at or above this `reputation.risk`.
    pub reputation_warn_risk: u32,
}

pub fn check_node(
    node: &Node,
    outcome: &GeoOutcome,
    t: &GeoThresholds,
) -> Vec<CheckResult> {
    match outcome {
        GeoOutcome::Failed(reason) => vec![CheckResult::warn(
            node_check(&node.name, "geocheck"),
            format!("no geocheck result: {reason}"),
        )],
        GeoOutcome::Done(facts) => vec![
            egress(node, facts),
            geo_consensus(node, &facts.report),
            reputation(node, &facts.report, *t),
            connectivity(node, &facts.report),
        ],
    }
}

fn text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn egress(node: &Node, facts: &GeoFacts) -> CheckResult {
    let name = node_check(&node.name, "egress address");
    let Some(ip) = facts.egress else {
        return CheckResult::warn(
            name,
            "geocheck reported no IPv4 address, so exits of channels expected to leave through this node cannot be verified",
        );
    };
    let identity = &facts.report["identity"];
    let mut detail = format!("egress {ip}");
    if let Some(asn) = identity.get("asn").and_then(text) {
        let asn = asn.strip_prefix("AS").map_or(asn.clone(), str::to_string);
        let _ = write!(detail, " AS{asn}");
    }
    if let Some(org) = identity.get("as_name").and_then(text) {
        let _ = write!(detail, " ({org})");
    }
    CheckResult::ok(name, detail)
}

/// Country shares out of `consensus`: `{ "DE": 61, "US": 32 }`, the same map
/// nested under `countries` / `votes` / `results`, or a list of
/// `{ country|code, percent|share }`. Anything else is no data.
fn country_shares(consensus: &Value) -> BTreeMap<String, f64> {
    let mut shares = BTreeMap::new();
    match consensus {
        Value::Object(map) => {
            for (k, v) in map {
                if k.len() == 2 {
                    if let Some(p) = v.as_f64() {
                        shares.insert(k.to_uppercase(), p);
                    }
                }
            }
            if shares.is_empty() {
                for key in ["countries", "votes", "results", "percentages"] {
                    if let Some(inner) = map.get(key) {
                        shares = country_shares(inner);
                        if !shares.is_empty() {
                            break;
                        }
                    }
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                let code = item
                    .get("country")
                    .or_else(|| item.get("code"))
                    .and_then(Value::as_str);
                let pct = item
                    .get("percent")
                    .or_else(|| item.get("share"))
                    .and_then(Value::as_f64);
                if let (Some(c), Some(p)) = (code, pct) {
                    shares.insert(c.to_uppercase(), p);
                }
            }
        }
        _ => {}
    }
    shares
}

/// `DE 61%, US 32%, RU 6%` — largest share first.
fn ranked(shares: &BTreeMap<String, f64>) -> String {
    let mut list: Vec<(&String, &f64)> = shares.iter().collect();
    list.sort_by(|a, b| b.1.total_cmp(a.1).then_with(|| a.0.cmp(b.0)));
    list.iter()
        .map(|(c, p)| format!("{c} {p:.0}%"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn geo_consensus(node: &Node, report: &Value) -> CheckResult {
    let name = node_check(&node.name, "geo consensus");
    let shares = country_shares(&report["consensus"]);
    let Some((top, _)) = shares
        .iter()
        .max_by(|a, b| a.1.total_cmp(b.1).then_with(|| b.0.cmp(a.0)))
    else {
        return CheckResult::ok(name, "no consensus data");
    };
    let seen = ranked(&shares);
    let expected = node.country_code.to_uppercase();
    if expected.is_empty() {
        CheckResult::ok(
            name,
            format!("seen as {seen}; the panel has no country for this node"),
        )
    } else if *top == expected {
        CheckResult::ok(name, format!("seen as {seen}"))
    } else {
        CheckResult::warn(
            name,
            format!("seen as {seen}; panel says {expected}"),
        )
    }
}

fn reputation(node: &Node, report: &Value, t: GeoThresholds) -> CheckResult {
    let name = node_check(&node.name, "reputation");
    let rep = &report["reputation"];
    if !rep.is_object() {
        return CheckResult::ok(name, "no reputation data");
    }
    let risk = rep.get("risk").and_then(Value::as_f64);
    let flags: Vec<&str> = rep
        .get("flags")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let detail = format!(
        "risk {}, flags: {}",
        risk.map_or_else(|| "?".to_string(), |r| format!("{r:.0}")),
        if flags.is_empty() {
            "none".to_string()
        } else {
            flags.join(", ")
        }
    );
    match risk {
        Some(r) if r >= f64::from(t.reputation_warn_risk) => {
            CheckResult::warn(name, detail)
        }
        _ => CheckResult::ok(name, detail),
    }
}

/// Endpoints as `[ { name|url|host, verdict }, … ]` or `{ name: { verdict } }`.
fn endpoints(checks: &Value) -> Vec<(String, String)> {
    let verdict = |v: &Value| {
        v.get("verdict").and_then(Value::as_str).map(str::to_string)
    };
    match checks.get("endpoints") {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|item| {
                let label = ["name", "url", "host"]
                    .iter()
                    .find_map(|k| item.get(*k).and_then(Value::as_str))
                    .unwrap_or("?");
                verdict(item).map(|v| (label.to_string(), v))
            })
            .collect(),
        Some(Value::Object(map)) => map
            .iter()
            .filter_map(|(k, v)| verdict(v).map(|v| (k.clone(), v)))
            .collect(),
        _ => Vec::new(),
    }
}

fn connectivity(node: &Node, report: &Value) -> CheckResult {
    let name = node_check(&node.name, "connectivity");
    let checks = &report["connectivity_checks"];
    if !checks.is_object() {
        return CheckResult::ok(name, "no connectivity data");
    }
    let mut notes: Vec<String> = endpoints(checks)
        .into_iter()
        .filter(|(_, v)| !v.eq_ignore_ascii_case("ok"))
        .map(|(n, v)| format!("{n}: {v}"))
        .collect();
    if checks.get("plain_http_blocked").and_then(Value::as_bool) == Some(true) {
        notes.push("plain http blocked".to_string());
    }
    match checks.get("clean").and_then(Value::as_bool) {
        Some(true) => CheckResult::ok(name, "clean"),
        Some(false) => CheckResult::warn(
            name,
            if notes.is_empty() {
                "not clean".to_string()
            } else {
                notes.join(", ")
            },
        ),
        None if notes.is_empty() => CheckResult::ok(name, "no verdict"),
        None => CheckResult::warn(name, notes.join(", ")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Severity;
    use rstest::rstest;
    use serde_json::json;

    fn node(country: &str) -> Node {
        Node {
            name: "beta".into(),
            country_code: country.into(),
            ..Default::default()
        }
    }

    fn report() -> Value {
        json!({
            "identity": {"ipv4": "192.0.2.20", "asn": 64500, "as_name": "Example Hosting", "org": "Example", "as_country": "DE"},
            "geo": {"cloudflare": "DE"},
            "consensus": {"DE": 61, "US": 32, "RU": 6},
            "reputation": {"type": "hosting", "risk": 50, "flags": ["VPN", "hosting", "anonymous"], "vpn": true},
            "connectivity_checks": {"clean": true, "plain_http_blocked": false, "ok": 2, "altered": 0, "unreachable": 0,
                "endpoints": [{"name": "google", "verdict": "ok", "rtt_ms": 12}, {"name": "cloudflare", "verdict": "ok", "rtt_ms": 8}]}
        })
    }

    fn done(report: Value) -> GeoOutcome {
        GeoOutcome::Done(GeoFacts {
            egress: crate::model::parse_ip("192.0.2.20"),
            report,
        })
    }

    fn thresholds() -> GeoThresholds {
        GeoThresholds {
            reputation_warn_risk: 75,
        }
    }

    #[test]
    fn a_healthy_report_is_four_ok_results_in_order() {
        let r = check_node(&node("DE"), &done(report()), &thresholds());
        let names: Vec<&str> = r.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "node beta / egress address",
                "node beta / geo consensus",
                "node beta / reputation",
                "node beta / connectivity"
            ]
        );
        assert!(r.iter().all(|r| r.severity == Severity::Ok), "{r:?}");
        assert_eq!(r[0].detail, "egress 192.0.2.20 AS64500 (Example Hosting)");
        assert_eq!(r[1].detail, "seen as DE 61%, US 32%, RU 6%");
        assert_eq!(r[2].detail, "risk 50, flags: VPN, hosting, anonymous");
        assert_eq!(r[3].detail, "clean");
    }

    #[test]
    fn a_failed_job_is_one_warning() {
        let r = check_node(
            &node("DE"),
            &GeoOutcome::Failed("timeout after 90s".into()),
            &thresholds(),
        );
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].name, "node beta / geocheck");
        assert_eq!(r[0].severity, Severity::Warn);
        assert!(r[0].detail.contains("timeout"), "{}", r[0].detail);
    }

    #[test]
    fn no_ipv4_in_the_report_warns_instead_of_passing() {
        let outcome = GeoOutcome::Done(GeoFacts {
            egress: None,
            report: report(),
        });
        let r = check_node(&node("DE"), &outcome, &thresholds());
        assert_eq!(r[0].severity, Severity::Warn);
        assert!(r[0].detail.contains("cannot be verified"), "{}", r[0].detail);
    }

    #[rstest]
    #[case::map(json!({"DE": 61, "US": 32}))]
    #[case::nested(json!({"countries": {"DE": 61, "US": 32}}))]
    #[case::list(json!([{"country": "DE", "percent": 61}, {"country": "US", "percent": 32}]))]
    fn consensus_is_read_in_every_shape_seen(#[case] consensus: Value) {
        let mut rep = report();
        rep["consensus"] = consensus;
        let r = check_node(&node("US"), &done(rep), &thresholds());
        assert_eq!(r[1].severity, Severity::Warn);
        assert_eq!(r[1].detail, "seen as DE 61%, US 32%; panel says US");
    }

    #[test]
    fn missing_sections_are_no_data_not_failures() {
        let r = check_node(
            &node("DE"),
            &done(json!({"identity": {"ipv4": "192.0.2.20"}})),
            &thresholds(),
        );
        assert!(r.iter().all(|r| r.severity == Severity::Ok), "{r:?}");
        assert_eq!(r[1].detail, "no consensus data");
        assert_eq!(r[2].detail, "no reputation data");
        assert_eq!(r[3].detail, "no connectivity data");
    }

    #[rstest]
    #[case::at_threshold_int(json!(75), Severity::Warn)]
    #[case::above_threshold_float(json!(90.0), Severity::Warn)]
    #[case::below_threshold_float(json!(74.9), Severity::Ok)]
    fn risk_at_the_threshold_warns(
        #[case] risk_val: Value,
        #[case] expected_severity: Severity,
    ) {
        let mut rep = report();
        rep["reputation"]["risk"] = risk_val;
        let r = check_node(&node("DE"), &done(rep), &thresholds());
        assert_eq!(r[2].severity, expected_severity);
        assert!(
            r[2].detail.starts_with("risk "),
            "detail should start with 'risk ': {}",
            r[2].detail
        );
    }

    #[test]
    fn an_unclean_egress_names_the_endpoints() {
        let mut rep = report();
        rep["connectivity_checks"] = json!({"clean": false, "plain_http_blocked": true,
            "endpoints": [{"name": "google", "verdict": "ok"}, {"name": "youtube", "verdict": "altered"}]});
        let r = check_node(&node("DE"), &done(rep), &thresholds());
        assert_eq!(r[3].severity, Severity::Warn);
        assert_eq!(r[3].detail, "youtube: altered, plain http blocked");
    }
}
