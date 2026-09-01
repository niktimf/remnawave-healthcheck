//! Verdicts over a geocheck report. The panel types `rawReport` as an opaque
//! object, so every field is read defensively: absent data is "no data".

use super::commas;
use crate::model::{CheckResult, GeoFacts, GeoOutcome, Node, node_check};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt::Write;

#[derive(Debug, Clone, Copy)]
pub struct GeoThresholds {
    /// WARN at or above this `reputation.risk`.
    pub reputation_warn_risk: u32,
}

/// The `schema` of `remnawave/geocheck` v0.3.0, the release remnanode pins in
/// its `Dockerfile`. geocheck bumps it whenever the JSON shape changes
/// incompatibly.
const GEOCHECK_SCHEMA: u64 = 1;

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
        GeoOutcome::Done(facts) => {
            let report = &facts.report;
            let mut results: Vec<CheckResult> =
                schema_guard(node, report).into_iter().collect();
            results.extend([
                egress(node, facts),
                geo_consensus(node, report),
                reputation(node, report, *t),
                connectivity(node, report),
                findings(node, report),
                routing(node, report),
            ]);
            results
        }
    }
}

/// `schema` is the one field that can tell these checks they are reading a
/// report they were not written for. Silent when it matches: this is a guard,
/// not a status, and every node repeating "schema 1" would only pad the report.
fn schema_guard(node: &Node, report: &Value) -> Option<CheckResult> {
    let name = node_check(&node.name, "geocheck");
    match report.get("schema").and_then(Value::as_u64) {
        Some(GEOCHECK_SCHEMA) => None,
        Some(other) => Some(CheckResult::warn(
            name,
            format!(
                "geocheck schema {other}, expected {GEOCHECK_SCHEMA}: fields may be misread"
            ),
        )),
        None => Some(CheckResult::warn(
            name,
            "no geocheck schema field: this report predates the shape these checks read",
        )),
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

/// Country shares out of `consensus`, which geocheck keys by address family and
/// fills with one row per country voted for. IPv4 is the family a node's panel
/// address is on; an IPv6-only node would otherwise read as "no data", so its
/// verdict is taken instead and the family returned along with it.
fn country_shares(
    consensus: &Value,
) -> Option<(&'static str, BTreeMap<String, f64>)> {
    ["ipv4", "ipv6"].into_iter().find_map(|family| {
        let rows = consensus.get(family)?.as_array()?;
        let shares: BTreeMap<String, f64> =
            rows.iter().filter_map(share).collect();
        (!shares.is_empty()).then_some((family, shares))
    })
}

/// One `{ code, country, count, total, percent }` row. `code` is the two-letter
/// code the panel's `country_code` is compared against; `country` next to it is
/// the full name, and reading that one instead turns `DE` into `GERMANY`.
fn share(row: &Value) -> Option<(String, f64)> {
    let code = row.get("code").and_then(Value::as_str)?;
    let percent = row.get("percent").and_then(Value::as_f64)?;
    Some((code.to_uppercase(), percent))
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

/// The ranking, tagged with the family when it is not the IPv4 view the
/// panel's node addresses are on.
fn seen_as(family: &str, shares: &BTreeMap<String, f64>) -> String {
    let ranked = ranked(shares);
    if family == "ipv6" {
        format!("{ranked} (IPv6)")
    } else {
        ranked
    }
}

/// The country holding the largest share, ties broken on the code so the
/// verdict is stable. `shares` is never empty: `country_shares` yields nothing
/// rather than an empty map.
fn top_country(shares: &BTreeMap<String, f64>) -> String {
    shares
        .iter()
        .max_by(|a, b| a.1.total_cmp(b.1).then_with(|| b.0.cmp(a.0)))
        .map(|(code, _)| code.clone())
        .unwrap_or_default()
}

fn geo_consensus(node: &Node, report: &Value) -> CheckResult {
    let name = node_check(&node.name, "geo consensus");
    let Some((family, shares)) = country_shares(&report["consensus"]) else {
        return CheckResult::ok(name, "no consensus data");
    };
    let seen = seen_as(family, &shares);
    let expected = node.country_code.to_uppercase();
    if expected.is_empty() {
        CheckResult::ok(
            name,
            format!("seen as {seen}; the panel has no country for this node"),
        )
    } else if top_country(&shares) == expected {
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
    // geocheck spends one proxycheck.io query per address per run against an
    // allowance of 100 a day without an API key. Exhausting it answers with an
    // error and nothing else, which must not read as a clean address.
    if let Some(error) = rep.get("error").and_then(Value::as_str) {
        return CheckResult::warn(
            name,
            format!("reputation unavailable: {error}"),
        );
    }
    let risk = rep.get("risk").and_then(Value::as_f64);
    let detail = reputation_detail(rep, risk);
    let over = risk.is_some_and(|r| r >= f64::from(t.reputation_warn_risk));
    if over || compromising(rep) {
        CheckResult::warn(name, detail)
    } else {
        CheckResult::ok(name, detail)
    }
}

/// Detections worth a warning whatever the risk number says. Every node is
/// hosting space, so `hosting` and `vpn` are the resting state of a healthy
/// exit and `risk` sits well above zero on its own; these two are not.
fn compromising(rep: &Value) -> bool {
    ["tor", "compromised"]
        .into_iter()
        .any(|flag| rep.get(flag).and_then(Value::as_bool) == Some(true))
}

fn reputation_detail(rep: &Value, risk: Option<f64>) -> String {
    let flags: Vec<&str> = rep
        .get("flags")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    format!(
        "risk {}, flags: {}",
        risk.map_or_else(|| "?".to_string(), |r| format!("{r:.0}")),
        if flags.is_empty() {
            "none".to_string()
        } else {
            flags.join(", ")
        }
    )
}

/// geocheck's own verdicts over the run, already graded. `alert` means it
/// believes the measurement itself was intercepted; that is worth a warning but
/// not a failure, because it describes the conditions the report was taken
/// under rather than the node refusing to serve.
fn findings(node: &Node, report: &Value) -> CheckResult {
    let name = node_check(&node.name, "geocheck findings");
    let Some(items) = report["findings"].as_array() else {
        return CheckResult::ok(name, "no findings data");
    };
    if items.is_empty() {
        return CheckResult::ok(name, "nothing flagged");
    }
    let listed = commas(items.iter().filter_map(finding));
    if items.iter().any(above_info) {
        CheckResult::warn(name, listed)
    } else {
        CheckResult::ok(name, listed)
    }
}

fn finding(item: &Value) -> Option<String> {
    let title = item.get("title").and_then(Value::as_str)?;
    Some(format!("{title} ({})", severity_of(item)))
}

/// A finding with no severity is read as context, so a shape that stops
/// carrying the field goes quiet here rather than warning on every node — the
/// `schema` guard is what catches that case.
fn severity_of(item: &Value) -> &str {
    item.get("severity")
        .and_then(Value::as_str)
        .unwrap_or("info")
}

fn above_info(item: &Value) -> bool {
    severity_of(item) != "info"
}

/// The traceroute report. This is `connectivity`; the captive-portal section
/// above is `connectivity_checks`, and geocheck really does name them that way.
///
/// A remnanode container without `CAP_NET_RAW` cannot trace at all, and the
/// score reported in that case describes nothing — an unusable trace is no
/// data rather than a bad route.
fn routing(node: &Node, report: &Value) -> CheckResult {
    let name = node_check(&node.name, "routing");
    let path = &report["connectivity"];
    if !traced(path) {
        return CheckResult::ok(name, "no routing data");
    }
    let intercepted = path["breakdown"]["intercepted"].as_u64().unwrap_or(0);
    if intercepted > 0 {
        return CheckResult::warn(name, intercepted_detail(path, intercepted));
    }
    let score = path["score"].as_i64().unwrap_or_default();
    let floor = path["latency_floor_ms"].as_f64().unwrap_or_default();
    CheckResult::ok(name, format!("score {score}/100, floor {floor:.1} ms"))
}

fn traced(path: &Value) -> bool {
    path.is_object()
        && ["icmp_available", "privileged"]
            .into_iter()
            .all(|f| path.get(f).and_then(Value::as_bool) != Some(false))
}

fn intercepted_detail(path: &Value, count: u64) -> String {
    let names = commas(targets_verdicted(path, "intercepted"));
    if names.is_empty() {
        format!("{count} targets intercepted")
    } else {
        format!("intercepted: {names}")
    }
}

fn targets_verdicted<'a>(path: &'a Value, verdict: &str) -> Vec<&'a str> {
    let Some(targets) = path["targets"].as_array() else {
        return Vec::new();
    };
    targets
        .iter()
        .filter(|t| t.get("verdict").and_then(Value::as_str) == Some(verdict))
        .filter_map(|t| t.get("name").and_then(Value::as_str))
        .collect()
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
    use crate::test_util::{by_aspect, geocheck_report, node};
    use rstest::rstest;
    use serde_json::json;

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

    fn checked(report: Value) -> Vec<CheckResult> {
        check_node(&node("beta", "DE"), &done(report), &thresholds())
    }

    /// The healthy report with one section swapped, which is how every case
    /// below isolates the section it is about.
    fn with_section(section: &str, value: Value) -> Vec<CheckResult> {
        let mut report = geocheck_report();
        report[section] = value;
        checked(report)
    }

    #[test]
    fn a_healthy_report_is_six_ok_results_in_order() {
        let r = checked(geocheck_report());
        let names: Vec<&str> = r.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "node beta / egress address",
                "node beta / geo consensus",
                "node beta / reputation",
                "node beta / connectivity",
                "node beta / geocheck findings",
                "node beta / routing"
            ]
        );
        assert!(r.iter().all(|r| r.severity == Severity::Ok), "{r:?}");
    }

    #[test]
    fn a_healthy_report_names_the_egress_with_its_network() {
        let r = checked(geocheck_report());
        assert_eq!(
            by_aspect(&r, "egress address").detail,
            "egress 192.0.2.20 AS64500 (Example Hosting)"
        );
    }

    #[test]
    fn geo_consensus_reads_the_code_out_of_the_ipv4_array() {
        let r = checked(geocheck_report());
        let c = by_aspect(&r, "geo consensus");
        assert_eq!(c.severity, Severity::Ok);
        assert_eq!(c.detail, "seen as DE 61%, US 33%, RU 6%");
    }

    #[test]
    fn consensus_falls_back_to_ipv6_when_there_is_no_ipv4_verdict() {
        let r = with_section(
            "consensus",
            json!({"ipv6": [
                {"code": "DE", "country": "Germany", "count": 4, "total": 4, "percent": 100.0}
            ]}),
        );
        let c = by_aspect(&r, "geo consensus");
        assert_eq!(c.severity, Severity::Ok);
        assert_eq!(c.detail, "seen as DE 100% (IPv6)");
    }

    #[test]
    fn a_consensus_disagreeing_with_the_panel_warns() {
        let r = check_node(
            &node("beta", "US"),
            &done(geocheck_report()),
            &thresholds(),
        );
        let c = by_aspect(&r, "geo consensus");
        assert_eq!(c.severity, Severity::Warn);
        assert_eq!(c.detail, "seen as DE 61%, US 33%, RU 6%; panel says US");
    }

    #[test]
    fn a_schema_these_checks_were_written_for_adds_no_result() {
        let r = checked(geocheck_report());
        let guards: Vec<&str> = r
            .iter()
            .map(|x| x.name.as_str())
            .filter(|n| n.ends_with("/ geocheck"))
            .collect();
        assert!(guards.is_empty(), "{guards:?}");
    }

    #[test]
    fn a_bumped_schema_warns_that_fields_may_be_misread() {
        let r = with_section("schema", json!(2));
        let result = by_aspect(&r, "geocheck");
        assert_eq!(result.severity, Severity::Warn);
        assert_eq!(
            result.detail,
            "geocheck schema 2, expected 1: fields may be misread"
        );
    }

    #[test]
    fn a_report_without_a_schema_field_warns_too() {
        let r = checked(json!({"identity": {"ipv4": "192.0.2.20"}}));
        assert_eq!(by_aspect(&r, "geocheck").severity, Severity::Warn);
    }

    #[test]
    fn a_failed_job_is_one_warning() {
        let r = check_node(
            &node("beta", "DE"),
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
            report: geocheck_report(),
        });
        let r = check_node(&node("beta", "DE"), &outcome, &thresholds());
        let egress = by_aspect(&r, "egress address");
        assert_eq!(egress.severity, Severity::Warn);
        assert!(
            egress.detail.contains("cannot be verified"),
            "{}",
            egress.detail
        );
    }

    #[rstest]
    #[case::consensus("geo consensus", "no consensus data")]
    #[case::reputation("reputation", "no reputation data")]
    #[case::connectivity("connectivity", "no connectivity data")]
    fn missing_sections_are_no_data_not_failures(
        #[case] aspect: &str,
        #[case] detail: &str,
    ) {
        let r = checked(json!({"identity": {"ipv4": "192.0.2.20"}}));
        let result = by_aspect(&r, aspect);
        assert_eq!(result.severity, Severity::Ok);
        assert_eq!(result.detail, detail);
    }

    #[rstest]
    #[case::at_threshold_int(json!(75), Severity::Warn)]
    #[case::above_threshold_float(json!(90.0), Severity::Warn)]
    #[case::below_threshold_float(json!(74.9), Severity::Ok)]
    fn risk_at_the_threshold_warns(
        #[case] risk: Value,
        #[case] expected: Severity,
    ) {
        let mut reputation = geocheck_report()["reputation"].clone();
        reputation["risk"] = risk;
        let r = with_section("reputation", reputation);
        let result = by_aspect(&r, "reputation");
        assert_eq!(result.severity, expected);
        assert!(
            result.detail.starts_with("risk "),
            "detail should start with 'risk ': {}",
            result.detail
        );
    }

    #[test]
    fn a_reputation_lookup_that_failed_warns_instead_of_reading_as_clean() {
        let r = with_section(
            "reputation",
            json!({"error": "proxycheck.io daily query allowance exhausted"}),
        );
        let result = by_aspect(&r, "reputation");
        assert_eq!(result.severity, Severity::Warn);
        assert_eq!(
            result.detail,
            "reputation unavailable: proxycheck.io daily query allowance exhausted"
        );
    }

    #[rstest]
    #[case::tor("tor")]
    #[case::compromised("compromised")]
    fn a_flagged_address_warns_even_at_a_low_risk(#[case] flag: &str) {
        let mut reputation = geocheck_report()["reputation"].clone();
        reputation["risk"] = json!(5);
        reputation[flag] = json!(true);
        let r = with_section("reputation", reputation);
        assert_eq!(by_aspect(&r, "reputation").severity, Severity::Warn);
    }

    #[test]
    fn a_hosting_address_at_its_resting_risk_is_not_a_warning() {
        let r = checked(geocheck_report());
        let result = by_aspect(&r, "reputation");
        assert_eq!(result.severity, Severity::Ok);
        assert_eq!(result.detail, "risk 50, flags: VPN, hosting");
    }

    #[test]
    fn a_report_with_nothing_flagged_says_so() {
        let r = checked(geocheck_report());
        let result = by_aspect(&r, "geocheck findings");
        assert_eq!(result.severity, Severity::Ok);
        assert_eq!(result.detail, "nothing flagged");
    }

    #[test]
    fn findings_above_info_warn_and_carry_their_severity() {
        let r = with_section(
            "findings",
            json!([
                {"id": "dns-hijack", "title": "DNS answers rewritten",
                 "severity": "alert", "detail": "resolver returned a different address"},
                {"id": "clock-skew", "title": "Clock skew", "severity": "warn", "detail": "12s"}
            ]),
        );
        let result = by_aspect(&r, "geocheck findings");
        assert_eq!(result.severity, Severity::Warn);
        assert_eq!(
            result.detail,
            "DNS answers rewritten (alert), Clock skew (warn)"
        );
    }

    #[test]
    fn findings_that_are_only_context_do_not_warn() {
        let r = with_section(
            "findings",
            json!([
                {"id": "no-ipv6", "title": "No IPv6", "severity": "info", "detail": "v4 only"}
            ]),
        );
        let result = by_aspect(&r, "geocheck findings");
        assert_eq!(result.severity, Severity::Ok);
        assert_eq!(result.detail, "No IPv6 (info)");
    }

    #[test]
    fn routing_reports_the_score_and_the_latency_floor() {
        let r = checked(geocheck_report());
        let result = by_aspect(&r, "routing");
        assert_eq!(result.severity, Severity::Ok);
        assert_eq!(result.detail, "score 82/100, floor 8.1 ms");
    }

    #[test]
    fn an_intercepted_route_warns_and_names_the_target() {
        let mut routing = geocheck_report()["connectivity"].clone();
        routing["breakdown"]["intercepted"] = json!(1);
        routing["targets"][0]["verdict"] = json!("intercepted");
        let r = with_section("connectivity", routing);
        let result = by_aspect(&r, "routing");
        assert_eq!(result.severity, Severity::Warn);
        assert_eq!(result.detail, "intercepted: Cloudflare DNS");
    }

    /// A remnanode container without `CAP_NET_RAW` cannot traceroute, and the
    /// score it reports then means nothing.
    #[rstest]
    #[case::no_icmp(json!("icmp_available"))]
    #[case::unprivileged(json!("privileged"))]
    fn routing_without_a_usable_trace_is_no_data(#[case] field: Value) {
        let mut routing = geocheck_report()["connectivity"].clone();
        routing[field.as_str().unwrap()] = json!(false);
        let r = with_section("connectivity", routing);
        let result = by_aspect(&r, "routing");
        assert_eq!(result.severity, Severity::Ok);
        assert_eq!(result.detail, "no routing data");
    }

    #[test]
    fn an_unclean_egress_names_the_endpoints() {
        let r = with_section(
            "connectivity_checks",
            json!({
                "clean": false,
                "plain_http_blocked": true,
                "endpoints": [
                    {"name": "google", "verdict": "ok"},
                    {"name": "youtube", "verdict": "altered"}
                ]
            }),
        );
        let result = by_aspect(&r, "connectivity");
        assert_eq!(result.severity, Severity::Warn);
        assert_eq!(result.detail, "youtube: altered, plain http blocked");
    }
}
