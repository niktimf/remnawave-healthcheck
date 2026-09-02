//! Verdicts over a geocheck report. The panel types `rawReport` as an opaque
//! object, so every field is read defensively: absent data is "no data".

use super::{Verdict, commas};
use crate::model::{CheckResult, GeoFacts, GeoOutcome, Node, node_check};
use serde_json::Value;
use std::collections::BTreeMap;

/// The `schema` of `remnawave/geocheck` v0.3.0, the release remnanode pins in
/// its `Dockerfile`. geocheck bumps it whenever the JSON shape changes
/// incompatibly.
const GEOCHECK_SCHEMA: u64 = 1;

/// Reads a geocheck report and says what it means. Holds the one judgement
/// call the caller gets to make, so the threshold stops travelling as an
/// argument through every verdict.
#[derive(Debug, Clone, Copy)]
pub struct GeoChecker {
    /// WARN at or above this `reputation.risk`.
    pub reputation_warn_risk: u32,
}

impl GeoChecker {
    pub fn check_node(
        &self,
        node: &Node,
        outcome: &GeoOutcome,
    ) -> Vec<CheckResult> {
        let facts = match outcome {
            GeoOutcome::Failed(reason) => {
                return vec![CheckResult::warn(
                    node_check(&node.name, "geocheck"),
                    format!("no geocheck result: {reason}"),
                )];
            }
            GeoOutcome::Done(facts) => facts,
        };
        let geo = Geo {
            node,
            facts,
            checker: *self,
        };
        let named = |(aspect, v): (&str, Verdict)| {
            CheckResult::new(
                node_check(&node.name, aspect),
                v.severity,
                v.detail,
            )
        };
        // Every geocheck-derived check, in report order, with the aspect it is
        // named by. The schema guard leads, and is usually absent.
        schema_guard(&facts.report)
            .map(|v| ("geocheck", v))
            .into_iter()
            .chain([
                ("egress address", geo.egress()),
                ("geo consensus", geo.consensus()),
                ("reputation", geo.reputation()),
                ("connectivity", geo.connectivity()),
                ("geocheck findings", geo.findings()),
                ("routing", geo.routing()),
            ])
            .map(named)
            .collect()
    }
}

/// One node's completed geocheck, with the settings its verdicts need. Every
/// check below reads the same report, so it is held once rather than passed
/// around.
struct Geo<'a> {
    node: &'a Node,
    facts: &'a GeoFacts,
    checker: GeoChecker,
}

impl Geo<'_> {
    fn report(&self) -> &Value {
        &self.facts.report
    }

    fn egress(&self) -> Verdict {
        let Some(ip) = self.facts.egress else {
            return Verdict::warn(
                "geocheck reported no IPv4 address, so exits of channels expected to leave through this node cannot be verified",
            );
        };
        let identity = &self.report()["identity"];
        let asn = identity.get("asn").and_then(text).map(|raw| {
            let number = raw.strip_prefix("AS").unwrap_or(&raw).to_string();
            format!(" AS{number}")
        });
        let network = identity
            .get("as_name")
            .and_then(text)
            .map(|name| format!(" ({name})"));
        Verdict::ok(format!(
            "egress {ip}{}{}",
            asn.unwrap_or_default(),
            network.unwrap_or_default()
        ))
    }

    fn consensus(&self) -> Verdict {
        let Some((family, shares)) =
            country_shares(&self.report()["consensus"])
        else {
            return Verdict::ok("no consensus data");
        };
        let seen = seen_as(family, &shares);
        let expected = self.node.country_code.to_uppercase();
        if expected.is_empty() {
            Verdict::ok(format!(
                "seen as {seen}; the panel has no country for this node"
            ))
        } else if top_country(&shares) == expected {
            Verdict::ok(format!("seen as {seen}"))
        } else {
            Verdict::warn(format!("seen as {seen}; panel says {expected}"))
        }
    }

    fn reputation(&self) -> Verdict {
        let rep = &self.report()["reputation"];
        if !rep.is_object() {
            return Verdict::ok("no reputation data");
        }
        // geocheck spends one proxycheck.io query per address per run against
        // an allowance of 100 a day without an API key. Exhausting it answers
        // with an error and nothing else, which must not read as a clean
        // address.
        if let Some(error) = rep.get("error").and_then(Value::as_str) {
            return Verdict::warn(format!("reputation unavailable: {error}"));
        }
        let risk = rep.get("risk").and_then(Value::as_f64);
        let detail = reputation_detail(rep, risk);
        let over = risk
            .is_some_and(|r| r >= f64::from(self.checker.reputation_warn_risk));
        if over || compromising(rep) {
            Verdict::warn(detail)
        } else {
            Verdict::ok(detail)
        }
    }

    fn connectivity(&self) -> Verdict {
        let checks = &self.report()["connectivity_checks"];
        if !checks.is_object() {
            return Verdict::ok("no connectivity data");
        }
        let altered = endpoints(checks)
            .into_iter()
            .filter(|(_, verdict)| !verdict.eq_ignore_ascii_case("ok"))
            .map(|(endpoint, verdict)| format!("{endpoint}: {verdict}"));
        let plain_http_blocked =
            checks.get("plain_http_blocked").and_then(Value::as_bool)
                == Some(true);
        let notes: Vec<String> = altered
            .chain(plain_http_blocked.then(|| "plain http blocked".to_string()))
            .collect();
        match checks.get("clean").and_then(Value::as_bool) {
            Some(true) => Verdict::ok("clean"),
            Some(false) if notes.is_empty() => Verdict::warn("not clean"),
            // No verdict and nothing to report is no data; anything else is
            // the notes, whether geocheck called the run unclean or said
            // nothing at all.
            None if notes.is_empty() => Verdict::ok("no verdict"),
            _ => Verdict::warn(notes.join(", ")),
        }
    }

    /// geocheck's own verdicts over the run, already graded. `alert` means it
    /// believes the measurement itself was intercepted; that is worth a warning
    /// but not a failure, because it describes the conditions the report was
    /// taken under rather than the node refusing to serve.
    fn findings(&self) -> Verdict {
        let Some(items) = self.report()["findings"].as_array() else {
            return Verdict::ok("no findings data");
        };
        if items.is_empty() {
            return Verdict::ok("nothing flagged");
        }
        let listed = commas(items.iter().filter_map(finding));
        if items.iter().any(above_info) {
            Verdict::warn(listed)
        } else {
            Verdict::ok(listed)
        }
    }

    /// The traceroute report. This is `connectivity`; the captive-portal
    /// section is `connectivity_checks`, and geocheck really does name them
    /// that way.
    ///
    /// A remnanode container without `CAP_NET_RAW` cannot trace at all, and the
    /// score reported in that case describes nothing — an unusable trace is no
    /// data rather than a bad route.
    fn routing(&self) -> Verdict {
        let path = &self.report()["connectivity"];
        if !traced(path) {
            return Verdict::ok("no routing data");
        }
        let intercepted =
            path["breakdown"]["intercepted"].as_u64().unwrap_or(0);
        if intercepted > 0 {
            return Verdict::warn(intercepted_detail(path, intercepted));
        }
        let score = path["score"].as_i64().unwrap_or_default();
        let floor = path["latency_floor_ms"].as_f64().unwrap_or_default();
        Verdict::ok(format!("score {score}/100, floor {floor:.1} ms"))
    }
}

/// `schema` is the one field that can tell these checks they are reading a
/// report they were not written for. Silent when it matches: this is a guard,
/// not a status, and every node repeating "schema 1" would only pad the report.
fn schema_guard(report: &Value) -> Option<Verdict> {
    match report.get("schema").and_then(Value::as_u64) {
        Some(GEOCHECK_SCHEMA) => None,
        Some(other) => Some(Verdict::warn(format!(
            "geocheck schema {other}, expected {GEOCHECK_SCHEMA}: fields may be misread"
        ))),
        None => Some(Verdict::warn(
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

    fn checker() -> GeoChecker {
        GeoChecker {
            reputation_warn_risk: 75,
        }
    }

    /// The healthy report with one section swapped, which is how each case
    /// below isolates the section it is about.
    fn report_with(section: &str, value: Value) -> Value {
        let mut report = geocheck_report();
        report[section] = value;
        report
    }

    fn reputation_with(field: &str, value: Value) -> Value {
        let mut reputation = geocheck_report()["reputation"].clone();
        reputation[field] = value;
        report_with("reputation", reputation)
    }

    fn routing_with(field: &str, value: Value) -> Value {
        let mut routing = geocheck_report()["connectivity"].clone();
        routing[field] = value;
        report_with("connectivity", routing)
    }

    #[test]
    fn a_healthy_report_is_six_ok_results_in_order() {
        let outcome = done(geocheck_report());
        let sut = checker();

        let results = sut.check_node(&node("beta", "DE"), &outcome);

        let names: Vec<&str> =
            results.iter().map(|r| r.name.as_str()).collect();
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
        assert!(
            results.iter().all(|r| r.severity == Severity::Ok),
            "{results:?}"
        );
    }

    #[test]
    fn a_healthy_report_names_the_egress_with_its_network() {
        let outcome = done(geocheck_report());
        let sut = checker();

        let results = sut.check_node(&node("beta", "DE"), &outcome);

        assert_eq!(
            by_aspect(&results, "egress address").detail,
            "egress 192.0.2.20 AS64500 (Example Hosting)"
        );
    }

    #[test]
    fn no_ipv4_in_the_report_warns_instead_of_passing() {
        let outcome = GeoOutcome::Done(GeoFacts {
            egress: None,
            report: geocheck_report(),
        });
        let sut = checker();

        let results = sut.check_node(&node("beta", "DE"), &outcome);

        let egress = by_aspect(&results, "egress address");
        assert_eq!(egress.severity, Severity::Warn);
        assert!(
            egress.detail.contains("cannot be verified"),
            "{}",
            egress.detail
        );
    }

    #[test]
    fn a_failed_job_is_one_warning() {
        let outcome = GeoOutcome::Failed("timeout after 90s".into());
        let sut = checker();

        let results = sut.check_node(&node("beta", "DE"), &outcome);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "node beta / geocheck");
        assert_eq!(results[0].severity, Severity::Warn);
        assert!(results[0].detail.contains("timeout"), "{}", results[0].detail);
    }

    #[test]
    fn a_schema_these_checks_were_written_for_adds_no_result() {
        let outcome = done(geocheck_report());
        let sut = checker();

        let results = sut.check_node(&node("beta", "DE"), &outcome);

        let guards: Vec<&str> = results
            .iter()
            .map(|r| r.name.as_str())
            .filter(|n| n.ends_with("/ geocheck"))
            .collect();
        assert!(guards.is_empty(), "{guards:?}");
    }

    #[test]
    fn a_bumped_schema_warns_that_fields_may_be_misread() {
        let outcome = done(report_with("schema", json!(2)));
        let sut = checker();

        let results = sut.check_node(&node("beta", "DE"), &outcome);

        let guard = by_aspect(&results, "geocheck");
        assert_eq!(guard.severity, Severity::Warn);
        assert_eq!(
            guard.detail,
            "geocheck schema 2, expected 1: fields may be misread"
        );
    }

    #[test]
    fn a_report_without_a_schema_field_warns_too() {
        let outcome = done(json!({"identity": {"ipv4": "192.0.2.20"}}));
        let sut = checker();

        let results = sut.check_node(&node("beta", "DE"), &outcome);

        assert_eq!(by_aspect(&results, "geocheck").severity, Severity::Warn);
    }

    #[test]
    fn geo_consensus_reads_the_code_out_of_the_ipv4_array() {
        let outcome = done(geocheck_report());
        let sut = checker();

        let results = sut.check_node(&node("beta", "DE"), &outcome);

        let consensus = by_aspect(&results, "geo consensus");
        assert_eq!(consensus.severity, Severity::Ok);
        assert_eq!(consensus.detail, "seen as DE 61%, US 33%, RU 6%");
    }

    #[test]
    fn consensus_falls_back_to_ipv6_when_there_is_no_ipv4_verdict() {
        let outcome = done(report_with(
            "consensus",
            json!({"ipv6": [
                {"code": "DE", "country": "Germany", "count": 4, "total": 4, "percent": 100.0}
            ]}),
        ));
        let sut = checker();

        let results = sut.check_node(&node("beta", "DE"), &outcome);

        let consensus = by_aspect(&results, "geo consensus");
        assert_eq!(consensus.severity, Severity::Ok);
        assert_eq!(consensus.detail, "seen as DE 100% (IPv6)");
    }

    #[test]
    fn a_consensus_disagreeing_with_the_panel_warns() {
        let outcome = done(geocheck_report());
        let sut = checker();

        let results = sut.check_node(&node("beta", "US"), &outcome);

        let consensus = by_aspect(&results, "geo consensus");
        assert_eq!(consensus.severity, Severity::Warn);
        assert_eq!(
            consensus.detail,
            "seen as DE 61%, US 33%, RU 6%; panel says US"
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
        let outcome = done(json!({"identity": {"ipv4": "192.0.2.20"}}));
        let sut = checker();

        let results = sut.check_node(&node("beta", "DE"), &outcome);

        let result = by_aspect(&results, aspect);
        assert_eq!(result.severity, Severity::Ok);
        assert_eq!(result.detail, detail);
    }

    #[test]
    fn a_hosting_address_at_its_resting_risk_is_not_a_warning() {
        let outcome = done(geocheck_report());
        let sut = checker();

        let results = sut.check_node(&node("beta", "DE"), &outcome);

        let reputation = by_aspect(&results, "reputation");
        assert_eq!(reputation.severity, Severity::Ok);
        assert_eq!(reputation.detail, "risk 50, flags: VPN, hosting");
    }

    #[rstest]
    #[case::at_threshold_int(json!(75), Severity::Warn)]
    #[case::above_threshold_float(json!(90.0), Severity::Warn)]
    #[case::below_threshold_float(json!(74.9), Severity::Ok)]
    fn risk_at_the_threshold_warns(
        #[case] risk: Value,
        #[case] expected: Severity,
    ) {
        let outcome = done(reputation_with("risk", risk));
        let sut = checker();

        let results = sut.check_node(&node("beta", "DE"), &outcome);

        let reputation = by_aspect(&results, "reputation");
        assert_eq!(reputation.severity, expected);
        assert!(
            reputation.detail.starts_with("risk "),
            "detail should start with 'risk ': {}",
            reputation.detail
        );
    }

    #[test]
    fn a_reputation_lookup_that_failed_warns_instead_of_reading_as_clean() {
        let outcome = done(report_with(
            "reputation",
            json!({"error": "proxycheck.io daily query allowance exhausted"}),
        ));
        let sut = checker();

        let results = sut.check_node(&node("beta", "DE"), &outcome);

        let reputation = by_aspect(&results, "reputation");
        assert_eq!(reputation.severity, Severity::Warn);
        assert_eq!(
            reputation.detail,
            "reputation unavailable: proxycheck.io daily query allowance exhausted"
        );
    }

    /// Every node is hosting space and scores a middling risk by default, so
    /// the risk number alone cannot separate a healthy exit from a taken-over
    /// one.
    #[rstest]
    #[case::tor("tor")]
    #[case::compromised("compromised")]
    fn a_flagged_address_warns_even_at_a_low_risk(#[case] flag: &str) {
        let mut reputation = geocheck_report()["reputation"].clone();
        reputation["risk"] = json!(5);
        reputation[flag] = json!(true);
        let outcome = done(report_with("reputation", reputation));
        let sut = checker();

        let results = sut.check_node(&node("beta", "DE"), &outcome);

        assert_eq!(by_aspect(&results, "reputation").severity, Severity::Warn);
    }

    #[test]
    fn a_report_with_nothing_flagged_says_so() {
        let outcome = done(geocheck_report());
        let sut = checker();

        let results = sut.check_node(&node("beta", "DE"), &outcome);

        let findings = by_aspect(&results, "geocheck findings");
        assert_eq!(findings.severity, Severity::Ok);
        assert_eq!(findings.detail, "nothing flagged");
    }

    #[test]
    fn findings_above_info_warn_and_carry_their_severity() {
        let outcome = done(report_with(
            "findings",
            json!([
                {"id": "dns-hijack", "title": "DNS answers rewritten",
                 "severity": "alert", "detail": "resolver returned a different address"},
                {"id": "clock-skew", "title": "Clock skew", "severity": "warn", "detail": "12s"}
            ]),
        ));
        let sut = checker();

        let results = sut.check_node(&node("beta", "DE"), &outcome);

        let findings = by_aspect(&results, "geocheck findings");
        assert_eq!(findings.severity, Severity::Warn);
        assert_eq!(
            findings.detail,
            "DNS answers rewritten (alert), Clock skew (warn)"
        );
    }

    #[test]
    fn findings_that_are_only_context_do_not_warn() {
        let outcome = done(report_with(
            "findings",
            json!([
                {"id": "no-ipv6", "title": "No IPv6", "severity": "info", "detail": "v4 only"}
            ]),
        ));
        let sut = checker();

        let results = sut.check_node(&node("beta", "DE"), &outcome);

        let findings = by_aspect(&results, "geocheck findings");
        assert_eq!(findings.severity, Severity::Ok);
        assert_eq!(findings.detail, "No IPv6 (info)");
    }

    #[test]
    fn routing_reports_the_score_and_the_latency_floor() {
        let outcome = done(geocheck_report());
        let sut = checker();

        let results = sut.check_node(&node("beta", "DE"), &outcome);

        let routing = by_aspect(&results, "routing");
        assert_eq!(routing.severity, Severity::Ok);
        assert_eq!(routing.detail, "score 82/100, floor 8.1 ms");
    }

    #[test]
    fn an_intercepted_route_warns_and_names_the_target() {
        let mut routing = geocheck_report()["connectivity"].clone();
        routing["breakdown"]["intercepted"] = json!(1);
        routing["targets"][0]["verdict"] = json!("intercepted");
        let outcome = done(report_with("connectivity", routing));
        let sut = checker();

        let results = sut.check_node(&node("beta", "DE"), &outcome);

        let result = by_aspect(&results, "routing");
        assert_eq!(result.severity, Severity::Warn);
        assert_eq!(result.detail, "intercepted: Cloudflare DNS");
    }

    /// A remnanode container without `CAP_NET_RAW` cannot traceroute, and the
    /// score it reports then means nothing.
    #[rstest]
    #[case::no_icmp("icmp_available")]
    #[case::unprivileged("privileged")]
    fn routing_without_a_usable_trace_is_no_data(#[case] field: &str) {
        let outcome = done(routing_with(field, json!(false)));
        let sut = checker();

        let results = sut.check_node(&node("beta", "DE"), &outcome);

        let routing = by_aspect(&results, "routing");
        assert_eq!(routing.severity, Severity::Ok);
        assert_eq!(routing.detail, "no routing data");
    }

    #[test]
    fn an_unclean_egress_names_the_endpoints() {
        let outcome = done(report_with(
            "connectivity_checks",
            json!({
                "clean": false,
                "plain_http_blocked": true,
                "endpoints": [
                    {"name": "google", "verdict": "ok"},
                    {"name": "youtube", "verdict": "altered"}
                ]
            }),
        ));
        let sut = checker();

        let results = sut.check_node(&node("beta", "DE"), &outcome);

        let result = by_aspect(&results, "connectivity");
        assert_eq!(result.severity, Severity::Warn);
        assert_eq!(result.detail, "youtube: altered, plain http blocked");
    }
}
