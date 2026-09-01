//! Helpers shared by this crate's unit tests.
//!
//! A fixture that mirrors an external contract belongs here rather than in the
//! module that happens to need it first: the geocheck report below is the panel's
//! `rawReport`, and when that contract moves it has to be corrected in one place.

use crate::model::{CheckResult, Node};
use serde_json::{Value, json};

/// An enabled, connected node carrying the country the panel claims for it.
pub(crate) fn node(name: &str, country_code: &str) -> Node {
    Node {
        name: name.into(),
        country_code: country_code.into(),
        is_connected: true,
        ..Default::default()
    }
}

/// The single result for `aspect`, so a test names the check it means instead of
/// indexing into the vector and breaking the moment a check is added.
///
/// # Panics
/// When no result carries the aspect, listing what was actually produced.
pub(crate) fn by_aspect(results: &[CheckResult], aspect: &str) -> CheckResult {
    let suffix = format!("/ {aspect}");
    results
        .iter()
        .find(|r| r.name.ends_with(&suffix))
        .unwrap_or_else(|| {
            let names: Vec<&str> =
                results.iter().map(|r| r.name.as_str()).collect();
            panic!("no result for {aspect:?}; got {names:?}")
        })
        .clone()
}

/// A healthy `rawReport`, in the shape geocheck actually emits.
///
/// Mirrors `internal/render/json.go` of `remnawave/geocheck` v0.3.0 — the
/// version pinned by remnanode's `Dockerfile` — down to `schema`, which that
/// file bumps whenever the shape changes incompatibly. `image` is absent
/// because the panel destructures it away before storing the rest as
/// `rawReport`.
pub(crate) fn geocheck_report() -> Value {
    json!({
        "schema": 1,
        "tool": "0.3.0",
        "timestamp": "2026-09-01T12:00:00Z",
        "duration_ms": 8421,
        "identity": {
            "ipv4": "192.0.2.20",
            "asn": 64500,
            "as_name": "Example Hosting",
            "org": "Example Hosting Ltd",
            "as_country": "DE"
        },
        "transport": {"interface": "192.0.2.20", "resolver": "9.9.9.9"},
        "findings": [],
        "reputation": geocheck_reputation(),
        "consensus": {"ipv4": geocheck_consensus()},
        "geo": {"services": [], "geoip": [], "cdn": []},
        "connectivity_checks": geocheck_portal(),
        "connectivity": geocheck_routing(),
    })
}

/// `reputation` as proxycheck.io answers for a healthy datacenter exit: every
/// node is hosting space, so `hosting` and `vpn` are the resting state and
/// `risk` sits well above zero without meaning anything is wrong.
fn geocheck_reputation() -> Value {
    json!({
        "type": "Hosting",
        "residential": false,
        "risk": 50,
        "confidence": 95,
        "flags": ["VPN", "hosting"],
        "proxy": false,
        "vpn": true,
        "tor": false,
        "hosting": true,
        "scraper": false,
        "compromised": false,
        "anonymous": false,
        "provider": "Example Hosting",
        "country": "Germany",
        "country_code": "DE"
    })
}

/// One entry per country the geolocation services voted for, largest first.
/// `code` is the two-letter code and `country` its full name — reading the
/// wrong one turns `DE` into `GERMANY`.
fn geocheck_consensus() -> Value {
    json!([
        {"code": "DE", "country": "Germany", "count": 11, "total": 18, "percent": 61.11},
        {"code": "US", "country": "United States", "count": 6, "total": 18, "percent": 33.33},
        {"code": "RU", "country": "Russia", "count": 1, "total": 18, "percent": 5.56}
    ])
}

/// `connectivity_checks`: captive portals and rewritten responses.
fn geocheck_portal() -> Value {
    json!({
        "clean": true,
        "plain_http_blocked": false,
        "ok": 4,
        "captive_portal": 0,
        "altered": 0,
        "unreachable": 0,
        "endpoints": [{
            "id": "gstatic",
            "name": "Google",
            "vendor": "Google",
            "url": "http://connectivitycheck.gstatic.com/generate_204",
            "verdict": "ok",
            "status": 204,
            "expected_status": 204,
            "rtt_ms": 12.4
        }]
    })
}

/// `connectivity`: the traceroute report. A different section from
/// `connectivity_checks`, despite the names.
fn geocheck_routing() -> Value {
    json!({
        "icmp_available": true,
        "privileged": true,
        "score": 82,
        "latency_floor_ms": 8.1,
        "breakdown": {
            "direct": 3, "peered": 2, "transit": 1,
            "detour": 0, "intercepted": 0, "failed": 0
        },
        "targets": [{
            "id": "cloudflare",
            "name": "Cloudflare DNS",
            "host": "1.1.1.1",
            "resolved": "1.1.1.1",
            "method": "icmp",
            "anycast": true,
            "dest_asn": 13335,
            "dest_as_name": "CLOUDFLARENET",
            "verdict": "direct",
            "score": 95,
            "rtt_ms": 9.2,
            "excess_ms": 1.1,
            "jitter_ms": 0.4,
            "loss": 0.0
        }]
    })
}
