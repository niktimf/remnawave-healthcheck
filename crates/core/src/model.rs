use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Severity of a single check. Ordering matters: the run's overall severity is the maximum.
///
/// One textual encoding, and only one: the state file goes through `Display`/`FromStr` too, so
/// what is written there is the same `OK`/`WARN`/`FAIL` the report and the alerts show. A derived
/// encoding would give the same value a second spelling that nothing else in the tool understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
pub enum Severity {
    Ok,
    Warn,
    Fail,
}

impl From<Severity> for String {
    fn from(severity: Severity) -> Self {
        severity.to_string()
    }
}

impl TryFrom<String> for Severity {
    type Error = ParseSeverityError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl Severity {
    pub fn is_ok(self) -> bool {
        self == Severity::Ok
    }
}

/// How a severity appears in the report and in every alert. These three strings are part of the
/// tool's output contract, not a debug rendering.
impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `pad`, not `write_str`: the report table formats severities with a width (`{:<6}`),
        // and only `pad` honours it.
        f.pad(match self {
            Severity::Ok => "OK",
            Severity::Warn => "WARN",
            Severity::Fail => "FAIL",
        })
    }
}

/// Anything that is not one of the three labels.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown severity: {0}")]
pub struct ParseSeverityError(pub String);

impl std::str::FromStr for Severity {
    type Err = ParseSeverityError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "OK" => Ok(Severity::Ok),
            "WARN" => Ok(Severity::Warn),
            "FAIL" => Ok(Severity::Fail),
            other => Err(ParseSeverityError(other.to_string())),
        }
    }
}

/// The one place that decides what counts as an address.
///
/// Both sides of the exit comparison — what the channel's tunnel came out as, and what the node
/// says its own egress is — go through here, so neither can drift into a different notion of
/// "same address". Anything that is not a bare IP (an HTML error page from a CDN, a curl error
/// line, a captive-portal form) is not an address and must never be reported as one.
pub fn parse_ip(text: &str) -> Option<std::net::IpAddr> {
    text.trim().parse().ok()
}

/// One check outcome. `key` is stable across runs and is what the diff compares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckResult {
    pub key: String,
    pub title: String,
    pub severity: Severity,
    pub detail: String,
}

impl CheckResult {
    pub fn new(
        key: impl Into<String>,
        title: impl Into<String>,
        severity: Severity,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            key: key.into(),
            title: title.into(),
            severity,
            detail: detail.into(),
        }
    }
}

/// A node as the panel describes it.
#[derive(Debug, Clone, PartialEq)]
pub struct Node {
    pub name: String,
    /// Address the panel uses to reach the node; also the SSH target.
    pub address: String,
    pub profile_uuid: Option<String>,
    /// Tags of the inbounds currently active on this node.
    pub inbound_tags: Vec<String>,
    /// Ports of those inbounds; drives the "is it listening" check.
    pub inbound_ports: Vec<u16>,
    pub is_disabled: bool,
    pub is_connected: bool,
    pub last_status_message: Option<String>,
    pub xray_version: Option<String>,
}

/// A client-facing channel, exactly as the monitoring user receives it.
#[derive(Debug, Clone, PartialEq)]
pub struct Channel {
    /// Host remark; used as the human-facing channel name and as part of the check key.
    pub remark: String,
    pub inbound_tag: String,
    /// Config profile the panel attached this host to. `None` is a legitimate panel state — a
    /// legacy host, or one whose config profile was deleted — not corrupted data; such a channel
    /// has no entry node to resolve and must fail loudly rather than being treated as healthy.
    pub profile_uuid: Option<String>,
    pub address: String,
    pub port: u16,
    /// Ready-made Xray outbound taken from the subscription. Never assembled by us.
    /// `Value::Null` means the subscription served no config for this channel.
    pub outbound: serde_json::Value,
}

impl Channel {
    /// Stable key of this channel's check, unique by construction.
    ///
    /// The remark alone is not: it is rendered from a template configured in the panel and
    /// nothing there enforces uniqueness. Two channels sharing a remark would share a key, and
    /// since the problem set is a map, one of them would silently vanish from the alert while the
    /// report on stdout still showed both. The client-facing endpoint is what tells two hosts of
    /// the same inbound apart, so it goes into the key; the human-facing title stays the plain
    /// remark.
    pub fn check_key(&self) -> String {
        format!("channel:{}@{}:{}", self.remark, self.address, self.port)
    }
}

/// An Xray config profile: the full JSON, as stored in the panel.
#[derive(Debug, Clone, PartialEq)]
pub struct Profile {
    pub uuid: String,
    pub name: String,
    pub config: serde_json::Value,
}

/// Everything one run needs from the panel.
#[derive(Debug, Clone, PartialEq)]
pub struct Snapshot {
    pub nodes: Vec<Node>,
    pub profiles: HashMap<String, Profile>,
    pub channels: Vec<Channel>,
    /// Remarks the rendered subscription actually served, duplicates included. Kept as a list
    /// rather than a count so `subscription:coverage` can compare sets and name what is missing:
    /// one channel dropped and another one duplicated leaves the counts equal.
    pub served_remarks: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_orders_ok_below_warn_below_fail() {
        assert!(Severity::Ok < Severity::Warn);
        assert!(Severity::Warn < Severity::Fail);
    }

    #[test]
    fn only_a_bare_address_parses_as_an_ip() {
        assert_eq!(
            parse_ip(" 203.0.113.7\n"),
            Some("203.0.113.7".parse().unwrap())
        );
        assert_eq!(
            parse_ip("2001:db8::1"),
            Some("2001:db8::1".parse().unwrap())
        );
        assert_eq!(parse_ip(""), None);
        assert_eq!(
            parse_ip("<html><title>502 Bad Gateway</title></html>"),
            None
        );
        assert_eq!(parse_ip("203.0.113.7 (cached)"), None);
        assert_eq!(parse_ip("curl: (28) Operation timed out"), None);
    }

    #[test]
    fn severity_renders_the_three_report_labels() {
        assert_eq!(Severity::Ok.to_string(), "OK");
        assert_eq!(Severity::Warn.to_string(), "WARN");
        assert_eq!(Severity::Fail.to_string(), "FAIL");
    }

    #[test]
    fn severity_honours_a_format_width() {
        // The report table lays severities out in a fixed column; losing the padding would
        // silently reflow every row of the report.
        assert_eq!(format!("{:<6}|", Severity::Ok), "OK    |");
        assert_eq!(format!("{:<6}|", Severity::Fail), "FAIL  |");
    }

    #[test]
    fn severity_parses_back_from_its_own_label() {
        for s in [Severity::Ok, Severity::Warn, Severity::Fail] {
            assert_eq!(s.to_string().parse::<Severity>(), Ok(s));
        }
    }

    #[test]
    fn an_unknown_severity_label_is_an_error_naming_the_input() {
        let err = "SOMETHING".parse::<Severity>().unwrap_err();
        assert_eq!(err, ParseSeverityError("SOMETHING".to_string()));
        assert!(err.to_string().contains("SOMETHING"));
        // Case and stray whitespace are not silently accepted: the labels are exact.
        assert!("fail".parse::<Severity>().is_err());
        assert!(" FAIL".parse::<Severity>().is_err());
        assert!("".parse::<Severity>().is_err());
    }

    #[test]
    fn channels_sharing_a_remark_still_get_different_keys() {
        let channel = |address: &str, port: u16| Channel {
            remark: "the same remark".into(),
            inbound_tag: "in-a".into(),
            profile_uuid: Some("p".into()),
            address: address.into(),
            port,
            outbound: serde_json::Value::Null,
        };
        let a = channel("alpha.example.com", 443);
        let b = channel("beta.example.com", 443);
        let c = channel("alpha.example.com", 8443);
        assert_ne!(a.check_key(), b.check_key());
        assert_ne!(a.check_key(), c.check_key());
        assert!(a.check_key().starts_with("channel:"));
        // Stable across calls: the diff between two runs depends on it.
        assert_eq!(a.check_key(), channel("alpha.example.com", 443).check_key());
    }

    #[test]
    fn check_result_carries_key_title_and_detail() {
        let r = CheckResult::new("channel:alpha", "alpha", Severity::Fail, "no exit");
        assert_eq!(r.key, "channel:alpha");
        assert_eq!(r.title, "alpha");
        assert_eq!(r.severity, Severity::Fail);
        assert_eq!(r.detail, "no exit");
    }
}
