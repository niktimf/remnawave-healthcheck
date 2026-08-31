//! Domain types shared by every crate: what a check produces, what the panel
//! describes, and the raw facts `io` collects for the checks to judge.

use chrono::{DateTime, Utc};
use serde_json::Value;
use std::collections::HashMap;
use std::net::IpAddr;

/// Severity of one check. A run's severity is the maximum over its results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Ok,
    Warn,
    Fail,
}

impl Severity {
    pub fn is_ok(self) -> bool {
        self == Self::Ok
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `pad` honours the column width the report table asks for.
        f.pad(self.label())
    }
}

/// One check outcome. `name` is the check's only identity; the report sorts
/// by severity and then by name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckResult {
    pub severity: Severity,
    pub name: String,
    pub detail: String,
}

impl CheckResult {
    pub fn new(
        name: impl Into<String>,
        severity: Severity,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            severity,
            name: name.into(),
            detail: detail.into(),
        }
    }

    pub fn ok(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self::new(name, Severity::Ok, detail)
    }

    pub fn warn(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self::new(name, Severity::Warn, detail)
    }

    pub fn fail(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self::new(name, Severity::Fail, detail)
    }
}

/// Name of a per-node check.
pub fn node_check(node: &str, aspect: &str) -> String {
    format!("node {node} / {aspect}")
}

/// The one place that decides what counts as an address. Both sides of an
/// exit comparison go through here, so an error page never becomes an IP.
pub fn parse_ip(text: &str) -> Option<IpAddr> {
    text.trim().parse().ok()
}

/// Host telemetry the panel relays from the node agent (`system` in `/api/nodes`).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct HostStats {
    pub cpus: u32,
    pub memory_total: u64,
    pub memory_free: u64,
    /// 1, 5 and 15 minute load averages, as the node reports them.
    pub load_avg: Vec<f64>,
    pub uptime_secs: u64,
}

/// A node as `/api/nodes` describes it.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Node {
    pub uuid: String,
    pub name: String,
    /// Address the panel reaches the node at; also the SSH target.
    pub address: String,
    pub country_code: String,
    pub is_disabled: bool,
    pub is_connected: bool,
    /// Mid-(re)connect; `is_connected` is false for that whole window.
    pub is_connecting: bool,
    pub last_status_message: Option<String>,
    pub users_online: u64,
    /// Seconds since xray last (re)started. A config push restarts xray, so
    /// this is the age of the applied config.
    pub xray_uptime_secs: u64,
    pub xray_version: Option<String>,
    pub node_version: Option<String>,
    pub system: Option<HostStats>,
    pub profile_uuid: Option<String>,
    pub inbound_tags: Vec<String>,
    pub inbound_ports: Vec<u16>,
}

impl Node {
    /// The panel's verdict, with a fixed precedence: disabled explains
    /// everything else; connecting keeps a stale `last_status_message` out of
    /// the report.
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
    pub const fn is_enabled(&self) -> bool {
        !self.is_disabled
    }

    /// Enabled and connected: the only state in which runtime numbers
    /// (users online, xray uptime, host stats) mean anything.
    pub const fn is_active(&self) -> bool {
        !self.is_disabled && !self.is_connecting && self.is_connected
    }

    /// The address when it is a name rather than an IP — what a TLS
    /// certificate can be asked about.
    pub fn domain(&self) -> Option<&str> {
        self.address
            .parse::<IpAddr>()
            .is_err()
            .then_some(self.address.as_str())
    }
}

/// What the panel says about a node, as one value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PanelState<'a> {
    Disabled,
    Connecting,
    Disconnected { reason: Option<&'a str> },
    Connected,
}

/// A client-facing channel, exactly as the monitoring user receives it.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Channel {
    /// Host remark: the human-facing channel name. Not unique on its own.
    pub remark: String,
    pub inbound_tag: String,
    /// `None` is a legitimate panel state (host without a profile); such a
    /// channel cannot be resolved and must fail loudly.
    pub profile_uuid: Option<String>,
    pub address: String,
    pub port: u16,
    /// Transport as `/raw` names it (`tcp`, `xhttp`, `ws`, ...).
    pub transport: Option<String>,
    /// xhttp/ws path, when the transport has one.
    pub path: Option<String>,
    /// SNI to present when probing the inbound directly.
    pub sni: Option<String>,
    /// Ready-made Xray outbound from the subscription. `Value::Null` means the
    /// subscription served no config for this channel.
    pub outbound: Value,
}

impl Channel {
    /// The check name: address and port are part of it because a remark is
    /// rendered from a panel template and two hosts can share one.
    pub fn name(&self) -> String {
        format!("channel {} ({}:{})", self.remark, self.address, self.port)
    }

    pub fn is_xhttp(&self) -> bool {
        self.transport
            .as_deref()
            .is_some_and(|t| t.eq_ignore_ascii_case("xhttp"))
    }
}

/// An Xray config profile: the full JSON, as stored in the panel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    pub uuid: String,
    pub name: String,
    pub config: Value,
}

/// Everything one run needs from the panel.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Snapshot {
    pub nodes: Vec<Node>,
    pub profiles: HashMap<String, Profile>,
    pub channels: Vec<Channel>,
    /// What the rendered subscription served, duplicates included, so the
    /// coverage check can name what is missing or doubled.
    pub served_remarks: Vec<String>,
    /// The subscription answered with the HWID placeholder instead of configs.
    pub hwid_stub: bool,
    /// Host of the panel URL — its TLS certificate is checked.
    pub panel_host: String,
    /// Host of the monitoring user's subscription URL, when it differs from
    /// the panel host.
    pub sub_host: Option<String>,
}

// ---------------------------------------------------------------------------
// Facts: produced by `io`, judged by `core::checks`.
// ---------------------------------------------------------------------------

/// Raw command output from one host over SSH.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostFacts {
    /// `name<TAB>state` per line, state being docker's machine value.
    pub docker_ps: String,
    /// Containers docker itself calls unhealthy, one per line.
    pub unhealthy: String,
    /// `ss -ltn` output.
    pub listening: String,
    /// `openssl x509 -enddate` output, or `None` when the node has no name.
    pub cert: Option<String>,
    /// acme.sh `Le_*` lines plus a `PORT80=open|closed` marker.
    pub renewal: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshOutcome {
    Reached(HostFacts),
    /// Why the session could not be opened, in ssh's own words.
    Unreachable(String),
}

/// What a completed geocheck job says about a node.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct GeoFacts {
    /// `rawReport.identity.ipv4`, when it parses as an address.
    pub egress: Option<IpAddr>,
    /// The whole `rawReport`, read defensively by the geo checks.
    pub report: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub enum GeoOutcome {
    Done(GeoFacts),
    /// The job failed, timed out or the node cannot run geocheck.
    Failed(String),
}

/// What a TLS handshake with an endpoint revealed.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TlsFacts {
    pub not_after: Option<DateTime<Utc>>,
    /// Handshake error text; `"expired"` when the peer certificate has expired.
    pub error: Option<String>,
}

/// Where a tunnel's traffic came out, plus xray's complaint when it did not.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProbeOutcome {
    pub exit_ip: Option<IpAddr>,
    pub stderr_tail: String,
}

/// HTTP status of the two xhttp path forms, or why there was none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XhttpFacts {
    pub without_slash: Result<u16, String>,
    pub with_slash: Result<u16, String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn node(
        disabled: bool,
        connecting: bool,
        connected: bool,
        message: Option<&str>,
    ) -> Node {
        Node {
            name: "alpha".into(),
            address: "192.0.2.1".into(),
            is_disabled: disabled,
            is_connecting: connecting,
            is_connected: connected,
            last_status_message: message.map(String::from),
            ..Default::default()
        }
    }

    #[rstest]
    #[case::disabled_wins_over_connected(
        true,
        false,
        true,
        PanelState::Disabled
    )]
    #[case::disabled_wins_over_connecting(
        true,
        true,
        false,
        PanelState::Disabled
    )]
    #[case::connecting_hides_stale_reason(
        false,
        true,
        false,
        PanelState::Connecting
    )]
    #[case::disconnected_with_reason(false, false, false, PanelState::Disconnected { reason: Some("boom") })]
    #[case::connected_ignores_old_reason(
        false,
        false,
        true,
        PanelState::Connected
    )]
    fn panel_state_has_a_fixed_precedence(
        #[case] disabled: bool,
        #[case] connecting: bool,
        #[case] connected: bool,
        #[case] expected: PanelState<'static>,
    ) {
        assert_eq!(
            node(disabled, connecting, connected, Some("boom")).panel_state(),
            expected
        );
    }

    #[test]
    fn only_an_enabled_connected_node_is_active() {
        assert!(node(false, false, true, None).is_active());
        assert!(!node(false, true, false, None).is_active());
        assert!(!node(true, false, true, None).is_active());
        assert!(node(false, false, false, None).is_enabled());
    }

    #[test]
    fn a_domain_is_an_address_that_is_not_an_ip() {
        let mut n = node(false, false, true, None);
        assert_eq!(n.domain(), None);
        n.address = "alpha.example.com".into();
        assert_eq!(n.domain(), Some("alpha.example.com"));
    }

    #[test]
    fn a_channel_name_carries_address_and_port() {
        let c = Channel {
            remark: "beta direct".into(),
            address: "beta.example.com".into(),
            port: 8443,
            transport: Some("XHTTP".into()),
            ..Default::default()
        };
        assert_eq!(c.name(), "channel beta direct (beta.example.com:8443)");
        assert!(c.is_xhttp());
    }

    #[test]
    fn severity_pads_to_the_requested_width() {
        assert_eq!(format!("{:<6}|", Severity::Ok), "OK    |");
        assert!(
            Severity::Ok < Severity::Warn && Severity::Warn < Severity::Fail
        );
    }
}
