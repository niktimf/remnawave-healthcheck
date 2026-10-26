//! Domain types shared by every crate: what a check produces, what the panel
//! describes, and the raw facts `io` collects for the checks to judge.

use chrono::{DateTime, Utc};
use serde_json::Value;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

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

/// The port a URL without an explicit one is served on.
pub const HTTPS_PORT: u16 = 443;

/// A host whose TLS certificate is checked, and the port it answers on. A
/// panel behind a reverse proxy on a non-standard port is a supported
/// deployment, so the port travels with the host rather than being assumed.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
    /// The name presented in the handshake when it is not `host`. A fronted
    /// channel connects to its own address and presents the edge's name, and
    /// the certificate that answers is the edge's.
    pub server_name: Option<String>,
}

impl Endpoint {
    /// What the check is named after: the bare host on the standard port, and
    /// `host:port` anywhere else, so two endpoints never share a row. A
    /// presented name of its own goes first, `name via host`.
    pub fn label(&self) -> String {
        let at = if self.port == HTTPS_PORT {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        };
        match &self.server_name {
            Some(name) => format!("{name} via {at}"),
            None => at,
        }
    }

    /// The name the handshake presents.
    pub fn presented_name(&self) -> &str {
        self.server_name.as_deref().unwrap_or(&self.host)
    }
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
    /// Where xhttp clients carry the session ID and seq
    /// (`transportOptions.extra`).
    pub xhttp_placements: XhttpPlacements,
    /// Security as `/raw` names it (`tls`, `reality`, `none`).
    pub security: Option<String>,
    /// TLS name to present when probing the inbound directly
    /// (`securityOptions.serverName`).
    pub sni: Option<String>,
    /// HTTP `Host` the client sends (`transportOptions.host`). On a fronted
    /// channel it differs from [`Channel::sni`]: the handshake carries the
    /// edge's own name and this is the key the edge routes on. Send one in
    /// place of the other and the edge answers instead of the inbound.
    pub host: Option<String>,
    /// What the rendered subscription served for this channel.
    pub served: Served,
}

/// The three shapes a rendered subscription entry takes.
///
/// The third exists because a host can carry an XRAY-JSON template with a
/// `remnawave.injectHosts` block: the panel then serves it not an outbound of
/// its own but a balancer over outbounds injected from other hosts. Such a
/// host is a client-side selector — its `address:port` is a placeholder no
/// node listens on — and asking where it exits has no answer.
#[derive(Debug, Clone, PartialEq, Default)]
pub enum Served {
    /// The panel resolved the host, the subscription carries no config for it.
    #[default]
    Nothing,
    /// One ready-made Xray outbound: an ordinary channel, probed by tunnel.
    Direct(Value),
    /// The same, but taken from another entry's balancer rather than served as
    /// an entry of its own. A host the panel keeps out of this subscription
    /// type still reaches clients this way — auto-select is the only way they
    /// get it — so it is a channel like any other, and probed like one.
    Candidate(Value),
    /// A balancer over the candidates the injector selected.
    Selector(Vec<Value>),
}

impl Served {
    /// The outbound to run a tunnel through, however the subscription
    /// delivered it.
    pub const fn outbound(&self) -> Option<&Value> {
        match self {
            Self::Direct(outbound) | Self::Candidate(outbound) => {
                Some(outbound)
            }
            Self::Nothing | Self::Selector(_) => None,
        }
    }

    /// The candidates of a balancer; empty for everything else.
    pub fn candidates(&self) -> &[Value] {
        match self {
            Self::Selector(candidates) => candidates,
            Self::Nothing | Self::Direct(_) | Self::Candidate(_) => &[],
        }
    }

    pub const fn is_selector(&self) -> bool {
        matches!(self, Self::Selector(_))
    }

    /// Served inside another entry, so the subscription renders no entry of its
    /// own for it and coverage must not expect one.
    pub const fn is_candidate(&self) -> bool {
        matches!(self, Self::Candidate(_))
    }
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

    /// Where a client's handshake for this channel lands and the name it
    /// presents there, for a plain-TLS channel only: Reality answers with
    /// someone else's certificate, so its expiry is not ours to report.
    pub fn tls_endpoint(&self) -> Option<Endpoint> {
        let tls = self
            .security
            .as_deref()
            .is_some_and(|s| s.eq_ignore_ascii_case("tls"));
        if !tls {
            return None;
        }
        Some(Endpoint {
            host: self.address.clone(),
            port: self.port,
            server_name: self.sni.clone().filter(|name| *name != self.address),
        })
    }

    /// The forms of the xhttp path this channel's clients request. No client
    /// removes a slash the path ends in, and a channel without a path is
    /// requested at `/`.
    pub fn xhttp_path_forms(&self) -> PathForms {
        let ends_in_slash =
            self.path.as_deref().is_none_or(|path| path.ends_with('/'));
        if self.xhttp_placements.appends_slash() || ends_in_slash {
            PathForms::WithSlash
        } else {
            PathForms::WithAndWithoutSlash
        }
    }
}

/// Where an xhttp client carries the session ID or seq. Only the path matters
/// to the path forms, so a header, a cookie and the query are one variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Placement {
    /// After a slash in the path, xray's choice for an unset placement.
    #[default]
    Path,
    Elsewhere,
}

impl Placement {
    /// The value naming the path in a `sessionIDPlacement` or `seqPlacement`.
    const PATH_SETTING: &str = "path";

    /// The placement xray takes from a `sessionIDPlacement` or `seqPlacement`
    /// value: an unset or empty one is the path.
    pub fn from_setting(value: Option<&str>) -> Self {
        match value {
            None | Some("" | Self::PATH_SETTING) => Self::Path,
            Some(_) => Self::Elsewhere,
        }
    }
}

/// Where an xhttp client carries the session ID and seq.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct XhttpPlacements {
    pub session_id: Placement,
    pub seq: Placement,
}

impl XhttpPlacements {
    /// Whether clients from xray 26.7.11 on append the slash to the path
    /// (XTLS/Xray-core#6307): only when the session ID or seq goes in it.
    /// Older clients always append it.
    fn appends_slash(self) -> bool {
        self.session_id == Placement::Path || self.seq == Placement::Path
    }
}

/// The forms of an xhttp path clients request. The probe asks for both; the
/// answer to a form no client requests reaches no client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathForms {
    /// Only the path with the trailing slash.
    WithSlash,
    /// The path with the trailing slash from clients before xray 26.7.11, the
    /// path without it from the later ones.
    WithAndWithoutSlash,
}

/// A version string, or the reason it is not in hand. The three states are
/// different answers and the report tells them apart: a version that was never
/// asked for is not one that could not be read.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Reported {
    /// Not asked for — the family was switched off.
    #[default]
    NotRead,
    Known(String),
    Failed(String),
}

/// A host the panel knows and does not serve here. It is not a channel —
/// there is no config to probe — but an inbound it belongs to is not an
/// unmonitored one either, and saying which of the two it is needs the name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnservedHost {
    pub remark: String,
    pub inbound_tag: String,
    pub why: Unserved,
}

/// Why the panel serves a host to nobody. The two are different states: one is
/// a switch an administrator threw, the other is a host that works and is kept
/// out of this subscription format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unserved {
    /// Switched off in the panel (`metadata.isDisabled`).
    Disabled,
    /// Kept out of this subscription type
    /// (`metadata.excludeFromSubscriptionTypes`) and carried by no balancer.
    ExcludedFromType,
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
    /// The panel's own version, as `/api/system/metadata` reports it.
    pub panel_version: Reported,
    /// Hosts the panel serves to nobody here, and why.
    pub unserved: Vec<UnservedHost>,
    /// What the rendered subscription served, duplicates included, so the
    /// coverage check can name what is missing or doubled.
    pub served_remarks: Vec<String>,
    /// The subscription answered with the HWID placeholder instead of configs.
    pub hwid_stub: bool,
    /// The panel URL's endpoint — its TLS certificate is checked.
    pub panel: Endpoint,
    /// The monitoring user's subscription endpoint, when it differs from the
    /// panel's.
    pub sub: Option<Endpoint>,
    /// Hosts named in the panel's data, resolved to addresses before the
    /// routing graph is walked. A cascade can point at a front domain for a
    /// node the panel records by address, and only an address can tell that
    /// the two name one machine. This crate opens no sockets, so it is handed
    /// the answers.
    pub resolved: HashMap<String, IpAddr>,
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

/// Where a tunnel's traffic came out, plus xray's complaint when it did not,
/// and how a download through it went.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProbeOutcome {
    pub exit_ip: Option<IpAddr>,
    pub stderr_tail: String,
    pub download: Download,
}

/// A download through a tunnel that came out somewhere. The echo answer is
/// a few dozen bytes; this is what shows a path that freezes or throttles a
/// transfer after its first packets.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Download {
    /// No exit came out, or `--no-download`.
    #[default]
    NotRun,
    Complete {
        bytes: u64,
        elapsed: Duration,
    },
    /// No byte for the silence bound, or the body broke off. `of` is the
    /// `Content-Length`, when the server sent one.
    Stalled {
        bytes: u64,
        of: Option<u64>,
        after: Duration,
    },
    /// The whole download outran its time bound while bytes still came.
    TimedOut {
        bytes: u64,
        of: Option<u64>,
    },
    /// Neither an answer nor a byte.
    Failed(String),
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
        let sut = node(disabled, connecting, connected, Some("boom"));

        let state = sut.panel_state();

        assert_eq!(state, expected);
    }

    #[rstest]
    #[case::enabled_and_connected(false, false, true, true)]
    #[case::still_connecting(false, true, false, false)]
    #[case::disabled(true, false, true, false)]
    #[case::disconnected(false, false, false, false)]
    fn only_an_enabled_connected_node_is_active(
        #[case] disabled: bool,
        #[case] connecting: bool,
        #[case] connected: bool,
        #[case] expected: bool,
    ) {
        let sut = node(disabled, connecting, connected, None);

        let active = sut.is_active();

        assert_eq!(active, expected);
    }

    /// Losing the connection does not disable a node: the panel still expects
    /// it back, so its checks stay in the report.
    #[test]
    fn a_disconnected_node_is_still_enabled() {
        let sut = node(false, false, false, None);

        let enabled = sut.is_enabled();

        assert!(enabled);
    }

    #[test]
    fn an_address_that_is_an_ip_is_not_a_domain() {
        let sut = node(false, false, true, None);

        let domain = sut.domain();

        assert_eq!(domain, None);
    }

    #[test]
    fn an_address_that_is_a_hostname_is_the_nodes_domain() {
        let mut sut = node(false, false, true, None);
        sut.address = "alpha.example.com".into();

        let domain = sut.domain();

        assert_eq!(domain, Some("alpha.example.com"));
    }

    fn channel() -> Channel {
        Channel {
            remark: "beta direct".into(),
            address: "beta.example.com".into(),
            port: 8443,
            transport: Some("XHTTP".into()),
            ..Default::default()
        }
    }

    #[test]
    fn a_channel_name_carries_address_and_port() {
        let sut = channel();

        let name = sut.name();

        assert_eq!(name, "channel beta direct (beta.example.com:8443)");
    }

    fn tls_channel(sni: &str) -> Channel {
        Channel {
            security: Some("tls".into()),
            sni: Some(sni.into()),
            ..channel()
        }
    }

    #[test]
    fn a_fronted_endpoint_is_named_after_the_presented_name_and_its_address() {
        let sut = Endpoint {
            host: "front.example.com".into(),
            port: HTTPS_PORT,
            server_name: Some("edge.example.net".into()),
        };

        let label = sut.label();

        assert_eq!(label, "edge.example.net via front.example.com");
    }

    #[test]
    fn a_tls_channel_is_checked_where_it_connects_under_the_name_it_presents() {
        let sut = tls_channel("edge.example.net");

        let endpoint = sut.tls_endpoint();

        assert_eq!(
            endpoint,
            Some(Endpoint {
                host: "beta.example.com".into(),
                port: 8443,
                server_name: Some("edge.example.net".into()),
            })
        );
    }

    #[test]
    fn a_channel_presenting_its_own_address_carries_no_separate_name() {
        let sut = tls_channel("beta.example.com");

        let endpoint = sut.tls_endpoint();

        assert_eq!(endpoint.map(|e| e.server_name), Some(None));
    }

    #[rstest]
    #[case::reality(Some("reality"))]
    #[case::plain(Some("none"))]
    #[case::unknown(None)]
    fn a_channel_without_plain_tls_has_no_certificate_to_check(
        #[case] security: Option<&str>,
    ) {
        let sut = Channel {
            security: security.map(String::from),
            ..tls_channel("edge.example.net")
        };

        let endpoint = sut.tls_endpoint();

        assert_eq!(endpoint, None);
    }

    #[test]
    fn the_transport_is_recognised_whatever_its_case() {
        let sut = channel();

        let xhttp = sut.is_xhttp();

        assert!(xhttp);
    }

    fn xhttp_channel(
        path: Option<&str>,
        session_id: Placement,
        seq: Placement,
    ) -> Channel {
        Channel {
            path: path.map(String::from),
            xhttp_placements: XhttpPlacements { session_id, seq },
            ..channel()
        }
    }

    /// From xray 26.7.11 on a client appends the slash to its path only when
    /// the session ID or seq goes in the path, and never removes one; older
    /// clients append it always (XTLS/Xray-core#6307).
    #[rstest]
    #[case::both_elsewhere(
        Some("/api/v1/telemetry/ingest"),
        Placement::Elsewhere,
        Placement::Elsewhere,
        PathForms::WithAndWithoutSlash
    )]
    #[case::a_path_ending_in_a_slash(
        Some("/video/download/"),
        Placement::Elsewhere,
        Placement::Elsewhere,
        PathForms::WithSlash
    )]
    #[case::no_path(
        None,
        Placement::Elsewhere,
        Placement::Elsewhere,
        PathForms::WithSlash
    )]
    #[case::session_id_in_the_path(
        Some("/api/v1/vless/de"),
        Placement::Path,
        Placement::Elsewhere,
        PathForms::WithSlash
    )]
    #[case::seq_in_the_path(
        Some("/api/v1/vless/de"),
        Placement::Elsewhere,
        Placement::Path,
        PathForms::WithSlash
    )]
    fn only_a_slashless_path_with_both_elsewhere_is_requested_bare(
        #[case] path: Option<&str>,
        #[case] session_id: Placement,
        #[case] seq: Placement,
        #[case] expected: PathForms,
    ) {
        let sut = xhttp_channel(path, session_id, seq);

        let forms = sut.xhttp_path_forms();

        assert_eq!(forms, expected);
    }

    #[rstest]
    #[case::unset(None, Placement::Path)]
    #[case::empty(Some(""), Placement::Path)]
    #[case::named(Some("path"), Placement::Path)]
    #[case::cookie(Some("cookie"), Placement::Elsewhere)]
    fn xray_takes_an_unset_or_empty_placement_for_the_path(
        #[case] value: Option<&str>,
        #[case] expected: Placement,
    ) {
        let placement = Placement::from_setting(value);

        assert_eq!(placement, expected);
    }

    #[test]
    fn severity_pads_to_the_requested_width() {
        let sut = Severity::Ok;

        let padded = format!("{sut:<6}|");

        assert_eq!(padded, "OK    |");
    }

    #[test]
    fn severities_order_from_ok_to_fail() {
        assert!(
            Severity::Ok < Severity::Warn && Severity::Warn < Severity::Fail
        );
    }
}
