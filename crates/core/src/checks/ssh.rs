//! Verdicts over what a node answered over SSH. Only what the panel API does
//! not know: containers, listening ports and the TLS certificate lifecycle.

use super::commas;
use crate::model::{
    CheckResult, HostFacts, Node, Severity, SshOutcome, node_check,
};
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// What the renewal command prints about port 80. `io::ssh` builds the command
/// with these; the check reads them back.
pub const PORT80_OPEN: &str = "PORT80=open";
pub const PORT80_CLOSED: &str = "PORT80=closed";

/// Reads what ssh gathered from a node and says what it means. Carries the
/// settings every verdict needs, so they stop travelling as an argument.
#[derive(Debug, Clone)]
pub struct SshChecker {
    pub cert_warn_days: u32,
    /// Container the node's Xray runs in.
    pub container: String,
    /// Directory acme.sh keeps its per-domain configuration in, no trailing slash.
    pub acme_dir: String,
}

struct Verdict {
    severity: Severity,
    detail: String,
}

impl Verdict {
    fn new(severity: Severity, detail: impl Into<String>) -> Self {
        Self {
            severity,
            detail: detail.into(),
        }
    }
    fn ok(detail: impl Into<String>) -> Self {
        Self::new(Severity::Ok, detail)
    }
    fn warn(detail: impl Into<String>) -> Self {
        Self::new(Severity::Warn, detail)
    }
    fn fail(detail: impl Into<String>) -> Self {
        Self::new(Severity::Fail, detail)
    }
}

struct Host<'a> {
    node: &'a Node,
    facts: &'a HostFacts,
    now: DateTime<Utc>,
    t: &'a SshChecker,
}

type Check = fn(&Host) -> Verdict;

/// Every node-side check, in report order, with the aspect it is named by.
const CHECKS: [(&str, Check); 4] = [
    ("containers", |h| h.containers()),
    ("inbound ports", |h| h.ports()),
    ("certificate expiry", |h| h.cert()),
    ("certificate renewal", |h| h.renewal()),
];

impl SshChecker {
    /// An unreachable host is one WARN, not four FAILs: some nodes admit only
    /// the CI runners, and the API-side checks still cover them.
    pub fn check_node(
        &self,
        node: &Node,
        outcome: &SshOutcome,
        now: DateTime<Utc>,
    ) -> Vec<CheckResult> {
        let facts = match outcome {
            SshOutcome::Unreachable(reason) => {
                return vec![CheckResult::warn(
                    node_check(&node.name, "ssh"),
                    format!("unreachable: {reason}; node-side checks skipped"),
                )];
            }
            SshOutcome::Reached(facts) => facts,
        };
        let host = Host {
            node,
            facts,
            now,
            t: self,
        };
        CHECKS
            .iter()
            .map(|(aspect, check)| {
                let v = check(&host);
                CheckResult::new(
                    node_check(&node.name, aspect),
                    v.severity,
                    v.detail,
                )
            })
            .collect()
    }
}

/// The only container state that is not a problem; `paused` still says "Up".
const RUNNING: &str = "running";

impl Host<'_> {
    fn containers(&self) -> Verdict {
        let rows: Vec<(&str, &str)> = self
            .facts
            .docker_ps
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| {
                let (name, state) = l.split_once('\t').unwrap_or((l, ""));
                (name.trim(), state.trim())
            })
            .collect();
        if rows.is_empty() {
            return Verdict::fail("no containers running");
        }
        let running: Vec<&str> = rows
            .iter()
            .map(|(n, _)| *n)
            .filter(|n| !n.is_empty())
            .collect();
        let expected = self.t.container.as_str();
        if !running.contains(&expected) {
            return Verdict::fail(format!(
                "the node container '{expected}' is not running (running: {})",
                commas(&running)
            ));
        }
        let unhealthy: BTreeSet<&str> = self
            .facts
            .unhealthy
            .lines()
            .map(str::trim)
            .filter(|n| !n.is_empty())
            .collect();
        let broken: Vec<&str> = rows
            .iter()
            .filter(|(name, state)| {
                *state != RUNNING || unhealthy.contains(name)
            })
            .map(|(name, _)| *name)
            .collect();
        if broken.is_empty() {
            Verdict::ok(format!("{} up", rows.len()))
        } else {
            Verdict::fail(format!("not healthy: {}", commas(&broken)))
        }
    }

    /// Expected ports are the panel's active inbounds; a loopback listener does
    /// not count as public.
    fn ports(&self) -> Verdict {
        if self.node.inbound_ports.is_empty() {
            return Verdict::ok("no inbound ports declared by the panel");
        }
        let public = public_listen_ports(&self.facts.listening);
        let silent: Vec<u16> = self
            .node
            .inbound_ports
            .iter()
            .copied()
            .filter(|p| !public.contains(p))
            .collect();
        if silent.is_empty() {
            Verdict::ok(format!(
                "listening on {}",
                commas(&self.node.inbound_ports)
            ))
        } else {
            Verdict::fail(format!("not listening: {}", commas(&silent)))
        }
    }

    fn cert(&self) -> Verdict {
        let Some(probed) = self.facts.cert.as_deref() else {
            return Verdict::ok("no TLS endpoint known for this node");
        };
        let Some(raw) = probed.split("notAfter=").nth(1) else {
            return Verdict::warn("certificate not parsed");
        };
        let raw = raw.lines().next().unwrap_or("").trim();
        let Ok(parsed) =
            NaiveDateTime::parse_from_str(raw, "%b %e %H:%M:%S %Y GMT")
        else {
            return Verdict::warn(format!("unparsable notAfter: {raw}"));
        };
        let not_after = Utc.from_utc_datetime(&parsed);
        let days = (not_after - self.now).num_days();
        let severity = if days < 0 {
            Severity::Fail
        } else if days < i64::from(self.t.cert_warn_days) {
            Severity::Warn
        } else {
            Severity::Ok
        };
        Verdict::new(
            severity,
            format!("{days}d left ({})", not_after.date_naive()),
        )
    }

    /// Health of the renewal mechanism: catches a broken renewal about two
    /// months before the expiry check would.
    fn renewal(&self) -> Verdict {
        const GRACE_DAYS: i64 = 1;
        let all = parse_renewal(&self.facts.renewal, &self.t.acme_dir);
        if all.is_empty() {
            return Verdict::ok("no acme.sh config (managed elsewhere)");
        }
        let mut certs: Vec<DueCert> = Vec::new();
        let mut unreadable: Vec<Option<String>> = Vec::new();
        for (domain, entry) in all {
            match entry.due {
                Some(due) => certs.push(DueCert {
                    domain,
                    webroot: entry.webroot,
                    due,
                }),
                None => unreadable.push(domain),
            }
        }
        let Some(soonest) = certs.iter().min_by_key(|c| c.due) else {
            return Verdict::warn(format!(
                "acme.sh config found but its renewal time could not be read: {}",
                commas(unreadable.iter().map(|d| domain_label(d.as_deref())))
            ));
        };
        let port80_closed = self.facts.renewal.contains(PORT80_CLOSED);
        let http01: BTreeSet<&Option<String>> = certs
            .iter()
            .filter(|c| c.needs_port_80())
            .map(|c| &c.domain)
            .collect();
        let mut overdue: Vec<(&DueCert, i64)> = certs
            .iter()
            .filter_map(|c| {
                let days = (self.now - c.due).num_days();
                (days > GRACE_DAYS).then_some((c, days))
            })
            .collect();
        overdue.sort_by_key(|(_, days)| Reverse(*days));
        if !overdue.is_empty() {
            let listed = commas(overdue.iter().map(|(c, days)| {
                format!("{} {days}d", domain_label(c.domain.as_deref()))
            }));
            let blocked = port80_closed
                && overdue.iter().any(|(c, _)| http01.contains(&c.domain));
            let reason = if blocked {
                " — port 80 is closed, http-01 cannot pass"
            } else {
                ""
            };
            return Verdict::fail(format!("renewal overdue: {listed}{reason}"));
        }
        if port80_closed && !http01.is_empty() {
            return Verdict::warn(format!(
                "port 80 is closed — http-01 renewal will fail: {}",
                commas(http01.into_iter().map(|d| domain_label(d.as_deref())))
            ));
        }
        Verdict::ok(format!(
            "next {} {}",
            domain_label(soonest.domain.as_deref()),
            soonest.due.date_naive()
        ))
    }
}

/// Ports of the `ss -ltn` listeners something outside the node can reach.
fn public_listen_ports(ss_output: &str) -> BTreeSet<u16> {
    let mut ports = BTreeSet::new();
    for line in ss_output.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 5 || !fields[0].eq_ignore_ascii_case("LISTEN") {
            continue;
        }
        let Some((address, port)) = listener(fields[3]) else {
            continue;
        };
        if address.is_loopback() {
            continue;
        }
        ports.insert(port);
    }
    ports
}

/// `*:443`, `[::]:8443`, `[fe80::1%eth0]:9100` — the shapes `ss` prints that
/// `SocketAddr` does not parse on its own.
fn listener(field: &str) -> Option<(IpAddr, u16)> {
    if let Ok(socket) = field.parse::<SocketAddr>() {
        return Some((socket.ip(), socket.port()));
    }
    let (address, port) = field.rsplit_once(':')?;
    let port = port.parse().ok()?;
    if address == "*" {
        return Some((IpAddr::V4(Ipv4Addr::UNSPECIFIED), port));
    }
    let address = address.trim_matches(|c| c == '[' || c == ']');
    address.split('%').next()?.parse().ok().map(|ip| (ip, port))
}

#[derive(Debug, Default, Clone)]
struct RenewalEntry {
    webroot: Option<String>,
    due: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
struct DueCert {
    domain: Option<String>,
    webroot: Option<String>,
    due: DateTime<Utc>,
}

impl DueCert {
    /// http-01 needs port 80; dns-01 (`Le_Webroot='dns*'`) does not.
    fn needs_port_80(&self) -> bool {
        !self.webroot.as_deref().unwrap_or("").starts_with("dns")
    }
}

const UNKNOWN_DOMAIN: &str = "?";

fn domain_label(domain: Option<&str>) -> &str {
    domain.unwrap_or(UNKNOWN_DOMAIN)
}

/// Value of `key='...'` on this line, if it carries one.
fn quoted_value(line: &str, key: &str) -> Option<String> {
    let needle = format!("{key}='");
    let start = line.find(&needle)? + needle.len();
    Some(line[start..].chars().take_while(|c| *c != '\'').collect())
}

/// Lines look like `/root/.acme.sh/<domain>/<file>.conf:Le_NextRenewTimeStr='...'`.
/// Entries whose time did not parse keep `due: None`: a broken acme.sh config
/// is a signal, not silence.
fn parse_renewal(
    text: &str,
    acme_dir: &str,
) -> BTreeMap<Option<String>, RenewalEntry> {
    let prefix = format!("{acme_dir}/");
    let mut found: BTreeMap<Option<String>, RenewalEntry> = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        let domain = line
            .strip_prefix(prefix.as_str())
            .and_then(|rest| rest.split('/').next())
            .map(|d| d.trim_end_matches("_ecc").to_string());
        if let Some(webroot) = quoted_value(line, "Le_Webroot") {
            found.entry(domain.clone()).or_default().webroot = Some(webroot);
        }
        if let Some(due) = quoted_value(line, "Le_NextRenewTimeStr") {
            let entry = found.entry(domain).or_default();
            if let Ok(naive) =
                NaiveDateTime::parse_from_str(&due, "%Y-%m-%dT%H:%M:%SZ")
            {
                entry.due = Some(Utc.from_utc_datetime(&naive));
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::by_aspect;
    use rstest::rstest;

    fn checker() -> SshChecker {
        SshChecker {
            cert_warn_days: 14,
            container: "remnanode".into(),
            acme_dir: "/root/.acme.sh".into(),
        }
    }

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 22, 12, 0, 0).unwrap()
    }

    fn node() -> Node {
        Node {
            name: "beta".into(),
            address: "192.0.2.20".into(),
            inbound_ports: vec![443, 8443],
            is_connected: true,
            ..Default::default()
        }
    }

    fn healthy() -> HostFacts {
        HostFacts {
            docker_ps: "remnanode\trunning\ncaddy\trunning\n".into(),
            unhealthy: String::new(),
            listening: "LISTEN 0 4096 0.0.0.0:443 0.0.0.0:*\nLISTEN 0 4096 0.0.0.0:8443 0.0.0.0:*\n".into(),
            cert: Some("notAfter=Nov 20 10:00:00 2026 GMT\n".into()),
            renewal: "/root/.acme.sh/beta.example.com/beta.example.com.conf:Le_Webroot='no'\n\
                      /root/.acme.sh/beta.example.com/beta.example.com.conf:Le_NextRenewTimeStr='2026-09-20T10:00:00Z'\n\
                      PORT80=open\n".into(),
        }
    }

    /// The healthy host with one gathered fact replaced.
    fn reached(mutate: impl FnOnce(&mut HostFacts)) -> SshOutcome {
        let mut facts = healthy();
        mutate(&mut facts);
        SshOutcome::Reached(facts)
    }

    #[test]
    fn a_healthy_host_is_four_ok_results_in_order() {
        let outcome = SshOutcome::Reached(healthy());
        let sut = checker();

        let results = sut.check_node(&node(), &outcome, now());

        let names: Vec<&str> =
            results.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "node beta / containers",
                "node beta / inbound ports",
                "node beta / certificate expiry",
                "node beta / certificate renewal"
            ]
        );
        for c in &results {
            assert_eq!(c.severity, Severity::Ok, "{}: {}", c.name, c.detail);
        }
    }

    /// A node that refuses ssh is one warning, not a wall of red: the API-side
    /// checks still cover it.
    #[test]
    fn an_unreachable_host_is_one_warning_and_nothing_else() {
        let outcome = SshOutcome::Unreachable("Connection timed out".into());
        let sut = checker();

        let results = sut.check_node(&node(), &outcome, now());

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "node beta / ssh");
        assert_eq!(results[0].severity, Severity::Warn);
        assert!(
            results[0].detail.contains("Connection timed out"),
            "{}",
            results[0].detail
        );
    }

    #[rstest]
    #[case::restarting(
        "remnanode\trunning\ncaddy\trestarting\n",
        "",
        Severity::Fail,
        "caddy"
    )]
    #[case::paused(
        "remnanode\trunning\ncaddy\tpaused\n",
        "",
        Severity::Fail,
        "caddy"
    )]
    #[case::unhealthy_but_running(
        "remnanode\trunning\n",
        "remnanode\n",
        Severity::Fail,
        "remnanode"
    )]
    #[case::node_container_missing(
        "caddy\trunning\nwatchtower\trunning\n",
        "",
        Severity::Fail,
        "remnanode"
    )]
    #[case::nothing_running("", "", Severity::Fail, "no containers")]
    #[case::all_good(
        "remnanode\trunning\ncaddy\trunning\n",
        "",
        Severity::Ok,
        "2 up"
    )]
    fn containers_verdicts(
        #[case] docker_ps: &str,
        #[case] unhealthy: &str,
        #[case] expected: Severity,
        #[case] mentions: &str,
    ) {
        let outcome = reached(|f| {
            f.docker_ps = docker_ps.into();
            f.unhealthy = unhealthy.into();
        });
        let sut = checker();

        let results = sut.check_node(&node(), &outcome, now());

        let containers = by_aspect(&results, "containers");
        assert_eq!(containers.severity, expected, "{}", containers.detail);
        assert!(containers.detail.contains(mentions), "{}", containers.detail);
    }

    #[rstest]
    #[case::loopback_does_not_count(
        "LISTEN 0 4096 0.0.0.0:443 0.0.0.0:*\nLISTEN 0 4096 127.0.0.1:8443 0.0.0.0:*\n",
        Severity::Fail
    )]
    #[case::wildcard_and_ipv6_count(
        "State Recv-Q Send-Q Local-Address:Port Peer-Address:Port\nLISTEN 0 4096 *:443 *:*\nLISTEN 0 4096 [::]:8443 [::]:*\n",
        Severity::Ok
    )]
    #[case::missing_port(
        "LISTEN 0 4096 0.0.0.0:443 0.0.0.0:*\n",
        Severity::Fail
    )]
    fn ports_verdicts(#[case] listening: &str, #[case] expected: Severity) {
        let outcome = reached(|f| f.listening = listening.into());
        let sut = checker();

        let results = sut.check_node(&node(), &outcome, now());

        let ports = by_aspect(&results, "inbound ports");
        assert_eq!(ports.severity, expected, "{}", ports.detail);
    }

    #[rstest]
    #[case::scoped_link_local(
        "LISTEN 0 4096 [fe80::1%eth0]:9100 [::]:*\n",
        true
    )]
    #[case::a_hostname_is_not_an_address(
        "LISTEN 0 4096 localhost:9100 [::]:*\n",
        false
    )]
    #[case::ipv6_loopback("LISTEN 0 4096 [::1]:9000 [::]:*\n", false)]
    fn a_listener_counts_only_on_a_public_address(
        #[case] line: &str,
        #[case] expected: bool,
    ) {
        let ports = public_listen_ports(line);

        assert_eq!(!ports.is_empty(), expected, "{ports:?}");
    }

    #[rstest]
    #[case::far_away(Some("notAfter=Nov 20 10:00:00 2026 GMT\n"), Severity::Ok)]
    #[case::soon(Some("notAfter=Aug 30 10:00:00 2026 GMT\n"), Severity::Warn)]
    #[case::expired(
        Some("notAfter=Aug 10 10:00:00 2026 GMT\n"),
        Severity::Fail
    )]
    #[case::no_endpoint(None, Severity::Ok)]
    #[case::endpoint_answered_nothing(Some(""), Severity::Warn)]
    fn cert_expiry_verdicts(
        #[case] cert: Option<&str>,
        #[case] expected: Severity,
    ) {
        let outcome = reached(|f| f.cert = cert.map(String::from));
        let sut = checker();

        let results = sut.check_node(&node(), &outcome, now());

        let expiry = by_aspect(&results, "certificate expiry");
        assert_eq!(expiry.severity, expected, "{}", expiry.detail);
    }

    #[rstest]
    #[case::overdue_and_port_closed(
        "/root/.acme.sh/beta.example.com/beta.example.com.conf:Le_Webroot='no'\n/root/.acme.sh/beta.example.com/beta.example.com.conf:Le_NextRenewTimeStr='2026-06-01T10:00:00Z'\nPORT80=closed\n",
        Severity::Fail,
        "port 80"
    )]
    #[case::port_closed_before_due(
        "/root/.acme.sh/beta.example.com/beta.example.com.conf:Le_Webroot='no'\n/root/.acme.sh/beta.example.com/beta.example.com.conf:Le_NextRenewTimeStr='2026-09-20T10:00:00Z'\nPORT80=closed\n",
        Severity::Warn,
        "port 80"
    )]
    #[case::dns01_ignores_port_80(
        "/root/.acme.sh/beta.example.com/beta.example.com.conf:Le_Webroot='dns_cf'\n/root/.acme.sh/beta.example.com/beta.example.com.conf:Le_NextRenewTimeStr='2026-09-20T10:00:00Z'\nPORT80=closed\n",
        Severity::Ok,
        "next beta.example.com"
    )]
    #[case::no_acme_at_all(
        "PORT80=closed\n",
        Severity::Ok,
        "managed elsewhere"
    )]
    #[case::unreadable_time(
        "/root/.acme.sh/beta.example.com/beta.example.com.conf:Le_Webroot='no'\n/root/.acme.sh/beta.example.com/beta.example.com.conf:Le_NextRenewTimeStr='not-a-timestamp'\nPORT80=open\n",
        Severity::Warn,
        "beta.example.com"
    )]
    fn renewal_verdicts(
        #[case] renewal: &str,
        #[case] expected: Severity,
        #[case] mentions: &str,
    ) {
        let outcome = reached(|f| f.renewal = renewal.into());
        let sut = checker();

        let results = sut.check_node(&node(), &outcome, now());

        let result = by_aspect(&results, "certificate renewal");
        assert_eq!(result.severity, expected, "{}", result.detail);
        assert!(result.detail.contains(mentions), "{}", result.detail);
    }
}
