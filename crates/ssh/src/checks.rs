use crate::facts::HostFacts;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use remnawave_healthcheck_core::keys::{CheckKey, NodeAspect};
use remnawave_healthcheck_core::model::{CheckResult, Node, Severity};
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// What a check concluded, before it is given the identity that makes it a `CheckResult`.
///
/// Verdict and identity are kept apart so that no check ever sees a key. A key is this tool's
/// memory across runs: one handed to the wrong check would make the old key look recovered and
/// the new one look new, and nothing about the report would look wrong while it happened.
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

/// Everything the node-side checks are allowed to look at, gathered once so that no check has to
/// be handed it a piece at a time.
struct HostChecks<'a> {
    node: &'a Node,
    facts: &'a HostFacts,
    now: DateTime<Utc>,
    cert_warn_days: u32,
    config_warn_days: u32,
}

/// One node-side check: it reads the host and answers with a verdict, never with a key.
type Check = fn(&HostChecks) -> Verdict;

/// Every check this crate runs against a host, in report order.
///
/// One list, so an unreachable host cannot report a different set of checks than a reachable one.
/// What each one is called is not decided here: an aspect carries its own name, and every key of
/// every check in the tool is built from one place, so nothing in this table can collide with a
/// check that lives in another crate.
const CHECKS: [(NodeAspect, Check); 7] = [
    (NodeAspect::Containers, |h| h.containers()),
    (NodeAspect::Ports, |h| h.ports()),
    (NodeAspect::Users, |h| h.users()),
    (NodeAspect::ConfigAge, |h| h.config_age()),
    (NodeAspect::CertExpiry, |h| h.cert()),
    (NodeAspect::CertRenewal, |h| h.renewal()),
    (NodeAspect::EgressIp, |h| h.egress()),
];

pub fn check_host(
    node: &Node,
    facts: &HostFacts,
    now: DateTime<Utc>,
    cert_warn_days: u32,
    config_warn_days: u32,
) -> Vec<CheckResult> {
    let host = HostChecks {
        node,
        facts,
        now,
        cert_warn_days,
        config_warn_days,
    };

    CHECKS
        .iter()
        .map(|(aspect, check)| {
            // An unreachable host answers every check with the one reason none of them could run,
            // rather than with a shorter list that would read as "nothing else was wrong".
            let verdict = match &facts.unreachable_reason {
                Some(reason) => Verdict::fail(reason.clone()),
                None => check(&host),
            };
            CheckResult::new(
                CheckKey::Node {
                    node: &node.name,
                    aspect: *aspect,
                }
                .key(),
                format!("{} {}", node.name, aspect.title()),
                verdict.severity,
                verdict.detail,
            )
        })
        .collect()
}

/// Comma-separated list, the way every detail line in this module writes one.
fn commas(items: impl IntoIterator<Item = impl std::fmt::Display>) -> String {
    let mut out = String::new();
    for item in items {
        if !out.is_empty() {
            out.push_str(", ");
        }
        let _ = write!(out, "{item}");
    }
    out
}

impl HostChecks<'_> {
    /// The node's own external address, reported as a fact in its own right. It is also the
    /// yardstick every channel expected to exit here is measured against, so when it is unknown
    /// the report says so out loud: those channel verdicts are then unverified rather than
    /// merely uninteresting.
    fn egress(&self) -> Verdict {
        match self.facts.egress_address() {
            Some(ip) => Verdict::ok(format!("egress {ip}")),
            None => Verdict::warn(
                "the node could not report its external address, so exits of channels expected \
                 to leave through it cannot be verified",
            ),
        }
    }
}

/// The one container this tool does expect by name: without it the node runs no Xray at all.
const NODE_CONTAINER: &str = "remnanode";

/// The only container state that is not a problem. `docker ps` also shows `restarting` and
/// `paused` containers, and the status line of a paused one still begins with "Up".
const RUNNING: &str = "running";

impl HostChecks<'_> {
    /// Any container that is not running — or is running but unhealthy — is a failure. Beyond
    /// `remnanode` there is no expected list: the node's own container set is the expectation,
    /// which keeps this free of configuration.
    fn containers(&self) -> Verdict {
        // `name<TAB>state`, split once and read three ways, instead of three passes each
        // re-splitting the same output.
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
        // A node whose container set looks perfectly healthy but does not include the node
        // container is not serving anything. Nothing else in this tool would notice on its own.
        let running: Vec<&str> = rows
            .iter()
            .map(|(name, _)| *name)
            .filter(|name| !name.is_empty())
            .collect();
        if !running.contains(&NODE_CONTAINER) {
            return Verdict::fail(format!(
                "the node container '{NODE_CONTAINER}' is not running (running: {})",
                commas(&running)
            ));
        }
        // Which containers are unhealthy is the daemon's judgement, taken from its own filter.
        // Reading it out of a status line would mean matching the substring "(unhealthy)" in
        // prose written for a human — and would go on quietly matching nothing the day that
        // prose changes.
        let unhealthy: BTreeSet<&str> = self
            .facts
            .unhealthy
            .lines()
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .collect();
        let broken: Vec<&str> = rows
            .iter()
            .filter(|(name, state)| *state != RUNNING || unhealthy.contains(name))
            .map(|(name, _)| *name)
            .collect();
        if broken.is_empty() {
            Verdict::ok(format!("{} up", rows.len()))
        } else {
            Verdict::fail(format!("not healthy: {}", commas(&broken)))
        }
    }
}

/// Ports of the `ss -ltn` listeners that something outside the node can actually reach.
///
/// A listener bound to a loopback address answers only from the node itself — the local fallback
/// web server of a Vision inbound is exactly that — so counting it would report a client-facing
/// inbound port as healthy while nothing outside can connect to it. Matching the port number
/// anywhere in the output did precisely that.
fn public_listen_ports(ss_output: &str) -> BTreeSet<u16> {
    let mut ports = BTreeSet::new();
    for line in ss_output.lines() {
        // ss -ltn: State Recv-Q Send-Q Local-Address:Port Peer-Address:Port
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

/// The address and port of one `ss` local-address field.
///
/// `SocketAddr` does the parsing wherever it can: it already knows `0.0.0.0:443` from `[::]:443`
/// from `[::1]:9000`, and what it accepts is the same notion of an address the rest of this tool
/// uses. Two shapes are left over because they are not address syntax at all: `ss` writes a
/// wildcard as `*`, and it can append an interface scope to a link-local address. Anything else
/// that does not parse — a resolved hostname, a truncated line — is no address, and a port this
/// tool cannot place is not one it may call publicly reachable.
fn listener(field: &str) -> Option<(IpAddr, u16)> {
    if let Ok(socket) = field.parse::<SocketAddr>() {
        return Some((socket.ip(), socket.port()));
    }
    let (address, port) = field.rsplit_once(':')?;
    let port = port.parse().ok()?;
    // `*:443` — bound to every address, which is as public as it gets.
    if address == "*" {
        return Some((IpAddr::V4(Ipv4Addr::UNSPECIFIED), port));
    }
    // `[fe80::1%eth0]:443` — the scope has no place in the address itself.
    let address = address.trim_matches(|c| c == '[' || c == ']');
    address.split('%').next()?.parse().ok().map(|ip| (ip, port))
}

impl HostChecks<'_> {
    /// Expected ports come from the inbounds the panel says are active on this self.node.
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
            Verdict::ok(format!("listening on {:?}", self.node.inbound_ports))
        } else {
            Verdict::fail(format!("not listening: {}", commas(&silent)))
        }
    }
}

/// Smallest `has N users` count the node logged, or `None` when it logged no such line. Only the
/// minimum is ever wanted: one inbound with no users is the failure worth reporting.
fn min_user_count(logs: &str) -> Option<u64> {
    logs.lines()
        .filter_map(|line| {
            let rest = line.split(" has ").nth(1)?;
            if !rest.contains("users") {
                return None;
            }
            rest.split_whitespace().next()?.parse::<u64>().ok()
        })
        .min()
}

impl HostChecks<'_> {
    fn users(&self) -> Verdict {
        match min_user_count(&self.facts.node_logs) {
            None => Verdict::fail("no 'has N users' lines in node logs"),
            Some(0) => Verdict::fail("an inbound has 0 users provisioned"),
            Some(min) => Verdict::ok(format!("min={min}")),
        }
    }
}

/// Timestamp of the last config push the node logged. A node quietly sitting on a stale config
/// looks healthy from the panel while its cascade outbounds carry dead credentials.
fn last_config_push(logs: &str) -> Option<DateTime<Utc>> {
    logs.lines()
        .filter(|l| l.contains(" has ") && l.contains("users"))
        .filter_map(|l| {
            // Borrowed, not collected: the prefix is a fixed-length ASCII timestamp, and this
            // runs for every one of up to 200 log lines.
            let stamp = l.get(..19)?;
            NaiveDateTime::parse_from_str(stamp, "%Y-%m-%dT%H:%M:%S")
                .or_else(|_| NaiveDateTime::parse_from_str(stamp, "%Y-%m-%d %H:%M:%S"))
                .ok()
        })
        .map(|naive| Utc.from_utc_datetime(&naive))
        .next_back()
}

impl HostChecks<'_> {
    fn config_age(&self) -> Verdict {
        match last_config_push(&self.facts.node_logs) {
            None => Verdict::warn("no config-push line in node logs"),
            Some(when) => {
                let age = (self.now - when).num_days();
                let severity = if age > i64::from(self.config_warn_days) {
                    Severity::Warn
                } else {
                    Severity::Ok
                };
                Verdict::new(severity, format!("{age}d old (last {})", when.date_naive()))
            }
        }
    }
}

impl HostChecks<'_> {
    fn cert(&self) -> Verdict {
        // No TLS endpoint to ask (the node's address is a bare IP) and an endpoint that answered
        // with nothing are different situations: the first is nothing to report, the second is a
        // certificate this tool looked at and could not read.
        let Some(probed) = self.facts.cert.as_deref() else {
            return Verdict::ok("no TLS endpoint known for this node");
        };
        let Some(raw) = probed.split("notAfter=").nth(1) else {
            return Verdict::warn("certificate not parsed");
        };
        let raw = raw.lines().next().unwrap_or("").trim();
        let Ok(parsed) = NaiveDateTime::parse_from_str(raw, "%b %e %H:%M:%S %Y GMT") else {
            return Verdict::warn(format!("unparsable notAfter: {raw}"));
        };
        let not_after = Utc.from_utc_datetime(&parsed);
        let days = (not_after - self.now).num_days();
        let severity = if days < 0 {
            Severity::Fail
        } else if days < i64::from(self.cert_warn_days) {
            Severity::Warn
        } else {
            Severity::Ok
        };
        Verdict::new(
            severity,
            format!("{days}d left ({})", not_after.date_naive()),
        )
    }
}

/// One acme.sh certificate as its `.conf` describes it, before the renewal time is known to be
/// readable.
#[derive(Debug, Default, Clone)]
struct RenewalEntry {
    webroot: Option<String>,
    due: Option<DateTime<Utc>>,
}

/// A certificate whose next renewal time did parse. Splitting these out of `RenewalEntry` is what
/// keeps the checks below free of "this one has a due date, honest" assertions.
#[derive(Debug, Clone)]
struct DueCert {
    domain: Option<String>,
    webroot: Option<String>,
    due: DateTime<Utc>,
}

impl DueCert {
    /// http-01 needs port 80; with DNS-01 (`Le_Webroot='dns*'`) the port is irrelevant.
    fn needs_port_80(&self) -> bool {
        !self.webroot.as_deref().unwrap_or("").starts_with("dns")
    }
}

/// How a certificate whose acme.sh path carried no domain has always been named in an alert.
const UNKNOWN_DOMAIN: &str = "?";

fn domain_label(domain: &Option<String>) -> &str {
    domain.as_deref().unwrap_or(UNKNOWN_DOMAIN)
}

/// Value of `key='...'` on this line, if it carries one.
fn quoted_value(line: &str, key: &str) -> Option<String> {
    let needle = format!("{key}='");
    let start = line.find(&needle)? + needle.len();
    Some(line[start..].chars().take_while(|c| *c != '\'').collect())
}

/// Lines look like `/root/.acme.sh/<domain>/<file>.conf:Le_NextRenewTimeStr='2026-09-20T10:00:00Z'`.
/// The domain comes from the directory: a host can hold several certificates and the alert must
/// name which one stalled. A line whose path carries no domain — `grep` without `-H`, say — has
/// no domain at all, which is `None` rather than a name that reads like one.
///
/// Entries whose renewal time didn't parse are kept, with `due: None`, rather than dropped here.
/// A domain with `Le_*` lines but no readable timestamp is a broken acme.sh config — a signal in
/// its own right — and the caller must be able to tell that apart from no config existing at all.
fn parse_renewal(text: &str) -> BTreeMap<Option<String>, RenewalEntry> {
    let mut found: BTreeMap<Option<String>, RenewalEntry> = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        let domain = line
            .strip_prefix("/root/.acme.sh/")
            .and_then(|rest| rest.split('/').next())
            .map(|d| d.trim_end_matches("_ecc").to_string());

        if let Some(webroot) = quoted_value(line, "Le_Webroot") {
            found.entry(domain.clone()).or_default().webroot = Some(webroot);
        }
        if let Some(due) = quoted_value(line, "Le_NextRenewTimeStr") {
            let entry = found.entry(domain).or_default();
            if let Ok(naive) = NaiveDateTime::parse_from_str(&due, "%Y-%m-%dT%H:%M:%SZ") {
                entry.due = Some(Utc.from_utc_datetime(&naive));
            }
        }
    }
    found
}

impl HostChecks<'_> {
    /// Health of the renewal *mechanism*, not of the certificate's remaining days.
    /// This is what catches a broken renewal at the first silent failure — roughly two months
    /// before the expiry check would notice.
    fn renewal(&self) -> Verdict {
        const GRACE_DAYS: i64 = 1;
        let all = parse_renewal(&self.facts.renewal);
        if all.is_empty() {
            return Verdict::ok("no acme.sh config (managed elsewhere)");
        }

        // Sorted once into the two kinds there are, so nothing below has to re-derive which is
        // which.
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

        // `Le_*` lines exist but no domain's renewal time parsed: the acme.sh config itself is
        // broken, which is a signal, not a reason to stay quiet.
        let Some(soonest) = certs.iter().min_by_key(|c| c.due) else {
            return Verdict::warn(format!(
                "acme.sh config found but its renewal time could not be read: {}",
                commas(unreadable.iter().map(domain_label))
            ));
        };

        let port80_closed = self.facts.renewal.contains("PORT80=closed");
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
            let listed = commas(
                overdue
                    .iter()
                    .map(|(c, days)| format!("{} {days}d", domain_label(&c.domain))),
            );
            let blocked = port80_closed && overdue.iter().any(|(c, _)| http01.contains(&c.domain));
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
                commas(http01.into_iter().map(domain_label))
            ));
        }
        Verdict::ok(format!(
            "next {} {}",
            domain_label(&soonest.domain),
            soonest.due.date_naive()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use remnawave_healthcheck_core::model::{Node, Severity};

    fn now() -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 22, 12, 0, 0).unwrap()
    }

    fn node() -> Node {
        Node {
            name: "beta".into(),
            address: "192.0.2.20".into(),
            profile_uuid: Some("p".into()),
            inbound_tags: vec!["in-a".into()],
            inbound_ports: vec![443, 8443],
            is_disabled: false,
            is_connected: true,
            is_connecting: false,
            last_status_message: None,
            xray_version: Some("26.6.27".into()),
        }
    }

    fn healthy_facts() -> HostFacts {
        HostFacts {
            unreachable_reason: None,
            docker_ps: "remnanode\trunning\ncaddy\trunning\n".into(),
            unhealthy: String::new(),
            listening: "LISTEN 0 4096 0.0.0.0:443 0.0.0.0:*\nLISTEN 0 4096 0.0.0.0:8443 0.0.0.0:*\n".into(),
            node_logs: "2026-08-22T09:00:00 inbound in-a has 42 users\n".into(),
            cert: Some("notAfter=Nov 20 10:00:00 2026 GMT\n".into()),
            renewal: "/root/.acme.sh/beta.example.com/beta.example.com.conf:Le_Webroot='no'\n\
                      /root/.acme.sh/beta.example.com/beta.example.com.conf:Le_NextRenewTimeStr='2026-09-20T10:00:00Z'\n\
                      PORT80=open\n".into(),
            egress_ip: "192.0.2.20\n".into(),
        }
    }

    fn severity_of(results: &[CheckResult], suffix: &str) -> Severity {
        results
            .iter()
            .find(|r| r.key.ends_with(suffix))
            .unwrap_or_else(|| panic!("no check {suffix}"))
            .severity
    }

    #[test]
    fn every_check_reports_under_its_own_key_reachable_or_not() {
        // The suffixes are the tool's memory across runs: renaming one makes the old key look
        // recovered and the new one look new, in the report and in the Telegram diff alike. A
        // check never sees its key, so this is the only place the pairing can be got wrong.
        let expected = [
            "node:beta:containers",
            "node:beta:ports",
            "node:beta:users",
            "node:beta:config-age",
            "node:beta:cert-expiry",
            "node:beta:cert-renewal",
            "node:beta:egress-ip",
        ];
        let keys = |results: &[CheckResult]| {
            results
                .iter()
                .map(|r| r.key.clone())
                .collect::<Vec<String>>()
        };

        let reachable = check_host(&node(), &healthy_facts(), now(), 14, 7);
        assert_eq!(keys(&reachable), expected);

        let unreachable = check_host(
            &node(),
            &HostFacts {
                unreachable_reason: Some("ssh unreachable".into()),
                ..HostFacts::default()
            },
            now(),
            14,
            7,
        );
        assert_eq!(keys(&unreachable), expected);
    }

    #[test]
    fn a_healthy_host_is_all_ok() {
        let r = check_host(&node(), &healthy_facts(), now(), 14, 7);
        for check in &r {
            assert_eq!(
                check.severity,
                Severity::Ok,
                "{} was {:?}: {}",
                check.key,
                check.severity,
                check.detail
            );
        }
    }

    #[test]
    fn unreachable_host_fails_every_check_with_one_reason() {
        let facts = HostFacts {
            unreachable_reason: Some("ssh unreachable: Connection timed out".into()),
            ..HostFacts::default()
        };
        let r = check_host(&node(), &facts, now(), 14, 7);
        assert_eq!(r.len(), 7, "one result per check, no more, no fewer");
        assert!(r.iter().all(|c| c.severity == Severity::Fail));
        assert!(r.iter().all(|c| c.detail.contains("unreachable")));
    }

    #[test]
    fn a_container_that_is_not_running_fails() {
        // `docker ps` lists a container that keeps dying as `restarting`, and one an operator
        // stopped mid-debugging as `paused`. The paused case is why the state is read instead of
        // the status line: that line reads "Up 5 days (Paused)", and anything keyed on "Up"
        // called it healthy.
        for state in ["restarting", "paused"] {
            let mut facts = healthy_facts();
            facts.docker_ps = format!("remnanode\trunning\ncaddy\t{state}\n");
            let r = check_host(&node(), &facts, now(), 14, 7);
            let containers = r.iter().find(|c| c.key.ends_with(":containers")).unwrap();
            assert_eq!(containers.severity, Severity::Fail, "{state}");
            assert!(containers.detail.contains("caddy"), "{}", containers.detail);
        }
    }

    #[test]
    fn a_container_the_daemon_calls_unhealthy_fails_while_still_running() {
        let mut facts = healthy_facts();
        facts.unhealthy = "remnanode\n".into();
        let r = check_host(&node(), &facts, now(), 14, 7);
        let containers = r.iter().find(|c| c.key.ends_with(":containers")).unwrap();
        assert_eq!(containers.severity, Severity::Fail);
        assert!(
            containers.detail.contains("remnanode"),
            "the reason must name the container: {}",
            containers.detail
        );
    }

    #[test]
    fn a_missing_node_container_fails_even_when_everything_else_is_up() {
        let mut facts = healthy_facts();
        facts.docker_ps = "caddy\trunning\nwatchtower\trunning\n".into();
        let r = check_host(&node(), &facts, now(), 14, 7);
        let containers = r.iter().find(|c| c.key.ends_with(":containers")).unwrap();
        assert_eq!(containers.severity, Severity::Fail);
        assert!(
            containers.detail.contains("remnanode"),
            "the reason must name the container: {}",
            containers.detail
        );
    }

    #[test]
    fn a_port_listening_only_on_loopback_is_not_a_public_inbound() {
        let mut facts = healthy_facts();
        facts.listening = "LISTEN 0 4096 0.0.0.0:443 0.0.0.0:*\n\
                           LISTEN 0 4096 127.0.0.1:8443 0.0.0.0:*\n"
            .into();
        let r = check_host(&node(), &facts, now(), 14, 7);
        let ports = r.iter().find(|c| c.key.ends_with(":ports")).unwrap();
        assert_eq!(ports.severity, Severity::Fail);
        assert!(ports.detail.contains("8443"), "{}", ports.detail);
    }

    #[test]
    fn wildcard_and_ipv6_listeners_count_as_public() {
        let mut facts = healthy_facts();
        facts.listening = "State Recv-Q Send-Q Local-Address:Port Peer-Address:Port\n\
                           LISTEN 0 4096 *:443 *:*\n\
                           LISTEN 0 4096 [::]:8443 [::]:*\n\
                           LISTEN 0 4096 [::1]:9000 [::]:*\n"
            .into();
        assert_eq!(
            severity_of(&check_host(&node(), &facts, now(), 14, 7), ":ports"),
            Severity::Ok
        );
        let public = public_listen_ports(&facts.listening);
        assert!(!public.contains(&9000), "[::1] is loopback");
    }

    #[test]
    fn a_scoped_link_local_listener_is_still_read() {
        // `fe80::1%eth0` is not address syntax `std` accepts, and dropping the line would have
        // hidden a listening port rather than reported one.
        let listening = "LISTEN 0 4096 [fe80::1%eth0]:9100 [::]:*\n";
        assert!(public_listen_ports(listening).contains(&9100));
        // A name is not an address: nothing here may call such a port publicly reachable.
        assert!(public_listen_ports("LISTEN 0 4096 localhost:9100 [::]:*\n").is_empty());
    }

    #[test]
    fn an_unknown_egress_address_warns_instead_of_passing_quietly() {
        let mut facts = healthy_facts();
        facts.egress_ip = "curl: (28) Operation timed out\n".into();
        let r = check_host(&node(), &facts, now(), 14, 7);
        let egress = r.iter().find(|c| c.key.ends_with(":egress-ip")).unwrap();
        assert_eq!(egress.severity, Severity::Warn);
        assert!(
            egress.detail.contains("cannot be verified"),
            "{}",
            egress.detail
        );

        let ok = check_host(&node(), &healthy_facts(), now(), 14, 7);
        let egress = ok.iter().find(|c| c.key.ends_with(":egress-ip")).unwrap();
        assert_eq!(egress.severity, Severity::Ok);
        assert!(egress.detail.contains("192.0.2.20"));
    }

    #[test]
    fn a_port_from_the_panel_that_is_not_listening_fails() {
        let mut facts = healthy_facts();
        facts.listening = "LISTEN 0 4096 0.0.0.0:443 0.0.0.0:*\n".into();
        let r = check_host(&node(), &facts, now(), 14, 7);
        let ports = r.iter().find(|c| c.key.ends_with(":ports")).unwrap();
        assert_eq!(ports.severity, Severity::Fail);
        assert!(ports.detail.contains("8443"));
    }

    #[test]
    fn a_stale_config_warns() {
        let mut facts = healthy_facts();
        facts.node_logs = "2026-08-01T09:00:00 inbound in-a has 42 users\n".into();
        let r = check_host(&node(), &facts, now(), 14, 7);
        assert_eq!(severity_of(&r, ":config-age"), Severity::Warn);
    }

    #[test]
    fn zero_provisioned_users_fails() {
        let mut facts = healthy_facts();
        facts.node_logs = "2026-08-22T09:00:00 inbound in-a has 0 users\n".into();
        let r = check_host(&node(), &facts, now(), 14, 7);
        assert_eq!(severity_of(&r, ":users"), Severity::Fail);
    }

    #[test]
    fn cert_expiry_warns_then_fails() {
        let mut facts = healthy_facts();
        facts.cert = Some("notAfter=Aug 30 10:00:00 2026 GMT\n".into());
        assert_eq!(
            severity_of(&check_host(&node(), &facts, now(), 14, 7), ":cert-expiry"),
            Severity::Warn
        );

        facts.cert = Some("notAfter=Aug 10 10:00:00 2026 GMT\n".into());
        assert_eq!(
            severity_of(&check_host(&node(), &facts, now(), 14, 7), ":cert-expiry"),
            Severity::Fail
        );
    }

    #[test]
    fn overdue_renewal_fails_and_names_the_domain() {
        let mut facts = healthy_facts();
        facts.renewal = "/root/.acme.sh/beta.example.com/beta.example.com.conf:Le_Webroot='no'\n\
                         /root/.acme.sh/beta.example.com/beta.example.com.conf:Le_NextRenewTimeStr='2026-06-01T10:00:00Z'\n\
                         PORT80=closed\n".into();
        let r = check_host(&node(), &facts, now(), 14, 7);
        let renewal = r.iter().find(|c| c.key.ends_with(":cert-renewal")).unwrap();
        assert_eq!(renewal.severity, Severity::Fail);
        assert!(renewal.detail.contains("beta.example.com"));
        assert!(
            renewal.detail.contains("port 80"),
            "a closed port 80 explains why http-01 cannot pass"
        );
    }

    #[test]
    fn closed_port_80_warns_before_renewal_is_overdue() {
        let mut facts = healthy_facts();
        facts.renewal = facts.renewal.replace("PORT80=open", "PORT80=closed");
        assert_eq!(
            severity_of(&check_host(&node(), &facts, now(), 14, 7), ":cert-renewal"),
            Severity::Warn
        );
    }

    #[test]
    fn dns_01_renewal_ignores_port_80() {
        let mut facts = healthy_facts();
        facts.renewal = facts
            .renewal
            .replace("Le_Webroot='no'", "Le_Webroot='dns_cf'")
            .replace("PORT80=open", "PORT80=closed");
        assert_eq!(
            severity_of(&check_host(&node(), &facts, now(), 14, 7), ":cert-renewal"),
            Severity::Ok
        );
    }

    #[test]
    fn a_host_without_acme_is_silent_about_renewal() {
        let mut facts = healthy_facts();
        facts.renewal = "NO_ACME_CONF\nPORT80=closed\n".into();
        let r = check_host(&node(), &facts, now(), 14, 7);
        let renewal = r.iter().find(|c| c.key.ends_with(":cert-renewal")).unwrap();
        assert_eq!(renewal.severity, Severity::Ok);
        assert!(renewal.detail.contains("managed elsewhere"));
    }

    #[test]
    fn unreadable_renewal_time_warns_and_names_the_domain() {
        let mut facts = healthy_facts();
        facts.renewal = "/root/.acme.sh/beta.example.com/beta.example.com.conf:Le_Webroot='no'\n\
                         /root/.acme.sh/beta.example.com/beta.example.com.conf:Le_NextRenewTimeStr='not-a-timestamp'\n\
                         PORT80=open\n".into();
        let r = check_host(&node(), &facts, now(), 14, 7);
        let renewal = r.iter().find(|c| c.key.ends_with(":cert-renewal")).unwrap();
        assert_eq!(renewal.severity, Severity::Warn);
        assert!(renewal.detail.contains("beta.example.com"));
    }

    #[test]
    fn no_acme_conf_output_still_reads_ok_after_the_unreadable_time_fix() {
        let mut facts = healthy_facts();
        facts.renewal = "NO_ACME_CONF\nPORT80=closed\n".into();
        let r = check_host(&node(), &facts, now(), 14, 7);
        let renewal = r.iter().find(|c| c.key.ends_with(":cert-renewal")).unwrap();
        assert_eq!(renewal.severity, Severity::Ok);
        assert!(renewal.detail.contains("managed elsewhere"));
    }

    #[test]
    fn a_node_without_a_tls_endpoint_is_silent_about_its_certificate() {
        let mut facts = healthy_facts();
        facts.cert = None;
        let r = check_host(&node(), &facts, now(), 14, 7);
        let cert = r.iter().find(|c| c.key.ends_with(":cert-expiry")).unwrap();
        assert_eq!(cert.severity, Severity::Ok);
        assert!(cert.detail.contains("no TLS endpoint"));
    }

    #[test]
    fn a_tls_endpoint_that_answered_with_nothing_is_not_the_same_as_having_none() {
        // The node has a name, so its certificate was asked for and the answer was empty — the
        // endpoint is down, or openssl said nothing. That is a certificate this tool looked at
        // and could not read, not a node with no TLS at all.
        let mut facts = healthy_facts();
        facts.cert = Some(String::new());
        let r = check_host(&node(), &facts, now(), 14, 7);
        let cert = r.iter().find(|c| c.key.ends_with(":cert-expiry")).unwrap();
        assert_eq!(cert.severity, Severity::Warn);
        assert_eq!(cert.detail, "certificate not parsed");
    }
}
