use crate::facts::HostFacts;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use remnawave_healthcheck_core::model::{CheckResult, Node, Severity};
use std::collections::{BTreeMap, BTreeSet};

pub fn check_host(
    node: &Node,
    facts: &HostFacts,
    now: DateTime<Utc>,
    cert_warn_days: i64,
    config_warn_days: i64,
) -> Vec<CheckResult> {
    let key = |suffix: &str| format!("node:{}:{}", node.name, suffix);
    let title = |suffix: &str| format!("{} {}", node.name, suffix);
    let suffixes = [
        "containers",
        "ports",
        "users",
        "config-age",
        "cert",
        "cert-renewal",
        "egress-ip",
    ];

    if !facts.reachable {
        let detail = facts.unreachable_reason.clone();
        return suffixes
            .iter()
            .map(|s| CheckResult::new(key(s), title(s), Severity::Fail, detail.clone()))
            .collect();
    }

    vec![
        containers(&key("containers"), &title("containers"), facts),
        ports(&key("ports"), &title("ports"), node, facts),
        users(&key("users"), &title("users"), facts),
        config_age(
            &key("config-age"),
            &title("config-age"),
            facts,
            now,
            config_warn_days,
        ),
        cert(&key("cert"), &title("cert"), facts, now, cert_warn_days),
        renewal(&key("cert-renewal"), &title("cert-renewal"), facts, now),
        egress(&key("egress-ip"), &title("egress-ip"), facts),
    ]
}

/// The node's own external address, reported as a fact in its own right. It is also the yardstick
/// every channel expected to exit here is measured against, so when it is unknown the report says
/// so out loud: those channel verdicts are then unverified rather than merely uninteresting.
fn egress(key: &str, title: &str, facts: &HostFacts) -> CheckResult {
    match egress_ip(facts) {
        Some(ip) => CheckResult::new(key, title, Severity::Ok, format!("egress {ip}")),
        None => CheckResult::new(
            key,
            title,
            Severity::Warn,
            "the node could not report its external address, so exits of channels expected to \
             leave through it cannot be verified",
        ),
    }
}

/// The one container this tool does expect by name: without it the node runs no Xray at all.
const NODE_CONTAINER: &str = "remnanode";

/// Any container that is not up — or is up but unhealthy — is a failure. Beyond `remnanode` there
/// is no expected list: the node's own container set is the expectation, which keeps this free of
/// configuration.
fn containers(key: &str, title: &str, facts: &HostFacts) -> CheckResult {
    let broken: Vec<&str> = facts
        .docker_ps
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter(|l| {
            let status = l.split('\t').nth(1).unwrap_or("");
            !status.starts_with("Up") || status.contains("unhealthy")
        })
        .filter_map(|l| l.split('\t').next())
        .collect();

    let total = facts
        .docker_ps
        .lines()
        .filter(|l| !l.trim().is_empty())
        .count();
    if total == 0 {
        return CheckResult::new(key, title, Severity::Fail, "no containers running");
    }
    // A node whose container set looks perfectly healthy but does not include the node container
    // is not serving anything. Nothing else in this tool would notice on its own.
    let running: Vec<&str> = facts
        .docker_ps
        .lines()
        .filter_map(|l| l.split('\t').next())
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .collect();
    if !running.contains(&NODE_CONTAINER) {
        return CheckResult::new(
            key,
            title,
            Severity::Fail,
            format!(
                "the node container '{NODE_CONTAINER}' is not running (running: {})",
                running.join(", ")
            ),
        );
    }
    if broken.is_empty() {
        CheckResult::new(key, title, Severity::Ok, format!("{total} up"))
    } else {
        CheckResult::new(
            key,
            title,
            Severity::Fail,
            format!("not healthy: {}", broken.join(", ")),
        )
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
        let Some((address, port)) = fields[3].rsplit_once(':') else {
            continue;
        };
        let Ok(port) = port.parse::<u16>() else {
            continue;
        };
        if is_loopback(address) {
            continue;
        }
        ports.insert(port);
    }
    ports
}

/// `127.0.0.1`, `[::1]`, and anything else that only the node can reach. A wildcard (`*`,
/// `0.0.0.0`, `[::]`) or a concrete external address is not loopback and counts as public.
fn is_loopback(address: &str) -> bool {
    let address = address.trim_matches(|c| c == '[' || c == ']');
    // ss can append a scope, e.g. `fe80::1%eth0`.
    let address = address.split('%').next().unwrap_or(address);
    match address.parse::<std::net::IpAddr>() {
        Ok(ip) => ip.is_loopback(),
        Err(_) => address == "localhost",
    }
}

/// Expected ports come from the inbounds the panel says are active on this node.
fn ports(key: &str, title: &str, node: &Node, facts: &HostFacts) -> CheckResult {
    if node.inbound_ports.is_empty() {
        return CheckResult::new(
            key,
            title,
            Severity::Ok,
            "no inbound ports declared by the panel",
        );
    }
    let public = public_listen_ports(&facts.listening);
    let silent: Vec<String> = node
        .inbound_ports
        .iter()
        .filter(|p| !public.contains(p))
        .map(|p| p.to_string())
        .collect();
    if silent.is_empty() {
        CheckResult::new(
            key,
            title,
            Severity::Ok,
            format!("listening on {:?}", node.inbound_ports),
        )
    } else {
        CheckResult::new(
            key,
            title,
            Severity::Fail,
            format!("not listening: {}", silent.join(", ")),
        )
    }
}

fn user_counts(logs: &str) -> Vec<u64> {
    logs.lines()
        .filter_map(|line| {
            let rest = line.split(" has ").nth(1)?;
            if !rest.contains("users") {
                return None;
            }
            rest.split_whitespace().next()?.parse::<u64>().ok()
        })
        .collect()
}

fn users(key: &str, title: &str, facts: &HostFacts) -> CheckResult {
    let counts = user_counts(&facts.node_logs);
    match counts.iter().min() {
        None => CheckResult::new(
            key,
            title,
            Severity::Fail,
            "no 'has N users' lines in node logs",
        ),
        Some(0) => CheckResult::new(
            key,
            title,
            Severity::Fail,
            "an inbound has 0 users provisioned",
        ),
        Some(min) => CheckResult::new(key, title, Severity::Ok, format!("min={min}")),
    }
}

/// Timestamp of the last config push the node logged. A node quietly sitting on a stale config
/// looks healthy from the panel while its cascade outbounds carry dead credentials.
fn last_config_push(logs: &str) -> Option<DateTime<Utc>> {
    logs.lines()
        .filter(|l| l.contains(" has ") && l.contains("users"))
        .filter_map(|l| {
            let stamp: String = l.chars().take(19).collect();
            NaiveDateTime::parse_from_str(&stamp, "%Y-%m-%dT%H:%M:%S")
                .or_else(|_| NaiveDateTime::parse_from_str(&stamp, "%Y-%m-%d %H:%M:%S"))
                .ok()
        })
        .map(|naive| Utc.from_utc_datetime(&naive))
        .next_back()
}

fn config_age(
    key: &str,
    title: &str,
    facts: &HostFacts,
    now: DateTime<Utc>,
    warn_days: i64,
) -> CheckResult {
    match last_config_push(&facts.node_logs) {
        None => CheckResult::new(
            key,
            title,
            Severity::Warn,
            "no config-push line in node logs",
        ),
        Some(when) => {
            let age = (now - when).num_days();
            let severity = if age > warn_days {
                Severity::Warn
            } else {
                Severity::Ok
            };
            CheckResult::new(
                key,
                title,
                severity,
                format!("{age}d old (last {})", when.date_naive()),
            )
        }
    }
}

fn cert(
    key: &str,
    title: &str,
    facts: &HostFacts,
    now: DateTime<Utc>,
    warn_days: i64,
) -> CheckResult {
    if facts.cert.trim().is_empty() {
        return CheckResult::new(
            key,
            title,
            Severity::Ok,
            "no TLS endpoint known for this node",
        );
    }
    let Some(raw) = facts.cert.split("notAfter=").nth(1) else {
        return CheckResult::new(key, title, Severity::Warn, "certificate not parsed");
    };
    let raw = raw.lines().next().unwrap_or("").trim();
    let Ok(parsed) = NaiveDateTime::parse_from_str(raw, "%b %e %H:%M:%S %Y GMT") else {
        return CheckResult::new(
            key,
            title,
            Severity::Warn,
            format!("unparsable notAfter: {raw}"),
        );
    };
    let not_after = Utc.from_utc_datetime(&parsed);
    let days = (not_after - now).num_days();
    let severity = if days < 0 {
        Severity::Fail
    } else if days < warn_days {
        Severity::Warn
    } else {
        Severity::Ok
    };
    CheckResult::new(
        key,
        title,
        severity,
        format!("{days}d left ({})", not_after.date_naive()),
    )
}

#[derive(Debug, Default, Clone)]
struct RenewalEntry {
    webroot: Option<String>,
    due: Option<DateTime<Utc>>,
}

/// Lines look like `/root/.acme.sh/<domain>/<file>.conf:Le_NextRenewTimeStr='2026-09-20T10:00:00Z'`.
/// The domain comes from the directory: a host can hold several certificates and the alert must
/// name which one stalled.
///
/// Entries whose renewal time didn't parse are kept, with `due: None`, rather than dropped here.
/// A domain with `Le_*` lines but no readable timestamp is a broken acme.sh config — a signal in
/// its own right — and the caller must be able to tell that apart from no config existing at all.
fn parse_renewal(text: &str) -> BTreeMap<String, RenewalEntry> {
    let mut found: BTreeMap<String, RenewalEntry> = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        let domain = line
            .strip_prefix("/root/.acme.sh/")
            .and_then(|rest| rest.split('/').next())
            .map(|d| d.trim_end_matches("_ecc").to_string())
            .unwrap_or_else(|| "?".to_string());

        for key in ["Le_Webroot", "Le_NextRenewTimeStr"] {
            let needle = format!("{key}='");
            if let Some(start) = line.find(&needle) {
                let value: String = line[start + needle.len()..]
                    .chars()
                    .take_while(|c| *c != '\'')
                    .collect();
                let entry = found.entry(domain.clone()).or_default();
                if key == "Le_Webroot" {
                    entry.webroot = Some(value);
                } else if let Ok(naive) =
                    NaiveDateTime::parse_from_str(&value, "%Y-%m-%dT%H:%M:%SZ")
                {
                    entry.due = Some(Utc.from_utc_datetime(&naive));
                }
            }
        }
    }
    found
}

/// Health of the renewal *mechanism*, not of the certificate's remaining days.
/// This is what catches a broken renewal at the first silent failure — roughly two months before
/// the expiry check would notice.
fn renewal(key: &str, title: &str, facts: &HostFacts, now: DateTime<Utc>) -> CheckResult {
    const GRACE_DAYS: i64 = 1;
    let all = parse_renewal(&facts.renewal);
    if all.is_empty() {
        return CheckResult::new(
            key,
            title,
            Severity::Ok,
            "no acme.sh config (managed elsewhere)",
        );
    }

    // `Le_*` lines exist but no domain's renewal time parsed: the acme.sh config itself is
    // broken, which is a signal, not a reason to stay quiet.
    let unreadable: Vec<&String> = all
        .iter()
        .filter(|(_, e)| e.due.is_none())
        .map(|(d, _)| d)
        .collect();
    let certs: BTreeMap<String, RenewalEntry> = all
        .iter()
        .filter(|(_, e)| e.due.is_some())
        .map(|(d, e)| (d.clone(), e.clone()))
        .collect();
    if certs.is_empty() {
        let names = unreadable
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        return CheckResult::new(
            key,
            title,
            Severity::Warn,
            format!("acme.sh config found but its renewal time could not be read: {names}"),
        );
    }

    let port80_closed = facts.renewal.contains("PORT80=closed");
    // http-01 needs port 80; with DNS-01 (Le_Webroot='dns*') the port is irrelevant.
    let http01: Vec<&String> = certs
        .iter()
        .filter(|(_, e)| !e.webroot.as_deref().unwrap_or("").starts_with("dns"))
        .map(|(d, _)| d)
        .collect();

    let mut overdue: Vec<(String, i64)> = certs
        .iter()
        .filter_map(|(d, e)| {
            let days = (now - e.due?).num_days();
            (days > GRACE_DAYS).then_some((d.clone(), days))
        })
        .collect();
    overdue.sort_by_key(|(_, days)| -days);

    if !overdue.is_empty() {
        let listed = overdue
            .iter()
            .map(|(d, n)| format!("{d} {n}d"))
            .collect::<Vec<_>>()
            .join(", ");
        let blocked = port80_closed && overdue.iter().any(|(d, _)| http01.contains(&d));
        let reason = if blocked {
            " — port 80 is closed, http-01 cannot pass"
        } else {
            ""
        };
        return CheckResult::new(
            key,
            title,
            Severity::Fail,
            format!("renewal overdue: {listed}{reason}"),
        );
    }
    if port80_closed && !http01.is_empty() {
        let names = http01
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        return CheckResult::new(
            key,
            title,
            Severity::Warn,
            format!("port 80 is closed — http-01 renewal will fail: {names}"),
        );
    }
    let soonest = certs.iter().min_by_key(|(_, e)| e.due).expect("non-empty");
    CheckResult::new(
        key,
        title,
        Severity::Ok,
        format!(
            "next {} {}",
            soonest.0,
            soonest.1.due.expect("filtered").date_naive()
        ),
    )
}

/// Node's own view of its egress address, used as the expectation for channel exits.
pub fn egress_ip(facts: &HostFacts) -> Option<String> {
    let candidate = facts.egress_ip.trim();
    candidate
        .parse::<std::net::IpAddr>()
        .ok()
        .map(|ip| ip.to_string())
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
            last_status_message: None,
            xray_version: Some("26.6.27".into()),
        }
    }

    fn healthy_facts() -> HostFacts {
        HostFacts {
            reachable: true,
            unreachable_reason: String::new(),
            docker_ps: "remnanode\tUp 5 days\ncaddy\tUp 5 days\n".into(),
            listening: "LISTEN 0 4096 0.0.0.0:443 0.0.0.0:*\nLISTEN 0 4096 0.0.0.0:8443 0.0.0.0:*\n".into(),
            node_logs: "2026-08-22T09:00:00 inbound in-a has 42 users\n".into(),
            cert: "notAfter=Nov 20 10:00:00 2026 GMT\n".into(),
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
            reachable: false,
            unreachable_reason: "ssh unreachable: Connection timed out".into(),
            ..HostFacts::default()
        };
        let r = check_host(&node(), &facts, now(), 14, 7);
        assert_eq!(r.len(), 7, "one result per check, no more, no fewer");
        assert!(r.iter().all(|c| c.severity == Severity::Fail));
        assert!(r.iter().all(|c| c.detail.contains("unreachable")));
    }

    #[test]
    fn a_stopped_or_unhealthy_container_fails() {
        let mut facts = healthy_facts();
        facts.docker_ps = "remnanode\tUp 5 days\ncaddy\tExited (1) 2 hours ago\n".into();
        let r = check_host(&node(), &facts, now(), 14, 7);
        assert_eq!(severity_of(&r, ":containers"), Severity::Fail);

        let mut facts = healthy_facts();
        facts.docker_ps = "remnanode\tUp 5 days (unhealthy)\n".into();
        let r = check_host(&node(), &facts, now(), 14, 7);
        assert_eq!(severity_of(&r, ":containers"), Severity::Fail);
    }

    #[test]
    fn a_missing_node_container_fails_even_when_everything_else_is_up() {
        let mut facts = healthy_facts();
        facts.docker_ps = "caddy\tUp 5 days\nwatchtower\tUp 5 days\n".into();
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
        facts.cert = "notAfter=Aug 30 10:00:00 2026 GMT\n".into();
        assert_eq!(
            severity_of(&check_host(&node(), &facts, now(), 14, 7), ":cert"),
            Severity::Warn
        );

        facts.cert = "notAfter=Aug 10 10:00:00 2026 GMT\n".into();
        assert_eq!(
            severity_of(&check_host(&node(), &facts, now(), 14, 7), ":cert"),
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
        facts.cert = String::new();
        let r = check_host(&node(), &facts, now(), 14, 7);
        let cert = r.iter().find(|c| c.key.ends_with(":cert")).unwrap();
        assert_eq!(cert.severity, Severity::Ok);
        assert!(cert.detail.contains("no TLS endpoint"));
    }

    #[test]
    fn egress_ip_is_trimmed_and_validated() {
        assert_eq!(egress_ip(&healthy_facts()).as_deref(), Some("192.0.2.20"));
        let mut facts = healthy_facts();
        facts.egress_ip = "curl: (7) Failed to connect\n".into();
        assert_eq!(egress_ip(&facts), None);
    }
}
