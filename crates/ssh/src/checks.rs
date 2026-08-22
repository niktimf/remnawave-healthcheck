use crate::facts::HostFacts;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use remnawave_healthcheck_core::model::{CheckResult, Node, Severity};
use std::collections::BTreeMap;

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
    ]
}

/// Any container that is not up — or is up but unhealthy — is a failure. There is no expected
/// list: the node's own container set is the expectation, which keeps this free of configuration.
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
    let silent: Vec<String> = node
        .inbound_ports
        .iter()
        .filter(|p| !facts.listening.contains(&format!(":{p} ")))
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
    found.retain(|_, e| e.due.is_some());
    found
}

/// Health of the renewal *mechanism*, not of the certificate's remaining days.
/// This is what catches a broken renewal at the first silent failure — roughly two months before
/// the expiry check would notice.
fn renewal(key: &str, title: &str, facts: &HostFacts, now: DateTime<Utc>) -> CheckResult {
    const GRACE_DAYS: i64 = 1;
    let certs = parse_renewal(&facts.renewal);
    if certs.is_empty() {
        return CheckResult::new(
            key,
            title,
            Severity::Ok,
            "no acme.sh config (managed elsewhere)",
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
        assert!(r.len() >= 5);
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
    fn egress_ip_is_trimmed_and_validated() {
        assert_eq!(egress_ip(&healthy_facts()).as_deref(), Some("192.0.2.20"));
        let mut facts = healthy_facts();
        facts.egress_ip = "curl: (7) Failed to connect\n".into();
        assert_eq!(egress_ip(&facts), None);
    }
}
