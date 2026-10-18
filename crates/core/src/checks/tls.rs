//! Verdict on one endpoint's certificate, from a handshake `io::tls` performed.

use crate::model::{CheckResult, Endpoint, Snapshot, TlsFacts};
use chrono::{DateTime, Utc};

/// Every endpoint whose certificate is checked: the panel, the subscription,
/// and each distinct handshake a served TLS channel makes. A fronted channel
/// presents the edge's name, and when that certificate expires the channel
/// goes down while every certificate of ours is still valid.
pub fn endpoints(snapshot: &Snapshot) -> Vec<Endpoint> {
    let channels = snapshot
        .channels
        .iter()
        .filter(|channel| channel.served.outbound().is_some())
        .filter_map(crate::model::Channel::tls_endpoint);
    let mut checked: Vec<Endpoint> = Vec::new();
    for endpoint in std::iter::once(snapshot.panel.clone())
        .chain(snapshot.sub.clone())
        .chain(channels)
    {
        if !checked.contains(&endpoint) {
            checked.push(endpoint);
        }
    }
    checked
}

pub fn check(
    host: &str,
    facts: &TlsFacts,
    now: DateTime<Utc>,
    warn_days: u32,
) -> CheckResult {
    let name = format!("tls {host}");
    if let Some(err) = &facts.error {
        return if err == "expired" {
            CheckResult::fail(name, "certificate expired")
        } else {
            CheckResult::fail(name, format!("handshake failed: {err}"))
        };
    }
    let Some(not_after) = facts.not_after else {
        return CheckResult::warn(name, "no certificate presented");
    };
    let days = (not_after - now).num_days();
    let date = not_after.date_naive();
    if days < 0 {
        CheckResult::fail(name, format!("expired {}d ago ({date})", -days))
    } else if days < i64::from(warn_days) {
        CheckResult::warn(name, format!("{days}d left ({date})"))
    } else {
        CheckResult::ok(name, format!("{days}d left ({date})"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Channel, Served, Severity, Snapshot};
    use chrono::TimeZone;
    use rstest::rstest;
    use serde_json::json;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 30, 12, 0, 0).unwrap()
    }

    fn facts(days_from_now: Option<i64>, error: Option<&str>) -> TlsFacts {
        TlsFacts {
            not_after: days_from_now.map(|d| now() + chrono::Duration::days(d)),
            error: error.map(String::from),
        }
    }

    fn panel() -> Endpoint {
        Endpoint {
            host: "panel.example.com".into(),
            port: 443,
            server_name: None,
        }
    }

    fn fronted(address: &str, served: Served) -> Channel {
        Channel {
            address: address.into(),
            port: 443,
            security: Some("tls".into()),
            sni: Some("edge.example.net".into()),
            served,
            ..Default::default()
        }
    }

    fn outbound() -> Served {
        Served::Direct(json!({"protocol": "vless"}))
    }

    #[test]
    fn channels_sharing_one_front_are_checked_once_after_the_panel() {
        let snapshot = Snapshot {
            panel: panel(),
            channels: vec![
                fronted("front.example.com", outbound()),
                fronted("front.example.com", outbound()),
            ],
            ..Default::default()
        };

        let checked = endpoints(&snapshot);

        assert_eq!(
            checked,
            vec![
                panel(),
                Endpoint {
                    host: "front.example.com".into(),
                    port: 443,
                    server_name: Some("edge.example.net".into()),
                },
            ]
        );
    }

    /// A selector's `address:port` is a placeholder no node listens on.
    #[test]
    fn a_selector_is_not_checked() {
        let snapshot = Snapshot {
            panel: panel(),
            channels: vec![fronted(
                "auto.example.com",
                Served::Selector(vec![]),
            )],
            ..Default::default()
        };

        let checked = endpoints(&snapshot);

        assert_eq!(checked, vec![panel()]);
    }

    #[rstest]
    #[case::healthy(Some(60), None, Severity::Ok, "60d left")]
    #[case::soon(Some(5), None, Severity::Warn, "5d left")]
    #[case::past(Some(-3), None, Severity::Fail, "expired 3d ago")]
    #[case::rustls_says_expired(
        None,
        Some("expired"),
        Severity::Fail,
        "certificate expired"
    )]
    #[case::handshake_error(
        None,
        Some("connection refused"),
        Severity::Fail,
        "handshake failed: connection refused"
    )]
    #[case::no_cert(None, None, Severity::Warn, "no certificate presented")]
    fn tls_table(
        #[case] days: Option<i64>,
        #[case] error: Option<&str>,
        #[case] expected: Severity,
        #[case] mentions: &str,
    ) {
        let facts = facts(days, error);

        let result = check("panel.example.com", &facts, now(), 14);

        assert_eq!(result.name, "tls panel.example.com");
        assert_eq!(result.severity, expected, "{}", result.detail);
        assert!(result.detail.contains(mentions), "{}", result.detail);
    }
}
