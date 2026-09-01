//! Verdict on one endpoint's certificate, from a handshake `io::tls` performed.

use crate::model::{CheckResult, TlsFacts};
use chrono::{DateTime, Utc};

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
    use crate::model::Severity;
    use chrono::TimeZone;
    use rstest::rstest;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 30, 12, 0, 0).unwrap()
    }

    fn facts(days_from_now: Option<i64>, error: Option<&str>) -> TlsFacts {
        TlsFacts {
            not_after: days_from_now.map(|d| now() + chrono::Duration::days(d)),
            error: error.map(String::from),
        }
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
