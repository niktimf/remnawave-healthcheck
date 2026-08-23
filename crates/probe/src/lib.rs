pub mod config;
pub mod tunnel;
pub mod xray;

pub use tunnel::{probe, ProbeOutcome};

use remnawave_healthcheck_core::model::{CheckResult, Severity};
use std::fmt::Write as _;
use std::net::IpAddr;

/// Turn one probe into a check result.
///
/// `key` is the channel's stable check key (`Channel::check_key`) and `remark` only the title a
/// human reads: the remark is not unique enough to key a check by, and this module is not the
/// place that decides what is.
///
/// `expect_ip` is what the expected exit node reports as its own egress address. When it is
/// unknown (SSH checks disabled, or the node was unreachable) the channel is not silently passed:
/// it warns, so the report never claims a verification it did not perform.
pub fn classify(
    key: &str,
    remark: &str,
    expect_node: &str,
    expect_ip: Option<IpAddr>,
    outcome: &ProbeOutcome,
) -> CheckResult {
    match (outcome.exit_ip, expect_ip) {
        (None, _) => {
            let mut detail = "no exit (tunnel dead)".to_string();
            if !outcome.stderr_tail.is_empty() {
                let _ = write!(detail, " | xray: {}", outcome.stderr_tail);
            }
            CheckResult::new(key, remark, Severity::Fail, detail)
        }
        (Some(got), None) => CheckResult::new(
            key,
            remark,
            Severity::Warn,
            format!(
                "exit {got}, but the egress address of expected node '{expect_node}' is unknown"
            ),
        ),
        (Some(got), Some(want)) if got == want => CheckResult::new(
            key,
            remark,
            Severity::Ok,
            format!("exit {got} ({expect_node})"),
        ),
        (Some(got), Some(want)) => CheckResult::new(
            key,
            remark,
            Severity::Fail,
            format!("wrong exit {got} (want {want} = {expect_node})"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use remnawave_healthcheck_core::model::Severity;

    fn outcome(ip: Option<&str>, tail: &str) -> ProbeOutcome {
        ProbeOutcome {
            exit_ip: ip.map(|ip| ip.parse().expect("test address is an IP")),
            stderr_tail: tail.to_string(),
        }
    }

    fn ip(text: &str) -> std::net::IpAddr {
        text.parse().expect("test address is an IP")
    }

    #[test]
    fn matching_exit_is_ok() {
        let r = classify(
            "channel:alpha@alpha.example.com:443",
            "alpha",
            "beta",
            Some(ip("192.0.2.20")),
            &outcome(Some("192.0.2.20"), ""),
        );
        assert_eq!(r.severity, Severity::Ok);
        assert_eq!(r.key, "channel:alpha@alpha.example.com:443");
        assert_eq!(r.title, "alpha", "the title stays the plain remark");
    }

    #[test]
    fn wrong_exit_names_both_sides() {
        let r = classify(
            "channel:alpha@alpha.example.com:443",
            "alpha",
            "beta",
            Some(ip("192.0.2.20")),
            &outcome(Some("203.0.113.7"), ""),
        );
        assert_eq!(r.severity, Severity::Fail);
        assert!(
            r.detail.contains("203.0.113.7")
                && r.detail.contains("192.0.2.20")
                && r.detail.contains("beta")
        );
    }

    #[test]
    fn dead_tunnel_carries_the_xray_stderr_tail() {
        let r = classify(
            "channel:alpha@alpha.example.com:443",
            "alpha",
            "beta",
            Some(ip("192.0.2.20")),
            &outcome(None, "failed to dial"),
        );
        assert_eq!(r.severity, Severity::Fail);
        assert!(r.detail.contains("tunnel dead"));
        assert!(r.detail.contains("failed to dial"));
    }

    #[test]
    fn unknown_expected_ip_downgrades_to_warn_rather_than_lying() {
        let r = classify(
            "channel:alpha@alpha.example.com:443",
            "alpha",
            "beta",
            None,
            &outcome(Some("203.0.113.7"), ""),
        );
        assert_eq!(r.severity, Severity::Warn);
        assert!(r.detail.contains("unknown"));
    }
}
