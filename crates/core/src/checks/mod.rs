//! Every check is a pure function from facts to `CheckResult`s. Nothing here
//! opens a socket or a process.

use crate::model::Severity;
use std::fmt::Write;

/// The detail every check reports when the subscription answered with the HWID
/// placeholder instead of configs.
pub const HWID_STUB_DETAIL: &str = "the subscription answered with the HWID placeholder (0.0.0.0:1) instead of configs: \
     register a device for the monitoring user (POST /api/hwid/devices) and set REMNAWAVE_HWID";

pub(crate) fn commas(
    items: impl IntoIterator<Item = impl std::fmt::Display>,
) -> String {
    let mut out = String::new();
    for item in items {
        if !out.is_empty() {
            out.push_str(", ");
        }
        let _ = write!(out, "{item}");
    }
    out
}

/// A verdict without a name. Checks that share one context produce these, and
/// the context names them in one place — so an aspect is spelled once rather
/// than at every return point inside a check.
pub(crate) struct Verdict {
    pub severity: Severity,
    pub detail: String,
}

impl Verdict {
    fn new(severity: Severity, detail: impl Into<String>) -> Self {
        Self {
            severity,
            detail: detail.into(),
        }
    }

    pub fn ok(detail: impl Into<String>) -> Self {
        Self::new(Severity::Ok, detail)
    }

    pub fn warn(detail: impl Into<String>) -> Self {
        Self::new(Severity::Warn, detail)
    }

    pub fn fail(detail: impl Into<String>) -> Self {
        Self::new(Severity::Fail, detail)
    }
}

pub mod channel;
pub mod geo;
pub mod panel;
pub mod ssh;
pub mod tls;
