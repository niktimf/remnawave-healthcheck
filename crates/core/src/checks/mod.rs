//! Every check is a pure function from facts to `CheckResult`s. Nothing here
//! opens a socket or a process.

use crate::model::Severity;

/// The detail every check reports when the subscription answered with the HWID
/// placeholder instead of configs.
pub const HWID_STUB_DETAIL: &str = "the subscription answered with the HWID placeholder (0.0.0.0:1) instead of configs: \
     register a device for the monitoring user (POST /api/hwid/devices) and set REMNAWAVE_HWID";

pub(crate) fn commas(
    items: impl IntoIterator<Item = impl std::fmt::Display>,
) -> String {
    items
        .into_iter()
        .map(|item| item.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;
const GIB: u64 = 1024 * MIB;

/// A byte count as a person reads it: whole KB below a megabyte, MB to one
/// decimal, whole GB.
// Shown to one decimal at most, far inside what an f64 holds exactly.
#[allow(clippy::cast_precision_loss)]
pub(crate) fn size(bytes: u64) -> String {
    if bytes < MIB {
        format!("{} KB", bytes / KIB)
    } else if bytes < GIB {
        format!("{:.1} MB", bytes as f64 / MIB as f64)
    } else {
        format!("{:.0} GB", bytes as f64 / GIB as f64)
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case::kilobytes(17 * 1024, "17 KB")]
    #[case::megabyte(1_048_576, "1.0 MB")]
    #[case::gigabytes(42 * 1024 * 1024 * 1024, "42 GB")]
    fn a_size_is_shown_in_the_unit_that_fits(
        #[case] bytes: u64,
        #[case] expected: &str,
    ) {
        let shown = size(bytes);

        assert_eq!(shown, expected);
    }
}

pub mod channel;
pub mod geo;
pub mod panel;
pub mod services;
pub mod ssh;
pub mod tls;
pub mod usage;
pub mod youtube;
