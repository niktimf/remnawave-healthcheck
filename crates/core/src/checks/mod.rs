//! Every check is a pure function from facts to `CheckResult`s. Nothing here
//! opens a socket or a process.

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

pub mod channel;
pub mod geo;
pub mod panel;
pub mod ssh;
pub mod tls;
