//! Helpers shared by this crate's unit tests.

use crate::config::{Args, Config};
use clap::Parser;
use remnawave_healthcheck_core::model::CheckResult;

/// The three required settings plus whatever a test wants to vary.
pub(crate) fn args(extra: &[&str]) -> Args {
    let mut argv = vec![
        "remnawave-healthcheck",
        "--panel-url",
        "https://panel.example.com",
        "--api-token",
        "t",
        "--user-id",
        "42",
    ];
    argv.extend_from_slice(extra);
    Args::parse_from(argv)
}

/// A configuration with nothing but the defaults.
pub(crate) fn config() -> Config {
    Config::from_args(args(&[])).unwrap()
}

/// The result named `name`.
///
/// # Panics
/// When there is none, listing every name that was produced.
pub(crate) fn by_name<'a>(
    results: &'a [CheckResult],
    name: &str,
) -> &'a CheckResult {
    results.iter().find(|r| r.name == name).unwrap_or_else(|| {
        panic!(
            "no {name}: {:?}",
            results.iter().map(|r| &r.name).collect::<Vec<_>>()
        )
    })
}
