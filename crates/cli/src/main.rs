mod config;
mod judge;
mod run;

mod telegram;
#[cfg(test)]
mod test_util;

use clap::Parser;
use remnawave_healthcheck_core::report::Outcome;
use std::process::ExitCode;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> ExitCode {
    // Logs go to stderr; stdout carries only the report table.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();
    let config = match config::Config::from_args(config::Args::parse()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("configuration: {e:#}");
            return Outcome::Aborted.into();
        }
    };
    match run::run(config).await {
        Ok(outcome) => outcome.into(),
        Err(e) => {
            tracing::error!("healthcheck failed: {e:#}");
            Outcome::Aborted.into()
        }
    }
}
