mod args;
mod ports;
mod run;
mod telegram;

use clap::Parser;
use remnawave_healthcheck_core::report::Outcome;
use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    let args = args::Args::parse();
    match run::run(args).await {
        Ok(outcome) => outcome.into(),
        Err(err) => {
            eprintln!("healthcheck failed: {err:#}");
            Outcome::Aborted.into()
        }
    }
}
