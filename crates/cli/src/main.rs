mod args;
mod run;
mod telegram;

use clap::Parser;

#[tokio::main]
async fn main() {
    let args = args::Args::parse();
    match run::run(args).await {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            eprintln!("healthcheck failed: {err:#}");
            std::process::exit(2);
        }
    }
}
