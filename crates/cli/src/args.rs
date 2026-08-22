use clap::Parser;
use std::path::PathBuf;

/// Health checker for a Remnawave installation. Keeps no inventory of its own: nodes, channels,
/// expected exits and the required Xray version all come from the panel.
#[derive(Debug, Parser)]
#[command(name = "remnawave-healthcheck", version)]
pub struct Args {
    /// Base URL of the panel, e.g. https://panel.example.com
    #[arg(long, env = "REMNAWAVE_PANEL_URL")]
    pub panel_url: String,

    /// API token created in the panel (an admin login JWT will not work)
    #[arg(long, env = "REMNAWAVE_API_TOKEN")]
    pub api_token: String,

    /// Subscription URL of the monitoring user; its last path segment is the shortUuid
    #[arg(long, env = "REMNAWAVE_SUBSCRIPTION_URL")]
    pub subscription_url: String,

    #[arg(long, env = "TELEGRAM_BOT_TOKEN")]
    pub telegram_bot_token: Option<String>,
    #[arg(long, env = "TELEGRAM_CHAT_ID")]
    pub telegram_chat_id: Option<String>,
    /// message_thread_id of a supergroup topic
    #[arg(long, env = "TELEGRAM_THREAD_ID")]
    pub telegram_thread_id: Option<String>,
    /// Link to the CI run, appended to alerts
    #[arg(long, env = "RUN_URL")]
    pub run_url: Option<String>,

    #[arg(long, default_value = ".healthcheck-state.json")]
    pub state_file: PathBuf,
    #[arg(long, default_value = ".xray-cache")]
    pub xray_cache: PathBuf,

    #[arg(long, default_value_t = 14)]
    pub cert_warn_days: i64,
    #[arg(long, default_value_t = 7)]
    pub config_warn_days: i64,

    /// Skip node-side checks entirely (no SSH is attempted)
    #[arg(long)]
    pub no_ssh: bool,
    /// Skip channel probing (no Xray is downloaded or started)
    #[arg(long)]
    pub no_channels: bool,
    /// Send one test message to Telegram and exit, bypassing the diff
    #[arg(long)]
    pub test_alert: bool,

    #[arg(long, default_value_t = 8)]
    pub concurrency: usize,
    #[arg(long, default_value_t = 22)]
    pub probe_timeout_secs: u64,
    /// First local SOCKS port; each channel gets the next one
    #[arg(long, default_value_t = 10800)]
    pub socks_base_port: u16,
}
