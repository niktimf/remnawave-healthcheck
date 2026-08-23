use clap::Parser;
use remnawave_healthcheck_core::model::{EchoUrl, ShellWord};
use std::path::PathBuf;

/// Health checker for a Remnawave installation. Keeps no inventory of its own:
/// nodes, channels, expected exits and the required Xray version all come from
/// the panel.
#[derive(Debug, Parser)]
#[command(name = "remnawave-healthcheck", version)]
pub struct Args {
    /// Base URL of the panel, e.g. <https://panel.example.com>
    #[arg(long, env = "REMNAWAVE_PANEL_URL")]
    pub panel_url: String,

    /// API token created in the panel (an admin login JWT will not work)
    #[arg(long, env = "REMNAWAVE_API_TOKEN")]
    pub api_token: String,

    /// Subscription URL of the monitoring user; its last path segment is the
    /// shortUuid
    #[arg(long, env = "REMNAWAVE_SUBSCRIPTION_URL")]
    pub subscription_url: String,

    #[arg(long, env = "TELEGRAM_BOT_TOKEN")]
    pub telegram_bot_token: Option<String>,
    #[arg(long, env = "TELEGRAM_CHAT_ID")]
    pub telegram_chat_id: Option<String>,
    /// `message_thread_id` of a supergroup topic
    #[arg(long, env = "TELEGRAM_THREAD_ID")]
    pub telegram_thread_id: Option<String>,
    /// Link to the CI run, appended to alerts
    #[arg(long, env = "RUN_URL")]
    pub run_url: Option<String>,

    #[arg(
        long,
        env = "REMNAWAVE_STATE_FILE",
        default_value = ".healthcheck-state.json"
    )]
    pub state_file: PathBuf,
    #[arg(long, env = "REMNAWAVE_XRAY_CACHE", default_value = ".xray-cache")]
    pub xray_cache: PathBuf,

    /// Warn this many days before a certificate expires
    #[arg(long, env = "REMNAWAVE_CERT_WARN_DAYS", default_value_t = 14)]
    pub cert_warn_days: u32,
    /// Warn when the node last took a config this many days ago.
    #[arg(long, env = "REMNAWAVE_CONFIG_WARN_DAYS", default_value_t = 7)]
    pub config_warn_days: u32,

    /// Skip node-side checks entirely (no SSH is attempted)
    #[arg(long, env = "REMNAWAVE_NO_SSH")]
    pub no_ssh: bool,
    /// Skip channel probing (no Xray is downloaded or started)
    #[arg(long, env = "REMNAWAVE_NO_CHANNELS")]
    pub no_channels: bool,
    /// Send one test message to Telegram and exit, bypassing the diff
    #[arg(long, env = "REMNAWAVE_TEST_ALERT")]
    pub test_alert: bool,

    #[arg(long, env = "REMNAWAVE_CONCURRENCY", default_value_t = 8)]
    pub concurrency: usize,
    #[arg(long, env = "REMNAWAVE_PROBE_TIMEOUT_SECS", default_value_t = 22)]
    pub probe_timeout_secs: u64,
    /// First local SOCKS port; each channel gets the next one
    #[arg(long, env = "REMNAWAVE_SOCKS_BASE_PORT", default_value_t = 10800)]
    pub socks_base_port: u16,
    /// Container the node's Xray runs in, as its compose file names it
    #[arg(long, env = "REMNAWAVE_NODE_CONTAINER", default_value = "remnanode")]
    pub node_container: ShellWord,

    /// Directory acme.sh keeps its per-domain configuration in
    #[arg(long, env = "REMNAWAVE_ACME_DIR", default_value = "/root/.acme.sh")]
    pub acme_dir: ShellWord,

    /// How many lines of the node's container log to read
    #[arg(long, env = "REMNAWAVE_NODE_LOG_LINES", default_value_t = 200)]
    pub node_log_lines: usize,

    /// Endpoint that echoes back the caller's IP address. Asked through each
    /// channel's tunnel and on the node itself, so both sides of an exit
    /// comparison ask the same service.
    #[arg(
        long,
        env = "REMNAWAVE_ECHO_URL",
        default_value = "https://api.ipify.org"
    )]
    pub echo_url: EchoUrl,
}
