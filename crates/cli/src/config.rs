//! Configuration from flags and environment. Every value is both a flag and a
//! variable; `--help` prints the whole table with defaults.

use crate::judge::Judge;
use anyhow::{Result, bail};
use clap::Parser;
use remnawave_healthcheck_core::checks::geo::GeoChecker;
use remnawave_healthcheck_core::checks::panel::PanelChecker;
use remnawave_healthcheck_core::checks::ssh::SshChecker;
use remnawave_healthcheck_io::{Hwid, SshConfig};
use std::path::PathBuf;
use std::time::Duration;

/// Health checker for a Remnawave installation. Keeps no inventory: nodes,
/// channels and expected exits all come from the panel.
#[derive(Debug, Parser)]
#[command(name = "remnawave-healthcheck", version)]
#[allow(clippy::struct_excessive_bools)]
pub struct Args {
    /// Base URL of the panel, e.g. <https://panel.example.com>
    #[arg(long, env = "REMNAWAVE_PANEL_URL")]
    pub panel_url: String,
    /// API token created in the panel (an admin login JWT will not work)
    #[arg(long, env = "REMNAWAVE_API_TOKEN", hide_env_values = true)]
    pub api_token: String,
    /// Numeric id of the monitoring user
    #[arg(long, env = "REMNAWAVE_USER_ID")]
    pub user_id: u64,

    #[arg(long, env = "TELEGRAM_BOT_TOKEN", hide_env_values = true)]
    pub telegram_bot_token: Option<String>,
    #[arg(long, env = "TELEGRAM_CHAT_ID", allow_hyphen_values = true)]
    pub telegram_chat_id: Option<String>,
    /// `message_thread_id` of a supergroup topic
    #[arg(long, env = "TELEGRAM_THREAD_ID")]
    pub telegram_thread_id: Option<i64>,

    /// Private key text; empty → ssh-agent / ~/.ssh decide
    #[arg(long, env = "SSH_PRIVATE_KEY", hide_env_values = true)]
    pub ssh_private_key: Option<String>,
    /// User on the nodes; unset -> root when a private key is given,
    /// otherwise ssh decides (config or the current user)
    #[arg(long, env = "SSH_USER")]
    pub ssh_user: Option<String>,
    #[arg(long, env = "SSH_PORT", default_value_t = 22)]
    pub ssh_port: u16,
    /// `known_hosts` text; set → StrictHostKeyChecking=yes, empty → accept-new
    #[arg(long, env = "SSH_KNOWN_HOSTS", hide_env_values = true)]
    pub ssh_known_hosts: Option<String>,
    #[arg(long, env = "SSH_CONNECT_TIMEOUT_SECS", default_value_t = 10)]
    pub ssh_connect_timeout_secs: u64,
    #[arg(long, env = "SSH_COMMAND_TIMEOUT_SECS", default_value_t = 30)]
    pub ssh_command_timeout_secs: u64,

    /// hwid of a device registered for the monitoring user
    #[arg(long, env = "REMNAWAVE_HWID")]
    pub hwid: Option<String>,
    #[arg(long, env = "REMNAWAVE_DEVICE_OS", default_value = "linux")]
    pub device_os: String,
    #[arg(long, env = "REMNAWAVE_DEVICE_OS_VERSION", default_value = "1")]
    pub device_os_version: String,
    #[arg(
        long,
        env = "REMNAWAVE_DEVICE_MODEL",
        default_value = "remnawave-healthcheck"
    )]
    pub device_model: String,

    /// Tunnels probed at once
    #[arg(long, env = "REMNAWAVE_CONCURRENCY", default_value_t = 8)]
    pub concurrency: usize,
    #[arg(long, env = "REMNAWAVE_PROBE_TIMEOUT_SECS", default_value_t = 22)]
    pub probe_timeout_secs: u64,
    /// Endpoint that echoes the caller's IP, asked through each tunnel
    #[arg(
        long,
        env = "REMNAWAVE_ECHO_URL",
        default_value = "https://api.ipify.org"
    )]
    pub echo_url: String,
    /// Container the node's Xray runs in
    #[arg(long, env = "REMNAWAVE_NODE_CONTAINER", default_value = "remnanode")]
    pub node_container: String,
    /// Directory acme.sh keeps its per-domain configuration in
    #[arg(long, env = "REMNAWAVE_ACME_DIR", default_value = "/root/.acme.sh")]
    pub acme_dir: String,
    /// Warn this many days before a certificate expires (nodes, panel, subscription host)
    #[arg(long, env = "REMNAWAVE_CERT_WARN_DAYS", default_value_t = 14)]
    pub cert_warn_days: u32,
    /// Warn when xray has run this many days without a config push
    #[arg(long, env = "REMNAWAVE_CONFIG_WARN_DAYS", default_value_t = 7)]
    pub config_warn_days: u32,
    /// Warn when the 1-minute load exceeds factor × cpus
    #[arg(long, env = "REMNAWAVE_LOAD_WARN_FACTOR", default_value_t = 2.0)]
    pub load_warn_factor: f64,
    #[arg(long, env = "REMNAWAVE_MEM_FREE_WARN_PCT", default_value_t = 10)]
    pub mem_free_warn_pct: u8,
    /// Warn at or above this geocheck reputation risk
    #[arg(long, env = "REMNAWAVE_REPUTATION_WARN_RISK", default_value_t = 75)]
    pub reputation_warn_risk: u32,
    #[arg(long, env = "REMNAWAVE_GEOCHECK_TIMEOUT_SECS", default_value_t = 90)]
    pub geocheck_timeout_secs: u64,
    #[arg(long, env = "REMNAWAVE_XRAY_CACHE", default_value = ".xray-cache")]
    pub xray_cache: PathBuf,
    #[arg(long, env = "REMNAWAVE_PANEL_TIMEOUT_SECS", default_value_t = 30)]
    pub panel_timeout_secs: u64,

    /// Skip node-side checks over SSH
    #[arg(long, env = "REMNAWAVE_NO_SSH")]
    pub no_ssh: bool,
    /// Skip channel probing (no Xray is downloaded or started)
    #[arg(long, env = "REMNAWAVE_NO_CHANNELS")]
    pub no_channels: bool,
    /// Skip geocheck jobs
    #[arg(long, env = "REMNAWAVE_NO_GEOCHECK")]
    pub no_geocheck: bool,
    /// Skip xhttp path probes
    #[arg(long, env = "REMNAWAVE_NO_XHTTP")]
    pub no_xhttp: bool,
}

#[derive(Debug, Clone)]
pub struct Telegram {
    pub bot_token: String,
    pub chat_id: String,
    pub thread_id: Option<i64>,
}

#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct Config {
    pub panel_url: String,
    pub api_token: String,
    pub user_id: u64,
    pub telegram: Option<Telegram>,
    pub ssh: SshConfig,
    pub hwid: Option<Hwid>,
    pub concurrency: usize,
    pub probe_timeout: Duration,
    pub echo_url: String,
    pub xray_cache: PathBuf,
    pub panel_timeout: Duration,
    pub geocheck_timeout: Duration,
    pub tls_timeout: Duration,
    pub xhttp_timeout: Duration,
    pub judge: Judge,
    pub no_ssh: bool,
    pub no_channels: bool,
    pub no_geocheck: bool,
    pub no_xhttp: bool,
    pub run_url: Option<String>,
}

fn non_empty(value: Option<String>) -> Option<String> {
    value.filter(|s| !s.trim().is_empty())
}

impl Config {
    pub fn from_args(args: Args) -> Result<Self> {
        let telegram = match (
            non_empty(args.telegram_bot_token),
            non_empty(args.telegram_chat_id),
        ) {
            (Some(bot_token), Some(chat_id)) => Some(Telegram {
                bot_token,
                chat_id,
                thread_id: args.telegram_thread_id,
            }),
            (None, None) => None,
            _ => bail!(
                "TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID must be set together, or neither"
            ),
        };
        if args.concurrency == 0 {
            bail!("REMNAWAVE_CONCURRENCY must be at least 1");
        }
        let hwid = non_empty(args.hwid).map(|hwid| Hwid {
            hwid,
            os: args.device_os.clone(),
            os_version: args.device_os_version.clone(),
            model: args.device_model.clone(),
        });
        let ssh_private_key = non_empty(args.ssh_private_key);
        // An explicit key without a user means a bare CI runner: root is the
        // only sensible login. Neither set -> ssh's own config decides.
        let ssh_user = non_empty(args.ssh_user)
            .or_else(|| ssh_private_key.is_some().then(|| "root".to_string()));
        Ok(Self {
            panel_url: args.panel_url,
            api_token: args.api_token,
            user_id: args.user_id,
            telegram,
            ssh: SshConfig {
                user: ssh_user,
                port: args.ssh_port,
                private_key: ssh_private_key,
                known_hosts: non_empty(args.ssh_known_hosts),
                connect_timeout: Duration::from_secs(
                    args.ssh_connect_timeout_secs,
                ),
                command_timeout: Duration::from_secs(
                    args.ssh_command_timeout_secs,
                ),
                acme_dir: args.acme_dir.clone(),
            },
            hwid,
            concurrency: args.concurrency,
            probe_timeout: Duration::from_secs(args.probe_timeout_secs),
            echo_url: args.echo_url,
            xray_cache: args.xray_cache,
            panel_timeout: Duration::from_secs(args.panel_timeout_secs),
            geocheck_timeout: Duration::from_secs(args.geocheck_timeout_secs),
            tls_timeout: Duration::from_secs(10),
            xhttp_timeout: Duration::from_secs(6),
            judge: Judge {
                panel: PanelChecker {
                    config_warn_days: args.config_warn_days,
                    load_warn_factor: args.load_warn_factor,
                    mem_free_warn_pct: args.mem_free_warn_pct,
                },
                geo: GeoChecker {
                    reputation_warn_risk: args.reputation_warn_risk,
                },
                ssh: SshChecker {
                    cert_warn_days: args.cert_warn_days,
                    container: args.node_container,
                    acme_dir: args.acme_dir,
                },
                cert_warn_days: args.cert_warn_days,
            },
            no_ssh: args.no_ssh,
            no_channels: args.no_channels,
            no_geocheck: args.no_geocheck,
            no_xhttp: args.no_xhttp,
            run_url: github_run_url(|k| std::env::var(k).ok()),
        })
    }
}

/// The URL GitHub Actions describes its own run with, when all three variables
/// are present.
pub fn github_run_url(get: impl Fn(&str) -> Option<String>) -> Option<String> {
    let server = non_empty(get("GITHUB_SERVER_URL"))?;
    let repo = non_empty(get("GITHUB_REPOSITORY"))?;
    let id = non_empty(get("GITHUB_RUN_ID"))?;
    Some(format!("{server}/{repo}/actions/runs/{id}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::args;
    use rstest::rstest;

    /// Half a Telegram configuration is a mistake, not a request to stay quiet.
    #[rstest]
    #[case::both(&["--telegram-bot-token", "tok", "--telegram-chat-id", "-100"], Ok(true))]
    #[case::neither(&[], Ok(false))]
    #[case::only_token(&["--telegram-bot-token", "tok"], Err(()))]
    #[case::only_chat(&["--telegram-chat-id", "-100"], Err(()))]
    fn telegram_is_both_or_neither(
        #[case] extra: &[&str],
        #[case] expected: Result<bool, ()>,
    ) {
        let args = args(extra);

        let config = Config::from_args(args);

        let got = config.map(|c| c.telegram.is_some()).map_err(|_| ());
        assert_eq!(got, expected);
    }

    #[test]
    fn the_documented_defaults_are_what_a_bare_run_gets() {
        let args = args(&[]);

        let config = Config::from_args(args).unwrap();

        assert_eq!(
            (
                config.concurrency,
                config.probe_timeout.as_secs(),
                config.judge.cert_warn_days
            ),
            (8, 22, 14)
        );
        assert_eq!((config.ssh.user.clone(), config.ssh.port), (None, 22));
        assert_eq!(config.judge.ssh.container, "remnanode");
        assert!(config.hwid.is_none());
    }

    /// A key with no user names a bare CI runner, where root is the only
    /// account that exists.
    #[test]
    fn an_ssh_key_without_a_user_means_root() {
        let args = args(&["--ssh-private-key", "KEY"]);

        let config = Config::from_args(args).unwrap();

        assert_eq!(config.ssh.user.as_deref(), Some("root"));
    }

    #[test]
    fn a_named_ssh_user_is_kept_as_given() {
        let args = args(&["--ssh-user", "deploy"]);

        let config = Config::from_args(args).unwrap();

        assert_eq!(config.ssh.user.as_deref(), Some("deploy"));
    }

    #[test]
    fn a_concurrency_of_zero_is_refused_by_name() {
        let args = args(&["--concurrency", "0"]);

        let err = Config::from_args(args).unwrap_err();

        assert_eq!(err.to_string(), "REMNAWAVE_CONCURRENCY must be at least 1");
    }

    #[test]
    fn an_hwid_becomes_device_headers() {
        let args = args(&["--hwid", "dev-1", "--device-model", "phone"]);

        let config = Config::from_args(args).unwrap();

        let hwid = config.hwid.unwrap();
        assert_eq!(
            (hwid.hwid.as_str(), hwid.os.as_str(), hwid.model.as_str()),
            ("dev-1", "linux", "phone")
        );
    }

    fn github_env(k: &str) -> Option<String> {
        match k {
            "GITHUB_SERVER_URL" => Some("https://github.com".to_string()),
            "GITHUB_REPOSITORY" => Some("acme/infra".to_string()),
            "GITHUB_RUN_ID" => Some("123".to_string()),
            _ => None,
        }
    }

    #[test]
    fn a_run_on_actions_links_back_to_its_own_run() {
        let url = github_run_url(github_env);

        assert_eq!(
            url.as_deref(),
            Some("https://github.com/acme/infra/actions/runs/123")
        );
    }

    /// Off Actions the variables are simply absent, and a partial set is not
    /// enough to build a link that would 404.
    #[test]
    fn a_missing_run_id_yields_no_link_at_all() {
        let url = github_run_url(|k| {
            if k == "GITHUB_RUN_ID" {
                None
            } else {
                github_env(k)
            }
        });

        assert_eq!(url, None);
    }
}
