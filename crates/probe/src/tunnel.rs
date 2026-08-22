use serde_json::Value;
use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;

/// Where the traffic came out, plus whatever Xray complained about if it did not.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProbeOutcome {
    pub exit_ip: Option<String>,
    pub stderr_tail: String,
}

const ECHO_URL: &str = "https://api.ipify.org";

/// Run Xray with `config`, ask an echo service for our address through the local SOCKS port,
/// then kill Xray. Nothing is left running when this returns.
pub async fn probe(
    xray_bin: &Path,
    config: &Value,
    socks_port: u16,
    timeout: Duration,
) -> ProbeOutcome {
    let dir = match tempdir_in_cache() {
        Ok(d) => d,
        Err(e) => {
            return ProbeOutcome {
                exit_ip: None,
                stderr_tail: format!("temp dir: {e}"),
            }
        }
    };
    let cfg_path = dir.join("config.json");
    if let Err(e) = tokio::fs::write(&cfg_path, config.to_string()).await {
        return ProbeOutcome {
            exit_ip: None,
            stderr_tail: format!("writing config: {e}"),
        };
    }

    let mut child = match tokio::process::Command::new(xray_bin)
        .arg("run")
        .arg("-c")
        .arg(&cfg_path)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            return ProbeOutcome {
                exit_ip: None,
                stderr_tail: format!("spawning xray: {e}"),
            }
        }
    };

    let proxy = format!("socks5h://127.0.0.1:{socks_port}");
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(&proxy).expect("valid proxy url"))
        .timeout(Duration::from_secs(8))
        .build()
        .expect("client builds");

    let deadline = Instant::now() + timeout;
    let mut exit_ip = None;
    while Instant::now() < deadline {
        if let Ok(resp) = client.get(ECHO_URL).send().await {
            if resp.status().is_success() {
                if let Ok(text) = resp.text().await {
                    let trimmed = text.trim().to_string();
                    if !trimmed.is_empty() {
                        exit_ip = Some(trimmed);
                        break;
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    let _ = child.kill().await;
    let mut stderr_tail = String::new();
    if exit_ip.is_none() {
        if let Some(mut err) = child.stderr.take() {
            let mut buf = String::new();
            let _ = err.read_to_string(&mut buf).await;
            stderr_tail = tail(&buf, 3, 200);
        }
    }
    let _ = tokio::fs::remove_dir_all(&dir).await;

    ProbeOutcome {
        exit_ip,
        stderr_tail,
    }
}

fn tempdir_in_cache() -> std::io::Result<std::path::PathBuf> {
    let base = std::env::temp_dir().join(format!("rwhc-{}", std::process::id()));
    let unique = base.join(format!("{:?}", std::time::SystemTime::now()).replace([' ', ':'], "-"));
    std::fs::create_dir_all(&unique)?;
    Ok(unique)
}

/// Last non-empty lines of Xray's stderr — this is where the real reason for a dead tunnel is.
fn tail(text: &str, lines: usize, chars: usize) -> String {
    let kept: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    let start = kept.len().saturating_sub(lines);
    kept[start..].join(" / ").chars().take(chars).collect()
}
