use serde_json::Value;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Where the traffic came out, plus whatever Xray complained about if it did not.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProbeOutcome {
    pub exit_ip: Option<String>,
    pub stderr_tail: String,
}

/// Run Xray with `config`, ask the echo endpoint for our address through the local SOCKS port,
/// then kill Xray. Nothing is left running when this returns.
///
/// `echo_url` comes from the caller (`--echo-url`) rather than being fixed here: one hard-coded
/// endpoint going down would paint every channel red at once, which is the false alarm this tool
/// exists to avoid.
pub async fn probe(
    xray_bin: &Path,
    config: &Value,
    socks_port: u16,
    timeout: Duration,
    echo_url: &str,
) -> ProbeOutcome {
    // The guard removes this directory on every exit path from here on — success, an early
    // return, or a panic — so a stray xray config carrying the monitoring user's VLESS
    // credentials never survives past this call.
    let dir = match scratch_dir() {
        Ok(d) => d,
        Err(e) => {
            return ProbeOutcome {
                exit_ip: None,
                stderr_tail: format!("scratch dir: {e}"),
            }
        }
    };
    let cfg_path = dir.path().join("config.json");
    if let Err(e) = write_config(&cfg_path, config).await {
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
        if let Ok(resp) = client.get(echo_url).send().await {
            if resp.status().is_success() {
                if let Ok(text) = resp.text().await {
                    if let Some(ip) = parse_echo_response(&text) {
                        exit_ip = Some(ip);
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
    // `dir` is dropped here (and on every early return above), which removes it.

    ProbeOutcome {
        exit_ip,
        stderr_tail,
    }
}

/// The echo endpoint answers with a bare IP address and nothing else. Anything that is not one —
/// an HTML error page from a CDN in front of it, a captive-portal login form, a rate-limit notice
/// — is not this channel's exit address and must never be reported as one. `ssh::egress_ip`
/// validates the node side the same way.
fn parse_echo_response(body: &str) -> Option<String> {
    body.trim()
        .parse::<std::net::IpAddr>()
        .ok()
        .map(|ip| ip.to_string())
}

async fn write_config(path: &Path, config: &Value) -> std::io::Result<()> {
    // 0o600: the file holds the subscription outbound verbatim — VLESS UUID, server address,
    // SNI, fingerprint. No point restricting the directory (see `scratch_dir`) if the file
    // inside it stays world-readable for the moment between creation and removal.
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .await?;
    file.write_all(config.to_string().as_bytes()).await
}

/// A scratch directory for one probe run. Removed on `Drop`, on every exit path — success, an
/// early return, or a panic — so a leftover xray config with live credentials never lingers in
/// `std::env::temp_dir()`. `Drop` cannot run async code; a synchronous removal of one small
/// directory is an acceptable price for that guarantee.
struct ScratchDir(PathBuf);

impl ScratchDir {
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Create a fresh, `0o700` scratch directory under the OS temp dir, wrapped in a guard that
/// removes it again once the probe is done with it.
fn scratch_dir() -> std::io::Result<ScratchDir> {
    let base = std::env::temp_dir().join(format!("rwhc-{}", std::process::id()));
    std::fs::create_dir_all(&base)?;
    let unique = base.join(format!("{:?}", std::time::SystemTime::now()).replace([' ', ':'], "-"));
    std::fs::DirBuilder::new().mode(0o700).create(&unique)?;
    Ok(ScratchDir(unique))
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The most important guarantee this module makes: a failed `spawn()` (bad binary path, no
    /// exec permission, ENOENT — the realistic case) must not leave the scratch directory, with
    /// its verbatim subscription outbound, behind on disk.
    #[tokio::test]
    async fn a_dead_spawn_leaves_no_scratch_dir_behind() {
        let base = std::env::temp_dir().join(format!("rwhc-{}", std::process::id()));
        let before = list_dir(&base);

        let outcome = probe(
            Path::new("/nonexistent/xray-binary-that-does-not-exist"),
            &serde_json::json!({"outbounds": []}),
            1,
            Duration::from_millis(50),
            "https://echo.example.com",
        )
        .await;

        assert_eq!(outcome.exit_ip, None);
        let after = list_dir(&base);
        assert_eq!(
            before, after,
            "the scratch directory created for this run must be gone once probe() returns"
        );
    }

    #[test]
    fn only_a_bare_ip_address_counts_as_an_exit() {
        assert_eq!(
            parse_echo_response(" 203.0.113.7\n").as_deref(),
            Some("203.0.113.7")
        );
        assert_eq!(
            parse_echo_response("2001:db8::1").as_deref(),
            Some("2001:db8::1")
        );
        assert_eq!(parse_echo_response(""), None);
        assert_eq!(
            parse_echo_response("<html><title>502 Bad Gateway</title></html>"),
            None,
            "an error page must not become an exit address"
        );
        assert_eq!(parse_echo_response("203.0.113.7 (cached)"), None);
    }

    #[test]
    fn scratch_dir_guard_removes_its_directory_on_drop() {
        let dir = scratch_dir().expect("scratch dir creates");
        let path = dir.path().to_path_buf();
        assert!(path.is_dir());
        drop(dir);
        assert!(!path.exists(), "guard must remove the directory on drop");
    }

    fn list_dir(dir: &Path) -> Vec<PathBuf> {
        std::fs::read_dir(dir)
            .map(|entries| entries.filter_map(|e| e.ok()).map(|e| e.path()).collect())
            .unwrap_or_default()
    }
}
