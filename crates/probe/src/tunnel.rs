use remnawave_healthcheck_core::model::parse_ip;
use serde_json::Value;
use std::net::IpAddr;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Where the traffic came out, plus whatever Xray complained about if it did not.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProbeOutcome {
    pub exit_ip: Option<IpAddr>,
    pub stderr_tail: String,
}

impl ProbeOutcome {
    /// A probe that never got as far as asking the tunnel anything: no exit address, and the
    /// reason in place of xray's stderr.
    fn not_probed(reason: String) -> Self {
        ProbeOutcome {
            exit_ip: None,
            stderr_tail: reason,
        }
    }
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
    match attempt(xray_bin, config, socks_port, timeout, echo_url).await {
        Ok(outcome) => outcome,
        // Nothing was probed, so there is no exit address; the reason takes the place xray's
        // stderr would have had, which is where the reader already looks for it.
        Err(reason) => ProbeOutcome::not_probed(reason),
    }
}

/// The probe proper. Everything that can go wrong before the tunnel is even asked a question
/// leaves through `Err`, and `probe` turns that into the outcome the caller expects — so no path
/// here has to assemble a failed outcome by hand, and none of them may panic.
async fn attempt(
    xray_bin: &Path,
    config: &Value,
    socks_port: u16,
    timeout: Duration,
    echo_url: &str,
) -> Result<ProbeOutcome, String> {
    // The guard removes this directory on every exit path from here on — success, an early
    // return, or a panic — so a stray xray config carrying the monitoring user's VLESS
    // credentials never survives past this call.
    let dir = scratch_dir().map_err(|e| format!("scratch dir: {e}"))?;
    let cfg_path = dir.as_ref().join("config.json");
    write_config(&cfg_path, config)
        .await
        .map_err(|e| format!("writing config: {e}"))?;

    // Built before xray is started: nothing here depends on the child, and a client that cannot
    // be built must not leave a process running behind it.
    let client = socks_client(socks_port).map_err(|e| format!("socks client: {e}"))?;

    let mut child = tokio::process::Command::new(xray_bin)
        .arg("run")
        .arg("-c")
        .arg(&cfg_path)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("spawning xray: {e}"))?;

    let deadline = Instant::now() + timeout;
    let mut exit_ip = None;
    while Instant::now() < deadline {
        if let Some(ip) = ask_echo(&client, echo_url).await {
            exit_ip = Some(ip);
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    let _ = child.kill().await;
    let mut stderr_tail = String::new();
    if exit_ip.is_none() {
        if let Some(mut err) = child.stderr.take() {
            let mut buf = String::new();
            let _ = err.read_to_string(&mut buf).await;
            stderr_tail = tail(&buf, STDERR_TAIL_LINES, STDERR_TAIL_CHARS);
        }
    }
    // `dir` is dropped here (and on every early return above), which removes it.

    Ok(ProbeOutcome {
        exit_ip,
        stderr_tail,
    })
}

/// One question to the echo endpoint through the tunnel. `None` covers every way of not getting
/// an answer — the tunnel is not up yet, the endpoint refused, the body is not an address — all
/// of which mean the same thing here: keep waiting until the deadline.
async fn ask_echo(client: &reqwest::Client, echo_url: &str) -> Option<IpAddr> {
    let resp = client.get(echo_url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    parse_echo_response(&resp.text().await.ok()?)
}

/// HTTP client that speaks to the tunnel's local SOCKS port. `socks5h`: name resolution happens
/// at the far end, so the echo endpoint's name is never looked up locally.
fn socks_client(socks_port: u16) -> reqwest::Result<reqwest::Client> {
    let proxy = reqwest::Proxy::all(format!("socks5h://127.0.0.1:{socks_port}"))?;
    reqwest::Client::builder()
        .proxy(proxy)
        .timeout(Duration::from_secs(8))
        .build()
}

/// The echo endpoint answers with a bare IP address and nothing else. Anything that is not one —
/// an HTML error page from a CDN in front of it, a captive-portal login form, a rate-limit notice
/// — is not this channel's exit address and must never be reported as one. `ssh::egress_ip`
/// validates the node side the same way, through the same function.
fn parse_echo_response(body: &str) -> Option<IpAddr> {
    parse_ip(body)
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

impl AsRef<Path> for ScratchDir {
    fn as_ref(&self) -> &Path {
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
    // Two probes of one run can start within the same nanosecond, and a clock can step
    // backwards; the counter is what actually guarantees the name is unused.
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let base = std::env::temp_dir().join(format!("rwhc-{}", std::process::id()));
    std::fs::create_dir_all(&base)?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_nanos());
    let unique = base.join(format!("{nanos}-{}", NEXT.fetch_add(1, Ordering::Relaxed)));
    std::fs::DirBuilder::new().mode(0o700).create(&unique)?;
    Ok(ScratchDir(unique))
}

/// How much of xray's stderr a dead tunnel's detail carries: enough lines for the real reason,
/// short enough that one channel cannot fill an alert.
const STDERR_TAIL_LINES: usize = 3;
const STDERR_TAIL_CHARS: usize = 200;

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
    ///
    /// Asserted as "no config file survives anywhere under the base", not as "the listing is
    /// unchanged": the base directory is shared by every probe of this process, so a listing
    /// taken before and after would also see scratch directories of tests running in parallel
    /// and fail for reasons that have nothing to do with this one.
    #[tokio::test]
    async fn a_dead_spawn_leaves_no_scratch_dir_behind() {
        let base = std::env::temp_dir().join(format!("rwhc-{}", std::process::id()));

        let outcome = probe(
            Path::new("/nonexistent/xray-binary-that-does-not-exist"),
            &serde_json::json!({"outbounds": []}),
            1,
            Duration::from_millis(50),
            "https://echo.example.com",
        )
        .await;

        assert_eq!(outcome.exit_ip, None);
        let leftovers: Vec<PathBuf> = list_dir(&base)
            .into_iter()
            .filter(|d| d.join("config.json").exists())
            .collect();
        assert!(
            leftovers.is_empty(),
            "a config with live credentials survived probe(): {leftovers:?}"
        );
    }

    /// What this endpoint can answer with, as opposed to what an address looks like: the full
    /// matrix of "is this an address" lives with `core::model::parse_ip`, which both sides of the
    /// exit comparison share. Here the subject is the echo endpoint itself — anything a CDN or a
    /// captive portal puts in front of it answers 200 with a body that is not this channel's exit.
    #[test]
    fn an_error_page_from_the_echo_endpoint_is_not_an_exit_address() {
        assert_eq!(
            parse_echo_response("<html><title>502 Bad Gateway</title></html>"),
            None
        );
        assert_eq!(parse_echo_response("203.0.113.7 (cached)"), None);
        assert_eq!(parse_echo_response(""), None);
        assert_eq!(
            parse_echo_response(" 203.0.113.7\n"),
            Some("203.0.113.7".parse().unwrap()),
            "a bare address, whitespace and all, is the one thing that does count"
        );
    }

    #[test]
    fn scratch_dir_guard_removes_its_directory_on_drop() {
        let dir = scratch_dir().expect("scratch dir creates");
        let path = dir.as_ref().to_path_buf();
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
