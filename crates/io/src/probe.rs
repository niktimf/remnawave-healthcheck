//! Run one subscription outbound through a real Xray and read where the
//! traffic comes out. The outbound is used verbatim: this tool checks what the
//! panel handed the client.

use crate::panel::error_chain;
use anyhow::{Context, Result};
use backon::{ExponentialBuilder, Retryable};
use remnawave_healthcheck_core::model::{Download, ProbeOutcome, parse_ip};
use reqwest::Url;
use serde_json::{Value, json};
use std::net::IpAddr;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;

fn release_url(version: &str) -> String {
    format!(
        "https://github.com/XTLS/Xray-core/releases/download/v{version}/Xray-linux-64.zip"
    )
}

/// Path to an Xray binary of exactly `version`, downloaded and cached when
/// missing. The cache entry appears only complete: unpacked under a temporary
/// name and renamed into place, so a killed run leaves no truncated binary.
pub async fn ensure_xray(version: &str, cache_dir: &Path) -> Result<PathBuf> {
    let dir = cache_dir.join(version);
    let binary = dir.join("xray");
    if binary.exists() {
        return Ok(binary);
    }
    tokio::fs::create_dir_all(&dir).await?;
    let url = release_url(version);
    let client = reqwest::Client::new();
    let bytes = (|| async {
        client
            .get(&url)
            .timeout(Duration::from_secs(180))
            .send()
            .await?
            .error_for_status()?
            .bytes()
            .await
    })
    .retry(
        ExponentialBuilder::default()
            .with_min_delay(Duration::from_secs(2))
            .with_max_times(2),
    )
    // A 404 for an unknown version is final; only transport errors and
    // 5xx responses are worth retrying.
    .when(|e: &reqwest::Error| e.status().is_none_or(|s| s.is_server_error()))
    .notify(|e, d| tracing::warn!("xray download: {e}; retrying in {d:?}"))
    .await
    .with_context(|| format!("downloading {url}"))?;

    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let target = dir2.join("xray");
        let partial = dir2.join(format!("xray.{}.partial", std::process::id()));
        unpack_into(&bytes, &partial).inspect_err(|_| {
            let _ = std::fs::remove_file(&partial);
        })?;
        std::fs::rename(&partial, &target).with_context(|| {
            format!("moving the unpacked binary into {}", target.display())
        })
    })
    .await??;
    Ok(binary)
}

fn unpack_into(bytes: &[u8], target: &Path) -> Result<()> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes))?;
    let mut entry = archive
        .by_name("xray")
        .context("release archive has no 'xray' entry")?;
    let mut file = std::fs::File::create(target)?;
    std::io::copy(&mut entry, &mut file)?;
    let mut perms = std::fs::metadata(target)?.permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(target, perms)?;
    Ok(())
}

/// Wrap a subscription outbound into a runnable config with a local SOCKS inbound.
pub fn build_config(outbound: &Value, socks_port: u16) -> Value {
    json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "protocol": "socks",
            "listen": "127.0.0.1",
            "port": socks_port,
            "settings": {"udp": true, "auth": "noauth"}
        }],
        "outbounds": [outbound]
    })
}

/// A port the kernel just handed out. Handed to xray immediately after, so
/// the window in which another process could grab it is negligible.
fn free_port() -> std::io::Result<u16> {
    Ok(std::net::TcpListener::bind(("127.0.0.1", 0))?
        .local_addr()?
        .port())
}

/// How long a download may go without a byte before it counts as stalled.
/// A freeze keeps the connection open and sends nothing, so it shows as
/// silence long before the total bound runs out.
pub const DOWNLOAD_SILENCE: Duration = Duration::from_secs(10);

/// What to download through a tunnel once it is shown to come out, and the
/// bounds on that download.
#[derive(Debug, Clone)]
pub struct DownloadTarget {
    pub url: Url,
    /// The whole download.
    pub total: Duration,
    /// The longest wait for the next byte.
    pub silence: Duration,
}

/// Run Xray with the outbound, ask the echo endpoint through the local SOCKS
/// port, download `download` when the echo answered, kill Xray. Nothing is
/// left running or on disk when this returns.
pub async fn probe(
    xray_bin: &Path,
    outbound: &Value,
    timeout: Duration,
    echo_url: &str,
    download: Option<&DownloadTarget>,
) -> ProbeOutcome {
    match attempt(None, xray_bin, outbound, timeout, echo_url, download).await {
        Ok(outcome) => outcome,
        // The reason takes the place xray's stderr would have had.
        Err(reason) => ProbeOutcome {
            exit_ip: None,
            stderr_tail: reason,
            download: Download::NotRun,
        },
    }
}

async fn attempt(
    scratch_base: Option<&Path>,
    xray_bin: &Path,
    outbound: &Value,
    timeout: Duration,
    echo_url: &str,
    download: Option<&DownloadTarget>,
) -> Result<ProbeOutcome, String> {
    let xray = Xray::start_in(scratch_base, xray_bin, outbound)?;
    let client = socks_client(xray.port(), Duration::from_secs(8))
        .map_err(|e| format!("socks client: {e}"))?;

    let deadline = Instant::now() + timeout;
    let mut exit_ip = None;
    while Instant::now() < deadline {
        if let Some(ip) = ask_echo(&client, echo_url).await {
            exit_ip = Some(ip);
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    // Only a tunnel that came out has a path worth timing.
    let download = match (exit_ip, download) {
        (Some(_), Some(target)) => fetch(&client, target).await,
        _ => Download::NotRun,
    };
    let stderr = xray.stop().await;
    let mut stderr_tail = String::new();
    if exit_ip.is_none() {
        stderr_tail = tail(&stderr, 3, 200);
        tracing::debug!(%stderr, "xray stderr");
    }
    Ok(ProbeOutcome {
        exit_ip,
        stderr_tail,
        download,
    })
}

/// Read `target` to the end, counting bytes. Stops at the first `silence`
/// without a byte, and at `total`, whichever comes first. A body without a
/// `Content-Length` is complete when the server ends it.
pub(crate) async fn fetch(
    client: &reqwest::Client,
    target: &DownloadTarget,
) -> Download {
    let started = tokio::time::Instant::now();
    let deadline = started + target.total;
    // Past both bounds below, so reqwest's own timeout never decides first.
    let request = client
        .get(target.url.clone())
        .timeout(target.total.saturating_add(target.silence))
        .send();
    let wake = (started + target.silence).min(deadline);
    let mut response = match tokio::time::timeout_at(wake, request).await {
        Ok(Ok(response)) => response,
        Ok(Err(e)) => return Download::Failed(error_chain(e)),
        Err(_) if wake >= deadline => {
            return Download::TimedOut { bytes: 0, of: None };
        }
        Err(_) => {
            return Download::Failed(format!(
                "no answer within {}s",
                target.silence.as_secs()
            ));
        }
    };
    if !response.status().is_success() {
        return Download::Failed(format!(
            "HTTP {}",
            response.status().as_u16()
        ));
    }
    let of = response.content_length();
    let mut bytes: u64 = 0;
    loop {
        let wake = (tokio::time::Instant::now() + target.silence).min(deadline);
        match tokio::time::timeout_at(wake, response.chunk()).await {
            Ok(Ok(Some(chunk))) => {
                bytes = bytes.saturating_add(chunk.len() as u64);
            }
            Ok(Ok(None)) => {
                let elapsed = started.elapsed();
                return Download::Complete { bytes, elapsed };
            }
            // A body that broke off stopped short, as a silent one does.
            Ok(Err(e)) => {
                tracing::debug!("download: {}", error_chain(e));
                let after = started.elapsed();
                return Download::Stalled { bytes, of, after };
            }
            Err(_) if wake >= deadline => {
                return Download::TimedOut { bytes, of };
            }
            Err(_) => {
                let after = started.elapsed();
                return Download::Stalled { bytes, of, after };
            }
        }
    }
}

/// A running Xray with one subscription outbound behind a local SOCKS port.
/// Killed when dropped, and its scratch directory, which holds the config
/// with the subscription's live credentials, is removed with it.
pub struct Xray {
    child: tokio::process::Child,
    port: u16,
    _scratch: tempfile::TempDir,
}

impl Xray {
    pub fn start(xray_bin: &Path, outbound: &Value) -> Result<Self, String> {
        Self::start_in(None, xray_bin, outbound)
    }

    fn start_in(
        scratch_base: Option<&Path>,
        xray_bin: &Path,
        outbound: &Value,
    ) -> Result<Self, String> {
        // 0700 dir, 0600 file: the config carries the subscription's live
        // credentials.
        let mut builder = tempfile::Builder::new();
        builder
            .prefix("rwhc-")
            .permissions(std::fs::Permissions::from_mode(0o700));
        let scratch = match scratch_base {
            Some(base) => builder.tempdir_in(base),
            None => builder.tempdir(),
        }
        .map_err(|e| format!("scratch dir: {e}"))?;
        let port = free_port().map_err(|e| format!("free port: {e}"))?;
        let cfg_path = scratch.path().join("config.json");
        write_private(&cfg_path, &build_config(outbound, port).to_string())
            .map_err(|e| format!("writing config: {e}"))?;
        let child = tokio::process::Command::new(xray_bin)
            .arg("run")
            .arg("-c")
            .arg(&cfg_path)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| format!("spawning xray: {e}"))?;
        Ok(Self {
            child,
            port,
            _scratch: scratch,
        })
    }

    /// The local SOCKS port the outbound is reachable through.
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Wait until Xray accepts connections on its SOCKS port. A request sent
    /// before that fails at the local hop and would be blamed on the far
    /// end.
    pub async fn listening(&self, within: Duration) -> bool {
        let deadline = Instant::now() + within;
        while Instant::now() < deadline {
            if tokio::net::TcpStream::connect(("127.0.0.1", self.port))
                .await
                .is_ok()
            {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        false
    }

    /// Kill Xray and return what it wrote to stderr.
    pub async fn stop(mut self) -> String {
        let _ = self.child.kill().await;
        let mut buf = String::new();
        if let Some(mut err) = self.child.stderr.take() {
            let _ = err.read_to_string(&mut buf).await;
        }
        buf
    }
}

fn write_private(path: &Path, text: &str) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(text.as_bytes())
}

fn socks_client(
    port: u16,
    timeout: Duration,
) -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .proxy(socks_proxy(port)?)
        .timeout(timeout)
        .build()
}

/// The proxy for an Xray's local SOCKS port. `socks5h`: names are resolved
/// at the far end, never locally, so DNS answers come from the exit too.
pub(crate) fn socks_proxy(port: u16) -> reqwest::Result<reqwest::Proxy> {
    reqwest::Proxy::all(format!("socks5h://127.0.0.1:{port}"))
}

/// One question to the echo endpoint. `None` for every way of not getting a
/// bare address back — keep waiting until the deadline.
async fn ask_echo(client: &reqwest::Client, echo_url: &str) -> Option<IpAddr> {
    let resp = client.get(echo_url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    parse_ip(&resp.text().await.ok()?)
}

/// Last non-empty lines of xray's stderr: where the real reason for a dead
/// tunnel is, short enough that one channel cannot fill an alert.
pub(crate) fn tail(text: &str, lines: usize, chars: usize) -> String {
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

    #[test]
    fn the_outbound_is_used_verbatim_behind_a_local_socks_inbound() {
        let outbound = json!({"protocol": "vless", "settings": {"vnext": [{"address": "edge.example.com", "port": 443}]}});

        let config = build_config(&outbound, 10842);

        assert_eq!(config["outbounds"][0], outbound);
        assert_eq!(config["inbounds"][0]["listen"], "127.0.0.1");
        assert_eq!(config["inbounds"][0]["port"], 10842);
    }

    #[test]
    fn a_free_port_is_handed_out() {
        let port = free_port().unwrap();

        assert!(port > 0);
    }

    /// The guarantee this module makes: a failed spawn must not leave the
    /// config, with its live credentials, on disk.
    #[tokio::test]
    async fn a_dead_spawn_leaves_no_scratch_dir_behind() {
        let base = tempfile::tempdir().unwrap();

        let outcome = attempt(
            Some(base.path()),
            Path::new("/nonexistent/xray-binary"),
            &json!({"protocol": "vless"}),
            Duration::from_millis(50),
            "https://echo.example.com",
            None,
        )
        .await;

        assert!(outcome.is_err(), "{outcome:?}");
        let leftovers: Vec<_> =
            std::fs::read_dir(base.path()).unwrap().collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    /// A server on a loopback port that answers one request with `head`,
    /// then writes each chunk and waits its pause after it, then closes.
    async fn serve(head: &str, chunks: Vec<(Vec<u8>, Duration)>) -> Url {
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        tokio::spawn(answer(listener, head.to_string(), chunks));
        url.parse().unwrap()
    }

    async fn answer(
        listener: tokio::net::TcpListener,
        head: String,
        chunks: Vec<(Vec<u8>, Duration)>,
    ) -> std::io::Result<()> {
        use tokio::io::AsyncWriteExt;
        let (mut socket, _) = listener.accept().await?;
        let mut request = [0u8; 4096];
        let _ = socket.read(&mut request).await?;
        socket.write_all(head.as_bytes()).await?;
        for (chunk, pause) in chunks {
            socket.write_all(&chunk).await?;
            tokio::time::sleep(pause).await;
        }
        Ok(())
    }

    fn target(url: Url, total: Duration, silence: Duration) -> DownloadTarget {
        DownloadTarget {
            url,
            total,
            silence,
        }
    }

    const MIB: usize = 1_048_576;

    #[tokio::test]
    async fn a_file_read_to_its_length_is_complete() {
        let url = serve(
            "HTTP/1.1 200 OK\r\nContent-Length: 1048576\r\nConnection: close\r\n\r\n",
            vec![(vec![0; MIB], Duration::ZERO)],
        )
        .await;
        let sut = target(url, Duration::from_secs(5), Duration::from_secs(2));

        let download = fetch(&reqwest::Client::new(), &sut).await;

        assert!(
            matches!(
                download,
                Download::Complete {
                    bytes: 1_048_576,
                    ..
                }
            ),
            "{download:?}"
        );
    }

    /// Without a `Content-Length` there is no size to fall short of: the
    /// server ending the body is the end of the file.
    #[tokio::test]
    async fn a_body_without_a_length_is_complete_when_the_server_ends_it() {
        let url = serve(
            "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n",
            vec![(vec![0; 300 * 1024], Duration::ZERO)],
        )
        .await;
        let sut = target(url, Duration::from_secs(5), Duration::from_secs(2));

        let download = fetch(&reqwest::Client::new(), &sut).await;

        assert!(
            matches!(download, Download::Complete { bytes: 307_200, .. }),
            "{download:?}"
        );
    }

    /// A server that accepts and never sends headers is cut at the total
    /// bound when that comes before the silence bound.
    #[tokio::test]
    async fn a_server_that_never_sends_headers_times_out_at_the_total_bound() {
        let url = serve("", vec![(Vec::new(), Duration::from_secs(5))]).await;
        let sut = target(url, Duration::from_millis(300), Duration::from_secs(3));
        let started = std::time::Instant::now();

        let download = fetch(&reqwest::Client::new(), &sut).await;

        assert!(
            matches!(download, Download::TimedOut { bytes: 0, of: None }),
            "{download:?}"
        );
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    /// The freeze: 20 KB, then nothing while the connection stays open.
    #[tokio::test]
    async fn a_body_that_goes_silent_is_stalled_where_it_stopped() {
        let url = serve(
            "HTTP/1.1 200 OK\r\nContent-Length: 1048576\r\n\r\n",
            vec![(vec![0; 20 * 1024], Duration::from_secs(5))],
        )
        .await;
        let sut =
            target(url, Duration::from_secs(5), Duration::from_millis(300));

        let download = fetch(&reqwest::Client::new(), &sut).await;

        assert!(
            matches!(
                download,
                Download::Stalled {
                    bytes: 20_480,
                    of: Some(1_048_576),
                    ..
                }
            ),
            "{download:?}"
        );
    }

    /// Bytes keep coming, too slowly to finish: throttled, not frozen.
    #[tokio::test]
    async fn a_body_still_trickling_at_the_bound_has_timed_out() {
        let trickle = (0..100)
            .map(|_| (vec![0; 1024], Duration::from_millis(50)))
            .collect();
        let url = serve(
            "HTTP/1.1 200 OK\r\nContent-Length: 1048576\r\n\r\n",
            trickle,
        )
        .await;
        let sut =
            target(url, Duration::from_millis(400), Duration::from_secs(2));

        let download = fetch(&reqwest::Client::new(), &sut).await;

        assert!(
            matches!(
                download,
                Download::TimedOut { bytes, of: Some(1_048_576) } if bytes > 0
            ),
            "{download:?}"
        );
    }

    #[tokio::test]
    async fn an_error_status_is_a_failed_download() {
        let url = serve(
            "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n",
            vec![],
        )
        .await;
        let sut = target(url, Duration::from_secs(5), Duration::from_secs(2));

        let download = fetch(&reqwest::Client::new(), &sut).await;

        assert_eq!(download, Download::Failed("HTTP 503".into()));
    }

    #[tokio::test]
    async fn a_target_nobody_listens_on_is_a_failed_download() {
        let sut = target(
            "http://127.0.0.1:1/".parse().unwrap(),
            Duration::from_secs(5),
            Duration::from_secs(2),
        );

        let download = fetch(&reqwest::Client::new(), &sut).await;

        assert!(matches!(download, Download::Failed(_)), "{download:?}");
    }

    #[test]
    fn the_stderr_tail_keeps_the_last_lines_only() {
        let stderr = "a\n\nb\nc\nd\n";

        let result = tail(stderr, 3, 200);

        assert_eq!(result, "b / c / d");
    }

    #[test]
    fn the_stderr_tail_is_cut_to_its_character_budget() {
        let stderr = "x".repeat(500);

        let result = tail(&stderr, 3, 10);

        assert_eq!(result.chars().count(), 10);
    }
}
