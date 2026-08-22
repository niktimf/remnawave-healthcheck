use anyhow::{Context, Result};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

fn release_url(version: &str) -> String {
    format!("https://github.com/XTLS/Xray-core/releases/download/v{version}/Xray-linux-64.zip")
}

/// Path to an Xray binary of exactly `version`, downloading and caching it when missing.
///
/// The cache entry appears only once it is complete: the download is unpacked next to it under a
/// temporary name and renamed into place afterwards. A process killed halfway through — a CI job
/// hitting its time limit is the realistic case — would otherwise leave a truncated file that the
/// next run accepts on sight, and every channel would then fail against a binary that cannot run.
pub async fn ensure(version: &str, cache_dir: &Path) -> Result<PathBuf> {
    let binary = cache_dir.join(version).join("xray");
    if binary.exists() {
        return Ok(binary);
    }
    let dir = binary.parent().expect("binary path always has a parent");
    tokio::fs::create_dir_all(dir).await?;

    download_into(version, dir).await?;
    Ok(binary)
}

async fn download_into(version: &str, dir: &Path) -> Result<()> {
    let url = release_url(version);
    let bytes = reqwest::Client::new()
        .get(&url)
        .timeout(std::time::Duration::from_secs(180))
        .send()
        .await
        .with_context(|| format!("downloading {url}"))?
        .error_for_status()?
        .bytes()
        .await?;

    let dir = dir.to_path_buf();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let target = dir.join("xray");
        // Same directory, so the rename below stays within one filesystem and is atomic. The pid
        // keeps two runs of the tool from unpacking over each other's partial file.
        let partial = dir.join(format!("xray.{}.partial", std::process::id()));
        let unpacked = unpack_into(bytes, &partial);
        if unpacked.is_err() {
            let _ = std::fs::remove_file(&partial);
        }
        unpacked?;
        std::fs::rename(&partial, &target)
            .with_context(|| format!("moving the unpacked binary into {}", target.display()))?;
        Ok(())
    })
    .await??;
    Ok(())
}

/// Unpack the `xray` entry of the release archive to `target` and make it executable.
fn unpack_into(bytes: impl AsRef<[u8]>, target: &Path) -> Result<()> {
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
