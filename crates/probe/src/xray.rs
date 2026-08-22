use anyhow::{Context, Result};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

fn release_url(version: &str) -> String {
    format!("https://github.com/XTLS/Xray-core/releases/download/v{version}/Xray-linux-64.zip")
}

/// Path to an Xray binary of exactly `version`, downloading and caching it when missing.
/// A partially written binary is removed rather than left behind as a poisoned cache entry.
pub async fn ensure(version: &str, cache_dir: &Path) -> Result<PathBuf> {
    let binary = cache_dir.join(version).join("xray");
    if binary.exists() {
        return Ok(binary);
    }
    let dir = binary.parent().expect("binary path always has a parent");
    tokio::fs::create_dir_all(dir).await?;

    let result = download_into(version, dir).await;
    if result.is_err() {
        let _ = tokio::fs::remove_file(&binary).await;
    }
    result?;
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
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes))?;
        let mut entry = archive
            .by_name("xray")
            .context("release archive has no 'xray' entry")?;
        let target = dir.join("xray");
        let mut file = std::fs::File::create(&target)?;
        std::io::copy(&mut entry, &mut file)?;
        let mut perms = std::fs::metadata(&target)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&target, perms)?;
        Ok(())
    })
    .await??;
    Ok(())
}
