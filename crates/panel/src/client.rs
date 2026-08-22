use crate::{dto, map, subscription};
use anyhow::{Context, Result};
use remnawave_healthcheck_core::model::Snapshot;
use std::time::Duration;

pub struct PanelClient {
    http: reqwest::Client,
    base: String,
    token: String,
}

impl PanelClient {
    pub fn new(base_url: &str, token: &str) -> Result<Self> {
        Ok(Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()?,
            base: base_url.trim_end_matches('/').to_string(),
            token: token.to_string(),
        })
    }

    async fn get(&self, path: &str, authorized: bool) -> Result<String> {
        let url = format!("{}{path}", self.base);
        let mut req = self.http.get(&url);
        if authorized {
            req = req.bearer_auth(&self.token);
        }
        let resp = req.send().await.with_context(|| format!("GET {url}"))?;
        let status = resp.status();
        let body = resp
            .text()
            .await
            .with_context(|| format!("reading body of {url}"))?;
        anyhow::ensure!(
            status.is_success(),
            "GET {url} returned {status}: {}",
            body.chars().take(300).collect::<String>()
        );
        Ok(body)
    }

    /// Everything one run needs, in four requests.
    pub async fn snapshot(&self, short_uuid: &str) -> Result<Snapshot> {
        let nodes = self.get("/api/nodes", true).await?;
        let profiles = self.get("/api/config-profiles", true).await?;
        let raw = self
            .get(
                &format!(
                    "/api/subscriptions/by-short-uuid/{short_uuid}/raw?withDisabledHosts=false"
                ),
                true,
            )
            .await?;
        let sub = self
            .get(&format!("/api/sub/{short_uuid}/json"), false)
            .await?;

        Ok(map::build_snapshot(
            dto::parse_nodes(&nodes).context("parsing /api/nodes")?,
            dto::parse_profiles(&profiles).context("parsing /api/config-profiles")?,
            dto::parse_resolved(&raw).context("parsing raw subscription")?,
            subscription::parse(&sub).context("parsing JSON subscription")?,
        ))
    }
}

/// The monitoring user's `shortUuid` is the last path segment of the subscription URL.
pub fn short_uuid_from_url(url: &str) -> Option<String> {
    let without_query = url.split('?').next()?;
    // Only look inside the path, not the host: `sub.example.com` in `https://sub.example.com/`
    // must not be mistaken for a path segment.
    let after_scheme = without_query.split("://").nth(1).unwrap_or(without_query);
    let path = match after_scheme.find('/') {
        Some(idx) => &after_scheme[idx..],
        None => return None,
    };
    let trimmed = path.trim_end_matches('/');
    (!trimmed.is_empty()).then(|| trimmed.rsplit('/').next().unwrap().to_string())
}

#[cfg(test)]
mod tests {
    use super::short_uuid_from_url;

    #[test]
    fn short_uuid_is_the_last_path_segment() {
        assert_eq!(
            short_uuid_from_url("https://sub.example.com/abc123").as_deref(),
            Some("abc123")
        );
        assert_eq!(
            short_uuid_from_url("https://sub.example.com/abc123/").as_deref(),
            Some("abc123")
        );
        assert_eq!(
            short_uuid_from_url("https://sub.example.com/abc123?x=1").as_deref(),
            Some("abc123")
        );
        assert_eq!(
            short_uuid_from_url("https://sub.example.com/").as_deref(),
            None
        );
    }
}
