//! The newest stable release of the panel, as GitHub publishes it.
//!
//! The only request this tool makes to anything but the panel and its nodes.
//! It is therefore treated as an opinion that may be unavailable: a rate-limited
//! or unreachable GitHub is a version we could not read, never a panel that is
//! out of date.

use crate::panel::USER_AGENT;
use remnawave_healthcheck_core::model::Reported;
use reqwest::Client;
use reqwest::header::{ACCEPT, AUTHORIZATION};
use serde::Deserialize;
use std::time::Duration;

pub const GITHUB_API: &str = "https://api.github.com";

/// The repository the panel is released from.
pub const PANEL_REPO: &str = "remnawave/panel";

#[derive(Debug, Deserialize)]
struct ReleaseDto {
    tag_name: String,
}

/// `releases/latest` is GitHub's newest **stable** release: it skips
/// pre-releases and drafts, which is the comparison worth making.
pub async fn latest_release(
    api: &str,
    repo: &str,
    token: Option<&str>,
    timeout: Duration,
) -> Reported {
    match fetch(api, repo, token, timeout).await {
        Ok(tag) => Reported::Known(tag),
        Err(why) => Reported::Failed(why),
    }
}

async fn fetch(
    api: &str,
    repo: &str,
    token: Option<&str>,
    timeout: Duration,
) -> Result<String, String> {
    let client = Client::builder()
        .timeout(timeout)
        .user_agent(USER_AGENT)
        .build()
        .map_err(crate::panel::error_chain)?;
    let request = client
        .get(format!("{api}/repos/{repo}/releases/latest"))
        .header(ACCEPT, "application/vnd.github+json");
    // Unauthenticated GitHub allows 60 requests an hour per address, and a
    // hosted runner shares its address with everyone else on it. A token — the
    // one every Actions run already has — lifts that to 1000.
    let request = match token {
        Some(t) => request.header(AUTHORIZATION, format!("Bearer {t}")),
        None => request,
    };
    let response = request.send().await.map_err(crate::panel::error_chain)?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("GET releases/latest: {status}"));
    }
    let release: ReleaseDto = response
        .json()
        .await
        .map_err(|e| format!("parsing releases/latest: {e}"))?;
    Ok(release.tag_name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn answering(response: ResponseTemplate) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/remnawave/panel/releases/latest"))
            .respond_with(response)
            .mount(&server)
            .await;
        server
    }

    #[tokio::test]
    async fn the_tag_of_the_latest_release_is_the_version() {
        let server =
            answering(ResponseTemplate::new(200).set_body_json(json!({
                "tag_name": "3.4.3", "name": "v3.4.3", "prerelease": false
            })))
            .await;

        let reported = latest_release(
            &server.uri(),
            PANEL_REPO,
            None,
            Duration::from_secs(5),
        )
        .await;

        assert_eq!(reported, Reported::Known("3.4.3".to_string()));
    }

    /// The allowance is 60 an hour per address, and a hosted runner shares its
    /// address. Exhausting it must not read as a panel that is up to date.
    #[tokio::test]
    async fn a_refused_request_is_a_version_that_could_not_be_read() {
        let server = answering(ResponseTemplate::new(403)).await;

        let reported = latest_release(
            &server.uri(),
            PANEL_REPO,
            None,
            Duration::from_secs(5),
        )
        .await;

        assert!(
            matches!(&reported, Reported::Failed(why) if why.contains("403")),
            "{reported:?}"
        );
    }

    #[tokio::test]
    async fn a_body_that_is_not_a_release_is_an_error() {
        let server =
            answering(ResponseTemplate::new(200).set_body_string("not json"))
                .await;

        let reported = latest_release(
            &server.uri(),
            PANEL_REPO,
            None,
            Duration::from_secs(5),
        )
        .await;

        assert!(matches!(reported, Reported::Failed(_)), "{reported:?}");
    }
}
