//! Ask every service through one subscription outbound. What to ask and how
//! to read the answer is `remnawave_healthcheck_core::checks::services`; this
//! module carries the requests through a fresh Xray and back.

use crate::probe::{Xray, socks_proxy, tail};
use remnawave_healthcheck_core::checks::services::{
    Access, Response, Service, Silence,
};
use serde_json::Value;
use std::path::Path;
use std::time::Duration;

/// How long Xray gets to open its SOCKS port.
const XRAY_START: Duration = Duration::from_secs(5);

/// Every service, asked one after another through `outbound`. One after
/// another, because a burst from one address is what gets a Cloudflare
/// challenge in place of an answer. `Err` when the tunnel itself could not
/// be brought up, so no answer can be blamed on a service.
pub async fn check(
    xray_bin: &Path,
    outbound: &Value,
    timeout: Duration,
) -> Result<Vec<(Service, Access)>, String> {
    let xray = Xray::start(xray_bin, outbound)?;
    if !xray.listening(XRAY_START).await {
        let stderr = xray.stop().await;
        return Err(format!(
            "xray did not open its SOCKS port within {XRAY_START:?}: {}",
            tail(&stderr, 3, 200)
        ));
    }
    let client = client(Some(xray.port()), timeout)
        .map_err(|e| format!("socks client: {e}"))?;
    let mut answers = Vec::with_capacity(Service::ALL.len());
    for service in Service::ALL {
        let access = ask(&client, service, service.request().url).await;
        answers.push((service, access));
    }
    xray.stop().await;
    Ok(answers)
}

/// Through the Xray at `socks_port`, or straight out in tests. No redirect
/// is followed: Claude and NotebookLM answer in `Location`.
fn client(
    socks_port: Option<u16>,
    timeout: Duration,
) -> reqwest::Result<reqwest::Client> {
    let builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeout);
    let builder = match socks_port {
        Some(port) => builder.proxy(socks_proxy(port)?),
        None => builder,
    };
    builder.build()
}

/// One service asked at `url`, which is the service's own except in tests.
async fn ask(client: &reqwest::Client, service: Service, url: &str) -> Access {
    match fetch(client, url, service.request().headers).await {
        Ok(response) => service.classify(&response),
        Err(e) => {
            tracing::debug!(service = service.label(), "{e:#}");
            Access::NoAnswer(short(&e))
        }
    }
}

async fn fetch(
    client: &reqwest::Client,
    url: &str,
    headers: &[(&str, &str)],
) -> reqwest::Result<Response> {
    let response = headers
        .iter()
        .fold(client.get(url), |request, (name, value)| {
            request.header(*name, *value)
        })
        .send()
        .await?;
    let status = response.status().as_u16();
    let location = response
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let body = response.text().await?;
    Ok(Response {
        status,
        location,
        body,
    })
}

/// The kind of transport failure. The full chain goes to the debug log.
fn short(e: &reqwest::Error) -> Silence {
    if e.is_timeout() {
        Silence::Timeout
    } else if e.is_connect() {
        Silence::Connection
    } else if e.is_body() || e.is_decode() {
        Silence::CutShort
    } else {
        Silence::Failed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header_exists, method};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn direct() -> reqwest::Client {
        client(None, Duration::from_secs(2)).unwrap()
    }

    #[tokio::test]
    async fn the_answer_is_read_by_the_services_own_classifier() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(header_exists("accept-language"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("Enjoy ad-free videos"),
            )
            .mount(&server)
            .await;

        let access =
            ask(&direct(), Service::YoutubePremium, &server.uri()).await;

        assert_eq!(access, Access::Available);
    }

    /// Claude's refusal is the redirect itself: following it would read the
    /// refusal page's status instead of its address.
    #[tokio::test]
    async fn a_redirect_is_read_where_it_points_not_followed() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(302).insert_header(
                "location",
                "https://claude.com/app-unavailable-in-region",
            ))
            .mount(&server)
            .await;

        let access = ask(&direct(), Service::Claude, &server.uri()).await;

        assert_eq!(access, Access::Blocked { region: None });
    }

    #[tokio::test]
    async fn a_transport_failure_is_no_answer_rather_than_an_unread_page() {
        let sut = client(None, Duration::from_millis(200)).unwrap();

        let access = ask(&sut, Service::ChatGpt, "http://127.0.0.1:1").await;

        assert_eq!(access, Access::NoAnswer(Silence::Connection));
    }

    #[tokio::test]
    async fn a_missing_xray_is_a_tunnel_failure_not_ten_silent_services() {
        let outcome = check(
            Path::new("/nonexistent/xray-binary"),
            &serde_json::json!({"protocol": "vless"}),
            Duration::from_secs(1),
        )
        .await;

        let err = outcome.unwrap_err();
        assert!(err.starts_with("spawning xray"), "{err}");
    }

    /// Every request as the stage sends it, straight from this machine. A
    /// challenge is a fair answer from some addresses, so the test asks only
    /// that every service answered; `--nocapture` prints what each said.
    #[tokio::test]
    #[ignore = "needs the network"]
    async fn every_service_answers_the_request_the_stage_sends() {
        let sut = direct_with(Duration::from_secs(15));

        let mut answers = Vec::new();
        for service in Service::ALL {
            let access = ask(&sut, service, service.request().url).await;
            println!("{}: {access:?}", service.label());
            answers.push((service, access));
        }

        let silent: Vec<_> = answers
            .iter()
            .filter(|(_, a)| matches!(a, Access::NoAnswer(_)))
            .collect();
        assert!(silent.is_empty(), "{silent:?}");
    }

    fn direct_with(timeout: Duration) -> reqwest::Client {
        client(None, timeout).unwrap()
    }

    /// The whole path through a real Xray: a `freedom` outbound leaves from
    /// this machine. Some service may stay silent from a given address
    /// (YouTube times out from RU), but a tunnel that works gets answers.
    #[tokio::test]
    #[ignore = "downloads Xray and needs the network"]
    async fn every_service_answers_through_a_real_xray() {
        let cache = tempfile::tempdir().unwrap();
        let binary = crate::probe::ensure_xray("26.6.27", cache.path())
            .await
            .unwrap();
        let outbound = serde_json::json!({"protocol": "freedom"});

        let answers = check(&binary, &outbound, Duration::from_secs(15))
            .await
            .unwrap();

        println!("{answers:?}");
        assert!(
            answers
                .iter()
                .any(|(_, a)| !matches!(a, Access::NoAnswer(_))),
            "{answers:?}"
        );
    }
}
