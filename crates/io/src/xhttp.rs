//! `GET <path>?v=0` and `GET <path>/?v=0` against an xhttp inbound. The node
//! is dialled by its address with the channel's SNI, so a CDN-fronted host is
//! probed where it actually lives.

use crate::panel::USER_AGENT;
use remnawave_healthcheck_core::model::{Channel, XhttpFacts};
use reqwest::Client;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

pub async fn probe(channel: &Channel, timeout: Duration) -> XhttpFacts {
    let both = |e: String| XhttpFacts {
        without_slash: Err(e.clone()),
        with_slash: Err(e),
    };
    let Some(path) = channel.path.as_deref() else {
        return both("channel has no path".to_string());
    };
    let sni = channel.sni.as_deref().unwrap_or(&channel.address);
    let client =
        match client_for(&channel.address, channel.port, sni, timeout).await {
            Ok(c) => c,
            Err(e) => return both(e),
        };
    let (plain, slash) = urls(sni, channel.port, path);
    XhttpFacts {
        without_slash: status(&client, &plain).await,
        with_slash: status(&client, &slash).await,
    }
}

/// The two forms: `…/submit?v=0` and `…/submit/?v=0`.
fn urls(sni: &str, port: u16, path: &str) -> (String, String) {
    let base = format!("https://{sni}:{port}/{}", path.trim_matches('/'));
    (format!("{base}?v=0"), format!("{base}/?v=0"))
}

async fn client_for(
    address: &str,
    port: u16,
    sni: &str,
    timeout: Duration,
) -> Result<Client, String> {
    let ip: IpAddr = match address.parse() {
        Ok(ip) => ip,
        Err(_) => tokio::net::lookup_host((address, port))
            .await
            .map_err(|e| format!("resolving {address}: {e}"))?
            .next()
            .ok_or_else(|| format!("resolving {address}: no address"))?
            .ip(),
    };
    Client::builder()
        .timeout(timeout)
        .user_agent(USER_AGENT)
        // Reality and self-signed certificates on inbounds are the norm.
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .resolve(sni, SocketAddr::new(ip, port))
        .build()
        .map_err(crate::panel::error_chain)
}

async fn status(client: &Client, url: &str) -> Result<u16, String> {
    client
        .get(url)
        .send()
        .await
        .map(|r| r.status().as_u16())
        .map_err(crate::panel::error_chain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// A server that answers `400` for `/p` and nothing at all for `/p/`.
    async fn server_answering_the_bare_path() -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/p"))
            .and(query_param("v", "0"))
            .respond_with(ResponseTemplate::new(400))
            .mount(&server)
            .await;
        server
    }

    #[test]
    fn both_url_forms_are_built_from_one_path() {
        let (without_slash, with_slash) =
            urls("cdn.example.com", 443, "/api/v1/traces/submit/");

        assert_eq!(
            without_slash,
            "https://cdn.example.com:443/api/v1/traces/submit?v=0"
        );
        assert_eq!(
            with_slash,
            "https://cdn.example.com:443/api/v1/traces/submit/?v=0"
        );
    }

    #[tokio::test]
    async fn a_served_path_is_read_as_its_status() {
        let server = server_answering_the_bare_path().await;
        let client = Client::new();

        let result = status(&client, &format!("{}/p?v=0", server.uri())).await;

        assert_eq!(result, Ok(400));
    }

    #[tokio::test]
    async fn a_path_form_the_server_does_not_serve_is_read_as_404() {
        let server = server_answering_the_bare_path().await;
        let client = Client::new();

        let result = status(&client, &format!("{}/p/?v=0", server.uri())).await;

        assert_eq!(result, Ok(404));
    }

    #[tokio::test]
    async fn a_host_that_refuses_the_connection_is_an_error() {
        let client = Client::new();

        let result = status(&client, "http://127.0.0.1:9/p").await;

        assert!(result.is_err(), "{result:?}");
    }

    #[tokio::test]
    async fn a_channel_without_a_path_is_two_errors() {
        let channel = Channel {
            address: "192.0.2.1".into(),
            port: 443,
            ..Default::default()
        };

        let facts = probe(&channel, Duration::from_secs(1)).await;

        assert!(facts.without_slash.is_err() && facts.with_slash.is_err());
    }
}
