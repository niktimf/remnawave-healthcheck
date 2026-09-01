//! A TLS handshake with an endpoint, to read its certificate's expiry. The
//! usual verifier is kept: an expired certificate fails the handshake, and
//! that failure is the fact reported.

use chrono::{DateTime, Utc};
use remnawave_healthcheck_core::model::TlsFacts;
use rustls::pki_types::ServerName;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

pub async fn inspect(host: &str, port: u16, timeout: Duration) -> TlsFacts {
    match tokio::time::timeout(timeout, handshake(host, port)).await {
        Err(_) => TlsFacts {
            not_after: None,
            error: Some(format!("timeout after {}s", timeout.as_secs())),
        },
        Ok(Ok(not_after)) => TlsFacts {
            not_after,
            error: None,
        },
        Ok(Err(e)) => TlsFacts {
            not_after: None,
            error: Some(e),
        },
    }
}

async fn handshake(
    host: &str,
    port: u16,
) -> Result<Option<DateTime<Utc>>, String> {
    let tcp = TcpStream::connect((host, port))
        .await
        .map_err(|e| e.to_string())?;
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| e.to_string())?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let name =
        ServerName::try_from(host.to_string()).map_err(|e| e.to_string())?;
    let stream = TlsConnector::from(Arc::new(config))
        .connect(name, tcp)
        .await
        .map_err(|e| describe(&e))?;
    let (_, conn) = stream.get_ref();
    let Some(cert) = conn.peer_certificates().and_then(|c| c.first()) else {
        return Ok(None);
    };
    let (_, parsed) = x509_parser::parse_x509_certificate(cert.as_ref())
        .map_err(|e| e.to_string())?;
    Ok(DateTime::from_timestamp(parsed.validity().not_after.timestamp(), 0))
}

/// `"expired"` for an expired peer certificate, rustls's own words otherwise.
fn describe(e: &std::io::Error) -> String {
    if let Some(inner) =
        e.get_ref().and_then(|i| i.downcast_ref::<rustls::Error>())
    {
        let text = inner.to_string();
        if matches!(
            inner,
            rustls::Error::InvalidCertificate(
                rustls::CertificateError::Expired
            )
        ) || text.contains("xpired")
        {
            return "expired".to_string();
        }
        return text;
    }
    e.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_closed_port_is_an_error_not_a_panic() {
        let port = std::net::TcpListener::bind(("127.0.0.1", 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port();

        let facts = inspect("127.0.0.1", port, Duration::from_secs(2)).await;

        assert!(facts.not_after.is_none());
        assert!(facts.error.is_some(), "{facts:?}");
    }

    #[tokio::test]
    #[ignore = "needs the network"]
    async fn a_public_host_presents_a_certificate_with_an_expiry() {
        let facts = inspect("example.com", 443, Duration::from_secs(10)).await;

        assert!(facts.error.is_none(), "{facts:?}");
        assert!(facts.not_after.unwrap() > Utc::now());
    }
}
