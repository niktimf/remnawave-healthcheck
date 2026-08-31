//! One `sendMessage`. Transport errors are retried with backoff; a 429 is
//! retried once after Telegram's `retry_after`. The bot token lives in the
//! URL, so no error text ever includes a URL.

use anyhow::Result;
use backon::{ExponentialBuilder, Retryable};
use serde_json::{Value, json};
use std::time::Duration;

pub struct Notifier {
    http: reqwest::Client,
    api_base: String,
    token: String,
    chat_id: String,
    thread_id: Option<i64>,
}

enum SendError {
    Transient(String),
    RateLimited(u64, String),
    Final(String),
}

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transient(s) | Self::Final(s) => f.write_str(s),
            Self::RateLimited(secs, s) => {
                write!(f, "rate limited ({secs}s): {s}")
            }
        }
    }
}

/// Seconds Telegram asks to wait, from the body of a 429.
fn retry_after(body: &str) -> Option<u64> {
    serde_json::from_str::<Value>(body)
        .ok()?
        .pointer("/parameters/retry_after")?
        .as_u64()
}

impl Notifier {
    pub fn new(
        bot_token: &str,
        chat_id: &str,
        thread_id: Option<i64>,
    ) -> Result<Self> {
        Ok(Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .build()?,
            api_base: "https://api.telegram.org".to_string(),
            token: bot_token.to_string(),
            chat_id: chat_id.to_string(),
            thread_id,
        })
    }

    #[cfg(test)]
    pub(crate) fn with_api_base(mut self, base: &str) -> Self {
        self.api_base = base.trim_end_matches('/').to_string();
        self
    }

    fn payload(&self, text: &str) -> Value {
        let mut p = json!({
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "HTML",
            "link_preview_options": {"is_disabled": true},
        });
        if let Some(thread) = self.thread_id {
            p["message_thread_id"] = json!(thread);
        }
        p
    }

    async fn post_once(&self, payload: &Value) -> Result<(), SendError> {
        let url = format!("{}/bot{}/sendMessage", self.api_base, self.token);
        let resp =
            self.http
                .post(&url)
                .json(payload)
                .send()
                .await
                .map_err(|e| {
                    SendError::Transient(format!(
                        "telegram unreachable: {}",
                        e.without_url()
                    ))
                })?;
        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }
        let body = resp.text().await.unwrap_or_default();
        let head: String = body.chars().take(300).collect();
        if status.as_u16() == 429 {
            return Err(SendError::RateLimited(
                retry_after(&body).unwrap_or(5).min(60),
                head,
            ));
        }
        if status.is_server_error() {
            return Err(SendError::Transient(format!("HTTP {status}: {head}")));
        }
        Err(SendError::Final(format!("HTTP {status}: {head}")))
    }

    pub async fn send(&self, text: &str) -> Result<(), String> {
        let payload = self.payload(text);
        let first = (|| async { self.post_once(&payload).await })
            .retry(
                ExponentialBuilder::default()
                    .with_min_delay(Duration::from_secs(1))
                    .with_max_times(2),
            )
            .when(|e| matches!(e, SendError::Transient(_)))
            .notify(|e, d| tracing::warn!("telegram: {e}; retrying in {d:?}"))
            .await;
        match first {
            Ok(()) => Ok(()),
            Err(SendError::RateLimited(secs, _)) => {
                tracing::warn!("telegram: rate limited, retrying in {secs}s");
                tokio::time::sleep(Duration::from_secs(secs)).await;
                self.post_once(&payload).await.map_err(|e| e.to_string())
            }
            Err(e) => Err(e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn notifier(server: &MockServer) -> Notifier {
        Notifier::new("123:secret", "-100", Some(7))
            .unwrap()
            .with_api_base(&server.uri())
    }

    #[tokio::test]
    async fn a_message_carries_chat_thread_and_html_mode() {
        let server = MockServer::start().await;
        Mock::given(method("POST")).and(path("/bot123:secret/sendMessage"))
            .and(body_partial_json(json!({"chat_id": "-100", "parse_mode": "HTML", "message_thread_id": 7, "link_preview_options": {"is_disabled": true}})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
            .expect(1).mount(&server).await;
        assert_eq!(notifier(&server).send("<b>hi</b>").await, Ok(()));
    }

    #[tokio::test]
    async fn a_rate_limit_is_waited_out_once() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/bot123:secret/sendMessage"))
            .respond_with(ResponseTemplate::new(429).set_body_json(
                json!({"ok": false, "parameters": {"retry_after": 0}}),
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/bot123:secret/sendMessage"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"ok": true})),
            )
            .expect(1)
            .mount(&server)
            .await;
        assert_eq!(notifier(&server).send("x").await, Ok(()));
    }

    #[tokio::test]
    async fn a_refusal_is_final_and_names_the_status_without_the_token() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/bot123:secret/sendMessage"))
            .respond_with(ResponseTemplate::new(400).set_body_string(
                r#"{"ok":false,"description":"Bad Request: chat not found"}"#,
            ))
            .expect(1)
            .mount(&server)
            .await;
        let err = notifier(&server).send("x").await.unwrap_err();
        assert!(err.contains("400") && err.contains("chat not found"), "{err}");
        assert!(!err.contains("secret"), "{err}");
    }

    #[test]
    fn retry_after_is_read_from_the_body() {
        assert_eq!(
            retry_after(r#"{"ok":false,"parameters":{"retry_after":37}}"#),
            Some(37)
        );
        assert_eq!(retry_after(r#"{"ok":false}"#), None);
        assert_eq!(retry_after("<html>502</html>"), None);
    }
}
