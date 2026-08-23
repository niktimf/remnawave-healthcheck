use std::time::Duration;

/// Where alerts go, once it is known that they can go anywhere at all.
///
/// Either credential alone is useless, so holding them as a pair that only
/// exists complete answers "is Telegram configured?" once, when this is built,
/// instead of at every place that wants to send something.
#[derive(Clone)]
pub struct Notifier {
    token: String,
    chat_id: String,
    /// Parsed once, when the notifier is built: a `--telegram-thread-id` that
    /// is not a number is a mistake in the invocation, and complaining about it
    /// belongs to startup rather than to every message.
    thread_id: Option<i64>,
}

impl Notifier {
    /// `None` when no credentials were given: running without a notifier is a
    /// deliberate configuration, so this is an absence, not an error.
    pub fn new(
        token: Option<&str>,
        chat_id: Option<&str>,
        thread_id: Option<&str>,
    ) -> Option<Self> {
        let (Some(token), Some(chat_id)) = (token, chat_id) else {
            return None;
        };
        Some(Self {
            token: token.to_string(),
            chat_id: chat_id.to_string(),
            thread_id: parse_thread_id(thread_id),
        })
    }

    pub async fn send(&self, text: &str) -> bool {
        post(&self.token, &self.chat_id, text, self.thread_id).await
    }
}

/// Written by hand, and the token is not in it: a derived `Debug` would put a
/// live bot token into whatever printed it.
impl std::fmt::Debug for Notifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Notifier")
            .field("token", &"<redacted>")
            .field("chat_id", &self.chat_id)
            .field("thread_id", &self.thread_id)
            .finish()
    }
}

/// The topic to post into, if one was given and it is a number. An empty value
/// is no thread rather than a malformed one — that is what an unset environment
/// variable looks like by the time it arrives.
fn parse_thread_id(thread_id: Option<&str>) -> Option<i64> {
    let thread = thread_id.map(str::trim).filter(|t| !t.is_empty())?;
    if let Ok(id) = thread.parse::<i64>() {
        Some(id)
    } else {
        eprintln!("[alert] ignoring non-numeric thread id {thread:?}");
        None
    }
}

/// Post a message. False on any failure — a dead notifier must never break the
/// run — but the reason is printed: the API body carries the real cause ("chat
/// not found", "bot was kicked", "Unauthorized" = token revoked).
async fn post(
    token: &str,
    chat_id: &str,
    text: &str,
    thread_id: Option<i64>,
) -> bool {
    let mut payload = serde_json::json!({
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
    });
    if let Some(thread) = thread_id {
        payload["message_thread_id"] = serde_json::json!(thread);
    }

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            // `without_url` here too: a builder error carries no URL today, but
            // nothing about this call site guarantees that, and the URL of this
            // client would hold the token.
            eprintln!("[alert] http client: {}", e.without_url());
            return false;
        }
    };
    let url = format!("https://api.telegram.org/bot{token}/sendMessage");
    match client.post(&url).json(&payload).send().await {
        Err(e) => {
            // `without_url`: a reqwest error's Display appends " for url
            // (...)", and that URL carries the bot token. Any network hiccup
            // would otherwise print the live token to stderr — into whatever
            // collects this tool's logs.
            eprintln!("[alert] telegram unreachable: {}", e.without_url());
            false
        }
        Ok(resp) if !resp.status().is_success() => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            // A rate limit is the one refusal that says when to come back, and
            // reads as an ordinary failure unless that number is pulled out.
            // Nothing waits for it: this tool sends one message per run, and a
            // failed delivery already leaves the state file untouched so the
            // change is reported again next run.
            match retry_after(&body) {
                Some(seconds) => eprintln!(
                    "[alert] telegram rate limit (HTTP {status}): \
                     it will accept this again in {seconds}s"
                ),
                None => eprintln!(
                    "[alert] telegram send failed: HTTP {status} — {}",
                    body.chars().take(300).collect::<String>()
                ),
            }
            false
        }
        Ok(_) => true,
    }
}

/// Seconds Telegram asks to wait, from the body of a refusal that carries them.
fn retry_after(body: &str) -> Option<u64> {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()?
        .get("parameters")?
        .get("retry_after")?
        .as_u64()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn half_a_credential_pair_is_no_notifier() {
        // Three call sites used to decide this independently; there is one now,
        // so each half alone still meaning "not configured" is worth pinning.
        assert!(Notifier::new(Some("token"), None, None).is_none());
        assert!(Notifier::new(None, Some("chat"), None).is_none());
        assert!(Notifier::new(None, None, Some("42")).is_none());
        assert!(Notifier::new(Some("token"), Some("chat"), None).is_some());
    }

    #[test]
    fn a_thread_id_is_read_once_and_only_if_it_is_a_number() {
        let thread_of = |raw| {
            Notifier::new(Some("token"), Some("chat"), raw)
                .unwrap()
                .thread_id
        };
        assert_eq!(thread_of(Some("42")), Some(42));
        assert_eq!(thread_of(Some(" 42 ")), Some(42));
        assert_eq!(thread_of(Some("-100123")), Some(-100_123));
        // Neither of these is a topic to post into, and neither may reach a
        // payload.
        assert_eq!(thread_of(Some("general")), None);
        assert_eq!(thread_of(Some("")), None);
        assert_eq!(thread_of(None), None);
    }

    #[test]
    fn a_rate_limit_is_read_out_of_the_refusal() {
        let body = r#"{"ok":false,"error_code":429,
                        "description":"Too Many Requests: retry after 37",
                        "parameters":{"retry_after":37}}"#;
        assert_eq!(retry_after(body), Some(37));
        // Every other refusal carries no such number, and must not be reported
        // as if it did.
        assert_eq!(retry_after(r#"{"ok":false,"error_code":400}"#), None);
        assert_eq!(retry_after("<html>502 Bad Gateway</html>"), None);
    }

    #[test]
    fn a_notifier_never_prints_its_token() {
        let notifier =
            Notifier::new(Some("123:secret"), Some("chat"), Some("42"))
                .unwrap();
        let printed = format!("{notifier:?}");
        assert!(!printed.contains("secret"), "{printed}");
        assert!(printed.contains("chat"), "{printed}");
    }
}
