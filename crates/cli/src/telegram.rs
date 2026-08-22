use std::time::Duration;

/// Post a message. Returns false on any failure — a dead notifier must never break the run,
/// but the reason is printed: the API body is where the real cause is ("chat not found",
/// "bot was kicked", "Unauthorized" = token revoked, "group chat was upgraded to a supergroup").
pub async fn send(token: &str, chat_id: &str, text: &str, thread_id: Option<&str>) -> bool {
    let mut payload = serde_json::json!({
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
    });
    if let Some(thread) = thread_id.map(str::trim).filter(|t| !t.is_empty()) {
        match thread.parse::<i64>() {
            Ok(id) => {
                payload["message_thread_id"] = serde_json::json!(id);
            }
            Err(_) => eprintln!("[alert] ignoring non-numeric thread id {thread:?}"),
        }
    }

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            // `without_url` here too: a builder error carries no URL today, but nothing about
            // this call site guarantees that, and the URL of this client would hold the token.
            eprintln!("[alert] http client: {}", e.without_url());
            return false;
        }
    };
    let url = format!("https://api.telegram.org/bot{token}/sendMessage");
    match client.post(&url).json(&payload).send().await {
        Err(e) => {
            // `without_url`: a reqwest error's Display appends " for url (...)", and that URL
            // carries the bot token. Any network hiccup would otherwise print the live token to
            // stderr — into whatever collects this tool's logs.
            eprintln!("[alert] telegram unreachable: {}", e.without_url());
            false
        }
        Ok(resp) if !resp.status().is_success() => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            eprintln!(
                "[alert] telegram send failed: HTTP {status} — {}",
                body.chars().take(300).collect::<String>()
            );
            false
        }
        Ok(_) => true,
    }
}
