use crate::model::CheckResult;
use std::collections::BTreeMap;

/// Non-OK checks of one run, keyed by the stable check key. BTreeMap keeps output deterministic.
pub type ProblemSet = BTreeMap<String, String>;

/// What changed between two runs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Diff {
    pub new: ProblemSet,
    pub recovered: ProblemSet,
    pub escalated: ProblemSet,
}

impl Diff {
    pub fn is_empty(&self) -> bool {
        self.new.is_empty() && self.recovered.is_empty() && self.escalated.is_empty()
    }
}

/// Non-OK results of one run, keyed by check key. Keys must be unique by construction — two
/// results sharing one key collapse into a single entry here, and the loser disappears from the
/// alert without a trace (see `Channel::check_key`).
pub fn problem_set(results: &[CheckResult]) -> ProblemSet {
    results
        .iter()
        .filter(|r| !r.severity.is_ok())
        .map(|r| {
            (
                r.key.clone(),
                format!("{}: {}", r.severity.label(), r.detail),
            )
        })
        .collect()
}

/// Severity encoded in a problem-set value ("FAIL: ..." -> 2). Unknown prefixes rank lowest.
fn rank(value: &str) -> i32 {
    match value.split(':').next().unwrap_or("").trim() {
        "OK" => 0,
        "WARN" => 1,
        "FAIL" => 2,
        _ => -1,
    }
}

/// Appearing and disappearing keys always count. So does a severity escalation on a key that
/// was already a problem. Softening (FAIL -> WARN) is deliberately silent: the problem is still
/// there and re-alerting on it is noise.
pub fn diff(current: &ProblemSet, previous: &ProblemSet) -> Diff {
    let new = current
        .iter()
        .filter(|(k, _)| !previous.contains_key(*k))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let recovered = previous
        .iter()
        .filter(|(k, _)| !current.contains_key(*k))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let escalated = current
        .iter()
        .filter(|(k, v)| previous.get(*k).is_some_and(|p| rank(v) > rank(p)))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    Diff {
        new,
        recovered,
        escalated,
    }
}

fn icon(value: &str) -> &'static str {
    if rank(value) == 1 {
        "\u{1F7E1}"
    } else {
        "\u{1F534}"
    }
}

/// Escape the characters Telegram's HTML parse mode treats specially. Public because every path
/// that puts text into an alert needs it, the out-of-band panel-failure alert included. A check's
/// own key or detail text (xray stderr, a panel status message) is not under our control and can
/// contain a stray `<` or bare `&`; unescaped, that either mangles the message's markup or makes Telegram reject
/// the whole alert with "can't parse entities" — losing the alert entirely, which is exactly the
/// failure this tool exists to prevent.
pub fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Telegram message body, HTML parse mode.
pub fn format_message(d: &Diff, run_url: Option<&str>) -> String {
    let mut lines = vec!["<b>Healthcheck</b>".to_string()];
    for (k, v) in &d.new {
        let mark = icon(v);
        let (k, v) = (escape_html(k), escape_html(v));
        lines.push(format!("{mark} NEW  {k} — {v}"));
    }
    for (k, v) in &d.escalated {
        let (k, v) = (escape_html(k), escape_html(v));
        lines.push(format!("\u{1F53A} WORSE  {k} — {v}"));
    }
    for (k, v) in &d.recovered {
        let (k, v) = (escape_html(k), escape_html(v));
        lines.push(format!("\u{1F7E2} RECOVERED  {k} — {v}"));
    }
    if let Some(url) = run_url {
        lines.push(format!("\n{url}"));
    }
    lines.join("\n")
}

pub fn to_json(state: &ProblemSet) -> String {
    serde_json::to_string_pretty(state).unwrap_or_else(|_| "{}".to_string())
}

/// Anything unreadable is treated as "no previous run" — a corrupt state file must not break
/// the run, it only costs one round of re-alerting.
pub fn from_json(raw: &str) -> ProblemSet {
    serde_json::from_str(raw).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CheckResult, Severity};

    fn ps(pairs: &[(&str, &str)]) -> ProblemSet {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn problem_set_keeps_only_non_ok() {
        let results = vec![
            CheckResult::new("a", "a", Severity::Ok, "fine"),
            CheckResult::new("b", "b", Severity::Warn, "meh"),
            CheckResult::new("c", "c", Severity::Fail, "bad"),
        ];
        let got = problem_set(&results);
        assert_eq!(got.len(), 2);
        assert_eq!(got["b"], "WARN: meh");
        assert_eq!(got["c"], "FAIL: bad");
    }

    #[test]
    fn diff_reports_new_recovered_and_escalated() {
        let previous = ps(&[("a", "WARN: x"), ("b", "FAIL: y")]);
        let current = ps(&[("a", "FAIL: x"), ("c", "FAIL: z")]);
        let d = diff(&current, &previous);
        assert_eq!(d.new.keys().collect::<Vec<_>>(), vec!["c"]);
        assert_eq!(d.recovered.keys().collect::<Vec<_>>(), vec!["b"]);
        assert_eq!(d.escalated.keys().collect::<Vec<_>>(), vec!["a"]);
        assert!(!d.is_empty());
    }

    #[test]
    fn softening_from_fail_to_warn_is_silent() {
        let previous = ps(&[("a", "FAIL: x")]);
        let current = ps(&[("a", "WARN: x")]);
        let d = diff(&current, &previous);
        assert!(d.is_empty(), "FAIL->WARN must not alert");
    }

    #[test]
    fn unchanged_state_is_silent() {
        let s = ps(&[("a", "FAIL: x")]);
        assert!(diff(&s, &s).is_empty());
    }

    #[test]
    fn json_roundtrip_and_tolerance_to_garbage() {
        let s = ps(&[("a", "FAIL: x")]);
        assert_eq!(from_json(&to_json(&s)), s);
        assert!(from_json("not json at all").is_empty());
        assert!(from_json("[1,2,3]").is_empty());
    }

    #[test]
    fn html_special_characters_in_keys_and_values_are_escaped() {
        let d = Diff {
            new: ps(&[("channel:<script>", "FAIL: xray said <boom> & died")]),
            recovered: ps(&[]),
            escalated: ps(&[]),
        };
        let msg = format_message(&d, None);
        assert!(
            !msg.contains("<script>"),
            "raw tag must not reach Telegram: {msg}"
        );
        assert!(
            !msg.contains("<boom>"),
            "raw tag must not reach Telegram: {msg}"
        );
        assert!(msg.contains("&lt;script&gt;"));
        assert!(msg.contains("&lt;boom&gt;"));
        assert!(msg.contains("&amp;"));
        // The template's own markup must still work as HTML.
        assert!(msg.contains("<b>Healthcheck</b>"));
    }

    #[test]
    fn message_lists_every_section_and_run_url() {
        let d = Diff {
            new: ps(&[("channel:a", "FAIL: no exit")]),
            recovered: ps(&[("channel:b", "FAIL: no exit")]),
            escalated: ps(&[("node:beta:cert", "FAIL: expired")]),
        };
        let msg = format_message(&d, Some("https://example.com/run/1"));
        assert!(msg.contains("NEW"));
        assert!(msg.contains("WORSE"));
        assert!(msg.contains("RECOVERED"));
        assert!(msg.contains("https://example.com/run/1"));
    }
}
