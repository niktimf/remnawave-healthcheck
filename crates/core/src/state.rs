use crate::model::{CheckResult, Severity};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One non-OK check as the problem set remembers it. Severity stays a `Severity` rather than
/// being glued into the detail text: the diff compares severities, and re-parsing them out of a
/// rendered string is how a typo turns into a missed escalation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Problem {
    pub severity: Severity,
    pub detail: String,
}

/// Non-OK checks of one run, keyed by the stable check key. BTreeMap keeps output deterministic.
pub type ProblemSet = BTreeMap<String, Problem>;

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
                Problem {
                    severity: r.severity,
                    detail: r.detail.clone(),
                },
            )
        })
        .collect()
}

/// Appearing and disappearing keys always count. So does a severity escalation on a key that
/// was already a problem. Softening (FAIL -> WARN) is deliberately silent: the problem is still
/// there and re-alerting on it is noise.
pub fn diff(current: &ProblemSet, previous: &ProblemSet) -> Diff {
    Diff {
        new: select(current, |k, _| !previous.contains_key(k)),
        recovered: select(previous, |k, _| !current.contains_key(k)),
        escalated: select(current, |k, v| {
            previous.get(k).is_some_and(|p| v.severity > p.severity)
        }),
    }
}

/// The entries of `from` the predicate keeps. Owned, because a diff outlives the two sets it was
/// computed from.
fn select(from: &ProblemSet, keep: impl Fn(&str, &Problem) -> bool) -> ProblemSet {
    from.iter()
        .filter(|(k, v)| keep(k, v))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// Every variant is spelled out: a wildcard here would give a future severity a red circle
/// silently instead of failing to compile.
fn icon(severity: Severity) -> &'static str {
    match severity {
        Severity::Warn => "\u{1F7E1}",
        Severity::Ok | Severity::Fail => "\u{1F534}",
    }
}

/// Escape the characters Telegram's HTML parse mode treats specially. Public because every path
/// that puts text into an alert needs it, the out-of-band panel-failure alert included. A check's
/// own key or detail text (xray stderr, a panel status message) is not under our control and can
/// contain a stray `<` or bare `&`; unescaped, that either mangles the message's markup or makes Telegram reject
/// the whole alert with "can't parse entities" — losing the alert entirely, which is exactly the
/// failure this tool exists to prevent.
pub fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            other => out.push(other),
        }
    }
    out
}

/// One problem as it appears in an alert line. The severity label is ours and needs no escaping;
/// the detail is not (xray stderr, a panel status message) and does.
fn render_problem(p: &Problem) -> String {
    format!("{}: {}", p.severity, escape_html(&p.detail))
}

/// Telegram message body, HTML parse mode.
pub fn format_message(d: &Diff, run_url: Option<&str>) -> String {
    let mut lines = vec!["<b>Healthcheck</b>".to_string()];
    for (k, p) in &d.new {
        let mark = icon(p.severity);
        let (k, v) = (escape_html(k), render_problem(p));
        lines.push(format!("{mark} NEW  {k} — {v}"));
    }
    for (k, p) in &d.escalated {
        let (k, v) = (escape_html(k), render_problem(p));
        lines.push(format!("\u{1F53A} WORSE  {k} — {v}"));
    }
    for (k, p) in &d.recovered {
        let (k, v) = (escape_html(k), render_problem(p));
        lines.push(format!("\u{1F7E2} RECOVERED  {k} — {v}"));
    }
    if let Some(url) = run_url {
        lines.push(format!("\n{url}"));
    }
    lines.join("\n")
}

/// A problem set is a map of strings to two owned fields, so serialising it cannot fail for any
/// reason short of a bug in this crate. Swallowing an error here would write `{}` — an empty
/// problem set — and the next run would report every still-broken check as recovered.
pub fn to_json(state: &ProblemSet) -> String {
    serde_json::to_string_pretty(state).expect("a problem set always serialises")
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

    fn ps(entries: &[(&str, Severity, &str)]) -> ProblemSet {
        entries
            .iter()
            .map(|(k, severity, detail)| {
                (
                    k.to_string(),
                    Problem {
                        severity: *severity,
                        detail: detail.to_string(),
                    },
                )
            })
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
        assert_eq!(got["b"].severity, Severity::Warn);
        assert_eq!(got["b"].detail, "meh");
        assert_eq!(got["c"].severity, Severity::Fail);
        assert_eq!(got["c"].detail, "bad");
        // Rendered into an alert, a problem still reads exactly as it always did.
        assert_eq!(render_problem(&got["b"]), "WARN: meh");
        assert_eq!(render_problem(&got["c"]), "FAIL: bad");
    }

    #[test]
    fn diff_reports_new_recovered_and_escalated() {
        let previous = ps(&[("a", Severity::Warn, "x"), ("b", Severity::Fail, "y")]);
        let current = ps(&[("a", Severity::Fail, "x"), ("c", Severity::Fail, "z")]);
        let d = diff(&current, &previous);
        assert_eq!(d.new.keys().collect::<Vec<_>>(), vec!["c"]);
        assert_eq!(d.recovered.keys().collect::<Vec<_>>(), vec!["b"]);
        assert_eq!(d.escalated.keys().collect::<Vec<_>>(), vec!["a"]);
        assert!(!d.is_empty());
    }

    #[test]
    fn softening_from_fail_to_warn_is_silent() {
        let previous = ps(&[("a", Severity::Fail, "x")]);
        let current = ps(&[("a", Severity::Warn, "x")]);
        let d = diff(&current, &previous);
        assert!(d.is_empty(), "FAIL->WARN must not alert");
    }

    #[test]
    fn a_changed_detail_at_the_same_severity_is_silent() {
        // Only the severity decides an escalation; a reworded detail is not news.
        let previous = ps(&[("a", Severity::Fail, "no exit (tunnel dead)")]);
        let current = ps(&[("a", Severity::Fail, "no exit (tunnel dead) | xray: boom")]);
        assert!(diff(&current, &previous).is_empty());
    }

    #[test]
    fn unchanged_state_is_silent() {
        let s = ps(&[("a", Severity::Fail, "x")]);
        assert!(diff(&s, &s).is_empty());
    }

    #[test]
    fn json_roundtrip_and_tolerance_to_garbage() {
        let s = ps(&[("a", Severity::Fail, "x")]);
        assert_eq!(from_json(&to_json(&s)), s);
        assert!(from_json("not json at all").is_empty());
        assert!(from_json("[1,2,3]").is_empty());
    }

    #[test]
    fn the_state_file_is_a_map_of_key_to_severity_and_detail() {
        let s = ps(&[("channel:a", Severity::Warn, "slow")]);
        let raw = to_json(&s);
        let parsed: serde_json::Value = serde_json::from_str(&raw).expect("state file is JSON");
        assert_eq!(parsed["channel:a"]["severity"], "WARN");
        assert_eq!(parsed["channel:a"]["detail"], "slow");
    }

    #[test]
    fn a_state_file_with_an_unreadable_entry_is_treated_as_no_previous_run() {
        // Half a problem set is not a problem set: silently keeping the readable half would make
        // the missing keys look recovered.
        assert!(from_json(r#"{"channel:a": {"severity": "Nope", "detail": "x"}}"#).is_empty());
        assert!(from_json(r#"{"channel:a": "FAIL: x"}"#).is_empty());
    }

    #[test]
    fn html_special_characters_in_keys_and_values_are_escaped() {
        let d = Diff {
            new: ps(&[(
                "channel:<script>",
                Severity::Fail,
                "xray said <boom> & died",
            )]),
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
            new: ps(&[("channel:a", Severity::Fail, "no exit")]),
            recovered: ps(&[("channel:b", Severity::Fail, "no exit")]),
            escalated: ps(&[("node:beta:cert", Severity::Fail, "expired")]),
        };
        let msg = format_message(&d, Some("https://example.com/run/1"));
        assert!(msg.contains("NEW"));
        assert!(msg.contains("WORSE"));
        assert!(msg.contains("RECOVERED"));
        assert!(msg.contains("https://example.com/run/1"));
    }

    #[test]
    fn alert_lines_keep_their_exact_wording() {
        // These lines are the tool's user-facing output; the refactor must not reflow them.
        let d = Diff {
            new: ps(&[("channel:a", Severity::Warn, "slow")]),
            recovered: ps(&[("channel:c", Severity::Fail, "no exit")]),
            escalated: ps(&[("channel:b", Severity::Fail, "no exit")]),
        };
        assert_eq!(
            format_message(&d, None),
            "<b>Healthcheck</b>\n\u{1F7E1} NEW  channel:a \u{2014} WARN: slow\n\u{1F53A} WORSE  channel:b \u{2014} FAIL: no exit\n\u{1F7E2} RECOVERED  channel:c \u{2014} FAIL: no exit"
        );
    }
}
