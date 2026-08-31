//! Three renderings of one result set: the stdout table, the GitHub job
//! summary (Markdown) and the Telegram message (HTML). Plus the exit outcome.

use crate::model::{CheckResult, Severity};
use std::fmt::Write;

pub fn overall(results: &[CheckResult]) -> Severity {
    results
        .iter()
        .map(|r| r.severity)
        .max()
        .unwrap_or(Severity::Ok)
}

/// How a run ended, as the process reports it. The numbers are the contract
/// with whatever runs the tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// No FAIL. Warnings do not break the build.
    Ok,
    /// At least one check failed.
    Failed,
    /// The run could not do its job: configuration, unreadable panel,
    /// undelivered report.
    Aborted,
}

impl Outcome {
    pub fn of(results: &[CheckResult]) -> Self {
        if overall(results) == Severity::Fail {
            Self::Failed
        } else {
            Self::Ok
        }
    }

    pub const fn code(self) -> u8 {
        match self {
            Self::Ok => 0,
            Self::Failed => 1,
            Self::Aborted => 2,
        }
    }
}

impl From<Outcome> for std::process::ExitCode {
    fn from(outcome: Outcome) -> Self {
        Self::from(outcome.code())
    }
}

/// Worst first, then by name.
pub fn sorted(results: &[CheckResult]) -> Vec<&CheckResult> {
    let mut rows: Vec<&CheckResult> = results.iter().collect();
    rows.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.name.cmp(&b.name))
    });
    rows
}

fn counts(results: &[CheckResult]) -> (usize, usize, usize) {
    let mut c = (0, 0, 0);
    for r in results {
        match r.severity {
            Severity::Fail => c.0 += 1,
            Severity::Warn => c.1 += 1,
            Severity::Ok => c.2 += 1,
        }
    }
    c
}

/// Plain-text table. Widths are measured in characters: remarks carry
/// Cyrillic and emoji, and byte widths would leave the table ragged.
pub fn render_table(results: &[CheckResult]) -> String {
    let rows = sorted(results);
    let name_w = rows
        .iter()
        .map(|r| r.name.chars().count())
        .max()
        .unwrap_or(0)
        .max(5);
    let mut out = String::new();
    for r in &rows {
        let _ = writeln!(
            out,
            "{:<6} {:<nw$}  {}",
            r.severity,
            r.name,
            r.detail,
            nw = name_w
        );
    }
    out.push('\n');
    let _ = writeln!(out, "OVERALL: {}", overall(results));
    out
}

fn escape_markdown_cell(s: &str) -> String {
    s.replace('|', "\\|").replace(['\n', '\r'], " ")
}

/// The GitHub job summary: every row, so the run page tells the whole story.
pub fn render_markdown(results: &[CheckResult]) -> String {
    let (fail, warn, ok) = counts(results);
    let mut out = format!(
        "## Healthcheck: {} — {fail} fail, {warn} warn, {ok} ok\n\n| Severity | Check | Detail |\n|---|---|---|\n",
        overall(results)
    );
    for r in sorted(results) {
        let _ = writeln!(
            out,
            "| {} | {} | {} |",
            r.severity,
            escape_markdown_cell(&r.name),
            escape_markdown_cell(&r.detail)
        );
    }
    out
}

/// Telegram's HTML parse mode treats these three specially; a stray `<` in xray
/// stderr would otherwise get the whole message rejected.
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

pub const TELEGRAM_LIMIT: usize = 4096;

const fn icon(severity: Severity) -> &'static str {
    match severity {
        Severity::Fail => "\u{1F534}",
        Severity::Warn => "\u{1F7E1}",
        Severity::Ok => "\u{2705}",
    }
}

/// The Telegram message: a headline with counts, then only the WARN/FAIL
/// rows (FAIL first), then the run URL. Cut to the API limit, never dropped.
pub fn render_telegram(
    results: &[CheckResult],
    run_url: Option<&str>,
) -> String {
    let worst = overall(results);
    let (fail, warn, ok) = counts(results);
    let headline = if worst == Severity::Ok {
        format!(
            "{} <b>Healthcheck: OK</b> — {} checks",
            icon(worst),
            results.len()
        )
    } else {
        format!(
            "{} <b>Healthcheck: {worst}</b> — {fail} fail, {warn} warn, {ok} ok",
            icon(worst)
        )
    };
    let problems: Vec<String> = sorted(results)
        .into_iter()
        .filter(|r| !r.severity.is_ok())
        .map(|r| {
            format!(
                "{} {} — {}",
                icon(r.severity),
                escape_html(&r.name),
                escape_html(&r.detail)
            )
        })
        .collect();
    let footer = run_url.map(|u| format!("\n{u}")).unwrap_or_default();

    let assemble = |lines: &[String], dropped: usize| {
        let mut text = headline.clone();
        for l in lines {
            text.push('\n');
            text.push_str(l);
        }
        if dropped > 0 {
            let _ = write!(text, "\n… and {dropped} more");
        }
        text.push('\n');
        text.push_str(&footer);
        text
    };

    let mut keep = problems.len();
    loop {
        let text = assemble(&problems[..keep], problems.len() - keep);
        if text.chars().count() <= TELEGRAM_LIMIT || keep == 0 {
            return text;
        }
        keep -= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn results() -> Vec<CheckResult> {
        vec![
            CheckResult::ok("node beta / certificate expiry", "40d left"),
            CheckResult::fail("channel b (b.example.com:443)", "no exit"),
            CheckResult::warn("channel a (a.example.com:443)", "node disabled"),
        ]
    }

    #[test]
    fn outcome_follows_the_worst_severity_and_keeps_its_numbers() {
        assert_eq!(Outcome::of(&results()), Outcome::Failed);
        assert_eq!(Outcome::of(&[CheckResult::warn("k", "d")]), Outcome::Ok);
        assert_eq!(
            (
                Outcome::Ok.code(),
                Outcome::Failed.code(),
                Outcome::Aborted.code()
            ),
            (0, 1, 2)
        );
    }

    #[test]
    fn the_table_is_worst_first_with_aligned_columns() {
        let out = render_table(&results());
        let lines: Vec<&str> = out.lines().collect();
        assert!(
            lines[0].starts_with("FAIL   channel b (b.example.com:443)"),
            "{out}"
        );
        assert!(
            lines[1].starts_with("WARN   channel a (a.example.com:443)"),
            "{out}"
        );
        assert!(lines[2].starts_with("OK     node beta"), "{out}");
        assert_eq!(lines.last(), Some(&"OVERALL: FAIL"));
        let table = render_table(&[
            CheckResult::ok("k", "x"),
            CheckResult::ok("Прокси", "y"),
        ]);
        let widths: Vec<usize> =
            table.lines().take(2).map(|l| l.chars().count()).collect();
        assert_eq!(widths[0], widths[1], "{table}");
    }

    #[test]
    fn markdown_escapes_pipes_and_newlines() {
        let out = render_markdown(&[CheckResult::fail("a|b", "line1\nline2")]);
        assert!(
            out.starts_with("## Healthcheck: FAIL — 1 fail, 0 warn, 0 ok\n"),
            "{out}"
        );
        assert!(out.contains("| FAIL | a\\|b | line1 line2 |"), "{out}");
    }

    #[test]
    fn telegram_text_for_a_failing_run_is_exact() {
        let msg =
            render_telegram(&results(), Some("https://example.com/run/1"));
        assert_eq!(
            msg,
            "\u{1F534} <b>Healthcheck: FAIL</b> — 1 fail, 1 warn, 1 ok\n\
             \u{1F534} channel b (b.example.com:443) — no exit\n\
             \u{1F7E1} channel a (a.example.com:443) — node disabled\n\
             \nhttps://example.com/run/1"
        );
    }

    #[test]
    fn telegram_text_for_a_clean_run_is_one_line() {
        let msg = render_telegram(
            &[CheckResult::ok("a", "x"), CheckResult::ok("b", "y")],
            None,
        );
        assert_eq!(msg, "\u{2705} <b>Healthcheck: OK</b> — 2 checks\n");
    }

    #[test]
    fn html_in_names_and_details_is_escaped_but_the_template_is_not() {
        let msg = render_telegram(
            &[CheckResult::fail("channel <x>", "xray said <boom> & died")],
            None,
        );
        assert!(msg.contains("&lt;boom&gt; &amp; died"), "{msg}");
        assert!(!msg.contains("<x>"), "{msg}");
        assert!(msg.contains("<b>Healthcheck: FAIL</b>"), "{msg}");
    }

    #[test]
    fn a_message_over_the_limit_is_cut_with_a_count_not_dropped() {
        let many: Vec<CheckResult> = (0..200)
            .map(|i| {
                CheckResult::fail(
                    format!("channel {i:03} (x.example.com:443)"),
                    "x".repeat(40),
                )
            })
            .collect();
        let msg = render_telegram(&many, Some("https://example.com/run/1"));
        assert!(
            msg.chars().count() <= TELEGRAM_LIMIT,
            "{}",
            msg.chars().count()
        );
        assert!(msg.contains("… and "), "{msg}");
        assert!(msg.ends_with("https://example.com/run/1"), "{msg}");
    }
}
