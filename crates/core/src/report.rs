//! One result set and the questions asked of it: how the run ended, and the
//! three renderings it goes out as — the stdout table, the GitHub job summary
//! (Markdown) and the Telegram message (HTML).

use crate::model::{CheckResult, Severity};
use std::fmt::Write;

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

pub const TELEGRAM_LIMIT: usize = 4096;

/// A finished run's results. Borrowing rather than owning keeps this free to
/// construct wherever the results are already in hand.
#[derive(Debug, Clone, Copy)]
pub struct Report<'a> {
    results: &'a [CheckResult],
}

impl<'a> Report<'a> {
    pub const fn of(results: &'a [CheckResult]) -> Self {
        Self { results }
    }

    /// The worst severity present; a run with no checks at all is OK.
    pub fn overall(&self) -> Severity {
        self.results
            .iter()
            .map(|r| r.severity)
            .max()
            .unwrap_or(Severity::Ok)
    }

    pub fn outcome(&self) -> Outcome {
        if self.overall() == Severity::Fail {
            Outcome::Failed
        } else {
            Outcome::Ok
        }
    }

    /// Worst first, then by name.
    fn sorted(&self) -> Vec<&CheckResult> {
        let mut rows: Vec<&CheckResult> = self.results.iter().collect();
        rows.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| a.name.cmp(&b.name))
        });
        rows
    }

    fn counts(&self) -> (usize, usize, usize) {
        let mut c = (0, 0, 0);
        for r in self.results {
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
    pub fn table(&self) -> String {
        let rows = self.sorted();
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
        let _ = writeln!(out, "OVERALL: {}", self.overall());
        out
    }

    /// The GitHub job summary: every row, so the run page tells the whole story.
    pub fn markdown(&self) -> String {
        let (fail, warn, ok) = self.counts();
        let mut out = format!(
            "## Healthcheck: {} — {fail} fail, {warn} warn, {ok} ok\n\n| Severity | Check | Detail |\n|---|---|---|\n",
            self.overall()
        );
        for r in self.sorted() {
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

    /// The Telegram message: a headline with counts, then only the WARN/FAIL
    /// rows (FAIL first), then the run URL. Cut to the API limit, never dropped.
    pub fn telegram(&self, run_url: Option<&str>) -> String {
        let headline = self.headline();
        let problems: Vec<String> = self
            .sorted()
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

    fn headline(&self) -> String {
        let worst = self.overall();
        if worst == Severity::Ok {
            return format!(
                "{} <b>Healthcheck: OK</b> — {} checks",
                icon(worst),
                self.results.len()
            );
        }
        let (fail, warn, ok) = self.counts();
        format!(
            "{} <b>Healthcheck: {worst}</b> — {fail} fail, {warn} warn, {ok} ok",
            icon(worst)
        )
    }
}

fn escape_markdown_cell(s: &str) -> String {
    s.replace('|', "\\|").replace(['\n', '\r'], " ")
}

/// Telegram's HTML parse mode treats these three specially; a stray `<` in xray
/// stderr would otherwise get the whole message rejected.
///
/// Free-standing on purpose: the tool also escapes text that never belonged to
/// a result set, such as the error that aborted a run.
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

const fn icon(severity: Severity) -> &'static str {
    match severity {
        Severity::Fail => "\u{1F534}",
        Severity::Warn => "\u{1F7E1}",
        Severity::Ok => "\u{2705}",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use rstest::rstest;

    fn results() -> Vec<CheckResult> {
        vec![
            CheckResult::ok("node beta / certificate expiry", "40d left"),
            CheckResult::fail("channel b (b.example.com:443)", "no exit"),
            CheckResult::warn("channel a (a.example.com:443)", "node disabled"),
        ]
    }

    #[test]
    fn one_failure_makes_the_whole_run_failed() {
        let results = results();
        let sut = Report::of(&results);

        let outcome = sut.outcome();

        assert_eq!(outcome, Outcome::Failed);
    }

    /// Warnings are things to look at, not things that should stop a pipeline.
    #[test]
    fn warnings_alone_leave_the_run_ok() {
        let results = [CheckResult::warn("k", "d")];
        let sut = Report::of(&results);

        let outcome = sut.outcome();

        assert_eq!(outcome, Outcome::Ok);
    }

    #[rstest]
    #[case::ok(Outcome::Ok, 0)]
    #[case::failed(Outcome::Failed, 1)]
    #[case::aborted(Outcome::Aborted, 2)]
    fn every_outcome_has_its_own_exit_code(
        #[case] sut: Outcome,
        #[case] expected: u8,
    ) {
        let code = sut.code();

        assert_eq!(code, expected);
    }

    #[test]
    fn the_table_is_worst_first() {
        let results = results();
        let sut = Report::of(&results);

        let table = sut.table();

        let lines: Vec<&str> = table.lines().collect();
        assert!(
            lines[0].starts_with("FAIL   channel b (b.example.com:443)"),
            "{table}"
        );
        assert!(
            lines[1].starts_with("WARN   channel a (a.example.com:443)"),
            "{table}"
        );
        assert!(lines[2].starts_with("OK     node beta"), "{table}");
        assert_eq!(lines.last(), Some(&"OVERALL: FAIL"));
    }

    /// Column widths are counted in characters, so a non-ASCII name lines up
    /// with an ASCII one instead of being padded by its byte length.
    #[test]
    fn columns_align_across_alphabets() {
        let results = [
            CheckResult::ok("k", "x"),
            CheckResult::ok(
                "\u{041f}\u{0440}\u{043e}\u{043a}\u{0441}\u{0438}",
                "y",
            ),
        ];
        let sut = Report::of(&results);

        let table = sut.table();

        let widths: Vec<usize> =
            table.lines().take(2).map(|l| l.chars().count()).collect();
        assert_eq!(widths[0], widths[1], "{table}");
    }

    #[test]
    fn markdown_escapes_pipes_and_newlines() {
        let results = [CheckResult::fail("a|b", "line1\nline2")];
        let sut = Report::of(&results);

        let markdown = sut.markdown();

        assert!(
            markdown.starts_with(
                "## Healthcheck: FAIL \u{2014} 1 fail, 0 warn, 0 ok\n"
            ),
            "{markdown}"
        );
        assert!(
            markdown.contains("| FAIL | a\\|b | line1 line2 |"),
            "{markdown}"
        );
    }

    #[test]
    fn telegram_text_for_a_failing_run_is_exact() {
        let results = results();
        let sut = Report::of(&results);

        let message = sut.telegram(Some("https://example.com/run/1"));

        assert_eq!(
            message,
            "\u{1F534} <b>Healthcheck: FAIL</b> \u{2014} 1 fail, 1 warn, 1 ok\n\
             \u{1F534} channel b (b.example.com:443) \u{2014} no exit\n\
             \u{1F7E1} channel a (a.example.com:443) \u{2014} node disabled\n\
             \nhttps://example.com/run/1"
        );
    }

    #[test]
    fn telegram_text_for_a_clean_run_is_one_line() {
        let results = [CheckResult::ok("a", "x"), CheckResult::ok("b", "y")];
        let sut = Report::of(&results);

        let message = sut.telegram(None);

        assert_eq!(
            message,
            "\u{2705} <b>Healthcheck: OK</b> \u{2014} 2 checks\n"
        );
    }

    #[test]
    fn html_in_names_and_details_is_escaped_but_the_template_is_not() {
        let results =
            [CheckResult::fail("channel <x>", "xray said <boom> & died")];
        let sut = Report::of(&results);

        let message = sut.telegram(None);

        assert!(message.contains("&lt;boom&gt; &amp; died"), "{message}");
        assert!(!message.contains("<x>"), "{message}");
        assert!(message.contains("<b>Healthcheck: FAIL</b>"), "{message}");
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
        let sut = Report::of(&many);

        let message = sut.telegram(Some("https://example.com/run/1"));

        assert!(
            message.chars().count() <= TELEGRAM_LIMIT,
            "{}",
            message.chars().count()
        );
        assert!(message.contains("\u{2026} and "), "{message}");
        assert!(message.ends_with("https://example.com/run/1"), "{message}");
    }
}
