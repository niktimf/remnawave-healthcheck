use crate::model::{CheckResult, Severity};
use std::fmt::Write;

/// Worst severity across the run; empty run is OK.
pub fn overall(results: &[CheckResult]) -> Severity {
    results
        .iter()
        .map(|r| r.severity)
        .max()
        .unwrap_or(Severity::Ok)
}

/// How a run ended, as the process reports it. The three numbers behind these variants are the
/// tool's contract with whatever runs it (a CI job reads them), which is why they live in one
/// place instead of being spelled out at every `return`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Everything that was looked at is fine. Warnings do not break the build.
    Ok,
    /// At least one check failed — or, in the test-alert mode, the message was not delivered.
    Failed,
    /// The run could not do its job at all: the panel was unreadable, or the tool was
    /// misconfigured.
    Aborted,
}

impl Outcome {
    /// The process exit status.
    pub fn code(self) -> u8 {
        match self {
            Outcome::Ok => 0,
            Outcome::Failed => 1,
            Outcome::Aborted => 2,
        }
    }
}

impl From<Outcome> for std::process::ExitCode {
    fn from(outcome: Outcome) -> Self {
        std::process::ExitCode::from(outcome.code())
    }
}

/// Non-zero only when something actually failed; warnings do not break the build.
pub fn outcome(results: &[CheckResult]) -> Outcome {
    if overall(results) == Severity::Fail {
        Outcome::Failed
    } else {
        Outcome::Ok
    }
}

/// Plain-text table, worst first. Written by hand so `core` stays dependency-light.
pub fn render(results: &[CheckResult]) -> String {
    let mut rows: Vec<&CheckResult> = results.iter().collect();
    rows.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.key.cmp(&b.key)));

    // Characters, not bytes: a title is a host remark rendered from a panel template, and those
    // carry Cyrillic and emoji. Padding by byte length would widen exactly the rows that contain
    // them and leave the table ragged.
    let key_w = column_width(rows.iter().map(|r| r.key.as_str()), 3);
    let title_w = column_width(rows.iter().map(|r| r.title.as_str()), 5);

    let mut out = String::new();
    for r in &rows {
        // Writing into a String cannot fail, and `writeln!` keeps each row out of an
        // intermediate allocation.
        let _ = writeln!(
            out,
            "{:<6} {:<kw$}  {:<tw$}  {}",
            r.severity,
            r.key,
            r.title,
            r.detail,
            kw = key_w,
            tw = title_w
        );
    }
    let _ = write!(out, "\nOVERALL: {}\n", overall(results));
    out
}

fn column_width<'a>(values: impl Iterator<Item = &'a str>, min: usize) -> usize {
    values
        .map(|v| v.chars().count())
        .max()
        .unwrap_or(0)
        .max(min)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CheckResult, Severity};

    fn results() -> Vec<CheckResult> {
        vec![
            CheckResult::new("node:beta:cert", "beta cert", Severity::Ok, "40d left"),
            CheckResult::new("channel:b", "b", Severity::Fail, "no exit"),
            CheckResult::new("channel:a", "a", Severity::Warn, "node disabled"),
        ]
    }

    #[test]
    fn overall_is_the_worst_severity() {
        assert_eq!(overall(&results()), Severity::Fail);
        assert_eq!(overall(&[]), Severity::Ok);
    }

    #[test]
    fn exit_code_is_one_only_on_fail() {
        assert_eq!(outcome(&results()), Outcome::Failed);
        assert_eq!(outcome(&results()).code(), 1);
        let warn_only = vec![CheckResult::new("k", "t", Severity::Warn, "d")];
        assert_eq!(outcome(&warn_only), Outcome::Ok);
        assert_eq!(outcome(&warn_only).code(), 0);
    }

    #[test]
    fn the_three_exit_codes_keep_their_numbers() {
        // Whatever runs this tool reads these; they are not free to drift.
        assert_eq!(Outcome::Ok.code(), 0);
        assert_eq!(Outcome::Failed.code(), 1);
        assert_eq!(Outcome::Aborted.code(), 2);
    }

    #[test]
    fn render_sorts_worst_first_then_by_key() {
        let out = render(&results());
        let fail_at = out.find("channel:b").unwrap();
        let warn_at = out.find("channel:a").unwrap();
        let ok_at = out.find("node:beta:cert").unwrap();
        assert!(fail_at < warn_at, "FAIL must come before WARN");
        assert!(warn_at < ok_at, "WARN must come before OK");
        assert!(out.contains("OVERALL: FAIL"));
    }

    #[test]
    fn a_row_starts_with_the_severity_in_its_own_column() {
        // The severity column is fixed-width; losing that padding reflows every row of the
        // report, and nothing above would notice.
        let out = render(&results());
        assert!(
            out.starts_with("FAIL   channel:b"),
            "unexpected first row: {out}"
        );
    }

    #[test]
    fn columns_are_measured_in_characters_not_bytes() {
        // Remarks come from a panel template and carry Cyrillic and emoji. Padding by byte
        // length would make those rows wider than the rest and leave the table ragged.
        let out = render(&[
            CheckResult::new(
                "k",
                "\u{41F}\u{440}\u{43E}\u{43A}\u{441}\u{438}",
                Severity::Ok,
                "x",
            ),
            CheckResult::new("k2", "ascii", Severity::Ok, "y"),
        ]);
        let detail_columns: Vec<usize> = out
            .lines()
            .filter(|l| l.ends_with('x') || l.ends_with('y'))
            .map(|l| l.chars().count())
            .collect();
        assert_eq!(detail_columns.len(), 2);
        assert_eq!(
            detail_columns[0], detail_columns[1],
            "both rows must be the same width: {out}"
        );
    }
}
