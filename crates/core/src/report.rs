use crate::model::{CheckResult, Severity};

/// Worst severity across the run; empty run is OK.
pub fn overall(results: &[CheckResult]) -> Severity {
    results
        .iter()
        .map(|r| r.severity)
        .max()
        .unwrap_or(Severity::Ok)
}

/// Non-zero only when something actually failed; warnings do not break the build.
pub fn exit_code(results: &[CheckResult]) -> i32 {
    if overall(results) == Severity::Fail {
        1
    } else {
        0
    }
}

/// Plain-text table, worst first. Written by hand so `core` stays dependency-light.
pub fn render(results: &[CheckResult]) -> String {
    let mut rows: Vec<&CheckResult> = results.iter().collect();
    rows.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.key.cmp(&b.key)));

    let key_w = rows.iter().map(|r| r.key.len()).max().unwrap_or(0).max(3);
    let title_w = rows.iter().map(|r| r.title.len()).max().unwrap_or(0).max(5);

    let mut out = String::new();
    for r in &rows {
        out.push_str(&format!(
            "{:<6} {:<kw$}  {:<tw$}  {}\n",
            r.severity.label(),
            r.key,
            r.title,
            r.detail,
            kw = key_w,
            tw = title_w
        ));
    }
    out.push_str(&format!("\nOVERALL: {}\n", overall(results).label()));
    out
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
        assert_eq!(exit_code(&results()), 1);
        let warn_only = vec![CheckResult::new("k", "t", Severity::Warn, "d")];
        assert_eq!(exit_code(&warn_only), 0);
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
}
