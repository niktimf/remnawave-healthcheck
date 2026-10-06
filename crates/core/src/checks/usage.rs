//! Whether a node lost users or traffic yesterday, read from the per-day
//! history the panel keeps. Yesterday is compared with the median of the
//! seven days before it, so one odd day in the baseline moves nothing.

use super::size;
use crate::model::{CheckResult, Node, Snapshot, node_check};
use chrono::{Days, NaiveDate};
use std::collections::{BTreeMap, HashMap};

/// The share of the usual that yesterday may fall to before it counts as a
/// drop: above 0, at most 1.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DropRatio(f64);

/// A share outside (0, 1], or not a number.
#[derive(Debug, Clone, Copy, PartialEq, thiserror::Error)]
#[error("{0} is not above 0 and at most 1")]
pub struct NotARatio(pub f64);

impl TryFrom<f64> for DropRatio {
    type Error = NotARatio;

    fn try_from(value: f64) -> Result<Self, Self::Error> {
        // Written so NaN fails both comparisons and is refused.
        if value > 0.0 && value <= 1.0 {
            Ok(Self(value))
        } else {
            Err(NotARatio(value))
        }
    }
}

impl DropRatio {
    // Day counts and byte totals far inside what an f64 holds exactly.
    #[allow(clippy::cast_precision_loss)]
    fn falls_below(self, yesterday: u64, median: u64) -> bool {
        (yesterday as f64) < (median as f64) * self.0
    }
}

impl std::fmt::Display for DropRatio {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:.0}%", self.0 * 100.0)
    }
}

/// How many of the seven baseline days must carry a number for their
/// median to be a baseline at all.
const MIN_DAYS_WITH_DATA: usize = 4;

/// What one compared number says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reading {
    Usual,
    Dropped,
    /// Fewer than four of the seven days carry a number: a node added this
    /// week, or one the panel has no history for.
    BaselineTooShort,
    /// The usual is below the minimum worth judging: a node with too few
    /// users for a drop in them to mean anything.
    BaselineTooSmall,
}

/// The thresholds one number is judged by.
#[derive(Debug, Clone, Copy)]
pub struct Rule {
    pub ratio: DropRatio,
    pub minimum: u64,
}

/// Yesterday against the median of the seven days before it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Trend {
    pub yesterday: u64,
    pub median: u64,
    pub reading: Reading,
}

impl Trend {
    /// `base` holds the seven days before yesterday. A day the panel has no
    /// number for is 0, and the panel itself writes 0 for a day it recorded
    /// nothing on, so a zero is a day without data.
    pub fn of(base: [u64; 7], yesterday: u64, rule: Rule) -> Self {
        let mut sorted = base;
        sorted.sort_unstable();
        let median = sorted[3];
        let with_data = base.iter().filter(|&&day| day > 0).count();
        let reading = if with_data < MIN_DAYS_WITH_DATA {
            Reading::BaselineTooShort
        } else if median < rule.minimum {
            Reading::BaselineTooSmall
        } else if rule.ratio.falls_below(yesterday, median) {
            Reading::Dropped
        } else {
            Reading::Usual
        };
        Self {
            yesterday,
            median,
            reading,
        }
    }
}

/// One node's numbers for one day, as the panel stores them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Day {
    pub bytes: u64,
    /// Users over the per-user threshold on this node that day.
    pub users: u64,
}

/// The panel's per-day history over the window asked for.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UsageHistory {
    /// The days the panel split the window into, as it returned them.
    pub dates: Vec<NaiveDate>,
    /// By node uuid, then by day. A node or a day the panel said nothing
    /// about has no entry.
    pub days: HashMap<String, BTreeMap<NaiveDate, Day>>,
}

impl UsageHistory {
    fn day(&self, node_uuid: &str, date: Option<NaiveDate>) -> Day {
        date.and_then(|date| self.days.get(node_uuid)?.get(&date).copied())
            .unwrap_or_default()
    }

    /// The last day before `today` the panel returned: today itself is
    /// still being counted.
    fn yesterday(&self, today: NaiveDate) -> Option<NaiveDate> {
        self.dates
            .iter()
            .copied()
            .filter(|date| *date < today)
            .max()
    }
}

/// What the usage stage ended with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsageOutcome {
    /// Switched off with `--no-usage`.
    Disabled,
    /// The history could not be read: a token without the scope, a panel
    /// that did not answer.
    Failed(String),
    Read(UsageHistory),
}

/// The thresholds a node's day is judged by.
#[derive(Debug, Clone, Copy)]
pub struct UsageChecker {
    pub drop_ratio: DropRatio,
    pub min_users: u64,
    pub min_bytes: u64,
}

/// The one row that stands in for every node when there is nothing per
/// node to say.
const HISTORY: &str = "panel / usage history";

impl UsageChecker {
    /// One `usage trend` row per enabled node, or one `panel / usage
    /// history` row when the history was not read.
    pub fn all(
        self,
        snapshot: &Snapshot,
        today: NaiveDate,
        outcome: &UsageOutcome,
    ) -> Vec<CheckResult> {
        let history = match outcome {
            UsageOutcome::Disabled => {
                return vec![CheckResult::ok(
                    HISTORY,
                    "disabled by --no-usage",
                )];
            }
            UsageOutcome::Failed(why) => {
                return vec![CheckResult::warn(
                    HISTORY,
                    format!("not read: {why}"),
                )];
            }
            UsageOutcome::Read(history) => history,
        };
        let nodes: Vec<&Node> =
            snapshot.nodes.iter().filter(|n| n.is_enabled()).collect();
        if nodes.is_empty() {
            return Vec::new();
        }
        let Some(yesterday) = history.yesterday(today) else {
            return vec![CheckResult::warn(
                HISTORY,
                format!("not read: the panel returned no day before {today}"),
            )];
        };
        nodes
            .into_iter()
            .map(|node| {
                let users = is_entry(node, snapshot);
                let compared =
                    self.compare(history, &node.uuid, yesterday, users);
                compared.verdict(&node.name, self.drop_ratio)
            })
            .collect()
    }

    fn compare(
        self,
        history: &UsageHistory,
        node_uuid: &str,
        yesterday: NaiveDate,
        users: bool,
    ) -> Compared {
        let base: [Day; 7] = std::array::from_fn(|i| {
            let back = Days::new(7 - i as u64);
            history.day(node_uuid, yesterday.checked_sub_days(back))
        });
        let last = history.day(node_uuid, Some(yesterday));
        let trend = |pick: fn(&Day) -> u64, minimum| {
            let rule = Rule {
                ratio: self.drop_ratio,
                minimum,
            };
            Trend::of(base.each_ref().map(pick), pick(&last), rule)
        };
        Compared {
            users: users.then(|| trend(|d| d.users, self.min_users)),
            bytes: trend(|d| d.bytes, self.min_bytes),
        }
    }
}

/// A node a channel of the subscription enters: its users connect to it and
/// can be counted there. A node only a cascade enters sees bridges, not
/// users, so only its traffic is compared.
fn is_entry(node: &Node, snapshot: &Snapshot) -> bool {
    snapshot.channels.iter().any(|channel| {
        channel.profile_uuid.is_some()
            && channel.profile_uuid == node.profile_uuid
            && node.inbound_tags.contains(&channel.inbound_tag)
    })
}

/// The numbers compared for one node.
struct Compared {
    users: Option<Trend>,
    bytes: Trend,
}

impl Compared {
    fn verdict(&self, node: &str, ratio: DropRatio) -> CheckResult {
        let name = node_check(node, "usage trend");
        let numbers = self.numbers();
        let dropped: Vec<&str> = self
            .labelled()
            .filter(|(_, trend)| trend.reading == Reading::Dropped)
            .map(|(label, _)| label)
            .collect();
        let notes: Vec<String> = self
            .labelled()
            .filter_map(|(label, trend)| match trend.reading {
                Reading::BaselineTooShort => {
                    Some(format!("{label}: baseline too short"))
                }
                Reading::BaselineTooSmall => {
                    Some(format!("{label}: baseline too small"))
                }
                Reading::Usual | Reading::Dropped => None,
            })
            .collect();
        let detail = std::iter::once(numbers).chain(notes).collect::<Vec<_>>();
        if dropped.is_empty() {
            CheckResult::ok(name, detail.join("; "))
        } else {
            CheckResult::warn(
                name,
                format!(
                    "{} below {ratio} of usual: {}",
                    dropped.join(" and "),
                    detail.join("; ")
                ),
            )
        }
    }

    fn labelled(&self) -> impl Iterator<Item = (&'static str, &Trend)> {
        self.users
            .iter()
            .map(|trend| ("users", trend))
            .chain(std::iter::once(("traffic", &self.bytes)))
    }

    fn numbers(&self) -> String {
        let bytes = &self.bytes;
        match &self.users {
            Some(users) => format!(
                "yesterday {} users / {}, usual {} / {}",
                users.yesterday,
                size(bytes.yesterday),
                users.median,
                size(bytes.median)
            ),
            None => format!(
                "yesterday {}, usual {}",
                size(bytes.yesterday),
                size(bytes.median)
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Channel, Severity};
    use pretty_assertions::assert_eq;
    use rstest::rstest;

    fn rule() -> Rule {
        Rule {
            ratio: DropRatio::try_from(0.5).unwrap(),
            minimum: 10,
        }
    }

    #[rstest]
    #[case::usual_day([40, 42, 38, 41, 39, 40, 43], 37, 40, Reading::Usual)]
    #[case::half_is_not_below_half(
        [40, 42, 38, 41, 39, 40, 43], 20, 40, Reading::Usual
    )]
    #[case::dropped([40, 42, 38, 41, 39, 40, 43], 15, 40, Reading::Dropped)]
    #[case::nobody_yesterday(
        [40, 42, 38, 41, 39, 40, 43], 0, 40, Reading::Dropped
    )]
    #[case::small_baseline(
        [3, 4, 2, 5, 3, 4, 3], 0, 3, Reading::BaselineTooSmall
    )]
    #[case::three_days_of_data(
        [0, 0, 0, 0, 40, 41, 42], 5, 0, Reading::BaselineTooShort
    )]
    #[case::four_days_of_data(
        [0, 0, 0, 40, 41, 42, 43], 30, 40, Reading::Usual
    )]
    fn yesterday_is_read_against_the_median_of_the_week_before(
        #[case] base: [u64; 7],
        #[case] yesterday: u64,
        #[case] median: u64,
        #[case] reading: Reading,
    ) {
        let trend = Trend::of(base, yesterday, rule());

        assert_eq!(
            trend,
            Trend {
                yesterday,
                median,
                reading
            }
        );
    }

    /// The median, not the mean: one spike in the week does not make an
    /// ordinary day look like a drop.
    #[test]
    fn one_spike_in_the_baseline_does_not_raise_the_usual() {
        let base = [40, 42, 38, 900, 39, 40, 43];

        let trend = Trend::of(base, 30, rule());

        assert_eq!((trend.median, trend.reading), (40, Reading::Usual));
    }

    #[rstest]
    #[case::half(0.5, Ok("50%"))]
    #[case::all(1.0, Ok("100%"))]
    #[case::zero(0.0, Err(()))]
    #[case::above_one(1.5, Err(()))]
    #[case::not_a_number(f64::NAN, Err(()))]
    fn a_drop_ratio_is_above_zero_and_at_most_one(
        #[case] value: f64,
        #[case] expected: Result<&str, ()>,
    ) {
        let ratio = DropRatio::try_from(value);

        let got = ratio.map(|r| r.to_string()).map_err(|_| ());
        assert_eq!(got, expected.map(str::to_string));
    }

    const GIB: u64 = 1024 * 1024 * 1024;

    fn today() -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 10, 6).unwrap()
    }

    fn checker() -> UsageChecker {
        UsageChecker {
            drop_ratio: DropRatio::try_from(0.5).unwrap(),
            min_users: 10,
            min_bytes: GIB,
        }
    }

    fn node(name: &str, tag: &str) -> Node {
        Node {
            uuid: format!("uuid-{name}"),
            name: name.into(),
            is_connected: true,
            profile_uuid: Some("p".into()),
            inbound_tags: vec![tag.into()],
            ..Default::default()
        }
    }

    /// `node-a` is entered by the subscription's one channel; `exit-a` only
    /// by a cascade, so it has no channel of its own.
    fn snapshot() -> Snapshot {
        Snapshot {
            nodes: vec![node("node-a", "in-a"), node("exit-a", "in-exit")],
            channels: vec![Channel {
                remark: "node-a direct".into(),
                inbound_tag: "in-a".into(),
                profile_uuid: Some("p".into()),
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    /// One node's `(users, GiB)` per day, oldest first, the last on `last`.
    fn history(
        node: &str,
        last: NaiveDate,
        days: &[(u64, u64)],
    ) -> UsageHistory {
        let first = last - Days::new(days.len() as u64 - 1);
        let dates: Vec<NaiveDate> =
            first.iter_days().take(days.len()).collect();
        let series = dates
            .iter()
            .zip(days)
            .map(|(date, &(users, gib))| {
                (
                    *date,
                    Day {
                        bytes: gib * GIB,
                        users,
                    },
                )
            })
            .collect();
        UsageHistory {
            dates,
            days: HashMap::from([(format!("uuid-{node}"), series)]),
        }
    }

    /// Nine days ending today.
    fn nine_days(node: &str, days: [(u64, u64); 9]) -> UsageHistory {
        history(node, today(), &days)
    }

    fn row(results: &[CheckResult], node: &str) -> (Severity, String) {
        let name = format!("node {node} / usage trend");
        let row = results.iter().find(|r| r.name == name).unwrap();
        (row.severity, row.detail.clone())
    }

    const USUAL_WEEK: [(u64, u64); 7] = [
        (40, 110),
        (41, 108),
        (39, 112),
        (40, 110),
        (42, 111),
        (38, 109),
        (40, 110),
    ];

    fn week_then(yesterday: (u64, u64), today: (u64, u64)) -> [(u64, u64); 9] {
        let mut days = [(0, 0); 9];
        days[..7].copy_from_slice(&USUAL_WEEK);
        days[7] = yesterday;
        days[8] = today;
        days
    }

    #[test]
    fn an_ordinary_day_on_an_entry_node_is_ok_with_its_numbers() {
        let outcome = UsageOutcome::Read(nine_days(
            "node-a",
            week_then((38, 105), (3, 4)),
        ));

        let results = checker().all(&snapshot(), today(), &outcome);

        assert_eq!(
            row(&results, "node-a"),
            (
                Severity::Ok,
                "yesterday 38 users / 105 GB, usual 40 / 110 GB".to_string()
            )
        );
    }

    /// Users stopped reaching the node while those still connected used as
    /// much as ever: traffic alone would not show it.
    #[test]
    fn users_falling_away_on_flat_traffic_warn() {
        let outcome = UsageOutcome::Read(nine_days(
            "node-a",
            week_then((15, 108), (2, 9)),
        ));

        let results = checker().all(&snapshot(), today(), &outcome);

        assert_eq!(
            row(&results, "node-a"),
            (
                Severity::Warn,
                "users below 50% of usual: yesterday 15 users / 108 GB, usual 40 / 110 GB"
                    .to_string()
            )
        );
    }

    #[test]
    fn a_node_only_a_cascade_enters_is_judged_by_traffic_alone() {
        let outcome = UsageOutcome::Read(nine_days(
            "exit-a",
            week_then((40, 30), (5, 5)),
        ));

        let results = checker().all(&snapshot(), today(), &outcome);

        assert_eq!(
            row(&results, "exit-a"),
            (
                Severity::Warn,
                "traffic below 50% of usual: yesterday 30 GB, usual 110 GB"
                    .to_string()
            )
        );
    }

    /// The panel leaves a node with no traffic in the window out of its
    /// series altogether: no history is not a drop.
    #[test]
    fn a_node_absent_from_the_history_has_too_short_a_baseline() {
        let outcome = UsageOutcome::Read(nine_days(
            "node-a",
            week_then((38, 105), (3, 4)),
        ));

        let results = checker().all(&snapshot(), today(), &outcome);

        assert_eq!(
            row(&results, "exit-a"),
            (
                Severity::Ok,
                "yesterday 0 KB, usual 0 KB; traffic: baseline too short"
                    .to_string()
            )
        );
    }

    /// Five days of history leave three in the baseline.
    #[test]
    fn a_window_shorter_than_nine_days_has_too_short_a_baseline() {
        let days = week_then((5, 10), (1, 1));
        let short = history("node-a", today(), &days[4..]);

        let results =
            checker().all(&snapshot(), today(), &UsageOutcome::Read(short));

        assert_eq!(
            row(&results, "node-a"),
            (
                Severity::Ok,
                "yesterday 5 users / 10 GB, usual 0 / 0 KB; users: baseline too short; traffic: baseline too short"
                    .to_string()
            )
        );
    }

    /// A window that ends yesterday: the last day returned is yesterday,
    /// not the day before it.
    #[test]
    fn a_window_without_today_still_reads_yesterday() {
        let days = week_then((38, 105), (3, 4));
        let yesterday = today() - Days::new(1);
        let window = history("node-a", yesterday, &days[..8]);

        let results =
            checker().all(&snapshot(), today(), &UsageOutcome::Read(window));

        assert_eq!(
            row(&results, "node-a").1,
            "yesterday 38 users / 105 GB, usual 40 / 110 GB"
        );
    }

    #[test]
    fn a_window_with_no_day_before_today_is_one_warning() {
        let only_today = history("node-a", today(), &[(3, 4)]);

        let results = checker().all(
            &snapshot(),
            today(),
            &UsageOutcome::Read(only_today),
        );

        assert_eq!(
            results,
            [CheckResult::warn(
                "panel / usage history",
                "not read: the panel returned no day before 2026-10-06"
            )]
        );
    }

    #[rstest]
    #[case::disabled(
        UsageOutcome::Disabled,
        CheckResult::ok("panel / usage history", "disabled by --no-usage")
    )]
    #[case::refused(
        UsageOutcome::Failed(
            "GET /api/bandwidth-stats/nodes returned 403 Forbidden".into()
        ),
        CheckResult::warn(
            "panel / usage history",
            "not read: GET /api/bandwidth-stats/nodes returned 403 Forbidden"
        )
    )]
    fn without_a_history_one_row_says_why(
        #[case] outcome: UsageOutcome,
        #[case] expected: CheckResult,
    ) {
        let results = checker().all(&snapshot(), today(), &outcome);

        assert_eq!(results, [expected]);
    }

    #[test]
    fn a_disabled_node_has_no_trend() {
        let mut s = snapshot();
        s.nodes[1].is_disabled = true;
        let outcome = UsageOutcome::Read(nine_days(
            "node-a",
            week_then((38, 105), (3, 4)),
        ));

        let results = checker().all(&s, today(), &outcome);

        assert!(
            results
                .iter()
                .all(|r| r.name != "node exit-a / usage trend"),
            "{results:?}"
        );
    }
}
