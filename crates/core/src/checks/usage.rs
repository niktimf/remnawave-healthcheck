//! Whether a node lost users or traffic yesterday, read from the per-day
//! history the panel keeps. Yesterday is compared with the median of the
//! seven days before it, so one odd day in the baseline moves nothing.

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
#[cfg(test)]
mod tests {
    use super::*;
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
}
