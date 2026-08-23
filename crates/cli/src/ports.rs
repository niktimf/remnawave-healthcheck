use anyhow::{ensure, Result};
use std::num::NonZeroU16;

/// The local SOCKS ports one batch of channel probes may use: a base port and a count, proven
/// when this is built to fit under the last TCP port.
///
/// The proof has to live in a value, not in a check somewhere earlier. Two channels handed the
/// same port would have the second xray fail to bind, and that channel would be reported as "no
/// exit (tunnel dead)" — pointing the reader at the tunnel instead of at the flags that clash.
/// Since a port can only be had by asking this type for one, nothing downstream has to re-derive
/// whether `base + n` is still a port, and nothing has to fall back to saturating arithmetic that
/// would hand out a duplicate rather than admit the sum did not fit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocksPorts {
    base: u16,
    count: NonZeroU16,
}

impl SocksPorts {
    /// The one place a bad combination of `--socks-base-port` and `--concurrency` is refused.
    ///
    /// Zero is not an answer to "how many channels at once": the smallest batch there is holds
    /// one, and a run that probes nothing is not what the flag asks for.
    pub fn new(base: u16, concurrency: usize) -> Result<Self> {
        let count = u16::try_from(concurrency.max(1))
            .ok()
            .and_then(NonZeroU16::new)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "--concurrency {concurrency} asks for more channels at once than there are ports"
                )
            })?;
        // Both operands are `u16`, so this sum cannot overflow a `u32` and needs no saturating.
        let highest = u32::from(base) + u32::from(count.get()) - 1;
        ensure!(
            u16::try_from(highest).is_ok(),
            "--socks-base-port {base} plus --concurrency {concurrency} would need a port above 65535 ({highest}); lower one of them"
        );
        Ok(Self { base, count })
    }

    /// How many channels may be probed at once — the size of one batch.
    pub fn concurrency(self) -> usize {
        usize::from(self.count.get())
    }

    /// One port per slot in a batch, in order. Zipping a batch against this cannot run out of
    /// either side: the batch is cut to `concurrency()`, which is how many ports there are.
    pub fn iter(self) -> impl Iterator<Item = u16> {
        let (base, count) = (self.base, self.count.get());
        (0..count).map(move |offset| base + offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_range_that_fits_under_the_last_port_is_accepted() {
        let ports = SocksPorts::new(60000, 100).unwrap();
        assert_eq!(ports.concurrency(), 100);
        assert_eq!(ports.iter().next(), Some(60000));
        assert_eq!(ports.iter().last(), Some(60099));
        assert_eq!(ports.iter().count(), 100);
    }

    #[test]
    fn a_range_overflowing_the_last_port_is_refused() {
        let err = SocksPorts::new(65530, 100).unwrap_err();
        assert!(err.to_string().contains("65535"), "{err}");
        // More slots than there are ports at all, whatever the base.
        assert!(SocksPorts::new(0, 100_000).is_err());
    }

    #[test]
    fn the_very_last_port_is_still_usable() {
        let ports = SocksPorts::new(65530, 6).unwrap();
        assert_eq!(ports.iter().last(), Some(65535));
        assert!(SocksPorts::new(65530, 7).is_err());
    }

    #[test]
    fn no_concurrency_at_all_is_a_batch_of_one() {
        let ports = SocksPorts::new(10800, 0).unwrap();
        assert_eq!(ports.concurrency(), 1);
        assert_eq!(ports.iter().collect::<Vec<u16>>(), vec![10800]);
    }

    #[test]
    fn every_slot_in_a_batch_gets_a_port_of_its_own() {
        // The property the whole type exists for: no two slots share a port.
        let ports = SocksPorts::new(10800, 8).unwrap();
        let handed_out: Vec<u16> = ports.iter().collect();
        let unique: std::collections::BTreeSet<u16> =
            handed_out.iter().copied().collect();
        assert_eq!(handed_out.len(), unique.len());
        assert_eq!(handed_out.len(), ports.concurrency());
    }
}
