//! PC RAM capacity, with the 3..4GiB device window kept outside RAM.
use crate::error::Result;
use crate::vm::memory::{PAGE_SIZE, align_up, validate_guest_memory_size};
use std::ops::Range;

pub(crate) const LOW_END: u64 = 0xc000_0000;
pub(crate) const HIGH_START: u64 = 0x1_0000_0000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Layout {
    pub reported: u64,
    pub low_end: u64,
    pub high_end: u64,
}

impl Layout {
    pub(crate) fn new(bytes: u64) -> Result<Self> {
        // This admits the checked page rounding, configured cap and retained
        // backing padding before the infallible address calculations below.
        validate_guest_memory_size(bytes)?;
        let reported = align_up(bytes, PAGE_SIZE);
        let low_end = reported.min(LOW_END);
        Ok(Self {
            reported,
            low_end,
            high_end: HIGH_START + (reported - low_end),
        })
    }

    pub(crate) fn high(self) -> Option<Range<u64>> {
        (self.high_end > HIGH_START).then_some(HIGH_START..self.high_end)
    }

    pub(crate) fn ranges(self) -> impl Iterator<Item = Range<u64>> {
        (self.low_end != 0)
            .then_some(0..self.low_end)
            .into_iter()
            .chain(self.high())
    }

    /// Admit one positive physical extent within a single RAM interval.
    /// Checked endpoints reject wrapping/cross-hole extents before a writer.
    pub(crate) fn contains(self, start: u64, bytes: u64) -> bool {
        bytes != 0
            && start.checked_add(bytes).is_some_and(|end| {
                self.ranges()
                    .any(|range| start >= range.start && end <= range.end)
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capacity_is_conserved_across_the_device_window_and_at_the_configured_cap() {
        for (bytes, expected) in [
            (0, vec![]),
            (4096, vec![0..4096]),
            (LOW_END, vec![0..LOW_END]),
            (
                LOW_END + 4096,
                vec![0..LOW_END, HIGH_START..HIGH_START + 4096],
            ),
            (4 << 30, vec![0..LOW_END, HIGH_START..5 << 30]),
            (64 << 30, vec![0..LOW_END, HIGH_START..65 << 30]),
        ] {
            let layout = Layout::new(bytes).unwrap();
            let ranges: Vec<_> = layout.ranges().collect();
            assert_eq!(ranges, expected);
            assert_eq!(
                ranges
                    .iter()
                    .map(|range| range.end - range.start)
                    .sum::<u64>(),
                bytes
            );
            assert!(
                ranges
                    .iter()
                    .all(|range| range.end <= LOW_END || range.start >= HIGH_START)
            );
        }
    }

    #[test]
    fn page_rounding_and_unrepresentable_requests_use_the_memory_allocation_contract() {
        let layout = Layout::new(LOW_END + 1).unwrap();
        assert_eq!(layout.reported, LOW_END + PAGE_SIZE);
        assert_eq!(layout.high_end, HIGH_START + PAGE_SIZE);
        assert!(Layout::new(u64::MAX).is_err());
        assert!(Layout::new((64 << 30) + 1).is_err());
    }

    #[test]
    fn extent_admission_distinguishes_ram_holes_padding_and_wrapping_addresses() {
        let layout = Layout::new(LOW_END + PAGE_SIZE).unwrap();
        assert!(layout.contains(0, PAGE_SIZE));
        assert!(layout.contains(LOW_END - PAGE_SIZE, PAGE_SIZE));
        assert!(layout.contains(HIGH_START, PAGE_SIZE));
        assert!(!layout.contains(LOW_END, 1));
        assert!(!layout.contains(LOW_END - 1, 2));
        assert!(!layout.contains(HIGH_START - 1, 2));
        assert!(!layout.contains(HIGH_START + PAGE_SIZE, 1));
        assert!(!layout.contains(u64::MAX, 2));
        assert!(!layout.contains(0, 0));
    }
}
