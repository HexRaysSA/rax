//! Best-effort working-set population without changing guest protections.
use super::{PAGE_SIZE, VirtualMemory, prot};
use crate::error::MemoryAccessKind;

impl VirtualMemory {
    /// Prefetch committed, accessible pages intersecting a validated byte range.
    /// Holes, reservations, guards and inaccessible pages are ignored. An advice
    /// failure never changes permissions, commitment or the caller's NTSTATUS.
    /// Walk allocation/state runs, not the potentially enormous free extent:
    /// O(log A + R + P) for A allocations, R intersecting runs and P eligible
    /// pages, with O(R) temporary run metadata and no range-sized byte buffer.
    pub(crate) fn prefetch_working_set(&self, start: u64, bytes: u64) {
        let Some(end) = start.checked_add(bytes).map(|end| end.min(self.high)) else {
            return;
        };
        if start >= end {
            return;
        }
        let first_key = self
            .allocs
            .range(..=start)
            .next_back()
            .map_or(start, |(&base, _)| base);
        for allocation in self.allocs.range(first_key..end).map(|(_, value)| value) {
            let lo = start.max(allocation.base);
            let hi = end.min(allocation.base + allocation.size);
            if lo >= hi {
                continue;
            }
            let first = (lo - allocation.base) / PAGE_SIZE;
            let last = (hi - allocation.base).div_ceil(PAGE_SIZE);
            for (from, to, state) in allocation.runs(first, last) {
                if !state.committed || state.protect & (prot::NOACCESS | prot::GUARD) != 0 {
                    continue;
                }
                for page in from..to {
                    let address = allocation.base + page * PAGE_SIZE;
                    // A read population preserves private-copy tracking, does not
                    // dirty code, and ignores execute-only mapping permissions.
                    // Eligibility above preserves NOACCESS and guard semantics.
                    let _ = self.space.translate_raw(address, MemoryAccessKind::Read);
                }
            }
        }
    }
}
