//! Initial native stack reservation and commitment, before guest publication.
//!
//! Windows Thread Stack Size defines image defaults and page/allocation rounding.
//! The native creation observations under `native-nt-thread-lifecycle` cover
//! commit below, equal to and above the selected reservation. Guard growth is
//! owned by the parent module; this allocator only installs its initial frontier.

use std::sync::Arc;

use crate::user::mm::PAGE_SIZE;
use crate::user::windows::memory::{AllocKind, VirtualMemory, prot};
use crate::user::windows::nt::status::{STATUS_CONFLICTING_ADDRESSES, STATUS_INVALID_PARAMETER};

const DEFAULT_RESERVE: u64 = 0x10_0000;
const RESERVE_GRANULARITY: u64 = 0x1_0000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Sizes {
    reserve: u64,
    commit: u64,
}

#[cfg(test)]
#[path = "allocation_tests.rs"]
mod tests;

/// Host-owned stack boundaries. The caller owns release after success.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Allocation {
    pub(crate) address: u64,
    pub(crate) base: u64,
    pub(crate) limit: u64,
}

fn round(value: u64, alignment: u64) -> Result<u64, u32> {
    value
        .checked_add(alignment - 1)
        .map(|rounded| rounded & !(alignment - 1))
        .ok_or(STATUS_INVALID_PARAMETER)
}

impl Sizes {
    /// O(1) time/storage. Image fields supply zero arguments, independently;
    /// a missing image reserve uses 1 MiB and a missing commit uses one page.
    pub(crate) fn select(
        reserve: u64,
        commit: u64,
        image_reserve: u64,
        image_commit: u64,
    ) -> Result<Self, u32> {
        let reserve = if reserve != 0 {
            reserve
        } else if image_reserve != 0 {
            image_reserve
        } else {
            DEFAULT_RESERVE
        };
        let commit = if commit != 0 { commit } else { image_commit };
        let commit = round(commit.max(PAGE_SIZE), PAGE_SIZE)?;
        let reserve = if commit >= reserve {
            round(commit, DEFAULT_RESERVE)?
        } else {
            round(reserve, RESERVE_GRANULARITY)?
        };
        Ok(Self { reserve, commit })
    }

    /// Reserve first, then commit the requested top range and an optional guard.
    /// A failed mapping releases the unpublished reservation in full.
    pub(crate) fn allocate(self, vm: &mut VirtualMemory) -> Result<Allocation, u32> {
        self.allocate_with_zero_bits(vm, 0)
    }

    pub(crate) fn allocate_with_zero_bits(
        self,
        vm: &mut VirtualMemory,
        zero_bits: u64,
    ) -> Result<Allocation, u32> {
        let base = if zero_bits == 0 {
            None
        } else {
            let shift = 32u32
                .checked_sub(u32::try_from(zero_bits).map_err(|_| STATUS_INVALID_PARAMETER)?)
                .ok_or(STATUS_INVALID_PARAMETER)?;
            let limit = 1u64 << shift;
            if self.reserve > limit {
                return Err(STATUS_INVALID_PARAMETER);
            }
            // Native ZeroBits constrains the 32-bit placement interval, even
            // for native64 callers. A valid but occupied interval conflicts.
            Some(
                vm.find_free(
                    self.reserve,
                    RESERVE_GRANULARITY,
                    vm.low(),
                    vm.high().min(limit),
                    false,
                )
                .ok_or(STATUS_CONFLICTING_ADDRESSES)?,
            )
        };
        let address = vm
            .reserve(
                base,
                self.reserve,
                prot::READWRITE,
                AllocKind::Private,
                false,
                Some(Arc::from("[stack]")),
            )
            .map_err(|error| error.status())?;
        let result = (|| {
            let base = address
                .checked_add(self.reserve)
                .ok_or(STATUS_INVALID_PARAMETER)?;
            let limit = base
                .checked_sub(self.commit)
                .filter(|limit| *limit >= address)
                .ok_or(STATUS_INVALID_PARAMETER)?;
            vm.commit(limit, self.commit, prot::READWRITE)
                .map_err(|error| error.status())?;
            if limit - address >= PAGE_SIZE {
                vm.commit(limit - PAGE_SIZE, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                    .map_err(|error| error.status())?;
            }
            Ok(Allocation {
                address,
                base,
                limit,
            })
        })();
        if result.is_err() {
            let _ = vm.release(address);
        }
        result
    }
}
