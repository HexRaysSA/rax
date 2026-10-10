//! Address requirements for private NtAllocateVirtualMemoryEx reservations.
use super::*;

/// Guest MEM_ADDRESS_REQUIREMENTS. HighestEndingAddress is inclusive; zero
/// fields request the VM's default bounds and 64 KiB allocation granularity.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AddressRequirements {
    /// Inclusive lower address bound, or zero for the VM default.
    pub lowest: u64,
    /// Inclusive upper address bound, or zero for the VM default.
    pub highest: u64,
    /// Power-of-two base alignment in bytes, or zero for 64 KiB.
    pub alignment: u64,
}

pub(super) fn validate_private(
    size: u64,
    allocation_type: u32,
    protect: u32,
) -> Result<(), VmError> {
    const KNOWN: u32 = mem::COMMIT
        | mem::RESERVE
        | mem::TOP_DOWN
        | mem::RESET
        | mem::RESET_UNDO
        | mem::WRITE_WATCH
        | mem::PHYSICAL
        | mem::LARGE_PAGES;
    if size == 0 || allocation_type & !KNOWN != 0 || allocation_type == 0 {
        return Err(VmError::InvalidParameter);
    }
    if !valid_protection(protect)
        || matches!(protect & 0xFF, prot::WRITECOPY | prot::EXECUTE_WRITECOPY)
    {
        return Err(VmError::InvalidProtection);
    }
    Ok(())
}

impl VirtualMemory {
    /// Same private allocation state machine as allocate(), with constrained
    /// address selection for a null base. No host allocation/kernel forwarding.
    /// Validation tests the empty interval before occupied mappings, so an
    /// impossible requirement is INVALID_PARAMETER rather than NO_MEMORY.
    pub fn allocate_extended(
        &mut self,
        base: Option<u64>,
        size: u64,
        allocation_type: u32,
        protect: u32,
        requirements: AddressRequirements,
    ) -> Result<(u64, u64), VmError> {
        if size == 0 || size > self.high - self.low {
            return Err(VmError::InvalidParameter);
        }
        if requirements == AddressRequirements::default() {
            return self.allocate(base, size, allocation_type, protect);
        }
        if base.is_some_and(|b| b != 0) {
            return Err(VmError::InvalidParameter);
        }
        let AddressRequirements {
            lowest,
            highest,
            alignment,
        } = requirements;
        let align = if alignment == 0 {
            ALLOCATION_GRANULARITY
        } else {
            alignment
        };
        if lowest % ALLOCATION_GRANULARITY != 0
            || highest != 0
                && (highest >= self.high
                    || highest % ALLOCATION_GRANULARITY != ALLOCATION_GRANULARITY - 1)
            || lowest >= self.high
            || align < ALLOCATION_GRANULARITY
            || !align.is_power_of_two()
        {
            return Err(VmError::InvalidParameter);
        }
        let lo = lowest.max(self.low);
        let hi = if highest == 0 { self.high } else { highest + 1 };
        let len = size
            .checked_add(PAGE_SIZE - 1)
            .ok_or(VmError::InvalidParameter)?
            & !(PAGE_SIZE - 1);
        let first = lo.checked_add(align - 1).ok_or(VmError::InvalidParameter)? & !(align - 1);
        if len == 0 || first.checked_add(len).is_none_or(|end| end > hi) {
            return Err(VmError::InvalidParameter);
        }
        validate_private(size, allocation_type, protect)?;
        // Keep unsupported flags and reset policy in the ordinary allocator.
        // With a null base, reset cannot identify an existing reservation.
        if allocation_type
            & (mem::RESET | mem::RESET_UNDO | mem::WRITE_WATCH | mem::PHYSICAL | mem::LARGE_PAGES)
            != 0
            || allocation_type & (mem::COMMIT | mem::RESERVE) == 0
        {
            return self.allocate(None, size, allocation_type, protect);
        }
        let candidate = self
            .find_free(len, align, lo, hi, allocation_type & mem::TOP_DOWN != 0)
            .ok_or(VmError::NoMemory)?;
        // A null-base COMMIT reserves implicitly. Selecting its address must
        // preserve that rule; otherwise a fixed-address commit would target a
        // nonexistent reservation. allocate() owns commit-failure rollback.
        self.allocate(
            Some(candidate),
            size,
            allocation_type | mem::RESERVE,
            protect,
        )
    }
}
