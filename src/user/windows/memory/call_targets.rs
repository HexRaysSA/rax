//! Guest CFG state is independent of mapping permissions and allocation lifetime.
//!
//! Native controls in `docs/specifications/windows/native-cfg-private-code`
//! distinguish default slots (every offset admitted), explicitly registered
//! 16-byte targets (only their aligned address admitted), and invalid slots.
//! Released/decommitted pages retain these bits. A new executable reservation
//! initializes them again; a non-executable reservation leaves them intact.
use std::collections::BTreeMap;

use crate::user::mm::{PAGE_SIZE, Perms};

use super::{AllocKind, VirtualMemory, VmError, perms_of, prot, valid_protection};

#[cfg(test)]
mod tests;

/// Two target bits per 16 guest bytes: one 4 KiB bitmap page covers 256 KiB.
const BITMAP_COVERAGE: u64 = PAGE_SIZE * 8 * 16 / 2;
const SLOT_BYTES: u64 = 16;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum TargetState {
    #[default]
    Invalid,
    Aligned,
    Any,
}

/// Piecewise-constant state over guest byte addresses; zero always has a run.
/// Lookup is O(log r), replacement O(k log r) time and O(k) temporary space,
/// for r boundaries and k replaced boundaries. Reservations need O(r) space.
struct Runs<T> {
    boundaries: BTreeMap<u64, T>,
}

impl<T: Copy + Default + PartialEq> Default for Runs<T> {
    fn default() -> Self {
        Self {
            boundaries: BTreeMap::from([(0, T::default())]),
        }
    }
}

impl<T: Copy + Default + PartialEq> Runs<T> {
    fn get(&self, address: u64) -> T {
        *self.boundaries.range(..=address).next_back().unwrap().1
    }

    fn set(&mut self, first: u64, end: u64, value: T) {
        debug_assert!(first < end);
        let after = self.get(end);
        let keys: Vec<u64> = self
            .boundaries
            .range(first..end)
            .map(|(&key, _)| key)
            .collect();
        for key in keys {
            self.boundaries.remove(&key);
        }
        self.boundaries.insert(first, value);
        self.boundaries.insert(end, after);
        for key in [first, end] {
            if let Some((_, &before)) = self.boundaries.range(..key).next_back()
                && self.boundaries.get(&key) == Some(&before)
            {
                self.boundaries.remove(&key);
            }
        }
    }
}

#[derive(Default)]
pub(super) struct CallTargets {
    slots: Runs<TargetState>,
    resident: Runs<bool>,
    original_execute: BTreeMap<u64, bool>,
}

impl CallTargets {
    pub(super) fn has_reservation(&self, base: u64) -> bool {
        self.original_execute.contains_key(&base)
    }

    fn storage(&mut self, first: u64, end: u64) {
        let first = first & !(BITMAP_COVERAGE - 1);
        let end = ((end - 1) | (BITMAP_COVERAGE - 1)).saturating_add(1);
        self.resident.set(first, end, true);
    }

    pub(super) fn reserve(&mut self, base: u64, end: u64, protection: u32) {
        let executable = perms_of(protection).contains(Perms::EXEC);
        self.original_execute.insert(base, executable);
        if executable {
            self.storage(base, end);
            self.slots.set(
                base,
                end,
                if protection & prot::TARGETS_INVALID != 0 {
                    TargetState::Invalid
                } else {
                    TargetState::Any
                },
            );
        }
    }

    pub(super) fn release(&mut self, base: u64) {
        self.original_execute.remove(&base);
        // Both target bits and their storage survive the VAD's lifetime.
    }

    /// Originally non-executable reservations initialize the affected bits on
    /// every ordinary executable transition. Originally executable reservations
    /// preserve them. NO_UPDATE preserves either kind; allocation/commit
    /// TARGETS_INVALID explicitly invalidates the whole requested range.
    pub(super) fn executable(
        &mut self,
        base: u64,
        first: u64,
        end: u64,
        invalid: bool,
        no_update: bool,
    ) {
        // Storage uses a separate field; target changes are published only for
        // reservations whose VM operation has already succeeded.
        self.storage(first, end);
        let Some(&original_execute) = self.original_execute.get(&base) else {
            return;
        };
        if invalid {
            self.slots.set(first, end, TargetState::Invalid);
        } else if !no_update && !original_execute {
            self.slots.set(first, end, TargetState::Any);
        }
    }

    fn valid(&self, address: u64) -> bool {
        match self.slots.get(address) {
            TargetState::Invalid => false,
            TargetState::Aligned => address % SLOT_BYTES == 0,
            TargetState::Any => true,
        }
    }
}

/// Validate allocation-time CFG modifiers separately from section protections.
/// The modifier is a request, never an AllocationProtect/Protect output bit.
pub(super) fn allocation_protection(protection: u32) -> Result<u32, VmError> {
    let ordinary = protection & !prot::TARGETS_INVALID;
    if !valid_protection(ordinary)
        || matches!(ordinary & 0xff, prot::WRITECOPY | prot::EXECUTE_WRITECOPY)
        || ordinary & prot::WRITECOMBINE != 0 && perms_of(ordinary).contains(Perms::EXEC)
    {
        return Err(VmError::InvalidProtection);
    }
    if protection & prot::TARGETS_INVALID != 0 && !perms_of(ordinary).contains(Perms::EXEC) {
        return Err(VmError::InvalidParameter);
    }
    Ok(ordinary)
}

/// Native protect rejects a CFG modifier on non-executable or copy protection
/// with INVALID_PARAMETER_4; malformed base/cache combinations fail earlier.
pub(super) fn protection_request(protection: u32) -> Result<u32, VmError> {
    let ordinary = protection & !prot::TARGETS_NO_UPDATE;
    if !valid_protection(ordinary) {
        return Err(VmError::InvalidProtection);
    }
    if protection & prot::TARGETS_NO_UPDATE != 0
        && (!perms_of(ordinary).contains(Perms::EXEC) || ordinary & 0xff == prot::EXECUTE_WRITECOPY)
    {
        return Err(VmError::InvalidParameter4);
    }
    Ok(ordinary)
}

impl VirtualMemory {
    /// CFG admission only: this does not grant execute permission or consume a
    /// guard. Sticky state also describes released and decommitted addresses.
    pub fn valid_call_target(&self, address: u64) -> bool {
        address < self.high && self.call_targets.valid(address)
    }

    /// Update one aligned target in a private reservation. Bitmap
    /// storage must already exist, independently of the target page's access
    /// rights. Guest API adapters own record capture, flags and output stores.
    pub fn set_call_target(&mut self, address: u64, valid: bool) -> Result<(), VmError> {
        if address % SLOT_BYTES != 0 {
            return Err(VmError::InvalidParameter);
        }
        let allocation = self.allocation(address).ok_or(VmError::NotAllocated)?;
        if allocation.kind != AllocKind::Private {
            return Err(VmError::NotSupported);
        }
        if !self.call_targets.resident.get(address) {
            return Err(VmError::CallTargetStorage);
        }
        self.call_targets.slots.set(
            address,
            address + SLOT_BYTES,
            if valid {
                TargetState::Aligned
            } else {
                TargetState::Invalid
            },
        );
        Ok(())
    }
}
