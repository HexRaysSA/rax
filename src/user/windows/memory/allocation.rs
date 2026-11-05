//! Reservation, private allocation and commitment in the guest address space.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::user::mm::{Mapping, PAGE_SIZE, Perms};

use super::{
    ALLOCATION_GRANULARITY, AllocKind, Allocation, PageState, RESERVED, VirtualMemory, VmError,
    call_targets, effective_perms, extended, mem, mm, page_range, perms_of, prot, valid_protection,
};

impl VirtualMemory {
    /// Reserves `size` bytes (rounded up to pages) at `base` (rounded down
    /// to the allocation granularity), or anywhere when `base` is `None`.
    pub fn reserve(
        &mut self,
        base: Option<u64>,
        size: u64,
        protect: u32,
        kind: AllocKind,
        top_down: bool,
        name: Option<Arc<str>>,
    ) -> Result<u64, VmError> {
        self.reserve_inner(base, size, protect, kind, top_down, name, true)
    }

    fn reserve_inner(
        &mut self,
        base: Option<u64>,
        size: u64,
        protect: u32,
        kind: AllocKind,
        top_down: bool,
        name: Option<Arc<str>>,
        publish_targets: bool,
    ) -> Result<u64, VmError> {
        if size == 0 {
            return Err(VmError::InvalidParameter);
        }
        let requested = protect;
        let protect = if kind == AllocKind::Private {
            call_targets::allocation_protection(protect)?
        } else if valid_protection(protect) {
            protect
        } else {
            return Err(VmError::InvalidProtection);
        };
        if kind == AllocKind::Private
            && matches!(protect & 0xFF, prot::WRITECOPY | prot::EXECUTE_WRITECOPY)
            || kind != AllocKind::Private && protect & (prot::NOCACHE | prot::WRITECOMBINE) != 0
        {
            return Err(VmError::InvalidProtection);
        }
        let (start, end) = match base {
            Some(b) => {
                let start = b & !(ALLOCATION_GRANULARITY - 1);
                let (_, end) = page_range(b, size)?;
                if !self.is_free(start, end - start) {
                    return Err(VmError::Conflicting);
                }
                (start, end)
            }
            None => {
                let len = size
                    .checked_add(PAGE_SIZE - 1)
                    .ok_or(VmError::InvalidParameter)?
                    & !(PAGE_SIZE - 1);
                let start = self
                    .find_free(len, ALLOCATION_GRANULARITY, self.low, self.high, top_down)
                    .ok_or(VmError::NoMemory)?;
                (start, start + len)
            }
        };
        self.allocs.insert(
            start,
            Allocation {
                base: start,
                size: end - start,
                protect,
                kind,
                pages: BTreeMap::from([(0, RESERVED)]),
                name,
            },
        );
        if kind == AllocKind::Private && publish_targets {
            self.call_targets.reserve(start, end, requested);
        }
        Ok(start)
    }

    /// The private-memory `VirtualAlloc` operation. `None` and `Some(0)`
    /// both request a system-selected address. Committing with a null base
    /// reserves implicitly. Returns the actual base and size, in bytes.
    /// Known facilities requiring additional state (AWE, write watch,
    /// large pages, reset undo) fail explicitly rather than being ignored.
    pub fn allocate(
        &mut self,
        base: Option<u64>,
        size: u64,
        allocation_type: u32,
        protect: u32,
    ) -> Result<(u64, u64), VmError> {
        self.allocate_private(base, size, allocation_type, protect, false)
    }

    pub(super) fn allocate_private(
        &mut self,
        base: Option<u64>,
        size: u64,
        allocation_type: u32,
        protect: u32,
        ec_code: bool,
    ) -> Result<(u64, u64), VmError> {
        extended::validate_private(size, allocation_type, protect)?;
        let base = base.filter(|&b| b != 0);
        if allocation_type & (mem::RESET | mem::RESET_UNDO) != 0 {
            if allocation_type != mem::RESET && allocation_type != mem::RESET_UNDO {
                return Err(VmError::InvalidParameter);
            }
            if ec_code {
                return Err(VmError::NotSupported);
            }
            if allocation_type == mem::RESET_UNDO {
                return Err(VmError::NotSupported);
            }
            let (first, end) = page_range(base.ok_or(VmError::InvalidParameter)?, size)?;
            let a = self.allocation(first).ok_or(VmError::NotAllocated)?;
            if end > a.base + a.size {
                return Err(VmError::Conflicting);
            }
            if a.kind != AllocKind::Private {
                return Err(VmError::InvalidParameter);
            }
            if a.runs((first - a.base) / PAGE_SIZE, (end - a.base) / PAGE_SIZE)
                .iter()
                .any(|(_, _, p)| !p.committed)
            {
                return Err(VmError::NotCommitted);
            }
            // This emulator has no paging file. Resident data remains intact,
            // which MEM_RESET explicitly permits; no protection is changed.
            return Ok((first, end - first));
        }
        if allocation_type & (mem::WRITE_WATCH | mem::PHYSICAL | mem::LARGE_PAGES) != 0 {
            return Err(VmError::NotSupported);
        }
        if allocation_type & (mem::COMMIT | mem::RESERVE) == 0 {
            return Err(VmError::InvalidParameter);
        }
        if allocation_type & mem::RESERVE != 0 || base.is_none() {
            let at = self.reserve_inner(
                base,
                size,
                protect,
                AllocKind::Private,
                allocation_type & mem::TOP_DOWN != 0,
                None,
                false,
            )?;
            let len = self.allocation(at).expect("new reservation").size;
            let result = if allocation_type & mem::COMMIT != 0 {
                self.commit_inner(at, len, protect, false, ec_code)
                    .map(|_| ())
            } else if ec_code {
                self.publish_private_ec(at, at + len)
            } else {
                Ok(())
            };
            if let Err(e) = result {
                // Reservation was new, so it cannot contain earlier data.
                self.release(at)?;
                return Err(e);
            }
            self.call_targets.reserve(at, at + len, protect);
            Ok((at, len))
        } else {
            self.commit_inner(
                base.expect("non-null commit"),
                size,
                protect,
                false,
                ec_code,
            )
        }
    }

    pub(super) fn check_protection(a: &Allocation, protect: u32) -> Result<(), VmError> {
        if a.kind == AllocKind::Private {
            call_targets::allocation_protection(protect)?;
            return Ok(());
        }
        if !valid_protection(protect)
            || a.kind == AllocKind::Private
                && matches!(protect & 0xFF, prot::WRITECOPY | prot::EXECUTE_WRITECOPY)
            || a.kind != AllocKind::Private && protect & (prot::NOCACHE | prot::WRITECOMBINE) != 0
        {
            Err(VmError::InvalidProtection)
        } else {
            Ok(())
        }
    }

    /// Commits `[start, start + len)` (page-rounded outward) inside one
    /// allocation with `protect`. Already committed pages keep their
    /// contents and take the new protection.
    pub fn commit(&mut self, start: u64, len: u64, protect: u32) -> Result<(u64, u64), VmError> {
        self.commit_inner(start, len, protect, false, false)
    }

    pub(super) fn commit_inner(
        &mut self,
        start: u64,
        len: u64,
        protect: u32,
        kernel_data: bool,
        ec_code: bool,
    ) -> Result<(u64, u64), VmError> {
        let requested = protect;
        let protect = if kernel_data || protect & prot::TARGETS_INVALID == 0 {
            if !valid_protection(protect) {
                return Err(VmError::InvalidProtection);
            }
            protect
        } else {
            call_targets::allocation_protection(protect)?
        };
        let (first, end) = page_range(start, len)?;
        let a = self.allocation(first).ok_or(VmError::NotAllocated)?;
        if a.kind != AllocKind::Private && requested & prot::TARGETS_INVALID != 0 {
            return Err(VmError::NotSupported);
        }
        if self.nls_views.contains(&a.base) {
            return Err(if protect == prot::READONLY {
                VmError::AlreadyCommitted
            } else {
                VmError::InvalidProtection
            });
        }
        if self.section_views.contains_key(&a.base)
            || (self.data_views.contains_key(&a.base) && !kernel_data)
            || (self.is_code_bitmap(a.base) && !kernel_data)
            || self.is_shared_view(a.base)
            || self.is_file_view(a.base)
        {
            return Err(VmError::AlreadyCommitted);
        }

        if end > a.base + a.size {
            return Err(VmError::Conflicting);
        }
        Self::check_protection(a, protect)?;
        let base = a.base;
        let name = a.name.clone();
        let i0 = (first - base) / PAGE_SIZE;
        let i1 = (end - base) / PAGE_SIZE;
        let runs = a.runs(i0, i1);
        let newly_committed: u64 = runs
            .iter()
            .filter(|(_, _, p)| !p.committed)
            .map(|(lo, hi, _)| (hi - lo) * PAGE_SIZE)
            .sum();
        let charge = self
            .committed
            .checked_add(newly_committed)
            .ok_or(VmError::CommitmentLimit)?;
        // AddressSpace::map replaces existing data. Verify all reserved
        // runs are unmapped and all committed runs are mapped before any
        // mutation. With scheduler serialization, subsequent map/protect
        // calls cannot fail their checked-range/coverage preconditions.
        for &(lo, hi, state) in &runs {
            let at = base + lo * PAGE_SIZE;
            let size = (hi - lo) * PAGE_SIZE;
            if state.committed {
                if self.space.first_unmapped(at, size).is_some() {
                    return Err(VmError::NotCommitted);
                }
            } else if !self.space.is_free(at, size) {
                return Err(VmError::Conflicting);
            }
        }
        if charge > self.commit_limit {
            return Err(VmError::CommitmentLimit);
        }
        let bitmap_pages = if ec_code || effective_perms(protect).contains(Perms::EXEC) {
            self.bitmap_execute_pages(first, end)?
        } else {
            BTreeSet::new()
        };
        let charge = charge
            .checked_add(self.bitmap_page_charge(&bitmap_pages))
            .filter(|&total| total <= self.commit_limit)
            .ok_or(VmError::CommitmentLimit)?;
        self.commit_bitmap_pages(&bitmap_pages)?;
        for &(lo, hi, state) in &runs {
            if !state.committed {
                let mut mapping = Mapping::anonymous(effective_perms(protect));
                mapping.name = name.clone();
                self.space
                    .map(base + lo * PAGE_SIZE, (hi - lo) * PAGE_SIZE, mapping)
                    .map_err(mm)?;
            }
        }
        self.space
            .protect(first, end - first, effective_perms(protect))
            .map_err(mm)?;
        self.allocs
            .get_mut(&base)
            .expect("validated allocation")
            .set_state(
                i0,
                i1,
                PageState {
                    committed: true,
                    protect,
                    reported: None,
                },
            );
        self.committed = charge;
        if ec_code {
            self.mark_ec_pages(first, end)?;
        }
        if perms_of(protect).contains(Perms::EXEC)
            && (self
                .allocation(base)
                .is_some_and(|allocation| allocation.kind != AllocKind::Private)
                || self.call_targets.has_reservation(base))
        {
            self.call_targets.executable(
                base,
                first,
                end,
                requested & prot::TARGETS_INVALID != 0,
                false,
            );
        }
        Ok((first, end - first))
    }
}
