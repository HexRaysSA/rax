//! Protection updates preserve allocation identity and guest mapping ownership.
use std::collections::BTreeSet;

use crate::user::mm::{PAGE_SIZE, Perms};

use super::{
    AllocKind, PageState, VirtualMemory, VmError, call_targets, effective_perms, mm, page_range,
    perms_of, prot,
};

impl VirtualMemory {
    /// Changes the protection of committed pages `[start, start + len)`;
    /// returns the old protection of the first page.
    pub fn protect(&mut self, start: u64, len: u64, protect: u32) -> Result<u32, VmError> {
        self.protect_inner(start, len, protect, true)
    }

    /// Install initial image permissions without turning a shared writable
    /// section into a process-private copy-capable range.
    pub(crate) fn protect_image_initial(
        &mut self,
        start: u64,
        len: u64,
        protect: u32,
    ) -> Result<u32, VmError> {
        if self
            .allocation(start)
            .is_none_or(|a| a.kind != AllocKind::Image)
        {
            return Err(VmError::InvalidParameter);
        }
        self.protect_inner(start, len, protect, false)
    }

    fn protect_inner(
        &mut self,
        start: u64,
        len: u64,
        protect: u32,
        track_copies: bool,
    ) -> Result<u32, VmError> {
        let requested = protect;
        let protect = call_targets::protection_request(protect)?;
        let (first, end) = page_range(start, len)?;
        let a = self.allocation(first).ok_or(VmError::NotAllocated)?;
        if a.kind != AllocKind::Private && requested & prot::TARGETS_NO_UPDATE != 0 {
            return Err(VmError::NotSupported);
        }
        if a.kind == AllocKind::Private
            && protect & prot::WRITECOMBINE != 0
            && perms_of(protect).contains(Perms::EXEC)
        {
            return Err(VmError::InvalidProtection);
        }
        self.check_file_protection(a.base, protect)?;
        if perms_of(protect).contains(Perms::EXEC)
            && self
                .section_views
                .get(&a.base)
                .is_some_and(|view| view.section.no_execute)
        {
            return Err(VmError::SectionProtection);
        }
        if self.is_code_bitmap(a.base) && !matches!(protect, prot::NOACCESS | prot::READONLY) {
            return Err(VmError::SectionProtection);
        }
        if self.nls_views.contains(&a.base) && protect != prot::READONLY {
            return Err(VmError::InvalidProtection);
        }
        if self.is_shared_view(a.base)
            && !matches!(protect, prot::NOACCESS | prot::READONLY | prot::READWRITE)
        {
            return Err(VmError::NotSupported);
        }
        if self.data_views.contains_key(&a.base) {
            if protect & (prot::NOCACHE | prot::WRITECOMBINE) != 0 {
                return Err(VmError::InvalidParameter4);
            }
            if !matches!(
                protect & 0xFF,
                prot::NOACCESS | prot::READONLY | prot::WRITECOPY
            ) {
                return Err(VmError::SectionProtection);
            }
        }

        if end > a.base + a.size {
            return Err(VmError::InvalidAddress);
        }
        // Native image-extension pages report MEM_COMMIT in class 0, but
        // NtProtectVirtualMemory rejects their protection changes as uncommitted.
        if self.intersects_image_extension(first, end) {
            return Err(VmError::NotCommitted);
        }
        Self::check_protection(a, protect)?;
        let base = a.base;
        let acquire_copy_potential =
            track_copies && a.kind == AllocKind::Image && perms_of(protect).contains(Perms::WRITE);
        let i0 = (first - base) / PAGE_SIZE;
        let i1 = (end - base) / PAGE_SIZE;
        if a.runs(i0, i1).iter().any(|(_, _, p)| !p.committed) {
            return Err(VmError::NotCommitted);
        }
        let p = a.state(i0);
        let old = if self.file_views.contains_key(&base) {
            self.query(first).expect("validated file page").protect
        } else {
            p.reported.unwrap_or(p.protect)
        };
        let bitmap_pages = if effective_perms(protect).contains(Perms::EXEC) {
            self.bitmap_execute_pages(first, end)?
        } else {
            BTreeSet::new()
        };
        if self
            .committed
            .checked_add(self.bitmap_page_charge(&bitmap_pages))
            .is_none_or(|total| total > self.commit_limit)
        {
            return Err(VmError::CommitmentLimit);
        }
        self.commit_bitmap_pages(&bitmap_pages)?;
        // This single AddressSpace operation checks all mapping coverage
        // before changing permissions; metadata changes only on success.
        self.space
            .protect(first, end - first, effective_perms(protect))
            .map_err(mm)?;
        if self.file_views.contains_key(&base) {
            self.space
                .set_file_copy_on_write(
                    first,
                    end - first,
                    !matches!(protect & 0xFF, prot::READWRITE | prot::EXECUTE_READWRITE),
                )
                .map_err(mm)?;
        }
        if acquire_copy_potential {
            self.space
                .track_private_copies(first, end - first)
                .map_err(mm)?;
        }
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
        if perms_of(protect).contains(Perms::EXEC) {
            self.call_targets.executable(
                base,
                first,
                end,
                false,
                requested & prot::TARGETS_NO_UPDATE != 0,
            );
        }
        Ok(old)
    }
}
