//! Live shared backing with explicit first-write copying. Ordinary shared
//! mappings keep their original policy; a private view opts in atomically.

use super::pagetable::{PTE_COW, PTE_PRIVATE};
use super::*;

impl AddressSpace {
    /// Same-copy-state prefix of a validated, aligned page range. O(S) time
    /// for populated page-table slots; absent subtrees are skipped and no
    /// guest frames are populated. The returned byte length is nonzero.
    pub(crate) fn private_copy_run(&self, start: u64, len: u64) -> (bool, u64) {
        debug_assert!(start % PAGE_SIZE == 0 && len != 0 && len % PAGE_SIZE == 0);
        let first = start / PAGE_SIZE;
        let end = first + len / PAGE_SIZE;
        let private = self.inner.table.get(first) & PTE_PRIVATE != 0;
        let mut next = first;
        let mut boundary = end;
        self.inner
            .table
            .for_each_populated(first, end, |vpn, slot| {
                if vpn >= boundary {
                    return;
                }
                let copied = slot.load(Ordering::Acquire) & PTE_PRIVATE != 0;
                if private {
                    if vpn != next || !copied {
                        boundary = next;
                    } else {
                        next = vpn + 1;
                    }
                } else if copied {
                    boundary = vpn;
                }
            });
        if private {
            boundary = boundary.min(next);
        }
        (private, (boundary - first) * PAGE_SIZE)
    }

    /// Keep untouched pages coherent with their shared object and copy one
    /// page on its first write, including a writable probe or raw write.
    /// Mapping changes follow the address-space scheduler/owner-lock contract.
    /// O(k log n) metadata work for k replaced ranges; no frames are populated.
    pub(crate) fn map_copy_on_write(
        &self,
        start: u64,
        len: u64,
        mapping: Mapping,
    ) -> Result<(), MmError> {
        if mapping.shared || !matches!(&mapping.backing, Backing::Shared { .. }) {
            return Err(MmError::InvalidArgument(
                "copy-on-write requires a private shared-object mapping",
            ));
        }
        mapping
            .backing
            .offset()
            .checked_add(len)
            .ok_or(MmError::OutOfRange)?;
        self.map_with_copy(start, len, mapping, true)
    }

    /// Change an owned file view between shared writes and first-write copies.
    /// Existing private frames remain private when the policy changes back.
    /// O(V log V + P log V) time for V affected VMAs and P populated entries;
    /// absent pages are neither visited nor allocated.
    pub(crate) fn set_file_copy_on_write(
        &self,
        start: u64,
        len: u64,
        copy: bool,
    ) -> Result<(), MmError> {
        let end = check_range(start, len, self.inner.va_limit)?;
        let mut vmas = self.vmas();
        if let Some(hole) = first_hole(&vmas, start, end) {
            return Err(MmError::NotMapped { addr: hole });
        }
        if vmas.overlapping(start, end).any(|vma| {
            !matches!(&vma.backing, Backing::Shared { object, .. } if object.is_file_backed())
        }) {
            return Err(MmError::InvalidArgument("copy policy requires file views"));
        }
        if copy {
            vmas.enable_shared_cow(start, end);
        } else {
            vmas.disable_shared_cow(start, end);
        }
        vmas.update(start, end, |vma| vma.shared = !copy);
        self.inner
            .table
            .for_each_populated(start >> 12, end >> 12, |vpn, slot| {
                let current = slot.load(Ordering::Acquire);
                if current & PTE_PRIVATE != 0 {
                    return;
                }
                let perms = vmas.find(vpn << 12).expect("validated file view").perms;
                let next = if copy {
                    make_pte(current & PTE_FRAME, perms & !Perms::WRITE)
                        | PTE_COW
                        | PTE_TRACK_PRIVATE
                } else {
                    make_pte(current & PTE_FRAME, perms)
                };
                slot.store(next, Ordering::Release);
            });
        vmas.coalesce(start, end);
        Ok(())
    }

    /// The first-write slow path serializes with page population and mapping
    /// changes. Guest threads of this address space run on one host thread.
    pub(super) fn copy_shared_page(
        &self,
        address: u64,
        raw: bool,
    ) -> Result<u64, GuestMemoryFault> {
        let vmas = self.vmas();
        let vma = vmas
            .find(address)
            .ok_or_else(|| fault(address, MemoryAccessKind::Write, MemoryFaultKind::Unmapped))?;
        if !raw && !vma.perms.contains(Perms::WRITE) {
            return Err(fault(
                address,
                MemoryAccessKind::Write,
                MemoryFaultKind::Permission,
            ));
        }
        let current = self.inner.table.get(address >> 12);
        if current & PTE_VALID == 0 {
            return Err(fault(
                address,
                MemoryAccessKind::Write,
                MemoryFaultKind::Other,
            ));
        }
        if current & PTE_COW == 0 {
            if raw {
                self.check_raw_write(address, current & PTE_FRAME)?;
            }
            self.acquire_private_copy(address);
            if vma.perms.contains(Perms::EXEC) {
                self.log_code_change(address & !PAGE_MASK, PAGE_SIZE);
            }
            return Ok((current & PTE_FRAME) | (address & PAGE_MASK));
        }
        if !vmas.copies_shared_page(address) {
            return Err(fault(
                address,
                MemoryAccessKind::Write,
                MemoryFaultKind::Other,
            ));
        }
        self.private_shared_frame(vma, address, current)
    }

    /// Caller holds the VMA lock. A failed allocation/read leaves the old
    /// entry and its extent reference unchanged. O(PAGE_SIZE) time and scratch.
    pub(super) fn private_shared_frame(
        &self,
        vma: &Vma,
        address: u64,
        previous: u64,
    ) -> Result<u64, GuestMemoryFault> {
        let page = address & !PAGE_MASK;
        let mut bytes = [0; PAGE_SIZE as usize];
        let arena = &self.inner.arena;
        if previous & PTE_VALID != 0 {
            arena.read(previous & PTE_FRAME, &mut bytes);
        } else if !vma
            .backing
            .fill_page(page - vma.start, &mut bytes)
            .map_err(|_| fault(address, MemoryAccessKind::Write, MemoryFaultKind::Other))?
        {
            return Err(fault(
                address,
                MemoryAccessKind::Write,
                MemoryFaultKind::Other,
            ));
        }
        let frame = arena
            .alloc_zeroed()
            .map_err(|_| fault(address, MemoryAccessKind::Write, MemoryFaultKind::Other))?;
        arena.write(frame, &bytes);
        self.inner
            .table
            .slot(page >> 12)
            .store(make_pte(frame, vma.perms) | PTE_PRIVATE, Ordering::Release);
        if previous & PTE_VALID != 0 && arena.is_extent(previous & PTE_FRAME) {
            let mut extents = self.inner.extents.lock().unwrap();
            self.unref_extent(&mut extents, (previous & PTE_FRAME) & !(EXTENT - 1));
        }
        if !self.available() {
            return Err(fault(
                address,
                MemoryAccessKind::Write,
                MemoryFaultKind::Other,
            ));
        }
        if vma.perms.contains(Perms::EXEC) {
            self.log_code_change(page, PAGE_SIZE);
        }
        Ok(frame | (address & PAGE_MASK))
    }
}

#[cfg(test)]
mod tests;
