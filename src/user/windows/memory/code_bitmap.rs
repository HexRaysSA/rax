//! Sparse guest-owned code tags read by the installed ARM64EC kernel extension.
//! Native controls qualify NOACCESS/MEM_MAPPED reservation, sparse READONLY
//! commitment, and sticky EC tags across free and ordinary exact-address reuse.
use super::*;
use crate::user::image::pe::hybrid::CodeKind;
use crate::user::windows::object_namespace::{BITMAP_BYTES, CodeBitmapPlan};

pub(super) struct CodeBitmap {
    pub(super) base: u64,
    // A freed address never confers ownership of a replacement allocation.
    pub(super) retired: bool,
}

impl VirtualMemory {
    pub(super) fn bitmap_execute_pages(
        &self,
        first: u64,
        end: u64,
    ) -> Result<BTreeSet<u64>, VmError> {
        if self.code_bitmap.is_none() {
            return Ok(BTreeSet::new());
        }
        let base = self.code_bitmap_base()?;
        if first >= end || end > 1 << 47 {
            return Err(VmError::InvalidAddress);
        }
        let start = (base + (first >> 15)) & !(PAGE_SIZE - 1);
        let end = ((base + ((end - 1) >> 15)) & !(PAGE_SIZE - 1)) + PAGE_SIZE;
        Ok((start..end).step_by(PAGE_SIZE as usize).collect())
    }

    pub(super) fn bitmap_page_charge(&self, pages: &BTreeSet<u64>) -> u64 {
        pages
            .iter()
            .filter(|&&address| {
                self.query(address)
                    .is_none_or(|region| region.state != mem::COMMIT)
            })
            .count() as u64
            * PAGE_SIZE
    }

    pub(super) fn commit_bitmap_pages(&mut self, pages: &BTreeSet<u64>) -> Result<(), VmError> {
        for &page in pages {
            self.commit_inner(page, PAGE_SIZE, prot::READONLY, true, false)?;
        }
        Ok(())
    }
    pub(crate) fn code_bitmap_address(&self) -> Result<Option<u64>, VmError> {
        self.code_bitmap
            .as_ref()
            .map(|_| self.code_bitmap_base())
            .transpose()
    }

    pub(crate) fn has_code_bitmap(&self) -> bool {
        self.code_bitmap
            .as_ref()
            .is_some_and(|bitmap| !bitmap.retired)
    }

    /// Only a live executable private allocation can supply a decoder owner.
    /// Sticky bits alone never admit freed, reserved, mapped or non-code bytes.
    pub(crate) fn private_code_kind(&self, pc: u64) -> Result<Option<CodeKind>, VmError> {
        let Some(allocation) = self.allocation(pc) else {
            return Ok(None);
        };
        // Reported protection may deliberately advertise an NX trap as RX.
        // Decoder ownership follows the actual page state instead.
        let state = allocation.state((pc - allocation.base) / PAGE_SIZE);
        if allocation.kind != AllocKind::Private
            || !state.committed
            || !perms_of(state.protect).contains(Perms::EXEC)
        {
            return Ok(None);
        }
        let Some(base) = self.code_bitmap_address()? else {
            return Ok(Some(CodeKind::Amd64));
        };
        let address = base.checked_add(pc >> 15).ok_or(VmError::InvalidAddress)?;
        let byte = self.space.u8(address).map_err(|_| VmError::NotCommitted)?;
        Ok(Some(if byte & (1 << ((pc >> 12) & 7)) != 0 {
            CodeKind::Arm64Ec
        } else {
            CodeKind::Amd64
        }))
    }

    /// Reserve-only EC requests also publish tags. Preflight storage commitment
    /// before mutation; allocation callers remove their new reservation on error.
    pub(super) fn publish_private_ec(&mut self, first: u64, end: u64) -> Result<(), VmError> {
        let pages = self.bitmap_execute_pages(first, end)?;
        if self
            .committed
            .checked_add(self.bitmap_page_charge(&pages))
            .is_none_or(|total| total > self.commit_limit)
        {
            return Err(VmError::CommitmentLimit);
        }
        self.commit_bitmap_pages(&pages)?;
        self.mark_ec_pages(first, end)
    }

    /// O(P / 8) updates for P guest pages, with constant temporary storage.
    /// The caller preflights and commits every affected bitmap page first.
    pub(super) fn mark_ec_pages(&mut self, first: u64, end: u64) -> Result<(), VmError> {
        let base = self.code_bitmap_base()?;
        let first_page = first / PAGE_SIZE;
        let end_page = end / PAGE_SIZE;
        for byte in first_page / 8..end_page.div_ceil(8) {
            let lo = first_page.saturating_sub(byte * 8).min(8) as u32;
            let hi = (end_page - byte * 8).min(8) as u32;
            let mask = (((1u16 << hi) - 1) & !((1u16 << lo) - 1)) as u8;
            let address = base + byte;
            let value = self.space.u8(address).map_err(|_| VmError::NotCommitted)? | mask;
            self.poke(address, &[value])
                .map_err(|_| VmError::NoMemory)?;
        }
        Ok(())
    }

    pub(super) fn is_code_bitmap(&self, base: u64) -> bool {
        self.code_bitmap
            .as_ref()
            .is_some_and(|bitmap| !bitmap.retired && bitmap.base == base)
    }

    fn code_bitmap_base(&self) -> Result<u64, VmError> {
        let bitmap = self
            .code_bitmap
            .as_ref()
            .filter(|bitmap| !bitmap.retired)
            .ok_or(VmError::InvalidAddress)?;
        let allocation = self
            .allocs
            .get(&bitmap.base)
            .ok_or(VmError::InvalidAddress)?;
        if allocation.size != BITMAP_BYTES
            || allocation.kind != AllocKind::Mapped
            || allocation.protect != prot::NOACCESS
            || allocation
                .runs(0, BITMAP_BYTES / PAGE_SIZE)
                .iter()
                .any(|(_, _, page)| {
                    page.protect != if page.committed { prot::READONLY } else { 0 }
                        || page.reported.is_some()
                })
        {
            return Err(VmError::InvalidAddress);
        }
        Ok(bitmap.base)
    }

    pub(crate) fn publish_ec_image(
        &mut self,
        plan: &CodeBitmapPlan,
        image_base: u64,
        image_size: u64,
    ) -> Result<(), VmError> {
        if plan.ranges.is_empty() && plan.base.is_none() {
            return Ok(());
        }
        // Preflight all ranges and occupied addresses before creating a view.
        for &(start, end) in &plan.ranges {
            if start >= end
                || u64::from(end) > image_size
                || image_base
                    .checked_add(u64::from(end))
                    .is_none_or(|end| end > 1 << 47)
            {
                return Err(VmError::InvalidParameter);
            }
        }
        let created = self.code_bitmap.is_none();
        if created {
            let base = plan.base.ok_or(VmError::NotSupported)?;
            if base == 0
                || base % ALLOCATION_GRANULARITY != 0
                || base
                    .checked_add(BITMAP_BYTES)
                    .is_none_or(|end| end > self.high)
            {
                return Err(VmError::InvalidAddress);
            }
            self.reserve(
                Some(base),
                BITMAP_BYTES,
                prot::NOACCESS,
                AllocKind::Mapped,
                false,
                None,
            )?;
            self.code_bitmap = Some(CodeBitmap {
                base,
                retired: false,
            });
        }
        let result = (|| {
            let base = self.code_bitmap_base()?;
            if plan.base.is_some_and(|selected| selected != base) {
                return Err(VmError::Conflicting);
            }
            // A bit is set for every page intersecting an EC range, including
            // a final partial page. Other ISA tags never acquire an EC bit.
            let mut updates = BTreeMap::<u64, u8>::new();
            for &(start, end) in &plan.ranges {
                let first = (image_base + u64::from(start)) / PAGE_SIZE;
                let last = (image_base + u64::from(end)).div_ceil(PAGE_SIZE);
                for page in first..last {
                    *updates.entry(base + page / 8).or_default() |= 1 << (page % 8);
                }
            }
            let mut pages: BTreeSet<_> = updates
                .keys()
                .map(|address| address & !(PAGE_SIZE - 1))
                .collect();
            // Executable AMD64 pages need readable zero bits too. Native
            // controls distinguish ordinary RW commitment from adding execute
            // permission; cover code already present when this view is born.
            if created {
                for vma in self.space.vma_snapshot() {
                    if vma.perms.contains(Perms::EXEC) {
                        pages.extend(self.bitmap_execute_pages(vma.start, vma.end)?);
                    }
                }
            }
            let charge = self.bitmap_page_charge(&pages);
            if self
                .committed
                .checked_add(charge)
                .is_none_or(|total| total > self.commit_limit)
            {
                return Err(VmError::CommitmentLimit);
            }
            // Check every existing backing byte before the first mutation.
            for &address in updates.keys() {
                if self
                    .query(address)
                    .is_some_and(|region| region.state == mem::COMMIT)
                {
                    self.space.u8(address).map_err(|_| VmError::NotCommitted)?;
                }
            }
            self.commit_bitmap_pages(&pages)?;
            for (address, mask) in updates {
                let value = self.space.u8(address).map_err(|_| VmError::NotCommitted)? | mask;
                self.poke(address, &[value])
                    .map_err(|_| VmError::NoMemory)?;
            }
            Ok(())
        })();
        if result.is_err() && created {
            let base = self.code_bitmap.as_ref().expect("new bitmap").base;
            self.release(base)?;
            self.code_bitmap = None;
        }
        result
    }
}

#[cfg(test)]
mod tests;
