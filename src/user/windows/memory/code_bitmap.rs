//! Sparse guest-owned code tags read by the installed ARM64EC kernel extension.
//! Native controls qualify NOACCESS/MEM_MAPPED reservation, sparse READONLY
//! commitment, and sticky EC tags across free and ordinary exact-address reuse.
use super::*;
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
            self.commit_inner(page, PAGE_SIZE, prot::READONLY, true)?;
        }
        Ok(())
    }
    pub(crate) fn code_bitmap_address(&self) -> Result<Option<u64>, VmError> {
        self.code_bitmap
            .as_ref()
            .map(|_| self.code_bitmap_base())
            .transpose()
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

    pub(super) fn publish_ec_image(
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
