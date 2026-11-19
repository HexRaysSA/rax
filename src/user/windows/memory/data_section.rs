//! Private guest frames for immutable selected NT data-section snapshots.
use super::*;
use crate::user::windows::object_namespace::DataSection;

#[derive(Debug)]
pub(super) struct DataView {
    // Retain the selected object after every guest handle has closed.
    _section: Arc<DataSection>,
    kernel_owner: Option<Arc<()>>,
}
mod kernel;
pub(crate) use kernel::KernelDataView;
impl VirtualMemory {
    pub(crate) fn owns_readonly_data_view(&self, base: u64, section: &Arc<DataSection>) -> bool {
        let identity = self
            .data_views
            .get(&base)
            .is_some_and(|view| Arc::ptr_eq(&view._section, section));
        let Some(allocation) = self.allocation(base).filter(|allocation| {
            identity
                && allocation.base == base
                && allocation.size == section.size
                && allocation.protect == prot::READONLY
        }) else {
            return false;
        };
        section.regions.iter().all(|region| {
            allocation
                .runs(
                    region.offset / PAGE_SIZE,
                    (region.offset + region.size) / PAGE_SIZE,
                )
                .into_iter()
                .all(|(_, _, page)| {
                    page.committed == region.bytes.is_some()
                        && page.protect == if page.committed { prot::READONLY } else { 0 }
                        && page.reported.is_none()
                })
        })
    }
    pub(crate) fn is_data_view(&self, address: u64) -> bool {
        self.allocation(address)
            .is_some_and(|a| self.data_views.contains_key(&a.base))
    }
    /// O(B + R log P) for copied committed bytes B, section runs R and VM
    /// state boundaries P. Reserved runs consume no frames. Writable copies
    /// have private frames and never change the selected host snapshot.
    pub(crate) fn map_data_section(
        &mut self,
        section: Arc<DataSection>,
        base: u64,
        offset: u64,
        size: u64,
        protection: u32,
    ) -> Result<(), VmError> {
        if base % ALLOCATION_GRANULARITY != 0
            || offset % ALLOCATION_GRANULARITY != 0
            || size == 0
            || size % PAGE_SIZE != 0
            || offset
                .checked_add(size)
                .is_none_or(|end| end > section.size)
            || !valid_protection(protection)
            || !matches!(protection & 0xFF, 1 | 2 | 8)
        {
            return Err(VmError::InvalidParameter);
        }
        let name =
            (!section.path.is_empty()).then(|| String::from_utf16_lossy(&section.path).into());
        let ordinary_protection = protection & !(prot::NOCACHE | prot::WRITECOMBINE);
        let allocation = self.reserve(
            Some(base),
            size,
            ordinary_protection,
            AllocKind::Mapped,
            false,
            name,
        )?;
        let result = (|| {
            for region in &section.regions {
                let Some(bytes) = &region.bytes else {
                    continue;
                };
                let begin = region.offset.max(offset);
                let end = (region.offset + region.size).min(offset + size);
                if begin >= end {
                    continue;
                }
                let address = base + begin - offset;
                self.commit(address, end - begin, prot::READWRITE)?;
                self.poke(
                    address,
                    &bytes[(begin - region.offset) as usize..(end - region.offset) as usize],
                )
                .map_err(|_| VmError::NoMemory)?;
                self.protect(address, end - begin, ordinary_protection)?;
                self.space
                    .track_private_copies(address, end - begin)
                    .map_err(mm)?;
                // Map-time cache flags are accepted by the native section
                // mapper, while NtProtectVirtualMemory rejects adding them.
                self.allocs
                    .get_mut(&allocation)
                    .expect("owned data reservation")
                    .set_state(
                        (address - base) / PAGE_SIZE,
                        (address + end - begin - base) / PAGE_SIZE,
                        PageState {
                            committed: true,
                            protect: protection,
                            reported: None,
                        },
                    );
            }
            self.allocs
                .get_mut(&allocation)
                .expect("owned data reservation")
                .protect = protection;
            Ok(())
        })();
        if let Err(error) = result {
            let _ = self.release(allocation);
            return Err(error);
        }
        self.pagefile_views.insert(allocation);
        self.data_views.insert(
            allocation,
            DataView {
                _section: section,
                kernel_owner: None,
            },
        );
        Ok(())
    }
}
#[cfg(test)]
mod tests;
