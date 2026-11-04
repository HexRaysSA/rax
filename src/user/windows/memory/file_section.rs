//! File views share the admitted file's pages until a private first write.
use super::*;
use crate::user::mm::Backing;
use crate::user::windows::object_namespace::{FileSection, file_data};

#[derive(Debug)]
pub(super) struct FileView {
    pub(super) section: Arc<FileSection>,
    initial: u32,
}

impl VirtualMemory {
    pub(crate) fn has_file_section(
        &self,
        identity: &crate::user::windows::fs::FileIdentity,
    ) -> bool {
        self.file_views
            .values()
            .any(|view| &view.section.lifetime.identity == identity)
    }

    pub(crate) fn is_file_view(&self, address: u64) -> bool {
        self.allocation(address)
            .is_some_and(|a| self.file_views.contains_key(&a.base))
    }

    /// O(log A + V log V) metadata work for A allocations and V replaced VMAs;
    /// no guest frames are populated. The existing no-paging-file frame budget
    /// conservatively reserves one view-sized bound, returned on final unmap.
    pub(crate) fn map_file_section(
        &mut self,
        section: Arc<FileSection>,
        base: u64,
        offset: u64,
        size: u64,
        protection: u32,
    ) -> Result<(), VmError> {
        let maximum = section
            .size
            .checked_add(PAGE_SIZE - 1)
            .ok_or(VmError::InvalidParameter)?
            & !(PAGE_SIZE - 1);
        if base % ALLOCATION_GRANULARITY != 0
            || offset % ALLOCATION_GRANULARITY != 0
            || size == 0
            || size % PAGE_SIZE != 0
            || offset.checked_add(size).is_none_or(|end| end > maximum)
            || !valid_protection(protection)
        {
            return Err(VmError::InvalidParameter);
        }
        if !file_data::allows(section.protection, protection) {
            return Err(VmError::SectionProtection);
        }
        let charge = self
            .committed
            .checked_add(size)
            .filter(|n| *n <= self.commit_limit)
            .ok_or(VmError::CommitmentLimit)?;
        let copy = !matches!(protection & 0xFF, prot::READWRITE | prot::EXECUTE_READWRITE);
        let mapping = Mapping {
            perms: effective_perms(protection),
            backing: Backing::Shared {
                object: section.backing.clone(),
                offset,
            },
            shared: !copy,
            name: None,
            flags: 0,
        };
        // Map-time cache modifiers are accepted for file views; ordinary
        // mapped reservations and later protection changes retain their checks.
        let ordinary = protection & !(prot::NOCACHE | prot::WRITECOMBINE);
        let allocation =
            self.reserve(Some(base), size, ordinary, AllocKind::Mapped, false, None)?;
        let result = if copy {
            self.space.map_copy_on_write(base, size, mapping)
        } else {
            self.space.map(base, size, mapping)
        };
        if let Err(error) = result {
            let _ = self.release(allocation);
            return Err(mm(error));
        }
        self.allocs
            .get_mut(&base)
            .expect("owned file reservation")
            .set_state(
                0,
                size / PAGE_SIZE,
                PageState {
                    committed: true,
                    protect: protection,
                    reported: None,
                },
            );
        self.allocs
            .get_mut(&base)
            .expect("owned file reservation")
            .protect = protection;
        self.file_views.insert(
            base,
            FileView {
                section,
                initial: protection,
            },
        );
        self.committed = charge;
        Ok(())
    }

    pub(super) fn check_file_protection(&self, base: u64, protection: u32) -> Result<(), VmError> {
        if let Some(view) = self.file_views.get(&base) {
            if protection & (prot::NOCACHE | prot::WRITECOMBINE) != 0 {
                return Err(VmError::InvalidParameter4);
            }
            if !file_data::allows(view.initial, protection) {
                return Err(VmError::SectionProtection);
            }
        }
        Ok(())
    }
}
