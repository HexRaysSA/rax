//! Real pagefile aliases, unique backing charges and identity-safe retirement.
use super::*;
use crate::user::mm::{Backing, SharedObject};

#[derive(Debug, Clone)]
pub(crate) struct SharedViewOwner {
    pub(crate) base: u64,
    pub(crate) size: u64,
    token: Arc<()>,
}

#[derive(Debug)]
struct SharedView {
    object: Arc<SharedObject>,
    offset: u64,
    size: u64,
    token: Arc<()>,
}

#[derive(Debug, Default)]
pub(super) struct SharedViews {
    views: BTreeMap<u64, SharedView>,
    // The retained view Arcs prevent identity reuse while a charge exists.
    pages: BTreeMap<(usize, u64), u32>,
}

impl VirtualMemory {
    /// Unique committed pagefile-section backing, counted once across aliases.
    pub(super) fn shared_committed_bytes(&self) -> u64 {
        self.shared_views.pages.len() as u64 * PAGE_SIZE
    }
    pub(crate) fn owns_shared_view(&self, owner: &SharedViewOwner) -> bool {
        self.shared_views
            .views
            .get(&owner.base)
            .is_some_and(|view| view.size == owner.size && Arc::ptr_eq(&view.token, &owner.token))
    }
    pub(crate) fn is_shared_view(&self, address: u64) -> bool {
        self.allocation(address)
            .is_some_and(|allocation| self.shared_views.views.contains_key(&allocation.base))
    }

    /// Maps real shared pages; the same object page consumes the commitment
    /// budget once across aliases. O(P log R + M log M) time and O(P + M)
    /// additional metadata/scratch for P object pages, R charged pages and M
    /// allocation/mapping runs when choosing an address automatically.
    /// The narrow caller validates the section's access/protection attributes.
    pub(crate) fn map_shared_view(
        &mut self,
        object: Arc<SharedObject>,
        base: Option<u64>,
        offset: u64,
        size: u64,
    ) -> Result<SharedViewOwner, VmError> {
        self.map_shared_view_with_protection(object, base, offset, size, prot::READWRITE)
    }

    /// Initial view protection is also its allocation protection. A readonly
    /// alias retains the same real backing without acquiring writable access.
    pub(crate) fn map_shared_view_with_protection(
        &mut self,
        object: Arc<SharedObject>,
        base: Option<u64>,
        offset: u64,
        size: u64,
        protection: u32,
    ) -> Result<SharedViewOwner, VmError> {
        if size == 0
            || !object.writable()
            || !matches!(protection, prot::READONLY | prot::READWRITE)
            || size % PAGE_SIZE != 0
            || offset % PAGE_SIZE != 0
            || offset
                .checked_add(size)
                .is_none_or(|end| end > object.len())
            || base.is_some_and(|base| base % ALLOCATION_GRANULARITY != 0)
        {
            return Err(VmError::InvalidParameter);
        }
        let identity = Arc::as_ptr(&object) as usize;
        let first = offset / PAGE_SIZE;
        let end = first + size / PAGE_SIZE;
        let mut newly_charged = 0;
        for page in first..end {
            match self.shared_views.pages.get(&(identity, page)) {
                None => newly_charged += PAGE_SIZE,
                Some(&u32::MAX) => return Err(VmError::NoMemory),
                Some(_) => {}
            }
        }
        let charge = self
            .committed
            .checked_add(newly_charged)
            .filter(|charge| *charge <= self.commit_limit)
            .ok_or(VmError::CommitmentLimit)?;
        let base = self.reserve(base, size, protection, AllocKind::Mapped, false, None)?;
        let mapping = Mapping {
            perms: effective_perms(protection),
            backing: Backing::Shared {
                object: object.clone(),
                offset,
            },
            shared: true,
            name: None,
            flags: 0,
        };
        if let Err(error) = self.space.map(base, size, mapping) {
            let _ = self.release(base);
            return Err(mm(error));
        }
        // The reservation is unique and still present; no fallible operation
        // follows this publication of committed metadata and page references.
        self.allocs
            .get_mut(&base)
            .expect("new shared reservation")
            .set_state(
                0,
                size / PAGE_SIZE,
                PageState {
                    committed: true,
                    protect: protection,
                    reported: None,
                },
            );
        for page in first..end {
            *self.shared_views.pages.entry((identity, page)).or_default() += 1;
        }
        let token = Arc::new(());
        self.shared_views.views.insert(
            base,
            SharedView {
                object,
                offset,
                size,
                token: token.clone(),
            },
        );
        self.pagefile_views.insert(base);
        self.publish_commitment(charge);
        Ok(SharedViewOwner { base, size, token })
    }

    pub(super) fn released_shared_charge(&self, base: u64) -> Option<u64> {
        let view = self.shared_views.views.get(&base)?;
        let identity = Arc::as_ptr(&view.object) as usize;
        let first = view.offset / PAGE_SIZE;
        let end = first + view.size / PAGE_SIZE;
        Some(
            (first..end)
                .filter(|page| self.shared_views.pages.get(&(identity, *page)) == Some(&1))
                .count() as u64
                * PAGE_SIZE,
        )
    }

    pub(super) fn forget_shared_view(&mut self, base: u64) {
        let Some(view) = self.shared_views.views.remove(&base) else {
            return;
        };
        let identity = Arc::as_ptr(&view.object) as usize;
        let first = view.offset / PAGE_SIZE;
        let end = first + view.size / PAGE_SIZE;
        for page in first..end {
            let key = (identity, page);
            // Every registered view acquired each reference after an overflow
            // check; only removing that view releases those exact references.
            let count = self
                .shared_views
                .pages
                .get_mut(&key)
                .expect("shared page reference");
            *count -= 1;
            if *count == 0 {
                self.shared_views.pages.remove(&key);
            }
        }
    }

    /// Last-handle retirement cannot free a private or mapped replacement at
    /// the same address after a caller explicitly unmapped the original view.
    pub(crate) fn retire_shared_view(&mut self, owner: &SharedViewOwner) -> Result<(), VmError> {
        if self.owns_shared_view(owner) {
            self.release(owner.base)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
