//! Guest-kernel ownership of private copies of selected read-only input views.
//! Guest allocation/protection operations cannot acquire this ownership token.
use super::*;

#[derive(Debug, Clone)]
pub(crate) struct KernelDataView {
    pub(crate) base: u64,
    pub(crate) size: u64,
    token: Arc<()>,
}

impl VirtualMemory {
    fn kernel_data_identity(&self, owner: &KernelDataView) -> bool {
        self.data_views.get(&owner.base).is_some_and(|view| {
            view.kernel_owner
                .as_ref()
                .is_some_and(|token| Arc::ptr_eq(token, &owner.token))
        })
    }
    pub(crate) fn map_kernel_data_view(
        &mut self,
        section: Arc<DataSection>,
        base: u64,
    ) -> Result<KernelDataView, VmError> {
        let size = section.size;
        self.map_data_section(section, base, 0, size, prot::READONLY)?;
        let token = Arc::new(());
        self.data_views
            .get_mut(&base)
            .expect("newly mapped private data view")
            .kernel_owner = Some(token.clone());
        Ok(KernelDataView { base, size, token })
    }

    /// Check allocation identity and the complete current read-only/reserved
    /// page profile, including pages committed by earlier kernel operations.
    pub(crate) fn owns_kernel_data_view(&self, owner: &KernelDataView) -> bool {
        let identity = self.kernel_data_identity(owner);
        self.allocation(owner.base).is_some_and(|allocation| {
            identity
                && allocation.base == owner.base
                && allocation.size == owner.size
                && allocation.kind == AllocKind::Mapped
                && allocation.protect == prot::READONLY
                && allocation
                    .runs(0, owner.size / PAGE_SIZE)
                    .into_iter()
                    .all(|(_, _, page)| {
                        page.protect == if page.committed { prot::READONLY } else { 0 }
                            && page.reported.is_none()
                    })
        })
    }

    pub(crate) fn commit_kernel_data_view(
        &mut self,
        owner: &KernelDataView,
        start: u64,
        len: u64,
    ) -> Result<(), VmError> {
        let (first, end) = page_range(start, len)?;
        if !self.owns_kernel_data_view(owner)
            || first < owner.base
            || end
                > owner
                    .base
                    .checked_add(owner.size)
                    .ok_or(VmError::InvalidAddress)?
        {
            return Err(VmError::InvalidAddress);
        }
        // Only this private, identity-checked entry point admits kernel growth
        // of a data view. Ordinary NtAllocateVirtualMemory retains its guard.
        self.commit_inner(start, len, prot::READONLY, true, false)?;
        Ok(())
    }

    pub(crate) fn write_kernel_data_view(
        &mut self,
        owner: &KernelDataView,
        address: u64,
        bytes: &[u8],
    ) -> Result<(), VmError> {
        let end = address
            .checked_add(bytes.len() as u64)
            .ok_or(VmError::InvalidAddress)?;
        if !self.owns_kernel_data_view(owner)
            || address < owner.base
            || end
                > owner
                    .base
                    .checked_add(owner.size)
                    .ok_or(VmError::InvalidAddress)?
        {
            return Err(VmError::InvalidAddress);
        }
        if bytes.is_empty() {
            return Ok(());
        }
        let allocation = self.allocation(owner.base).expect("verified kernel view");
        let first = (address - owner.base) / PAGE_SIZE;
        let last = (end - owner.base).div_ceil(PAGE_SIZE);
        if allocation
            .runs(first, last)
            .iter()
            .any(|(_, _, page)| !page.committed)
        {
            return Err(VmError::NotCommitted);
        }
        self.poke(address, bytes).map_err(|_| VmError::NoMemory)
    }

    pub(crate) fn retire_kernel_data_view(
        &mut self,
        owner: &KernelDataView,
    ) -> Result<(), VmError> {
        if self.kernel_data_identity(owner) {
            self.release(owner.base)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
