//! File-name metadata follows one allocation and is retired with that owner.
use super::*;
use crate::user::windows::mapped_filename::Filename;

impl VirtualMemory {
    pub(crate) fn record_mapped_filename(
        &mut self,
        base: u64,
        name: Filename,
    ) -> Result<(), VmError> {
        if !self.allocation(base).is_some_and(|allocation| {
            allocation.base == base
                && matches!(allocation.kind, AllocKind::Image | AllocKind::Mapped)
        }) {
            return Err(VmError::InvalidAddress);
        }
        self.mapped_filenames.insert(base, name);
        Ok(())
    }

    pub(crate) fn mapped_filename(&self, address: u64) -> Result<Option<Vec<u16>>, String> {
        let Some(allocation) = self.allocation(address) else {
            return Ok(None);
        };
        if let Some(name) = self.mapped_filenames.get(&allocation.base) {
            return name.read().map(Some).map_err(|error| error.to_string());
        }
        if let Some(view) = self.section_view(address) {
            #[cfg(windows)]
            if let Some(result) = view.section.mapped_filename() {
                return result.map(Some).map_err(|error| error.to_string());
            }
            let _ = view;
            return Err("mapped image has no captured backing-file name".into());
        }
        if allocation.kind == AllocKind::Image {
            return Err("mapped image has no selected backing-file name".into());
        }
        Ok(None)
    }
}
