//! File-name metadata follows one allocation and is retired with that owner.
use super::*;
use crate::user::windows::fs::FileIdentity;
use crate::user::windows::mapped_filename::Filename;
use crate::user::windows::nt::status::*;
use crate::user::windows::object_namespace::{FileSection, ImageSection};

enum MappedFile<'a> {
    Image(&'a ImageSection),
    Data(&'a FileSection),
    #[cfg(windows)]
    Loader(&'a Filename),
}

impl MappedFile<'_> {
    fn identity(&self) -> Option<&FileIdentity> {
        match self {
            Self::Image(section) => section.file_identity(),
            Self::Data(section) => Some(&section.lifetime.identity),
            #[cfg(windows)]
            Self::Loader(_) => None,
        }
    }

    #[cfg(windows)]
    fn with_native_view<T>(
        &self,
        use_view: impl FnOnce(&crate::user::windows::mapped_filename::native::View) -> Result<T, String>,
    ) -> Result<T, String> {
        match self {
            Self::Image(section) => use_view(&section.native_file_view()?),
            Self::Data(section) => use_view(section.native_filename()?.native_view()?),
            Self::Loader(filename) => use_view(filename.native_view()?),
        }
    }
}

impl VirtualMemory {
    /// Compare the backing files of two allocated guest views. The first
    /// address must belong to an image. The addresses need not be view bases.
    /// O(log A) for A guest allocations, plus optional native metadata work.
    pub(crate) fn compare_mapped_files(&self, image: u64, file: u64) -> Result<u32, String> {
        let (Some(image), Some(file)) = (self.allocation(image), self.allocation(file)) else {
            return Ok(STATUS_INVALID_ADDRESS);
        };
        if image.kind != AllocKind::Image {
            return Ok(STATUS_CONFLICTING_ADDRESSES);
        }
        let (Some(image), Some(file)) = (self.mapped_file(image), self.mapped_file(file)) else {
            return Ok(STATUS_CONFLICTING_ADDRESSES);
        };
        if let (Some(image), Some(file)) = (image.identity(), file.identity()) {
            return Ok(if image == file {
                STATUS_SUCCESS
            } else {
                STATUS_NOT_SAME_DEVICE
            });
        }
        #[cfg(windows)]
        return image
            .with_native_view(|image| file.with_native_view(|file| image.compare_file(file)));
        #[cfg(not(windows))]
        Err("image section has no retained file identity".into())
    }

    fn mapped_file(&self, allocation: &Allocation) -> Option<MappedFile<'_>> {
        if let Some(view) = self.section_views.get(&allocation.base) {
            return Some(MappedFile::Image(&view.section));
        }
        if let Some(view) = self.file_views.get(&allocation.base) {
            return Some(MappedFile::Data(&view.section));
        }
        #[cfg(windows)]
        if allocation.kind == AllocKind::Image {
            return self
                .mapped_filenames
                .get(&allocation.base)
                .map(MappedFile::Loader);
        }
        None
    }

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
        if let Some(view) = self.file_views.get(&allocation.base) {
            return view
                .section
                .mapped_filename()?
                .map(Some)
                .ok_or_else(|| "mapped data file has no native backing-file name".to_owned());
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
