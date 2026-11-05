//! Installed projected images share their selected kernel address contracts.
use super::*;
use crate::user::windows::object_namespace::{ImageSection, ImageTemplate};
#[cfg(test)]
#[path = "native_image_tests.rs"]
mod tests;

pub(super) fn select(
    p: &mut Proc,
    pe: &PeImage,
    path: Option<&Path>,
) -> Result<Option<super::super::native::SelectedImage>, LoadError> {
    let Some(runtime) = p.native.as_ref() else {
        return Ok(None);
    };
    let Some(path) = path else {
        return Ok(None);
    };
    runtime.installed_view(p.arch, pe, path).map_err(|error| {
        LoadError::new(
            STATUS_NOT_SUPPORTED,
            format!("selected installed image: {error}"),
        )
    })
}

pub(super) fn map_selected(
    p: &mut Proc,
    pe: &PeImage,
    section: Arc<ImageSection>,
    image: &ImageTemplate,
) -> Result<u64, LoadError> {
    // File metadata still owns the module/export/unwind interpretation. Admit
    // this kernel snapshot only for that exact installed file's PE identity.
    let h = pe.headers();
    let at = h.nt_offset as usize;
    let bytes = &image.bytes;
    if image.machine != h.machine
        || image.bytes.len() != pe.mapped_size() as usize
        || bytes.get(0x3C..0x40) != Some(&(h.nt_offset).to_le_bytes())
        || bytes.get(at + 8..at + 12) != Some(&h.time_date_stamp.to_le_bytes())
        || section.size != image.bytes.len() as u64
    {
        return Err(LoadError::new(
            STATUS_INVALID_IMAGE_FORMAT,
            "installed file and pinned section identities disagree",
        ));
    }
    let base = image.preferred;
    // Native default guard branches can reference this shared preferred base.
    // A fallback placement would silently break those cross-image branches.
    if !p.vm.is_free(base, image.allocation_size()) {
        return Err(LoadError::new(
            STATUS_CONFLICTING_ADDRESSES,
            "selected installed preferred image and extension range is occupied",
        ));
    }
    p.vm.map_section_image(
        section,
        image,
        base,
        base,
        image.allocation_size(),
        0,
        image.bytes.len() as u64,
        false,
        false,
    )
    .map_err(|e| {
        LoadError::new(
            e.status(),
            "cannot map selected installed image and extensions",
        )
    })?;
    Ok(base)
}
