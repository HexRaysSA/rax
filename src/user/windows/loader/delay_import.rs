//! Resolve a single RVA-based delay import from a mapped PE.

use super::{GuestImage, LoadError, Modules, SymRef};
use crate::user::image::pe::PeKind;
use crate::user::image::pe::RvaSource;
use crate::user::image::pe::imports::{
    DELAY_DESCRIPTOR_SIZE, DelayDescriptor, ImportRef, MAX_IMPORT_NAME,
};
use crate::user::windows::nt::status::{STATUS_INVALID_PARAMETER, STATUS_NOT_SUPPORTED};
use crate::user::windows::process::Proc;

pub(crate) struct DelayImport {
    pub parent: usize,
    pub library: String,
    pub symbol: SymRef,
    pub slots: DelaySlots,
}

#[derive(Clone, Copy)]
pub(crate) struct DelaySlots {
    pub module: u64,
    pub thunk: u64,
}

fn invalid() -> LoadError {
    LoadError::new(
        STATUS_INVALID_PARAMETER,
        "invalid PE delay import descriptor or thunk",
    )
}

fn in_image(modules: &Modules, parent: usize, rva: u32, size: u64) -> Option<u64> {
    let image = &modules.list[parent];
    let rva = u64::from(rva);
    (rva != 0 && rva % size == 0 && rva + size <= image.size).then_some(image.base + rva)
}

pub(crate) fn read(
    p: &Proc,
    base: u64,
    descriptor: u64,
    thunk: u64,
) -> Result<DelayImport, LoadError> {
    let parent = p.modules.by_base(base).ok_or_else(invalid)?;
    let image = &p.modules.list[parent];
    let directory = image.delay_imports;
    let offset = descriptor
        .checked_sub(base + u64::from(directory.rva))
        .filter(|&offset| {
            directory.is_present()
                && offset.is_multiple_of(DELAY_DESCRIPTOR_SIZE)
                && offset <= u64::from(directory.size).saturating_sub(DELAY_DESCRIPTOR_SIZE)
                && u64::from(directory.size) >= DELAY_DESCRIPTOR_SIZE
        })
        .ok_or_else(invalid)?;
    let rva = u64::from(directory.rva) + offset;
    let source = GuestImage {
        mem: &p.space,
        base,
        size: image.size,
    };
    let desc = DelayDescriptor::read_at(&source, rva).map_err(|_| invalid())?;
    if desc.attributes != 1 || desc.unload_iat_rva != 0 {
        return Err(LoadError::new(
            STATUS_NOT_SUPPORTED,
            "legacy or explicitly unloadable delay import",
        ));
    }
    if desc.name_rva == 0 || desc.iat_rva == 0 || desc.name_table_rva == 0 {
        return Err(invalid());
    }
    let name = source
        .cstr_at(u64::from(desc.name_rva), MAX_IMPORT_NAME)
        .map_err(|_| invalid())?
        .filter(|name| !name.is_empty())
        .ok_or_else(invalid)?;
    let width = p.arch.ptr_size();
    let kind = if width == 8 {
        PeKind::Pe32Plus
    } else {
        PeKind::Pe32
    };
    let module = in_image(&p.modules, parent, desc.module_handle_rva, width)
        .filter(|&module| module != thunk)
        .ok_or_else(invalid)?;
    let entry = desc
        .thunks(&source, kind)
        .map_err(|_| invalid())?
        .into_iter()
        .find(|entry| in_image(&p.modules, parent, entry.iat_slot, width) == Some(thunk))
        .ok_or_else(invalid)?;
    let symbol = match entry.symbol {
        ImportRef::Name { hint, name } => SymRef::Name(name, Some(hint)),
        ImportRef::Ordinal(ordinal) => SymRef::Ordinal(u32::from(ordinal)),
    };
    Ok(DelayImport {
        parent,
        library: String::from_utf8_lossy(&name).into_owned(),
        symbol,
        slots: DelaySlots { module, thunk },
    })
}
