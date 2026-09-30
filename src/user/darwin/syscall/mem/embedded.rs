//! Supplied-file mappings. The source's extent is rounded to the guest page
//! size so the final partial Darwin page is zero-filled on either guest ABI.

use super::*;
use crate::user::darwin::fd::{EmbeddedFile, OpenFile};

pub(super) fn mmap(
    ctx: &mut Ctx<'_>,
    file: &OpenFile,
    object: &EmbeddedFile,
    fixed: Option<u64>,
    hint: u64,
    size: u64,
    prot: u32,
    flags: u32,
    pos: u64,
    inherit: u32,
) -> SysResult {
    let EmbeddedFile::Supplied { entry, .. } = object else {
        return Err(Errno::ENODEV);
    };
    if entry.is_dir() {
        return Err(Errno::EINVAL);
    }
    let shared = flags & MAP_SHARED != 0;
    if shared && prot & vm::VM_PROT_WRITE != 0 {
        return Err(Errno::EACCES);
    }
    if size == 0 {
        return Ok(Rv::one(0));
    }
    let mask = ctx.proc.vm.page - 1;
    let mut maxprot = if shared {
        vm::VM_PROT_READ | vm::VM_PROT_EXECUTE
    } else {
        vm::VM_PROT_ALL
    };
    if flags & MAP_RESILIENT_CODESIGN != 0 {
        maxprot &= prot;
    }
    let mapping = Mapping {
        perms: vm::perms(prot),
        backing: Backing::Source {
            source: crate::user::darwin::fd::supplied_source(entry, ctx.proc.vm.page)?,
            offset: pos & !mask,
        },
        shared,
        name: file
            .path
            .as_ref()
            .map(|path| Arc::from(String::from_utf8_lossy(path).as_ref())),
        flags: VmFlags::new(maxprot, inherit, 0).bits(),
    };
    let address = match map_at(ctx, fixed, hint, size, mapping.clone()) {
        Err(Errno::ENOMEM) if fixed.is_none() && hint != 0 => map_at(ctx, None, 0, size, mapping)?,
        result => result?,
    };
    Ok(Rv::one(address + (pos & mask)))
}
