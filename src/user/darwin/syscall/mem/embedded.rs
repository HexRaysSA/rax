//! Supplied-file mappings. Guest-private workspace files can share live
//! backing with their descriptors. Both kinds use Darwin guest page sizes.

use super::*;
use crate::user::darwin::fd::{EmbeddedFile, OpenFile};
use crate::user::supplied_fs::Kind;

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
    if object
        .workspace()
        .map(|(_, access)| access)
        .or_else(|| object.resource().map(|(_, access)| access))
        .is_some_and(|access| access == crate::user::darwin::io::O_WRONLY)
    {
        return Err(Errno::EACCES);
    }
    let Some(entry) = object.entry() else {
        return Err(Errno::ENODEV);
    };
    if entry.is_dir() {
        return Err(Errno::EINVAL);
    }
    let shared = flags & MAP_SHARED != 0;
    let workspace = object.workspace();
    let writable = workspace.is_some_and(|(_, access)| access == O_RDWR);
    if shared && !writable && prot & vm::VM_PROT_WRITE != 0 {
        return Err(Errno::EACCES);
    }
    if size == 0 {
        return Ok(Rv::one(0));
    }
    let mask = ctx.proc.vm.page - 1;
    let mut maxprot = if shared && !writable {
        vm::VM_PROT_READ | vm::VM_PROT_EXECUTE
    } else {
        vm::VM_PROT_ALL
    };
    if flags & MAP_RESILIENT_CODESIGN != 0 {
        maxprot &= prot;
    }
    let offset = pos & !mask;
    let backing = match &entry.kind {
        Kind::Workspace(file) if shared && workspace.is_some() => Backing::Shared {
            object: file.shared_mapping(writable, ctx.proc.vm.page)?,
            offset,
        },
        _ => Backing::Source {
            source: match object.resource() {
                Some((fork, _)) => {
                    crate::user::darwin::fd::resource_source(fork, ctx.proc.vm.page)?
                }
                None => crate::user::darwin::fd::supplied_source(entry, ctx.proc.vm.page)?,
            },
            offset,
        },
    };
    let mapping = Mapping {
        perms: vm::perms(prot),
        backing,
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
