//! Memory entries (`mach_make_memory_entry`, `vm_map` of an entry;
//! `osfmk/vm/vm_memory_entry.c`), for the memory the guest shares with the
//! host's services.
//!
//! An entry is a host memory entry behind a proxy port, over a host file
//! the guest's memory is (or becomes) a shared mapping of: what a service
//! that maps the entry writes, the guest reads, and the other way round.
//! An entry of guest memory rebacks the range with such a file (its
//! contents kept) unless one already backs it; `MAP_MEM_NAMED_CREATE`
//! makes one of new zero-filled memory, and `MAP_MEM_VM_COPY` one of a
//! copy. Mapping an entry the bridge made maps its file shared (or a copy
//! of it); an entry a service made is mapped as a copy of its contents.

use std::os::unix::fs::FileExt;
use std::sync::Arc;

use crate::user::darwin::mach::ipc::Port;
use crate::user::darwin::mach::kr::{self, KernReturn};
use crate::user::darwin::syscall::Ctx;
use crate::user::darwin::vm::{self, VmFlags};
use crate::user::mm::{Backing, Mapping, SharedObject};

/// `MAP_MEM_*` flags of a `mach_make_memory_entry` permission.
pub mod map_mem {
    /// `MAP_MEM_ONLY`: change the cache mode of an existing entry.
    pub const ONLY: i32 = 0x01_0000;
    /// `MAP_MEM_NAMED_CREATE`: new memory, not the caller's.
    pub const NAMED_CREATE: i32 = 0x02_0000;
    /// `MAP_MEM_PURGABLE`.
    pub const PURGABLE: i32 = 0x04_0000;
    /// `MAP_MEM_NAMED_REUSE`.
    pub const NAMED_REUSE: i32 = 0x08_0000;
    /// `MAP_MEM_USE_DATA_ADDR`.
    pub const USE_DATA_ADDR: i32 = 0x10_0000;
    /// `MAP_MEM_VM_COPY`: a copy of the caller's memory.
    pub const VM_COPY: i32 = 0x20_0000;
    /// `MAP_MEM_VM_SHARE`: the caller's memory itself.
    pub const VM_SHARE: i32 = 0x40_0000;
    /// `MAP_MEM_4K_DATA_ADDR`.
    pub const DATA_ADDR_4K: i32 = 0x80_0000;
}

/// A memory entry the bridge made: the object behind it and the part.
#[derive(Clone, Debug)]
pub struct Entry {
    /// The host file.
    pub object: Arc<SharedObject>,
    /// Where the entry starts in it.
    pub offset: u64,
    /// Its size.
    pub len: u64,
}

/// `mach_make_memory_entry_64(target, size, offset, permission, parent)`
/// with no parent: the entry's port and its size.
pub fn make(
    ctx: &mut Ctx<'_>,
    size: u64,
    offset: u64,
    perm: i32,
) -> Result<(Arc<Port>, u64), KernReturn> {
    use map_mem::*;
    if perm & (ONLY | NAMED_REUSE) != 0 {
        return Err(kr::KERN_INVALID_ARGUMENT);
    }
    let prot = perm as u32 & vm::VM_PROT_ALL;
    let page = ctx.proc.vm.page;
    let entry = if perm & NAMED_CREATE != 0 {
        let len = size
            .checked_add(page - 1)
            .ok_or(kr::KERN_INVALID_ARGUMENT)?
            & !(page - 1);
        if len == 0 {
            return Err(kr::KERN_INVALID_ARGUMENT);
        }
        let object = SharedObject::anonymous(len).map_err(|_| kr::KERN_RESOURCE_SHORTAGE)?;
        Entry {
            object: Arc::new(object),
            offset: 0,
            len,
        }
    } else {
        of_guest(ctx, offset, size, perm & VM_COPY != 0)?
    };
    let len = entry.len;
    let port = crate::user::darwin::bridge::make_entry(ctx.proc, entry, prot)?;
    Ok((port, len))
}

/// An entry of the guest's memory `[offset, offset + size)` (whole pages),
/// which must be mapped: its own backing file when one file backs it all,
/// else a new file with its contents, which then backs the range too
/// unless `copy` asks for a copy only.
fn of_guest(ctx: &mut Ctx<'_>, offset: u64, size: u64, copy: bool) -> Result<Entry, KernReturn> {
    let page = ctx.proc.vm.page;
    let start = offset & !(page - 1);
    let end = offset
        .checked_add(size)
        .and_then(|e| e.checked_add(page - 1))
        .ok_or(kr::KERN_INVALID_ARGUMENT)?
        & !(page - 1);
    let len = end - start;
    if len == 0 {
        return Err(kr::KERN_INVALID_ARGUMENT);
    }
    let vmas = ctx.proc.space.vmas_in(start, end);
    let covered = vmas.first().is_some_and(|v| v.start <= start)
        && vmas.last().is_some_and(|v| v.end >= end)
        && vmas.windows(2).all(|w| w[0].end == w[1].start);
    if !covered {
        return Err(kr::KERN_INVALID_ADDRESS);
    }
    if !copy
        && vmas.len() == 1
        && vmas[0].shared
        && let Backing::Shared { object, offset: o } = &vmas[0].backing
    {
        return Ok(Entry {
            object: object.clone(),
            offset: o + (start - vmas[0].start),
            len,
        });
    }
    let mut data = vec![0u8; len as usize];
    ctx.proc
        .space
        .read_raw(start, &mut data)
        .map_err(|_| kr::KERN_INVALID_ADDRESS)?;
    let object = SharedObject::anonymous(len).map_err(|_| kr::KERN_RESOURCE_SHORTAGE)?;
    object
        .host_file()
        .write_all_at(&data, 0)
        .map_err(|_| kr::KERN_RESOURCE_SHORTAGE)?;
    let object = Arc::new(object);
    if !copy {
        // The range becomes a shared mapping of the file, each part with
        // its own protections and attributes.
        for v in &vmas {
            let (s, e) = (v.start.max(start), v.end.min(end));
            let mapping = Mapping {
                perms: v.perms,
                backing: Backing::Shared {
                    object: object.clone(),
                    offset: s - start,
                },
                shared: true,
                name: v.name.clone(),
                flags: v.flags,
            };
            ctx.proc
                .space
                .map(s, e - s, mapping)
                .map_err(super::vm::mm_kr)?;
        }
    }
    Ok(Entry {
        object,
        offset: 0,
        len,
    })
}

/// The mapping `vm_map` enters for entry `e` from `offset`: the file shared,
/// or (`copy`) a private copy of it.
pub fn mapping(
    e: &Entry,
    offset: u64,
    copy: bool,
    cur: u32,
    max: u32,
    inh: u32,
    tag: u32,
) -> Mapping {
    let flags = VmFlags::new(max, inh, tag).bits();
    if copy {
        return Mapping {
            flags,
            backing: Backing::Anonymous,
            ..Mapping::anonymous(vm::perms(cur))
        };
    }
    Mapping {
        perms: vm::perms(cur),
        backing: Backing::Shared {
            object: e.object.clone(),
            offset: e.offset + offset,
        },
        shared: true,
        name: None,
        flags,
    }
}

/// The contents of `len` bytes of entry `e` from `offset` (for a copy).
pub fn contents(e: &Entry, offset: u64, len: u64) -> Vec<u8> {
    let mut data = vec![0u8; len as usize];
    let _ = e.object.read_at(e.offset + offset, &mut data);
    data
}
