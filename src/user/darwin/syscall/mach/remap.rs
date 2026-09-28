//! `mach_vm_remap` and `mach_vm_remap_new` on the calling task's own map
//! (`mach_vm_remap_external` and `mach_vm_remap_new_external` in
//! `osfmk/vm/vm_user.c`; `vm_map_remap` and `vm_map_remap_extract` in
//! `osfmk/vm/vm_map.c`).
//!
//! A shared remap (`copy` false) maps the source's memory itself a second
//! time. A part of the source that is a shared mapping maps its object;
//! a private part first becomes a shared mapping of a new object holding
//! its contents (as XNU shares an entry's object, shadowing a
//! copy-on-write one first), so that a store through either mapping is
//! seen through the other. A copy maps private memory holding the
//! contents.

use std::sync::Arc;

use crate::user::darwin::mach::kr::{self, KernReturn};
use crate::user::darwin::syscall::Ctx;
use crate::user::darwin::syscall::mach::vm::{locate, mm_kr};
use crate::user::darwin::vm::{self, VmFlags};
use crate::user::mm::{Backing, Mapping, SharedObject, Vma};

/// `VM_FLAGS_USER_REMAP`: `FIXED`, `ANYWHERE`, `RANDOM_ADDR`, `OVERWRITE`,
/// `RETURN_DATA_ADDR`, `RESILIENT_CODESIGN`, `RESILIENT_MEDIA`.
const VM_FLAGS_USER_REMAP: u32 = 0x1 | 0x8 | 0x4000 | 0x10_0000 | 0x20 | 0x40;
/// `VM_FLAGS_RETURN_DATA_ADDR`: the address returned is the data's, with
/// the source's offset in its page.
const VM_FLAGS_RETURN_DATA_ADDR: u32 = 0x10_0000;
/// `VM_FLAGS_RESILIENT_MEDIA`, which only a copy may ask for.
const VM_FLAGS_RESILIENT_MEDIA: u32 = 0x40;

/// The protections of a remap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protections {
    /// `mach_vm_remap`: the new mapping keeps the source's, and the call
    /// reports the strictest of them.
    Legacy,
    /// `mach_vm_remap_new`: the new mapping gets these, which the source
    /// must allow (a copy needs only readable memory).
    New { cur: u32, max: u32 },
}

/// A remap's result: the address, and the protections reported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Remapped {
    pub addr: u64,
    pub cur: u32,
    pub max: u32,
}

/// The source task a remap names: the calling task's control port, its
/// read port (which `mach_vm_remap_new` takes for a copy or for memory it
/// maps at most readable), or another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Control,
    Read,
    Other,
}

/// Remaps `size` bytes at `src` of task `from` to `target` (or anywhere at
/// or above it) with `flags`, as a copy or shared, with `prot`, inherited
/// as `inheritance`.
#[allow(clippy::too_many_arguments)]
pub fn remap(
    ctx: &mut Ctx<'_>,
    target: u64,
    size: u64,
    mask: u64,
    mut flags: u32,
    from: Source,
    src: u64,
    copy: bool,
    prot: Protections,
    inheritance: u32,
) -> Result<Remapped, KernReturn> {
    if flags & !VM_FLAGS_USER_REMAP != 0 {
        return Err(kr::KERN_INVALID_ARGUMENT);
    }
    // The source's map: a control port's, or (mach_vm_remap_new copying,
    // or mapping at most readable memory) a read port's.
    let mut readable = false;
    if let Protections::New { cur, max } = prot {
        flags |= VM_FLAGS_RETURN_DATA_ADDR;
        if cur & !vm::VM_PROT_ALL != 0 || max & !vm::VM_PROT_ALL != 0 || cur & !max != 0 {
            return Err(kr::KERN_INVALID_ARGUMENT);
        }
        let wx = vm::VM_PROT_WRITE | vm::VM_PROT_EXECUTE;
        if max & wx == wx {
            return Err(kr::KERN_PROTECTION_FAILURE);
        }
        readable = copy || max == vm::VM_PROT_READ || max == vm::VM_PROT_NONE;
    }
    match from {
        Source::Control => {}
        Source::Read if readable => {}
        _ => return Err(kr::KERN_INVALID_ARGUMENT),
    }
    // vm_map_remap_sanitize: the inheritance, then the source range.
    if inheritance > vm::VM_INHERIT_NONE || size == 0 {
        return Err(kr::KERN_INVALID_ARGUMENT);
    }
    let page_mask = ctx.proc.vm.page - 1;
    let start = src & !page_mask;
    let (end, data_offset) = if flags & VM_FLAGS_RETURN_DATA_ADDR != 0 {
        let end = src
            .checked_add(size)
            .and_then(|e| e.checked_add(page_mask))
            .ok_or(kr::KERN_INVALID_ARGUMENT)?
            & !page_mask;
        (end, src & page_mask)
    } else {
        // The legacy rounding: the start truncated, the size rounded up
        // on its own.
        let len = size
            .checked_add(page_mask)
            .ok_or(kr::KERN_INVALID_ARGUMENT)?
            & !page_mask;
        (start.checked_add(len).ok_or(kr::KERN_INVALID_ARGUMENT)?, 0)
    };
    if flags & VM_FLAGS_RESILIENT_MEDIA != 0 && !copy {
        return Err(kr::KERN_INVALID_ARGUMENT);
    }
    // vm_map_remap_extract: every page mapped, each entry allowing what
    // the new mapping needs.
    let vmas = ctx.proc.space.vmas_in(start, end);
    let covered = vmas.first().is_some_and(|v| v.start <= start)
        && vmas.last().is_some_and(|v| v.end >= end)
        && vmas.windows(2).all(|w| w[0].end == w[1].start);
    if !covered {
        return Err(kr::KERN_INVALID_ADDRESS);
    }
    let (mut cur_out, mut max_out) = (vm::VM_PROT_ALL, vm::VM_PROT_ALL);
    for v in &vmas {
        let (p, m) = (vm::prot(v.perms), VmFlags::from_bits(v.flags).max_prot());
        match prot {
            Protections::Legacy => {
                cur_out &= p;
                max_out &= m;
            }
            Protections::New { cur, max } => {
                let (need_cur, need_max) = if copy {
                    (vm::VM_PROT_NONE, vm::VM_PROT_READ)
                } else {
                    (cur, max)
                };
                if p & need_cur != need_cur || m & need_max != need_max {
                    return Err(kr::KERN_PROTECTION_FAILURE);
                }
            }
        }
    }
    if let Protections::New { cur, max } = prot {
        (cur_out, max_out) = (cur, max);
    }
    let (at, _) = locate(ctx, target, end - start, mask, flags)?;
    // What each part maps: its memory's object and offset, or (a copy) its
    // contents.
    let mut parts = Vec::with_capacity(vmas.len());
    for v in &vmas {
        let (s, e) = (v.start.max(start), v.end.min(end));
        let source = if copy {
            let mut data = vec![0u8; (e - s) as usize];
            ctx.proc
                .space
                .read_raw(s, &mut data)
                .map_err(|_| kr::KERN_MEMORY_ERROR)?;
            Part::Copy(data)
        } else {
            let (object, offset) = share(ctx, v, s, e)?;
            Part::Shared(object, offset)
        };
        parts.push((s - start, e - s, v.clone(), source));
    }
    for (delta, len, v, source) in parts {
        let flags = VmFlags::from_bits(v.flags);
        let (perms, max) = match prot {
            Protections::Legacy => (v.perms, flags.max_prot()),
            Protections::New { cur, max } => (vm::perms(cur), max),
        };
        let attrs = VmFlags::new(max, inheritance, flags.tag()).bits();
        let (backing, shared, data) = match source {
            Part::Copy(data) => (Backing::Anonymous, false, Some(data)),
            Part::Shared(object, offset) => (Backing::Shared { object, offset }, true, None),
        };
        let mapping = Mapping {
            perms,
            backing,
            shared,
            name: v.name.clone(),
            flags: attrs,
        };
        ctx.proc
            .space
            .map(at + delta, len, mapping)
            .map_err(mm_kr)?;
        if let Some(d) = data {
            ctx.proc
                .space
                .write_raw(at + delta, &d)
                .map_err(|_| kr::KERN_MEMORY_ERROR)?;
        }
    }
    Ok(Remapped {
        addr: at + data_offset,
        cur: cur_out,
        max: max_out,
    })
}

/// What a part of the source becomes in the new mapping.
enum Part {
    Copy(Vec<u8>),
    Shared(Arc<SharedObject>, u64),
}

/// The object and offset of `[s, e)` of VMA `v`, the part made a shared
/// mapping of a new object holding its contents if it is private.
fn share(
    ctx: &mut Ctx<'_>,
    v: &Vma,
    s: u64,
    e: u64,
) -> Result<(Arc<SharedObject>, u64), KernReturn> {
    if v.shared
        && let Backing::Shared { object, offset } = &v.backing
    {
        return Ok((object.clone(), offset + (s - v.start)));
    }
    let len = e - s;
    let mut data = vec![0u8; len as usize];
    ctx.proc
        .space
        .read_raw(s, &mut data)
        .map_err(|_| kr::KERN_MEMORY_ERROR)?;
    let object = Arc::new(SharedObject::anonymous(len).map_err(|_| kr::KERN_RESOURCE_SHORTAGE)?);
    let mapping = Mapping {
        perms: v.perms,
        backing: Backing::Shared {
            object: object.clone(),
            offset: 0,
        },
        shared: true,
        name: v.name.clone(),
        flags: v.flags,
    };
    ctx.proc.space.map(s, len, mapping).map_err(mm_kr)?;
    // The contents, kept: stored through the new mapping.
    ctx.proc
        .space
        .write_raw(s, &data)
        .map_err(|_| kr::KERN_MEMORY_ERROR)?;
    Ok((object, 0))
}
