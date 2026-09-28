//! The `mach_vm` and `vm_map` subsystems (`mach_vm.defs`, `vm_map.defs`,
//! `osfmk/vm/vm_user.c`, `vm_map.c`) on the calling task's map.
//!
//! The emulated map is flat: the shared region's mappings are ordinary
//! entries rather than a nested submap, so `mach_vm_region_recurse`
//! reports them at depth 0 with `is_submap` clear.

use std::sync::Arc;

use super::{Buf, MigResult, Out, OutDesc, Req, ids, is_task, null_port};
use crate::user::darwin::mach::ipc::{KObject, Right, disp};
use crate::user::darwin::mach::kr::{self, KernReturn};
use crate::user::darwin::syscall::Ctx;
use crate::user::darwin::syscall::mach::entry;
use crate::user::darwin::syscall::mach::reclaim;
use crate::user::darwin::syscall::mach::vm as mvm;
use crate::user::darwin::vm::{self, VmFlags};
use crate::user::mm::{Backing, Mapping, Vma};

/// `VM_REGION_*` flavors.
mod region {
    pub const BASIC_INFO_64: i32 = 9;
    pub const BASIC_INFO: i32 = 10;
    pub const EXTENDED_INFO_LEGACY: i32 = 11;
    pub const TOP_INFO: i32 = 12;
    pub const EXTENDED_INFO: i32 = 13;
}

/// `SM_*` share modes.
mod sm {
    pub const COW: u32 = 1;
    pub const PRIVATE: u32 = 2;
    pub const EMPTY: u32 = 3;
    pub const SHARED: u32 = 4;
}

fn ok(k: KernReturn) -> MigResult {
    if k == kr::KERN_SUCCESS {
        Ok(Out::Simple(Vec::new()))
    } else {
        Err(k)
    }
}

/// Serves `mach_vm` and `vm_map`.
pub fn serve(ctx: &mut Ctx<'_>, req: &mut Req) -> MigResult {
    use ids::mach_vm as m;
    use ids::vm_map as v;
    // convert_port_to_map: only the calling task's map is reachable.
    if !is_task(ctx, req)
        && !matches!(
            req.port.kobject,
            crate::user::darwin::mach::ipc::KObject::TaskRead
                | crate::user::darwin::mach::ipc::KObject::TaskInspect
        )
    {
        return Err(kr::KERN_INVALID_ARGUMENT);
    }
    let writable = is_task(ctx, req);
    match req.id {
        m::KERNELRPC_MACH_VM_ALLOCATE => {
            req.simple(52)?;
            let a = mvm::allocate_at(ctx, req.u64(32), req.u64(40), req.u32(48))?;
            Ok(Out::Simple(Buf::new().u64(a).done()))
        }
        m::KERNELRPC_MACH_VM_DEALLOCATE => {
            req.simple(48)?;
            ok(mvm::deallocate(ctx, req.u64(32), req.u64(40)))
        }
        m::KERNELRPC_MACH_VM_PROTECT => {
            req.simple(56)?;
            ok(mvm::protect(
                ctx,
                req.u64(32),
                req.u64(40),
                req.u32(48) != 0,
                req.u32(52),
            ))
        }
        m::KERNELRPC_MACH_VM_MAP | v::VM_MAP_64 => {
            req.complex_of(1, 100)?;
            let object = req.take_port(28, &[17, 18, 16, 0])?;
            let (addr, size, mask, flags, offset, copy, cur, max, inh) = (
                req.u64(48),
                req.u64(56),
                req.u64(64),
                req.u32(72),
                req.u64(76),
                req.u32(84) != 0,
                req.u32(88),
                req.u32(92),
                req.u32(96),
            );
            // The object's port: its right goes with the request.
            let port = object.as_ref().and_then(|o| o.port().cloned());
            if ctx.proc.config.strace {
                eprintln!(
                    "[{:#x}]   vm_map addr {addr:#x} size {size:#x} mask {mask:#x} flags {flags:#x} \
                     object {:?} offset {offset:#x} copy {copy} prot {cur}/{max} inherit {inh}",
                    ctx.thread.tid,
                    port.as_ref().map(|p| &p.kobject)
                );
            }
            if let Some(o) = object {
                crate::user::darwin::syscall::mach::kmsg::release(ctx.proc, [o]);
            }
            // VM_PROT_IS_MASK is taken for an object's mapping (and dropped
            // for anonymous memory).
            let (plain_cur, plain_max) =
                (cur & !entry::VM_PROT_IS_MASK, max & !entry::VM_PROT_IS_MASK);
            if plain_max & !vm::VM_PROT_ALL != 0
                || plain_cur & !vm::VM_PROT_ALL != 0
                || inh > 2
                || plain_cur & !plain_max != 0
            {
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            let (cur, max) = if port.is_none() {
                (plain_cur, plain_max)
            } else {
                (cur, max)
            };
            match port {
                None => {
                    let a = mvm::map_at(ctx, addr, size, mask, flags, cur)?;
                    let page = ctx.proc.vm.page;
                    let len = (size + page - 1) & !(page - 1);
                    let f = VmFlags::new(max, inh, flags >> 24);
                    let _ = ctx.proc.space.set_flags(a, len, 0x3f, f.bits() & 0x3f);
                    Ok(Out::Simple(Buf::new().u64(a).done()))
                }
                // A memory entry behind a proxy; other memory-entry and
                // pager objects are not modelled.
                Some(p) => {
                    let KObject::Proxy(h) = &p.kobject else {
                        return Err(kr::KERN_INVALID_OBJECT);
                    };
                    let (mapping, data) = match crate::user::darwin::bridge::entry_of(ctx.proc, &p)
                    {
                        Some(e) => {
                            let (cur, max) = entry::protections(&e, cur, max)?;
                            (
                                entry::mapping(&e, offset, copy, cur, max, inh, flags >> 24),
                                copy.then(|| entry::contents(&e, offset, size)),
                            )
                        }
                        // A service's entry: its memory, or a copy.
                        None if !copy => {
                            let (object, cur, max) =
                                crate::user::darwin::bridge::map_object_shared(
                                    ctx.proc, h, size, offset, cur, max,
                                )?;
                            let mapping = Mapping {
                                perms: vm::perms(cur),
                                backing: Backing::Shared { object, offset: 0 },
                                shared: true,
                                name: None,
                                flags: VmFlags::new(max, inh, flags >> 24).bits(),
                            };
                            (mapping, None)
                        }
                        None => {
                            let (data, cur, max) =
                                crate::user::darwin::bridge::map_object(h, size, offset, cur, max)?;
                            let mapping = Mapping {
                                flags: VmFlags::new(max, inh, flags >> 24).bits(),
                                ..Mapping::anonymous(vm::perms(cur))
                            };
                            (mapping, Some(data))
                        }
                    };
                    let a = mvm::map_mapping(ctx, addr, size, mask, flags, mapping)?;
                    if let Some(d) = data {
                        ctx.proc
                            .space
                            .write_raw(a, &d)
                            .map_err(|_| kr::KERN_INVALID_ADDRESS)?;
                    }
                    Ok(Out::Simple(Buf::new().u64(a).done()))
                }
            }
        }
        m::MACH_MAKE_MEMORY_ENTRY | v::MACH_MAKE_MEMORY_ENTRY | v::MACH_MAKE_MEMORY_ENTRY_64 => {
            req.complex_of(1, 68)?;
            let parent = req.take_port(28, &[17, 18, 16, 0])?;
            if let Some(p) = parent {
                // Entries of entries are not modelled.
                crate::user::darwin::syscall::mach::kmsg::release(ctx.proc, [p]);
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            if !writable {
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            let (port, len) = entry::make(ctx, req.u64(48), req.u64(56), req.i32(64))?;
            Ok(Out::Complex(
                vec![OutDesc::Port(Some(Right::Send(port)), disp::MOVE_SEND)],
                Buf::new().u64(len).done(),
            ))
        }
        m::KERNELRPC_MACH_VM_REMAP
        | v::KERNELRPC_VM_REMAP
        | m::KERNELRPC_MACH_VM_REMAP_NEW
        | v::KERNELRPC_VM_REMAP_NEW => {
            use crate::user::darwin::syscall::mach::remap::{self, Protections, Source};
            let new = matches!(
                req.id,
                m::KERNELRPC_MACH_VM_REMAP_NEW | v::KERNELRPC_VM_REMAP_NEW
            );
            req.complex_of(1, if new { 100 } else { 92 })?;
            let src_task = req.take_port(28, &[17, 18, 16, 0])?;
            let from = match src_task.as_ref().and_then(|r| r.port()) {
                Some(p) if p.kobject == KObject::Task && Arc::ptr_eq(p, &ctx.proc.task_port) => {
                    Source::Control
                }
                Some(p) if p.kobject == KObject::TaskRead => Source::Read,
                _ => Source::Other,
            };
            if let Some(r) = src_task {
                crate::user::darwin::syscall::mach::kmsg::release(ctx.proc, [r]);
            }
            // The target is a vm_map_t: only the task's control port.
            if !writable {
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            let (prot, inheritance) = if new {
                (
                    Protections::New {
                        cur: req.u32(88),
                        max: req.u32(92),
                    },
                    req.u32(96),
                )
            } else {
                (Protections::Legacy, req.u32(88))
            };
            let r = remap::remap(
                ctx,
                req.u64(48),
                req.u64(56),
                req.u64(64),
                req.u32(72),
                from,
                req.u64(76),
                req.u32(84) != 0,
                prot,
                inheritance,
            )?;
            Ok(Out::Simple(
                Buf::new().u64(r.addr).u32(r.cur).u32(r.max).done(),
            ))
        }
        m::MACH_VM_INHERIT | v::VM_INHERIT => {
            req.simple(52)?;
            ok(inherit(ctx, req.u64(32), req.u64(40), req.u32(48)))
        }
        m::MACH_VM_BEHAVIOR_SET | v::VM_BEHAVIOR_SET => {
            req.simple(52)?;
            ok(behavior_set(ctx, req.u64(32), req.u64(40), req.i32(48)))
        }
        m::MACH_VM_MSYNC | v::VM_MSYNC => {
            req.simple(52)?;
            ok(msync(ctx, req.u64(32), req.u64(40), req.u32(48)))
        }
        m::KERNELRPC_MACH_VM_READ | v::KERNELRPC_VM_READ => {
            req.simple(48)?;
            let (addr, size) = (req.u64(32), req.u64(40));
            let data = read(ctx, addr, size)?;
            let n = data.len() as u32;
            Ok(Out::Complex(
                vec![OutDesc::Ool(data)],
                Buf::new().u32(n).done(),
            ))
        }
        m::MACH_VM_READ_OVERWRITE | v::VM_READ_OVERWRITE => {
            req.simple(56)?;
            let (addr, size, dest) = (req.u64(32), req.u64(40), req.u64(48));
            let data = read(ctx, addr, size)?;
            ctx.proc
                .space
                .write(dest, &data)
                .map_err(|_| kr::KERN_INVALID_ADDRESS)?;
            Ok(Out::Simple(Buf::new().u64(size).done()))
        }
        m::MACH_VM_WRITE | v::VM_WRITE => {
            req.complex_of(1, 64)?;
            if !writable {
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            let data = take_ool(req, 28)?;
            let addr = req.u64(52);
            write(ctx, addr, &data)
        }
        m::MACH_VM_COPY | v::VM_COPY => {
            req.simple(56)?;
            let (src, size, dst) = (req.u64(32), req.u64(40), req.u64(48));
            let data = read(ctx, src, size)?;
            write(ctx, dst, &data)
        }
        m::MACH_VM_PAGE_QUERY | v::VM_MAP_PAGE_QUERY => {
            req.simple(40)?;
            let addr = req.u64(32);
            // VM_PAGE_QUERY_PAGE_PRESENT (1), _REF (4), _DIRTY (8).
            let (disp, refs) = match ctx.proc.space.vma_at(addr) {
                None => return Err(kr::KERN_INVALID_ADDRESS),
                Some(_) if ctx.proc.space.is_resident(addr) => (0x1 | 0x4, 1),
                Some(_) => (0, 0),
            };
            Ok(Out::Simple(Buf::new().u32(disp).u32(refs).done()))
        }
        m::MACH_VM_REGION | v::VM_REGION_64 => {
            req.simple(48)?;
            let (addr, fl, count) = (req.u64(32), req.i32(40), req.u32(44).min(10));
            let (vma, words) = region_info(ctx, addr, fl, count)?;
            let mut b = Buf::new()
                .u64(vma.start)
                .u64(vma.len())
                .u32(words.len() as u32);
            for w in &words {
                b = b.u32(*w);
            }
            Ok(Out::Complex(vec![null_port()], b.done()))
        }
        m::MACH_VM_REGION_RECURSE | v::VM_REGION_RECURSE_64 => {
            req.simple(48)?;
            // The macOS 27 SDK's vm_region_recurse_info_t holds 21 words (V3).
            let (addr, depth, count) = (req.u64(32), req.u32(40), req.u32(44).min(21));
            let (vma, words) = submap_info(ctx, addr, count)?;
            let mut b = Buf::new()
                .u64(vma.start)
                .u64(vma.len())
                .u32(depth)
                .u32(words.len() as u32);
            for w in &words {
                b = b.u32(*w);
            }
            Ok(Out::Simple(b.done()))
        }
        // The deferred-reclamation ring: a `task_t` routine takes only
        // the task's own control port; the query also a read port.
        m::MACH_VM_DEFERRED_RECLAMATION_BUFFER_ALLOCATE => {
            req.simple(40)?;
            if !writable {
                return Err(kr::MACH_SEND_INVALID_DEST);
            }
            let (addr, deadline) = reclaim::allocate(ctx, req.u32(32), req.u32(36))?;
            Ok(Out::Simple(Buf::new().u64(addr).u64(deadline).done()))
        }
        m::MACH_VM_DEFERRED_RECLAMATION_BUFFER_FLUSH
        | m::MACH_VM_DEFERRED_RECLAMATION_BUFFER_RESIZE => {
            req.simple(36)?;
            if !writable {
                return Err(kr::MACH_SEND_INVALID_DEST);
            }
            let n = req.u32(32);
            let (bytes, deadline) = if req.id == m::MACH_VM_DEFERRED_RECLAMATION_BUFFER_FLUSH {
                reclaim::flush(ctx, n)?
            } else {
                reclaim::resize(ctx, n)?
            };
            Ok(Out::Simple(Buf::new().u64(bytes).u64(deadline).done()))
        }
        m::MACH_VM_DEFERRED_RECLAMATION_BUFFER_QUERY => {
            req.simple(24)?;
            if req.port.kobject == crate::user::darwin::mach::ipc::KObject::TaskInspect {
                return Err(kr::KERN_INVALID_TASK);
            }
            let (addr, size) = reclaim::query(ctx);
            Ok(Out::Simple(Buf::new().u64(addr).u64(size).done()))
        }
        m::KERNELRPC_MACH_VM_PURGABLE_CONTROL | v::KERNELRPC_VM_PURGABLE_CONTROL => {
            req.simple(48)?;
            let (addr, control, state) = (req.u64(32), req.i32(40), req.i32(44));
            purgable_control(ctx, addr, control, state)
                .map(|s| Out::Simple(Buf::new().i32(s).done()))
        }
        _ => {
            if ctx.proc.config.strace || std::env::var_os("RAX_DARWIN_WARN").is_some() {
                eprintln!(
                    "rax-user: unimplemented MIG routine {} ({})",
                    req.id,
                    ids::name(req.id).unwrap_or("?")
                );
            }
            Err(kr::MIG_BAD_ID)
        }
    }
}

fn take_ool(req: &mut Req, off: usize) -> Result<Vec<u8>, KernReturn> {
    use crate::user::darwin::mach::msg::Item;
    let i = req
        .items
        .iter()
        .position(|(p, _)| *p == off)
        .ok_or(kr::MIG_TYPE_ERROR)?;
    match req.items.remove(i).1 {
        Item::Ool { data, .. } => Ok(data),
        other => {
            req.items.push((off, other));
            Err(kr::MIG_TYPE_ERROR)
        }
    }
}

/// `mach_vm_read`: the bytes of a readable range (`KERN_INVALID_ADDRESS`
/// when unmapped, `KERN_PROTECTION_FAILURE` when not readable).
fn read(ctx: &Ctx<'_>, addr: u64, size: u64) -> Result<Vec<u8>, KernReturn> {
    if size == 0 {
        return Ok(Vec::new());
    }
    if addr.checked_add(size).is_none() || size > (1 << 32) {
        return Err(kr::KERN_INVALID_ARGUMENT);
    }
    let page = ctx.proc.vm.page;
    let lo = addr & !(page - 1);
    let hi = (addr + size + page - 1) & !(page - 1);
    if ctx.proc.space.first_unmapped(lo, hi - lo).is_some() {
        return Err(kr::KERN_INVALID_ADDRESS);
    }
    for v in ctx.proc.space.vmas_in(lo, hi) {
        if vm::prot(v.perms) & vm::VM_PROT_READ == 0 {
            return Err(kr::KERN_PROTECTION_FAILURE);
        }
    }
    let mut buf = vec![0u8; size as usize];
    ctx.proc
        .space
        .read_raw(addr, &mut buf)
        .map_err(|_| kr::KERN_INVALID_ADDRESS)?;
    Ok(buf)
}

/// `mach_vm_write` / `mach_vm_copy`'s destination
/// (`vm_map_copy_overwrite`): the range must be mapped and writable. Data
/// that travelled in a kernel buffer (at most `msg_ool_size_small`) is
/// written with `copyout`, which fails with `KERN_INVALID_ADDRESS` either
/// way; a page list reports a read-only destination as
/// `KERN_PROTECTION_FAILURE`.
fn write(ctx: &Ctx<'_>, addr: u64, data: &[u8]) -> MigResult {
    if data.is_empty() {
        return Ok(Out::Simple(Vec::new()));
    }
    let small = match ctx.proc.abi {
        crate::user::darwin::abi::DarwinAbi::X86_64 => 16 << 10,
        crate::user::darwin::abi::DarwinAbi::Arm64 => 32 << 10,
    };
    let page = ctx.proc.vm.page;
    let lo = addr & !(page - 1);
    let hi = (addr + data.len() as u64 + page - 1) & !(page - 1);
    if ctx.proc.space.first_unmapped(lo, hi - lo).is_some() {
        return Err(kr::KERN_INVALID_ADDRESS);
    }
    for v in ctx.proc.space.vmas_in(lo, hi) {
        if vm::prot(v.perms) & vm::VM_PROT_WRITE == 0 {
            return Err(if data.len() <= small {
                kr::KERN_INVALID_ADDRESS
            } else {
                kr::KERN_PROTECTION_FAILURE
            });
        }
    }
    ctx.proc
        .space
        .write_raw(addr, data)
        .map_err(|_| kr::KERN_INVALID_ADDRESS)?;
    Ok(Out::Simple(Vec::new()))
}

fn range(ctx: &Ctx<'_>, addr: u64, size: u64) -> Result<(u64, u64), KernReturn> {
    let page = ctx.proc.vm.page;
    let lo = addr & !(page - 1);
    let hi = addr
        .checked_add(size)
        .and_then(|e| e.checked_add(page - 1))
        .ok_or(kr::KERN_INVALID_ARGUMENT)?
        & !(page - 1);
    Ok((lo, hi - lo))
}

/// `mach_vm_inherit`.
fn inherit(ctx: &Ctx<'_>, addr: u64, size: u64, inh: u32) -> KernReturn {
    if inh > 3 {
        return kr::KERN_INVALID_ARGUMENT;
    }
    if size == 0 {
        return kr::KERN_SUCCESS;
    }
    let (lo, len) = match range(ctx, addr, size) {
        Ok(r) => r,
        Err(k) => return k,
    };
    // VM_INHERIT_DONATE_COPY is not allowed from user space.
    if inh == 3 {
        return kr::KERN_INVALID_ARGUMENT;
    }
    if ctx.proc.space.first_unmapped(lo, len).is_some() {
        return kr::KERN_INVALID_ADDRESS;
    }
    match ctx
        .proc
        .space
        .set_flags(lo, len, 0x30, VmFlags::new(0, inh, 0).bits() & 0x30)
    {
        Ok(()) => kr::KERN_SUCCESS,
        Err(_) => kr::KERN_INVALID_ADDRESS,
    }
}

/// `mach_vm_behavior_set`: hints are accepted; `VM_BEHAVIOR_FREE` and
/// `_ZERO` discard page contents as their `madvise` forms do.
fn behavior_set(ctx: &Ctx<'_>, addr: u64, size: u64, behavior: i32) -> KernReturn {
    if !(0..=12).contains(&behavior) || behavior == 11 {
        return kr::KERN_INVALID_ARGUMENT;
    }
    if size == 0 {
        return kr::KERN_SUCCESS;
    }
    let (lo, len) = match range(ctx, addr, size) {
        Ok(r) => r,
        Err(k) => return k,
    };
    if ctx.proc.space.first_unmapped(lo, len).is_some() {
        return kr::KERN_INVALID_ADDRESS;
    }
    if behavior == 6 || behavior == 12 {
        let _ = ctx.proc.space.discard(lo, len);
    }
    kr::KERN_SUCCESS
}

/// `mach_vm_msync`: the range must be mapped (`KERN_INVALID_ADDRESS`);
/// file-backed shared pages are written back.
fn msync(ctx: &Ctx<'_>, addr: u64, size: u64, flags: u32) -> KernReturn {
    // VM_SYNC_ASYNCHRONOUS 0x1, SYNCHRONOUS 0x2, INVALIDATE 0x4,
    // KILLPAGES 0x8, DEACTIVATE 0x10, CONTIGUOUS 0x20, REUSABLEPAGES 0x40.
    if flags & (0x1 | 0x2) == (0x1 | 0x2) {
        return kr::KERN_INVALID_ARGUMENT;
    }
    if size == 0 {
        return kr::KERN_SUCCESS;
    }
    let (lo, len) = match range(ctx, addr, size) {
        Ok(r) => r,
        Err(k) => return k,
    };
    if ctx.proc.space.first_unmapped(lo, len).is_some() {
        return kr::KERN_INVALID_ADDRESS;
    }
    let _ = ctx.proc.space.sync(lo, len);
    kr::KERN_SUCCESS
}

/// `mach_vm_purgable_control` on anonymous memory: objects are never
/// purged, so the state is kept as set and `VM_PURGABLE_GET_STATE`
/// reports `VM_PURGABLE_NONVOLATILE` for non-purgeable memory.
fn purgable_control(ctx: &Ctx<'_>, addr: u64, control: i32, state: i32) -> Result<i32, KernReturn> {
    // VM_PURGABLE_SET_STATE 0, GET_STATE 1, PURGE_ALL 3,
    // SET_STATE_FROM_KERNEL 2 (kernel only).
    match control {
        0 | 1 => {}
        3 => return Ok(state),
        _ => return Err(kr::KERN_INVALID_ARGUMENT),
    }
    if ctx.proc.space.vma_at(addr).is_none() {
        return Err(kr::KERN_INVALID_ADDRESS);
    }
    // Only VM_FLAGS_PURGABLE allocations are purgeable; the emulator
    // creates none.
    Err(kr::KERN_INVALID_ARGUMENT)
}

/// The entry at or after `addr` (`vm_map_lookup_entry` then the next).
fn entry_at_or_after(ctx: &Ctx<'_>, addr: u64) -> Result<Vma, KernReturn> {
    ctx.proc
        .space
        .vmas_in(addr, u64::MAX)
        .into_iter()
        .find(|v| v.end > addr)
        .ok_or(kr::KERN_INVALID_ADDRESS)
}

/// Resident pages of `v`.
pub(crate) fn resident(ctx: &Ctx<'_>, v: &Vma) -> u32 {
    let page = crate::user::mm::PAGE_SIZE;
    let mut n = 0u32;
    let mut a = v.start;
    while a < v.end {
        if ctx.proc.space.is_resident(a) {
            n += 1;
        }
        a += page;
    }
    // In units of the map's pages.
    let ratio = (ctx.proc.vm.page / page) as u32;
    n.div_ceil(ratio.max(1))
}

pub(crate) fn share_mode(v: &Vma, resident: u32) -> u32 {
    if v.shared {
        sm::SHARED
    } else {
        match v.backing {
            Backing::Anonymous if resident == 0 => sm::EMPTY,
            Backing::Anonymous => sm::PRIVATE,
            _ => sm::COW,
        }
    }
}

pub(crate) fn backing_offset(v: &Vma) -> u64 {
    match &v.backing {
        Backing::Anonymous => 0,
        Backing::Source { offset, .. } | Backing::Shared { offset, .. } => *offset,
    }
}

/// `vm_map_region(flavor)` with the caller's `count`.
fn region_info(
    ctx: &Ctx<'_>,
    addr: u64,
    fl: i32,
    count: u32,
) -> Result<(Vma, Vec<u32>), KernReturn> {
    let v = entry_at_or_after(ctx, addr)?;
    let f = VmFlags::from_bits(v.flags);
    let prot = vm::prot(v.perms);
    let off = backing_offset(&v);
    let w = match fl {
        region::BASIC_INFO_64 => {
            // protection, max_protection, inheritance, shared, reserved,
            // offset (8), behavior, user_wired_count.
            if count < 9 {
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            vec![
                prot,
                f.max_prot(),
                f.inheritance(),
                u32::from(v.shared),
                0,
                off as u32,
                (off >> 32) as u32,
                0,
                0,
            ]
        }
        region::BASIC_INFO => {
            // As above with a 32-bit offset.
            if count < 8 {
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            vec![
                prot,
                f.max_prot(),
                f.inheritance(),
                u32::from(v.shared),
                0,
                off as u32,
                0,
                0,
            ]
        }
        region::EXTENDED_INFO | region::EXTENDED_INFO_LEGACY => {
            // protection, user_tag, pages_resident,
            // pages_shared_now_private, pages_swapped_out, pages_dirtied,
            // ref_count, shadow_depth:16 | external_pager:8 |
            // share_mode:8, pages_reusable.
            if count < 8 {
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            let r = resident(ctx, &v);
            let smode = share_mode(&v, r);
            let external = u32::from(!matches!(v.backing, Backing::Anonymous));
            let mut w = vec![
                prot,
                f.tag(),
                r,
                0,
                0,
                0,
                1,
                (external << 16) | (smode << 24),
            ];
            if count >= 9 && fl == region::EXTENDED_INFO {
                w.push(0);
            }
            w
        }
        region::TOP_INFO => {
            // obj_id, ref_count, private_pages_resident,
            // shared_pages_resident, share_mode.
            if count < 5 {
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            let r = resident(ctx, &v);
            let smode = share_mode(&v, r);
            let (private, shared) = if v.shared { (0, r) } else { (r, 0) };
            vec![0, 1, private, shared, smode]
        }
        _ => return Err(kr::KERN_INVALID_ARGUMENT),
    };
    Ok((v, w))
}

/// `vm_map_region_recurse_64` for a flat map: `vm_region_submap_info_64`
/// (V0 16, V1 17, V2 19 words, and V3 21 with `pages_wired` and
/// `wire_tag`, which the macOS 27 SDK's `mach/vm_region.h` and its kernel
/// add; the short form 12).
fn submap_info(ctx: &Ctx<'_>, addr: u64, count: u32) -> Result<(Vma, Vec<u32>), KernReturn> {
    let v = entry_at_or_after(ctx, addr)?;
    let f = VmFlags::from_bits(v.flags);
    let prot = vm::prot(v.perms);
    let off = backing_offset(&v);
    let r = resident(ctx, &v);
    let smode = share_mode(&v, r);
    let external = u32::from(!matches!(v.backing, Backing::Anonymous));
    let n = match count {
        21.. => 21,
        19..=20 => 19,
        17..=18 => 17,
        16 => 16,
        12..=15 => 12,
        _ => return Err(kr::KERN_INVALID_ARGUMENT),
    };
    let w = if n == 12 {
        // vm_region_submap_short_info_64: protection, max_protection,
        // inheritance, offset (8), user_tag, ref_count,
        // shadow_depth:16 | external_pager:8 | share_mode:8, is_submap,
        // behavior, object_id, user_wired_count:16 | flags:16.
        vec![
            prot,
            f.max_prot(),
            f.inheritance(),
            off as u32,
            (off >> 32) as u32,
            f.tag(),
            1,
            (external << 16) | (smode << 24),
            0,
            0,
            0,
            0,
        ]
    } else {
        let mut w = vec![
            prot,
            f.max_prot(),
            f.inheritance(),
            off as u32,
            (off >> 32) as u32,
            f.tag(),
            r,
            0,
            0,
            0,
            1,
            (external << 16) | (smode << 24),
            0,
            0,
            0,
            0,
        ];
        if n >= 17 {
            w.push(0);
        }
        if n >= 19 {
            // object_id_full
            w.extend_from_slice(&[0, 0]);
        }
        if n == 21 {
            // pages_wired, wire_tag and padding: nothing is wired.
            w.extend_from_slice(&[0, 0]);
        }
        w
    };
    Ok((v, w))
}
