//! Host-owned fiber contexts, stacks, and guest-visible identity blocks.
//!
//! Microsoft defines fiber stacks, call-preserved registers, fiber data and
//! cross-thread switching. This engine retains the whole interpreter CPU and
//! continuation stack: keeping volatile registers is an implementation detail,
//! not an additional Windows ABI guarantee. TLS/TEB identity remains the
//! running thread's; only stack/SEH metadata and FiberData change.
//!
//! A live fiber owns its stack, including the stack adopted during conversion.
//! Reconversion transfers that ownership to Thread.thread_stack_alloc. This
//! ownership profile permits controlled migration after the original thread
//! exits, without dereferencing guest ownership words. MAX_FIBERS is a bounded
//! host-bookkeeping admission limit, not a native Windows limit.

use std::collections::BTreeMap;
use std::sync::Arc;

use super::{Proc, Thread};
use crate::error::MemoryAccessKind;
use crate::user::mm::PAGE_SIZE;
use crate::user::windows::arch::{WinArch, WinCpu};
use crate::user::windows::hle::Frame;
use crate::user::windows::layout::offsets;
use crate::user::windows::memory::{AllocKind, Mem, prot};
use crate::user::windows::nt::status::*;
use crate::user::windows::tls::{FlsError, FlsKey};

/// The sole supported CreateFiberEx/ConvertThreadToFiberEx flag.
pub(crate) const FIBER_FLAG_FLOAT_SWITCH: u32 = 1;
/// Maximum live fibers; guest VM and heap limits also apply.
pub(crate) const MAX_FIBERS: usize = 4096;

/// Stack fields that follow a fiber instead of an OS thread.
struct Stack {
    alloc: u64,
    base: u64,
    limit: u64,
    exception_list: u64,
    guaranteed_bytes: u32,
}

struct Fiber {
    /// None precisely while this fiber is selected on an OS thread.
    cpu: Option<WinCpu>,
    frames: Vec<Frame>,
    stack: Stack,
    active: Option<u32>,
    deleting: bool,
    flags: u32,
    start: u64,
    parameter: u64,
    /// Thread on which the dormant context was last captured.
    last_tid: u32,
    /// Includes loader-owned synthetic startup-wrapper continuations.
    thread_bound: bool,
}

/// Process-wide live fiber identities; guest identity blocks contain only data.
#[derive(Default)]
pub struct FiberState {
    fibers: BTreeMap<u64, Fiber>,
}

impl FiberState {
    /// Whether a host-authoritative fiber identity remains live.
    pub(crate) fn contains(&self, handle: u64) -> bool {
        self.fibers.contains_key(&handle)
    }

    /// The start routine and data for the synthetic first-entry trap.
    pub(crate) fn start_info(&self, handle: u64) -> Option<(u64, u64)> {
        self.fibers
            .get(&handle)
            .filter(|f| !f.deleting)
            .map(|f| (f.start, f.parameter))
    }

    /// Whether any live fiber owns this stack reservation.
    pub(crate) fn retains_stack(&self, alloc: u64) -> bool {
        self.fibers.values().any(|f| f.stack.alloc == alloc)
    }

    /// Number of live identities (including a deleting callback context).
    pub(crate) fn len(&self) -> usize {
        self.fibers.len()
    }
}

fn flags(flags: u32) -> Result<(), u32> {
    if flags & !FIBER_FLAG_FLOAT_SWITCH != 0 {
        Err(STATUS_INVALID_PARAMETER)
    } else {
        Ok(())
    }
}

fn thread_bound_frames(frames: &[Frame]) -> bool {
    frames
        .iter()
        .any(|f| !matches!(f.api.name, "RtlUserFiberStart" | "RtlUserThreadStart"))
}

fn admit(p: &Proc) -> Result<(), u32> {
    if p.fibers.len() >= MAX_FIBERS {
        Err(STATUS_NO_MEMORY)
    } else {
        Ok(())
    }
}

fn fls_error(error: FlsError) -> u32 {
    match error {
        FlsError::NoMemory | FlsError::GenerationExhausted => STATUS_NO_MEMORY,
        _ => STATUS_INVALID_PARAMETER,
    }
}

fn pointer_addr(teb: u64, offset: u64) -> Result<u64, u32> {
    teb.checked_add(offset).ok_or(STATUS_ACCESS_VIOLATION)
}

/// Preflight all switch-publication words before stack or registry effects.
fn preflight(p: &Proc, t: &Thread) -> Result<(), u32> {
    let o = offsets(p.arch);
    for (offset, size) in [
        (o.teb_exception_list, o.ptr),
        (o.teb_stack_base, o.ptr),
        (o.teb_stack_limit, o.ptr),
        (o.teb_fiber_data, o.ptr),
        (o.teb_deallocation_stack, o.ptr),
        (o.teb_guaranteed_stack_bytes, 4),
    ] {
        p.space
            .probe(
                pointer_addr(t.teb, offset)?,
                size as usize,
                MemoryAccessKind::Write,
            )
            .map_err(|_| STATUS_ACCESS_VIOLATION)?;
    }
    Ok(())
}

fn capture_stack(p: &Proc, t: &Thread) -> Result<Stack, u32> {
    let o = offsets(p.arch);
    // Stack allocation and base remain host-owned. Guest-writable SEH links
    // and guaranteed bytes are data, never heap/allocation ownership pointers.
    Ok(Stack {
        alloc: t.stack_alloc,
        base: t.stack_base,
        limit: t.stack_limit,
        exception_list: p
            .space
            .ptr(pointer_addr(t.teb, o.teb_exception_list)?, o.ptr)
            .map_err(|_| STATUS_ACCESS_VIOLATION)?,
        guaranteed_bytes: p
            .space
            .u32(pointer_addr(t.teb, o.teb_guaranteed_stack_bytes)?)
            .map_err(|_| STATUS_ACCESS_VIOLATION)?,
    })
}

fn publish(p: &Proc, t: &Thread, stack: &Stack, handle: u64) -> Result<(), u32> {
    let o = offsets(p.arch);
    for (offset, value) in [
        (o.teb_exception_list, stack.exception_list),
        (o.teb_stack_base, stack.base),
        (o.teb_stack_limit, stack.limit),
        (o.teb_fiber_data, handle),
        (o.teb_deallocation_stack, stack.alloc),
    ] {
        p.space
            .wptr(pointer_addr(t.teb, offset)?, o.ptr, value)
            .map_err(|_| STATUS_ACCESS_VIOLATION)?;
    }
    p.space
        .w32(
            pointer_addr(t.teb, o.teb_guaranteed_stack_bytes)?,
            stack.guaranteed_bytes,
        )
        .map_err(|_| STATUS_ACCESS_VIOLATION)
}

fn marker(p: &mut Proc, parameter: u64) -> Result<u64, u32> {
    let size = p.arch.ptr_size();
    let handle = p
        .heaps
        .alloc(&mut p.vm, p.process_heap, size, true)
        .ok_or(STATUS_NO_MEMORY)?;
    // Invalid freeing of an opaque marker cannot recycle its address into a
    // replacement for a still-live CPU/stack ownership ledger.
    if p.fibers.contains(handle) {
        let _ = p.heaps.free(p.process_heap, handle);
        return Err(STATUS_INVALID_PARAMETER);
    }
    if p.space.wptr(handle, size, parameter).is_err() {
        let _ = p.heaps.free(p.process_heap, handle);
        return Err(STATUS_ACCESS_VIOLATION);
    }
    Ok(handle)
}

fn validate_marker(p: &Proc, handle: u64) -> Result<(), u32> {
    match p.heaps.size(p.process_heap, handle) {
        Ok(size) if size == p.arch.ptr_size() => Ok(()),
        _ => Err(STATUS_INVALID_PARAMETER),
    }
}

fn round(value: u64, alignment: u64) -> Result<u64, u32> {
    value
        .checked_add(alignment - 1)
        .map(|v| v & !(alignment - 1))
        .ok_or(STATUS_INVALID_PARAMETER)
}

fn allocate_stack(p: &mut Proc, reserve: u64, commit: u64) -> Result<Stack, u32> {
    let reserve = if reserve == 0 {
        if p.exe_stack_reserve == 0 {
            0x10_0000
        } else {
            p.exe_stack_reserve
        }
    } else {
        reserve
    };
    let commit = if commit == 0 {
        p.exe_stack_commit.max(PAGE_SIZE)
    } else {
        commit
    };
    let commit = round(commit.max(PAGE_SIZE), PAGE_SIZE)?;
    // Microsoft Thread Stack Size: commit >= selected reserve promotes the
    // reservation to a 1 MiB multiple; otherwise reserve rounds to 64 KiB.
    // Do not enlarge the specified reservation merely for a private guard.
    let reserve = if commit >= reserve {
        round(commit, 0x10_0000)?
    } else {
        round(reserve, 0x1_0000)?
    };
    let alloc =
        p.vm.reserve(
            None,
            reserve,
            prot::READWRITE,
            AllocKind::Private,
            false,
            Some(Arc::from("[fiber stack]")),
        )
        .map_err(|e| e.status())?;
    let result = (|| {
        let base = alloc.checked_add(reserve).ok_or(STATUS_INVALID_PARAMETER)?;
        let limit = base - commit;
        p.vm.commit(limit, commit, prot::READWRITE)
            .map_err(|e| e.status())?;
        // When initial commit fills the reservation there is no private guard.
        // Exact native full-commit guard layout is unknown. Otherwise add one
        // if it fits, retaining a bottom reserved page when space allows.
        if limit - alloc >= PAGE_SIZE {
            p.vm.commit(limit - PAGE_SIZE, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                .map_err(|e| e.status())?;
        }
        Ok(Stack {
            alloc,
            base,
            limit,
            exception_list: if p.arch == WinArch::X86 {
                0xFFFF_FFFF
            } else {
                0
            },
            guaranteed_bytes: 0,
        })
    })();
    if result.is_err() {
        let _ = p.vm.release(alloc);
    }
    result
}

/// Creates a dormant fiber. No TLS blocks, thread object or notifications exist.
pub(crate) fn create(
    p: &mut Proc,
    t: &Thread,
    reserve: u64,
    commit: u64,
    options: u32,
    start: u64,
    parameter: u64,
) -> Result<u64, u32> {
    flags(options)?;
    admit(p)?;
    let stack = allocate_stack(p, reserve, commit)?;
    let handle = match marker(p, parameter) {
        Ok(handle) => handle,
        Err(status) => {
            let _ = p.vm.release(stack.alloc);
            return Err(status);
        }
    };
    let mut cpu = t.cpu.new_thread();
    cpu.set_teb(t.teb);
    cpu.set_sp((stack.base - 0x40) & !0xF);
    cpu.set_pc(p.traps.fiber_start());
    p.fibers.fibers.insert(
        handle,
        Fiber {
            cpu: Some(cpu),
            frames: Vec::new(),
            stack,
            active: None,
            deleting: false,
            flags: options,
            start,
            parameter,
            last_tid: t.tid,
            thread_bound: false,
        },
    );
    Ok(handle)
}

/// Adopts the current stack and CPU as a fiber without changing execution.
pub(crate) fn convert(
    p: &mut Proc,
    t: &mut Thread,
    parameter: u64,
    options: u32,
) -> Result<u64, u32> {
    flags(options)?;
    if t.current_fiber.is_some() {
        return Err(STATUS_INVALID_PARAMETER);
    }
    admit(p)?;
    preflight(p, t)?;
    let stack = capture_stack(p, t)?;
    let handle = marker(p, parameter)?;
    if let Err(error) = p
        .tls
        .fls_move_context(FlsKey::Thread(t.tid), FlsKey::Fiber(handle))
    {
        let _ = p.heaps.free(p.process_heap, handle);
        return Err(fls_error(error));
    }
    // Serial scheduler + complete destination preflight: no intervening guest
    // effects can change the checked publication mapping/protection.
    if let Err(status) = publish(p, t, &stack, handle) {
        let _ = p
            .tls
            .fls_move_context(FlsKey::Fiber(handle), FlsKey::Thread(t.tid));
        let _ = p.heaps.free(p.process_heap, handle);
        return Err(status);
    }
    p.fibers.fibers.insert(
        handle,
        Fiber {
            cpu: None,
            frames: Vec::new(),
            stack,
            active: Some(t.tid),
            deleting: false,
            flags: options,
            start: 0,
            parameter,
            last_tid: t.tid,
            thread_bound: false,
        },
    );
    t.current_fiber = Some(handle);
    t.thread_stack_alloc = 0;
    Ok(handle)
}

/// Returns current-fiber ownership to its executing thread, retaining the stack.
pub(crate) fn reconvert(p: &mut Proc, t: &mut Thread) -> Result<(), u32> {
    let handle = t.current_fiber.ok_or(STATUS_INVALID_PARAMETER)?;
    validate_marker(p, handle)?;
    let fiber = p
        .fibers
        .fibers
        .get(&handle)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    if fiber.active != Some(t.tid) || fiber.deleting {
        return Err(STATUS_INVALID_PARAMETER);
    }
    preflight(p, t)?;
    p.tls
        .fls_move_context(FlsKey::Fiber(handle), FlsKey::Thread(t.tid))
        .map_err(fls_error)?;
    p.space
        .wptr(t.teb + offsets(p.arch).teb_fiber_data, p.arch.ptr_size(), 0)
        .map_err(|_| STATUS_ACCESS_VIOLATION)?;
    p.fibers.fibers.remove(&handle);
    t.current_fiber = None;
    t.thread_stack_alloc = t.stack_alloc;
    p.heaps
        .free(p.process_heap, handle)
        .map_err(|_| STATUS_INVALID_PARAMETER)?;
    Ok(())
}

/// Validates a switch before the dispatcher completes SwitchToFiber's call.
pub(crate) fn validate_switch(p: &Proc, t: &Thread, target: u64) -> Result<(), u32> {
    let current = t.current_fiber.ok_or(STATUS_INVALID_PARAMETER)?;
    if current == target {
        return Err(STATUS_INVALID_PARAMETER);
    }
    validate_marker(p, current)?;
    validate_marker(p, target)?;
    let from = p
        .fibers
        .fibers
        .get(&current)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    let to = p
        .fibers
        .fibers
        .get(&target)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    if from.active != Some(t.tid)
        || from.deleting
        || to.active.is_some()
        || to.deleting
        || to.cpu.is_none()
    {
        return Err(STATUS_INVALID_PARAMETER);
    }
    // Synthetic entry wrappers are fiber-local, but arbitrary HLE receipts
    // may own thread-bound loader locks, waits, or cleanup stages. Their
    // cross-thread retargeting is not a native-guaranteed implementation.
    if to.last_tid != t.tid && (to.thread_bound || thread_bound_frames(&to.frames)) {
        return Err(STATUS_NOT_SUPPORTED);
    }
    preflight(p, t)?;
    // Capture-side reads must also succeed before the export's guest return.
    capture_stack(p, t)?;
    Ok(())
}

/// Parks the returned caller context and resumes `target` without pruning frames.
pub(crate) fn switch(p: &mut Proc, t: &mut Thread, target: u64) -> Result<(), u32> {
    validate_switch(p, t, target)?;
    let current = t.current_fiber.ok_or(STATUS_INVALID_PARAMETER)?;
    let outgoing_stack = capture_stack(p, t)?;
    // Copy rather than restore FP for an x86 non-saving target. Mixed flags
    // and the complete enabled XSAVE subset are explicitly a RAX profile.
    if p.arch == WinArch::X86 && p.fibers.fibers[&target].flags == 0 {
        p.fibers
            .fibers
            .get_mut(&target)
            .and_then(|f| f.cpu.as_mut())
            .ok_or(STATUS_INVALID_PARAMETER)?
            .inherit_fiber_fp(&t.cpu)?;
    }
    let target_stack = &p.fibers.fibers[&target].stack;
    publish(p, t, target_stack, target)?;
    let to = p
        .fibers
        .fibers
        .get_mut(&target)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    let incoming = to.cpu.take().ok_or(STATUS_INVALID_PARAMETER)?;
    let cpu = std::mem::replace(&mut t.cpu, incoming);
    let frames = std::mem::replace(&mut t.frames, std::mem::take(&mut to.frames));
    t.stack_alloc = to.stack.alloc;
    t.stack_base = to.stack.base;
    t.stack_limit = to.stack.limit;
    to.active = Some(t.tid);
    to.last_tid = t.tid;
    t.cpu.set_teb(t.teb);
    let from = p
        .fibers
        .fibers
        .get_mut(&current)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    from.cpu = Some(cpu);
    from.frames = frames;
    from.stack = outgoing_stack;
    from.active = None;
    from.last_tid = t.tid;
    from.thread_bound = thread_bound_frames(&from.frames)
        || (p.loader.held_by(t.tid)
            && !t.attached
            && from
                .frames
                .iter()
                .any(|f| f.api.name == "RtlUserThreadStart"));
    t.current_fiber = Some(target);
    Ok(())
}

/// Marks an identity unavailable during FLS callbacks. `true` means ExitThread.
pub(crate) fn begin_delete(p: &mut Proc, t: &Thread, handle: u64) -> Result<bool, u32> {
    validate_marker(p, handle)?;
    let fiber = p
        .fibers
        .fibers
        .get_mut(&handle)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    if fiber.deleting || fiber.active.is_some_and(|tid| tid != t.tid) {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let current = t.current_fiber == Some(handle);
    if fiber.active.is_some() != current {
        return Err(STATUS_INVALID_PARAMETER);
    }
    fiber.deleting = true;
    Ok(current)
}

/// Releases a dormant, deleting identity after its FLS callbacks finish.
pub(crate) fn finish_delete(p: &mut Proc, handle: u64) -> Result<(), u32> {
    validate_marker(p, handle)?;
    let fiber = p
        .fibers
        .fibers
        .get(&handle)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    if !fiber.deleting || fiber.active.is_some() {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let alloc = fiber.stack.alloc;
    p.vm.release(alloc).map_err(|e| e.status())?;
    p.heaps
        .free(p.process_heap, handle)
        .map_err(|_| STATUS_INVALID_PARAMETER)?;
    p.fibers.fibers.remove(&handle);
    p.tls.fls_discard_context(FlsKey::Fiber(handle));
    Ok(())
}

/// Removes the active fiber after normal cleanup or forced termination.
/// Dormant fibers retain independent stacks and may be migrated later.
pub(crate) fn destroy_active(p: &mut Proc, t: &Thread) -> Result<(), u32> {
    let Some(handle) = t.current_fiber else {
        return Ok(());
    };
    let fiber = p
        .fibers
        .fibers
        .get(&handle)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    if fiber.active != Some(t.tid) {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let alloc = fiber.stack.alloc;
    p.vm.release(alloc).map_err(|e| e.status())?;
    p.heaps
        .free(p.process_heap, handle)
        .map_err(|_| STATUS_INVALID_PARAMETER)?;
    p.fibers.fibers.remove(&handle);
    p.tls.fls_discard_context(FlsKey::Fiber(handle));
    Ok(())
}

/// The selected created fiber's start routine and parameter. The synthetic
/// trap must not treat a converted running thread as a new fiber entry.
pub(crate) fn start_info(p: &Proc, t: &Thread) -> Result<(u64, u64), u32> {
    let handle = t.current_fiber.ok_or(STATUS_INVALID_PARAMETER)?;
    let fiber = p
        .fibers
        .fibers
        .get(&handle)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    if fiber.active != Some(t.tid) || fiber.deleting {
        return Err(STATUS_INVALID_PARAMETER);
    }
    Ok((fiber.start, fiber.parameter))
}

/// Drops parked host receipts before forced-process abort bookkeeping. No guest
/// writes, callbacks, heap frees or VM changes are performed here.
pub(crate) fn discard_continuations(p: &mut Proc) {
    for fiber in p.fibers.fibers.values_mut() {
        fiber.frames.clear();
    }
}

/// An ended thread cannot own a parked thread-bound receipt. Such contexts
/// become unavailable before their receipts drop; their stack/identity remains
/// owned until process destruction. Plain entry-wrapper fibers remain migratable.
/// This is an explicit fail-closed profile, not native forced-fiber semantics.
pub(crate) fn discard_thread_continuations(p: &mut Proc, tid: u32) {
    for fiber in p.fibers.fibers.values_mut() {
        if fiber.active.is_none()
            && fiber.last_tid == tid
            && (fiber.thread_bound || thread_bound_frames(&fiber.frames))
        {
            fiber.deleting = true;
            fiber.frames.clear();
        }
    }
}

/// Final process resource teardown. Continue releasing independent resources
/// after a failure, retaining the first diagnostic status. No guest callbacks.
pub(crate) fn destroy_all(p: &mut Proc) -> Result<(), u32> {
    let fibers = std::mem::take(&mut p.fibers.fibers);
    let mut error = None;
    for (handle, fiber) in fibers {
        p.tls.fls_discard_context(FlsKey::Fiber(handle));
        if let Err(failure) = p.vm.release(fiber.stack.alloc) {
            error.get_or_insert(failure.status());
        }
        if p.heaps.free(p.process_heap, handle).is_err() {
            error.get_or_insert(STATUS_INVALID_PARAMETER);
        }
        // `fiber` owns its frames until here: all receipts drop before return.
    }
    match error {
        Some(status) => Err(status),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests;
