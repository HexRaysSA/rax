//! CRT-owned blocks, checked guest-size arithmetic, and failure preservation.
//!
//! Heap block metadata stays host-authoritative. Ordinary allocation ledger
//! lookups are expected O(1); allocation/reallocation uses the shared heap's
//! best-fit indices and O(n) bounded-buffer initialization/copy. Private error
//! cells and blocks from another runtime are never accepted as CRT blocks.
//! `_msize` returns this allocator's requested size, not a claimed native heap
//! capacity. `_expand` uses the non-LFH shared allocator, including its zero
//! logical-size and shrinking policy. Detected invalid/double/cross-runtime
//! blocks use the checked corruption policy; exact native invalid-pointer
//! recovery or termination is unknown (Microsoft permits detected errors).

use crate::user::windows::heap::HeapError;
use crate::user::windows::hle::{ApiErr, ApiResult, Arg::*, Conv::Cdecl, Ctx, Export, Flow};
use crate::user::windows::nt::status::STATUS_HEAP_CORRUPTION;

use super::{RuntimeKind, invalid, memory, runtime, state, strings};

pub(crate) static ALLOCATION_EXPORTS: &[Export] = &[
    Export::func("malloc", Cdecl, &[Ptr], malloc),
    Export::func("calloc", Cdecl, &[Ptr, Ptr], calloc),
    Export::func("realloc", Cdecl, &[Ptr, Ptr], realloc),
    Export::func("free", Cdecl, &[Ptr], free),
    Export::func("_msize", Cdecl, &[Ptr], msize),
    Export::func("_expand", Cdecl, &[Ptr, Ptr], expand),
    Export::func("_strdup", Cdecl, &[Ptr], strdup),
    Export::func("_wcsdup", Cdecl, &[Ptr], wcsdup),
    Export::func("_get_heap_handle", Cdecl, &[], heap_handle),
];

/// `_HEAP_MAXREQ = SIZE_MAX - 31` matches the retained installed mingw-w64
/// malloc.h width constants. Microsoft documents the limit, not its numeric
/// value. It is an explicit SDK-width admission profile, not a version oracle.
fn max_request(c: &Ctx) -> u64 {
    c.arch().ptr(u64::MAX) - 31
}

fn oom(c: &mut Ctx, kind: RuntimeKind) -> ApiResult {
    state::set_errno(c, kind, 12)?;
    Flow::ret(0)
}

fn corrupt() -> ApiResult {
    Ok(Flow::TerminateProcess(STATUS_HEAP_CORRUPTION))
}

fn heap_failure(c: &mut Ctx, kind: RuntimeKind, error: HeapError) -> ApiResult {
    match error {
        HeapError::NoMemory => oom(c, kind),
        HeapError::MemoryFault(fault) => Err(fault.into()),
        HeapError::BadHeap | HeapError::BadBlock => corrupt(),
    }
}

/// Establish errno before any caller-visible allocator mutation.
fn allocate(c: &mut Ctx, kind: RuntimeKind, size: u64, zero: bool) -> ApiResult {
    state::ensure_writable_context(c, kind)?;
    if size > max_request(c) {
        return oom(c, kind);
    }
    let index = kind.index();
    if c.p.crt.runtimes[index].allocations.try_reserve(1).is_err() {
        return oom(c, kind);
    }
    let heap = c.p.crt.runtimes[index].heap;
    match c.p.heaps.alloc_checked(&mut c.p.vm, heap, size, zero) {
        Ok(block) => {
            c.p.crt.runtimes[index].allocations.insert(block, size);
            Flow::ret(block)
        }
        Err(error) => heap_failure(c, kind, error),
    }
}

fn malloc(c: &mut Ctx) -> ApiResult {
    let kind = runtime(c)?;
    allocate(c, kind, c.arg(0)?, false)
}

fn calloc(c: &mut Ctx) -> ApiResult {
    let kind = runtime(c)?;
    let count = c.arg(0)?;
    let size = c.arg(1)?;
    state::ensure_writable_context(c, kind)?;
    let Some(bytes) = count
        .checked_mul(size)
        .filter(|&bytes| bytes <= max_request(c))
    else {
        return oom(c, kind);
    };
    // Microsoft specifies a nonzero allocation when either operand is zero.
    // The exact usable size is unspecified; this personality selects 1 byte.
    allocate(c, kind, bytes.max(1), true)
}

fn free(c: &mut Ctx) -> ApiResult {
    let kind = runtime(c)?;
    let block = c.arg(0)?;
    if block == 0 {
        return Flow::void();
    }
    let index = kind.index();
    if !c.p.crt.runtimes[index].allocations.contains_key(&block) {
        return corrupt();
    }
    let heap = c.p.crt.runtimes[index].heap;
    match c.p.heaps.free(heap, block) {
        Ok(()) => {
            c.p.crt.runtimes[index].allocations.remove(&block);
            Flow::void()
        }
        Err(_) => corrupt(),
    }
}

fn resize(c: &mut Ctx, in_place: bool) -> ApiResult {
    let kind = runtime(c)?;
    let block = c.arg(0)?;
    let size = c.arg(1)?;
    if block == 0 {
        if !in_place {
            return allocate(c, kind, size, false);
        }
        return invalid::invoke(
            c,
            kind,
            [0; 5],
            Box::new(move |c, _| {
                state::set_errno(c, kind, 22)?;
                Flow::ret(0)
            }),
        );
    }
    state::ensure_writable_context(c, kind)?;
    let index = kind.index();
    if !c.p.crt.runtimes[index].allocations.contains_key(&block) {
        return corrupt();
    }
    let heap = c.p.crt.runtimes[index].heap;
    if size == 0 && !in_place {
        match c.p.heaps.free(heap, block) {
            Ok(()) => {
                c.p.crt.runtimes[index].allocations.remove(&block);
                return Flow::ret(0);
            }
            Err(_) => return corrupt(),
        }
    }
    if size > max_request(c) {
        return oom(c, kind);
    }
    // Reserving one slot before moving also makes publication fallible only
    // before the heap operation. Old allocations survive every failure.
    if c.p.crt.runtimes[index].allocations.try_reserve(1).is_err() {
        return oom(c, kind);
    }
    match c
        .p
        .heaps
        .realloc(&mut c.p.vm, heap, block, size, in_place, false)
    {
        Ok(next) => {
            c.p.crt.runtimes[index].allocations.remove(&block);
            c.p.crt.runtimes[index].allocations.insert(next, size);
            Flow::ret(next)
        }
        Err(error) => heap_failure(c, kind, error),
    }
}
fn realloc(c: &mut Ctx) -> ApiResult {
    resize(c, false)
}
fn expand(c: &mut Ctx) -> ApiResult {
    resize(c, true)
}

fn msize(c: &mut Ctx) -> ApiResult {
    let kind = runtime(c)?;
    let block = c.arg(0)?;
    if block == 0 {
        return invalid::invoke(
            c,
            kind,
            [0; 5],
            Box::new(move |c, _| {
                state::set_errno(c, kind, 22)?;
                Flow::ret(c.arch().ptr(u64::MAX))
            }),
        );
    }
    let runtime = &c.p.crt.runtimes[kind.index()];
    if !runtime.allocations.contains_key(&block) {
        return corrupt();
    }
    match c.p.heaps.size(runtime.heap, block) {
        Ok(size) => Flow::ret(size),
        Err(_) => corrupt(),
    }
}

fn duplicate(c: &mut Ctx, unit: u64) -> ApiResult {
    let kind = runtime(c)?;
    let source = c.arg(0)?;
    state::ensure_writable_context(c, kind)?;
    // No host text conversion, artificial NUL cutoff, or proportional buffer.
    let length = strings::string_len(c, source, unit, None)?;
    let Some(bytes) = length
        .checked_add(1)
        .and_then(|n| n.checked_mul(unit))
        .filter(|&bytes| bytes <= max_request(c))
    else {
        return oom(c, kind);
    };
    let flow = allocate(c, kind, bytes, false)?;
    let Flow::Ret(crate::user::windows::hle::Value::Int(block)) = flow else {
        return Ok(flow);
    };
    if block == 0 {
        return Flow::ret(0);
    }
    if let Err(error) = memory::copy(c, block, source, bytes) {
        let runtime = &mut c.p.crt.runtimes[kind.index()];
        if c.p.heaps.free(runtime.heap, block).is_err() {
            return Err(ApiErr::Internal("CRT string-copy rollback failed".into()));
        }
        runtime.allocations.remove(&block);
        return Err(error);
    }
    Flow::ret(block)
}
fn strdup(c: &mut Ctx) -> ApiResult {
    duplicate(c, 1)
}
fn wcsdup(c: &mut Ctx) -> ApiResult {
    duplicate(c, 2)
}

fn heap_handle(c: &mut Ctx) -> ApiResult {
    let kind = runtime(c)?;
    Flow::ret(state::ensure_heap(c, kind)?)
}
