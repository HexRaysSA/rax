//! Runtime-private heaps and thread (not fiber) error/handler cells.

use crate::error::MemoryAccessKind;
use crate::user::windows::context::ExceptionRecord;
use crate::user::windows::heap::HeapError;
use crate::user::windows::hle::{ApiErr, ApiResult, Arg::*, Conv::Cdecl, Ctx, Export, Flow};
use crate::user::windows::memory::{Mem, MemFault};
use crate::user::windows::nt::status::{STATUS_HEAP_CORRUPTION, STATUS_NO_MEMORY};
use crate::user::windows::process::Proc;

use super::{RuntimeKind, ThreadState, invalid, runtime};

/// Common admitted pointer exports; legacy compatibility wrappers are not
/// manufactured as native MSVCRT named exports.
pub(crate) static STATE_EXPORTS: &[Export] = &[
    Export::func("_errno", Cdecl, &[], errno_pointer),
    Export::func("__doserrno", Cdecl, &[], doserrno_pointer),
];

pub(crate) static UCRT_STATE_EXPORTS: &[Export] = &[
    Export::func("_get_errno", Cdecl, &[Ptr], get_errno),
    Export::func("_set_errno", Cdecl, &[I32], set_errno_api),
    Export::func("_get_doserrno", Cdecl, &[Ptr], get_doserrno),
    Export::func("_set_doserrno", Cdecl, &[I32], set_doserrno),
    Export::func(
        "_set_invalid_parameter_handler",
        Cdecl,
        &[Ptr],
        invalid::set_global,
    ),
    Export::func(
        "_get_invalid_parameter_handler",
        Cdecl,
        &[],
        invalid::get_global,
    ),
    Export::func(
        "_set_thread_local_invalid_parameter_handler",
        Cdecl,
        &[Ptr],
        invalid::set_thread,
    ),
    Export::func(
        "_get_thread_local_invalid_parameter_handler",
        Cdecl,
        &[],
        invalid::get_thread,
    ),
    Export::func(
        "_invalid_parameter",
        Cdecl,
        &[Ptr, Ptr, Ptr, I32, Ptr],
        invalid::parameter,
    ),
    Export::func("_invalid_parameter_noinfo", Cdecl, &[], invalid::noinfo),
    Export::func(
        "_invalid_parameter_noinfo_noreturn",
        Cdecl,
        &[],
        invalid::noreturn,
    ),
    Export::func(
        "_invoke_watson",
        Cdecl,
        &[Ptr, Ptr, Ptr, I32, Ptr],
        invalid::watson,
    ),
];

fn no_context_memory(c: &Ctx) -> ApiErr {
    // Lazy PTD establishment is a separate admission failure: there is no
    // error cell in which to record ENOMEM yet. This is an explicit profile,
    // not a native claim about the CRT's internal allocation failure policy.
    ApiErr::Raise(ExceptionRecord::new(
        STATUS_NO_MEMORY,
        c.entry_pc,
        Vec::new(),
    ))
}

pub(super) fn ensure_heap(c: &mut Ctx, kind: RuntimeKind) -> Result<u64, ApiErr> {
    let index = kind.index();
    let existing = c.p.crt.runtimes[index].heap;
    if existing != 0 {
        return Ok(existing);
    }
    let heap =
        c.p.heaps
            .create(&mut c.p.vm, 0, 0, 0)
            .ok_or_else(|| no_context_memory(c))?;
    c.p.crt.runtimes[index].heap = heap;
    Ok(heap)
}

pub(super) fn probe(c: &Ctx, address: u64, bytes: usize, write: bool) -> Result<(), ApiErr> {
    let last = address
        .checked_add(bytes.saturating_sub(1) as u64)
        .filter(|&last| c.arch().ptr(last) == last)
        .ok_or(MemFault {
            addr: address,
            write,
        })?;
    let _ = last;
    c.mem()
        .probe(
            address,
            bytes,
            if write {
                MemoryAccessKind::Write
            } else {
                MemoryAccessKind::Read
            },
        )
        .map_err(|error| {
            ApiErr::Fault(MemFault {
                addr: error.address,
                write,
            })
        })
}

/// Establish a thread context without requiring existing cells to be writable.
pub(super) fn ensure_context(c: &mut Ctx, kind: RuntimeKind) -> Result<u64, ApiErr> {
    let index = kind.index();
    if let Some(context) = c.p.crt.runtimes[index].contexts.get(&c.t.tid) {
        return Ok(context.cells);
    }
    let heap = ensure_heap(c, kind)?;
    c.p.crt.runtimes[index]
        .contexts
        .try_reserve(1)
        .map_err(|_| no_context_memory(c))?;
    // Two 32-bit error cells and the pointer-width _tpxcptinfoptrs object.
    // calloc initialization keeps that exposed slot NULL before publication.
    let bytes = 8 + c.arch().ptr_size();
    let cells = match c.p.heaps.alloc_checked(&mut c.p.vm, heap, bytes, true) {
        Ok(cells) => cells,
        Err(HeapError::MemoryFault(fault)) => return Err(fault.into()),
        Err(HeapError::NoMemory) => return Err(no_context_memory(c)),
        Err(_) => return Err(ApiErr::Internal("CRT private heap was destroyed".into())),
    };
    c.p.crt.runtimes[index].contexts.insert(
        c.t.tid,
        ThreadState {
            cells,
            invalid_handler: 0,
            terminate_handler: 0,
            locale_flags: 1,
        },
    );
    Ok(cells)
}

pub(super) fn set_errno(c: &mut Ctx, kind: RuntimeKind, value: u32) -> Result<(), ApiErr> {
    let cells = ensure_context(c, kind)?;
    c.mem().w32(cells, value)?;
    Ok(())
}

/// Preflight errno before allocator effects: reporting ENOMEM must not fault
/// after resizing a caller's block. Accessors do not impose this write probe.
pub(super) fn ensure_writable_context(c: &mut Ctx, kind: RuntimeKind) -> Result<u64, ApiErr> {
    let cells = ensure_context(c, kind)?;
    probe(c, cells, 4, true)?;
    Ok(cells)
}

fn errno_pointer(c: &mut Ctx) -> ApiResult {
    let kind = runtime(c)?;
    Flow::ret(ensure_context(c, kind)?)
}

fn doserrno_pointer(c: &mut Ctx) -> ApiResult {
    let kind = runtime(c)?;
    Flow::ret(ensure_context(c, kind)? + 4)
}

fn get_error(c: &mut Ctx, offset: u64) -> ApiResult {
    let kind = runtime(c)?;
    let output = c.arg(0)?;
    if output == 0 {
        return invalid::invoke(
            c,
            kind,
            [0; 5],
            Box::new(move |c, _| {
                set_errno(c, kind, 22)?;
                Flow::ret(22)
            }),
        );
    }
    probe(c, output, 4, true)?;
    let cells = ensure_context(c, kind)?;
    let value = c.mem().u32(cells + offset)?;
    c.mem().w32(output, value)?;
    Flow::ret(0)
}

fn get_errno(c: &mut Ctx) -> ApiResult {
    get_error(c, 0)
}
fn get_doserrno(c: &mut Ctx) -> ApiResult {
    get_error(c, 4)
}

fn set_errno_api(c: &mut Ctx) -> ApiResult {
    let kind = runtime(c)?;
    let value = c.arg(0)? as u32;
    set_errno(c, kind, value)?;
    Flow::ret(0)
}

fn set_doserrno(c: &mut Ctx) -> ApiResult {
    let kind = runtime(c)?;
    let value = c.arg(0)? as u32;
    let cells = ensure_context(c, kind)?;
    c.mem().w32(cells + 4, value)?;
    Flow::ret(0)
}

/// Called only for actual thread destruction, not conversion or fiber switch.
/// No guest callbacks; a failed private-heap release is diagnostic, not hidden.
pub(crate) fn release_thread(p: &mut Proc, tid: u32) -> Result<(), u32> {
    for runtime in &mut p.crt.runtimes {
        if let Some(context) = runtime.contexts.get(&tid) {
            p.heaps
                .free(runtime.heap, context.cells)
                .map_err(|_| STATUS_HEAP_CORRUPTION)?;
            runtime.contexts.remove(&tid);
        }
    }
    Ok(())
}
