//! Interlocked singly linked lists (`SLIST_HEADER`).
//!
//! The MSVC CRT initializes one during startup (`__scrt_initialize_type_info`
//! calls `InitializeSListHead`), so an ordinary MSVC executable cannot reach
//! `main` without these.
//!
//! Header layouts follow the Windows SDK `winnt.h` (10.0.26100):
//!
//! - x64 and ARM64: 16 bytes, 16-byte aligned. The low quadword holds
//!   `Depth:16` then `Sequence:48`; the high quadword holds `Reserved:4` then
//!   `NextEntry:60`, the first entry's address shifted right by four, so
//!   entries are 16-byte aligned too.
//! - x86: 8 bytes: `Next` (a 32-bit pointer) at 0, `Depth` at 4, `CpuId` at 6.
//!
//! Every built-in call runs inside one scheduler turn, so each operation is
//! atomic with respect to the guest's other threads without a lock of its own.
//! Each one reads and validates everything before writing anything, and
//! proves the header writable before touching an entry, so a fault leaves the
//! list as it was. The way native Windows advances `Sequence` and `CpuId` is
//! not documented; this implementation increments `Sequence` on every change
//! except a flush, writes `CpuId` only when initializing the header, and
//! nothing depends on either.

use super::super::arch::WinArch;
use super::super::context::ExceptionRecord;
use super::super::hle::{ApiErr, ApiResult, Arg::*, Conv::Stdcall, Ctx, Export, Flow};
use super::super::memory::Mem;
use super::super::nt::status::STATUS_DATATYPE_MISALIGNMENT;

pub(super) static NTDLL_EXPORTS: &[Export] = &[
    Export::func("RtlInitializeSListHead", Stdcall, &[Ptr], initialize),
    Export::func("RtlInterlockedPushEntrySList", Stdcall, &[Ptr, Ptr], push),
    Export::func("RtlInterlockedPopEntrySList", Stdcall, &[Ptr], pop),
    Export::func("RtlInterlockedFlushSList", Stdcall, &[Ptr], flush),
    Export::func("RtlQueryDepthSList", Stdcall, &[Ptr], query_depth),
    Export::func("RtlFirstEntrySList", Stdcall, &[Ptr], first_entry),
    Export::func(
        "RtlInterlockedPushListSListEx",
        Stdcall,
        &[Ptr, Ptr, Ptr, I32],
        push_list,
    ),
];

/// KERNEL32 and KERNELBASE forward to NTDLL, as on Windows, so
/// `GetProcAddress` gives the same address for both names. The x86-only
/// `InterlockedPushListSList` is `__fastcall`, which the built-in calling
/// conventions do not model; the SDK maps callers to the `Ex` form.
pub(super) static KERNEL_FORWARDS: &[Export] = &[
    Export::forward("InitializeSListHead", "NTDLL.RtlInitializeSListHead"),
    Export::forward(
        "InterlockedPushEntrySList",
        "NTDLL.RtlInterlockedPushEntrySList",
    ),
    Export::forward(
        "InterlockedPopEntrySList",
        "NTDLL.RtlInterlockedPopEntrySList",
    ),
    Export::forward("InterlockedFlushSList", "NTDLL.RtlInterlockedFlushSList"),
    Export::forward("QueryDepthSList", "NTDLL.RtlQueryDepthSList"),
    Export::forward(
        "InterlockedPushListSListEx",
        "NTDLL.RtlInterlockedPushListSListEx",
    ),
];

const SEQUENCE_MASK: u64 = (1 << 48) - 1;

/// A decoded header: the first entry, the depth, and the sequence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Header {
    first: u64,
    depth: u16,
    sequence: u64,
}

fn wide(c: &Ctx) -> bool {
    c.arch() != WinArch::X86
}

/// x64 and ARM64 require 16-byte headers and entries; a misaligned one is
/// raised as Windows raises a misaligned interlocked operation.
fn check_aligned(c: &Ctx, address: u64) -> Result<(), ApiErr> {
    if wide(c) && address % 16 != 0 {
        return Err(ApiErr::Raise(ExceptionRecord::new(
            STATUS_DATATYPE_MISALIGNMENT,
            c.entry_pc,
            vec![],
        )));
    }
    Ok(())
}

fn read_header(c: &Ctx, header: u64) -> Result<Header, ApiErr> {
    let mem = c.mem();
    if wide(c) {
        let (low, high) = (mem.u64(header)?, mem.u64(header + 8)?);
        Ok(Header {
            first: high & !0xF,
            depth: low as u16,
            sequence: (low >> 16) & SEQUENCE_MASK,
        })
    } else {
        Ok(Header {
            first: u64::from(mem.u32(header)?),
            depth: mem.u16(header + 4)?,
            sequence: 0,
        })
    }
}

fn write_header(c: &Ctx, header: u64, value: Header) -> Result<(), ApiErr> {
    let mem = c.mem();
    if wide(c) {
        let low = u64::from(value.depth) | ((value.sequence & SEQUENCE_MASK) << 16);
        mem.w64(header, low)?;
        mem.w64(header + 8, value.first & !0xF)?;
    } else {
        mem.w32(header, value.first as u32)?;
        mem.w16(header + 4, value.depth)?;
    }
    Ok(())
}

/// Writes the header's own bytes back, proving it writable before an entry
/// is modified.
fn probe_header_writable(c: &Ctx, header: u64) -> Result<(), ApiErr> {
    let size = if wide(c) { 16 } else { 8 };
    let bytes = c.mem().bytes(header, size)?;
    c.mem().wr(header, &bytes)?;
    Ok(())
}

fn read_next(c: &Ctx, entry: u64) -> Result<u64, ApiErr> {
    Ok(c.read_ptr(entry)?)
}

fn write_next(c: &Ctx, entry: u64, next: u64) -> Result<(), ApiErr> {
    Ok(c.write_ptr(entry, next)?)
}

/// Clears every byte of the header, x86's `CpuId` word included: it is the
/// only operation that writes that word.
fn initialize(c: &mut Ctx) -> ApiResult {
    let header = c.ptr(0)?;
    check_aligned(c, header)?;
    let size = if wide(c) { 16 } else { 8 };
    c.mem().wr(header, &[0; 16][..size])?;
    Flow::void()
}

fn push(c: &mut Ctx) -> ApiResult {
    let (header, entry) = (c.ptr(0)?, c.ptr(1)?);
    check_aligned(c, header)?;
    check_aligned(c, entry)?;
    let old = read_header(c, header)?;
    probe_header_writable(c, header)?;
    write_next(c, entry, old.first)?;
    write_header(
        c,
        header,
        Header {
            first: entry,
            depth: old.depth.wrapping_add(1),
            sequence: old.sequence.wrapping_add(1),
        },
    )?;
    Flow::ret(old.first)
}

fn pop(c: &mut Ctx) -> ApiResult {
    let header = c.ptr(0)?;
    check_aligned(c, header)?;
    let old = read_header(c, header)?;
    if old.first == 0 {
        return Flow::ret(0);
    }
    let next = read_next(c, old.first)?;
    write_header(
        c,
        header,
        Header {
            first: next,
            depth: old.depth.wrapping_sub(1),
            sequence: old.sequence.wrapping_add(1),
        },
    )?;
    Flow::ret(old.first)
}

fn flush(c: &mut Ctx) -> ApiResult {
    let header = c.ptr(0)?;
    check_aligned(c, header)?;
    let old = read_header(c, header)?;
    if old.first == 0 {
        return Flow::ret(0);
    }
    write_header(
        c,
        header,
        Header {
            first: 0,
            depth: 0,
            sequence: old.sequence,
        },
    )?;
    Flow::ret(old.first)
}

fn query_depth(c: &mut Ctx) -> ApiResult {
    let header = c.ptr(0)?;
    Flow::ret(u64::from(read_header(c, header)?.depth))
}

fn first_entry(c: &mut Ctx) -> ApiResult {
    let header = c.ptr(0)?;
    Flow::ret(read_header(c, header)?.first)
}

fn push_list(c: &mut Ctx) -> ApiResult {
    let (header, list, list_end, count) = (c.ptr(0)?, c.ptr(1)?, c.ptr(2)?, c.u32(3)?);
    check_aligned(c, header)?;
    check_aligned(c, list)?;
    check_aligned(c, list_end)?;
    let old = read_header(c, header)?;
    probe_header_writable(c, header)?;
    write_next(c, list_end, old.first)?;
    write_header(
        c,
        header,
        Header {
            first: list,
            depth: old.depth.wrapping_add(count as u16),
            sequence: old.sequence.wrapping_add(1),
        },
    )?;
    Flow::ret(old.first)
}

#[cfg(test)]
mod tests;
