//! NT class2 captures caller records before mutating guest-owned CFG state.
//!
//! Native and WoW64 entry differ in capture and processed-output publication.
//! Their private-memory worker is shared; no guest pointer reaches the host.
use crate::error::MemoryAccessKind;
use crate::user::mm::PAGE_SIZE;
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiErr, ApiResult, Ctx, Flow};
use crate::user::windows::memory::{Mem, MemFault};
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::Object;

#[derive(Clone, Copy)]
struct Range {
    base: u64,
    bytes: u64,
}

struct List {
    count: u32,
    reserved: u32,
    processed: u64,
    targets: u64,
    section: u64,
}

#[derive(Clone, Copy)]
struct Target {
    offset: u64,
    flags: u64,
}

fn read_probe(c: &Ctx, address: u64, bytes: u64) -> Result<(), ApiErr> {
    super::memory_prefetch::probe_ranges(c, address, bytes)
}

fn list(c: &Ctx, address: u64, wow: bool) -> Result<List, ApiErr> {
    // The WoW thunk reads only its conversion prefix. Section and FileOffset
    // do not cross that thunk, even if the supplied 32-byte record spans pages.
    read_probe(c, address, if wow { 16 } else { 40 })?;
    Ok(List {
        count: c.mem().u32(address)?,
        reserved: c.mem().u32(address + 4)?,
        processed: c.read_ptr(address + 8)?,
        targets: c.read_ptr(address + 8 + c.psize())?,
        section: if wow { 0 } else { c.read_ptr(address + 24)? },
    })
}

fn range(c: &Ctx, address: u64) -> Result<Range, ApiErr> {
    Ok(Range {
        base: c.read_ptr(address)?,
        bytes: c.read_ptr(address + c.psize())?,
    })
}

fn capture_targets(c: &Ctx, info: &List) -> Result<Option<Vec<Target>>, ApiErr> {
    let bytes = u64::from(info.count) * 2 * c.psize();
    read_probe(c, info.targets, bytes)?;
    // This is an owned shadow, including when NumberOfEntriesProcessed aliases
    // the input table. Charge its bounded capture against guest kernel memory.
    if u64::from(info.count) * std::mem::size_of::<Target>() as u64 > c.p.vm.commit_limit() {
        return Ok(None);
    }
    let mut records = Vec::new();
    if records.try_reserve_exact(info.count as usize).is_err() {
        return Ok(None);
    }
    for index in 0..u64::from(info.count) {
        let at = info.targets + index * 2 * c.psize();
        records.push(Target {
            offset: c.read_ptr(at)?,
            flags: c.read_ptr(at + c.psize())?,
        });
    }
    Ok(Some(records))
}

fn header_status(c: &Ctx, count: u64, range: Range, info: &List) -> Result<u32, ApiErr> {
    Ok(if count != 1 || range.bytes == 0 {
        STATUS_INVALID_PARAMETER_4
    } else if info.count == 0 || info.reserved != 0 {
        STATUS_INVALID_PARAMETER_5
    } else if info.section != 0 {
        match c.p.objects.get(info.section) {
            Some(Object::ImageSection(_) | Object::DataSection(_) | Object::FileSection(_)) => {
                return Err(c.unsupported("CFG section-backed target registration"));
            }
            Some(_) => STATUS_OBJECT_TYPE_MISMATCH,
            None if info.section == c.arch().ptr(u64::MAX)
                || info.section == c.arch().ptr(u64::MAX - 1) =>
            {
                STATUS_OBJECT_TYPE_MISMATCH
            }
            None => STATUS_INVALID_HANDLE,
        }
    } else {
        STATUS_SUCCESS
    })
}

fn extended_flags(c: &Ctx, flags: u64) -> Result<u32, ApiErr> {
    if flags & 4 != 0 {
        return Ok(STATUS_ACCESS_DENIED);
    }
    if flags & (8 | 16) == 0 {
        return Ok(STATUS_SUCCESS);
    }
    let Some(native) = &c.p.native else {
        return Ok(STATUS_NOT_SUPPORTED);
    };
    match (
        native.version.major,
        native.version.minor,
        native.version.build,
        native.object_namespace.native_machine,
    ) {
        (10, 0, 20348, Some(0x8664)) => Ok(STATUS_ACCESS_DENIED),
        (10, 0, 26100, Some(0x8664)) | (10, 0, 29695 | 29698, Some(0xaa64)) => {
            Ok(STATUS_NOT_SUPPORTED)
        }
        _ => Err(c.unsupported("native CFG extended-target flag capability is not captured")),
    }
}

fn apply(
    c: &mut Ctx,
    range: Range,
    targets: &[Target],
    processed: &mut u32,
) -> Result<u32, ApiErr> {
    if range.base % PAGE_SIZE != 0
        || range.bytes % PAGE_SIZE != 0
        || range
            .base
            .checked_add(range.bytes)
            .is_none_or(|end| end > c.p.vm.high())
    {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    // Validate the entire descriptor table before publishing any target bit.
    // Duplicates are accepted; decreasing or unaligned offsets are rejected.
    let mut previous = 0;
    for target in targets {
        if target.offset % 16 != 0
            || target.offset >= range.bytes
            || target.offset < previous
            || target.flags & !0x1f != 0
        {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        previous = target.offset;
    }
    // Policy rejection prevalidates the whole captured table. In contrast, a
    // later bitmap-storage fault preserves the earlier target stores below.
    for target in targets {
        let status = extended_flags(c, target.flags)?;
        if status != STATUS_SUCCESS {
            return Ok(status);
        }
    }
    for target in targets {
        if let Err(error) =
            c.p.vm
                .set_call_target(range.base + target.offset, target.flags & 1 != 0)
        {
            return Ok(error.status());
        }
        *processed += 1;
    }
    Ok(STATUS_SUCCESS)
}

/// O(n + n log r) time and O(n) shadow space for n target records and r sparse
/// target boundaries. The shadow bounds input/output aliases and never escapes.
pub(super) fn set(
    c: &mut Ctx,
    process: u64,
    count: u64,
    ranges: u64,
    information: u64,
    length: u32,
) -> ApiResult {
    let wow = c.arch() == WinArch::X86;
    let width = c.psize();
    let mut captured_range = None;
    if wow {
        if count == 0 {
            return Flow::ret(STATUS_INVALID_PARAMETER_3.into());
        }
        if count
            .checked_mul(16)
            .is_none_or(|bytes| bytes > c.p.vm.commit_limit())
        {
            c.set_last_error(8)?;
            return Flow::ret(STATUS_NO_MEMORY.into());
        }
        read_probe(c, ranges, count * 2 * width)?;
        captured_range = Some(range(c, ranges)?);
    }
    if length != if wow { 32 } else { 40 } {
        return Flow::ret(STATUS_INVALID_PARAMETER_6.into());
    }
    if count == 0 || count.checked_mul(16).is_none() {
        return Flow::ret(STATUS_INVALID_PARAMETER_3.into());
    }
    if !wow && information % 4 != 0 {
        return Flow::ret(STATUS_DATATYPE_MISALIGNMENT.into());
    }
    let info = list(c, information, wow)?;
    let captured_range = if let Some(value) = captured_range {
        value
    } else {
        if ranges % 4 != 0 {
            return Flow::ret(STATUS_DATATYPE_MISALIGNMENT.into());
        }
        read_probe(c, ranges, count * 16)?;
        range(c, ranges)?
    };
    if wow && info.count == 0 {
        return Flow::ret(STATUS_INVALID_PARAMETER_5.into());
    }
    if !wow {
        let status = header_status(c, count, captured_range, &info)?;
        if status != STATUS_SUCCESS {
            return Flow::ret(status.into());
        }
        if info.targets % 4 != 0 {
            return Flow::ret(STATUS_DATATYPE_MISALIGNMENT.into());
        }
    }
    let Some(targets) = capture_targets(c, &info)? else {
        return Flow::ret(STATUS_NO_MEMORY.into());
    };
    if !wow {
        if info.processed % 4 != 0 {
            return Flow::ret(STATUS_DATATYPE_MISALIGNMENT.into());
        }
        c.mem()
            .probe(info.processed, 4, MemoryAccessKind::Write)
            .map_err(|fault| MemFault {
                addr: fault.address,
                write: true,
            })?;
    }
    let mut processed = 0;
    let status = header_status(c, count, captured_range, &info)?;
    let status = if status == STATUS_SUCCESS {
        super::memory_prefetch::process_status(c, process)?
    } else {
        status
    };
    if !wow && status != STATUS_SUCCESS {
        return Flow::ret(status.into());
    }
    if !wow {
        c.mem().w32(info.processed, 0)?;
    }
    let result = if status == STATUS_SUCCESS {
        apply(c, captured_range, &targets, &mut processed)
    } else {
        Ok(status)
    };
    if wow {
        // Copyback faults are swallowed by the thunk; they do not replace the
        // NT result or authorize any host access. Inputs are already captured.
        if let Err(fault) = c.mem().w32(info.processed, processed) {
            // Writable guards are visited by the attempted thunk store;
            // readonly guards fail permission validation without visitation.
            let _ = super::query::write_guard_result(c, Err(fault.into()));
        }
    } else {
        c.mem().w32(info.processed, processed)?;
    }
    Flow::ret(result?.into())
}
