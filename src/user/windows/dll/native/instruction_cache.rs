//! Guest-only synchronization with independently captured native probe ordering.
use crate::user::mm::PAGE_SIZE;
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiResult, Ctx, Flow};
use crate::user::windows::memory::prot;
use crate::user::windows::nt::{self, status::*};
use crate::user::windows::objects::Object;
use std::ops::Bound::{Excluded, Included};

const USER_PROBE: u64 = 0x7fff_ffff_0000;
const PROCESS_VM_WRITE: u32 = 0x20;

pub(super) fn flush(c: &mut Ctx) -> ApiResult {
    Flow::ret(u64::from(synchronize(c)?))
}

pub(in crate::user::windows::dll) fn win32(c: &mut Ctx) -> ApiResult {
    let status = synchronize(c)?;
    if status == STATUS_SUCCESS {
        Flow::bool(true)
    } else {
        c.fail(nt::status_to_error(status), 0)
    }
}

fn synchronize(c: &mut Ctx) -> Result<u32, crate::user::windows::hle::ApiErr> {
    if c.arch() == WinArch::X86 {
        // The captured x86 entry ignores all three arguments. In particular,
        // an unused argument slot must not consume a caller guard page.
        c.p.space.synchronize_code(0, c.p.space.va_limit());
        return Ok(STATUS_SUCCESS);
    }
    let (handle, base, length) = (c.ptr(0)?, c.ptr(1)?, c.ptr(2)?);
    if base != 0 {
        if length == 0 {
            return Ok(STATUS_SUCCESS);
        }
        if base.checked_add(length).is_none_or(|end| end > USER_PROBE) {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
    }
    let status = process_status(c, handle)?;
    if status != STATUS_SUCCESS {
        return Ok(status);
    }
    if base == 0 {
        // Null selects the whole process, ignores length and visits no data
        // pages. The x86 adapter bounds large invalidations by a full flush.
        c.p.space.synchronize_code(0, c.p.space.va_limit());
    } else {
        consume_first_guard(c, base, base + length);
        c.p.space.synchronize_code(base, length);
    }
    Ok(STATUS_SUCCESS)
}

fn process_status(c: &Ctx, handle: u64) -> Result<u32, crate::user::windows::hle::ApiErr> {
    if handle == c.arch().ptr(u64::MAX) {
        return Ok(STATUS_SUCCESS);
    }
    if handle == c.arch().ptr(u64::MAX - 1) {
        return Ok(STATUS_OBJECT_TYPE_MISMATCH);
    }
    match c.p.objects.get(handle) {
        None => Ok(STATUS_INVALID_HANDLE),
        Some(Object::Process { pid, .. }) => {
            if c.p.objects.access(handle).unwrap_or(0) & PROCESS_VM_WRITE == 0 {
                Ok(STATUS_ACCESS_DENIED)
            } else if *pid != c.p.pid {
                Err(c.unsupported("NtFlushInstructionCache for another guest process"))
            } else {
                Ok(STATUS_SUCCESS)
            }
        }
        Some(_) => Ok(STATUS_OBJECT_TYPE_MISMATCH),
    }
}

/// Find the first armed page using allocation/state runs, not a page walk.
/// O(A log R + Rv) time and O(1) scratch for A visited allocations, R state
/// runs per allocation and Rv visited run boundaries. Reported protection
/// overrides do not authorize or suppress actual guard consumption.
fn consume_first_guard(c: &mut Ctx, start: u64, end: u64) {
    let guard = c.p.vm.allocations().find_map(|allocation| {
        let lo = start.max(allocation.base);
        let hi = end.min(allocation.base + allocation.size);
        if lo >= hi {
            return None;
        }
        let first = (lo - allocation.base) / PAGE_SIZE;
        let last = (hi - 1 - allocation.base) / PAGE_SIZE;
        let armed = |state: &crate::user::windows::memory::PageState| {
            state.committed && state.protect & prot::GUARD != 0
        };
        if allocation
            .pages
            .range(..=first)
            .next_back()
            .is_some_and(|(_, state)| armed(state))
        {
            return Some(allocation.base + first * PAGE_SIZE);
        }
        allocation
            .pages
            .range((Excluded(first), Included(last)))
            .find_map(|(&page, state)| armed(state).then_some(allocation.base + page * PAGE_SIZE))
    });
    if let Some(page) = guard {
        c.p.vm.take_guard(page);
    }
}
