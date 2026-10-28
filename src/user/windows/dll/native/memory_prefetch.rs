//! NtSetInformationVirtualMemory class0: guest ranges and native/WoW capture.
//! Independent native controls live in docs/specifications/windows/native-memory-prefetch.
use super::query::guard_result;
use crate::error::MemoryAccessKind;
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiErr, ApiResult, Ctx, Flow};
use crate::user::windows::memory::{Mem, MemFault};
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::Object;

pub(super) fn set(c: &mut Ctx) -> ApiResult {
    let result = checked(c);
    guard_result(c, result)
}

fn probe_ranges(c: &Ctx, address: u64, bytes: u64) -> Result<(), ApiErr> {
    let length = usize::try_from(bytes).map_err(|_| MemFault {
        addr: address,
        write: false,
    })?;
    c.mem()
        .probe(address, length, MemoryAccessKind::Read)
        .map_err(|fault| MemFault {
            addr: fault.address,
            write: false,
        })?;
    Ok(())
}

fn process_status(c: &Ctx, handle: u64) -> Result<u32, ApiErr> {
    if handle == c.arch().ptr(u64::MAX) {
        return Ok(STATUS_SUCCESS);
    }
    if handle == c.arch().ptr(u64::MAX - 1) {
        return Ok(STATUS_OBJECT_TYPE_MISMATCH);
    }
    match c.p.objects.get(handle) {
        None => Ok(STATUS_INVALID_HANDLE),
        Some(Object::Process { pid, .. }) => {
            if c.p.objects.access(handle).unwrap_or(0) & 8 == 0 {
                Ok(STATUS_ACCESS_DENIED)
            } else if *pid != c.p.pid {
                Err(c.unsupported("NtSetInformationVirtualMemory for another process"))
            } else {
                Ok(STATUS_SUCCESS)
            }
        }
        Some(_) => Ok(STATUS_OBJECT_TYPE_MISMATCH),
    }
}

fn checked(c: &mut Ctx) -> ApiResult {
    let (process, class, count, ranges, information, length) = (
        c.ptr(0)?,
        c.u32(1)?,
        c.ptr(2)?,
        c.ptr(3)?,
        c.ptr(4)?,
        c.u32(5)?,
    );
    let wow = c.arch() == WinArch::X86;
    let width = c.psize();
    let bytes = count.saturating_mul(2 * width);
    if wow {
        // The thunk captures and widens the range list before entering the
        // native service, including before its class, length and handle checks.
        if count == 0 {
            return Flow::ret(STATUS_INVALID_PARAMETER_3.into());
        }
        if count
            .checked_mul(16)
            .is_none_or(|size| size > c.p.vm.commit_limit())
        {
            // The WoW64 conversion allocation reports ERROR_NOT_ENOUGH_MEMORY
            // as well as its NT failure. Other reached paths preserve LastError.
            c.set_last_error(8)?;
            return Flow::ret(STATUS_NO_MEMORY.into());
        }
        probe_ranges(c, ranges, bytes)?;
    }
    if class >= 9 {
        return Flow::ret(STATUS_INVALID_PARAMETER_2.into());
    }
    if class != 0 {
        return Err(c.unsupported(format!("NtSetInformationVirtualMemory class {class}")));
    }
    if information == 0 {
        return Flow::ret(STATUS_INVALID_PARAMETER_5.into());
    }
    if length != 4 {
        return Flow::ret(STATUS_INVALID_PARAMETER_6.into());
    }
    if count == 0 || count > u64::MAX / 16 {
        return Flow::ret(STATUS_INVALID_PARAMETER_3.into());
    }
    if information % 4 != 0 {
        return Flow::ret(STATUS_DATATYPE_MISALIGNMENT.into());
    }
    let flags = c.mem().u32(information)?;
    let status = process_status(c, process)?;
    if status != STATUS_SUCCESS {
        return Flow::ret(status.into());
    }
    if !wow {
        if ranges % 4 != 0 {
            return Flow::ret(STATUS_DATATYPE_MISALIGNMENT.into());
        }
        probe_ranges(c, ranges, bytes)?;
    }
    // WoW64 widens both fields before native validation. Its valid range can
    // exceed the 32-bit process limit; unavailable target pages remain advice
    // misses. No guest pointer or handle is forwarded to the host kernel.
    let high = crate::user::windows::layout::user_limit(WinArch::X64, true);
    for index in 0..count {
        let at = ranges + index * 2 * width;
        let address = c.read_ptr(at)?;
        let size = c.read_ptr(at + width)?;
        if size == 0 || address.checked_add(size).is_none_or(|end| end > high) {
            return Flow::ret(STATUS_INVALID_PARAMETER_4.into());
        }
    }
    if flags & !1 != 0 {
        return Flow::ret(STATUS_INVALID_PARAMETER_5.into());
    }
    if flags == 1 {
        // A second bounded walk needs no guest-count-sized host allocation.
        // Guest threads cannot run during this dispatch, and the service never
        // writes caller buffers. Re-read the checked, resident descriptors.
        for index in 0..count {
            let at = ranges + index * 2 * width;
            c.p.vm
                .prefetch_working_set(c.read_ptr(at)?, c.read_ptr(at + width)?);
        }
    }
    // Flag0 is a cache hint, not working-set insertion. This model has no
    // standby-list cache: accepting the advice leaves guest residency intact.
    Flow::ret(STATUS_SUCCESS.into())
}
