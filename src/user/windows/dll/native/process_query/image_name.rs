//! The executable path held by the guest's loader and process objects.

use super::super::query::{probe_write, return_length, write_guard_result};
use super::{PROCESS_QUERY_INFORMATION, process_query_target};
use crate::user::mm::PAGE_SIZE;
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiResult, Ctx, Flow};
use crate::user::windows::memory::{Mem, MemFault};
use crate::user::windows::nt::status::{
    STATUS_ACCESS_VIOLATION, STATUS_DATATYPE_MISALIGNMENT, STATUS_GUARD_PAGE_VIOLATION,
    STATUS_INFO_LENGTH_MISMATCH, STATUS_INVALID_PARAMETER, STATUS_NAME_TOO_LONG, STATUS_SUCCESS,
    STATUS_UNSUCCESSFUL,
};

pub(super) const CLASS: u32 = 43;
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
const WOW64_DESCRIPTOR_DELTA: u32 = 8;

pub(super) fn query(c: &mut Ctx, handle: u64, out: u64, length: u32, returned: u64) -> ApiResult {
    if c.arch() == WinArch::X86 {
        let result = checked(c, handle, out, length, returned, true);
        return write_guard_result(c, result);
    }
    if length != 0 {
        if out % 4 != 0 {
            return Flow::ret(STATUS_DATATYPE_MISALIGNMENT.into());
        }
        if out
            .checked_add(u64::from(length))
            .is_none_or(|end| end > c.p.vm.high())
        {
            return Flow::ret(STATUS_ACCESS_VIOLATION.into());
        }
    }
    checked(c, handle, out, length, returned, false)
}

fn checked(
    c: &mut Ctx,
    handle: u64,
    out: u64,
    length: u32,
    returned: u64,
    wow64: bool,
) -> ApiResult {
    if returned != 0
        && let Err(fault) = probe_write(c, returned, 4)
    {
        // WoW64 still adjusts the caller's length after the underlying native
        // call faults on a guard. Its later direct store can itself fail.
        if wow64 && c.p.vm.take_guard(fault.addr) {
            adjust_failed_length(c, returned)?;
            return Flow::ret(STATUS_GUARD_PAGE_VIOLATION.into());
        }
        return Err(fault.into());
    }

    let rights = PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION;
    let pid = match process_query_target(c, handle, rights) {
        Ok(pid) => pid,
        Err(status) => {
            if wow64 {
                adjust_failed_length(c, returned)?;
            }
            return Flow::ret(status.into());
        }
    };
    let name: Vec<u16> = if pid == c.p.pid {
        c.p.modules.executable_path().encode_utf16().collect()
    } else {
        let Some((_, exit)) = c.p.children.basic(pid) else {
            return Err(c.unsupported("ProcessImageFileNameWin32 outside the guest family"));
        };
        let name = if exit.is_none() {
            c.p.children.with_process(pid, |child| {
                child.modules.executable_path().encode_utf16().collect()
            })
        } else {
            None
        };
        let Some(name) = name else {
            if wow64 {
                adjust_failed_length(c, returned)?;
            }
            return Flow::ret(STATUS_UNSUCCESSFUL.into());
        };
        name
    };
    let Ok(maximum_bytes) = u16::try_from(2 * (name.len() + 1)) else {
        return Flow::ret(STATUS_NAME_TOO_LONG.into());
    };
    let width = c.psize();
    let header = 2 * width;
    let required = header as u32 + u32::from(maximum_bytes);
    if length < required {
        return_length(c, returned, required)?;
        return Flow::ret(STATUS_INFO_LENGTH_MISMATCH.into());
    }
    if wow64 {
        // The thunk publishes the converted size before touching its caller's
        // output. This matters if the output faults or overlaps ReturnLength.
        return_length(c, returned, required)?;
        if out == 0 {
            return Flow::ret(STATUS_INVALID_PARAMETER.into());
        }
    }
    let mut lengths = [0u8; 4];
    lengths[..2].copy_from_slice(&(maximum_bytes - 2).to_le_bytes());
    lengths[2..].copy_from_slice(&maximum_bytes.to_le_bytes());
    let path = out + header;
    let path_bytes: Vec<u8> = name
        .into_iter()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect();
    if wow64 {
        let mut descriptor = [0u8; 8];
        descriptor[..4].copy_from_slice(&lengths);
        descriptor[4..].copy_from_slice(&(path as u32).to_le_bytes());
        c.mem().wr(out, &descriptor)?;
        if path / PAGE_SIZE == (path + path_bytes.len() as u64 - 1) / PAGE_SIZE {
            c.mem().wr(path, &path_bytes)?;
        } else {
            write_path_range(c, path, &path_bytes)?;
        }
    } else {
        // Native64 copies the string before it writes either descriptor field.
        // A read-only guard on a later page remains armed on a failed copy.
        if let Err(fault) = write_native_path(c, path, &path_bytes) {
            if fault.addr / PAGE_SIZE != path / PAGE_SIZE {
                return write_guard_result(c, Err(fault.into()));
            }
            return Err(fault.into());
        }
        c.mem().wr(out, &lengths)?;
        c.write_ptr(out + width, path)?;
        return_length(c, returned, required)?;
    }
    Flow::ret(STATUS_SUCCESS.into())
}

fn write_native_path(c: &Ctx, address: u64, bytes: &[u8]) -> Result<(), MemFault> {
    if address / PAGE_SIZE == (address + bytes.len() as u64 - 1) / PAGE_SIZE {
        return c.mem().wr(address, bytes);
    }
    if (65..=128).contains(&bytes.len()) {
        // On the measured ARM64 kernel this copy stores both 32-byte ends
        // before the interior. Keep the observed fault boundary without
        // changing the order of descriptor or ReturnLength publication.
        let end = bytes.len() - 32;
        write_path_range(c, address, &bytes[..32])?;
        write_path_range(c, address + end as u64, &bytes[end..])?;
        write_path_range(c, address + 32, &bytes[32..end])
    } else {
        write_path_range(c, address, bytes)
    }
}

fn write_path_range(c: &Ctx, mut address: u64, bytes: &[u8]) -> Result<(), MemFault> {
    for word in bytes.chunks(8) {
        c.mem().wr(address, word)?;
        address += word.len() as u64;
    }
    Ok(())
}

fn adjust_failed_length(c: &Ctx, returned: u64) -> Result<(), MemFault> {
    if returned != 0 {
        let old = c.mem().u32(returned)?;
        return_length(c, returned, old.wrapping_sub(WOW64_DESCRIPTOR_DELTA))?;
    }
    Ok(())
}
