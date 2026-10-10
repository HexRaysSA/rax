//! Guest-only virtual-memory queries; build29683 native/WoW64 copy profile.
use super::query::{guard_result, probe_write};
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiErr, ApiResult, Ctx, Flow};
use crate::user::windows::memory::{AllocKind, Mem, RegionInfo};
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::Object;

mod working_set;

pub(super) fn query(c: &mut Ctx) -> ApiResult {
    let result = checked(c);
    match guard_result(c, result) {
        Err(ApiErr::Fault(_)) => Flow::ret(STATUS_ACCESS_VIOLATION.into()),
        result => result,
    }
}

fn checked(c: &mut Ctx) -> ApiResult {
    let (process, address, class, output, length, returned) = (
        c.ptr(0)?,
        c.ptr(1)?,
        c.u32(2)?,
        c.ptr(3)?,
        c.ptr(4)?,
        c.ptr(5)?,
    );
    let wow = c.arch() == WinArch::X86;
    // WoW64 probes this optional destination before kernel dispatch. A fault
    // consumes its guard and disables later publication. If output shares
    // that page, its subsequent copy can succeed; the native entry differs.
    let returned = if wow {
        compatibility_destination(c, returned)
    } else {
        returned
    };
    // The pinned native enum ends at 15. Other declared classes are explicit
    // frontiers, not falsely reported as implemented or invalid.
    if class >= 15 {
        if wow {
            compatibility_length(c, returned, None);
        }
        return Flow::ret(STATUS_INVALID_INFO_CLASS.into());
    }
    let required = match class {
        0 => RegionInfo::encoded_size(c.psize()),
        4 => (c.psize() * 2) as usize,
        6 => {
            if wow {
                12
            } else {
                24
            }
        }
        _ => return Err(c.unsupported(format!("NtQueryVirtualMemory class {class}"))),
    };
    if length < required as u64 {
        if wow {
            compatibility_length(c, returned, None);
        }
        return Flow::ret(STATUS_INFO_LENGTH_MISMATCH.into());
    }
    if address >= c.p.vm.high() {
        if wow {
            compatibility_length(c, returned, None);
        }
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    }
    if !wow {
        if output % 8 != 0 {
            return Flow::ret(STATUS_DATATYPE_MISALIGNMENT.into());
        }
        let bytes =
            usize::try_from(length).map_err(|_| crate::user::windows::memory::MemFault {
                addr: output,
                write: true,
            })?;
        // Probe the complete guest extent without allocating proportional to
        // a guest-controlled SIZE_T. The shared probe stops at its first fault.
        probe_write(c, output, bytes)?;
        if returned != 0 {
            probe_write(c, returned, c.psize() as usize)?;
        }
    }
    if class == 4 {
        return working_set::query(c, process, output, length, returned);
    }
    let status = process_status(c, process)?;
    if status != STATUS_SUCCESS {
        if wow {
            compatibility_length(c, returned, Some(required as u32));
        }
        return Flow::ret(status.into());
    }
    if class == 6 && c.p.vm.allocation(address).is_none() {
        if wow {
            compatibility_length(c, returned, Some(required as u32));
        }
        return Flow::ret(STATUS_INVALID_ADDRESS.into());
    }
    let result = if wow && output == 0 {
        Ok(())
    } else {
        write_information(c, address, class, output)
    };
    if wow {
        compatibility_length(c, returned, result.is_ok().then_some(required as u32));
    }
    result?;
    if !wow && returned != 0 {
        c.write_ptr(returned, required as u64)?;
    }
    Flow::ret(STATUS_SUCCESS.into())
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
            // Both query-information and query-limited-information suffice;
            // PROCESS_VM_READ alone does not, per the original native oracle.
            if c.p.objects.access(handle).unwrap_or(0) & 0x1400 == 0 {
                Ok(STATUS_ACCESS_DENIED)
            } else if *pid != c.p.pid {
                Err(c.unsupported("NtQueryVirtualMemory for another process"))
            } else {
                Ok(STATUS_SUCCESS)
            }
        }
        Some(_) => Ok(STATUS_OBJECT_TYPE_MISMATCH),
    }
}

fn write_information(c: &Ctx, address: u64, class: u32, output: u64) -> Result<(), ApiErr> {
    if class == 0 {
        let region =
            c.p.vm
                .query(address)
                .expect("validated guest address limit");
        region.write(c.mem(), output, c.psize())?;
        return Ok(());
    }
    let allocation =
        c.p.vm
            .allocation(address)
            .expect("validated allocated address");
    let mut bytes = [0u8; 24];
    if allocation.kind == AllocKind::Image {
        // All current image owners map complete SEC_IMAGE-style PE images.
        // There is no guest code-integrity decision or kernel CFG/SCP extension
        // mapping: signing level is UNCHECKED (0), extension/partial/no-execute
        // flags are clear. Never inherit the host kernel's trust flags.
        let width = c.psize() as usize;
        bytes[..width].copy_from_slice(&allocation.base.to_le_bytes()[..width]);
        bytes[width..width * 2].copy_from_slice(&allocation.size.to_le_bytes()[..width]);
    }
    c.mem().wr(
        output,
        &bytes[..if c.arch() == WinArch::X86 { 12 } else { 24 }],
    )?;
    Ok(())
}

fn compatibility_destination(c: &mut Ctx, address: u64) -> u64 {
    if address == 0 {
        return 0;
    }
    if let Err(fault) = probe_write(c, address, 4) {
        c.p.vm.take_guard(fault.addr);
        0
    } else {
        address
    }
}
fn compatibility_length(c: &mut Ctx, address: u64, value: Option<u32>) {
    if address != 0
        && let Some(value) = value
        && let Err(fault) = c.mem().w32(address, value)
    {
        c.p.vm.take_guard(fault.addr);
    }
}
