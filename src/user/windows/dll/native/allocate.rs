//! Native/WoW64 private allocation capture and output publication. Original
//! build29683 oracles and the bounded profile are retained in native-runtime.md.
use super::query::{guard_result, probe_write};
use crate::error::MemoryAccessKind;
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiErr, ApiResult, Ctx, Flow};
use crate::user::windows::memory::{AddressRequirements, Mem, MemFault};
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::Object;

pub(super) fn extended(c: &mut Ctx) -> ApiResult {
    let result = checked(c);
    match guard_result(c, result) {
        Err(ApiErr::Fault(_)) => Flow::ret(STATUS_ACCESS_VIOLATION.into()),
        result => result,
    }
}

fn output_probe(c: &mut Ctx, address: u64) -> Result<(), MemFault> {
    loop {
        let result = probe_write(c, address, c.psize() as usize);
        if c.arch() == WinArch::X64
            && let Err(fault) = result
            && c.p.vm.take_guard(fault.addr)
        {
            // The retained x64-on-ARM64 profile clears output guards and retries.
            // Each retry removes a guard; a pointer spans at most two pages.
            continue;
        }
        return result;
    }
}

fn checked(c: &mut Ctx) -> ApiResult {
    let (handle, base_ptr, size_ptr, flags, protection, parameters, count) = (
        c.ptr(0)?,
        c.ptr(1)?,
        c.ptr(2)?,
        c.u32(3)?,
        c.u32(4)?,
        c.ptr(5)?,
        c.u32(6)?,
    );
    let wow = c.arch() == WinArch::X86;
    if wow && count > 6 {
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    }
    // The WoW64 thunk captures SIZE_T first, consuming any read guard as an
    // access violation, but the native base probe still precedes that error's
    // return. Its size output is copied after the allocation, even on failure.
    let captured_size = if wow {
        let result = c.read_ptr(size_ptr);
        if let Err(fault) = result {
            c.p.vm.take_guard(fault.addr);
        }
        Some(result)
    } else {
        None
    };
    output_probe(c, base_ptr)?;
    let base = c.read_ptr(base_ptr)?;
    let size = if let Some(result) = captured_size {
        result?
    } else {
        output_probe(c, size_ptr)?;
        c.read_ptr(size_ptr)?
    };
    let requirements = read_parameters(c, parameters, count)?;
    let (requirements, invalid_node) = match requirements {
        Ok(requirements) => requirements,
        Err(status) => return publish(c, base_ptr, size_ptr, base, size, status, wow),
    };
    let status = process_status(c, handle)?;
    if status != STATUS_SUCCESS {
        return publish(c, base_ptr, size_ptr, base, size, status, wow);
    }
    if invalid_node {
        return publish(
            c,
            base_ptr,
            size_ptr,
            base,
            size,
            STATUS_INVALID_PARAMETER,
            wow,
        );
    }
    match c.p.vm.allocate_extended(
        (base != 0).then_some(base),
        size,
        flags,
        protection,
        requirements,
    ) {
        Ok((base, size)) => publish(c, base_ptr, size_ptr, base, size, STATUS_SUCCESS, true),
        Err(error) => publish(c, base_ptr, size_ptr, base, size, error.status(), wow),
    }
}

fn publish(
    c: &Ctx,
    base_ptr: u64,
    size_ptr: u64,
    base: u64,
    size: u64,
    status: u32,
    copy: bool,
) -> ApiResult {
    if copy {
        c.write_ptr(base_ptr, base)?;
        c.write_ptr(size_ptr, size)?;
    }
    Flow::ret(status.into())
}

fn probe_read(c: &Ctx, address: u64, bytes: usize) -> Result<(), MemFault> {
    c.mem()
        .probe(address, bytes, MemoryAccessKind::Read)
        .map_err(|fault| MemFault {
            addr: fault.address,
            write: false,
        })
}

#[derive(Clone, Copy, Default)]
struct CapturedParameter {
    kind: u64,
    value: u64,
    requirements: Option<AddressRequirements>,
}

fn capture_wow(
    c: &Ctx,
    parameters: u64,
    count: u32,
) -> Result<([CapturedParameter; 6], bool), ApiErr> {
    // WoW64 converts address requirements and partition handles before native
    // type validation. Either conversion supplies an aligned parameter copy.
    // Reserved type bits do not suppress capture; later kernel validation owns
    // their rejection. The entry point has already bounded count to six.
    let mut captured = [CapturedParameter::default(); 6];
    let mut converted = false;
    for index in 0..count {
        let at = parameters + u64::from(index) * 16;
        let record = &mut captured[index as usize];
        record.kind = c.mem().u64(at)?;
        record.value = c.mem().u64(at + 8)?;
        match record.kind & 0xff {
            1 => {
                converted = true;
                probe_read(c, record.value, 12)?;
                record.requirements = Some(AddressRequirements {
                    lowest: c.read_ptr(record.value)?,
                    highest: c.read_ptr(record.value + 4)?,
                    alignment: c.read_ptr(record.value + 8)?,
                });
            }
            3 => converted = true,
            _ => {}
        }
    }
    Ok((captured, converted))
}

fn read_parameters(
    c: &Ctx,
    parameters: u64,
    count: u32,
) -> Result<Result<(AddressRequirements, bool), u32>, ApiErr> {
    let mut requirements = AddressRequirements::default();
    if count == 0 {
        return Ok(if parameters == 0 {
            Ok((requirements, false))
        } else {
            Err(STATUS_INVALID_PARAMETER)
        });
    }
    if parameters == 0 {
        return Ok(Err(STATUS_INVALID_PARAMETER));
    }
    if c.arch() != WinArch::X86 && parameters % 8 != 0 {
        return Ok(Err(STATUS_DATATYPE_MISALIGNMENT));
    }
    // Full capture precedes type/pointed-requirement validation. Probe the
    // extent without allocating a guest-controlled host buffer. At most six
    // distinct declared types can survive validation.
    let bytes = usize::try_from(u64::from(count) * 16).map_err(|_| MemFault {
        addr: parameters,
        write: false,
    })?;
    probe_read(c, parameters, bytes)?;
    let captured = if c.arch() == WinArch::X86 {
        let (records, converted) = capture_wow(c, parameters, count)?;
        if !converted && parameters % 8 != 0 {
            return Ok(Err(STATUS_DATATYPE_MISALIGNMENT));
        }
        Some(records)
    } else {
        None
    };
    let mut seen = 0u8;
    let mut invalid_node = false;
    for index in 0..count.min(7) {
        let at = parameters
            .checked_add(u64::from(index) * 16)
            .ok_or(MemFault {
                addr: u64::MAX,
                write: false,
            })?;
        let kind = if let Some(records) = &captured {
            records[index as usize].kind
        } else {
            c.mem().u64(at)?
        };
        if !(1..=6).contains(&kind) || seen & (1 << kind) != 0 {
            return Ok(Err(STATUS_INVALID_PARAMETER));
        }
        seen |= 1 << kind;
        let value = if let Some(records) = &captured {
            records[index as usize].value
        } else {
            c.mem().u64(at + 8)?
        };
        match kind {
            1 => {
                if let Some(records) = &captured {
                    requirements = records[index as usize].requirements.unwrap();
                    continue;
                }
                if c.arch() != WinArch::X86 && value % 8 != 0 {
                    return Ok(Err(STATUS_DATATYPE_MISALIGNMENT));
                }
                probe_read(c, value, (c.psize() * 3) as usize)?;
                requirements = AddressRequirements {
                    lowest: c.read_ptr(value)?,
                    highest: c.read_ptr(value + c.psize())?,
                    alignment: c.read_ptr(value + c.psize() * 2)?,
                };
            }
            2 => {
                // Native NUMA validation follows complete requirement capture
                // and process-handle validation, including VM_OPERATION rights.
                invalid_node = value != 0;
            } // Guest's single NUMA node.
            5 => {
                if value != 0 {
                    return Ok(Err(STATUS_INVALID_PARAMETER));
                } // Ordinary private allocation profile.
            }
            _ if value == 0 => return Ok(Err(STATUS_INVALID_PARAMETER)),
            _ => {
                return Err(c.unsupported(format!(
                    "NtAllocateVirtualMemoryEx extended parameter type {kind}"
                )));
            }
        }
    }
    Ok(Ok((requirements, invalid_node)))
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
                Err(c.unsupported("NtAllocateVirtualMemoryEx for another process"))
            } else {
                Ok(STATUS_SUCCESS)
            }
        }
        Some(_) => Ok(STATUS_OBJECT_TYPE_MISMATCH),
    }
}
