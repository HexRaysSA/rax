//! Native/WoW64 private allocation capture and output publication. Original
//! build29683 oracles and the bounded profile are retained in native-runtime.md.
use super::query::{guard_result, probe_write};
use crate::error::MemoryAccessKind;
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiErr, ApiResult, Ctx, Flow};
use crate::user::windows::memory::{
    AddressRequirements, Mem, MemFault, PrivateAttributes, mem, prot,
};
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::Object;

pub(super) fn extended(c: &mut Ctx) -> ApiResult {
    let result = checked(c);
    match guard_result(c, result) {
        Err(ApiErr::Fault(_)) => Flow::ret(STATUS_ACCESS_VIOLATION.into()),
        result => result,
    }
}

const ATTR_GRAPHICS: u64 = 0x01;
const ATTR_NONPAGED: u64 = 0x02;
const ATTR_ZERO_PAGES_OPTIONAL: u64 = 0x04;
const ATTR_NONPAGED_LARGE: u64 = 0x08;
const XMEM_NONPAGED: u64 = ATTR_NONPAGED | ATTR_ZERO_PAGES_OPTIONAL;
const XMEM_GRAPHICS: u64 = XMEM_NONPAGED | ATTR_GRAPHICS;
const XMEM_LARGE_GRAPHICS: u64 = ATTR_NONPAGED_LARGE | ATTR_ZERO_PAGES_OPTIONAL | ATTR_GRAPHICS;
const PAGE_GRAPHICS_NOACCESS: u32 = 0x800;
const PAGE_GRAPHICS_READWRITE: u32 = 0x2000;
const PAGE_GRAPHICS_COHERENT: u32 = 0x20000;
const SECTION_MAP_WRITE: u32 = 0x02;

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
    let requirements = match requirements {
        Ok(requirements) => requirements,
        Err(status) => return publish(c, base_ptr, size_ptr, base, size, status, wow),
    };
    let status = process_status(c, handle)?;
    if status != STATUS_SUCCESS {
        return publish(c, base_ptr, size_ptr, base, size, status, wow);
    }
    // This describes the process view, not the currently active instruction
    // decoder: an EC function may enter the service through its ARM64 core.
    if requirements.ec_code
        && (c.p.arch != WinArch::X64 || !c.p.vm.has_code_bitmap() || protection & 0xf0 == 0)
    {
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
    if requirements.node.is_some_and(|node| node != 0) {
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
    let desired = (base != 0).then_some(base);
    let result = if let Some(handle) = requirements.physical_section {
        if requirements.ec_code
            || !matches!(requirements.gameos_attributes, 0 | ATTR_NONPAGED_LARGE)
        {
            return Flow::ret(STATUS_INVALID_PARAMETER.into());
        }
        let section = match c.p.objects.get(handle) {
            Some(Object::GameOsPhysicalSection(section)) => section.clone(),
            Some(_) => return Flow::ret(STATUS_OBJECT_TYPE_MISMATCH.into()),
            None => return Flow::ret(STATUS_INVALID_HANDLE.into()),
        };
        if c.p.objects.access(handle).unwrap_or(0) & SECTION_MAP_WRITE == 0 {
            return Flow::ret(STATUS_ACCESS_DENIED.into());
        }
        c.p.vm.reserve_physical(
            desired,
            size,
            flags,
            protection,
            requirements.address,
            section,
        )
    } else {
        let Some((flags, protection)) =
            gameos_allocation_flags(flags, protection, requirements.gameos_attributes)
        else {
            return Flow::ret(STATUS_INVALID_PARAMETER.into());
        };
        c.p.vm.allocate_extended_attributes(
            desired,
            size,
            flags,
            protection,
            requirements.address,
            PrivateAttributes {
                node: requirements.node.map(|_| 0),
                ec_code: requirements.ec_code,
            },
        )
    };
    match result {
        Ok((base, size)) => publish(c, base_ptr, size_ptr, base, size, STATUS_SUCCESS, true),
        Err(error) => publish(c, base_ptr, size_ptr, base, size, error.status(), wow),
    }
}

fn gameos_allocation_flags(flags: u32, protect: u32, attributes: u64) -> Option<(u32, u32)> {
    const XMEM_RESERVE: u32 = mem::LARGE_PAGES | mem::PHYSICAL | mem::RESERVE;
    const XMEM_COMMIT: u32 = XMEM_RESERVE | mem::COMMIT;
    const XMEM_LARGE_COMMIT: u32 = XMEM_COMMIT & !mem::PHYSICAL;
    const GRAPHICS_NOACCESS: u32 = prot::NOACCESS | PAGE_GRAPHICS_NOACCESS;
    match (flags, protect, attributes) {
        (_, _, 0) => Some((flags, protect)),
        // The portable profile preserves the CPU reservation and committed
        // bytes. It has no graphics MMU or host large-page requirement.
        (XMEM_RESERVE, GRAPHICS_NOACCESS, XMEM_GRAPHICS) => Some((mem::RESERVE, prot::NOACCESS)),
        (XMEM_COMMIT, prot::READWRITE, XMEM_NONPAGED) => {
            Some((mem::RESERVE | mem::COMMIT, prot::READWRITE))
        }
        (XMEM_LARGE_COMMIT, _, XMEM_LARGE_GRAPHICS)
            if protect == prot::READWRITE | PAGE_GRAPHICS_READWRITE | PAGE_GRAPHICS_COHERENT
                || protect == prot::READWRITE | PAGE_GRAPHICS_READWRITE | prot::WRITECOMBINE =>
        {
            Some((
                mem::RESERVE | mem::COMMIT,
                protect & !(PAGE_GRAPHICS_READWRITE | PAGE_GRAPHICS_COHERENT),
            ))
        }
        _ => None,
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

#[derive(Default)]
struct AllocationParameters {
    address: AddressRequirements,
    node: Option<u64>,
    ec_code: bool,
    physical_section: Option<u64>,
    gameos_attributes: u64,
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
) -> Result<Result<AllocationParameters, u32>, ApiErr> {
    let mut requirements = AddressRequirements::default();
    if count == 0 {
        return Ok(if parameters == 0 {
            Ok(AllocationParameters::default())
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
    let mut node = None;
    let mut ec_code = false;
    let mut physical_section = None;
    let mut gameos_attributes = 0;
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
                node = Some(value);
            } // Guest's single NUMA node.
            4 if value != 0 && super::super::gameos::enabled(c) => {
                physical_section = Some(value);
            }
            5 => {
                if value == 0x40 {
                    // EC admission follows process-handle access validation.
                    ec_code = true;
                } else if matches!(
                    value,
                    ATTR_NONPAGED_LARGE | XMEM_NONPAGED | XMEM_GRAPHICS | XMEM_LARGE_GRAPHICS
                ) && super::super::gameos::enabled(c)
                {
                    gameos_attributes = value;
                } else if matches!(value, 0x80 | 0xc0) {
                    return Ok(Err(STATUS_NOT_SUPPORTED));
                } else if value != 0 {
                    return Ok(Err(STATUS_INVALID_PARAMETER));
                }
            }
            _ if value == 0 => return Ok(Err(STATUS_INVALID_PARAMETER)),
            _ => {
                return Err(c.unsupported(format!(
                    "NtAllocateVirtualMemoryEx extended parameter type {kind}"
                )));
            }
        }
    }
    Ok(Ok(AllocationParameters {
        address: requirements,
        node,
        ec_code,
        physical_section,
        gameos_attributes,
    }))
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
