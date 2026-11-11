//! Selected installed SEC_IMAGE views; native/WoW64 build29683 argument order.
use super::query::{guard_result, probe_write};
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiErr, ApiResult, Ctx, Flow};
use crate::user::windows::memory::{FileViewOptions, Mem, valid_protection};
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::Object;
mod data;
mod extended;
mod file;
mod geometry;
mod shared;

pub(super) use extended::map_ex;

pub(super) fn map(c: &mut Ctx) -> ApiResult {
    let result = checked(c);
    guard_result(c, result)
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
                Err(c.unsupported("NtMapViewOfSection for another process"))
            } else {
                Ok(STATUS_SUCCESS)
            }
        }
        Some(_) => Ok(STATUS_OBJECT_TYPE_MISMATCH),
    }
}
fn checked(c: &mut Ctx) -> ApiResult {
    let (
        section_handle,
        process,
        base_pointer,
        zero,
        commit,
        offset_pointer,
        size_pointer,
        inherit,
        flags,
        protection,
    ) = (
        c.ptr(0)?,
        c.ptr(1)?,
        c.ptr(2)?,
        c.ptr(3)?,
        c.ptr(4)?,
        c.ptr(5)?,
        c.ptr(6)?,
        c.u32(7)?,
        c.u32(8)?,
        c.u32(9)?,
    );
    let wow = c.arch() == WinArch::X86;
    let (base, size) = if wow {
        let base = c.read_ptr(base_pointer)?;
        // The WoW64 SIZE_T capture consumes a reached guard but returns AV.
        let size = match c.read_ptr(size_pointer) {
            Ok(size) => size,
            Err(fault) => {
                c.p.vm.take_guard(fault.addr);
                return Flow::ret(STATUS_ACCESS_VIOLATION.into());
            }
        };
        (base, size)
    } else {
        if !valid_protection(protection) {
            if c.arch() == WinArch::X64 {
                // The measured x64-on-ARM64 capture visits base/size read
                // guards even when invalid PAGE_* remains the final status.
                // The optional offset is not reached. Capture faults do not
                // replace this protection failure in that path.
                for pointer in [base_pointer, size_pointer] {
                    if let Err(fault) = c.read_ptr(pointer) {
                        c.p.vm.take_guard(fault.addr);
                    }
                }
            }
            return Flow::ret(STATUS_INVALID_PAGE_PROTECTION.into());
        }
        probe_write(c, base_pointer, c.psize() as usize)?;
        probe_write(c, size_pointer, c.psize() as usize)?;
        (c.read_ptr(base_pointer)?, c.read_ptr(size_pointer)?)
    };
    let failed = |c: &mut Ctx, status: u32| -> ApiResult {
        // WoW64 copies captured base/size back even when the native call failed.
        // A caller-store fault can replace its handle/access/geometry status.
        if wow {
            c.write_ptr(base_pointer, base)?;
            c.write_ptr(size_pointer, size)?;
        }
        Flow::ret(status.into())
    };
    if !valid_protection(protection) {
        return failed(c, STATUS_INVALID_PAGE_PROTECTION);
    }
    let offset = if offset_pointer == 0 {
        0
    } else {
        if offset_pointer % 4 != 0 {
            return failed(c, STATUS_DATATYPE_MISALIGNMENT);
        }
        probe_write(c, offset_pointer, 8)?;
        c.mem().u64(offset_pointer)?
    };
    let status = process_status(c, process)?;
    if status != STATUS_SUCCESS {
        return failed(c, status);
    }
    let section = match c.p.objects.get(section_handle) {
        Some(object @ (Object::DataSection(_) | Object::FileSection(_))) => {
            let request = data::Request {
                handle: section_handle,
                base,
                size,
                zero,
                commit,
                offset,
                inherit,
                flags,
                protection,
            };
            let mapped = if let Object::DataSection(section) = object {
                let section = section.clone();
                data::map(c, section, request)
            } else {
                let Object::FileSection(section) = object else {
                    unreachable!("typed file section")
                };
                let section = section.clone();
                file::map(c, section, request, FileViewOptions::default())
            };
            return match mapped {
                Ok((address, length)) => {
                    c.write_ptr(base_pointer, address)?;
                    c.write_ptr(size_pointer, length)?;
                    if offset_pointer != 0 {
                        c.mem().w64(offset_pointer, offset)?;
                    }
                    Flow::ret(STATUS_SUCCESS.into())
                }
                Err(data::Failure::Status(status)) => failed(c, status),
                Err(data::Failure::Unsupported(reason)) => Err(c.unsupported(reason)),
            };
        }
        Some(Object::ImageSection(section)) => section.clone(),
        Some(Object::Mapping {
            file: None,
            size: section_size,
            protect,
            attributes,
            shared: Some(backing),
        }) => {
            let section = shared::Section {
                size: *section_size,
                protection: *protect,
                attributes: *attributes,
                backing: backing.clone(),
            };
            let request = data::Request {
                handle: section_handle,
                base,
                size,
                zero,
                commit,
                offset,
                inherit,
                flags,
                protection,
            };
            return match shared::map(c, section, request) {
                Ok((address, length)) => {
                    c.write_ptr(base_pointer, address)?;
                    c.write_ptr(size_pointer, length)?;
                    if offset_pointer != 0 {
                        c.mem().w64(offset_pointer, offset)?;
                    }
                    Flow::ret(STATUS_SUCCESS.into())
                }
                Err(data::Failure::Status(status)) => failed(c, status),
                Err(data::Failure::Unsupported(reason)) => Err(c.unsupported(reason)),
            };
        }
        Some(Object::Mapping { .. }) => {
            return Err(c.unsupported("NtMapViewOfSection requires selected pagefile backing"));
        }
        Some(_) => return failed(c, STATUS_OBJECT_TYPE_MISMATCH),
        None if section_handle == c.arch().ptr(u64::MAX)
            || section_handle == c.arch().ptr(u64::MAX - 1) =>
        {
            return failed(c, STATUS_OBJECT_TYPE_MISMATCH);
        }
        None => return failed(c, STATUS_INVALID_HANDLE),
    };
    let required = match protection & 0xFF {
        1 | 2 | 8 => 4,
        4 => 2,
        0x10 => 8,
        0x20 | 0x80 => 12,
        0x40 => 10,
        _ => unreachable!("validated PAGE_* base"),
    };
    if c.p.objects.access(section_handle).unwrap_or(0) & required != required {
        return failed(c, STATUS_ACCESS_DENIED);
    }
    if section.no_execute && protection != crate::user::windows::memory::prot::READONLY {
        return failed(c, STATUS_INVALID_PAGE_PROTECTION);
    }
    if !matches!(inherit, 1 | 2) || flags & !(0x0010_0000 | 0x0080_0000 | 0x2000_0000) != 0 {
        return failed(c, STATUS_INVALID_PARAMETER);
    }
    let image = section
        .image_for(c.arch())
        .map_err(|error| c.unsupported(format!("selected image section backing: {error}")))?;
    let limit = section
        .size
        .checked_add(4095)
        .ok_or_else(|| c.unsupported("image section extent overflow"))?
        & !4095;
    let plan = match geometry::with_extensions(
        &c.p.vm,
        (!section.no_execute).then_some(image.preferred),
        limit,
        base,
        size,
        offset,
        zero,
        commit,
        flags,
        wow,
        if section.no_execute {
            None
        } else {
            c.p.vm.section_low_placement(&section)
        },
        if limit == section.image_size {
            image.allocation_size() - image.bytes.len() as u64
        } else {
            0
        },
        image.large_pages,
    ) {
        Ok(plan) => plan,
        Err(status) => return failed(c, status),
    };
    let differs = plan.image_base.checked_sub(plan.offset) != Some(image.preferred);
    // Inspection views preserve the image bytes regardless of the rebase flag.
    let relocated = !section.no_execute && differs && flags & 0x0080_0000 != 0;
    if let Err(error) = c.p.vm.map_section_image(
        section.clone(),
        &image,
        plan.allocation_base,
        plan.image_base,
        plan.allocation_size,
        plan.offset,
        plan.size,
        plan.large,
        relocated,
    ) {
        if error == crate::user::windows::memory::VmError::NotSupported {
            return Err(c.unsupported("selected kernel image relocation encoding"));
        }
        return failed(c, error.status());
    }
    if !section.no_execute
        && base == 0
        && image.preferred.checked_add(offset) != Some(plan.image_base)
        && geometry::ceiling(zero, c.p.vm.high()).is_ok_and(|high| high <= 1u64 << 32)
    {
        c.p.vm
            .record_section_low_placement(section, plan.image_base);
    }
    // Copy-back is deliberately after ownership publication. A WoW64 late
    // caller-store failure keeps the successfully mapped view alive.
    c.write_ptr(base_pointer, plan.image_base)?;
    c.write_ptr(size_pointer, plan.size)?;
    if offset_pointer != 0 {
        c.mem().w64(offset_pointer, plan.offset)?;
    }
    let mismatch = image.machine
        != match c.arch() {
            WinArch::X86 => 0x14C,
            WinArch::X64 => 0x8664,
            WinArch::Arm64 => 0xAA64,
        };
    let status = if mismatch && !wow {
        STATUS_IMAGE_MACHINE_TYPE_MISMATCH
    } else if differs {
        if relocated {
            STATUS_IMAGE_AT_DIFFERENT_BASE
        } else {
            STATUS_IMAGE_NOT_AT_BASE
        }
    } else if mismatch {
        STATUS_IMAGE_MACHINE_TYPE_MISMATCH
    } else {
        STATUS_SUCCESS
    };
    Flow::ret(status.into())
}
