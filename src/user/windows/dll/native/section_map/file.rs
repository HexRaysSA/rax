//! Native non-image file geometry, with exact-byte limits before page rounding.
use super::{
    data::{Failure, Request},
    geometry,
};
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::Ctx;
use crate::user::windows::memory::{ALLOCATION_GRANULARITY, mem};
use crate::user::windows::nt::status::*;
use crate::user::windows::object_namespace::{FileSection, file_data};
use std::sync::Arc;

pub(super) fn map(
    c: &mut Ctx,
    section: Arc<FileSection>,
    r: Request,
) -> Result<(u64, u64), Failure> {
    let required = match r.protection & 0xFF {
        1 | 2 | 8 => 4,
        4 => 2,
        0x10 => 8,
        0x20 | 0x80 => 12,
        0x40 => 10,
        _ => return Err(STATUS_INVALID_PAGE_PROTECTION.into()),
    };
    if c.p.objects.access(r.handle).unwrap_or(0) & required != required {
        return Err(STATUS_ACCESS_DENIED.into());
    }
    if !matches!(r.inherit, 1 | 2)
        || r.flags & !(mem::TOP_DOWN | mem::PHYSICAL | mem::RESERVE | 1) != 0
    {
        return Err(STATUS_INVALID_PARAMETER.into());
    }
    let high = geometry::ceiling(r.zero, c.p.vm.high())?;
    let wow = c.arch() == WinArch::X86;
    let size_limit = if wow {
        if c.p.vm.high() > 0x7FFF0000 {
            1u64 << 32
        } else {
            1u64 << 31
        }
    } else {
        c.p.vm.high()
    };
    if !wow && r.base >= c.p.vm.high() || r.size > size_limit {
        return Err(STATUS_INVALID_PARAMETER.into());
    }
    if r.base % ALLOCATION_GRANULARITY != 0 || r.offset % ALLOCATION_GRANULARITY != 0 {
        return Err(STATUS_MAPPED_ALIGNMENT.into());
    }
    if r.commit > section.size {
        return Err(STATUS_INVALID_PARAMETER.into());
    }
    if r.offset >= section.size || r.size > section.size - r.offset {
        return Err(STATUS_INVALID_VIEW_SIZE.into());
    }
    if !file_data::allows(section.protection, r.protection)
        || r.flags & mem::RESERVE != 0 && !matches!(section.protection, 4 | 0x40)
    {
        return Err(STATUS_SECTION_PROTECTION.into());
    }
    let size = if r.size == 0 {
        section.size - r.offset
    } else {
        r.size
    };
    let size = size.checked_add(4095).ok_or(STATUS_INVALID_PARAMETER)? & !4095;
    if r.base != 0 && r.zero != 0 && r.base.checked_add(size).is_none_or(|end| end > high) {
        return Err(STATUS_INVALID_PARAMETER.into());
    }
    let address = if r.base == 0 {
        c.p.vm
            .find_free(
                size,
                ALLOCATION_GRANULARITY,
                c.p.vm.low(),
                high,
                r.flags & mem::TOP_DOWN != 0,
            )
            .ok_or(STATUS_NO_MEMORY)?
    } else {
        if !c.p.vm.is_free(r.base, size) {
            return Err(STATUS_CONFLICTING_ADDRESSES.into());
        }
        r.base
    };
    c.p.vm
        .map_file_section(section, address, r.offset, size, r.protection)
        .map_err(|error| Failure::Status(error.status()))?;
    Ok((address, size))
}
