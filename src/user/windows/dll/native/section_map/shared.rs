//! Pagefile-backed sections retain real aliases and their initial protection.
use super::data::{Failure, Request};
use crate::user::mm::SharedObject;
use crate::user::windows::hle::Ctx;
use crate::user::windows::memory::{ALLOCATION_GRANULARITY, mem, prot};
use crate::user::windows::nt::status::*;
use std::sync::Arc;

pub(super) struct Section {
    pub(super) size: u64,
    pub(super) protection: u32,
    pub(super) attributes: u32,
    pub(super) backing: Arc<SharedObject>,
}

pub(super) fn map(c: &mut Ctx, section: Section, request: Request) -> Result<(u64, u64), Failure> {
    if section.protection != prot::READWRITE || section.attributes != 0x0800_0000 {
        return Err(Failure::Unsupported(
            "NtMapViewOfSection pagefile section profile is not selected",
        ));
    }
    let required = match request.protection {
        prot::READONLY => 4,
        prot::READWRITE => 2,
        _ => {
            return Err(Failure::Unsupported(
                "NtMapViewOfSection pagefile view protection is not selected",
            ));
        }
    };
    if c.p.objects.access(request.handle).unwrap_or(0) & required != required {
        return Err(STATUS_ACCESS_DENIED.into());
    }
    if !matches!(request.inherit, 1 | 2) {
        return Err(STATUS_INVALID_PARAMETER.into());
    }
    if request.flags & !mem::TOP_DOWN != 0 || request.zero != 0 {
        return Err(Failure::Unsupported(
            "NtMapViewOfSection pagefile allocation options are not selected",
        ));
    }
    if request.base % ALLOCATION_GRANULARITY != 0 || request.offset % ALLOCATION_GRANULARITY != 0 {
        return Err(STATUS_MAPPED_ALIGNMENT.into());
    }
    if request.offset >= section.size || request.size > section.size - request.offset {
        return Err(STATUS_INVALID_VIEW_SIZE.into());
    }
    // The native control checks commitment against the caller's unrounded
    // view extent. A zero ViewSize selects the remaining section extent.
    let caller_size = if request.size == 0 {
        section.size - request.offset
    } else {
        request.size
    };
    if request.commit > caller_size {
        return Err(STATUS_INVALID_PARAMETER.into());
    }
    let size = if request.size == 0 {
        section.size - request.offset
    } else {
        request
            .size
            .checked_add(4095)
            .ok_or(STATUS_INVALID_PARAMETER)?
            & !4095
    };
    if size > section.size - request.offset {
        return Err(STATUS_INVALID_VIEW_SIZE.into());
    }
    let base = if request.base == 0 {
        c.p.vm
            .find_free(
                size,
                ALLOCATION_GRANULARITY,
                c.p.vm.low(),
                c.p.vm.high(),
                request.flags & mem::TOP_DOWN != 0,
            )
            .ok_or(STATUS_NO_MEMORY)?
    } else {
        if request.base >= c.p.vm.high()
            || request
                .base
                .checked_add(size)
                .is_none_or(|end| end > c.p.vm.high())
        {
            return Err(STATUS_INVALID_PARAMETER.into());
        }
        if !c.p.vm.is_free(request.base, size) {
            return Err(STATUS_CONFLICTING_ADDRESSES.into());
        }
        request.base
    };
    let view =
        c.p.vm
            .map_shared_view_with_protection(
                section.backing,
                Some(base),
                request.offset,
                size,
                request.protection,
            )
            .map_err(|error| Failure::Status(error.status()))?;
    Ok((view.base, view.size))
}
