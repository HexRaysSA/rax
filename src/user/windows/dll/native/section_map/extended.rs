//! The measured ARM64EC translation-cache views use the ordinary file geometry
//! and publish an executable bitmap owner without exposing the CFG modifier.
use super::{
    data::{Failure, Request},
    file, guard_result, probe_write, process_status,
};
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiResult, Ctx, Flow};
use crate::user::windows::memory::{FileViewOptions, Mem, prot};
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::Object;

pub(in super::super) fn map_ex(c: &mut Ctx) -> ApiResult {
    let result = checked(c);
    guard_result(c, result)
}

fn checked(c: &mut Ctx) -> ApiResult {
    let (
        handle,
        process,
        base_pointer,
        offset_pointer,
        size_pointer,
        flags,
        protection,
        parameters,
        count,
    ) = (
        c.ptr(0)?,
        c.ptr(1)?,
        c.ptr(2)?,
        c.ptr(3)?,
        c.ptr(4)?,
        c.u32(5)?,
        c.u32(6)?,
        c.ptr(7)?,
        c.u32(8)?,
    );
    if c.arch() != WinArch::X64
        || offset_pointer != 0
        || flags != 0
        || protection != (prot::EXECUTE_READ | prot::TARGETS_INVALID)
    {
        return Err(c.unsupported("NtMapViewOfSectionEx profile is not measured"));
    }
    let ec_code = match (parameters, count) {
        (0, 0) => false,
        (pointer, 1) if pointer != 0 => {
            let parameter = c.mem().bytes(pointer, 16)?;
            if parameter != [5, 0, 0, 0, 0, 0, 0, 0, 0x40, 0, 0, 0, 0, 0, 0, 0] {
                return Err(c.unsupported("NtMapViewOfSectionEx parameter is not measured"));
            }
            true
        }
        _ => return Err(c.unsupported("NtMapViewOfSectionEx parameter count is not measured")),
    };
    probe_write(c, base_pointer, 8)?;
    probe_write(c, size_pointer, 8)?;
    if c.read_ptr(base_pointer)? != 0
        || c.read_ptr(size_pointer)? != 0
        || base_pointer.abs_diff(size_pointer) < 8
    {
        return Err(c.unsupported("NtMapViewOfSectionEx cache view geometry is not measured"));
    }
    let status = process_status(c, process)?;
    if status != STATUS_SUCCESS {
        return Flow::ret(status.into());
    }
    let section = match c.p.objects.get(handle) {
        Some(Object::FileSection(section)) if section.is_cache_section() => section.clone(),
        Some(_) => {
            return Err(c.unsupported("NtMapViewOfSectionEx requires a selected cache Section"));
        }
        None => return Flow::ret(STATUS_INVALID_HANDLE.into()),
    };
    let request = Request {
        handle,
        base: 0,
        size: 0,
        zero: 0,
        commit: 0,
        offset: 0,
        inherit: 2,
        flags,
        protection: prot::EXECUTE_READ,
    };
    let options = FileViewOptions {
        ec_code,
        targets_invalid: true,
    };
    match file::map(c, section, request, options) {
        Ok((base, size)) => {
            c.write_ptr(base_pointer, base)?;
            c.write_ptr(size_pointer, size)?;
            Flow::ret(STATUS_SUCCESS.into())
        }
        Err(Failure::Status(status)) => Flow::ret(status.into()),
        Err(Failure::Unsupported(reason)) => Err(c.unsupported(reason)),
    }
}
