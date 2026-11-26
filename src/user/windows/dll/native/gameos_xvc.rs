//! Selected GameOS virtual console device operations on guest-owned state.

use super::file_attributes::{attributes::Attributes, path};
use super::file_open::{Request, host::Creation};
use super::named_object::{Checked, status};
use super::query::probe_write;
use crate::user::windows::hle::Ctx;
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::{
    STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_PARAMETER, STATUS_SUCCESS,
};
use crate::user::windows::objects::Object;

const QUERY_MEMORY_CAPABILITIES: u32 = 0x0015_0068;

pub(super) fn open(
    c: &mut Ctx,
    request: Request,
    attrs: &Attributes,
    name: Option<&[u16]>,
    creation: Option<&Creation>,
) -> Option<Checked<(u64, u64)>> {
    if !super::super::gameos::enabled(c) || attrs.root != 0 {
        return None;
    }
    let name = name?;
    let expected: Vec<_> = r"\Device\xvcmgmt".encode_utf16().collect();
    let named = if attrs.flags & 0x40 != 0 {
        path::equal(c, name, &expected)
    } else {
        name == expected
    };
    named.then(|| open_device(c, request, attrs, creation))
}

fn open_device(
    c: &mut Ctx,
    request: Request,
    attrs: &Attributes,
    creation: Option<&Creation>,
) -> Checked<(u64, u64)> {
    if attrs.flags & !0x40 != 0
        || attrs.custom_security
        || (request.access, request.share, request.options) != (0x100003, 2, 1)
        || !creation.is_some_and(|create| {
            create.disposition == 3
                && create.attributes == 0
                && create.allocation.is_none()
                && create.ea.is_empty()
        })
    {
        return Err(c.unsupported("XvcMgmt device open parameters").into());
    }
    probe_write(c, request.io, 16)?;
    let Some(id) = c.p.objects.try_create(Object::GameOsXvcFile) else {
        return status(STATUS_INSUFFICIENT_RESOURCES);
    };
    if let Some(handle) = c.p.objects.open_access(id, false, request.access) {
        Ok((handle.into(), 0))
    } else {
        c.p.objects.release(id);
        status(STATUS_INSUFFICIENT_RESOURCES)
    }
}

pub(super) fn control(c: &mut Ctx, code: u32) -> Checked<u32> {
    if code != QUERY_MEMORY_CAPABILITIES || (c.ptr(1)?, c.ptr(2)?, c.ptr(3)?) != (0, 0, 0) {
        return Err(c.unsupported(format!("XvcMgmt control {code:#x}")).into());
    }
    let (io, output, length) = (c.ptr(4)?, c.ptr(8)?, c.u32(9)?);
    if length < 8 {
        return status(STATUS_INVALID_PARAMETER);
    }
    probe_write(c, io, 16)?;
    probe_write(c, output, 8)?;
    // xvcmgmt reads SFR counter 0x27 from XVIO for this control. The
    // portable guest exposes none of the corresponding capability bits.
    c.mem().w64(output, 0)?;
    c.mem().w64(io, 0)?;
    c.mem().w64(io + 8, 8)?;
    Ok(STATUS_SUCCESS)
}
