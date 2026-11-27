//! Selected GameOS virtual console device operations on guest-owned state.

use super::file_attributes::{attributes::Attributes, path};
use super::file_open::{Request, host::Creation};
use super::named_object::{Checked, status};
use super::query::probe_write;
use crate::user::windows::hle::{ApiResult, Ctx, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::{
    STATUS_ACCESS_DENIED, STATUS_BUFFER_TOO_SMALL, STATUS_CANCELLED, STATUS_CONNECTION_ABORTED,
    STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER,
    STATUS_NOT_FOUND, STATUS_PENDING, STATUS_SUCCESS,
};
use crate::user::windows::objects::Object;
use crate::user::windows::security::token::attributes::{
    Attribute, Attributes as TokenAttributes, Values,
};

const QUERY_MEMORY_CAPABILITIES: u32 = 0x0015_0068;
const ANALYSIS_LAUNCH_ID: [u8; 16] = *b"RAX GameOS Probe";
const QUEUE_REGISTER: u32 = 0x0015_0098;
const QUEUE_BIND: u32 = 0x0015_00a0;
const QUEUE_RECEIVE: u32 = 0x0015_00ac;
const QUEUE_UNREGISTER: u32 = 0x0015_00b0;
const QUEUE_DISCONNECT: u32 = 0x0015_00f4;
const QUEUE_ROUTES: [([u8; 16], [u8; 16]); 2] = [
    (
        [
            0x6b, 0x41, 0x2a, 0xc1, 0x47, 0xf3, 0x5c, 0x40, 0xb7, 0x65, 0x2d, 0xe0, 0x27, 0xa6,
            0x24, 0x9e,
        ],
        ANALYSIS_LAUNCH_ID,
    ),
    (
        [
            0x97, 0x61, 0xe1, 0xe0, 0x56, 0xdd, 0x10, 0x4a, 0x91, 0x95, 0x5e, 0xe7, 0xa1, 0x55,
            0xa8, 0x38,
        ],
        [
            0x27, 0x51, 0xa1, 0x19, 0xd7, 0xb9, 0x42, 0x43, 0x9a, 0x6d, 0x30, 0x24, 0xaa, 0xde,
            0x3f, 0x32,
        ],
    ),
];

pub(super) fn query_launch_token(
    c: &mut Ctx,
    output: u64,
    length: u32,
    returned: u64,
) -> ApiResult {
    let attributes = TokenAttributes::new(vec![Attribute {
        name: "XBOX://LI".encode_utf16().collect(),
        flags: 0,
        values: Values::Octet(vec![ANALYSIS_LAUNCH_ID.to_vec()]),
    }])
    .ok_or_else(|| c.unsupported("invalid GameOS analysis launch attribute"))?;
    let packet = attributes
        .pack(&attributes.all(), 8, output, length as usize)
        .ok_or_else(|| c.unsupported("cannot pack GameOS analysis launch attribute"))?;
    c.mem().w32(returned, packet.required)?;
    if !packet.complete {
        return Flow::ret(STATUS_BUFFER_TOO_SMALL.into());
    }
    c.mem().wr(output, &packet.bytes)?;
    Flow::ret(STATUS_SUCCESS.into())
}

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
    let memory_query = (request.access, request.share, request.options) == (0x100003, 2, 1)
        && creation.is_some_and(|create| {
            create.disposition == 3
                && create.attributes == 0
                && create.allocation.is_none()
                && create.ea.is_empty()
        });
    let message_queue = c.p.cfg.gameos_analysis
        && (request.access, request.share, request.options) == (0x100003, 3, 0)
        && creation.is_none();
    if attrs.flags & !0x40 != 0 || attrs.custom_security || !(memory_query || message_queue) {
        return Err(c.unsupported("XvcMgmt device open parameters").into());
    }
    probe_write(c, request.io, 16)?;
    let object = if message_queue {
        Object::GameOsXvcQueue {
            registered: false,
            bound: false,
            pending: None,
        }
    } else {
        Object::GameOsXvcFile
    };
    let Some(id) = c.p.objects.try_create(object) else {
        return status(STATUS_INSUFFICIENT_RESOURCES);
    };
    if let Some(handle) = c.p.objects.open_access(id, false, request.access) {
        Ok((handle.into(), 0))
    } else {
        c.p.objects.release(id);
        status(STATUS_INSUFFICIENT_RESOURCES)
    }
}

pub(super) fn queue_control(c: &mut Ctx, handle: u64, code: u32) -> Checked<u32> {
    let (event, apc, context) = (c.ptr(1)?, c.ptr(2)?, c.ptr(3)?);
    let (io, input, input_len, output, output_len) =
        (c.ptr(4)?, c.ptr(6)?, c.u32(7)?, c.ptr(8)?, c.u32(9)?);
    if code == QUEUE_RECEIVE && event == 0 && apc == 0 && context != 0 {
        let Some(id) = c.p.objects.id(handle) else {
            return status(STATUS_INVALID_HANDLE);
        };
        if !matches!(
            c.p.objects.obj(id),
            Some(Object::GameOsXvcQueue {
                bound: true,
                pending: None,
                ..
            })
        ) || input_len != 8
            || output_len == 0
            || output_len > 0x4000
        {
            return status(STATUS_INVALID_PARAMETER);
        }
        if c.mem().u64(input)? != u64::from(id) + 1 {
            return status(STATUS_INVALID_HANDLE);
        }
        // No producer exists on an offline queue. The receive remains pending
        // without publishing an I/O completion or touching the payload.
        probe_write(c, io, 16)?;
        probe_write(c, output, output_len as usize)?;
        if let Some(Object::GameOsXvcQueue { pending, .. }) = c.p.objects.obj_mut(id) {
            *pending = Some((io, context));
        }
        return Ok(STATUS_PENDING);
    }
    if apc != 0 || context != 0 {
        return Err(c.unsupported("GameOS queue APC completion").into());
    }
    let event_id =
        c.p.objects
            .id(event)
            .ok_or_else(|| super::named_object::Failure::Status(STATUS_INVALID_HANDLE))?;
    if !matches!(c.p.objects.obj(event_id), Some(Object::Event { .. })) {
        return status(STATUS_INVALID_HANDLE);
    }
    if c.p.objects.access(event).unwrap_or(0) & 2 == 0 {
        return status(STATUS_ACCESS_DENIED);
    }
    let id =
        c.p.objects
            .id(handle)
            .ok_or_else(|| super::named_object::Failure::Status(STATUS_INVALID_HANDLE))?;
    let Some(Object::GameOsXvcQueue {
        registered, bound, ..
    }) = c.p.objects.obj(id)
    else {
        return status(STATUS_INVALID_HANDLE);
    };
    let (registered, bound) = (*registered, *bound);
    let cookie = u64::from(id) + 1;
    let (next, information) = match code {
        QUEUE_REGISTER if (input_len, output_len) == (32, 8) && !registered => {
            let mut request = [0; 32];
            c.mem().rd(input, &mut request)?;
            if !QUEUE_ROUTES
                .iter()
                .any(|(kind, endpoint)| request[..16] == *kind && request[16..] == *endpoint)
            {
                return status(STATUS_ACCESS_DENIED);
            }
            ((true, false), 8)
        }
        QUEUE_BIND if (input_len, output_len) == (8, 0) && registered && !bound => {
            if c.mem().u64(input)? != cookie {
                return status(STATUS_INVALID_HANDLE);
            }
            ((true, true), 0)
        }
        QUEUE_DISCONNECT | QUEUE_UNREGISTER if (input_len, output_len) == (8, 0) && registered => {
            if c.mem().u64(input)? != cookie {
                return status(STATUS_INVALID_HANDLE);
            }
            if code == QUEUE_DISCONNECT {
                // The guest tears down locally when the peer has gone away.
                return status(STATUS_CONNECTION_ABORTED);
            }
            ((false, false), 0)
        }
        QUEUE_REGISTER | QUEUE_BIND | QUEUE_DISCONNECT | QUEUE_UNREGISTER => {
            return status(STATUS_INVALID_PARAMETER);
        }
        _ => {
            return Err(c
                .unsupported(format!("GameOS queue control {code:#x}"))
                .into());
        }
    };
    probe_write(c, io, 16)?;
    if information != 0 {
        probe_write(c, output, 8)?;
        c.mem().w64(output, cookie)?;
    }
    c.mem().w64(io, 0)?;
    c.mem().w64(io + 8, information)?;
    if let Some(Object::GameOsXvcQueue {
        registered, bound, ..
    }) = c.p.objects.obj_mut(id)
    {
        (*registered, *bound) = next;
    }
    if let Some(Object::Event { signaled, .. }) = c.p.objects.obj_mut(event_id) {
        *signaled = 1;
    }
    Ok(STATUS_SUCCESS)
}

pub(super) fn cancel_io(c: &mut Ctx) -> ApiResult {
    let (handle, request, output) = (c.ptr(0)?, c.ptr(1)?, c.ptr(2)?);
    if !(super::super::gameos::enabled(c) && c.p.cfg.gameos_analysis) {
        return Err(c.unsupported("NtCancelIoFileEx outside GameOS analysis"));
    }
    let Some(id) = c.p.objects.id(handle) else {
        return Flow::ret(STATUS_INVALID_HANDLE.into());
    };
    let Some(Object::GameOsXvcQueue { pending, .. }) = c.p.objects.obj(id) else {
        return Err(c.unsupported("NtCancelIoFileEx for a non-XVC file"));
    };
    let Some((io, context)) = pending.filter(|(io, _)| request == 0 || request == *io) else {
        return Flow::ret(STATUS_NOT_FOUND.into());
    };
    probe_write(c, io, 16)?;
    probe_write(c, output, 16)?;
    super::super::threadpool::complete_io(c.p, id, context, io).map_err(|e| c.unsupported(e))?;
    c.mem().w64(io, STATUS_CANCELLED.into())?;
    c.mem().w64(io + 8, 0)?;
    c.mem().w64(output, STATUS_SUCCESS.into())?;
    c.mem().w64(output + 8, 0)?;
    if let Some(Object::GameOsXvcQueue { pending, .. }) = c.p.objects.obj_mut(id) {
        *pending = None;
    }
    Flow::ret(STATUS_SUCCESS.into())
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
