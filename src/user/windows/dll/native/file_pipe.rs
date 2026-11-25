//! Installed ARM64 and WoW64 CreatePipe open the NPFS directory, create
//! a byte-stream read end relative to it, then opens the write end relative
//! to that read end. The directory and endpoints belong to the guest.

use super::file_attributes::{attributes, path};
use super::file_open::{Request, mapped_access, publish};
use super::named_object::{Checked, Failure, finish_flow, finish_with, nt_return, status};
use super::query::probe_write;
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiResult, Ctx, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::{ObjId, Object, PipeEnd};
use crate::user::windows::sync::Wait;

const ROOT: &str = "\\Device\\NamedPipe\\";
const SHARE_READ_WRITE: u32 = 3;
const SYNCHRONOUS_NONALERT: u32 = 0x20;
const NON_DIRECTORY_FILE: u32 = 0x40;
const ROOT_ACCESS: u32 = 0x8010_0000;
const READER_ACCESS: u32 = 0x8010_0100;
const WRITER_ACCESS: u32 = 0x4010_0080;
const FILE_OPENED: u64 = 1;
const FILE_CREATED: u64 = 2;

pub(super) fn open(
    c: &mut Ctx,
    request: Request,
    attrs: &attributes::Attributes,
    name: Option<&[u16]>,
) -> Option<Checked<(u64, u64)>> {
    let name = name?;
    if attrs.root == 0 {
        let root: Vec<u16> = ROOT.encode_utf16().collect();
        let matches = if attrs.flags & 0x40 == 0 {
            name == root
        } else {
            path::equal(c, name, &root)
        };
        if !matches {
            return None;
        }
        if request.access != ROOT_ACCESS
            || request.share != SHARE_READ_WRITE
            || request.options != SYNCHRONOUS_NONALERT
            || attrs.custom_security
        {
            return Some(Err(c
                .unsupported("NPFS directory open outside the anonymous byte-pipe profile")
                .into()));
        }
        if let Err(error) = probe_write(c, request.io, 2 * c.psize() as usize) {
            return Some(Err(error.into()));
        }
        return Some(open_object(
            c,
            request,
            attrs,
            Object::PipeDirectory,
            FILE_OPENED,
        ));
    }
    let Object::Pipe {
        end: Some(reader),
        write: false,
    } = c.p.objects.get(attrs.root)?
    else {
        return None;
    };
    if !name.is_empty()
        || request.access != WRITER_ACCESS
        || request.share != SHARE_READ_WRITE
        || request.options != SYNCHRONOUS_NONALERT | NON_DIRECTORY_FILE
        || attrs.custom_security
    {
        return Some(Err(c
            .unsupported("anonymous pipe peer open outside the synchronous byte-pipe profile")
            .into()));
    }
    let reader = reader.clone();
    if let Err(error) = probe_write(c, request.io, 2 * c.psize() as usize) {
        return Some(Err(error.into()));
    }
    let Some(writer) = reader.prepare_writer() else {
        return Some(status(STATUS_ACCESS_DENIED));
    };
    let result = open_object(
        c,
        request,
        attrs,
        Object::Pipe {
            end: Some(writer.clone()),
            write: true,
        },
        FILE_OPENED,
    );
    if result.is_ok() {
        writer.finish_writer_open();
    }
    Some(result)
}

pub(super) fn create(c: &mut Ctx) -> ApiResult {
    let mut caller_store = false;
    let result = create_checked(c, &mut caller_store);
    finish_with(c, result, caller_store)
}

fn create_checked(c: &mut Ctx, caller_store: &mut bool) -> Checked<u32> {
    let request = Request {
        output: c.ptr(0)?,
        access: c.u32(1)?,
        attributes: c.ptr(2)?,
        io: c.ptr(3)?,
        share: c.u32(4)?,
        options: c.u32(6)?,
    };
    let disposition = c.u32(5)?;
    let [kind, read_mode, completion, instances, inbound, outbound] = [
        c.u32(7)?,
        c.u32(8)?,
        c.u32(9)?,
        c.u32(10)?,
        c.u32(11)?,
        c.u32(12)?,
    ];
    let timeout = c.ptr(13)?;
    probe_write(c, request.output, c.psize() as usize)?;
    probe_write(c, request.io, 2 * c.psize() as usize)?;
    let attrs = attributes::capture_create(c, request.attributes, c.arch() == WinArch::X86)?
        .ok_or(Failure::Status(STATUS_INVALID_PARAMETER))?;
    let name = attributes::validate(c, &attrs)?;
    match c.p.objects.get(attrs.root) {
        Some(Object::PipeDirectory) => {}
        Some(_) => return status(STATUS_OBJECT_TYPE_MISMATCH),
        None => return status(STATUS_INVALID_HANDLE),
    }
    if !name.as_deref().is_some_and(<[u16]>::is_empty)
        || request.access != READER_ACCESS
        || request.share != SHARE_READ_WRITE
        || request.options != SYNCHRONOUS_NONALERT
        || disposition != 2
        || [kind, read_mode, completion, instances] != [0, 0, 0, 1]
        || attrs.custom_security
        || inbound != outbound
        || !(1..=1 << 20).contains(&inbound)
    {
        return Err(c
            .unsupported("NtCreateNamedPipeFile outside the anonymous byte-pipe profile")
            .into());
    }
    if timeout == 0 || c.mem().u64(timeout)? as i64 > 0 {
        return status(STATUS_INVALID_PARAMETER);
    }
    let id =
        c.p.objects
            .try_create_pipe_reader(c.p.pid, inbound)
            .ok_or(Failure::Status(STATUS_INSUFFICIENT_RESOURCES))?;
    let (handle, information) = open_id(c, request, &attrs, id, FILE_CREATED)?;
    *caller_store = true;
    let result = publish(c, request, STATUS_SUCCESS, handle, information);
    if result.is_err() {
        let _ = c.p.objects.close(handle);
    }
    result
}

fn open_object(
    c: &mut Ctx,
    request: Request,
    attrs: &attributes::Attributes,
    object: Object,
    information: u64,
) -> Checked<(u64, u64)> {
    let id =
        c.p.objects
            .try_create(object)
            .ok_or(Failure::Status(STATUS_INSUFFICIENT_RESOURCES))?;
    open_id(c, request, attrs, id, information)
}

fn open_id(
    c: &mut Ctx,
    request: Request,
    attrs: &attributes::Attributes,
    id: ObjId,
    information: u64,
) -> Checked<(u64, u64)> {
    let objects = &mut c.p.objects;
    if let Some(handle) =
        objects.open_access(id, attrs.flags & 2 != 0, mapped_access(request.access))
    {
        Ok((handle.into(), information))
    } else {
        objects.release(id);
        status(STATUS_INSUFFICIENT_RESOURCES)
    }
}

pub(super) fn read(
    c: &mut Ctx,
    endpoint: PipeEnd,
    io: u64,
    output: u64,
    length: usize,
    caller_store: &mut bool,
) -> Checked<Flow> {
    match endpoint.read(length) {
        Ok(Some(bytes)) => {
            *caller_store = true;
            c.mem().wr(output, &bytes)?;
            complete(c, io, STATUS_SUCCESS, bytes.len())
        }
        Ok(None) => Ok(Flow::Block {
            wait: Wait::Pipe(endpoint.clone()),
            then: Box::new(move |c, _| {
                let mut caller_store = false;
                let result = read(c, endpoint, io, output, length, &mut caller_store);
                finish_flow(c, result, caller_store)
            }),
        }),
        Err(code) => {
            *caller_store = true;
            complete(c, io, code, 0)
        }
    }
}

pub(super) fn write(
    c: &mut Ctx,
    endpoint: PipeEnd,
    io: u64,
    input: Vec<u8>,
    done: usize,
    caller_store: &mut bool,
) -> Checked<Flow> {
    match endpoint.write(&input[done..]) {
        Ok(count) if done + count < input.len() => Ok(Flow::Block {
            wait: Wait::Pipe(endpoint.clone()),
            then: Box::new(move |c, _| {
                let mut caller_store = false;
                let result = write(c, endpoint, io, input, done + count, &mut caller_store);
                finish_flow(c, result, caller_store)
            }),
        }),
        Ok(_) => {
            *caller_store = true;
            complete(c, io, STATUS_SUCCESS, input.len())
        }
        Err(code) => {
            *caller_store = true;
            complete(c, io, code, 0)
        }
    }
}

fn complete(c: &Ctx, io: u64, code: u32, count: usize) -> Checked<Flow> {
    let information = io
        .checked_add(c.psize())
        .ok_or(Failure::Status(STATUS_ACCESS_VIOLATION))?;
    c.mem().wptr(io, c.psize(), u64::from(code))?;
    c.mem().wptr(information, c.psize(), count as u64)?;
    Ok(nt_return(code))
}
