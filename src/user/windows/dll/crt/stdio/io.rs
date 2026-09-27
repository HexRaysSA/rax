//! Bounded byte transfers and flush frontiers retained across guest faults.
//!
//! O(n) transfer time, O(1) host scratch space; persistent buffers live in
//! checked guest memory. Lifecycle/revision checks fail closed on callback
//! reentry that changes the same stream or descriptor. No host borrow crosses
//! callbacks, and consumed flush prefixes are published before the next fault.

use std::io::ErrorKind;

use crate::user::windows::hle::{ApiErr, ApiResult, Cont, Ctx, Flow, Value};
use crate::user::windows::memory::Mem;
use crate::user::windows::objects::Object;

use super::super::{RuntimeKind, runtime};
use super::storage::{Buffer, Descriptor, Direction, StdioError, Stream, probe};
use super::{O_BINARY, O_TEXT, api, backend, state};

#[derive(Clone, Copy)]
enum Request {
    Read,
    Write,
    Fread,
    Fwrite,
    Flush,
    Close,
}

pub(super) fn read(c: &mut Ctx) -> ApiResult {
    begin(c, Request::Read)
}
pub(super) fn write(c: &mut Ctx) -> ApiResult {
    begin(c, Request::Write)
}
pub(super) fn fread(c: &mut Ctx) -> ApiResult {
    begin(c, Request::Fread)
}
pub(super) fn fwrite(c: &mut Ctx) -> ApiResult {
    begin(c, Request::Fwrite)
}
pub(super) fn fflush(c: &mut Ctx) -> ApiResult {
    begin(c, Request::Flush)
}
pub(super) fn fclose(c: &mut Ctx) -> ApiResult {
    begin(c, Request::Close)
}

fn begin(c: &mut Ctx, request: Request) -> ApiResult {
    decode(c, runtime(c)?, request, [0; 4], 0)
}
fn decode(
    c: &mut Ctx,
    kind: RuntimeKind,
    request: Request,
    mut args: [u64; 4],
    mut cursor: usize,
) -> ApiResult {
    while cursor < c.api.args.len() {
        match c.arg(cursor) {
            Ok(value) => {
                args[cursor] = value;
                cursor += 1;
            }
            Err(fault) => {
                return Ok(Flow::RetryFault {
                    fault,
                    retry: Box::new(move |c, _| decode(c, kind, request, args, cursor)),
                });
            }
        }
    }
    if matches!(request, Request::Flush | Request::Close) {
        return start_flush(c, kind, request, args[0]);
    }
    start_transfer(c, kind, request, args)
}

fn converted(error: StdioError) -> ApiErr {
    match error {
        StdioError::Fault(fault) => ApiErr::Fault(fault),
        error => ApiErr::Internal(format!("CRT I/O storage: {error:?}")),
    }
}
fn writable(request: Request) -> bool {
    matches!(request, Request::Write | Request::Fwrite)
}
fn stdio(request: Request) -> bool {
    matches!(request, Request::Fread | Request::Fwrite)
}
fn errno(error: &std::io::Error) -> u32 {
    match error.kind() {
        ErrorKind::PermissionDenied => 13,
        ErrorKind::StorageFull => 28,
        ErrorKind::OutOfMemory => 12,
        ErrorKind::InvalidInput => 22,
        _ => 5,
    }
}

struct Transfer {
    kind: RuntimeKind,
    request: Request,
    address: u64,
    total: u64,
    item: u64,
    done: u64,
    /// Low-level _read budgets raw input, not contracted text output.
    raw_done: u64,
    /// Current request's logical tail still queued in this stream buffer.
    buffer_current: u64,
    stream: Option<Stream>,
    descriptor: Descriptor,
    failed: Option<u32>,
    ended: bool,
}

fn start_transfer(c: &mut Ctx, kind: RuntimeKind, request: Request, args: [u64; 4]) -> ApiResult {
    let is_stdio = stdio(request);
    let (address, total, item) = if is_stdio {
        if args[1] == 0 || args[2] == 0 {
            return Flow::ret(0);
        }
        let total = args[1]
            .checked_mul(args[2])
            .filter(|&n| c.arch().ptr(n) == n);
        let Some(total) = total else {
            return api::invalid(c, kind, 22, Value::Int(0));
        };
        (args[0], total, args[1])
    } else {
        let count = args[2] as u32;
        if count > i32::MAX as u32 {
            return api::invalid(c, kind, 22, Value::Int(u32::MAX.into()));
        }
        (args[1], u64::from(count), 1)
    };
    if address == 0 || (is_stdio && args[3] == 0) {
        return api::invalid(
            c,
            kind,
            22,
            Value::Int(if is_stdio { 0 } else { u32::MAX.into() }),
        );
    }
    if let Err(error) = api::preflight_error(c, kind) {
        return match error {
            ApiErr::Fault(fault) => Ok(Flow::RetryFault {
                fault,
                retry: Box::new(move |c, _| start_transfer(c, kind, request, args)),
            }),
            error => Err(error),
        };
    }
    let streams = state(c, kind)?;
    let prepared: Result<(Option<Stream>, Descriptor), StdioError> = (|| {
        let stream = if is_stdio {
            let stream = streams.stream(args[3])?;
            if (writable(request) && !stream.writable) || (!writable(request) && !stream.readable) {
                return Err(StdioError::Invalid);
            }
            Some(stream)
        } else {
            None
        };
        let fd = stream.map_or(args[0] as u32 as i32, |s| s.descriptor);
        let descriptor = streams.validate_descriptor(c.p, fd, writable(request))?;
        Ok((stream, descriptor))
    })();
    let (mut stream, descriptor) = match prepared {
        Ok(values) => values,
        Err(StdioError::Fault(fault)) => {
            return Ok(Flow::RetryFault {
                fault,
                retry: Box::new(move |c, _| start_transfer(c, kind, request, args)),
            });
        }
        Err(StdioError::Invalid) => {
            return api::invalid(
                c,
                kind,
                9,
                Value::Int(if is_stdio { 0 } else { u32::MAX.into() }),
            );
        }
        Err(StdioError::NoMemory | StdioError::GenerationExhausted) => {
            return api::report(
                c,
                kind,
                12,
                Value::Int(if is_stdio { 0 } else { u32::MAX.into() }),
            );
        }
        Err(error) => return Err(converted(error)),
    };
    if !matches!(descriptor.translation, O_TEXT | O_BINARY) && writable(request) && total & 1 != 0 {
        return api::invalid(
            c,
            kind,
            22,
            Value::Int(if is_stdio { 0 } else { u32::MAX.into() }),
        );
    }
    supported(c, descriptor)?;
    if let Some(original) = stream {
        stream = Some(match streams.ensure_buffer(c.p, original.file) {
            Ok(stream) => stream,
            Err(StdioError::Fault(fault)) => {
                return Ok(Flow::RetryFault {
                    fault,
                    retry: Box::new(move |c, _| start_transfer(c, kind, request, args)),
                });
            }
            Err(StdioError::NoMemory | StdioError::GenerationExhausted) => {
                return api::report(c, kind, 12, Value::Int(0));
            }
            Err(error) => return Err(converted(error)),
        });
    }
    drive(
        c,
        Transfer {
            kind,
            request,
            address,
            total,
            item,
            done: 0,
            raw_done: 0,
            buffer_current: 0,
            stream,
            descriptor,
            failed: None,
            ended: false,
        },
    )
}

fn supported(c: &Ctx, descriptor: Descriptor) -> Result<(), ApiErr> {
    if !matches!(descriptor.translation, O_TEXT | O_BINARY) {
        return Err(c.unsupported("CRT Unicode byte translation"));
    }
    match descriptor.object.and_then(|id| c.p.objects.obj(id)) {
        Some(Object::File(file))
            if file.directory || file.overlapped || (!file.null && file.host.is_none()) =>
        {
            Err(c.unsupported("CRT directory/overlapped/metadata-only I/O"))
        }
        Some(Object::Pipe { .. }) => Err(c.unsupported("CRT pipe I/O")),
        Some(Object::File(_) | Object::Console(_) | Object::Null) => Ok(()),
        _ => Err(c.unsupported("CRT I/O object")),
    }
}

fn live(
    c: &mut Ctx,
    kind: RuntimeKind,
    stream: Option<Stream>,
    descriptor: Descriptor,
    write: bool,
) -> Result<(), ApiErr> {
    api::preflight_error(c, kind)?;
    let streams = state(c, kind)?;
    let now = streams
        .validate_descriptor(c.p, descriptor.fd, write)
        .map_err(converted)?;
    if now.generation != descriptor.generation || now.revision != descriptor.revision {
        return Err(c.unsupported("CRT descriptor changed during fault repair"));
    }
    if descriptor.revision == u64::MAX {
        return Err(c.unsupported("CRT descriptor revision exhausted"));
    }
    if let Some(stream) = stream {
        let now = streams.stream(stream.file).map_err(converted)?;
        if now.generation != stream.generation || now.revision != stream.revision {
            return Err(c.unsupported("CRT stream changed during fault repair"));
        }
        if stream.revision == u64::MAX {
            return Err(c.unsupported("CRT stream revision exhausted"));
        }
        streams.preflight(c.p, stream.file).map_err(converted)?;
        streams
            .validate_buffer(c.p, stream.buffer)
            .map_err(converted)?;
    }
    Ok(())
}

fn publish(c: &mut Ctx, job: &mut Transfer) -> Result<(), ApiErr> {
    if let Some(stream) = job.stream {
        job.stream = Some(
            state(c, job.kind)?
                .publish(c.p, stream.file, stream.generation, stream)
                .map_err(converted)?,
        );
    }
    Ok(())
}

fn drive(c: &mut Ctx, mut job: Transfer) -> ApiResult {
    let result = (|| -> Result<(), ApiErr> {
        while (if matches!(job.request, Request::Read) {
            job.raw_done
        } else {
            job.done
        }) < job.total
            && !job.ended
            && job.failed.is_none()
        {
            live(
                c,
                job.kind,
                job.stream,
                job.descriptor,
                writable(job.request),
            )?;
            if writable(job.request) {
                write_step(c, &mut job)?;
            } else {
                read_step(c, &mut job)?;
            }
        }
        if let Some(stream) = job.stream.as_mut() {
            if job.failed.is_some() {
                stream.error = true;
            }
            publish(c, &mut job)?;
        }
        Ok(())
    })();
    match result {
        Err(ApiErr::Fault(fault)) => Ok(Flow::RetryFault {
            fault,
            retry: Box::new(move |c, _| drive(c, job)),
        }),
        Err(error) => Err(error),
        Ok(()) => {
            let result = if stdio(job.request) {
                job.done / job.item
            } else if job.failed.is_some() {
                u32::MAX.into()
            } else {
                job.done
            };
            match job.failed {
                Some(errno) => api::report(c, job.kind, errno, Value::Int(result)),
                None => Flow::ret(result),
            }
        }
    }
}

fn at(c: &Ctx, base: u64, offset: u64, write: bool) -> Result<u64, ApiErr> {
    base.checked_add(offset)
        .filter(|&at| c.arch().ptr(at) == at)
        .ok_or_else(|| {
            crate::user::windows::memory::MemFault {
                addr: c.arch().ptr(u64::MAX),
                write,
            }
            .into()
        })
}

/// Read at most one bounded host block, translating in constant scratch.
/// A lone trailing CR may consume one lookahead byte; a non-LF is retained.
fn descriptor_read(
    c: &mut Ctx,
    kind: RuntimeKind,
    d: &mut Descriptor,
    output: &mut [u8],
) -> Result<(usize, usize, Option<u32>), ApiErr> {
    if d.translation == O_TEXT && d.text_eof {
        return Ok((0, 0, None));
    }
    let id = d
        .object
        .ok_or_else(|| c.unsupported("unassociated CRT descriptor"))?;
    let mut raw = [0; backend::CHUNK];
    let mut count = 0;
    let cached = d.lookahead.take();
    if let Some(byte) = cached {
        raw[0] = byte;
        count = 1;
    }
    let read = backend::read(c.p, id, &mut raw[count..output.len()]);
    match read {
        Ok(n) => count += n,
        Err(error) => {
            let code = errno(&error);
            // A failed host read did not consume this previously cached byte.
            d.lookahead = cached;
            *d = state(c, kind)?
                .publish_descriptor(d.fd, d.generation, *d)
                .map_err(converted)?;
            return Ok((0, count, Some(code)));
        }
    }
    if d.translation == O_BINARY {
        output[..count].copy_from_slice(&raw[..count]);
        *d = state(c, kind)?
            .publish_descriptor(d.fd, d.generation, *d)
            .map_err(converted)?;
        return Ok((count, count, None));
    }
    let mut source = 0;
    let mut done = 0;
    let mut raw_used = count;
    let mut failure = None;
    while source < count {
        let byte = raw[source];
        source += 1;
        if byte == 0x1A {
            d.text_eof = true;
            break;
        }
        if byte != b'\r' {
            output[done] = byte;
            done += 1;
            continue;
        }
        let from_raw = source < count;
        let next = if from_raw {
            let byte = raw[source];
            source += 1;
            Some(byte)
        } else {
            let mut byte = [0];
            match backend::read(c.p, id, &mut byte) {
                Ok(0) => None,
                Ok(_) => Some(byte[0]),
                Err(error) => {
                    failure = Some(errno(&error));
                    None
                }
            }
        };
        if next == Some(b'\n') {
            output[done] = b'\n';
            if !from_raw {
                raw_used += 1;
            }
        } else {
            output[done] = b'\r';
            if let Some(next) = next {
                if from_raw {
                    source -= 1;
                } else {
                    d.lookahead = Some(next);
                }
            }
        }
        done += 1;
        if failure.is_some() {
            break;
        }
    }
    *d = state(c, kind)?
        .publish_descriptor(d.fd, d.generation, *d)
        .map_err(converted)?;
    Ok((done, raw_used, failure))
}

fn read_step(c: &mut Ctx, job: &mut Transfer) -> Result<(), ApiErr> {
    let frontier = if matches!(job.request, Request::Read) {
        job.raw_done
    } else {
        job.done
    };
    let wanted = (job.total - frontier).min(backend::CHUNK as u64) as usize;
    let destination = at(c, job.address, job.done, true)?;
    probe(c.p, destination, wanted as u64, true).map_err(converted)?;
    let mut scratch = [0; backend::CHUNK];
    let (count, raw_count, failure) = if let Some(mut stream) = job.stream {
        if stream.last == Direction::Write {
            return Err(c.unsupported("CRT read after write without flush/position barrier"));
        }
        let capacity = stream.buffer.capacity();
        if capacity == 0 {
            descriptor_read(c, job.kind, &mut job.descriptor, &mut scratch[..wanted])?
        } else {
            if stream.read_cursor == stream.read_end {
                let count = capacity.min(backend::CHUNK as u64) as usize;
                let buffer = stream.buffer.address();
                probe(c.p, buffer, count as u64, true).map_err(converted)?;
                let (filled, _, failure) =
                    descriptor_read(c, job.kind, &mut job.descriptor, &mut scratch[..count])?;
                c.mem().wr(buffer, &scratch[..filled])?;
                stream.read_cursor = 0;
                stream.read_end = filled as u64;
                job.failed = failure;
                job.stream = Some(stream);
                // Publish the read buffer before a later destination fault.
                publish(c, job)?;
                stream = job.stream.expect("stream target");
            }
            let count = wanted.min((stream.read_end - stream.read_cursor) as usize);
            let source = at(c, stream.buffer.address(), stream.read_cursor, false)?;
            c.mem().rd(source, &mut scratch[..count])?;
            stream.read_cursor += count as u64;
            job.stream = Some(stream);
            (count, 0, None)
        }
    } else {
        descriptor_read(c, job.kind, &mut job.descriptor, &mut scratch[..wanted])?
    };
    c.mem().wr(destination, &scratch[..count])?;
    job.done += count as u64;
    job.raw_done += raw_count as u64;
    if let Some(failure) = failure {
        job.failed = Some(failure);
    }
    if count == 0 {
        job.ended = true;
    }
    if matches!(job.request, Request::Read) && (raw_count < wanted || job.descriptor.text_eof) {
        job.ended = true;
    }
    if let Some(stream) = job.stream.as_mut() {
        stream.last = Direction::Read;
        stream.io_started = true;
        if count == 0 && job.failed.is_none() {
            stream.eof = true;
        }
    }
    publish(c, job)
}

/// Map physical short-write progress back to completed logical input bytes.
/// A failing flush discards remaining buffered data as documented; it does not
/// retry a partially accepted CR-LF pair from its CR byte.
fn descriptor_write(c: &mut Ctx, d: Descriptor, input: &[u8]) -> (usize, Option<u32>, bool) {
    let mut physical = [0; backend::CHUNK * 2];
    let mut ends = [0usize; backend::CHUNK];
    let mut count = 0;
    let mut logical = 0;
    for &byte in input {
        if d.translation == O_TEXT && byte == 0x1A {
            break;
        }
        if d.translation == O_TEXT && byte == b'\n' {
            physical[count] = b'\r';
            count += 1;
        }
        physical[count] = byte;
        count += 1;
        ends[logical] = count;
        logical += 1;
    }
    let terminated = logical < input.len();
    let Some(id) = d.object else {
        return (0, Some(9), false);
    };
    // Reduced append-only grants cannot overwrite an ordinary FileObj cursor.
    let append_only = d.grant & 4 != 0 && d.grant & (0x4000_0000 | 2) == 0;
    let written = backend::write(c.p, id, &physical[..count], d.append || append_only);
    let done = ends[..logical]
        .iter()
        .take_while(|&&end| end <= written.bytes)
        .count();
    let complete = if written.error.is_none() {
        logical
    } else {
        done
    };
    (
        complete,
        written.error.as_ref().map(errno),
        terminated && written.error.is_none(),
    )
}

fn flush_pending(c: &mut Ctx, job: &mut Transfer) -> Result<(), ApiErr> {
    while let Some(mut stream) = job.stream {
        if stream.write_start == stream.write_pending {
            break;
        }
        live(c, job.kind, job.stream, job.descriptor, true)?;
        let count = (stream.write_pending - stream.write_start).min(backend::CHUNK as u64) as usize;
        let source = at(c, stream.buffer.address(), stream.write_start, false)?;
        let mut scratch = [0; backend::CHUNK];
        c.mem().rd(source, &mut scratch[..count])?;
        let (done, failure, terminated) = descriptor_write(c, job.descriptor, &scratch[..count]);
        stream.write_start += done as u64;
        if terminated {
            stream.write_start = stream.write_pending;
        }
        if let Some(failure) = failure {
            // fwrite cannot report this call's unaccepted buffered suffix as
            // written when its mandatory full-buffer flush fails. Previous
            // calls' already-returned buffered counts are not retroactively
            // changed; fflush explicitly permits loss on write failure.
            let current_begin = stream.write_pending - job.buffer_current;
            let unaccepted = stream.write_pending - stream.write_start.max(current_begin);
            job.done -= unaccepted;
            stream.write_start = stream.write_pending;
            stream.error = true;
            job.failed = Some(failure);
        }
        job.stream = Some(stream);
        publish(c, job)?;
        if job.failed.is_some() {
            break;
        }
    }
    if let Some(mut stream) = job.stream {
        stream.write_start = 0;
        stream.write_pending = 0;
        job.buffer_current = 0;
        job.stream = Some(stream);
        publish(c, job)?;
    }
    Ok(())
}

fn write_step(c: &mut Ctx, job: &mut Transfer) -> Result<(), ApiErr> {
    if job
        .stream
        .is_some_and(|s| s.write_pending == s.buffer.capacity() && s.write_pending != 0)
    {
        flush_pending(c, job)?;
        if job.failed.is_some() {
            return Ok(());
        }
    }
    let mut count = (job.total - job.done).min(backend::CHUNK as u64) as usize;
    let source = at(c, job.address, job.done, false)?;
    let mut scratch = [0; backend::CHUNK];
    c.mem().rd(source, &mut scratch[..count])?;
    // Exclude-marker profile: CTRL+Z terminates this text-output request, not
    // subsequent requests. Scan before enqueueing so fwrite cannot accept a
    // suffix which later disappears during flush or leaks from a later chunk.
    let terminator = if job.descriptor.translation == O_TEXT {
        scratch[..count].iter().position(|&byte| byte == 0x1A)
    } else {
        None
    };
    if let Some(prefix) = terminator {
        count = prefix;
    }
    if let Some(mut stream) = job.stream {
        if stream.last == Direction::Read && !stream.eof {
            return Err(c.unsupported("CRT write after read without flush/position barrier"));
        }
        if stream.last == Direction::Read {
            stream.read_cursor = 0;
            stream.read_end = 0;
        }
        if stream.buffer.capacity() != 0 {
            let copied = count.min((stream.buffer.capacity() - stream.write_pending) as usize);
            let destination = at(c, stream.buffer.address(), stream.write_pending, true)?;
            probe(c.p, destination, copied as u64, true).map_err(converted)?;
            c.mem().wr(destination, &scratch[..copied])?;
            stream.write_pending += copied as u64;
            stream.last = Direction::Write;
            stream.io_started = true;
            job.done += copied as u64;
            job.buffer_current += copied as u64;
            if terminator.is_some() && copied == count {
                job.ended = true;
            }
            job.stream = Some(stream);
            publish(c, job)?;
            if stream.write_pending == stream.buffer.capacity() {
                flush_pending(c, job)?;
            }
            return Ok(());
        }
        stream.last = Direction::Write;
        stream.io_started = true;
        job.stream = Some(stream);
    }
    let (done, failure, _) = descriptor_write(c, job.descriptor, &scratch[..count]);
    job.done += done as u64;
    job.failed = failure;
    if terminator.is_some() && done == count {
        job.ended = true;
    }
    publish(c, job)
}

struct Flush {
    kind: RuntimeKind,
    request: Request,
    files: Vec<(u64, u64, u64)>,
    cursor: usize,
    active: Option<Transfer>,
    failed: Option<u32>,
    drained: bool,
}

fn start_flush(c: &mut Ctx, kind: RuntimeKind, request: Request, file: u64) -> ApiResult {
    if file == 0 && matches!(request, Request::Close) {
        return api::invalid(c, kind, 22, Value::Int(u32::MAX.into()));
    }
    let streams = state(c, kind)?;
    let result = if file == 0 {
        streams.open_streams()
    } else {
        streams
            .stream(file)
            .map(|s| vec![(file, s.generation, s.revision)])
    };
    match result {
        Ok(files) => walk_flush(
            c,
            Flush {
                kind,
                request,
                files,
                cursor: 0,
                active: None,
                failed: None,
                drained: false,
            },
        ),
        Err(StdioError::Invalid) => api::invalid(c, kind, 22, Value::Int(u32::MAX.into())),
        Err(StdioError::NoMemory | StdioError::GenerationExhausted) => {
            api::report(c, kind, 12, Value::Int(u32::MAX.into()))
        }
        Err(error) => Err(converted(error)),
    }
}

fn walk_flush(c: &mut Ctx, mut job: Flush) -> ApiResult {
    let result = (|| -> Result<(), ApiErr> {
        while job.cursor < job.files.len() {
            api::preflight_error(c, job.kind)?;
            let streams = state(c, job.kind)?;
            if job.active.is_none() {
                let (file, generation, revision) = job.files[job.cursor];
                let stream = streams.stream(file).map_err(converted)?;
                if stream.generation != generation || stream.revision != revision {
                    return Err(c.unsupported("CRT flush set changed during fault repair"));
                }
                let descriptor = streams.descriptor(stream.descriptor).map_err(converted)?;
                // No read-buffer discard. Even read-only fflush negates ungetc.
                streams.preflight(c.p, file).map_err(converted)?;
                job.active = Some(Transfer {
                    kind: job.kind,
                    request: Request::Fwrite,
                    address: 0,
                    total: 0,
                    item: 1,
                    done: 0,
                    raw_done: 0,
                    buffer_current: 0,
                    stream: Some(stream),
                    descriptor,
                    failed: None,
                    ended: false,
                });
            }
            let active = job.active.as_mut().expect("active flush");
            if !job.drained {
                let stream = active.stream.expect("flush stream");
                if stream.last == Direction::Write {
                    supported(c, active.descriptor)?;
                    flush_pending(c, active)?;
                    if active.failed.is_none() {
                        let inherited = stream.commit_inherit
                            && c.mem().u32(
                                streams
                                    .mode_cell(1)
                                    .ok_or_else(|| c.unsupported("CRT commode cell"))?,
                            )? != 0;
                        if stream.commit || inherited {
                            live(c, job.kind, active.stream, active.descriptor, true)?;
                            if let Some(id) = active.descriptor.object {
                                if let Err(error) = backend::commit(c.p, id) {
                                    active.failed = Some(errno(&error));
                                }
                            }
                        }
                    }
                }
                if let Some(stream) = active.stream.as_mut() {
                    stream.pushback = None;
                    // Input fflush retains both its read-ahead and direction.
                    // An output flush supplies the required write->read barrier.
                    if stream.last == Direction::Write {
                        stream.last = Direction::None;
                    }
                    if active.failed.is_some() {
                        stream.error = true;
                    }
                }
                publish(c, active)?;
                job.drained = true;
                if let Some(error) = active.failed {
                    job.failed.get_or_insert(error);
                }
            }
            if matches!(job.request, Request::Close) {
                let stream = active.stream.expect("close stream");
                match streams.close_stream(c.p, stream.file) {
                    Ok(()) => {}
                    Err(StdioError::Host(_)) => {
                        job.failed.get_or_insert(5);
                    }
                    Err(error) => return Err(converted(error)),
                }
            }
            job.cursor += 1;
            job.active = None;
            job.drained = false;
        }
        Ok(())
    })();
    match result {
        Err(ApiErr::Fault(fault)) => Ok(Flow::RetryFault {
            fault,
            retry: Box::new(move |c, _| walk_flush(c, job)),
        }),
        Err(error) => Err(error),
        Ok(()) => match job.failed {
            Some(errno) => api::report(c, job.kind, errno, Value::Int(u32::MAX.into())),
            None => Flow::ret(0),
        },
    }
}

/// The selected SDK retail terminating-DLL path calls `_flushall`, not
/// `fflush(NULL)`. Its nonflushable/no-commit streams are skipped completely:
/// in particular, input buffering and pushback are not cleared. The public
/// `_flushall` input-discard prose conflicts with these retained SDK bytes.
/// Streams stay open. Only this initialized runtime participates.
pub(super) fn ucrt_process_detach(c: &mut Ctx, then: Cont) -> ApiResult {
    let Some(streams) = c.p.crt.runtimes[RuntimeKind::Ucrt.index()].stdio.clone() else {
        return then(c, 0);
    };
    let files = streams.open_streams().map_err(converted)?;
    detach_flush(
        c,
        DetachFlush {
            files,
            cursor: 0,
            active: None,
            commit: false,
            phase: DetachPhase::Buffer,
            then,
        },
    )
}

#[derive(Clone, Copy)]
enum DetachPhase {
    Buffer,
    Commit,
    Publish,
    Error,
}

struct DetachFlush {
    files: Vec<(u64, u64, u64)>,
    cursor: usize,
    active: Option<Transfer>,
    commit: bool,
    phase: DetachPhase,
    then: Cont,
}

/// Capture the stream set once, then retain the selected stream and each
/// irreversible host-I/O frontier across guest faults. The snapshot needs
/// O(S) host storage; the payload scratch remains 256 bytes. Registry scans
/// mean metadata work is O(S² + K*S) for S streams and K flush chunks.
fn detach_flush(c: &mut Ctx, mut job: DetachFlush) -> ApiResult {
    let kind = RuntimeKind::Ucrt;
    let result = (|| -> Result<(), ApiErr> {
        while job.cursor < job.files.len() {
            let streams = state(c, kind)?;
            if job.active.is_none() {
                let (file, generation, revision) = job.files[job.cursor];
                let stream = streams.stream(file).map_err(converted)?;
                if stream.generation != generation || stream.revision != revision {
                    return Err(c.unsupported("CRT detach flush set changed during fault repair"));
                }
                let inherited = stream.commit_inherit
                    && c.mem().u32(
                        streams
                            .mode_cell(1)
                            .ok_or_else(|| c.unsupported("CRT commode cell"))?,
                    )? != 0;
                let commit = stream.commit || inherited;
                if !(stream.last == Direction::Write && stream.buffer.capacity() != 0) && !commit {
                    // No publication, errno allocation, descriptor validation,
                    // or buffer access for a skipped ordinary-read stream.
                    job.cursor += 1;
                    continue;
                }
                api::preflight_error(c, kind)?;
                streams.preflight(c.p, file).map_err(converted)?;
                let descriptor = streams.descriptor(stream.descriptor).map_err(converted)?;
                job.active = Some(Transfer {
                    kind,
                    request: Request::Fwrite,
                    address: 0,
                    total: 0,
                    item: 1,
                    done: 0,
                    raw_done: 0,
                    buffer_current: 0,
                    stream: Some(stream),
                    descriptor,
                    failed: None,
                    ended: false,
                });
                job.commit = commit;
                job.phase = DetachPhase::Buffer;
            }
            let active = job.active.as_mut().expect("selected detach flush");
            if matches!(job.phase, DetachPhase::Buffer) {
                let stream = active.stream.expect("detach stream");
                if stream.last == Direction::Write && stream.buffer.capacity() != 0 {
                    supported(c, active.descriptor)?;
                    flush_pending(c, active)?;
                }
                job.phase = DetachPhase::Commit;
            }
            if matches!(job.phase, DetachPhase::Commit) {
                if job.commit && active.failed.is_none() {
                    // Commit can also visit read-only streams; do not require
                    // write rights just to validate their captured descriptor.
                    live(
                        c,
                        kind,
                        active.stream,
                        active.descriptor,
                        !active.descriptor.readable,
                    )?;
                    if let Some(id) = active.descriptor.object {
                        if let Err(error) = backend::commit(c.p, id) {
                            active.failed = Some(errno(&error));
                        }
                    }
                }
                // A late FILE/errno fault must not replay a completed commit.
                job.phase = DetachPhase::Publish;
            }
            if matches!(job.phase, DetachPhase::Publish) {
                let stream = active.stream.as_mut().expect("detach stream");
                if stream.last == Direction::Write {
                    stream.last = Direction::None;
                }
                if active.failed.is_some() {
                    stream.error = true;
                }
                // Unlike public fflush, this path never negates pushback.
                publish(c, active)?;
                job.phase = DetachPhase::Error;
            }
            if let Some(error) = active.failed {
                super::super::state::set_errno(c, kind, error)?;
            }
            job.cursor += 1;
            job.active = None;
        }
        Ok(())
    })();
    match result {
        Err(ApiErr::Fault(fault)) => Ok(Flow::RetryFault {
            fault,
            retry: Box::new(move |c, _| detach_flush(c, job)),
        }),
        Err(error) => Err(error),
        Ok(()) => (job.then)(c, 0),
    }
}
