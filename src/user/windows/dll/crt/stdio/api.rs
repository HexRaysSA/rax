//! Captured ABI formals, actual FILE configuration and descriptor ownership.

use crate::user::windows::hle::{ApiErr, ApiResult, Ctx, Flow, Value};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::STATUS_STACK_BUFFER_OVERRUN;

use super::super::{RuntimeKind, runtime, state as errors};
use super::storage::{IOFBF, IOLBF, IONBF, StdioError};
use super::{O_BINARY, O_TEXT, O_U8TEXT, O_U16TEXT, O_WTEXT, state};

#[derive(Clone, Copy)]
enum Request {
    Iob,
    AcrtIob,
    ModePointer(usize),
    GetMode,
    SetMode,
    SetBuffer,
    Eof,
    Error,
    Clear,
    Fileno,
    OpenHandle,
    GetHandle,
    FdOpen(bool),
    Close,
    SetTranslation,
}

fn ret(value: u64) -> Flow {
    Flow::Ret(Value::Int(value))
}
fn negative() -> u64 {
    u64::from(u32::MAX)
}

pub(super) fn iob(c: &mut Ctx) -> ApiResult {
    begin(c, Request::Iob)
}
pub(super) fn acrt_iob(c: &mut Ctx) -> ApiResult {
    begin(c, Request::AcrtIob)
}
pub(super) fn fmode_pointer(c: &mut Ctx) -> ApiResult {
    begin(c, Request::ModePointer(0))
}
pub(super) fn commode_pointer(c: &mut Ctx) -> ApiResult {
    begin(c, Request::ModePointer(1))
}
pub(super) fn get_fmode(c: &mut Ctx) -> ApiResult {
    begin(c, Request::GetMode)
}
pub(super) fn set_fmode(c: &mut Ctx) -> ApiResult {
    begin(c, Request::SetMode)
}
pub(super) fn setvbuf(c: &mut Ctx) -> ApiResult {
    begin(c, Request::SetBuffer)
}
pub(super) fn feof(c: &mut Ctx) -> ApiResult {
    begin(c, Request::Eof)
}
pub(super) fn ferror(c: &mut Ctx) -> ApiResult {
    begin(c, Request::Error)
}
pub(super) fn clearerr(c: &mut Ctx) -> ApiResult {
    begin(c, Request::Clear)
}
pub(super) fn fileno(c: &mut Ctx) -> ApiResult {
    begin(c, Request::Fileno)
}
pub(super) fn open_osfhandle(c: &mut Ctx) -> ApiResult {
    begin(c, Request::OpenHandle)
}
pub(super) fn get_osfhandle(c: &mut Ctx) -> ApiResult {
    begin(c, Request::GetHandle)
}
pub(super) fn fdopen(c: &mut Ctx) -> ApiResult {
    begin(c, Request::FdOpen(false))
}
pub(super) fn wfdopen(c: &mut Ctx) -> ApiResult {
    begin(c, Request::FdOpen(true))
}
pub(super) fn close(c: &mut Ctx) -> ApiResult {
    begin(c, Request::Close)
}
pub(super) fn setmode(c: &mut Ctx) -> ApiResult {
    begin(c, Request::SetTranslation)
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
    perform(c, kind, request, args)
}

pub(super) fn invalid(c: &mut Ctx, kind: RuntimeKind, errno: u32, result: Value) -> ApiResult {
    match errors::ensure_context(c, kind) {
        Err(ApiErr::Fault(fault)) => {
            return Ok(Flow::RetryFault {
                fault,
                retry: Box::new(move |c, _| invalid(c, kind, errno, result)),
            });
        }
        Err(error) => return Err(error),
        Ok(_) => {}
    }
    let runtime = &c.p.crt.runtimes[kind.index()];
    let local = runtime.contexts[&c.t.tid].invalid_handler;
    let target = if local == 0 {
        runtime.invalid_handler
    } else {
        local
    };
    if target == 0 {
        return Ok(Flow::TerminateProcess(STATUS_STACK_BUFFER_OVERRUN));
    }
    Flow::call_checked(target, vec![0; 5], move |c, _| {
        report(c, kind, errno, result)
    })
}

/// Capture the result across error-cell repair; do not repeat the operation or
/// the invalid-parameter callback merely because its errno store faults.
pub(super) fn report(c: &mut Ctx, kind: RuntimeKind, errno: u32, result: Value) -> ApiResult {
    match errors::set_errno(c, kind, errno) {
        Ok(()) => Ok(Flow::Ret(result)),
        Err(ApiErr::Fault(fault)) => Ok(Flow::RetryFault {
            fault,
            retry: Box::new(move |c, _| report(c, kind, errno, result)),
        }),
        Err(error) => Err(error),
    }
}

pub(super) fn preflight_error(c: &mut Ctx, kind: RuntimeKind) -> Result<(), ApiErr> {
    errors::ensure_writable_context(c, kind).map(|_| ())
}

fn failure(c: &Ctx, request: Request) -> Value {
    match request {
        Request::Clear => Value::None,
        Request::GetMode | Request::SetMode => Value::Int(22),
        Request::Eof | Request::Error | Request::FdOpen(_) => Value::Int(0),
        Request::GetHandle => Value::Int(c.arch().ptr(u64::MAX)),
        _ => Value::Int(negative()),
    }
}

fn perform(c: &mut Ctx, kind: RuntimeKind, request: Request, args: [u64; 4]) -> ApiResult {
    // Pure pointer accessors do not need writable errno. All mutations and
    // operations with failure reporting preflight it before external effects.
    if !matches!(
        request,
        Request::Iob | Request::AcrtIob | Request::ModePointer(_)
    ) {
        if let Err(error) = preflight_error(c, kind) {
            return match error {
                ApiErr::Fault(fault) => Ok(Flow::RetryFault {
                    fault,
                    retry: Box::new(move |c, _| perform(c, kind, request, args)),
                }),
                error => Err(error),
            };
        }
    }
    if let Request::FdOpen(wide) = request {
        if args[1] == 0 {
            return invalid(c, kind, 22, Value::Int(0));
        }
        return scan_mode(c, kind, args, wide, [0; 64], 0);
    }
    let streams = state(c, kind)?;
    let result: Result<Flow, StdioError> = (|| {
        Ok(match request {
            Request::Iob => ret(streams.standard_file(0).ok_or(StdioError::Invalid)?),
            Request::AcrtIob => ret(streams.standard_file(args[0] as u32 as usize).unwrap_or(0)),
            Request::ModePointer(index) => {
                ret(streams.mode_cell(index).ok_or(StdioError::Invalid)?)
            }
            Request::GetMode => {
                if args[0] == 0 {
                    return Err(StdioError::Invalid);
                }
                super::storage::probe(c.p, args[0], 4, true)?;
                let at = streams.mode_cell(0).ok_or(StdioError::Invalid)?;
                let value = c.mem().u32(at)?;
                c.mem().w32(args[0], value)?;
                ret(0)
            }
            Request::SetMode => {
                let mode = args[0] as u32 as i32;
                if !matches!(mode, O_TEXT | O_BINARY | O_WTEXT) {
                    return Err(StdioError::Invalid);
                }
                let at = streams.mode_cell(0).ok_or(StdioError::Invalid)?;
                c.mem().w32(at, mode as u32)?;
                ret(0)
            }
            Request::SetBuffer => {
                let mode = args[2] as u32 as i32;
                if args[0] == 0 || !matches!(mode, IOFBF | IOLBF | IONBF) {
                    return Err(StdioError::Invalid);
                }
                streams.replace_buffer(c.p, args[0], mode, args[1], args[3])?;
                ret(0)
            }
            Request::Eof => ret(u64::from(streams.stream(args[0])?.eof)),
            Request::Error => ret(u64::from(streams.stream(args[0])?.error)),
            Request::Clear => {
                let mut stream = streams.stream(args[0])?;
                stream.eof = false;
                stream.error = false;
                streams.publish(c.p, args[0], stream.generation, stream)?;
                Flow::Ret(Value::None)
            }
            Request::Fileno => {
                let fd = streams.stream(args[0])?.descriptor;
                let descriptor = streams.descriptor(fd)?;
                ret(if descriptor.object.is_none() {
                    u64::from(u32::MAX - 1)
                } else {
                    fd as u32 as u64
                })
            }
            Request::OpenHandle => {
                let flags = args[1] as u32 as i32;
                // Access-mask bits come from the retained producer header.
                // Other flags remain explicit unsupported cases, not ignored.
                let supported = 3 | 8 | O_TEXT | O_BINARY | O_WTEXT | O_U16TEXT | O_U8TEXT;
                if flags & !supported != 0 {
                    return Err(StdioError::Internal(
                        "unsupported _open_osfhandle flag".into(),
                    ));
                }
                ret(streams.attach_descriptor(c.p, args[0], flags)? as u32 as u64)
            }
            Request::GetHandle => {
                let descriptor = streams.descriptor(args[0] as u32 as i32)?;
                if let Some(id) = descriptor.object {
                    if c.p.objects.id(descriptor.handle) != Some(id)
                        || c.p.objects.access(descriptor.handle) != Some(descriptor.grant)
                    {
                        return Err(StdioError::Internal("CRT-owned handle invalidated".into()));
                    }
                    ret(descriptor.handle)
                } else {
                    ret(c.arch().ptr(u64::MAX - 1))
                }
            }
            Request::Close => {
                streams.close_descriptor(c.p, args[0] as u32 as i32)?;
                ret(0)
            }
            Request::SetTranslation => {
                ret(streams.set_mode(args[0] as u32 as i32, args[1] as u32 as i32)? as u32 as u64)
            }
            Request::FdOpen(_) => return Err(StdioError::Internal("fdopen scan dispatch".into())),
        })
    })();
    match result {
        Ok(flow) => Ok(flow),
        Err(StdioError::Fault(fault)) => Ok(Flow::RetryFault {
            fault,
            retry: Box::new(move |c, _| perform(c, kind, request, args)),
        }),
        Err(StdioError::Invalid) => {
            let errno = if matches!(request, Request::GetHandle | Request::Close) {
                9
            } else if matches!(request, Request::SetTranslation)
                && streams.descriptor(args[0] as u32 as i32).is_err()
            {
                9
            } else {
                22
            };
            let result = failure(c, request);
            invalid(c, kind, errno, result)
        }
        Err(StdioError::NoMemory | StdioError::GenerationExhausted) => {
            let result = failure(c, request);
            report(c, kind, 12, result)
        }
        Err(StdioError::Host(_)) => {
            let result = failure(c, request);
            report(c, kind, 9, result)
        }
        Err(StdioError::Internal(message)) => Err(c.unsupported(format!("CRT stdio: {message}"))),
    }
}

fn scan_mode(
    c: &mut Ctx,
    kind: RuntimeKind,
    args: [u64; 4],
    wide: bool,
    mut bytes: [u8; 64],
    mut cursor: usize,
) -> ApiResult {
    loop {
        let width = if wide { 2 } else { 1 };
        let at = args[1]
            .checked_add(cursor as u64 * width)
            .filter(|at| c.arch().ptr(*at) == *at);
        let value = match at {
            Some(at) if wide => c.mem().u16(at),
            Some(at) => c.mem().u8(at).map(u16::from),
            None => Err(crate::user::windows::memory::MemFault {
                addr: c.arch().ptr(u64::MAX),
                write: false,
            }),
        };
        let value = match value {
            Ok(value) => value,
            Err(fault) => {
                return Ok(Flow::RetryFault {
                    fault,
                    retry: Box::new(move |c, _| scan_mode(c, kind, args, wide, bytes, cursor)),
                });
            }
        };
        if value == 0 {
            return attach(c, kind, args[0] as u32 as i32, &bytes[..cursor]);
        }
        if cursor == bytes.len() || value > 0x7F {
            return invalid(c, kind, 22, Value::Int(0));
        }
        bytes[cursor] = value as u8;
        cursor += 1;
    }
}

fn attach(c: &mut Ctx, kind: RuntimeKind, fd: i32, mode: &[u8]) -> ApiResult {
    let Some(&first) = mode.first() else {
        return invalid(c, kind, 22, Value::Int(0));
    };
    let (mut read, mut write, append) = match first {
        b'r' => (true, false, false),
        b'w' => (false, true, false),
        b'a' => (false, true, true),
        _ => return invalid(c, kind, 22, Value::Int(0)),
    };
    let mut translation = None;
    let mut commit = None;
    let mut plus = false;
    for &byte in &mode[1..] {
        match byte {
            b'+' if !plus => {
                plus = true;
                read = true;
                write = true;
            }
            b't' if translation.is_none() => translation = Some(O_TEXT),
            b'b' if translation.is_none() => translation = Some(O_BINARY),
            b'c' if commit.is_none() => commit = Some(true),
            b'n' if commit.is_none() => commit = Some(false),
            _ => return invalid(c, kind, 22, Value::Int(0)),
        }
    }
    attach_decoded(c, kind, fd, read, write, append, translation, commit)
}

fn attach_decoded(
    c: &mut Ctx,
    kind: RuntimeKind,
    fd: i32,
    read: bool,
    write: bool,
    append: bool,
    translation: Option<i32>,
    commit: Option<bool>,
) -> ApiResult {
    let streams = state(c, kind)?;
    let result: Result<u64, StdioError> = (|| {
        let fmode = c
            .mem()
            .u32(streams.mode_cell(0).ok_or(StdioError::Invalid)?)? as i32;
        let translation = translation.unwrap_or(if fmode == 0 { O_TEXT } else { fmode });
        let commode = c
            .mem()
            .u32(streams.mode_cell(1).ok_or(StdioError::Invalid)?)?;
        streams.attach_stream(
            c.p,
            fd,
            read,
            write,
            commit.unwrap_or(commode != 0),
            Some(translation),
            append,
        )
    })();
    match result {
        Ok(file) => Flow::ret(file),
        Err(StdioError::Fault(fault)) => Ok(Flow::RetryFault {
            fault,
            retry: Box::new(move |c, _| {
                attach_decoded(c, kind, fd, read, write, append, translation, commit)
            }),
        }),
        Err(StdioError::Invalid) => invalid(c, kind, 9, Value::Int(0)),
        Err(StdioError::NoMemory | StdioError::GenerationExhausted) => {
            report(c, kind, 12, Value::Int(0))
        }
        Err(StdioError::Host(_)) => report(c, kind, 9, Value::Int(0)),
        Err(StdioError::Internal(message)) => Err(c.unsupported(format!("CRT fdopen: {message}"))),
    }
}
