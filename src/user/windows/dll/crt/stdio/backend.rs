//! Synchronous bounded host transfers, with explicit accepted-prefix counts.
//!
//! Guest access and descriptor validation belong to the caller. No guest code,
//! RefCell borrow, retry of already accepted bytes, or O(request-size) allocation
//! occurs here. Host filesystem effects are not an atomic guest transaction.

use crate::user::console::{Console, OutputStream};
use std::io::{self, Read, Seek, SeekFrom, Write};

use crate::user::windows::objects::{ObjId, Object, StdStream};
use crate::user::windows::process::Proc;

pub(super) const CHUNK: usize = 256;

/// Even an error reports the prefix accepted before the error. It must not be
/// silently discarded by write_all or replayed by a guest-fault continuation.
#[derive(Debug)]
pub(super) struct Written {
    pub bytes: usize,
    pub error: Option<io::Error>,
}

fn interrupted<T>(mut operation: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    loop {
        match operation() {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => return result,
        }
    }
}

pub(super) fn read_chunk(reader: &mut impl Read, output: &mut [u8]) -> io::Result<usize> {
    if output.len() > CHUNK {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unbounded CRT read",
        ));
    }
    if output.is_empty() {
        return Ok(0);
    }
    interrupted(|| reader.read(output))
}

pub(super) fn write_chunk(writer: &mut impl Write, input: &[u8]) -> Written {
    if input.len() > CHUNK * 2 {
        return Written {
            bytes: 0,
            error: Some(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unbounded CRT write",
            )),
        };
    }
    let mut done = 0;
    while done < input.len() {
        match interrupted(|| writer.write(&input[done..])) {
            Ok(0) => {
                return Written {
                    bytes: done,
                    error: Some(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "CRT write made no progress",
                    )),
                };
            }
            Ok(count) if count <= input.len() - done => done += count,
            Ok(_) => {
                return Written {
                    bytes: done,
                    error: Some(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid host write count",
                    )),
                };
            }
            Err(error) => {
                return Written {
                    bytes: done,
                    error: Some(error),
                };
            }
        }
    }
    Written {
        bytes: done,
        error: None,
    }
}

fn unsupported(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}

pub(super) fn read(p: &mut Proc, object: ObjId, output: &mut [u8]) -> io::Result<usize> {
    // All variants, including NUL, enforce the same scratch bound.
    if output.len() > CHUNK {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unbounded CRT read",
        ));
    }
    match p.objects.obj_mut(object) {
        Some(Object::File(file)) if file.null => Ok(0),
        Some(Object::File(file)) if !file.directory && !file.overlapped => {
            let host = file
                .host
                .as_mut()
                .ok_or_else(|| unsupported("metadata-only file"))?;
            read_chunk(host, output)
        }
        Some(Object::Console(StdStream::In)) => match &p.cfg.console {
            Console::Host => read_chunk(&mut io::stdin(), output),
            console => console.read(output),
        },
        Some(Object::Null) => Ok(0),
        Some(Object::Pipe { .. }) => Err(unsupported("CRT pipe I/O")),
        _ => Err(unsupported("CRT input object")),
    }
}

pub(super) fn write(p: &mut Proc, object: ObjId, input: &[u8], append: bool) -> Written {
    if input.len() > CHUNK * 2 {
        return Written {
            bytes: 0,
            error: Some(unsupported("unbounded CRT write")),
        };
    }
    let fail = |error| Written {
        bytes: 0,
        error: Some(error),
    };
    if let Console::Captured(_) = &p.cfg.console {
        let stream = match p.objects.obj(object) {
            Some(Object::Console(StdStream::Out)) => Some(OutputStream::Stdout),
            Some(Object::Console(StdStream::Err)) => Some(OutputStream::Stderr),
            _ => None,
        };
        if let Some(stream) = stream {
            return match p.cfg.console.write_all(stream, input) {
                Ok(()) => Written {
                    bytes: input.len(),
                    error: None,
                },
                Err(error) => fail(error),
            };
        }
    }
    match p.objects.obj_mut(object) {
        Some(Object::File(file)) if file.null => Written {
            bytes: input.len(),
            error: None,
        },
        Some(Object::File(file)) if !file.directory && !file.overlapped => {
            let Some(host) = file.host.as_mut() else {
                return fail(unsupported("metadata-only file"));
            };
            if !input.is_empty() && (append || file.append) {
                if let Err(error) = interrupted(|| host.seek(SeekFrom::End(0))) {
                    return fail(error);
                }
            }
            write_chunk(host, input)
        }
        Some(Object::Console(StdStream::Out)) => console_write(&mut io::stdout(), input),
        Some(Object::Console(StdStream::Err)) => console_write(&mut io::stderr(), input),
        Some(Object::Null) => Written {
            bytes: input.len(),
            error: None,
        },
        Some(Object::Pipe { .. }) => fail(unsupported("CRT pipe I/O")),
        _ => fail(unsupported("CRT output object")),
    }
}

fn console_write(writer: &mut impl Write, input: &[u8]) -> Written {
    let mut result = write_chunk(writer, input);
    // Host stdout may be line buffered. A guest _IONBF write without LF must
    // not remain hidden inside that unrelated host buffer. If flush fails,
    // bytes already accepted remain accounted for, not replayed.
    if result.error.is_none() {
        result.error = interrupted(|| writer.flush()).err();
    }
    result
}

pub(super) fn commit(p: &mut Proc, object: ObjId) -> io::Result<()> {
    match p.objects.obj_mut(object) {
        Some(Object::File(file)) if file.null => Ok(()),
        Some(Object::File(file)) if !file.directory && !file.overlapped => {
            let host = file
                .host
                .as_mut()
                .ok_or_else(|| unsupported("metadata-only file"))?;
            interrupted(|| host.sync_all())
        }
        Some(Object::Console(_) | Object::Null) => Ok(()),
        _ => Err(unsupported("CRT commit object")),
    }
}

#[cfg(test)]
#[path = "backend_tests.rs"]
mod tests;
