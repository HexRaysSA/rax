//! Filesystem identity and attributes share byte-granular copy and IOSB publication.
use super::super::named_object::{Checked, Failure, status};
use super::super::query::{probe_write, write_guard_result};
use super::host::{self, Error, Record};
use crate::user::windows::arch::WinArch;
use crate::user::windows::fs::FileIdentity;
use crate::user::windows::hle::{ApiErr, Ctx};
use crate::user::windows::memory::{Mem, MemFault};
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::{CURRENT_PROCESS, CURRENT_THREAD, Object};

#[derive(Clone, Copy)]
pub(super) enum Kind {
    Volume,
    Attributes,
}

pub(super) fn checked(
    c: &mut Ctx,
    caller_store: &mut bool,
    args: super::Arguments,
    kind: Kind,
) -> Checked<u32> {
    let super::Arguments {
        handle,
        io,
        output,
        length,
        ..
    } = args;
    // Native admission uses the padded structure size, while the provider
    // reports only the initialized prefix and copied label or name bytes.
    let (minimum, alignment) = match kind {
        Kind::Volume => (24, 8),
        Kind::Attributes => (16, 4),
    };
    if length < minimum {
        return status(STATUS_INFO_LENGTH_MISMATCH);
    }
    let wow = c.arch() == WinArch::X86;
    if wow {
        if io == 0 {
            return status(STATUS_ACCESS_VIOLATION);
        }
    } else {
        probe_write(c, io, 4)?;
    }
    if output % alignment != 0 {
        return status(STATUS_DATATYPE_MISALIGNMENT);
    }
    probe_write(c, output, length as usize)?;
    let (record, synchronous) = match c.p.objects.get(handle) {
        Some(Object::Console(_) | Object::Null) => return status(STATUS_INVALID_DEVICE_REQUEST),
        Some(Object::File(file)) if file.null => return status(STATUS_INVALID_DEVICE_REQUEST),
        Some(Object::Pipe { .. }) => {
            let record = match kind {
                Kind::Volume => Record::volume(0, false, b"N\0a\0m\0e\0d\0P\0i\0p\0e\0", length),
                Kind::Attributes => Record::pipe(length),
            };
            (record, true)
        }
        Some(Object::File(file)) => {
            let record = if matches!(file.lifetime.identity, FileIdentity::GuestDirectory(_)) {
                match kind {
                    Kind::Volume => Record::volume(0, false, b"", length),
                    Kind::Attributes => {
                        // FILE_READ_ONLY_VOLUME | FILE_UNICODE_ON_DISK |
                        // FILE_CASE_PRESERVED_NAMES. This volume is guest-local.
                        Record::encode(0x80006, 255, b"R\0A\0X\0", length, true)
                    }
                }
            } else {
                let (result, description) = match kind {
                    Kind::Volume => (host::volume(file, length), "information"),
                    Kind::Attributes => (host::attributes(file, length), "attributes"),
                };
                result.map_err(|error| -> Failure {
                    match error {
                        #[cfg(windows)]
                        Error::Status(code) => Failure::Status(code),
                        Error::Unavailable(message) => c
                            .unsupported(format!("owned file volume {description}: {message}"))
                            .into(),
                    }
                })?
            };
            let synchronous =
                c.p.objects.file_state(handle).expect("resolved file").mode & 0x30 != 0;
            (record, synchronous)
        }
        Some(_) => return status(STATUS_OBJECT_TYPE_MISMATCH),
        None if handle == c.arch().ptr(CURRENT_PROCESS)
            || handle == c.arch().ptr(CURRENT_THREAD) =>
        {
            return status(STATUS_OBJECT_TYPE_MISMATCH);
        }
        None => return status(STATUS_INVALID_HANDLE),
    };
    let Record { status, data } = record;
    c.mem().wr(output, &data)?;
    *caller_store = wow || !synchronous;
    let information = io.checked_add(c.psize()).ok_or(MemFault {
        addr: u64::MAX,
        write: true,
    })?;
    let publish: Checked<()> = (|| {
        if wow {
            c.mem().w32(io, status)?;
            c.mem().w32(information, data.len() as u32)?;
        } else if synchronous {
            // A synchronous completion copies Information first, then only
            // the low ULONG status. A late fault is consumed but not returned.
            c.mem().wptr(information, c.psize(), data.len() as u64)?;
            c.mem().w32(io, status)?;
        } else {
            c.mem().wptr(io, c.psize(), u64::from(status))?;
            c.mem().wptr(information, c.psize(), data.len() as u64)?;
        }
        Ok(())
    })();
    match publish {
        Err(Failure::Api(ApiErr::Fault(fault))) if synchronous && !wow => {
            let _ = write_guard_result(c, Err(fault.into()));
        }
        result => result?,
    }
    Ok(status)
}
