//! Class5 has byte-granular overflow and mode-dependent IOSB publication.
use super::super::named_object::{Checked, Failure, status};
use super::super::query::{probe_write, write_guard_result};
use super::host::{self, Error, Record};
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiErr, Ctx};
use crate::user::windows::memory::{Mem, MemFault};
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::{CURRENT_PROCESS, CURRENT_THREAD, Object};

pub(super) fn checked(
    c: &mut Ctx,
    caller_store: &mut bool,
    args: super::Arguments,
) -> Checked<u32> {
    let super::Arguments {
        handle,
        io,
        output,
        length,
        ..
    } = args;
    // The syscall minimum includes WCHAR[1] and structure tail padding.
    // MS-FSA's 12-byte protocol store minimum is a different boundary.
    if length < 16 {
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
    if output % 4 != 0 {
        return status(STATUS_DATATYPE_MISALIGNMENT);
    }
    probe_write(c, output, length as usize)?;
    let (record, synchronous) = match c.p.objects.get(handle) {
        Some(Object::Console(_) | Object::Null) => return status(0xc000_0010),
        Some(Object::File(file)) if file.null => return status(0xc000_0010),
        Some(Object::Pipe { .. }) => (Record::pipe(length), true),
        Some(Object::File(file)) => {
            let attributes = host::attributes(file, length).map_err(|e| -> Failure {
                match e {
                    #[cfg(windows)]
                    Error::Status(code) => Failure::Status(code),
                    Error::Unavailable(message) => c
                        .unsupported(format!("owned file volume attributes: {message}"))
                        .into(),
                }
            })?;
            let synchronous =
                c.p.objects.file_state(handle).expect("resolved file").mode & 0x30 != 0;
            (attributes, synchronous)
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
