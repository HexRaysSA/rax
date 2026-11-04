//! Class4 device information; captured native and WoW64 publication order.
use super::super::named_object::{Checked, status};
use super::super::query::probe_write;
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::Ctx;
use crate::user::windows::memory::Mem;
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
        class,
    } = args;
    if class != 4 {
        return Err(c
            .unsupported(format!("volume information class {class}"))
            .into());
    }
    if length < 8 {
        return status(STATUS_INFO_LENGTH_MISMATCH);
    }
    let wow = c.arch() == WinArch::X86;
    if wow {
        // A null IOSB passes through to the native query; a nonnull IOSB is
        // private native scratch until a successful late caller copy.
        if io == 0 {
            return status(STATUS_ACCESS_VIOLATION);
        }
    } else {
        // Probe the ULONG status, not the complete native IOSB. The later
        // Information store can fail after output/status have been written.
        probe_write(c, io, 4)?;
    }
    if output % 4 != 0 {
        return status(STATUS_DATATYPE_MISALIGNMENT);
    }
    probe_write(c, output, length as usize)?;
    let (device, characteristics) = match c.p.objects.get(handle) {
        Some(Object::Console(_)) => (0x50, 0x20000),
        Some(Object::Null) => (0x15, 0x100),
        Some(Object::Pipe { .. }) => (0x11, 0x20000),
        Some(Object::File(file)) if file.null => (0x15, 0x100),
        Some(Object::File(file)) => super::host::device(file)
            .map_err(|e| c.unsupported(format!("owned file volume device information: {e}")))?,
        Some(_) => return status(STATUS_OBJECT_TYPE_MISMATCH),
        None if handle == c.arch().ptr(CURRENT_PROCESS)
            || handle == c.arch().ptr(CURRENT_THREAD) =>
        {
            return status(STATUS_OBJECT_TYPE_MISMATCH);
        }
        None => return status(STATUS_INVALID_HANDLE),
    };
    let mut data = [0; 8];
    data[..4].copy_from_slice(&device.to_le_bytes());
    data[4..].copy_from_slice(&characteristics.to_le_bytes());
    c.mem().wr(output, &data)?;
    *caller_store = wow;
    // The native union's unused upper status word is zeroed for a stable
    // result. Providers may leave that reserved word unchanged; Status is
    // the low ULONG and Information has the caller's pointer width.
    c.mem().wptr(io, c.psize(), 0)?;
    let Some(information) = io.checked_add(c.psize()) else {
        return status(STATUS_ACCESS_VIOLATION);
    };
    c.mem().wptr(information, c.psize(), 8)?;
    Ok(STATUS_SUCCESS)
}
