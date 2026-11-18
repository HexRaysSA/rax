//! Counted command line for the current process or its modeled child.

use super::super::named_object::{Checked, Failure, status};
use super::{probe_write, return_length};
use crate::user::windows::hle::{ApiResult, Ctx, Flow};
use crate::user::windows::layout::offsets;
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::{CURRENT_PROCESS, CURRENT_THREAD, Object};
use crate::user::windows::process::Proc;

pub(super) fn query(c: &mut Ctx, handle: u64, out: u64, length: u32, returned: u64) -> ApiResult {
    let width = c.arch().ptr_size() as usize;
    let wow64 = width == 4;
    if !wow64 && length != 0 && out % 4 != 0 {
        return Flow::ret(STATUS_DATATYPE_MISALIGNMENT.into());
    }
    if returned != 0 {
        probe_write(c, returned, 4)?;
    }
    let bytes = match capture(c, handle) {
        Ok(bytes) => bytes,
        Err(Failure::Status(status)) => {
            if wow64 && returned != 0 {
                // WoW64 subtracts the descriptor width difference even when
                // the native query leaves the caller's ReturnLength untouched.
                let previous = c.mem().u32(returned)?;
                return_length(c, returned, previous.wrapping_sub(8))?;
            }
            return Flow::ret(status.into());
        }
        Err(Failure::Api(error)) => return Err(error),
    };
    let header_size = 2 * width;
    let size = header_size + bytes.len() + 2;
    if (length as usize) < size {
        return_length(c, returned, size as u32)?;
        return Flow::ret(STATUS_INFO_LENGTH_MISMATCH.into());
    }
    probe_write(c, out, size)?;
    let mut record = vec![0; size];
    record[..2].copy_from_slice(&(bytes.len() as u16).to_le_bytes());
    record[2..4].copy_from_slice(&((bytes.len() + 2) as u16).to_le_bytes());
    record[width..header_size].copy_from_slice(&(out + header_size as u64).to_le_bytes()[..width]);
    record[header_size..size - 2].copy_from_slice(&bytes);
    // The native64 descriptor's alignment padding is left untouched.
    c.mem().wr(out, &record[..4])?;
    c.mem().wr(out + width as u64, &record[width..])?;
    return_length(c, returned, size as u32)?;
    Flow::ret(0)
}

fn capture(c: &Ctx, handle: u64) -> Checked<Vec<u8>> {
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    let pid = if handle == c.arch().ptr(CURRENT_PROCESS) {
        c.p.pid
    } else {
        match c.p.objects.get(handle) {
            Some(Object::Process { pid, .. }) => {
                if c.p.objects.access(handle).unwrap_or(0) & PROCESS_QUERY_LIMITED_INFORMATION == 0
                {
                    return status(STATUS_ACCESS_DENIED);
                }
                *pid
            }
            None if handle != c.arch().ptr(CURRENT_THREAD) => return status(STATUS_INVALID_HANDLE),
            _ => return status(STATUS_OBJECT_TYPE_MISMATCH),
        }
    };
    let bytes = if pid == c.p.pid {
        read(c.p)
    } else {
        if c.p.children.basic(pid).is_none() {
            return Err(c
                .unsupported("ProcessCommandLineInformation outside the guest family")
                .into());
        }
        c.p.children
            .with_process(pid, |child| read(child))
            .unwrap_or(Err(STATUS_PROCESS_IS_TERMINATING))
    };
    bytes.map_err(Failure::Status)
}

fn read(p: &Proc) -> Result<Vec<u8>, u32> {
    let layout = offsets(p.arch);
    let params = p
        .current_parameters()
        .map_err(|_| STATUS_ACCESS_VIOLATION)?;
    let address = params
        .checked_add(layout.pp_command_line)
        .ok_or(STATUS_ACCESS_VIOLATION)?;
    let descriptor = p
        .space
        .bytes(address, (2 * layout.ptr) as usize)
        .map_err(|_| STATUS_ACCESS_VIOLATION)?;
    let length = usize::from(u16::from_le_bytes(descriptor[..2].try_into().unwrap()));
    let max = usize::from(u16::from_le_bytes(descriptor[2..4].try_into().unwrap()));
    if length > max || length > 0xfffc || length % 2 != 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if length == 0 {
        return Ok(Vec::new());
    }
    let buffer = if layout.ptr == 4 {
        u64::from(u32::from_le_bytes(descriptor[4..8].try_into().unwrap()))
    } else {
        u64::from_le_bytes(descriptor[8..16].try_into().unwrap())
    };
    p.space
        .bytes(buffer, length)
        .map_err(|_| STATUS_ACCESS_VIOLATION)
}
