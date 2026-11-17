//! Native64 counted command line for the current process or its modeled child.

use super::{probe_write, return_length};
use crate::user::windows::hle::{ApiResult, Ctx, Flow};
use crate::user::windows::layout::offsets;
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::{CURRENT_PROCESS, CURRENT_THREAD, Object};
use crate::user::windows::process::Proc;

pub(super) fn query(c: &mut Ctx, handle: u64, out: u64, length: u32, returned: u64) -> ApiResult {
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    if length != 0 && out % 8 != 0 {
        return Flow::ret(STATUS_DATATYPE_MISALIGNMENT.into());
    }
    if returned != 0 {
        probe_write(c, returned, 4)?;
    }
    let pid = if handle == CURRENT_PROCESS {
        c.p.pid
    } else {
        match c.p.objects.get(handle) {
            Some(Object::Process { pid, .. }) => {
                if c.p.objects.access(handle).unwrap_or(0) & PROCESS_QUERY_LIMITED_INFORMATION == 0
                {
                    return Flow::ret(STATUS_ACCESS_DENIED.into());
                }
                *pid
            }
            None if handle != CURRENT_THREAD => return Flow::ret(STATUS_INVALID_HANDLE.into()),
            _ => return Flow::ret(STATUS_OBJECT_TYPE_MISMATCH.into()),
        }
    };
    let bytes = if pid == c.p.pid {
        read(c.p)
    } else {
        if c.p.children.basic(pid).is_none() {
            return Err(c.unsupported("ProcessCommandLineInformation outside the guest family"));
        }
        c.p.children
            .with_process(pid, |child| read(child))
            .unwrap_or(Err(STATUS_PROCESS_IS_TERMINATING))
    };
    let bytes = match bytes {
        Ok(bytes) => bytes,
        Err(status) => return Flow::ret(status.into()),
    };
    let size = 16 + bytes.len() + 2;
    if (length as usize) < size {
        return_length(c, returned, size as u32)?;
        return Flow::ret(STATUS_INFO_LENGTH_MISMATCH.into());
    }
    probe_write(c, out, size)?;
    let mut record = vec![0; size];
    record[..2].copy_from_slice(&(bytes.len() as u16).to_le_bytes());
    record[2..4].copy_from_slice(&((bytes.len() + 2) as u16).to_le_bytes());
    record[8..16].copy_from_slice(&(out + 16).to_le_bytes());
    record[16..size - 2].copy_from_slice(&bytes);
    c.mem().wr(out, &record)?;
    return_length(c, returned, size as u32)?;
    Flow::ret(0)
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
        .bytes(address, 16)
        .map_err(|_| STATUS_ACCESS_VIOLATION)?;
    let length = usize::from(u16::from_le_bytes(descriptor[..2].try_into().unwrap()));
    let max = usize::from(u16::from_le_bytes(descriptor[2..4].try_into().unwrap()));
    if length > max || length > 0xfffc || length % 2 != 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if length == 0 {
        return Ok(Vec::new());
    }
    let buffer = u64::from_le_bytes(descriptor[8..16].try_into().unwrap());
    p.space
        .bytes(buffer, length)
        .map_err(|_| STATUS_ACCESS_VIOLATION)
}
