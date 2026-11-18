//! Cross-address-space writes to an owned guest child.

use super::named_object::{Checked, finish, status};
use super::query::probe_write;
use super::wow64_process_memory;
use crate::user::mm::{AddressSpace, PAGE_SIZE};
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiResult, Ctx};
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::{CURRENT_PROCESS, CURRENT_THREAD, Object};

const PROCESS_VM_WRITE: u32 = 0x20;

pub(super) fn write(c: &mut Ctx) -> ApiResult {
    if c.arch() == WinArch::X86 {
        return wow64_process_memory::write_x86(c);
    }
    let result = checked(c);
    finish(c, result)
}

fn checked(c: &mut Ctx) -> Checked<u32> {
    let (process, destination, source, length, returned) =
        (c.ptr(0)?, c.ptr(1)?, c.ptr(2)?, c.ptr(3)?, c.ptr(4)?);
    if returned != 0 {
        probe_write(c, returned, 8)?;
    }
    if length == 0 {
        if returned != 0 {
            c.write_ptr(returned, 0)?;
        }
        return Ok(STATUS_SUCCESS);
    }
    if source
        .checked_add(length)
        .is_none_or(|end| end > c.p.vm.high())
    {
        return status(STATUS_ACCESS_VIOLATION);
    }
    let pid = if process == CURRENT_PROCESS {
        c.p.pid
    } else {
        match c.p.objects.get(process) {
            Some(Object::Process { pid, .. }) => {
                if c.p.objects.access(process).unwrap_or(0) & PROCESS_VM_WRITE == 0 {
                    return status(STATUS_ACCESS_DENIED);
                }
                *pid
            }
            None if process != CURRENT_THREAD => return status(STATUS_INVALID_HANDLE),
            _ => return status(STATUS_OBJECT_TYPE_MISMATCH),
        }
    };
    let write = |target: &AddressSpace, limit| {
        if destination
            .checked_add(length)
            .is_none_or(|end| end > limit)
        {
            return (STATUS_ACCESS_VIOLATION, 0);
        }
        let copied = copy(c.mem(), source, target, destination, length);
        (
            if copied == length {
                STATUS_SUCCESS
            } else {
                STATUS_PARTIAL_COPY
            },
            copied,
        )
    };
    let (status, copied) = if pid == c.p.pid {
        write(&c.p.space, c.p.vm.high())
    } else {
        if c.p.children.basic(pid).is_none() {
            return Err(c
                .unsupported("NtWriteVirtualMemory outside the guest family")
                .into());
        }
        c.p.children
            .with_process(pid, |child| write(&child.space, child.vm.high()))
            .unwrap_or((STATUS_PROCESS_IS_TERMINATING, 0))
    };
    if returned != 0 {
        c.write_ptr(returned, copied)?;
    }
    Ok(status)
}

pub(super) fn copy(
    source: &AddressSpace,
    input: u64,
    target: &AddressSpace,
    output: u64,
    length: u64,
) -> u64 {
    let mut buffer = [0u8; PAGE_SIZE as usize];
    let mut done = 0;
    while done < length {
        let (from, to) = (input + done, output + done);
        let size = (length - done)
            .min(PAGE_SIZE - from % PAGE_SIZE)
            .min(PAGE_SIZE - to % PAGE_SIZE);
        let buffer = &mut buffer[..size as usize];
        if source.read(from, buffer).is_err() || target.write(to, buffer).is_err() {
            break;
        }
        done += size;
    }
    done
}
