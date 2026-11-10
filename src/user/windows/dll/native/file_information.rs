//! Retained file names, fixed records and modeled standard-stream information.
//! The independent native corpus owns class/length/probe/publication behavior.
//! Host adapters receive only admitted File objects and fixed class numbers.

pub(super) mod host;
mod name;
mod publish;
mod records;
mod security_device;

use super::named_object::{Checked, finish_with, status};
use super::query::probe_write;
use crate::error::MemoryAccessKind;
use crate::user::mm::PAGE_SIZE;
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiResult, Ctx};
use crate::user::windows::memory::prot;
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::{CURRENT_PROCESS, CURRENT_THREAD, Object};

#[derive(Clone, Copy)]
struct Layout {
    bytes: u32,
    alignment: u64,
}

impl Layout {
    fn of(class: u32) -> Option<Self> {
        let (bytes, alignment) = match class {
            9 => (8, 4),
            4 => (40, 8),
            5 => (24, 8),
            6 | 14 => (8, 8),
            7 | 8 | 16 | 17 | 41 => (4, 4),
            34 => (56, 8),
            35 => (8, 4),
            43 => (4, 8),
            51 => (1, 1),
            59 => (24, 8),
            _ => return None,
        };
        Some(Self { bytes, alignment })
    }
}

pub(super) fn query(c: &mut Ctx) -> ApiResult {
    let mut caller_store = false;
    let result = checked(c, &mut caller_store);
    finish_with(c, result, caller_store)
}

fn checked(c: &mut Ctx, caller_store: &mut bool) -> Checked<u32> {
    let (handle, io, output, length, class) =
        (c.ptr(0)?, c.ptr(1)?, c.ptr(2)?, c.u32(3)?, c.u32(4)?);
    let wow = c.arch() == WinArch::X86;
    // The WoW64 thunk validates nonnull caller buffer spans even for an
    // information class which has no native conversion. It visits no guard.
    if wow
        && output != 0
        && (output < 0x10000
            || output
                .checked_add(u64::from(length))
                .is_none_or(|end| end > c.p.vm.high()))
    {
        return status(STATUS_ACCESS_VIOLATION);
    }
    if wow && output != 0 {
        // The captured thunk rejects inaccessible caller spans even for an
        // unknown class, while leaving readable guards untouched at this stage.
        let end = output + u64::from(length);
        let mut address = output;
        while address < end {
            match c
                .mem()
                .probe(address, (end - address) as usize, MemoryAccessKind::Read)
            {
                Ok(()) => break,
                Err(fault) => {
                    let guarded = c.p.vm.query(fault.address).is_some_and(|region| {
                        region.protect & prot::GUARD != 0
                            && matches!(
                                region.protect & 0xff,
                                prot::READONLY
                                    | prot::READWRITE
                                    | prot::WRITECOPY
                                    | prot::EXECUTE_READ
                                    | prot::EXECUTE_READWRITE
                                    | prot::EXECUTE_WRITECOPY
                            )
                    });
                    if !guarded {
                        return status(STATUS_ACCESS_VIOLATION);
                    }
                    address = (fault.address & !(PAGE_SIZE - 1)) + PAGE_SIZE;
                }
            }
        }
    }
    let Some(layout) = Layout::of(class) else {
        if matches!(class, 0 | 90..=u32::MAX) {
            return status(if wow {
                0xc000_0002
            } else {
                STATUS_INVALID_INFO_CLASS
            });
        }
        return Err(c
            .unsupported(format!("file information class {class}"))
            .into());
    };
    if length < layout.bytes {
        return status(STATUS_INFO_LENGTH_MISMATCH);
    }
    if wow {
        if io == 0 {
            return status(STATUS_ACCESS_VIOLATION);
        }
    } else {
        probe_write(c, io, 4)?;
        if output % layout.alignment != 0 {
            return status(STATUS_DATATYPE_MISALIGNMENT);
        }
    }
    probe_write(c, output, length as usize)?;
    let Some(object) = c.p.objects.get(handle) else {
        return status(
            if handle == c.arch().ptr(CURRENT_PROCESS) || handle == c.arch().ptr(CURRENT_THREAD) {
                STATUS_OBJECT_TYPE_MISMATCH
            } else {
                STATUS_INVALID_HANDLE
            },
        );
    };
    if !matches!(
        object,
        Object::File(_)
            | Object::SecurityFile(_)
            | Object::Console(_)
            | Object::Null
            | Object::Pipe { .. }
    ) {
        return status(STATUS_OBJECT_TYPE_MISMATCH);
    }
    let record = if matches!(object, Object::SecurityFile(_)) {
        security_device::query(c, handle, class)?
    } else if class == 9 {
        name::query(c, handle, object, length)?
    } else {
        records::query(c, handle, object, class)?
    };
    *caller_store = wow;
    publish::record(c, io, output, &record, wow, length)
}
