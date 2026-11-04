use super::super::named_object::{Checked, status};
use crate::error::MemoryAccessKind;
use crate::user::mm::PAGE_SIZE;
use crate::user::windows::hle::Ctx;
use crate::user::windows::memory::{Mem, MemFault, prot};
use crate::user::windows::nt::status::STATUS_ACCESS_VIOLATION;

pub(super) fn read(c: &Ctx, address: u64, bytes: usize) -> Checked<()> {
    c.mem()
        .probe(address, bytes, MemoryAccessKind::Read)
        .map_err(|fault| {
            MemFault {
                addr: fault.address,
                write: false,
            }
            .into()
        })
}

/// Native ProbeForRead validates range/alignment before handle lookup; mapped
/// pages are reached only by the subsequent captured input copy.
pub(super) fn native_span(c: &Ctx, input: u64, length: u32) -> Checked<()> {
    if input
        .checked_add(u64::from(length))
        .is_none_or(|end| end > c.p.vm.high())
    {
        return status(STATUS_ACCESS_VIOLATION);
    }
    Ok(())
}

/// The thunk validates a readable span without visiting readable guard pages,
/// before even dispatching the information class. NULL is handled downstream.
pub(super) fn wow64_span(c: &Ctx, input: u64, length: u32) -> Checked<()> {
    let Some(end) = input.checked_add(u64::from(length)) else {
        return status(STATUS_ACCESS_VIOLATION);
    };
    if input < 0x10000 || end > c.p.vm.high() {
        return status(STATUS_ACCESS_VIOLATION);
    }
    let mut address = input;
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
    Ok(())
}
