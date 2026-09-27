//! Checked growth of the selected stack's guard frontier.
//!
//! Growth commits one lower guard page, publishes the newly usable old guard
//! as StackLimit, and retries the original access. At exhaustion the consumed
//! guard is published as an emergency frontier for exception dispatch, without
//! consuming the reserved bottom page. Non-stack guards retain one-shot behavior.

use super::{Proc, Thread};
use crate::error::MemoryAccessKind;
use crate::user::mm::PAGE_SIZE;
use crate::user::windows::context::ExceptionRecord;
use crate::user::windows::hle::ApiErr;
use crate::user::windows::layout::offsets;
use crate::user::windows::memory::{Mem, MemFault, mem, prot};
use crate::user::windows::nt::status::STATUS_STACK_OVERFLOW;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StackFault {
    Access(MemFault),
    Overflow(u64),
}

impl StackFault {
    pub(crate) fn into_api(self, pc: u64) -> ApiErr {
        match self {
            Self::Access(fault) => ApiErr::Fault(fault),
            Self::Overflow(address) => ApiErr::Raise(ExceptionRecord::new(
                STATUS_STACK_OVERFLOW,
                pc,
                vec![1, address],
            )),
        }
    }
}

impl From<MemFault> for StackFault {
    fn from(fault: MemFault) -> Self {
        Self::Access(fault)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Growth {
    NotStack,
    Grown,
    Overflow,
}

/// Called after the faulting guard was consumed. Host stack metadata, not a
/// guest-editable allocation pointer, bounds every mapping operation.
pub(crate) fn grow(p: &mut Proc, t: &mut Thread, address: u64) -> Result<Growth, MemFault> {
    let page = address & !(PAGE_SIZE - 1);
    let Some(old_guard) = t.stack_limit.checked_sub(PAGE_SIZE) else {
        return Ok(Growth::NotStack);
    };
    if page != old_guard || page < t.stack_alloc || page >= t.stack_base {
        return Ok(Growth::NotStack);
    }
    let pointer = t.teb + offsets(p.arch).teb_stack_limit;
    p.space
        .probe(pointer, p.arch.ptr_size() as usize, MemoryAccessKind::Write)
        .map_err(|fault| MemFault {
            addr: fault.address,
            write: true,
        })?;
    let next = old_guard.checked_sub(PAGE_SIZE).filter(|&new_guard| {
        t.stack_alloc
            .checked_add(PAGE_SIZE)
            .is_some_and(|bottom| new_guard >= bottom)
            && p.vm
                .query(new_guard)
                .is_some_and(|r| r.allocation_base == t.stack_alloc && r.state == mem::RESERVE)
    });
    let growth = match next {
        Some(new_guard)
            if p.vm
                .commit(new_guard, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                .is_ok() =>
        {
            Growth::Grown
        }
        _ => Growth::Overflow,
    };
    // Single-host-thread mapping contract makes publication infallible after
    // preflight. Preserve a checked error if that contract is violated.
    p.space.wptr(pointer, p.arch.ptr_size(), old_guard)?;
    t.stack_limit = old_guard;
    // On overflow the consumed guard remains the checked emergency page.
    // Publishing its frontier lets SEH records/handlers use it without taking
    // the same one-shot guard twice; the next lower page is never admitted.
    Ok(growth)
}

/// Stack allocations performed by the personality probe every descending guard
/// before writing. This avoids consuming a guest continuation on a setup fault.
pub(crate) fn prepare(
    p: &mut Proc,
    t: &mut Thread,
    address: u64,
    bytes: u64,
) -> Result<(), StackFault> {
    let fault = |addr| MemFault { addr, write: true };
    let end = address.checked_add(bytes).ok_or_else(|| fault(address))?;
    if address >= t.stack_alloc && end <= t.stack_base {
        while address < t.stack_limit {
            let guard = t
                .stack_limit
                .checked_sub(PAGE_SIZE)
                .ok_or_else(|| fault(address))?;
            if !p.vm.take_guard(guard) {
                return Err(fault(address).into());
            }
            match grow(p, t, guard)? {
                Growth::Grown => {}
                Growth::Overflow => return Err(StackFault::Overflow(guard)),
                Growth::NotStack => return Err(fault(guard).into()),
            }
        }
    }
    let len = usize::try_from(bytes).map_err(|_| fault(address))?;
    p.space
        .probe(address, len, MemoryAccessKind::Write)
        .map_err(|error| fault(error.address).into())
}

#[cfg(test)]
mod tests;
