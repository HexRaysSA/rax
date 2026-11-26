//! RTL_RESOURCE ownership in the portable scheduler. The native lock's
//! semaphore handles are internal, so waiters use scheduler continuations.

use crate::user::windows::hle::{ApiErr, ApiResult, Arg::*, Conv::Stdcall, Ctx, Export, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::sync::Wait;

pub(in crate::user::windows::dll) static EXPORTS: &[Export] = &[
    Export::func("RtlInitializeResource", Stdcall, &[Ptr], initialize),
    Export::func("RtlDeleteResource", Stdcall, &[Ptr], delete),
    Export::func("RtlAcquireResourceShared", Stdcall, &[Ptr, I32], shared),
    Export::func(
        "RtlAcquireResourceExclusive",
        Stdcall,
        &[Ptr, I32],
        exclusive,
    ),
    Export::func("RtlReleaseResource", Stdcall, &[Ptr], release),
];

const WAIT_KEY: u128 = 1 << 66;

// The SDK-compatible nActive (LONG) precedes the owner HANDLE. Reading
// both together also checks the span needed for a later ownership update.
fn state_addr(c: &Ctx, address: u64) -> Result<u64, ApiErr> {
    if address == 0 || address % c.psize() != 0 {
        return Err(c.unsupported("misaligned or null RTL_RESOURCE"));
    }
    let active = if c.arch().is64() { 0x44 } else { 0x28 };
    if address.checked_add(active + 4 + c.psize()).is_none() {
        return Err(c.unsupported("overflowing RTL_RESOURCE"));
    }
    Ok(address + active)
}

fn state(c: &Ctx, active: u64) -> Result<(i32, u64), ApiErr> {
    let count = c.mem().u32(active)? as i32;
    let owner = c.read_ptr(active + 4)?;
    if (count < 0) != (owner != 0) {
        return Err(c.unsupported("inconsistent RTL_RESOURCE owner and count"));
    }
    Ok((count, owner))
}

fn store(c: &Ctx, active: u64, count: i32, owner: u64) -> Result<(), ApiErr> {
    let mut bytes = [0; 12];
    bytes[..4].copy_from_slice(&count.to_le_bytes());
    bytes[4..].copy_from_slice(&owner.to_le_bytes());
    c.mem().wr(active, &bytes[..4 + c.psize() as usize])?;
    Ok(())
}

fn clear(c: &Ctx, address: u64) -> ApiResult {
    let mut bytes = [0; 0x60];
    let (size, lock_count) = if c.arch().is64() {
        (0x60, 8)
    } else {
        (0x38, 4)
    };
    bytes[lock_count..lock_count + 4].copy_from_slice(&(-1i32).to_le_bytes());
    c.mem().wr(address, &bytes[..size])?;
    Flow::void()
}

fn initialize(c: &mut Ctx) -> ApiResult {
    let address = c.ptr(0)?;
    state_addr(c, address)?;
    clear(c, address)
}

fn delete(c: &mut Ctx) -> ApiResult {
    let address = c.ptr(0)?;
    let (count, _) = state(c, state_addr(c, address)?)?;
    if count != 0 {
        return Err(c.unsupported("deleting a held RTL_RESOURCE"));
    }
    clear(c, address)
}

fn acquire(c: &mut Ctx, address: u64, exclusive: bool, wait: bool) -> ApiResult {
    let active = state_addr(c, address)?;
    let (count, owner) = state(c, active)?;
    let tid = u64::from(c.t.tid);
    if owner == tid || (exclusive && count == 0) {
        let next = count
            .checked_sub(1)
            .ok_or_else(|| c.unsupported("RTL_RESOURCE recursion overflow"))?;
        store(c, active, next, tid)?;
    } else if !exclusive && count >= 0 {
        let next = count
            .checked_add(1)
            .ok_or_else(|| c.unsupported("RTL_RESOURCE reader overflow"))?;
        store(c, active, next, 0)?;
    } else if wait {
        return Flow::block(
            Wait::Address {
                key: WAIT_KEY | u128::from(address),
                deadline: None,
            },
            move |c, _| acquire(c, address, exclusive, wait),
        );
    } else {
        return Flow::bool(false);
    }
    Flow::bool(true)
}

fn shared(c: &mut Ctx) -> ApiResult {
    acquire(c, c.ptr(0)?, false, c.u32(1)? as u8 != 0)
}

fn exclusive(c: &mut Ctx) -> ApiResult {
    acquire(c, c.ptr(0)?, true, c.u32(1)? as u8 != 0)
}

fn release(c: &mut Ctx) -> ApiResult {
    let address = c.ptr(0)?;
    let active = state_addr(c, address)?;
    let (count, owner) = state(c, active)?;
    let next = match count {
        1.. => count - 1,
        ..=-1 if owner == u64::from(c.t.tid) => count + 1,
        _ => return Err(c.unsupported("unowned RTL_RESOURCE release")),
    };
    store(c, active, next, if next == 0 { 0 } else { owner })?;
    if next == 0 {
        c.p.sync.wake(WAIT_KEY | u128::from(address), usize::MAX);
    }
    Flow::void()
}
