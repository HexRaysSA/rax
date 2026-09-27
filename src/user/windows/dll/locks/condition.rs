use crate::user::windows::hle::{ApiResult, Ctx, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::error::{ERROR_INVALID_PARAMETER, ERROR_TIMEOUT};
use crate::user::windows::nt::status::*;
use crate::user::windows::sync::{self, CONDVAR_KEY, SyncError, Wait};
use std::time::{Duration, Instant};

fn deadline(milliseconds: u32) -> Result<Option<Instant>, SyncError> {
    if milliseconds == u32::MAX {
        return Ok(None);
    }
    Instant::now()
        .checked_add(Duration::from_millis(milliseconds.into()))
        .map(Some)
        .ok_or(SyncError::Invalid("timeout deadline overflow"))
}

pub(super) fn initialize(c: &mut Ctx) -> ApiResult {
    let addr = c.ptr(0)?;
    sync::cv_init(c.p, addr)?;
    Flow::void()
}

fn wake(c: &mut Ctx, count: usize) -> ApiResult {
    let addr = c.ptr(0)?;
    sync::cv_check(c.p, addr)?;
    c.p.sync.wake(u128::from(addr) | CONDVAR_KEY, count);
    Flow::void()
}
pub(super) fn wake_one(c: &mut Ctx) -> ApiResult {
    wake(c, 1)
}
pub(super) fn wake_all(c: &mut Ctx) -> ApiResult {
    wake(c, usize::MAX)
}

fn finish(c: &mut Ctx, status: u64) -> ApiResult {
    if status == u64::from(STATUS_TIMEOUT) {
        c.fail(ERROR_TIMEOUT, 0)
    } else {
        Flow::bool(true)
    }
}

fn reacquire(c: &mut Ctx, addr: u64, mode: Option<bool>, status: u64) -> ApiResult {
    let acquired = match mode {
        None => sync::cs_try_enter(c.p, addr, c.t.tid)?,
        Some(exclusive) => sync::srw_try(c.p, addr, c.t.tid, exclusive)?,
    };
    if acquired {
        return finish(c, status);
    }
    let wait = match mode {
        None => Wait::CritSec { addr },
        Some(exclusive) => Wait::Srw { addr, exclusive },
    };
    Ok(Flow::Block {
        wait,
        then: Box::new(move |c, _| finish(c, status)),
    })
}

pub(super) fn sleep_cs(c: &mut Ctx) -> ApiResult {
    let (cv, lock, ms) = (c.ptr(0)?, c.ptr(1)?, c.u32(2)?);
    sync::cv_check(c.p, cv)?;
    if sync::cs_recursion(c.p, lock, c.t.tid)? != 1 {
        return Err(SyncError::Invalid(
            "condition wait requires exactly one critical-section entry",
        )
        .into());
    }
    let deadline = deadline(ms)?;
    if !sync::cs_leave(c.p, lock, c.t.tid)? {
        return Err(
            SyncError::Invalid("condition wait requires critical-section ownership").into(),
        );
    }
    Ok(Flow::Block {
        wait: Wait::Address {
            key: u128::from(cv) | CONDVAR_KEY,
            deadline,
        },
        then: Box::new(move |c, status| reacquire(c, lock, None, status)),
    })
}

pub(super) fn sleep_srw(c: &mut Ctx) -> ApiResult {
    let (cv, lock, ms, flags) = (c.ptr(0)?, c.ptr(1)?, c.u32(2)?, c.u32(3)?);
    if flags & !1 != 0 {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    }
    sync::cv_check(c.p, cv)?;
    let exclusive = flags == 0;
    if sync::srw_held(c.p, lock, c.t.tid)? != Some(exclusive) {
        return Err(SyncError::Invalid("condition wait requires matching SRW ownership").into());
    }
    let deadline = deadline(ms)?;
    sync::srw_release(c.p, lock, c.t.tid, exclusive)?;
    Ok(Flow::Block {
        wait: Wait::Address {
            key: u128::from(cv) | CONDVAR_KEY,
            deadline,
        },
        then: Box::new(move |c, status| reacquire(c, lock, Some(exclusive), status)),
    })
}

pub(super) fn wait_address(c: &mut Ctx) -> ApiResult {
    let (address, compare, size, ms) = (c.ptr(0)?, c.ptr(1)?, c.ptr(2)?, c.u32(3)?);
    if !matches!(size, 1 | 2 | 4 | 8) {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    }
    // Unlike SRW/CV storage, byte-address waits need not be pointer-aligned.
    let mut current = [0; 8];
    let mut undesired = [0; 8];
    c.mem().rd(address, &mut current[..size as usize])?;
    c.mem().rd(compare, &mut undesired[..size as usize])?;
    if current[..size as usize] != undesired[..size as usize] {
        return Flow::bool(true);
    }
    if ms == 0 {
        return c.fail(ERROR_TIMEOUT, 0);
    }
    Ok(Flow::Block {
        wait: Wait::Address {
            key: address.into(),
            deadline: deadline(ms)?,
        },
        then: Box::new(finish),
    })
}

fn wake_address(c: &mut Ctx, count: usize) -> ApiResult {
    let address = c.ptr(0)?;
    // Waking only hashes the address; no value access is required.
    c.p.sync.wake(address.into(), count);
    Flow::void()
}
pub(super) fn wake_address_one(c: &mut Ctx) -> ApiResult {
    wake_address(c, 1)
}
pub(super) fn wake_address_all(c: &mut Ctx) -> ApiResult {
    wake_address(c, usize::MAX)
}
