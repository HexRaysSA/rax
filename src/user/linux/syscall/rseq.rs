//! `rseq` (`kernel/rseq.c`, Linux 6.19): registering and unregistering a
//! thread's restartable-sequences area. What the return to user mode does
//! with it is [`rseq`](super::super::rseq).

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::rseq::{
    self as model, ALIGN, CPU_ID_UNINITIALIZED, FEATURE_SIZE, ORIG_SIZE, Rseq,
};
use super::super::signal::deliver::{self, ForceMode};
use super::super::signal::{SIGSEGV, SigInfo};
use super::events::access_ok;
use super::{Ctx, SysResult};

/// `RSEQ_FLAG_UNREGISTER`.
const FLAG_UNREGISTER: i32 = 1;

/// `rseq`: unregistering names the registration exactly (`EINVAL`, and
/// `EPERM` for another signature) and resets the IDs; registering checks
/// the flags, then a registration already there (`EINVAL` for another
/// area or length, `EPERM` for another signature, else `EBUSY`), then the
/// length and alignment (`EINVAL`) and the range (`EFAULT`), and writes the
/// fields the kernel owns before the thread returns to user mode with its
/// IDs.
pub fn rseq(c: &mut Ctx<'_>, addr: u64, len: u32, flags: i32, sig: u32) -> SysResult {
    if flags & FLAG_UNREGISTER != 0 {
        if flags & !FLAG_UNREGISTER != 0 {
            return Err(Errno(EINVAL));
        }
        let Some(r) = c.t.rseq.clone() else {
            return Err(Errno(EINVAL));
        };
        if r.addr != addr || len != r.len {
            return Err(Errno(EINVAL));
        }
        if r.sig != sig {
            return Err(Errno(EPERM));
        }
        // rseq_reset_ids: a failure leaves the task in a state it cannot
        // return to user mode in.
        if !model::set_ids(&c.p.space, addr, CPU_ID_UNINITIALIZED, 0, 0) {
            let (p, mut th) = c.split();
            deliver::force_signal(p, &mut th, SigInfo::kernel(SIGSEGV), ForceMode::Current);
            return Err(Errno(EFAULT));
        }
        c.t.rseq = None;
        return Ok(0);
    }
    if flags != 0 {
        return Err(Errno(EINVAL));
    }
    if let Some(r) = &c.t.rseq {
        if r.addr != addr || len != r.len {
            return Err(Errno(EINVAL));
        }
        if r.sig != sig {
            return Err(Errno(EPERM));
        }
        return Err(Errno(EBUSY));
    }
    let aligned = addr % ALIGN == 0;
    if len < ORIG_SIZE
        || (len == ORIG_SIZE && !aligned)
        || (len != ORIG_SIZE && (!aligned || len < FEATURE_SIZE))
    {
        return Err(Errno(EINVAL));
    }
    if !access_ok(c, addr, u64::from(len)) {
        return Err(Errno(EFAULT));
    }
    // A stale critical section is cleared, and the IDs read as
    // uninitialized until the return to user mode fills them in.
    c.write_u64(addr + 8, 0)?;
    c.write_u32(addr, CPU_ID_UNINITIALIZED)?;
    c.write_u32(addr + 4, CPU_ID_UNINITIALIZED)?;
    c.write_u32(addr + 20, 0)?;
    c.write_u32(addr + 24, 0)?;
    c.t.rseq = Some(Rseq::new(addr, len, sig));
    Ok(0)
}
