//! The `kevent` family of calls (`kevent`, `kevent64`, `kevent_qos`:
//! `kevent_legacy_internal` and `kevent_qos` in `bsd/kern/kern_event.c`).

use std::time::Duration;

use crate::user::darwin::abi::Errno;
use crate::user::darwin::arch::SysResult;
use crate::user::darwin::kevent::{self, Call, Layout, kflag};
use crate::user::darwin::syscall::Ctx;

/// Which call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Api {
    /// `kevent(fd, changelist, nchanges, eventlist, nevents, timeout)`.
    Kevent,
    /// `kevent64(fd, changelist, nchanges, eventlist, nevents, flags,
    /// timeout)`.
    Kevent64,
    /// `kevent_qos(fd, changelist, nchanges, eventlist, nevents, data_out,
    /// data_available, flags)`.
    Qos,
}

/// `kevent_legacy_get_deadline`: a relative `struct timespec` timeout.
fn timeout(ctx: &Ctx<'_>, addr: u64) -> Result<Duration, Errno> {
    let b = ctx.read(addr, 16)?;
    let sec = i64::from_le_bytes(b[0..8].try_into().expect("8 bytes"));
    let nsec = i64::from_le_bytes(b[8..16].try_into().expect("8 bytes"));
    // timespec_is_valid.
    if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
        return Err(Errno::EINVAL);
    }
    Ok(Duration::from_secs(sec as u64) + Duration::from_nanos(nsec as u64))
}

/// Runs one `kevent` family call.
pub fn kevent(ctx: &mut Ctx<'_>, a: &[u64; 8], api: Api) -> SysResult {
    let (layout, flags, tmo_addr, data_out, data_available) = match api {
        Api::Kevent => (Layout::Kevent, kflag::LEGACY32, a[5], 0, 0),
        Api::Kevent64 => (
            Layout::Kevent64,
            (a[5] as u32 & kflag::USER) | kflag::LEGACY64,
            a[6],
            0,
            0,
        ),
        Api::Qos => (Layout::Qos, a[7] as u32 & kflag::USER, 0, a[5], a[6]),
    };
    let user_flags = match api {
        Api::Kevent => 0,
        Api::Kevent64 => a[5] as u32,
        Api::Qos => a[7] as u32,
    };
    // Workloop flags belong to kevent_id.
    if api != Api::Kevent && user_flags & kflag::ID_USER != 0 {
        return Err(Errno::EINVAL);
    }
    let tmo = if tmo_addr != 0 && flags & kflag::IMMEDIATE == 0 && !is_resumed(ctx) {
        Some(timeout(ctx, tmo_addr)?)
    } else {
        None
    };
    let call = Call {
        fd: a[0] as i32,
        changelist: a[1],
        nchanges: a[2] as i32,
        eventlist: a[3],
        nevents: a[4] as i32,
        flags,
        layout,
        timeout: tmo,
        data_out,
        data_available,
    };
    if flags & kflag::WORKQ != 0 {
        // The process's work-queue kqueue: not provided yet.
        return Err(Errno::ENOTSUP);
    }
    kevent::kevent(ctx, call)
}

fn is_resumed(ctx: &Ctx<'_>) -> bool {
    ctx.thread.resume.is_some_and(|r| r.step == 1)
}
