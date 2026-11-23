//! Wait operations on guest-owned child processes.

use crate::user::darwin::abi::Errno;
use crate::user::darwin::arch::{Rv, SysResult};
use crate::user::darwin::process::family::{Member, Report, Selector, WaitFor};
use crate::user::darwin::signal::{self, SIGCHLD};
use crate::user::darwin::syscall::{self, Ctx};
use crate::user::darwin::wait::{Wait, WaitKey};

/// `wait4` and `waitid` options (`bsd/sys/wait.h`).
pub mod opt {
    pub const WNOHANG: i32 = 0x01;
    pub const WUNTRACED: i32 = 0x02;
    pub const WEXITED: i32 = 0x04;
    pub const WSTOPPED: i32 = 0x08;
    pub const WCONTINUED: i32 = 0x10;
    pub const WNOWAIT: i32 = 0x20;
}

/// `idtype_t`.
pub mod idtype {
    pub const P_PID: i32 = 1;
    pub const P_PGID: i32 = 2;
}

/// `sizeof(struct user64_rusage)`.
pub(super) const RUSAGE_SIZE: usize = 144;

pub(super) fn wait4(
    ctx: &mut Ctx<'_>,
    pid: i32,
    status: u64,
    options: i32,
    rusage: u64,
) -> SysResult {
    let member = ctx.proc.family.as_ref().expect("closed process");
    let selector = match pid {
        i32::MIN => return Err(Errno::EINVAL),
        -1 => Selector::Any,
        0 => Selector::Group(member.identity(0)?.group),
        1.. => Selector::Pid(pid),
        _ => Selector::Group(-pid),
    };
    let wanted = WaitFor {
        exited: true,
        stopped: options & opt::WUNTRACED != 0,
        continued: options & opt::WCONTINUED != 0,
    };
    let Some((child, report)) = member.report(ctx.proc.pid, selector, wanted)? else {
        return no_report(ctx, options);
    };
    if status != 0 {
        ctx.write_u32(status, report.status as u32)?;
    }
    if rusage != 0 && report.is_exit() {
        let mut bytes = [0; RUSAGE_SIZE];
        for (at, ns) in [(0, report.user_ns), (16, report.system_ns)] {
            let seconds = ns / 1_000_000_000;
            let microseconds = ns % 1_000_000_000 / 1_000;
            bytes[at..at + 8].copy_from_slice(&seconds.to_le_bytes());
            bytes[at + 8..at + 16].copy_from_slice(&microseconds.to_le_bytes());
        }
        ctx.write(rusage, &bytes)?;
    }
    consume(ctx, child, report);
    Ok(Rv::one(child as u64))
}

pub(super) fn waitid(ctx: &mut Ctx<'_>, kind: i32, id: i32, info: u64, options: i32) -> SysResult {
    let valid = opt::WNOHANG | opt::WNOWAIT | opt::WCONTINUED | opt::WSTOPPED | opt::WEXITED;
    if options == 0 || options & !valid != 0 {
        return Err(Errno::EINVAL);
    }
    let selector = match kind {
        idtype::P_PID | idtype::P_PGID if id < 0 => return Err(Errno::EINVAL),
        idtype::P_PID => Selector::Pid(id),
        idtype::P_PGID => Selector::Group(id),
        _ => Selector::Any,
    };
    let member = ctx.proc.family.as_ref().expect("closed process");
    let wanted = WaitFor {
        exited: options & opt::WEXITED != 0,
        stopped: options & opt::WSTOPPED != 0,
        continued: options & opt::WCONTINUED != 0,
    };
    let Some((child, report)) = member.report(ctx.proc.pid, selector, wanted)? else {
        return no_report(ctx, options);
    };
    let mut bytes = [0; 104];
    bytes[0..4].copy_from_slice(&SIGCHLD.to_le_bytes());
    bytes[8..12].copy_from_slice(&report.code.to_le_bytes());
    bytes[12..16].copy_from_slice(&child.to_le_bytes());
    bytes[20..24].copy_from_slice(&report.value.to_le_bytes());
    ctx.write(info, &bytes)?;
    if options & opt::WNOWAIT == 0 {
        consume(ctx, child, report);
    }
    Ok(Rv::one(0))
}

fn no_report(ctx: &mut Ctx<'_>, options: i32) -> SysResult {
    if options & opt::WNOHANG != 0 {
        return Ok(Rv::one(0));
    }
    syscall::sleep(ctx, Wait::key(WaitKey::Child, None))
}

fn consume(ctx: &mut Ctx<'_>, child: i32, report: Report) {
    let member = ctx.proc.family.as_ref().expect("closed process");
    if !report.is_exit() {
        member.consume_job(child, report);
        return;
    }
    let sig = signal::bit(SIGCHLD);
    if !member.reap(ctx.proc.pid, child) && ctx.thread.sig.mask & sig != 0 {
        ctx.thread.sig.pending &= !sig;
    }
}

pub(super) fn identity(member: &Member, number: u32, pid: i32) -> SysResult {
    use crate::user::darwin::abi::tables::nr;
    let identity = member.identity(if number == nr::GETPGRP { 0 } else { pid })?;
    Ok(Rv::one(if number == nr::GETSID {
        identity.session
    } else {
        identity.group
    } as u64))
}
