//! Process identity and life cycle.

use crate::user::darwin::abi::Errno;
use crate::user::darwin::arch::SysResult;
use crate::user::darwin::process::ExitStatus;
use crate::user::darwin::syscall::Ctx;

/// `exit(rval)`: the process ends with the low 8 bits of `rval`
/// (`exit1` records `W_EXITCODE(rval, 0)`).
pub fn exit(ctx: &mut Ctx<'_>, rval: i32) -> SysResult {
    ctx.proc.exit_with(ExitStatus::Exited(rval & 0xff));
    ctx.thread.exited = true;
    Err(Errno::EJUSTRETURN)
}

/// A host process-ID call's result (`getpgrp`, `getsid`, `setsid`, ...):
/// guest processes are host processes.
pub fn host_id(f: impl FnOnce() -> i32) -> SysResult {
    let r = f();
    if r < 0 {
        return Err(Errno::last());
    }
    Ok(crate::user::darwin::arch::Rv::one(r as u64))
}

/// `getgroups(gidsetsize, gidset)`.
#[cfg(unix)]
pub fn getgroups(ctx: &mut Ctx<'_>, size: u32, list: u64) -> SysResult {
    let mut groups = vec![0 as libc::gid_t; 64];
    // SAFETY: `groups` has room for 64 entries.
    let n = unsafe { libc::getgroups(groups.len() as i32, groups.as_mut_ptr()) };
    if n < 0 {
        return Err(Errno::last());
    }
    let n = n as usize;
    if size == 0 {
        return Ok(crate::user::darwin::arch::Rv::one(n as u64));
    }
    if (size as usize) < n {
        return Err(Errno::EINVAL);
    }
    let b: Vec<u8> = groups[..n]
        .iter()
        .flat_map(|g| (*g as u32).to_le_bytes())
        .collect();
    ctx.write(list, &b)?;
    Ok(crate::user::darwin::arch::Rv::one(n as u64))
}

/// `getlogin(namebuf, namelen)` (`__getlogin`): the session's login name.
#[cfg(unix)]
pub fn getlogin(ctx: &mut Ctx<'_>, buf: u64, len: u32) -> SysResult {
    // SAFETY: getlogin returns a pointer to a static string or null.
    let p = unsafe { libc::getlogin() };
    let name: Vec<u8> = if p.is_null() {
        Vec::new()
    } else {
        // SAFETY: a non-null result is NUL-terminated.
        unsafe { std::ffi::CStr::from_ptr(p) }.to_bytes().to_vec()
    };
    // MAXLOGNAME is 255 on Darwin; the kernel copies at most namelen.
    let mut out = name;
    out.push(0);
    let n = out.len().min(len as usize);
    ctx.write(buf, &out[..n])?;
    Ok(crate::user::darwin::arch::Rv::one(0))
}

/// `getpriority(which, who)`: the host's scheduling priority.
#[cfg(unix)]
pub fn getpriority(ctx: &mut Ctx<'_>, which: i32, who: u64) -> SysResult {
    let _ = ctx;
    crate::user::darwin::host::set_errno(0);
    // SAFETY: getpriority takes no pointers.
    let r = unsafe { libc::getpriority(which as _, who as _) };
    if r == -1 {
        let e = Errno::last();
        if e.0 != 0 {
            return Err(e);
        }
    }
    Ok(crate::user::darwin::arch::Rv::one(r as i64 as u64))
}

/// `KAUTH_UID_NONE` and `KAUTH_GID_NONE`: no identity.
const KAUTH_ID_NONE: u32 = !0 - 100;

/// `gettid(uidp, gidp)`: the calling thread's assumed identity, `ESRCH`
/// when it has none.
pub fn gettid(ctx: &mut Ctx<'_>, uidp: u64, gidp: u64) -> SysResult {
    let (uid, gid) = ctx.thread.assumed.ok_or(Errno::ESRCH)?;
    ctx.write_u32(uidp, uid)?;
    ctx.write_u32(gidp, gid)?;
    Ok(crate::user::darwin::arch::Rv::one(0))
}

/// `settid(uid, gid)` (`kern_settid`): a privileged thread assumes an
/// identity, or with `KAUTH_UID_NONE` gives it up. (The assumed identity
/// is recorded for `gettid`; the host still checks the process's.)
pub fn settid(ctx: &mut Ctx<'_>, uid: u32, gid: u32) -> SysResult {
    if ctx.proc.creds.1 != 0 {
        return Err(Errno::EPERM);
    }
    let assumed = &mut ctx.thread.assumed;
    if uid == KAUTH_ID_NONE {
        if assumed.is_none() {
            return Err(Errno::EPERM);
        }
        *assumed = None;
    } else {
        if assumed.is_some() {
            return Err(Errno::EPERM);
        }
        *assumed = Some((uid, gid));
    }
    Ok(crate::user::darwin::arch::Rv::one(0))
}

/// `settid_with_pid(pid, assume)`: assume the effective identity of
/// process `pid`, or give up an assumed one.
pub fn settid_with_pid(ctx: &mut Ctx<'_>, pid: i32, assume: i32) -> SysResult {
    let (uid, gid) = if assume != 0 {
        if pid == 0 {
            return Err(Errno::ESRCH);
        }
        effective_ids(ctx, pid).ok_or(Errno::ESRCH)?
    } else {
        (KAUTH_ID_NONE, KAUTH_ID_NONE)
    };
    settid(ctx, uid, gid)
}

/// The effective user and group of process `pid`.
fn effective_ids(ctx: &Ctx<'_>, pid: i32) -> Option<(u32, u32)> {
    if pid == ctx.proc.pid {
        return Some((ctx.proc.creds.1, ctx.proc.creds.3));
    }
    #[cfg(target_os = "macos")]
    {
        // SAFETY: an all-zero proc_bsdinfo is a valid value to overwrite;
        // the call writes at most its size.
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::proc_bsdinfo>() as i32;
        // SAFETY: `info` has `size` writable bytes.
        let n = unsafe {
            libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, (&raw mut info).cast(), size)
        };
        (n == size).then_some((info.pbi_uid, info.pbi_gid))
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

/// `task_read_for_pid` and `task_inspect_for_pid` (`kern_proc.c`): the
/// read (or inspect) port of the calling process; another process's is
/// refused as it is to an unentitled caller (`EPERM`, or `ESRCH` when
/// there is no such process), the kernel's (pid 0) always. `target` must
/// name the caller's task control port (`EINVAL`). The port's name, or
/// `MACH_PORT_NULL`, is stored at `t` (a failed store is ignored).
pub fn task_flavor_for_pid(
    ctx: &mut Ctx<'_>,
    target: u32,
    pid: i32,
    t: u64,
    read: bool,
) -> SysResult {
    use crate::user::darwin::mig::task::{inspect_port, read_port};
    let result = if pid == 0 {
        Err(Errno::EPERM)
    } else if !crate::user::darwin::syscall::mach::port::is_self_task(ctx.proc, target) {
        Err(Errno::EINVAL)
    } else if pid == ctx.proc.pid {
        Ok(())
    } else {
        if !ctx.proc.config.host_services {
            Err(Errno::EPERM)
        } else {
            #[cfg(unix)]
            {
                // SAFETY: kill with signal 0 only checks that the process exists.
                let exists = unsafe { libc::kill(pid, 0) } == 0
                    || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
                Err(if exists { Errno::EPERM } else { Errno::ESRCH })
            }
            #[cfg(not(unix))]
            Err(Errno::ENOTSUP)
        }
    };
    let name = if result.is_ok() {
        let port = if read {
            read_port(ctx.proc)
        } else {
            inspect_port(ctx.proc)
        };
        ctx.proc.insert_send(&port)
    } else {
        0
    };
    let _ = ctx.write_u32(t, name);
    result.map(|()| crate::user::darwin::arch::Rv::one(0))
}

/// The emulated process's image name (`p_comm`, `p_name`): the last
/// component of the path it was executed by.
pub(crate) fn image_name(ctx: &Ctx<'_>) -> Vec<u8> {
    let path = ctx.proc.program.image.path.as_bytes();
    let name = path.rsplit(|&c| c == b'/').next().unwrap_or(path);
    name.to_vec()
}
