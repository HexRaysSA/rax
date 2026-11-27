//! Process identity and life cycle.

use crate::user::darwin::abi::Errno;
use crate::user::darwin::arch::{Rv, SysResult};
use crate::user::darwin::process::ExitStatus;
use crate::user::darwin::syscall::Ctx;

/// `exit(rval)`: the process ends with the low 8 bits of `rval`
/// (`exit1` records `W_EXITCODE(rval, 0)`).
pub fn exit(ctx: &mut Ctx<'_>, rval: i32) -> SysResult {
    ctx.proc.exit_with(ExitStatus::Exited(rval & 0xff));
    ctx.thread.exited = true;
    Err(Errno::EJUSTRETURN)
}

/// Return `PROC_PIDUNIQIDENTIFIERINFO` for the sole process in a closed guest.
/// libdispatch queries this during firehose initialization.
pub(super) fn closed_pidinfo(ctx: &Ctx<'_>, a: &[u64; 8], extended: bool) -> SysResult {
    const PIDINFO: i32 = 2;
    const UNIQIDENTIFIERINFO: i32 = 17;
    const COMPARE_IDVERSION: u32 = 1;
    const COMPARE_UNIQUEID: u32 = 2;
    const SIZE: usize = 56;

    if a[0] as i32 != PIDINFO || a[1] as i32 != ctx.proc.pid || a[2] as i32 != UNIQIDENTIFIERINFO {
        return Err(Errno::EPERM);
    }
    let (flags, ext_id, buffer, size) = if extended {
        (a[3] as u32, a[4], a[6], a[7] as u32)
    } else {
        (0, 0, a[4], a[5] as u32)
    };
    if flags & COMPARE_IDVERSION != 0 && flags & COMPARE_UNIQUEID != 0 {
        return Err(Errno::EINVAL);
    }
    if size < SIZE as u32 {
        return Err(Errno::ENOMEM);
    }
    let version = ctx.proc.audit[7];
    // PID and generation identify the process within its private namespace.
    let unique_id = (u64::from(version) << 32) | u64::from(ctx.proc.pid as u32);
    if (flags & COMPARE_IDVERSION != 0 && ext_id != u64::from(version))
        || (flags & COMPARE_UNIQUEID != 0 && ext_id != unique_id)
    {
        return Err(Errno::ESRCH);
    }
    // XNU's proc_uniqidentifierinfo. The closed process has no visible parent.
    let mut info = [0; SIZE];
    info[..16].copy_from_slice(&ctx.proc.program.main.uuid.unwrap_or_default());
    info[16..24].copy_from_slice(&unique_id.to_le_bytes());
    info[32..36].copy_from_slice(&version.to_le_bytes());
    ctx.write(buffer, &info)?;
    Ok(Rv::one(SIZE as u64))
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

/// The closed guest has no supplementary group assignments beyond its effective GID.
pub(super) fn closed_getgroups(ctx: &mut Ctx<'_>, size: i32, list: u64) -> SysResult {
    if size < 0 {
        return Err(Errno::EINVAL);
    }
    if size != 0 {
        ctx.write_u32(list, ctx.proc.creds.3)?;
    }
    Ok(Rv::one(1))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::darwin::{
        abi::{DarwinAbi, tables::nr},
        process::bounded_tests::process_with_profile,
        syscall::bsd,
    };

    #[test]
    fn closed_getgroups_copies_only_the_effective_group() {
        for abi in [DarwinAbi::X86_64, DarwinAbi::Arm64] {
            let mut p = process_with_profile(abi, true);
            p.proc.creds.3 = 1234;
            let (_, mut thread) = p.proc.threads.pop_first().unwrap();
            let list = thread.cpu.sp() - 16;
            let mut ctx = Ctx {
                proc: &mut p.proc,
                thread: &mut thread,
                nr: i64::from(nr::GETGROUPS),
                pc: 0,
            };
            let call = |ctx: &mut Ctx<'_>, size: i32, dst| {
                bsd::call(ctx, nr::GETGROUPS, &[size as u64, dst, 0, 0, 0, 0, 0, 0])
            };
            assert_eq!(call(&mut ctx, 0, 0), Ok(Rv::one(1)));
            assert_eq!(call(&mut ctx, -1, 0), Err(Errno::EINVAL));
            assert_eq!(call(&mut ctx, 1, 0), Err(Errno::EFAULT));
            for size in [1, 2] {
                ctx.write_u32(list, u32::MAX).unwrap();
                ctx.write_u32(list + 4, u32::MAX).unwrap();
                assert_eq!(call(&mut ctx, size, list), Ok(Rv::one(1)));
                assert_eq!(ctx.read_u32(list).unwrap(), 1234);
                assert_eq!(ctx.read_u32(list + 4).unwrap(), u32::MAX);
            }
        }
    }
}

/// A closed process family starts in one audit session. Each family has its
/// own namespace, unrelated to host audit sessions or guest POSIX job control.
const SESSION_ID: u32 = 100_000;
const AU_IP_V4: u32 = 4;

/// Copy the requested prefix of the 48-byte Darwin `auditinfo_addr_t`.
/// This model has no terminal, auditing mask, or session privileges.
pub(super) fn closed_getaudit_addr(ctx: &Ctx<'_>, output: u64, length: u32) -> SysResult {
    let mut info = [0; 48];
    info[..4].copy_from_slice(&ctx.proc.creds.0.to_le_bytes());
    info[16..20].copy_from_slice(&AU_IP_V4.to_le_bytes());
    info[36..40].copy_from_slice(&SESSION_ID.to_le_bytes());
    ctx.write(output, &info[..info.len().min(length as usize)])?;
    Ok(Rv::one(0))
}

#[cfg(test)]
mod closed_audit_tests {
    use super::*;
    use crate::user::darwin::{
        abi::{DarwinAbi, Errno, tables::nr},
        process::bounded_tests::process,
        syscall::bsd,
    };

    #[test]
    fn closed_audit_address_copies_guest_identity_and_only_the_requested_prefix() {
        for abi in [DarwinAbi::Arm64, DarwinAbi::X86_64] {
            let mut guest = process(abi);
            guest.proc.creds.0 = 0x1234;
            guest.proc.creds.1 = 0x5678;
            let (_, mut thread) = guest.proc.threads.pop_first().unwrap();
            let output = thread.cpu.sp() - 64;
            let mut ctx = Ctx {
                proc: &mut guest.proc,
                thread: &mut thread,
                nr: i64::from(nr::GETAUDIT_ADDR),
                pc: 0,
            };
            let call = |ctx: &mut Ctx<'_>, destination, length| {
                bsd::call(
                    ctx,
                    nr::GETAUDIT_ADDR,
                    &[destination, length, 0, 0, 0, 0, 0, 0],
                )
            };
            assert_eq!(call(&mut ctx, 0, 0), Ok(Rv::one(0)));
            assert_eq!(call(&mut ctx, 0, 1), Err(Errno::EFAULT));
            let mut expected = [0; 48];
            expected[..4].copy_from_slice(&0x1234u32.to_le_bytes());
            expected[16..20].copy_from_slice(&4u32.to_le_bytes());
            expected[36..40].copy_from_slice(&SESSION_ID.to_le_bytes());
            for length in [0, 1, 37, 48, 64] {
                ctx.write(output, &[0xa5; 64]).unwrap();
                assert_eq!(call(&mut ctx, output, length), Ok(Rv::one(0)));
                let bytes = ctx.read(output, 64).unwrap();
                let copied = (length as usize).min(expected.len());
                assert_eq!(&bytes[..copied], &expected[..copied]);
                assert!(bytes[copied..].iter().all(|&byte| byte == 0xa5));
            }
            for operation in [nr::AUDITON, nr::SETAUDIT_ADDR] {
                assert_eq!(bsd::call(&mut ctx, operation, &[0; 8]), Err(Errno::EPERM));
            }
        }
    }
}
