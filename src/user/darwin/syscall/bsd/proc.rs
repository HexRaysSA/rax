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
