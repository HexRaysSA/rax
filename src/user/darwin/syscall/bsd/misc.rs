//! Process attributes, entropy, time, code signing, policy, and tracing
//! calls.

use crate::user::darwin::abi::Errno;
use crate::user::darwin::abi::types::{Timeval, rusage_bytes};
use crate::user::darwin::arch::{Rv, SysResult};
use crate::user::darwin::syscall::Ctx;

/// `GETENTROPY_MAX`.
const GETENTROPY_MAX: u64 = 256;

/// `getentropy(buffer, size)`.
pub fn getentropy(ctx: &mut Ctx<'_>, buf: u64, size: u64) -> SysResult {
    if size > GETENTROPY_MAX {
        return Err(Errno::EINVAL);
    }
    let mut b = vec![0u8; size as usize];
    ctx.proc.entropy.fill(&mut b);
    ctx.write(buf, &b)?;
    Ok(Rv::one(0))
}

/// `getrlimit(which, rlp)`.
pub fn getrlimit(ctx: &mut Ctx<'_>, which: u32, rlp: u64) -> SysResult {
    // _RLIMIT_POSIX_FLAG is ignored for reads.
    let which = (which & !0x1000) as usize;
    let (cur, max) = *ctx.proc.rlimits.get(which).ok_or(Errno::EINVAL)?;
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&cur.to_le_bytes());
    b[8..].copy_from_slice(&max.to_le_bytes());
    ctx.write(rlp, &b)?;
    Ok(Rv::one(0))
}

/// `setrlimit(which, rlp)`.
pub fn setrlimit(ctx: &mut Ctx<'_>, which: u32, rlp: u64) -> SysResult {
    let which = (which & !0x1000) as usize;
    if which >= ctx.proc.rlimits.len() {
        return Err(Errno::EINVAL);
    }
    let b = ctx.read(rlp, 16)?;
    let cur = u64::from_le_bytes(b[..8].try_into().expect("8 bytes"));
    let max = u64::from_le_bytes(b[8..].try_into().expect("8 bytes"));
    if cur > max {
        return Err(Errno::EINVAL);
    }
    let (_, old_max) = ctx.proc.rlimits[which];
    // Raising the hard limit needs privilege.
    if max > old_max && ctx.proc.creds.1 != 0 {
        return Err(Errno::EPERM);
    }
    ctx.proc.rlimits[which] = (cur, max);
    Ok(Rv::one(0))
}

/// `umask(newmask)`: the host's mask follows, so files the host creates
/// for the guest get the guest's mask.
pub fn umask(ctx: &mut Ctx<'_>, mask: u32) -> SysResult {
    let old = ctx.proc.umask;
    ctx.proc.umask = mask & 0o777;
    // SAFETY: umask takes no pointers.
    unsafe { libc::umask(ctx.proc.umask as libc::mode_t) };
    Ok(Rv::one(u64::from(old)))
}

/// `gettimeofday(tp, tzp, mach_absolute_time)`.
pub fn gettimeofday(ctx: &mut Ctx<'_>, tp: u64, tzp: u64, abs: u64) -> SysResult {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let mach = super::super::mach::absolute_time(ctx.proc.abi);
    if tp != 0 {
        // tv_sec passes through uint32_t, as on arm64's commpage.
        let tv = Timeval {
            sec: i64::from(now.as_secs() as u32),
            usec: now.subsec_micros() as i32,
        };
        ctx.write(tp, &tv.bytes())?;
    }
    if tzp != 0 {
        // struct timezone { tz_minuteswest, tz_dsttime }: the kernel's is
        // zero.
        ctx.write(tzp, &[0u8; 8])?;
    }
    if abs != 0 {
        ctx.write(abs, &mach.to_le_bytes())?;
    }
    Ok(Rv::one(0))
}

/// `getrusage(who, rusage)`.
pub fn getrusage(ctx: &mut Ctx<'_>, who: i32, out: u64) -> SysResult {
    // RUSAGE_SELF (0) and RUSAGE_CHILDREN (-1).
    let hw = match who {
        0 => libc::RUSAGE_SELF,
        -1 => libc::RUSAGE_CHILDREN,
        _ => return Err(Errno::EINVAL),
    };
    // SAFETY: getrusage writes a complete struct on success.
    let r = unsafe {
        let mut r: libc::rusage = std::mem::zeroed();
        crate::user::darwin::host::check(libc::getrusage(hw, &mut r))?;
        r
    };
    ctx.write(out, &rusage_bytes(&r))?;
    Ok(Rv::one(0))
}

/// Code-signing status flags (`bsd/sys/codesign.h`).
pub mod cs {
    pub const CS_VALID: u32 = 0x0000_0001;
    pub const CS_ADHOC: u32 = 0x0000_0002;
    pub const CS_LINKER_SIGNED: u32 = 0x0002_0000;
    pub const CS_SIGNED: u32 = 0x2000_0000;
}

/// `csops(pid, ops, useraddr, usersize)` and `csops_audittoken`.
pub fn csops(ctx: &mut Ctx<'_>, pid: i32, ops: u32, addr: u64, size: u64) -> SysResult {
    const CS_OPS_STATUS: u32 = 0;
    const CS_OPS_CDHASH: u32 = 5;
    const CS_OPS_PIDOFFSET: u32 = 6;
    const CS_OPS_ENTITLEMENTS_BLOB: u32 = 7;
    const CS_OPS_IDENTITY: u32 = 11;
    const CS_OPS_TEAMID: u32 = 14;
    const CS_OPS_DER_ENTITLEMENTS_BLOB: u32 = 16;
    if pid != 0 && pid != ctx.proc.pid {
        return Err(Errno::ESRCH);
    }
    match ops {
        CS_OPS_STATUS => {
            if size < 4 {
                return Err(Errno::EINVAL);
            }
            let flags = cs::CS_VALID | cs::CS_ADHOC | cs::CS_LINKER_SIGNED | cs::CS_SIGNED;
            ctx.write(addr, &flags.to_le_bytes())?;
            Ok(Rv::one(0))
        }
        CS_OPS_PIDOFFSET => {
            ctx.write(addr, &0u64.to_le_bytes())?;
            Ok(Rv::one(0))
        }
        // No embedded entitlements, identity, or team.
        CS_OPS_ENTITLEMENTS_BLOB
        | CS_OPS_DER_ENTITLEMENTS_BLOB
        | CS_OPS_IDENTITY
        | CS_OPS_TEAMID
        | CS_OPS_CDHASH => Err(Errno::ENOENT),
        _ => Err(Errno::EINVAL),
    }
}

/// AMFI's dyld policy call (`amfi_check_dyld_policy_self` through
/// `__mac_syscall("AMFI", 0x5a, {in_flags, out_ptr})`).
const AMFI_CHECK_DYLD_POLICY_SELF: i32 = 0x5a;

/// AMFI output flags granted to programs: `@`-paths, `DYLD_*` path and
/// print variables, fallback paths, failed insertion, and interposing (an
/// unrestricted, unsigned-developer process).
const AMFI_DYLD_OUTPUT: u64 = (1 << 0) | (1 << 1) | (1 << 3) | (1 << 4) | (1 << 5) | (1 << 6);

/// `__mac_syscall(policy, call, arg)`.
pub fn mac_syscall(ctx: &mut Ctx<'_>, policy: u64, call: i32, arg: u64) -> SysResult {
    let name = ctx.cstr(policy, 32)?;
    match (name.as_slice(), call) {
        (b"AMFI", AMFI_CHECK_DYLD_POLICY_SELF) => {
            let out = ctx.read_u64(arg + 8)?;
            ctx.write_u64(out, AMFI_DYLD_OUTPUT)?;
            Ok(Rv::one(0))
        }
        // No policy module answers: ENOSYS, as mac_syscall reports an
        // unregistered policy.
        _ => Err(Errno::ENOSYS),
    }
}

/// `kdebug_trace*`, `kdebug_typefilter`: tracing is disabled (the
/// commpage's kdebug word is zero), so events are dropped.
pub fn kdebug(_ctx: &mut Ctx<'_>) -> SysResult {
    Ok(Rv::one(0))
}
