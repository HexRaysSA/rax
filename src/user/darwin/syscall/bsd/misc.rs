//! Process attributes, entropy, time, code signing, policy, and tracing
//! calls.

use crate::user::darwin::abi::Errno;
use crate::user::darwin::abi::types::Timeval;
#[cfg(unix)]
use crate::user::darwin::abi::types::rusage_bytes;
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
/// for the guest get the guest's mask. Embedded processes change only
/// their own mask.
pub fn umask(ctx: &mut Ctx<'_>, mask: u32) -> SysResult {
    let old = ctx.proc.umask;
    ctx.proc.umask = mask & 0o777;
    #[cfg(unix)]
    if ctx.proc.config.host_services {
        // SAFETY: umask takes no pointers.
        unsafe { libc::umask(ctx.proc.umask as libc::mode_t) };
    }
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
#[cfg(unix)]
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

/// `gethostuuid(uuid_buf, timeoutp)` (`sys_generic.c`): the machine's
/// UUID, the host's; the timeout is read first (`EFAULT`), and without a
/// UUID the call fails `EWOULDBLOCK`.
pub fn gethostuuid(ctx: &mut Ctx<'_>, buf: u64, timeout: u64) -> SysResult {
    let t = ctx.read(timeout, 16)?;
    let sec = i64::from_le_bytes(t[0..8].try_into().expect("8 bytes"));
    let nsec = i64::from_le_bytes(t[8..16].try_into().expect("8 bytes"));
    #[cfg(target_os = "macos")]
    let uuid = {
        let ts = libc::timespec {
            tv_sec: sec as libc::time_t,
            tv_nsec: nsec as libc::c_long,
        };
        let mut u = [0u8; 16];
        // SAFETY: `u` holds a uuid_t and `ts` is a live timespec.
        (unsafe { libc::gethostuuid(u.as_mut_ptr(), &ts) } == 0).then_some(u)
    };
    #[cfg(not(target_os = "macos"))]
    let uuid: Option<[u8; 16]> = {
        let _ = (sec, nsec);
        None
    };
    let u = uuid.ok_or(Errno::EWOULDBLOCK)?;
    ctx.write(buf, &u)?;
    Ok(Rv::one(0))
}

/// `kdebug_trace*`, `kdebug_typefilter`: tracing is disabled (the
/// commpage's kdebug word is zero), so events are dropped.
pub fn kdebug(_ctx: &mut Ctx<'_>) -> SysResult {
    Ok(Rv::one(0))
}

/// `csrctl` operations (`CSR_SYSCALL_*`).
mod csr {
    pub const CHECK: u32 = 0;
    pub const GET_ACTIVE_CONFIG: u32 = 1;
    pub const ALLOW_UNTRUSTED_KEXTS: u32 = 1 << 0;
    pub const ALLOW_KERNEL_DEBUGGER: u32 = 1 << 3;
    pub const ALLOW_APPLE_INTERNAL: u32 = 1 << 4;
    pub const ALLOW_DEVICE_CONFIGURATION: u32 = 1 << 7;
    /// `CSR_VALID_FLAGS`.
    pub const VALID_FLAGS: u32 = 0x1fff;
}

/// The machine's System Integrity Protection configuration
/// (`csr_get_active_config`): the host's on a macOS host, else fully
/// enabled (no exceptions).
fn csr_active_config() -> u32 {
    #[cfg(target_os = "macos")]
    {
        let mut config: u32 = 0;
        // SAFETY: csrctl(CSR_SYSCALL_GET_ACTIVE_CONFIG) writes 4 bytes to
        // `config`, whose address and size it is given.
        let r = unsafe {
            libc::syscall(
                483,
                csr::GET_ACTIVE_CONFIG,
                &mut config as *mut u32,
                std::mem::size_of::<u32>(),
            )
        };
        if r == 0 {
            return config & csr::VALID_FLAGS;
        }
    }
    0
}

/// `csrctl(op, useraddr, usersize)`: the SIP configuration, or whether it
/// allows every flag of a mask (`EPERM` if not). With SIP off
/// (`CSR_ALLOW_UNTRUSTED_KEXTS` or `CSR_ALLOW_APPLE_INTERNAL`) the kernel
/// debugger is allowed too; on an Intel Mac device configuration needs the
/// configuration boot mode, which a running system is not in.
pub fn csrctl(ctx: &mut Ctx<'_>, op: u32, addr: u64, size: u64) -> SysResult {
    let intel = ctx.proc.abi == crate::user::darwin::abi::DarwinAbi::X86_64;
    match op {
        csr::CHECK | csr::GET_ACTIVE_CONFIG => {}
        _ => return Err(Errno::ENOSYS),
    }
    if addr == 0 || size != 4 {
        return Err(Errno::EINVAL);
    }
    let mut config = csr_active_config();
    if op == csr::GET_ACTIVE_CONFIG {
        ctx.write(addr, &config.to_le_bytes())?;
        return Ok(Rv::one(0));
    }
    let b = ctx.read(addr, 4)?;
    let mask = u32::from_le_bytes(b.try_into().expect("4 bytes"));
    if intel && mask & csr::ALLOW_DEVICE_CONFIGURATION != 0 {
        return Err(Errno::EPERM);
    }
    if config & (csr::ALLOW_UNTRUSTED_KEXTS | csr::ALLOW_APPLE_INTERNAL) != 0 {
        config |= csr::ALLOW_KERNEL_DEBUGGER;
    }
    if config & mask == mask {
        Ok(Rv::one(0))
    } else {
        Err(Errno::EPERM)
    }
}

/// `CROSSARCH_MAX_VALID_NAMESPACE` (`CROSSARCH_ROSETTA`).
const CROSSARCH_MAX_VALID_NAMESPACE: u32 = 0;

/// `crossarch_trap(name)`: no cross-architecture service is provided to
/// a process (`ENOTSUP`); an unknown namespace is `EINVAL`.
pub fn crossarch_trap(name: u32) -> SysResult {
    if name > CROSSARCH_MAX_VALID_NAMESPACE {
        return Err(Errno::EINVAL);
    }
    Err(Errno::ENOTSUP)
}
