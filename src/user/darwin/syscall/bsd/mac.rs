//! `__mac_syscall(policy, call, arg)`: calls into the kernel's policy
//! modules (`security/mac_base.c`).
//!
//! The guest's process is the host's, which runs no sandbox and no
//! policy the emulator stands in for: AMFI's dyld policy is answered for
//! an unrestricted process, and the Sandbox policy's checks and container
//! queries are the host's answers about the same process (or another),
//! with the guest's memory the arguments name copied through. A policy's
//! other calls are refused as a registered policy refuses a call it does
//! not know (`ENOTSUP`), and a policy the host has not registered as the
//! kernel refuses one (`ENOPOLICY`).

use crate::user::darwin::abi::Errno;
use crate::user::darwin::arch::{Rv, SysResult};
use crate::user::darwin::syscall::Ctx;

/// AMFI's dyld policy call (`amfi_check_dyld_policy_self` through
/// `__mac_syscall("AMFI", 0x5a, {in_flags, out_ptr})`).
const AMFI_CHECK_DYLD_POLICY_SELF: i32 = 0x5a;

/// AMFI output flags granted to programs: `@`-paths, `DYLD_*` path and
/// print variables, fallback paths, failed insertion, and interposing (an
/// unrestricted, unsigned-developer process).
const AMFI_DYLD_OUTPUT: u64 = (1 << 0) | (1 << 1) | (1 << 3) | (1 << 4) | (1 << 5) | (1 << 6);

/// The Sandbox policy's calls the emulator passes to the host.
mod sandbox {
    /// `sandbox_check` and its variants: a 128-byte argument block.
    pub const CHECK: i32 = 2;
    /// `sandbox_container_path_for_pid`: pid, buffer, size.
    pub const CONTAINER_PATH: i32 = 4;
    /// The check's argument block.
    pub const CHECK_SIZE: usize = 0x80;
    /// Its fields: where the result goes, the operation's name, the filter
    /// type the kernel reads, and the filter's value.
    pub const RESULT: usize = 0x00;
    pub const OPERATION: usize = 0x10;
    pub const FILTER_TYPE: usize = 0x18;
    pub const FILTER: usize = 0x20;
    /// The kernel filter types (as `sandbox_check_common` maps the
    /// library's) whose value points at a string: a path (1), a name.
    pub const STRING_FILTERS: &[u64] = &[
        0x01, 0x05, 0x06, 0x07, 0x13, 0x19, 0x1b, 0x1c, 0x21, 0x22, 0x2d, 0x32, 0x45,
    ];
    /// Filter types whose value points at a 16-byte block on the caller's
    /// stack: a pointer-sized value and an integer (0x23), or two values
    /// (0xf1). The integer ones (0x34, 0x41, 0x4b, 0x6a, 0xf0) are values.
    pub const BLOCK_FILTERS: &[u64] = &[0x23, 0xf1];
    /// The block filter whose first field may point at a string.
    pub const NAMED_BLOCK: u64 = 0x23;
}

/// The host's `__mac_syscall` (no policy is registered without a macOS
/// host).
fn host(policy: &std::ffi::CStr, call: i32, arg: *mut std::ffi::c_void) -> Result<i32, Errno> {
    #[cfg(target_os = "macos")]
    {
        unsafe extern "C" {
            fn __mac_syscall(policy: *const libc::c_char, call: i32, arg: *mut libc::c_void)
            -> i32;
        }
        // SAFETY: `arg` is null or points at the block the call reads and
        // writes, which the caller keeps alive.
        let r = unsafe { __mac_syscall(policy.as_ptr(), call, arg) };
        if r < 0 { Err(Errno::last()) } else { Ok(r) }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (policy, call, arg);
        Err(Errno::ENOPOLICY)
    }
}

/// `__mac_syscall(policy, call, arg)`.
pub fn mac_syscall(ctx: &mut Ctx<'_>, policy: u64, call: i32, arg: u64) -> SysResult {
    let name = ctx.cstr(policy, 32)?;
    if ctx.proc.config.strace {
        eprintln!(
            "[{:#x}]   __mac_syscall policy {:?} call {call}",
            ctx.thread.tid,
            String::from_utf8_lossy(&name)
        );
    }
    match (name.as_slice(), call) {
        (b"AMFI", AMFI_CHECK_DYLD_POLICY_SELF) => {
            let out = ctx.read_u64(arg + 8)?;
            ctx.write_u64(out, AMFI_DYLD_OUTPUT)?;
            Ok(Rv::one(0))
        }
        (b"Sandbox", sandbox::CHECK) => check(ctx, arg),
        (b"Sandbox", sandbox::CONTAINER_PATH) => container_path(ctx, arg),
        _ => {
            // Whether the host has the policy: an unknown call to it says.
            let c = std::ffi::CString::new(name).map_err(|_| Errno::EINVAL)?;
            match host(&c, i32::MAX, std::ptr::null_mut()) {
                Err(Errno::ENOPOLICY) => Err(Errno::ENOPOLICY),
                _ => Err(Errno::ENOTSUP),
            }
        }
    }
}

/// A guest string argument copied for the host (null stays null).
fn string(ctx: &Ctx<'_>, addr: u64) -> Result<Option<std::ffi::CString>, Errno> {
    if addr == 0 {
        return Ok(None);
    }
    let s = ctx.cstr(addr, 4096)?;
    Ok(Some(std::ffi::CString::new(s).map_err(|_| Errno::EINVAL)?))
}

/// `sandbox_check`: the host's answer, the block's pointers made the
/// host's copies of what they point at, the result written back.
fn check(ctx: &mut Ctx<'_>, arg: u64) -> SysResult {
    use sandbox::*;
    let mut block = ctx.read(arg, CHECK_SIZE)?;
    let field = |b: &[u8], o: usize| u64::from_le_bytes(b[o..o + 8].try_into().expect("8 bytes"));
    let result_at = field(&block, RESULT);
    let operation = string(ctx, field(&block, OPERATION))?;
    let kind = field(&block, FILTER_TYPE);
    let value = field(&block, FILTER);
    let filter_string = if STRING_FILTERS.contains(&kind) {
        string(ctx, value)?
    } else {
        None
    };
    let mut filter_block = [0u8; 16];
    let mut block_string = None;
    if BLOCK_FILTERS.contains(&kind) && value != 0 {
        ctx.read_into(value, &mut filter_block)?;
        let first = field(&filter_block, 0);
        if kind == NAMED_BLOCK && first != 0 {
            // A string when it points at one, else a value.
            block_string = string(ctx, first).ok().flatten();
            if let Some(s) = &block_string {
                filter_block[0..8].copy_from_slice(&(s.as_ptr() as u64).to_le_bytes());
            }
        }
    }
    let mut result = 0u64;
    let put = |b: &mut [u8], o: usize, v: u64| b[o..o + 8].copy_from_slice(&v.to_le_bytes());
    put(&mut block, RESULT, &mut result as *mut u64 as u64);
    put(
        &mut block,
        OPERATION,
        operation.as_ref().map_or(0, |s| s.as_ptr() as u64),
    );
    if let Some(s) = &filter_string {
        put(&mut block, FILTER, s.as_ptr() as u64);
    } else if BLOCK_FILTERS.contains(&kind) && value != 0 {
        put(&mut block, FILTER, filter_block.as_ptr() as u64);
    }
    let r = host(c"Sandbox", CHECK, block.as_mut_ptr().cast())?;
    if result_at != 0 {
        ctx.write_u64(result_at, result)?;
    }
    Ok(Rv::one(r as u64))
}

/// `sandbox_container_path_for_pid`: the host's answer, the path copied
/// into the guest's buffer.
fn container_path(ctx: &mut Ctx<'_>, arg: u64) -> SysResult {
    // pid, 0, buffer, size, 0.
    let mut block = ctx.read(arg, 40)?;
    let (buf, size) = (
        u64::from_le_bytes(block[16..24].try_into().expect("8 bytes")),
        u64::from_le_bytes(block[24..32].try_into().expect("8 bytes")),
    );
    let mut out = vec![0u8; (size as usize).min(1 << 16)];
    block[16..24].copy_from_slice(&(out.as_mut_ptr() as u64).to_le_bytes());
    block[24..32].copy_from_slice(&(out.len() as u64).to_le_bytes());
    let r = host(
        c"Sandbox",
        sandbox::CONTAINER_PATH,
        block.as_mut_ptr().cast(),
    )?;
    if buf != 0 {
        ctx.write(buf, &out)?;
    }
    Ok(Rv::one(r as u64))
}
