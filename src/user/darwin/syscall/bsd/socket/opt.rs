//! Socket options: `setsockopt` and `getsockopt`.

use super::sock;
use crate::user::darwin::abi::Errno;
use crate::user::darwin::arch::{Rv, SysResult};
use crate::user::darwin::host::check;
use crate::user::darwin::syscall::Ctx;

/// The most of an option value the host is given: more than any option
/// takes (the kernel copies only an option's own size of a longer
/// value, so a longer one is cut here without effect).
const OPT_MAX: u32 = 1 << 16;

/// `setsockopt(s, level, name, val, valsize)`: a NULL value with a size
/// faults before the descriptor is looked up.
pub fn setsockopt(
    ctx: &mut Ctx<'_>,
    fd: i32,
    level: i32,
    name: i32,
    val: u64,
    valsize: u32,
) -> SysResult {
    if val == 0 && valsize != 0 {
        return Err(Errno::EFAULT);
    }
    let (_, h) = sock(ctx, fd)?;
    let len = valsize.min(OPT_MAX);
    let buf = ctx.read(val, len as usize)?;
    let ptr = if val == 0 {
        std::ptr::null()
    } else {
        buf.as_ptr()
    };
    // SAFETY: `ptr` is NULL or holds `len` bytes.
    check(unsafe { libc::setsockopt(h, level, name, ptr.cast(), len) })?;
    Ok(Rv::one(0))
}

/// `getsockopt(s, level, name, val, avalsize)`: `*avalsize` is read only
/// with a value buffer (else the size is 0); the value is copied cut to
/// that size, and the size copied is written back (after the option's
/// effects, such as `SO_ERROR` clearing).
pub fn getsockopt(
    ctx: &mut Ctx<'_>,
    fd: i32,
    level: i32,
    name: i32,
    val: u64,
    avalsize: u64,
) -> SysResult {
    let (_, h) = sock(ctx, fd)?;
    let valsize = if val != 0 { ctx.read_u32(avalsize)? } else { 0 };
    let mut buf = vec![0u8; valsize.min(OPT_MAX) as usize];
    let mut len = buf.len() as libc::socklen_t;
    let ptr = if val == 0 {
        std::ptr::null_mut()
    } else {
        buf.as_mut_ptr()
    };
    // SAFETY: `ptr` is NULL (with a size of 0) or holds `len` bytes.
    check(unsafe { libc::getsockopt(h, level, name, ptr.cast(), &mut len) })?;
    let n = (len as usize).min(buf.len());
    ctx.write(val, &buf[..n])?;
    ctx.write_u32(avalsize, n as u32)?;
    Ok(Rv::one(0))
}
