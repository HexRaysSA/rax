//! File calls of a compatibility task whose offsets or structures differ
//! from the native ones: 64-bit offsets passed in two registers, low half
//! first (`arch/x86/kernel/sys_ia32.c`, the `compat_sys_p{read,write}v*`
//! of `fs/read_write.c`), 32-bit `compat_off_t` offsets
//! (`compat_sys_lseek`, `compat_sys_truncate`, `compat_sys_ftruncate`,
//! `compat_sys_sendfile`), `_llseek`, and `fcntl`'s `struct compat_flock`
//! and `struct compat_flock64` (`do_compat_fcntl64`, `fs/fcntl.c`).

use super::super::super::abi::errno::Errno;
use super::super::super::abi::errno_table::*;
use super::super::super::abi::types::MAX_NON_LFS;
use super::super::super::fs::locks::Owner;
use super::super::copy::{self, SendfileOffset};
use super::super::io;
use super::super::locks::{self, FlockLayout};
use super::super::{Ctx, SysResult};

/// A 64-bit value passed in two 32-bit registers, low half first.
pub fn dual(lo: u64, hi: u64) -> i64 {
    (u64::from(hi as u32) << 32 | u64::from(lo as u32)) as i64
}

/// A `compat_off_t` (or other `compat_long_t`) argument: the register's
/// 32 bits, sign-extended.
pub fn sext(v: u64) -> i64 {
    i64::from(v as u32 as i32)
}

/// `compat_sys_lseek`: the offset sign-extended; the result, a 64-bit
/// `off_t` in the kernel, reaches the caller in its 32-bit register.
pub fn lseek(c: &mut Ctx<'_>, fd: i32, off: u64, whence: u32) -> SysResult {
    io::lseek(c, fd, sext(off), whence)
}

/// `SEEK_MAX` (`SEEK_HOLE`).
const SEEK_MAX: u32 = 4;

/// `_llseek` (`sys_llseek`): the offset from two registers, the new
/// position stored as a `loff_t` at `result`.
pub fn llseek(c: &mut Ctx<'_>, fd: i32, hi: u64, lo: u64, result: u64, whence: u32) -> SysResult {
    // fd_pos, then the whence check, then vfs_llseek.
    c.p.fds.file(fd)?;
    if whence > SEEK_MAX {
        return Err(Errno(EINVAL));
    }
    let pos = io::lseek(c, fd, dual(lo, hi), whence)?;
    c.write_u64(result, pos)?;
    Ok(0)
}

/// `do_sys_ftruncate` with `small` set, as `compat_sys_ftruncate` and
/// `sys_ia32_ftruncate64` (`ksys_ftruncate`) call it: a file opened
/// without `O_LARGEFILE` cannot be made longer than `MAX_NON_LFS`
/// (`EINVAL`).
pub fn ftruncate(c: &mut Ctx<'_>, fd: i32, len: i64) -> SysResult {
    if len < 0 {
        return Err(Errno(EINVAL));
    }
    let file = c.p.fds.file(fd)?;
    if file.flags() & c.p.abi.open_flags().largefile == 0 && len > MAX_NON_LFS {
        return Err(Errno(EINVAL));
    }
    io::ftruncate(c, fd, len)
}

/// `compat_sys_sendfile` (a `compat_off_t` offset) and `sendfile64` (a
/// `loff_t` one).
pub fn sendfile(c: &mut Ctx<'_>, a: [u64; 6], width: SendfileOffset) -> SysResult {
    let count = u64::from(a[3] as u32);
    copy::sendfile_as(c, a[0] as i32, a[1] as i32, a[2], count, width)
}

/// `fcntl` commands with a compatibility structure (i386 numbering).
mod cmd {
    pub const F_GETLK: u32 = 5;
    pub const F_SETLK: u32 = 6;
    pub const F_SETLKW: u32 = 7;
    pub const F_GETLK64: u32 = 12;
    pub const F_SETLK64: u32 = 13;
    pub const F_SETLKW64: u32 = 14;
    pub const F_OFD_GETLK: u32 = 36;
    pub const F_OFD_SETLK: u32 = 37;
    pub const F_OFD_SETLKW: u32 = 38;
}

/// `compat_sys_fcntl64` and (`is64` false) `compat_sys_fcntl`, which
/// refuses the commands of `struct compat_flock64` (`EINVAL`) before it
/// looks at the descriptor. The record-lock commands convert their
/// structure; every other command is the native one.
pub fn fcntl(c: &mut Ctx<'_>, fd: i32, command: u32, arg: u64, is64: bool) -> SysResult {
    use cmd::*;
    use locks::{getlk, setlk};
    let (process, ofd) = (Owner::Process, Owner::Description);
    let (short, long) = (FlockLayout::Compat, FlockLayout::Compat64);
    match command {
        F_GETLK64 | F_SETLK64 | F_SETLKW64 | F_OFD_GETLK | F_OFD_SETLK | F_OFD_SETLKW if !is64 => {
            Err(Errno(EINVAL))
        }
        F_GETLK => getlk(c, fd, arg, process, short),
        F_GETLK64 => getlk(c, fd, arg, process, long),
        F_OFD_GETLK => getlk(c, fd, arg, ofd, long),
        F_SETLK | F_SETLKW => setlk(c, fd, arg, process, command == F_SETLKW, short),
        F_SETLK64 | F_SETLKW64 => setlk(c, fd, arg, process, command == F_SETLKW64, long),
        F_OFD_SETLK | F_OFD_SETLKW => setlk(c, fd, arg, ofd, command == F_OFD_SETLKW, long),
        _ => super::super::fcntl::fcntl(c, fd, command, arg),
    }
}
