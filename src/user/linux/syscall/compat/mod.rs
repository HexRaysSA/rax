//! The system calls of an i386 compatibility task
//! (`arch/x86/entry/syscalls/syscall_32.tbl` on an x86-64 kernel with
//! `CONFIG_IA32_EMULATION`).
//!
//! A call the table gives a native entry point whose arguments and memory
//! layouts are the same for a 32-bit caller goes to the native handler with
//! the registers as `do_int80_emulation` zero-extends them. A call with a
//! compatibility entry point (`compat_sys_*`, `sys_ia32_*`) or a 32-bit-only
//! one goes through its conversion here. Every other call is `ENOSYS`, so
//! none runs with 64-bit layouts on 32-bit memory.
//!
//! | Module | Contents |
//! |---|---|
//! | this one | the table and the calls without a module of their own |
//! | [`tls`] | `set_thread_area`, `get_thread_area` |

pub mod tls;

use super::super::abi::Sysno as S;
use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::{Ctx, Outcome, call_handler};

/// `PAGE_SHIFT`: `mmap2`'s offset unit.
const PAGE_SHIFT: u32 = 12;

/// Terminal `ioctl`s whose argument (an `int`, `struct termios`, or
/// `struct winsize`) has the same layout for a 32-bit caller
/// (`compat_sys_ioctl` passes them to the driver as they are).
const SAME_LAYOUT_IOCTLS: &[u32] = &[
    0x5401, // TCGETS
    0x5402, // TCSETS
    0x5403, // TCSETSW
    0x5404, // TCSETSF
    0x540F, // TIOCGPGRP
    0x5410, // TIOCSPGRP
    0x5413, // TIOCGWINSZ
    0x5414, // TIOCSWINSZ
    0x541B, // FIONREAD
    0x5421, // FIONBIO
    0x5450, // FIONCLEX
    0x5451, // FIOCLEX
];

/// Runs system call `s` of a compatibility task.
pub(super) fn call(c: &mut Ctx<'_>, s: S, a: [u64; 6]) -> Result<Outcome, Errno> {
    let r = |v: Result<u64, Errno>| v.map(Outcome::Return);
    match s {
        // The native entry points, the same for a 32-bit caller.
        S::Exit
        | S::ExitGroup
        | S::Read
        | S::Write
        | S::Close
        | S::Getpid
        | S::Gettid
        | S::Getppid
        | S::Brk
        | S::Munmap
        | S::Mprotect
        | S::Madvise
        | S::SetTidAddress
        | S::Dup
        | S::Dup2
        | S::Dup3
        | S::Kill
        | S::Tkill
        | S::Tgkill
        | S::Uname
        | S::SchedYield
        | S::Getrandom
        | S::Pipe
        | S::Pipe2
        | S::MemfdCreate
        // The vectors are read as `struct compat_iovec` (`iov`).
        | S::Readv
        | S::Writev => call_handler(c, s, a),
        // The 32-bit ID calls are the native ones.
        S::Getuid32 => call_handler(c, S::Getuid, a),
        S::Geteuid32 => call_handler(c, S::Geteuid, a),
        S::Getgid32 => call_handler(c, S::Getgid, a),
        S::Getegid32 => call_handler(c, S::Getegid, a),
        S::SetThreadArea => r(tls::set_thread_area(c, a[0])),
        S::GetThreadArea => r(tls::get_thread_area(c, a[0])),
        // sys_mmap_pgoff: the offset in pages.
        S::Mmap2 => {
            let mut native = a;
            native[5] = u64::from(a[5] as u32) << PAGE_SHIFT;
            call_handler(c, S::Mmap, native)
        }
        // compat_sys_ia32_mmap: the arguments in a struct mmap_arg_struct32.
        S::Mmap => {
            let b = c.read_mem(a[0], 24)?;
            let word = |i: usize| u64::from(u32::from_le_bytes(b[i * 4..i * 4 + 4].try_into().unwrap()));
            if word(5) & ((1 << PAGE_SHIFT) - 1) != 0 {
                return Err(Errno(EINVAL));
            }
            call_handler(c, S::Mmap, [word(0), word(1), word(2), word(3), word(4), word(5)])
        }
        S::Ioctl if SAME_LAYOUT_IOCTLS.contains(&(a[1] as u32)) => call_handler(c, s, a),
        // compat_sys_ioctl: a command without a 32-bit conversion.
        S::Ioctl => Err(Errno(ENOTTY)),
        _ => Err(Errno(ENOSYS)),
    }
}
