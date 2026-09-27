//! The system calls of an ARM EABI compatibility task on arm64
//! (`arch/arm64/tools/syscall_32.tbl`, `CONFIG_COMPAT`).
//!
//! arm64's compat table gives most calls the entry points i386's gives
//! them, and [`super::call`] runs those. This module runs first and takes
//! the calls whose ARM conversion differs:
//!
//! - the `aarch32_*` wrappers (`arch/arm64/kernel/sys32.c`): a 64-bit
//!   argument in an even/odd register pair, after a pad for `pread64`,
//!   `pwrite64`, `truncate64`, `ftruncate64`, and `readahead`; the
//!   reordered `arm_fadvise64_64` and `arm_sync_file_range`; and
//!   `statfs64`'s OABI size fixup (88 is taken as 84);
//! - the calls i386 reaches only through `socketcall` or `ipc`: `accept`,
//!   `send`, `recv`, `semop`, `semtimedop` (`time32`), and the
//!   `ipc_parse_version` forms of `semctl`, `msgctl`, and `shmctl`
//!   (`compat_sys_old_*`, `CONFIG_ARCH_WANT_COMPAT_IPC_PARSE_VERSION`);
//! - the numbers past the table, the ARM private calls among them
//!   (`compat_arm_syscall`, `arch/arm64/kernel/sys_compat.c`).
//!
//! The handlers choose the EABI layouts, whose 64-bit fields are 8-byte
//! aligned (`struct stat64`, `struct compat_flock64`), from the task's ABI,
//! as they choose `COMPAT_SHMLBA` for `shmat`.

use super::super::super::abi::Sysno as S;
use super::super::super::abi::errno::Errno;
use super::super::super::abi::errno_table::*;
use super::super::super::abi::syscalls::ARM_TABLE;
use super::super::super::signal::deliver::{ForceMode, force_signal};
use super::super::super::signal::frame::FaultUpdate;
use super::super::super::signal::{SIGILL, SigInfo, code};
use super::super::{Ctx, Outcome, SysResult, call_handler, io, path};
use super::file::{self, dual};
use super::ipc;
use super::stat::{self, FsOf};

/// `__ARM_NR_COMPAT_BASE`: the ARM private calls' base.
pub const ARM_NR_BASE: u32 = 0x0f_0000;
/// `__ARM_NR_compat_cacheflush`.
pub const ARM_NR_CACHEFLUSH: u32 = ARM_NR_BASE + 2;
/// `__ARM_NR_compat_set_tls`.
pub const ARM_NR_SET_TLS: u32 = ARM_NR_BASE + 5;
/// `__ARM_NR_COMPAT_END`: numbers below it are `ENOSYS` when unknown.
pub const ARM_NR_END: u32 = ARM_NR_BASE + 0x800;

/// `__NR_compat32_syscalls`: one past the table's highest number
/// (`scripts/syscallhdr.sh`), the first number `invoke_syscall` hands to
/// `do_ni_syscall`.
pub fn compat32_syscalls() -> u64 {
    ARM_TABLE.last().map_or(0, |&(nr, _)| nr + 1)
}

/// Runs call `s` where its ARM conversion differs from i386's; `None` for
/// the others.
pub(super) fn call(c: &mut Ctx<'_>, s: S, a: [u64; 6]) -> Option<Result<Outcome, Errno>> {
    let r = |v: SysResult| Some(v.map(Outcome::Return));
    let fd = |x: u64| x as i32;
    match s {
        // compat_sys_aarch32_*: the pair after a pad.
        S::Pread64 => r(io::pread(c, fd(a[0]), a[1], a[2], dual(a[4], a[5]))),
        S::Pwrite64 => r(io::pwrite(c, fd(a[0]), a[1], a[2], dual(a[4], a[5]))),
        S::Truncate64 => r(path::truncate(c, a[0], dual(a[2], a[3]))),
        S::Ftruncate64 => r(file::ftruncate(c, fd(a[0]), dual(a[2], a[3]))),
        S::Readahead => r(io::readahead(c, fd(a[0]))),
        // (fd, advice, offset, len) and (fd, flags, offset, nbytes).
        S::ArmFadvise6464 => r(io::fadvise(c, fd(a[0]), dual(a[4], a[5]), a[1] as u32)),
        S::ArmSyncFileRange => r(io::sync_file_range(
            c,
            fd(a[0]),
            dual(a[2], a[3]),
            dual(a[4], a[5]),
            a[1] as u32,
        )),
        S::Statfs64 => r(stat::statfs64(
            c,
            FsOf::Path(a[0]),
            statfs64_size(a[1]),
            a[2],
        )),
        S::Fstatfs64 => r(stat::statfs64(
            c,
            FsOf::Fd(fd(a[0])),
            statfs64_size(a[1]),
            a[2],
        )),
        // sys_accept, sys_send, and compat_sys_recv: accept4, sendto, and
        // recvfrom without flags or an address.
        S::Accept => Some(call_handler(c, S::Accept4, [a[0], a[1], a[2], 0, 0, 0])),
        S::Send => Some(call_handler(c, S::Sendto, [a[0], a[1], a[2], a[3], 0, 0])),
        S::Recv => Some(call_handler(c, S::Recvfrom, [a[0], a[1], a[2], a[3], 0, 0])),
        // System V IPC's direct calls.
        S::Semop => Some(call_handler(c, S::Semop, a)),
        S::Semtimedop => {
            c.time32 = true;
            Some(call_handler(c, S::Semtimedop, a))
        }
        S::Semctl => {
            let (cmd, v64) = ipc::parse_version(a[2] as i32);
            r(ipc::semctl(c, fd(a[0]), fd(a[1]), cmd, a[3], v64))
        }
        S::Msgctl => {
            let (cmd, v64) = ipc::parse_version(a[1] as i32);
            r(ipc::msgctl(c, fd(a[0]), cmd, a[2], v64))
        }
        S::Shmctl => {
            let (cmd, v64) = ipc::parse_version(a[1] as i32);
            r(ipc::shmctl(c, fd(a[0]), cmd, a[2], v64))
        }
        _ => None,
    }
}

/// `compat_sys_aarch32_statfs64`: 88, the EABI `struct statfs64`'s size
/// without the packing the OABI kernel applied, is taken as 84.
fn statfs64_size(size: u64) -> u64 {
    match size as u32 {
        88 => 84,
        n => u64::from(n),
    }
}

/// `do_ni_syscall` → `compat_arm_syscall`, for a number `nr` at or past
/// [`compat32_syscalls`]: `cacheflush` and `set_tls`; `ENOSYS` below
/// [`ARM_NR_END`] (and for a number that is negative as an `int`); past
/// it, `SIGILL` (`ILL_ILLTRP` at the `SVC`) and a result of 0.
pub fn past_table(c: &mut Ctx<'_>, nr: u64, a: [u64; 6]) -> Result<Outcome, Errno> {
    let scno = nr as u32;
    match scno {
        ARM_NR_CACHEFLUSH => cacheflush(c, a[0] as u32, a[1] as u32, a[2] as u32),
        ARM_NR_SET_TLS => {
            c.t.cpu.set_thread_pointer(u64::from(a[0] as u32));
            Ok(Outcome::Return(0))
        }
        _ if (scno as i32) < ARM_NR_END as i32 => Err(Errno(ENOSYS)),
        _ => {
            let pc = c.t.cpu.pc() - c.t.cpu.syscall_insn_len();
            c.t.fault.apply(FaultUpdate::Arm64 { address: 0, esr: 0 });
            let info = SigInfo::fault(SIGILL, code::ILL_ILLTRP, pc);
            let (p, mut th) = c.split();
            force_signal(p, &mut th, info, ForceMode::Current);
            Ok(Outcome::Return(0))
        }
    }
}

/// `do_compat_cache_op`: `EINVAL` for an end below the start or nonzero
/// flags; then `caches_clean_inval_user_pou` over the range, which faults
/// (`EFAULT`) on a page that is not mapped readable. The emulated core
/// caches no code, so nothing else is done.
fn cacheflush(c: &mut Ctx<'_>, start: u32, end: u32, flags: u32) -> Result<Outcome, Errno> {
    if end < start || flags != 0 {
        return Err(Errno(EINVAL));
    }
    let page = super::super::super::abi::PAGE_SIZE;
    let mut at = u64::from(start) & !(page - 1);
    while at < u64::from(end) {
        let mut b = [0u8; 1];
        c.p.space
            .read(at.max(u64::from(start)), &mut b)
            .map_err(|_| Errno(EFAULT))?;
        at += page;
    }
    Ok(Outcome::Return(0))
}
