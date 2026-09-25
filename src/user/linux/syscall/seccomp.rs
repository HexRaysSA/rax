//! `seccomp`, `prctl(PR_SET_SECCOMP)`, and the check at system-call entry
//! (`kernel/seccomp.c`).
//!
//! A call is checked when it enters, before its handler runs, but not when
//! it runs again after sleeping: the kernel checks it once. Filters are
//! installed with `no_new_privs` or `CAP_SYS_ADMIN` (`EACCES` otherwise)
//! and pass the checks of [`bpf::check`] (`EINVAL` otherwise).
//! `SECCOMP_FILTER_FLAG_NEW_LISTENER` is refused (`EINVAL`, as by a kernel
//! without user notification): no filter has a listener, so
//! `SECCOMP_RET_USER_NOTIF` is `ENOSYS`, as the kernel makes it when the
//! listener has gone.

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::abi::{AUDIT_ARCH_I386, LinuxAbi, Sysno};
use super::super::seccomp::{self as sc, Verdict, bpf};
use super::super::signal::deliver::{ForceMode, force_signal};
use super::super::signal::{SIGKILL, SIGSYS, SigInfo};
use super::{Ctx, Outcome, SysResult};

/// `SECCOMP_SET_MODE_STRICT` and the other operations.
const SET_MODE_STRICT: u32 = 0;
const SET_MODE_FILTER: u32 = 1;
const GET_ACTION_AVAIL: u32 = 2;
const GET_NOTIF_SIZES: u32 = 3;
/// `SECCOMP_FILTER_FLAG_*`.
const FLAG_TSYNC: u32 = 1;
const FLAG_LOG: u32 = 2;
const FLAG_NEW_LISTENER: u32 = 8;
const FLAG_TSYNC_ESRCH: u32 = 16;
const FLAG_WAIT_KILLABLE_RECV: u32 = 32;
/// `SECCOMP_FILTER_FLAG_MASK`.
const FLAG_MASK: u32 = 0x3F;
/// `struct seccomp_notif`, `struct seccomp_notif_resp`, and
/// `struct seccomp_data` sizes (`struct seccomp_notif_sizes`).
const NOTIF_SIZES: [u16; 3] = [80, 24, bpf::SECCOMP_DATA as u16];
/// x86-64 `__NR_uretprobe` and `__NR_uprobe`: exempt from filters
/// (`seccomp_uprobe_exception`) and allowed in strict mode.
const X86_64_UPROBE_CALLS: [i32; 2] = [335, 336];
/// The i386 `mode1_syscalls_32`: read, write, exit, sigreturn.
const I386_STRICT: [i32; 4] = [3, 4, 1, 119];

/// How a call entered the kernel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Entry {
    /// The native ABI.
    Native,
    /// x86-64 `INT 0x80`: the i386 ABI.
    Compat,
}

/// `mode1_syscalls`: whether strict mode allows call `nr`.
fn strict_allows(abi: LinuxAbi, entry: Entry, nr: i32) -> bool {
    match entry {
        Entry::Compat => I386_STRICT.contains(&nr),
        Entry::Native => {
            (abi == LinuxAbi::X86_64 && X86_64_UPROBE_CALLS.contains(&nr))
                || u64::try_from(nr)
                    .ok()
                    .and_then(|n| abi.sysno(n))
                    .is_some_and(|s| {
                        matches!(
                            s,
                            Sysno::Read | Sysno::Write | Sysno::Exit | Sysno::RtSigreturn
                        )
                    })
        }
    }
}

/// `__secure_computing` for call `nr` of the calling thread: `None` lets
/// it run; otherwise the outcome that replaces it.
pub fn entry(
    c: &mut Ctx<'_>,
    nr: u64,
    args: [u64; 6],
    entry: Entry,
    recheck: bool,
) -> Option<Outcome> {
    let mode = c.t.seccomp.mode;
    if mode == sc::MODE_DISABLED {
        return None;
    }
    let abi = c.p.abi;
    let nr = nr as i32;
    let arch = match entry {
        Entry::Native => abi.audit_arch(),
        Entry::Compat => AUDIT_ARCH_I386,
    };
    if mode == sc::MODE_FILTER
        && entry == Entry::Native
        && abi == LinuxAbi::X86_64
        && X86_64_UPROBE_CALLS.contains(&nr)
    {
        return None;
    }
    let ip = c.t.cpu.pc();
    let verdict =
        c.t.seccomp
            .verdict(nr, arch, ip, args, |n| strict_allows(abi, entry, n));
    let sigsys = |datum: u16| SigInfo::seccomp(ip, nr, arch, i32::from(datum));
    match verdict {
        Verdict::Allow => None,
        Verdict::Errno(e) => Some(Outcome::Return((-i64::from(e)) as u64)),
        // SECCOMP_RET_TRACE: allowed when looked at again after the
        // tracer's stop; a stop for a tracer that asked for it; else no
        // call (ENOSYS).
        Verdict::Trace(_) if recheck => None,
        Verdict::Trace(datum) => {
            let traced = c.t.ptrace.as_ref().is_some_and(|tr| {
                tr.tracer >= 0 && tr.event_enabled(super::super::ptrace::EVENT_SECCOMP)
            });
            Some(if traced {
                Outcome::SeccompTrace(datum)
            } else {
                Outcome::Return(Errno(ENOSYS).as_return())
            })
        }
        Verdict::Trap(datum) => {
            // The handler sees the registers as they were
            // (syscall_rollback: the result register gets its entry value
            // back, which a traced thread's entry view replaced).
            if let Some(e) = c.t.syscall {
                let x86 = matches!(c.t.cpu, super::super::arch::GuestCpu::X86_64(_));
                c.t.cpu.set_syscall_result(if x86 { e.nr } else { e.arg0 });
            }
            let (p, mut th) = c.split();
            force_signal(p, &mut th, sigsys(datum), ForceMode::Current);
            Some(Outcome::Unchanged)
        }
        Verdict::KillThread(datum) | Verdict::KillProcess(datum) => {
            c.t.seccomp.mode = sc::MODE_DEAD;
            let last = c.peers.lo.is_empty() && c.peers.hi.is_empty();
            if matches!(verdict, Verdict::KillThread(_)) && !last {
                return Some(Outcome::KillThread(SIGSYS));
            }
            // force_sig_seccomp with HANDLER_EXIT: SIGSYS at its default
            // action, which dumps core. The disposition's SA_IMMUTABLE is
            // not modeled: the thread takes the signal before another runs.
            let (p, mut th) = c.split();
            force_signal(p, &mut th, sigsys(datum), ForceMode::Default);
            Some(Outcome::Unchanged)
        }
        // __secure_computing_strict: do_exit(SIGKILL).
        Verdict::StrictKill => {
            c.t.seccomp.mode = sc::MODE_DEAD;
            Some(Outcome::KillThread(SIGKILL))
        }
    }
}

/// `seccomp(op, flags, uargs)` (`do_seccomp`).
pub fn seccomp(c: &mut Ctx<'_>, op: u32, flags: u32, uargs: u64) -> SysResult {
    match op {
        SET_MODE_STRICT => {
            if flags != 0 || uargs != 0 {
                return Err(Errno(EINVAL));
            }
            set_mode_strict(c)
        }
        SET_MODE_FILTER => set_mode_filter(c, flags, uargs),
        GET_ACTION_AVAIL => {
            if flags != 0 {
                return Err(Errno(EINVAL));
            }
            if !sc::action_known(c.read_u32(uargs)?) {
                return Err(Errno(EOPNOTSUPP));
            }
            Ok(0)
        }
        GET_NOTIF_SIZES => {
            if flags != 0 {
                return Err(Errno(EINVAL));
            }
            let b: Vec<u8> = NOTIF_SIZES.iter().flat_map(|s| s.to_le_bytes()).collect();
            c.write_mem(uargs, &b)?;
            Ok(0)
        }
        _ => Err(Errno(EINVAL)),
    }
}

/// `prctl(PR_SET_SECCOMP, mode, filter)` (`prctl_set_seccomp`).
pub fn prctl_set(c: &mut Ctx<'_>, mode: u64, filter: u64) -> SysResult {
    match mode {
        // Strict mode through prctl ignores the filter argument.
        1 => seccomp(c, SET_MODE_STRICT, 0, 0),
        2 => seccomp(c, SET_MODE_FILTER, 0, filter),
        _ => Err(Errno(EINVAL)),
    }
}

/// `seccomp_may_assign_mode`: a thread's mode, once set, stays.
fn may_assign(c: &Ctx<'_>, mode: u32) -> bool {
    let cur = c.t.seccomp.mode;
    cur == sc::MODE_DISABLED || cur == mode
}

/// `seccomp_set_mode_strict`.
fn set_mode_strict(c: &mut Ctx<'_>) -> SysResult {
    if !may_assign(c, sc::MODE_STRICT) {
        return Err(Errno(EINVAL));
    }
    c.t.seccomp.mode = sc::MODE_STRICT;
    // disable_TSC, where TIF_NOTSC exists.
    if c.p.abi == LinuxAbi::X86_64 {
        c.t.notsc = true;
        c.t.cpu.set_tsc_disabled(true);
    }
    Ok(0)
}

/// `seccomp_prepare_user_filter`: the `struct sock_fprog` at `at`, its
/// program copied and checked.
fn prepare(c: &Ctx<'_>, at: u64) -> Result<Vec<bpf::Insn>, Errno> {
    let fprog = c.read_mem(at, 16)?;
    let len = u16::from_le_bytes([fprog[0], fprog[1]]) as usize;
    let filter = u64::from_le_bytes(fprog[8..16].try_into().unwrap());
    if len == 0 || len > bpf::BPF_MAXINSNS {
        return Err(Errno(EINVAL));
    }
    // CAP_SYS_ADMIN in the namespace, or no_new_privs.
    if !c.t.no_new_privs && c.p.creds.1 != 0 {
        return Err(Errno(EACCES));
    }
    // bpf_check_basics_ok, then the copy, then the checks.
    if filter == 0 {
        return Err(Errno(EINVAL));
    }
    let raw = c.read_mem(filter, len * 8)?;
    let prog: Vec<bpf::Insn> = raw.chunks_exact(8).map(bpf::Insn::decode).collect();
    if !bpf::check(&prog) {
        return Err(Errno(EINVAL));
    }
    Ok(prog)
}

/// `seccomp_set_mode_filter`.
fn set_mode_filter(c: &mut Ctx<'_>, flags: u32, uargs: u64) -> SysResult {
    if flags & !FLAG_MASK != 0 || flags & FLAG_NEW_LISTENER != 0 {
        return Err(Errno(EINVAL));
    }
    if flags & FLAG_WAIT_KILLABLE_RECV != 0 {
        return Err(Errno(EINVAL));
    }
    let prog = prepare(c, uargs)?;
    if !may_assign(c, sc::MODE_FILTER) {
        return Err(Errno(EINVAL));
    }
    // seccomp_attach_filter.
    if !c.t.seccomp.fits(&prog) {
        return Err(Errno(ENOMEM));
    }
    if flags & FLAG_TSYNC != 0 {
        // seccomp_can_sync_threads: every other thread without a mode or
        // with filters the caller's chain ends in.
        let mine = &c.t.seccomp;
        let failed = c
            .peers
            .lo
            .iter()
            .chain(c.peers.hi.iter())
            .find(|t| {
                !(t.seccomp.mode == sc::MODE_DISABLED
                    || (t.seccomp.mode == sc::MODE_FILTER && t.seccomp.within(mine)))
            })
            .map(|t| t.tid);
        if let Some(tid) = failed {
            if flags & FLAG_TSYNC_ESRCH != 0 {
                return Err(Errno(ESRCH));
            }
            return Ok(tid as u64);
        }
    }
    c.t.seccomp.attach(prog, flags & FLAG_LOG != 0);
    if flags & FLAG_TSYNC != 0 && c.p.exit.is_none() {
        // seccomp_sync_threads (not in a process being killed).
        let (chain, nnp) = (c.t.seccomp.clone(), c.t.no_new_privs);
        for t in c.peers.lo.iter_mut().chain(c.peers.hi.iter_mut()) {
            t.seccomp = chain.clone();
            t.no_new_privs |= nnp;
        }
    }
    Ok(0)
}
