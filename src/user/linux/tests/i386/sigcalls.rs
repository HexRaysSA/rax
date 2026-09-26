//! The signal calls of an i386 task against Linux 6.19 on x86-64
//! (`kernel/signal.c`, `kernel/compat.c`, `arch/x86/entry/syscalls/
//! syscall_32.tbl`): `struct compat_sigaction` and `struct
//! compat_old_sigaction`, `signal`, the one-word mask calls (`sgetmask`,
//! `ssetmask`, `sigprocmask`, `sigpending`, `sigsuspend`),
//! `compat_stack_t`, `struct compat_siginfo` in `rt_sigqueueinfo`,
//! `rt_tgsigqueueinfo`, `pidfd_send_signal`, and `rt_sigtimedwait`'s two
//! time layouts, and the 32-bit sign extension of a result before restart
//! processing (`syscall_get_error`).

use super::super::harness::{CODE, Harness};
use super::{put, u32_at};
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::{LinuxAbi, Sysno};
use crate::user::linux::signal::deliver::SyscallEntry;
use crate::user::linux::signal::frame::ia32::{self, sc};
use crate::user::linux::signal::*;

fn words(w: &[u32]) -> Vec<u8> {
    w.iter().flat_map(|v| v.to_le_bytes()).collect()
}

fn read(h: &Harness, at: u64, len: usize) -> Vec<u8> {
    let mut b = vec![0u8; len];
    h.proc.state.space.read(at, &mut b).unwrap();
    b
}

/// A register holding a 32-bit negative value, as `int $0x80` passes it.
fn reg(v: i32) -> u64 {
    u64::from(v as u32)
}

#[test]
fn compat_sigaction_is_twenty_bytes_and_hides_the_abi_flag() {
    let mut h = Harness::new(LinuxAbi::I386);
    let (act, oact) = (h.scratch + 0x100, h.scratch + 0x200);
    // An unknown flag (0x100) and SIGKILL in the mask are dropped.
    let flags = sa::SIGINFO | sa::RESTORER | sa::ONSTACK | 0x100;
    let mask = sigmask(SIGUSR2) | sigmask(SIGRTMIN + 1) | sigmask(SIGKILL);
    let mut b = words(&[0x1234, flags as u32, 0x5678]);
    b.extend_from_slice(&mask.to_le_bytes());
    put(&h, act, &b);
    assert_eq!(h.call(Sysno::RtSigaction, &[SIGUSR1 as u64, act, 0, 8]), 0);
    // The handler was installed by a 32-bit call: i386 frames.
    let stored = h.proc.state.sigactions[SIGUSR1 as usize - 1];
    assert_ne!(stored.flags & sa::IA32_ABI, 0);
    put(&h, oact, &[0xEE; 24]);
    assert_eq!(h.call(Sysno::RtSigaction, &[SIGUSR1 as u64, 0, oact, 8]), 0);
    let expect_mask = sigmask(SIGUSR2) | sigmask(SIGRTMIN + 1);
    let mut expect = words(&[0x1234, (flags & !0x100) as u32, 0x5678]);
    expect.extend_from_slice(&expect_mask.to_le_bytes());
    expect.extend_from_slice(&[0xEE; 4]);
    assert_eq!(read(&h, oact, 24), expect, "SA_IA32_ABI is never reported");
    // compat_sigset_t is 8 bytes.
    assert_eq!(
        h.call(Sysno::RtSigaction, &[SIGUSR1 as u64, 0, oact, 4]),
        -i64::from(EINVAL)
    );
    assert_eq!(
        h.call(Sysno::RtSigaction, &[SIGUSR1 as u64, 0x10_0000, 0, 8]),
        -i64::from(EFAULT)
    );
}

#[test]
fn old_sigaction_and_signal_use_one_word_masks() {
    let mut h = Harness::new(LinuxAbi::I386);
    let (act, oact) = (h.scratch + 0x100, h.scratch + 0x200);
    // struct compat_old_sigaction: {handler, mask, flags, restorer}; the
    // mask word becomes the whole mask, SIGKILL and SIGSTOP removed.
    put(
        &h,
        act,
        &words(&[0x2000, 0xFFFF_FFFF, sa::RESTART as u32, 0x3000]),
    );
    assert_eq!(h.call(Sysno::Sigaction, &[SIGUSR2 as u64, act, oact]), 0);
    assert_eq!(read(&h, oact, 16), words(&[0, 0, 0, 0]));
    let a = h.proc.state.sigactions[SIGUSR2 as usize - 1];
    assert_eq!((a.handler, a.restorer), (0x2000, 0x3000));
    assert_eq!(a.mask, 0xFFFF_FFFF & !KERNEL_ONLY_MASK);
    assert_eq!(a.flags, sa::RESTART | sa::IA32_ABI);
    // The old action's mask is its low word.
    h.proc.state.sigactions[SIGUSR2 as usize - 1].mask |= sigmask(SIGRTMIN + 1);
    assert_eq!(h.call(Sysno::Sigaction, &[SIGUSR2 as u64, 0, oact]), 0);
    assert_eq!(
        read(&h, oact, 16),
        words(&[0x2000, 0xFFFB_FEFF, sa::RESTART as u32, 0x3000])
    );
    assert_eq!(
        h.call(Sysno::Sigaction, &[SIGKILL as u64, act, 0]),
        -i64::from(EINVAL)
    );
    // signal: SA_ONESHOT | SA_NOMASK, an empty mask; the old handler.
    assert_eq!(h.call(Sysno::Signal, &[SIGUSR2 as u64, 0x4000]), 0x2000);
    let a = h.proc.state.sigactions[SIGUSR2 as usize - 1];
    assert_eq!(
        (a.handler, a.flags, a.mask),
        (0x4000, sa::RESETHAND | sa::NODEFER | sa::IA32_ABI, 0)
    );
    assert_eq!(
        h.call(Sysno::Signal, &[SIGSTOP as u64, 0x4000]),
        -i64::from(EINVAL)
    );
}

#[test]
fn the_old_mask_calls_see_the_low_word() {
    let mut h = Harness::new(LinuxAbi::I386);
    let at = h.scratch + 0x100;
    // SIGRTMIN + 1 (33) is the first signal of the upper word.
    h.proc.threads[0].sigmask = sigmask(SIGHUP) | sigmask(SIGRTMIN + 1);
    // sgetmask returns blocked.sig[0], a long: EAX is its low word.
    assert_eq!(
        h.call(Sysno::Sgetmask, &[]) as u64,
        sigmask(SIGHUP) | sigmask(SIGRTMIN + 1)
    );
    // ssetmask(-1): siginitset sign-extends, so every signal is blocked.
    assert_eq!(h.call(Sysno::Ssetmask, &[reg(-1)]), 1);
    assert_eq!(h.proc.threads[0].sigmask, !KERNEL_ONLY_MASK);
    // The old low word comes back as an int.
    assert_eq!(
        h.call(Sysno::Ssetmask, &[4]),
        i64::from(0xFFFB_FEFFu32 as i32)
    );
    assert_eq!(h.proc.threads[0].sigmask, 4);
    // sigprocmask with compat_old_sigset_t: SIG_SETMASK replaces only the
    // low word; the old low word is stored.
    h.proc.threads[0].sigmask = sigmask(SIGRTMIN + 5) | sigmask(SIGINT);
    put(&h, at, &(sigmask(SIGUSR1) as u32 | 1 << 8).to_le_bytes());
    assert_eq!(h.call(Sysno::Sigprocmask, &[2, at, at + 8]), 0);
    assert_eq!(
        h.proc.threads[0].sigmask,
        sigmask(SIGRTMIN + 5) | sigmask(SIGUSR1)
    );
    assert_eq!(u32_at(&h, at + 8), sigmask(SIGINT) as u32);
    put(&h, at, &(sigmask(SIGUSR2) as u32).to_le_bytes());
    assert_eq!(h.call(Sysno::Sigprocmask, &[0, at, 0]), 0);
    assert_eq!(h.call(Sysno::Sigprocmask, &[1, at, 0]), 0);
    assert_eq!(
        h.proc.threads[0].sigmask,
        sigmask(SIGRTMIN + 5) | sigmask(SIGUSR1)
    );
    assert_eq!(h.call(Sysno::Sigprocmask, &[3, at, 0]), -i64::from(EINVAL));
    // sigpending: the low word of the blocked pending signals.
    let (pid, tid) = (h.proc.state.pid as u64, h.proc.threads[0].tid as u64);
    h.ok(Sysno::Tgkill, &[pid, tid, SIGUSR1 as u64]);
    h.ok(Sysno::Tgkill, &[pid, tid, (SIGRTMIN + 5) as u64]);
    put(&h, at, &[0xEE; 8]);
    assert_eq!(h.call(Sysno::Sigpending, &[at]), 0);
    assert_eq!(
        read(&h, at, 8),
        [&(sigmask(SIGUSR1) as u32).to_le_bytes()[..], &[0xEE; 4]].concat()
    );
}

#[test]
fn old_sigsuspend_waits_with_its_third_argument_as_the_mask() {
    let mut h = Harness::new(LinuxAbi::I386);
    let at = h.scratch + 0x100;
    let mut b = words(&[CODE as u32 + 0x100, 0, 0]);
    b.extend_from_slice(&0u64.to_le_bytes());
    put(&h, at, &b);
    h.ok(Sysno::RtSigaction, &[SIGUSR1 as u64, at, 0, 8]);
    h.proc.threads[0].sigmask = sigmask(SIGUSR1) | sigmask(SIGRTMIN);
    let (pid, tid) = (h.proc.state.pid as u64, h.proc.threads[0].tid as u64);
    h.ok(Sysno::Tgkill, &[pid, tid, SIGUSR1 as u64]);
    // The first two arguments are ignored; the third unblocks SIGUSR1
    // (and every real-time signal) while waiting.
    let blocked = u64::from(sigmask(SIGHUP) as u32);
    assert_eq!(
        h.call(Sysno::Sigsuspend, &[7, 7, blocked]),
        -514,
        "-ERESTARTNOHAND"
    );
    let t = &h.proc.threads[0];
    assert_eq!(t.sigmask, sigmask(SIGHUP));
    assert_eq!(t.saved_sigmask, Some(sigmask(SIGUSR1) | sigmask(SIGRTMIN)));
}

#[test]
fn compat_sigaltstack_is_twelve_bytes() {
    let mut h = Harness::new(LinuxAbi::I386);
    let (ss, old) = (h.scratch + 0x100, h.scratch + 0x200);
    put(&h, old, &[0xEE; 16]);
    put(&h, ss, &words(&[0x0070_0000, 0, 0x4000]));
    assert_eq!(h.call(Sysno::Sigaltstack, &[ss, old]), 0);
    // The old stack: none (SS_DISABLE), written as 12 bytes.
    assert_eq!(
        read(&h, old, 16),
        [words(&[0, 2, 0]), vec![0xEE; 4]].concat()
    );
    assert_eq!(
        h.proc.threads[0].altstack,
        AltStack {
            sp: 0x0070_0000,
            size: 0x4000,
            flags: 0
        }
    );
    assert_eq!(h.call(Sysno::Sigaltstack, &[0, old]), 0);
    assert_eq!(read(&h, old, 12), words(&[0x0070_0000, 0, 0x4000]));
    // COMPAT_MINSIGSTKSZ is 2048.
    put(&h, ss, &words(&[0x0070_0000, 0, 2047]));
    assert_eq!(h.call(Sysno::Sigaltstack, &[ss, 0]), -i64::from(ENOMEM));
    // On the stack, it cannot change.
    h.proc.threads[0].cpu.set_sp(0x0070_1000);
    put(&h, ss, &words(&[0, 2, 0]));
    assert_eq!(h.call(Sysno::Sigaltstack, &[ss, old]), -i64::from(EPERM));
    assert_eq!(read(&h, old, 12), words(&[0x0070_0000, 0, 0x4000]));
}

/// A `struct compat_siginfo` for `SI_QUEUE` from `pid`/`uid` with `si_int`.
fn queued(sig: i32, pid: u32, uid: u32, value: u32) -> Vec<u8> {
    let mut b = words(&[sig as u32, 0, -1i32 as u32, pid, uid, value]);
    b.resize(128, 0);
    b
}

#[test]
fn queued_and_waited_signals_carry_compat_siginfo() {
    let mut h = Harness::new(LinuxAbi::I386);
    let (info, set, ts, out) = (
        h.scratch + 0x100,
        h.scratch + 0x200,
        h.scratch + 0x300,
        h.scratch + 0x400,
    );
    let (pid, tid) = (h.proc.state.pid as u64, h.proc.threads[0].tid as u64);
    let me = h.proc.state.pid as u32;
    h.proc.threads[0].sigmask = sigmask(SIGRTMIN) | sigmask(SIGRTMIN + 1) | sigmask(SIGUSR1);
    // __copy_siginfo_from_user32: the layout's fields widened, si_signo
    // replaced; bytes past them are not checked (no E2BIG).
    let mut b = queued(SIGUSR2, me, 1000, 0xCAFE);
    b[100] = 0xFF;
    put(&h, info, &b);
    let rt0 = SIGRTMIN as u64;
    h.ok(Sysno::RtSigqueueinfo, &[pid, rt0, info]);
    put(&h, info, &queued(SIGRTMIN + 1, me, 1000, 0xBEEF));
    h.ok(Sysno::RtTgsigqueueinfo, &[pid, tid, rt0 + 1, info]);
    let queued_rt0 = h
        .proc
        .state
        .shared_pending
        .records()
        .find(|i| i.signo == SIGRTMIN);
    assert!(queued_rt0.is_some_and(|i| i.value() == 0xCAFE && i.pid() == me as i32));
    // rt_sigtimedwait (time32): struct old_timespec32, and the record as
    // struct compat_siginfo. The thread's own queue is taken first.
    put(
        &h,
        set,
        &(sigmask(SIGRTMIN) | sigmask(SIGRTMIN + 1)).to_le_bytes(),
    );
    put(&h, ts, &words(&[0, 0]));
    put(&h, out, &[0xEE; 136]);
    assert_eq!(
        h.call(Sysno::RtSigtimedwait, &[set, out, ts, 8]),
        i64::from(SIGRTMIN + 1)
    );
    assert_eq!(
        read(&h, out, 24),
        words(&[SIGRTMIN as u32 + 1, 0, -1i32 as u32, me, 1000, 0xBEEF])
    );
    assert!(read(&h, out + 24, 104).iter().all(|&x| x == 0));
    assert_eq!(read(&h, out + 128, 8), [0xEE; 8]);
    // rt_sigtimedwait_time64: the padding above the nanoseconds is
    // ignored.
    put(&h, ts, &words(&[0, 0, 0, 0xFFFF_FFFF]));
    assert_eq!(
        h.call(Sysno::RtSigtimedwaitTime64, &[set, out, ts, 8]),
        i64::from(SIGRTMIN)
    );
    assert_eq!(u32_at(&h, out + 20), 0xCAFE);
    // Nothing left: EAGAIN at once; an invalid old_timespec32: EINVAL.
    assert_eq!(
        h.call(Sysno::RtSigtimedwait, &[set, out, ts, 8]),
        -i64::from(EAGAIN)
    );
    put(&h, ts, &words(&[0, 1_000_000_000]));
    assert_eq!(
        h.call(Sysno::RtSigtimedwait, &[set, out, ts, 8]),
        -i64::from(EINVAL)
    );
    // pidfd_send_signal reads struct compat_siginfo in a 32-bit call.
    let pidfd = h.ok(Sysno::PidfdOpen, &[pid, 0]);
    put(&h, info, &queued(SIGUSR1, me, 1000, 0x77));
    h.ok(Sysno::PidfdSendSignal, &[pidfd, SIGUSR1 as u64, info, 0]);
    put(&h, set, &sigmask(SIGUSR1).to_le_bytes());
    put(&h, ts, &words(&[0, 0]));
    assert_eq!(
        h.call(Sysno::RtSigtimedwait, &[set, out, ts, 8]),
        i64::from(SIGUSR1)
    );
    assert_eq!(u32_at(&h, out + 20), 0x77);
}

#[test]
fn a_result_is_a_restart_code_by_its_low_half() {
    // syscall_get_error sign-extends a 32-bit call's result: an lseek to
    // 0xFFFFFE00 reads as -ERESTARTSYS, and a handler without SA_RESTART
    // turns it into -EINTR, as on Linux.
    let mut h = Harness::new(LinuxAbi::I386);
    let act = h.scratch + 0x100;
    let mut b = words(&[
        CODE as u32 + 0x100,
        sa::RESTORER as u32,
        CODE as u32 + 0x200,
    ]);
    b.extend_from_slice(&0u64.to_le_bytes());
    put(&h, act, &b);
    h.ok(Sysno::RtSigaction, &[SIGUSR1 as u64, act, 0, 8]);
    let (pid, tid) = (h.proc.state.pid as u64, h.proc.threads[0].tid as u64);
    h.ok(Sysno::Tgkill, &[pid, tid, SIGUSR1 as u64]);
    let t = &mut h.proc.threads[0];
    t.cpu.set_pc(CODE + 0x42);
    t.syscall = Some(SyscallEntry { nr: 19, arg0: 3 });
    t.cpu.set_syscall_result(0xFFFF_FE00);
    let sp = t.cpu.sp();
    h.proc.deliver_signals(0);
    let frame = h.proc.threads[0].cpu.sp();
    assert!(frame < sp);
    let context = read(&h, frame + ia32::off::SC, sc::SIZE);
    let w = |at: usize| u32::from_le_bytes(context[at..at + 4].try_into().unwrap());
    assert_eq!(w(sc::AX), -(EINTR as i32) as u32);
    assert_eq!(w(sc::IP), CODE as u32 + 0x42);
}
