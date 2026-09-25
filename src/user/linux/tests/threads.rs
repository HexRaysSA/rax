//! Threads, driven through the system calls of chosen threads without
//! executing guest code: `clone`/`clone3` and `unshare` (`kernel/fork.c`
//! and the architectures' `copy_thread`), thread exit (`kernel/exit.c`,
//! `mm_release`, `exit_robust_list`), futexes (`kernel/futex/`), signal
//! targeting (`complete_signal`, `retarget_shared_pending`), and the `/proc`
//! thread views (`fs/proc/base.c`). Expectations come from those Linux 6.19
//! functions.

use std::time::Duration;

use super::harness::{Harness, each_abi};
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::{LinuxAbi, Sysno};
use crate::user::linux::futex::{FUTEX_OWNER_DIED, FUTEX_WAITERS};
use crate::user::linux::process::ExitStatus;
use crate::user::linux::signal::deliver::restart::*;
use crate::user::linux::signal::*;
use crate::user::linux::syscall::RestartBlock;
use crate::user::linux::syscall::thread::cf::*;

/// What every threads library passes.
const THREAD: u64 =
    CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM;

// futex(2) operations.
const WAIT: u64 = 0;
const WAKE: u64 = 1;
const CMP_REQUEUE: u64 = 4;
const WAKE_OP: u64 = 5;
const LOCK_PI: u64 = 6;
const UNLOCK_PI: u64 = 7;
const TRYLOCK_PI: u64 = 8;
const WAIT_BITSET: u64 = 9;
const WAKE_BITSET: u64 = 10;
const PRIVATE: u64 = 128;

fn neg(e: i32) -> i64 {
    -(e as i64)
}

fn put_u32(h: &Harness, at: u64, v: u32) {
    h.proc.state.space.write_raw(at, &v.to_le_bytes()).unwrap();
}

fn u32_at(h: &Harness, at: u64) -> u32 {
    let mut b = [0u8; 4];
    h.proc.state.space.read(at, &mut b).unwrap();
    u32::from_le_bytes(b)
}

fn put_u64s(h: &Harness, at: u64, words: &[u64]) {
    let b: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    h.proc.state.space.write_raw(at, &b).unwrap();
}

/// `clone` arguments in the ABI's order: x86-64 `(flags, newsp,
/// parent_tid, child_tid, tls)`, arm64/riscv `(flags, newsp, parent_tid,
/// tls, child_tid)`.
fn clone_args(abi: LinuxAbi, flags: u64, stack: u64, ptid: u64, ctid: u64, tls: u64) -> [u64; 5] {
    match abi {
        LinuxAbi::X86_64 => [flags, stack, ptid, ctid, tls],
        _ => [flags, stack, ptid, tls, ctid],
    }
}

/// Creates a thread of thread 0 with `flags` added; returns its TID and
/// list index.
fn spawn(h: &mut Harness, extra: u64, ctid: u64) -> (i32, usize) {
    let args = clone_args(h.abi(), THREAD | extra, 0, 0, ctid, 0);
    let tid = h.ok(Sysno::Clone, &args) as i32;
    (tid, h.index_of(tid))
}

/// A handler for `sig` so it is not fatal.
fn handle(h: &mut Harness, sig: i32) {
    let act = h.scratch + 0xe00;
    let mut words = vec![0x40_1000];
    if h.abi().has_sa_restorer() {
        words.extend([sa::RESTORER, 0x40_1100]);
    } else {
        words.push(0);
    }
    words.push(0);
    put_u64s(h, act, &words);
    h.ok(Sysno::RtSigaction, &[sig as u64, act, 0, 8]);
}

#[test]
fn clone_creates_a_thread_in_the_kernel_register_state() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let (ptid, ctid) = (h.scratch, h.scratch + 8);
        let (stack, tls) = (0x7000_0000u64, 0x6000_1230u64);
        h.proc.threads[0].sigmask = sigmask(SIGUSR1);
        let flags =
            THREAD | CLONE_SETTLS | CLONE_PARENT_SETTID | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID;
        let tid = h.ok(
            Sysno::Clone,
            &clone_args(abi, flags, stack, ptid, ctid, tls),
        ) as i32;
        assert!(tid > h.proc.state.pid, "{abi:?}");
        assert_eq!(h.proc.threads.len(), 2);
        let parent_pc = h.proc.threads[0].cpu.pc();
        let parent_comm = h.proc.threads[0].comm.clone();
        let c = &h.proc.threads[1];
        // copy_thread: a copy of the registers with the return value 0,
        // the given stack pointer, and the TLS pointer.
        assert_eq!(
            (
                c.tid,
                c.cpu.sp(),
                c.cpu.thread_pointer(),
                c.cpu.syscall_return_value(),
                c.cpu.pc()
            ),
            (tid, stack, tls, 0, parent_pc),
            "{abi:?}"
        );
        // copy_process: the mask is inherited, the queue and alternate
        // stack are not; the TID words are recorded.
        assert_eq!(c.sigmask, sigmask(SIGUSR1));
        assert!(c.pending.next(0).is_none());
        assert_eq!(c.altstack, AltStack::DISABLED);
        assert_eq!((c.clear_child_tid, c.set_child_tid), (ctid, ctid));
        assert_eq!(c.comm, parent_comm);
        assert_eq!(u32_at(&h, ptid), tid as u32, "CLONE_PARENT_SETTID");
        // schedule_tail writes CLONE_CHILD_SETTID as the child first runs.
        assert_eq!(u32_at(&h, ctid), 0);
        h.proc.deliver_signals(1);
        assert_eq!(u32_at(&h, ctid), tid as u32, "CLONE_CHILD_SETTID");
    });
}

#[test]
fn clone_rejects_what_copy_process_refuses() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let a = |flags| clone_args(abi, flags, 0, 0, 0, 0);
        assert_eq!(h.err(Sysno::Clone, &a(CLONE_THREAD | CLONE_VM)), EINVAL);
        assert_eq!(h.err(Sysno::Clone, &a(CLONE_SIGHAND)), EINVAL);
        assert_eq!(h.err(Sysno::Clone, &a(CLONE_NEWNS | CLONE_FS)), EINVAL);
        assert_eq!(
            h.err(Sysno::Clone, &a(THREAD | CLONE_PIDFD | CLONE_DETACHED)),
            EINVAL
        );
        // Namespaces need privileges the emulated process lacks.
        assert_eq!(h.err(Sysno::Clone, &a(CLONE_NEWUTS)), EPERM);
        // Not supported: new processes, and threads that do not share the
        // descriptor table and file-system context.
        assert_eq!(h.err(Sysno::Clone, &a(SIGCHLD as u64)), ENOSYS);
        assert_eq!(h.err(Sysno::Clone, &a(THREAD & !CLONE_FILES)), EINVAL);
        if abi == LinuxAbi::X86_64 {
            // set_new_tls: ARCH_SET_FS refuses a kernel address.
            let bad = clone_args(abi, THREAD | CLONE_SETTLS, 0, 0, 0, 1 << 47);
            assert_eq!(h.err(Sysno::Clone, &bad), EPERM);
        }
        assert_eq!(h.proc.threads.len(), 1, "{abi:?}: nothing was created");
    });
}

#[test]
fn clone3_reads_a_versioned_structure() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let args = h.scratch + 0x100;
        let set = |h: &Harness, words: &[u64]| {
            let mut w = words.to_vec();
            w.resize(12, 0);
            put_u64s(h, args, &w);
        };
        set(&h, &[]);
        assert_eq!(h.err(Sysno::Clone3, &[args, 63]), EINVAL);
        assert_eq!(h.err(Sysno::Clone3, &[args, 4097]), E2BIG);
        let mut tail = vec![0u64; 12];
        tail[11] = 1;
        set(&h, &tail);
        assert_eq!(h.err(Sysno::Clone3, &[args, 96]), E2BIG);
        // flags, pidfd, child_tid, parent_tid, exit_signal, stack,
        // stack_size, tls, set_tid, set_tid_size, cgroup.
        set(&h, &[0, 0, 0, 0, 65]);
        assert_eq!(h.err(Sysno::Clone3, &[args, 88]), EINVAL);
        set(&h, &[0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(h.err(Sysno::Clone3, &[args, 88]), EINVAL);
        set(&h, &[THREAD, 0, 0, 0, SIGCHLD as u64]);
        assert_eq!(h.err(Sysno::Clone3, &[args, 88]), EINVAL);
        set(&h, &[THREAD, 0, 0, 0, 0, 0x10000]);
        assert_eq!(h.err(Sysno::Clone3, &[args, 88]), EINVAL);
        let top = abi.task_size();
        set(&h, &[THREAD, 0, 0, 0, 0, top - 0x1000, 0x2000]);
        assert_eq!(h.err(Sysno::Clone3, &[args, 88]), EINVAL);
        set(&h, &[CLONE_DETACHED]);
        assert_eq!(h.err(Sysno::Clone3, &[args, 64]), EINVAL);
        // The stack is a base and a size: the child starts at the top.
        let tls = 0x6000_2000;
        set(
            &h,
            &[THREAD | CLONE_SETTLS, 0, 0, 0, 0, 0x7000_0000, 0x8000, tls],
        );
        let tid = h.ok(Sysno::Clone3, &[args, 64]) as i32;
        let c = &h.proc.threads[h.index_of(tid)];
        assert_eq!((c.cpu.sp(), c.cpu.thread_pointer()), (0x7000_8000, tls));
        // Choosing a TID needs CAP_CHECKPOINT_RESTORE.
        let want = h.scratch + 0x200;
        put_u32(&h, want, 4_000_000);
        set(&h, &[THREAD, 0, 0, 0, 0, 0, 0, 0, want, 1]);
        if h.proc.state.creds.1 == 0 {
            assert_eq!(h.ok(Sysno::Clone3, &[args, 88]), 4_000_000);
        } else {
            assert_eq!(h.err(Sysno::Clone3, &[args, 88]), EPERM);
        }
    });
}

#[test]
fn a_pending_signal_makes_clone_restart() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    handle(&mut h, SIGUSR1);
    let pid = h.proc.state.pid as u64;
    h.ok(Sysno::Tgkill, &[pid, pid, SIGUSR1 as u64]);
    let args = clone_args(LinuxAbi::X86_64, THREAD, 0, 0, 0, 0);
    assert_eq!(h.call(Sysno::Clone, &args), neg(ERESTARTNOINTR));
    assert_eq!(h.proc.threads.len(), 1);
}

#[test]
fn futex_wait_sleeps_until_a_matching_wake() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let (_, w) = spawn(&mut h, 0, 0);
        let word = h.scratch + 0x40;
        put_u32(&h, word, 0);
        // A value mismatch returns at once.
        assert_eq!(
            h.call(Sysno::Futex, &[word, WAIT | PRIVATE, 1, 0, 0, 0]),
            neg(EAGAIN)
        );
        assert_eq!(
            h.start(
                w,
                Sysno::Futex,
                &[word, WAIT_BITSET | PRIVATE, 0, 0, 0, 0b01]
            ),
            None,
            "{abi:?}"
        );
        // A disjoint bitset or a shared key does not match.
        assert_eq!(
            h.call(Sysno::Futex, &[word, WAKE_BITSET | PRIVATE, 1, 0, 0, 0b10]),
            0
        );
        assert_eq!(h.call(Sysno::Futex, &[word, WAKE, 1, 0, 0, 0]), 0);
        assert!(h.proc.threads[w].blocked.is_some());
        // As in futex_wake, a count of 0 still wakes one waiter.
        assert_eq!(h.call(Sysno::Futex, &[word, WAKE | PRIVATE, 0, 0, 0, 0]), 1);
        assert_eq!(h.proc.wake_sleepers(), 1);
        assert_eq!(h.result(w), 0);
        assert!(!h.proc.state.futex.is_queued(h.proc.threads[w].tid));
    });
}

#[test]
fn futex_requeue_and_wake_op_count_what_they_move() {
    let mut h = Harness::new(LinuxAbi::Aarch64);
    let (a, b, c) = (h.scratch + 0x40, h.scratch + 0x44, h.scratch + 0x48);
    put_u32(&h, a, 0);
    put_u32(&h, b, 0);
    let waiters: Vec<usize> = (0..3).map(|_| spawn(&mut h, 0, 0).1).collect();
    for &w in &waiters {
        assert_eq!(
            h.start(w, Sysno::Futex, &[a, WAIT | PRIVATE, 0, 0, 0, 0]),
            None
        );
    }
    // CMP_REQUEUE: the value must match; then one woken, one moved.
    assert_eq!(
        h.call(Sysno::Futex, &[a, CMP_REQUEUE | PRIVATE, 1, 1, b, 7]),
        neg(EAGAIN)
    );
    assert_eq!(
        h.call(Sysno::Futex, &[a, CMP_REQUEUE | PRIVATE, 1, 1, b, 0]),
        2
    );
    assert_eq!(h.call(Sysno::Futex, &[b, WAKE | PRIVATE, 10, 0, 0, 0]), 1);
    // WAKE_OP: *a = 7; its old value 5 == 5 fires the wake on a, where
    // the last waiter sleeps (it checked its value already).
    put_u32(&h, a, 5);
    let op = (0 << 28) | (0 << 24) | (7 << 12) | 5; // SET 7, CMP_EQ 5
    assert_eq!(
        h.call(Sysno::Futex, &[b, WAKE_OP | PRIVATE, 1, 1, a, op]),
        1,
        "nothing on b; the waiter left on a"
    );
    assert_eq!(u32_at(&h, a), 7);
    h.proc.wake_sleepers();
    for &w in &waiters {
        assert_eq!(h.result(w), 0);
    }
    // An unknown operation leaves the word alone; an unknown comparison
    // fails after the store.
    put_u32(&h, c, 1);
    assert_eq!(
        h.call(Sysno::Futex, &[b, WAKE_OP | PRIVATE, 1, 1, c, 6 << 28]),
        neg(ENOSYS)
    );
    assert_eq!(u32_at(&h, c), 1);
    assert_eq!(
        h.call(
            Sysno::Futex,
            &[b, WAKE_OP | PRIVATE, 1, 1, c, (9 << 24) | (4 << 12)]
        ),
        neg(ENOSYS)
    );
    assert_eq!(u32_at(&h, c), 4);
}

#[test]
fn an_interrupted_futex_wait_restarts_or_times_out() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        handle(&mut h, SIGUSR1);
        let (tid, w) = spawn(&mut h, 0, 0);
        let (word, ts) = (h.scratch + 0x40, h.scratch + 0x80);
        put_u32(&h, word, 0);
        let pid = h.proc.state.pid as u64;
        // Without a timeout: -ERESTARTSYS, and the entry is gone.
        assert_eq!(
            h.start(w, Sysno::Futex, &[word, WAIT | PRIVATE, 0, 0, 0, 0]),
            None
        );
        h.ok(Sysno::Tgkill, &[pid, tid as u64, SIGUSR1 as u64]);
        assert_eq!(h.proc.wake_sleepers(), 1);
        assert_eq!(h.result(w), neg(ERESTARTSYS), "{abi:?}");
        assert!(!h.proc.state.futex.is_queued(tid));
        // With a timeout: futex_wait_restart continues to the deadline.
        h.proc.threads[w].sigpending = false;
        h.proc.threads[w].pending.flush(u64::MAX);
        put_u64s(&h, ts, &[5, 0]);
        assert_eq!(
            h.start(w, Sysno::Futex, &[word, WAIT | PRIVATE, 0, ts, 0, 0]),
            None
        );
        h.ok(Sysno::Tgkill, &[pid, tid as u64, SIGUSR1 as u64]);
        h.proc.wake_sleepers();
        assert_eq!(h.result(w), neg(ERESTART_RESTARTBLOCK));
        assert!(matches!(
            h.proc.threads[w].restart,
            Some(RestartBlock::Futex { uaddr, val: 0, .. }) if uaddr == word
        ));
        // A wake takes precedence over a signal that arrived first.
        h.proc.threads[w].sigpending = false;
        h.proc.threads[w].pending.flush(u64::MAX);
        assert_eq!(
            h.start(w, Sysno::Futex, &[word, WAIT | PRIVATE, 0, 0, 0, 0]),
            None
        );
        h.ok(Sysno::Tgkill, &[pid, tid as u64, SIGUSR1 as u64]);
        assert_eq!(h.call(Sysno::Futex, &[word, WAKE | PRIVATE, 1, 0, 0, 0]), 1);
        h.proc.wake_sleepers();
        assert_eq!(h.result(w), 0);
        // The timeout.
        h.proc.threads[w].sigpending = false;
        h.proc.threads[w].pending.flush(u64::MAX);
        put_u64s(&h, ts, &[0, 20_000_000]);
        assert_eq!(
            h.start(w, Sysno::Futex, &[word, WAIT | PRIVATE, 0, ts, 0, 0]),
            None
        );
        std::thread::sleep(Duration::from_millis(30));
        assert_eq!(h.proc.wake_sleepers(), 1);
        assert_eq!(h.result(w), neg(ETIMEDOUT));
    });
}

#[test]
fn pi_futex_ownership_passes_to_the_waiter() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let (tid, w) = spawn(&mut h, 0, 0);
        let me = h.proc.state.pid as u32;
        let word = h.scratch + 0x40;
        put_u32(&h, word, 0);
        assert_eq!(
            h.call(Sysno::Futex, &[word, LOCK_PI | PRIVATE, 0, 0, 0, 0]),
            0
        );
        assert_eq!(u32_at(&h, word), me);
        assert_eq!(
            h.call(Sysno::Futex, &[word, LOCK_PI | PRIVATE, 0, 0, 0, 0]),
            neg(EDEADLK)
        );
        assert_eq!(
            h.start(w, Sysno::Futex, &[word, TRYLOCK_PI | PRIVATE, 0, 0, 0, 0]),
            Some(neg(EAGAIN))
        );
        assert_eq!(
            h.start(w, Sysno::Futex, &[word, LOCK_PI | PRIVATE, 0, 0, 0, 0]),
            None
        );
        assert_eq!(u32_at(&h, word), me | FUTEX_WAITERS);
        // wake_futex_pi: the waiter owns it, FUTEX_WAITERS set.
        assert_eq!(
            h.call(Sysno::Futex, &[word, UNLOCK_PI | PRIVATE, 0, 0, 0, 0]),
            0
        );
        assert_eq!(u32_at(&h, word), tid as u32 | FUTEX_WAITERS, "{abi:?}");
        h.proc.wake_sleepers();
        assert_eq!(h.result(w), 0);
        assert_eq!(
            h.call(Sysno::Futex, &[word, UNLOCK_PI | PRIVATE, 0, 0, 0, 0]),
            neg(EPERM)
        );
        assert_eq!(
            h.start(w, Sysno::Futex, &[word, UNLOCK_PI | PRIVATE, 0, 0, 0, 0]),
            Some(0)
        );
        assert_eq!(u32_at(&h, word), 0);
        // An owner that does not exist: FUTEX_WAITERS is set, then ESRCH.
        put_u32(&h, word, 0x3fff_fffe);
        assert_eq!(
            h.call(Sysno::Futex, &[word, LOCK_PI | PRIVATE, 0, 0, 0, 0]),
            neg(ESRCH)
        );
        assert_eq!(u32_at(&h, word), 0x3fff_fffe | FUTEX_WAITERS);
    });
}

#[test]
fn thread_exit_clears_the_tid_word_and_releases_robust_futexes() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let ctid = h.scratch + 0x40;
        let (tid, w) = spawn(&mut h, CLONE_CHILD_CLEARTID, ctid);
        put_u32(&h, ctid, tid as u32);
        // A robust list with one held futex that another thread waits on.
        let (head, entry, offset) = (h.scratch + 0x100, h.scratch + 0x140, 0x20u64);
        let lock = entry + offset;
        put_u64s(&h, head, &[entry, offset, 0]);
        put_u64s(&h, entry, &[head]);
        put_u32(&h, lock, tid as u32 | FUTEX_WAITERS);
        assert_eq!(h.start(w, Sysno::SetRobustList, &[head, 24]), Some(0));
        // Thread 0 waits on the lock with a shared key, as robust mutexes
        // do; a third thread waits on the TID word.
        assert_eq!(
            h.start(
                0,
                Sysno::Futex,
                &[lock, WAIT, tid as u64 | FUTEX_WAITERS as u64, 0, 0, 0]
            ),
            None
        );
        let (_, joiner) = {
            // Spawning needs a running thread: create from the waiter.
            let args = clone_args(abi, THREAD, 0, 0, 0, 0);
            let t = h.start(w, Sysno::Clone, &args).unwrap() as i32;
            (t, h.index_of(t))
        };
        assert_eq!(
            h.start(joiner, Sysno::Futex, &[ctid, WAIT, tid as u64, 0, 0, 0]),
            None
        );
        assert_eq!(h.start(w, Sysno::Exit, &[3]), None, "{abi:?}");
        assert_eq!(h.proc.threads.len(), 2);
        // exit_robust_list, then mm_release.
        assert_eq!(u32_at(&h, lock), FUTEX_WAITERS | FUTEX_OWNER_DIED);
        assert_eq!(u32_at(&h, ctid), 0);
        assert_eq!(h.proc.wake_sleepers(), 2);
        let joiner = h.index_of(h.proc.threads[1].tid);
        assert_eq!((h.result(0), h.result(joiner)), (0, 0));
    });
}

#[test]
fn process_signals_go_to_a_thread_that_takes_them() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    handle(&mut h, SIGUSR1);
    handle(&mut h, SIGUSR2);
    let pid = h.proc.state.pid as u64;
    let word = h.scratch + 0x40;
    put_u32(&h, word, 0);
    let (tid, w) = spawn(&mut h, 0, 0);
    assert_eq!(
        h.start(w, Sysno::Futex, &[word, WAIT | PRIVATE, 0, 0, 0, 0]),
        None
    );
    // The leader wants it (it is running): the sleeper is left alone.
    h.ok(Sysno::Kill, &[pid, SIGUSR1 as u64]);
    assert!(h.proc.threads[0].sigpending);
    assert!(!h.proc.threads[w].sigpending);
    assert_eq!(h.proc.wake_sleepers(), 0);
    // The leader blocks SIGUSR2: the sleeping thread takes it.
    let set = h.scratch + 0x80;
    put_u64s(&h, set, &[sigmask(SIGUSR2)]);
    h.ok(Sysno::RtSigprocmask, &[0, set, 0, 8]);
    h.ok(Sysno::Kill, &[pid, SIGUSR2 as u64]);
    assert!(h.proc.threads[w].sigpending);
    assert_eq!(h.proc.wake_sleepers(), 1);
    assert_eq!(h.result(w), neg(ERESTARTSYS));
    assert_eq!(h.proc.state.curr_target, tid);
    // Blocking a signal meant for the leader passes it on
    // (retarget_shared_pending).
    h.proc.threads[w].sigpending = false;
    assert_eq!(
        h.start(w, Sysno::Futex, &[word, WAIT | PRIVATE, 0, 0, 0, 0]),
        None
    );
    put_u64s(&h, set, &[sigmask(SIGUSR1)]);
    h.ok(Sysno::RtSigprocmask, &[0, set, 0, 8]);
    assert!(h.proc.threads[w].sigpending);
    // A fatal default action takes the process down as it is sent.
    h.ok(Sysno::Kill, &[pid, SIGTERM as u64]);
    assert!(matches!(
        h.proc.state.exit,
        Some(ExitStatus::Signaled { info, core: false, .. }) if info.signo == SIGTERM
    ));
}

#[test]
fn thread_signals_and_exits() {
    let mut h = Harness::new(LinuxAbi::Riscv64);
    handle(&mut h, SIGUSR1);
    let pid = h.proc.state.pid as u64;
    let (tid, w) = spawn(&mut h, 0, 0);
    // tgkill queues on the thread and wakes it.
    h.ok(Sysno::Tgkill, &[pid, tid as u64, SIGUSR1 as u64]);
    assert!(h.proc.threads[w].pending.contains(SIGUSR1));
    assert!(h.proc.threads[w].sigpending);
    assert!(!h.proc.threads[0].pending.contains(SIGUSR1));
    assert_eq!(h.err(Sysno::Tgkill, &[pid + 1, tid as u64, 0]), ESRCH);
    // The leader exits first: the process goes on, and the zombie leader
    // can still be named.
    assert_eq!(h.start(0, Sysno::Exit, &[7]), None);
    assert!(h.proc.state.exit.is_none());
    let w = h.index_of(tid);
    assert_eq!(
        h.start(w, Sysno::Tgkill, &[pid, pid, SIGUSR1 as u64]),
        Some(0)
    );
    assert_eq!(h.start(w, Sysno::Kill, &[pid, 0]), Some(0));
    assert_eq!(h.start(w, Sysno::Getpid, &[]), Some(pid as i64));
    // The last thread's code is the process's (synchronize_group_exit).
    assert_eq!(h.start(w, Sysno::Exit, &[9]), None);
    assert_eq!(h.proc.state.exit, Some(ExitStatus::Exited(9)));

    let mut h = Harness::new(LinuxAbi::Riscv64);
    let (_, w) = spawn(&mut h, 0, 0);
    assert_eq!(h.start(w, Sysno::ExitGroup, &[5]), Some(0));
    assert_eq!(h.proc.state.exit, Some(ExitStatus::Exited(5)));
    // A thread that no longer exists.
    let mut h = Harness::new(LinuxAbi::Riscv64);
    let (tid, w) = spawn(&mut h, 0, 0);
    h.start(w, Sysno::Exit, &[0]);
    assert_eq!(h.err(Sysno::Tgkill, &[pid, tid as u64, 0]), ESRCH);
}

#[test]
fn a_vfork_clone_sleeps_until_the_child_exits() {
    let mut h = Harness::new(LinuxAbi::Aarch64);
    let args = clone_args(LinuxAbi::Aarch64, THREAD | CLONE_VFORK, 0, 0, 0, 0);
    assert_eq!(h.start(0, Sysno::Clone, &args), None);
    assert_eq!(h.proc.threads.len(), 2);
    let child = h.proc.threads[1].tid;
    // An ordinary signal does not end the wait.
    handle(&mut h, SIGUSR1);
    h.proc.threads[0].sigpending = true;
    assert_eq!(h.proc.wake_sleepers(), 0);
    assert_eq!(h.start(1, Sysno::Exit, &[0]), None);
    assert_eq!(h.proc.wake_sleepers(), 1);
    assert_eq!(h.result(0), child as i64);
}

/// The contents of a guest file, read by thread 0.
fn read_file(h: &mut Harness, path: &str) -> Vec<u8> {
    let at = h.scratch + 0x400;
    let mut p = path.as_bytes().to_vec();
    p.push(0);
    h.proc.state.space.write_raw(at, &p).unwrap();
    let fd = h.ok(Sysno::Openat, &[-100i64 as u64, at, 0, 0]);
    let buf = h.scratch + 0x600;
    let n = h.ok(Sysno::Read, &[fd, buf, 0x800]);
    h.ok(Sysno::Close, &[fd]);
    let mut out = vec![0u8; n as usize];
    h.proc.state.space.read(buf, &mut out).unwrap();
    out
}

#[test]
fn proc_shows_each_thread() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let (tid, w) = spawn(&mut h, 0, 0);
    let status = String::from_utf8(read_file(&mut h, "/proc/self/status")).unwrap();
    assert!(status.contains("Threads:\t2"), "{status}");
    let task =
        String::from_utf8(read_file(&mut h, &format!("/proc/self/task/{tid}/status"))).unwrap();
    assert!(task.contains(&format!("Pid:\t{tid}")), "{task}");
    // Names are per thread; another thread's is set through its comm file.
    let at = h.scratch + 0x400;
    let path = format!("/proc/self/task/{tid}/comm\0");
    h.proc.state.space.write_raw(at, path.as_bytes()).unwrap();
    let fd = h.ok(Sysno::Openat, &[-100i64 as u64, at, 1, 0]);
    let name = h.scratch + 0x500;
    h.proc
        .state
        .space
        .write_raw(name, b"a-worker-with-a-long-name")
        .unwrap();
    assert_eq!(h.ok(Sysno::Write, &[fd, name, 25]), 25);
    assert_eq!(h.proc.threads[w].comm, b"a-worker-with-a");
    let name2 = h.scratch + 0x540;
    h.proc.state.space.write_raw(name2, b"main\0").unwrap();
    h.ok(Sysno::Prctl, &[15, name2, 0, 0, 0]);
    assert_eq!(
        read_file(&mut h, &format!("/proc/self/task/{tid}/comm")),
        b"a-worker-with-a\n"
    );
    assert_eq!(read_file(&mut h, "/proc/thread-self/comm"), b"main\n");
    assert_eq!(read_file(&mut h, "/proc/self/comm"), b"main\n");
}

#[test]
fn unshare_follows_ksys_unshare() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let unshare = |h: &mut Harness, flags: u64| h.call(Sysno::Unshare, &[flags]);
        // Alone, nothing needs unsharing.
        assert_eq!(unshare(&mut h, 0), 0);
        let alone =
            CLONE_FILES | CLONE_FS | CLONE_SYSVSEM | CLONE_THREAD | CLONE_SIGHAND | CLONE_VM;
        assert_eq!(unshare(&mut h, alone), 0);
        // Unknown flags, before privilege.
        assert_eq!(unshare(&mut h, CLONE_SETTLS), neg(EINVAL));
        assert_eq!(unshare(&mut h, CLONE_SETTLS | CLONE_NEWNET), neg(EINVAL));
        assert_eq!(unshare(&mut h, 1 << 40), neg(EINVAL));
        // Namespaces need privileges.
        assert_eq!(unshare(&mut h, CLONE_NEWUSER), neg(EPERM));
        assert_eq!(unshare(&mut h, CLONE_NEWNS), neg(EPERM));
        assert_eq!(unshare(&mut h, CLONE_NEWTIME), neg(EPERM));
        // With another thread: the thread group, handlers, and address
        // space are shared, and so (here) are the tables; implied flags
        // count (CLONE_NEWUSER takes CLONE_THREAD before privilege).
        spawn(&mut h, 0, 0);
        assert_eq!(unshare(&mut h, 0), 0);
        assert_eq!(unshare(&mut h, CLONE_SYSVSEM), 0);
        for f in [CLONE_THREAD, CLONE_SIGHAND, CLONE_VM, CLONE_FILES, CLONE_FS] {
            assert_eq!(unshare(&mut h, f), neg(EINVAL), "{f:#x}");
        }
        assert_eq!(unshare(&mut h, CLONE_NEWUSER), neg(EINVAL));
        assert_eq!(unshare(&mut h, CLONE_NEWNS), neg(EINVAL));
        assert_eq!(unshare(&mut h, CLONE_NEWNET), neg(EPERM));
    });
}
