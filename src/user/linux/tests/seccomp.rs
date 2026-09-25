//! Seccomp against `kernel/seccomp.c` (Linux 6.19), through the system
//! calls on every ABI: installing filters (the checks in order), what
//! filters decide and what they see, `SECCOMP_RET_TRAP`'s `SIGSYS`, the
//! kill actions against the number of threads, strict mode,
//! `SECCOMP_FILTER_FLAG_TSYNC`, and x86-64 `INT 0x80` calls.

use super::harness::{CODE, Harness, P, each_abi};
use crate::user::linux::ExitStatus;
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::{AUDIT_ARCH_I386, LinuxAbi, Sysno};
use crate::user::linux::arch::CpuEvent;
use crate::user::linux::process::Peers;
use crate::user::linux::seccomp::bpf::*;
use crate::user::linux::seccomp::*;
use crate::user::linux::signal::*;
use crate::user::linux::syscall::thread::cf::*;
use crate::user::linux::syscall::{Outcome, dispatch_compat};

const SET_MODE_STRICT: u64 = 0;
const SET_MODE_FILTER: u64 = 1;
const GET_ACTION_AVAIL: u64 = 2;
const GET_NOTIF_SIZES: u64 = 3;
const TSYNC: u64 = 1;
const LOG: u64 = 2;
const NEW_LISTENER: u64 = 8;
const TSYNC_ESRCH: u64 = 16;
const PR_SET_NO_NEW_PRIVS: u64 = 38;
const PR_GET_NO_NEW_PRIVS: u64 = 39;
const PR_GET_SECCOMP: u64 = 21;
const PR_SET_SECCOMP: u64 = 22;
const THREAD: u64 = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD;

fn stmt(code: u16, k: u32) -> Insn {
    Insn {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jeq(k: u32, jt: u8, jf: u8) -> Insn {
    Insn {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt,
        jf,
        k,
    }
}

fn ld(off: u32) -> Insn {
    stmt(BPF_LD | BPF_W | BPF_ABS, off)
}

fn ret(k: u32) -> Insn {
    stmt(BPF_RET | BPF_K, k)
}

fn nr(h: &Harness, s: Sysno) -> u32 {
    h.abi().number(s).unwrap() as u32
}

/// Returns `hit` for call `s`, `RET_ALLOW` for the others.
pub(super) fn on(h: &Harness, s: Sysno, hit: u32) -> Vec<Insn> {
    vec![ld(0), jeq(nr(h, s), 0, 1), ret(hit), ret(RET_ALLOW)]
}

fn encode(prog: &[Insn]) -> Vec<u8> {
    prog.iter()
        .flat_map(|i| {
            let mut b = i.code.to_le_bytes().to_vec();
            b.extend([i.jt, i.jf]);
            b.extend(i.k.to_le_bytes());
            b
        })
        .collect()
}

/// Writes `prog` and its `struct sock_fprog` to `at`; returns the
/// `sock_fprog` address.
pub(super) fn fprog(h: &Harness, at: u64, prog: &[Insn]) -> u64 {
    let insns = at + 16;
    let mut b = (prog.len() as u16).to_le_bytes().to_vec();
    b.extend([0u8; 6]);
    b.extend(insns.to_le_bytes());
    b.extend(encode(prog));
    h.proc.state.space.write_raw(at, &b).unwrap();
    at
}

pub(super) fn nnp(h: &mut Harness) {
    h.ok(Sysno::Prctl, &[PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0]);
}

/// Installs `prog` with `flags`: the raw result.
fn install(h: &mut Harness, at: u64, flags: u64, prog: &[Insn]) -> i64 {
    let f = fprog(h, at, prog);
    h.call(Sysno::Seccomp, &[SET_MODE_FILTER, flags, f])
}

fn root() -> bool {
    // SAFETY: geteuid has no failure mode.
    unsafe { libc::geteuid() == 0 }
}

#[test]
fn installing_follows_seccomp_set_mode_filter() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = h.anon(16 * P, 3, false);
        let allow = [ret(RET_ALLOW)];
        let f = fprog(&h, m, &allow);
        // The operation and its flags.
        assert_eq!(h.err(Sysno::Seccomp, &[4, 0, 0]), EINVAL);
        assert_eq!(h.err(Sysno::Seccomp, &[SET_MODE_STRICT, 1, 0]), EINVAL);
        assert_eq!(h.err(Sysno::Seccomp, &[SET_MODE_STRICT, 0, f]), EINVAL);
        assert_eq!(h.err(Sysno::Seccomp, &[SET_MODE_FILTER, 0x40, f]), EINVAL);
        assert_eq!(
            h.err(Sysno::Seccomp, &[SET_MODE_FILTER, NEW_LISTENER, f]),
            EINVAL
        );
        assert_eq!(h.err(Sysno::Seccomp, &[SET_MODE_FILTER, 32, f]), EINVAL);
        // sock_fprog, then its length, then no_new_privs, then the program.
        assert_eq!(h.err(Sysno::Seccomp, &[SET_MODE_FILTER, 0, 8]), EFAULT);
        let empty = fprog(&h, m + P, &[]);
        assert_eq!(h.err(Sysno::Seccomp, &[SET_MODE_FILTER, 0, empty]), EINVAL);
        h.proc
            .state
            .space
            .write_raw(m + 2 * P, &4097u16.to_le_bytes())
            .unwrap();
        assert_eq!(
            h.err(Sysno::Seccomp, &[SET_MODE_FILTER, 0, m + 2 * P]),
            EINVAL
        );
        if !root() {
            assert_eq!(h.err(Sysno::Seccomp, &[SET_MODE_FILTER, 0, f]), EACCES);
        }
        assert_eq!(h.call(Sysno::Prctl, &[PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0]), 0);
        assert_eq!(
            h.err(Sysno::Prctl, &[PR_SET_NO_NEW_PRIVS, 1, 0, 0, 1]),
            EINVAL
        );
        nnp(&mut h);
        assert_eq!(
            h.err(Sysno::Prctl, &[PR_GET_NO_NEW_PRIVS, 0, 0, 1, 0]),
            EINVAL
        );
        assert_eq!(h.call(Sysno::Prctl, &[PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0]), 1);
        // A NULL program, an unreadable one, and ones the checks reject:
        // no final return, a load past seccomp_data, a jump out.
        let mut null = vec![1u8, 0, 0, 0, 0, 0, 0, 0];
        null.extend(0u64.to_le_bytes());
        h.proc.state.space.write_raw(m + 3 * P, &null).unwrap();
        assert_eq!(
            h.err(Sysno::Seccomp, &[SET_MODE_FILTER, 0, m + 3 * P]),
            EINVAL
        );
        let mut far = vec![1u8, 0, 0, 0, 0, 0, 0, 0];
        far.extend(8u64.to_le_bytes());
        h.proc.state.space.write_raw(m + 3 * P, &far).unwrap();
        assert_eq!(
            h.err(Sysno::Seccomp, &[SET_MODE_FILTER, 0, m + 3 * P]),
            EFAULT
        );
        for bad in [
            vec![ld(0)],
            vec![ld(64), ret(RET_ALLOW)],
            vec![jeq(0, 5, 0), ret(RET_ALLOW)],
        ] {
            assert_eq!(install(&mut h, m + 4 * P, 0, &bad), -(EINVAL as i64));
        }
        assert_eq!(h.call(Sysno::Prctl, &[PR_GET_SECCOMP, 0, 0, 0, 0]), 0);
        assert_eq!(install(&mut h, m + 4 * P, LOG, &allow), 0);
        assert_eq!(h.call(Sysno::Prctl, &[PR_GET_SECCOMP, 0, 0, 0, 0]), 2);
        // Once filtering, never strict.
        assert_eq!(h.err(Sysno::Seccomp, &[SET_MODE_STRICT, 0, 0]), EINVAL);
        assert_eq!(h.err(Sysno::Prctl, &[PR_SET_SECCOMP, 1, 0, 0, 0]), EINVAL);
        assert_eq!(h.err(Sysno::Prctl, &[PR_SET_SECCOMP, 3, 0, 0, 0]), EINVAL);
        assert_eq!(h.call(Sysno::Prctl, &[PR_SET_SECCOMP, 2, f, 0, 0]), 0);
        let status = crate::user::linux::procfs::status(&h.proc.state, &h.proc.threads[0], 1);
        let status = String::from_utf8(status).unwrap();
        assert!(
            status.contains("NoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t2\n"),
            "{status}"
        );
        // The actions a filter may return, and the notification sizes.
        let a = m + 5 * P;
        for (action, want) in [
            (RET_KILL_PROCESS, 0),
            (RET_KILL_THREAD, 0),
            (RET_TRAP, 0),
            (RET_ERRNO, 0),
            (RET_USER_NOTIF, 0),
            (RET_TRACE, 0),
            (RET_LOG, 0),
            (RET_ALLOW, 0),
            (0x0001_0000, -(EOPNOTSUPP as i64)),
            (RET_ERRNO | 1, -(EOPNOTSUPP as i64)),
        ] {
            h.proc
                .state
                .space
                .write_raw(a, &action.to_le_bytes())
                .unwrap();
            assert_eq!(h.call(Sysno::Seccomp, &[GET_ACTION_AVAIL, 0, a]), want);
        }
        assert_eq!(h.err(Sysno::Seccomp, &[GET_ACTION_AVAIL, 1, a]), EINVAL);
        assert_eq!(h.err(Sysno::Seccomp, &[GET_ACTION_AVAIL, 0, 8]), EFAULT);
        assert_eq!(h.call(Sysno::Seccomp, &[GET_NOTIF_SIZES, 0, a]), 0);
        let mut sizes = [0u8; 6];
        h.proc.state.space.read(a, &mut sizes).unwrap();
        assert_eq!(sizes, [80, 0, 24, 0, 64, 0]);
        assert_eq!(h.err(Sysno::Seccomp, &[GET_NOTIF_SIZES, 1, a]), EINVAL);
        assert_eq!(h.err(Sysno::Seccomp, &[GET_NOTIF_SIZES, 0, 8]), EFAULT);
    });
}

#[test]
fn chains_are_bounded_by_max_insns_per_path() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = h.anon(16 * P, 3, false);
        nnp(&mut h);
        // Lengths count as converted to eBPF: 4096 returns of K are
        // 3 + 2 * 4096 = 8195, and 3 * (8195 + 4) + 8195 > 32768.
        let big = vec![ret(RET_ALLOW); BPF_MAXINSNS];
        for _ in 0..3 {
            assert_eq!(install(&mut h, m, 0, &big), 0);
        }
        assert_eq!(install(&mut h, m, 0, &big), -(ENOMEM as i64));
        // 32768 - 3 * 8199 = 8171 = 3 + 2 * 4084; one more is too many.
        let mut last = vec![ret(RET_ALLOW); 4084];
        last.push(stmt(BPF_RET | BPF_A, 0));
        assert_eq!(install(&mut h, m, 0, &last), -(ENOMEM as i64));
        last.pop();
        assert_eq!(install(&mut h, m, 0, &last), 0);
        assert_eq!(h.proc.threads[0].seccomp.count(), 4);
    });
}

#[test]
fn filters_see_seccomp_data_and_decide() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = h.anon(4 * P, 3, false);
        nnp(&mut h);
        let arch = abi.audit_arch();
        // Other architectures die; getpid returns ip & 0xFFF as its errno;
        // write to fd 2 fails with the capped errno; getppid returns its
        // second argument's high word.
        let prog = vec![
            ld(4),
            jeq(arch, 1, 0),
            ret(RET_KILL_PROCESS),
            ld(0),
            jeq(nr(&h, Sysno::Getpid), 0, 4),
            ld(8),
            stmt(BPF_ALU | BPF_AND | BPF_K, 0xFFF),
            stmt(BPF_ALU | BPF_OR | BPF_K, RET_ERRNO),
            stmt(BPF_RET | BPF_A, 0),
            jeq(nr(&h, Sysno::Write), 0, 4),
            ld(16),
            jeq(2, 0, 1),
            ret(RET_ERRNO | 0xFFFF),
            ret(RET_ALLOW),
            jeq(nr(&h, Sysno::Getppid), 0, 2),
            ld(28),
            stmt(BPF_RET | BPF_A, 0),
            ret(RET_ALLOW),
        ];
        assert_eq!(install(&mut h, m, 0, &prog), 0);
        // seccomp_data.ip: the address after the calling instruction.
        h.proc.threads[0].cpu.set_pc(0x40_1ABC);
        assert_eq!(h.err(Sysno::Getpid, &[]), 0xABC);
        assert_eq!(h.err(Sysno::Write, &[2, m, 0]), 4095);
        assert_eq!(h.call(Sysno::Write, &[1, m, 0]), 0);
        // args[1] high word: offset 16 + 8 + 4.
        assert_eq!(h.err(Sysno::Getppid, &[0, (RET_ERRNO as u64 | 7) << 32]), 7);
        assert!(h.call(Sysno::Getppid, &[0, (RET_ALLOW as u64) << 32]) >= 0);
        assert!(h.call(Sysno::Gettid, &[]) > 0);
        // A second filter: the lowest action wins, errno 0 is a success
        // that skips the call.
        let second = on(&h, Sysno::Gettid, RET_ERRNO);
        assert_eq!(install(&mut h, m + P, 0, &second), 0);
        assert_eq!(h.call(Sysno::Gettid, &[]), 0);
        // Tracing without a tracer, and notification without a listener.
        let third = on(&h, Sysno::Getuid, RET_TRACE);
        assert_eq!(install(&mut h, m + P, 0, &third), 0);
        assert_eq!(h.err(Sysno::Getuid, &[]), ENOSYS);
        let fourth = on(&h, Sysno::Getgid, RET_USER_NOTIF);
        assert_eq!(install(&mut h, m + P, 0, &fourth), 0);
        assert_eq!(h.err(Sysno::Getgid, &[]), ENOSYS);
        // Numbers the ABI does not define reach the filters too.
        let n = 0x7777u64;
        let fifth = vec![
            ld(0),
            jeq(n as u32, 0, 1),
            ret(RET_ERRNO | 5),
            ret(RET_ALLOW),
        ];
        assert_eq!(install(&mut h, m + P, 0, &fifth), 0);
        assert_eq!(
            h.proc.dispatch_to_completion(0, n, [0; 6]),
            Outcome::Return(-5i64 as u64)
        );
    });
}

#[test]
fn traps_raise_sigsys_with_the_call() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = h.anon(4 * P, 3, false);
        nnp(&mut h);
        let prog = on(&h, Sysno::Getpid, RET_TRAP | 0x1234);
        assert_eq!(install(&mut h, m, 0, &prog), 0);
        // Blocked, SIGSYS is unblocked; the result register is untouched.
        h.proc.threads[0].sigmask = sigmask(SIGSYS);
        h.proc.threads[0].cpu.set_syscall_result(0xDEAD);
        let ip = h.proc.threads[0].cpu.pc();
        assert_eq!(h.start(0, Sysno::Getpid, &[]), Some(0xDEAD));
        let t = &mut h.proc.threads[0];
        assert_eq!(t.sigmask & sigmask(SIGSYS), 0);
        let info = t.pending.dequeue(0).expect("SIGSYS pending");
        assert_eq!(info.signo, SIGSYS);
        assert_eq!(info.code, code::SYS_SECCOMP);
        assert_eq!(info.errno, 0x1234);
        assert_eq!(info.addr(), ip);
        let b = info.encode();
        assert_eq!(
            i32::from_le_bytes(b[24..28].try_into().unwrap()),
            abi.number(Sysno::Getpid).unwrap() as i32
        );
        assert_eq!(
            u32::from_le_bytes(b[28..32].try_into().unwrap()),
            abi.audit_arch()
        );
    });
}

#[test]
fn kills_follow_the_number_of_threads() {
    each_abi(|abi| {
        // KILL_THREAD ends a thread that has others alone, and the last
        // thread with the process (SIGSYS, which dumps core).
        let mut h = Harness::new(abi);
        let m = h.anon(4 * P, 3, false);
        nnp(&mut h);
        let prog = on(&h, Sysno::Getpid, RET_KILL_THREAD);
        assert_eq!(install(&mut h, m, 0, &prog), 0);
        let tid = h.ok(Sysno::Clone, &[THREAD, 0, 0, 0, 0]) as i32;
        let w = h.index_of(tid);
        assert_eq!(h.start(w, Sysno::Getpid, &[]), None);
        assert_eq!(h.proc.threads.len(), 1);
        assert!(h.proc.state.exit.is_none());
        assert_eq!(h.dispatch(Sysno::Getpid, &[]), Outcome::Unchanged);
        assert_eq!(h.proc.threads[0].seccomp.mode, MODE_DEAD);
        h.proc.deliver_signals(0);
        assert!(matches!(
            h.proc.state.exit,
            Some(ExitStatus::Signaled { info, core: true, .. })
                if info.signo == SIGSYS && info.code == code::SYS_SECCOMP
        ));
        // KILL_PROCESS ends every thread, even with a handler.
        let mut h = Harness::new(abi);
        let m = h.anon(4 * P, 3, false);
        nnp(&mut h);
        let prog = on(&h, Sysno::Getpid, RET_KILL_PROCESS | 9);
        assert_eq!(install(&mut h, m, 0, &prog), 0);
        h.proc.state.sigactions[(SIGSYS - 1) as usize].handler = 0x40_1000;
        let tid = h.ok(Sysno::Clone, &[THREAD, 0, 0, 0, 0]) as i32;
        let w = h.index_of(tid);
        assert_eq!(h.start(w, Sysno::Getpid, &[]), Some(0));
        h.proc.deliver_signals(w);
        assert!(matches!(
            h.proc.state.exit,
            Some(ExitStatus::Signaled { info, core: true, .. })
                if info.signo == SIGSYS && info.errno == 9
        ));
    });
}

#[test]
fn strict_mode_allows_four_calls() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = h.anon(P, 3, false);
        let tid = h.ok(Sysno::Clone, &[THREAD, 0, 0, 0, 0]) as i32;
        let w = h.index_of(tid);
        assert_eq!(h.call(Sysno::Prctl, &[PR_SET_SECCOMP, 1, 0, 0, 0]), 0);
        assert_eq!(h.proc.threads[0].seccomp.mode, MODE_STRICT);
        // Only the caller: the other thread runs anything.
        assert!(h.start(w, Sysno::Getpid, &[]).is_some_and(|r| r > 0));
        assert_eq!(h.call(Sysno::Write, &[1, m, 0]), 0);
        assert_eq!(h.call(Sysno::Read, &[0, m, 0]), 0);
        // Anything else kills the caller alone with SIGKILL.
        assert_eq!(h.start(0, Sysno::Getpid, &[]), None);
        assert_eq!(h.proc.threads.len(), 1);
        assert!(h.proc.state.exit.is_none());
        // The last thread's death by SIGKILL is the process's.
        let w = h.index_of(tid);
        assert_eq!(
            h.start(w, Sysno::Prctl, &[PR_SET_SECCOMP, 1, 0, 0, 0]),
            Some(0)
        );
        assert_eq!(h.start(w, Sysno::Seccomp, &[SET_MODE_STRICT, 0, 0]), None);
        assert!(matches!(
            h.proc.state.exit,
            Some(ExitStatus::Signaled { info, core: false, .. }) if info.signo == SIGKILL
        ));
    });
}

#[test]
fn tsync_gives_every_thread_the_filters() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let m = h.anon(4 * P, 3, false);
        let tid = h.ok(Sysno::Clone, &[THREAD, 0, 0, 0, 0]) as i32;
        let w = h.index_of(tid);
        nnp(&mut h);
        assert!(!h.proc.threads[w].no_new_privs);
        // A new thread inherits the caller's filters and no_new_privs.
        let first = on(&h, Sysno::Getuid, RET_ERRNO | 1);
        assert_eq!(install(&mut h, m, 0, &first), 0);
        let tid2 = h.ok(Sysno::Clone, &[THREAD, 0, 0, 0, 0]) as i32;
        let w2 = h.index_of(tid2);
        assert!(h.proc.threads[w2].no_new_privs);
        assert_eq!(h.start(w2, Sysno::Getuid, &[]), Some(-1));
        // The first thread has no filters: TSYNC joins it, and gives it
        // no_new_privs.
        let second = on(&h, Sysno::Getgid, RET_ERRNO | 2);
        assert_eq!(install(&mut h, m + P, TSYNC, &second), 0);
        assert_eq!(h.proc.threads[w].seccomp.mode, MODE_FILTER);
        assert!(h.proc.threads[w].no_new_privs);
        assert_eq!(h.start(w, Sysno::Getgid, &[]), Some(-2));
        assert_eq!(h.start(w, Sysno::Getuid, &[]), Some(-1));
        // A thread whose filters are not the caller's ancestors stops it:
        // its TID, or ESRCH.
        let own = on(&h, Sysno::Getppid, RET_ERRNO | 3);
        let f = fprog(&h, m + 2 * P, &own);
        assert_eq!(
            h.start(w, Sysno::Seccomp, &[SET_MODE_FILTER, 0, f]),
            Some(0)
        );
        let third = on(&h, Sysno::Getegid, RET_ERRNO | 4);
        assert_eq!(install(&mut h, m + 3 * P, TSYNC, &third), tid as i64);
        assert_eq!(
            install(&mut h, m + 3 * P, TSYNC | TSYNC_ESRCH, &third),
            -(ESRCH as i64)
        );
        assert_eq!(h.proc.threads[0].seccomp.count(), 2);
        // Strict mode stops it too.
        let mut h = Harness::new(abi);
        let m = h.anon(P, 3, false);
        nnp(&mut h);
        let tid = h.ok(Sysno::Clone, &[THREAD, 0, 0, 0, 0]) as i32;
        let w = h.index_of(tid);
        assert_eq!(
            h.start(w, Sysno::Seccomp, &[SET_MODE_STRICT, 0, 0]),
            Some(0)
        );
        assert_eq!(install(&mut h, m, TSYNC, &[ret(RET_ALLOW)]), tid as i64);
    });
}

#[test]
fn calls_are_checked_once_as_they_enter() {
    each_abi(|abi| {
        // A call that sleeps is not checked again when it resumes, though
        // a filter installed meanwhile would refuse it.
        let mut h = Harness::new(abi);
        let m = h.anon(P, 3, false);
        nnp(&mut h);
        let tid = h.ok(Sysno::Clone, &[THREAD, 0, 0, 0, 0]) as i32;
        let w = h.index_of(tid);
        let fds = m;
        h.ok(Sysno::Pipe2, &[fds, 0]);
        let mut b = [0u8; 8];
        h.proc.state.space.read(fds, &mut b).unwrap();
        let (r, wr) = (
            u32::from_le_bytes(b[..4].try_into().unwrap()) as u64,
            u32::from_le_bytes(b[4..].try_into().unwrap()) as u64,
        );
        assert_eq!(h.start(w, Sysno::Read, &[r, m + 64, 1]), None);
        let deny = on(&h, Sysno::Read, RET_ERRNO | 1);
        assert_eq!(install(&mut h, m + 512, TSYNC, &deny), 0);
        assert_eq!(h.call(Sysno::Write, &[wr, m + 128, 1]), 1);
        std::thread::sleep(std::time::Duration::from_millis(5));
        h.proc.wake_sleepers();
        assert_eq!(h.result(w), 1);
        assert_eq!(h.start(w, Sysno::Read, &[r, m + 64, 1]), Some(-1));
    });
}

/// Runs `RDTSC; SYSCALL` at `CODE` on thread `idx`: whether `RDTSC`
/// completed (or faulted with `SIGSEGV`, `SI_KERNEL`, as #GP does).
fn rdtsc_runs(h: &mut Harness, idx: usize) -> bool {
    h.proc
        .state
        .space
        .write_raw(CODE, &[0x0F, 0x31, 0x0F, 0x05])
        .unwrap();
    let cpu = &mut h.proc.threads[idx].cpu;
    cpu.set_pc(CODE);
    match cpu.run(16) {
        CpuEvent::Syscall { .. } => true,
        CpuEvent::Signal(info, _) => {
            assert_eq!((info.signo, info.code), (SIGSEGV, code::SI_KERNEL));
            assert_eq!(h.proc.threads[idx].cpu.pc(), CODE);
            false
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn strict_mode_and_pr_set_tsc_disable_rdtsc_on_x86_64() {
    // x86 set_tsc_mode and get_tsc_mode; CR4.TSD makes RDTSC #GP at CPL3
    // (Intel SDM Vol. 2B, RDTSC).
    const PR_GET_TSC: u64 = 25;
    const PR_SET_TSC: u64 = 26;
    let mut h = Harness::new(LinuxAbi::X86_64);
    let m = h.anon(P, 3, false);
    assert!(rdtsc_runs(&mut h, 0));
    assert_eq!(h.call(Sysno::Prctl, &[PR_GET_TSC, m, 0, 0, 0]), 0);
    assert_eq!(h.byte(m), 1);
    assert_eq!(h.err(Sysno::Prctl, &[PR_GET_TSC, 8, 0, 0, 0]), EFAULT);
    assert_eq!(h.err(Sysno::Prctl, &[PR_SET_TSC, 3, 0, 0, 0]), EINVAL);
    assert_eq!(h.err(Sysno::Prctl, &[PR_SET_TSC, 0, 0, 0, 0]), EINVAL);
    // The mode is an unsigned int.
    assert_eq!(
        h.call(Sysno::Prctl, &[PR_SET_TSC, (1 << 32) | 2, 0, 0, 0]),
        0
    );
    assert!(!rdtsc_runs(&mut h, 0));
    h.call(Sysno::Prctl, &[PR_GET_TSC, m, 0, 0, 0]);
    assert_eq!(h.byte(m), 2);
    // Threads inherit it; it is per thread.
    let tid = h.ok(Sysno::Clone, &[THREAD, 0, 0, 0, 0]) as i32;
    let w = h.index_of(tid);
    assert!(!rdtsc_runs(&mut h, w));
    assert_eq!(h.call(Sysno::Prctl, &[PR_SET_TSC, 1, 0, 0, 0]), 0);
    assert!(rdtsc_runs(&mut h, 0));
    assert!(!rdtsc_runs(&mut h, w));
    // Strict mode disables it (disable_TSC).
    let mut h = Harness::new(LinuxAbi::X86_64);
    assert_eq!(h.call(Sysno::Seccomp, &[SET_MODE_STRICT, 0, 0]), 0);
    assert!(h.proc.threads[0].notsc);
    assert!(!rdtsc_runs(&mut h, 0));
    // Other architectures have neither prctl, nor TIF_NOTSC for strict
    // mode to set.
    for abi in [LinuxAbi::Aarch64, LinuxAbi::Riscv64] {
        let mut h = Harness::new(abi);
        let m = h.anon(P, 3, false);
        assert_eq!(h.err(Sysno::Prctl, &[PR_GET_TSC, m, 0, 0, 0]), EINVAL);
        assert_eq!(h.err(Sysno::Prctl, &[PR_SET_TSC, 2, 0, 0, 0]), EINVAL);
        assert_eq!(h.call(Sysno::Seccomp, &[SET_MODE_STRICT, 0, 0]), 0);
        assert!(!h.proc.threads[0].notsc);
    }
}

#[test]
fn int80_calls_are_checked_as_i386() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let m = h.anon(P, 3, false);
    nnp(&mut h);
    let prog = vec![
        ld(4),
        jeq(AUDIT_ARCH_I386, 0, 3),
        ld(0),
        jeq(20, 0, 1),
        ret(RET_ERRNO | 6),
        ret(RET_ALLOW),
    ];
    assert_eq!(install(&mut h, m, 0, &prog), 0);
    let mut compat = |nr: u64| {
        let t = &mut h.proc.threads[0];
        dispatch_compat(&mut h.proc.state, t, Peers::none(), nr, [0; 6], false)
    };
    // i386 getpid (20) is refused by the filter; other calls reach the
    // missing i386 table.
    assert_eq!(compat(20), Outcome::Return(-6i64 as u64));
    assert_eq!(compat(64), Outcome::Return(-(ENOSYS as i64) as u64));
    // Strict mode allows i386 read, write, exit, and sigreturn.
    let mut h = Harness::new(LinuxAbi::X86_64);
    assert_eq!(h.call(Sysno::Seccomp, &[SET_MODE_STRICT, 0, 0]), 0);
    let mut compat = |nr: u64| {
        let t = &mut h.proc.threads[0];
        dispatch_compat(&mut h.proc.state, t, Peers::none(), nr, [0; 6], false)
    };
    for nr in [3, 4, 1, 119] {
        assert_eq!(compat(nr), Outcome::Return(-(ENOSYS as i64) as u64));
    }
    assert_eq!(compat(0), Outcome::KillThread(SIGKILL));
}
