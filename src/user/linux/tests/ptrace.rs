//! Process tracing against `kernel/ptrace.c` and `kernel/signal.c` (Linux
//! 6.19) on every ABI, within one process: `ptrace`'s checks in order,
//! `PTRACE_TRACEME` and `TracerPid`, each architecture's general registers
//! as a tracer reads and writes them (x86-64's `struct user` too), the
//! signal-delivery-stop and the tracer's verdict on it (cancelled,
//! changed, requeued when blocked), a group stop, `execve`'s `SIGTRAP` and
//! event stop, ignored signals queued for a tracer, and a tracer's link
//! ending (the stopped thread goes on, or dies with `PTRACE_O_EXITKILL`),
//! and a tracer reading an answer together with the stop or the end that
//! follows it. The fixture `ptrace` covers tracing between two processes.

use super::harness::{Harness, each_abi};
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::{LinuxAbi, Sysno};
use crate::user::linux::arch::GuestCpu;
use crate::user::linux::process::Threads;
use crate::user::linux::ptrace::tracee::{self as pt, Verdict, parked, take_verdict};
use crate::user::linux::ptrace::{Link, LinkId, Msg, Resumption, StopKind, Traced, opt, regs};
use crate::user::linux::signal::deliver::SyscallEntry;
use crate::user::linux::signal::{
    SIG_IGN, SIGKILL, SIGSTOP, SIGTRAP, SIGUSR1, SIGUSR2, SigInfo, code, sigmask,
};

const TRACEME: u64 = 0;
const PEEKDATA: u64 = 2;
const KILL: u64 = 8;
const ATTACH: u64 = 16;
const SEIZE: u64 = 0x4206;

fn e(errno: i32) -> i64 {
    -(errno as i64)
}

/// Makes thread 0 traced by a tracer with no link (its stops wait).
fn traced(h: &mut Harness, options: u64) {
    h.proc.threads[0].ptrace = Some(Traced::new(4242, LinkId::Parent, false, options));
}

fn send(h: &mut Harness, info: SigInfo) {
    let state = &mut h.proc.state;
    let mut th = Threads::split(&mut h.proc.threads, None);
    let tid = th.iter().next().unwrap().tid;
    crate::user::linux::signal::deliver::send_signal(
        state,
        &mut th,
        info,
        crate::user::linux::signal::deliver::Dest::Thread(tid),
        false,
    );
}

fn resume(h: &mut Harness, sig: i32) {
    let s = h.proc.threads[0]
        .ptrace
        .as_mut()
        .unwrap()
        .stop
        .as_mut()
        .unwrap();
    s.resumed = Some(Resumption::Continue(sig));
}

#[test]
fn requests_check_in_the_kernels_order() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let me = h.proc.threads[0].tid as u64;
        let buf = h.scratch;
        // A task that does not exist, then (for another) one out of reach
        // or not traced.
        assert_eq!(h.call(Sysno::Ptrace, &[PEEKDATA, 0, buf, buf]), e(ESRCH));
        assert_eq!(
            h.call(Sysno::Ptrace, &[PEEKDATA, 0x7fff_fff, buf, buf]),
            e(ESRCH)
        );
        assert_eq!(h.call(Sysno::Ptrace, &[ATTACH, 0x7fff_fff, 0, 0]), e(ESRCH));
        assert_eq!(
            h.call(Sysno::Ptrace, &[PEEKDATA, me, buf, buf]),
            e(ESRCH),
            "not traced"
        );
        // The caller's own process, even with PTRACE_SEIZE's bad address
        // or options (they come first).
        assert_eq!(h.call(Sysno::Ptrace, &[ATTACH, me, 0, 0]), e(EPERM));
        assert_eq!(h.call(Sysno::Ptrace, &[SEIZE, me, 1, 0]), e(EIO));
        assert_eq!(h.call(Sysno::Ptrace, &[SEIZE, me, 0, 0x40_0000]), e(EIO));
        assert_eq!(
            h.call(Sysno::Ptrace, &[SEIZE, me, 0, opt::SUSPEND_SECCOMP]),
            e(EINVAL)
        );
        assert_eq!(
            h.call(Sysno::Ptrace, &[SEIZE, me, 0, opt::EXITKILL]),
            e(EPERM)
        );
        // Another process with no link to this one is out of reach.
        let init = 1u64;
        assert_eq!(h.call(Sysno::Ptrace, &[ATTACH, init, 0, 0]), e(EPERM));
    });
}

#[test]
fn traceme_once_and_tracer_pid() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        assert_eq!(h.call(Sysno::Ptrace, &[TRACEME, 0, 0, 0]), 0);
        assert_eq!(h.call(Sysno::Ptrace, &[TRACEME, 0, 0, 0]), e(EPERM));
        let ppid = h.proc.state.ppid;
        let t = &h.proc.threads[0];
        assert_eq!(pt::tracer_pid(t), ppid.max(0));
        let status = crate::user::linux::procfs::status(&h.proc.state, t, 1);
        let text = String::from_utf8(status).unwrap();
        assert!(
            text.contains(&format!("TracerPid:\t{}\n", ppid.max(0))),
            "{text}"
        );
    });
}

/// The general registers each tracer sees, and what writing them may do.
#[test]
fn general_registers_as_each_architecture_lays_them_out() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let t = &mut h.proc.threads[0];
        t.cpu.set_pc(0x40_1234);
        t.cpu.set_sp(0x7fff_0000);
        let syscall = Some(SyscallEntry { nr: 62, arg0: 5 });
        let b = regs::prstatus(&t.cpu, syscall);
        let word = |i: usize| u64::from_le_bytes(b[8 * i..8 * i + 8].try_into().unwrap());
        let (size, pc, sp) = match abi {
            LinuxAbi::X86_64 => (216, 16, 19),
            LinuxAbi::Aarch64 => (272, 32, 31),
            LinuxAbi::Riscv64 => (256, 0, 2),
        };
        assert_eq!(b.len(), size);
        assert_eq!(regs::prstatus_size(&t.cpu), size);
        assert_eq!((word(pc), word(sp)), (0x40_1234, 0x7fff_0000));
        // Written back unchanged: nothing moves.
        let mut sc = syscall;
        regs::set_prstatus(&mut t.cpu, &mut sc, &b).unwrap();
        assert_eq!(regs::prstatus(&t.cpu, sc), b);
        // A new PC through the set.
        let mut moved = b.clone();
        moved[8 * pc..8 * pc + 8].copy_from_slice(&0x40_2000u64.to_le_bytes());
        regs::set_prstatus(&mut t.cpu, &mut sc, &moved).unwrap();
        assert_eq!(t.cpu.pc(), 0x40_2000);
        match abi {
            LinuxAbi::X86_64 => {
                assert_eq!(word(15), 62, "orig_rax");
                assert_eq!((word(17), word(20)), (0x33, 0x2b), "cs, ss");
                assert_eq!(
                    regs::prstatus(&t.cpu, None)[15 * 8..16 * 8],
                    u64::MAX.to_le_bytes()
                );
            }
            LinuxAbi::Aarch64 => {
                // A PSTATE that is not EL0t with DAIF clear: EINVAL, and
                // nothing written.
                let mut bad = b.clone();
                bad[33 * 8..34 * 8].copy_from_slice(&0x3c5u64.to_le_bytes());
                bad[32 * 8..33 * 8].copy_from_slice(&0x9999u64.to_le_bytes());
                assert_eq!(
                    regs::set_prstatus(&mut t.cpu, &mut sc, &bad),
                    Err(crate::user::linux::abi::errno::Errno(EINVAL))
                );
                assert_eq!(t.cpu.pc(), 0x40_2000);
            }
            LinuxAbi::Riscv64 => {}
        }
    });
}

#[test]
fn x86_64_user_area_checks_what_putreg_checks() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let t = &mut h.proc.threads[0];
    let mut sc = Some(SyscallEntry { nr: 1, arg0: 0 });
    let eio = crate::user::linux::abi::errno::Errno(EIO);
    // Offsets: aligned, within struct user (928 bytes).
    assert_eq!(regs::peek_user(&t.cpu, sc, 4).err(), Some(eio));
    assert_eq!(regs::peek_user(&t.cpu, sc, 928).err(), Some(eio));
    assert_eq!(regs::peek_user(&t.cpu, sc, 848), Ok(0), "u_debugreg[0]");
    assert_eq!(regs::peek_user(&t.cpu, sc, 15 * 8), Ok(1), "orig_rax");
    // Selectors of user privilege, never a null CS or SS; bases within
    // user space; debug registers only zero here.
    assert_eq!(
        regs::poke_user(&mut t.cpu, &mut sc, 17 * 8, 0).err(),
        Some(eio)
    );
    assert_eq!(
        regs::poke_user(&mut t.cpu, &mut sc, 17 * 8, 0x30).err(),
        Some(eio)
    );
    assert_eq!(regs::poke_user(&mut t.cpu, &mut sc, 17 * 8, 0x33), Ok(()));
    assert_eq!(regs::poke_user(&mut t.cpu, &mut sc, 23 * 8, 0), Ok(()));
    assert_eq!(
        regs::poke_user(&mut t.cpu, &mut sc, 21 * 8, 1 << 47).err(),
        Some(eio)
    );
    assert_eq!(regs::poke_user(&mut t.cpu, &mut sc, 21 * 8, 0x1000), Ok(()));
    assert_eq!(regs::peek_user(&t.cpu, sc, 21 * 8), Ok(0x1000));
    assert_eq!(
        regs::poke_user(&mut t.cpu, &mut sc, 848 + 8 * 7, 1).err(),
        Some(eio)
    );
    assert_eq!(regs::poke_user(&mut t.cpu, &mut sc, 848 + 8 * 7, 0), Ok(()));
    // EFLAGS: only the bits a tracer may change (FLAG_MASK: CF PF AF ZF
    // SF TF DF OF NT RF AC).
    const FLAG_MASK: u64 = 0x5_4dd5;
    let before = regs::peek_user(&t.cpu, sc, 18 * 8).unwrap();
    assert_eq!(
        regs::poke_user(&mut t.cpu, &mut sc, 18 * 8, u64::MAX),
        Ok(())
    );
    assert_eq!(
        regs::peek_user(&t.cpu, sc, 18 * 8),
        Ok((before & !FLAG_MASK) | FLAG_MASK)
    );
    assert_eq!(regs::poke_user(&mut t.cpu, &mut sc, 18 * 8, 0), Ok(()));
    assert_eq!(
        regs::peek_user(&t.cpu, sc, 18 * 8),
        Ok(before & !FLAG_MASK | 0x2)
    );
    // orig_rax: -1 leaves the call; a number is one.
    assert_eq!(
        regs::poke_user(&mut t.cpu, &mut sc, 15 * 8, u64::MAX),
        Ok(())
    );
    assert!(sc.is_none());
    // Other architectures have no user area.
    let h = Harness::new(LinuxAbi::Aarch64);
    assert_eq!(
        regs::peek_user(&h.proc.threads[0].cpu, None, 0).err(),
        Some(eio)
    );
    assert!(matches!(h.proc.threads[0].cpu, GuestCpu::Aarch64(_)));
}

#[test]
fn a_traced_thread_stops_before_taking_a_signal() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        traced(&mut h, 0);
        let me = h.proc.state.pid;
        // Cancelled: the handler never sees it.
        send(&mut h, SigInfo::kill(SIGUSR1, code::SI_USER, me, 0));
        h.proc.deliver_signals(0);
        assert!(parked(&h.proc.threads[0]));
        let stop = h.proc.threads[0]
            .ptrace
            .as_ref()
            .unwrap()
            .stop
            .clone()
            .unwrap();
        assert_eq!((stop.code, stop.info.unwrap().signo), (SIGUSR1, SIGUSR1));
        resume(&mut h, 0);
        assert!(!parked(&h.proc.threads[0]));
        let (p, t) = (&h.proc.state, &mut h.proc.threads[0]);
        assert_eq!(take_verdict(p, t), Some(Verdict::Drop));
        // Changed: the siginfo is rewritten as sent by the tracer.
        send(&mut h, SigInfo::kill(SIGUSR1, code::SI_USER, me, 0));
        h.proc.deliver_signals(0);
        resume(&mut h, SIGUSR2);
        let (p, t) = (&h.proc.state, &mut h.proc.threads[0]);
        let Some(Verdict::Deliver(info)) = take_verdict(p, t) else {
            panic!("a signal to deliver");
        };
        assert_eq!((info.signo, info.code), (SIGUSR2, code::SI_USER));
        // Left as it was, but now blocked: requeued for later.
        send(&mut h, SigInfo::kill(SIGUSR1, code::SI_USER, me, 0));
        h.proc.deliver_signals(0);
        h.proc.threads[0].sigmask = sigmask(SIGUSR1);
        resume(&mut h, SIGUSR1);
        h.proc.deliver_signals(0);
        assert!(!parked(&h.proc.threads[0]));
        assert!(h.proc.threads[0].pending.contains(SIGUSR1));
        // SIGKILL is never stopped for.
        h.proc.threads[0].sigmask = 0;
        h.proc.threads[0].pending = Default::default();
        send(&mut h, SigInfo::kernel(SIGKILL));
        h.proc.deliver_signals(0);
        assert!(!parked(&h.proc.threads[0]));
        assert!(h.proc.state.exit.is_some());
    });
}

#[test]
fn traced_threads_queue_ignored_signals_and_trap_group_stops() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        h.proc.state.sigactions[(SIGUSR1 - 1) as usize].handler = SIG_IGN;
        let me = h.proc.state.pid;
        send(&mut h, SigInfo::kill(SIGUSR1, code::SI_USER, me, 0));
        assert!(!h.proc.threads[0].pending.contains(SIGUSR1), "dropped");
        traced(&mut h, 0);
        send(&mut h, SigInfo::kill(SIGUSR1, code::SI_USER, me, 0));
        assert!(
            h.proc.threads[0].pending.contains(SIGUSR1),
            "the tracer sees it"
        );
        h.proc.threads[0].pending = Default::default();
        // A stop signal the tracer lets through: a group stop the tracer is
        // told of, with no siginfo.
        send(&mut h, SigInfo::kernel(SIGSTOP));
        h.proc.deliver_signals(0);
        resume(&mut h, SIGSTOP);
        h.proc.deliver_signals(0);
        let stop = h.proc.threads[0]
            .ptrace
            .as_ref()
            .unwrap()
            .stop
            .clone()
            .unwrap();
        assert_eq!((stop.code, stop.kind), (SIGSTOP, StopKind::Quiet));
        assert!(stop.info.is_none());
        resume(&mut h, SIGUSR2);
        h.proc.deliver_signals(0);
        assert!(!parked(&h.proc.threads[0]));
        assert!(
            !h.proc.threads[0].pending.contains(SIGUSR2),
            "a group stop's signal is not sent"
        );
    });
}

#[test]
fn execve_stops_a_traced_thread() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        // Traced (not seized): the thread sends itself SIGTRAP.
        traced(&mut h, 0);
        let (p, t) = (&mut h.proc.state, &mut h.proc.threads[0]);
        pt::exec_event(p, t, 77);
        assert!(t.pending.contains(SIGTRAP));
        // PTRACE_O_TRACEEXEC: an event stop, the old thread ID as message.
        t.pending = Default::default();
        t.ptrace = Some(Traced::new(4242, LinkId::Parent, false, opt::TRACEEXEC));
        pt::exec_event(p, t, 77);
        let tr = t.ptrace.as_ref().unwrap();
        assert_eq!(tr.message, 77);
        assert_eq!(tr.stop.as_ref().unwrap().code, SIGTRAP | (4 << 8));
        assert!(!t.pending.contains(SIGTRAP));
        // Seized, without the option: nothing.
        t.ptrace = Some(Traced::new(4242, LinkId::Parent, true, 0));
        pt::exec_event(p, t, 77);
        assert!(!t.pending.contains(SIGTRAP));
        assert!(t.ptrace.as_ref().unwrap().stop.is_none());
    });
}

#[test]
fn a_tracers_link_ending_detaches_or_kills() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let (mine, theirs) = Link::pair().unwrap();
        h.proc.state.parent_link = Some(mine);
        traced(&mut h, 0);
        let me = h.proc.state.pid;
        send(&mut h, SigInfo::kill(SIGUSR1, code::SI_USER, me, 0));
        h.proc.deliver_signals(0);
        assert!(parked(&h.proc.threads[0]));
        drop(theirs);
        h.proc.collect_async(None);
        // exit_ptrace: it goes on with the signal it stopped for, and is
        // traced no more.
        assert!(!parked(&h.proc.threads[0]));
        let (p, t) = (&h.proc.state, &mut h.proc.threads[0]);
        let Some(Verdict::Deliver(info)) = take_verdict(p, t) else {
            panic!("the signal it stopped for");
        };
        assert_eq!(info.signo, SIGUSR1);
        assert!(t.ptrace.is_none());
        // With PTRACE_O_EXITKILL the tracee dies.
        let mut h = Harness::new(abi);
        let (mine, theirs) = Link::pair().unwrap();
        h.proc.state.parent_link = Some(mine);
        traced(&mut h, opt::EXITKILL);
        drop(theirs);
        h.proc.collect_async(None);
        assert!(h.proc.threads[0].pending.contains(SIGKILL) || h.proc.state.exit.is_some());
    });
}

/// The messages that arrived on `link`, waiting for at least one.
fn recv_some(link: &mut Link) -> Vec<Msg> {
    loop {
        let got = link.recv();
        if !got.is_empty() || link.closed {
            return got;
        }
        std::thread::yield_now();
    }
}

/// A tracee stops as soon as it answers an attach, and may die as soon as
/// it answers a request: the tracer reads the answer with what follows it
/// (the stop, the link's end) and loses neither.
#[test]
fn answers_and_what_follows_them_arrive_together() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let (mine, mut theirs) = Link::pair().unwrap();
        h.proc.state.parent_link = Some(mine);
        let parent = h.proc.state.ppid;
        assert_eq!(
            h.start(0, Sysno::Ptrace, &[ATTACH, parent as u64, 0, 0]),
            None
        );
        assert!(matches!(recv_some(&mut theirs)[..], [Msg::Attach { .. }]));
        assert!(theirs.send(&Msg::Reply {
            ret: 0,
            payload: Vec::new()
        }));
        assert!(theirs.send(&Msg::Stop {
            tid: parent,
            code: SIGSTOP
        }));
        assert_eq!(h.proc.wake_sleepers(), 1);
        assert_eq!(h.result(0), 0);
        let tracee = h.proc.state.tracees.get(parent).unwrap();
        assert_eq!(tracee.stopped, Some(SIGSTOP), "the stop that came along");
        // PTRACE_KILL answered, then the tracee's end.
        assert_eq!(
            h.start(0, Sysno::Ptrace, &[KILL, parent as u64, 0, 0]),
            None
        );
        assert!(matches!(recv_some(&mut theirs)[..], [Msg::Request { .. }]));
        assert!(theirs.send(&Msg::Reply {
            ret: 0,
            payload: Vec::new()
        }));
        drop(theirs);
        assert_eq!(h.proc.wake_sleepers(), 1);
        assert_eq!(h.result(0), 0, "the answer that came before the end");
    });
}
