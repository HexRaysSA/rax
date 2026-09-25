//! System-call stops and single-stepping against the architectures'
//! system-call entry paths, `kernel/entry/syscall-common.c`, and
//! `kernel/ptrace.c` (Linux 6.19), on every ABI: the entry view (x86-64's
//! and RISC-V's `-ENOSYS`, AArch64's `x7`), `PTRACE_O_TRACESYSGOOD` and the
//! stops' messages, `PTRACE_GET_SYSCALL_INFO` and `PTRACE_SET_SYSCALL_INFO`,
//! a call changed or skipped at its entry stop, `PTRACE_SYSEMU` (the work
//! flags read before the stop), a system-call stop's signal sent from the
//! kernel, AArch64's `NT_ARM_SYSTEM_CALL`, one instruction per step with
//! each architecture's trap, a stepped system call's report, the stop as a
//! handler is entered, and RISC-V refusing to step. The tracer here speaks
//! over a real link, so the tracee answers as it does between processes;
//! the fixture `ptrace` covers two processes.

use super::harness::{CODE, Harness, each_abi};
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::{LinuxAbi, Sysno};
use crate::user::linux::arch::{CpuEvent, GuestCpu};
use crate::user::linux::ptrace::{Link, LinkId, Msg, StopKind, Traced, call, opt, regs, req};
use crate::user::linux::signal::{SIGSTOP, SIGTRAP, SIGUSR1, SigInfo, code, sa};
use crate::user::linux::syscall::ptrace::{mode, parked};

/// The tracer's end of thread 0's link to it.
pub(super) struct Tracer {
    pub(super) link: Link,
}

fn e(errno: i32) -> i64 {
    -(errno as i64)
}

/// Makes thread 0 traced along its parent link with `options`, stopped in
/// a signal-delivery-stop (`SIGSTOP`) so that the tracer can resume it.
pub(super) fn traced(h: &mut Harness, options: u64) -> Tracer {
    let (mine, theirs) = Link::pair().unwrap();
    h.proc.state.parent_link = Some(mine);
    let tracer = h.proc.state.ppid;
    h.proc.threads[0].ptrace = Some(Traced::new(tracer, LinkId::Parent, false, options));
    let me = h.proc.threads[0].tid;
    let mut th = crate::user::linux::process::Threads::split(&mut h.proc.threads, None);
    crate::user::linux::signal::deliver::send_signal(
        &mut h.proc.state,
        &mut th,
        SigInfo::kernel(SIGSTOP),
        crate::user::linux::signal::deliver::Dest::Thread(me),
        false,
    );
    h.proc.deliver_signals(0);
    assert!(parked(&h.proc.threads[0]));
    Tracer { link: theirs }
}

/// A request to thread 0 as its tracer makes it: the answer and its bytes.
pub(super) fn ask(
    h: &mut Harness,
    tr: &mut Tracer,
    request: u64,
    addr: u64,
    data: u64,
    payload: &[u8],
) -> (i64, Vec<u8>) {
    let tid = h.proc.threads[0].tid;
    let m = Msg::Request {
        tid,
        req: request,
        addr,
        data,
        payload: payload.to_vec(),
    };
    assert!(tr.link.send(&m));
    loop {
        h.proc.collect_async(None);
        for m in tr.link.recv() {
            if let Msg::Reply { ret, payload } = m {
                return (ret, payload);
            }
        }
    }
}

/// Resumes thread 0 with `request` and signal `sig`, and lets it take the
/// stop's verdict (as it would on its way back to user mode).
pub(super) fn resume(h: &mut Harness, tr: &mut Tracer, request: u64, sig: u64) -> i64 {
    let (ret, _) = ask(h, tr, request, 0, sig, &[]);
    if ret == 0 && !crate::user::linux::syscall::ptrace::resumed_in_call(&h.proc.threads[0]) {
        h.proc.deliver_signals(0);
    }
    ret
}

/// The stop thread 0 is in: its exit code, kind, and message.
fn stop(h: &Harness) -> (i32, StopKind, u64) {
    let tr = h.proc.threads[0].ptrace.as_ref().unwrap();
    let s = tr.stop.as_ref().expect("stopped");
    (s.code, s.kind, tr.message)
}

/// `PTRACE_GET_SYSCALL_INFO` with room for the whole structure.
fn info(h: &mut Harness, tr: &mut Tracer) -> (i64, Vec<u8>) {
    ask(h, tr, req::GET_SYSCALL_INFO, call::INFO_SIZE as u64, 0, &[])
}

fn word(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

/// A system call of thread 0 as its CPU reports it: the number and argument
/// registers set, then the entry.
fn make_call(h: &mut Harness, s: Sysno, args: [u64; 6]) -> u64 {
    let nr = h.abi().number(s).unwrap();
    match &mut h.proc.threads[0].cpu {
        GuestCpu::X86_64(c) => {
            let r = c.vcpu_mut().user_regs_mut();
            r.rax = nr;
            [r.rdi, r.rsi, r.rdx, r.r10, r.r8, r.r9] = args;
        }
        GuestCpu::Aarch64(c) => {
            c.core_mut().set_x(8, nr);
            for (i, &a) in args.iter().enumerate() {
                c.core_mut().set_x(i as u8, a);
            }
        }
        GuestCpu::Riscv64(c) => {
            c.core_mut().set_x(17, nr);
            for (i, &a) in args.iter().enumerate() {
                c.core_mut().set_x(10 + i as u8, a);
            }
        }
    }
    h.proc.enter_syscall(0, nr, args);
    nr
}

fn audit_arch(abi: LinuxAbi) -> u32 {
    abi.audit_arch()
}

#[test]
fn syscall_stops_show_each_architectures_entry_and_exit() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let mut tr = traced(&mut h, opt::TRACESYSGOOD);
        assert_eq!(resume(&mut h, &mut tr, req::SYSCALL, 0), 0);
        assert!(mode(&h.proc.threads[0]).syscall);
        if abi == LinuxAbi::Aarch64 {
            if let GuestCpu::Aarch64(c) = &mut h.proc.threads[0].cpu {
                c.core_mut().set_x(7, 0x77);
            }
        }
        let args = [3, 0x1000, 7, 0, 0, 0];
        let nr = make_call(&mut h, Sysno::Getpid, args);
        assert!(parked(&h.proc.threads[0]));
        assert_eq!(
            stop(&h),
            (SIGTRAP | 0x80, StopKind::Entry { emu: false }, 1)
        );
        // The entry view: x86-64's rax and RISC-V's a0 are -ENOSYS; AArch64
        // keeps x0 and shows the direction in x7.
        let t = &h.proc.threads[0];
        let result = t.cpu.syscall_return_value() as i64;
        match abi {
            LinuxAbi::Aarch64 => {
                assert_eq!(result, 3);
                let GuestCpu::Aarch64(c) = &t.cpu else {
                    unreachable!()
                };
                assert_eq!(c.core().get_x(7), 0);
            }
            _ => assert_eq!(result, e(ENOSYS)),
        }
        let (size, b) = info(&mut h, &mut tr);
        assert_eq!(size, 80, "offsetofend(entry.args)");
        assert_eq!(b[0], call::INFO_ENTRY);
        assert_eq!(
            u32::from_le_bytes(b[4..8].try_into().unwrap()),
            audit_arch(abi)
        );
        assert_eq!(word(&b, 8), h.proc.threads[0].cpu.pc());
        assert_eq!(word(&b, 24), nr);
        assert_eq!([word(&b, 32), word(&b, 40), word(&b, 48)], [3, 0x1000, 7]);
        let (ret, msg) = ask(&mut h, &mut tr, req::GETEVENTMSG, 0, 0, &[]);
        assert_eq!((ret, word(&msg, 0)), (0, 1));
        // Resumed: the call runs and stops again as it finishes, its result
        // in place.
        assert_eq!(resume(&mut h, &mut tr, req::SYSCALL, 0), 0);
        h.proc.resume_in_call(0);
        assert_eq!(stop(&h), (SIGTRAP | 0x80, StopKind::Exit, 2));
        let pid = h.proc.state.pid as u64;
        assert_eq!(h.proc.threads[0].cpu.syscall_return_value(), pid);
        if let GuestCpu::Aarch64(c) = &h.proc.threads[0].cpu {
            assert_eq!(c.core().get_x(7), 1);
        }
        let (size, b) = info(&mut h, &mut tr);
        assert_eq!((size, b[0]), (33, call::INFO_EXIT));
        assert_eq!((word(&b, 24), b[32]), (pid, 0));
        // A tracer too small for the structure gets its size all the same.
        let (size, _) = ask(&mut h, &mut tr, req::GET_SYSCALL_INFO, 4, 0, &[]);
        assert_eq!(size, 33);
        // Resumed with PTRACE_CONT: no more stops; AArch64's x7 is back.
        assert_eq!(resume(&mut h, &mut tr, req::CONT, 0), 0);
        assert!(!parked(&h.proc.threads[0]));
        if let GuestCpu::Aarch64(c) = &h.proc.threads[0].cpu {
            assert_eq!(c.core().get_x(7), 0x77);
        }
        make_call(&mut h, Sysno::Getpid, [0; 6]);
        assert!(!parked(&h.proc.threads[0]));
    });
}

#[test]
fn without_tracesysgood_the_stop_is_plain_sigtrap_and_info_is_none() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let mut tr = traced(&mut h, 0);
        // At a signal-delivery-stop: no system call (the header only).
        let (size, b) = info(&mut h, &mut tr);
        assert_eq!((size, b[0]), (24, call::INFO_NONE));
        resume(&mut h, &mut tr, req::SYSCALL, 0);
        make_call(&mut h, Sysno::Getpid, [0; 6]);
        assert_eq!(stop(&h), (SIGTRAP, StopKind::Entry { emu: false }, 1));
        // ptrace_get_syscall_info_op reads si_code SIGTRAP|0x80 only.
        let (size, b) = info(&mut h, &mut tr);
        assert_eq!((size, b[0]), (24, call::INFO_NONE));
        let (ret, si) = ask(&mut h, &mut tr, req::GETSIGINFO, 0, 0, &[]);
        let si = SigInfo::decode(&si);
        assert_eq!((ret, si.signo, si.code), (0, SIGTRAP, SIGTRAP));
        assert_eq!(si.pid(), h.proc.threads[0].tid);
    });
}

#[test]
fn a_call_changed_or_skipped_at_its_entry() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let mut tr = traced(&mut h, opt::TRACESYSGOOD);
        resume(&mut h, &mut tr, req::SYSCALL, 0);
        // getpid becomes getppid.
        make_call(&mut h, Sysno::Getpid, [0; 6]);
        let (_, mut b) = info(&mut h, &mut tr);
        let getppid = h.abi().number(Sysno::Getppid).unwrap();
        b[24..32].copy_from_slice(&getppid.to_le_bytes());
        let (ret, _) = ask(&mut h, &mut tr, req::SET_SYSCALL_INFO, 88, 0, &b);
        assert_eq!(ret, 0);
        resume(&mut h, &mut tr, req::SYSCALL, 0);
        h.proc.resume_in_call(0);
        let ppid = h.proc.state.ppid as u64;
        assert_eq!(h.proc.threads[0].cpu.syscall_return_value(), ppid);
        // At the exit stop the result can be changed too, as an error.
        let (_, mut b) = info(&mut h, &mut tr);
        b[24..32].copy_from_slice(&(-(EPERM as i64)).to_le_bytes());
        b[32] = 1;
        assert_eq!(ask(&mut h, &mut tr, req::SET_SYSCALL_INFO, 88, 0, &b).0, 0);
        assert_eq!(
            h.proc.threads[0].cpu.syscall_return_value() as i64,
            e(EPERM)
        );
        // The checks: reserved fields, the stop's kind, an int number.
        let mut bad = b.clone();
        bad[2] = 1;
        assert_eq!(
            ask(&mut h, &mut tr, req::SET_SYSCALL_INFO, 88, 0, &bad).0,
            e(EINVAL)
        );
        let mut bad = b.clone();
        bad[0] = call::INFO_ENTRY;
        assert_eq!(
            ask(&mut h, &mut tr, req::SET_SYSCALL_INFO, 88, 0, &bad).0,
            e(EINVAL)
        );
        resume(&mut h, &mut tr, req::SYSCALL, 0);
        // Skipped (-1): the result register is what the tracer left.
        make_call(&mut h, Sysno::Getpid, [0; 6]);
        let (_, mut b) = info(&mut h, &mut tr);
        b[24..32].copy_from_slice(&(1u64 << 32).to_le_bytes());
        assert_eq!(
            ask(&mut h, &mut tr, req::SET_SYSCALL_INFO, 88, 0, &b).0,
            e(ERANGE)
        );
        b[24..32].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(ask(&mut h, &mut tr, req::SET_SYSCALL_INFO, 88, 0, &b).0, 0);
        let left = match abi {
            // syscall_set_nr(-1) makes AArch64's result ENOSYS itself.
            LinuxAbi::Aarch64 => e(ENOSYS) as u64,
            _ => {
                h.proc.threads[0].cpu.set_syscall_result(42);
                42
            }
        };
        resume(&mut h, &mut tr, req::SYSCALL, 0);
        h.proc.resume_in_call(0);
        assert_eq!(stop(&h).1, StopKind::Exit, "skipped calls stop at exit too");
        assert_eq!(h.proc.threads[0].cpu.syscall_return_value(), left);
        let (_, b) = info(&mut h, &mut tr);
        assert_eq!(word(&b, 24), left);
    });
}

#[test]
fn sysemu_skips_by_the_flags_read_before_the_stop() {
    for abi in [LinuxAbi::X86_64, LinuxAbi::Aarch64] {
        let mut h = Harness::new(abi);
        let mut tr = traced(&mut h, 0);
        assert_eq!(resume(&mut h, &mut tr, req::SYSEMU, 0), 0);
        make_call(&mut h, Sysno::Getpid, [0; 6]);
        assert_eq!(stop(&h).1, StopKind::Entry { emu: true });
        h.proc.threads[0].cpu.set_syscall_result(5);
        // Resumed with PTRACE_SYSCALL: still not made, and the exit stops.
        resume(&mut h, &mut tr, req::SYSCALL, 0);
        h.proc.resume_in_call(0);
        assert_eq!(stop(&h).1, StopKind::Exit);
        assert_eq!(h.proc.threads[0].cpu.syscall_return_value(), 5);
        // Resumed from a PTRACE_SYSCALL entry with PTRACE_SYSEMU: made, and
        // no exit stop.
        resume(&mut h, &mut tr, req::SYSCALL, 0);
        make_call(&mut h, Sysno::Getpid, [0; 6]);
        resume(&mut h, &mut tr, req::SYSEMU, 0);
        h.proc.resume_in_call(0);
        let pid = h.proc.state.pid as u64;
        assert_eq!(h.proc.threads[0].cpu.syscall_return_value(), pid);
        assert!(!parked(&h.proc.threads[0]));
    }
    // RISC-V has no PTRACE_SYSEMU.
    let mut h = Harness::new(LinuxAbi::Riscv64);
    let mut tr = traced(&mut h, 0);
    assert_eq!(ask(&mut h, &mut tr, req::SYSEMU, 0, 0, &[]).0, e(EIO));
    assert!(parked(&h.proc.threads[0]));
}

#[test]
fn a_syscall_stops_signal_is_sent_from_the_kernel() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let mut tr = traced(&mut h, opt::TRACESYSGOOD);
        resume(&mut h, &mut tr, req::SYSCALL, 0);
        make_call(&mut h, Sysno::Getpid, [0; 6]);
        // Resumed with SIGUSR1 at the entry: the call is made, then the
        // signal is queued (SEND_SIG_PRIV) and seen at the next return.
        resume(&mut h, &mut tr, req::CONT, SIGUSR1 as u64);
        h.proc.resume_in_call(0);
        let pid = h.proc.state.pid as u64;
        assert_eq!(h.proc.threads[0].cpu.syscall_return_value(), pid);
        let si = h.proc.threads[0].pending.dequeue(0).expect("queued");
        assert_eq!((si.signo, si.code, si.pid()), (SIGUSR1, code::SI_KERNEL, 0));
        // At an exit stop: sent as the thread goes on.
        h.proc.threads[0].pending = Default::default();
        let mut tr = traced(&mut h, opt::TRACESYSGOOD);
        resume(&mut h, &mut tr, req::SYSCALL, 0);
        make_call(&mut h, Sysno::Getpid, [0; 6]);
        resume(&mut h, &mut tr, req::SYSCALL, 0);
        h.proc.resume_in_call(0);
        assert_eq!(stop(&h).1, StopKind::Exit);
        let (ret, _) = ask(&mut h, &mut tr, req::CONT, 0, SIGUSR1 as u64, &[]);
        assert_eq!(ret, 0);
        h.proc.deliver_signals(0);
        let s = h.proc.threads[0]
            .ptrace
            .as_ref()
            .unwrap()
            .stop
            .clone()
            .unwrap();
        assert_eq!((s.code, s.kind), (SIGUSR1, StopKind::Signal));
        assert_eq!(s.info.unwrap().code, code::SI_KERNEL);
    });
}

#[test]
fn a_tracer_gone_at_a_syscall_stop_sends_sigtrap_unless_tracesysgood() {
    each_abi(|abi| {
        for (options, sigtrap) in [(0, true), (opt::TRACESYSGOOD, false)] {
            let mut h = Harness::new(abi);
            let mut tr = traced(&mut h, options);
            resume(&mut h, &mut tr, req::SYSCALL, 0);
            make_call(&mut h, Sysno::Getpid, [0; 6]);
            drop(tr);
            h.proc.collect_async(None);
            assert!(!parked(&h.proc.threads[0]));
            h.proc.resume_in_call(0);
            assert!(h.proc.threads[0].ptrace.is_none());
            // ptrace_stop returns the stop's own exit code, which send_sig
            // takes only when it is a signal (SIGTRAP then kills).
            let t = &h.proc.threads[0];
            let dying = matches!(
                &h.proc.state.exit,
                Some(crate::user::linux::process::ExitStatus::Signaled { info, .. })
                    if info.signo == SIGTRAP
            );
            assert_eq!(t.pending.contains(SIGTRAP) || dying, sigtrap);
        }
    });
}

#[test]
fn aarch64_system_call_register_set() {
    let mut h = Harness::new(LinuxAbi::Aarch64);
    let mut tr = traced(&mut h, opt::TRACESYSGOOD);
    resume(&mut h, &mut tr, req::SYSCALL, 0);
    let nr = make_call(&mut h, Sysno::Getpid, [0; 6]);
    assert_eq!(
        regs::layout(&h.proc.threads[0].cpu, regs::NT_ARM_SYSTEM_CALL),
        Ok((4, 4))
    );
    let x86 = Harness::new(LinuxAbi::X86_64);
    assert_eq!(
        regs::layout(&x86.proc.threads[0].cpu, regs::NT_ARM_SYSTEM_CALL).map_err(|e| e.0),
        Err(EINVAL)
    );
    let (ret, b) = ask(
        &mut h,
        &mut tr,
        req::GETREGSET,
        regs::NT_ARM_SYSTEM_CALL,
        4,
        &[],
    );
    assert_eq!((ret, b), (0, (nr as u32).to_le_bytes().to_vec()));
    // Set to -1: skipped, x0 (the first argument here) left as it is.
    let (ret, _) = ask(
        &mut h,
        &mut tr,
        req::SETREGSET,
        regs::NT_ARM_SYSTEM_CALL,
        4,
        &(-1i32).to_le_bytes(),
    );
    assert_eq!(ret, 0);
    h.proc.threads[0].cpu.set_syscall_result(9);
    resume(&mut h, &mut tr, req::CONT, 0);
    h.proc.resume_in_call(0);
    assert_eq!(h.proc.threads[0].cpu.syscall_return_value(), 9);
}

/// `nop` on each architecture, and its length.
fn nop(abi: LinuxAbi) -> (&'static [u8], u64) {
    match abi {
        LinuxAbi::X86_64 => (&[0x90], 1),
        LinuxAbi::Aarch64 => (&[0x1f, 0x20, 0x03, 0xd5], 4),
        LinuxAbi::Riscv64 => (&[0x13, 0, 0, 0], 4),
    }
}

/// The system-call instruction on each architecture.
fn syscall_insn(abi: LinuxAbi) -> &'static [u8] {
    match abi {
        LinuxAbi::X86_64 => &[0x0f, 0x05],
        LinuxAbi::Aarch64 => &[0x01, 0x00, 0x00, 0xd4],
        LinuxAbi::Riscv64 => &[0x73, 0, 0, 0],
    }
}

#[test]
fn single_steps_trap_after_each_instruction() {
    for abi in [LinuxAbi::X86_64, LinuxAbi::Aarch64] {
        let mut h = Harness::new(abi);
        let (op, len) = nop(abi);
        let at = CODE + 0x1000;
        let mut code = op.to_vec();
        code.extend_from_slice(syscall_insn(abi));
        h.proc.state.space.write_raw(at, &code).unwrap();
        let mut tr = traced(&mut h, 0);
        h.proc.threads[0].cpu.set_pc(at);
        assert_eq!(resume(&mut h, &mut tr, req::SINGLESTEP, 0), 0);
        assert!(mode(&h.proc.threads[0]).step);
        // One instruction, then SIGTRAP TRAP_TRACE at the next one.
        assert_eq!(h.proc.threads[0].cpu.step(), CpuEvent::Yield);
        assert_eq!(h.proc.threads[0].cpu.pc(), at + len);
        h.proc.step_trap(0);
        let si = h.proc.threads[0].pending.dequeue(0).expect("trapped");
        assert_eq!(
            (si.signo, si.code, si.addr()),
            (SIGTRAP, code::TRAP_TRACE, at + len)
        );
        // A stepped system call reports as it finishes: x86-64's
        // TRAP_BRKPT, AArch64's generic SI_USER from no one.
        let getpid = h.abi().number(Sysno::Getpid).unwrap();
        h.proc.threads[0].cpu.set_syscall_number(getpid);
        let CpuEvent::Syscall { nr, args } = h.proc.threads[0].cpu.step() else {
            panic!("the system call");
        };
        h.proc.enter_syscall(0, nr, args);
        let pid = h.proc.state.pid as u64;
        assert_eq!(h.proc.threads[0].cpu.syscall_return_value(), pid);
        let si = h.proc.threads[0].pending.dequeue(0).expect("reported");
        let after = at + len + syscall_insn(abi).len() as u64;
        match abi {
            LinuxAbi::X86_64 => {
                assert_eq!(
                    (si.signo, si.code, si.addr()),
                    (SIGTRAP, code::TRAP_BRKPT, after)
                );
            }
            _ => assert_eq!((si.signo, si.code, si.pid()), (SIGTRAP, code::SI_USER, 0)),
        }
    }
}

#[test]
fn stepping_into_a_handler_stops_before_its_first_instruction() {
    for abi in [LinuxAbi::X86_64, LinuxAbi::Aarch64] {
        let mut h = Harness::new(abi);
        let handler = CODE + 0x100;
        let a = &mut h.proc.state.sigactions[(SIGUSR1 - 1) as usize];
        a.handler = handler;
        a.flags = sa::RESTORER;
        a.restorer = CODE + 0x200;
        let mut tr = traced(&mut h, 0);
        resume(&mut h, &mut tr, req::CONT, 0);
        // SIGUSR1: a signal-delivery-stop, then stepping into the handler.
        let me = h.proc.threads[0].tid;
        h.proc.threads[0]
            .pending
            .enqueue(SigInfo::kill(SIGUSR1, code::SI_USER, me, 0));
        h.proc.threads[0].sigpending = true;
        h.proc.deliver_signals(0);
        assert_eq!(stop(&h).1, StopKind::Signal);
        assert_eq!(resume(&mut h, &mut tr, req::SINGLESTEP, SIGUSR1 as u64), 0);
        assert!(parked(&h.proc.threads[0]));
        assert_eq!(stop(&h), (SIGTRAP, StopKind::Quiet, 0));
        assert_eq!(h.proc.threads[0].cpu.pc(), handler);
        let (_, si) = ask(&mut h, &mut tr, req::GETSIGINFO, 0, 0, &[]);
        assert_eq!(SigInfo::decode(&si).code, SIGTRAP);
        // x86-64 stops stepping as the frame is built; AArch64 does not.
        assert_eq!(mode(&h.proc.threads[0]).step, abi == LinuxAbi::Aarch64);
    }
}

#[test]
fn riscv_cannot_step() {
    let mut h = Harness::new(LinuxAbi::Riscv64);
    let mut tr = traced(&mut h, 0);
    resume(&mut h, &mut tr, req::SYSCALL, 0);
    make_call(&mut h, Sysno::Getpid, [0; 6]);
    assert!(mode(&h.proc.threads[0]).syscall);
    // ptrace_resume clears the system-call stops before refusing.
    assert_eq!(ask(&mut h, &mut tr, req::SINGLESTEP, 0, 0, &[]).0, e(EIO));
    assert!(parked(&h.proc.threads[0]));
    let m = mode(&h.proc.threads[0]);
    assert!(!m.syscall && !m.step);
    assert_eq!(
        ask(&mut h, &mut tr, req::SYSEMU_SINGLESTEP, 0, 0, &[]).0,
        e(EIO)
    );
}
