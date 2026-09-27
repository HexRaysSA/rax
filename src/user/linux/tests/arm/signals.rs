//! AArch32 signal frames and their returns against Linux 6.19 on arm64
//! (`arch/arm64/kernel/signal32.c`, `asm/signal32.h`, `sigreturn32.S`,
//! `ptrace.c`'s `valid_compat_regs`): the layouts of `struct
//! compat_sigframe` and `struct compat_rt_sigframe`, the VFP record in
//! `uc_regspace`, the handler's entry state and return address
//! (`compat_setup_return`), the fault record in the sigcontext,
//! `sigreturn` and `rt_sigreturn`, and bad frames.

use super::super::harness::{CODE, Harness};
use super::{arm, get, put, u32_at, words};
use crate::user::linux::abi::{LinuxAbi, Sysno};
use crate::user::linux::signal::frame::arm::{RT_SIGFRAME_SIZE, SIGFRAME_SIZE, uc};
use crate::user::linux::signal::*;
use crate::user::linux::syscall::Outcome;

/// Handler entry points (never executed): A32, and T32 (bit 0 set).
const HANDLER: u64 = CODE + 0x100;
const THUMB_HANDLER: u64 = CODE + 0x201;
/// `sa_restorer`, a T32 one.
const RESTORER: u64 = CODE + 0x301;
/// The thread's CPSR before delivery: N, Z, C, V, Q, GE = 0b1010, and
/// ITSTATE bits, User mode.
const CPSR: u32 = 0xF800_0000 | 0x000A_0000 | 0x0600_1C00 | 0x10;
/// An FPSCR with bits outside FPSR's and FPCR's masks (5 and 6).
const FPSCR: u32 = 0x8340_0060 | 0x1F;

/// `rt_sigaction` with a `struct compat_sigaction`.
fn sigaction(h: &mut Harness, sig: i32, handler: u64, flags: u64, mask: u64) {
    let at = h.scratch + 0x800;
    let mut b = words(&[handler as u32, flags as u32, RESTORER as u32]);
    b.extend_from_slice(&mask.to_le_bytes());
    put(h, at, &b);
    h.ok(Sysno::RtSigaction, &[sig as u64, at, 0, 8]);
}

fn raise(h: &mut Harness, sig: i32) {
    let (pid, tid) = (h.proc.state.pid as u64, h.proc.threads[0].tid as u64);
    h.ok(Sysno::Tgkill, &[pid, tid, sig as u64]);
}

/// Puts the thread in a known context at an 8-byte-aligned stack address
/// 0x3000 below its initial one, whose frame area it fills with 0xEE; the
/// stack pointer.
fn prepare(h: &mut Harness) -> u64 {
    let sp = (h.proc.threads[0].cpu.sp() & !7) - 0x3000;
    put(h, sp - 0x400, &[0xEE; 0x400]);
    let core = arm(h).core_mut();
    for r in 0..13 {
        core.regs[r] = 0x1111_1111 * (r as u32 + 1);
    }
    core.regs[13] = sp as u32;
    core.regs[14] = 0xE0E0_E0E0;
    core.cpsr = crate::isa::arm::Psr::from_u32(CPSR);
    for (i, d) in core.vfp.dregs.iter_mut().enumerate() {
        *d = 0x0101_0101_0101_0101 * (i as u64 + 1);
    }
    core.vfp.fpscr = crate::isa::arm::vfp::Fpscr::from_bits(FPSCR);
    arm(h).set_pc(CODE + 0x40);
    sp
}

#[test]
fn an_rt_frame_is_the_compat_layout() {
    let mut h = Harness::new(LinuxAbi::Arm);
    sigaction(&mut h, SIGUSR1, HANDLER, sa::SIGINFO, sigmask(SIGUSR2));
    let sp = prepare(&mut h);
    h.proc.threads[0].sigmask = sigmask(SIGRTMIN + 1);
    raise(&mut h, SIGUSR1);
    h.proc.deliver_signals(0);
    let frame = (sp - RT_SIGFRAME_SIZE) & !7;
    let ucp = frame + 128;
    let sigpage = h.proc.state.sigtramp;
    // compat_setup_return: r0 = sig, r1 = &info, r2 = &uc, SP = the
    // frame, LR = the [sigpage]'s A32 rt_sigreturn (word 3).
    let core = arm(&mut h).core();
    assert_eq!(core.regs[..3], [SIGUSR1 as u32, frame as u32, ucp as u32]);
    assert_eq!(core.regs[3], 0x4444_4444);
    assert_eq!(
        (u64::from(core.regs[13]), u64::from(core.regs[14])),
        (frame, sigpage + 12)
    );
    assert_eq!(u64::from(core.regs[15]), HANDLER);
    // The flags byte, IT, and T cleared; GE and the mode kept.
    assert_eq!(core.cpsr.to_u32(), 0x000A_0010);
    // struct compat_siginfo.
    assert_eq!(u32_at(&h, frame), SIGUSR1 as u32);
    assert_eq!(u32_at(&h, frame + 8) as i32, code::SI_TKILL);
    // uc_flags, uc_link zero; uc_stack: the disabled alternate stack.
    assert_eq!(get(&h, ucp, 8), [0; 8]);
    assert_eq!(get(&h, ucp + uc::STACK, 12), words(&[0, 2, 0]));
    // The sigcontext: trap_no, error_code, oldmask (the mask's low half),
    // r0-r15, the CPSR, fault_address.
    let mut mc = vec![0, 0, 0];
    mc.extend((0..13).map(|r| 0x1111_1111 * (r + 1)));
    mc.extend([sp as u32, 0xE0E0_E0E0, (CODE + 0x40) as u32, CPSR, 0]);
    assert_eq!(get(&h, ucp + uc::MCONTEXT, 84), words(&mc));
    // uc_sigmask: the mask before delivery, both halves.
    let saved = sigmask(SIGRTMIN + 1);
    assert_eq!(get(&h, ucp + uc::SIGMASK, 8), saved.to_le_bytes());
    // __unused is not written.
    assert_eq!(get(&h, ucp + 112, 120), [0xEE; 120]);
    // The VFP record: magic, size 288, D0-D31, FPSCR within FPSR's and
    // FPCR's masks, FPEXC with EN, FPINST and FPINST2 zero, the padding
    // left, then an 8-byte end_magic of zero.
    let vfp = ucp + uc::REGSPACE;
    assert_eq!(get(&h, vfp, 8), words(&[0x5646_5001, 288]));
    let d: Vec<u8> = (0..32u64)
        .flat_map(|i| (0x0101_0101_0101_0101 * (i + 1)).to_le_bytes())
        .collect();
    assert_eq!(get(&h, vfp + 8, 256), d);
    assert_eq!(u32_at(&h, vfp + 264), FPSCR & !0x60);
    assert_eq!(get(&h, vfp + 268, 4), [0xEE; 4]);
    assert_eq!(get(&h, vfp + 272, 12), words(&[1 << 30, 0, 0]));
    assert_eq!(get(&h, vfp + 284, 4), [0xEE; 4]);
    assert_eq!(get(&h, vfp + 288, 8), [0; 8]);
    assert_eq!(get(&h, vfp + 296, 8), [0xEE; 8]);
    // The handler's mask: the old one, the action's, and the signal.
    let t = &h.proc.threads[0];
    assert_eq!(t.sigmask, saved | sigmask(SIGUSR2) | sigmask(SIGUSR1));
}

#[test]
fn a_non_rt_frame_and_the_thumb_and_restorer_returns() {
    let mut h = Harness::new(LinuxAbi::Arm);
    // A T32 handler without SA_SIGINFO or SA_RESTORER: the [sigpage]'s T32
    // sigreturn (word 2), with the Thumb bit.
    sigaction(&mut h, SIGUSR1, THUMB_HANDLER, 0, 0);
    let sp = prepare(&mut h);
    raise(&mut h, SIGUSR1);
    h.proc.deliver_signals(0);
    let frame = (sp - SIGFRAME_SIZE) & !7;
    let sigpage = h.proc.state.sigtramp;
    let cpu = arm(&mut h);
    assert!(cpu.thumb());
    assert_eq!((cpu.pc(), cpu.sp()), (THUMB_HANDLER - 1, frame));
    let core = cpu.core();
    assert_eq!(core.regs[..3], [SIGUSR1 as u32, 0x2222_2222, 0x3333_3333]);
    assert_eq!(u64::from(core.regs[14]), sigpage + 8 + 1);
    // uc_flags 0x5ac3c35a; uc_link and uc_stack are not written.
    assert_eq!(u32_at(&h, frame), 0x5ac3_c35a);
    assert_eq!(get(&h, frame + 4, 16), [0xEE; 16]);
    assert_eq!(u32_at(&h, frame + uc::CPSR), CPSR);
    // With SA_RESTORER, LR is the restorer as given; an RT T32 handler
    // otherwise returns through word 5.
    for (flags, lr) in [
        (sa::RESTORER, RESTORER),
        (sa::SIGINFO | sa::RESTORER, RESTORER),
        (sa::SIGINFO, sigpage + 20 + 1),
    ] {
        sigaction(&mut h, SIGUSR2, THUMB_HANDLER, flags, 0);
        prepare(&mut h);
        raise(&mut h, SIGUSR2);
        h.proc.deliver_signals(0);
        assert_eq!(u64::from(arm(&mut h).core().regs[14]), lr, "{flags:#x}");
        h.proc.threads[0].sigmask = 0;
    }
}

#[test]
fn a_faults_record_is_the_compat_fsr_and_fault_address() {
    let mut h = Harness::new(LinuxAbi::Arm);
    sigaction(&mut h, SIGSEGV, HANDLER, sa::SIGINFO, 0);
    prepare(&mut h);
    // A write fault at 0x1000: the ESR's WnR becomes the FSR's bit 11.
    let t = &mut h.proc.threads[0];
    t.fault.fault_address = 0x1000;
    t.fault.fault_code = (0x24 << 26) | (1 << 25) | (1 << 6) | 7;
    let info = SigInfo::fault(SIGSEGV, code::SEGV_MAPERR, 0x1000);
    h.proc.trap_signal(0, info, frame::FaultUpdate::None);
    h.proc.deliver_signals(0);
    let ucp = u64::from(arm(&mut h).core().regs[2]);
    assert_eq!(get(&h, ucp + uc::MCONTEXT, 8), words(&[0, 1 << 11]));
    assert_eq!(u32_at(&h, ucp + uc::MCONTEXT + 80), 0x1000);
    assert_eq!(u32_at(&h, ucp - 128 + 12), 0x1000, "si_addr");
}

#[test]
fn sigreturn_and_rt_sigreturn_restore_the_frame() {
    for rt in [true, false] {
        let mut h = Harness::new(LinuxAbi::Arm);
        let flags = if rt { sa::SIGINFO } else { 0 };
        sigaction(&mut h, SIGUSR1, HANDLER, flags, 0);
        let sp = prepare(&mut h);
        raise(&mut h, SIGUSR1);
        h.proc.deliver_signals(0);
        let frame = arm(&mut h).sp();
        let ucp = if rt { frame + 128 } else { frame };
        // The handler edits the frame: r4, the PC, the CPSR (Thumb, the
        // Z flag, and E, which a CPU without mixed-endian EL0 drops), D7,
        // FPSCR, and the mask.
        put(&h, ucp + uc::R0 + 16, &0xFEED_0004u32.to_le_bytes());
        put(&h, ucp + uc::R0 + 60, &((CODE + 0x81) as u32).to_le_bytes());
        put(&h, ucp + uc::CPSR, &(0x4000_0230u32).to_le_bytes());
        put(&h, ucp + uc::REGSPACE + 8 + 7 * 8, &0x7777u64.to_le_bytes());
        put(&h, ucp + uc::REGSPACE + 264, &0x0100_0000u32.to_le_bytes());
        put(&h, ucp + uc::SIGMASK, &sigmask(SIGUSR2).to_le_bytes());
        let s = if rt {
            Sysno::RtSigreturn
        } else {
            Sysno::Sigreturn
        };
        assert!(matches!(h.dispatch(s, &[]), Outcome::Unchanged), "{s:?}");
        let cpu = arm(&mut h);
        assert_eq!(cpu.core().regs[4], 0xFEED_0004);
        assert_eq!(cpu.core().regs[0], 0x1111_1111, "r0 from the frame");
        assert_eq!(cpu.sp(), sp, "SP from the frame");
        assert_eq!((cpu.pc(), cpu.thumb()), (CODE + 0x80, true));
        assert_eq!(cpu.core().cpsr.to_u32(), 0x4000_0030);
        assert_eq!(cpu.core().vfp.dregs[7], 0x7777);
        assert_eq!(cpu.core().vfp.fpscr.bits(), 0x0100_0000);
        assert_eq!(h.proc.threads[0].sigmask, sigmask(SIGUSR2), "{s:?}");
    }
}

#[test]
fn bad_frames_force_sigsegv() {
    // An unaligned SP, a CPSR that is not User mode (the registers are
    // restored, the PSR forced to User keeping the flags), and a VFP
    // record with the wrong magic.
    for case in 0..3 {
        let mut h = Harness::new(LinuxAbi::Arm);
        sigaction(&mut h, SIGUSR1, HANDLER, sa::SIGINFO, 0);
        prepare(&mut h);
        raise(&mut h, SIGUSR1);
        h.proc.deliver_signals(0);
        let frame = arm(&mut h).sp();
        let ucp = frame + 128;
        put(&h, ucp + uc::R0 + 16, &0xFEED_0004u32.to_le_bytes());
        match case {
            0 => arm(&mut h).set_sp(frame + 4),
            1 => put(&h, ucp + uc::CPSR, &0x8000_0013u32.to_le_bytes()),
            _ => put(&h, ucp + uc::REGSPACE, &0u32.to_le_bytes()),
        }
        assert!(matches!(
            h.dispatch(Sysno::RtSigreturn, &[]),
            Outcome::Unchanged
        ));
        let t = &mut h.proc.threads[0];
        let info = t.pending.dequeue(0).expect("SIGSEGV forced");
        assert_eq!(info.signo, SIGSEGV, "case {case}");
        let core = arm(&mut h).core();
        assert_eq!(core.regs[0], 0, "case {case}: the result is 0");
        match case {
            0 => assert_eq!(core.regs[4], 0x5555_5555, "nothing restored"),
            1 => {
                assert_eq!(core.regs[4], 0xFEED_0004);
                assert_eq!(core.cpsr.to_u32(), 0x8000_0010);
            }
            _ => {
                assert_eq!(core.regs[4], 0xFEED_0004);
                assert_eq!(core.vfp.dregs[1], 0x0202_0202_0202_0202, "VFP state kept");
            }
        }
    }
}
