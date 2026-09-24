//! Signal delivery and `rt_sigreturn` on every ABI, driven through the
//! personality without executing guest code. Frame addresses follow each
//! architecture's `get_sigframe`; field offsets follow the UAPI structures
//! (`asm/sigcontext.h`, `asm/ucontext.h`, `asm-generic/siginfo.h`); register
//! effects follow `setup_rt_frame`/`setup_return` (Linux 6.19).

use super::harness::{CODE, Harness, each_abi};
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::{LinuxAbi, Sysno};
use crate::user::linux::arch::GuestCpu;
use crate::user::linux::process::ExitStatus;
use crate::user::linux::signal::deliver::SyscallEntry;
use crate::user::linux::signal::deliver::restart::*;
use crate::user::linux::signal::*;
use crate::user::linux::syscall::Outcome;

/// Handler entry point (never executed).
const HANDLER: u64 = CODE + 0x100;
/// `sa_restorer`.
const RESTORER: u64 = CODE + 0x200;

fn restorer_flag(abi: LinuxAbi) -> u64 {
    if abi.has_sa_restorer() {
        sa::RESTORER
    } else {
        0
    }
}

/// `rt_sigaction(sig, {handler, flags, RESTORER, mask})`.
fn install(h: &mut Harness, sig: i32, handler: u64, flags: u64, mask: u64) {
    let at = h.scratch + 0x800;
    let mut b = Vec::new();
    b.extend_from_slice(&handler.to_le_bytes());
    b.extend_from_slice(&flags.to_le_bytes());
    if h.abi().has_sa_restorer() {
        b.extend_from_slice(&RESTORER.to_le_bytes());
    }
    b.extend_from_slice(&mask.to_le_bytes());
    h.proc.state.space.write_raw(at, &b).unwrap();
    h.ok(Sysno::RtSigaction, &[sig as u64, at, 0, 8]);
}

fn raise(h: &mut Harness, sig: i32) {
    let (pid, tid) = (h.proc.state.pid as u64, h.proc.threads[0].tid as u64);
    h.ok(Sysno::Tgkill, &[pid, tid, sig as u64]);
}

fn cpu(h: &mut Harness) -> &mut GuestCpu {
    &mut h.proc.threads[0].cpu
}

fn word(seed: u64, i: u64) -> u64 {
    seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ (i + 1).wrapping_mul(0x0101_0101_0101_0101)
}

/// General registers other than SP and PC, in a fixed order.
fn gprs(cpu: &GuestCpu) -> Vec<u64> {
    match cpu {
        GuestCpu::X86_64(c) => {
            let r = c.vcpu().user_regs();
            vec![
                r.rax, r.rbx, r.rcx, r.rdx, r.rsi, r.rdi, r.rbp, r.r8, r.r9, r.r10, r.r11, r.r12,
                r.r13, r.r14, r.r15,
            ]
        }
        GuestCpu::Aarch64(c) => (0..31).map(|i| c.core().get_x(i)).collect(),
        GuestCpu::Riscv64(c) => (1..32).filter(|&i| i != 2).map(|i| c.core().x(i)).collect(),
    }
}

fn set_gprs(cpu: &mut GuestCpu, seed: u64) {
    match cpu {
        GuestCpu::X86_64(c) => {
            let r = c.vcpu_mut().user_regs_mut();
            for (i, reg) in [
                &mut r.rax, &mut r.rbx, &mut r.rcx, &mut r.rdx, &mut r.rsi, &mut r.rdi, &mut r.rbp,
                &mut r.r8, &mut r.r9, &mut r.r10, &mut r.r11, &mut r.r12, &mut r.r13, &mut r.r14,
                &mut r.r15,
            ]
            .into_iter()
            .enumerate()
            {
                *reg = word(seed, i as u64);
            }
        }
        GuestCpu::Aarch64(c) => {
            for i in 0..31 {
                c.core_mut().set_x(i, word(seed, u64::from(i)));
            }
        }
        GuestCpu::Riscv64(c) => {
            for i in (1..32).filter(|&i| i != 2) {
                c.core_mut().set_x(i, word(seed, u64::from(i)));
            }
        }
    }
}

/// Floating-point and vector state with its control and status registers.
fn fpstate(cpu: &GuestCpu) -> Vec<u64> {
    match cpu {
        GuestCpu::X86_64(c) => {
            let r = c.vcpu().user_regs();
            let mut v: Vec<u64> = Vec::new();
            r.xmm.iter().for_each(|x| v.extend(x));
            r.ymm_high.iter().for_each(|x| v.extend(x));
            r.zmm_high.iter().for_each(|x| v.extend(x));
            r.zmm_ext.iter().for_each(|x| v.extend(x));
            v.extend(r.k);
            v.push(u64::from(c.vcpu().mxcsr()));
            v
        }
        GuestCpu::Aarch64(c) => {
            let mut v: Vec<u64> = (0..32)
                .flat_map(|i| {
                    let x = c.core().get_simd(i);
                    [x as u64, (x >> 64) as u64]
                })
                .collect();
            v.push(u64::from(c.core().fpsr_value()));
            v.push(u64::from(c.core().fpcr_value()));
            v
        }
        GuestCpu::Riscv64(c) => {
            let core = c.core();
            let mut v: Vec<u64> = (0..32).map(|i| core.f(i)).collect();
            v.push(u64::from(core.fcsr()));
            v.extend([core.vstart(), core.vl(), core.vtype(), core.vcsr(), 16]);
            for r in 0..32 {
                let b = core.vreg(r);
                v.push(u64::from_le_bytes(b[..8].try_into().unwrap()));
                v.push(u64::from_le_bytes(b[8..].try_into().unwrap()));
            }
            v
        }
    }
}

fn set_fpstate(cpu: &mut GuestCpu, seed: u64) {
    match cpu {
        GuestCpu::X86_64(c) => {
            let r = c.vcpu_mut().user_regs_mut();
            let mut n = 0u64;
            let mut next = || {
                n += 1;
                word(seed, 100 + n)
            };
            r.xmm.iter_mut().flatten().for_each(|w| *w = next());
            r.ymm_high.iter_mut().flatten().for_each(|w| *w = next());
            r.zmm_high.iter_mut().flatten().for_each(|w| *w = next());
            r.zmm_ext.iter_mut().flatten().for_each(|w| *w = next());
            r.k.iter_mut().for_each(|w| *w = next());
            c.vcpu_mut()
                .set_mxcsr(if seed % 2 == 0 { 0x9FC0 } else { 0x1F81 })
                .unwrap();
        }
        GuestCpu::Aarch64(c) => {
            for i in 0..32 {
                let lo = u128::from(word(seed, 200 + u64::from(i)));
                c.core_mut().set_simd(i, lo | (lo << 64) ^ 0x55);
            }
            c.core_mut()
                .set_fpsr_value(if seed % 2 == 0 { 0x0800_001F } else { 0x1 });
            c.core_mut().set_fpcr_value(if seed % 2 == 0 {
                0x0340_0000
            } else {
                0x0080_0000
            });
        }
        GuestCpu::Riscv64(c) => {
            let core = c.core_mut();
            for i in 0..32 {
                core.set_f(i, word(seed, 300 + u64::from(i)));
                let lo = word(seed, 400 + u64::from(i));
                let mut b = [0u8; 16];
                b[..8].copy_from_slice(&lo.to_le_bytes());
                b[8..].copy_from_slice(&(!lo).to_le_bytes());
                core.set_vreg(i, &b);
            }
            core.set_fcsr(if seed % 2 == 0 { 0x61 } else { 0x1F });
            // vl, vtype (SEW = 32, LMUL = 1 / SEW = 8, LMUL = 2), vstart,
            // vcsr (vxrm, vxsat).
            if seed % 2 == 0 {
                core.set_vl_vtype(4, 0x10);
                core.set_vstart(1);
                core.set_vcsr(0b101);
            } else {
                core.set_vl_vtype(7, 0x01);
                core.set_vstart(0);
                core.set_vcsr(0b010);
            }
        }
    }
}

/// The flags the frame saves: RFLAGS, SPSR, nothing on riscv.
fn flags(cpu: &GuestCpu) -> u64 {
    match cpu {
        GuestCpu::X86_64(c) => c.vcpu().user_rflags(),
        GuestCpu::Aarch64(c) => c.core().el0_spsr(),
        GuestCpu::Riscv64(_) => 0,
    }
}

fn set_flags(cpu: &mut GuestCpu, seed: u64) {
    match cpu {
        // CF PF AF ZF SF IF DF OF, and bit 1.
        GuestCpu::X86_64(c) => {
            c.vcpu_mut()
                .set_user_rflags(if seed % 2 == 0 { 0x0ED7 } else { 0x0202 })
        }
        GuestCpu::Aarch64(c) => {
            c.core_mut()
                .set_nzcv_bits(if seed % 2 == 0 { 0b1010 } else { 0b0101 })
        }
        GuestCpu::Riscv64(_) => {}
    }
}

/// The complete user context a frame must preserve.
fn context(h: &mut Harness) -> (Vec<u64>, Vec<u64>, u64, u64, u64) {
    let c = cpu(h);
    (gprs(c), fpstate(c), flags(c), c.sp(), c.pc())
}

/// Puts the thread in a known context at a 16-byte-aligned stack address
/// `0x3000` below its initial stack pointer and returns that address.
fn prepare(h: &mut Harness, seed: u64) -> u64 {
    let sp = (h.proc.threads[0].cpu.sp() & !0xF) - 0x3000;
    let c = cpu(h);
    set_gprs(c, seed);
    set_fpstate(c, seed);
    set_flags(c, seed);
    c.set_sp(sp);
    c.set_pc(CODE + 0x40);
    sp
}

fn read(h: &Harness, addr: u64, len: usize) -> Vec<u8> {
    let mut b = vec![0u8; len];
    h.proc.state.space.read(addr, &mut b).unwrap();
    b
}

fn u64_at(h: &Harness, addr: u64) -> u64 {
    u64::from_le_bytes(read(h, addr, 8).try_into().unwrap())
}

fn u32_at(h: &Harness, addr: u64) -> u32 {
    u32::from_le_bytes(read(h, addr, 4).try_into().unwrap())
}

/// The frame address each `get_sigframe` computes for a thread at `sp`
/// without an alternate stack.
fn expected_frame(abi: LinuxAbi, sp: u64) -> u64 {
    // The default RV64 core has V: the frame grows by the vector record,
    // 8 + 48 + 32 * VLENB (16) = 568 bytes, rounded up to 16.
    let rv_size = (1088u64 + 8 + 48 + 32 * 16).div_ceil(16) * 16;
    match abi {
        LinuxAbi::X86_64 => {
            // Red zone, 64-byte-aligned XSAVE area (2688 + 4 bytes for
            // XCR0 = 0xE7), frame below with (frame + 8) % 16 == 0.
            let buf_fx = (sp - 128 - (2688 + 4)) & !63;
            ((buf_fx - 440) & !15) - 8
        }
        LinuxAbi::Aarch64 => ((sp - 16) & !15) - 4688,
        LinuxAbi::Riscv64 => (sp - rv_size) & !15,
    }
}

// ------------------------------------------------------------- delivery

#[test]
fn handler_frames_match_each_abi() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let flags = sa::SIGINFO | restorer_flag(abi);
        install(&mut h, SIGUSR1, HANDLER, flags, sigmask(SIGUSR2));
        let sp = prepare(&mut h, 2);
        let before = context(&mut h);
        raise(&mut h, SIGUSR1);
        h.proc.deliver_signals(0);
        let frame = expected_frame(abi, sp);
        let (pid, uid) = (h.proc.state.pid, h.proc.state.creds.0);
        let c = &h.proc.threads[0].cpu;
        assert_eq!((c.pc(), c.sp()), (HANDLER, frame), "{abi:?}");
        assert_eq!(
            h.proc.threads[0].sigmask,
            sigmask(SIGUSR1) | sigmask(SIGUSR2),
            "sa_mask and the signal itself are blocked"
        );
        let (gp, fp, fl, old_sp, old_pc) = before;
        match abi {
            LinuxAbi::X86_64 => {
                let GuestCpu::X86_64(x) = c else {
                    unreachable!()
                };
                let r = x.vcpu().user_regs();
                assert_eq!(
                    (r.rdi, r.rsi, r.rdx, r.rax),
                    (10, frame + 312, frame + 8, 0)
                );
                assert_eq!(x.vcpu().user_rflags() & 0x0001_0500, 0, "DF, RF, TF clear");
                assert_eq!(
                    x.vcpu().mxcsr(),
                    0x1F80,
                    "handlers start with init FPU state"
                );
                assert_eq!(r.zmm_ext[5], [0; 8]);
                assert_eq!(u64_at(&h, frame), RESTORER, "pretcode");
                assert_eq!(
                    u64_at(&h, frame + 8),
                    0x7,
                    "UC_FP_XSTATE|SIGCONTEXT_SS|STRICT"
                );
                assert_eq!(u64_at(&h, frame + 16), 0, "uc_link");
                assert_eq!(read(&h, frame + 24, 24), AltStack::encode_stack_t(0, 2, 0));
                let mc = frame + 48;
                let saved = |i: u64| u64_at(&h, mc + 8 * i);
                // sigcontext: r8..r15, rdi, rsi, rbp, rbx, rdx, rax, rcx, rsp, rip, eflags.
                let order = [7, 8, 9, 10, 11, 12, 13, 14, 5, 4, 6, 1, 3, 0, 2];
                for (slot, &g) in order.iter().enumerate() {
                    assert_eq!(saved(slot as u64), gp[g], "sigcontext word {slot}");
                }
                assert_eq!((saved(15), saved(16), saved(17)), (old_sp, old_pc, fl));
                assert_eq!(u32_at(&h, mc + 144), 0x33, "cs, gs = 0");
                assert_eq!(u32_at(&h, mc + 148), 0x2b << 16, "fs = 0, ss");
                assert_eq!(saved(21), 0, "oldmask");
                let fpstate = saved(23);
                assert_eq!(fpstate % 64, 0);
                assert!(fpstate > frame + 440 && fpstate + 2692 <= sp - 128);
                assert_eq!(u64_at(&h, frame + 304), 0, "uc_sigmask");
                // _fpx_sw_bytes and the magics (asm/sigcontext.h).
                assert_eq!(u32_at(&h, fpstate + 464), 0x4650_5853);
                assert_eq!(u32_at(&h, fpstate + 468), 2692);
                assert_eq!(u64_at(&h, fpstate + 472), 0xE7);
                assert_eq!(u32_at(&h, fpstate + 480), 2688);
                assert_eq!(u32_at(&h, fpstate + 2688), 0x4650_5845);
                assert_eq!(u64_at(&h, fpstate + 512) & 0xE7, 0xE7, "XSTATE_BV");
                assert_eq!(u64_at(&h, fpstate + 160), fp[0], "xmm0");
                assert_eq!(
                    u32_at(&h, fpstate + 24) as u64,
                    *fp.last().unwrap(),
                    "mxcsr"
                );
            }
            LinuxAbi::Aarch64 => {
                let GuestCpu::Aarch64(a) = c else {
                    unreachable!()
                };
                let core = a.core();
                let next_frame = (sp - 16) & !15;
                assert_eq!(
                    (core.get_x(0), core.get_x(1), core.get_x(2)),
                    (10, frame, frame + 128)
                );
                assert_eq!((core.get_x(29), core.get_x(30)), (next_frame, RESTORER));
                assert_eq!(
                    read(&h, next_frame, 16),
                    [gp[29].to_le_bytes(), gp[30].to_le_bytes()].concat()
                );
                assert_eq!(u64_at(&h, frame + 128), 0, "uc_flags");
                assert_eq!(u64_at(&h, frame + 168), 0, "uc_sigmask");
                assert_eq!(u64_at(&h, frame + 304), 0, "fault_address");
                for r in 0..31u64 {
                    assert_eq!(u64_at(&h, frame + 312 + 8 * r), gp[r as usize], "x{r}");
                }
                assert_eq!(u64_at(&h, frame + 560), old_sp);
                assert_eq!(u64_at(&h, frame + 568), old_pc);
                assert_eq!(u64_at(&h, frame + 576), fl, "pstate");
                // fpsimd_context at __reserved, then the terminator.
                assert_eq!(
                    (u32_at(&h, frame + 592), u32_at(&h, frame + 596)),
                    (0x4650_8001, 528)
                );
                assert_eq!(u32_at(&h, frame + 600) as u64, fp[64], "fpsr");
                assert_eq!(u32_at(&h, frame + 604) as u64, fp[65], "fpcr");
                assert_eq!(
                    read(&h, frame + 608, 16),
                    [fp[0].to_le_bytes(), fp[1].to_le_bytes()].concat()
                );
                assert_eq!(
                    read(&h, frame + 1120, 8),
                    [0; 8],
                    "no ESR record without a fault"
                );
            }
            LinuxAbi::Riscv64 => {
                let GuestCpu::Riscv64(r) = c else {
                    unreachable!()
                };
                let core = r.core();
                assert_eq!(
                    (core.x(10), core.x(11), core.x(12)),
                    (10, frame, frame + 128)
                );
                assert_eq!(core.x(1), h.proc.state.sigtramp, "ra = __vdso_rt_sigreturn");
                assert_eq!(u64_at(&h, frame + 304), old_pc, "sc_regs.pc");
                let mut i = 0;
                for x in 1..32u64 {
                    let v = u64_at(&h, frame + 304 + 8 * x);
                    if x == 2 {
                        assert_eq!(v, old_sp);
                    } else {
                        assert_eq!(v, gp[i], "x{x}");
                        i += 1;
                    }
                }
                for f in 0..32u64 {
                    assert_eq!(u64_at(&h, frame + 560 + 8 * f), fp[f as usize], "f{f}");
                }
                assert_eq!(u32_at(&h, frame + 816) as u64, fp[32], "fcsr");
                assert_eq!(u32_at(&h, frame + 1076), 0, "sc_extdesc.reserved");
                // The vector record: header at sc_extdesc.hdr, then
                // __riscv_v_ext_state {vstart, vl, vtype, vcsr, vlenb,
                // datap} and the registers at datap.
                assert_eq!(
                    (u32_at(&h, frame + 1080), u32_at(&h, frame + 1084)),
                    (0x5346_5457, 568)
                );
                let state: Vec<u64> = (0..6).map(|i| u64_at(&h, frame + 1088 + 8 * i)).collect();
                assert_eq!(&state[..5], &fp[33..38], "vstart, vl, vtype, vcsr, vlenb");
                assert_eq!(state[5], frame + 1136, "datap");
                assert_eq!(u64_at(&h, frame + 1136), fp[38], "v0");
                assert_eq!(read(&h, frame + 1080 + 568, 8), [0; 8], "END header");
            }
        }
        // siginfo: SI_TKILL from this process.
        let info = frame + if abi == LinuxAbi::X86_64 { 312 } else { 0 };
        assert_eq!(u32_at(&h, info), SIGUSR1 as u32);
        assert_eq!(u32_at(&h, info + 8) as i32, code::SI_TKILL);
        assert_eq!(
            (u32_at(&h, info + 16) as i32, u32_at(&h, info + 20)),
            (pid, uid)
        );
    });
}

#[test]
fn sigreturn_restores_the_interrupted_context() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        install(
            &mut h,
            SIGUSR1,
            HANDLER,
            sa::SIGINFO | restorer_flag(abi),
            0,
        );
        prepare(&mut h, 2);
        let before = context(&mut h);
        raise(&mut h, SIGUSR1);
        h.proc.deliver_signals(0);
        let frame = h.proc.threads[0].cpu.sp();
        // The handler clobbers everything, then returns: x86 `ret` pops
        // pretcode; arm64 and riscv return to the trampoline with SP at the
        // frame.
        let c = cpu(&mut h);
        set_gprs(c, 7);
        set_fpstate(c, 7);
        set_flags(c, 7);
        c.set_sp(if abi == LinuxAbi::X86_64 {
            frame + 8
        } else {
            frame
        });
        assert_eq!(h.dispatch(Sysno::RtSigreturn, &[]), Outcome::Unchanged);
        assert_eq!(context(&mut h), before, "{abi:?}");
        assert_eq!(h.proc.threads[0].sigmask, 0, "the saved mask is back");
    });
}

#[test]
fn a_handler_can_edit_the_saved_context() {
    // Handlers that skip a faulting instruction rewrite the saved PC.
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        install(
            &mut h,
            SIGUSR1,
            HANDLER,
            sa::SIGINFO | restorer_flag(abi),
            0,
        );
        prepare(&mut h, 2);
        raise(&mut h, SIGUSR1);
        h.proc.deliver_signals(0);
        let frame = h.proc.threads[0].cpu.sp();
        let (pc_slot, mask_slot) = match abi {
            LinuxAbi::X86_64 => (frame + 48 + 128, frame + 304),
            LinuxAbi::Aarch64 => (frame + 568, frame + 168),
            LinuxAbi::Riscv64 => (frame + 304, frame + 168),
        };
        let space = &h.proc.state.space;
        space.write(pc_slot, &(CODE + 0x77c).to_le_bytes()).unwrap();
        space
            .write(
                mask_slot,
                &(sigmask(SIGUSR2) | sigmask(SIGKILL)).to_le_bytes(),
            )
            .unwrap();
        let c = cpu(&mut h);
        c.set_sp(if abi == LinuxAbi::X86_64 {
            frame + 8
        } else {
            frame
        });
        h.dispatch(Sysno::RtSigreturn, &[]);
        assert_eq!(h.proc.threads[0].cpu.pc(), CODE + 0x77c);
        assert_eq!(
            h.proc.threads[0].sigmask,
            sigmask(SIGUSR2),
            "SIGKILL can never be blocked"
        );
    });
}

#[test]
fn a_bad_frame_raises_sigsegv() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        cpu(&mut h).set_sp(0x10_0000); // unmapped
        assert_eq!(h.dispatch(Sysno::RtSigreturn, &[]), Outcome::Unchanged);
        let t = &mut h.proc.threads[0];
        assert_eq!(t.cpu.syscall_return_value(), 0, "badframe returns 0");
        let info = t.pending.dequeue(0).expect("SIGSEGV is forced");
        assert_eq!(info.signo, SIGSEGV);
        match abi {
            // restore_sigframe zero-fills every unreadable word, so the
            // restored SP is 0; arm64_notify_segfault(0) finds mappings
            // above it: SEGV_ACCERR at 0.
            LinuxAbi::Aarch64 => {
                assert_eq!((info.code, info.addr()), (code::SEGV_ACCERR, 0));
            }
            _ => assert_eq!(info.code, code::SI_KERNEL),
        }
    });
}

#[test]
fn x86_handlers_need_sa_restorer() {
    // x64_setup_rt_frame returns -EFAULT without SA_RESTORER, and the
    // failed delivery of a non-SIGSEGV signal forces SIGSEGV.
    let mut h = Harness::new(LinuxAbi::X86_64);
    install(&mut h, SIGUSR1, HANDLER, sa::SIGINFO, 0);
    prepare(&mut h, 2);
    raise(&mut h, SIGUSR1);
    h.proc.deliver_signals(0);
    assert!(matches!(
        h.proc.state.exit,
        Some(ExitStatus::Signaled { info, .. }) if info.signo == SIGSEGV
    ));
}

#[test]
fn arm64_without_sa_restorer_returns_through_the_vdso() {
    let mut h = Harness::new(LinuxAbi::Aarch64);
    install(&mut h, SIGUSR1, HANDLER, 0, 0);
    prepare(&mut h, 2);
    raise(&mut h, SIGUSR1);
    h.proc.deliver_signals(0);
    let GuestCpu::Aarch64(a) = &h.proc.threads[0].cpu else {
        unreachable!()
    };
    let tramp = h.proc.state.sigtramp;
    assert_eq!(a.core().get_x(30), tramp);
    // Without SA_SIGINFO, x1 and x2 keep their values.
    assert_eq!(a.core().get_x(1), word(2, 1));
    // __kernel_rt_sigreturn: mov x8, #139 ; svc #0, after a nop.
    assert_eq!(u32_at(&h, tramp - 4), 0xd503_201f);
    assert_eq!(u32_at(&h, tramp), 0xd280_1168);
    assert_eq!(u32_at(&h, tramp + 4), 0xd400_0001);
    let vma = h.proc.state.space.vma_at(tramp).unwrap();
    assert_eq!(vma.name.as_deref(), Some("[vdso]"));
}

#[test]
fn riscv_trampoline_is_li_a7_ecall_and_x86_has_none() {
    let h = Harness::new(LinuxAbi::Riscv64);
    let tramp = h.proc.state.sigtramp;
    assert_eq!(
        (u32_at(&h, tramp), u32_at(&h, tramp + 4)),
        (0x08b0_0893, 0x73)
    );
    assert_eq!(Harness::new(LinuxAbi::X86_64).proc.state.sigtramp, 0);
}

#[test]
fn a_fault_records_the_arch_fault_state() {
    use crate::error::MemoryAccessKind;
    use crate::user::cpu::{AccessFault, AccessFaultKind};
    use crate::user::linux::arch::fault_signal;
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        install(
            &mut h,
            SIGSEGV,
            HANDLER,
            sa::SIGINFO | restorer_flag(abi),
            0,
        );
        prepare(&mut h, 2);
        let f = AccessFault {
            addr: 0x1234_5000,
            access: MemoryAccessKind::Write,
            kind: AccessFaultKind::Unmapped,
            pc: CODE + 0x40,
        };
        let update = match abi {
            LinuxAbi::X86_64 => crate::user::linux::arch::x86_64::page_fault_record(&f),
            LinuxAbi::Aarch64 => frame::FaultUpdate::Arm64 {
                address: f.addr,
                esr: crate::user::linux::arch::aarch64::abort_esr(&f),
            },
            LinuxAbi::Riscv64 => frame::FaultUpdate::None,
        };
        h.proc.trap_signal(0, fault_signal(&f), update);
        h.proc.deliver_signals(0);
        let frame = h.proc.threads[0].cpu.sp();
        match abi {
            LinuxAbi::X86_64 => {
                let mc = frame + 48;
                assert_eq!(u64_at(&h, mc + 152), 0b110, "err: W | U, not present");
                assert_eq!(u64_at(&h, mc + 160), 14, "trapno");
                assert_eq!(u64_at(&h, mc + 176), 0x1234_5000, "cr2");
            }
            LinuxAbi::Aarch64 => {
                // Data abort from EL0 (EC 0x24), IL, WnR, level-3
                // translation fault.
                let esr = (0x24 << 26) | (1 << 25) | (1 << 6) | 0x07;
                assert_eq!(u64_at(&h, frame + 304), 0x1234_5000, "fault_address");
                assert_eq!(
                    (u32_at(&h, frame + 1120), u32_at(&h, frame + 1124)),
                    (0x4553_5201, 16)
                );
                assert_eq!(u64_at(&h, frame + 1128), esr);
                assert_eq!(read(&h, frame + 1136, 8), [0; 8], "terminator");
            }
            LinuxAbi::Riscv64 => {}
        }
        let info = frame + if abi == LinuxAbi::X86_64 { 312 } else { 0 };
        assert_eq!(u32_at(&h, info + 8) as i32, code::SEGV_MAPERR);
        assert_eq!(u64_at(&h, info + 16), 0x1234_5000);
    });
}

// ----------------------------------------------------- nesting, stacks

#[test]
fn unblocked_signals_nest_frames() {
    // Each pending, unblocked signal gets a frame below the last; the
    // last one delivered runs first.
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let f = sa::SIGINFO | restorer_flag(abi);
        install(&mut h, SIGUSR1, HANDLER, f, 0);
        install(&mut h, SIGUSR2, HANDLER + 0x40, f, 0);
        let sp = prepare(&mut h, 2);
        raise(&mut h, SIGUSR2);
        raise(&mut h, SIGUSR1);
        h.proc.deliver_signals(0);
        let c = &h.proc.threads[0].cpu;
        assert_eq!(c.pc(), HANDLER + 0x40, "SIGUSR2 delivered last");
        assert!(c.sp() < expected_frame(abi, sp));
        assert_eq!(
            h.proc.threads[0].sigmask,
            sigmask(SIGUSR1) | sigmask(SIGUSR2)
        );
    });
}

#[test]
fn nodefer_resethand_and_masked_signals() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let f = restorer_flag(abi) | sa::NODEFER | sa::RESETHAND;
        install(&mut h, SIGUSR1, HANDLER, f, 0);
        prepare(&mut h, 2);
        raise(&mut h, SIGUSR1);
        h.proc.deliver_signals(0);
        assert_eq!(h.proc.threads[0].sigmask, 0, "SA_NODEFER");
        assert_eq!(
            h.proc.state.sigactions[(SIGUSR1 - 1) as usize].handler,
            SIG_DFL
        );
        // A blocked signal stays pending and is reported by rt_sigpending.
        h.proc.threads[0].sigmask = sigmask(SIGUSR2);
        raise(&mut h, SIGUSR2);
        h.proc.deliver_signals(0);
        assert!(h.proc.state.exit.is_none());
        let at = h.scratch;
        h.ok(Sysno::RtSigpending, &[at, 8]);
        assert_eq!(u64_at(&h, at), sigmask(SIGUSR2));
        // The default action of SIGUSR1 (after SA_RESETHAND) terminates.
        raise(&mut h, SIGUSR1);
        h.proc.deliver_signals(0);
        assert!(matches!(
            h.proc.state.exit,
            Some(ExitStatus::Signaled { info, core: false, .. }) if info.signo == SIGUSR1
        ));
    });
}

#[test]
fn sa_onstack_uses_the_alternate_stack() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let alt = h.anon(0x10000, 3, false);
        let ss = h.scratch + 0x900;
        let stack_t = AltStack::encode_stack_t(alt, ss::AUTODISARM, 0x10000);
        h.proc.state.space.write_raw(ss, &stack_t).unwrap();
        h.ok(Sysno::Sigaltstack, &[ss, 0]);
        install(
            &mut h,
            SIGUSR1,
            HANDLER,
            sa::ONSTACK | sa::SIGINFO | restorer_flag(abi),
            0,
        );
        prepare(&mut h, 2);
        raise(&mut h, SIGUSR1);
        h.proc.deliver_signals(0);
        let frame = h.proc.threads[0].cpu.sp();
        // x86 switches to the stack top after subtracting the red zone, so
        // no red zone is left below it.
        let top = alt + 0x10000 + if abi == LinuxAbi::X86_64 { 128 } else { 0 };
        assert_eq!(frame, expected_frame(abi, top));
        // The frame records the stack; SS_AUTODISARM disabled it.
        let uc_stack = frame + if abi == LinuxAbi::X86_64 { 24 } else { 144 };
        assert_eq!(read(&h, uc_stack, 24), stack_t);
        assert_eq!(h.proc.threads[0].altstack, AltStack::DISABLED);
        // rt_sigreturn restores it.
        let sp = if abi == LinuxAbi::X86_64 {
            frame + 8
        } else {
            frame
        };
        cpu(&mut h).set_sp(sp);
        h.dispatch(Sysno::RtSigreturn, &[]);
        assert_eq!(h.proc.threads[0].altstack.sp, alt);
        assert_eq!(h.proc.threads[0].altstack.flags, ss::AUTODISARM);
    });
}

#[test]
fn an_unwritable_stack_escalates_to_a_fatal_sigsegv() {
    // signal_setup_done → force_sigsegv(SIGUSR1) → SIGSEGV with its
    // handler, whose frame fails too → force_fatal_sig(SIGSEGV).
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let f = sa::SIGINFO | restorer_flag(abi);
        install(&mut h, SIGUSR1, HANDLER, f, 0);
        install(&mut h, SIGSEGV, HANDLER, f, 0);
        prepare(&mut h, 2);
        cpu(&mut h).set_sp(0x10_0000);
        raise(&mut h, SIGUSR1);
        h.proc.deliver_signals(0);
        assert!(matches!(
            h.proc.state.exit,
            Some(ExitStatus::Signaled { info, core: true, .. })
                if info.signo == SIGSEGV && info.code == code::SI_KERNEL
        ));
    });
}

// -------------------------------------------------------------- restart

/// Makes the thread look as if system call `nr` with first argument
/// `arg0` just returned `value`.
fn returning(h: &mut Harness, nr: u64, arg0: u64, value: i64) -> u64 {
    let c = cpu(h);
    c.set_syscall_result(value as u64);
    let pc = c.pc();
    h.proc.threads[0].syscall = Some(SyscallEntry { nr, arg0 });
    pc
}

#[test]
fn restart_codes_follow_the_handler_and_sa_restart() {
    each_abi(|abi| {
        let len = if abi == LinuxAbi::X86_64 { 2 } else { 4 };
        let nr = abi.number(Sysno::Read).unwrap();
        for (code, restartable, with_restart, rewound) in [
            (ERESTARTSYS, true, false, false),
            (ERESTARTSYS, true, true, true),
            (ERESTARTNOINTR, true, false, true),
            (ERESTARTNOHAND, true, true, false),
            (ERESTART_RESTARTBLOCK, true, true, false),
        ] {
            let _ = restartable;
            let mut h = Harness::new(abi);
            let flags = restorer_flag(abi) | if with_restart { sa::RESTART } else { 0 };
            install(&mut h, SIGUSR1, HANDLER, flags, 0);
            prepare(&mut h, 2);
            raise(&mut h, SIGUSR1);
            let pc = returning(&mut h, nr, 0x5a5a, -(code as i64));
            h.proc.deliver_signals(0);
            let frame = h.proc.threads[0].cpu.sp();
            // The frame's saved PC and result register show the outcome.
            let (saved_pc, saved_ret) = match abi {
                LinuxAbi::X86_64 => (u64_at(&h, frame + 48 + 128), u64_at(&h, frame + 48 + 104)),
                LinuxAbi::Aarch64 => (u64_at(&h, frame + 568), u64_at(&h, frame + 312)),
                LinuxAbi::Riscv64 => (u64_at(&h, frame + 304), u64_at(&h, frame + 304 + 80)),
            };
            if rewound {
                let arg = if abi == LinuxAbi::X86_64 { nr } else { 0x5a5a };
                assert_eq!((saved_pc, saved_ret), (pc - len, arg), "{abi:?} {code}");
            } else {
                assert_eq!(
                    (saved_pc, saved_ret as i64),
                    (pc, -i64::from(EINTR)),
                    "{abi:?} {code}"
                );
            }
        }
    });
}

#[test]
fn without_a_handler_calls_restart() {
    each_abi(|abi| {
        let len = if abi == LinuxAbi::X86_64 { 2 } else { 4 };
        let nr = abi
            .number(Sysno::Nanosleep)
            .unwrap_or(abi.number(Sysno::ClockNanosleep).unwrap());
        let restart_nr = abi.number(Sysno::RestartSyscall).unwrap();
        for code in [
            ERESTARTSYS,
            ERESTARTNOINTR,
            ERESTARTNOHAND,
            ERESTART_RESTARTBLOCK,
        ] {
            let mut h = Harness::new(abi);
            install(&mut h, SIGCHLD, SIG_IGN, 0, 0);
            prepare(&mut h, 2);
            // An ignored-but-blocked signal stays queued; unblocking it
            // makes it pending, and delivery discards it.
            h.proc.threads[0].sigmask = sigmask(SIGCHLD);
            raise(&mut h, SIGCHLD);
            h.proc.threads[0].sigmask = 0;
            let pc = returning(&mut h, nr, 0x77, -(code as i64));
            h.proc.deliver_signals(0);
            let c = &h.proc.threads[0].cpu;
            assert_eq!(c.pc(), pc - len, "{abi:?} {code}");
            let (nr_reg, arg0) = match c {
                GuestCpu::X86_64(x) => (x.vcpu().user_regs().rax, 0x77),
                GuestCpu::Aarch64(a) => (a.core().get_x(8), a.core().get_x(0)),
                GuestCpu::Riscv64(r) => (r.core().x(17), r.core().x(10)),
            };
            let want_nr = if code == ERESTART_RESTARTBLOCK {
                restart_nr
            } else if abi == LinuxAbi::X86_64 {
                nr
            } else {
                nr_reg
            };
            assert_eq!(nr_reg, want_nr, "{abi:?} {code}");
            assert_eq!(arg0, 0x77);
        }
    });
}

#[test]
fn restart_syscall_without_a_block_is_eintr() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        assert_eq!(h.err(Sysno::RestartSyscall, &[]), EINTR);
    });
}

// ------------------------------------------------------ signal syscalls

#[test]
fn sigsuspend_returns_through_the_restart_path() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        install(&mut h, SIGUSR1, HANDLER, restorer_flag(abi), 0);
        prepare(&mut h, 2);
        // SIGUSR1 is blocked and pending; sigsuspend unblocks it.
        h.proc.threads[0].sigmask = sigmask(SIGUSR1) | sigmask(SIGUSR2);
        raise(&mut h, SIGUSR1);
        let set = h.scratch;
        h.proc
            .state
            .space
            .write_raw(set, &sigmask(SIGUSR2).to_le_bytes())
            .unwrap();
        let nr = abi.number(Sysno::RtSigsuspend).unwrap();
        let out = h.dispatch(Sysno::RtSigsuspend, &[set, 8]);
        assert_eq!(out, Outcome::Return(-(ERESTARTNOHAND as i64) as u64));
        assert_eq!(h.proc.threads[0].sigmask, sigmask(SIGUSR2));
        returning(&mut h, nr, set, -(ERESTARTNOHAND as i64));
        h.proc.deliver_signals(0);
        let frame = h.proc.threads[0].cpu.sp();
        let mask_slot = frame + if abi == LinuxAbi::X86_64 { 304 } else { 168 };
        assert_eq!(
            u64_at(&h, mask_slot),
            sigmask(SIGUSR1) | sigmask(SIGUSR2),
            "the frame saves the mask sigsuspend replaced"
        );
        assert_eq!(h.proc.threads[0].saved_sigmask, None);
        // With a handler, -ERESTARTNOHAND becomes -EINTR.
        let saved_ret = match abi {
            LinuxAbi::X86_64 => u64_at(&h, frame + 48 + 104),
            LinuxAbi::Aarch64 => u64_at(&h, frame + 312),
            LinuxAbi::Riscv64 => u64_at(&h, frame + 304 + 80),
        };
        assert_eq!(saved_ret as i64, -i64::from(EINTR));
        assert_eq!(h.proc.threads[0].cpu.pc(), HANDLER);
    });
}

#[test]
fn sigtimedwait_dequeues_without_a_handler() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let rt = SIGRTMIN + 2;
        h.proc.threads[0].sigmask = sigmask(rt);
        let info_at = h.scratch + 0x200;
        let set = h.scratch;
        h.proc
            .state
            .space
            .write_raw(set, &sigmask(rt).to_le_bytes())
            .unwrap();
        // sigqueue with a value to ourselves (SI_QUEUE is negative, so it
        // may be forged).
        let q = SigInfo::queued(0, code::SI_QUEUE, 1, 2, 0xfeed);
        h.proc
            .state
            .space
            .write_raw(h.scratch + 0x300, &q.encode())
            .unwrap();
        let pid = h.proc.state.pid as u64;
        h.ok(Sysno::RtSigqueueinfo, &[pid, rt as u64, h.scratch + 0x300]);
        let zero = h.scratch + 0x100;
        h.proc.state.space.write_raw(zero, &[0u8; 16]).unwrap();
        let out = h.dispatch(Sysno::RtSigtimedwait, &[set, info_at, zero, 8]);
        assert_eq!(out, Outcome::Return(rt as u64));
        assert_eq!(u32_at(&h, info_at), rt as u32);
        assert_eq!(u32_at(&h, info_at + 8) as i32, code::SI_QUEUE);
        assert_eq!(u64_at(&h, info_at + 24), 0xfeed, "si_value");
        // Nothing left: a zero timeout is EAGAIN.
        assert_eq!(
            h.err(Sysno::RtSigtimedwait, &[set, info_at, zero, 8]),
            EAGAIN
        );
        // Forging SI_USER (>= 0) to another process is EPERM.
        let forged = SigInfo::kill(0, code::SI_USER, 1, 2);
        h.proc
            .state
            .space
            .write_raw(h.scratch + 0x300, &forged.encode())
            .unwrap();
        assert_eq!(
            h.err(
                Sysno::RtSigqueueinfo,
                &[pid + 1, rt as u64, h.scratch + 0x300]
            ),
            EPERM
        );
    });
}

#[test]
fn sigaction_masks_flags_and_flushes_ignored_signals() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        h.proc.threads[0].sigmask = sigmask(SIGUSR1);
        raise(&mut h, SIGUSR1);
        assert!(h.proc.threads[0].pending.contains(SIGUSR1));
        // Unknown flag bits (SA_UNSUPPORTED 0x400) are dropped; SIG_IGN
        // discards the pending instance even though it is blocked.
        install(
            &mut h,
            SIGUSR1,
            SIG_IGN,
            0x400 | sa::RESTART,
            sigmask(SIGKILL),
        );
        assert!(!h.proc.threads[0].pending.contains(SIGUSR1));
        let old = h.scratch + 0xa00;
        h.ok(Sysno::RtSigaction, &[SIGUSR1 as u64, 0, old, 8]);
        assert_eq!(u64_at(&h, old), SIG_IGN);
        assert_eq!(u64_at(&h, old + 8), sa::RESTART);
        let mask_at = old + if abi.has_sa_restorer() { 24 } else { 16 };
        assert_eq!(u64_at(&h, mask_at), 0, "SIGKILL is removed from sa_mask");
        assert_eq!(
            h.err(Sysno::RtSigaction, &[SIGKILL as u64, old, 0, 8]),
            EINVAL
        );
        assert_eq!(h.err(Sysno::RtSigaction, &[65, 0, 0, 8]), EINVAL);
        assert_eq!(
            h.err(Sysno::RtSigaction, &[SIGUSR1 as u64, 0, 0, 4]),
            EINVAL
        );
    });
}

#[test]
fn kill_and_tgkill_validate_their_targets() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let (pid, tid) = (h.proc.state.pid as u64, h.proc.threads[0].tid as u64);
        assert_eq!(h.ok(Sysno::Kill, &[pid, 0]), 0, "sig 0 probes");
        assert_eq!(h.err(Sysno::Kill, &[pid, 65]), EINVAL);
        assert_eq!(h.err(Sysno::Kill, &[(-1i64) as u64, SIGUSR1 as u64]), ESRCH);
        assert_eq!(h.err(Sysno::Tgkill, &[0, tid, 1]), EINVAL);
        assert_eq!(h.err(Sysno::Tgkill, &[pid, tid + 1, 1]), ESRCH);
        assert_eq!(h.err(Sysno::Tkill, &[0, 1]), EINVAL);
        h.ok(Sysno::Kill, &[0, SIGUSR2 as u64]);
        let info = h.proc.state.shared_pending.dequeue(0).unwrap();
        assert_eq!(
            (info.signo, info.code, info.pid()),
            (SIGUSR2, code::SI_USER, pid as i32)
        );
    });
}

#[test]
fn stop_and_continue_signals_cancel_each_other() {
    // prepare_signal: generating SIGCONT discards pending stop signals and
    // vice versa.
    let mut h = Harness::new(LinuxAbi::X86_64);
    let all = sigmask(SIGTSTP) | sigmask(SIGCONT);
    h.proc.threads[0].sigmask = all;
    raise(&mut h, SIGTSTP);
    raise(&mut h, SIGCONT);
    assert!(!h.proc.threads[0].pending.contains(SIGTSTP));
    assert!(h.proc.threads[0].pending.contains(SIGCONT));
    raise(&mut h, SIGTSTP);
    assert!(!h.proc.threads[0].pending.contains(SIGCONT));
}

#[test]
fn sigaltstack_reports_and_refuses_changes_on_the_stack() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let (new, old) = (h.scratch, h.scratch + 0x40);
        let alt = h.anon(0x4000, 3, false);
        h.proc
            .state
            .space
            .write_raw(new, &AltStack::encode_stack_t(alt, 0, 0x4000))
            .unwrap();
        h.ok(Sysno::Sigaltstack, &[new, old]);
        assert_eq!(
            read(&h, old, 24),
            AltStack::encode_stack_t(0, ss::DISABLE, 0)
        );
        cpu(&mut h).set_sp(alt + 0x100);
        h.ok(Sysno::Sigaltstack, &[0, old]);
        assert_eq!(
            read(&h, old, 24),
            AltStack::encode_stack_t(alt, ss::ONSTACK, 0x4000)
        );
        assert_eq!(h.err(Sysno::Sigaltstack, &[new, old]), EPERM);
        let min = minsigstksz(abi);
        cpu(&mut h).set_sp(0x7000_0000);
        h.proc
            .state
            .space
            .write_raw(new, &AltStack::encode_stack_t(alt, 0, min - 1))
            .unwrap();
        assert_eq!(h.err(Sysno::Sigaltstack, &[new, 0]), ENOMEM);
    });
}

#[test]
fn writing_to_a_widowed_pipe_raises_sigpipe() {
    // pipe_write: no readers → send_sig(SIGPIPE) and -EPIPE.
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let fds = h.scratch;
        h.ok(Sysno::Pipe2, &[fds, 0]);
        let (rd, wr) = (u32_at(&h, fds) as u64, u32_at(&h, fds + 4) as u64);
        h.ok(Sysno::Close, &[rd]);
        assert_eq!(h.err(Sysno::Write, &[wr, fds, 1]), EPIPE);
        // send_sig is PIDTYPE_PID: the writing thread's own queue.
        assert!(h.proc.state.shared_pending.dequeue(0).is_none());
        let info = h.proc.threads[0].pending.dequeue(0).expect("SIGPIPE");
        assert_eq!((info.signo, info.code), (SIGPIPE, code::SI_USER));
        assert_eq!(info.pid(), h.proc.state.pid);
        // Ignored, it is not even queued.
        install(&mut h, SIGPIPE, SIG_IGN, 0, 0);
        assert_eq!(h.err(Sysno::Write, &[wr, fds, 1]), EPIPE);
        assert!(h.proc.threads[0].pending.dequeue(0).is_none());
    });
}

#[test]
fn proc_status_reports_the_signal_sets() {
    // fs/proc/array.c task_sig: SigQ, SigPnd, ShdPnd, SigBlk, SigIgn, SigCgt.
    let mut h = Harness::new(LinuxAbi::X86_64);
    install(&mut h, SIGUSR1, HANDLER, sa::RESTORER, 0);
    install(&mut h, SIGPIPE, SIG_IGN, 0, 0);
    h.proc.threads[0].sigmask = sigmask(SIGUSR2);
    raise(&mut h, SIGUSR2);
    let pid = h.proc.state.pid as u64;
    h.ok(Sysno::Kill, &[pid, SIGUSR2 as u64]);
    let status = crate::user::linux::procfs::status(&h.proc.state, &h.proc.threads[0], 1);
    let status = String::from_utf8(status).unwrap();
    for line in [
        "SigQ:\t2/63000",
        "SigPnd:\t0000000000000800",
        "ShdPnd:\t0000000000000800",
        "SigBlk:\t0000000000000800",
        "SigIgn:\t0000000000001000",
        "SigCgt:\t0000000000000200",
    ] {
        assert!(status.contains(line), "{line:?} in\n{status}");
    }
}
