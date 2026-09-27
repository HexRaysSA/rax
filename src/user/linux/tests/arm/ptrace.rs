//! Tracing an AArch32 thread against Linux 6.19 on arm64
//! (`arch/arm64/kernel/ptrace.c`): the answers a 32-bit tracer gets
//! (`compat_arch_ptrace`: `compat_elf_gregset_t`, 32-bit ARM's `struct
//! user` offsets, the TLS word, the system-call number, the VFP set; the
//! ARM requests arm64 does not have are `EIO`), the sets of its view
//! (`user_aarch32_view`), the AArch32 ptrace view a 64-bit tracer has
//! (`user_aarch32_ptrace_view`: also the TLS word and `NT_ARM_SYSTEM_CALL`),
//! `valid_compat_regs` on writing, and a 32-bit tracer's view of an AArch64
//! thread (`compat_get_user_reg`, `valid_native_regs`). The tracer's own
//! side is the fixtures `ptrace`, `ptracestops`, and `ptraceregs`.

use super::super::harness::Harness;
use super::super::ptrace_stops::{Tracer, traced};
use super::arm;
use crate::isa::arm::vfp::Fpscr;
use crate::user::linux::abi::LinuxAbi;
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::arch::GuestCpu;
use crate::user::linux::ptrace::{Msg, regs, regs_a32, req};

fn e(errno: i32) -> i64 {
    -(errno as i64)
}

/// A request to thread 0, asked in a 32-bit call when `compat`.
fn ask(
    h: &mut Harness,
    tr: &mut Tracer,
    compat: bool,
    request: u64,
    addr: u64,
    data: u64,
    payload: &[u8],
) -> (i64, Vec<u8>) {
    let m = Msg::Request {
        tid: h.proc.threads[0].tid,
        req: request,
        addr,
        data,
        compat,
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

fn word(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

/// A traced AArch32 thread with known registers: r0 0x11110000, r12
/// 0xcccc, D15 and an FPSCR with RMode 01 and IOC, and a TLS word.
fn tracee(h: &mut Harness) -> Tracer {
    let tr = traced(h, 0);
    let c = arm(h);
    let core = c.core_mut();
    core.regs[0] = 0x1111_0000;
    core.regs[12] = 0xcccc;
    core.vfp.dregs[15] = 0x1122_3344_5566_7788;
    core.vfp.fpscr = Fpscr::from_bits((1 << 22) | 1);
    h.proc.threads[0].cpu.set_thread_pointer(0xb6f0_1000);
    tr
}

#[test]
fn a_32_bit_tracer_gets_compat_arch_ptraces_forms() {
    let mut h = Harness::new(LinuxAbi::Arm);
    let mut tr = tracee(&mut h);
    let t = &mut tr;
    // compat_elf_gregset_t: r0-r15, the CPSR (User mode, A, I, F clear),
    // orig_r0 (none outside a call).
    let (r, gregs) = ask(&mut h, t, true, req::GETREGS, 0, 0, &[]);
    assert_eq!((r, gregs.len()), (0, 72));
    assert_eq!((word(&gregs, 0), word(&gregs, 48)), (0x1111_0000, 0xcccc));
    assert_eq!(u64::from(word(&gregs, 60)), h.proc.threads[0].cpu.pc());
    let cpsr = word(&gregs, 64);
    assert_eq!((cpsr & 0x1f, cpsr & 0x1c0), (0x10, 0));
    assert_eq!(word(&gregs, 68), 0);
    // struct user's words: the registers, then zero up to 296 bytes;
    // past it and misaligned are EIO; the image's addresses at 0x10000.
    assert_eq!(
        ask(&mut h, t, true, req::PEEKUSR, 60, 0, &[]),
        (0, gregs[60..64].to_vec())
    );
    assert_eq!(
        ask(&mut h, t, true, req::PEEKUSR, 292, 0, &[]),
        (0, vec![0; 4])
    );
    assert_eq!(ask(&mut h, t, true, req::PEEKUSR, 296, 0, &[]).0, e(EIO));
    assert_eq!(ask(&mut h, t, true, req::PEEKUSR, 2, 0, &[]).0, e(EIO));
    let prog = &h.proc.state.mm.program;
    let (code, data, end) = (prog.start_code, prog.start_data, prog.end_code);
    for (off, want) in [(0x1_0000, code), (0x1_0004, data), (0x1_0008, end)] {
        let (r, v) = ask(&mut h, t, true, req::PEEKUSR, off, 0, &[]);
        assert_eq!((r, word(&v, 0)), (0, want as u32), "{off:#x}");
    }
    // Writing: a register, a word past them (dropped), and a CPSR that
    // valid_compat_regs refuses (another mode, A set): EINVAL, nothing
    // written. E is dropped (no mixed-endian EL0).
    assert_eq!(ask(&mut h, t, true, req::POKEUSR, 4, 0x1234, &[]).0, 0);
    assert_eq!(arm(&mut h).core().regs[1], 0x1234);
    assert_eq!(ask(&mut h, t, true, req::POKEUSR, 72, 7, &[]).0, 0);
    assert_eq!(ask(&mut h, t, true, req::POKEUSR, 296, 7, &[]).0, e(EIO));
    assert_eq!(ask(&mut h, t, true, req::POKEUSR, 3, 7, &[]).0, e(EIO));
    let svc = u64::from(cpsr & !0x1f | 0x13);
    assert_eq!(
        ask(&mut h, t, true, req::POKEUSR, 64, svc, &[]).0,
        e(EINVAL)
    );
    let abort = u64::from(cpsr | 0x100);
    assert_eq!(
        ask(&mut h, t, true, req::POKEUSR, 64, abort, &[]).0,
        e(EINVAL)
    );
    let nzcv_e = u64::from(cpsr | 0xf000_0200);
    assert_eq!(ask(&mut h, t, true, req::POKEUSR, 64, nzcv_e, &[]).0, 0);
    let (_, now) = ask(&mut h, t, true, req::PEEKUSR, 64, 0, &[]);
    assert_eq!(word(&now, 0), cpsr | 0xf000_0000);
    // A refused PTRACE_SETREGS writes nothing.
    let mut bad = gregs.clone();
    bad[0..4].copy_from_slice(&0x5555u32.to_le_bytes());
    bad[64..68].copy_from_slice(&(cpsr | 0x80).to_le_bytes());
    assert_eq!(ask(&mut h, t, true, req::SETREGS, 0, 0, &bad).0, e(EINVAL));
    assert_eq!(arm(&mut h).core().regs[0], 0x1111_0000);
    assert_eq!(ask(&mut h, t, true, req::SETREGS, 0, 0, &gregs).0, 0);
    assert_eq!(arm(&mut h).core().regs[1], word(&gregs, 4));
    // The TLS word, and the system-call number (as NT_ARM_SYSTEM_CALL
    // writes it).
    let (r, tls) = ask(&mut h, t, true, req::compat_arm::GET_THREAD_AREA, 0, 0, &[]);
    assert_eq!((r, word(&tls, 0)), (0, 0xb6f0_1000));
    assert_eq!(
        ask(&mut h, t, true, req::compat_arm::SET_SYSCALL, 0, 42, &[]).0,
        0
    );
    assert_eq!(h.proc.threads[0].syscall.map(|s| s.nr), Some(42));
    // The VFP set: D0-D31, then the FPSCR's status and control bits.
    let (r, vfp) = ask(&mut h, t, true, req::compat_arm::GETVFPREGS, 0, 0, &[]);
    assert_eq!((r, vfp.len()), (0, 260));
    assert_eq!(vfp[120..128], 0x1122_3344_5566_7788u64.to_le_bytes());
    assert_eq!(word(&vfp, 256), (1 << 22) | 1);
    let mut next = vfp.clone();
    next[120..128].copy_from_slice(&7u64.to_le_bytes());
    next[256..260].copy_from_slice(&(2u32 << 22).to_le_bytes());
    assert_eq!(
        ask(&mut h, t, true, req::compat_arm::SETVFPREGS, 0, 0, &next).0,
        0
    );
    let v = &arm(&mut h).core().vfp;
    assert_eq!((v.dregs[15], v.fpscr.bits()), (7, 2 << 22));
    // ARM's other requests have nothing behind them on arm64 (no FPA,
    // iWMMXt, or Crunch; no hardware breakpoints here).
    for request in [14, 15, 18, 19, 25, 26, 29, 30] {
        assert_eq!(
            ask(&mut h, t, true, request, 0, 0, &[]).0,
            e(EIO),
            "{request}"
        );
    }
    // PEEKDATA's word is 32 bits.
    let at = h.scratch;
    h.proc.state.space.write_raw(at, b"abcdefgh").unwrap();
    assert_eq!(
        ask(&mut h, t, true, req::PEEKDATA, at, 0, &[]),
        (0, b"abcd".to_vec())
    );
}

#[test]
fn the_views_sets_follow_the_tracer_then_the_thread() {
    let mut h = Harness::new(LinuxAbi::Arm);
    let mut tr = tracee(&mut h);
    let t = &mut tr;
    let get = |h: &mut Harness, t: &mut Tracer, compat: bool, nt: u64| {
        ask(h, t, compat, req::GETREGSET, nt, 4096, &[])
    };
    // A 32-bit tracer's view: the general and VFP sets only.
    let (r, gregs) = get(&mut h, t, true, regs::NT_PRSTATUS);
    assert_eq!((r, gregs.len()), (0, 72));
    assert_eq!(get(&mut h, t, true, regs_a32::NT_ARM_VFP).1.len(), 260);
    for nt in [regs::NT_ARM_TLS, regs::NT_ARM_SYSTEM_CALL, regs::NT_PRFPREG] {
        assert_eq!(get(&mut h, t, true, nt).0, e(EINVAL), "{nt:#x}");
    }
    // A 64-bit tracer's: also the TLS word and the system-call number
    // (-1 outside a call), still no NT_PRFPREG; no PTRACE_PEEKUSR or
    // PTRACE_GETREGS on arm64.
    assert_eq!(get(&mut h, t, false, regs::NT_PRSTATUS), (0, gregs.clone()));
    let (r, tls) = get(&mut h, t, false, regs::NT_ARM_TLS);
    assert_eq!((r, tls), (0, 0xb6f0_1000u32.to_le_bytes().to_vec()));
    let (r, nr) = get(&mut h, t, false, regs::NT_ARM_SYSTEM_CALL);
    assert_eq!((r, nr), (0, (-1i32).to_le_bytes().to_vec()));
    assert_eq!(get(&mut h, t, false, regs::NT_PRFPREG).0, e(EINVAL));
    assert_eq!(ask(&mut h, t, false, req::PEEKUSR, 0, 0, &[]).0, e(EIO));
    assert_eq!(ask(&mut h, t, false, req::GETREGS, 0, 0, &[]).0, e(EIO));
    // Writing them: the TLS word; a general set with a bad CPSR is
    // EINVAL with nothing written; a prefix writes its registers only.
    let set = |h: &mut Harness, t: &mut Tracer, nt: u64, b: &[u8]| {
        ask(h, t, false, req::SETREGSET, nt, b.len() as u64, b).0
    };
    assert_eq!(
        set(&mut h, t, regs::NT_ARM_TLS, &0x4000u32.to_le_bytes()),
        0
    );
    assert_eq!(h.proc.threads[0].cpu.thread_pointer(), 0x4000);
    let mut bad = gregs.clone();
    bad[0..4].copy_from_slice(&9u32.to_le_bytes());
    bad[64..68].copy_from_slice(&0x1bu32.to_le_bytes());
    assert_eq!(set(&mut h, t, regs::NT_PRSTATUS, &bad), e(EINVAL));
    assert_eq!(arm(&mut h).core().regs[0], 0x1111_0000);
    assert_eq!(set(&mut h, t, regs::NT_PRSTATUS, &9u32.to_le_bytes()), 0);
    assert_eq!(arm(&mut h).core().regs[0], 9);
    // The tracer's side sizes the sets the same way.
    let cpu = &h.proc.threads[0].cpu;
    assert_eq!(
        regs::layout(cpu, true, true, regs::NT_PRSTATUS),
        Ok((4, 72))
    );
    assert_eq!(
        regs::layout(cpu, true, true, regs::NT_ARM_TLS)
            .unwrap_err()
            .0,
        EINVAL
    );
    assert_eq!(regs::layout(cpu, false, true, regs::NT_ARM_TLS), Ok((4, 4)));
    assert_eq!(
        regs::layout(cpu, false, true, regs_a32::NT_ARM_VFP),
        Ok((4, 260))
    );
}

#[test]
fn a_32_bit_tracer_sees_an_aarch64_thread_in_32_bits() {
    // compat_get_user_reg of an AArch64 thread: x0-x14's low words, the
    // PC, PSTATE; writing one zero-extends it, and an AArch32 CPSR is
    // refused (valid_native_regs).
    let mut h = Harness::new(LinuxAbi::Aarch64);
    let mut tr = traced(&mut h, 0);
    let t = &mut tr;
    let GuestCpu::Aarch64(c) = &mut h.proc.threads[0].cpu else {
        panic!("an AArch64 task has an AArch64 CPU");
    };
    c.core_mut().set_x(0, 0xdead_beef_1234_5678);
    c.core_mut().set_x(13, 0x13);
    let (r, gregs) = ask(&mut h, t, true, req::GETREGS, 0, 0, &[]);
    assert_eq!((r, gregs.len()), (0, 72));
    assert_eq!((word(&gregs, 0), word(&gregs, 52)), (0x1234_5678, 0x13));
    assert_eq!(
        u64::from(word(&gregs, 60)),
        h.proc.threads[0].cpu.pc() & 0xffff_ffff
    );
    assert_eq!(ask(&mut h, t, true, req::POKEUSR, 0, 0xffff_0001, &[]).0, 0);
    let GuestCpu::Aarch64(c) = &h.proc.threads[0].cpu else {
        unreachable!()
    };
    assert_eq!(c.core().get_x(0), 0xffff_0001);
    assert_eq!(
        ask(&mut h, t, true, req::POKEUSR, 64, 0x10, &[]).0,
        e(EINVAL)
    );
}
