//! i386 signal frames and their returns against Linux 6.19 on x86-64
//! (`arch/x86/kernel/signal_32.c`, `get_sigframe` in `signal.c`,
//! `fpu/signal.c`, `fpu/regset.c`): the layouts of `struct sigframe_ia32`
//! and `struct rt_sigframe_ia32` (`asm/sigframe.h`, `asm/ia32.h`,
//! `uapi/asm/sigcontext.h`), the FSAVE header converted from the FXSAVE
//! image (x87 tag words per the Intel SDM Vol. 1 §8.1.7 and §10.5.1.1),
//! the `[vdso]` trampolines, `sigreturn` and `rt_sigreturn` with their
//! selector reloads, `IRET` checks, and bad frames, and strict seccomp's
//! 32-bit list.

use super::super::harness::{CODE, Harness};
use super::{READ_EXEC_ONLY, SEG_32BIT, USEABLE, put, u32_at, user_desc};
use crate::isa::x86_64::{LINUX_USER_DS, LINUX_USER32_CS, X86UserSegment};
use crate::user::cpu::x86_64::X86UserCpu;
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::{LinuxAbi, Sysno};
use crate::user::linux::arch::GuestCpu;
use crate::user::linux::process::ExitStatus;
use crate::user::linux::signal::frame::ia32::{self, off, rt, sc};
use crate::user::linux::signal::*;
use crate::user::linux::syscall::Outcome;

/// Handler entry point (never executed).
const HANDLER: u64 = CODE + 0x100;
/// `sa_restorer`.
const RESTORER: u64 = CODE + 0x200;
/// The standard XSAVE size for XCR0 = 0xE7 (x87, SSE, AVX, and the three
/// AVX-512 components: the ZMM_Hi256 area ends at 1664 + 1024).
const XSAVE_SIZE: u64 = 2688;
/// `FP_XSTATE_MAGIC1` and `FP_XSTATE_MAGIC2` (`uapi/asm/sigcontext.h`).
const MAGIC1: u32 = 0x4650_5853;
const MAGIC2: u32 = 0x4650_5845;

fn x86(h: &mut Harness) -> &mut X86UserCpu {
    match &mut h.proc.threads[0].cpu {
        GuestCpu::X86_64(c) => c,
        _ => unreachable!("an i386 task has an x86 CPU"),
    }
}

fn read(h: &Harness, at: u64, len: usize) -> Vec<u8> {
    let mut b = vec![0u8; len];
    h.proc.state.space.read(at, &mut b).unwrap();
    b
}

fn u64_at(h: &Harness, at: u64) -> u64 {
    u64::from(u32_at(h, at)) | u64::from(u32_at(h, at + 4)) << 32
}

fn words(w: &[u32]) -> Vec<u8> {
    w.iter().flat_map(|v| v.to_le_bytes()).collect()
}

/// `rt_sigaction` with a `struct compat_sigaction`.
fn rt_sigaction(h: &mut Harness, sig: i32, handler: u64, flags: u64, mask: u64) {
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

/// The x87 state the tests start from, as an FXSAVE legacy region: FCW
/// 0x027F, FSW 0x2821 (TOP = 5, IE, PE), FOP 0x1D9, a 64-bit FIP and FDP,
/// and ST0-ST4 valid, zero, NaN, denormal, and unnormal, ST5-ST7 empty.
fn x87_legacy() -> Vec<u8> {
    let mut b = vec![0u8; 512];
    b[0..2].copy_from_slice(&0x027Fu16.to_le_bytes());
    b[2..4].copy_from_slice(&0x2821u16.to_le_bytes());
    // Physical registers 5, 6, 7, 0, 1 (ST0-ST4 with TOP = 5) are in use.
    b[4] = 0b1110_0011;
    b[6..8].copy_from_slice(&0x01D9u16.to_le_bytes());
    b[8..16].copy_from_slice(&0x1_2345_6789u64.to_le_bytes());
    b[16..24].copy_from_slice(&0x9_8765_4321u64.to_le_bytes());
    b[24..28].copy_from_slice(&0x1F80u32.to_le_bytes());
    for (i, (significand, exponent)) in [
        (0x8000_0000_0000_0000u64, 0x3FFFu16),
        (0, 0),
        (0xC000_0000_0000_0000, 0x7FFF),
        (1, 0),
        (0x4000_0000_0000_0000, 0x4000),
    ]
    .into_iter()
    .enumerate()
    {
        let at = 32 + 16 * i;
        b[at..at + 8].copy_from_slice(&significand.to_le_bytes());
        b[at + 8..at + 10].copy_from_slice(&exponent.to_le_bytes());
    }
    b
}

/// The full tag word of [`x87_legacy`] (valid 00, zero 01, special 10,
/// empty 11, by physical register): 0 special, 1 special, 2-4 empty, 5
/// valid, 6 zero, 7 special.
const X87_TWD: u32 = 0xFFFF_0000 | 2 | 2 << 2 | 3 << 4 | 3 << 6 | 3 << 8 | 1 << 12 | 2 << 14;

/// Puts the thread in a known context: 32-bit registers with nonzero upper
/// halves (which the frame drops), R8-R15, arithmetic flags and AC, the
/// x87 state of [`x87_legacy`], and vector registers, at a 16-byte-aligned
/// stack address `0x3000` below its initial one, which it returns.
fn prepare(h: &mut Harness) -> u64 {
    let sp = (h.proc.threads[0].cpu.sp() & !0xF) - 0x3000;
    let c = x86(h);
    let v = c.vcpu_mut();
    v.fxrstor_image(&x87_legacy()).unwrap();
    v.set_mxcsr(0x9FC0).unwrap();
    let r = v.user_regs_mut();
    for (i, reg) in [
        &mut r.rax, &mut r.rbx, &mut r.rcx, &mut r.rdx, &mut r.rsi, &mut r.rdi, &mut r.rbp,
    ]
    .into_iter()
    .enumerate()
    {
        *reg = 0xAAAA_0000_0000_0000 | (0x1111_1111 * (i as u64 + 1));
    }
    for (i, reg) in [
        &mut r.r8, &mut r.r9, &mut r.r10, &mut r.r11, &mut r.r12, &mut r.r13, &mut r.r14,
        &mut r.r15,
    ]
    .into_iter()
    .enumerate()
    {
        *reg = 0x0808_0808_0000_0000 | i as u64;
    }
    for (i, x) in r.xmm.iter_mut().enumerate() {
        *x = [0x0101_0101 * (i as u64 + 1), !(i as u64)];
    }
    r.ymm_high[3] = [0x33, 0x34];
    r.rsp = sp;
    r.rip = CODE + 0x40;
    // AC, OF, SF, ZF, CF.
    v.set_user_rflags(0x4_0000 | 0x800 | 0x80 | 0x40 | 0x1 | 0x202);
    sp
}

/// `get_sigframe` for a 32-bit frame of `size` bytes at `sp`: the XSAVE
/// area 64-byte aligned below it, the FSAVE header below that, and the
/// frame with `(frame + 4) % 16 == 0`.
fn layout(sp: u64, size: u64) -> (u64, u64, u64) {
    let buf_fx = (sp - (XSAVE_SIZE + 4)) & !63;
    let buf = buf_fx - ia32::FSAVE_SIZE;
    let frame = ((buf - size + 4) & !15) - 4;
    (frame, buf, buf_fx)
}

/// The legacy region of the thread's x87 state.
fn legacy(h: &mut Harness) -> Vec<u8> {
    let v = x86(h).vcpu();
    v.xsave_image(v.xcr0()).bytes[..512].to_vec()
}

#[test]
fn an_rt_frame_is_the_ia32_layout() {
    let mut h = Harness::new(LinuxAbi::I386);
    rt_sigaction(
        &mut h,
        SIGUSR1,
        HANDLER,
        sa::SIGINFO | sa::RESTORER,
        sigmask(SIGUSR2),
    );
    let sp = prepare(&mut h);
    // A real-time signal blocked: the upper half of the saved mask.
    h.proc.threads[0].sigmask = sigmask(SIGRTMIN + 1);
    raise(&mut h, SIGUSR1);
    h.proc.deliver_signals(0);
    let (frame, buf, buf_fx) = layout(sp, ia32::RT_SIGFRAME_SIZE);
    assert_eq!((frame + 4) % 16, 0);
    let v = x86(&mut h).vcpu();
    let r = v.user_regs();
    // -mregparm=3: EAX = sig, EDX = &info, ECX = &uc.
    assert_eq!((r.rip, r.rsp), (HANDLER, frame));
    assert_eq!(
        (r.rax, r.rdx, r.rcx),
        (SIGUSR1 as u64, frame + 16, frame + 144)
    );
    // Unchanged: EBX, ESI, EDI, EBP, and R8-R15.
    assert_eq!(r.rbx, 0xAAAA_0000_2222_2222);
    assert_eq!(r.r15, 0x0808_0808_0000_0007);
    let sel = |s| v.user_selector(s);
    assert_eq!(sel(X86UserSegment::Cs), LINUX_USER32_CS);
    for s in [X86UserSegment::Ds, X86UserSegment::Es, X86UserSegment::Ss] {
        assert_eq!(sel(s), LINUX_USER_DS);
    }
    // DF, RF, TF clear; the rest kept.
    assert_eq!(
        v.user_rflags(),
        0x4_0000 | 0x800 | 0x80 | 0x40 | 0x1 | 0x202
    );
    // The handler starts with the initial FPU state.
    let l = legacy(&mut h);
    assert_eq!((l[0], l[1], l[4]), (0x7F, 0x03, 0));
    assert_eq!(x86(&mut h).vcpu().mxcsr(), 0x1F80);
    assert_eq!(
        h.proc.threads[0].sigmask,
        sigmask(SIGRTMIN + 1) | sigmask(SIGUSR1) | sigmask(SIGUSR2)
    );

    // pretcode, sig, pinfo, puc.
    assert_eq!(
        read(&h, frame, 16),
        words(&[
            RESTORER as u32,
            SIGUSR1 as u32,
            frame as u32 + 16,
            frame as u32 + 144
        ])
    );
    // struct compat_siginfo: SI_TKILL with the sender at 12 and 16.
    let (pid, uid) = (h.proc.state.pid as u32, h.proc.state.creds.0);
    let info = read(&h, frame + rt::INFO, 128);
    assert_eq!(
        info[..20],
        words(&[SIGUSR1 as u32, 0, -6i32 as u32, pid, uid])[..]
    );
    assert!(info[20..].iter().all(|&b| b == 0));
    // uc_flags (UC_FP_XSTATE), uc_link, uc_stack (no stack: SS_DISABLE).
    assert_eq!(read(&h, frame + rt::UC, 20), words(&[1, 0, 0, 2, 0]));
    // The sigcontext: 32-bit registers, selectors, the fault record, the
    // FPU state's address, the mask's lower half.
    let context = read(&h, frame + rt::MCONTEXT, sc::SIZE);
    let w = |at: usize| u32::from_le_bytes(context[at..at + 4].try_into().unwrap());
    assert_eq!((w(sc::GS), w(sc::FS)), (0, 0));
    assert_eq!((w(sc::ES), w(sc::DS)), (0x2B, 0x2B));
    assert_eq!(
        [
            w(sc::AX),
            w(sc::BX),
            w(sc::CX),
            w(sc::DX),
            w(sc::SI),
            w(sc::DI),
            w(sc::BP)
        ],
        [
            0x1111_1111,
            0x2222_2222,
            0x3333_3333,
            0x4444_4444,
            0x5555_5555,
            0x6666_6666,
            0x7777_7777
        ]
    );
    assert_eq!((w(sc::SP), w(sc::SP_AT_SIGNAL)), (sp as u32, sp as u32));
    assert_eq!((w(sc::IP), w(sc::CS)), (CODE as u32 + 0x40, 0x23));
    assert_eq!((w(sc::FLAGS), w(sc::SS)), (0x4_0AC3, 0x2B));
    assert_eq!((w(sc::TRAPNO), w(sc::ERR), w(sc::CR2)), (0, 0, 0));
    assert_eq!(w(sc::FPSTATE), buf as u32);
    assert_eq!(w(sc::OLDMASK), 0);
    assert_eq!(
        u64_at(&h, frame + rt::UC_SIGMASK),
        sigmask(SIGRTMIN + 1),
        "uc_sigmask is the whole mask"
    );
    assert_eq!(
        read(&h, frame + rt::RETCODE, 8),
        [0xB8, 173, 0, 0, 0, 0xCD, 0x80, 0]
    );

    // The FSAVE header: environment words with their upper halves set, the
    // full tag word, the pointers' 32-bit offsets, the code selector
    // without an opcode, and the data selector; then status and the FXSR
    // magic (0).
    let fsave = read(&h, buf, 112);
    let f = |i: usize| u32::from_le_bytes(fsave[i * 4..i * 4 + 4].try_into().unwrap());
    assert_eq!(
        [f(0), f(1), f(2), f(3), f(4), f(5), f(6)],
        [
            0xFFFF_027F,
            0xFFFF_2821,
            X87_TWD,
            0x2345_6789,
            0x23,
            0x8765_4321,
            0xFFFF_002B
        ]
    );
    let src = x87_legacy();
    for i in 0..8 {
        assert_eq!(
            fsave[28 + 10 * i..38 + 10 * i],
            src[32 + 16 * i..42 + 16 * i],
            "st{i}"
        );
    }
    assert_eq!(fsave[108..112], [0x21, 0x28, 0, 0]);
    // The XSAVE area: the legacy region as FXSAVE64 stores it, and the
    // software bytes counting the header in the extended size.
    assert_eq!(buf_fx % 64, 0);
    assert_eq!(read(&h, buf_fx, 24), src[..24]);
    assert_eq!(
        read(&h, buf_fx + 464, 20),
        words(&[
            MAGIC1,
            (XSAVE_SIZE + 4 + 112) as u32,
            0xE7,
            0,
            XSAVE_SIZE as u32
        ])
    );
    assert_eq!(u32_at(&h, buf_fx + XSAVE_SIZE), MAGIC2);
    assert_eq!(u64_at(&h, buf_fx + 512), 0xE7, "XSTATE_BV");
}

#[test]
fn a_non_rt_frame_is_the_legacy_layout() {
    let mut h = Harness::new(LinuxAbi::I386);
    // sigaction with a struct compat_old_sigaction: {handler, mask, flags,
    // restorer}.
    let at = h.scratch + 0x800;
    put(
        &h,
        at,
        &words(&[HANDLER as u32, 0, sa::RESTORER as u32, RESTORER as u32]),
    );
    h.ok(Sysno::Sigaction, &[SIGUSR1 as u64, at, 0]);
    let sp = prepare(&mut h);
    h.proc.threads[0].sigmask = sigmask(SIGHUP) | sigmask(SIGRTMIN + 3);
    raise(&mut h, SIGUSR1);
    h.proc.deliver_signals(0);
    let (frame, buf, _) = layout(sp, ia32::SIGFRAME_SIZE);
    let r = x86(&mut h).vcpu().user_regs().clone();
    assert_eq!((r.rip, r.rsp), (HANDLER, frame));
    assert_eq!((r.rax, r.rdx, r.rcx), (SIGUSR1 as u64, 0, 0));
    assert_eq!(
        read(&h, frame, 8),
        words(&[RESTORER as u32, SIGUSR1 as u32])
    );
    let context = read(&h, frame + off::SC, sc::SIZE);
    let w = |at: usize| u32::from_le_bytes(context[at..at + 4].try_into().unwrap());
    assert_eq!((w(sc::AX), w(sc::FPSTATE)), (0x1111_1111, buf as u32));
    // oldmask and extramask: the two halves of the saved mask.
    assert_eq!(w(sc::OLDMASK), sigmask(SIGHUP) as u32);
    assert_eq!(
        u32_at(&h, frame + off::EXTRAMASK),
        (sigmask(SIGRTMIN + 3) >> 32) as u32
    );
    // popl %eax; movl $119, %eax; int $0x80.
    assert_eq!(
        read(&h, frame + off::RETCODE, 8),
        [0x58, 0xB8, 119, 0, 0, 0, 0xCD, 0x80]
    );
}

#[test]
fn without_sa_restorer_handlers_return_through_the_vdso() {
    let mut h = Harness::new(LinuxAbi::I386);
    let vdso = h.proc.state.sigtramp;
    assert!(vdso != 0 && vdso % 4096 == 0 && vdso < 0xF7FF_E000);
    // vdso32/sigreturn.S: __kernel_sigreturn, then __kernel_rt_sigreturn,
    // each 16-byte aligned and followed by a nop.
    let code = read(&h, vdso, 0x30);
    assert_eq!(
        code[0x10..0x19],
        [0x58, 0xB8, 119, 0, 0, 0, 0xCD, 0x80, 0x90]
    );
    assert_eq!(code[0x20..0x28], [0xB8, 173, 0, 0, 0, 0xCD, 0x80, 0x90]);
    rt_sigaction(&mut h, SIGUSR1, HANDLER, sa::SIGINFO, 0);
    rt_sigaction(&mut h, SIGUSR2, HANDLER, 0, 0);
    let sp = prepare(&mut h);
    raise(&mut h, SIGUSR1);
    h.proc.deliver_signals(0);
    let (frame, _, _) = layout(sp, ia32::RT_SIGFRAME_SIZE);
    assert_eq!(u32_at(&h, frame), vdso as u32 + 0x20);
    x86(&mut h).vcpu_mut().user_regs_mut().rsp = sp;
    raise(&mut h, SIGUSR2);
    h.proc.deliver_signals(0);
    let (frame, _, _) = layout(sp, ia32::SIGFRAME_SIZE);
    assert_eq!(u32_at(&h, frame), vdso as u32 + 0x10);
}

/// Runs the handler's return: `ret` pops `pretcode`, and the non-RT
/// trampoline's `popl` the signal number.
fn return_from_handler(h: &mut Harness, rt: bool) -> Outcome {
    let r = x86(h).vcpu_mut().user_regs_mut();
    r.rsp += if rt { 4 } else { 8 };
    let s = if rt {
        Sysno::RtSigreturn
    } else {
        Sysno::Sigreturn
    };
    h.dispatch(s, &[])
}

#[test]
fn sigreturn_restores_the_interrupted_context() {
    for rt in [true, false] {
        let mut h = Harness::new(LinuxAbi::I386);
        let flags = sa::RESTORER | if rt { sa::SIGINFO } else { 0 };
        rt_sigaction(&mut h, SIGUSR1, HANDLER, flags, sigmask(SIGUSR2));
        let sp = prepare(&mut h);
        h.proc.threads[0].sigmask = sigmask(SIGRTMIN + 2) | sigmask(SIGHUP);
        let before = x86(&mut h).vcpu().user_regs().clone();
        raise(&mut h, SIGUSR1);
        h.proc.deliver_signals(0);
        // The handler clobbers what it may: R8 as well, which a 32-bit
        // handler cannot see and sigreturn does not restore.
        let v = x86(&mut h).vcpu_mut();
        v.user_regs_mut().r8 = 0x5A5A;
        v.user_regs_mut().xmm[2] = [1, 2];
        v.set_user_rflags(0x202);
        assert_eq!(return_from_handler(&mut h, rt), Outcome::Unchanged);
        let v = x86(&mut h).vcpu();
        let r = v.user_regs();
        // EAX..EBP from the frame, zero-extended.
        assert_eq!(
            [r.rax, r.rbx, r.rcx, r.rdx, r.rsi, r.rdi, r.rbp],
            [
                before.rax, before.rbx, before.rcx, before.rdx, before.rsi, before.rdi, before.rbp
            ]
            .map(|x| x & 0xFFFF_FFFF),
            "rt {rt}"
        );
        assert_eq!((r.rsp, r.rip), (sp, CODE + 0x40));
        assert_eq!(r.r8, 0x5A5A);
        assert_eq!(r.r9, before.r9);
        assert_eq!(r.xmm, before.xmm);
        assert_eq!(r.ymm_high[3], [0x33, 0x34]);
        assert_eq!(v.user_rflags(), 0x4_0AC3);
        assert_eq!(v.mxcsr(), 0x9FC0);
        assert_eq!(v.user_selector(X86UserSegment::Cs), LINUX_USER32_CS);
        // The x87 state through the FSAVE header: the environment folded
        // back with FOP from the upper half of fcs (zero) and the pointers
        // as their 32-bit offsets.
        let l = legacy(&mut h);
        let src = x87_legacy();
        assert_eq!(l[0..6], src[0..6]);
        assert_eq!(l[6..8], [0, 0], "FOP");
        assert_eq!(l[8..16], 0x2345_6789u64.to_le_bytes());
        assert_eq!(l[16..24], 0x8765_4321u64.to_le_bytes());
        for i in 0..8 {
            assert_eq!(l[32 + 16 * i..42 + 16 * i], src[32 + 16 * i..42 + 16 * i]);
        }
        assert_eq!(
            h.proc.threads[0].sigmask,
            sigmask(SIGRTMIN + 2) | sigmask(SIGHUP),
            "the frame's mask, both halves"
        );
    }
}

#[test]
fn a_handler_can_edit_the_saved_context() {
    let mut h = Harness::new(LinuxAbi::I386);
    rt_sigaction(&mut h, SIGUSR1, HANDLER, sa::SIGINFO | sa::RESTORER, 0);
    let sp = prepare(&mut h);
    raise(&mut h, SIGUSR1);
    h.proc.deliver_signals(0);
    let (frame, buf, buf_fx) = layout(sp, ia32::RT_SIGFRAME_SIZE);
    let mc = frame + rt::MCONTEXT;
    put(&h, mc + sc::IP as u64, &0x0040_2000u32.to_le_bytes());
    put(&h, mc + sc::AX as u64, &7u32.to_le_bytes());
    // Only FIX_EFLAGS bits come back: DF and CF, not IF's clearing or IOPL.
    put(&h, mc + sc::FLAGS as u64, &0x3401u32.to_le_bytes());
    // The FSAVE header wins over the FXSAVE image for the x87 control word
    // and the registers; the tag word becomes the abridged one.
    put(&h, buf, &0xFFFF_0C7Fu32.to_le_bytes());
    put(&h, buf + 8, &0xFFFF_FFFCu32.to_le_bytes());
    put(&h, buf + 28, &[0x11; 10]);
    put(&h, buf_fx + 32, &[0x22; 10]);
    // XMM0 from the XSAVE area.
    put(&h, buf_fx + 160, &[0x44; 16]);
    return_from_handler(&mut h, true);
    let v = x86(&mut h).vcpu();
    let r = v.user_regs();
    assert_eq!((r.rip, r.rax), (0x0040_2000, 7));
    // DF and CF from the frame, the other FIX_EFLAGS bits clear, IF kept.
    assert_eq!(v.user_rflags(), 0x400 | 0x1 | 0x202);
    assert_eq!(r.xmm[0], [0x4444_4444_4444_4444; 2]);
    let l = legacy(&mut h);
    assert_eq!(l[0..2], [0x7F, 0x0C]);
    // Tag 0xFFFC: physical register 0 valid, the others empty.
    assert_eq!(l[4], 0x01);
    assert_eq!(l[32..42], [0x11; 10]);
}

#[test]
fn fpstate_variants_restore_or_fail_as_the_kernel_does() {
    // (edit, restored): a frame without FP_XSTATE_MAGIC1 is FXSAVE only and
    // the AVX state returns to its initial value; a null fpstate restores
    // the initial state; an invalid MXCSR, a nonzero header reserved byte,
    // or a component XCR0 lacks fails the frame (SIGSEGV, initial state).
    #[derive(Clone, Copy, Debug)]
    enum Edit {
        NoMagic1,
        NullFpstate,
        BadMxcsr,
        HeaderReserved,
        UnknownFeature,
    }
    for edit in [
        Edit::NoMagic1,
        Edit::NullFpstate,
        Edit::BadMxcsr,
        Edit::HeaderReserved,
        Edit::UnknownFeature,
    ] {
        let mut h = Harness::new(LinuxAbi::I386);
        rt_sigaction(&mut h, SIGUSR1, HANDLER, sa::SIGINFO | sa::RESTORER, 0);
        let sp = prepare(&mut h);
        raise(&mut h, SIGUSR1);
        h.proc.deliver_signals(0);
        let (frame, _, buf_fx) = layout(sp, ia32::RT_SIGFRAME_SIZE);
        match edit {
            Edit::NoMagic1 => put(&h, buf_fx + 464, &0u32.to_le_bytes()),
            Edit::NullFpstate => put(&h, frame + rt::MCONTEXT + 76, &0u32.to_le_bytes()),
            Edit::BadMxcsr => put(&h, buf_fx + 24, &0x1_0000u32.to_le_bytes()),
            Edit::HeaderReserved => put(&h, buf_fx + 512 + 40, &[1]),
            Edit::UnknownFeature => put(&h, buf_fx + 512, &(0xE7u64 | 1 << 9).to_le_bytes()),
        }
        // Something the handler left in the AVX state.
        x86(&mut h).vcpu_mut().user_regs_mut().ymm_high[3] = [9, 9];
        return_from_handler(&mut h, true);
        let failed = matches!(
            edit,
            Edit::BadMxcsr | Edit::HeaderReserved | Edit::UnknownFeature
        );
        let t = &mut h.proc.threads[0];
        let segv = t.pending.dequeue(0);
        assert_eq!(segv.map(|i| i.signo), failed.then_some(SIGSEGV), "{edit:?}");
        let r = x86(&mut h).vcpu().user_regs();
        let xmm1 = r.xmm[1];
        let ymm3 = r.ymm_high[3];
        let mxcsr = x86(&mut h).vcpu().mxcsr();
        match edit {
            Edit::NoMagic1 => {
                assert_eq!(xmm1, [0x0202_0202, !1], "SSE from the FXSAVE image");
                assert_eq!(ymm3, [0, 0], "AVX to its initial state");
                assert_eq!(mxcsr, 0x9FC0);
            }
            _ => {
                assert_eq!((xmm1, ymm3, mxcsr), ([0, 0], [0, 0], 0x1F80), "{edit:?}");
            }
        }
    }
}

#[test]
fn sigreturn_reloads_changed_data_selectors() {
    let mut h = Harness::new(LinuxAbi::I386);
    // A flat TLS data segment in GDT entry 12 (selector 0x63).
    let at = h.scratch + 0x900;
    put(
        &h,
        at,
        &user_desc(12, 0x1000, 0xFFFFF, SEG_32BIT | 1 << 4 | USEABLE),
    );
    h.ok(Sysno::SetThreadArea, &[at]);
    rt_sigaction(&mut h, SIGUSR1, HANDLER, sa::SIGINFO | sa::RESTORER, 0);
    let sp = prepare(&mut h);
    x86(&mut h)
        .vcpu_mut()
        .load_user_segment(X86UserSegment::Gs, 0x63)
        .unwrap();
    raise(&mut h, SIGUSR1);
    h.proc.deliver_signals(0);
    let (frame, _, _) = layout(sp, ia32::RT_SIGFRAME_SIZE);
    let mc = frame + rt::MCONTEXT;
    assert_eq!(u32_at(&h, mc + sc::GS as u64), 0x63);
    // The handler changes GS; the frame asks for FS = 0x60 (RPL fixed up to
    // 0x63), ES = 2 (a null selector, kept), and DS = 0x18 (the kernel's
    // data segment, which does not load: null).
    let v = x86(&mut h).vcpu_mut();
    v.load_user_segment(X86UserSegment::Gs, 0).unwrap();
    put(&h, mc + sc::FS as u64, &0x60u32.to_le_bytes());
    put(&h, mc + sc::ES as u64, &2u32.to_le_bytes());
    put(&h, mc + sc::DS as u64, &0x18u32.to_le_bytes());
    assert_eq!(return_from_handler(&mut h, true), Outcome::Unchanged);
    let v = x86(&mut h).vcpu();
    let sel = |s| v.user_selector(s);
    assert_eq!(sel(X86UserSegment::Gs), 0x63);
    assert_eq!(sel(X86UserSegment::Fs), 0x63);
    assert_eq!(sel(X86UserSegment::Es), 2);
    assert_eq!(sel(X86UserSegment::Ds), 0);
    assert!(h.proc.threads[0].pending.dequeue(0).is_none());
}

#[test]
fn a_bad_frame_raises_sigsegv_after_setting_the_mask_it_read() {
    let mut h = Harness::new(LinuxAbi::I386);
    // An unreadable frame: the mask stays, EAX is zero.
    h.proc.threads[0].sigmask = sigmask(SIGHUP);
    x86(&mut h).vcpu_mut().user_regs_mut().rsp = 0x10_0000;
    assert_eq!(h.dispatch(Sysno::RtSigreturn, &[]), Outcome::Unchanged);
    let t = &mut h.proc.threads[0];
    assert_eq!(t.cpu.syscall_return_value(), 0);
    assert_eq!(t.sigmask, sigmask(SIGHUP));
    let info = t.pending.dequeue(0).unwrap();
    assert_eq!((info.signo, info.code), (SIGSEGV, code::SI_KERNEL));
    // uc_sigmask readable, uc_mcontext not: the frame straddles an
    // unmapped page below the scratch page, and set_current_blocked has
    // already taken the frame's mask.
    let frame = h.scratch - 200;
    h.ok(Sysno::Munmap, &[h.scratch - 4096, 4096]);
    put(
        &h,
        frame + rt::UC_SIGMASK,
        &(sigmask(SIGUSR2) | sigmask(SIGRTMIN)).to_le_bytes(),
    );
    x86(&mut h).vcpu_mut().user_regs_mut().rsp = frame + 4;
    h.dispatch(Sysno::RtSigreturn, &[]);
    let t = &mut h.proc.threads[0];
    assert_eq!(t.sigmask, sigmask(SIGUSR2) | sigmask(SIGRTMIN));
    assert_eq!(t.pending.dequeue(0).map(|i| i.signo), Some(SIGSEGV));
}

#[test]
fn an_invalid_selector_faults_the_return_with_the_state_restored() {
    // (CS, SS, trap, error code): a data segment as CS, a code segment, a
    // read-only TLS data segment, or a null selector as SS: #GP(selector),
    // SIGSEGV. (A TLS entry cannot be made not present, `tls_desc_okay`,
    // so no SS load raises #SS.)
    let cases = [
        (0x2B, 0x2B, 13, 0x28),
        (0x23, 0x23, 13, 0x20),
        (0x23, 0x6B, 13, 0x68),
        (0x23, 0x00, 13, 0),
    ];
    for (cs, ss, trap, error) in cases {
        let mut h = Harness::new(LinuxAbi::I386);
        let at = h.scratch + 0x900;
        put(
            &h,
            at,
            &user_desc(
                13,
                0,
                0xFFFFF,
                SEG_32BIT | READ_EXEC_ONLY | 1 << 4 | USEABLE,
            ),
        );
        h.ok(Sysno::SetThreadArea, &[at]);
        rt_sigaction(&mut h, SIGUSR1, HANDLER, sa::SIGINFO | sa::RESTORER, 0);
        let sp = prepare(&mut h);
        raise(&mut h, SIGUSR1);
        h.proc.deliver_signals(0);
        let (frame, _, _) = layout(sp, ia32::RT_SIGFRAME_SIZE);
        let mc = frame + rt::MCONTEXT;
        put(&h, mc + sc::CS as u64, &(cs as u32).to_le_bytes());
        put(&h, mc + sc::SS as u64, &(ss as u32).to_le_bytes());
        assert_eq!(return_from_handler(&mut h, true), Outcome::Unchanged);
        let t = &mut h.proc.threads[0];
        // sigreturn returned the restored EAX; the return then faulted.
        assert_eq!(t.cpu.syscall_return_value(), 0x1111_1111, "{cs:#x}/{ss:#x}");
        let info = t.pending.dequeue(0).unwrap();
        assert_eq!((info.signo, info.code), (SIGSEGV, code::SI_KERNEL));
        assert_eq!((t.fault.trap_nr, t.fault.error_code), (trap, error));
    }
    // A return to 64-bit mode is not provided: the task ends.
    let mut h = Harness::new(LinuxAbi::I386);
    rt_sigaction(&mut h, SIGUSR1, HANDLER, sa::SIGINFO | sa::RESTORER, 0);
    let sp = prepare(&mut h);
    raise(&mut h, SIGUSR1);
    h.proc.deliver_signals(0);
    let (frame, _, _) = layout(sp, ia32::RT_SIGFRAME_SIZE);
    put(
        &h,
        frame + rt::MCONTEXT + sc::CS as u64,
        &0x33u32.to_le_bytes(),
    );
    assert!(matches!(
        return_from_handler(&mut h, true),
        Outcome::Fatal(_)
    ));
}

#[test]
fn an_alternate_stack_holds_the_frame_and_uc_stack_is_compat_stack_t() {
    let mut h = Harness::new(LinuxAbi::I386);
    let stack = h.ok(
        Sysno::Mmap2,
        &[0, 4 * 4096, 3, 0x22, u64::from(u32::MAX), 0],
    );
    let ss = h.scratch + 0xA00;
    put(&h, ss, &words(&[stack as u32, 0, 4 * 4096]));
    h.ok(Sysno::Sigaltstack, &[ss, 0]);
    rt_sigaction(
        &mut h,
        SIGUSR1,
        HANDLER,
        sa::SIGINFO | sa::RESTORER | sa::ONSTACK,
        0,
    );
    prepare(&mut h);
    raise(&mut h, SIGUSR1);
    h.proc.deliver_signals(0);
    let (frame, _, _) = layout(stack + 4 * 4096, ia32::RT_SIGFRAME_SIZE);
    assert_eq!(x86(&mut h).vcpu().user_regs().rsp, frame);
    assert_eq!(
        read(&h, frame + rt::UC_STACK, 12),
        words(&[stack as u32, 0, 4 * 4096])
    );
    // The frame's stack_t comes back through compat_restore_altstack.
    put(&h, frame + rt::UC_STACK, &words(&[stack as u32, 2, 0]));
    return_from_handler(&mut h, true);
    assert_eq!(h.proc.threads[0].altstack, AltStack::DISABLED);
}

#[test]
fn a_stack_segment_of_its_own_switches_to_sa_restorer() {
    // The legacy stack switch: SS other than __USER_DS, no SA_RESTORER,
    // and a nonzero sa_restorer, which names the stack. It counts as
    // entering the alternate stack, so the frame must lie on the one
    // sigaltstack registered; without one, frame setup fails and the
    // SIGSEGV forced for it kills the task.
    for registered in [false, true] {
        let mut h = Harness::new(LinuxAbi::I386);
        let stack = h.ok(
            Sysno::Mmap2,
            &[0, 4 * 4096, 3, 0x22, u64::from(u32::MAX), 0],
        );
        let top = stack + 4 * 4096;
        if registered {
            let ss = h.scratch + 0xA00;
            put(&h, ss, &words(&[stack as u32, 0, 4 * 4096]));
            h.ok(Sysno::Sigaltstack, &[ss, 0]);
        }
        let at = h.scratch + 0x900;
        put(
            &h,
            at,
            &user_desc(12, 0, 0xFFFFF, SEG_32BIT | 1 << 4 | USEABLE),
        );
        h.ok(Sysno::SetThreadArea, &[at]);
        let act = h.scratch + 0x800;
        let mut b = words(&[HANDLER as u32, sa::SIGINFO as u32, top as u32]);
        b.extend_from_slice(&0u64.to_le_bytes());
        put(&h, act, &b);
        h.ok(Sysno::RtSigaction, &[SIGUSR1 as u64, act, 0, 8]);
        prepare(&mut h);
        x86(&mut h)
            .vcpu_mut()
            .load_user_segment(X86UserSegment::Ss, 0x63)
            .unwrap();
        raise(&mut h, SIGUSR1);
        h.proc.deliver_signals(0);
        if !registered {
            assert!(matches!(
                h.proc.state.exit,
                Some(ExitStatus::Signaled { info, .. }) if info.signo == SIGSEGV
            ));
            continue;
        }
        let (frame, _, _) = layout(top, ia32::RT_SIGFRAME_SIZE);
        let v = x86(&mut h).vcpu();
        assert_eq!(v.user_regs().rsp, frame);
        assert_eq!(v.user_selector(X86UserSegment::Ss), LINUX_USER_DS);
        assert_eq!(
            u32_at(&h, frame + rt::MCONTEXT + sc::SS as u64),
            0x63,
            "the interrupted SS is saved"
        );
    }
}

#[test]
fn strict_seccomp_allows_sigreturn_but_not_rt_sigreturn() {
    // mode1_syscalls_32: read, write, exit, and sigreturn (119).
    let mut h = Harness::new(LinuxAbi::I386);
    assert_eq!(h.call(Sysno::Prctl, &[22, 1, 0, 0, 0]), 0);
    x86(&mut h).vcpu_mut().user_regs_mut().rsp = 0x10_0000;
    // A bad frame: the call ran, and SIGSEGV is forced.
    assert_eq!(h.dispatch(Sysno::Sigreturn, &[]), Outcome::Unchanged);
    assert!(h.proc.state.exit.is_none());
    assert_eq!(h.start(0, Sysno::RtSigreturn, &[]), None);
    assert!(matches!(
        h.proc.state.exit,
        Some(ExitStatus::Signaled { info, .. }) if info.signo == SIGKILL
    ));
}

#[test]
fn restart_codes_become_eintr_through_an_i386_frame() {
    // A sleeping call interrupted by a handler without SA_RESTART: the
    // frame saves EAX = -EINTR and EIP after `int $0x80`.
    let mut h = Harness::new(LinuxAbi::I386);
    rt_sigaction(&mut h, SIGUSR1, HANDLER, sa::SIGINFO | sa::RESTORER, 0);
    let sp = prepare(&mut h);
    let t = &mut h.proc.threads[0];
    t.syscall = Some(crate::user::linux::signal::deliver::SyscallEntry { nr: 29, arg0: 0 });
    t.cpu.set_syscall_result(-514i64 as u64);
    raise(&mut h, SIGUSR1);
    h.proc.deliver_signals(0);
    let (frame, _, _) = layout(sp, ia32::RT_SIGFRAME_SIZE);
    let mc = frame + rt::MCONTEXT;
    assert_eq!(u32_at(&h, mc + sc::AX as u64), -(EINTR as i32) as u32);
    assert_eq!(u32_at(&h, mc + sc::IP as u64), CODE as u32 + 0x40);
}
