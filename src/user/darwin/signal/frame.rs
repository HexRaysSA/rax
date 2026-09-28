//! Signal frames: entering a handler (`sendsig`) and leaving it
//! (`sigreturn`), from `bsd/dev/arm/unix_signal.c` and
//! `bsd/dev/i386/unix_signal.c`.
//!
//! The kernel writes the interrupted state and the signal's details on
//! the user stack and starts libSystem's trampoline (`_sigtramp`, the
//! `sa_tramp` of `__sigaction`) with the handler, the handler style, the
//! signal, the `siginfo_t`, the `ucontext_t`, and a token; the trampoline
//! calls the handler and returns through `sigreturn(uctx, style, token)`,
//! which reinstates the state the `ucontext_t` points to.
//!
//! arm64 (`struct user_sigframe64`, 976 bytes at a 16-byte aligned SP
//! below a 128-byte red zone): `siginfo_t` (104), `ucontext_t` (56), and
//! `mcontext64` (816: exception, thread, and NEON state).
//!
//! x86-64, downward from the interrupted RSP: a 128-byte red zone,
//! `ucontext_t` (56), `siginfo_t` (104), and `mcontext_avx64` (1032:
//! exception, thread, and AVX state); the trampoline's RSP is 16-byte
//! aligned minus 8, as after a call.

use super::{
    CANTMASK, Proc, SIGBUS, SIGFPE, SIGILL, SIGSEGV, SIGTRAP, SS_ONSTACK, Signal, Thread,
    Validation, bit, exc,
};
use crate::user::darwin::abi::{DarwinAbi, Errno};
use crate::user::darwin::arch::DarwinCpu;
use crate::user::darwin::thread_state as ts;

/// `UC_TRAD`: a handler taking only the signal number.
pub const UC_TRAD: u32 = 1;
/// `UC_FLAVOR`: a handler taking `siginfo_t` and `ucontext_t`.
pub const UC_FLAVOR: u32 = 30;
/// `sigreturn` style that marks the thread on its alternate stack.
pub const UC_SET_ALT_STACK: u32 = 0x4000_0000;
/// `sigreturn` style that marks the thread off its alternate stack.
pub const UC_RESET_ALT_STACK: u32 = 0x8000_0000;

/// The ABI's red zone below the stack pointer.
const REDZONE: u64 = 128;
/// `sizeof(siginfo_t)` (`user64_siginfo_t`).
pub const SIGINFO_SIZE: u64 = 104;
/// `sizeof(ucontext_t)` (`struct user_ucontext64`).
pub const UCONTEXT_SIZE: u64 = 56;
/// `UC_FLAVOR_SIZE64`: `sizeof(struct __darwin_mcontext64)` on arm64.
pub const ARM64_MCONTEXT_SIZE: u64 = 816;
/// `sizeof(struct __darwin_mcontext_avx64)`.
pub const X86_MCONTEXT_SIZE: u64 = 1032;
/// `sizeof(struct user_sigframe64)` on arm64.
const ARM64_FRAME_SIZE: u64 = SIGINFO_SIZE + UCONTEXT_SIZE + ARM64_MCONTEXT_SIZE;

/// arm64 thread-state flags (`__DARWIN_ARM_THREAD_STATE64_FLAGS_*`).
mod flags {
    /// The pointers are not signed (a process without pointer
    /// authentication).
    pub const NO_PTRAUTH: u32 = 0x1;
    /// The kernel signed `pc`.
    pub const KERNEL_SIGNED_PC: u32 = 0x4;
    /// The kernel signed `lr`.
    pub const KERNEL_SIGNED_LR: u32 = 0x8;
    /// The sigreturn token of `pc`.
    pub const SIGRETURN_PC_MASK: u32 = 0x000f_0000;
    /// The sigreturn token of `lr`.
    pub const SIGRETURN_LR_MASK: u32 = 0x00f0_0000;
    /// The per-thread diversifier.
    pub const USER_DIVERSIFIER_MASK: u32 = 0xff00_0000;
}

/// `si_code` values (`bsd/sys/signal.h`).
pub(super) mod code {
    pub const ILL_ILLOPC: i32 = 1;
    pub const ILL_ILLTRP: i32 = 2;
    pub const FPE_FLTDIV: i32 = 1;
    pub const FPE_FLTOVF: i32 = 2;
    pub const FPE_FLTUND: i32 = 3;
    pub const FPE_FLTRES: i32 = 4;
    pub const FPE_FLTINV: i32 = 5;
    pub const FPE_INTDIV: i32 = 7;
    pub const FPE_INTOVF: i32 = 8;
    pub const SEGV_MAPERR: i32 = 1;
    pub const SEGV_ACCERR: i32 = 2;
    pub const BUS_ADRALN: i32 = 1;
    pub const BUS_ADRERR: i32 = 2;
    pub const TRAP_BRKPT: i32 = 1;
    pub const CLD_EXITED: i32 = 1;
    pub const CLD_KILLED: i32 = 2;
    pub const CLD_DUMPED: i32 = 3;
    pub const CLD_STOPPED: i32 = 5;
    pub const CLD_CONTINUED: i32 = 6;
}

/// The signal frame could not be written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameFault;

fn put64(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

fn put32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn get64(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().expect("8 bytes"))
}

fn get32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().expect("4 bytes"))
}

/// Whether the process uses pointer authentication (an arm64e main
/// executable with the pointer-authentication ABI: not `IMGPF_NOJOP`).
pub fn uses_ptrauth(proc: &Proc) -> bool {
    const CPU_SUBTYPE_MASK: u32 = 0xff00_0000;
    const CPU_SUBTYPE_ARM64E: u32 = 2;
    const CPU_SUBTYPE_PTRAUTH_ABI: u32 = 0x8000_0000;
    let sub = proc.program.main.header.cpusubtype;
    proc.abi == DarwinAbi::Arm64
        && sub & !CPU_SUBTYPE_MASK == CPU_SUBTYPE_ARM64E
        && sub & CPU_SUBTYPE_PTRAUTH_ABI != 0
}

/// The sigreturn token of a kernel-signed pointer
/// (`thread_generate_sigreturn_token`). The kernel signs `ptr ^ secret`
/// with a process key; with RAX's identity pointer-authentication
/// algorithm the signature is the value itself.
fn pointer_token(ptr: u64, secret: u64) -> u32 {
    ((ptr ^ secret) >> 32) as u32
}

/// A `siginfo_t` for `sig` (`sendsig`'s per-signal rules): `si_addr` is
/// the interrupted PC, or the fault address for `SIGSEGV` and `SIGBUS`;
/// `pad[0]` is the interrupted stack pointer; other signals carry the
/// sender that `psignal` recorded.
fn siginfo(proc: &mut Proc, thread: &Thread, sig: Signal, pc: u64, sp: u64) -> [u8; 104] {
    let x86 = proc.abi == DarwinAbi::X86_64;
    let uu_code = thread.sig.code;
    let uu_subcode = thread.sig.subcode;
    let far = thread.sig.entry.far;
    let mut addr = pc;
    let (mut si_code, mut pid, mut uid, mut status) = (0i32, 0i32, 0u32, 0i32);
    match sig {
        SIGILL if x86 => {
            si_code = if uu_code == exc::CODE_1 {
                code::ILL_ILLOPC
            } else {
                0
            };
        }
        SIGILL => si_code = code::ILL_ILLTRP,
        SIGFPE if x86 => {
            // The x87 status word or MXCSR exception flags.
            let flag = |b: u32| uu_subcode & (1 << b) != 0;
            si_code = if uu_code == exc::CODE_1 {
                code::FPE_INTDIV
            } else if uu_code == exc::CODE_2 {
                code::FPE_INTOVF
            } else if flag(2) {
                code::FPE_FLTDIV
            } else if flag(3) {
                code::FPE_FLTOVF
            } else if flag(4) {
                code::FPE_FLTUND
            } else if flag(5) {
                code::FPE_FLTRES
            } else if flag(0) {
                code::FPE_FLTINV
            } else {
                0
            };
        }
        // Floating-point traps are not enabled on arm64: FPE_NOOP.
        SIGFPE => {}
        SIGBUS if x86 => {
            si_code = code::BUS_ADRERR;
            addr = far;
        }
        SIGBUS => {
            si_code = code::BUS_ADRALN;
            addr = far;
        }
        SIGTRAP if x86 => si_code = code::TRAP_BRKPT,
        SIGSEGV if x86 => {
            addr = far;
            si_code = match uu_code {
                // CR2 means nothing after a general-protection fault.
                exc::I386_GPFLT => {
                    addr = 0;
                    0
                }
                exc::KERN_PROTECTION_FAILURE => code::SEGV_ACCERR,
                exc::KERN_INVALID_ADDRESS => code::SEGV_MAPERR,
                _ => 0,
            };
        }
        SIGSEGV => {
            addr = far;
            si_code = code::SEGV_ACCERR;
        }
        _ => {
            let o = std::mem::take(&mut proc.sigacts.origin);
            pid = o.pid;
            uid = o.uid;
            si_code = o.code;
            let mut s = o.status;
            if si_code == code::CLD_EXITED {
                let term = s & 0x7f;
                if term != 0 && term != 0x7f {
                    si_code = if s & 0x80 != 0 {
                        code::CLD_DUMPED
                    } else {
                        code::CLD_KILLED
                    };
                    s = (s << 8) | s;
                }
            }
            status = (s >> 8) & 0xff;
        }
    }
    let mut b = [0u8; 104];
    put32(&mut b, 0, sig as u32);
    put32(&mut b, 8, si_code as u32);
    put32(&mut b, 12, pid as u32);
    put32(&mut b, 16, uid);
    put32(&mut b, 20, status as u32);
    put64(&mut b, 24, addr);
    put64(&mut b, 48, sp);
    b
}

/// A `ucontext_t` (`sendsig_fill_uctx64`).
fn ucontext(oonstack: bool, mask: u32, sp: u64, size: u64, mcsize: u64, mctx: u64) -> [u8; 56] {
    let mut b = [0u8; 56];
    put32(&mut b, 0, u32::from(oonstack));
    put32(&mut b, 4, mask);
    put64(&mut b, 8, sp);
    put64(&mut b, 16, size);
    put32(&mut b, 24, if oonstack { SS_ONSTACK } else { 0 });
    put64(&mut b, 40, mcsize);
    put64(&mut b, 48, mctx);
    b
}

/// Enters the handler `catcher` for `sig` on `thread` (`sendsig`), with
/// `mask` as the mask its `sigreturn` restores and `siginfo_set` the
/// signals whose handlers take `siginfo_t`.
pub fn sendsig(
    proc: &mut Proc,
    thread: &mut Thread,
    catcher: u64,
    sig: Signal,
    mask: u32,
    siginfo_set: u32,
) -> Result<(), FrameFault> {
    let infostyle = if siginfo_set & bit(sig) != 0 {
        UC_FLAVOR
    } else {
        UC_TRAD
    };
    if thread.sig.pending_sigreturn == 0 {
        // A new secret for validating sigreturn arguments.
        let mut b = [0u8; 12];
        proc.entropy.fill(&mut b);
        thread.sig.token = u64::from_le_bytes(b[..8].try_into().expect("8 bytes"));
        let div = u32::from_le_bytes(b[8..].try_into().expect("4 bytes"));
        thread.sig.diversifier = (div & flags::USER_DIVERSIFIER_MASK).max(1 << 24);
    }
    thread.sig.pending_sigreturn += 1;
    let r = match proc.abi {
        DarwinAbi::Arm64 => sendsig_arm64(proc, thread, catcher, sig, mask, infostyle),
        DarwinAbi::X86_64 => sendsig_x86_64(proc, thread, catcher, sig, mask, infostyle),
    };
    if r.is_err() {
        thread.sig.pending_sigreturn -= 1;
    }
    r
}

/// The stack a handler runs on: the alternate stack's top when the
/// action asks for it and the thread is not already on it (which marks
/// the thread on it), else the interrupted stack pointer. Returns the
/// stack pointer and the alternate stack's size (0 when not switching).
fn handler_stack(proc: &Proc, thread: &mut Thread, sig: Signal, sp: u64) -> (u64, u64) {
    let alt = &mut thread.sig.altstack;
    if alt.enabled && alt.flags & SS_ONSTACK == 0 && proc.sigacts.onstack & bit(sig) != 0 {
        alt.flags |= SS_ONSTACK;
        (alt.sp.wrapping_add(alt.size), alt.size)
    } else {
        (sp, 0)
    }
}

fn sendsig_arm64(
    proc: &mut Proc,
    thread: &mut Thread,
    catcher: u64,
    sig: Signal,
    mask: u32,
    infostyle: u32,
) -> Result<(), FrameFault> {
    let trampact = proc.sigacts.tramp[sig as usize];
    let oonstack = thread.sig.altstack.flags & SS_ONSTACK != 0;
    let jop = uses_ptrauth(proc);
    let secret = thread.sig.token;
    let DarwinCpu::Arm64(cpu) = &thread.cpu else {
        unreachable!("an arm64 process runs arm64 threads");
    };
    let (pc, lr, sp) = (cpu.pc(), cpu.core().get_x(30), cpu.sp());
    let state_flags = if jop {
        flags::KERNEL_SIGNED_PC
            | flags::KERNEL_SIGNED_LR
            | thread.sig.diversifier
            | (pointer_token(pc, secret) & flags::SIGRETURN_PC_MASK)
            | (pointer_token(lr, secret) & flags::SIGRETURN_LR_MASK)
    } else {
        flags::NO_PTRAUTH
    };
    let mut frame = vec![0u8; ARM64_FRAME_SIZE as usize];
    let mctx = (SIGINFO_SIZE + UCONTEXT_SIZE) as usize;
    frame[mctx..mctx + 16].copy_from_slice(&ts::arm64_exception_state(&thread.sig.entry));
    frame[mctx + 16..mctx + 288].copy_from_slice(&ts::arm64_thread_state(cpu, state_flags));
    frame[mctx + 288..mctx + 816].copy_from_slice(&ts::arm64_neon_state(cpu));

    let (top, stack_size) = handler_stack(proc, thread, sig, sp);
    let fp = top.wrapping_sub(ARM64_FRAME_SIZE + REDZONE) & !0xf;
    let p_uctx = fp + SIGINFO_SIZE;
    frame[SIGINFO_SIZE as usize..mctx].copy_from_slice(&ucontext(
        oonstack,
        mask,
        fp,
        stack_size,
        ARM64_MCONTEXT_SIZE,
        fp + mctx as u64,
    ));
    let info = siginfo(proc, thread, sig, pc, sp);
    frame[..SIGINFO_SIZE as usize].copy_from_slice(&info);
    proc.space.write(fp, &frame).map_err(|_| FrameFault)?;
    let token = p_uctx ^ secret;
    let DarwinCpu::Arm64(cpu) = &mut thread.cpu else {
        unreachable!("an arm64 process runs arm64 threads");
    };
    let core = cpu.core_mut();
    // Installing a handler is an asynchronous guest exception. Discard the
    // interrupted thread's reservation only after its frame is committed.
    core.clear_exclusive_monitor();
    core.set_x(0, catcher);
    core.set_x(1, u64::from(infostyle));
    core.set_x(2, sig as u64);
    core.set_x(3, fp);
    core.set_x(4, p_uctx);
    core.set_x(5, token);
    // cpsr = PSR64_USER64_DEFAULT: NZCV clear.
    core.set_nzcv_bits(0);
    crate::isa::arm::common::cpu::ArmCpu::set_pc(core, trampact);
    cpu.set_sp(fp);
    Ok(())
}

fn sendsig_x86_64(
    proc: &mut Proc,
    thread: &mut Thread,
    catcher: u64,
    sig: Signal,
    mask: u32,
    infostyle: u32,
) -> Result<(), FrameFault> {
    let trampact = proc.sigacts.tramp[sig as usize];
    let oonstack = thread.sig.altstack.flags & SS_ONSTACK != 0;
    let DarwinCpu::X86_64(cpu) = &thread.cpu else {
        unreachable!("an x86-64 process runs x86-64 threads");
    };
    let mut mctx = vec![0u8; X86_MCONTEXT_SIZE as usize];
    mctx[..16].copy_from_slice(&ts::x86_exception_state(&thread.sig.entry));
    mctx[16..184].copy_from_slice(&ts::x86_thread_state(cpu));
    mctx[184..184 + ts::X86_AVX_STATE64_SIZE].copy_from_slice(&ts::x86_avx_state(cpu));
    let (rip, rsp) = (cpu.pc(), cpu.vcpu().user_regs().rsp);

    let (top, stack_size) = handler_stack(proc, thread, sig, rsp);
    let mut sp = top.wrapping_sub(REDZONE);
    sp = sp.wrapping_sub(UCONTEXT_SIZE);
    let uctxp = sp;
    sp = sp.wrapping_sub(SIGINFO_SIZE);
    let sip = sp;
    sp = sp.wrapping_sub(X86_MCONTEXT_SIZE);
    let mctxp = sp;
    // TRUNC_DOWN64(sp, 16), then room for a return address.
    let fp = (sp.wrapping_sub(16) & !0xf).wrapping_sub(8);
    let token = uctxp ^ thread.sig.token;
    let uctx = ucontext(oonstack, mask, fp, stack_size, X86_MCONTEXT_SIZE, mctxp);
    proc.space.write(uctxp, &uctx).map_err(|_| FrameFault)?;
    proc.space.write(mctxp, &mctx).map_err(|_| FrameFault)?;
    let info = siginfo(proc, thread, sig, rip, rsp);
    proc.space.write(sip, &info).map_err(|_| FrameFault)?;
    let DarwinCpu::X86_64(cpu) = &mut thread.cpu else {
        unreachable!("an x86-64 process runs x86-64 threads");
    };
    let v = cpu.vcpu_mut();
    let r = v.user_regs_mut();
    r.rip = trampact;
    r.rsp = fp;
    r.rdi = catcher;
    r.rsi = u64::from(infostyle);
    r.rdx = sig as u64;
    r.rcx = sip;
    r.r8 = uctxp;
    r.r9 = token;
    // get_eflags_exportmask through set_thread_state64: IF alone.
    v.set_user_rflags(0x200);
    Ok(())
}

/// How `sigreturn` finished.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Returned {
    /// Only the alternate-stack mark changed: the call returns 0.
    Zero,
    /// The interrupted state is back in the registers (`EJUSTRETURN`).
    State,
}

/// `sigreturn(uctx, infostyle, token)`: reinstates the state `uctx`
/// describes, or changes only the alternate-stack mark for the
/// `UC_SET_ALT_STACK` and `UC_RESET_ALT_STACK` styles.
pub fn sigreturn(
    proc: &mut Proc,
    thread: &mut Thread,
    uctx: u64,
    infostyle: u32,
    token: u64,
) -> Result<Returned, Errno> {
    let r = match infostyle {
        UC_SET_ALT_STACK => {
            thread.sig.altstack.flags |= SS_ONSTACK;
            return Ok(Returned::Zero);
        }
        UC_RESET_ALT_STACK => {
            thread.sig.altstack.flags &= !SS_ONSTACK;
            return Ok(Returned::Zero);
        }
        _ => match proc.abi {
            DarwinAbi::Arm64 => sigreturn_arm64(proc, thread, uctx, token),
            DarwinAbi::X86_64 => sigreturn_x86_64(proc, thread, uctx, token),
        },
    };
    // The AST that resets PCs in restartable ranges runs on every
    // sigreturn (`act_set_ast_reset_pcs`).
    if r.is_ok()
        && let Some(pc) = crate::user::darwin::mig::task::restartable_lookup(
            &proc.task.restartable,
            thread.cpu.pc(),
        )
    {
        thread.cpu.set_pc(pc);
    }
    r.map(|()| Returned::State)
}

fn read(proc: &Proc, addr: u64, len: u64) -> Result<Vec<u8>, Errno> {
    let mut b = vec![0u8; len as usize];
    proc.space.read(addr, &mut b).map_err(|_| Errno::EFAULT)?;
    Ok(b)
}

/// Sets the thread's alternate-stack mark from `uc_onstack`.
fn set_onstack(thread: &mut Thread, uc: &[u8]) {
    if get32(uc, 0) & 1 != 0 {
        thread.sig.altstack.flags |= SS_ONSTACK;
    } else {
        thread.sig.altstack.flags &= !SS_ONSTACK;
    }
}

fn sigreturn_arm64(
    proc: &mut Proc,
    thread: &mut Thread,
    uctx: u64,
    token: u64,
) -> Result<(), Errno> {
    let uc = read(proc, uctx, UCONTEXT_SIZE)?;
    if get64(&uc, 40) != ARM64_MCONTEXT_SIZE {
        return Err(Errno::EINVAL);
    }
    let mc = read(proc, get64(&uc, 48), ARM64_MCONTEXT_SIZE)?;
    set_onstack(thread, &uc);
    thread.sig.mask = get32(&uc, 4) & !CANTMASK;
    let validate = proc.sigacts.validation != Validation::Disabled;
    if token != uctx ^ thread.sig.token && validate {
        return Err(Errno::EINVAL);
    }
    let ss = &mc[16..288];
    if uses_ptrauth(proc) && validate {
        // TSSF_CHECK_SIGRETURN_TOKEN | TSSF_ALLOW_ONLY_MATCHING_TOKEN: a
        // kernel-signed pc or lr must carry the token the kernel stored.
        let f = get32(ss, 268);
        let secret = thread.sig.token;
        let pc_ok = f & flags::KERNEL_SIGNED_PC == 0
            || f & flags::SIGRETURN_PC_MASK
                == pointer_token(get64(ss, 256), secret) & flags::SIGRETURN_PC_MASK;
        let lr_ok = f & flags::KERNEL_SIGNED_LR == 0
            || f & flags::SIGRETURN_LR_MASK
                == pointer_token(get64(ss, 240), secret) & flags::SIGRETURN_LR_MASK;
        if !pc_ok || !lr_ok {
            return Err(Errno::EINVAL);
        }
    }
    let DarwinCpu::Arm64(cpu) = &mut thread.cpu else {
        unreachable!("an arm64 process runs arm64 threads");
    };
    ts::set_arm64_thread_state(cpu, ss);
    ts::set_arm64_neon_state(cpu, &mc[288..816]);
    thread.sig.pending_sigreturn = thread.sig.pending_sigreturn.saturating_sub(1);
    Ok(())
}

fn sigreturn_x86_64(
    proc: &mut Proc,
    thread: &mut Thread,
    uctx: u64,
    token: u64,
) -> Result<(), Errno> {
    let uc = read(proc, uctx, UCONTEXT_SIZE)?;
    thread.sig.mask = get32(&uc, 4) & !CANTMASK;
    let mc = read(proc, get64(&uc, 48), X86_MCONTEXT_SIZE)?;
    let bad_token =
        token != uctx ^ thread.sig.token && proc.sigacts.validation != Validation::Disabled;
    set_onstack(thread, &uc);
    if bad_token {
        return Err(Errno::EINVAL);
    }
    let DarwinCpu::X86_64(cpu) = &mut thread.cpu else {
        unreachable!("an x86-64 process runs x86-64 threads");
    };
    ts::set_x86_thread_state(cpu, &mc[16..184]).map_err(|_| Errno::EINVAL)?;
    thread.sig.pending_sigreturn = thread.sig.pending_sigreturn.saturating_sub(1);
    ts::set_x86_avx_state(cpu, &mc[184..184 + ts::X86_AVX_STATE64_SIZE]).map_err(|_| Errno::EINVAL)
}
