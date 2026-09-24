//! Linux x86-64 thread ABI.
//!
//! - System calls: `SYSCALL` with the number in RAX and arguments in RDI,
//!   RSI, RDX, R10, R8, R9; the result returns in RAX, and RCX/R11 hold the
//!   return RIP and RFLAGS (the kernel returns with `SYSRET`).
//! - `INT 0x80` enters the 32-bit (IA32 emulation) system-call table with
//!   EAX, EBX, ECX, EDX, ESI, EDI, EBP.
//! - Exceptions become signals as in `arch/x86/kernel/traps.c`.

use super::{ArchCaps, CpuEvent, fault_signal};
use crate::error::MemoryAccessKind;
use crate::isa::x86_64::{X86EventSource, X86SyscallInsn, X86UserEvent};
use crate::user::cpu::x86_64::{X86Exit, X86UserCpu};
use crate::user::cpu::{AccessFault, AccessFaultKind};
use crate::user::linux::signal::frame::FaultUpdate;
use crate::user::linux::signal::{SIGBUS, SIGFPE, SIGILL, SIGSEGV, SIGTRAP, SigInfo, code};

/// `sizeof(struct rt_sigframe)` on x86-64: `pretcode` (8) + `struct
/// ucontext` (304) + `struct siginfo` (128).
pub const RT_SIGFRAME_SIZE: u64 = 440;

/// `HWCAP2_FSGSBASE`: the kernel enabled `CR4.FSGSBASE`.
pub const HWCAP2_FSGSBASE: u64 = 1 << 1;

/// Capabilities: `AT_HWCAP` is CPUID leaf 1 EDX; `AT_HWCAP2` reports
/// FSGSBASE; the signal frame size is `init_sigframe_size()` computed for the
/// XSAVE area the emulated CPU's XCR0 selects.
pub fn caps(cpu: &X86UserCpu) -> ArchCaps {
    let (_, _, _, edx) = cpu.vcpu().cpuid(1, 0);
    // CPUID.(EAX=0DH,ECX=0):EBX = XSAVE area size for the enabled XCR0.
    let (_, xsave_size, _, _) = cpu.vcpu().cpuid(0xD, 0);
    // MAX_FRAME_SIGINFO_UCTXT_SIZE + MAX_FRAME_PADDING (15) + fpstate size
    // (XSAVE area + FP_XSTATE_MAGIC2 (4)) + MAX_XSAVE_PADDING (63), rounded
    // up to FRAME_ALIGNMENT (16).
    let frame = RT_SIGFRAME_SIZE + 15 + u64::from(xsave_size) + 4 + 63;
    ArchCaps {
        hwcap: u64::from(edx),
        hwcap2: Some(HWCAP2_FSGSBASE),
        platform: Some("x86_64"),
        minsigstksz: frame.div_ceil(16) * 16,
    }
}

/// `start_thread`: RIP = entry, RSP = sp, RFLAGS = IF, every other register
/// zero (`ELF_PLAT_INIT`), FS/GS bases zero, default x87/SSE control state.
pub fn start(cpu: &mut X86UserCpu, entry: u64, sp: u64) {
    let v = cpu.vcpu_mut();
    *v.user_regs_mut() = Default::default();
    v.user_regs_mut().rip = entry;
    v.user_regs_mut().rsp = sp;
    v.set_user_rflags(0x202);
    v.set_fs_base(0);
    v.set_gs_base(0);
    v.set_mxcsr(0x1F80).expect("default MXCSR is valid");
}

/// `fpu__exception_code()`: the `si_code` for a SIMD floating-point
/// exception, from the unmasked exception flags `err`.
fn fp_exception_code(err: u32) -> i32 {
    if err & 0x001 != 0 {
        code::FPE_FLTINV
    } else if err & 0x004 != 0 {
        code::FPE_FLTDIV
    } else if err & 0x008 != 0 {
        code::FPE_FLTOVF
    } else if err & 0x012 != 0 {
        code::FPE_FLTUND
    } else if err & 0x020 != 0 {
        code::FPE_FLTRES
    } else {
        0
    }
}

/// Maps an x86 exception or software interrupt to its Linux signal.
fn event_signal(e: &X86UserEvent, mxcsr: u32) -> Result<SigInfo, ()> {
    let fault = |signo, code, addr| Ok(SigInfo::fault(signo, code, addr));
    match (e.source, e.vector) {
        // INT3/INT 3 and INTO/INT 4 use DPL-3 gates (do_int3_user, do_trap).
        (_, 3) => fault(SIGTRAP, code::SI_KERNEL, 0),
        (_, 4) => fault(SIGSEGV, code::SI_KERNEL, 0),
        // Every other vector's gate is DPL 0, so INT n raises #GP(n*8+2).
        (X86EventSource::SoftwareInterrupt, _) => fault(SIGSEGV, code::SI_KERNEL, 0),
        (X86EventSource::Exception, 0) => fault(SIGFPE, code::FPE_INTDIV, e.insn_rip),
        // INT1/ICEBP and single-step: send_sigtrap(regs, 0, TRAP_BRKPT).
        (X86EventSource::Exception, 1) => fault(SIGTRAP, code::TRAP_BRKPT, e.return_rip),
        (X86EventSource::Exception, 5) => fault(SIGSEGV, code::SI_KERNEL, 0),
        (X86EventSource::Exception, 6) => fault(SIGILL, code::ILL_ILLOPN, e.insn_rip),
        (X86EventSource::Exception, 11 | 12) => fault(SIGBUS, code::SI_KERNEL, 0),
        (X86EventSource::Exception, 13) => fault(SIGSEGV, code::SI_KERNEL, 0),
        (X86EventSource::Exception, 17) => fault(SIGBUS, code::BUS_ADRALN, 0),
        // #XM: flags set in MXCSR[5:0] whose masks MXCSR[12:7] are clear.
        (X86EventSource::Exception, 19) => fault(
            SIGFPE,
            fp_exception_code(mxcsr & !(mxcsr >> 7) & 0x3f),
            e.insn_rip,
        ),
        // #MF: x87 status is not exported by the core; report the signal
        // without a diagnosis.
        (X86EventSource::Exception, 16) => fault(SIGFPE, code::FPE_FLTUNK, e.insn_rip),
        _ => Err(()),
    }
}

/// The `thread.trap_nr`/`thread.error_code` a trap leaves (`do_trap`,
/// `gp_user_force_sig_segv`, `math_error`): a DPL-0 `INT n` gate is
/// #GP(n * 8 + 2).
pub(crate) fn trap_record(e: &X86UserEvent) -> FaultUpdate {
    let (trap_nr, error_code) = match (e.source, e.vector) {
        (X86EventSource::SoftwareInterrupt, v) if v != 3 && v != 4 => (13, u64::from(v) * 8 + 2),
        (_, v @ (16 | 19)) => (u64::from(v), 0),
        (_, v) => (u64::from(v), e.error_code.unwrap_or(0)),
    };
    FaultUpdate::X86 {
        trap_nr,
        error_code,
        cr2: None,
    }
}

/// `set_signal_archinfo` for a page fault: vector 14, the #PF error code
/// (P for protection violations, W for writes, U always, I for
/// instruction fetches; P is forced at or above `TASK_SIZE_MAX`), and cr2.
pub(crate) fn page_fault_record(f: &AccessFault) -> FaultUpdate {
    let mut error_code = 1 << 2;
    if f.kind == AccessFaultKind::Permission || f.addr >= (1 << 47) - 4096 {
        error_code |= 1;
    }
    match f.access {
        MemoryAccessKind::Write => error_code |= 1 << 1,
        MemoryAccessKind::Fetch => error_code |= 1 << 4,
        MemoryAccessKind::Read => {}
    }
    FaultUpdate::X86 {
        trap_nr: 14,
        error_code,
        cr2: Some(f.addr),
    }
}

/// Runs one time slice.
pub fn run(cpu: &mut X86UserCpu) -> CpuEvent {
    match cpu.run() {
        X86Exit::Syscall {
            insn: X86SyscallInsn::Syscall,
            ..
        } => {
            let r = cpu.vcpu().user_regs();
            CpuEvent::Syscall {
                nr: r.rax,
                args: [r.rdi, r.rsi, r.rdx, r.r10, r.r8, r.r9],
            }
        }
        X86Exit::Syscall {
            insn: X86SyscallInsn::Sysenter,
            insn_rip,
        } => {
            // SYSENTER is #UD in 64-bit mode on AMD processors and enters the
            // 32-bit compat path with a vDSO-relative return on Intel, which a
            // vDSO-less process cannot use; report it as the #UD it is on AMD.
            cpu.vcpu_mut().user_regs_mut().rip = insn_rip;
            CpuEvent::Signal(
                SigInfo::fault(SIGILL, code::ILL_ILLOPN, insn_rip),
                FaultUpdate::X86 {
                    trap_nr: 6,
                    error_code: 0,
                    cr2: None,
                },
            )
        }
        X86Exit::Event(e) if e.source == X86EventSource::SoftwareInterrupt && e.vector == 0x80 => {
            let r = cpu.vcpu_mut().user_regs_mut();
            r.rip = e.return_rip;
            let lo = |v: u64| v & 0xFFFF_FFFF;
            CpuEvent::CompatSyscall {
                nr: lo(r.rax),
                args: [
                    lo(r.rbx),
                    lo(r.rcx),
                    lo(r.rdx),
                    lo(r.rsi),
                    lo(r.rdi),
                    lo(r.rbp),
                ],
            }
        }
        X86Exit::Event(e) => match event_signal(&e, cpu.vcpu().mxcsr()) {
            Ok(info) => {
                // The frame's saved RIP: past the instruction for traps and
                // for INT3/INTO, the instruction itself for faults and for
                // the #GP a DPL-0 gate raises.
                let rip = match (e.source, e.vector) {
                    (_, 3 | 4) => e.return_rip,
                    (X86EventSource::SoftwareInterrupt, _) => e.insn_rip,
                    _ => e.return_rip,
                };
                cpu.vcpu_mut().user_regs_mut().rip = rip;
                CpuEvent::Signal(info, trap_record(&e))
            }
            Err(()) => CpuEvent::Internal(format!("unexpected x86 event {e:?}")),
        },
        X86Exit::Fault(f) => CpuEvent::Signal(fault_signal(&f), page_fault_record(&f)),
        X86Exit::Yield => CpuEvent::Yield,
        X86Exit::Internal(e) => CpuEvent::Internal(e.to_string()),
    }
}
