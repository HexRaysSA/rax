//! Linux RV64 thread ABI.
//!
//! - System calls: `ECALL` with the number in a7 and arguments in a0-a5;
//!   the result returns in a0 and the kernel advances `epc` past the 4-byte
//!   `ECALL` (`arch/riscv/kernel/traps.c` `do_trap_ecall_u`).
//! - Exceptions become signals as in `arch/riscv/kernel/traps.c` and
//!   `arch/riscv/mm/fault.c`.

use super::{ArchCaps, CpuEvent, fault_signal};
use crate::user::cpu::riscv64::{RvExit, RvUserCpu};
use crate::user::linux::signal::frame::FaultUpdate;
use crate::user::linux::signal::{SIGBUS, SIGILL, SIGTRAP, SigInfo, code};

/// `COMPAT_HWCAP_ISA_*` bit for a single-letter extension: `1 << (c - 'a')`.
pub const fn isa_bit(letter: u8) -> u64 {
    1 << (letter - b'a')
}

/// `sizeof(struct rt_sigframe)`: `struct siginfo` (128) + `struct
/// ucontext` (176-byte header, `struct sigcontext` of 256 bytes of
/// general registers and a 528-byte FP union).
pub const RT_SIGFRAME_SIZE: u64 = 128 + 176 + 256 + 528;

/// Size of the vector-state record appended to a frame: header (8),
/// `struct __riscv_v_ext_state` (48), and 32 registers of VLENB bytes.
pub fn vector_context_size(vlenb: u64) -> u64 {
    8 + 48 + 32 * vlenb
}

/// Capabilities: the single-letter ISA bits of the configured core, no
/// `AT_HWCAP2` or platform string, and `get_rt_frame_size(true)` with the
/// vector record when V is present.
pub fn caps(cpu: &RvUserCpu) -> ArchCaps {
    let isa = &cpu.core().config().isa;
    let mut hwcap = isa_bit(b'i');
    for (present, letter) in [
        (isa.m, b'm'),
        (isa.a, b'a'),
        (isa.f, b'f'),
        (isa.d, b'd'),
        (isa.c, b'c'),
        (isa.v, b'v'),
    ] {
        if present {
            hwcap |= isa_bit(letter);
        }
    }
    let mut frame = RT_SIGFRAME_SIZE;
    if isa.v {
        frame += vector_context_size(16);
    }
    ArchCaps {
        hwcap,
        hwcap2: None,
        platform: None,
        minsigstksz: frame.div_ceil(16) * 16,
    }
}

/// `start_thread`: epc = entry, sp = sp, every other integer and FP
/// register, `fcsr`, and the vector state zero.
pub fn start(cpu: &mut RvUserCpu, entry: u64, sp: u64) {
    let core = cpu.core_mut();
    for r in 1..32 {
        core.set_x(r, 0);
        core.set_f(r, 0);
    }
    core.set_f(0, 0);
    core.set_fcsr(0);
    core.set_x(2, sp);
    core.set_pc(entry);
}

/// Runs up to `budget` instructions.
pub fn run(cpu: &mut RvUserCpu, budget: u64) -> CpuEvent {
    match cpu.run(budget) {
        RvExit::Ecall { pc } => {
            cpu.core_mut().set_pc(pc.wrapping_add(4));
            let c = cpu.core();
            CpuEvent::Syscall {
                nr: c.x(17),
                args: [c.x(10), c.x(11), c.x(12), c.x(13), c.x(14), c.x(15)],
            }
        }
        RvExit::Ebreak { pc } => CpuEvent::Signal(
            SigInfo::fault(SIGTRAP, code::TRAP_BRKPT, pc),
            FaultUpdate::None,
        ),
        RvExit::Illegal { pc, .. } => CpuEvent::Signal(
            SigInfo::fault(SIGILL, code::ILL_ILLOPC, pc),
            FaultUpdate::None,
        ),
        // DO_ERROR_INFO(..., SIGBUS, BUS_ADRALN, ...) reports regs->epc.
        RvExit::Misaligned { pc, .. } => CpuEvent::Signal(
            SigInfo::fault(SIGBUS, code::BUS_ADRALN, pc),
            FaultUpdate::None,
        ),
        RvExit::Fault(f) => CpuEvent::Signal(fault_signal(&f), FaultUpdate::None),
        RvExit::Yield => CpuEvent::Yield,
        RvExit::Internal(e) => CpuEvent::Internal(e),
    }
}
