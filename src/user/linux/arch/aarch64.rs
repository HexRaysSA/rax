//! Linux AArch64 thread ABI.
//!
//! - System calls: `SVC #0` with the number in X8 and arguments in X0-X5;
//!   the result returns in X0 (`arch/arm64/kernel/syscall.c`).
//! - Exceptions become signals as in `arch/arm64/kernel/traps.c` and
//!   `arch/arm64/mm/fault.c`.

use super::{ArchCaps, CpuEvent, fault_signal};
use crate::error::MemoryAccessKind;
use crate::isa::arm::common::cpu::ArmCpu;
use crate::user::cpu::aarch64::{A64Exit, A64UserCpu};
use crate::user::cpu::{AccessFault, AccessFaultKind};
use crate::user::linux::signal::frame::FaultUpdate;
use crate::user::linux::signal::{SIGILL, SIGTRAP, SigInfo, code};

/// `arch/arm64/include/uapi/asm/hwcap.h` bits advertised for the emulated
/// core: FP, ASIMD, AES, SHA1, SHA2, CRC32, ATOMICS (LSE), and CPUID (EL0
/// access to the ID registers, which the core permits).
pub mod hwcap {
    /// `HWCAP_FP`.
    pub const FP: u64 = 1 << 0;
    /// `HWCAP_ASIMD`.
    pub const ASIMD: u64 = 1 << 1;
    /// `HWCAP_AES`.
    pub const AES: u64 = 1 << 3;
    /// `HWCAP_SHA1`.
    pub const SHA1: u64 = 1 << 5;
    /// `HWCAP_SHA2`.
    pub const SHA2: u64 = 1 << 6;
    /// `HWCAP_CRC32`.
    pub const CRC32: u64 = 1 << 7;
    /// `HWCAP_ATOMICS`.
    pub const ATOMICS: u64 = 1 << 8;
    /// `HWCAP_CPUID`.
    pub const CPUID: u64 = 1 << 11;
}

/// `AT_HWCAP2` bits (`arch/arm64/include/uapi/asm/hwcap.h`) the
/// personality consults. None is advertised for the emulated core.
pub mod hwcap2 {
    /// `HWCAP2_BTI`: branch target identification (`PROT_BTI`).
    pub const BTI: u64 = 1 << 17;
}

/// `sizeof(struct rt_sigframe)`: `struct siginfo` (128) + `struct
/// ucontext` (168 bytes of header padded to 176 for the 16-byte-aligned
/// `struct sigcontext` of 4384 bytes, whose `__reserved` area holds the
/// FP/SIMD and ESR records).
pub const RT_SIGFRAME_SIZE: u64 = 128 + 176 + 4384;

/// `signal_minsigstksz` (`minsigstksz_setup`): the rounded frame size plus a
/// frame record (16) and 16 bytes of alignment padding.
pub const MINSIGSTKSZ: u64 = RT_SIGFRAME_SIZE.div_ceil(16) * 16 + 16 + 16;

/// Capabilities: the hwcap set above, `AT_HWCAP2` zero, platform
/// `"aarch64"`.
pub fn caps() -> ArchCaps {
    use hwcap::*;
    ArchCaps {
        hwcap: FP | ASIMD | AES | SHA1 | SHA2 | CRC32 | ATOMICS | CPUID,
        hwcap2: Some(0),
        platform: Some("aarch64"),
        minsigstksz: MINSIGSTKSZ,
    }
}

/// `start_thread`: PC = entry, SP_EL0 = sp, EL0t with every other register,
/// NZCV, FPCR, FPSR, and TPIDR_EL0 zero.
pub fn start(cpu: &mut A64UserCpu, entry: u64, sp: u64) {
    let core = cpu.core_mut();
    core.enter_el0();
    for r in 0..31 {
        core.set_x(r, 0);
    }
    for v in 0..32 {
        core.set_simd(v, 0);
    }
    core.set_fpcr_value(0);
    core.set_fpsr_value(0);
    core.set_tpidr_el0(0);
    core.set_pc(entry);
    cpu.set_sp(sp);
}

/// The `ESR_EL1` of an EL0 abort (Arm ARM D24.2.40): EC 0x20
/// (instruction abort from a lower EL) or 0x24 (data abort), IL = 1, WnR
/// for writes, and the fault status code: a level-3 translation fault
/// (0x07) for unmapped pages and pages the kernel cannot populate, a
/// level-3 permission fault (0x0F), or an alignment fault (0x21). Linux
/// reports the level at which its page-table walk stopped; the emulated
/// address space has no page tables, so level 3 is reported for every
/// translation and permission fault.
pub fn abort_esr(f: &AccessFault) -> u64 {
    let ec: u64 = if f.access == MemoryAccessKind::Fetch {
        0x20
    } else {
        0x24
    };
    let fsc: u64 = match f.kind {
        AccessFaultKind::Unmapped | AccessFaultKind::Bus => 0x07,
        AccessFaultKind::Permission => 0x0F,
        AccessFaultKind::Alignment => 0x21,
    };
    let wnr = u64::from(f.access == MemoryAccessKind::Write);
    (ec << 26) | (1 << 25) | (wnr << 6) | fsc
}

/// Runs up to `budget` instructions.
pub fn run(cpu: &mut A64UserCpu, budget: u64) -> CpuEvent {
    match cpu.run(budget) {
        A64Exit::Svc { .. } => {
            let c = cpu.core();
            CpuEvent::Syscall {
                nr: c.get_x(8),
                args: [
                    c.get_x(0),
                    c.get_x(1),
                    c.get_x(2),
                    c.get_x(3),
                    c.get_x(4),
                    c.get_x(5),
                ],
            }
        }
        // brk_handler → arm64_force_sig_fault(SIGTRAP, TRAP_BRKPT, pc).
        // The fault record is untouched (send_user_sigtrap).
        A64Exit::Brk { pc, .. } => CpuEvent::Signal(
            SigInfo::fault(SIGTRAP, code::TRAP_BRKPT, pc),
            FaultUpdate::None,
        ),
        // do_el0_undef → force_signal_inject(SIGILL, ILL_ILLOPC, pc, 0),
        // whose arm64_notify_die clears the fault record.
        A64Exit::Undefined { pc, .. } => CpuEvent::Signal(
            SigInfo::fault(SIGILL, code::ILL_ILLOPC, pc),
            FaultUpdate::Arm64 { address: 0, esr: 0 },
        ),
        // do_page_fault / do_bad_area → set_thread_esr(far, esr).
        A64Exit::Fault(f) => CpuEvent::Signal(
            fault_signal(&f),
            FaultUpdate::Arm64 {
                address: f.addr,
                esr: abort_esr(&f),
            },
        ),
        A64Exit::Yield => CpuEvent::Yield,
        A64Exit::Internal(e) => CpuEvent::Internal(e),
    }
}
