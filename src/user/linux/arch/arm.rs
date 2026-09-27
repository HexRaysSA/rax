//! Linux thread ABI of an ARM EABI task on arm64 (`CONFIG_COMPAT`).
//!
//! The kernel modelled is a distribution's: `CONFIG_KUSER_HELPERS`, no
//! compat vDSO, and `CONFIG_ARMV8_DEPRECATED` with
//! `CONFIG_CP15_BARRIER_EMULATION` (the A32 CP15 barriers emulated, their
//! default mode) and `CONFIG_SWP_EMULATION` (off by default, so `SWP` is
//! `SIGILL`), on a CPU without mixed-endian EL0 (`SETEND` is `SIGILL`),
//! and without `CONFIG_COMPAT_ALIGNMENT_FIXUPS` (its default), so a
//! misaligned multi-word access (LDM, STM, LDRD, VLDR, ...) is `SIGBUS`.
//!
//! - System calls: `SVC` (whatever its immediate) with the number in R7 and
//!   the arguments in R0-R5; the result returns in R0 (`el0_svc_compat`,
//!   `arch/arm64/kernel/syscall.c`). The ARM private calls from `0xf0000`
//!   (`compat_arm_syscall`) are the dispatcher's.
//! - Exceptions become signals as `el0t_32_sync_handler` routes them
//!   (`arch/arm64/kernel/entry-common.c`): `BKPT` (`do_bkpt32`) and the
//!   AArch32 breakpoint encodings (`try_handle_aarch32_break`) are `SIGTRAP`
//!   with `TRAP_BRKPT`; `do_el0_undef` emulates the CP15 barriers in A32
//!   state (`armv8_deprecated.c`) and makes every other UNDEFINED
//!   instruction `SIGILL` with `ILL_ILLOPC`; aborts go through
//!   `do_page_fault`, alignment faults through `do_alignment_fault` to
//!   `SIGBUS` with `BUS_ADRALN`, and a PC alignment fault is `SIGBUS` with
//!   `BUS_ADRALN` (`do_sp_pc_abort`).

use super::{ArchCaps, CpuEvent, fault_signal};
use crate::error::MemoryAccessKind;
use crate::user::cpu::arm::{A32Exit, A32UserCpu};
use crate::user::cpu::{AccessFault, AccessFaultKind};
use crate::user::linux::signal::frame::FaultUpdate;
use crate::user::linux::signal::{SIGILL, SIGTRAP, SigInfo, code};

/// `COMPAT_HWCAP_*` (`arch/arm64/include/asm/hwcap.h`) advertised for the
/// emulated core: `COMPAT_ELF_HWCAP_DEFAULT` (HALF, THUMB, FAST_MULT, EDSP,
/// TLS, IDIV, LPAE) and what `compat_elf_hwcaps` finds in the AArch32 ID
/// registers of an ARMv8-A core: NEON, VFPv4 (fused multiply-add), and VFP
/// and VFPv3 (`MVFR0.FPDP`). The core has no AArch32 AES, SHA, or CRC32, so
/// `AT_HWCAP2` is zero.
pub mod hwcap {
    /// `COMPAT_HWCAP_HALF`.
    pub const HALF: u64 = 1 << 1;
    /// `COMPAT_HWCAP_THUMB`.
    pub const THUMB: u64 = 1 << 2;
    /// `COMPAT_HWCAP_FAST_MULT`.
    pub const FAST_MULT: u64 = 1 << 4;
    /// `COMPAT_HWCAP_VFP`.
    pub const VFP: u64 = 1 << 6;
    /// `COMPAT_HWCAP_EDSP`.
    pub const EDSP: u64 = 1 << 7;
    /// `COMPAT_HWCAP_NEON`.
    pub const NEON: u64 = 1 << 12;
    /// `COMPAT_HWCAP_VFPv3`.
    pub const VFPV3: u64 = 1 << 13;
    /// `COMPAT_HWCAP_TLS`.
    pub const TLS: u64 = 1 << 15;
    /// `COMPAT_HWCAP_VFPv4`.
    pub const VFPV4: u64 = 1 << 16;
    /// `COMPAT_HWCAP_IDIVA`.
    pub const IDIVA: u64 = 1 << 17;
    /// `COMPAT_HWCAP_IDIVT`.
    pub const IDIVT: u64 = 1 << 18;
    /// `COMPAT_HWCAP_LPAE`.
    pub const LPAE: u64 = 1 << 20;
}

/// Capabilities: the hwcap set above, `AT_HWCAP2` and `AT_HWCAP3` zero
/// (`COMPAT_ELF_HWCAP2`, `COMPAT_ELF_HWCAP3`), platform `"v8l"`
/// (`COMPAT_ELF_PLATFORM`). Without a compat vDSO, `COMPAT_ARCH_DLINFO` is
/// empty: no `AT_MINSIGSTKSZ`.
pub fn caps() -> ArchCaps {
    use hwcap::*;
    ArchCaps {
        hwcap: HALF
            | THUMB
            | FAST_MULT
            | VFP
            | EDSP
            | NEON
            | VFPV3
            | TLS
            | VFPV4
            | IDIVA
            | IDIVT
            | LPAE,
        hwcap2: Some(0),
        hwcap3: Some(0),
        platform: Some("v8l"),
        minsigstksz: None,
    }
}

/// `compat_start_thread`: PC = entry with bit 0 selecting Thumb, SP = sp,
/// User mode with every other register, the flags, the FP/SIMD registers,
/// FPSCR, and both thread ID registers zero (`start_thread_common`,
/// `fpsimd_flush_thread`, `tls_thread_flush`).
pub fn start(cpu: &mut A32UserCpu, entry: u64, sp: u64) {
    let core = cpu.core_mut();
    core.regs = [0; 16];
    core.cpsr = crate::isa::arm::Psr::from_u32(crate::isa::arm::ProcessorMode::User as u32);
    core.cpsr.t = entry & 1 != 0;
    core.vfp.dregs = [0; 32];
    core.vfp.fpscr = crate::isa::arm::vfp::Fpscr::from_bits(0);
    core.cp15.tpidrurw = 0;
    core.cp15.tpidruro = 0;
    cpu.set_pc(entry);
    cpu.set_sp(sp);
}

/// `AARCH32_BREAK_ARM` (any condition), `AARCH32_BREAK_THUMB`, and
/// `AARCH32_BREAK_THUMB2_LO`/`_HI` (`arch/arm64/include/asm/debug-monitors.h`):
/// the UNDEFINED encodings `try_handle_aarch32_break` reports as
/// breakpoints.
fn is_break(insn: u32, thumb: bool) -> bool {
    if thumb {
        insn == 0xde01 || insn == 0xf7f0_a000
    } else {
        insn & !0xf000_0000 == 0x07f0_01f0
    }
}

/// `try_emulate_cp15_barrier`: in A32 state, `MCR p15, 0, Rt, c7, c10, 4/5`
/// (CP15DSB, CP15DMB) and `MCR p15, 0, Rt, c7, c5, 4` (CP15ISB), unless the
/// encoding is unconditional. A barrier among one thread's instructions
/// needs no action here.
fn is_cp15_barrier(insn: u32, thumb: bool) -> bool {
    !thumb
        && insn >> 28 != 0xf
        && (insn & 0x0fff_0fdf == 0x0e07_0f9a || insn & 0x0fff_0fff == 0x0e07_0f95)
}

/// Runs up to `budget` instructions.
pub fn run(cpu: &mut A32UserCpu, budget: u64) -> CpuEvent {
    let mut left = budget;
    loop {
        match cpu.run(left) {
            A32Exit::Undefined {
                pc, insn, thumb, ..
            } if is_cp15_barrier(insn, thumb) => {
                // arm64_skip_faulting_instruction; the emulated barrier is
                // an instruction of the slice.
                cpu.set_pc(pc + 4);
                left = left.saturating_sub(1);
                if left == 0 {
                    return CpuEvent::Yield;
                }
            }
            exit => return event(cpu, exit),
        }
    }
}

fn event(cpu: &A32UserCpu, exit: A32Exit) -> CpuEvent {
    match exit {
        A32Exit::Svc { .. } => {
            let r = &cpu.core().regs;
            CpuEvent::Syscall {
                nr: u64::from(r[7]),
                args: [0, 1, 2, 3, 4, 5].map(|i| u64::from(r[i])),
            }
        }
        // try_handle_aarch32_break → send_user_sigtrap: the fault record is
        // untouched.
        A32Exit::Undefined {
            pc, insn, thumb, ..
        } if is_break(insn, thumb) => CpuEvent::Signal(
            SigInfo::fault(SIGTRAP, code::TRAP_BRKPT, pc),
            FaultUpdate::None,
        ),
        // force_signal_inject → arm64_notify_die clears the record.
        A32Exit::Undefined { pc, .. } => CpuEvent::Signal(
            SigInfo::fault(SIGILL, code::ILL_ILLOPC, pc),
            FaultUpdate::Arm64 { address: 0, esr: 0 },
        ),
        // do_bkpt32 → arm64_notify_die(SIGTRAP, TRAP_BRKPT, pc, esr).
        A32Exit::Bkpt { imm, pc } => CpuEvent::Signal(
            SigInfo::fault(SIGTRAP, code::TRAP_BRKPT, pc),
            FaultUpdate::Arm64 {
                address: 0,
                esr: bkpt32_esr(imm, cpu.thumb()),
            },
        ),
        // do_sp_pc_abort → arm64_notify_die(SIGBUS, BUS_ADRALN, pc, esr).
        A32Exit::Fault(f)
            if f.access == MemoryAccessKind::Fetch && f.kind == AccessFaultKind::Alignment =>
        {
            CpuEvent::Signal(
                fault_signal(&f),
                FaultUpdate::Arm64 {
                    address: 0,
                    esr: PC_ALIGN_ESR,
                },
            )
        }
        // do_page_fault / do_bad_area → set_thread_esr(far, esr).
        A32Exit::Fault(f) => CpuEvent::Signal(
            fault_signal(&f),
            FaultUpdate::Arm64 {
                address: f.addr,
                esr: abort_esr(&f),
            },
        ),
        A32Exit::Yield => CpuEvent::Yield,
        A32Exit::Internal(e) => CpuEvent::Internal(e),
    }
}

/// The `ESR_EL1` of a PC alignment fault (EC 0x22, IL set).
const PC_ALIGN_ESR: u64 = (0x22 << 26) | (1 << 25);

/// The `ESR_EL1` of an AArch32 `BKPT` (EC 0x38; IL clear for the 16-bit
/// T32 encoding; the immediate in bits 15:0).
fn bkpt32_esr(imm: u16, thumb: bool) -> u64 {
    (0x38 << 26) | (u64::from(!thumb) << 25) | u64::from(imm)
}

/// The `ESR_EL1` of an abort from AArch32 EL0, as for AArch64 (the same
/// exception classes; see [`super::aarch64::abort_esr`]).
pub fn abort_esr(f: &AccessFault) -> u64 {
    super::aarch64::abort_esr(f)
}
