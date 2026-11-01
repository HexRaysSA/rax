//! Linux arm64 HWCAP_CPUID emulation after an architectural EL0 fault.
//!
//! Linux 6.19 cpufeature.c selects the CRm=0 identity registers and CRm=2..7
//! feature sub-block. Tracked fields use the kernel's user mask and hidden safe
//! defaults; untracked slots read zero. This personality currently advertises
//! no SVE, SME, MTE, BTI, PAC, GCS or POE process ABI, so the corresponding
//! FTR_VISIBLE_IF_IS_ENABLED fields remain hidden.

use super::A64UserCpu;
use crate::isa::arm::aarch64::sysregs::SystemRegisters;
use crate::isa::arm::common::cpu::ArmCpu;
use crate::isa::arm::common::sysreg::Aarch64SysRegEncoding;

fn visible_value(registers: &SystemRegisters, crm: u8, op2: u8) -> Option<u64> {
    if crm == 0 {
        return match op2 {
            0 => Some(registers.midr_el1 & u64::from(u32::MAX)),
            // sysreg.h SYS_MPIDR_SAFE_VAL fixes RES1 and hides affinity.
            5 => Some(1 << 31),
            6 => Some(0),
            _ => None,
        };
    }
    if !(2..=7).contains(&crm) {
        return None;
    }
    let (mask, safe) = match (crm, op2) {
        (2, 5) => (0x0000_0000_000f_fff0, 0),    // ID_ISAR5_EL1
        (2, 7) => (0x0000_0000_0ff0_fff0, 0),    // ID_ISAR6_EL1
        (3, 0) => (0x0000_0000_0000_0f00, 0),    // MVFR0_EL1
        (3, 1) => (0x0000_0000_ffff_ff00, 0),    // MVFR1_EL1
        (3, 4) => (0x0000_0000_0000_00f0, 0),    // ID_PFR2_EL1
        (4, 0) => (0x000f_0000_00ff_0000, 0x11), // ID_AA64PFR0_EL1
        (4, 1) => (0x0000_0000_0000_00f0, 0),    // ID_AA64PFR1_EL1
        (4, 2) => (0x0000_000f_0000_0ff0, 0),    // ID_AA64PFR2_EL1
        (4, 7) => (0x0000_0000_fc00_0003, 0),    // ID_AA64FPFR0_EL1
        (5, 0) => (0, 6),                        // ID_AA64DFR0_EL1
        (6, 0) => (0xf0ff_ffff_f0ff_fff0, 0),    // ID_AA64ISAR0_EL1
        (6, 1) => (0x00ff_f0ff_00ff_f00f, 0),    // ID_AA64ISAR1_EL1
        (6, 2) => (0x0fff_0000_00ff_00ff, 0),    // ID_AA64ISAR2_EL1
        (6, 3) => (0x0000_0000_f00f_00f0, 0),    // ID_AA64ISAR3_EL1
        (7, 0) => (0xf000_0000_0000_0000, 0x0000_0111_ff00_0000), // ID_AA64MMFR0_EL1
        (7, 1) => (0x0000_f000_0000_0000, 0),    // ID_AA64MMFR1_EL1
        (7, 2) => (0x0000_000f_0000_0000, 0),    // ID_AA64MMFR2_EL1
        _ => (0, 0),
    };
    let encoding = Aarch64SysRegEncoding::new(3, 0, 0, crm, op2);
    Some((registers.read(encoding, 1).unwrap_or(0) & mask) | safe)
}

/// Called only for an actual undefined instruction from the EL0 CPU adapter.
/// The kernel rereads the instruction through user-accessible memory before
/// emulating it (traps.c do_el0_undef); an unreadable word remains SIGILL.
pub(super) fn emulate(cpu: &mut A64UserCpu, pc: u64) -> bool {
    let mut bytes = [0; 4];
    if cpu.space().read(pc, &mut bytes).is_err() {
        return false;
    }
    let instruction = u32::from_le_bytes(bytes);
    // MRS, op0=3, op1=0 and CRn=0. MSR and every other register class reject.
    if instruction & 0xffff_f000 != 0xd538_0000 {
        return false;
    }
    let system = cpu.core().export_sregs();
    let Some(execution) = system.execution else {
        return false;
    };
    let Some(value) = visible_value(
        &execution.sysregs,
        ((instruction >> 8) & 15) as u8,
        ((instruction >> 5) & 7) as u8,
    ) else {
        return false;
    };
    let pstate = cpu.core().el0_spsr() & !(3 << 10);
    // arm64_skip_faulting_instruction clears BTYPE for an emulated A64 word.
    cpu.core_mut().set_el0_spsr(pstate);
    cpu.core_mut().set_x((instruction & 31) as u8, value);
    cpu.core_mut().set_pc(pc.wrapping_add(4));
    true
}
