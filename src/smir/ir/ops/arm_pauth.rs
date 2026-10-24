//! State-backed AArch64 pointer authentication and instruction boundaries.

use crate::isa::arm::aarch64::pauth_instruction::PauthInstruction;
use crate::smir::ir::types::{ArchReg, ArmReg, VReg};

/// One exactly decoded 64-bit PAuth instruction. `raw` and `instruction` must
/// agree; malformed IR exits before architectural effects. Keys, algorithm,
/// profile, controls, privilege and current SP are read from guest state at
/// execution time. No host PAC instruction or process-global key is used.
///
/// PAC/AUT/XPAC/PACGA write the descriptor's destination (X31 discards).
/// Authenticated calls additionally write X30; branches write PC/BTYPE. Loads
/// perform one checked 8-byte access before destination or base writeback.
/// Exception returns restore banked PSTATE/SP and clear the exclusive monitor.
/// NZCV is unchanged except when restored by an exception return. Feature,
/// privilege, authentication, alignment and memory failures are precise at the
/// operation's guest PC. Native admission remains closed until a target has
/// state marshalling and exact helper exits for this operation and boundaries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArmPauthOp {
    pub raw: u32,
    pub instruction: PauthInstruction,
}

impl ArmPauthOp {
    pub fn decode(raw: u32) -> Option<Self> {
        Some(Self {
            raw,
            instruction: PauthInstruction::decode(raw)?,
        })
    }

    pub fn valid(self) -> bool {
        PauthInstruction::decode(self.raw) == Some(self.instruction)
    }

    /// Conservative architectural clobbers also invalidate optimizer facts
    /// about banked aliases. This is a fixed-size set: O(1) time and space.
    pub(crate) fn destinations(self) -> Vec<VReg> {
        architectural_state()
    }
}

/// Observable state at every faultable guest boundary. Includes vector and
/// status registers so an optimizer cannot discard earlier committed writes
/// merely because a later authentication or entry check exits the region.
pub(crate) fn architectural_state() -> Vec<VReg> {
    let mut registers: Vec<_> = (0..31).map(ArmReg::X).collect();
    registers.extend((0..32).map(ArmReg::V));
    registers.extend((0..4).map(ArmReg::SpEl));
    registers.extend([
        ArmReg::Sp,
        ArmReg::Pc,
        ArmReg::Nzcv,
        ArmReg::Pstate,
        ArmReg::Fpcr,
        ArmReg::Fpsr,
    ]);
    // Raw encodings of all state consumed by the shared planner and ERET.
    for (op1, crn, crm, op2) in [
        (0, 2, 1, 0),
        (0, 2, 1, 1),
        (0, 2, 1, 2),
        (0, 2, 1, 3),
        (0, 2, 2, 0),
        (0, 2, 2, 1),
        (0, 2, 2, 2),
        (0, 2, 2, 3),
        (0, 2, 3, 0),
        (0, 2, 3, 1),
        (0, 1, 0, 0),
        (4, 1, 0, 0),
        (6, 1, 0, 0),
        (0, 2, 0, 2),
        (4, 2, 0, 2),
        (6, 2, 0, 2),
        (4, 1, 1, 0),
        (6, 1, 1, 0),
        (0, 4, 0, 0),
        (0, 4, 0, 1),
        (4, 4, 0, 0),
        (4, 4, 0, 1),
        (6, 4, 0, 0),
        (6, 4, 0, 1),
    ] {
        registers.push(ArmReg::SysReg(
            (3 << 14) | (op1 << 11) | (crn << 7) | (crm << 3) | op2,
        ));
    }
    for (op0, op1, crn, crm, op2) in [
        (3, 0, 0, 4, 0), // ID_AA64PFR0_EL1: implemented EL/width state.
        (2, 0, 0, 2, 2), // MDSCR_EL1.
        (2, 0, 1, 3, 4), // OSDLR_EL1.
        (3, 4, 1, 1, 1), // MDCR_EL2.
        (3, 6, 1, 3, 1), // MDCR_EL3.
    ] {
        registers.push(ArmReg::SysReg(
            (op0 << 14) | (op1 << 11) | (crn << 7) | (crm << 3) | op2,
        ));
    }
    registers
        .into_iter()
        .map(|reg| VReg::Arch(ArchReg::Arm(reg)))
        .collect()
}
