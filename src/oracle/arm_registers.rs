//! AArch64 architectural register names in oracle effects.

use crate::smir::ir::types::ArmReg;

pub(super) fn arm_reg_name(reg: &ArmReg) -> String {
    match reg {
        ArmReg::X(n) => format!("x{n}"),
        ArmReg::Sp => "sp".to_string(),
        ArmReg::Pc => "pc".to_string(),
        ArmReg::Nzcv => "nzcv".to_string(),
        ArmReg::V(n) => format!("v{n}"),
        ArmReg::Fpcr => "fpcr".to_string(),
        ArmReg::Fpsr => "fpsr".to_string(),
        ArmReg::SysReg(reg) => format!("sysreg_{reg:#x}"),
        ArmReg::Pstate => "pstate".to_string(),
        ArmReg::SpEl(el) => format!("sp_el{el}"),
    }
}
