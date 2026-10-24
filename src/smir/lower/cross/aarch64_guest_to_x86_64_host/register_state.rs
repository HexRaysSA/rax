//! Guest-register state offsets and scalar register transfers.

use super::*;

impl Aarch64X86_64Lowerer {
    pub(super) fn arm_offset(reg: ArmReg) -> Result<i32, LowerError> {
        match reg {
            ArmReg::X(n) if n < 31 => Ok(A64_X0_OFFSET + i32::from(n) * 8),
            ArmReg::X(_) => Err(LowerError::InvalidRegister(
                "x31 must be encoded as XZR".into(),
            )),
            ArmReg::Sp => Ok(A64_SP_OFFSET),
            ArmReg::Pc => Ok(A64_PC_OFFSET),
            ArmReg::Nzcv => Ok(A64_NZCV_OFFSET),
            ArmReg::Fpcr => Ok(A64_FPCR_OFFSET),
            ArmReg::Fpsr => Ok(A64_FPSR_OFFSET),
            ArmReg::V(n) if n < 32 => Ok(A64_V_OFFSET + i32::from(n) * 16),
            ArmReg::Pstate | ArmReg::SpEl(_) => Err(LowerError::UnsupportedOp {
                op: format!("AArch64 full system register {reg:?}"),
            }),
            ArmReg::V(_) | ArmReg::SysReg(_) => {
                Err(LowerError::InvalidRegister(format!("{reg:?}")))
            }
        }
    }

    pub(super) fn virtual_slot(&self, id: VirtualId) -> Result<i32, LowerError> {
        self.virtual_slots
            .get(&id)
            .copied()
            .ok_or_else(|| LowerError::RegisterAllocationFailed {
                reason: format!("missing stack slot for virtual {:?}", id),
            })
    }

    pub(super) fn emit_mov_imm(&mut self, dst: PhysReg, imm: i64, width: OpWidth) {
        let mut e = X86Emitter::new(&mut self.code);
        if width == OpWidth::W64 {
            e.emit_mov_ri_imm64(dst, imm);
        } else {
            e.emit_mov_ri(dst, imm, width);
        }
    }

    pub(super) fn load_vreg_to(
        &mut self,
        vreg: VReg,
        dst: PhysReg,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        match vreg {
            VReg::Imm(value) => {
                self.emit_mov_imm(dst, value, width);
            }
            VReg::Virtual(id) => {
                let off = self.virtual_slot(id)?;
                let mut e = X86Emitter::new(&mut self.code);
                e.emit_mov_rm(dst, PhysReg::Rbp, off, OpWidth::W64);
            }
            VReg::Arch(ArchReg::Arm(reg)) => {
                let off = Self::arm_offset(reg)?;
                let load_width = if reg == ArmReg::Nzcv {
                    OpWidth::W32
                } else {
                    OpWidth::W64
                };
                let mut e = X86Emitter::new(&mut self.code);
                e.emit_mov_rm(dst, STATE, off, load_width);
            }
            VReg::Arch(other) => {
                return Err(LowerError::InvalidRegister(format!(
                    "non-AArch64 register in AArch64 lowerer: {other:?}"
                )));
            }
        }
        Ok(())
    }

    pub(super) fn load_src_to(
        &mut self,
        src: &SrcOperand,
        dst: PhysReg,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        match src {
            SrcOperand::Reg(v) => self.load_vreg_to(*v, dst, width),
            SrcOperand::Imm(value) | SrcOperand::Imm64(value) => {
                self.emit_mov_imm(dst, *value, width);
                Ok(())
            }
            SrcOperand::Shifted { reg, shift, amount } => {
                self.load_vreg_to(*reg, dst, width)?;
                self.emit_shift_imm(dst, *shift, *amount, width)
            }
            SrcOperand::Extended { reg, extend, shift } => {
                self.load_vreg_to(*reg, dst, OpWidth::W64)?;
                self.emit_extend_in_place(dst, *extend, width)?;
                if *shift != 0 {
                    let mut e = X86Emitter::new(&mut self.code);
                    e.emit_shl_ri(dst, *shift, width);
                }
                Ok(())
            }
        }
    }

    pub(super) fn store_reg_to(
        &mut self,
        dst: VReg,
        src: PhysReg,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        self.emit_normalize_gpr_width(src, width)?;
        match dst {
            VReg::Imm(_) => {}
            VReg::Virtual(id) => {
                let off = self.virtual_slot(id)?;
                let mut e = X86Emitter::new(&mut self.code);
                e.emit_mov_mr(PhysReg::Rbp, off, src, OpWidth::W64);
            }
            VReg::Arch(ArchReg::Arm(reg)) => {
                let off = Self::arm_offset(reg)?;
                let store_width = if reg == ArmReg::Nzcv {
                    OpWidth::W32
                } else {
                    match width {
                        OpWidth::W32 | OpWidth::W64 => OpWidth::W64,
                        other => other,
                    }
                };
                let mut e = X86Emitter::new(&mut self.code);
                e.emit_mov_mr(STATE, off, src, store_width);
            }
            VReg::Arch(other) => {
                return Err(LowerError::InvalidRegister(format!(
                    "non-AArch64 destination in AArch64 lowerer: {other:?}"
                )));
            }
        }
        Ok(())
    }
}
