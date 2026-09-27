//! Branch and conditional-branch execution

use crate::isa::arm::aarch64::cpu::*;
use std::collections::HashSet;
use std::fmt::Debug;

use crate::isa::arm::aarch64::exceptions::{
    ExceptionType, SyndromeRegister, build_spsr, exception_target_el, parse_spsr, vector_offset,
};
use crate::isa::arm::aarch64::gic::{Gic, GicConfig};
use crate::isa::arm::aarch64::mmu::{Mmu, MmuConfig, TranslationFault, TranslationGranule};
use crate::isa::arm::aarch64::sysregs::SystemRegisters;
use crate::isa::arm::aarch64::{NUM_ELS, NUM_GPRS, NUM_SIMD_REGS, sctlr};

use crate::isa::arm::common::cpu::{
    ArmCpu, ArmError, ArmException, ArmProfile, ArmVersion, CpuExit, MemoryFaultInfo,
    MemoryFaultType, ProcessorState, WatchpointKind,
};
use crate::isa::arm::common::features::ArmFeatures;
use crate::isa::arm::common::memory::ArmMemory;
use crate::isa::arm::common::sysreg::Aarch64SysRegEncoding;
use crate::vm::vcpu::Aarch64SystemRegisters;

impl AArch64Cpu {
    /// Return from exception (ERET).
    pub(crate) fn exception_return(&mut self) -> Result<CpuExit, ArmError> {
        // Get saved state from current EL
        let spsr = self.sysregs.bank(self.current_el).spsr;
        let elr = self.sysregs.bank(self.current_el).elr;

        // Parse SPSR
        let (nzcv, daif, target_el, sp_sel, ssbs, pan, uao, dit, tco, btype, il, ss) =
            parse_spsr(spsr);

        // Check if return is valid
        if target_el > self.current_el {
            // Cannot return to higher EL
            return Err(ArmError::Internal("ERET to higher EL".to_string()));
        }

        // Restore state
        self.nzcv = nzcv;
        self.daif = daif;
        self.current_el = target_el;
        self.sp_sel = sp_sel;
        self.ssbs = ssbs;
        self.pan = pan;
        self.uao = uao;
        self.dit = dit;
        self.tco = tco;
        self.btype = btype;
        self.il = il;
        self.ss = ss;

        // Set PC
        self.pc = elr;

        Ok(CpuExit::Continue)
    }

    /// Execute branch and system instruction.
    pub(crate) fn exec_branch_system(&mut self, insn: u32) -> Result<CpuExit, ArmError> {
        // Use bits [31:24] for primary decode
        let bits_31_24 = (insn >> 24) & 0xFF;

        // B.cond: bits[31:24] = 01010100 (0x54)
        if bits_31_24 == 0x54 {
            return self.exec_b_cond(insn);
        }

        // B, BL: bits[31:26] = 00010x or 10010x -> bits[31:24] starts with 000101 or 100101
        // Actually B: 000101, BL: 100101, so check bits[30:26] = 00101
        let bits_30_26 = (insn >> 26) & 0x1F;
        if bits_30_26 == 0b00101 {
            return self.exec_b_bl(insn);
        }

        // CBZ/CBNZ: bits[31:24] = x0110100 or x0110101 -> 0x34/0x35 or 0xB4/0xB5
        if bits_31_24 == 0x34 || bits_31_24 == 0x35 || bits_31_24 == 0xB4 || bits_31_24 == 0xB5 {
            return self.exec_cbz_cbnz(insn);
        }

        // TBZ/TBNZ: bits[31:24] = x0110110 or x0110111 -> 0x36/0x37 or 0xB6/0xB7
        if bits_31_24 == 0x36 || bits_31_24 == 0x37 || bits_31_24 == 0xB6 || bits_31_24 == 0xB7 {
            return self.exec_tbz_tbnz(insn);
        }

        // Exception generation: bits[31:24] = 0xD4
        if bits_31_24 == 0xD4 {
            return self.exec_exception_system(insn);
        }

        // System instructions: bits[31:22] = 1101010100 -> bits[31:24] = 0xD5 and bits[23:22] = 00
        if bits_31_24 == 0xD5 {
            let bits_23_22 = (insn >> 22) & 0x3;
            if bits_23_22 == 0 {
                return self.exec_exception_system(insn);
            }
        }

        // Unconditional branch (register): bits[31:25] = 1101011 -> bits[31:24]
        // = 0xD6, or 0xD7 for the FEAT_PAuth forms with opc<3> set (BRAA,
        // BRAB, BLRAA, BLRAB).
        if bits_31_24 == 0xD6 || bits_31_24 == 0xD7 {
            return self.exec_br_reg(insn);
        }

        Err(ArmError::UndefinedInstruction(insn))
    }

    pub(crate) fn exec_bitfield(&mut self, insn: u32) -> Result<CpuExit, ArmError> {
        let sf = (insn >> 31) & 1;
        let opc = (insn >> 29) & 0x3;
        let n = (insn >> 22) & 1;
        let immr = ((insn >> 16) & 0x3F) as u32;
        let imms = ((insn >> 10) & 0x3F) as u32;
        let rn = ((insn >> 5) & 0x1F) as u8;
        let rd = (insn & 0x1F) as u8;

        let datasize = if sf != 0 { 64u32 } else { 32 };
        if (sf == 0 && (n != 0 || immr >= 32 || imms >= 32)) || (sf != 0 && n == 0) {
            return Err(ArmError::UndefinedInstruction(insn));
        }

        // Decode wmask and tmask
        let (wmask, tmask) = decode_bitmasks(n != 0, imms, immr, false, datasize)?;

        let src = if sf != 0 {
            self.get_x(rn)
        } else {
            self.get_w(rn) as u64
        };

        let dst = if sf != 0 {
            self.get_x(rd)
        } else {
            self.get_w(rd) as u64
        };

        // Rotate right
        let bot = if immr == 0 {
            src
        } else {
            (src >> immr) | (src << (datasize - immr))
        };

        // Per the ARM pseudocode: bot = ROR(src, immr) AND wmask, and the
        // destination combines top/bot under TMASK (not wmask — using wmask
        // here turns e.g. `asr xD, xN, #32` into a rotate).
        let bot = bot & wmask;
        let result = match opc {
            0b00 => {
                // SBFM
                // Sign-extend based on imms
                let top = if (src >> imms) & 1 != 0 { !0u64 } else { 0u64 };
                (top & !tmask) | (bot & tmask)
            }
            0b01 => {
                // BFM
                let merged = (dst & !wmask) | bot;
                (dst & !tmask) | (merged & tmask)
            }
            0b10 => {
                // UBFM
                bot & tmask
            }
            _ => return Err(ArmError::UndefinedInstruction(insn)),
        };

        if sf != 0 {
            self.set_x(rd, result);
        } else {
            self.set_w(rd, result as u32);
        }

        Ok(CpuExit::Continue)
    }

    pub(crate) fn exec_b_cond(&mut self, insn: u32) -> Result<CpuExit, ArmError> {
        if (insn >> 4) & 1 != 0 {
            return Err(ArmError::UndefinedInstruction(insn));
        }

        let imm19 = ((insn >> 5) & 0x7FFFF) as i64;
        let cond = (insn & 0xF) as u8;

        let offset = ((imm19 << 45) >> 43) as i64; // Sign extend and multiply by 4

        if self.condition_holds(cond) {
            self.pc = ((self.pc as i64).wrapping_sub(4).wrapping_add(offset)) as u64;
        }

        Ok(CpuExit::Continue)
    }

    pub(crate) fn exec_cbz_cbnz(&mut self, insn: u32) -> Result<CpuExit, ArmError> {
        let sf = (insn >> 31) & 1;
        let op = (insn >> 24) & 1; // 0=CBZ, 1=CBNZ
        let imm19 = ((insn >> 5) & 0x7FFFF) as i64;
        let rt = (insn & 0x1F) as u8;

        let offset = ((imm19 << 45) >> 43) as i64;
        let operand = if sf != 0 {
            self.get_x(rt)
        } else {
            self.get_w(rt) as u64
        };

        let take_branch = if op == 0 { operand == 0 } else { operand != 0 };

        if take_branch {
            self.pc = ((self.pc as i64).wrapping_sub(4).wrapping_add(offset)) as u64;
        }

        Ok(CpuExit::Continue)
    }

    pub(crate) fn exec_tbz_tbnz(&mut self, insn: u32) -> Result<CpuExit, ArmError> {
        let b5 = (insn >> 31) & 1;
        let op = (insn >> 24) & 1; // 0=TBZ, 1=TBNZ
        let b40 = ((insn >> 19) & 0x1F) as u32;
        let imm14 = ((insn >> 5) & 0x3FFF) as i64;
        let rt = (insn & 0x1F) as u8;

        let bit_pos = (b5 << 5) | b40;
        let offset = ((imm14 << 50) >> 48) as i64;
        let operand = self.get_x(rt);
        let bit_set = (operand >> bit_pos) & 1 != 0;

        let take_branch = if op == 0 { !bit_set } else { bit_set };

        if take_branch {
            self.pc = ((self.pc as i64).wrapping_sub(4).wrapping_add(offset)) as u64;
        }

        Ok(CpuExit::Continue)
    }

    pub(crate) fn exec_b_bl(&mut self, insn: u32) -> Result<CpuExit, ArmError> {
        let op = (insn >> 31) & 1; // 0=B, 1=BL
        let imm26 = (insn & 0x03FF_FFFF) as i64;

        let offset = ((imm26 << 38) >> 36) as i64; // Sign extend and multiply by 4

        if op != 0 {
            // BL - save return address
            self.set_x(30, self.pc);
            self.btype = 0b10;
        }

        self.pc = ((self.pc as i64).wrapping_sub(4).wrapping_add(offset)) as u64;

        Ok(CpuExit::Continue)
    }
}
