//! x86_64 code generator for SMIR.
//!
//! This module lowers SMIR IR to native x86_64 machine code.

use std::collections::HashMap;

use crate::smir::flags::FlagUpdate;
use crate::smir::ir::{CallTarget, SmirBlock, SmirFunction, Terminator};
use crate::smir::ops::{OpKind, X86AluEncoding, X86OpHint, X86SsePrefix, X86VecAlign, X86VecMap};
use crate::smir::types::{
    Address, ArchReg, BlockId, Condition, DispSize, GuestAddr, MemWidth, OpWidth, ShiftOp,
    SignExtend, SrcOperand, VReg, VecElementType, VecWidth, X86Reg,
};

use super::regalloc::{PhysReg, RegAlloc, RegLocation};
use super::{CodeBuffer, LowerError, LowerResult, RelocKind, RelocTarget, Relocation, SmirLowerer};

// ============================================================================
// x86_64 Condition Codes
// ============================================================================

/// x86_64 condition codes for Jcc/SETcc/CMOVcc
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum X86Cond {
    O = 0x0,  // Overflow
    No = 0x1, // Not overflow
    B = 0x2,  // Below (unsigned <), aka C/NAE
    Ae = 0x3, // Above or equal (unsigned >=), aka NC/NB
    E = 0x4,  // Equal, aka Z
    Ne = 0x5, // Not equal, aka NZ
    Be = 0x6, // Below or equal (unsigned <=), aka NA
    A = 0x7,  // Above (unsigned >), aka NBE
    S = 0x8,  // Sign (negative)
    Ns = 0x9, // Not sign (positive or zero)
    P = 0xA,  // Parity even
    Np = 0xB, // Parity odd
    L = 0xC,  // Less (signed <), aka NGE
    Ge = 0xD, // Greater or equal (signed >=), aka NL
    Le = 0xE, // Less or equal (signed <=), aka NG
    G = 0xF,  // Greater (signed >), aka NLE
}

impl X86Cond {
    /// Convert from SMIR Condition
    pub fn from_condition(cond: Condition) -> Self {
        match cond {
            Condition::Eq => X86Cond::E,
            Condition::Ne => X86Cond::Ne,
            Condition::Ult => X86Cond::B,
            Condition::Ule => X86Cond::Be,
            Condition::Ugt => X86Cond::A,
            Condition::Uge => X86Cond::Ae,
            Condition::Slt => X86Cond::L,
            Condition::Sle => X86Cond::Le,
            Condition::Sgt => X86Cond::G,
            Condition::Sge => X86Cond::Ge,
            Condition::Negative => X86Cond::S,
            Condition::Positive => X86Cond::Ns,
            Condition::Overflow => X86Cond::O,
            Condition::NoOverflow => X86Cond::No,
            Condition::Parity => X86Cond::P,
            Condition::NoParity => X86Cond::Np,
            Condition::Always => X86Cond::E, // Shouldn't be used for conditional ops
        }
    }

    /// Invert the condition
    pub fn invert(self) -> Self {
        match self {
            X86Cond::O => X86Cond::No,
            X86Cond::No => X86Cond::O,
            X86Cond::B => X86Cond::Ae,
            X86Cond::Ae => X86Cond::B,
            X86Cond::E => X86Cond::Ne,
            X86Cond::Ne => X86Cond::E,
            X86Cond::Be => X86Cond::A,
            X86Cond::A => X86Cond::Be,
            X86Cond::S => X86Cond::Ns,
            X86Cond::Ns => X86Cond::S,
            X86Cond::P => X86Cond::Np,
            X86Cond::Np => X86Cond::P,
            X86Cond::L => X86Cond::Ge,
            X86Cond::Ge => X86Cond::L,
            X86Cond::Le => X86Cond::G,
            X86Cond::G => X86Cond::Le,
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum ShiftCount {
    One,
    Imm(u8),
    Cl,
}

#[derive(Clone, Copy, Debug)]
enum VecEncodingKind {
    Vex,
    Evex,
}

#[derive(Clone, Copy, Debug)]
struct VecEncoding {
    kind: VecEncodingKind,
    map: X86VecMap,
    pp: X86SsePrefix,
    opcode: u8,
    width: VecWidth,
}

// ============================================================================
// x86_64 Instruction Emitter
// ============================================================================

/// x86_64 instruction emitter - handles raw instruction encoding
pub struct X86Emitter<'a> {
    code: &'a mut CodeBuffer,
}

impl<'a> X86Emitter<'a> {
    pub fn new(code: &'a mut CodeBuffer) -> Self {
        Self { code }
    }

    // ========================================================================
    // REX Prefix
    // ========================================================================

    /// Emit REX prefix if needed
    /// REX = 0100WRXB where:
    /// - W: 64-bit operand size
    /// - R: ModRM.reg extension
    /// - X: SIB.index extension
    /// - B: ModRM.rm or SIB.base extension
    fn emit_rex(&mut self, w: bool, r: PhysReg, x: Option<PhysReg>, b: PhysReg) {
        let mut rex = 0x40u8;
        if w {
            rex |= 0x08;
        }
        if r.is_extended() {
            rex |= 0x04;
        }
        if x.map_or(false, |reg| reg.is_extended()) {
            rex |= 0x02;
        }
        if b.is_extended() {
            rex |= 0x01;
        }
        if rex != 0x40 {
            self.code.emit_u8(rex);
        }
    }

    fn emit_rex_force(&mut self, w: bool, r: PhysReg, x: Option<PhysReg>, b: PhysReg) {
        let mut rex = 0x40u8;
        if w {
            rex |= 0x08;
        }
        if r.is_extended() {
            rex |= 0x04;
        }
        if x.map_or(false, |reg| reg.is_extended()) {
            rex |= 0x02;
        }
        if b.is_extended() {
            rex |= 0x01;
        }
        self.code.emit_u8(rex);
    }

    /// Emit REX prefix for 64-bit operation with single register
    fn emit_rex_w(&mut self, reg: PhysReg) {
        let mut rex = 0x48u8; // REX.W
        if reg.is_extended() {
            rex |= 0x01; // REX.B
        }
        self.code.emit_u8(rex);
    }

    /// Emit REX prefix for two-register operation
    fn emit_rex_rr(&mut self, w: bool, reg: PhysReg, rm: PhysReg) {
        self.emit_rex(w, reg, None, rm);
    }

    /// Emit optional REX for width
    fn emit_rex_for_width(&mut self, width: OpWidth, r: PhysReg, rm: PhysReg) {
        match width {
            OpWidth::W64 => self.emit_rex_rr(true, r, rm),
            OpWidth::W32 => {
                // Only need REX if using extended registers
                if r.is_extended() || rm.is_extended() {
                    self.emit_rex_rr(false, r, rm);
                }
            }
            OpWidth::W16 => {
                self.code.emit_u8(0x66); // Operand size prefix
                if r.is_extended() || rm.is_extended() {
                    self.emit_rex_rr(false, r, rm);
                }
            }
            OpWidth::W8 => {
                // Need REX for SPL, BPL, SIL, DIL or extended registers
                if r.is_extended()
                    || rm.is_extended()
                    || matches!(r, PhysReg::Rsp | PhysReg::Rbp | PhysReg::Rsi | PhysReg::Rdi)
                    || matches!(
                        rm,
                        PhysReg::Rsp | PhysReg::Rbp | PhysReg::Rsi | PhysReg::Rdi
                    )
                {
                    if r.is_extended() || rm.is_extended() {
                        self.emit_rex_rr(false, r, rm);
                    } else {
                        self.emit_rex_force(false, r, None, rm);
                    }
                }
            }
            OpWidth::W128 => {
                // XMM operations handled separately
            }
        }
    }

    fn emit_rex_for_width_mem(&mut self, width: OpWidth, base: PhysReg, index: Option<PhysReg>) {
        let needs_rex = base.is_extended() || index.map_or(false, |reg| reg.is_extended());
        match width {
            OpWidth::W64 => self.emit_rex(true, PhysReg::Rax, index, base),
            OpWidth::W32 => {
                if needs_rex {
                    self.emit_rex(false, PhysReg::Rax, index, base);
                }
            }
            OpWidth::W16 => {
                self.code.emit_u8(0x66);
                if needs_rex {
                    self.emit_rex(false, PhysReg::Rax, index, base);
                }
            }
            OpWidth::W8 => {
                if needs_rex {
                    self.emit_rex(false, PhysReg::Rax, index, base);
                }
            }
            OpWidth::W128 => {}
        }
    }

    fn emit_rex_for_mem(&mut self, base: PhysReg, index: Option<PhysReg>) {
        if base.is_extended() || index.map_or(false, |reg| reg.is_extended()) {
            self.emit_rex(false, PhysReg::Rax, index, base);
        }
    }

    fn emit_rex_for_width_mem_reg(
        &mut self,
        width: OpWidth,
        reg: PhysReg,
        base: PhysReg,
        index: Option<PhysReg>,
    ) {
        let needs_rex =
            reg.is_extended() || base.is_extended() || index.map_or(false, |r| r.is_extended());
        match width {
            OpWidth::W64 => self.emit_rex(true, reg, index, base),
            OpWidth::W32 => {
                if needs_rex {
                    self.emit_rex(false, reg, index, base);
                }
            }
            OpWidth::W16 => {
                self.code.emit_u8(0x66);
                if needs_rex {
                    self.emit_rex(false, reg, index, base);
                }
            }
            OpWidth::W8 => {
                if needs_rex
                    || matches!(
                        reg,
                        PhysReg::Rsp | PhysReg::Rbp | PhysReg::Rsi | PhysReg::Rdi
                    )
                {
                    if needs_rex {
                        self.emit_rex(false, reg, index, base);
                    } else {
                        self.emit_rex_force(false, reg, index, base);
                    }
                }
            }
            OpWidth::W128 => {}
        }
    }

    fn emit_rex_for_xmm(&mut self, reg: PhysReg, rm: PhysReg) {
        if reg.is_extended() || rm.is_extended() {
            self.emit_rex(false, reg, None, rm);
        }
    }

    fn emit_rex_for_xmm_mem(&mut self, reg: PhysReg, base: PhysReg, index: Option<PhysReg>) {
        let needs_rex =
            reg.is_extended() || base.is_extended() || index.map_or(false, |r| r.is_extended());
        if needs_rex {
            self.emit_rex(false, reg, index, base);
        }
    }

    fn emit_imm_by_width(&mut self, imm: i64, width: OpWidth) {
        match width {
            OpWidth::W8 => self.code.emit_u8(imm as u8),
            OpWidth::W16 => self.code.emit_u16(imm as u16),
            OpWidth::W32 => self.code.emit_u32(imm as u32),
            OpWidth::W64 => self.code.emit_i32(imm as i32),
            OpWidth::W128 => {}
        }
    }

    // ========================================================================
    // ModR/M and SIB
    // ========================================================================

    /// Emit ModR/M byte
    /// ModR/M = mod(2) | reg(3) | rm(3)
    fn emit_modrm(&mut self, mode: u8, reg: PhysReg, rm: PhysReg) {
        let byte = (mode << 6) | (reg.low3() << 3) | rm.low3();
        self.code.emit_u8(byte);
    }

    /// Emit ModR/M for register-register operation (mod=11)
    fn emit_modrm_rr(&mut self, reg: PhysReg, rm: PhysReg) {
        self.emit_modrm(0b11, reg, rm);
    }

    /// Emit ModR/M with /digit extension
    fn emit_modrm_digit(&mut self, mode: u8, digit: u8, rm: PhysReg) {
        let byte = (mode << 6) | (digit << 3) | rm.low3();
        self.code.emit_u8(byte);
    }

    /// Emit SIB byte
    /// SIB = scale(2) | index(3) | base(3)
    fn emit_sib(&mut self, scale: u8, index: PhysReg, base: PhysReg) {
        let scale_bits = match scale {
            1 => 0b00,
            2 => 0b01,
            4 => 0b10,
            8 => 0b11,
            _ => 0b00,
        };
        let byte = (scale_bits << 6) | (index.low3() << 3) | base.low3();
        self.code.emit_u8(byte);
    }

    // ========================================================================
    // Memory Operand Encoding
    // ========================================================================

    /// Emit ModR/M and optional SIB for memory operand [base + disp]
    fn emit_modrm_mem(&mut self, reg: PhysReg, base: PhysReg, disp: i32) {
        self.emit_modrm_mem_disp(reg, base, disp, DispSize::Auto);
    }

    fn emit_modrm_mem_disp(
        &mut self,
        reg: PhysReg,
        base: PhysReg,
        disp: i32,
        disp_size: DispSize,
    ) -> Option<usize> {
        // RSP/R12 needs SIB byte
        let needs_sib = base == PhysReg::Rsp || base == PhysReg::R12;

        // RBP/R13 with no displacement needs explicit disp8=0
        let force_disp = (base == PhysReg::Rbp || base == PhysReg::R13) && disp == 0;

        let (mode, disp_bytes) = match disp_size {
            DispSize::Auto => {
                if disp == 0 && !force_disp {
                    (0b00, 0) // [base]
                } else if disp >= -128 && disp <= 127 {
                    (0b01, 1) // [base + disp8]
                } else {
                    (0b10, 4) // [base + disp32]
                }
            }
            DispSize::Disp8 => (0b01, 1),
            DispSize::Disp32 => (0b10, 4),
        };

        if needs_sib {
            self.emit_modrm(mode, reg, PhysReg::Rsp); // rm=100 signals SIB
            self.emit_sib(1, PhysReg::Rsp, base); // index=RSP means no index
        } else {
            self.emit_modrm(mode, reg, base);
        }

        let disp_offset = if disp_bytes > 0 {
            let off = self.code.position();
            match disp_bytes {
                1 => self.code.emit_i8(disp as i8),
                4 => self.code.emit_i32(disp),
                _ => {}
            }
            Some(off)
        } else {
            None
        };

        disp_offset
    }

    /// Emit ModR/M for [base + index*scale + disp]
    fn emit_modrm_sib(
        &mut self,
        reg: PhysReg,
        base: Option<PhysReg>,
        index: PhysReg,
        scale: u8,
        disp: i32,
    ) {
        self.emit_modrm_sib_disp(reg, base, index, scale, disp, DispSize::Auto);
    }

    fn emit_modrm_sib_disp(
        &mut self,
        reg: PhysReg,
        base: Option<PhysReg>,
        index: PhysReg,
        scale: u8,
        disp: i32,
        disp_size: DispSize,
    ) -> Option<usize> {
        let (mode, base_reg, disp_bytes) = match base {
            Some(b) => match disp_size {
                DispSize::Auto => {
                    if disp == 0 && b != PhysReg::Rbp && b != PhysReg::R13 {
                        (0b00, b, 0)
                    } else if disp >= -128 && disp <= 127 {
                        (0b01, b, 1)
                    } else {
                        (0b10, b, 4)
                    }
                }
                DispSize::Disp8 => (0b01, b, 1),
                DispSize::Disp32 => (0b10, b, 4),
            },
            None => (0b00, PhysReg::Rbp, 4), // disp32 only mode
        };

        self.emit_modrm(mode, reg, PhysReg::Rsp); // rm=100 signals SIB
        self.emit_sib(scale, index, base_reg);

        let disp_offset = if disp_bytes > 0 {
            let off = self.code.position();
            match disp_bytes {
                1 => self.code.emit_i8(disp as i8),
                4 => self.code.emit_i32(disp),
                _ => {}
            }
            Some(off)
        } else {
            None
        };

        disp_offset
    }

    fn emit_modrm_pcrel(&mut self, reg: PhysReg, disp: i32) -> usize {
        // mod=00, rm=101 indicates RIP-relative
        self.emit_modrm(0b00, reg, PhysReg::Rbp);
        let off = self.code.position();
        self.code.emit_i32(disp);
        off
    }

    /// Emit ModR/M for absolute address [disp32] (no base, no index)
    /// Uses SIB mode with base=RBP (101), index=RSP (100) meaning no index
    fn emit_modrm_abs(&mut self, reg: PhysReg, addr: u64) {
        // ModR/M: mod=00, rm=100 (SIB follows)
        self.emit_modrm(0b00, reg, PhysReg::Rsp); // rm=100 signals SIB
                                                  // SIB: scale=00, index=100 (none), base=101 (disp32)
        self.code.emit_u8(0x25); // scale=0, index=RSP(4), base=RBP(5)
                                 // 32-bit displacement (address)
        self.code.emit_u32(addr as u32);
    }

    // ========================================================================
    // MOV Instructions
    // ========================================================================

    /// MOV r64, r64 (or r32/r16/r8)
    pub fn emit_mov_rr(&mut self, dst: PhysReg, src: PhysReg, width: OpWidth) {
        if dst == src && width != OpWidth::W32 {
            // A same-register move is a true no-op for 8/16/64/128-bit widths,
            // but a 32-bit `mov eax, eax` ZERO-EXTENDS bits 63:32 (the canonical
            // x86-64 zero-extend idiom), so it must still be emitted.
            return;
        }

        self.emit_rex_for_width(width, src, dst);

        let opcode = match width {
            OpWidth::W8 => 0x88,
            _ => 0x89,
        };
        self.code.emit_u8(opcode);
        self.emit_modrm_rr(src, dst);
    }

    /// MOV r/m, imm using ModR/M encoding
    pub fn emit_mov_rm_imm(&mut self, dst: PhysReg, imm: i64, width: OpWidth) {
        self.emit_rex_for_width(width, PhysReg::Rax, dst);

        let opcode = match width {
            OpWidth::W8 => 0xC6,
            _ => 0xC7,
        };
        self.code.emit_u8(opcode);
        self.emit_modrm_digit(0b11, 0, dst);

        match width {
            OpWidth::W8 => self.code.emit_u8(imm as u8),
            OpWidth::W16 => self.code.emit_u16(imm as u16),
            OpWidth::W32 => self.code.emit_u32(imm as u32),
            OpWidth::W64 => self.code.emit_i32(imm as i32),
            OpWidth::W128 => {}
        }
    }

    /// MOV r64, imm64 (or r32, imm32 / etc.)
    pub fn emit_mov_ri(&mut self, dst: PhysReg, imm: i64, width: OpWidth) {
        match width {
            OpWidth::W64 => {
                if imm >= i32::MIN as i64 && imm <= i32::MAX as i64 {
                    // Use MOV r/m64, imm32 (sign-extended)
                    self.emit_rex_w(dst);
                    self.code.emit_u8(0xC7);
                    self.emit_modrm_digit(0b11, 0, dst);
                    self.code.emit_i32(imm as i32);
                } else {
                    // Full 64-bit immediate: MOV r64, imm64
                    self.emit_mov_ri_imm64(dst, imm);
                }
            }
            OpWidth::W32 => {
                if dst.is_extended() {
                    self.code.emit_u8(0x41); // REX.B
                }
                self.code.emit_u8(0xB8 + dst.low3());
                self.code.emit_u32(imm as u32);
            }
            OpWidth::W16 => {
                self.code.emit_u8(0x66); // Operand size prefix
                if dst.is_extended() {
                    self.code.emit_u8(0x41);
                }
                self.code.emit_u8(0xB8 + dst.low3());
                self.code.emit_u16(imm as u16);
            }
            OpWidth::W8 => {
                if dst.is_extended()
                    || matches!(
                        dst,
                        PhysReg::Rsp | PhysReg::Rbp | PhysReg::Rsi | PhysReg::Rdi
                    )
                {
                    self.code
                        .emit_u8(0x40 | if dst.is_extended() { 0x01 } else { 0 });
                }
                self.code.emit_u8(0xB0 + dst.low3());
                self.code.emit_u8(imm as u8);
            }
            OpWidth::W128 => {} // Not applicable
        }
    }

    /// MOV r64, imm64 (always use imm64 encoding)
    pub fn emit_mov_ri_imm64(&mut self, dst: PhysReg, imm: i64) {
        self.emit_rex_w(dst);
        self.code.emit_u8(0xB8 + dst.low3());
        self.code.emit_u64(imm as u64);
    }

    /// MOV r64, [base + disp]
    pub fn emit_mov_rm(&mut self, dst: PhysReg, base: PhysReg, disp: i32, width: OpWidth) {
        self.emit_mov_rm_disp(dst, base, disp, DispSize::Auto, width);
    }

    pub fn emit_mov_rm_disp(
        &mut self,
        dst: PhysReg,
        base: PhysReg,
        disp: i32,
        disp_size: DispSize,
        width: OpWidth,
    ) {
        self.emit_rex_for_width(width, dst, base);

        let opcode = match width {
            OpWidth::W8 => 0x8A,
            _ => 0x8B,
        };
        self.code.emit_u8(opcode);
        self.emit_modrm_mem_disp(dst, base, disp, disp_size);
    }

    pub fn emit_mov_mi_disp(
        &mut self,
        base: PhysReg,
        disp: i32,
        disp_size: DispSize,
        imm: i64,
        width: OpWidth,
    ) {
        self.emit_rex_for_width_mem(width, base, None);
        let opcode = match width {
            OpWidth::W8 => 0xC6,
            _ => 0xC7,
        };
        self.code.emit_u8(opcode);
        self.emit_modrm_mem_disp(PhysReg::Rax, base, disp, disp_size);
        self.emit_imm_by_width(imm, width);
    }

    /// MOV [base + disp], r64
    pub fn emit_mov_mr(&mut self, base: PhysReg, disp: i32, src: PhysReg, width: OpWidth) {
        self.emit_mov_mr_disp(base, disp, DispSize::Auto, src, width);
    }

    pub fn emit_mov_mr_disp(
        &mut self,
        base: PhysReg,
        disp: i32,
        disp_size: DispSize,
        src: PhysReg,
        width: OpWidth,
    ) {
        self.emit_rex_for_width(width, src, base);

        let opcode = match width {
            OpWidth::W8 => 0x88,
            _ => 0x89,
        };
        self.code.emit_u8(opcode);
        self.emit_modrm_mem_disp(src, base, disp, disp_size);
    }

    /// MOV r64, [abs32] - Load from absolute 32-bit address
    pub fn emit_mov_rm_abs(&mut self, dst: PhysReg, addr: u64, width: OpWidth) {
        // REX prefix for width and extended registers
        // Note: we use Rax as placeholder for rm since we're using SIB mode
        self.emit_rex_for_width(width, dst, PhysReg::Rax);

        let opcode = match width {
            OpWidth::W8 => 0x8A,
            _ => 0x8B,
        };
        self.code.emit_u8(opcode);
        self.emit_modrm_abs(dst, addr);
    }

    pub fn emit_mov_mi_abs(&mut self, addr: u64, imm: i64, width: OpWidth) {
        self.emit_rex_for_width_mem(width, PhysReg::Rbp, None);
        let opcode = match width {
            OpWidth::W8 => 0xC6,
            _ => 0xC7,
        };
        self.code.emit_u8(opcode);
        self.emit_modrm_abs(PhysReg::Rax, addr);
        self.emit_imm_by_width(imm, width);
    }

    /// MOV [abs32], r64 - Store to absolute 32-bit address
    pub fn emit_mov_mr_abs(&mut self, addr: u64, src: PhysReg, width: OpWidth) {
        // REX prefix for width and extended registers
        self.emit_rex_for_width(width, src, PhysReg::Rax);

        let opcode = match width {
            OpWidth::W8 => 0x88,
            _ => 0x89,
        };
        self.code.emit_u8(opcode);
        self.emit_modrm_abs(src, addr);
    }

    /// MOV r64, [base + index*scale + disp] - Load with SIB addressing
    pub fn emit_mov_rm_sib(
        &mut self,
        dst: PhysReg,
        base: Option<PhysReg>,
        index: PhysReg,
        scale: u8,
        disp: i32,
        width: OpWidth,
    ) {
        self.emit_mov_rm_sib_disp(dst, base, index, scale, disp, DispSize::Auto, width);
    }

    pub fn emit_mov_rm_sib_disp(
        &mut self,
        dst: PhysReg,
        base: Option<PhysReg>,
        index: PhysReg,
        scale: u8,
        disp: i32,
        disp_size: DispSize,
        width: OpWidth,
    ) {
        // REX prefix - use index for the rm extension bit since it's in the SIB
        let base_for_rex = base.unwrap_or(PhysReg::Rax);
        let w = width == OpWidth::W64;
        if width == OpWidth::W8
            && !dst.is_extended()
            && !base_for_rex.is_extended()
            && !index.is_extended()
            && matches!(
                dst,
                PhysReg::Rsp | PhysReg::Rbp | PhysReg::Rsi | PhysReg::Rdi
            )
        {
            self.emit_rex_force(false, dst, Some(index), base_for_rex);
        } else {
            self.emit_rex(w, dst, Some(index), base_for_rex);
        }

        let opcode = match width {
            OpWidth::W8 => 0x8A,
            _ => 0x8B,
        };
        self.code.emit_u8(opcode);
        self.emit_modrm_sib_disp(dst, base, index, scale, disp, disp_size);
    }

    pub fn emit_mov_mi_sib_disp(
        &mut self,
        base: Option<PhysReg>,
        index: PhysReg,
        scale: u8,
        disp: i32,
        disp_size: DispSize,
        imm: i64,
        width: OpWidth,
    ) {
        let base_reg = base.unwrap_or(PhysReg::Rbp);
        self.emit_rex_for_width_mem(width, base_reg, Some(index));
        let opcode = match width {
            OpWidth::W8 => 0xC6,
            _ => 0xC7,
        };
        self.code.emit_u8(opcode);
        self.emit_modrm_sib_disp(PhysReg::Rax, base, index, scale, disp, disp_size);
        self.emit_imm_by_width(imm, width);
    }

    /// MOV [base + index*scale + disp], r64 - Store with SIB addressing
    pub fn emit_mov_mr_sib(
        &mut self,
        base: Option<PhysReg>,
        index: PhysReg,
        scale: u8,
        disp: i32,
        src: PhysReg,
        width: OpWidth,
    ) {
        self.emit_mov_mr_sib_disp(base, index, scale, disp, DispSize::Auto, src, width);
    }

    pub fn emit_mov_mr_sib_disp(
        &mut self,
        base: Option<PhysReg>,
        index: PhysReg,
        scale: u8,
        disp: i32,
        disp_size: DispSize,
        src: PhysReg,
        width: OpWidth,
    ) {
        let base_for_rex = base.unwrap_or(PhysReg::Rax);
        let w = width == OpWidth::W64;
        if width == OpWidth::W8
            && !src.is_extended()
            && !base_for_rex.is_extended()
            && !index.is_extended()
            && matches!(
                src,
                PhysReg::Rsp | PhysReg::Rbp | PhysReg::Rsi | PhysReg::Rdi
            )
        {
            self.emit_rex_force(false, src, Some(index), base_for_rex);
        } else {
            self.emit_rex(w, src, Some(index), base_for_rex);
        }

        let opcode = match width {
            OpWidth::W8 => 0x88,
            _ => 0x89,
        };
        self.code.emit_u8(opcode);
        self.emit_modrm_sib_disp(src, base, index, scale, disp, disp_size);
    }

    /// MOV r64, [rip + disp32]
    pub fn emit_mov_rm_pcrel(&mut self, dst: PhysReg, disp: i32, width: OpWidth) -> usize {
        self.emit_rex_for_width(width, dst, PhysReg::Rbp);

        let opcode = match width {
            OpWidth::W8 => 0x8A,
            _ => 0x8B,
        };
        self.code.emit_u8(opcode);
        self.emit_modrm_pcrel(dst, disp)
    }

    pub fn emit_mov_mi_pcrel(&mut self, disp: i32, width: OpWidth, imm: i64) -> usize {
        self.emit_rex_for_width_mem(width, PhysReg::Rbp, None);
        let opcode = match width {
            OpWidth::W8 => 0xC6,
            _ => 0xC7,
        };
        self.code.emit_u8(opcode);
        let offset = self.emit_modrm_pcrel(PhysReg::Rax, disp);
        self.emit_imm_by_width(imm, width);
        offset
    }

    /// MOV [rip + disp32], r64
    pub fn emit_mov_mr_pcrel(&mut self, disp: i32, src: PhysReg, width: OpWidth) -> usize {
        self.emit_rex_for_width(width, src, PhysReg::Rbp);

        let opcode = match width {
            OpWidth::W8 => 0x88,
            _ => 0x89,
        };
        self.code.emit_u8(opcode);
        self.emit_modrm_pcrel(src, disp)
    }

    /// REP STOS (store AL/AX/EAX/RAX to [RDI])
    pub fn emit_rep_stos(&mut self, width: MemWidth) {
        self.code.emit_u8(0xF3); // REP prefix
        match width {
            MemWidth::B1 => {
                self.code.emit_u8(0xAA); // STOSB
            }
            MemWidth::B2 => {
                self.code.emit_u8(0x66); // Operand size override
                self.code.emit_u8(0xAB); // STOSW
            }
            MemWidth::B4 => {
                self.code.emit_u8(0xAB); // STOSD
            }
            MemWidth::B8 => {
                self.code.emit_u8(0x48); // REX.W
                self.code.emit_u8(0xAB); // STOSQ
            }
            MemWidth::B16 | MemWidth::B32 | MemWidth::B64 => {}
        }
    }

    /// REP MOVS (move [RSI] -> [RDI])
    pub fn emit_rep_movs(&mut self, width: MemWidth) {
        self.code.emit_u8(0xF3); // REP prefix
        match width {
            MemWidth::B1 => {
                self.code.emit_u8(0xA4); // MOVSB
            }
            MemWidth::B2 => {
                self.code.emit_u8(0x66); // Operand size override
                self.code.emit_u8(0xA5); // MOVSW
            }
            MemWidth::B4 => {
                self.code.emit_u8(0xA5); // MOVSD
            }
            MemWidth::B8 => {
                self.code.emit_u8(0x48); // REX.W
                self.code.emit_u8(0xA5); // MOVSQ
            }
            MemWidth::B16 | MemWidth::B32 | MemWidth::B64 => {}
        }
    }

    /// MOVZX r64, r/m8 or r/m16
    pub fn emit_movzx(
        &mut self,
        dst: PhysReg,
        src: PhysReg,
        src_width: OpWidth,
        dst_width: OpWidth,
    ) {
        self.emit_rex_for_width(dst_width, dst, src);

        match src_width {
            OpWidth::W8 => {
                self.code.emit_u8(0x0F);
                self.code.emit_u8(0xB6);
            }
            OpWidth::W16 => {
                self.code.emit_u8(0x0F);
                self.code.emit_u8(0xB7);
            }
            _ => {} // 32-bit zero-extends automatically to 64-bit
        }
        self.emit_modrm_rr(dst, src);
    }

    /// MOVSX r64, r/m8 or r/m16 or r/m32
    pub fn emit_movsx(
        &mut self,
        dst: PhysReg,
        src: PhysReg,
        src_width: OpWidth,
        dst_width: OpWidth,
    ) {
        self.emit_rex_for_width(dst_width, dst, src);

        match src_width {
            OpWidth::W8 => {
                self.code.emit_u8(0x0F);
                self.code.emit_u8(0xBE);
            }
            OpWidth::W16 => {
                self.code.emit_u8(0x0F);
                self.code.emit_u8(0xBF);
            }
            OpWidth::W32 => {
                // MOVSXD r64, r/m32
                self.code.emit_u8(0x63);
            }
            _ => {}
        }
        self.emit_modrm_rr(dst, src);
    }

    pub fn emit_movzx_rm_disp(
        &mut self,
        dst: PhysReg,
        base: PhysReg,
        disp: i32,
        disp_size: DispSize,
        src_width: OpWidth,
        dst_width: OpWidth,
    ) {
        if src_width == OpWidth::W32 {
            self.emit_rex_for_width_mem_reg(OpWidth::W32, dst, base, None);
            self.code.emit_u8(0x8B);
            self.emit_modrm_mem_disp(dst, base, disp, disp_size);
            return;
        }

        self.emit_rex_for_width_mem_reg(dst_width, dst, base, None);
        match src_width {
            OpWidth::W8 => {
                self.code.emit_u8(0x0F);
                self.code.emit_u8(0xB6);
            }
            OpWidth::W16 => {
                self.code.emit_u8(0x0F);
                self.code.emit_u8(0xB7);
            }
            _ => {}
        }
        self.emit_modrm_mem_disp(dst, base, disp, disp_size);
    }

    pub fn emit_movzx_rm_sib_disp(
        &mut self,
        dst: PhysReg,
        base: Option<PhysReg>,
        index: PhysReg,
        scale: u8,
        disp: i32,
        disp_size: DispSize,
        src_width: OpWidth,
        dst_width: OpWidth,
    ) {
        let base_reg = base.unwrap_or(PhysReg::Rbp);
        if src_width == OpWidth::W32 {
            self.emit_rex_for_width_mem_reg(OpWidth::W32, dst, base_reg, Some(index));
            self.code.emit_u8(0x8B);
            self.emit_modrm_sib_disp(dst, base, index, scale, disp, disp_size);
            return;
        }

        self.emit_rex_for_width_mem_reg(dst_width, dst, base_reg, Some(index));
        match src_width {
            OpWidth::W8 => {
                self.code.emit_u8(0x0F);
                self.code.emit_u8(0xB6);
            }
            OpWidth::W16 => {
                self.code.emit_u8(0x0F);
                self.code.emit_u8(0xB7);
            }
            _ => {}
        }
        self.emit_modrm_sib_disp(dst, base, index, scale, disp, disp_size);
    }

    pub fn emit_movzx_rm_abs(
        &mut self,
        dst: PhysReg,
        addr: u64,
        src_width: OpWidth,
        dst_width: OpWidth,
    ) {
        if src_width == OpWidth::W32 {
            self.emit_rex_for_width(OpWidth::W32, dst, PhysReg::Rax);
            self.code.emit_u8(0x8B);
            self.emit_modrm_abs(dst, addr);
            return;
        }

        self.emit_rex_for_width(dst_width, dst, PhysReg::Rax);
        match src_width {
            OpWidth::W8 => {
                self.code.emit_u8(0x0F);
                self.code.emit_u8(0xB6);
            }
            OpWidth::W16 => {
                self.code.emit_u8(0x0F);
                self.code.emit_u8(0xB7);
            }
            _ => {}
        }
        self.emit_modrm_abs(dst, addr);
    }

    pub fn emit_movzx_rm_pcrel(
        &mut self,
        dst: PhysReg,
        disp: i32,
        src_width: OpWidth,
        dst_width: OpWidth,
    ) -> usize {
        if src_width == OpWidth::W32 {
            self.emit_rex_for_width(OpWidth::W32, dst, PhysReg::Rbp);
            self.code.emit_u8(0x8B);
            return self.emit_modrm_pcrel(dst, disp);
        }

        self.emit_rex_for_width(dst_width, dst, PhysReg::Rbp);
        match src_width {
            OpWidth::W8 => {
                self.code.emit_u8(0x0F);
                self.code.emit_u8(0xB6);
            }
            OpWidth::W16 => {
                self.code.emit_u8(0x0F);
                self.code.emit_u8(0xB7);
            }
            _ => {}
        }
        self.emit_modrm_pcrel(dst, disp)
    }

    pub fn emit_movsx_rm_disp(
        &mut self,
        dst: PhysReg,
        base: PhysReg,
        disp: i32,
        disp_size: DispSize,
        src_width: OpWidth,
        dst_width: OpWidth,
    ) {
        self.emit_rex_for_width_mem_reg(dst_width, dst, base, None);
        match src_width {
            OpWidth::W8 => {
                self.code.emit_u8(0x0F);
                self.code.emit_u8(0xBE);
            }
            OpWidth::W16 => {
                self.code.emit_u8(0x0F);
                self.code.emit_u8(0xBF);
            }
            OpWidth::W32 => {
                self.code.emit_u8(0x63);
            }
            _ => {}
        }
        self.emit_modrm_mem_disp(dst, base, disp, disp_size);
    }

    pub fn emit_movsx_rm_sib_disp(
        &mut self,
        dst: PhysReg,
        base: Option<PhysReg>,
        index: PhysReg,
        scale: u8,
        disp: i32,
        disp_size: DispSize,
        src_width: OpWidth,
        dst_width: OpWidth,
    ) {
        let base_reg = base.unwrap_or(PhysReg::Rbp);
        self.emit_rex_for_width_mem_reg(dst_width, dst, base_reg, Some(index));
        match src_width {
            OpWidth::W8 => {
                self.code.emit_u8(0x0F);
                self.code.emit_u8(0xBE);
            }
            OpWidth::W16 => {
                self.code.emit_u8(0x0F);
                self.code.emit_u8(0xBF);
            }
            OpWidth::W32 => {
                self.code.emit_u8(0x63);
            }
            _ => {}
        }
        self.emit_modrm_sib_disp(dst, base, index, scale, disp, disp_size);
    }

    pub fn emit_movsx_rm_abs(
        &mut self,
        dst: PhysReg,
        addr: u64,
        src_width: OpWidth,
        dst_width: OpWidth,
    ) {
        self.emit_rex_for_width(dst_width, dst, PhysReg::Rax);
        match src_width {
            OpWidth::W8 => {
                self.code.emit_u8(0x0F);
                self.code.emit_u8(0xBE);
            }
            OpWidth::W16 => {
                self.code.emit_u8(0x0F);
                self.code.emit_u8(0xBF);
            }
            OpWidth::W32 => {
                self.code.emit_u8(0x63);
            }
            _ => {}
        }
        self.emit_modrm_abs(dst, addr);
    }

    pub fn emit_movsx_rm_pcrel(
        &mut self,
        dst: PhysReg,
        disp: i32,
        src_width: OpWidth,
        dst_width: OpWidth,
    ) -> usize {
        self.emit_rex_for_width(dst_width, dst, PhysReg::Rbp);
        match src_width {
            OpWidth::W8 => {
                self.code.emit_u8(0x0F);
                self.code.emit_u8(0xBE);
            }
            OpWidth::W16 => {
                self.code.emit_u8(0x0F);
                self.code.emit_u8(0xBF);
            }
            OpWidth::W32 => {
                self.code.emit_u8(0x63);
            }
            _ => {}
        }
        self.emit_modrm_pcrel(dst, disp)
    }

    pub fn emit_sse_mov_rr(&mut self, prefix: Option<u8>, opcode: u8, reg: PhysReg, rm: PhysReg) {
        if let Some(prefix) = prefix {
            self.code.emit_u8(prefix);
        }
        self.emit_rex_for_xmm(reg, rm);
        self.code.emit_u8(0x0F);
        self.code.emit_u8(opcode);
        self.emit_modrm_rr(reg, rm);
    }

    pub fn emit_sse_mov_rm_disp(
        &mut self,
        prefix: Option<u8>,
        opcode: u8,
        reg: PhysReg,
        base: PhysReg,
        disp: i32,
        disp_size: DispSize,
    ) {
        if let Some(prefix) = prefix {
            self.code.emit_u8(prefix);
        }
        self.emit_rex_for_xmm_mem(reg, base, None);
        self.code.emit_u8(0x0F);
        self.code.emit_u8(opcode);
        self.emit_modrm_mem_disp(reg, base, disp, disp_size);
    }

    pub fn emit_sse_mov_rm_sib_disp(
        &mut self,
        prefix: Option<u8>,
        opcode: u8,
        reg: PhysReg,
        base: Option<PhysReg>,
        index: PhysReg,
        scale: u8,
        disp: i32,
        disp_size: DispSize,
    ) {
        let base_reg = base.unwrap_or(PhysReg::Rbp);
        if let Some(prefix) = prefix {
            self.code.emit_u8(prefix);
        }
        self.emit_rex_for_xmm_mem(reg, base_reg, Some(index));
        self.code.emit_u8(0x0F);
        self.code.emit_u8(opcode);
        self.emit_modrm_sib_disp(reg, base, index, scale, disp, disp_size);
    }

    pub fn emit_sse_mov_rm_abs(&mut self, prefix: Option<u8>, opcode: u8, reg: PhysReg, addr: u64) {
        if let Some(prefix) = prefix {
            self.code.emit_u8(prefix);
        }
        self.emit_rex_for_xmm(reg, PhysReg::Rax);
        self.code.emit_u8(0x0F);
        self.code.emit_u8(opcode);
        self.emit_modrm_abs(reg, addr);
    }

    pub fn emit_sse_mov_rm_pcrel(
        &mut self,
        prefix: Option<u8>,
        opcode: u8,
        reg: PhysReg,
        disp: i32,
    ) -> usize {
        if let Some(prefix) = prefix {
            self.code.emit_u8(prefix);
        }
        self.emit_rex_for_xmm(reg, PhysReg::Rbp);
        self.code.emit_u8(0x0F);
        self.code.emit_u8(opcode);
        self.emit_modrm_pcrel(reg, disp)
    }

    pub fn emit_sse_op38_rr(&mut self, prefix: Option<u8>, opcode: u8, reg: PhysReg, rm: PhysReg) {
        if let Some(prefix) = prefix {
            self.code.emit_u8(prefix);
        }
        self.emit_rex_for_xmm(reg, rm);
        self.code.emit_u8(0x0F);
        self.code.emit_u8(0x38);
        self.code.emit_u8(opcode);
        self.emit_modrm_rr(reg, rm);
    }

    pub fn emit_sse_op38_rm_disp(
        &mut self,
        prefix: Option<u8>,
        opcode: u8,
        reg: PhysReg,
        base: PhysReg,
        disp: i32,
        disp_size: DispSize,
    ) {
        if let Some(prefix) = prefix {
            self.code.emit_u8(prefix);
        }
        self.emit_rex_for_xmm_mem(reg, base, None);
        self.code.emit_u8(0x0F);
        self.code.emit_u8(0x38);
        self.code.emit_u8(opcode);
        self.emit_modrm_mem_disp(reg, base, disp, disp_size);
    }

    pub fn emit_sse_op38_rm_sib_disp(
        &mut self,
        prefix: Option<u8>,
        opcode: u8,
        reg: PhysReg,
        base: Option<PhysReg>,
        index: PhysReg,
        scale: u8,
        disp: i32,
        disp_size: DispSize,
    ) {
        let base_reg = base.unwrap_or(PhysReg::Rbp);
        if let Some(prefix) = prefix {
            self.code.emit_u8(prefix);
        }
        self.emit_rex_for_xmm_mem(reg, base_reg, Some(index));
        self.code.emit_u8(0x0F);
        self.code.emit_u8(0x38);
        self.code.emit_u8(opcode);
        self.emit_modrm_sib_disp(reg, base, index, scale, disp, disp_size);
    }

    pub fn emit_sse_op38_rm_abs(
        &mut self,
        prefix: Option<u8>,
        opcode: u8,
        reg: PhysReg,
        addr: u64,
    ) {
        if let Some(prefix) = prefix {
            self.code.emit_u8(prefix);
        }
        self.emit_rex_for_xmm(reg, PhysReg::Rax);
        self.code.emit_u8(0x0F);
        self.code.emit_u8(0x38);
        self.code.emit_u8(opcode);
        self.emit_modrm_abs(reg, addr);
    }

    pub fn emit_sse_op38_rm_pcrel(
        &mut self,
        prefix: Option<u8>,
        opcode: u8,
        reg: PhysReg,
        disp: i32,
    ) -> usize {
        if let Some(prefix) = prefix {
            self.code.emit_u8(prefix);
        }
        self.emit_rex_for_xmm(reg, PhysReg::Rbp);
        self.code.emit_u8(0x0F);
        self.code.emit_u8(0x38);
        self.code.emit_u8(opcode);
        self.emit_modrm_pcrel(reg, disp)
    }

    fn vex_pp_bits(pp: X86SsePrefix) -> u8 {
        match pp {
            X86SsePrefix::None => 0,
            X86SsePrefix::OpSize => 1,
            X86SsePrefix::Rep => 2,
            X86SsePrefix::Repne => 3,
        }
    }

    fn vex_map_bits(map: X86VecMap) -> u8 {
        match map {
            X86VecMap::Map0F => 0x01,
            X86VecMap::Map0F38 => 0x02,
            X86VecMap::Map0F3A => 0x03,
        }
    }

    fn emit_vex_prefix(
        &mut self,
        map: X86VecMap,
        pp: X86SsePrefix,
        width: VecWidth,
        w: bool,
        r: u8,
        x: u8,
        b: u8,
        vvvv: u8,
    ) {
        let l_bit = match width {
            VecWidth::V256 => 1,
            _ => 0,
        };
        let pp_bits = Self::vex_pp_bits(pp);
        let vvvv_inv = (!vvvv) & 0x0F;
        let r_inv = if r != 0 { 0 } else { 1 };
        let x_inv = if x != 0 { 0 } else { 1 };
        let b_inv = if b != 0 { 0 } else { 1 };

        if map == X86VecMap::Map0F && !w && x == 0 && b == 0 {
            self.code.emit_u8(0xC5);
            let byte2 = (r_inv << 7) | (vvvv_inv << 3) | (l_bit << 2) | pp_bits;
            self.code.emit_u8(byte2);
        } else {
            self.code.emit_u8(0xC4);
            let map_bits = Self::vex_map_bits(map) & 0x1F;
            let byte2 = (r_inv << 7) | (x_inv << 6) | (b_inv << 5) | map_bits;
            let byte3 = ((w as u8) << 7) | (vvvv_inv << 3) | (l_bit << 2) | pp_bits;
            self.code.emit_u8(byte2);
            self.code.emit_u8(byte3);
        }
    }

    fn emit_evex_prefix(
        &mut self,
        map: X86VecMap,
        pp: X86SsePrefix,
        width: VecWidth,
        w: bool,
        r: u8,
        x: u8,
        b: u8,
        r2: u8,
        x2: u8,
        b2: u8,
        vvvv: u8,
    ) {
        let pp_bits = Self::vex_pp_bits(pp);
        let vvvv_low = vvvv & 0x0F;
        let vvvv_high = (vvvv >> 4) & 0x01;
        let vvvv_inv = (!vvvv_low) & 0x0F;
        let vprime_inv = if vvvv_high != 0 { 0 } else { 1 };
        let r_inv = if r != 0 { 0 } else { 1 };
        let x_inv = if x != 0 { 0 } else { 1 };
        let b_inv = if b != 0 { 0 } else { 1 };
        let r2_inv = if r2 != 0 { 0 } else { 1 };
        let x2_inv = if x2 != 0 { 0 } else { 1 };
        let b2_inv = if b2 != 0 { 0 } else { 1 };

        let l_bits = match width {
            VecWidth::V128 => 0,
            VecWidth::V256 => 1,
            VecWidth::V512 => 2,
            VecWidth::V64 => 0,
        };

        self.code.emit_u8(0x62);
        let map_bits = Self::vex_map_bits(map) & 0x0F;
        let byte2 = (r2_inv << 7) | (x2_inv << 6) | (b2_inv << 5) | (r_inv << 4) | map_bits;
        let byte3 = ((w as u8) << 7) | (vvvv_inv << 3) | 0x04 | pp_bits;
        let byte4 = (l_bits << 5) | (vprime_inv << 3);
        self.code.emit_u8(byte2);
        self.code.emit_u8(byte3);
        self.code.emit_u8(byte4);
    }

    pub fn emit_vex_rrr(
        &mut self,
        map: X86VecMap,
        pp: X86SsePrefix,
        width: VecWidth,
        opcode: u8,
        dst: PhysReg,
        src1: PhysReg,
        src2: PhysReg,
    ) {
        let r = dst.vec_ext();
        let b = src2.vec_ext();
        let vvvv = src1.encoding() & 0x1F;
        self.emit_vex_prefix(map, pp, width, false, r, 0, b, vvvv);
        self.code.emit_u8(opcode);
        self.emit_modrm_rr(dst, src2);
    }

    pub fn emit_evex_rrr(
        &mut self,
        map: X86VecMap,
        pp: X86SsePrefix,
        width: VecWidth,
        opcode: u8,
        dst: PhysReg,
        src1: PhysReg,
        src2: PhysReg,
    ) {
        let r = dst.vec_ext();
        let r2 = dst.vec_ext2();
        let b = src2.vec_ext();
        let b2 = src2.vec_ext2();
        let vvvv = src1.encoding() & 0x1F;
        self.emit_evex_prefix(map, pp, width, false, r, 0, b, r2, 0, b2, vvvv);
        self.code.emit_u8(opcode);
        self.emit_modrm_rr(dst, src2);
    }

    // ========================================================================
    // ALU Instructions (two-operand)
    // ========================================================================

    /// Generic ALU r/m, r instruction
    fn emit_alu_rr(&mut self, opcode: u8, dst: PhysReg, src: PhysReg, width: OpWidth) {
        self.emit_rex_for_width(width, src, dst);

        let op = match width {
            OpWidth::W8 => opcode,
            _ => opcode + 1,
        };
        self.code.emit_u8(op);
        self.emit_modrm_rr(src, dst);
    }

    fn emit_alu_rr_dir(
        &mut self,
        opcode: u8,
        dst: PhysReg,
        src: PhysReg,
        width: OpWidth,
        encoding: X86AluEncoding,
    ) {
        if encoding == X86AluEncoding::RegRm {
            self.emit_rex_for_width(width, dst, src);
            let op = match width {
                OpWidth::W8 => opcode + 2,
                _ => opcode + 3,
            };
            self.code.emit_u8(op);
            self.emit_modrm_rr(dst, src);
        } else {
            self.emit_alu_rr(opcode, dst, src, width);
        }
    }

    fn alu_op_byte(opcode: u8, width: OpWidth, encoding: X86AluEncoding) -> u8 {
        match width {
            OpWidth::W8 => match encoding {
                X86AluEncoding::RegRm => opcode + 2,
                _ => opcode,
            },
            _ => match encoding {
                X86AluEncoding::RegRm => opcode + 3,
                _ => opcode + 1,
            },
        }
    }

    fn emit_alu_mem_disp(
        &mut self,
        opcode: u8,
        reg: PhysReg,
        base: PhysReg,
        disp: i32,
        disp_size: DispSize,
        width: OpWidth,
        encoding: X86AluEncoding,
    ) {
        self.emit_rex_for_width_mem_reg(width, reg, base, None);
        let op = Self::alu_op_byte(opcode, width, encoding);
        self.code.emit_u8(op);
        self.emit_modrm_mem_disp(reg, base, disp, disp_size);
    }

    fn emit_alu_mem_sib_disp(
        &mut self,
        opcode: u8,
        reg: PhysReg,
        base: Option<PhysReg>,
        index: PhysReg,
        scale: u8,
        disp: i32,
        disp_size: DispSize,
        width: OpWidth,
        encoding: X86AluEncoding,
    ) {
        let base_reg = base.unwrap_or(PhysReg::Rbp);
        self.emit_rex_for_width_mem_reg(width, reg, base_reg, Some(index));
        let op = Self::alu_op_byte(opcode, width, encoding);
        self.code.emit_u8(op);
        self.emit_modrm_sib_disp(reg, base, index, scale, disp, disp_size);
    }

    fn emit_alu_mem_abs(
        &mut self,
        opcode: u8,
        reg: PhysReg,
        addr: u64,
        width: OpWidth,
        encoding: X86AluEncoding,
    ) {
        self.emit_rex_for_width_mem_reg(width, reg, PhysReg::Rbp, None);
        let op = Self::alu_op_byte(opcode, width, encoding);
        self.code.emit_u8(op);
        self.emit_modrm_abs(reg, addr);
    }

    fn emit_alu_mem_pcrel(
        &mut self,
        opcode: u8,
        reg: PhysReg,
        disp: i32,
        width: OpWidth,
        encoding: X86AluEncoding,
    ) -> usize {
        self.emit_rex_for_width_mem_reg(width, reg, PhysReg::Rbp, None);
        let op = Self::alu_op_byte(opcode, width, encoding);
        self.code.emit_u8(op);
        self.emit_modrm_pcrel(reg, disp)
    }

    /// Generic ALU r/m, imm instruction
    fn emit_alu_ri(&mut self, digit: u8, dst: PhysReg, imm: i64, width: OpWidth) {
        self.emit_rex_for_width(width, PhysReg::Rax, dst);

        match width {
            OpWidth::W8 => {
                self.code.emit_u8(0x80);
                self.emit_modrm_digit(0b11, digit, dst);
                self.code.emit_u8(imm as u8);
            }
            _ => {
                if imm >= -128 && imm <= 127 {
                    // Use sign-extended imm8
                    self.code.emit_u8(0x83);
                    self.emit_modrm_digit(0b11, digit, dst);
                    self.code.emit_i8(imm as i8);
                } else {
                    self.code.emit_u8(0x81);
                    self.emit_modrm_digit(0b11, digit, dst);
                    // Immediate width follows the operand: 16-bit op (0x66
                    // prefix) takes imm16, else imm32 (sign-extended for 64-bit).
                    // Emitting imm32 for a W16 op left 2 stray bytes that the CPU
                    // decoded as a separate instruction (`add [rax],al`).
                    if width == OpWidth::W16 {
                        self.code.emit_u16(imm as u16);
                    } else {
                        self.code.emit_i32(imm as i32);
                    }
                }
            }
        }
    }

    fn digit_reg(digit: u8) -> PhysReg {
        match digit & 0x7 {
            0 => PhysReg::Rax,
            1 => PhysReg::Rcx,
            2 => PhysReg::Rdx,
            3 => PhysReg::Rbx,
            4 => PhysReg::Rsp,
            5 => PhysReg::Rbp,
            6 => PhysReg::Rsi,
            _ => PhysReg::Rdi,
        }
    }

    fn emit_alu_mi_disp(
        &mut self,
        digit: u8,
        base: PhysReg,
        disp: i32,
        disp_size: DispSize,
        imm: i64,
        width: OpWidth,
    ) {
        self.emit_rex_for_width_mem(width, base, None);
        let reg = Self::digit_reg(digit);
        let use_imm8 = width != OpWidth::W8 && imm >= -128 && imm <= 127;
        let opcode = if width == OpWidth::W8 {
            0x80
        } else if use_imm8 {
            0x83
        } else {
            0x81
        };
        self.code.emit_u8(opcode);
        self.emit_modrm_mem_disp(reg, base, disp, disp_size);
        if width == OpWidth::W8 || use_imm8 {
            self.code.emit_i8(imm as i8);
        } else if width == OpWidth::W16 {
            self.code.emit_u16(imm as u16);
        } else {
            self.code.emit_i32(imm as i32);
        }
    }

    fn emit_alu_mi_sib_disp(
        &mut self,
        digit: u8,
        base: Option<PhysReg>,
        index: PhysReg,
        scale: u8,
        disp: i32,
        disp_size: DispSize,
        imm: i64,
        width: OpWidth,
    ) {
        let base_reg = base.unwrap_or(PhysReg::Rbp);
        self.emit_rex_for_width_mem(width, base_reg, Some(index));
        let reg = Self::digit_reg(digit);
        let use_imm8 = width != OpWidth::W8 && imm >= -128 && imm <= 127;
        let opcode = if width == OpWidth::W8 {
            0x80
        } else if use_imm8 {
            0x83
        } else {
            0x81
        };
        self.code.emit_u8(opcode);
        self.emit_modrm_sib_disp(reg, base, index, scale, disp, disp_size);
        if width == OpWidth::W8 || use_imm8 {
            self.code.emit_i8(imm as i8);
        } else if width == OpWidth::W16 {
            self.code.emit_u16(imm as u16);
        } else {
            self.code.emit_i32(imm as i32);
        }
    }

    fn emit_alu_mi_abs(&mut self, digit: u8, addr: u64, imm: i64, width: OpWidth) {
        self.emit_rex_for_width_mem(width, PhysReg::Rbp, None);
        let reg = Self::digit_reg(digit);
        let use_imm8 = width != OpWidth::W8 && imm >= -128 && imm <= 127;
        let opcode = if width == OpWidth::W8 {
            0x80
        } else if use_imm8 {
            0x83
        } else {
            0x81
        };
        self.code.emit_u8(opcode);
        self.emit_modrm_abs(reg, addr);
        if width == OpWidth::W8 || use_imm8 {
            self.code.emit_i8(imm as i8);
        } else if width == OpWidth::W16 {
            self.code.emit_u16(imm as u16);
        } else {
            self.code.emit_i32(imm as i32);
        }
    }

    fn emit_alu_mi_pcrel(&mut self, digit: u8, disp: i32, imm: i64, width: OpWidth) -> usize {
        self.emit_rex_for_width_mem(width, PhysReg::Rbp, None);
        let reg = Self::digit_reg(digit);
        let use_imm8 = width != OpWidth::W8 && imm >= -128 && imm <= 127;
        let opcode = if width == OpWidth::W8 {
            0x80
        } else if use_imm8 {
            0x83
        } else {
            0x81
        };
        self.code.emit_u8(opcode);
        let offset = self.emit_modrm_pcrel(reg, disp);
        if width == OpWidth::W8 || use_imm8 {
            self.code.emit_i8(imm as i8);
        } else if width == OpWidth::W16 {
            self.code.emit_u16(imm as u16);
        } else {
            self.code.emit_i32(imm as i32);
        }
        offset
    }

    fn emit_alu_acc_imm(&mut self, opcode: u8, imm: i64, width: OpWidth) {
        match width {
            OpWidth::W8 => {
                self.code.emit_u8(opcode);
                self.code.emit_u8(imm as u8);
            }
            OpWidth::W16 => {
                self.code.emit_u8(0x66);
                self.code.emit_u8(opcode + 1);
                self.code.emit_u16(imm as u16);
            }
            OpWidth::W32 => {
                self.code.emit_u8(opcode + 1);
                self.code.emit_u32(imm as u32);
            }
            OpWidth::W64 => {
                self.emit_rex_w(PhysReg::Rax);
                self.code.emit_u8(opcode + 1);
                self.code.emit_i32(imm as i32);
            }
            OpWidth::W128 => {}
        }
    }

    /// ADD r/m, r
    pub fn emit_add_rr(&mut self, dst: PhysReg, src: PhysReg, width: OpWidth) {
        self.emit_alu_rr(0x00, dst, src, width);
    }

    /// ADD r/m, imm
    pub fn emit_add_ri(&mut self, dst: PhysReg, imm: i64, width: OpWidth) {
        self.emit_alu_ri(0, dst, imm, width);
    }

    /// SUB r/m, r
    pub fn emit_sub_rr(&mut self, dst: PhysReg, src: PhysReg, width: OpWidth) {
        self.emit_alu_rr(0x28, dst, src, width);
    }

    /// SUB r/m, imm
    pub fn emit_sub_ri(&mut self, dst: PhysReg, imm: i64, width: OpWidth) {
        self.emit_alu_ri(5, dst, imm, width);
    }

    /// ADC r/m, r (add with carry)
    pub fn emit_adc_rr(&mut self, dst: PhysReg, src: PhysReg, width: OpWidth) {
        self.emit_alu_rr(0x10, dst, src, width);
    }

    /// ADC r/m, imm
    pub fn emit_adc_ri(&mut self, dst: PhysReg, imm: i64, width: OpWidth) {
        self.emit_alu_ri(2, dst, imm, width);
    }

    /// SBB r/m, r (subtract with borrow)
    pub fn emit_sbb_rr(&mut self, dst: PhysReg, src: PhysReg, width: OpWidth) {
        self.emit_alu_rr(0x18, dst, src, width);
    }

    /// SBB r/m, imm
    pub fn emit_sbb_ri(&mut self, dst: PhysReg, imm: i64, width: OpWidth) {
        self.emit_alu_ri(3, dst, imm, width);
    }

    /// AND r/m, r
    pub fn emit_and_rr(&mut self, dst: PhysReg, src: PhysReg, width: OpWidth) {
        self.emit_alu_rr(0x20, dst, src, width);
    }

    /// AND r/m, imm
    pub fn emit_and_ri(&mut self, dst: PhysReg, imm: i64, width: OpWidth) {
        self.emit_alu_ri(4, dst, imm, width);
    }

    /// OR r/m, r
    pub fn emit_or_rr(&mut self, dst: PhysReg, src: PhysReg, width: OpWidth) {
        self.emit_alu_rr(0x08, dst, src, width);
    }

    /// OR r/m, imm
    pub fn emit_or_ri(&mut self, dst: PhysReg, imm: i64, width: OpWidth) {
        self.emit_alu_ri(1, dst, imm, width);
    }

    /// XOR r/m, r
    pub fn emit_xor_rr(&mut self, dst: PhysReg, src: PhysReg, width: OpWidth) {
        self.emit_alu_rr(0x30, dst, src, width);
    }

    /// XOR r/m, imm
    pub fn emit_xor_ri(&mut self, dst: PhysReg, imm: i64, width: OpWidth) {
        self.emit_alu_ri(6, dst, imm, width);
    }

    /// CMP r/m, r
    pub fn emit_cmp_rr(&mut self, op1: PhysReg, op2: PhysReg, width: OpWidth) {
        self.emit_alu_rr(0x38, op1, op2, width);
    }

    /// CMP r/m, imm
    pub fn emit_cmp_ri(&mut self, op1: PhysReg, imm: i64, width: OpWidth) {
        self.emit_alu_ri(7, op1, imm, width);
    }

    /// TEST r/m, r
    pub fn emit_test_rr(&mut self, op1: PhysReg, op2: PhysReg, width: OpWidth) {
        self.emit_rex_for_width(width, op2, op1);

        let opcode = match width {
            OpWidth::W8 => 0x84,
            _ => 0x85,
        };
        self.code.emit_u8(opcode);
        self.emit_modrm_rr(op2, op1);
    }

    /// TEST r/m, imm
    pub fn emit_test_ri(&mut self, op1: PhysReg, imm: i64, width: OpWidth) {
        self.emit_rex_for_width(width, PhysReg::Rax, op1);

        match width {
            OpWidth::W8 => {
                self.code.emit_u8(0xF6);
                self.emit_modrm_digit(0b11, 0, op1);
                self.code.emit_u8(imm as u8);
            }
            _ => {
                self.code.emit_u8(0xF7);
                self.emit_modrm_digit(0b11, 0, op1);
                self.code.emit_i32(imm as i32);
            }
        }
    }

    pub fn emit_test_mr_disp(
        &mut self,
        base: PhysReg,
        disp: i32,
        disp_size: DispSize,
        reg: PhysReg,
        width: OpWidth,
    ) {
        self.emit_rex_for_width_mem_reg(width, reg, base, None);
        let opcode = match width {
            OpWidth::W8 => 0x84,
            _ => 0x85,
        };
        self.code.emit_u8(opcode);
        self.emit_modrm_mem_disp(reg, base, disp, disp_size);
    }

    pub fn emit_test_mr_sib_disp(
        &mut self,
        base: Option<PhysReg>,
        index: PhysReg,
        scale: u8,
        disp: i32,
        disp_size: DispSize,
        reg: PhysReg,
        width: OpWidth,
    ) {
        let base_reg = base.unwrap_or(PhysReg::Rbp);
        self.emit_rex_for_width_mem_reg(width, reg, base_reg, Some(index));
        let opcode = match width {
            OpWidth::W8 => 0x84,
            _ => 0x85,
        };
        self.code.emit_u8(opcode);
        self.emit_modrm_sib_disp(reg, base, index, scale, disp, disp_size);
    }

    pub fn emit_test_mr_abs(&mut self, addr: u64, reg: PhysReg, width: OpWidth) {
        self.emit_rex_for_width_mem_reg(width, reg, PhysReg::Rbp, None);
        let opcode = match width {
            OpWidth::W8 => 0x84,
            _ => 0x85,
        };
        self.code.emit_u8(opcode);
        self.emit_modrm_abs(reg, addr);
    }

    pub fn emit_test_mr_pcrel(&mut self, disp: i32, reg: PhysReg, width: OpWidth) -> usize {
        self.emit_rex_for_width_mem_reg(width, reg, PhysReg::Rbp, None);
        let opcode = match width {
            OpWidth::W8 => 0x84,
            _ => 0x85,
        };
        self.code.emit_u8(opcode);
        self.emit_modrm_pcrel(reg, disp)
    }

    pub fn emit_test_mi_disp(
        &mut self,
        base: PhysReg,
        disp: i32,
        disp_size: DispSize,
        imm: i64,
        width: OpWidth,
    ) {
        self.emit_rex_for_width_mem(width, base, None);
        let opcode = match width {
            OpWidth::W8 => 0xF6,
            _ => 0xF7,
        };
        self.code.emit_u8(opcode);
        self.emit_modrm_mem_disp(PhysReg::Rax, base, disp, disp_size);
        self.emit_imm_by_width(imm, width);
    }

    pub fn emit_test_mi_sib_disp(
        &mut self,
        base: Option<PhysReg>,
        index: PhysReg,
        scale: u8,
        disp: i32,
        disp_size: DispSize,
        imm: i64,
        width: OpWidth,
    ) {
        let base_reg = base.unwrap_or(PhysReg::Rbp);
        self.emit_rex_for_width_mem(width, base_reg, Some(index));
        let opcode = match width {
            OpWidth::W8 => 0xF6,
            _ => 0xF7,
        };
        self.code.emit_u8(opcode);
        self.emit_modrm_sib_disp(PhysReg::Rax, base, index, scale, disp, disp_size);
        self.emit_imm_by_width(imm, width);
    }

    pub fn emit_test_mi_abs(&mut self, addr: u64, imm: i64, width: OpWidth) {
        self.emit_rex_for_width_mem(width, PhysReg::Rbp, None);
        let opcode = match width {
            OpWidth::W8 => 0xF6,
            _ => 0xF7,
        };
        self.code.emit_u8(opcode);
        self.emit_modrm_abs(PhysReg::Rax, addr);
        self.emit_imm_by_width(imm, width);
    }

    pub fn emit_test_mi_pcrel(&mut self, disp: i32, imm: i64, width: OpWidth) -> usize {
        self.emit_rex_for_width_mem(width, PhysReg::Rbp, None);
        let opcode = match width {
            OpWidth::W8 => 0xF6,
            _ => 0xF7,
        };
        self.code.emit_u8(opcode);
        let offset = self.emit_modrm_pcrel(PhysReg::Rax, disp);
        self.emit_imm_by_width(imm, width);
        offset
    }

    // ========================================================================
    // Unary ALU Instructions
    // ========================================================================

    /// NEG r/m
    pub fn emit_neg(&mut self, dst: PhysReg, width: OpWidth) {
        self.emit_rex_for_width(width, PhysReg::Rax, dst);

        let opcode = match width {
            OpWidth::W8 => 0xF6,
            _ => 0xF7,
        };
        self.code.emit_u8(opcode);
        self.emit_modrm_digit(0b11, 3, dst);
    }

    /// NOT r/m
    pub fn emit_not(&mut self, dst: PhysReg, width: OpWidth) {
        self.emit_rex_for_width(width, PhysReg::Rax, dst);

        let opcode = match width {
            OpWidth::W8 => 0xF6,
            _ => 0xF7,
        };
        self.code.emit_u8(opcode);
        self.emit_modrm_digit(0b11, 2, dst);
    }

    /// INC r/m
    pub fn emit_inc(&mut self, dst: PhysReg, width: OpWidth) {
        self.emit_rex_for_width(width, PhysReg::Rax, dst);

        let opcode = match width {
            OpWidth::W8 => 0xFE,
            _ => 0xFF,
        };
        self.code.emit_u8(opcode);
        self.emit_modrm_digit(0b11, 0, dst);
    }

    /// DEC r/m
    pub fn emit_dec(&mut self, dst: PhysReg, width: OpWidth) {
        self.emit_rex_for_width(width, PhysReg::Rax, dst);

        let opcode = match width {
            OpWidth::W8 => 0xFE,
            _ => 0xFF,
        };
        self.code.emit_u8(opcode);
        self.emit_modrm_digit(0b11, 1, dst);
    }

    pub fn emit_group3_m_disp(
        &mut self,
        digit: u8,
        base: PhysReg,
        disp: i32,
        disp_size: DispSize,
        width: OpWidth,
    ) {
        self.emit_rex_for_width_mem(width, base, None);
        let opcode = match width {
            OpWidth::W8 => 0xF6,
            _ => 0xF7,
        };
        self.code.emit_u8(opcode);
        self.emit_modrm_mem_disp(Self::digit_reg(digit), base, disp, disp_size);
    }

    pub fn emit_group3_m_sib_disp(
        &mut self,
        digit: u8,
        base: Option<PhysReg>,
        index: PhysReg,
        scale: u8,
        disp: i32,
        disp_size: DispSize,
        width: OpWidth,
    ) {
        let base_reg = base.unwrap_or(PhysReg::Rbp);
        self.emit_rex_for_width_mem(width, base_reg, Some(index));
        let opcode = match width {
            OpWidth::W8 => 0xF6,
            _ => 0xF7,
        };
        self.code.emit_u8(opcode);
        self.emit_modrm_sib_disp(Self::digit_reg(digit), base, index, scale, disp, disp_size);
    }

    pub fn emit_group3_m_abs(&mut self, digit: u8, addr: u64, width: OpWidth) {
        self.emit_rex_for_width_mem(width, PhysReg::Rbp, None);
        let opcode = match width {
            OpWidth::W8 => 0xF6,
            _ => 0xF7,
        };
        self.code.emit_u8(opcode);
        self.emit_modrm_abs(Self::digit_reg(digit), addr);
    }

    pub fn emit_group3_m_pcrel(&mut self, digit: u8, disp: i32, width: OpWidth) -> usize {
        self.emit_rex_for_width_mem(width, PhysReg::Rbp, None);
        let opcode = match width {
            OpWidth::W8 => 0xF6,
            _ => 0xF7,
        };
        self.code.emit_u8(opcode);
        self.emit_modrm_pcrel(Self::digit_reg(digit), disp)
    }

    pub fn emit_group5_m_disp(&mut self, digit: u8, base: PhysReg, disp: i32, disp_size: DispSize) {
        self.emit_rex_for_mem(base, None);
        self.code.emit_u8(0xFF);
        self.emit_modrm_mem_disp(Self::digit_reg(digit), base, disp, disp_size);
    }

    pub fn emit_group5_m_sib_disp(
        &mut self,
        digit: u8,
        base: Option<PhysReg>,
        index: PhysReg,
        scale: u8,
        disp: i32,
        disp_size: DispSize,
    ) {
        let base_reg = base.unwrap_or(PhysReg::Rbp);
        self.emit_rex_for_mem(base_reg, Some(index));
        self.code.emit_u8(0xFF);
        self.emit_modrm_sib_disp(Self::digit_reg(digit), base, index, scale, disp, disp_size);
    }

    pub fn emit_group5_m_abs(&mut self, digit: u8, addr: u64) {
        self.emit_rex_for_mem(PhysReg::Rbp, None);
        self.code.emit_u8(0xFF);
        self.emit_modrm_abs(Self::digit_reg(digit), addr);
    }

    pub fn emit_group5_m_pcrel(&mut self, digit: u8, disp: i32) -> usize {
        self.emit_rex_for_mem(PhysReg::Rbp, None);
        self.code.emit_u8(0xFF);
        self.emit_modrm_pcrel(Self::digit_reg(digit), disp)
    }

    // ========================================================================
    // Shift Instructions
    // ========================================================================

    /// SHL r/m, imm8
    pub fn emit_shl_ri(&mut self, dst: PhysReg, amount: u8, width: OpWidth) {
        self.emit_rex_for_width(width, PhysReg::Rax, dst);

        if amount == 1 {
            let opcode = match width {
                OpWidth::W8 => 0xD0,
                _ => 0xD1,
            };
            self.code.emit_u8(opcode);
            self.emit_modrm_digit(0b11, 4, dst);
        } else {
            let opcode = match width {
                OpWidth::W8 => 0xC0,
                _ => 0xC1,
            };
            self.code.emit_u8(opcode);
            self.emit_modrm_digit(0b11, 4, dst);
            self.code.emit_u8(amount);
        }
    }

    /// SHL r/m, CL
    pub fn emit_shl_cl(&mut self, dst: PhysReg, width: OpWidth) {
        self.emit_rex_for_width(width, PhysReg::Rax, dst);

        let opcode = match width {
            OpWidth::W8 => 0xD2,
            _ => 0xD3,
        };
        self.code.emit_u8(opcode);
        self.emit_modrm_digit(0b11, 4, dst);
    }

    /// SHR r/m, imm8
    pub fn emit_shr_ri(&mut self, dst: PhysReg, amount: u8, width: OpWidth) {
        self.emit_rex_for_width(width, PhysReg::Rax, dst);

        if amount == 1 {
            let opcode = match width {
                OpWidth::W8 => 0xD0,
                _ => 0xD1,
            };
            self.code.emit_u8(opcode);
            self.emit_modrm_digit(0b11, 5, dst);
        } else {
            let opcode = match width {
                OpWidth::W8 => 0xC0,
                _ => 0xC1,
            };
            self.code.emit_u8(opcode);
            self.emit_modrm_digit(0b11, 5, dst);
            self.code.emit_u8(amount);
        }
    }

    /// SHR r/m, CL
    pub fn emit_shr_cl(&mut self, dst: PhysReg, width: OpWidth) {
        self.emit_rex_for_width(width, PhysReg::Rax, dst);

        let opcode = match width {
            OpWidth::W8 => 0xD2,
            _ => 0xD3,
        };
        self.code.emit_u8(opcode);
        self.emit_modrm_digit(0b11, 5, dst);
    }

    /// SAR r/m, imm8
    pub fn emit_sar_ri(&mut self, dst: PhysReg, amount: u8, width: OpWidth) {
        self.emit_rex_for_width(width, PhysReg::Rax, dst);

        if amount == 1 {
            let opcode = match width {
                OpWidth::W8 => 0xD0,
                _ => 0xD1,
            };
            self.code.emit_u8(opcode);
            self.emit_modrm_digit(0b11, 7, dst);
        } else {
            let opcode = match width {
                OpWidth::W8 => 0xC0,
                _ => 0xC1,
            };
            self.code.emit_u8(opcode);
            self.emit_modrm_digit(0b11, 7, dst);
            self.code.emit_u8(amount);
        }
    }

    /// SAR r/m, CL
    pub fn emit_sar_cl(&mut self, dst: PhysReg, width: OpWidth) {
        self.emit_rex_for_width(width, PhysReg::Rax, dst);

        let opcode = match width {
            OpWidth::W8 => 0xD2,
            _ => 0xD3,
        };
        self.code.emit_u8(opcode);
        self.emit_modrm_digit(0b11, 7, dst);
    }

    /// ROL r/m, imm8
    pub fn emit_rol_ri(&mut self, dst: PhysReg, amount: u8, width: OpWidth) {
        self.emit_rex_for_width(width, PhysReg::Rax, dst);

        if amount == 1 {
            let opcode = match width {
                OpWidth::W8 => 0xD0,
                _ => 0xD1,
            };
            self.code.emit_u8(opcode);
            self.emit_modrm_digit(0b11, 0, dst);
        } else {
            let opcode = match width {
                OpWidth::W8 => 0xC0,
                _ => 0xC1,
            };
            self.code.emit_u8(opcode);
            self.emit_modrm_digit(0b11, 0, dst);
            self.code.emit_u8(amount);
        }
    }

    /// ROL r/m, CL
    pub fn emit_rol_cl(&mut self, dst: PhysReg, width: OpWidth) {
        self.emit_rex_for_width(width, PhysReg::Rax, dst);

        let opcode = match width {
            OpWidth::W8 => 0xD2,
            _ => 0xD3,
        };
        self.code.emit_u8(opcode);
        self.emit_modrm_digit(0b11, 0, dst);
    }

    /// ROR r/m, imm8
    pub fn emit_ror_ri(&mut self, dst: PhysReg, amount: u8, width: OpWidth) {
        self.emit_rex_for_width(width, PhysReg::Rax, dst);

        if amount == 1 {
            let opcode = match width {
                OpWidth::W8 => 0xD0,
                _ => 0xD1,
            };
            self.code.emit_u8(opcode);
            self.emit_modrm_digit(0b11, 1, dst);
        } else {
            let opcode = match width {
                OpWidth::W8 => 0xC0,
                _ => 0xC1,
            };
            self.code.emit_u8(opcode);
            self.emit_modrm_digit(0b11, 1, dst);
            self.code.emit_u8(amount);
        }
    }

    /// ROR r/m, CL
    pub fn emit_ror_cl(&mut self, dst: PhysReg, width: OpWidth) {
        self.emit_rex_for_width(width, PhysReg::Rax, dst);

        let opcode = match width {
            OpWidth::W8 => 0xD2,
            _ => 0xD3,
        };
        self.code.emit_u8(opcode);
        self.emit_modrm_digit(0b11, 1, dst);
    }

    fn shift_opcode(width: OpWidth, count: ShiftCount) -> u8 {
        match count {
            ShiftCount::One => match width {
                OpWidth::W8 => 0xD0,
                _ => 0xD1,
            },
            ShiftCount::Cl => match width {
                OpWidth::W8 => 0xD2,
                _ => 0xD3,
            },
            ShiftCount::Imm(_) => match width {
                OpWidth::W8 => 0xC0,
                _ => 0xC1,
            },
        }
    }

    pub fn emit_shift_m_disp(
        &mut self,
        digit: u8,
        base: PhysReg,
        disp: i32,
        disp_size: DispSize,
        width: OpWidth,
        count: ShiftCount,
    ) {
        self.emit_rex_for_width_mem(width, base, None);
        let opcode = Self::shift_opcode(width, count);
        self.code.emit_u8(opcode);
        self.emit_modrm_mem_disp(Self::digit_reg(digit), base, disp, disp_size);
        if let ShiftCount::Imm(imm) = count {
            self.code.emit_u8(imm);
        }
    }

    pub fn emit_shift_m_sib_disp(
        &mut self,
        digit: u8,
        base: Option<PhysReg>,
        index: PhysReg,
        scale: u8,
        disp: i32,
        disp_size: DispSize,
        width: OpWidth,
        count: ShiftCount,
    ) {
        let base_reg = base.unwrap_or(PhysReg::Rbp);
        self.emit_rex_for_width_mem(width, base_reg, Some(index));
        let opcode = Self::shift_opcode(width, count);
        self.code.emit_u8(opcode);
        self.emit_modrm_sib_disp(Self::digit_reg(digit), base, index, scale, disp, disp_size);
        if let ShiftCount::Imm(imm) = count {
            self.code.emit_u8(imm);
        }
    }

    pub fn emit_shift_m_abs(&mut self, digit: u8, addr: u64, width: OpWidth, count: ShiftCount) {
        self.emit_rex_for_width_mem(width, PhysReg::Rbp, None);
        let opcode = Self::shift_opcode(width, count);
        self.code.emit_u8(opcode);
        self.emit_modrm_abs(Self::digit_reg(digit), addr);
        if let ShiftCount::Imm(imm) = count {
            self.code.emit_u8(imm);
        }
    }

    pub fn emit_shift_m_pcrel(
        &mut self,
        digit: u8,
        disp: i32,
        width: OpWidth,
        count: ShiftCount,
    ) -> usize {
        self.emit_rex_for_width_mem(width, PhysReg::Rbp, None);
        let opcode = Self::shift_opcode(width, count);
        self.code.emit_u8(opcode);
        let offset = self.emit_modrm_pcrel(Self::digit_reg(digit), disp);
        if let ShiftCount::Imm(imm) = count {
            self.code.emit_u8(imm);
        }
        offset
    }

    pub fn emit_shld_rr_imm(&mut self, dst: PhysReg, src: PhysReg, imm: u8, width: OpWidth) {
        self.emit_rex_for_width(width, src, dst);
        self.code.emit_u8(0x0F);
        self.code.emit_u8(0xA4);
        self.emit_modrm_rr(src, dst);
        self.code.emit_u8(imm);
    }

    pub fn emit_shld_rr_cl(&mut self, dst: PhysReg, src: PhysReg, width: OpWidth) {
        self.emit_rex_for_width(width, src, dst);
        self.code.emit_u8(0x0F);
        self.code.emit_u8(0xA5);
        self.emit_modrm_rr(src, dst);
    }

    pub fn emit_shrd_rr_imm(&mut self, dst: PhysReg, src: PhysReg, imm: u8, width: OpWidth) {
        self.emit_rex_for_width(width, src, dst);
        self.code.emit_u8(0x0F);
        self.code.emit_u8(0xAC);
        self.emit_modrm_rr(src, dst);
        self.code.emit_u8(imm);
    }

    pub fn emit_shrd_rr_cl(&mut self, dst: PhysReg, src: PhysReg, width: OpWidth) {
        self.emit_rex_for_width(width, src, dst);
        self.code.emit_u8(0x0F);
        self.code.emit_u8(0xAD);
        self.emit_modrm_rr(src, dst);
    }

    pub fn emit_shld_mr_disp(
        &mut self,
        base: PhysReg,
        disp: i32,
        disp_size: DispSize,
        src: PhysReg,
        imm: Option<u8>,
        width: OpWidth,
    ) {
        self.emit_rex_for_width_mem_reg(width, src, base, None);
        self.code.emit_u8(0x0F);
        self.code.emit_u8(if imm.is_some() { 0xA4 } else { 0xA5 });
        self.emit_modrm_mem_disp(src, base, disp, disp_size);
        if let Some(val) = imm {
            self.code.emit_u8(val);
        }
    }

    pub fn emit_shld_mr_sib_disp(
        &mut self,
        base: Option<PhysReg>,
        index: PhysReg,
        scale: u8,
        disp: i32,
        disp_size: DispSize,
        src: PhysReg,
        imm: Option<u8>,
        width: OpWidth,
    ) {
        let base_reg = base.unwrap_or(PhysReg::Rbp);
        self.emit_rex_for_width_mem_reg(width, src, base_reg, Some(index));
        self.code.emit_u8(0x0F);
        self.code.emit_u8(if imm.is_some() { 0xA4 } else { 0xA5 });
        self.emit_modrm_sib_disp(src, base, index, scale, disp, disp_size);
        if let Some(val) = imm {
            self.code.emit_u8(val);
        }
    }

    pub fn emit_shld_mr_abs(&mut self, addr: u64, src: PhysReg, imm: Option<u8>, width: OpWidth) {
        self.emit_rex_for_width_mem_reg(width, src, PhysReg::Rbp, None);
        self.code.emit_u8(0x0F);
        self.code.emit_u8(if imm.is_some() { 0xA4 } else { 0xA5 });
        self.emit_modrm_abs(src, addr);
        if let Some(val) = imm {
            self.code.emit_u8(val);
        }
    }

    pub fn emit_shld_mr_pcrel(
        &mut self,
        disp: i32,
        src: PhysReg,
        imm: Option<u8>,
        width: OpWidth,
    ) -> usize {
        self.emit_rex_for_width_mem_reg(width, src, PhysReg::Rbp, None);
        self.code.emit_u8(0x0F);
        self.code.emit_u8(if imm.is_some() { 0xA4 } else { 0xA5 });
        let offset = self.emit_modrm_pcrel(src, disp);
        if let Some(val) = imm {
            self.code.emit_u8(val);
        }
        offset
    }

    pub fn emit_shrd_mr_disp(
        &mut self,
        base: PhysReg,
        disp: i32,
        disp_size: DispSize,
        src: PhysReg,
        imm: Option<u8>,
        width: OpWidth,
    ) {
        self.emit_rex_for_width_mem_reg(width, src, base, None);
        self.code.emit_u8(0x0F);
        self.code.emit_u8(if imm.is_some() { 0xAC } else { 0xAD });
        self.emit_modrm_mem_disp(src, base, disp, disp_size);
        if let Some(val) = imm {
            self.code.emit_u8(val);
        }
    }

    pub fn emit_shrd_mr_sib_disp(
        &mut self,
        base: Option<PhysReg>,
        index: PhysReg,
        scale: u8,
        disp: i32,
        disp_size: DispSize,
        src: PhysReg,
        imm: Option<u8>,
        width: OpWidth,
    ) {
        let base_reg = base.unwrap_or(PhysReg::Rbp);
        self.emit_rex_for_width_mem_reg(width, src, base_reg, Some(index));
        self.code.emit_u8(0x0F);
        self.code.emit_u8(if imm.is_some() { 0xAC } else { 0xAD });
        self.emit_modrm_sib_disp(src, base, index, scale, disp, disp_size);
        if let Some(val) = imm {
            self.code.emit_u8(val);
        }
    }

    pub fn emit_shrd_mr_abs(&mut self, addr: u64, src: PhysReg, imm: Option<u8>, width: OpWidth) {
        self.emit_rex_for_width_mem_reg(width, src, PhysReg::Rbp, None);
        self.code.emit_u8(0x0F);
        self.code.emit_u8(if imm.is_some() { 0xAC } else { 0xAD });
        self.emit_modrm_abs(src, addr);
        if let Some(val) = imm {
            self.code.emit_u8(val);
        }
    }

    pub fn emit_shrd_mr_pcrel(
        &mut self,
        disp: i32,
        src: PhysReg,
        imm: Option<u8>,
        width: OpWidth,
    ) -> usize {
        self.emit_rex_for_width_mem_reg(width, src, PhysReg::Rbp, None);
        self.code.emit_u8(0x0F);
        self.code.emit_u8(if imm.is_some() { 0xAC } else { 0xAD });
        let offset = self.emit_modrm_pcrel(src, disp);
        if let Some(val) = imm {
            self.code.emit_u8(val);
        }
        offset
    }

    // ========================================================================
    // Multiply/Divide
    // ========================================================================

    /// IMUL r, r/m (two-operand form, dst = dst * src)
    pub fn emit_imul_rr(&mut self, dst: PhysReg, src: PhysReg, width: OpWidth) {
        self.emit_rex_for_width(width, dst, src);
        self.code.emit_u8(0x0F);
        self.code.emit_u8(0xAF);
        self.emit_modrm_rr(dst, src);
    }

    /// IMUL r, r/m, imm (three-operand form)
    pub fn emit_imul_rri(&mut self, dst: PhysReg, src: PhysReg, imm: i32, width: OpWidth) {
        self.emit_rex_for_width(width, dst, src);

        if imm >= -128 && imm <= 127 {
            self.code.emit_u8(0x6B);
            self.emit_modrm_rr(dst, src);
            self.code.emit_i8(imm as i8);
        } else {
            self.code.emit_u8(0x69);
            self.emit_modrm_rr(dst, src);
            self.code.emit_i32(imm);
        }
    }

    pub fn emit_imul_rri_force(
        &mut self,
        dst: PhysReg,
        src: PhysReg,
        imm: i32,
        width: OpWidth,
        use_imm8: bool,
    ) {
        self.emit_rex_for_width(width, dst, src);
        if use_imm8 {
            self.code.emit_u8(0x6B);
            self.emit_modrm_rr(dst, src);
            self.code.emit_i8(imm as i8);
        } else {
            self.code.emit_u8(0x69);
            self.emit_modrm_rr(dst, src);
            self.code.emit_i32(imm);
        }
    }

    pub fn emit_imul_rmi_disp(
        &mut self,
        dst: PhysReg,
        base: PhysReg,
        disp: i32,
        disp_size: DispSize,
        imm: i32,
        width: OpWidth,
        use_imm8: bool,
    ) {
        self.emit_rex_for_width_mem_reg(width, dst, base, None);
        if use_imm8 {
            self.code.emit_u8(0x6B);
            self.emit_modrm_mem_disp(dst, base, disp, disp_size);
            self.code.emit_i8(imm as i8);
        } else {
            self.code.emit_u8(0x69);
            self.emit_modrm_mem_disp(dst, base, disp, disp_size);
            self.code.emit_i32(imm);
        }
    }

    pub fn emit_imul_rmi_sib_disp(
        &mut self,
        dst: PhysReg,
        base: Option<PhysReg>,
        index: PhysReg,
        scale: u8,
        disp: i32,
        disp_size: DispSize,
        imm: i32,
        width: OpWidth,
        use_imm8: bool,
    ) {
        let base_reg = base.unwrap_or(PhysReg::Rbp);
        self.emit_rex_for_width_mem_reg(width, dst, base_reg, Some(index));
        if use_imm8 {
            self.code.emit_u8(0x6B);
            self.emit_modrm_sib_disp(dst, base, index, scale, disp, disp_size);
            self.code.emit_i8(imm as i8);
        } else {
            self.code.emit_u8(0x69);
            self.emit_modrm_sib_disp(dst, base, index, scale, disp, disp_size);
            self.code.emit_i32(imm);
        }
    }

    pub fn emit_imul_rmi_abs(
        &mut self,
        dst: PhysReg,
        addr: u64,
        imm: i32,
        width: OpWidth,
        use_imm8: bool,
    ) {
        self.emit_rex_for_width_mem_reg(width, dst, PhysReg::Rbp, None);
        if use_imm8 {
            self.code.emit_u8(0x6B);
            self.emit_modrm_abs(dst, addr);
            self.code.emit_i8(imm as i8);
        } else {
            self.code.emit_u8(0x69);
            self.emit_modrm_abs(dst, addr);
            self.code.emit_i32(imm);
        }
    }

    pub fn emit_imul_rmi_pcrel(
        &mut self,
        dst: PhysReg,
        disp: i32,
        imm: i32,
        width: OpWidth,
        use_imm8: bool,
    ) -> usize {
        self.emit_rex_for_width_mem_reg(width, dst, PhysReg::Rbp, None);
        if use_imm8 {
            self.code.emit_u8(0x6B);
            let offset = self.emit_modrm_pcrel(dst, disp);
            self.code.emit_i8(imm as i8);
            offset
        } else {
            self.code.emit_u8(0x69);
            let offset = self.emit_modrm_pcrel(dst, disp);
            self.code.emit_i32(imm);
            offset
        }
    }

    /// MUL r/m (unsigned, RDX:RAX = RAX * r/m)
    pub fn emit_mul(&mut self, src: PhysReg, width: OpWidth) {
        self.emit_rex_for_width(width, PhysReg::Rax, src);

        let opcode = match width {
            OpWidth::W8 => 0xF6,
            _ => 0xF7,
        };
        self.code.emit_u8(opcode);
        self.emit_modrm_digit(0b11, 4, src);
    }

    /// IMUL r/m (signed, RDX:RAX = RAX * r/m)
    pub fn emit_imul(&mut self, src: PhysReg, width: OpWidth) {
        self.emit_rex_for_width(width, PhysReg::Rax, src);

        let opcode = match width {
            OpWidth::W8 => 0xF6,
            _ => 0xF7,
        };
        self.code.emit_u8(opcode);
        self.emit_modrm_digit(0b11, 5, src);
    }

    /// DIV r/m (unsigned)
    pub fn emit_div(&mut self, src: PhysReg, width: OpWidth) {
        self.emit_rex_for_width(width, PhysReg::Rax, src);

        let opcode = match width {
            OpWidth::W8 => 0xF6,
            _ => 0xF7,
        };
        self.code.emit_u8(opcode);
        self.emit_modrm_digit(0b11, 6, src);
    }

    /// IDIV r/m (signed)
    pub fn emit_idiv(&mut self, src: PhysReg, width: OpWidth) {
        self.emit_rex_for_width(width, PhysReg::Rax, src);

        let opcode = match width {
            OpWidth::W8 => 0xF6,
            _ => 0xF7,
        };
        self.code.emit_u8(opcode);
        self.emit_modrm_digit(0b11, 7, src);
    }

    /// CQO (sign-extend RAX into RDX:RAX)
    pub fn emit_cqo(&mut self) {
        self.code.emit_u8(0x48); // REX.W
        self.code.emit_u8(0x99);
    }

    /// CDQ (sign-extend EAX into EDX:EAX)
    pub fn emit_cdq(&mut self) {
        self.code.emit_u8(0x99);
    }

    /// CWD (sign-extend AX into DX:AX)
    pub fn emit_cwd(&mut self) {
        self.code.emit_u8(0x66);
        self.code.emit_u8(0x99);
    }

    /// XOR RDX, RDX (zero RDX for unsigned division)
    pub fn emit_zero_rdx(&mut self) {
        self.emit_xor_rr(PhysReg::Rdx, PhysReg::Rdx, OpWidth::W64);
    }

    // ========================================================================
    // Stack Operations
    // ========================================================================

    /// PUSH r64
    pub fn emit_push(&mut self, src: PhysReg) {
        if src.is_extended() {
            self.code.emit_u8(0x41); // REX.B
        }
        self.code.emit_u8(0x50 + src.low3());
    }

    pub fn emit_push_imm8(&mut self, imm: i8) {
        self.code.emit_u8(0x6A);
        self.code.emit_i8(imm);
    }

    pub fn emit_push_imm32(&mut self, imm: i32) {
        self.code.emit_u8(0x68);
        self.code.emit_i32(imm);
    }

    /// POP r64
    pub fn emit_pop(&mut self, dst: PhysReg) {
        if dst.is_extended() {
            self.code.emit_u8(0x41); // REX.B
        }
        self.code.emit_u8(0x58 + dst.low3());
    }

    // ========================================================================
    // Control Flow
    // ========================================================================

    /// CALL rel32
    pub fn emit_call_rel32(&mut self, rel: i32) {
        self.code.emit_u8(0xE8);
        self.code.emit_i32(rel);
    }

    /// CALL r/m64
    pub fn emit_call_reg(&mut self, target: PhysReg) {
        if target.is_extended() {
            self.code.emit_u8(0x41); // REX.B
        }
        self.code.emit_u8(0xFF);
        self.emit_modrm_digit(0b11, 2, target);
    }

    /// RET
    pub fn emit_ret(&mut self) {
        self.code.emit_u8(0xC3);
    }

    /// RET imm16
    pub fn emit_ret_imm16(&mut self, imm: u16) {
        self.code.emit_u8(0xC2);
        self.code.emit_u16(imm);
    }

    /// JMP rel8
    pub fn emit_jmp_rel8(&mut self, rel: i8) {
        self.code.emit_u8(0xEB);
        self.code.emit_i8(rel);
    }

    /// JMP rel32
    pub fn emit_jmp_rel32(&mut self, rel: i32) {
        self.code.emit_u8(0xE9);
        self.code.emit_i32(rel);
    }

    /// JMP r/m64
    pub fn emit_jmp_reg(&mut self, target: PhysReg) {
        if target.is_extended() {
            self.code.emit_u8(0x41);
        }
        self.code.emit_u8(0xFF);
        self.emit_modrm_digit(0b11, 4, target);
    }

    /// Jcc rel8
    pub fn emit_jcc_rel8(&mut self, cond: X86Cond, rel: i8) {
        self.code.emit_u8(0x70 + cond as u8);
        self.code.emit_i8(rel);
    }

    /// Jcc rel32
    pub fn emit_jcc_rel32(&mut self, cond: X86Cond, rel: i32) {
        self.code.emit_u8(0x0F);
        self.code.emit_u8(0x80 + cond as u8);
        self.code.emit_i32(rel);
    }

    /// SETcc r/m8
    pub fn emit_setcc(&mut self, cond: X86Cond, dst: PhysReg) {
        // Need REX for certain registers
        if dst.is_extended()
            || matches!(
                dst,
                PhysReg::Rsp | PhysReg::Rbp | PhysReg::Rsi | PhysReg::Rdi
            )
        {
            self.code
                .emit_u8(0x40 | if dst.is_extended() { 0x01 } else { 0 });
        }
        self.code.emit_u8(0x0F);
        self.code.emit_u8(0x90 + cond as u8);
        self.emit_modrm_digit(0b11, 0, dst);
    }

    /// CMOVcc r, r/m
    pub fn emit_cmovcc(&mut self, cond: X86Cond, dst: PhysReg, src: PhysReg, width: OpWidth) {
        self.emit_rex_for_width(width, dst, src);
        self.code.emit_u8(0x0F);
        self.code.emit_u8(0x40 + cond as u8);
        self.emit_modrm_rr(dst, src);
    }

    // ========================================================================
    // Miscellaneous
    // ========================================================================

    /// NOP (single-byte)
    pub fn emit_nop(&mut self) {
        self.code.emit_u8(0x90);
    }

    /// CLC
    pub fn emit_clc(&mut self) {
        self.code.emit_u8(0xF8);
    }

    /// STC
    pub fn emit_stc(&mut self) {
        self.code.emit_u8(0xF9);
    }

    /// CMC
    pub fn emit_cmc(&mut self) {
        self.code.emit_u8(0xF5);
    }

    /// CLD
    pub fn emit_cld(&mut self) {
        self.code.emit_u8(0xFC);
    }

    /// STD
    pub fn emit_std(&mut self) {
        self.code.emit_u8(0xFD);
    }

    /// Multi-byte NOP
    pub fn emit_nop_n(&mut self, n: usize) {
        // Use optimal multi-byte NOPs
        let mut remaining = n;
        while remaining > 0 {
            match remaining {
                1 => {
                    self.code.emit_u8(0x90);
                    remaining -= 1;
                }
                2 => {
                    self.code.emit_bytes(&[0x66, 0x90]);
                    remaining -= 2;
                }
                3 => {
                    self.code.emit_bytes(&[0x0F, 0x1F, 0x00]);
                    remaining -= 3;
                }
                4 => {
                    self.code.emit_bytes(&[0x0F, 0x1F, 0x40, 0x00]);
                    remaining -= 4;
                }
                5 => {
                    self.code.emit_bytes(&[0x0F, 0x1F, 0x44, 0x00, 0x00]);
                    remaining -= 5;
                }
                6 => {
                    self.code.emit_bytes(&[0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00]);
                    remaining -= 6;
                }
                7 => {
                    self.code
                        .emit_bytes(&[0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00]);
                    remaining -= 7;
                }
                8 => {
                    self.code
                        .emit_bytes(&[0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00]);
                    remaining -= 8;
                }
                _ => {
                    self.code
                        .emit_bytes(&[0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00]);
                    remaining -= 9;
                }
            }
        }
    }

    /// INT3 (breakpoint)
    pub fn emit_int3(&mut self) {
        self.code.emit_u8(0xCC);
    }

    /// UD2 (undefined instruction)
    pub fn emit_ud2(&mut self) {
        self.code.emit_u8(0x0F);
        self.code.emit_u8(0x0B);
    }

    /// LEA r64, [base + disp]
    pub fn emit_lea(&mut self, dst: PhysReg, base: PhysReg, disp: i32) {
        self.emit_lea_disp(dst, base, disp, DispSize::Auto);
    }

    pub fn emit_lea_disp(&mut self, dst: PhysReg, base: PhysReg, disp: i32, disp_size: DispSize) {
        self.emit_rex_rr(true, dst, base);
        self.code.emit_u8(0x8D);
        self.emit_modrm_mem_disp(dst, base, disp, disp_size);
    }

    /// LEA r64, [base + index*scale + disp]
    pub fn emit_lea_sib(
        &mut self,
        dst: PhysReg,
        base: Option<PhysReg>,
        index: PhysReg,
        scale: u8,
        disp: i32,
    ) {
        self.emit_lea_sib_disp(dst, base, index, scale, disp, DispSize::Auto);
    }

    pub fn emit_lea_sib_disp(
        &mut self,
        dst: PhysReg,
        base: Option<PhysReg>,
        index: PhysReg,
        scale: u8,
        disp: i32,
        disp_size: DispSize,
    ) {
        self.emit_rex(true, dst, Some(index), base.unwrap_or(PhysReg::Rbp));
        self.code.emit_u8(0x8D);
        self.emit_modrm_sib_disp(dst, base, index, scale, disp, disp_size);
    }

    /// LEA r64, [rip + disp32]
    pub fn emit_lea_pcrel(&mut self, dst: PhysReg, disp: i32) -> usize {
        self.emit_rex_rr(true, dst, PhysReg::Rbp);
        self.code.emit_u8(0x8D);
        self.emit_modrm_pcrel(dst, disp)
    }

    /// XCHG r64, r64
    pub fn emit_xchg(&mut self, r1: PhysReg, r2: PhysReg, width: OpWidth) {
        if width != OpWidth::W8 && (r1 == PhysReg::Rax || r2 == PhysReg::Rax) {
            let other = if r1 == PhysReg::Rax { r2 } else { r1 };
            self.emit_rex_for_width(width, other, PhysReg::Rax);
            self.code.emit_u8(0x90 + other.low3());
            return;
        }

        self.emit_rex_for_width(width, r1, r2);

        let opcode = match width {
            OpWidth::W8 => 0x86,
            _ => 0x87,
        };
        self.code.emit_u8(opcode);
        self.emit_modrm_rr(r1, r2);
    }

    /// BSWAP r64/r32
    pub fn emit_bswap(&mut self, reg: PhysReg, width: OpWidth) {
        match width {
            OpWidth::W64 => {
                self.emit_rex_w(reg);
                self.code.emit_u8(0x0F);
                self.code.emit_u8(0xC8 + reg.low3());
            }
            OpWidth::W32 => {
                if reg.is_extended() {
                    self.code.emit_u8(0x41);
                }
                self.code.emit_u8(0x0F);
                self.code.emit_u8(0xC8 + reg.low3());
            }
            _ => {} // BSWAP only works on 32/64-bit
        }
    }

    /// BSF r, r/m
    pub fn emit_bsf(&mut self, dst: PhysReg, src: PhysReg, width: OpWidth) {
        self.emit_rex_for_width(width, dst, src);
        self.code.emit_u8(0x0F);
        self.code.emit_u8(0xBC);
        self.emit_modrm_rr(dst, src);
    }

    /// BSR r, r/m
    pub fn emit_bsr(&mut self, dst: PhysReg, src: PhysReg, width: OpWidth) {
        self.emit_rex_for_width(width, dst, src);
        self.code.emit_u8(0x0F);
        self.code.emit_u8(0xBD);
        self.emit_modrm_rr(dst, src);
    }

    /// LZCNT r, r/m (requires LZCNT support)
    pub fn emit_lzcnt(&mut self, dst: PhysReg, src: PhysReg, width: OpWidth) {
        self.code.emit_u8(0xF3); // Rep prefix
        self.emit_rex_for_width(width, dst, src);
        self.code.emit_u8(0x0F);
        self.code.emit_u8(0xBD);
        self.emit_modrm_rr(dst, src);
    }

    /// TZCNT r, r/m (requires BMI1)
    pub fn emit_tzcnt(&mut self, dst: PhysReg, src: PhysReg, width: OpWidth) {
        self.code.emit_u8(0xF3); // Rep prefix
        self.emit_rex_for_width(width, dst, src);
        self.code.emit_u8(0x0F);
        self.code.emit_u8(0xBC);
        self.emit_modrm_rr(dst, src);
    }

    /// POPCNT r, r/m
    pub fn emit_popcnt(&mut self, dst: PhysReg, src: PhysReg, width: OpWidth) {
        self.code.emit_u8(0xF3); // Rep prefix
        self.emit_rex_for_width(width, dst, src);
        self.code.emit_u8(0x0F);
        self.code.emit_u8(0xB8);
        self.emit_modrm_rr(dst, src);
    }
}

// ============================================================================
// x86_64 Lowerer
// ============================================================================

/// x86_64 code generator
pub struct X86_64Lowerer {
    /// Code buffer
    code: CodeBuffer,

    /// Register allocator
    regalloc: RegAlloc,

    /// Block offsets in generated code
    block_offsets: HashMap<BlockId, usize>,

    /// Relocations to apply
    relocations: Vec<Relocation>,

    /// Pending jumps to fix up (source offset, target block, reloc kind)
    pending_jumps: Vec<(usize, BlockId, RelocKind)>,

    /// Guest base address used for PC-relative fixups
    guest_base: GuestAddr,

    /// Guest PC for blocks
    block_guest_pcs: HashMap<BlockId, GuestAddr>,

    /// Pending return immediate for current block
    pending_ret_imm: Option<u16>,

    /// Native-exit blocks (JIT general-exit ABI): block-id ⇒ resume guest PC.
    /// A block in this map is lowered as an EXIT STUB that records `exit_pc`
    /// (via the `[rbp+24]` state pointer) and returns to the trampoline, instead
    /// of lowering its ops/terminator. Lets the JIT run a hot loop natively and
    /// hand control back to the interpreter at the loop-exit address. Set via
    /// [`X86_64Lowerer::set_native_exits`] before `lower_function`.
    native_exits: std::collections::HashMap<BlockId, u64>,

    /// Folded condition for the current block's `CondBranch` terminator.
    /// Set by `lower_block` when the block's last op is a `TestCondition`
    /// feeding the terminator's `cond` vreg: the SETcc-into-a-vreg + `test`
    /// round-trip is elided and the terminator emits `Jcc<cond>` directly off
    /// the live guest flags (the body's last flag-setting op). This avoids
    /// materializing the condition into a host register — which, under the 1:1
    /// identity reg map where every GPR is guest-live, would clobber guest
    /// state (no free scratch). Also faster: one `jcc` instead of setcc+test+jnz.
    pending_cond: Option<Condition>,

    /// Whether to adjust PC-relative displacements for code layout
    pcrel_adjust: bool,
}

impl X86_64Lowerer {
    /// Create a new x86_64 lowerer
    pub fn new() -> Self {
        X86_64Lowerer {
            code: CodeBuffer::with_capacity(4096),
            regalloc: RegAlloc::new(),
            block_offsets: HashMap::new(),
            relocations: Vec::new(),
            pending_jumps: Vec::new(),
            guest_base: 0,
            pcrel_adjust: true,
            block_guest_pcs: HashMap::new(),
            pending_ret_imm: None,
            pending_cond: None,
            native_exits: std::collections::HashMap::new(),
        }
    }

    /// Mark blocks as JIT native-exit stubs (block-id ⇒ resume guest PC). Call
    /// after `new()` and before `lower_function`. Each marked block lowers to an
    /// exit stub that records `exit_pc` and returns; its ops/terminator are not
    /// emitted. Requires the block to be reachable only as an exit edge.
    pub fn set_native_exits(&mut self, exits: std::collections::HashMap<BlockId, u64>) {
        self.native_exits = exits;
    }

    pub fn set_pcrel_adjust(&mut self, adjust: bool) {
        self.pcrel_adjust = adjust;
    }

    /// Get a physical register for a VReg, loading from stack if needed
    fn get_reg(&mut self, vreg: VReg) -> Result<PhysReg, LowerError> {
        let loc = self.regalloc.alloc_vreg(vreg)?;
        match loc {
            RegLocation::Register(r) => Ok(r),
            RegLocation::Stack(offset) => {
                // Load from stack into a temp register
                let temp = self.regalloc.get_scratch()?;
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_mov_rm(temp, PhysReg::Rbp, offset, OpWidth::W64);
                Ok(temp)
            }
            RegLocation::Constant(val) => {
                // Load constant into a register
                let temp = self.regalloc.get_scratch()?;
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_mov_ri(temp, val, OpWidth::W64);
                Ok(temp)
            }
            RegLocation::Unallocated => Err(LowerError::RegisterAllocationFailed {
                reason: "vreg not allocated".to_string(),
            }),
        }
    }

    /// Get the destination register for a VReg
    fn get_dst_reg(&mut self, vreg: VReg) -> Result<PhysReg, LowerError> {
        let loc = self.regalloc.alloc_vreg(vreg)?;
        match loc {
            RegLocation::Register(r) => Ok(r),
            RegLocation::Stack(_) | RegLocation::Constant(_) | RegLocation::Unallocated => {
                Err(LowerError::RegisterAllocationFailed {
                    reason: "destination must be a register".to_string(),
                })
            }
        }
    }

    /// Emit function prologue
    fn emit_prologue(&mut self) {
        let mut emitter = X86Emitter::new(&mut self.code);

        // PUSH RBP
        emitter.emit_push(PhysReg::Rbp);

        // MOV RBP, RSP
        emitter.emit_mov_rr(PhysReg::Rbp, PhysReg::Rsp, OpWidth::W64);

        // Save callee-saved registers
        for &reg in self.regalloc.callee_saved_used() {
            emitter.emit_push(reg);
        }

        // Allocate stack space for spills
        let frame_size = self.regalloc.frame_size();
        if frame_size > 0 {
            emitter.emit_sub_ri(PhysReg::Rsp, frame_size as i64, OpWidth::W64);
        }
    }

    /// Emit function epilogue
    fn emit_epilogue(&mut self) {
        self.emit_epilogue_with_ret(None);
    }

    fn emit_epilogue_with_ret(&mut self, ret_imm: Option<u16>) {
        let mut emitter = X86Emitter::new(&mut self.code);

        // Deallocate stack space with `mov rsp, rbp` (flag-preserving) rather
        // than `add rsp, frame` (which sets RFLAGS, clobbering the guest flags
        // the block body computed). RBP = RSP after the prologue's `push rbp`,
        // so this exactly undoes the frame `sub rsp, frame`.
        emitter.emit_mov_rr(PhysReg::Rsp, PhysReg::Rbp, OpWidth::W64);

        // NOTE: callee-saved guest registers are intentionally NOT restored
        // here. A lowered block owns all GPRs (identity-mapped guest state), and
        // the `enter_native` shim preserves the HOST's callee-saved registers.
        // Restoring them here would clobber guest writes to RBX/R12-R15 — the
        // hazard the native differential exposes.

        // POP RBP
        emitter.emit_pop(PhysReg::Rbp);

        // RET
        if let Some(imm) = ret_imm {
            if imm == 0 {
                emitter.emit_ret();
            } else {
                emitter.emit_ret_imm16(imm);
            }
        } else {
            emitter.emit_ret();
        }
    }

    /// Lower a single operation
    fn lower_op(&mut self, op: &crate::smir::ops::SmirOp) -> Result<(), LowerError> {
        let alu_hint = match op.x86_hint {
            Some(X86OpHint::AluEncoding(enc)) => Some(enc),
            _ => None,
        };

        match &op.kind {
            // ================================================================
            // Data Movement
            // ================================================================
            OpKind::Mov { dst, src, width } => {
                let dst_reg = self.get_dst_reg(*dst)?;
                let use_modrm_imm = matches!(op.x86_hint, Some(X86OpHint::MovImmModRm));
                match src {
                    SrcOperand::Reg(r) => {
                        let src_reg = self.get_reg(*r)?;
                        let mut emitter = X86Emitter::new(&mut self.code);
                        emitter.emit_mov_rr(dst_reg, src_reg, *width);
                    }
                    SrcOperand::Imm(val) => {
                        let mut emitter = X86Emitter::new(&mut self.code);
                        if use_modrm_imm {
                            emitter.emit_mov_rm_imm(dst_reg, *val, *width);
                        } else {
                            emitter.emit_mov_ri(dst_reg, *val, *width);
                        }
                    }
                    SrcOperand::Imm64(val) => {
                        let mut emitter = X86Emitter::new(&mut self.code);
                        if *width == OpWidth::W64 {
                            emitter.emit_mov_ri_imm64(dst_reg, *val);
                        } else {
                            emitter.emit_mov_ri(dst_reg, *val, *width);
                        }
                    }
                    _ => {
                        return Err(LowerError::UnsupportedOp {
                            op: "Mov with shifted/extended operand".to_string(),
                        });
                    }
                }
            }

            OpKind::Lea { dst, addr } => {
                let dst_reg = self.get_dst_reg(*dst)?;

                match addr {
                    Address::Direct(base) => {
                        let base_reg = self.get_reg(*base)?;
                        // LEA dst, [base] is just a MOV
                        let mut emitter = X86Emitter::new(&mut self.code);
                        emitter.emit_mov_rr(dst_reg, base_reg, OpWidth::W64);
                    }
                    Address::BaseOffset {
                        base,
                        offset,
                        disp_size,
                    } => {
                        let base_reg = self.get_reg(*base)?;
                        let mut emitter = X86Emitter::new(&mut self.code);
                        emitter.emit_lea_disp(dst_reg, base_reg, *offset as i32, *disp_size);
                    }
                    Address::BaseIndexScale {
                        base,
                        index,
                        scale,
                        disp,
                        disp_size,
                    } => {
                        let index_reg = self.get_reg(*index)?;
                        let base_phys = match base {
                            Some(b) => Some(self.get_reg(*b)?),
                            None => None,
                        };
                        let mut emitter = X86Emitter::new(&mut self.code);
                        emitter.emit_lea_sib_disp(
                            dst_reg, base_phys, index_reg, *scale, *disp, *disp_size,
                        );
                    }
                    Address::PcRel { offset, base, .. } => {
                        let disp_offset = {
                            let mut emitter = X86Emitter::new(&mut self.code);
                            emitter.emit_lea_pcrel(dst_reg, 0)
                        };
                        let insn_end = self.code.position();

                        let disp = if let Some(base_pc) = base {
                            let target = (*base_pc as i64 + *offset) as u64;
                            let disp = if self.pcrel_adjust {
                                let next_rip = self.guest_base as i64 + insn_end as i64;
                                target as i64 - next_rip
                            } else {
                                *offset
                            };
                            if disp < i32::MIN as i64 || disp > i32::MAX as i64 {
                                return Err(LowerError::InvalidOperand {
                                    op: "Lea".to_string(),
                                    operand: "PcRel offset out of range".to_string(),
                                });
                            }
                            self.relocations.push(Relocation {
                                offset: disp_offset,
                                kind: RelocKind::PcRel32,
                                target: RelocTarget::GuestAddr(target),
                            });
                            disp
                        } else {
                            let disp = *offset;
                            if disp < i32::MIN as i64 || disp > i32::MAX as i64 {
                                return Err(LowerError::InvalidOperand {
                                    op: "Lea".to_string(),
                                    operand: "PcRel offset out of range".to_string(),
                                });
                            }
                            disp
                        };

                        self.code.patch_i32(disp_offset, disp as i32);
                    }
                    Address::Absolute(addr) => {
                        // LEA with absolute address - just MOV the constant
                        let mut emitter = X86Emitter::new(&mut self.code);
                        emitter.emit_mov_ri(dst_reg, *addr as i64, OpWidth::W64);
                    }
                    _ => {
                        return Err(LowerError::UnsupportedOp {
                            op: format!("Lea with {:?} address", addr),
                        });
                    }
                }
            }

            OpKind::Xchg { reg1, reg2, width } => {
                let reg1 = self.get_dst_reg(*reg1)?;
                let reg2 = self.get_dst_reg(*reg2)?;
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_xchg(reg1, reg2, *width);
            }

            OpKind::CMove {
                dst,
                src,
                cond,
                width,
            } => {
                let dst_reg = self.get_dst_reg(*dst)?;
                let src_reg = self.get_reg(*src)?;
                let x86_cond = X86Cond::from_condition(*cond);

                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_cmovcc(x86_cond, dst_reg, src_reg, *width);
            }

            // ================================================================
            // Integer Arithmetic
            // ================================================================
            OpKind::Add {
                dst,
                src1,
                src2,
                width,
                ..
            } => {
                let dst_reg = self.get_dst_reg(*dst)?;
                let src1_reg = self.get_reg(*src1)?;

                // Move src1 to dst if different
                if dst_reg != src1_reg {
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_mov_rr(dst_reg, src1_reg, *width);
                }

                match src2 {
                    SrcOperand::Reg(r) => {
                        let src2_reg = self.get_reg(*r)?;
                        let mut emitter = X86Emitter::new(&mut self.code);
                        let encoding = alu_hint.unwrap_or(X86AluEncoding::RmReg);
                        emitter.emit_alu_rr_dir(0x00, dst_reg, src2_reg, *width, encoding);
                    }
                    SrcOperand::Imm(val) => {
                        let mut emitter = X86Emitter::new(&mut self.code);
                        if matches!(alu_hint, Some(X86AluEncoding::AccImm))
                            && dst_reg == PhysReg::Rax
                        {
                            emitter.emit_alu_acc_imm(0x04, *val, *width);
                        } else {
                            emitter.emit_add_ri(dst_reg, *val, *width);
                        }
                    }
                    _ => {
                        return Err(LowerError::UnsupportedOp {
                            op: "Add with shifted operand".to_string(),
                        });
                    }
                }
            }

            OpKind::Sub {
                dst,
                src1,
                src2,
                width,
                ..
            } => {
                let dst_reg = self.get_dst_reg(*dst)?;
                let src1_reg = self.get_reg(*src1)?;

                if dst_reg != src1_reg {
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_mov_rr(dst_reg, src1_reg, *width);
                }

                match src2 {
                    SrcOperand::Reg(r) => {
                        let src2_reg = self.get_reg(*r)?;
                        let mut emitter = X86Emitter::new(&mut self.code);
                        let encoding = alu_hint.unwrap_or(X86AluEncoding::RmReg);
                        emitter.emit_alu_rr_dir(0x28, dst_reg, src2_reg, *width, encoding);
                    }
                    SrcOperand::Imm(val) => {
                        let mut emitter = X86Emitter::new(&mut self.code);
                        if matches!(alu_hint, Some(X86AluEncoding::AccImm))
                            && dst_reg == PhysReg::Rax
                        {
                            emitter.emit_alu_acc_imm(0x2C, *val, *width);
                        } else {
                            emitter.emit_sub_ri(dst_reg, *val, *width);
                        }
                    }
                    _ => {
                        return Err(LowerError::UnsupportedOp {
                            op: "Sub with shifted operand".to_string(),
                        });
                    }
                }
            }

            OpKind::Adc {
                dst,
                src1,
                src2,
                width,
                ..
            } => {
                let dst_reg = self.get_dst_reg(*dst)?;
                let src1_reg = self.get_reg(*src1)?;

                if dst_reg != src1_reg {
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_mov_rr(dst_reg, src1_reg, *width);
                }

                match src2 {
                    SrcOperand::Reg(r) => {
                        let src2_reg = self.get_reg(*r)?;
                        let mut emitter = X86Emitter::new(&mut self.code);
                        let encoding = alu_hint.unwrap_or(X86AluEncoding::RmReg);
                        emitter.emit_alu_rr_dir(0x10, dst_reg, src2_reg, *width, encoding);
                    }
                    SrcOperand::Imm(val) => {
                        let mut emitter = X86Emitter::new(&mut self.code);
                        if matches!(alu_hint, Some(X86AluEncoding::AccImm))
                            && dst_reg == PhysReg::Rax
                        {
                            emitter.emit_alu_acc_imm(0x14, *val, *width);
                        } else {
                            emitter.emit_adc_ri(dst_reg, *val, *width);
                        }
                    }
                    _ => {
                        return Err(LowerError::UnsupportedOp {
                            op: "Adc with shifted operand".to_string(),
                        });
                    }
                }
            }

            OpKind::Sbb {
                dst,
                src1,
                src2,
                width,
                ..
            } => {
                let dst_reg = self.get_dst_reg(*dst)?;
                let src1_reg = self.get_reg(*src1)?;

                if dst_reg != src1_reg {
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_mov_rr(dst_reg, src1_reg, *width);
                }

                match src2 {
                    SrcOperand::Reg(r) => {
                        let src2_reg = self.get_reg(*r)?;
                        let mut emitter = X86Emitter::new(&mut self.code);
                        let encoding = alu_hint.unwrap_or(X86AluEncoding::RmReg);
                        emitter.emit_alu_rr_dir(0x18, dst_reg, src2_reg, *width, encoding);
                    }
                    SrcOperand::Imm(val) => {
                        let mut emitter = X86Emitter::new(&mut self.code);
                        if matches!(alu_hint, Some(X86AluEncoding::AccImm))
                            && dst_reg == PhysReg::Rax
                        {
                            emitter.emit_alu_acc_imm(0x1C, *val, *width);
                        } else {
                            emitter.emit_sbb_ri(dst_reg, *val, *width);
                        }
                    }
                    _ => {
                        return Err(LowerError::UnsupportedOp {
                            op: "Sbb with shifted operand".to_string(),
                        });
                    }
                }
            }

            OpKind::Neg {
                dst, src, width, ..
            } => {
                let dst_reg = self.get_dst_reg(*dst)?;
                let src_reg = self.get_reg(*src)?;

                if dst_reg != src_reg {
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_mov_rr(dst_reg, src_reg, *width);
                }

                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_neg(dst_reg, *width);
            }

            OpKind::Inc {
                dst, src, width, ..
            } => {
                let dst_reg = self.get_dst_reg(*dst)?;
                let src_reg = self.get_reg(*src)?;

                if dst_reg != src_reg {
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_mov_rr(dst_reg, src_reg, *width);
                }

                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_inc(dst_reg, *width);
            }

            OpKind::Dec {
                dst, src, width, ..
            } => {
                let dst_reg = self.get_dst_reg(*dst)?;
                let src_reg = self.get_reg(*src)?;

                if dst_reg != src_reg {
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_mov_rr(dst_reg, src_reg, *width);
                }

                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_dec(dst_reg, *width);
            }

            OpKind::MulS {
                dst_lo,
                dst_hi,
                src1,
                src2,
                width,
                ..
            } => {
                // For two-operand IMUL (dst = src1 * src2), we use the efficient form
                // For widening multiply (dst_hi:dst_lo = src1 * src2), we use IMUL with RAX
                if dst_hi.is_some() {
                    // Widening multiply: IMUL r/m -> RDX:RAX = RAX * r/m
                    // Move src1 to RAX
                    let src1_reg = self.get_reg(*src1)?;
                    {
                        let mut emitter = X86Emitter::new(&mut self.code);
                        emitter.emit_mov_rr(PhysReg::Rax, src1_reg, *width);
                    }

                    // Get src2 and do IMUL
                    match src2 {
                        SrcOperand::Reg(r) => {
                            let src2_reg = self.get_reg(*r)?;
                            let mut emitter = X86Emitter::new(&mut self.code);
                            emitter.emit_imul(src2_reg, *width);
                        }
                        SrcOperand::Imm(val) => {
                            // Load immediate to a temp register
                            let temp = self.regalloc.get_scratch()?;
                            {
                                let mut emitter = X86Emitter::new(&mut self.code);
                                emitter.emit_mov_ri(temp, *val, *width);
                            }
                            let mut emitter = X86Emitter::new(&mut self.code);
                            emitter.emit_imul(temp, *width);
                            self.regalloc.free_temp(temp);
                        }
                        _ => {
                            return Err(LowerError::UnsupportedOp {
                                op: "MulS with shifted operand".to_string(),
                            });
                        }
                    }

                    // Move results to destination registers
                    let dst_lo_reg = self.get_dst_reg(*dst_lo)?;
                    if dst_lo_reg != PhysReg::Rax {
                        let mut emitter = X86Emitter::new(&mut self.code);
                        emitter.emit_mov_rr(dst_lo_reg, PhysReg::Rax, *width);
                    }

                    if let Some(hi) = dst_hi {
                        let dst_hi_reg = self.get_dst_reg(*hi)?;
                        if dst_hi_reg != PhysReg::Rdx {
                            let mut emitter = X86Emitter::new(&mut self.code);
                            emitter.emit_mov_rr(dst_hi_reg, PhysReg::Rdx, *width);
                        }
                    }
                } else {
                    // Two-operand form: dst = src1 * src2
                    let dst_reg = self.get_dst_reg(*dst_lo)?;
                    let src1_reg = self.get_reg(*src1)?;

                    match src2 {
                        SrcOperand::Reg(r) => {
                            let src2_reg = self.get_reg(*r)?;
                            // Move src1 to dst, then IMUL dst, src2
                            if dst_reg != src1_reg {
                                let mut emitter = X86Emitter::new(&mut self.code);
                                emitter.emit_mov_rr(dst_reg, src1_reg, *width);
                            }
                            let mut emitter = X86Emitter::new(&mut self.code);
                            emitter.emit_imul_rr(dst_reg, src2_reg, *width);
                        }
                        SrcOperand::Imm(val) => {
                            // Three-operand form: IMUL dst, src1, imm
                            let mut emitter = X86Emitter::new(&mut self.code);
                            let use_imm8 = match op.x86_hint {
                                Some(X86OpHint::ImulImm8) => true,
                                Some(X86OpHint::ImulImm32) => false,
                                _ => *val >= -128 && *val <= 127,
                            };
                            emitter.emit_imul_rri_force(
                                dst_reg,
                                src1_reg,
                                *val as i32,
                                *width,
                                use_imm8,
                            );
                        }
                        _ => {
                            return Err(LowerError::UnsupportedOp {
                                op: "MulS with shifted operand".to_string(),
                            });
                        }
                    }
                }
            }

            OpKind::MulU {
                dst_lo,
                dst_hi,
                src1,
                src2,
                width,
                ..
            } => {
                // Unsigned multiply always uses RAX
                // MUL r/m -> RDX:RAX = RAX * r/m
                let src1_reg = self.get_reg(*src1)?;
                {
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_mov_rr(PhysReg::Rax, src1_reg, *width);
                }

                match src2 {
                    SrcOperand::Reg(r) => {
                        let src2_reg = self.get_reg(*r)?;
                        let mut emitter = X86Emitter::new(&mut self.code);
                        emitter.emit_mul(src2_reg, *width);
                    }
                    SrcOperand::Imm(val) => {
                        let temp = self.regalloc.get_scratch()?;
                        {
                            let mut emitter = X86Emitter::new(&mut self.code);
                            emitter.emit_mov_ri(temp, *val, *width);
                        }
                        let mut emitter = X86Emitter::new(&mut self.code);
                        emitter.emit_mul(temp, *width);
                        self.regalloc.free_temp(temp);
                    }
                    _ => {
                        return Err(LowerError::UnsupportedOp {
                            op: "MulU with shifted operand".to_string(),
                        });
                    }
                }

                // Move results to destination registers
                let dst_lo_reg = self.get_dst_reg(*dst_lo)?;
                if dst_lo_reg != PhysReg::Rax {
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_mov_rr(dst_lo_reg, PhysReg::Rax, *width);
                }

                if let Some(hi) = dst_hi {
                    let dst_hi_reg = self.get_dst_reg(*hi)?;
                    if dst_hi_reg != PhysReg::Rdx {
                        let mut emitter = X86Emitter::new(&mut self.code);
                        emitter.emit_mov_rr(dst_hi_reg, PhysReg::Rdx, *width);
                    }
                }
            }

            OpKind::DivU {
                quot,
                rem,
                src1,
                src2,
                width,
            } => {
                // Unsigned divide: RDX:RAX / src2 -> RAX (quot), RDX (rem)
                // For unsigned, RDX must be zero
                let src1_reg = self.get_reg(*src1)?;
                {
                    let mut emitter = X86Emitter::new(&mut self.code);
                    // Move dividend to RAX
                    emitter.emit_mov_rr(PhysReg::Rax, src1_reg, *width);
                    // Zero RDX
                    emitter.emit_zero_rdx();
                }

                match src2 {
                    SrcOperand::Reg(r) => {
                        let src2_reg = self.get_reg(*r)?;
                        let mut emitter = X86Emitter::new(&mut self.code);
                        emitter.emit_div(src2_reg, *width);
                    }
                    SrcOperand::Imm(val) => {
                        // DIV doesn't support immediate, need to load into temp
                        let temp = self.regalloc.get_scratch()?;
                        {
                            let mut emitter = X86Emitter::new(&mut self.code);
                            emitter.emit_mov_ri(temp, *val, *width);
                        }
                        let mut emitter = X86Emitter::new(&mut self.code);
                        emitter.emit_div(temp, *width);
                        self.regalloc.free_temp(temp);
                    }
                    _ => {
                        return Err(LowerError::UnsupportedOp {
                            op: "DivU with shifted operand".to_string(),
                        });
                    }
                }

                // Move results to destination registers
                let quot_reg = self.get_dst_reg(*quot)?;
                if quot_reg != PhysReg::Rax {
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_mov_rr(quot_reg, PhysReg::Rax, *width);
                }

                if let Some(r) = rem {
                    let rem_reg = self.get_dst_reg(*r)?;
                    if rem_reg != PhysReg::Rdx {
                        let mut emitter = X86Emitter::new(&mut self.code);
                        emitter.emit_mov_rr(rem_reg, PhysReg::Rdx, *width);
                    }
                }
            }

            OpKind::DivS {
                quot,
                rem,
                src1,
                src2,
                width,
            } => {
                // Signed divide: RDX:RAX / src2 -> RAX (quot), RDX (rem)
                // For signed, RDX must be sign-extension of RAX (via CQO/CDQ)
                let src1_reg = self.get_reg(*src1)?;
                {
                    let mut emitter = X86Emitter::new(&mut self.code);
                    // Move dividend to RAX
                    emitter.emit_mov_rr(PhysReg::Rax, src1_reg, *width);
                    // Sign-extend RAX into RDX:RAX
                    match width {
                        OpWidth::W64 => emitter.emit_cqo(),
                        OpWidth::W32 => emitter.emit_cdq(),
                        _ => {
                            // For 16-bit: CWD, for 8-bit: CBW
                            // We'll use the 32-bit form for smaller widths
                            emitter.emit_cdq();
                        }
                    }
                }

                match src2 {
                    SrcOperand::Reg(r) => {
                        let src2_reg = self.get_reg(*r)?;
                        let mut emitter = X86Emitter::new(&mut self.code);
                        emitter.emit_idiv(src2_reg, *width);
                    }
                    SrcOperand::Imm(val) => {
                        // IDIV doesn't support immediate, need to load into temp
                        let temp = self.regalloc.get_scratch()?;
                        {
                            let mut emitter = X86Emitter::new(&mut self.code);
                            emitter.emit_mov_ri(temp, *val, *width);
                        }
                        let mut emitter = X86Emitter::new(&mut self.code);
                        emitter.emit_idiv(temp, *width);
                        self.regalloc.free_temp(temp);
                    }
                    _ => {
                        return Err(LowerError::UnsupportedOp {
                            op: "DivS with shifted operand".to_string(),
                        });
                    }
                }

                // Move results to destination registers
                let quot_reg = self.get_dst_reg(*quot)?;
                if quot_reg != PhysReg::Rax {
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_mov_rr(quot_reg, PhysReg::Rax, *width);
                }

                if let Some(r) = rem {
                    let rem_reg = self.get_dst_reg(*r)?;
                    if rem_reg != PhysReg::Rdx {
                        let mut emitter = X86Emitter::new(&mut self.code);
                        emitter.emit_mov_rr(rem_reg, PhysReg::Rdx, *width);
                    }
                }
            }

            // ================================================================
            // Bitwise Operations
            // ================================================================
            OpKind::And {
                dst,
                src1,
                src2,
                width,
                ..
            } => {
                let dst_reg = self.get_dst_reg(*dst)?;
                let src1_reg = self.get_reg(*src1)?;

                if dst_reg != src1_reg {
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_mov_rr(dst_reg, src1_reg, *width);
                }

                match src2 {
                    SrcOperand::Reg(r) => {
                        let src2_reg = self.get_reg(*r)?;
                        let mut emitter = X86Emitter::new(&mut self.code);
                        let encoding = alu_hint.unwrap_or(X86AluEncoding::RmReg);
                        emitter.emit_alu_rr_dir(0x20, dst_reg, src2_reg, *width, encoding);
                    }
                    SrcOperand::Imm(val) => {
                        let mut emitter = X86Emitter::new(&mut self.code);
                        if matches!(alu_hint, Some(X86AluEncoding::AccImm))
                            && dst_reg == PhysReg::Rax
                        {
                            emitter.emit_alu_acc_imm(0x24, *val, *width);
                        } else {
                            emitter.emit_and_ri(dst_reg, *val, *width);
                        }
                    }
                    _ => {
                        return Err(LowerError::UnsupportedOp {
                            op: "And with shifted operand".to_string(),
                        });
                    }
                }
            }

            OpKind::Or {
                dst,
                src1,
                src2,
                width,
                ..
            } => {
                let dst_reg = self.get_dst_reg(*dst)?;
                let src1_reg = self.get_reg(*src1)?;

                if dst_reg != src1_reg {
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_mov_rr(dst_reg, src1_reg, *width);
                }

                match src2 {
                    SrcOperand::Reg(r) => {
                        let src2_reg = self.get_reg(*r)?;
                        let mut emitter = X86Emitter::new(&mut self.code);
                        let encoding = alu_hint.unwrap_or(X86AluEncoding::RmReg);
                        emitter.emit_alu_rr_dir(0x08, dst_reg, src2_reg, *width, encoding);
                    }
                    SrcOperand::Imm(val) => {
                        let mut emitter = X86Emitter::new(&mut self.code);
                        if matches!(alu_hint, Some(X86AluEncoding::AccImm))
                            && dst_reg == PhysReg::Rax
                        {
                            emitter.emit_alu_acc_imm(0x0C, *val, *width);
                        } else {
                            emitter.emit_or_ri(dst_reg, *val, *width);
                        }
                    }
                    _ => {
                        return Err(LowerError::UnsupportedOp {
                            op: "Or with shifted operand".to_string(),
                        });
                    }
                }
            }

            OpKind::Xor {
                dst,
                src1,
                src2,
                width,
                ..
            } => {
                let dst_reg = self.get_dst_reg(*dst)?;
                let src1_reg = self.get_reg(*src1)?;

                if dst_reg != src1_reg {
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_mov_rr(dst_reg, src1_reg, *width);
                }

                match src2 {
                    SrcOperand::Reg(r) => {
                        let src2_reg = self.get_reg(*r)?;
                        let mut emitter = X86Emitter::new(&mut self.code);
                        let encoding = alu_hint.unwrap_or(X86AluEncoding::RmReg);
                        emitter.emit_alu_rr_dir(0x30, dst_reg, src2_reg, *width, encoding);
                    }
                    SrcOperand::Imm(val) => {
                        let mut emitter = X86Emitter::new(&mut self.code);
                        if matches!(alu_hint, Some(X86AluEncoding::AccImm))
                            && dst_reg == PhysReg::Rax
                        {
                            emitter.emit_alu_acc_imm(0x34, *val, *width);
                        } else {
                            emitter.emit_xor_ri(dst_reg, *val, *width);
                        }
                    }
                    _ => {
                        return Err(LowerError::UnsupportedOp {
                            op: "Xor with shifted operand".to_string(),
                        });
                    }
                }
            }

            OpKind::Not { dst, src, width } => {
                let dst_reg = self.get_dst_reg(*dst)?;
                let src_reg = self.get_reg(*src)?;

                if dst_reg != src_reg {
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_mov_rr(dst_reg, src_reg, *width);
                }

                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_not(dst_reg, *width);
            }

            OpKind::Bsf {
                dst, src, width, ..
            } => {
                let dst_reg = self.get_dst_reg(*dst)?;
                let src_reg = self.get_reg(*src)?;
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_bsf(dst_reg, src_reg, *width);
            }

            OpKind::Bsr {
                dst, src, width, ..
            } => {
                let dst_reg = self.get_dst_reg(*dst)?;
                let src_reg = self.get_reg(*src)?;
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_bsr(dst_reg, src_reg, *width);
            }

            // ================================================================
            // Shifts
            // ================================================================
            OpKind::Shl {
                dst,
                src,
                amount,
                width,
                ..
            } => {
                let dst_reg = self.get_dst_reg(*dst)?;
                let src_reg = self.get_reg(*src)?;

                if dst_reg != src_reg {
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_mov_rr(dst_reg, src_reg, *width);
                }

                match amount {
                    SrcOperand::Imm(val) => {
                        let mut emitter = X86Emitter::new(&mut self.code);
                        emitter.emit_shl_ri(dst_reg, *val as u8, *width);
                    }
                    SrcOperand::Reg(r) => {
                        // Move shift amount to CL
                        let amt_reg = self.get_reg(*r)?;
                        if amt_reg != PhysReg::Rcx {
                            let mut emitter = X86Emitter::new(&mut self.code);
                            emitter.emit_mov_rr(PhysReg::Rcx, amt_reg, OpWidth::W8);
                        }
                        let mut emitter = X86Emitter::new(&mut self.code);
                        emitter.emit_shl_cl(dst_reg, *width);
                    }
                    _ => {
                        return Err(LowerError::UnsupportedOp {
                            op: "Shl with shifted operand".to_string(),
                        });
                    }
                }
            }

            OpKind::Shr {
                dst,
                src,
                amount,
                width,
                ..
            } => {
                let dst_reg = self.get_dst_reg(*dst)?;
                let src_reg = self.get_reg(*src)?;

                if dst_reg != src_reg {
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_mov_rr(dst_reg, src_reg, *width);
                }

                match amount {
                    SrcOperand::Imm(val) => {
                        let mut emitter = X86Emitter::new(&mut self.code);
                        emitter.emit_shr_ri(dst_reg, *val as u8, *width);
                    }
                    SrcOperand::Reg(r) => {
                        let amt_reg = self.get_reg(*r)?;
                        if amt_reg != PhysReg::Rcx {
                            let mut emitter = X86Emitter::new(&mut self.code);
                            emitter.emit_mov_rr(PhysReg::Rcx, amt_reg, OpWidth::W8);
                        }
                        let mut emitter = X86Emitter::new(&mut self.code);
                        emitter.emit_shr_cl(dst_reg, *width);
                    }
                    _ => {
                        return Err(LowerError::UnsupportedOp {
                            op: "Shr with shifted operand".to_string(),
                        });
                    }
                }
            }

            OpKind::Sar {
                dst,
                src,
                amount,
                width,
                ..
            } => {
                let dst_reg = self.get_dst_reg(*dst)?;
                let src_reg = self.get_reg(*src)?;

                if dst_reg != src_reg {
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_mov_rr(dst_reg, src_reg, *width);
                }

                match amount {
                    SrcOperand::Imm(val) => {
                        let mut emitter = X86Emitter::new(&mut self.code);
                        emitter.emit_sar_ri(dst_reg, *val as u8, *width);
                    }
                    SrcOperand::Reg(r) => {
                        let amt_reg = self.get_reg(*r)?;
                        if amt_reg != PhysReg::Rcx {
                            let mut emitter = X86Emitter::new(&mut self.code);
                            emitter.emit_mov_rr(PhysReg::Rcx, amt_reg, OpWidth::W8);
                        }
                        let mut emitter = X86Emitter::new(&mut self.code);
                        emitter.emit_sar_cl(dst_reg, *width);
                    }
                    _ => {
                        return Err(LowerError::UnsupportedOp {
                            op: "Sar with shifted operand".to_string(),
                        });
                    }
                }
            }

            OpKind::Rol {
                dst,
                src,
                amount,
                width,
                ..
            } => {
                let dst_reg = self.get_dst_reg(*dst)?;
                let src_reg = self.get_reg(*src)?;

                if dst_reg != src_reg {
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_mov_rr(dst_reg, src_reg, *width);
                }

                match amount {
                    SrcOperand::Imm(val) => {
                        let mut emitter = X86Emitter::new(&mut self.code);
                        emitter.emit_rol_ri(dst_reg, *val as u8, *width);
                    }
                    SrcOperand::Reg(r) => {
                        let amt_reg = self.get_reg(*r)?;
                        if amt_reg != PhysReg::Rcx {
                            let mut emitter = X86Emitter::new(&mut self.code);
                            emitter.emit_mov_rr(PhysReg::Rcx, amt_reg, OpWidth::W8);
                        }
                        let mut emitter = X86Emitter::new(&mut self.code);
                        emitter.emit_rol_cl(dst_reg, *width);
                    }
                    _ => {
                        return Err(LowerError::UnsupportedOp {
                            op: "Rol with shifted operand".to_string(),
                        });
                    }
                }
            }

            OpKind::Ror {
                dst,
                src,
                amount,
                width,
                ..
            } => {
                let dst_reg = self.get_dst_reg(*dst)?;
                let src_reg = self.get_reg(*src)?;

                if dst_reg != src_reg {
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_mov_rr(dst_reg, src_reg, *width);
                }

                match amount {
                    SrcOperand::Imm(val) => {
                        let mut emitter = X86Emitter::new(&mut self.code);
                        emitter.emit_ror_ri(dst_reg, *val as u8, *width);
                    }
                    SrcOperand::Reg(r) => {
                        let amt_reg = self.get_reg(*r)?;
                        if amt_reg != PhysReg::Rcx {
                            let mut emitter = X86Emitter::new(&mut self.code);
                            emitter.emit_mov_rr(PhysReg::Rcx, amt_reg, OpWidth::W8);
                        }
                        let mut emitter = X86Emitter::new(&mut self.code);
                        emitter.emit_ror_cl(dst_reg, *width);
                    }
                    _ => {
                        return Err(LowerError::UnsupportedOp {
                            op: "Ror with shifted operand".to_string(),
                        });
                    }
                }
            }

            OpKind::Shld {
                dst,
                src,
                amount,
                width,
                ..
            } => {
                let dst_reg = self.get_dst_reg(*dst)?;
                let src_reg = self.get_reg(*src)?;

                match amount {
                    SrcOperand::Imm(val) => {
                        let mut emitter = X86Emitter::new(&mut self.code);
                        emitter.emit_shld_rr_imm(dst_reg, src_reg, *val as u8, *width);
                    }
                    SrcOperand::Reg(r) => {
                        let amt_reg = self.get_reg(*r)?;
                        if amt_reg != PhysReg::Rcx {
                            return Err(LowerError::InvalidOperand {
                                op: "Shld".to_string(),
                                operand: "requires CL".to_string(),
                            });
                        }
                        let mut emitter = X86Emitter::new(&mut self.code);
                        emitter.emit_shld_rr_cl(dst_reg, src_reg, *width);
                    }
                    _ => {
                        return Err(LowerError::UnsupportedOp {
                            op: "Shld with shifted operand".to_string(),
                        });
                    }
                }
            }

            OpKind::Shrd {
                dst,
                src,
                amount,
                width,
                ..
            } => {
                let dst_reg = self.get_dst_reg(*dst)?;
                let src_reg = self.get_reg(*src)?;

                match amount {
                    SrcOperand::Imm(val) => {
                        let mut emitter = X86Emitter::new(&mut self.code);
                        emitter.emit_shrd_rr_imm(dst_reg, src_reg, *val as u8, *width);
                    }
                    SrcOperand::Reg(r) => {
                        let amt_reg = self.get_reg(*r)?;
                        if amt_reg != PhysReg::Rcx {
                            return Err(LowerError::InvalidOperand {
                                op: "Shrd".to_string(),
                                operand: "requires CL".to_string(),
                            });
                        }
                        let mut emitter = X86Emitter::new(&mut self.code);
                        emitter.emit_shrd_rr_cl(dst_reg, src_reg, *width);
                    }
                    _ => {
                        return Err(LowerError::UnsupportedOp {
                            op: "Shrd with shifted operand".to_string(),
                        });
                    }
                }
            }

            // ================================================================
            // Comparisons
            // ================================================================
            OpKind::Cmp { src1, src2, width } => {
                let src1_reg = self.get_reg(*src1)?;

                match src2 {
                    SrcOperand::Reg(r) => {
                        let src2_reg = self.get_reg(*r)?;
                        let mut emitter = X86Emitter::new(&mut self.code);
                        let encoding = alu_hint.unwrap_or(X86AluEncoding::RmReg);
                        emitter.emit_alu_rr_dir(0x38, src1_reg, src2_reg, *width, encoding);
                    }
                    SrcOperand::Imm(val) => {
                        let mut emitter = X86Emitter::new(&mut self.code);
                        if matches!(alu_hint, Some(X86AluEncoding::AccImm))
                            && src1_reg == PhysReg::Rax
                        {
                            emitter.emit_alu_acc_imm(0x3C, *val, *width);
                        } else {
                            emitter.emit_cmp_ri(src1_reg, *val, *width);
                        }
                    }
                    _ => {
                        return Err(LowerError::UnsupportedOp {
                            op: "Cmp with shifted operand".to_string(),
                        });
                    }
                }
            }

            OpKind::Test { src1, src2, width } => {
                let src1_reg = self.get_reg(*src1)?;

                match src2 {
                    SrcOperand::Reg(r) => {
                        let src2_reg = self.get_reg(*r)?;
                        let mut emitter = X86Emitter::new(&mut self.code);
                        emitter.emit_test_rr(src1_reg, src2_reg, *width);
                    }
                    SrcOperand::Imm(val) => {
                        let mut emitter = X86Emitter::new(&mut self.code);
                        emitter.emit_test_ri(src1_reg, *val, *width);
                    }
                    _ => {
                        return Err(LowerError::UnsupportedOp {
                            op: "Test with shifted operand".to_string(),
                        });
                    }
                }
            }

            OpKind::SetCC { dst, cond, width } => {
                let dst_reg = self.get_dst_reg(*dst)?;
                let x86_cond = X86Cond::from_condition(*cond);

                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_setcc(x86_cond, dst_reg);

                // Zero-extend to full width if needed
                if *width != OpWidth::W8 {
                    emitter.emit_movzx(dst_reg, dst_reg, OpWidth::W8, *width);
                }
            }

            OpKind::SetCF { value } => {
                let mut emitter = X86Emitter::new(&mut self.code);
                if *value {
                    emitter.emit_stc();
                } else {
                    emitter.emit_clc();
                }
            }

            OpKind::SetDF { value } => {
                let mut emitter = X86Emitter::new(&mut self.code);
                if *value {
                    emitter.emit_std();
                } else {
                    emitter.emit_cld();
                }
            }

            OpKind::CmcCF => {
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_cmc();
            }

            // ================================================================
            // Memory Operations
            // ================================================================
            OpKind::VLoad { dst, addr, width } => {
                let dst_reg = self.get_dst_reg(*dst)?;
                if !dst_reg.is_vec() {
                    return Err(LowerError::InvalidOperand {
                        op: "VLoad".to_string(),
                        operand: "destination must be vector register".to_string(),
                    });
                }
                if let Some(enc_hint) = self.vec_hint(op.x86_hint) {
                    let enc = self.coerce_vec_encoding(
                        VecEncoding {
                            width: *width,
                            ..enc_hint
                        },
                        &[dst_reg],
                    );
                    self.emit_vec_mem(enc, dst_reg, None, addr)?;
                } else {
                    if *width != VecWidth::V128 || self.vec_requires_vex(&[dst_reg]) {
                        let enc = self.coerce_vec_encoding(
                            self.default_vec_mov_encoding(*width, 0x6F, op.x86_hint),
                            &[dst_reg],
                        );
                        self.emit_vec_mem(enc, dst_reg, None, addr)?;
                    } else {
                        let prefix = self
                            .sse_prefix(op.x86_hint)
                            .or_else(|| self.vec_move_prefix(op.x86_hint));
                        self.emit_sse_mov_mem(prefix, 0x6F, dst_reg, addr)?;
                    }
                }
            }

            OpKind::VStore { src, addr, width } => {
                let src_reg = self.get_reg(*src)?;
                if !src_reg.is_vec() {
                    return Err(LowerError::InvalidOperand {
                        op: "VStore".to_string(),
                        operand: "source must be vector register".to_string(),
                    });
                }
                if let Some(enc_hint) = self.vec_hint(op.x86_hint) {
                    let enc = self.coerce_vec_encoding(
                        VecEncoding {
                            width: *width,
                            ..enc_hint
                        },
                        &[src_reg],
                    );
                    self.emit_vec_mem(enc, src_reg, None, addr)?;
                } else {
                    if *width != VecWidth::V128 || self.vec_requires_vex(&[src_reg]) {
                        let enc = self.coerce_vec_encoding(
                            self.default_vec_mov_encoding(*width, 0x7F, op.x86_hint),
                            &[src_reg],
                        );
                        self.emit_vec_mem(enc, src_reg, None, addr)?;
                    } else {
                        let prefix = self
                            .sse_prefix(op.x86_hint)
                            .or_else(|| self.vec_move_prefix(op.x86_hint));
                        self.emit_sse_mov_mem(prefix, 0x7F, src_reg, addr)?;
                    }
                }
            }

            OpKind::VMov { dst, src, width } => {
                let dst_reg = self.get_dst_reg(*dst)?;
                let src_reg = self.get_reg(*src)?;
                if !dst_reg.is_vec() || !src_reg.is_vec() {
                    return Err(LowerError::InvalidOperand {
                        op: "VMov".to_string(),
                        operand: "requires vector registers".to_string(),
                    });
                }
                if let Some(enc_hint) = self.vec_hint(op.x86_hint) {
                    let enc = self.coerce_vec_encoding(
                        VecEncoding {
                            width: *width,
                            ..enc_hint
                        },
                        &[dst_reg, src_reg],
                    );
                    let opcode = enc.opcode;
                    let (reg, rm) = if opcode == 0x7F || opcode == 0x29 {
                        (src_reg, dst_reg)
                    } else {
                        (dst_reg, src_reg)
                    };
                    self.emit_vec_rr(enc, reg, rm, 0x1F);
                } else {
                    if *width != VecWidth::V128 || self.vec_requires_vex(&[dst_reg, src_reg]) {
                        let enc = self.coerce_vec_encoding(
                            self.default_vec_mov_encoding(*width, 0x6F, op.x86_hint),
                            &[dst_reg, src_reg],
                        );
                        self.emit_vec_rr(enc, dst_reg, src_reg, 0x1F);
                    } else {
                        let prefix = self
                            .sse_prefix(op.x86_hint)
                            .or_else(|| self.vec_move_prefix(op.x86_hint));
                        let opcode = self.sse_opcode(op.x86_hint, 0x6F);
                        let (reg, rm) = if opcode == 0x7F {
                            (src_reg, dst_reg)
                        } else {
                            (dst_reg, src_reg)
                        };
                        let mut emitter = X86Emitter::new(&mut self.code);
                        emitter.emit_sse_mov_rr(prefix, opcode, reg, rm);
                    }
                }
            }

            OpKind::VAdd {
                dst,
                src1,
                src2,
                elem,
                lanes,
            } => {
                let width = self.vec_width_from_lanes(*elem, *lanes).ok_or_else(|| {
                    LowerError::UnsupportedOp {
                        op: format!("VAdd {:?}x{}", elem, lanes),
                    }
                })?;
                let dst_reg = self.get_dst_reg(*dst)?;
                let src1_reg = self.get_reg(*src1)?;
                let src2_reg = self.get_reg(*src2)?;
                if !dst_reg.is_vec() || !src1_reg.is_vec() || !src2_reg.is_vec() {
                    return Err(LowerError::InvalidOperand {
                        op: "VAdd".to_string(),
                        operand: "requires vector registers".to_string(),
                    });
                }

                if let Some(enc_hint) = self.vec_hint(op.x86_hint) {
                    let enc = self.coerce_vec_encoding(
                        VecEncoding { width, ..enc_hint },
                        &[dst_reg, src1_reg, src2_reg],
                    );
                    self.emit_vec_rrr(enc, dst_reg, src1_reg, src2_reg);
                } else if width != VecWidth::V128
                    || self.vec_requires_vex(&[dst_reg, src1_reg, src2_reg])
                {
                    let (map, pp, opcode) = match elem {
                        VecElementType::I32 => (X86VecMap::Map0F, X86SsePrefix::OpSize, 0xFE),
                        VecElementType::F32 => (X86VecMap::Map0F, X86SsePrefix::None, 0x58),
                        VecElementType::F64 => (X86VecMap::Map0F, X86SsePrefix::OpSize, 0x58),
                        _ => {
                            return Err(LowerError::UnsupportedOp {
                                op: format!("VAdd {:?}x{}", elem, lanes),
                            })
                        }
                    };
                    let kind = if self.vec_requires_evex(width, &[dst_reg, src1_reg, src2_reg]) {
                        VecEncodingKind::Evex
                    } else {
                        VecEncodingKind::Vex
                    };
                    let enc = VecEncoding {
                        kind,
                        map,
                        pp,
                        opcode,
                        width,
                    };
                    self.emit_vec_rrr(enc, dst_reg, src1_reg, src2_reg);
                } else {
                    let (prefix, opcode) = match elem {
                        VecElementType::I32 => (Some(0x66), 0xFE),
                        VecElementType::F32 => (None, 0x58),
                        VecElementType::F64 => (Some(0x66), 0x58),
                        _ => {
                            return Err(LowerError::UnsupportedOp {
                                op: format!("VAdd {:?}x{}", elem, lanes),
                            })
                        }
                    };
                    if dst_reg != src1_reg {
                        let mut emitter = X86Emitter::new(&mut self.code);
                        emitter.emit_sse_mov_rr(prefix, 0x6F, dst_reg, src1_reg);
                    }
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_sse_mov_rr(prefix, opcode, dst_reg, src2_reg);
                }
            }

            OpKind::VSub {
                dst,
                src1,
                src2,
                elem,
                lanes,
            } => {
                let width = self.vec_width_from_lanes(*elem, *lanes).ok_or_else(|| {
                    LowerError::UnsupportedOp {
                        op: format!("VSub {:?}x{}", elem, lanes),
                    }
                })?;
                let dst_reg = self.get_dst_reg(*dst)?;
                let src1_reg = self.get_reg(*src1)?;
                let src2_reg = self.get_reg(*src2)?;
                if !dst_reg.is_vec() || !src1_reg.is_vec() || !src2_reg.is_vec() {
                    return Err(LowerError::InvalidOperand {
                        op: "VSub".to_string(),
                        operand: "requires vector registers".to_string(),
                    });
                }

                if let Some(enc_hint) = self.vec_hint(op.x86_hint) {
                    let enc = self.coerce_vec_encoding(
                        VecEncoding { width, ..enc_hint },
                        &[dst_reg, src1_reg, src2_reg],
                    );
                    self.emit_vec_rrr(enc, dst_reg, src1_reg, src2_reg);
                } else if width != VecWidth::V128
                    || self.vec_requires_vex(&[dst_reg, src1_reg, src2_reg])
                {
                    let (map, pp, opcode) = match elem {
                        VecElementType::I32 => (X86VecMap::Map0F, X86SsePrefix::OpSize, 0xFA),
                        VecElementType::F32 => (X86VecMap::Map0F, X86SsePrefix::None, 0x5C),
                        VecElementType::F64 => (X86VecMap::Map0F, X86SsePrefix::OpSize, 0x5C),
                        _ => {
                            return Err(LowerError::UnsupportedOp {
                                op: format!("VSub {:?}x{}", elem, lanes),
                            })
                        }
                    };
                    let kind = if self.vec_requires_evex(width, &[dst_reg, src1_reg, src2_reg]) {
                        VecEncodingKind::Evex
                    } else {
                        VecEncodingKind::Vex
                    };
                    let enc = VecEncoding {
                        kind,
                        map,
                        pp,
                        opcode,
                        width,
                    };
                    self.emit_vec_rrr(enc, dst_reg, src1_reg, src2_reg);
                } else {
                    let (prefix, opcode) = match elem {
                        VecElementType::I32 => (Some(0x66), 0xFA),
                        VecElementType::F32 => (None, 0x5C),
                        VecElementType::F64 => (Some(0x66), 0x5C),
                        _ => {
                            return Err(LowerError::UnsupportedOp {
                                op: format!("VSub {:?}x{}", elem, lanes),
                            })
                        }
                    };
                    if dst_reg != src1_reg {
                        let mut emitter = X86Emitter::new(&mut self.code);
                        emitter.emit_sse_mov_rr(prefix, 0x6F, dst_reg, src1_reg);
                    }
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_sse_mov_rr(prefix, opcode, dst_reg, src2_reg);
                }
            }

            OpKind::VMax {
                dst,
                src1,
                src2,
                elem,
                lanes,
            } => {
                let width = self.vec_width_from_lanes(*elem, *lanes).ok_or_else(|| {
                    LowerError::UnsupportedOp {
                        op: format!("VMax {:?}x{}", elem, lanes),
                    }
                })?;
                let dst_reg = self.get_dst_reg(*dst)?;
                let src1_reg = self.get_reg(*src1)?;
                let src2_reg = self.get_reg(*src2)?;
                if !dst_reg.is_vec() || !src1_reg.is_vec() || !src2_reg.is_vec() {
                    return Err(LowerError::InvalidOperand {
                        op: "VMax".to_string(),
                        operand: "requires vector registers".to_string(),
                    });
                }

                if let Some(enc_hint) = self.vec_hint(op.x86_hint) {
                    let enc = self.coerce_vec_encoding(
                        VecEncoding { width, ..enc_hint },
                        &[dst_reg, src1_reg, src2_reg],
                    );
                    self.emit_vec_rrr(enc, dst_reg, src1_reg, src2_reg);
                } else if width != VecWidth::V128
                    || self.vec_requires_vex(&[dst_reg, src1_reg, src2_reg])
                {
                    let (map, pp, opcode) = match elem {
                        VecElementType::F32 => (X86VecMap::Map0F, X86SsePrefix::None, 0x5F),
                        VecElementType::F64 => (X86VecMap::Map0F, X86SsePrefix::OpSize, 0x5F),
                        _ => {
                            return Err(LowerError::UnsupportedOp {
                                op: format!("VMax {:?}x{}", elem, lanes),
                            })
                        }
                    };
                    let kind = if self.vec_requires_evex(width, &[dst_reg, src1_reg, src2_reg]) {
                        VecEncodingKind::Evex
                    } else {
                        VecEncodingKind::Vex
                    };
                    let enc = VecEncoding {
                        kind,
                        map,
                        pp,
                        opcode,
                        width,
                    };
                    self.emit_vec_rrr(enc, dst_reg, src1_reg, src2_reg);
                } else {
                    let (prefix, opcode) = match elem {
                        VecElementType::F32 => (None, 0x5F),
                        VecElementType::F64 => (Some(0x66), 0x5F),
                        _ => {
                            return Err(LowerError::UnsupportedOp {
                                op: format!("VMax {:?}x{}", elem, lanes),
                            })
                        }
                    };
                    if dst_reg != src1_reg {
                        let mut emitter = X86Emitter::new(&mut self.code);
                        emitter.emit_sse_mov_rr(prefix, 0x6F, dst_reg, src1_reg);
                    }
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_sse_mov_rr(prefix, opcode, dst_reg, src2_reg);
                }
            }

            OpKind::VMul {
                dst,
                src1,
                src2,
                elem,
                lanes,
            } => {
                let width = self.vec_width_from_lanes(*elem, *lanes).ok_or_else(|| {
                    LowerError::UnsupportedOp {
                        op: format!("VMul {:?}x{}", elem, lanes),
                    }
                })?;
                let dst_reg = self.get_dst_reg(*dst)?;
                let src1_reg = self.get_reg(*src1)?;
                let src2_reg = self.get_reg(*src2)?;
                if !dst_reg.is_vec() || !src1_reg.is_vec() || !src2_reg.is_vec() {
                    return Err(LowerError::InvalidOperand {
                        op: "VMul".to_string(),
                        operand: "requires vector registers".to_string(),
                    });
                }

                if let Some(enc_hint) = self.vec_hint(op.x86_hint) {
                    let enc = self.coerce_vec_encoding(
                        VecEncoding { width, ..enc_hint },
                        &[dst_reg, src1_reg, src2_reg],
                    );
                    self.emit_vec_rrr(enc, dst_reg, src1_reg, src2_reg);
                } else if width != VecWidth::V128
                    || self.vec_requires_vex(&[dst_reg, src1_reg, src2_reg])
                {
                    let (map, pp, opcode) = match elem {
                        VecElementType::I32 => (X86VecMap::Map0F38, X86SsePrefix::OpSize, 0x40),
                        VecElementType::F32 => (X86VecMap::Map0F, X86SsePrefix::None, 0x59),
                        VecElementType::F64 => (X86VecMap::Map0F, X86SsePrefix::OpSize, 0x59),
                        _ => {
                            return Err(LowerError::UnsupportedOp {
                                op: format!("VMul {:?}x{}", elem, lanes),
                            })
                        }
                    };
                    let kind = if self.vec_requires_evex(width, &[dst_reg, src1_reg, src2_reg]) {
                        VecEncodingKind::Evex
                    } else {
                        VecEncodingKind::Vex
                    };
                    let enc = VecEncoding {
                        kind,
                        map,
                        pp,
                        opcode,
                        width,
                    };
                    self.emit_vec_rrr(enc, dst_reg, src1_reg, src2_reg);
                } else {
                    match elem {
                        VecElementType::I32 => {
                            if dst_reg != src1_reg {
                                let mut emitter = X86Emitter::new(&mut self.code);
                                emitter.emit_sse_mov_rr(Some(0x66), 0x6F, dst_reg, src1_reg);
                            }
                            let mut emitter = X86Emitter::new(&mut self.code);
                            emitter.emit_sse_op38_rr(Some(0x66), 0x40, dst_reg, src2_reg);
                        }
                        VecElementType::F32 | VecElementType::F64 => {
                            let prefix = if matches!(elem, VecElementType::F64) {
                                Some(0x66)
                            } else {
                                None
                            };
                            if dst_reg != src1_reg {
                                let mut emitter = X86Emitter::new(&mut self.code);
                                emitter.emit_sse_mov_rr(prefix, 0x6F, dst_reg, src1_reg);
                            }
                            let mut emitter = X86Emitter::new(&mut self.code);
                            emitter.emit_sse_mov_rr(prefix, 0x59, dst_reg, src2_reg);
                        }
                        _ => {
                            return Err(LowerError::UnsupportedOp {
                                op: format!("VMul {:?}x{}", elem, lanes),
                            })
                        }
                    }
                }
            }

            OpKind::VShift {
                dst,
                src,
                amount,
                shift,
                elem,
                lanes,
            } => {
                if *shift != ShiftOp::Lsl || *elem != VecElementType::I32 {
                    return Err(LowerError::UnsupportedOp {
                        op: format!("VShift {:?} {:?}x{}", shift, elem, lanes),
                    });
                }
                let imm = match amount {
                    SrcOperand::Imm(val) => {
                        if *val < 0 || *val > u8::MAX as i64 {
                            return Err(LowerError::InvalidOperand {
                                op: "VShift".to_string(),
                                operand: "imm out of range".to_string(),
                            });
                        }
                        *val as u8
                    }
                    _ => {
                        return Err(LowerError::UnsupportedOp {
                            op: "VShift with non-imm".to_string(),
                        });
                    }
                };

                let width = self.vec_width_from_lanes(*elem, *lanes).ok_or_else(|| {
                    LowerError::UnsupportedOp {
                        op: format!("VShift {:?}x{}", elem, lanes),
                    }
                })?;
                let dst_reg = self.get_dst_reg(*dst)?;
                let src_reg = self.get_reg(*src)?;
                if !dst_reg.is_vec() || !src_reg.is_vec() {
                    return Err(LowerError::InvalidOperand {
                        op: "VShift".to_string(),
                        operand: "requires vector registers".to_string(),
                    });
                }

                if let Some(enc_hint) = self.vec_hint(op.x86_hint) {
                    let enc = self.coerce_vec_encoding(
                        VecEncoding { width, ..enc_hint },
                        &[dst_reg, src_reg],
                    );
                    self.emit_vec_shift_imm(enc, dst_reg, src_reg, imm);
                } else if width != VecWidth::V128 || self.vec_requires_vex(&[dst_reg, src_reg]) {
                    let kind = if self.vec_requires_evex(width, &[dst_reg, src_reg]) {
                        VecEncodingKind::Evex
                    } else {
                        VecEncodingKind::Vex
                    };
                    let enc = VecEncoding {
                        kind,
                        map: X86VecMap::Map0F,
                        pp: X86SsePrefix::OpSize,
                        opcode: 0x72,
                        width,
                    };
                    self.emit_vec_shift_imm(enc, dst_reg, src_reg, imm);
                } else {
                    let prefix = Some(0x66);
                    if dst_reg != src_reg {
                        let mut emitter = X86Emitter::new(&mut self.code);
                        emitter.emit_sse_mov_rr(prefix, 0x6F, dst_reg, src_reg);
                    }
                    let mut emitter = X86Emitter::new(&mut self.code);
                    if let Some(prefix) = prefix {
                        emitter.code.emit_u8(prefix);
                    }
                    emitter.emit_rex_for_xmm(dst_reg, dst_reg);
                    emitter.code.emit_u8(0x0F);
                    emitter.code.emit_u8(0x72);
                    emitter.emit_modrm_digit(0b11, 6, dst_reg);
                    emitter.code.emit_u8(imm);
                }
            }

            OpKind::Load {
                dst,
                addr,
                width,
                sign,
            } => {
                let dst_reg = self.get_dst_reg(*dst)?;
                let op_width = width.to_op_width().unwrap_or(OpWidth::W64);
                let preserve_x86_partial = matches!(dst, VReg::Arch(ArchReg::X86(_)))
                    && matches!(op_width, OpWidth::W8 | OpWidth::W16)
                    && matches!(sign, SignExtend::Zero);
                let needs_extend = op_width != OpWidth::W64 && !preserve_x86_partial;

                match addr {
                    Address::Direct(base) => {
                        let base_reg = self.get_reg(*base)?;
                        let mut emitter = X86Emitter::new(&mut self.code);
                        emitter.emit_mov_rm(dst_reg, base_reg, 0, op_width);

                        // Sign/zero extend if loading smaller than 64-bit
                        if needs_extend {
                            match sign {
                                SignExtend::Zero => {
                                    // 32-bit loads automatically zero-extend
                                    if op_width != OpWidth::W32 {
                                        emitter.emit_movzx(
                                            dst_reg,
                                            dst_reg,
                                            op_width,
                                            OpWidth::W64,
                                        );
                                    }
                                }
                                SignExtend::Sign => {
                                    emitter.emit_movsx(dst_reg, dst_reg, op_width, OpWidth::W64);
                                }
                            }
                        }
                    }
                    Address::BaseOffset {
                        base,
                        offset,
                        disp_size,
                    } => {
                        let base_reg = self.get_reg(*base)?;
                        let mut emitter = X86Emitter::new(&mut self.code);
                        emitter.emit_mov_rm_disp(
                            dst_reg,
                            base_reg,
                            *offset as i32,
                            *disp_size,
                            op_width,
                        );

                        if needs_extend {
                            match sign {
                                SignExtend::Zero => {
                                    if op_width != OpWidth::W32 {
                                        emitter.emit_movzx(
                                            dst_reg,
                                            dst_reg,
                                            op_width,
                                            OpWidth::W64,
                                        );
                                    }
                                }
                                SignExtend::Sign => {
                                    emitter.emit_movsx(dst_reg, dst_reg, op_width, OpWidth::W64);
                                }
                            }
                        }
                    }
                    Address::PcRel { offset, base, .. } => {
                        let disp_offset = {
                            let mut emitter = X86Emitter::new(&mut self.code);
                            emitter.emit_mov_rm_pcrel(dst_reg, 0, op_width)
                        };
                        let insn_end = self.code.position();

                        let disp = if let Some(base_pc) = base {
                            let target = (*base_pc as i64 + *offset) as u64;
                            let disp = if self.pcrel_adjust {
                                let next_rip = self.guest_base as i64 + insn_end as i64;
                                target as i64 - next_rip
                            } else {
                                *offset
                            };
                            if disp < i32::MIN as i64 || disp > i32::MAX as i64 {
                                return Err(LowerError::InvalidOperand {
                                    op: "Load".to_string(),
                                    operand: "PcRel offset out of range".to_string(),
                                });
                            }
                            self.relocations.push(Relocation {
                                offset: disp_offset,
                                kind: RelocKind::PcRel32,
                                target: RelocTarget::GuestAddr(target),
                            });
                            disp
                        } else {
                            let disp = *offset;
                            if disp < i32::MIN as i64 || disp > i32::MAX as i64 {
                                return Err(LowerError::InvalidOperand {
                                    op: "Load".to_string(),
                                    operand: "PcRel offset out of range".to_string(),
                                });
                            }
                            disp
                        };

                        self.code.patch_i32(disp_offset, disp as i32);

                        if needs_extend {
                            match sign {
                                SignExtend::Zero => {
                                    if op_width != OpWidth::W32 {
                                        let mut emitter = X86Emitter::new(&mut self.code);
                                        emitter.emit_movzx(
                                            dst_reg,
                                            dst_reg,
                                            op_width,
                                            OpWidth::W64,
                                        );
                                    }
                                }
                                SignExtend::Sign => {
                                    let mut emitter = X86Emitter::new(&mut self.code);
                                    emitter.emit_movsx(dst_reg, dst_reg, op_width, OpWidth::W64);
                                }
                            }
                        }
                    }
                    Address::Absolute(abs_addr) => {
                        let mut emitter = X86Emitter::new(&mut self.code);
                        emitter.emit_mov_rm_abs(dst_reg, *abs_addr, op_width);

                        if needs_extend {
                            match sign {
                                SignExtend::Zero => {
                                    if op_width != OpWidth::W32 {
                                        emitter.emit_movzx(
                                            dst_reg,
                                            dst_reg,
                                            op_width,
                                            OpWidth::W64,
                                        );
                                    }
                                }
                                SignExtend::Sign => {
                                    emitter.emit_movsx(dst_reg, dst_reg, op_width, OpWidth::W64);
                                }
                            }
                        }
                    }
                    Address::BaseIndexScale {
                        base,
                        index,
                        scale,
                        disp,
                        disp_size,
                    } => {
                        let base_reg = base.map(|b| self.get_reg(b)).transpose()?;
                        let index_reg = self.get_reg(*index)?;
                        let mut emitter = X86Emitter::new(&mut self.code);
                        emitter.emit_mov_rm_sib_disp(
                            dst_reg, base_reg, index_reg, *scale, *disp, *disp_size, op_width,
                        );

                        if needs_extend {
                            match sign {
                                SignExtend::Zero => {
                                    if op_width != OpWidth::W32 {
                                        emitter.emit_movzx(
                                            dst_reg,
                                            dst_reg,
                                            op_width,
                                            OpWidth::W64,
                                        );
                                    }
                                }
                                SignExtend::Sign => {
                                    emitter.emit_movsx(dst_reg, dst_reg, op_width, OpWidth::W64);
                                }
                            }
                        }
                    }
                    _ => {
                        return Err(LowerError::UnsupportedOp {
                            op: format!("Load with unsupported addressing: {:?}", addr),
                        });
                    }
                }
            }

            OpKind::Store { src, addr, width } => {
                let op_width = width.to_op_width().unwrap_or(OpWidth::W64);

                if let VReg::Imm(imm) = src {
                    let imm_ok = match op_width {
                        OpWidth::W64 => *imm >= i32::MIN as i64 && *imm <= i32::MAX as i64,
                        OpWidth::W128 => false,
                        _ => true,
                    };

                    if imm_ok {
                        match addr {
                            Address::Direct(base) => {
                                let base_reg = self.get_reg(*base)?;
                                let mut emitter = X86Emitter::new(&mut self.code);
                                emitter.emit_mov_mi_disp(
                                    base_reg,
                                    0,
                                    DispSize::Auto,
                                    *imm,
                                    op_width,
                                );
                                return Ok(());
                            }
                            Address::BaseOffset {
                                base,
                                offset,
                                disp_size,
                            } => {
                                let base_reg = self.get_reg(*base)?;
                                let mut emitter = X86Emitter::new(&mut self.code);
                                emitter.emit_mov_mi_disp(
                                    base_reg,
                                    *offset as i32,
                                    *disp_size,
                                    *imm,
                                    op_width,
                                );
                                return Ok(());
                            }
                            Address::PcRel { offset, base, .. } => {
                                let disp_offset = {
                                    let mut emitter = X86Emitter::new(&mut self.code);
                                    emitter.emit_mov_mi_pcrel(0, op_width, *imm)
                                };
                                let insn_end = self.code.position();

                                let disp = if let Some(base_pc) = base {
                                    let target = (*base_pc as i64 + *offset) as u64;
                                    let disp = if self.pcrel_adjust {
                                        let next_rip = self.guest_base as i64 + insn_end as i64;
                                        target as i64 - next_rip
                                    } else {
                                        *offset
                                    };
                                    if disp < i32::MIN as i64 || disp > i32::MAX as i64 {
                                        return Err(LowerError::InvalidOperand {
                                            op: "Store".to_string(),
                                            operand: "PcRel offset out of range".to_string(),
                                        });
                                    }
                                    self.relocations.push(Relocation {
                                        offset: disp_offset,
                                        kind: RelocKind::PcRel32,
                                        target: RelocTarget::GuestAddr(target),
                                    });
                                    disp
                                } else {
                                    let disp = *offset;
                                    if disp < i32::MIN as i64 || disp > i32::MAX as i64 {
                                        return Err(LowerError::InvalidOperand {
                                            op: "Store".to_string(),
                                            operand: "PcRel offset out of range".to_string(),
                                        });
                                    }
                                    disp
                                };

                                self.code.patch_i32(disp_offset, disp as i32);
                                return Ok(());
                            }
                            Address::Absolute(abs_addr) => {
                                let mut emitter = X86Emitter::new(&mut self.code);
                                emitter.emit_mov_mi_abs(*abs_addr, *imm, op_width);
                                return Ok(());
                            }
                            Address::BaseIndexScale {
                                base,
                                index,
                                scale,
                                disp,
                                disp_size,
                            } => {
                                let base_reg = base.map(|b| self.get_reg(b)).transpose()?;
                                let index_reg = self.get_reg(*index)?;
                                let mut emitter = X86Emitter::new(&mut self.code);
                                emitter.emit_mov_mi_sib_disp(
                                    base_reg, index_reg, *scale, *disp, *disp_size, *imm, op_width,
                                );
                                return Ok(());
                            }
                            _ => {}
                        }
                    }
                }

                let src_reg = self.get_reg(*src)?;

                match addr {
                    Address::Direct(base) => {
                        let base_reg = self.get_reg(*base)?;
                        let mut emitter = X86Emitter::new(&mut self.code);
                        emitter.emit_mov_mr(base_reg, 0, src_reg, op_width);
                    }
                    Address::BaseOffset {
                        base,
                        offset,
                        disp_size,
                    } => {
                        let base_reg = self.get_reg(*base)?;
                        let mut emitter = X86Emitter::new(&mut self.code);
                        emitter.emit_mov_mr_disp(
                            base_reg,
                            *offset as i32,
                            *disp_size,
                            src_reg,
                            op_width,
                        );
                    }
                    Address::PcRel { offset, base, .. } => {
                        let disp_offset = {
                            let mut emitter = X86Emitter::new(&mut self.code);
                            emitter.emit_mov_mr_pcrel(0, src_reg, op_width)
                        };
                        let insn_end = self.code.position();

                        let disp = if let Some(base_pc) = base {
                            let target = (*base_pc as i64 + *offset) as u64;
                            let disp = if self.pcrel_adjust {
                                let next_rip = self.guest_base as i64 + insn_end as i64;
                                target as i64 - next_rip
                            } else {
                                *offset
                            };
                            if disp < i32::MIN as i64 || disp > i32::MAX as i64 {
                                return Err(LowerError::InvalidOperand {
                                    op: "Store".to_string(),
                                    operand: "PcRel offset out of range".to_string(),
                                });
                            }
                            self.relocations.push(Relocation {
                                offset: disp_offset,
                                kind: RelocKind::PcRel32,
                                target: RelocTarget::GuestAddr(target),
                            });
                            disp
                        } else {
                            let disp = *offset;
                            if disp < i32::MIN as i64 || disp > i32::MAX as i64 {
                                return Err(LowerError::InvalidOperand {
                                    op: "Store".to_string(),
                                    operand: "PcRel offset out of range".to_string(),
                                });
                            }
                            disp
                        };

                        self.code.patch_i32(disp_offset, disp as i32);
                    }
                    Address::Absolute(abs_addr) => {
                        let mut emitter = X86Emitter::new(&mut self.code);
                        emitter.emit_mov_mr_abs(*abs_addr, src_reg, op_width);
                    }
                    Address::BaseIndexScale {
                        base,
                        index,
                        scale,
                        disp,
                        disp_size,
                    } => {
                        let base_reg = base.map(|b| self.get_reg(b)).transpose()?;
                        let index_reg = self.get_reg(*index)?;
                        let mut emitter = X86Emitter::new(&mut self.code);
                        emitter.emit_mov_mr_sib_disp(
                            base_reg, index_reg, *scale, *disp, *disp_size, src_reg, op_width,
                        );
                    }
                    _ => {
                        return Err(LowerError::UnsupportedOp {
                            op: format!("Store with unsupported addressing: {:?}", addr),
                        });
                    }
                }
            }

            OpKind::RepStos {
                dst,
                src,
                count,
                width,
            } => {
                let dst_reg = self.get_reg(*dst)?;
                let src_reg = self.get_reg(*src)?;
                let count_reg = self.get_reg(*count)?;

                if dst_reg != PhysReg::Rdi || src_reg != PhysReg::Rax || count_reg != PhysReg::Rcx {
                    return Err(LowerError::InvalidOperand {
                        op: "RepStos".to_string(),
                        operand: "requires RDI/RAX/RCX".to_string(),
                    });
                }

                let mut emitter = X86Emitter::new(&mut self.code);
                match width {
                    MemWidth::B1 | MemWidth::B2 | MemWidth::B4 | MemWidth::B8 => {
                        emitter.emit_rep_stos(*width);
                    }
                    _ => {
                        return Err(LowerError::UnsupportedOp {
                            op: format!("RepStos width {:?}", width),
                        });
                    }
                }
            }

            OpKind::RepMovs {
                dst,
                src,
                count,
                width,
            } => {
                let dst_reg = self.get_reg(*dst)?;
                let src_reg = self.get_reg(*src)?;
                let count_reg = self.get_reg(*count)?;

                if dst_reg != PhysReg::Rdi || src_reg != PhysReg::Rsi || count_reg != PhysReg::Rcx {
                    return Err(LowerError::InvalidOperand {
                        op: "RepMovs".to_string(),
                        operand: "requires RDI/RSI/RCX".to_string(),
                    });
                }

                let mut emitter = X86Emitter::new(&mut self.code);
                match width {
                    MemWidth::B1 | MemWidth::B2 | MemWidth::B4 | MemWidth::B8 => {
                        emitter.emit_rep_movs(*width);
                    }
                    _ => {
                        return Err(LowerError::UnsupportedOp {
                            op: format!("RepMovs width {:?}", width),
                        });
                    }
                }
            }

            OpKind::IoIn { dst, port, width } => {
                let dst_reg = self.get_dst_reg(*dst)?;
                if dst_reg != PhysReg::Rax {
                    return Err(LowerError::InvalidOperand {
                        op: "IoIn".to_string(),
                        operand: "destination must be RAX".to_string(),
                    });
                }

                let imm_port = if let VReg::Imm(val) = port {
                    if *val < 0 || *val > u8::MAX as i64 {
                        return Err(LowerError::InvalidOperand {
                            op: "IoIn".to_string(),
                            operand: "port immediate out of range".to_string(),
                        });
                    }
                    Some(*val as u8)
                } else {
                    None
                };

                if imm_port.is_none() {
                    let port_reg = self.get_reg(*port)?;
                    if port_reg != PhysReg::Rdx {
                        return Err(LowerError::InvalidOperand {
                            op: "IoIn".to_string(),
                            operand: "port must be DX".to_string(),
                        });
                    }
                }

                match width {
                    MemWidth::B1 => {
                        if let Some(port) = imm_port {
                            self.code.emit_u8(0xE4);
                            self.code.emit_u8(port);
                        } else {
                            self.code.emit_u8(0xEC);
                        }
                    }
                    MemWidth::B2 => {
                        self.code.emit_u8(0x66);
                        if let Some(port) = imm_port {
                            self.code.emit_u8(0xE5);
                            self.code.emit_u8(port);
                        } else {
                            self.code.emit_u8(0xED);
                        }
                    }
                    MemWidth::B4 => {
                        if let Some(port) = imm_port {
                            self.code.emit_u8(0xE5);
                            self.code.emit_u8(port);
                        } else {
                            self.code.emit_u8(0xED);
                        }
                    }
                    _ => {
                        return Err(LowerError::UnsupportedOp {
                            op: format!("IoIn width {:?}", width),
                        });
                    }
                }
            }

            OpKind::IoOut { port, value, width } => {
                let value_reg = self.get_reg(*value)?;
                if value_reg != PhysReg::Rax {
                    return Err(LowerError::InvalidOperand {
                        op: "IoOut".to_string(),
                        operand: "value must be RAX".to_string(),
                    });
                }

                let imm_port = if let VReg::Imm(val) = port {
                    if *val < 0 || *val > u8::MAX as i64 {
                        return Err(LowerError::InvalidOperand {
                            op: "IoOut".to_string(),
                            operand: "port immediate out of range".to_string(),
                        });
                    }
                    Some(*val as u8)
                } else {
                    None
                };

                if imm_port.is_none() {
                    let port_reg = self.get_reg(*port)?;
                    if port_reg != PhysReg::Rdx {
                        return Err(LowerError::InvalidOperand {
                            op: "IoOut".to_string(),
                            operand: "port must be DX".to_string(),
                        });
                    }
                }

                match width {
                    MemWidth::B1 => {
                        if let Some(port) = imm_port {
                            self.code.emit_u8(0xE6);
                            self.code.emit_u8(port);
                        } else {
                            self.code.emit_u8(0xEE);
                        }
                    }
                    MemWidth::B2 => {
                        self.code.emit_u8(0x66);
                        if let Some(port) = imm_port {
                            self.code.emit_u8(0xE7);
                            self.code.emit_u8(port);
                        } else {
                            self.code.emit_u8(0xEF);
                        }
                    }
                    MemWidth::B4 => {
                        if let Some(port) = imm_port {
                            self.code.emit_u8(0xE7);
                            self.code.emit_u8(port);
                        } else {
                            self.code.emit_u8(0xEF);
                        }
                    }
                    _ => {
                        return Err(LowerError::UnsupportedOp {
                            op: format!("IoOut width {:?}", width),
                        });
                    }
                }
            }

            // ================================================================
            // Extensions
            // ================================================================
            OpKind::ZeroExtend {
                dst,
                src,
                from_width,
                to_width,
            } => {
                let dst_reg = self.get_dst_reg(*dst)?;
                let src_reg = self.get_reg(*src)?;

                let mut emitter = X86Emitter::new(&mut self.code);
                if *from_width == OpWidth::W32 && *to_width == OpWidth::W64 {
                    // 32-bit mov automatically zero-extends
                    emitter.emit_mov_rr(dst_reg, src_reg, OpWidth::W32);
                } else {
                    emitter.emit_movzx(dst_reg, src_reg, *from_width, *to_width);
                }
            }

            OpKind::SignExtend {
                dst,
                src,
                from_width,
                to_width,
            } => {
                let dst_reg = self.get_dst_reg(*dst)?;
                let src_reg = self.get_reg(*src)?;

                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_movsx(dst_reg, src_reg, *from_width, *to_width);
            }

            OpKind::Cwd { dst, src, width } => {
                if !matches!(src, VReg::Arch(ArchReg::X86(X86Reg::Rax)))
                    || !matches!(dst, VReg::Arch(ArchReg::X86(X86Reg::Rdx)))
                {
                    return Err(LowerError::InvalidOperand {
                        op: "Cwd".to_string(),
                        operand: "requires RAX/RDX".to_string(),
                    });
                }

                let mut emitter = X86Emitter::new(&mut self.code);
                match width {
                    OpWidth::W16 => emitter.emit_cwd(),
                    OpWidth::W32 => emitter.emit_cdq(),
                    OpWidth::W64 => emitter.emit_cqo(),
                    _ => {
                        return Err(LowerError::UnsupportedOp {
                            op: format!("Cwd width {:?}", width),
                        });
                    }
                }
            }

            // ================================================================
            // Misc
            // ================================================================
            OpKind::Nop => {
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_nop();
            }

            OpKind::Breakpoint => {
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_int3();
            }

            OpKind::Leave => {
                self.code.emit_u8(0xC9);
            }

            OpKind::Undefined { .. } => {
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_ud2();
            }

            // Unimplemented ops
            _ => {
                return Err(LowerError::UnsupportedOp {
                    op: format!("{:?}", op.kind),
                });
            }
        }

        Ok(())
    }

    /// Lower a block terminator
    fn lower_terminator(&mut self, term: &Terminator) -> Result<(), LowerError> {
        match term {
            Terminator::Branch { target } => {
                // Record jump to fix up later
                let jump_offset = self.code.position();
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_jmp_rel32(0); // Placeholder
                self.pending_jumps
                    .push((jump_offset + 1, *target, RelocKind::PcRel32));
            }

            Terminator::CondBranch {
                cond,
                true_target,
                false_target,
            } => {
                // Determine the native condition for the taken branch. If
                // `lower_block` folded a trailing `TestCondition` (the common
                // guest-Jcc shape), branch directly off the live guest flags
                // with the guest condition — no register is touched. Otherwise
                // fall back to materializing the cond vreg and `test`ing it.
                let taken = if let Some(c) = self.pending_cond.take() {
                    X86Cond::from_condition(c)
                } else {
                    let cond_reg = self.get_reg(*cond)?;
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_test_rr(cond_reg, cond_reg, OpWidth::W64);
                    X86Cond::Ne
                };

                // Jcc<taken> true_target
                let jnz_offset = self.code.position();
                {
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_jcc_rel32(taken, 0); // Placeholder
                }
                self.pending_jumps
                    .push((jnz_offset + 2, *true_target, RelocKind::PcRel32));

                // JMP false_target
                let jmp_offset = self.code.position();
                {
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_jmp_rel32(0); // Placeholder
                }
                self.pending_jumps
                    .push((jmp_offset + 1, *false_target, RelocKind::PcRel32));
            }

            Terminator::IndirectBranch { target, .. } => {
                let target_reg = self.get_reg(*target)?;
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_jmp_reg(target_reg);
            }

            Terminator::IndirectBranchMem { addr, .. } => {
                self.emit_group5_mem(4, addr)?;
            }

            Terminator::Return { .. } => {
                let ret_imm = self.pending_ret_imm.take();
                self.emit_epilogue_with_ret(ret_imm);
            }

            Terminator::Call {
                target,
                continuation,
                ..
            } => match target {
                CallTarget::GuestAddr(addr) => {
                    let call_pos = self.code.position();
                    let next_rip = if self.pcrel_adjust {
                        self.guest_base as i64 + (call_pos + 5) as i64
                    } else {
                        self.block_guest_pcs
                            .get(continuation)
                            .copied()
                            .unwrap_or(self.guest_base + (call_pos + 5) as u64)
                            as i64
                    };
                    let rel = *addr as i64 - next_rip;
                    if rel < i32::MIN as i64 || rel > i32::MAX as i64 {
                        return Err(LowerError::RelocationOutOfRange {
                            offset: call_pos,
                            target: *addr as usize,
                        });
                    }
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_call_rel32(rel as i32);
                }
                CallTarget::Indirect(reg) => {
                    let target_reg = self.get_reg(*reg)?;
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_call_reg(target_reg);
                }
                CallTarget::IndirectMem(addr) => {
                    self.emit_group5_mem(2, addr)?;
                }
                _ => {
                    return Err(LowerError::UnsupportedOp {
                        op: format!("Call target {:?}", target),
                    });
                }
            },

            Terminator::TailCall { target, .. } => match target {
                CallTarget::GuestAddr(addr) => {
                    let jmp_pos = self.code.position();
                    let next_rip = if self.pcrel_adjust {
                        self.guest_base as i64 + (jmp_pos + 5) as i64
                    } else {
                        self.guest_base as i64 + (jmp_pos + 5) as i64
                    };
                    let rel = *addr as i64 - next_rip;
                    if rel < i32::MIN as i64 || rel > i32::MAX as i64 {
                        return Err(LowerError::RelocationOutOfRange {
                            offset: jmp_pos,
                            target: *addr as usize,
                        });
                    }
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_jmp_rel32(rel as i32);
                }
                CallTarget::Indirect(reg) => {
                    let target_reg = self.get_reg(*reg)?;
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_jmp_reg(target_reg);
                }
                CallTarget::IndirectMem(addr) => {
                    self.emit_group5_mem(4, addr)?;
                }
                _ => {
                    return Err(LowerError::UnsupportedOp {
                        op: format!("TailCall target {:?}", target),
                    });
                }
            },

            Terminator::Unreachable => {
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_ud2();
            }

            _ => {
                return Err(LowerError::UnsupportedOp {
                    op: format!("Terminator: {:?}", term),
                });
            }
        }

        Ok(())
    }

    fn is_rsp(&self, vreg: VReg) -> bool {
        matches!(vreg, VReg::Arch(ArchReg::X86(X86Reg::Rsp)))
    }

    fn sse_prefix(&self, hint: Option<X86OpHint>) -> Option<u8> {
        match hint {
            Some(X86OpHint::SseMov { prefix, .. }) | Some(X86OpHint::SseOp { prefix, .. }) => {
                match prefix {
                    X86SsePrefix::None => None,
                    X86SsePrefix::OpSize => Some(0x66),
                    X86SsePrefix::Rep => Some(0xF3),
                    X86SsePrefix::Repne => Some(0xF2),
                }
            }
            _ => None,
        }
    }

    fn sse_opcode(&self, hint: Option<X86OpHint>, default: u8) -> u8 {
        match hint {
            Some(X86OpHint::SseMov { opcode, .. }) | Some(X86OpHint::SseOp { opcode, .. }) => {
                opcode
            }
            _ => default,
        }
    }

    fn vec_hint(&self, hint: Option<X86OpHint>) -> Option<VecEncoding> {
        match hint {
            Some(X86OpHint::VexOp {
                map,
                pp,
                opcode,
                width,
            }) => Some(VecEncoding {
                kind: VecEncodingKind::Vex,
                map,
                pp,
                opcode,
                width,
            }),
            Some(X86OpHint::EvexOp {
                map,
                pp,
                opcode,
                width,
            }) => Some(VecEncoding {
                kind: VecEncodingKind::Evex,
                map,
                pp,
                opcode,
                width,
            }),
            _ => None,
        }
    }

    fn vec_requires_vex(&self, regs: &[PhysReg]) -> bool {
        regs.iter()
            .any(|reg| reg.is_ymm() || reg.is_zmm() || reg.vec_ext2() != 0)
    }

    fn vec_requires_evex(&self, width: VecWidth, regs: &[PhysReg]) -> bool {
        width == VecWidth::V512 || regs.iter().any(|reg| reg.is_zmm() || reg.vec_ext2() != 0)
    }

    fn coerce_vec_encoding(&self, mut encoding: VecEncoding, regs: &[PhysReg]) -> VecEncoding {
        if self.vec_requires_evex(encoding.width, regs) {
            encoding.kind = VecEncodingKind::Evex;
        }
        encoding
    }

    fn vec_move_pp(&self, hint: Option<X86OpHint>) -> X86SsePrefix {
        match hint {
            Some(X86OpHint::VecAlign(X86VecAlign::Aligned)) => X86SsePrefix::OpSize,
            Some(X86OpHint::VecAlign(X86VecAlign::Unaligned)) => X86SsePrefix::Rep,
            _ => X86SsePrefix::Rep,
        }
    }

    fn vec_move_prefix(&self, hint: Option<X86OpHint>) -> Option<u8> {
        match self.vec_move_pp(hint) {
            X86SsePrefix::OpSize => Some(0x66),
            X86SsePrefix::Rep => Some(0xF3),
            X86SsePrefix::Repne => Some(0xF2),
            X86SsePrefix::None => None,
        }
    }

    fn default_vec_mov_encoding(
        &self,
        width: VecWidth,
        opcode: u8,
        hint: Option<X86OpHint>,
    ) -> VecEncoding {
        VecEncoding {
            kind: VecEncodingKind::Vex,
            map: X86VecMap::Map0F,
            pp: self.vec_move_pp(hint),
            opcode,
            width,
        }
    }

    fn vec_width_from_lanes(&self, elem: VecElementType, lanes: u8) -> Option<VecWidth> {
        if lanes == VecWidth::V128.lanes(elem) as u8 {
            Some(VecWidth::V128)
        } else if lanes == VecWidth::V256.lanes(elem) as u8 {
            Some(VecWidth::V256)
        } else if lanes == VecWidth::V512.lanes(elem) as u8 {
            Some(VecWidth::V512)
        } else {
            None
        }
    }

    fn emit_sse_mov_mem(
        &mut self,
        prefix: Option<u8>,
        opcode: u8,
        reg: PhysReg,
        addr: &Address,
    ) -> Result<(), LowerError> {
        match addr {
            Address::Direct(base) => {
                let base_reg = self.get_reg(*base)?;
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_sse_mov_rm_disp(prefix, opcode, reg, base_reg, 0, DispSize::Auto);
            }
            Address::BaseOffset {
                base,
                offset,
                disp_size,
            } => {
                let base_reg = self.get_reg(*base)?;
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_sse_mov_rm_disp(
                    prefix,
                    opcode,
                    reg,
                    base_reg,
                    *offset as i32,
                    *disp_size,
                );
            }
            Address::BaseIndexScale {
                base,
                index,
                scale,
                disp,
                disp_size,
            } => {
                let base_reg = base.map(|b| self.get_reg(b)).transpose()?;
                let index_reg = self.get_reg(*index)?;
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_sse_mov_rm_sib_disp(
                    prefix, opcode, reg, base_reg, index_reg, *scale, *disp, *disp_size,
                );
            }
            Address::PcRel { offset, base, .. } => {
                let disp_offset = {
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_sse_mov_rm_pcrel(prefix, opcode, reg, 0)
                };
                let insn_end = self.code.position();

                let disp = if let Some(base_pc) = base {
                    let target = (*base_pc as i64 + *offset) as u64;
                    let disp = if self.pcrel_adjust {
                        let next_rip = self.guest_base as i64 + insn_end as i64;
                        target as i64 - next_rip
                    } else {
                        *offset
                    };
                    if disp < i32::MIN as i64 || disp > i32::MAX as i64 {
                        return Err(LowerError::InvalidOperand {
                            op: "PcRel SSE mov".to_string(),
                            operand: "offset out of range".to_string(),
                        });
                    }
                    self.relocations.push(Relocation {
                        offset: disp_offset,
                        kind: RelocKind::PcRel32,
                        target: RelocTarget::GuestAddr(target),
                    });
                    disp
                } else {
                    let disp = *offset;
                    if disp < i32::MIN as i64 || disp > i32::MAX as i64 {
                        return Err(LowerError::InvalidOperand {
                            op: "PcRel SSE mov".to_string(),
                            operand: "offset out of range".to_string(),
                        });
                    }
                    disp
                };

                self.code.patch_i32(disp_offset, disp as i32);
            }
            Address::Absolute(addr) => {
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_sse_mov_rm_abs(prefix, opcode, reg, *addr);
            }
            _ => {
                return Err(LowerError::UnsupportedOp {
                    op: format!("SSE mov with unsupported addressing: {:?}", addr),
                });
            }
        }

        Ok(())
    }

    fn emit_sse_op38_mem(
        &mut self,
        prefix: Option<u8>,
        opcode: u8,
        reg: PhysReg,
        addr: &Address,
    ) -> Result<(), LowerError> {
        match addr {
            Address::Direct(base) => {
                let base_reg = self.get_reg(*base)?;
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_sse_op38_rm_disp(prefix, opcode, reg, base_reg, 0, DispSize::Auto);
            }
            Address::BaseOffset {
                base,
                offset,
                disp_size,
            } => {
                let base_reg = self.get_reg(*base)?;
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_sse_op38_rm_disp(
                    prefix,
                    opcode,
                    reg,
                    base_reg,
                    *offset as i32,
                    *disp_size,
                );
            }
            Address::BaseIndexScale {
                base,
                index,
                scale,
                disp,
                disp_size,
            } => {
                let base_reg = base.map(|b| self.get_reg(b)).transpose()?;
                let index_reg = self.get_reg(*index)?;
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_sse_op38_rm_sib_disp(
                    prefix, opcode, reg, base_reg, index_reg, *scale, *disp, *disp_size,
                );
            }
            Address::PcRel { offset, base, .. } => {
                let disp_offset = {
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_sse_op38_rm_pcrel(prefix, opcode, reg, 0)
                };
                let insn_end = self.code.position();

                let disp = if let Some(base_pc) = base {
                    let target = (*base_pc as i64 + *offset) as u64;
                    let disp = if self.pcrel_adjust {
                        let next_rip = self.guest_base as i64 + insn_end as i64;
                        target as i64 - next_rip
                    } else {
                        *offset
                    };
                    if disp < i32::MIN as i64 || disp > i32::MAX as i64 {
                        return Err(LowerError::InvalidOperand {
                            op: "PcRel SSE 0F 38".to_string(),
                            operand: "offset out of range".to_string(),
                        });
                    }
                    self.relocations.push(Relocation {
                        offset: disp_offset,
                        kind: RelocKind::PcRel32,
                        target: RelocTarget::GuestAddr(target),
                    });
                    disp
                } else {
                    let disp = *offset;
                    if disp < i32::MIN as i64 || disp > i32::MAX as i64 {
                        return Err(LowerError::InvalidOperand {
                            op: "PcRel SSE 0F 38".to_string(),
                            operand: "offset out of range".to_string(),
                        });
                    }
                    disp
                };

                self.code.patch_i32(disp_offset, disp as i32);
            }
            Address::Absolute(addr) => {
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_sse_op38_rm_abs(prefix, opcode, reg, *addr);
            }
            _ => {
                return Err(LowerError::UnsupportedOp {
                    op: format!("SSE 0F 38 with unsupported addressing: {:?}", addr),
                });
            }
        }

        Ok(())
    }

    fn emit_vec_mem(
        &mut self,
        encoding: VecEncoding,
        reg: PhysReg,
        vvvv_reg: Option<PhysReg>,
        addr: &Address,
    ) -> Result<(), LowerError> {
        let encoding = match vvvv_reg {
            Some(vreg) => self.coerce_vec_encoding(encoding, &[reg, vreg]),
            None => self.coerce_vec_encoding(encoding, &[reg]),
        };
        let vvvv = vvvv_reg.map_or(0x1F, |vreg| vreg.encoding() & 0x1F);
        let r = reg.vec_ext();
        let r2 = reg.vec_ext2();

        match addr {
            Address::Direct(base) => {
                let base_reg = self.get_reg(*base)?;
                let b = base_reg.vec_ext();
                let b2 = base_reg.vec_ext2();
                let mut emitter = X86Emitter::new(&mut self.code);
                match encoding.kind {
                    VecEncodingKind::Vex => {
                        emitter.emit_vex_prefix(
                            encoding.map,
                            encoding.pp,
                            encoding.width,
                            false,
                            r,
                            0,
                            b,
                            vvvv,
                        );
                    }
                    VecEncodingKind::Evex => {
                        emitter.emit_evex_prefix(
                            encoding.map,
                            encoding.pp,
                            encoding.width,
                            false,
                            r,
                            0,
                            b,
                            r2,
                            0,
                            b2,
                            vvvv,
                        );
                    }
                }
                emitter.code.emit_u8(encoding.opcode);
                emitter.emit_modrm_mem_disp(reg, base_reg, 0, DispSize::Auto);
            }
            Address::BaseOffset {
                base,
                offset,
                disp_size,
            } => {
                let base_reg = self.get_reg(*base)?;
                let b = base_reg.vec_ext();
                let b2 = base_reg.vec_ext2();
                let mut emitter = X86Emitter::new(&mut self.code);
                match encoding.kind {
                    VecEncodingKind::Vex => {
                        emitter.emit_vex_prefix(
                            encoding.map,
                            encoding.pp,
                            encoding.width,
                            false,
                            r,
                            0,
                            b,
                            vvvv,
                        );
                    }
                    VecEncodingKind::Evex => {
                        emitter.emit_evex_prefix(
                            encoding.map,
                            encoding.pp,
                            encoding.width,
                            false,
                            r,
                            0,
                            b,
                            r2,
                            0,
                            b2,
                            vvvv,
                        );
                    }
                }
                emitter.code.emit_u8(encoding.opcode);
                emitter.emit_modrm_mem_disp(reg, base_reg, *offset as i32, *disp_size);
            }
            Address::BaseIndexScale {
                base,
                index,
                scale,
                disp,
                disp_size,
            } => {
                let base_reg = base.map(|b| self.get_reg(b)).transpose()?;
                let index_reg = self.get_reg(*index)?;
                let base_bits = base_reg.unwrap_or(PhysReg::Rbp);
                let b = base_bits.vec_ext();
                let b2 = base_bits.vec_ext2();
                let x = index_reg.vec_ext();
                let x2 = index_reg.vec_ext2();
                let mut emitter = X86Emitter::new(&mut self.code);
                match encoding.kind {
                    VecEncodingKind::Vex => {
                        emitter.emit_vex_prefix(
                            encoding.map,
                            encoding.pp,
                            encoding.width,
                            false,
                            r,
                            x,
                            b,
                            vvvv,
                        );
                    }
                    VecEncodingKind::Evex => {
                        emitter.emit_evex_prefix(
                            encoding.map,
                            encoding.pp,
                            encoding.width,
                            false,
                            r,
                            x,
                            b,
                            r2,
                            x2,
                            b2,
                            vvvv,
                        );
                    }
                }
                emitter.code.emit_u8(encoding.opcode);
                emitter.emit_modrm_sib_disp(reg, base_reg, index_reg, *scale, *disp, *disp_size);
            }
            Address::PcRel { offset, base, .. } => {
                let disp_offset = {
                    let mut emitter = X86Emitter::new(&mut self.code);
                    match encoding.kind {
                        VecEncodingKind::Vex => {
                            emitter.emit_vex_prefix(
                                encoding.map,
                                encoding.pp,
                                encoding.width,
                                false,
                                r,
                                0,
                                0,
                                vvvv,
                            );
                        }
                        VecEncodingKind::Evex => {
                            emitter.emit_evex_prefix(
                                encoding.map,
                                encoding.pp,
                                encoding.width,
                                false,
                                r,
                                0,
                                0,
                                r2,
                                0,
                                0,
                                vvvv,
                            );
                        }
                    }
                    emitter.code.emit_u8(encoding.opcode);
                    emitter.emit_modrm_pcrel(reg, 0)
                };
                let insn_end = self.code.position();

                let disp = if let Some(base_pc) = base {
                    let target = (*base_pc as i64 + *offset) as u64;
                    let disp = if self.pcrel_adjust {
                        let next_rip = self.guest_base as i64 + insn_end as i64;
                        target as i64 - next_rip
                    } else {
                        *offset
                    };
                    if disp < i32::MIN as i64 || disp > i32::MAX as i64 {
                        return Err(LowerError::InvalidOperand {
                            op: "PcRel VEX/EVEX".to_string(),
                            operand: "offset out of range".to_string(),
                        });
                    }
                    self.relocations.push(Relocation {
                        offset: disp_offset,
                        kind: RelocKind::PcRel32,
                        target: RelocTarget::GuestAddr(target),
                    });
                    disp
                } else {
                    let disp = *offset;
                    if disp < i32::MIN as i64 || disp > i32::MAX as i64 {
                        return Err(LowerError::InvalidOperand {
                            op: "PcRel VEX/EVEX".to_string(),
                            operand: "offset out of range".to_string(),
                        });
                    }
                    disp
                };

                self.code.patch_i32(disp_offset, disp as i32);
            }
            Address::Absolute(addr) => {
                let mut emitter = X86Emitter::new(&mut self.code);
                match encoding.kind {
                    VecEncodingKind::Vex => {
                        emitter.emit_vex_prefix(
                            encoding.map,
                            encoding.pp,
                            encoding.width,
                            false,
                            r,
                            0,
                            0,
                            vvvv,
                        );
                    }
                    VecEncodingKind::Evex => {
                        emitter.emit_evex_prefix(
                            encoding.map,
                            encoding.pp,
                            encoding.width,
                            false,
                            r,
                            0,
                            0,
                            r2,
                            0,
                            0,
                            vvvv,
                        );
                    }
                }
                emitter.code.emit_u8(encoding.opcode);
                emitter.emit_modrm_abs(reg, *addr);
            }
            _ => {
                return Err(LowerError::UnsupportedOp {
                    op: format!("VEX/EVEX with unsupported addressing: {:?}", addr),
                });
            }
        }

        Ok(())
    }

    fn emit_vec_rrr(&mut self, encoding: VecEncoding, dst: PhysReg, src1: PhysReg, src2: PhysReg) {
        let encoding = self.coerce_vec_encoding(encoding, &[dst, src1, src2]);
        let mut emitter = X86Emitter::new(&mut self.code);
        match encoding.kind {
            VecEncodingKind::Vex => {
                emitter.emit_vex_rrr(
                    encoding.map,
                    encoding.pp,
                    encoding.width,
                    encoding.opcode,
                    dst,
                    src1,
                    src2,
                );
            }
            VecEncodingKind::Evex => {
                emitter.emit_evex_rrr(
                    encoding.map,
                    encoding.pp,
                    encoding.width,
                    encoding.opcode,
                    dst,
                    src1,
                    src2,
                );
            }
        }
    }

    fn emit_vec_rr(&mut self, encoding: VecEncoding, reg: PhysReg, rm: PhysReg, vvvv: u8) {
        let encoding = self.coerce_vec_encoding(encoding, &[reg, rm]);
        let r = reg.vec_ext();
        let r2 = reg.vec_ext2();
        let b = rm.vec_ext();
        let b2 = rm.vec_ext2();
        let mut emitter = X86Emitter::new(&mut self.code);
        match encoding.kind {
            VecEncodingKind::Vex => {
                emitter.emit_vex_prefix(
                    encoding.map,
                    encoding.pp,
                    encoding.width,
                    false,
                    r,
                    0,
                    b,
                    vvvv,
                );
            }
            VecEncodingKind::Evex => {
                emitter.emit_evex_prefix(
                    encoding.map,
                    encoding.pp,
                    encoding.width,
                    false,
                    r,
                    0,
                    b,
                    r2,
                    0,
                    b2,
                    vvvv,
                );
            }
        }
        emitter.code.emit_u8(encoding.opcode);
        emitter.emit_modrm_rr(reg, rm);
    }

    fn emit_vec_shift_imm(&mut self, encoding: VecEncoding, dst: PhysReg, src: PhysReg, imm: u8) {
        let encoding = self.coerce_vec_encoding(encoding, &[dst, src]);
        let b = src.vec_ext();
        let b2 = src.vec_ext2();
        let vvvv = dst.encoding() & 0x1F;
        let mut emitter = X86Emitter::new(&mut self.code);
        match encoding.kind {
            VecEncodingKind::Vex => {
                emitter.emit_vex_prefix(
                    encoding.map,
                    encoding.pp,
                    encoding.width,
                    false,
                    0,
                    0,
                    b,
                    vvvv,
                );
            }
            VecEncodingKind::Evex => {
                emitter.emit_evex_prefix(
                    encoding.map,
                    encoding.pp,
                    encoding.width,
                    false,
                    0,
                    0,
                    b,
                    0,
                    0,
                    b2,
                    vvvv,
                );
            }
        }
        emitter.code.emit_u8(encoding.opcode);
        emitter.emit_modrm_digit(0b11, 6, src);
        emitter.code.emit_u8(imm);
    }

    fn emit_movzx_mem(
        &mut self,
        dst: PhysReg,
        addr: &Address,
        src_width: OpWidth,
        dst_width: OpWidth,
    ) -> Result<(), LowerError> {
        match addr {
            Address::Direct(base) => {
                let base_reg = self.get_reg(*base)?;
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_movzx_rm_disp(dst, base_reg, 0, DispSize::Auto, src_width, dst_width);
            }
            Address::BaseOffset {
                base,
                offset,
                disp_size,
            } => {
                let base_reg = self.get_reg(*base)?;
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_movzx_rm_disp(
                    dst,
                    base_reg,
                    *offset as i32,
                    *disp_size,
                    src_width,
                    dst_width,
                );
            }
            Address::BaseIndexScale {
                base,
                index,
                scale,
                disp,
                disp_size,
            } => {
                let base_reg = base.map(|b| self.get_reg(b)).transpose()?;
                let index_reg = self.get_reg(*index)?;
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_movzx_rm_sib_disp(
                    dst, base_reg, index_reg, *scale, *disp, *disp_size, src_width, dst_width,
                );
            }
            Address::PcRel { offset, base, .. } => {
                let disp_offset = {
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_movzx_rm_pcrel(dst, 0, src_width, dst_width)
                };
                let insn_end = self.code.position();

                let disp = if let Some(base_pc) = base {
                    let target = (*base_pc as i64 + *offset) as u64;
                    let disp = if self.pcrel_adjust {
                        let next_rip = self.guest_base as i64 + insn_end as i64;
                        target as i64 - next_rip
                    } else {
                        *offset
                    };
                    if disp < i32::MIN as i64 || disp > i32::MAX as i64 {
                        return Err(LowerError::InvalidOperand {
                            op: "PcRel movzx".to_string(),
                            operand: "offset out of range".to_string(),
                        });
                    }
                    self.relocations.push(Relocation {
                        offset: disp_offset,
                        kind: RelocKind::PcRel32,
                        target: RelocTarget::GuestAddr(target),
                    });
                    disp
                } else {
                    let disp = *offset;
                    if disp < i32::MIN as i64 || disp > i32::MAX as i64 {
                        return Err(LowerError::InvalidOperand {
                            op: "PcRel movzx".to_string(),
                            operand: "offset out of range".to_string(),
                        });
                    }
                    disp
                };

                self.code.patch_i32(disp_offset, disp as i32);
            }
            Address::Absolute(addr) => {
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_movzx_rm_abs(dst, *addr, src_width, dst_width);
            }
            _ => {
                return Err(LowerError::UnsupportedOp {
                    op: format!("Movzx with unsupported addressing: {:?}", addr),
                });
            }
        }

        Ok(())
    }

    fn emit_movsx_mem(
        &mut self,
        dst: PhysReg,
        addr: &Address,
        src_width: OpWidth,
        dst_width: OpWidth,
    ) -> Result<(), LowerError> {
        match addr {
            Address::Direct(base) => {
                let base_reg = self.get_reg(*base)?;
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_movsx_rm_disp(dst, base_reg, 0, DispSize::Auto, src_width, dst_width);
            }
            Address::BaseOffset {
                base,
                offset,
                disp_size,
            } => {
                let base_reg = self.get_reg(*base)?;
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_movsx_rm_disp(
                    dst,
                    base_reg,
                    *offset as i32,
                    *disp_size,
                    src_width,
                    dst_width,
                );
            }
            Address::BaseIndexScale {
                base,
                index,
                scale,
                disp,
                disp_size,
            } => {
                let base_reg = base.map(|b| self.get_reg(b)).transpose()?;
                let index_reg = self.get_reg(*index)?;
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_movsx_rm_sib_disp(
                    dst, base_reg, index_reg, *scale, *disp, *disp_size, src_width, dst_width,
                );
            }
            Address::PcRel { offset, base, .. } => {
                let disp_offset = {
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_movsx_rm_pcrel(dst, 0, src_width, dst_width)
                };
                let insn_end = self.code.position();

                let disp = if let Some(base_pc) = base {
                    let target = (*base_pc as i64 + *offset) as u64;
                    let disp = if self.pcrel_adjust {
                        let next_rip = self.guest_base as i64 + insn_end as i64;
                        target as i64 - next_rip
                    } else {
                        *offset
                    };
                    if disp < i32::MIN as i64 || disp > i32::MAX as i64 {
                        return Err(LowerError::InvalidOperand {
                            op: "PcRel movsx".to_string(),
                            operand: "offset out of range".to_string(),
                        });
                    }
                    self.relocations.push(Relocation {
                        offset: disp_offset,
                        kind: RelocKind::PcRel32,
                        target: RelocTarget::GuestAddr(target),
                    });
                    disp
                } else {
                    let disp = *offset;
                    if disp < i32::MIN as i64 || disp > i32::MAX as i64 {
                        return Err(LowerError::InvalidOperand {
                            op: "PcRel movsx".to_string(),
                            operand: "offset out of range".to_string(),
                        });
                    }
                    disp
                };

                self.code.patch_i32(disp_offset, disp as i32);
            }
            Address::Absolute(addr) => {
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_movsx_rm_abs(dst, *addr, src_width, dst_width);
            }
            _ => {
                return Err(LowerError::UnsupportedOp {
                    op: format!("Movsx with unsupported addressing: {:?}", addr),
                });
            }
        }

        Ok(())
    }

    fn emit_alu_mem_reg(
        &mut self,
        opcode: u8,
        addr: &Address,
        reg: PhysReg,
        width: OpWidth,
        encoding: X86AluEncoding,
    ) -> Result<(), LowerError> {
        match addr {
            Address::Direct(base) => {
                let base_reg = self.get_reg(*base)?;
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_alu_mem_disp(
                    opcode,
                    reg,
                    base_reg,
                    0,
                    DispSize::Auto,
                    width,
                    encoding,
                );
            }
            Address::BaseOffset {
                base,
                offset,
                disp_size,
            } => {
                let base_reg = self.get_reg(*base)?;
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_alu_mem_disp(
                    opcode,
                    reg,
                    base_reg,
                    *offset as i32,
                    *disp_size,
                    width,
                    encoding,
                );
            }
            Address::BaseIndexScale {
                base,
                index,
                scale,
                disp,
                disp_size,
            } => {
                let base_reg = base.map(|b| self.get_reg(b)).transpose()?;
                let index_reg = self.get_reg(*index)?;
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_alu_mem_sib_disp(
                    opcode, reg, base_reg, index_reg, *scale, *disp, *disp_size, width, encoding,
                );
            }
            Address::PcRel { offset, base, .. } => {
                let disp_offset = {
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_alu_mem_pcrel(opcode, reg, 0, width, encoding)
                };
                let insn_end = self.code.position();

                let disp = if let Some(base_pc) = base {
                    let target = (*base_pc as i64 + *offset) as u64;
                    let disp = if self.pcrel_adjust {
                        let next_rip = self.guest_base as i64 + insn_end as i64;
                        target as i64 - next_rip
                    } else {
                        *offset
                    };
                    if disp < i32::MIN as i64 || disp > i32::MAX as i64 {
                        return Err(LowerError::InvalidOperand {
                            op: "PcRel ALU".to_string(),
                            operand: "offset out of range".to_string(),
                        });
                    }
                    self.relocations.push(Relocation {
                        offset: disp_offset,
                        kind: RelocKind::PcRel32,
                        target: RelocTarget::GuestAddr(target),
                    });
                    disp
                } else {
                    let disp = *offset;
                    if disp < i32::MIN as i64 || disp > i32::MAX as i64 {
                        return Err(LowerError::InvalidOperand {
                            op: "PcRel ALU".to_string(),
                            operand: "offset out of range".to_string(),
                        });
                    }
                    disp
                };

                self.code.patch_i32(disp_offset, disp as i32);
            }
            Address::Absolute(addr) => {
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_alu_mem_abs(opcode, reg, *addr, width, encoding);
            }
            _ => {
                return Err(LowerError::UnsupportedOp {
                    op: format!("ALU with unsupported addressing: {:?}", addr),
                });
            }
        }

        Ok(())
    }

    fn emit_alu_mem_imm(
        &mut self,
        digit: u8,
        addr: &Address,
        imm: i64,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        match addr {
            Address::Direct(base) => {
                let base_reg = self.get_reg(*base)?;
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_alu_mi_disp(digit, base_reg, 0, DispSize::Auto, imm, width);
            }
            Address::BaseOffset {
                base,
                offset,
                disp_size,
            } => {
                let base_reg = self.get_reg(*base)?;
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_alu_mi_disp(digit, base_reg, *offset as i32, *disp_size, imm, width);
            }
            Address::BaseIndexScale {
                base,
                index,
                scale,
                disp,
                disp_size,
            } => {
                let base_reg = base.map(|b| self.get_reg(b)).transpose()?;
                let index_reg = self.get_reg(*index)?;
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_alu_mi_sib_disp(
                    digit, base_reg, index_reg, *scale, *disp, *disp_size, imm, width,
                );
            }
            Address::PcRel { offset, base, .. } => {
                let disp_offset = {
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_alu_mi_pcrel(digit, 0, imm, width)
                };
                let insn_end = self.code.position();

                let disp = if let Some(base_pc) = base {
                    let target = (*base_pc as i64 + *offset) as u64;
                    let disp = if self.pcrel_adjust {
                        let next_rip = self.guest_base as i64 + insn_end as i64;
                        target as i64 - next_rip
                    } else {
                        *offset
                    };
                    if disp < i32::MIN as i64 || disp > i32::MAX as i64 {
                        return Err(LowerError::InvalidOperand {
                            op: "PcRel ALU imm".to_string(),
                            operand: "offset out of range".to_string(),
                        });
                    }
                    self.relocations.push(Relocation {
                        offset: disp_offset,
                        kind: RelocKind::PcRel32,
                        target: RelocTarget::GuestAddr(target),
                    });
                    disp
                } else {
                    let disp = *offset;
                    if disp < i32::MIN as i64 || disp > i32::MAX as i64 {
                        return Err(LowerError::InvalidOperand {
                            op: "PcRel ALU imm".to_string(),
                            operand: "offset out of range".to_string(),
                        });
                    }
                    disp
                };

                self.code.patch_i32(disp_offset, disp as i32);
            }
            Address::Absolute(addr) => {
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_alu_mi_abs(digit, *addr, imm, width);
            }
            _ => {
                return Err(LowerError::UnsupportedOp {
                    op: format!("ALU imm with unsupported addressing: {:?}", addr),
                });
            }
        }

        Ok(())
    }

    fn emit_test_mem_reg(
        &mut self,
        addr: &Address,
        reg: PhysReg,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        match addr {
            Address::Direct(base) => {
                let base_reg = self.get_reg(*base)?;
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_test_mr_disp(base_reg, 0, DispSize::Auto, reg, width);
            }
            Address::BaseOffset {
                base,
                offset,
                disp_size,
            } => {
                let base_reg = self.get_reg(*base)?;
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_test_mr_disp(base_reg, *offset as i32, *disp_size, reg, width);
            }
            Address::BaseIndexScale {
                base,
                index,
                scale,
                disp,
                disp_size,
            } => {
                let base_reg = base.map(|b| self.get_reg(b)).transpose()?;
                let index_reg = self.get_reg(*index)?;
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_test_mr_sib_disp(
                    base_reg, index_reg, *scale, *disp, *disp_size, reg, width,
                );
            }
            Address::PcRel { offset, base, .. } => {
                let disp_offset = {
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_test_mr_pcrel(0, reg, width)
                };
                let insn_end = self.code.position();

                let disp = if let Some(base_pc) = base {
                    let target = (*base_pc as i64 + *offset) as u64;
                    let disp = if self.pcrel_adjust {
                        let next_rip = self.guest_base as i64 + insn_end as i64;
                        target as i64 - next_rip
                    } else {
                        *offset
                    };
                    if disp < i32::MIN as i64 || disp > i32::MAX as i64 {
                        return Err(LowerError::InvalidOperand {
                            op: "PcRel TEST".to_string(),
                            operand: "offset out of range".to_string(),
                        });
                    }
                    self.relocations.push(Relocation {
                        offset: disp_offset,
                        kind: RelocKind::PcRel32,
                        target: RelocTarget::GuestAddr(target),
                    });
                    disp
                } else {
                    let disp = *offset;
                    if disp < i32::MIN as i64 || disp > i32::MAX as i64 {
                        return Err(LowerError::InvalidOperand {
                            op: "PcRel TEST".to_string(),
                            operand: "offset out of range".to_string(),
                        });
                    }
                    disp
                };

                self.code.patch_i32(disp_offset, disp as i32);
            }
            Address::Absolute(addr) => {
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_test_mr_abs(*addr, reg, width);
            }
            _ => {
                return Err(LowerError::UnsupportedOp {
                    op: format!("TEST with unsupported addressing: {:?}", addr),
                });
            }
        }

        Ok(())
    }

    fn emit_test_mem_imm(
        &mut self,
        addr: &Address,
        imm: i64,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        match addr {
            Address::Direct(base) => {
                let base_reg = self.get_reg(*base)?;
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_test_mi_disp(base_reg, 0, DispSize::Auto, imm, width);
            }
            Address::BaseOffset {
                base,
                offset,
                disp_size,
            } => {
                let base_reg = self.get_reg(*base)?;
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_test_mi_disp(base_reg, *offset as i32, *disp_size, imm, width);
            }
            Address::BaseIndexScale {
                base,
                index,
                scale,
                disp,
                disp_size,
            } => {
                let base_reg = base.map(|b| self.get_reg(b)).transpose()?;
                let index_reg = self.get_reg(*index)?;
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_test_mi_sib_disp(
                    base_reg, index_reg, *scale, *disp, *disp_size, imm, width,
                );
            }
            Address::PcRel { offset, base, .. } => {
                let disp_offset = {
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_test_mi_pcrel(0, imm, width)
                };
                let insn_end = self.code.position();

                let disp = if let Some(base_pc) = base {
                    let target = (*base_pc as i64 + *offset) as u64;
                    let disp = if self.pcrel_adjust {
                        let next_rip = self.guest_base as i64 + insn_end as i64;
                        target as i64 - next_rip
                    } else {
                        *offset
                    };
                    if disp < i32::MIN as i64 || disp > i32::MAX as i64 {
                        return Err(LowerError::InvalidOperand {
                            op: "PcRel TEST imm".to_string(),
                            operand: "offset out of range".to_string(),
                        });
                    }
                    self.relocations.push(Relocation {
                        offset: disp_offset,
                        kind: RelocKind::PcRel32,
                        target: RelocTarget::GuestAddr(target),
                    });
                    disp
                } else {
                    let disp = *offset;
                    if disp < i32::MIN as i64 || disp > i32::MAX as i64 {
                        return Err(LowerError::InvalidOperand {
                            op: "PcRel TEST imm".to_string(),
                            operand: "offset out of range".to_string(),
                        });
                    }
                    disp
                };

                self.code.patch_i32(disp_offset, disp as i32);
            }
            Address::Absolute(addr) => {
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_test_mi_abs(*addr, imm, width);
            }
            _ => {
                return Err(LowerError::UnsupportedOp {
                    op: format!("TEST imm with unsupported addressing: {:?}", addr),
                });
            }
        }

        Ok(())
    }

    fn emit_group3_mem(
        &mut self,
        digit: u8,
        addr: &Address,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        match addr {
            Address::Direct(base) => {
                let base_reg = self.get_reg(*base)?;
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_group3_m_disp(digit, base_reg, 0, DispSize::Auto, width);
            }
            Address::BaseOffset {
                base,
                offset,
                disp_size,
            } => {
                let base_reg = self.get_reg(*base)?;
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_group3_m_disp(digit, base_reg, *offset as i32, *disp_size, width);
            }
            Address::BaseIndexScale {
                base,
                index,
                scale,
                disp,
                disp_size,
            } => {
                let base_reg = base.map(|b| self.get_reg(b)).transpose()?;
                let index_reg = self.get_reg(*index)?;
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_group3_m_sib_disp(
                    digit, base_reg, index_reg, *scale, *disp, *disp_size, width,
                );
            }
            Address::PcRel { offset, base, .. } => {
                let disp_offset = {
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_group3_m_pcrel(digit, 0, width)
                };
                let insn_end = self.code.position();

                let disp = if let Some(base_pc) = base {
                    let target = (*base_pc as i64 + *offset) as u64;
                    let disp = if self.pcrel_adjust {
                        let next_rip = self.guest_base as i64 + insn_end as i64;
                        target as i64 - next_rip
                    } else {
                        *offset
                    };
                    if disp < i32::MIN as i64 || disp > i32::MAX as i64 {
                        return Err(LowerError::InvalidOperand {
                            op: "PcRel Group3".to_string(),
                            operand: "offset out of range".to_string(),
                        });
                    }
                    self.relocations.push(Relocation {
                        offset: disp_offset,
                        kind: RelocKind::PcRel32,
                        target: RelocTarget::GuestAddr(target),
                    });
                    disp
                } else {
                    let disp = *offset;
                    if disp < i32::MIN as i64 || disp > i32::MAX as i64 {
                        return Err(LowerError::InvalidOperand {
                            op: "PcRel Group3".to_string(),
                            operand: "offset out of range".to_string(),
                        });
                    }
                    disp
                };

                self.code.patch_i32(disp_offset, disp as i32);
            }
            Address::Absolute(addr) => {
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_group3_m_abs(digit, *addr, width);
            }
            _ => {
                return Err(LowerError::UnsupportedOp {
                    op: format!("Group3 with unsupported addressing: {:?}", addr),
                });
            }
        }

        Ok(())
    }

    fn emit_shift_mem(
        &mut self,
        digit: u8,
        addr: &Address,
        width: OpWidth,
        count: ShiftCount,
    ) -> Result<(), LowerError> {
        match addr {
            Address::Direct(base) => {
                let base_reg = self.get_reg(*base)?;
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_shift_m_disp(digit, base_reg, 0, DispSize::Auto, width, count);
            }
            Address::BaseOffset {
                base,
                offset,
                disp_size,
            } => {
                let base_reg = self.get_reg(*base)?;
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_shift_m_disp(
                    digit,
                    base_reg,
                    *offset as i32,
                    *disp_size,
                    width,
                    count,
                );
            }
            Address::BaseIndexScale {
                base,
                index,
                scale,
                disp,
                disp_size,
            } => {
                let base_reg = base.map(|b| self.get_reg(b)).transpose()?;
                let index_reg = self.get_reg(*index)?;
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_shift_m_sib_disp(
                    digit, base_reg, index_reg, *scale, *disp, *disp_size, width, count,
                );
            }
            Address::PcRel { offset, base, .. } => {
                let disp_offset = {
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_shift_m_pcrel(digit, 0, width, count)
                };
                let insn_end = self.code.position();

                let disp = if let Some(base_pc) = base {
                    let target = (*base_pc as i64 + *offset) as u64;
                    let disp = if self.pcrel_adjust {
                        let next_rip = self.guest_base as i64 + insn_end as i64;
                        target as i64 - next_rip
                    } else {
                        *offset
                    };
                    if disp < i32::MIN as i64 || disp > i32::MAX as i64 {
                        return Err(LowerError::InvalidOperand {
                            op: "PcRel shift".to_string(),
                            operand: "offset out of range".to_string(),
                        });
                    }
                    self.relocations.push(Relocation {
                        offset: disp_offset,
                        kind: RelocKind::PcRel32,
                        target: RelocTarget::GuestAddr(target),
                    });
                    disp
                } else {
                    let disp = *offset;
                    if disp < i32::MIN as i64 || disp > i32::MAX as i64 {
                        return Err(LowerError::InvalidOperand {
                            op: "PcRel shift".to_string(),
                            operand: "offset out of range".to_string(),
                        });
                    }
                    disp
                };

                self.code.patch_i32(disp_offset, disp as i32);
            }
            Address::Absolute(addr) => {
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_shift_m_abs(digit, *addr, width, count);
            }
            _ => {
                return Err(LowerError::UnsupportedOp {
                    op: format!("Shift with unsupported addressing: {:?}", addr),
                });
            }
        }

        Ok(())
    }

    fn emit_group5_mem(&mut self, digit: u8, addr: &Address) -> Result<(), LowerError> {
        match addr {
            Address::Direct(base) => {
                let base_reg = self.get_reg(*base)?;
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_group5_m_disp(digit, base_reg, 0, DispSize::Auto);
            }
            Address::BaseOffset {
                base,
                offset,
                disp_size,
            } => {
                let base_reg = self.get_reg(*base)?;
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_group5_m_disp(digit, base_reg, *offset as i32, *disp_size);
            }
            Address::BaseIndexScale {
                base,
                index,
                scale,
                disp,
                disp_size,
            } => {
                let base_reg = base.map(|b| self.get_reg(b)).transpose()?;
                let index_reg = self.get_reg(*index)?;
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter
                    .emit_group5_m_sib_disp(digit, base_reg, index_reg, *scale, *disp, *disp_size);
            }
            Address::PcRel { offset, base, .. } => {
                let disp_offset = {
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_group5_m_pcrel(digit, 0)
                };
                let insn_end = self.code.position();

                let disp = if let Some(base_pc) = base {
                    let target = (*base_pc as i64 + *offset) as u64;
                    let disp = if self.pcrel_adjust {
                        let next_rip = self.guest_base as i64 + insn_end as i64;
                        target as i64 - next_rip
                    } else {
                        *offset
                    };
                    if disp < i32::MIN as i64 || disp > i32::MAX as i64 {
                        return Err(LowerError::InvalidOperand {
                            op: "PcRel Group5".to_string(),
                            operand: "offset out of range".to_string(),
                        });
                    }
                    self.relocations.push(Relocation {
                        offset: disp_offset,
                        kind: RelocKind::PcRel32,
                        target: RelocTarget::GuestAddr(target),
                    });
                    disp
                } else {
                    let disp = *offset;
                    if disp < i32::MIN as i64 || disp > i32::MAX as i64 {
                        return Err(LowerError::InvalidOperand {
                            op: "PcRel Group5".to_string(),
                            operand: "offset out of range".to_string(),
                        });
                    }
                    disp
                };

                self.code.patch_i32(disp_offset, disp as i32);
            }
            Address::Absolute(addr) => {
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_group5_m_abs(digit, *addr);
            }
            _ => {
                return Err(LowerError::UnsupportedOp {
                    op: format!("Group5 with unsupported addressing: {:?}", addr),
                });
            }
        }

        Ok(())
    }

    fn emit_shld_mem(
        &mut self,
        addr: &Address,
        src: PhysReg,
        amount: Option<u8>,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        match addr {
            Address::Direct(base) => {
                let base_reg = self.get_reg(*base)?;
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_shld_mr_disp(base_reg, 0, DispSize::Auto, src, amount, width);
            }
            Address::BaseOffset {
                base,
                offset,
                disp_size,
            } => {
                let base_reg = self.get_reg(*base)?;
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_shld_mr_disp(base_reg, *offset as i32, *disp_size, src, amount, width);
            }
            Address::BaseIndexScale {
                base,
                index,
                scale,
                disp,
                disp_size,
            } => {
                let base_reg = base.map(|b| self.get_reg(b)).transpose()?;
                let index_reg = self.get_reg(*index)?;
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_shld_mr_sib_disp(
                    base_reg, index_reg, *scale, *disp, *disp_size, src, amount, width,
                );
            }
            Address::PcRel { offset, base, .. } => {
                let disp_offset = {
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_shld_mr_pcrel(0, src, amount, width)
                };
                let insn_end = self.code.position();

                let disp = if let Some(base_pc) = base {
                    let target = (*base_pc as i64 + *offset) as u64;
                    let disp = if self.pcrel_adjust {
                        let next_rip = self.guest_base as i64 + insn_end as i64;
                        target as i64 - next_rip
                    } else {
                        *offset
                    };
                    if disp < i32::MIN as i64 || disp > i32::MAX as i64 {
                        return Err(LowerError::InvalidOperand {
                            op: "PcRel SHLD".to_string(),
                            operand: "offset out of range".to_string(),
                        });
                    }
                    self.relocations.push(Relocation {
                        offset: disp_offset,
                        kind: RelocKind::PcRel32,
                        target: RelocTarget::GuestAddr(target),
                    });
                    disp
                } else {
                    let disp = *offset;
                    if disp < i32::MIN as i64 || disp > i32::MAX as i64 {
                        return Err(LowerError::InvalidOperand {
                            op: "PcRel SHLD".to_string(),
                            operand: "offset out of range".to_string(),
                        });
                    }
                    disp
                };

                self.code.patch_i32(disp_offset, disp as i32);
            }
            Address::Absolute(addr) => {
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_shld_mr_abs(*addr, src, amount, width);
            }
            _ => {
                return Err(LowerError::UnsupportedOp {
                    op: format!("SHLD with unsupported addressing: {:?}", addr),
                });
            }
        }

        Ok(())
    }

    fn emit_shrd_mem(
        &mut self,
        addr: &Address,
        src: PhysReg,
        amount: Option<u8>,
        width: OpWidth,
    ) -> Result<(), LowerError> {
        match addr {
            Address::Direct(base) => {
                let base_reg = self.get_reg(*base)?;
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_shrd_mr_disp(base_reg, 0, DispSize::Auto, src, amount, width);
            }
            Address::BaseOffset {
                base,
                offset,
                disp_size,
            } => {
                let base_reg = self.get_reg(*base)?;
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_shrd_mr_disp(base_reg, *offset as i32, *disp_size, src, amount, width);
            }
            Address::BaseIndexScale {
                base,
                index,
                scale,
                disp,
                disp_size,
            } => {
                let base_reg = base.map(|b| self.get_reg(b)).transpose()?;
                let index_reg = self.get_reg(*index)?;
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_shrd_mr_sib_disp(
                    base_reg, index_reg, *scale, *disp, *disp_size, src, amount, width,
                );
            }
            Address::PcRel { offset, base, .. } => {
                let disp_offset = {
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_shrd_mr_pcrel(0, src, amount, width)
                };
                let insn_end = self.code.position();

                let disp = if let Some(base_pc) = base {
                    let target = (*base_pc as i64 + *offset) as u64;
                    let disp = if self.pcrel_adjust {
                        let next_rip = self.guest_base as i64 + insn_end as i64;
                        target as i64 - next_rip
                    } else {
                        *offset
                    };
                    if disp < i32::MIN as i64 || disp > i32::MAX as i64 {
                        return Err(LowerError::InvalidOperand {
                            op: "PcRel SHRD".to_string(),
                            operand: "offset out of range".to_string(),
                        });
                    }
                    self.relocations.push(Relocation {
                        offset: disp_offset,
                        kind: RelocKind::PcRel32,
                        target: RelocTarget::GuestAddr(target),
                    });
                    disp
                } else {
                    let disp = *offset;
                    if disp < i32::MIN as i64 || disp > i32::MAX as i64 {
                        return Err(LowerError::InvalidOperand {
                            op: "PcRel SHRD".to_string(),
                            operand: "offset out of range".to_string(),
                        });
                    }
                    disp
                };

                self.code.patch_i32(disp_offset, disp as i32);
            }
            Address::Absolute(addr) => {
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_shrd_mr_abs(*addr, src, amount, width);
            }
            _ => {
                return Err(LowerError::UnsupportedOp {
                    op: format!("SHRD with unsupported addressing: {:?}", addr),
                });
            }
        }

        Ok(())
    }

    fn emit_imul_mem_imm(
        &mut self,
        dst: PhysReg,
        addr: &Address,
        imm: i32,
        width: OpWidth,
        use_imm8: bool,
    ) -> Result<(), LowerError> {
        match addr {
            Address::Direct(base) => {
                let base_reg = self.get_reg(*base)?;
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_imul_rmi_disp(dst, base_reg, 0, DispSize::Auto, imm, width, use_imm8);
            }
            Address::BaseOffset {
                base,
                offset,
                disp_size,
            } => {
                let base_reg = self.get_reg(*base)?;
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_imul_rmi_disp(
                    dst,
                    base_reg,
                    *offset as i32,
                    *disp_size,
                    imm,
                    width,
                    use_imm8,
                );
            }
            Address::BaseIndexScale {
                base,
                index,
                scale,
                disp,
                disp_size,
            } => {
                let base_reg = base.map(|b| self.get_reg(b)).transpose()?;
                let index_reg = self.get_reg(*index)?;
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_imul_rmi_sib_disp(
                    dst, base_reg, index_reg, *scale, *disp, *disp_size, imm, width, use_imm8,
                );
            }
            Address::PcRel { offset, base, .. } => {
                let disp_offset = {
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_imul_rmi_pcrel(dst, 0, imm, width, use_imm8)
                };
                let insn_end = self.code.position();

                let disp = if let Some(base_pc) = base {
                    let target = (*base_pc as i64 + *offset) as u64;
                    let disp = if self.pcrel_adjust {
                        let next_rip = self.guest_base as i64 + insn_end as i64;
                        target as i64 - next_rip
                    } else {
                        *offset
                    };
                    if disp < i32::MIN as i64 || disp > i32::MAX as i64 {
                        return Err(LowerError::InvalidOperand {
                            op: "PcRel IMUL".to_string(),
                            operand: "offset out of range".to_string(),
                        });
                    }
                    self.relocations.push(Relocation {
                        offset: disp_offset,
                        kind: RelocKind::PcRel32,
                        target: RelocTarget::GuestAddr(target),
                    });
                    disp
                } else {
                    let disp = *offset;
                    if disp < i32::MIN as i64 || disp > i32::MAX as i64 {
                        return Err(LowerError::InvalidOperand {
                            op: "PcRel IMUL".to_string(),
                            operand: "offset out of range".to_string(),
                        });
                    }
                    disp
                };

                self.code.patch_i32(disp_offset, disp as i32);
            }
            Address::Absolute(addr) => {
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_imul_rmi_abs(dst, *addr, imm, width, use_imm8);
            }
            _ => {
                return Err(LowerError::UnsupportedOp {
                    op: format!("IMUL with unsupported addressing: {:?}", addr),
                });
            }
        }

        Ok(())
    }

    fn try_lower_push_pop(
        &mut self,
        ops: &[crate::smir::ops::SmirOp],
        idx: usize,
    ) -> Result<Option<usize>, LowerError> {
        if idx + 1 >= ops.len() {
            return Ok(None);
        }

        match (&ops[idx].kind, &ops[idx + 1].kind) {
            (
                OpKind::Sub {
                    dst,
                    src1,
                    src2: SrcOperand::Imm(8),
                    width: OpWidth::W64,
                    flags: FlagUpdate::None,
                },
                OpKind::Store {
                    src,
                    addr: Address::Direct(addr_base),
                    width: MemWidth::B8,
                },
            ) if *dst == *src1 && self.is_rsp(*dst) && self.is_rsp(*addr_base) => {
                if let VReg::Imm(val) = src {
                    let hint = ops[idx + 1].x86_hint;
                    let mut emitter = X86Emitter::new(&mut self.code);
                    match hint {
                        Some(X86OpHint::PushImm8) => {
                            emitter.emit_push_imm8(*val as i8);
                            return Ok(Some(2));
                        }
                        Some(X86OpHint::PushImm32) => {
                            emitter.emit_push_imm32(*val as i32);
                            return Ok(Some(2));
                        }
                        _ => {}
                    }
                }

                if matches!(src, VReg::Arch(ArchReg::X86(X86Reg::Rsp))) {
                    return Ok(None);
                }
                let src_reg = self.get_reg(*src)?;
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_push(src_reg);
                return Ok(Some(2));
            }
            (
                OpKind::Load {
                    dst,
                    addr: Address::Direct(addr_base),
                    width: MemWidth::B8,
                    sign: SignExtend::Zero,
                },
                OpKind::Add {
                    dst: add_dst,
                    src1,
                    src2: SrcOperand::Imm(8),
                    width: OpWidth::W64,
                    flags: FlagUpdate::None,
                },
            ) if *add_dst == *src1 && self.is_rsp(*add_dst) && self.is_rsp(*addr_base) => {
                if matches!(dst, VReg::Arch(ArchReg::X86(X86Reg::Rsp))) {
                    return Ok(None);
                }
                let dst_reg = self.get_dst_reg(*dst)?;
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_pop(dst_reg);
                return Ok(Some(2));
            }
            _ => {}
        }

        Ok(None)
    }

    fn try_lower_mem_extend(
        &mut self,
        ops: &[crate::smir::ops::SmirOp],
        idx: usize,
    ) -> Result<Option<usize>, LowerError> {
        let (tmp, addr, mem_width, sign) = match ops.get(idx).map(|op| &op.kind) {
            Some(OpKind::Load {
                dst,
                addr,
                width,
                sign,
            }) => (*dst, addr, *width, *sign),
            _ => return Ok(None),
        };

        let op_width = match mem_width.to_op_width() {
            Some(width) => width,
            None => return Ok(None),
        };

        let next = match ops.get(idx + 1) {
            Some(op) => op,
            None => return Ok(None),
        };

        match &next.kind {
            OpKind::ZeroExtend {
                dst,
                src,
                from_width,
                to_width,
            } if *src == tmp && *from_width == op_width && sign == SignExtend::Zero => {
                let dst_reg = self.get_dst_reg(*dst)?;
                self.emit_movzx_mem(dst_reg, addr, *from_width, *to_width)?;
                return Ok(Some(2));
            }
            OpKind::SignExtend {
                dst,
                src,
                from_width,
                to_width,
            } if *src == tmp && *from_width == op_width && sign == SignExtend::Sign => {
                let dst_reg = self.get_dst_reg(*dst)?;
                self.emit_movsx_mem(dst_reg, addr, *from_width, *to_width)?;
                return Ok(Some(2));
            }
            _ => {}
        }

        Ok(None)
    }

    fn try_lower_vmem_binop(
        &mut self,
        ops: &[crate::smir::ops::SmirOp],
        idx: usize,
    ) -> Result<Option<usize>, LowerError> {
        let (tmp, addr, width) = match ops.get(idx).map(|op| &op.kind) {
            Some(OpKind::VLoad { dst, addr, width }) => (*dst, addr, *width),
            _ => return Ok(None),
        };

        if width != VecWidth::V128 {
            return Ok(None);
        }

        let op = match ops.get(idx + 1) {
            Some(op) => op,
            None => return Ok(None),
        };

        match &op.kind {
            OpKind::VAdd {
                dst,
                src1,
                src2,
                elem,
                lanes,
            } if *src2 == tmp && *dst == *src1 => {
                if *elem != VecElementType::I32 || *lanes != 4 {
                    return Ok(None);
                }
                let dst_reg = self.get_dst_reg(*dst)?;
                if !dst_reg.is_vec() {
                    return Err(LowerError::InvalidOperand {
                        op: "VAdd".to_string(),
                        operand: "destination must be vector register".to_string(),
                    });
                }
                if let Some(enc_hint) = self.vec_hint(op.x86_hint) {
                    let enc = VecEncoding { width, ..enc_hint };
                    self.emit_vec_mem(enc, dst_reg, Some(dst_reg), addr)?;
                } else {
                    if self.vec_requires_vex(&[dst_reg]) {
                        return Ok(None);
                    }
                    let prefix = self.sse_prefix(op.x86_hint);
                    let opcode = self.sse_opcode(op.x86_hint, 0xFE);
                    self.emit_sse_mov_mem(prefix, opcode, dst_reg, addr)?;
                }
                return Ok(Some(2));
            }
            OpKind::VMul {
                dst,
                src1,
                src2,
                elem,
                lanes,
            } if *src2 == tmp && *dst == *src1 => {
                if *elem != VecElementType::I32 || *lanes != 4 {
                    return Ok(None);
                }
                let dst_reg = self.get_dst_reg(*dst)?;
                if !dst_reg.is_vec() {
                    return Err(LowerError::InvalidOperand {
                        op: "VMul".to_string(),
                        operand: "destination must be vector register".to_string(),
                    });
                }
                if let Some(enc_hint) = self.vec_hint(op.x86_hint) {
                    let enc = VecEncoding { width, ..enc_hint };
                    self.emit_vec_mem(enc, dst_reg, Some(dst_reg), addr)?;
                } else {
                    if self.vec_requires_vex(&[dst_reg]) {
                        return Ok(None);
                    }
                    self.emit_sse_op38_mem(Some(0x66), 0x40, dst_reg, addr)?;
                }
                return Ok(Some(2));
            }
            _ => {}
        }

        Ok(None)
    }

    fn try_lower_mem_shift(
        &mut self,
        ops: &[crate::smir::ops::SmirOp],
        idx: usize,
    ) -> Result<Option<usize>, LowerError> {
        if idx + 2 >= ops.len() {
            return Ok(None);
        }

        let (tmp, addr, mem_width, sign) = match ops.get(idx).map(|op| &op.kind) {
            Some(OpKind::Load {
                dst,
                addr,
                width,
                sign,
            }) => (*dst, addr, *width, *sign),
            _ => return Ok(None),
        };

        if sign != SignExtend::Zero {
            return Ok(None);
        }

        let op_width = match mem_width.to_op_width() {
            Some(width) => width,
            None => return Ok(None),
        };

        let (digit, amount, dst, src, width) = match &ops[idx + 1].kind {
            OpKind::Rol {
                dst,
                src,
                amount,
                width,
                ..
            } => (0, amount, dst, src, width),
            OpKind::Ror {
                dst,
                src,
                amount,
                width,
                ..
            } => (1, amount, dst, src, width),
            OpKind::Shl {
                dst,
                src,
                amount,
                width,
                ..
            } => (4, amount, dst, src, width),
            OpKind::Shr {
                dst,
                src,
                amount,
                width,
                ..
            } => (5, amount, dst, src, width),
            OpKind::Sar {
                dst,
                src,
                amount,
                width,
                ..
            } => (7, amount, dst, src, width),
            _ => return Ok(None),
        };

        if *dst != tmp || *src != tmp || *width != op_width {
            return Ok(None);
        }

        match &ops[idx + 2].kind {
            OpKind::Store {
                src,
                addr: store_addr,
                width: store_width,
            } if *src == tmp && *store_addr == *addr && *store_width == mem_width => {}
            _ => return Ok(None),
        }

        let count = match amount {
            SrcOperand::Imm(val) => {
                if *val < 0 || *val > u8::MAX as i64 {
                    return Ok(None);
                }
                let imm = *val as u8;
                if imm == 1 {
                    ShiftCount::One
                } else {
                    ShiftCount::Imm(imm)
                }
            }
            SrcOperand::Reg(reg) => {
                let amt_reg = self.get_reg(*reg)?;
                if amt_reg != PhysReg::Rcx {
                    return Ok(None);
                }
                ShiftCount::Cl
            }
            _ => return Ok(None),
        };

        self.emit_shift_mem(digit, addr, op_width, count)?;
        Ok(Some(3))
    }

    fn try_lower_mem_alu(
        &mut self,
        ops: &[crate::smir::ops::SmirOp],
        idx: usize,
    ) -> Result<Option<usize>, LowerError> {
        let (tmp, addr, mem_width, sign) = match ops.get(idx).map(|op| &op.kind) {
            Some(OpKind::Load {
                dst,
                addr,
                width,
                sign,
            }) => (*dst, addr, *width, *sign),
            _ => return Ok(None),
        };

        if sign != SignExtend::Zero {
            return Ok(None);
        }

        let op_width = match mem_width.to_op_width() {
            Some(width) => width,
            None => return Ok(None),
        };

        if idx + 2 < ops.len() {
            if let OpKind::Store {
                src,
                addr: store_addr,
                width: store_width,
            } = &ops[idx + 2].kind
            {
                if *src == tmp && *store_width == mem_width && *store_addr == *addr {
                    match &ops[idx + 1].kind {
                        OpKind::Not { dst, src, width }
                            if *dst == tmp && *src == tmp && *width == op_width =>
                        {
                            self.emit_group3_mem(2, addr, op_width)?;
                            return Ok(Some(3));
                        }
                        OpKind::Neg {
                            dst, src, width, ..
                        } if *dst == tmp && *src == tmp && *width == op_width => {
                            self.emit_group3_mem(3, addr, op_width)?;
                            return Ok(Some(3));
                        }
                        _ => {}
                    }

                    if let Some((opcode, digit, src2)) = match &ops[idx + 1].kind {
                        OpKind::Add {
                            dst,
                            src1,
                            src2,
                            width,
                            ..
                        } if *dst == tmp && *src1 == tmp && *width == op_width => {
                            Some((0x00, 0, src2))
                        }
                        OpKind::Sub {
                            dst,
                            src1,
                            src2,
                            width,
                            ..
                        } if *dst == tmp && *src1 == tmp && *width == op_width => {
                            Some((0x28, 5, src2))
                        }
                        OpKind::Adc {
                            dst,
                            src1,
                            src2,
                            width,
                            ..
                        } if *dst == tmp && *src1 == tmp && *width == op_width => {
                            Some((0x10, 2, src2))
                        }
                        OpKind::Sbb {
                            dst,
                            src1,
                            src2,
                            width,
                            ..
                        } if *dst == tmp && *src1 == tmp && *width == op_width => {
                            Some((0x18, 3, src2))
                        }
                        OpKind::And {
                            dst,
                            src1,
                            src2,
                            width,
                            ..
                        } if *dst == tmp && *src1 == tmp && *width == op_width => {
                            Some((0x20, 4, src2))
                        }
                        OpKind::Or {
                            dst,
                            src1,
                            src2,
                            width,
                            ..
                        } if *dst == tmp && *src1 == tmp && *width == op_width => {
                            Some((0x08, 1, src2))
                        }
                        OpKind::Xor {
                            dst,
                            src1,
                            src2,
                            width,
                            ..
                        } if *dst == tmp && *src1 == tmp && *width == op_width => {
                            Some((0x30, 6, src2))
                        }
                        _ => None,
                    } {
                        match src2 {
                            SrcOperand::Reg(r) => {
                                let reg = self.get_reg(*r)?;
                                self.emit_alu_mem_reg(
                                    opcode,
                                    addr,
                                    reg,
                                    op_width,
                                    X86AluEncoding::RmReg,
                                )?;
                                return Ok(Some(3));
                            }
                            SrcOperand::Imm(val) => {
                                self.emit_alu_mem_imm(digit, addr, *val, op_width)?;
                                return Ok(Some(3));
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        if idx + 1 < ops.len() {
            match &ops[idx + 1].kind {
                OpKind::Test { src1, src2, width } if *width == op_width && *src1 == tmp => {
                    match src2 {
                        SrcOperand::Reg(r) => {
                            let reg = self.get_reg(*r)?;
                            self.emit_test_mem_reg(addr, reg, op_width)?;
                            return Ok(Some(2));
                        }
                        SrcOperand::Imm(val) => {
                            self.emit_test_mem_imm(addr, *val, op_width)?;
                            return Ok(Some(2));
                        }
                        _ => {}
                    }
                }
                OpKind::Cmp { src1, src2, width } if *width == op_width => match (src1, src2) {
                    (s1, SrcOperand::Reg(r)) if *s1 == tmp => {
                        let reg = self.get_reg(*r)?;
                        self.emit_alu_mem_reg(0x38, addr, reg, op_width, X86AluEncoding::RmReg)?;
                        return Ok(Some(2));
                    }
                    (s1, SrcOperand::Reg(r)) if *r == tmp => {
                        let reg = self.get_reg(*s1)?;
                        self.emit_alu_mem_reg(0x38, addr, reg, op_width, X86AluEncoding::RegRm)?;
                        return Ok(Some(2));
                    }
                    (s1, SrcOperand::Imm(val)) if *s1 == tmp => {
                        self.emit_alu_mem_imm(7, addr, *val, op_width)?;
                        return Ok(Some(2));
                    }
                    _ => {}
                },
                OpKind::Add {
                    dst,
                    src1,
                    src2: SrcOperand::Reg(r),
                    width,
                    ..
                } if *width == op_width && *dst == *src1 && *r == tmp => {
                    let reg = self.get_dst_reg(*dst)?;
                    self.emit_alu_mem_reg(0x00, addr, reg, op_width, X86AluEncoding::RegRm)?;
                    return Ok(Some(2));
                }
                OpKind::Sub {
                    dst,
                    src1,
                    src2: SrcOperand::Reg(r),
                    width,
                    ..
                } if *width == op_width && *dst == *src1 && *r == tmp => {
                    let reg = self.get_dst_reg(*dst)?;
                    self.emit_alu_mem_reg(0x28, addr, reg, op_width, X86AluEncoding::RegRm)?;
                    return Ok(Some(2));
                }
                OpKind::Adc {
                    dst,
                    src1,
                    src2: SrcOperand::Reg(r),
                    width,
                    ..
                } if *width == op_width && *dst == *src1 && *r == tmp => {
                    let reg = self.get_dst_reg(*dst)?;
                    self.emit_alu_mem_reg(0x10, addr, reg, op_width, X86AluEncoding::RegRm)?;
                    return Ok(Some(2));
                }
                OpKind::Sbb {
                    dst,
                    src1,
                    src2: SrcOperand::Reg(r),
                    width,
                    ..
                } if *width == op_width && *dst == *src1 && *r == tmp => {
                    let reg = self.get_dst_reg(*dst)?;
                    self.emit_alu_mem_reg(0x18, addr, reg, op_width, X86AluEncoding::RegRm)?;
                    return Ok(Some(2));
                }
                OpKind::And {
                    dst,
                    src1,
                    src2: SrcOperand::Reg(r),
                    width,
                    ..
                } if *width == op_width && *dst == *src1 && *r == tmp => {
                    let reg = self.get_dst_reg(*dst)?;
                    self.emit_alu_mem_reg(0x20, addr, reg, op_width, X86AluEncoding::RegRm)?;
                    return Ok(Some(2));
                }
                OpKind::Or {
                    dst,
                    src1,
                    src2: SrcOperand::Reg(r),
                    width,
                    ..
                } if *width == op_width && *dst == *src1 && *r == tmp => {
                    let reg = self.get_dst_reg(*dst)?;
                    self.emit_alu_mem_reg(0x08, addr, reg, op_width, X86AluEncoding::RegRm)?;
                    return Ok(Some(2));
                }
                OpKind::Xor {
                    dst,
                    src1,
                    src2: SrcOperand::Reg(r),
                    width,
                    ..
                } if *width == op_width && *dst == *src1 && *r == tmp => {
                    let reg = self.get_dst_reg(*dst)?;
                    self.emit_alu_mem_reg(0x30, addr, reg, op_width, X86AluEncoding::RegRm)?;
                    return Ok(Some(2));
                }
                _ => {}
            }
        }

        Ok(None)
    }

    fn try_lower_mem_imul(
        &mut self,
        ops: &[crate::smir::ops::SmirOp],
        idx: usize,
    ) -> Result<Option<usize>, LowerError> {
        let (tmp, addr, mem_width, sign) = match ops.get(idx).map(|op| &op.kind) {
            Some(OpKind::Load {
                dst,
                addr,
                width,
                sign,
            }) => (*dst, addr, *width, *sign),
            _ => return Ok(None),
        };

        if sign != SignExtend::Zero {
            return Ok(None);
        }

        let op_width = match mem_width.to_op_width() {
            Some(width) => width,
            None => return Ok(None),
        };

        let op = match ops.get(idx + 1) {
            Some(op) => op,
            None => return Ok(None),
        };

        let (dst_lo, src1, src2, width) = match &op.kind {
            OpKind::MulS {
                dst_lo,
                dst_hi,
                src1,
                src2,
                width,
                ..
            } if dst_hi.is_none() => (*dst_lo, *src1, src2, *width),
            _ => return Ok(None),
        };

        if src1 != tmp || width != op_width {
            return Ok(None);
        }

        let imm = match src2 {
            SrcOperand::Imm(val) => *val as i32,
            _ => return Ok(None),
        };

        let dst_reg = self.get_dst_reg(dst_lo)?;
        let use_imm8 = match op.x86_hint {
            Some(X86OpHint::ImulImm8) => true,
            Some(X86OpHint::ImulImm32) => false,
            _ => imm >= -128 && imm <= 127,
        };

        self.emit_imul_mem_imm(dst_reg, addr, imm, op_width, use_imm8)?;
        Ok(Some(2))
    }

    fn try_lower_mem_group3(
        &mut self,
        ops: &[crate::smir::ops::SmirOp],
        idx: usize,
    ) -> Result<Option<usize>, LowerError> {
        let (tmp, addr, mem_width, sign) = match ops.get(idx).map(|op| &op.kind) {
            Some(OpKind::Load {
                dst,
                addr,
                width,
                sign,
            }) => (*dst, addr, *width, *sign),
            _ => return Ok(None),
        };

        if sign != SignExtend::Zero {
            return Ok(None);
        }

        let op_width = match mem_width.to_op_width() {
            Some(width) => width,
            None => return Ok(None),
        };

        let op = match ops.get(idx + 1) {
            Some(op) => op,
            None => return Ok(None),
        };

        let rax = VReg::Arch(ArchReg::X86(X86Reg::Rax));
        let rdx = VReg::Arch(ArchReg::X86(X86Reg::Rdx));

        match &op.kind {
            OpKind::MulU {
                dst_lo,
                dst_hi,
                src1,
                src2,
                width,
                ..
            } if *width == op_width
                && *dst_lo == rax
                && *dst_hi == Some(rdx)
                && *src1 == rax
                && matches!(src2, SrcOperand::Reg(r) if *r == tmp) =>
            {
                self.emit_group3_mem(4, addr, op_width)?;
                return Ok(Some(2));
            }
            OpKind::MulS {
                dst_lo,
                dst_hi,
                src1,
                src2,
                width,
                ..
            } if *width == op_width
                && *dst_lo == rax
                && *dst_hi == Some(rdx)
                && *src1 == rax
                && matches!(src2, SrcOperand::Reg(r) if *r == tmp) =>
            {
                self.emit_group3_mem(5, addr, op_width)?;
                return Ok(Some(2));
            }
            OpKind::DivU {
                quot,
                rem,
                src1,
                src2,
                width,
            } if *width == op_width
                && *quot == rax
                && *rem == Some(rdx)
                && *src1 == rax
                && matches!(src2, SrcOperand::Reg(r) if *r == tmp) =>
            {
                self.emit_group3_mem(6, addr, op_width)?;
                return Ok(Some(2));
            }
            OpKind::DivS {
                quot,
                rem,
                src1,
                src2,
                width,
            } if *width == op_width
                && *quot == rax
                && *rem == Some(rdx)
                && *src1 == rax
                && matches!(src2, SrcOperand::Reg(r) if *r == tmp) =>
            {
                self.emit_group3_mem(7, addr, op_width)?;
                return Ok(Some(2));
            }
            _ => {}
        }

        Ok(None)
    }

    fn try_lower_mem_shld(
        &mut self,
        ops: &[crate::smir::ops::SmirOp],
        idx: usize,
    ) -> Result<Option<usize>, LowerError> {
        if idx + 2 >= ops.len() {
            return Ok(None);
        }

        let (tmp, addr, mem_width, sign) = match &ops[idx].kind {
            OpKind::Load {
                dst,
                addr,
                width,
                sign,
            } => (*dst, addr, *width, *sign),
            _ => return Ok(None),
        };

        if sign != SignExtend::Zero {
            return Ok(None);
        }

        let op_width = match mem_width.to_op_width() {
            Some(width) => width,
            None => return Ok(None),
        };

        let (is_shld, src_reg, amount) = match &ops[idx + 1].kind {
            OpKind::Shld {
                dst,
                src,
                amount,
                width,
                ..
            } if *dst == tmp && *width == op_width => (true, *src, amount),
            OpKind::Shrd {
                dst,
                src,
                amount,
                width,
                ..
            } if *dst == tmp && *width == op_width => (false, *src, amount),
            _ => return Ok(None),
        };

        if let OpKind::Store {
            src,
            addr: store_addr,
            width: store_width,
        } = &ops[idx + 2].kind
        {
            if *src != tmp || *store_width != mem_width || *store_addr != *addr {
                return Ok(None);
            }
        } else {
            return Ok(None);
        }

        let src_phys = self.get_reg(src_reg)?;
        let amount_imm = match amount {
            SrcOperand::Imm(val) => Some(*val as u8),
            SrcOperand::Reg(r) => {
                let amt_reg = self.get_reg(*r)?;
                if amt_reg != PhysReg::Rcx {
                    return Ok(None);
                }
                None
            }
            _ => return Ok(None),
        };

        if is_shld {
            self.emit_shld_mem(addr, src_phys, amount_imm, op_width)?;
        } else {
            self.emit_shrd_mem(addr, src_phys, amount_imm, op_width)?;
        }

        Ok(Some(3))
    }

    /// Lower a single basic block
    fn lower_block(&mut self, block: &SmirBlock) -> Result<(), LowerError> {
        // Record block offset
        self.block_offsets.insert(block.id, self.code.position());
        self.block_guest_pcs.insert(block.id, block.guest_pc);

        // JIT native-exit stub: record the resume guest PC into `exit_pc` and
        // return to the trampoline, skipping this block's ops/terminator. The
        // state pointer lives at [rbp+24] (the enter_native frame layout); we
        // borrow RAX as scratch (push/pop) so no guest register is disturbed.
        // exit_pc is at GuestRegs offset 136 (gpr[16]*8 + rflags), 140 = +hi32.
        if let Some(&resume_pc) = self.native_exits.get(&block.id) {
            self.code.emit_u8(0x50); // push rax
            // mov rax, [rbp+24]  (48 8B 45 18)
            self.code.emit_u8(0x48);
            self.code.emit_u8(0x8B);
            self.code.emit_u8(0x45);
            self.code.emit_u8(0x18);
            // mov dword [rax+136], resume_pc<low32>   (C7 80 <disp32> <imm32>)
            self.code.emit_u8(0xC7);
            self.code.emit_u8(0x80);
            self.code.emit_u32(136);
            self.code.emit_u32(resume_pc as u32);
            // mov dword [rax+140], resume_pc<high32>
            self.code.emit_u8(0xC7);
            self.code.emit_u8(0x80);
            self.code.emit_u32(140);
            self.code.emit_u32((resume_pc >> 32) as u32);
            self.code.emit_u8(0x58); // pop rax
            // epilogue: mov rsp,rbp ; pop rbp ; ret (flag-preserving teardown)
            self.emit_epilogue_with_ret(None);
            return Ok(());
        }

        // Initialize register allocator for this block
        self.regalloc.begin_block(block);

        let mut end_idx = block.ops.len();
        if matches!(block.terminator, Terminator::Return { .. }) && block.ops.len() >= 2 {
            if let (
                OpKind::Load {
                    dst: load_dst,
                    addr: Address::Direct(addr_base),
                    width: MemWidth::B8,
                    sign: SignExtend::Zero,
                },
                OpKind::Add {
                    dst,
                    src1,
                    src2: SrcOperand::Imm(imm),
                    width: OpWidth::W64,
                    flags: FlagUpdate::None,
                },
            ) = (
                &block.ops[block.ops.len() - 2].kind,
                &block.ops[block.ops.len() - 1].kind,
            ) {
                if self.is_rsp(*dst)
                    && self.is_rsp(*src1)
                    && self.is_rsp(*addr_base)
                    && matches!(load_dst, VReg::Virtual(_))
                {
                    let imm_total = *imm;
                    if imm_total >= 8 && imm_total <= (8 + u16::MAX as i64) {
                        self.pending_ret_imm = Some((imm_total - 8) as u16);
                        end_idx -= 2;
                    }
                }
            }
        }

        // Fold a trailing `TestCondition` that exists only to feed this block's
        // `CondBranch` into a direct `Jcc<cond>` off live flags. The x86 lifter
        // emits, for a guest Jcc, `TestCondition { dst, cond }` as the block's
        // last op plus `CondBranch { cond: dst, .. }`. Materializing `dst` into
        // a host register would clobber guest state under the identity reg map
        // (no free scratch GPR), so skip the op and let `lower_terminator` read
        // the flags the block body's last flag-setting op (e.g. `dec`) produced.
        self.pending_cond = None;
        if let Terminator::CondBranch { cond, .. } = &block.terminator {
            if end_idx > 0 {
                if let OpKind::TestCondition {
                    dst,
                    cond: guest_cond,
                } = &block.ops[end_idx - 1].kind
                {
                    if dst == cond {
                        self.pending_cond = Some(*guest_cond);
                        end_idx -= 1;
                    }
                }
            }
        }

        // Lower each operation
        let mut idx = 0;
        while idx < end_idx {
            self.regalloc.set_current_idx(idx);
            if let Some(consumed) = self.try_lower_mem_extend(&block.ops, idx)? {
                idx += consumed;
                continue;
            }
            if let Some(consumed) = self.try_lower_vmem_binop(&block.ops, idx)? {
                idx += consumed;
                continue;
            }
            if let Some(consumed) = self.try_lower_mem_shift(&block.ops, idx)? {
                idx += consumed;
                continue;
            }
            if let Some(consumed) = self.try_lower_mem_alu(&block.ops, idx)? {
                idx += consumed;
                continue;
            }
            if let Some(consumed) = self.try_lower_mem_imul(&block.ops, idx)? {
                idx += consumed;
                continue;
            }
            if let Some(consumed) = self.try_lower_mem_group3(&block.ops, idx)? {
                idx += consumed;
                continue;
            }
            if let Some(consumed) = self.try_lower_mem_shld(&block.ops, idx)? {
                idx += consumed;
                continue;
            }
            if let Some(consumed) = self.try_lower_push_pop(&block.ops, idx)? {
                idx += consumed;
                continue;
            }
            self.lower_op(&block.ops[idx])?;
            idx += 1;
        }

        // Lower terminator
        self.lower_terminator(&block.terminator)?;

        Ok(())
    }

    /// Fix up all pending jumps
    fn fixup_jumps(&mut self) -> Result<(), LowerError> {
        for (offset, target, kind) in self.pending_jumps.drain(..).collect::<Vec<_>>() {
            let target_offset =
                self.block_offsets
                    .get(&target)
                    .ok_or_else(|| LowerError::UndefinedLabel {
                        label: format!("block_{}", target.0),
                    })?;

            match kind {
                RelocKind::PcRel32 => {
                    let rel = (*target_offset as i64) - (offset as i64) - 4;
                    if rel < i32::MIN as i64 || rel > i32::MAX as i64 {
                        return Err(LowerError::RelocationOutOfRange {
                            offset,
                            target: *target_offset,
                        });
                    }
                    self.code.patch_i32(offset, rel as i32);
                }
                RelocKind::PcRel8 => {
                    let rel = (*target_offset as i64) - (offset as i64) - 1;
                    if rel < -128 || rel > 127 {
                        return Err(LowerError::RelocationOutOfRange {
                            offset,
                            target: *target_offset,
                        });
                    }
                    self.code.data[offset] = rel as i8 as u8;
                }
                _ => {}
            }
        }

        Ok(())
    }
}

impl Default for X86_64Lowerer {
    fn default() -> Self {
        Self::new()
    }
}

impl SmirLowerer for X86_64Lowerer {
    fn target_arch(&self) -> &'static str {
        "x86_64"
    }

    fn lower_function(&mut self, func: &SmirFunction) -> Result<LowerResult, LowerError> {
        // Reset state
        self.code.clear();
        self.regalloc.reset();
        self.block_offsets.clear();
        self.relocations.clear();
        self.pending_jumps.clear();
        self.guest_base = func.guest_range.0;
        self.pending_ret_imm = None;
        self.pending_cond = None;
        self.block_guest_pcs = func
            .blocks
            .iter()
            .map(|block| (block.id, block.guest_pc))
            .collect();

        let entry_offset = self.code.position();

        // First pass: allocate registers and compute frame size
        // For now, use simple approach - just lower blocks in order

        // Emit prologue: `push rbp; mov rbp, rsp`, then a FIXED-SIZE region
        // (NOP-filled) reserved for the callee-saved saves + frame allocation.
        // Those depend on register allocation, which isn't known until the body
        // is lowered, so the region is backpatched after `fixup_jumps`. A fixed
        // size keeps every body offset / jump target stable. The original code
        // left this prologue as a never-finished stub, making it asymmetric with
        // `emit_epilogue` (which tears down callee-saved + frame) — that
        // corrupted the stack and made `ret` jump to garbage.
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_push(PhysReg::Rbp);
            emitter.emit_mov_rr(PhysReg::Rbp, PhysReg::Rsp, OpWidth::W64);
        }
        const PROLOGUE_RESERVE: usize = 16;
        let prologue_patch_at = self.code.position();
        for _ in 0..PROLOGUE_RESERVE {
            self.code.emit_u8(0x90); // NOP placeholder, backpatched below
        }

        // Lower entry block first
        if let Some(entry_block) = func.get_block(func.entry) {
            self.lower_block(entry_block)?;
        }

        // Lower remaining blocks
        for block in &func.blocks {
            if block.id != func.entry {
                self.lower_block(block)?;
            }
        }

        // Fix up all jumps
        self.fixup_jumps()?;

        // Backpatch the reserved prologue region now that the frame size is
        // final: emit just the frame allocation, mirroring `emit_epilogue`'s
        // teardown. Callee-saved guest regs are intentionally NOT pushed (the
        // block owns all GPRs; the enter_native shim preserves host state), so
        // guest writes to RBX/R12-R15 survive the call.
        {
            let mut tmp = CodeBuffer::new();
            {
                let mut e = X86Emitter::new(&mut tmp);
                let frame = self.regalloc.frame_size();
                if frame > 0 {
                    // Flag-preserving frame allocation: LEA, not SUB. The entry
                    // shim sets the guest's RFLAGS (incl. CF) before the block;
                    // a `sub rsp,frame` here would clobber CF before the body's
                    // ADC/SBB read it as a carry-in.
                    e.emit_lea(PhysReg::Rsp, PhysReg::Rsp, -(frame as i32));
                }
            }
            let bytes = tmp.data().to_vec();
            assert!(
                bytes.len() <= PROLOGUE_RESERVE,
                "prologue setup ({} bytes) exceeds reserved region ({})",
                bytes.len(),
                PROLOGUE_RESERVE
            );
            for (i, &b) in bytes.iter().enumerate() {
                self.code.data[prologue_patch_at + i] = b;
            }
            // Any remaining reserved bytes stay 0x90 (NOP) and execute harmlessly.
        }

        let code_size = self.code.len();

        Ok(LowerResult {
            code_size,
            entry_offset,
            block_offsets: self.block_offsets.clone(),
            relocations: self.relocations.clone(),
            stack_size: self.regalloc.frame_size(),
        })
    }

    fn code_buffer(&self) -> &CodeBuffer {
        &self.code
    }

    fn finalize(&mut self) -> Result<Vec<u8>, LowerError> {
        Ok(self.code.data().to_vec())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smir::flags::FlagUpdate;
    use crate::smir::ir::{FunctionBuilder, Terminator};
    use crate::smir::types::{FunctionId, OpWidth, SrcOperand, VReg};

    #[test]
    fn test_emit_mov_rr() {
        let mut buf = CodeBuffer::new();
        {
            let mut emit = X86Emitter::new(&mut buf);
            emit.emit_mov_rr(PhysReg::Rax, PhysReg::Rcx, OpWidth::W64);
        }
        // MOV RAX, RCX = 48 89 C8
        assert_eq!(buf.data(), &[0x48, 0x89, 0xC8]);
    }

    #[test]
    fn test_emit_mov_ri() {
        let mut buf = CodeBuffer::new();
        {
            let mut emit = X86Emitter::new(&mut buf);
            emit.emit_mov_ri(PhysReg::Rax, 42, OpWidth::W64);
        }
        // MOV RAX, 42 (using imm32 sign-extended)
        // 48 C7 C0 2A 00 00 00
        assert_eq!(buf.data(), &[0x48, 0xC7, 0xC0, 0x2A, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_emit_add_rr() {
        let mut buf = CodeBuffer::new();
        {
            let mut emit = X86Emitter::new(&mut buf);
            emit.emit_add_rr(PhysReg::Rax, PhysReg::Rbx, OpWidth::W64);
        }
        // ADD RAX, RBX = 48 01 D8
        assert_eq!(buf.data(), &[0x48, 0x01, 0xD8]);
    }

    #[test]
    fn test_emit_jmp_rel32() {
        let mut buf = CodeBuffer::new();
        {
            let mut emit = X86Emitter::new(&mut buf);
            emit.emit_jmp_rel32(0x12345678);
        }
        // JMP rel32 = E9 78 56 34 12
        assert_eq!(buf.data(), &[0xE9, 0x78, 0x56, 0x34, 0x12]);
    }

    #[test]
    fn test_emit_ret() {
        let mut buf = CodeBuffer::new();
        {
            let mut emit = X86Emitter::new(&mut buf);
            emit.emit_ret();
        }
        assert_eq!(buf.data(), &[0xC3]);
    }

    #[test]
    fn test_emit_push_pop() {
        let mut buf = CodeBuffer::new();
        {
            let mut emit = X86Emitter::new(&mut buf);
            emit.emit_push(PhysReg::Rbp);
            emit.emit_pop(PhysReg::Rbp);
        }
        // PUSH RBP = 55, POP RBP = 5D
        assert_eq!(buf.data(), &[0x55, 0x5D]);
    }

    #[test]
    fn test_emit_extended_reg() {
        let mut buf = CodeBuffer::new();
        {
            let mut emit = X86Emitter::new(&mut buf);
            emit.emit_mov_rr(PhysReg::R8, PhysReg::R9, OpWidth::W64);
        }
        // MOV R8, R9 = 4D 89 C8
        assert_eq!(buf.data(), &[0x4D, 0x89, 0xC8]);
    }

    #[test]
    fn test_emit_setcc() {
        let mut buf = CodeBuffer::new();
        {
            let mut emit = X86Emitter::new(&mut buf);
            emit.emit_setcc(X86Cond::E, PhysReg::Rax);
        }
        // SETE AL = 0F 94 C0
        assert_eq!(buf.data(), &[0x0F, 0x94, 0xC0]);
    }

    #[test]
    fn test_lower_simple_function() {
        // Create a simple function: return 42
        let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);

        let v0 = builder.alloc_vreg();

        builder.push_op(
            0x1000,
            OpKind::Mov {
                dst: v0,
                src: SrcOperand::imm(42),
                width: OpWidth::W64,
            },
        );

        builder.set_terminator(Terminator::Return { values: vec![v0] });

        let func = builder.finish();

        // Lower it
        let mut lowerer = X86_64Lowerer::new();
        let result = lowerer.lower_function(&func).unwrap();

        assert!(result.code_size > 0);

        let code = lowerer.finalize().unwrap();
        // Should start with PUSH RBP; MOV RBP, RSP
        assert!(code.len() >= 4);
        assert_eq!(code[0], 0x55); // PUSH RBP
    }

    #[test]
    fn test_lower_add() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);

        let v0 = builder.alloc_vreg();
        let v1 = builder.alloc_vreg();
        let v2 = builder.alloc_vreg();

        builder.push_op(
            0x1000,
            OpKind::Mov {
                dst: v0,
                src: SrcOperand::imm(10),
                width: OpWidth::W64,
            },
        );

        builder.push_op(
            0x1004,
            OpKind::Mov {
                dst: v1,
                src: SrcOperand::imm(20),
                width: OpWidth::W64,
            },
        );

        builder.push_op(
            0x1008,
            OpKind::Add {
                dst: v2,
                src1: v0,
                src2: SrcOperand::Reg(v1),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        );

        builder.set_terminator(Terminator::Return { values: vec![v2] });

        let func = builder.finish();

        let mut lowerer = X86_64Lowerer::new();
        let result = lowerer.lower_function(&func).unwrap();

        assert!(result.code_size > 0);
    }

    #[test]
    fn test_x86_cond_invert() {
        assert_eq!(X86Cond::E.invert(), X86Cond::Ne);
        assert_eq!(X86Cond::L.invert(), X86Cond::Ge);
        assert_eq!(X86Cond::B.invert(), X86Cond::Ae);
    }

    #[test]
    fn test_lower_div_unsigned() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);

        let dividend = builder.alloc_vreg();
        let divisor = builder.alloc_vreg();
        let quotient = builder.alloc_vreg();
        let remainder = builder.alloc_vreg();

        // dividend = 100
        builder.push_op(
            0x1000,
            OpKind::Mov {
                dst: dividend,
                src: SrcOperand::imm(100),
                width: OpWidth::W64,
            },
        );

        // divisor = 7
        builder.push_op(
            0x1004,
            OpKind::Mov {
                dst: divisor,
                src: SrcOperand::imm(7),
                width: OpWidth::W64,
            },
        );

        // (quotient, remainder) = dividend / divisor
        builder.push_op(
            0x1008,
            OpKind::DivU {
                quot: quotient,
                rem: Some(remainder),
                src1: dividend,
                src2: SrcOperand::Reg(divisor),
                width: OpWidth::W64,
            },
        );

        builder.set_terminator(Terminator::Return {
            values: vec![quotient],
        });

        let func = builder.finish();

        let mut lowerer = X86_64Lowerer::new();
        let result = lowerer.lower_function(&func).unwrap();

        assert!(result.code_size > 0);
        let code = lowerer.finalize().unwrap();
        // Should contain DIV instruction (F7 /6)
        // Look for the pattern in the generated code
        assert!(!code.is_empty());
    }

    #[test]
    fn test_lower_div_signed() {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);

        let dividend = builder.alloc_vreg();
        let divisor = builder.alloc_vreg();
        let quotient = builder.alloc_vreg();

        // dividend = -100
        builder.push_op(
            0x1000,
            OpKind::Mov {
                dst: dividend,
                src: SrcOperand::imm(-100i64),
                width: OpWidth::W64,
            },
        );

        // divisor = 7
        builder.push_op(
            0x1004,
            OpKind::Mov {
                dst: divisor,
                src: SrcOperand::imm(7),
                width: OpWidth::W64,
            },
        );

        // quotient = dividend / divisor (signed)
        builder.push_op(
            0x1008,
            OpKind::DivS {
                quot: quotient,
                rem: None,
                src1: dividend,
                src2: SrcOperand::Reg(divisor),
                width: OpWidth::W64,
            },
        );

        builder.set_terminator(Terminator::Return {
            values: vec![quotient],
        });

        let func = builder.finish();

        let mut lowerer = X86_64Lowerer::new();
        let result = lowerer.lower_function(&func).unwrap();

        assert!(result.code_size > 0);
        let code = lowerer.finalize().unwrap();
        // Should contain CQO (48 99) and IDIV (F7 /7) instructions
        assert!(!code.is_empty());
    }

    #[test]
    fn test_emit_div_instructions() {
        // Test DIV instruction encoding
        let mut buf = CodeBuffer::new();
        {
            let mut emit = X86Emitter::new(&mut buf);
            emit.emit_div(PhysReg::Rcx, OpWidth::W64);
        }
        // DIV RCX = 48 F7 F1
        assert_eq!(buf.data(), &[0x48, 0xF7, 0xF1]);

        // Test IDIV instruction encoding
        let mut buf2 = CodeBuffer::new();
        {
            let mut emit = X86Emitter::new(&mut buf2);
            emit.emit_idiv(PhysReg::Rbx, OpWidth::W64);
        }
        // IDIV RBX = 48 F7 FB
        assert_eq!(buf2.data(), &[0x48, 0xF7, 0xFB]);

        // Test CQO instruction encoding
        let mut buf3 = CodeBuffer::new();
        {
            let mut emit = X86Emitter::new(&mut buf3);
            emit.emit_cqo();
        }
        // CQO = 48 99
        assert_eq!(buf3.data(), &[0x48, 0x99]);
    }
}
