//! misc.rs

use crate::isa::riscv::{
    Isa as RvIsa, Op as RvOp, Xlen as RvXlen, decode as rv_decode, rvc::decode_rvc as rv_decode_rvc,
};
use crate::smir::ir::flags::FlagUpdate;
use crate::smir::ir::ops::{OpKind, RvVectorState, SmirOp};
use crate::smir::ir::types::*;
use crate::smir::ir::{SmirBlock, SmirFunction};
use crate::smir::lift::riscv::*;

use crate::smir::lift::{
    ControlFlow, LiftContext, LiftError, LiftResult, MemoryReader, SmirLifter,
};

impl RiscVLifter {
    /// Create a new RV64 lifter with specified extensions
    pub fn new_rv64(extensions: RiscVExtensions) -> Self {
        Self {
            xlen: 64,
            extensions,
        }
    }

    /// Create a new RV32 lifter with specified extensions
    pub fn new_rv32(extensions: RiscVExtensions) -> Self {
        Self {
            xlen: 32,
            extensions,
        }
    }

    /// Create a standard RV64GC lifter
    pub fn rv64gc() -> Self {
        Self::new_rv64(RiscVExtensions::rv64gc())
    }

    /// Get the operation width for this XLEN
    pub(crate) fn op_width(&self) -> OpWidth {
        if self.xlen == 64 {
            OpWidth::W64
        } else {
            OpWidth::W32
        }
    }

    pub(crate) fn rv_xlen(&self) -> RvXlen {
        if self.xlen == 64 {
            RvXlen::Rv64
        } else {
            RvXlen::Rv32
        }
    }

    pub(crate) fn decoder_isa(&self) -> RvIsa {
        RvIsa {
            m: self.extensions.m,
            a: self.extensions.a,
            f: self.extensions.f,
            d: self.extensions.d,
            q: self.extensions.q,
            c: self.extensions.c,
            zicsr: self.extensions.zicsr,
            zifencei: self.extensions.zifencei,
            zihintpause: self.extensions.zihintpause,
            zihintntl: self.extensions.zihintntl,
            zacas: self.extensions.zacas,
            zawrs: self.extensions.zawrs,
            zicbom: self.extensions.zicbom,
            zicboz: self.extensions.zicboz,
            zicbop: self.extensions.zicbop,
            zba: self.extensions.zba,
            zbb: self.extensions.zbb,
            zbc: self.extensions.zbc,
            zbs: self.extensions.zbs,
            zicond: self.extensions.zicond,
            zfa: self.extensions.zfa,
            zbkb: self.extensions.zbkb,
            zfh: self.extensions.zfh,
            zbkx: self.extensions.zbkx,
            zknh: self.extensions.zknh,
            zksh: self.extensions.zksh,
            zksed: self.extensions.zksed,
            zkne: self.extensions.zkne,
            zknd: self.extensions.zknd,
            zcb: self.extensions.zcb,
            zcmp: self.extensions.zcmp,
            zcmt: self.extensions.zcmt,
            zclsd: self.extensions.zclsd,
            zilsd: self.extensions.zilsd,
            h: self.extensions.h,
            svinval: self.extensions.svinval,
            v: self.extensions.v,
            // The SMIR lifter is the differential-oracle path; it does not lift
            // vendor custom extensions.
            xsoteria: false,
            xandes: false,
            xthead: false,
            xhazard3: false,
            xida_sltw: self.extensions.xida_sltw,
        }
    }

    /// Get a VReg for an integer register (x0 returns Imm(0))
    pub(crate) fn get_x_reg(&self, reg: u8, _ctx: &mut LiftContext) -> VReg {
        if reg == 0 {
            VReg::Imm(0)
        } else {
            VReg::Arch(ArchReg::RiscV(RiscVReg::X(reg)))
        }
    }

    /// Define a new value for an integer register (x0 writes are ignored)
    pub(crate) fn def_x_reg(&self, reg: u8, _ctx: &mut LiftContext) -> Option<VReg> {
        if reg == 0 {
            None
        } else {
            Some(VReg::Arch(ArchReg::RiscV(RiscVReg::X(reg))))
        }
    }

    /// Get the PC register
    pub(crate) fn get_pc(&self, _ctx: &mut LiftContext) -> VReg {
        VReg::Arch(ArchReg::RiscV(RiscVReg::Pc))
    }

    /// Define a new PC value
    pub(crate) fn def_pc(&self, _ctx: &mut LiftContext) -> VReg {
        VReg::Arch(ArchReg::RiscV(RiscVReg::Pc))
    }

    // ========================================================================
    // Instruction Format Extraction
    // ========================================================================

    /// Extract rd field (bits 11:7)
    pub(crate) fn rd(insn: u32) -> u8 {
        ((insn >> 7) & 0x1F) as u8
    }

    /// Extract rs1 field (bits 19:15)
    pub(crate) fn rs1(insn: u32) -> u8 {
        ((insn >> 15) & 0x1F) as u8
    }

    /// Extract rs2 field (bits 24:20)
    pub(crate) fn rs2(insn: u32) -> u8 {
        ((insn >> 20) & 0x1F) as u8
    }

    /// Extract funct3 field (bits 14:12)
    pub(crate) fn funct3(insn: u32) -> u8 {
        ((insn >> 12) & 0x7) as u8
    }

    /// Extract funct7 field (bits 31:25)
    pub(crate) fn funct7(insn: u32) -> u8 {
        ((insn >> 25) & 0x7F) as u8
    }

    /// Extract I-type immediate (bits 31:20, sign-extended)
    pub(crate) fn imm_i(insn: u32) -> i64 {
        ((insn as i32) >> 20) as i64
    }

    /// Extract S-type immediate (bits 31:25 | 11:7, sign-extended)
    pub(crate) fn imm_s(insn: u32) -> i64 {
        let hi = ((insn >> 25) & 0x7F) as i32;
        let lo = ((insn >> 7) & 0x1F) as i32;
        let imm = (hi << 5) | lo;
        // Sign-extend from bit 11
        ((imm << 20) >> 20) as i64
    }

    /// Extract B-type immediate (bits 31|7|30:25|11:8, sign-extended, shifted left by 1)
    pub(crate) fn imm_b(insn: u32) -> i64 {
        let bit12 = ((insn >> 31) & 1) as i32;
        let bit11 = ((insn >> 7) & 1) as i32;
        let bits10_5 = ((insn >> 25) & 0x3F) as i32;
        let bits4_1 = ((insn >> 8) & 0xF) as i32;
        let imm = (bit12 << 12) | (bit11 << 11) | (bits10_5 << 5) | (bits4_1 << 1);
        // Sign-extend from bit 12
        ((imm << 19) >> 19) as i64
    }

    /// Extract U-type immediate (bits 31:12, shifted left by 12)
    pub(crate) fn imm_u(insn: u32) -> i64 {
        ((insn & 0xFFFF_F000) as i32) as i64
    }

    /// Extract J-type immediate (bits 31|19:12|20|30:21, sign-extended, shifted left by 1)
    pub(crate) fn imm_j(insn: u32) -> i64 {
        let bit20 = ((insn >> 31) & 1) as i32;
        let bits19_12 = ((insn >> 12) & 0xFF) as i32;
        let bit11 = ((insn >> 20) & 1) as i32;
        let bits10_1 = ((insn >> 21) & 0x3FF) as i32;
        let imm = (bit20 << 20) | (bits19_12 << 12) | (bit11 << 11) | (bits10_1 << 1);
        // Sign-extend from bit 20
        ((imm << 11) >> 11) as i64
    }

    // ========================================================================
    // Instruction Lifting
    // ========================================================================

    /// Lift a single 32-bit RISC-V instruction
    pub(crate) fn lift_insn32(
        &mut self,
        insn: u32,
        addr: GuestAddr,
        ctx: &mut LiftContext,
    ) -> Result<(Vec<SmirOp>, ControlFlow), LiftError> {
        let opcode = insn & 0x7F;

        match opcode {
            0x37 => self.lift_lui(insn, addr, ctx),
            0x17 => self.lift_auipc(insn, addr, ctx),
            0x6F => self.lift_jal(insn, addr, ctx),
            0x67 => self.lift_jalr(insn, addr, ctx),
            0x63 => self.lift_branch(insn, addr, ctx),
            0x03 => self.lift_load(insn, addr, ctx),
            0x23 => self.lift_store(insn, addr, ctx),
            0x13 => self.lift_op_imm(insn, addr, ctx),
            0x1B if self.xlen == 64 => self.lift_op_imm32(insn, addr, ctx),
            0x33 => self.lift_op(insn, addr, ctx),
            0x3B if self.xlen == 64 => self.lift_op32(insn, addr, ctx),
            0x0F => self.lift_fence(insn, addr, ctx),
            0x73 => self.lift_system(insn, addr, ctx),
            0x2F if self.extensions.a || self.extensions.zacas => self.lift_atomic(insn, addr, ctx),
            // FP load/store and OP-FP. Only the fflags/rounding-free ops (moves,
            // sign-inject, load/store) are lifted; arithmetic/convert/compare are
            // gaps until SMIR FP tracks fflags + NaN-boxing + frm.
            0x07 if self.extensions.f => self.lift_fp_ldst(insn, addr, ctx),
            0x27 if self.extensions.f => self.lift_fp_ldst(insn, addr, ctx),
            0x53 if self.extensions.f => self.lift_op_fp(insn, addr, ctx),
            // Fused multiply-add family (FMADD/FMSUB/FNMSUB/FNMADD .S/.D/.H).
            0x43 | 0x47 | 0x4b | 0x4f if self.extensions.f => self.lift_fp_fma(insn, addr, ctx),
            // OP-V (0x57): vector arithmetic + vset{i}vl{i} configuration. All
            // RVV ops route to the opaque RvVector engine.
            0x57 => self.lift_vector(insn, addr, ctx),
            _ => Err(LiftError::InvalidEncoding {
                addr,
                bytes: insn.to_le_bytes().to_vec(),
            }),
        }
    }

    /// LUI: Load Upper Immediate
    pub(crate) fn lift_lui(
        &mut self,
        insn: u32,
        addr: GuestAddr,
        ctx: &mut LiftContext,
    ) -> Result<(Vec<SmirOp>, ControlFlow), LiftError> {
        let rd = Self::rd(insn);
        let imm = Self::imm_u(insn);

        let mut ops = Vec::new();

        if let Some(dst) = self.def_x_reg(rd, ctx) {
            ops.push(SmirOp::new(
                ctx.next_op_id(),
                addr,
                OpKind::Mov {
                    dst,
                    src: SrcOperand::Imm(imm),
                    width: self.op_width(),
                },
            ));
        }

        Ok((ops, ControlFlow::NextInsn))
    }

    /// AUIPC: Add Upper Immediate to PC
    pub(crate) fn lift_auipc(
        &mut self,
        insn: u32,
        addr: GuestAddr,
        ctx: &mut LiftContext,
    ) -> Result<(Vec<SmirOp>, ControlFlow), LiftError> {
        let rd = Self::rd(insn);
        let imm = Self::imm_u(insn);
        let result = (addr as i64).wrapping_add(imm);

        let mut ops = Vec::new();

        if let Some(dst) = self.def_x_reg(rd, ctx) {
            ops.push(SmirOp::new(
                ctx.next_op_id(),
                addr,
                OpKind::Mov {
                    dst,
                    src: SrcOperand::Imm(result),
                    width: self.op_width(),
                },
            ));
        }

        Ok((ops, ControlFlow::NextInsn))
    }

    /// Hypervisor memory instructions (HLV*/HSV*) are modeled like direct
    /// loads/stores in the local RISC-V interpreter.
    pub(crate) fn lift_hypervisor_mem(
        &mut self,
        insn: u32,
        addr: GuestAddr,
        ctx: &mut LiftContext,
    ) -> Result<(Vec<SmirOp>, ControlFlow), LiftError> {
        let d = rv_decode(insn, self.rv_xlen(), &self.decoder_isa());
        if d.is_illegal() {
            return Err(LiftError::InvalidEncoding {
                addr,
                bytes: insn.to_le_bytes().to_vec(),
            });
        }

        let base = self.get_x_reg(d.rs1, ctx);
        let mut ops = Vec::new();

        match d.op {
            RvOp::HlvB
            | RvOp::HlvBu
            | RvOp::HlvH
            | RvOp::HlvHu
            | RvOp::HlvxHu
            | RvOp::HlvW
            | RvOp::HlvWu
            | RvOp::HlvxWu
            | RvOp::HlvD => {
                let (width, sign) = match d.op {
                    RvOp::HlvB => (MemWidth::B1, SignExtend::Sign),
                    RvOp::HlvBu => (MemWidth::B1, SignExtend::Zero),
                    RvOp::HlvH => (MemWidth::B2, SignExtend::Sign),
                    RvOp::HlvHu | RvOp::HlvxHu => (MemWidth::B2, SignExtend::Zero),
                    RvOp::HlvW => (MemWidth::B4, SignExtend::Sign),
                    RvOp::HlvWu | RvOp::HlvxWu => (MemWidth::B4, SignExtend::Zero),
                    RvOp::HlvD => (MemWidth::B8, SignExtend::Sign),
                    _ => unreachable!(),
                };
                if let Some(dst) = self.def_x_reg(d.rd, ctx) {
                    ops.push(SmirOp::new(
                        ctx.next_op_id(),
                        addr,
                        OpKind::Load {
                            dst,
                            addr: Address::Direct(base),
                            width,
                            sign,
                        },
                    ));
                }
            }
            RvOp::HsvB | RvOp::HsvH | RvOp::HsvW | RvOp::HsvD => {
                let width = match d.op {
                    RvOp::HsvB => MemWidth::B1,
                    RvOp::HsvH => MemWidth::B2,
                    RvOp::HsvW => MemWidth::B4,
                    RvOp::HsvD => MemWidth::B8,
                    _ => unreachable!(),
                };
                let src = self.get_x_reg(d.rs2, ctx);
                ops.push(SmirOp::new(
                    ctx.next_op_id(),
                    addr,
                    OpKind::Store {
                        src,
                        addr: Address::Direct(base),
                        width,
                    },
                ));
            }
            _ => {
                return Err(LiftError::InvalidEncoding {
                    addr,
                    bytes: insn.to_le_bytes().to_vec(),
                });
            }
        }

        Ok((ops, ControlFlow::NextInsn))
    }

    /// Integer register-immediate operations
    pub(crate) fn lift_op_imm(
        &mut self,
        insn: u32,
        addr: GuestAddr,
        ctx: &mut LiftContext,
    ) -> Result<(Vec<SmirOp>, ControlFlow), LiftError> {
        let rd = Self::rd(insn);
        let rs1_reg = Self::rs1(insn);
        let funct3 = Self::funct3(insn);
        let imm = Self::imm_i(insn);
        let shamt = (imm & 0x3F) as u8; // 6-bit shift amount for RV64

        // Route non-base OP-IMM (Zbb/Zbs immediates, unary count/extend) through
        // the decode-driven bit-manip path.
        let dop = rv_decode(insn, self.rv_xlen(), &self.decoder_isa()).op;
        if !matches!(
            dop,
            RvOp::Addi
                | RvOp::Slti
                | RvOp::Sltiu
                | RvOp::Xori
                | RvOp::Ori
                | RvOp::Andi
                | RvOp::Slli
                | RvOp::Srli
                | RvOp::Srai
        ) {
            return self.lift_zb_imm(insn, addr, ctx);
        }

        let rs1 = self.get_x_reg(rs1_reg, ctx);
        let width = self.op_width();

        let mut ops = Vec::new();

        if let Some(dst) = self.def_x_reg(rd, ctx) {
            let kind = match funct3 {
                0b000 => OpKind::Add {
                    // ADDI
                    dst,
                    src1: rs1,
                    src2: SrcOperand::Imm(imm),
                    width,
                    flags: FlagUpdate::None,
                },
                0b010 => {
                    // SLTI (set less than immediate)
                    ops.push(SmirOp::new(
                        ctx.next_op_id(),
                        addr,
                        OpKind::Cmp {
                            src1: rs1,
                            src2: SrcOperand::Imm(imm),
                            width,
                        },
                    ));
                    OpKind::SetCC {
                        dst,
                        cond: Condition::Slt,
                        width: OpWidth::W64,
                    }
                }
                0b011 => {
                    // SLTIU (set less than immediate unsigned)
                    ops.push(SmirOp::new(
                        ctx.next_op_id(),
                        addr,
                        OpKind::Cmp {
                            src1: rs1,
                            src2: SrcOperand::Imm(imm),
                            width,
                        },
                    ));
                    OpKind::SetCC {
                        dst,
                        cond: Condition::Ult,
                        width: OpWidth::W64,
                    }
                }
                0b100 => OpKind::Xor {
                    // XORI
                    dst,
                    src1: rs1,
                    src2: SrcOperand::Imm(imm),
                    width,
                    flags: FlagUpdate::None,
                },
                0b110 => OpKind::Or {
                    // ORI
                    dst,
                    src1: rs1,
                    src2: SrcOperand::Imm(imm),
                    width,
                    flags: FlagUpdate::None,
                },
                0b111 => OpKind::And {
                    // ANDI
                    dst,
                    src1: rs1,
                    src2: SrcOperand::Imm(imm),
                    width,
                    flags: FlagUpdate::None,
                },
                // SLLI: RV64 funct6 (bits[31:26]) must be 0; other funct6 values
                // are Zbb/Zbs/crypto immediates handled elsewhere (or not yet
                // lifted) — never silently lower them as a plain shift.
                0b001 if (insn >> 26) & 0x3F == 0 => OpKind::Shl {
                    dst,
                    src: rs1,
                    amount: SrcOperand::Imm(shamt as i64),
                    width,
                    flags: FlagUpdate::None,
                },
                // SRLI (funct6 == 0) / SRAI (funct6 == 0b010000). Any other funct6
                // (RORI/BEXTI/...) is not this instruction.
                0b101 if (insn >> 26) & 0x3F == 0 => OpKind::Shr {
                    dst,
                    src: rs1,
                    amount: SrcOperand::Imm(shamt as i64),
                    width,
                    flags: FlagUpdate::None,
                },
                0b101 if (insn >> 26) & 0x3F == 0b010000 => OpKind::Sar {
                    dst,
                    src: rs1,
                    amount: SrcOperand::Imm(shamt as i64),
                    width,
                    flags: FlagUpdate::None,
                },
                _ => {
                    return Err(LiftError::Unsupported {
                        addr,
                        mnemonic: format!("OP-IMM funct3={funct3:#05b} insn={insn:#010x}"),
                    });
                }
            };

            ops.push(SmirOp::new(ctx.next_op_id(), addr, kind));
        }

        Ok((ops, ControlFlow::NextInsn))
    }

    /// Emit `dst = term0 ^ term1 ^ term2` where each term is a rotate / shift /
    /// identity of `src`, optionally sign-extending a 32-bit result to 64 bits.
    pub(crate) fn crypto_xor3(
        &mut self,
        ctx: &mut LiftContext,
        ops: &mut Vec<SmirOp>,
        addr: GuestAddr,
        src: VReg,
        dst: VReg,
        terms: &[(CryptoTerm, i64)],
        sext32: bool,
    ) {
        let mk = |ctx: &mut LiftContext, k: OpKind| SmirOp::new(ctx.next_op_id(), addr, k);
        let term =
            |ctx: &mut LiftContext, ops: &mut Vec<SmirOp>, kind: CryptoTerm, amt: i64| -> VReg {
                if matches!(kind, CryptoTerm::X) {
                    return src;
                }
                let (tw, op): (OpWidth, u8) = match kind {
                    CryptoTerm::R => (OpWidth::W32, 0),
                    CryptoTerm::RW => (OpWidth::W64, 0),
                    CryptoTerm::L => (OpWidth::W32, 1),
                    CryptoTerm::S => (OpWidth::W32, 2),
                    CryptoTerm::SW => (OpWidth::W64, 2),
                    CryptoTerm::X => unreachable!(),
                };
                let t = ctx.alloc_vreg();
                let k = match op {
                    0 => OpKind::Ror {
                        dst: t,
                        src,
                        amount: SrcOperand::Imm(amt),
                        width: tw,
                        flags: FlagUpdate::None,
                    },
                    1 => OpKind::Rol {
                        dst: t,
                        src,
                        amount: SrcOperand::Imm(amt),
                        width: tw,
                        flags: FlagUpdate::None,
                    },
                    _ => OpKind::Shr {
                        dst: t,
                        src,
                        amount: SrcOperand::Imm(amt),
                        width: tw,
                        flags: FlagUpdate::None,
                    },
                };
                ops.push(mk(ctx, k));
                t
            };
        let xw = if sext32 { OpWidth::W32 } else { OpWidth::W64 };
        let a = term(ctx, ops, terms[0].0, terms[0].1);
        let b = term(ctx, ops, terms[1].0, terms[1].1);
        let c = term(ctx, ops, terms[2].0, terms[2].1);
        let ab = ctx.alloc_vreg();
        ops.push(mk(
            ctx,
            OpKind::Xor {
                dst: ab,
                src1: a,
                src2: SrcOperand::Reg(b),
                width: xw,
                flags: FlagUpdate::None,
            },
        ));
        if sext32 {
            let abc = ctx.alloc_vreg();
            ops.push(mk(
                ctx,
                OpKind::Xor {
                    dst: abc,
                    src1: ab,
                    src2: SrcOperand::Reg(c),
                    width: xw,
                    flags: FlagUpdate::None,
                },
            ));
            ops.push(mk(
                ctx,
                OpKind::SignExtend {
                    dst,
                    src: abc,
                    from_width: OpWidth::W32,
                    to_width: OpWidth::W64,
                },
            ));
        } else {
            ops.push(mk(
                ctx,
                OpKind::Xor {
                    dst,
                    src1: ab,
                    src2: SrcOperand::Reg(c),
                    width: xw,
                    flags: FlagUpdate::None,
                },
            ));
        }
    }

    /// 32-bit integer register-immediate operations (RV64 only)
    pub(crate) fn lift_op_imm32(
        &mut self,
        insn: u32,
        addr: GuestAddr,
        ctx: &mut LiftContext,
    ) -> Result<(Vec<SmirOp>, ControlFlow), LiftError> {
        let rd = Self::rd(insn);
        let rs1_reg = Self::rs1(insn);
        let funct3 = Self::funct3(insn);
        let imm = Self::imm_i(insn);
        let shamt = (imm & 0x1F) as u8; // 5-bit shift amount for 32-bit ops

        // Route non-base OP-IMM-32 (Zba slli.uw, Zbb roriw/clzw/cpopw/ctzw)
        // through the decode-driven word bit-manip path.
        let dop = rv_decode(insn, self.rv_xlen(), &self.decoder_isa()).op;
        if !matches!(dop, RvOp::Addiw | RvOp::Slliw | RvOp::Srliw | RvOp::Sraiw) {
            return self.lift_zb_imm32(insn, addr, ctx);
        }

        let rs1 = self.get_x_reg(rs1_reg, ctx);
        let width = OpWidth::W32;

        let mut ops = Vec::new();

        if let Some(dst) = self.def_x_reg(rd, ctx) {
            let tmp = ctx.alloc_vreg();

            let kind = match funct3 {
                0b000 => {
                    // ADDIW
                    ops.push(SmirOp::new(
                        ctx.next_op_id(),
                        addr,
                        OpKind::Add {
                            dst: tmp,
                            src1: rs1,
                            src2: SrcOperand::Imm(imm),
                            width,
                            flags: FlagUpdate::None,
                        },
                    ));
                    OpKind::SignExtend {
                        dst,
                        src: tmp,
                        from_width: OpWidth::W32,
                        to_width: OpWidth::W64,
                    }
                }
                // SLLIW: funct7 must be 0 (Zba slli.uw uses funct7 0b0000010 and
                // a 6-bit shamt — not this instruction).
                0b001 if Self::funct7(insn) == 0 => {
                    ops.push(SmirOp::new(
                        ctx.next_op_id(),
                        addr,
                        OpKind::Shl {
                            dst: tmp,
                            src: rs1,
                            amount: SrcOperand::Imm(shamt as i64),
                            width,
                            flags: FlagUpdate::None,
                        },
                    ));
                    OpKind::SignExtend {
                        dst,
                        src: tmp,
                        from_width: OpWidth::W32,
                        to_width: OpWidth::W64,
                    }
                }
                // SRLIW (funct7 == 0) / SRAIW (funct7 == 0b0100000). RORIW
                // (funct7 == 0b0110000) is not lowered here.
                0b101 if matches!(Self::funct7(insn), 0x00 | 0x20) => {
                    let arith = Self::funct7(insn) == 0x20;
                    let shift = if arith {
                        OpKind::Sar {
                            dst: tmp,
                            src: rs1,
                            amount: SrcOperand::Imm(shamt as i64),
                            width,
                            flags: FlagUpdate::None,
                        }
                    } else {
                        OpKind::Shr {
                            dst: tmp,
                            src: rs1,
                            amount: SrcOperand::Imm(shamt as i64),
                            width,
                            flags: FlagUpdate::None,
                        }
                    };
                    ops.push(SmirOp::new(ctx.next_op_id(), addr, shift));
                    OpKind::SignExtend {
                        dst,
                        src: tmp,
                        from_width: OpWidth::W32,
                        to_width: OpWidth::W64,
                    }
                }
                _ => {
                    return Err(LiftError::Unsupported {
                        addr,
                        mnemonic: format!("OP-IMM-32 funct3={funct3:#05b} insn={insn:#010x}"),
                    });
                }
            };

            ops.push(SmirOp::new(ctx.next_op_id(), addr, kind));
        }

        Ok((ops, ControlFlow::NextInsn))
    }

    /// Integer register-register operations
    pub(crate) fn lift_op(
        &mut self,
        insn: u32,
        addr: GuestAddr,
        ctx: &mut LiftContext,
    ) -> Result<(Vec<SmirOp>, ControlFlow), LiftError> {
        let rd = Self::rd(insn);
        let rs1_reg = Self::rs1(insn);
        let rs2_reg = Self::rs2(insn);
        let funct3 = Self::funct3(insn);
        let funct7 = Self::funct7(insn);

        let rs1 = self.get_x_reg(rs1_reg, ctx);
        let rs2 = self.get_x_reg(rs2_reg, ctx);
        let width = self.op_width();

        // M extension (multiply/divide)
        if funct7 == 0x01 && self.extensions.m {
            return self.lift_op_m(insn, addr, ctx);
        }
        // Anything that isn't a base RV64I register ALU op (Zba/Zbb/Zbs/Zbc/
        // Zicond/crypto) is lowered through the decode-driven bit-manip path.
        let is_base = funct7 == 0x00 || (funct7 == 0x20 && matches!(funct3, 0b000 | 0b101));
        if !is_base {
            return self.lift_zb_op(insn, addr, ctx);
        }

        let mut ops = Vec::new();

        if let Some(dst) = self.def_x_reg(rd, ctx) {
            let kind = match (funct7, funct3) {
                (0x00, 0b000) => OpKind::Add {
                    // ADD
                    dst,
                    src1: rs1,
                    src2: SrcOperand::Reg(rs2),
                    width,
                    flags: FlagUpdate::None,
                },
                (0x20, 0b000) => OpKind::Sub {
                    // SUB
                    dst,
                    src1: rs1,
                    src2: SrcOperand::Reg(rs2),
                    width,
                    flags: FlagUpdate::None,
                },
                (0x00, 0b001) => OpKind::Shl {
                    // SLL
                    dst,
                    src: rs1,
                    amount: SrcOperand::Reg(rs2),
                    width,
                    flags: FlagUpdate::None,
                },
                (0x00, 0b010) => {
                    // SLT
                    ops.push(SmirOp::new(
                        ctx.next_op_id(),
                        addr,
                        OpKind::Cmp {
                            src1: rs1,
                            src2: SrcOperand::Reg(rs2),
                            width,
                        },
                    ));
                    OpKind::SetCC {
                        dst,
                        cond: Condition::Slt,
                        width: OpWidth::W64,
                    }
                }
                (0x00, 0b011) => {
                    // SLTU
                    ops.push(SmirOp::new(
                        ctx.next_op_id(),
                        addr,
                        OpKind::Cmp {
                            src1: rs1,
                            src2: SrcOperand::Reg(rs2),
                            width,
                        },
                    ));
                    OpKind::SetCC {
                        dst,
                        cond: Condition::Ult,
                        width: OpWidth::W64,
                    }
                }
                (0x00, 0b100) => OpKind::Xor {
                    // XOR
                    dst,
                    src1: rs1,
                    src2: SrcOperand::Reg(rs2),
                    width,
                    flags: FlagUpdate::None,
                },
                (0x00, 0b101) => OpKind::Shr {
                    // SRL
                    dst,
                    src: rs1,
                    amount: SrcOperand::Reg(rs2),
                    width,
                    flags: FlagUpdate::None,
                },
                (0x20, 0b101) => OpKind::Sar {
                    // SRA
                    dst,
                    src: rs1,
                    amount: SrcOperand::Reg(rs2),
                    width,
                    flags: FlagUpdate::None,
                },
                (0x00, 0b110) => OpKind::Or {
                    // OR
                    dst,
                    src1: rs1,
                    src2: SrcOperand::Reg(rs2),
                    width,
                    flags: FlagUpdate::None,
                },
                (0x00, 0b111) => OpKind::And {
                    // AND
                    dst,
                    src1: rs1,
                    src2: SrcOperand::Reg(rs2),
                    width,
                    flags: FlagUpdate::None,
                },
                _ => {
                    return Err(LiftError::InvalidEncoding {
                        addr,
                        bytes: insn.to_le_bytes().to_vec(),
                    });
                }
            };

            ops.push(SmirOp::new(ctx.next_op_id(), addr, kind));
        }

        Ok((ops, ControlFlow::NextInsn))
    }

    /// 32-bit register-register operations (RV64 only)
    pub(crate) fn lift_op32(
        &mut self,
        insn: u32,
        addr: GuestAddr,
        ctx: &mut LiftContext,
    ) -> Result<(Vec<SmirOp>, ControlFlow), LiftError> {
        let rd = Self::rd(insn);
        let rs1_reg = Self::rs1(insn);
        let rs2_reg = Self::rs2(insn);
        let funct3 = Self::funct3(insn);
        let funct7 = Self::funct7(insn);

        let rs1 = self.get_x_reg(rs1_reg, ctx);
        let rs2 = self.get_x_reg(rs2_reg, ctx);
        let width = OpWidth::W32;

        // M extension (multiply/divide) - 32-bit variants
        if funct7 == 0x01 && self.extensions.m {
            return self.lift_op32_m(insn, addr, ctx);
        }
        // Non-base word ALU (Zba add.uw/sh*add.uw, Zbb rolw/rorw, Zbkb packw)
        // share the decode-driven bit-manip path.
        let dop = rv_decode(insn, self.rv_xlen(), &self.decoder_isa()).op;
        if !matches!(
            dop,
            RvOp::Addw | RvOp::Subw | RvOp::Sllw | RvOp::Sltw | RvOp::Srlw | RvOp::Sraw
        ) {
            return self.lift_zb_op(insn, addr, ctx);
        }

        let mut ops = Vec::new();

        if let Some(dst) = self.def_x_reg(rd, ctx) {
            let tmp = ctx.alloc_vreg();

            let inner_kind = match (funct7, funct3) {
                (0x00, 0b000) => OpKind::Add {
                    // ADDW
                    dst: tmp,
                    src1: rs1,
                    src2: SrcOperand::Reg(rs2),
                    width,
                    flags: FlagUpdate::None,
                },
                (0x20, 0b000) => OpKind::Sub {
                    // SUBW
                    dst: tmp,
                    src1: rs1,
                    src2: SrcOperand::Reg(rs2),
                    width,
                    flags: FlagUpdate::None,
                },
                (0x00, 0b010) => {
                    // IDA compatibility SLTW: signed compare of low 32-bit operands.
                    ops.push(SmirOp::new(
                        ctx.next_op_id(),
                        addr,
                        OpKind::Cmp {
                            src1: rs1,
                            src2: SrcOperand::Reg(rs2),
                            width,
                        },
                    ));
                    OpKind::SetCC {
                        dst: tmp,
                        cond: Condition::Slt,
                        width,
                    }
                }
                // Word shifts: RISC-V masks the shift amount to 5 bits, but the
                // SMIR shift only zeroes at >= width.bits() (after a 6-bit mask),
                // so pre-mask rs2 to 0x1F.
                (0x00, 0b001) | (0x00, 0b101) | (0x20, 0b101) => {
                    let amt = ctx.alloc_vreg();
                    ops.push(SmirOp::new(
                        ctx.next_op_id(),
                        addr,
                        OpKind::And {
                            dst: amt,
                            src1: rs2,
                            src2: SrcOperand::Imm(0x1F),
                            width: OpWidth::W64,
                            flags: FlagUpdate::None,
                        },
                    ));
                    let amount = SrcOperand::Reg(amt);
                    match (funct7, funct3) {
                        (0x00, 0b001) => OpKind::Shl {
                            dst: tmp,
                            src: rs1,
                            amount,
                            width,
                            flags: FlagUpdate::None,
                        },
                        (0x00, 0b101) => OpKind::Shr {
                            dst: tmp,
                            src: rs1,
                            amount,
                            width,
                            flags: FlagUpdate::None,
                        },
                        _ => OpKind::Sar {
                            dst: tmp,
                            src: rs1,
                            amount,
                            width,
                            flags: FlagUpdate::None,
                        },
                    }
                }
                _ => {
                    return Err(LiftError::Unsupported {
                        addr,
                        mnemonic: format!("OP-32 funct7={funct7:#x} funct3={funct3:#05b}"),
                    });
                }
            };

            ops.push(SmirOp::new(ctx.next_op_id(), addr, inner_kind));
            ops.push(SmirOp::new(
                ctx.next_op_id(),
                addr,
                OpKind::SignExtend {
                    dst,
                    src: tmp,
                    from_width: OpWidth::W32,
                    to_width: OpWidth::W64,
                },
            ));
        }

        Ok((ops, ControlFlow::NextInsn))
    }

    /// Emit a bit-exact [`OpKind::RvFp`] for a scalar OP-FP / FMA instruction
    /// whose result depends on `fflags` / NaN-canonicalisation / dynamic
    /// rounding. Routes the source/destination register *files* per
    /// [`crate::isa::riscv::float::fp_uses_int_src1`] /
    /// [`crate::isa::riscv::float::fp_writes_int_dst`], threads `fcsr` in and out, and
    /// updates `fcsr` even when an integer destination is `x0` (exceptions still
    /// accrue). Read all source vregs (incl. `fcsr_src`) BEFORE defining any
    /// destination so a `rd == rs1` aliasing case reads the old value.
    pub(crate) fn emit_rvfp(
        &mut self,
        d: &crate::isa::riscv::Insn,
        addr: GuestAddr,
        ctx: &mut LiftContext,
        ops: &mut Vec<SmirOp>,
    ) {
        use crate::isa::riscv::float::{fp_uses_int_src1, fp_writes_int_dst};
        let op = d.op;
        let src1 = if fp_uses_int_src1(op) {
            self.get_x_reg(d.rs1, ctx)
        } else {
            VReg::Arch(ArchReg::RiscV(RiscVReg::F(d.rs1)))
        };
        let src2 = VReg::Arch(ArchReg::RiscV(RiscVReg::F(d.rs2)));
        let src3 = VReg::Arch(ArchReg::RiscV(RiscVReg::F(d.rs3)));
        let fcsr_src = VReg::Arch(ArchReg::RiscV(RiscVReg::Csr(0x003)));
        let fcsr_dst = VReg::Arch(ArchReg::RiscV(RiscVReg::Csr(0x003)));
        let dst = if fp_writes_int_dst(op) {
            // rd == x0 discards the result but `fcsr` must still update.
            self.def_x_reg(d.rd, ctx)
                .unwrap_or_else(|| ctx.alloc_vreg())
        } else {
            VReg::Arch(ArchReg::RiscV(RiscVReg::F(d.rd)))
        };
        ops.push(SmirOp::new(
            ctx.next_op_id(),
            addr,
            OpKind::RvFp {
                dst,
                fcsr_dst,
                src1,
                src2,
                src3,
                fcsr_src,
                op,
                rm_field: d.rm(),
                xlen: self.xlen,
            },
        ));
    }

    /// Emit the RISC-V FCLASS 10-bit classification of FP value `f` (the value
    /// must already be unboxed for .S/.H) into integer register `dst`.
    pub(crate) fn emit_fclass(
        &mut self,
        ctx: &mut LiftContext,
        ops: &mut Vec<SmirOp>,
        addr: GuestAddr,
        f: VReg,
        mant_bits: u32,
        exp_bits: u32,
        dst: VReg,
    ) {
        let w = OpWidth::W64;
        let emask = (1i64 << exp_bits) - 1;
        let mmask = (1i64 << mant_bits) - 1;
        let push = |ctx: &mut LiftContext, ops: &mut Vec<SmirOp>, k: OpKind| {
            ops.push(SmirOp::new(ctx.next_op_id(), addr, k));
        };
        let shr = |ctx: &mut LiftContext, ops: &mut Vec<SmirOp>, src: VReg, amt: i64| -> VReg {
            let r = ctx.alloc_vreg();
            push(
                ctx,
                ops,
                OpKind::Shr {
                    dst: r,
                    src,
                    amount: SrcOperand::Imm(amt),
                    width: w,
                    flags: FlagUpdate::None,
                },
            );
            r
        };
        let andi = |ctx: &mut LiftContext, ops: &mut Vec<SmirOp>, src: VReg, imm: i64| -> VReg {
            let r = ctx.alloc_vreg();
            push(
                ctx,
                ops,
                OpKind::And {
                    dst: r,
                    src1: src,
                    src2: SrcOperand::Imm(imm),
                    width: w,
                    flags: FlagUpdate::None,
                },
            );
            r
        };
        let cmpset = |ctx: &mut LiftContext,
                      ops: &mut Vec<SmirOp>,
                      a: VReg,
                      imm: i64,
                      cond: Condition|
         -> VReg {
            push(
                ctx,
                ops,
                OpKind::Cmp {
                    src1: a,
                    src2: SrcOperand::Imm(imm),
                    width: w,
                },
            );
            let r = ctx.alloc_vreg();
            push(
                ctx,
                ops,
                OpKind::SetCC {
                    dst: r,
                    cond,
                    width: w,
                },
            );
            r
        };
        let andv = |ctx: &mut LiftContext, ops: &mut Vec<SmirOp>, a: VReg, b: VReg| -> VReg {
            let r = ctx.alloc_vreg();
            push(
                ctx,
                ops,
                OpKind::And {
                    dst: r,
                    src1: a,
                    src2: SrcOperand::Reg(b),
                    width: w,
                    flags: FlagUpdate::None,
                },
            );
            r
        };
        let not1 = |ctx: &mut LiftContext, ops: &mut Vec<SmirOp>, a: VReg| -> VReg {
            let r = ctx.alloc_vreg();
            push(
                ctx,
                ops,
                OpKind::Xor {
                    dst: r,
                    src1: a,
                    src2: SrcOperand::Imm(1),
                    width: w,
                    flags: FlagUpdate::None,
                },
            );
            r
        };

        let exp_sh = shr(ctx, ops, f, mant_bits as i64);
        let exp = andi(ctx, ops, exp_sh, emask);
        let sign_sh = shr(ctx, ops, f, (mant_bits + exp_bits) as i64);
        let sign = andi(ctx, ops, sign_sh, 1);
        let mant = andi(ctx, ops, f, mmask);
        let mq_sh = shr(ctx, ops, mant, (mant_bits - 1) as i64);
        let mq = andi(ctx, ops, mq_sh, 1);

        let emax = cmpset(ctx, ops, exp, emask, Condition::Eq);
        let ezero = cmpset(ctx, ops, exp, 0, Condition::Eq);
        let mzero = cmpset(ctx, ops, mant, 0, Condition::Eq);
        let mnz = not1(ctx, ops, mzero);
        let pos = not1(ctx, ops, sign);
        let nmq = not1(ctx, ops, mq);
        let enorm = {
            let a = not1(ctx, ops, emax);
            let b = not1(ctx, ops, ezero);
            andv(ctx, ops, a, b)
        };

        // (class bit index, condition vreg)
        let emz = andv(ctx, ops, emax, mzero);
        let emnz = andv(ctx, ops, emax, mnz);
        let ezmz = andv(ctx, ops, ezero, mzero);
        let ezmnz = andv(ctx, ops, ezero, mnz);
        let bits: [(i64, VReg); 10] = [
            (0, andv(ctx, ops, emz, sign)),   // -inf
            (7, andv(ctx, ops, emz, pos)),    // +inf
            (9, andv(ctx, ops, emnz, mq)),    // qNaN
            (8, andv(ctx, ops, emnz, nmq)),   // sNaN
            (3, andv(ctx, ops, ezmz, sign)),  // -0
            (4, andv(ctx, ops, ezmz, pos)),   // +0
            (2, andv(ctx, ops, ezmnz, sign)), // -subnormal
            (5, andv(ctx, ops, ezmnz, pos)),  // +subnormal
            (1, andv(ctx, ops, enorm, sign)), // -normal
            (6, andv(ctx, ops, enorm, pos)),  // +normal
        ];
        // acc = OR of (bit << k); first term initializes via Shl into acc.
        let mut acc: Option<VReg> = None;
        for (k, b) in bits {
            let t = ctx.alloc_vreg();
            push(
                ctx,
                ops,
                OpKind::Shl {
                    dst: t,
                    src: b,
                    amount: SrcOperand::Imm(k),
                    width: w,
                    flags: FlagUpdate::None,
                },
            );
            acc = Some(match acc {
                None => t,
                Some(a) => {
                    let r = ctx.alloc_vreg();
                    push(
                        ctx,
                        ops,
                        OpKind::Or {
                            dst: r,
                            src1: a,
                            src2: SrcOperand::Reg(t),
                            width: w,
                            flags: FlagUpdate::None,
                        },
                    );
                    r
                }
            });
        }
        push(
            ctx,
            ops,
            OpKind::Mov {
                dst,
                src: SrcOperand::Reg(acc.unwrap()),
                width: w,
            },
        );
    }

    /// M extension multiply/divide operations
    pub(crate) fn lift_op_m(
        &mut self,
        insn: u32,
        addr: GuestAddr,
        ctx: &mut LiftContext,
    ) -> Result<(Vec<SmirOp>, ControlFlow), LiftError> {
        let rd = Self::rd(insn);
        let rs1_reg = Self::rs1(insn);
        let rs2_reg = Self::rs2(insn);
        let funct3 = Self::funct3(insn);

        let rs1 = self.get_x_reg(rs1_reg, ctx);
        let rs2 = self.get_x_reg(rs2_reg, ctx);
        let width = self.op_width();

        let mut ops = Vec::new();

        if let Some(dst) = self.def_x_reg(rd, ctx) {
            let kind = match funct3 {
                0b000 => OpKind::MulS {
                    // MUL (lower bits)
                    dst_lo: dst,
                    dst_hi: None,
                    src1: rs1,
                    src2: SrcOperand::Reg(rs2),
                    width,
                    flags: FlagUpdate::None,
                },
                0b001 => {
                    // MULH (upper bits, signed * signed)
                    let lo = ctx.alloc_vreg();
                    OpKind::MulS {
                        dst_lo: lo,
                        dst_hi: Some(dst),
                        src1: rs1,
                        src2: SrcOperand::Reg(rs2),
                        width,
                        flags: FlagUpdate::None,
                    }
                }
                0b010 => {
                    // MULHSU (signed * unsigned, high word). No direct SMIR op,
                    // but the identity mulhsu(a,b) = mulhu(a,b) - (a<0 ? b : 0)
                    // holds (s_a = u_a - 2^64*(a<0)).
                    let lo = ctx.alloc_vreg();
                    let hi = ctx.alloc_vreg();
                    ops.push(SmirOp::new(
                        ctx.next_op_id(),
                        addr,
                        OpKind::MulU {
                            dst_lo: lo,
                            dst_hi: Some(hi),
                            src1: rs1,
                            src2: SrcOperand::Reg(rs2),
                            width,
                            flags: FlagUpdate::None,
                        },
                    ));
                    ops.push(SmirOp::new(
                        ctx.next_op_id(),
                        addr,
                        OpKind::Cmp {
                            src1: rs1,
                            src2: SrcOperand::Imm(0),
                            width,
                        },
                    ));
                    let neg = ctx.alloc_vreg();
                    ops.push(SmirOp::new(
                        ctx.next_op_id(),
                        addr,
                        OpKind::SetCC {
                            dst: neg,
                            cond: Condition::Slt,
                            width,
                        },
                    ));
                    let zero = ctx.alloc_vreg();
                    ops.push(SmirOp::new(
                        ctx.next_op_id(),
                        addr,
                        OpKind::Mov {
                            dst: zero,
                            src: SrcOperand::Imm(0),
                            width,
                        },
                    ));
                    let subv = ctx.alloc_vreg();
                    ops.push(SmirOp::new(
                        ctx.next_op_id(),
                        addr,
                        OpKind::Select {
                            dst: subv,
                            cond: neg,
                            src_true: rs2,
                            src_false: zero,
                            width,
                        },
                    ));
                    ops.push(SmirOp::new(
                        ctx.next_op_id(),
                        addr,
                        OpKind::Sub {
                            dst,
                            src1: hi,
                            src2: SrcOperand::Reg(subv),
                            width,
                            flags: FlagUpdate::None,
                        },
                    ));
                    return Ok((ops, ControlFlow::NextInsn));
                }
                0b011 => {
                    // MULHU (upper bits, unsigned * unsigned)
                    let lo = ctx.alloc_vreg();
                    OpKind::MulU {
                        dst_lo: lo,
                        dst_hi: Some(dst),
                        src1: rs1,
                        src2: SrcOperand::Reg(rs2),
                        width,
                        flags: FlagUpdate::None,
                    }
                }
                // DIV/DIVU/REM/REMU: SMIR's DivS/DivU trap (x86 #DE) on a zero
                // divisor and don't implement RISC-V's div-by-zero/overflow
                // results; lifted via a non-trapping sequence below instead.
                0b100 | 0b101 | 0b110 | 0b111 => {
                    let ovf_min = match width {
                        OpWidth::W32 => i32::MIN as i64,
                        _ => i64::MIN,
                    };
                    return self.lift_div_rem(insn, addr, dst, rs1, rs2, width, ovf_min, ctx);
                }
                _ => unreachable!(),
            };

            ops.push(SmirOp::new(ctx.next_op_id(), addr, kind));
        }

        Ok((ops, ControlFlow::NextInsn))
    }

    /// Lift DIV/DIVU/REM/REMU via a non-trapping sequence implementing RISC-V's
    /// divide-by-zero and signed MIN/-1 overflow results (SMIR's DivS/DivU trap
    /// like x86 #DE, so the divisor is first sanitized and the special results
    /// are selected afterward). `width` is the operation width.
    pub(crate) fn lift_div_rem(
        &mut self,
        insn: u32,
        addr: GuestAddr,
        dst: VReg,
        rs1: VReg,
        rs2: VReg,
        width: OpWidth,
        ovf_min: i64,
        ctx: &mut LiftContext,
    ) -> Result<(Vec<SmirOp>, ControlFlow), LiftError> {
        let funct3 = Self::funct3(insn);
        let signed = matches!(funct3, 0b100 | 0b110); // DIV, REM
        let is_rem = matches!(funct3, 0b110 | 0b111);
        let mut ops = Vec::new();
        let mk = |ctx: &mut LiftContext, k: OpKind| SmirOp::new(ctx.next_op_id(), addr, k);
        let mov = |ctx: &mut LiftContext, ops: &mut Vec<SmirOp>, v: i64| -> VReg {
            let t = ctx.alloc_vreg();
            ops.push(SmirOp::new(
                ctx.next_op_id(),
                addr,
                OpKind::Mov {
                    dst: t,
                    src: SrcOperand::Imm(v),
                    width,
                },
            ));
            t
        };
        let setcc = |ctx: &mut LiftContext,
                     ops: &mut Vec<SmirOp>,
                     a: VReg,
                     b: i64,
                     cond: Condition|
         -> VReg {
            ops.push(SmirOp::new(
                ctx.next_op_id(),
                addr,
                OpKind::Cmp {
                    src1: a,
                    src2: SrcOperand::Imm(b),
                    width,
                },
            ));
            let r = ctx.alloc_vreg();
            ops.push(SmirOp::new(
                ctx.next_op_id(),
                addr,
                OpKind::SetCC {
                    dst: r,
                    cond,
                    width: OpWidth::W64,
                },
            ));
            r
        };

        // is_zero = (rs2 == 0)
        let is_zero = setcc(ctx, &mut ops, rs2, 0, Condition::Eq);
        // For signed forms, detect MIN / -1 overflow.
        let (need_special, ovf) = if signed {
            let min = ovf_min;
            let is_min = setcc(ctx, &mut ops, rs1, min, Condition::Eq);
            let is_neg1 = setcc(ctx, &mut ops, rs2, -1, Condition::Eq);
            let ovf = ctx.alloc_vreg();
            ops.push(mk(
                ctx,
                OpKind::And {
                    dst: ovf,
                    src1: is_min,
                    src2: SrcOperand::Reg(is_neg1),
                    width: OpWidth::W64,
                    flags: FlagUpdate::None,
                },
            ));
            let nsp = ctx.alloc_vreg();
            ops.push(mk(
                ctx,
                OpKind::Or {
                    dst: nsp,
                    src1: is_zero,
                    src2: SrcOperand::Reg(ovf),
                    width: OpWidth::W64,
                    flags: FlagUpdate::None,
                },
            ));
            (nsp, Some(ovf))
        } else {
            (is_zero, None)
        };

        // safe_divisor = need_special ? 1 : rs2  (avoids /0 and signed MIN/-1).
        let one = mov(ctx, &mut ops, 1);
        let safe = ctx.alloc_vreg();
        ops.push(mk(
            ctx,
            OpKind::Select {
                dst: safe,
                cond: need_special,
                src_true: one,
                src_false: rs2,
                width,
            },
        ));
        // Raw quotient / remainder over the sanitized divisor.
        let raw = ctx.alloc_vreg();
        let divkind = if signed {
            OpKind::DivS {
                quot: if is_rem { ctx.alloc_vreg() } else { raw },
                rem: if is_rem { Some(raw) } else { None },
                src1: rs1,
                src2: SrcOperand::Reg(safe),
                width,
                flags: FlagUpdate::None,
            }
        } else {
            OpKind::DivU {
                quot: if is_rem { ctx.alloc_vreg() } else { raw },
                rem: if is_rem { Some(raw) } else { None },
                src1: rs1,
                src2: SrcOperand::Reg(safe),
                width,
                flags: FlagUpdate::None,
            }
        };
        ops.push(mk(ctx, divkind));

        // Apply the overflow special-case for signed forms.
        let after_ovf = if let Some(ovf) = ovf {
            let ov_val = mov(ctx, &mut ops, if is_rem { 0 } else { ovf_min });
            let t = ctx.alloc_vreg();
            ops.push(mk(
                ctx,
                OpKind::Select {
                    dst: t,
                    cond: ovf,
                    src_true: ov_val,
                    src_false: raw,
                    width,
                },
            ));
            t
        } else {
            raw
        };
        // Apply the divide-by-zero special-case: REM->dividend, DIV->all-ones.
        let zero_val = if is_rem { rs1 } else { mov(ctx, &mut ops, -1) };
        ops.push(mk(
            ctx,
            OpKind::Select {
                dst,
                cond: is_zero,
                src_true: zero_val,
                src_false: after_ovf,
                width,
            },
        ));

        Ok((ops, ControlFlow::NextInsn))
    }

    /// M extension 32-bit multiply/divide operations
    pub(crate) fn lift_op32_m(
        &mut self,
        insn: u32,
        addr: GuestAddr,
        ctx: &mut LiftContext,
    ) -> Result<(Vec<SmirOp>, ControlFlow), LiftError> {
        let rd = Self::rd(insn);
        let rs1_reg = Self::rs1(insn);
        let rs2_reg = Self::rs2(insn);
        let funct3 = Self::funct3(insn);

        let rs1 = self.get_x_reg(rs1_reg, ctx);
        let rs2 = self.get_x_reg(rs2_reg, ctx);
        let width = OpWidth::W32;

        // Word div/rem: sign/zero-extend the operands to 64 bits, run the
        // non-trapping div sequence at W64 with a 32-bit overflow min, then
        // sign-extend the low 32 bits of the result into rd. (Operating the div
        // directly at W32 trips the interp's x86-style quotient-overflow #DE.)
        if matches!(funct3, 0b100 | 0b101 | 0b110 | 0b111) {
            let signed = matches!(funct3, 0b100 | 0b110);
            let ext_kind = |dst, src| {
                if signed {
                    OpKind::SignExtend {
                        dst,
                        src,
                        from_width: OpWidth::W32,
                        to_width: OpWidth::W64,
                    }
                } else {
                    OpKind::ZeroExtend {
                        dst,
                        src,
                        from_width: OpWidth::W32,
                        to_width: OpWidth::W64,
                    }
                }
            };
            let mut ops2 = Vec::new();
            let e1 = ctx.alloc_vreg();
            ops2.push(SmirOp::new(ctx.next_op_id(), addr, ext_kind(e1, rs1)));
            let e2 = ctx.alloc_vreg();
            ops2.push(SmirOp::new(ctx.next_op_id(), addr, ext_kind(e2, rs2)));
            let tmp = ctx.alloc_vreg();
            let (dr_ops, cf) =
                self.lift_div_rem(insn, addr, tmp, e1, e2, OpWidth::W64, -(1i64 << 31), ctx)?;
            ops2.extend(dr_ops);
            if let Some(dst) = self.def_x_reg(rd, ctx) {
                ops2.push(SmirOp::new(
                    ctx.next_op_id(),
                    addr,
                    OpKind::SignExtend {
                        dst,
                        src: tmp,
                        from_width: OpWidth::W32,
                        to_width: OpWidth::W64,
                    },
                ));
            }
            return Ok((ops2, cf));
        }

        let mut ops = Vec::new();

        if let Some(dst) = self.def_x_reg(rd, ctx) {
            let tmp = ctx.alloc_vreg();

            let inner_kind = match funct3 {
                0b000 => OpKind::MulS {
                    // MULW
                    dst_lo: tmp,
                    dst_hi: None,
                    src1: rs1,
                    src2: SrcOperand::Reg(rs2),
                    width,
                    flags: FlagUpdate::None,
                },
                _ => {
                    return Err(LiftError::Unsupported {
                        addr,
                        mnemonic: format!("OP-32-M funct3={funct3:#05b}"),
                    });
                }
            };

            ops.push(SmirOp::new(ctx.next_op_id(), addr, inner_kind));
            ops.push(SmirOp::new(
                ctx.next_op_id(),
                addr,
                OpKind::SignExtend {
                    dst,
                    src: tmp,
                    from_width: OpWidth::W32,
                    to_width: OpWidth::W64,
                },
            ));
        }

        Ok((ops, ControlFlow::NextInsn))
    }

    // ========================================================================
    // Compressed Instructions (C extension)
    // ========================================================================

    /// Lift a 16-bit compressed instruction
    pub(crate) fn lift_insn16(
        &mut self,
        insn: u16,
        addr: GuestAddr,
        ctx: &mut LiftContext,
    ) -> Result<(Vec<SmirOp>, ControlFlow), LiftError> {
        if (self.xlen == 32 && self.extensions.zclsd)
            || self.extensions.zcmp
            || self.extensions.zcmt
        {
            let decoded = rv_decode_rvc(insn, self.rv_xlen(), &self.decoder_isa());
            match decoded.op {
                RvOp::LdPair => {
                    return self.lift_load_pair(decoded.rd, decoded.rs1, decoded.imm, addr, ctx);
                }
                RvOp::SdPair => {
                    return self.lift_store_pair(decoded.rs2, decoded.rs1, decoded.imm, addr, ctx);
                }
                RvOp::CmMvsa01 | RvOp::CmMva01s => {
                    return self.lift_zcmp_move(decoded.op, decoded.rd, decoded.rs1, addr, ctx);
                }
                RvOp::CmPush | RvOp::CmPop | RvOp::CmPopRet | RvOp::CmPopRetz => {
                    return self.lift_zcmp_stack(&decoded, addr, ctx);
                }
                RvOp::CmJt | RvOp::CmJalt => return self.lift_zcmt(&decoded, addr, ctx),
                _ => {}
            }
        }
        let op = insn & 0x3;
        let funct3 = (insn >> 13) & 0x7;

        match (op, funct3) {
            // Quadrant 0
            (0b00, 0b000) if insn != 0 => self.lift_c_addi4spn(insn, addr, ctx),
            (0b00, 0b100) if self.extensions.zcb => self.lift_c_zcb_ldst(insn, addr, ctx),
            (0b00, 0b010) => self.lift_c_lw(insn, addr, ctx),
            (0b00, 0b001) if self.extensions.d => self.lift_c_fp_ldst(insn, addr, ctx), // c.fld
            (0b00, 0b011) if self.xlen == 64 => self.lift_c_ld(insn, addr, ctx),
            (0b00, 0b110) => self.lift_c_sw(insn, addr, ctx),
            (0b00, 0b101) if self.extensions.d => self.lift_c_fp_ldst(insn, addr, ctx), // c.fsd
            (0b00, 0b111) if self.xlen == 64 => self.lift_c_sd(insn, addr, ctx),

            // Quadrant 1
            (0b01, 0b000) => self.lift_c_addi(insn, addr, ctx), // C.NOP/C.ADDI
            (0b01, 0b001) if self.xlen == 64 => self.lift_c_addiw(insn, addr, ctx),
            (0b01, 0b001) if self.xlen == 32 => self.lift_c_jal(insn, addr, ctx),
            (0b01, 0b010) => self.lift_c_li(insn, addr, ctx),
            (0b01, 0b011) => self.lift_c_lui_addi16sp(insn, addr, ctx),
            (0b01, 0b100) => self.lift_c_misc_alu(insn, addr, ctx),
            (0b01, 0b101) => self.lift_c_j(insn, addr, ctx),
            (0b01, 0b110) => self.lift_c_beqz(insn, addr, ctx),
            (0b01, 0b111) => self.lift_c_bnez(insn, addr, ctx),

            // Quadrant 2
            (0b10, 0b000) => self.lift_c_slli(insn, addr, ctx),
            (0b10, 0b010) => self.lift_c_lwsp(insn, addr, ctx),
            (0b10, 0b001) if self.extensions.d => self.lift_c_fp_ldst(insn, addr, ctx), // c.fldsp
            (0b10, 0b011) if self.xlen == 64 => self.lift_c_ldsp(insn, addr, ctx),
            (0b10, 0b100) => self.lift_c_jr_mv_add(insn, addr, ctx),
            (0b10, 0b110) => self.lift_c_swsp(insn, addr, ctx),
            (0b10, 0b101) if self.extensions.d => self.lift_c_fp_ldst(insn, addr, ctx), // c.fsdsp
            (0b10, 0b111) if self.xlen == 64 => self.lift_c_sdsp(insn, addr, ctx),

            _ => Err(LiftError::InvalidEncoding {
                addr,
                bytes: insn.to_le_bytes().to_vec(),
            }),
        }
    }

    /// Get compressed register (rd', rs1', rs2' - maps 0-7 to x8-x15)
    pub(crate) fn creg(r: u8) -> u8 {
        8 + (r & 0x7)
    }

    // Extract C.J / C.JAL offset
    pub(crate) fn c_j_offset(&self, insn: u16) -> i64 {
        let bit11 = ((insn >> 12) & 1) as i16;
        let bit4 = ((insn >> 11) & 1) as i16;
        let bit9_8 = ((insn >> 9) & 0x3) as i16;
        let bit10 = ((insn >> 8) & 1) as i16;
        let bit6 = ((insn >> 7) & 1) as i16;
        let bit7 = ((insn >> 6) & 1) as i16;
        let bit3_1 = ((insn >> 3) & 0x7) as i16;
        let bit5 = ((insn >> 2) & 1) as i16;

        let raw = (bit11 << 11)
            | (bit10 << 10)
            | (bit9_8 << 8)
            | (bit7 << 7)
            | (bit6 << 6)
            | (bit5 << 5)
            | (bit4 << 4)
            | (bit3_1 << 1);
        ((raw << 4) >> 4) as i64 // Sign-extend from 12 bits
    }

    pub(crate) fn c_branch_offset(&self, insn: u16) -> i64 {
        let bit8 = ((insn >> 12) & 1) as i16;
        let bit4_3 = ((insn >> 10) & 0x3) as i16;
        let bit7_6 = ((insn >> 5) & 0x3) as i16;
        let bit2_1 = ((insn >> 3) & 0x3) as i16;
        let bit5 = ((insn >> 2) & 1) as i16;

        let raw = (bit8 << 8) | (bit7_6 << 6) | (bit5 << 5) | (bit4_3 << 3) | (bit2_1 << 1);
        ((raw << 7) >> 7) as i64 // Sign-extend from 9 bits
    }
}
