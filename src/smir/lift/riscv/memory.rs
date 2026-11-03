//! memory.rs

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
    /// Load instructions (LB, LH, LW, LD, LBU, LHU, LWU)
    pub(crate) fn lift_load(
        &mut self,
        insn: u32,
        addr: GuestAddr,
        ctx: &mut LiftContext,
    ) -> Result<(Vec<SmirOp>, ControlFlow), LiftError> {
        let rd = Self::rd(insn);
        let rs1_reg = Self::rs1(insn);
        let funct3 = Self::funct3(insn);
        let imm = Self::imm_i(insn);

        if self.xlen == 32 && funct3 == 0b011 {
            if self.extensions.zilsd && rd & 1 == 0 {
                return self.lift_load_pair(rd, rs1_reg, imm, addr, ctx);
            }
            return Err(LiftError::InvalidEncoding {
                addr,
                bytes: insn.to_le_bytes().to_vec(),
            });
        }

        let rs1 = self.get_x_reg(rs1_reg, ctx);

        let (width, sign) = match funct3 {
            0b000 => (MemWidth::B1, SignExtend::Sign), // LB
            0b001 => (MemWidth::B2, SignExtend::Sign), // LH
            0b010 => (MemWidth::B4, SignExtend::Sign), // LW
            0b011 => (MemWidth::B8, SignExtend::Zero), // LD (RV64)
            0b100 => (MemWidth::B1, SignExtend::Zero), // LBU
            0b101 => (MemWidth::B2, SignExtend::Zero), // LHU
            0b110 => (MemWidth::B4, SignExtend::Zero), // LWU (RV64)
            _ => {
                return Err(LiftError::InvalidEncoding {
                    addr,
                    bytes: insn.to_le_bytes().to_vec(),
                });
            }
        };

        let mut ops = Vec::new();
        // x0 suppresses only the architectural register write. The memory
        // access must remain observable and faulting, so discard its value into
        // a temporary virtual register.
        let dst = self.def_x_reg(rd, ctx).unwrap_or_else(|| ctx.alloc_vreg());
        let address = Address::BaseOffset {
            base: rs1,
            offset: imm,
            disp_size: DispSize::Auto,
        };
        ops.push(SmirOp::new(
            ctx.next_op_id(),
            addr,
            OpKind::Load {
                dst,
                addr: address,
                width,
                sign,
            },
        ));

        Ok((ops, ControlFlow::NextInsn))
    }

    /// Store instructions (SB, SH, SW, SD)
    pub(crate) fn lift_store(
        &mut self,
        insn: u32,
        addr: GuestAddr,
        ctx: &mut LiftContext,
    ) -> Result<(Vec<SmirOp>, ControlFlow), LiftError> {
        let rs1_reg = Self::rs1(insn);
        let rs2_reg = Self::rs2(insn);
        let funct3 = Self::funct3(insn);
        let imm = Self::imm_s(insn);

        if self.xlen == 32 && funct3 == 0b011 {
            if self.extensions.zilsd && rs2_reg & 1 == 0 {
                return self.lift_store_pair(rs2_reg, rs1_reg, imm, addr, ctx);
            }
            return Err(LiftError::InvalidEncoding {
                addr,
                bytes: insn.to_le_bytes().to_vec(),
            });
        }

        let rs1 = self.get_x_reg(rs1_reg, ctx);
        let rs2 = self.get_x_reg(rs2_reg, ctx);

        let width = match funct3 {
            0b000 => MemWidth::B1, // SB
            0b001 => MemWidth::B2, // SH
            0b010 => MemWidth::B4, // SW
            0b011 => MemWidth::B8, // SD (RV64)
            _ => {
                return Err(LiftError::InvalidEncoding {
                    addr,
                    bytes: insn.to_le_bytes().to_vec(),
                });
            }
        };

        let mut ops = Vec::new();
        let address = Address::BaseOffset {
            base: rs1,
            offset: imm,
            disp_size: DispSize::Auto,
        };

        ops.push(SmirOp::new(
            ctx.next_op_id(),
            addr,
            OpKind::Store {
                src: rs2,
                addr: address,
                width,
            },
        ));

        Ok((ops, ControlFlow::NextInsn))
    }

    /// RV32 Zilsd/Zclsd `ld`: one 64-bit memory access followed by an exact
    /// low/high split into the aligned destination pair. `rd=x0` discards the
    /// complete result and does not access or write x1.
    pub(crate) fn lift_load_pair(
        &mut self,
        rd: u8,
        rs1: u8,
        imm: i64,
        addr: GuestAddr,
        ctx: &mut LiftContext,
    ) -> Result<(Vec<SmirOp>, ControlFlow), LiftError> {
        if self.xlen != 32 || rd & 1 != 0 {
            return Err(LiftError::Internal(format!(
                "RV32 pair lift received invalid destination x{rd}"
            )));
        }
        let packed = ctx.alloc_vreg();
        let mut ops = vec![SmirOp::new(
            ctx.next_op_id(),
            addr,
            OpKind::Load {
                dst: packed,
                addr: Address::BaseOffset {
                    base: self.get_x_reg(rs1, ctx),
                    offset: imm,
                    disp_size: DispSize::Auto,
                },
                width: MemWidth::B8,
                sign: SignExtend::Zero,
            },
        )];

        if rd != 0 {
            let low = self
                .def_x_reg(rd, ctx)
                .expect("nonzero aligned pair destination");
            let high = self
                .def_x_reg(rd + 1, ctx)
                .expect("aligned pair high destination");
            let shifted = ctx.alloc_vreg();
            ops.push(SmirOp::new(
                ctx.next_op_id(),
                addr,
                OpKind::ZeroExtend {
                    dst: low,
                    src: packed,
                    from_width: OpWidth::W32,
                    to_width: OpWidth::W64,
                },
            ));
            ops.push(SmirOp::new(
                ctx.next_op_id(),
                addr,
                OpKind::Shr {
                    dst: shifted,
                    src: packed,
                    amount: SrcOperand::Imm(32),
                    width: OpWidth::W64,
                    flags: FlagUpdate::None,
                },
            ));
            ops.push(SmirOp::new(
                ctx.next_op_id(),
                addr,
                OpKind::ZeroExtend {
                    dst: high,
                    src: shifted,
                    from_width: OpWidth::W32,
                    to_width: OpWidth::W64,
                },
            ));
        }
        Ok((ops, ControlFlow::NextInsn))
    }

    /// RV32 Zilsd/Zclsd `sd`: concatenate the aligned source pair and perform
    /// one 64-bit memory access. `rs2=x0` stores 64 zero bits without reading
    /// x1, as required by the extension.
    pub(crate) fn lift_store_pair(
        &mut self,
        rs2: u8,
        rs1: u8,
        imm: i64,
        addr: GuestAddr,
        ctx: &mut LiftContext,
    ) -> Result<(Vec<SmirOp>, ControlFlow), LiftError> {
        if self.xlen != 32 || rs2 & 1 != 0 {
            return Err(LiftError::Internal(format!(
                "RV32 pair lift received invalid source x{rs2}"
            )));
        }
        let mut ops = Vec::new();
        let packed = if rs2 == 0 {
            VReg::Imm(0)
        } else {
            let low = ctx.alloc_vreg();
            let high = ctx.alloc_vreg();
            let shifted = ctx.alloc_vreg();
            let packed = ctx.alloc_vreg();
            ops.push(SmirOp::new(
                ctx.next_op_id(),
                addr,
                OpKind::ZeroExtend {
                    dst: low,
                    src: self.get_x_reg(rs2, ctx),
                    from_width: OpWidth::W32,
                    to_width: OpWidth::W64,
                },
            ));
            ops.push(SmirOp::new(
                ctx.next_op_id(),
                addr,
                OpKind::ZeroExtend {
                    dst: high,
                    src: self.get_x_reg(rs2 + 1, ctx),
                    from_width: OpWidth::W32,
                    to_width: OpWidth::W64,
                },
            ));
            ops.push(SmirOp::new(
                ctx.next_op_id(),
                addr,
                OpKind::Shl {
                    dst: shifted,
                    src: high,
                    amount: SrcOperand::Imm(32),
                    width: OpWidth::W64,
                    flags: FlagUpdate::None,
                },
            ));
            ops.push(SmirOp::new(
                ctx.next_op_id(),
                addr,
                OpKind::Or {
                    dst: packed,
                    src1: shifted,
                    src2: SrcOperand::Reg(low),
                    width: OpWidth::W64,
                    flags: FlagUpdate::None,
                },
            ));
            packed
        };
        ops.push(SmirOp::new(
            ctx.next_op_id(),
            addr,
            OpKind::Store {
                src: packed,
                addr: Address::BaseOffset {
                    base: self.get_x_reg(rs1, ctx),
                    offset: imm,
                    disp_size: DispSize::Auto,
                },
                width: MemWidth::B8,
            },
        ));
        Ok((ops, ControlFlow::NextInsn))
    }

    /// Pack before defining either destination: source/address pairs may alias.
    fn pack_atomic_word_pair(
        &self,
        register: u8,
        addr: GuestAddr,
        ctx: &mut LiftContext,
        ops: &mut Vec<SmirOp>,
    ) -> VReg {
        if register == 0 {
            return VReg::Imm(0);
        }
        let low = ctx.alloc_vreg();
        let high = ctx.alloc_vreg();
        let shifted = ctx.alloc_vreg();
        let packed = ctx.alloc_vreg();
        for (dst, source) in [(low, register), (high, register + 1)] {
            ops.push(SmirOp::new(
                ctx.next_op_id(),
                addr,
                OpKind::ZeroExtend {
                    dst,
                    src: self.get_x_reg(source, ctx),
                    from_width: OpWidth::W32,
                    to_width: OpWidth::W64,
                },
            ));
        }
        ops.push(SmirOp::new(
            ctx.next_op_id(),
            addr,
            OpKind::Shl {
                dst: shifted,
                src: high,
                amount: SrcOperand::Imm(32),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        ));
        ops.push(SmirOp::new(
            ctx.next_op_id(),
            addr,
            OpKind::Or {
                dst: packed,
                src1: shifted,
                src2: SrcOperand::Reg(low),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        ));
        packed
    }

    fn lift_rv32_cas_pair(
        &mut self,
        insn: u32,
        addr: GuestAddr,
        order: MemoryOrder,
        ctx: &mut LiftContext,
    ) -> Result<(Vec<SmirOp>, ControlFlow), LiftError> {
        let rd = Self::rd(insn);
        let rs1 = Self::rs1(insn);
        let rs2 = Self::rs2(insn);
        if rd & 1 != 0 || rs2 & 1 != 0 {
            return Err(LiftError::InvalidEncoding {
                addr,
                bytes: insn.to_le_bytes().to_vec(),
            });
        }
        let mut ops = Vec::new();
        let address = ctx.alloc_vreg();
        ops.push(SmirOp::new(
            ctx.next_op_id(),
            addr,
            OpKind::ZeroExtend {
                dst: address,
                src: self.get_x_reg(rs1, ctx),
                from_width: OpWidth::W32,
                to_width: OpWidth::W64,
            },
        ));
        let expected = self.pack_atomic_word_pair(rd, addr, ctx, &mut ops);
        let new_val = self.pack_atomic_word_pair(rs2, addr, ctx, &mut ops);
        let packed = ctx.alloc_vreg();
        ops.push(SmirOp::new(
            ctx.next_op_id(),
            addr,
            OpKind::Cas {
                dst: packed,
                success: ctx.alloc_vreg(),
                addr: Address::Direct(address),
                expected,
                new_val,
                width: MemWidth::B8,
                order,
            },
        ));
        if rd != 0 {
            let shifted = ctx.alloc_vreg();
            ops.push(SmirOp::new(
                ctx.next_op_id(),
                addr,
                OpKind::ZeroExtend {
                    dst: self.def_x_reg(rd, ctx).expect("nonzero pair low result"),
                    src: packed,
                    from_width: OpWidth::W32,
                    to_width: OpWidth::W64,
                },
            ));
            ops.push(SmirOp::new(
                ctx.next_op_id(),
                addr,
                OpKind::Shr {
                    dst: shifted,
                    src: packed,
                    amount: SrcOperand::Imm(32),
                    width: OpWidth::W64,
                    flags: FlagUpdate::None,
                },
            ));
            ops.push(SmirOp::new(
                ctx.next_op_id(),
                addr,
                OpKind::ZeroExtend {
                    dst: self
                        .def_x_reg(rd + 1, ctx)
                        .expect("nonzero pair high result"),
                    src: shifted,
                    from_width: OpWidth::W32,
                    to_width: OpWidth::W64,
                },
            ));
        }
        Ok((ops, ControlFlow::NextInsn))
    }

    /// Atomic instructions (A extension)
    pub(crate) fn lift_atomic(
        &mut self,
        insn: u32,
        addr: GuestAddr,
        ctx: &mut LiftContext,
    ) -> Result<(Vec<SmirOp>, ControlFlow), LiftError> {
        // The public lifter must enforce the same XLEN, extension and reserved
        // fields as direct execution. Zacas supplies Zaamo, never Zalrsc.
        let decoded = crate::isa::riscv::decode(insn, self.rv_xlen(), &self.decoder_isa());
        if decoded.is_illegal() {
            return Err(LiftError::InvalidEncoding {
                addr,
                bytes: insn.to_le_bytes().to_vec(),
            });
        }
        let rd = Self::rd(insn);
        let rs1_reg = Self::rs1(insn);
        let rs2_reg = Self::rs2(insn);
        let funct3 = Self::funct3(insn);
        let funct5 = (insn >> 27) & 0x1F;
        let aq = ((insn >> 26) & 1) != 0;
        let rl = ((insn >> 25) & 1) != 0;

        let rs1 = self.get_x_reg(rs1_reg, ctx);
        let rs2 = self.get_x_reg(rs2_reg, ctx);
        let rd_old = self.get_x_reg(rd, ctx);

        let width = match funct3 {
            0b010 => MemWidth::B4, // 32-bit
            0b011 => MemWidth::B8, // 64-bit
            0b100 if self.xlen == 64 && self.extensions.zacas && funct5 == 0b00101 => MemWidth::B16,
            _ => {
                return Err(LiftError::InvalidEncoding {
                    addr,
                    bytes: insn.to_le_bytes().to_vec(),
                });
            }
        };

        let order = match (aq, rl) {
            (false, false) => MemoryOrder::Relaxed,
            (true, false) => MemoryOrder::Acquire,
            (false, true) => MemoryOrder::Release,
            (true, true) => MemoryOrder::SeqCst,
        };

        if self.xlen == 32 && width == MemWidth::B8 && funct5 == 0b00101 && self.extensions.zacas {
            return self.lift_rv32_cas_pair(insn, addr, order, ctx);
        }
        let mut ops = Vec::new();
        let address = if self.xlen == 32 {
            let normalized = ctx.alloc_vreg();
            ops.push(SmirOp::new(
                ctx.next_op_id(),
                addr,
                OpKind::ZeroExtend {
                    dst: normalized,
                    src: rs1,
                    from_width: OpWidth::W32,
                    to_width: OpWidth::W64,
                },
            ));
            Address::Direct(normalized)
        } else {
            Address::Direct(rs1)
        };

        if width == MemWidth::B16 {
            if rd & 1 != 0 || rs2_reg & 1 != 0 {
                return Err(LiftError::InvalidEncoding {
                    addr,
                    bytes: insn.to_le_bytes().to_vec(),
                });
            }
            // Both architectural register pairs are now in range. A pair whose
            // first register is x0 reads as two zero words; an rd=x0 result
            // discards both words.
            let dst_lo = self.def_x_reg(rd, ctx).unwrap_or_else(|| ctx.alloc_vreg());
            let dst_hi = if rd == 0 {
                ctx.alloc_vreg()
            } else {
                self.def_x_reg(rd + 1, ctx)
                    .expect("nonzero AMOCAS.Q high destination cannot be x0")
            };
            ops.push(SmirOp::new(
                ctx.next_op_id(),
                addr,
                OpKind::CasPair {
                    dst_lo,
                    dst_hi,
                    success: ctx.alloc_vreg(),
                    addr: address,
                    expected_lo: rd_old,
                    expected_hi: if rd == 0 {
                        VReg::Imm(0)
                    } else {
                        self.get_x_reg(rd + 1, ctx)
                    },
                    new_lo: rs2,
                    new_hi: if rs2_reg == 0 {
                        VReg::Imm(0)
                    } else {
                        self.get_x_reg(rs2_reg + 1, ctx)
                    },
                    order,
                    failure_order: if aq {
                        MemoryOrder::Acquire
                    } else {
                        MemoryOrder::Relaxed
                    },
                },
            ));
            return Ok((ops, ControlFlow::NextInsn));
        }

        {
            // AMO/SC have a memory side effect that must occur even when rd==x0
            // (the loaded value is simply discarded), so never gate the whole
            // op on a non-x0 destination — use a throwaway vreg for rd==x0.
            let dst = self.def_x_reg(rd, ctx).unwrap_or_else(|| ctx.alloc_vreg());
            // Word LR/AMO results are sign-extended into rd (SC writes a 0/1
            // status, so it is excluded).
            let needs_sext = self.xlen == 64 && width == MemWidth::B4 && funct5 != 0b00011;
            let result = if needs_sext { ctx.alloc_vreg() } else { dst };
            let kind = match funct5 {
                0b00010 => {
                    // LR.W/D (Load Reserved)
                    OpKind::LoadExclusive {
                        dst: result,
                        addr: address,
                        width,
                    }
                }
                0b00011 => {
                    // SC.W/D (Store Conditional)
                    let status = dst; // SC writes status to rd
                    OpKind::StoreExclusive {
                        status,
                        src: rs2,
                        addr: address,
                        width,
                    }
                }
                0b00001 => OpKind::AtomicRmw {
                    // AMOSWAP
                    dst: result,
                    addr: address,
                    src: rs2,
                    op: AtomicOp::Swap,
                    width,
                    order,
                },
                0b00101 if self.extensions.zacas => OpKind::Cas {
                    // AMOCAS.W/D: compare memory with old rd, store rs2 on
                    // match, and always return the old memory value in rd.
                    dst: result,
                    success: ctx.alloc_vreg(),
                    addr: address,
                    expected: rd_old,
                    new_val: rs2,
                    width,
                    order,
                },
                0b00000 => OpKind::AtomicRmw {
                    // AMOADD
                    dst: result,
                    addr: address,
                    src: rs2,
                    op: AtomicOp::Add,
                    width,
                    order,
                },
                0b00100 => OpKind::AtomicRmw {
                    // AMOXOR
                    dst: result,
                    addr: address,
                    src: rs2,
                    op: AtomicOp::Xor,
                    width,
                    order,
                },
                0b01100 => OpKind::AtomicRmw {
                    // AMOAND
                    dst: result,
                    addr: address,
                    src: rs2,
                    op: AtomicOp::And,
                    width,
                    order,
                },
                0b01000 => OpKind::AtomicRmw {
                    // AMOOR
                    dst: result,
                    addr: address,
                    src: rs2,
                    op: AtomicOp::Or,
                    width,
                    order,
                },
                0b10000 => OpKind::AtomicRmw {
                    // AMOMIN
                    dst: result,
                    addr: address,
                    src: rs2,
                    op: AtomicOp::Min,
                    width,
                    order,
                },
                0b10100 => OpKind::AtomicRmw {
                    // AMOMAX
                    dst: result,
                    addr: address,
                    src: rs2,
                    op: AtomicOp::Max,
                    width,
                    order,
                },
                0b11000 => OpKind::AtomicRmw {
                    // AMOMINU
                    dst: result,
                    addr: address,
                    src: rs2,
                    op: AtomicOp::Umin,
                    width,
                    order,
                },
                0b11100 => OpKind::AtomicRmw {
                    // AMOMAXU
                    dst: result,
                    addr: address,
                    src: rs2,
                    op: AtomicOp::Umax,
                    width,
                    order,
                },
                _ => {
                    return Err(LiftError::InvalidEncoding {
                        addr,
                        bytes: insn.to_le_bytes().to_vec(),
                    });
                }
            };

            let exclusive = matches!(funct5, 0b00010 | 0b00011);
            if exclusive
                && matches!(
                    order,
                    MemoryOrder::Release | MemoryOrder::AcqRel | MemoryOrder::SeqCst
                )
            {
                ops.push(SmirOp::new(
                    ctx.next_op_id(),
                    addr,
                    OpKind::Fence {
                        kind: FenceKind::Full,
                    },
                ));
            }
            ops.push(SmirOp::new(ctx.next_op_id(), addr, kind));
            if exclusive
                && matches!(
                    order,
                    MemoryOrder::Acquire | MemoryOrder::AcqRel | MemoryOrder::SeqCst
                )
            {
                ops.push(SmirOp::new(
                    ctx.next_op_id(),
                    addr,
                    OpKind::Fence {
                        kind: FenceKind::Full,
                    },
                ));
            }
            if needs_sext {
                ops.push(SmirOp::new(
                    ctx.next_op_id(),
                    addr,
                    OpKind::SignExtend {
                        dst,
                        src: result,
                        from_width: OpWidth::W32,
                        to_width: OpWidth::W64,
                    },
                ));
            }
        }

        Ok((ops, ControlFlow::NextInsn))
    }
}
