//! mem.rs

use crate::smir::lift::x86_64::*;
use std::collections::{HashMap, HashSet};

use crate::smir::ir::flags::{FlagSet, FlagUpdate};
use crate::smir::ir::memory::MemoryError;
use crate::smir::ir::ops::{
    OpKind, SmirOp, X86AdxKind, X86AluEncoding, X86BlsKind, X86CacheControlKind, X86CountKind,
    X86OpHint, X86RepMode, X86SsePrefix, X86StringKind, X86ThreeDNowKind, X86VecAlign, X86VecMap,
    X86X87ArithmeticDestination, X86X87ArithmeticSource, X86X87CompareSource, X86X87Constant,
    X86X87ControlKind, X86X87DataKind, X86X87EnvWidth, X86X87FloatWidth, X86X87IntWidth,
    X86XSaveKind,
};
use crate::smir::ir::types::*;
use crate::smir::ir::{
    CallTarget, CallingConv, FunctionAttrs, SmirBlock, SmirFunction, Terminator, TrapKind,
    X86InstructionBytes,
};

impl X86_64Lifter {
    /// Normalize `mask & applicable_bits` to exactly 0/1 without changing
    /// architectural flags. PredLoad observes predicate bit 0 rather than
    /// generic integer nonzeroness.
    pub(crate) fn append_nonzero_mask_predicate(
        &self,
        mask: VReg,
        applicable_bits: u64,
        pc: u64,
        ctx: &mut LiftContext,
        ops: &mut Vec<SmirOp>,
    ) -> VReg {
        let active_mask = ctx.alloc_vreg();
        ops.push(SmirOp::new(
            OpId(ops.len() as u16),
            pc,
            OpKind::And {
                dst: active_mask,
                src1: mask,
                src2: SrcOperand::Imm(applicable_bits as i64),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        ));
        // For nonzero x, x | -x has bit 63 set.
        let negated = ctx.alloc_vreg();
        ops.push(SmirOp::new(
            OpId(ops.len() as u16),
            pc,
            OpKind::Neg {
                dst: negated,
                src: active_mask,
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        ));
        let combined = ctx.alloc_vreg();
        ops.push(SmirOp::new(
            OpId(ops.len() as u16),
            pc,
            OpKind::Or {
                dst: combined,
                src1: active_mask,
                src2: SrcOperand::Reg(negated),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        ));
        let active = ctx.alloc_vreg();
        ops.push(SmirOp::new(
            OpId(ops.len() as u16),
            pc,
            OpKind::Shr {
                dst: active,
                src: combined,
                amount: SrcOperand::Imm(63),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        ));
        active
    }

    pub(crate) fn append_broadcast_memory_source(
        &self,
        addr: Address,
        elem: VecElementType,
        width: VecWidth,
        pc: u64,
        ctx: &mut LiftContext,
        ops: &mut Vec<SmirOp>,
    ) -> VReg {
        let scalar = ctx.alloc_vreg();
        ops.push(SmirOp::new(
            OpId(ops.len() as u16),
            pc,
            OpKind::Load {
                dst: scalar,
                addr,
                width: match elem.bytes() {
                    1 => MemWidth::B1,
                    2 => MemWidth::B2,
                    4 => MemWidth::B4,
                    8 => MemWidth::B8,
                    _ => unreachable!(),
                },
                sign: SignExtend::Zero,
            },
        ));
        let vector = ctx.alloc_vreg();
        ops.push(SmirOp::new(
            OpId(ops.len() as u16),
            pc,
            OpKind::VBroadcast {
                dst: vector,
                scalar,
                elem,
                lanes: width.lanes(elem) as u8,
            },
        ));
        vector
    }

    /// Materialize an EVEX scalar broadcast whose memory access is suppressed
    /// when every applicable opmask bit is clear. The architectural memory
    /// operand is scalar, so aggregate the lane predicates and issue at most
    /// one read before broadcasting it to the active vector width.
    pub(crate) fn append_masked_broadcast_memory_source(
        &self,
        addr: Address,
        elem: VecElementType,
        width: VecWidth,
        mask: VReg,
        pc: u64,
        ctx: &mut LiftContext,
        ops: &mut Vec<SmirOp>,
    ) -> VReg {
        let lanes = width.lanes(elem) as u8;
        let lane_mask = if lanes == 64 {
            u64::MAX
        } else {
            (1u64 << lanes) - 1
        };
        let active = self.append_nonzero_mask_predicate(mask, lane_mask, pc, ctx, ops);
        let scalar = ctx.alloc_vreg();
        ops.push(SmirOp::new(
            OpId(ops.len() as u16),
            pc,
            OpKind::Mov {
                dst: scalar,
                src: SrcOperand::Imm(0),
                width: OpWidth::W64,
            },
        ));
        ops.push(SmirOp::new(
            OpId(ops.len() as u16),
            pc,
            OpKind::PredLoad {
                dst: scalar,
                cond: active,
                addr,
                width: match elem.bytes() {
                    1 => MemWidth::B1,
                    2 => MemWidth::B2,
                    4 => MemWidth::B4,
                    8 => MemWidth::B8,
                    _ => unreachable!(),
                },
                signed: SignExtend::Zero,
            },
        ));
        let vector = ctx.alloc_vreg();
        ops.push(SmirOp::new(
            OpId(ops.len() as u16),
            pc,
            OpKind::VBroadcast {
                dst: vector,
                scalar,
                elem,
                lanes,
            },
        ));
        vector
    }

    pub(crate) fn lift_vec_movnt(
        &self,
        prefix: VecPrefix,
        opcode: u8,
        bytes: &[u8],
        pc: u64,
        ctx: &mut LiftContext,
    ) -> Result<LiftResult, LiftError> {
        let valid_shape = match opcode {
            0x2B => matches!(prefix.pp, X86SsePrefix::None | X86SsePrefix::OpSize),
            0xE7 => prefix.pp == X86SsePrefix::OpSize,
            _ => false,
        };
        let wrong_evex_w = prefix.encoding == VecEncodingKind::Evex
            && match opcode {
                0x2B => prefix.w != (prefix.pp == X86SsePrefix::OpSize),
                0xE7 => prefix.w,
                _ => false,
            };
        if !valid_shape
            || prefix.l_bits == 3
            || prefix.vvvv != 0
            || prefix.v_high
            || prefix.aaa != 0
            || prefix.zeroing
            || prefix.b
            || wrong_evex_w
        {
            return Err(LiftError::InvalidEncoding {
                addr: pc,
                bytes: bytes.to_vec(),
            });
        }
        let cursor = prefix.bytes + 1;
        let modrm_prefix = X86Prefix {
            operand_size_override: prefix.pp == X86SsePrefix::OpSize,
            ..prefix.modrm_prefix(cursor)
        };
        let modrm = decode_modrm(&bytes[cursor..], &modrm_prefix, pc)?;
        if !modrm.is_memory {
            return Err(LiftError::InvalidEncoding {
                addr: pc,
                bytes: bytes.to_vec(),
            });
        }
        let next_pc = pc + cursor as u64 + modrm.bytes_consumed as u64;
        let (addr, mut ops) = if prefix.encoding == VecEncodingKind::Evex {
            self.vec_full_addr_to_smir(prefix, modrm.addr.as_ref().unwrap(), next_pc, ctx)
        } else {
            self.x86_addr_to_smir(modrm.addr.as_ref().unwrap(), next_pc, ctx)
        };
        ops.push(SmirOp::new(
            OpId(ops.len() as u16),
            pc,
            OpKind::X86CheckAlignment {
                addr: addr.clone(),
                alignment: prefix.width.bytes() as u8,
            },
        ));
        ops.push(SmirOp::with_hint(
            OpId(ops.len() as u16),
            pc,
            OpKind::VStore {
                src: self.vec_reg(
                    modrm.reg
                        + if prefix.encoding == VecEncodingKind::Evex && prefix.reg_high {
                            16
                        } else {
                            0
                        },
                    prefix.width,
                ),
                addr,
                width: prefix.width,
            },
            X86OpHint::VecAlign(X86VecAlign::Aligned),
        ));
        Ok(LiftResult::fallthrough(ops, cursor + modrm.bytes_consumed))
    }

    pub(crate) fn lift_vec_gather(
        &self,
        prefix: VecPrefix,
        opcode: u8,
        bytes: &[u8],
        pc: u64,
        ctx: &mut LiftContext,
    ) -> Result<LiftResult, LiftError> {
        if prefix.map != X86VecMap::Map0F38
            || prefix.pp != X86SsePrefix::OpSize
            || prefix.b
            || prefix.zeroing
            || prefix.l_bits == 3
        {
            return Err(LiftError::InvalidEncoding {
                addr: pc,
                bytes: bytes.to_vec(),
            });
        }
        if prefix.encoding == VecEncodingKind::Evex && (prefix.aaa == 0 || prefix.vvvv != 0) {
            return Err(LiftError::InvalidEncoding {
                addr: pc,
                bytes: bytes.to_vec(),
            });
        }

        let cursor = prefix.bytes + 1;
        let modrm_prefix = prefix.modrm_prefix(cursor);
        let modrm = decode_modrm(&bytes[cursor..], &modrm_prefix, pc)?;
        if !modrm.is_memory || modrm.byte & 7 != 4 || bytes.len() <= cursor + 1 {
            return Err(LiftError::InvalidEncoding {
                addr: pc,
                bytes: bytes.to_vec(),
            });
        }

        let sib = bytes[cursor + 1];
        let index_number = ((sib >> 3) & 7)
            | modrm_prefix.rex_x()
            | if prefix.encoding == VecEncodingKind::Evex && prefix.v_high {
                16
            } else {
                0
            };
        let dst_number = modrm.reg
            + if prefix.encoding == VecEncodingKind::Evex && prefix.reg_high {
                16
            } else {
                0
            };
        if dst_number == index_number
            || (prefix.encoding == VecEncodingKind::Vex
                && (prefix.vvvv == dst_number || prefix.vvvv == index_number))
        {
            return Err(LiftError::InvalidEncoding {
                addr: pc,
                bytes: bytes.to_vec(),
            });
        }

        let data_elem = if prefix.w {
            VecElementType::I64
        } else {
            VecElementType::I32
        };
        let index_elem = if opcode & 1 == 0 {
            VecElementType::I32
        } else {
            VecElementType::I64
        };
        let lanes = prefix
            .width
            .lanes(data_elem)
            .min(prefix.width.lanes(index_elem)) as u8;
        let result_bits = usize::from(lanes) * data_elem.bytes() as usize * 8;
        let result_width = match result_bits {
            64 => VecWidth::V64,
            128 => VecWidth::V128,
            256 => VecWidth::V256,
            512 => VecWidth::V512,
            _ => unreachable!("invalid gather result width"),
        };
        let index_bits = usize::from(lanes) * index_elem.bytes() as usize * 8;
        let index_width = match index_bits {
            64 => VecWidth::V64,
            128 => VecWidth::V128,
            256 => VecWidth::V256,
            512 => VecWidth::V512,
            _ => unreachable!("invalid gather index width"),
        };
        let dst = self.vec_reg(dst_number, result_width);
        let index = self.vec_reg(index_number, index_width);
        let mut ops = Vec::new();
        if prefix.encoding == VecEncodingKind::Vex {
            self.append_gather_destination_normalization(
                dst,
                result_width,
                data_elem,
                lanes,
                pc,
                ctx,
                &mut ops,
            );
        }

        let scalar_zero = ctx.alloc_vreg();
        ops.push(SmirOp::new(
            OpId(ops.len() as u16),
            pc,
            OpKind::Mov {
                dst: scalar_zero,
                src: SrcOperand::Imm(0),
                width: OpWidth::W64,
            },
        ));
        let mut conditions = Vec::with_capacity(lanes as usize);
        let vector_mask = if prefix.encoding == VecEncodingKind::Vex {
            let mask = self.vec_reg(prefix.vvvv, result_width);
            let old_mask = ctx.alloc_vreg();
            ops.push(SmirOp::new(
                OpId(ops.len() as u16),
                pc,
                OpKind::VMov {
                    dst: old_mask,
                    src: mask,
                    width: result_width,
                },
            ));
            let normalized = self.append_zero_vector(result_width, data_elem, pc, ctx, &mut ops);
            for lane in 0..lanes {
                let raw = ctx.alloc_vreg();
                let cond = ctx.alloc_vreg();
                let sign_mask = ctx.alloc_vreg();
                ops.push(SmirOp::new(
                    OpId(ops.len() as u16),
                    pc,
                    OpKind::VExtractLane {
                        dst: raw,
                        vec: old_mask,
                        lane,
                        elem: data_elem,
                        sign: SignExtend::Zero,
                    },
                ));
                ops.push(SmirOp::new(
                    OpId(ops.len() as u16),
                    pc,
                    OpKind::Shr {
                        dst: cond,
                        src: raw,
                        amount: SrcOperand::Imm(i64::from(data_elem.bytes() * 8 - 1)),
                        width: if data_elem == VecElementType::I32 {
                            OpWidth::W32
                        } else {
                            OpWidth::W64
                        },
                        flags: FlagUpdate::None,
                    },
                ));
                ops.push(SmirOp::new(
                    OpId(ops.len() as u16),
                    pc,
                    OpKind::Sub {
                        dst: sign_mask,
                        src1: scalar_zero,
                        src2: SrcOperand::Reg(cond),
                        width: if data_elem == VecElementType::I32 {
                            OpWidth::W32
                        } else {
                            OpWidth::W64
                        },
                        flags: FlagUpdate::None,
                    },
                ));
                ops.push(SmirOp::new(
                    OpId(ops.len() as u16),
                    pc,
                    OpKind::VInsertLane {
                        dst: normalized,
                        vec: normalized,
                        scalar: sign_mask,
                        lane,
                        elem: data_elem,
                    },
                ));
                conditions.push(cond);
            }
            ops.push(SmirOp::new(
                OpId(ops.len() as u16),
                pc,
                OpKind::VMov {
                    dst: mask,
                    src: normalized,
                    width: result_width,
                },
            ));
            Some(mask)
        } else {
            let mask = VReg::Arch(ArchReg::X86(X86Reg::K(prefix.aaa)));
            let snapshot = ctx.alloc_vreg();
            ops.push(SmirOp::new(
                OpId(ops.len() as u16),
                pc,
                OpKind::Mov {
                    dst: snapshot,
                    src: SrcOperand::Reg(mask),
                    width: OpWidth::W64,
                },
            ));
            for lane in 0..lanes {
                let shifted = ctx.alloc_vreg();
                let cond = ctx.alloc_vreg();
                ops.push(SmirOp::new(
                    OpId(ops.len() as u16),
                    pc,
                    OpKind::Shr {
                        dst: shifted,
                        src: snapshot,
                        amount: SrcOperand::Imm(i64::from(lane)),
                        width: OpWidth::W64,
                        flags: FlagUpdate::None,
                    },
                ));
                ops.push(SmirOp::new(
                    OpId(ops.len() as u16),
                    pc,
                    OpKind::And {
                        dst: cond,
                        src1: shifted,
                        src2: SrcOperand::Imm(1),
                        width: OpWidth::W64,
                        flags: FlagUpdate::None,
                    },
                ));
                conditions.push(cond);
            }
            None
        };

        let mut x86_addr = modrm.addr.unwrap();
        x86_addr.index = None;
        if prefix.encoding == VecEncodingKind::Evex && x86_addr.disp_size == DispSize::Disp8 {
            x86_addr.disp *= i64::from(data_elem.bytes());
        }
        let mem_width = if data_elem == VecElementType::I32 {
            MemWidth::B4
        } else {
            MemWidth::B8
        };
        for (lane, cond) in conditions.into_iter().enumerate() {
            let lane = lane as u8;
            let value = ctx.alloc_vreg();
            ops.push(SmirOp::new(
                OpId(ops.len() as u16),
                pc,
                OpKind::VExtractLane {
                    dst: value,
                    vec: dst,
                    lane,
                    elem: data_elem,
                    sign: SignExtend::Zero,
                },
            ));
            let addr = self
                .append_vsib_lane_address(&x86_addr, index, lane, index_elem, pc, ctx, &mut ops);
            ops.push(SmirOp::new(
                OpId(ops.len() as u16),
                pc,
                OpKind::PredLoad {
                    dst: value,
                    cond,
                    addr,
                    width: mem_width,
                    signed: SignExtend::Zero,
                },
            ));
            ops.push(SmirOp::new(
                OpId(ops.len() as u16),
                pc,
                OpKind::VInsertLane {
                    dst,
                    vec: dst,
                    scalar: value,
                    lane,
                    elem: data_elem,
                },
            ));
            if let Some(mask) = vector_mask {
                ops.push(SmirOp::new(
                    OpId(ops.len() as u16),
                    pc,
                    OpKind::VInsertLane {
                        dst: mask,
                        vec: mask,
                        scalar: scalar_zero,
                        lane,
                        elem: data_elem,
                    },
                ));
            } else {
                let mask = VReg::Arch(ArchReg::X86(X86Reg::K(prefix.aaa)));
                ops.push(SmirOp::new(
                    OpId(ops.len() as u16),
                    pc,
                    OpKind::And {
                        dst: mask,
                        src1: mask,
                        src2: SrcOperand::Imm(!(1i64 << lane)),
                        width: OpWidth::W64,
                        flags: FlagUpdate::None,
                    },
                ));
            }
        }

        if prefix.encoding == VecEncodingKind::Evex {
            // Intel SDM 086, VGATHER/VPGATHER Operation: unused destination
            // and opmask bits are cleared after ENDFOR. Defer both until all
            // accesses succeed, including mixed widths where early clearing
            // of unused destination elements is also permitted. Each earlier
            // completed lane and its cleared mask bit remain visible on fault.
            self.append_gather_destination_normalization(
                dst,
                result_width,
                data_elem,
                lanes,
                pc,
                ctx,
                &mut ops,
            );
            let mask = VReg::Arch(ArchReg::X86(X86Reg::K(prefix.aaa)));
            ops.push(SmirOp::new(
                OpId(ops.len() as u16),
                pc,
                OpKind::And {
                    dst: mask,
                    src1: mask,
                    src2: SrcOperand::Imm(((1u64 << lanes) - 1) as i64),
                    width: OpWidth::W64,
                    flags: FlagUpdate::None,
                },
            ));
        }

        Ok(LiftResult::fallthrough(ops, cursor + modrm.bytes_consumed))
    }

    fn append_gather_destination_normalization(
        &self,
        dst: VReg,
        width: VecWidth,
        elem: VecElementType,
        lanes: u8,
        pc: u64,
        ctx: &mut LiftContext,
        ops: &mut Vec<SmirOp>,
    ) {
        let old_dst = ctx.alloc_vreg();
        ops.push(SmirOp::new(
            OpId(ops.len() as u16),
            pc,
            OpKind::VMov {
                dst: old_dst,
                src: dst,
                width,
            },
        ));
        let normalized = self.append_zero_vector(width, elem, pc, ctx, ops);
        for lane in 0..lanes {
            let old = ctx.alloc_vreg();
            ops.push(SmirOp::new(
                OpId(ops.len() as u16),
                pc,
                OpKind::VExtractLane {
                    dst: old,
                    vec: old_dst,
                    lane,
                    elem,
                    sign: SignExtend::Zero,
                },
            ));
            ops.push(SmirOp::new(
                OpId(ops.len() as u16),
                pc,
                OpKind::VInsertLane {
                    dst: normalized,
                    vec: normalized,
                    scalar: old,
                    lane,
                    elem,
                },
            ));
        }
        ops.push(SmirOp::new(
            OpId(ops.len() as u16),
            pc,
            OpKind::VMov {
                dst,
                src: normalized,
                width,
            },
        ));
    }

    pub(crate) fn lift_vec_movntdqa(
        &self,
        prefix: VecPrefix,
        bytes: &[u8],
        pc: u64,
        ctx: &mut LiftContext,
    ) -> Result<LiftResult, LiftError> {
        if prefix.pp != X86SsePrefix::OpSize
            || prefix.vvvv != 0
            || prefix.l_bits == 3
            || prefix.b
            || prefix.aaa != 0
            || prefix.zeroing
            || (prefix.encoding == VecEncodingKind::Evex && (prefix.w || prefix.v_high))
        {
            return Err(LiftError::InvalidEncoding {
                addr: pc,
                bytes: bytes.to_vec(),
            });
        }
        let cursor = prefix.bytes + 1;
        let modrm_prefix = X86Prefix {
            operand_size_override: true,
            ..prefix.modrm_prefix(cursor)
        };
        let modrm = decode_modrm(&bytes[cursor..], &modrm_prefix, pc)?;
        if !modrm.is_memory {
            return Err(LiftError::InvalidEncoding {
                addr: pc,
                bytes: bytes.to_vec(),
            });
        }
        let next_pc = pc + cursor as u64 + modrm.bytes_consumed as u64;
        let (addr, mut ops) = if prefix.encoding == VecEncodingKind::Evex {
            self.vec_full_addr_to_smir(prefix, modrm.addr.as_ref().unwrap(), next_pc, ctx)
        } else {
            self.x86_addr_to_smir(modrm.addr.as_ref().unwrap(), next_pc, ctx)
        };
        ops.push(SmirOp::new(
            OpId(ops.len() as u16),
            pc,
            OpKind::X86CheckAlignment {
                addr: addr.clone(),
                alignment: prefix.width.bytes() as u8,
            },
        ));
        let loaded = ctx.alloc_vreg();
        ops.push(SmirOp::with_hint(
            OpId(ops.len() as u16),
            pc,
            OpKind::VLoad {
                dst: loaded,
                addr,
                width: prefix.width,
            },
            X86OpHint::VecAlign(X86VecAlign::Aligned),
        ));
        let dst = self.vec_reg(
            modrm.reg
                + if prefix.encoding == VecEncodingKind::Evex && prefix.reg_high {
                    16
                } else {
                    0
                },
            prefix.width,
        );
        ops.push(SmirOp::new(
            OpId(ops.len() as u16),
            pc,
            OpKind::VMov {
                dst,
                src: loaded,
                width: prefix.width,
            },
        ));
        Ok(LiftResult::fallthrough(ops, cursor + modrm.bytes_consumed))
    }

    /// Lift VEX/EVEX load-and-broadcast instructions from vector, memory, or
    /// (for EVEX opcodes 7A..7C) GPR sources.  Tuple memory forms use one
    /// predicate shared by every tuple-element load: Type E6 suppresses the
    /// complete source access only when every architecturally relevant mask
    /// bit is zero.
    pub(crate) fn lift_vec_load_broadcast(
        &self,
        prefix: VecPrefix,
        opcode: u8,
        bytes: &[u8],
        pc: u64,
        ctx: &mut LiftContext,
    ) -> Result<LiftResult, LiftError> {
        if prefix.map != X86VecMap::Map0F38
            || prefix.pp != X86SsePrefix::OpSize
            || prefix.vvvv != 0
            || prefix.v_high
            || prefix.l_bits == 3
            || prefix.b
            || (prefix.zeroing && prefix.aaa == 0)
        {
            return Err(LiftError::InvalidEncoding {
                addr: pc,
                bytes: bytes.to_vec(),
            });
        }

        let (elem, source_lanes, memory_only, gpr_source, valid_width) =
            match (prefix.encoding, opcode, prefix.w) {
                (VecEncodingKind::Vex, 0x18, false) => (
                    VecElementType::F32,
                    1,
                    false,
                    false,
                    matches!(prefix.width, VecWidth::V128 | VecWidth::V256),
                ),
                (VecEncodingKind::Vex, 0x19, false) => (
                    VecElementType::F64,
                    1,
                    false,
                    false,
                    prefix.width == VecWidth::V256,
                ),
                (VecEncodingKind::Vex, 0x1A, false) => (
                    VecElementType::F32,
                    4,
                    true,
                    false,
                    prefix.width == VecWidth::V256,
                ),
                (VecEncodingKind::Vex, 0x58, false) => (
                    VecElementType::I32,
                    1,
                    false,
                    false,
                    matches!(prefix.width, VecWidth::V128 | VecWidth::V256),
                ),
                (VecEncodingKind::Vex, 0x59, false) => (
                    VecElementType::I64,
                    1,
                    false,
                    false,
                    matches!(prefix.width, VecWidth::V128 | VecWidth::V256),
                ),
                (VecEncodingKind::Vex, 0x5A, false) => (
                    VecElementType::I32,
                    4,
                    true,
                    false,
                    prefix.width == VecWidth::V256,
                ),
                (VecEncodingKind::Vex, 0x78, false) => (
                    VecElementType::I8,
                    1,
                    false,
                    false,
                    matches!(prefix.width, VecWidth::V128 | VecWidth::V256),
                ),
                (VecEncodingKind::Vex, 0x79, false) => (
                    VecElementType::I16,
                    1,
                    false,
                    false,
                    matches!(prefix.width, VecWidth::V128 | VecWidth::V256),
                ),

                (VecEncodingKind::Evex, 0x18, false) => {
                    (VecElementType::F32, 1, false, false, true)
                }
                (VecEncodingKind::Evex, 0x19, false) => (
                    VecElementType::F32,
                    2,
                    false,
                    false,
                    matches!(prefix.width, VecWidth::V256 | VecWidth::V512),
                ),
                (VecEncodingKind::Evex, 0x19, true) => (
                    VecElementType::F64,
                    1,
                    false,
                    false,
                    matches!(prefix.width, VecWidth::V256 | VecWidth::V512),
                ),
                (VecEncodingKind::Evex, 0x1A, false) => (
                    VecElementType::F32,
                    4,
                    true,
                    false,
                    matches!(prefix.width, VecWidth::V256 | VecWidth::V512),
                ),
                (VecEncodingKind::Evex, 0x1A, true) => (
                    VecElementType::F64,
                    2,
                    true,
                    false,
                    matches!(prefix.width, VecWidth::V256 | VecWidth::V512),
                ),
                (VecEncodingKind::Evex, 0x1B, false) => (
                    VecElementType::F32,
                    8,
                    true,
                    false,
                    prefix.width == VecWidth::V512,
                ),
                (VecEncodingKind::Evex, 0x1B, true) => (
                    VecElementType::F64,
                    4,
                    true,
                    false,
                    prefix.width == VecWidth::V512,
                ),
                (VecEncodingKind::Evex, 0x58, false) => {
                    (VecElementType::I32, 1, false, false, true)
                }
                (VecEncodingKind::Evex, 0x59, false) => {
                    (VecElementType::I32, 2, false, false, true)
                }
                (VecEncodingKind::Evex, 0x59, true) => (VecElementType::I64, 1, false, false, true),
                (VecEncodingKind::Evex, 0x5A, false) => (
                    VecElementType::I32,
                    4,
                    true,
                    false,
                    matches!(prefix.width, VecWidth::V256 | VecWidth::V512),
                ),
                (VecEncodingKind::Evex, 0x5A, true) => (
                    VecElementType::I64,
                    2,
                    true,
                    false,
                    matches!(prefix.width, VecWidth::V256 | VecWidth::V512),
                ),
                (VecEncodingKind::Evex, 0x5B, false) => (
                    VecElementType::I32,
                    8,
                    true,
                    false,
                    prefix.width == VecWidth::V512,
                ),
                (VecEncodingKind::Evex, 0x5B, true) => (
                    VecElementType::I64,
                    4,
                    true,
                    false,
                    prefix.width == VecWidth::V512,
                ),
                (VecEncodingKind::Evex, 0x78, false) => (VecElementType::I8, 1, false, false, true),
                (VecEncodingKind::Evex, 0x79, false) => {
                    (VecElementType::I16, 1, false, false, true)
                }
                (VecEncodingKind::Evex, 0x7A, false) => (VecElementType::I8, 1, false, true, true),
                (VecEncodingKind::Evex, 0x7B, false) => (VecElementType::I16, 1, false, true, true),
                (VecEncodingKind::Evex, 0x7C, false) => (VecElementType::I32, 1, false, true, true),
                (VecEncodingKind::Evex, 0x7C, true) => (VecElementType::I64, 1, false, true, true),
                _ => {
                    return Err(LiftError::InvalidEncoding {
                        addr: pc,
                        bytes: bytes.to_vec(),
                    });
                }
            };
        if !valid_width {
            return Err(LiftError::InvalidEncoding {
                addr: pc,
                bytes: bytes.to_vec(),
            });
        }

        let cursor = prefix.bytes + 1;
        let modrm_prefix = X86Prefix {
            operand_size_override: true,
            ..prefix.modrm_prefix(cursor)
        };
        let modrm = decode_modrm(&bytes[cursor..], &modrm_prefix, pc)?;
        // Intel SDM Table 2-41 defines EVEX.X as ignored when ModR/M.r/m is a
        // GPR. `decode_modrm` uses EVEX.B for GPR bit 3; do not treat X as a
        // nonexistent bit-4 GPR extension for the GPR-source broadcast forms.
        if (memory_only && !modrm.is_memory) || (gpr_source && modrm.is_memory) {
            return Err(LiftError::InvalidEncoding {
                addr: pc,
                bytes: bytes.to_vec(),
            });
        }
        let next_pc = pc + cursor as u64 + modrm.bytes_consumed as u64;
        let destination_lanes = prefix.width.lanes(elem) as u8;
        let mut ops = Vec::new();

        let memory_condition =
            if prefix.encoding == VecEncodingKind::Evex && prefix.aaa != 0 && modrm.is_memory {
                let lane_mask = if destination_lanes == 64 {
                    u64::MAX
                } else {
                    (1u64 << destination_lanes) - 1
                };
                Some(self.append_nonzero_mask_predicate(
                    VReg::Arch(ArchReg::X86(X86Reg::K(prefix.aaa))),
                    lane_mask,
                    pc,
                    ctx,
                    &mut ops,
                ))
            } else {
                None
            };

        let source = if gpr_source {
            self.gpr(modrm.rm)
        } else if modrm.is_memory {
            let tuple_bytes = u32::from(source_lanes) * elem.bytes();
            let (addr, pre_ops) = self.vec_disp8_addr_to_smir(
                prefix,
                modrm.addr.as_ref().unwrap(),
                next_pc,
                tuple_bytes,
                ctx,
            );
            ops.extend(pre_ops);
            let base = ctx.alloc_vreg();
            ops.push(SmirOp::new(
                OpId(ops.len() as u16),
                pc,
                OpKind::Lea { dst: base, addr },
            ));
            let vector = self.append_zero_vector(prefix.width, elem, pc, ctx, &mut ops);
            let mem_width = match elem.bytes() {
                1 => MemWidth::B1,
                2 => MemWidth::B2,
                4 => MemWidth::B4,
                8 => MemWidth::B8,
                _ => unreachable!(),
            };
            for lane in 0..source_lanes {
                let scalar = ctx.alloc_vreg();
                ops.push(SmirOp::new(
                    OpId(ops.len() as u16),
                    pc,
                    OpKind::Mov {
                        dst: scalar,
                        src: SrcOperand::Imm(0),
                        width: OpWidth::W64,
                    },
                ));
                let lane_addr = Address::base_off(base, i64::from(lane) * i64::from(elem.bytes()));
                if let Some(cond) = memory_condition {
                    ops.push(SmirOp::new(
                        OpId(ops.len() as u16),
                        pc,
                        OpKind::PredLoad {
                            dst: scalar,
                            cond,
                            addr: lane_addr,
                            width: mem_width,
                            signed: SignExtend::Zero,
                        },
                    ));
                } else {
                    ops.push(SmirOp::new(
                        OpId(ops.len() as u16),
                        pc,
                        OpKind::Load {
                            dst: scalar,
                            addr: lane_addr,
                            width: mem_width,
                            sign: SignExtend::Zero,
                        },
                    ));
                }
                ops.push(SmirOp::new(
                    OpId(ops.len() as u16),
                    pc,
                    OpKind::VInsertLane {
                        dst: vector,
                        vec: vector,
                        scalar,
                        lane,
                        elem,
                    },
                ));
            }
            vector
        } else {
            self.xmm(
                modrm.rm
                    + if prefix.encoding == VecEncodingKind::Evex && prefix.rm_high {
                        16
                    } else {
                        0
                    },
            )
        };

        let raw = ctx.alloc_vreg();
        if source_lanes == 1 {
            let scalar = if gpr_source {
                source
            } else {
                let scalar = ctx.alloc_vreg();
                ops.push(SmirOp::new(
                    OpId(ops.len() as u16),
                    pc,
                    OpKind::VExtractLane {
                        dst: scalar,
                        vec: source,
                        lane: 0,
                        elem,
                        sign: SignExtend::Zero,
                    },
                ));
                scalar
            };
            ops.push(SmirOp::new(
                OpId(ops.len() as u16),
                pc,
                OpKind::VBroadcast {
                    dst: raw,
                    scalar,
                    elem,
                    lanes: destination_lanes,
                },
            ));
        } else {
            let zeroed = self.append_zero_vector(prefix.width, elem, pc, ctx, &mut ops);
            for lane in 0..destination_lanes {
                let scalar = ctx.alloc_vreg();
                ops.push(SmirOp::new(
                    OpId(ops.len() as u16),
                    pc,
                    OpKind::VExtractLane {
                        dst: scalar,
                        vec: source,
                        lane: lane % source_lanes,
                        elem,
                        sign: SignExtend::Zero,
                    },
                ));
                ops.push(SmirOp::new(
                    OpId(ops.len() as u16),
                    pc,
                    OpKind::VInsertLane {
                        dst: raw,
                        vec: if lane == 0 { zeroed } else { raw },
                        scalar,
                        lane,
                        elem,
                    },
                ));
            }
        }

        let dst = self.vec_reg(
            modrm.reg
                + if prefix.encoding == VecEncodingKind::Evex && prefix.reg_high {
                    16
                } else {
                    0
                },
            prefix.width,
        );
        if prefix.encoding == VecEncodingKind::Evex {
            self.append_evex_vector_mask_result(prefix, dst, raw, elem, pc, ctx, &mut ops);
        } else {
            ops.push(SmirOp::new(
                OpId(ops.len() as u16),
                pc,
                OpKind::VMov {
                    dst,
                    src: raw,
                    width: prefix.width,
                },
            ));
        }

        Ok(LiftResult::fallthrough(ops, cursor + modrm.bytes_consumed))
    }

    pub(crate) fn lift_vec_packed_f32_to_f16_store(
        &self,
        prefix: VecPrefix,
        bytes: &[u8],
        pc: u64,
        ctx: &mut LiftContext,
    ) -> Result<LiftResult, LiftError> {
        if prefix.map != X86VecMap::Map0F3A
            || prefix.pp != X86SsePrefix::OpSize
            || prefix.w
            || prefix.vvvv != 0
            || (prefix.encoding == VecEncodingKind::Evex
                && (prefix.v_high || (prefix.zeroing && prefix.aaa == 0)))
        {
            return Err(LiftError::InvalidEncoding {
                addr: pc,
                bytes: bytes.to_vec(),
            });
        }

        let opcode = bytes[prefix.bytes];
        let cursor = prefix.bytes + 1;
        let modrm_prefix = X86Prefix {
            operand_size_override: true,
            ..prefix.modrm_prefix(cursor)
        };
        let modrm = decode_modrm(&bytes[cursor..], &modrm_prefix, pc)?;
        let register_sae = prefix.encoding == VecEncodingKind::Evex && prefix.b && !modrm.is_memory;
        if (prefix.encoding == VecEncodingKind::Evex
            && ((prefix.b && modrm.is_memory) || (prefix.zeroing && modrm.is_memory)))
            || (!register_sae && prefix.l_bits == 3)
        {
            return Err(LiftError::InvalidEncoding {
                addr: pc,
                bytes: bytes.to_vec(),
            });
        }

        let imm_offset = cursor + modrm.bytes_consumed;
        let imm = *bytes.get(imm_offset).ok_or(LiftError::Incomplete {
            addr: pc,
            have: bytes.len(),
            need: imm_offset + 1,
        })?;
        let instruction_width = if register_sae {
            VecWidth::V512
        } else {
            prefix.width
        };
        let lanes = instruction_width.lanes(VecElementType::F32) as u8;
        let dst_width = match lanes {
            4 => VecWidth::V64,
            8 => VecWidth::V128,
            16 => VecWidth::V256,
            _ => unreachable!(),
        };
        let round = if imm & 4 != 0 {
            FpRoundMode::Dynamic
        } else {
            match imm & 3 {
                0 => FpRoundMode::RoundNearest,
                1 => FpRoundMode::RoundDown,
                2 => FpRoundMode::RoundUp,
                _ => FpRoundMode::RoundTowardZero,
            }
        };
        let mask = (prefix.encoding == VecEncodingKind::Evex && prefix.aaa != 0)
            .then_some(VReg::Arch(ArchReg::X86(X86Reg::K(prefix.aaa))));
        let src = self.vec_reg(
            modrm.reg
                + if prefix.encoding == VecEncodingKind::Evex && prefix.reg_high {
                    16
                } else {
                    0
                },
            instruction_width,
        );
        let next_pc = pc + imm_offset as u64 + 1;
        let hint = if register_sae {
            X86OpHint::EvexOp {
                map: prefix.map,
                pp: prefix.pp,
                opcode,
                width: instruction_width,
                w: false,
            }
        } else {
            self.vec_hint(prefix, opcode)
        };
        let mut ops = Vec::new();
        if modrm.is_memory {
            let (addr, pre_ops) = self.vec_disp8_addr_to_smir(
                prefix,
                modrm.addr.as_ref().unwrap(),
                next_pc,
                u32::from(lanes) * 2,
                ctx,
            );
            ops.extend(pre_ops);
            ops.push(SmirOp::with_hint(
                OpId(ops.len() as u16),
                pc,
                OpKind::X86PackedFpConvertStore {
                    addr,
                    src,
                    mask,
                    lanes,
                    round,
                },
                hint,
            ));
        } else {
            let dst = self.vec_reg(
                modrm.rm
                    + if prefix.encoding == VecEncodingKind::Evex && prefix.rm_high {
                        16
                    } else {
                        0
                    },
                dst_width,
            );
            ops.push(SmirOp::with_hint(
                OpId(ops.len() as u16),
                pc,
                OpKind::X86PackedFpConvert {
                    dst,
                    src,
                    mask,
                    from: VecElementType::F32,
                    to: VecElementType::F16,
                    lanes,
                    dst_width,
                    mask_zeroing: prefix.zeroing,
                    zero_upper: true,
                    round,
                    suppress_exceptions: register_sae,
                    report_fp16_denormal: false,
                },
                hint,
            ));
        }
        Ok(LiftResult::fallthrough(ops, imm_offset + 1))
    }
}
