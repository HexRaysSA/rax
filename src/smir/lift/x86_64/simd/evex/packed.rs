//! packed.rs

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
    pub(crate) fn lift_evex_vpopcnt(
        &self,
        prefix: VecPrefix,
        opcode: u8,
        bytes: &[u8],
        pc: u64,
        ctx: &mut LiftContext,
    ) -> Result<LiftResult, LiftError> {
        if prefix.encoding != VecEncodingKind::Evex
            || prefix.pp != X86SsePrefix::OpSize
            || prefix.vvvv != 0
            || prefix.v_high
            || prefix.l_bits == 3
            || (prefix.zeroing && prefix.aaa == 0)
        {
            return Err(LiftError::InvalidEncoding {
                addr: pc,
                bytes: bytes.to_vec(),
            });
        }
        let elem = match (opcode, prefix.w) {
            (0x54, false) => VecElementType::I8,
            (0x54, true) => VecElementType::I16,
            (0x55, false) => VecElementType::I32,
            (0x55, true) => VecElementType::I64,
            _ => unreachable!(),
        };
        let cursor = prefix.bytes + 1;
        let modrm_prefix = X86Prefix {
            operand_size_override: true,
            ..prefix.modrm_prefix(cursor)
        };
        let modrm = decode_modrm(&bytes[cursor..], &modrm_prefix, pc)?;
        let broadcast_allowed = opcode == 0x55;
        if prefix.b && (!modrm.is_memory || !broadcast_allowed) {
            return Err(LiftError::InvalidEncoding {
                addr: pc,
                bytes: bytes.to_vec(),
            });
        }
        let next_pc = pc + cursor as u64 + modrm.bytes_consumed as u64;
        let broadcast = prefix.b;
        let mut ops = Vec::new();
        let mask = (prefix.aaa != 0).then_some(VReg::Arch(ArchReg::X86(X86Reg::K(prefix.aaa))));
        let src = if modrm.is_memory {
            let scale = if broadcast {
                elem.bytes()
            } else {
                prefix.width.bytes()
            };
            let (addr, pre_ops) = self.vec_disp8_addr_to_smir(
                prefix,
                modrm.addr.as_ref().unwrap(),
                next_pc,
                scale,
                ctx,
            );
            ops.extend(pre_ops);
            if let Some(mask) = mask {
                self.append_evex_masked_vector_source(
                    addr,
                    elem,
                    prefix.width,
                    broadcast,
                    mask,
                    pc,
                    ctx,
                    &mut ops,
                )
            } else if broadcast {
                self.append_broadcast_memory_source(addr, elem, prefix.width, pc, ctx, &mut ops)
            } else {
                let loaded = ctx.alloc_vreg();
                ops.push(SmirOp::new(
                    OpId(ops.len() as u16),
                    pc,
                    OpKind::VLoad {
                        dst: loaded,
                        addr,
                        width: prefix.width,
                    },
                ));
                loaded
            }
        } else {
            self.vec_reg(modrm.rm + if prefix.rm_high { 16 } else { 0 }, prefix.width)
        };
        let dst = self.vec_reg(
            modrm.reg + if prefix.reg_high { 16 } else { 0 },
            prefix.width,
        );
        ops.push(SmirOp::new(
            OpId(ops.len() as u16),
            pc,
            OpKind::VPopcnt {
                dst,
                src,
                mask,
                elem,
                width: prefix.width,
                zeroing: prefix.zeroing,
            },
        ));
        Ok(LiftResult::fallthrough(ops, cursor + modrm.bytes_consumed))
    }

    pub(crate) fn lift_evex_vplzcnt(
        &self,
        prefix: VecPrefix,
        bytes: &[u8],
        pc: u64,
        ctx: &mut LiftContext,
    ) -> Result<LiftResult, LiftError> {
        if prefix.encoding != VecEncodingKind::Evex
            || prefix.pp != X86SsePrefix::OpSize
            || prefix.vvvv != 0
            || prefix.v_high
            || prefix.l_bits == 3
            || (prefix.zeroing && prefix.aaa == 0)
        {
            return Err(LiftError::InvalidEncoding {
                addr: pc,
                bytes: bytes.to_vec(),
            });
        }
        let elem = if prefix.w {
            VecElementType::I64
        } else {
            VecElementType::I32
        };
        let cursor = prefix.bytes + 1;
        let modrm_prefix = X86Prefix {
            operand_size_override: true,
            ..prefix.modrm_prefix(cursor)
        };
        let modrm = decode_modrm(&bytes[cursor..], &modrm_prefix, pc)?;
        if prefix.b && !modrm.is_memory {
            return Err(LiftError::InvalidEncoding {
                addr: pc,
                bytes: bytes.to_vec(),
            });
        }
        let next_pc = pc + cursor as u64 + modrm.bytes_consumed as u64;
        let mut ops = Vec::new();
        let mask = (prefix.aaa != 0).then_some(VReg::Arch(ArchReg::X86(X86Reg::K(prefix.aaa))));
        let src = if modrm.is_memory {
            let scale = if prefix.b {
                elem.bytes()
            } else {
                prefix.width.bytes()
            };
            let (addr, pre_ops) = self.vec_disp8_addr_to_smir(
                prefix,
                modrm.addr.as_ref().unwrap(),
                next_pc,
                scale,
                ctx,
            );
            ops.extend(pre_ops);
            if let Some(mask) = mask {
                self.append_evex_masked_vector_source(
                    addr,
                    elem,
                    prefix.width,
                    prefix.b,
                    mask,
                    pc,
                    ctx,
                    &mut ops,
                )
            } else if prefix.b {
                self.append_broadcast_memory_source(addr, elem, prefix.width, pc, ctx, &mut ops)
            } else {
                let loaded = ctx.alloc_vreg();
                ops.push(SmirOp::new(
                    OpId(ops.len() as u16),
                    pc,
                    OpKind::VLoad {
                        dst: loaded,
                        addr,
                        width: prefix.width,
                    },
                ));
                loaded
            }
        } else {
            self.vec_reg(modrm.rm + if prefix.rm_high { 16 } else { 0 }, prefix.width)
        };
        let dst = self.vec_reg(
            modrm.reg + if prefix.reg_high { 16 } else { 0 },
            prefix.width,
        );
        ops.push(SmirOp::new(
            OpId(ops.len() as u16),
            pc,
            OpKind::VLeadingZeros {
                dst,
                src,
                mask,
                elem,
                width: prefix.width,
                zeroing: prefix.zeroing,
            },
        ));
        Ok(LiftResult::fallthrough(ops, cursor + modrm.bytes_consumed))
    }

    pub(crate) fn lift_evex_integer_narrow(
        &self,
        prefix: VecPrefix,
        opcode: u8,
        bytes: &[u8],
        pc: u64,
        ctx: &mut LiftContext,
    ) -> Result<LiftResult, LiftError> {
        let mode = match opcode >> 4 {
            1 => X86NarrowMode::UnsignedSaturate,
            2 => X86NarrowMode::SignedSaturate,
            3 => X86NarrowMode::Truncate,
            _ => unreachable!(),
        };
        let (src_elem, dst_elem) = match opcode & 0x0F {
            0 => (VecElementType::I16, VecElementType::I8),
            1 => (VecElementType::I32, VecElementType::I8),
            2 => (VecElementType::I64, VecElementType::I8),
            3 => (VecElementType::I32, VecElementType::I16),
            4 => (VecElementType::I64, VecElementType::I16),
            5 => (VecElementType::I64, VecElementType::I32),
            _ => unreachable!(),
        };
        if prefix.encoding != VecEncodingKind::Evex
            || prefix.pp != X86SsePrefix::Rep
            || prefix.w
            || prefix.l_bits == 3
            || prefix.b
            || prefix.vvvv != 0
            || prefix.v_high
            || (prefix.zeroing && prefix.aaa == 0)
        {
            return Err(LiftError::InvalidEncoding {
                addr: pc,
                bytes: bytes.to_vec(),
            });
        }
        let cursor = prefix.bytes + 1;
        let modrm_prefix = prefix.modrm_prefix(cursor);
        let modrm = decode_modrm(&bytes[cursor..], &modrm_prefix, pc)?;
        if modrm.is_memory && prefix.zeroing {
            return Err(LiftError::InvalidEncoding {
                addr: pc,
                bytes: bytes.to_vec(),
            });
        }
        let next_pc = pc + cursor as u64 + modrm.bytes_consumed as u64;
        let mask = (prefix.aaa != 0).then_some(VReg::Arch(ArchReg::X86(X86Reg::K(prefix.aaa))));
        let src = self.vec_reg(
            modrm.reg + if prefix.reg_high { 16 } else { 0 },
            prefix.width,
        );
        let lanes = prefix.width.lanes(src_elem) as u8;
        let output_bytes = u32::from(lanes) * dst_elem.bytes();
        let output_width = if output_bytes <= 16 {
            VecWidth::V128
        } else {
            VecWidth::V256
        };
        let mut ops = Vec::new();
        if modrm.is_memory {
            let (addr, pre_ops) = self.vec_disp8_addr_to_smir(
                prefix,
                modrm.addr.as_ref().unwrap(),
                next_pc,
                output_bytes,
                ctx,
            );
            ops.extend(pre_ops);
            let base = ctx.alloc_vreg();
            ops.push(SmirOp::new(
                OpId(ops.len() as u16),
                pc,
                OpKind::Lea { dst: base, addr },
            ));
            let dst_bits = dst_elem.bytes() * 8;
            let dst_mask = (1u64 << dst_bits) - 1;
            for lane in 0..lanes {
                let active = self.append_mask_bit_condition(mask, lane, pc, ctx, &mut ops);
                let raw = ctx.alloc_vreg();
                let narrowed = ctx.alloc_vreg();
                ops.push(SmirOp::new(
                    OpId(ops.len() as u16),
                    pc,
                    OpKind::VExtractLane {
                        dst: raw,
                        vec: src,
                        lane,
                        elem: src_elem,
                        sign: SignExtend::Sign,
                    },
                ));
                match mode {
                    X86NarrowMode::Truncate => ops.push(SmirOp::new(
                        OpId(ops.len() as u16),
                        pc,
                        OpKind::And {
                            dst: narrowed,
                            src1: raw,
                            src2: SrcOperand::Imm(dst_mask as i64),
                            width: OpWidth::W64,
                            flags: FlagUpdate::None,
                        },
                    )),
                    X86NarrowMode::SignedSaturate | X86NarrowMode::UnsignedSaturate => {
                        // Use a one-lane VNarrow operation so register and memory
                        // forms share exactly the same saturation semantics.
                        let wide =
                            self.append_zero_vector(VecWidth::V128, src_elem, pc, ctx, &mut ops);
                        let packed = ctx.alloc_vreg();
                        ops.push(SmirOp::new(
                            OpId(ops.len() as u16),
                            pc,
                            OpKind::VInsertLane {
                                dst: wide,
                                vec: wide,
                                scalar: raw,
                                lane: 0,
                                elem: src_elem,
                            },
                        ));
                        ops.push(SmirOp::new(
                            OpId(ops.len() as u16),
                            pc,
                            OpKind::X86NarrowInt {
                                dst: packed,
                                src: wide,
                                mask: None,
                                src_elem,
                                dst_elem,
                                width: match src_elem {
                                    VecElementType::I64 => VecWidth::V64,
                                    _ => VecWidth::V128,
                                },
                                mode,
                                zeroing: true,
                            },
                        ));
                        ops.push(SmirOp::new(
                            OpId(ops.len() as u16),
                            pc,
                            OpKind::VExtractLane {
                                dst: narrowed,
                                vec: packed,
                                lane: 0,
                                elem: dst_elem,
                                sign: SignExtend::Zero,
                            },
                        ));
                    }
                }
                ops.push(SmirOp::new(
                    OpId(ops.len() as u16),
                    pc,
                    OpKind::PredStore {
                        src: SrcOperand::Reg(narrowed),
                        cond: active,
                        addr: Address::base_off(
                            base,
                            i64::from(lane) * i64::from(dst_elem.bytes()),
                        ),
                        width: match dst_elem.bytes() {
                            1 => MemWidth::B1,
                            2 => MemWidth::B2,
                            4 => MemWidth::B4,
                            _ => unreachable!(),
                        },
                    },
                ));
            }
        } else {
            let dst = self.vec_reg(modrm.rm + if prefix.rm_high { 16 } else { 0 }, output_width);
            ops.push(SmirOp::new(
                OpId(0),
                pc,
                OpKind::X86NarrowInt {
                    dst,
                    src,
                    mask,
                    src_elem,
                    dst_elem,
                    width: prefix.width,
                    mode,
                    zeroing: prefix.zeroing,
                },
            ));
        }
        Ok(LiftResult::fallthrough(ops, cursor + modrm.bytes_consumed))
    }

    pub(crate) fn append_vsib_lane_address(
        &self,
        x86_addr: &X86Address,
        index: VReg,
        lane: u8,
        index_elem: VecElementType,
        pc: u64,
        ctx: &mut LiftContext,
        ops: &mut Vec<SmirOp>,
    ) -> Address {
        let width = x86_addr.address_width;
        let mut offset = ctx.alloc_vreg();
        ops.push(SmirOp::new(
            OpId(ops.len() as u16),
            pc,
            OpKind::VExtractLane {
                dst: offset,
                vec: index,
                lane,
                elem: index_elem,
                sign: SignExtend::Sign,
            },
        ));
        if width == OpWidth::W32 {
            // Even no-base/scale-one/disp-zero VSIB addresses truncate the
            // signed index modulo 2^32 before the segment base is added.
            let truncated = ctx.alloc_vreg();
            ops.push(SmirOp::new(
                OpId(ops.len() as u16),
                pc,
                OpKind::Mov {
                    dst: truncated,
                    src: SrcOperand::Reg(offset),
                    width,
                },
            ));
            offset = truncated;
        }
        if x86_addr.scale != 1 {
            let scaled = ctx.alloc_vreg();
            ops.push(SmirOp::new(
                OpId(ops.len() as u16),
                pc,
                OpKind::Shl {
                    dst: scaled,
                    src: offset,
                    amount: SrcOperand::Imm(i64::from(x86_addr.scale.trailing_zeros())),
                    width,
                    flags: FlagUpdate::None,
                },
            ));
            offset = scaled;
        }
        if let Some(base) = x86_addr.base {
            let sum = ctx.alloc_vreg();
            ops.push(SmirOp::new(
                OpId(ops.len() as u16),
                pc,
                OpKind::Add {
                    dst: sum,
                    src1: self.gpr(base),
                    src2: SrcOperand::Reg(offset),
                    width,
                    flags: FlagUpdate::None,
                },
            ));
            offset = sum;
        }
        if x86_addr.disp != 0 {
            let sum = ctx.alloc_vreg();
            ops.push(SmirOp::new(
                OpId(ops.len() as u16),
                pc,
                OpKind::Add {
                    dst: sum,
                    src1: offset,
                    src2: SrcOperand::Imm(x86_addr.disp),
                    width,
                    flags: FlagUpdate::None,
                },
            ));
            offset = sum;
        }
        match x86_addr.segment {
            Some(segment) => Address::SegmentRel {
                segment: VReg::Arch(ArchReg::X86(segment)),
                base: Some(offset),
                index: None,
                scale: 1,
                disp: 0,
            },
            None => Address::Direct(offset),
        }
    }

    pub(crate) fn append_vdbpsadbw(
        &self,
        src1: VReg,
        src2: VReg,
        width: VecWidth,
        imm: u8,
        pc: u64,
        ctx: &mut LiftContext,
        ops: &mut Vec<SmirOp>,
    ) -> VReg {
        // First apply the immediate-controlled dword shuffle to SRC2 within
        // each independent 128-bit lane.
        let dwords = width.lanes(VecElementType::I32) as u8;
        let mut shuffled = self.append_zero_vector(width, VecElementType::I32, pc, ctx, ops);
        for lane in 0..dwords {
            let block_base = lane & !3;
            let selector = (imm >> (2 * (lane & 3))) & 3;
            let scalar = ctx.alloc_vreg();
            ops.push(SmirOp::new(
                OpId(ops.len() as u16),
                pc,
                OpKind::VExtractLane {
                    dst: scalar,
                    vec: src2,
                    lane: block_base + selector,
                    elem: VecElementType::I32,
                    sign: SignExtend::Zero,
                },
            ));
            let inserted = ctx.alloc_vreg();
            ops.push(SmirOp::new(
                OpId(ops.len() as u16),
                pc,
                OpKind::VInsertLane {
                    dst: inserted,
                    vec: shuffled,
                    scalar,
                    lane,
                    elem: VecElementType::I32,
                },
            ));
            shuffled = inserted;
        }

        // VDBPSADBW's four result pairs are projections of four ordinary
        // MPSADBW computations over the shuffled SRC2 and stationary SRC1.
        // Repeating each imm3 in bits 5:3 applies the same selector to every
        // 128-bit block at all vector lengths.
        let mut partials = Vec::with_capacity(4);
        for selector in [0u8, 1, 6, 7] {
            let partial = ctx.alloc_vreg();
            ops.push(SmirOp::new(
                OpId(ops.len() as u16),
                pc,
                OpKind::VMpsadbw {
                    dst: partial,
                    src1: shuffled,
                    src2: src1,
                    mask: None,
                    width,
                    imm: selector | (selector << 3),
                    zeroing: false,
                },
            ));
            partials.push(partial);
        }

        let words = width.lanes(VecElementType::I16) as u8;
        let mut result = self.append_zero_vector(width, VecElementType::I16, pc, ctx, ops);
        for lane in 0..words {
            let scalar = ctx.alloc_vreg();
            ops.push(SmirOp::new(
                OpId(ops.len() as u16),
                pc,
                OpKind::VExtractLane {
                    dst: scalar,
                    vec: partials[usize::from((lane & 7) / 2)],
                    lane,
                    elem: VecElementType::I16,
                    sign: SignExtend::Zero,
                },
            ));
            let inserted = ctx.alloc_vreg();
            ops.push(SmirOp::new(
                OpId(ops.len() as u16),
                pc,
                OpKind::VInsertLane {
                    dst: inserted,
                    vec: result,
                    scalar,
                    lane,
                    elem: VecElementType::I16,
                },
            ));
            result = inserted;
        }
        result
    }

    pub(crate) fn lift_evex_packed_rotate_variable(
        &self,
        prefix: VecPrefix,
        opcode: u8,
        bytes: &[u8],
        pc: u64,
        ctx: &mut LiftContext,
    ) -> Result<LiftResult, LiftError> {
        if prefix.encoding != VecEncodingKind::Evex
            || prefix.map != X86VecMap::Map0F38
            || prefix.pp != X86SsePrefix::OpSize
            || prefix.l_bits == 3
            || (prefix.zeroing && prefix.aaa == 0)
            || !matches!(opcode, 0x14 | 0x15)
        {
            return Err(LiftError::InvalidEncoding {
                addr: pc,
                bytes: bytes.to_vec(),
            });
        }
        let elem = if prefix.w {
            VecElementType::I64
        } else {
            VecElementType::I32
        };
        let cursor = prefix.bytes + 1;
        let modrm_prefix = prefix.modrm_prefix(cursor);
        let modrm = decode_modrm(&bytes[cursor..], &modrm_prefix, pc)?;
        if prefix.b && !modrm.is_memory {
            return Err(LiftError::InvalidEncoding {
                addr: pc,
                bytes: bytes.to_vec(),
            });
        }
        let next_pc = pc + cursor as u64 + modrm.bytes_consumed as u64;
        let mut ops = Vec::new();
        let count = if modrm.is_memory {
            let broadcast = prefix.b;
            let tuple_bytes = if broadcast {
                elem.bytes()
            } else {
                prefix.width.bytes()
            };
            let (addr, pre_ops) = self.vec_disp8_addr_to_smir(
                prefix,
                modrm.addr.as_ref().unwrap(),
                next_pc,
                tuple_bytes,
                ctx,
            );
            ops.extend(pre_ops);
            if prefix.aaa != 0 && broadcast {
                self.append_masked_broadcast_memory_source(
                    addr,
                    elem,
                    prefix.width,
                    VReg::Arch(ArchReg::X86(X86Reg::K(prefix.aaa))),
                    pc,
                    ctx,
                    &mut ops,
                )
            } else if prefix.aaa != 0 {
                self.append_evex_masked_vector_source(
                    addr,
                    elem,
                    prefix.width,
                    broadcast,
                    VReg::Arch(ArchReg::X86(X86Reg::K(prefix.aaa))),
                    pc,
                    ctx,
                    &mut ops,
                )
            } else if broadcast {
                let scalar = ctx.alloc_vreg();
                let vector = ctx.alloc_vreg();
                ops.push(SmirOp::new(
                    OpId(ops.len() as u16),
                    pc,
                    OpKind::Load {
                        dst: scalar,
                        addr,
                        width: if elem == VecElementType::I32 {
                            MemWidth::B4
                        } else {
                            MemWidth::B8
                        },
                        sign: SignExtend::Zero,
                    },
                ));
                ops.push(SmirOp::new(
                    OpId(ops.len() as u16),
                    pc,
                    OpKind::VBroadcast {
                        dst: vector,
                        scalar,
                        elem,
                        lanes: prefix.width.lanes(elem) as u8,
                    },
                ));
                vector
            } else {
                let vector = ctx.alloc_vreg();
                ops.push(SmirOp::new(
                    OpId(ops.len() as u16),
                    pc,
                    OpKind::VLoad {
                        dst: vector,
                        addr,
                        width: prefix.width,
                    },
                ));
                vector
            }
        } else {
            self.vec_reg(modrm.rm + if prefix.rm_high { 16 } else { 0 }, prefix.width)
        };
        let src = self.vec_reg(
            prefix.vvvv + if prefix.v_high { 16 } else { 0 },
            prefix.width,
        );
        let dst = self.vec_reg(
            modrm.reg + if prefix.reg_high { 16 } else { 0 },
            prefix.width,
        );
        ops.push(SmirOp::new(
            OpId(ops.len() as u16),
            pc,
            OpKind::X86PackedRotate {
                dst,
                src,
                count: Some(count),
                mask: (prefix.aaa != 0).then_some(VReg::Arch(ArchReg::X86(X86Reg::K(prefix.aaa)))),
                amount: 0,
                width: prefix.width,
                elem,
                left: opcode == 0x15,
                zeroing: prefix.zeroing,
            },
        ));
        Ok(LiftResult::fallthrough(ops, cursor + modrm.bytes_consumed))
    }

    pub(crate) fn append_evex_whole_tuple_128(
        &self,
        addr: Address,
        mask: Option<VReg>,
        applicable_mask: i64,
        pc: u64,
        ctx: &mut LiftContext,
        ops: &mut Vec<SmirOp>,
    ) -> VReg {
        let Some(mask_reg) = mask else {
            let loaded = ctx.alloc_vreg();
            ops.push(SmirOp::new(
                OpId(ops.len() as u16),
                pc,
                OpKind::VLoad {
                    dst: loaded,
                    addr,
                    width: VecWidth::V128,
                },
            ));
            return loaded;
        };

        // Tuple1_4X is an all-or-none 16-byte access. PredVLoad consumes
        // condition bit zero, so map any applicable writemask bit to one
        // canonical Boolean without changing architectural flags.
        let applicable = ctx.alloc_vreg();
        ops.push(SmirOp::new(
            OpId(ops.len() as u16),
            pc,
            OpKind::And {
                dst: applicable,
                src1: mask_reg,
                src2: SrcOperand::Imm(applicable_mask),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        ));
        let negated = ctx.alloc_vreg();
        ops.push(SmirOp::new(
            OpId(ops.len() as u16),
            pc,
            OpKind::Neg {
                dst: negated,
                src: applicable,
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        ));
        let sign = ctx.alloc_vreg();
        ops.push(SmirOp::new(
            OpId(ops.len() as u16),
            pc,
            OpKind::Or {
                dst: sign,
                src1: applicable,
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
                src: sign,
                amount: SrcOperand::Imm(63),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        ));

        let loaded = self.append_zero_vector(VecWidth::V128, VecElementType::I32, pc, ctx, ops);
        ops.push(SmirOp::new(
            OpId(ops.len() as u16),
            pc,
            OpKind::PredVLoad {
                dst: loaded,
                cond: active,
                addr,
                width: VecWidth::V128,
            },
        ));
        loaded
    }

    pub(crate) fn lift_evex_pabs(
        &self,
        prefix: VecPrefix,
        opcode: u8,
        bytes: &[u8],
        pc: u64,
        ctx: &mut LiftContext,
    ) -> Result<LiftResult, LiftError> {
        let elem = match opcode {
            0x1C => VecElementType::I8,
            0x1D => VecElementType::I16,
            0x1E => VecElementType::I32,
            0x1F => VecElementType::I64,
            _ => unreachable!(),
        };
        if prefix.encoding != VecEncodingKind::Evex
            || prefix.pp != X86SsePrefix::OpSize
            || prefix.vvvv != 0
            || prefix.v_high
            || prefix.l_bits == 3
            || (prefix.zeroing && prefix.aaa == 0)
            || (matches!(opcode, 0x1C | 0x1D) && prefix.b)
            || (opcode == 0x1E && prefix.w)
            || (opcode == 0x1F && !prefix.w)
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
        if prefix.b && !modrm.is_memory {
            return Err(LiftError::InvalidEncoding {
                addr: pc,
                bytes: bytes.to_vec(),
            });
        }
        let next_pc = pc + cursor as u64 + modrm.bytes_consumed as u64;
        let lanes = prefix.width.lanes(elem) as u8;
        let mut ops = Vec::new();
        let src = if modrm.is_memory {
            let scale = if prefix.b {
                elem.bytes()
            } else {
                prefix.width.bytes()
            };
            let (addr, pre_ops) = self.vec_disp8_addr_to_smir(
                prefix,
                modrm.addr.as_ref().unwrap(),
                next_pc,
                scale,
                ctx,
            );
            ops.extend(pre_ops);
            let mem_width = match elem {
                VecElementType::I8 => MemWidth::B1,
                VecElementType::I16 => MemWidth::B2,
                VecElementType::I32 => MemWidth::B4,
                VecElementType::I64 => MemWidth::B8,
                _ => unreachable!(),
            };
            if prefix.b {
                let scalar = ctx.alloc_vreg();
                if prefix.aaa == 0 {
                    ops.push(SmirOp::new(
                        OpId(ops.len() as u16),
                        pc,
                        OpKind::Load {
                            dst: scalar,
                            addr,
                            width: mem_width,
                            sign: SignExtend::Zero,
                        },
                    ));
                } else {
                    let zero = ctx.alloc_vreg();
                    ops.push(SmirOp::new(
                        OpId(ops.len() as u16),
                        pc,
                        OpKind::Mov {
                            dst: zero,
                            src: SrcOperand::Imm(0),
                            width: OpWidth::W64,
                        },
                    ));
                    let mask = VReg::Arch(ArchReg::X86(X86Reg::K(prefix.aaa)));
                    let mut active = zero;
                    for lane in 0..lanes {
                        let shifted = ctx.alloc_vreg();
                        let bit = ctx.alloc_vreg();
                        let combined = ctx.alloc_vreg();
                        ops.push(SmirOp::new(
                            OpId(ops.len() as u16),
                            pc,
                            OpKind::Shr {
                                dst: shifted,
                                src: mask,
                                amount: SrcOperand::Imm(i64::from(lane)),
                                width: OpWidth::W64,
                                flags: FlagUpdate::None,
                            },
                        ));
                        ops.push(SmirOp::new(
                            OpId(ops.len() as u16),
                            pc,
                            OpKind::And {
                                dst: bit,
                                src1: shifted,
                                src2: SrcOperand::Imm(1),
                                width: OpWidth::W64,
                                flags: FlagUpdate::None,
                            },
                        ));
                        ops.push(SmirOp::new(
                            OpId(ops.len() as u16),
                            pc,
                            OpKind::Or {
                                dst: combined,
                                src1: active,
                                src2: SrcOperand::Reg(bit),
                                width: OpWidth::W64,
                                flags: FlagUpdate::None,
                            },
                        ));
                        active = combined;
                    }
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
                            width: mem_width,
                            signed: SignExtend::Zero,
                        },
                    ));
                }
                let loaded = ctx.alloc_vreg();
                ops.push(SmirOp::new(
                    OpId(ops.len() as u16),
                    pc,
                    OpKind::VBroadcast {
                        dst: loaded,
                        scalar,
                        elem,
                        lanes,
                    },
                ));
                loaded
            } else if prefix.aaa == 0 {
                let loaded = ctx.alloc_vreg();
                ops.push(SmirOp::new(
                    OpId(ops.len() as u16),
                    pc,
                    OpKind::VLoad {
                        dst: loaded,
                        addr,
                        width: prefix.width,
                    },
                ));
                loaded
            } else {
                let loaded = self.append_zero_vector(prefix.width, elem, pc, ctx, &mut ops);
                let base = ctx.alloc_vreg();
                ops.push(SmirOp::new(
                    OpId(ops.len() as u16),
                    pc,
                    OpKind::Lea { dst: base, addr },
                ));
                let mask = VReg::Arch(ArchReg::X86(X86Reg::K(prefix.aaa)));
                for lane in 0..lanes {
                    let shifted = ctx.alloc_vreg();
                    let active = ctx.alloc_vreg();
                    let scalar = ctx.alloc_vreg();
                    ops.push(SmirOp::new(
                        OpId(ops.len() as u16),
                        pc,
                        OpKind::Shr {
                            dst: shifted,
                            src: mask,
                            amount: SrcOperand::Imm(i64::from(lane)),
                            width: OpWidth::W64,
                            flags: FlagUpdate::None,
                        },
                    ));
                    ops.push(SmirOp::new(
                        OpId(ops.len() as u16),
                        pc,
                        OpKind::And {
                            dst: active,
                            src1: shifted,
                            src2: SrcOperand::Imm(1),
                            width: OpWidth::W64,
                            flags: FlagUpdate::None,
                        },
                    ));
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
                            addr: Address::base_off(
                                base,
                                i64::from(lane) * i64::from(elem.bytes()),
                            ),
                            width: mem_width,
                            signed: SignExtend::Zero,
                        },
                    ));
                    ops.push(SmirOp::new(
                        OpId(ops.len() as u16),
                        pc,
                        OpKind::VInsertLane {
                            dst: loaded,
                            vec: loaded,
                            scalar,
                            lane,
                            elem,
                        },
                    ));
                }
                loaded
            }
        } else {
            self.vec_reg(modrm.rm + if prefix.rm_high { 16 } else { 0 }, prefix.width)
        };
        let dst = self.vec_reg(
            modrm.reg + if prefix.reg_high { 16 } else { 0 },
            prefix.width,
        );
        let masked = prefix.aaa != 0;
        let raw = if masked { ctx.alloc_vreg() } else { dst };
        ops.push(SmirOp::with_hint(
            OpId(ops.len() as u16),
            pc,
            OpKind::VUnary {
                dst: raw,
                src,
                elem,
                lanes,
                op: VecUnaryOp::Abs,
            },
            self.vec_hint(prefix, opcode),
        ));
        if masked {
            self.append_evex_vector_mask_result(prefix, dst, raw, elem, pc, ctx, &mut ops);
        }
        Ok(LiftResult::fallthrough(ops, cursor + modrm.bytes_consumed))
    }

    pub(crate) fn lift_evex_integer_unpack(
        &self,
        prefix: VecPrefix,
        opcode: u8,
        bytes: &[u8],
        pc: u64,
        ctx: &mut LiftContext,
    ) -> Result<LiftResult, LiftError> {
        let elem = match opcode {
            0x60 | 0x68 => VecElementType::I8,
            0x61 | 0x69 => VecElementType::I16,
            0x62 | 0x6A => VecElementType::I32,
            0x6C | 0x6D => VecElementType::I64,
            _ => unreachable!(),
        };
        if prefix.encoding != VecEncodingKind::Evex
            || prefix.pp != X86SsePrefix::OpSize
            || prefix.l_bits == 3
            || (prefix.zeroing && prefix.aaa == 0)
            || matches!(elem, VecElementType::I32) && prefix.w
            || matches!(elem, VecElementType::I64) && !prefix.w
        {
            return Err(LiftError::InvalidEncoding {
                addr: pc,
                bytes: bytes.to_vec(),
            });
        }
        let high = matches!(opcode, 0x68 | 0x69 | 0x6A | 0x6D);
        let cursor = prefix.bytes + 1;
        let modrm_prefix = X86Prefix {
            operand_size_override: true,
            ..prefix.modrm_prefix(cursor)
        };
        let modrm = decode_modrm(&bytes[cursor..], &modrm_prefix, pc)?;
        let broadcast = prefix.b && modrm.is_memory;
        if prefix.b
            && (!modrm.is_memory || !matches!(elem, VecElementType::I32 | VecElementType::I64))
        {
            return Err(LiftError::InvalidEncoding {
                addr: pc,
                bytes: bytes.to_vec(),
            });
        }
        let next_pc = pc + cursor as u64 + modrm.bytes_consumed as u64;
        let mut ops = Vec::new();
        let mask = (prefix.aaa != 0).then_some(VReg::Arch(ArchReg::X86(X86Reg::K(prefix.aaa))));
        let src2 = if modrm.is_memory {
            let tuple_bytes = if broadcast {
                elem.bytes()
            } else {
                prefix.width.bytes()
            };
            let (addr, pre_ops) = self.vec_disp8_addr_to_smir(
                prefix,
                modrm.addr.as_ref().unwrap(),
                next_pc,
                tuple_bytes,
                ctx,
            );
            ops.extend(pre_ops);
            if broadcast {
                // VPUNPCK* uses exception class E4NF/E4NF.nb. Its opmask
                // controls only the destination update; it never suppresses
                // the scalar broadcast memory access.
                self.append_broadcast_memory_source(addr, elem, prefix.width, pc, ctx, &mut ops)
            } else {
                let loaded = ctx.alloc_vreg();
                ops.push(SmirOp::new(
                    OpId(ops.len() as u16),
                    pc,
                    OpKind::VLoad {
                        dst: loaded,
                        addr,
                        width: prefix.width,
                    },
                ));
                loaded
            }
        } else {
            self.vec_reg(modrm.rm + if prefix.rm_high { 16 } else { 0 }, prefix.width)
        };
        let dst = self.vec_reg(
            modrm.reg + if prefix.reg_high { 16 } else { 0 },
            prefix.width,
        );
        let raw = if prefix.aaa == 0 {
            dst
        } else {
            ctx.alloc_vreg()
        };
        self.append_vector_interleave(
            raw,
            self.vec_reg(
                prefix.vvvv + if prefix.v_high { 16 } else { 0 },
                prefix.width,
            ),
            src2,
            elem,
            prefix.width,
            high,
            self.vec_hint(prefix, opcode),
            pc,
            &mut ops,
        );
        if prefix.aaa != 0 {
            self.append_evex_vector_mask_result(prefix, dst, raw, elem, pc, ctx, &mut ops);
        }
        Ok(LiftResult::fallthrough(ops, cursor + modrm.bytes_consumed))
    }

    pub(crate) fn lift_evex_word_move(
        &self,
        prefix: VecPrefix,
        opcode: u8,
        bytes: &[u8],
        pc: u64,
        ctx: &mut LiftContext,
    ) -> Result<LiftResult, LiftError> {
        if prefix.encoding != VecEncodingKind::Evex
            || prefix.map != X86VecMap::Map5
            || prefix.pp != X86SsePrefix::OpSize
            || prefix.l_bits != 0
            || prefix.vvvv != 0
            || prefix.v_high
            || prefix.aaa != 0
            || prefix.zeroing
            || prefix.b
            || !matches!(opcode, 0x6E | 0x7E)
        {
            return Err(LiftError::InvalidEncoding {
                addr: pc,
                bytes: bytes.to_vec(),
            });
        }

        let cursor = prefix.bytes + 1;
        let modrm_prefix = prefix.modrm_prefix(cursor);
        let modrm = decode_modrm(&bytes[cursor..], &modrm_prefix, pc)?;
        if !modrm.is_memory && prefix.rm_high {
            return Err(LiftError::InvalidEncoding {
                addr: pc,
                bytes: bytes.to_vec(),
            });
        }

        let next_pc = pc + cursor as u64 + modrm.bytes_consumed as u64;
        let xmm = self.xmm(modrm.reg + if prefix.reg_high { 16 } else { 0 });
        let mut ops = Vec::new();
        if opcode == 0x6E {
            let scalar = if modrm.is_memory {
                let (addr, pre_ops) = self.vec_disp8_addr_to_smir(
                    prefix,
                    modrm.addr.as_ref().unwrap(),
                    next_pc,
                    MemWidth::B2.bytes(),
                    ctx,
                );
                ops.extend(pre_ops);
                let scalar = ctx.alloc_vreg();
                ops.push(SmirOp::new(
                    OpId(ops.len() as u16),
                    pc,
                    OpKind::Load {
                        dst: scalar,
                        addr,
                        width: MemWidth::B2,
                        sign: SignExtend::Zero,
                    },
                ));
                scalar
            } else {
                self.gpr(modrm.rm)
            };
            self.append_scalar_zeroed_xmm_result(
                xmm,
                scalar,
                VecElementType::I16,
                true,
                pc,
                ctx,
                &mut ops,
            );
        } else {
            let memory_address = if modrm.is_memory {
                let (addr, pre_ops) = self.vec_disp8_addr_to_smir(
                    prefix,
                    modrm.addr.as_ref().unwrap(),
                    next_pc,
                    MemWidth::B2.bytes(),
                    ctx,
                );
                ops.extend(pre_ops);
                Some(addr)
            } else {
                None
            };
            let scalar = ctx.alloc_vreg();
            ops.push(SmirOp::new(
                OpId(ops.len() as u16),
                pc,
                OpKind::VExtractLane {
                    dst: scalar,
                    vec: xmm,
                    lane: 0,
                    elem: VecElementType::I16,
                    sign: SignExtend::Zero,
                },
            ));
            if let Some(addr) = memory_address {
                ops.push(SmirOp::new(
                    OpId(ops.len() as u16),
                    pc,
                    OpKind::Store {
                        src: scalar,
                        addr,
                        width: MemWidth::B2,
                    },
                ));
            } else {
                ops.push(SmirOp::new(
                    OpId(ops.len() as u16),
                    pc,
                    OpKind::Mov {
                        dst: self.gpr(modrm.rm),
                        src: SrcOperand::Reg(scalar),
                        width: OpWidth::W32,
                    },
                ));
            }
        }

        Ok(LiftResult::fallthrough(ops, cursor + modrm.bytes_consumed))
    }
}
