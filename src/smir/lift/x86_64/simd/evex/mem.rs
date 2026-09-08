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
    /// Store active EVEX destination elements in architectural lane order.
    /// Inactive lanes perform no memory access; a fault after earlier active
    /// lanes have committed preserves those earlier stores.
    pub(crate) fn append_evex_masked_vector_store(
        &self,
        addr: Address,
        src: VReg,
        elem: VecElementType,
        width: VecWidth,
        mask: VReg,
        pc: u64,
        ctx: &mut LiftContext,
        ops: &mut Vec<SmirOp>,
    ) {
        let base = ctx.alloc_vreg();
        ops.push(SmirOp::new(
            OpId(ops.len() as u16),
            pc,
            OpKind::Lea { dst: base, addr },
        ));
        let mem_width = match elem {
            VecElementType::I8 => MemWidth::B1,
            VecElementType::I16 | VecElementType::F16 => MemWidth::B2,
            VecElementType::I32 | VecElementType::F32 => MemWidth::B4,
            VecElementType::I64 | VecElementType::F64 => MemWidth::B8,
            _ => unreachable!(),
        };
        for lane in 0..width.lanes(elem) as u8 {
            let active = self.append_mask_bit_condition(Some(mask), lane, pc, ctx, ops);
            let scalar = ctx.alloc_vreg();
            ops.push(SmirOp::new(
                OpId(ops.len() as u16),
                pc,
                OpKind::VExtractLane {
                    dst: scalar,
                    vec: src,
                    lane,
                    elem,
                    sign: SignExtend::Zero,
                },
            ));
            ops.push(SmirOp::new(
                OpId(ops.len() as u16),
                pc,
                OpKind::PredStore {
                    src: SrcOperand::Reg(scalar),
                    cond: active,
                    addr: Address::base_off(base, i64::from(lane) * i64::from(elem.bytes())),
                    width: mem_width,
                },
            ));
        }
    }

    /// Expand MASKMOVQ/MASKMOVDQU/VMASKMOVDQU into independently predicated
    /// byte stores. The predicate for byte `n` is bit 7 of mask byte `n`.
    /// A false predicate performs no memory access, matching the instruction's
    /// byte-selective store semantics and its permitted all-zero-mask behavior.
    pub(crate) fn append_maskmov(
        &self,
        data: VReg,
        mask: VReg,
        lanes: u8,
        address_size_override: bool,
        segment_override: Option<u8>,
        pc: u64,
        ctx: &mut LiftContext,
        ops: &mut Vec<SmirOp>,
    ) {
        let base = if address_size_override {
            let truncated = ctx.alloc_vreg();
            ops.push(SmirOp::new(
                OpId(ops.len() as u16),
                pc,
                OpKind::And {
                    dst: truncated,
                    src1: self.gpr(7),
                    src2: SrcOperand::Imm(0xFFFF_FFFF),
                    width: OpWidth::W64,
                    flags: FlagUpdate::None,
                },
            ));
            truncated
        } else {
            self.gpr(7)
        };

        for lane in 0..lanes {
            let (lane_base, disp) = if address_size_override && lane != 0 {
                let wrapped = ctx.alloc_vreg();
                ops.push(SmirOp::new(
                    OpId(ops.len() as u16),
                    pc,
                    OpKind::Add {
                        dst: wrapped,
                        src1: base,
                        src2: SrcOperand::Imm(i64::from(lane)),
                        width: OpWidth::W32,
                        flags: FlagUpdate::None,
                    },
                ));
                (wrapped, 0)
            } else {
                (
                    base,
                    if address_size_override {
                        0
                    } else {
                        i64::from(lane)
                    },
                )
            };
            let mask_byte = ctx.alloc_vreg();
            let active = ctx.alloc_vreg();
            let data_byte = ctx.alloc_vreg();
            ops.push(SmirOp::new(
                OpId(ops.len() as u16),
                pc,
                OpKind::VExtractLane {
                    dst: mask_byte,
                    vec: mask,
                    lane,
                    elem: VecElementType::I8,
                    sign: SignExtend::Zero,
                },
            ));
            ops.push(SmirOp::new(
                OpId(ops.len() as u16),
                pc,
                OpKind::Shr {
                    dst: active,
                    src: mask_byte,
                    amount: SrcOperand::Imm(7),
                    width: OpWidth::W64,
                    flags: FlagUpdate::None,
                },
            ));
            ops.push(SmirOp::new(
                OpId(ops.len() as u16),
                pc,
                OpKind::VExtractLane {
                    dst: data_byte,
                    vec: data,
                    lane,
                    elem: VecElementType::I8,
                    sign: SignExtend::Zero,
                },
            ));
            let addr = match segment_override {
                Some(0x64) => Address::SegmentRel {
                    segment: VReg::Arch(ArchReg::X86(X86Reg::FsBase)),
                    base: Some(lane_base),
                    index: None,
                    scale: 1,
                    disp,
                },
                Some(0x65) => Address::SegmentRel {
                    segment: VReg::Arch(ArchReg::X86(X86Reg::GsBase)),
                    base: Some(lane_base),
                    index: None,
                    scale: 1,
                    disp,
                },
                _ => Address::base_off(lane_base, disp),
            };
            ops.push(SmirOp::new(
                OpId(ops.len() as u16),
                pc,
                OpKind::PredStore {
                    src: SrcOperand::Reg(data_byte),
                    cond: active,
                    addr,
                    width: MemWidth::B1,
                },
            ));
        }
    }

    pub(crate) fn lift_evex_scatter(
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
            || prefix.b
            || prefix.zeroing
            || prefix.l_bits == 3
            || prefix.aaa == 0
            || prefix.vvvv != 0
            || !matches!(opcode, 0xA0..=0xA3)
        {
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
        let index_number =
            ((sib >> 3) & 7) | modrm_prefix.rex_x() | if prefix.v_high { 16 } else { 0 };
        let source_number = modrm.reg + if prefix.reg_high { 16 } else { 0 };

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
        let width_for = |bits: usize| match bits {
            64 => VecWidth::V64,
            128 => VecWidth::V128,
            256 => VecWidth::V256,
            512 => VecWidth::V512,
            _ => unreachable!("invalid scatter vector width"),
        };
        let source_width = width_for(usize::from(lanes) * data_elem.bytes() as usize * 8);
        let index_width = width_for(usize::from(lanes) * index_elem.bytes() as usize * 8);
        let source = self.vec_reg(source_number, source_width);
        let index = self.vec_reg(index_number, index_width);
        let mask = VReg::Arch(ArchReg::X86(X86Reg::K(prefix.aaa)));
        let snapshot = ctx.alloc_vreg();
        let valid_mask = (1u64 << lanes) - 1;
        let mut ops = vec![SmirOp::new(
            OpId(0),
            pc,
            OpKind::Mov {
                dst: snapshot,
                src: SrcOperand::Reg(mask),
                width: OpWidth::W64,
            },
        )];
        let mut x86_addr = modrm.addr.unwrap();
        x86_addr.index = None;
        if x86_addr.disp_size == DispSize::Disp8 {
            x86_addr.disp *= i64::from(data_elem.bytes());
        }
        let mem_width = if data_elem == VecElementType::I32 {
            MemWidth::B4
        } else {
            MemWidth::B8
        };
        for lane in 0..lanes {
            let shifted = ctx.alloc_vreg();
            let cond = ctx.alloc_vreg();
            let value = ctx.alloc_vreg();
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
            ops.push(SmirOp::new(
                OpId(ops.len() as u16),
                pc,
                OpKind::VExtractLane {
                    dst: value,
                    vec: source,
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
                OpKind::PredStore {
                    src: SrcOperand::Reg(value),
                    cond,
                    addr,
                    width: mem_width,
                },
            ));
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
        // The SDM clears k[MAX_KL-1:KL] after ENDFOR. A fault leaves high
        // mask bits unchanged and retains every preceding lane's mask clear.
        ops.push(SmirOp::new(
            OpId(ops.len() as u16),
            pc,
            OpKind::And {
                dst: mask,
                src1: mask,
                src2: SrcOperand::Imm(valid_mask as i64),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        ));
        Ok(LiftResult::fallthrough(ops, cursor + modrm.bytes_consumed))
    }

    pub(crate) fn lift_evex_mask_broadcast(
        &self,
        prefix: VecPrefix,
        opcode: u8,
        bytes: &[u8],
        pc: u64,
        ctx: &mut LiftContext,
    ) -> Result<LiftResult, LiftError> {
        if prefix.encoding != VecEncodingKind::Evex
            || prefix.map != X86VecMap::Map0F38
            || prefix.pp != X86SsePrefix::Rep
            || prefix.vvvv != 0
            || prefix.v_high
            || prefix.aaa != 0
            || prefix.zeroing
            || prefix.b
            || prefix.l_bits == 3
            || !matches!((opcode, prefix.w), (0x2A, true) | (0x3A, false))
        {
            return Err(LiftError::InvalidEncoding {
                addr: pc,
                bytes: bytes.to_vec(),
            });
        }
        let cursor = prefix.bytes + 1;
        let modrm_prefix = X86Prefix {
            rep_prefix: Some(0xF3),
            ..prefix.modrm_prefix(cursor)
        };
        let modrm = decode_modrm(&bytes[cursor..], &modrm_prefix, pc)?;
        // Intel SDM Table 2-41 defines EVEX.X/B as ignored when ModR/M.r/m
        // selects an opmask register. Only the low three r/m bits select K0-K7.
        if modrm.is_memory {
            return Err(LiftError::InvalidEncoding {
                addr: pc,
                bytes: bytes.to_vec(),
            });
        }
        let (elem, source_mask) = if opcode == 0x2A {
            (VecElementType::I64, 0xFF)
        } else {
            (VecElementType::I32, 0xFFFF)
        };
        let mut ops = Vec::new();
        let scalar = ctx.alloc_vreg();
        ops.push(SmirOp::new(
            OpId(0),
            pc,
            OpKind::And {
                dst: scalar,
                src1: VReg::Arch(ArchReg::X86(X86Reg::K(modrm.rm & 7))),
                src2: SrcOperand::Imm(source_mask),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        ));
        ops.push(SmirOp::new(
            OpId(1),
            pc,
            OpKind::VBroadcast {
                dst: self.vec_reg(
                    modrm.reg + if prefix.reg_high { 16 } else { 0 },
                    prefix.width,
                ),
                scalar,
                elem,
                lanes: prefix.width.lanes(elem) as u8,
            },
        ));
        Ok(LiftResult::fallthrough(ops, cursor + modrm.bytes_consumed))
    }
}
