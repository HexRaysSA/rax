//! Fail-closed admission for partially completing EVEX gather/scatter.

use std::collections::{HashMap, HashSet};

use crate::smir::ir::flags::FlagUpdate;
use crate::smir::ir::ops::{OpKind, SmirOp};
use crate::smir::ir::types::{
    Address, ArchReg, BlockId, GuestAddr, MemWidth, OpWidth, SignExtend, SrcOperand, VReg,
    VecElementType, VecWidth, X86Reg,
};
use crate::smir::ir::{SmirBlock, X86EvexVsibMemoryEncoding, X86InstructionBytes};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct X86JitEvexVsibMemorySequence {
    /// Number of operations after the separately admitted APX guard, if any.
    pub(crate) consumed: usize,
    pub(crate) encoding: X86EvexVsibMemoryEncoding,
}

/// A structural cursor, not an interpreter: every accepted operation is one
/// expected node of the VSIB graph. Fresh-role checks prevent a forged virtual
/// identity from aliasing a predicate, address, or preserved lane value.
struct Cursor<'a> {
    ops: &'a [SmirOp],
    offset: usize,
    pc: GuestAddr,
    virtuals: HashSet<VReg>,
}

impl<'a> Cursor<'a> {
    fn peek(&self) -> Option<&OpKind> {
        let op = self.ops.get(self.offset)?;
        (op.guest_pc == self.pc && op.x86_hint.is_none()).then_some(&op.kind)
    }

    fn take(&mut self) -> Option<OpKind> {
        let kind = self.peek()?.clone();
        self.offset += 1;
        Some(kind)
    }

    fn fresh(&mut self, register: VReg) -> Option<VReg> {
        (matches!(register, VReg::Virtual(_)) && self.virtuals.insert(register)).then_some(register)
    }

    fn zero(&mut self) -> Option<VReg> {
        match self.take()? {
            OpKind::Mov {
                dst,
                src: SrcOperand::Imm(0),
                width: OpWidth::W64,
            } => self.fresh(dst),
            _ => None,
        }
    }

    fn snapshot(&mut self, mask: VReg) -> Option<Option<VReg>> {
        if matches!(self.peek(), Some(OpKind::Mov {
            src: SrcOperand::Reg(source), width: OpWidth::W64, ..
        }) if *source == mask)
        {
            match self.take()? {
                OpKind::Mov { dst, .. } => Some(Some(self.fresh(dst)?)),
                _ => None,
            }
        } else {
            Some(None)
        }
    }

    fn condition(
        &mut self,
        snapshot: Option<VReg>,
        mask: VReg,
        lane: u8,
        before_first_mask_write: bool,
    ) -> Option<VReg> {
        let source_valid =
            |source| snapshot == Some(source) || (before_first_mask_write && source == mask);
        let first = self.take()?;
        let shifted = match first {
            OpKind::Shr {
                dst,
                src,
                amount: SrcOperand::Imm(amount),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            } if source_valid(src) && amount == i64::from(lane) => self.fresh(dst)?,
            // O2 removes SHR-by-zero and propagates its full-width copy.
            OpKind::And {
                dst,
                src1,
                src2: SrcOperand::Imm(1),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            } if lane == 0 && source_valid(src1) => return self.fresh(dst),
            _ => return None,
        };
        match self.take()? {
            OpKind::And {
                dst,
                src1,
                src2: SrcOperand::Imm(1),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            } if src1 == shifted => self.fresh(dst),
            _ => None,
        }
    }

    fn lane_extract(
        &mut self,
        vector: VReg,
        lane: u8,
        elem: VecElementType,
        sign: SignExtend,
    ) -> Option<VReg> {
        match self.take()? {
            OpKind::VExtractLane {
                dst,
                vec,
                lane: actual_lane,
                elem: actual_elem,
                sign: actual_sign,
            } if vec == vector
                && actual_lane == lane
                && actual_elem == elem
                && actual_sign == sign =>
            {
                self.fresh(dst)
            }
            _ => None,
        }
    }

    fn lane_insert(
        &mut self,
        destination: VReg,
        scalar: VReg,
        lane: u8,
        elem: VecElementType,
    ) -> Option<()> {
        matches!(
            self.take()?,
            OpKind::VInsertLane {
                dst, vec, scalar: actual_scalar, lane: actual_lane, elem: actual_elem,
            } if dst == destination && vec == destination && actual_scalar == scalar
                && actual_lane == lane && actual_elem == elem
        )
        .then_some(())
    }

    fn mask_clear(&mut self, mask: VReg, bits: i64) -> Option<()> {
        matches!(
            self.take()?,
            OpKind::And {
                dst, src1, src2: SrcOperand::Imm(actual_bits),
                width: OpWidth::W64, flags: FlagUpdate::None,
            } if dst == mask && src1 == mask && actual_bits == bits
        )
        .then_some(())
    }

    fn lane_address(
        &mut self,
        encoding: X86EvexVsibMemoryEncoding,
        index: VReg,
        lane: u8,
    ) -> Option<Address> {
        let width = if encoding.address_32 {
            OpWidth::W32
        } else {
            OpWidth::W64
        };
        let mut offset = self.lane_extract(index, lane, encoding.index_elem, SignExtend::Sign)?;
        if encoding.address_32 {
            offset = match self.take()? {
                OpKind::Mov {
                    dst,
                    src: SrcOperand::Reg(src),
                    width: OpWidth::W32,
                } if src == offset => self.fresh(dst)?,
                _ => return None,
            };
        }
        if encoding.scale != 1 {
            offset = match self.take()? {
                OpKind::Shl {
                    dst,
                    src,
                    amount: SrcOperand::Imm(amount),
                    width: actual_width,
                    flags: FlagUpdate::None,
                } if src == offset
                    && actual_width == width
                    && amount == i64::from(encoding.scale.trailing_zeros()) =>
                {
                    self.fresh(dst)?
                }
                _ => return None,
            };
        }
        if let Some(base) = encoding.base {
            let base = VReg::Arch(ArchReg::X86(X86Reg::gpr(base)));
            offset = match self.take()? {
                OpKind::Add {
                    dst,
                    src1,
                    src2: SrcOperand::Reg(src2),
                    width: actual_width,
                    flags: FlagUpdate::None,
                } if src1 == base && src2 == offset && actual_width == width => self.fresh(dst)?,
                _ => return None,
            };
        }
        if encoding.displacement != 0 {
            offset = match self.take()? {
                OpKind::Add {
                    dst,
                    src1,
                    src2: SrcOperand::Imm(displacement),
                    width: actual_width,
                    flags: FlagUpdate::None,
                } if src1 == offset
                    && displacement == encoding.displacement
                    && actual_width == width =>
                {
                    self.fresh(dst)?
                }
                _ => return None,
            };
        }
        Some(match encoding.segment {
            Some(segment) => Address::SegmentRel {
                segment: VReg::Arch(ArchReg::X86(segment)),
                base: Some(offset),
                index: None,
                scale: 1,
                disp: 0,
            },
            None => Address::Direct(offset),
        })
    }

    fn gather_normalization(
        &mut self,
        encoding: X86EvexVsibMemoryEncoding,
        destination: VReg,
        width: VecWidth,
    ) -> Option<()> {
        let snapshot = match self.take()? {
            OpKind::VMov {
                dst,
                src,
                width: actual_width,
            } if src == destination && actual_width == width => self.fresh(dst)?,
            _ => return None,
        };
        let zero = self.zero()?;
        let normalized = match self.take()? {
            OpKind::VBroadcast {
                dst,
                scalar,
                elem,
                lanes,
            } if scalar == zero && elem == encoding.data_elem && lanes == encoding.lanes => {
                self.fresh(dst)?
            }
            _ => return None,
        };
        for lane in 0..encoding.lanes {
            let value = self.lane_extract(snapshot, lane, encoding.data_elem, SignExtend::Zero)?;
            self.lane_insert(normalized, value, lane, encoding.data_elem)?;
        }
        matches!(
            self.take()?,
            OpKind::VMov { dst, src, width: actual_width }
                if dst == destination && src == normalized && actual_width == width
        )
        .then_some(())
    }

    /// Every internal virtual definition and use must belong to this exact
    /// instruction span. This also rejects live values escaping its frontier.
    fn closed_virtuals(
        &self,
        definitions: &HashMap<VReg, usize>,
        uses: &HashMap<VReg, usize>,
    ) -> bool {
        let mut local_definitions = HashMap::new();
        let mut local_uses = HashMap::new();
        for op in &self.ops[..self.offset] {
            for reg in op.kind.dests() {
                if matches!(reg, VReg::Virtual(_)) {
                    *local_definitions.entry(reg).or_insert(0usize) += 1;
                }
            }
            for reg in op.kind.source_vregs() {
                if matches!(reg, VReg::Virtual(_)) {
                    *local_uses.entry(reg).or_insert(0usize) += 1;
                }
            }
        }
        local_definitions.len() == self.virtuals.len()
            && local_uses.keys().all(|reg| self.virtuals.contains(reg))
            && self.virtuals.iter().all(|reg| {
                definitions.get(reg) == local_definitions.get(reg)
                    && uses.get(reg).copied().unwrap_or(0)
                        == local_uses.get(reg).copied().unwrap_or(0)
            })
    }
}

fn vector_view(register: u8, bytes: u32) -> Option<(VReg, VecWidth)> {
    let (reg, width) = match bytes {
        8 => (X86Reg::Xmm(register), VecWidth::V64),
        16 => (X86Reg::Xmm(register), VecWidth::V128),
        32 => (X86Reg::Ymm(register), VecWidth::V256),
        64 => (X86Reg::Zmm(register), VecWidth::V512),
        _ => return None,
    };
    Some((VReg::Arch(ArchReg::X86(reg)), width))
}

/// Bind raw bytes to the complete partially completing instruction graph.
/// The APX guard, when required, must immediately precede `index`; it is
/// admitted independently and is not included in `consumed`. No load/store,
/// vector insert, or opmask mutation from the interior is admitted alone.
///
/// Matching takes O(S) time and O(V) auxiliary space for S operations and V
/// virtual registers in the span (both O(KL), with KL <= 16). Caller-owned
/// definition/use maps are reused, without lifting or interpreting guest code.
pub(crate) fn x86_jit_evex_vsib_memory_sequence(
    block: &SmirBlock,
    index: usize,
    allow_mem: bool,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
    virtual_definitions: &HashMap<VReg, usize>,
    virtual_uses: &HashMap<VReg, usize>,
) -> Option<X86JitEvexVsibMemorySequence> {
    if !allow_mem {
        return None;
    }
    let pc = block.ops.get(index)?.guest_pc;
    let encoding = instruction_bytes
        .get(&(block.id, pc))?
        .evex_vsib_memory_encoding()?;
    let previous = index.checked_sub(1).and_then(|i| block.ops.get(i));
    let has_guard = previous.is_some_and(|op| {
        op.guest_pc == pc && op.x86_hint.is_none() && matches!(op.kind, OpKind::X86RequireApx)
    });
    if has_guard != encoding.requires_apx
        || (previous.is_some_and(|op| op.guest_pc == pc) && !has_guard)
        || (has_guard && index >= 2 && block.ops[index - 2].guest_pc == pc)
    {
        return None;
    }
    let mut cursor = Cursor {
        ops: &block.ops[index..],
        offset: 0,
        pc,
        virtuals: HashSet::new(),
    };
    let mask = VReg::Arch(ArchReg::X86(X86Reg::K(encoding.writemask)));
    let (data, data_width) = vector_view(
        encoding.data_register,
        u32::from(encoding.lanes) * encoding.data_elem.bytes(),
    )?;
    let (vector_index, _) = vector_view(
        encoding.index_register,
        u32::from(encoding.lanes) * encoding.index_elem.bytes(),
    )?;
    let memory_width = match encoding.data_elem {
        VecElementType::I32 => MemWidth::B4,
        VecElementType::I64 => MemWidth::B8,
        _ => return None,
    };

    // The unoptimized EVEX gather retains the VEX path's unused scalar zero.
    if !encoding.scatter
        && matches!(
            cursor.peek(),
            Some(OpKind::Mov {
                src: SrcOperand::Imm(0),
                width: OpWidth::W64,
                ..
            })
        )
    {
        cursor.zero()?;
    }
    let snapshot = cursor.snapshot(mask)?;
    // Gather captures every predicate before its first destination/mask write.
    // O1/O2 can therefore propagate the snapshot to the original K register.
    let mut conditions = [None; 16];
    if !encoding.scatter {
        for lane in 0..encoding.lanes {
            conditions[usize::from(lane)] = Some(cursor.condition(snapshot, mask, lane, true)?);
        }
    }
    for lane in 0..encoding.lanes {
        let condition = if encoding.scatter {
            cursor.condition(snapshot, mask, lane, lane == 0)?
        } else {
            conditions[usize::from(lane)]?
        };
        let value = cursor.lane_extract(data, lane, encoding.data_elem, SignExtend::Zero)?;
        let address = cursor.lane_address(encoding, vector_index, lane)?;
        if encoding.scatter {
            if !matches!(
                cursor.take()?,
                OpKind::PredStore {
                    src: SrcOperand::Reg(source), cond, addr, width,
                } if source == value && cond == condition && addr == address && width == memory_width
            ) {
                return None;
            }
        } else {
            if !matches!(
                cursor.take()?,
                OpKind::PredLoad { dst, cond, addr, width, signed: SignExtend::Zero }
                    if dst == value && cond == condition && addr == address && width == memory_width
            ) {
                return None;
            }
            cursor.lane_insert(data, value, lane, encoding.data_elem)?;
        }
        cursor.mask_clear(mask, !(1i64 << lane))?;
    }
    if !encoding.scatter {
        cursor.gather_normalization(encoding, data, data_width)?;
    }
    cursor.mask_clear(mask, ((1u64 << encoding.lanes) - 1) as i64)?;
    if cursor
        .ops
        .get(cursor.offset)
        .is_some_and(|op| op.guest_pc == pc)
        || !cursor.closed_virtuals(virtual_definitions, virtual_uses)
        || !super::evex_vsib_virtuals::x86_jit_vsib_non_op_virtuals_closed(block, &cursor.virtuals)
    {
        return None;
    }
    Some(X86JitEvexVsibMemorySequence {
        consumed: cursor.offset,
        encoding,
    })
}
