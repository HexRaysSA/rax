//! Native admission shape for LOCK-prefixed x86 memory read-modify-write.
//!
//! A locked ALU instruction lifts to
//! `[Mov v_src, imm] ; AtomicRmw v_old, [mem], v_src ; <alu> v_flags, v_old, v_src(All)`.
//! The trailing operation exists only to publish the architectural flags and is
//! deleted by optimization when they are dead.
//!
//! Both the direct x86 interpreter and the SMIR interpreter realize a locked
//! ALU as an ordinary read-modify-write through the vCPU MMU — the emulator
//! provides no stronger indivisibility guarantee — so the fused native form
//! (helper load, native compute, helper store, optional flag replay) matches
//! interpretation exactly, including MMIO ordering and fault precision.

use crate::smir::ir::SmirBlock;
use crate::smir::ir::types::{Address, AtomicOp, MemWidth, MemoryOrder, OpWidth, VReg};

/// One validated LOCK-prefixed memory read-modify-write.
pub(crate) struct X86JitAtomicRmw<'a> {
    /// Total operations consumed by the fused form.
    pub(crate) consumed: usize,
    pub(crate) guest_pc: u64,
    pub(crate) addr: &'a Address,
    pub(crate) mem_width: MemWidth,
    pub(crate) width: OpWidth,
    /// Group-1 opcode base (`ADD` = 00h) and `/digit` for the immediate form.
    pub(crate) opcode: u8,
    pub(crate) digit: u8,
    /// `None` for the immediate form, otherwise the architectural source GPR.
    pub(crate) source_reg: Option<VReg>,
    pub(crate) source_imm: i64,
    /// `XCHG` replaces the element outright and publishes no flags.
    pub(crate) swap: bool,
    /// Whether the architectural flags are still published.
    pub(crate) replay: bool,
    /// `INC`/`DEC` publish a different flag set than the equivalent Group-1
    /// `ADD`/`SUB` (they leave CF unchanged), so the lifter replays the unary
    /// operation instead. 1 selects `INC`, 2 selects `DEC`.
    pub(crate) replay_unary: Option<u8>,
    /// `XADD` writes the pre-operation memory value back to an architectural
    /// GPR after the memory update retires.
    pub(crate) writeback: Option<VReg>,
}

fn atomic_group(op: AtomicOp) -> Option<(u8, u8, u8)> {
    // (Group-1 opcode base, /digit, x86_binary_alu_shape tag). `Swap` has no
    // arithmetic at all: the element is replaced by the source, and the encoding
    // fields are never consulted.
    match op {
        AtomicOp::Add => Some((0x00, 0, 0)),
        AtomicOp::Or => Some((0x08, 1, 1)),
        AtomicOp::And => Some((0x20, 4, 4)),
        AtomicOp::Sub => Some((0x28, 5, 5)),
        AtomicOp::Xor => Some((0x30, 6, 6)),
        AtomicOp::Swap => Some((0x00, 0, u8::MAX)),
        _ => None,
    }
}

/// Recognize the fused LOCK read-modify-write starting at `index`.
pub(crate) fn x86_jit_mem_atomic_rmw_sequence<'a>(
    block: &'a SmirBlock,
    index: usize,
    allow_mem: bool,
    virtual_definitions: &std::collections::HashMap<VReg, usize>,
    virtual_uses: &std::collections::HashMap<VReg, usize>,
) -> Option<X86JitAtomicRmw<'a>> {
    use crate::smir::ir::ops::OpKind;
    use crate::smir::ir::types::SrcOperand;

    if !allow_mem {
        return None;
    }

    // An immediate source is materialized into a single-use virtual first.
    let mut cursor = index;
    let mut source_imm = 0i64;
    let mut immediate_source: Option<VReg> = None;
    let mut immediate_width = None;
    if let Some(OpKind::Mov {
        dst: dst @ VReg::Virtual(_),
        src: SrcOperand::Imm(value) | SrcOperand::Imm64(value),
        width,
    }) = block.ops.get(index).map(|op| &op.kind)
    {
        source_imm = *value;
        immediate_source = Some(*dst);
        immediate_width = Some(*width);
        if block.ops.get(index)?.x86_hint.is_some() || virtual_definitions.get(dst) != Some(&1) {
            return None;
        }
        cursor += 1;
    }

    let atomic = block.ops.get(cursor)?;
    let OpKind::AtomicRmw {
        dst: old @ VReg::Virtual(_),
        addr,
        src,
        op,
        width: mem_width,
        order: MemoryOrder::SeqCst,
    } = &atomic.kind
    else {
        return None;
    };
    if block.ops.get(index)?.guest_pc != atomic.guest_pc {
        return None;
    }
    let (opcode, digit, tag) = atomic_group(*op)?;
    let width = mem_width.to_op_width()?;
    if !matches!(
        width,
        OpWidth::W8 | OpWidth::W16 | OpWidth::W32 | OpWidth::W64
    ) || !super::x86_jit_mem_address_shape_valid(addr)
    {
        return None;
    }
    if virtual_definitions.get(old) != Some(&1) {
        return None;
    }

    // The source is either the materialized immediate or an architectural GPR
    // whose live value the fused form stages before the helper calls.
    let source_reg = match (immediate_source, src) {
        (Some(materialized), src) if materialized == *src => None,
        (None, VReg::Arch(crate::smir::ir::types::ArchReg::X86(reg)))
            if reg.gpr_index().is_some() =>
        {
            Some(*src)
        }
        _ => return None,
    };
    if immediate_width.is_some_and(|materialized_width| materialized_width != width) {
        return None;
    }

    let source_operand = match source_reg {
        Some(reg) => SrcOperand::Reg(reg),
        None => SrcOperand::Imm(source_imm),
    };
    let expected_source = match immediate_source {
        Some(materialized) => SrcOperand::Reg(materialized),
        None => source_operand.clone(),
    };

    let consumed_without_replay = cursor + 1 - index;
    let mut result = X86JitAtomicRmw {
        consumed: consumed_without_replay,
        guest_pc: atomic.guest_pc,
        addr,
        mem_width: *mem_width,
        width,
        opcode,
        digit,
        source_reg,
        source_imm,
        swap: matches!(op, AtomicOp::Swap),
        replay: false,
        replay_unary: None,
        writeback: None,
    };

    // Optional trailing operations, in the order the lifter emits them: the
    // flag replay (same Group-1 operation on the loaded value and the same
    // source), then XADD's architectural write-back of the loaded value.
    let mut tail = cursor + 1;
    let mut source_uses = 1usize;
    if !result.swap
        && let Some(replay) = block
            .ops
            .get(tail)
            .filter(|op| op.guest_pc == atomic.guest_pc)
    {
        if let Some((
            replay_tag,
            flags_result,
            replay_old,
            replay_source,
            replay_width,
            replay_flags,
        )) = super::x86_binary_alu_shape(&replay.kind)
        {
            // Constant propagation can fold the materialized immediate back
            // into the replay's source operand, leaving the materializing MOV
            // with a single use.
            let folded_immediate =
                immediate_source.is_some() && replay_source.as_imm() == Some(source_imm);
            if replay_tag == tag
                && matches!(flags_result, VReg::Virtual(_))
                && replay_old == *old
                && (replay_source == expected_source || folded_immediate)
                && replay_width == width
                && replay_flags == crate::smir::ir::flags::FlagUpdate::All
                && (width != OpWidth::W64
                    || matches!(
                        replay.x86_hint,
                        None | Some(crate::smir::ir::ops::X86OpHint::AluEncoding(_))
                    ))
                && virtual_definitions.get(&flags_result) == Some(&1)
                && !virtual_uses.contains_key(&flags_result)
            {
                result.replay = true;
                if !folded_immediate && immediate_source.is_some() {
                    source_uses += 1;
                }
                tail += 1;
            }
        } else if let Some((unary_tag, flags_result, replay_old, replay_width, replay_flags)) =
            super::x86_flagged_unary_shape(&replay.kind)
        {
            // `lock inc`/`lock dec` update memory through ADD/SUB of one but
            // publish the unary flag contract, which leaves CF unchanged.
            let unary_matches = matches!((unary_tag, *op), (1, AtomicOp::Add) | (2, AtomicOp::Sub))
                && source_reg.is_none()
                && source_imm == 1;
            if unary_matches
                && matches!(flags_result, VReg::Virtual(_))
                && replay_old == *old
                && replay_width == width
                && replay_flags == crate::smir::ir::flags::FlagUpdate::All
                && virtual_definitions.get(&flags_result) == Some(&1)
                && !virtual_uses.contains_key(&flags_result)
            {
                result.replay = true;
                result.replay_unary = Some(unary_tag);
                tail += 1;
            }
        }
    }
    if let Some(write) = block
        .ops
        .get(tail)
        .filter(|op| op.guest_pc == atomic.guest_pc)
    {
        if let OpKind::Mov {
            dst: dst @ VReg::Arch(crate::smir::ir::types::ArchReg::X86(reg)),
            src: SrcOperand::Reg(moved),
            width: move_width,
        } = &write.kind
        {
            // A byte destination is ambiguous between SPL/BPL/SIL/DIL and the
            // legacy high-byte registers, and RSP/RBP plus the APX EGPRs are
            // state-backed rather than identity mapped.
            if *moved == *old
                && *move_width == width
                && matches!(width, OpWidth::W16 | OpWidth::W32 | OpWidth::W64)
                && write.x86_hint.is_none()
                && reg
                    .gpr_index()
                    .is_some_and(|index| index <= 15 && !matches!(index, 4 | 5))
            {
                result.writeback = Some(*dst);
                tail += 1;
            }
        }
    }

    let expected_old_uses = usize::from(result.replay) + usize::from(result.writeback.is_some());
    if virtual_uses.get(old).copied().unwrap_or(0) != expected_old_uses {
        return None;
    }
    if let Some(materialized) = immediate_source {
        if virtual_uses.get(&materialized).copied().unwrap_or(0) != source_uses {
            return None;
        }
    }
    result.consumed = tail - index;
    Some(result)
}

/// Length of the fused LOCK read-modify-write starting at `index`, if any.
pub(crate) fn x86_jit_mem_atomic_rmw_sequence_len(
    block: &SmirBlock,
    index: usize,
    allow_mem: bool,
    virtual_definitions: &std::collections::HashMap<VReg, usize>,
    virtual_uses: &std::collections::HashMap<VReg, usize>,
) -> Option<usize> {
    x86_jit_mem_atomic_rmw_sequence(block, index, allow_mem, virtual_definitions, virtual_uses)
        .map(|sequence| sequence.consumed)
}
