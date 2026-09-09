//! Exact optimized scalar memory forms; faulting accesses are never removed.

use super::*;
use crate::smir::ir::types::{ArchReg, MemWidth, OpWidth, SignExtend, SrcOperand, VReg};
use crate::smir::ir::{
    SmirBlock,
    flags::FlagUpdate,
    ops::{OpKind, X86OpHint},
};
use std::collections::HashMap;

fn hint_valid(hint: Option<X86OpHint>) -> bool {
    matches!(hint, None | Some(X86OpHint::AluEncoding(_)))
}

/// After constant folding, the load may feed an architectural copy, or be
/// deliberately unused before an architectural constant write. The load must
/// still run first because it can fault or touch MMIO.
pub(crate) fn x86_jit_mem_alu_folded_source_valid(
    consumer: &crate::smir::ir::ops::SmirOp,
    temporary: VReg,
    width: OpWidth,
    uses: &HashMap<VReg, usize>,
) -> bool {
    let OpKind::Mov {
        dst,
        src,
        width: OpWidth::W64,
    } = &consumer.kind
    else {
        return false;
    };
    if width != OpWidth::W64
        || !hint_valid(consumer.x86_hint)
        || !matches!(dst, VReg::Arch(ArchReg::X86(reg)) if reg.gpr_index().is_some())
    {
        return false;
    }
    match src {
        SrcOperand::Reg(source) => *source == temporary && uses.get(&temporary) == Some(&1),
        SrcOperand::Imm(0) | SrcOperand::Imm64(0) => !uses.contains_key(&temporary),
        _ => false,
    }
}

pub(crate) struct X86JitFoldedAluRmw {
    pub(crate) consumed: usize,
    pub(crate) opcode: u8,
    pub(crate) digit: u8,
    pub(crate) immediate: i64,
    pub(crate) replay: bool,
}

/// Match only a W64 identity/zero compute between the original checked load
/// and store, optionally followed by the exact still-live architectural flag
/// replay. Copy propagation may also remove the identity MOV itself.
pub(crate) fn x86_jit_mem_alu_folded_rmw_sequence(
    block: &SmirBlock,
    index: usize,
    allow_mem: bool,
    definitions: &HashMap<VReg, usize>,
    uses: &HashMap<VReg, usize>,
) -> Option<X86JitFoldedAluRmw> {
    if !allow_mem {
        return None;
    }
    let load = block.ops.get(index)?;
    let OpKind::Load {
        dst: old @ VReg::Virtual(_),
        addr,
        width: MemWidth::B8,
        sign: SignExtend::Zero,
    } = &load.kind
    else {
        return None;
    };
    if !x86_jit_mem_address_shape_valid(addr) || definitions.get(old) != Some(&1) {
        return None;
    }
    let next = block.ops.get(index + 1)?;
    let (result, zero, store_index) = match &next.kind {
        OpKind::Mov {
            dst: result @ VReg::Virtual(_),
            src,
            width: OpWidth::W64,
        } if next.guest_pc == load.guest_pc
            && hint_valid(next.x86_hint)
            && definitions.get(result) == Some(&1)
            && uses.get(result) == Some(&1) =>
        {
            let zero = match src {
                SrcOperand::Reg(source) if source == old => false,
                SrcOperand::Imm(0) | SrcOperand::Imm64(0) => true,
                _ => return None,
            };
            (*result, zero, index + 2)
        }
        OpKind::Store { src, .. } if src == old => (*old, false, index + 1),
        _ => return None,
    };
    let store = block.ops.get(store_index)?;
    if store.guest_pc != load.guest_pc
        || !matches!(&store.kind,
        OpKind::Store { src, addr: target, width: MemWidth::B8 } if *src == result && target == addr)
    {
        return None;
    }

    // Without a flag replay OR 0 realizes an identity; AND 0 realizes zero.
    // PUSHFQ/POPFQ around speculative computation preserves incoming flags.
    let mut sequence = X86JitFoldedAluRmw {
        consumed: store_index + 1 - index,
        opcode: if zero { 0x20 } else { 0x08 },
        digit: if zero { 4 } else { 1 },
        immediate: 0,
        replay: false,
    };
    let compute_uses = usize::from(!zero);
    let old_uses = uses.get(old).copied().unwrap_or(0);
    if old_uses == compute_uses {
        return Some(sequence);
    }
    if old_uses != compute_uses + 1 {
        return None;
    }
    let replay = block.ops.get(store_index + 1)?;
    if replay.guest_pc != load.guest_pc || !hint_valid(replay.x86_hint) {
        return None;
    }
    let (tag, flags_result, replay_old, source, width, flags) = x86_binary_alu_shape(&replay.kind)?;
    let immediate = source.as_imm()?;
    let same_result = if zero {
        tag == 4 && immediate == 0
    } else {
        (matches!(tag, 0 | 1 | 5 | 6) && immediate == 0) || (tag == 4 && immediate == -1)
    };
    if !same_result
        || replay_old != *old
        || width != OpWidth::W64
        || flags != FlagUpdate::All
        || !matches!(flags_result, VReg::Virtual(_))
        || definitions.get(&flags_result) != Some(&1)
        || uses.contains_key(&flags_result)
    {
        return None;
    }
    sequence.consumed += 1;
    sequence.opcode = tag * 8;
    sequence.digit = tag;
    sequence.immediate = immediate;
    sequence.replay = true;
    Some(sequence)
}
