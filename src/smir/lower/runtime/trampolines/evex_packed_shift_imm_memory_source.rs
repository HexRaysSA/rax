//! Fail-closed helper-backed EVEX immediate packed-shift memory admission.

use std::collections::HashMap;

use super::evex_memory_source_common::{
    X86EvexE4MemoryReplayForm, X86EvexE4MemoryShape, exact_evex_e4_memory_sequence_tail,
    exact_evex_vector_mask_result, vector_index,
};
use crate::smir::ir::ops::OpKind;
use crate::smir::ir::types::{ArchReg, BlockId, GuestAddr, VReg, X86Reg};
use crate::smir::ir::{
    X86EvexPackedShiftImmMemoryEncoding, X86EvexPackedShiftImmMemoryReplay, X86InstructionBytes,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct X86JitEvexPackedShiftImmMemorySequence {
    pub(crate) consumed: usize,
    pub(crate) address_offset: usize,
    pub(crate) memory_size: u32,
    pub(crate) encoding: X86EvexPackedShiftImmMemoryEncoding,
}

/// Bind provenance, memory materialization, shift, and merge/zero mask tail
/// before admitting any native operation. The load graph is E4 for D/Q and
/// unconditionally full-vector for E4NF.nb word/byte-lane shifts. Matching is
/// O(L + T) time and O(1) auxiliary space for L lanes and T mask-tail ops;
/// caller-owned definition/use maps take O(N) time and O(V) space.
pub(crate) fn x86_jit_evex_packed_shift_imm_memory_sequence(
    block: &crate::smir::ir::SmirBlock,
    index: usize,
    allow_mem: bool,
    instruction_bytes: &HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
    virtual_definitions: &HashMap<VReg, usize>,
    virtual_uses: &HashMap<VReg, usize>,
) -> Option<X86JitEvexPackedShiftImmMemorySequence> {
    if !allow_mem {
        return None;
    }
    let first = block.ops.get(index)?;
    let encoding = instruction_bytes
        .get(&(block.id, first.guest_pc))?
        .evex_packed_shift_imm_memory_encoding()?;
    let form = match encoding.replay {
        X86EvexPackedShiftImmMemoryReplay::Vector { .. } => X86EvexE4MemoryReplayForm::Vector,
        X86EvexPackedShiftImmMemoryReplay::Broadcast { .. } => X86EvexE4MemoryReplayForm::Broadcast,
        X86EvexPackedShiftImmMemoryReplay::MaskedVector { .. } => {
            X86EvexE4MemoryReplayForm::MaskedVector
        }
    };
    // E4NF masking affects the destination, never memory access. The common
    // load matcher therefore sees an unmasked source; the tail below still
    // validates the exact architectural writemask and zeroing reconstruction.
    let unconditional = form == X86EvexE4MemoryReplayForm::Vector;
    let shape = X86EvexE4MemoryShape {
        width: encoding.width,
        elem: encoding.elem,
        writemask: if unconditional {
            None
        } else {
            encoding.writemask
        },
        zeroing: !unconditional && encoding.zeroing,
        vector_load_hint: None,
        form,
        memory_source_uses: 1,
    };
    let exact = exact_evex_e4_memory_sequence_tail(
        block,
        index,
        shape,
        virtual_definitions,
        virtual_uses,
        |block, tail_index, loaded| {
            let shift = block.ops.get(tail_index)?;
            let raw = match shift.kind {
                OpKind::X86PackedShiftImm {
                    dst,
                    src,
                    width,
                    elem,
                    shift: kind,
                    amount,
                    byte_lane,
                } if shift.x86_hint.is_none()
                    && src == loaded
                    && width == encoding.width
                    && elem == encoding.elem
                    && kind == encoding.shift
                    && amount == encoding.immediate
                    && byte_lane == encoding.byte_lane =>
                {
                    dst
                }
                _ => return None,
            };
            let mut consumed = 1;
            if let Some(mask) = encoding.writemask {
                if !matches!(raw, VReg::Virtual(_)) {
                    return None;
                }
                exact_evex_vector_mask_result(
                    block,
                    tail_index,
                    &mut consumed,
                    shift.guest_pc,
                    raw,
                    VReg::Arch(ArchReg::X86(X86Reg::K(mask))),
                    encoding.width,
                    encoding.elem,
                    encoding.destination,
                    encoding.zeroing,
                    virtual_definitions,
                    virtual_uses,
                )?;
            } else if encoding.zeroing
                || vector_index(&raw, encoding.width) != Some(encoding.destination)
            {
                return None;
            }
            Some(consumed)
        },
    )?;
    Some(X86JitEvexPackedShiftImmMemorySequence {
        consumed: exact.consumed,
        address_offset: exact.address_offset,
        memory_size: exact.memory_size,
        encoding,
    })
}
