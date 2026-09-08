//! Conservative local low-bit proofs for generic vector memory operations.
//!
//! Encoding hints belong to the source instruction when it has x86 byte
//! provenance. They are not an analysis scratch field: changing even an absent
//! hint can invalidate an exact native replay sequence. Generic, unhinted IR
//! without that provenance may select an aligned move only from local facts.

use std::collections::HashMap;

use crate::smir::ir::SmirFunction;
use crate::smir::ir::ops::{OpKind, SmirOp, X86OpHint, X86VecAlign};
use crate::smir::ir::types::{Address, OpWidth, SrcOperand, VReg};

/// The widest vector memory operation is 64 bytes. Capping the number of
/// proven low zero bits at six retains every relevant fact without computing
/// a potentially overflowing host-sized alignment or a full register value.
const MAX_LOW_ZERO_BITS: u32 = 6;
type LowZeroBits = HashMap<VReg, u32>;

/// Infer aligned vector-move hints from local proofs, preserving source hints.
///
/// No calling convention or incoming register alignment is assumed. Each
/// block starts independently, and operations with implicit state effects
/// invalidate local facts. Provenance-covered operations and pre-existing
/// encoding hints are never changed. This does not eliminate memory accesses
/// or prove that an address is mapped, non-faulting, or non-volatile.
///
/// Expected time is O(N + D), where N is the number of operations and D their
/// explicit destinations; space is O(R) for the locally tracked registers.
pub fn vector_alignment_inference(func: &mut SmirFunction) -> usize {
    let mut inferred = 0;
    let provenance = &func.x86_instruction_bytes;
    for block in &mut func.blocks {
        let mut facts = LowZeroBits::new();
        for op in &mut block.ops {
            if !provenance.contains_key(&(block.id, op.guest_pc)) {
                inferred += apply_hint(op, &facts);
            }
            update_facts(op, &mut facts);
        }
    }
    inferred
}

fn apply_hint(op: &mut SmirOp, facts: &LowZeroBits) -> usize {
    if op.x86_hint.is_some() {
        return 0;
    }
    let (address, width) = match &op.kind {
        OpKind::VLoad { addr, width, .. } | OpKind::VStore { addr, width, .. } => (addr, width),
        _ => return 0,
    };
    if address_low_zero_bits(address, facts)
        .is_some_and(|bits| bits >= width.bytes().trailing_zeros())
    {
        op.x86_hint = Some(X86OpHint::VecAlign(X86VecAlign::Aligned));
        1
    } else {
        0
    }
}

/// All integer values are divisible by one; an unknown register proves zero
/// low zero bits, never an ABI-specific stack or frame alignment.
fn register_bits(register: &VReg, facts: &LowZeroBits) -> u32 {
    facts.get(register).copied().unwrap_or(0)
}

fn constant_bits(value: u64) -> u32 {
    value.trailing_zeros().min(MAX_LOW_ZERO_BITS)
}

fn operand_bits(operand: &SrcOperand, facts: &LowZeroBits) -> u32 {
    if let Some(value) = operand.as_imm() {
        constant_bits(value as u64)
    } else if let Some(register) = operand.as_reg() {
        register_bits(&register, facts)
    } else {
        0
    }
}

fn update_facts(op: &SmirOp, facts: &mut LowZeroBits) {
    // Ordinary loads/stores affect only their explicit destination and memory;
    // their interpreter arms do not modify other registers. Preserve facts
    // across them, but invalidate a load's destination below. Other side
    // effects may include implicit writes (e.g. SYSCALL, SWI, system helpers).
    if op.kind.has_side_effects()
        && !matches!(
            op.kind,
            OpKind::Load { .. }
                | OpKind::Store { .. }
                | OpKind::VLoad { .. }
                | OpKind::VStore { .. }
        )
    {
        facts.clear();
        return;
    }

    // Read every input before invalidating destinations, including the old
    // destination of an in-place operation or conditional move.
    let computed = match &op.kind {
        OpKind::Mov {
            dst,
            src,
            width: OpWidth::W64,
        } => Some((*dst, operand_bits(src, facts))),
        OpKind::Add {
            dst,
            src1,
            src2,
            width: OpWidth::W64,
            ..
        }
        | OpKind::Sub {
            dst,
            src1,
            src2,
            width: OpWidth::W64,
            ..
        } => Some((
            *dst,
            register_bits(src1, facts).min(operand_bits(src2, facts)),
        )),
        OpKind::Shl {
            dst,
            src,
            amount,
            width: OpWidth::W64,
            ..
        } => {
            amount.as_imm().map(|amount| {
                // Canonical W64 scalar shifts mask the count to six bits.
                // Addition of capped exponents models modulo-2^64 overflow:
                // discarding high bits cannot destroy any proven low zeros.
                let shift = (amount as u64 & 0x3F) as u32;
                (
                    *dst,
                    (register_bits(src, facts) + shift).min(MAX_LOW_ZERO_BITS),
                )
            })
        }
        OpKind::And {
            dst,
            src1,
            src2,
            width: OpWidth::W64,
            ..
        } => Some((
            *dst,
            register_bits(src1, facts).max(operand_bits(src2, facts)),
        )),
        OpKind::CMove {
            dst,
            src,
            width: OpWidth::W64,
            ..
        } => Some((
            *dst,
            register_bits(dst, facts).min(register_bits(src, facts)),
        )),
        OpKind::Select {
            dst,
            src_true,
            src_false,
            width: OpWidth::W64,
            ..
        } => Some((
            *dst,
            register_bits(src_true, facts).min(register_bits(src_false, facts)),
        )),
        OpKind::Lea { dst, addr }
        | OpKind::X86Lea {
            dst,
            addr,
            width: OpWidth::W64,
        } => address_low_zero_bits(addr, facts).map(|bits| (*dst, bits)),
        // Partial writes and operations without an explicit transfer proof
        // invalidate their destinations; no incoming upper-bit fact survives.
        _ => None,
    };

    for destination in op.kind.dests() {
        facts.remove(&destination);
    }
    if let Some((destination, bits)) = computed {
        if bits != 0 {
            facts.insert(destination, bits);
        }
    }
}

fn address_low_zero_bits(address: &Address, facts: &LowZeroBits) -> Option<u32> {
    match address {
        Address::Direct(base) => Some(register_bits(base, facts)),
        Address::BaseOffset { base, offset, .. } => {
            Some(register_bits(base, facts).min(constant_bits(*offset as u64)))
        }
        Address::BaseIndexScale {
            base,
            index,
            scale,
            disp,
            ..
        } => {
            let scaled = (register_bits(index, facts) + constant_bits(u64::from(*scale)))
                .min(MAX_LOW_ZERO_BITS);
            let base_bits = base
                .as_ref()
                .map_or(MAX_LOW_ZERO_BITS, |base| register_bits(base, facts));
            Some(
                scaled
                    .min(base_bits)
                    .min(constant_bits(*disp as i64 as u64)),
            )
        }
        Address::PcRel {
            offset,
            base: Some(base),
            ..
        } => Some(constant_bits(base.wrapping_add(*offset as u64))),
        Address::Absolute(value) => Some(constant_bits(*value)),
        // These require architectural address-size/segment/GP proofs not
        // represented by the local generic facts. An unknown PC is likewise
        // not inferred from the containing block's guest address.
        Address::X86Addr32(_)
        | Address::SegmentRel { .. }
        | Address::GpRel { .. }
        | Address::PcRel { base: None, .. } => None,
    }
}
