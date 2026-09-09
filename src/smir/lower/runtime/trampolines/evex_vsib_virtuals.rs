//! Function-wide closure of virtual values elided by native VSIB fusion.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};

use crate::smir::ir::types::{GuestAddr, VReg};
use crate::smir::ir::{SmirBlock, SmirFunction, Terminator};

/// No value from `owned` may enter a phi or terminator, even in its defining
/// block. Exact VSIB lowering does not materialize those internal values.
/// Keep this match exhaustive so new terminator forms require an explicit
/// register-operand audit. Address and call-target helpers cover nested addr32,
/// segment, base, and index operands as well as indirect register targets.
pub(super) fn x86_jit_vsib_non_op_virtuals_closed(
    block: &SmirBlock,
    owned: &HashSet<VReg>,
) -> bool {
    if block.phis.iter().any(|phi| {
        owned.contains(&phi.dst) || phi.sources.iter().any(|(_, source)| owned.contains(source))
    }) {
        return false;
    }
    match &block.terminator {
        Terminator::CondBranch { cond, .. }
        | Terminator::Switch { index: cond, .. }
        | Terminator::IndirectBranch { target: cond, .. } => !owned.contains(cond),
        Terminator::IndirectBranchMem { addr, .. } => {
            addr.regs().iter().all(|reg| !owned.contains(reg))
        }
        Terminator::Return { values } => values.iter().all(|reg| !owned.contains(reg)),
        Terminator::Call { target, args, .. } | Terminator::TailCall { target, args } => {
            args.iter().all(|reg| !owned.contains(reg))
                && target.regs().iter().all(|reg| !owned.contains(reg))
        }
        Terminator::Branch { .. } | Terminator::Trap { .. } | Terminator::Unreachable => true,
    }
}

/// Reject references to a VSIB-private virtual outside its owning instruction.
///
/// Ownership is `(block ordinal, guest PC)`, not only BlockId: malformed blocks
/// that reuse an ID must not silently share private values. The valid source
/// bytes select this narrow family; this check does not admit an instruction or
/// replace the exact graph matcher. It examines every block, including blocks
/// that a caller may otherwise exclude from native execution.
///
/// Expected time is O(N + P + T), for operation/operand visits N, phi references
/// P, and terminator references T; x86 byte classification is bounded by 15 B.
/// Auxiliary space is O(V), for V VSIB-owned virtual registers.
pub(crate) fn x86_jit_vsib_function_virtuals_closed(function: &SmirFunction) -> bool {
    let mut owners: HashMap<VReg, (usize, GuestAddr)> = HashMap::new();
    for (ordinal, block) in function.blocks.iter().enumerate() {
        for op in &block.ops {
            if !function
                .x86_instruction_bytes
                .get(&(block.id, op.guest_pc))
                .is_some_and(|bytes| bytes.evex_vsib_memory_encoding().is_some())
            {
                continue;
            }
            let owner = (ordinal, op.guest_pc);
            for register in op.kind.dests() {
                if !matches!(register, VReg::Virtual(_)) {
                    continue;
                }
                match owners.entry(register) {
                    Entry::Vacant(entry) => {
                        entry.insert(owner);
                    }
                    Entry::Occupied(entry) if *entry.get() == owner => {}
                    Entry::Occupied(_) => return false,
                }
            }
        }
    }
    if owners.is_empty() {
        return true;
    }
    let owned: HashSet<_> = owners.keys().copied().collect();
    for (ordinal, block) in function.blocks.iter().enumerate() {
        if !x86_jit_vsib_non_op_virtuals_closed(block, &owned) {
            return false;
        }
        for op in &block.ops {
            let owner = (ordinal, op.guest_pc);
            for register in op.kind.dests().into_iter().chain(op.kind.source_vregs()) {
                if owners.get(&register).is_some_and(|actual| *actual != owner) {
                    return false;
                }
            }
        }
    }
    true
}
