//! Function-wide closure of virtuals elided by scalar ALU memory fusion.

use super::{
    x86_jit_mem_alu_rmw_sequence_len, x86_jit_mem_alu_source_sequence_len,
    x86_jit_mem_atomic_rmw_sequence_len,
};
use crate::smir::ir::ops::OpKind;
use crate::smir::ir::types::VReg;
use crate::smir::ir::{SmirBlock, SmirFunction, Terminator};
use std::collections::HashMap;

#[derive(Default)]
struct Counts {
    definitions: HashMap<VReg, usize>,
    uses: HashMap<VReg, usize>,
}

impl Counts {
    fn add_definition(&mut self, register: VReg) {
        if matches!(register, VReg::Virtual(_)) {
            *self.definitions.entry(register).or_default() += 1;
        }
    }

    fn add_use(&mut self, register: VReg) {
        if matches!(register, VReg::Virtual(_)) {
            *self.uses.entry(register).or_default() += 1;
        }
    }

    fn add_ops(&mut self, block: &SmirBlock) {
        for op in &block.ops {
            for register in op.kind.dests() {
                self.add_definition(register);
            }
            for register in op.kind.source_vregs() {
                self.add_use(register);
            }
        }
    }

    fn add_non_ops(&mut self, block: &SmirBlock) {
        for phi in &block.phis {
            self.add_definition(phi.dst);
            for (_, source) in &phi.sources {
                self.add_use(*source);
            }
        }
        // Keep exhaustive: a new terminator must account for every virtual
        // operand, including registers nested in indirect memory/call targets.
        match &block.terminator {
            Terminator::CondBranch { cond, .. }
            | Terminator::Switch { index: cond, .. }
            | Terminator::IndirectBranch { target: cond, .. } => self.add_use(*cond),
            Terminator::IndirectBranchMem { addr, .. } => {
                for register in addr.regs() {
                    self.add_use(register);
                }
            }
            Terminator::Return { values } => {
                for register in values {
                    self.add_use(*register);
                }
            }
            Terminator::Call { target, args, .. } | Terminator::TailCall { target, args } => {
                for register in target.regs() {
                    self.add_use(register);
                }
                for register in args {
                    self.add_use(*register);
                }
            }
            Terminator::Branch { .. } | Terminator::Trap { .. } | Terminator::Unreachable => {}
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Family {
    Rmw,
    Atomic,
    Source,
}

fn sequence(block: &SmirBlock, index: usize, counts: &Counts) -> Option<(Family, usize)> {
    if let Some(length) =
        x86_jit_mem_alu_rmw_sequence_len(block, index, true, &counts.definitions, &counts.uses)
    {
        return Some((Family::Rmw, length));
    }
    if let Some(length) =
        x86_jit_mem_atomic_rmw_sequence_len(block, index, true, &counts.definitions, &counts.uses)
    {
        return Some((Family::Atomic, length));
    }
    x86_jit_mem_alu_source_sequence_len(block, index, true, &counts.definitions, &counts.uses)
        .map(|length| (Family::Source, length))
}

/// Every locally fused scalar span must retain the identical exact match when
/// references from the complete function are counted. Matchers require one
/// definition and exact use counts for every internal virtual (including dead
/// flag results and constant materializers), so any phi, terminator, foreign
/// operation, or foreign-block reference invalidates the match. Excluded native
/// blocks are included: they must not observe an elided value after a frontier.
///
/// No unrelated native family is admitted or rejected here. Expected time is
/// O(N + P + T), for operation/operand visits N, phi references P, and terminator
/// references T. Auxiliary space is O(V), for function-wide virtual registers.
pub(crate) fn x86_jit_scalar_alu_function_virtuals_closed(function: &SmirFunction) -> bool {
    if !function
        .blocks
        .iter()
        .flat_map(|block| &block.ops)
        .any(|op| {
            matches!(
                op.kind,
                OpKind::Load {
                    dst: VReg::Virtual(_),
                    ..
                } | OpKind::AtomicRmw {
                    dst: VReg::Virtual(_),
                    ..
                }
            )
        })
    {
        return true;
    }
    let mut global = Counts::default();
    for block in &function.blocks {
        global.add_ops(block);
        global.add_non_ops(block);
    }
    for block in &function.blocks {
        let mut local = Counts::default();
        local.add_ops(block);
        let mut index = 0;
        while index < block.ops.len() {
            if let Some(matched) = sequence(block, index, &local) {
                if sequence(block, index, &global) != Some(matched) {
                    return false;
                }
                index += matched.1;
            } else {
                index += 1;
            }
        }
    }
    true
}
