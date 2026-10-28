//! Admission of observable x86 instruction retirement boundaries.

use super::{SmirFunction, ops::OpKind, types::BlockId};
use std::collections::HashMap;

/// Validate the complete graph before emitting any executable code. One
/// source encoding belongs to each executable block, including zero-op NOPs.
/// Complexity: O(B + I + O) time, O(B) auxiliary space.
pub(crate) fn validate_x86_retirement(
    function: &SmirFunction,
    exits: &HashMap<BlockId, u64>,
) -> Result<(), &'static str> {
    if !function.attrs.x86_instruction_retirement {
        return Ok(());
    }
    let mut sources = HashMap::new();
    for (&(block, pc), instruction) in &function.x86_instruction_bytes {
        if sources.insert(block, (pc, instruction)).is_some() {
            return Err("multiple x86 instructions in one retirement block");
        }
    }
    for block in &function.blocks {
        if exits.contains_key(&block.id) {
            continue;
        }
        let Some(&(pc, instruction)) = sources.get(&block.id) else {
            return Err("missing x86 retirement source instruction");
        };
        let next = pc
            .checked_add(instruction.as_slice().len() as u64)
            .ok_or("x86 retirement PC overflow")?;
        if pc != block.guest_pc
            || block.ops.iter().any(|op| {
                op.guest_pc != pc
                    && !(op.guest_pc == next && matches!(op.kind, OpKind::TestCondition { .. }))
            })
        {
            return Err("x86 retirement operations cross an instruction boundary");
        }
    }
    Ok(())
}

/// Restore instruction boundaries after ordinary O2 optimization. The original
/// single-instruction CFG supplies the execution order, including instructions
/// with no surviving semantic ops. Follow merged unconditional edges rather
/// than sorting PCs: a merged chain can jump backward in the address space.
/// Cross-instruction constant/copy optimization is retained. Complexity is
/// O(B + I + O) time and space; no guest execution or byte-distance inference.
pub(crate) fn split_x86_retirement(
    function: &mut SmirFunction,
    original: &SmirFunction,
) -> Result<(), &'static str> {
    use super::{SmirBlock, Terminator};
    use std::collections::HashSet;
    let originals: HashMap<_, _> = original.blocks.iter().map(|b| (b.id, b)).collect();
    let live: HashSet<_> = function.blocks.iter().map(|b| b.id).collect();
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    let mut provenance = HashMap::new();
    for optimized in &function.blocks {
        if !optimized.phis.is_empty() {
            return Err("x86 retirement phi nodes");
        }
        let mut chain = Vec::new();
        let mut id = optimized.id;
        loop {
            let block = originals.get(&id).ok_or("unknown optimized x86 block")?;
            if !seen.insert(id) {
                return Err("overlapping/cyclic merged retirement chain");
            }
            chain.push(*block);
            let next = match block.terminator {
                Terminator::Branch { target } => Some(target),
                Terminator::CondBranch {
                    true_target,
                    false_target,
                    ..
                } if true_target == false_target => Some(true_target),
                _ => None,
            };
            if let Some(next) = next.filter(|next| !live.contains(next)) {
                id = next;
            } else {
                break;
            }
        }
        let mut operations: HashMap<_, Vec<_>> = HashMap::new();
        for op in &optimized.ops {
            operations.entry(op.guest_pc).or_default().push(op.clone());
        }
        for (index, original_block) in chain.iter().enumerate() {
            let mut block = SmirBlock::new(original_block.id, original_block.guest_pc);
            block.ops = operations.remove(&block.guest_pc).unwrap_or_default();
            let key = (block.id, block.guest_pc);
            if let Some(instruction) = original.x86_instruction_bytes.get(&key) {
                provenance.insert(key, *instruction);
            } else if chain.len() != 1 || !block.ops.is_empty() {
                return Err("missing original x86 instruction boundary");
            }
            block.terminator = if let Some(next) = chain.get(index + 1) {
                Terminator::Branch { target: next.id }
            } else {
                optimized.terminator.clone()
            };
            result.push(block);
        }
        if !operations.is_empty() {
            return Err("optimized operation has no original instruction");
        }
    }
    function.blocks = result;
    function.x86_instruction_bytes = provenance;
    function.attrs.x86_instruction_retirement = true;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smir::{
        ir::{
            SmirBlock, Terminator, X86InstructionBytes,
            ops::SmirOp,
            types::{FunctionId, OpId},
        },
        lower::{SmirLowerer, aarch64::Aarch64Lowerer, x86_64::X86_64Lowerer},
        optimize::{OptLevel, optimize_function},
    };

    fn function() -> SmirFunction {
        let mut f = SmirFunction::new(FunctionId(0), BlockId(0), 0x100);
        f.attrs.x86_instruction_retirement = true;
        f.attrs.preserve_interpreter_frontiers = true;
        let mut b = SmirBlock::new(BlockId(0), 0x100);
        b.terminator = Terminator::Branch { target: BlockId(1) };
        f.add_block(b);
        let mut b = SmirBlock::new(BlockId(1), 0x101);
        b.terminator = Terminator::Return { values: vec![] };
        f.add_block(b);
        f.x86_instruction_bytes.insert(
            (BlockId(0), 0x100),
            X86InstructionBytes::new(&[0x90]).unwrap(),
        );
        f
    }

    #[test]
    fn optimized_nop_keeps_its_observable_retirement_block() {
        let mut f = function();
        optimize_function(&mut f, OptLevel::O2);
        assert_eq!(f.blocks.len(), 2);
        assert!(f.blocks[0].ops.is_empty());
        assert!(validate_x86_retirement(&f, &HashMap::from([(BlockId(1), 0x101)])).is_ok());
    }

    #[test]
    fn restores_eliminated_instruction_order_after_cross_instruction_block_merging() {
        let mut original = function();
        original.blocks[1].terminator = Terminator::Branch { target: BlockId(2) };
        original.x86_instruction_bytes.insert(
            (BlockId(1), 0x101),
            X86InstructionBytes::new(&[0x90]).unwrap(),
        );
        let mut frontier = SmirBlock::new(BlockId(2), 0x102);
        frontier.terminator = Terminator::Return { values: vec![] };
        original.add_block(frontier);
        let mut optimized = original.clone();
        optimized.attrs.x86_instruction_retirement = false;
        optimize_function(&mut optimized, OptLevel::O2);
        assert_eq!(optimized.blocks.len(), 2);
        split_x86_retirement(&mut optimized, &original).unwrap();
        assert_eq!(
            optimized
                .blocks
                .iter()
                .map(|b| b.guest_pc)
                .collect::<Vec<_>>(),
            vec![0x100, 0x101, 0x102]
        );
        assert_eq!(optimized.x86_instruction_bytes.len(), 2);
        let exits = HashMap::from([(BlockId(2), 0x102)]);
        assert!(validate_x86_retirement(&optimized, &exits).is_ok());
        let mut x86 = X86_64Lowerer::new();
        x86.set_native_exits(exits.clone());
        let mut a64 = Aarch64Lowerer::new();
        a64.set_native_exits(exits);
        assert!(x86.lower_function(&optimized).is_ok());
        assert!(a64.lower_function(&optimized).is_ok());
    }

    #[test]
    fn both_lowerers_reject_missing_ambiguous_and_cross_instruction_sources() {
        for case in 0..4 {
            let mut f = function();
            match case {
                0 => f.x86_instruction_bytes.clear(),
                1 => {
                    f.x86_instruction_bytes.insert(
                        (BlockId(0), 0x101),
                        X86InstructionBytes::new(&[0x90]).unwrap(),
                    );
                }
                2 => f.blocks[0]
                    .ops
                    .push(SmirOp::new(OpId(0), 0x102, OpKind::Nop)),
                3 => f.blocks[0].guest_pc = 0x102,
                _ => unreachable!(),
            }
            let exits = HashMap::from([(BlockId(1), 0x101)]);
            let mut x86 = X86_64Lowerer::new();
            x86.set_native_exits(exits.clone());
            let mut a64 = Aarch64Lowerer::new();
            a64.set_native_exits(exits);
            assert!(x86.lower_function(&f).is_err(), "case{case}");
            assert!(a64.lower_function(&f).is_err(), "case{case}");
        }
    }
}
