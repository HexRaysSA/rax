//! SMIR optimization passes.
//!
//! This module implements optimization passes for SMIR to improve execution performance.
//! The most impactful optimization for x86 is dead flag elimination, which removes
//! flag updates that are never read.

use std::collections::{HashMap, HashSet};

use crate::smir::flags::{FlagSet, FlagState, FlagUpdate};
use crate::smir::ir::{CallTarget, SmirBlock, SmirFunction, Terminator};
use crate::smir::ops::{OpKind, SmirOp, X86OpHint, X86VecAlign};
use crate::smir::types::{
    Address, ArchReg, BlockId, HexagonReg, MemWidth, OpWidth, SrcOperand, VReg, VecWidth, X86Reg,
};

// ============================================================================
// Optimization Level
// ============================================================================

/// Optimization level
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum OptLevel {
    /// No optimization (for debugging)
    #[default]
    O0,

    /// Basic optimizations (fast compile, some speedup)
    O1,

    /// Full optimization (slower compile, best runtime)
    O2,
}

// ============================================================================
// Optimization Statistics
// ============================================================================

/// Statistics from optimization passes
#[derive(Clone, Debug, Default)]
pub struct OptStats {
    /// Dead flag updates eliminated
    pub dead_flags_eliminated: usize,

    /// Constants propagated
    pub constants_propagated: usize,

    /// Expressions folded
    pub expressions_folded: usize,

    /// Dead ops eliminated
    pub dead_ops_eliminated: usize,

    /// Strength reductions applied
    pub strength_reductions: usize,

    /// Blocks merged
    pub blocks_merged: usize,

    /// Redundant loads eliminated
    pub redundant_loads_eliminated: usize,

    /// Vector alignment hints inferred
    pub vector_alignments_inferred: usize,
}

impl OptStats {
    /// Create new empty stats
    pub fn new() -> Self {
        Self::default()
    }

    /// Merge stats from another run
    pub fn merge(&mut self, other: &OptStats) {
        self.dead_flags_eliminated += other.dead_flags_eliminated;
        self.constants_propagated += other.constants_propagated;
        self.expressions_folded += other.expressions_folded;
        self.dead_ops_eliminated += other.dead_ops_eliminated;
        self.strength_reductions += other.strength_reductions;
        self.blocks_merged += other.blocks_merged;
        self.redundant_loads_eliminated += other.redundant_loads_eliminated;
        self.vector_alignments_inferred += other.vector_alignments_inferred;
    }

    /// Total optimizations applied
    pub fn total(&self) -> usize {
        self.dead_flags_eliminated
            + self.constants_propagated
            + self.expressions_folded
            + self.dead_ops_eliminated
            + self.strength_reductions
            + self.blocks_merged
            + self.redundant_loads_eliminated
            + self.vector_alignments_inferred
    }
}

// ============================================================================
// Main Optimization Entry Point
// ============================================================================

/// Run optimization pipeline on a function
pub fn optimize_function(func: &mut SmirFunction, level: OptLevel) -> OptStats {
    optimize_function_with_stats(func, level)
}

/// Run optimization pipeline on a function, returning statistics
pub fn optimize_function_with_stats(func: &mut SmirFunction, level: OptLevel) -> OptStats {
    let mut stats = OptStats::new();

    match level {
        OptLevel::O0 => {}
        OptLevel::O1 => {
            for block in &mut func.blocks {
                stats.dead_flags_eliminated += dead_flag_elimination(block);
                stats.constants_propagated += constant_propagation(block);
                stats.dead_ops_eliminated += dead_code_elimination(block);
            }
        }
        OptLevel::O2 => {
            for block in &mut func.blocks {
                stats.dead_flags_eliminated += dead_flag_elimination(block);
                stats.constants_propagated += constant_propagation(block);
                stats.expressions_folded += constant_folding(block);
                stats.strength_reductions += strength_reduction(block);
                stats.dead_ops_eliminated += dead_code_elimination(block);
            }
            stats.blocks_merged += block_merging(func);
            stats.redundant_loads_eliminated += redundant_load_elimination(func);
            stats.vector_alignments_inferred += vector_alignment_inference(func);
        }
    }

    stats
}

// ============================================================================
// Dead Flag Elimination
// ============================================================================

/// Eliminate dead flag updates.
///
/// This is the most impactful optimization for x86 - removes flag updates that
/// are never read. Uses backward analysis to find live flags.
///
/// Returns the number of flag updates eliminated.
pub fn dead_flag_elimination(block: &mut SmirBlock) -> usize {
    if block.ops.is_empty() {
        return 0;
    }

    // Backward analysis to find live flags
    let mut live_out = FlagSet::EMPTY;

    // Check terminator for flag usage
    if let Terminator::CondBranch { cond, .. } = &block.terminator {
        // The cond VReg should have been set by a SetCC or TestCondition op
        // We need to look at what flags those require
        // For now, assume all flags could be needed if there's a conditional branch
        // A more sophisticated analysis would track which condition was used
        live_out = FlagSet::NZCV;
    }

    // Also check if any op reads flags
    for op in block.ops.iter().rev() {
        let reads = op.kind.flags_read();
        live_out = live_out.union(reads);
    }

    // Map from op index to live flags after that op
    let mut liveness = vec![FlagSet::EMPTY; block.ops.len()];

    // Backward pass
    let mut current_live = live_out;
    for i in (0..block.ops.len()).rev() {
        liveness[i] = current_live;

        let op = &block.ops[i];
        let reads = op.kind.flags_read();
        let writes = op.kind.flags_written();

        // live_in = (live_out - writes) | reads
        current_live = current_live.difference(writes).union(reads);
    }

    // Forward pass: eliminate dead flag updates
    let mut eliminated = 0;
    for i in 0..block.ops.len() {
        let live = liveness[i];

        if let Some(flags) = block.ops[i].kind.flags_written_mut() {
            let written = flags.as_set();
            if !written.is_empty() && live.intersection(written).is_empty() {
                *flags = FlagUpdate::None;
                eliminated += 1;
            }
        }
    }

    eliminated
}

// ============================================================================
// Constant Propagation
// ============================================================================

/// Constant propagation within a block.
///
/// Tracks known constant values through the block and replaces register
/// operands with immediate values when possible.
///
/// Returns the number of constants propagated.
pub fn constant_propagation(block: &mut SmirBlock) -> usize {
    let mut constants: HashMap<VReg, i64> = HashMap::new();
    let mut propagated = 0;

    for op in &mut block.ops {
        match &mut op.kind {
            OpKind::Mov { dst, src, .. } => {
                if let SrcOperand::Imm(imm) = src {
                    constants.insert(*dst, *imm);
                } else if let SrcOperand::Reg(r) = src {
                    if let Some(&val) = constants.get(r) {
                        *src = SrcOperand::Imm(val);
                        constants.insert(*dst, val);
                        propagated += 1;
                    } else {
                        constants.remove(dst);
                    }
                } else {
                    constants.remove(dst);
                }
            }

            OpKind::Add {
                dst, src1, src2, ..
            } => {
                // Try to replace src2 with constant if known
                if let SrcOperand::Reg(r) = src2 {
                    if let Some(&val) = constants.get(r) {
                        *src2 = SrcOperand::Imm(val);
                        propagated += 1;
                    }
                }

                // Check if result is constant
                if let Some(&v1) = constants.get(src1) {
                    if let SrcOperand::Imm(v2) = src2 {
                        constants.insert(*dst, v1.wrapping_add(*v2));
                    } else {
                        constants.remove(dst);
                    }
                } else {
                    constants.remove(dst);
                }
            }

            OpKind::Sub {
                dst, src1, src2, ..
            } => {
                if let SrcOperand::Reg(r) = src2 {
                    if let Some(&val) = constants.get(r) {
                        *src2 = SrcOperand::Imm(val);
                        propagated += 1;
                    }
                }

                if let Some(&v1) = constants.get(src1) {
                    if let SrcOperand::Imm(v2) = src2 {
                        constants.insert(*dst, v1.wrapping_sub(*v2));
                    } else {
                        constants.remove(dst);
                    }
                } else {
                    constants.remove(dst);
                }
            }

            OpKind::And {
                dst, src1, src2, ..
            } => {
                if let SrcOperand::Reg(r) = src2 {
                    if let Some(&val) = constants.get(r) {
                        *src2 = SrcOperand::Imm(val);
                        propagated += 1;
                    }
                }

                if let Some(&v1) = constants.get(src1) {
                    if let SrcOperand::Imm(v2) = src2 {
                        constants.insert(*dst, v1 & *v2);
                    } else {
                        constants.remove(dst);
                    }
                } else {
                    constants.remove(dst);
                }
            }

            OpKind::Or {
                dst, src1, src2, ..
            } => {
                if let SrcOperand::Reg(r) = src2 {
                    if let Some(&val) = constants.get(r) {
                        *src2 = SrcOperand::Imm(val);
                        propagated += 1;
                    }
                }

                if let Some(&v1) = constants.get(src1) {
                    if let SrcOperand::Imm(v2) = src2 {
                        constants.insert(*dst, v1 | *v2);
                    } else {
                        constants.remove(dst);
                    }
                } else {
                    constants.remove(dst);
                }
            }

            OpKind::Xor {
                dst, src1, src2, ..
            } => {
                if let SrcOperand::Reg(r) = src2 {
                    if let Some(&val) = constants.get(r) {
                        *src2 = SrcOperand::Imm(val);
                        propagated += 1;
                    }
                }

                if let Some(&v1) = constants.get(src1) {
                    if let SrcOperand::Imm(v2) = src2 {
                        constants.insert(*dst, v1 ^ *v2);
                    } else {
                        constants.remove(dst);
                    }
                } else {
                    constants.remove(dst);
                }
            }

            OpKind::Shl {
                dst, src, amount, ..
            } => {
                if let SrcOperand::Reg(r) = amount {
                    if let Some(&val) = constants.get(r) {
                        *amount = SrcOperand::Imm(val);
                        propagated += 1;
                    }
                }

                if let Some(&v) = constants.get(src) {
                    if let SrcOperand::Imm(a) = amount {
                        constants.insert(*dst, v << (*a as u32));
                    } else {
                        constants.remove(dst);
                    }
                } else {
                    constants.remove(dst);
                }
            }

            OpKind::Shr {
                dst, src, amount, ..
            } => {
                if let SrcOperand::Reg(r) = amount {
                    if let Some(&val) = constants.get(r) {
                        *amount = SrcOperand::Imm(val);
                        propagated += 1;
                    }
                }

                if let Some(&v) = constants.get(src) {
                    if let SrcOperand::Imm(a) = amount {
                        constants.insert(*dst, ((v as u64) >> (*a as u32)) as i64);
                    } else {
                        constants.remove(dst);
                    }
                } else {
                    constants.remove(dst);
                }
            }

            OpKind::Load { dst, .. } | OpKind::AtomicLoad { dst, .. } => {
                // Loads produce unknown values
                constants.remove(dst);
            }

            _ => {
                // For other ops, invalidate destinations
                for dst in op.kind.dests() {
                    constants.remove(&dst);
                }
            }
        }
    }

    propagated
}

// ============================================================================
// Constant Folding
// ============================================================================

/// Fold constant expressions at compile time.
///
/// Evaluates operations where all operands are constants and replaces them
/// with simple moves.
///
/// Returns the number of expressions folded.
pub fn constant_folding(block: &mut SmirBlock) -> usize {
    let mut folded = 0;

    for i in 0..block.ops.len() {
        let new_kind = match &block.ops[i].kind {
            // Add with two immediates
            OpKind::Add {
                dst,
                src1,
                src2: SrcOperand::Imm(v2),
                width,
                ..
            } if matches!(src1, VReg::Imm(..)) => {
                if let VReg::Imm(v1) = src1 {
                    let result = ((*v1 as u64).wrapping_add(*v2 as u64)) & width.mask();
                    Some(OpKind::Mov {
                        dst: *dst,
                        src: SrcOperand::Imm(result as i64),
                        width: *width,
                    })
                } else {
                    None
                }
            }

            // Sub with two immediates
            OpKind::Sub {
                dst,
                src1,
                src2: SrcOperand::Imm(v2),
                width,
                ..
            } if matches!(src1, VReg::Imm(..)) => {
                if let VReg::Imm(v1) = src1 {
                    let result = ((*v1 as u64).wrapping_sub(*v2 as u64)) & width.mask();
                    Some(OpKind::Mov {
                        dst: *dst,
                        src: SrcOperand::Imm(result as i64),
                        width: *width,
                    })
                } else {
                    None
                }
            }

            // And with zero -> 0
            OpKind::And {
                dst,
                src2: SrcOperand::Imm(0),
                width,
                ..
            } => Some(OpKind::Mov {
                dst: *dst,
                src: SrcOperand::Imm(0),
                width: *width,
            }),

            // And with -1 (all bits) -> mov src1
            OpKind::And {
                dst,
                src1,
                src2: SrcOperand::Imm(-1),
                width,
                ..
            } => Some(OpKind::Mov {
                dst: *dst,
                src: SrcOperand::Reg(*src1),
                width: *width,
            }),

            // Or with zero -> mov src1
            OpKind::Or {
                dst,
                src1,
                src2: SrcOperand::Imm(0),
                width,
                ..
            } => Some(OpKind::Mov {
                dst: *dst,
                src: SrcOperand::Reg(*src1),
                width: *width,
            }),

            // Xor with zero -> mov src1
            OpKind::Xor {
                dst,
                src1,
                src2: SrcOperand::Imm(0),
                width,
                ..
            } => Some(OpKind::Mov {
                dst: *dst,
                src: SrcOperand::Reg(*src1),
                width: *width,
            }),

            // Xor of same register -> 0
            OpKind::Xor {
                dst,
                src1,
                src2: SrcOperand::Reg(src2),
                width,
                ..
            } if src1 == src2 => Some(OpKind::Mov {
                dst: *dst,
                src: SrcOperand::Imm(0),
                width: *width,
            }),

            // Shift by zero -> mov src
            OpKind::Shl {
                dst,
                src,
                amount: SrcOperand::Imm(0),
                width,
                ..
            }
            | OpKind::Shr {
                dst,
                src,
                amount: SrcOperand::Imm(0),
                width,
                ..
            }
            | OpKind::Sar {
                dst,
                src,
                amount: SrcOperand::Imm(0),
                width,
                ..
            } => Some(OpKind::Mov {
                dst: *dst,
                src: SrcOperand::Reg(*src),
                width: *width,
            }),

            // Add zero -> mov src1
            OpKind::Add {
                dst,
                src1,
                src2: SrcOperand::Imm(0),
                width,
                ..
            } => Some(OpKind::Mov {
                dst: *dst,
                src: SrcOperand::Reg(*src1),
                width: *width,
            }),

            // Sub zero -> mov src1
            OpKind::Sub {
                dst,
                src1,
                src2: SrcOperand::Imm(0),
                width,
                ..
            } => Some(OpKind::Mov {
                dst: *dst,
                src: SrcOperand::Reg(*src1),
                width: *width,
            }),

            _ => None,
        };

        if let Some(new_kind) = new_kind {
            block.ops[i].kind = new_kind;
            folded += 1;
        }
    }

    folded
}

// ============================================================================
// Dead Code Elimination
// ============================================================================

/// Eliminate dead code.
///
/// Removes operations whose results are never used and have no side effects.
///
/// Returns the number of operations eliminated.
pub fn dead_code_elimination(block: &mut SmirBlock) -> usize {
    // Build use set starting from terminator
    let mut used: HashSet<VReg> = HashSet::new();

    // Terminator uses
    match &block.terminator {
        Terminator::CondBranch { cond, .. } => {
            used.insert(*cond);
        }
        Terminator::IndirectBranch { target, .. } => {
            used.insert(*target);
        }
        Terminator::IndirectBranchMem { addr, .. } => {
            used.extend(addr.regs());
        }
        Terminator::Return { values } => {
            for v in values {
                used.insert(*v);
            }
        }
        Terminator::Switch { index, .. } => {
            used.insert(*index);
        }
        Terminator::Call { target, args, .. } => {
            if let CallTarget::Indirect(reg) = target {
                used.insert(*reg);
            }
            if let CallTarget::IndirectMem(addr) = target {
                used.extend(addr.regs());
            }
            for arg in args {
                used.insert(*arg);
            }
        }
        Terminator::TailCall { target, args, .. } => {
            if let CallTarget::Indirect(reg) = target {
                used.insert(*reg);
            }
            if let CallTarget::IndirectMem(addr) = target {
                used.extend(addr.regs());
            }
            for arg in args {
                used.insert(*arg);
            }
        }
        _ => {}
    }

    // Backward pass to find all used values
    for op in block.ops.iter().rev() {
        let dests = op.kind.dests();
        let is_used = dests.is_empty() || dests.iter().any(|d| used.contains(d));

        if is_used || op.kind.has_side_effects() {
            for src in op.kind.source_vregs() {
                used.insert(src);
            }
        }
    }

    // Count ops before removal
    let before = block.ops.len();

    // Remove unused ops
    block.ops.retain(|op| {
        let dests = op.kind.dests();
        dests.is_empty() || dests.iter().any(|d| used.contains(d)) || op.kind.has_side_effects()
    });

    before - block.ops.len()
}

// ============================================================================
// Strength Reduction
// ============================================================================

/// Strength reduction transformations.
///
/// Replaces expensive operations with cheaper equivalents:
/// - Multiply by power of 2 -> shift left
/// - Unsigned divide by power of 2 -> shift right
///
/// Returns the number of reductions applied.
pub fn strength_reduction(block: &mut SmirBlock) -> usize {
    let mut reductions = 0;

    for op in &mut block.ops {
        let new_kind = match &op.kind {
            // Multiply by power of 2 -> shift
            OpKind::MulU {
                dst_lo,
                src1,
                src2: SrcOperand::Imm(imm),
                width,
                ..
            }
            | OpKind::MulS {
                dst_lo,
                src1,
                src2: SrcOperand::Imm(imm),
                width,
                ..
            } if *imm > 0 && (*imm as u64).is_power_of_two() => {
                let shift = (*imm as u64).trailing_zeros() as i64;
                Some(OpKind::Shl {
                    dst: *dst_lo,
                    src: *src1,
                    amount: SrcOperand::Imm(shift),
                    width: *width,
                    flags: FlagUpdate::None,
                })
            }

            // Unsigned divide by power of 2 -> shift right
            OpKind::DivU {
                quot,
                src1,
                src2: SrcOperand::Imm(imm),
                width,
                ..
            } if *imm > 0 && (*imm as u64).is_power_of_two() => {
                let shift = (*imm as u64).trailing_zeros() as i64;
                Some(OpKind::Shr {
                    dst: *quot,
                    src: *src1,
                    amount: SrcOperand::Imm(shift),
                    width: *width,
                    flags: FlagUpdate::None,
                })
            }

            _ => None,
        };

        if let Some(new_kind) = new_kind {
            op.kind = new_kind;
            reductions += 1;
        }
    }

    reductions
}

// ============================================================================
// Block Merging
// ============================================================================

/// Merge adjacent blocks with unconditional jumps.
///
/// When a block ends with an unconditional branch to a block with only one
/// predecessor, merge them together.
///
/// Returns the number of blocks merged.
pub fn block_merging(func: &mut SmirFunction) -> usize {
    if func.blocks.len() < 2 {
        return 0;
    }

    // Build predecessor count
    let mut pred_count: HashMap<BlockId, usize> = HashMap::new();

    for block in &func.blocks {
        match &block.terminator {
            Terminator::Branch { target } => {
                *pred_count.entry(*target).or_default() += 1;
            }
            Terminator::CondBranch {
                true_target,
                false_target,
                ..
            } => {
                *pred_count.entry(*true_target).or_default() += 1;
                *pred_count.entry(*false_target).or_default() += 1;
            }
            Terminator::Switch {
                targets, default, ..
            } => {
                for target in targets {
                    *pred_count.entry(*target).or_default() += 1;
                }
                *pred_count.entry(*default).or_default() += 1;
            }
            _ => {}
        }
    }

    // Find blocks to merge
    let mut merge_pairs: Vec<(BlockId, BlockId)> = Vec::new();

    for block in &func.blocks {
        if let Terminator::Branch { target } = &block.terminator {
            // Only merge if target has single predecessor
            if pred_count.get(target) == Some(&1) && *target != block.id {
                merge_pairs.push((block.id, *target));
            }
        }
    }

    let merged_count = merge_pairs.len();

    // Perform merges
    for (from, to) in merge_pairs {
        let from_idx = func.blocks.iter().position(|b| b.id == from);
        let to_idx = func.blocks.iter().position(|b| b.id == to);

        if let (Some(from_idx), Some(to_idx)) = (from_idx, to_idx) {
            // Get ops and terminator from target block
            let to_ops = func.blocks[to_idx].ops.clone();
            let to_term = func.blocks[to_idx].terminator.clone();

            // Append to source block
            func.blocks[from_idx].ops.extend(to_ops);
            func.blocks[from_idx].terminator = to_term;

            // Mark target block for removal
            func.blocks[to_idx].ops.clear();
            func.blocks[to_idx].terminator = Terminator::Unreachable;
        }
    }

    // Remove empty blocks (but keep entry block)
    func.blocks.retain(|b| {
        b.id == func.entry || !b.ops.is_empty() || !matches!(b.terminator, Terminator::Unreachable)
    });

    merged_count
}

// ============================================================================
// Redundant Load Elimination
// ============================================================================

/// Eliminate redundant loads.
///
/// When a value is loaded from memory and the same address is loaded again
/// (without an intervening store), replace the second load with a move.
///
/// Returns the number of redundant loads eliminated.
pub fn redundant_load_elimination(func: &mut SmirFunction) -> usize {
    let mut eliminated = 0;

    for block in &mut func.blocks {
        eliminated += redundant_load_elimination_block(block);
    }

    eliminated
}

// ============================================================================
// Vector Alignment Inference
// ============================================================================

/// Infer vector alignment hints for VLoad/VStore ops.
pub fn vector_alignment_inference(func: &mut SmirFunction) -> usize {
    let mut inferred = 0;

    for block in &mut func.blocks {
        inferred += vector_alignment_inference_block(block);
    }

    inferred
}

fn vector_alignment_inference_block(block: &mut SmirBlock) -> usize {
    let mut inferred = 0;
    let mut alignments = seed_x86_alignments();

    for op in &mut block.ops {
        inferred += apply_vec_align_hint(op, &alignments);
        update_pointer_alignment(op, &mut alignments);
    }

    inferred
}

fn seed_x86_alignments() -> HashMap<VReg, usize> {
    let mut alignments = HashMap::new();
    alignments.insert(VReg::Arch(ArchReg::X86(X86Reg::Rsp)), 16);
    alignments.insert(VReg::Arch(ArchReg::X86(X86Reg::Rbp)), 16);
    alignments
}

fn apply_vec_align_hint(op: &mut SmirOp, alignments: &HashMap<VReg, usize>) -> usize {
    let (addr, width) = match &op.kind {
        OpKind::VLoad { addr, width, .. } | OpKind::VStore { addr, width, .. } => (addr, width),
        _ => return 0,
    };

    match op.x86_hint {
        None | Some(X86OpHint::VecAlign(X86VecAlign::Unaligned)) => {}
        _ => return 0,
    }

    let required = vec_width_bytes(*width);
    if let Some(alignment) = address_alignment(addr, alignments) {
        if alignment >= required {
            op.x86_hint = Some(X86OpHint::VecAlign(X86VecAlign::Aligned));
            return 1;
        }
    }

    0
}

fn update_pointer_alignment(op: &SmirOp, alignments: &mut HashMap<VReg, usize>) {
    let mut computed = HashMap::new();

    match &op.kind {
        OpKind::Mov { dst, src, width } if *width == OpWidth::W64 => {
            if let Some(src_reg) = src.as_reg() {
                if let Some(&alignment) = alignments.get(&src_reg) {
                    computed.insert(*dst, alignment);
                }
            } else if let Some(imm) = src.as_imm() {
                if imm >= 0 {
                    computed.insert(*dst, alignment_from_addr(imm as u64));
                }
            }
        }
        OpKind::Add {
            dst,
            src1,
            src2,
            width,
            ..
        }
        | OpKind::Sub {
            dst,
            src1,
            src2,
            width,
            ..
        } if *width == OpWidth::W64 => {
            if let Some(&src_align) = alignments.get(src1) {
                if let Some(imm) = src2.as_imm() {
                    computed.insert(*dst, gcd(src_align, imm.unsigned_abs() as usize));
                } else if let Some(src2_reg) = src2.as_reg() {
                    if let Some(&src2_align) = alignments.get(&src2_reg) {
                        computed.insert(*dst, gcd(src_align, src2_align));
                    }
                }
            }
        }
        OpKind::Shl {
            dst,
            src,
            amount,
            width,
            ..
        } if *width == OpWidth::W64 => {
            if let (Some(&src_align), Some(shift)) = (alignments.get(src), amount.as_imm()) {
                if let Ok(shift) = u32::try_from(shift) {
                    if let Some(alignment) = src_align.checked_shl(shift) {
                        computed.insert(*dst, alignment);
                    }
                }
            }
        }
        OpKind::And {
            dst,
            src1,
            src2,
            width,
            ..
        } if *width == OpWidth::W64 => {
            if let Some(imm) = src2.as_imm() {
                let mask = imm as u64;
                let mut alignment = if mask == 0 {
                    1
                } else {
                    1usize << mask.trailing_zeros()
                };
                if let Some(&src_align) = alignments.get(src1) {
                    alignment = alignment.max(src_align);
                }
                computed.insert(*dst, alignment);
            }
        }
        OpKind::CMove {
            dst, src, width, ..
        } if *width == OpWidth::W64 => {
            if let (Some(&dst_align), Some(&src_align)) = (alignments.get(dst), alignments.get(src))
            {
                computed.insert(*dst, gcd(dst_align, src_align));
            }
        }
        OpKind::Select {
            dst,
            src_true,
            src_false,
            width,
            ..
        } if *width == OpWidth::W64 => {
            if let (Some(&a), Some(&b)) = (alignments.get(src_true), alignments.get(src_false)) {
                computed.insert(*dst, gcd(a, b));
            }
        }
        OpKind::Lea { dst, addr } => {
            if let Some(alignment) = address_alignment(addr, alignments) {
                computed.insert(*dst, alignment);
            }
        }
        _ => {}
    }

    for dst in op.kind.dests() {
        if let Some(&alignment) = computed.get(&dst) {
            alignments.insert(dst, alignment);
        } else {
            alignments.remove(&dst);
        }
    }
}

fn vec_width_bytes(width: VecWidth) -> usize {
    match width {
        VecWidth::V64 => 8,
        VecWidth::V128 => 16,
        VecWidth::V256 => 32,
        VecWidth::V512 => 64,
    }
}

fn address_alignment(addr: &Address, alignments: &HashMap<VReg, usize>) -> Option<usize> {
    match addr {
        Address::Direct(base) => alignments.get(base).copied(),
        Address::BaseOffset { base, offset, .. } => {
            let base_align = alignments.get(base).copied()?;
            Some(gcd(base_align, offset.unsigned_abs() as usize))
        }
        Address::BaseIndexScale {
            base,
            index,
            scale,
            disp,
            ..
        } => {
            let index_align = alignments.get(index).copied()?;
            let scaled = index_align.checked_mul(*scale as usize)?;
            let mut alignment = scaled;
            if let Some(base_reg) = base {
                let base_align = alignments.get(base_reg).copied()?;
                alignment = gcd(alignment, base_align);
            }
            alignment = gcd(alignment, (*disp as i64).unsigned_abs() as usize);
            Some(alignment)
        }
        Address::PcRel { offset, base, .. } => {
            let base_addr = match base {
                Some(base_addr) => *base_addr as i128,
                None => return None,
            };
            let target = base_addr + *offset as i128;
            if target < 0 {
                None
            } else {
                Some(alignment_from_addr(target as u64))
            }
        }
        Address::Absolute(addr) => Some(alignment_from_addr(*addr)),
        _ => None,
    }
}

fn alignment_from_addr(addr: u64) -> usize {
    if addr == 0 {
        return 1;
    }
    1usize << addr.trailing_zeros()
}

fn gcd(mut a: usize, mut b: usize) -> usize {
    if a == 0 {
        return b;
    }
    if b == 0 {
        return a;
    }
    while b != 0 {
        let tmp = a % b;
        a = b;
        b = tmp;
    }
    a
}

fn redundant_load_elimination_block(block: &mut SmirBlock) -> usize {
    // Track what's currently in registers from memory
    // Key: (base_vreg, offset, width), Value: VReg holding the loaded value
    let mut mem_to_reg: HashMap<(Option<VReg>, i64, MemWidth), VReg> = HashMap::new();
    let mut eliminated = 0;

    let mut new_ops = Vec::new();

    for op in &block.ops {
        match &op.kind {
            OpKind::Load {
                dst,
                addr,
                width,
                sign,
            } => {
                let key = address_key(addr, *width);
                if let Some(&existing) = mem_to_reg.get(&key) {
                    // Replace load with move
                    new_ops.push(SmirOp {
                        id: op.id,
                        guest_pc: op.guest_pc,
                        kind: OpKind::Mov {
                            dst: *dst,
                            src: SrcOperand::Reg(existing),
                            width: width.to_op_width().unwrap_or(OpWidth::W64),
                        },
                        x86_hint: None,
                    });
                    eliminated += 1;
                } else {
                    mem_to_reg.insert(key, *dst);
                    new_ops.push(op.clone());
                }
            }

            OpKind::Store { addr, width, .. } => {
                // Invalidate any loads from this address
                let key = address_key(addr, *width);
                mem_to_reg.remove(&key);

                // Conservatively, also invalidate overlapping addresses
                // (For now, just invalidate all on any store for simplicity)
                // A more sophisticated version would track precise aliasing
                mem_to_reg.clear();

                new_ops.push(op.clone());
            }

            OpKind::AtomicStore { .. }
            | OpKind::AtomicRmw { .. }
            | OpKind::Cas { .. }
            | OpKind::StoreExclusive { .. }
            | OpKind::Fence { .. } => {
                // Memory operations invalidate all cached loads
                mem_to_reg.clear();
                new_ops.push(op.clone());
            }

            OpKind::IoIn { .. } | OpKind::IoOut { .. } => {
                // I/O has side effects; be conservative
                mem_to_reg.clear();
                new_ops.push(op.clone());
            }

            OpKind::Syscall { .. } => {
                // System calls may have memory side effects
                mem_to_reg.clear();
                new_ops.push(op.clone());
            }

            _ => {
                new_ops.push(op.clone());
            }
        }
    }

    block.ops = new_ops;
    eliminated
}

/// Create a key for memory address tracking
fn address_key(addr: &Address, width: MemWidth) -> (Option<VReg>, i64, MemWidth) {
    match addr {
        Address::Direct(r) => (Some(*r), 0, width),
        Address::BaseOffset { base, offset, .. } => (Some(*base), *offset, width),
        Address::Absolute(a) => (None, *a as i64, width),
        // For complex addresses, don't track (return unique key that won't match)
        _ => (None, i64::MIN, width),
    }
}

// ============================================================================
// OpKind Helper Methods for Optimization
// ============================================================================

impl OpKind {
    /// Get mutable reference to flag update field
    pub fn flags_written_mut(&mut self) -> Option<&mut FlagUpdate> {
        match self {
            OpKind::Add { flags, .. }
            | OpKind::Sub { flags, .. }
            | OpKind::Adc { flags, .. }
            | OpKind::Sbb { flags, .. }
            | OpKind::Neg { flags, .. }
            | OpKind::Inc { flags, .. }
            | OpKind::Dec { flags, .. }
            | OpKind::And { flags, .. }
            | OpKind::Or { flags, .. }
            | OpKind::Xor { flags, .. }
            | OpKind::AndNot { flags, .. }
            | OpKind::Shl { flags, .. }
            | OpKind::Shr { flags, .. }
            | OpKind::Sar { flags, .. }
            | OpKind::Shld { flags, .. }
            | OpKind::Shrd { flags, .. }
            | OpKind::Rol { flags, .. }
            | OpKind::Ror { flags, .. }
            | OpKind::Bsf { flags, .. }
            | OpKind::Bsr { flags, .. }
            | OpKind::MulU { flags, .. }
            | OpKind::MulS { flags, .. } => Some(flags),
            _ => None,
        }
    }

    /// Get the flags written by this operation
    pub fn flags_written(&self) -> FlagSet {
        match self {
            OpKind::Add { flags, .. }
            | OpKind::Sub { flags, .. }
            | OpKind::Adc { flags, .. }
            | OpKind::Sbb { flags, .. }
            | OpKind::Neg { flags, .. }
            | OpKind::Inc { flags, .. }
            | OpKind::Dec { flags, .. }
            | OpKind::And { flags, .. }
            | OpKind::Or { flags, .. }
            | OpKind::Xor { flags, .. }
            | OpKind::AndNot { flags, .. }
            | OpKind::Shl { flags, .. }
            | OpKind::Shr { flags, .. }
            | OpKind::Sar { flags, .. }
            | OpKind::Shld { flags, .. }
            | OpKind::Shrd { flags, .. }
            | OpKind::Rol { flags, .. }
            | OpKind::Ror { flags, .. }
            | OpKind::Bsf { flags, .. }
            | OpKind::Bsr { flags, .. }
            | OpKind::MulU { flags, .. }
            | OpKind::MulS { flags, .. } => flags.as_set(),

            // Cmp and Test always update flags
            OpKind::Cmp { .. } | OpKind::Test { .. } => FlagSet::NZCV,

            // Bit test updates CF
            OpKind::Bt { .. } => FlagSet::CF,

            OpKind::SetCF { .. } | OpKind::CmcCF => FlagSet::CF,

            _ => FlagSet::EMPTY,
        }
    }

    /// Get the flags read by this operation
    pub fn flags_read(&self) -> FlagSet {
        match self {
            // Add/Sub with carry read CF
            OpKind::Adc { .. } | OpKind::Sbb { .. } => FlagSet::CF,

            // Conditional move reads flags based on condition
            OpKind::CMove { cond, .. } | OpKind::SetCC { cond, .. } => {
                FlagState::required_flags(*cond)
            }

            // TestCondition reads flags
            OpKind::TestCondition { cond, .. } => FlagState::required_flags(*cond),

            // Complement carry reads CF
            OpKind::CmcCF => FlagSet::CF,

            // ReadFlags reads all flags
            OpKind::ReadFlags { .. } => FlagSet::ALL_X86,

            _ => FlagSet::EMPTY,
        }
    }

    /// Get source registers used by this operation
    pub fn source_vregs(&self) -> Vec<VReg> {
        let mut result = Vec::new();

        match self {
            OpKind::Add { src1, src2, .. }
            | OpKind::Sub { src1, src2, .. }
            | OpKind::Adc { src1, src2, .. }
            | OpKind::Sbb { src1, src2, .. }
            | OpKind::And { src1, src2, .. }
            | OpKind::Or { src1, src2, .. }
            | OpKind::Xor { src1, src2, .. }
            | OpKind::AndNot { src1, src2, .. }
            | OpKind::Cmp { src1, src2, .. }
            | OpKind::Test { src1, src2, .. } => {
                result.push(*src1);
                if let SrcOperand::Reg(r) = src2 {
                    result.push(*r);
                }
            }

            OpKind::Shld {
                dst: src1,
                src: src3,
                amount: src2,
                ..
            }
            | OpKind::Shrd {
                dst: src1,
                src: src3,
                amount: src2,
                ..
            } => {
                result.push(*src1);
                result.push(*src3);
                if let SrcOperand::Reg(r) = src2 {
                    result.push(*r);
                }
            }

            OpKind::MulU { src1, src2, .. }
            | OpKind::MulS { src1, src2, .. }
            | OpKind::DivU { src1, src2, .. }
            | OpKind::DivS { src1, src2, .. } => {
                result.push(*src1);
                if let SrcOperand::Reg(r) = src2 {
                    result.push(*r);
                }
            }

            OpKind::MulAdd {
                acc, src1, src2, ..
            }
            | OpKind::MulSub {
                acc, src1, src2, ..
            } => {
                result.push(*acc);
                result.push(*src1);
                result.push(*src2);
            }

            OpKind::Neg { src, .. }
            | OpKind::Inc { src, .. }
            | OpKind::Dec { src, .. }
            | OpKind::Not { src, .. }
            | OpKind::Cwd { src, .. }
            | OpKind::Bsf { src, .. }
            | OpKind::Bsr { src, .. }
            | OpKind::Clz { src, .. }
            | OpKind::Ctz { src, .. }
            | OpKind::Popcnt { src, .. }
            | OpKind::Bswap { src, .. }
            | OpKind::Rbit { src, .. } => {
                result.push(*src);
            }

            OpKind::Leave => {
                result.push(VReg::Arch(ArchReg::X86(X86Reg::Rbp)));
            }

            OpKind::Shl { src, amount, .. }
            | OpKind::Shr { src, amount, .. }
            | OpKind::Sar { src, amount, .. }
            | OpKind::Rol { src, amount, .. }
            | OpKind::Ror { src, amount, .. } => {
                result.push(*src);
                if let SrcOperand::Reg(r) = amount {
                    result.push(*r);
                }
            }

            // Bidirectional shift: both `src` and `amount` are SrcOperand.
            OpKind::BidirShift { src, amount, .. } => {
                if let SrcOperand::Reg(r) = src {
                    result.push(*r);
                }
                if let SrcOperand::Reg(r) = amount {
                    result.push(*r);
                }
            }

            // Saturating clamp: `src` is a SrcOperand (register or immediate).
            OpKind::SatN { src, .. } => {
                if let SrcOperand::Reg(r) = src {
                    result.push(*r);
                }
            }

            OpKind::Bt { src, index, .. }
            | OpKind::Bts { src, index, .. }
            | OpKind::Btr { src, index, .. }
            | OpKind::Btc { src, index, .. } => {
                result.push(*src);
                if let SrcOperand::Reg(r) = index {
                    result.push(*r);
                }
            }

            OpKind::Bfx { src, .. } => {
                result.push(*src);
            }

            OpKind::Bfi { src, dst_in, .. } => {
                result.push(*src);
                result.push(*dst_in);
            }

            OpKind::Mov { src, .. } => {
                if let SrcOperand::Reg(r) = src {
                    result.push(*r);
                }
            }

            OpKind::CMove { src, .. } => {
                result.push(*src);
            }

            OpKind::Select {
                cond,
                src_true,
                src_false,
                ..
            } => {
                result.push(*cond);
                result.push(*src_true);
                result.push(*src_false);
            }

            OpKind::ZeroExtend { src, .. }
            | OpKind::SignExtend { src, .. }
            | OpKind::Truncate { src, .. } => {
                result.push(*src);
            }

            OpKind::Lea { addr, .. } => {
                result.extend(addr.regs());
            }

            OpKind::Xchg { reg1, reg2, .. } => {
                result.push(*reg1);
                result.push(*reg2);
            }

            OpKind::Load { addr, .. }
            | OpKind::AtomicLoad { addr, .. }
            | OpKind::LoadExclusive { addr, .. } => {
                result.extend(addr.regs());
            }

            OpKind::Store { src, addr, .. } | OpKind::AtomicStore { src, addr, .. } => {
                result.push(*src);
                result.extend(addr.regs());
            }

            // Predicated load: reads the predicate `cond` and the address base
            // register(s). The `dst` is conditionally written (in dests()).
            OpKind::PredLoad { cond, addr, .. } => {
                result.push(*cond);
                result.extend(addr.regs());
            }

            // Predicated store: reads the predicate `cond`, the source operand
            // (when a register), and the address base register(s).
            OpKind::PredStore {
                src, cond, addr, ..
            } => {
                result.push(*cond);
                if let SrcOperand::Reg(r) = src {
                    result.push(*r);
                }
                result.extend(addr.regs());
            }

            OpKind::RepStos {
                dst, src, count, ..
            } => {
                result.push(*dst);
                result.push(*src);
                result.push(*count);
            }

            OpKind::RepMovs {
                dst, src, count, ..
            } => {
                result.push(*dst);
                result.push(*src);
                result.push(*count);
            }

            OpKind::LoadPair { addr, .. } => {
                result.extend(addr.regs());
            }

            OpKind::StorePair {
                src1, src2, addr, ..
            } => {
                result.push(*src1);
                result.push(*src2);
                result.extend(addr.regs());
            }

            OpKind::AtomicRmw { addr, src, .. } => {
                result.extend(addr.regs());
                result.push(*src);
            }

            OpKind::Cas {
                addr,
                expected,
                new_val,
                ..
            } => {
                result.extend(addr.regs());
                result.push(*expected);
                result.push(*new_val);
            }

            OpKind::StoreExclusive { src, addr, .. } => {
                result.push(*src);
                result.extend(addr.regs());
            }

            OpKind::IoIn { port, .. } => {
                result.push(*port);
            }

            OpKind::IoOut { port, value, .. } => {
                result.push(*port);
                result.push(*value);
            }

            OpKind::WriteFlags { src } | OpKind::WriteSysReg { src, .. } => {
                result.push(*src);
            }

            OpKind::Syscall { num, args } => {
                result.push(*num);
                result.extend(args.iter().copied());
            }

            // FP operations
            OpKind::FAdd { src1, src2, .. }
            | OpKind::FSub { src1, src2, .. }
            | OpKind::FMul { src1, src2, .. }
            | OpKind::FDiv { src1, src2, .. }
            | OpKind::FMin { src1, src2, .. }
            | OpKind::FMax { src1, src2, .. }
            | OpKind::FCmp { src1, src2, .. }
            | OpKind::HexFp { src1, src2, .. }
            | OpKind::HexFpRecip { src1, src2, .. } => {
                result.push(*src1);
                result.push(*src2);
            }

            OpKind::FFma {
                src1, src2, src3, ..
            }
            | OpKind::HexFp3 {
                src1, src2, src3, ..
            } => {
                result.push(*src1);
                result.push(*src2);
                result.push(*src3);
            }

            OpKind::FAbs { src, .. }
            | OpKind::FNeg { src, .. }
            | OpKind::FSqrt { src, .. }
            | OpKind::FConvert { src, .. }
            | OpKind::IntToFp { src, .. }
            | OpKind::FpToInt { src, .. }
            | OpKind::FRound { src, .. } => {
                result.push(*src);
            }

            // Vector operations
            OpKind::VAdd { src1, src2, .. }
            | OpKind::VSub { src1, src2, .. }
            | OpKind::VMax { src1, src2, .. }
            | OpKind::VMul { src1, src2, .. }
            | OpKind::VLane { src1, src2, .. }
            | OpKind::VAnd { src1, src2, .. }
            | OpKind::VOr { src1, src2, .. }
            | OpKind::VXor { src1, src2, .. }
            | OpKind::VCmp { src1, src2, .. } => {
                result.push(*src1);
                result.push(*src2);
            }

            OpKind::VShift { src, amount, .. } => {
                result.push(*src);
                if let SrcOperand::Reg(r) = amount {
                    result.push(*r);
                }
            }

            OpKind::VWidenMul { src1, src2, dst_lo, dst_hi, acc, .. }
            | OpKind::VWidenAddSub { src1, src2, dst_lo, dst_hi, acc, .. } => {
                result.push(*src1);
                result.push(*src2);
                if *acc {
                    // accumulating form reads the existing destination pair
                    result.push(*dst_lo);
                    result.push(*dst_hi);
                }
            }

            OpKind::VLaneUnary { src, .. } => {
                result.push(*src);
            }

            OpKind::VNavg { src1, src2, .. } => {
                result.push(*src1);
                result.push(*src2);
            }

            OpKind::VShiftAcc { src, amount, dst, .. } => {
                result.push(*src);
                // shift-accumulate reads the existing destination lane
                result.push(*dst);
                if let SrcOperand::Reg(r) = amount {
                    result.push(*r);
                }
            }

            OpKind::VPairReduceMul { src_lo, src_hi, src2, dst_lo, dst_hi, acc, .. }
            | OpKind::VSlideReduceMul { src_lo, src_hi, src2, dst_lo, dst_hi, acc, .. }
            | OpKind::VRotReduceMulPair { src_lo, src_hi, src2, dst_lo, dst_hi, acc, .. } => {
                result.push(*src_lo);
                result.push(*src_hi);
                result.push(*src2);
                if *acc {
                    result.push(*dst_lo);
                    result.push(*dst_hi);
                }
            }

            OpKind::VPairPairReduceMul { src_lo, src_hi, src2_lo, src2_hi, .. } => {
                result.push(*src_lo);
                result.push(*src_hi);
                result.push(*src2_lo);
                result.push(*src2_hi);
            }

            OpKind::VReduceMul { src1, src2, dst, acc, .. }
            | OpKind::VMulEvenWiden { src1, src2, dst, acc, .. }
            | OpKind::VMulSubLane { src1, src2, dst, acc, .. } => {
                result.push(*src1);
                result.push(*src2);
                if *acc {
                    result.push(*dst);
                }
            }

            OpKind::VWidenExt { src, .. } => {
                result.push(*src);
            }

            OpKind::VLut { src_idx, table, sel, dst, oracc, .. } => {
                result.push(*src_idx);
                result.push(*table);
                if let SrcOperand::Reg(r) = sel {
                    result.push(*r);
                }
                if *oracc {
                    result.push(*dst);
                }
            }

            OpKind::VLut16 { src_idx, table, sel, dst_lo, dst_hi, oracc, .. } => {
                result.push(*src_idx);
                result.push(*table);
                if let SrcOperand::Reg(r) = sel {
                    result.push(*r);
                }
                if *oracc {
                    result.push(*dst_lo);
                    result.push(*dst_hi);
                }
            }

            OpKind::VShuffVdd { src_lo, src_hi, amount, .. }
            | OpKind::VDealVdd { src_lo, src_hi, amount, .. } => {
                result.push(*src_lo);
                result.push(*src_hi);
                if let SrcOperand::Reg(r) = amount {
                    result.push(*r);
                }
            }

            OpKind::VShuffleEOPair { src1, src2, .. } => {
                result.push(*src1);
                result.push(*src2);
            }

            // In-place dual-register shuffle/deal reads AND writes both Vy and Vx.
            OpKind::VShuffleDeal { dst_y, dst_x, amount, .. } => {
                result.push(*dst_y);
                result.push(*dst_x);
                if let SrcOperand::Reg(r) = amount {
                    result.push(*r);
                }
            }

            // vunpacko OR-accumulates the source into the existing dst pair.
            OpKind::VUnpackOAcc { src, dst_lo, dst_hi, .. } => {
                result.push(*src);
                result.push(*dst_lo);
                result.push(*dst_hi);
            }

            OpKind::VInsertWordR { dst, scalar } => {
                // read-modify-write: preserves the other words of dst.
                result.push(*dst);
                result.push(*scalar);
            }

            OpKind::VExtractWord { src, sel, .. } => {
                result.push(*src);
                result.push(*sel);
            }

            OpKind::VLut4 { src, table, .. } => {
                result.push(*src);
                result.push(*table);
            }

            OpKind::VRotr { src, amount, .. } => {
                result.push(*src);
                result.push(*amount);
            }

            OpKind::VAddSubMixedSat { src1, src2, .. } => {
                result.push(*src1);
                result.push(*src2);
            }

            OpKind::VSetPredQ { scalar, .. } => {
                result.push(*scalar);
            }

            OpKind::VShuffEqQ { src1, src2, .. } => {
                result.push(*src1);
                result.push(*src2);
            }

            // vmpa(Vx, Vu, Rtt):sat reads the dst (Vx) accumulator, Vu, and Rtt.
            OpKind::VMpaHhSat { dst, src, table, .. } => {
                result.push(*dst);
                result.push(*src);
                result.push(*table);
            }

            // vmpyhsat_acc accumulates into the existing dst pair.
            OpKind::VMpyHsatAcc { dst_lo, dst_hi, src, scalar } => {
                result.push(*dst_lo);
                result.push(*dst_hi);
                result.push(*src);
                result.push(*scalar);
            }

            // vasr_into shifts Vu into the running accumulator pair (read+write).
            OpKind::VAsrInto { dst_lo, dst_hi, src, amount } => {
                result.push(*dst_lo);
                result.push(*dst_hi);
                result.push(*src);
                result.push(*amount);
            }

            OpKind::V6Mpy { src_lo, src_hi, src2_lo, src2_hi, dst_lo, dst_hi, acc, .. } => {
                result.push(*src_lo);
                result.push(*src_hi);
                result.push(*src2_lo);
                result.push(*src2_hi);
                if *acc {
                    result.push(*dst_lo);
                    result.push(*dst_hi);
                }
            }

            OpKind::VDelta { src, control, .. } => {
                result.push(*src);
                result.push(*control);
            }

            OpKind::VPack { src1, src2, .. }
            | OpKind::VPackSat { src1, src2, .. }
            | OpKind::VShuffleEO { src1, src2, .. }
            | OpKind::VDealB4W { src1, src2, .. }
            | OpKind::VMulSubLaneFrac { src1, src2, .. }
            | OpKind::VMulSubLaneSh { src1, src2, .. }
            | OpKind::VMulShiftSat { src1, src2, .. } => {
                result.push(*src1);
                result.push(*src2);
            }

            OpKind::VMulWord64Pair { src1, src2, dst_lo, dst_hi, mode } => {
                result.push(*src1);
                result.push(*src2);
                // mode 1 (vmpyowh_64_acc) reads the existing dst pair.
                if *mode == 1 {
                    result.push(*dst_lo);
                    result.push(*dst_hi);
                }
            }

            OpKind::VShuffle2 { src, .. } => {
                result.push(*src);
            }

            OpKind::VAlign { src1, src2, amount, .. } => {
                result.push(*src1);
                result.push(*src2);
                if let SrcOperand::Reg(r) = amount {
                    result.push(*r);
                }
            }

            OpKind::VShiftV { src, amount, .. } => {
                result.push(*src);
                result.push(*amount);
            }

            OpKind::VNarrowShiftSat { src_lo, src_hi, amount, .. } => {
                result.push(*src_lo);
                result.push(*src_hi);
                if let SrcOperand::Reg(r) = amount {
                    result.push(*r);
                }
            }

            OpKind::VSatDW { src_lo, src_hi, .. } => {
                result.push(*src_lo);
                result.push(*src_hi);
            }

            OpKind::VNarrowShiftV { src_lo, src_hi, amount, .. } => {
                result.push(*src_lo);
                result.push(*src_hi);
                result.push(*amount);
            }

            OpKind::VCmpToQ { src1, src2, .. } => {
                result.push(*src1);
                result.push(*src2);
            }

            OpKind::VBlend { mask_q, src_true, src_false, .. } => {
                result.push(*mask_q);
                result.push(*src_true);
                result.push(*src_false);
            }

            OpKind::VMaskZero { mask_q, src, dst, oracc, .. } => {
                result.push(*mask_q);
                result.push(*src);
                // oracc (vandqrt_acc) OR-accumulates into the existing dst.
                if *oracc {
                    result.push(*dst);
                }
            }

            OpKind::VQFromVAndR { src1, src2, dst, oracc } => {
                result.push(*src1);
                result.push(*src2);
                // oracc (vandvrt_acc) OR-accumulates into the existing dst Q.
                if *oracc {
                    result.push(*dst);
                }
            }

            // Q-predicated conditional add/sub: dst is read-modify-written.
            OpKind::VLaneCond { dst, src, mask_q, .. } => {
                result.push(*dst);
                result.push(*src);
                result.push(*mask_q);
            }

            // Carry add/sub: reads both vectors; reads the carry Q when it has a
            // carry-in (carry / carrysat forms).
            OpKind::VCarry { src1, src2, q_inout, has_cin, .. } => {
                result.push(*src1);
                result.push(*src2);
                if *has_cin {
                    result.push(*q_inout);
                }
            }

            OpKind::VSwap { mask_q, src1, src2, .. } => {
                result.push(*mask_q);
                result.push(*src1);
                result.push(*src2);
            }

            // Scalar-predicate-gated move/combine: when the gate is false the
            // dest(s) keep their prior value, so they are read; also reads the
            // predicate and the candidate sources.
            OpKind::VCondMove { dst_lo, dst_hi, src_lo, src_hi, pred, .. } => {
                result.push(*pred);
                result.push(*src_lo);
                result.push(*dst_lo);
                if let Some(hi) = dst_hi {
                    result.push(*src_hi);
                    result.push(*hi);
                }
            }

            OpKind::VPrefixSumQ { mask_q, .. } => {
                result.push(*mask_q);
            }

            // The histogram family read-modify-writes the WHOLE V0..V31 file and
            // reads the input vector from memory (the `.tmp` load's address) plus
            // the q-mask for the q-forms.
            OpKind::VHist { input, mask_q, use_q, .. } => {
                result.extend(input.regs());
                if *use_q {
                    result.push(*mask_q);
                }
                for n in 0..32u8 {
                    result.push(VReg::Arch(ArchReg::Hexagon(HexagonReg::V(n))));
                }
            }

            OpKind::VMov { src, .. } | OpKind::VBroadcast { scalar: src, .. } => {
                result.push(*src);
            }

            OpKind::VInsertLane { vec, scalar, .. } => {
                result.push(*vec);
                result.push(*scalar);
            }

            OpKind::VExtractLane { vec, .. } => {
                result.push(*vec);
            }

            OpKind::VShuffle {
                src1,
                src2,
                indices,
                ..
            } => {
                result.push(*src1);
                if let Some(s2) = src2 {
                    result.push(*s2);
                }
                result.push(*indices);
            }

            OpKind::VLoad { addr, .. } => {
                result.extend(addr.regs());
            }

            OpKind::VStore { src, addr, .. } => {
                result.push(*src);
                result.extend(addr.regs());
            }

            // Operations with no source registers
            OpKind::ReadFlags { .. }
            | OpKind::SetCF { .. }
            | OpKind::SetDF { .. }
            | OpKind::CmcCF
            | OpKind::MaterializeFlags
            | OpKind::TestCondition { .. }
            | OpKind::SetCC { .. }
            | OpKind::ClearExclusive
            | OpKind::Prefetch { .. }
            | OpKind::Fence { .. }
            | OpKind::IoIn { .. }
            | OpKind::IoOut { .. }
            | OpKind::Swi { .. }
            | OpKind::ReadSysReg { .. }
            | OpKind::Nop
            | OpKind::Undefined { .. }
            | OpKind::Breakpoint => {}

            // AVX10 operations - extract source registers
            OpKind::VMin { src1, src2, .. } | OpKind::VFma { src1, src2, .. } => {
                result.push(*src1);
                result.push(*src2);
            }

            OpKind::VDotProduct {
                acc, src1, src2, ..
            }
            | OpKind::VDotProductBF16 {
                acc, src1, src2, ..
            } => {
                result.push(*acc);
                result.push(*src1);
                result.push(*src2);
            }

            OpKind::VMultiplyAdd52 {
                dst, src1, src2, ..
            } => {
                result.push(*dst); // dst is also input (accumulator)
                result.push(*src1);
                result.push(*src2);
            }

            OpKind::VPopcnt { src, .. } | OpKind::VCvtBF16ToFP32 { src, .. } => {
                result.push(*src);
            }

            OpKind::VPermute {
                src1,
                src2,
                indices,
                ..
            } => {
                result.push(*src1);
                if let Some(s2) = src2 {
                    result.push(*s2);
                }
                result.push(*indices);
            }

            OpKind::VShuffleBitQM { src, indices, .. } => {
                result.push(*src);
                result.push(*indices);
            }

            OpKind::VCvtFP32ToBF16 { src1, src2, .. } => {
                result.push(*src1);
                if let Some(s2) = src2 {
                    result.push(*s2);
                }
            }

            OpKind::VFP16Arith { src1, src2, .. }
            | OpKind::VMinMax { src1, src2, .. }
            | OpKind::VMpsadbw { src1, src2, .. } => {
                result.push(*src1);
                result.push(*src2);
            }

            OpKind::VCvtFpToIntSat { src, .. } => {
                result.push(*src);
            }

            OpKind::VDotProductExt {
                acc, src1, src2, ..
            } => {
                result.push(*acc);
                result.push(*src1);
                result.push(*src2);
            }

            // Carry-less multiply: src1/src2 are SrcOperands; the `_acc` forms
            // also read the existing dst/dst_hi (XOR target).
            OpKind::ClMul {
                src1, src2, dst, dst_hi, acc, ..
            } => {
                if let SrcOperand::Reg(r) = src1 {
                    result.push(*r);
                }
                if let SrcOperand::Reg(r) = src2 {
                    result.push(*r);
                }
                if *acc {
                    result.push(*dst);
                    if let Some(hi) = dst_hi {
                        result.push(*hi);
                    }
                }
            }

            // Wide complex multiply: reads both halves of the Rss and Rtt pairs.
            OpKind::CmpyW128Sat {
                rss_lo, rss_hi, rtt_lo, rtt_hi, ..
            } => {
                result.push(*rss_lo);
                result.push(*rss_hi);
                result.push(*rtt_lo);
                result.push(*rtt_hi);
            }

            // Register-amount saturating shift: src and amount are SrcOperands.
            OpKind::SatOrigShl { src, amount, .. } => {
                if let SrcOperand::Reg(r) = src {
                    result.push(*r);
                }
                if let SrcOperand::Reg(r) = amount {
                    result.push(*r);
                }
            }
        }

        result
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smir::ops::OpKind;
    use crate::smir::types::{GuestAddr, OpId};

    fn make_op(id: u16, kind: OpKind) -> SmirOp {
        SmirOp::new(OpId(id), 0x1000, kind)
    }

    #[test]
    fn test_dead_flag_elimination() {
        let mut block = SmirBlock::new(BlockId(0), 0x1000);

        let v0 = VReg::virt(0);
        let v1 = VReg::virt(1);
        let v2 = VReg::virt(2);

        // Add with flags that are never used
        block.push_op(make_op(
            0,
            OpKind::Add {
                dst: v0,
                src1: v1,
                src2: SrcOperand::Imm(1),
                width: OpWidth::W64,
                flags: FlagUpdate::All,
            },
        ));

        // Another add with flags
        block.push_op(make_op(
            1,
            OpKind::Add {
                dst: v2,
                src1: v0,
                src2: SrcOperand::Imm(2),
                width: OpWidth::W64,
                flags: FlagUpdate::All,
            },
        ));

        block.set_terminator(Terminator::Return { values: vec![v2] });

        let eliminated = dead_flag_elimination(&mut block);

        // Both flag updates should be eliminated since no flags are read
        assert_eq!(eliminated, 2);

        // Check flags are now None
        for op in &block.ops {
            if let OpKind::Add { flags, .. } = &op.kind {
                assert_eq!(*flags, FlagUpdate::None);
            }
        }
    }

    #[test]
    fn test_constant_propagation() {
        let mut block = SmirBlock::new(BlockId(0), 0x1000);

        let v0 = VReg::virt(0);
        let v1 = VReg::virt(1);
        let v2 = VReg::virt(2);

        // mov v0, 10
        block.push_op(make_op(
            0,
            OpKind::Mov {
                dst: v0,
                src: SrcOperand::Imm(10),
                width: OpWidth::W64,
            },
        ));

        // mov v1, v0 (should propagate to mov v1, 10)
        block.push_op(make_op(
            1,
            OpKind::Mov {
                dst: v1,
                src: SrcOperand::Reg(v0),
                width: OpWidth::W64,
            },
        ));

        // add v2, v1, v0 (v0 should be replaced with 10)
        block.push_op(make_op(
            2,
            OpKind::Add {
                dst: v2,
                src1: v1,
                src2: SrcOperand::Reg(v0),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        ));

        block.set_terminator(Terminator::Return { values: vec![v2] });

        let propagated = constant_propagation(&mut block);

        assert!(propagated >= 2);

        // Check that v0 in add was replaced with immediate
        if let OpKind::Add { src2, .. } = &block.ops[2].kind {
            assert!(matches!(src2, SrcOperand::Imm(10)));
        }
    }

    #[test]
    fn test_constant_folding() {
        let mut block = SmirBlock::new(BlockId(0), 0x1000);

        let v0 = VReg::virt(0);
        let v1 = VReg::virt(1);

        // and v0, v1, 0 -> mov v0, 0
        block.push_op(make_op(
            0,
            OpKind::And {
                dst: v0,
                src1: v1,
                src2: SrcOperand::Imm(0),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        ));

        block.set_terminator(Terminator::Return { values: vec![v0] });

        let folded = constant_folding(&mut block);

        assert_eq!(folded, 1);

        // Check it was folded to a mov
        if let OpKind::Mov { src, .. } = &block.ops[0].kind {
            assert!(matches!(src, SrcOperand::Imm(0)));
        } else {
            panic!("Expected Mov operation");
        }
    }

    #[test]
    fn test_xor_same_register_fold() {
        let mut block = SmirBlock::new(BlockId(0), 0x1000);

        let v0 = VReg::virt(0);
        let v1 = VReg::virt(1);

        // xor v0, v1, v1 -> mov v0, 0
        block.push_op(make_op(
            0,
            OpKind::Xor {
                dst: v0,
                src1: v1,
                src2: SrcOperand::Reg(v1),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        ));

        block.set_terminator(Terminator::Return { values: vec![v0] });

        let folded = constant_folding(&mut block);

        assert_eq!(folded, 1);

        if let OpKind::Mov { src, .. } = &block.ops[0].kind {
            assert!(matches!(src, SrcOperand::Imm(0)));
        } else {
            panic!("Expected Mov operation");
        }
    }

    #[test]
    fn test_dead_code_elimination() {
        let mut block = SmirBlock::new(BlockId(0), 0x1000);

        let v0 = VReg::virt(0);
        let v1 = VReg::virt(1);
        let v2 = VReg::virt(2);

        // mov v0, 10 (unused)
        block.push_op(make_op(
            0,
            OpKind::Mov {
                dst: v0,
                src: SrcOperand::Imm(10),
                width: OpWidth::W64,
            },
        ));

        // mov v1, 20 (used)
        block.push_op(make_op(
            1,
            OpKind::Mov {
                dst: v1,
                src: SrcOperand::Imm(20),
                width: OpWidth::W64,
            },
        ));

        // mov v2, 30 (unused)
        block.push_op(make_op(
            2,
            OpKind::Mov {
                dst: v2,
                src: SrcOperand::Imm(30),
                width: OpWidth::W64,
            },
        ));

        block.set_terminator(Terminator::Return { values: vec![v1] });

        let eliminated = dead_code_elimination(&mut block);

        assert_eq!(eliminated, 2);
        assert_eq!(block.ops.len(), 1);

        // Only v1 should remain
        if let OpKind::Mov { dst, .. } = &block.ops[0].kind {
            assert_eq!(*dst, v1);
        }
    }

    #[test]
    fn test_strength_reduction_mul() {
        let mut block = SmirBlock::new(BlockId(0), 0x1000);

        let v0 = VReg::virt(0);
        let v1 = VReg::virt(1);

        // mul v0, v1, 8 -> shl v0, v1, 3
        block.push_op(make_op(
            0,
            OpKind::MulU {
                dst_lo: v0,
                dst_hi: None,
                src1: v1,
                src2: SrcOperand::Imm(8),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        ));

        block.set_terminator(Terminator::Return { values: vec![v0] });

        let reductions = strength_reduction(&mut block);

        assert_eq!(reductions, 1);

        if let OpKind::Shl { amount, .. } = &block.ops[0].kind {
            assert!(matches!(amount, SrcOperand::Imm(3)));
        } else {
            panic!("Expected Shl operation");
        }
    }

    #[test]
    fn test_strength_reduction_div() {
        let mut block = SmirBlock::new(BlockId(0), 0x1000);

        let v0 = VReg::virt(0);
        let v1 = VReg::virt(1);

        // div v0, v1, 16 -> shr v0, v1, 4
        block.push_op(make_op(
            0,
            OpKind::DivU {
                quot: v0,
                rem: None,
                src1: v1,
                src2: SrcOperand::Imm(16),
                width: OpWidth::W64,
            },
        ));

        block.set_terminator(Terminator::Return { values: vec![v0] });

        let reductions = strength_reduction(&mut block);

        assert_eq!(reductions, 1);

        if let OpKind::Shr { amount, .. } = &block.ops[0].kind {
            assert!(matches!(amount, SrcOperand::Imm(4)));
        } else {
            panic!("Expected Shr operation");
        }
    }

    #[test]
    fn test_optimize_function() {
        use crate::smir::ir::FunctionBuilder;
        use crate::smir::types::FunctionId;

        let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);

        let v0 = builder.alloc_vreg();
        let v1 = builder.alloc_vreg();
        let v2 = builder.alloc_vreg();
        let v3 = builder.alloc_vreg();

        // mov v0, 10
        builder.push_op(
            0x1000,
            OpKind::Mov {
                dst: v0,
                src: SrcOperand::Imm(10),
                width: OpWidth::W64,
            },
        );

        // add v1, v0, 5 (with flags)
        builder.push_op(
            0x1004,
            OpKind::Add {
                dst: v1,
                src1: v0,
                src2: SrcOperand::Imm(5),
                width: OpWidth::W64,
                flags: FlagUpdate::All,
            },
        );

        // mov v2, 100 (dead)
        builder.push_op(
            0x1008,
            OpKind::Mov {
                dst: v2,
                src: SrcOperand::Imm(100),
                width: OpWidth::W64,
            },
        );

        // and v3, v1, 0 -> should fold to mov v3, 0
        builder.push_op(
            0x100c,
            OpKind::And {
                dst: v3,
                src1: v1,
                src2: SrcOperand::Imm(0),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        );

        builder.set_terminator(Terminator::Return { values: vec![v3] });

        let mut func = builder.finish();

        let stats = optimize_function(&mut func, OptLevel::O2);

        // Should have optimizations applied
        assert!(stats.total() > 0);
    }

    #[test]
    fn test_opt_stats() {
        let mut stats1 = OptStats::new();
        stats1.dead_flags_eliminated = 5;
        stats1.constants_propagated = 3;

        let mut stats2 = OptStats::new();
        stats2.dead_ops_eliminated = 2;
        stats2.expressions_folded = 1;

        stats1.merge(&stats2);

        assert_eq!(stats1.dead_flags_eliminated, 5);
        assert_eq!(stats1.constants_propagated, 3);
        assert_eq!(stats1.dead_ops_eliminated, 2);
        assert_eq!(stats1.expressions_folded, 1);
        assert_eq!(stats1.total(), 11);
    }
}
