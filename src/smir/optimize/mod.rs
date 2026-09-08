//! SMIR optimization passes.
//!
//! This module implements optimization passes for SMIR to improve execution performance.
//! The most impactful optimization for x86 is dead flag elimination, which removes
//! flag updates that are never read.

use std::collections::{HashMap, HashSet};

use crate::smir::ir::flags::{FlagSet, FlagState, FlagUpdate};
use crate::smir::ir::ops::{
    OpKind, SmirOp, X86AdxKind, X86LmswOp, X86LmswSource, X86MonitorMwaitOp, X86OpHint, X86RepMode,
    X86SelectorQueryOp, X86SelectorQuerySource, X86SelectorVerifyOp, X86SelectorVerifySource,
    X86SmswOp, X86SmswTarget, X86StringKind, X86SystemSelectorLoadOp, X86SystemSelectorSource,
    X86SystemSelectorStoreOp, X86SystemSelectorTarget, X86ThreeDNowKind, X86WaitPkgOp,
    X86X87DataKind,
};
use crate::smir::ir::types::{
    Address, ArchReg, ArmReg, BlockId, FpRoundMode, HexagonReg, MemWidth, OpWidth, ShiftOp,
    SignExtend, SrcOperand, VReg, VecElementType, VecWidth, X86Reg,
};
use crate::smir::ir::{CallTarget, SmirBlock, SmirFunction, Terminator};

// ---- module tree (auto-split) ----
mod liveness;
#[cfg(test)]
mod tests;
mod vector_alignment;

pub use vector_alignment::vector_alignment_inference;

use liveness::{
    compute_liveness, op_fully_defines, op_has_precise_deopt_edge, op_out_width,
    terminator_reg_uses,
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

    /// Copy-propagation operand rewrites
    pub copies_propagated: usize,

    /// Branch foldings / unreachable blocks removed
    pub branches_folded: usize,
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
        self.copies_propagated += other.copies_propagated;
        self.branches_folded += other.branches_folded;
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
            + self.copies_propagated
            + self.branches_folded
    }
}

// ============================================================================
// Main Optimization Entry Point
// ============================================================================

/// Run optimization pipeline on a function
pub fn optimize_function(func: &mut SmirFunction, level: OptLevel) -> OptStats {
    optimize_function_with_stats(func, level)
}

/// Run optimization pipeline on a function, returning statistics.
///
/// Block-level passes are run to a fixpoint (they enable one another and change
/// liveness); liveness is recomputed each round so dead-flag and dead-code
/// elimination always see correct, frontier-aware live-out sets. This is the
/// only entry point that is safe to use on JIT regions / against KVM — the bare
/// per-block passes assume a caller-supplied live-out and must not be used
/// directly on architectural regions.
pub fn optimize_function_with_stats(func: &mut SmirFunction, level: OptLevel) -> OptStats {
    let mut stats = OptStats::new();
    if level == OptLevel::O0 {
        return stats;
    }
    let o2 = level == OptLevel::O2;

    let max_rounds = 8;
    for _ in 0..max_rounds {
        let live = compute_liveness(func);
        let mut round_changes = 0usize;
        for block in &mut func.blocks {
            let flag_out = live
                .flag_out
                .get(&block.id)
                .copied()
                .unwrap_or(FlagSet::ALL_X86);
            let empty_regs;
            let reg_out = match live.reg_out.get(&block.id) {
                Some(r) => r,
                None => {
                    empty_regs = HashSet::new();
                    &empty_regs
                }
            };

            let n = dead_flag_elimination_with(block, flag_out);
            stats.dead_flags_eliminated += n;
            round_changes += n;

            let n = constant_propagation(block);
            stats.constants_propagated += n;
            round_changes += n;

            let n = copy_propagation(block);
            stats.copies_propagated += n;
            round_changes += n;

            if o2 {
                let n = constant_folding(block);
                stats.expressions_folded += n;
                round_changes += n;

                let n = strength_reduction(block);
                stats.strength_reductions += n;
                round_changes += n;
            }

            let n = dead_code_elimination_with(block, reg_out);
            stats.dead_ops_eliminated += n;
            round_changes += n;
        }

        if o2 {
            let n = branch_folding(func);
            stats.branches_folded += n;
            round_changes += n;

            let n = block_merging(func);
            stats.blocks_merged += n;
            round_changes += n;

            let n = redundant_load_elimination(func);
            stats.redundant_loads_eliminated += n;
            round_changes += n;
        }

        if round_changes == 0 {
            break;
        }
    }

    if o2 {
        // Local proof pass for generic, unhinted vector moves. Source encoding
        // hints and provenance-covered operations remain unchanged.
        stats.vector_alignments_inferred += vector_alignment_inference(func);
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
    // Bare per-block use: approximate live-out from the terminator only (a
    // CondBranch needs the status flags; any other terminator is assumed to
    // leave no flag live). This is the legacy block-local contract; JIT regions
    // must go through `optimize_function`, which supplies a frontier-aware
    // live-out via `dead_flag_elimination_with`.
    let live_out = if matches!(block.terminator, Terminator::CondBranch { .. }) {
        FlagSet::NZCV
    } else {
        FlagSet::EMPTY
    };
    dead_flag_elimination_with(block, live_out)
}

/// Eliminate dead flag updates given the flags live on block exit.
///
/// A flag-writing op has its `FlagUpdate` cleared to `None` when none of the
/// flags it writes are live after it — either because a later op in this block
/// overwrites them before any read, or because they are not in `live_out`.
/// Returns the number of flag updates eliminated.
pub fn dead_flag_elimination_with(block: &mut SmirBlock, live_out: FlagSet) -> usize {
    if block.ops.is_empty() {
        return 0;
    }

    // Backward pass: liveness[i] = flags live immediately AFTER op i.
    let mut liveness = vec![FlagSet::EMPTY; block.ops.len()];
    let mut current_live = live_out;
    for i in (0..block.ops.len()).rev() {
        liveness[i] = current_live;
        let op = &block.ops[i];
        let reads = op.kind.flags_read();
        // Only flags DEFINITELY written kill upstream liveness.
        let kills = op.kind.flags_must_write();
        // live_in = (live_out - must_write) | reads
        current_live = current_live.difference(kills).union(reads);
        // A conditional deoptimization observes the complete status image at
        // this exact boundary. A later definition on the enabled continuation
        // must not make any earlier flag definition dead on the exit edge.
        if op_has_precise_deopt_edge(&op.kind) {
            current_live = current_live.union(FlagSet::ALL_X86);
        }
    }

    // Forward pass: eliminate dead flag updates.
    let mut eliminated = 0;
    for i in 0..block.ops.len() {
        let live = liveness[i];
        // These operations exist only to define status flags. Unlike the ALU
        // families below they have no FlagUpdate field to suppress, so replace
        // the entire pure operation when none of its defined flags are live.
        // A memory-source instruction has already lifted its access into a
        // separate Load; removing the flag-only consumer therefore retains
        // precise fault/MMIO behavior.
        if matches!(
            block.ops[i].kind,
            OpKind::Cmp { .. }
                | OpKind::Test { .. }
                | OpKind::Bt { .. }
                | OpKind::SetCF { .. }
                | OpKind::CmcCF
        ) && live
            .intersection(block.ops[i].kind.flags_written())
            .is_empty()
        {
            block.ops[i].kind = OpKind::Nop;
            eliminated += 1;
            continue;
        }
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
    // Tracked values are the FULL architectural register value (for x86, a W32
    // definition zero-extends, so we mask to 32 bits and store the
    // zero-extended 64-bit value). Partial-width (8/16-bit) definitions leave
    // the upper bits unknown, so they are NOT tracked.
    let mut constants: HashMap<VReg, i64> = HashMap::new();
    let mut propagated = 0;

    // Mask a value to a width (the register value the op produces / sees).
    fn m(v: i64, w: OpWidth) -> i64 {
        ((v as u64) & w.mask()) as i64
    }
    // Only W32/W64 definitions fully overwrite the destination register.
    fn trackable(w: OpWidth) -> bool {
        matches!(w, OpWidth::W32 | OpWidth::W64)
    }
    fn crc32c(mut crc: u32, data: u64, width: OpWidth) -> Option<u32> {
        if !matches!(
            width,
            OpWidth::W8 | OpWidth::W16 | OpWidth::W32 | OpWidth::W64
        ) {
            return None;
        }
        const POLY_REFLECTED: u32 = 0x82F6_3B78;
        for byte in 0..(width.bits() / 8) {
            crc ^= ((data >> (byte * 8)) & 0xff) as u32;
            for _ in 0..8 {
                crc = (crc >> 1) ^ (POLY_REFLECTED & 0u32.wrapping_sub(crc & 1));
            }
        }
        Some(crc)
    }

    for op in &mut block.ops {
        // CRC32 has no flag effects. When both explicit input registers are
        // known, evaluate the Castagnoli recurrence at compile time and expose
        // the zero-extended result to subsequent propagation.
        let folded_crc =
            match &op.kind {
                OpKind::Crc32C {
                    dst,
                    crc,
                    data,
                    data_width,
                } => constants.get(crc).zip(constants.get(data)).and_then(
                    |(&crc_value, &data_value)| {
                        crc32c(crc_value as u32, data_value as u64, *data_width)
                            .map(|value| (*dst, value))
                    },
                ),
                _ => None,
            };
        if let Some((dst, value)) = folded_crc {
            op.kind = OpKind::Mov {
                dst,
                src: SrcOperand::Imm(i64::from(value)),
                width: OpWidth::W64,
            };
            constants.insert(dst, i64::from(value));
            propagated += 1;
            continue;
        }

        // Discriminants read before the mutable borrow of `op.kind` below.
        let alu = alu_tag(&op.kind);
        let is_shl = matches!(op.kind, OpKind::Shl { .. });
        let is_sar = matches!(op.kind, OpKind::Sar { .. });
        match &mut op.kind {
            OpKind::Mov { dst, src, width } => {
                if let SrcOperand::Imm(imm) = src {
                    if trackable(*width) {
                        constants.insert(*dst, m(*imm, *width));
                    } else {
                        constants.remove(dst);
                    }
                } else if let SrcOperand::Reg(r) = src {
                    if let Some(&val) = constants.get(r) {
                        *src = SrcOperand::Imm(m(val, *width));
                        propagated += 1;
                        if trackable(*width) {
                            constants.insert(*dst, m(val, *width));
                        } else {
                            constants.remove(dst);
                        }
                    } else {
                        constants.remove(dst);
                    }
                } else {
                    constants.remove(dst);
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
            }
            | OpKind::And {
                dst,
                src1,
                src2,
                width,
                ..
            }
            | OpKind::Or {
                dst,
                src1,
                src2,
                width,
                ..
            }
            | OpKind::Xor {
                dst,
                src1,
                src2,
                width,
                ..
            } => {
                // Substitute a known constant for the register second operand.
                if let SrcOperand::Reg(r) = src2 {
                    if let Some(&val) = constants.get(r) {
                        *src2 = SrcOperand::Imm(m(val, *width));
                        propagated += 1;
                    }
                }
                // Fold the result if both operands are now known constants.
                let folded = if let (Some(&v1), SrcOperand::Imm(v2)) = (constants.get(src1), &*src2)
                {
                    let a = (v1 as u64) & width.mask();
                    let b = (*v2 as u64) & width.mask();
                    let r = match alu {
                        AluTag::Add => a.wrapping_add(b),
                        AluTag::Sub => a.wrapping_sub(b),
                        AluTag::And => a & b,
                        AluTag::Or => a | b,
                        AluTag::Xor => a ^ b,
                    } & width.mask();
                    Some(r as i64)
                } else {
                    None
                };
                match (folded, trackable(*width)) {
                    (Some(r), true) => {
                        constants.insert(*dst, r);
                    }
                    _ => {
                        constants.remove(dst);
                    }
                }
            }

            OpKind::Shl {
                dst,
                src,
                amount,
                width,
                ..
            }
            | OpKind::Shr {
                dst,
                src,
                amount,
                width,
                ..
            }
            | OpKind::Sar {
                dst,
                src,
                amount,
                width,
                ..
            } => {
                if let SrcOperand::Reg(r) = amount {
                    if let Some(&val) = constants.get(r) {
                        *amount = SrcOperand::Imm(val);
                        propagated += 1;
                    }
                }
                let folded = if let (Some(&v), SrcOperand::Imm(a)) = (constants.get(src), &*amount)
                {
                    // Generic SMIR shifts retain a six-bit count. Counts at or
                    // above the operand width saturate the result; they are not
                    // implicitly x86-masked to width-1. This is observable for
                    // AArch32 LSR/ASR #32.
                    let cnt = (*a as u64) & 0x3f;
                    let base = (v as u64) & width.mask();
                    let r = if cnt >= u64::from(width.bits()) {
                        if is_sar && (base & width.sign_bit()) != 0 {
                            width.mask()
                        } else {
                            0
                        }
                    } else if is_shl {
                        base << cnt
                    } else if is_sar {
                        ((base as i64) << (64 - width.bits()) >> (64 - width.bits()) >> cnt) as u64
                    } else {
                        base >> cnt
                    } & width.mask();
                    Some(r as i64)
                } else {
                    None
                };
                match (folded, trackable(*width)) {
                    (Some(r), true) => {
                        constants.insert(*dst, r);
                    }
                    _ => {
                        constants.remove(dst);
                    }
                }
            }

            OpKind::ArmRegShift {
                dst,
                src,
                amount,
                shift,
                width,
                ..
            } => {
                if let SrcOperand::Reg(r) = amount {
                    if let Some(&val) = constants.get(r) {
                        *amount = SrcOperand::Imm(val);
                        propagated += 1;
                    }
                }
                let folded = if *width == OpWidth::W32 {
                    if let (Some(&value), SrcOperand::Imm(raw_count)) =
                        (constants.get(src), &*amount)
                    {
                        let value = value as u32;
                        let count = (*raw_count as u64 & 0xff) as u32;
                        match shift {
                            ShiftOp::Lsl if count < 32 => Some(value.wrapping_shl(count) as i64),
                            ShiftOp::Lsl => Some(0),
                            ShiftOp::Lsr if count < 32 => Some(value.wrapping_shr(count) as i64),
                            ShiftOp::Lsr => Some(0),
                            ShiftOp::Asr if count < 32 => {
                                Some(((value as i32) >> count) as u32 as i64)
                            }
                            ShiftOp::Asr => Some(if value & 0x8000_0000 != 0 {
                                i64::from(u32::MAX)
                            } else {
                                0
                            }),
                            ShiftOp::Ror => Some(value.rotate_right(count % 32) as i64),
                            ShiftOp::Rrx => None,
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };
                if let Some(value) = folded {
                    constants.insert(*dst, value);
                } else {
                    constants.remove(dst);
                }
            }

            OpKind::Load { dst, .. } | OpKind::AtomicLoad { dst, .. } => {
                // Loads produce unknown values.
                constants.remove(dst);
            }

            _ => {
                // For other ops, invalidate destinations.
                for dst in op.kind.dests() {
                    constants.remove(&dst);
                }
            }
        }
    }

    propagated
}

/// Small discriminant for the ALU constant-fold in `constant_propagation`.
#[derive(Clone, Copy)]
enum AluTag {
    Add,
    Sub,
    And,
    Or,
    Xor,
}

fn alu_tag(kind: &OpKind) -> AluTag {
    match kind {
        OpKind::Sub { .. } => AluTag::Sub,
        OpKind::And { .. } => AluTag::And,
        OpKind::Or { .. } => AluTag::Or,
        OpKind::Xor { .. } => AluTag::Xor,
        // Add and anything else (the tag is only consulted in the ALU arm).
        _ => AluTag::Add,
    }
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
        // Rewrites that turn a flag-setting op into a flag-less `Mov` are only
        // legal when the op's flags are dead (`FlagUpdate::None`, established by
        // `dead_flag_elimination`). Shift-by-0 is exempt: x86 leaves flags
        // untouched on a zero count, so the `Mov` is flag-equivalent regardless.
        let new_kind = match &block.ops[i].kind {
            // Add with two immediates
            OpKind::Add {
                dst,
                src1,
                src2: SrcOperand::Imm(v2),
                width,
                flags,
            } if matches!(src1, VReg::Imm(..)) && matches!(flags, FlagUpdate::None) => {
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
                flags,
            } if matches!(src1, VReg::Imm(..)) && matches!(flags, FlagUpdate::None) => {
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
                flags,
                ..
            } if matches!(flags, FlagUpdate::None) => Some(OpKind::Mov {
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
                flags,
            } if matches!(flags, FlagUpdate::None) => Some(OpKind::Mov {
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
                flags,
            } if matches!(flags, FlagUpdate::None) => Some(OpKind::Mov {
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
                flags,
            } if matches!(flags, FlagUpdate::None) => Some(OpKind::Mov {
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
                flags,
            } if src1 == src2 && matches!(flags, FlagUpdate::None) => Some(OpKind::Mov {
                dst: *dst,
                src: SrcOperand::Imm(0),
                width: *width,
            }),

            // Sub of same register -> 0
            OpKind::Sub {
                dst,
                src1,
                src2: SrcOperand::Reg(src2),
                width,
                flags,
            } if src1 == src2 && matches!(flags, FlagUpdate::None) => Some(OpKind::Mov {
                dst: *dst,
                src: SrcOperand::Imm(0),
                width: *width,
            }),

            // And/Or of a register with itself -> mov src1 (idempotent).
            OpKind::And {
                dst,
                src1,
                src2: SrcOperand::Reg(src2),
                width,
                flags,
            }
            | OpKind::Or {
                dst,
                src1,
                src2: SrcOperand::Reg(src2),
                width,
                flags,
            } if src1 == src2 && matches!(flags, FlagUpdate::None) => Some(OpKind::Mov {
                dst: *dst,
                src: SrcOperand::Reg(*src1),
                width: *width,
            }),

            // Multiply by 1 -> mov src1 (no high half, flags dead).
            OpKind::MulU {
                dst_lo,
                dst_hi: None,
                src1,
                src2: SrcOperand::Imm(1),
                width,
                flags: FlagUpdate::None,
            }
            | OpKind::MulS {
                dst_lo,
                dst_hi: None,
                src1,
                src2: SrcOperand::Imm(1),
                width,
                flags: FlagUpdate::None,
            } => Some(OpKind::Mov {
                dst: *dst_lo,
                src: SrcOperand::Reg(*src1),
                width: *width,
            }),

            // Multiply by 0 -> mov 0 (no high half, flags dead).
            OpKind::MulU {
                dst_lo,
                dst_hi: None,
                src2: SrcOperand::Imm(0),
                width,
                flags: FlagUpdate::None,
                ..
            }
            | OpKind::MulS {
                dst_lo,
                dst_hi: None,
                src2: SrcOperand::Imm(0),
                width,
                flags: FlagUpdate::None,
                ..
            } => Some(OpKind::Mov {
                dst: *dst_lo,
                src: SrcOperand::Imm(0),
                width: *width,
            }),

            // Shift by zero -> mov src (flags untouched on x86 zero count).
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
                flags,
            } if matches!(flags, FlagUpdate::None) => Some(OpKind::Mov {
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
                flags,
            } if matches!(flags, FlagUpdate::None) => Some(OpKind::Mov {
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
    // Bare per-block use: seed only from the terminator (legacy contract). JIT
    // regions must go through `optimize_function`, which supplies a
    // frontier-aware register live-out via `dead_code_elimination_with`.
    dead_code_elimination_with(block, &HashSet::new())
}

/// Eliminate dead operations given the registers live on block exit.
///
/// An op is kept when any of its destinations is still used downstream (live),
/// or it has memory/side-effects, or it still writes a live flag (after
/// `dead_flag_elimination` has cleared the dead ones). x86 partial-register
/// writes are treated as read-modify-write so they keep the prior definition
/// live. Returns the number of operations removed.
pub fn dead_code_elimination_with(block: &mut SmirBlock, live_out: &HashSet<VReg>) -> usize {
    // Values used by something we must keep, seeded with the live-out set and
    // the terminator's own register uses.
    let mut used: HashSet<VReg> = live_out.clone();
    for u in terminator_reg_uses(&block.terminator) {
        used.insert(u);
    }

    // Backward pass to find all used values.
    for op in block.ops.iter().rev() {
        let dests = op.kind.dests();
        // Destination-less operations are conservatively live unless their
        // variant is the explicitly side-effect-free Nop produced by earlier
        // simplification passes.
        let dest_live = !matches!(op.kind, OpKind::Nop)
            && (dests.is_empty() || dests.iter().any(|d| used.contains(d)));
        let keep = dest_live || op.kind.has_side_effects() || !op.kind.flags_written().is_empty();

        if keep {
            for src in op.kind.source_vregs() {
                used.insert(src);
            }
            // A partial-width write merges into (reads) its destination.
            if !op_fully_defines(&op.kind) {
                for d in &dests {
                    used.insert(*d);
                }
            }
        }
    }

    // Remove ops that are neither live, side-effecting, nor flag-producing.
    let before = block.ops.len();
    block.ops.retain(|op| {
        let dests = op.kind.dests();
        (!matches!(op.kind, OpKind::Nop)
            && (dests.is_empty() || dests.iter().any(|d| used.contains(d))))
            || op.kind.has_side_effects()
            || !op.kind.flags_written().is_empty()
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
            // Multiply by power of 2 -> shift. Only legal when there is no
            // high-half result to produce (`dst_hi == None`) and the multiply's
            // flags are dead (a shift's CF/OF differ from MUL/IMUL's), which
            // `dead_flag_elimination` establishes as `FlagUpdate::None`.
            OpKind::MulU {
                dst_lo,
                dst_hi: None,
                src1,
                src2: SrcOperand::Imm(imm),
                width,
                flags: FlagUpdate::None,
            }
            | OpKind::MulS {
                dst_lo,
                dst_hi: None,
                src1,
                src2: SrcOperand::Imm(imm),
                width,
                flags: FlagUpdate::None,
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

            // Unsigned divide by power of 2 -> shift right. Only legal when the
            // remainder is not needed (`rem == None`); the quotient of an
            // unsigned divide by 2^k is exactly `src >> k`.
            OpKind::DivU {
                quot,
                rem: None,
                src1,
                src2: SrcOperand::Imm(imm),
                width,
                flags: FlagUpdate::None,
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
// Copy Propagation
// ============================================================================

/// Apply `f` to every PURE-SOURCE register operand of `kind` (operands that are
/// read but never also written — so never a destination or read-modify-write
/// field). Returns how many operands changed. Address operands and RMW fields
/// (Shld/Shrd dst, Xchg, CMove dst, accumulators) are intentionally left
/// untouched: a missed rewrite only forgoes an optimization, never changes
/// semantics.
fn rewrite_pure_src_vregs(kind: &mut OpKind, f: &dyn Fn(VReg) -> VReg) -> usize {
    let mut n = 0usize;
    let mut do_v = |v: &mut VReg, n: &mut usize| {
        let nv = f(*v);
        if nv != *v {
            *v = nv;
            *n += 1;
        }
    };
    let mut do_s = |s: &mut SrcOperand, n: &mut usize| {
        if let SrcOperand::Reg(r) = s {
            let nv = f(*r);
            if nv != *r {
                *s = SrcOperand::Reg(nv);
                *n += 1;
            }
        }
    };
    match kind {
        OpKind::Add { src1, src2, .. }
        | OpKind::Sub { src1, src2, .. }
        | OpKind::Adc { src1, src2, .. }
        | OpKind::Sbb { src1, src2, .. }
        | OpKind::And { src1, src2, .. }
        | OpKind::Or { src1, src2, .. }
        | OpKind::Xor { src1, src2, .. }
        | OpKind::AndNot { src1, src2, .. }
        | OpKind::Cmp { src1, src2, .. }
        | OpKind::Test { src1, src2, .. }
        | OpKind::MulU { src1, src2, .. }
        | OpKind::MulS { src1, src2, .. }
        | OpKind::DivU { src1, src2, .. }
        | OpKind::DivS { src1, src2, .. } => {
            do_v(src1, &mut n);
            do_s(src2, &mut n);
        }
        OpKind::Mov { src, .. } => do_s(src, &mut n),
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
        | OpKind::X86Count { src, .. }
        | OpKind::Bswap { src, .. }
        | OpKind::Rbit { src, .. }
        | OpKind::ZeroExtend { src, .. }
        | OpKind::SignExtend { src, .. }
        | OpKind::Truncate { src, .. } => do_v(src, &mut n),
        OpKind::Shl { src, amount, .. }
        | OpKind::Shr { src, amount, .. }
        | OpKind::Sar { src, amount, .. }
        | OpKind::Rol { src, amount, .. }
        | OpKind::Ror { src, amount, .. }
        | OpKind::Rcl { src, amount, .. }
        | OpKind::Rcr { src, amount, .. } => {
            do_v(src, &mut n);
            do_s(amount, &mut n);
        }
        // Shld/Shrd: `dst` is read-modify-write (skip); `src` and `amount` are
        // pure sources.
        OpKind::Shld { src, amount, .. } | OpKind::Shrd { src, amount, .. } => {
            do_v(src, &mut n);
            do_s(amount, &mut n);
        }
        OpKind::X86NddDoubleShift {
            base, fill, amount, ..
        } => {
            do_v(base, &mut n);
            do_v(fill, &mut n);
            do_s(amount, &mut n);
        }
        OpKind::CMove { src, .. } => do_v(src, &mut n),
        OpKind::Bt { src, index, .. }
        | OpKind::Bts { src, index, .. }
        | OpKind::Btr { src, index, .. }
        | OpKind::Btc { src, index, .. } => {
            do_v(src, &mut n);
            do_s(index, &mut n);
        }
        OpKind::Select {
            cond,
            src_true,
            src_false,
            ..
        } => {
            do_v(cond, &mut n);
            do_v(src_true, &mut n);
            do_v(src_false, &mut n);
        }
        OpKind::X86Sha32 { src1, src2, wk, .. } => {
            do_v(src1, &mut n);
            do_v(src2, &mut n);
            if let Some(wk) = wk {
                do_v(wk, &mut n);
            }
        }
        OpKind::X86PackedStringCompare {
            src1,
            src2,
            len1,
            len2,
            ..
        } => {
            do_v(src1, &mut n);
            do_v(src2, &mut n);
            if let Some(len1) = len1 {
                do_v(len1, &mut n);
            }
            if let Some(len2) = len2 {
                do_v(len2, &mut n);
            }
        }
        // XGETBV, XSETBV, and CPUID expose their implicit architectural
        // operands in `source_vregs()` for liveness, but native helper ABIs
        // require those operands to remain ECX or EAX/ECX. Do not rewrite them.
        _ => {}
    }
    n
}

/// Copy propagation within a block.
///
/// For `mov dst, reg(src)` (a full-width register copy), later pure-source uses
/// of `dst` are rewritten to `src` until `dst` or `src` is redefined. This
/// turns the very common lifted pattern `mov vtmp, r; OP _, vtmp` into
/// `OP _, r`, letting dead-code elimination drop the now-unused copy.
///
/// Returns the number of operand rewrites performed.
pub fn copy_propagation(block: &mut SmirBlock) -> usize {
    // `copies[d] = s` means "register d currently holds the same value as s".
    let mut copies: HashMap<VReg, VReg> = HashMap::new();
    let mut count = 0;

    for op in &mut block.ops {
        // 1) Rewrite pure-source uses through the copy map.
        if !copies.is_empty() {
            let map = &copies;
            count += rewrite_pure_src_vregs(&mut op.kind, &|v| map.get(&v).copied().unwrap_or(v));
        }

        // 2) Invalidate copies killed by this op's destinations.
        let dests = op.kind.dests();
        if !dests.is_empty() {
            for d in &dests {
                copies.remove(d);
            }
            copies.retain(|_, val| !dests.contains(val));
        }

        // 3) Record a new register copy. ONLY W64 moves give full-register
        //    equality (`rcx == rax`); a W32 `mov ecx, eax` yields
        //    `ecx == zero_extend(low32(eax))`, which is not equal to `eax` when
        //    its upper bits are set, so substituting it into a 64-bit use would
        //    be wrong. Restrict to W64 to stay correct regardless of use width.
        if let OpKind::Mov {
            dst,
            src: SrcOperand::Reg(s),
            width: OpWidth::W64,
        } = &op.kind
        {
            if dst != s {
                copies.insert(*dst, *s);
            }
        }
    }

    count
}

// ============================================================================
// Branch Folding
// ============================================================================

/// Fold degenerate conditional branches and drop unreachable blocks.
///
/// - A `CondBranch` whose two targets are identical becomes an unconditional
///   `Branch` (the condition no longer matters).
/// - Blocks not reachable from the entry are removed (they can arise after
///   constant folding / block merging).
///
/// Returns the number of transformations applied.
pub fn branch_folding(func: &mut SmirFunction) -> usize {
    let mut changes = 0;

    // Same-target conditional branches -> unconditional.
    for block in &mut func.blocks {
        if let Terminator::CondBranch {
            true_target,
            false_target,
            ..
        } = &block.terminator
        {
            if true_target == false_target {
                let target = *true_target;
                block.set_terminator(Terminator::Branch { target });
                changes += 1;
            }
        }
    }

    // Reachability from the entry.
    let mut reachable: HashSet<BlockId> = HashSet::new();
    let mut stack = vec![func.entry];
    while let Some(id) = stack.pop() {
        if !reachable.insert(id) {
            continue;
        }
        if let Some(b) = func.blocks.iter().find(|b| b.id == id) {
            for s in b.terminator.successors() {
                if !reachable.contains(&s) {
                    stack.push(s);
                }
            }
        }
    }
    let before = func.blocks.len();
    func.blocks.retain(|b| reachable.contains(&b.id));
    changes += before - func.blocks.len();

    changes
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

    let interpreter_frontiers: HashSet<BlockId> = if func.attrs.preserve_interpreter_frontiers {
        func.blocks
            .iter()
            .filter(|block| {
                block.ops.is_empty()
                    && matches!(
                        &block.terminator,
                        Terminator::Return { values } if values.is_empty()
                    )
            })
            .map(|block| block.id)
            .collect()
    } else {
        HashSet::new()
    };
    let mut merged_count = 0;
    loop {
        // Recompute predecessors after every merge. Selecting every pair from a
        // single stale snapshot is unsound for A->B->C chains: merging A<-B and
        // then B<-C leaves A targeting a removed C while resurrecting the now
        // unreachable B. One-at-a-time contraction keeps each chosen edge and
        // its single-predecessor proof valid.
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

        let merge_pair = func.blocks.iter().find_map(|block| {
            let Terminator::Branch { target } = &block.terminator else {
                return None;
            };
            (pred_count.get(target) == Some(&1)
                && *target != block.id
                && !interpreter_frontiers.contains(target))
            .then_some((block.id, *target))
        });
        let Some((from, to)) = merge_pair else {
            break;
        };

        let from_idx = func.blocks.iter().position(|b| b.id == from);
        let to_idx = func.blocks.iter().position(|b| b.id == to);

        if let (Some(from_idx), Some(to_idx)) = (from_idx, to_idx) {
            // Get ops and terminator from target block
            let to_ops = func.blocks[to_idx].ops.clone();
            let to_term = func.blocks[to_idx].terminator.clone();

            // Instruction provenance follows operations across a merge. A
            // duplicate `(destination block, guest PC)` is ambiguous and is
            // removed fail-closed instead of allowing either instruction to
            // claim the combined semantic group.
            let moved_provenance = func
                .x86_instruction_bytes
                .iter()
                .filter_map(|(&(block, guest_pc), &instruction)| {
                    (block == to).then_some((guest_pc, instruction))
                })
                .collect::<Vec<_>>();
            for (guest_pc, instruction) in moved_provenance {
                func.x86_instruction_bytes.remove(&(to, guest_pc));
                if func
                    .x86_instruction_bytes
                    .insert((from, guest_pc), instruction)
                    .is_some()
                {
                    func.x86_instruction_bytes.remove(&(from, guest_pc));
                }
            }

            // Append to source block
            func.blocks[from_idx].ops.extend(to_ops);
            func.blocks[from_idx].terminator = to_term;

            // Mark target block for removal
            func.blocks[to_idx].ops.clear();
            func.blocks[to_idx].terminator = Terminator::Unreachable;
            merged_count += 1;
        }

        // Remove the consumed target immediately so the next predecessor proof
        // is computed from the contracted graph.
        func.blocks.retain(|b| {
            b.id == func.entry
                || !b.ops.is_empty()
                || !matches!(b.terminator, Terminator::Unreachable)
        });
    }

    merged_count
}

// ============================================================================
// Redundant Load Elimination
// ============================================================================

/// Eliminate redundant loads.
///
/// When a value is loaded from memory and the same address is loaded again
/// (without an intervening store), replace the second load with a move.
/// This transform is disabled unless
/// [`FunctionAttrs::allow_redundant_load_elimination`](crate::smir::ir::FunctionAttrs::allow_redundant_load_elimination)
/// explicitly proves that ordinary loads cannot fault or perform volatile/MMIO
/// reads. The load extension mode is part of the identity key.
///
/// Returns the number of redundant loads eliminated.
pub fn redundant_load_elimination(func: &mut SmirFunction) -> usize {
    if !func.attrs.allow_redundant_load_elimination {
        return 0;
    }

    let mut eliminated = 0;

    for block in &mut func.blocks {
        eliminated += redundant_load_elimination_block(block);
    }

    eliminated
}

fn redundant_load_elimination_block(block: &mut SmirBlock) -> usize {
    // Track what's currently in registers from memory
    // Key: (base_vreg, offset, width, extension), Value: loaded VReg.
    let mut mem_to_reg: HashMap<(Option<VReg>, i64, MemWidth, SignExtend), VReg> = HashMap::new();
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
                // Only loads from a key-able address (Direct/BaseOffset/Absolute)
                // are candidates. Complex addresses (BaseIndexScale, PcRel) are
                // NOT tracked — a single sentinel key would make distinct
                // addresses (e.g. [rsi+rdx-16] vs [rsi+rdx-8]) collide and
                // wrongly forward one load's value to the other.
                if let Some(key) = address_key(addr, *width, *sign) {
                    if let Some(&existing) = mem_to_reg.get(&key) {
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
                } else {
                    new_ops.push(op.clone());
                }
            }

            // Any op that writes memory may alias an arbitrary cached address, so
            // conservatively drop every cached load. This is keyed off
            // `writes_memory()` rather than an explicit op list so that store-like
            // ops cannot silently regress by falling through to the default arm:
            // the prior explicit list omitted PredStore, RepStos, RepMovs,
            // StorePair, VStore, and RvVector, any of which could leave a stale
            // cached load alive across a memory write. (#112)
            other if other.writes_memory() => {
                mem_to_reg.clear();
                new_ops.push(op.clone());
            }

            // I/O ports and syscalls don't write guest RAM through a tracked
            // address, and a fence imposes ordering on prior writes — none are
            // covered by `writes_memory()`, but all may have arbitrary memory side
            // effects, so be conservative and also drop the cache.
            OpKind::Fence { .. }
            | OpKind::IoIn { .. }
            | OpKind::IoOut { .. }
            | OpKind::Syscall { .. } => {
                mem_to_reg.clear();
                new_ops.push(op.clone());
            }

            _ => {
                new_ops.push(op.clone());
            }
        }

        // Invalidate any cached load whose BASE register this op redefines: once
        // the base changes, the cached `(base, offset)` no longer names the same
        // memory (e.g. `load [rsi-8]; lea rsi,[rsi-32]; load [rsi-8]` are two
        // different addresses). Without this, the second load would be wrongly
        // forwarded from the first.
        for d in op.kind.dests() {
            mem_to_reg.retain(|key, _| key.0 != Some(d));
        }
    }

    block.ops = new_ops;
    eliminated
}

/// Create a key for memory-address tracking, or `None` for addresses we do not
/// track (complex forms whose equality we cannot cheaply decide). Returning
/// `None` — never a shared sentinel — is what keeps distinct untracked
/// addresses from aliasing each other.
fn address_key(
    addr: &Address,
    width: MemWidth,
    sign: SignExtend,
) -> Option<(Option<VReg>, i64, MemWidth, SignExtend)> {
    match addr {
        Address::Direct(r) => Some((Some(*r), 0, width, sign)),
        Address::BaseOffset { base, offset, .. } => Some((Some(*base), *offset, width, sign)),
        Address::Absolute(a) => Some((None, *a as i64, width, sign)),
        _ => None,
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
            | OpKind::X86Xadd(crate::smir::ir::ops::X86XaddOp { flags, .. })
            | OpKind::X86Cmpxchg(crate::smir::ir::ops::X86CmpxchgOp { flags, .. })
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
            | OpKind::X86NddDoubleShift { flags, .. }
            | OpKind::Rol { flags, .. }
            | OpKind::Ror { flags, .. }
            | OpKind::ArmRegShift { flags, .. }
            | OpKind::ArmDpRegShift { flags, .. }
            | OpKind::Rcl { flags, .. }
            | OpKind::Rcr { flags, .. }
            | OpKind::Bsf { flags, .. }
            | OpKind::Bsr { flags, .. }
            | OpKind::X86Count { flags, .. }
            | OpKind::Bextr { flags, .. }
            | OpKind::Bzhi { flags, .. }
            | OpKind::X86Bls { flags, .. }
            | OpKind::X86Tbm { flags, .. }
            | OpKind::X86Adx { flags, .. }
            | OpKind::MulU { flags, .. }
            | OpKind::MulS { flags, .. } => Some(flags),
            _ => None,
        }
    }

    /// Get the flags written by this operation (the flags it may define).
    pub fn flags_written(&self) -> FlagSet {
        match self {
            OpKind::Add { flags, .. }
            | OpKind::X86Xadd(crate::smir::ir::ops::X86XaddOp { flags, .. })
            | OpKind::X86Cmpxchg(crate::smir::ir::ops::X86CmpxchgOp { flags, .. })
            | OpKind::Sub { flags, .. }
            | OpKind::Adc { flags, .. }
            | OpKind::Sbb { flags, .. }
            | OpKind::Neg { flags, .. }
            | OpKind::And { flags, .. }
            | OpKind::Or { flags, .. }
            | OpKind::Xor { flags, .. }
            | OpKind::AndNot { flags, .. }
            | OpKind::Shl { flags, .. }
            | OpKind::Shr { flags, .. }
            | OpKind::Sar { flags, .. }
            | OpKind::ArmRegShift { flags, .. }
            | OpKind::ArmDpRegShift { flags, .. }
            | OpKind::Shld { flags, .. }
            | OpKind::Shrd { flags, .. }
            | OpKind::X86NddDoubleShift { flags, .. }
            | OpKind::Bsf { flags, .. }
            | OpKind::Bsr { flags, .. }
            | OpKind::X86Count { flags, .. }
            | OpKind::Bextr { flags, .. }
            | OpKind::Bzhi { flags, .. }
            | OpKind::X86Bls { flags, .. }
            | OpKind::X86Tbm { flags, .. }
            | OpKind::X86Adx { flags, .. }
            | OpKind::MulU { flags, .. }
            | OpKind::MulS { flags, .. } => flags.as_set(),

            OpKind::Rol { flags, .. }
            | OpKind::Ror { flags, .. }
            | OpKind::Rcl { flags, .. }
            | OpKind::Rcr { flags, .. } => {
                flags.as_set().intersection(FlagSet::CF.union(FlagSet::OF))
            }

            // INC/DEC update OF/SF/ZF/AF/PF but PRESERVE CF (their defining
            // difference from ADD/SUB by 1). Never report CF as written.
            OpKind::Inc { flags, .. } | OpKind::Dec { flags, .. } => {
                flags.as_set().difference(FlagSet::CF)
            }

            // Cmp, Test, and CMPccXADD update all x86 arithmetic flags.
            OpKind::Cmp { .. } | OpKind::Test { .. } | OpKind::AtomicCmpXadd { .. } => {
                FlagSet::ALL_X86
            }

            OpKind::X86FpCompare { .. } => FlagSet::ALL_X86,

            OpKind::X86PackedStringCompare { .. } => FlagSet::ALL_X86,

            OpKind::X86Opmask(op) if op.is_test() => FlagSet::ALL_X86,

            OpKind::X86Cmpxchg8b16b { .. } => FlagSet::ZF,

            OpKind::X86SelectorVerify(..) | OpKind::X86SelectorQuery(..) => FlagSet::ZF,

            OpKind::X86Random { .. } => FlagSet::ALL_X86,

            OpKind::X86WaitPkg(X86WaitPkgOp::Umwait { .. } | X86WaitPkgOp::Tpause { .. }) => {
                FlagSet::ALL_X86
            }

            OpKind::X86StackFlags(crate::smir::ir::ops::X86StackFlagsOp {
                kind: crate::smir::ir::ops::X86StackFlagsKind::Pop,
                ..
            }) => FlagSet::ALL_X86,

            OpKind::X86XTest => FlagSet::ALL_X86,

            OpKind::X86X87Data {
                kind: X86X87DataKind::Compare { eflags: true, .. },
                ..
            } => FlagSet::ALL_X86,

            // Every register bit-test form updates CF.
            OpKind::Bt { .. } | OpKind::Bts { .. } | OpKind::Btr { .. } | OpKind::Btc { .. } => {
                FlagSet::CF
            }

            // SCAS and CMPS may update all arithmetic flags. With REP, an
            // initial count of zero performs no comparison and preserves them.
            OpKind::X86String {
                kind: X86StringKind::Scas | X86StringKind::Cmps,
                ..
            } => FlagSet::ALL_X86,

            OpKind::SetCF { .. } | OpKind::CmcCF => FlagSet::CF,

            _ => FlagSet::EMPTY,
        }
    }

    /// Flags this op DEFINITELY writes a defined value to, regardless of its
    /// operands — the set safe to treat as "killed" (overwritten) in backward
    /// flag-liveness. Conservatively smaller than `flags_written` for ops whose
    /// flag effect is operand-conditional or partly undefined: a shift/rotate
    /// by a variable count writes nothing when the count is 0, and MUL/IMUL and
    /// BSF/BSR leave most flags undefined. Using a smaller must-write set can
    /// only keep more upstream flags live (safe), never delete a needed one.
    pub fn flags_must_write(&self) -> FlagSet {
        match self {
            OpKind::Shl { .. }
            | OpKind::Shr { .. }
            | OpKind::Sar { .. }
            | OpKind::Shld { .. }
            | OpKind::Shrd { .. }
            | OpKind::X86NddDoubleShift { .. }
            | OpKind::Rol { .. }
            | OpKind::Ror { .. }
            | OpKind::Rcl { .. }
            | OpKind::Rcr { .. }
            | OpKind::MulU { .. }
            | OpKind::MulS { .. }
            | OpKind::Bsf { .. }
            | OpKind::Bsr { .. } => FlagSet::EMPTY,
            OpKind::X86String {
                kind: X86StringKind::Scas | X86StringKind::Cmps,
                rep,
                ..
            } if *rep != X86RepMode::None => FlagSet::EMPTY,
            // POPF can fault before or after its stack read. Incoming flags
            // remain architectural on either exit, so it cannot kill their
            // liveness even though every successful form writes status flags.
            OpKind::X86StackFlags(crate::smir::ir::ops::X86StackFlagsOp {
                kind: crate::smir::ir::ops::X86StackFlagsKind::Pop,
                ..
            }) => FlagSet::EMPTY,
            OpKind::X86X87Data {
                kind: X86X87DataKind::Compare { eflags: true, .. },
                ..
            } => FlagSet::OF.union(FlagSet::SF).union(FlagSet::AF),
            _ => self.flags_written(),
        }
    }

    /// Get the flags read by this operation
    pub fn flags_read(&self) -> FlagSet {
        match self {
            // Add/Sub with carry read CF
            OpKind::Adc { .. } | OpKind::Sbb { .. } | OpKind::Rcl { .. } | OpKind::Rcr { .. } => {
                FlagSet::CF
            }

            // A zero low-byte count preserves C only when C is among the
            // requested architectural outputs. Flagless T32 forms and
            // dead-flag-eliminated shifts do not consume the incoming carry.
            OpKind::ArmRegShift { flags, .. } => {
                if flags.as_set().contains(FlagSet::CF) {
                    FlagSet::CF
                } else {
                    FlagSet::EMPTY
                }
            }

            OpKind::ArmDpRegShift { kind, flags, .. } => {
                if kind.reads_carry() || (kind.is_logical() && flags.as_set().contains(FlagSet::CF))
                {
                    FlagSet::CF
                } else {
                    FlagSet::EMPTY
                }
            }

            OpKind::X86Adx { kind, .. } => match kind {
                X86AdxKind::Adcx => FlagSet::CF,
                X86AdxKind::Adox => FlagSet::OF,
            },

            // Conditional move reads flags based on condition
            OpKind::CMove { cond, .. } | OpKind::SetCC { cond, .. } => {
                FlagState::required_flags(*cond)
            }

            // TestCondition reads flags
            OpKind::TestCondition { cond, .. } => FlagState::required_flags(*cond),

            OpKind::X86X87Data {
                kind: X86X87DataKind::ConditionalMove(cond),
                ..
            } => FlagState::required_flags(*cond),

            // AArch64 conditional-compare lifting materializes ArmReg::Nzcv
            // from the immediately preceding flag-producing compare op.
            OpKind::Mov {
                src: SrcOperand::Reg(VReg::Arch(ArchReg::Arm(ArmReg::Nzcv))),
                ..
            } => FlagSet::NZCV,

            // Complement carry reads CF
            OpKind::CmcCF => FlagSet::CF,

            // ReadFlags reads all flags
            OpKind::ReadFlags { .. } => FlagSet::ALL_X86,

            // PUSHF consumes the current image. POPF also consumes it for its
            // precise pre/post-memory fault state and privilege-preserved bits.
            OpKind::X86StackFlags(..) => FlagSet::ALL_X86,

            _ => FlagSet::EMPTY,
        }
    }

    /// Get source registers used by this operation
    pub fn source_vregs(&self) -> Vec<VReg> {
        let mut result = Vec::new();

        match self {
            OpKind::X86Opmask(op) => result.extend(op.source_vregs()),

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

            OpKind::X86NddDoubleShift {
                base, fill, amount, ..
            } => {
                result.push(*base);
                result.push(*fill);
                if let SrcOperand::Reg(r) = amount {
                    result.push(*r);
                }
            }

            OpKind::MulU { src1, src2, .. } | OpKind::MulS { src1, src2, .. } => {
                result.push(*src1);
                if let SrcOperand::Reg(r) = src2 {
                    result.push(*r);
                }
            }

            OpKind::DivU {
                quot,
                rem,
                src1,
                src2,
                width,
                ..
            }
            | OpKind::DivS {
                quot,
                rem,
                src1,
                src2,
                width,
                ..
            } => {
                result.push(*src1);

                // The x86 one-operand W16/W32/W64 forms consume the implicit
                // high dividend half in RDX. Model that use explicitly so
                // liveness/DCE cannot erase a preceding CWD/CDQ/CQO or other
                // RDX definition. Byte forms consume AX, which is already
                // represented by the RAX source.
                let rax = VReg::Arch(ArchReg::X86(X86Reg::Rax));
                let rdx = VReg::Arch(ArchReg::X86(X86Reg::Rdx));
                if *quot == rax
                    && *rem == Some(rdx)
                    && *src1 == rax
                    && matches!(width, OpWidth::W16 | OpWidth::W32 | OpWidth::W64)
                {
                    result.push(rdx);
                }

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

            OpKind::Bextr { src, control, .. } => {
                result.push(*src);
                result.push(*control);
            }

            OpKind::Bzhi { src, index, .. } => {
                result.push(*src);
                result.push(*index);
            }

            OpKind::X86Bls { src, .. } | OpKind::X86Tbm { src, .. } => result.push(*src),

            OpKind::X86Adx { src1, src2, .. } => {
                result.push(*src1);
                result.push(*src2);
            }

            OpKind::Pdep { src, mask, .. } | OpKind::Pext { src, mask, .. } => {
                result.push(*src);
                result.push(*mask);
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
            | OpKind::X86Count { src, .. }
            | OpKind::Bswap { src, .. }
            | OpKind::Rbit { src, .. } => {
                result.push(*src);
            }

            OpKind::X86Enter(..) => {
                result.push(VReg::Arch(ArchReg::X86(X86Reg::Rsp)));
                result.push(VReg::Arch(ArchReg::X86(X86Reg::Rbp)));
            }

            OpKind::X86StackFlags(..) => {
                result.push(VReg::Arch(ArchReg::X86(X86Reg::Rsp)));
            }

            OpKind::X86Leave(..) => {
                result.push(VReg::Arch(ArchReg::X86(X86Reg::Rbp)));
            }

            OpKind::Shl { src, amount, .. }
            | OpKind::Shr { src, amount, .. }
            | OpKind::Sar { src, amount, .. }
            | OpKind::Rol { src, amount, .. }
            | OpKind::Ror { src, amount, .. }
            | OpKind::ArmRegShift { src, amount, .. }
            | OpKind::Rcl { src, amount, .. }
            | OpKind::Rcr { src, amount, .. } => {
                result.push(*src);
                if let SrcOperand::Reg(r) = amount {
                    result.push(*r);
                }
            }

            OpKind::ArmDpRegShift { rn, rm, rs, .. } => {
                if let Some(rn) = rn {
                    result.push(*rn);
                }
                result.push(*rm);
                result.push(*rs);
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

            OpKind::Lea { addr, .. } | OpKind::X86Lea { addr, .. } => {
                result.extend(addr.regs());
            }

            OpKind::Xchg { reg1, reg2, .. } => {
                result.push(*reg1);
                result.push(*reg2);
            }

            OpKind::X86Xadd(xadd) => {
                result.push(xadd.dst.vreg());
                result.push(xadd.src.vreg());
            }

            OpKind::X86Cmpxchg(cmpxchg) => {
                result.push(cmpxchg.dst.vreg());
                result.push(cmpxchg.src.vreg());
                result.push(VReg::Arch(ArchReg::X86(X86Reg::Rax)));
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

            OpKind::PredVLoad {
                dst, cond, addr, ..
            } => {
                result.push(*dst);
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

            OpKind::CasPair {
                addr,
                expected_lo,
                expected_hi,
                new_lo,
                new_hi,
                ..
            } => {
                result.extend(addr.regs());
                result.extend([*expected_lo, *expected_hi, *new_lo, *new_hi]);
            }

            OpKind::AtomicCmpXadd { addr, cmp, add, .. } => {
                result.extend(addr.regs());
                result.push(*cmp);
                result.push(*add);
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
            | OpKind::X86FpCompare { src1, src2, .. }
            | OpKind::HexFp { src1, src2, .. }
            | OpKind::HexFpRecip { src1, src2, .. }
            | OpKind::HexCabacDecBin { src1, src2, .. }
            | OpKind::HexTlbMatch { src1, src2, .. } => {
                result.push(*src1);
                result.push(*src2);
            }

            OpKind::FFma {
                src1, src2, src3, ..
            }
            | OpKind::HexFp3 {
                src1, src2, src3, ..
            }
            | OpKind::HexFpDf {
                src1, src2, src3, ..
            } => {
                result.push(*src1);
                result.push(*src2);
                result.push(*src3);
            }

            OpKind::HexFpScFma {
                src1,
                src2,
                src3,
                scale,
                ..
            } => {
                result.push(*src1);
                result.push(*src2);
                result.push(*src3);
                result.push(*scale);
            }

            OpKind::RvFp {
                src1,
                src2,
                src3,
                fcsr_src,
                ..
            } => {
                result.push(*src1);
                result.push(*src2);
                result.push(*src3);
                result.push(*fcsr_src);
            }

            OpKind::RvIntCrypto { src1, src2, .. } => {
                result.push(*src1);
                result.push(*src2);
            }

            OpKind::RvVector {
                rs1, rs2, state, ..
            } => {
                result.push(*rs1);
                result.push(*rs2);
                result.extend(state.x_srcs.iter().copied().filter(|r| !r.is_imm()));
                result.extend(state.f_srcs.iter().copied().filter(|r| !r.is_imm()));
                result.extend(
                    [
                        state.fcsr_src,
                        state.vl_src,
                        state.vtype_src,
                        state.vstart_src,
                        state.vcsr_src,
                    ]
                    .into_iter()
                    .filter(|r| !r.is_imm()),
                );
            }

            OpKind::FAbs { src, .. }
            | OpKind::FNeg { src, .. }
            | OpKind::FSqrt { src, .. }
            | OpKind::FConvert { src, .. }
            | OpKind::IntToFp { src, .. }
            | OpKind::FpToInt { src, .. }
            | OpKind::X86FpToInt { src, .. }
            | OpKind::X86ScalarFpToIntSat { src, .. }
            | OpKind::FRound { src, .. } => {
                result.push(*src);
            }

            OpKind::X86IntToFp { merge, src, .. } => {
                result.push(*merge);
                result.push(*src);
            }

            OpKind::X86FpConvert {
                dst,
                merge,
                src,
                mask,
                mask_zeroing,
                ..
            } => {
                result.push(*merge);
                result.push(*src);
                result.extend(mask.iter().copied());
                if mask.is_some() && !mask_zeroing {
                    result.push(*dst);
                }
            }

            OpKind::X86Round { merge, src, .. } => {
                result.push(*merge);
                result.push(*src);
            }

            OpKind::X86VectorFpCompare {
                src1, src2, mask, ..
            } => {
                result.push(*src1);
                result.push(*src2);
                result.extend(mask.iter().copied());
            }

            OpKind::X86GetExponent {
                dst,
                merge,
                src,
                mask,
                mask_zeroing,
                ..
            } => {
                result.extend(merge.iter().copied());
                result.push(*src);
                result.extend(mask.iter().copied());
                if mask.is_some() && !mask_zeroing {
                    result.push(*dst);
                }
            }

            OpKind::X86GetMantissa {
                dst,
                merge,
                src,
                mask,
                mask_zeroing,
                ..
            } => {
                result.extend(merge.iter().copied());
                result.push(*src);
                result.extend(mask.iter().copied());
                if mask.is_some() && !mask_zeroing {
                    result.push(*dst);
                }
            }

            OpKind::X86RoundScale {
                dst,
                merge,
                src,
                mask,
                mask_zeroing,
                ..
            } => {
                result.extend(merge.iter().copied());
                result.push(*src);
                result.extend(mask.iter().copied());
                if mask.is_some() && !mask_zeroing {
                    result.push(*dst);
                }
            }

            OpKind::X86Reduce {
                dst,
                merge,
                src,
                mask,
                mask_zeroing,
                ..
            } => {
                result.extend(merge.iter().copied());
                result.push(*src);
                result.extend(mask.iter().copied());
                if mask.is_some() && !mask_zeroing {
                    result.push(*dst);
                }
            }

            OpKind::X86Range {
                dst,
                src1,
                src2,
                mask,
                mask_zeroing,
                ..
            } => {
                result.push(*src1);
                result.push(*src2);
                result.extend(mask.iter().copied());
                if mask.is_some() && !mask_zeroing {
                    result.push(*dst);
                }
            }

            OpKind::X86FixupImm {
                dst,
                src1,
                src2,
                mask,
                ..
            } => {
                // Response action zero preserves the old destination even for
                // an active, unmasked lane, so `dst` is always a source.
                result.push(*dst);
                result.push(*src1);
                result.push(*src2);
                result.extend(mask.iter().copied());
            }

            OpKind::X86Exp2 {
                dst,
                src,
                mask,
                mask_zeroing,
                ..
            } => {
                result.push(*src);
                result.extend(mask.iter().copied());
                if mask.is_some() && !mask_zeroing {
                    result.push(*dst);
                }
            }

            OpKind::X86Recip14 {
                dst,
                merge,
                src,
                mask,
                mask_zeroing,
                ..
            }
            | OpKind::X86Rsqrt14 {
                dst,
                merge,
                src,
                mask,
                mask_zeroing,
                ..
            }
            | OpKind::X86RecipFp16 {
                dst,
                merge,
                src,
                mask,
                mask_zeroing,
                ..
            }
            | OpKind::X86RsqrtFp16 {
                dst,
                merge,
                src,
                mask,
                mask_zeroing,
                ..
            }
            | OpKind::X86Recip28 {
                dst,
                merge,
                src,
                mask,
                mask_zeroing,
                ..
            } => {
                result.extend(merge.iter().copied());
                result.push(*src);
                result.extend(mask.iter().copied());
                if mask.is_some() && !mask_zeroing {
                    result.push(*dst);
                }
            }

            OpKind::X86Rsqrt28 {
                dst,
                merge,
                src,
                mask,
                mask_zeroing,
                ..
            } => {
                result.extend(merge.iter().copied());
                result.push(*src);
                result.extend(mask.iter().copied());
                if mask.is_some() && !mask_zeroing {
                    result.push(*dst);
                }
            }

            OpKind::X86ScaleF {
                dst,
                src1,
                src2,
                mask,
                mask_zeroing,
                ..
            } => {
                result.push(*src1);
                result.push(*src2);
                result.extend(mask.iter().copied());
                if mask.is_some() && !mask_zeroing {
                    result.push(*dst);
                }
            }

            OpKind::X86FP16Complex {
                dst,
                src1,
                src2,
                mask,
                mask_zeroing,
                accumulate,
                ..
            } => {
                result.push(*src1);
                result.push(*src2);
                result.extend(mask.iter().copied());
                if *accumulate || (mask.is_some() && !mask_zeroing) {
                    result.push(*dst);
                }
            }

            OpKind::X86FourFma {
                dst,
                src0,
                src1,
                src2,
                src3,
                mem,
                mask,
                ..
            } => {
                result.push(*dst);
                result.push(*src0);
                result.push(*src1);
                result.push(*src2);
                result.push(*src3);
                result.push(*mem);
                result.extend(mask.iter().copied());
            }

            OpKind::X86FourDotProduct {
                dst,
                src0,
                src1,
                src2,
                src3,
                mem,
                mask,
                ..
            } => {
                result.push(*dst);
                result.push(*src0);
                result.push(*src1);
                result.push(*src2);
                result.push(*src3);
                result.push(*mem);
                result.extend(mask.iter().copied());
            }

            OpKind::X86PackedFpConvert {
                dst,
                src,
                mask,
                mask_zeroing,
                zero_upper,
                ..
            } => {
                result.push(*src);
                result.extend(mask.iter().copied());
                if !zero_upper || (mask.is_some() && !mask_zeroing) {
                    result.push(*dst);
                }
            }

            OpKind::X86PackedIntToFp {
                dst,
                src,
                mask,
                mask_zeroing,
                zero_upper,
                ..
            }
            | OpKind::X86PackedFpToInt {
                dst,
                src,
                mask,
                mask_zeroing,
                zero_upper,
                ..
            } => {
                result.push(*src);
                result.extend(mask.iter().copied());
                if !zero_upper || (mask.is_some() && !mask_zeroing) {
                    result.push(*dst);
                }
            }

            OpKind::X86PackedIntToFp16 {
                dst,
                src,
                mask,
                mask_zeroing,
                zero_upper,
                ..
            } => {
                result.push(*src);
                result.extend(mask.iter().copied());
                if !zero_upper || (mask.is_some() && !mask_zeroing) {
                    result.push(*dst);
                }
            }

            OpKind::X86PackedFp16ToInt {
                dst,
                src,
                mask,
                mask_zeroing,
                zero_upper,
                ..
            } => {
                result.push(*src);
                result.extend(mask.iter().copied());
                if !zero_upper || (mask.is_some() && !mask_zeroing) {
                    result.push(*dst);
                }
            }

            OpKind::X86PackedFpConvertStore {
                addr, src, mask, ..
            } => {
                result.push(*src);
                result.extend(mask.iter().copied());
                result.extend(addr.regs());
            }

            // Vector operations
            OpKind::VAdd { src1, src2, .. }
            | OpKind::VSub { src1, src2, .. }
            | OpKind::VAddSubSat { src1, src2, .. }
            | OpKind::VMax { src1, src2, .. }
            | OpKind::VX86MinMax { src1, src2, .. }
            | OpKind::VMul { src1, src2, .. }
            | OpKind::VDiv { src1, src2, .. }
            | OpKind::VLane { src1, src2, .. }
            | OpKind::VAnd { src1, src2, .. }
            | OpKind::VAndNot { src1, src2, .. }
            | OpKind::VOr { src1, src2, .. }
            | OpKind::VXor { src1, src2, .. }
            | OpKind::VFMinMaxNm { src1, src2, .. }
            | OpKind::VPermute2 { src1, src2, .. }
            | OpKind::VCmp { src1, src2, .. } => {
                result.push(*src1);
                result.push(*src2);
            }

            OpKind::X86ThreeDNow {
                src1, src2, kind, ..
            } => {
                if !matches!(
                    kind,
                    X86ThreeDNowKind::Pf2Iw
                        | X86ThreeDNowKind::Pi2Fw
                        | X86ThreeDNowKind::Pf2Id
                        | X86ThreeDNowKind::PfRcp
                        | X86ThreeDNowKind::PfRsqrt
                        | X86ThreeDNowKind::Pi2Fd
                ) {
                    result.push(*src1);
                }
                result.push(*src2);
            }

            OpKind::VBitSelect {
                mask,
                src_true,
                src_false,
                ..
            } => {
                result.push(*mask);
                result.push(*src_true);
                result.push(*src_false);
            }

            OpKind::VPermute {
                src1,
                src2,
                indices,
                ..
            } => {
                result.push(*src1);
                result.extend(src2.iter().copied());
                result.push(*indices);
            }

            OpKind::X86PermuteBytesWords {
                dst,
                table1,
                table2,
                indices,
                mask,
                zeroing,
                ..
            } => {
                if mask.is_some() && !zeroing {
                    result.push(*dst);
                }
                result.push(*table1);
                result.extend(table2.iter().copied());
                result.push(*indices);
                result.extend(mask.iter().copied());
            }

            OpKind::VMultiplyAdd52 {
                acc,
                src1,
                src2,
                mask,
                ..
            } => {
                result.push(*acc);
                result.push(*src1);
                result.push(*src2);
                result.extend(mask.iter().copied());
            }

            OpKind::VUnary { src, .. }
            | OpKind::X86Sqrt { src, .. }
            | OpKind::VReduce { src, .. }
            | OpKind::X86Phminposuw { src, .. }
            | OpKind::X86MovMask { src, .. }
            | OpKind::X86MovdQ { src, .. } => {
                result.push(*src);
            }

            OpKind::X86Sse4aBitfield { dst, source, .. } => {
                // Both forms read the old destination. Register forms also
                // obtain their controls (and INSERTQ payload) from `source`.
                result.extend([*dst, *source]);
            }

            OpKind::X86Sse4aMovntStore { src, addr, .. } => {
                result.push(*src);
                result.extend(addr.regs());
            }

            OpKind::VConflict { src, mask, .. } => {
                result.push(*src);
                result.extend(mask.iter().copied());
            }

            OpKind::VPopcnt { src, mask, .. } | OpKind::VLeadingZeros { src, mask, .. } => {
                result.push(*src);
                result.extend(mask.iter().copied());
            }

            OpKind::X86Aes { src1, src2, .. } => {
                result.push(*src1);
                result.extend(src2.iter().copied());
            }

            OpKind::VTableLookup {
                dst,
                table,
                num_tables,
                index,
                is_tbx,
                ..
            } => {
                result.push(*index);
                // The table is `num_tables` consecutive registers from `table`.
                if let VReg::Arch(ArchReg::Arm(ArmReg::V(base))) = table {
                    for i in 0..*num_tables {
                        result.push(VReg::Arch(ArchReg::Arm(ArmReg::V((base + i) % 32))));
                    }
                } else {
                    result.push(*table);
                }
                // TBX reads the destination (out-of-range indices keep it).
                if *is_tbx {
                    result.push(*dst);
                }
            }

            OpKind::VShift { src, amount, .. } => {
                result.push(*src);
                if let SrcOperand::Reg(r) = amount {
                    result.push(*r);
                }
            }

            OpKind::VWidenMul {
                src1,
                src2,
                dst_lo,
                dst_hi,
                acc,
                ..
            }
            | OpKind::VWidenAddSub {
                src1,
                src2,
                dst_lo,
                dst_hi,
                acc,
                ..
            } => {
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

            OpKind::VShiftAcc {
                src, amount, dst, ..
            } => {
                result.push(*src);
                // shift-accumulate reads the existing destination lane
                result.push(*dst);
                if let SrcOperand::Reg(r) = amount {
                    result.push(*r);
                }
            }

            OpKind::VPairReduceMul {
                src_lo,
                src_hi,
                src2,
                dst_lo,
                dst_hi,
                acc,
                ..
            }
            | OpKind::VSlideReduceMul {
                src_lo,
                src_hi,
                src2,
                dst_lo,
                dst_hi,
                acc,
                ..
            }
            | OpKind::VRotReduceMulPair {
                src_lo,
                src_hi,
                src2,
                dst_lo,
                dst_hi,
                acc,
                ..
            } => {
                result.push(*src_lo);
                result.push(*src_hi);
                result.push(*src2);
                if *acc {
                    result.push(*dst_lo);
                    result.push(*dst_hi);
                }
            }

            OpKind::VPairPairReduceMul {
                src_lo,
                src_hi,
                src2_lo,
                src2_hi,
                ..
            } => {
                result.push(*src_lo);
                result.push(*src_hi);
                result.push(*src2_lo);
                result.push(*src2_hi);
            }

            OpKind::VReduceMul {
                src1,
                src2,
                dst,
                acc,
                ..
            }
            | OpKind::VMulEvenWiden {
                src1,
                src2,
                dst,
                acc,
                ..
            }
            | OpKind::VMulSubLane {
                src1,
                src2,
                dst,
                acc,
                ..
            } => {
                result.push(*src1);
                result.push(*src2);
                if *acc {
                    result.push(*dst);
                }
            }

            OpKind::VWidenExt { src, .. } => {
                result.push(*src);
            }

            OpKind::VLut {
                src_idx,
                table,
                sel,
                dst,
                oracc,
                ..
            } => {
                result.push(*src_idx);
                result.push(*table);
                if let SrcOperand::Reg(r) = sel {
                    result.push(*r);
                }
                if *oracc {
                    result.push(*dst);
                }
            }

            OpKind::VLut16 {
                src_idx,
                table,
                sel,
                dst_lo,
                dst_hi,
                oracc,
                ..
            } => {
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

            OpKind::VShuffVdd {
                src_lo,
                src_hi,
                amount,
                ..
            }
            | OpKind::VDealVdd {
                src_lo,
                src_hi,
                amount,
                ..
            } => {
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
            OpKind::VShuffleDeal {
                dst_y,
                dst_x,
                amount,
                ..
            } => {
                result.push(*dst_y);
                result.push(*dst_x);
                if let SrcOperand::Reg(r) = amount {
                    result.push(*r);
                }
            }

            // vunpacko OR-accumulates the source into the existing dst pair.
            OpKind::VUnpackOAcc {
                src,
                dst_lo,
                dst_hi,
                ..
            } => {
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
            OpKind::VMpaHhSat {
                dst, src, table, ..
            } => {
                result.push(*dst);
                result.push(*src);
                result.push(*table);
            }

            // vmpyhsat_acc accumulates into the existing dst pair.
            OpKind::VMpyHsatAcc {
                dst_lo,
                dst_hi,
                src,
                scalar,
            } => {
                result.push(*dst_lo);
                result.push(*dst_hi);
                result.push(*src);
                result.push(*scalar);
            }

            // vasr_into shifts Vu into the running accumulator pair (read+write).
            OpKind::VAsrInto {
                dst_lo,
                dst_hi,
                src,
                amount,
            } => {
                result.push(*dst_lo);
                result.push(*dst_hi);
                result.push(*src);
                result.push(*amount);
            }

            OpKind::V6Mpy {
                src_lo,
                src_hi,
                src2_lo,
                src2_hi,
                dst_lo,
                dst_hi,
                acc,
                ..
            } => {
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

            OpKind::VMulWord64Pair {
                src1,
                src2,
                dst_lo,
                dst_hi,
                mode,
            } => {
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

            OpKind::VAlign {
                src1, src2, amount, ..
            } => {
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

            OpKind::VNarrowShiftSat {
                src_lo,
                src_hi,
                amount,
                ..
            } => {
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

            OpKind::VNarrowShiftV {
                src_lo,
                src_hi,
                amount,
                ..
            } => {
                result.push(*src_lo);
                result.push(*src_hi);
                result.push(*amount);
            }

            OpKind::VCmpToQ {
                dst,
                src1,
                src2,
                accumulate,
                ..
            } => {
                result.push(*src1);
                result.push(*src2);
                if accumulate.is_some() {
                    result.push(*dst);
                }
            }

            OpKind::VBlend {
                mask_q,
                src_true,
                src_false,
                ..
            } => {
                result.push(*mask_q);
                result.push(*src_true);
                result.push(*src_false);
            }

            OpKind::VMaskZero {
                mask_q,
                src,
                dst,
                oracc,
                ..
            } => {
                result.push(*mask_q);
                result.push(*src);
                // oracc (vandqrt_acc) OR-accumulates into the existing dst.
                if *oracc {
                    result.push(*dst);
                }
            }

            OpKind::VQFromVAndR {
                src1,
                src2,
                dst,
                oracc,
            } => {
                result.push(*src1);
                result.push(*src2);
                // oracc (vandvrt_acc) OR-accumulates into the existing dst Q.
                if *oracc {
                    result.push(*dst);
                }
            }

            // Q-predicated conditional add/sub: dst is read-modify-written.
            OpKind::VLaneCond {
                dst, src, mask_q, ..
            } => {
                result.push(*dst);
                result.push(*src);
                result.push(*mask_q);
            }

            // Carry add/sub: reads both vectors; reads the carry Q when it has a
            // carry-in (carry / carrysat forms).
            OpKind::VCarry {
                src1,
                src2,
                q_inout,
                has_cin,
                ..
            } => {
                result.push(*src1);
                result.push(*src2);
                if *has_cin {
                    result.push(*q_inout);
                }
            }

            OpKind::VSwap {
                mask_q, src1, src2, ..
            } => {
                result.push(*mask_q);
                result.push(*src1);
                result.push(*src2);
            }

            // Scalar-predicate-gated move/combine: when the gate is false the
            // dest(s) keep their prior value, so they are read; also reads the
            // predicate and the candidate sources.
            OpKind::VCondMove {
                dst_lo,
                dst_hi,
                src_lo,
                src_hi,
                pred,
                ..
            } => {
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
            OpKind::VHist {
                input,
                mask_q,
                use_q,
                ..
            } => {
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

            OpKind::VInterleave { src1, src2, .. } => {
                result.push(*src1);
                result.push(*src2);
            }

            OpKind::VByteShuffle { src, control, .. } => {
                result.push(*src);
                result.push(*control);
            }

            OpKind::VHorizontalBin { src1, src2, .. } => {
                result.push(*src1);
                result.push(*src2);
            }

            OpKind::VLoad { addr, .. } => {
                result.extend(addr.regs());
            }

            OpKind::X86LoadMxcsr { addr, .. } | OpKind::X86StoreMxcsr { addr, .. } => {
                result.extend(addr.regs());
            }

            OpKind::X86CacheControl { addr, .. }
            | OpKind::X86CheckAlignment { addr, .. }
            | OpKind::X86CheckAlignmentAc { addr, .. } => {
                result.extend(addr.regs());
            }

            OpKind::X86FxSave { addr, .. } | OpKind::X86FxRstor { addr, .. } => {
                result.extend(addr.regs());
            }

            OpKind::X86XSave {
                addr,
                src_low,
                src_high,
                ..
            }
            | OpKind::X86XRstor {
                addr,
                src_low,
                src_high,
                ..
            } => {
                result.extend(addr.regs());
                result.extend([*src_low, *src_high]);
            }

            OpKind::X86XGetBv { selector, .. } => result.push(*selector),
            OpKind::X86XSetBv {
                selector,
                src_low,
                src_high,
            } => result.extend([*selector, *src_low, *src_high]),
            OpKind::X86FsGsBase {
                operand,
                base,
                write,
                ..
            } => result.push(if *write { *operand } else { *base }),
            OpKind::X86SwapGs {
                gs_base,
                kernel_gs_base,
            } => result.extend([*gs_base, *kernel_gs_base]),
            OpKind::X86MonitorMwait(X86MonitorMwaitOp {
                rcx, hint, addr, ..
            }) => {
                result.extend([*rcx, *hint]);
                if let Some(addr) = addr {
                    result.extend(addr.regs());
                }
            }
            OpKind::X86WaitPkg(X86WaitPkgOp::Umonitor { addr, .. }) => {
                result.extend(addr.regs());
            }
            OpKind::X86WaitPkg(
                X86WaitPkgOp::Umwait {
                    control,
                    deadline_low,
                    deadline_high,
                }
                | X86WaitPkgOp::Tpause {
                    control,
                    deadline_low,
                    deadline_high,
                },
            ) => result.extend([*control, *deadline_low, *deadline_high]),
            OpKind::X86Pkru {
                eax,
                ecx,
                edx,
                pkru,
                write,
            } => {
                if *write {
                    result.extend([*eax, *ecx, *edx]);
                } else {
                    result.extend([*ecx, *pkru]);
                }
            }
            OpKind::X86Cpuid { leaf, subleaf, .. } => result.extend([*leaf, *subleaf]),
            OpKind::X86ReadPmc(read) => result.push(read.selector),
            OpKind::X86Msr(msr) => {
                result.push(msr.ecx);
                if msr.write {
                    result.extend([msr.eax, msr.edx]);
                }
            }
            OpKind::X86WriteControl { src, .. } | OpKind::X86WriteDebug { src, .. } => {
                result.push(*src)
            }
            OpKind::X86Smsw(X86SmswOp {
                target: X86SmswTarget::Memory { addr },
                ..
            }) => result.extend(addr.regs()),
            OpKind::X86SystemSelectorStore(X86SystemSelectorStoreOp {
                target: X86SystemSelectorTarget::Memory { addr },
                ..
            }) => result.extend(addr.regs()),
            OpKind::X86SystemSelectorStore(X86SystemSelectorStoreOp {
                target: X86SystemSelectorTarget::Stack { stack_pointer, .. },
                ..
            }) => result.push(*stack_pointer),
            OpKind::X86SystemSelectorLoad(X86SystemSelectorLoadOp {
                source: X86SystemSelectorSource::Register { src },
                ..
            }) => result.push(*src),
            OpKind::X86SystemSelectorLoad(X86SystemSelectorLoadOp {
                source: X86SystemSelectorSource::Memory { addr, .. },
                ..
            }) => result.extend(addr.regs()),
            OpKind::X86SystemSelectorLoad(X86SystemSelectorLoadOp {
                source: X86SystemSelectorSource::Stack { stack_pointer, .. },
                ..
            }) => result.push(*stack_pointer),
            OpKind::X86SystemSelectorLoad(X86SystemSelectorLoadOp {
                source:
                    X86SystemSelectorSource::FarPointer {
                        addr,
                        dst,
                        offset_width,
                        ..
                    },
                ..
            }) => {
                result.extend(addr.regs());
                if *offset_width == OpWidth::W16 {
                    result.push(*dst);
                }
            }
            OpKind::X86SelectorVerify(X86SelectorVerifyOp {
                source: X86SelectorVerifySource::Register { src },
                ..
            }) => result.push(*src),
            OpKind::X86SelectorVerify(X86SelectorVerifyOp {
                source: X86SelectorVerifySource::Memory { addr, .. },
                ..
            }) => result.extend(addr.regs()),
            OpKind::X86SelectorQuery(X86SelectorQueryOp {
                dst,
                source: X86SelectorQuerySource::Register { src },
                ..
            }) => result.extend([*dst, *src]),
            OpKind::X86SelectorQuery(X86SelectorQueryOp {
                dst,
                source: X86SelectorQuerySource::Memory { addr, .. },
                ..
            }) => {
                result.push(*dst);
                result.extend(addr.regs());
            }
            OpKind::X86FarJump(jump) => result.extend(jump.addr.regs()),
            OpKind::X86FarCall(call) => result.extend(call.addr.regs()),
            OpKind::X86FarReturn(..) => {}
            OpKind::X86FastSystemTransfer(transfer) => {
                if transfer.kind == crate::smir::ir::ops::X86FastSystemTransferKind::Sysexit {
                    result.extend([transfer.return_stack_pointer, transfer.return_target]);
                }
            }
            OpKind::X86Lmsw(X86LmswOp {
                source: X86LmswSource::Register { src },
                ..
            }) => result.push(*src),
            OpKind::X86Lmsw(X86LmswOp {
                source: X86LmswSource::Memory { addr },
                ..
            }) => result.extend(addr.regs()),
            OpKind::X86DescriptorTableStore(store) => result.extend(store.addr.regs()),
            OpKind::X86DescriptorTableLoad(load) => result.extend(load.addr.regs()),
            OpKind::X86Invlpg(invlpg) => result.extend(invlpg.addr.regs()),
            OpKind::X86Invpcid(invpcid) => {
                result.push(invpcid.invpcid_type);
                result.extend(invpcid.addr.regs());
            }

            OpKind::X86Cmpxchg8b16b {
                addr,
                compare_lo,
                compare_hi,
                new_lo,
                new_hi,
                ..
            } => {
                result.extend(addr.regs());
                result.extend([*compare_lo, *compare_hi, *new_lo, *new_hi]);
            }

            OpKind::X86X87Control {
                addr: Some(addr), ..
            } => {
                result.extend(addr.regs());
            }

            OpKind::X86X87Data {
                addr: Some(addr), ..
            } => {
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
            | OpKind::SetAC { .. }
            | OpKind::X86RequireApx
            | OpKind::X86RequireSse4a
            | OpKind::X86RequireTbm
            | OpKind::X86RequireXop
            | OpKind::X86Cli { .. }
            | OpKind::X86Sti { .. }
            | OpKind::X86Clts
            | OpKind::X86ReadControl { .. }
            | OpKind::X86Smsw(X86SmswOp {
                target: X86SmswTarget::Register { .. },
                ..
            })
            | OpKind::X86SystemSelectorStore(X86SystemSelectorStoreOp {
                target: X86SystemSelectorTarget::Register { .. },
                ..
            })
            | OpKind::X86ReadDebug { .. }
            | OpKind::X86ReadTsc(..)
            | OpKind::X86Random { .. }
            | OpKind::X86ReadPid { .. }
            | OpKind::X86X87Control { addr: None, .. }
            | OpKind::X86X87Data { addr: None, .. }
            | OpKind::CmcCF
            | OpKind::MaterializeFlags
            | OpKind::X86XTest
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
            OpKind::VMin { src1, src2, .. } => {
                result.push(*src1);
                result.push(*src2);
            }

            OpKind::VFma {
                src1, src2, acc, ..
            } => {
                result.push(*src1);
                result.push(*src2);
                result.push(*acc);
            }

            OpKind::X86Fma(fma) => result.extend(fma.source_vregs()),

            OpKind::X86FP16Fma {
                src1,
                src2,
                src3,
                mask,
                ..
            } => {
                result.push(*src1);
                result.push(*src2);
                result.push(*src3);
                result.extend(mask.iter().copied());
            }

            OpKind::VDotProductBF16 {
                acc,
                src1,
                src2,
                mask,
                ..
            } => {
                result.push(*acc);
                result.push(*src1);
                result.push(*src2);
                result.extend(mask.iter().copied());
            }

            OpKind::VDotProduct {
                acc,
                src1,
                src2,
                mask,
                ..
            } => {
                result.push(*acc);
                result.push(*src1);
                result.push(*src2);
                result.extend(mask.iter().copied());
            }

            OpKind::VMultiplyAdd52 {
                acc,
                src1,
                src2,
                mask,
                ..
            } => {
                result.push(*acc);
                result.push(*src1);
                result.push(*src2);
                result.extend(mask.iter().copied());
            }

            OpKind::VCvtBF16ToFP32 { src, .. } => {
                result.push(*src);
            }

            OpKind::VConflict { src, mask, .. } => {
                result.push(*src);
                result.extend(mask.iter().copied());
            }

            OpKind::VPopcnt { src, mask, .. } | OpKind::VLeadingZeros { src, mask, .. } => {
                result.push(*src);
                result.extend(mask.iter().copied());
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

            OpKind::X86PermuteBytesWords {
                dst,
                table1,
                table2,
                indices,
                mask,
                zeroing,
                ..
            } => {
                if mask.is_some() && !zeroing {
                    result.push(*dst);
                }
                result.push(*table1);
                result.extend(table2.iter().copied());
                result.push(*indices);
                result.extend(mask.iter().copied());
            }

            OpKind::VShuffleBitQM {
                src, indices, mask, ..
            } => {
                result.push(*src);
                result.push(*indices);
                result.extend(mask.iter().copied());
            }

            OpKind::VCompress {
                dst,
                src,
                mask,
                zeroing,
                ..
            }
            | OpKind::VExpand {
                dst,
                src,
                mask,
                zeroing,
                ..
            } => {
                result.push(*src);
                if let Some(mask) = mask {
                    result.push(*mask);
                }
                if !zeroing {
                    result.push(*dst);
                }
            }

            OpKind::X86NarrowInt {
                dst,
                src,
                mask,
                zeroing,
                ..
            } => {
                result.push(*src);
                if let Some(mask) = mask {
                    result.push(*mask);
                }
                if !zeroing {
                    result.push(*dst);
                }
            }

            OpKind::VCvtFP32ToBF16 {
                dst,
                src1,
                src2,
                mask,
                zeroing,
                ..
            } => {
                result.push(*src1);
                if let Some(s2) = src2 {
                    result.push(*s2);
                }
                result.extend(mask.iter().copied());
                if mask.is_some() && !zeroing {
                    result.push(*dst);
                }
            }

            OpKind::VFP16Arith {
                dst,
                src1,
                src2,
                mask,
                zeroing,
                ..
            } => {
                result.push(*src1);
                result.push(*src2);
                result.extend(mask.iter().copied());
                if mask.is_some() && !zeroing {
                    result.push(*dst);
                }
            }

            OpKind::VMinMax { src1, src2, .. } | OpKind::VSadBytes { src1, src2, .. } => {
                result.push(*src1);
                result.push(*src2);
            }

            OpKind::VMpsadbw {
                dst,
                src1,
                src2,
                mask,
                zeroing,
                ..
            } => {
                result.push(*src1);
                result.push(*src2);
                result.extend(mask.iter().copied());
                if mask.is_some() && !zeroing {
                    result.push(*dst);
                }
            }

            OpKind::X86Aes { src1, src2, .. } => {
                result.push(*src1);
                result.extend(src2.iter().copied());
            }

            OpKind::X86DotProduct { src1, src2, .. } => {
                result.push(*src1);
                result.push(*src2);
            }

            OpKind::X86FpBinary {
                src1, src2, mask, ..
            } => {
                result.push(*src1);
                result.push(*src2);
                result.extend(mask.iter().copied());
            }

            OpKind::X86Sha32 { src1, src2, wk, .. } => {
                result.push(*src1);
                result.push(*src2);
                result.extend(wk.iter().copied());
            }

            OpKind::X86PackedStringCompare {
                dst,
                src1,
                src2,
                len1,
                len2,
                kind,
                zero_upper,
                ..
            } => {
                result.push(*src1);
                result.push(*src2);
                result.extend(len1.iter().copied());
                result.extend(len2.iter().copied());
                // Legacy mask forms overwrite only XMM0 bits 127:0. VEX mask
                // forms clear the shared architectural vector value above bit
                // 127 and therefore do not read the old destination.
                if kind.returns_mask() && !zero_upper {
                    result.push(*dst);
                }
            }

            OpKind::X86Sha512Msg1 { dst, src } | OpKind::X86Sha512Msg2 { dst, src } => {
                result.push(*dst);
                result.push(*src);
            }

            OpKind::X86Sha512Rounds2 { dst, state, wk } => {
                result.push(*dst);
                result.push(*state);
                result.push(*wk);
            }

            OpKind::X86Sm3Msg1 {
                dst, src1, src2, ..
            }
            | OpKind::X86Sm3Msg2 {
                dst, src1, src2, ..
            } => {
                result.push(*dst);
                result.push(*src1);
                result.push(*src2);
            }

            OpKind::X86Sm3Rounds2 {
                dst, state, words, ..
            } => {
                result.push(*dst);
                result.push(*state);
                result.push(*words);
            }

            OpKind::X86Sm4 { src1, src2, .. } => {
                result.push(*src1);
                result.push(*src2);
            }

            OpKind::X86Convert16ToFp32 { src, .. } => {
                result.push(*src);
            }

            OpKind::X86PackedShiftImm { src, .. } => {
                result.push(*src);
            }

            OpKind::X86PackedAlignRight { high, low, .. } => {
                result.push(*high);
                result.push(*low);
            }

            OpKind::X86PackedShuffleImm { src, .. } => {
                result.push(*src);
            }

            OpKind::X86PackedShift { src, count, .. } => {
                result.push(*src);
                result.push(*count);
            }
            OpKind::X86PackedShiftVariable {
                src, count, mask, ..
            } => {
                result.push(*src);
                result.push(*count);
                if let Some(mask) = mask {
                    result.push(*mask);
                }
            }

            OpKind::X86PackedRotate {
                src, count, mask, ..
            } => {
                result.push(*src);
                if let Some(count) = count {
                    result.push(*count);
                }
                if let Some(mask) = mask {
                    result.push(*mask);
                }
            }

            OpKind::X86XopPackedBit { src, count, .. } => {
                result.push(*src);
                if let SrcOperand::Reg(register) = count {
                    result.push(*register);
                }
            }

            OpKind::X86TernaryLogic {
                src1,
                src2,
                src3,
                mask,
                ..
            } => {
                result.push(*src1);
                result.push(*src2);
                result.push(*src3);
                if let Some(mask) = mask {
                    result.push(*mask);
                }
            }

            OpKind::X86PackedFunnelShift {
                src,
                fill,
                count,
                mask,
                ..
            } => {
                result.push(*src);
                result.push(*fill);
                if let Some(count) = count {
                    result.push(*count);
                }
                if let Some(mask) = mask {
                    result.push(*mask);
                }
            }

            OpKind::X86MultiShiftQB {
                control,
                source,
                mask,
                ..
            } => {
                result.push(*control);
                result.push(*source);
                if let Some(mask) = mask {
                    result.push(*mask);
                }
            }

            OpKind::VCvtFpToIntSat {
                dst,
                src,
                mask,
                zeroing,
                ..
            } => {
                result.push(*src);
                if let Some(mask) = mask {
                    result.push(*mask);
                    if !*zeroing {
                        result.push(*dst);
                    }
                }
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
                src1,
                src2,
                dst,
                dst_hi,
                acc,
                ..
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

            OpKind::Crc32C { crc, data, .. } => {
                result.push(*crc);
                result.push(*data);
            }

            // Wide complex multiply: reads both halves of the Rss and Rtt pairs.
            OpKind::CmpyW128Sat {
                rss_lo,
                rss_hi,
                rtt_lo,
                rtt_hi,
                ..
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

            OpKind::X86String {
                kind,
                rep,
                accumulator,
                src_index,
                dst_index,
                count,
                src_segment,
                ..
            } => {
                match kind {
                    X86StringKind::Movs => result.extend([*src_index, *dst_index]),
                    X86StringKind::Stos => result.extend([*accumulator, *dst_index]),
                    X86StringKind::Lods => result.extend([*accumulator, *src_index]),
                    X86StringKind::Scas => result.extend([*accumulator, *dst_index]),
                    X86StringKind::Cmps => result.extend([*src_index, *dst_index]),
                }
                if *rep != X86RepMode::None {
                    result.push(*count);
                }
                if let Some(segment) = src_segment {
                    result.push(*segment);
                }
            }
        }

        result
    }
}

// ============================================================================
// Tests
// ============================================================================
