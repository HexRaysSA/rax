//! SMIR optimization passes.
//!
//! This module implements optimization passes for SMIR to improve execution performance.
//! The most impactful optimization for x86 is dead flag elimination, which removes
//! flag updates that are never read.

use std::collections::{HashMap, HashSet};

use crate::smir::ir::flags::{FlagSet, FlagUpdate};
use crate::smir::ir::ops::{
    OpKind, SmirOp, X86LmswOp, X86LmswSource, X86MonitorMwaitOp, X86OpHint, X86RepMode,
    X86SelectorQueryOp, X86SelectorQuerySource, X86SelectorVerifyOp, X86SelectorVerifySource,
    X86SmswOp, X86SmswTarget, X86StringKind, X86SystemSelectorLoadOp, X86SystemSelectorSource,
    X86SystemSelectorStoreOp, X86SystemSelectorTarget, X86ThreeDNowKind, X86WaitPkgOp,
};
use crate::smir::ir::types::{
    Address, ArchReg, ArmReg, BlockId, FpRoundMode, HexagonReg, MemWidth, OpWidth, ShiftOp,
    SignExtend, SrcOperand, VReg, VecElementType, VecWidth, X86Reg,
};
use crate::smir::ir::{CallTarget, SmirBlock, SmirFunction, Terminator};

// ---- module tree (auto-split) ----
mod hexagon_packets;
mod redundant_loads;
pub use redundant_loads::redundant_load_elimination;
mod liveness;
mod scalar_metadata;
pub(crate) use liveness::terminator_reg_uses;
#[cfg(test)]
mod tests;
mod vector_alignment;

pub use vector_alignment::vector_alignment_inference;

use liveness::{compute_liveness, op_fully_defines, op_has_precise_deopt_edge, op_out_width};

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
                | OpKind::Cmn { .. }
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
        | OpKind::Cmn { src1, src2, .. }
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
    // Syscalls are host frontiers with an eBPF guest continuation. Keep that
    // continuation even though Trap has no generic CFG successor.
    let ebpf = func
        .blocks
        .iter()
        .flat_map(|b| &b.ops)
        .any(|op| matches!(op.kind, OpKind::EbpfInstruction { .. }));
    if ebpf {
        for block in &func.blocks {
            if matches!(
                block.terminator,
                Terminator::Trap {
                    kind: crate::smir::ir::TrapKind::SystemCall
                }
            ) && let Some(last) = block.ops.last()
            {
                let continuation = last.guest_pc.wrapping_add(8);
                stack.extend(
                    func.blocks
                        .iter()
                        .filter(|b| b.guest_pc == continuation)
                        .map(|b| b.id),
                );
            }
        }
    }
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
    if func.attrs.x86_instruction_retirement || func.blocks.len() < 2 {
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
            // The entry block also has the function's implicit external
            // predecessor (the caller), which `pred_count` does not see; it
            // is never a single-predecessor merge target.
            (pred_count.get(target) == Some(&1)
                && *target != block.id
                && *target != func.entry
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

// ============================================================================
// OpKind Helper Methods for Optimization
// ============================================================================

mod sources;
mod vector_sources;

// ============================================================================
// Tests
// ============================================================================
