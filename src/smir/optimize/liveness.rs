//! Frontier-aware register and flag liveness for SMIR regions.

use std::collections::{HashMap, HashSet};

use crate::smir::ir::flags::FlagSet;
use crate::smir::ir::ops::OpKind;
use crate::smir::ir::types::{BlockId, OpWidth, VReg, VecWidth};
use crate::smir::ir::{SmirBlock, SmirFunction, Terminator};

/// Destination width of an integer op, when it has architecturally meaningful
/// width (used for x86 partial-register liveness). `None` for ops without a
/// single integer result width (vectors, memory, etc.).
pub(super) fn op_out_width(kind: &OpKind) -> Option<OpWidth> {
    match kind {
        OpKind::ArmDpRegShift { .. } => Some(OpWidth::W32),
        OpKind::Add { width, .. }
        | OpKind::X86Xadd(crate::smir::ir::ops::X86XaddOp { width, .. })
        | OpKind::Sub { width, .. }
        | OpKind::Adc { width, .. }
        | OpKind::Sbb { width, .. }
        | OpKind::Neg { width, .. }
        | OpKind::Inc { width, .. }
        | OpKind::Dec { width, .. }
        | OpKind::And { width, .. }
        | OpKind::Or { width, .. }
        | OpKind::Xor { width, .. }
        | OpKind::AndNot { width, .. }
        | OpKind::Not { width, .. }
        | OpKind::Shl { width, .. }
        | OpKind::Shr { width, .. }
        | OpKind::Sar { width, .. }
        | OpKind::Shld { width, .. }
        | OpKind::Shrd { width, .. }
        | OpKind::X86NddDoubleShift { width, .. }
        | OpKind::Rol { width, .. }
        | OpKind::Ror { width, .. }
        | OpKind::ArmRegShift { width, .. }
        | OpKind::Rcl { width, .. }
        | OpKind::Rcr { width, .. }
        | OpKind::MulU { width, .. }
        | OpKind::MulS { width, .. }
        | OpKind::DivU { width, .. }
        | OpKind::DivS { width, .. }
        | OpKind::Mov { width, .. }
        | OpKind::CMove { width, .. }
        | OpKind::Cwd { width, .. }
        | OpKind::Bsf { width, .. }
        | OpKind::Bsr { width, .. }
        | OpKind::Clz { width, .. }
        | OpKind::Ctz { width, .. }
        | OpKind::Popcnt { width, .. }
        | OpKind::X86Count { width, .. }
        | OpKind::X86Bls { width, .. }
        | OpKind::X86Tbm { width, .. }
        | OpKind::X86Adx { width, .. }
        | OpKind::Bswap { width, .. }
        | OpKind::Bt { width, .. }
        | OpKind::Bts { width, .. }
        | OpKind::Btr { width, .. }
        | OpKind::Btc { width, .. } => Some(*width),
        // CRC32 always commits a zero-extended 32-bit Castagnoli residue,
        // including the r64,r/m64 encoding, so it fully defines the GPR.
        OpKind::Crc32C { .. } => Some(OpWidth::W64),
        // ZeroExtend / SignExtend write the *destination* (to) width.
        OpKind::ZeroExtend { to_width, .. } | OpKind::SignExtend { to_width, .. } => {
            Some(*to_width)
        }
        // LEA computes a full pointer; SETcc writes a single byte.
        OpKind::Lea { .. } => Some(OpWidth::W64),
        OpKind::X86Lea { width, .. } => Some(*width),
        OpKind::SetCC { .. } => Some(OpWidth::W8),
        OpKind::VBitSelect { width, .. } => match width {
            VecWidth::V64 => Some(OpWidth::W64),
            VecWidth::V128 => Some(OpWidth::W128),
            _ => None,
        },
        OpKind::X86XopPackedBit { .. } => Some(OpWidth::W128),
        _ => None,
    }
}

/// True if executing `op` fully overwrites every architectural register it
/// defines, so an earlier definition of the same register becomes dead.
/// Conservative: returns false when unsure (the register stays live — this is
/// the safe direction; it can only cost a missed optimization, never delete a
/// live definition).
pub(super) fn op_fully_defines(kind: &OpKind) -> bool {
    let dests = kind.dests();
    if dests.is_empty() {
        return true;
    }
    // SSA virtual temporaries are defined in full by their (single) writer.
    if dests.iter().all(|d| matches!(d, VReg::Virtual(_))) {
        return true;
    }
    matches!(
        op_out_width(kind),
        Some(OpWidth::W32) | Some(OpWidth::W64) | Some(OpWidth::W128)
    )
}

/// Whether an operation has a conditional edge that returns control to the
/// architectural interpreter before any following operation executes.
///
/// Every architectural register and status flag is observable on that edge.
/// This is intentionally narrower than `has_side_effects`: ordinary state
/// updates are not optimization frontiers. Extend this predicate whenever an
/// op gains an in-block deoptimization path whose state is captured at entry.
pub(super) fn op_has_precise_deopt_edge(kind: &OpKind) -> bool {
    matches!(
        kind,
        OpKind::ArmInstructionBegin { .. }
            | OpKind::ArmInstructionCommit { .. }
            | OpKind::ArmPauth(..)
            | OpKind::X86RequireApx
            | OpKind::X86RequireSse4a
            | OpKind::X86RequireTbm
            | OpKind::X86RequireXop
            | OpKind::IoIn { .. }
            | OpKind::IoOut { .. }
    )
}

/// Registers read by a terminator (used at the block's exit point).
pub(crate) fn terminator_reg_uses(term: &Terminator) -> Vec<VReg> {
    let mut v = Vec::new();
    match term {
        Terminator::CondBranch { cond, .. } => v.push(*cond),
        Terminator::Switch { index, .. } => v.push(*index),
        Terminator::IndirectBranch { target, .. } => v.push(*target),
        Terminator::IndirectBranchMem { addr, .. } => v.extend(addr.regs()),
        Terminator::Return { values } => v.extend(values.iter().copied()),
        Terminator::Call { target, args, .. } | Terminator::TailCall { target, args } => {
            v.extend(target.regs());
            v.extend(args.iter().copied());
        }
        _ => {}
    }
    v
}

/// Does this terminator hand control out of the region (back to the
/// interpreter, a callee, or an unknown target)? Anything that is not an
/// internal branch whose every target is a block present in `func`.
fn terminator_is_exit(func: &SmirFunction, term: &Terminator) -> bool {
    let in_func = |id: BlockId| func.blocks.iter().any(|b| b.id == id);
    match term {
        Terminator::Branch { target } => !in_func(*target),
        Terminator::CondBranch {
            true_target,
            false_target,
            ..
        } => !in_func(*true_target) || !in_func(*false_target),
        Terminator::Switch {
            targets, default, ..
        } => !in_func(*default) || targets.iter().any(|t| !in_func(*t)),
        // Indirect branches (incomplete target lists), calls (escape to a
        // callee), tail calls, traps, returns, unreachable: all exits.
        _ => true,
    }
}

/// Per-block live-out sets after a frontier-aware backward dataflow fixpoint.
pub(super) struct FuncLiveness {
    pub(super) reg_out: HashMap<BlockId, HashSet<VReg>>,
    pub(super) flag_out: HashMap<BlockId, FlagSet>,
}

/// Backward transfer through one block: given the live-out reg/flag sets,
/// returns the live-in sets. Handles x86 partial-register RMW and conditional
/// deoptimization edges.
fn block_transfer(
    block: &SmirBlock,
    universe: &HashSet<VReg>,
    mut rlive: HashSet<VReg>,
    mut flive: FlagSet,
) -> (HashSet<VReg>, FlagSet) {
    for op in block.ops.iter().rev() {
        let full = op_fully_defines(&op.kind);
        let dests = op.kind.dests();
        if full {
            for d in &dests {
                rlive.remove(d);
            }
        }
        for s in op.kind.source_vregs() {
            rlive.insert(s);
        }
        if !full {
            // Partial-width write reads the destination it merges into.
            for d in &dests {
                rlive.insert(*d);
            }
        }
        flive = flive
            .difference(op.kind.flags_must_write())
            .union(op.kind.flags_read());

        // A disabled dynamic guard exits before the next operation. State at
        // this exact instruction boundary is therefore live even when the
        // successful continuation overwrites it later in the same region.
        if op_has_precise_deopt_edge(&op.kind) {
            rlive.extend(universe.iter().copied());
            flive = flive.union(FlagSet::ALL_X86);
        }
    }
    (rlive, flive)
}

/// Compute per-block register + flag live-out for a function, with all
/// architectural state live at frontier exits.
pub(super) fn compute_liveness(func: &SmirFunction) -> FuncLiveness {
    // Universe of architectural registers touched anywhere in the function —
    // the set that is live-out at any region exit or conditional deopt edge.
    let mut universe: HashSet<VReg> = HashSet::new();
    let note = |v: VReg, set: &mut HashSet<VReg>| {
        if matches!(v, VReg::Arch(_)) {
            set.insert(v);
        }
    };
    for block in &func.blocks {
        for op in &block.ops {
            for d in op.kind.dests() {
                note(d, &mut universe);
            }
            for s in op.kind.source_vregs() {
                note(s, &mut universe);
            }
        }
        for u in terminator_reg_uses(&block.terminator) {
            note(u, &mut universe);
        }
    }

    let mut reg_in: HashMap<BlockId, HashSet<VReg>> =
        func.blocks.iter().map(|b| (b.id, HashSet::new())).collect();
    let mut flag_in: HashMap<BlockId, FlagSet> =
        func.blocks.iter().map(|b| (b.id, FlagSet::EMPTY)).collect();

    // Iterate to fixpoint (live sets grow monotonically).
    let max_iters = func.blocks.len() + 2;
    for _ in 0..max_iters {
        let mut changed = false;
        for block in &func.blocks {
            let mut rout: HashSet<VReg> = HashSet::new();
            let mut fout = FlagSet::EMPTY;
            if terminator_is_exit(func, &block.terminator) {
                rout.extend(universe.iter().copied());
                fout = FlagSet::ALL_X86;
            }
            for s in block.terminator.successors() {
                if let Some(ri) = reg_in.get(&s) {
                    rout.extend(ri.iter().copied());
                }
                if let Some(fi) = flag_in.get(&s) {
                    fout = fout.union(*fi);
                }
            }
            for u in terminator_reg_uses(&block.terminator) {
                rout.insert(u);
            }
            let (rin, fin) = block_transfer(block, &universe, rout, fout);
            if reg_in[&block.id] != rin {
                reg_in.insert(block.id, rin);
                changed = true;
            }
            if flag_in[&block.id] != fin {
                flag_in.insert(block.id, fin);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    // Materialize live-out per block from the converged live-in sets.
    let mut reg_out = HashMap::new();
    let mut flag_out = HashMap::new();
    for block in &func.blocks {
        let mut rout: HashSet<VReg> = HashSet::new();
        let mut fout = FlagSet::EMPTY;
        if terminator_is_exit(func, &block.terminator) {
            rout.extend(universe.iter().copied());
            fout = FlagSet::ALL_X86;
        }
        for s in block.terminator.successors() {
            if let Some(ri) = reg_in.get(&s) {
                rout.extend(ri.iter().copied());
            }
            if let Some(fi) = flag_in.get(&s) {
                fout = fout.union(*fi);
            }
        }
        for u in terminator_reg_uses(&block.terminator) {
            rout.insert(u);
        }
        reg_out.insert(block.id, rout);
        flag_out.insert(block.id, fout);
    }

    FuncLiveness { reg_out, flag_out }
}
