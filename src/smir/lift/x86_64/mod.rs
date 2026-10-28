//! x86_64 instruction lifter.
//!
//! This module lifts x86_64 machine code to SMIR. Unlike AArch64 which has a clean
//! decoder, x86 decoding is interleaved with lifting due to variable-length encoding.

use std::collections::{HashMap, HashSet};

use crate::smir::ir::flags::{FlagSet, FlagUpdate};
use crate::smir::ir::memory::MemoryError;
use crate::smir::ir::ops::{
    OpKind, SmirOp, X86AdxKind, X86AluEncoding, X86BlsKind, X86CacheControlKind, X86CountKind,
    X86MonitorMwaitOp, X86OpHint, X86ReadPmcOp, X86ReadTscOp, X86RepMode, X86Sha32Op, X86SsePrefix,
    X86StringKind, X86ThreeDNowKind, X86VecAlign, X86VecMap, X86WaitPkgOp,
    X86X87ArithmeticDestination, X86X87ArithmeticSource, X86X87CompareSource, X86X87Constant,
    X86X87ControlKind, X86X87DataKind, X86X87EnvWidth, X86X87FloatWidth, X86X87IntWidth,
    X86XSaveKind,
};
use crate::smir::ir::types::*;
use crate::smir::ir::{
    CallTarget, CallingConv, FunctionAttrs, SmirBlock, SmirFunction, Terminator, TrapKind,
    X86InstructionBytes,
};
use crate::smir::lift::{
    ControlFlow, LiftContext, LiftError, LiftResult, MemoryReader, SmirLifter,
};

// ---- module tree (auto-split) ----
mod apx;
pub use apx::*;
mod common;
pub use common::*;
mod decode;
pub use decode::*;
mod dispatch;
pub use dispatch::*;
mod scalar;
pub use scalar::*;
mod simd;
pub use simd::*;
#[cfg(test)]
mod tests;

fn x86_rotate_flags() -> FlagUpdate {
    FlagUpdate::Specific(FlagSet::CF.union(FlagSet::OF))
}

fn x86_bextr_flags() -> FlagUpdate {
    FlagUpdate::Specific(FlagSet::CF.union(FlagSet::ZF).union(FlagSet::OF))
}

fn x86_bzhi_flags() -> FlagUpdate {
    FlagUpdate::Specific(
        FlagSet::CF
            .union(FlagSet::ZF)
            .union(FlagSet::SF)
            .union(FlagSet::OF),
    )
}

fn x86_bls_flags() -> FlagUpdate {
    FlagUpdate::Specific(
        FlagSet::CF
            .union(FlagSet::ZF)
            .union(FlagSet::SF)
            .union(FlagSet::OF),
    )
}

const APX_CCMP_FLAGS_MASK: i64 = 0x8D5; // CF, PF, AF, ZF, SF, OF

// ============================================================================
// x86_64 Lifter
// ============================================================================

/// x86_64 instruction lifter
pub struct X86_64Lifter {
    /// Whether to use strict mode (fail on unsupported instructions)
    strict: bool,
    /// End a partially lifted block at an explicit interpreter frontier when
    /// decoding reaches an unsupported, invalid, incomplete, or unreadable
    /// instruction. This is intentionally independent of `strict`: individual
    /// instruction lifting still reports the exact error, while region lifting
    /// can retain all preceding native work and hand control back at the exact
    /// faulting/unsupported guest PC.
    interpreter_frontiers: bool,
    /// Lift-through-calls: when set, `lift_function` follows a `CALL`'s
    /// continuation (return address) and keeps lifting the caller's CFG past the
    /// call, instead of ending the function at the call. Used by the JIT's
    /// lift-through-calls path (the call itself lowers to a runtime call-out).
    /// `max_blocks` bounds the lifted CFG so a large/looping function can't lift
    /// unboundedly.
    lift_through_calls: bool,
    /// Cap on lifted blocks (only enforced under `lift_through_calls`).
    max_blocks: usize,
    /// Exact instruction provenance accumulated by `lift_block` for transfer to
    /// the next `lift_function` result. The block ID participates in the key so
    /// synthetic ops carrying another block's guest PC cannot claim its bytes.
    lifted_instruction_bytes: HashMap<(BlockId, GuestAddr), X86InstructionBytes>,
    /// Preserve one guest instruction per block for native retirement.
    instruction_retirement: bool,
}

impl Default for X86_64Lifter {
    fn default() -> Self {
        Self::new()
    }
}

impl X86_64Lifter {
    /// Create a new x86_64 lifter
    pub fn new() -> Self {
        X86_64Lifter {
            strict: false,
            interpreter_frontiers: false,
            lift_through_calls: false,
            max_blocks: 0,
            lifted_instruction_bytes: HashMap::new(),
            instruction_retirement: false,
        }
    }

    /// Create a lifter in strict mode
    pub fn strict() -> Self {
        X86_64Lifter {
            strict: true,
            interpreter_frontiers: false,
            lift_through_calls: false,
            max_blocks: 0,
            lifted_instruction_bytes: HashMap::new(),
            instruction_retirement: false,
        }
    }

    /// Retain a supported region prefix when a later instruction must execute
    /// in the interpreter. The generated frontier contains no guest operation;
    /// the JIT records its guest PC and exits before executing that instruction.
    pub fn set_interpreter_frontiers(&mut self, enabled: bool) {
        self.interpreter_frontiers = enabled;
    }

    /// Preserve each successfully lifted instruction as one CFG block.
    /// Native runtimes can then count dynamic completion without inferring
    /// instruction counts from byte distances or surviving optimized ops.
    pub fn set_instruction_retirement(&mut self, enabled: bool) {
        self.instruction_retirement = enabled;
    }

    /// Enable lift-through-calls with a block cap (see the field docs).
    pub fn set_lift_through_calls(&mut self, max_blocks: usize) {
        self.lift_through_calls = true;
        self.max_blocks = max_blocks;
    }
}

// ============================================================================
// SmirLifter Implementation
// ============================================================================

fn x86_interpreter_frontier_error(error: &LiftError) -> bool {
    matches!(
        error,
        LiftError::InvalidEncoding { .. }
            | LiftError::Unsupported { .. }
            | LiftError::MemoryError { .. }
            | LiftError::Incomplete { .. }
    )
}

fn x86_interpreter_frontier_control_flow(result: &LiftResult, lift_through_calls: bool) -> bool {
    match &result.control_flow {
        ControlFlow::IndirectBranch { target }
            if matches!(
                result.ops.last(),
                Some(SmirOp {
                    kind: OpKind::X86FarJump(jump),
                    ..
                }) if jump.target == *target
            ) || matches!(
                result.ops.last(),
                Some(SmirOp {
                    kind: OpKind::X86FarCall(call),
                    ..
                }) if call.target == *target
            ) || matches!(
                result.ops.last(),
                Some(SmirOp {
                    kind: OpKind::X86FarReturn(ret),
                    ..
                }) if ret.target == *target
            ) || matches!(
                result.ops.last(),
                Some(SmirOp {
                    kind: OpKind::X86FastSystemTransfer(transfer),
                    ..
                }) if transfer.target == *target
            ) =>
        {
            false
        }
        ControlFlow::IndirectBranch { .. }
        | ControlFlow::IndirectBranchMem { .. }
        | ControlFlow::Return
        | ControlFlow::Trap { .. }
        | ControlFlow::Syscall => true,
        ControlFlow::Call { target } => {
            !lift_through_calls
                || !match target {
                    CallTarget::GuestAddr(_) | CallTarget::Indirect(_) => true,
                    CallTarget::IndirectMem(addr) => addr.is_x86_state_backed_shape(),
                    CallTarget::X86IndirectMemAddr32(addr) => {
                        addr.is_x86_addr32_state_backed_shape()
                    }
                    _ => false,
                }
        }
        _ => false,
    }
}

fn terminate_at_interpreter_frontier(
    block: &mut SmirBlock,
    block_addr: GuestAddr,
    frontier_pc: GuestAddr,
    ctx: &mut LiftContext,
) {
    block.terminator = if frontier_pc == block_addr {
        // No instruction in this block can execute natively. Represent it as a
        // zero-op frontier so the runtime can reject an entry frontier or route
        // an incoming native edge back to the interpreter at this exact PC.
        Terminator::Return { values: vec![] }
    } else {
        // Preserve the supported prefix as executable native work. The target
        // is subsequently lifted into the zero-op frontier above.
        Terminator::Branch {
            target: ctx.get_or_create_block(frontier_pc),
        }
    };
}

impl SmirLifter for X86_64Lifter {
    fn source_arch(&self) -> SourceArch {
        SourceArch::X86_64
    }

    fn lift_insn(
        &mut self,
        addr: GuestAddr,
        bytes: &[u8],
        ctx: &mut LiftContext,
    ) -> Result<LiftResult, LiftError> {
        ctx.guest_pc = addr;
        self.lift_insn_inner(addr, bytes, ctx)
    }

    fn lift_block(
        &mut self,
        addr: GuestAddr,
        mem: &dyn MemoryReader,
        ctx: &mut LiftContext,
    ) -> Result<SmirBlock, LiftError> {
        let block_id = ctx.get_or_create_block(addr);
        let mut block = SmirBlock::new(block_id, addr);

        let mut pc = addr;
        let mut buf = [0u8; 15];

        loop {
            // Read instruction bytes
            let bytes = match mem.read(pc, 15) {
                Ok(bytes) => bytes,
                Err(error) => {
                    let error = LiftError::MemoryError { addr: pc, error };
                    if self.interpreter_frontiers && x86_interpreter_frontier_error(&error) {
                        terminate_at_interpreter_frontier(&mut block, addr, pc, ctx);
                        break;
                    }
                    return Err(error);
                }
            };

            buf[..bytes.len()].copy_from_slice(&bytes);

            ctx.guest_pc = pc;
            let result = match self.lift_insn_inner(pc, &buf[..bytes.len()], ctx) {
                Ok(result) => result,
                Err(error)
                    if self.interpreter_frontiers && x86_interpreter_frontier_error(&error) =>
                {
                    terminate_at_interpreter_frontier(&mut block, addr, pc, ctx);
                    break;
                }
                Err(error) => return Err(error),
            };

            // Ordinary terminal instructions are interpreter frontiers too.
            // Split them before appending their instruction-local ops so a
            // supported straight-line prefix remains native while the exact
            // terminal PC (RET/HLT/syscall/indirect/unsupported CALL form) is
            // re-executed by the interpreter. Supported callout forms remain in
            // the native block when lift-through-calls is enabled.
            if self.interpreter_frontiers
                && x86_interpreter_frontier_control_flow(&result, self.lift_through_calls)
            {
                terminate_at_interpreter_frontier(&mut block, addr, pc, ctx);
                break;
            }

            if let Some(instruction) = X86InstructionBytes::new(&buf[..result.bytes_consumed]) {
                self.lifted_instruction_bytes
                    .insert((block_id, pc), instruction);
            }

            // Add ops to block
            block.ops.extend(result.ops);
            let instruction_pc = pc;
            pc += result.bytes_consumed as u64;

            // Check for block-ending control flow
            match result.control_flow {
                ControlFlow::Fallthrough | ControlFlow::NextInsn => {
                    if self.instruction_retirement {
                        block.terminator = Terminator::Branch {
                            target: ctx.get_or_create_block(pc),
                        };
                        break;
                    }
                    continue;
                }
                ControlFlow::Branch { target } | ControlFlow::DirectBranch(target) => {
                    block.terminator = Terminator::Branch {
                        target: ctx.get_or_create_block(target),
                    };
                    break;
                }
                ControlFlow::CondBranch {
                    cond,
                    target,
                    fallthrough,
                } => {
                    // We need a VReg holding the condition result
                    let cond_vreg = ctx.alloc_vreg();
                    block.ops.push(SmirOp::new(
                        OpId(block.ops.len() as u16),
                        if self.instruction_retirement {
                            instruction_pc
                        } else {
                            pc
                        },
                        OpKind::TestCondition {
                            dst: cond_vreg,
                            cond,
                        },
                    ));
                    block.terminator = Terminator::CondBranch {
                        cond: cond_vreg,
                        true_target: ctx.get_or_create_block(target),
                        false_target: ctx.get_or_create_block(fallthrough),
                    };
                    break;
                }
                ControlFlow::CondBranchReg {
                    cond,
                    taken,
                    not_taken,
                } => {
                    block.terminator = Terminator::CondBranch {
                        cond,
                        true_target: ctx.get_or_create_block(taken),
                        false_target: ctx.get_or_create_block(not_taken),
                    };
                    break;
                }
                ControlFlow::IndirectBranch { target } => {
                    block.terminator = Terminator::IndirectBranch {
                        target,
                        possible_targets: vec![],
                    };
                    break;
                }
                ControlFlow::IndirectBranchMem { addr } => {
                    block.terminator = Terminator::IndirectBranchMem {
                        addr,
                        possible_targets: vec![],
                    };
                    break;
                }
                ControlFlow::Call { target } => {
                    let continuation = ctx.get_or_create_block(pc);
                    block.terminator = Terminator::Call {
                        target,
                        args: vec![],
                        continuation,
                    };
                    break;
                }
                ControlFlow::Return => {
                    block.terminator = Terminator::Return { values: vec![] };
                    break;
                }
                ControlFlow::Trap { kind } => {
                    block.terminator = Terminator::Trap { kind };
                    break;
                }
                ControlFlow::Syscall => {
                    // For syscall, we'll use a TailCall to the syscall runtime
                    block.terminator = Terminator::TailCall {
                        target: CallTarget::Runtime(crate::smir::ir::RuntimeFunc::Syscall),
                        args: vec![],
                    };
                    break;
                }
            }
        }

        Ok(block)
    }

    fn lift_function(
        &mut self,
        entry: GuestAddr,
        mem: &dyn MemoryReader,
        ctx: &mut LiftContext,
    ) -> Result<SmirFunction, LiftError> {
        self.lifted_instruction_bytes.clear();
        let entry_block = ctx.get_or_create_block(entry);
        let mut func = SmirFunction::new(FunctionId(entry as u32), entry_block, entry);
        func.attrs.preserve_interpreter_frontiers =
            self.interpreter_frontiers || (self.lift_through_calls && self.max_blocks != 0);

        func.attrs.x86_instruction_retirement = self.instruction_retirement;

        // Work queue of blocks to lift
        let mut worklist = vec![entry];
        let mut visited = HashSet::new();

        while let Some(block_addr) = worklist.pop() {
            if visited.contains(&block_addr) {
                continue;
            }
            // Lift-through-calls: bound the lifted CFG so a large or call-chained
            // function can't lift unboundedly (the cap counts lifted blocks).
            // Every queued address is already referenced by a lifted terminator;
            // retain it as an exact-PC interpreter frontier instead of returning
            // a function with a dangling BlockId. Continue draining the worklist
            // so every other queued successor receives the same frontier.
            if self.lift_through_calls && self.max_blocks != 0 && visited.len() >= self.max_blocks {
                visited.insert(block_addr);
                let mut frontier = SmirBlock::new(ctx.get_or_create_block(block_addr), block_addr);
                frontier.set_terminator(Terminator::Return { values: vec![] });
                func.add_block(frontier);
                continue;
            }
            visited.insert(block_addr);

            let block = self.lift_block(block_addr, mem, ctx)?;

            // Add branch targets to worklist
            match &block.terminator {
                Terminator::Branch { target } => {
                    if let Some(&addr) = ctx
                        .block_cache
                        .iter()
                        .find_map(|(a, id)| if id == target { Some(a) } else { None })
                    {
                        worklist.push(addr);
                    }
                }
                Terminator::CondBranch {
                    true_target,
                    false_target,
                    ..
                } => {
                    for target in [true_target, false_target] {
                        if let Some(&addr) = ctx
                            .block_cache
                            .iter()
                            .find_map(|(a, id)| if id == target { Some(a) } else { None })
                        {
                            worklist.push(addr);
                        }
                    }
                }
                // Lift-through-calls: follow the CALL's continuation (the return
                // address) so the caller's CFG past the call is lifted. The call
                // target itself is NOT lifted — it runs in the interpreter via the
                // runtime call-out. TailCall has no continuation (it doesn't return).
                Terminator::Call { continuation, .. } if self.lift_through_calls => {
                    if let Some(&addr) = ctx
                        .block_cache
                        .iter()
                        .find_map(|(a, id)| if id == continuation { Some(a) } else { None })
                    {
                        worklist.push(addr);
                    }
                }
                _ => {}
            }

            func.add_block(block);
        }

        func.x86_instruction_bytes = std::mem::take(&mut self.lifted_instruction_bytes);
        Ok(func)
    }
}
