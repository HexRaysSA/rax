//! Interpreter core loop, block/function execution

use crate::smir::interpret::*;
use std::cmp::Ordering;
use std::collections::HashMap;

use crate::smir::ir::context::{ArchRegState, ExitReason, SmirContext, VecValue};
use crate::smir::ir::flags::{FlagSet, FlagUpdate, LazyFlagOp, LazyFlags};
use crate::smir::ir::memory::{MemoryError, SmirMemory};
use crate::smir::ir::ops::{
    HexFpOp, HexFpRecipKind, OpKind, RvVectorState, SmirOp, X86AdxKind, X86BlsKind,
    X86CacheControlKind, X86CountKind, X86OpHint, X86ThreeDNowKind, X86X87ArithmeticDestination,
    X86X87ArithmeticSource, X86X87CompareSource, X86X87Constant, X86X87ControlKind, X86X87DataKind,
    X86X87EnvWidth, X86X87FloatWidth, X86X87IntWidth, X86XSaveKind,
};
use crate::smir::ir::types::*;
use crate::smir::ir::{CallTarget, SmirBlock, SmirFunction, Terminator, TrapKind};

impl SmirInterpreter {
    /// Create a new interpreter
    pub fn new() -> Self {
        SmirInterpreter {
            block_cache: HashMap::new(),
            func_cache: HashMap::new(),
            max_insns_per_run: 10000,
            block_addrs: HashMap::new(),
        }
    }

    /// Set the maximum instructions per run
    pub fn set_max_insns(&mut self, max: u64) {
        self.max_insns_per_run = max;
    }

    /// Add a block to the cache
    pub fn add_block(&mut self, addr: GuestAddr, block: SmirBlock) {
        self.block_addrs.insert(block.id, addr);
        self.block_cache.insert(addr, block);
    }

    /// Add a function to the cache
    pub fn add_function(&mut self, func: SmirFunction) {
        let addr = func.guest_range.0;
        for block in &func.blocks {
            self.block_addrs.insert(block.id, block.guest_pc);
            self.block_cache.insert(block.guest_pc, block.clone());
        }
        self.func_cache.insert(addr, func);
    }

    /// Run until exit condition
    pub fn run(&mut self, ctx: &mut SmirContext, memory: &mut dyn SmirMemory) -> ExitReason {
        let stepping = matches!(ctx.source_arch, SourceArch::Ebpf | SourceArch::Aarch64)
            && ctx.debug.single_step;
        let budget = if stepping {
            self.max_insns_per_run.min(1)
        } else {
            self.max_insns_per_run
        };
        let limit = ctx.insn_count.saturating_add(budget);

        loop {
            // Check instruction limit
            if ctx.insn_count >= limit {
                return ExitReason::InsnLimit;
            }

            // Check for pending exit
            if let Some(reason) = ctx.exit_reason.take() {
                return reason;
            }

            if let ArchRegState::Ebpf(state) = &mut ctx.arch_regs
                && let Some(pending) = state.pending_call.take()
            {
                // The deferred phase of a legacy dual-resolution call is the
                // registry call (V0-V2 only).
                if let Err(trap) = state.config.enter_call(
                    crate::isa::ebpf::cpu::CallForm::Registry,
                    &mut state.r,
                    &mut state.call_frames,
                    pending.fault_pc,
                    pending.target_pc,
                    pending.return_pc,
                    0,
                ) {
                    ctx.pc = pending.fault_pc;
                    state.pc = ctx.pc;
                    return ExitReason::EbpfTrap(trap);
                }
                ctx.pc = pending.target_pc;
                state.pc = ctx.pc;
            }

            // Check breakpoints
            if ctx.debug.has_breakpoint(ctx.pc) {
                return ExitReason::Breakpoint { addr: ctx.pc };
            }

            // Get block from cache
            let block = match self.block_cache.get(&ctx.pc) {
                Some(b) => b.clone(),
                None if matches!(ctx.source_arch, SourceArch::Ebpf | SourceArch::Aarch64) => {
                    // Resume at an observable guest boundary inside an optimized
                    // block after an instruction limit or a retryable fault.
                    let suffix = self.block_cache.values().find_map(|block| {
                        let index = block.ops.iter().position(|op| {
                            op.guest_pc == ctx.pc
                                && matches!(
                                    op.kind,
                                    OpKind::EbpfInstruction { .. }
                                        | OpKind::ArmInstructionBegin { .. }
                                )
                        })?;
                        let mut suffix = block.clone();
                        suffix.ops = block.ops[index..].to_vec();
                        suffix.guest_pc = ctx.pc;
                        Some(suffix)
                    });
                    match suffix {
                        Some(block) => block,
                        None => return ExitReason::BlockNotFound { addr: ctx.pc },
                    }
                }
                None if ctx.source_arch == SourceArch::Hexagon => {
                    let suffix = self.block_cache.values().find_map(|block| {
                        let index = block.ops.iter().position(|op| {
                            op.guest_pc == ctx.pc && matches!(op.kind, OpKind::HexagonPacketBegin)
                        })?;
                        let mut suffix = block.clone();
                        suffix.ops = block.ops[index..].to_vec();
                        suffix.guest_pc = ctx.pc;
                        Some(suffix)
                    });
                    match suffix {
                        Some(block) => block,
                        None => return ExitReason::BlockNotFound { addr: ctx.pc },
                    }
                }
                None => return ExitReason::BlockNotFound { addr: ctx.pc },
            };

            // Execute block
            match self.execute_block_limited(ctx, memory, &block, limit) {
                BlockResult::Continue(next_pc) => {
                    ctx.pc = next_pc;
                    if ctx.source_arch == SourceArch::Ebpf {
                        ctx.arch_regs.set_pc(next_pc);
                    }
                }
                BlockResult::Exit(ExitReason::InsnLimit) if stepping && ctx.insn_count >= limit => {
                    return ExitReason::SingleStep;
                }
                BlockResult::Exit(reason) => return reason,
            }

            // Single-step mode
            if ctx.debug.single_step {
                return ExitReason::SingleStep;
            }
        }
    }

    /// Execute a single block
    pub fn execute_block(
        &self,
        ctx: &mut SmirContext,
        memory: &mut dyn SmirMemory,
        block: &SmirBlock,
    ) -> BlockResult {
        self.execute_block_limited(ctx, memory, block, u64::MAX)
    }

    /// Translate a failed eBPF guest access into the direct-CPU trap: the
    /// faulting instruction, the effective start address computed from the
    /// unmodified operands, the access width in bytes, and its direction
    /// (read-modify-write atomics are writes). Backend error addresses are not
    /// used because their convention differs (`FlatMemory` reports the end).
    fn ebpf_memory_trap(
        &self,
        ctx: &SmirContext,
        op: &SmirOp,
    ) -> Option<crate::isa::ebpf::EbpfTrap> {
        let (addr, width, write) = match &op.kind {
            OpKind::Load { addr, width, .. } => (addr, *width, false),
            OpKind::Store { addr, width, .. } => (addr, *width, true),
            OpKind::AtomicRmw { addr, width, .. } | OpKind::Cas { addr, width, .. } => {
                (addr, *width, true)
            }
            _ => return None,
        };
        Some(crate::isa::ebpf::EbpfTrap::MemoryFault {
            pc: op.guest_pc,
            fault: crate::isa::ebpf::EbpfMemFault {
                addr: self.compute_address(ctx, addr),
                size: width.bytes() as usize,
                write,
            },
        })
    }

    fn execute_block_limited(
        &self,
        ctx: &mut SmirContext,
        memory: &mut dyn SmirMemory,
        block: &SmirBlock,
        limit: u64,
    ) -> BlockResult {
        if block.ops.iter().any(|op| {
            matches!(
                op.kind,
                OpKind::ArmInstructionBegin { .. }
                    | OpKind::ArmInstructionCommit { .. }
                    | OpKind::ArmPauth(..)
            )
        }) {
            return self.execute_aarch64_boundaries(ctx, memory, block, limit);
        }
        if ctx.source_arch == SourceArch::Hexagon
            && block.ops.iter().any(|op| {
                matches!(
                    op.kind,
                    OpKind::HexagonPacketBegin | OpKind::HexagonPacketCommit
                )
            })
        {
            return self.execute_hexagon_packets(ctx, memory, block, limit);
        }
        let ebpf = ctx.source_arch == SourceArch::Ebpf;
        let guest_boundaries = ebpf
            && block
                .ops
                .iter()
                .any(|op| matches!(op.kind, OpKind::EbpfInstruction { .. }));
        for op in &block.ops {
            if let OpKind::EbpfInstruction {
                dialect,
                endian,
                size,
            } = op.kind
            {
                let ArchRegState::Ebpf(state) = &mut ctx.arch_regs else {
                    return BlockResult::Exit(ExitReason::Undefined {
                        addr: op.guest_pc,
                        opcode: 0,
                    });
                };
                if ctx.debug.has_breakpoint(op.guest_pc) {
                    ctx.pc = op.guest_pc;
                    state.pc = op.guest_pc;
                    return BlockResult::Exit(ExitReason::Breakpoint { addr: op.guest_pc });
                }
                // The configured eBPF instruction meter is a fatal guest trap,
                // as in the direct CPU and the Anza reference; only the
                // interpreter's own run budget is a resumable slice.
                let meter_exhausted = state
                    .config
                    .max_instructions
                    .is_some_and(|max| ctx.insn_count >= max);
                if meter_exhausted || ctx.insn_count >= limit {
                    ctx.pc = op.guest_pc;
                    state.pc = op.guest_pc;
                    return BlockResult::Exit(if meter_exhausted {
                        ExitReason::EbpfTrap(crate::isa::ebpf::EbpfTrap::ExceededMaxInstructions {
                            pc: op.guest_pc,
                        })
                    } else {
                        ExitReason::InsnLimit
                    });
                }
                if !matches!(size, 8 | 16) {
                    return BlockResult::Exit(ExitReason::Undefined {
                        addr: op.guest_pc,
                        opcode: 0,
                    });
                }
                state.config.dialect = dialect;
                state.config.endian = endian;
                ctx.pc = op.guest_pc;
                state.pc = op.guest_pc;
                ctx.insn_count = ctx.insn_count.saturating_add(1);
                // Mirror the direct CPU fetch after its metering: the slot must
                // be aligned and inside the text, and a 16-byte LDDW must end
                // inside it.
                if let Err(trap) = state.config.validate_target_pc(op.guest_pc, op.guest_pc) {
                    return BlockResult::Exit(ExitReason::EbpfTrap(trap));
                }
                if size == 16
                    && let Some((_, end)) = state.config.text_range
                    && op.guest_pc.checked_add(16).is_none_or(|next| next > end)
                {
                    return BlockResult::Exit(ExitReason::EbpfTrap(
                        crate::isa::ebpf::EbpfTrap::DecodeError {
                            pc: op.guest_pc,
                            error: crate::isa::ebpf::EbpfDecodeError::UnexpectedEof {
                                needed: 16,
                                available: end.saturating_sub(op.guest_pc) as usize,
                            },
                        },
                    ));
                }
            }

            if let Err(e) = self.execute_op(ctx, memory, op) {
                if ebpf && let Some(trap) = self.ebpf_memory_trap(ctx, op) {
                    return BlockResult::Exit(ExitReason::EbpfTrap(trap));
                }
                return BlockResult::Exit(ExitReason::MemoryFault {
                    addr: match e {
                        MemoryError::PageFault { addr, .. } => addr,
                        MemoryError::AccessViolation { addr, .. } => addr,
                        MemoryError::Alignment { addr, .. } => addr,
                        MemoryError::Mmio { addr, .. } => addr,
                        MemoryError::OutOfBounds { addr } => addr,
                        MemoryError::ExclusiveFailed => ctx.pc,
                    },
                    write: match e {
                        MemoryError::PageFault { write, .. }
                        | MemoryError::AccessViolation { write, .. } => write,
                        // These error variants do not carry an access direction;
                        // recover it from the faulting operation's memory-effect
                        // metadata rather than misreporting every store as a read.
                        _ => op.kind.writes_memory(),
                    },
                });
            }
            if !guest_boundaries {
                ctx.insn_count = ctx.insn_count.saturating_add(1);
            }
            if let Some(reason) = ctx.exit_reason.take() {
                if matches!(reason, ExitReason::Syscall { .. })
                    && let ArchRegState::Ebpf(state) = &mut ctx.arch_regs
                    && let Terminator::Call {
                        target: CallTarget::GuestAddr(target),
                        continuation,
                        ..
                    } = &block.terminator
                {
                    state.pending_call = Some(crate::smir::ir::context::EbpfPendingCall {
                        target_pc: *target,
                        fault_pc: op.guest_pc,
                        return_pc: self
                            .block_addrs
                            .get(continuation)
                            .copied()
                            .unwrap_or_else(|| op.guest_pc.wrapping_add(8)),
                    });
                }
                return BlockResult::Exit(reason);
            }
        }

        // Execute terminator
        self.execute_terminator(ctx, memory, &block.terminator)
    }

    /// OR the Hexagon USR sticky overflow/saturation bit (USR:0) into the
    /// context's USR register, preserving all other bits. Used by saturating
    /// ops whose `fSATN`/`fSATUN` semantics set `fSET_OVF` when a clamp
    /// clobbered the value.
    #[inline]
    pub(crate) fn set_hex_ovf(ctx: &mut SmirContext) {
        let usr = ctx.read_arch_reg(ArchReg::Hexagon(HexagonReg::Usr));
        ctx.write_arch_reg(ArchReg::Hexagon(HexagonReg::Usr), usr | 1);
    }

    /// Execute a single operation
    pub(crate) fn execute_op(
        &self,
        ctx: &mut SmirContext,
        memory: &mut dyn SmirMemory,
        op: &SmirOp,
    ) -> Result<(), MemoryError> {
        if let OpKind::ArmPauth(operation) = op.kind {
            let result = if let ArchRegState::Aarch64(state) = &mut ctx.arch_regs {
                arm_pauth::execute_pauth(state, memory, operation, op.guest_pc)
            } else {
                Err(arm_pauth::unsupported(op.guest_pc, "AArch64 PAuth state"))
            };
            if let Err(reason) = result {
                ctx.request_exit(reason);
            } else if let ArchRegState::Aarch64(state) = &ctx.arch_regs {
                ctx.flags.lazy = None;
                ctx.flags.materialized =
                    crate::smir::ir::flags::MaterializedFlags::from_nzcv(state.nzcv);
            }
            return Ok(());
        }
        if matches!(
            op.kind,
            OpKind::ArmInstructionBegin { .. } | OpKind::ArmInstructionCommit { .. }
        ) {
            ctx.request_exit(arm_pauth::unsupported(
                op.guest_pc,
                "AArch64 instruction framing",
            ));
            return Ok(());
        }
        let arm_flags = Self::arm_alu_prior_flags(ctx, &op.kind);
        self.execute_op_arithmetic(ctx, memory, op)?;
        if let Some(prior) = arm_flags {
            Self::commit_arm_alu_flags(ctx, &op.kind, prior);
        }
        Ok(())
    }

    /// Execute block terminator
    pub(crate) fn execute_terminator(
        &self,
        ctx: &mut SmirContext,
        memory: &mut dyn SmirMemory,
        term: &Terminator,
    ) -> BlockResult {
        match term {
            Terminator::Branch { target } => {
                let addr = self
                    .block_addrs
                    .get(target)
                    .copied()
                    .unwrap_or(target.0 as u64);
                BlockResult::Continue(addr)
            }

            Terminator::CondBranch {
                cond,
                true_target,
                false_target,
            } => {
                let cond_val = ctx.read_vreg(*cond);
                let target = if cond_val != 0 {
                    true_target
                } else {
                    false_target
                };
                let addr = self
                    .block_addrs
                    .get(target)
                    .copied()
                    .unwrap_or(target.0 as u64);
                BlockResult::Continue(addr)
            }

            Terminator::Switch {
                index,
                targets,
                default,
            } => {
                let idx = ctx.read_vreg(*index) as usize;
                let target = if idx < targets.len() {
                    &targets[idx]
                } else {
                    default
                };
                let addr = self
                    .block_addrs
                    .get(target)
                    .copied()
                    .unwrap_or(target.0 as u64);
                BlockResult::Continue(addr)
            }

            Terminator::IndirectBranch { target, .. } => {
                let addr = ctx.read_vreg(*target);
                BlockResult::Continue(addr)
            }

            Terminator::IndirectBranchMem { addr, .. } => {
                let target_addr = self.compute_address(ctx, addr);
                let val = self
                    .load_memory(memory, target_addr, MemWidth::B8, SignExtend::Zero)
                    .unwrap_or(0);
                BlockResult::Continue(val)
            }

            Terminator::Return { values: _ } => {
                if let ArchRegState::Ebpf(state) = &mut ctx.arch_regs {
                    if let Some(frame) = state.call_frames.pop() {
                        state.r[6..10].copy_from_slice(&frame.caller_saved_regs);
                        state.r[10] = frame.frame_pointer;
                        return BlockResult::Continue(frame.return_pc);
                    }
                    ctx.pc = ctx.pc.wrapping_add(8);
                    state.pc = ctx.pc;
                    return BlockResult::Exit(ExitReason::Return { to: state.r[0] });
                }
                // Get return address from arch-specific location
                let ret_addr = match &ctx.arch_regs {
                    ArchRegState::X86_64(x86) => {
                        // Pop from stack
                        let rsp = x86.gpr[4];
                        let mut buf = [0u8; 8];
                        if memory.read(rsp, &mut buf).is_ok() {
                            u64::from_le_bytes(buf)
                        } else {
                            0
                        }
                    }
                    ArchRegState::Aarch64(arm) => arm.x[30], // LR
                    ArchRegState::Hexagon(hex) => hex.lr as u64,
                    ArchRegState::RiscV(rv) => rv.x[1], // ra
                    ArchRegState::Ebpf(ebpf) => ebpf.r[0],
                };
                BlockResult::Exit(ExitReason::Return { to: ret_addr })
            }

            Terminator::Call {
                target,
                args: _,
                continuation,
            } => {
                let target_addr = match target {
                    CallTarget::GuestAddr(addr) => *addr,
                    CallTarget::GuestAddrInterworking { addr, .. } => *addr,
                    CallTarget::Direct(fid) => self
                        .func_cache
                        .get(&(fid.0 as u64))
                        .map(|f| f.guest_range.0)
                        .unwrap_or(0),
                    CallTarget::Indirect(reg) => ctx.read_vreg(*reg),
                    CallTarget::IndirectInterworking(reg) => {
                        u64::from(ctx.read_vreg(*reg) as u32) & !1
                    }
                    CallTarget::IndirectMem(addr) => {
                        let target_addr = self.compute_address(ctx, addr);
                        self.load_memory(memory, target_addr, MemWidth::B8, SignExtend::Zero)
                            .unwrap_or(0)
                    }
                    CallTarget::X86IndirectMemAddr32(addr) => {
                        let target_addr = self.compute_x86_addr32(ctx, addr);
                        self.load_memory(memory, target_addr, MemWidth::B8, SignExtend::Zero)
                            .unwrap_or(0)
                    }
                    CallTarget::Runtime(_) => {
                        // Return to continuation for runtime calls
                        let addr = self
                            .block_addrs
                            .get(continuation)
                            .copied()
                            .unwrap_or(continuation.0 as u64);
                        return BlockResult::Continue(addr);
                    }
                };
                if let ArchRegState::Ebpf(state) = &mut ctx.arch_regs {
                    let target_addr = if state.config.dialect.is_solana()
                        && matches!(target, CallTarget::Indirect(_))
                    {
                        target_addr & !7
                    } else {
                        target_addr
                    };
                    let return_pc = self
                        .block_addrs
                        .get(continuation)
                        .copied()
                        .unwrap_or_else(|| ctx.pc.wrapping_add(8));
                    let form = crate::isa::ebpf::cpu::CallForm::of_guest_call(
                        state.config.dialect,
                        matches!(target, CallTarget::Indirect(_)),
                    );
                    // The direct CPU reports the slot-relative immediate (V3/V4
                    // relative calls) or the register value as the call key.
                    let key = match form {
                        crate::isa::ebpf::cpu::CallForm::Relative => {
                            (target_addr.wrapping_sub(return_pc) as i64 / 8) as u32
                        }
                        _ => target_addr as u32,
                    };
                    if let Err(trap) = state.config.enter_call(
                        form,
                        &mut state.r,
                        &mut state.call_frames,
                        ctx.pc,
                        target_addr,
                        return_pc,
                        key,
                    ) {
                        return BlockResult::Exit(ExitReason::EbpfTrap(trap));
                    }
                    return BlockResult::Continue(target_addr);
                }
                BlockResult::Continue(target_addr)
            }

            Terminator::TailCall { target, args: _ } => {
                let target_addr = match target {
                    CallTarget::GuestAddr(addr) => *addr,
                    CallTarget::GuestAddrInterworking { addr, .. } => *addr,
                    CallTarget::Direct(fid) => self
                        .func_cache
                        .get(&(fid.0 as u64))
                        .map(|f| f.guest_range.0)
                        .unwrap_or(0),
                    CallTarget::Indirect(reg) => ctx.read_vreg(*reg),
                    CallTarget::IndirectInterworking(reg) => {
                        u64::from(ctx.read_vreg(*reg) as u32) & !1
                    }
                    CallTarget::IndirectMem(addr) => {
                        let target_addr = self.compute_address(ctx, addr);
                        self.load_memory(memory, target_addr, MemWidth::B8, SignExtend::Zero)
                            .unwrap_or(0)
                    }
                    CallTarget::X86IndirectMemAddr32(addr) => {
                        let target_addr = self.compute_x86_addr32(ctx, addr);
                        self.load_memory(memory, target_addr, MemWidth::B8, SignExtend::Zero)
                            .unwrap_or(0)
                    }
                    CallTarget::Runtime(_) => 0,
                };
                BlockResult::Continue(target_addr)
            }

            Terminator::Trap { kind } => {
                match kind {
                    TrapKind::Halt => BlockResult::Exit(ExitReason::Halt),
                    TrapKind::Breakpoint => {
                        BlockResult::Exit(ExitReason::Breakpoint { addr: ctx.pc })
                    }
                    TrapKind::X86Debug {
                        fault_pc,
                        return_pc,
                        requires_apx,
                    } => {
                        let encoding_enabled = matches!(
                            &ctx.arch_regs,
                            ArchRegState::X86_64(x86) if !*requires_apx || x86.apx_enabled
                        );
                        if !encoding_enabled {
                            BlockResult::Exit(ExitReason::Undefined {
                                addr: *fault_pc,
                                opcode: 0,
                            })
                        } else {
                            BlockResult::Exit(ExitReason::Debug { addr: *return_pc })
                        }
                    }
                    TrapKind::X86Breakpoint {
                        fault_pc,
                        return_pc,
                        requires_apx,
                    } => {
                        let encoding_enabled = matches!(
                            &ctx.arch_regs,
                            ArchRegState::X86_64(x86) if !*requires_apx || x86.apx_enabled
                        );
                        if !encoding_enabled {
                            BlockResult::Exit(ExitReason::Undefined {
                                addr: *fault_pc,
                                opcode: 0,
                            })
                        } else {
                            BlockResult::Exit(ExitReason::X86Breakpoint {
                                fault_pc: *fault_pc,
                                return_pc: *return_pc,
                            })
                        }
                    }
                    TrapKind::X86SoftwareInterrupt {
                        vector,
                        fault_pc,
                        return_pc,
                        requires_apx,
                    } => {
                        let encoding_enabled = matches!(
                            &ctx.arch_regs,
                            ArchRegState::X86_64(x86) if !*requires_apx || x86.apx_enabled
                        );
                        if !encoding_enabled {
                            BlockResult::Exit(ExitReason::Undefined {
                                addr: *fault_pc,
                                opcode: 0,
                            })
                        } else {
                            BlockResult::Exit(ExitReason::X86SoftwareInterrupt {
                                vector: *vector,
                                fault_pc: *fault_pc,
                                return_pc: *return_pc,
                            })
                        }
                    }
                    TrapKind::X86InterruptReturn {
                        width,
                        fault_pc,
                        requires_apx,
                    } => {
                        let encoding_enabled = matches!(
                            &ctx.arch_regs,
                            ArchRegState::X86_64(x86) if !*requires_apx || x86.apx_enabled
                        );
                        if !encoding_enabled {
                            BlockResult::Exit(ExitReason::Undefined {
                                addr: *fault_pc,
                                opcode: 0,
                            })
                        } else {
                            BlockResult::Exit(ExitReason::X86InterruptReturn {
                                width: *width,
                                fault_pc: *fault_pc,
                            })
                        }
                    }
                    TrapKind::X86StringIo {
                        kind,
                        width,
                        address_width,
                        repeated,
                        memory_segment,
                        fault_pc,
                        return_pc,
                        requires_apx,
                    } => {
                        let encoding_enabled = matches!(
                            &ctx.arch_regs,
                            ArchRegState::X86_64(x86) if !*requires_apx || x86.apx_enabled
                        );
                        if !encoding_enabled {
                            BlockResult::Exit(ExitReason::Undefined {
                                addr: *fault_pc,
                                opcode: 0,
                            })
                        } else {
                            BlockResult::Exit(ExitReason::X86StringIo {
                                kind: *kind,
                                width: *width,
                                address_width: *address_width,
                                repeated: *repeated,
                                memory_segment: *memory_segment,
                                fault_pc: *fault_pc,
                                return_pc: *return_pc,
                            })
                        }
                    }
                    TrapKind::SystemCall => {
                        // Already handled in Syscall op
                        BlockResult::Continue(ctx.pc)
                    }
                    TrapKind::Undefined | TrapKind::InvalidOpcode => {
                        BlockResult::Exit(ExitReason::Undefined {
                            addr: ctx.pc,
                            opcode: 0,
                        })
                    }
                    TrapKind::GeneralProtection => {
                        BlockResult::Exit(ExitReason::GeneralProtection {
                            addr: ctx.pc,
                            error_code: 0,
                        })
                    }
                    TrapKind::DivideByZero | TrapKind::Overflow | TrapKind::Bounds => {
                        BlockResult::Exit(ExitReason::Undefined {
                            addr: ctx.pc,
                            opcode: 0,
                        })
                    }
                    TrapKind::Ebpf(trap) => BlockResult::Exit(ExitReason::EbpfTrap(*trap)),
                }
            }

            Terminator::Unreachable => BlockResult::Exit(ExitReason::Undefined {
                addr: ctx.pc,
                opcode: 0,
            }),
        }
    }
}
