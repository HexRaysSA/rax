//! Opt-in production RISC-V SMIR native execution path.
//!
//! [`RiscVCpu::step_jit`] preserves a one-instruction execution contract.
//! [`RiscVCpu::run_jit`] additionally forms bounded straight-line regions from
//! side-effect-free fallthrough instructions, ending a region at memory,
//! control-flow, fence, or replay-sensitive boundaries. Cache identity covers
//! every instruction parcel in the region. Native memory helpers record precise
//! synchronous traps in a stack-owned context, allowing earlier instructions in
//! a region to retire without replaying a faulting access.

use std::collections::HashMap;
use std::sync::Arc;

use super::*;
use crate::smir::RiscVLifter;
use crate::smir::ir::ops::OpKind;
use crate::smir::ir::types::{BlockId, FunctionId, OpId, SourceArch};
use crate::smir::ir::{CallingConv, SmirBlock, SmirFunction, Terminator};
use crate::smir::lift::riscv::RiscVExtensions;
use crate::smir::lift::{ControlFlow, LiftContext, LiftResult, SmirLifter};
use crate::smir::lower::SmirLowerer;
#[cfg(target_arch = "aarch64")]
use crate::smir::lower::cross::riscv_guest_to_aarch64_host::RiscVAarch64Lowerer;
#[cfg(target_arch = "x86_64")]
use crate::smir::lower::cross::riscv_guest_to_x86_64_host::RiscVX86_64Lowerer;
use crate::smir::lower::runtime::{
    ExecMem, RISCV_FP_RESULT_INVALID, RiscVAtomicCasResult, RiscVAtomicCasStatus,
    RiscVAtomicResult, RiscVFpOpCode, RiscVFpResult, RiscVGuestRegs, RiscVLoadResult,
};
use crate::smir::optimize::{OptLevel, optimize_function};

const MAX_CACHE_ENTRIES: usize = 1024;
const MAX_REGION_INSNS: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct JitKey {
    pc: u64,
    raw: [u32; MAX_REGION_INSNS],
    len: [u8; MAX_REGION_INSNS],
    count: u8,
    opt_level: u8,
}

impl JitKey {
    fn new(region: &PreparedRegion, level: OptLevel) -> Self {
        let mut key = Self {
            pc: region.start_pc,
            raw: [0; MAX_REGION_INSNS],
            len: [0; MAX_REGION_INSNS],
            count: region.instructions.len() as u8,
            opt_level: opt_level_code(level),
        };
        for (index, prepared) in region.instructions.iter().enumerate() {
            key.raw[index] = prepared.insn.raw;
            key.len[index] = prepared.insn.len;
        }
        key
    }
}

fn opt_level_code(level: OptLevel) -> u8 {
    match level {
        OptLevel::O0 => 0,
        OptLevel::O1 => 1,
        OptLevel::O2 => 2,
    }
}

struct PreparedInstruction {
    pc: u64,
    insn: Insn,
    lifted: Option<LiftResult>,
}

struct PreparedRegion {
    start_pc: u64,
    instructions: Vec<PreparedInstruction>,
}

impl PreparedRegion {
    fn interpreter_only(start_pc: u64, insn: Insn) -> Self {
        Self {
            start_pc,
            instructions: vec![PreparedInstruction {
                pc: start_pc,
                insn,
                lifted: None,
            }],
        }
    }
}

struct NativeBlock {
    executable: ExecMem,
    entry_offset: usize,
    guest_pcs: Vec<u64>,
}

#[derive(Clone)]
enum CacheEntry {
    Native(Arc<NativeBlock>),
    InterpreterOnly,
}

/// Per-hart JIT cache and observability counters.
#[derive(Default)]
pub(super) struct RiscVJitCache {
    entries: HashMap<JitKey, CacheEntry>,
    cache_hits: u64,
    cache_misses: u64,
    native_executions: u64,
    interpreter_fallbacks: u64,
}

impl RiscVJitCache {
    pub(super) fn clear(&mut self) {
        *self = Self::default();
    }

    fn stats(&self) -> RiscVJitStats {
        RiscVJitStats {
            cache_entries: self.entries.len(),
            cache_hits: self.cache_hits,
            cache_misses: self.cache_misses,
            native_executions: self.native_executions,
            interpreter_fallbacks: self.interpreter_fallbacks,
        }
    }

    fn resolve(&mut self, key: JitKey, region: PreparedRegion, level: OptLevel) -> CacheEntry {
        if let Some(entry) = self.entries.get(&key) {
            self.cache_hits = self.cache_hits.wrapping_add(1);
            return entry.clone();
        }

        self.cache_misses = self.cache_misses.wrapping_add(1);
        let entry = compile_native_region(region, level)
            .map_or(CacheEntry::InterpreterOnly, CacheEntry::Native);
        if self.entries.len() >= MAX_CACHE_ENTRIES {
            self.entries.clear();
        }
        self.entries.insert(key, entry.clone());
        entry
    }
}

impl RiscVCpu {
    /// Fetch and execute one instruction through the host-native RISC-V SMIR JIT
    /// when the instruction lies inside the admitted native boundary.
    ///
    /// Unsupported instructions, vector operations, environmental operations,
    /// and lowering failures execute through the interpreter using the same
    /// already-decoded instruction. The ordinary [`Self::step`] path never
    /// enters native code.
    pub fn step_jit(&mut self, level: OptLevel) -> RiscVExit {
        self.step_jit_region(level, 1).0
    }

    /// Run bounded straight-line native regions until a non-`Continue` exit or
    /// the architectural instruction budget is exhausted.
    ///
    /// Interrupts are sampled between regions. A region contains only
    /// fallthrough instructions and terminates at operations capable of
    /// changing memory or other state external to the exclusively borrowed
    /// hart, so no newly observable interrupt source is skipped within a
    /// region.
    pub fn run_jit(&mut self, max_insns: u64, level: OptLevel) -> RiscVExit {
        let mut remaining = max_insns;
        while remaining != 0 {
            let region_limit = remaining.min(MAX_REGION_INSNS as u64) as usize;
            let (exit, consumed) = self.step_jit_region(level, region_limit);
            debug_assert!(consumed > 0 && consumed <= remaining);
            remaining -= consumed;
            if exit != RiscVExit::Continue {
                return exit;
            }
        }
        RiscVExit::Continue
    }

    fn step_jit_region(&mut self, level: OptLevel, max_insns: usize) -> (RiscVExit, u64) {
        debug_assert!((1..=MAX_REGION_INSNS).contains(&max_insns));
        if let Some(trap) = self.pending_machine_interrupt() {
            self.deliver_trap(trap, self.pc);
            return (RiscVExit::Continue, 1);
        }

        let pc = self.pc;
        if let Some(trap) = self.instruction_fetch_alignment_trap(pc) {
            self.deliver_trap(trap, pc);
            return (RiscVExit::Trap(trap), 1);
        }
        let insn = match decode_at(self.mem.as_ref(), pc, self.cfg.xlen, &self.cfg.isa) {
            Ok(insn) => insn,
            Err(DecodeError::Fetch(_)) => {
                let trap = Trap {
                    cause: cause::INSTR_ACCESS_FAULT,
                    tval: pc,
                };
                self.deliver_trap(trap, pc);
                return (RiscVExit::Trap(trap), 1);
            }
        };
        let region = prepare_native_region(
            self.cfg,
            self.mem.as_ref(),
            pc,
            insn,
            max_insns.min(MAX_REGION_INSNS),
        );
        let key = JitKey::new(&region, level);
        let entry = self.jit.resolve(key, region, level);
        let CacheEntry::Native(block) = entry else {
            return (self.execute_jit_fallback(&insn, pc), 1);
        };

        self.execute_native_region(&block, &insn, pc)
    }

    fn execute_native_region(
        &mut self,
        block: &NativeBlock,
        first_insn: &Insn,
        start_pc: u64,
    ) -> (RiscVExit, u64) {
        let instruction_count = block.guest_pcs.len() as u64;
        let reservation_before = self.reservation;
        let memory = self.mem.as_mut() as *mut dyn Memory;
        let reservation = &mut self.reservation as *mut Option<u64>;
        let mut context = JitContext {
            memory,
            reservation,
            address_mask: self.xmask(),
            fault: None,
        };
        let mut state = self.export_jit_state();
        state.ctx = (&mut context as *mut JitContext) as usize as u64;
        state.load_fn = jit_load as *const () as usize as u64;
        state.store_fn = jit_store as *const () as usize as u64;
        state.atomic_rmw_fn = jit_atomic_rmw as *const () as usize as u64;
        state.cas_fn = jit_compare_and_swap as *const () as usize as u64;
        state.cas_pair_fn = jit_compare_and_swap_pair as *const () as usize as u64;
        state.load_exclusive_fn = jit_load_exclusive as *const () as usize as u64;
        state.store_exclusive_fn = jit_store_exclusive as *const () as usize as u64;
        state.clear_exclusive_fn = jit_clear_exclusive as *const () as usize as u64;
        state.int_crypto_fn = jit_int_crypto as *const () as usize as u64;
        state.fp_fn = jit_scalar_fp as *const () as usize as u64;
        state.vector_fn = jit_vector as *const () as usize as u64;

        block.executable.run_riscv(block.entry_offset, &mut state);
        self.jit.native_executions = self.jit.native_executions.wrapping_add(1);

        match (state.exit_reason, context.fault) {
            (0, None) => {
                self.import_jit_state(&state);
                self.cycle = self.cycle.wrapping_add(instruction_count);
                self.instret = self.instret.wrapping_add(instruction_count);
                (RiscVExit::Continue, instruction_count)
            }
            (1, Some(trap)) => {
                let fault_pc = state.pc & self.xmask();
                let fault_index = block
                    .guest_pcs
                    .iter()
                    .position(|candidate| *candidate == fault_pc)
                    .unwrap_or_else(|| {
                        debug_assert!(false, "native helper reported an unrecognized guest PC");
                        // A region admits at most one memory instruction and makes
                        // it final. Never replay an access after a reported fault;
                        // the final index is therefore the only conservative
                        // retirement frontier if lowerer metadata is malformed.
                        block.guest_pcs.len() - 1
                    });
                // A Zcmt table entry is architecturally a second instruction
                // fetch. The shared byte-read helper reports ordinary load
                // faults, so reclassify this isolated table access here.
                let trap = if matches!(first_insn.op, Op::CmJt | Op::CmJalt)
                    && trap.cause == cause::LOAD_ACCESS_FAULT
                {
                    Trap {
                        cause: cause::INSTR_ACCESS_FAULT,
                        tval: trap.tval,
                    }
                } else {
                    trap
                };
                // State writes from earlier instructions precede the helper
                // exit, while the faulting instruction's destination write is
                // guarded by the helper success result. Import those retired
                // writes before architectural trap delivery.
                self.import_jit_state(&state);
                self.cycle = self.cycle.wrapping_add(fault_index as u64 + 1);
                self.instret = self.instret.wrapping_add(fault_index as u64);
                self.deliver_trap(trap, fault_pc);
                (RiscVExit::Trap(trap), fault_index as u64 + 1)
            }
            _ => {
                // Non-memory native failures (for example an illegal dynamic
                // FP rounding mode) are replay-safe only for deliberately
                // isolated single-instruction blocks. Restore non-state ABI
                // data before executing the decoded interpreter path.
                assert_eq!(
                    instruction_count, 1,
                    "a multi-instruction native region requested unsafe replay"
                );
                self.reservation = reservation_before;
                (self.execute_jit_fallback(first_insn, start_pc), 1)
            }
        }
    }

    /// Current JIT cache and execution counters.
    pub fn jit_stats(&self) -> RiscVJitStats {
        self.jit.stats()
    }

    /// Drop all cached native/interpreter decisions and reset JIT counters.
    pub fn clear_jit_cache(&mut self) {
        self.jit.clear();
    }

    fn execute_jit_fallback(&mut self, insn: &Insn, pc: u64) -> RiscVExit {
        self.jit.interpreter_fallbacks = self.jit.interpreter_fallbacks.wrapping_add(1);
        self.cycle = self.cycle.wrapping_add(1);
        match self.execute(insn, pc) {
            Ok(exit) => {
                self.account_retired_exit(exit);
                exit
            }
            Err(trap) => {
                self.deliver_trap(trap, pc);
                RiscVExit::Trap(trap)
            }
        }
    }

    fn export_jit_state(&self) -> RiscVGuestRegs {
        let mut state = RiscVGuestRegs {
            x: self.x,
            f: self.f,
            pc: self.pc,
            fcsr: u64::from(self.fcsr),
            vl: self.vl,
            vtype: self.vtype,
            vstart: self.vstart,
            vcsr: self.vcsr(),
            jvt: self.jvt,
            ..Default::default()
        };
        for register in 0..32 {
            let start = register * VLENB as usize;
            state.v[register].copy_from_slice(&self.v[start..start + VLENB as usize]);
        }
        state
    }

    fn import_jit_state(&mut self, state: &RiscVGuestRegs) {
        self.x = state.x.map(|value| value & self.xmask());
        self.x[0] = 0;
        self.f = state.f;
        self.pc = state.pc & self.xmask();
        self.fcsr = state.fcsr as u32 & 0xff;
        self.vl = state.vl;
        self.vtype = state.vtype;
        self.vstart = state.vstart;
        self.set_vcsr(state.vcsr);
        self.jvt = state.jvt & !0x3f & self.xmask();
        for register in 0..32 {
            let start = register * VLENB as usize;
            self.v[start..start + VLENB as usize].copy_from_slice(&state.v[register]);
        }
    }
}

fn decoded_native_boundary(cfg: RiscVConfig, insn: &Insn) -> bool {
    // The shared decoder has already applied reserved-field, XLEN, and
    // extension-profile checks. Never let a hand-written lifter reinterpret a
    // parcel that the architectural decoder classified as illegal.
    if insn.is_illegal() {
        return false;
    }

    // Control-flow instruction-alignment traps without C are currently an
    // interpreter-only boundary: the scalar lifter represents only the target.
    if !cfg.isa.c
        && matches!(
            insn.op,
            Op::Jal | Op::Jalr | Op::Beq | Op::Bne | Op::Blt | Op::Bge | Op::Bltu | Op::Bgeu
        )
    {
        return false;
    }
    true
}

fn prepare_native_region(
    cfg: RiscVConfig,
    memory: &dyn Memory,
    start_pc: u64,
    first_insn: Insn,
    max_insns: usize,
) -> PreparedRegion {
    let extensions = extensions_for_isa(&cfg.isa);
    let mut lifter = match cfg.xlen {
        Xlen::Rv32 => RiscVLifter::new_rv32(extensions),
        Xlen::Rv64 => RiscVLifter::new_rv64(extensions),
    };
    let source_arch = match cfg.xlen {
        Xlen::Rv32 => SourceArch::RiscV32,
        Xlen::Rv64 => SourceArch::RiscV64,
    };
    let mut context = LiftContext::new(source_arch);
    let mut instructions = Vec::with_capacity(max_insns);
    let mut pc = start_pc;
    let mut insn = first_insn;
    let address_mask = match cfg.xlen {
        Xlen::Rv32 => u64::from(u32::MAX),
        Xlen::Rv64 => u64::MAX,
    };

    while instructions.len() < max_insns {
        if !decoded_native_boundary(cfg, &insn) {
            break;
        }
        let raw = insn.raw.to_le_bytes();
        let bytes = &raw[..usize::from(insn.len)];
        let Ok(lifted) = lifter.lift_insn(pc, bytes, &mut context) else {
            break;
        };
        if !admit_lifted_instruction(&insn, &lifted)
            || (!instructions.is_empty() && !safe_after_region_prefix(&lifted))
        {
            break;
        }

        let can_continue = region_can_continue(&lifted);
        let bytes_consumed = lifted.bytes_consumed as u64;
        instructions.push(PreparedInstruction {
            pc,
            insn,
            lifted: Some(lifted),
        });
        if instructions.len() == max_insns || !can_continue {
            break;
        }

        pc = pc.wrapping_add(bytes_consumed) & address_mask;
        // The Memory interface does not distinguish normal executable RAM
        // from read-sensitive device space. Region formation therefore assumes
        // instruction fetches are observationally pure, as required for any
        // ahead-of-execution decode cache; architectural state is still left
        // untouched until the native region runs.
        let Ok(next) = decode_at(memory, pc, cfg.xlen, &cfg.isa) else {
            break;
        };
        insn = next;
    }

    if instructions.is_empty() {
        PreparedRegion::interpreter_only(start_pc, first_insn)
    } else {
        PreparedRegion {
            start_pc,
            instructions,
        }
    }
}

fn safe_after_region_prefix(lifted: &LiftResult) -> bool {
    matches!(
        lifted.control_flow,
        ControlFlow::Fallthrough | ControlFlow::NextInsn
    ) && !lifted.ops.iter().any(|op| {
        matches!(
            op.kind,
            OpKind::RvFp { .. }
                | OpKind::RvVector { .. }
                | OpKind::Syscall { .. }
                | OpKind::Breakpoint
                | OpKind::Undefined { .. }
        )
    })
}

fn region_can_continue(lifted: &LiftResult) -> bool {
    matches!(
        lifted.control_flow,
        ControlFlow::Fallthrough | ControlFlow::NextInsn
    ) && !lifted.ops.iter().any(|op| {
        matches!(
            op.kind,
            OpKind::Load { .. }
                | OpKind::Store { .. }
                | OpKind::PredLoad { .. }
                | OpKind::PredStore { .. }
                | OpKind::AtomicLoad { .. }
                | OpKind::AtomicStore { .. }
                | OpKind::AtomicRmw { .. }
                | OpKind::Cas { .. }
                | OpKind::CasPair { .. }
                | OpKind::LoadExclusive { .. }
                | OpKind::StoreExclusive { .. }
                | OpKind::ClearExclusive
                | OpKind::Fence { .. }
                | OpKind::RvFp { .. }
                | OpKind::RvVector { .. }
                | OpKind::Syscall { .. }
                | OpKind::Breakpoint
                | OpKind::Undefined { .. }
        )
    })
}

fn compile_native_region(region: PreparedRegion, level: OptLevel) -> Option<Arc<NativeBlock>> {
    let guest_pcs = region
        .instructions
        .iter()
        .map(|prepared| prepared.pc)
        .collect::<Vec<_>>();
    let (mut function, return_pcs) = function_for_region(region)?;
    optimize_function(&mut function, level);
    #[cfg(target_arch = "x86_64")]
    let mut lowerer = RiscVX86_64Lowerer::new();
    #[cfg(target_arch = "aarch64")]
    let mut lowerer = RiscVAarch64Lowerer::new();
    lowerer.set_return_pcs(return_pcs);
    let lowered = lowerer.lower_function(&function).ok()?;
    let code = lowerer.finalize().ok()?;
    let executable = ExecMem::new(&code).ok()?;
    Some(Arc::new(NativeBlock {
        executable,
        entry_offset: lowered.entry_offset,
        guest_pcs,
    }))
}

fn function_for_region(
    mut region: PreparedRegion,
) -> Option<(SmirFunction, HashMap<BlockId, u64>)> {
    if region.instructions.len() == 1 {
        let prepared = region.instructions.pop()?;
        return function_for_lift(prepared.pc, prepared.lifted?);
    }

    let entry = BlockId(0);
    let end_pc = region.instructions.last().and_then(|prepared| {
        prepared
            .lifted
            .as_ref()
            .map(|lifted| prepared.pc.wrapping_add(lifted.bytes_consumed as u64))
    })?;
    let mut ops = Vec::new();
    for prepared in region.instructions {
        let lifted = prepared.lifted?;
        if !matches!(
            lifted.control_flow,
            ControlFlow::Fallthrough | ControlFlow::NextInsn
        ) {
            return None;
        }
        ops.extend(lifted.ops);
    }
    for (index, op) in ops.iter_mut().enumerate() {
        op.id = OpId(index as u16);
    }

    let mut return_pcs = HashMap::new();
    return_pcs.insert(entry, end_pc);
    let mut function = SmirFunction::new(FunctionId(0), entry, region.start_pc);
    function.blocks = vec![SmirBlock {
        id: entry,
        guest_pc: region.start_pc,
        phis: vec![],
        ops,
        terminator: Terminator::Return { values: vec![] },
        exec_count: 0,
    }];
    function.guest_range = (region.start_pc, end_pc);
    function.calling_convention = CallingConv::RiscVStd;
    Some((function, return_pcs))
}

fn admit_lifted_instruction(insn: &Insn, lifted: &LiftResult) -> bool {
    // The native FP ABI carries no privilege or mstatus.FS state. Keep scalar
    // and vector FP instructions, plus the FP CSRs, on the architectural path
    // so their FS=Off checks cannot be bypassed by native execution.
    if insn.op.is_fp()
        || super::vector_validation::is_vector_fp_encoding(insn)
        || matches!(
            insn.op,
            Op::Csrrw | Op::Csrrs | Op::Csrrc | Op::Csrrwi | Op::Csrrsi | Op::Csrrci
        ) && matches!(insn.csr, 0x001..=0x003)
    {
        return false;
    }
    let mut memory_accesses = 0usize;
    for op in &lifted.ops {
        match op.kind {
            // OP-V arithmetic/configuration is transactionally executed by the
            // vector helper without guest-memory access. Vector loads/stores
            // remain interpreter-only because the generic Memory interface
            // cannot roll back partial lane effects after a later fault.
            OpKind::RvVector { insn, .. } if insn & 0x7f != 0x57 => return false,
            OpKind::Syscall { .. } | OpKind::Breakpoint => return false,
            OpKind::Load { .. }
            | OpKind::Store { .. }
            | OpKind::AtomicRmw { .. }
            | OpKind::Cas { .. }
            | OpKind::CasPair { .. }
            | OpKind::LoadExclusive { .. }
            | OpKind::StoreExclusive { .. } => memory_accesses += 1,
            _ => {}
        }
    }
    // Zcmp stack macros architecturally expose ordered partial stores/loads if
    // a later access faults; their primitive expansion implements that policy.
    // Other multi-access instructions remain excluded because the generic
    // Memory trait cannot infer or roll back their instruction-specific policy.
    memory_accesses <= 1
        || matches!(
            insn.op,
            Op::CmPush | Op::CmPop | Op::CmPopRet | Op::CmPopRetz
        )
}

fn function_for_lift(pc: u64, lifted: LiftResult) -> Option<(SmirFunction, HashMap<BlockId, u64>)> {
    let entry = BlockId(0);
    let mut return_pcs = HashMap::new();
    let mut blocks = Vec::new();
    let terminator = match lifted.control_flow {
        ControlFlow::Fallthrough | ControlFlow::NextInsn => {
            return_pcs.insert(entry, pc.wrapping_add(lifted.bytes_consumed as u64));
            Terminator::Return { values: vec![] }
        }
        ControlFlow::Branch { target } | ControlFlow::DirectBranch(target) => {
            return_pcs.insert(entry, target);
            Terminator::Return { values: vec![] }
        }
        ControlFlow::CondBranchReg {
            cond,
            taken,
            not_taken,
        } => {
            let taken_id = BlockId(1);
            let not_taken_id = BlockId(2);
            return_pcs.insert(taken_id, taken);
            return_pcs.insert(not_taken_id, not_taken);
            blocks.push(SmirBlock {
                id: taken_id,
                guest_pc: taken,
                phis: vec![],
                ops: vec![],
                terminator: Terminator::Return { values: vec![] },
                exec_count: 0,
            });
            blocks.push(SmirBlock {
                id: not_taken_id,
                guest_pc: not_taken,
                phis: vec![],
                ops: vec![],
                terminator: Terminator::Return { values: vec![] },
                exec_count: 0,
            });
            Terminator::CondBranch {
                cond,
                true_target: taken_id,
                false_target: not_taken_id,
            }
        }
        ControlFlow::IndirectBranch { target } => Terminator::IndirectBranch {
            target,
            possible_targets: vec![],
        },
        _ => return None,
    };

    let mut ops = lifted.ops;
    for (index, op) in ops.iter_mut().enumerate() {
        op.id = OpId(index as u16);
    }
    blocks.insert(
        0,
        SmirBlock {
            id: entry,
            guest_pc: pc,
            phis: vec![],
            ops,
            terminator,
            exec_count: 0,
        },
    );
    let mut function = SmirFunction::new(FunctionId(0), entry, pc);
    function.blocks = blocks;
    function.guest_range = (pc, pc.wrapping_add(lifted.bytes_consumed as u64));
    function.calling_convention = CallingConv::RiscVStd;
    Some((function, return_pcs))
}

fn extensions_for_isa(isa: &Isa) -> RiscVExtensions {
    RiscVExtensions {
        m: isa.m,
        a: isa.a,
        f: isa.f,
        d: isa.d,
        q: isa.q,
        c: isa.c,
        zicsr: isa.zicsr,
        zifencei: isa.zifencei,
        zihintpause: isa.zihintpause,
        zihintntl: isa.zihintntl,
        zacas: isa.zacas,
        zawrs: isa.zawrs,
        zicbom: isa.zicbom,
        zicboz: isa.zicboz,
        zicbop: isa.zicbop,
        zba: isa.zba,
        zbb: isa.zbb,
        zbc: isa.zbc,
        zbs: isa.zbs,
        zicond: isa.zicond,
        zfa: isa.zfa,
        zbkb: isa.zbkb,
        zfh: isa.zfh,
        zbkx: isa.zbkx,
        zknh: isa.zknh,
        zksh: isa.zksh,
        zksed: isa.zksed,
        zkne: isa.zkne,
        zknd: isa.zknd,
        zcb: isa.zcb,
        zcmp: isa.zcmp,
        zcmt: isa.zcmt,
        zclsd: isa.zclsd,
        zilsd: isa.zilsd,
        h: isa.h,
        svinval: isa.svinval,
        v: isa.v,
        xandes: isa.xandes,
        xthead: isa.xthead,
        xhazard3: isa.xhazard3,
        xida_sltw: isa.xida_sltw,
    }
}

struct JitContext {
    memory: *mut dyn Memory,
    reservation: *mut Option<u64>,
    address_mask: u64,
    fault: Option<Trap>,
}

impl JitContext {
    unsafe fn from_abi<'a>(ctx: u64) -> Option<&'a mut Self> {
        if ctx == 0 {
            None
        } else {
            Some(unsafe { &mut *(ctx as usize as *mut Self) })
        }
    }

    fn record_fault(&mut self, cause: u64, tval: u64) {
        if self.fault.is_none() {
            self.fault = Some(Trap { cause, tval });
        }
    }

    fn normalize_addr(&self, addr: u64) -> u64 {
        addr & self.address_mask
    }

    unsafe fn memory(&mut self) -> &mut dyn Memory {
        unsafe { &mut *self.memory }
    }

    unsafe fn reservation(&mut self) -> &mut Option<u64> {
        unsafe { &mut *self.reservation }
    }
}

fn valid_size(size: u64) -> Option<usize> {
    match size {
        1 | 2 | 4 | 8 => Some(size as usize),
        _ => None,
    }
}

unsafe fn jit_load_impl(ctx: u64, addr: u64, size: u64, signed: u64) -> RiscVLoadResult {
    let Some(context) = (unsafe { JitContext::from_abi(ctx) }) else {
        return RiscVLoadResult::default();
    };
    let Some(size) = valid_size(size) else {
        context.record_fault(cause::LOAD_ACCESS_FAULT, addr);
        return RiscVLoadResult::default();
    };
    let addr = context.normalize_addr(addr);
    let mut bytes = [0u8; 8];
    if unsafe { context.memory() }
        .read(addr, &mut bytes[..size])
        .is_err()
    {
        context.record_fault(cause::LOAD_ACCESS_FAULT, addr);
        return RiscVLoadResult::default();
    }
    let raw = u64::from_le_bytes(bytes);
    RiscVLoadResult {
        value: if signed != 0 {
            sign_extend(raw, size)
        } else {
            raw & mask_bytes(size)
        },
        success: 1,
    }
}

unsafe fn jit_store_impl(ctx: u64, addr: u64, value: u64, size: u64) -> u64 {
    let Some(context) = (unsafe { JitContext::from_abi(ctx) }) else {
        return 0;
    };
    let Some(size) = valid_size(size) else {
        context.record_fault(cause::STORE_ACCESS_FAULT, addr);
        return 0;
    };
    let addr = context.normalize_addr(addr);
    if unsafe { context.memory() }
        .write(addr, &value.to_le_bytes()[..size])
        .is_err()
    {
        context.record_fault(cause::STORE_ACCESS_FAULT, addr);
        return 0;
    }
    1
}

fn decode_order(order: u64) -> Option<u64> {
    (order <= 4).then_some(order)
}

fn fence_before(order: u64) {
    use std::sync::atomic::{Ordering, fence};
    match order {
        2 | 3 => fence(Ordering::Release),
        4 => fence(Ordering::SeqCst),
        _ => {}
    }
}

fn fence_after(order: u64) {
    use std::sync::atomic::{Ordering, fence};
    match order {
        1 | 3 => fence(Ordering::Acquire),
        4 => fence(Ordering::SeqCst),
        _ => {}
    }
}

unsafe fn jit_atomic_rmw_impl(
    ctx: u64,
    addr: u64,
    operand: u64,
    size: u64,
    op: u64,
    order: u64,
) -> RiscVAtomicResult {
    let Some(context) = (unsafe { JitContext::from_abi(ctx) }) else {
        return RiscVAtomicResult::default();
    };
    let addr = context.normalize_addr(addr);
    if !matches!(size, 4 | 8) || addr % size != 0 || decode_order(order).is_none() || op > 11 {
        context.record_fault(cause::STORE_MISALIGNED, addr);
        return RiscVAtomicResult::default();
    }
    fence_before(order);
    let mut bytes = [0u8; 8];
    if unsafe { context.memory() }
        .read(addr, &mut bytes[..size as usize])
        .is_err()
    {
        context.record_fault(cause::LOAD_ACCESS_FAULT, addr);
        return RiscVAtomicResult::default();
    }
    let bits = size * 8;
    let mask = if size == 8 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    };
    let old = u64::from_le_bytes(bytes) & mask;
    let operand = operand & mask;
    let signed = |value: u64| -> i64 {
        if size == 8 {
            value as i64
        } else {
            value as u32 as i32 as i64
        }
    };
    let new = match op {
        0 => old.wrapping_add(operand),
        1 => old.wrapping_sub(operand),
        2 => 0u64.wrapping_sub(old),
        3 => old & operand,
        4 => old | operand,
        5 => old ^ operand,
        6 => !(old & operand),
        7 => signed(old).max(signed(operand)) as u64,
        8 => signed(old).min(signed(operand)) as u64,
        9 => old.max(operand),
        10 => old.min(operand),
        11 => operand,
        _ => {
            context.record_fault(cause::STORE_ACCESS_FAULT, addr);
            return RiscVAtomicResult::default();
        }
    } & mask;
    if unsafe { context.memory() }
        .write(addr, &new.to_le_bytes()[..size as usize])
        .is_err()
    {
        context.record_fault(cause::STORE_ACCESS_FAULT, addr);
        return RiscVAtomicResult::default();
    }
    fence_after(order);
    RiscVAtomicResult {
        value: old,
        access_success: 1,
    }
}

unsafe fn jit_compare_and_swap_impl(
    ctx: u64,
    addr: u64,
    expected: u64,
    new_value: u64,
    size: u64,
    order: u64,
) -> RiscVAtomicCasResult {
    let Some(context) = (unsafe { JitContext::from_abi(ctx) }) else {
        return RiscVAtomicCasResult::default();
    };
    let addr = context.normalize_addr(addr);
    if !matches!(size, 4 | 8) || addr % size != 0 || decode_order(order).is_none() {
        context.record_fault(cause::STORE_MISALIGNED, addr);
        return RiscVAtomicCasResult::default();
    }
    fence_before(order);
    let mut bytes = [0u8; 8];
    if unsafe { context.memory() }
        .read(addr, &mut bytes[..size as usize])
        .is_err()
    {
        context.record_fault(cause::LOAD_ACCESS_FAULT, addr);
        return RiscVAtomicCasResult::default();
    }
    let mask = if size == 8 {
        u64::MAX
    } else {
        u64::from(u32::MAX)
    };
    let old = u64::from_le_bytes(bytes) & mask;
    if old != expected & mask {
        fence_after(order);
        return RiscVAtomicCasResult {
            old,
            status: RiscVAtomicCasStatus::CompareFailed as u64,
        };
    }
    fence_before(order);
    if unsafe { context.memory() }
        .write(addr, &(new_value & mask).to_le_bytes()[..size as usize])
        .is_err()
    {
        context.record_fault(cause::STORE_ACCESS_FAULT, addr);
        return RiscVAtomicCasResult::default();
    }
    fence_after(order);
    RiscVAtomicCasResult {
        old,
        status: RiscVAtomicCasStatus::Swapped as u64,
    }
}

#[allow(clippy::too_many_arguments)]
unsafe fn jit_compare_and_swap_pair_impl(
    ctx: u64,
    addr: u64,
    expected_lo: u64,
    expected_hi: u64,
    new_lo: u64,
    new_hi: u64,
    order: u64,
    failure_order: u64,
    out_old_hi: *mut u64,
) -> RiscVAtomicCasResult {
    let Some(context) = (unsafe { JitContext::from_abi(ctx) }) else {
        return RiscVAtomicCasResult::default();
    };
    let addr = context.normalize_addr(addr);
    let required_failure_order = if matches!(order, 1 | 3 | 4) { 1 } else { 0 };
    if addr % 16 != 0 {
        context.record_fault(cause::STORE_MISALIGNED, addr);
        return RiscVAtomicCasResult::default();
    }
    if decode_order(order).is_none() || failure_order != required_failure_order {
        context.record_fault(cause::STORE_ACCESS_FAULT, addr);
        return RiscVAtomicCasResult::default();
    }
    if out_old_hi.is_null() {
        context.record_fault(cause::STORE_ACCESS_FAULT, addr);
        return RiscVAtomicCasResult::default();
    }
    let mut bytes = [0u8; 16];
    if unsafe { context.memory() }.read(addr, &mut bytes).is_err() {
        context.record_fault(cause::LOAD_ACCESS_FAULT, addr);
        return RiscVAtomicCasResult::default();
    }
    let old = [
        u64::from_le_bytes(bytes[..8].try_into().unwrap()),
        u64::from_le_bytes(bytes[8..].try_into().unwrap()),
    ];
    let status = if old == [expected_lo, expected_hi] {
        fence_before(order);
        bytes[..8].copy_from_slice(&new_lo.to_le_bytes());
        bytes[8..].copy_from_slice(&new_hi.to_le_bytes());
        if unsafe { context.memory() }.write(addr, &bytes).is_err() {
            context.record_fault(cause::STORE_ACCESS_FAULT, addr);
            return RiscVAtomicCasResult::default();
        }
        RiscVAtomicCasStatus::Swapped
    } else {
        fence_after(failure_order);
        RiscVAtomicCasStatus::CompareFailed
    };
    if status == RiscVAtomicCasStatus::Swapped {
        fence_after(order);
    }
    unsafe { out_old_hi.write(old[1]) };
    RiscVAtomicCasResult {
        old: old[0],
        status: status as u64,
    }
}

unsafe fn jit_load_exclusive_impl(ctx: u64, addr: u64, size: u64) -> RiscVAtomicResult {
    let Some(context) = (unsafe { JitContext::from_abi(ctx) }) else {
        return RiscVAtomicResult::default();
    };
    let addr = context.normalize_addr(addr);
    if !matches!(size, 4 | 8) || addr % size != 0 {
        context.record_fault(cause::LOAD_MISALIGNED, addr);
        return RiscVAtomicResult::default();
    }
    let mut bytes = [0u8; 8];
    if unsafe { context.memory() }
        .read(addr, &mut bytes[..size as usize])
        .is_err()
    {
        context.record_fault(cause::LOAD_ACCESS_FAULT, addr);
        return RiscVAtomicResult::default();
    }
    unsafe { *context.reservation() = Some(addr) };
    RiscVAtomicResult {
        value: u64::from_le_bytes(bytes),
        access_success: 1,
    }
}

unsafe fn jit_store_exclusive_impl(
    ctx: u64,
    addr: u64,
    value: u64,
    size: u64,
) -> RiscVAtomicResult {
    let Some(context) = (unsafe { JitContext::from_abi(ctx) }) else {
        return RiscVAtomicResult::default();
    };
    let addr = context.normalize_addr(addr);
    if !matches!(size, 4 | 8) || addr % size != 0 {
        context.record_fault(cause::STORE_MISALIGNED, addr);
        return RiscVAtomicResult::default();
    }
    let succeeds = unsafe { context.reservation().take() == Some(addr) };
    let access = if succeeds {
        unsafe { context.memory() }.write(addr, &value.to_le_bytes()[..size as usize])
    } else {
        // A failed RISC-V SC generates no store, but it must still pass the
        // store address's memory-permission check before reporting failure.
        unsafe { context.memory() }.probe(addr, size as usize, true)
    };
    if access.is_err() {
        context.record_fault(cause::STORE_ACCESS_FAULT, addr);
        return RiscVAtomicResult::default();
    }
    RiscVAtomicResult {
        value: u64::from(succeeds),
        access_success: 1,
    }
}

unsafe fn jit_clear_exclusive_impl(ctx: u64) {
    if let Some(context) = unsafe { JitContext::from_abi(ctx) } {
        unsafe { *context.reservation() = None };
    }
}

fn int_crypto_op(code: u64) -> Option<Op> {
    Some(match code {
        0 => Op::Clmul,
        1 => Op::Clmulh,
        2 => Op::Clmulr,
        3 => Op::Xperm4,
        4 => Op::Xperm8,
        5 => Op::Sha512Sig0l,
        6 => Op::Sha512Sig0h,
        7 => Op::Sha512Sig1l,
        8 => Op::Sha512Sig1h,
        9 => Op::Sha512Sum0r,
        10 => Op::Sha512Sum1r,
        11 => Op::Sm4ed,
        12 => Op::Sm4ks,
        13 => Op::Aes32esi,
        14 => Op::Aes32esmi,
        15 => Op::Aes32dsi,
        16 => Op::Aes32dsmi,
        17 => Op::Aes64es,
        18 => Op::Aes64esm,
        19 => Op::Aes64ds,
        20 => Op::Aes64dsm,
        21 => Op::Aes64im,
        22 => Op::Aes64ks1i,
        23 => Op::Aes64ks2,
        _ => return None,
    })
}

unsafe fn jit_int_crypto_impl(op_code: u64, src1: u64, src2: u64, imm: u64, xlen: u64) -> u64 {
    let Some(op) = int_crypto_op(op_code) else {
        return 0;
    };
    let Ok(xlen) = u32::try_from(xlen) else {
        return 0;
    };
    super::super::crypto::eval_int_crypto(op, src1, src2, imm as u8, xlen).unwrap_or(0)
}

unsafe fn jit_scalar_fp_impl(
    op_code: u64,
    rm_field: u64,
    fcsr: u64,
    a: u64,
    b: u64,
    c: u64,
) -> RiscVFpResult {
    let Some(op_code) = RiscVFpOpCode::from_code(op_code) else {
        return RiscVFpResult {
            value: 0,
            fcsr_status: RISCV_FP_RESULT_INVALID,
        };
    };
    let Some((value, new_fcsr)) = super::super::float::eval_scalar_fp(
        op_code.into_op(),
        rm_field as u8,
        fcsr as u32,
        a,
        b,
        c,
    ) else {
        return RiscVFpResult {
            value: 0,
            fcsr_status: RISCV_FP_RESULT_INVALID,
        };
    };
    RiscVFpResult {
        value,
        fcsr_status: u64::from(new_fcsr),
    }
}

unsafe fn jit_vector_impl(state: *mut RiscVGuestRegs, insn: u64, xlen: u64) -> u64 {
    let Some(state) = (unsafe { state.as_mut() }) else {
        return 0;
    };
    let Ok(insn) = u32::try_from(insn) else {
        return 0;
    };
    // Only memory-free OP-V is admitted by the production dispatcher. Keep the
    // helper independently fail-closed if malformed lowered IR calls it with a
    // vector load/store or another opcode.
    if insn & 0x7f != 0x57 {
        return 0;
    }
    let (config, decode_xlen) = match xlen {
        32 => (RiscVConfig::rv32(Isa::rv64gc()), Xlen::Rv32),
        64 => (RiscVConfig::rv64gc(), Xlen::Rv64),
        _ => return 0,
    };
    let decoded = super::super::decode::decode(insn, decode_xlen, &config.isa);
    if decoded.is_illegal() {
        return 0;
    }

    // Execute over an empty memory object: an admitted OP-V instruction must
    // not observe or mutate guest memory. All architectural results remain in
    // this transient hart until exact success, making a zero return fully
    // transactional with respect to the caller's state ABI.
    let mut cpu = RiscVCpu::new(
        config,
        Box::new(super::super::memory::FlatMemory::new(0, 0)),
    );
    cpu.set_pc(state.pc);
    for register in 1..32u8 {
        cpu.set_x(register, state.x[register as usize]);
    }
    for register in 0..32u8 {
        cpu.set_f(register, state.f[register as usize]);
        cpu.set_vreg(register, &state.v[register as usize]);
    }
    cpu.set_fcsr(state.fcsr as u32);
    cpu.set_vl_vtype(state.vl, state.vtype);
    cpu.set_vstart(state.vstart);
    cpu.set_vcsr(state.vcsr);

    if !matches!(
        cpu.execute_insn(&decoded, state.pc),
        Ok(RiscVExit::Continue)
    ) {
        return 0;
    }

    state.x[0] = 0;
    for register in 1..32u8 {
        state.x[register as usize] = cpu.x(register);
    }
    for register in 0..32u8 {
        state.f[register as usize] = cpu.f(register);
        state.v[register as usize] = cpu.vreg(register);
    }
    state.fcsr = u64::from(cpu.fcsr());
    state.vl = cpu.vl();
    state.vtype = cpu.vtype();
    state.vstart = cpu.vstart();
    state.vcsr = cpu.vcsr();
    1
}

// The x86-64 code generator intentionally uses the SysV ABI even on targets
// whose platform C ABI differs. AArch64 uses AAPCS64, which is its C ABI.
// Keep one semantic implementation per helper and expose architecture-correct
// entry wrappers to generated code.
macro_rules! define_jit_abi {
    ($name:ident, $implementation:ident, ($($arg:ident: $ty:ty),* $(,)?) -> $ret:ty) => {
        #[cfg(target_arch = "x86_64")]
        unsafe extern "sysv64" fn $name($($arg: $ty),*) -> $ret {
            unsafe { $implementation($($arg),*) }
        }

        #[cfg(target_arch = "aarch64")]
        unsafe extern "C" fn $name($($arg: $ty),*) -> $ret {
            unsafe { $implementation($($arg),*) }
        }
    };
}

define_jit_abi!(jit_load, jit_load_impl, (ctx: u64, addr: u64, size: u64, signed: u64) -> RiscVLoadResult);
define_jit_abi!(jit_store, jit_store_impl, (ctx: u64, addr: u64, value: u64, size: u64) -> u64);
define_jit_abi!(jit_atomic_rmw, jit_atomic_rmw_impl, (ctx: u64, addr: u64, operand: u64, size: u64, op: u64, order: u64) -> RiscVAtomicResult);
define_jit_abi!(jit_compare_and_swap, jit_compare_and_swap_impl, (ctx: u64, addr: u64, expected: u64, new_value: u64, size: u64, order: u64) -> RiscVAtomicCasResult);
define_jit_abi!(jit_compare_and_swap_pair, jit_compare_and_swap_pair_impl, (ctx: u64, addr: u64, expected_lo: u64, expected_hi: u64, new_lo: u64, new_hi: u64, order: u64, failure_order: u64, out_old_hi: *mut u64) -> RiscVAtomicCasResult);
define_jit_abi!(jit_load_exclusive, jit_load_exclusive_impl, (ctx: u64, addr: u64, size: u64) -> RiscVAtomicResult);
define_jit_abi!(jit_store_exclusive, jit_store_exclusive_impl, (ctx: u64, addr: u64, value: u64, size: u64) -> RiscVAtomicResult);
define_jit_abi!(jit_clear_exclusive, jit_clear_exclusive_impl, (ctx: u64) -> ());
define_jit_abi!(jit_int_crypto, jit_int_crypto_impl, (op_code: u64, src1: u64, src2: u64, imm: u64, xlen: u64) -> u64);
define_jit_abi!(jit_scalar_fp, jit_scalar_fp_impl, (op_code: u64, rm_field: u64, fcsr: u64, a: u64, b: u64, c: u64) -> RiscVFpResult);
define_jit_abi!(jit_vector, jit_vector_impl, (state: *mut RiscVGuestRegs, insn: u64, xlen: u64) -> u64);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::riscv::{FlatMemory, MemError, Memory};
    use std::sync::atomic::{AtomicUsize, Ordering};

    const CODE: u64 = 0x1000;
    const DATA: u64 = 0x2000;
    const MEMORY_LEN: usize = 0x4000;

    #[derive(Debug)]
    struct CountingMemory {
        bytes: Vec<u8>,
        watched_addr: u64,
        watched_reads: Arc<AtomicUsize>,
    }

    impl CountingMemory {
        fn new(watched_addr: u64, watched_reads: Arc<AtomicUsize>) -> Self {
            Self {
                bytes: vec![0; MEMORY_LEN],
                watched_addr,
                watched_reads,
            }
        }

        fn range(&self, addr: u64, size: usize) -> Result<std::ops::Range<usize>, MemError> {
            let start = usize::try_from(addr).map_err(|_| MemError::OutOfBounds { addr, size })?;
            let end = start
                .checked_add(size)
                .filter(|end| *end <= self.bytes.len())
                .ok_or(MemError::OutOfBounds { addr, size })?;
            Ok(start..end)
        }
    }

    impl Memory for CountingMemory {
        fn read(&self, addr: u64, buf: &mut [u8]) -> Result<(), MemError> {
            if addr == self.watched_addr {
                self.watched_reads.fetch_add(1, Ordering::SeqCst);
            }
            let range = self.range(addr, buf.len())?;
            buf.copy_from_slice(&self.bytes[range]);
            Ok(())
        }

        fn write(&mut self, addr: u64, data: &[u8]) -> Result<(), MemError> {
            let range = self.range(addr, data.len())?;
            self.bytes[range].copy_from_slice(data);
            Ok(())
        }
    }

    fn cpu_with_counted_memory(watched_addr: u64) -> (RiscVCpu, Arc<AtomicUsize>) {
        let reads = Arc::new(AtomicUsize::new(0));
        let memory = CountingMemory::new(watched_addr, Arc::clone(&reads));
        (
            RiscVCpu::new(RiscVConfig::rv64gc(), Box::new(memory)),
            reads,
        )
    }

    fn lw_x0_from_x1() -> u32 {
        (1 << 15) | (0b010 << 12) | 0x03
    }

    fn cpu_with_word(word: u32) -> RiscVCpu {
        cpu_with_config_word(RiscVConfig::rv64gc(), word)
    }

    fn cpu_with_config_word(config: RiscVConfig, word: u32) -> RiscVCpu {
        let mut cpu = RiscVCpu::new(config, Box::new(FlatMemory::new(0, MEMORY_LEN)));
        cpu.write_memory(CODE, &word.to_le_bytes()).unwrap();
        cpu.set_pc(CODE);
        cpu
    }

    fn cpu_with_half(config: RiscVConfig, half: u16) -> RiscVCpu {
        let mut cpu = RiscVCpu::new(config, Box::new(FlatMemory::new(0, MEMORY_LEN)));
        cpu.write_memory(CODE, &half.to_le_bytes()).unwrap();
        cpu.set_pc(CODE);
        cpu
    }

    fn config(xlen: Xlen, isa: Isa) -> RiscVConfig {
        RiscVConfig { xlen, isa }
    }

    #[test]
    fn jit_fallback_counts_only_normally_completed_instructions_as_retired() {
        for level in [OptLevel::O0, OptLevel::O2] {
            for (word, expected_exit, expected_instret) in [
                (0x1050_0073, RiscVExit::Wfi, 1),
                (0x0000_0073, RiscVExit::Ecall, 0),
                (0x0010_0073, RiscVExit::Ebreak, 0),
            ] {
                let mut cpu = cpu_with_word(word);
                assert_eq!(cpu.step_jit(level), expected_exit, "{level:?}");
                assert_eq!(cpu.cycle, 1, "{level:?}, word={word:#010x}");
                assert_eq!(
                    cpu.instret(),
                    expected_instret,
                    "{level:?}, word={word:#010x}"
                );
            }
        }
    }

    #[test]
    fn jit_fallback_rejects_rv32_only_counter_high_csrs_on_rv64() {
        for level in [OptLevel::O0, OptLevel::O2] {
            let mut cpu = cpu_with_word(0xC800_20F3); // csrr x1, cycleh
            cpu.set_x(1, 0xfeed_face);
            assert_eq!(
                cpu.step_jit(level),
                RiscVExit::Trap(Trap::illegal(0)),
                "{level:?}"
            );
            assert_eq!(cpu.x(1), 0xfeed_face, "{level:?}");
            assert_eq!(cpu.instret(), 0, "{level:?}");
        }
    }

    #[test]
    fn jit_fallback_preserves_csr_privilege_and_counter_traps() {
        let cases = [
            (0x3050_20f3, Trap::illegal(0x3050_20f3)), // csrr x1, mtvec
            (0xc000_20f3, Trap::illegal(0)),           // csrr x1, cycle with CY=0
        ];
        for level in [OptLevel::O0, OptLevel::O2] {
            for (word, trap) in cases {
                let mut cpu = cpu_with_word(word);
                cpu.set_privilege(Priv::User);
                cpu.set_x(1, 0xfeed_face);
                assert_eq!(cpu.step_jit(level), RiscVExit::Trap(trap), "{level:?}");
                assert_eq!(cpu.x(1), 0xfeed_face, "{level:?}");
                assert_eq!(cpu.instret(), 0, "{level:?}");
                assert_eq!(cpu.jit_stats().native_executions, 0, "{level:?}");
                assert_eq!(cpu.jit_stats().interpreter_fallbacks, 1, "{level:?}");
            }
        }
    }

    #[test]
    fn jit_falls_back_for_fp_state_gates_at_o0_and_o2() {
        let fadd_s = 0x0031_00d3; // fadd.s f1, f2, f3
        let read_fcsr = 0x0030_20f3; // csrr x1, fcsr
        let vector_fadd_vv = (1u32 << 25) | (2 << 20) | (0b001 << 12) | (1 << 7) | 0x57;

        for level in [OptLevel::O0, OptLevel::O2] {
            for word in [fadd_s, read_fcsr] {
                let mut cpu = cpu_with_word(word);
                let expected = if word == read_fcsr {
                    Trap::illegal(0)
                } else {
                    Trap::illegal(word.into())
                };
                assert_eq!(
                    cpu.step_jit(level),
                    RiscVExit::Trap(expected),
                    "{level:?}: {word:#010x}"
                );
                assert_eq!(cpu.jit_stats().native_executions, 0, "{level:?}");
                assert_eq!(cpu.jit_stats().interpreter_fallbacks, 1, "{level:?}");
            }

            let mut vector_config = RiscVConfig::rv64gc();
            vector_config.isa.v = true;
            let mut vector = cpu_with_config_word(vector_config, vector_fadd_vv);
            vector.set_vl_vtype(4, 0x10); // e32,m1
            assert_eq!(
                vector.step_jit(level),
                RiscVExit::Trap(Trap::illegal(vector_fadd_vv.into())),
                "{level:?}: vector FP"
            );
            assert_eq!(vector.jit_stats().native_executions, 0, "{level:?}");
            assert_eq!(vector.jit_stats().interpreter_fallbacks, 1, "{level:?}");
        }
    }

    #[test]
    fn jit_checks_fetch_alignment_before_region_formation() {
        let config = RiscVConfig::rv32(Isa {
            c: false,
            ..Isa::rv64gc()
        });
        for level in [OptLevel::O0, OptLevel::O2] {
            let mut cpu = RiscVCpu::new(config, Box::new(FlatMemory::new(0, MEMORY_LEN)));
            cpu.write_memory(CODE + 2, &0x0000_0013u32.to_le_bytes())
                .unwrap();
            cpu.set_pc(CODE + 2);
            assert_eq!(
                cpu.step_jit(level),
                RiscVExit::Trap(Trap {
                    cause: cause::INSTR_MISALIGNED,
                    tval: CODE + 2,
                }),
                "{level:?}"
            );
            assert_eq!(cpu.cycle, 0, "{level:?}");
            assert_eq!(cpu.instret(), 0, "{level:?}");
            assert_eq!(cpu.jit_stats().native_executions, 0, "{level:?}");
            assert_eq!(cpu.jit_stats().interpreter_fallbacks, 0, "{level:?}");
        }
    }

    #[test]
    fn jit_falls_back_for_rv32_zfa_doubleword_moves_at_o0_and_o2() {
        let config = RiscVConfig::rv32(Isa::rv64gc());
        let fmvh_x_d = (0b1110001 << 25) | (1 << 20) | (10 << 15) | (11 << 7) | 0x53;
        let fmvp_d_x = (0b1011001 << 25) | (12 << 20) | (11 << 15) | (10 << 7) | 0x53;

        for level in [OptLevel::O0, OptLevel::O2] {
            let mut high = cpu_with_config_word(config, fmvh_x_d);
            high.csr_write(0x300, 0b01 << 13).unwrap(); // mstatus.FS=Initial
            high.set_f(10, 0x89ab_cdef_0123_4567);
            assert_eq!(high.step_jit(level), RiscVExit::Continue, "{level:?}");
            assert_eq!(high.x(11), 0x89ab_cdef, "{level:?}");
            assert_eq!(high.jit_stats().native_executions, 0, "{level:?}");
            assert_eq!(high.jit_stats().interpreter_fallbacks, 1, "{level:?}");

            let mut pack = cpu_with_config_word(config, fmvp_d_x);
            pack.csr_write(0x300, 0b01 << 13).unwrap(); // mstatus.FS=Initial
            pack.set_x(11, 0x7654_3210);
            pack.set_x(12, 0xfedc_ba98);
            assert_eq!(pack.step_jit(level), RiscVExit::Continue, "{level:?}");
            assert_eq!(pack.f(10), 0xfedc_ba98_7654_3210, "{level:?}");
            assert_eq!(pack.jit_stats().native_executions, 0, "{level:?}");
            assert_eq!(pack.jit_stats().interpreter_fallbacks, 1, "{level:?}");
        }
    }

    #[test]
    fn jit_executes_hlvx_wu_on_rv32_at_o0_and_o2() {
        let config = RiscVConfig::rv32(Isa::rv64gc());
        let hlvx_wu = (0x34 << 25) | (3 << 20) | (10 << 15) | (0b100 << 12) | (5 << 7) | 0x73;

        for level in [OptLevel::O0, OptLevel::O2] {
            let mut cpu = cpu_with_config_word(config, hlvx_wu);
            cpu.write_memory(DATA, &0xfedc_ba98u32.to_le_bytes())
                .unwrap();
            cpu.set_x(10, DATA);
            assert_eq!(cpu.step_jit(level), RiscVExit::Continue, "{level:?}");
            assert_eq!(cpu.x(5), 0xfedc_ba98, "{level:?}");
            assert_eq!(cpu.jit_stats().native_executions, 1, "{level:?}");
        }
    }

    #[test]
    fn jit_boundary_rejects_every_predecoded_illegal_compressed_encoding() {
        let full = Isa::rv64gc();
        let cases = [
            ("C.LUI rd=x0", config(Xlen::Rv64, full), 0x6005),
            ("C.ADDIW rd=x0", config(Xlen::Rv64, full), 0x2005),
            ("RV32 C.SLLI shamt[5]=1", config(Xlen::Rv32, full), 0x1402),
            (
                "C.MUL without M",
                config(Xlen::Rv64, Isa { m: false, ..full }),
                0x9C45,
            ),
            (
                "C.SEXT.B without Zbb",
                config(Xlen::Rv64, Isa { zbb: false, ..full }),
                0x9C65,
            ),
            (
                "C.ZEXT.W without Zba",
                config(Xlen::Rv64, Isa { zba: false, ..full }),
                0x9C71,
            ),
            (
                "C.FLD without D",
                config(Xlen::Rv64, Isa { d: false, ..full }),
                0x2000,
            ),
        ];

        for level in [OptLevel::O0, OptLevel::O2] {
            for (name, config, half) in cases {
                let expected = RiscVExit::Trap(Trap::illegal(half.into()));

                let mut direct = cpu_with_half(config, half);
                assert_eq!(direct.step(), expected, "direct: {name}");
                assert_eq!(direct.instret(), 0, "direct: {name}");

                let mut jit = cpu_with_half(config, half);
                assert_eq!(jit.step_jit(level), expected, "{level:?}: {name}");
                assert_eq!(jit.instret(), 0, "{level:?}: {name}");
                assert_eq!(jit.jit_stats().native_executions, 0, "{level:?}: {name}");
                assert_eq!(
                    jit.jit_stats().interpreter_fallbacks,
                    1,
                    "{level:?}: {name}"
                );
            }
        }
    }

    #[test]
    fn jit_boundary_rejects_reserved_rv32_shift_immediates() {
        let shift_imm = |funct6: u32, funct3: u32| {
            (funct6 << 26) | (0b10_0000 << 20) | (2 << 15) | (funct3 << 12) | (1 << 7) | 0x13
        };
        let words = [
            shift_imm(0b000000, 0b001), // slli
            shift_imm(0b001010, 0b001), // bseti
            shift_imm(0b010010, 0b001), // bclri
            shift_imm(0b011010, 0b001), // binvi
            shift_imm(0b000000, 0b101), // srli
            shift_imm(0b010000, 0b101), // srai
            shift_imm(0b011000, 0b101), // rori
            shift_imm(0b010010, 0b101), // bexti
        ];
        let config = RiscVConfig::rv32(Isa::rv64gc());

        for level in [OptLevel::O0, OptLevel::O2] {
            for word in words {
                let expected = RiscVExit::Trap(Trap::illegal(word));

                let mut direct = cpu_with_config_word(config, word);
                assert_eq!(direct.step(), expected, "direct: {word:#010x}");
                assert_eq!(direct.instret(), 0, "direct: {word:#010x}");

                let mut jit = cpu_with_config_word(config, word);
                assert_eq!(jit.step_jit(level), expected, "{level:?}: {word:#010x}");
                assert_eq!(jit.instret(), 0, "{level:?}: {word:#010x}");
                assert_eq!(
                    jit.jit_stats().native_executions,
                    0,
                    "{level:?}: {word:#010x}"
                );
                assert_eq!(
                    jit.jit_stats().interpreter_fallbacks,
                    1,
                    "{level:?}: {word:#010x}"
                );
            }
        }
    }

    #[test]
    fn production_jit_keeps_successful_load_to_x0_side_effects_at_o0_and_o2() {
        for level in [OptLevel::O0, OptLevel::O2] {
            let (mut cpu, reads) = cpu_with_counted_memory(DATA);
            cpu.write_memory(CODE, &lw_x0_from_x1().to_le_bytes())
                .expect("write test instruction");
            cpu.write_memory(DATA, &0x1234_5678u32.to_le_bytes())
                .expect("write test data");
            cpu.set_pc(CODE);
            cpu.set_x(1, DATA);

            assert_eq!(cpu.step_jit(level), RiscVExit::Continue);
            assert_eq!(cpu.x(0), 0);
            assert_eq!(reads.load(Ordering::SeqCst), 1, "{level:?}");
            assert_eq!(cpu.jit_stats().native_executions, 1, "{level:?}");
            assert_eq!(cpu.jit_stats().interpreter_fallbacks, 0, "{level:?}");
        }
    }

    #[test]
    fn production_jit_keeps_faulting_load_to_x0_at_o0_and_o2() {
        let fault_addr = MEMORY_LEN as u64;
        for level in [OptLevel::O0, OptLevel::O2] {
            let (mut cpu, reads) = cpu_with_counted_memory(fault_addr);
            cpu.write_memory(CODE, &lw_x0_from_x1().to_le_bytes())
                .expect("write test instruction");
            cpu.set_pc(CODE);
            cpu.set_x(1, fault_addr);

            assert_eq!(
                cpu.step_jit(level),
                RiscVExit::Trap(Trap {
                    cause: cause::LOAD_ACCESS_FAULT,
                    tval: fault_addr,
                }),
                "{level:?}"
            );
            assert_eq!(cpu.x(0), 0);
            assert_eq!(reads.load(Ordering::SeqCst), 1, "{level:?}");
            assert_eq!(cpu.jit_stats().native_executions, 1, "{level:?}");
            assert_eq!(cpu.jit_stats().interpreter_fallbacks, 0, "{level:?}");
        }
    }
}
