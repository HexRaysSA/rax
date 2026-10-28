//! Bounded guest-region compilation and native admission.

use super::*;

impl X86_64Vcpu {
    /// Compile a region, optionally lowering internal backward Branch/CondBranch
    /// edges as native exits. The yielding mode is for run-loop auto promotion:
    /// it bounds each native invocation to an acyclic slice of the lifted CFG.
    pub(super) fn jit_compile_region_with_edge_exits(
        &mut self,
        yield_backward_edges: bool,
    ) -> Result<Option<JitRegion>> {
        use crate::smir::ir::Terminator;
        use crate::smir::ir::memory::MemoryError;
        #[cfg(target_arch = "x86_64")]
        use crate::smir::ir::ops::OpKind;
        use crate::smir::ir::types::SourceArch;
        use crate::smir::lift::x86_64::X86_64Lifter;
        use crate::smir::lift::{LiftContext, MemoryReader, SmirLifter};
        use crate::smir::lower::SmirLowerer;
        #[cfg(target_arch = "aarch64")]
        use crate::smir::lower::aarch64::Aarch64Lowerer;
        use crate::smir::lower::runtime::ExecMem;
        #[cfg(target_arch = "aarch64")]
        use crate::smir::lower::runtime::is_x86_aarch64_native_clobber_safe_excluding;
        #[cfg(target_arch = "x86_64")]
        use crate::smir::lower::runtime::{
            is_native_clobber_safe_excluding, uses_x86_mxcsr_state_excluding,
            uses_x86_native_mmx_excluding, uses_x86_native_vectors_excluding,
            uses_x86_x87_environment_state_excluding, uses_x86_x87_tag_state_excluding,
            uses_x86_xmm_state_excluding, x86_jit_op_uses_mem_helper,
            x86_native_mmx_features_supported_excluding, x86_native_mmx_pairs_valid_excluding,
            x86_native_scalar_features_supported_excluding,
            x86_native_vector_features_supported_excluding,
            x86_native_vector_mask_independent_excluding,
            x86_native_vector_uses_avx_ymm16_only_excluding,
            x86_native_vector_uses_k16_opmasks_excluding,
        };
        #[cfg(target_arch = "x86_64")]
        use crate::smir::lower::x86_64::{
            X86_64Lowerer, x86_far_call_terminal_shape_valid, x86_far_jump_terminal_shape_valid,
            x86_far_return_terminal_shape_valid, x86_fast_system_transfer_terminal_shape_valid,
        };
        use crate::smir::optimize::{OptLevel, optimize_function};
        use std::collections::HashMap;

        if self.jit_requires_protected_paging_fallback() {
            return Ok(None);
        }
        let entry = self.regs.rip;

        // Snapshot the largest readable prefix of a bounded guest-code window.
        // 512 B covers typical hot loops; an unmapped suffix becomes an explicit
        // interpreter frontier instead of rejecting an otherwise liftable
        // prefix.
        let bytes = match self.jit_read_lift_window(entry, JIT_LIFT_WINDOW) {
            Some(bytes) => bytes,
            None => return Ok(None),
        };

        struct Win {
            base: u64,
            bytes: Vec<u8>,
        }
        impl MemoryReader for Win {
            fn read(&self, addr: u64, size: usize) -> core::result::Result<Vec<u8>, MemoryError> {
                let off = addr
                    .checked_sub(self.base)
                    .filter(|&o| (o as usize) < self.bytes.len())
                    .ok_or(MemoryError::OutOfBounds { addr })? as usize;
                let n = (self.bytes.len() - off).min(size);
                Ok(self.bytes[off..off + n].to_vec())
            }
        }
        let reader = Win { base: entry, bytes };

        // Try lift-through-calls first (a call-heavy loop body lifts into one
        // native region with runtime call-outs). If that bigger region is
        // ineligible, retry WITHOUT call-mode (the smaller call-as-frontier
        // region). This makes lift-through-calls STRICTLY ADDITIVE — never worse
        // than the baseline mem/register JIT coverage.
        #[cfg(target_arch = "x86_64")]
        // The callout helper implements the 64-bit near-CALL contract: an
        // 8-byte return-address push and a 64-bit target. Compatibility-mode
        // CALL widths remain exact interpreter frontiers.
        let want_call = self.jit_call && self.sregs.cs.l;
        #[cfg(target_arch = "aarch64")]
        let want_call = false;
        let modes: &[bool] = if want_call { &[true, false] } else { &[false] };
        'modes: for &cm in modes {
            let mut lifter = X86_64Lifter::strict();
            lifter.set_interpreter_frontiers(true);
            lifter.set_instruction_retirement(true);
            if cm {
                lifter.set_lift_through_calls(512);
            }
            let mut lctx = LiftContext::new(SourceArch::X86_64);
            let mut func = match lifter.lift_function(entry, &reader, &mut lctx) {
                Ok(f) => f,
                Err(e) => {
                    if jit_bail_log() {
                        eprintln!("[JIT-BAIL] lift-err:{e:?} @ {entry:#x} (call={cm})");
                    }
                    continue 'modes;
                }
            };

            // Capture source pages before optimization can merge or discard IR
            // structure. A runnable region with incomplete provenance cannot be
            // protected against self-modifying code and therefore fails closed.
            let Some(source_pages) = JitRegion::collect_source_pages(&func) else {
                if jit_bail_log() {
                    eprintln!("[JIT-BAIL] source-pages @ {entry:#x} (call={cm})");
                }
                continue 'modes;
            };

            // Optimize across instruction boundaries as before, then restore
            // the original dynamic retirement CFG. Keeping the exact original
            // graph includes NOPs and merged branches whose semantic ops vanish.
            let retirement_graph = func.clone();
            func.attrs.x86_instruction_retirement = false;

            // Optimize before computing exits / lowering (frontier-aware, see note).
            if std::env::var_os("RAX_JIT_NO_OPT").is_none() {
                optimize_function(&mut func, OptLevel::O2);
            }

            if let Err(error) = crate::smir::ir::split_x86_retirement(&mut func, &retirement_graph)
            {
                if jit_bail_log() {
                    eprintln!("[JIT-BAIL] retirement:{error} @ {entry:#x} (call={cm})");
                }
                continue 'modes;
            }

            // Mark every frontier terminal as a native-exit stub (records guest
            // PC); internal Branch/CondBranch edges stay native (loops, if/else).
            let mut exits: HashMap<_, u64> = HashMap::new();
            // Block ids present in the lifted function — to validate a CALL's
            // continuation was lifted before lowering it as a call-out.
            let lifted: std::collections::HashSet<_> = func.blocks.iter().map(|b| b.id).collect();
            for b in &func.blocks {
                let frontier = match &b.terminator {
                    Terminator::Trap { .. }
                    | Terminator::Return { .. }
                    | Terminator::TailCall { .. }
                    | Terminator::IndirectBranchMem { .. }
                    | Terminator::Switch { .. } => true,
                    Terminator::IndirectBranch { .. } => {
                        #[cfg(target_arch = "x86_64")]
                        {
                            !(x86_far_jump_terminal_shape_valid(b)
                                || x86_far_call_terminal_shape_valid(b)
                                || x86_far_return_terminal_shape_valid(b)
                                || x86_fast_system_transfer_terminal_shape_valid(b))
                        }
                        #[cfg(target_arch = "aarch64")]
                        {
                            true
                        }
                    }
                    // Lift-through-calls: a CALL is NOT a frontier when call-mode
                    // is on, the continuation was lifted, and the target form is
                    // supported — it lowers to a runtime call-out and continues
                    // natively at `continuation`.
                    Terminator::Call {
                        target,
                        continuation,
                        ..
                    } => {
                        #[cfg(target_arch = "x86_64")]
                        let target_ok = jit_call_target_supported(target, self.jit_mem);
                        #[cfg(target_arch = "aarch64")]
                        let target_ok = false;
                        !(cm && target_ok && lifted.contains(continuation))
                    }
                    _ => false,
                };
                if frontier {
                    exits.insert(b.id, b.guest_pc);
                }
            }
            // Auto-promotion bounds every invocation by converting internal
            // backward edges into native exits. This also makes a closed loop
            // eligible even when it has no terminal frontier: the run loop
            // regains control at each iteration for SMC/interrupt housekeeping.
            // Explicit `jit_try_block` compilation does not request edge exits,
            // so a frontier-less loop still declines instead of running forever.
            let edge_exits = if yield_backward_edges {
                Self::jit_backward_native_exit_edges(&func, &exits)
            } else {
                HashMap::new()
            };
            #[cfg(target_arch = "x86_64")]
            let mut yielded_backward_exit_pcs: Vec<u64> = edge_exits.values().copied().collect();
            #[cfg(target_arch = "x86_64")]
            {
                yielded_backward_exit_pcs.sort_unstable();
                yielded_backward_exit_pcs.dedup();
            }
            #[cfg(target_arch = "x86_64")]
            let mut callout_boundaries = Vec::new();
            #[cfg(target_arch = "x86_64")]
            if cm {
                let block_pcs: HashMap<_, _> = func
                    .blocks
                    .iter()
                    .map(|block| (block.id, block.guest_pc))
                    .collect();
                let mut metadata_complete = true;
                for block in &func.blocks {
                    let Terminator::Call {
                        target,
                        continuation,
                        ..
                    } = &block.terminator
                    else {
                        continue;
                    };
                    if !jit_call_target_supported(target, self.jit_mem)
                        || !lifted.contains(continuation)
                    {
                        continue;
                    }
                    let Some(&return_pc) = block_pcs.get(continuation) else {
                        metadata_complete = false;
                        break;
                    };
                    let mut sites = func.x86_instruction_bytes.iter().filter_map(
                        |(&(instruction_block, pc), instruction)| {
                            (instruction_block == block.id
                                && pc.checked_add(instruction.as_slice().len() as u64)
                                    == Some(return_pc))
                            .then_some(pc)
                        },
                    );
                    let Some(call_pc) = sites.next() else {
                        metadata_complete = false;
                        break;
                    };
                    if sites.next().is_some() {
                        metadata_complete = false;
                        break;
                    }
                    callout_boundaries.push((call_pc, return_pc));
                }
                if !metadata_complete {
                    // The lowerer also rejects missing/ambiguous CALL
                    // provenance. Fail this mode before producing unverifiable
                    // runtime metadata and retry the call-as-frontier mode.
                    continue 'modes;
                }
                callout_boundaries.sort_unstable();
            }
            #[cfg(target_arch = "x86_64")]
            let has_native_terminal = func
                .blocks
                .iter()
                .filter(|block| !exits.contains_key(&block.id))
                .any(|block| {
                    x86_far_jump_terminal_shape_valid(block)
                        || x86_far_call_terminal_shape_valid(block)
                        || x86_far_return_terminal_shape_valid(block)
                        || x86_fast_system_transfer_terminal_shape_valid(block)
                });
            #[cfg(target_arch = "aarch64")]
            let has_native_terminal = false;
            if exits.is_empty() && edge_exits.is_empty() && !has_native_terminal {
                if jit_bail_log() {
                    eprintln!("[JIT-BAIL] no-frontier @ {entry:#x} (call={cm})");
                }
                continue 'modes;
            }
            // Entry block is itself a frontier ⇒ no native work.
            if exits.contains_key(&func.entry) {
                if jit_bail_log() {
                    // Diagnostic: WHY is the entry a frontier? Print the entry
                    // terminator's shape (and, for a Call, why it stayed a
                    // frontier) so we can see what lift-through-calls must crack.
                    let why = func
                        .blocks
                        .iter()
                        .find(|b| b.id == func.entry)
                        .map(|b| match &b.terminator {
                            Terminator::Trap { .. } => "Trap".to_string(),
                            Terminator::Return { .. } => "Return".to_string(),
                            Terminator::TailCall { .. } => "TailCall".to_string(),
                            Terminator::IndirectBranch { .. } => "IndirectBranch".to_string(),
                            Terminator::IndirectBranchMem { .. } => "IndirectBranchMem".to_string(),
                            Terminator::Switch { .. } => "Switch".to_string(),
                            Terminator::Call {
                                target,
                                continuation,
                                ..
                            } => {
                                let tk = target.kind_name();
                                format!("Call/{tk}(lifted-cont={})", lifted.contains(continuation))
                            }
                            _ => "other".to_string(),
                        })
                        .unwrap_or_else(|| "?".to_string());
                    eprintln!("[JIT-BAIL] entry-frontier:{why} @ {entry:#x} (call={cm})");
                }
                continue 'modes;
            }
            // Standalone x86-64 SMIR models original-VEX CMPccXADD plus the
            // 64-bit FSGSBASE/SWAPGS and MONITOR/MWAIT/WAITPKG contracts, but
            // this CPU can also compile compatibility-mode regions. Reject
            // these mode-dependent ops before native admission and let the
            // direct decoder apply compatibility-mode operand/address and
            // exception rules. CS.L is in the JIT cache tag.
            #[cfg(target_arch = "x86_64")]
            if !self.sregs.cs.l
                && func
                    .blocks
                    .iter()
                    .filter(|block| !exits.contains_key(&block.id))
                    .flat_map(|block| &block.ops)
                    .any(|op| {
                        matches!(
                            op.kind,
                            OpKind::AtomicCmpXadd { .. }
                                | OpKind::X86CacheMaintenance { .. }
                                | OpKind::X86FsGsBase { .. }
                                | OpKind::X86SwapGs { .. }
                                | OpKind::X86MonitorMwait(..)
                                | OpKind::X86WaitPkg(..)
                                | OpKind::X86LoadMxcsr { .. }
                                | OpKind::X86StoreMxcsr { .. }
                                | OpKind::X86Msr(..)
                                | OpKind::X86ReadControl { .. }
                                | OpKind::X86Smsw(..)
                                | OpKind::X86Lmsw(..)
                                | OpKind::X86DescriptorTableStore(..)
                                | OpKind::X86DescriptorTableLoad(..)
                                | OpKind::X86Invlpg(..)
                                | OpKind::X86Invpcid(..)
                                | OpKind::X86SystemSelectorStore(..)
                                | OpKind::X86SystemSelectorLoad(..)
                                | OpKind::X86SelectorVerify(..)
                                | OpKind::X86SelectorQuery(..)
                                | OpKind::X86FarJump(..)
                                | OpKind::X86FarCall(..)
                                | OpKind::X86FarReturn(..)
                                | OpKind::X86Enter(..)
                                | OpKind::X86Leave(..)
                                | OpKind::X86StackFlags(..)
                                | OpKind::X86FastSystemTransfer(..)
                                | OpKind::X86WriteControl { .. }
                                | OpKind::X86ReadDebug { .. }
                                | OpKind::X86WriteDebug { .. }
                        )
                    })
            {
                if jit_bail_log() {
                    eprintln!("[JIT-BAIL] long-mode-system-op @ {entry:#x}");
                }
                continue 'modes;
            }
            // Fail-safe gate over the EXECUTED (non-exit) blocks.
            #[cfg(target_arch = "x86_64")]
            let allow_mem = self.jit_mem;
            #[cfg(target_arch = "x86_64")]
            let uses_vector = {
                if !x86_native_scalar_features_supported_excluding(&func, &exits) {
                    if jit_bail_log() {
                        eprintln!("[JIT-BAIL] host-scalar-features @ {entry:#x} (call={cm})");
                    }
                    continue 'modes;
                }
                let uses_vector = uses_x86_native_vectors_excluding(&func, &exits);
                if uses_vector && !x86_native_vector_features_supported_excluding(&func, &exits) {
                    if jit_bail_log() {
                        eprintln!("[JIT-BAIL] host-vector-features @ {entry:#x} (call={cm})");
                    }
                    continue 'modes;
                }
                if uses_vector
                    && !jit_mxcsr_masks_all_exceptions(self.mxcsr)
                    && (!crate::smir::lower::runtime::x86_native_unmasked_mxcsr_supported()
                        || !x86_native_vector_mask_independent_excluding(&func, &exits))
                {
                    if jit_bail_log() {
                        eprintln!("[JIT-BAIL] unmasked-mxcsr @ {entry:#x} (call={cm})");
                    }
                    continue 'modes;
                }
                uses_vector
            };
            #[cfg(target_arch = "x86_64")]
            let avx_ymm16_vector_state =
                uses_vector && x86_native_vector_uses_avx_ymm16_only_excluding(&func, &exits);
            #[cfg(target_arch = "x86_64")]
            let narrow_vector_opmasks = uses_vector
                && !avx_ymm16_vector_state
                && x86_native_vector_uses_k16_opmasks_excluding(&func, &exits);
            #[cfg(target_arch = "x86_64")]
            let uses_xmm_state = uses_x86_xmm_state_excluding(&func, &exits);
            #[cfg(target_arch = "x86_64")]
            let uses_mxcsr_state = uses_x86_mxcsr_state_excluding(&func, &exits);
            #[cfg(target_arch = "x86_64")]
            let uses_mmx = uses_x86_native_mmx_excluding(&func, &exits);
            #[cfg(target_arch = "x86_64")]
            let uses_x87_tag_state = uses_x86_x87_tag_state_excluding(&func, &exits);
            #[cfg(target_arch = "x86_64")]
            let uses_x87_environment_state =
                uses_x86_x87_environment_state_excluding(&func, &exits);
            #[cfg(target_arch = "x86_64")]
            let uses_timestamp = func
                .blocks
                .iter()
                .filter(|block| !exits.contains_key(&block.id))
                .flat_map(|block| &block.ops)
                .any(|op| {
                    matches!(
                        op.kind,
                        OpKind::X86ReadTsc(..) | OpKind::X86ReadPmc(..) | OpKind::X86Msr(..)
                    )
                });
            #[cfg(target_arch = "x86_64")]
            let uses_io = JitRegion::uses_io_excluding(&func, &exits);
            #[cfg(target_arch = "x86_64")]
            let Some(vsib_instructions) =
                JitRegion::collect_vsib_instructions_excluding(&func, &exits)
            else {
                continue 'modes;
            };
            #[cfg(target_arch = "x86_64")]
            if uses_mmx && !x86_native_mmx_features_supported_excluding(&func, &exits) {
                if jit_bail_log() {
                    eprintln!("[JIT-BAIL] host-mmx-features @ {entry:#x} (call={cm})");
                }
                continue 'modes;
            }
            #[cfg(target_arch = "x86_64")]
            if !x86_native_mmx_pairs_valid_excluding(&func, &exits) {
                if jit_bail_log() {
                    eprintln!("[JIT-BAIL] mmx-state-pair @ {entry:#x} (call={cm})");
                }
                continue 'modes;
            }
            #[cfg(target_arch = "x86_64")]
            let uses_mem_helpers = allow_mem
                && func
                    .blocks
                    .iter()
                    .filter(|block| !exits.contains_key(&block.id))
                    .any(|block| {
                        block
                            .ops
                            .iter()
                            .any(|op| x86_jit_op_uses_mem_helper(&op.kind))
                            || matches!(
                                &block.terminator,
                                Terminator::Call { target, .. }
                                    if jit_call_target_uses_mem_helper(target)
                            )
                    });
            #[cfg(target_arch = "x86_64")]
            {
                if !is_native_clobber_safe_excluding(&func, &exits, allow_mem) {
                    if jit_bail_log() {
                        eprintln!(
                            "[JIT-BAIL] gate:{} @ {:#x} (call={cm})",
                            jit_classify_bail(&func, &exits, allow_mem),
                            entry
                        );
                    }
                    continue 'modes;
                }
            }
            #[cfg(target_arch = "aarch64")]
            if !is_x86_aarch64_native_clobber_safe_excluding(&func, &exits) {
                if jit_bail_log() {
                    eprintln!("[JIT-BAIL] x86-aarch64-gate @ {entry:#x}");
                }
                continue 'modes;
            }

            #[cfg(target_arch = "aarch64")]
            let mut lowerer = Aarch64Lowerer::new();
            #[cfg(target_arch = "aarch64")]
            lowerer.set_x86_guest_state_guards(true);
            #[cfg(target_arch = "x86_64")]
            let mut lowerer = X86_64Lowerer::new();
            #[cfg(target_arch = "x86_64")]
            lowerer.set_narrow_vector_opmask_helpers(narrow_vector_opmasks);
            #[cfg(target_arch = "x86_64")]
            lowerer.set_avx_ymm16_vector_state(avx_ymm16_vector_state);
            #[cfg(target_arch = "x86_64")]
            lowerer.set_native_vector_state_active(uses_vector);
            #[cfg(target_arch = "x86_64")]
            lowerer.set_guest_pcrel_lea_immediates(true);
            #[cfg(target_arch = "x86_64")]
            lowerer.set_jit_fault_deopt_guards(true);
            #[cfg(target_arch = "x86_64")]
            lowerer.set_preserve_mmx_helpers(uses_mmx);
            #[cfg(target_arch = "x86_64")]
            lowerer.set_preserve_vector_system_helpers(uses_vector);
            lowerer.set_native_exits(exits);
            lowerer.set_native_exit_edges(edge_exits);
            #[cfg(target_arch = "x86_64")]
            if allow_mem {
                lowerer.set_mem_helpers(true);
                lowerer.set_preserve_vector_mem_helpers(uses_vector && uses_mem_helpers);
            }
            #[cfg(target_arch = "x86_64")]
            if cm {
                // Lower CALL terminators as runtime call-outs (rax_jit_call).
                lowerer.set_call_helpers(true);
                lowerer.set_preserve_vector_call_helpers(uses_vector);
            }
            let res = match lowerer.lower_function(&func) {
                Ok(r) if r.relocations.is_empty() => r,
                Ok(r) => {
                    if jit_bail_log() {
                        eprintln!(
                            "[JIT-BAIL] relocs:{} @ {:#x} (call={cm})",
                            r.relocations.len(),
                            entry
                        );
                    }
                    continue 'modes;
                }
                Err(e) => {
                    if jit_bail_log() {
                        eprintln!("[JIT-BAIL] lower-err:{e:?} @ {entry:#x} (call={cm})");
                    }
                    continue 'modes;
                }
            };
            let code = match lowerer.finalize() {
                Ok(c) => c,
                Err(_) => continue 'modes,
            };
            let exec = match ExecMem::new(&code) {
                Ok(m) => m,
                Err(_) => continue 'modes,
            };
            return Ok(Some(JitRegion {
                exec,
                entry_offset: res.entry_offset,
                source_pages,
                #[cfg(target_arch = "x86_64")]
                vsib_instructions,
                #[cfg(target_arch = "x86_64")]
                uses_vector,
                #[cfg(target_arch = "x86_64")]
                uses_xmm_state,
                #[cfg(target_arch = "x86_64")]
                uses_mxcsr_state,
                #[cfg(target_arch = "x86_64")]
                avx_ymm16_vector_state,
                #[cfg(target_arch = "x86_64")]
                narrow_vector_opmasks,
                #[cfg(target_arch = "x86_64")]
                uses_mmx,
                #[cfg(target_arch = "x86_64")]
                uses_x87_tag_state,
                #[cfg(target_arch = "x86_64")]
                uses_x87_environment_state,
                #[cfg(target_arch = "x86_64")]
                uses_timestamp,
                #[cfg(target_arch = "x86_64")]
                uses_io,
                #[cfg(target_arch = "x86_64")]
                yielded_backward_exit_pcs,
                #[cfg(target_arch = "x86_64")]
                callout_boundaries,
            }));
        }
        Ok(None)
    }
}
