//! Native x86 guest-region metadata shared by compilation and execution.

use super::X86_64Vcpu;
use crate::smir::ir::SmirFunction;

/// MXCSR exception-mask bits IM..PM (bits 7..=12). Native vector execution
/// cannot translate a host #XM/SIGFPE into the precise guest SMIR exit, so all
/// six classes must remain masked at the native boundary.
#[cfg(target_arch = "x86_64")]
const X86_MXCSR_EXCEPTION_MASKS: u32 = 0x1F80;

#[cfg(target_arch = "x86_64")]
pub(super) fn jit_mxcsr_masks_all_exceptions(mxcsr: u32) -> bool {
    mxcsr & X86_MXCSR_EXCEPTION_MASKS == X86_MXCSR_EXCEPTION_MASKS
}

/// RFLAGS fields owned by native execution. Arithmetic operations materialize
/// the six status flags, while CLD/STD commit DF through the GuestRegs shadow.
#[cfg(target_arch = "x86_64")]
const X86_NATIVE_RFLAGS_MASK: u64 = crate::isa::x86_64::flags::bits::CF
    | crate::isa::x86_64::flags::bits::PF
    | crate::isa::x86_64::flags::bits::AF
    | crate::isa::x86_64::flags::bits::ZF
    | crate::isa::x86_64::flags::bits::SF
    | crate::isa::x86_64::flags::bits::OF
    | crate::isa::x86_64::flags::bits::DF;

/// Merge host-safe native RFLAGS, the AC shadow, and virtualized interrupt
/// controls without importing any other host-process flag state.
#[cfg(target_arch = "x86_64")]
pub(super) fn merge_native_rflags(
    prior: u64,
    native: u64,
    ac_flag: bool,
    interrupt_flags: u64,
) -> u64 {
    let interrupt_control = crate::isa::x86_64::execute::system::X86_INTERRUPT_CONTROL_RFLAGS_MASK;
    (prior & !(X86_NATIVE_RFLAGS_MASK | crate::isa::x86_64::flags::bits::AC | interrupt_control))
        | (native & X86_NATIVE_RFLAGS_MASK)
        | (interrupt_flags & interrupt_control)
        | if ac_flag {
            crate::isa::x86_64::flags::bits::AC
        } else {
            0
        }
}

/// A compiled native hot-block region. The lowered code is register-state
/// independent (it marshals guest state in/out per run), so one `JitRegion` is
/// cached by (RIP, mode_tag) and re-run for every later entry to that RIP until
/// an underlying guest source page is written (SMC invalidation).
pub(super) struct JitRegion {
    pub(super) exec: crate::smir::lower::runtime::ExecMem,
    pub(super) entry_offset: usize,
    /// Sorted, deduplicated 4 KiB virtual pages containing every instruction
    /// byte executed by this region. Compilation reads at most 512 contiguous
    /// bytes, so this is currently one or two pages. Keeping the complete set
    /// makes execution-time SMC protection independent of prior interpreter
    /// fetches and keeps cache invalidation exact if the lift window changes.
    pub(super) source_pages: Vec<u64>,
    /// Whether the entry trampoline must marshal native vector state.
    #[cfg(target_arch = "x86_64")]
    pub(super) uses_vector: bool,
    /// Whether state-backed XMM operations (including helper-backed masked and
    /// SSE4A scalar stores) need vector state copied through `GuestRegs`
    /// without activating the native vector entry bridge.
    #[cfg(target_arch = "x86_64")]
    pub(super) uses_xmm_state: bool,
    /// Whether a scalar state-backed operation needs architectural MXCSR
    /// marshalled without activating the native vector entry bridge.
    #[cfg(target_arch = "x86_64")]
    pub(super) uses_mxcsr_state: bool,
    /// Whether the AVX-only wrapper marshals YMM0-YMM15 while upper ZMM halves
    /// and opmasks remain state-backed.
    #[cfg(target_arch = "x86_64")]
    pub(super) avx_ymm16_vector_state: bool,
    /// Whether vector state can use AVX512F KMOVW while retaining K[63:16] in
    /// memory. False selects the general AVX512BW KMOVQ path.
    #[cfg(target_arch = "x86_64")]
    pub(super) narrow_vector_opmasks: bool,
    /// Whether the native entry bridge must marshal MM0-MM7 and enter MMX state.
    #[cfg(target_arch = "x86_64")]
    pub(super) uses_mmx: bool,
    /// Whether an x87/MMX state marker reads or commits the guest tag word.
    /// `EMMS` needs this channel without activating MM0-MM7 marshalling.
    #[cfg(target_arch = "x86_64")]
    pub(super) uses_x87_tag_state: bool,
    /// Whether a state-backed native x87 operation reads or commits the exact
    /// environment. Real compiled regions also activate the append-only raw
    /// direct-engine payload channel for callout and exit coherence.
    #[cfg(target_arch = "x86_64")]
    pub(super) uses_x87_environment_state: bool,
    /// Whether the region reads the real-time guest timestamp counter. Such a
    /// region cannot be replayed bit-for-bit by RAX_JIT_VERIFY because its
    /// interpreter replay necessarily observes a later clock value.
    #[cfg(target_arch = "x86_64")]
    pub(super) uses_timestamp: bool,
    /// Whether the region terminates in helper-backed external port I/O.
    /// Verification cannot replay an unserviced external input/output exit.
    #[cfg(target_arch = "x86_64")]
    pub(super) uses_io: bool,
    /// Guest PCs used as resume targets by synthesized backward-edge exits.
    /// Verification must observe the actual backward transition to one of
    /// these PCs, rather than stopping at an earlier forward arrival at the
    /// same internal block.
    #[cfg(target_arch = "x86_64")]
    pub(super) yielded_backward_exit_pcs: Vec<u64>,
    /// `(call_pc, return_pc)` pairs for near CALLs lowered through the direct
    /// interpreter helper. Verification must ignore any coincidental visit to
    /// the region's final exit PC while such a callee is still active, matching
    /// the helper's own run-until-return contract.
    #[cfg(target_arch = "x86_64")]
    pub(super) callout_boundaries: Vec<(u64, u64)>,
    /// Sorted exact source encodings for admitted VSIB instructions. The
    /// verifier validates a partial-lane marker against these bytes and the
    /// independently reconstructed pre-instruction state before replaying it.
    #[cfg(target_arch = "x86_64")]
    pub(super) vsib_instructions: Vec<(u64, crate::smir::ir::X86InstructionBytes)>,
}

impl JitRegion {
    #[cfg(any(test, target_arch = "x86_64"))]
    pub(super) fn collect_vsib_instructions_excluding(
        func: &SmirFunction,
        excluded: &std::collections::HashMap<crate::smir::ir::types::BlockId, u64>,
    ) -> Option<Vec<(u64, crate::smir::ir::X86InstructionBytes)>> {
        let mut instructions: Vec<_> = func
            .x86_instruction_bytes
            .iter()
            .filter_map(|(&(block, pc), bytes)| {
                (!excluded.contains_key(&block) && bytes.evex_vsib_memory_encoding().is_some())
                    .then_some((pc, *bytes))
            })
            .collect();
        instructions.sort_unstable_by_key(|&(pc, _)| pc);
        if instructions
            .windows(2)
            .any(|pair| pair[0].0 == pair[1].0 && pair[0].1 != pair[1].1)
        {
            return None;
        }
        instructions.dedup();
        Some(instructions)
    }

    #[cfg(target_arch = "x86_64")]
    pub(super) fn uses_io_excluding(
        func: &SmirFunction,
        excluded: &std::collections::HashMap<crate::smir::ir::types::BlockId, u64>,
    ) -> bool {
        func.blocks
            .iter()
            .filter(|block| !excluded.contains_key(&block.id))
            .flat_map(|block| &block.ops)
            .any(|op| {
                matches!(
                    op.kind,
                    crate::smir::ir::ops::OpKind::IoIn { .. }
                        | crate::smir::ir::ops::OpKind::IoOut { .. }
                )
            })
    }

    /// Derive the exact source-page set from pre-optimization instruction
    /// provenance. Returning `None` fails closed for an empty region or an
    /// instruction whose inclusive end overflows the linear-address space. For
    /// I retained instructions, sorting takes O(I log I) time and O(I) space.
    pub(super) fn collect_source_pages(func: &SmirFunction) -> Option<Vec<u64>> {
        let mut pages = Vec::new();
        for (&(_, pc), instruction) in &func.x86_instruction_bytes {
            let span = instruction.as_slice().len().checked_sub(1)? as u64;
            let end = pc.checked_add(span)?;
            pages.push(pc & !0xFFF);
            pages.push(end & !0xFFF);
        }
        pages.sort_unstable();
        pages.dedup();
        (!pages.is_empty()).then_some(pages)
    }
}

impl X86_64Vcpu {
    /// The JIT cache key discriminator: address space (CR3), CPU mode (CS.L
    /// long-mode, CS.DB default-size), and every mutable runtime capability that
    /// changes region eligibility or lowering. A compiled region or ineligible
    /// memo can therefore never be reused after memory-helper, call-through, or
    /// native-vector MXCSR policy changes.
    #[inline]
    pub(super) fn jit_mode_tag(&self) -> u64 {
        let mode =
            (self.sregs.cr3 & !0xFFF) | (self.sregs.cs.l as u64) | ((self.sregs.cs.db as u64) << 1);

        // CR3's page-offset bits are masked above and are available as tag-only
        // discriminators. These fields exist only for the native x86-64 JIT;
        // the aarch64 lowering path has neither capability.
        #[cfg(target_arch = "x86_64")]
        {
            mode | (u64::from(self.jit_mem) << 2)
                | (u64::from(self.jit_call) << 3)
                | (u64::from(jit_mxcsr_masks_all_exceptions(self.mxcsr)) << 4)
        }
        #[cfg(target_arch = "aarch64")]
        {
            mode
        }
    }

    /// Establish the active native region before any helper can access guest
    /// memory. Marking is idempotent and costs O(P), where P is the number of
    /// source pages (currently P <= 2 for the 512-byte lift window).
    pub(super) fn jit_enter_region(&mut self, region: &JitRegion) {
        self.jit_active_source_range = region
            .source_pages
            .first()
            .copied()
            .zip(region.source_pages.last().copied());
        self.jit_active_region_stale = false;
        for &page in &region.source_pages {
            self.mmu.mark_code_page(page);
        }
    }

    /// Clear transient active-region state after the native trampoline has
    /// returned and all architectural state has been imported.
    pub(super) fn jit_leave_region(&mut self) {
        self.jit_active_source_range = None;
        self.jit_active_region_stale = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::x86_64::flags;
    use crate::smir::ir::X86InstructionBytes;
    use crate::smir::ir::types::{BlockId, FunctionId};
    use std::sync::Arc;
    use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

    fn test_vcpu() -> (X86_64Vcpu, Arc<GuestMemoryMmap>) {
        let memory =
            Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap());
        let mut vcpu = X86_64Vcpu::new(0, memory.clone());
        vcpu.sregs.cr0 = 0x21;
        vcpu.sregs.efer = 1 << 10;
        vcpu.sregs.cs.l = true;
        vcpu.regs.rflags = 0x2;
        (vcpu, memory)
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn mxcsr_native_vector_boundary_requires_every_exception_mask() {
        let masked_with_status_rounding_daz_and_ftz =
            X86_MXCSR_EXCEPTION_MASKS | 0x3F | (3 << 13) | (1 << 6) | (1 << 15);
        assert!(jit_mxcsr_masks_all_exceptions(
            masked_with_status_rounding_daz_and_ftz
        ));
        for bit in 7..=12 {
            assert!(
                !jit_mxcsr_masks_all_exceptions(
                    masked_with_status_rounding_daz_and_ftz & !(1 << bit)
                ),
                "MXCSR exception mask bit {bit}"
            );
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn native_rflags_merge_commits_status_and_df_without_host_control_leakage() {
        let interrupt_control =
            crate::isa::x86_64::execute::system::X86_INTERRUPT_CONTROL_RFLAGS_MASK;
        let preserved = 0x2 | flags::bits::TF | flags::bits::NT | flags::bits::RF;
        let prior = preserved | X86_NATIVE_RFLAGS_MASK | flags::bits::AC | interrupt_control;
        let native_bits = [
            flags::bits::CF,
            flags::bits::PF,
            flags::bits::AF,
            flags::bits::ZF,
            flags::bits::SF,
            flags::bits::OF,
            flags::bits::DF,
        ];

        for pattern in 0u64..128 {
            let native = native_bits.into_iter().enumerate().fold(
                flags::bits::ID | flags::bits::AC | flags::bits::VM,
                |value, (index, bit)| value | (((pattern >> index) & 1) * bit),
            );
            for ac_flag in [false, true] {
                for interrupt_flags in [0, interrupt_control] {
                    let expected = preserved
                        | (native & X86_NATIVE_RFLAGS_MASK)
                        | interrupt_flags
                        | if ac_flag { flags::bits::AC } else { 0 };
                    assert_eq!(
                        merge_native_rflags(prior, native, ac_flag, interrupt_flags),
                        expected,
                        "pattern={pattern:#04X}, AC={ac_flag}, interrupt={interrupt_flags:#08X}"
                    );
                }
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn jit_mode_tag_separates_runtime_capability_and_mxcsr_policies() {
        let (mut vcpu, _) = test_vcpu();
        vcpu.sregs.cr3 = 0x1234_5000;
        vcpu.sregs.cs.l = true;
        vcpu.sregs.cs.db = true;

        vcpu.set_jit_call(false);
        vcpu.set_jit_mem(false);
        let register_only = vcpu.jit_mode_tag();
        assert_eq!(register_only & !0x1F, 0x1234_5000);
        assert_eq!(register_only & 0x3, 0x3);
        assert_ne!(register_only & (1 << 4), 0);

        // Model both kinds of stale entry under the original policy. Enabling
        // helpers must select a disjoint key without scanning or clearing either
        // table, so the new capability can trigger a fresh compilation attempt.
        let head = 0x2000;
        let cached = JitRegion {
            exec: crate::smir::lower::runtime::ExecMem::new(&[0xC3]).unwrap(),
            entry_offset: 0,
            source_pages: vec![head & !0xFFF],
            uses_vector: false,
            uses_xmm_state: false,
            uses_mxcsr_state: false,
            avx_ymm16_vector_state: false,
            narrow_vector_opmasks: false,
            uses_mmx: false,
            uses_x87_tag_state: false,
            uses_x87_environment_state: false,
            uses_timestamp: false,
            uses_io: false,
            yielded_backward_exit_pcs: Vec::new(),
            callout_boundaries: Vec::new(),
            vsib_instructions: Vec::new(),
        };
        vcpu.jit_cache
            .insert((head, register_only), Some(Arc::new(cached)));
        vcpu.jit_ineligible
            .insert((head, register_only), vec![0x90]);

        vcpu.set_jit_mem(true);
        let memory = vcpu.jit_mode_tag();
        assert_eq!(register_only ^ memory, 1 << 2);
        assert!(!vcpu.jit_cache.contains_key(&(head, memory)));
        assert!(!vcpu.jit_ineligible.contains_key(&(head, memory)));

        vcpu.set_jit_call(true);
        let calls = vcpu.jit_mode_tag();
        assert_eq!(memory ^ calls, 1 << 3);
        assert!(!vcpu.jit_cache.contains_key(&(head, calls)));
        assert!(!vcpu.jit_ineligible.contains_key(&(head, calls)));

        // Restoring a policy must recover its original discriminator; this keeps
        // cache reuse deterministic rather than leaking one tag per transition.
        vcpu.set_jit_call(false);
        assert_eq!(vcpu.jit_mode_tag(), memory);
        vcpu.set_jit_mem(false);
        assert_eq!(vcpu.jit_mode_tag(), register_only);

        // A cached vector region compiled with masked exceptions cannot be
        // selected after LDMXCSR exposes host #XM/SIGFPE. Restoring the mask
        // recovers the original cache discriminator without invalidation.
        vcpu.mxcsr &= !(1 << 7);
        let unmasked = vcpu.jit_mode_tag();
        assert_eq!(register_only ^ unmasked, 1 << 4);
        assert!(!vcpu.jit_cache.contains_key(&(head, unmasked)));
        assert!(!vcpu.jit_ineligible.contains_key(&(head, unmasked)));
        vcpu.mxcsr |= 1 << 7;
        assert_eq!(vcpu.jit_mode_tag(), register_only);
    }

    #[test]
    fn vsib_source_collection_filters_non_vsib_reserved_and_excluded_metadata() {
        let mut function = SmirFunction::new(FunctionId(0), BlockId(0), 0);
        let no_exclusions = std::collections::HashMap::new();
        assert_eq!(
            JitRegion::collect_vsib_instructions_excluding(&function, &no_exclusions),
            Some(Vec::new())
        );
        let gather = X86InstructionBytes::new(&[0x62, 0xF2, 0x7D, 0x4B, 0x90, 0x0C, 0x10]).unwrap();
        let scatter =
            X86InstructionBytes::new(&[0x62, 0xF2, 0x7D, 0x4B, 0xA0, 0x0C, 0x10]).unwrap();
        for (block, pc, bytes) in [
            (0, 0x3000, gather),
            (0, 0x1000, scatter),
            (1, 0x3000, gather),
            (2, 0x2500, scatter),
            (0, 0x1800, X86InstructionBytes::new(&[0x90]).unwrap()),
            (
                0,
                0x2000,
                // k0 is reserved for gather/scatter.
                X86InstructionBytes::new(&[0x62, 0xF2, 0x7D, 0x48, 0x90, 0x0C, 0x10]).unwrap(),
            ),
            (
                0,
                0x2100,
                // VSIB requires a memory ModRM and SIB.
                X86InstructionBytes::new(&[0x62, 0xF2, 0x7D, 0x4B, 0x90, 0xCC]).unwrap(),
            ),
            (
                0,
                0x2200,
                X86InstructionBytes::new(&[0x62, 0xF2, 0x7D, 0x4B, 0x90, 0x0C]).unwrap(),
            ),
        ] {
            function
                .x86_instruction_bytes
                .insert((BlockId(block), pc), bytes);
        }
        assert_eq!(
            JitRegion::collect_vsib_instructions_excluding(
                &function,
                &std::collections::HashMap::from([(BlockId(2), 0x2500)]),
            ),
            Some(vec![(0x1000, scatter), (0x3000, gather)]),
            "source output is sorted, deduplicated, valid, and non-excluded"
        );
    }

    #[test]
    fn vsib_source_collection_rejects_conflicting_exact_bytes_for_one_pc() {
        let gather = X86InstructionBytes::new(&[0x62, 0xF2, 0x7D, 0x4B, 0x90, 0x0C, 0x10]).unwrap();
        let scatter =
            X86InstructionBytes::new(&[0x62, 0xF2, 0x7D, 0x4B, 0xA0, 0x0C, 0x10]).unwrap();
        let unused_x4 =
            X86InstructionBytes::new(&[0x62, 0xF2, 0x79, 0x4B, 0x90, 0x0C, 0x10]).unwrap();
        assert_eq!(
            gather.evex_vsib_memory_encoding(),
            unused_x4.evex_vsib_memory_encoding(),
            "ignored X4 differs in exact bytes, not VSIB semantics"
        );
        for other in [scatter, unused_x4] {
            for reverse_insertion in [false, true] {
                let mut function = SmirFunction::new(FunctionId(0), BlockId(0), 0x1000);
                let mut entries = [(0, gather), (1, gather), (2, other)];
                if reverse_insertion {
                    entries.reverse();
                }
                for (block, bytes) in entries {
                    function
                        .x86_instruction_bytes
                        .insert((BlockId(block), 0x1000), bytes);
                }
                assert_eq!(
                    JitRegion::collect_vsib_instructions_excluding(
                        &function,
                        &std::collections::HashMap::new(),
                    ),
                    None,
                    "the runtime PC must identify one exact instruction"
                );
                assert_eq!(
                    JitRegion::collect_vsib_instructions_excluding(
                        &function,
                        &std::collections::HashMap::from([(BlockId(2), 0x1000)]),
                    ),
                    Some(vec![(0x1000, gather)]),
                    "an excluded conflicting entry cannot execute natively"
                );
            }
        }
    }

    #[test]
    fn source_page_collection_fails_closed_on_missing_or_wrapping_provenance() {
        let mut function = SmirFunction::new(FunctionId(0), BlockId(0), 0);
        assert_eq!(JitRegion::collect_source_pages(&function), None);

        function.x86_instruction_bytes.insert(
            (BlockId(0), u64::MAX),
            X86InstructionBytes::new(&[0x66, 0x90]).unwrap(),
        );
        assert_eq!(JitRegion::collect_source_pages(&function), None);
    }

    #[test]
    fn region_entry_marks_cross_page_sources_on_every_run_but_compilation_does_not() {
        let (mut vcpu, memory) = test_vcpu();
        let entry = 0x2FFD;
        // MOV EAX,1 crosses from page 0x2000 into page 0x3000; RET is an
        // interpreter frontier and is deliberately absent from native source
        // provenance.
        memory
            .write_slice(&[0xB8, 1, 0, 0, 0, 0xC3], GuestAddress(entry))
            .unwrap();
        vcpu.regs.rip = entry;

        assert!(!vcpu.mmu.is_code_page(0x2000));
        assert!(!vcpu.mmu.is_code_page(0x3000));
        let region = vcpu
            .jit_compile_region()
            .unwrap()
            .expect("cross-page MOV should compile");
        assert_eq!(region.source_pages, vec![0x2000, 0x3000]);
        assert!(
            !vcpu.mmu.is_code_page(0x2000) && !vcpu.mmu.is_code_page(0x3000),
            "lookahead and successful compilation are not execution"
        );

        for run in 0..2 {
            vcpu.jit_enter_region(&region);
            assert!(vcpu.mmu.is_code_page(0x2000));
            assert!(vcpu.mmu.is_code_page(0x3000));
            assert_eq!(vcpu.jit_active_source_range, Some((0x2000, 0x3000)));
            if run == 0 {
                vcpu.invalidate_code_page(0x4000);
                assert!(!vcpu.jit_active_region_stale);
                vcpu.invalidate_code_page(0x3000);
                assert!(vcpu.jit_active_region_stale);
            } else {
                assert!(
                    !vcpu.jit_active_region_stale,
                    "each entry resets transient stale state"
                );
            }
            vcpu.jit_leave_region();
            assert_eq!(vcpu.jit_active_source_range, None);
            vcpu.mmu.clear_code_pages();
        }

        // Cache invalidation follows retained provenance rather than inferring
        // overlap solely from the cache key. The deliberately unrelated key
        // makes this assertion distinguish the two mechanisms.
        let unrelated_key = (0x7000, vcpu.jit_mode_tag());
        vcpu.jit_cache.insert(unrelated_key, Some(Arc::new(region)));
        vcpu.invalidate_code_page(0x3000);
        assert!(!vcpu.jit_cache.contains_key(&unrelated_key));

        let frontier = 0x5000;
        memory.write_slice(&[0xC3], GuestAddress(frontier)).unwrap();
        vcpu.regs.rip = frontier;
        assert!(vcpu.jit_compile_region().unwrap().is_none());
        assert!(
            !vcpu.mmu.is_code_page(frontier),
            "ineligible lookahead must not classify bytes as executed code"
        );
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn scalar_store_helper_deopts_when_only_the_last_byte_is_on_a_code_page() {
        use super::super::rax_jit_mem_store;

        let (mut vcpu, memory) = test_vcpu();
        let addr = 0x2FFC;
        let before = [0xCC_u8; 8];
        memory.write_slice(&before, GuestAddress(addr)).unwrap();
        vcpu.mmu.mark_code_page(0x3000);
        assert!(!vcpu.mmu.is_code_page(addr));

        assert_eq!(
            unsafe {
                rax_jit_mem_store(
                    &mut vcpu,
                    addr,
                    0x8877_6655_4433_2211,
                    std::mem::size_of::<u64>() as u32,
                )
            },
            0
        );
        let mut after = [0_u8; 8];
        memory.read_slice(&mut after, GuestAddress(addr)).unwrap();
        assert_eq!(after, before);
    }
}
