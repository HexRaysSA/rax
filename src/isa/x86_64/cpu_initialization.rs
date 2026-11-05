//! Software-vCPU construction and reset, with attached memory retained.
use super::{
    DECODE_CACHE_SIZE, DecodeCacheEntry, FpuState, GuestMemoryMmap, LazyFlags, Mmu, X86_64Vcpu,
    execute,
};
#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
use super::{jit_call_enabled, jit_mem_enabled};
use crate::isa::x86_64::identity;
use crate::vm::vcpu::{Registers, SystemRegisters};
use std::sync::Arc;

impl X86_64Vcpu {
    pub fn new(id: u32, mem: Arc<GuestMemoryMmap>) -> Self {
        // Use vec! to heap-allocate the cache, then convert to boxed array
        let cache_vec = vec![DecodeCacheEntry::default(); DECODE_CACHE_SIZE];
        let decode_cache: Box<[DecodeCacheEntry; DECODE_CACHE_SIZE]> =
            cache_vec.into_boxed_slice().try_into().unwrap();

        X86_64Vcpu {
            id,
            apic_base: identity::initial_apic_base(id),
            insn_count: 0,
            instruction_faulted: false,
            regs: Registers::default(),
            sregs: SystemRegisters {
                // Intel SDM086 Vol.3A Table11-1: RESET sets CD, NW and ET.
                cr0: 0x6000_0010,
                ..SystemRegisters::default()
            },
            mmu: Mmu::new_for_cpu(mem, id),
            fpu: FpuState::default(),
            halted: false,
            interrupt_inhibit: false,
            io_pending: None,
            kernel_gs_base: 0,
            tsc_adjust: 0,
            tsc_aux: 0,
            misc_enable: execute::system::IA32_MISC_ENABLE_RESET,
            pat: execute::system::IA32_PAT_RESET,
            umwait_control: 0,
            pkru: 0,
            mxcsr: 0x1F80,
            xcr0: 1, // x87 state component always enabled
            xgetbv1_value: 0,
            xeon_phi_avx512: false,
            vp2intersect: false,
            sse4a: false,
            tbm: false,
            xop: false,
            avx10_media: false,
            avx10_vminmax: false,
            avx10_sat_convert: false,
            apx: false,

            decode_cache,
            lazy_flags: LazyFlags::default(),
            #[cfg(feature = "debug")]
            single_step: false,
            #[cfg(feature = "debug")]
            debugger_active: false,
            #[cfg(feature = "debug")]
            debug_breakpoints: std::collections::HashSet::new(),
            bios_cdrom: None,
            bios_mem_bytes: 0,
            #[cfg(all(
                feature = "smir-jit",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ))]
            jit_cache: std::collections::HashMap::new(),
            #[cfg(all(
                feature = "smir-jit",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ))]
            jit_hot: std::collections::HashMap::new(),
            #[cfg(all(
                feature = "smir-jit",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ))]
            jit_ineligible: std::collections::HashMap::new(),
            #[cfg(all(
                feature = "smir-jit",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ))]
            jit_ineligible_dirty: std::collections::HashSet::new(),
            #[cfg(all(
                feature = "smir-jit",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ))]
            jit_active_source_range: None,
            #[cfg(all(
                feature = "smir-jit",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ))]
            jit_active_region_stale: false,
            jit_mem: {
                #[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
                {
                    jit_mem_enabled() || jit_call_enabled()
                }
                #[cfg(not(all(feature = "smir-jit", target_arch = "x86_64")))]
                {
                    true
                }
            },
            jit_call: {
                #[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
                {
                    jit_call_enabled()
                }
                #[cfg(not(all(feature = "smir-jit", target_arch = "x86_64")))]
                {
                    true
                }
            },
            jit_callout_exit: None,
            #[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
            jit_mem_log: None,
            #[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
            jit_mem_trace: None,
            #[cfg(any(test, all(feature = "smir-jit", target_arch = "x86_64")))]
            jit_verify_vsib_stop: None,
            jit_vsib_resume_pc: None,
            user: None,
            jit_disabled_by_embedder: false,
        }
    }

    /// Reset architectural CPU state to power-on defaults, preserving the
    /// attached guest memory. Mirrors the field initialisation in [`new`] for
    /// every architectural and cache field touched by execution.
    pub fn reset_state(&mut self) {
        self.apic_base = identity::initial_apic_base(self.id);
        let _ = self.mmu.set_task_priority(0);
        self.jit_vsib_resume_pc = None;
        self.jit_callout_exit = None;
        self.insn_count = 0;
        self.instruction_faulted = false;
        self.regs = Registers::default();
        self.sregs = SystemRegisters {
            cr0: 0x6000_0010,
            ..SystemRegisters::default()
        };
        self.fpu = FpuState::default();
        self.lazy_flags = LazyFlags::default();
        self.halted = false;
        self.interrupt_inhibit = false;
        self.io_pending = None;
        self.kernel_gs_base = 0;
        self.tsc_adjust = 0;
        self.tsc_aux = 0;
        self.misc_enable = execute::system::IA32_MISC_ENABLE_RESET;
        self.pat = execute::system::IA32_PAT_RESET;
        self.umwait_control = 0;
        self.pkru = 0;
        self.mmu.set_data_access_state(self.regs.rflags, self.pkru);
        self.xcr0 = 1;
        self.xgetbv1_value = 0;
        self.decode_cache.iter_mut().for_each(|e| {
            e.rip = 0;
            e.bytes_len = 0;
        });
        #[cfg(all(
            feature = "smir-jit",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        {
            self.jit_cache.clear();
            self.jit_hot.clear();
            self.jit_ineligible.clear();
            self.jit_ineligible_dirty.clear();
        }
    }
}
