//! Complete represented CPU execution state, with target-owned bindings retained.
//!
//! This is an internal component of the backend record. Memory, monitor rights,
//! owned/shared controller state and device publication belong to the adapter
//! and coordinated VM transaction; this component cannot replace that boundary.

use super::native_execution::NativeExecution;
use super::*;
use serde::{Deserialize, Serialize};
use std::sync::atomic::Ordering;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CoreCheckpoint {
    x: [u64; 31],
    sp_el: [u64; 4],
    pc: u64,
    nzcv: u8,
    daif: u8,
    current_el: u8,
    sp_sel: bool,
    aarch32: Option<crate::isa::arm::aarch64::aarch32_state::Aarch32Pstate>,
    pan: bool,
    uao: bool,
    dit: bool,
    ssbs: bool,
    tco: bool,
    btype: u8,
    il: bool,
    ss: bool,
    v: [u128; 32],
    fpcr: u32,
    fpsr: u32,
    sve_vl: u16,
    sve_p: [u32; 16],
    sve_ffr: u32,
    sysregs: SystemRegisters,
    nonsecure_reset: bool,
    timer_levels: (bool, bool),
    fault_log_budget: u32,
    insn_count: u64,
    last_instruction_size: u8,
    cycle_count: u64,
    halted: bool,
    wfi: bool,
    wfe: bool,
    event_register: bool,
    pending_exceptions: Vec<ArmException>,
    config: ConfigCheckpoint,
    mmu: MmuConfig,
    monitor: (Option<u32>, u8),
    gic_present: bool,
    gic_shared: bool,
    gic_cpu_id: u32,
    instruction_guarded: bool,
    last_fault_level: u8,
    tbi_tag: u64,
    pc_ring: [[u64; 32]; 2],
    pc_ring_idx: u8,
    execution: NativeExecution,
    breakpoints: Vec<u64>,
    watchpoints: Vec<(u64, u64, WatchpointKind)>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ConfigCheckpoint {
    version: ArmVersion,
    features: u64,
    pauth: super::super::pauth::PauthConfig,
    initial_el: u8,
    gic_config: Option<GicConfig>,
    num_breakpoints: u8,
    num_watchpoints: u8,
}

fn invalid(message: &str) -> ArmError {
    ArmError::Configuration(format!("AArch64 private state: {message}"))
}

impl ConfigCheckpoint {
    fn capture(config: &AArch64Config) -> Self {
        let AArch64Config {
            version,
            features,
            pauth,
            initial_el,
            gic_config,
            num_breakpoints,
            num_watchpoints,
        } = config;
        Self {
            version: *version,
            features: features.bits(),
            pauth: *pauth,
            initial_el: *initial_el,
            gic_config: gic_config.clone(),
            num_breakpoints: *num_breakpoints,
            num_watchpoints: *num_watchpoints,
        }
    }

    fn materialize(&self) -> AArch64Config {
        AArch64Config {
            version: self.version,
            features: ArmFeatures::from_bits_retain(self.features),
            pauth: self.pauth,
            initial_el: self.initial_el,
            gic_config: self.gic_config.clone(),
            num_breakpoints: self.num_breakpoints,
            num_watchpoints: self.num_watchpoints,
        }
    }
}

impl CoreCheckpoint {
    pub(crate) fn invalidate_mapping_reservation(&mut self) {
        self.monitor = (None, 0);
    }
    pub(crate) fn owns_gic(&self) -> bool {
        self.gic_present && !self.gic_shared
    }
    pub(crate) fn capture(cpu: &AArch64Cpu) -> Result<Self, ArmError> {
        #[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
        if cpu.jit.bounded_active {
            return Err(ArmError::Configuration(
                "cannot capture AArch64 state during a native instruction".into(),
            ));
        }
        let AArch64Cpu {
            x,
            sp_el,
            pc,
            nzcv,
            daif,
            current_el,
            sp_sel,
            aarch32,
            pan,
            uao,
            dit,
            ssbs,
            tco,
            btype,
            il,
            ss,
            v,
            fpcr,
            fpsr,
            sve_vl,
            sve_p,
            sve_ffr,
            sysregs,
            nonsecure_reset,
            timer_levels,
            fault_log_budget,
            insn_count,
            last_instruction_size,
            cycle_count,
            halted,
            wfi,
            wfe,
            event_register,
            pending_exceptions,
            config,
            mmu,
            aarch32_monitor,
            gic,
            gic_shared,
            gic_cpu_id,
            instruction_guarded,
            last_fault_level,
            tbi_tag,
            pc_ring,
            pc_ring_idx,
            execution,
            breakpoints,
            watchpoints,
            memory: _,
            gic_irq_line: _,
            #[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
            jit,
        } = cpu;
        // These fields contain host code, compilation decisions and cache
        // invalidation bookkeeping. Restore reconstructs them cold.
        #[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
        let Aarch64JitState {
            cache: _,
            hot: _,
            code_pages: _,
            smc_dirty: _,
            bounded_active: _,
            bounded_runs: _,
        } = jit;
        let mut ordered_breakpoints: Vec<_> = breakpoints.iter().copied().collect();
        ordered_breakpoints.sort_unstable();
        let checkpoint = Self {
            x: *x,
            sp_el: *sp_el,
            pc: *pc,
            nzcv: *nzcv,
            daif: *daif,
            current_el: *current_el,
            sp_sel: *sp_sel,
            aarch32: *aarch32,
            pan: *pan,
            uao: *uao,
            dit: *dit,
            ssbs: *ssbs,
            tco: *tco,
            btype: *btype,
            il: *il,
            ss: *ss,
            v: *v,
            fpcr: *fpcr,
            fpsr: *fpsr,
            sve_vl: *sve_vl,
            sve_p: *sve_p,
            sve_ffr: *sve_ffr,
            sysregs: sysregs.clone(),
            nonsecure_reset: *nonsecure_reset,
            timer_levels: *timer_levels,
            fault_log_budget: *fault_log_budget,
            insn_count: *insn_count,
            last_instruction_size: *last_instruction_size,
            cycle_count: *cycle_count,
            halted: *halted,
            wfi: *wfi,
            wfe: *wfe,
            event_register: event_register.load(std::sync::atomic::Ordering::Acquire),
            pending_exceptions: pending_exceptions.clone(),
            config: ConfigCheckpoint::capture(config),
            mmu: mmu.config().clone(),
            monitor: (aarch32_monitor.address, aarch32_monitor.size),
            gic_present: gic.is_some(),
            gic_shared: *gic_shared,
            gic_cpu_id: u32::try_from(*gic_cpu_id)
                .map_err(|_| invalid("CPU binding exceeds u32"))?,
            instruction_guarded: instruction_guarded.load(Ordering::Relaxed),
            last_fault_level: last_fault_level.load(Ordering::Relaxed),
            tbi_tag: tbi_tag.load(Ordering::Relaxed),
            pc_ring: std::array::from_fn(|half| {
                std::array::from_fn(|index| pc_ring[half * 32 + index])
            }),
            pc_ring_idx: u8::try_from(*pc_ring_idx)
                .map_err(|_| invalid("PC ring index exceeds u8"))?,
            execution: execution.clone(),
            breakpoints: ordered_breakpoints,
            watchpoints: watchpoints
                .iter()
                .map(|&(address, size, kind)| (address, size as u64, kind))
                .collect(),
        };
        checkpoint.validate(cpu)?;
        Ok(checkpoint)
    }

    fn validate(&self, target: &AArch64Cpu) -> Result<(), ArmError> {
        if self.nzcv > 15
            || self.daif > 15
            || self.btype > 3
            || self.current_el > 3
            || self.pc_ring_idx >= 64
            || !matches!(self.last_instruction_size, 2 | 4)
            || self.last_fault_level > 3
        {
            return Err(invalid("invalid execution field"));
        }
        if self.sve_vl != 128 {
            return Err(invalid("unsupported represented SVE vector length"));
        }
        if let Some(ArmError::ArchitecturalException { ec, iss, target_el }) =
            &self.execution.native_fault
        {
            if *ec > 0x3f
                || *iss > 0x1ff_ffff
                || target_el.is_some_and(|el| !(1..=3).contains(&el) || el < self.current_el)
            {
                return Err(invalid("invalid pending native exception"));
            }
        }
        if !self.config.version.supports_aarch64()
            || self.config.initial_el > 3
            || ArmFeatures::from_bits(self.config.features).is_none()
        {
            return Err(invalid("invalid AArch64 profile"));
        }
        if Mmu::with_config(self.mmu.clone()).config() != &self.mmu {
            return Err(invalid(
                "MMU configuration is outside the modeled walker profile",
            ));
        }
        if self.gic_present != target.gic.is_some()
            || self.gic_shared != target.gic_shared
            || u64::from(self.gic_cpu_id) != target.gic_cpu_id as u64
            || self.config.gic_config != target.config.gic_config
            || self.sysregs.mpidr_el1 != target.sysregs.mpidr_el1
        {
            return Err(invalid("target hardware/controller binding differs"));
        }
        if self.breakpoints.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(invalid("breakpoints are not ordered and unique"));
        }
        // The public debug API admits zero-length and wrapping ranges. Retain
        // its existing state exactly rather than imposing new snapshot rules.
        if self
            .watchpoints
            .iter()
            .any(|&(_, size, _)| usize::try_from(size).is_err())
        {
            return Err(invalid("invalid watchpoint range"));
        }
        if self.monitor.0.is_some() && !matches!(self.monitor.1, 1 | 2 | 4 | 8) {
            return Err(invalid("invalid mixed-width monitor"));
        }
        Ok(())
    }

    /// Apply only to a newly prepared CPU. All memory/controller references are
    /// retained, and no RAM, controller or target IRQ line is changed here.
    /// Further projection/profile admission is still performed offside.
    pub(crate) fn install_in_prepared(&self, cpu: &mut AArch64Cpu) -> Result<(), ArmError> {
        self.validate(cpu)?;
        cpu.clear_jit_cache();
        cpu.x = self.x;
        cpu.sp_el = self.sp_el;
        cpu.pc = self.pc;
        cpu.nzcv = self.nzcv;
        cpu.daif = self.daif;
        cpu.current_el = self.current_el;
        cpu.sp_sel = self.sp_sel;
        cpu.aarch32 = self.aarch32;
        cpu.pan = self.pan;
        cpu.uao = self.uao;
        cpu.dit = self.dit;
        cpu.ssbs = self.ssbs;
        cpu.tco = self.tco;
        cpu.btype = self.btype;
        cpu.il = self.il;
        cpu.ss = self.ss;
        cpu.v = self.v;
        cpu.fpcr = self.fpcr;
        cpu.fpsr = self.fpsr;
        cpu.sve_vl = self.sve_vl;
        cpu.sve_p = self.sve_p;
        cpu.sve_ffr = self.sve_ffr;
        cpu.sysregs = self.sysregs.clone();
        cpu.nonsecure_reset = self.nonsecure_reset;
        cpu.timer_levels = self.timer_levels;
        cpu.fault_log_budget = self.fault_log_budget;
        cpu.insn_count = self.insn_count;
        cpu.last_instruction_size = self.last_instruction_size;
        cpu.cycle_count = self.cycle_count;
        cpu.halted = self.halted;
        cpu.wfi = self.wfi;
        cpu.wfe = self.wfe;
        cpu.event_register
            .store(self.event_register, std::sync::atomic::Ordering::Release);
        cpu.pending_exceptions = self.pending_exceptions.clone();
        cpu.config = self.config.materialize();
        cpu.mmu = Mmu::with_config(self.mmu.clone());
        cpu.aarch32_monitor.address = self.monitor.0;
        cpu.aarch32_monitor.size = self.monitor.1;
        cpu.instruction_guarded
            .store(self.instruction_guarded, Ordering::Relaxed);
        cpu.last_fault_level
            .store(self.last_fault_level, Ordering::Relaxed);
        cpu.tbi_tag.store(self.tbi_tag, Ordering::Relaxed);
        cpu.pc_ring = std::array::from_fn(|index| self.pc_ring[index / 32][index % 32]);
        cpu.pc_ring_idx = usize::from(self.pc_ring_idx);
        cpu.execution = self.execution.clone();
        cpu.breakpoints = self.breakpoints.iter().copied().collect();
        cpu.watchpoints = self
            .watchpoints
            .iter()
            .map(|&(address, size, kind)| (address, size as usize, kind))
            .collect();
        AArch64Cpu::validate_saved_state(cpu.pstate_bits(), &cpu.export_sregs())
    }

    pub(crate) fn configuration(&self) -> AArch64Config {
        self.config.materialize()
    }
}

impl AArch64Cpu {
    pub(crate) fn owned_checkpoint_gic(&self) -> Option<std::sync::Arc<std::sync::Mutex<Gic>>> {
        if self.gic_shared {
            None
        } else {
            self.gic.clone()
        }
    }
    /// A detached replacement retains the target's controller and IRQ handles.
    /// The checkpoint installs controller contents only at publication.
    pub(crate) fn retain_checkpoint_bindings(&mut self, target: &Self) {
        self.gic = target.gic.clone();
        self.gic_cpu_id = target.gic_cpu_id;
        self.gic_shared = target.gic_shared;
        self.gic_irq_line = target.gic_irq_line.clone();
        self.config.gic_config = target.config.gic_config.clone();
    }
}

#[cfg(test)]
#[path = "checkpoint_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "retirement_counter_tests.rs"]
mod retirement_counters;
