//! Complete represented core/controller state, excluding memory and host debug controls.
use super::*;
use crate::error::{Error, Result};
use crate::isa::arm::cortex_m::exec::Snapshot;
use crate::isa::arm::cortex_m::exec::fp::FPSCR_MASK;
use serde::{Deserialize, Serialize};

// Bound decoded queue storage as well as the outer 16 MiB wire record.
const MAX_PENDING: usize = 262_144;
const _: () = assert!(std::mem::size_of::<ArmException>() <= 64);
fn pending<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Vec<ArmException>, D::Error> {
    crate::devices::checkpoint_serde::vector::<ArmException, D, MAX_PENDING>(d)
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct CoreCheckpoint {
    variant: CortexMVariant,
    registers: Snapshot,
    nvic: Nvic,
    scb: Scb,
    systick: SysTick,
    vfp: Option<VfpState>,
    halted: bool,
    #[serde(deserialize_with = "pending")]
    pending_exceptions: Vec<ArmException>,
    insn_addr: u32,
    it_rewritten: bool,
    features: u64,
    version: ArmVersion,
}

impl CoreCheckpoint {
    pub(crate) fn capture(cpu: &CortexMCpu) -> Result<Self> {
        if cpu.pending_exceptions.len() > MAX_PENDING {
            return Err(Error::InvalidConfig(
                "Cortex-M checkpoint pending exceptions exceed budget".into(),
            ));
        }
        let image = Self {
            variant: cpu.variant,
            registers: cpu.snapshot(),
            nvic: cpu.nvic.clone(),
            scb: cpu.scb.clone(),
            systick: cpu.systick.clone(),
            vfp: cpu.vfp.clone(),
            halted: cpu.halted,
            pending_exceptions: cpu.pending_exceptions.clone(),
            insn_addr: cpu.insn_addr,
            it_rewritten: cpu.it_rewritten,
            features: cpu.features.bits(),
            version: cpu.version,
        };
        image.validate(cpu)?;
        Ok(image)
    }
    pub(crate) fn validate(&self, target: &CortexMCpu) -> Result<()> {
        if self.variant != target.variant
            || self.features != target.features.bits()
            || self.version != target.version
            || !Self::same_fpu(self.vfp.as_ref(), target.vfp.as_ref())
            || self.pending_exceptions.len() > MAX_PENDING
        {
            return Err(Error::InvalidConfig(
                "Cortex-M checkpoint model/profile or FPU differs".into(),
            ));
        }
        self.registers.validate_checkpoint(target.vfp.is_some())?;
        self.nvic.validate_checkpoint(&target.nvic)?;
        self.scb.validate_checkpoint(target.variant)?;
        self.systick.validate_checkpoint(&target.systick)
    }
    /// Only a detached, already admitted core is modified; no register callbacks.
    pub(crate) fn install(self, target: &mut CortexMCpu) {
        target.restore(self.registers);
        target.nvic = self.nvic;
        target.scb = self.scb;
        target.systick = self.systick;
        target.vfp = self.vfp;
        target.halted = self.halted;
        target.pending_exceptions = self.pending_exceptions;
        target.insn_addr = self.insn_addr;
        target.it_rewritten = self.it_rewritten;
    }
    /// Both cores lack the Floating-point Extension, or both have it with
    /// the same identification, and the saved state holds only values its
    /// instructions can give: D16-D31 zero (FPv5-D16), the M-profile FPSCR.
    fn same_fpu(saved: Option<&VfpState>, target: Option<&VfpState>) -> bool {
        let identity = |vfp: &VfpState| [vfp.mvfr0, vfp.mvfr1, vfp.mvfr2, vfp.fpsid, vfp.fpexc];
        match (saved, target) {
            (None, None) => true,
            (Some(saved), Some(target)) => {
                identity(saved) == identity(target)
                    && saved.dregs[16..].iter().all(|d| *d == 0)
                    && saved.fpscr.bits() & !FPSCR_MASK == 0
            }
            _ => false,
        }
    }
}

/// The represented state outside [`CoreCheckpoint`]: the Private Peripheral
/// Bus registers, whether loads and stores reach them, and the reset VTOR.
/// A record carries it only when a core uses any of it, or has the
/// Floating-point Extension (see [`PpbCheckpoint::needed`]), so other cores
/// keep the earlier record format.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct PpbCheckpoint {
    ppb: Ppb,
    mapped: bool,
    initial_vtor: u32,
}

impl PpbCheckpoint {
    pub(crate) fn capture(cpu: &CortexMCpu) -> Self {
        Self {
            ppb: cpu.ppb.clone(),
            mapped: cpu.ppb_mapped,
            initial_vtor: cpu.initial_vtor,
        }
    }
    /// The state of a core that uses none of it, which a record without it
    /// stands for.
    pub(crate) fn reset() -> Self {
        Self {
            ppb: Ppb::default(),
            mapped: false,
            initial_vtor: 0,
        }
    }
    /// Whether a record of `core` needs this state: it differs from a reset
    /// core's, or the core has the Floating-point Extension, whose state the
    /// earlier format refuses.
    pub(crate) fn needed(&self, core: &CoreCheckpoint) -> bool {
        core.vfp.is_some() || *self != Self::reset()
    }
    /// The configuration the embedder chose (the PPB routing, the reset
    /// VTOR, the cache identification) must be the target's.
    pub(crate) fn validate(&self, target: &CortexMCpu) -> Result<()> {
        if self.mapped != target.ppb_mapped
            || self.initial_vtor != target.initial_vtor
            || self.ppb.caches() != target.ppb.caches()
        {
            return Err(Error::InvalidConfig(
                "Cortex-M checkpoint PPB configuration differs".into(),
            ));
        }
        self.ppb.validate_checkpoint(target.vfp.is_some())
    }
    /// Only a detached, already admitted core is modified.
    pub(crate) fn install(self, target: &mut CortexMCpu) {
        target.ppb = self.ppb;
        target.ppb_mapped = self.mapped;
        target.initial_vtor = self.initial_vtor;
    }
}

impl CortexMCpu {
    pub(crate) fn retain_checkpoint_host_controls(&mut self, target: &Self) {
        self.breakpoints = target.breakpoints.clone();
        self.watchpoints = target.watchpoints.clone();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::arm::cortex_m::exec::fp::CONTROL_FPCA;
    use crate::isa::arm::cortex_m::ppb::CacheIdentification;
    use crate::isa::arm::cpu_trait::{ArmCpu, WatchpointKind};

    #[test]
    fn imported_counter_boundary_wraps_without_losing_controller_state() {
        let mut source = CortexMCpu::new_m4(0x4000);
        source.memory_mut().write(0x1000, &[0x00, 0xbf]).unwrap();
        source.set_pc(0x1000);
        source.insn_count = u64::MAX;
        source.cycle_count = u64::MAX;
        // Raw set_sp is an existing API; admission must retain even this value.
        source.set_sp(0x3001);
        let image = CoreCheckpoint::capture(&source).unwrap();
        let mut target = CortexMCpu::new_m4(0x4000);
        target.memory_mut().write(0x1000, &[0x00, 0xbf]).unwrap();
        image.validate(&target).unwrap();
        image.install(&mut target);
        assert_eq!(target.get_sp(), 0x3001);
        target.execute_one().unwrap();
        assert_eq!(target.instruction_count(), 0);
        assert_eq!(target.cycle_count(), Some(0));
    }

    #[test]
    fn checkpoint_rebind_keeps_target_debug_controls() {
        let mut source = CortexMCpu::new_m4(0x4000);
        source.set_breakpoint(0x1000).unwrap();
        source
            .set_watchpoint(0x2000, 4, WatchpointKind::Write)
            .unwrap();
        let mut target = CortexMCpu::new_m4(0x4000);
        target.set_breakpoint(0x3000).unwrap();
        target
            .set_watchpoint(0x2100, 2, WatchpointKind::Read)
            .unwrap();
        let mut candidate = CortexMCpu::new_m4(0x4000);
        CoreCheckpoint::capture(&source)
            .unwrap()
            .install(&mut candidate);
        candidate.retain_checkpoint_host_controls(&target);
        assert_eq!(candidate.breakpoints, target.breakpoints);
        assert_eq!(candidate.watchpoints, target.watchpoints);
    }

    #[test]
    fn decoded_pending_queue_cannot_exceed_the_storage_budget() {
        let mut source = CortexMCpu::new_m4(0x4000);
        source.pending_exceptions = vec![ArmException::UndefinedInstruction; MAX_PENDING + 1];
        assert!(CoreCheckpoint::capture(&source).is_err());
        let mut image = CoreCheckpoint::capture(&CortexMCpu::new_m4(0x4000)).unwrap();
        image.pending_exceptions = source.pending_exceptions;
        let raw = crate::codec::serialize(&image).unwrap();
        assert!(crate::codec::deserialize::<CoreCheckpoint>(&raw).is_err());
    }

    /// A Cortex-M7 with the FPU, the PPB mapped, a reset VTOR and caches.
    fn m7() -> CortexMCpu {
        let mut cpu = CortexMCpu::new(
            CortexMVariant::CortexM7,
            Box::new(FlatMemory::new(0, 0x4000)),
        );
        cpu.set_floating_point(true);
        cpu.map_private_peripheral_bus(true);
        cpu.set_initial_vtor(0x0800_0000);
        cpu.set_cache_identification(CacheIdentification {
            clidr: 0x0900_0003,
            ctr: 0x8303_C003,
            ccsidr_data: 0xF01F_E019,
            ccsidr_instruction: 0xF03F_E019,
        });
        cpu
    }

    /// Stores giving each PPB register outside the NVIC, SCB and SysTick a
    /// value other than its reset value.
    const PPB_STORES: [(u32, u32); 13] = [
        (0xE000_EDFC, 1 << 24),     // DEMCR.TRCENA
        (0xE000_1004, 1000),        // DWT_CYCCNT
        (0xE000_1000, 1),           // DWT_CTRL.CYCCNTENA
        (0xE000_E008, 7),           // ACTLR
        (0xE000_ED84, 1),           // CSSELR: the instruction cache
        (0xE000_ED88, 0x00F0_0000), // CPACR: CP10 and CP11
        (0xE000_ED98, 5),           // MPU_RNR
        (0xE000_EDA0, 0x0307_002F), // MPU_RASR of region 5
        (0xE000_ED9C, 0x2000_0000), // MPU_RBAR of region 5
        (0xE000_ED94, 5),           // MPU_CTRL
        (0xE000_EF34, 0x4000_0000), // FPCCR: LSPEN, ASPEN clear
        (0xE000_EF38, 0x2000_1000), // FPCAR
        (0xE000_EF3C, 0x0300_0000), // FPDSCR: DN and FZ
    ];

    /// The PPB registers read back after a restore.
    const PPB_LOADS: [u32; 16] = [
        0xE000_1000,
        0xE000_1004,
        0xE000_E008,
        0xE000_ED78,
        0xE000_ED7C,
        0xE000_ED80,
        0xE000_ED84,
        0xE000_ED88,
        0xE000_ED94,
        0xE000_ED98,
        0xE000_ED9C,
        0xE000_EDA0,
        0xE000_EDFC,
        0xE000_EF34,
        0xE000_EF38,
        0xE000_EF3C,
    ];

    #[test]
    fn ppb_registers_reset_vtor_and_fp_state_survive_a_checkpoint() {
        let mut source = m7();
        for (address, value) in PPB_STORES {
            source.ppb_store(address, 4, value);
        }
        source.cycle_count += 300; // DWT_CYCCNT counts
        source.vfp.as_mut().unwrap().write_s_bits(7, 0x4049_0FDB);
        source.control |= CONTROL_FPCA;
        let core = CoreCheckpoint::capture(&source).unwrap();
        let ppb = PpbCheckpoint::capture(&source);
        assert!(ppb.needed(&core));
        let core = crate::codec::serialize(&core).unwrap();
        let ppb = crate::codec::serialize(&ppb).unwrap();

        let mut target = m7();
        let core: CoreCheckpoint = crate::codec::deserialize(&core).unwrap();
        let ppb: PpbCheckpoint = crate::codec::deserialize(&ppb).unwrap();
        core.validate(&target).unwrap();
        ppb.validate(&target).unwrap();
        core.install(&mut target);
        ppb.install(&mut target);
        for address in PPB_LOADS {
            assert_eq!(
                target.ppb_load(address, 4),
                source.ppb_load(address, 4),
                "{address:#x}"
            );
        }
        assert_eq!(target.ppb_load(0xE000_1004, 4), 1300);
        assert_eq!(target.vfp.as_ref().unwrap().read_s_bits(7), 0x4049_0FDB);
        assert_eq!(target.control & CONTROL_FPCA, CONTROL_FPCA);
        // The reset VTOR applies at the next reset.
        assert_eq!(target.initial_vtor, 0x0800_0000);
    }

    #[test]
    fn a_ppb_record_needs_the_target_configuration_and_writable_values() {
        let ppb = PpbCheckpoint::capture(&m7());
        ppb.validate(&m7()).unwrap();
        let mut unmapped = m7();
        unmapped.map_private_peripheral_bus(false);
        let mut other_vtor = m7();
        other_vtor.set_initial_vtor(0);
        let mut no_cache = m7();
        no_cache.set_cache_identification(CacheIdentification::default());
        for target in [unmapped, other_vtor, no_cache] {
            assert!(ppb.validate(&target).is_err());
        }

        let mut source = m7();
        source.ppb_store(0xE000_ED88, 4, 0x00F0_0000);
        let mut no_fpu = m7();
        no_fpu.set_floating_point(false);
        // CPACR's CP10 and CP11 exist only with the FPU.
        assert!(PpbCheckpoint::capture(&source).validate(&no_fpu).is_err());
        for corrupt in [
            |ppb: &mut Ppb| ppb.cpacr |= 1,
            |ppb: &mut Ppb| ppb.fpcar |= 4,
            |ppb: &mut Ppb| ppb.fpdscr |= 1,
        ] {
            let mut bad = PpbCheckpoint::capture(&source);
            corrupt(&mut bad.ppb);
            assert!(bad.validate(&m7()).is_err());
        }
    }

    #[test]
    fn fp_state_needs_a_target_with_the_same_fpu() {
        let with_fpu = CoreCheckpoint::capture(&m7()).unwrap();
        let mut no_fpu = m7();
        no_fpu.set_floating_point(false);
        assert!(with_fpu.validate(&no_fpu).is_err());
        assert!(
            CoreCheckpoint::capture(&no_fpu)
                .unwrap()
                .validate(&m7())
                .is_err()
        );

        let mut source = m7();
        source.vfp.as_mut().unwrap().dregs[16] = 1; // D16-D31 do not exist
        assert!(CoreCheckpoint::capture(&source).is_err());
        let mut source = m7();
        source.vfp.as_mut().unwrap().fpscr =
            crate::isa::arm::aarch32::vfp::Fpscr::from_bits(1 << 8);
        assert!(CoreCheckpoint::capture(&source).is_err());
    }

    #[test]
    fn a_reset_core_needs_no_ppb_record() {
        for cpu in [
            CortexMCpu::new_m4(0x4000),
            CortexMCpu::new(
                CortexMVariant::CortexM7,
                Box::new(FlatMemory::new(0, 0x4000)),
            ),
        ] {
            let core = CoreCheckpoint::capture(&cpu).unwrap();
            assert!(!PpbCheckpoint::capture(&cpu).needed(&core));
        }
    }
}
