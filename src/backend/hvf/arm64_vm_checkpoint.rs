//! Shared native device capture at the same exclusion boundary as CPUs and RAM.
use super::checkpoint_api::{Api, check};
use super::*;
use crate::backend::CheckpointBoundary;
use crate::backend::arm64_hvf_context::{GlobalContext, MAX_SHARED_CONTEXT};
use crate::vm::snapshot::{BackendContext, HVF_AARCH64_CONTEXT};

impl NativeVmLifetime {
    pub(super) fn ensure_live(&self) -> Result<()> {
        if self.restore_failed.load(Ordering::Acquire) {
            Err(Error::Emulator(
                "native VM is unavailable after failed checkpoint rollback".into(),
            ))
        } else if self.owner_teardown_failed.load(Ordering::Acquire) {
            Err(Error::Emulator(
                "native VM is unavailable after failed vCPU owner teardown".into(),
            ))
        } else {
            Ok(())
        }
    }

    pub(super) fn admit_shared(&self, record: Option<&BackendContext>) -> Result<GlobalContext> {
        self.ensure_live()?;
        if self.entered.load(Ordering::Acquire) {
            return Err(Error::InvalidConfig(
                "SDK GIC restore requires a destination VM that has not entered a vCPU".into(),
            ));
        }
        let record = record
            .filter(|r| r.kind == HVF_AARCH64_CONTEXT)
            .ok_or_else(|| {
                Error::InvalidConfig("native restore requires shared GIC/backend state".into())
            })?;
        let context = GlobalContext::decode(&record.data)?;
        let topology = self
            .topology
            .lock()
            .map_err(|_| Error::Emulator("native topology lock poisoned".into()))?;
        let mapping = self
            .mapping
            .lock()
            .map_err(|_| Error::Emulator("native mapping lock poisoned".into()))?;
        let mapping = mapping
            .as_ref()
            .ok_or_else(|| Error::InvalidConfig("native target has no RAM mapping".into()))?;
        if usize::from(context.cpus) != topology.created.len()
            || topology
                .created
                .iter()
                .copied()
                .ne(0..u32::from(context.cpus))
            || topology.configured.is_some_and(|(count, end)| {
                count != context.cpus || context.ram_base.checked_add(context.ram_size) != Some(end)
            })
            || (context.ram_base, context.ram_size) != (mapping.ram_base, mapping.ram_size)
            || context.distributor_base != crate::machine::arm_virt::AARCH64_GICD_BASE
            || context.redistributor_base != crate::machine::arm_virt::AARCH64_GICR_BASE
        {
            return Err(Error::InvalidConfig(
                "native source/target topology or RAM differs".into(),
            ));
        }
        let (mut base, mut count) = (0, 0);
        // SAFETY: VM-wide immutable SDK property; this VM remains retained.
        check(
            unsafe { hv_gic_get_spi_interrupt_range(&mut base, &mut count) },
            "admit native SPI range",
        )?;
        if (context.spi_base, context.spi_count) != (base, count) {
            return Err(Error::InvalidConfig(
                "native source/target SPI range differs".into(),
            ));
        }
        Api::load()?;
        Ok(context)
    }

    pub(super) fn restore_shared(
        &self,
        boundary: &CheckpointBoundary<'_>,
        record: Option<&BackendContext>,
    ) -> Result<()> {
        boundary.require_owner(self.identity())?;
        let context = self.admit_shared(record)?;
        let api = Api::load()?;
        // SAFETY: all destination CPUs are created and have never run; the
        // caller holds stopped exclusion through all CPU/GIC/RAM publication.
        check(
            unsafe { (api.set_gic)(context.gic.as_ptr().cast(), context.gic.len()) },
            "restore shared GIC state",
        )?;
        *self
            .irq_levels
            .lock()
            .map_err(|_| Error::Emulator("native IRQ shadow lock poisoned".into()))? =
            context.irq_levels.into_iter().collect();
        *self
            .power
            .lock()
            .map_err(|_| Error::Emulator("native power lock poisoned".into()))? =
            Some(context.power);
        Ok(())
    }
    pub(super) fn identity(&self) -> usize {
        self as *const Self as usize
    }

    pub(super) fn stopped(&self) -> Result<CheckpointBoundary<'_>> {
        let guard = self
            .quiescence
            .write()
            .map_err(|_| Error::Emulator("native checkpoint exclusion lock poisoned".into()))?;
        self.ensure_live()?;
        Ok(CheckpointBoundary::held(self.identity(), guard))
    }

    pub(super) fn capture_shared(
        &self,
        boundary: &CheckpointBoundary<'_>,
    ) -> Result<BackendContext> {
        boundary.require_owner(self.identity())?;
        let api = Api::load()?;
        let topology = self
            .topology
            .lock()
            .map_err(|_| Error::Emulator("native topology lock poisoned".into()))?;
        let count = u8::try_from(topology.created.len())
            .map_err(|_| Error::Emulator("native CPU count exceeds checkpoint format".into()))?;
        if topology
            .configured
            .is_some_and(|(configured, _)| configured != count)
            || topology.created.iter().copied().ne(0..u32::from(count))
        {
            return Err(Error::Emulator("native CPU topology is incomplete".into()));
        }
        let mapping = self
            .mapping
            .lock()
            .map_err(|_| Error::Emulator("native memory association lock poisoned".into()))?;
        let mapping = mapping
            .as_ref()
            .ok_or_else(|| Error::Emulator("native VM has no RAM association".into()))?;
        if topology
            .configured
            .is_some_and(|(_, end)| mapping.ram_base.checked_add(mapping.ram_size) != Some(end))
        {
            return Err(Error::Emulator(
                "native RAM differs from configured topology".into(),
            ));
        }
        // SAFETY: the matching boundary holds exclusive hardware exclusion;
        // every native owner and external IRQ writer has returned to its caller.
        let state = OwnedHypervisorObject(unsafe { (api.create_gic)() });
        if state.0.is_null() {
            return Err(Error::Emulator(
                "native GIC state cannot be represented".into(),
            ));
        }
        let mut size = 0;
        check(
            unsafe { (api.gic_size)(state.0, &mut size) },
            "capture GIC state length",
        )?;
        if size == 0 || size > MAX_SHARED_CONTEXT - 64 * 1024 {
            return Err(Error::Emulator(
                "native GIC state exceeds checkpoint limit".into(),
            ));
        }
        let mut gic = Vec::new();
        gic.try_reserve_exact(size)
            .map_err(|error| Error::Emulator(format!("native GIC allocation: {error}")))?;
        gic.resize(size, 0);
        check(
            unsafe { (api.gic_data)(state.0, gic.as_mut_ptr().cast()) },
            "capture GIC state",
        )?;
        let (mut spi_base, mut spi_count) = (0, 0);
        check(
            unsafe { hv_gic_get_spi_interrupt_range(&mut spi_base, &mut spi_count) },
            "capture native SPI range",
        )?;
        let irq_levels = self
            .irq_levels
            .lock()
            .map_err(|_| Error::Emulator("native IRQ shadow lock poisoned".into()))?
            .iter()
            .map(|(&irq, &level)| (irq, level))
            .collect();
        let power = self
            .power
            .lock()
            .map_err(|_| Error::Emulator("native power lock poisoned".into()))?
            .clone()
            .unwrap_or_else(|| {
                // Only synthesize a graph when none exists. A restored graph
                // retains its offline CPUs and unacknowledged transitions.
                let mut power = crate::backend::arm64_hvf_power::Power::new(count);
                power
                    .states
                    .fill(crate::backend::arm64_hvf_power::State::On);
                power.shutdown = self.standalone_shutdown.load(Ordering::Acquire);
                power
            });
        let context = GlobalContext {
            cpus: count,
            power,
            ram_base: mapping.ram_base,
            ram_size: mapping.ram_size,
            distributor_base: crate::machine::arm_virt::AARCH64_GICD_BASE,
            redistributor_base: crate::machine::arm_virt::AARCH64_GICR_BASE,
            spi_base,
            spi_count,
            affinities: (0..u32::from(count))
                .map(crate::isa::arm::aarch64::AArch64Cpu::mpidr_for_cpu_id)
                .collect(),
            irq_levels,
            gic,
        };
        Ok(BackendContext {
            kind: HVF_AARCH64_CONTEXT,
            data: context.encode()?,
        })
    }
}
