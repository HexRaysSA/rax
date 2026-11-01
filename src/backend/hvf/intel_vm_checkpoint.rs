//! Shared Intel checkpoint state, matched to the registered RAM and CPU graph.
use super::*;
use crate::backend::intel_hvf_context::{Context, GlobalContext};
use crate::config::{ArchKind, BackendKind, CheckpointConfig};
use crate::vm::snapshot::{BackendContext, BackendContexts, HVF_INTEL_CONTEXT};

impl Lifetime {
    fn topology(&self) -> Result<u8> {
        let cpus = self
            .cpus
            .lock()
            .map_err(|_| Error::Emulator("native Intel topology lock poisoned".into()))?;
        let count = u8::try_from(cpus.len()).map_err(|_| {
            Error::InvalidConfig("native CPU count exceeds checkpoint format".into())
        })?;
        let configured = self
            .configured
            .lock()
            .map_err(|_| Error::Emulator("native Intel configuration lock poisoned".into()))?;
        if count == 0
            || cpus.iter().copied().ne(0..u32::from(count))
            || configured.is_some_and(|(expected, _)| expected != count)
        {
            return Err(Error::InvalidConfig(
                "native Intel CPU graph is incomplete".into(),
            ));
        }
        Ok(count)
    }
    pub(super) fn capture_shared(
        &self,
        boundary: &crate::backend::CheckpointBoundary<'_>,
    ) -> Result<BackendContext> {
        boundary.require_owner(self.identity())?;
        self.ready()?;
        let cpus = self.topology()?;
        let (ram_size, regions, fixed_holes) =
            native_memory::checkpoint_shape(&self.memory_layout)?;
        let pending_irqs = self
            .pending_irqs
            .lock()
            .map_err(|_| Error::Emulator("native IRQ queue lock poisoned".into()))?
            .clone();
        let context = GlobalContext {
            cpus,
            ram_size,
            regions,
            fixed_holes,
            pending_irqs,
            resume_clock: *self
                .resume_clock
                .lock()
                .map_err(|_| Error::Emulator("native clock epoch lock poisoned".into()))?,
            anchor: self.capture_clock.load(Ordering::Acquire),
        };
        Ok(BackendContext {
            kind: HVF_INTEL_CONTEXT,
            data: context.encode()?,
        })
    }

    fn admit_shared(&self, record: Option<&BackendContext>) -> Result<GlobalContext> {
        let record = record
            .filter(|record| record.kind == HVF_INTEL_CONTEXT)
            .ok_or_else(|| {
                Error::InvalidConfig("native Intel checkpoint requires its shared VM record".into())
            })?;
        let context = GlobalContext::decode(&record.data)?;
        let (ram_size, regions, fixed_holes) =
            native_memory::checkpoint_shape(&self.memory_layout)?;
        if context.cpus != self.topology()?
            || context.ram_size != ram_size
            || context.regions != regions
            || context.fixed_holes != fixed_holes
        {
            return Err(Error::InvalidConfig(
                "native Intel VM topology or RAM/MMIO association differs".into(),
            ));
        }
        Ok(context)
    }
    pub(super) fn validate_shared(
        &self,
        config: &CheckpointConfig,
        record: Option<&BackendContext>,
        cpus: Option<&BackendContexts>,
    ) -> Result<()> {
        self.ready()?;
        if config.backend != BackendKind::Hvf || config.arch != ArchKind::X86_64 {
            return Err(Error::InvalidConfig(
                "native Intel context has a foreign configuration".into(),
            ));
        }
        let context = self.admit_shared(record)?;
        if config.vcpus != context.cpus || config.memory_bytes != context.ram_size {
            return Err(Error::InvalidConfig(
                "native Intel declared topology differs".into(),
            ));
        }
        let cpus =
            cpus.ok_or_else(|| Error::InvalidConfig("missing native Intel CPU records".into()))?;
        if cpus.entries().len() != usize::from(context.cpus) {
            return Err(Error::InvalidConfig(
                "native Intel CPU record count differs".into(),
            ));
        }
        let mut profile = None;
        for (id, record) in cpus.entries().iter().enumerate() {
            let record = record
                .as_ref()
                .filter(|record| record.kind == HVF_INTEL_CONTEXT)
                .ok_or_else(|| Error::InvalidConfig("missing native Intel CPU producer".into()))?;
            let cpu = Context::decode(&record.data)?;
            if cpu.id != id as u32
                || cpu.anchor != context.anchor
                || cpu.clock.epoch != context.resume_clock
                || profile
                    .as_ref()
                    .is_some_and(|profile| profile != &cpu.profile)
            {
                return Err(Error::InvalidConfig(
                    "native Intel CPU identity, profile or clock graph differs".into(),
                ));
            }
            profile = Some(cpu.profile);
        }
        Ok(())
    }
    pub(super) fn restore_shared(
        &self,
        boundary: &crate::backend::CheckpointBoundary<'_>,
        record: Option<&BackendContext>,
        rollback: bool,
    ) -> Result<()> {
        boundary.require_owner(self.identity())?;
        self.ready()?;
        let context = self.admit_shared(record)?;
        let mut irqs = self
            .pending_irqs
            .lock()
            .map_err(|_| Error::Emulator("native IRQ queue lock poisoned".into()))?;
        let mut clock = self
            .resume_clock
            .lock()
            .map_err(|_| Error::Emulator("native clock epoch lock poisoned".into()))?;
        *irqs = context.pending_irqs;
        *clock = if rollback { context.resume_clock } else { None };
        Ok(())
    }
}
