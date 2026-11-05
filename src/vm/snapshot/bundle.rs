//! Additive extension container without changing the public base Snapshot shape.
use super::{CpuSnapshot, CpuSnapshots, PciSnapshot, PhysicalMemorySnapshot, Snapshot, codec};
use crate::error::{Error, Result};
use crate::vm::runtime::pci_state::PciDeviceCheckpoint;
use std::path::Path;
pub struct SnapshotBundle {
    pub(super) resources: Option<super::ResourcesSnapshot>,
    pub(super) backend_contexts: Option<super::BackendContexts>,
    pub(super) vm_context: Option<super::BackendContext>,
    pub(super) execution: Option<super::ExecutionSnapshot>,
    pub(super) clock: Option<crate::vm::timing::ClockState>,
    pub(super) base: Snapshot,
    pub(super) cpus: Option<CpuSnapshots>,
    pub(super) pci: Option<PciSnapshot>,
    pub(super) physical_memory: Option<PhysicalMemorySnapshot>,
}
impl std::fmt::Debug for SnapshotBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnapshotBundle")
            .field("base", &self.base.summary())
            .field("resources", &self.resources)
            .field("backend_contexts", &self.backend_contexts.is_some())
            .field("vm_context", &self.vm_context.is_some())
            .field("execution", &self.execution.is_some())
            .field("clock", &self.clock)
            .field("pci", &self.pci.is_some())
            .field("cpus", &self.cpus.as_ref().map(|c| c.entries().len()))
            .field("physical_memory", &self.physical_memory.is_some())
            .finish_non_exhaustive()
    }
}
impl SnapshotBundle {
    pub fn new(base: Snapshot) -> Self {
        Self {
            base,
            resources: None,
            backend_contexts: None,
            vm_context: None,
            execution: None,
            clock: None,
            cpus: None,
            pci: None,
            physical_memory: None,
        }
    }
    pub fn base(&self) -> &Snapshot {
        &self.base
    }
    pub fn resources(&self) -> Option<&super::ResourcesSnapshot> {
        self.resources.as_ref()
    }
    /// Resources must bind to represented CPU or machine ownership.
    fn has_resource_owner(&self) -> bool {
        self.cpus.is_some()
            && (self.backend_contexts.is_some()
                || self
                    .execution
                    .as_ref()
                    .is_some_and(|state| state.pc.is_some()))
    }
    /// Store immutable checkpoint bytes independently of CPU record limits.
    pub fn with_resources(mut self, resources: Vec<super::CheckpointResource>) -> Result<Self> {
        if !self.has_resource_owner() {
            return Err(Error::Emulator(
                "checkpoint resources require a CPU table and a backend or PC owner".into(),
            ));
        }
        self.resources = Some(super::ResourcesSnapshot::capture(resources)?);
        self.validate()?;
        Ok(self)
    }
    pub fn take_resources(&mut self) -> Option<super::ResourcesSnapshot> {
        self.resources.take()
    }
    pub fn backend_contexts(&self) -> Option<&super::BackendContexts> {
        self.backend_contexts.as_ref()
    }
    pub fn with_backend_contexts(
        mut self,
        entries: Vec<Option<super::BackendContext>>,
    ) -> Result<Self> {
        if self.cpus.is_none() {
            return Err(Error::Emulator(
                "backend contexts require the complete CPU set".into(),
            ));
        }
        self.backend_contexts = Some(super::BackendContexts::capture(
            entries,
            self.base.config.vcpus,
        )?);
        Ok(self)
    }
    pub fn take_backend_contexts(&mut self) -> Option<super::BackendContexts> {
        self.backend_contexts.take()
    }
    pub fn vm_context(&self) -> Option<&super::BackendContext> {
        self.vm_context.as_ref()
    }
    pub fn take_vm_context(&mut self) -> Option<super::BackendContext> {
        self.vm_context.take()
    }
    /// Admit public, private and shared producer state together. Native CPU
    /// projections are incomplete until all three parts are available.
    pub fn with_checkpoint_records(
        mut self,
        cpus: Vec<CpuSnapshot>,
        contexts: Vec<Option<super::BackendContext>>,
        shared: Option<super::BackendContext>,
    ) -> Result<Self> {
        self.cpus = Some(if super::producer::is_native(&self.base.config) {
            CpuSnapshots::capture_native(cpus, &self.base)?
        } else {
            CpuSnapshots::capture(cpus, &self.base)?
        });
        self.backend_contexts = if contexts.iter().any(Option::is_some) {
            Some(super::BackendContexts::capture(
                contexts,
                self.base.config.vcpus,
            )?)
        } else {
            if contexts.len() != usize::from(self.base.config.vcpus) {
                return Err(Error::Emulator(
                    "backend context count differs from CPU count".into(),
                ));
            }
            None
        };
        self.vm_context = shared;
        self.validate()?;
        Ok(self)
    }
    pub fn execution(&self) -> Option<&super::ExecutionSnapshot> {
        self.execution.as_ref()
    }
    pub(crate) fn with_execution(mut self, state: super::ExecutionSnapshot) -> Result<Self> {
        state.validate(&self.base)?;
        self.execution = Some(state);
        self.validate()?;
        Ok(self)
    }
    /// Admit the machine graph and its resources together. A resource-only PC
    /// producer need not manufacture an empty opaque CPU context extension.
    pub(crate) fn with_machine_state(
        mut self,
        state: super::ExecutionSnapshot,
        resources: Vec<super::CheckpointResource>,
    ) -> Result<Self> {
        self.execution = Some(state);
        if !resources.is_empty() {
            self.resources = Some(super::ResourcesSnapshot::capture(resources)?);
        }
        self.validate()?;
        Ok(self)
    }
    pub fn take_execution(&mut self) -> Option<super::ExecutionSnapshot> {
        self.execution.take()
    }
    pub fn clock(&self) -> Option<&crate::vm::timing::ClockState> {
        self.clock.as_ref()
    }
    pub fn with_clock(mut self, state: crate::vm::timing::ClockState) -> Result<Self> {
        self.validate_cpu_graph()?;
        super::clock::validate(&state, &self.base)?;
        self.clock = Some(state);
        Ok(self)
    }
    pub fn take_clock(&mut self) -> Option<crate::vm::timing::ClockState> {
        self.clock.take()
    }
    pub fn cpus(&self) -> Option<&CpuSnapshots> {
        self.cpus.as_ref()
    }
    pub fn with_cpus(mut self, entries: Vec<CpuSnapshot>) -> Result<Self> {
        self.cpus = Some(CpuSnapshots::capture(entries, &self.base)?);
        Ok(self)
    }
    pub fn take_cpus(&mut self) -> Option<CpuSnapshots> {
        self.cpus.take()
    }
    pub fn pci(&self) -> Option<&PciSnapshot> {
        self.pci.as_ref()
    }
    pub fn with_pci(mut self, state: PciDeviceCheckpoint) -> Result<Self> {
        self.base.validate_memory_metadata()?;
        self.pci = Some(PciSnapshot::capture(state, &self.base)?);
        self.validate_physical_metadata()?;
        Ok(self)
    }
    pub fn physical_memory(&self) -> Option<&PhysicalMemorySnapshot> {
        self.physical_memory.as_ref()
    }
    pub fn with_physical_memory(mut self, state: PhysicalMemorySnapshot) -> Result<Self> {
        state.verify_projection(&self.base.memory_data, self.base.memory_size)?;
        self.physical_memory = Some(state);
        self.validate()?;
        Ok(self)
    }
    /// Required extensions must be handled explicitly before taking the base.
    pub fn take_physical_memory(&mut self) -> Option<PhysicalMemorySnapshot> {
        self.physical_memory.take()
    }
    pub fn take_pci(&mut self) -> Option<PciSnapshot> {
        self.pci.take()
    }
    /// Compatibility with the immediately preceding unreleased bundle API.
    /// Required physical state cannot be silently discarded by pair extraction.
    pub fn into_parts(self) -> Result<(Snapshot, Option<PciSnapshot>)> {
        if self.vm_context.is_some() {
            return Err(Error::Emulator(
                "checkpoint contains required shared backend state".into(),
            ));
        }
        if self.resources.is_some() {
            return Err(Error::Emulator(
                "checkpoint contains required resources".into(),
            ));
        }
        if self.backend_contexts.is_some() {
            return Err(Error::Emulator(
                "checkpoint contains required backend contexts".into(),
            ));
        }
        if self.execution.is_some() {
            return Err(Error::Emulator(
                "checkpoint contains required execution state".into(),
            ));
        }
        if self.clock.is_some() {
            return Err(Error::Emulator(
                "checkpoint contains required clock state".into(),
            ));
        }
        if self.cpus.is_some() {
            return Err(Error::Emulator(
                "checkpoint contains required CPU set".to_string(),
            ));
        }
        if self.physical_memory.is_some() {
            return Err(Error::Emulator(
                "checkpoint contains required physical memory".to_string(),
            ));
        }
        Ok((self.base, self.pci))
    }
    pub fn into_base(self) -> Result<Snapshot> {
        if self.resources.is_some()
            || self.vm_context.is_some()
            || self.backend_contexts.is_some()
            || self.execution.is_some()
            || self.pci.is_some()
            || self.physical_memory.is_some()
            || self.cpus.is_some()
            || self.clock.is_some()
        {
            return Err(Error::Emulator(
                "checkpoint contains required extensions; use SnapshotBundle::load".to_string(),
            ));
        }
        Ok(self.base)
    }
    /// Verify all represented physical bytes and the reported-RAM projection.
    /// PCI media/controller validation remains available through PciSnapshot.
    pub fn verify_physical_memory(&self) -> Result<()> {
        self.validate_complete()?;
        if let Some(state) = &self.physical_memory {
            state.verify_projection(&self.base.memory_data, self.base.memory_size)?;
        }
        Ok(())
    }
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        self.validate_complete()?;
        codec::save_bundle_atomic(self, path.as_ref())
    }
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let bundle = codec::load_bundle(path.as_ref())?;
        bundle.validate_complete()?;
        Ok(bundle)
    }
    /// Builders may temporarily lack later sections. Materialized native files
    /// require their platform owners and every byte in the SDK-mapped RAM window.
    pub(crate) fn validate_complete(&self) -> Result<()> {
        self.validate()?;
        self.validate_clint_graph()?;
        if super::producer::is_native(&self.base.config) {
            if self.execution.is_none() || self.clock.is_none() {
                return Err(Error::InvalidConfig(
                    "native checkpoint requires coordinator and clock state".into(),
                ));
            }
            let physical = self.physical_memory.as_ref().ok_or_else(|| {
                Error::InvalidConfig(
                    "native checkpoint requires its complete physical RAM image".into(),
                )
            })?;
            let spans = if self.base.config.arch == crate::config::ArchKind::Aarch64 {
                if self
                    .execution
                    .as_ref()
                    .and_then(|state| state.pl011.as_ref())
                    .is_none()
                {
                    return Err(Error::InvalidConfig(
                        "native AArch64 checkpoint requires its PL011 UART image".into(),
                    ));
                }
                vec![(
                    crate::machine::arm_virt::AARCH64_RAM_BASE,
                    self.base.memory_size,
                )]
            } else {
                let shared = self
                    .vm_context
                    .as_ref()
                    .ok_or_else(|| Error::InvalidConfig("missing native Intel VM graph".into()))?;
                let shared =
                    crate::backend::intel_hvf_context::GlobalContext::decode(&shared.data)?;
                shared.require_controller_owned_irqs()?;
                if self
                    .execution
                    .as_ref()
                    .and_then(|state| state.pc.as_ref())
                    .is_none()
                {
                    return Err(Error::InvalidConfig(
                        "native Intel checkpoint requires its PC controller inventory".into(),
                    ));
                }
                if self.pci.is_none() {
                    return Err(Error::InvalidConfig(
                        "native Intel checkpoint requires its PCI bridge image".into(),
                    ));
                }
                shared.regions
            };
            for (base, size) in spans {
                let end = base.checked_add(size).ok_or_else(|| {
                    Error::InvalidConfig("native checkpoint RAM span overflows".into())
                })?;
                if !physical.layout().any(|(start, size)| {
                    start <= base && start.checked_add(size).is_some_and(|limit| limit >= end)
                }) {
                    return Err(Error::InvalidConfig(
                        "native physical image does not cover mapped RAM".into(),
                    ));
                }
            }
        }
        Ok(())
    }
    /// Metadata-only closure after a builder has admitted the physical image.
    /// Do not decompress/hash that image a second time during capture.
    pub(crate) fn validate_clint_graph(&self) -> Result<()> {
        let platform = self
            .execution
            .as_ref()
            .and_then(|e| e.riscv_platform.as_ref());
        let mut platform_harts = 0;
        if let Some(contexts) = &self.backend_contexts {
            for record in contexts.entries().iter().flatten() {
                if record.kind == super::RISCV_CONTEXT
                    && crate::backend::emulator::riscv::context_uses_platform(&record.data)?
                {
                    platform_harts += 1;
                }
            }
        }
        if platform.is_some() {
            let physical = self.physical_memory.as_ref().ok_or_else(|| {
                Error::InvalidConfig("CLINT checkpoint requires complete physical RAM".into())
            })?;
            let end = self
                .base
                .memory_size
                .checked_add(crate::vm::memory::GUEST_MEMORY_PADDING)
                .ok_or_else(|| Error::InvalidConfig("CLINT RAM extent overflows".into()))?;
            if !physical
                .layout()
                .any(|(start, size)| start == 0 && size >= end)
            {
                return Err(Error::InvalidConfig(
                    "CLINT physical image omits mapped RAM".into(),
                ));
            }
            if self.clock.is_none()
                || self.cpus.is_none()
                || platform_harts != usize::from(self.base.config.vcpus)
            {
                return Err(Error::InvalidConfig(
                    "CLINT checkpoint missing matching private harts or clock".into(),
                ));
            }
        } else if platform_harts != 0 {
            return Err(Error::InvalidConfig(
                "CLINT hart checkpoint lacks shared platform state".into(),
            ));
        }
        Ok(())
    }
    pub(crate) fn validate(&self) -> Result<()> {
        self.validate_cpu_graph()?;
        if let Some(resources) = &self.resources {
            if !self.has_resource_owner() {
                return Err(Error::Emulator(
                    "checkpoint resources require a CPU table and a backend or PC owner".into(),
                ));
            }
            resources.validate_metadata()?;
        }
        if let Some(contexts) = &self.backend_contexts {
            if self.cpus.is_none() {
                return Err(Error::Emulator(
                    "backend contexts require the complete CPU set".into(),
                ));
            }
            contexts.validate(self.base.config.vcpus)?;
        }
        if let Some(execution) = &self.execution {
            if self.cpus.is_none() {
                return Err(Error::Emulator(
                    "execution checkpoint requires the complete CPU set".into(),
                ));
            }
            execution.validate(&self.base)?;
            if let Some(pc) = &execution.pc {
                let keys: std::collections::BTreeSet<_> = self
                    .resources
                    .as_ref()
                    .map(|r| r.keys().collect())
                    .unwrap_or_default();
                if pc.references()?.iter().any(|key| !keys.contains(key)) {
                    return Err(Error::InvalidConfig(
                        "PC device references missing checkpoint media".into(),
                    ));
                }
            }
            if self.base.config.arch == crate::config::ArchKind::X86_64 {
                for (cpu, apic) in self
                    .cpus
                    .as_ref()
                    .unwrap()
                    .entries()
                    .iter()
                    .zip(&execution.local_apics)
                {
                    let crate::vm::vcpu::CpuState::X86_64(cpu) = &cpu.state else {
                        return Err(Error::InvalidConfig(
                            "x86 priority graph contains another CPU architecture".into(),
                        ));
                    };
                    let tpr = apic.registers.priority_handle().load();
                    if tpr > 255 || cpu.sregs.cr8 > 15 || u64::from(tpr >> 4) != cpu.sregs.cr8 {
                        return Err(Error::InvalidConfig(
                            "checkpoint CR8 and local APIC TPR disagree".into(),
                        ));
                    }
                }
            }
            if self.base.config.backend == crate::config::BackendKind::Hvf
                && self.base.config.arch == crate::config::ArchKind::X86_64
            {
                let contexts = self.backend_contexts.as_ref().ok_or_else(|| {
                    Error::InvalidConfig("missing native Intel CPU contexts".into())
                })?;
                for (context, apic) in contexts.entries().iter().zip(&execution.local_apics) {
                    let record = context.as_ref().ok_or_else(|| {
                        Error::InvalidConfig("missing native Intel CPU producer".into())
                    })?;
                    let context = crate::backend::intel_hvf_context::Context::decode(&record.data)?;
                    if context.tpr != apic.registers.priority_handle().load() {
                        return Err(Error::InvalidConfig(
                            "native Intel TPR and local APIC priority differ".into(),
                        ));
                    }
                    let timer = apic.registers.deadline_handle().snapshot();
                    if context
                        .deadline
                        .map_or(!timer.is_quiescent(), |saved| saved != timer)
                    {
                        return Err(Error::InvalidConfig(
                            "native Intel deadline and local APIC timer differ".into(),
                        ));
                    }
                }
            }
            if super::producer::is_native(&self.base.config)
                && self.base.config.arch == crate::config::ArchKind::Aarch64
            {
                let shared = self
                    .vm_context
                    .as_ref()
                    .ok_or_else(|| Error::InvalidConfig("missing native power graph".into()))?;
                crate::backend::arm64_hvf_context::GlobalContext::decode(&shared.data)?
                    .power
                    .validate_online(&execution.online)?;
            }
        }
        if let Some(clock) = &self.clock {
            super::clock::validate(clock, &self.base)?;
        }
        if let Some(pci) = &self.pci {
            pci.validate(&self.base.config, self.base.memory_size)?;
        }
        self.validate_physical_metadata()
    }
    fn validate_cpu_graph(&self) -> Result<()> {
        super::producer::validate(
            &self.base,
            self.cpus.as_ref(),
            self.backend_contexts.as_ref(),
            self.vm_context.as_ref(),
        )
    }
    fn validate_physical_metadata(&self) -> Result<()> {
        let media = self.pci.as_ref().map_or(0, |p| {
            p.nvme_media().map_or(0, |m| m.size()) + p.ahci_media().map_or(0, |m| m.size())
        });
        let resources = self.resources.as_ref().map_or(0, |r| r.total_bytes());
        if self.resources.is_some()
            && resources > super::resources::remaining_budget(self.base.memory_size, media)?
        {
            return Err(Error::Emulator(
                "RAM plus media/resources exceeds bundle budget".into(),
            ));
        }
        if let Some(state) = &self.physical_memory {
            let total = media
                .checked_add(resources)
                .ok_or_else(|| Error::Emulator("checkpoint media/resource size overflow".into()))?;
            state.validate_metadata(total)?;
        }
        Ok(())
    }
}
