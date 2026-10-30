//! Capture CPU, platform, endpoint and RAM state under one writer boundary.
use super::*;
use crate::vm::memory::checkpoint::CheckpointBindings;
use crate::vm::snapshot::{ExecutionSnapshot, PhysicalMemorySnapshot, SnapshotBundle};

impl Vmm {
    /// Capture a stopped VM. Controlled RAM and endpoint writers are excluded;
    /// external raw aliases and host mapping changes still require coordination.
    pub fn take_snapshot_bundle(&self, insn_count: u64) -> Result<SnapshotBundle> {
        #[cfg(feature = "debug")]
        self.debugger.ready()?;
        let _timing = self.timing_context.enter();
        // Match dispatch: UART/PCI endpoints, shared platform, legacy devices,
        // independently owned GICs, then physical RAM. No guest callback runs
        // while the physical domain is held.
        let uart = self
            .pl011
            .as_ref()
            .map(|uart| {
                uart.lock()
                    .map_err(|_| Error::Emulator("PL011 capture lock poisoned".into()))
            })
            .transpose()?;
        let cluster = self
            .vm
            .as_any()
            .downcast_ref::<crate::backend::emulator::EmulatorVm>()
            .and_then(|vm| vm.arm_cluster());
        let bindings = CheckpointBindings::new(
            self.guest_mem.memory(),
            self.vcpus
                .iter()
                .flat_map(|cpu| cpu.checkpoint_owned_gics())
                .collect(),
        );
        let capture = |pci| {
            let capture = |arm_cluster| {
                let lock_error = || Error::Emulator("legacy device capture lock poisoned".into());
                let pic = self.pic.lock().map_err(|_| lock_error())?;
                let pit = self.pit.lock().map_err(|_| lock_error())?;
                let serial = self.serial.lock().map_err(|_| lock_error())?;
                let mut lapics = Vec::with_capacity(self.local_apics.len());
                for apic in &self.local_apics {
                    lapics.push(apic.lock().map_err(|_| lock_error())?);
                }
                let boundary = self.vm.checkpoint_boundary()?;
                let scope = bindings.enter()?;
                let clock = self.timing_context.checkpoint_state();
                let now = std::time::Instant::now();
                let execution = ExecutionSnapshot {
                    cursor: self.coordinator.cursor,
                    retired: self.coordinator.retired,
                    online: self.coordinator.online.clone(),
                    local_apics: lapics.iter().map(|apic| apic.checkpoint_at(now)).collect(),
                    arm_cluster,
                    pl011: uart.as_ref().map(|uart| uart.checkpoint()).transpose()?,
                };
                if let Some(cluster) = &execution.arm_cluster {
                    for (id, cpu) in self.vcpus.iter().enumerate() {
                        if let Some(off) = cpu.checkpoint_powered_off() {
                            cluster.validate_cpu_power(id, off)?;
                        }
                    }
                }
                let mut cpus = Vec::with_capacity(self.vcpus.len());
                let mut backend_contexts = Vec::with_capacity(self.vcpus.len());
                let mut resources = Vec::new();
                for cpu in &self.vcpus {
                    let (public, private) =
                        cpu.capture_checkpoint_record(&boundary, Some(&scope))?;
                    cpus.push(public);
                    backend_contexts.push(private);
                    resources.extend(cpu.capture_checkpoint_resources()?);
                }
                let shared = self.vm.capture_checkpoint_vm_context(&boundary)?;
                let first = cpus
                    .first()
                    .ok_or_else(|| Error::InvalidConfig("no vcpu available".into()))?;
                let devices = DeviceState {
                    pic: pic.clone(),
                    pit: pit.clone(),
                    serial: serial.clone(),
                    lapic: (**lapics
                        .first()
                        .ok_or_else(|| Error::InvalidConfig("no local controller".into()))?)
                    .clone(),
                };
                let (physical, memory_data) = PhysicalMemorySnapshot::capture_with_projection(
                    self.guest_mem.memory(),
                    self.guest_mem.size(),
                )?;
                let base = Snapshot {
                    version: 8,
                    config: self.checkpoint_config.clone(),
                    instruction_count: insn_count,
                    elapsed_nanos: clock.elapsed_nanos,
                    cpu_state: first.state.clone(),
                    emulator_state: first.emulator.clone(),
                    devices,
                    memory_size: self.guest_mem.size(),
                    memory_data,
                };
                let mut bundle = SnapshotBundle::new(base)
                    .with_checkpoint_records(cpus, backend_contexts, shared)?
                    .with_clock(clock)?
                    .with_execution(execution)?;
                if !resources.is_empty() {
                    bundle = bundle.with_resources(resources)?;
                }
                if let Some(pci) = pci {
                    bundle = bundle.with_pci(pci)?;
                }
                bundle.with_physical_memory(physical)
            };
            match &cluster {
                Some(cluster) => cluster.checkpoint_with(|state| capture(Some(state))),
                None => capture(None),
            }
        };
        match &self.pci_devices {
            Some(pci) => pci.checkpoint_with(|state| capture(Some(state))),
            None => capture(None),
        }
    }
}
