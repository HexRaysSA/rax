//! Bind the stopped native graph to the ordered public CPU and VM records.
use super::*;
use crate::vm::snapshot::{
    BackendContext, CpuSnapshot, KVM_CPU_TAG, KVM_VM_TAG, KVM_X86_64_CONTEXT, SnapshotBundle,
};
use crate::vm::vcpu::CpuState;
use serde::de::DeserializeOwned;

const CPU_LIMIT: usize = 16 * 1024 * 1024;
const VM_LIMIT: usize = 64 * 1024;

#[derive(Serialize, Deserialize)]
struct CpuRecord {
    state: cpu::Image,
    deferred: Option<deferred::Image>,
    terminal: Option<super::super::super::io::TerminalImage>,
}

#[derive(Serialize, Deserialize)]
struct VmRecord {
    // The leading option marker selects the target IRQ chip before creation.
    controllers: Option<shared::Image>,
    powered_off: bool,
    clock: clock::Image,
}

pub(crate) struct Capture {
    pub cpus: Vec<CpuSnapshot>,
    pub contexts: Vec<Option<BackendContext>>,
    pub priorities: Vec<Option<u8>>,
    pub shared: BackendContext,
}

fn encode<const LIMIT: usize>(
    tag: &[u8; 8],
    identity: u8,
    payload: &impl Serialize,
) -> Result<BackendContext> {
    Ok(BackendContext {
        kind: KVM_X86_64_CONTEXT,
        data: crate::codec::serialize_limited(&(tag, identity, payload), LIMIT).map_err(invalid)?,
    })
}

fn decode<T: DeserializeOwned, const LIMIT: usize>(
    record: &BackendContext,
    tag: &[u8; 8],
    identity: u8,
) -> Result<T> {
    if record.kind != KVM_X86_64_CONTEXT
        || record.data.len() > LIMIT
        || !record.data.starts_with(tag)
        || record.data.get(8) != Some(&identity)
    {
        return Err(invalid("checkpoint record type, bound or identity differs"));
    }
    crate::codec::deserialize_limited::<T, LIMIT>(&record.data[9..]).map_err(invalid)
}

impl Image {
    pub(crate) fn into_checkpoint_capture(self) -> Result<Capture> {
        let count = self.cpus.len();
        let mut cpus = Vec::with_capacity(count);
        let mut contexts = Vec::with_capacity(count);
        let mut priorities = Vec::with_capacity(count);
        for (id, ((state, deferred), terminal)) in self
            .cpus
            .into_iter()
            .zip(self.deferred)
            .zip(self.terminal)
            .enumerate()
        {
            priorities.push(state.checkpoint_priority()?);
            let (public, emulator) = state.public()?;
            cpus.push(CpuSnapshot {
                state: CpuState::X86_64(public),
                emulator,
            });
            let row = CpuRecord {
                state,
                deferred,
                terminal,
            };
            contexts.push(Some(encode::<CPU_LIMIT>(KVM_CPU_TAG, id as u8, &row)?));
        }
        let shared = VmRecord {
            controllers: self.shared,
            powered_off: self.powered_off,
            clock: self.clock,
        };
        Ok(Capture {
            cpus,
            contexts,
            priorities,
            shared: encode::<VM_LIMIT>(KVM_VM_TAG, count as u8, &shared)?,
        })
    }

    pub(crate) fn from_checkpoint_bundle(bundle: &SnapshotBundle) -> Result<Self> {
        let count = bundle.base().config.vcpus;
        let shared = bundle
            .vm_context()
            .ok_or_else(|| invalid("missing KVM VM record"))?;
        let shared: VmRecord = decode::<_, VM_LIMIT>(shared, KVM_VM_TAG, count)?;
        let records = bundle
            .backend_contexts()
            .ok_or_else(|| invalid("missing KVM CPU records"))?;
        let cpus = bundle
            .cpus()
            .ok_or_else(|| invalid("missing KVM CPU projections"))?;
        let execution = bundle
            .execution()
            .ok_or_else(|| invalid("missing KVM execution checkpoint"))?;
        let mut image = Self {
            version: 4,
            cpus: Vec::with_capacity(usize::from(count)),
            deferred: Vec::with_capacity(usize::from(count)),
            terminal: Vec::with_capacity(usize::from(count)),
            clock: shared.clock,
            powered_off: shared.powered_off,
            shared: shared.controllers,
        };
        let projection = |state: &CpuState, emulator: &crate::vm::snapshot::EmulatorState| {
            crate::codec::serialize_limited(&(state, emulator), CPU_LIMIT).map_err(invalid)
        };
        for (id, ((record, cpu), apic)) in records
            .entries()
            .iter()
            .zip(cpus.entries())
            .zip(&execution.local_apics)
            .enumerate()
        {
            let record = record
                .as_ref()
                .ok_or_else(|| invalid("missing KVM CPU record"))?;
            let row: CpuRecord = decode::<_, CPU_LIMIT>(record, KVM_CPU_TAG, id as u8)?;
            let (state, emulator) = row.state.public()?;
            let priority_differs = row.state.checkpoint_priority()?.is_some_and(|priority| {
                let priority = u32::from(priority);
                priority != apic.registers.priority_handle().load()
                    || (id == 0 && priority != bundle.base().devices.lapic.priority_handle().load())
            });
            if row.state.id != id as u32
                || priority_differs
                || projection(&CpuState::X86_64(state), &emulator)?
                    != projection(&cpu.state, &cpu.emulator)?
            {
                return Err(invalid(
                    "KVM CPU record disagrees with its public projection",
                ));
            }
            image.cpus.push(row.state);
            image.deferred.push(row.deferred);
            image.terminal.push(row.terminal);
        }
        Ok(image)
    }

    #[cfg(test)]
    pub(crate) fn break_debug_setter(record: &mut BackendContext, id: u8) {
        let mut row: CpuRecord = decode::<_, CPU_LIMIT>(record, KVM_CPU_TAG, id).unwrap();
        row.state.break_debug_setter();
        *record = encode::<CPU_LIMIT>(KVM_CPU_TAG, id, &row).unwrap();
    }

    /// Leave a live target untouched when materializing SMM would make an
    /// in-place rollback impossible. A new, unpublished VM can be discarded.
    pub(crate) fn admit_public_restore(
        &self,
        vm: &KvmVm,
        boundary: &CheckpointBoundary<'_>,
        disposable: bool,
    ) -> Result<()> {
        let handles = vm.checkpoint_cpu_handles(boundary)?;
        let prepare = self.admit_restore_locked(vm, &lock_cpus(vm, &handles)?)?;
        if !disposable && prepare.into_iter().any(|required| required) {
            return Err(invalid(
                "nested SMM requires a new VM for checkpoint restore",
            ));
        }
        Ok(())
    }

    pub(crate) fn admit_public_backup(
        &self,
        vm: &KvmVm,
        boundary: &CheckpointBoundary<'_>,
    ) -> Result<()> {
        for cpu in &self.cpus {
            cpu.checkpoint_priority()?;
        }
        self.admit_public_restore(vm, boundary, false)
    }
}
