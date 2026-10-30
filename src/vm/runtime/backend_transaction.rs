//! A stopped hardware transaction with complete CPU, device and RAM rollback.
use super::*;
use crate::backend::CheckpointBoundary;
use crate::vm::memory::checkpoint::CheckpointPublication;
use crate::vm::snapshot::{PhysicalMemoryRestore, PhysicalMemorySnapshot, SnapshotBundle};
use vm_memory::GuestMemoryMmap;

pub(super) struct BackendRestore<'a, 'boundary, 'scope> {
    pub vm: &'a dyn Vm,
    pub cpus: &'a mut [Box<dyn VCpu>],
    pub boundary: &'a CheckpointBoundary<'boundary>,
    pub publication: &'a CheckpointPublication<'scope>,
    pub memory: &'a GuestMemoryMmap,
    pub bundle: &'a SnapshotBundle,
}

impl BackendRestore<'_, '_, '_> {
    pub fn commit(
        self,
        physical: Option<PhysicalMemoryRestore<'_>>,
        projection: Option<&[u8]>,
    ) -> Result<()> {
        // Repeat immutable target admission after acquiring exclusion: a CPU
        // may have entered between the initial preflight and this boundary.
        self.vm.validate_checkpoint_vm_context(
            &self.bundle.base().config,
            self.bundle.vm_context(),
            self.bundle.backend_contexts(),
        )?;
        let source = self.bundle.cpus().ok_or_else(|| {
            Error::InvalidConfig("hardware restore is missing its CPU set".into())
        })?;
        let contexts = self.bundle.backend_contexts().ok_or_else(|| {
            Error::InvalidConfig("hardware restore is missing private CPU records".into())
        })?;
        let backup = self
            .cpus
            .iter()
            .map(|cpu| cpu.capture_checkpoint_record(self.boundary, Some(self.publication)))
            .collect::<Result<Vec<_>>>()?;
        let shared_backup = self.vm.capture_checkpoint_vm_context(self.boundary)?;
        let (ram_backup, reported_backup) = PhysicalMemorySnapshot::capture_with_projection(
            self.memory,
            self.bundle.base().memory_size,
        )?;
        let rollback_ram = ram_backup.prepare_with_projection(
            self.memory,
            &reported_backup,
            self.bundle.base().memory_size,
        )?;

        let result: Result<()> = (|| {
            for ((cpu, state), context) in self
                .cpus
                .iter_mut()
                .zip(source.entries())
                .zip(contexts.entries())
            {
                cpu.restore_checkpoint_record(
                    self.boundary,
                    &state.state,
                    &state.emulator,
                    context.as_ref(),
                )?;
            }
            if let Some(physical) = physical {
                physical.commit_in_scope(self.publication)?;
            } else if let Some(projection) = projection {
                self.publication.write(0, projection)?;
            }
            self.vm
                .restore_checkpoint_vm_context(self.boundary, self.bundle.vm_context())?;
            for (cpu, context) in self.cpus.iter_mut().zip(contexts.entries()) {
                cpu.finish_checkpoint_restore(self.boundary, context.as_ref())?;
            }
            Ok(())
        })();
        if let Err(error) = result {
            let rollback = (|| {
                for (cpu, (state, context)) in self.cpus.iter_mut().zip(&backup) {
                    cpu.restore_checkpoint_record(
                        self.boundary,
                        &state.state,
                        &state.emulator,
                        context.as_ref(),
                    )?;
                }
                rollback_ram.commit_in_scope(self.publication)?;
                self.vm
                    .restore_checkpoint_vm_context(self.boundary, shared_backup.as_ref())?;
                for (cpu, (_, context)) in self.cpus.iter_mut().zip(&backup) {
                    cpu.finish_checkpoint_restore(self.boundary, context.as_ref())?;
                }
                Ok::<_, Error>(())
            })();
            if let Err(rollback) = rollback {
                self.vm.poison_checkpoint_restore();
                return Err(Error::Emulator(format!(
                    "hardware checkpoint restore failed: {error}; rollback failed: {rollback}; guest entry disabled"
                )));
            }
            return Err(error);
        }
        Ok(())
    }
}
