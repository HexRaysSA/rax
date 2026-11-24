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
    pub timing: &'a Arc<crate::vm::timing::TimingContext>,
    pub disposable: bool,
    pub rtc_irq_level: Option<bool>,
    pub serial_irq: Option<u32>,
}

impl BackendRestore<'_, '_, '_> {
    pub fn commit(
        self,
        physical: Option<PhysicalMemoryRestore<'_>>,
        projection: Option<&[u8]>,
    ) -> Result<()> {
        if self.bundle.has_kvm_context() {
            #[cfg(all(feature = "kvm", target_os = "linux", target_arch = "x86_64"))]
            return self.commit_kvm(physical.ok_or_else(|| {
                Error::InvalidConfig("native KVM checkpoint requires physical RAM".into())
            })?);

            #[cfg(not(all(feature = "kvm", target_os = "linux", target_arch = "x86_64")))]
            return Err(Error::InvalidConfig(
                "native KVM checkpoint restore requires Linux x86-64 KVM".into(),
            ));
        }
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
        let (ram_backup, reported_backup) = self.capture_ram()?;
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
            self.write_ram(physical, projection)?;
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
                    cpu.rollback_checkpoint_record(
                        self.boundary,
                        &state.state,
                        &state.emulator,
                        context.as_ref(),
                    )?;
                }
                rollback_ram.commit_in_scope(self.publication)?;
                self.vm
                    .rollback_checkpoint_vm_context(self.boundary, shared_backup.as_ref())?;
                for (cpu, (_, context)) in self.cpus.iter_mut().zip(&backup) {
                    cpu.finish_checkpoint_restore(self.boundary, context.as_ref())?;
                }
                Ok::<_, Error>(())
            })();
            return self.after_rollback(error, rollback);
        }
        Ok(())
    }

    fn capture_ram(&self) -> Result<(PhysicalMemorySnapshot, Vec<u8>)> {
        PhysicalMemorySnapshot::capture_with_projection(self.memory, self.bundle.base().memory_size)
    }

    fn write_ram(
        &self,
        physical: Option<PhysicalMemoryRestore<'_>>,
        projection: Option<&[u8]>,
    ) -> Result<()> {
        if let Some(physical) = physical {
            physical.commit_in_scope(self.publication)?;
        } else if let Some(projection) = projection {
            self.publication.write(0, projection)?;
        }
        Ok(())
    }

    fn after_rollback(&self, error: Error, rollback: Result<()>) -> Result<()> {
        if let Err(rollback) = rollback {
            self.vm.poison_checkpoint_restore();
            return Err(Error::Emulator(format!(
                "hardware checkpoint restore failed: {error}; rollback failed: {rollback}; guest entry disabled"
            )));
        }
        Err(error)
    }

    #[cfg(all(feature = "kvm", target_os = "linux", target_arch = "x86_64"))]
    fn commit_kvm(self, physical: PhysicalMemoryRestore<'_>) -> Result<()> {
        use crate::backend::kvm::{CheckpointImage, KvmVm};
        let vm = self.vm.as_any().downcast_ref::<KvmVm>().ok_or_else(|| {
            Error::InvalidConfig("native KVM checkpoint requires its managed VM owner".into())
        })?;
        let source = CheckpointImage::from_checkpoint_bundle(self.bundle)?;
        source.validate_rtc_irq_level(self.rtc_irq_level)?;
        source.validate_serial_irq_level(
            self.serial_irq,
            self.bundle.base().devices.serial.has_pending_interrupt(),
        )?;
        let phase = self.bundle.clock().copied().ok_or_else(|| {
            Error::InvalidConfig("native KVM checkpoint requires a software-device clock".into())
        })?;
        source.admit_public_restore(vm, self.boundary, self.disposable)?;

        let install = || {
            source.restore_stored(vm, self.boundary)?;
            physical.commit_in_scope(self.publication)?;
            source.stage_resume_clock_with_timing(vm, self.boundary, self.timing.clone(), phase)
        };
        if self.disposable {
            return install();
        }

        let (backup, sampled_at) = vm.capture_native_banks_at(self.boundary)?;
        let backup_phase = self.timing.checkpoint_state_at(sampled_at);
        backup.admit_public_backup(vm, self.boundary)?;
        let (ram_backup, reported_backup) = self.capture_ram()?;
        let rollback_ram = ram_backup.prepare_with_projection(
            self.memory,
            &reported_backup,
            self.bundle.base().memory_size,
        )?;
        if let Err(error) = install() {
            let rollback = (|| {
                backup.restore_stored(vm, self.boundary)?;
                rollback_ram.commit_in_scope(self.publication)?;
                backup.stage_resume_clock_with_timing(
                    vm,
                    self.boundary,
                    self.timing.clone(),
                    backup_phase,
                )
            })();
            return self.after_rollback(error, rollback);
        }
        Ok(())
    }
}
