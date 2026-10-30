//! Checkpoint target admission and coordinated component publication.
use super::*;

impl Vmm {
    fn validate_snapshot_target(&self, snapshot: &Snapshot) -> Result<()> {
        if let CpuState::X86_64(cpu) = &snapshot.cpu_state {
            let tpr = snapshot.devices.lapic.priority_handle().load();
            if tpr > 255 || cpu.sregs.cr8 > 15 || u64::from(tpr >> 4) != cpu.sregs.cr8 {
                return Err(Error::InvalidConfig(
                    "checkpoint BSP CR8 and local APIC TPR disagree".into(),
                ));
            }
        }
        snapshot.validate_envelope()?;
        if snapshot.config.arch != self.checkpoint_config.arch {
            return Err(Error::InvalidConfig(
                "checkpoint architecture does not match target machine".to_string(),
            ));
        }
        if snapshot.memory_size != self.guest_mem.size() {
            return Err(Error::InvalidConfig(
                "checkpoint RAM extent does not match target machine".to_string(),
            ));
        }
        if snapshot.config.vcpus as usize != self.vcpus.len() {
            return Err(Error::InvalidConfig(
                "checkpoint CPU count does not match target machine".to_string(),
            ));
        }
        if snapshot.config.pci_devices != self.checkpoint_config.pci_devices {
            return Err(Error::InvalidConfig(
                "checkpoint PCI topology does not match target machine".to_string(),
            ));
        }
        Ok(())
    }

    /// Restore represented public/base-private CPU contexts, four legacy models,
    /// physical backing (or reported projection), PCI/media and explicit timing
    /// state when present. Independent writers must be quiescent. Additional
    /// backend-private/platform state and native setter/resource transactions
    /// remain separate.
    pub fn restore_snapshot_bundle(
        &mut self,
        bundle: &crate::vm::snapshot::SnapshotBundle,
    ) -> Result<()> {
        #[cfg(feature = "debug")]
        self.debugger.ready()?;
        let _timing = self.timing_context.enter();
        bundle.validate_complete()?;
        self.vm.validate_checkpoint_vm_context(
            &bundle.base().config,
            bundle.vm_context(),
            bundle.backend_contexts(),
        )?;
        let snapshot = bundle.base();
        self.validate_snapshot_target(snapshot)?;
        #[cfg(feature = "debug")]
        if let Some(execution) = bundle.execution() {
            self.validate_debugger_restore_online(execution.online())?;
        }
        let timing_context = &self.timing_context;
        let clock_restore = bundle
            .clock()
            .map(|state| timing_context.prepare_checkpoint_state(state))
            .transpose()?;
        if snapshot.config.vcpus > 1 && bundle.cpus().is_none() {
            return Err(Error::InvalidConfig(
                "checkpoint is missing additional CPU state".to_string(),
            ));
        }
        if bundle.pci().is_none()
            && bundle.physical_memory().is_none()
            && bundle.cpus().is_none()
            && bundle.clock().is_none()
            && bundle.execution().is_none()
            && bundle.backend_contexts().is_none()
            && bundle.resources().is_none()
            && bundle.vm_context().is_none()
        {
            return self.restore_snapshot(snapshot);
        }
        for (source, target) in [
            (
                &snapshot.config.storage.nvme,
                &self.checkpoint_config.storage.nvme,
            ),
            (
                &snapshot.config.storage.ahci,
                &self.checkpoint_config.storage.ahci,
            ),
        ] {
            match (source, target) {
                (None, None) => (),
                (Some(s), Some(t)) if s.identity == t.identity && s.mode == t.mode => (),
                _ => {
                    return Err(Error::InvalidConfig(
                        "checkpoint storage binding does not match target machine".to_string(),
                    ));
                }
            }
        }
        match (&self.pci_devices, bundle.pci()) {
            (Some(_), Some(_)) | (None, None) => (),
            _ => {
                return Err(Error::InvalidConfig(
                    "checkpoint PCI component does not match target machine".to_string(),
                ));
            }
        }
        let mut states = Vec::new();
        let count = bundle.cpus().map_or(1, |c| c.entries().len());
        if count > self.vcpus.len() {
            return Err(Error::InvalidConfig(
                "checkpoint CPU set exceeds target count".to_string(),
            ));
        }
        states
            .try_reserve_exact(count)
            .map_err(|e| Error::Emulator(format!("CPU restore allocation: {e}")))?;
        if let Some(cpus) = bundle.cpus() {
            if cpus.entries().len() != self.vcpus.len() {
                return Err(Error::InvalidConfig(
                    "checkpoint CPU set count does not match target".to_string(),
                ));
            }
            for (index, entry) in cpus.entries().iter().enumerate() {
                let context = bundle
                    .backend_contexts()
                    .and_then(|contexts| contexts.entries()[index].as_ref());
                states.push((&entry.state, &entry.emulator, context));
            }
        } else {
            states.push((&snapshot.cpu_state, &snapshot.emulator_state, None));
        }
        for (vcpu, (state, emulator, context)) in self.vcpus.iter().zip(&states) {
            vcpu.validate_checkpoint_for_machine(&snapshot.config, state, emulator, *context)?;
        }
        let resources = match bundle.resources() {
            Some(resources) => resources.prepare()?,
            None => Arc::new(crate::vm::snapshot::PreparedResources::default()),
        };
        let mut referenced = std::collections::BTreeSet::new();
        for (vcpu, (_, _, context)) in self.vcpus.iter().zip(&states) {
            for key in vcpu.checkpoint_resource_references(*context)? {
                resources.resolve(key)?;
                referenced.insert(key);
            }
        }
        if referenced != resources.keys().collect() {
            return Err(Error::InvalidConfig(
                "checkpoint contains unreferenced resources".into(),
            ));
        }
        let mut replacements = Vec::new();
        replacements
            .try_reserve_exact(states.len())
            .map_err(|e| Error::Emulator(format!("CPU replacement allocation: {e}")))?;
        for (vcpu, (state, emulator, context)) in self.vcpus.iter().zip(&states) {
            let mut replacement =
                vcpu.prepare_checkpoint_replacement(state, emulator, *context, &resources)?;
            #[cfg(feature = "debug")]
            if let (Some(controls), Some(candidate)) =
                (vcpu.debugger_controls(), replacement.as_mut())
            {
                // The frontend remains authoritative while guest state moves
                // backward. Bind only offside CPUs; rejection cannot publish a
                // prefix or roll the current controller back to a saved session.
                candidate.bind_debugger_controls(&controls)?;
            }
            replacements.push(replacement);
        }
        let physical = bundle
            .physical_memory()
            .map(|p| {
                p.prepare_with_projection(
                    self.guest_mem.memory(),
                    &snapshot.memory_data,
                    snapshot.memory_size,
                )
            })
            .transpose()?;
        let memory = if physical.is_none() {
            let memory = snapshot.decompress_memory()?;
            self.guest_mem.validate_restore_len(memory.len())?;
            Some(memory)
        } else {
            None
        };
        let pci = bundle.pci().map(|p| p.to_devices()).transpose()?;
        let execution = bundle
            .execution()
            .map(|state| {
                state.validate(snapshot)?;
                let now = std::time::Instant::now();
                let apics = state
                    .local_apics
                    .iter()
                    .map(|apic| apic.prepare(now))
                    .collect::<Vec<_>>();
                Ok::<_, Error>((
                    coordinator::ExecutionCoordinator {
                        cursor: state.cursor,
                        retired: state.retired,
                        online: state.online.clone(),
                    },
                    apics,
                ))
            })
            .transpose()?;
        if self.checkpoint_config.arch == ArchKind::Aarch64
            && self.checkpoint_config.vcpus > 1
            && self
                .vm
                .as_any()
                .downcast_ref::<crate::backend::emulator::EmulatorVm>()
                .is_some()
            && bundle
                .execution()
                .and_then(|state| state.arm_cluster.as_ref())
                .is_none()
        {
            return Err(Error::InvalidConfig(
                "AArch64 SMP checkpoint requires shared interrupt/power state".into(),
            ));
        }
        let arm_restore = if let Some(state) = bundle
            .execution()
            .and_then(|saved| saved.arm_cluster.as_ref())
        {
            let cluster = self
                .vm
                .as_any()
                .downcast_ref::<crate::backend::emulator::EmulatorVm>()
                .and_then(|vm| vm.arm_cluster())
                .ok_or_else(|| {
                    Error::InvalidConfig(
                        "ARM platform checkpoint requires the software cluster".into(),
                    )
                })?;
            cluster.validate_checkpoint(
                state,
                bundle
                    .execution()
                    .ok_or_else(|| Error::InvalidConfig("missing execution state".into()))?
                    .online(),
            )?;
            Some((cluster, state.clone()))
        } else {
            None
        };
        if let Some((_, state)) = &arm_restore {
            for (id, cpu) in replacements.iter().enumerate() {
                if let Some(off) = cpu.as_ref().and_then(|cpu| cpu.checkpoint_powered_off()) {
                    state.validate_cpu_power(id, off)?;
                }
            }
        }
        let uart_state = bundle.execution().and_then(|state| state.pl011.clone());
        if uart_state.is_some() && self.pl011.is_none() {
            return Err(Error::InvalidConfig(
                "checkpoint PL011 target binding differs".into(),
            ));
        }
        if let Some(state) = &uart_state {
            state.validate()?;
        }
        if let Some(memory) = &memory {
            crate::vm::memory::reservations::preflight_write(
                self.guest_mem.memory(),
                0,
                memory.len(),
            )?;
        }
        let devices = snapshot.devices.clone();
        let lock_err =
            |what: &str| Error::Emulator(format!("device {what} lock poisoned during restore"));
        // UART/PCI -> shared platform -> legacy devices -> owned GIC -> RAM.
        let mut uart = self
            .pl011
            .as_ref()
            .map(|uart| uart.lock().map_err(|_| lock_err("PL011")))
            .transpose()?;
        let bindings = crate::vm::memory::checkpoint::CheckpointBindings::new(
            self.guest_mem.memory(),
            replacements
                .iter()
                .flatten()
                .flat_map(|cpu| cpu.checkpoint_owned_gics())
                .collect(),
        );
        // This guard outlives both controller wrappers, which publish their
        // state after the inner closure returns. Releasing it inside the
        // closure would expose RAM/leases before controller publication.
        let mut publication = None;
        let mut legacy_publication = None;
        let mut backend_publication = None;
        let vm = &*self.vm;
        let guest_memory = self.guest_mem.memory();
        let coordinator = &mut self.coordinator;
        let vcpus = &mut self.vcpus;
        let pic = &self.pic;
        let pit = &self.pit;
        let serial = &self.serial;
        let local_apics = &self.local_apics;
        let commit = || -> Result<()> {
            let pic = pic.lock().map_err(|_| lock_err("pic"))?;
            let pit = pit.lock().map_err(|_| lock_err("pit"))?;
            let serial = serial.lock().map_err(|_| lock_err("serial"))?;
            let mut lapics = Vec::with_capacity(local_apics.len());
            for controller in local_apics {
                lapics.push(controller.lock().map_err(|_| lock_err("lapic"))?);
            }
            legacy_publication = Some((pic, pit, serial, lapics));
            let (pic, pit, serial, lapics) =
                legacy_publication.as_mut().expect("legacy locks installed");
            // Historical/native setters remain fallible and do not promise
            // whole-VM rollback. Run them before the physical freeze: legacy
            // reset may clear a monitor through the ordinary domain API.
            backend_publication = Some(vm.checkpoint_boundary()?);
            let boundary = backend_publication
                .as_ref()
                .expect("backend exclusion installed");
            if bundle.vm_context().is_none() {
                for ((vcpu, (state, emulator, context)), replacement) in
                    vcpus.iter_mut().zip(&states).zip(&replacements)
                {
                    if replacement.is_none() {
                        vcpu.restore_checkpoint_record(boundary, state, emulator, *context)?;
                    }
                }
            }
            publication = Some(bindings.enter()?);
            let scope = publication.as_ref().expect("publication installed");
            if bundle.vm_context().is_some() && replacements.iter().any(Option::is_some) {
                return Err(Error::InvalidConfig(
                    "shared hardware restore cannot replace CPU owners".into(),
                ));
            }
            let mut permits = Vec::with_capacity(replacements.len());
            for cpu in replacements.iter_mut().flatten() {
                permits.push(cpu.prepare_checkpoint_publication(scope)?);
            }
            if bundle.vm_context().is_some() {
                drop(permits);
                backend_transaction::BackendRestore {
                    vm,
                    cpus: vcpus,
                    boundary,
                    publication: scope,
                    memory: guest_memory,
                    bundle,
                }
                .commit(physical, memory.as_deref())?;
            } else {
                if let Some(physical) = physical {
                    physical.commit_in_scope(scope)?;
                } else if let Some(memory) = memory {
                    scope.write(0, &memory)?;
                }
                // RAM invalidates old rights before admitted source rights
                // are installed under the same controller/writer boundary.
                for permit in permits {
                    permit.commit();
                }
            }
            for (vcpu, replacement) in vcpus.iter_mut().zip(replacements) {
                if let Some(replacement) = replacement {
                    *vcpu = replacement;
                }
            }
            **pic = devices.pic;
            **pit = devices.pit;
            **serial = devices.serial;
            if let (Some(target), Some(state)) = (&mut uart, uart_state) {
                target.restore_checkpoint(state);
            }
            if let Some((saved, apics)) = execution {
                *coordinator = saved;
                let resume = std::time::Instant::now();
                for (target, mut restored) in lapics.iter_mut().zip(apics) {
                    restored.resume_timer_at(resume);
                    target.replace_state(restored);
                }
            } else {
                lapics[0].replace_state(devices.lapic);
                lapics[0].enable_coordinated_delivery();
            }
            if let Some(clock) = clock_restore {
                clock.commit();
            } else {
                timing_context.set_resume_base(snapshot.elapsed_nanos);
            }
            Ok(())
        };
        let commit = || match arm_restore {
            Some((cluster, state)) => cluster.restore_with(state, commit),
            None => commit(),
        };
        let result = match (&self.pci_devices, pci) {
            (Some(devices), Some(pci)) => devices.restore_checkpoint_with(pci, commit),
            (None, None) => commit(),
            _ => unreachable!("PCI topology admitted before commit"),
        };
        drop(publication);
        drop(legacy_publication);
        drop(backend_publication);
        result
    }

    /// Restore represented base state after validating input and target admission.
    /// Full SMP/private/platform/PCI closure remains separate.
    pub fn restore_snapshot(&mut self, snapshot: &Snapshot) -> Result<()> {
        #[cfg(feature = "debug")]
        self.debugger.ready()?;
        let _timing = self.timing_context.enter();
        snapshot.validate_for_restore()?;
        if self.checkpoint_config.storage.has_images() || snapshot.config.storage.has_images() {
            return Err(Error::InvalidConfig(
                "image-backed checkpoint restore requires complete device/media state".to_string(),
            ));
        }
        self.validate_snapshot_target(snapshot)?;
        let vcpu = self
            .vcpus
            .get_mut(0)
            .ok_or_else(|| Error::InvalidConfig("no vcpu available".to_string()))?;
        vcpu.validate_checkpoint_state(&snapshot.cpu_state, &snapshot.emulator_state)?;
        let memory = snapshot.decompress_memory()?;
        self.guest_mem.validate_restore_len(memory.len())?;
        let devices = snapshot.devices.clone();
        let lock_err =
            |what: &str| Error::Emulator(format!("device {what} lock poisoned during restore"));
        let mut pic = self.pic.lock().map_err(|_| lock_err("pic"))?;
        let mut pit = self.pit.lock().map_err(|_| lock_err("pit"))?;
        let mut serial = self.serial.lock().map_err(|_| lock_err("serial"))?;
        let mut lapic = self.lapic.lock().map_err(|_| lock_err("lapic"))?;
        vcpu.set_state(&snapshot.cpu_state)?;
        vcpu.set_emulator_state(&snapshot.emulator_state)?;
        self.guest_mem.write_all(&memory)?;
        *pic = devices.pic;
        *pit = devices.pit;
        *serial = devices.serial;
        lapic.replace_state(devices.lapic);
        lapic.enable_coordinated_delivery();
        crate::vm::timing::set_resume_base(snapshot.elapsed_nanos);

        info!(
            insn_count = snapshot.instruction_count,
            summary = %snapshot.summary(),
            "restored checkpoint"
        );

        Ok(())
    }
}
