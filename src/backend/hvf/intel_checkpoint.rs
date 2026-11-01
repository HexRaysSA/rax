//! Complete owner-thread capture/publication. VM-level rollback holds exclusion.
use super::*;
use crate::backend::intel_hvf_context::{
    self as wire, ClockBinding, Context, DebugState, Packet, Profile, Register,
};
use crate::backend::intel_hvf_projection::Read;
use crate::vm::snapshot::{BackendContext, CpuSnapshot, EmulatorState, HVF_INTEL_CONTEXT};

pub(super) enum ClockPublication {
    RebaseCpu,
    RebaseVm,
    Rollback,
}

impl HvfCore {
    pub(super) fn native_profile(&self) -> Result<&Profile> {
        self.checkpoint_profile
            .as_ref()
            .ok_or_else(|| Error::Emulator("native Intel profile is not initialized".into()))
    }

    pub(super) fn execution_ready(&self) -> Result<()> {
        self._vm.ready()?;
        for failure in [&self.restore_failure, &self.execution_failure] {
            if let Some(failure) = failure {
                return Err(Error::Emulator(failure.clone()));
            }
        }
        self.native_step.ready().map_err(Error::Emulator)?;
        self.priority.ready().map_err(Error::Emulator)
    }

    fn capture_clock(&self, anchor: Option<u64>) -> Result<(u64, ClockBinding)> {
        let epoch = self
            ._vm
            .resume_clock
            .lock()
            .map_err(|_| Error::Emulator("native clock epoch lock poisoned".into()))?;
        // Pair an unscoped clock read with the epoch under one lock. A peer
        // cannot establish its first resume epoch between these two samples.
        let anchor = match anchor {
            Some(anchor) => anchor,
            None => intel_clock::Api::load()?.now(),
        };
        Ok((
            anchor,
            ClockBinding {
                offset: self.tsc_offset,
                pending: self.pending_clock,
                epoch: *epoch,
            },
        ))
    }

    pub(super) fn prepare_native_clock(&mut self) -> Result<()> {
        let Some((saved, coordinated)) = self.pending_clock else {
            return Ok(());
        };
        let api = intel_clock::Api::load()?;
        let base = if coordinated {
            let mut resumed = self
                ._vm
                .resume_clock
                .lock()
                .map_err(|_| Error::Emulator("native clock epoch lock poisoned".into()))?;
            *resumed.get_or_insert_with(|| api.now())
        } else {
            api.now()
        };
        let offset = saved.wrapping_sub(base) as i64;
        api.set(self.vcpu_id, offset)?;
        self.tsc_offset = offset;
        self.pending_clock = None;
        Ok(())
    }

    pub(super) fn read_guest_tsc(&self) -> Result<u64> {
        let (anchor, binding) = self.capture_clock(None)?;
        Ok(binding.at(anchor))
    }
    pub(super) fn write_guest_tsc(&mut self, value: u64) -> Result<()> {
        let api = intel_clock::Api::load()?;
        let offset = value.wrapping_sub(api.now()) as i64;
        api.set(self.vcpu_id, offset)?;
        self.tsc_offset = offset;
        self.pending_clock = None;
        Ok(())
    }

    pub(super) fn capture_native(&self, anchor: Option<u64>) -> Result<Context> {
        self._vm.ready()?;
        native_memory::validate_cpu_backing(&self.memory_layout, &self.mem)?;
        let (anchor, clock) = self.capture_clock(anchor)?;
        let profile = self.native_profile()?.clone();
        let native = convert::Native(self.vcpu_id);
        let registers = wire::register_ids()
            .into_iter()
            .map(|id| {
                Ok(Register {
                    id,
                    value: native.register(id)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let vmcs = profile
            .fields
            .iter()
            .map(|&id| {
                Ok(Register {
                    id,
                    value: native.vmcs(id)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let msrs = wire::MSRS
            .iter()
            .map(|&id| {
                Ok(Register {
                    id,
                    value: native.msr(id)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let fp = intel_fp::read(self.vcpu_id, &profile.xsave)?;
        let (tpr, priority_failure) = self.priority.checkpoint().map_err(Error::Emulator)?;
        let (enabled, completed, failure) =
            self.native_step.checkpoint().map_err(Error::Emulator)?;
        let (output, output_failure) = self.output.checkpoint();
        let output = output
            .map(|(exit, length)| -> Result<_> { Ok((Packet::from_exit(&exit)?, length)) })
            .transpose()?;
        let mut context = Context {
            id: self.id,
            profile,
            public: X86_64CpuState {
                regs: Default::default(),
                sregs: Default::default(),
            },
            emulator: EmulatorState::default(),
            registers,
            vmcs,
            msrs,
            fp,
            tpr,
            priority_failure,
            apic_base: self.apic_base.load(Ordering::SeqCst),
            halted: self.halted,
            shutdown: self.shutdown,
            anchor,
            guest_tsc: clock.at(anchor),
            clock,
            port_input: self.port_input.clone(),
            mmio_input: self.mmio_input.clone(),
            request: self.pending_request.clone(),
            output,
            output_failure,
            execution_failure: self.execution_failure.clone(),
            restore_failure: self.restore_failure.clone(),
            debug: DebugState {
                enabled,
                completed,
                failure,
            },
        };
        let (public, emulator) = context.projection()?;
        context.public = public;
        context.emulator = emulator;
        context.validate()?;
        Ok(context)
    }

    pub(super) fn capture_native_record(
        &self,
        anchor: Option<u64>,
    ) -> Result<(CpuSnapshot, Option<BackendContext>)> {
        let context = self.capture_native(anchor)?;
        let public = CpuSnapshot {
            state: CpuState::X86_64(context.public.clone()),
            emulator: context.emulator.clone(),
        };
        Ok((
            public,
            Some(BackendContext {
                kind: HVF_INTEL_CONTEXT,
                data: context.encode()?,
            }),
        ))
    }

    pub(super) fn native_emulator_state(&self) -> Result<EmulatorState> {
        self.execution_ready()?;
        let fp = intel_fp::read(self.vcpu_id, &self.native_profile()?.xsave)?;
        let mut registers = crate::vm::vcpu::Registers::default();
        let mut emulator = self.native_profile()?.xsave.project(&fp, &mut registers)?;
        emulator.kernel_gs_base = native_msr::read(self.vcpu_id, wire::KERNEL_GS_BASE)?;
        emulator.tsc_aux = native_msr::read(self.vcpu_id, wire::TSC_AUX)? as u32;
        emulator.pat = rosetta::MsrDefaults::default().pat;
        emulator.misc_enable = rosetta::MsrDefaults::default().misc_enable;
        emulator.halted = self.halted;
        emulator.interrupt_inhibit = vmcs_read(
            self.vcpu_id,
            hv_vmx_vmcs_field_t::VMCS_GUEST_INTERRUPTIBILITY_STATE,
        )? & 3
            != 0;
        Ok(emulator)
    }

    pub(super) fn set_native_emulator_state(&mut self, emulator: &EmulatorState) -> Result<()> {
        self.execution_ready()?;
        let default = EmulatorState::default();
        if crate::codec::serialize(&emulator.lazy_flags)
            .map_err(|error| Error::Emulator(error.to_string()))?
            != crate::codec::serialize(&default.lazy_flags)
                .map_err(|error| Error::Emulator(error.to_string()))?
            || emulator.tsc_adjust != 0
            || emulator.umwait_control != 0
            || emulator.misc_enable != rosetta::MsrDefaults::default().misc_enable
            || emulator.pat != rosetta::MsrDefaults::default().pat
        {
            return Err(Error::InvalidConfig(
                "native Intel state contains unsupported software-private controls".into(),
            ));
        }
        let mut context = self.capture_native(None)?;
        context.fp = context
            .profile
            .xsave
            .overlay_emulator(&context.fp, emulator)?;
        for register in &mut context.msrs {
            if register.id == wire::KERNEL_GS_BASE {
                register.value = emulator.kernel_gs_base;
            }
            if register.id == wire::TSC_AUX {
                register.value = u64::from(emulator.tsc_aux);
            }
        }
        for register in &mut context.vmcs {
            if register.id == hv_vmx_vmcs_field_t::VMCS_GUEST_INTERRUPTIBILITY_STATE as u32 {
                if !emulator.interrupt_inhibit {
                    register.value &= !3;
                } else if register.value & 3 == 0 {
                    register.value |= 1;
                }
            }
            if register.id == hv_vmx_vmcs_field_t::VMCS_GUEST_ACTIVITY_STATE as u32 {
                if emulator.halted {
                    register.value = 1;
                } else if register.value == 1 {
                    register.value = 0;
                }
            }
        }
        context.halted = emulator.halted;
        let (public, projection) = context.projection()?;
        context.public = public;
        context.emulator = projection;
        context.validate()?;
        // An architectural overlay does not rebase the guest clock or change
        // which restored VM epoch this CPU will join on its next entry.
        let clock = (self.tsc_offset, self.pending_clock);
        let result = self.restore_native_raw(&context);
        (self.tsc_offset, self.pending_clock) = clock;
        result
    }

    pub(super) fn admit_native(
        &self,
        state: &CpuState,
        emulator: &EmulatorState,
        record: Option<&BackendContext>,
    ) -> Result<Context> {
        let record = record
            .filter(|record| record.kind == HVF_INTEL_CONTEXT)
            .ok_or_else(|| {
                Error::InvalidConfig(
                    "native Intel checkpoint requires its complete CPU record".into(),
                )
            })?;
        let context = Context::decode(&record.data)?;
        context.admit(self.id, self.native_profile()?, state, emulator)?;
        Ok(context)
    }

    /// Low-level publication is repeatable after a failure while exclusion is
    /// held. A failed write fences ordinary entry until a complete rollback or
    /// another complete import succeeds; no partially programmed CPU can run.
    pub(super) fn apply_native(
        &mut self,
        context: &Context,
        preserve_debug: bool,
        clock: ClockPublication,
    ) -> Result<()> {
        context.admit(
            self.id,
            self.native_profile()?,
            &CpuState::X86_64(context.public.clone()),
            &context.emulator,
        )?;
        let result = self.program_native(context, preserve_debug, clock);
        if let Err(error) = &result {
            self.restore_failure = Some(format!(
                "native Intel checkpoint publication failed; guest entry prohibited: {error}"
            ));
        }
        result
    }

    fn program_native(
        &mut self,
        context: &Context,
        preserve_debug: bool,
        clock: ClockPublication,
    ) -> Result<()> {
        let (debug, monitor, exceptions) = if preserve_debug {
            let (enabled, _, failure) = self.native_step.checkpoint().map_err(Error::Emulator)?;
            (
                DebugState {
                    enabled,
                    completed: false,
                    failure,
                },
                vmcs_read(self.vcpu_id, hv_vmx_vmcs_field_t::VMCS_CTRL_CPU_BASED)?
                    & wire::MONITOR_TRAP,
                vmcs_read(self.vcpu_id, hv_vmx_vmcs_field_t::VMCS_CTRL_EXC_BITMAP)?
                    & wire::DEBUG_EXCEPTIONS,
            )
        } else {
            (
                context.debug.clone(),
                context.vmcs(hv_vmx_vmcs_field_t::VMCS_CTRL_CPU_BASED as u32)? & wire::MONITOR_TRAP,
                context.vmcs(hv_vmx_vmcs_field_t::VMCS_CTRL_EXC_BITMAP as u32)?
                    & wire::DEBUG_EXCEPTIONS,
            )
        };
        let debug =
            native_step::State::from_checkpoint(debug.enabled, debug.completed, debug.failure)
                .map_err(Error::Emulator)?;
        let output = output::State::from_checkpoint(
            context
                .output
                .as_ref()
                .map(|(packet, length)| (packet.exit(), *length)),
            context.output_failure.clone(),
        )
        .map_err(Error::Emulator)?;
        // Set XCR0 before the complete image, and retain every unprojected host
        // component. Remaining writes occur with VM entry excluded.
        write_register(
            self.vcpu_id,
            hv_x86_reg_t::HV_X86_XCR0,
            context.register(hv_x86_reg_t::HV_X86_XCR0 as u32)?,
        )?;
        intel_fp::write(self.vcpu_id, &context.profile.xsave, &context.fp)?;
        for register in &context.registers {
            if register.id == hv_x86_reg_t::HV_X86_XCR0 as u32 {
                continue;
            }
            let id = register_from_raw(register.id).ok_or_else(|| {
                Error::InvalidConfig("unknown native register in admitted context".into())
            })?;
            write_register(self.vcpu_id, id, register.value)?;
        }
        for register in &context.vmcs {
            let field = vmcs_from_raw(register.id).ok_or_else(|| {
                Error::InvalidConfig("unknown VMCS field in admitted context".into())
            })?;
            let mut value = register.value;
            if field == hv_vmx_vmcs_field_t::VMCS_CTRL_CPU_BASED {
                value = (value & !wire::MONITOR_TRAP) | monitor;
            }
            if field == hv_vmx_vmcs_field_t::VMCS_CTRL_EXC_BITMAP {
                value = (value & !wire::DEBUG_EXCEPTIONS) | exceptions;
            }
            vmcs_write(self.vcpu_id, field, value)?;
            if vmcs_read(self.vcpu_id, field)? != value {
                return Err(Error::Emulator(format!(
                    "native checkpoint VMCS field {field:?} readback differs"
                )));
            }
        }
        for register in &context.msrs {
            native_msr::write(self.vcpu_id, register.id, register.value)?;
            if native_msr::read(self.vcpu_id, register.id)? != register.value {
                return Err(Error::Emulator(format!(
                    "native checkpoint MSR {:#x} readback differs",
                    register.id
                )));
            }
        }
        for register in &context.registers {
            let id = register_from_raw(register.id).ok_or_else(|| {
                Error::InvalidConfig("unknown native register in verification".into())
            })?;
            if read_register(self.vcpu_id, id)? != register.value {
                return Err(Error::Emulator(format!(
                    "native checkpoint register {id:?} readback differs"
                )));
            }
        }
        let pending_clock = match clock {
            ClockPublication::RebaseCpu => Some((context.guest_tsc, false)),
            ClockPublication::RebaseVm => Some((context.guest_tsc, true)),
            ClockPublication::Rollback => {
                intel_clock::Api::load()?.set(self.vcpu_id, context.clock.offset)?;
                self.tsc_offset = context.clock.offset;
                context.clock.pending
            }
        };
        self.priority
            .restore_checkpoint(context.tpr, context.priority_failure.clone())
            .map_err(Error::Emulator)?;
        self.apic_base.store(context.apic_base, Ordering::SeqCst);
        self.native_step = debug;
        self.port_input = context.port_input.clone();
        self.mmio_input = context.mmio_input.clone();
        self.pending_request = context.request.clone();
        self.output = output;
        self.execution_failure = context.execution_failure.clone();
        self.restore_failure = context.restore_failure.clone();
        self.halted = context.halted;
        self.shutdown = context.shutdown;
        self.pending_clock = pending_clock;
        Ok(())
    }

    pub(super) fn finish_native(&mut self, context: &Context) -> Result<()> {
        let result = (|| {
            write_register(
                self.vcpu_id,
                hv_x86_reg_t::HV_X86_TPR,
                u64::from(context.tpr),
            )?;
            if read_register(self.vcpu_id, hv_x86_reg_t::HV_X86_TPR)? != u64::from(context.tpr) {
                return Err(Error::Emulator(
                    "native checkpoint TPR readback differs".into(),
                ));
            }
            // SAFETY: creator thread and live stopped CPU. RAM and controller
            // publication precede this derived translation invalidation.
            let status = unsafe { hv_vcpu_invalidate_tlb(self.vcpu_id) };
            if status != HV_SUCCESS {
                return Err(Error::Emulator(format!(
                    "native checkpoint TLB invalidation: {}",
                    hv_error_string(status)
                )));
            }
            Ok(())
        })();
        if let Err(error) = &result {
            self.restore_failure = Some(format!(
                "native Intel checkpoint finalization failed; guest entry prohibited: {error}"
            ));
        }
        result
    }

    pub(super) fn restore_native_raw(&mut self, context: &Context) -> Result<()> {
        #[cfg(not(feature = "debug"))]
        if context.debug.enabled
            || context.vmcs(hv_vmx_vmcs_field_t::VMCS_CTRL_EXC_BITMAP as u32)?
                & wire::DEBUG_EXCEPTIONS
                != 0
        {
            return Err(Error::InvalidConfig(
                "raw native debugger controls require a debug-enabled backend".into(),
            ));
        }
        let backup = self.capture_native(None)?;
        let result = self
            .apply_native(context, false, ClockPublication::RebaseCpu)
            .and_then(|()| self.finish_native(context));
        if let Err(error) = result {
            if let Err(rollback) = self
                .apply_native(&backup, false, ClockPublication::Rollback)
                .and_then(|()| self.finish_native(&backup))
            {
                self._vm.poison(format!(
                    "raw native context restore failed: {error}; rollback failed: {rollback}"
                ));
                return Err(Error::Emulator(format!(
                    "native context restore failed: {error}; rollback failed: {rollback}; guest entry disabled"
                )));
            }
            return Err(error);
        }
        Ok(())
    }
}
