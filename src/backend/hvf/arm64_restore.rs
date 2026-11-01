//! Native architectural publication and post-RAM interrupt/TLB completion.
use super::checkpoint_api::{Api, SmeState, Zt, check};
use super::*;
use crate::backend::arm64_hvf_context::{Context, FEATURE_IDS};
use crate::vm::snapshot::{BackendContext, EmulatorState, HVF_AARCH64_CONTEXT};

impl HvfArm64Core {
    pub(super) fn admit_native_context(
        &self,
        public: &CpuState,
        emulator: &EmulatorState,
        record: Option<&BackendContext>,
    ) -> Result<Context> {
        let record = record
            .filter(|r| r.kind == HVF_AARCH64_CONTEXT)
            .ok_or_else(|| {
                Error::InvalidConfig(
                    "native AArch64 restore requires its complete backend record".into(),
                )
            })?;
        let context = Context::decode(&record.data)?;
        let profile = self
            .checkpoint_profile
            .as_ref()
            .map_err(|error| Error::Emulator(error.clone()))?;
        context.admit(self.id, profile, public)?;
        let encode = |state: &EmulatorState| {
            crate::codec::serialize_limited(state, 4096)
                .map_err(|error| Error::Emulator(format!("native emulator projection: {error}")))
        };
        if encode(emulator)? != encode(&EmulatorState::default())? {
            return Err(Error::InvalidConfig(
                "native checkpoint contains foreign emulator state".into(),
            ));
        }
        Ok(context)
    }

    /// All CPUs and the shared image have been admitted by the caller. Its
    /// stopped VM boundary remains held through rollback or final publication.
    pub(super) fn apply_native_context(&mut self, context: &Context) -> Result<()> {
        let api = Api::load()?;
        let registers = &context.public.regs;
        // Disable timers while comparator/control pairs are reconstructed.
        self.write_sys_reg(HV_SYS_REG_CNTP_CTL_EL0, 0)?;
        self.write_sys_reg(HV_SYS_REG_CNTV_CTL_EL0, 0)?;
        for register in &context.system {
            if FEATURE_IDS.contains(&register.id)
                || register.id == HV_SYS_REG_MPIDR_EL1
                || [
                    HV_SYS_REG_CNTP_CTL_EL0,
                    HV_SYS_REG_CNTP_CVAL_EL0,
                    HV_SYS_REG_CNTV_CTL_EL0,
                    HV_SYS_REG_CNTV_CVAL_EL0,
                ]
                .contains(&register.id)
            {
                continue;
            }
            self.write_sys_reg(register.id, register.value)?;
        }
        if context.profile.maximum_svl != 0 {
            let mode = SmeState {
                streaming: context.sme.streaming,
                za: context.sme.za_enabled,
            };
            // SAFETY: owner thread, admitted mode and concrete SDK C layout.
            check(
                unsafe { (api.set_sme)(self.vcpu, &mode) },
                "restore SME mode",
            )?;
        }
        for (index, value) in registers.x.iter().enumerate() {
            self.write_gpr(index as u32, *value)?;
        }
        self.write_gpr(HV_REG_PC, registers.pc)?;
        self.write_gpr(HV_REG_CPSR, registers.pstate)?;
        self.write_gpr(HV_REG_FPCR, u64::from(registers.fpcr))?;
        for (index, q) in registers.v.iter().enumerate() {
            self.write_simd_reg(index as u32, *q)?;
        }
        let bytes = usize::from(context.profile.maximum_svl);
        if context.sme.streaming {
            for (index, z) in context.sme.z.chunks_exact(bytes).enumerate() {
                // SAFETY: validation fixed each vector length to the SDK maximum.
                check(
                    unsafe { (api.set_z)(self.vcpu, index as u32, z.as_ptr(), z.len()) },
                    "restore streaming Z",
                )?;
            }
            for (index, p) in context.sme.p.chunks_exact(bytes / 8).enumerate() {
                check(
                    unsafe { (api.set_p)(self.vcpu, index as u32, p.as_ptr(), p.len()) },
                    "restore streaming P",
                )?;
            }
        }
        if context.sme.za_enabled {
            check(
                unsafe { (api.set_za)(self.vcpu, context.sme.za.as_ptr(), context.sme.za.len()) },
                "restore ZA",
            )?;
            if let Some(data) = &context.sme.zt {
                let mut zt = Zt([0; 64]);
                zt.0.copy_from_slice(data);
                check(unsafe { (api.set_zt)(self.vcpu, &zt) }, "restore ZT0")?;
            }
        }
        // Streaming transitions overwrite FPSR; publish the saved flags last.
        self.write_gpr(HV_REG_FPSR, u64::from(registers.fpsr))?;
        self.write_sys_reg(HV_SYS_REG_CNTP_CVAL_EL0, context.public.sregs.cntp_cval_el0)?;
        self.write_sys_reg(HV_SYS_REG_CNTV_CVAL_EL0, context.public.sregs.cntv_cval_el0)?;
        self.write_sys_reg(HV_SYS_REG_CNTP_CTL_EL0, context.public.sregs.cntp_ctl_el0)?;
        self.write_sys_reg(HV_SYS_REG_CNTV_CTL_EL0, context.public.sregs.cntv_ctl_el0)?;
        let controls = &context.controls;
        check(
            unsafe { hv_vcpu_set_vtimer_offset(self.vcpu, controls.vtimer_offset) },
            "restore virtual timer offset",
        )?;
        check(
            unsafe { hv_vcpu_set_vtimer_mask(self.vcpu, controls.vtimer_masked) },
            "restore virtual timer mask",
        )?;
        check(
            unsafe { (api.set_trap_exceptions)(self.vcpu, controls.trap_debug_exceptions) },
            "restore debug exception control",
        )?;
        check(
            unsafe { (api.set_trap_registers)(self.vcpu, controls.trap_debug_registers) },
            "restore debug register control",
        )?;
        check(
            unsafe { (api.set_serror)(self.vcpu, controls.pending_serror) },
            "restore pending SError",
        )?;
        self.pending_mmio_read = context
            .pending_read
            .as_ref()
            .map(|pending| PendingMmioRead {
                addr: pending.address,
                rt: pending.register,
                size: pending.size,
                sign_extend: pending.sign_extend,
                sixty_four: pending.sixty_four,
                retire_pc: pending.retire_pc,
            });
        self.pending_io_reply = context.pending_reply.clone();
        self.pending_mmio_write = context.pending_write.clone();
        self.io_completion_error = context
            .completion_error
            .as_ref()
            .map(|payload| Error::Emulator(payload.clone()));
        self.shutdown = context.shutdown;
        Ok(())
    }

    /// Shared GIC and RAM are live before derived ICC state is verified, but
    /// no native CPU can enter until every CPU completes this phase.
    pub(super) fn finish_native_context(&mut self, context: &Context) -> Result<()> {
        let api = Api::load()?;
        for register in &context.gic_cpu {
            // SAFETY: owner thread; typed decoder admits exactly the writable ICC bank.
            check(
                unsafe { (api.set_icc)(self.vcpu, register.id, register.value) },
                "restore GIC CPU register",
            )?;
        }
        let mut priority = 0;
        check(
            unsafe { (api.get_icc)(self.vcpu, 0xc65b, &mut priority) },
            "verify GIC running priority",
        )?;
        if priority != context.running_priority {
            return Err(Error::Emulator(
                "restored GIC running priority differs from its causal state".into(),
            ));
        }
        check(
            unsafe { (api.invalidate_tlb)(self.vcpu, 0x18, 0) },
            "invalidate restored EL1 translations",
        )?;
        Ok(())
    }
}
