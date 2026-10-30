//! Native CPU capture; every SDK access executes on the permanent owner.
use super::checkpoint_api::{Api, SmeState, Zt, check};
use super::*;
use crate::backend::arm64_hvf_context::{
    Context, Controls, FEATURE_IDS, ICC_IDS, PendingRead, Profile, Register, SYSTEM_IDS, Sme,
};

impl HvfArm64Core {
    /// Discover target capability independently, before its first guest entry.
    pub(super) fn detect_checkpoint_profile(&self) -> Result<Profile> {
        let api = Api::load()?;
        let mut system = Vec::new();
        for &id in SYSTEM_IDS {
            let mut value = 0;
            // SAFETY: this method runs on the handle's permanent owner, with a
            // live output word and a register identifier from the SDK inventory.
            let status = unsafe { hv_vcpu_get_sys_reg(self.vcpu, id, &mut value) };
            if status == HV_UNSUPPORTED {
                continue;
            }
            check(status, "discover native system register")?;
            system.push(Register { id, value });
        }
        let mut bytes = 0;
        // SAFETY: the resolved SDK function receives a live size_t output.
        let status = unsafe { (api.maximum_svl)(&mut bytes) };
        if status != HV_UNSUPPORTED {
            check(status, "discover maximum native SVL")?;
            if !(16..=256).contains(&bytes) || bytes % 16 != 0 {
                return Err(Error::Emulator("invalid native maximum SVL".into()));
            }
        } else {
            bytes = 0;
        }
        Ok(Profile {
            system_ids: system.iter().map(|r| r.id).collect(),
            feature_values: system
                .into_iter()
                .filter(|r| FEATURE_IDS.contains(&r.id))
                .collect(),
            maximum_svl: bytes as u16,
        })
    }

    fn capture_sme(&self, api: &Api, maximum_svl: u16) -> Result<Sme> {
        let mut sme = Sme {
            streaming: false,
            za_enabled: false,
            z: vec![],
            p: vec![],
            za: vec![],
            zt: None,
        };
        if maximum_svl == 0 {
            return Ok(sme);
        }
        let mut mode = SmeState::default();
        // SAFETY: the owner thread has exclusive access to this handle; all
        // output storage below matches the admitted SDK maximum register size.
        check(
            unsafe { (api.get_sme)(self.vcpu, &mut mode) },
            "capture SME mode",
        )?;
        sme.streaming = mode.streaming;
        sme.za_enabled = mode.za;
        let bytes = usize::from(maximum_svl);
        if mode.streaming {
            sme.z.resize(32 * bytes, 0);
            sme.p.resize(2 * bytes, 0);
            for (index, register) in sme.z.chunks_exact_mut(bytes).enumerate() {
                check(
                    unsafe {
                        (api.get_z)(
                            self.vcpu,
                            index as u32,
                            register.as_mut_ptr(),
                            register.len(),
                        )
                    },
                    "capture streaming Z",
                )?;
            }
            for (index, register) in sme.p.chunks_exact_mut(bytes / 8).enumerate() {
                check(
                    unsafe {
                        (api.get_p)(
                            self.vcpu,
                            index as u32,
                            register.as_mut_ptr(),
                            register.len(),
                        )
                    },
                    "capture streaming P",
                )?;
            }
        }
        if mode.za {
            sme.za.resize(bytes * bytes, 0);
            check(
                unsafe { (api.get_za)(self.vcpu, sme.za.as_mut_ptr(), sme.za.len()) },
                "capture ZA",
            )?;
            let mut zt = Zt([0; 64]);
            let status = unsafe { (api.get_zt)(self.vcpu, &mut zt) };
            if status != HV_UNSUPPORTED {
                check(status, "capture ZT0")?;
                sme.zt = Some(zt.0.to_vec());
            }
        }
        Ok(sme)
    }

    pub(super) fn capture_native_context(&self) -> Result<Context> {
        let api = Api::load()?;
        let profile = self
            .checkpoint_profile
            .as_ref()
            .map_err(|error| Error::Emulator(error.clone()))?;
        let CpuState::Aarch64(public) = self.native_state()? else {
            unreachable!("native AArch64 projection")
        };
        let system = profile
            .system_ids
            .iter()
            .map(|&id| self.read_sys_reg(id).map(|value| Register { id, value }))
            .collect::<Result<Vec<_>>>()?;
        let mut gic_cpu = Vec::with_capacity(ICC_IDS.len());
        for &id in ICC_IDS {
            let mut value = 0;
            // SAFETY: owner thread, exact SDK enum width and live output word.
            check(
                unsafe { (api.get_icc)(self.vcpu, id, &mut value) },
                "capture GIC CPU register",
            )?;
            gic_cpu.push(Register { id, value });
        }
        let mut running_priority = 0;
        check(
            unsafe { (api.get_icc)(self.vcpu, 0xc65b, &mut running_priority) },
            "capture GIC running priority",
        )?;
        let mut controls = Controls {
            vtimer_masked: false,
            vtimer_offset: 0,
            trap_debug_exceptions: false,
            trap_debug_registers: false,
            pending_serror: false,
        };
        check(
            unsafe { hv_vcpu_get_vtimer_mask(self.vcpu, &mut controls.vtimer_masked) },
            "capture virtual timer mask",
        )?;
        check(
            unsafe { hv_vcpu_get_vtimer_offset(self.vcpu, &mut controls.vtimer_offset) },
            "capture virtual timer offset",
        )?;
        check(
            unsafe { (api.get_trap_exceptions)(self.vcpu, &mut controls.trap_debug_exceptions) },
            "capture debug exception control",
        )?;
        check(
            unsafe { (api.get_trap_registers)(self.vcpu, &mut controls.trap_debug_registers) },
            "capture debug register control",
        )?;
        check(
            unsafe { (api.get_serror)(self.vcpu, &mut controls.pending_serror) },
            "capture pending SError",
        )?;
        let completion_error = match self.io_completion_error.as_ref() {
            None => None,
            Some(Error::Emulator(message)) => Some(message.clone()),
            Some(_) => {
                return Err(Error::Emulator(
                    "unknown native completion error producer".into(),
                ));
            }
        };
        let mut context = Context {
            id: self.id,
            profile: profile.clone(),
            public,
            system,
            gic_cpu,
            running_priority,
            controls,
            sme: self.capture_sme(api, profile.maximum_svl)?,
            shutdown: self.native_shutdown()?,
            pending_read: self.pending_mmio_read.map(|pending| PendingRead {
                address: pending.addr,
                register: pending.rt,
                size: pending.size,
                sign_extend: pending.sign_extend,
                sixty_four: pending.sixty_four,
            }),
            pending_reply: self.pending_io_reply.clone(),
            pending_write: self.pending_mmio_write.clone(),
            completion_error,
        };
        context.project_system()?;
        context.validate()?;
        Ok(context)
    }
}
