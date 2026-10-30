//! Stopped SDK paging inspection and fallible post-debugger cache synchronization.
use super::*;
impl HvfVcpu {
    pub(super) fn debug_paging_state(&self) -> Result<crate::vm::vcpu::DebugAddressSpace> {
        use hv_vmx_vmcs_field_t::*;
        self.priority.ready().map_err(Error::Emulator)?;
        let guard = self
            .memory_layout
            .read()
            .map_err(|_| Error::Emulator("HVF debug layout lock poisoned".into()))?;
        let registered = guard
            .as_ref()
            .ok_or_else(|| Error::InvalidConfig("HVF debug RAM is not registered".into()))?;
        registered.mapping.ready().map_err(Error::Emulator)?;
        let cr0 = read_register(self.vcpu_id, hv_x86_reg_t::HV_X86_CR0)?;
        let cr3 = read_register(self.vcpu_id, hv_x86_reg_t::HV_X86_CR3)?;
        let cr4 = read_register(self.vcpu_id, hv_x86_reg_t::HV_X86_CR4)?;
        let efer = vmcs_read(self.vcpu_id, VMCS_GUEST_IA32_EFER)?;
        let pdpte = if cr0 & (1 << 31) != 0 && cr4 & (1 << 5) != 0 && efer & (1 << 10) == 0 {
            let mut values = [0; 4];
            for (value, field) in values.iter_mut().zip([
                VMCS_GUEST_PDPTE0,
                VMCS_GUEST_PDPTE1,
                VMCS_GUEST_PDPTE2,
                VMCS_GUEST_PDPTE3,
            ]) {
                *value = vmcs_read(self.vcpu_id, field)?;
            }
            Some(values)
        } else {
            None
        };
        let edx = self.cpuid_config.cpuid(1, 0).3;
        Ok(crate::vm::vcpu::DebugAddressSpace::X86(
            crate::vm::vcpu::X86DebugPaging {
                cr0,
                cr3,
                cr4,
                efer,
                pdpte,
                physical_bits: self.cpuid_config.cpuid(0x8000_0008, 0).0 & 255,
                pse36: edx & (1 << 17) != 0,
                pat: edx & (1 << 16) != 0,
            },
        ))
    }
    pub(super) fn debug_invalidate_translation(&self) -> Result<()> {
        self.priority.ready().map_err(Error::Emulator)?;
        // SAFETY: the serialized VMM owns this live SDK vCPU and no entry runs
        // during debugger publication. The call retains no Rust reference.
        let result = unsafe { hv_vcpu_invalidate_tlb(self.vcpu_id) };
        if result != HV_SUCCESS {
            return Err(Error::Emulator(self.priority.poison(format!(
                "debug TLB invalidation: {}",
                hv_error_string(result)
            ))));
        }
        Ok(())
    }
}
