//! INIT publication on the permanent SDK owner, preserving the native clock.
//! Intel SDM086 Vol.3A Table11-1 and note2 define the architectural reset set.
//! Linux v6.8 vmx_vcpu_reset documents valid VMX TR/LDTR representations.
use super::*;
use crate::backend::intel_hvf_context::Context;

fn reset_mpx(context: &mut Context) -> Result<()> {
    // INIT clears BNDREGS/BNDCSR while preserving every other XSAVE component.
    // Retain XCOMP_BV: its bits describe the compacted storage layout.
    let compact = u64::from_le_bytes(
        context.fp[520..528]
            .try_into()
            .map_err(|_| Error::InvalidConfig("missing native XSAVE header".into()))?,
    );
    let mut offset = 576usize;
    for component in &context.profile.xsave.components {
        let start = if compact >> 63 != 0 {
            if compact & (1u64 << component.bit) == 0 {
                continue;
            }
            if component.align64 {
                offset = (offset + 63) & !63;
            }
            let start = offset;
            offset += component.size as usize;
            start
        } else {
            component.offset as usize
        };
        if matches!(component.bit, 3 | 4) {
            let bytes = context
                .fp
                .get_mut(start..start + component.size as usize)
                .ok_or_else(|| Error::InvalidConfig("native MPX image exceeds XSAVE".into()))?;
            bytes.fill(0);
        }
    }
    let mut active = u64::from_le_bytes(context.fp[512..520].try_into().unwrap());
    active &= !((1 << 3) | (1 << 4));
    context.fp[512..520].copy_from_slice(&active.to_le_bytes());
    Ok(())
}

fn reset(context: &mut Context, signature: u32) -> Result<()> {
    use hv_vmx_vmcs_field_t::*;
    use hv_x86_reg_t::*;

    // Capture validates all bounds before this pure transformation. The XSAVE
    // buffer is at least 576 bytes and every component lies inside that buffer.
    context.validate()?;
    let cr0 = (context.public.sregs.cr0 & 0x6000_0000) | 0x10;
    for register in &mut context.registers {
        register.value = match register_from_raw(register.id) {
            Some(HV_X86_RIP) => 0xfff0,
            Some(HV_X86_RFLAGS) => 2,
            Some(HV_X86_RDX) => u64::from(signature),
            Some(HV_X86_DR6) => 0xffff_0ff0,
            Some(HV_X86_XCR0) => register.value,
            _ => 0,
        };
    }
    for register in &mut context.vmcs {
        let value = match vmcs_from_raw(register.id) {
            Some(VMCS_GUEST_CS_SELECTOR) => 0xf000,
            Some(VMCS_GUEST_CS_BASE) => 0xffff_0000,
            Some(
                VMCS_GUEST_CS_LIMIT
                | VMCS_GUEST_DS_LIMIT
                | VMCS_GUEST_ES_LIMIT
                | VMCS_GUEST_FS_LIMIT
                | VMCS_GUEST_GS_LIMIT
                | VMCS_GUEST_SS_LIMIT
                | VMCS_GUEST_TR_LIMIT
                | VMCS_GUEST_LDTR_LIMIT
                | VMCS_GUEST_GDTR_LIMIT
                | VMCS_GUEST_IDTR_LIMIT,
            ) => 0xffff,
            Some(
                VMCS_GUEST_CS_ACCESS_RIGHTS
                | VMCS_GUEST_DS_ACCESS_RIGHTS
                | VMCS_GUEST_ES_ACCESS_RIGHTS
                | VMCS_GUEST_FS_ACCESS_RIGHTS
                | VMCS_GUEST_GS_ACCESS_RIGHTS
                | VMCS_GUEST_SS_ACCESS_RIGHTS,
            ) => 0x93,
            Some(VMCS_GUEST_TR_ACCESS_RIGHTS) => 0x8b,
            Some(VMCS_GUEST_LDTR_ACCESS_RIGHTS) => 0x82,
            Some(VMCS_GUEST_CR0 | VMCS_CTRL_CR0_SHADOW) => cr0,
            Some(VMCS_GUEST_DR7) => 0x400,
            Some(VMCS_CTRL_VMENTRY_CONTROLS) => register.value & !(1 << 9),
            Some(VMCS_CTRL_CPU_BASED) => register.value & !(1 << 2),
            Some(
                VMCS_GUEST_DS_SELECTOR
                | VMCS_GUEST_ES_SELECTOR
                | VMCS_GUEST_FS_SELECTOR
                | VMCS_GUEST_GS_SELECTOR
                | VMCS_GUEST_SS_SELECTOR
                | VMCS_GUEST_TR_SELECTOR
                | VMCS_GUEST_LDTR_SELECTOR
                | VMCS_GUEST_DS_BASE
                | VMCS_GUEST_ES_BASE
                | VMCS_GUEST_FS_BASE
                | VMCS_GUEST_GS_BASE
                | VMCS_GUEST_SS_BASE
                | VMCS_GUEST_TR_BASE
                | VMCS_GUEST_LDTR_BASE
                | VMCS_GUEST_GDTR_BASE
                | VMCS_GUEST_IDTR_BASE
                | VMCS_GUEST_CR3
                | VMCS_GUEST_CR4
                | VMCS_CTRL_CR4_SHADOW
                | VMCS_GUEST_IA32_EFER
                | VMCS_GUEST_INTERRUPTIBILITY_STATE
                | VMCS_GUEST_ACTIVITY_STATE
                | VMCS_GUEST_PENDING_DBG_EXCEPTIONS
                | VMCS_CTRL_VMENTRY_IRQ_INFO
                | VMCS_CTRL_VMENTRY_EXCEPTION_ERROR
                | VMCS_CTRL_VMENTRY_INSTRUCTION_LENGTH,
            ) => 0,
            _ => continue,
        };
        register.value = value;
    }
    reset_mpx(context)?;
    context.tpr = 0;
    context.halted = false;
    context.shutdown = false;
    context.port_input = Default::default();
    context.mmio_input = Default::default();
    context.request = None;
    context.output = None;
    context.output_failure = None;
    context.debug.completed = false;
    let (public, emulator) = context.projection()?;
    context.public = public;
    context.emulator = emulator;
    context.validate()
}

impl HvfCore {
    pub(super) fn deliver_init_signal(&mut self) -> Result<()> {
        self.execution_ready()?;
        let before = self.capture_native(None)?;
        let mut initialized = before.clone();
        reset(&mut initialized, self.cpuid_config.cpuid(1, 0).0)?;
        let result = self
            .apply_native(
                &initialized,
                true,
                intel_checkpoint::ClockPublication::Rollback,
            )
            .and_then(|()| self.finish_native(&initialized));
        if let Err(error) = result {
            if let Err(rollback) = self
                .apply_native(&before, false, intel_checkpoint::ClockPublication::Rollback)
                .and_then(|()| self.finish_native(&before))
            {
                self._vm.poison(format!(
                    "native INIT failed: {error}; rollback failed: {rollback}"
                ));
                return Err(Error::Emulator(format!(
                    "native INIT failed: {error}; rollback failed: {rollback}; guest entry disabled"
                )));
            }
            return Err(error);
        }
        Ok(())
    }
}
