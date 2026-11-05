//! Stage data causes under the existing pending-transaction entry exclusion.
use super::bindings::{hv_vmx_vmcs_field_t as V, hv_x86_reg_t as R};
use super::{HvfCore, data_breakpoints, read_register, vmcs_read, vmcs_write};
use crate::backend::intel_hvf_io::mmio::{Action, Plan};
use crate::error::{Error, Result};

impl HvfCore {
    pub(super) fn data_breakpoint_causes(&self, plan: &Plan) -> Result<u64> {
        let (size, writing) = match &plan.action {
            Action::Read(input) => (input.size, false),
            Action::AluRead(input) => (input.size, false),
            Action::Write(data) => (data.len() as u8, true),
            Action::Rmw(input) => (input.size, true),
        };
        let dr7 = vmcs_read(self.vcpu_id, V::VMCS_GUEST_DR7)?;
        let enabled = data_breakpoints::relevant(dr7, writing);
        if enabled == 0 {
            return Ok(0);
        }
        let mut addresses = [0; 4];
        for (slot, register) in [R::HV_X86_DR0, R::HV_X86_DR1, R::HV_X86_DR2, R::HV_X86_DR3]
            .into_iter()
            .enumerate()
        {
            if enabled & (1 << slot) != 0 {
                addresses[slot] = read_register(self.vcpu_id, register)?;
            }
        }
        data_breakpoints::causes(dr7, &addresses, plan.linear, size, writing)
            .map_err(|error| Error::Emulator(error.into()))
    }

    pub(super) fn retain_data_breakpoints(&self, causes: u64) -> Result<()> {
        if causes == 0 {
            return Ok(());
        }
        // A pending input/output excludes native entry, state overlays and
        // asynchronous injection until the device effect and retirement finish.
        // The existing serialized VMCS field therefore retains these deferred
        // causes across owner destruction without inventing a second state bank.
        // DR6 is untouched: only subsequent hardware #DB delivery publishes it.
        let pending = vmcs_read(self.vcpu_id, V::VMCS_GUEST_PENDING_DBG_EXCEPTIONS)?;
        if pending | causes != pending {
            vmcs_write(
                self.vcpu_id,
                V::VMCS_GUEST_PENDING_DBG_EXCEPTIONS,
                pending | causes,
            )?;
        }
        Ok(())
    }
}
