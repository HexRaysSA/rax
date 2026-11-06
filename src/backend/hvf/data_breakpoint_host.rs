//! Stage memory/I/O causes under the pending-transaction entry exclusion.
use super::bindings::{hv_vmx_vmcs_field_t as V, hv_x86_reg_t as R};
use super::{HvfCore, data_breakpoints, read_register, vmcs_read, vmcs_write};
use crate::backend::intel_hvf_context::{Context, Packet};
use crate::backend::intel_hvf_io::mmio::{Action, Plan};
use crate::error::{Error, Result};

impl Context {
    /// The original linear address is absent from old pending-MMIO records.
    /// GPA aliases and replacement of already-fetched code make recomputation
    /// ambiguous, even when the saved pending field is nonzero. Reject before
    /// any destination mutation, including imports of old terminal records.
    pub(super) fn reject_ambiguous_legacy_mmio(&self) -> Result<()> {
        if self.mmio_debug_complete {
            return Ok(());
        }
        let writing = if let Some((_, operation)) = self.mmio_input.descriptor() {
            operation.is_some()
        } else if matches!(self.output, Some((Packet::Write { .. }, _))) {
            true
        } else {
            return Ok(());
        };
        if data_breakpoints::relevant(self.public.sregs.dr7, writing) != 0 {
            return Err(Error::InvalidConfig(
                "legacy pending MMIO record lacks complete data-breakpoint provenance".into(),
            ));
        }
        Ok(())
    }

    /// Older producers omitted the I/O cause, but retained the complete pending
    /// access and guest debug bank. Reconstruct it only on an admitted incoming
    /// record. Live rollback and terminal failure records retain their exact image.
    pub(super) fn pending_port_breakpoint_causes(&self) -> Result<u64> {
        if self.shutdown
            || self.execution_failure.is_some()
            || self.restore_failure.is_some()
            || self.priority_failure.is_some()
            || self.output_failure.is_some()
            || self.port_input.failure().is_some()
            || self.mmio_input.failure().is_some()
        {
            return Ok(0);
        }
        let access = if let Some(input) = self.port_input.descriptor() {
            Some((input.io.port, input.io.size))
        } else if let Some((Packet::PortWrite { port, data }, _)) = &self.output {
            Some((*port, data.len() as u8))
        } else {
            None
        };
        let Some((port, size)) = access else {
            return Ok(0);
        };
        let guest = &self.public.sregs;
        let addresses = [guest.dr0, guest.dr1, guest.dr2, guest.dr3];
        data_breakpoints::port_causes(guest.dr7, guest.cr4, &addresses, port, size)
            .map_err(|error| Error::InvalidConfig(error.into()))
    }
}

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
        let addresses = self.debug_breakpoint_addresses(enabled)?;
        data_breakpoints::causes(dr7, &addresses, plan.linear, size, writing)
            .map_err(|error| Error::Emulator(error.into()))
    }

    pub(super) fn port_breakpoint_causes(&self, io: super::port_io::ScalarIo) -> Result<u64> {
        let dr7 = vmcs_read(self.vcpu_id, V::VMCS_GUEST_DR7)?;
        let enabled = data_breakpoints::port_relevant(dr7);
        if enabled == 0 {
            return Ok(0);
        }
        let cr4 = vmcs_read(self.vcpu_id, V::VMCS_GUEST_CR4)?;
        if cr4 & data_breakpoints::DEBUG_EXTENSIONS == 0 {
            return Ok(0);
        }
        let addresses = self.debug_breakpoint_addresses(enabled)?;
        data_breakpoints::port_causes(dr7, cr4, &addresses, io.port, io.size)
            .map_err(|error| Error::Emulator(error.into()))
    }

    fn debug_breakpoint_addresses(&self, enabled: u8) -> Result<[u64; 4]> {
        let mut addresses = [0; 4];
        for (slot, register) in [R::HV_X86_DR0, R::HV_X86_DR1, R::HV_X86_DR2, R::HV_X86_DR3]
            .into_iter()
            .enumerate()
        {
            if enabled & (1 << slot) != 0 {
                addresses[slot] = read_register(self.vcpu_id, register)?;
            }
        }
        Ok(addresses)
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
