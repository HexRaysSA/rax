//! SDK adapter for the shared stopped APIC_BASE access policy.
use super::*;

impl HvfCore {
    pub(super) fn handle_apic_base(&self, value: Option<u64>) -> Result<()> {
        struct Access<'a>(&'a HvfCore);
        impl apic_identity::Access for Access<'_> {
            type Error = Error;
            fn ready(&self) -> Result<()> {
                self.0.priority.ready().map_err(Error::Emulator)
            }
            fn base(&self) -> u64 {
                self.0.apic_base.load(Ordering::SeqCst)
            }
            fn publish(&mut self, value: u64) {
                self.0.apic_base.store(value, Ordering::SeqCst);
            }
            fn write_gpr(&mut self, index: u8, value: u64) -> Result<()> {
                write_register(self.0.vcpu_id, general_register(index)?, value)
            }
            fn advance(&mut self) -> Result<()> {
                self.0.advance_current_instruction()
            }
            fn inject_gp(&mut self) -> Result<()> {
                self.0.inject_fault(xsetbv::XsetbvFault::GeneralProtection)
            }
            fn fence(&self, error: Error) -> Error {
                Error::Emulator(
                    self.0
                        .priority
                        .poison(format!("APIC_BASE completion: {error}")),
                )
            }
        }
        let mut access = Access(self);
        match value {
            Some(value) => apic_identity::write(&mut access, value),
            None => apic_identity::read(&mut access),
        }
    }
}
