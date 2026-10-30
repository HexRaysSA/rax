//! Noncommitting rejection and stopped SDK publication for APIC_BASE accesses.
pub(crate) trait Access {
    type Error;
    fn ready(&self) -> Result<(), Self::Error>;
    fn base(&self) -> u64;
    fn publish(&mut self, value: u64);
    fn write_gpr(&mut self, index: u8, value: u64) -> Result<(), Self::Error>;
    fn advance(&mut self) -> Result<(), Self::Error>;
    fn inject_gp(&mut self) -> Result<(), Self::Error>;
    fn fence(&self, error: Self::Error) -> Self::Error;
}

pub(crate) fn read<T: Access>(access: &mut T) -> Result<(), T::Error> {
    access.ready()?;
    let value = access.base();
    access
        .write_gpr(0, value & u64::from(u32::MAX))
        .map_err(|e| access.fence(e))?;
    access
        .write_gpr(2, value >> 32)
        .map_err(|e| access.fence(e))?;
    access.advance().map_err(|e| access.fence(e))
}

pub(crate) fn write<T: Access>(access: &mut T, value: u64) -> Result<(), T::Error> {
    access.ready()?;
    if !super::apic_profile::valid_apic_base(value) {
        return access.inject_gp().map_err(|e| access.fence(e));
    }
    // A failed SDK completion may have partially changed RIP. Fence entry and
    // preserve the old model. Publication after successful completion cannot fail.
    access.advance().map_err(|e| access.fence(e))?;
    access.publish(value);
    Ok(())
}
