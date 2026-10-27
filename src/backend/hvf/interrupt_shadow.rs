//! Complete the saved STI/MOV-SS shadow after an emulated instruction succeeds.
//! Intel SDM Vol.3C28.7.1 and29.3.4: VM exit preserves the pre-instruction shadow;
//! it expires after one guest instruction, including an intercepted instruction
//! completed by software. Fault paths do not call this boundary.

pub(crate) trait Access {
    type Error;
    fn interruptibility(&mut self) -> Result<u64, Self::Error>;
    fn advance_ip(&mut self) -> Result<(), Self::Error>;
    fn write_interruptibility(&mut self, value: u64) -> Result<(), Self::Error>;
}

/// Pre-read the shadow before committing IP. Clear only STI/MOV-SS bits after
/// successful advancement; preserve NMI/SMI/enclave and unrelated saved state.
/// Host write failures stop execution and are propagated; no rollback is implied.
pub(crate) fn complete<T: Access>(host: &mut T) -> Result<(), T::Error> {
    let before = host.interruptibility()?;
    host.advance_ip()?;
    let after = before & !3;
    if after != before {
        host.write_interruptibility(after)?;
    }
    Ok(())
}
