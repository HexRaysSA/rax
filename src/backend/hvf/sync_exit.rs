//! Synchronous VM-exit boundaries; host calls remain in the Intel adapter.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AdvanceError {
    InvalidLength,
    InvalidCodeWidth,
}

/// CS.D controls decoding defaults; EIP remains32-bit in non64-bit code.
pub(crate) fn code_width(efer: u64, cs_access: u64) -> u32 {
    if efer & (1 << 10) != 0 && cs_access & (1 << 13) != 0 {
        64
    } else {
        32
    }
}

/// Fixed-width IP increment. Subsequent fetch/segment/canonical faults are separate.
pub(crate) fn next_ip(current: u64, length: u64, bits: u32) -> Result<u64, AdvanceError> {
    if !(1..=15).contains(&length) {
        return Err(AdvanceError::InvalidLength);
    }
    let mask = match bits {
        32 => 0xffff_ffff,
        64 => u64::MAX,
        _ => return Err(AdvanceError::InvalidCodeWidth),
    };
    Ok(current.wrapping_add(length) & mask)
}

pub(crate) trait HaltAccess {
    type Error;
    fn advance_current_instruction(&mut self) -> Result<(), Self::Error>;
    fn set_halted(&mut self, halted: bool) -> Result<(), Self::Error>;
}

pub(crate) fn halt<T: HaltAccess>(host: &mut T) -> Result<(), T::Error> {
    host.advance_current_instruction()?;
    host.set_halted(true)
}

pub(crate) fn wake<T: HaltAccess>(host: &mut T) -> Result<(), T::Error> {
    host.set_halted(false)
}

/// SDK/Intel VM-exit interruption-information field; checked against the SDK probe.
pub(crate) const VM_EXIT_INTERRUPTION_INFO_FIELD: u32 = 0x0000_4404;

pub(crate) trait ExceptionAccess {
    type Error;
    fn read_vmcs(&mut self, field: u32) -> Result<u64, Self::Error>;
}

/// None is an invalid exit record, never a fabricated vector zero.
/// This projects the existing vector-only public API, not a full exception frame.
pub(crate) fn exception_vector<T: ExceptionAccess>(host: &mut T) -> Result<Option<u8>, T::Error> {
    let info = host.read_vmcs(VM_EXIT_INTERRUPTION_INFO_FIELD)?;
    Ok((info & (1 << 31) != 0).then_some((info & 0xff) as u8))
}
