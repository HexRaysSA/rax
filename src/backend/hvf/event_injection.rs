//! Arbitration of the single VM-entry event slot.
//!
//! A blocked request remains owned by the caller. No private IRQ queue accepts
//! an event while reporting that injection was blocked.

const VALID: u64 = 1 << 31;
const IF: u64 = 1 << 9;
const STI_OR_MOV_SS: u64 = 3;
const NMI_BLOCKING: u64 = 1 << 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Event {
    Interrupt(u8),
    Nmi,
}

impl Event {
    fn information(self) -> u64 {
        VALID
            | match self {
                Self::Interrupt(vector) => u64::from(vector),
                Self::Nmi => (2 << 8) | 2,
            }
    }
}

pub(crate) trait Access {
    type Error;
    fn entry_information(&mut self) -> Result<u64, Self::Error>;
    fn rflags(&mut self) -> Result<u64, Self::Error>;
    fn interruptibility(&mut self) -> Result<u64, Self::Error>;
    fn pending_debug(&mut self) -> Result<u64, Self::Error>;
    fn write_entry_information(&mut self, information: u64) -> Result<(), Self::Error>;
}

/// Intel SDM Vol.3C28.3.1.4-5: external IRQs require IF and no STI/MOV-SS
/// blocking. NMI blocking applies to NMIs, not to external IRQs.
/// Section28.7.3: injecting either event discards pending debug exceptions.
/// Deliver an unblocked previous-instruction debug trap first; it has higher
/// priority than either event. The caller continues to own a deferred request.
pub(crate) fn available<T: Access>(host: &mut T, event: Event) -> Result<bool, T::Error> {
    if host.entry_information()? & VALID != 0 {
        return Ok(false);
    }
    if matches!(event, Event::Interrupt(_)) && host.rflags()? & IF == 0 {
        return Ok(false);
    }
    let blocked = match event {
        Event::Interrupt(_) => STI_OR_MOV_SS,
        Event::Nmi => STI_OR_MOV_SS | NMI_BLOCKING,
    };
    let shadow = host.interruptibility()?;
    if shadow & blocked != 0 {
        return Ok(false);
    }
    Ok(!super::retirement::pending_trap(
        host.pending_debug()?,
        shadow,
    ))
}

/// True means the event was written successfully; false consumes nothing.
/// A host error is propagated without consuming the caller's request.
pub(crate) fn inject<T: Access>(host: &mut T, event: Event) -> Result<bool, T::Error> {
    if !available(host, event)? {
        return Ok(false);
    }
    host.write_entry_information(event.information())?;
    Ok(true)
}
