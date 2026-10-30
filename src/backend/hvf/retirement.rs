//! Completion of intercepted non-branch instructions, including guest debugging.
//! Intel SDM December 2024: Vol.3B 19.3.1.1/19.3.1.4; Vol.3C 28.7.3,
//! 29.3.4. Fault paths and incomplete device transfers do not reach this boundary.

pub(crate) const SINGLE_STEP: u64 = 1 << 8;
pub(crate) const RESUME: u64 = 1 << 16;
pub(crate) const BRANCH_STEP: u64 = 1 << 1;
pub(crate) const PENDING_STEP: u64 = 1 << 14;

/// SDM 28.7.3: a valid pending debug trap wakes HLT on VM entry when
/// MOV-SS does not block it. STI blocking does not suppress debug delivery.
pub(crate) fn pending_trap(pending: u64, interruptibility: u64) -> bool {
    pending & ((1 << 12) | PENDING_STEP) != 0 && interruptibility & (1 << 1) == 0
}

pub(crate) trait Access {
    type Error;
    fn rflags(&mut self) -> Result<u64, Self::Error>;
    fn debug_control(&mut self) -> Result<u64, Self::Error>;
    fn pending_debug(&mut self) -> Result<u64, Self::Error>;
    fn interruptibility(&mut self) -> Result<u64, Self::Error>;
    fn advance_ip(&mut self) -> Result<(), Self::Error>;
    fn write_rflags(&mut self, value: u64) -> Result<(), Self::Error>;
    fn write_pending_debug(&mut self, value: u64) -> Result<(), Self::Error>;
    fn write_interruptibility(&mut self, value: u64) -> Result<(), Self::Error>;
}

/// These instructions neither branch nor explicitly change TF/RF. Preserve
/// saved guest debug causes and synthesize the guest's instruction-step trap;
/// MTF takes priority over that trap, so delivery remains pending across a host
/// stop. Read before writing; a later failure requires the owner to fence all
/// further entry and capture, since architectural writes may already be visible.
/// O(1) time and auxiliary space.
pub(crate) fn complete<T: Access>(host: &mut T) -> Result<(), T::Error> {
    let flags = host.rflags()?;
    let control = host.debug_control()?;
    let pending = host.pending_debug()?;
    let shadow = host.interruptibility()?;
    let next_pending = if flags & SINGLE_STEP != 0 && control & BRANCH_STEP == 0 {
        pending | PENDING_STEP
    } else {
        pending
    };

    struct Boundary<'a, T> {
        host: &'a mut T,
        flags: u64,
        pending: u64,
        next_pending: u64,
        shadow: u64,
    }
    impl<T: Access> super::interrupt_shadow::Access for Boundary<'_, T> {
        type Error = T::Error;
        fn interruptibility(&mut self) -> Result<u64, Self::Error> {
            Ok(self.shadow)
        }
        fn advance_ip(&mut self) -> Result<(), Self::Error> {
            self.host.advance_ip()?;
            if self.flags & RESUME != 0 {
                self.host.write_rflags(self.flags & !RESUME)?;
            }
            if self.next_pending != self.pending {
                self.host.write_pending_debug(self.next_pending)?;
            }
            Ok(())
        }
        fn write_interruptibility(&mut self, value: u64) -> Result<(), Self::Error> {
            self.host.write_interruptibility(value)
        }
    }
    super::interrupt_shadow::complete(&mut Boundary {
        host,
        flags,
        pending,
        next_pending,
        shadow,
    })
}
