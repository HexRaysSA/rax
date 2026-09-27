//! Exception types, masks, behaviors, and thread-state flavors
//! (`osfmk/mach/exception_types.h`, `osfmk/mach/{arm,i386}/exception.h`,
//! `osfmk/mach/{arm,i386}/thread_status.h`), and the checks
//! `*_set_exception_ports` makes before it installs a handler
//! (`set_exception_ports_validation`, `osfmk/kern/ipc_tt.c`, and
//! `ipc_is_valid_exception_port`, `osfmk/kern/exception_policy.c`).

use std::sync::Arc;

use super::ipc::{KObject, Port};
use super::kr::{self, KernReturn};
use crate::user::darwin::abi::DarwinAbi;

/// `EXC_*` exception types.
pub mod exc {
    /// `EXC_BAD_ACCESS`.
    pub const BAD_ACCESS: i32 = 1;
    /// `EXC_BAD_INSTRUCTION`.
    pub const BAD_INSTRUCTION: i32 = 2;
    /// `EXC_ARITHMETIC`.
    pub const ARITHMETIC: i32 = 3;
    /// `EXC_SOFTWARE`.
    pub const SOFTWARE: i32 = 5;
    /// `EXC_BREAKPOINT`.
    pub const BREAKPOINT: i32 = 6;
    /// `EXC_SYSCALL`.
    pub const SYSCALL: i32 = 7;
    /// `EXC_MACH_SYSCALL`.
    pub const MACH_SYSCALL: i32 = 8;
    /// `EXC_RPC_ALERT`.
    pub const RPC_ALERT: i32 = 9;
    /// `EXC_CRASH`.
    pub const CRASH: i32 = 10;
    /// `EXC_RESOURCE`.
    pub const RESOURCE: i32 = 11;
    /// `EXC_GUARD`.
    pub const GUARD: i32 = 12;
    /// `EXC_CORPSE_NOTIFY`.
    pub const CORPSE_NOTIFY: i32 = 13;
}

/// `EXC_TYPES_COUNT`: actions are indexed by exception type, 1 ..= 13.
pub const EXC_TYPES_COUNT: usize = 14;

/// `EXC_MASK_VALID`: `EXC_MASK_ALL` with `EXC_MASK_CRASH` and
/// `EXC_MASK_CORPSE_NOTIFY`.
pub const EXC_MASK_VALID: u32 = 0x3ffe;

/// The exceptions the host's handler (`ux_handler`) turns into signals:
/// `EXC_MASK_ALL` less `EXC_MASK_RPC_ALERT` and `EXC_MASK_GUARD`.
pub const EXC_MASK_UX: u32 = 0x09fe;

/// `exception_behavior_t` values and flags.
pub mod behavior {
    /// `EXCEPTION_DEFAULT`.
    pub const DEFAULT: i32 = 1;
    /// `EXCEPTION_STATE`.
    pub const STATE: i32 = 2;
    /// `EXCEPTION_STATE_IDENTITY`.
    pub const STATE_IDENTITY: i32 = 3;
    /// `EXCEPTION_IDENTITY_PROTECTED`.
    pub const IDENTITY_PROTECTED: i32 = 4;
    /// `EXCEPTION_STATE_IDENTITY_PROTECTED`.
    pub const STATE_IDENTITY_PROTECTED: i32 = 5;
    /// `MACH_EXCEPTION_BACKTRACE_PREFERRED`.
    pub const BACKTRACE_PREFERRED: u32 = 0x2000_0000;
    /// `MACH_EXCEPTION_ERRORS`.
    pub const ERRORS: u32 = 0x4000_0000;
    /// `MACH_EXCEPTION_CODES`: 64-bit codes.
    pub const CODES: u32 = 0x8000_0000;
    /// `MACH_EXCEPTION_MASK`: every flag.
    pub const FLAGS: u32 = CODES | ERRORS | BACKTRACE_PREFERRED;

    /// The behavior without its flags.
    pub fn base(b: i32) -> i32 {
        (b as u32 & !FLAGS) as i32
    }
}

/// Whether `flavor` is a thread-state flavor of the kernel's
/// architecture (`VALID_THREAD_STATE_FLAVOR`); the kernel of an arm64
/// guest is the host's Apple-silicon kernel, which also takes flavor 25
/// (its `ARM_STATE_FLAVOR_IS_OTHER_VALID`), that of an x86-64 guest an
/// Intel kernel.
pub fn valid_flavor(abi: DarwinAbi, flavor: i32) -> bool {
    match abi {
        DarwinAbi::Arm64 => matches!(flavor, 1..=7 | 9 | 10 | 14..=17 | 25 | 27),
        DarwinAbi::X86_64 => matches!(flavor, 1..=13 | 16..=25),
    }
}

/// A handler as `set_exception_ports` receives it: none, a dead name, or
/// a send right.
#[derive(Clone, Debug, Default)]
pub enum Handler {
    /// `MACH_PORT_NULL`.
    #[default]
    None,
    /// `MACH_PORT_DEAD` (a dead name copied in).
    Dead,
    /// A send right.
    Port(Arc<Port>),
}

impl Handler {
    /// The port of a live handler.
    pub fn port(&self) -> Option<&Arc<Port>> {
        match self {
            Handler::Port(p) => Some(p),
            _ => None,
        }
    }
}

/// `set_exception_ports_validation`, in its order: the mask, then (for a
/// handler) the behavior and whether the port may handle exceptions (a
/// plain port, not a kernel object's), then the flavor and the 64-bit
/// codes the protected and backtrace behaviors need, handler or not.
///
/// Behavior 5 without `MACH_EXCEPTION_CODES` is refused too: XNU takes it
/// and then panics when it delivers an exception to it.
pub fn validate(
    abi: DarwinAbi,
    mask: u32,
    handler: &Handler,
    behavior: i32,
    flavor: i32,
) -> Result<(), KernReturn> {
    if mask & !EXC_MASK_VALID != 0 {
        return Err(kr::KERN_INVALID_ARGUMENT);
    }
    let base = behavior::base(behavior);
    if let Handler::Port(p) = handler {
        if !(behavior::DEFAULT..=behavior::STATE_IDENTITY_PROTECTED).contains(&base) {
            return Err(kr::KERN_INVALID_ARGUMENT);
        }
        if p.kobject != KObject::None {
            return Err(kr::KERN_INVALID_RIGHT);
        }
    }
    if flavor != 0 && !valid_flavor(abi, flavor) {
        return Err(kr::KERN_INVALID_ARGUMENT);
    }
    let codes = behavior as u32 & behavior::CODES != 0;
    let needs_codes = base == behavior::IDENTITY_PROTECTED
        || base == behavior::STATE_IDENTITY_PROTECTED
        || behavior as u32 & behavior::BACKTRACE_PREFERRED != 0;
    if needs_codes && !codes {
        return Err(kr::KERN_INVALID_ARGUMENT);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_follows_xnu_order() {
        let port = Handler::Port(Port::new(KObject::None));
        let kernel = Handler::Port(Port::new(KObject::Host));
        let a = DarwinAbi::Arm64;
        let codes = behavior::CODES as i32;
        // Masks: bit 0 and bits past EXC_CORPSE_NOTIFY.
        for m in [0x1, 0x4000, 0x8000_0000, 0x3fff] {
            assert_eq!(validate(a, m, &port, 1, 0), Err(kr::KERN_INVALID_ARGUMENT));
        }
        assert_eq!(validate(a, EXC_MASK_VALID, &port, 1, 0), Ok(()));
        // The behavior before the port, the port before the flavor.
        assert_eq!(
            validate(a, 2, &kernel, 7, 0),
            Err(kr::KERN_INVALID_ARGUMENT)
        );
        assert_eq!(
            validate(a, 2, &kernel, 1, 9999),
            Err(kr::KERN_INVALID_RIGHT)
        );
        // Without a handler the behavior is not looked at, the flavor is.
        assert_eq!(validate(a, 2, &Handler::None, 7, 0), Ok(()));
        assert_eq!(
            validate(a, 2, &Handler::None, 1, 9999),
            Err(kr::KERN_INVALID_ARGUMENT)
        );
        // The protected and backtrace behaviors need 64-bit codes.
        assert_eq!(
            validate(a, 2, &Handler::None, 4, 0),
            Err(kr::KERN_INVALID_ARGUMENT)
        );
        assert_eq!(validate(a, 2, &port, 4 | codes, 0), Ok(()));
        assert_eq!(
            validate(a, 2, &port, 0x2000_0001, 0),
            Err(kr::KERN_INVALID_ARGUMENT)
        );
        assert_eq!(validate(a, 2, &port, 0xa000_0001u32 as i32, 0), Ok(()));
        assert_eq!(validate(a, 2, &port, 5, 0), Err(kr::KERN_INVALID_ARGUMENT));
    }

    #[test]
    fn flavors_follow_the_kernels() {
        let arm: Vec<i32> = (0..60)
            .filter(|&f| valid_flavor(DarwinAbi::Arm64, f))
            .collect();
        assert_eq!(arm, [1, 2, 3, 4, 5, 6, 7, 9, 10, 14, 15, 16, 17, 25, 27]);
        let x86: Vec<i32> = (0..60)
            .filter(|&f| valid_flavor(DarwinAbi::X86_64, f))
            .collect();
        assert_eq!(
            x86,
            [
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25
            ]
        );
    }
}
