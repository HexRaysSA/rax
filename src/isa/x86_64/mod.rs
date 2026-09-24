//! x86_64 CPU emulator implementation.

pub(crate) mod apx;
pub mod bios;
mod cpu;
mod cpu_fetch;
mod decode;
mod exception;
pub(crate) mod execute;
pub mod flags;
pub(crate) mod memory;
#[cfg(test)]
mod memory_tests;
mod simd_native;
mod threaded;
mod user_mode;
#[cfg(test)]
mod user_mode_tests;
mod user_xstate;

pub use cpu::{CURRENT_RIP, RIP_HISTORY, RIP_IDX, X86_64Vcpu, get_total_instruction_count};
pub use memory::{AccessType, Mmu};
pub use user_mode::{
    LINUX_USER_CS, LINUX_USER_DS, LINUX_USER32_CS, X86EventSource, X86SyscallInsn, X86UserEvent,
    X86UserTrap,
};
pub use user_xstate::{
    XSAVE_EXTENDED_OFFSET, XSAVE_HEADER_OFFSET, XSAVE_LEGACY_SIZE, XrstorError, XsaveImage,
};

/// Implemented MXCSR bits for the fixed x86-64 CPU profile. Bits 16..31 are
/// reserved and loading any of them as one raises #GP(0).
pub(crate) const MXCSR_SUPPORTED_MASK: u32 = 0x0000_FFFF;

#[inline]
pub(crate) const fn mxcsr_value_is_valid(value: u32) -> bool {
    value & !MXCSR_SUPPORTED_MASK == 0
}

// Compatibility path for callers that previously reached VM-wide timing
// through the x86-64 ISA namespace. Internal code uses `crate::vm::timing`.
#[doc(hidden)]
pub use crate::vm::timing;

// Compatibility alias for the former file/module name.
pub(crate) use memory as mmu;
