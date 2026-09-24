//! Guest CPU adapters for user-mode execution.
//!
//! Each adapter binds one ISA core to an [`AddressSpace`] and runs it in its
//! unprivileged mode (x86-64 CPL 3, AArch64 EL0, RISC-V U-mode). A run ends
//! at the first event an operating system must handle — a system call, an
//! exception, a memory fault — or when the instruction budget of a time
//! slice is spent. Adapters are OS-neutral: they report *what the hardware
//! did*, and an OS personality decides what that means (a Linux signal, a
//! system call, ...).
//!
//! Every adapter keeps the core's code caches coherent with the address
//! space by applying [`AddressSpace::code_changes_since`] before it resumes
//! execution, clears LL/SC reservations whenever it leaves the guest (as an
//! exception return does on real hardware), and restores the unprivileged
//! execution state after any trap the core models architecturally.

pub mod aarch64;
pub mod riscv64;
pub mod x86_64;

#[cfg(test)]
mod tests;

use std::fmt;

use crate::error::{GuestMemoryFault, MemoryAccessKind, MemoryFaultKind};
use crate::user::mm::{AddressSpace, CodeChanges};

/// Guest instruction-set architectures supported by user-mode emulation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Isa {
    /// x86-64 (AMD64 / Intel 64) in 64-bit mode.
    X86_64,
    /// ARMv8-A and later in AArch64 state.
    Aarch64,
    /// 64-bit RISC-V (RV64GC plus the extensions the core implements).
    Riscv64,
}

impl Isa {
    /// Canonical short name (`uname -m` spelling on Linux).
    pub fn name(self) -> &'static str {
        match self {
            Isa::X86_64 => "x86_64",
            Isa::Aarch64 => "aarch64",
            Isa::Riscv64 => "riscv64",
        }
    }
}

impl fmt::Display for Isa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A data or instruction access that faulted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccessFault {
    /// First inaccessible byte.
    pub addr: u64,
    /// Access direction.
    pub access: MemoryAccessKind,
    /// Why the access failed.
    pub kind: AccessFaultKind,
    /// Address of the faulting instruction.
    pub pc: u64,
}

/// Why an access failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessFaultKind {
    /// No mapping covers the address.
    Unmapped,
    /// The mapping forbids the access.
    Permission,
    /// The access violated an architectural alignment requirement.
    Alignment,
    /// The backing store could not supply the page (for example a file
    /// mapping past end of file) or no frame was available.
    Bus,
}

impl AccessFault {
    /// Builds a fault from an address-space translation failure.
    pub fn from_memory(fault: GuestMemoryFault, pc: u64) -> Self {
        AccessFault {
            addr: fault.address,
            access: fault.access,
            kind: match fault.kind {
                MemoryFaultKind::Unmapped => AccessFaultKind::Unmapped,
                MemoryFaultKind::Permission => AccessFaultKind::Permission,
                MemoryFaultKind::Other => AccessFaultKind::Bus,
            },
            pc,
        }
    }
}

/// Takes the code changes a consumer at `epoch` has not applied yet and
/// advances `epoch`. Cheap (one atomic load) when nothing changed.
pub(crate) fn take_code_changes(space: &AddressSpace, epoch: &mut u64) -> CodeChanges {
    if space.code_epoch() == *epoch {
        return CodeChanges::None;
    }
    let (changes, now) = space.code_changes_since(*epoch);
    *epoch = now;
    changes
}

/// Monotonic nanoseconds since the emulator's clock epoch, used to drive
/// guest-visible counters (`CNTVCT_EL0`, RISC-V `time`).
pub(crate) fn host_nanos() -> u64 {
    crate::vm::timing::elapsed_nanos()
}
