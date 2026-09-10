//! Stable status/error codes returned across the C ABI.
//!
//! Every fallible entry point returns a [`RaxStatus`]. The numeric values are
//! part of the stable ABI and must never be renumbered; new codes are only ever
//! appended. `RAX_OK` is guaranteed to be `0` so the common success check is a
//! plain `== 0` / truthiness test in C.

use std::os::raw::c_int;

/// Result code returned by `rax_*` functions. ABI-stable; values are frozen.
#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RaxStatus {
    /// Success.
    Ok = 0,
    /// Host memory allocation failed.
    NoMem = 1,
    /// An argument was invalid (e.g. a NULL pointer, zero length where one is
    /// required, or an out-of-domain enum value).
    Arg = 2,
    /// The engine handle was NULL or otherwise invalid.
    Handle = 3,
    /// The requested architecture is not supported by this build.
    Arch = 4,
    /// The requested backend is unavailable in this build/platform, or does not
    /// support the requested architecture.
    Backend = 5,
    /// The requested CPU mode flags are invalid for the architecture.
    Mode = 6,
    /// A memory-mapping error: overlap with an existing region, an access to an
    /// unmapped address, or a request that would leave the engine with no
    /// mapped memory.
    Map = 7,
    /// A guest access violated the permissions of the targeted region.
    Perm = 8,
    /// An address or length was out of the representable/allocatable range.
    Bounds = 9,
    /// The register id is not valid for the engine's architecture.
    Reg = 10,
    /// The operation is not valid in the engine's current state.
    State = 11,
    /// Execution hit an unrecoverable guest fault (e.g. a triple fault).
    Fault = 12,
    /// A host I/O error occurred (context save/load).
    Io = 13,
    /// Serialized data was malformed or version-incompatible.
    Format = 14,
    /// A hook could not be registered or the hook handle was invalid.
    Hook = 15,
    /// The feature is not supported by this build, backend, or architecture.
    Unsupported = 16,
    /// An internal invariant was violated (a recovered Rust panic). This should
    /// never occur in correct usage; please report it.
    Internal = 17,
}

impl RaxStatus {
    /// Raw integer code, for FFI returns.
    #[inline]
    pub fn code(self) -> c_int {
        self as c_int
    }

    /// A static, human-readable description.
    pub fn message(self) -> &'static str {
        match self {
            RaxStatus::Ok => "success",
            RaxStatus::NoMem => "out of memory",
            RaxStatus::Arg => "invalid argument",
            RaxStatus::Handle => "invalid engine handle",
            RaxStatus::Arch => "unsupported architecture",
            RaxStatus::Backend => "unavailable or incompatible backend",
            RaxStatus::Mode => "invalid CPU mode flags",
            RaxStatus::Map => "memory mapping error",
            RaxStatus::Perm => "memory permission violation",
            RaxStatus::Bounds => "address or length out of range",
            RaxStatus::Reg => "invalid register for architecture",
            RaxStatus::State => "operation invalid in current state",
            RaxStatus::Fault => "unrecoverable guest fault",
            RaxStatus::Io => "host I/O error",
            RaxStatus::Format => "malformed or incompatible serialized data",
            RaxStatus::Hook => "hook registration error",
            RaxStatus::Unsupported => "operation not supported",
            RaxStatus::Internal => "internal error",
        }
    }
}

/// Maps an engine [`rax_engine::Error`] to the closest ABI status code.
pub(crate) fn status_from_engine_error(e: &rax_engine::Error) -> RaxStatus {
    use rax_engine::Error as E;
    match e {
        E::Io(_) => RaxStatus::Io,
        E::InvalidConfig(_) => RaxStatus::Arg,
        E::Emulator(_)
        | E::GuestAccess(_)
        | E::InvalidInstruction { .. }
        | E::FaultDelivery { .. } => RaxStatus::Fault,
        E::PageFault { .. } => RaxStatus::Fault,
        E::GeneralProtection { .. } => RaxStatus::Fault,
        E::GuestMemory(_) => RaxStatus::Map,
        E::GuestMemoryCreate(_) => RaxStatus::Map,
        E::KernelLoad(_) => RaxStatus::Io,
        E::LinuxLoader(_) => RaxStatus::Io,
        E::LinuxBoot(_) => RaxStatus::Io,
        E::DeviceOverlap { .. } => RaxStatus::Map,
        E::MmioOverlap { .. } => RaxStatus::Map,
        E::DeviceNotFound { .. } => RaxStatus::Backend,
        // KVM is only present under cfg; treated as a backend error otherwise.
        #[allow(unreachable_patterns)]
        _ => RaxStatus::Backend,
    }
}
