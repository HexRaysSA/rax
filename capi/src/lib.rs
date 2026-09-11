//! # rax — stable C/C++ API for the RAX emulation engine
//!
//! This crate is the embeddable face of [`rax_engine`]: it exposes a complete,
//! ABI-stable C interface (and, via `include/rax.hpp`, an idiomatic C++ wrapper)
//! for driving the RAX CPU emulator from any C or C++ program. The produced
//! native library is `librax` (`librax.a` / `librax.so` / `librax.dylib`); link
//! with `-lrax`.
//!
//! The design centre is *arbitrary emulation*: open an engine for an
//! architecture, map guest memory at arbitrary addresses, load code and data,
//! read and write the full register file, then run, single-step, or step a
//! bounded number of instructions with complete control over stop conditions
//! and a rich set of execution hooks. See `include/rax.h` for the canonical,
//! fully documented interface.
//!
//! ## ABI and safety contract
//!
//! * Every entry point validates its arguments and returns a [`RaxStatus`];
//!   NULL handles and out-of-range arguments are reported, never dereferenced.
//! * Every entry point is wrapped in a panic guard so a Rust panic can never
//!   unwind across the FFI boundary; it is converted to [`RaxStatus::Internal`].
//! * An `rax_engine` handle is *not* thread-safe: a single handle must be used
//!   from one thread at a time. Distinct handles are fully independent and may
//!   be driven from different threads concurrently.
//! * The library never takes ownership of caller buffers; it copies in/out.

#![allow(clippy::missing_safety_doc)]

// Every exported entry point promises to contain Rust panics. Refuse a build
// configuration that would silently turn catch_unwind into process aborts and
// make that ABI contract false.
#[cfg(panic = "abort")]
compile_error!("rax-capi requires panic=unwind to preserve its C ABI panic-containment contract");

use std::os::raw::{c_char, c_int};
use std::panic::{AssertUnwindSafe, catch_unwind};

mod analyze;
mod arch;
mod context;
mod decode;
mod engine;
mod fault;
mod hook;
mod instruction_info;
mod mem;
mod reg;
mod run;
mod status;

#[cfg(test)]
mod tests;

pub use fault::*;
pub use instruction_info::*;
pub use status::RaxStatus;

// Re-export the FFI surface and ABI constants from each module so they form a
// tidy Rust API for rlib consumers in addition to the C ABI. (The
// `#[unsafe(no_mangle)]` symbols are exported regardless.)
pub use analyze::{
    RAX_ADDRESS_ABSOLUTE, RAX_ADDRESS_BASE_DISP, RAX_ADDRESS_BASE_INDEX_DISP,
    RAX_ADDRESS_GP_RELATIVE, RAX_ADDRESS_NONE, RAX_ADDRESS_PC_RELATIVE, RAX_ADDRESS_REGISTER,
    RAX_ADDRESS_SEGMENT_RELATIVE, RAX_ADDRESS_UNKNOWN, RAX_ANALYSIS_ABI_VERSION,
    RAX_ANALYSIS_COMPLETE, RAX_ANALYSIS_HAS_SMIR, RAX_ANALYSIS_PARTIAL, RAX_ANALYSIS_TRUNCATED,
    RAX_ANALYSIS_UNSUPPORTED, RAX_ANALYSIS_VALID, RAX_EFFECT_ADDRESS_COMPLETE, RAX_EFFECT_ATOMIC,
    RAX_EFFECT_CONDITIONAL, RAX_EFFECT_IMPLICIT, RAX_EFFECT_MEMORY, RAX_EFFECT_ORDERED,
    RAX_EFFECT_READ, RAX_EFFECT_REGISTER, RAX_EFFECT_REPEATED, RAX_EFFECT_VALUE_COMPLETE,
    RAX_EFFECT_WRITE, RAX_FLAG_A, RAX_FLAG_ARITHMETIC, RAX_FLAG_C, RAX_FLAG_D, RAX_FLAG_N,
    RAX_FLAG_NZCV, RAX_FLAG_P, RAX_FLAG_V, RAX_FLAG_Z, RAX_VALUE_CONSTANT, RAX_VALUE_REGISTER,
    RAX_VALUE_UNKNOWN, RaxAnalysis, RaxAnalysisEffect, rax_analyze,
};
pub use arch::{
    RAX_BACKEND_DEFAULT, RAX_BACKEND_EMULATOR, RAX_MODE_16, RAX_MODE_32, RAX_MODE_64, RAX_MODE_ARM,
    RAX_MODE_BIG_ENDIAN, RAX_MODE_LITTLE_ENDIAN, RAX_MODE_THUMB, RAX_RISCV_EXT_SUPPORTED,
    RAX_RISCV_EXT_XANDES, RAX_RISCV_EXT_XHAZARD3, RAX_RISCV_EXT_XIDA_SLTW, RAX_RISCV_EXT_XTHEAD,
    RAX_RISCV_EXT_ZCLSD, RAX_RISCV_EXT_ZCMP, RAX_RISCV_EXT_ZCMT, RAX_RISCV_EXT_ZILSD, RaxArch,
};
pub use decode::{
    RAX_FLOW_BRANCH, RAX_FLOW_CALL, RAX_FLOW_COND_BRANCH, RAX_FLOW_FALLTHROUGH,
    RAX_FLOW_INDIRECT_CALL, RAX_FLOW_INDIRECT_JUMP, RAX_FLOW_RETURN, RAX_FLOW_SYSCALL,
    RAX_FLOW_TRAP, RAX_FLOW_UNKNOWN, RaxDecoded,
};
pub use engine::{DEFAULT_MEM_SIZE, Engine, RAX_OPEN_NO_DEFAULT_STATE, RaxEngineConfig};
pub use hook::{
    RAX_HOOK_BLOCK, RAX_HOOK_CODE, RAX_HOOK_INTR, RAX_HOOK_INVALID, RAX_HOOK_IO_IN,
    RAX_HOOK_IO_OUT, RAX_HOOK_MEM_FETCH, RAX_HOOK_MEM_READ, RAX_HOOK_MEM_WRITE, RAX_HOOK_MMIO_READ,
    RAX_HOOK_MMIO_WRITE, RAX_MEM_FETCH, RAX_MEM_READ, RAX_MEM_WRITE,
};
pub use mem::{
    RAX_PROT_ALL, RAX_PROT_EXEC, RAX_PROT_NONE, RAX_PROT_READ, RAX_PROT_WRITE, RaxMemRegion,
};
pub use run::{
    ExitInfo, RAX_NO_ADDR, RAX_STOP_COUNT, RAX_STOP_DEBUG, RAX_STOP_ERROR, RAX_STOP_EXCEPTION,
    RAX_STOP_HLT, RAX_STOP_INTERRUPT, RAX_STOP_IO_IN, RAX_STOP_IO_OUT, RAX_STOP_MMIO_READ,
    RAX_STOP_MMIO_WRITE, RAX_STOP_NONE, RAX_STOP_SHUTDOWN, RAX_STOP_TIMEOUT, RAX_STOP_UNTIL,
};

/// ABI major version. Incremented only on a breaking ABI change.
pub const RAX_API_MAJOR: u32 = 1;
/// ABI minor version. Incremented when backward-compatible additions are made.
pub const RAX_API_MINOR: u32 = 5;
/// ABI patch version.
pub const RAX_API_PATCH: u32 = 0;

/// Runs `f` under a panic guard, returning [`RaxStatus::Internal`] if it panics.
///
/// All public entry points funnel through this so a panic in engine code (which
/// would otherwise be undefined behaviour across an `extern "C"` boundary) is
/// contained and surfaced as a status code. The workspace release profile keeps
/// unwinding enabled specifically to preserve this contract in optimized dylibs.
#[inline]
pub(crate) fn guard<F>(f: F) -> RaxStatus
where
    F: FnOnce() -> RaxStatus,
{
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(s) => s,
        Err(_) => RaxStatus::Internal,
    }
}

/// As [`guard`], but for entry points that compute a value; on panic returns
/// `on_panic`.
#[inline]
pub(crate) fn guard_val<T, F>(on_panic: T, f: F) -> T
where
    F: FnOnce() -> T,
{
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(v) => v,
        Err(_) => on_panic,
    }
}

// ===========================================================================
// Library-global entry points
// ===========================================================================

/// Returns the packed library version `(major << 16) | (minor << 8) | patch`.
///
/// If `major`/`minor`/`patch` are non-NULL they receive the components.
#[unsafe(no_mangle)]
pub extern "C" fn rax_version(major: *mut u32, minor: *mut u32, patch: *mut u32) -> u32 {
    guard_val(0, || {
        unsafe {
            if !major.is_null() {
                *major = RAX_API_MAJOR;
            }
            if !minor.is_null() {
                *minor = RAX_API_MINOR;
            }
            if !patch.is_null() {
                *patch = RAX_API_PATCH;
            }
        }
        (RAX_API_MAJOR << 16) | (RAX_API_MINOR << 8) | RAX_API_PATCH
    })
}

/// Returns a static, NUL-terminated human-readable version string.
#[unsafe(no_mangle)]
pub extern "C" fn rax_version_string() -> *const c_char {
    // Static NUL-terminated string with embedded version.
    concat!(env!("CARGO_PKG_VERSION"), " (rax-capi ABI ", "1.5.0", ")\0").as_ptr() as *const c_char
}

/// Returns a static, NUL-terminated description for a [`RaxStatus`] code.
///
/// Unknown codes yield a generic "unknown status" string (never NULL).
#[unsafe(no_mangle)]
pub extern "C" fn rax_strerror(status: c_int) -> *const c_char {
    let s = match status {
        0 => "success\0",
        1 => "out of memory\0",
        2 => "invalid argument\0",
        3 => "invalid engine handle\0",
        4 => "unsupported architecture\0",
        5 => "unavailable or incompatible backend\0",
        6 => "invalid CPU mode flags\0",
        7 => "memory mapping error\0",
        8 => "memory permission violation\0",
        9 => "address or length out of range\0",
        10 => "invalid register for architecture\0",
        11 => "operation invalid in current state\0",
        12 => "unrecoverable guest fault\0",
        13 => "host I/O error\0",
        14 => "malformed or incompatible serialized data\0",
        15 => "hook registration error\0",
        16 => "operation not supported\0",
        17 => "internal error\0",
        _ => "unknown status\0",
    };
    s.as_ptr() as *const c_char
}
