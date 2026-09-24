#![allow(
    warnings,
    clippy::approx_constant,
    clippy::bad_bit_mask,
    clippy::eq_op,
    clippy::erasing_op,
    clippy::overly_complex_bool_expr
)]

pub mod backend;
pub mod config;
pub mod debug;
pub mod devices;
pub mod error;
pub mod host;
pub mod isa;
pub mod machine;
pub mod observability;
pub mod oracle;
pub mod smir;
pub mod user;
pub mod vm;

// Compatibility aliases for the pre-reorganization public module paths. New
// code should use `isa`, `machine`, `vm`, `debug`, `observability`, and `host`.
pub use host::{console, terminal};
pub use isa::{arm, riscv};
pub use machine as arch;
pub use oracle as isa_oracle;
pub use vm::runtime as vmm;
pub use vm::vcpu as cpu;
pub use vm::{memory, snapshot, timing};

#[cfg(feature = "debug")]
pub use debug::gdb;
#[cfg(feature = "profiling")]
pub use observability::profiling;
#[cfg(feature = "trace")]
pub use observability::trace;

pub use crate::error::{Error, Result};
