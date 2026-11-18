//! Portable SMIR: decoding, static verification, a typed IR and an interpreter.
//!
//! [`decode_object`] yields unverified syntax and [`verify_object`] a static
//! proof. [`ir::Module::load`] verifies an object and lowers it to the typed
//! form that [`interp::run`] executes. Only the scalar subset executes so far;
//! a module that needs anything else is refused before it runs.

#[path = "../../../src/smir/portable/mod.rs"]
mod frozen_format;

pub(crate) mod abi;
pub(crate) mod admission;
pub mod carrier;
pub(crate) mod context;
pub(crate) mod error;
pub(crate) mod execution;
pub mod interp;
pub mod ir;
pub(crate) mod limits;
pub(crate) mod metadata;
pub mod runtime;
pub(crate) mod wire;

pub use admission::{AdmissionRequirements, RequirementView, VerifiedObject, verify_object};
pub use error::{Error, ErrorClass};
pub use limits::Limits;
pub use wire::{ParsedObject, RecordValue, canonical_bytes, decode_object};

#[cfg(test)]
#[path = "../tests/abi/mod.rs"]
mod abi_tests;
#[cfg(test)]
#[path = "../tests/integration/core.rs"]
mod core_tests;
#[cfg(test)]
#[path = "../tests/execution/mod.rs"]
mod execution_tests;
#[cfg(test)]
#[path = "../tests/metadata/mod.rs"]
mod metadata_tests;
