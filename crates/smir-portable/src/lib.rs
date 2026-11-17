//! Portable SMIR static verification. Decoded objects convey no execution authority.
//!
//! This subsystem is being integrated through explicit production gates. Its
//! independent reference snapshots are versioned separately. Earlier receipts
//! remain historical during a schema migration.

#[path = "../../../src/smir/portable/mod.rs"]
mod frozen_format;

pub(crate) mod abi;
pub(crate) mod admission;
pub(crate) mod context;
pub(crate) mod error;
pub(crate) mod execution;
pub(crate) mod limits;
pub(crate) mod metadata;
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
