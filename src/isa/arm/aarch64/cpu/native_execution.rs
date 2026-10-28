//! Portable continuation and policy, independent of compiled host code.

use crate::isa::arm::common::cpu::ArmError;

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct NativeExecution {
    /// Already-produced synchronous event, delivered before another attempt.
    pub native_fault: Option<ArmError>,
    /// Historical entries, retained when a context moves to an interpreter.
    pub pauth_native_runs: u64,
    /// Per-instance admission policy for native memory helper regions.
    pub mem: bool,
    /// Per-instance native tier switch; compiled code remains a derived cache.
    pub disabled: bool,
}
