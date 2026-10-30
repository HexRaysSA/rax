//! Host debugger controls, separate from guest architectural debug registers.

/// The current host session's CPU overlay, retained when a VM imports guest state.
/// Raw CPU-context import remains a distinct operation that preserves its payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DebuggerControls {
    pub active: bool,
    pub single_step: bool,
    /// Internal execute breakpoint addresses, in increasing order.
    pub breakpoints: Vec<u64>,
}
