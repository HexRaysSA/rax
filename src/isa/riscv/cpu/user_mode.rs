//! Accessors used by process-level (user-mode) embedders.
//!
//! A user-mode embedder runs the hart in U-mode and implements the
//! supervisor itself. These methods expose the few pieces of state that a
//! supervisor maintains and that have no CSR-level setter.

use super::*;

impl RiscVCpu {
    /// Sets the value read by the `time` CSR (`rdtime`), which a platform
    /// timer, not the hart, advances.
    pub fn set_time(&mut self, ticks: u64) {
        self.time = ticks;
    }

    /// The value read by the `time` CSR.
    pub fn time(&self) -> u64 {
        self.time
    }

    /// Invalidates any LR reservation, as a trap return or context switch
    /// does (Linux performs a dummy SC on every exception return for this).
    pub fn clear_reservation(&mut self) {
        self.reservation = None;
    }
}
