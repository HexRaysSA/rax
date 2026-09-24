//! Accessors used by process-level (user-mode) embedders.
//!
//! A user-mode embedder executes EL0 code through [`ArmCpu::step`], which
//! returns `SVC`, `BRK`, and synchronous faults to the caller instead of
//! vectoring them to EL1, and implements the operating system itself. These
//! methods expose the EL0 thread state such an embedder maintains.

use super::*;

impl AArch64Cpu {
    /// Enters EL0 using `SP_EL0` (`EL0t`) with every PSTATE field in its
    /// Linux `execve` state: NZCV, DAIF, BTYPE, and the single-step,
    /// illegal-state, PAN, UAO, DIT, SSBS, and TCO bits clear.
    pub fn enter_el0(&mut self) {
        self.current_el = 0;
        self.sp_sel = false;
        self.nzcv = 0;
        self.daif = 0;
        self.btype = 0;
        self.ss = false;
        self.il = false;
        self.pan = false;
        self.uao = false;
        self.dit = false;
        self.ssbs = false;
        self.tco = false;
        self.halted = false;
        self.wfi = false;
        self.wfe = false;
        self.event_register = false;
        self.pending_exceptions.clear();
        self.update_mmu_config();
    }

    /// `TPIDR_EL0`, the EL0 read/write thread pointer.
    pub fn tpidr_el0(&self) -> u64 {
        self.sysregs.tpidr_el0
    }

    /// Sets `TPIDR_EL0`.
    pub fn set_tpidr_el0(&mut self, value: u64) {
        self.sysregs.tpidr_el0 = value;
    }

    /// `TPIDRRO_EL0`, the EL0 read-only thread pointer.
    pub fn tpidrro_el0(&self) -> u64 {
        self.sysregs.tpidrro_el0
    }

    /// Sets `TPIDRRO_EL0` (writable only above EL0 architecturally).
    pub fn set_tpidrro_el0(&mut self, value: u64) {
        self.sysregs.tpidrro_el0 = value;
    }

    /// Sets the generic-timer physical count; the virtual count follows with
    /// the current `CNTVOFF_EL2`. The system counter, not the PE, advances
    /// this value.
    pub fn set_generic_counter(&mut self, ticks: u64) {
        self.sysregs.cntpct_el0 = ticks;
        self.sysregs.cntvct_el0 = ticks.wrapping_sub(self.sysregs.cntvoff_el2);
    }

    /// `CNTFRQ_EL0`, the advertised system-counter frequency in hertz.
    pub fn counter_frequency(&self) -> u64 {
        self.sysregs.cntfrq_el0
    }

    /// Clears a pending `WFI`/`WFE` wait so the next step executes an
    /// instruction. Returns whether a wait was pending.
    pub fn clear_wait(&mut self) -> bool {
        let waiting = self.wfi || self.wfe;
        self.wfi = false;
        self.wfe = false;
        self.event_register = false;
        waiting
    }

    /// Clears the halted state entered by `HLT`.
    pub fn clear_halt(&mut self) {
        self.halted = false;
    }

    /// Clears the local exclusive monitor, as exception entry and return do.
    pub fn clear_exclusive_monitor(&mut self) {
        self.memory.clear_exclusive();
    }

    /// NZCV as the four-bit field of PSTATE (N in bit 3).
    pub fn nzcv_bits(&self) -> u8 {
        self.nzcv & 0xF
    }

    /// Sets NZCV from a four-bit field (N in bit 3).
    pub fn set_nzcv_bits(&mut self, bits: u8) {
        self.nzcv = bits & 0xF;
    }
}
