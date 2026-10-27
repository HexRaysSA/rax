//! Host-supplied hardware-thread identity; guest CSR writes remain read-only.
use super::{Memory, RiscVConfig, RiscVCpu};
impl RiscVCpu {
    /// Create a hart with an explicit MXLEN-bit hardware-thread ID.
    /// The embedding execution environment owns uniqueness and a hart zero.
    /// `new` retains its existing hart-zero behavior. Warm reset preserves ID.
    pub fn new_with_hart_id(cfg: RiscVConfig, mem: Box<dyn Memory>, hart_id: u64) -> Self {
        let mut cpu = Self::new(cfg, mem);
        cpu.mhartid = hart_id & cpu.xmask();
        cpu
    }
}
