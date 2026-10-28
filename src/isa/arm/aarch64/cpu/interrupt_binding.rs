//! Target-owned per-PE binding to a VM-owned interrupt controller.
use super::super::gic::Gic;
use super::AArch64Cpu;
use std::sync::{Arc, Mutex, atomic::AtomicBool};

impl AArch64Cpu {
    pub(crate) fn bind_platform_gic(
        &mut self,
        gic: Arc<Mutex<Gic>>,
        cpu_id: usize,
        line: Arc<AtomicBool>,
    ) {
        self.gic = Some(gic);
        self.gic_cpu_id = cpu_id;
        self.gic_shared = true;
        self.gic_irq_line = Some(line);
        self.timer_levels = (false, false);
    }
}
