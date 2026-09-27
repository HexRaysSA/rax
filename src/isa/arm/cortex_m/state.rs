//! Architectural state transfer for embedders that drive a [`CortexMCpu`]
//! as a vCPU: the registers of [`CortexMRegisters`] and the modeled System
//! Control Block registers of [`CortexMSystemRegisters`].

use super::cpu::CortexMCpu;
use super::scb::shcsr;
use crate::vm::vcpu::{CortexMRegisters, CortexMSystemRegisters};

/// SHCSR active bits and the system handler each reports.
const SHCSR_ACTIVE: [(u32, u16); 6] = [
    (shcsr::MEMFAULTACT, 4),
    (shcsr::BUSFAULTACT, 5),
    (shcsr::USGFAULTACT, 6),
    (shcsr::SVCALLACT, 11),
    (shcsr::MONITORACT, 12),
    (shcsr::PENDSVACT, 14),
];

impl CortexMCpu {
    /// The core registers: R0-R12, both stack pointers, LR, PC, xPSR, and
    /// the special registers. The FP registers read as zero (the
    /// Floating-point Extension is not implemented).
    pub fn export_regs(&self) -> CortexMRegisters {
        CortexMRegisters {
            r: self.regs,
            msp: self.sp_main,
            psp: self.sp_process,
            lr: self.lr,
            pc: self.pc,
            xpsr: self.xpsr,
            control: u32::from(self.control),
            primask: u32::from(self.primask),
            faultmask: u32::from(self.faultmask),
            basepri: u32::from(self.basepri),
            ..CortexMRegisters::default()
        }
    }

    /// Installs `regs`. The mode follows xPSR's exception number (Thread
    /// mode when it is zero), and that exception becomes active; PC bit 0 is
    /// ignored. Bits [1:0] of the stack pointers read as zero.
    pub fn import_regs(&mut self, regs: &CortexMRegisters) {
        self.regs = regs.r;
        self.sp_main = regs.msp & !3;
        self.sp_process = regs.psp & !3;
        self.lr = regs.lr;
        self.pc = regs.pc & !1;
        self.xpsr = regs.xpsr;
        // Without the Floating-point Extension CONTROL.FPCA is RAZ/WI.
        self.control = (regs.control & 3) as u8;
        self.primask = regs.primask & 1 != 0;
        self.faultmask = regs.faultmask & 1 != 0;
        self.basepri = regs.basepri as u8;
        let exception = (regs.xpsr & 0x1FF) as u16;
        self.thread_mode = exception == 0;
        self.current_exception = exception;
        if exception != 0 {
            self.set_active(exception, true);
        }
    }

    /// The modeled System Control Block registers: VTOR, AIRCR, CCR, SHPR,
    /// SHCSR (enables, and the active bits of the system handlers), CFSR,
    /// HFSR, MMFAR, and BFAR.
    pub fn export_sregs(&self) -> CortexMSystemRegisters {
        let scb = self.scb();
        let mut shcsr = scb.read(0x24, 0, None);
        for (bit, exception) in SHCSR_ACTIVE {
            if self.is_active(exception) {
                shcsr |= bit;
            }
        }
        let nvic = self.nvic();
        CortexMSystemRegisters {
            vtor: scb.vtor(),
            aircr: 0xFA05_0000 | (u32::from(scb.priority_group()) << 8),
            ccr: scb.read(0x14, 0, None),
            shpr: [nvic.read_shpr(0), nvic.read_shpr(1), nvic.read_shpr(2)],
            shcsr,
            cfsr: scb.get_cfsr(),
            hfsr: scb.read(0x2C, 0, None),
            mmfar: scb.read(0x34, 0, None),
            bfar: scb.read(0x38, 0, None),
            ..CortexMSystemRegisters::default()
        }
    }

    /// Installs the modeled System Control Block registers. The SHCSR
    /// active bits set the system handlers' active state; other active
    /// exceptions are unchanged.
    pub fn import_sregs(&mut self, sregs: &CortexMSystemRegisters) {
        {
            let scb = self.scb_mut();
            scb.set_vtor(sregs.vtor);
            scb.write(0x0C, 0x05FA_0000 | (sregs.aircr & 0x700));
            scb.write(0x14, sregs.ccr);
            scb.write(0x24, sregs.shcsr);
            scb.set_status(sregs.cfsr, sregs.hfsr);
            scb.write(0x34, sregs.mmfar);
            scb.write(0x38, sregs.bfar);
        }
        let nvic = self.nvic_mut();
        for (i, shpr) in sregs.shpr.iter().enumerate() {
            nvic.write_shpr(i, *shpr);
        }
        for (bit, exception) in SHCSR_ACTIVE {
            self.set_active(exception, sregs.shcsr & bit != 0);
        }
        let current = self.current_exception;
        if current != 0 {
            self.set_active(current, true);
        }
    }

    /// Instructions executed.
    pub fn instruction_count(&self) -> u64 {
        self.insn_count
    }

    /// Whether a `WFI`/`WFE` put the processor to sleep.
    pub fn is_sleeping(&self) -> bool {
        self.sleeping
    }

    /// Leaves a `WFI`/`WFE` sleep or a halt so the next step executes.
    pub fn wake(&mut self) {
        self.sleeping = false;
        self.halted = false;
    }
}
