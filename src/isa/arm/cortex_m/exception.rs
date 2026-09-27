//! The Armv7-M exception model (Armv7-M ARM, DDI 0403E.e, B1.5): execution
//! priority, exception entry with priority escalation to HardFault, and
//! exception return. The Floating-point Extension is not implemented, so
//! every frame is the 32-byte basic frame.

use super::cpu::CortexMCpu;
use super::exec::{Fault, XPSR_T};
use super::scb::{cfsr, hfsr};
use crate::isa::arm::common::cpu::AccessType;

/// Exception numbers (B1.5.2).
pub mod number {
    pub const NMI: u16 = 2;
    pub const HARD_FAULT: u16 = 3;
    pub const MEM_MANAGE: u16 = 4;
    pub const BUS_FAULT: u16 = 5;
    pub const USAGE_FAULT: u16 = 6;
    pub const SV_CALL: u16 = 11;
    pub const DEBUG_MONITOR: u16 = 12;
    pub const PEND_SV: u16 = 14;
    pub const SYS_TICK: u16 = 15;
}

/// Why an exception could not be taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryError {
    /// A stack push or pop, or the vector read, failed with a bus error.
    Bus { address: u32, access: AccessType },
    /// The exception would escalate to HardFault while the execution
    /// priority is already HardFault or higher: the processor locks up
    /// (B1.5.15, "Unrecoverable exception cases").
    Lockup { exception: u16 },
}

impl From<Fault> for EntryError {
    fn from(fault: Fault) -> Self {
        match fault {
            Fault::Bus { address, access } => EntryError::Bus { address, access },
            Fault::Unaligned { address } => EntryError::Bus {
                address,
                access: AccessType::Write,
            },
            // Stacking only performs aligned word accesses.
            _ => EntryError::Lockup { exception: 0 },
        }
    }
}

/// Bits [27:4] of an EXC_RETURN value are all ones without the
/// Floating-point Extension.
const EXC_RETURN_ONES: u32 = 0x0FFF_FFF0;

impl CortexMCpu {
    pub(super) fn is_active(&self, exception: u16) -> bool {
        exception != 0 && self.active[usize::from(exception / 64)] & (1 << (exception % 64)) != 0
    }

    pub(super) fn set_active(&mut self, exception: u16, active: bool) {
        let bit = 1u64 << (exception % 64);
        let word = &mut self.active[usize::from(exception / 64)];
        if active {
            *word |= bit;
        } else {
            *word &= !bit;
        }
    }

    fn active_count(&self) -> u32 {
        self.active.iter().map(|w| w.count_ones()).sum()
    }

    /// The configured priority of `exception` (Reset -3, NMI -2,
    /// HardFault -1).
    fn exception_priority(&self, exception: u16) -> i32 {
        i32::from(self.nvic().get_exception_priority(exception))
    }

    /// The group priority of `priority` under AIRCR.PRIGROUP; the fixed
    /// negative priorities are not grouped.
    fn group_priority(&self, priority: i32) -> i32 {
        if priority < 0 {
            return priority;
        }
        let group = 2i32 << self.scb().priority_group();
        priority - priority % group
    }

    /// `ExecutionPriority()` (B1.5.4).
    pub(super) fn execution_priority(&self) -> i32 {
        let mut highest = 256;
        for exception in 2..512u16 {
            if self.is_active(exception) {
                highest = highest.min(self.group_priority(self.exception_priority(exception)));
            }
        }
        let mut boosted = 256;
        if self.basepri != 0 {
            boosted = self.group_priority(i32::from(self.basepri));
        }
        if self.primask {
            boosted = 0;
        }
        if self.faultmask {
            boosted = -1;
        }
        highest.min(boosted)
    }

    /// Whether `exception` is enabled (the configurable faults follow
    /// SHCSR; DebugMonitor needs DEMCR.MON_EN, which is not modeled).
    fn exception_enabled(&self, exception: u16) -> bool {
        match exception {
            number::MEM_MANAGE => self.scb().is_memmanage_enabled(),
            number::BUS_FAULT => self.scb().is_busfault_enabled(),
            number::USAGE_FAULT => self.scb().is_usagefault_enabled(),
            number::DEBUG_MONITOR => false,
            _ => true,
        }
    }

    /// The exception a synchronous `exception` is taken as: itself, or
    /// HardFault when it is disabled or cannot preempt ("Priority
    /// escalation", B1.5.4). Records the escalation in HFSR.
    fn escalate(&mut self, exception: u16) -> Result<u16, EntryError> {
        let current = self.execution_priority();
        let priority = self.group_priority(self.exception_priority(exception));
        if exception != number::HARD_FAULT
            && self.exception_enabled(exception)
            && priority < current
        {
            return Ok(exception);
        }
        if current <= -1 {
            return Err(EntryError::Lockup { exception });
        }
        let status = if exception == number::DEBUG_MONITOR {
            hfsr::DEBUGEVT
        } else if exception == number::HARD_FAULT {
            0
        } else {
            hfsr::FORCED
        };
        self.scb_mut().set_hardfault(status);
        Ok(number::HARD_FAULT)
    }

    /// Takes synchronous exception `exception` (SVCall, a fault, or the
    /// DebugMonitor exception of a BKPT) with `return_address` stacked,
    /// escalating to HardFault as the architecture requires. Returns the
    /// exception taken.
    pub fn take_synchronous(
        &mut self,
        exception: u16,
        return_address: u32,
    ) -> Result<u16, EntryError> {
        let saved = self.snapshot();
        let result = self.escalate(exception).and_then(|taken| {
            self.push_stack(return_address)?;
            self.exception_taken(taken)?;
            Ok(taken)
        });
        if result.is_err() {
            self.restore(saved);
        }
        result
    }

    /// Takes asynchronous `exception` (NMI, PendSV, SysTick, an interrupt)
    /// that can preempt, returning to `return_address`.
    pub(super) fn enter_asynchronous(
        &mut self,
        exception: u16,
        return_address: u32,
    ) -> Result<(), EntryError> {
        let saved = self.snapshot();
        let result = self
            .push_stack(return_address)
            .and_then(|()| self.exception_taken(exception));
        if result.is_err() {
            self.restore(saved);
        }
        result
    }

    /// Takes `fault` architecturally: records it in CFSR (and BFAR) and
    /// takes the UsageFault or BusFault at the faulting instruction, which
    /// PC still addresses.
    pub fn take_fault(&mut self, fault: Fault) -> Result<u16, EntryError> {
        let (exception, status) = match fault {
            Fault::Undefined(_) => (number::USAGE_FAULT, cfsr::UNDEFINSTR),
            Fault::NoCoprocessor(_) => (number::USAGE_FAULT, cfsr::NOCP),
            Fault::InvalidState => (number::USAGE_FAULT, cfsr::INVSTATE),
            Fault::Unaligned { .. } => (number::USAGE_FAULT, cfsr::UNALIGNED),
            Fault::DivideByZero => (number::USAGE_FAULT, cfsr::DIVBYZERO),
            Fault::Bus {
                access: AccessType::InstructionFetch,
                ..
            } => (number::BUS_FAULT, cfsr::IBUSERR),
            Fault::Bus { address, .. } => {
                self.scb_mut().write(0x38, address);
                (number::BUS_FAULT, cfsr::PRECISERR | cfsr::BFARVALID)
            }
            Fault::Lockup => return Err(EntryError::Lockup { exception: 0 }),
        };
        self.scb_mut().set_cfsr_bits(status);
        self.take_synchronous(exception, self.pc)
    }

    /// `PushStack()` without the Floating-point Extension (B1.5.6).
    fn push_stack(&mut self, return_address: u32) -> Result<(), EntryError> {
        let force_align = self.scb().stack_align();
        let use_psp = self.control & 2 != 0 && self.thread_mode;
        let sp = if use_psp {
            self.sp_process
        } else {
            self.sp_main
        };
        let realigned = force_align && sp & 4 != 0;
        let frame = sp.wrapping_sub(0x20) & !(u32::from(force_align) << 2);
        let xpsr = (self.xpsr & !(1 << 9)) | (u32::from(realigned) << 9);
        let words = [
            self.regs[0],
            self.regs[1],
            self.regs[2],
            self.regs[3],
            self.regs[12],
            self.lr,
            return_address & !1,
            xpsr,
        ];
        for (i, word) in words.iter().enumerate() {
            self.set_mem_a(frame.wrapping_add(4 * i as u32), 4, *word)?;
        }
        if use_psp {
            self.sp_process = frame;
        } else {
            self.sp_main = frame;
        }
        self.lr = if self.thread_mode {
            0xFFFF_FFF9 | (u32::from(self.control & 2) << 1)
        } else {
            0xFFFF_FFF1
        };
        Ok(())
    }

    /// `ExceptionTaken()` (B1.5.6).
    fn exception_taken(&mut self, exception: u16) -> Result<(), EntryError> {
        let table = self.scb().vtor() & !0x7F;
        let vector = self.mem_a(table.wrapping_add(4 * u32::from(exception)), 4)?;
        self.pc = vector & !1;
        self.thread_mode = false;
        self.current_exception = exception;
        // IPSR = exception, EPSR.T from the vector, IT/ICI cleared.
        self.xpsr = (self.xpsr & 0xF80F_0000) | u32::from(exception) | ((vector & 1) << 24);
        // CONTROL.SPSEL (and FPCA) clear; nPRIV unchanged.
        self.control &= 1;
        self.set_active(exception, true);
        self.memory.clear_exclusive();
        self.event_register = true;
        self.sleeping = false;
        Ok(())
    }

    /// `ExceptionReturn()` (B1.5.8), from a BXWritePC of `exc_return` in
    /// Handler mode.
    pub(super) fn exception_return(&mut self, exc_return: u32) -> Result<(), Fault> {
        let returning = self.current_exception;
        let nested = self.active_count();
        let target = if exc_return & EXC_RETURN_ONES != EXC_RETURN_ONES
            || !self.is_active(returning)
        {
            None
        } else {
            match exc_return & 0xF {
                0b0001 => Some((false, false)),
                0b1001 | 0b1101 if nested != 1 && self.scb().read(0x14, 0, None) & 1 == 0 => None,
                0b1001 => Some((true, false)),
                0b1101 => Some((true, true)),
                _ => None,
            }
        };
        let Some((to_thread, use_psp)) = target else {
            // Illegal EXC_RETURN or an inactive handler: INVPC, taken
            // without stacking a new frame.
            self.deactivate(returning);
            return self.invpc(exc_return, None);
        };
        self.deactivate(returning);
        self.thread_mode = to_thread;
        self.control = (self.control & !2) | (u8::from(use_psp) << 1);
        let return_address = self.pop_stack(use_psp)?;
        let ipsr = self.xpsr & 0x1FF;
        if to_thread != (ipsr == 0) {
            // The stacked IPSR contradicts the return mode: stack the frame
            // again and take INVPC.
            return self.invpc(exc_return, Some(return_address));
        }
        self.memory.clear_exclusive();
        self.event_register = true;
        Ok(())
    }

    /// `DeActivate()`: every return except from NMI clears FAULTMASK.
    fn deactivate(&mut self, exception: u16) {
        self.set_active(exception, false);
        if exception != number::NMI {
            self.faultmask = false;
        }
    }

    /// Takes the INVPC UsageFault of a failed exception return; `restack`
    /// holds the return address when the popped frame must be pushed back.
    fn invpc(&mut self, exc_return: u32, restack: Option<u32>) -> Result<(), Fault> {
        self.scb_mut().set_cfsr_bits(cfsr::INVPC);
        let taken = match self.escalate(number::USAGE_FAULT) {
            Ok(taken) => taken,
            Err(_) => return Err(Fault::Lockup),
        };
        if let Some(return_address) = restack {
            self.push_stack(return_address).map_err(entry_fault)?;
        }
        self.lr = 0xF000_0000 | exc_return;
        self.exception_taken(taken).map_err(entry_fault)
    }

    /// `PopStack()` without the Floating-point Extension (B1.5.8); returns
    /// the stacked return address.
    fn pop_stack(&mut self, use_psp: bool) -> Result<u32, Fault> {
        let force_align = self.scb().stack_align();
        let frame = if use_psp {
            self.sp_process
        } else {
            self.sp_main
        };
        let mut words = [0u32; 8];
        for (i, word) in words.iter_mut().enumerate() {
            *word = self.mem_a(frame.wrapping_add(4 * i as u32), 4)?;
        }
        let psr = words[7];
        self.regs[0] = words[0];
        self.regs[1] = words[1];
        self.regs[2] = words[2];
        self.regs[3] = words[3];
        self.regs[12] = words[4];
        self.lr = words[5];
        self.pc = words[6] & !1;
        let realign = u32::from(psr & (1 << 9) != 0 && force_align) << 2;
        let sp = frame.wrapping_add(0x20) | realign;
        if use_psp {
            self.sp_process = sp;
        } else {
            self.sp_main = sp;
        }
        let mut keep = 0xF800_0000 | 0x1FF | 0x0700_0000 | 0xFC00;
        if self.has_dsp() {
            keep |= 0x000F_0000;
        }
        self.xpsr = psr & keep;
        self.current_exception = (psr & 0x1FF) as u16;
        Ok(words[6])
    }

    /// Whether the current mode is privileged (Handler mode, or Thread mode
    /// with CONTROL.nPRIV clear).
    pub(super) fn privileged(&self) -> bool {
        !self.thread_mode || self.control & 1 == 0
    }

    /// Whether EPSR.T is set.
    pub fn thumb_state(&self) -> bool {
        self.xpsr & XPSR_T != 0
    }
}

fn entry_fault(error: EntryError) -> Fault {
    match error {
        EntryError::Bus { address, access } => Fault::Bus { address, access },
        EntryError::Lockup { .. } => Fault::Lockup,
    }
}
