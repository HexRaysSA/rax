//! AArch32_EnterMode / AArch32_EnterHypMode, Arm XML 2025-12. AArch64
//! handlers continue to use the enclosing PE's ordinary vector-entry path.

use crate::isa::arm::aarch64::aarch32_state::{Aarch32Pstate, register_index};
use crate::isa::arm::aarch64::cpu::AArch64Cpu;
use crate::isa::arm::aarch64::exceptions::{ExceptionType, SyndromeRegister};
use crate::isa::arm::common::cpu::{AccessType, ArmError, MemoryFaultInfo, MemoryFaultType};
use crate::isa::arm::common::features::ArmFeatures;
use crate::isa::arm::common::sysreg::Aarch64SysRegEncoding;

impl AArch64Cpu {
    pub(in crate::isa::arm::aarch64::cpu) fn take_aarch32_exception(
        &mut self,
        target: u8,
        kind: ExceptionType,
        syndrome: SyndromeRegister,
    ) -> Result<(), ArmError> {
        let old = self.aarch32.ok_or_else(|| {
            ArmError::Internal(
                "AArch64 exception cannot enter a configured AArch32 lower EL".into(),
            )
        })?;
        if target != 1 && target != 2 {
            return Err(ArmError::Internal(
                "invalid AArch32 exception target".into(),
            ));
        }
        let saved = (self.pstate_bits() & !((1 << 24) | (1 << 21))) | (u64::from(self.dit) << 21);
        let ec = (syndrome.value >> 26) as u8;
        let (mode, vector, lr_offset, bank) = match kind {
            ExceptionType::Irq => (0x12, 0x18, 4, Some(0)),
            ExceptionType::Fiq => (0x11, 0x1c, 4, Some(3)),
            ExceptionType::Synchronous => match ec {
                0x11 => (0x13, 0x08, 0, None), // SVC: PC already advanced.
                0x20 | 0x21 | 0x38 => (0x17, 0x0c, 4, Some(1)),
                0x24 | 0x25 => (0x17, 0x10, 8, Some(1)),
                _ => (0x1b, 0x04, if old.t { 2 } else { 4 }, Some(2)),
            },
            ExceptionType::SError => (0x17, 0x10, 8, Some(1)),
        };
        let sctlr = self.sysregs.bank(target).sctlr;
        let mode = if target == 2 { 0x1a } else { mode };
        let mut vector = vector;
        if target == 2 {
            self.sysregs.el2.spsr = saved;
            self.sysregs.el2.elr = self.pc;
            if matches!(kind, ExceptionType::Synchronous) && self.current_el < 2 {
                vector = 0x14;
            }
        } else {
            if let Some(bank) = bank {
                let encoding = Aarch64SysRegEncoding::new(3, 4, 4, 3, bank).encode();
                self.sysregs.impl_defined.insert(encoding, saved);
            } else {
                self.sysregs.el1.spsr = saved;
            }
            let lr = usize::from(register_index(14, mode).unwrap());
            self.x[lr] = (self.x[lr] & 0xffff_ffff_0000_0000)
                | u64::from((self.pc as u32).wrapping_add(lr_offset));
        }
        if target == 2 && !matches!(kind, ExceptionType::Irq | ExceptionType::Fiq) {
            self.sysregs.bank_mut(target).esr = syndrome.value;
        }
        if target == 1 && ec == 0x38 {
            let status = if self.sysregs.el1.tcr & (1 << 31) != 0 {
                0x222
            } else {
                2
            };
            self.sysregs
                .impl_defined
                .insert(Aarch64SysRegEncoding::new(3, 4, 5, 0, 1).encode(), status);
            self.sysregs.el1.far = (self.sysregs.el1.far & 0xffff_ffff) | (self.pc << 32);
        }
        self.clear_exclusive_monitor();
        self.current_el = target;
        self.sp_sel = true;
        self.aarch32 = Some(Aarch32Pstate {
            mode,
            t: sctlr & (1 << 30) != 0,
            e: sctlr & (1 << 25) != 0,
            it: 0,
            ..old
        });
        self.ss = false;
        self.il = false;
        self.btype = 0;
        if target == 2 {
            let scr = self.sysregs.scr_el3;
            if scr & (1 << 3) == 0 {
                self.daif |= 4;
            }
            if scr & (1 << 1) == 0 {
                self.daif |= 2;
            }
            if scr & (1 << 2) == 0 {
                self.daif |= 1;
            }
        } else {
            self.daif |= match mode {
                0x11 => 7,
                0x12 | 0x17 => 6,
                _ => 2,
            };
            if sctlr & (1 << 23) == 0 {
                self.pan = true;
            }
        }
        if self.config.features.contains(ArmFeatures::SSBS) {
            self.ssbs = sctlr & (1 << 31) != 0;
        }
        let vbar = if target == 1 && sctlr & (1 << 13) != 0 {
            0xffff_0000
        } else {
            self.sysregs.bank(target).vbar as u32
        };
        self.pc = u64::from((vbar & !31) | vector);
        self.update_mmu_config();
        Ok(())
    }

    /// AArch32_Report{Data,Prefetch}Abort uses DFSR/IFSR and their distinct
    /// halves of FAR. SVC and UNDEF do not overwrite those abort registers.
    pub(in crate::isa::arm::aarch64::cpu) fn record_aarch32_abort(
        &mut self,
        target: u8,
        fault: &MemoryFaultInfo,
        level: u8,
    ) -> Result<bool, ArmError> {
        if crate::isa::arm::aarch64::exception_return::uses_aarch32(
            self.pauth_controls(),
            self.sysregs.id_aa64pfr0_el1,
            target,
        ) != Some(true)
        {
            return Ok(false);
        }
        let instruction = fault.access == AccessType::InstructionFetch;
        if target == 1 {
            let long = self.sysregs.el1.tcr & (1 << 31) != 0;
            let code = fault_status(fault.fault_type, level, long)?;
            let mut status = if long {
                (1 << 9) | code
            } else {
                ((code & 16) << 6) | (code & 15)
            };
            if instruction {
                self.sysregs
                    .impl_defined
                    .insert(Aarch64SysRegEncoding::new(3, 4, 5, 0, 1).encode(), status);
            } else {
                if matches!(fault.access, AccessType::Write | AccessType::Atomic) {
                    status |= 1 << 11;
                }
                self.sysregs.el1.esr = status;
            }
        }
        let far = &mut self.sysregs.bank_mut(target).far;
        *far = if instruction {
            (*far & 0xffff_ffff) | (u64::from(fault.address as u32) << 32)
        } else {
            (*far & 0xffff_ffff_0000_0000) | u64::from(fault.address as u32)
        };
        Ok(true)
    }
}

fn fault_status(kind: MemoryFaultType, level: u8, long: bool) -> Result<u64, ArmError> {
    let page = level >= 2;
    let code = if long {
        match kind {
            MemoryFaultType::AddressSize => u64::from(level & 3),
            MemoryFaultType::Translation => 4 | u64::from(level & 3),
            MemoryFaultType::AccessFlag => 8 | u64::from(level & 3),
            MemoryFaultType::Permission => 12 | u64::from(level & 3),
            MemoryFaultType::Alignment => 0x21,
            MemoryFaultType::External | MemoryFaultType::SyncExternal => 0x10,
            MemoryFaultType::TlbConflict => 0x30,
            MemoryFaultType::Lockdown => 0x34,
            MemoryFaultType::UnsupportedAtomic => 0x35,
            MemoryFaultType::SpAlignment => {
                return Err(ArmError::Internal("AArch32 SP alignment abort".into()));
            }
        }
    } else {
        match kind {
            MemoryFaultType::Translation => {
                if page {
                    7
                } else {
                    5
                }
            }
            MemoryFaultType::AccessFlag => {
                if page {
                    6
                } else {
                    3
                }
            }
            MemoryFaultType::Permission => {
                if page {
                    15
                } else {
                    13
                }
            }
            MemoryFaultType::Alignment => 1,
            MemoryFaultType::External | MemoryFaultType::SyncExternal => 8,
            MemoryFaultType::TlbConflict => 0x10,
            MemoryFaultType::Lockdown => 0x14,
            MemoryFaultType::UnsupportedAtomic => 0x15,
            MemoryFaultType::AddressSize | MemoryFaultType::SpAlignment => {
                return Err(ArmError::UnsupportedExecutionState(
                    "AArch32 short-descriptor fault class".into(),
                ));
            }
        }
    };
    Ok(code)
}
