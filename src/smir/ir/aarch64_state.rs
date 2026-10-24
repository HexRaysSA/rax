//! Complete AArch64 state adapters; legacy system-register fields retain overlay authority.

use super::context::Aarch64RegState;
use crate::isa::arm::aarch64::AArch64Cpu;
use crate::isa::arm::aarch64::pauth_execution::PauthEnvironment;
use crate::isa::arm::common::{features::ArmFeatures, sysreg::Aarch64SysRegEncoding};
use crate::vm::vcpu::{Aarch64CpuState, Aarch64Registers, Aarch64SystemRegisters};

const NZCV: u64 = 0xf000_0000;

impl Aarch64RegState {
    pub fn from_cpu_state(state: &Aarch64CpuState) -> Result<Self, &'static str> {
        AArch64Cpu::validate_saved_state(state.regs.pstate, &state.sregs)
            .map_err(|_| "invalid AArch64 PSTATE")?;
        let execution = state
            .sregs
            .execution
            .as_ref()
            .ok_or("missing AArch64 system state")?;
        ArmFeatures::from_bits(execution.features).ok_or("unknown AArch64 feature bits")?;
        let mut result = Self {
            x: state.regs.x,
            sp: state.regs.sp,
            pc: state.regs.pc,
            nzcv: (state.regs.pstate & NZCV) as u32,
            fpcr: state.regs.fpcr,
            fpsr: state.regs.fpsr,
            v: state.regs.v,
            pstate: state.regs.pstate & !NZCV,
            system: Some(Box::new(state.sregs.clone())),
            instruction_guarded: None,
            event_register: false,
        };
        result.set_sp_value(result.sp);
        Ok(result)
    }

    pub fn to_cpu_state(&self) -> Option<Aarch64CpuState> {
        let system = self.system.as_ref()?;
        system.execution.as_ref()?;
        let mut exported = (**system).clone();
        match self.active_sp_bank() {
            Some(0) => exported.sp_el0 = self.sp,
            Some(1) => exported.sp_el1 = self.sp,
            Some(2) => exported.execution.as_mut()?.sp_el2 = self.sp,
            Some(3) => exported.execution.as_mut()?.sp_el3 = self.sp,
            _ => {}
        }
        let mut x = self.x;
        let sp = if let Some(index) = self.aarch32_sp_register() {
            let value = u64::from(self.sp as u32);
            x[usize::from(index)] = (x[usize::from(index)] & 0xffff_ffff_0000_0000) | value;
            value
        } else {
            self.sp
        };
        Some(Aarch64CpuState {
            regs: Aarch64Registers {
                x,
                sp,
                pc: self.pc,
                pstate: self.pstate_bits(),
                v: self.v,
                fpcr: self.fpcr,
                fpsr: self.fpsr,
            },
            sregs: exported,
        })
    }

    pub fn pstate_bits(&self) -> u64 {
        (self.pstate & !NZCV) | (u64::from(self.nzcv) & NZCV)
    }

    pub fn current_el(&self) -> u8 {
        if self.pstate & 16 != 0 {
            crate::isa::arm::aarch64::aarch32_state::mode_el((self.pstate & 31) as u8).unwrap_or(0)
        } else {
            ((self.pstate >> 2) & 3) as u8
        }
    }

    fn active_sp_bank(&self) -> Option<u8> {
        if self.pstate & 16 != 0 {
            return None;
        }
        if self.pstate & 1 == 0 {
            Some(0)
        } else {
            Some(self.current_el())
        }
    }

    pub(super) fn aarch32_sp_register(&self) -> Option<u8> {
        if self.pstate & 16 == 0 {
            return None;
        }
        crate::isa::arm::aarch64::aarch32_state::register_index(13, (self.pstate & 31) as u8)
    }

    pub fn sp_bank(&self, el: u8) -> Option<u64> {
        if el > 3 {
            return None;
        }
        if Some(el) == self.active_sp_bank() {
            return Some(self.sp);
        }
        let system = self.system.as_ref()?;
        Some(match el {
            0 => system.sp_el0,
            1 => system.sp_el1,
            2 => system.execution.as_ref()?.sp_el2,
            _ => system.execution.as_ref()?.sp_el3,
        })
    }

    pub fn set_sp_bank(&mut self, el: u8, value: u64) -> bool {
        if el > 3 {
            return false;
        }
        let current = Some(el) == self.active_sp_bank();
        let Some(system) = &mut self.system else {
            if current {
                self.sp = value;
            }
            return current;
        };
        match el {
            0 => system.sp_el0 = value,
            1 => system.sp_el1 = value,
            2 => {
                let Some(state) = &mut system.execution else {
                    return false;
                };
                state.sp_el2 = value;
            }
            _ => {
                let Some(state) = &mut system.execution else {
                    return false;
                };
                state.sp_el3 = value;
            }
        }
        if current {
            self.sp = value;
        }
        true
    }

    pub fn set_sp_value(&mut self, value: u64) {
        if let Some(index) = self.aarch32_sp_register() {
            self.sp = u64::from(value as u32);
            self.x[usize::from(index)] =
                (self.x[usize::from(index)] & 0xffff_ffff_0000_0000) | self.sp;
            return;
        }
        self.sp = value;
        if let Some(bank) = self.active_sp_bank() {
            self.set_sp_bank(bank, value);
        }
    }

    pub fn set_pstate_value(&mut self, value: u64) -> bool {
        if AArch64Cpu::validate_pstate_bits(value).is_err()
            || (value & 16 != 0
                && self
                    .system
                    .as_ref()
                    .is_none_or(|system| AArch64Cpu::validate_saved_state(value, system).is_err()))
        {
            return false;
        }
        let new_sp = if value & 16 != 0 {
            let Some(index) =
                crate::isa::arm::aarch64::aarch32_state::register_index(13, (value & 31) as u8)
            else {
                return false;
            };
            u64::from(self.x[usize::from(index)] as u32)
        } else {
            let new_bank = if value & 1 == 0 {
                0
            } else {
                ((value >> 2) & 3) as u8
            };
            let Some(sp) = self.sp_bank(new_bank) else {
                return false;
            };
            sp
        };
        self.set_sp_value(self.sp);
        self.pstate = value & !NZCV;
        self.nzcv = (value & NZCV) as u32;
        self.sp = new_sp;
        true
    }

    pub fn pauth_environment(&self) -> Option<PauthEnvironment> {
        AArch64Cpu::validate_pstate_bits(self.pstate_bits()).ok()?;
        let system = self.system.as_ref()?;
        let execution = system.execution.as_ref()?;
        let features = ArmFeatures::from_bits(execution.features)?;
        let mut environment = PauthEnvironment::from_system_registers(
            features,
            execution.pauth,
            self.current_el(),
            &execution.sysregs,
        );
        environment.controls.sctlr[1] = system.sctlr_el1;
        environment.controls.tcr[1] = system.tcr_el1;
        Some(environment)
    }

    /// An MMU-disabled fetch is known to be unguarded. A translated fetch
    /// requires authoritative per-instruction GP metadata from its memory plane.
    pub fn guarded_instruction(&self) -> Option<bool> {
        let environment = self.pauth_environment()?;
        if environment.controls.sctlr[environment.controls.regime_el()] & 1 == 0 {
            Some(false)
        } else {
            self.instruction_guarded
        }
    }

    pub fn read_system_register(&self, encoded: u16) -> Option<u64> {
        let encoding = Aarch64SysRegEncoding::decode(encoded);
        let tuple = (
            encoding.op0,
            encoding.op1,
            encoding.crn,
            encoding.crm,
            encoding.op2,
        );
        match tuple {
            (3, 3, 4, 2, 0) => return Some(u64::from(self.nzcv)),
            (3, 3, 4, 4, 0) => return Some(u64::from(self.fpcr)),
            (3, 3, 4, 4, 1) => return Some(u64::from(self.fpsr)),
            (3, 0, 4, 2, 2) => return Some(u64::from(self.current_el()) << 2),
            (3, 0, 4, 2, 0) => return Some(self.pstate & 1),
            (3, 0, 4, 1, 0) => return self.sp_bank(0),
            (3, 4, 4, 1, 0) => return self.sp_bank(1),
            (3, 6, 4, 1, 0) => return self.sp_bank(2),
            _ => {}
        }
        let system = self.system.as_ref()?;
        if let Some(value) = read_legacy(system, tuple) {
            return Some(value);
        }
        // ArchReg identifies internal state, not a guest MRS access. The lifter
        // or semantic operation must separately enforce guest privilege/traps.
        system.execution.as_ref()?.sysregs.read(encoding, 3)
    }

    pub fn write_system_register(&mut self, encoded: u16, value: u64) -> bool {
        let encoding = Aarch64SysRegEncoding::decode(encoded);
        let tuple = (
            encoding.op0,
            encoding.op1,
            encoding.crn,
            encoding.crm,
            encoding.op2,
        );
        match tuple {
            (3, 3, 4, 2, 0) => {
                self.nzcv = (value & NZCV) as u32;
                return true;
            }
            (3, 3, 4, 4, 0) => {
                self.fpcr = value as u32;
                return true;
            }
            (3, 3, 4, 4, 1) => {
                self.fpsr = value as u32;
                return true;
            }
            (3, 0, 4, 1, 0) => return self.set_sp_bank(0, value),
            (3, 4, 4, 1, 0) => return self.set_sp_bank(1, value),
            (3, 6, 4, 1, 0) => return self.set_sp_bank(2, value),
            _ => {}
        }
        let Some(system) = &mut self.system else {
            return false;
        };
        if write_legacy(system, tuple, value) {
            return true;
        }
        let Some(state) = &mut system.execution else {
            return false;
        };
        state.sysregs.write(encoding, value, 3)
    }
}

type Encoding = (u8, u8, u8, u8, u8);

fn read_legacy(system: &Aarch64SystemRegisters, encoding: Encoding) -> Option<u64> {
    Some(match encoding {
        (3, 0, 1, 0, 0) => system.sctlr_el1,
        (3, 0, 2, 0, 2) => system.tcr_el1,
        (3, 0, 2, 0, 0) => system.ttbr0_el1,
        (3, 0, 2, 0, 1) => system.ttbr1_el1,
        (3, 0, 10, 2, 0) => system.mair_el1,
        (3, 0, 12, 0, 0) => system.vbar_el1,
        (3, 0, 5, 2, 0) => system.esr_el1,
        (3, 0, 6, 0, 0) => system.far_el1,
        (3, 0, 4, 0, 1) => system.elr_el1,
        (3, 0, 4, 0, 0) => system.spsr_el1,
        (3, 3, 13, 0, 2) => system.tpidr_el0,
        (3, 0, 13, 0, 4) => system.tpidr_el1,
        (3, 3, 13, 0, 3) => system.tpidrro_el0,
        (3, 3, 14, 2, 1) => system.cntp_ctl_el0,
        (3, 3, 14, 2, 2) => system.cntp_cval_el0,
        (3, 3, 14, 3, 1) => system.cntv_ctl_el0,
        (3, 3, 14, 3, 2) => system.cntv_cval_el0,
        _ => return None,
    })
}

fn write_legacy(system: &mut Aarch64SystemRegisters, encoding: Encoding, value: u64) -> bool {
    match encoding {
        (3, 0, 1, 0, 0) => system.sctlr_el1 = value,
        (3, 0, 2, 0, 2) => system.tcr_el1 = value,
        (3, 0, 2, 0, 0) => system.ttbr0_el1 = value,
        (3, 0, 2, 0, 1) => system.ttbr1_el1 = value,
        (3, 0, 10, 2, 0) => system.mair_el1 = value,
        (3, 0, 12, 0, 0) => system.vbar_el1 = value,
        (3, 0, 5, 2, 0) => system.esr_el1 = value,
        (3, 0, 6, 0, 0) => system.far_el1 = value,
        (3, 0, 4, 0, 1) => system.elr_el1 = value,
        (3, 0, 4, 0, 0) => system.spsr_el1 = value,
        (3, 3, 13, 0, 2) => system.tpidr_el0 = value,
        (3, 0, 13, 0, 4) => system.tpidr_el1 = value,
        (3, 3, 13, 0, 3) => system.tpidrro_el0 = value,
        (3, 3, 14, 2, 1) => system.cntp_ctl_el0 = value,
        (3, 3, 14, 2, 2) => system.cntp_cval_el0 = value,
        (3, 3, 14, 3, 1) => system.cntv_ctl_el0 = value,
        (3, 3, 14, 3, 2) => system.cntv_cval_el0 = value,
        _ => return false,
    }
    true
}
