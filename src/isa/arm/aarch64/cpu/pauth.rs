//! Direct pointer-authentication data-processing dispatch.

use super::*;

impl AArch64Cpu {
    pub(super) fn exec_pauth_dp1(
        &mut self,
        instruction: u32,
        _opcode: u32,
        _rn: u8,
        _rd: u8,
    ) -> Result<CpuExit, ArmError> {
        self.execute_pauth_instruction(instruction)
    }

    pub(super) fn exec_ldraa(&mut self, instruction: u32) -> Result<CpuExit, ArmError> {
        self.execute_pauth_instruction(instruction)
    }
}

use crate::isa::arm::aarch64::pauth::{
    PauthConfig, PauthControls, PauthException, PauthKey, PauthKeyKind, PauthKeys,
};
use crate::isa::arm::aarch64::pauth_execution::{
    PauthEffect, PauthEnvironment, PauthExecutionError, PauthInputs,
};
use crate::isa::arm::aarch64::pauth_instruction::PauthInstruction;

impl From<PauthException> for ArmError {
    fn from(value: PauthException) -> Self {
        Self::ArchitecturalException {
            ec: value.ec,
            iss: value.iss,
            target_el: value.target_el,
        }
    }
}

impl AArch64Cpu {
    /// Architectural PAuth controls, with EL presence derived from the PE's ID register.
    pub fn pauth_controls(&self) -> PauthControls {
        self.pauth_environment().controls
    }

    /// Replace the modeled system controls through the trusted host interface.
    /// EL presence, current EL, and feature metadata are read-only in this view.
    /// Rejected metadata leaves every control and native-cache entry unchanged.
    pub fn set_pauth_controls(&mut self, controls: PauthControls) -> Result<(), ArmError> {
        let current = self.pauth_controls();
        if controls.current_el != current.current_el
            || controls.implemented_els != current.implemented_els
            || controls.secure_el2 != current.secure_el2
            || controls.vhe != current.vhe
            || controls.sctlr[0] != 0
            || controls.tcr[0] != 0
        {
            return Err(ArmError::Configuration(
                "PAuth control view cannot change PE metadata".into(),
            ));
        }
        for el in 1..=3 {
            self.sysregs.bank_mut(el).sctlr = controls.sctlr[usize::from(el)];
            self.sysregs.bank_mut(el).tcr = controls.tcr[usize::from(el)];
        }
        self.sysregs.hcr_el2 = controls.hcr_el2;
        self.sysregs.scr_el3 = controls.scr_el3;
        self.update_mmu_config();
        #[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
        {
            self.jit.cache.clear();
            self.jit.hot.clear();
        }
        Ok(())
    }

    /// Read all five keys for trusted host-side state transfer.
    pub fn pauth_keys(&self) -> PauthKeys {
        PauthKeys::from_system_registers(&self.sysregs)
    }

    /// Replace keys through the trusted host interface; guest MSR still checks permissions.
    pub fn set_pauth_keys(&mut self, keys: PauthKeys) {
        self.sysregs.apiakeylo_el1 = keys.ia.lo;
        self.sysregs.apiakeyhi_el1 = keys.ia.hi;
        self.sysregs.apibkeylo_el1 = keys.ib.lo;
        self.sysregs.apibkeyhi_el1 = keys.ib.hi;
        self.sysregs.apdakeylo_el1 = keys.da.lo;
        self.sysregs.apdakeyhi_el1 = keys.da.hi;
        self.sysregs.apdbkeylo_el1 = keys.db.lo;
        self.sysregs.apdbkeyhi_el1 = keys.db.hi;
        self.sysregs.apgakeylo_el1 = keys.ga.lo;
        self.sysregs.apgakeyhi_el1 = keys.ga.hi;
    }

    /// Select the algorithm/profile and invalidate compiled configuration assumptions.
    pub fn configure_pauth(&mut self, config: PauthConfig) {
        self.config.pauth = config;
        self.update_pauth_id_registers();
        #[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
        {
            self.jit.cache.clear();
            self.jit.hot.clear();
        }
    }

    pub(super) fn update_pauth_id_registers(&mut self) {
        use crate::isa::arm::aarch64::pauth::{PauthAlgorithm, PauthProfile};
        self.sysregs.id_aa64isar1_el1 &= !((15 << 4) | (15 << 8) | (15 << 24) | (15 << 28));
        self.sysregs.id_aa64isar2_el1 &= !((15 << 8) | (15 << 12));
        let address = if self.config.features.contains(ArmFeatures::PACA) {
            match self.config.pauth.profile {
                PauthProfile::Base => 1,
                PauthProfile::Pauth2 => 3,
                PauthProfile::Fpac => 4,
                PauthProfile::FpacCombine => 5,
            }
        } else {
            0
        };
        let generic = u64::from(self.config.features.contains(ArmFeatures::PACG));
        match self.config.pauth.algorithm {
            PauthAlgorithm::Qarma5 => {
                self.sysregs.id_aa64isar1_el1 |= (address << 4) | (generic << 24)
            }
            PauthAlgorithm::Qarma3 => {
                self.sysregs.id_aa64isar2_el1 |= (address << 12) | (generic << 8)
            }
        }
    }

    pub(super) fn pauth_environment(&self) -> PauthEnvironment {
        PauthEnvironment::from_system_registers(
            self.config.features,
            self.config.pauth,
            self.current_el,
            &self.sysregs,
        )
    }

    pub(super) fn pauth_error(instruction: u32, error: PauthExecutionError) -> ArmError {
        match error {
            PauthExecutionError::Undefined => ArmError::UndefinedInstruction(instruction),
            PauthExecutionError::Exception(exception) => exception.into(),
            PauthExecutionError::SpAlignment { address } => {
                ArmError::MemoryError(MemoryFaultInfo {
                    address,
                    access: crate::isa::arm::common::cpu::AccessType::Read,
                    fault_type: MemoryFaultType::SpAlignment,
                    stage2: false,
                })
            }
            PauthExecutionError::UnsupportedState => {
                ArmError::Configuration("invalid PAuth execution metadata".to_string())
            }
        }
    }

    pub(crate) fn pauth_value(
        &self,
        pointer: u64,
        modifier: u64,
        kind: PauthKeyKind,
        authenticate: bool,
        combined: bool,
    ) -> Result<u64, ArmError> {
        self.pauth_environment()
            .value(pointer, modifier, kind, authenticate, combined)
            .map_err(|error| Self::pauth_error(0, error))
    }

    pub(super) fn exec_pauth_generic(
        &mut self,
        instruction: u32,
        _rd: u8,
        _rn: u8,
        _rm: u8,
    ) -> Result<CpuExit, ArmError> {
        self.execute_pauth_instruction(instruction)
    }

    fn execute_pauth_instruction(&mut self, raw: u32) -> Result<CpuExit, ArmError> {
        let instruction =
            PauthInstruction::decode(raw).ok_or(ArmError::UndefinedInstruction(raw))?;
        if matches!(instruction, PauthInstruction::ExceptionReturn { .. })
            && self.config.features.contains(ArmFeatures::PACA)
            && self.current_el == 0
        {
            return Err(ArmError::InvalidExceptionLevel(0));
        }
        let environment = self.pauth_environment();
        let effect = environment
            .plan(
                instruction,
                PauthInputs {
                    x: &self.x,
                    sp: self.current_sp(),
                    pc: self.pc.wrapping_sub(4),
                    elr: self.sysregs.bank(self.current_el).elr,
                    guarded: self
                        .instruction_guarded
                        .load(std::sync::atomic::Ordering::Relaxed),
                },
            )
            .map_err(|error| Self::pauth_error(raw, error))?;
        match effect {
            PauthEffect::None => {}
            PauthEffect::Register { dst, value } => self.set_x(dst, value),
            PauthEffect::Branch {
                target,
                link,
                btype,
            } => {
                if let Some(link) = link {
                    self.set_x(30, link);
                }
                self.btype = btype;
                self.pc = target;
            }
            PauthEffect::ExceptionReturn { target } => {
                return self.exception_return_to(Some(target));
            }
            PauthEffect::Load {
                address,
                dst,
                writeback,
            } => {
                let value = self.pauth_load64(address)?;
                self.set_x(dst, value);
                if let Some((base, value)) = writeback {
                    if base == 31 {
                        self.set_current_sp(value);
                    } else {
                        self.set_x(base, value);
                    }
                }
            }
        }
        Ok(CpuExit::Continue)
    }
}

impl AArch64Cpu {
    /// LDRAA/LDRAB byte order follows the effective SCTLR EE/E0E control.
    /// The backing memory's scalar byte order is converted explicitly.
    pub fn pauth_load64(&self, address: u64) -> Result<u64, ArmError> {
        let value = self.mem_read_u64(address).map_err(|mut error| {
            if let ArmError::MemoryError(info) = &mut error {
                self.retag_fault_address(info);
            }
            error
        })?;
        let controls = self.pauth_controls();
        let endian_bit = if self.current_el == 0 { 24 } else { 25 };
        let big_endian = controls.sctlr[controls.regime_el()] & (1 << endian_bit) != 0;
        Ok(if big_endian != self.memory.is_big_endian() {
            value.swap_bytes()
        } else {
            value
        })
    }

    pub(super) fn exec_br_reg_pauth(
        &mut self,
        instruction: u32,
        _opc: u32,
        _rn: u8,
        _rm: u8,
    ) -> Result<CpuExit, ArmError> {
        self.execute_pauth_instruction(instruction)
    }

    pub(super) fn check_pauth_key_instruction(
        &self,
        insn: u32,
        encoding: Aarch64SysRegEncoding,
        read: bool,
        rt: u8,
    ) -> Result<(), ArmError> {
        if encoding.op0 != 3 || encoding.op1 != 0 || encoding.crn != 2 {
            return Ok(());
        }
        let generic = match (encoding.crm, encoding.op2) {
            (1 | 2, 0..=3) => false,
            (3, 0..=1) => true,
            _ => return Ok(()),
        };
        let feature = if generic {
            ArmFeatures::PACG
        } else {
            ArmFeatures::PACA
        };
        if self.current_el == 0 || !self.config.features.contains(feature) {
            return Err(ArmError::UndefinedInstruction(insn));
        }
        self.pauth_controls()
            .check_key_access()
            .map_err(|mut trap| {
                trap.iss = (u32::from(encoding.op0) << 20)
                    | (u32::from(encoding.op2) << 17)
                    | (u32::from(encoding.op1) << 14)
                    | (u32::from(encoding.crn) << 10)
                    | (u32::from(rt) << 5)
                    | (u32::from(encoding.crm) << 1)
                    | u32::from(read);
                trap.into()
            })
    }

    pub(super) fn exec_pauth_hint(&mut self, immediate: u8) -> Result<CpuExit, ArmError> {
        self.execute_pauth_instruction(0xd503_201f | (u32::from(immediate) << 5))
    }
}

impl AArch64Cpu {
    /// Copy the architectural signing context for an EL0 thread clone. The
    /// caller constructs the child from the same PE configuration and address
    /// space. Translation roots accompany TCR/SCTLR so enabling a copied
    /// translation regime never pairs it with a reset TTBR.
    pub(crate) fn copy_user_pauth_state_from(&mut self, source: &Self) {
        self.config.pauth = source.config.pauth;
        self.sp_el = source.sp_el;
        self.set_pauth_keys(source.pauth_keys());
        self.sysregs.el1 = source.sysregs.el1.clone();
        self.sysregs.el2 = source.sysregs.el2.clone();
        self.sysregs.el3 = source.sysregs.el3.clone();
        self.sysregs.hcr_el2 = source.sysregs.hcr_el2;
        self.sysregs.scr_el3 = source.sysregs.scr_el3;
        self.update_pauth_id_registers();
        self.update_mmu_config();
        self.clear_jit_cache();
    }
}
