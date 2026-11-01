//! Native AArch64 public-state transfer with canonical current-SP authority.
use super::*;
fn unsupported_stack_mode(pstate: u64) -> Error {
    Error::InvalidConfig(format!(
        "ARM64 HVF state requires EL0t, EL1t or EL1h mode (PSTATE mode {:#x})",
        pstate & 0x1f,
    ))
}
impl HvfArm64Core {
    pub(super) fn native_state(&self) -> Result<CpuState> {
        let mut regs = Aarch64Registers::default();

        // Read X0-X30
        for i in 0..31 {
            regs.x[i] = self.read_gpr(i as u32)?;
        }

        // Read PC, SP, PSTATE
        regs.pc = self.read_gpr(HV_REG_PC)?;
        regs.pstate = self.read_gpr(HV_REG_CPSR)?;

        // Read FPCR/FPSR
        regs.fpcr = self.read_gpr(HV_REG_FPCR)? as u32;
        regs.fpsr = self.read_gpr(HV_REG_FPSR)? as u32;

        // Read V0-V31
        for i in 0..32 {
            regs.v[i] = self.read_simd_reg(i as u32)?;
        }

        // Read system registers
        let mut sregs = Aarch64SystemRegisters::default();
        sregs.sctlr_el1 = self.read_sys_reg(HV_SYS_REG_SCTLR_EL1)?;
        sregs.tcr_el1 = self.read_sys_reg(HV_SYS_REG_TCR_EL1)?;
        sregs.ttbr0_el1 = self.read_sys_reg(HV_SYS_REG_TTBR0_EL1)?;
        sregs.ttbr1_el1 = self.read_sys_reg(HV_SYS_REG_TTBR1_EL1)?;
        sregs.mair_el1 = self.read_sys_reg(HV_SYS_REG_MAIR_EL1)?;
        sregs.vbar_el1 = self.read_sys_reg(HV_SYS_REG_VBAR_EL1)?;
        sregs.esr_el1 = self.read_sys_reg(HV_SYS_REG_ESR_EL1)?;
        sregs.far_el1 = self.read_sys_reg(HV_SYS_REG_FAR_EL1)?;
        sregs.elr_el1 = self.read_sys_reg(HV_SYS_REG_ELR_EL1)?;
        sregs.spsr_el1 = self.read_sys_reg(HV_SYS_REG_SPSR_EL1)?;
        sregs.sp_el0 = self.read_sys_reg(HV_SYS_REG_SP_EL0)?;
        sregs.sp_el1 = self.read_sys_reg(HV_SYS_REG_SP_EL1)?;
        sregs.tpidr_el0 = self.read_sys_reg(HV_SYS_REG_TPIDR_EL0)?;
        sregs.tpidr_el1 = self.read_sys_reg(HV_SYS_REG_TPIDR_EL1)?;
        sregs.tpidrro_el0 = self.read_sys_reg(HV_SYS_REG_TPIDRRO_EL0)?;
        sregs.cntp_cval_el0 = self.read_sys_reg(HV_SYS_REG_CNTP_CVAL_EL0)?;
        sregs.cntp_ctl_el0 = self.read_sys_reg(HV_SYS_REG_CNTP_CTL_EL0)?;
        sregs.cntv_cval_el0 = self.read_sys_reg(HV_SYS_REG_CNTV_CVAL_EL0)?;
        sregs.cntv_ctl_el0 = self.read_sys_reg(HV_SYS_REG_CNTV_CTL_EL0)?;

        regs.sp = stack::current_sp(regs.pstate, sregs.sp_el0, sregs.sp_el1)
            .ok_or_else(|| unsupported_stack_mode(regs.pstate))?;
        Ok(CpuState::Aarch64(Aarch64CpuState { regs, sregs }))
    }

    /// Register overlays retain an incomplete load's instruction frontier.
    /// Explicit replacement uses set_state and cancels the transaction instead.
    pub(super) fn validate_pending_pc_overlay(&self, pc: u64) -> Result<()> {
        let deferred = self
            .pending_mmio_read
            .is_some_and(|pending| pending.retire_pc.is_some());
        if deferred && pc != self.read_gpr(HV_REG_PC)? {
            return Err(Error::InvalidConfig(
                "cannot change PC during a pending native read; complete the input or use set_state for explicit replacement".into(),
            ));
        }
        Ok(())
    }

    pub(super) fn restore_native_state(&mut self, state: &CpuState) -> Result<()> {
        let state = match state {
            CpuState::Aarch64(state) => state,
            _ => {
                return Err(Error::InvalidConfig(
                    "ARM64 HVF backend requires aarch64 state".to_string(),
                ));
            }
        };

        let regs = &state.regs;
        let sregs = &state.sregs;
        // Admit the represented EL0/EL1 mode before the first native write.
        // The current-SP projection overlays its selected bank; the other
        // represented bank retains the caller's complete banked value.
        let [sp_el0, sp_el1] =
            stack::restored_banks(regs.pstate, regs.sp, sregs.sp_el0, sregs.sp_el1)
                .ok_or_else(|| unsupported_stack_mode(regs.pstate))?;

        // Write X0-X30
        for i in 0..31 {
            self.write_gpr(i as u32, regs.x[i])?;
        }

        // Write PC, SP, PSTATE
        self.write_gpr(HV_REG_PC, regs.pc)?;
        self.write_gpr(HV_REG_CPSR, regs.pstate)?;

        // Write FPCR/FPSR
        self.write_gpr(HV_REG_FPCR, regs.fpcr as u64)?;
        self.write_gpr(HV_REG_FPSR, regs.fpsr as u64)?;

        // Write V0-V31
        for i in 0..32 {
            self.write_simd_reg(i as u32, regs.v[i])?;
        }

        // Write system registers
        self.write_sys_reg(HV_SYS_REG_SCTLR_EL1, sregs.sctlr_el1)?;
        self.write_sys_reg(HV_SYS_REG_TCR_EL1, sregs.tcr_el1)?;
        self.write_sys_reg(HV_SYS_REG_TTBR0_EL1, sregs.ttbr0_el1)?;
        self.write_sys_reg(HV_SYS_REG_TTBR1_EL1, sregs.ttbr1_el1)?;
        self.write_sys_reg(HV_SYS_REG_MAIR_EL1, sregs.mair_el1)?;
        self.write_sys_reg(HV_SYS_REG_VBAR_EL1, sregs.vbar_el1)?;
        self.write_sys_reg(HV_SYS_REG_ESR_EL1, sregs.esr_el1)?;
        self.write_sys_reg(HV_SYS_REG_FAR_EL1, sregs.far_el1)?;
        self.write_sys_reg(HV_SYS_REG_ELR_EL1, sregs.elr_el1)?;
        self.write_sys_reg(HV_SYS_REG_SPSR_EL1, sregs.spsr_el1)?;
        self.write_sys_reg(HV_SYS_REG_SP_EL0, sp_el0)?;
        self.write_sys_reg(HV_SYS_REG_SP_EL1, sp_el1)?;
        self.write_sys_reg(HV_SYS_REG_TPIDR_EL0, sregs.tpidr_el0)?;
        self.write_sys_reg(HV_SYS_REG_TPIDR_EL1, sregs.tpidr_el1)?;
        self.write_sys_reg(HV_SYS_REG_TPIDRRO_EL0, sregs.tpidrro_el0)?;
        // Install compare values before enabling either timer.
        self.write_sys_reg(HV_SYS_REG_CNTP_CVAL_EL0, sregs.cntp_cval_el0)?;
        self.write_sys_reg(HV_SYS_REG_CNTV_CVAL_EL0, sregs.cntv_cval_el0)?;
        self.write_sys_reg(HV_SYS_REG_CNTP_CTL_EL0, sregs.cntp_ctl_el0)?;
        self.write_sys_reg(HV_SYS_REG_CNTV_CTL_EL0, sregs.cntv_ctl_el0)?;

        Ok(())
    }
}
