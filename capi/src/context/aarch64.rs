//! Frozen legacy AArch64 context layout and strict format-4 decoder.

use super::{CTX_VERSION_AARCH64, CpuState, Reader};
use rax_engine::isa::arm::aarch64::AArch64Cpu;
use rax_engine::isa::arm::common::features::ArmFeatures;
use rax_engine::vm::vcpu::{Aarch64Registers, Aarch64SystemRegisters};

const CPU_STATE_AARCH64_VARIANT: u32 = 2;

pub(super) fn decode_state(bytes: &[u8], version: u32) -> Option<CpuState> {
    if version == CTX_VERSION_AARCH64 {
        let state: CpuState = rax_engine::codec::deserialize_strict(bytes).ok()?;
        let CpuState::Aarch64(arm) = &state else {
            return None;
        };
        let execution = arm.sregs.execution.as_ref()?;
        ArmFeatures::from_bits(execution.features)?;
        AArch64Cpu::validate_saved_state(arm.regs.pstate, &arm.sregs).ok()?;
        return Some(state);
    }

    // Formats 1 and 2 used exactly these fields in this order. Do not derive
    // this layout from the current Rust struct, which has a mandatory extension.
    let mut r = Reader::new(bytes);
    if r.u32()? != CPU_STATE_AARCH64_VARIANT {
        return None;
    }
    let mut regs = Aarch64Registers::default();
    for value in &mut regs.x {
        *value = r.u64()?;
    }
    regs.sp = r.u64()?;
    regs.pc = r.u64()?;
    regs.pstate = r.u64()?;
    for vector in &mut regs.v {
        vector[0] = r.u64()?;
        vector[1] = r.u64()?;
    }
    regs.fpcr = r.u32()?;
    regs.fpsr = r.u32()?;
    let sregs = Aarch64SystemRegisters {
        sctlr_el1: r.u64()?,
        tcr_el1: r.u64()?,
        ttbr0_el1: r.u64()?,
        ttbr1_el1: r.u64()?,
        mair_el1: r.u64()?,
        vbar_el1: r.u64()?,
        esr_el1: r.u64()?,
        far_el1: r.u64()?,
        elr_el1: r.u64()?,
        spsr_el1: r.u64()?,
        sp_el0: r.u64()?,
        sp_el1: r.u64()?,
        tpidr_el0: r.u64()?,
        tpidr_el1: r.u64()?,
        tpidrro_el0: r.u64()?,
        cntp_ctl_el0: r.u64()?,
        cntp_cval_el0: r.u64()?,
        cntv_ctl_el0: r.u64()?,
        cntv_cval_el0: r.u64()?,
        execution: None,
    };
    const AUTH_ENABLES: u64 = (1 << 31) | (1 << 30) | (1 << 27) | (1 << 13);
    if sregs.sctlr_el1 & AUTH_ENABLES != 0 || !r.at_end() {
        return None;
    }
    AArch64Cpu::validate_saved_state(regs.pstate, &sregs).ok()?;
    Some(CpuState::aarch64(regs, sregs))
}
