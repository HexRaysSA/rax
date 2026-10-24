//! AArch64 register views, including keyed authentication and banked state.

use super::*;

// AArch64 system registers (8 bytes each), in `rax.h` order.
const A64_SYSREG: i32 = 0x0400;
const A64_TPIDR_EL0: i32 = 0x0400;
const A64_TPIDRRO_EL0: i32 = 0x0401;
const A64_TPIDR_EL1: i32 = 0x0402;
const A64_SP_EL0: i32 = 0x0403;
const A64_SP_EL1: i32 = 0x0404;
const A64_ELR_EL1: i32 = 0x0405;
const A64_SPSR_EL1: i32 = 0x0406;
const A64_ESR_EL1: i32 = 0x0407;
const A64_FAR_EL1: i32 = 0x0408;
const A64_VBAR_EL1: i32 = 0x0409;
const A64_SCTLR_EL1: i32 = 0x040A;
const A64_TCR_EL1: i32 = 0x040B;
const A64_TTBR0_EL1: i32 = 0x040C;
const A64_TTBR1_EL1: i32 = 0x040D;
const A64_MAIR_EL1: i32 = 0x040E;
const A64_CNTP_CTL_EL0: i32 = 0x040F;
const A64_CNTP_CVAL_EL0: i32 = 0x0410;
const A64_CNTV_CTL_EL0: i32 = 0x0411;
const A64_CNTV_CVAL_EL0: i32 = 0x0412;

const A64_APIAKEYLO_EL1: i32 = 0x0413;
const A64_APIAKEYHI_EL1: i32 = 0x0414;
const A64_APIBKEYLO_EL1: i32 = 0x0415;
const A64_APIBKEYHI_EL1: i32 = 0x0416;
const A64_APDAKEYLO_EL1: i32 = 0x0417;
const A64_APDAKEYHI_EL1: i32 = 0x0418;
const A64_APDBKEYLO_EL1: i32 = 0x0419;
const A64_APDBKEYHI_EL1: i32 = 0x041A;
const A64_APGAKEYLO_EL1: i32 = 0x041B;
const A64_APGAKEYHI_EL1: i32 = 0x041C;
const A64_HCR_EL2: i32 = 0x041D;
const A64_SCR_EL3: i32 = 0x041E;
const A64_SP_EL2: i32 = 0x041F;
const A64_SP_EL3: i32 = 0x0420;
const A64_SCTLR_EL2: i32 = 0x0421;
const A64_TCR_EL2: i32 = 0x0422;
const A64_TTBR0_EL2: i32 = 0x0423;
const A64_TTBR1_EL2: i32 = 0x0424;
const A64_MAIR_EL2: i32 = 0x0425;
const A64_VBAR_EL2: i32 = 0x0426;
const A64_ESR_EL2: i32 = 0x0427;
const A64_FAR_EL2: i32 = 0x0428;
const A64_ELR_EL2: i32 = 0x0429;
const A64_SPSR_EL2: i32 = 0x042A;
const A64_SCTLR_EL3: i32 = 0x042B;
const A64_TCR_EL3: i32 = 0x042C;
const A64_TTBR0_EL3: i32 = 0x042D;
const A64_MAIR_EL3: i32 = 0x042E;
const A64_VBAR_EL3: i32 = 0x042F;
const A64_ESR_EL3: i32 = 0x0430;
const A64_FAR_EL3: i32 = 0x0431;
const A64_ELR_EL3: i32 = 0x0432;
const A64_SPSR_EL3: i32 = 0x0433;

fn arm64_sysreg(s: &mut rax_engine::cpu::Aarch64SystemRegisters, id: i32) -> Option<&mut u64> {
    Some(match id {
        A64_TPIDR_EL0 => &mut s.tpidr_el0,
        A64_TPIDRRO_EL0 => &mut s.tpidrro_el0,
        A64_TPIDR_EL1 => &mut s.tpidr_el1,
        A64_SP_EL0 => &mut s.sp_el0,
        A64_SP_EL1 => &mut s.sp_el1,
        A64_ELR_EL1 => &mut s.elr_el1,
        A64_SPSR_EL1 => &mut s.spsr_el1,
        A64_ESR_EL1 => &mut s.esr_el1,
        A64_FAR_EL1 => &mut s.far_el1,
        A64_VBAR_EL1 => &mut s.vbar_el1,
        A64_SCTLR_EL1 => &mut s.sctlr_el1,
        A64_TCR_EL1 => &mut s.tcr_el1,
        A64_TTBR0_EL1 => &mut s.ttbr0_el1,
        A64_TTBR1_EL1 => &mut s.ttbr1_el1,
        A64_MAIR_EL1 => &mut s.mair_el1,
        A64_CNTP_CTL_EL0 => &mut s.cntp_ctl_el0,
        A64_CNTP_CVAL_EL0 => &mut s.cntp_cval_el0,
        A64_CNTV_CTL_EL0 => &mut s.cntv_ctl_el0,
        A64_CNTV_CVAL_EL0 => &mut s.cntv_cval_el0,
        _ => {
            let state = s.execution.as_mut()?;
            match id {
                A64_APIAKEYLO_EL1 => &mut state.sysregs.apiakeylo_el1,
                A64_APIAKEYHI_EL1 => &mut state.sysregs.apiakeyhi_el1,
                A64_APIBKEYLO_EL1 => &mut state.sysregs.apibkeylo_el1,
                A64_APIBKEYHI_EL1 => &mut state.sysregs.apibkeyhi_el1,
                A64_APDAKEYLO_EL1 => &mut state.sysregs.apdakeylo_el1,
                A64_APDAKEYHI_EL1 => &mut state.sysregs.apdakeyhi_el1,
                A64_APDBKEYLO_EL1 => &mut state.sysregs.apdbkeylo_el1,
                A64_APDBKEYHI_EL1 => &mut state.sysregs.apdbkeyhi_el1,
                A64_APGAKEYLO_EL1 => &mut state.sysregs.apgakeylo_el1,
                A64_APGAKEYHI_EL1 => &mut state.sysregs.apgakeyhi_el1,
                A64_HCR_EL2 => &mut state.sysregs.hcr_el2,
                A64_SCR_EL3 => &mut state.sysregs.scr_el3,
                A64_SP_EL2 => &mut state.sp_el2,
                A64_SP_EL3 => &mut state.sp_el3,
                A64_SCTLR_EL2 => &mut state.sysregs.el2.sctlr,
                A64_TCR_EL2 => &mut state.sysregs.el2.tcr,
                A64_TTBR0_EL2 => &mut state.sysregs.el2.ttbr0,
                A64_TTBR1_EL2 => &mut state.sysregs.el2.ttbr1,
                A64_MAIR_EL2 => &mut state.sysregs.el2.mair,
                A64_VBAR_EL2 => &mut state.sysregs.el2.vbar,
                A64_ESR_EL2 => &mut state.sysregs.el2.esr,
                A64_FAR_EL2 => &mut state.sysregs.el2.far,
                A64_ELR_EL2 => &mut state.sysregs.el2.elr,
                A64_SPSR_EL2 => &mut state.sysregs.el2.spsr,
                A64_SCTLR_EL3 => &mut state.sysregs.el3.sctlr,
                A64_TCR_EL3 => &mut state.sysregs.el3.tcr,
                A64_TTBR0_EL3 => &mut state.sysregs.el3.ttbr0,
                A64_MAIR_EL3 => &mut state.sysregs.el3.mair,
                A64_VBAR_EL3 => &mut state.sysregs.el3.vbar,
                A64_ESR_EL3 => &mut state.sysregs.el3.esr,
                A64_FAR_EL3 => &mut state.sysregs.el3.far,
                A64_ELR_EL3 => &mut state.sysregs.el3.elr,
                A64_SPSR_EL3 => &mut state.sysregs.el3.spsr,
                _ => return None,
            }
        }
    })
}

/// The banked SP register (`A64_SP_EL0`/`A64_SP_EL1`) that PSTATE selects as
/// the current SP, if it is one of those two: EL0 and `EL1t` use `SP_EL0`,
/// `EL1h` uses `SP_EL1`.
fn arm64_current_sp(pstate: u64) -> Option<i32> {
    let el = (pstate >> 2) & 3;
    let sp_sel = pstate & 1 != 0;
    match (el, sp_sel) {
        (0, _) | (_, false) => Some(A64_SP_EL0),
        (1, true) => Some(A64_SP_EL1),
        (2, true) => Some(A64_SP_EL2),
        (3, true) => Some(A64_SP_EL3),
        _ => None,
    }
}

pub(super) fn arm64_size(id: i32) -> Option<usize> {
    let fam = id & !0xFF;
    let idx = (id & 0xFF) as usize;
    Some(match id {
        SC_SP | SC_PC | SC_PSTATE => 8,
        SC_FPCR | SC_FPSR => 4,
        A64_TPIDR_EL0..=A64_SPSR_EL3 => 8,
        _ => match fam {
            REG_GP if idx < 31 => 8,
            REG_VEC if idx < 32 => 16,
            _ => return None,
        },
    })
}

pub(super) fn arm64_read(st: &CpuState, id: i32, out: &mut [u8]) -> Option<usize> {
    let x = st.as_aarch64()?;
    let r = &x.regs;
    let size = arm64_size(id)?;
    let fam = id & !0xFF;
    let idx = (id & 0xFF) as usize;
    if id & !0xFF == A64_SYSREG {
        let mut sregs = x.sregs.clone();
        put_uint(out, *arm64_sysreg(&mut sregs, id)?, 8);
        return Some(size);
    }
    match id {
        SC_SP => put_uint(out, r.sp, 8),
        SC_PC => put_uint(out, r.pc, 8),
        SC_PSTATE => put_uint(out, r.pstate, 8),
        SC_FPCR => put_uint(out, r.fpcr as u64, 4),
        SC_FPSR => put_uint(out, r.fpsr as u64, 4),
        _ => match fam {
            REG_GP => put_uint(out, r.x[idx], 8),
            REG_VEC => {
                out[0..8].copy_from_slice(&r.v[idx][0].to_le_bytes());
                out[8..16].copy_from_slice(&r.v[idx][1].to_le_bytes());
            }
            _ => return None,
        },
    }
    Some(size)
}

pub(super) fn arm64_write(st: &mut CpuState, id: i32, inp: &[u8]) -> Option<usize> {
    let size = arm64_size(id)?;
    let x = match st {
        CpuState::Aarch64(x) => x,
        _ => return None,
    };
    let fam = id & !0xFF;
    let idx = (id & 0xFF) as usize;
    if fam == A64_SYSREG {
        let v = get_uint(inp, 8);
        *arm64_sysreg(&mut x.sregs, id)? = v;
        // The vCPU installs the banked SPs first and then the current SP
        // from `regs.sp`; keep that copy equal so the write takes effect.
        if arm64_current_sp(x.regs.pstate) == Some(id) {
            x.regs.sp = v;
        }
        return Some(size);
    }
    let r = &mut x.regs;
    match id {
        SC_SP => r.sp = get_uint(inp, 8),
        SC_PC => r.pc = get_uint(inp, 8),
        SC_PSTATE => {
            r.pstate = get_uint(inp, 8);
            // The vCPU installs `regs.sp` as the current SP after the new
            // PSTATE, so it must be the bank that PSTATE selects; otherwise
            // switching SPSel/EL copies the old stack pointer into the new
            // bank.
            match arm64_current_sp(r.pstate) {
                Some(A64_SP_EL0) => r.sp = x.sregs.sp_el0,
                Some(A64_SP_EL1) => r.sp = x.sregs.sp_el1,
                Some(A64_SP_EL2) => r.sp = x.sregs.execution.as_ref()?.sp_el2,
                Some(A64_SP_EL3) => r.sp = x.sregs.execution.as_ref()?.sp_el3,
                _ => {}
            }
        }
        SC_FPCR => r.fpcr = get_uint(inp, 4) as u32,
        SC_FPSR => r.fpsr = get_uint(inp, 4) as u32,
        _ => match fam {
            REG_GP => r.x[idx] = get_uint(inp, 8),
            REG_VEC => {
                let mut lo = [0u8; 8];
                let mut hi = [0u8; 8];
                lo.copy_from_slice(&inp[0..8]);
                hi.copy_from_slice(&inp[8..16]);
                r.v[idx][0] = u64::from_le_bytes(lo);
                r.v[idx][1] = u64::from_le_bytes(hi);
            }
            _ => return None,
        },
    }
    Some(size)
}
