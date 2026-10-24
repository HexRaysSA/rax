//! Arm ELFromSPSR / IllegalExceptionReturn for the modeled AArch64 PE.
//!
//! RME, GCS and NV3 state are not advertised. AArch32 destinations are
//! classified explicitly so an execution plane must perform a state handoff
//! rather than interpreting the saved M field as an AArch64 mode.

use super::pauth::PauthControls;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExceptionReturnMode {
    Illegal,
    Aarch64 { el: u8, sp_elx: bool },
    Aarch32 { el: u8, mode: u8 },
}

fn has_aarch32(pfr0: u64, el: u8) -> bool {
    (pfr0 >> (u32::from(el) * 4)) & 15 == 2
}

pub(crate) fn uses_aarch32(controls: PauthControls, pfr0: u64, el: u8) -> Option<bool> {
    if !has_aarch32(pfr0, el) {
        return Some(false);
    }
    let secure = controls.scr_el3 & 1 == 0;
    if el == 3 || (el == 2 && secure) {
        return Some(false);
    }
    let secure_el2 = controls.secure_el2 && controls.scr_el3 & (1 << 18) != 0;
    if controls.implemented_els & 8 != 0
        && controls.scr_el3 & (1 << 10) == 0
        && (!secure || !secure_el2)
    {
        return Some(true);
    }
    if el == 2 {
        return Some(false);
    }
    let mut el0 = controls;
    el0.current_el = 0;
    let el0_is_host = el0.regime_el() == 2;
    if controls.implemented_els & 4 != 0
        && !el0_is_host
        && controls.hcr_el2 & (1 << 31) == 0
        && (!secure || secure_el2)
    {
        return Some(true);
    }
    if el == 1 { Some(false) } else { None }
}

/// This PE starts its highest implemented EL in AArch64. Lower-EL execution
/// width follows SCR.RW/HCR.RW, except for the architecturally unknown EL0
/// choice when its parent is AArch64. All shifts have bounded EL inputs.
pub fn classify_exception_return(
    controls: PauthControls,
    pfr0: u64,
    spsr: u64,
) -> ExceptionReturnMode {
    let mode = (spsr & 31) as u8;
    let aarch32 = mode & 16 != 0;
    let el = if aarch32 {
        match mode {
            0x10 => 0,
            0x11 | 0x12 | 0x13 | 0x17 | 0x1b | 0x1f => 1,
            0x1a => 2,
            0x16 => 3,
            _ => return ExceptionReturnMode::Illegal,
        }
    } else {
        let el = (mode >> 2) & 3;
        if mode & 2 != 0 || (el == 0 && mode & 1 != 0) {
            return ExceptionReturnMode::Illegal;
        }
        el
    };
    if controls.implemented_els & (1 << el) == 0
        || el > controls.current_el
        || (el == 2 && !controls.el2_enabled())
        || (aarch32 && !has_aarch32(pfr0, el))
        || (aarch32 && el == 2 && controls.scr_el3 & 1 == 0)
        || (el == 1 && controls.el2_enabled() && controls.hcr_el2 & (1 << 27) != 0)
    {
        return ExceptionReturnMode::Illegal;
    }
    if let Some(expected) = uses_aarch32(controls, pfr0, el) {
        if expected != aarch32 {
            return ExceptionReturnMode::Illegal;
        }
    }
    if aarch32 {
        ExceptionReturnMode::Aarch32 { el, mode }
    } else {
        ExceptionReturnMode::Aarch64 {
            el,
            sp_elx: mode & 1 != 0,
        }
    }
}

/// All PSTATE fields represented by the AArch64 core, in architectural positions.
pub const MODELED_AARCH64_PSTATE: u64 =
    0xf000_0000 | (0x3f << 20) | (1 << 12) | (3 << 10) | (15 << 6) | 15;

/// SetPSTATEFromPSR for an AArch64 result. On an illegal return the EL/SP
/// remain unchanged, NZCV/DAIF/PAN are restored, IL is set, and the permitted
/// ARBITRARY SSBS/UAO/DIT/TCO/BTYPE fields select zero consistently.
/// AArch32 requires its separate bank/mode handoff and returns `None`.
pub fn aarch64_return_pstate(
    current: u64,
    saved: u64,
    mode: ExceptionReturnMode,
    ss: bool,
) -> Option<u64> {
    let value = match mode {
        ExceptionReturnMode::Illegal => {
            (saved & (0xf000_0000 | (15 << 6) | (1 << 22))) | (current & 15) | (1 << 20)
        }
        ExceptionReturnMode::Aarch64 { .. } => saved & MODELED_AARCH64_PSTATE,
        ExceptionReturnMode::Aarch32 { .. } => return None,
    };
    Some((value & !(1 << 21)) | (u64::from(ss) << 21))
}

/// DebugExceptionReturnSS for modeled debug controls. OS software lock and
/// halting-debug state are not implemented/enabled by this PE.
pub fn exception_return_ss(
    controls: PauthControls,
    sysregs: &super::sysregs::SystemRegisters,
    current: u64,
    saved: u64,
    mode: ExceptionReturnMode,
) -> bool {
    if sysregs.mdscr_el1 & 1 == 0 || sysregs.osdlr_el1 & 1 != 0 {
        return false;
    }
    let destination = match mode {
        ExceptionReturnMode::Illegal => controls.current_el,
        ExceptionReturnMode::Aarch64 { el, .. } | ExceptionReturnMode::Aarch32 { el, .. } => el,
    };
    let debug_target = if controls.el2_enabled()
        && (controls.hcr_el2 & (1 << 27) != 0 || sysregs.mdcr_el2 & (1 << 8) != 0)
    {
        2
    } else {
        1
    };
    let secure_enabled = controls.scr_el3 & 1 != 0 || sysregs.mdcr_el3 & (1 << 16) == 0;
    let kde = sysregs.mdscr_el1 & (1 << 13) != 0;
    let enabled = |el: u8, d: bool| {
        secure_enabled && (el < debug_target || (el == debug_target && kde && !d))
    };
    saved & (1 << 21) != 0
        && !enabled(controls.current_el, current & (1 << 9) != 0)
        && enabled(destination, saved & (1 << 9) != 0)
}
