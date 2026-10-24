//! AArch32 state views of an AArch64-capable PE.
//!
//! Arm A64 XML 2025-12: LookUpRIndex, AArch32_WriteMode,
//! GetPSRFromPSTATE, SetPSTATEFromPSR and RestoredITBits. Physical X registers
//! retain their upper 32 bits on AArch32 writes, the permitted ZEROUPPER=FALSE choice.

use super::pauth::PauthControls;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Aarch32Pstate {
    pub mode: u8,
    pub q: bool,
    pub it: u8,
    pub ge: u8,
    pub e: bool,
    pub t: bool,
}

pub fn mode_el(mode: u8) -> Option<u8> {
    match mode {
        0x10 => Some(0),
        0x11 | 0x12 | 0x13 | 0x17 | 0x1b | 0x1f => Some(1),
        0x1a => Some(2),
        0x16 => Some(3),
        _ => None,
    }
}

/// Physical X-register index for a banked R0-R14. Monitor SP/LR have
/// separate storage and cannot be reached by this PE's AArch64-reset EL3.
pub fn register_index(register: u8, mode: u8) -> Option<u8> {
    mode_el(mode)?;
    if register > 14 || (mode == 0x16 && register >= 13) {
        return None;
    }
    Some(match (register, mode) {
        (8..=14, 0x11) => register + 16,
        (13, 0x12) => 17,
        (14, 0x12) => 16,
        (13, 0x13) => 19,
        (14, 0x13) => 18,
        (13, 0x17) => 21,
        (14, 0x17) => 20,
        (13, 0x1b) => 23,
        (14, 0x1b) => 22,
        (13, 0x1a) => 15,
        _ => register,
    })
}

impl Aarch32Pstate {
    pub fn from_spsr(value: u64) -> Option<Self> {
        let mode = (value & 31) as u8;
        mode_el(mode)?;
        Some(Self {
            mode,
            q: value & (1 << 27) != 0,
            it: ((((value >> 10) & 63) << 2) | ((value >> 25) & 3)) as u8,
            ge: ((value >> 16) & 15) as u8,
            e: value & (1 << 9) != 0,
            t: value & (1 << 5) != 0,
        })
    }

    pub fn bits(self) -> u64 {
        u64::from(self.mode)
            | (u64::from(self.q) << 27)
            | (u64::from(self.it & 3) << 25)
            | (u64::from(self.it >> 2) << 10)
            | (u64::from(self.ge & 15) << 16)
            | (u64::from(self.e) << 9)
            | (u64::from(self.t) << 5)
    }

    pub(crate) fn sp_register(self) -> u8 {
        // All modes admitted by the AArch64-reset PE have an X-register view.
        register_index(13, self.mode).expect("validated non-Monitor mode")
    }
}

/// Legal AArch32 ERET restore in the 64-bit SPSR representation. IL selects
/// the permitted copy-T/copy-IT resolution. Otherwise reserved IT values and
/// IT blocks forbidden by ARM state or the destination SCTLR.ITD become zero.
pub fn return_pstate(saved: u64, ss: bool, mut controls: PauthControls) -> Option<u64> {
    let mut state = Aarch32Pstate::from_spsr(saved)?;
    controls.current_el = mode_el(state.mode)?;
    if state.mode == 0x16 {
        return None;
    }
    let illegal_execution = saved & (1 << 20) != 0;
    let reserved_it = state.it & 0xf0 != 0 && state.it & 15 == 0;
    let itd = controls.sctlr[controls.regime_el()] & (1 << 7) != 0;
    if !illegal_execution
        && (reserved_it || (!state.t && state.it != 0) || (itd && state.it & 7 != 0))
    {
        state.it = 0;
    }
    let common = saved & (0xf000_0000 | (7 << 22) | (1 << 20) | (7 << 6));
    Some(common | state.bits() | (u64::from(ss) << 21))
}

pub fn return_address(target: u64, pstate: u64) -> u64 {
    u64::from(target as u32) & if pstate & (1 << 5) != 0 { !1 } else { !3 }
}
