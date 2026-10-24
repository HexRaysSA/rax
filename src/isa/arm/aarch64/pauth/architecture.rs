//! Shared architectural PAuth configuration, control checks, and PAC layout.

use super::{PauthAddressLayout, PauthAlgorithm, PauthKey, PauthProfile};

/// Algorithm and authentication-failure behavior of the virtual PE.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PauthConfig {
    pub algorithm: PauthAlgorithm,
    pub profile: PauthProfile,
}

impl Default for PauthConfig {
    fn default() -> Self {
        Self {
            algorithm: PauthAlgorithm::Qarma5,
            profile: PauthProfile::FpacCombine,
        }
    }
}

/// Architectural pointer-authentication key selector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PauthKeyKind {
    Ia,
    Ib,
    Da,
    Db,
    Ga,
}

impl PauthKeyKind {
    pub fn data(self) -> bool {
        matches!(self, Self::Da | Self::Db)
    }
    pub fn key_b(self) -> bool {
        matches!(self, Self::Ib | Self::Db)
    }
    pub fn enable_bit(self) -> Option<u32> {
        match self {
            Self::Ia => Some(31),
            Self::Ib => Some(30),
            Self::Da => Some(27),
            Self::Db => Some(13),
            Self::Ga => None,
        }
    }
}

/// All five 128-bit keys, in architectural low/high order within each key.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PauthKeys {
    pub ia: PauthKey,
    pub ib: PauthKey,
    pub da: PauthKey,
    pub db: PauthKey,
    pub ga: PauthKey,
}

impl PauthKeys {
    pub fn get(self, kind: PauthKeyKind) -> PauthKey {
        match kind {
            PauthKeyKind::Ia => self.ia,
            PauthKeyKind::Ib => self.ib,
            PauthKeyKind::Da => self.da,
            PauthKeyKind::Db => self.db,
            PauthKeyKind::Ga => self.ga,
        }
    }
}

/// Exact synchronous syndrome, before exception entry mutates architectural state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PauthException {
    pub ec: u8,
    pub iss: u32,
    pub target_el: Option<u8>,
}

impl PauthException {
    pub fn authentication(data: bool, key_b: bool) -> Self {
        Self {
            ec: 0x1c,
            iss: (u32::from(data) << 1) | u32::from(key_b),
            target_el: None,
        }
    }
}

/// Control-state view used by direct, SMIR, and native execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PauthControls {
    pub current_el: u8,
    /// One bit per implemented exception level, including EL0.
    pub implemented_els: u8,
    pub secure_el2: bool,
    pub vhe: bool,
    pub sctlr: [u64; 4],
    pub tcr: [u64; 4],
    pub hcr_el2: u64,
    pub scr_el3: u64,
}

impl PauthControls {
    /// Target of a local synchronous PAC, BTI, or illegal-state exception.
    pub fn local_exception_target(self) -> u8 {
        if self.current_el != 0 {
            self.current_el
        } else if self.el2_enabled() && self.hcr_el2 & (1 << 27) != 0 {
            2
        } else {
            1
        }
    }

    /// Arm EndOfDecode / BTypeCompatible rules for ordinary A64, BTI,
    /// BRK/HLT, and PACIxSP. Call only when FEAT_BTI is implemented.
    /// FEAT_PAuth_EnhCtl and PAuth_LR are outside this PE's feature set.
    pub fn branch_target_compatible(self, instruction: u32, btype: u8, pauth: bool) -> bool {
        if btype == 0 {
            return true;
        }
        if instruction & 0xffff_ff3f == 0xd503_241f {
            return match (instruction >> 6) & 3 {
                0 => false,
                1 => btype != 3,
                2 => btype != 2,
                _ => true,
            };
        }
        if pauth && matches!(instruction, 0xd503_233f | 0xd503_237f) {
            let control = if self.current_el == 0 { 35 } else { 36 };
            return btype != 3 || self.sctlr[self.regime_el()] & (1 << control) == 0;
        }
        // BRK/HLT remain compatible regardless of whether execution later
        // takes their breakpoint/halting/undefined exception.
        matches!(instruction & 0xffe0_001f, 0xd420_0000 | 0xd440_0000)
    }

    fn has_el(self, el: u8) -> bool {
        self.implemented_els & (1 << el) != 0
    }

    pub fn el2_enabled(self) -> bool {
        self.has_el(2)
            && (!self.has_el(3)
                || self.scr_el3 & 1 != 0
                || (self.secure_el2 && self.scr_el3 & (1 << 18) != 0))
    }

    fn in_host(self) -> bool {
        self.vhe
            && self.el2_enabled()
            && self.hcr_el2 & (1 << 34) != 0
            && (self.current_el == 2 || (self.current_el == 0 && self.hcr_el2 & (1 << 27) != 0))
    }

    pub fn regime_el(self) -> usize {
        if self.current_el == 0 {
            if self.in_host() { 2 } else { 1 }
        } else {
            usize::from(self.current_el.min(3))
        }
    }

    pub fn two_ranges(self) -> bool {
        self.regime_el() == 1 || self.in_host()
    }

    fn check_trap(self, key_access: bool) -> Result<(), PauthException> {
        let hcr_bit = if key_access { 40 } else { 41 };
        let scr_bit = if key_access { 16 } else { 17 };
        // Arm IsAPI*KeyEnabled: EL2 trap takes priority over the ordinary
        // EL3 PAC trap. EL3 SDD extensions are not advertised by this PE.
        let el2_trap = self.current_el < 2
            && self.el2_enabled()
            && self.hcr_el2 & (1 << hcr_bit) == 0
            && !(self.current_el == 0 && self.in_host());
        let target = if el2_trap {
            Some(2)
        } else if self.current_el < 3 && self.has_el(3) && self.scr_el3 & (1 << scr_bit) == 0 {
            Some(3)
        } else {
            None
        };
        if let Some(target_el) = target {
            Err(PauthException {
                ec: if key_access { 0x18 } else { 0x09 },
                iss: 0,
                target_el: Some(target_el),
            })
        } else {
            Ok(())
        }
    }

    pub fn check_key_access(self) -> Result<(), PauthException> {
        self.check_trap(true)
    }

    /// A disabled address key returns identity before higher-EL PAC-use traps.
    /// The generic key has no SCTLR enable and always checks PAC-use traps.
    pub fn key_enabled(self, kind: PauthKeyKind) -> Result<bool, PauthException> {
        if let Some(bit) = kind.enable_bit() {
            if self.sctlr[self.regime_el()] & (1 << bit) == 0 {
                return Ok(false);
            }
        }
        self.check_trap(false)?;
        Ok(true)
    }

    /// Arm AArch64_BranchAddr: remove only an ignored instruction-address tag.
    /// Single-range EL2/EL3 zero-extend; EL1/host regimes sign-extend from bit 55.
    pub fn branch_address(self, address: u64) -> u64 {
        self.effective_address(address, false)
    }

    pub fn top_byte_ignored(self, address: u64, data: bool) -> bool {
        self.layout(address, data).top_byte_ignore
    }

    pub fn effective_address(self, address: u64, data: bool) -> u64 {
        if !self.top_byte_ignored(address, data) {
            address
        } else if self.two_ranges() && address & (1 << 55) != 0 {
            ((address << 8) as i64 >> 8) as u64
        } else {
            address & 0x00ff_ffff_ffff_ffff
        }
    }

    /// Non-LVA PAC-effective TxSZ uses the same constrained FORCE/clamping
    /// choice as the existing translation walker (16..48, or 16..47 for 64 KiB).
    pub fn layout(self, pointer: u64, data: bool) -> PauthAddressLayout {
        let tcr = self.tcr[self.regime_el()];
        let upper = self.two_ranges() && pointer & (1 << 55) != 0;
        let txsz = ((tcr >> if upper { 16 } else { 0 }) & 63) as u8;
        let granule = (tcr >> if upper { 30 } else { 14 }) & 3;
        let granule_64k = if upper { granule == 3 } else { granule == 1 };
        let txsz = txsz.clamp(16, if granule_64k { 47 } else { 48 });
        let (tbi_bit, tbid_bit) = if self.two_ranges() {
            (37 + u32::from(upper), 51 + u32::from(upper))
        } else {
            (20, 29)
        };
        let tbi = tcr & (1 << tbi_bit) != 0 && (data || tcr & (1 << tbid_bit) == 0);
        // Width is proven in [16,48] by the clamped TxSZ above.
        PauthAddressLayout {
            address_bits: 64 - txsz,
            top_byte_ignore: tbi,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn controls(el: u8) -> PauthControls {
        PauthControls {
            current_el: el,
            implemented_els: 15,
            secure_el2: false,
            vhe: false,
            sctlr: [0, 0, 0, 0],
            tcr: [0, 16 | (16 << 16), 16, 16],
            hcr_el2: (1 << 40) | (1 << 41),
            scr_el3: 1 | (1 << 16) | (1 << 17),
        }
    }

    #[test]
    fn pauth_controls_enables_and_higher_el_trap_priority() {
        for el in 0..=3 {
            for kind in [
                PauthKeyKind::Ia,
                PauthKeyKind::Ib,
                PauthKeyKind::Da,
                PauthKeyKind::Db,
            ] {
                let mut state = controls(el);
                assert_eq!(state.key_enabled(kind), Ok(false));
                state.sctlr[state.regime_el()] = 1 << kind.enable_bit().unwrap();
                assert_eq!(state.key_enabled(kind), Ok(true));
                state.hcr_el2 = 0;
                state.scr_el3 = 1;
                let trap = state.key_enabled(kind);
                if el < 2 {
                    assert_eq!(trap.unwrap_err().target_el, Some(2));
                } else if el == 2 {
                    assert_eq!(trap.unwrap_err().target_el, Some(3));
                } else {
                    assert_eq!(trap, Ok(true));
                }
            }
        }
    }

    #[test]
    fn pauth_controls_vhe_and_tbid_select_instruction_layout() {
        let mut state = controls(0);
        state.hcr_el2 |= (1 << 34) | (1 << 27);
        assert_eq!(state.regime_el(), 1); // E2H is not implemented without VHE.
        state.vhe = true;
        assert_eq!(state.regime_el(), 2);
        assert!(state.two_ranges());
        state.tcr[2] = 16 | (16 << 16) | (1 << 37) | (1 << 51);
        assert_eq!(
            state
                .layout(0xab00_0000_0000_1230, true)
                .strip(0xab00_0000_0000_1230),
            0xab00_0000_0000_1230
        );
        assert_eq!(
            state
                .layout(0xab00_0000_0000_1230, false)
                .strip(0xab00_0000_0000_1230),
            0x1230
        );
        // In host EL0, HCR.API does not cause a use trap; SCR.API still applies.
        state.hcr_el2 &= !(1 << 41);
        state.sctlr[2] = 1 << 31;
        assert_eq!(state.key_enabled(PauthKeyKind::Ia), Ok(true));
        state.scr_el3 &= !(1 << 17);
        assert_eq!(
            state.key_enabled(PauthKeyKind::Ia).unwrap_err().target_el,
            Some(3)
        );
    }

    #[test]
    fn pauth_branch_address_removes_tags_with_regime_specific_extension() {
        let mut state = controls(1);
        state.tcr[1] |= (1 << 37) | (1 << 38);
        assert_eq!(state.branch_address(0xab00_0000_0000_1230), 0x1230);
        assert_eq!(
            state.branch_address(0xabff_ffff_0000_1230),
            0xffff_ffff_0000_1230
        );
        state.tcr[1] |= 1 << 51;
        assert_eq!(
            state.branch_address(0xab00_0000_0000_1230),
            0xab00_0000_0000_1230
        );
        let mut state = controls(3);
        state.tcr[3] |= 1 << 20;
        assert_eq!(
            state.branch_address(0xabff_ffff_0000_1230),
            0x00ff_ffff_0000_1230
        );
    }

    #[test]
    fn pauth_controls_resolve_upper_range_and_single_regimes() {
        for el in 0..=3 {
            let mut state = controls(el);
            let regime = state.regime_el();
            if state.two_ranges() {
                state.tcr[regime] = 16 | (32 << 16) | (1 << 38);
                let pointer = 0xab80_ffff_0000_1230;
                assert_eq!(
                    state.layout(pointer, true).strip(pointer),
                    0xabff_ffff_0000_1230
                );
            } else {
                state.tcr[regime] = 16 | (1 << 20) | (1 << 29);
                let pointer = 0xab00_0000_0000_1230;
                assert_eq!(state.layout(pointer, true).strip(pointer), pointer);
                assert_eq!(state.layout(pointer, false).strip(pointer), 0x1230);
            }
        }
    }
}
