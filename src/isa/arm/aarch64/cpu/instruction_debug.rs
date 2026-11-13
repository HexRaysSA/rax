//! Arm base self-hosted instruction breakpoints. The modeled debug profile
//! has no BWE/ABLE, extended comparator banks, halting debug or OS software
//! lock. Reserved control combinations select the permitted disabled result.
//! Source: Arm shared ASL 2025-12, AArch64_CheckDebug, BreakpointMatch,
//! BreakpointValueMatch, StateMatch and GenerateDebugExceptionsFrom.
use super::*;

impl AArch64Cpu {
    pub(super) fn update_debug_id_registers(&mut self) {
        // BRPs/WRPs encode count minus one. The existing CTX_CMPs=0
        // profile has one context-aware comparator: the last implemented BRP.
        self.sysregs.id_aa64dfr0_el1 = (self.sysregs.id_aa64dfr0_el1 & !0x00f0_f000)
            | (u64::from(self.config.num_breakpoints - 1) << 12)
            | (u64::from(self.config.num_watchpoints - 1) << 20);
    }

    /// Native regions do not carry an instruction-by-instruction debug check.
    /// Defer while an implemented execution comparator is enabled, including
    /// a comparator installed after a region was already compiled.
    pub(super) fn instruction_debug_armed(&self) -> bool {
        self.sysregs.mdscr_el1 & (1 << 15) != 0
            && self.sysregs.dbgbcr[..usize::from(self.config.num_breakpoints)]
                .iter()
                .any(|control| control & 1 != 0)
    }

    pub(super) fn check_instruction_breakpoints(&self) -> Result<(), ArmError> {
        if !self.instruction_debug_armed() {
            return Ok(());
        }
        let controls = self.pauth_controls();
        let secure = controls.implemented_els & 8 != 0
            && (self.current_el == 3 || controls.scr_el3 & 1 == 0);
        let target = if controls.el2_enabled()
            && (controls.hcr_el2 & (1 << 27) != 0 || self.sysregs.mdcr_el2 & (1 << 8) != 0)
        {
            2
        } else {
            1
        };
        if self.sysregs.osdlr_el1 & 1 != 0
            || self.halted
            || (secure && self.sysregs.mdcr_el3 & (1 << 16) != 0)
            || self.current_el > target
            || (self.current_el == target
                && (self.sysregs.mdscr_el1 & (1 << 13) == 0 || self.daif & 8 != 0))
        {
            return Ok(());
        }

        let mut address_active = false;
        let mut address_match = false;
        let mut mismatch_active = false;
        let mut mismatch = true;
        let mut context_match = false;
        for slot in 0..usize::from(self.config.num_breakpoints) {
            let control = self.sysregs.dbgbcr[slot];
            let Some(kind) = self.breakpoint_type(slot) else {
                continue;
            };
            // Linking-enabled units contribute only through their link.
            if kind & 1 != 0 && kind & 0b1010 != 0 {
                continue;
            }
            if !self.breakpoint_state_match(control, secure) {
                continue;
            }
            if kind & 1 != 0 {
                let link = ((control >> 16) & 15) as usize;
                if self
                    .breakpoint_type(link)
                    .is_none_or(|kind| kind & 1 == 0 || kind & 0b1010 == 0)
                    || !self.breakpoint_value_match(link)
                {
                    continue;
                }
            }
            let matched = self.breakpoint_value_match(slot);
            match kind {
                0 | 1 => {
                    address_active = true;
                    address_match |= matched;
                }
                4 | 5 => {
                    mismatch_active = true;
                    mismatch &= !matched;
                }
                _ => context_match |= matched,
            }
        }
        let address = if address_active && mismatch_active {
            address_match && mismatch
        } else {
            (address_active && address_match) || (mismatch_active && mismatch)
        };
        if address || context_match {
            Err(ArmError::ArchitecturalException {
                ec: if self.current_el == target {
                    0x31
                } else {
                    0x30
                },
                iss: 0x22,
                target_el: Some(target),
            })
        } else {
            Ok(())
        }
    }

    /// None selects Constraint_DISABLED for disabled, unimplemented or
    /// reserved breakpoint types in the base debug profile.
    fn breakpoint_type(&self, slot: usize) -> Option<u8> {
        if slot >= usize::from(self.config.num_breakpoints) {
            return None;
        }
        let control = self.sysregs.dbgbcr[slot];
        if control & 1 == 0 {
            return None;
        }
        let kind = ((control >> 20) & 15) as u8;
        let controls = self.pauth_controls();
        let context_count = (((self.sysregs.id_aa64dfr0_el1 >> 28) & 15) + 1)
            .min(u64::from(self.config.num_breakpoints)) as usize;
        let context_aware = slot >= usize::from(self.config.num_breakpoints) - context_count;
        if (kind & 0b1010 != 0 && !context_aware)
            || (kind & 8 != 0 && controls.implemented_els & 4 == 0)
            || (matches!(kind, 6 | 7 | 12..=15) && !controls.vhe)
            || (matches!(kind, 4 | 5) && (self.sysregs.id_aa64pfr0_el1 >> 4) & 15 != 2)
        {
            None
        } else {
            Some(kind)
        }
    }

    fn breakpoint_value_match(&self, slot: usize) -> bool {
        let Some(kind) = self.breakpoint_type(slot) else {
            return false;
        };
        let control = self.sysregs.dbgbcr[slot];
        let value = self.sysregs.dbgbvr[slot];
        let controls = self.pauth_controls();
        let host = controls.vhe
            && controls.el2_enabled()
            && controls.hcr_el2 & (1 << 34) != 0
            && (self.current_el == 2
                || (self.current_el == 0 && controls.hcr_el2 & (1 << 27) != 0));
        if kind & 0b1010 == 0 {
            // DebugAddrTop=48 without LVA/LVA3. Ignore RESS consistently;
            // mismatched sign-extension bits have an UNPREDICTABLE match.
            let mask = ((1u64 << 49) - 1) & !3;
            let has_aarch32 = (0..4).any(|el| (self.sysregs.id_aa64pfr0_el1 >> (el * 4)) & 15 == 2);
            return self.pc & mask == value & mask && (!has_aarch32 || control & (1 << 5) != 0);
        }
        let low = match kind {
            2 | 3 => {
                if host {
                    self.sysregs.el2.contextidr as u32 == value as u32
                } else {
                    self.current_el < 2 && self.sysregs.el1.contextidr as u32 == value as u32
                }
            }
            6 | 7 | 10 | 11 | 14 | 15 => {
                self.current_el < 2 && !host && self.sysregs.el1.contextidr as u32 == value as u32
            }
            _ => true,
        };
        let high = if kind & 12 == 8 {
            // VMID16 is not advertised by this profile.
            self.current_el < 2
                && controls.el2_enabled()
                && !host
                && ((self.sysregs.vttbr_el2 >> 48) & 255) == ((value >> 32) & 255)
        } else if kind & 12 == 12 {
            self.current_el != 3
                && controls.el2_enabled()
                && self.sysregs.el2.contextidr as u32 == (value >> 32) as u32
        } else {
            true
        };
        low && high
    }

    fn breakpoint_state_match(&self, control: u64, secure: bool) -> bool {
        let controls = self.pauth_controls();
        let el2 = controls.implemented_els & 4 != 0;
        let el3 = controls.implemented_els & 8 != 0;
        let hmc = control & (1 << 13) != 0;
        let ssc = (control >> 14) & 3;
        let pmc = (control >> 1) & 3;
        let aarch32_el1 = (self.sysregs.id_aa64pfr0_el1 >> 4) & 15 == 2;
        // CheckValidStateMatch, selecting Constraint_DISABLED for reserved
        // combinations. SSCE is RES0: RME security states are not represented.
        let reserved = (!hmc && ssc == 3 && pmc == 2)
            || (!hmc && ssc >= 2 && !el3)
            || (hmc && ssc == 0 && pmc & 1 == 0)
            || (hmc && ssc != 0 && pmc == 2)
            || (!aarch32_el1 && !hmc && pmc == 0 && ssc != 3)
            || (!el2 && !el3 && (hmc || ssc != 0))
            || (!el3 && matches!(ssc, 1 | 2) && !(hmc && ssc == 1 && pmc == 0))
            || (!el3 && hmc && ssc == 2 && pmc == 0)
            || (!el2 && hmc && ssc == 3 && pmc == 0)
            || (!controls.secure_el2
                && ((ssc == 3 && pmc & 1 != 0)
                    || (pmc == 0 && ((!hmc && ssc == 3) || (hmc && ssc == 1)))));
        if reserved {
            return false;
        }
        let privilege = match self.current_el {
            0 => pmc & 2 != 0,
            1 => pmc & 1 != 0,
            2 => el2 && ((hmc && !(ssc == 2 && pmc == 0)) || ssc == 3),
            3 => el3 && hmc && ssc & 1 == 0,
            _ => false,
        };
        let security = match ssc {
            0 => true,
            1 => !secure,
            _ => secure,
        };
        privilege && security
    }
}
