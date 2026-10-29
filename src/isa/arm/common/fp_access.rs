//! Represented AArch64 FP permission controls shared with mixed-width PEs.
//! Data: pinned Arm XML 2025-12 CheckFPEnabled/Trap and AdvSIMDFPAccessTrap.
//! System: Arm 102530_0002_05_en FPCR/FPSR accessibility (normal execution).

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FpAccessClass {
    Data,
    System,
    Sve,
    Sme,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FpAccessTrap {
    pub target_el: u8,
    pub ec: u8,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct FpAccessControls {
    pub current_el: u8,
    pub el2_enabled: bool,
    pub have_el3: bool,
    pub vhe: bool,
    pub hcr: u64,
    pub cpacr: u64,
    pub cptr_el2: u64,
    pub cptr_el3: u64,
}

impl FpAccessControls {
    fn host_el2(self) -> bool {
        self.el2_enabled && self.vhe && self.hcr & (1 << 34) != 0
    }

    /// Higher controls are also used by AArch32 after its local access checks.
    pub(crate) fn higher_fault(self) -> Option<FpAccessTrap> {
        if self.current_el <= 2 && self.el2_enabled {
            let disabled = if self.host_el2() {
                let tge = self.hcr & (1 << 27) != 0;
                match (self.cptr_el2 >> 20) & 3 {
                    0 | 2 => true,
                    1 => self.current_el == 0 && tge,
                    _ => false,
                }
            } else {
                self.cptr_el2 & (1 << 10) != 0
            };
            if disabled {
                return Some(FpAccessTrap {
                    target_el: 2,
                    ec: 7,
                });
            }
        }
        if self.have_el3 && self.cptr_el3 & (1 << 10) != 0 {
            return Some(FpAccessTrap {
                target_el: 3,
                ec: 7,
            });
        }
        None
    }

    /// Check scalable-vector and FP controls in their architectural order at
    /// each EL. The represented state is normal, non-streaming execution.
    fn scalable_fault(self, class: FpAccessClass) -> Option<FpAccessTrap> {
        let sme = class == FpAccessClass::Sme;
        let shift = if sme { 24 } else { 16 };
        let trap_bit = if sme { 12 } else { 8 };
        let ec = if sme { 0x1d } else { 0x19 };
        let tge = self.el2_enabled && self.hcr & (1 << 27) != 0;
        let host = self.host_el2() && (self.current_el == 2 || (self.current_el == 0 && tge));
        let disabled = |field: u64, el0: bool| field & 1 == 0 || (el0 && field != 3);
        if self.current_el <= 1 && !host {
            if disabled((self.cpacr >> shift) & 3, self.current_el == 0) {
                let routed = tge && (!sme || self.current_el == 0);
                return Some(FpAccessTrap {
                    target_el: if routed { 2 } else { 1 },
                    ec,
                });
            }
            if disabled((self.cpacr >> 20) & 3, self.current_el == 0) {
                return Some(FpAccessTrap {
                    target_el: if tge { 2 } else { 1 },
                    ec: if tge { 0 } else { 7 },
                });
            }
        }
        if self.current_el <= 2 && self.el2_enabled {
            let (scalable_disabled, fp_disabled) = if self.host_el2() {
                let el0_host = self.current_el == 0 && tge;
                (
                    disabled((self.cptr_el2 >> shift) & 3, el0_host),
                    disabled((self.cptr_el2 >> 20) & 3, el0_host),
                )
            } else {
                (
                    self.cptr_el2 & (1 << trap_bit) != 0,
                    self.cptr_el2 & (1 << 10) != 0,
                )
            };
            if scalable_disabled {
                return Some(FpAccessTrap { target_el: 2, ec });
            }
            if fp_disabled {
                return Some(FpAccessTrap {
                    target_el: 2,
                    ec: 7,
                });
            }
        }
        if self.have_el3 {
            if self.cptr_el3 & (1 << trap_bit) == 0 {
                return Some(FpAccessTrap { target_el: 3, ec });
            }
            if self.cptr_el3 & (1 << 10) != 0 {
                return Some(FpAccessTrap {
                    target_el: 3,
                    ec: 7,
                });
            }
        }
        None
    }

    pub(crate) fn fault(self, class: FpAccessClass) -> Option<FpAccessTrap> {
        let fpen = (self.cpacr >> 20) & 3;
        let tge = self.el2_enabled && self.hcr & (1 << 27) != 0;
        let in_host = self.host_el2() && (self.current_el == 2 || (self.current_el == 0 && tge));
        let disabled = match class {
            FpAccessClass::Sve | FpAccessClass::Sme => return self.scalable_fault(class),
            FpAccessClass::Data => {
                self.current_el <= 1
                    && !in_host
                    && (fpen & 1 == 0 || (self.current_el == 0 && fpen != 3))
            }
            FpAccessClass::System => match self.current_el {
                0 => !in_host && fpen != 3,
                1 => fpen & 1 == 0,
                _ => false,
            },
        };
        if disabled {
            let routed = tge && (class == FpAccessClass::Data || self.current_el == 0);
            return Some(FpAccessTrap {
                target_el: if routed { 2 } else { 1 },
                ec: if routed { 0 } else { 7 },
            });
        }
        self.higher_fault()
    }
}

/// Guest accesses, retained before IR optimization, independent of the host
/// trampoline's register-liveness decision. These fields are derived caches.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct FpAccessRequirements {
    pub data: bool,
    pub system: bool,
    pub sve: bool,
}

impl FpAccessRequirements {
    pub(crate) fn observe(&mut self, instruction: u32) {
        if is_fp_system_instruction(instruction) {
            self.system = true;
            return;
        }
        let major = (instruction >> 25) & 15;
        if major == 2 {
            self.sve = true;
            return;
        }
        self.data |= matches!(major, 2 | 7 | 15)
            || (matches!(major, 4 | 6 | 12 | 14) && instruction & (1 << 26) != 0);
    }

    pub(crate) fn permitted(self, controls: FpAccessControls) -> bool {
        (!self.data || controls.fault(FpAccessClass::Data).is_none())
            && (!self.system || controls.fault(FpAccessClass::System).is_none())
            && (!self.sve || controls.fault(FpAccessClass::Sve).is_none())
    }
}

/// MRS/MSR FPCR/FPSR, including Rt=31. L, op2[0] and Rt vary.
pub(crate) fn is_fp_system_instruction(instruction: u32) -> bool {
    instruction & 0xffdf_ffc0 == 0xd51b_4400
}
