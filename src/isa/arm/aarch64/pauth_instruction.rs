//! Typed, allocation-free PAuth instruction descriptors (Arm A64 XML 2025-12).
//!
//! Every operand is a 64-bit architectural value. Register 31 is XZR in
//! destination/target/data slots; explicit `Sp` identifies modifier slots.
//! Authenticated loads encode the scaled signed displacement in bytes.

use super::pauth::PauthKeyKind;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PauthModifier {
    Zero,
    Register(u8),
    Sp,
}

impl PauthModifier {
    fn register_or_sp(index: u8) -> Self {
        if index == 31 {
            Self::Sp
        } else {
            Self::Register(index)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PauthInstruction {
    Sign {
        dst: u8,
        modifier: PauthModifier,
        key: PauthKeyKind,
        hint: bool,
    },
    Authenticate {
        dst: u8,
        modifier: PauthModifier,
        key: PauthKeyKind,
        hint: bool,
    },
    Strip {
        dst: u8,
        data: bool,
        hint: bool,
    },
    Generic {
        dst: u8,
        data: u8,
        modifier: PauthModifier,
    },
    Branch {
        target: u8,
        modifier: PauthModifier,
        key_b: bool,
        link: bool,
    },
    Return {
        key_b: bool,
    },
    ExceptionReturn {
        key_b: bool,
    },
    Load {
        dst: u8,
        base: u8,
        offset: i16,
        writeback: bool,
        key_b: bool,
    },
}

impl PauthInstruction {
    /// Decode only legal PAuth forms. Reserved encodings and the selected
    /// WBOVERLAPLD UNDEFINED resolution return `None`; no allocation occurs.
    pub fn decode(raw: u32) -> Option<Self> {
        let rd = (raw & 31) as u8;
        let rn = ((raw >> 5) & 31) as u8;
        if raw & 0xffff_f01f == 0xd503_201f {
            return Self::hint(((raw >> 5) & 127) as u8);
        }
        if raw & 0xffff_0000 == 0xdac1_0000 {
            let opcode = (raw >> 10) & 63;
            if opcode > 17 || (opcode >= 8 && rn != 31) {
                return None;
            }
            if opcode >= 16 {
                return Some(Self::Strip {
                    dst: rd,
                    data: opcode == 17,
                    hint: false,
                });
            }
            let modifier = if opcode & 8 != 0 {
                PauthModifier::Zero
            } else {
                PauthModifier::register_or_sp(rn)
            };
            let key = match opcode & 3 {
                0 => PauthKeyKind::Ia,
                1 => PauthKeyKind::Ib,
                2 => PauthKeyKind::Da,
                _ => PauthKeyKind::Db,
            };
            return Some(if opcode & 4 == 0 {
                Self::Sign {
                    dst: rd,
                    modifier,
                    key,
                    hint: false,
                }
            } else {
                Self::Authenticate {
                    dst: rd,
                    modifier,
                    key,
                    hint: false,
                }
            });
        }
        if raw & 0xffe0_fc00 == 0x9ac0_3000 {
            return Some(Self::Generic {
                dst: rd,
                data: rn,
                modifier: PauthModifier::register_or_sp(((raw >> 16) & 31) as u8),
            });
        }
        if raw & 0xff20_0400 == 0xf820_0400 {
            let writeback = raw & (1 << 11) != 0;
            if writeback && rn == rd && rn != 31 {
                return None;
            }
            let immediate = (((raw >> 22) & 1) << 9) | ((raw >> 12) & 511);
            let offset = (((immediate << 22) as i32 >> 22) * 8) as i16;
            return Some(Self::Load {
                dst: rd,
                base: rn,
                offset,
                writeback,
                key_b: raw & (1 << 23) != 0,
            });
        }
        if raw & 0xfe00_0000 == 0xd600_0000 && (raw >> 16) & 31 == 31 {
            let opcode = (raw >> 21) & 15;
            let op3 = (raw >> 10) & 63;
            if !matches!(op3, 2 | 3) {
                return None;
            }
            let key_b = op3 == 3;
            return match opcode {
                0 | 1 if rd == 31 => Some(Self::Branch {
                    target: rn,
                    modifier: PauthModifier::Zero,
                    key_b,
                    link: opcode == 1,
                }),
                8 | 9 => Some(Self::Branch {
                    target: rn,
                    modifier: PauthModifier::register_or_sp(rd),
                    key_b,
                    link: opcode == 9,
                }),
                2 if rn == 31 && rd == 31 => Some(Self::Return { key_b }),
                4 if rn == 31 && rd == 31 => Some(Self::ExceptionReturn { key_b }),
                _ => None,
            };
        }
        None
    }

    fn hint(immediate: u8) -> Option<Self> {
        let (dst, modifier, key, authenticate) = match immediate {
            7 => {
                return Some(Self::Strip {
                    dst: 30,
                    data: false,
                    hint: true,
                });
            }
            8 => (17, PauthModifier::Register(16), PauthKeyKind::Ia, false),
            10 => (17, PauthModifier::Register(16), PauthKeyKind::Ib, false),
            12 => (17, PauthModifier::Register(16), PauthKeyKind::Ia, true),
            14 => (17, PauthModifier::Register(16), PauthKeyKind::Ib, true),
            24 => (30, PauthModifier::Zero, PauthKeyKind::Ia, false),
            25 => (30, PauthModifier::Sp, PauthKeyKind::Ia, false),
            26 => (30, PauthModifier::Zero, PauthKeyKind::Ib, false),
            27 => (30, PauthModifier::Sp, PauthKeyKind::Ib, false),
            28 => (30, PauthModifier::Zero, PauthKeyKind::Ia, true),
            29 => (30, PauthModifier::Sp, PauthKeyKind::Ia, true),
            30 => (30, PauthModifier::Zero, PauthKeyKind::Ib, true),
            31 => (30, PauthModifier::Sp, PauthKeyKind::Ib, true),
            _ => return None,
        };
        Some(if authenticate {
            Self::Authenticate {
                dst,
                modifier,
                key,
                hint: true,
            }
        } else {
            Self::Sign {
                dst,
                modifier,
                key,
                hint: true,
            }
        })
    }

    pub fn valid_operands(self) -> bool {
        let modifier_valid =
            |modifier| !matches!(modifier, PauthModifier::Register(index) if index >= 31);
        match self {
            Self::Sign {
                dst,
                modifier,
                key,
                hint,
            }
            | Self::Authenticate {
                dst,
                modifier,
                key,
                hint,
            } => {
                dst <= 31
                    && modifier_valid(modifier)
                    && key != PauthKeyKind::Ga
                    && (!hint
                        || (matches!(key, PauthKeyKind::Ia | PauthKeyKind::Ib)
                            && ((dst == 17 && modifier == PauthModifier::Register(16))
                                || (dst == 30
                                    && matches!(
                                        modifier,
                                        PauthModifier::Zero | PauthModifier::Sp
                                    )))))
            }
            Self::Strip { dst, data, hint } => dst <= 31 && (!hint || (dst == 30 && !data)),
            Self::Generic {
                dst,
                data,
                modifier,
            } => {
                dst <= 31
                    && data <= 31
                    && modifier_valid(modifier)
                    && modifier != PauthModifier::Zero
            }
            Self::Branch {
                target, modifier, ..
            } => target <= 31 && modifier_valid(modifier),
            Self::Load {
                dst,
                base,
                offset,
                writeback,
                ..
            } => {
                dst <= 31
                    && base <= 31
                    && (-4096..=4088).contains(&offset)
                    && offset & 7 == 0
                    && !(writeback && dst == base && base != 31)
            }
            Self::Return { .. } | Self::ExceptionReturn { .. } => true,
        }
    }

    pub fn is_hint(self) -> bool {
        matches!(
            self,
            Self::Sign { hint: true, .. }
                | Self::Authenticate { hint: true, .. }
                | Self::Strip { hint: true, .. }
        )
    }

    pub fn is_control_flow(self) -> bool {
        matches!(
            self,
            Self::Branch { .. } | Self::Return { .. } | Self::ExceptionReturn { .. }
        )
    }
}
