//! Architected QARMA pointer-authentication primitive.
//!
//! Arm A64 XML 2025-12, shared pseudocode `ComputePACQARMA` and its cell
//! transformations. This primitive does not insert a PAC into an address or
//! enforce instruction permissions. Callers must apply those architectural rules.

#[path = "pauth/architecture.rs"]
mod architecture;
pub use architecture::*;

/// Architected cryptographic algorithm used to compute a 64-bit PAC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PauthAlgorithm {
    Qarma3,
    Qarma5,
}

/// A 128-bit architectural key. Hi is Arm pseudocode key0; Lo is key1.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PauthKey {
    pub lo: u64,
    pub hi: u64,
}

/// Architectural authentication-failure profile, independent of key selection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PauthProfile {
    Base,
    Pauth2,
    Fpac,
    #[default]
    FpacCombine,
}

/// A failed authentication that must raise the architectural PAC exception.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PauthFailure {
    pub data: bool,
    pub key_b: bool,
}

/// Validated layout for one effective translation regime and address range.
/// Resolve TBI/TBID and address-range selection before constructing this value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PauthAddressLayout {
    address_bits: u8,
    top_byte_ignore: bool,
}

impl PauthAddressLayout {
    /// Supported address widths are 16 through 52 bits. Larger-address
    /// extensions require their own PAC-placement rules and are rejected.
    pub fn new(address_bits: u8, top_byte_ignore: bool) -> Option<Self> {
        (16..=52).contains(&address_bits).then_some(Self {
            address_bits,
            top_byte_ignore,
        })
    }

    fn extension_mask(self) -> u64 {
        let upper = if self.top_byte_ignore {
            0x00ff_ffff_ffff_ffff
        } else {
            u64::MAX
        };
        upper & (u64::MAX << self.address_bits)
    }

    fn pac_mask(self) -> u64 {
        self.extension_mask() & !(1 << 55)
    }

    /// Restore extension bits from pointer bit 55, preserving any ignored tag.
    pub fn strip(self, pointer: u64) -> u64 {
        let mask = self.extension_mask();
        if pointer & (1 << 55) != 0 {
            pointer | mask
        } else {
            pointer & !mask
        }
    }

    /// Sign a pointer. Key enablement and privilege checks belong to the
    /// architectural instruction layer and must precede this primitive.
    pub fn sign(
        self,
        algorithm: PauthAlgorithm,
        profile: PauthProfile,
        pointer: u64,
        modifier: u64,
        key: PauthKey,
    ) -> u64 {
        let top_bit = if self.top_byte_ignore { 55 } else { 63 };
        let extension = if pointer & (1 << top_bit) != 0 {
            u64::MAX
        } else {
            0
        };
        let mask = self.extension_mask();
        let extended = (pointer & !mask) | (extension & mask);
        let mut pac = algorithm.compute(extended, modifier, key);
        let supplied_extension = pointer & mask;
        if profile == PauthProfile::Base && supplied_extension != 0 && supplied_extension != mask {
            pac ^= 1 << (top_bit - 1);
        }
        if profile != PauthProfile::Base {
            pac ^= pointer;
        }
        let result = if self.top_byte_ignore {
            pointer & !mask
        } else {
            pointer & ((1 << self.address_bits) - 1)
        };
        result | (pac & self.pac_mask()) | (extension & (1 << 55))
    }

    /// Authenticate a pointer, distinguishing standalone AUT from combined
    /// branch/load authentication. Does not mutate architectural state.
    pub fn authenticate(
        self,
        algorithm: PauthAlgorithm,
        profile: PauthProfile,
        pointer: u64,
        modifier: u64,
        key: PauthKey,
        failure: PauthFailure,
        combined: bool,
    ) -> Result<u64, PauthFailure> {
        let original = self.strip(pointer);
        let pac = algorithm.compute(original, modifier, key);
        let mask = self.pac_mask();
        if profile == PauthProfile::Base {
            if (pac ^ pointer) & mask == 0 {
                return Ok(original);
            }
            let shift = if self.top_byte_ignore { 53 } else { 61 };
            let error_code = if failure.key_b { 2 } else { 1 };
            return Ok((original & !(3 << shift)) | (error_code << shift));
        }
        let result = pointer ^ (pac & mask);
        let extension = if result & (1 << 55) != 0 { u64::MAX } else { 0 };
        let faulting = match profile {
            PauthProfile::FpacCombine => true,
            PauthProfile::Fpac => !combined,
            _ => false,
        };
        if faulting && (result ^ extension) & mask != 0 {
            Err(failure)
        } else {
            Ok(result)
        }
    }
}

const SHUFFLE: [u8; 16] = [13, 6, 11, 0, 7, 12, 1, 10, 8, 3, 14, 5, 2, 9, 4, 15];
const INV_SHUFFLE: [u8; 16] = [3, 6, 12, 9, 14, 11, 1, 4, 8, 13, 7, 2, 5, 0, 10, 15];
const SUB: [u8; 16] = [11, 6, 8, 15, 12, 0, 9, 14, 3, 7, 4, 5, 13, 2, 1, 10];
const INV_SUB: [u8; 16] = [5, 14, 13, 8, 10, 11, 1, 9, 2, 6, 15, 0, 4, 12, 7, 3];
const SUB1: [u8; 16] = [10, 13, 14, 6, 15, 7, 3, 5, 9, 8, 0, 12, 11, 1, 2, 4];
const TWEAK: [u8; 16] = [4, 5, 6, 7, 11, 2, 3, 8, 12, 13, 14, 15, 0, 1, 10, 9];
const INV_TWEAK: [u8; 16] = [12, 13, 5, 6, 0, 1, 2, 3, 7, 15, 14, 4, 8, 9, 10, 11];
const RC: [u64; 5] = [
    0x0000_0000_0000_0000,
    0x1319_8a2e_0370_7344,
    0xa409_3822_299f_31d0,
    0x082e_fa98_ec4e_6c89,
    0x4528_21e6_38d0_1377,
];

fn cell(value: u64, index: usize) -> u64 {
    (value >> (index * 4)) & 15
}

fn permute(value: u64, indices: &[u8; 16]) -> u64 {
    let mut result = 0;
    for (destination, &source) in indices.iter().enumerate() {
        result |= cell(value, usize::from(source)) << (destination * 4);
    }
    result
}

fn substitute(value: u64, table: &[u8; 16]) -> u64 {
    let mut result = 0;
    for index in 0..16 {
        result |= u64::from(table[cell(value, index) as usize]) << (index * 4);
    }
    result
}

fn rotate_cell(value: u64, shift: u32) -> u64 {
    ((value << shift) | (value >> (4 - shift))) & 15
}

fn multiply(value: u64) -> u64 {
    let mut result = 0;
    for index in 0..4 {
        let a = cell(value, index);
        let b = cell(value, index + 4);
        let c = cell(value, index + 8);
        let d = cell(value, index + 12);
        let t0 = rotate_cell(c, 1) ^ rotate_cell(b, 2) ^ rotate_cell(a, 1);
        let t1 = rotate_cell(d, 1) ^ rotate_cell(b, 1) ^ rotate_cell(a, 2);
        let t2 = rotate_cell(d, 2) ^ rotate_cell(c, 1) ^ rotate_cell(a, 1);
        let t3 = rotate_cell(d, 1) ^ rotate_cell(c, 2) ^ rotate_cell(b, 1);
        result |= t3 << (index * 4);
        result |= t2 << ((index + 4) * 4);
        result |= t1 << ((index + 8) * 4);
        result |= t0 << ((index + 12) * 4);
    }
    result
}

fn tweak(value: u64, inverse: bool) -> u64 {
    let mut result = 0;
    let indices = if inverse { &INV_TWEAK } else { &TWEAK };
    for (index, &source) in indices.iter().enumerate() {
        let mut nibble = cell(value, usize::from(source));
        let rotate = if inverse {
            matches!(index, 0 | 6 | 8 | 9 | 10 | 11 | 15)
        } else {
            matches!(index, 2 | 4 | 7 | 11 | 12 | 14 | 15)
        };
        if rotate {
            nibble = if inverse {
                ((nibble << 1) & 15) | ((nibble ^ (nibble >> 3)) & 1)
            } else {
                (nibble >> 1) | (((nibble ^ (nibble >> 1)) & 1) << 3)
            };
        }
        result |= nibble << (index * 4);
    }
    result
}

impl PauthAlgorithm {
    /// Compute the full 64-bit primitive, before architectural PAC placement.
    /// Time and auxiliary space are O(1), for fixed 64-bit inputs and 3/5 rounds.
    pub fn compute(self, data: u64, modifier: u64, key: PauthKey) -> u64 {
        let rounds = match self {
            Self::Qarma3 => 3,
            Self::Qarma5 => 5,
        };
        let forward = if self == Self::Qarma3 { &SUB1 } else { &SUB };
        let backward = if self == Self::Qarma3 {
            &SUB1
        } else {
            &INV_SUB
        };
        let modified_key = key.hi.rotate_right(1) ^ (key.hi >> 63);
        let mut running_modifier = modifier;
        let mut value = data ^ key.hi;
        for (index, &constant) in RC.iter().take(rounds).enumerate() {
            value ^= key.lo ^ running_modifier ^ constant;
            if index != 0 {
                value = multiply(permute(value, &SHUFFLE));
            }
            value = substitute(value, forward);
            running_modifier = tweak(running_modifier, false);
        }
        value ^= modified_key ^ running_modifier;
        value = substitute(multiply(permute(value, &SHUFFLE)), forward);
        value = multiply(permute(value, &SHUFFLE)) ^ key.lo;
        value = substitute(permute(value, &INV_SHUFFLE), backward);
        value = permute(multiply(value), &INV_SHUFFLE) ^ key.hi ^ running_modifier;
        for index in 0..rounds {
            value = substitute(value, backward);
            if index + 1 != rounds {
                value = permute(multiply(value), &INV_SHUFFLE);
            }
            running_modifier = tweak(running_modifier, true);
            value ^= RC[rounds - 1 - index] ^ key.lo ^ running_modifier ^ 0xc0ac_29b7_c97c_50dd;
        }
        value ^ modified_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_layout_profiles_roundtrip_and_fail_as_specified() {
        let key = PauthKey {
            lo: 0x0123_4567_89ab_cdef,
            hi: 0xfedc_ba98_7654_3210,
        };
        for algorithm in [PauthAlgorithm::Qarma3, PauthAlgorithm::Qarma5] {
            for profile in [
                PauthProfile::Base,
                PauthProfile::Pauth2,
                PauthProfile::Fpac,
                PauthProfile::FpacCombine,
            ] {
                for bits in [16, 32, 48, 52] {
                    for tbi in [false, true] {
                        let layout = PauthAddressLayout::new(bits, tbi).unwrap();
                        for pointer in [0x1230, u64::MAX - 15] {
                            let pointer = if tbi {
                                (pointer & 0x00ff_ffff_ffff_ffff) | 0xab00_0000_0000_0000
                            } else {
                                pointer
                            };
                            for key_b in [false, true] {
                                let failure = PauthFailure { data: false, key_b };
                                let signed = layout.sign(algorithm, profile, pointer, 7, key);
                                assert_eq!(
                                    layout.authenticate(
                                        algorithm, profile, signed, 7, key, failure, false
                                    ),
                                    Ok(pointer),
                                    "{algorithm:?} {profile:?} {bits} {tbi}"
                                );
                                assert_eq!(layout.strip(signed), pointer);
                                let corrupted = signed ^ (1 << bits);
                                for combined in [false, true] {
                                    let result = layout.authenticate(
                                        algorithm, profile, corrupted, 7, key, failure, combined,
                                    );
                                    let should_fault = profile == PauthProfile::FpacCombine
                                        || (profile == PauthProfile::Fpac && !combined);
                                    if should_fault {
                                        assert_eq!(result, Err(failure));
                                    } else {
                                        assert_ne!(result.unwrap(), pointer);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        for bits in [0, 15, 53, 55, 63, 64, 255] {
            assert!(PauthAddressLayout::new(bits, false).is_none());
        }
    }

    #[test]
    fn cell_transformations_are_invertible() {
        for index in 0..16 {
            for nibble in 0..16u64 {
                let value = nibble << (index * 4);
                assert_eq!(permute(permute(value, &SHUFFLE), &INV_SHUFFLE), value);
                assert_eq!(tweak(tweak(value, false), true), value);
                assert_eq!(substitute(substitute(value, &SUB), &INV_SUB), value);
            }
        }
    }

    #[test]
    fn architected_qarma_matches_qemu_vectors() {
        // Independently executed QEMU v10.1.0 primitive; provenance under
        // docs/specifications/arm/pauth/. Both key halves remain observable.
        let values = [0, 1, u64::MAX, 0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210];
        let expected = [
            (
                PauthAlgorithm::Qarma5,
                [
                    0xf996_e761_1815_2f52,
                    0xee61_2f38_5909_4bed,
                    0xd846_298b_f877_365e,
                    0x1ff1_153f_f358_952b,
                    0x76c4_954b_6c87_a4e7,
                ],
            ),
            (
                PauthAlgorithm::Qarma3,
                [
                    0xa02d_2cde_41c3_b717,
                    0x7de9_0f93_0898_8f39,
                    0x4e06_1aa8_4821_78bb,
                    0xe92e_ca3c_0855_5416,
                    0x661b_7663_3c14_1f8f,
                ],
            ),
        ];
        for (algorithm, outputs) in expected {
            for (index, expected) in outputs.into_iter().enumerate() {
                let key = PauthKey {
                    lo: values[(index + 2) % 5],
                    hi: values[(index + 3) % 5],
                };
                assert_eq!(
                    algorithm.compute(values[index], values[(index + 1) % 5], key),
                    expected,
                    "{algorithm:?} case {index}"
                );
            }
        }
    }
}
