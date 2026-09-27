//! x87 register encodings shared by the register API and context migration.
//!
//! The engine holds the eight x87 physical registers R0-R7 in the exact
//! 80-bit memory format (Intel SDM Vol. 1 §4.2.2, Figure 4-3): bytes 0-7 are
//! the 64-bit significand including the explicit integer bit J (bit 63), and
//! bytes 8-9 hold the 15-bit biased exponent (bias 16383) with the sign in
//! bit 15.

/// The exact binary80 encoding of the binary64 value `bits`. Every binary64
/// value is representable, so only a signaling NaN changes meaning: it is
/// quieted, as `FLD m64fp` loads it. Mirrors the engine's widening of a
/// binary64 into an x87 register.
pub(crate) fn from_f64_bits(bits: u64) -> [u8; 10] {
    const FRACTION_BITS: u32 = 52;
    let sign = (bits >> 63) as u16;
    let exponent = (bits >> FRACTION_BITS) & 0x7FF;
    let fraction = bits & ((1 << FRACTION_BITS) - 1);
    let (significand, biased): (u64, u16) = if exponent == 0x7FF {
        // Infinity (fraction 0) or NaN; bit 62 is the quiet bit.
        let mut significand = (1 << 63) | (fraction << (63 - FRACTION_BITS));
        if fraction != 0 {
            significand |= 1 << 62;
        }
        (significand, 0x7FFF)
    } else if exponent == 0 {
        if fraction == 0 {
            (0, 0)
        } else {
            // A binary64 subnormal is a normal binary80 value:
            // value = fraction * 2^-1074 = (fraction << (63 - h)) * 2^(h - 1074 - 63),
            // where h is the index of fraction's highest set bit.
            let highest = 63 - fraction.leading_zeros();
            let unbiased = highest as i32 - 1074;
            (fraction << (63 - highest), (unbiased + 16383) as u16)
        }
    } else {
        (
            ((1 << FRACTION_BITS) | fraction) << (63 - FRACTION_BITS),
            (exponent as i32 - 1023 + 16383) as u16,
        )
    };
    let mut raw = [0u8; 10];
    raw[..8].copy_from_slice(&significand.to_le_bytes());
    raw[8..].copy_from_slice(&(biased | (sign << 15)).to_le_bytes());
    raw
}

/// The two-bit FSAVE tag of a nonempty register holding `raw` (Intel SDM
/// Vol. 1 §8.1.7): 0 valid, 1 zero, 2 special (NaN, infinity, denormal, or an
/// unsupported encoding with J clear).
pub(crate) fn tag_of(raw: &[u8; 10]) -> u16 {
    let significand = u64::from_le_bytes(raw[..8].try_into().expect("8 bytes"));
    let exponent = u16::from_le_bytes([raw[8], raw[9]]) & 0x7FFF;
    if exponent == 0 {
        if significand == 0 { 1 } else { 2 }
    } else if exponent == 0x7FFF || significand >> 63 == 0 {
        2
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(significand: u64, sign_exponent: u16) -> [u8; 10] {
        let mut raw = [0u8; 10];
        raw[..8].copy_from_slice(&significand.to_le_bytes());
        raw[8..].copy_from_slice(&sign_exponent.to_le_bytes());
        raw
    }

    // Expected encodings follow from the binary80 definition: value =
    // (-1)^s * 2^(e - 16383) * (J.fraction), with J explicit.
    #[test]
    fn widening_is_exact_for_every_binary64_class() {
        let cases: &[(f64, u64, u16)] = &[
            (1.0, 1 << 63, 0x3FFF),
            (-2.5, 0xA000_0000_0000_0000, 0xC000),
            (0.0, 0, 0),
            (-0.0, 0, 0x8000),
            (f64::INFINITY, 1 << 63, 0x7FFF),
            (f64::NEG_INFINITY, 1 << 63, 0xFFFF),
            (f64::MAX, 0xFFFF_FFFF_FFFF_F800, 0x43FE),
            // 2^-1022, the smallest normal: exponent 16383 - 1022.
            (f64::MIN_POSITIVE, 1 << 63, 0x3C01),
            // 2^-1074, the smallest subnormal: exponent 16383 - 1074 = 0x3BCD.
            (f64::from_bits(1), 1 << 63, 0x3BCD),
            // The largest subnormal, (1 - 2^-52) * 2^-1022.
            (
                f64::from_bits(0x000F_FFFF_FFFF_FFFF),
                0xFFFF_FFFF_FFFF_F000,
                0x3C00,
            ),
        ];
        for &(value, significand, sign_exponent) in cases {
            assert_eq!(
                from_f64_bits(value.to_bits()),
                raw(significand, sign_exponent),
                "{value:e}"
            );
        }
    }

    #[test]
    fn nans_keep_their_payload_and_signaling_nans_are_quieted() {
        // Quiet NaN with payload 0x1234 and the sign set.
        let quiet = 0xFFF8_0000_0000_1234u64;
        assert_eq!(
            from_f64_bits(quiet),
            raw(0xC000_0000_0091_A000, 0xFFFF),
            "payload << 11, quiet bit 62"
        );
        // Signaling NaN 0x7FF0_0000_0000_0001 gains the quiet bit.
        assert_eq!(
            from_f64_bits(0x7FF0_0000_0000_0001),
            raw(0xC000_0000_0000_0800, 0x7FFF)
        );
    }

    #[test]
    fn tags_follow_the_fsave_classification() {
        assert_eq!(tag_of(&from_f64_bits(1.0f64.to_bits())), 0);
        assert_eq!(tag_of(&from_f64_bits(0.0f64.to_bits())), 1);
        assert_eq!(tag_of(&from_f64_bits((-0.0f64).to_bits())), 1);
        assert_eq!(tag_of(&from_f64_bits(f64::INFINITY.to_bits())), 2);
        assert_eq!(tag_of(&from_f64_bits(f64::NAN.to_bits())), 2);
        // A binary80 denormal (exponent 0, nonzero significand).
        assert_eq!(tag_of(&raw(1, 0)), 2);
        // An unnormal (nonzero exponent, J clear) is unsupported: special.
        assert_eq!(tag_of(&raw(0x4000_0000_0000_0000, 0x3FFF)), 2);
        // A binary64 subnormal widens to a normal binary80 value.
        assert_eq!(tag_of(&from_f64_bits(1)), 0);
    }
}
