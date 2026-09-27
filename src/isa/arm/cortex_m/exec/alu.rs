//! Pure data-processing helpers of the Armv7-M pseudocode (Armv7-M ARM,
//! DDI 0403E.e, A2.2 "Pseudocode details of operations on integers" and
//! A5.3.2 "Modified immediate constants in Thumb instructions").

/// A shift type of `DecodeImmShift()` / `Shift_C()`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Shift {
    Lsl,
    Lsr,
    Asr,
    Ror,
    Rrx,
}

impl Shift {
    /// The shift type of a register-controlled shift (`type` field).
    pub(crate) fn from_type(ty: u32) -> Shift {
        match ty & 3 {
            0 => Shift::Lsl,
            1 => Shift::Lsr,
            2 => Shift::Asr,
            _ => Shift::Ror,
        }
    }
}

/// `DecodeImmShift(type, imm5)`: an immediate shift of 0 encodes a 32-bit
/// LSR/ASR, and ROR #0 encodes RRX.
pub(crate) fn decode_imm_shift(ty: u32, imm5: u32) -> (Shift, u32) {
    match ty & 3 {
        0 => (Shift::Lsl, imm5),
        1 => (Shift::Lsr, if imm5 == 0 { 32 } else { imm5 }),
        2 => (Shift::Asr, if imm5 == 0 { 32 } else { imm5 }),
        _ if imm5 == 0 => (Shift::Rrx, 1),
        _ => (Shift::Ror, imm5),
    }
}

/// `Shift_C(value, type, amount, carry_in)` for any `amount`, including
/// register-controlled amounts up to 255.
pub(crate) fn shift_c(value: u32, shift: Shift, amount: u32, carry_in: bool) -> (u32, bool) {
    if amount == 0 {
        return (value, carry_in);
    }
    match shift {
        Shift::Lsl => lsl_c(value, amount),
        Shift::Lsr => lsr_c(value, amount),
        Shift::Asr => asr_c(value, amount),
        Shift::Ror => ror_c(value, amount),
        Shift::Rrx => ((value >> 1) | (u32::from(carry_in) << 31), value & 1 != 0),
    }
}

/// `Shift(value, type, amount, carry_in)`.
pub(crate) fn shift(value: u32, shift: Shift, amount: u32, carry_in: bool) -> u32 {
    shift_c(value, shift, amount, carry_in).0
}

/// `LSL_C(x, n)`, `n > 0`.
fn lsl_c(x: u32, n: u32) -> (u32, bool) {
    let extended = u64::from(x) << n.min(33);
    (extended as u32, (extended >> 32) & 1 != 0)
}

/// `LSR_C(x, n)`, `n > 0`.
fn lsr_c(x: u32, n: u32) -> (u32, bool) {
    if n > 32 {
        return (0, false);
    }
    let carry = (u64::from(x) >> (n - 1)) & 1 != 0;
    ((u64::from(x) >> n) as u32, carry)
}

/// `ASR_C(x, n)`, `n > 0`.
fn asr_c(x: u32, n: u32) -> (u32, bool) {
    let n = n.min(32);
    let extended = i64::from(x as i32);
    ((extended >> n) as u32, (extended >> (n - 1)) & 1 != 0)
}

/// `ROR_C(x, n)`, `n > 0`: the carry is bit 31 of the result.
pub(crate) fn ror_c(x: u32, n: u32) -> (u32, bool) {
    let result = x.rotate_right(n % 32);
    (result, result >> 31 != 0)
}

/// `AddWithCarry(x, y, carry_in)` → (result, carry_out, overflow).
pub(crate) fn add_with_carry(x: u32, y: u32, carry_in: bool) -> (u32, bool, bool) {
    let unsigned_sum = u64::from(x) + u64::from(y) + u64::from(carry_in);
    let signed_sum = i64::from(x as i32) + i64::from(y as i32) + i64::from(carry_in);
    let result = unsigned_sum as u32;
    (
        result,
        u64::from(result) != unsigned_sum,
        i64::from(result as i32) != signed_sum,
    )
}

/// `ThumbExpandImm_C(imm12, carry_in)` → (imm32, carry_out). The
/// replicated forms with a zero byte are UNPREDICTABLE and return `None`.
pub(crate) fn thumb_expand_imm_c(imm12: u32, carry_in: bool) -> Option<(u32, bool)> {
    let imm8 = imm12 & 0xFF;
    if imm12 >> 10 == 0 {
        let imm32 = match (imm12 >> 8) & 3 {
            0 => imm8,
            _ if imm8 == 0 => return None,
            1 => (imm8 << 16) | imm8,
            2 => (imm8 << 24) | (imm8 << 8),
            _ => imm8 * 0x0101_0101,
        };
        Some((imm32, carry_in))
    } else {
        Some(ror_c(0x80 | (imm12 & 0x7F), imm12 >> 7))
    }
}

/// `SignedSatQ(i, n)` for `1 <= n <= 32` → (result, saturated).
pub(crate) fn signed_sat_q(i: i64, n: u32) -> (u32, bool) {
    let max = (1i64 << (n - 1)) - 1;
    let min = -(1i64 << (n - 1));
    if i > max {
        (max as u32, true)
    } else if i < min {
        (min as u32, true)
    } else {
        (i as u32, false)
    }
}

/// `UnsignedSatQ(i, n)` for `0 <= n <= 31` → (result, saturated).
pub(crate) fn unsigned_sat_q(i: i64, n: u32) -> (u32, bool) {
    let max = (1i64 << n) - 1;
    if i > max {
        (max as u32, true)
    } else if i < 0 {
        (0, true)
    } else {
        (i as u32, false)
    }
}

/// Byte-reverses each halfword.
pub(crate) fn rev16(x: u32) -> u32 {
    ((x >> 8) & 0x00FF_00FF) | ((x << 8) & 0xFF00_FF00)
}

/// Byte-reverses the low halfword and sign-extends it.
pub(crate) fn revsh(x: u32) -> u32 {
    (x as u16).swap_bytes() as i16 as i32 as u32
}

#[cfg(test)]
#[path = "alu_tests.rs"]
mod tests;
