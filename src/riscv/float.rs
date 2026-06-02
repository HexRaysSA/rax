//! IEEE-754 floating-point support for the F and D extensions.
//!
//! Rounding-mode plumbing and the accrued-exception flag bits live here; the
//! arithmetic itself is filled in by the F/D phase. The RISC-V FP model keeps
//! all five rounding modes plus the `fflags` accrued-exception bits inside the
//! `fcsr` CSR, which the CPU owns.

/// RISC-V floating-point rounding modes (`frm` field, also the instruction
/// `rm` field; `Dyn` selects the CSR `frm`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoundingMode {
    /// Round to nearest, ties to even.
    Rne,
    /// Round towards zero.
    Rtz,
    /// Round down (towards -inf).
    Rdn,
    /// Round up (towards +inf).
    Rup,
    /// Round to nearest, ties to max magnitude.
    Rmm,
    /// Use the dynamic rounding mode from `fcsr.frm`.
    Dyn,
}

impl RoundingMode {
    /// Decode a 3-bit rounding-mode field.
    pub fn from_bits(bits: u8) -> Option<RoundingMode> {
        Some(match bits & 0x7 {
            0 => RoundingMode::Rne,
            1 => RoundingMode::Rtz,
            2 => RoundingMode::Rdn,
            3 => RoundingMode::Rup,
            4 => RoundingMode::Rmm,
            7 => RoundingMode::Dyn,
            _ => return None, // 5,6 reserved
        })
    }
}

/// Accrued floating-point exception flag bits (`fcsr.fflags`).
pub mod fflags {
    /// Inexact.
    pub const NX: u32 = 0x01;
    /// Underflow.
    pub const UF: u32 = 0x02;
    /// Overflow.
    pub const OF: u32 = 0x04;
    /// Divide by zero.
    pub const DZ: u32 = 0x08;
    /// Invalid operation.
    pub const NV: u32 = 0x10;
}

/// Canonical quiet NaN bit patterns.
pub const CANONICAL_NAN_F32: u32 = 0x7fc0_0000;
/// Canonical quiet NaN for double precision.
pub const CANONICAL_NAN_F64: u64 = 0x7ff8_0000_0000_0000;
