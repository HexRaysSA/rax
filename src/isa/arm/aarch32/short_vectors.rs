//! Optional VFP short vectors: Arm DDI0406C.d D11.1-4, Tables D11-1/2.
//!
//! Only the fourteen listed F32/F64 forms depend on these controls. Invalid
//! iteration shapes choose Undefined before access checks or data effects.
use super::vfp::VfpState;
use crate::isa::arm::decoder::{Aarch32Decoder, DecodedInsn, Mnemonic, ThumbDecoder};

pub(crate) const CONTROL_MASK: u32 = 0x0037_0000;
#[derive(Clone, Copy)]
enum Shape {
    Binary,
    Unary,
    Immediate,
}

pub(crate) struct Plan {
    pub(crate) iterations: u8,
    raw: u32,
    double: bool,
    shape: Shape,
    stride: u8,
    d: u8,
    n: u8,
    m: u8,
}
fn scalar(register: u8, double: bool) -> bool {
    register & (if double { 12 } else { 24 }) == 0
}
fn register(raw: u32, shift: u32, high: u32, double: bool) -> u8 {
    let low = (raw >> shift) & 15;
    let bit = (raw >> high) & 1;
    if double {
        (low | (bit << 4)) as u8
    } else {
        ((low << 1) | bit) as u8
    }
}
fn insert(raw: u32, register: u8, shift: u32, high: u32, double: bool) -> u32 {
    let value = u32::from(register);
    let (low, bit) = if double {
        (value & 15, value >> 4)
    } else {
        (value >> 1, value & 1)
    };
    (raw & !((15 << shift) | (1 << high))) | (low << shift) | (bit << high)
}
impl Plan {
    fn advance(&self, register: u8, iteration: u8) -> u8 {
        let mask = if self.double { 3 } else { 7 };
        (register & !mask) | ((register + iteration * self.stride) & mask)
    }
    pub(crate) fn instruction(&self, original: &DecodedInsn, iteration: u8) -> DecodedInsn {
        let mut raw = insert(
            self.raw,
            self.advance(self.d, iteration),
            12,
            22,
            self.double,
        );
        if matches!(self.shape, Shape::Binary) {
            // Table D11-2: the first operand advances even from a scalar bank.
            raw = insert(raw, self.advance(self.n, iteration), 16, 7, self.double);
        }
        if !matches!(self.shape, Shape::Immediate) {
            let m = if scalar(self.m, self.double) {
                self.m
            } else {
                self.advance(self.m, iteration)
            };
            raw = insert(raw, m, 0, 5, self.double);
        }
        DecodedInsn {
            raw,
            ..original.clone()
        }
    }
}

/// None leaves the scalar/independent instruction on its existing dispatch path.
/// A reserved capability is denied only for the affected legacy scalar forms.
pub(crate) fn plan(insn: &DecodedInsn, state: &VfpState) -> Result<Option<Plan>, ()> {
    let capability = (state.mvfr0 >> 24) & 15;
    let controls = state.fpscr.bits() & CONTROL_MASK;
    if capability == 0 || capability == 1 && controls == 0 {
        return Ok(None);
    }
    let raw = if insn.state.is_thumb() {
        ThumbDecoder::a32_equivalent(insn.raw).unwrap_or(insn.raw)
    } else {
        insn.raw
    };
    // Exclude Advanced SIMD, core transfers, half data and memory/system forms.
    if raw & 0x0f00_0010 != 0x0e00_0000 || !matches!((raw >> 8) & 15, 10 | 11) {
        return Ok(None);
    }
    if !Aarch32Decoder::decode(raw).is_ok_and(|decoded| decoded.mnemonic == insn.mnemonic) {
        return Ok(None);
    }
    let shape = match insn.mnemonic {
        Mnemonic::VADD
        | Mnemonic::VSUB
        | Mnemonic::VMUL
        | Mnemonic::VDIV
        | Mnemonic::VMLA
        | Mnemonic::VMLS
        | Mnemonic::VNMLA
        | Mnemonic::VNMLS
        | Mnemonic::VNMUL => Shape::Binary,
        Mnemonic::VABS | Mnemonic::VNEG | Mnemonic::VSQRT => Shape::Unary,
        Mnemonic::VMOV if raw & (1 << 6) == 0 => Shape::Immediate,
        Mnemonic::VMOV => Shape::Unary,
        // DDI0406C.d A8 VFMA/VFMS/VFNMA/VFNMS require scalar controls.
        Mnemonic::VFMA | Mnemonic::VFMS | Mnemonic::VFNMA | Mnemonic::VFNMS
            if capability == 1 && controls != 0 =>
        {
            return Err(());
        }
        _ => return Ok(None),
    };
    if capability != 1 {
        return Err(());
    }
    let length = ((controls >> 16) & 7) as u8 + 1;
    let stride = match (controls >> 20) & 3 {
        0 => 1,
        3 if (2..=4).contains(&length) => 2,
        _ => return Err(()),
    };
    let double = (raw >> 8) & 15 == 11;
    let d = register(raw, 12, 22, double);
    if scalar(d, double) {
        return Ok(None);
    }
    if double && (length > 4 || stride == 2 && length > 2) {
        return Err(());
    }
    Ok(Some(Plan {
        iterations: length,
        raw,
        double,
        shape,
        stride,
        d,
        n: register(raw, 16, 7, double),
        m: register(raw, 0, 5, double),
    }))
}
