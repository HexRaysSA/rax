//! Arm DDI0597 VCADD and VCMLA A1/T1 fields and register constraints.
use super::{Aarch32Decoder, Mnemonic};

pub(crate) struct ComplexSimdFields {
    pub mnemonic: Mnemonic,
    pub element_bits: u8,
    pub d: u8,
    pub n: u8,
    pub m: u8,
    pub registers: u8,
    pub rotation: u8,
    pub index: Option<u8>,
}

impl Aarch32Decoder {
    /// None means another encoding class. Err means an allocated but
    /// undefined register selection. A32 and T32 use the same bit positions.
    pub(crate) fn complex_simd_fields(raw: u32) -> Option<Result<ComplexSimdFields, ()>> {
        let (mnemonic, rotation, size_bit, indexed) = if raw & 0xfea0_0f10 == 0xfc80_0800 {
            (Mnemonic::VCADD, 1 + 2 * ((raw >> 24) & 1), 20, false)
        } else if raw & 0xfe20_0f10 == 0xfc20_0800 {
            (Mnemonic::VCMLA, (raw >> 23) & 3, 20, false)
        } else if raw & 0xff00_0f10 == 0xfe00_0800 {
            (Mnemonic::VCMLA, (raw >> 20) & 3, 23, true)
        } else {
            return None;
        };
        let q = ((raw >> 6) & 1) as u8;
        let d = (((raw >> 18) & 16) | ((raw >> 12) & 15)) as u8;
        let n = (((raw >> 3) & 16) | ((raw >> 16) & 15)) as u8;
        let vm = (raw & 15) as u8;
        if q != 0 && (d | n | if indexed { 0 } else { vm }) & 1 != 0 {
            return Some(Err(()));
        }
        let element_bits = 16 << ((raw >> size_bit) & 1);
        let m_high = ((raw >> 5) & 1) as u8;
        let (m, index) = if indexed && element_bits == 16 {
            (vm, Some(m_high))
        } else {
            (vm | (m_high << 4), indexed.then_some(0))
        };
        Some(Ok(ComplexSimdFields {
            mnemonic,
            element_bits,
            d,
            n,
            m,
            registers: 1 + q,
            rotation: rotation as u8,
            index,
        }))
    }
}
