//! Arm DDI0597 VSDOT and VUDOT A1/T1 encodings.
use super::{Aarch32Decoder, Mnemonic};

pub(crate) struct DotProductFields {
    pub mnemonic: Mnemonic,
    pub d: u8,
    pub n: u8,
    pub m: u8,
    pub registers: u8,
    pub index: Option<u8>,
}

impl Aarch32Decoder {
    /// None denotes another encoding class. Err denotes a misaligned Q register.
    pub(crate) fn dot_product_fields(raw: u32) -> Option<Result<DotProductFields, ()>> {
        if raw & 0xfdb0_0f00 != 0xfc20_0d00 {
            return None;
        }

        let indexed = raw & (1 << 25) != 0;
        let q = ((raw >> 6) & 1) as u8;
        let d = (((raw >> 18) & 16) | ((raw >> 12) & 15)) as u8;
        let n = (((raw >> 3) & 16) | ((raw >> 16) & 15)) as u8;
        let vm = (raw & 15) as u8;
        if q != 0 && (d | n | if indexed { 0 } else { vm }) & 1 != 0 {
            return Some(Err(()));
        }

        let m_high = ((raw >> 5) & 1) as u8;
        let (m, index) = if indexed {
            (vm, Some(m_high))
        } else {
            (vm | (m_high << 4), None)
        };
        Some(Ok(DotProductFields {
            mnemonic: if raw & (1 << 4) == 0 {
                Mnemonic::VSDOT
            } else {
                Mnemonic::VUDOT
            },
            d,
            n,
            m,
            registers: 1 + q,
            index,
        }))
    }
}
