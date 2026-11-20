//! Arm DDI0597 AdvSIMD integer dot and matrix product A1/T1 encodings.
use super::{Aarch32Decoder, Mnemonic};

pub(crate) enum ProductShape {
    Dot { registers: u8, index: Option<u8> },
    Matrix,
}

pub(crate) struct Int8ProductFields {
    pub mnemonic: Mnemonic,
    pub d: u8,
    pub n: u8,
    pub m: u8,
    pub shape: ProductShape,
}

impl Aarch32Decoder {
    /// None denotes another encoding class. Err denotes a reserved form.
    pub(crate) fn int8_product_fields(raw: u32) -> Option<Result<Int8ProductFields, ()>> {
        let alternate = raw & (1 << 23) != 0;
        let u = raw & (1 << 4) != 0;
        let d = (((raw >> 18) & 16) | ((raw >> 12) & 15)) as u8;
        let n = (((raw >> 3) & 16) | ((raw >> 16) & 15)) as u8;
        let m_low = (raw & 15) as u8;
        let m_high = ((raw >> 5) & 1) as u8;
        if raw & 0xff30_0f40 == 0xfc20_0c40 {
            let mnemonic = match (alternate, u) {
                (false, false) => Mnemonic::VSMMLA,
                (false, true) => Mnemonic::VUMMLA,
                (true, false) => Mnemonic::VUSMMLA,
                (true, true) => return Some(Err(())),
            };
            let m = m_low | (m_high << 4);
            return Some(if (d | n | m) & 1 != 0 {
                Err(())
            } else {
                Ok(Int8ProductFields {
                    mnemonic,
                    d,
                    n,
                    m,
                    shape: ProductShape::Matrix,
                })
            });
        }

        let mnemonic = if raw & 0xfdb0_0f00 == 0xfc20_0d00 {
            if u { Mnemonic::VUDOT } else { Mnemonic::VSDOT }
        } else if raw & 0xffb0_0f10 == 0xfca0_0d00 {
            Mnemonic::VUSDOT
        } else if raw & 0xffb0_0f00 == 0xfe80_0d00 {
            if u {
                Mnemonic::VSUDOT
            } else {
                Mnemonic::VUSDOT
            }
        } else {
            return None;
        };
        let indexed = raw & (1 << 25) != 0;
        let q = ((raw >> 6) & 1) as u8;
        if q != 0 && (d | n | if indexed { 0 } else { m_low }) & 1 != 0 {
            return Some(Err(()));
        }
        let (m, index) = if indexed {
            (m_low, Some(m_high))
        } else {
            (m_low | (m_high << 4), None)
        };
        Some(Ok(Int8ProductFields {
            mnemonic,
            d,
            n,
            m,
            shape: ProductShape::Dot {
                registers: 1 + q,
                index,
            },
        }))
    }
}
