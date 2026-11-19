//! FEAT_AA32BF16 A1/T1 allocations and operand fields (Arm DDI0597).
use super::{Aarch32Decoder, Mnemonic};

pub(crate) enum BfloatFields {
    ScalarConvert {
        d: u8,
        m: u8,
        top: bool,
    },
    VectorConvert {
        d: u8,
        m: u8,
    },
    Dot {
        d: u8,
        n: u8,
        m: u8,
        registers: u8,
        index: Option<u8>,
    },
    Matrix {
        d: u8,
        n: u8,
        m: u8,
    },
    WideningFma {
        d: u8,
        n: u8,
        m: u8,
        index: Option<u8>,
        top: bool,
    },
}

impl BfloatFields {
    pub(crate) fn mnemonic(&self) -> Mnemonic {
        match self {
            Self::ScalarConvert { top: false, .. } => Mnemonic::VCVTB_BF16_F32,
            Self::ScalarConvert { top: true, .. } => Mnemonic::VCVTT_BF16_F32,
            Self::VectorConvert { .. } => Mnemonic::VCVT_BF16_F32,
            Self::Dot { .. } => Mnemonic::VDOT_BF16,
            Self::Matrix { .. } => Mnemonic::VMMLA_BF16,
            Self::WideningFma { top: false, .. } => Mnemonic::VFMAB_BF16,
            Self::WideningFma { top: true, .. } => Mnemonic::VFMAT_BF16,
        }
    }
}

impl Aarch32Decoder {
    /// None denotes another allocation. Err denotes an invalid Q operand.
    pub(crate) fn bfloat_fields(raw: u32) -> Option<Result<BfloatFields, ()>> {
        let vd = ((raw >> 12) & 15) as u8;
        let vm = (raw & 15) as u8;
        let d_high = ((raw >> 22) & 1) as u8;
        let m_high = ((raw >> 5) & 1) as u8;
        if raw >> 28 != 15 {
            return (raw & 0x0fbf_0f50 == 0x0eb3_0940).then_some(Ok(BfloatFields::ScalarConvert {
                d: (vd << 1) | d_high,
                m: (vm << 1) | m_high,
                top: raw & (1 << 7) != 0,
            }));
        }

        let d = vd | (d_high << 4);
        let m = vm | (m_high << 4);
        if raw & 0xffbf_0fd0 == 0xf3b6_0640 {
            return Some(if m & 1 == 0 {
                Ok(BfloatFields::VectorConvert { d, m })
            } else {
                Err(())
            });
        }

        let n = (((raw >> 3) & 16) | ((raw >> 16) & 15)) as u8;
        let indexed = raw & (1 << 25) != 0;
        let q = raw & (1 << 6) != 0;
        let pair_operands = d | n | if indexed { 0 } else { m };
        let fields = if raw & 0xfdb0_0f10 == 0xfc00_0d00 {
            if q && pair_operands & 1 != 0 {
                return Some(Err(()));
            }
            BfloatFields::Dot {
                d,
                n,
                m: if indexed { vm } else { m },
                registers: 1 + u8::from(q),
                index: indexed.then_some(m_high),
            }
        } else if raw & 0xffb0_0f50 == 0xfc00_0c40 {
            if (d | n | m) & 1 != 0 {
                return Some(Err(()));
            }
            BfloatFields::Matrix { d, n, m }
        } else if raw & 0xfdb0_0f10 == 0xfc30_0810 {
            if pair_operands & 1 != 0 {
                return Some(Err(()));
            }
            BfloatFields::WideningFma {
                d,
                n,
                m: if indexed { vm & 7 } else { m },
                index: indexed.then_some((m_high << 1) | (vm >> 3)),
                top: q,
            }
        } else {
            return None;
        };
        Some(Ok(fields))
    }
}
