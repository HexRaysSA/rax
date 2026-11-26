//! Register and flag effects shared by direct execution and HVF MMIO.
use crate::isa::x86_64::flags::bits;

#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) enum Operation {
    AndNot,
    Extract,
    IsolateLowest,
    MaskThroughLowest,
    ResetLowest,
}

impl Operation {
    pub(crate) fn apply(self, bits: u32, source: u64, other: u64, flags: u64) -> (u64, u64) {
        let mask = u64::MAX >> (64 - bits);
        let source = source & mask;
        let (value, carry) = match self {
            Self::AndNot => (source & !other, false),
            Self::Extract => {
                let start = (other & 0xff) as u32;
                let length = ((other >> 8) & 0xff) as u32;
                let value = if start >= bits || length == 0 {
                    0
                } else {
                    (source >> start) & (u64::MAX >> (64 - length.min(bits)))
                };
                (value, false)
            }
            Self::IsolateLowest => (source & source.wrapping_neg(), source != 0),
            Self::MaskThroughLowest => (source ^ source.wrapping_sub(1), source == 0),
            Self::ResetLowest => (source & source.wrapping_sub(1), source == 0),
        };
        let value = value & mask;
        // Preserve undefined arithmetic flags and all unrelated RFLAGS bits.
        let mut flags = flags & !(bits::OF | bits::CF | bits::ZF);
        if !matches!(self, Self::Extract) {
            flags &= !bits::SF;
            if value & (1 << (bits - 1)) != 0 {
                flags |= bits::SF;
            }
        }
        if value == 0 && !matches!(self, Self::MaskThroughLowest) {
            flags |= bits::ZF;
        }
        if carry {
            flags |= bits::CF;
        }
        (value, flags)
    }
}
