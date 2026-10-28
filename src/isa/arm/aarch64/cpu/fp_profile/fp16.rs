//! Optional FP16 arithmetic encodings, excluding legacy half conversions/storage.

include!("fp16_encodings.rs");

pub(super) fn required(instruction: u32) -> bool {
    matches!((instruction >> 25) & 15, 7 | 15)
        && REQUIRES_FP16
            .iter()
            .any(|&(mask, value)| instruction & mask == value)
}
