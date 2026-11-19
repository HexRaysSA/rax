/// The low result and signed overflow of a truncated IMUL product.
pub(crate) fn truncated_product(left: u64, right: u64, size: u8) -> (u64, bool) {
    match size {
        2 => {
            let product = i32::from(left as i16) * i32::from(right as i16);
            (u64::from(product as u16), i16::try_from(product).is_err())
        }
        4 => {
            let product = i64::from(left as i32) * i64::from(right as i32);
            (u64::from(product as u32), i32::try_from(product).is_err())
        }
        8 => {
            let product = i128::from(left as i64) * i128::from(right as i64);
            (product as u64, i64::try_from(product).is_err())
        }
        _ => (left.wrapping_mul(right), false),
    }
}
