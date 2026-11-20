pub(crate) fn dot<const N: usize>(
    left: [u8; N],
    right: [u8; N],
    (left_signed, right_signed): (bool, bool),
) -> i32 {
    fn extend(byte: u8, signed: bool) -> i32 {
        if signed {
            i32::from(byte as i8)
        } else {
            i32::from(byte)
        }
    }
    left.into_iter()
        .zip(right)
        .map(|(a, b)| extend(a, left_signed) * extend(b, right_signed))
        .sum()
}

/// Arm MatMulAdd packs the rows of the first operand and the columns of
/// the second operand in successive 64-bit halves.
pub(crate) fn matrix_accumulate(
    addend: u128,
    left: u128,
    right: u128,
    signed: (bool, bool),
) -> u128 {
    let rows = [left as u64, (left >> 64) as u64].map(u64::to_le_bytes);
    let columns = [right as u64, (right >> 64) as u64].map(u64::to_le_bytes);
    let mut result = 0;
    for (row, left) in rows.into_iter().enumerate() {
        for (column, right) in columns.into_iter().enumerate() {
            let shift = 32 * (2 * row + column);
            let sum = ((addend >> shift) as u32).wrapping_add_signed(dot(left, right, signed));
            result |= u128::from(sum) << shift;
        }
    }
    result
}
