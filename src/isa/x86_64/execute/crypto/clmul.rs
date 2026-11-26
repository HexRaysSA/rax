//! Unsigned polynomial products over GF(2) used by x86 carry-less multiply.

pub(crate) fn qword(a: u64, b: u64) -> [u8; 16] {
    let mut lo = 0u64;
    let mut hi = 0u64;
    for i in 0..64 {
        if (b >> i) & 1 != 0 {
            if i == 0 {
                lo ^= a;
            } else {
                lo ^= a << i;
                hi ^= a >> (64 - i);
            }
        }
    }

    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&lo.to_le_bytes());
    out[8..].copy_from_slice(&hi.to_le_bytes());
    out
}
