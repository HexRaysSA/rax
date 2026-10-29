//! Decode restrictions precede execution-time FP access for these classes.
fn same(word: u32, mask: u32, value: u32) -> bool {
    word & mask == value
}

pub(super) fn reserved(word: u32) -> bool {
    let size = (word >> 22) & 3;
    let q = word & (1 << 30) != 0;
    let u = word & (1 << 29) != 0;
    // Scalar FRINT32/64 accepts S/D; BFCVT fixes its ptype to 01.
    if same(word, 0xff3e_7c00, 0x1e28_4000) {
        return size >= 2;
    }
    if same(word, 0xff3f_fc00, 0x1e23_4000) {
        return size != 1;
    }
    // These scalar AdvSIMD slots do not encode FRINT32/64. FRECPX S/D
    // shares the upper-size, opcode=11111, U=0 slots and remains valid.
    if same(word, 0x9f3f_ec00, 0x1e21_e800) {
        let frecpx = size >= 2 && q && !u && word & (1 << 12) != 0;
        return !frecpx;
    }
    // Vector FRINT32/64: sz_hi=0, with no 64-bit .1D arrangement.
    // FSQRT S/D instead occupies opcode=11111, U=1, sz_hi=1.
    if same(word, 0x9f3f_ec00, 0x0e21_e800) {
        let fsqrt = size >= 2 && u && word & (1 << 12) != 0;
        if fsqrt {
            return size == 3 && !q;
        }
        return size >= 2 || (size == 1 && !q);
    }
    // FCVTN's legacy S/H and D/S forms remain valid; size=10 is BFCVTN.
    if same(word, 0xbf3f_fc00, 0x0e21_6800) {
        return size == 3;
    }
    // Vector three-same-extra families: DotProd, mixed dot, matrix and BF16.
    if same(word, 0x9f20_0000, 0x0e00_0000) {
        let opcode = (word >> 10) & 63;
        match opcode {
            0x25 => return size != 2,
            0x27 => return size != 2 || u,
            0x29 | 0x2b => return size != 2 || !q || (opcode == 0x2b && u),
            0x3f if u => return !matches!(size, 1 | 3),
            0x3b if u => return size != 1 || !q,
            _ => {}
        }
        let multiply = (word >> 13) & 7 == 6 && word & (1 << 10) != 0;
        let add = (word >> 13) & 7 == 7 && (word >> 10) & 3 == 1;
        if u && (multiply || add) {
            return size == 0 || (size == 3 && !q);
        }
    }
    // SDOT/UDOT by element accepts only size=10.
    if same(word, 0x9f00_f400, 0x0f00_e000) {
        return size != 2;
    }
    // FCMLA by element accepts H/S. S requires Q=1,L=0; H has no
    // upper complex pair when Q=0. H also carries the separate FP16 need.
    if same(word, 0xbf00_9400, 0x2f00_1000) {
        return match size {
            1 => word & (1 << 11) != 0 && !q,
            2 => word & (1 << 21) != 0 || !q,
            _ => true,
        };
    }
    false
}
