//! Shared packed-shuffle encodings and expected device replies.
pub(super) const FORMS: [(&str, &[u8], usize); 5] = [
    ("legacy", &[0x66, 0x44, 0x0f, 0x38, 0x00, 0x3f], 16),
    ("vex128-w0", &[0xc4, 0x62, 0x39, 0x00, 0x7f, 3], 16),
    ("vex128-w1", &[0xc4, 0x62, 0xb9, 0x00, 0x7f, 3], 16),
    ("vex256-w0", &[0xc4, 0x62, 0x3d, 0x00, 0x7f, 3], 32),
    ("vex256-w1", &[0xc4, 0x62, 0xbd, 0x00, 0x7f, 3], 32),
];

pub(super) const CONTROL: [u8; 32] = [
    0x0f, 0x20, 0x81, 0x73, 0xf4, 0x05, 0x6e, 0x07, 0x18, 0x89, 0x3a, 0x0b, 0x8c, 0x4d, 0x02, 0xff,
    0x01, 0x90, 0x2f, 0x3e, 0x45, 0xb4, 0x67, 0x38, 0x8e, 0x3a, 0xf1, 0x03, 0x77, 0x0c, 0x4d, 0x2e,
];

pub(super) const EXPECTED: [u8; 32] = [
    0x4f, 0x40, 0, 0x43, 0, 0x45, 0x4e, 0x47, 0x48, 0, 0x4a, 0x4b, 0, 0x4d, 0x42, 0, 0x51, 0, 0x5f,
    0x5e, 0x55, 0, 0x57, 0x58, 0, 0x5a, 0, 0x53, 0x57, 0x5c, 0x5d, 0x5e,
];

pub(super) fn source() -> [u8; 32] {
    std::array::from_fn(|index| 0x40 + index as u8)
}

pub(super) struct ImmediateCase {
    pub(super) mnemonic: &'static str,
    pub(super) encoding: &'static str,
    pub(super) code: Vec<u8>,
    pub(super) width: usize,
    pub(super) expected: [u8; 32],
}

pub(super) fn immediate_reply() -> [u8; 32] {
    std::array::from_fn(|index| 0x80 + index as u8)
}

pub(super) const PERMUTE_HALVES: [(&str, u8); 2] = [("vperm2f128", 0x06), ("vperm2i128", 0x46)];

pub(super) fn permute_halves_code(opcode: u8, control: u8) -> [u8; 7] {
    [0xc4, 0x63, 0x3d, opcode, 0x7f, 3, control]
}

pub(super) fn permute_halves_expected(control: u8) -> [u8; 32] {
    let mut output = [0; 32];
    let left = source();
    let right = immediate_reply();
    let halves = [&left[..16], &left[16..], &right[..16], &right[16..]];
    for (half, selector) in output
        .chunks_exact_mut(16)
        .zip([control & 15, control >> 4])
    {
        if selector & 8 == 0 {
            half.copy_from_slice(halves[usize::from(selector & 3)]);
        }
    }
    output
}

pub(super) fn immediate_cases() -> Vec<ImmediateCase> {
    let mut cases = Vec::new();
    for (mnemonic, control, legacy, vex128, vex256, expected) in [
        (
            "shufps",
            0x1b,
            &[0x44, 0x0f, 0xc6, 0x3f][..],
            &[0xc5, 0x38, 0xc6, 0x7f, 3][..],
            &[0xc5, 0x3c, 0xc6, 0x7f, 3][..],
            [
                0x4c, 0x4d, 0x4e, 0x4f, 0x48, 0x49, 0x4a, 0x4b, 0x84, 0x85, 0x86, 0x87, 0x80, 0x81,
                0x82, 0x83, 0x5c, 0x5d, 0x5e, 0x5f, 0x58, 0x59, 0x5a, 0x5b, 0x94, 0x95, 0x96, 0x97,
                0x90, 0x91, 0x92, 0x93,
            ],
        ),
        (
            "shufpd",
            0xa9,
            &[0x66, 0x44, 0x0f, 0xc6, 0x3f][..],
            &[0xc5, 0x39, 0xc6, 0x7f, 3][..],
            &[0xc4, 0x61, 0xbd, 0xc6, 0x7f, 3][..],
            [
                0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85,
                0x86, 0x87, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x98, 0x99, 0x9a, 0x9b,
                0x9c, 0x9d, 0x9e, 0x9f,
            ],
        ),
        (
            "palignr",
            13,
            &[0x66, 0x44, 0x0f, 0x3a, 0x0f, 0x3f][..],
            &[0xc4, 0x63, 0x39, 0x0f, 0x7f, 3][..],
            &[0xc4, 0x63, 0xbd, 0x0f, 0x7f, 3][..],
            [
                0x8d, 0x8e, 0x8f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a,
                0x4b, 0x4c, 0x9d, 0x9e, 0x9f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
                0x59, 0x5a, 0x5b, 0x5c,
            ],
        ),
    ] {
        for (encoding, bytes, width) in [
            ("legacy", legacy, 16),
            ("vex128", vex128, 16),
            ("vex256", vex256, 32),
        ] {
            let mut code = bytes.to_vec();
            code.push(control);
            let mut expected = expected;
            expected[width..].fill(0);
            cases.push(ImmediateCase {
                mnemonic,
                encoding,
                code,
                width,
                expected,
            });
        }
    }
    cases
}

pub(super) fn unary_cases() -> Vec<ImmediateCase> {
    let mut cases = Vec::new();
    for (mnemonic, prefix, pp, order) in [
        (
            "pshufd",
            0x66,
            1,
            [12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3],
        ),
        (
            "pshufhw",
            0xf3,
            2,
            [0, 1, 2, 3, 4, 5, 6, 7, 14, 15, 12, 13, 10, 11, 8, 9],
        ),
        (
            "pshuflw",
            0xf2,
            3,
            [6, 7, 4, 5, 2, 3, 0, 1, 8, 9, 10, 11, 12, 13, 14, 15],
        ),
    ] {
        for (encoding, code, width) in [
            ("legacy", vec![prefix, 0x44, 0x0f, 0x70, 0x3f, 0x1b], 16),
            ("vex128", vec![0xc5, 0x78 | pp, 0x70, 0x7f, 3, 0x1b], 16),
            ("vex256", vec![0xc5, 0x7c | pp, 0x70, 0x7f, 3, 0x1b], 32),
            (
                "vex128-w1",
                vec![0xc4, 0x61, 0xf8 | pp, 0x70, 0x7f, 3, 0x1b],
                16,
            ),
            (
                "vex256-w1",
                vec![0xc4, 0x61, 0xfc | pp, 0x70, 0x7f, 3, 0x1b],
                32,
            ),
        ] {
            let mut expected = [0; 32];
            let reply = immediate_reply();
            for i in 0..width {
                expected[i] = reply[(i & !15) + order[i & 15]];
            }
            cases.push(ImmediateCase {
                mnemonic,
                encoding,
                code,
                width,
                expected,
            });
        }
    }
    cases
}
