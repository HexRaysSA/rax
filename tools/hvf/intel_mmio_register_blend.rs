//! Shared register-mask blend cases for planner and Intel guest tests.

pub(super) const LEFT: [u8; 32] = [
    0x80, 0x40, 0x20, 0x10, 0x81, 0xf8, 0x51, 0xd3, 0x12, 0x34, 0x80, 0x7f, 0, 0, 0, 0x80, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x95, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x9c, 0x1d, 0x1e, 0x1f,
];
pub(super) const REPLY: [u8; 32] = [
    0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x00, 0x00, 0x00, 0x80, 0x07, 0x00, 0xc0, 0x7f,
    0x56, 0x47, 0x38, 0x29, 0x1a, 0xab, 0xcd, 0xef, 0x11, 0x00, 0x77, 0x88, 0xfe, 0xdc, 0xba, 0x98,
];

pub(super) struct Case {
    pub(super) mnemonic: &'static str,
    pub(super) code: Vec<u8>,
    pub(super) width: usize,
    pub(super) bank: u8,
    pub(super) mask: [u8; 32],
    pub(super) expected: [u8; 32],
}

impl Case {
    pub(super) fn is_vex(&self) -> bool {
        self.code[0] == 0xc4
    }
}

pub(super) fn cases() -> Vec<Case> {
    let mut cases = Vec::new();
    for (legacy, vex, legacy_op, vex_op, element) in [
        ("blendvps", "vblendvps", 0x14, 0x4a, 4),
        ("blendvpd", "vblendvpd", 0x15, 0x4b, 8),
        ("pblendvb", "vpblendvb", 0x10, 0x4c, 1),
    ] {
        for (width, prefix, banks, low_bits) in [
            (16, None, &[0][..], &[0][..]),
            (16, Some(0x39), &[0, 8, 12, 15][..], &[0, 15][..]),
            (32, Some(0x3d), &[0, 8, 12, 15][..], &[0, 15][..]),
        ] {
            let lanes = width / element;
            let all = u32::MAX >> (32 - lanes);
            for &bank in banks {
                for &low in low_bits {
                    let (mnemonic, code) = if let Some(prefix) = prefix {
                        (
                            vex,
                            vec![0xc4, 0x63, prefix, vex_op, 0x7f, 3, bank << 4 | low],
                        )
                    } else {
                        (legacy, vec![0x66, 0x44, 0x0f, 0x38, legacy_op, 0x3f])
                    };
                    for active in [0, all, 0x5555_5555 & all, 1 << (lanes - 1), 1] {
                        let mask = if bank == 8 {
                            // The mask aliases the first source.
                            LEFT
                        } else {
                            std::array::from_fn(|i| {
                                let payload = ((0x35 + i * 13) & 0x7f) as u8;
                                let sign = i < width
                                    && i % element == element - 1
                                    && active & (1 << (i / element)) != 0;
                                payload | (u8::from(sign) << 7)
                            })
                        };
                        let mut expected = if prefix.is_none() { LEFT } else { [0; 32] };
                        for start in (0..width).step_by(element) {
                            let end = start + element;
                            let source = if mask[end - 1] >= 0x80 { &REPLY } else { &LEFT };
                            expected[start..end].copy_from_slice(&source[start..end]);
                        }
                        cases.push(Case {
                            mnemonic,
                            code: code.clone(),
                            width,
                            bank,
                            mask,
                            expected,
                        });
                    }
                }
            }
        }
    }
    cases
}
