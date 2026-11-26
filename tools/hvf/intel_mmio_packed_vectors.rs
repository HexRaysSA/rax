//! Packed integer MMIO operand forms and RAM reference results.

pub(super) type Vector = [u64; 4];

pub(super) struct Case {
    pub(super) map: u8,
    pub(super) opcode: u8,
    pub mnemonic: &'static str,
    pub sources: [[Vector; 2]; 2],
    pub results: [Vector; 2],
}

impl Case {
    pub(super) fn legacy(&self) -> Vec<u8> {
        let mut code = vec![0x66, 0x44, 0x0f];
        if self.map == 2 {
            code.push(0x38);
        }
        code.extend([self.opcode, 0x3f]);
        code
    }

    pub(super) fn forms(&self) -> Vec<(Vec<u8>, &'static str, usize)> {
        self.forms_with_vvvv(0x38)
    }

    pub(super) fn unary_forms(&self) -> Vec<(Vec<u8>, &'static str, usize)> {
        self.forms_with_vvvv(0x78)
    }

    fn forms_with_vvvv(&self, vvvv: u8) -> Vec<(Vec<u8>, &'static str, usize)> {
        packed_forms(self.map, self.opcode, vvvv, self.legacy())
    }
}

fn packed_forms(
    map: u8,
    opcode: u8,
    vvvv: u8,
    legacy: Vec<u8>,
) -> Vec<(Vec<u8>, &'static str, usize)> {
    let mut forms = vec![(legacy, "legacy", 16)];
    if map == 1 {
        forms.extend([
            (vec![0xc5, vvvv | 1, opcode, 0x7f, 3], "vex2-128", 16),
            (vec![0xc5, vvvv | 5, opcode, 0x7f, 3], "vex2-256", 32),
        ]);
    }
    for (control, label, size) in [
        (1, "vex3-w0-128", 16),
        (5, "vex3-w0-256", 32),
        (0x81, "vex3-w1-128", 16),
        (0x85, "vex3-w1-256", 32),
    ] {
        forms.push((
            vec![0xc4, 0x60 | map, vvvv | control, opcode, 0x7f, 3],
            label,
            size,
        ));
    }
    forms
}

pub(super) struct WideningCase {
    pub(super) name: &'static str,
    opcode: u8,
    from: usize,
    to: usize,
}

impl WideningCase {
    pub(super) fn forms(&self) -> Vec<(Vec<u8>, &'static str, usize)> {
        packed_forms(
            2,
            self.opcode,
            0x78,
            vec![0x66, 0x44, 0x0f, 0x38, self.opcode, 0x3f],
        )
    }

    pub(super) fn reply_len(&self, width: usize) -> usize {
        width / self.to * self.from
    }

    pub(super) fn expected(&self, source: &[u8], width: usize) -> [u8; 32] {
        let mut result = [0; 32];
        let signed = self.opcode < 0x30;
        for (input, output) in source
            .chunks_exact(self.from)
            .zip(result[..width].chunks_exact_mut(self.to))
        {
            let value = match (self.from, signed) {
                (1, true) => i64::from(input[0] as i8),
                (1, false) => i64::from(input[0]),
                (2, true) => i64::from(i16::from_le_bytes(input.try_into().unwrap())),
                (2, false) => i64::from(u16::from_le_bytes(input.try_into().unwrap())),
                (4, true) => i64::from(i32::from_le_bytes(input.try_into().unwrap())),
                (4, false) => i64::from(u32::from_le_bytes(input.try_into().unwrap())),
                _ => unreachable!(),
            };
            output.copy_from_slice(&value.to_le_bytes()[..self.to]);
        }
        result
    }
}

pub(super) const WIDENING_INPUTS: [[u8; 16]; 2] = [
    [
        0x80, 0xff, 0x00, 0x80, 0xff, 0x7f, 0x34, 0x12, 0x01, 0x00, 0xfe, 0xff, 0x00, 0x90, 0x67,
        0x45,
    ],
    [
        0xff, 0x7f, 0xff, 0xff, 0x00, 0x01, 0x01, 0x80, 0x00, 0x00, 0x00, 0x80, 0xff, 0xff, 0xff,
        0x7f,
    ],
];

pub(super) const WIDENING_CASES: [WideningCase; 12] = [
    WideningCase {
        name: "pmovsxbw",
        opcode: 0x20,
        from: 1,
        to: 2,
    },
    WideningCase {
        name: "pmovsxbd",
        opcode: 0x21,
        from: 1,
        to: 4,
    },
    WideningCase {
        name: "pmovsxbq",
        opcode: 0x22,
        from: 1,
        to: 8,
    },
    WideningCase {
        name: "pmovsxwd",
        opcode: 0x23,
        from: 2,
        to: 4,
    },
    WideningCase {
        name: "pmovsxwq",
        opcode: 0x24,
        from: 2,
        to: 8,
    },
    WideningCase {
        name: "pmovsxdq",
        opcode: 0x25,
        from: 4,
        to: 8,
    },
    WideningCase {
        name: "pmovzxbw",
        opcode: 0x30,
        from: 1,
        to: 2,
    },
    WideningCase {
        name: "pmovzxbd",
        opcode: 0x31,
        from: 1,
        to: 4,
    },
    WideningCase {
        name: "pmovzxbq",
        opcode: 0x32,
        from: 1,
        to: 8,
    },
    WideningCase {
        name: "pmovzxwd",
        opcode: 0x33,
        from: 2,
        to: 4,
    },
    WideningCase {
        name: "pmovzxwq",
        opcode: 0x34,
        from: 2,
        to: 8,
    },
    WideningCase {
        name: "pmovzxdq",
        opcode: 0x35,
        from: 4,
        to: 8,
    },
];

const HORIZONTAL_WORDS: [[Vector; 2]; 2] = [
    [
        [
            0xffff800000017fff,
            0xff8800630061007b,
            0xfffe7fff00018000,
            0xfcf7ff0b00f50309,
        ],
        [
            0x7fff7fff80008000,
            0x001300077fffffff,
            0x85487ab739bac647,
            0x0035005b00020003,
        ],
    ],
    [
        [
            0xfffe00640063fff6,
            0x7fff800000030001,
            0x001f0009fffefffe,
            0x7ff8fcf7ffd90004,
        ],
        [
            0xf52f8ad00ad07530,
            0x00018000ffee7fee,
            0x00170013fffb0007,
            0x03e88300fc187d64,
        ],
    ],
];

const HORIZONTAL_DWORDS: [[Vector; 2]; 2] = [
    [
        [
            0x000000017fffffff,
            0x0000000180000000,
            0xffffffff80000000,
            0x0000009b00000309,
        ],
        [
            0x8000000080000000,
            0xffffffff7fffffff,
            0x0000000cffffffa4,
            0xfffffb2e00000063,
        ],
    ],
    [
        [
            0x3ade68b1fffffff4,
            0x0000003080000000,
            0x0000000500000011,
            0x7fffffff80000000,
        ],
        [
            0x0000000000000001,
            0xfff0e14000000012,
            0x7fffffff7fffffff,
            0xffffffe70000000c,
        ],
    ],
];

pub(super) const HORIZONTAL_CASES: [Case; 6] = [
    Case {
        map: 2,
        opcode: 0x01,
        mnemonic: "phaddw",
        sources: HORIZONTAL_WORDS,
        results: [
            [
                0xffeb00dc7fff8000,
                0x001a7ffefffe0000,
                0xfc0203fe7ffd8001,
                0x00900005ffff0001,
            ],
            [
                0xffff000400620059,
                0x80017fdc7fff8000,
                0x7cefffdd0028fffc,
                0x86e8797c002a0002,
            ],
        ],
    },
    Case {
        map: 2,
        opcode: 0x02,
        mnemonic: "phaddd",
        sources: HORIZONTAL_DWORDS,
        results: [
            [
                0x8000000180000000,
                0x7ffffffe00000000,
                0x000003a47fffffff,
                0xfffffb91ffffffb0,
            ],
            [
                0x800000303ade68a5,
                0xfff0e15200000001,
                0xffffffff00000016,
                0xfffffff3fffffffe,
            ],
        ],
    },
    Case {
        map: 2,
        opcode: 0x03,
        mnemonic: "phaddsw",
        sources: HORIZONTAL_WORDS,
        results: [
            [
                0xffeb00dc80007fff,
                0x001a7ffe7fff8000,
                0xfc0203fe7ffd8001,
                0x00900005ffff0001,
            ],
            [
                0xffff000400620059,
                0x80017fdc80007fff,
                0x7cefffdd0028fffc,
                0x86e8797c002a0002,
            ],
        ],
    },
    Case {
        map: 2,
        opcode: 0x05,
        mnemonic: "phsubw",
        sources: HORIZONTAL_WORDS,
        results: [
            [
                0x00db001a80017ffe,
                0xfff4800000000000,
                0x0214021480017fff,
                0x00260001f56f8c8d,
            ],
            [
                0x0001fffe0066ff93,
                0x7fff800095a16a60,
                0x7cff002bffea0000,
                0x7f18814cfffc000c,
            ],
        ],
    },
    Case {
        map: 2,
        opcode: 0x06,
        mnemonic: "phsubd",
        sources: HORIZONTAL_DWORDS,
        results: [
            [
                0x7fffffff7ffffffe,
                0x8000000000000000,
                0x0000026e80000001,
                0x00000535ffffff98,
            ],
            [
                0x7fffffd0c5219743,
                0x000f1ed200000001,
                0x000000010000000c,
                0x0000002500000000,
            ],
        ],
    },
    Case {
        map: 2,
        opcode: 0x07,
        mnemonic: "phsubsw",
        sources: HORIZONTAL_WORDS,
        results: [
            [
                0x00db001a80017ffe,
                0xfff4800000000000,
                0x021402147fff8000,
                0x002600017fff8c8d,
            ],
            [
                0x8000fffe0066ff93,
                0x80007fff95a16a60,
                0x8000002bffea0000,
                0x80007ffffffc000c,
            ],
        ],
    },
];

pub(super) const UNSIGNED_CASES: [Case; 3] = [
    Case {
        map: 1,
        opcode: 0xe0,
        mnemonic: "pavgb",
        sources: [
            [
                [
                    0x0e037f80ff0000ff,
                    0xfe01020f807fff00,
                    0x5107ac01de03ffff,
                    0x380d651300ff2040,
                ],
                [
                    0x0d04807f000001ff,
                    0x01fe0b037f800001,
                    0x5b09002a03d4ff00,
                    0x1462a91de7070d43,
                ],
            ],
            [
                [
                    0x0000000000000000,
                    0xffffffffffffffff,
                    0x00ff00ff00ff00ff,
                    0x152249354e500947,
                ],
                [
                    0xffffffffffffffff,
                    0x0000000000000000,
                    0xff00ff00ff00ff00,
                    0x152249354e500947,
                ],
            ],
        ],
        results: [
            [
                0x0e048080800001ff,
                0x8080070980808001,
                0x56085616716cff80,
                0x2638871874831742,
            ],
            [
                0x8080808080808080,
                0x8080808080808080,
                0x8080808080808080,
                0x152249354e500947,
            ],
        ],
    },
    Case {
        map: 1,
        opcode: 0xe3,
        mnemonic: "pavgw",
        sources: [
            [
                [
                    0x00010000ffffffff,
                    0x0000ffff7fff8000,
                    0x8000010eb0f00000,
                    0x01f000cd032501f4,
                ],
                [
                    0x00000001fffeffff,
                    0xfffe000080007fff,
                    0x0001004104000007,
                    0x0087004e00ca0001,
                ],
            ],
            [
                [
                    0x0001002d0020000c,
                    0xfffeffff006f0010,
                    0x0026000a000c8001,
                    0x001900200017000d,
                ],
                [
                    0x000300170020000b,
                    0xfffefffe00760009,
                    0x0026000bffffffff,
                    0x00421eae02550036,
                ],
            ],
        ],
        results: [
            [
                0x00010001ffffffff,
                0x7fff800080008000,
                0x400100a85a780004,
                0x013c008e01f800fb,
            ],
            [
                0x000200220020000c,
                0xfffeffff0073000d,
                0x0026000b8006c000,
                0x002e0f6701360022,
            ],
        ],
    },
    Case {
        map: 1,
        opcode: 0xf6,
        mnemonic: "psadbw",
        sources: [
            [
                [
                    0x0e037f80ff0000ff,
                    0xfe01020f807fff00,
                    0x5107ac01de03ffff,
                    0x380d651300ff2040,
                ],
                [
                    0x0d04807f000001ff,
                    0x01fe0b037f800001,
                    0x5b09002a03d4ff00,
                    0x1462a91de7070d43,
                ],
            ],
            [
                [
                    0x0000000000000000,
                    0xffffffffffffffff,
                    0x00ff00ff00ff00ff,
                    0x152249354e500947,
                ],
                [
                    0xffffffffffffffff,
                    0x0000000000000000,
                    0xff00ff00ff00ff00,
                    0x152249354e500947,
                ],
            ],
        ],
        results: [
            [
                0x0000000000000104,
                0x0000000000000311,
                0x000000000000038c,
                0x00000000000002bc,
            ],
            [
                0x00000000000007f8,
                0x00000000000007f8,
                0x00000000000007f8,
                0x0000000000000000,
            ],
        ],
    },
];

pub(super) const SIGN_CASES: [Case; 3] = [
    Case {
        map: 2,
        opcode: 0x08,
        mnemonic: "psignb",
        sources: [
            [
                [
                    0x81090012ffff7f80,
                    0x81090012ffff7f80,
                    0x81090012ffff7f80,
                    0x81090012ffff7f80,
                ],
                [
                    0x7f807f00010080ff,
                    0x7f807f00010080ff,
                    0x7f807f00010080ff,
                    0x7f807f00010080ff,
                ],
            ],
            [
                [
                    0x81ff0080ff097f12,
                    0x81ff0080ff097f12,
                    0x81ff0080ff097f12,
                    0x81ff0080ff097f12,
                ],
                [
                    0x7f007fff01808000,
                    0x7f007fff01808000,
                    0x7f007fff01808000,
                    0x7f007fff01808000,
                ],
            ],
        ],
        results: [
            [
                0x81f70000ff008180,
                0x81f70000ff008180,
                0x81f70000ff008180,
                0x81f70000ff008180,
            ],
            [
                0x81000080fff78100,
                0x81000080fff78100,
                0x81000080fff78100,
                0x81000080fff78100,
            ],
        ],
    },
    Case {
        map: 2,
        opcode: 0x09,
        mnemonic: "psignw",
        sources: [
            [
                [
                    0xffffffff7fff8000,
                    0x8001000900000012,
                    0xffffffff7fff8000,
                    0x8001000900000012,
                ],
                [
                    0x000100008000ffff,
                    0x7fff80007fff0000,
                    0x000100008000ffff,
                    0x7fff80007fff0000,
                ],
            ],
            [
                [
                    0xffff00097fff0012,
                    0x8001ffff00008000,
                    0xffff00097fff0012,
                    0x8001ffff00008000,
                ],
                [
                    0x0001800080000000,
                    0x7fff00007fffffff,
                    0x0001800080000000,
                    0x7fff00007fffffff,
                ],
            ],
        ],
        results: [
            [
                0xffff000080018000,
                0x8001fff700000000,
                0xffff000080018000,
                0x8001fff700000000,
            ],
            [
                0xfffffff780010000,
                0x8001000000008000,
                0xfffffff780010000,
                0x8001000000008000,
            ],
        ],
    },
    Case {
        map: 2,
        opcode: 0x0a,
        mnemonic: "psignd",
        sources: [
            [
                [
                    0x7fffffff80000000,
                    0xffffffffffffffff,
                    0x0000000000000012,
                    0x8000000100000009,
                ],
                [
                    0x80000000ffffffff,
                    0x0000000100000000,
                    0x7fffffff00000000,
                    0x7fffffff80000000,
                ],
            ],
            [
                [
                    0x7fffffff00000012,
                    0xffffffff00000009,
                    0x0000000080000000,
                    0x80000001ffffffff,
                ],
                [
                    0x8000000000000000,
                    0x0000000180000000,
                    0x7fffffffffffffff,
                    0x7fffffff00000000,
                ],
            ],
        ],
        results: [
            [
                0x8000000180000000,
                0xffffffff00000000,
                0x0000000000000000,
                0x80000001fffffff7,
            ],
            [
                0x8000000100000000,
                0xfffffffffffffff7,
                0x0000000080000000,
                0x8000000100000000,
            ],
        ],
    },
];

// Full vector fingerprints from the PABS RAM oracle.
pub(super) const ABSOLUTE_CASES: [Case; 3] = [
    Case {
        map: 2,
        opcode: 0x1c,
        mnemonic: "pabsb",
        sources: [
            [
                [
                    0xa7a6a5a4a3a2a1a0,
                    0xafaeadacabaaa9a8,
                    0xb7b6b5b4b3b2b1b0,
                    0xbfbebdbcbbbab9b8,
                ],
                [
                    0x017ff7128100ff80,
                    0x017ff7128100ff80,
                    0x80017ff7128100ff,
                    0x80017ff7128100ff,
                ],
            ],
            [
                [
                    0xa7a6a5a4a3a2a1a0,
                    0xafaeadacabaaa9a8,
                    0xb7b6b5b4b3b2b1b0,
                    0xbfbebdbcbbbab9b8,
                ],
                [
                    0x00ff80017ff71281,
                    0x00ff80017ff71281,
                    0x8100ff80017ff712,
                    0x8100ff80017ff712,
                ],
            ],
        ],
        results: [
            [
                0x017f09127f000180,
                0x017f09127f000180,
                0x80017f09127f0001,
                0x80017f09127f0001,
            ],
            [
                0x000180017f09127f,
                0x000180017f09127f,
                0x7f000180017f0912,
                0x7f000180017f0912,
            ],
        ],
    },
    Case {
        map: 2,
        opcode: 0x1d,
        mnemonic: "pabsw",
        sources: [
            [
                [
                    0xa7a6a5a4a3a2a1a0,
                    0xafaeadacabaaa9a8,
                    0xb7b6b5b4b3b2b1b0,
                    0xbfbebdbcbbbab9b8,
                ],
                [
                    0x80010000ffff8000,
                    0x00017ffffff70012,
                    0x001280010000ffff,
                    0x800000017ffffff7,
                ],
            ],
            [
                [
                    0xa7a6a5a4a3a2a1a0,
                    0xafaeadacabaaa9a8,
                    0xb7b6b5b4b3b2b1b0,
                    0xbfbebdbcbbbab9b8,
                ],
                [
                    0x7ffffff700128001,
                    0x0000ffff80000001,
                    0x00017ffffff70012,
                    0x80010000ffff8000,
                ],
            ],
        ],
        results: [
            [
                0x7fff000000018000,
                0x00017fff00090012,
                0x00127fff00000001,
                0x800000017fff0009,
            ],
            [
                0x7fff000900127fff,
                0x0000000180000001,
                0x00017fff00090012,
                0x7fff000000018000,
            ],
        ],
    },
    Case {
        map: 2,
        opcode: 0x1e,
        mnemonic: "pabsd",
        sources: [
            [
                [
                    0xa7a6a5a4a3a2a1a0,
                    0xafaeadacabaaa9a8,
                    0xb7b6b5b4b3b2b1b0,
                    0xbfbebdbcbbbab9b8,
                ],
                [
                    0xffffffff80000000,
                    0x8000000100000000,
                    0x7ffffffffffffff7,
                    0x8000000000000001,
                ],
            ],
            [
                [
                    0xa7a6a5a4a3a2a1a0,
                    0xafaeadacabaaa9a8,
                    0xb7b6b5b4b3b2b1b0,
                    0xbfbebdbcbbbab9b8,
                ],
                [
                    0x0000001280000001,
                    0x7ffffffffffffff7,
                    0xffffffff80000000,
                    0x8000000100000000,
                ],
            ],
        ],
        results: [
            [
                0x0000000180000000,
                0x7fffffff00000000,
                0x7fffffff00000009,
                0x8000000000000001,
            ],
            [
                0x000000127fffffff,
                0x7fffffff00000009,
                0x0000000180000000,
                0x7fffffff00000000,
            ],
        ],
    },
];
