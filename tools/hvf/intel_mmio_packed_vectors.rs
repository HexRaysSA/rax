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
        let mut forms = vec![(self.legacy(), "legacy", 16)];
        if self.map == 1 {
            forms.extend([
                (vec![0xc5, 0x39, self.opcode, 0x7f, 3], "vex2-128", 16),
                (vec![0xc5, 0x3d, self.opcode, 0x7f, 3], "vex2-256", 32),
            ]);
        }
        for (control, label, size) in [
            (0x39, "vex3-w0-128", 16),
            (0x3d, "vex3-w0-256", 32),
            (0xb9, "vex3-w1-128", 16),
            (0xbd, "vex3-w1-256", 32),
        ] {
            forms.push((
                vec![0xc4, 0x60 | self.map, control, self.opcode, 0x7f, 3],
                label,
                size,
            ));
        }
        forms
    }
}

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
