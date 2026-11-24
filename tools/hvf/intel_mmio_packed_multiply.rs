//! Packed integer multiply operands and results from x86-64 RAM execution.

pub const PATTERNS: [[[u64; 4]; 2]; 2] = [
    [
        [
            0xffff7fff80008000,
            0x8001000140004000,
            0xff000080feffffff,
            0x007f0080ffff00ff,
        ],
        [
            0x8000ffff80008000,
            0x7fff7fffffff0001,
            0x7fff808081807f7f,
            0x40008000ff80007f,
        ],
    ],
    [
        [
            0x40010001ffff0000,
            0x1ee7dead7fff8000,
            0x217fff8001007f7f,
            0x000000014000fffe,
        ],
        [
            0x400040000001ffff,
            0x800112037fffffff,
            0x458fffff7f018080,
            0x8000c00040008000,
        ],
    ],
];

pub struct Case {
    map: u8,
    opcode: u8,
    pub mnemonic: &'static str,
    pub results: [[u64; 4]; 2],
}

pub const CASES: [Case; 9] = [
    Case {
        map: 1,
        opcode: 0xd5,
        mnemonic: "pmullw",
        results: [
            [
                0x8000800100000000,
                0xffff7fffc0004000,
                0x01004000fe808081,
                0xc000000000807e81,
            ],
            [
                0x40004000ffff0000,
                0x9ee7c60700018000,
                0xf0f1008001003f80,
                0x0000c00000000000,
            ],
        ],
    },
    Case {
        map: 1,
        opcode: 0xe5,
        mnemonic: "pmulhw",
        results: [
            [
                0x0000ffff40004000,
                0xc0000000ffff0000,
                0xff80ffc0007effff,
                0x001fffc000000000,
            ],
            [
                0x10000000ffff0000,
                0xf08cfda73fff0000,
                0x09190000007fc080,
                0x0000ffff10000001,
            ],
        ],
    },
    Case {
        map: 1,
        opcode: 0xe4,
        mnemonic: "pmulhuw",
        results: [
            [
                0x7fff7ffe40004000,
                0x3fff00003fff0000,
                0x7f7f004080fd7f7e,
                0x001f0040ff7f0000,
            ],
            [
                0x1000000000000000,
                0x0f730faa3fff7fff,
                0x0919ff7f007f3fff,
                0x0000000010007fff,
            ],
        ],
    },
    Case {
        map: 1,
        opcode: 0xf4,
        mnemonic: "pmuludq",
        results: [
            [
                0x4000800040000000,
                0x4000000000004000,
                0x80fefefeff7f8081,
                0xff7f01fd80017e81,
            ],
            [
                0x0001fffd00010000,
                0x3fffbfff80008000,
                0x007f40c1407e3f80,
                0x10005fffffff0000,
            ],
        ],
    },
    Case {
        map: 1,
        opcode: 0xf5,
        mnemonic: "pmaddwd",
        results: [
            [
                0x0000000180000000,
                0xc0017ffe00000000,
                0xff404100007e7f01,
                0xffdfc00000007f01,
            ],
            [
                0x10008000ffffffff,
                0xee3464ee3fff8001,
                0x0919f171c0ff4080,
                0xffffc00010010000,
            ],
        ],
    },
    Case {
        map: 2,
        opcode: 0x40,
        mnemonic: "pmulld",
        results: [
            [
                0xffff800140000000,
                0x7ffe7fff00004000,
                0x7fc04000ff7f8081,
                0x8040000080017e81,
            ],
            [
                0x8000400000010000,
                0x090cc60780008000,
                0x16800080407e3f80,
                0x8000c000ffff0000,
            ],
        ],
    },
    Case {
        map: 2,
        opcode: 0x28,
        mnemonic: "pmuldq",
        results: [
            [
                0x3fff800040000000,
                0xffffc00000004000,
                0x007e7f80ff7f8081,
                0x0000007f80017e81,
            ],
            [
                0xfffffffe00010000,
                0x3fffbfff80008000,
                0x007f40c1407e3f80,
                0x10005fffffff0000,
            ],
        ],
    },
    Case {
        map: 2,
        opcode: 0x0b,
        mnemonic: "pmulhrsw",
        results: [
            [
                0x0001ffff80008000,
                0x8002000100000001,
                0xff00ff8100feffff,
                0x0040ff8000000001,
            ],
            [
                0x2001000100000000,
                0xe119fb507ffe0001,
                0x1234000000fe8100,
                0x0000000020000002,
            ],
        ],
    },
    Case {
        map: 2,
        opcode: 0x04,
        mnemonic: "pmaddubsw",
        results: [
            [
                0x8080fe82c000c000,
                0x3f7fffffffc00000,
                0x7e81c00080007fff,
                0x0000000080007e81,
            ],
            [
                0x1000000000ff0000,
                0xf1e711a33e02ff80,
                0xd0d6fe81007f8100,
                0x0000000010008080,
            ],
        ],
    },
];

impl Case {
    pub fn legacy(&self) -> Vec<u8> {
        let mut code = vec![0x66, 0x44, 0x0f];
        if self.map == 2 {
            code.push(0x38);
        }
        code.extend([self.opcode, 0x3f]);
        code
    }

    pub fn forms(&self) -> Vec<(Vec<u8>, &'static str, usize)> {
        let mut forms = vec![(self.legacy(), "legacy", 16)];
        if self.map == 1 {
            forms.push((vec![0xc5, 0x39, self.opcode, 0x7f, 3], "vex2-128", 16));
            forms.push((vec![0xc5, 0x3d, self.opcode, 0x7f, 3], "vex2-256", 32));
        }
        for (control, name, width) in [
            (0x39, "vex3-w0-128", 16),
            (0x3d, "vex3-w0-256", 32),
            (0xb9, "vex3-w1-128", 16),
            (0xbd, "vex3-w1-256", 32),
        ] {
            forms.push((
                vec![0xc4, 0x60 | self.map, control, self.opcode, 0x7f, 3],
                name,
                width,
            ));
        }
        forms
    }
}

pub fn bytes(qwords: [u64; 4]) -> [u8; 32] {
    let mut bytes = [0; 32];
    for (output, word) in bytes.chunks_exact_mut(8).zip(qwords) {
        output.copy_from_slice(&word.to_le_bytes());
    }
    bytes
}
