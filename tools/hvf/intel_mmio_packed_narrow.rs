//! Packed integer saturation vectors observed in x86-64 RAM execution.

type Vector = [u64; 4];

pub(super) struct Case {
    map: u8,
    opcode: u8,
    pub mnemonic: &'static str,
    pub sources: [[Vector; 2]; 2],
    pub results: [Vector; 2],
}

const WORDS: [[Vector; 2]; 2] = [
    [
        [
            0xff81ff80ff7f8000,
            0x007e00010000ffff,
            0x00ff0100007f0080,
            0x7fff0025ff7e00fe,
        ],
        [
            0x010000ff0080007f,
            0x000cff80fffe7fff,
            0x000200010000ffff,
            0x0081007dff818000,
        ],
    ],
    [
        [
            0x0101010000ff00fe,
            0x00010000ffff8000,
            0x007eff81ff80ff7f,
            0x008200810080007f,
        ],
        [
            0x007f0002fffa0028,
            0x7fff010000ff0080,
            0x0061004efff7000b,
            0x00ff010100030000,
        ],
    ],
];

const DWORDS: [[Vector; 2]; 2] = [
    [
        [
            0xffff7fff80000000,
            0xffff8001ffff8000,
            0x0000800000007fff,
            0x000100000000ffff,
        ],
        [
            0x00007fff00007ffe,
            0x7fffffff00008000,
            0x00000000ffffffff,
            0x0000fffe00000001,
        ],
    ],
    [
        [
            0x00000000ffffffff,
            0x0000fffe00000001,
            0x0000fffffff0edfa,
            0x0001000100010000,
        ],
        [
            0x000100000000ffff,
            0x800000007fffffff,
            0xffff8001ffff8000,
            0x00007ffe0000ff98,
        ],
    ],
];

pub(super) const CASES: [Case; 4] = [
    Case {
        map: 1,
        opcode: 0x63,
        mnemonic: "packsswb",
        sources: WORDS,
        results: [
            [
                0x7e0100ff81808080,
                0x0c80fe7f7f7f7f7f,
                0x7f25807f7f7f7f7f,
                0x7f7d8180020100ff,
            ],
            [
                0x0100ff807f7f7f7f,
                0x7f7f7f7f7f02fa28,
                0x7f7f7f7f7e818080,
                0x7f7f0300614ef70b,
            ],
        ],
    },
    Case {
        map: 1,
        opcode: 0x6b,
        mnemonic: "packssdw",
        sources: DWORDS,
        results: [
            [
                0x8001800080008000,
                0x7fff7fff7fff7ffe,
                0x7fff7fff7fff7fff,
                0x7fff00010000ffff,
            ],
            [
                0x7fff00010000ffff,
                0x80007fff7fff7fff,
                0x7fff7fff7fff8000,
                0x7ffe7fff80018000,
            ],
        ],
    },
    Case {
        map: 1,
        opcode: 0x67,
        mnemonic: "packuswb",
        sources: WORDS,
        results: [
            [
                0x7e01000000000000,
                0x0c0000ffffff807f,
                0xff2500feffff7f80,
                0x817d000002010000,
            ],
            [
                0x01000000fffffffe,
                0xffffff807f020028,
                0x8281807f7e000000,
                0xffff0300614e000b,
            ],
        ],
    },
    Case {
        map: 2,
        opcode: 0x2b,
        mnemonic: "packusdw",
        sources: DWORDS,
        results: [
            [
                0x0000000000000000,
                0xffff80007fff7ffe,
                0xffffffff80007fff,
                0xfffe000100000000,
            ],
            [
                0xfffe000100000000,
                0x0000ffffffffffff,
                0xffffffffffff0000,
                0x7ffeff9800000000,
            ],
        ],
    },
];

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
