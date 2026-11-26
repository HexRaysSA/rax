//! Immediate blend forms shared by the MMIO planner and native guest tests.

pub(super) const LEFT: [u8; 32] = [
    0x00, 0x00, 0x80, 0x7f, 0x00, 0x00, 0xc0, 0x7f, 0x12, 0x34, 0x80, 0x7f, 0x00, 0x00, 0x00, 0x80,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

pub(super) const REPLY: [u8; 32] = [
    0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x00, 0x00, 0x00, 0x80, 0x07, 0x00, 0xc0, 0x7f,
    0x56, 0x47, 0x38, 0x29, 0x1a, 0xab, 0xcd, 0xef, 0x11, 0x00, 0x77, 0x88, 0xfe, 0xdc, 0xba, 0x98,
];

pub(super) struct Form {
    pub(super) mnemonic: &'static str,
    pub(super) encoding: &'static str,
    pub(super) width: usize,
    opcode: u8,
    vex: Option<u8>,
    element: usize,
}

impl Form {
    pub(super) fn is_vex(&self) -> bool {
        self.vex.is_some()
    }

    pub(super) fn code(&self, mask: u8) -> [u8; 7] {
        match self.vex {
            Some(prefix) => [0xc4, 0x63, prefix, self.opcode, 0x7f, 3, mask],
            None => [0x66, 0x44, 0x0f, 0x3a, self.opcode, 0x3f, mask],
        }
    }

    pub(super) fn expected(&self, mask: u8) -> [u8; 32] {
        let mut bytes = LEFT;
        if self.is_vex() {
            bytes[self.width..].fill(0);
        }
        for start in (0..self.width).step_by(self.element) {
            let bit = (start / self.element) % 8;
            if mask & (1 << bit) != 0 {
                let element = start..start + self.element;
                bytes[element.clone()].copy_from_slice(&REPLY[element]);
            }
        }
        bytes
    }
}

pub(super) fn forms() -> Vec<Form> {
    let mut forms = Vec::new();
    for (legacy, vex, opcode, element) in [
        (Some("blendps"), "vblendps", 0x0c, 4),
        (Some("blendpd"), "vblendpd", 0x0d, 8),
        (Some("pblendw"), "vpblendw", 0x0e, 2),
        (None, "vpblendd", 0x02, 4),
    ] {
        if let Some(mnemonic) = legacy {
            forms.push(Form {
                mnemonic,
                encoding: "legacy",
                width: 16,
                opcode,
                vex: None,
                element,
            });
        }
        for (encoding, prefix, width) in [
            ("vex128-w0", 0x39, 16),
            ("vex256-w0", 0x3d, 32),
            ("vex128-w1", 0xb9, 16),
            ("vex256-w1", 0xbd, 32),
        ] {
            if legacy.is_some() || prefix & 0x80 == 0 {
                forms.push(Form {
                    mnemonic: vex,
                    encoding,
                    width,
                    opcode,
                    vex: Some(prefix),
                    element,
                });
            }
        }
    }
    forms
}
