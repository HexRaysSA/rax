//! BMI1 memory reads on an Intel Hypervisor.framework vCPU.
use super::*;

pub(super) fn run(output: &Path) {
    const INITIAL_FLAGS: u64 = 0x8d7;

    assert!(!output.exists(), "observations must be new");
    let mut case = 0;
    for width in [4, 8] {
        let bits = 8 * width as u64;
        let high = 1 << (bits - 1);
        let mask = high | (high - 1);
        for (name, encoding, memory, rcx, result, flags) in [
            ("andn-sign", [0x70, 0xf2, 0x07], high | 7, 3, high | 4, 0x80),
            ("andn-zero", [0x70, 0xf2, 0x07], mask, mask, 0, 0x40),
            (
                "bextr-clipped",
                [0x70, 0xf7, 0x07],
                mask,
                0xff00 | (bits - 1),
                1,
                0,
            ),
            (
                "bextr-start-outside",
                [0x70, 0xf7, 0x07],
                mask,
                0x0100 | bits,
                0,
                0x40,
            ),
            ("bextr-empty", [0x70, 0xf7, 0x07], mask, 0, 0, 0x40),
            ("bextr-full", [0x70, 0xf7, 0x07], mask, 0xff00, mask, 0),
            ("blsi-zero", [0x78, 0xf3, 0x1f], 0, 0, 0, 0x40),
            ("blsi-sign", [0x78, 0xf3, 0x1f], high, 0, high, 0x81),
            ("blsmsk-zero", [0x78, 0xf3, 0x17], 0, 0, mask, 0x81),
            ("blsmsk-low", [0x78, 0xf3, 0x17], 0x18, 0, 0xf, 0),
            ("blsr-zero", [0x78, 0xf3, 0x0f], 0, 0, 0, 0x41),
            ("blsr-clear", [0x78, 0xf3, 0x0f], 0x18, 0, 0x10, 0),
        ] {
            let [vex, opcode, modrm] = encoding;
            let code = [
                0xc4,
                0xe2,
                vex | if width == 8 { 0x80 } else { 0 },
                opcode,
                modrm,
            ];
            let defined = if opcode == 0xf7 { 0x841 } else { 0x8c1 };
            for restore in [false, true] {
                scalar_read_with_initial_rcx(
                    &code,
                    &memory.to_le_bytes()[..width],
                    INITIAL_FLAGS,
                    Some(rcx),
                    result,
                    INITIAL_FLAGS & !defined | flags,
                    restore,
                );
                let name = if restore {
                    format!("{name}-restored")
                } else {
                    name.to_owned()
                };
                record(output, case, &name, width, result);
                case += 1;
            }
        }
    }
    assert_eq!(case, 48);
    println!("{{\"cases\":{case},\"failed\":0,\"guest_execution_performed\":true}}");
}
