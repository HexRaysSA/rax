//! CMOVcc memory reads on an Intel Hypervisor.framework vCPU.
use super::*;

const REPLY: u64 = 0x1020_3040_5060_7080;

pub(super) fn run(output: &Path) {
    assert!(!output.exists(), "observations must be new");
    let mut case = 0;
    // The fixture starts with ZF clear, so CMOVNE selects the value and CMOVE keeps the low bits.
    for (prefix, width, selected, unselected) in [
        (&[0x66][..], 2, 0x1122_3344_5566_7080, SEED),
        (&[][..], 4, 0x5060_7080, 0x5566_7788),
        (&[0x48][..], 8, REPLY, SEED),
    ] {
        for (opcode, expected) in [(0x44, unselected), (0x45, selected)] {
            let code = [prefix, &[0x0f, opcode, 0x07]].concat();
            for restore in [false, true] {
                scalar_read(&code, &REPLY.to_le_bytes()[..width], expected, 2, restore);
                let name = match (opcode, restore) {
                    (0x44, false) => "cmove-false",
                    (0x44, true) => "cmove-false-restored",
                    (_, false) => "cmovne-true",
                    (_, true) => "cmovne-true-restored",
                };
                record(output, case, name, width, expected);
                case += 1;
            }
        }
    }
    assert_eq!(case, 12);
    println!("{{\"cases\":{case},\"failed\":0,\"guest_execution_performed\":true}}");
}
