//! BSF and BSR memory reads on an Intel Hypervisor.framework vCPU.
use super::*;

pub(super) fn run(output: &Path) {
    assert!(!output.exists(), "observations must be new");
    let mut case = 0;
    for (opcode, direct, restored) in [(0xbc, "bsf", "bsf-restored"), (0xbd, "bsr", "bsr-restored")]
    {
        for (prefix, width, preserved) in [
            (&[0x66][..], 2, SEED & !0xffff),
            (&[][..], 4, 0),
            (&[0x48][..], 8, 0),
        ] {
            let code = [prefix, &[0x0f, opcode, 0x07]].concat();
            let top = width * 8 - 1;
            let mixed = if opcode == 0xbc { 2 } else { top } as u64;
            for (source, expected, flags) in [
                (0u64, SEED, 0x42),
                (1u64 << top, preserved | top as u64, 2),
                ((1u64 << top) | 4, preserved | mixed, 2),
            ] {
                for (restore, name) in [(false, direct), (true, restored)] {
                    scalar_read(
                        &code,
                        &source.to_le_bytes()[..width],
                        expected,
                        flags,
                        restore,
                    );
                    record(output, case, name, width, expected);
                    case += 1;
                }
            }
        }
    }
    assert_eq!(case, 36);
    println!("{{\"cases\":{case},\"failed\":0,\"guest_execution_performed\":true}}");
}
