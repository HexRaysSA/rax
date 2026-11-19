//! POPCNT memory reads on an Intel Hypervisor.framework vCPU.
use super::*;

pub(super) fn run(output: &Path) {
    assert!(!output.exists(), "observations must be new");
    let mut case = 0;
    for (prefix, width, preserved, count) in [
        (&[0x66, 0xf3][..], 2, SEED & !0xffff, 2),
        (&[0xf3][..], 4, 0, 3),
        (&[0xf3, 0x48][..], 8, 0, 5),
    ] {
        let code = [prefix, &[0x0f, 0xb8, 0x07]].concat();
        for (source, result, flags) in [(0u64, 0, 0x42), (0x8000_0001_8000_8001, count, 2)] {
            let expected = preserved | result;
            for restore in [false, true] {
                scalar_read(
                    &code,
                    &source.to_le_bytes()[..width],
                    expected,
                    flags,
                    restore,
                );
                let name = if restore { "popcnt-restored" } else { "popcnt" };
                record(output, case, name, width, expected);
                case += 1;
            }
        }
    }
    assert_eq!(case, 12);
    println!("{{\"cases\":{case},\"failed\":0,\"guest_execution_performed\":true}}");
}
