//! Legacy ADCX and ADOX memory reads on an Intel Hypervisor.framework vCPU.
use super::*;
use rax::isa::x86_64::flags::bits::{CF, OF};

pub(super) fn run(output: &Path) {
    assert!(!output.exists(), "observations must be new");
    let mut case = 0;
    for (prefix, flag, names) in [
        (0x66, CF, ["adcx", "adcx-restored"]),
        (0xf3, OF, ["adox", "adox-restored"]),
    ] {
        for width in [4, 8] {
            let mut code = vec![prefix];
            if width == 8 {
                code.push(0x48);
            }
            code.extend([0x0f, 0x38, 0xf6, 0x07]);
            let mask = u64::MAX >> (64 - 8 * width);
            let threshold = mask - (SEED & mask);
            for carry in [false, true] {
                for reply in [0u64, threshold] {
                    let unchanged = 0x8d7 & !flag;
                    let initial_flags = unchanged | if carry { flag } else { 0 };
                    let expected_flags =
                        unchanged | if carry && reply == threshold { flag } else { 0 };
                    let result = SEED.wrapping_add(reply).wrapping_add(u64::from(carry)) & mask;
                    for (restore, name) in [(false, names[0]), (true, names[1])] {
                        scalar_read_with_flags(
                            &code,
                            &reply.to_le_bytes()[..width],
                            initial_flags,
                            result,
                            expected_flags,
                            restore,
                        );
                        record(output, case, name, width, result);
                        case += 1;
                    }
                }
            }
        }
    }
    assert_eq!(case, 32);
    println!("{{\"cases\":{case},\"failed\":0,\"guest_execution_performed\":true}}");
}
