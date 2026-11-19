//! Legacy CRC32 memory reads on an Intel Hypervisor.framework vCPU.
use super::*;

pub(super) fn run(output: &Path) {
    assert!(!output.exists(), "observations must be new");
    let flags = 0x8d7;
    let code_and_widths: [(&[u8], usize); 5] = [
        (&[0xf2, 0x0f, 0x38, 0xf0, 0x07][..], 1),
        (&[0xf2, 0x48, 0x0f, 0x38, 0xf0, 0x07][..], 1),
        (&[0x66, 0xf2, 0x0f, 0x38, 0xf1, 0x07][..], 2),
        (&[0xf2, 0x0f, 0x38, 0xf1, 0x07][..], 4),
        (&[0x66, 0xf2, 0x48, 0x0f, 0x38, 0xf1, 0x07][..], 8),
    ];
    // Each row was calculated with the SSE4.2 intrinsics on physical Intel
    // using SEED, with one value per source width in increasing order.
    let observations = [
        (0_u64, [0x087a_05c0, 0xc385_5cc1, 0x0b10_720c, 0x32c6_5ce5]),
        (
            0xfedc_ba98_7654_3210,
            [0x1824_c2af, 0x2d98_9406, 0xe59c_f21e, 0x1f11_cf01],
        ),
    ];
    let mut case = 0;
    for (code, width) in code_and_widths {
        for (reply, reference) in observations {
            let result = reference[width.trailing_zeros() as usize];
            for (restore, name) in [(false, "crc32"), (true, "crc32-restored")] {
                scalar_read_with_flags(
                    code,
                    &reply.to_le_bytes()[..width],
                    flags,
                    result,
                    flags,
                    restore,
                );
                record(output, case, name, width, result);
                case += 1;
            }
        }
    }
    assert_eq!(case, 20);
    println!("{{\"cases\":{case},\"failed\":0,\"guest_execution_performed\":true}}");
}
