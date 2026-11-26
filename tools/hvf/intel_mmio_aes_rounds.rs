//! Actual Intel HVF read exits for AES round operands, including owner restore.
use super::xmm::{alignment_fault, packed_binary_case};
use super::*;

#[path = "intel_mmio_aes_unary.rs"]
mod unary;

const ROUNDS: [(&str, u8); 4] = [
    ("enc", 0xdc),
    ("enclast", 0xdd),
    ("dec", 0xde),
    ("declast", 0xdf),
];
const PATTERNS: [usize; 4] = [0, 5, 10, 15];

// Independent QEMU 11.1.2 TCG RAM results, grouped by round and pattern.
const EXPECTED: [[[u128; 2]; 4]; 4] = [
    [
        [
            0xf0bc7e529f2b81bbff641e670eb72909,
            0x0d763eee552dba4713b961166fc8ea1f,
        ],
        [
            0xd0c6dd76a299c453dfd0183a879b4f1a,
            0x66e426c46c78560519cff154991da79a,
        ],
        [
            0xa15f65688d17fc7808551c15d8e433eb,
            0xebef16c7767b98d1d4ca153138b35a05,
        ],
        [
            0x66ef333eebd77f678a42beedf3bb979c,
            0xcc2c419f85af5179f6a9f21a08bea277,
        ],
    ],
    [
        [
            0x97c85966bdb384043562cb7eec948263,
            0x184d5ea079280fdb23f1e8e76cc905f2,
        ],
        [
            0xb4f7906e782dc53c298abc32978a3561,
            0xc20f62cf13b87c90855deb40b7a0e04e,
        ],
        [
            0x9994b04e8010bd3360312c298ae2a22e,
            0x97eb58f18104ef2e2130775c5a77c33a,
        ],
        [
            0x5c8e62347fecab1c51cfcbce933db954,
            0x70b9f106086c3355406421b2d9bb3e3f,
        ],
    ],
    [
        [
            0xdc3147894008bd26cd5c8482cdcea7c9,
            0x3ee6f1e4c8f54280bc404479e1502b6c,
        ],
        [
            0x054e7a6abcd878b7e832b13a370e7f67,
            0x5f79de3fa113112d2b98f1c1d1826880,
        ],
        [
            0x50660c632e301a9d893dbcaebd16d1c5,
            0xdb6eb1905928d34eb1036dfb675010a3,
        ],
        [
            0xc4cc4047db2feed6f9fa850b16a91ab7,
            0x29b8d8deeebd0c84be467db027ea2503,
        ],
    ],
    [
        [
            0xab79f6079a41faf27ab8c693d6ef0652,
            0x89baff015152b64a9248ebf060dd155e,
        ],
        [
            0xf6897753ff09eeb3ebe61844183feaec,
            0x86f8b20b092865ca192cbe08b6b562da,
        ],
        [
            0x1171efd6a4b7c943cf7a5d4e17d60e70,
            0xbca266ec6d0c2ca134ba43e906f02a58,
        ],
        [
            0xb8895a647b32c540ee401033eb5c0bae,
            0x25349117d4c970b669aad026e122a58d,
        ],
    ],
];

pub(super) fn run(output: &Path, profile: &str) {
    match profile {
        "--vector-aes-rounds" => run_rounds(output, false),
        "--vector-vaes-rounds" => run_rounds(output, true),
        "--vector-aes-unary" => unary::run(output),
        _ => unreachable!("unknown AES profile"),
    }
}

fn run_rounds(output: &Path, wide: bool) {
    assert!(!output.exists(), "observations must be new");
    let qwords = |bytes: [u8; 32]| {
        std::array::from_fn(|i| u64::from_le_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap()))
    };
    let mut case = 0;
    for ((round, opcode), cases) in ROUNDS.into_iter().zip(EXPECTED) {
        let legacy = [0x66, 0x44, 0x0f, 0x38, opcode, 0x3f];
        let vex128 = [0xc4, 0x62, 0x39, opcode, 0x7f, 3];
        let vex256 = [0xc4, 0x62, 0x3d, opcode, 0x7f, 3];
        let forms: &[(&str, &[u8], usize, bool)] = if wide {
            &[("vex256", &vex256, 32, true)]
        } else {
            &[
                ("legacy", &legacy, 16, false),
                ("vex128", &vex128, 16, true),
            ]
        };
        for (pattern, [low, high]) in PATTERNS.into_iter().zip(cases) {
            let left: [u8; 32] =
                std::array::from_fn(|i| (pattern * 37 + i / 16 * 61 + i % 16 * 23) as u8);
            let reply: [u8; 32] = std::array::from_fn(|i| {
                (pattern * 11 + i % 16 * 13).wrapping_sub(i / 16 * 43) as u8
            });
            for &(form, code, width, vex) in forms {
                let mut expected = [0; 32];
                expected[..16].copy_from_slice(&low.to_le_bytes());
                if wide {
                    expected[16..].copy_from_slice(&high.to_le_bytes());
                }
                for (restore, phase) in [(false, "direct"), (true, "restored")] {
                    let value = packed_binary_case(
                        code,
                        vex,
                        restore,
                        qwords(left),
                        &reply[..width],
                        qwords(expected),
                    );
                    record(
                        output,
                        case,
                        &format!("aes{round}-{form}-{pattern}-{phase}"),
                        width,
                        value,
                    );
                    case += 1;
                }
            }
        }
        if !wide {
            let event = alignment_fault(&legacy, false, 3);
            record(
                output,
                case,
                &format!("aes{round}-legacy-alignment"),
                0,
                event,
            );
            case += 1;
        }
    }
    println!("{{\"cases\":{case},\"failed\":0,\"guest_execution_performed\":true}}");
}
