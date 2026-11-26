//! Native HVF AES inverse-mix and key-schedule device reads.
use super::super::record;
use super::super::xmm::{alignment_fault, packed_binary_case};
use std::path::Path;

// Low 128 bits of the independently observed QEMU 11.1.2 RAM results.
// Every AESIMC input and eight immediate values on two key inputs.
const CASES: [(usize, Option<u8>, u128); 32] = [
    (0, None, 0x4453fa228dc0c30ed04de1b3e2399dbe),
    (1, None, 0x9182b6dcf77c54aba3b79dd80c7580e9),
    (2, None, 0xe106033f264c905248c7d266d5717a3e),
    (3, None, 0x91b03dddc4c5b02d61ec5c1863b81c3f),
    (4, None, 0x527b673940dbed0618182a7dcf8a530e),
    (5, None, 0x7c9198ac9fe127f541bef72954f0fbbf),
    (6, None, 0x5e41e4306f761190f677cf85847be3ec),
    (7, None, 0xf7c0c88ee16646b571297f6e4e0bd28f),
    (8, None, 0xd7203911581ef61012a9981c87173840),
    (9, None, 0xc3d67fa3be93d66fd73ec2fa05fa626d),
    (10, None, 0x8312ca1002a5bf60e6b2ecf35168e5dc),
    (11, None, 0x39089545a1cb15d3a30825b70696b9c1),
    (12, None, 0xdc1e798c09346fc26c91755f56e5015a),
    (13, None, 0x1e855183bb0808c70f7b192cd0e9645d),
    (14, None, 0x3d92e7930a78b46e3493b62a31c5a6a2),
    (15, None, 0x79a5d63ba889c4719540909cd76480db),
    (0, Some(0x00), 0x5aa03710a037105a61350a3c350a3c61),
    (0, Some(0x01), 0x5aa03711a037105a61350a3d350a3c61),
    (0, Some(0x1b), 0x5aa0370ba037105a61350a27350a3c61),
    (0, Some(0x7f), 0x5aa0376fa037105a61350a43350a3c61),
    (0, Some(0x80), 0x5aa03790a037105a61350abc350a3c61),
    (0, Some(0x81), 0x5aa03791a037105a61350abd350a3c61),
    (0, Some(0xfe), 0x5aa037eea037105a61350ac2350a3c61),
    (0, Some(0xff), 0x5aa037efa037105a61350ac3350a3c61),
    (15, Some(0x00), 0x1f4b9a7c4b9a7c1f4c5834895834894c),
    (15, Some(0x01), 0x1f4b9a7d4b9a7c1f4c5834885834894c),
    (15, Some(0x1b), 0x1f4b9a674b9a7c1f4c5834925834894c),
    (15, Some(0x7f), 0x1f4b9a034b9a7c1f4c5834f65834894c),
    (15, Some(0x80), 0x1f4b9afc4b9a7c1f4c5834095834894c),
    (15, Some(0x81), 0x1f4b9afd4b9a7c1f4c5834085834894c),
    (15, Some(0xfe), 0x1f4b9a824b9a7c1f4c5834775834894c),
    (15, Some(0xff), 0x1f4b9a834b9a7c1f4c5834765834894c),
];

fn encoding(vex: bool, immediate: Option<u8>) -> Vec<u8> {
    let (legacy_map, vex_map, opcode) = if immediate.is_some() {
        (0x3a, 0x63, 0xdf)
    } else {
        (0x38, 0x62, 0xdb)
    };
    let mut instruction = if vex {
        vec![0xc4, vex_map, 0x79, opcode, 0x7f, 3]
    } else {
        vec![0x66, 0x44, 0x0f, legacy_map, opcode, 0x3f]
    };
    instruction.extend(immediate);
    instruction
}

pub(super) fn run(output: &Path) {
    assert!(!output.exists(), "observations must be new");
    let words = |bytes: [u8; 32]| {
        std::array::from_fn(|lane| {
            let start = lane * 8;
            u64::from_le_bytes(bytes[start..start + 8].try_into().unwrap())
        })
    };
    // Keep the same upper-half canary as the independent RAM control.
    let seed: [u8; 32] = std::array::from_fn(|i| ((i * 17) ^ (i / 3 * 29) ^ 177) as u8);
    let mut index = 0;
    for (pattern, immediate, result) in CASES {
        let reply: [u8; 16] =
            std::array::from_fn(|i| (pattern * 43 + i * 73).wrapping_sub(i % 5 * 19) as u8);
        let mnemonic = immediate.map_or_else(
            || "aesimc".to_owned(),
            |immediate| format!("aeskeygenassist-{immediate:02x}"),
        );
        let mut expected = [0; 32];
        expected[..16].copy_from_slice(&result.to_le_bytes());
        for (vex, form) in [(false, "legacy"), (true, "vex128")] {
            let instruction = encoding(vex, immediate);
            for (restore, phase) in [(false, "direct"), (true, "restored")] {
                let value = packed_binary_case(
                    &instruction,
                    vex,
                    restore,
                    words(seed),
                    &reply,
                    words(expected),
                );
                record(
                    output,
                    index,
                    &format!("{mnemonic}-{form}-{pattern}-{phase}"),
                    16,
                    value,
                );
                index += 1;
            }
        }
    }
    for (mnemonic, immediate) in [("aesimc", None), ("aeskeygenassist-80", Some(0x80))] {
        let value = alignment_fault(&encoding(false, immediate), false, 3);
        record(
            output,
            index,
            &format!("{mnemonic}-legacy-alignment"),
            0,
            value,
        );
        index += 1;
    }
    println!("{{\"cases\":{index},\"failed\":0,\"guest_execution_performed\":true}}");
}
