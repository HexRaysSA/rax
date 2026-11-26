//! Actual Intel HVF read exits for carry-less multiply, including owner restore.
use super::record;
use super::xmm::{alignment_fault, packed_binary_case};
use std::path::Path;

// QEMU 11.1.2 ordinary RAM results. The wide reference concatenates two
// independently executed VEX.128 products with different lane inputs.
const CASES: [(usize, u8, u128, u128); 8] = [
    (
        1,
        0x00,
        0x2bd2f23b6ef2def9b023e41ab45edd47,
        0x00586ed7a8ef92afb1d9ecbae58bffc0,
    ),
    (
        1,
        0x81,
        0x114b828cffa365e8f987755ce0a1838f,
        0x18ce372d0efad0c4d0c67e2bf1038ac0,
    ),
    (
        1,
        0x1e,
        0x560cf9f9d8d42eeea46d4841d6658bdf,
        0x018e0431756e4d65b503416068cbd990,
    ),
    (
        1,
        0x9f,
        0x227cf7b9d172fc4d59cb666e928f7c57,
        0x4b3f93d6d098e06920f8af199e1b9c50,
    ),
    (
        6,
        0x00,
        0x3a035b9c7f9f9b1bef69739bc4dcf63c,
        0x323413644cc51734504ab22d252cb3f1,
    ),
    (
        6,
        0x81,
        0x19a85dc20bf9d266bc34696b17e3ecac,
        0x1423b79fd7def127a6b1ea8ccd691509,
    ),
    (
        6,
        0x1e,
        0x01a96b3837c3aa900e8f08de45a22b8c,
        0x7e5b3aad0ef2939c355a888ffce9de89,
    ),
    (
        6,
        0x9f,
        0x00f9c66101ac0301aedb6ff14b570c5c,
        0x23136f79d5d75457265ff2cc873cd531,
    ),
];

pub(super) fn run(output: &Path, wide: bool) {
    assert!(!output.exists(), "observations must be new");
    let qwords = |bytes: [u8; 32]| {
        std::array::from_fn(|i| u64::from_le_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap()))
    };
    let mut index = 0;
    for (pattern, control, low, high) in CASES {
        let source: [u8; 32] =
            std::array::from_fn(|i| (pattern * 37 + i / 16 * 61 + i % 16 * 23) as u8);
        let reply: [u8; 32] =
            std::array::from_fn(|i| (pattern * 11 + i % 16 * 13).wrapping_sub(i / 16 * 43) as u8);
        let w = if control & 2 == 0 { 0 } else { 0x80 };
        let legacy = [0x66, 0x44, 0x0f, 0x3a, 0x44, 0x3f, control];
        let vex128 = [0xc4, 0x63, 0x39 | w, 0x44, 0x7f, 3, control];
        let vex256 = [0xc4, 0x63, 0x3d | w, 0x44, 0x7f, 3, control];
        let forms: &[(&str, &[u8], usize, bool)] = if wide {
            &[("vex256", &vex256, 32, true)]
        } else {
            &[
                ("legacy", &legacy, 16, false),
                ("vex128", &vex128, 16, true),
            ]
        };
        let mut expected = [0; 32];
        expected[..16].copy_from_slice(&low.to_le_bytes());
        if wide {
            expected[16..].copy_from_slice(&high.to_le_bytes());
        }
        for &(form, code, width, vex) in forms {
            for (restore, phase) in [(false, "direct"), (true, "restored")] {
                let result = packed_binary_case(
                    code,
                    vex,
                    restore,
                    qwords(source),
                    &reply[..width],
                    qwords(expected),
                );
                record(
                    output,
                    index,
                    &format!("pclmul-{form}-{pattern}-{control:02x}-{phase}"),
                    width,
                    result,
                );
                index += 1;
            }
        }
    }
    if !wide {
        let code = [0x66, 0x44, 0x0f, 0x3a, 0x44, 0x7f, 3, 0x11];
        let fault_pc = alignment_fault(&code, true, 3);
        record(output, index, "pclmul-legacy-alignment", 0, fault_pc);
        index += 1;
    }
    println!("{{\"cases\":{index},\"failed\":0,\"guest_execution_performed\":true}}");
}
