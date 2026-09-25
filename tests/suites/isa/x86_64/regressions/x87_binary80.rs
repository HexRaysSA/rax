//! Regression tests: x87 registers hold binary80 values, and the
//! environment image uses the protected-mode 32-bit layout.
//!
//! The direct engine held x87 registers as binary64, so extended-precision
//! results were rounded to 53 bits after every operation, 64-bit integers
//! above 2^53 lost bits through FILD/FISTP, and musl's `printf`, which
//! formats through `long double`, printed wrong last digits (found by the
//! morok program corpus under rax-user). It now executes x87 instructions
//! with the SMIR interpreter's binary80 implementation. Every expected value
//! below follows the Intel SDM (Vol. 1, 8.1 and 8.3.2; Figure 8-9 for the
//! environment) and was confirmed on an x86-64 translator (Rosetta 2) with
//! the same instruction sequence.

use crate::common::*;

const SRC: u64 = 0x2000;
const DST: u64 = 0x3000;

/// Runs `code` (then HLT) with `src` at 0x2000 and returns the `len` bytes
/// written at 0x3000.
fn run(code: &[u8], src: &[u8], len: usize) -> Vec<u8> {
    let mut code = code.to_vec();
    code.push(0xF4);
    let (mut vcpu, mem) = setup_vm(&code, None);
    mem.write_slice(src, GuestAddress(SRC)).unwrap();
    run_until_hlt(&mut vcpu).unwrap();
    let mut out = vec![0u8; len];
    mem.read_slice(&mut out, GuestAddress(DST)).unwrap();
    out
}

/// A little-endian byte image as a big-endian hex string, as the SDM writes
/// binary80 values (sign and exponent first).
fn hex(bytes: &[u8]) -> String {
    bytes.iter().rev().map(|b| format!("{b:02x}")).collect()
}

const FNINIT: [u8; 2] = [0xDB, 0xE3];
const FLD1: [u8; 2] = [0xD9, 0xE8];
const FLDZ: [u8; 2] = [0xD9, 0xEE];
const FLD_M64_SRC: [u8; 7] = [0xDD, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00];
const FDIVP_ST1_ST0: [u8; 2] = [0xDE, 0xF9];
const FADDP_ST1_ST0: [u8; 2] = [0xDE, 0xC1];
const FSTP_M80_DST: [u8; 7] = [0xDB, 0x3C, 0x25, 0x00, 0x30, 0x00, 0x00];
const FLDCW_SRC_8: [u8; 7] = [0xD9, 0x2C, 0x25, 0x08, 0x20, 0x00, 0x00];
const FILD_M64_SRC: [u8; 7] = [0xDF, 0x2C, 0x25, 0x00, 0x20, 0x00, 0x00];
const FISTP_M64_DST: [u8; 7] = [0xDF, 0x3C, 0x25, 0x00, 0x30, 0x00, 0x00];
const FNSTENV_DST: [u8; 7] = [0xD9, 0x34, 0x25, 0x00, 0x30, 0x00, 0x00];

#[test]
fn division_keeps_the_64_bit_significand() {
    // 1/3 with the default FCW (64-bit precision, round to nearest):
    // significand AAAA...AAAB, not binary64's AAAA...A800.
    let code = [
        &FNINIT[..],
        &FLD1,
        &FLD_M64_SRC,
        &FDIVP_ST1_ST0,
        &FSTP_M80_DST,
    ]
    .concat();
    let out = run(&code, &3.0f64.to_le_bytes(), 10);
    assert_eq!(hex(&out), "3ffdaaaaaaaaaaaaaaab");
}

#[test]
fn precision_control_rounds_to_53_bits() {
    // FCW.PC = 10b (double precision): the same quotient rounded to 53 bits.
    let mut src = 3.0f64.to_le_bytes().to_vec();
    src.extend_from_slice(&0x027Fu16.to_le_bytes());
    let code = [
        &FNINIT[..],
        &FLDCW_SRC_8,
        &FLD1,
        &FLD_M64_SRC,
        &FDIVP_ST1_ST0,
        &FSTP_M80_DST,
    ]
    .concat();
    assert_eq!(hex(&run(&code, &src, 10)), "3ffdaaaaaaaaaaaaa800");
}

#[test]
fn addition_keeps_bits_binary64_drops() {
    // 1e16 + 1 needs 54 significand bits: exact in binary80, 1e16 in binary64.
    let code = [
        &FNINIT[..],
        &FLD_M64_SRC,
        &FLD1,
        &FADDP_ST1_ST0,
        &FSTP_M80_DST,
    ]
    .concat();
    let out = run(&code, &1e16f64.to_le_bytes(), 10);
    assert_eq!(hex(&out), "40348e1bc9bf04000400");
}

#[test]
fn integer_loads_and_stores_are_exact_to_64_bits() {
    for value in [i64::MAX, i64::MIN, (1 << 53) + 1, -((1 << 60) + 7)] {
        let code = [&FNINIT[..], &FILD_M64_SRC, &FISTP_M64_DST].concat();
        let out = run(&code, &value.to_le_bytes(), 8);
        assert_eq!(i64::from_le_bytes(out.try_into().unwrap()), value);
    }
}

#[test]
fn fnstenv_uses_the_32_bit_protected_mode_layout() {
    // After FLD1 (R7 valid) and FLDZ (R6 zero): FCW at 0, FSW at 4 (TOP = 6),
    // and the full tag word at 8, each field starting a doubleword.
    let code = [&FNINIT[..], &FLD1, &FLDZ, &FNSTENV_DST].concat();
    let env = run(&code, &[], 28);
    let word = |at: usize| u16::from_le_bytes([env[at], env[at + 1]]);
    assert_eq!(word(0), 0x037F, "FCW");
    assert_eq!(word(2), 0, "reserved");
    assert_eq!(word(4), 0x3000, "FSW");
    assert_eq!(word(8), 0x1FFF, "FTW");
}
