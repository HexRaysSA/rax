//! tests::simd tests

use super::*;
use crate::smir::lower::x86_64::test_support::host_c_helper_reference;
use crate::smir::lower::x86_64::*;

#[test]
fn legacy_vector_move_preserves_explicit_no_prefix_encoding() {
    let bytes = lower_single_hinted_op(
        OpKind::VMov {
            dst: VReg::Arch(ArchReg::X86(X86Reg::Xmm(1))),
            src: VReg::Arch(ArchReg::X86(X86Reg::Xmm(0))),
            width: VecWidth::V128,
        },
        X86OpHint::SseMov {
            prefix: X86SsePrefix::None,
            opcode: 0x28,
        },
    );

    assert!(
        bytes.windows(3).any(|window| window == [0x0F, 0x28, 0xC8]),
        "MOVAPS register transfer missing from {bytes:02X?}"
    );
    assert!(
        !bytes
            .windows(4)
            .any(|window| window == [0xF3, 0x0F, 0x28, 0xC8]),
        "explicit no-prefix MOVAPS was corrupted into a reserved F3 form: {bytes:02X?}"
    );
}
#[test]
fn vector_mem_helper_preservation_uses_canonical_full_state_encodings() {
    let mut lowerer = X86_64Lowerer::new();
    lowerer.emit_helper_vector_state(PhysReg::Rax, true);
    let stores = lowerer.code.data().to_vec();
    for expected in [
        &[0x62, 0xF1, 0xFE, 0x48, 0x7F, 0x40, 0x05][..],
        &[0x62, 0x61, 0xFE, 0x48, 0x7F, 0x78, 0x24][..],
        &[0xC4, 0xE1, 0xF8, 0x91, 0x80, 0x40, 0x09, 0x00, 0x00][..],
        &[0xC4, 0xE1, 0xF8, 0x91, 0xB8, 0x78, 0x09, 0x00, 0x00][..],
        &[0x0F, 0xAE, 0x98, 0x88, 0x09, 0x00, 0x00][..],
        &[0x0F, 0xAE, 0x90, 0x8C, 0x09, 0x00, 0x00][..],
    ] {
        assert!(
            stores
                .windows(expected.len())
                .any(|window| window == expected),
            "missing {expected:02X?} in {stores:02X?}"
        );
    }

    lowerer.code.clear();
    lowerer.emit_helper_vector_state(PhysReg::Rcx, false);
    let loads = lowerer.code.data();
    for expected in [
        &[0x62, 0xF1, 0xFE, 0x48, 0x6F, 0x41, 0x05][..],
        &[0x62, 0x61, 0xFE, 0x48, 0x6F, 0x79, 0x24][..],
        &[0xC4, 0xE1, 0xF8, 0x90, 0x81, 0x40, 0x09, 0x00, 0x00][..],
        &[0xC4, 0xE1, 0xF8, 0x90, 0xB9, 0x78, 0x09, 0x00, 0x00][..],
        &[0x0F, 0xAE, 0x91, 0x88, 0x09, 0x00, 0x00][..],
    ] {
        assert!(
            loads
                .windows(expected.len())
                .any(|window| window == expected),
            "missing {expected:02X?} in {loads:02X?}"
        );
    }
}
#[test]
fn vector_helper_narrow_opmask_mode_uses_avx512f_kmovw_only() {
    let mut lowerer = X86_64Lowerer::new();
    lowerer.set_narrow_vector_opmask_helpers(true);
    lowerer.emit_helper_vector_state(PhysReg::Rax, true);
    let stores = lowerer.code.data().to_vec();
    for expected in [
        &[0xC5, 0xF8, 0x91, 0x80, 0x40, 0x09, 0x00, 0x00][..],
        &[0xC5, 0xF8, 0x91, 0xB8, 0x78, 0x09, 0x00, 0x00][..],
    ] {
        assert!(
            stores
                .windows(expected.len())
                .any(|window| window == expected),
            "missing narrow opmask store {expected:02X?} in {stores:02X?}"
        );
    }
    assert!(
        !stores
            .windows(4)
            .any(|window| window == [0xC4, 0xE1, 0xF8, 0x91]),
        "narrow helper emitted AVX512BW KMOVQ: {stores:02X?}"
    );

    lowerer.code.clear();
    lowerer.emit_helper_vector_state(PhysReg::Rcx, false);
    let loads = lowerer.code.data();
    for expected in [
        &[0xC5, 0xF8, 0x90, 0x81, 0x40, 0x09, 0x00, 0x00][..],
        &[0xC5, 0xF8, 0x90, 0xB9, 0x78, 0x09, 0x00, 0x00][..],
    ] {
        assert!(
            loads
                .windows(expected.len())
                .any(|window| window == expected),
            "missing narrow opmask load {expected:02X?} in {loads:02X?}"
        );
    }
    assert!(
        !loads
            .windows(4)
            .any(|window| window == [0xC4, 0xE1, 0xF8, 0x90]),
        "narrow helper emitted AVX512BW KMOVQ: {loads:02X?}"
    );
}
#[test]
fn lifted_native_vector_instructions_reach_native_jit_lowering() {
    for (instruction, expected) in [
        (&[0x0F, 0x28, 0xC1][..], &[0x0F, 0x28, 0xC1][..]),
        (&[0xC5, 0xFC, 0x28, 0xC1][..], &[0xC5, 0xFC, 0x28, 0xC1][..]),
        (
            &[0x62, 0xE1, 0x7C, 0x48, 0x28, 0xE3][..],
            &[0x62, 0xE1, 0x7C, 0x48, 0x28, 0xE3][..],
        ),
        (
            &[0x62, 0xB1, 0x7C, 0x48, 0x28, 0xE3][..],
            &[0x62, 0xB1, 0x7C, 0x48, 0x28, 0xE3][..],
        ),
        (
            &[0x62, 0xA1, 0xFD, 0x48, 0x28, 0xE3][..],
            &[0x62, 0xA1, 0xFD, 0x48, 0x28, 0xE3][..],
        ),
        (
            &[0x62, 0xA1, 0x7C, 0x28, 0x28, 0xE3][..],
            &[0x62, 0xA1, 0x7C, 0x28, 0x28, 0xE3][..],
        ),
        (&[0x0F, 0x54, 0xCA][..], &[0x0F, 0x54, 0xCA][..]),
        (&[0x66, 0x0F, 0xDF, 0xDC][..], &[0x66, 0x0F, 0xDF, 0xDC][..]),
        (&[0xC5, 0xE8, 0x57, 0xCB][..], &[0xC5, 0xE8, 0x57, 0xCB][..]),
        (&[0xC5, 0xD5, 0xDF, 0xE6][..], &[0xC5, 0xD5, 0xDF, 0xE6][..]),
        (
            &[0x62, 0xA1, 0xD5, 0x40, 0x54, 0xE6][..],
            &[0x62, 0xA1, 0xD5, 0x40, 0x54, 0xE6][..],
        ),
        (
            &[0x62, 0xA1, 0xD5, 0x40, 0xEB, 0xE6][..],
            &[0x62, 0xA1, 0xD5, 0x40, 0xEB, 0xE6][..],
        ),
        (
            &[0x62, 0xA1, 0x55, 0x20, 0xEF, 0xE6][..],
            &[0x62, 0xA1, 0x55, 0x20, 0xEF, 0xE6][..],
        ),
        (&[0x66, 0x0F, 0xFC, 0xCA][..], &[0x66, 0x0F, 0xFC, 0xCA][..]),
        (&[0x66, 0x0F, 0xFB, 0xDC][..], &[0x66, 0x0F, 0xFB, 0xDC][..]),
        (&[0xC5, 0xE9, 0xFE, 0xCB][..], &[0xC5, 0xE9, 0xFE, 0xCB][..]),
        (&[0xC5, 0xD5, 0xF9, 0xE6][..], &[0xC5, 0xD5, 0xF9, 0xE6][..]),
        (
            &[0x62, 0xA1, 0xD5, 0x40, 0xD4, 0xE6][..],
            &[0x62, 0xA1, 0xD5, 0x40, 0xD4, 0xE6][..],
        ),
        (
            &[0x62, 0xA1, 0x55, 0x20, 0xFA, 0xE6][..],
            &[0x62, 0xA1, 0x55, 0x20, 0xFA, 0xE6][..],
        ),
        (&[0x66, 0x0F, 0xEC, 0xCA][..], &[0x66, 0x0F, 0xEC, 0xCA][..]),
        (&[0x66, 0x0F, 0xDD, 0xDC][..], &[0x66, 0x0F, 0xDD, 0xDC][..]),
        (&[0xC5, 0xE9, 0xE8, 0xCB][..], &[0xC5, 0xE9, 0xE8, 0xCB][..]),
        (&[0xC5, 0xD5, 0xD9, 0xE6][..], &[0xC5, 0xD5, 0xD9, 0xE6][..]),
        (
            &[0x62, 0xA1, 0x55, 0x40, 0xDC, 0xE6][..],
            &[0x62, 0xA1, 0x55, 0x40, 0xDC, 0xE6][..],
        ),
        (
            &[0x62, 0xA1, 0x55, 0x20, 0xED, 0xE6][..],
            &[0x62, 0xA1, 0x55, 0x20, 0xED, 0xE6][..],
        ),
        (
            &[0x62, 0x01, 0x35, 0x00, 0xD8, 0xC2][..],
            &[0x62, 0x01, 0x35, 0x00, 0xD8, 0xC2][..],
        ),
        (
            &[0x62, 0x01, 0x15, 0x40, 0xE9, 0xE6][..],
            &[0x62, 0x01, 0x15, 0x40, 0xE9, 0xE6][..],
        ),
        (
            &[0x62, 0xF1, 0xFD, 0x48, 0xEC, 0xC1][..],
            &[0x62, 0xF1, 0xFD, 0x48, 0xEC, 0xC1][..],
        ),
        (&[0x66, 0x0F, 0xD5, 0xCA][..], &[0x66, 0x0F, 0xD5, 0xCA][..]),
        (
            &[0x66, 0x0F, 0x38, 0x40, 0xDC][..],
            &[0x66, 0x0F, 0x38, 0x40, 0xDC][..],
        ),
        (&[0xC5, 0xE9, 0xD5, 0xCB][..], &[0xC5, 0xE9, 0xD5, 0xCB][..]),
        (
            &[0xC4, 0xE1, 0xF1, 0xD5, 0xC2][..],
            &[0xC4, 0xE1, 0xF1, 0xD5, 0xC2][..],
        ),
        (
            &[0xC4, 0xE2, 0x55, 0x40, 0xE6][..],
            &[0xC4, 0xE2, 0x55, 0x40, 0xE6][..],
        ),
        (
            &[0x62, 0xA1, 0x55, 0x40, 0xD5, 0xE6][..],
            &[0x62, 0xA1, 0x55, 0x40, 0xD5, 0xE6][..],
        ),
        (
            &[0x62, 0xA2, 0x55, 0x20, 0x40, 0xE6][..],
            &[0x62, 0xA2, 0x55, 0x20, 0x40, 0xE6][..],
        ),
        (
            &[0x62, 0x02, 0xB5, 0x40, 0x40, 0xC2][..],
            &[0x62, 0x02, 0xB5, 0x40, 0x40, 0xC2][..],
        ),
        (
            &[0x62, 0x02, 0x95, 0x00, 0x40, 0xE6][..],
            &[0x62, 0x02, 0x95, 0x00, 0x40, 0xE6][..],
        ),
        (
            &[0x66, 0x0F, 0x38, 0x1C, 0xCA][..],
            &[0x66, 0x0F, 0x38, 0x1C, 0xCA][..],
        ),
        (
            &[0x66, 0x0F, 0x38, 0x1D, 0xDC][..],
            &[0x66, 0x0F, 0x38, 0x1D, 0xDC][..],
        ),
        (
            &[0x66, 0x0F, 0x38, 0x1E, 0xEE][..],
            &[0x66, 0x0F, 0x38, 0x1E, 0xEE][..],
        ),
        (
            &[0xC4, 0xE2, 0x79, 0x1C, 0xCA][..],
            &[0xC4, 0xE2, 0x79, 0x1C, 0xCA][..],
        ),
        (
            &[0xC4, 0xE2, 0x7D, 0x1D, 0xDC][..],
            &[0xC4, 0xE2, 0x7D, 0x1D, 0xDC][..],
        ),
        (
            &[0xC4, 0xE2, 0x7D, 0x1E, 0xEE][..],
            &[0xC4, 0xE2, 0x7D, 0x1E, 0xEE][..],
        ),
        (
            &[0x62, 0xA2, 0x7D, 0x48, 0x1C, 0xE5][..],
            &[0x62, 0xA2, 0x7D, 0x48, 0x1C, 0xE5][..],
        ),
        (
            &[0x62, 0xA2, 0x7D, 0x28, 0x1D, 0xF7][..],
            &[0x62, 0xA2, 0x7D, 0x28, 0x1D, 0xF7][..],
        ),
        (
            &[0x62, 0x02, 0x7D, 0x48, 0x1E, 0xC1][..],
            &[0x62, 0x02, 0x7D, 0x48, 0x1E, 0xC1][..],
        ),
        (
            &[0x62, 0x02, 0xFD, 0x48, 0x1F, 0xD3][..],
            &[0x62, 0x02, 0xFD, 0x48, 0x1F, 0xD3][..],
        ),
        (
            &[0x62, 0x02, 0xFD, 0x08, 0x1F, 0xE5][..],
            &[0x62, 0x02, 0xFD, 0x08, 0x1F, 0xE5][..],
        ),
        (&[0x66, 0x0F, 0x64, 0xCA][..], &[0x66, 0x0F, 0x64, 0xCA][..]),
        (&[0x66, 0x0F, 0x65, 0xDC][..], &[0x66, 0x0F, 0x65, 0xDC][..]),
        (&[0x66, 0x0F, 0x66, 0xEE][..], &[0x66, 0x0F, 0x66, 0xEE][..]),
        (&[0x66, 0x0F, 0x74, 0xCA][..], &[0x66, 0x0F, 0x74, 0xCA][..]),
        (&[0x66, 0x0F, 0x75, 0xDC][..], &[0x66, 0x0F, 0x75, 0xDC][..]),
        (&[0x66, 0x0F, 0x76, 0xEE][..], &[0x66, 0x0F, 0x76, 0xEE][..]),
        (
            &[0x66, 0x0F, 0x38, 0x29, 0xCA][..],
            &[0x66, 0x0F, 0x38, 0x29, 0xCA][..],
        ),
        (
            &[0x66, 0x0F, 0x38, 0x37, 0xDC][..],
            &[0x66, 0x0F, 0x38, 0x37, 0xDC][..],
        ),
        (&[0xC5, 0xF1, 0x74, 0xC2][..], &[0xC5, 0xF1, 0x74, 0xC2][..]),
        (&[0xC5, 0xED, 0x65, 0xCB][..], &[0xC5, 0xED, 0x65, 0xCB][..]),
        (&[0xC5, 0xDD, 0x76, 0xDD][..], &[0xC5, 0xDD, 0x76, 0xDD][..]),
        (
            &[0xC4, 0xE2, 0x71, 0x29, 0xC2][..],
            &[0xC4, 0xE2, 0x71, 0x29, 0xC2][..],
        ),
        (
            &[0xC4, 0xE2, 0xF1, 0x29, 0xC2][..],
            &[0xC4, 0xE2, 0xF1, 0x29, 0xC2][..],
        ),
        (
            &[0xC4, 0xE2, 0x6D, 0x37, 0xCB][..],
            &[0xC4, 0xE2, 0x6D, 0x37, 0xCB][..],
        ),
        (&[0xC5, 0x31, 0x76, 0xC2][..], &[0xC5, 0x31, 0x76, 0xC2][..]),
        (&[0x66, 0x0F, 0x60, 0xCA][..], &[0x66, 0x0F, 0x60, 0xCA][..]),
        (&[0x66, 0x0F, 0x61, 0xDC][..], &[0x66, 0x0F, 0x61, 0xDC][..]),
        (&[0x66, 0x0F, 0x62, 0xEE][..], &[0x66, 0x0F, 0x62, 0xEE][..]),
        (&[0x66, 0x0F, 0x6C, 0xCA][..], &[0x66, 0x0F, 0x6C, 0xCA][..]),
        (&[0x66, 0x0F, 0x68, 0xCA][..], &[0x66, 0x0F, 0x68, 0xCA][..]),
        (&[0x66, 0x0F, 0x69, 0xDC][..], &[0x66, 0x0F, 0x69, 0xDC][..]),
        (&[0x66, 0x0F, 0x6A, 0xEE][..], &[0x66, 0x0F, 0x6A, 0xEE][..]),
        (&[0x66, 0x0F, 0x6D, 0xCA][..], &[0x66, 0x0F, 0x6D, 0xCA][..]),
        (&[0xC5, 0xF1, 0x60, 0xC2][..], &[0xC5, 0xF1, 0x60, 0xC2][..]),
        (&[0xC5, 0xED, 0x69, 0xCB][..], &[0xC5, 0xED, 0x69, 0xCB][..]),
        (
            &[0xC4, 0xE1, 0xF1, 0x61, 0xC2][..],
            &[0xC4, 0xE1, 0xF1, 0x61, 0xC2][..],
        ),
        (&[0xC5, 0x31, 0x6A, 0xC2][..], &[0xC5, 0x31, 0x6A, 0xC2][..]),
        (
            &[0x62, 0xA1, 0x75, 0x00, 0x60, 0xC2][..],
            &[0x62, 0xA1, 0x75, 0x00, 0x60, 0xC2][..],
        ),
        (
            &[0x62, 0xA1, 0xF5, 0x00, 0x61, 0xC2][..],
            &[0x62, 0xA1, 0xF5, 0x00, 0x61, 0xC2][..],
        ),
        (
            &[0x62, 0xF1, 0x75, 0x48, 0x62, 0xC2][..],
            &[0x62, 0xF1, 0x75, 0x48, 0x62, 0xC2][..],
        ),
        (
            &[0x62, 0xF1, 0xF5, 0x48, 0x6D, 0xC2][..],
            &[0x62, 0xF1, 0xF5, 0x48, 0x6D, 0xC2][..],
        ),
        (
            &[0x62, 0xF1, 0x75, 0x28, 0x69, 0xC2][..],
            &[0x62, 0xF1, 0x75, 0x28, 0x69, 0xC2][..],
        ),
        (
            &[0x62, 0xF2, 0x7D, 0xCC, 0xC4, 0xCA][..],
            &[0x62, 0xF2, 0x7D, 0xCC, 0xC4, 0xCA][..],
        ),
        (
            &[0x62, 0xA2, 0xFD, 0x4F, 0xC4, 0xCA][..],
            &[0x62, 0xA2, 0xFD, 0x4F, 0xC4, 0xCA][..],
        ),
        (
            &[0x62, 0xF2, 0x6E, 0xCC, 0x52, 0xCB][..],
            &[0x62, 0xF2, 0x6E, 0xCC, 0x52, 0xCB][..],
        ),
        (
            &[0x62, 0xA2, 0x76, 0x27, 0x52, 0xC2][..],
            &[0x62, 0xA2, 0x76, 0x27, 0x52, 0xC2][..],
        ),
        (
            &[0x62, 0xF2, 0xED, 0xCC, 0xB4, 0xCB][..],
            &[0x62, 0xF2, 0xED, 0xCC, 0xB4, 0xCB][..],
        ),
        (
            &[0x62, 0xA2, 0xF5, 0x47, 0xB5, 0xC2][..],
            &[0x62, 0xA2, 0xF5, 0x47, 0xB5, 0xC2][..],
        ),
        (
            &[0x62, 0xF2, 0x6D, 0xCC, 0x50, 0xCB][..],
            &[0x62, 0xF2, 0x6D, 0xCC, 0x50, 0xCB][..],
        ),
        (
            &[0x62, 0xA2, 0x75, 0x47, 0x53, 0xC2][..],
            &[0x62, 0xA2, 0x75, 0x47, 0x53, 0xC2][..],
        ),
        (
            &[0x62, 0xF2, 0x65, 0x48, 0x8F, 0xEA][..],
            &[0x62, 0xF2, 0x65, 0x48, 0x8F, 0xEA][..],
        ),
        (
            &[0x62, 0xF2, 0x65, 0x49, 0x8F, 0xEA][..],
            &[0x62, 0xF2, 0x65, 0x49, 0x8F, 0xEA][..],
        ),
        (
            &[0x62, 0xF2, 0x7D, 0xCC, 0x54, 0xCA][..],
            &[0x62, 0xF2, 0x7D, 0xCC, 0x54, 0xCA][..],
        ),
        (
            &[0x62, 0xA2, 0xFD, 0x4F, 0x55, 0xCA][..],
            &[0x62, 0xA2, 0xFD, 0x4F, 0x55, 0xCA][..],
        ),
        (
            &[0x62, 0xF2, 0x6D, 0x48, 0x47, 0xCB][..],
            &[0x62, 0xF2, 0x6D, 0x48, 0x47, 0xCB][..],
        ),
        (
            &[0x62, 0xF2, 0x6D, 0xCC, 0x47, 0xCB][..],
            &[0x62, 0xF2, 0x6D, 0xCC, 0x47, 0xCB][..],
        ),
        (
            &[0x62, 0xF2, 0x6D, 0x48, 0x15, 0xCB][..],
            &[0x62, 0xF2, 0x6D, 0x48, 0x15, 0xCB][..],
        ),
        (
            &[0x62, 0xF2, 0x6D, 0xCC, 0x15, 0xCB][..],
            &[0x62, 0xF2, 0x6D, 0xCC, 0x15, 0xCB][..],
        ),
        (
            &[0x62, 0xF1, 0x75, 0x48, 0x72, 0xCA, 0x07][..],
            &[0x62, 0xF1, 0x75, 0x48, 0x72, 0xCA, 0x07][..],
        ),
        (
            &[0x62, 0xF1, 0x75, 0xCC, 0x72, 0xCA, 0x07][..],
            &[0x62, 0xF1, 0x75, 0xCC, 0x72, 0xCA, 0x07][..],
        ),
        (
            &[0x62, 0xB1, 0xF5, 0x40, 0x72, 0xC2, 0x3F][..],
            &[0x62, 0xB1, 0xF5, 0x40, 0x72, 0xC2, 0x3F][..],
        ),
        (
            &[0x62, 0xF3, 0x6D, 0x48, 0x25, 0xCB, 0x96][..],
            &[0x62, 0xF3, 0x6D, 0x48, 0x25, 0xCB, 0x96][..],
        ),
        (
            &[0x62, 0xF3, 0x6D, 0xCC, 0x25, 0xCB, 0x96][..],
            &[0x62, 0xF3, 0x6D, 0xCC, 0x25, 0xCB, 0x96][..],
        ),
        (
            &[0x62, 0xA3, 0xF5, 0x27, 0x25, 0xC2, 0xE4][..],
            &[0x62, 0xA3, 0xF5, 0x27, 0x25, 0xC2, 0xE4][..],
        ),
        (
            &[0x62, 0xF3, 0x6D, 0x48, 0x71, 0xCB, 0x07][..],
            &[0x62, 0xF3, 0x6D, 0x48, 0x71, 0xCB, 0x07][..],
        ),
        (
            &[0x62, 0xF3, 0x6D, 0xCC, 0x71, 0xCB, 0x07][..],
            &[0x62, 0xF3, 0x6D, 0xCC, 0x71, 0xCB, 0x07][..],
        ),
        (
            &[0x62, 0xF2, 0x6D, 0x48, 0x71, 0xCB][..],
            &[0x62, 0xF2, 0x6D, 0x48, 0x71, 0xCB][..],
        ),
        (
            &[0x62, 0xF2, 0x6D, 0xCC, 0x71, 0xCB][..],
            &[0x62, 0xF2, 0x6D, 0xCC, 0x71, 0xCB][..],
        ),
        (
            &[0x62, 0xF2, 0xED, 0x48, 0x83, 0xCB][..],
            &[0x62, 0xF2, 0xED, 0x48, 0x83, 0xCB][..],
        ),
        (
            &[0x62, 0xF2, 0xED, 0xCC, 0x83, 0xCB][..],
            &[0x62, 0xF2, 0xED, 0xCC, 0x83, 0xCB][..],
        ),
        (
            &[0x62, 0xA2, 0x75, 0x40, 0xDC, 0xC2][..],
            &[0x62, 0xA2, 0x75, 0x40, 0xDC, 0xC2][..],
        ),
        (
            &[0x62, 0xF2, 0x6D, 0x48, 0xDD, 0xCB][..],
            &[0x62, 0xF2, 0x6D, 0x48, 0xDD, 0xCB][..],
        ),
        (
            &[0xC4, 0xE2, 0x55, 0xDE, 0xE6][..],
            &[0xC4, 0xE2, 0x55, 0xDE, 0xE6][..],
        ),
        (
            &[0xC4, 0xC2, 0x39, 0xDF, 0xF9][..],
            &[0xC4, 0xC2, 0x39, 0xDF, 0xF9][..],
        ),
        (
            &[0xC4, 0x42, 0x79, 0xDB, 0xC8][..],
            &[0xC4, 0x42, 0x79, 0xDB, 0xC8][..],
        ),
        (
            &[0xC4, 0x43, 0x79, 0xDF, 0xDA, 0x5A][..],
            &[0xC4, 0x43, 0x79, 0xDF, 0xDA, 0x5A][..],
        ),
        (
            &[0xC4, 0x42, 0x7F, 0xCC, 0xCA][..],
            &[0xC4, 0x42, 0x7F, 0xCC, 0xCA][..],
        ),
        (
            &[0xC4, 0x42, 0x7F, 0xCD, 0xCA][..],
            &[0xC4, 0x42, 0x7F, 0xCD, 0xCA][..],
        ),
        (
            &[0xC4, 0x42, 0x27, 0xCB, 0xCA][..],
            &[0xC4, 0x42, 0x27, 0xCB, 0xCA][..],
        ),
        (
            &[0xC4, 0x42, 0x20, 0xDA, 0xCA][..],
            &[0xC4, 0x42, 0x20, 0xDA, 0xCA][..],
        ),
        (
            &[0xC4, 0x42, 0x21, 0xDA, 0xCA][..],
            &[0xC4, 0x42, 0x21, 0xDA, 0xCA][..],
        ),
        (
            &[0xC4, 0x43, 0x21, 0xDE, 0xCA, 0x3E][..],
            &[0xC4, 0x43, 0x21, 0xDE, 0xCA, 0x3E][..],
        ),
        (
            &[0xC4, 0xE2, 0x6A, 0xDA, 0xCB][..],
            &[0xC4, 0xE2, 0x6A, 0xDA, 0xCB][..],
        ),
        (
            &[0xC4, 0xE2, 0x56, 0xDA, 0xE6][..],
            &[0xC4, 0xE2, 0x56, 0xDA, 0xE6][..],
        ),
        (
            &[0xC4, 0xC2, 0x3B, 0xDA, 0xF9][..],
            &[0xC4, 0xC2, 0x3B, 0xDA, 0xF9][..],
        ),
        (
            &[0xC4, 0x42, 0x27, 0xDA, 0xD4][..],
            &[0xC4, 0x42, 0x27, 0xDA, 0xD4][..],
        ),
        (
            &[0xC5, 0xF1, 0x71, 0xD2, 0x03][..],
            &[0xC5, 0xF1, 0x71, 0xD2, 0x03][..],
        ),
        (
            &[0xC5, 0xDD, 0x71, 0xE5, 0x04][..],
            &[0xC5, 0xDD, 0x71, 0xE5, 0x04][..],
        ),
        (
            &[0x62, 0xB1, 0x75, 0x40, 0x72, 0xF2, 0x05][..],
            &[0x62, 0xB1, 0x75, 0x40, 0x72, 0xF2, 0x05][..],
        ),
        (
            &[0x62, 0xB1, 0xF5, 0x00, 0x72, 0xE2, 0x09][..],
            &[0x62, 0xB1, 0xF5, 0x00, 0x72, 0xE2, 0x09][..],
        ),
        (
            &[0xC4, 0xC1, 0x31, 0x73, 0xFA, 0x07][..],
            &[0xC4, 0xC1, 0x31, 0x73, 0xFA, 0x07][..],
        ),
        (
            &[0xC4, 0xC1, 0x25, 0x73, 0xDC, 0x08][..],
            &[0xC4, 0xC1, 0x25, 0x73, 0xDC, 0x08][..],
        ),
        (&[0xC5, 0xE9, 0xD1, 0xCB][..], &[0xC5, 0xE9, 0xD1, 0xCB][..]),
        (&[0xC5, 0xD5, 0xE2, 0xE6][..], &[0xC5, 0xD5, 0xE2, 0xE6][..]),
        (
            &[0x62, 0xA1, 0xED, 0x40, 0xF3, 0xCB][..],
            &[0x62, 0xA1, 0xED, 0x40, 0xF3, 0xCB][..],
        ),
        (
            &[0x62, 0xA1, 0xF5, 0x00, 0xE2, 0xC2][..],
            &[0x62, 0xA1, 0xF5, 0x00, 0xE2, 0xC2][..],
        ),
        (&[0x66, 0x0F, 0x63, 0xCA][..], &[0x66, 0x0F, 0x63, 0xCA][..]),
        (&[0x66, 0x0F, 0x67, 0xDC][..], &[0x66, 0x0F, 0x67, 0xDC][..]),
        (&[0x66, 0x0F, 0x6B, 0xEE][..], &[0x66, 0x0F, 0x6B, 0xEE][..]),
        (
            &[0x66, 0x0F, 0x38, 0x2B, 0xCA][..],
            &[0x66, 0x0F, 0x38, 0x2B, 0xCA][..],
        ),
        (&[0xC5, 0xED, 0x63, 0xCB][..], &[0xC5, 0xED, 0x63, 0xCB][..]),
        (&[0xC5, 0xD5, 0x67, 0xE6][..], &[0xC5, 0xD5, 0x67, 0xE6][..]),
        (
            &[0xC4, 0xC1, 0x3D, 0x6B, 0xF9][..],
            &[0xC4, 0xC1, 0x3D, 0x6B, 0xF9][..],
        ),
        (
            &[0xC4, 0x42, 0x25, 0x2B, 0xD4][..],
            &[0xC4, 0x42, 0x25, 0x2B, 0xD4][..],
        ),
        (
            &[0xC4, 0xE1, 0xF1, 0x63, 0xC2][..],
            &[0xC4, 0xE1, 0xF1, 0x63, 0xC2][..],
        ),
        (
            &[0x62, 0xA1, 0x75, 0x40, 0x63, 0xC2][..],
            &[0x62, 0xA1, 0x75, 0x40, 0x63, 0xC2][..],
        ),
        (
            &[0x62, 0xA1, 0x5D, 0x40, 0x67, 0xDD][..],
            &[0x62, 0xA1, 0x5D, 0x40, 0x67, 0xDD][..],
        ),
        (
            &[0x62, 0x81, 0x45, 0x40, 0x6B, 0xF0][..],
            &[0x62, 0x81, 0x45, 0x40, 0x6B, 0xF0][..],
        ),
        (
            &[0x62, 0x02, 0x2D, 0x40, 0x2B, 0xCB][..],
            &[0x62, 0x02, 0x2D, 0x40, 0x2B, 0xCB][..],
        ),
        (
            &[0x62, 0xA1, 0xF5, 0x40, 0x63, 0xC2][..],
            &[0x62, 0xA1, 0xF5, 0x40, 0x63, 0xC2][..],
        ),
        (
            &[0x66, 0x0F, 0x38, 0x00, 0xCA][..],
            &[0x66, 0x0F, 0x38, 0x00, 0xCA][..],
        ),
        (
            &[0xC4, 0xE2, 0x59, 0x00, 0xDD][..],
            &[0xC4, 0xE2, 0x59, 0x00, 0xDD][..],
        ),
        (
            &[0xC4, 0xC2, 0x45, 0x00, 0xF0][..],
            &[0xC4, 0xC2, 0x45, 0x00, 0xF0][..],
        ),
        (
            &[0xC4, 0xE2, 0xD9, 0x00, 0xDD][..],
            &[0xC4, 0xE2, 0xD9, 0x00, 0xDD][..],
        ),
        (
            &[0x62, 0xA2, 0x75, 0x40, 0x00, 0xC2][..],
            &[0x62, 0xA2, 0x75, 0x40, 0x00, 0xC2][..],
        ),
        (
            &[0x62, 0x52, 0x2D, 0x08, 0x00, 0xCB][..],
            &[0x62, 0x52, 0x2D, 0x08, 0x00, 0xCB][..],
        ),
        (
            &[0x62, 0x52, 0x15, 0x28, 0x00, 0xE6][..],
            &[0x62, 0x52, 0x15, 0x28, 0x00, 0xE6][..],
        ),
        (
            &[0x62, 0xA2, 0xF5, 0x40, 0x00, 0xC2][..],
            &[0x62, 0xA2, 0xF5, 0x40, 0x00, 0xC2][..],
        ),
        (
            &[0x66, 0x0F, 0x38, 0x01, 0xCA][..],
            &[0x66, 0x0F, 0x38, 0x01, 0xCA][..],
        ),
        (
            &[0x66, 0x0F, 0x38, 0x02, 0xDC][..],
            &[0x66, 0x0F, 0x38, 0x02, 0xDC][..],
        ),
        (
            &[0x66, 0x0F, 0x38, 0x03, 0xEE][..],
            &[0x66, 0x0F, 0x38, 0x03, 0xEE][..],
        ),
        (
            &[0x66, 0x41, 0x0F, 0x38, 0x05, 0xF8][..],
            &[0x66, 0x41, 0x0F, 0x38, 0x05, 0xF8][..],
        ),
        (
            &[0x66, 0x45, 0x0F, 0x38, 0x06, 0xCA][..],
            &[0x66, 0x45, 0x0F, 0x38, 0x06, 0xCA][..],
        ),
        (
            &[0x66, 0x45, 0x0F, 0x38, 0x07, 0xDC][..],
            &[0x66, 0x45, 0x0F, 0x38, 0x07, 0xDC][..],
        ),
        (
            &[0xC4, 0xE2, 0x69, 0x01, 0xCB][..],
            &[0xC4, 0xE2, 0x69, 0x01, 0xCB][..],
        ),
        (
            &[0xC4, 0xE2, 0x55, 0x02, 0xE6][..],
            &[0xC4, 0xE2, 0x55, 0x02, 0xE6][..],
        ),
        (
            &[0xC4, 0xC2, 0x3D, 0x03, 0xF9][..],
            &[0xC4, 0xC2, 0x3D, 0x03, 0xF9][..],
        ),
        (
            &[0xC4, 0x42, 0x25, 0x05, 0xD4][..],
            &[0xC4, 0x42, 0x25, 0x05, 0xD4][..],
        ),
        (
            &[0xC4, 0x42, 0x0D, 0x06, 0xEF][..],
            &[0xC4, 0x42, 0x0D, 0x06, 0xEF][..],
        ),
        (
            &[0xC4, 0xE2, 0x71, 0x07, 0xC2][..],
            &[0xC4, 0xE2, 0x71, 0x07, 0xC2][..],
        ),
        (
            &[0xC4, 0xE2, 0xE9, 0x01, 0xCB][..],
            &[0xC4, 0xE2, 0xE9, 0x01, 0xCB][..],
        ),
        (
            &[0x66, 0x0F, 0x38, 0x0B, 0xCA][..],
            &[0x66, 0x0F, 0x38, 0x0B, 0xCA][..],
        ),
        (
            &[0xC4, 0xE2, 0xE9, 0x0B, 0xCB][..],
            &[0xC4, 0xE2, 0x69, 0x0B, 0xCB][..],
        ),
        (
            &[0xC4, 0xE2, 0x6D, 0x0B, 0xCB][..],
            &[0xC4, 0xE2, 0x6D, 0x0B, 0xCB][..],
        ),
        (
            &[0x62, 0xA2, 0x75, 0x40, 0x0B, 0xC2][..],
            &[0x62, 0xA2, 0x75, 0x40, 0x0B, 0xC2][..],
        ),
        (
            &[0x62, 0xA2, 0xF5, 0x00, 0x0B, 0xC2][..],
            &[0x62, 0xA2, 0x75, 0x00, 0x0B, 0xC2][..],
        ),
        (
            &[0x66, 0x0F, 0x38, 0x08, 0xCA][..],
            &[0x66, 0x0F, 0x38, 0x08, 0xCA][..],
        ),
        (
            &[0xC4, 0xE2, 0xE9, 0x09, 0xCB][..],
            &[0xC4, 0xE2, 0x69, 0x09, 0xCB][..],
        ),
        (
            &[0xC4, 0xE2, 0x6D, 0x0A, 0xCB][..],
            &[0xC4, 0xE2, 0x6D, 0x0A, 0xCB][..],
        ),
        (&[0x66, 0x0F, 0xDA, 0xCA][..], &[0x66, 0x0F, 0xDA, 0xCA][..]),
        (
            &[0xC4, 0xE2, 0xE9, 0x3A, 0xCB][..],
            &[0xC4, 0xE2, 0x69, 0x3A, 0xCB][..],
        ),
        (&[0xC5, 0xED, 0xEE, 0xCB][..], &[0xC5, 0xED, 0xEE, 0xCB][..]),
        (
            &[0x62, 0xA2, 0xF5, 0x40, 0x38, 0xC2][..],
            &[0x62, 0xA2, 0x75, 0x40, 0x38, 0xC2][..],
        ),
        (
            &[0x62, 0xA2, 0xF5, 0x40, 0x3F, 0xC2][..],
            &[0x62, 0xA2, 0xF5, 0x40, 0x3F, 0xC2][..],
        ),
        (&[0x66, 0x0F, 0xE5, 0xCA][..], &[0x66, 0x0F, 0xE5, 0xCA][..]),
        (&[0x66, 0x0F, 0xE4, 0xEF][..], &[0x66, 0x0F, 0xE4, 0xEF][..]),
        (
            &[0xC4, 0xE1, 0xE9, 0xE5, 0xCB][..],
            &[0xC5, 0xE9, 0xE5, 0xCB][..],
        ),
        (&[0xC5, 0xED, 0xE4, 0xCB][..], &[0xC5, 0xED, 0xE4, 0xCB][..]),
        (
            &[0x62, 0xA1, 0x75, 0x40, 0xE5, 0xC2][..],
            &[0x62, 0xA1, 0x75, 0x40, 0xE5, 0xC2][..],
        ),
        (
            &[0x62, 0xA1, 0xF5, 0x00, 0xE4, 0xC2][..],
            &[0x62, 0xA1, 0x75, 0x00, 0xE4, 0xC2][..],
        ),
        (&[0x66, 0x0F, 0xE0, 0xCA][..], &[0x66, 0x0F, 0xE0, 0xCA][..]),
        (&[0x66, 0x0F, 0xE3, 0xDC][..], &[0x66, 0x0F, 0xE3, 0xDC][..]),
        (
            &[0xC4, 0xE1, 0xF1, 0xE0, 0xC2][..],
            &[0xC4, 0xE1, 0xF1, 0xE0, 0xC2][..],
        ),
        (&[0xC5, 0xED, 0xE3, 0xCB][..], &[0xC5, 0xED, 0xE3, 0xCB][..]),
        (
            &[0x62, 0xA1, 0x75, 0x40, 0xE0, 0xC2][..],
            &[0x62, 0xA1, 0x75, 0x40, 0xE0, 0xC2][..],
        ),
        (
            &[0x62, 0xA1, 0xF5, 0x00, 0xE3, 0xC2][..],
            &[0x62, 0xA1, 0xF5, 0x00, 0xE3, 0xC2][..],
        ),
        (&[0x66, 0x0F, 0xF6, 0xCA][..], &[0x66, 0x0F, 0xF6, 0xCA][..]),
        (
            &[0xC4, 0xE1, 0xE9, 0xF6, 0xCB][..],
            &[0xC4, 0xE1, 0xE9, 0xF6, 0xCB][..],
        ),
        (&[0xC5, 0xED, 0xF6, 0xCB][..], &[0xC5, 0xED, 0xF6, 0xCB][..]),
        (
            &[0x62, 0xA1, 0x75, 0x40, 0xF6, 0xC2][..],
            &[0x62, 0xA1, 0x75, 0x40, 0xF6, 0xC2][..],
        ),
        (
            &[0x62, 0xA1, 0xF5, 0x00, 0xF6, 0xC2][..],
            &[0x62, 0xA1, 0xF5, 0x00, 0xF6, 0xC2][..],
        ),
        (
            &[0x66, 0x0F, 0x38, 0x41, 0xCA][..],
            &[0x66, 0x0F, 0x38, 0x41, 0xCA][..],
        ),
        (
            &[0xC4, 0xE2, 0xF9, 0x41, 0xCB][..],
            &[0xC4, 0xE2, 0x79, 0x41, 0xCB][..],
        ),
        (
            &[0x66, 0x45, 0x0F, 0x3A, 0x42, 0xCA, 0xE7][..],
            &[0x66, 0x45, 0x0F, 0x3A, 0x42, 0xCA, 0xE7][..],
        ),
        (
            &[0xC4, 0x43, 0xA1, 0x42, 0xCA, 0xE7][..],
            &[0xC4, 0x43, 0xA1, 0x42, 0xCA, 0xE7][..],
        ),
        (
            &[0xC4, 0x43, 0x25, 0x42, 0xCA, 0xE7][..],
            &[0xC4, 0x43, 0x25, 0x42, 0xCA, 0xE7][..],
        ),
        (
            &[0x62, 0xA3, 0x76, 0xC3, 0x42, 0xC2, 0x3F][..],
            &[0x62, 0xA3, 0x76, 0xC3, 0x42, 0xC2, 0x3F][..],
        ),
        (
            &[0x62, 0x53, 0x2E, 0x0A, 0x42, 0xCB, 0xE7][..],
            &[0x62, 0x53, 0x2E, 0x0A, 0x42, 0xCB, 0xE7][..],
        ),
        (
            &[0x66, 0x0F, 0x38, 0x04, 0xCA][..],
            &[0x66, 0x0F, 0x38, 0x04, 0xCA][..],
        ),
        (
            &[0xC4, 0xE2, 0xD9, 0x04, 0xDB][..],
            &[0xC4, 0xE2, 0xD9, 0x04, 0xDB][..],
        ),
        (
            &[0xC4, 0xC2, 0x4D, 0x04, 0xF0][..],
            &[0xC4, 0xC2, 0x4D, 0x04, 0xF0][..],
        ),
        (
            &[0x62, 0xA2, 0x75, 0x40, 0x04, 0xC2][..],
            &[0x62, 0xA2, 0x75, 0x40, 0x04, 0xC2][..],
        ),
        (
            &[0x62, 0x52, 0xAD, 0x08, 0x04, 0xCB][..],
            &[0x62, 0x52, 0xAD, 0x08, 0x04, 0xCB][..],
        ),
    ] {
        let mut block = instruction.to_vec();
        block.push(0xF4);
        let (lowered, _) = lower_rex2_block(&block);
        assert!(
            lowered
                .windows(expected.len())
                .any(|window| window == expected),
            "lift/JIT round trip omitted {instruction:02X?}: {lowered:02X?}"
        );
    }
}
#[test]
fn lower_packed_integer_minmax_emits_exact_bytes_canonicalizes_wig_and_rejects_malformed() {
    let xmm = |index| VReg::Arch(ArchReg::X86(X86Reg::Xmm(index)));
    let ymm = |index| VReg::Arch(ArchReg::X86(X86Reg::Ymm(index)));
    let zmm = |index| VReg::Arch(ArchReg::X86(X86Reg::Zmm(index)));
    let minmax = |dst, src1, src2, elem, lanes, op, signed| OpKind::VLane {
        dst,
        src1,
        src2,
        elem,
        lanes,
        op,
        signed,
        set_ovf: false,
    };

    for (name, kind, hint, expected) in [
        (
            "PMINUB xmm1,xmm2",
            minmax(
                xmm(1),
                xmm(1),
                xmm(2),
                VecElementType::I8,
                16,
                VLaneOp::Min,
                false,
            ),
            X86OpHint::SseOp {
                prefix: X86SsePrefix::OpSize,
                opcode: 0xDA,
            },
            &[0x66, 0x0F, 0xDA, 0xCA][..],
        ),
        (
            "PMAXSD xmm8,xmm9",
            minmax(
                xmm(8),
                xmm(8),
                xmm(9),
                VecElementType::I32,
                4,
                VLaneOp::Max,
                true,
            ),
            X86OpHint::SseOp {
                prefix: X86SsePrefix::OpSize,
                opcode: 0x3D,
            },
            &[0x66, 0x45, 0x0F, 0x38, 0x3D, 0xC1][..],
        ),
        (
            "VEX.W1-hinted VPMINUW xmm1,xmm2,xmm3 canonicalized to W0",
            minmax(
                xmm(1),
                xmm(2),
                xmm(3),
                VecElementType::I16,
                8,
                VLaneOp::Min,
                false,
            ),
            X86OpHint::VexOp {
                map: X86VecMap::Map0F38,
                pp: X86SsePrefix::OpSize,
                opcode: 0x3A,
                width: VecWidth::V128,
                w: true,
            },
            &[0xC4, 0xE2, 0x69, 0x3A, 0xCB][..],
        ),
        (
            "VEX.256 VPMAXSW ymm1,ymm2,ymm3",
            minmax(
                ymm(1),
                ymm(2),
                ymm(3),
                VecElementType::I16,
                16,
                VLaneOp::Max,
                true,
            ),
            X86OpHint::VexOp {
                map: X86VecMap::Map0F,
                pp: X86SsePrefix::OpSize,
                opcode: 0xEE,
                width: VecWidth::V256,
                w: false,
            },
            &[0xC5, 0xED, 0xEE, 0xCB][..],
        ),
        (
            "EVEX.W1-hinted VPMINSB zmm16,zmm17,zmm18 canonicalized to W0",
            minmax(
                zmm(16),
                zmm(17),
                zmm(18),
                VecElementType::I8,
                64,
                VLaneOp::Min,
                true,
            ),
            X86OpHint::EvexOp {
                map: X86VecMap::Map0F38,
                pp: X86SsePrefix::OpSize,
                opcode: 0x38,
                width: VecWidth::V512,
                w: true,
            },
            &[0x62, 0xA2, 0x75, 0x40, 0x38, 0xC2][..],
        ),
        (
            "EVEX.W1 VPMAXUQ zmm16,zmm17,zmm18",
            minmax(
                zmm(16),
                zmm(17),
                zmm(18),
                VecElementType::I64,
                8,
                VLaneOp::Max,
                false,
            ),
            X86OpHint::EvexOp {
                map: X86VecMap::Map0F38,
                pp: X86SsePrefix::OpSize,
                opcode: 0x3F,
                width: VecWidth::V512,
                w: true,
            },
            &[0x62, 0xA2, 0xF5, 0x40, 0x3F, 0xC2][..],
        ),
        (
            "EVEX.128 VPMINSD xmm16,xmm17,xmm18",
            minmax(
                xmm(16),
                xmm(17),
                xmm(18),
                VecElementType::I32,
                4,
                VLaneOp::Min,
                true,
            ),
            X86OpHint::EvexOp {
                map: X86VecMap::Map0F38,
                pp: X86SsePrefix::OpSize,
                opcode: 0x39,
                width: VecWidth::V128,
                w: false,
            },
            &[0x62, 0xA2, 0x75, 0x00, 0x39, 0xC2][..],
        ),
    ] {
        let code = lower_single_hinted_op(kind, hint);
        assert!(
            code.windows(expected.len())
                .any(|window| window == expected),
            "{name}: missing {expected:02X?} in {code:02X?}"
        );
    }

    assert!(matches!(
        lower_single_op_err(minmax(
            xmm(1),
            xmm(1),
            xmm(2),
            VecElementType::I8,
            16,
            VLaneOp::Min,
            false,
        )),
        LowerError::UnsupportedOp { .. }
    ));

    for (kind, hint) in [
        (
            minmax(
                xmm(1),
                xmm(2),
                xmm(3),
                VecElementType::I8,
                16,
                VLaneOp::Min,
                false,
            ),
            X86OpHint::SseOp {
                prefix: X86SsePrefix::OpSize,
                opcode: 0xDA,
            },
        ),
        (
            minmax(
                xmm(1),
                xmm(1),
                xmm(2),
                VecElementType::I8,
                16,
                VLaneOp::Min,
                true,
            ),
            X86OpHint::SseOp {
                prefix: X86SsePrefix::OpSize,
                opcode: 0xDA,
            },
        ),
        (
            OpKind::VLane {
                dst: xmm(1),
                src1: xmm(1),
                src2: xmm(2),
                elem: VecElementType::I8,
                lanes: 16,
                op: VLaneOp::Min,
                signed: false,
                set_ovf: true,
            },
            X86OpHint::SseOp {
                prefix: X86SsePrefix::OpSize,
                opcode: 0xDA,
            },
        ),
        (
            minmax(
                xmm(1),
                xmm(1),
                xmm(2),
                VecElementType::I64,
                2,
                VLaneOp::Max,
                false,
            ),
            X86OpHint::SseOp {
                prefix: X86SsePrefix::OpSize,
                opcode: 0x3F,
            },
        ),
        (
            minmax(
                ymm(1),
                ymm(2),
                ymm(3),
                VecElementType::I16,
                16,
                VLaneOp::Max,
                true,
            ),
            X86OpHint::VexOp {
                map: X86VecMap::Map0F38,
                pp: X86SsePrefix::OpSize,
                opcode: 0xEE,
                width: VecWidth::V256,
                w: false,
            },
        ),
        (
            minmax(
                ymm(16),
                ymm(17),
                ymm(18),
                VecElementType::I16,
                16,
                VLaneOp::Max,
                true,
            ),
            X86OpHint::VexOp {
                map: X86VecMap::Map0F,
                pp: X86SsePrefix::OpSize,
                opcode: 0xEE,
                width: VecWidth::V256,
                w: false,
            },
        ),
        (
            minmax(
                zmm(1),
                zmm(2),
                zmm(3),
                VecElementType::I16,
                32,
                VLaneOp::Max,
                true,
            ),
            X86OpHint::VexOp {
                map: X86VecMap::Map0F,
                pp: X86SsePrefix::OpSize,
                opcode: 0xEE,
                width: VecWidth::V512,
                w: false,
            },
        ),
        (
            minmax(
                xmm(16),
                xmm(17),
                xmm(18),
                VecElementType::I32,
                4,
                VLaneOp::Min,
                true,
            ),
            X86OpHint::EvexOp {
                map: X86VecMap::Map0F38,
                pp: X86SsePrefix::OpSize,
                opcode: 0x39,
                width: VecWidth::V128,
                w: true,
            },
        ),
        (
            minmax(
                zmm(16),
                zmm(17),
                zmm(18),
                VecElementType::I64,
                8,
                VLaneOp::Max,
                false,
            ),
            X86OpHint::EvexOp {
                map: X86VecMap::Map0F38,
                pp: X86SsePrefix::OpSize,
                opcode: 0x3F,
                width: VecWidth::V512,
                w: false,
            },
        ),
        (
            minmax(
                zmm(16),
                zmm(17),
                zmm(18),
                VecElementType::I64,
                8,
                VLaneOp::Max,
                false,
            ),
            X86OpHint::EvexOp {
                map: X86VecMap::Map0F,
                pp: X86SsePrefix::OpSize,
                opcode: 0x3F,
                width: VecWidth::V512,
                w: true,
            },
        ),
        (
            minmax(
                ymm(16),
                ymm(17),
                ymm(18),
                VecElementType::I8,
                32,
                VLaneOp::Min,
                true,
            ),
            X86OpHint::EvexOp {
                map: X86VecMap::Map0F38,
                pp: X86SsePrefix::OpSize,
                opcode: 0x38,
                width: VecWidth::V128,
                w: false,
            },
        ),
        (
            minmax(
                VReg::Virtual(crate::smir::ir::types::VirtualId(71)),
                xmm(1),
                xmm(2),
                VecElementType::I8,
                16,
                VLaneOp::Min,
                false,
            ),
            X86OpHint::SseOp {
                prefix: X86SsePrefix::OpSize,
                opcode: 0xDA,
            },
        ),
    ] {
        assert!(matches!(
            lower_single_hinted_op_err(kind, hint),
            LowerError::UnsupportedOp { .. } | LowerError::InvalidOperand { .. }
        ));
    }
}
#[test]
fn lower_psign_emits_exact_bytes_canonicalizes_wig_and_rejects_malformed_encodings() {
    let xmm = |index| VReg::Arch(ArchReg::X86(X86Reg::Xmm(index)));
    let ymm = |index| VReg::Arch(ArchReg::X86(X86Reg::Ymm(index)));
    let zmm = |index| VReg::Arch(ArchReg::X86(X86Reg::Zmm(index)));
    let sign = |dst, src1, src2, elem, lanes| OpKind::VLane {
        dst,
        src1,
        src2,
        elem,
        lanes,
        op: VLaneOp::Sign,
        signed: true,
        set_ovf: false,
    };

    for (name, kind, hint, expected) in [
        (
            "PSIGNB xmm1,xmm2",
            sign(xmm(1), xmm(1), xmm(2), VecElementType::I8, 16),
            X86OpHint::SseOp {
                prefix: X86SsePrefix::OpSize,
                opcode: 0x08,
            },
            &[0x66, 0x0F, 0x38, 0x08, 0xCA][..],
        ),
        (
            "PSIGNB xmm8,xmm1",
            sign(xmm(8), xmm(8), xmm(1), VecElementType::I8, 16),
            X86OpHint::SseOp {
                prefix: X86SsePrefix::OpSize,
                opcode: 0x08,
            },
            &[0x66, 0x44, 0x0F, 0x38, 0x08, 0xC1][..],
        ),
        (
            "VEX.W1-hinted VPSIGNW xmm1,xmm2,xmm3 canonicalized to W0",
            sign(xmm(1), xmm(2), xmm(3), VecElementType::I16, 8),
            X86OpHint::VexOp {
                map: X86VecMap::Map0F38,
                pp: X86SsePrefix::OpSize,
                opcode: 0x09,
                width: VecWidth::V128,
                w: true,
            },
            &[0xC4, 0xE2, 0x69, 0x09, 0xCB][..],
        ),
        (
            "VEX.256 VPSIGND ymm1,ymm2,ymm3",
            sign(ymm(1), ymm(2), ymm(3), VecElementType::I32, 8),
            X86OpHint::VexOp {
                map: X86VecMap::Map0F38,
                pp: X86SsePrefix::OpSize,
                opcode: 0x0A,
                width: VecWidth::V256,
                w: false,
            },
            &[0xC4, 0xE2, 0x6D, 0x0A, 0xCB][..],
        ),
    ] {
        let code = lower_single_hinted_op(kind, hint);
        assert!(
            code.windows(expected.len())
                .any(|window| window == expected),
            "{name}: missing {expected:02X?} in {code:02X?}"
        );
    }

    assert!(matches!(
        lower_single_op_err(sign(xmm(1), xmm(1), xmm(2), VecElementType::I8, 16,)),
        LowerError::UnsupportedOp { .. }
    ));
    for (kind, hint) in [
        (
            sign(xmm(1), xmm(2), xmm(3), VecElementType::I8, 16),
            X86OpHint::SseOp {
                prefix: X86SsePrefix::OpSize,
                opcode: 0x08,
            },
        ),
        (
            sign(ymm(16), ymm(1), ymm(2), VecElementType::I16, 16),
            X86OpHint::VexOp {
                map: X86VecMap::Map0F38,
                pp: X86SsePrefix::OpSize,
                opcode: 0x09,
                width: VecWidth::V256,
                w: false,
            },
        ),
        (
            sign(ymm(1), ymm(2), ymm(3), VecElementType::I32, 8),
            X86OpHint::VexOp {
                map: X86VecMap::Map0F,
                pp: X86SsePrefix::OpSize,
                opcode: 0x0A,
                width: VecWidth::V256,
                w: false,
            },
        ),
        (
            sign(ymm(1), ymm(2), ymm(3), VecElementType::I32, 8),
            X86OpHint::VexOp {
                map: X86VecMap::Map0F38,
                pp: X86SsePrefix::None,
                opcode: 0x0A,
                width: VecWidth::V256,
                w: false,
            },
        ),
        (
            sign(ymm(1), ymm(2), ymm(3), VecElementType::I32, 8),
            X86OpHint::VexOp {
                map: X86VecMap::Map0F38,
                pp: X86SsePrefix::OpSize,
                opcode: 0x09,
                width: VecWidth::V256,
                w: false,
            },
        ),
        (
            sign(ymm(1), ymm(2), ymm(3), VecElementType::I32, 8),
            X86OpHint::VexOp {
                map: X86VecMap::Map0F38,
                pp: X86SsePrefix::OpSize,
                opcode: 0x0A,
                width: VecWidth::V128,
                w: false,
            },
        ),
        (
            sign(zmm(1), zmm(2), zmm(3), VecElementType::I32, 16),
            X86OpHint::EvexOp {
                map: X86VecMap::Map0F38,
                pp: X86SsePrefix::OpSize,
                opcode: 0x0A,
                width: VecWidth::V512,
                w: false,
            },
        ),
        (
            OpKind::VLane {
                dst: xmm(1),
                src1: xmm(1),
                src2: xmm(2),
                elem: VecElementType::I8,
                lanes: 16,
                op: VLaneOp::Sign,
                signed: false,
                set_ovf: false,
            },
            X86OpHint::SseOp {
                prefix: X86SsePrefix::OpSize,
                opcode: 0x08,
            },
        ),
        (
            OpKind::VLane {
                dst: xmm(1),
                src1: xmm(1),
                src2: xmm(2),
                elem: VecElementType::I8,
                lanes: 16,
                op: VLaneOp::Sign,
                signed: true,
                set_ovf: true,
            },
            X86OpHint::SseOp {
                prefix: X86SsePrefix::OpSize,
                opcode: 0x08,
            },
        ),
        (
            sign(xmm(1), xmm(1), xmm(2), VecElementType::I64, 2),
            X86OpHint::SseOp {
                prefix: X86SsePrefix::OpSize,
                opcode: 0x08,
            },
        ),
    ] {
        assert!(matches!(
            lower_single_hinted_op_err(kind, hint),
            LowerError::UnsupportedOp { .. } | LowerError::InvalidOperand { .. }
        ));
    }
}
#[test]
fn lower_pavg_emits_exact_bytes_and_rejects_malformed_encodings() {
    let xmm = |index| VReg::Arch(ArchReg::X86(X86Reg::Xmm(index)));
    let ymm = |index| VReg::Arch(ArchReg::X86(X86Reg::Ymm(index)));
    let zmm = |index| VReg::Arch(ArchReg::X86(X86Reg::Zmm(index)));
    let average = |dst, src1, src2, elem, lanes| OpKind::VLane {
        dst,
        src1,
        src2,
        elem,
        lanes,
        op: VLaneOp::AvgRnd,
        signed: false,
        set_ovf: false,
    };

    for (name, kind, hint, expected) in [
        (
            "PAVGB xmm1,xmm2",
            average(xmm(1), xmm(1), xmm(2), VecElementType::I8, 16),
            X86OpHint::SseOp {
                prefix: X86SsePrefix::OpSize,
                opcode: 0xE0,
            },
            &[0x66, 0x0F, 0xE0, 0xCA][..],
        ),
        (
            "VEX.W1 VPAVGW xmm1,xmm2,xmm3",
            average(xmm(1), xmm(2), xmm(3), VecElementType::I16, 8),
            X86OpHint::VexOp {
                map: X86VecMap::Map0F,
                pp: X86SsePrefix::OpSize,
                opcode: 0xE3,
                width: VecWidth::V128,
                w: true,
            },
            &[0xC4, 0xE1, 0xE9, 0xE3, 0xCB][..],
        ),
        (
            "VEX.256 VPAVGB ymm1,ymm2,ymm3",
            average(ymm(1), ymm(2), ymm(3), VecElementType::I8, 32),
            X86OpHint::VexOp {
                map: X86VecMap::Map0F,
                pp: X86SsePrefix::OpSize,
                opcode: 0xE0,
                width: VecWidth::V256,
                w: false,
            },
            &[0xC5, 0xED, 0xE0, 0xCB][..],
        ),
        (
            "EVEX.W1 VPAVGW xmm16,xmm17,xmm18",
            average(xmm(16), xmm(17), xmm(18), VecElementType::I16, 8),
            X86OpHint::EvexOp {
                map: X86VecMap::Map0F,
                pp: X86SsePrefix::OpSize,
                opcode: 0xE3,
                width: VecWidth::V128,
                w: true,
            },
            &[0x62, 0xA1, 0xF5, 0x00, 0xE3, 0xC2][..],
        ),
        (
            "EVEX.256 VPAVGB ymm16,ymm17,ymm18",
            average(ymm(16), ymm(17), ymm(18), VecElementType::I8, 32),
            X86OpHint::EvexOp {
                map: X86VecMap::Map0F,
                pp: X86SsePrefix::OpSize,
                opcode: 0xE0,
                width: VecWidth::V256,
                w: false,
            },
            &[0x62, 0xA1, 0x75, 0x20, 0xE0, 0xC2][..],
        ),
        (
            "EVEX.512 VPAVGW zmm16,zmm17,zmm18",
            average(zmm(16), zmm(17), zmm(18), VecElementType::I16, 32),
            X86OpHint::EvexOp {
                map: X86VecMap::Map0F,
                pp: X86SsePrefix::OpSize,
                opcode: 0xE3,
                width: VecWidth::V512,
                w: false,
            },
            &[0x62, 0xA1, 0x75, 0x40, 0xE3, 0xC2][..],
        ),
    ] {
        let code = lower_single_hinted_op(kind, hint);
        assert!(
            code.windows(expected.len())
                .any(|window| window == expected),
            "{name}: missing {expected:02X?} in {code:02X?}"
        );
    }

    assert!(matches!(
        lower_single_op_err(average(xmm(1), xmm(1), xmm(2), VecElementType::I8, 16,)),
        LowerError::UnsupportedOp { .. }
    ));
    for (kind, hint) in [
        (
            average(xmm(1), xmm(2), xmm(3), VecElementType::I8, 16),
            X86OpHint::SseOp {
                prefix: X86SsePrefix::OpSize,
                opcode: 0xE0,
            },
        ),
        (
            average(ymm(16), ymm(17), ymm(18), VecElementType::I16, 16),
            X86OpHint::VexOp {
                map: X86VecMap::Map0F,
                pp: X86SsePrefix::OpSize,
                opcode: 0xE3,
                width: VecWidth::V256,
                w: false,
            },
        ),
        (
            average(zmm(16), zmm(17), zmm(18), VecElementType::I8, 64),
            X86OpHint::EvexOp {
                map: X86VecMap::Map0F,
                pp: X86SsePrefix::OpSize,
                opcode: 0xE3,
                width: VecWidth::V512,
                w: false,
            },
        ),
        (
            average(ymm(16), ymm(17), ymm(18), VecElementType::I8, 32),
            X86OpHint::EvexOp {
                map: X86VecMap::Map0F,
                pp: X86SsePrefix::OpSize,
                opcode: 0xE0,
                width: VecWidth::V128,
                w: false,
            },
        ),
        (
            OpKind::VLane {
                dst: xmm(1),
                src1: xmm(1),
                src2: xmm(2),
                elem: VecElementType::I8,
                lanes: 16,
                op: VLaneOp::AvgRnd,
                signed: true,
                set_ovf: false,
            },
            X86OpHint::SseOp {
                prefix: X86SsePrefix::OpSize,
                opcode: 0xE0,
            },
        ),
    ] {
        assert!(matches!(
            lower_single_hinted_op_err(kind, hint),
            LowerError::UnsupportedOp { .. } | LowerError::InvalidOperand { .. }
        ));
    }
}
#[test]
fn lower_psadbw_emits_exact_bytes_and_rejects_malformed_encodings() {
    let xmm = |index| VReg::Arch(ArchReg::X86(X86Reg::Xmm(index)));
    let ymm = |index| VReg::Arch(ArchReg::X86(X86Reg::Ymm(index)));
    let zmm = |index| VReg::Arch(ArchReg::X86(X86Reg::Zmm(index)));
    let sad = |dst, src1, src2, width| OpKind::VSadBytes {
        dst,
        src1,
        src2,
        width,
    };

    for (name, kind, hint, expected) in [
        (
            "PSADBW xmm1,xmm2",
            sad(xmm(1), xmm(1), xmm(2), VecWidth::V128),
            X86OpHint::SseOp {
                prefix: X86SsePrefix::OpSize,
                opcode: 0xF6,
            },
            &[0x66, 0x0F, 0xF6, 0xCA][..],
        ),
        (
            "VEX.W1 VPSADBW xmm1,xmm2,xmm3",
            sad(xmm(1), xmm(2), xmm(3), VecWidth::V128),
            X86OpHint::VexOp {
                map: X86VecMap::Map0F,
                pp: X86SsePrefix::OpSize,
                opcode: 0xF6,
                width: VecWidth::V128,
                w: true,
            },
            &[0xC4, 0xE1, 0xE9, 0xF6, 0xCB][..],
        ),
        (
            "VEX.256 VPSADBW ymm1,ymm2,ymm3",
            sad(ymm(1), ymm(2), ymm(3), VecWidth::V256),
            X86OpHint::VexOp {
                map: X86VecMap::Map0F,
                pp: X86SsePrefix::OpSize,
                opcode: 0xF6,
                width: VecWidth::V256,
                w: false,
            },
            &[0xC5, 0xED, 0xF6, 0xCB][..],
        ),
        (
            "EVEX.W1 VPSADBW xmm16,xmm17,xmm18",
            sad(xmm(16), xmm(17), xmm(18), VecWidth::V128),
            X86OpHint::EvexOp {
                map: X86VecMap::Map0F,
                pp: X86SsePrefix::OpSize,
                opcode: 0xF6,
                width: VecWidth::V128,
                w: true,
            },
            &[0x62, 0xA1, 0xF5, 0x00, 0xF6, 0xC2][..],
        ),
        (
            "EVEX.256 VPSADBW ymm16,ymm17,ymm18",
            sad(ymm(16), ymm(17), ymm(18), VecWidth::V256),
            X86OpHint::EvexOp {
                map: X86VecMap::Map0F,
                pp: X86SsePrefix::OpSize,
                opcode: 0xF6,
                width: VecWidth::V256,
                w: false,
            },
            &[0x62, 0xA1, 0x75, 0x20, 0xF6, 0xC2][..],
        ),
        (
            "EVEX.512 VPSADBW zmm16,zmm17,zmm18",
            sad(zmm(16), zmm(17), zmm(18), VecWidth::V512),
            X86OpHint::EvexOp {
                map: X86VecMap::Map0F,
                pp: X86SsePrefix::OpSize,
                opcode: 0xF6,
                width: VecWidth::V512,
                w: false,
            },
            &[0x62, 0xA1, 0x75, 0x40, 0xF6, 0xC2][..],
        ),
    ] {
        let code = lower_single_hinted_op(kind, hint);
        assert!(
            code.windows(expected.len())
                .any(|window| window == expected),
            "{name}: missing {expected:02X?} in {code:02X?}"
        );
    }

    assert!(matches!(
        lower_single_op_err(sad(xmm(1), xmm(1), xmm(2), VecWidth::V128)),
        LowerError::UnsupportedOp { .. }
    ));
    for (kind, hint) in [
        (
            sad(xmm(1), xmm(2), xmm(3), VecWidth::V128),
            X86OpHint::SseOp {
                prefix: X86SsePrefix::OpSize,
                opcode: 0xF6,
            },
        ),
        (
            sad(ymm(16), ymm(17), ymm(18), VecWidth::V256),
            X86OpHint::VexOp {
                map: X86VecMap::Map0F,
                pp: X86SsePrefix::OpSize,
                opcode: 0xF6,
                width: VecWidth::V256,
                w: false,
            },
        ),
        (
            sad(zmm(16), zmm(17), zmm(18), VecWidth::V512),
            X86OpHint::EvexOp {
                map: X86VecMap::Map0F,
                pp: X86SsePrefix::OpSize,
                opcode: 0xE0,
                width: VecWidth::V512,
                w: false,
            },
        ),
        (
            sad(ymm(16), ymm(17), ymm(18), VecWidth::V256),
            X86OpHint::EvexOp {
                map: X86VecMap::Map0F,
                pp: X86SsePrefix::OpSize,
                opcode: 0xF6,
                width: VecWidth::V128,
                w: false,
            },
        ),
        (
            sad(xmm(1), xmm(1), ymm(2), VecWidth::V128),
            X86OpHint::SseOp {
                prefix: X86SsePrefix::OpSize,
                opcode: 0xF6,
            },
        ),
    ] {
        assert!(matches!(
            lower_single_hinted_op_err(kind, hint),
            LowerError::UnsupportedOp { .. } | LowerError::InvalidOperand { .. }
        ));
    }
}
#[test]
fn lower_phminposuw_emits_exact_bytes_canonicalizes_wig_and_rejects_malformed() {
    let xmm = |index| VReg::Arch(ArchReg::X86(X86Reg::Xmm(index)));
    let minpos = |dst, src| OpKind::X86Phminposuw { dst, src };

    for (name, kind, hint, expected) in [
        (
            "PHMINPOSUW xmm1,xmm2",
            minpos(xmm(1), xmm(2)),
            X86OpHint::SseOp {
                prefix: X86SsePrefix::OpSize,
                opcode: 0x41,
            },
            &[0x66, 0x0F, 0x38, 0x41, 0xCA][..],
        ),
        (
            "VEX.W1-hinted VPHMINPOSUW xmm1,xmm1 canonicalized to W0",
            minpos(xmm(1), xmm(1)),
            X86OpHint::VexOp {
                map: X86VecMap::Map0F38,
                pp: X86SsePrefix::OpSize,
                opcode: 0x41,
                width: VecWidth::V128,
                w: true,
            },
            &[0xC4, 0xE2, 0x79, 0x41, 0xC9][..],
        ),
    ] {
        let code = lower_single_hinted_op(kind, hint);
        assert!(
            code.windows(expected.len())
                .any(|window| window == expected),
            "{name}: missing {expected:02X?} in {code:02X?}"
        );
    }

    assert!(matches!(
        lower_single_op_err(minpos(xmm(1), xmm(2))),
        LowerError::UnsupportedOp { .. }
    ));

    for (kind, hint) in [
        (
            minpos(xmm(16), xmm(2)),
            X86OpHint::SseOp {
                prefix: X86SsePrefix::OpSize,
                opcode: 0x41,
            },
        ),
        (
            minpos(xmm(1), VReg::Arch(ArchReg::X86(X86Reg::Ymm(2)))),
            X86OpHint::SseOp {
                prefix: X86SsePrefix::OpSize,
                opcode: 0x41,
            },
        ),
        (
            minpos(xmm(1), xmm(2)),
            X86OpHint::SseOp {
                prefix: X86SsePrefix::None,
                opcode: 0x41,
            },
        ),
        (
            minpos(xmm(1), xmm(2)),
            X86OpHint::VexOp {
                map: X86VecMap::Map0F3A,
                pp: X86SsePrefix::OpSize,
                opcode: 0x41,
                width: VecWidth::V128,
                w: false,
            },
        ),
        (
            minpos(xmm(1), xmm(2)),
            X86OpHint::VexOp {
                map: X86VecMap::Map0F38,
                pp: X86SsePrefix::OpSize,
                opcode: 0x40,
                width: VecWidth::V128,
                w: false,
            },
        ),
        (
            minpos(xmm(1), xmm(2)),
            X86OpHint::VexOp {
                map: X86VecMap::Map0F38,
                pp: X86SsePrefix::OpSize,
                opcode: 0x41,
                width: VecWidth::V256,
                w: false,
            },
        ),
        (
            minpos(xmm(1), xmm(2)),
            X86OpHint::EvexOp {
                map: X86VecMap::Map0F38,
                pp: X86SsePrefix::OpSize,
                opcode: 0x41,
                width: VecWidth::V128,
                w: false,
            },
        ),
    ] {
        assert!(matches!(
            lower_single_hinted_op_err(kind, hint),
            LowerError::UnsupportedOp { .. } | LowerError::InvalidOperand { .. }
        ));
    }
}
#[test]
fn lower_mpsadbw_emits_exact_bytes_and_rejects_malformed_classic_encodings() {
    let xmm = |index| VReg::Arch(ArchReg::X86(X86Reg::Xmm(index)));
    let ymm = |index| VReg::Arch(ArchReg::X86(X86Reg::Ymm(index)));
    let mpsad = |dst, src1, src2, width, imm| OpKind::VMpsadbw {
        dst,
        src1,
        src2,
        mask: None,
        width,
        imm,
        zeroing: false,
    };

    for (name, kind, hint, expected) in [
        (
            "MPSADBW xmm1,xmm2,0xE7",
            mpsad(xmm(1), xmm(1), xmm(2), VecWidth::V128, 0xE7),
            X86OpHint::SseOp {
                prefix: X86SsePrefix::OpSize,
                opcode: 0x42,
            },
            &[0x66, 0x0F, 0x3A, 0x42, 0xCA, 0xE7][..],
        ),
        (
            "VEX.W1 VMPSADBW xmm1,xmm2,xmm3,0xFF",
            mpsad(xmm(1), xmm(2), xmm(3), VecWidth::V128, 0xFF),
            X86OpHint::VexOp {
                map: X86VecMap::Map0F3A,
                pp: X86SsePrefix::OpSize,
                opcode: 0x42,
                width: VecWidth::V128,
                w: true,
            },
            &[0xC4, 0xE3, 0xE9, 0x42, 0xCB, 0xFF][..],
        ),
        (
            "VEX.256 VMPSADBW ymm1,ymm2,ymm3,0x3F",
            mpsad(ymm(1), ymm(2), ymm(3), VecWidth::V256, 0x3F),
            X86OpHint::VexOp {
                map: X86VecMap::Map0F3A,
                pp: X86SsePrefix::OpSize,
                opcode: 0x42,
                width: VecWidth::V256,
                w: false,
            },
            &[0xC4, 0xE3, 0x6D, 0x42, 0xCB, 0x3F][..],
        ),
        (
            "VEX.W1 VMPSADBW xmm9,xmm11,xmm10,0xE7",
            mpsad(xmm(9), xmm(11), xmm(10), VecWidth::V128, 0xE7),
            X86OpHint::VexOp {
                map: X86VecMap::Map0F3A,
                pp: X86SsePrefix::OpSize,
                opcode: 0x42,
                width: VecWidth::V128,
                w: true,
            },
            &[0xC4, 0x43, 0xA1, 0x42, 0xCA, 0xE7][..],
        ),
    ] {
        let code = lower_single_hinted_op(kind, hint);
        assert!(
            code.windows(expected.len())
                .any(|window| window == expected),
            "{name}: missing {expected:02X?} in {code:02X?}"
        );
    }

    let masked_classic = OpKind::VMpsadbw {
        dst: xmm(1),
        src1: xmm(1),
        src2: xmm(2),
        mask: Some(VReg::Arch(ArchReg::X86(X86Reg::K(1)))),
        width: VecWidth::V128,
        imm: 0,
        zeroing: false,
    };
    assert!(matches!(
        lower_single_hinted_op_err(
            masked_classic,
            X86OpHint::SseOp {
                prefix: X86SsePrefix::OpSize,
                opcode: 0x42,
            },
        ),
        LowerError::UnsupportedOp { .. }
    ));

    for (kind, hint) in [
        (
            mpsad(xmm(1), xmm(2), xmm(3), VecWidth::V128, 0),
            X86OpHint::SseOp {
                prefix: X86SsePrefix::OpSize,
                opcode: 0x42,
            },
        ),
        (
            mpsad(xmm(1), xmm(1), xmm(2), VecWidth::V128, 0),
            X86OpHint::SseOp {
                prefix: X86SsePrefix::None,
                opcode: 0x42,
            },
        ),
        (
            mpsad(xmm(1), xmm(1), xmm(2), VecWidth::V128, 0),
            X86OpHint::SseOp {
                prefix: X86SsePrefix::OpSize,
                opcode: 0xF6,
            },
        ),
        (
            mpsad(ymm(1), ymm(2), ymm(3), VecWidth::V256, 0),
            X86OpHint::VexOp {
                map: X86VecMap::Map0F38,
                pp: X86SsePrefix::OpSize,
                opcode: 0x42,
                width: VecWidth::V256,
                w: false,
            },
        ),
        (
            mpsad(ymm(1), ymm(2), ymm(3), VecWidth::V256, 0),
            X86OpHint::VexOp {
                map: X86VecMap::Map0F3A,
                pp: X86SsePrefix::OpSize,
                opcode: 0x42,
                width: VecWidth::V128,
                w: false,
            },
        ),
        (
            mpsad(ymm(16), ymm(17), ymm(18), VecWidth::V256, 0),
            X86OpHint::VexOp {
                map: X86VecMap::Map0F3A,
                pp: X86SsePrefix::OpSize,
                opcode: 0x42,
                width: VecWidth::V256,
                w: false,
            },
        ),
    ] {
        assert!(matches!(
            lower_single_hinted_op_err(kind, hint),
            LowerError::UnsupportedOp { .. } | LowerError::InvalidOperand { .. }
        ));
    }
}
#[test]
fn lower_enter_mmx_commits_guest_tag_word_without_clobbering_arch_state() {
    let code = lower_single_op(OpKind::X86X87Control {
        kind: X86X87ControlKind::EnterMmx,
        addr: None,
    });
    let mut expected = vec![
        0x50,
        0x48,
        0x8B,
        0x45,
        X86_STATE_PTR_AT_RBP as u8,
        0x48,
        0xC7,
        0x80,
    ];
    expected.extend_from_slice(&(X86_GUEST_X87_TAG_WORD_OFFSET as u32).to_le_bytes());
    expected.extend_from_slice(&0u32.to_le_bytes());
    expected.push(0x58);
    assert!(
        code.windows(expected.len())
            .any(|window| window == expected),
        "missing precise EnterMmx state commit: {code:02X?}"
    );

    assert!(matches!(
        lower_single_op_err(OpKind::X86X87Control {
            kind: X86X87ControlKind::EnterMmx,
            addr: Some(Address::Absolute(0x1000)),
        }),
        LowerError::InvalidOperand { .. }
    ));
}
#[test]
fn lower_empty_mmx_commits_empty_tag_word_without_clobbering_arch_state() {
    let code = lower_single_op(OpKind::X86X87Control {
        kind: X86X87ControlKind::EmptyMmx,
        addr: None,
    });
    let mut expected = vec![
        0x50,
        0x48,
        0x8B,
        0x45,
        X86_STATE_PTR_AT_RBP as u8,
        0x48,
        0xC7,
        0x80,
    ];
    expected.extend_from_slice(&(X86_GUEST_X87_TAG_WORD_OFFSET as u32).to_le_bytes());
    expected.extend_from_slice(&0xFFFFu32.to_le_bytes());
    expected.push(0x58);
    assert!(
        code.windows(expected.len())
            .any(|window| window == expected),
        "missing precise EmptyMmx state commit: {code:02X?}"
    );

    assert!(matches!(
        lower_single_op_err(OpKind::X86X87Control {
            kind: X86X87ControlKind::EmptyMmx,
            addr: Some(Address::Absolute(0x1000)),
        }),
        LowerError::InvalidOperand { .. }
    ));
}
#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[test]
fn native_empty_mmx_follows_mmx_work_and_preserves_payloads_flags_and_gprs() {
    use crate::smir::lower::runtime::{ExecMem, GuestRegs};

    let mm0 = VReg::Arch(ArchReg::X86(X86Reg::Mm(0)));
    let mm1 = VReg::Arch(ArchReg::X86(X86Reg::Mm(1)));
    let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
    builder.push_op(
        0x1000,
        OpKind::X86X87Control {
            kind: X86X87ControlKind::EnterMmx,
            addr: None,
        },
    );
    builder.push_op(
        0x1000,
        OpKind::VAnd {
            dst: mm0,
            src1: mm0,
            src2: mm1,
            width: VecWidth::V64,
        },
    );
    builder.push_op(
        0x1002,
        OpKind::X86X87Control {
            kind: X86X87ControlKind::EmptyMmx,
            addr: None,
        },
    );
    builder.set_terminator(Terminator::Return { values: vec![] });
    let mut function = builder.finish();
    function.blocks[0].ops[1].x86_hint = Some(X86OpHint::SseOp {
        prefix: X86SsePrefix::None,
        opcode: 0xDB,
    });

    let mut lowerer = X86_64Lowerer::new();
    let lowered = lowerer
        .lower_function(&function)
        .expect("lower native MMX work followed by EmptyMmx");
    let code = lowerer.finalize().expect("finalize MMX/EmptyMmx code");
    let exec = ExecMem::new(&code).expect("map MMX/EmptyMmx code");
    let mut regs = GuestRegs {
        mm: [
            0xFF00_FF00_AAAA_AAAA,
            0x0FF0_00FF_5555_FFFF,
            0x0123_4567_89AB_CDEF,
            0x1111_2222_3333_4444,
            0x5555_6666_7777_8888,
            0x9999_AAAA_BBBB_CCCC,
            0xDEAD_BEEF_CAFE_BABE,
            u64::MAX,
        ],
        mmx_active: 1,
        x87_tag_word: 0,
        rflags: 0x2 | 0x8D5,
        ..GuestRegs::default()
    };
    let untouched = regs.mm[2..].to_vec();
    regs.gpr[0] = 0x8877_6655_4433_2211;
    exec.run(lowered.entry_offset, &mut regs);

    assert_eq!(regs.mm[0], 0x0F00_0000_0000_AAAA);
    assert_eq!(regs.mm[1], 0x0FF0_00FF_5555_FFFF);
    assert_eq!(regs.mm[2..], untouched);
    assert_eq!(regs.x87_tag_word, 0xFFFF);
    assert_eq!(regs.gpr[0], 0x8877_6655_4433_2211);
    assert_eq!(regs.rflags & 0x8D5, 0x8D5);
}
#[test]
fn lower_mmx_logic_emits_exact_classic_opcodes_and_rejects_malformed_ir() {
    let mm = |index| VReg::Arch(ArchReg::X86(X86Reg::Mm(index)));
    let logic = |opcode| match opcode {
        0xDB => OpKind::VAnd {
            dst: mm(1),
            src1: mm(1),
            src2: mm(2),
            width: VecWidth::V64,
        },
        0xDF => OpKind::VAndNot {
            dst: mm(1),
            src1: mm(1),
            src2: mm(2),
            width: VecWidth::V64,
        },
        0xEB => OpKind::VOr {
            dst: mm(1),
            src1: mm(1),
            src2: mm(2),
            width: VecWidth::V64,
        },
        0xEF => OpKind::VXor {
            dst: mm(1),
            src1: mm(1),
            src2: mm(2),
            width: VecWidth::V64,
        },
        _ => unreachable!(),
    };

    for opcode in [0xDB, 0xDF, 0xEB, 0xEF] {
        let code = lower_single_hinted_op(
            logic(opcode),
            X86OpHint::SseOp {
                prefix: X86SsePrefix::None,
                opcode,
            },
        );
        assert!(
            code.windows(3).any(|window| window == [0x0F, opcode, 0xCA]),
            "missing MMX opcode 0F {opcode:02X} /r: {code:02X?}"
        );
    }

    assert!(matches!(
        lower_single_op_err(logic(0xDB)),
        LowerError::InvalidOperand { .. }
    ));
    assert!(matches!(
        lower_single_hinted_op_err(
            logic(0xDB),
            X86OpHint::SseOp {
                prefix: X86SsePrefix::OpSize,
                opcode: 0xDB,
            },
        ),
        LowerError::InvalidOperand { .. }
    ));
    assert!(matches!(
        lower_single_hinted_op_err(
            OpKind::VAnd {
                dst: mm(1),
                src1: mm(2),
                src2: mm(3),
                width: VecWidth::V64,
            },
            X86OpHint::SseOp {
                prefix: X86SsePrefix::None,
                opcode: 0xDB,
            },
        ),
        LowerError::InvalidOperand { .. }
    ));
}
#[test]
fn lower_mmx_packed_add_sub_emits_all_classic_register_opcodes() {
    let mm = |index| VReg::Arch(ArchReg::X86(X86Reg::Mm(index)));
    let arithmetic = |opcode| match opcode {
        0xFC | 0xFD | 0xFE | 0xD4 => {
            let (elem, lanes) = match opcode {
                0xFC => (VecElementType::I8, 8),
                0xFD => (VecElementType::I16, 4),
                0xFE => (VecElementType::I32, 2),
                0xD4 => (VecElementType::I64, 1),
                _ => unreachable!(),
            };
            OpKind::VAdd {
                dst: mm(3),
                src1: mm(3),
                src2: mm(6),
                elem,
                lanes,
            }
        }
        0xF8 | 0xF9 | 0xFA | 0xFB => {
            let (elem, lanes) = match opcode {
                0xF8 => (VecElementType::I8, 8),
                0xF9 => (VecElementType::I16, 4),
                0xFA => (VecElementType::I32, 2),
                0xFB => (VecElementType::I64, 1),
                _ => unreachable!(),
            };
            OpKind::VSub {
                dst: mm(3),
                src1: mm(3),
                src2: mm(6),
                elem,
                lanes,
            }
        }
        _ => {
            let (elem, lanes, subtract, signed) = match opcode {
                0xEC => (VecElementType::I8, 8, false, true),
                0xED => (VecElementType::I16, 4, false, true),
                0xDC => (VecElementType::I8, 8, false, false),
                0xDD => (VecElementType::I16, 4, false, false),
                0xE8 => (VecElementType::I8, 8, true, true),
                0xE9 => (VecElementType::I16, 4, true, true),
                0xD8 => (VecElementType::I8, 8, true, false),
                0xD9 => (VecElementType::I16, 4, true, false),
                _ => unreachable!(),
            };
            OpKind::VAddSubSat {
                dst: mm(3),
                src1: mm(3),
                src2: mm(6),
                elem,
                lanes,
                subtract,
                signed,
            }
        }
    };

    for opcode in [
        0xFC, 0xFD, 0xFE, 0xD4, 0xF8, 0xF9, 0xFA, 0xFB, 0xEC, 0xED, 0xDC, 0xDD, 0xE8, 0xE9, 0xD8,
        0xD9,
    ] {
        let code = lower_single_hinted_op(
            arithmetic(opcode),
            X86OpHint::SseOp {
                prefix: X86SsePrefix::None,
                opcode,
            },
        );
        assert!(
            code.windows(3).any(|window| window == [0x0F, opcode, 0xDE]),
            "missing MMX opcode 0F {opcode:02X} /r: {code:02X?}"
        );
    }

    assert!(matches!(
        lower_single_hinted_op_err(
            OpKind::VAdd {
                dst: mm(3),
                src1: mm(3),
                src2: mm(6),
                elem: VecElementType::I8,
                lanes: 4,
            },
            X86OpHint::SseOp {
                prefix: X86SsePrefix::None,
                opcode: 0xFC,
            },
        ),
        LowerError::InvalidOperand { .. }
    ));
}
#[test]
fn lower_mmx_packed_compare_emits_all_classic_register_opcodes() {
    let mm = |index| VReg::Arch(ArchReg::X86(X86Reg::Mm(index)));
    for (elem, lanes, cond, opcode) in [
        (VecElementType::I8, 8, VecCmpCond::Gt, 0x64),
        (VecElementType::I16, 4, VecCmpCond::Gt, 0x65),
        (VecElementType::I32, 2, VecCmpCond::Gt, 0x66),
        (VecElementType::I8, 8, VecCmpCond::Eq, 0x74),
        (VecElementType::I16, 4, VecCmpCond::Eq, 0x75),
        (VecElementType::I32, 2, VecCmpCond::Eq, 0x76),
    ] {
        let code = lower_single_hinted_op(
            OpKind::VCmp {
                dst: mm(4),
                src1: mm(4),
                src2: mm(1),
                cond,
                elem,
                lanes,
            },
            X86OpHint::SseOp {
                prefix: X86SsePrefix::None,
                opcode,
            },
        );
        assert!(
            code.windows(3).any(|window| window == [0x0F, opcode, 0xE1]),
            "missing MMX compare 0F {opcode:02X} /r: {code:02X?}"
        );
    }
}
#[test]
fn lower_mmx_interleave_emits_all_classic_register_opcodes() {
    let mm = |index| VReg::Arch(ArchReg::X86(X86Reg::Mm(index)));
    for (elem, lanes, block_lanes, high, opcode) in [
        (VecElementType::I8, 8, 8, false, 0x60),
        (VecElementType::I16, 4, 4, false, 0x61),
        (VecElementType::I32, 2, 2, false, 0x62),
        (VecElementType::I8, 8, 8, true, 0x68),
        (VecElementType::I16, 4, 4, true, 0x69),
        (VecElementType::I32, 2, 2, true, 0x6A),
    ] {
        let code = lower_single_hinted_op(
            OpKind::VInterleave {
                dst: mm(5),
                src1: mm(5),
                src2: mm(2),
                elem,
                lanes,
                block_lanes,
                high,
            },
            X86OpHint::SseOp {
                prefix: X86SsePrefix::None,
                opcode,
            },
        );
        assert!(
            code.windows(3).any(|window| window == [0x0F, opcode, 0xEA]),
            "missing MMX interleave 0F {opcode:02X} /r: {code:02X?}"
        );
    }
}
#[test]
fn lower_mmx_pack_emits_all_classic_register_opcodes_with_rm_source() {
    let mm = |index| VReg::Arch(ArchReg::X86(X86Reg::Mm(index)));
    for (src_elem, src_lanes, to_unsigned, opcode) in [
        (VecElementType::I16, 4, false, 0x63),
        (VecElementType::I16, 4, true, 0x67),
        (VecElementType::I32, 2, false, 0x6B),
    ] {
        let code = lower_single_hinted_op(
            OpKind::VPackSat {
                dst: mm(6),
                src1: mm(3),
                src2: mm(6),
                src_elem,
                to_unsigned,
                src_lanes,
                block_lanes: src_lanes,
            },
            X86OpHint::SseOp {
                prefix: X86SsePrefix::None,
                opcode,
            },
        );
        assert!(
            code.windows(3).any(|window| window == [0x0F, opcode, 0xF3]),
            "missing MMX pack 0F {opcode:02X} /r: {code:02X?}"
        );
    }
}
#[test]
fn lower_mmx_minmax_emits_all_classic_register_opcodes() {
    let mm = |index| VReg::Arch(ArchReg::X86(X86Reg::Mm(index)));
    for (elem, lanes, lane_op, signed, opcode) in [
        (VecElementType::I8, 8, VLaneOp::Min, false, 0xDA),
        (VecElementType::I8, 8, VLaneOp::Max, false, 0xDE),
        (VecElementType::I16, 4, VLaneOp::Min, true, 0xEA),
        (VecElementType::I16, 4, VLaneOp::Max, true, 0xEE),
    ] {
        let code = lower_single_hinted_op(
            OpKind::VLane {
                dst: mm(7),
                src1: mm(7),
                src2: mm(0),
                elem,
                lanes,
                op: lane_op,
                signed,
                set_ovf: false,
            },
            X86OpHint::SseOp {
                prefix: X86SsePrefix::None,
                opcode,
            },
        );
        assert!(
            code.windows(3).any(|window| window == [0x0F, opcode, 0xF8]),
            "missing MMX min/max 0F {opcode:02X} /r: {code:02X?}"
        );
    }
}
#[test]
fn lower_mmx_average_emits_byte_and_word_classic_opcodes() {
    let mm = |index| VReg::Arch(ArchReg::X86(X86Reg::Mm(index)));
    for (elem, lanes, opcode) in [
        (VecElementType::I8, 8, 0xE0),
        (VecElementType::I16, 4, 0xE3),
    ] {
        let code = lower_single_hinted_op(
            OpKind::VLane {
                dst: mm(2),
                src1: mm(2),
                src2: mm(5),
                elem,
                lanes,
                op: VLaneOp::AvgRnd,
                signed: false,
                set_ovf: false,
            },
            X86OpHint::SseOp {
                prefix: X86SsePrefix::None,
                opcode,
            },
        );
        assert!(
            code.windows(3).any(|window| window == [0x0F, opcode, 0xD5]),
            "missing MMX average 0F {opcode:02X} /r: {code:02X?}"
        );
    }
}
#[test]
fn lower_mmx_maddwd_emits_classic_register_opcode() {
    let mm = |index| VReg::Arch(ArchReg::X86(X86Reg::Mm(index)));
    let code = lower_single_hinted_op(
        OpKind::VDotProduct {
            dst: mm(3),
            acc: VReg::Imm(0),
            src1: mm(3),
            src2: mm(6),
            mask: None,
            src_elem: VecElementType::I16,
            acc_elem: VecElementType::I32,
            width: VecWidth::V64,
            src1_unsigned: false,
            saturate: false,
            zeroing: false,
        },
        X86OpHint::SseOp {
            prefix: X86SsePrefix::None,
            opcode: 0xF5,
        },
    );
    assert!(
        code.windows(3).any(|window| window == [0x0F, 0xF5, 0xDE]),
        "missing MMX PMADDWD 0F F5 /r: {code:02X?}"
    );
}
#[test]
fn lower_mmx_sad_bytes_emits_classic_register_opcode() {
    let mm = |index| VReg::Arch(ArchReg::X86(X86Reg::Mm(index)));
    let code = lower_single_hinted_op(
        OpKind::VSadBytes {
            dst: mm(4),
            src1: mm(4),
            src2: mm(1),
            width: VecWidth::V64,
        },
        X86OpHint::SseOp {
            prefix: X86SsePrefix::None,
            opcode: 0xF6,
        },
    );
    assert!(
        code.windows(3).any(|window| window == [0x0F, 0xF6, 0xE1]),
        "missing MMX PSADBW 0F F6 /r: {code:02X?}"
    );
}
#[test]
fn lower_mmx_shared_count_shifts_emit_all_classic_opcodes() {
    let mm = |index| VReg::Arch(ArchReg::X86(X86Reg::Mm(index)));
    for (elem, shift, opcode) in [
        (VecElementType::I16, ShiftOp::Lsr, 0xD1),
        (VecElementType::I32, ShiftOp::Lsr, 0xD2),
        (VecElementType::I64, ShiftOp::Lsr, 0xD3),
        (VecElementType::I16, ShiftOp::Asr, 0xE1),
        (VecElementType::I32, ShiftOp::Asr, 0xE2),
        (VecElementType::I16, ShiftOp::Lsl, 0xF1),
        (VecElementType::I32, ShiftOp::Lsl, 0xF2),
        (VecElementType::I64, ShiftOp::Lsl, 0xF3),
    ] {
        let code = lower_single_hinted_op(
            OpKind::X86PackedShift {
                dst: mm(2),
                src: mm(2),
                count: mm(5),
                width: VecWidth::V64,
                elem,
                shift,
            },
            X86OpHint::SseOp {
                prefix: X86SsePrefix::None,
                opcode,
            },
        );
        assert!(
            code.windows(3).any(|window| window == [0x0F, opcode, 0xD5]),
            "missing MMX packed shift 0F {opcode:02X} /r: {code:02X?}"
        );
    }
}
#[test]
fn lower_mmx_immediate_shifts_emit_all_classic_group_forms() {
    let mm = |index| VReg::Arch(ArchReg::X86(X86Reg::Mm(index)));
    for (elem, shift, opcode, digit) in [
        (VecElementType::I16, ShiftOp::Lsr, 0x71, 2),
        (VecElementType::I16, ShiftOp::Asr, 0x71, 4),
        (VecElementType::I16, ShiftOp::Lsl, 0x71, 6),
        (VecElementType::I32, ShiftOp::Lsr, 0x72, 2),
        (VecElementType::I32, ShiftOp::Asr, 0x72, 4),
        (VecElementType::I32, ShiftOp::Lsl, 0x72, 6),
        (VecElementType::I64, ShiftOp::Lsr, 0x73, 2),
        (VecElementType::I64, ShiftOp::Lsl, 0x73, 6),
    ] {
        let code = lower_single_hinted_op(
            OpKind::X86PackedShiftImm {
                dst: mm(1),
                src: mm(1),
                width: VecWidth::V64,
                elem,
                shift,
                amount: 17,
                byte_lane: false,
            },
            X86OpHint::SseOp {
                prefix: X86SsePrefix::None,
                opcode,
            },
        );
        let modrm = 0xC1 | (digit << 3);
        assert!(
            code.windows(4)
                .any(|window| window == [0x0F, opcode, modrm, 17]),
            "missing MMX immediate shift 0F {opcode:02X} /{digit}: {code:02X?}"
        );
    }
}
#[test]
fn lower_mmx_absolute_value_emits_ssse3_byte_word_and_dword_opcodes() {
    let mm = |index| VReg::Arch(ArchReg::X86(X86Reg::Mm(index)));
    for (elem, lanes, opcode) in [
        (VecElementType::I8, 8, 0x1C),
        (VecElementType::I16, 4, 0x1D),
        (VecElementType::I32, 2, 0x1E),
    ] {
        let code = lower_single_hinted_op(
            OpKind::VUnary {
                dst: mm(0),
                src: mm(1),
                elem,
                lanes,
                op: VecUnaryOp::Abs,
            },
            X86OpHint::SseOp {
                prefix: X86SsePrefix::None,
                opcode,
            },
        );
        assert!(
            code.windows(4)
                .any(|window| window == [0x0F, 0x38, opcode, 0xC1]),
            "missing MMX PABS 0F 38 {opcode:02X} /r: {code:02X?}"
        );
    }
}
#[test]
fn lower_mmx_sign_emits_ssse3_byte_word_and_dword_opcodes() {
    let mm = |index| VReg::Arch(ArchReg::X86(X86Reg::Mm(index)));
    for (elem, lanes, opcode) in [
        (VecElementType::I8, 8, 0x08),
        (VecElementType::I16, 4, 0x09),
        (VecElementType::I32, 2, 0x0A),
    ] {
        let code = lower_single_hinted_op(
            OpKind::VLane {
                dst: mm(0),
                src1: mm(0),
                src2: mm(1),
                elem,
                lanes,
                op: VLaneOp::Sign,
                signed: true,
                set_ovf: false,
            },
            X86OpHint::SseOp {
                prefix: X86SsePrefix::None,
                opcode,
            },
        );
        assert!(
            code.windows(4)
                .any(|window| window == [0x0F, 0x38, opcode, 0xC1]),
            "missing MMX PSIGN 0F 38 {opcode:02X} /r: {code:02X?}"
        );
    }
}
#[test]
fn lower_mmx_horizontal_emits_all_ssse3_add_sub_opcodes() {
    let mm = |index| VReg::Arch(ArchReg::X86(X86Reg::Mm(index)));
    for (elem, lanes, subtract, saturating, opcode) in [
        (VecElementType::I16, 4, false, false, 0x01),
        (VecElementType::I32, 2, false, false, 0x02),
        (VecElementType::I16, 4, false, true, 0x03),
        (VecElementType::I16, 4, true, false, 0x05),
        (VecElementType::I32, 2, true, false, 0x06),
        (VecElementType::I16, 4, true, true, 0x07),
    ] {
        let code = lower_single_hinted_op(
            OpKind::VHorizontalBin {
                dst: mm(0),
                src1: mm(0),
                src2: mm(1),
                elem,
                lanes,
                block_lanes: lanes,
                subtract,
                saturating,
            },
            X86OpHint::SseOp {
                prefix: X86SsePrefix::None,
                opcode,
            },
        );
        assert!(
            code.windows(4)
                .any(|window| window == [0x0F, 0x38, opcode, 0xC1]),
            "missing horizontal MMX opcode 0F 38 {opcode:02X} /r: {code:02X?}"
        );
    }
}
#[test]
fn lower_mmx_maddubs_emits_ssse3_saturating_dot_product_opcode() {
    let mm = |index| VReg::Arch(ArchReg::X86(X86Reg::Mm(index)));
    let code = lower_single_hinted_op(
        OpKind::VDotProduct {
            dst: mm(0),
            acc: VReg::Imm(0),
            src1: mm(0),
            src2: mm(1),
            mask: None,
            src_elem: VecElementType::I8,
            acc_elem: VecElementType::I16,
            width: VecWidth::V64,
            src1_unsigned: true,
            saturate: true,
            zeroing: false,
        },
        X86OpHint::SseOp {
            prefix: X86SsePrefix::None,
            opcode: 0x04,
        },
    );
    assert!(
        code.windows(4)
            .any(|window| window == [0x0F, 0x38, 0x04, 0xC1]),
        "missing MMX PMADDUBSW 0F 38 04 /r: {code:02X?}"
    );
}
#[test]
fn lower_mmx_mulhrsw_emits_ssse3_rounded_high_multiply_opcode() {
    let mm = |index| VReg::Arch(ArchReg::X86(X86Reg::Mm(index)));
    let code = lower_single_hinted_op(
        OpKind::VMulShiftSat {
            dst: mm(0),
            src1: mm(0),
            src2: mm(1),
            src_elem: VecElementType::I16,
            lanes: 4,
            signed1: true,
            signed2: true,
            shift_left: 0,
            round: true,
            sat_bits: 0,
            out_shift: 15,
        },
        X86OpHint::SseOp {
            prefix: X86SsePrefix::None,
            opcode: 0x0B,
        },
    );
    assert!(
        code.windows(4)
            .any(|window| window == [0x0F, 0x38, 0x0B, 0xC1]),
        "missing MMX PMULHRSW 0F 38 0B /r: {code:02X?}"
    );
}
#[test]
fn lower_mmx_byte_shuffle_emits_ssse3_opcode_and_rejects_malformed_ir() {
    let mm = |index| VReg::Arch(ArchReg::X86(X86Reg::Mm(index)));
    let shuffle = |dst, src, control, lanes, block_lanes| OpKind::VByteShuffle {
        dst,
        src,
        control,
        lanes,
        block_lanes,
    };
    let hint = X86OpHint::SseOp {
        prefix: X86SsePrefix::None,
        opcode: 0x00,
    };
    let code = lower_single_hinted_op(shuffle(mm(0), mm(0), mm(1), 8, 8), hint);
    assert!(
        code.windows(4)
            .any(|window| window == [0x0F, 0x38, 0x00, 0xC1]),
        "missing MMX PSHUFB 0F 38 00 /r: {code:02X?}"
    );

    for (kind, malformed_hint) in [
        (shuffle(mm(0), mm(2), mm(1), 8, 8), hint),
        (shuffle(mm(0), mm(0), mm(1), 16, 8), hint),
        (
            shuffle(mm(0), mm(0), mm(1), 8, 8),
            X86OpHint::SseOp {
                prefix: X86SsePrefix::OpSize,
                opcode: 0x00,
            },
        ),
    ] {
        assert!(matches!(
            lower_single_hinted_op_err(kind, malformed_hint),
            LowerError::InvalidOperand { .. }
        ));
    }
}
#[test]
fn lower_mmx_movemask_emits_width_exact_gpr_encoding_and_rejects_unsafe_dst() {
    let mm1 = VReg::Arch(ArchReg::X86(X86Reg::Mm(1)));
    for (dst_width, expected) in [
        (OpWidth::W32, &[0x44, 0x0F, 0xD7, 0xC1][..]),
        (OpWidth::W64, &[0x4C, 0x0F, 0xD7, 0xC1][..]),
    ] {
        let code = lower_single_hinted_op(
            OpKind::X86MovMask {
                dst: VReg::Arch(ArchReg::X86(X86Reg::R8)),
                src: mm1,
                elem: VecElementType::I8,
                lanes: 8,
                dst_width,
            },
            X86OpHint::SseOp {
                prefix: X86SsePrefix::None,
                opcode: 0xD7,
            },
        );
        assert!(
            code.windows(expected.len())
                .any(|window| window == expected),
            "missing MMX PMOVMSKB encoding {expected:02X?}: {code:02X?}"
        );
    }

    let error = lower_single_hinted_op_err(
        OpKind::X86MovMask {
            dst: VReg::Arch(ArchReg::X86(X86Reg::Rbp)),
            src: mm1,
            elem: VecElementType::I8,
            lanes: 8,
            dst_width: OpWidth::W64,
        },
        X86OpHint::SseOp {
            prefix: X86SsePrefix::None,
            opcode: 0xD7,
        },
    );
    assert!(
        matches!(
            error,
            LowerError::InvalidOperand { .. } | LowerError::InvalidRegister(_)
        ),
        "{error:?}"
    );
}
#[test]
fn lower_mmx_movq_emits_directional_opcodes_and_rejects_malformed_ir() {
    let mm = |index| VReg::Arch(ArchReg::X86(X86Reg::Mm(index)));
    for (opcode, expected) in [
        (0x6F, &[0x0F, 0x6F, 0xCA][..]),
        (0x7F, &[0x0F, 0x7F, 0xD1][..]),
    ] {
        let code = lower_single_hinted_op(
            OpKind::VMov {
                dst: mm(1),
                src: mm(2),
                width: VecWidth::V64,
            },
            X86OpHint::SseMov {
                prefix: X86SsePrefix::None,
                opcode,
            },
        );
        assert!(
            code.windows(expected.len())
                .any(|window| window == expected),
            "missing MMX MOVQ encoding {expected:02X?}: {code:02X?}"
        );
    }

    for (kind, hint) in [
        (
            OpKind::VMov {
                dst: mm(1),
                src: mm(2),
                width: VecWidth::V128,
            },
            X86OpHint::SseMov {
                prefix: X86SsePrefix::None,
                opcode: 0x6F,
            },
        ),
        (
            OpKind::VMov {
                dst: mm(1),
                src: VReg::Arch(ArchReg::X86(X86Reg::Xmm(2))),
                width: VecWidth::V64,
            },
            X86OpHint::SseMov {
                prefix: X86SsePrefix::None,
                opcode: 0x6F,
            },
        ),
        (
            OpKind::VMov {
                dst: mm(1),
                src: mm(2),
                width: VecWidth::V64,
            },
            X86OpHint::SseMov {
                prefix: X86SsePrefix::OpSize,
                opcode: 0x6F,
            },
        ),
    ] {
        assert!(matches!(
            lower_single_hinted_op_err(kind, hint),
            LowerError::InvalidOperand { .. } | LowerError::InvalidRegister(_)
        ));
    }
}
#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[test]
fn native_mmx_movq_executes_both_register_directions_and_round_trips_state() {
    use crate::smir::lower::runtime::{ExecMem, GuestRegs};

    let mm = |index| VReg::Arch(ArchReg::X86(X86Reg::Mm(index)));
    let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
    for (dst, src) in [(mm(0), mm(1)), (mm(2), mm(0))] {
        builder.push_op(
            0x1000,
            OpKind::X86X87Control {
                kind: X86X87ControlKind::EnterMmx,
                addr: None,
            },
        );
        builder.push_op(
            0x1000,
            OpKind::VMov {
                dst,
                src,
                width: VecWidth::V64,
            },
        );
    }
    builder.set_terminator(Terminator::Return { values: vec![] });
    let mut function = builder.finish();
    function.blocks[0].ops[1].x86_hint = Some(X86OpHint::SseMov {
        prefix: X86SsePrefix::None,
        opcode: 0x6F,
    });
    function.blocks[0].ops[3].x86_hint = Some(X86OpHint::SseMov {
        prefix: X86SsePrefix::None,
        opcode: 0x7F,
    });

    let mut lowerer = X86_64Lowerer::new();
    let lowered = lowerer
        .lower_function(&function)
        .expect("lower native MMX MOVQ operations");
    let code = lowerer.finalize().expect("finalize MMX MOVQ code");
    let exec = ExecMem::new(&code).expect("map MMX MOVQ code");
    let mut regs = GuestRegs {
        mm: [
            0xAAAA_AAAA_AAAA_AAAA,
            0x0123_4567_89AB_CDEF,
            0xBBBB_BBBB_BBBB_BBBB,
            0,
            0,
            0,
            0,
            0,
        ],
        mmx_active: 1,
        x87_tag_word: 0xFFFF,
        rflags: 0x2 | 0x8D5,
        ..GuestRegs::default()
    };
    exec.run(lowered.entry_offset, &mut regs);

    assert_eq!(regs.mm[0], 0x0123_4567_89AB_CDEF);
    assert_eq!(regs.mm[1], 0x0123_4567_89AB_CDEF);
    assert_eq!(regs.mm[2], 0x0123_4567_89AB_CDEF);
    assert_eq!(regs.x87_tag_word, 0);
    assert_eq!(regs.rflags & 0x8D5, 0x8D5);
}
#[test]
fn lower_mmx_word_lane_ops_emit_directional_rex_and_reject_malformed_ir() {
    let mm = |index| VReg::Arch(ArchReg::X86(X86Reg::Mm(index)));
    let gpr = |reg| VReg::Arch(ArchReg::X86(reg));
    for (name, kind, opcode, expected) in [
        (
            "PINSRW mm1,r10w,3",
            OpKind::VInsertLane {
                dst: mm(1),
                vec: mm(1),
                scalar: gpr(X86Reg::R10),
                lane: 3,
                elem: VecElementType::I16,
            },
            0xC4,
            &[0x41, 0x0F, 0xC4, 0xCA, 0x03][..],
        ),
        (
            "PEXTRW r8d,mm2,3",
            OpKind::VExtractLane {
                dst: gpr(X86Reg::R8),
                vec: mm(2),
                lane: 3,
                elem: VecElementType::I16,
                sign: SignExtend::Zero,
            },
            0xC5,
            &[0x44, 0x0F, 0xC5, 0xC2, 0x03][..],
        ),
    ] {
        let code = lower_single_hinted_op(
            kind,
            X86OpHint::SseOp {
                prefix: X86SsePrefix::None,
                opcode,
            },
        );
        assert!(
            code.windows(expected.len())
                .any(|window| window == expected),
            "{name}: missing {expected:02X?} in {code:02X?}"
        );
    }

    for (kind, hint) in [
        (
            OpKind::VInsertLane {
                dst: mm(1),
                vec: mm(2),
                scalar: gpr(X86Reg::R10),
                lane: 3,
                elem: VecElementType::I16,
            },
            X86OpHint::SseOp {
                prefix: X86SsePrefix::None,
                opcode: 0xC4,
            },
        ),
        (
            OpKind::VInsertLane {
                dst: mm(1),
                vec: mm(1),
                scalar: gpr(X86Reg::Rbp),
                lane: 3,
                elem: VecElementType::I16,
            },
            X86OpHint::SseOp {
                prefix: X86SsePrefix::None,
                opcode: 0xC4,
            },
        ),
        (
            OpKind::VExtractLane {
                dst: gpr(X86Reg::R8),
                vec: mm(2),
                lane: 4,
                elem: VecElementType::I16,
                sign: SignExtend::Zero,
            },
            X86OpHint::SseOp {
                prefix: X86SsePrefix::None,
                opcode: 0xC5,
            },
        ),
        (
            OpKind::VExtractLane {
                dst: gpr(X86Reg::R8),
                vec: mm(2),
                lane: 3,
                elem: VecElementType::I16,
                sign: SignExtend::Sign,
            },
            X86OpHint::SseOp {
                prefix: X86SsePrefix::OpSize,
                opcode: 0xC5,
            },
        ),
    ] {
        assert!(matches!(
            lower_single_hinted_op_err(kind, hint),
            LowerError::InvalidOperand { .. } | LowerError::InvalidRegister(_)
        ));
    }
}
#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[test]
fn native_mmx_word_lane_ops_execute_extended_gprs_and_round_trip_state() {
    use crate::smir::lower::runtime::{ExecMem, GuestRegs};

    let mm1 = VReg::Arch(ArchReg::X86(X86Reg::Mm(1)));
    let r8 = VReg::Arch(ArchReg::X86(X86Reg::R8));
    let r10 = VReg::Arch(ArchReg::X86(X86Reg::R10));
    let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
    builder.push_op(
        0x1000,
        OpKind::X86X87Control {
            kind: X86X87ControlKind::EnterMmx,
            addr: None,
        },
    );
    builder.push_op(
        0x1000,
        OpKind::VInsertLane {
            dst: mm1,
            vec: mm1,
            scalar: r10,
            lane: 2,
            elem: VecElementType::I16,
        },
    );
    builder.push_op(
        0x1000,
        OpKind::X86X87Control {
            kind: X86X87ControlKind::EnterMmx,
            addr: None,
        },
    );
    builder.push_op(
        0x1000,
        OpKind::VExtractLane {
            dst: r8,
            vec: mm1,
            lane: 2,
            elem: VecElementType::I16,
            sign: SignExtend::Zero,
        },
    );
    builder.set_terminator(Terminator::Return { values: vec![] });
    let mut function = builder.finish();
    function.blocks[0].ops[1].x86_hint = Some(X86OpHint::SseOp {
        prefix: X86SsePrefix::None,
        opcode: 0xC4,
    });
    function.blocks[0].ops[3].x86_hint = Some(X86OpHint::SseOp {
        prefix: X86SsePrefix::None,
        opcode: 0xC5,
    });

    let mut lowerer = X86_64Lowerer::new();
    let lowered = lowerer
        .lower_function(&function)
        .expect("lower native MMX word lane operations");
    let code = lowerer.finalize().expect("finalize MMX word lane code");
    let exec = ExecMem::new(&code).expect("map MMX word lane code");
    let mut regs = GuestRegs {
        mm: [0, 0x4444_3333_2222_1111, 0, 0, 0, 0, 0, 0],
        mmx_active: 1,
        x87_tag_word: 0xFFFF,
        rflags: 0x2 | 0x8D5,
        ..GuestRegs::default()
    };
    regs.gpr[8] = u64::MAX;
    regs.gpr[10] = 0xDEAD_BEEF_CAFE_A1B2;
    exec.run(lowered.entry_offset, &mut regs);

    assert_eq!(regs.mm[1], 0x4444_A1B2_2222_1111);
    assert_eq!(regs.gpr[8], 0xA1B2);
    assert_eq!(regs.gpr[10], 0xDEAD_BEEF_CAFE_A1B2);
    assert_eq!(regs.x87_tag_word, 0);
    assert_eq!(regs.rflags & 0x8D5, 0x8D5);
}
#[test]
fn lower_mmx_movd_q_emits_bidirectional_width_exact_register_encodings() {
    let mm = |index| VReg::Arch(ArchReg::X86(X86Reg::Mm(index)));
    let gpr = |reg| VReg::Arch(ArchReg::X86(reg));
    for (name, kind, opcode, expected) in [
        (
            "MOVD mm1,eax",
            OpKind::X86MovdQ {
                dst: mm(1),
                src: gpr(X86Reg::Rax),
                width: OpWidth::W32,
                zero_upper: false,
            },
            0x6E,
            &[0x0F, 0x6E, 0xC8][..],
        ),
        (
            "MOVQ mm1,r10",
            OpKind::X86MovdQ {
                dst: mm(1),
                src: gpr(X86Reg::R10),
                width: OpWidth::W64,
                zero_upper: false,
            },
            0x6E,
            &[0x49, 0x0F, 0x6E, 0xCA][..],
        ),
        (
            "MOVD eax,mm1",
            OpKind::X86MovdQ {
                dst: gpr(X86Reg::Rax),
                src: mm(1),
                width: OpWidth::W32,
                zero_upper: false,
            },
            0x7E,
            &[0x0F, 0x7E, 0xC8][..],
        ),
        (
            "MOVQ r10,mm1",
            OpKind::X86MovdQ {
                dst: gpr(X86Reg::R10),
                src: mm(1),
                width: OpWidth::W64,
                zero_upper: false,
            },
            0x7E,
            &[0x49, 0x0F, 0x7E, 0xCA][..],
        ),
    ] {
        let code = lower_single_hinted_op(
            kind,
            X86OpHint::SseOp {
                prefix: X86SsePrefix::None,
                opcode,
            },
        );
        assert!(
            code.windows(expected.len())
                .any(|window| window == expected),
            "{name}: missing {expected:02X?} in {code:02X?}"
        );
    }

    assert!(matches!(
        lower_single_hinted_op_err(
            OpKind::X86MovdQ {
                dst: mm(1),
                src: gpr(X86Reg::Rax),
                width: OpWidth::W64,
                zero_upper: true,
            },
            X86OpHint::SseOp {
                prefix: X86SsePrefix::None,
                opcode: 0x6E,
            },
        ),
        LowerError::InvalidOperand { .. }
    ));
}
#[test]
fn lower_mmx_align_right_emits_ssse3_immediate_opcode_and_rejects_malformed() {
    let mm = |index| VReg::Arch(ArchReg::X86(X86Reg::Mm(index)));
    let align = |dst, high, low, width| OpKind::X86PackedAlignRight {
        dst,
        high,
        low,
        width,
        amount: 0x25,
    };
    let hint = X86OpHint::SseOp {
        prefix: X86SsePrefix::None,
        opcode: 0x0F,
    };
    let code = lower_single_hinted_op(align(mm(0), mm(0), mm(1), VecWidth::V64), hint);
    assert!(
        code.windows(5)
            .any(|window| window == [0x0F, 0x3A, 0x0F, 0xC1, 0x25]),
        "missing MMX PALIGNR 0F 3A 0F /r ib: {code:02X?}"
    );

    for (kind, malformed_hint) in [
        (align(mm(0), mm(2), mm(1), VecWidth::V64), hint),
        (align(mm(0), mm(0), mm(1), VecWidth::V128), hint),
        (
            align(mm(0), mm(0), mm(1), VecWidth::V64),
            X86OpHint::SseOp {
                prefix: X86SsePrefix::OpSize,
                opcode: 0x0F,
            },
        ),
    ] {
        assert!(matches!(
            lower_single_hinted_op_err(kind, malformed_hint),
            LowerError::InvalidOperand { .. }
        ));
    }
}
#[test]
fn lower_mmx_word_shuffle_emits_immediate_opcode_and_rejects_malformed() {
    let mm = |index| VReg::Arch(ArchReg::X86(X86Reg::Mm(index)));
    let shuffle = |dst, src, width, high_words| OpKind::X86PackedShuffleImm {
        dst,
        src,
        width,
        elem: VecElementType::I16,
        imm: 0x1B,
        high_words,
    };
    let hint = X86OpHint::SseOp {
        prefix: X86SsePrefix::None,
        opcode: 0x70,
    };
    let code = lower_single_hinted_op(shuffle(mm(0), mm(1), VecWidth::V64, None), hint);
    assert!(
        code.windows(4)
            .any(|window| window == [0x0F, 0x70, 0xC1, 0x1B]),
        "missing MMX PSHUFW 0F 70 /r ib: {code:02X?}"
    );

    for (kind, malformed_hint) in [
        (shuffle(mm(0), mm(1), VecWidth::V128, None), hint),
        (shuffle(mm(0), mm(1), VecWidth::V64, Some(true)), hint),
        (
            shuffle(mm(0), mm(1), VecWidth::V64, None),
            X86OpHint::SseOp {
                prefix: X86SsePrefix::OpSize,
                opcode: 0x70,
            },
        ),
    ] {
        assert!(matches!(
            lower_single_hinted_op_err(kind, malformed_hint),
            LowerError::InvalidOperand { .. }
        ));
    }
}
#[test]
fn lower_mmx_word_multiply_emits_low_and_high_classic_opcodes() {
    let mm = |index| VReg::Arch(ArchReg::X86(X86Reg::Mm(index)));
    let kinds = [
        OpKind::VMul {
            dst: mm(1),
            src1: mm(1),
            src2: mm(4),
            elem: VecElementType::I16,
            lanes: 4,
        },
        OpKind::VMulShiftSat {
            dst: mm(1),
            src1: mm(1),
            src2: mm(4),
            src_elem: VecElementType::I16,
            lanes: 4,
            signed1: false,
            signed2: false,
            shift_left: 0,
            round: false,
            sat_bits: 0,
            out_shift: 16,
        },
        OpKind::VMulShiftSat {
            dst: mm(1),
            src1: mm(1),
            src2: mm(4),
            src_elem: VecElementType::I16,
            lanes: 4,
            signed1: true,
            signed2: true,
            shift_left: 0,
            round: false,
            sat_bits: 0,
            out_shift: 16,
        },
    ];
    for (kind, opcode) in kinds.into_iter().zip([0xD5, 0xE4, 0xE5]) {
        let code = lower_single_hinted_op(
            kind,
            X86OpHint::SseOp {
                prefix: X86SsePrefix::None,
                opcode,
            },
        );
        assert!(
            code.windows(3).any(|window| window == [0x0F, opcode, 0xCC]),
            "missing MMX multiply 0F {opcode:02X} /r: {code:02X?}"
        );
    }
}
#[test]
fn lower_x86_packed_fp_convert_emits_legacy_and_vex_native_opcodes() {
    fn lower_hinted(kind: OpKind, hint: X86OpHint) -> Vec<u8> {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
        builder.push_op(0x1000, kind);
        builder.set_terminator(Terminator::Return { values: vec![] });
        let mut func = builder.finish();
        func.blocks[0].ops[0].x86_hint = Some(hint);
        let mut lowerer = X86_64Lowerer::new();
        let result = lowerer.lower_function(&func).expect("lower hinted op");
        assert!(result.relocations.is_empty());
        lowerer.finalize().expect("finalize")
    }

    let xmm0 = VReg::Arch(ArchReg::X86(X86Reg::Xmm(0)));
    let xmm1 = VReg::Arch(ArchReg::X86(X86Reg::Xmm(1)));
    let ymm0 = VReg::Arch(ArchReg::X86(X86Reg::Ymm(0)));
    let ymm1 = VReg::Arch(ArchReg::X86(X86Reg::Ymm(1)));

    for (name, kind, expected) in [
        (
            "CVTPS2PD xmm0,xmm1",
            OpKind::X86PackedFpConvert {
                dst: xmm0,
                src: xmm1,
                mask: None,
                from: VecElementType::F32,
                to: VecElementType::F64,
                lanes: 2,
                dst_width: VecWidth::V128,
                mask_zeroing: false,
                zero_upper: false,
                round: FpRoundMode::Dynamic,
                suppress_exceptions: false,
                report_fp16_denormal: false,
            },
            &[0x0F, 0x5A, 0xC1][..],
        ),
        (
            "CVTPD2PS xmm0,xmm1",
            OpKind::X86PackedFpConvert {
                dst: xmm0,
                src: xmm1,
                mask: None,
                from: VecElementType::F64,
                to: VecElementType::F32,
                lanes: 2,
                dst_width: VecWidth::V128,
                mask_zeroing: false,
                zero_upper: false,
                round: FpRoundMode::Dynamic,
                suppress_exceptions: false,
                report_fp16_denormal: false,
            },
            &[0x66, 0x0F, 0x5A, 0xC1][..],
        ),
    ] {
        let code = lower_single_op(kind);
        assert!(
            code.windows(expected.len())
                .any(|window| window == expected),
            "{name}: missing native opcode in {code:02X?}"
        );
    }

    for (name, kind, hint, expected) in [
        (
            "VCVTPS2PD ymm0,xmm1",
            OpKind::X86PackedFpConvert {
                dst: ymm0,
                src: xmm1,
                mask: None,
                from: VecElementType::F32,
                to: VecElementType::F64,
                lanes: 4,
                dst_width: VecWidth::V256,
                mask_zeroing: false,
                zero_upper: true,
                round: FpRoundMode::Dynamic,
                suppress_exceptions: false,
                report_fp16_denormal: false,
            },
            X86OpHint::VexOp {
                map: X86VecMap::Map0F,
                pp: X86SsePrefix::None,
                opcode: 0x5A,
                width: VecWidth::V256,
                w: false,
            },
            &[0xC5, 0xFC, 0x5A, 0xC1][..],
        ),
        (
            "VCVTPD2PS xmm0,ymm1",
            OpKind::X86PackedFpConvert {
                dst: xmm0,
                src: ymm1,
                mask: None,
                from: VecElementType::F64,
                to: VecElementType::F32,
                lanes: 4,
                dst_width: VecWidth::V128,
                mask_zeroing: false,
                zero_upper: true,
                round: FpRoundMode::Dynamic,
                suppress_exceptions: false,
                report_fp16_denormal: false,
            },
            X86OpHint::VexOp {
                map: X86VecMap::Map0F,
                pp: X86SsePrefix::OpSize,
                opcode: 0x5A,
                width: VecWidth::V256,
                w: false,
            },
            &[0xC5, 0xFD, 0x5A, 0xC1][..],
        ),
    ] {
        let code = lower_hinted(kind, hint);
        assert!(
            code.windows(expected.len())
                .any(|window| window == expected),
            "{name}: missing native opcode in {code:02X?}"
        );
    }

    let zmm0 = VReg::Arch(ArchReg::X86(X86Reg::Zmm(0)));
    let zmm1 = VReg::Arch(ArchReg::X86(X86Reg::Zmm(1)));
    let zmm6 = VReg::Arch(ArchReg::X86(X86Reg::Zmm(6)));
    let ymm5 = VReg::Arch(ArchReg::X86(X86Reg::Ymm(5)));
    let k1 = VReg::Arch(ArchReg::X86(X86Reg::K(1)));
    let k3 = VReg::Arch(ArchReg::X86(X86Reg::K(3)));
    let k4 = VReg::Arch(ArchReg::X86(X86Reg::K(4)));
    for (name, kind, expected) in [
        (
            "VCVTPS2PD zmm0{k1}{z},ymm1",
            OpKind::X86PackedFpConvert {
                dst: zmm0,
                src: ymm1,
                mask: Some(k1),
                from: VecElementType::F32,
                to: VecElementType::F64,
                lanes: 8,
                dst_width: VecWidth::V512,
                mask_zeroing: true,
                zero_upper: true,
                round: FpRoundMode::Dynamic,
                suppress_exceptions: false,
                report_fp16_denormal: false,
            },
            &[0x62, 0xF1, 0x7C, 0xC9, 0x5A, 0xC1][..],
        ),
        (
            "VCVTPD2PS ymm5{k4}{z},zmm6",
            OpKind::X86PackedFpConvert {
                dst: ymm5,
                src: zmm6,
                mask: Some(k4),
                from: VecElementType::F64,
                to: VecElementType::F32,
                lanes: 8,
                dst_width: VecWidth::V256,
                mask_zeroing: true,
                zero_upper: true,
                round: FpRoundMode::Dynamic,
                suppress_exceptions: false,
                report_fp16_denormal: false,
            },
            &[0x62, 0xF1, 0xFD, 0xCC, 0x5A, 0xEE][..],
        ),
        (
            "VCVTPS2PD zmm18{k3},ymm17",
            OpKind::X86PackedFpConvert {
                dst: VReg::Arch(ArchReg::X86(X86Reg::Zmm(18))),
                src: VReg::Arch(ArchReg::X86(X86Reg::Ymm(17))),
                mask: Some(k3),
                from: VecElementType::F32,
                to: VecElementType::F64,
                lanes: 8,
                dst_width: VecWidth::V512,
                mask_zeroing: false,
                zero_upper: true,
                round: FpRoundMode::Dynamic,
                suppress_exceptions: false,
                report_fp16_denormal: false,
            },
            &[0x62, 0xA1, 0x7C, 0x4B, 0x5A, 0xD1][..],
        ),
        (
            "VCVTPD2PS ymm0{k1},zmm1,{rd-sae}",
            OpKind::X86PackedFpConvert {
                dst: ymm0,
                src: zmm1,
                mask: Some(k1),
                from: VecElementType::F64,
                to: VecElementType::F32,
                lanes: 8,
                dst_width: VecWidth::V256,
                mask_zeroing: false,
                zero_upper: true,
                round: FpRoundMode::RoundDown,
                suppress_exceptions: true,
                report_fp16_denormal: false,
            },
            &[0x62, 0xF1, 0xFD, 0x39, 0x5A, 0xC1][..],
        ),
    ] {
        let code = lower_hinted(
            kind,
            X86OpHint::EvexOp {
                map: X86VecMap::Map0F,
                pp: if name.contains("PD2PS") {
                    X86SsePrefix::OpSize
                } else {
                    X86SsePrefix::None
                },
                opcode: 0x5A,
                width: VecWidth::V512,
                w: name.contains("PD2PS"),
            },
        );
        assert!(
            code.windows(expected.len())
                .any(|window| window == expected),
            "{name}: missing EVEX opcode in {code:02X?}"
        );
    }
}
#[test]
fn lower_x86_packed_fp32_fp64_integer_conversions_are_canonical_and_shape_safe() {
    let xmm1 = VReg::Arch(ArchReg::X86(X86Reg::Xmm(1)));
    let xmm2 = VReg::Arch(ArchReg::X86(X86Reg::Xmm(2)));
    for (name, kind, expected) in [
        (
            "CVTDQ2PS xmm1,xmm2",
            OpKind::X86PackedIntToFp {
                dst: xmm1,
                src: xmm2,
                mask: None,
                int_elem: VecElementType::I32,
                fp_elem: VecElementType::F32,
                signed: true,
                lanes: 4,
                src_width: VecWidth::V128,
                dst_width: VecWidth::V128,
                mask_zeroing: false,
                zero_upper: false,
                round: FpRoundMode::Dynamic,
                suppress_exceptions: false,
            },
            &[0x0F, 0x5B, 0xCA][..],
        ),
        (
            "CVTDQ2PD xmm1,xmm2",
            OpKind::X86PackedIntToFp {
                dst: xmm1,
                src: xmm2,
                mask: None,
                int_elem: VecElementType::I32,
                fp_elem: VecElementType::F64,
                signed: true,
                lanes: 2,
                src_width: VecWidth::V64,
                dst_width: VecWidth::V128,
                mask_zeroing: false,
                zero_upper: false,
                round: FpRoundMode::Dynamic,
                suppress_exceptions: false,
            },
            &[0xF3, 0x0F, 0xE6, 0xCA][..],
        ),
        (
            "CVTPS2DQ xmm1,xmm2",
            OpKind::X86PackedFpToInt {
                dst: xmm1,
                src: xmm2,
                mask: None,
                fp_elem: VecElementType::F32,
                int_elem: VecElementType::I32,
                signed: true,
                truncate: false,
                lanes: 4,
                src_width: VecWidth::V128,
                dst_width: VecWidth::V128,
                mask_zeroing: false,
                zero_upper: false,
                round: FpRoundMode::Dynamic,
                suppress_exceptions: false,
            },
            &[0x66, 0x0F, 0x5B, 0xCA][..],
        ),
        (
            "CVTTPD2DQ xmm1,xmm2",
            OpKind::X86PackedFpToInt {
                dst: xmm1,
                src: xmm2,
                mask: None,
                fp_elem: VecElementType::F64,
                int_elem: VecElementType::I32,
                signed: true,
                truncate: true,
                lanes: 2,
                src_width: VecWidth::V128,
                dst_width: VecWidth::V128,
                mask_zeroing: false,
                zero_upper: false,
                round: FpRoundMode::RoundTowardZero,
                suppress_exceptions: false,
            },
            &[0x66, 0x0F, 0xE6, 0xCA][..],
        ),
    ] {
        let code = lower_single_op(kind);
        assert!(
            code.windows(expected.len())
                .any(|window| window == expected),
            "{name}: missing {expected:02X?} in {code:02X?}"
        );
    }

    let vex = lower_single_hinted_op(
        OpKind::X86PackedFpToInt {
            dst: xmm1,
            src: VReg::Arch(ArchReg::X86(X86Reg::Ymm(2))),
            mask: None,
            fp_elem: VecElementType::F64,
            int_elem: VecElementType::I32,
            signed: true,
            truncate: false,
            lanes: 4,
            src_width: VecWidth::V256,
            dst_width: VecWidth::V128,
            mask_zeroing: false,
            zero_upper: true,
            round: FpRoundMode::Dynamic,
            suppress_exceptions: false,
        },
        X86OpHint::VexOp {
            map: X86VecMap::Map0F,
            pp: X86SsePrefix::Repne,
            opcode: 0xE6,
            width: VecWidth::V256,
            w: false,
        },
    );
    assert!(
        vex.windows(4)
            .any(|window| window == [0xC5, 0xFF, 0xE6, 0xCA])
    );

    let k2 = VReg::Arch(ArchReg::X86(X86Reg::K(2)));
    let k3 = VReg::Arch(ArchReg::X86(X86Reg::K(3)));
    for (name, kind, hint, expected) in [
        (
            "VCVTQQ2PS ymm17{k3}{z},zmm18,{rd-sae}",
            OpKind::X86PackedIntToFp {
                dst: VReg::Arch(ArchReg::X86(X86Reg::Ymm(17))),
                src: VReg::Arch(ArchReg::X86(X86Reg::Zmm(18))),
                mask: Some(k3),
                int_elem: VecElementType::I64,
                fp_elem: VecElementType::F32,
                signed: true,
                lanes: 8,
                src_width: VecWidth::V512,
                dst_width: VecWidth::V256,
                mask_zeroing: true,
                zero_upper: true,
                round: FpRoundMode::RoundDown,
                suppress_exceptions: true,
            },
            X86OpHint::EvexOp {
                map: X86VecMap::Map0F,
                pp: X86SsePrefix::None,
                opcode: 0x5B,
                width: VecWidth::V512,
                w: true,
            },
            &[0x62, 0xA1, 0xFC, 0xBB, 0x5B, 0xCA][..],
        ),
        (
            "VCVTUDQ2PD zmm1{k2},ymm3",
            OpKind::X86PackedIntToFp {
                dst: VReg::Arch(ArchReg::X86(X86Reg::Zmm(1))),
                src: VReg::Arch(ArchReg::X86(X86Reg::Ymm(3))),
                mask: Some(k2),
                int_elem: VecElementType::I32,
                fp_elem: VecElementType::F64,
                signed: false,
                lanes: 8,
                src_width: VecWidth::V256,
                dst_width: VecWidth::V512,
                mask_zeroing: false,
                zero_upper: true,
                round: FpRoundMode::Dynamic,
                suppress_exceptions: false,
            },
            X86OpHint::EvexOp {
                map: X86VecMap::Map0F,
                pp: X86SsePrefix::Rep,
                opcode: 0x7A,
                width: VecWidth::V512,
                w: false,
            },
            &[0x62, 0xF1, 0x7E, 0x4A, 0x7A, 0xCB][..],
        ),
        (
            "VCVTPS2DQ zmm1{k2}{z},zmm3,{ru-sae}",
            OpKind::X86PackedFpToInt {
                dst: VReg::Arch(ArchReg::X86(X86Reg::Zmm(1))),
                src: VReg::Arch(ArchReg::X86(X86Reg::Zmm(3))),
                mask: Some(k2),
                fp_elem: VecElementType::F32,
                int_elem: VecElementType::I32,
                signed: true,
                truncate: false,
                lanes: 16,
                src_width: VecWidth::V512,
                dst_width: VecWidth::V512,
                mask_zeroing: true,
                zero_upper: true,
                round: FpRoundMode::RoundUp,
                suppress_exceptions: true,
            },
            X86OpHint::EvexOp {
                map: X86VecMap::Map0F,
                pp: X86SsePrefix::OpSize,
                opcode: 0x5B,
                width: VecWidth::V512,
                w: false,
            },
            &[0x62, 0xF1, 0x7D, 0xDA, 0x5B, 0xCB][..],
        ),
        (
            "VCVTTPD2UQQ zmm1{k2},zmm3",
            OpKind::X86PackedFpToInt {
                dst: VReg::Arch(ArchReg::X86(X86Reg::Zmm(1))),
                src: VReg::Arch(ArchReg::X86(X86Reg::Zmm(3))),
                mask: Some(k2),
                fp_elem: VecElementType::F64,
                int_elem: VecElementType::I64,
                signed: false,
                truncate: true,
                lanes: 8,
                src_width: VecWidth::V512,
                dst_width: VecWidth::V512,
                mask_zeroing: false,
                zero_upper: true,
                round: FpRoundMode::RoundTowardZero,
                suppress_exceptions: false,
            },
            X86OpHint::EvexOp {
                map: X86VecMap::Map0F,
                pp: X86SsePrefix::OpSize,
                opcode: 0x78,
                width: VecWidth::V512,
                w: true,
            },
            &[0x62, 0xF1, 0xFD, 0x4A, 0x78, 0xCB][..],
        ),
    ] {
        let code = lower_single_hinted_op(kind, hint);
        assert!(
            code.windows(expected.len())
                .any(|window| window == expected),
            "{name}: missing {expected:02X?} in {code:02X?}"
        );
    }

    // Round-trip every EVEX opcode/pp/W semantic family through the
    // production lifter and lowerer. Register encodings are canonical, so
    // the instruction bytes must be reproduced exactly.
    for instruction in [
        &[0x62, 0xF1, 0x7C, 0x4A, 0x5B, 0xCB][..],
        &[0x62, 0xA1, 0xFC, 0x4B, 0x5B, 0xCA][..],
        &[0x62, 0xF1, 0x7F, 0x4A, 0x7A, 0xCB][..],
        &[0x62, 0xF1, 0xFF, 0x4A, 0x7A, 0xCB][..],
        &[0x62, 0xF1, 0x7E, 0x48, 0xE6, 0xCB][..],
        &[0x62, 0xF1, 0xFE, 0x48, 0xE6, 0xCB][..],
        &[0x62, 0xF1, 0x7E, 0x4A, 0x7A, 0xCB][..],
        &[0x62, 0xF1, 0xFE, 0x4A, 0x7A, 0xCB][..],
        &[0x62, 0xF1, 0x7D, 0x4A, 0x5B, 0xCB][..],
        &[0x62, 0xF1, 0x7E, 0x4A, 0x5B, 0xCB][..],
        &[0x62, 0xF1, 0xFF, 0x4A, 0xE6, 0xCB][..],
        &[0x62, 0xF1, 0xFD, 0x4A, 0xE6, 0xCB][..],
        &[0x62, 0xF1, 0x7D, 0x4A, 0x7B, 0xCB][..],
        &[0x62, 0xF1, 0x7D, 0x4A, 0x7A, 0xCB][..],
        &[0x62, 0xF1, 0xFD, 0x4A, 0x7B, 0xCB][..],
        &[0x62, 0xF1, 0xFD, 0x4A, 0x7A, 0xCB][..],
        &[0x62, 0xF1, 0x7C, 0x4A, 0x79, 0xCB][..],
        &[0x62, 0xF1, 0x7C, 0x4A, 0x78, 0xCB][..],
        &[0x62, 0xF1, 0xFC, 0x4A, 0x79, 0xCB][..],
        &[0x62, 0xF1, 0xFC, 0x4A, 0x78, 0xCB][..],
        &[0x62, 0xF1, 0x7D, 0x4A, 0x79, 0xCB][..],
        &[0x62, 0xF1, 0x7D, 0x4A, 0x78, 0xCB][..],
        &[0x62, 0xF1, 0xFD, 0x4A, 0x79, 0xCB][..],
        &[0x62, 0xF1, 0xFD, 0x4A, 0x78, 0xCB][..],
    ] {
        let mut block = instruction.to_vec();
        block.push(0xF4);
        let (code, _) = lower_rex2_block(&block);
        assert!(
            code.windows(instruction.len())
                .any(|window| window == instruction),
            "round-trip missing {instruction:02X?} in {code:02X?}"
        );
    }

    let malformed = OpKind::X86PackedIntToFp {
        dst: VReg::Arch(ArchReg::X86(X86Reg::Zmm(1))),
        src: VReg::Arch(ArchReg::X86(X86Reg::Ymm(3))),
        mask: Some(k2),
        int_elem: VecElementType::I32,
        fp_elem: VecElementType::F64,
        signed: false,
        lanes: 8,
        src_width: VecWidth::V512,
        dst_width: VecWidth::V512,
        mask_zeroing: false,
        zero_upper: true,
        round: FpRoundMode::Dynamic,
        suppress_exceptions: false,
    };
    assert!(matches!(
        lower_single_hinted_op_err(
            malformed,
            X86OpHint::EvexOp {
                map: X86VecMap::Map0F,
                pp: X86SsePrefix::Rep,
                opcode: 0x7A,
                width: VecWidth::V512,
                w: false,
            }
        ),
        LowerError::InvalidOperand { .. }
    ));

    let ties_away = OpKind::X86PackedFpToInt {
        dst: VReg::Arch(ArchReg::X86(X86Reg::Zmm(1))),
        src: VReg::Arch(ArchReg::X86(X86Reg::Zmm(3))),
        mask: Some(k2),
        fp_elem: VecElementType::F64,
        int_elem: VecElementType::I64,
        signed: true,
        truncate: false,
        lanes: 8,
        src_width: VecWidth::V512,
        dst_width: VecWidth::V512,
        mask_zeroing: false,
        zero_upper: true,
        round: FpRoundMode::RoundNearestTiesAway,
        suppress_exceptions: true,
    };
    assert!(matches!(
        lower_single_hinted_op_err(
            ties_away,
            X86OpHint::EvexOp {
                map: X86VecMap::Map0F,
                pp: X86SsePrefix::OpSize,
                opcode: 0x7B,
                width: VecWidth::V512,
                w: true,
            }
        ),
        LowerError::InvalidOperand { .. }
    ));
}
#[test]
fn lower_x86_packed_int_to_fp16_emits_canonical_evex_and_rejects_synthetic_shapes() {
    let k2 = VReg::Arch(ArchReg::X86(X86Reg::K(2)));
    let k3 = VReg::Arch(ArchReg::X86(X86Reg::K(3)));
    let k5 = VReg::Arch(ArchReg::X86(X86Reg::K(5)));
    let k6 = VReg::Arch(ArchReg::X86(X86Reg::K(6)));
    for (name, kind, hint, expected) in [
        (
            "VCVTDQ2PH xmm1{k2}{z},xmm3",
            OpKind::X86PackedIntToFp16 {
                dst: VReg::Arch(ArchReg::X86(X86Reg::Xmm(1))),
                src: VReg::Arch(ArchReg::X86(X86Reg::Xmm(3))),
                mask: Some(k2),
                int_elem: VecElementType::I32,
                signed: true,
                lanes: 4,
                src_width: VecWidth::V128,
                dst_width: VecWidth::V64,
                mask_zeroing: true,
                zero_upper: true,
                round: FpRoundMode::Dynamic,
                suppress_exceptions: false,
            },
            X86OpHint::EvexOp {
                map: X86VecMap::Map5,
                pp: X86SsePrefix::None,
                opcode: 0x5B,
                width: VecWidth::V128,
                w: false,
            },
            &[0x62, 0xF5, 0x7C, 0x8A, 0x5B, 0xCB][..],
        ),
        (
            "VCVTQQ2PH xmm17{k3}{z},zmm18,{rd-sae}",
            OpKind::X86PackedIntToFp16 {
                dst: VReg::Arch(ArchReg::X86(X86Reg::Xmm(17))),
                src: VReg::Arch(ArchReg::X86(X86Reg::Zmm(18))),
                mask: Some(k3),
                int_elem: VecElementType::I64,
                signed: true,
                lanes: 8,
                src_width: VecWidth::V512,
                dst_width: VecWidth::V128,
                mask_zeroing: true,
                zero_upper: true,
                round: FpRoundMode::RoundDown,
                suppress_exceptions: true,
            },
            X86OpHint::EvexOp {
                map: X86VecMap::Map5,
                pp: X86SsePrefix::None,
                opcode: 0x5B,
                width: VecWidth::V512,
                w: true,
            },
            &[0x62, 0xA5, 0xFC, 0xBB, 0x5B, 0xCA][..],
        ),
        (
            "VCVTUDQ2PH xmm4{k5}{z},ymm6",
            OpKind::X86PackedIntToFp16 {
                dst: VReg::Arch(ArchReg::X86(X86Reg::Xmm(4))),
                src: VReg::Arch(ArchReg::X86(X86Reg::Ymm(6))),
                mask: Some(k5),
                int_elem: VecElementType::I32,
                signed: false,
                lanes: 8,
                src_width: VecWidth::V256,
                dst_width: VecWidth::V128,
                mask_zeroing: true,
                zero_upper: true,
                round: FpRoundMode::Dynamic,
                suppress_exceptions: false,
            },
            X86OpHint::EvexOp {
                map: X86VecMap::Map5,
                pp: X86SsePrefix::Repne,
                opcode: 0x7A,
                width: VecWidth::V256,
                w: false,
            },
            &[0x62, 0xF5, 0x7F, 0xAD, 0x7A, 0xE6][..],
        ),
        (
            "VCVTW2PH zmm7{k6}{z},zmm8,{rn-sae}",
            OpKind::X86PackedIntToFp16 {
                dst: VReg::Arch(ArchReg::X86(X86Reg::Zmm(7))),
                src: VReg::Arch(ArchReg::X86(X86Reg::Zmm(8))),
                mask: Some(k6),
                int_elem: VecElementType::I16,
                signed: true,
                lanes: 32,
                src_width: VecWidth::V512,
                dst_width: VecWidth::V512,
                mask_zeroing: true,
                zero_upper: true,
                round: FpRoundMode::RoundNearest,
                suppress_exceptions: true,
            },
            X86OpHint::EvexOp {
                map: X86VecMap::Map5,
                pp: X86SsePrefix::Rep,
                opcode: 0x7D,
                width: VecWidth::V512,
                w: false,
            },
            &[0x62, 0xD5, 0x7E, 0x9E, 0x7D, 0xF8][..],
        ),
    ] {
        let code = lower_single_hinted_op(kind, hint);
        assert!(
            code.windows(expected.len())
                .any(|window| window == expected),
            "{name}: missing canonical EVEX bytes in {code:02X?}"
        );
    }

    let make = |dst_width, round, suppress_exceptions| OpKind::X86PackedIntToFp16 {
        dst: VReg::Arch(ArchReg::X86(X86Reg::Xmm(1))),
        src: VReg::Arch(ArchReg::X86(X86Reg::Xmm(3))),
        mask: Some(k2),
        int_elem: VecElementType::I32,
        signed: true,
        lanes: 4,
        src_width: VecWidth::V128,
        dst_width,
        mask_zeroing: true,
        zero_upper: true,
        round,
        suppress_exceptions,
    };
    assert!(matches!(
        lower_single_op_err(make(VecWidth::V64, FpRoundMode::Dynamic, false)),
        LowerError::UnsupportedOp { .. }
    ));
    for (kind, hint) in [
        (
            make(VecWidth::V128, FpRoundMode::Dynamic, false),
            X86OpHint::EvexOp {
                map: X86VecMap::Map5,
                pp: X86SsePrefix::None,
                opcode: 0x5B,
                width: VecWidth::V128,
                w: false,
            },
        ),
        (
            make(VecWidth::V64, FpRoundMode::Dynamic, false),
            X86OpHint::EvexOp {
                map: X86VecMap::Map5,
                pp: X86SsePrefix::Repne,
                opcode: 0x7A,
                width: VecWidth::V128,
                w: false,
            },
        ),
        (
            make(VecWidth::V64, FpRoundMode::RoundUp, true),
            X86OpHint::EvexOp {
                map: X86VecMap::Map5,
                pp: X86SsePrefix::None,
                opcode: 0x5B,
                width: VecWidth::V128,
                w: false,
            },
        ),
    ] {
        assert!(matches!(
            lower_single_hinted_op_err(kind, hint),
            LowerError::InvalidOperand { .. }
        ));
    }

    let ties_away = OpKind::X86PackedIntToFp16 {
        dst: VReg::Arch(ArchReg::X86(X86Reg::Ymm(1))),
        src: VReg::Arch(ArchReg::X86(X86Reg::Zmm(3))),
        mask: Some(k2),
        int_elem: VecElementType::I32,
        signed: true,
        lanes: 16,
        src_width: VecWidth::V512,
        dst_width: VecWidth::V256,
        mask_zeroing: true,
        zero_upper: true,
        round: FpRoundMode::RoundNearestTiesAway,
        suppress_exceptions: true,
    };
    assert!(matches!(
        lower_single_hinted_op_err(
            ties_away,
            X86OpHint::EvexOp {
                map: X86VecMap::Map5,
                pp: X86SsePrefix::None,
                opcode: 0x5B,
                width: VecWidth::V512,
                w: false,
            },
        ),
        LowerError::InvalidOperand { .. }
    ));
}
#[test]
fn lower_x86_packed_fp16_to_int_emits_canonical_evex_and_rejects_synthetic_shapes() {
    let k2 = VReg::Arch(ArchReg::X86(X86Reg::K(2)));
    let k3 = VReg::Arch(ArchReg::X86(X86Reg::K(3)));
    let k5 = VReg::Arch(ArchReg::X86(X86Reg::K(5)));
    let k6 = VReg::Arch(ArchReg::X86(X86Reg::K(6)));
    for (name, kind, hint, expected) in [
        (
            "VCVTPH2DQ xmm1{k2}{z},xmm3",
            OpKind::X86PackedFp16ToInt {
                dst: VReg::Arch(ArchReg::X86(X86Reg::Xmm(1))),
                src: VReg::Arch(ArchReg::X86(X86Reg::Xmm(3))),
                mask: Some(k2),
                int_elem: VecElementType::I32,
                signed: true,
                truncate: false,
                lanes: 4,
                src_width: VecWidth::V64,
                dst_width: VecWidth::V128,
                mask_zeroing: true,
                zero_upper: true,
                round: FpRoundMode::Dynamic,
                suppress_exceptions: false,
            },
            X86OpHint::EvexOp {
                map: X86VecMap::Map5,
                pp: X86SsePrefix::OpSize,
                opcode: 0x5B,
                width: VecWidth::V128,
                w: false,
            },
            &[0x62, 0xF5, 0x7D, 0x8A, 0x5B, 0xCB][..],
        ),
        (
            "VCVTPH2QQ zmm17{k3}{z},xmm18,{rd-sae}",
            OpKind::X86PackedFp16ToInt {
                dst: VReg::Arch(ArchReg::X86(X86Reg::Zmm(17))),
                src: VReg::Arch(ArchReg::X86(X86Reg::Xmm(18))),
                mask: Some(k3),
                int_elem: VecElementType::I64,
                signed: true,
                truncate: false,
                lanes: 8,
                src_width: VecWidth::V128,
                dst_width: VecWidth::V512,
                mask_zeroing: true,
                zero_upper: true,
                round: FpRoundMode::RoundDown,
                suppress_exceptions: true,
            },
            X86OpHint::EvexOp {
                map: X86VecMap::Map5,
                pp: X86SsePrefix::OpSize,
                opcode: 0x7B,
                width: VecWidth::V512,
                w: false,
            },
            &[0x62, 0xA5, 0x7D, 0xBB, 0x7B, 0xCA][..],
        ),
        (
            "VCVTTPH2UDQ zmm4{k5}{z},ymm6,{sae}",
            OpKind::X86PackedFp16ToInt {
                dst: VReg::Arch(ArchReg::X86(X86Reg::Zmm(4))),
                src: VReg::Arch(ArchReg::X86(X86Reg::Ymm(6))),
                mask: Some(k5),
                int_elem: VecElementType::I32,
                signed: false,
                truncate: true,
                lanes: 16,
                src_width: VecWidth::V256,
                dst_width: VecWidth::V512,
                mask_zeroing: true,
                zero_upper: true,
                round: FpRoundMode::RoundTowardZero,
                suppress_exceptions: true,
            },
            X86OpHint::EvexOp {
                map: X86VecMap::Map5,
                pp: X86SsePrefix::None,
                opcode: 0x78,
                width: VecWidth::V512,
                w: false,
            },
            &[0x62, 0xF5, 0x7C, 0x9D, 0x78, 0xE6][..],
        ),
        (
            "VCVTPH2UW ymm7{k6}{z},ymm8",
            OpKind::X86PackedFp16ToInt {
                dst: VReg::Arch(ArchReg::X86(X86Reg::Ymm(7))),
                src: VReg::Arch(ArchReg::X86(X86Reg::Ymm(8))),
                mask: Some(k6),
                int_elem: VecElementType::I16,
                signed: false,
                truncate: false,
                lanes: 16,
                src_width: VecWidth::V256,
                dst_width: VecWidth::V256,
                mask_zeroing: true,
                zero_upper: true,
                round: FpRoundMode::Dynamic,
                suppress_exceptions: false,
            },
            X86OpHint::EvexOp {
                map: X86VecMap::Map5,
                pp: X86SsePrefix::None,
                opcode: 0x7D,
                width: VecWidth::V256,
                w: false,
            },
            &[0x62, 0xD5, 0x7C, 0xAE, 0x7D, 0xF8][..],
        ),
    ] {
        let code = lower_single_hinted_op(kind, hint);
        assert!(
            code.windows(expected.len())
                .any(|window| window == expected),
            "{name}: missing canonical EVEX bytes in {code:02X?}"
        );
    }

    let make = |round, suppress_exceptions| OpKind::X86PackedFp16ToInt {
        dst: VReg::Arch(ArchReg::X86(X86Reg::Xmm(1))),
        src: VReg::Arch(ArchReg::X86(X86Reg::Xmm(3))),
        mask: Some(k2),
        int_elem: VecElementType::I32,
        signed: true,
        truncate: false,
        lanes: 4,
        src_width: VecWidth::V64,
        dst_width: VecWidth::V128,
        mask_zeroing: true,
        zero_upper: true,
        round,
        suppress_exceptions,
    };
    assert!(matches!(
        lower_single_op_err(make(FpRoundMode::Dynamic, false)),
        LowerError::UnsupportedOp { .. }
    ));
    for (kind, hint) in [
        (
            make(FpRoundMode::RoundUp, true),
            X86OpHint::EvexOp {
                map: X86VecMap::Map5,
                pp: X86SsePrefix::OpSize,
                opcode: 0x5B,
                width: VecWidth::V128,
                w: false,
            },
        ),
        (
            make(FpRoundMode::Dynamic, false),
            X86OpHint::EvexOp {
                map: X86VecMap::Map5,
                pp: X86SsePrefix::None,
                opcode: 0x79,
                width: VecWidth::V128,
                w: false,
            },
        ),
    ] {
        assert!(matches!(
            lower_single_hinted_op_err(kind, hint),
            LowerError::InvalidOperand { .. }
        ));
    }
}
#[test]
fn lower_x86_packed_fp16_precision_converts_remain_explicitly_interpreter_only() {
    let rax = VReg::Arch(ArchReg::X86(X86Reg::Rax));
    let xmm0 = VReg::Arch(ArchReg::X86(X86Reg::Xmm(0)));
    let xmm1 = VReg::Arch(ArchReg::X86(X86Reg::Xmm(1)));
    let k1 = VReg::Arch(ArchReg::X86(X86Reg::K(1)));
    for (kind, hint) in [
        (
            OpKind::X86PackedFpConvert {
                dst: xmm0,
                src: xmm1,
                mask: Some(k1),
                from: VecElementType::F16,
                to: VecElementType::F64,
                lanes: 2,
                dst_width: VecWidth::V128,
                mask_zeroing: false,
                zero_upper: true,
                round: FpRoundMode::Dynamic,
                suppress_exceptions: false,
                report_fp16_denormal: true,
            },
            X86OpHint::EvexOp {
                map: X86VecMap::Map5,
                pp: X86SsePrefix::None,
                opcode: 0x5A,
                width: VecWidth::V128,
                w: false,
            },
        ),
        (
            OpKind::X86PackedFpConvert {
                dst: xmm0,
                src: xmm1,
                mask: Some(k1),
                from: VecElementType::F32,
                to: VecElementType::F16,
                lanes: 16,
                dst_width: VecWidth::V256,
                mask_zeroing: true,
                zero_upper: true,
                round: FpRoundMode::RoundUp,
                suppress_exceptions: true,
                report_fp16_denormal: false,
            },
            X86OpHint::EvexOp {
                map: X86VecMap::Map5,
                pp: X86SsePrefix::OpSize,
                opcode: 0x1D,
                width: VecWidth::V512,
                w: false,
            },
        ),
        (
            OpKind::X86PackedFpConvertStore {
                addr: Address::Direct(rax),
                src: xmm1,
                mask: Some(k1),
                lanes: 4,
                round: FpRoundMode::Dynamic,
            },
            X86OpHint::EvexOp {
                map: X86VecMap::Map0F3A,
                pp: X86SsePrefix::OpSize,
                opcode: 0x1D,
                width: VecWidth::V128,
                w: false,
            },
        ),
    ] {
        assert!(matches!(
            lower_single_hinted_op_err(kind, hint),
            LowerError::UnsupportedOp { .. } | LowerError::InvalidOperand { .. }
        ));
    }
}
#[test]
fn lower_movx_legacy_high_bytes_uses_stack_snapshot() {
    let gpr = |reg| VReg::Arch(ArchReg::X86(reg));
    for (name, kind, expected) in [
        (
            "movzx eax,ah",
            OpKind::ZeroExtend {
                dst: gpr(X86Reg::Rax),
                src: gpr(X86Reg::Rax),
                from_width: OpWidth::W8,
                to_width: OpWidth::W32,
            },
            &[
                0x50, 0x0F, 0xB6, 0x44, 0x24, 0x01, 0x48, 0x8D, 0x64, 0x24, 0x08,
            ][..],
        ),
        (
            "movsx ecx,bh",
            OpKind::SignExtend {
                dst: gpr(X86Reg::Rcx),
                src: gpr(X86Reg::Rbx),
                from_width: OpWidth::W8,
                to_width: OpWidth::W32,
            },
            &[
                0x53, 0x0F, 0xBE, 0x4C, 0x24, 0x01, 0x48, 0x8D, 0x64, 0x24, 0x08,
            ][..],
        ),
        (
            "movzx dx,ch",
            OpKind::ZeroExtend {
                dst: gpr(X86Reg::Rdx),
                src: gpr(X86Reg::Rcx),
                from_width: OpWidth::W8,
                to_width: OpWidth::W16,
            },
            &[
                0x51, 0x66, 0x0F, 0xB6, 0x54, 0x24, 0x01, 0x48, 0x8D, 0x64, 0x24, 0x08,
            ][..],
        ),
    ] {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
        builder.push_op(0x1000, kind);
        builder.set_terminator(Terminator::Return { values: vec![] });
        let mut func = builder.finish();
        func.blocks[0].ops[0].x86_hint = Some(X86OpHint::LegacyHighByteReg);
        let mut lowerer = X86_64Lowerer::new();
        let result = lowerer.lower_function(&func).expect(name);
        assert!(result.relocations.is_empty(), "{name}");
        let code = lowerer.finalize().expect(name);
        assert!(
            code.windows(expected.len())
                .any(|window| window == expected),
            "{name}: missing {expected:02X?} in {code:02X?}"
        );
    }
}
#[test]
fn lower_movx_legacy_high_byte_hint_rejects_invalid_parent() {
    let gpr = |reg| VReg::Arch(ArchReg::X86(reg));
    let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
    builder.push_op(
        0x1000,
        OpKind::ZeroExtend {
            dst: gpr(X86Reg::Rax),
            src: gpr(X86Reg::Rsi),
            from_width: OpWidth::W8,
            to_width: OpWidth::W32,
        },
    );
    builder.set_terminator(Terminator::Return { values: vec![] });
    let mut func = builder.finish();
    func.blocks[0].ops[0].x86_hint = Some(X86OpHint::LegacyHighByteReg);
    let mut lowerer = X86_64Lowerer::new();
    assert!(lowerer.lower_function(&func).is_err());
}
#[test]
fn lower_helper_backed_vector_memory_uses_state_abi_and_rejects_malformed_ir() {
    let x86 = |reg| VReg::Arch(ArchReg::X86(reg));
    let lower = |kind: OpKind, hint: Option<X86OpHint>| -> Result<Vec<u8>, LowerError> {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
        builder.push_op(0x1000, kind);
        builder.set_terminator(Terminator::Return { values: vec![] });
        let mut function = builder.finish();
        function.blocks[0].ops[0].x86_hint = hint;
        let mut lowerer = X86_64Lowerer::new();
        lowerer.set_mem_helpers(true);
        lowerer.lower_function(&function)?;
        lowerer.finalize()
    };

    let load = lower(
        OpKind::VLoad {
            dst: x86(X86Reg::Ymm(17)),
            addr: Address::BaseOffset {
                base: x86(X86Reg::Rsp),
                offset: 32,
                disp_size: DispSize::Disp8,
            },
            width: VecWidth::V256,
        },
        Some(X86OpHint::VexOp {
            map: X86VecMap::Map0F,
            pp: X86SsePrefix::Rep,
            opcode: 0x6F,
            width: VecWidth::V256,
            w: false,
        }),
    )
    .expect("lower helper-backed YMM load");
    let load_call = host_c_helper_reference(X86_GUEST_VEC_LOAD_FN_OFFSET);
    assert!(
        load.windows(load_call.len())
            .any(|bytes| bytes == load_call)
    );
    assert!(
        load.windows(6)
            .any(|bytes| bytes == [0x41, 0xB8, 1, 0, 0, 0]),
        "VEX load must request upper-lane zeroing: {load:02X?}"
    );

    let legacy = lower(
        OpKind::VLoad {
            dst: x86(X86Reg::Xmm(3)),
            addr: Address::Absolute(0x2000),
            width: VecWidth::V128,
        },
        Some(X86OpHint::SseMov {
            prefix: X86SsePrefix::OpSize,
            opcode: 0x6F,
        }),
    )
    .expect("lower helper-backed legacy XMM load");
    assert!(
        legacy
            .windows(6)
            .any(|bytes| bytes == [0x41, 0xB8, 0, 0, 0, 0]),
        "legacy SSE load must preserve upper lanes: {legacy:02X?}"
    );

    let store = lower(
        OpKind::VStore {
            src: x86(X86Reg::Zmm(31)),
            addr: Address::SegmentRel {
                segment: x86(X86Reg::GsBase),
                base: Some(x86(X86Reg::Rbp)),
                index: Some(x86(X86Reg::R16)),
                scale: 4,
                disp: i64::MAX,
            },
            width: VecWidth::V512,
        },
        None,
    )
    .expect("lower helper-backed ZMM store");
    let store_call = host_c_helper_reference(X86_GUEST_VEC_STORE_FN_OFFSET);
    assert!(
        store
            .windows(store_call.len())
            .any(|bytes| bytes == store_call)
    );

    for malformed in [
        OpKind::VLoad {
            dst: x86(X86Reg::Xmm(0)),
            addr: Address::Direct(x86(X86Reg::Rax)),
            width: VecWidth::V256,
        },
        OpKind::VStore {
            src: VReg::Virtual(crate::smir::ir::types::VirtualId(7)),
            addr: Address::Direct(x86(X86Reg::Rax)),
            width: VecWidth::V128,
        },
        OpKind::VLoad {
            dst: x86(X86Reg::Xmm(0)),
            addr: Address::GpRel { offset: 0 },
            width: VecWidth::V128,
        },
    ] {
        assert!(
            matches!(
                lower(malformed, None),
                Err(LowerError::InvalidOperand { .. }
                    | LowerError::UnsupportedOp { .. }
                    | LowerError::InvalidRegister(_)
                    | LowerError::RegisterAllocationFailed { .. })
            ),
            "malformed vector-memory IR must fail lowering"
        );
    }
}
