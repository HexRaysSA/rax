//! mask part 2 tests

use super::*;
use crate::smir::lift::x86_64::tests::*;
use crate::smir::lift::x86_64::*;

#[test]
fn lift_evex_vpconflict_covers_shapes_prefix_memory_masks_and_invalids() {
    for (bytes, elem, width) in [
        (
            &[0x62, 0xA2, 0x7D, 0x8A, 0xC4, 0xCA][..],
            VecElementType::I32,
            VecWidth::V128,
        ),
        (
            &[0x62, 0xA2, 0xFD, 0x2B, 0xC4, 0xDC][..],
            VecElementType::I64,
            VecWidth::V256,
        ),
    ] {
        let lifted = lift_single(bytes).unwrap();
        assert!(lifted.ops.iter().any(|op| matches!(
            op.kind,
            OpKind::VConflict {
                elem: actual_elem,
                width: actual_width,
                ..
            } if actual_elem == elem && actual_width == width
        )));
    }
    let direct_masked = lift_single(&[0x62, 0xF2, 0x7D, 0xCC, 0xC4, 0xCA]).unwrap();
    assert_eq!(direct_masked.ops.len(), 1);
    assert!(matches!(
        direct_masked.ops[0].kind,
        OpKind::VConflict {
            dst: VReg::Arch(ArchReg::X86(X86Reg::Zmm(1))),
            src: VReg::Arch(ArchReg::X86(X86Reg::Zmm(2))),
            mask: Some(VReg::Arch(ArchReg::X86(X86Reg::K(4)))),
            elem: VecElementType::I32,
            width: VecWidth::V512,
            zeroing: true,
        }
    ));
    let memory = lift_single(&[0x62, 0xF2, 0x7D, 0x89, 0xC4, 0x00]).unwrap();
    assert_eq!(
        memory
            .ops
            .iter()
            .filter(|op| matches!(
                op.kind,
                OpKind::PredLoad {
                    width: MemWidth::B4,
                    ..
                }
            ))
            .count(),
        4
    );
    for bytes in [
        &[0xC4, 0xE2, 0x7D, 0xC4, 0xC1][..],
        &[0x62, 0xA2, 0x75, 0x8A, 0xC4, 0xCA][..],
        &[0x62, 0xA2, 0x7D, 0x80, 0xC4, 0xCA][..],
        &[0x62, 0xA2, 0x7D, 0x9A, 0xC4, 0xCA][..],
    ] {
        assert!(matches!(
            lift_single(bytes),
            Err(LiftError::InvalidEncoding { .. } | LiftError::Unsupported { .. })
        ));
    }
}
#[test]
fn lift_vpmadd52_covers_vex_evex_high_low_masks_broadcasts_and_invalids() {
    for (bytes, width, high) in [
        (&[0xC4, 0xE2, 0xE9, 0xB4, 0xCB][..], VecWidth::V128, false),
        (&[0xC4, 0xE2, 0xD5, 0xB5, 0xE6][..], VecWidth::V256, true),
        (
            &[0x62, 0xA2, 0xED, 0xC2, 0xB4, 0xCB][..],
            VecWidth::V512,
            false,
        ),
    ] {
        let lifted = lift_single(bytes).unwrap();
        assert!(lifted.ops.iter().any(|op| matches!(
            op.kind,
            OpKind::VMultiplyAdd52 {
                width: actual_width,
                high: actual_high,
                ..
            } if actual_width == width && actual_high == high
        )));
    }
    let direct_masked = lift_single(&[0x62, 0xF2, 0xED, 0xCC, 0xB4, 0xCB]).unwrap();
    assert_eq!(
        direct_masked.ops.len(),
        1,
        "register-only masked IFMA must not expand through virtual mask operations"
    );
    assert!(matches!(
        direct_masked.ops[0].kind,
        OpKind::VMultiplyAdd52 {
            dst: VReg::Arch(ArchReg::X86(X86Reg::Zmm(1))),
            acc: VReg::Arch(ArchReg::X86(X86Reg::Zmm(1))),
            src1: VReg::Arch(ArchReg::X86(X86Reg::Zmm(2))),
            src2: VReg::Arch(ArchReg::X86(X86Reg::Zmm(3))),
            mask: Some(VReg::Arch(ArchReg::X86(X86Reg::K(4)))),
            width: VecWidth::V512,
            high: false,
            zeroing: true,
        }
    ));
    let broadcast = lift_single(&[0x62, 0xE2, 0xD5, 0x33, 0xB5, 0x20]).unwrap();
    assert_eq!(
        broadcast
            .ops
            .iter()
            .filter(|op| matches!(
                op.kind,
                OpKind::PredLoad {
                    width: MemWidth::B8,
                    ..
                }
            ))
            .count(),
        1,
        "masked m64bcst must perform exactly one conditional 8-byte access"
    );
    assert!(broadcast.ops.iter().any(|op| matches!(
        op.kind,
        OpKind::VBroadcast {
            elem: VecElementType::I64,
            lanes: 4,
            ..
        }
    )));
    for bytes in [
        &[0xC4, 0xE2, 0x69, 0xB4, 0xCB][..],
        &[0x62, 0xA2, 0xE4, 0xC2, 0xB4, 0xCB][..],
        &[0x62, 0xA2, 0xED, 0xC0, 0xB4, 0xCB][..],
        &[0x62, 0xA2, 0xED, 0xD2, 0xB4, 0xCB][..],
    ] {
        assert!(matches!(
            lift_single(bytes),
            Err(LiftError::InvalidEncoding { .. } | LiftError::Unsupported { .. })
        ));
    }
}
#[test]
fn lift_vnni_dot_covers_vex_evex_variants_masks_broadcasts_and_invalids() {
    for (bytes, src_elem, unsigned, saturate, width) in [
        (
            &[0xC4, 0xE2, 0x69, 0x50, 0xCB][..],
            VecElementType::I8,
            true,
            false,
            VecWidth::V128,
        ),
        (
            &[0xC4, 0xE2, 0x55, 0x51, 0xE6][..],
            VecElementType::I8,
            true,
            true,
            VecWidth::V256,
        ),
        (
            &[0x62, 0xA2, 0x6D, 0xC2, 0x52, 0xCB][..],
            VecElementType::I16,
            false,
            false,
            VecWidth::V512,
        ),
        (
            &[0x62, 0xE2, 0x55, 0x33, 0x53, 0x20][..],
            VecElementType::I16,
            false,
            true,
            VecWidth::V256,
        ),
    ] {
        let lifted = lift_single(bytes).unwrap();
        assert!(lifted.ops.iter().any(|op| matches!(
            op.kind,
            OpKind::VDotProduct {
                src_elem: actual_elem,
                src1_unsigned: actual_unsigned,
                saturate: actual_saturate,
                width: actual_width,
                acc_elem: VecElementType::I32,
                ..
            } if actual_elem == src_elem
                && actual_unsigned == unsigned
                && actual_saturate == saturate
                && actual_width == width
        )));
    }

    let direct_masked = lift_single(&[0x62, 0xF2, 0x6D, 0xCC, 0x50, 0xCB]).unwrap();
    assert_eq!(
        direct_masked.ops.len(),
        1,
        "register-only masked VNNI must not expand through virtual mask operations"
    );
    assert!(matches!(
        direct_masked.ops[0].kind,
        OpKind::VDotProduct {
            dst: VReg::Arch(ArchReg::X86(X86Reg::Zmm(1))),
            acc: VReg::Arch(ArchReg::X86(X86Reg::Zmm(1))),
            src1: VReg::Arch(ArchReg::X86(X86Reg::Zmm(2))),
            src2: VReg::Arch(ArchReg::X86(X86Reg::Zmm(3))),
            mask: Some(VReg::Arch(ArchReg::X86(X86Reg::K(4)))),
            src_elem: VecElementType::I8,
            acc_elem: VecElementType::I32,
            width: VecWidth::V512,
            src1_unsigned: true,
            saturate: false,
            zeroing: true,
        }
    ));
    let broadcast = lift_single(&[0x62, 0xE2, 0x55, 0x33, 0x53, 0x20]).unwrap();
    assert_eq!(
        broadcast
            .ops
            .iter()
            .filter(|op| matches!(
                op.kind,
                OpKind::PredLoad {
                    width: MemWidth::B4,
                    ..
                }
            ))
            .count(),
        8
    );
    for bytes in [
        &[0xC4, 0xE2, 0xE9, 0x50, 0xCB][..],
        &[0x62, 0xA2, 0x6C, 0xC2, 0x52, 0xCB][..],
        &[0x62, 0xA2, 0x6D, 0xC0, 0x52, 0xCB][..],
        &[0x62, 0xA2, 0x6D, 0xD2, 0x52, 0xCB][..],
    ] {
        assert!(matches!(
            lift_single(bytes),
            Err(LiftError::InvalidEncoding { .. } | LiftError::Unsupported { .. })
        ));
    }
}
#[test]
fn lift_evex_vmovsh_covers_aliases_masks_load_store_fault_suppression_and_invalids() {
    let register = lift_single(&[0x62, 0xA5, 0x6E, 0x83, 0x10, 0xCB]).unwrap();
    assert_eq!(register.bytes_consumed, 6);
    assert!(register.ops.iter().any(|op| matches!(
        op.kind,
        OpKind::VExtractLane {
            vec: VReg::Arch(ArchReg::X86(X86Reg::Xmm(19))),
            lane: 0,
            elem: VecElementType::F16,
            ..
        }
    )));
    assert_eq!(
        register
            .ops
            .iter()
            .filter(|op| matches!(
                op.kind,
                OpKind::VExtractLane {
                    vec: VReg::Arch(ArchReg::X86(X86Reg::Xmm(18))),
                    lane: 1..=7,
                    elem: VecElementType::F16,
                    ..
                }
            ))
            .count(),
        7,
    );
    assert!(register.ops.iter().any(|op| matches!(
        op.kind,
        OpKind::VInsertLane {
            dst: VReg::Arch(ArchReg::X86(X86Reg::Xmm(17))),
            lane: 7,
            elem: VecElementType::F16,
            ..
        }
    )));

    let register_alias = lift_single(&[0x62, 0xF5, 0x6E, 0x0A, 0x11, 0xD9]).unwrap();
    assert!(register_alias.ops.iter().any(|op| matches!(
        op.kind,
        OpKind::VExtractLane {
            vec: VReg::Arch(ArchReg::X86(X86Reg::Xmm(3))),
            lane: 0,
            elem: VecElementType::F16,
            ..
        }
    )));
    assert!(register_alias.ops.iter().any(|op| matches!(
        op.kind,
        OpKind::VInsertLane {
            dst: VReg::Arch(ArchReg::X86(X86Reg::Xmm(1))),
            lane: 7,
            elem: VecElementType::F16,
            ..
        }
    )));

    let load = lift_single(&[0x62, 0xF5, 0x7E, 0x0A, 0x10, 0x48, 0x7F]).unwrap();
    assert!(load.ops.iter().any(|op| matches!(
        op.kind,
        OpKind::PredLoad {
            addr: Address::BaseOffset { offset: 254, .. },
            width: MemWidth::B2,
            ..
        }
    )));
    assert!(matches!(
        load.ops.last().unwrap().kind,
        OpKind::VBroadcast {
            dst: VReg::Arch(ArchReg::X86(X86Reg::Xmm(1))),
            elem: VecElementType::F16,
            lanes: 1,
            ..
        }
    ));

    let store = lift_single(&[0x62, 0xF5, 0x7E, 0x0A, 0x11, 0x50, 0x7F]).unwrap();
    assert!(store.ops.iter().any(|op| matches!(
        op.kind,
        OpKind::VExtractLane {
            vec: VReg::Arch(ArchReg::X86(X86Reg::Xmm(2))),
            lane: 0,
            elem: VecElementType::F16,
            ..
        }
    )));
    assert!(matches!(
        store.ops.last().unwrap().kind,
        OpKind::PredStore {
            addr: Address::BaseOffset { offset: 254, .. },
            width: MemWidth::B2,
            ..
        }
    ));

    // LLIG leaves L'L uninterpreted for every VMOVSH form.
    assert!(lift_single(&[0x62, 0xF5, 0x7E, 0x68, 0x10, 0xCB]).is_ok());

    for invalid in [
        &[0x62, 0xF5, 0xFE, 0x08, 0x10, 0xCB][..], // W=1
        &[0x62, 0xF5, 0x7E, 0x18, 0x10, 0xCB][..], // EVEX.b
        &[0x62, 0xF5, 0x7E, 0x88, 0x10, 0xCB][..], // {z} with k0
        &[0x62, 0xF5, 0x7D, 0x08, 0x10, 0xCB][..], // pp != F3
        &[0x62, 0xF5, 0x6E, 0x08, 0x10, 0x08][..], // memory load reserved vvvv
        &[0x62, 0xF5, 0x7E, 0x8A, 0x11, 0x10][..], // memory store cannot zero
        &[0x62, 0xF5, 0x6E, 0x0A, 0x11, 0x10][..], // memory store reserved vvvv
    ] {
        assert!(lift_single(invalid).is_err(), "accepted {invalid:02X?}");
    }
}
#[test]
fn lift_vpshufbitqmb_covers_widths_high_sources_masks_memory_and_invalids() {
    for (bytes, width, dst, src, indices) in [
        (
            &[0x62, 0xF2, 0x6D, 0x08, 0x8F, 0xCB][..],
            VecWidth::V128,
            X86Reg::K(1),
            X86Reg::Xmm(2),
            X86Reg::Xmm(3),
        ),
        (
            &[0x62, 0xF2, 0x55, 0x2B, 0x8F, 0xE6][..],
            VecWidth::V256,
            X86Reg::K(4),
            X86Reg::Ymm(5),
            X86Reg::Ymm(6),
        ),
        (
            &[0x62, 0xB2, 0x6D, 0x42, 0x8F, 0xFB][..],
            VecWidth::V512,
            X86Reg::K(7),
            X86Reg::Zmm(18),
            X86Reg::Zmm(19),
        ),
    ] {
        let lifted = lift_single(bytes).unwrap();
        assert!(lifted.ops.iter().any(|op| matches!(
            op.kind,
            OpKind::VShuffleBitQM {
                src: VReg::Arch(ArchReg::X86(actual_src)),
                indices: VReg::Arch(ArchReg::X86(actual_indices)),
                width: actual_width,
                ..
            } if actual_src == src && actual_indices == indices && actual_width == width
        )));
        assert!(
            lifted
                .ops
                .iter()
                .any(|op| op.kind.dests().contains(&VReg::Arch(ArchReg::X86(dst))))
        );
    }

    let memory = lift_single(&[0x62, 0xF2, 0x55, 0x43, 0x8F, 0x60, 0x01]).unwrap();
    assert_eq!(
        memory
            .ops
            .iter()
            .filter(|op| matches!(
                op.kind,
                OpKind::PredLoad {
                    width: MemWidth::B1,
                    ..
                }
            ))
            .count(),
        64
    );
    assert!(matches!(
        memory.ops.last().unwrap().kind,
        OpKind::VShuffleBitQM {
            dst: VReg::Arch(ArchReg::X86(X86Reg::K(4))),
            mask: Some(VReg::Arch(ArchReg::X86(X86Reg::K(3)))),
            width: VecWidth::V512,
            ..
        }
    ));

    for bytes in [
        &[0xC4, 0xE2, 0x6D, 0x8F, 0xCB][..],       // EVEX-only
        &[0x62, 0xF2, 0xED, 0x08, 0x8F, 0xCB][..], // W=1
        &[0x62, 0xF2, 0x6D, 0x68, 0x8F, 0xCB][..], // L'L=3
        &[0x62, 0xF2, 0x6D, 0x88, 0x8F, 0xCB][..], // EVEX.z is reserved
        &[0x62, 0xF2, 0x6D, 0x18, 0x8F, 0xCB][..], // EVEX.b is reserved
        &[0x62, 0x72, 0x6D, 0x08, 0x8F, 0xCB][..], // extended K destination
        &[0x62, 0xE2, 0x6D, 0x08, 0x8F, 0xCB][..], // EVEX.R' on K destination
    ] {
        assert!(matches!(
            lift_single(bytes),
            Err(LiftError::InvalidEncoding { .. } | LiftError::Unsupported { .. })
        ));
    }
}
#[test]
fn lift_evex_scatter_covers_integer_float_layouts_vsib_masks_and_invalids() {
    for (bytes, stores, width) in [
        (
            &[0x62, 0xF2, 0x7D, 0x09, 0xA0, 0x0C, 0x90][..],
            4,
            MemWidth::B4,
        ),
        (
            &[0x62, 0xC2, 0xFD, 0x07, 0xA0, 0x4C, 0xD5, 0x01][..],
            2,
            MemWidth::B8,
        ),
        (
            &[0x62, 0xF2, 0x7D, 0x2A, 0xA1, 0x24, 0x58][..],
            4,
            MemWidth::B4,
        ),
        (
            &[0x62, 0xC2, 0xFD, 0x43, 0xA1, 0x6C, 0xE1, 0x08][..],
            8,
            MemWidth::B8,
        ),
        (
            &[0x62, 0xF2, 0x7D, 0x29, 0xA2, 0x0C, 0x90][..],
            8,
            MemWidth::B4,
        ),
        (
            &[0x62, 0xF2, 0xFD, 0x29, 0xA2, 0x0C, 0xD0][..],
            4,
            MemWidth::B8,
        ),
        (
            &[0x62, 0xF2, 0x7D, 0x49, 0xA3, 0x0C, 0x90][..],
            8,
            MemWidth::B4,
        ),
        (
            &[0x62, 0xF2, 0xFD, 0x49, 0xA3, 0x0C, 0xD0][..],
            8,
            MemWidth::B8,
        ),
    ] {
        let lifted = lift_single(bytes).unwrap();
        assert_eq!(lifted.bytes_consumed, bytes.len());
        assert_eq!(
                lifted
                    .ops
                    .iter()
                    .filter(|op| matches!(op.kind, OpKind::PredStore { width: actual, .. } if actual == width))
                    .count(),
                stores
            );
        let last_store = lifted
            .ops
            .iter()
            .rposition(|op| matches!(op.kind, OpKind::PredStore { .. }))
            .unwrap();
        assert!(lifted.ops[last_store + 1..].iter().any(|op| matches!(
            op.kind,
            OpKind::And {
                dst: VReg::Arch(ArchReg::X86(X86Reg::K(_))),
                ..
            }
        )));
    }

    for bytes in [
        &[0xC4, 0xE2, 0x7D, 0xA0, 0x0C, 0x90][..], // EVEX-only
        &[0x62, 0xF2, 0x7C, 0x09, 0xA0, 0x0C, 0x90][..], // mandatory 66 absent
        &[0x62, 0xF2, 0x7D, 0x08, 0xA0, 0x0C, 0x90][..], // k0 reserved
        &[0x62, 0xF2, 0x7D, 0x89, 0xA0, 0x0C, 0x90][..], // {z} reserved
        &[0x62, 0xF2, 0x75, 0x09, 0xA0, 0x0C, 0x90][..], // EVEX.vvvv reserved
        &[0x62, 0xF2, 0x7D, 0x19, 0xA0, 0x0C, 0x90][..], // EVEX.b reserved
        &[0x62, 0xF2, 0x7D, 0x09, 0xA0, 0xC1][..], // register destination
        &[0x62, 0xF2, 0x7D, 0x09, 0xA0, 0x08][..], // non-VSIB memory
    ] {
        assert!(
            matches!(
                lift_single(bytes),
                Err(LiftError::InvalidEncoding { .. } | LiftError::Unsupported { .. })
            ),
            "accepted reserved scatter encoding {bytes:02X?}"
        );
    }
}
#[test]
fn lift_evex_integer_test_masks_cover_elements_polarities_e4_memory_and_invalids() {
    for bytes in [
        &[0x62, 0xF2, 0x65, 0x08, 0x26, 0xD4][..],
        &[0x62, 0xB2, 0xDD, 0x21, 0x26, 0xDD][..],
        &[0x62, 0xF2, 0x75, 0x52, 0x27, 0x60, 0x7F][..],
        &[0x62, 0x92, 0x8D, 0x40, 0x27, 0xEF][..],
        &[0x62, 0xF2, 0x66, 0x08, 0x26, 0xD4][..],
        &[0x62, 0xB2, 0xDE, 0x21, 0x26, 0xDD][..],
        &[0x62, 0xF2, 0x76, 0x52, 0x27, 0x60, 0x7F][..],
        &[0x62, 0x92, 0x8E, 0x40, 0x27, 0xEF][..],
    ] {
        let lifted = lift_single(bytes).unwrap();
        assert_eq!(lifted.bytes_consumed, bytes.len());
        assert!(matches!(
            lifted.ops.last().unwrap().kind,
            OpKind::Mov {
                dst: VReg::Arch(ArchReg::X86(X86Reg::K(_))),
                ..
            } | OpKind::And {
                dst: VReg::Arch(ArchReg::X86(X86Reg::K(_))),
                ..
            }
        ));
    }
    let memory = lift_single(&[0x62, 0xF2, 0x75, 0x52, 0x27, 0x60, 0x7F]).unwrap();
    assert_eq!(
        memory
            .ops
            .iter()
            .filter(|op| matches!(
                op.kind,
                OpKind::PredLoad {
                    width: MemWidth::B4,
                    ..
                }
            ))
            .count(),
        1,
        "one broadcast memory operand must issue at most one scalar read"
    );

    for bytes in [
        &[0xC4, 0xE2, 0x65, 0x26, 0xD4][..],       // EVEX-only
        &[0x62, 0xF2, 0x64, 0x08, 0x26, 0xD4][..], // mandatory prefix absent
        &[0x62, 0xF2, 0x65, 0x68, 0x26, 0xD4][..], // L'L=3
        &[0x62, 0xF2, 0x65, 0x88, 0x26, 0xD4][..], // EVEX.z reserved
        &[0x62, 0xF2, 0x65, 0x18, 0x26, 0xD4][..], // byte broadcast reserved
        &[0x62, 0xE2, 0x65, 0x08, 0x26, 0xD4][..], // extended K destination
    ] {
        assert!(
            matches!(
                lift_single(bytes),
                Err(LiftError::InvalidEncoding { .. } | LiftError::Unsupported { .. })
            ),
            "accepted reserved integer-test-mask encoding {bytes:02X?}"
        );
    }
}
#[test]
fn lift_pmullw_covers_legacy_vex_evex_masks_alignment_and_invalids() {
    for (bytes, lanes, dst, src1, src2) in [
        (
            &[0x66, 0x0F, 0xD5, 0xD1][..],
            8u8,
            X86Reg::Xmm(2),
            X86Reg::Xmm(2),
            X86Reg::Xmm(1),
        ),
        (
            &[0xC5, 0xF1, 0xD5, 0xC2][..],
            8,
            X86Reg::Xmm(0),
            X86Reg::Xmm(1),
            X86Reg::Xmm(2),
        ),
        (
            &[0xC4, 0x41, 0x35, 0xD5, 0xC2][..],
            16,
            X86Reg::Ymm(8),
            X86Reg::Ymm(9),
            X86Reg::Ymm(10),
        ),
        (
            &[0x62, 0xA1, 0x75, 0x01, 0xD5, 0xC2][..],
            8,
            X86Reg::Xmm(16),
            X86Reg::Xmm(17),
            X86Reg::Xmm(18),
        ),
        (
            &[0x62, 0xA1, 0x75, 0xA2, 0xD5, 0xC2][..],
            16,
            X86Reg::Ymm(16),
            X86Reg::Ymm(17),
            X86Reg::Ymm(18),
        ),
        (
            &[0x62, 0xA1, 0x75, 0x40, 0xD5, 0xC2][..],
            32,
            X86Reg::Zmm(16),
            X86Reg::Zmm(17),
            X86Reg::Zmm(18),
        ),
    ] {
        let result = lift_single(bytes).unwrap();
        assert_eq!(result.bytes_consumed, bytes.len());
        assert!(result.ops.iter().any(|op| matches!(
            op.kind,
            OpKind::VMul {
                src1: VReg::Arch(ArchReg::X86(actual_src1)),
                src2: VReg::Arch(ArchReg::X86(actual_src2)),
                elem: VecElementType::I16,
                lanes: actual_lanes,
                ..
            } if actual_src1 == src1 && actual_src2 == src2 && actual_lanes == lanes
        )));
        assert!(
            result.ops.iter().any(|op| matches!(
                op.kind,
                OpKind::VMul {
                    dst: VReg::Arch(ArchReg::X86(actual_dst)),
                    ..
                } if actual_dst == dst
            )) || result.ops.iter().any(|op| matches!(
                op.kind,
                OpKind::VMov {
                    dst: VReg::Arch(ArchReg::X86(actual_dst)),
                    ..
                } if actual_dst == dst
            )) || result.ops.iter().any(|op| matches!(
                op.kind,
                OpKind::VInsertLane {
                    dst: VReg::Arch(ArchReg::X86(actual_dst)),
                    ..
                } if actual_dst == dst
            ))
        );
    }

    let legacy_memory = lift_single(&[0x66, 0x0F, 0xD5, 0x00]).unwrap();
    assert!(
        legacy_memory
            .ops
            .iter()
            .any(|op| matches!(op.kind, OpKind::X86CheckAlignment { alignment: 16, .. }))
    );
    let masked_memory = lift_single(&[0x62, 0xF1, 0x75, 0xC9, 0xD5, 0x40, 0x01]).unwrap();
    assert_eq!(
        masked_memory
            .ops
            .iter()
            .filter(|op| matches!(
                op.kind,
                OpKind::PredLoad {
                    width: MemWidth::B2,
                    ..
                }
            ))
            .count(),
        32,
    );
    assert!(masked_memory.ops.iter().any(|op| matches!(
        op.kind,
        OpKind::Lea {
            addr: Address::BaseOffset { offset: 64, .. },
            ..
        }
    )));
    assert!(lift_single(&[0xC4, 0xE1, 0xF1, 0xD5, 0xC2]).is_ok());

    let mmx = lift_single(&[0x0F, 0xD5, 0xC1]).unwrap();
    assert!(matches!(
        mmx.ops.as_slice(),
        [
            SmirOp {
                kind: OpKind::VMul {
                    dst: VReg::Arch(ArchReg::X86(X86Reg::Mm(0))),
                    src1: VReg::Arch(ArchReg::X86(X86Reg::Mm(0))),
                    src2: VReg::Arch(ArchReg::X86(X86Reg::Mm(1))),
                    elem: VecElementType::I16,
                    lanes: 4,
                },
                x86_hint: Some(X86OpHint::SseOp {
                    prefix: X86SsePrefix::None,
                    opcode: 0xD5,
                }),
                ..
            },
            SmirOp {
                kind: OpKind::X86X87Control {
                    kind: X86X87ControlKind::EnterMmx,
                    ..
                },
                ..
            }
        ]
    ));
    let mmx_memory = lift_single(&[0x0F, 0xD5, 0x40, 0x01]).unwrap();
    assert!(mmx_memory.ops.iter().any(|op| matches!(
        (&op.kind, op.x86_hint),
        (
            OpKind::VLoad {
                width: VecWidth::V64,
                ..
            },
            Some(X86OpHint::VecAlign(X86VecAlign::Unaligned))
        )
    )));
    assert!(
        !mmx_memory
            .ops
            .iter()
            .any(|op| matches!(op.kind, OpKind::X86CheckAlignment { .. }))
    );
    for bytes in [
        &[0xF3, 0x66, 0x0F, 0xD5, 0xC1][..],
        &[0xC5, 0xF0, 0xD5, 0xC2][..],
        &[0x62, 0xA1, 0x75, 0xC0, 0xD5, 0xC2][..],
        &[0x62, 0xA1, 0x75, 0x50, 0xD5, 0xC2][..],
        &[0x62, 0xF1, 0x75, 0x59, 0xD5, 0x00][..],
        &[0x62, 0xA1, 0x74, 0x40, 0xD5, 0xC2][..],
    ] {
        assert!(
            matches!(
                lift_single(bytes),
                Err(LiftError::InvalidEncoding { .. } | LiftError::Unsupported { .. })
            ),
            "invalid PMULLW accepted: {bytes:02X?}",
        );
    }
}
#[test]
fn lift_vdbpsadbw_decomposes_shuffle_sad_masks_and_full_tuple_memory() {
    let high = lift_single(&[0x62, 0xA3, 0x6D, 0xC3, 0x42, 0xCB, 0xE4]).unwrap();
    assert_eq!(high.bytes_consumed, 7);
    assert_eq!(
        high.ops
            .iter()
            .filter_map(|op| match op.kind {
                OpKind::VMpsadbw {
                    dst: VReg::Virtual(_),
                    src1: VReg::Virtual(_),
                    src2: VReg::Arch(ArchReg::X86(X86Reg::Zmm(18))),
                    mask: None,
                    width: VecWidth::V512,
                    imm,
                    zeroing: false,
                } => Some(imm),
                _ => None,
            })
            .collect::<Vec<_>>(),
        vec![0, 9, 54, 63],
    );
    assert!(high.ops.iter().any(|op| matches!(
        op.kind,
        OpKind::VExtractLane {
            vec: VReg::Arch(ArchReg::X86(X86Reg::Zmm(19))),
            lane: 15,
            elem: VecElementType::I32,
            ..
        }
    )));
    assert!(high.ops.iter().any(|op| matches!(
        op.kind,
        OpKind::VInsertLane {
            dst: VReg::Arch(ArchReg::X86(X86Reg::Zmm(17))),
            elem: VecElementType::I16,
            ..
        }
    )));

    let ymm = lift_single(&[0x62, 0x53, 0x35, 0x28, 0x42, 0xC2, 0x63]).unwrap();
    assert_eq!(ymm.bytes_consumed, 7);
    assert_eq!(
        ymm.ops
            .iter()
            .filter(|op| matches!(
                op.kind,
                OpKind::VMpsadbw {
                    width: VecWidth::V256,
                    ..
                }
            ))
            .count(),
        4,
    );
    assert!(matches!(
        ymm.ops.last().map(|op| &op.kind),
        Some(OpKind::VMov {
            dst: VReg::Arch(ArchReg::X86(X86Reg::Ymm(8))),
            width: VecWidth::V256,
            ..
        })
    ));

    // E4NF uses a complete, non-fault-suppressible source read. FULLMEM
    // disp8 scales by the selected vector length.
    let memory = lift_single(&[0x62, 0xF3, 0x6D, 0x4A, 0x42, 0x48, 0x02, 0xA5]).unwrap();
    let load = memory
        .ops
        .iter()
        .position(|op| {
            matches!(
                op.kind,
                OpKind::VLoad {
                    addr: Address::BaseOffset { offset: 128, .. },
                    width: VecWidth::V512,
                    ..
                }
            )
        })
        .unwrap();
    let first_sad = memory
        .ops
        .iter()
        .position(|op| matches!(op.kind, OpKind::VMpsadbw { .. }))
        .unwrap();
    assert!(load < first_sad);
    assert!(
        !memory
            .ops
            .iter()
            .any(|op| matches!(op.kind, OpKind::PredLoad { .. }))
    );

    for bytes in [
        &[0x62, 0xF3, 0xED, 0x48, 0x42, 0xC8, 0][..], // W=1
        &[0x62, 0xF3, 0x6D, 0x68, 0x42, 0xC8, 0][..], // L'L=3
        &[0x62, 0xF3, 0x6D, 0x18, 0x42, 0xC8, 0][..], // EVEX.b register
        &[0x62, 0xF3, 0x6D, 0x58, 0x42, 0x08, 0][..], // EVEX.b memory
        &[0x62, 0xF3, 0x6D, 0x88, 0x42, 0xC8, 0][..], // zeroing with k0
        &[0x62, 0xF3, 0x6C, 0x48, 0x42, 0xC8, 0][..], // pp != 66/F3
        &[0x62, 0xF3, 0x6D, 0x48, 0x42, 0xC8][..],    // missing imm8
    ] {
        assert!(
            matches!(
                lift_single(bytes),
                Err(LiftError::InvalidEncoding { .. }
                    | LiftError::Unsupported { .. }
                    | LiftError::Incomplete { .. })
            ),
            "invalid VDBPSADBW encoding accepted: {bytes:02X?}",
        );
    }
}
#[test]
fn lift_evex_packed_immediate_shuffle_covers_masks_broadcast_and_reserved_bits() {
    for (bytes, width, elem, lanes) in [
        (
            &[0x62, 0xA1, 0x7D, 0x0B, 0x70, 0xCA, 0x1B][..],
            VecWidth::V128,
            VecElementType::I32,
            4usize,
        ),
        (
            &[0x62, 0xA1, 0x7E, 0x0B, 0x70, 0xCA, 0x1B][..],
            VecWidth::V128,
            VecElementType::I16,
            8,
        ),
        (
            &[0x62, 0xA1, 0x7F, 0x0B, 0x70, 0xCA, 0x1B][..],
            VecWidth::V128,
            VecElementType::I16,
            8,
        ),
        (
            &[0x62, 0xA1, 0x7D, 0x2B, 0x70, 0xCA, 0x1B][..],
            VecWidth::V256,
            VecElementType::I32,
            8,
        ),
        (
            &[0x62, 0xA1, 0x7E, 0xAB, 0x70, 0xCA, 0x1B][..],
            VecWidth::V256,
            VecElementType::I16,
            16,
        ),
        (
            &[0x62, 0xA1, 0x7F, 0xAB, 0x70, 0xCA, 0x1B][..],
            VecWidth::V256,
            VecElementType::I16,
            16,
        ),
        (
            &[0x62, 0xA1, 0x7D, 0x4B, 0x70, 0xCA, 0x1B][..],
            VecWidth::V512,
            VecElementType::I32,
            16,
        ),
        (
            &[0x62, 0xA1, 0x7E, 0x4B, 0x70, 0xCA, 0x1B][..],
            VecWidth::V512,
            VecElementType::I16,
            32,
        ),
        (
            &[0x62, 0xA1, 0x7F, 0x4B, 0x70, 0xCA, 0x1B][..],
            VecWidth::V512,
            VecElementType::I16,
            32,
        ),
    ] {
        let result = lift_single(bytes).unwrap();
        assert_eq!(result.bytes_consumed, bytes.len());
        assert!(result.ops.iter().any(|op| matches!(op.kind, OpKind::VShuffle {
                src1: VReg::Arch(ArchReg::X86(src)), elem: actual_elem, lanes: actual_lanes, ..
            } if src == match width { VecWidth::V128 => X86Reg::Xmm(18), VecWidth::V256 => X86Reg::Ymm(18), VecWidth::V512 => X86Reg::Zmm(18), _ => unreachable!() }
                && actual_elem == elem && usize::from(actual_lanes) == lanes)));
        assert_eq!(
            result
                .ops
                .iter()
                .filter(|op| matches!(op.kind, OpKind::Select { .. }))
                .count(),
            lanes
        );
    }

    let full = lift_single(&[0x62, 0xE1, 0x7E, 0x4B, 0x70, 0x48, 0x7F, 0x1B]).unwrap();
    assert!(full.ops.iter().any(|op| matches!(
        op.kind,
        OpKind::VLoad {
            addr: Address::BaseOffset { offset: 8128, .. },
            width: VecWidth::V512,
            ..
        }
    )));
    let broadcast = lift_single(&[0x62, 0xE1, 0x7D, 0x5B, 0x70, 0x48, 0x7F, 0x1B]).unwrap();
    assert!(broadcast.ops.iter().any(|op| matches!(
        op.kind,
        OpKind::Load {
            addr: Address::BaseOffset { offset: 508, .. },
            width: MemWidth::B4,
            ..
        }
    )));
    assert!(broadcast.ops.iter().any(|op| matches!(
        op.kind,
        OpKind::VBroadcast {
            elem: VecElementType::I32,
            lanes: 16,
            ..
        }
    )));

    for bytes in [
        &[0x62, 0xA1, 0xFD, 0x0B, 0x70, 0xCA, 0x1B][..],
        &[0x62, 0xA1, 0x75, 0x0B, 0x70, 0xCA, 0x1B][..],
        &[0x62, 0xA1, 0x7D, 0x03, 0x70, 0xCA, 0x1B][..],
        &[0x62, 0xA1, 0x7D, 0x6B, 0x70, 0xCA, 0x1B][..],
        &[0x62, 0xA1, 0x7D, 0x80, 0x70, 0xCA, 0x1B][..],
        &[0x62, 0xA1, 0x7D, 0x1B, 0x70, 0xCA, 0x1B][..],
        &[0x62, 0xE1, 0x7E, 0x5B, 0x70, 0x08, 0x1B][..],
        &[0x62, 0xA1, 0x7D, 0x0B, 0x70, 0xCA][..],
    ] {
        assert!(
            matches!(
                lift_single(bytes),
                Err(LiftError::InvalidEncoding { .. }
                    | LiftError::Incomplete { .. }
                    | LiftError::Unsupported { .. })
            ),
            "invalid EVEX packed shuffle accepted: {bytes:02X?}"
        );
    }
}
#[test]
fn lift_evex_aligned_moves_masks_every_element_and_checks_alignment_first() {
    for (bytes, elem, lanes, dst) in [
        (
            &[0x62, 0xF1, 0x7C, 0x49, 0x28, 0xD1][..],
            VecElementType::F32,
            16,
            X86Reg::Zmm(2),
        ),
        (
            &[0x62, 0xF1, 0xFD, 0xCA, 0x28, 0xE3][..],
            VecElementType::F64,
            8,
            X86Reg::Zmm(4),
        ),
        (
            &[0x62, 0xA1, 0x7D, 0x49, 0x6F, 0xC8][..],
            VecElementType::I32,
            16,
            X86Reg::Zmm(17),
        ),
        (
            &[0x62, 0xF1, 0xFD, 0xCA, 0x6F, 0xE3][..],
            VecElementType::I64,
            8,
            X86Reg::Zmm(4),
        ),
    ] {
        let lifted = lift_single(bytes).unwrap();
        assert_eq!(
            lifted
                .ops
                .iter()
                .filter(|op| matches!(
                    op.kind,
                    OpKind::VInsertLane {
                        dst: VReg::Arch(ArchReg::X86(actual_dst)),
                        elem: actual_elem,
                        ..
                    } if actual_dst == dst && actual_elem == elem
                ))
                .count(),
            lanes,
            "masked aligned register move: {bytes:02X?}"
        );
    }

    for (bytes, elem, mem_width, alignment, lanes) in [
        (
            &[0x62, 0xF1, 0x7C, 0x09, 0x28, 0x10][..],
            VecElementType::F32,
            MemWidth::B4,
            16,
            4,
        ),
        (
            &[0x62, 0xF1, 0xFD, 0x2A, 0x28, 0x10][..],
            VecElementType::F64,
            MemWidth::B8,
            32,
            4,
        ),
        (
            &[0x62, 0xF1, 0x7D, 0x4B, 0x6F, 0x28][..],
            VecElementType::I32,
            MemWidth::B4,
            64,
            16,
        ),
        (
            &[0x62, 0xF1, 0xFD, 0x4C, 0x6F, 0x28][..],
            VecElementType::I64,
            MemWidth::B8,
            64,
            8,
        ),
    ] {
        let lifted = lift_single(bytes).unwrap();
        let check = lifted
            .ops
            .iter()
            .position(|op| {
                matches!(
                    op.kind,
                    OpKind::X86CheckAlignment { alignment: actual, .. }
                        if actual == alignment
                )
            })
            .unwrap();
        let first_load = lifted
            .ops
            .iter()
            .position(|op| {
                matches!(
                    op.kind,
                    OpKind::PredLoad {
                        width: actual,
                        ..
                    } if actual == mem_width
                )
            })
            .unwrap();
        assert!(check < first_load, "Type E1 ordering: {bytes:02X?}");
        assert_eq!(
            lifted
                .ops
                .iter()
                .filter(|op| matches!(
                    op.kind,
                    OpKind::PredLoad {
                        width: actual,
                        ..
                    } if actual == mem_width
                ))
                .count(),
            lanes
        );
        assert_eq!(
            lifted
                .ops
                .iter()
                .filter(|op| matches!(
                    op.kind,
                    OpKind::VInsertLane {
                        elem: actual,
                        ..
                    } if actual == elem
                ))
                .count(),
            lanes * 2
        );
    }

    for (bytes, mem_width, alignment, lanes) in [
        (
            &[0x62, 0xF1, 0x7C, 0x09, 0x29, 0x08][..],
            MemWidth::B4,
            16,
            4,
        ),
        (
            &[0x62, 0xF1, 0xFD, 0x2A, 0x29, 0x08][..],
            MemWidth::B8,
            32,
            4,
        ),
        (
            &[0x62, 0xF1, 0x7D, 0x4B, 0x7F, 0x08][..],
            MemWidth::B4,
            64,
            16,
        ),
        (
            &[0x62, 0xF1, 0xFD, 0x4C, 0x7F, 0x08][..],
            MemWidth::B8,
            64,
            8,
        ),
    ] {
        let lifted = lift_single(bytes).unwrap();
        let check = lifted
            .ops
            .iter()
            .position(|op| {
                matches!(
                    op.kind,
                    OpKind::X86CheckAlignment { alignment: actual, .. }
                        if actual == alignment
                )
            })
            .unwrap();
        let first_store = lifted
            .ops
            .iter()
            .position(|op| {
                matches!(
                    op.kind,
                    OpKind::PredStore {
                        width: actual,
                        ..
                    } if actual == mem_width
                )
            })
            .unwrap();
        assert!(check < first_store, "Type E1 ordering: {bytes:02X?}");
        assert_eq!(
            lifted
                .ops
                .iter()
                .filter(|op| matches!(
                    op.kind,
                    OpKind::PredStore {
                        width: actual,
                        ..
                    } if actual == mem_width
                ))
                .count(),
            lanes
        );
    }

    for bytes in [
        &[0x62, 0xF1, 0x7C, 0x49, 0x28, 0x50, 0x01][..],
        &[0x62, 0xF1, 0xFD, 0x4B, 0x7F, 0x58, 0x01][..],
    ] {
        let lifted = lift_single(bytes).unwrap();
        assert!(lifted.ops.iter().any(|op| matches!(
            op.kind,
            OpKind::Lea {
                addr: Address::BaseOffset {
                    offset: 64,
                    disp_size: DispSize::Disp8,
                    ..
                },
                ..
            }
        )));
    }

    let high_store = lift_single(&[0x62, 0xC1, 0xFD, 0x4C, 0x29, 0x29]).unwrap();
    assert!(high_store.ops.iter().any(|op| matches!(
        op.kind,
        OpKind::VExtractLane {
            vec: VReg::Arch(ArchReg::X86(X86Reg::Zmm(21))),
            elem: VecElementType::F64,
            ..
        }
    )));

    for bytes in [
        &[0x62, 0xF1, 0x7C, 0xC8, 0x28, 0xC1][..], // {z} with k0
        &[0x62, 0xF1, 0x7C, 0xC9, 0x29, 0x08][..], // {z} memory store
        &[0x62, 0xF1, 0xFC, 0x49, 0x28, 0xC1][..], // VMOVAPS with W=1
        &[0x62, 0xF1, 0x7D, 0x49, 0x28, 0xC1][..], // VMOVAPD with W=0
        &[0x62, 0xF1, 0x7C, 0x69, 0x28, 0xC1][..], // reserved L'L=3
        &[0x62, 0xF1, 0x7C, 0x59, 0x28, 0xC1][..], // reserved EVEX.b
        &[0x62, 0xF1, 0x74, 0x49, 0x28, 0xC1][..], // reserved vvvv
        &[0x62, 0xF1, 0x7C, 0x41, 0x28, 0xC1][..], // reserved V'
    ] {
        assert!(
            matches!(
                lift_single(bytes),
                Err(LiftError::InvalidEncoding { .. } | LiftError::Unsupported { .. })
            ),
            "invalid masked aligned move accepted: {bytes:02X?}"
        );
    }
}
#[test]
fn lift_evex_get_exponent_covers_all_formats_shapes_masks_sae_and_memory() {
    for (bytes, elem, width, lanes, scalar) in [
        (
            &[0x62, 0xF2, 0x7D, 0x08, 0x42, 0xCB][..],
            VecElementType::F32,
            VecWidth::V128,
            4,
            false,
        ),
        (
            &[0x62, 0xF2, 0xFD, 0x28, 0x42, 0xCB][..],
            VecElementType::F64,
            VecWidth::V256,
            4,
            false,
        ),
        (
            &[0x62, 0xF6, 0x7D, 0x48, 0x42, 0xCB][..],
            VecElementType::F16,
            VecWidth::V512,
            32,
            false,
        ),
        (
            &[0x62, 0xF2, 0x6D, 0x08, 0x43, 0xCB][..],
            VecElementType::F32,
            VecWidth::V128,
            1,
            true,
        ),
        (
            &[0x62, 0xF2, 0xED, 0x68, 0x43, 0xCB][..],
            VecElementType::F64,
            VecWidth::V128,
            1,
            true,
        ),
        (
            &[0x62, 0xF6, 0x6D, 0x08, 0x43, 0xCB][..],
            VecElementType::F16,
            VecWidth::V128,
            1,
            true,
        ),
    ] {
        let lifted = lift_single(bytes).unwrap();
        assert_eq!(lifted.bytes_consumed, bytes.len());
        assert!(matches!(
            lifted.ops.last().map(|op| &op.kind),
            Some(OpKind::X86GetExponent {
                elem: actual_elem,
                width: actual_width,
                lanes: actual_lanes,
                scalar: actual_scalar,
                suppress_exceptions: false,
                ..
            }) if *actual_elem == elem
                && *actual_width == width
                && *actual_lanes == lanes
                && *actual_scalar == scalar
        ));
    }

    let packed_sae = lift_single(&[0x62, 0xA2, 0x7D, 0x9A, 0x42, 0xCB]).unwrap();
    assert!(matches!(
        packed_sae.ops.as_slice(),
        [SmirOp {
            kind: OpKind::X86GetExponent {
                dst: VReg::Arch(ArchReg::X86(X86Reg::Zmm(17))),
                merge: None,
                src: VReg::Arch(ArchReg::X86(X86Reg::Zmm(19))),
                mask: Some(VReg::Arch(ArchReg::X86(X86Reg::K(2)))),
                elem: VecElementType::F32,
                width: VecWidth::V512,
                lanes: 16,
                scalar: false,
                mask_zeroing: true,
                suppress_exceptions: true,
            },
            x86_hint: Some(X86OpHint::EvexOp {
                map: X86VecMap::Map0F38,
                pp: X86SsePrefix::OpSize,
                opcode: 0x42,
                width: VecWidth::V512,
                w: false,
            }),
            ..
        }]
    ));

    let scalar_sae = lift_single(&[0x62, 0xA6, 0x6D, 0x12, 0x43, 0xCB]).unwrap();
    assert!(matches!(
        scalar_sae.ops.as_slice(),
        [SmirOp {
            kind: OpKind::X86GetExponent {
                dst: VReg::Arch(ArchReg::X86(X86Reg::Xmm(17))),
                merge: Some(VReg::Arch(ArchReg::X86(X86Reg::Xmm(18)))),
                src: VReg::Arch(ArchReg::X86(X86Reg::Xmm(19))),
                mask: Some(VReg::Arch(ArchReg::X86(X86Reg::K(2)))),
                elem: VecElementType::F16,
                scalar: true,
                suppress_exceptions: true,
                ..
            },
            ..
        }]
    ));

    let full_memory = lift_single(&[0x62, 0xF2, 0x7D, 0x4A, 0x42, 0x48, 0x01]).unwrap();
    assert_eq!(
        full_memory
            .ops
            .iter()
            .filter(|op| matches!(
                op.kind,
                OpKind::PredLoad {
                    width: MemWidth::B4,
                    ..
                }
            ))
            .count(),
        16
    );
    let broadcast = lift_single(&[0x62, 0xF6, 0x7D, 0x1A, 0x42, 0x48, 0x01]).unwrap();
    assert!(broadcast.ops.iter().any(|op| matches!(
        op.kind,
        OpKind::PredLoad {
            addr: Address::BaseOffset { offset: 2, .. },
            width: MemWidth::B2,
            ..
        }
    )));
    assert_eq!(
        broadcast
            .ops
            .iter()
            .filter(|op| matches!(op.kind, OpKind::PredLoad { .. }))
            .count(),
        1
    );
    let scalar_memory = lift_single(&[0x62, 0xF2, 0x6D, 0x8A, 0x43, 0x48, 0x01]).unwrap();
    assert!(scalar_memory.ops.iter().any(|op| matches!(
        op.kind,
        OpKind::PredLoad {
            addr: Address::BaseOffset { offset: 4, .. },
            width: MemWidth::B4,
            ..
        }
    )));
    assert!(matches!(
        scalar_memory.ops.last().map(|op| &op.kind),
        Some(OpKind::X86GetExponent {
            merge: Some(VReg::Arch(ArchReg::X86(X86Reg::Xmm(2)))),
            src: VReg::Virtual(_),
            mask_zeroing: true,
            ..
        })
    ));

    for invalid in [
        &[0x62, 0xF2, 0x7C, 0x08, 0x42, 0xCB][..], // pp != 66
        &[0x62, 0xF6, 0xFD, 0x08, 0x42, 0xCB][..], // FP16 W=1
        &[0x62, 0xF2, 0x75, 0x08, 0x42, 0xCB][..], // packed reserved vvvv
        &[0x62, 0xF2, 0x7D, 0x00, 0x42, 0xCB][..], // packed reserved V'
        &[0x62, 0xF2, 0x7D, 0x68, 0x42, 0xCB][..], // packed L'L=3
        &[0x62, 0xF2, 0x6D, 0x18, 0x43, 0x08][..], // scalar EVEX.b memory
        &[0x62, 0xF2, 0x6D, 0x88, 0x43, 0xCB][..], // {z} with k0
    ] {
        assert!(lift_single(invalid).is_err(), "accepted {invalid:02X?}");
    }
}
#[test]
fn lift_evex_get_mantissa_covers_all_formats_controls_masks_sae_and_memory() {
    for (bytes, elem, width, lanes, scalar, imm) in [
        (
            &[0x62, 0xF3, 0x7D, 0x08, 0x26, 0xCB, 0x03][..],
            VecElementType::F32,
            VecWidth::V128,
            4,
            false,
            0x03,
        ),
        (
            &[0x62, 0xF3, 0xFD, 0x28, 0x26, 0xCB, 0x07][..],
            VecElementType::F64,
            VecWidth::V256,
            4,
            false,
            0x07,
        ),
        (
            &[0x62, 0xF3, 0x7C, 0x48, 0x26, 0xCB, 0x0B][..],
            VecElementType::F16,
            VecWidth::V512,
            32,
            false,
            0x0B,
        ),
        (
            &[0x62, 0xF3, 0x6D, 0x08, 0x27, 0xCB, 0x03][..],
            VecElementType::F32,
            VecWidth::V128,
            1,
            true,
            0x03,
        ),
        (
            &[0x62, 0xF3, 0xED, 0x68, 0x27, 0xCB, 0x02][..],
            VecElementType::F64,
            VecWidth::V128,
            1,
            true,
            0x02,
        ),
        (
            &[0x62, 0xF3, 0x6C, 0x08, 0x27, 0xCB, 0x01][..],
            VecElementType::F16,
            VecWidth::V128,
            1,
            true,
            0x01,
        ),
    ] {
        let lifted = lift_single(bytes).unwrap();
        assert_eq!(lifted.bytes_consumed, bytes.len());
        assert!(matches!(
            lifted.ops.last().map(|op| &op.kind),
            Some(OpKind::X86GetMantissa {
                elem: actual_elem,
                width: actual_width,
                lanes: actual_lanes,
                imm: actual_imm,
                scalar: actual_scalar,
                suppress_exceptions: false,
                ..
            }) if *actual_elem == elem
                && *actual_width == width
                && *actual_lanes == lanes
                && *actual_imm == imm
                && *actual_scalar == scalar
        ));
    }

    let packed_sae = lift_single(&[0x62, 0xA3, 0x7C, 0x1A, 0x26, 0xCB, 0x0B]).unwrap();
    assert!(matches!(
        packed_sae.ops.as_slice(),
        [SmirOp {
            kind: OpKind::X86GetMantissa {
                dst: VReg::Arch(ArchReg::X86(X86Reg::Zmm(17))),
                merge: None,
                src: VReg::Arch(ArchReg::X86(X86Reg::Zmm(19))),
                mask: Some(VReg::Arch(ArchReg::X86(X86Reg::K(2)))),
                elem: VecElementType::F16,
                width: VecWidth::V512,
                lanes: 32,
                imm: 0x0B,
                scalar: false,
                mask_zeroing: false,
                suppress_exceptions: true,
            },
            x86_hint: Some(X86OpHint::EvexOp {
                map: X86VecMap::Map0F3A,
                pp: X86SsePrefix::None,
                opcode: 0x26,
                width: VecWidth::V512,
                w: false,
            }),
            ..
        }]
    ));

    let scalar_sae = lift_single(&[0x62, 0xA3, 0x6D, 0x92, 0x27, 0xCB, 0x03]).unwrap();
    assert!(matches!(
        scalar_sae.ops.as_slice(),
        [SmirOp {
            kind: OpKind::X86GetMantissa {
                dst: VReg::Arch(ArchReg::X86(X86Reg::Xmm(17))),
                merge: Some(VReg::Arch(ArchReg::X86(X86Reg::Xmm(18)))),
                src: VReg::Arch(ArchReg::X86(X86Reg::Xmm(19))),
                mask: Some(VReg::Arch(ArchReg::X86(X86Reg::K(2)))),
                elem: VecElementType::F32,
                imm: 3,
                scalar: true,
                mask_zeroing: true,
                suppress_exceptions: true,
                ..
            },
            ..
        }]
    ));

    let full_memory = lift_single(&[0x62, 0xF3, 0x7D, 0x4A, 0x26, 0x48, 0x01, 0x03]).unwrap();
    assert_eq!(
        full_memory
            .ops
            .iter()
            .filter(|op| matches!(
                op.kind,
                OpKind::PredLoad {
                    width: MemWidth::B4,
                    ..
                }
            ))
            .count(),
        16
    );
    assert!(full_memory.ops.iter().any(|op| matches!(
        op.kind,
        OpKind::Lea {
            addr: Address::BaseOffset { offset: 64, .. },
            ..
        }
    )));

    let broadcast = lift_single(&[0x62, 0xF3, 0x7C, 0x5A, 0x26, 0x48, 0x01, 0x03]).unwrap();
    assert_eq!(
        broadcast
            .ops
            .iter()
            .filter(|op| matches!(op.kind, OpKind::PredLoad { .. }))
            .count(),
        1
    );
    assert!(broadcast.ops.iter().any(|op| matches!(
        op.kind,
        OpKind::PredLoad {
            addr: Address::BaseOffset { offset: 2, .. },
            width: MemWidth::B2,
            ..
        }
    )));

    let scalar_memory = lift_single(&[0x62, 0xF3, 0x6D, 0x8A, 0x27, 0x48, 0x01, 0x03]).unwrap();
    assert!(scalar_memory.ops.iter().any(|op| matches!(
        op.kind,
        OpKind::PredLoad {
            addr: Address::BaseOffset { offset: 4, .. },
            width: MemWidth::B4,
            ..
        }
    )));
    assert!(matches!(
        scalar_memory.ops.last().map(|op| &op.kind),
        Some(OpKind::X86GetMantissa {
            merge: Some(VReg::Arch(ArchReg::X86(X86Reg::Xmm(2)))),
            src: VReg::Virtual(_),
            mask_zeroing: true,
            ..
        })
    ));

    let high_imm = lift_single(&[0x62, 0xF3, 0x7D, 0x08, 0x26, 0xCB, 0xF3]).unwrap();
    assert!(matches!(
        high_imm.ops.last().map(|op| &op.kind),
        Some(OpKind::X86GetMantissa { imm: 0xF3, .. })
    ));

    for invalid in [
        &[0x62, 0xF3, 0x7E, 0x08, 0x26, 0xCB, 0x03][..], // pp=F3
        &[0x62, 0xF3, 0xFC, 0x08, 0x26, 0xCB, 0x03][..], // FP16 W=1
        &[0x62, 0xF3, 0x75, 0x08, 0x26, 0xCB, 0x03][..], // packed reserved vvvv
        &[0x62, 0xF3, 0x7D, 0x00, 0x26, 0xCB, 0x03][..], // packed reserved V'
        &[0x62, 0xF3, 0x7D, 0x68, 0x26, 0xCB, 0x03][..], // packed L'L=3
        &[0x62, 0xF3, 0x6D, 0x18, 0x27, 0x08, 0x03][..], // scalar EVEX.b memory
        &[0x62, 0xF3, 0x6D, 0x88, 0x27, 0xCB, 0x03][..], // {z} with k0
    ] {
        assert!(lift_single(invalid).is_err(), "accepted {invalid:02X?}");
    }
    assert!(matches!(
        lift_single(&[0x62, 0xF3, 0x7D, 0x08, 0x26, 0xCB]),
        Err(LiftError::Incomplete { .. })
    ));
}
#[test]
fn lift_evex_round_scale_covers_all_formats_controls_masks_sae_and_memory() {
    for (bytes, elem, width, lanes, scalar, imm) in [
        (
            &[0x62, 0xF3, 0x7D, 0x08, 0x08, 0xCB, 0x53][..],
            VecElementType::F32,
            VecWidth::V128,
            4,
            false,
            0x53,
        ),
        (
            &[0x62, 0xF3, 0xFD, 0x28, 0x09, 0xCB, 0xA7][..],
            VecElementType::F64,
            VecWidth::V256,
            4,
            false,
            0xA7,
        ),
        (
            &[0x62, 0xF3, 0x7C, 0x48, 0x08, 0xCB, 0xB9][..],
            VecElementType::F16,
            VecWidth::V512,
            32,
            false,
            0xB9,
        ),
        (
            &[0x62, 0xF3, 0x6D, 0x08, 0x0A, 0xCB, 0x4D][..],
            VecElementType::F32,
            VecWidth::V128,
            1,
            true,
            0x4D,
        ),
        (
            &[0x62, 0xF3, 0xED, 0x08, 0x0B, 0xCB, 0x21][..],
            VecElementType::F64,
            VecWidth::V128,
            1,
            true,
            0x21,
        ),
        (
            &[0x62, 0xF3, 0x6C, 0x08, 0x0A, 0xCB, 0x10][..],
            VecElementType::F16,
            VecWidth::V128,
            1,
            true,
            0x10,
        ),
    ] {
        let lifted = lift_single(bytes).unwrap();
        assert_eq!(lifted.bytes_consumed, bytes.len());
        assert!(matches!(
            lifted.ops.last().map(|op| &op.kind),
            Some(OpKind::X86RoundScale {
                elem: actual_elem,
                width: actual_width,
                lanes: actual_lanes,
                imm: actual_imm,
                scalar: actual_scalar,
                suppress_exceptions: false,
                ..
            }) if *actual_elem == elem
                && *actual_width == width
                && *actual_lanes == lanes
                && *actual_imm == imm
                && *actual_scalar == scalar
        ));
    }

    let packed_sae = lift_single(&[0x62, 0xA3, 0x7C, 0x9A, 0x08, 0xCB, 0xB9]).unwrap();
    assert!(matches!(
        packed_sae.ops.as_slice(),
        [SmirOp {
            kind: OpKind::X86RoundScale {
                dst: VReg::Arch(ArchReg::X86(X86Reg::Zmm(17))),
                merge: None,
                src: VReg::Arch(ArchReg::X86(X86Reg::Zmm(19))),
                mask: Some(VReg::Arch(ArchReg::X86(X86Reg::K(2)))),
                elem: VecElementType::F16,
                width: VecWidth::V512,
                lanes: 32,
                imm: 0xB9,
                scalar: false,
                mask_zeroing: true,
                suppress_exceptions: true,
            },
            x86_hint: Some(X86OpHint::EvexOp {
                map: X86VecMap::Map0F3A,
                pp: X86SsePrefix::None,
                opcode: 0x08,
                width: VecWidth::V512,
                w: false,
            }),
            ..
        }]
    ));

    let scalar_sae = lift_single(&[0x62, 0xA3, 0x6D, 0x92, 0x0A, 0xCB, 0x4D]).unwrap();
    assert!(matches!(
        scalar_sae.ops.as_slice(),
        [SmirOp {
            kind: OpKind::X86RoundScale {
                dst: VReg::Arch(ArchReg::X86(X86Reg::Xmm(17))),
                merge: Some(VReg::Arch(ArchReg::X86(X86Reg::Xmm(18)))),
                src: VReg::Arch(ArchReg::X86(X86Reg::Xmm(19))),
                mask: Some(VReg::Arch(ArchReg::X86(X86Reg::K(2)))),
                elem: VecElementType::F32,
                imm: 0x4D,
                scalar: true,
                mask_zeroing: true,
                suppress_exceptions: true,
                ..
            },
            ..
        }]
    ));

    let full_memory = lift_single(&[0x62, 0xF3, 0x7D, 0x4A, 0x08, 0x48, 0x01, 0x53]).unwrap();
    assert_eq!(
        full_memory
            .ops
            .iter()
            .filter(|op| matches!(
                op.kind,
                OpKind::PredLoad {
                    width: MemWidth::B4,
                    ..
                }
            ))
            .count(),
        16
    );
    assert!(full_memory.ops.iter().any(|op| matches!(
        op.kind,
        OpKind::Lea {
            addr: Address::BaseOffset { offset: 64, .. },
            ..
        }
    )));

    let broadcast = lift_single(&[0x62, 0xF3, 0x7C, 0x5A, 0x08, 0x48, 0x01, 0x33]).unwrap();
    assert_eq!(
        broadcast
            .ops
            .iter()
            .filter(|op| matches!(op.kind, OpKind::PredLoad { .. }))
            .count(),
        1
    );
    assert!(broadcast.ops.iter().any(|op| matches!(
        op.kind,
        OpKind::PredLoad {
            addr: Address::BaseOffset { offset: 2, .. },
            width: MemWidth::B2,
            ..
        }
    )));

    let scalar_memory = lift_single(&[0x62, 0xF3, 0x6D, 0x8A, 0x0A, 0x48, 0x01, 0x4D]).unwrap();
    assert!(scalar_memory.ops.iter().any(|op| matches!(
        op.kind,
        OpKind::PredLoad {
            addr: Address::BaseOffset { offset: 4, .. },
            width: MemWidth::B4,
            ..
        }
    )));
    assert!(matches!(
        scalar_memory.ops.last().map(|op| &op.kind),
        Some(OpKind::X86RoundScale {
            merge: Some(VReg::Arch(ArchReg::X86(X86Reg::Xmm(2)))),
            src: VReg::Virtual(_),
            mask_zeroing: true,
            ..
        })
    ));

    for invalid in [
        &[0x62, 0xF3, 0x7E, 0x08, 0x08, 0xCB, 0x53][..], // pp=F3
        &[0x62, 0xF3, 0xFC, 0x08, 0x08, 0xCB, 0x53][..], // FP16 W=1
        &[0x62, 0xF3, 0xFD, 0x08, 0x08, 0xCB, 0x53][..], // F64 opcode 08
        &[0x62, 0xF3, 0x75, 0x08, 0x08, 0xCB, 0x53][..], // packed reserved vvvv
        &[0x62, 0xF3, 0x7D, 0x00, 0x08, 0xCB, 0x53][..], // packed reserved V'
        &[0x62, 0xF3, 0x7D, 0x68, 0x08, 0xCB, 0x53][..], // packed L'L=3
        &[0x62, 0xF3, 0x6D, 0x18, 0x0A, 0x08, 0x4D][..], // scalar EVEX.b memory
        &[0x62, 0xF3, 0x6D, 0x88, 0x0A, 0xCB, 0x4D][..], // {z} with k0
    ] {
        assert!(lift_single(invalid).is_err(), "accepted {invalid:02X?}");
    }
    assert!(matches!(
        lift_single(&[0x62, 0xF3, 0x7D, 0x08, 0x08, 0xCB]),
        Err(LiftError::Incomplete { .. })
    ));
}
#[test]
fn lift_avx512_four_fma_covers_groups_masks_tuple_fault_suppression_and_invalids() {
    let packed = lift_single(&[0x62, 0xC2, 0x5F, 0xC2, 0xAA, 0x48, 0x02]).unwrap();
    assert_eq!(packed.bytes_consumed, 7);
    assert_eq!(
        packed
            .ops
            .iter()
            .filter(|op| matches!(
                op.kind,
                OpKind::PredVLoad {
                    width: VecWidth::V128,
                    ..
                }
            ))
            .count(),
        1,
        "masked Tuple1_4X must perform one all-or-none 16-byte read"
    );
    assert!(matches!(
        packed.ops.last().map(|op| &op.kind),
        Some(OpKind::X86FourFma {
            dst: VReg::Arch(ArchReg::X86(X86Reg::Zmm(17))),
            src0: VReg::Arch(ArchReg::X86(X86Reg::Zmm(20))),
            src1: VReg::Arch(ArchReg::X86(X86Reg::Zmm(21))),
            src2: VReg::Arch(ArchReg::X86(X86Reg::Zmm(22))),
            src3: VReg::Arch(ArchReg::X86(X86Reg::Zmm(23))),
            mask: Some(VReg::Arch(ArchReg::X86(X86Reg::K(2)))),
            scalar: false,
            negate_product: true,
            mask_zeroing: true,
            ..
        })
    ));

    // The encoded low two source-index bits select a member of the same
    // aligned source block. LL is ignored for the scalar family.
    for p2 in [0x08, 0x28, 0x48] {
        let scalar = lift_single(&[0x62, 0xF2, 0x57, p2, 0x9B, 0x08]).unwrap();
        assert!(matches!(
            scalar.ops.last().map(|op| &op.kind),
            Some(OpKind::X86FourFma {
                dst: VReg::Arch(ArchReg::X86(X86Reg::Xmm(1))),
                src0: VReg::Arch(ArchReg::X86(X86Reg::Xmm(4))),
                src1: VReg::Arch(ArchReg::X86(X86Reg::Xmm(5))),
                src2: VReg::Arch(ArchReg::X86(X86Reg::Xmm(6))),
                src3: VReg::Arch(ArchReg::X86(X86Reg::Xmm(7))),
                scalar: true,
                negate_product: false,
                ..
            })
        ));
    }

    let unmasked = lift_single(&[0x62, 0xF2, 0x5F, 0x48, 0x9A, 0x08]).unwrap();
    assert!(unmasked.ops.iter().any(|op| matches!(
        op.kind,
        OpKind::VLoad {
            width: VecWidth::V128,
            ..
        }
    )));

    for invalid in [
        &[0x62, 0xF2, 0x5F, 0x48, 0x9A, 0xC8][..], // ModRM.mod=11b
        &[0x62, 0xF2, 0x5F, 0x58, 0x9A, 0x08][..], // EVEX.b
        &[0x62, 0xF2, 0xDF, 0x48, 0x9A, 0x08][..], // EVEX.W=1
        &[0x62, 0xF2, 0x5F, 0x28, 0x9A, 0x08][..], // packed VL=256
        &[0x62, 0xF2, 0x5F, 0x68, 0x9B, 0x08][..], // EVEX.L'L=3
        &[0x62, 0xF2, 0x5F, 0xC8, 0x9A, 0x08][..], // {z} with k0
    ] {
        assert!(lift_single(invalid).is_err(), "accepted {invalid:02X?}");
    }
    let different_pp = lift_single(&[0x62, 0xF2, 0x5D, 0x48, 0x9A, 0x08]).unwrap();
    assert!(
        !different_pp
            .ops
            .iter()
            .any(|op| matches!(op.kind, OpKind::X86FourFma { .. }))
    );
    assert!(matches!(
        lift_single(&[0x62, 0xF2, 0x5F, 0x48, 0x9A]),
        Err(LiftError::Incomplete { .. })
    ));
}
#[test]
fn lift_avx512_four_dot_product_covers_groups_masks_tuple_and_invalids() {
    let saturating = lift_single(&[0x62, 0xC2, 0x5F, 0xC2, 0x53, 0x48, 0x02]).unwrap();
    assert_eq!(saturating.bytes_consumed, 7);
    assert_eq!(
        saturating
            .ops
            .iter()
            .filter(|op| matches!(
                op.kind,
                OpKind::PredVLoad {
                    width: VecWidth::V128,
                    ..
                }
            ))
            .count(),
        1,
        "masked Tuple1_4X must perform one all-or-none 16-byte read"
    );
    assert!(saturating.ops.iter().any(|op| matches!(
        op.kind,
        OpKind::PredVLoad {
            addr: Address::BaseOffset { offset: 32, .. },
            ..
        }
    )));
    assert!(matches!(
        saturating.ops.last().map(|op| &op.kind),
        Some(OpKind::X86FourDotProduct {
            dst: VReg::Arch(ArchReg::X86(X86Reg::Zmm(17))),
            src0: VReg::Arch(ArchReg::X86(X86Reg::Zmm(20))),
            src1: VReg::Arch(ArchReg::X86(X86Reg::Zmm(21))),
            src2: VReg::Arch(ArchReg::X86(X86Reg::Zmm(22))),
            src3: VReg::Arch(ArchReg::X86(X86Reg::Zmm(23))),
            mask: Some(VReg::Arch(ArchReg::X86(X86Reg::K(2)))),
            saturating: true,
            mask_zeroing: true,
            ..
        })
    ));

    let wrapping = lift_single(&[0x62, 0xF2, 0x7F, 0x48, 0x52, 0x08]).unwrap();
    assert!(wrapping.ops.iter().any(|op| matches!(
        op.kind,
        OpKind::VLoad {
            width: VecWidth::V128,
            ..
        }
    )));
    assert!(matches!(
        wrapping.ops.last().map(|op| &op.kind),
        Some(OpKind::X86FourDotProduct {
            saturating: false,
            mask: None,
            ..
        })
    ));

    for invalid in [
        &[0x62, 0xF2, 0x7F, 0x48, 0x52, 0xC8][..], // ModRM.mod=11b
        &[0x62, 0xF2, 0x7F, 0x58, 0x52, 0x08][..], // EVEX.b
        &[0x62, 0xF2, 0xFF, 0x48, 0x52, 0x08][..], // EVEX.W=1
        &[0x62, 0xF2, 0x7F, 0x28, 0x52, 0x08][..], // VL=256
        &[0x62, 0xF2, 0x7F, 0x68, 0x52, 0x08][..], // EVEX.L'L=3
        &[0x62, 0xF2, 0x7F, 0xC8, 0x52, 0x08][..], // {z} with k0
    ] {
        assert!(lift_single(invalid).is_err(), "accepted {invalid:02X?}");
    }
    let different_pp = lift_single(&[0x62, 0xF2, 0x7D, 0x48, 0x52, 0x08]).unwrap();
    assert!(
        !different_pp
            .ops
            .iter()
            .any(|op| matches!(op.kind, OpKind::X86FourDotProduct { .. }))
    );
    assert!(matches!(
        lift_single(&[0x62, 0xF2, 0x7F, 0x48, 0x52]),
        Err(LiftError::Incomplete { .. })
    ));
}
