//! gate::native tests

use super::*;
use crate::smir::lower::runtime::jit_gate_tests::*;
use crate::smir::lower::runtime::*;

#[test]
fn scalar_alu_immediate_gate_accepts_w64_values_without_imm32_truncation() {
    let add = |value, width| OpKind::Add {
        dst: x86(X86Reg::Rbx),
        src1: x86(X86Reg::Rbx),
        src2: SrcOperand::Imm(value),
        width,
        flags: FlagUpdate::All,
    };
    let native = |op| {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
        builder.push_op(0x1000, op);
        builder.set_terminator(Terminator::Return { values: Vec::new() });
        is_native_clobber_safe(&builder.finish())
    };

    assert!(native(add(i64::from(i32::MIN), OpWidth::W64)));
    assert!(native(add(i64::from(i32::MAX), OpWidth::W64)));
    assert!(native(add(0x8000_0000, OpWidth::W64)));
    assert!(native(add(i64::from(i32::MIN) - 1, OpWidth::W64)));
    assert!(native(add(0x8000_0000, OpWidth::W32)));
}

#[test]
fn get_exponent_native_gate_validates_shapes_and_encodings() {
    let packed = OpKind::X86GetExponent {
        dst: x86(X86Reg::Zmm(17)),
        merge: None,
        src: x86(X86Reg::Zmm(19)),
        mask: Some(x86(X86Reg::K(2))),
        elem: VecElementType::F16,
        width: VecWidth::V512,
        lanes: 32,
        scalar: false,
        mask_zeroing: false,
        suppress_exceptions: true,
    };
    let packed_op = crate::smir::ir::ops::SmirOp::with_hint(
        crate::smir::ir::types::OpId(0),
        0xA000,
        packed.clone(),
        X86OpHint::EvexOp {
            map: crate::smir::ir::ops::X86VecMap::Map6,
            pp: X86SsePrefix::OpSize,
            opcode: 0x42,
            width: VecWidth::V512,
            w: false,
        },
    );
    assert!(is_x86_native_vector_op(&packed));
    assert!(x86_native_vector_smir_op(&packed_op));

    let scalar = OpKind::X86GetExponent {
        dst: x86(X86Reg::Xmm(17)),
        merge: Some(x86(X86Reg::Xmm(18))),
        src: x86(X86Reg::Xmm(19)),
        mask: Some(x86(X86Reg::K(2))),
        elem: VecElementType::F32,
        width: VecWidth::V128,
        lanes: 1,
        scalar: true,
        mask_zeroing: true,
        suppress_exceptions: true,
    };
    let scalar_op = crate::smir::ir::ops::SmirOp::with_hint(
        crate::smir::ir::types::OpId(1),
        0xA006,
        scalar.clone(),
        X86OpHint::EvexOp {
            map: crate::smir::ir::ops::X86VecMap::Map0F38,
            pp: X86SsePrefix::OpSize,
            opcode: 0x43,
            width: VecWidth::V128,
            w: false,
        },
    );
    assert!(is_x86_native_vector_op(&scalar));
    assert!(x86_native_vector_smir_op(&scalar_op));

    let mut wrong_hint = scalar_op.clone();
    wrong_hint.x86_hint = Some(X86OpHint::EvexOp {
        map: crate::smir::ir::ops::X86VecMap::Map0F38,
        pp: X86SsePrefix::OpSize,
        opcode: 0x42,
        width: VecWidth::V128,
        w: false,
    });
    assert!(!x86_native_vector_smir_op(&wrong_hint));

    let mut virtual_source = scalar.clone();
    let OpKind::X86GetExponent { src, .. } = &mut virtual_source else {
        unreachable!()
    };
    *src = VReg::virt(7);
    assert!(!is_x86_native_vector_op(&virtual_source));

    let mut short_sae = packed;
    let OpKind::X86GetExponent {
        dst,
        src,
        width,
        lanes,
        ..
    } = &mut short_sae
    else {
        unreachable!()
    };
    *dst = x86(X86Reg::Ymm(17));
    *src = x86(X86Reg::Ymm(19));
    *width = VecWidth::V256;
    *lanes = 16;
    assert!(!is_x86_native_vector_op(&short_sae));
}
#[test]
fn get_mantissa_native_gate_validates_shapes_and_encodings() {
    let packed = OpKind::X86GetMantissa {
        dst: x86(X86Reg::Zmm(17)),
        merge: None,
        src: x86(X86Reg::Zmm(19)),
        mask: Some(x86(X86Reg::K(2))),
        elem: VecElementType::F16,
        width: VecWidth::V512,
        lanes: 32,
        imm: 0xFB,
        scalar: false,
        mask_zeroing: false,
        suppress_exceptions: true,
    };
    let packed_op = crate::smir::ir::ops::SmirOp::with_hint(
        crate::smir::ir::types::OpId(0),
        0xA000,
        packed.clone(),
        X86OpHint::EvexOp {
            map: crate::smir::ir::ops::X86VecMap::Map0F3A,
            pp: X86SsePrefix::None,
            opcode: 0x26,
            width: VecWidth::V512,
            w: false,
        },
    );
    assert!(is_x86_native_vector_op(&packed));
    assert!(x86_native_vector_smir_op(&packed_op));

    let scalar = OpKind::X86GetMantissa {
        dst: x86(X86Reg::Xmm(17)),
        merge: Some(x86(X86Reg::Xmm(18))),
        src: x86(X86Reg::Xmm(19)),
        mask: Some(x86(X86Reg::K(2))),
        elem: VecElementType::F32,
        width: VecWidth::V128,
        lanes: 1,
        imm: 3,
        scalar: true,
        mask_zeroing: true,
        suppress_exceptions: true,
    };
    let scalar_op = crate::smir::ir::ops::SmirOp::with_hint(
        crate::smir::ir::types::OpId(1),
        0xA007,
        scalar.clone(),
        X86OpHint::EvexOp {
            map: crate::smir::ir::ops::X86VecMap::Map0F3A,
            pp: X86SsePrefix::OpSize,
            opcode: 0x27,
            width: VecWidth::V128,
            w: false,
        },
    );
    assert!(is_x86_native_vector_op(&scalar));
    assert!(x86_native_vector_smir_op(&scalar_op));

    let mut wrong_hint = scalar_op.clone();
    wrong_hint.x86_hint = Some(X86OpHint::EvexOp {
        map: crate::smir::ir::ops::X86VecMap::Map0F3A,
        pp: X86SsePrefix::None,
        opcode: 0x27,
        width: VecWidth::V128,
        w: false,
    });
    assert!(!x86_native_vector_smir_op(&wrong_hint));

    let mut virtual_source = scalar.clone();
    let OpKind::X86GetMantissa { src, .. } = &mut virtual_source else {
        unreachable!()
    };
    *src = VReg::virt(7);
    assert!(!is_x86_native_vector_op(&virtual_source));

    let mut short_sae = packed;
    let OpKind::X86GetMantissa {
        dst,
        src,
        width,
        lanes,
        ..
    } = &mut short_sae
    else {
        unreachable!()
    };
    *dst = x86(X86Reg::Ymm(17));
    *src = x86(X86Reg::Ymm(19));
    *width = VecWidth::V256;
    *lanes = 16;
    assert!(!is_x86_native_vector_op(&short_sae));
}
#[test]
fn round_scale_native_gate_validates_shapes_and_encodings() {
    let packed = OpKind::X86RoundScale {
        dst: x86(X86Reg::Zmm(17)),
        merge: None,
        src: x86(X86Reg::Zmm(19)),
        mask: Some(x86(X86Reg::K(2))),
        elem: VecElementType::F16,
        width: VecWidth::V512,
        lanes: 32,
        imm: 0xB9,
        scalar: false,
        mask_zeroing: true,
        suppress_exceptions: true,
    };
    let packed_op = crate::smir::ir::ops::SmirOp::with_hint(
        crate::smir::ir::types::OpId(0),
        0xA000,
        packed.clone(),
        X86OpHint::EvexOp {
            map: crate::smir::ir::ops::X86VecMap::Map0F3A,
            pp: X86SsePrefix::None,
            opcode: 0x08,
            width: VecWidth::V512,
            w: false,
        },
    );
    assert!(is_x86_native_vector_op(&packed));
    assert!(x86_native_vector_smir_op(&packed_op));

    let scalar = OpKind::X86RoundScale {
        dst: x86(X86Reg::Xmm(17)),
        merge: Some(x86(X86Reg::Xmm(18))),
        src: x86(X86Reg::Xmm(19)),
        mask: Some(x86(X86Reg::K(2))),
        elem: VecElementType::F64,
        width: VecWidth::V128,
        lanes: 1,
        imm: 0x21,
        scalar: true,
        mask_zeroing: true,
        suppress_exceptions: true,
    };
    let scalar_op = crate::smir::ir::ops::SmirOp::with_hint(
        crate::smir::ir::types::OpId(1),
        0xA007,
        scalar.clone(),
        X86OpHint::EvexOp {
            map: crate::smir::ir::ops::X86VecMap::Map0F3A,
            pp: X86SsePrefix::OpSize,
            opcode: 0x0B,
            width: VecWidth::V128,
            w: true,
        },
    );
    assert!(is_x86_native_vector_op(&scalar));
    assert!(x86_native_vector_smir_op(&scalar_op));

    let mut wrong_hint = scalar_op.clone();
    wrong_hint.x86_hint = Some(X86OpHint::EvexOp {
        map: crate::smir::ir::ops::X86VecMap::Map0F3A,
        pp: X86SsePrefix::OpSize,
        opcode: 0x0A,
        width: VecWidth::V128,
        w: true,
    });
    assert!(!x86_native_vector_smir_op(&wrong_hint));

    let mut virtual_source = scalar.clone();
    let OpKind::X86RoundScale { src, .. } = &mut virtual_source else {
        unreachable!()
    };
    *src = VReg::virt(7);
    assert!(!is_x86_native_vector_op(&virtual_source));

    let mut short_sae = packed;
    let OpKind::X86RoundScale {
        dst,
        src,
        width,
        lanes,
        ..
    } = &mut short_sae
    else {
        unreachable!()
    };
    *dst = x86(X86Reg::Ymm(17));
    *src = x86(X86Reg::Ymm(19));
    *width = VecWidth::V256;
    *lanes = 16;
    assert!(!is_x86_native_vector_op(&short_sae));
}
#[test]
fn reduce_native_gate_validates_shapes_and_encodings() {
    let packed = OpKind::X86Reduce {
        dst: x86(X86Reg::Zmm(17)),
        merge: None,
        src: x86(X86Reg::Zmm(19)),
        mask: Some(x86(X86Reg::K(2))),
        elem: VecElementType::F16,
        width: VecWidth::V512,
        lanes: 32,
        imm: 0xB9,
        scalar: false,
        mask_zeroing: true,
        suppress_exceptions: true,
    };
    let packed_op = crate::smir::ir::ops::SmirOp::with_hint(
        crate::smir::ir::types::OpId(0),
        0xA000,
        packed.clone(),
        X86OpHint::EvexOp {
            map: crate::smir::ir::ops::X86VecMap::Map0F3A,
            pp: X86SsePrefix::None,
            opcode: 0x56,
            width: VecWidth::V512,
            w: false,
        },
    );
    assert!(is_x86_native_vector_op(&packed));
    assert!(x86_native_vector_smir_op(&packed_op));

    let scalar = OpKind::X86Reduce {
        dst: x86(X86Reg::Xmm(17)),
        merge: Some(x86(X86Reg::Xmm(18))),
        src: x86(X86Reg::Xmm(19)),
        mask: Some(x86(X86Reg::K(2))),
        elem: VecElementType::F64,
        width: VecWidth::V128,
        lanes: 1,
        imm: 0x21,
        scalar: true,
        mask_zeroing: true,
        suppress_exceptions: true,
    };
    let scalar_op = crate::smir::ir::ops::SmirOp::with_hint(
        crate::smir::ir::types::OpId(1),
        0xA007,
        scalar.clone(),
        X86OpHint::EvexOp {
            map: crate::smir::ir::ops::X86VecMap::Map0F3A,
            pp: X86SsePrefix::OpSize,
            opcode: 0x57,
            width: VecWidth::V128,
            w: true,
        },
    );
    assert!(is_x86_native_vector_op(&scalar));
    assert!(x86_native_vector_smir_op(&scalar_op));

    let mut wrong_hint = scalar_op.clone();
    wrong_hint.x86_hint = Some(X86OpHint::EvexOp {
        map: crate::smir::ir::ops::X86VecMap::Map0F3A,
        pp: X86SsePrefix::OpSize,
        opcode: 0x56,
        width: VecWidth::V128,
        w: true,
    });
    assert!(!x86_native_vector_smir_op(&wrong_hint));

    let mut virtual_source = scalar.clone();
    let OpKind::X86Reduce { src, .. } = &mut virtual_source else {
        unreachable!()
    };
    *src = VReg::virt(7);
    assert!(!is_x86_native_vector_op(&virtual_source));

    let mut short_sae = packed;
    let OpKind::X86Reduce {
        dst,
        src,
        width,
        lanes,
        ..
    } = &mut short_sae
    else {
        unreachable!()
    };
    *dst = x86(X86Reg::Ymm(17));
    *src = x86(X86Reg::Ymm(19));
    *width = VecWidth::V256;
    *lanes = 16;
    assert!(!is_x86_native_vector_op(&short_sae));
}
#[test]
fn range_native_gate_validates_shapes_immediate_and_encodings() {
    let packed = OpKind::X86Range {
        dst: x86(X86Reg::Zmm(17)),
        src1: x86(X86Reg::Zmm(18)),
        src2: x86(X86Reg::Zmm(19)),
        mask: Some(x86(X86Reg::K(2))),
        elem: VecElementType::F32,
        width: VecWidth::V512,
        lanes: 16,
        imm: 0x0F,
        scalar: false,
        mask_zeroing: true,
        suppress_exceptions: true,
    };
    let packed_op = crate::smir::ir::ops::SmirOp::with_hint(
        crate::smir::ir::types::OpId(0),
        0xA000,
        packed.clone(),
        X86OpHint::EvexOp {
            map: X86VecMap::Map0F3A,
            pp: X86SsePrefix::OpSize,
            opcode: 0x50,
            width: VecWidth::V512,
            w: false,
        },
    );
    assert!(is_x86_native_vector_op(&packed));
    assert!(x86_native_vector_smir_op(&packed_op));

    let scalar = OpKind::X86Range {
        dst: x86(X86Reg::Xmm(17)),
        src1: x86(X86Reg::Xmm(18)),
        src2: x86(X86Reg::Xmm(19)),
        mask: Some(x86(X86Reg::K(2))),
        elem: VecElementType::F64,
        width: VecWidth::V128,
        lanes: 1,
        imm: 0x0D,
        scalar: true,
        mask_zeroing: true,
        suppress_exceptions: true,
    };
    let scalar_op = crate::smir::ir::ops::SmirOp::with_hint(
        crate::smir::ir::types::OpId(1),
        0xA007,
        scalar.clone(),
        X86OpHint::EvexOp {
            map: X86VecMap::Map0F3A,
            pp: X86SsePrefix::OpSize,
            opcode: 0x51,
            width: VecWidth::V128,
            w: true,
        },
    );
    assert!(is_x86_native_vector_op(&scalar));
    assert!(x86_native_vector_smir_op(&scalar_op));

    let mut wrong_hint = scalar_op;
    wrong_hint.x86_hint = Some(X86OpHint::EvexOp {
        map: X86VecMap::Map0F3A,
        pp: X86SsePrefix::OpSize,
        opcode: 0x50,
        width: VecWidth::V128,
        w: true,
    });
    assert!(!x86_native_vector_smir_op(&wrong_hint));

    let mut virtual_source = scalar.clone();
    let OpKind::X86Range { src2, .. } = &mut virtual_source else {
        unreachable!()
    };
    *src2 = VReg::virt(7);
    assert!(!is_x86_native_vector_op(&virtual_source));

    let mut high_imm = scalar;
    let OpKind::X86Range { imm, .. } = &mut high_imm else {
        unreachable!()
    };
    *imm = 0x10;
    assert!(!is_x86_native_vector_op(&high_imm));

    let mut short_sae = packed;
    let OpKind::X86Range {
        dst,
        src1,
        src2,
        width,
        lanes,
        ..
    } = &mut short_sae
    else {
        unreachable!()
    };
    *dst = x86(X86Reg::Ymm(17));
    *src1 = x86(X86Reg::Ymm(18));
    *src2 = x86(X86Reg::Ymm(19));
    *width = VecWidth::V256;
    *lanes = 8;
    assert!(!is_x86_native_vector_op(&short_sae));
}
#[test]
fn exp2_native_gate_validates_zmm_shapes_masks_and_encodings() {
    let packed = OpKind::X86Exp2 {
        dst: x86(X86Reg::Zmm(17)),
        src: x86(X86Reg::Zmm(19)),
        mask: Some(x86(X86Reg::K(2))),
        elem: VecElementType::F32,
        width: VecWidth::V512,
        lanes: 16,
        mask_zeroing: true,
        suppress_exceptions: true,
    };
    let packed_op = crate::smir::ir::ops::SmirOp::with_hint(
        crate::smir::ir::types::OpId(0),
        0xA000,
        packed.clone(),
        X86OpHint::EvexOp {
            map: X86VecMap::Map0F38,
            pp: X86SsePrefix::OpSize,
            opcode: 0xC8,
            width: VecWidth::V512,
            w: false,
        },
    );
    assert!(is_x86_native_vector_op(&packed));
    assert!(x86_native_vector_smir_op(&packed_op));

    let double = OpKind::X86Exp2 {
        dst: x86(X86Reg::Zmm(1)),
        src: x86(X86Reg::Zmm(3)),
        mask: None,
        elem: VecElementType::F64,
        width: VecWidth::V512,
        lanes: 8,
        mask_zeroing: false,
        suppress_exceptions: false,
    };
    let double_op = crate::smir::ir::ops::SmirOp::with_hint(
        crate::smir::ir::types::OpId(1),
        0xA006,
        double.clone(),
        X86OpHint::EvexOp {
            map: X86VecMap::Map0F38,
            pp: X86SsePrefix::OpSize,
            opcode: 0xC8,
            width: VecWidth::V512,
            w: true,
        },
    );
    assert!(is_x86_native_vector_op(&double));
    assert!(x86_native_vector_smir_op(&double_op));

    let mut wrong_hint = double_op;
    wrong_hint.x86_hint = Some(X86OpHint::EvexOp {
        map: X86VecMap::Map0F3A,
        pp: X86SsePrefix::OpSize,
        opcode: 0xC8,
        width: VecWidth::V512,
        w: true,
    });
    assert!(!x86_native_vector_smir_op(&wrong_hint));

    let mut virtual_source = double.clone();
    let OpKind::X86Exp2 { src, .. } = &mut virtual_source else {
        unreachable!()
    };
    *src = VReg::virt(7);
    assert!(!is_x86_native_vector_op(&virtual_source));

    let mut bad_mask = double.clone();
    let OpKind::X86Exp2 {
        mask, mask_zeroing, ..
    } = &mut bad_mask
    else {
        unreachable!()
    };
    *mask = Some(x86(X86Reg::K(0)));
    *mask_zeroing = true;
    assert!(!is_x86_native_vector_op(&bad_mask));

    let mut short = packed;
    let OpKind::X86Exp2 {
        dst,
        src,
        width,
        lanes,
        ..
    } = &mut short
    else {
        unreachable!()
    };
    *dst = x86(X86Reg::Ymm(17));
    *src = x86(X86Reg::Ymm(19));
    *width = VecWidth::V256;
    *lanes = 8;
    assert!(!is_x86_native_vector_op(&short));
}
#[test]
fn recip14_native_gate_validates_widths_scalar_masks_and_encodings() {
    let packed = OpKind::X86Recip14 {
        dst: x86(X86Reg::Ymm(17)),
        merge: None,
        src: x86(X86Reg::Ymm(19)),
        mask: Some(x86(X86Reg::K(2))),
        elem: VecElementType::F32,
        width: VecWidth::V256,
        lanes: 8,
        scalar: false,
        mask_zeroing: true,
    };
    let packed_op = crate::smir::ir::ops::SmirOp::with_hint(
        crate::smir::ir::types::OpId(0),
        0xA000,
        packed.clone(),
        X86OpHint::EvexOp {
            map: X86VecMap::Map0F38,
            pp: X86SsePrefix::OpSize,
            opcode: 0x4C,
            width: VecWidth::V256,
            w: false,
        },
    );
    assert!(is_x86_native_vector_op(&packed));
    assert!(x86_native_vector_smir_op(&packed_op));

    let scalar = OpKind::X86Recip14 {
        dst: x86(X86Reg::Xmm(17)),
        merge: Some(x86(X86Reg::Xmm(18))),
        src: x86(X86Reg::Xmm(19)),
        mask: Some(x86(X86Reg::K(2))),
        elem: VecElementType::F64,
        width: VecWidth::V128,
        lanes: 1,
        scalar: true,
        mask_zeroing: true,
    };
    let scalar_op = crate::smir::ir::ops::SmirOp::with_hint(
        crate::smir::ir::types::OpId(1),
        0xA006,
        scalar.clone(),
        X86OpHint::EvexOp {
            map: X86VecMap::Map0F38,
            pp: X86SsePrefix::OpSize,
            opcode: 0x4D,
            width: VecWidth::V128,
            w: true,
        },
    );
    assert!(is_x86_native_vector_op(&scalar));
    assert!(x86_native_vector_smir_op(&scalar_op));

    let mut wrong_hint = scalar_op;
    wrong_hint.x86_hint = Some(X86OpHint::EvexOp {
        map: X86VecMap::Map0F38,
        pp: X86SsePrefix::OpSize,
        opcode: 0x4C,
        width: VecWidth::V128,
        w: true,
    });
    assert!(!x86_native_vector_smir_op(&wrong_hint));

    let mut virtual_merge = scalar.clone();
    let OpKind::X86Recip14 { merge, .. } = &mut virtual_merge else {
        unreachable!()
    };
    *merge = Some(VReg::virt(7));
    assert!(!is_x86_native_vector_op(&virtual_merge));

    let mut missing_merge = scalar;
    let OpKind::X86Recip14 { merge, .. } = &mut missing_merge else {
        unreachable!()
    };
    *merge = None;
    assert!(!is_x86_native_vector_op(&missing_merge));

    let mut mismatched_width = packed;
    let OpKind::X86Recip14 { dst, src, .. } = &mut mismatched_width else {
        unreachable!()
    };
    *dst = x86(X86Reg::Zmm(17));
    *src = x86(X86Reg::Zmm(19));
    assert!(!is_x86_native_vector_op(&mismatched_width));
}
#[test]
fn rsqrt14_native_gate_validates_widths_scalar_masks_and_encodings() {
    let packed = OpKind::X86Rsqrt14 {
        dst: x86(X86Reg::Ymm(17)),
        merge: None,
        src: x86(X86Reg::Ymm(19)),
        mask: Some(x86(X86Reg::K(2))),
        elem: VecElementType::F32,
        width: VecWidth::V256,
        lanes: 8,
        scalar: false,
        mask_zeroing: true,
    };
    let packed_op = crate::smir::ir::ops::SmirOp::with_hint(
        crate::smir::ir::types::OpId(0),
        0xA000,
        packed.clone(),
        X86OpHint::EvexOp {
            map: X86VecMap::Map0F38,
            pp: X86SsePrefix::OpSize,
            opcode: 0x4E,
            width: VecWidth::V256,
            w: false,
        },
    );
    assert!(is_x86_native_vector_op(&packed));
    assert!(x86_native_vector_smir_op(&packed_op));

    let scalar = OpKind::X86Rsqrt14 {
        dst: x86(X86Reg::Xmm(17)),
        merge: Some(x86(X86Reg::Xmm(18))),
        src: x86(X86Reg::Xmm(19)),
        mask: Some(x86(X86Reg::K(2))),
        elem: VecElementType::F64,
        width: VecWidth::V128,
        lanes: 1,
        scalar: true,
        mask_zeroing: true,
    };
    let scalar_op = crate::smir::ir::ops::SmirOp::with_hint(
        crate::smir::ir::types::OpId(1),
        0xA006,
        scalar.clone(),
        X86OpHint::EvexOp {
            map: X86VecMap::Map0F38,
            pp: X86SsePrefix::OpSize,
            opcode: 0x4F,
            width: VecWidth::V128,
            w: true,
        },
    );
    assert!(is_x86_native_vector_op(&scalar));
    assert!(x86_native_vector_smir_op(&scalar_op));

    let mut wrong_hint = scalar_op;
    wrong_hint.x86_hint = Some(X86OpHint::EvexOp {
        map: X86VecMap::Map0F38,
        pp: X86SsePrefix::OpSize,
        opcode: 0x4E,
        width: VecWidth::V128,
        w: true,
    });
    assert!(!x86_native_vector_smir_op(&wrong_hint));

    let mut virtual_merge = scalar.clone();
    let OpKind::X86Rsqrt14 { merge, .. } = &mut virtual_merge else {
        unreachable!()
    };
    *merge = Some(VReg::virt(7));
    assert!(!is_x86_native_vector_op(&virtual_merge));

    let mut missing_merge = scalar;
    let OpKind::X86Rsqrt14 { merge, .. } = &mut missing_merge else {
        unreachable!()
    };
    *merge = None;
    assert!(!is_x86_native_vector_op(&missing_merge));

    let mut mismatched_width = packed;
    let OpKind::X86Rsqrt14 { dst, src, .. } = &mut mismatched_width else {
        unreachable!()
    };
    *dst = x86(X86Reg::Zmm(17));
    *src = x86(X86Reg::Zmm(19));
    assert!(!is_x86_native_vector_op(&mismatched_width));
}
#[test]
fn fp16_approx_native_gate_validates_widths_scalar_masks_and_encodings() {
    let packed = OpKind::X86RecipFp16 {
        dst: x86(X86Reg::Ymm(17)),
        merge: None,
        src: x86(X86Reg::Ymm(19)),
        mask: Some(x86(X86Reg::K(2))),
        width: VecWidth::V256,
        lanes: 16,
        scalar: false,
        mask_zeroing: true,
    };
    let packed_op = crate::smir::ir::ops::SmirOp::with_hint(
        crate::smir::ir::types::OpId(0),
        0xA000,
        packed.clone(),
        X86OpHint::EvexOp {
            map: X86VecMap::Map6,
            pp: X86SsePrefix::OpSize,
            opcode: 0x4C,
            width: VecWidth::V256,
            w: false,
        },
    );
    assert!(is_x86_native_vector_op(&packed));
    assert!(x86_native_vector_smir_op(&packed_op));

    let scalar = OpKind::X86RsqrtFp16 {
        dst: x86(X86Reg::Xmm(17)),
        merge: Some(x86(X86Reg::Xmm(18))),
        src: x86(X86Reg::Xmm(19)),
        mask: Some(x86(X86Reg::K(2))),
        width: VecWidth::V128,
        lanes: 1,
        scalar: true,
        mask_zeroing: true,
    };
    let scalar_op = crate::smir::ir::ops::SmirOp::with_hint(
        crate::smir::ir::types::OpId(1),
        0xA006,
        scalar.clone(),
        X86OpHint::EvexOp {
            map: X86VecMap::Map6,
            pp: X86SsePrefix::OpSize,
            opcode: 0x4F,
            width: VecWidth::V128,
            w: false,
        },
    );
    assert!(is_x86_native_vector_op(&scalar));
    assert!(x86_native_vector_smir_op(&scalar_op));

    let mut wrong_hint = scalar_op;
    wrong_hint.x86_hint = Some(X86OpHint::EvexOp {
        map: X86VecMap::Map0F38,
        pp: X86SsePrefix::OpSize,
        opcode: 0x4F,
        width: VecWidth::V128,
        w: false,
    });
    assert!(!x86_native_vector_smir_op(&wrong_hint));

    let mut virtual_merge = scalar.clone();
    let OpKind::X86RsqrtFp16 { merge, .. } = &mut virtual_merge else {
        unreachable!()
    };
    *merge = Some(VReg::virt(7));
    assert!(!is_x86_native_vector_op(&virtual_merge));

    let mut missing_merge = scalar;
    let OpKind::X86RsqrtFp16 { merge, .. } = &mut missing_merge else {
        unreachable!()
    };
    *merge = None;
    assert!(!is_x86_native_vector_op(&missing_merge));

    let mut mismatched_width = packed;
    let OpKind::X86RecipFp16 { dst, src, .. } = &mut mismatched_width else {
        unreachable!()
    };
    *dst = x86(X86Reg::Zmm(17));
    *src = x86(X86Reg::Zmm(19));
    assert!(!is_x86_native_vector_op(&mismatched_width));
}
#[test]
fn scale_f_native_gate_validates_shapes_rounding_and_encodings() {
    let packed = OpKind::X86ScaleF {
        dst: x86(X86Reg::Zmm(17)),
        src1: x86(X86Reg::Zmm(18)),
        src2: x86(X86Reg::Zmm(19)),
        mask: Some(x86(X86Reg::K(2))),
        elem: VecElementType::F16,
        width: VecWidth::V512,
        lanes: 32,
        scalar: false,
        mask_zeroing: true,
        round: FpRoundMode::RoundNearest,
        suppress_exceptions: true,
    };
    let packed_op = crate::smir::ir::ops::SmirOp::with_hint(
        crate::smir::ir::types::OpId(0),
        0xA000,
        packed.clone(),
        X86OpHint::EvexOp {
            map: X86VecMap::Map6,
            pp: X86SsePrefix::OpSize,
            opcode: 0x2C,
            width: VecWidth::V512,
            w: false,
        },
    );
    assert!(is_x86_native_vector_op(&packed));
    assert!(x86_native_vector_smir_op(&packed_op));

    let scalar = OpKind::X86ScaleF {
        dst: x86(X86Reg::Xmm(17)),
        src1: x86(X86Reg::Xmm(18)),
        src2: x86(X86Reg::Xmm(19)),
        mask: Some(x86(X86Reg::K(2))),
        elem: VecElementType::F64,
        width: VecWidth::V128,
        lanes: 1,
        scalar: true,
        mask_zeroing: true,
        round: FpRoundMode::RoundTowardZero,
        suppress_exceptions: true,
    };
    let scalar_op = crate::smir::ir::ops::SmirOp::with_hint(
        crate::smir::ir::types::OpId(1),
        0xA006,
        scalar.clone(),
        X86OpHint::EvexOp {
            map: X86VecMap::Map0F38,
            pp: X86SsePrefix::OpSize,
            opcode: 0x2D,
            width: VecWidth::V128,
            w: true,
        },
    );
    assert!(is_x86_native_vector_op(&scalar));
    assert!(x86_native_vector_smir_op(&scalar_op));

    let mut wrong_hint = scalar_op;
    wrong_hint.x86_hint = Some(X86OpHint::EvexOp {
        map: X86VecMap::Map0F38,
        pp: X86SsePrefix::OpSize,
        opcode: 0x2C,
        width: VecWidth::V128,
        w: true,
    });
    assert!(!x86_native_vector_smir_op(&wrong_hint));

    let mut virtual_source = scalar.clone();
    let OpKind::X86ScaleF { src2, .. } = &mut virtual_source else {
        unreachable!()
    };
    *src2 = VReg::virt(7);
    assert!(!is_x86_native_vector_op(&virtual_source));

    let mut inconsistent_sae = scalar;
    let OpKind::X86ScaleF {
        round,
        suppress_exceptions,
        ..
    } = &mut inconsistent_sae
    else {
        unreachable!()
    };
    *round = FpRoundMode::Dynamic;
    *suppress_exceptions = true;
    assert!(!is_x86_native_vector_op(&inconsistent_sae));

    let mut short_er = packed;
    let OpKind::X86ScaleF {
        dst,
        src1,
        src2,
        width,
        lanes,
        ..
    } = &mut short_er
    else {
        unreachable!()
    };
    *dst = x86(X86Reg::Ymm(17));
    *src1 = x86(X86Reg::Ymm(18));
    *src2 = x86(X86Reg::Ymm(19));
    *width = VecWidth::V256;
    *lanes = 16;
    assert!(!is_x86_native_vector_op(&short_er));
}
#[test]
fn fp16_complex_native_gate_validates_pairs_aliases_rounding_and_encodings() {
    let packed = OpKind::X86FP16Complex {
        dst: x86(X86Reg::Zmm(17)),
        src1: x86(X86Reg::Zmm(18)),
        src2: x86(X86Reg::Zmm(19)),
        mask: Some(x86(X86Reg::K(2))),
        width: VecWidth::V512,
        pairs: 16,
        scalar: false,
        mask_zeroing: true,
        accumulate: true,
        conjugate: false,
        round: FpRoundMode::RoundNearest,
    };
    let packed_op = crate::smir::ir::ops::SmirOp::with_hint(
        crate::smir::ir::types::OpId(0),
        0xA000,
        packed.clone(),
        X86OpHint::EvexOp {
            map: X86VecMap::Map6,
            pp: X86SsePrefix::Rep,
            opcode: 0x56,
            width: VecWidth::V512,
            w: false,
        },
    );
    assert!(is_x86_native_vector_op(&packed));
    assert!(x86_native_vector_smir_op(&packed_op));

    let scalar = OpKind::X86FP16Complex {
        dst: x86(X86Reg::Xmm(17)),
        src1: x86(X86Reg::Xmm(18)),
        src2: x86(X86Reg::Xmm(19)),
        mask: Some(x86(X86Reg::K(2))),
        width: VecWidth::V128,
        pairs: 1,
        scalar: true,
        mask_zeroing: true,
        accumulate: false,
        conjugate: true,
        round: FpRoundMode::RoundTowardZero,
    };
    let scalar_op = crate::smir::ir::ops::SmirOp::with_hint(
        crate::smir::ir::types::OpId(1),
        0xA006,
        scalar.clone(),
        X86OpHint::EvexOp {
            map: X86VecMap::Map6,
            pp: X86SsePrefix::Repne,
            opcode: 0xD7,
            width: VecWidth::V128,
            w: false,
        },
    );
    assert!(is_x86_native_vector_op(&scalar));
    assert!(x86_native_vector_smir_op(&scalar_op));

    let mut wrong_hint = scalar_op;
    wrong_hint.x86_hint = Some(X86OpHint::EvexOp {
        map: X86VecMap::Map6,
        pp: X86SsePrefix::Rep,
        opcode: 0xD7,
        width: VecWidth::V128,
        w: false,
    });
    assert!(!x86_native_vector_smir_op(&wrong_hint));

    let mut alias = scalar.clone();
    let OpKind::X86FP16Complex { dst, src1, .. } = &mut alias else {
        unreachable!()
    };
    *src1 = *dst;
    assert!(!is_x86_native_vector_op(&alias));

    let mut virtual_source = scalar;
    let OpKind::X86FP16Complex { src2, .. } = &mut virtual_source else {
        unreachable!()
    };
    *src2 = VReg::virt(7);
    assert!(!is_x86_native_vector_op(&virtual_source));

    let mut short_er = packed;
    let OpKind::X86FP16Complex {
        dst,
        src1,
        src2,
        width,
        pairs,
        ..
    } = &mut short_er
    else {
        unreachable!()
    };
    *dst = x86(X86Reg::Ymm(17));
    *src1 = x86(X86Reg::Ymm(18));
    *src2 = x86(X86Reg::Ymm(19));
    *width = VecWidth::V256;
    *pairs = 8;
    assert!(!is_x86_native_vector_op(&short_er));
}
#[test]
fn bmi_gate_and_feature_requirements_cover_exact_native_shapes() {
    let bextr_flags = FlagSet::CF.union(FlagSet::ZF).union(FlagSet::OF);
    let bzhi_flags = FlagSet::CF
        .union(FlagSet::ZF)
        .union(FlagSet::SF)
        .union(FlagSet::OF);
    let valid = [
        (
            OpKind::Bextr {
                dst: x86(X86Reg::Rax),
                src: x86(X86Reg::Rdx),
                control: x86(X86Reg::Rcx),
                width: OpWidth::W32,
                flags: FlagUpdate::Specific(bextr_flags),
            },
            (false, true, false, false, false),
        ),
        (
            OpKind::Bextr {
                dst: x86(X86Reg::R15),
                src: x86(X86Reg::R15),
                control: x86(X86Reg::R15),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
            (false, true, false, false, false),
        ),
        (
            OpKind::Bzhi {
                dst: x86(X86Reg::R8),
                src: x86(X86Reg::R9),
                index: x86(X86Reg::R10),
                width: OpWidth::W32,
                flags: FlagUpdate::Specific(bzhi_flags),
            },
            (true, false, false, false, false),
        ),
        (
            OpKind::Bzhi {
                dst: x86(X86Reg::R11),
                src: x86(X86Reg::R11),
                index: x86(X86Reg::R11),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
            (true, false, false, false, false),
        ),
        (
            OpKind::Bextr {
                dst: x86(X86Reg::Rsp),
                src: x86(X86Reg::Rbp),
                control: x86(X86Reg::R16),
                width: OpWidth::W64,
                flags: FlagUpdate::Specific(bextr_flags),
            },
            (false, true, false, false, false),
        ),
        (
            OpKind::Bzhi {
                dst: x86(X86Reg::R31),
                src: x86(X86Reg::R16),
                index: x86(X86Reg::Rsp),
                width: OpWidth::W32,
                flags: FlagUpdate::None,
            },
            (true, false, false, false, false),
        ),
        (
            OpKind::Pdep {
                dst: x86(X86Reg::R12),
                src: x86(X86Reg::R12),
                mask: x86(X86Reg::R13),
                width: OpWidth::W32,
            },
            (true, false, false, false, false),
        ),
        (
            OpKind::Pext {
                dst: x86(X86Reg::R14),
                src: x86(X86Reg::R15),
                mask: x86(X86Reg::R14),
                width: OpWidth::W64,
            },
            (true, false, false, false, false),
        ),
        (
            OpKind::Pdep {
                dst: x86(X86Reg::Rax),
                src: x86(X86Reg::Rdx),
                mask: x86(X86Reg::Rsp),
                width: OpWidth::W64,
            },
            (true, false, false, false, false),
        ),
        (
            OpKind::Pext {
                dst: x86(X86Reg::Rbp),
                src: x86(X86Reg::Rdx),
                mask: x86(X86Reg::Rcx),
                width: OpWidth::W64,
            },
            (true, false, false, false, false),
        ),
        (
            OpKind::Pdep {
                dst: x86(X86Reg::R16),
                src: x86(X86Reg::Rdx),
                mask: x86(X86Reg::Rcx),
                width: OpWidth::W32,
            },
            (true, false, false, false, false),
        ),
        (
            OpKind::Pext {
                dst: x86(X86Reg::R31),
                src: x86(X86Reg::Rsp),
                mask: x86(X86Reg::Rbp),
                width: OpWidth::W64,
            },
            (true, false, false, false, false),
        ),
    ];

    for (op, expected_features) in &valid {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
        builder.push_op(0x1000, op.clone());
        builder.set_terminator(Terminator::Return { values: vec![] });
        let func = builder.finish();
        assert!(op.is_jit_safe(), "{op:?} must be on the scalar whitelist");
        assert!(
            is_native_clobber_safe(&func),
            "{op:?} must pass the x86 gate"
        );
        assert_eq!(
            x86_native_scalar_feature_requirements_excluding(
                &func,
                &std::collections::HashMap::new()
            ),
            *expected_features,
            "{op:?} host feature requirement"
        );
    }
    assert_eq!(x86_flag_defs(&valid[0].0), bextr_flags);
    assert_eq!(x86_flag_defs(&valid[2].0), bzhi_flags);
    assert_eq!(x86_flag_defs(&valid[1].0), FlagSet::EMPTY);

    let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
    builder.push_op(0x1000, valid[0].0.clone());
    builder.push_op(0x1001, valid[2].0.clone());
    builder.set_terminator(Terminator::Return { values: vec![] });
    let func = builder.finish();
    let mut excluded = std::collections::HashMap::new();
    excluded.insert(func.entry, 0x1000);
    assert!(x86_native_scalar_features_supported_excluding(
        &func, &excluded
    ));
    #[cfg(target_arch = "x86_64")]
    assert_eq!(
        x86_native_scalar_features_supported_excluding(&func, &std::collections::HashMap::new()),
        std::is_x86_feature_detected!("bmi1") && std::is_x86_feature_detected!("bmi2")
    );
    #[cfg(not(target_arch = "x86_64"))]
    assert!(!x86_native_scalar_features_supported_excluding(
        &func,
        &std::collections::HashMap::new()
    ));

    for (name, op) in [
        (
            "BEXTR word width",
            OpKind::Bextr {
                dst: x86(X86Reg::Rax),
                src: x86(X86Reg::Rdx),
                control: x86(X86Reg::Rcx),
                width: OpWidth::W16,
                flags: FlagUpdate::Specific(bextr_flags),
            },
        ),
        (
            "BEXTR undefined flag request",
            OpKind::Bextr {
                dst: x86(X86Reg::Rax),
                src: x86(X86Reg::Rdx),
                control: x86(X86Reg::Rcx),
                width: OpWidth::W64,
                flags: FlagUpdate::All,
            },
        ),
        (
            "BZHI incomplete flag request",
            OpKind::Bzhi {
                dst: x86(X86Reg::Rax),
                src: x86(X86Reg::Rdx),
                index: x86(X86Reg::Rcx),
                width: OpWidth::W64,
                flags: FlagUpdate::Specific(FlagSet::ZF),
            },
        ),
        (
            "state-backed BEXTR word width",
            OpKind::Bextr {
                dst: x86(X86Reg::R16),
                src: x86(X86Reg::Rsp),
                control: x86(X86Reg::Rbp),
                width: OpWidth::W16,
                flags: FlagUpdate::None,
            },
        ),
        (
            "state-backed BZHI virtual source",
            OpKind::Bzhi {
                dst: x86(X86Reg::R31),
                src: VReg::Virtual(VirtualId(0)),
                index: x86(X86Reg::Rbp),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        ),
        (
            "state-backed BZHI incomplete flag request",
            OpKind::Bzhi {
                dst: x86(X86Reg::R31),
                src: x86(X86Reg::Rsp),
                index: x86(X86Reg::Rbp),
                width: OpWidth::W64,
                flags: FlagUpdate::Specific(FlagSet::ZF),
            },
        ),
        (
            "state-backed PDEP word width",
            OpKind::Pdep {
                dst: x86(X86Reg::R16),
                src: x86(X86Reg::Rsp),
                mask: x86(X86Reg::Rbp),
                width: OpWidth::W16,
            },
        ),
        (
            "state-backed PEXT virtual source",
            OpKind::Pext {
                dst: x86(X86Reg::R31),
                src: VReg::Virtual(VirtualId(0)),
                mask: x86(X86Reg::Rbp),
                width: OpWidth::W64,
            },
        ),
        (
            "PEXT virtual source",
            OpKind::Pext {
                dst: x86(X86Reg::Rax),
                src: VReg::Virtual(VirtualId(0)),
                mask: x86(X86Reg::Rcx),
                width: OpWidth::W64,
            },
        ),
        (
            "BZHI foreign index",
            OpKind::Bzhi {
                dst: x86(X86Reg::Rax),
                src: x86(X86Reg::Rdx),
                index: arm_x(0),
                width: OpWidth::W64,
                flags: FlagUpdate::Specific(bzhi_flags),
            },
        ),
    ] {
        assert!(
            op.is_jit_safe(),
            "malformed shape remains class-whitelisted"
        );
        assert!(!x86_gate(op), "malformed {name} must deopt");
    }

    let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
    builder.push_op(
        0x1000,
        OpKind::Pdep {
            dst: x86(X86Reg::R16),
            src: x86(X86Reg::Rsp),
            mask: x86(X86Reg::Rbp),
            width: OpWidth::W64,
        },
    );
    builder.set_terminator(Terminator::Return { values: vec![] });
    let mut hinted = builder.finish();
    hinted.blocks[0].ops[0].x86_hint = Some(X86OpHint::Mulx);
    assert!(
        !is_native_clobber_safe(&hinted),
        "hinted state-backed PDEP must fail closed"
    );

    let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
    builder.push_op(
        0x1000,
        OpKind::Bextr {
            dst: x86(X86Reg::R16),
            src: x86(X86Reg::Rsp),
            control: x86(X86Reg::Rbp),
            width: OpWidth::W64,
            flags: FlagUpdate::None,
        },
    );
    builder.set_terminator(Terminator::Return { values: vec![] });
    let mut hinted = builder.finish();
    hinted.blocks[0].ops[0].x86_hint = Some(X86OpHint::Mulx);
    assert!(
        !is_native_clobber_safe(&hinted),
        "hinted state-backed BEXTR must fail closed"
    );
}
#[test]
fn bswap_gate_accepts_native_and_state_backed_gpr_widths_and_rejects_unsafe_ir() {
    for op in [
        OpKind::Bswap {
            dst: x86(X86Reg::R8),
            src: x86(X86Reg::Rax),
            width: OpWidth::W16,
        },
        OpKind::Bswap {
            dst: x86(X86Reg::R9),
            src: x86(X86Reg::R9),
            width: OpWidth::W32,
        },
        OpKind::Bswap {
            dst: x86(X86Reg::R15),
            src: x86(X86Reg::R14),
            width: OpWidth::W64,
        },
        OpKind::Bswap {
            dst: x86(X86Reg::Rax),
            src: x86(X86Reg::Rsp),
            width: OpWidth::W64,
        },
        OpKind::Bswap {
            dst: x86(X86Reg::Rbp),
            src: x86(X86Reg::Rax),
            width: OpWidth::W64,
        },
        OpKind::Bswap {
            dst: x86(X86Reg::R16),
            src: x86(X86Reg::Rax),
            width: OpWidth::W32,
        },
        OpKind::Bswap {
            dst: x86(X86Reg::R31),
            src: x86(X86Reg::Rbp),
            width: OpWidth::W16,
        },
    ] {
        assert!(op.is_jit_safe());
        assert!(x86_gate(op));
    }

    for (name, op) in [
        (
            "byte width",
            OpKind::Bswap {
                dst: x86(X86Reg::Rax),
                src: x86(X86Reg::Rcx),
                width: OpWidth::W8,
            },
        ),
        (
            "virtual source",
            OpKind::Bswap {
                dst: x86(X86Reg::Rax),
                src: VReg::Virtual(VirtualId(0)),
                width: OpWidth::W64,
            },
        ),
        (
            "foreign architecture source",
            OpKind::Bswap {
                dst: x86(X86Reg::Rax),
                src: arm_x(0),
                width: OpWidth::W64,
            },
        ),
    ] {
        assert!(!x86_gate(op), "malformed {name} Bswap must deopt");
    }

    let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
    builder.push_op(
        0x1000,
        OpKind::Bswap {
            dst: x86(X86Reg::R16),
            src: x86(X86Reg::Rax),
            width: OpWidth::W64,
        },
    );
    builder.set_terminator(Terminator::Return { values: vec![] });
    let mut hinted = builder.finish();
    hinted.blocks[0].ops[0].x86_hint = Some(X86OpHint::Mulx);
    assert!(
        !is_native_clobber_safe(&hinted),
        "hinted state-backed Bswap must fail closed"
    );
}
#[test]
fn xchg_gate_accepts_native_and_state_backed_register_shapes_and_rejects_unsafe_ir() {
    for op in [
        OpKind::Xchg {
            reg1: x86(X86Reg::Rax),
            reg2: x86(X86Reg::R8),
            width: OpWidth::W8,
        },
        OpKind::Xchg {
            reg1: x86(X86Reg::Rax),
            reg2: x86(X86Reg::R8),
            width: OpWidth::W16,
        },
        OpKind::Xchg {
            reg1: x86(X86Reg::R9),
            reg2: x86(X86Reg::R9),
            width: OpWidth::W32,
        },
        OpKind::Xchg {
            reg1: x86(X86Reg::R15),
            reg2: x86(X86Reg::R14),
            width: OpWidth::W64,
        },
        OpKind::Xchg {
            reg1: x86(X86Reg::Rax),
            reg2: x86(X86Reg::Rsp),
            width: OpWidth::W8,
        },
        OpKind::Xchg {
            reg1: x86(X86Reg::Rax),
            reg2: x86(X86Reg::Rsp),
            width: OpWidth::W16,
        },
        OpKind::Xchg {
            reg1: x86(X86Reg::Rbp),
            reg2: x86(X86Reg::R16),
            width: OpWidth::W32,
        },
        OpKind::Xchg {
            reg1: x86(X86Reg::R31),
            reg2: x86(X86Reg::R31),
            width: OpWidth::W64,
        },
    ] {
        assert!(op.is_jit_safe());
        assert!(x86_gate(op));
    }

    for (name, op) in [
        (
            "vector width",
            OpKind::Xchg {
                reg1: x86(X86Reg::Rax),
                reg2: x86(X86Reg::Rcx),
                width: OpWidth::W128,
            },
        ),
        (
            "virtual register",
            OpKind::Xchg {
                reg1: x86(X86Reg::Rax),
                reg2: VReg::Virtual(VirtualId(0)),
                width: OpWidth::W64,
            },
        ),
        (
            "foreign architecture register",
            OpKind::Xchg {
                reg1: x86(X86Reg::Rax),
                reg2: arm_x(0),
                width: OpWidth::W64,
            },
        ),
    ] {
        assert!(!x86_gate(op), "malformed {name} Xchg must deopt");
    }

    let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
    builder.push_op(
        0x1000,
        OpKind::Xchg {
            reg1: x86(X86Reg::R16),
            reg2: x86(X86Reg::Rax),
            width: OpWidth::W64,
        },
    );
    builder.set_terminator(Terminator::Return { values: vec![] });
    let mut hinted = builder.finish();
    hinted.blocks[0].ops[0].x86_hint = Some(X86OpHint::Mulx);
    assert!(
        !is_native_clobber_safe(&hinted),
        "hinted state-backed Xchg must fail closed"
    );
}
#[test]
fn clobber_gate_rejects_flag_preserving_x86_native_flag_clobber_ops() {
    for (name, op) in [
        (
            "adc",
            OpKind::Adc {
                dst: x86(X86Reg::Rax),
                src1: x86(X86Reg::Rax),
                src2: SrcOperand::Reg(x86(X86Reg::Rcx)),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        ),
        (
            "sbb",
            OpKind::Sbb {
                dst: x86(X86Reg::Rax),
                src1: x86(X86Reg::Rax),
                src2: SrcOperand::Reg(x86(X86Reg::Rcx)),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        ),
        (
            "shld",
            OpKind::Shld {
                dst: x86(X86Reg::Rax),
                src: x86(X86Reg::Rdx),
                amount: SrcOperand::Reg(x86(X86Reg::Rcx)),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        ),
        (
            "shrd",
            OpKind::Shrd {
                dst: x86(X86Reg::Rax),
                src: x86(X86Reg::Rdx),
                amount: SrcOperand::Reg(x86(X86Reg::Rcx)),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
        ),
    ] {
        assert!(op.is_jit_safe(), "{name} remains on the generic whitelist");
        assert!(
            !x86_gate(op),
            "{name} must preserve guest flags by deopting"
        );
    }
}
#[test]
fn clobber_gate_allows_dead_flag_preserving_x86_native_flag_clobber_ops() {
    let mut b = FunctionBuilder::new(FunctionId(0), 0x1000);
    b.push_op(
        0x1000,
        OpKind::Add {
            dst: x86(X86Reg::Rax),
            src1: x86(X86Reg::Rax),
            src2: SrcOperand::Imm(1),
            width: OpWidth::W64,
            flags: FlagUpdate::None,
        },
    );
    b.push_op(
        0x1003,
        OpKind::Cmp {
            src1: x86(X86Reg::Rcx),
            src2: SrcOperand::Imm(0),
            width: OpWidth::W64,
        },
    );
    b.set_terminator(Terminator::Return { values: vec![] });

    assert!(
        is_native_clobber_safe(&b.finish()),
        "a later flag definition kills the exit live set, so the dead flag-preserving add can run natively"
    );
}
#[test]
fn clobber_gate_allows_live_flags_across_natively_preserved_binary_alu() {
    let mut b = FunctionBuilder::new(FunctionId(0), 0x1000);
    b.push_op(
        0x1000,
        OpKind::Cmp {
            src1: x86(X86Reg::Rcx),
            src2: SrcOperand::Imm(0),
            width: OpWidth::W64,
        },
    );
    b.push_op(
        0x1003,
        OpKind::Add {
            dst: x86(X86Reg::Rax),
            src1: x86(X86Reg::Rax),
            src2: SrcOperand::Imm(1),
            width: OpWidth::W64,
            flags: FlagUpdate::None,
        },
    );
    b.push_op(
        0x1006,
        OpKind::SetCC {
            dst: x86(X86Reg::Rbx),
            cond: crate::smir::ir::types::Condition::Eq,
            width: OpWidth::W64,
        },
    );
    b.set_terminator(Terminator::Return { values: vec![] });

    assert!(
        is_native_clobber_safe(&b.finish()),
        "the lowerer now preserves flags across ADD flags=None before setcc"
    );
}
