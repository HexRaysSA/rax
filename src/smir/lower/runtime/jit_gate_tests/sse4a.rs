//! Fail-closed native admission for AMD SSE4A state-backed operations.

use super::*;
use crate::smir::ir::ops::{OpKind, SmirOp, X86OpHint, X86Sse4aBitfieldKind};
use crate::smir::ir::types::{
    Address, ArchReg, FunctionId, MemWidth, OpId, VReg, VirtualId, X86Reg,
};
use crate::smir::ir::{FunctionBuilder, Terminator};
use crate::smir::lower::runtime::GuestRegs;
use crate::smir::lower::x86_64::{
    x86_require_sse4a_shape_valid, x86_sse4a_bitfield_shape_valid,
    x86_sse4a_movnt_store_shape_valid,
};

fn xmm(index: u8) -> VReg {
    VReg::Arch(ArchReg::X86(X86Reg::Xmm(index)))
}

fn bitfield(
    dst: VReg,
    source: VReg,
    kind: X86Sse4aBitfieldKind,
    length: Option<u8>,
    index: Option<u8>,
) -> OpKind {
    OpKind::X86Sse4aBitfield {
        dst,
        source,
        kind,
        length,
        index,
    }
}

fn movnt(src: VReg, addr: Address, width: MemWidth) -> OpKind {
    OpKind::X86Sse4aMovntStore { src, addr, width }
}

fn function_with(kind: OpKind) -> crate::smir::ir::SmirFunction {
    let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
    builder.push_op(0x1000, kind);
    builder.set_terminator(Terminator::Return { values: vec![] });
    builder.finish()
}

fn x86_gate_with_mem(kind: OpKind, allow_mem: bool) -> bool {
    is_native_clobber_safe_excluding(
        &function_with(kind),
        &std::collections::HashMap::new(),
        allow_mem,
    )
}

#[test]
fn sse4a_gates_admit_exact_x86_shapes_and_reject_both_aarch64_paths() {
    let guard = SmirOp::new(OpId(0), 0x1000, OpKind::X86RequireSse4a);
    assert!(guard.kind.is_jit_safe());
    assert!(guard.is_jit_safe());
    assert!(x86_require_sse4a_shape_valid(&guard));
    assert!(x86_gate(OpKind::X86RequireSse4a));
    assert!(!aarch64_gate(vec![OpKind::X86RequireSse4a], false));
    assert!(!x86_aarch64_gate(vec![OpKind::X86RequireSse4a]));

    for kind in [
        bitfield(
            xmm(1),
            xmm(1),
            X86Sse4aBitfieldKind::Extract,
            Some(8),
            Some(4),
        ),
        bitfield(xmm(1), xmm(2), X86Sse4aBitfieldKind::Extract, None, None),
        bitfield(
            xmm(1),
            xmm(2),
            X86Sse4aBitfieldKind::Insert,
            Some(8),
            Some(4),
        ),
        bitfield(xmm(1), xmm(2), X86Sse4aBitfieldKind::Insert, None, None),
    ] {
        let op = SmirOp::new(OpId(0), 0x1000, kind.clone());
        assert!(op.kind.is_jit_safe(), "{op:?}");
        assert!(op.is_jit_safe(), "{op:?}");
        assert!(x86_sse4a_bitfield_shape_valid(&op), "{op:?}");
        assert!(x86_gate(kind.clone()), "{op:?}");
        assert!(!aarch64_gate(vec![kind.clone()], false), "{op:?}");
        assert!(!x86_aarch64_gate(vec![kind]), "{op:?}");
    }
}

#[test]
fn sse4a_gate_rejects_malformed_operands_controls_and_hints() {
    for (name, kind) in [
        (
            "virtual destination",
            bitfield(
                VReg::Virtual(VirtualId(0)),
                xmm(1),
                X86Sse4aBitfieldKind::Insert,
                None,
                None,
            ),
        ),
        (
            "extended XMM",
            bitfield(xmm(16), xmm(1), X86Sse4aBitfieldKind::Insert, None, None),
        ),
        (
            "unpaired controls",
            bitfield(xmm(1), xmm(1), X86Sse4aBitfieldKind::Extract, Some(8), None),
        ),
        (
            "out-of-range length",
            bitfield(
                xmm(1),
                xmm(1),
                X86Sse4aBitfieldKind::Extract,
                Some(64),
                Some(0),
            ),
        ),
        (
            "immediate EXTRQ source mismatch",
            bitfield(
                xmm(1),
                xmm(2),
                X86Sse4aBitfieldKind::Extract,
                Some(8),
                Some(4),
            ),
        ),
    ] {
        let op = SmirOp::new(OpId(0), 0x1000, kind.clone());
        assert!(!x86_sse4a_bitfield_shape_valid(&op), "{name}");
        assert!(!x86_gate(kind), "{name}");
    }

    for kind in [
        OpKind::X86RequireSse4a,
        bitfield(xmm(1), xmm(2), X86Sse4aBitfieldKind::Insert, None, None),
    ] {
        let mut function = function_with(kind);
        function.blocks[0].ops[0].x86_hint = Some(X86OpHint::RexByteReg);
        assert!(!is_native_clobber_safe(&function));
    }
}

#[test]
fn sse4a_movnt_gate_requires_memory_mode_and_exact_shape() {
    for kind in [
        movnt(xmm(0), Address::Absolute(0x2000), MemWidth::B4),
        movnt(
            xmm(15),
            Address::Direct(VReg::Arch(ArchReg::X86(X86Reg::Rax))),
            MemWidth::B8,
        ),
    ] {
        let op = SmirOp::new(OpId(0), 0x1000, kind.clone());
        assert!(!op.kind.is_jit_safe(), "custom memory gate is mandatory");
        assert!(!op.is_jit_safe(), "custom memory gate is mandatory");
        assert!(x86_sse4a_movnt_store_shape_valid(&op), "{op:?}");
        assert!(!x86_gate_with_mem(kind.clone(), false), "{op:?}");
        assert!(x86_gate_with_mem(kind.clone(), true), "{op:?}");
        assert!(!aarch64_gate(vec![kind.clone()], true), "{op:?}");
        assert!(!x86_aarch64_gate(vec![kind]), "{op:?}");
    }

    for (name, kind) in [
        (
            "virtual source",
            movnt(
                VReg::Virtual(VirtualId(0)),
                Address::Absolute(0x2000),
                MemWidth::B4,
            ),
        ),
        (
            "unencodable XMM",
            movnt(xmm(16), Address::Absolute(0x2000), MemWidth::B8),
        ),
        (
            "invalid width",
            movnt(xmm(1), Address::Absolute(0x2000), MemWidth::B2),
        ),
        (
            "non-x86 GP-relative address",
            movnt(xmm(1), Address::GpRel { offset: 0 }, MemWidth::B4),
        ),
    ] {
        assert!(!x86_gate_with_mem(kind, true), "{name}");
    }

    let mut hinted = function_with(movnt(xmm(1), Address::Absolute(0x2000), MemWidth::B4));
    hinted.blocks[0].ops[0].x86_hint = Some(X86OpHint::RexByteReg);
    assert!(!is_native_clobber_safe_excluding(
        &hinted,
        &std::collections::HashMap::new(),
        true,
    ));
}

#[test]
fn sse4a_state_detection_layout_and_o2_retention_are_exact() {
    assert_eq!(GuestRegs::default().xmm_state_active, 0);
    assert_eq!(GuestRegs::default().mxcsr_state_active, 0);
    assert_eq!(GuestRegs::default().vector_scratch, [0; 8]);
    assert_eq!(
        std::mem::offset_of!(GuestRegs, xmm_state_active),
        std::mem::offset_of!(GuestRegs, umwait_control) + std::mem::size_of::<u64>()
    );
    assert_eq!(
        std::mem::offset_of!(GuestRegs, mxcsr_state_active),
        std::mem::offset_of!(GuestRegs, xmm_state_active) + std::mem::size_of::<u64>()
    );
    assert_eq!(
        std::mem::offset_of!(GuestRegs, vector_scratch),
        std::mem::offset_of!(GuestRegs, mxcsr_state_active) + std::mem::size_of::<u64>()
    );
    let scratch_end =
        std::mem::offset_of!(GuestRegs, vector_scratch) + std::mem::size_of::<[u64; 8]>();
    assert_eq!(std::mem::offset_of!(GuestRegs, cpuid_tbm), scratch_end);
    assert_eq!(
        std::mem::offset_of!(GuestRegs, cpuid_xop),
        std::mem::offset_of!(GuestRegs, cpuid_tbm) + std::mem::size_of::<u64>()
    );
    assert_eq!(
        std::mem::offset_of!(GuestRegs, x86_vsib_frontier_lane_plus_one),
        crate::smir::lower::X86_GUEST_VSIB_FRONTIER_LANE_PLUS_ONE_OFFSET as usize
    );
    assert_eq!(GuestRegs::default().x86_vsib_frontier_lane_plus_one, 0);
    assert_eq!(
        std::mem::offset_of!(GuestRegs, x86_vsib_instruction_ordinal),
        crate::smir::lower::X86_GUEST_VSIB_INSTRUCTION_ORDINAL_OFFSET as usize
    );
    assert_eq!(GuestRegs::default().x86_vsib_instruction_ordinal, 0);
    let field_end =
        std::mem::offset_of!(GuestRegs, x86_vsib_instruction_ordinal) + std::mem::size_of::<u64>();
    assert!(field_end <= std::mem::size_of::<GuestRegs>());
    assert!(
        std::mem::size_of::<GuestRegs>() - field_end < std::mem::align_of::<GuestRegs>(),
        "only trailing repr(C) alignment padding may follow append-only VSIB metadata"
    );

    let mut function = function_with(bitfield(
        xmm(1),
        xmm(2),
        X86Sse4aBitfieldKind::Insert,
        None,
        None,
    ));
    let excluded = std::collections::HashMap::new();
    assert!(uses_x86_xmm_state_excluding(&function, &excluded));

    let mut excluded_entry = std::collections::HashMap::new();
    excluded_entry.insert(function.entry, 0x1000);
    assert!(!uses_x86_xmm_state_excluding(&function, &excluded_entry));

    function.blocks[0]
        .ops
        .insert(0, SmirOp::new(OpId(1), 0x1000, OpKind::X86RequireSse4a));
    crate::smir::optimize::optimize_function(&mut function, crate::smir::optimize::OptLevel::O2);
    assert!(matches!(
        function.entry_block().unwrap().ops.as_slice(),
        [
            SmirOp {
                kind: OpKind::X86RequireSse4a,
                ..
            },
            SmirOp {
                kind: OpKind::X86Sse4aBitfield { .. },
                ..
            }
        ]
    ));
    assert!(is_native_clobber_safe(&function));

    let mut movnt_function = function_with(movnt(xmm(9), Address::Absolute(0x2000), MemWidth::B8));
    assert!(uses_x86_xmm_state_excluding(&movnt_function, &excluded));
    assert!(x86_jit_op_uses_mem_helper(
        &movnt_function.blocks[0].ops[0].kind
    ));
    movnt_function.blocks[0]
        .ops
        .insert(0, SmirOp::new(OpId(2), 0x1000, OpKind::X86RequireSse4a));
    crate::smir::optimize::optimize_function(
        &mut movnt_function,
        crate::smir::optimize::OptLevel::O2,
    );
    assert!(matches!(
        movnt_function.entry_block().unwrap().ops.as_slice(),
        [
            SmirOp {
                kind: OpKind::X86RequireSse4a,
                ..
            },
            SmirOp {
                kind: OpKind::X86Sse4aMovntStore { .. },
                ..
            }
        ]
    ));
    assert!(is_native_clobber_safe_excluding(
        &movnt_function,
        &excluded,
        true,
    ));
}

#[test]
fn sse4a_side_effect_metadata_distinguishes_fault_guard_from_data_transform() {
    assert!(OpKind::X86RequireSse4a.has_side_effects());
    assert!(
        !bitfield(
            xmm(1),
            xmm(1),
            X86Sse4aBitfieldKind::Extract,
            Some(8),
            Some(4),
        )
        .has_side_effects()
    );
    let movnt = movnt(xmm(1), Address::Absolute(0x2000), MemWidth::B4);
    assert!(movnt.has_side_effects());
    assert!(movnt.writes_memory());
}
