//! Fail-closed admission and ABI tests for state-backed x87 environment operations.

use super::*;
use crate::smir::ir::ops::X86X87DataKind;
use crate::smir::lower::runtime::{
    GuestRegs, uses_x86_x87_environment_state_excluding, uses_x86_x87_tag_state_excluding,
};
use crate::smir::lower::{
    X86_GUEST_STACK_FLAGS_RFLAGS_VALID_OFFSET, X86_GUEST_X87_CONTROL_WORD_OFFSET,
    X86_GUEST_X87_DATA_PTR_OFFSET, X86_GUEST_X87_INSTR_PTR_OFFSET,
    X86_GUEST_X87_LAST_OPCODE_OFFSET, X86_GUEST_X87_PAYLOAD_ACTIVE_OFFSET,
    X86_GUEST_X87_PAYLOAD_OFFSET, X86_GUEST_X87_STATE_ACTIVE_OFFSET,
    X86_GUEST_X87_STATUS_WORD_OFFSET,
};

fn control(kind: X86X87ControlKind) -> OpKind {
    OpKind::X86X87Control { kind, addr: None }
}

fn metadata(kind: X86X87DataKind, st: u8, fop: u16) -> OpKind {
    OpKind::X86X87Data {
        kind,
        addr: None,
        st,
        fop,
    }
}

fn stack_metadata_forms() -> Vec<OpKind> {
    let mut forms = vec![
        metadata(X86X87DataKind::DecrementTop, 6, 0x01F6),
        metadata(X86X87DataKind::IncrementTop, 7, 0x01F7),
    ];
    for st in 0..8 {
        forms.push(metadata(X86X87DataKind::Free, st, 0x05C0 + u16::from(st)));
        forms.push(metadata(
            X86X87DataKind::FreePop,
            st,
            0x07C0 + u16::from(st),
        ));
    }
    forms
}

fn x86_aarch64_gate(op: OpKind) -> bool {
    let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
    builder.push_op(0x1000, op);
    builder.set_terminator(Terminator::Return { values: vec![] });
    is_x86_aarch64_native_clobber_safe_excluding(
        &builder.finish(),
        &std::collections::HashMap::new(),
    )
}

#[test]
fn x87_no_wait_environment_controls_are_narrowly_x86_native_safe() {
    for kind in [
        X86X87ControlKind::Init,
        X86X87ControlKind::ClearExceptions,
        X86X87ControlKind::StoreStatusAx,
    ] {
        let op = control(kind);
        assert!(op.is_jit_safe(), "{kind:?}");
        assert!(x86_gate(op.clone()), "x86-64 gate rejected {kind:?}");
        assert!(
            !aarch64_gate(vec![op], false),
            "AArch64 guest-state ABI admitted x87 {kind:?}"
        );
    }

    for kind in [
        X86X87ControlKind::LoadControlWord,
        X86X87ControlKind::StoreControlWord,
        X86X87ControlKind::StoreStatusWord,
        X86X87ControlKind::LoadEnvironment(crate::smir::ir::ops::X86X87EnvWidth::W32),
        X86X87ControlKind::StoreEnvironment(crate::smir::ir::ops::X86X87EnvWidth::W32),
        X86X87ControlKind::RestoreState(crate::smir::ir::ops::X86X87EnvWidth::W32),
        X86X87ControlKind::SaveState(crate::smir::ir::ops::X86X87EnvWidth::W32),
    ] {
        let op = control(kind);
        assert!(!op.is_jit_safe(), "payload/memory x87 {kind:?}");
        assert!(!x86_gate(op), "x86-64 gate admitted {kind:?}");
    }
}

#[test]
fn x87_stack_metadata_shapes_are_narrowly_x86_native_safe() {
    for op in stack_metadata_forms() {
        assert!(op.is_jit_safe(), "exact shape: {op:?}");
        assert!(x86_gate(op.clone()), "x86-64 gate rejected {op:?}");
        assert!(
            !aarch64_gate(vec![op.clone()], false),
            "AArch64 guest-state ABI admitted {op:?}"
        );
        assert!(
            !x86_aarch64_gate(op.clone()),
            "x86-on-AArch64 bridge admitted {op:?}"
        );
    }

    let addressed_free = OpKind::X86X87Data {
        kind: X86X87DataKind::Free,
        addr: Some(Address::Direct(x86(X86Reg::Rax))),
        st: 3,
        fop: 0x05C3,
    };
    for op in [
        metadata(X86X87DataKind::Free, 8, 0x05C8),
        metadata(X86X87DataKind::Free, 3, 0x05C2),
        metadata(X86X87DataKind::FreePop, 3, 0x07C2),
        metadata(X86X87DataKind::DecrementTop, 0, 0x01F6),
        metadata(X86X87DataKind::IncrementTop, 7, 0x01F6),
        metadata(X86X87DataKind::LoadRegister, 0, 0x01C0),
        addressed_free,
    ] {
        assert!(!op.is_jit_safe(), "malformed/unsupported shape: {op:?}");
        assert!(!x86_gate(op.clone()), "x86-64 gate admitted {op:?}");
        assert!(!aarch64_gate(vec![op.clone()], false));
        assert!(!x86_aarch64_gate(op));
    }

    let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
    builder.push_op(0x1000, metadata(X86X87DataKind::FreePop, 3, 0x07C3));
    builder.set_terminator(Terminator::Return { values: vec![] });
    let mut hinted = builder.finish();
    hinted.blocks[0].ops[0].x86_hint = Some(X86OpHint::RexByteReg);
    assert!(!hinted.blocks[0].ops[0].is_jit_safe());
    assert!(!is_native_clobber_safe(&hinted));
}

#[test]
fn x87_sign_payload_shapes_are_narrowly_x86_native_safe() {
    for op in [
        metadata(X86X87DataKind::ChangeSign, 0, 0x01E0),
        metadata(X86X87DataKind::Absolute, 1, 0x01E1),
    ] {
        assert!(op.is_jit_safe(), "exact shape: {op:?}");
        assert!(x86_gate(op.clone()), "x86-64 gate rejected {op:?}");
        assert!(!aarch64_gate(vec![op.clone()], false));
        assert!(!x86_aarch64_gate(op));
    }

    for op in [
        metadata(X86X87DataKind::ChangeSign, 1, 0x01E0),
        metadata(X86X87DataKind::ChangeSign, 0, 0x01E1),
        metadata(X86X87DataKind::Absolute, 0, 0x01E1),
        metadata(X86X87DataKind::Absolute, 1, 0x01E0),
        OpKind::X86X87Data {
            kind: X86X87DataKind::Absolute,
            addr: Some(Address::Direct(x86(X86Reg::Rax))),
            st: 1,
            fop: 0x01E1,
        },
    ] {
        assert!(!op.is_jit_safe(), "malformed shape: {op:?}");
        assert!(!x86_gate(op.clone()));
        assert!(!aarch64_gate(vec![op.clone()], false));
        assert!(!x86_aarch64_gate(op));
    }
}

#[test]
fn x87_register_store_shapes_require_exact_register_encoding_and_x86_host() {
    for (kind, base) in [
        (X86X87DataKind::StoreRegister, 0x05D0),
        (X86X87DataKind::StorePopRegister, 0x05D8),
        (X86X87DataKind::StorePopRegister, 0x07D0),
    ] {
        for st in 0..8 {
            let op = metadata(kind, st, base + u16::from(st));
            assert!(op.is_jit_safe());
            assert!(x86_gate(op.clone()));
            assert!(!aarch64_gate(vec![op.clone()], false));
            assert!(!x86_aarch64_gate(op));
            for invalid in [
                metadata(kind, 8, base + 8),
                metadata(kind, st, base ^ 0x0100),
            ] {
                assert!(!invalid.is_jit_safe());
                assert!(!x86_gate(invalid.clone()));
                assert!(!aarch64_gate(vec![invalid.clone()], false));
                assert!(!x86_aarch64_gate(invalid));
            }
        }
    }
}

#[test]
fn x87_environment_detector_honors_native_exit_exclusion() {
    for (index, kind) in [
        X86X87ControlKind::Init,
        X86X87ControlKind::ClearExceptions,
        X86X87ControlKind::StoreStatusAx,
    ]
    .into_iter()
    .enumerate()
    {
        let mut builder = FunctionBuilder::new(FunctionId(index as u32), 0x1000);
        builder.push_op(0x1000, control(kind));
        builder.set_terminator(Terminator::Return { values: vec![] });
        let function = builder.finish();
        assert!(uses_x86_x87_environment_state_excluding(
            &function,
            &std::collections::HashMap::new()
        ));
        assert!(!uses_x86_x87_tag_state_excluding(
            &function,
            &std::collections::HashMap::new()
        ));
        assert!(!uses_x86_x87_environment_state_excluding(
            &function,
            &std::collections::HashMap::from([(function.entry, 0x1002)])
        ));
    }
}

#[test]
fn x87_stack_metadata_environment_detector_honors_native_exit_exclusion() {
    for (index, op) in stack_metadata_forms().into_iter().enumerate() {
        let mut builder = FunctionBuilder::new(FunctionId(index as u32), 0x1000);
        builder.push_op(0x1000, op.clone());
        builder.set_terminator(Terminator::Return { values: vec![] });
        let function = builder.finish();
        assert!(
            uses_x86_x87_environment_state_excluding(&function, &std::collections::HashMap::new()),
            "{op:?}"
        );
        assert!(!uses_x86_x87_environment_state_excluding(
            &function,
            &std::collections::HashMap::from([(function.entry, 0x1002)])
        ));
    }
}

#[test]
fn x87_sign_payload_environment_detector_honors_native_exit_exclusion() {
    for (index, op) in [
        metadata(X86X87DataKind::ChangeSign, 0, 0x01E0),
        metadata(X86X87DataKind::Absolute, 1, 0x01E1),
    ]
    .into_iter()
    .enumerate()
    {
        let mut builder = FunctionBuilder::new(FunctionId(index as u32), 0x1000);
        builder.push_op(0x1000, op.clone());
        builder.set_terminator(Terminator::Return { values: vec![] });
        let function = builder.finish();
        assert!(
            uses_x86_x87_environment_state_excluding(&function, &std::collections::HashMap::new()),
            "{op:?}"
        );
        assert!(!uses_x86_x87_environment_state_excluding(
            &function,
            &std::collections::HashMap::from([(function.entry, 0x1002)])
        ));
    }
}

#[test]
fn x87_environment_and_payload_abi_is_append_only_and_exact() {
    for (actual, expected) in [
        (
            std::mem::offset_of!(GuestRegs, x87_control_word),
            X86_GUEST_X87_CONTROL_WORD_OFFSET as usize,
        ),
        (
            std::mem::offset_of!(GuestRegs, x87_status_word),
            X86_GUEST_X87_STATUS_WORD_OFFSET as usize,
        ),
        (
            std::mem::offset_of!(GuestRegs, x87_data_ptr),
            X86_GUEST_X87_DATA_PTR_OFFSET as usize,
        ),
        (
            std::mem::offset_of!(GuestRegs, x87_instr_ptr),
            X86_GUEST_X87_INSTR_PTR_OFFSET as usize,
        ),
        (
            std::mem::offset_of!(GuestRegs, x87_last_opcode),
            X86_GUEST_X87_LAST_OPCODE_OFFSET as usize,
        ),
        (
            std::mem::offset_of!(GuestRegs, x87_state_active),
            X86_GUEST_X87_STATE_ACTIVE_OFFSET as usize,
        ),
        (
            std::mem::offset_of!(GuestRegs, x87_payload),
            X86_GUEST_X87_PAYLOAD_OFFSET as usize,
        ),
        (
            std::mem::offset_of!(GuestRegs, x87_payload_active),
            X86_GUEST_X87_PAYLOAD_ACTIVE_OFFSET as usize,
        ),
    ] {
        assert_eq!(actual, expected);
    }
    assert_eq!(
        X86_GUEST_X87_CONTROL_WORD_OFFSET,
        X86_GUEST_STACK_FLAGS_RFLAGS_VALID_OFFSET + 8
    );
    assert_eq!(
        X86_GUEST_X87_STATE_ACTIVE_OFFSET,
        X86_GUEST_X87_CONTROL_WORD_OFFSET + 5 * 8
    );
    assert_eq!(
        X86_GUEST_X87_PAYLOAD_OFFSET,
        X86_GUEST_X87_STATE_ACTIVE_OFFSET + 8
    );
    assert_eq!(
        X86_GUEST_X87_PAYLOAD_ACTIVE_OFFSET,
        X86_GUEST_X87_PAYLOAD_OFFSET + 8 * 8
    );

    let defaults = GuestRegs::default();
    assert_eq!(defaults.x87_control_word, 0x037F);
    assert_eq!(defaults.x87_status_word, 0);
    assert_eq!(defaults.x87_tag_word, 0xFFFF);
    assert_eq!(defaults.x87_data_ptr, 0);
    assert_eq!(defaults.x87_instr_ptr, 0);
    assert_eq!(defaults.x87_last_opcode, 0);
    assert_eq!(defaults.x87_state_active, 0);
    assert_eq!(defaults.x87_payload, [0; 8]);
    assert_eq!(defaults.x87_payload_active, 0);
}
