//! State-backed native lowering tests for x87 environment operations.

use super::*;
use crate::smir::ir::ops::X86X87DataKind;
use crate::smir::lower::{
    X86_GUEST_CR0_OFFSET, X86_GUEST_X87_CONTROL_WORD_OFFSET, X86_GUEST_X87_PAYLOAD_HIGH_OFFSET,
    X86_GUEST_X87_STATUS_WORD_OFFSET, X86_GUEST_X87_TAG_WORD_OFFSET,
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

fn lower(
    kind: OpKind,
    fault_guards: bool,
    hint: Option<X86OpHint>,
) -> Result<(Vec<u8>, usize), LowerError> {
    let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
    builder.push_op(0x1000, kind);
    builder.set_terminator(Terminator::Return { values: vec![] });
    let mut function = builder.finish();
    function.blocks[0].ops[0].x86_hint = hint;
    let mut lowerer = X86_64Lowerer::new();
    lowerer.set_jit_fault_deopt_guards(fault_guards);
    let lowered = lowerer.lower_function(&function)?;
    assert!(lowered.relocations.is_empty());
    Ok((lowerer.finalize()?, lowered.entry_offset))
}

#[test]
fn lower_x87_no_wait_controls_require_dynamic_fault_guards_and_exact_state_slots() {
    for kind in [
        X86X87ControlKind::Init,
        X86X87ControlKind::ClearExceptions,
        X86X87ControlKind::StoreStatusAx,
    ] {
        assert!(matches!(
            lower(control(kind), false, None),
            Err(LowerError::UnsupportedOp { .. })
        ));
        let (code, _) = lower(control(kind), true, None).expect("guarded x87 control");
        assert!(
            code.windows(4)
                .any(|window| window == (X86_GUEST_CR0_OFFSET as u32).to_le_bytes()),
            "{kind:?}: missing dynamic CR0 guard: {code:02X?}"
        );
        let state_offset = match kind {
            X86X87ControlKind::Init => X86_GUEST_X87_CONTROL_WORD_OFFSET,
            X86X87ControlKind::ClearExceptions | X86X87ControlKind::StoreStatusAx => {
                X86_GUEST_X87_STATUS_WORD_OFFSET
            }
            _ => unreachable!(),
        };
        assert!(
            code.windows(4)
                .any(|window| window == (state_offset as u32).to_le_bytes()),
            "{kind:?}: missing x87 state slot: {code:02X?}"
        );
    }

    let (init, _) = lower(control(X86X87ControlKind::Init), true, None).unwrap();
    assert!(
        init.windows(4)
            .any(|window| window == (X86_GUEST_X87_TAG_WORD_OFFSET as u32).to_le_bytes())
    );
}

#[test]
fn lower_x87_controls_reject_non_lifter_shapes_fail_closed() {
    let malformed_address = OpKind::X86X87Control {
        kind: X86X87ControlKind::Init,
        addr: Some(Address::PcRel {
            offset: 0,
            disp_size: DispSize::Disp32,
            base: Some(0x1002),
        }),
    };
    assert!(matches!(
        lower(malformed_address, true, None),
        Err(LowerError::InvalidOperand { .. })
    ));
    assert!(matches!(
        lower(
            control(X86X87ControlKind::ClearExceptions),
            true,
            Some(X86OpHint::RexByteReg),
        ),
        Err(LowerError::InvalidOperand { .. })
    ));

    for kind in [
        X86X87ControlKind::LoadControlWord,
        X86X87ControlKind::StoreControlWord,
        X86X87ControlKind::StoreStatusWord,
    ] {
        assert!(matches!(
            lower(control(kind), true, None),
            Err(LowerError::UnsupportedOp { .. })
        ));
    }
}

#[test]
fn lower_x87_stack_metadata_requires_waiting_guards_and_exact_state_slots() {
    for op in [
        metadata(X86X87DataKind::DecrementTop, 6, 0x01F6),
        metadata(X86X87DataKind::IncrementTop, 7, 0x01F7),
        metadata(X86X87DataKind::Free, 3, 0x05C3),
        metadata(X86X87DataKind::FreePop, 3, 0x07C3),
    ] {
        assert!(matches!(
            lower(op.clone(), false, None),
            Err(LowerError::UnsupportedOp { .. })
        ));
        let (code, _) = lower(op.clone(), true, None).expect("guarded x87 stack metadata");
        for offset in [
            X86_GUEST_CR0_OFFSET,
            X86_GUEST_X87_STATUS_WORD_OFFSET,
            crate::smir::lower::X86_GUEST_X87_INSTR_PTR_OFFSET,
            crate::smir::lower::X86_GUEST_X87_LAST_OPCODE_OFFSET,
        ] {
            assert!(
                code.windows(4)
                    .any(|window| window == (offset as u32).to_le_bytes()),
                "{op:?}: missing state offset {offset}: {code:02X?}"
            );
        }
        if matches!(
            op,
            OpKind::X86X87Data {
                kind: X86X87DataKind::Free | X86X87DataKind::FreePop,
                ..
            }
        ) {
            assert!(
                code.windows(4).any(|window| {
                    window == (X86_GUEST_X87_TAG_WORD_OFFSET as u32).to_le_bytes()
                })
            );
        }
    }
}

#[test]
fn lower_x87_stack_metadata_rejects_every_malformed_shape() {
    for op in [
        metadata(X86X87DataKind::Free, 8, 0x05C8),
        metadata(X86X87DataKind::Free, 3, 0x05C2),
        metadata(X86X87DataKind::FreePop, 3, 0x07C2),
        metadata(X86X87DataKind::DecrementTop, 0, 0x01F6),
        metadata(X86X87DataKind::IncrementTop, 7, 0x01F6),
    ] {
        assert!(matches!(
            lower(op, true, None),
            Err(LowerError::InvalidOperand { .. })
        ));
    }
    assert!(matches!(
        lower(
            metadata(X86X87DataKind::Free, 3, 0x05C3),
            true,
            Some(X86OpHint::RexByteReg),
        ),
        Err(LowerError::InvalidOperand { .. })
    ));
}

#[test]
fn lower_x87_sign_payload_requires_waiting_guards_and_exact_state_slots() {
    for op in [
        metadata(X86X87DataKind::ChangeSign, 0, 0x01E0),
        metadata(X86X87DataKind::Absolute, 1, 0x01E1),
    ] {
        assert!(matches!(
            lower(op.clone(), false, None),
            Err(LowerError::UnsupportedOp { .. })
        ));
        let (code, _) = lower(op.clone(), true, None).expect("guarded x87 sign operation");
        for offset in [
            X86_GUEST_CR0_OFFSET,
            X86_GUEST_X87_STATUS_WORD_OFFSET,
            X86_GUEST_X87_TAG_WORD_OFFSET,
            // The sign is in the sign-and-exponent word.
            X86_GUEST_X87_PAYLOAD_HIGH_OFFSET,
            crate::smir::lower::X86_GUEST_X87_INSTR_PTR_OFFSET,
            crate::smir::lower::X86_GUEST_X87_LAST_OPCODE_OFFSET,
        ] {
            assert!(
                code.windows(4)
                    .any(|window| window == (offset as u32).to_le_bytes()),
                "{op:?}: missing state offset {offset}: {code:02X?}"
            );
        }
    }
}

#[test]
fn lower_x87_sign_payload_rejects_every_malformed_shape() {
    for op in [
        metadata(X86X87DataKind::ChangeSign, 1, 0x01E0),
        metadata(X86X87DataKind::ChangeSign, 0, 0x01E1),
        metadata(X86X87DataKind::Absolute, 0, 0x01E1),
        metadata(X86X87DataKind::Absolute, 1, 0x01E0),
    ] {
        assert!(matches!(
            lower(op, true, None),
            Err(LowerError::InvalidOperand { .. })
        ));
    }
    assert!(matches!(
        lower(
            metadata(X86X87DataKind::Absolute, 1, 0x01E1),
            true,
            Some(X86OpHint::RexByteReg),
        ),
        Err(LowerError::InvalidOperand { .. })
    ));
}

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
fn execute_native(
    kind: X86X87ControlKind,
    configure: impl FnOnce(&mut crate::smir::lower::runtime::GuestRegs),
) -> crate::smir::lower::runtime::GuestRegs {
    execute_native_op(control(kind), configure)
}

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
fn execute_native_op(
    op: OpKind,
    configure: impl FnOnce(&mut crate::smir::lower::runtime::GuestRegs),
) -> crate::smir::lower::runtime::GuestRegs {
    use crate::smir::lower::runtime::{ExecMem, GuestRegs};

    let (code, entry) = lower(op, true, None).expect("lower native x87 state operation");
    let exec = ExecMem::new(&code).expect("map native x87 control");
    let mut regs = GuestRegs::default();
    regs.gpr = std::array::from_fn(|index| 0xA500_0000_0000_0000 | index as u64);
    regs.rflags = 0x2 | 0x08D5 | (1 << 10);
    regs.exit_pc = 0xDEAD_BEEF;
    regs.cr0 = 0x21;
    regs.x87_control_word = 0x027F;
    regs.x87_status_word = 0xFFFF;
    regs.x87_tag_word = 0x6996;
    regs.x87_data_ptr = 0x1122_3344_5566_7788;
    regs.x87_instr_ptr = 0x8877_6655_4433_2211;
    regs.x87_last_opcode = 0x05A5;
    configure(&mut regs);
    exec.run(entry, &mut regs);
    regs
}

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[test]
fn native_x87_stack_metadata_commits_exact_environment_state() {
    for (kind, st, fop, expected_top, expected_tag, clear_c1) in [
        (X86X87DataKind::DecrementTop, 6, 0x01F6, 4, 0, true),
        (X86X87DataKind::IncrementTop, 7, 0x01F7, 6, 0, true),
        (X86X87DataKind::Free, 3, 0x05C3, 5, 3, false),
        (X86X87DataKind::FreePop, 3, 0x07C3, 6, 0x0C03, false),
    ] {
        let result = execute_native_op(metadata(kind, st, fop), |regs| {
            regs.x87_status_word = (5 << 11) | 0x4700 | 0x003F;
            regs.x87_tag_word = 0;
        });
        assert_eq!((result.x87_status_word >> 11) & 7, expected_top, "{kind:?}");
        assert_eq!(result.x87_tag_word, expected_tag, "{kind:?}");
        assert_eq!(result.x87_status_word & 0x0200 == 0, clear_c1, "{kind:?}");
        assert_eq!(result.x87_instr_ptr, 0x1000, "{kind:?}");
        assert_eq!(result.x87_last_opcode, u64::from(fop), "{kind:?}");
        assert_eq!(result.x87_data_ptr, 0x1122_3344_5566_7788, "{kind:?}");
        assert_eq!(result.gpr[0], 0xA500_0000_0000_0000, "{kind:?}");
        assert_eq!(result.rflags, 0x2 | 0x08D5 | (1 << 10), "{kind:?}");
    }
}

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[test]
fn native_x87_stack_metadata_pending_error_guard_is_noncommitting() {
    for (kind, st, fop) in [
        (X86X87DataKind::DecrementTop, 6, 0x01F6),
        (X86X87DataKind::IncrementTop, 7, 0x01F7),
        (X86X87DataKind::Free, 3, 0x05C3),
        (X86X87DataKind::FreePop, 3, 0x07C3),
    ] {
        let result = execute_native_op(metadata(kind, st, fop), |regs| {
            regs.cr0 |= 1 << 5;
            regs.x87_status_word = (5 << 11) | 0x8080 | 0x4700;
            regs.x87_tag_word = 0x6996;
        });
        assert_eq!(result.exit_pc, 0x1000, "{kind:?}");
        assert_eq!(result.x87_status_word, (5 << 11) | 0x8080 | 0x4700);
        assert_eq!(result.x87_tag_word, 0x6996);
        assert_eq!(result.x87_instr_ptr, 0x8877_6655_4433_2211);
        assert_eq!(result.x87_last_opcode, 0x05A5);
        assert_eq!(result.gpr[0], 0xA500_0000_0000_0000);
        assert_eq!(result.rflags, 0x2 | 0x08D5 | (1 << 10));
    }
}

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[test]
fn native_x87_sign_payload_is_bit_exact_for_dynamic_top_and_special_values() {
    // (operation, ST(i), FOP, sign-and-exponent word before, after): the
    // sign is bit 15 of the word (bit 79 of the binary80 value), and the
    // significand never changes.
    for (kind, st, fop, input, expected) in [
        (X86X87DataKind::ChangeSign, 0, 0x01E0, 0x7FFF, 0xFFFF),
        (X86X87DataKind::ChangeSign, 0, 0x01E0, 0x3FFF, 0xBFFF),
        (X86X87DataKind::ChangeSign, 0, 0x01E0, 0x0000, 0x8000),
        (X86X87DataKind::Absolute, 1, 0x01E1, 0xFFFF, 0x7FFF),
        (X86X87DataKind::Absolute, 1, 0x01E1, 0x8000, 0x0000),
        (X86X87DataKind::Absolute, 1, 0x01E1, 0x4001, 0x4001),
    ] {
        for top in 0..8usize {
            for tag in 0..3u64 {
                let result = execute_native_op(metadata(kind, st, fop), |regs| {
                    regs.x87_status_word = ((top as u64) << 11) | 0x4700 | 0x003F;
                    regs.x87_tag_word = tag << (top * 2);
                    regs.x87_payload =
                        std::array::from_fn(|index| 0xA500_0000_0000_0000 | index as u64);
                    regs.x87_payload_high = std::array::from_fn(|index| 0x1230 | index as u64);
                    regs.x87_payload_high[top] = input;
                });
                assert_eq!(
                    result.x87_payload_high[top], expected,
                    "{kind:?}, TOP={top}, tag={tag}"
                );
                for index in 0..8 {
                    assert_eq!(
                        result.x87_payload[index],
                        0xA500_0000_0000_0000 | index as u64,
                        "{kind:?}, TOP={top}, tag={tag}, significand {index}"
                    );
                    if index != top {
                        assert_eq!(
                            result.x87_payload_high[index],
                            0x1230 | index as u64,
                            "{kind:?}, TOP={top}, tag={tag}, physical={index}"
                        );
                    }
                }
                assert_eq!(result.x87_status_word & 0x0200, 0);
                assert_eq!(result.x87_status_word & 0x4500, 0x4500);
                assert_eq!(result.x87_tag_word, tag << (top * 2));
                assert_eq!(result.x87_instr_ptr, 0x1000);
                assert_eq!(result.x87_last_opcode, u64::from(fop));
                assert_eq!(result.gpr[0], 0xA500_0000_0000_0000);
                assert_eq!(result.rflags, 0x2 | 0x08D5 | (1 << 10));
            }
        }
    }
}

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[test]
fn native_x87_sign_payload_empty_stack_guard_is_noncommitting() {
    for (kind, st, fop) in [
        (X86X87DataKind::ChangeSign, 0, 0x01E0),
        (X86X87DataKind::Absolute, 1, 0x01E1),
    ] {
        let result = execute_native_op(metadata(kind, st, fop), |regs| {
            regs.x87_status_word = (5 << 11) | 0x4700 | 0x003F;
            regs.x87_tag_word = 3 << (5 * 2);
            regs.x87_payload = std::array::from_fn(|index| 0xA500_0000_0000_0000 | index as u64);
            regs.x87_payload_high = std::array::from_fn(|index| 0x1230 | index as u64);
        });
        assert_eq!(result.exit_pc, 0x1000, "{kind:?}");
        assert_eq!(result.x87_status_word, (5 << 11) | 0x4700 | 0x003F);
        assert_eq!(result.x87_tag_word, 3 << (5 * 2));
        assert_eq!(
            result.x87_payload,
            std::array::from_fn(|index| 0xA500_0000_0000_0000 | index as u64)
        );
        assert_eq!(
            result.x87_payload_high,
            std::array::from_fn(|index| 0x1230 | index as u64)
        );
        assert_eq!(result.x87_instr_ptr, 0x8877_6655_4433_2211);
        assert_eq!(result.x87_last_opcode, 0x05A5);
        assert_eq!(result.gpr[0], 0xA500_0000_0000_0000);
        assert_eq!(result.rflags, 0x2 | 0x08D5 | (1 << 10));
    }
}

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[test]
fn native_x87_controls_commit_only_the_architecturally_selected_state() {
    let init = execute_native(X86X87ControlKind::Init, |_| {});
    assert_eq!(init.x87_control_word, 0x037F);
    assert_eq!(init.x87_status_word, 0);
    assert_eq!(init.x87_tag_word, 0xFFFF);
    assert_eq!(init.x87_data_ptr, 0);
    assert_eq!(init.x87_instr_ptr, 0);
    assert_eq!(init.x87_last_opcode, 0);
    assert_eq!(init.gpr[0], 0xA500_0000_0000_0000);
    assert_eq!(init.rflags, 0x2 | 0x08D5 | (1 << 10));

    let clear = execute_native(X86X87ControlKind::ClearExceptions, |_| {});
    assert_eq!(clear.x87_control_word, 0x027F);
    assert_eq!(clear.x87_status_word, 0x7F00);
    assert_eq!(clear.x87_tag_word, 0x6996);
    assert_eq!(clear.x87_data_ptr, 0x1122_3344_5566_7788);
    assert_eq!(clear.x87_instr_ptr, 0x8877_6655_4433_2211);
    assert_eq!(clear.x87_last_opcode, 0x05A5);
    assert_eq!(clear.gpr[0], 0xA500_0000_0000_0000);
    assert_eq!(clear.rflags, 0x2 | 0x08D5 | (1 << 10));

    let status = execute_native(X86X87ControlKind::StoreStatusAx, |regs| {
        regs.x87_status_word = 0xC5A3;
        regs.gpr[0] = 0x1122_3344_5566_7788;
    });
    assert_eq!(status.gpr[0], 0x1122_3344_5566_C5A3);
    assert_eq!(status.x87_status_word, 0xC5A3);
    assert_eq!(status.rflags, 0x2 | 0x08D5 | (1 << 10));
}

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[test]
fn native_x87_cr0_guard_exits_at_the_instruction_without_committing() {
    for fault_bits in [1 << 2, 1 << 3, (1 << 2) | (1 << 3)] {
        for kind in [
            X86X87ControlKind::Init,
            X86X87ControlKind::ClearExceptions,
            X86X87ControlKind::StoreStatusAx,
        ] {
            let guarded = execute_native(kind, |regs| regs.cr0 |= fault_bits);
            assert_eq!(guarded.exit_pc, 0x1000, "{kind:?}, CR0={fault_bits:#x}");
            assert_eq!(guarded.x87_control_word, 0x027F, "{kind:?}");
            assert_eq!(guarded.x87_status_word, 0xFFFF, "{kind:?}");
            assert_eq!(guarded.x87_tag_word, 0x6996, "{kind:?}");
            assert_eq!(guarded.gpr[0], 0xA500_0000_0000_0000, "{kind:?}");
            assert_eq!(guarded.rflags, 0x2 | 0x08D5 | (1 << 10), "{kind:?}");
        }
    }
}
