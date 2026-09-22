//! Optimizer preservation tests for state-backed x87 environment operations.

use super::*;
use crate::smir::ir::ops::{X86X87ControlKind, X86X87DataKind};
use crate::smir::ir::types::SourceArch;
use crate::smir::ir::{FunctionBuilder, SmirFunction};
use crate::smir::lift::x86_64::X86_64Lifter;
use crate::smir::lift::{LiftContext, SmirLifter};
use crate::smir::optimize::tests::*;

const CONTROL_FORMS: [([u8; 2], X86X87ControlKind); 3] = [
    ([0xDB, 0xE2], X86X87ControlKind::ClearExceptions),
    ([0xDB, 0xE3], X86X87ControlKind::Init),
    ([0xDF, 0xE0], X86X87ControlKind::StoreStatusAx),
];

const LEGACY_PREFIXES: [&[u8]; 14] = [
    &[],
    &[0x66],
    &[0xF2],
    &[0xF3],
    &[0x67],
    &[0x64],
    &[0x65],
    &[0x48],
    &[0x44],
    &[0x41],
    &[0x4D],
    &[0x66, 0x48],
    &[0xF2, 0x48],
    &[0xF3, 0x48],
];

fn stack_metadata_forms() -> Vec<([u8; 2], X86X87DataKind, u8, u16)> {
    let mut forms = vec![
        ([0xD9, 0xF6], X86X87DataKind::DecrementTop, 6, 0x01F6),
        ([0xD9, 0xF7], X86X87DataKind::IncrementTop, 7, 0x01F7),
    ];
    for st in 0..8 {
        forms.push((
            [0xDD, 0xC0 + st],
            X86X87DataKind::Free,
            st,
            0x05C0 + u16::from(st),
        ));
        forms.push((
            [0xDF, 0xC0 + st],
            X86X87DataKind::FreePop,
            st,
            0x07C0 + u16::from(st),
        ));
    }
    forms
}

fn sign_payload_forms() -> [([u8; 2], X86X87DataKind, u8, u16); 2] {
    [
        ([0xD9, 0xE0], X86X87DataKind::ChangeSign, 0, 0x01E0),
        ([0xD9, 0xE1], X86X87DataKind::Absolute, 1, 0x01E1),
    ]
}

fn register_store_forms() -> Vec<([u8; 2], X86X87DataKind, u8, u16)> {
    [
        (0xDD, 0xD0, X86X87DataKind::StoreRegister, 0x05D0),
        (0xDD, 0xD8, X86X87DataKind::StorePopRegister, 0x05D8),
        (0xDF, 0xD0, X86X87DataKind::StorePopRegister, 0x07D0),
    ]
    .into_iter()
    .flat_map(|(escape, base, kind, fop)| {
        (0..8u8).map(move |st| ([escape, base + st], kind, st, fop + u16::from(st)))
    })
    .collect()
}

fn lifted(bytes: &[u8]) -> SmirFunction {
    let mut lifter = X86_64Lifter::strict();
    let mut lift_ctx = LiftContext::new(SourceArch::X86_64);
    let lifted = lifter.lift_insn(0x1000, bytes, &mut lift_ctx).unwrap();
    assert_eq!(lifted.bytes_consumed, bytes.len());
    let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
    builder.set_terminator(Terminator::Return { values: vec![] });
    let mut function = builder.finish();
    function.blocks[0].ops = lifted.ops;
    function
}

fn assert_form(function: &SmirFunction, expected: X86X87ControlKind, rex2: bool) {
    let ops = &function.blocks[0].ops;
    assert_eq!(ops.len(), 1 + usize::from(rex2), "{ops:?}");
    if rex2 {
        assert!(matches!(ops[0].kind, OpKind::X86RequireApx), "{ops:?}");
    }
    assert!(
        matches!(
            ops.last().unwrap().kind,
            OpKind::X86X87Control { kind, addr: None } if kind == expected
        ),
        "{ops:?}"
    );
    for (index, op) in ops.iter().enumerate() {
        assert_eq!(op.id, OpId(index as u16), "{ops:?}");
        assert_eq!(op.guest_pc, 0x1000, "{ops:?}");
    }
}

fn assert_stack_metadata_form(
    function: &SmirFunction,
    expected: X86X87DataKind,
    st: u8,
    fop: u16,
    rex2: bool,
) {
    let ops = &function.blocks[0].ops;
    assert_eq!(ops.len(), 1 + usize::from(rex2), "{ops:?}");
    if rex2 {
        assert!(matches!(ops[0].kind, OpKind::X86RequireApx), "{ops:?}");
    }
    assert!(
        matches!(
            ops.last().unwrap().kind,
            OpKind::X86X87Data {
                kind,
                addr: None,
                st: actual_st,
                fop: actual_fop,
            } if kind == expected && actual_st == st && actual_fop == fop
        ),
        "{ops:?}"
    );
    for (index, op) in ops.iter().enumerate() {
        assert_eq!(op.id, OpId(index as u16), "{ops:?}");
        assert_eq!(op.guest_pc, 0x1000, "{ops:?}");
    }
}

#[test]
fn every_optimizer_level_preserves_each_x87_no_wait_control_side_effect() {
    for level in [OptLevel::O0, OptLevel::O1, OptLevel::O2] {
        for (bytes, expected) in CONTROL_FORMS {
            for prefix in [None, Some(0x66), Some(0xF2), Some(0xF3)] {
                let encoded = prefix.into_iter().chain(bytes).collect::<Vec<_>>();
                let mut function = lifted(&encoded);
                optimize_function(&mut function, level);
                assert_form(&function, expected, false);
            }
        }
    }
}

#[test]
fn o2_preserves_every_rex2_apx_guard_before_each_x87_no_wait_control() {
    for payload in 0x00..=0x7F {
        for (bytes, expected) in CONTROL_FORMS {
            let mut encoded = vec![0xD5, payload];
            encoded.extend_from_slice(&bytes);
            let mut function = lifted(&encoded);
            optimize_function(&mut function, OptLevel::O2);
            assert_form(&function, expected, true);
        }
    }
}

#[test]
fn every_optimizer_level_preserves_every_prefixed_x87_stack_metadata_operation() {
    for level in [OptLevel::O0, OptLevel::O1, OptLevel::O2] {
        for (bytes, expected, st, fop) in stack_metadata_forms() {
            for prefix in LEGACY_PREFIXES {
                let encoded = prefix.iter().copied().chain(bytes).collect::<Vec<_>>();
                let mut function = lifted(&encoded);
                optimize_function(&mut function, level);
                assert_stack_metadata_form(&function, expected, st, fop, false);
            }
        }
    }
}

#[test]
fn o2_preserves_every_rex2_apx_guard_before_every_x87_stack_metadata_operation() {
    for payload in 0x00..=0x7F {
        for (bytes, expected, st, fop) in stack_metadata_forms() {
            let mut encoded = vec![0xD5, payload];
            encoded.extend_from_slice(&bytes);
            let mut function = lifted(&encoded);
            optimize_function(&mut function, OptLevel::O2);
            assert_stack_metadata_form(&function, expected, st, fop, true);
        }
    }
}

#[test]
fn every_optimizer_level_preserves_every_prefixed_x87_sign_payload_operation() {
    for level in [OptLevel::O0, OptLevel::O1, OptLevel::O2] {
        for (bytes, expected, st, fop) in sign_payload_forms()
            .into_iter()
            .chain(register_store_forms())
        {
            for prefix in LEGACY_PREFIXES {
                let encoded = prefix.iter().copied().chain(bytes).collect::<Vec<_>>();
                let mut function = lifted(&encoded);
                optimize_function(&mut function, level);
                assert_stack_metadata_form(&function, expected, st, fop, false);
            }
        }
    }
}

#[test]
fn o2_preserves_every_rex2_apx_guard_before_every_x87_sign_payload_operation() {
    for payload in 0x00..=0x7F {
        for (bytes, expected, st, fop) in sign_payload_forms()
            .into_iter()
            .chain(register_store_forms())
        {
            let mut encoded = vec![0xD5, payload];
            encoded.extend_from_slice(&bytes);
            let mut function = lifted(&encoded);
            optimize_function(&mut function, OptLevel::O2);
            assert_stack_metadata_form(&function, expected, st, fop, true);
        }
    }
}
