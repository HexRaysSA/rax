//! Strict-lifting coverage for legacy x87 register encodings.

use super::*;

fn assert_single_x87_alias(bytes: &[u8], expected: X86X87DataKind, st: u8, fop: u16) {
    let result = lift_single(bytes)
        .unwrap_or_else(|error| panic!("legacy x87 encoding {bytes:02X?} must lift: {error}"));
    assert_eq!(result.bytes_consumed, bytes.len(), "{bytes:02X?}");
    assert!(matches!(result.control_flow, ControlFlow::Fallthrough));
    assert!(matches!(
        result.ops.as_slice(),
        [SmirOp {
            id: OpId(0),
            guest_pc: 0x1000,
            kind: OpKind::X86X87Data {
                kind,
                addr: None,
                st: actual_st,
                fop: actual_fop,
            },
            ..
        }] if *kind == expected && *actual_st == st && *actual_fop == fop
    ));
    let native = expected == X86X87DataKind::StorePopRegister;
    assert_eq!(result.ops[0].kind.is_jit_safe(), native, "{bytes:02X?}");
    assert_eq!(result.ops[0].is_jit_safe(), native, "{bytes:02X?}");
}

fn assert_ffreep_op(ops: &[SmirOp], st: u8, guest_pc: u64) {
    let fop = 0x07C0 + u16::from(st);
    assert!(matches!(
        ops,
        [SmirOp {
            id: OpId(0),
            guest_pc: actual_pc,
            kind: OpKind::X86X87Data {
                kind: X86X87DataKind::FreePop,
                addr: None,
                st: actual_st,
                fop: actual_fop,
            },
            ..
        }] if *actual_pc == guest_pc && *actual_st == st && *actual_fop == fop
    ));
    assert!(ops[0].kind.is_jit_safe());
    assert!(ops[0].is_jit_safe());
}

#[test]
fn all_direct_accepted_legacy_x87_register_ranges_lift_exactly() {
    for st in 0u8..8 {
        let ordered_no_pop = X86X87DataKind::Compare {
            source: X86X87CompareSource::Register,
            unordered: false,
            pop: 0,
            eflags: false,
        };
        let ordered_pop = X86X87DataKind::Compare {
            source: X86X87CompareSource::Register,
            unordered: false,
            pop: 1,
            eflags: false,
        };

        assert_single_x87_alias(
            &[0xDC, 0xD0 + st],
            ordered_no_pop,
            st,
            0x04D0 + u16::from(st),
        );
        assert_single_x87_alias(&[0xDC, 0xD8 + st], ordered_pop, st, 0x04D8 + u16::from(st));
        assert_single_x87_alias(
            &[0xDD, 0xC8 + st],
            X86X87DataKind::Exchange,
            st,
            0x05C8 + u16::from(st),
        );
        assert_single_x87_alias(&[0xDE, 0xD0 + st], ordered_pop, st, 0x06D0 + u16::from(st));
        assert_single_x87_alias(
            &[0xDF, 0xD0 + st],
            X86X87DataKind::StorePopRegister,
            st,
            0x07D0 + u16::from(st),
        );

        let ffreep = lift_single(&[0xDF, 0xC0 + st]).unwrap();
        assert_eq!(ffreep.bytes_consumed, 2);
        assert!(matches!(ffreep.control_flow, ControlFlow::Fallthrough));
        assert_ffreep_op(&ffreep.ops, st, 0x1000);
    }
}

#[test]
fn legacy_x87_register_ranges_trap_on_lock_and_survive_o2_in_order() {
    for bytes in [
        &[0xF0, 0xDC, 0xD0][..],
        &[0xF0, 0xDC, 0xD8][..],
        &[0xF0, 0xDD, 0xC8][..],
        &[0xF0, 0xDE, 0xD0][..],
        &[0xF0, 0xDF, 0xC0][..],
        &[0xF0, 0xDF, 0xD0][..],
    ] {
        let result = lift_single(bytes)
            .expect("LOCK-prefixed x87 register encoding must strictly lift to #UD");
        assert_invalid_opcode_trap(&result, bytes.len());
    }

    let memory = TestMemory::new(
        0x2000,
        vec![
            0xDC, 0xD0, 0xDC, 0xD8, 0xDD, 0xC8, 0xDE, 0xD0, 0xDF, 0xC3, 0xDF, 0xD0, 0x90, 0xF4,
        ],
    );
    let mut lifter = X86_64Lifter::strict();
    let mut context = LiftContext::new(SourceArch::X86_64);
    let mut function = lifter.lift_function(0x2000, &memory, &mut context).unwrap();
    crate::smir::optimize::optimize_function(&mut function, crate::smir::optimize::OptLevel::O2);

    let entry = function
        .blocks
        .iter()
        .find(|block| block.guest_pc == 0x2000)
        .unwrap();
    assert_eq!(entry.ops.len(), 6);
    for guest_pc in [0x2000, 0x2002, 0x2004, 0x2006, 0x200A] {
        assert_eq!(
            entry
                .ops
                .iter()
                .filter(|op| op.guest_pc == guest_pc)
                .count(),
            1,
            "O2 removed or duplicated the x87 operation at {guest_pc:#x}",
        );
    }
    let ffreep_ops = entry
        .ops
        .iter()
        .filter(|op| op.guest_pc == 0x2008)
        .cloned()
        .collect::<Vec<_>>();
    assert_ffreep_op(&ffreep_ops, 3, 0x2008);
}
