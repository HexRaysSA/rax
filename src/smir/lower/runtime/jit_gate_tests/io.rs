//! Exact scalar x86 port-I/O admission, provenance, and ABI coverage.

use crate::smir::lower::x86_64::test_support::host_c_helper_reference;
use std::collections::HashMap;

use super::*;
use crate::smir::ir::{SmirBlock, SmirFunction, X86InstructionBytes};
use crate::smir::lift::x86_64::X86_64Lifter;
use crate::smir::lift::{ControlFlow, LiftContext, SmirLifter};
use crate::smir::lower::runtime::{
    GuestRegs, is_native_clobber_safe_excluding, is_x86_aarch64_native_clobber_safe_excluding,
};
use crate::smir::lower::x86_64::{X86_64Lowerer, X86IoEncoding, X86IoPort, x86_io_encoding};
use crate::smir::lower::{
    SmirLowerer, X86_GUEST_CMPCCXADD_FN_OFFSET, X86_GUEST_IO_FN_OFFSET, X86_GUEST_IO_REQUEST_OFFSET,
};
use crate::smir::optimize::{OptLevel, optimize_function};

const PC: u64 = 0x494F_0000;
const LEVELS: [OptLevel; 3] = [OptLevel::O0, OptLevel::O1, OptLevel::O2];
const SCANNER_PREFIXES: &[&[u8]] = &[
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

fn lift(bytes: &[u8]) -> SmirFunction {
    let mut lifter = X86_64Lifter::strict();
    let mut context = LiftContext::new(crate::smir::SourceArch::X86_64);
    let result = lifter
        .lift_insn(PC, bytes, &mut context)
        .unwrap_or_else(|error| panic!("{bytes:02X?}: {error:?}"));
    assert_eq!(result.bytes_consumed, bytes.len(), "{bytes:02X?}");
    assert!(
        matches!(
            &result.control_flow,
            ControlFlow::Fallthrough | ControlFlow::NextInsn
        ),
        "{bytes:02X?}: {:?}",
        result.control_flow
    );

    let mut block = SmirBlock::new(BlockId(0), PC);
    block.ops = result.ops;
    block.set_terminator(Terminator::Return { values: Vec::new() });
    let mut function = SmirFunction::new(FunctionId(0), block.id, PC);
    function.add_block(block);
    function.x86_instruction_bytes.insert(
        (BlockId(0), PC),
        X86InstructionBytes::new(bytes).expect("one complete x86 instruction"),
    );
    function
}

fn encoding(function: &SmirFunction) -> Option<X86IoEncoding> {
    x86_io_encoding(&function.blocks[0], 0, &function.x86_instruction_bytes)
}

fn admitted(function: &SmirFunction, allow_mem: bool) -> bool {
    is_native_clobber_safe_excluding(function, &HashMap::new(), allow_mem)
}

fn lower(function: &SmirFunction) -> Result<Vec<u8>, crate::smir::lower::LowerError> {
    let mut lowerer = X86_64Lowerer::new();
    lowerer.set_jit_fault_deopt_guards(true);
    lowerer.lower_function(function)?;
    lowerer.finalize()
}

fn expected_size(prefix: &[u8], opcode: u8) -> u8 {
    if matches!(opcode, 0xE4 | 0xE6 | 0xEC | 0xEE) {
        1
    } else if prefix == [0x66] {
        2
    } else {
        4
    }
}

#[test]
fn scalar_io_abi_is_append_only_exact_and_fail_closed() {
    assert_eq!(
        std::mem::offset_of!(GuestRegs, io_fn),
        X86_GUEST_IO_FN_OFFSET as usize
    );
    assert_eq!(X86_GUEST_IO_FN_OFFSET, X86_GUEST_CMPCCXADD_FN_OFFSET + 8);
    assert_eq!(
        std::mem::offset_of!(GuestRegs, io_request),
        X86_GUEST_IO_REQUEST_OFFSET as usize
    );
    assert_eq!(X86_GUEST_IO_REQUEST_OFFSET, X86_GUEST_IO_FN_OFFSET + 8);
    assert_eq!(GuestRegs::default().io_fn, 0);
    assert_eq!(GuestRegs::default().io_request, 0);

    for (port, size, output, value) in [
        (0x0000, 1, false, 0),
        (0xFFFF, 4, false, 0),
        (0x0080, 1, true, 0xA5),
        (0x03F8, 2, true, 0xBEEF),
        (0xFFFF, 4, true, 0x89AB_CDEF),
    ] {
        let mut state = GuestRegs::default();
        state.set_io_request(port, size, output, value);
        assert_eq!(state.take_io_request(), Some((port, size, output, value)));
        assert_eq!(state.io_request, 0, "request must be consumed once");
        assert_eq!(state.take_io_request(), None);
    }

    for malformed in [
        1,
        3_u64 << 16,
        (1_u64 << 25) | (1 << 16),
        (1_u64 << 32) | (1 << 16),
        (0x100_u64 << 32) | (1 << 24) | (1 << 16),
        (0x1_0000_u64 << 32) | (1 << 24) | (2 << 16),
    ] {
        let mut state = GuestRegs {
            io_request: malformed,
            ..GuestRegs::default()
        };
        assert_eq!(state.take_io_request(), None, "{malformed:#018x}");
        assert_eq!(
            state.io_request, 0,
            "malformed state must still be consumed"
        );
    }
}

#[test]
fn all_14392_scanner_scalar_io_images_admit_at_o0_o1_o2() {
    let mut encodings = 0usize;
    let mut input_encodings = 0usize;
    let mut output_encodings = 0usize;
    let mut optimization_profiles = 0usize;

    for prefix in SCANNER_PREFIXES {
        for opcode in [0xE4_u8, 0xE5, 0xE6, 0xE7] {
            for immediate in u8::MIN..=u8::MAX {
                let mut bytes = prefix.to_vec();
                bytes.extend([opcode, immediate]);
                for level in LEVELS {
                    let mut function = lift(&bytes);
                    optimize_function(&mut function, level);
                    let actual = encoding(&function)
                        .unwrap_or_else(|| panic!("{bytes:02X?}, {level:?}: not classified"));
                    assert_eq!(actual.port, X86IoPort::Immediate(u16::from(immediate)));
                    assert_eq!(actual.size, expected_size(prefix, opcode));
                    assert_eq!(actual.output, matches!(opcode, 0xE6 | 0xE7));
                    assert!(admitted(&function, false), "{bytes:02X?}, {level:?}");
                    assert!(admitted(&function, true), "{bytes:02X?}, {level:?}");
                    optimization_profiles += 1;
                }
                if matches!(opcode, 0xE4 | 0xE5) {
                    input_encodings += 1;
                } else {
                    output_encodings += 1;
                }
                encodings += 1;
            }
        }

        for opcode in [0xEC_u8, 0xED, 0xEE, 0xEF] {
            let mut bytes = prefix.to_vec();
            bytes.push(opcode);
            for level in LEVELS {
                let mut function = lift(&bytes);
                optimize_function(&mut function, level);
                let actual = encoding(&function)
                    .unwrap_or_else(|| panic!("{bytes:02X?}, {level:?}: not classified"));
                assert_eq!(actual.port, X86IoPort::Dx);
                assert_eq!(actual.size, expected_size(prefix, opcode));
                assert_eq!(actual.output, matches!(opcode, 0xEE | 0xEF));
                assert!(admitted(&function, false), "{bytes:02X?}, {level:?}");
                assert!(admitted(&function, true), "{bytes:02X?}, {level:?}");
                optimization_profiles += 1;
            }
            if matches!(opcode, 0xEC | 0xED) {
                input_encodings += 1;
            } else {
                output_encodings += 1;
            }
            encodings += 1;
        }
    }

    assert_eq!(input_encodings, 7_196);
    assert_eq!(output_encodings, 7_196);
    assert_eq!(encodings, 14_392);
    assert_eq!(optimization_profiles, 43_176);
}

#[test]
fn scalar_io_prefix_order_width_and_unsigned_immediate_are_exact() {
    let cases: &[(&[u8], X86IoPort, u8, bool)] = &[
        (&[0xE4, 0x80], X86IoPort::Immediate(0x80), 1, false),
        (&[0xE6, 0xFF], X86IoPort::Immediate(0xFF), 1, true),
        (&[0xE5, 0x80], X86IoPort::Immediate(0x80), 4, false),
        (&[0x66, 0xE7, 0xFF], X86IoPort::Immediate(0xFF), 2, true),
        (
            &[0x66, 0x48, 0xE5, 0xA5],
            X86IoPort::Immediate(0xA5),
            4,
            false,
        ),
        (
            &[0x48, 0x66, 0xE7, 0xA5],
            X86IoPort::Immediate(0xA5),
            2,
            true,
        ),
        (&[0xF2, 0x48, 0x66, 0xED], X86IoPort::Dx, 2, false),
        (&[0xF3, 0x66, 0x48, 0xEF], X86IoPort::Dx, 4, true),
    ];

    for (bytes, port, size, output) in cases {
        let function = lift(bytes);
        let actual = encoding(&function).unwrap();
        assert_eq!(actual.port, *port, "{bytes:02X?}");
        assert_eq!(actual.size, *size, "{bytes:02X?}");
        assert_eq!(actual.output, *output, "{bytes:02X?}");

        let code = lower(&function).unwrap_or_else(|error| panic!("{bytes:02X?}: {error:?}"));
        let helper_call = host_c_helper_reference(X86_GUEST_IO_FN_OFFSET);
        assert!(
            code.windows(helper_call.len())
                .any(|window| window == helper_call),
            "{bytes:02X?}: helper call absent from {code:02X?}"
        );
    }
}

#[test]
fn scalar_io_frontier_keeps_pre_exit_registers_and_flags_live_at_o1_o2() {
    let rax = x86(X86Reg::Rax);
    let rbx = x86(X86Reg::Rbx);
    let rcx = x86(X86Reg::Rcx);
    for level in [OptLevel::O1, OptLevel::O2] {
        let mut builder = crate::smir::ir::FunctionBuilder::new(FunctionId(0), PC);
        builder.push_op(
            PC,
            OpKind::Mov {
                dst: rbx,
                src: SrcOperand::Imm(1),
                width: OpWidth::W64,
            },
        );
        builder.push_op(
            PC + 5,
            OpKind::Cmp {
                src1: rax,
                src2: SrcOperand::Reg(rcx),
                width: OpWidth::W64,
            },
        );
        builder.push_op(
            PC + 8,
            OpKind::IoOut {
                port: VReg::Imm(0x80),
                value: rax,
                width: MemWidth::B1,
            },
        );
        builder.push_op(
            PC + 10,
            OpKind::Mov {
                dst: rbx,
                src: SrcOperand::Imm(2),
                width: OpWidth::W64,
            },
        );
        builder.push_op(
            PC + 15,
            OpKind::Cmp {
                src1: rbx,
                src2: SrcOperand::Reg(rcx),
                width: OpWidth::W64,
            },
        );
        builder.set_terminator(Terminator::Return { values: vec![rbx] });
        let mut function = builder.finish();

        optimize_function(&mut function, level);

        assert_eq!(
            function.blocks[0]
                .ops
                .iter()
                .filter(|op| matches!(op.kind, OpKind::Mov { dst, .. } if dst == rbx))
                .count(),
            2,
            "{level:?}: the external exit observes the first RBX value"
        );
        assert_eq!(
            function.blocks[0]
                .ops
                .iter()
                .filter(|op| matches!(op.kind, OpKind::Cmp { .. }))
                .count(),
            2,
            "{level:?}: the external exit observes the first status image"
        );
    }
}

fn assert_rejected(function: &SmirFunction, name: &str) {
    assert!(!admitted(function, false), "{name}: register-only gate");
    assert!(!admitted(function, true), "{name}: helper-aware gate");
    assert!(lower(function).is_err(), "{name}: standalone lowerer");
}

#[test]
fn scalar_io_rejects_every_malformed_provenance_and_ir_shape() {
    let canonical = lift(&[0xE4, 0x80]);

    let mut missing = canonical.clone();
    missing.x86_instruction_bytes.clear();
    assert_rejected(&missing, "missing provenance");

    for (name, source) in [
        ("incomplete immediate", &[0xE4][..]),
        ("trailing byte", &[0xE4, 0x80, 0x90]),
        ("wrong direction", &[0xE6, 0x80]),
        ("LOCK", &[0xF0, 0xE4, 0x80]),
        ("REX2", &[0xD5, 0x00, 0xE4, 0x80]),
    ] {
        let mut malformed = canonical.clone();
        malformed
            .x86_instruction_bytes
            .insert((BlockId(0), PC), X86InstructionBytes::new(source).unwrap());
        assert_rejected(&malformed, name);
    }

    let mut hinted = canonical.clone();
    hinted.blocks[0].ops[0].x86_hint = Some(X86OpHint::RexByteReg);
    assert_rejected(&hinted, "x86 hint");

    let mut duplicate = canonical.clone();
    let mut second = duplicate.blocks[0].ops[0].clone();
    second.id = crate::smir::ir::types::OpId(1);
    duplicate.blocks[0].ops.push(second);
    assert_rejected(&duplicate, "multiple operations at source PC");

    let mutations: &[(&str, OpKind)] = &[
        (
            "negative immediate",
            OpKind::IoIn {
                dst: x86(X86Reg::Rax),
                port: VReg::Imm(-128),
                width: MemWidth::B1,
            },
        ),
        (
            "wrong immediate",
            OpKind::IoIn {
                dst: x86(X86Reg::Rax),
                port: VReg::Imm(0x81),
                width: MemWidth::B1,
            },
        ),
        (
            "wrong destination",
            OpKind::IoIn {
                dst: x86(X86Reg::Rcx),
                port: VReg::Imm(0x80),
                width: MemWidth::B1,
            },
        ),
        (
            "wrong width",
            OpKind::IoIn {
                dst: x86(X86Reg::Rax),
                port: VReg::Imm(0x80),
                width: MemWidth::B2,
            },
        ),
        (
            "wrong kind",
            OpKind::IoOut {
                port: VReg::Imm(0x80),
                value: x86(X86Reg::Rax),
                width: MemWidth::B1,
            },
        ),
    ];
    for (name, kind) in mutations {
        let mut malformed = canonical.clone();
        malformed.blocks[0].ops[0].kind = kind.clone();
        assert_rejected(&malformed, name);
    }
}

#[test]
fn scalar_io_class_whitelists_and_cross_host_gates_remain_closed() {
    for bytes in [&[0xE4, 0x80][..], &[0xEF][..]] {
        let function = lift(bytes);
        let op = &function.blocks[0].ops[0];
        assert!(matches!(
            op.kind,
            OpKind::IoIn { .. } | OpKind::IoOut { .. }
        ));
        assert!(
            !op.kind.is_jit_safe(),
            "exact admission must own the exception"
        );
        assert!(encoding(&function).is_some());
        assert!(admitted(&function, false));
        assert!(!is_x86_aarch64_native_clobber_safe_excluding(
            &function,
            &HashMap::new()
        ));
        assert!(!x86_aarch64_scalar_shape_valid(&op.kind));
    }
}
