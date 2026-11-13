use super::*;
use crate::smir::ir::ops::SmirOp;
use crate::smir::ir::types::{OpId, VirtualId};
use crate::smir::lower::x86_64::test_support::host_c_helper_reference;

#[test]
fn all_96_destination_width_cells_optimize_admit_and_lower_at_o0_o1_o2() {
    let cases = all_cases();
    assert_eq!(cases.len(), 32 * 3);
    let mut lowerings = 0usize;
    for case in cases {
        for level in LEVELS {
            let function = optimize(lift_case(case), level);
            assert_exact_lift_and_sequence(&function, case);
            let (code, _) = lower(&function, case);

            let mut alignment = vec![0x48, 0xF7, 0xC6];
            alignment.extend_from_slice(&(case.width.bytes() - 1).to_le_bytes());
            assert!(
                code.windows(alignment.len())
                    .any(|window| window == alignment),
                "{level:?} {case:?}: missing alignment mask in {code:02X?}"
            );
            let mut destination = vec![0xBA];
            destination.extend_from_slice(&u32::from(case.destination).to_le_bytes());
            assert!(
                code.windows(destination.len())
                    .any(|window| window == destination),
                "{level:?} {case:?}: missing destination argument"
            );
            let mut size = vec![0xB9];
            size.extend_from_slice(&case.width.bytes().to_le_bytes());
            assert!(
                code.windows(size.len()).any(|window| window == size),
                "{level:?} {case:?}: missing transfer size"
            );
            let helper = host_c_helper_reference(crate::smir::lower::X86_GUEST_VEC_LOAD_FN_OFFSET);
            assert!(
                code.windows(helper.len()).any(|window| window == helper),
                "{level:?} {case:?}: missing vector-load helper"
            );
            lowerings += 1;
        }
    }
    assert_eq!(lowerings, 96 * LEVELS.len());
}

#[test]
fn every_legacy_and_apx_base_register_lifts_admits_and_lowers() {
    let mut lowerings = 0usize;
    for base in 0..32u8 {
        for width in [VecWidth::V128, VecWidth::V256, VecWidth::V512] {
            let case = MovntdqaMemoryCase {
                destination: (base.wrapping_mul(13).wrapping_add(width.bytes() as u8)) & 31,
                width,
                base,
            };
            let function = optimize(lift_case(case), OptLevel::O2);
            assert_eq!(
                matches!(function.blocks[0].ops[0].kind, OpKind::X86RequireApx),
                base >= 16,
                "{case:?}"
            );
            let _ = lower(&function, case);
            lowerings += 1;
        }
    }
    assert_eq!(lowerings, 32 * 3);
}

#[test]
fn complete_address_shapes_and_llvm_23_evex_apx_anchors_lower() {
    for (name, bytes, width, destination, requires_apx) in [
        (
            "LLVM EVEX xmm9 r11 compressed disp8",
            &[0x62, 0x52, 0x7D, 0x08, 0x2A, 0x4B, 0x04][..],
            VecWidth::V128,
            9,
            false,
        ),
        (
            "LLVM EVEX ymm17 r11 compressed disp8",
            &[0x62, 0xC2, 0x7D, 0x28, 0x2A, 0x4B, 0x04][..],
            VecWidth::V256,
            17,
            false,
        ),
        (
            "LLVM EVEX zmm31 r11 compressed disp8",
            &[0x62, 0x42, 0x7D, 0x48, 0x2A, 0x7B, 0x04][..],
            VecWidth::V512,
            31,
            false,
        ),
        (
            "LLVM APX r18 plus r21 scale4",
            &[0x62, 0xEA, 0x79, 0x48, 0x2A, 0x0C, 0xAA][..],
            VecWidth::V512,
            17,
            true,
        ),
        (
            "LLVM GS APX r18 compressed disp8",
            &[0x65, 0x62, 0xEA, 0x7D, 0x28, 0x2A, 0x4A, 0x04][..],
            VecWidth::V256,
            17,
            true,
        ),
        (
            "RSP SIB",
            &[0x62, 0xF2, 0x7D, 0x08, 0x2A, 0x44, 0x24, 0x01][..],
            VecWidth::V128,
            0,
            false,
        ),
        (
            "RIP relative",
            &[0x62, 0xF2, 0x7D, 0x48, 0x2A, 0x0D, 0x40, 0x00, 0x00, 0x00][..],
            VecWidth::V512,
            1,
            false,
        ),
        (
            "FS address-size absolute",
            &[
                0x64, 0x67, 0x62, 0xF2, 0x7D, 0x28, 0x2A, 0x14, 0x25, 0x40, 0x33, 0x22, 0x11,
            ][..],
            VecWidth::V256,
            2,
            false,
        ),
    ] {
        let function = optimize(function_from_bytes(bytes, name), OptLevel::O2);
        let index = instruction_index(&function);
        assert_eq!(index, usize::from(requires_apx), "{name}");
        let case = MovntdqaMemoryCase {
            destination,
            width,
            base: 0,
        };
        let encoding = sequence(&function, true)
            .unwrap_or_else(|| panic!("{name}: no exact sequence ({bytes:02X?})"))
            .encoding;
        assert_eq!(encoding, case.expected_encoding(), "{name}");
        let _ = lower(&function, case);
    }
}

fn assert_rejected(name: &str, function: &SmirFunction) {
    let excluded = HashMap::new();
    assert!(
        !is_native_clobber_safe_excluding(function, &excluded, true),
        "{name}: clobber gate admitted malformed sequence"
    );
    assert!(
        !x86_native_replay_feature_requirements(function, &excluded).any,
        "{name}: feature gate admitted malformed sequence"
    );
    let mut lowerer = X86_64Lowerer::new();
    lowerer.set_mem_helpers(true);
    lowerer.set_preserve_vector_mem_helpers(true);
    lowerer.set_native_vector_state_active(true);
    lowerer.set_narrow_vector_opmask_helpers(true);
    lowerer.set_avx_ymm16_vector_state(false);
    lowerer.set_jit_fault_deopt_guards(true);
    assert!(
        lowerer.lower_function(function).is_err(),
        "{name}: lowerer accepted malformed sequence"
    );
}

#[test]
fn graph_byte_provenance_frontier_and_apx_invariants_fail_closed() {
    let case = MovntdqaMemoryCase {
        destination: 17,
        width: VecWidth::V256,
        base: 2,
    };
    let base = lift_case(case);
    let index = instruction_index(&base);
    let temporary = match base.blocks[0].ops[index + 1].kind {
        OpKind::VLoad { dst, .. } => dst,
        _ => unreachable!(),
    };

    let mut malformed = Vec::new();
    let mut extra_use = base.clone();
    extra_use.blocks[0].ops.push(SmirOp::new(
        OpId(3),
        PC + 1,
        OpKind::VMov {
            dst: x86(X86Reg::Ymm(4)),
            src: temporary,
            width: VecWidth::V256,
        },
    ));
    malformed.push(("temporary used twice", extra_use));

    let mut extra_definition = base.clone();
    extra_definition.blocks[0].ops.insert(
        0,
        SmirOp::new(
            OpId(3),
            PC - 1,
            OpKind::VMov {
                dst: temporary,
                src: x86(X86Reg::Ymm(4)),
                width: VecWidth::V256,
            },
        ),
    );
    malformed.push(("temporary defined twice", extra_definition));

    let mut guard_hint = base.clone();
    guard_hint.blocks[0].ops[index].x86_hint = Some(X86OpHint::VecAlign(X86VecAlign::Aligned));
    malformed.push(("guard hint", guard_hint));

    let mut wrong_alignment = base.clone();
    if let OpKind::X86CheckAlignment { alignment, .. } =
        &mut wrong_alignment.blocks[0].ops[index].kind
    {
        *alignment = 16;
    }
    malformed.push(("wrong alignment", wrong_alignment));

    let mut virtual_guard_address = base.clone();
    if let OpKind::X86CheckAlignment { addr, .. } =
        &mut virtual_guard_address.blocks[0].ops[index].kind
    {
        *addr = Address::Direct(VReg::Virtual(VirtualId(0xFF00)));
    }
    malformed.push(("virtual guard address", virtual_guard_address));

    let mut mismatched_address = base.clone();
    if let OpKind::VLoad { addr, .. } = &mut mismatched_address.blocks[0].ops[index + 1].kind {
        *addr = Address::Direct(x86(X86Reg::Rax));
    }
    malformed.push(("guard/load address mismatch", mismatched_address));

    let mut load_hint = base.clone();
    load_hint.blocks[0].ops[index + 1].x86_hint = None;
    malformed.push(("missing load hint", load_hint));

    let mut load_width = base.clone();
    if let OpKind::VLoad { width, .. } = &mut load_width.blocks[0].ops[index + 1].kind {
        *width = VecWidth::V128;
    }
    malformed.push(("wrong load width", load_width));

    let mut load_destination = base.clone();
    if let OpKind::VLoad { dst, .. } = &mut load_destination.blocks[0].ops[index + 1].kind {
        *dst = x86(X86Reg::Ymm(3));
    }
    malformed.push(("architectural load destination", load_destination));

    let mut load_pc = base.clone();
    load_pc.blocks[0].ops[index + 1].guest_pc += 1;
    malformed.push(("load guest PC", load_pc));

    let mut write_pc = base.clone();
    write_pc.blocks[0].ops[index + 2].guest_pc += 1;
    malformed.push(("write guest PC", write_pc));

    let mut write_hint = base.clone();
    write_hint.blocks[0].ops[index + 2].x86_hint = Some(X86OpHint::VecAlign(X86VecAlign::Aligned));
    malformed.push(("write hint", write_hint));

    let mut write_source = base.clone();
    if let OpKind::VMov { src, .. } = &mut write_source.blocks[0].ops[index + 2].kind {
        *src = x86(X86Reg::Ymm(2));
    }
    malformed.push(("write bypasses temporary", write_source));

    let mut write_destination = base.clone();
    if let OpKind::VMov { dst, .. } = &mut write_destination.blocks[0].ops[index + 2].kind {
        *dst = x86(X86Reg::Ymm(18));
    }
    malformed.push(("encoded destination mismatch", write_destination));

    let mut write_namespace = base.clone();
    if let OpKind::VMov { dst, .. } = &mut write_namespace.blocks[0].ops[index + 2].kind {
        *dst = x86(X86Reg::Xmm(17));
    }
    malformed.push(("destination namespace", write_namespace));

    let mut write_width = base.clone();
    if let OpKind::VMov { width, .. } = &mut write_width.blocks[0].ops[index + 2].kind {
        *width = VecWidth::V128;
    }
    malformed.push(("write width", write_width));

    let mut previous_same_pc = base.clone();
    previous_same_pc.blocks[0].ops.insert(
        0,
        SmirOp::new(
            OpId(3),
            PC,
            OpKind::VMov {
                dst: x86(X86Reg::Ymm(4)),
                src: x86(X86Reg::Ymm(5)),
                width: VecWidth::V256,
            },
        ),
    );
    malformed.push(("same-PC predecessor", previous_same_pc));

    let mut next_same_pc = base.clone();
    next_same_pc.blocks[0].ops.push(SmirOp::new(
        OpId(3),
        PC,
        OpKind::VMov {
            dst: x86(X86Reg::Ymm(4)),
            src: x86(X86Reg::Ymm(5)),
            width: VecWidth::V256,
        },
    ));
    malformed.push(("same-PC successor", next_same_pc));

    let mut missing_bytes = base.clone();
    missing_bytes.x86_instruction_bytes.clear();
    malformed.push(("missing bytes", missing_bytes));

    let mut byte_destination = base.clone();
    byte_destination.x86_instruction_bytes.insert(
        (BlockId(0), PC),
        X86InstructionBytes::new(
            &MovntdqaMemoryCase {
                destination: 18,
                ..case
            }
            .bytes(),
        )
        .unwrap(),
    );
    malformed.push(("byte destination", byte_destination));

    let mut byte_width = base.clone();
    byte_width.x86_instruction_bytes.insert(
        (BlockId(0), PC),
        X86InstructionBytes::new(
            &MovntdqaMemoryCase {
                width: VecWidth::V512,
                ..case
            }
            .bytes(),
        )
        .unwrap(),
    );
    malformed.push(("byte width", byte_width));

    let mut vex_bytes = base.clone();
    vex_bytes.x86_instruction_bytes.insert(
        (BlockId(0), PC),
        X86InstructionBytes::new(&[0xC4, 0xE2, 0x7D, 0x2A, 0x10]).unwrap(),
    );
    malformed.push(("VEX bytes", vex_bytes));

    let mut spurious_apx = base.clone();
    spurious_apx.blocks[0]
        .ops
        .insert(0, SmirOp::new(OpId(3), PC, OpKind::X86RequireApx));
    malformed.push(("spurious APX guard", spurious_apx));

    let apx_case = MovntdqaMemoryCase { base: 18, ..case };
    let mut missing_apx = lift_case(apx_case);
    missing_apx.blocks[0].ops.remove(0);
    malformed.push(("missing APX guard", missing_apx));

    for (name, function) in malformed {
        assert_rejected(name, &function);
    }
}

#[test]
fn excluded_blocks_and_avx_only_bridge_fail_closed() {
    let case = MovntdqaMemoryCase {
        destination: 31,
        width: VecWidth::V512,
        base: 18,
    };
    let function = lift_case(case);
    let excluded = HashMap::from([(BlockId(0), PC)]);
    assert!(!uses_x86_native_vectors_excluding(&function, &excluded));
    assert!(!x86_native_replay_feature_requirements(&function, &excluded).any);

    let mut lowerer = X86_64Lowerer::new();
    lowerer.set_mem_helpers(true);
    lowerer.set_preserve_vector_mem_helpers(true);
    lowerer.set_avx_ymm16_vector_state(true);
    lowerer.set_jit_fault_deopt_guards(true);
    assert!(matches!(
        lowerer.lower_function(&function),
        Err(LowerError::InvalidOperand { .. })
    ));
}
