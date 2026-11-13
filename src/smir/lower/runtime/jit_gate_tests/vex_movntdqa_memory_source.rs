//! Exact helper-backed VEX `VMOVNTDQA` memory-source coverage.

use super::*;
use crate::smir::ir::ops::{OpKind, SmirOp, X86OpHint, X86VecAlign};
use crate::smir::ir::types::{
    Address, ArchReg, BlockId, DispSize, FunctionId, OpId, VReg, VecWidth, VirtualId, X86Reg,
};
use crate::smir::ir::{SmirBlock, SmirFunction, Terminator, X86InstructionBytes};
use crate::smir::lift::x86_64::X86_64Lifter;
use crate::smir::lift::{ControlFlow, LiftContext, SmirLifter};
use crate::smir::lower::SmirLowerer;
use crate::smir::lower::runtime::{
    GuestRegs, X86_VECTOR_STATE_YMM16, is_native_clobber_safe_excluding,
    is_x86_aarch64_native_clobber_safe_excluding, uses_x86_native_vectors_excluding,
    x86_jit_evex_movntdqa_memory_sequence, x86_jit_vex_movntdqa_memory_sequence,
    x86_native_replay_feature_requirements, x86_native_vector_uses_avx_ymm16_only_excluding,
};
use crate::smir::lower::x86_64::X86_64Lowerer;
use crate::smir::lower::x86_64::test_support::host_c_helper_reference;
use crate::smir::optimize::OptLevel;

const PC: u64 = 0xC42A;
const DISP: i64 = 0x20;
const LEVELS: [OptLevel; 3] = [OptLevel::O0, OptLevel::O1, OptLevel::O2];
const DIFFERENTIAL_LEVELS: [OptLevel; 2] = [OptLevel::O0, OptLevel::O2];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MovntdqaMemoryCase {
    destination: u8,
    width: VecWidth,
    w: bool,
}

impl MovntdqaMemoryCase {
    const fn base(self) -> u8 {
        if self.destination < 8 { 3 } else { 11 }
    }

    fn bytes(self) -> Vec<u8> {
        let base = self.base();
        vec![
            0xC4,
            (if self.destination < 8 { 0x80 } else { 0 })
                | (if (self.destination ^ u8::from(self.w)) & 1 == 0 {
                    0x40
                } else {
                    0
                })
                | (if base < 8 { 0x20 } else { 0 })
                | 0x02,
            (u8::from(self.w) << 7)
                | 0x78
                | (if self.width == VecWidth::V256 {
                    0x04
                } else {
                    0
                })
                | 1,
            0x2A,
            0x40 | ((self.destination & 7) << 3) | (base & 7),
            DISP as u8,
        ]
    }
}

fn x86(reg: X86Reg) -> VReg {
    VReg::Arch(ArchReg::X86(reg))
}

fn destination(case: MovntdqaMemoryCase) -> VReg {
    x86(match case.width {
        VecWidth::V128 => X86Reg::Xmm(case.destination),
        VecWidth::V256 => X86Reg::Ymm(case.destination),
        _ => unreachable!("VEX VMOVNTDQA has only 128-bit and 256-bit forms"),
    })
}

fn expected_address(case: MovntdqaMemoryCase) -> Address {
    Address::BaseOffset {
        base: x86(X86Reg::gpr(case.base())),
        offset: DISP,
        disp_size: DispSize::Disp8,
    }
}

fn assert_exact_sequence(ops: &[SmirOp], case: MovntdqaMemoryCase) {
    let [guard, load, write] = ops else {
        panic!("{case:?}: expected exact guard/load/write group, got {ops:?}")
    };
    assert_eq!(guard.guest_pc, PC, "{case:?}");
    assert!(guard.x86_hint.is_none(), "{case:?}");
    assert!(
        matches!(
            &guard.kind,
            OpKind::X86CheckAlignment { addr, alignment }
                if addr == &expected_address(case)
                    && u32::from(*alignment) == case.width.bytes()
        ),
        "{case:?}: {:?}",
        guard.kind
    );
    let temporary = match &load.kind {
        OpKind::VLoad {
            dst: temporary @ VReg::Virtual(_),
            addr,
            width,
        } if addr == &expected_address(case) && *width == case.width => *temporary,
        other => panic!("{case:?}: expected aligned virtual VLoad, got {other:?}"),
    };
    assert_eq!(load.guest_pc, PC, "{case:?}");
    assert_eq!(
        load.x86_hint,
        Some(X86OpHint::VecAlign(X86VecAlign::Aligned)),
        "{case:?}"
    );
    assert_eq!(write.guest_pc, PC, "{case:?}");
    assert!(write.x86_hint.is_none(), "{case:?}");
    assert!(
        matches!(
            write.kind,
            OpKind::VMov { dst, src, width }
                if dst == destination(case) && src == temporary && width == case.width
        ),
        "{case:?}: {:?}",
        write.kind
    );
}

fn lift_instruction(bytes: &[u8]) -> SmirFunction {
    let mut lifter = X86_64Lifter::strict();
    let mut context = LiftContext::new(crate::smir::ir::types::SourceArch::X86_64);
    let result = lifter
        .lift_insn(PC, bytes, &mut context)
        .unwrap_or_else(|error| panic!("{bytes:02X?}: {error:?}"));
    assert_eq!(result.bytes_consumed, bytes.len(), "{bytes:02X?}");
    assert!(matches!(result.control_flow, ControlFlow::Fallthrough));

    let mut block = SmirBlock::new(BlockId(0), PC);
    block.ops = result.ops;
    block.set_terminator(Terminator::Return { values: Vec::new() });
    let mut function = SmirFunction::new(FunctionId(0), block.id, PC);
    function.add_block(block);
    function.x86_instruction_bytes.insert(
        (BlockId(0), PC),
        X86InstructionBytes::new(bytes).expect("VEX instruction fits metadata"),
    );
    function
}

fn lift_case(case: MovntdqaMemoryCase) -> SmirFunction {
    let function = lift_instruction(&case.bytes());
    assert_exact_sequence(&function.blocks[0].ops, case);
    function
}

fn optimize(mut function: SmirFunction, level: OptLevel) -> SmirFunction {
    crate::smir::optimize::optimize_function(&mut function, level);
    function
}

fn lower(function: &SmirFunction) -> (Vec<u8>, usize) {
    let excluded = std::collections::HashMap::new();
    assert!(is_native_clobber_safe_excluding(function, &excluded, true));
    assert!(!is_native_clobber_safe_excluding(
        function, &excluded, false
    ));
    assert!(!is_x86_aarch64_native_clobber_safe_excluding(
        function, &excluded
    ));
    assert!(uses_x86_native_vectors_excluding(function, &excluded));
    assert!(x86_native_vector_uses_avx_ymm16_only_excluding(
        function, &excluded
    ));

    let requirements = x86_native_replay_feature_requirements(function, &excluded);
    assert!(requirements.any);
    assert!(requirements.all_spans_support_avx_ymm16);
    assert!(requirements.needs_avx);
    assert!(!requirements.needs_avx2);
    assert!(!requirements.needs_avx512bw);
    assert!(!requirements.needs_avx512vl);
    assert!(!requirements.needs_avx512dq);

    let mut lowerer = X86_64Lowerer::new();
    lowerer.set_mem_helpers(true);
    lowerer.set_preserve_vector_mem_helpers(true);
    lowerer.set_avx_ymm16_vector_state(true);
    lowerer.set_jit_fault_deopt_guards(true);
    let result = lowerer
        .lower_function(function)
        .unwrap_or_else(|error| panic!("helper-backed VEX VMOVNTDQA lowering failed: {error:?}"));
    assert!(result.relocations.is_empty());
    (
        lowerer
            .finalize()
            .expect("finalize helper-backed VEX VMOVNTDQA"),
        result.entry_offset,
    )
}

fn all_cases() -> Vec<MovntdqaMemoryCase> {
    let mut cases = Vec::new();
    for destination in 0..16 {
        for width in [VecWidth::V128, VecWidth::V256] {
            for w in [false, true] {
                cases.push(MovntdqaMemoryCase {
                    destination,
                    width,
                    w,
                });
            }
        }
    }
    cases
}

#[test]
fn all_64_destination_width_and_wig_cells_are_optimized_admitted_and_lowered() {
    let cases = all_cases();
    assert_eq!(cases.len(), 16 * 2 * 2);
    let mut lowered = 0usize;
    for case in cases {
        for level in LEVELS {
            let function = optimize(lift_case(case), level);
            assert_exact_sequence(&function.blocks[0].ops, case);
            let (code, _) = lower(&function);

            let mut alignment_check = vec![0x48, 0xF7, 0xC6];
            alignment_check.extend_from_slice(&(case.width.bytes() - 1).to_le_bytes());
            assert!(
                code.windows(alignment_check.len())
                    .any(|window| window == alignment_check),
                "{level:?} {case:?}: missing alignment mask in {code:02X?}"
            );
            let mut destination_argument = vec![0xBA];
            destination_argument.extend_from_slice(&u32::from(case.destination).to_le_bytes());
            assert!(
                code.windows(destination_argument.len())
                    .any(|window| window == destination_argument),
                "{level:?} {case:?}: missing destination argument in {code:02X?}"
            );
            let mut size_argument = vec![0xB9];
            size_argument.extend_from_slice(&case.width.bytes().to_le_bytes());
            assert!(
                code.windows(size_argument.len())
                    .any(|window| window == size_argument),
                "{level:?} {case:?}: missing transfer size in {code:02X?}"
            );
            let helper_call =
                host_c_helper_reference(crate::smir::lower::X86_GUEST_VEC_LOAD_FN_OFFSET);
            assert!(
                code.windows(helper_call.len())
                    .any(|window| window == helper_call),
                "{level:?} {case:?}: missing vector-load helper call"
            );
            lowered += 1;
        }
    }
    assert_eq!(lowered, 64 * LEVELS.len());
}

#[test]
fn complete_address_shapes_and_llvm_23_encodings_lower() {
    for (name, bytes, width, destination) in [
        (
            "LLVM r11 disp8 to xmm9",
            &[0xC4, 0x42, 0x79, 0x2A, 0x4B, 0x20][..],
            VecWidth::V128,
            9,
        ),
        (
            "LLVM r11 disp8 to ymm9",
            &[0xC4, 0x42, 0x7D, 0x2A, 0x4B, 0x20][..],
            VecWidth::V256,
            9,
        ),
        (
            "RSP SIB",
            &[0xC4, 0xE2, 0x79, 0x2A, 0x44, 0x24, 0x20][..],
            VecWidth::V128,
            0,
        ),
        (
            "RBP disp8",
            &[0xC4, 0xE2, 0x79, 0x2A, 0x45, 0x20][..],
            VecWidth::V128,
            0,
        ),
        (
            "R12 SIB",
            &[0xC4, 0xC2, 0x7D, 0x2A, 0x44, 0x24, 0x20][..],
            VecWidth::V256,
            0,
        ),
        (
            "R13 disp8",
            &[0xC4, 0xC2, 0x7D, 0x2A, 0x45, 0x20][..],
            VecWidth::V256,
            0,
        ),
        (
            "LLVM extended SIB disp32 to xmm14",
            &[0xC4, 0x02, 0x79, 0x2A, 0xB4, 0x7E, 0x44, 0x33, 0x22, 0x11][..],
            VecWidth::V128,
            14,
        ),
        (
            "LLVM extended SIB disp32 to ymm14",
            &[0xC4, 0x02, 0x7D, 0x2A, 0xB4, 0x7E, 0x40, 0x33, 0x22, 0x11][..],
            VecWidth::V256,
            14,
        ),
        (
            "RIP relative",
            &[0xC4, 0xE2, 0x79, 0x2A, 0x05, 0x40, 0x00, 0x00, 0x00][..],
            VecWidth::V128,
            0,
        ),
        (
            "FS base",
            &[0x64, 0xC4, 0xE2, 0x79, 0x2A, 0x00][..],
            VecWidth::V128,
            0,
        ),
        (
            "GS address-size absolute W1",
            &[
                0x65, 0x67, 0xC4, 0xE2, 0xFD, 0x2A, 0x04, 0x25, 0x40, 0x33, 0x22, 0x11,
            ][..],
            VecWidth::V256,
            0,
        ),
    ] {
        let function = optimize(lift_instruction(bytes), OptLevel::O2);
        let [guard, load, write] = function.blocks[0].ops.as_slice() else {
            panic!("{name}: unexpected optimized operations")
        };
        assert!(
            matches!(
                (&guard.kind, &load.kind, &write.kind),
                (
                    OpKind::X86CheckAlignment { alignment, .. },
                    OpKind::VLoad { width: load_width, .. },
                    OpKind::VMov {
                        dst,
                        width: write_width,
                        ..
                    }
                ) if u32::from(*alignment) == width.bytes()
                    && *load_width == width
                    && *write_width == width
                    && *dst == x86(match width {
                        VecWidth::V128 => X86Reg::Xmm(destination),
                        VecWidth::V256 => X86Reg::Ymm(destination),
                        _ => unreachable!(),
                    })
            ),
            "{name}: {:?}",
            function.blocks[0].ops
        );
        let _ = lower(&function);
    }
}

fn assert_rejected(name: &str, function: &SmirFunction) {
    let excluded = std::collections::HashMap::new();
    assert!(
        !is_native_clobber_safe_excluding(function, &excluded, true),
        "{name}: clobber gate admitted malformed group"
    );
    assert!(
        !x86_native_replay_feature_requirements(function, &excluded).any,
        "{name}: feature classifier admitted malformed group"
    );
    let mut lowerer = X86_64Lowerer::new();
    lowerer.set_mem_helpers(true);
    lowerer.set_preserve_vector_mem_helpers(true);
    lowerer.set_avx_ymm16_vector_state(true);
    lowerer.set_jit_fault_deopt_guards(true);
    assert!(
        lowerer.lower_function(function).is_err(),
        "{name}: lowerer accepted malformed group"
    );
}

#[test]
fn classifier_and_lowerer_fail_closed_for_every_graph_and_provenance_invariant() {
    let case = MovntdqaMemoryCase {
        destination: 3,
        width: VecWidth::V128,
        w: false,
    };
    let base = lift_case(case);
    let temporary = match base.blocks[0].ops[1].kind {
        OpKind::VLoad { dst, .. } => dst,
        _ => unreachable!(),
    };

    let mut extra_use = base.clone();
    extra_use.blocks[0].ops.push(SmirOp::new(
        OpId(3),
        PC + 1,
        OpKind::VMov {
            dst: x86(X86Reg::Xmm(4)),
            src: temporary,
            width: VecWidth::V128,
        },
    ));

    let mut extra_definition = base.clone();
    extra_definition.blocks[0].ops.insert(
        0,
        SmirOp::new(
            OpId(3),
            PC - 1,
            OpKind::VMov {
                dst: temporary,
                src: x86(X86Reg::Xmm(4)),
                width: VecWidth::V128,
            },
        ),
    );

    let mut guard_hint = base.clone();
    guard_hint.blocks[0].ops[0].x86_hint = Some(X86OpHint::VecAlign(X86VecAlign::Aligned));

    let mut wrong_alignment = base.clone();
    if let OpKind::X86CheckAlignment { alignment, .. } = &mut wrong_alignment.blocks[0].ops[0].kind
    {
        *alignment = 32;
    }

    let mut invalid_guard_address = base.clone();
    if let OpKind::X86CheckAlignment { addr, .. } = &mut invalid_guard_address.blocks[0].ops[0].kind
    {
        *addr = Address::Direct(VReg::Virtual(VirtualId(0xFFFF)));
    }

    let mut mismatched_addresses = base.clone();
    if let OpKind::VLoad { addr, .. } = &mut mismatched_addresses.blocks[0].ops[1].kind {
        *addr = Address::Direct(x86(X86Reg::Rax));
    }

    let mut nonvirtual_load = base.clone();
    if let OpKind::VLoad { dst, .. } = &mut nonvirtual_load.blocks[0].ops[1].kind {
        *dst = x86(X86Reg::Xmm(5));
    }

    let mut no_load_hint = base.clone();
    no_load_hint.blocks[0].ops[1].x86_hint = None;

    let mut unaligned_load_hint = base.clone();
    unaligned_load_hint.blocks[0].ops[1].x86_hint =
        Some(X86OpHint::VecAlign(X86VecAlign::Unaligned));

    let mut load_width = base.clone();
    if let OpKind::VLoad { width, .. } = &mut load_width.blocks[0].ops[1].kind {
        *width = VecWidth::V256;
    }

    let mut invalid_load_address = base.clone();
    if let OpKind::VLoad { addr, .. } = &mut invalid_load_address.blocks[0].ops[1].kind {
        *addr = Address::Direct(VReg::Virtual(VirtualId(0xFFFE)));
    }

    let mut wrong_load_pc = base.clone();
    wrong_load_pc.blocks[0].ops[1].guest_pc += 1;

    let mut wrong_write_pc = base.clone();
    wrong_write_pc.blocks[0].ops[2].guest_pc += 1;

    let mut previous_boundary = base.clone();
    previous_boundary.blocks[0].ops.insert(
        0,
        SmirOp::new(
            OpId(3),
            PC,
            OpKind::VMov {
                dst: x86(X86Reg::Xmm(4)),
                src: x86(X86Reg::Xmm(5)),
                width: VecWidth::V128,
            },
        ),
    );

    let mut next_boundary = base.clone();
    next_boundary.blocks[0].ops.push(SmirOp::new(
        OpId(3),
        PC,
        OpKind::VMov {
            dst: x86(X86Reg::Xmm(4)),
            src: x86(X86Reg::Xmm(5)),
            width: VecWidth::V128,
        },
    ));

    let mut wrong_source = base.clone();
    if let OpKind::VMov { src, .. } = &mut wrong_source.blocks[0].ops[2].kind {
        *src = x86(X86Reg::Xmm(2));
    }

    let mut high_destination = base.clone();
    if let OpKind::VMov { dst, .. } = &mut high_destination.blocks[0].ops[2].kind {
        *dst = x86(X86Reg::Xmm(16));
    }

    let mut wrong_namespace = base.clone();
    if let OpKind::VMov { dst, .. } = &mut wrong_namespace.blocks[0].ops[2].kind {
        *dst = x86(X86Reg::Ymm(3));
    }

    let mut wrong_write_width = base.clone();
    if let OpKind::VMov { width, .. } = &mut wrong_write_width.blocks[0].ops[2].kind {
        *width = VecWidth::V256;
    }

    let mut write_hint = base.clone();
    write_hint.blocks[0].ops[2].x86_hint = Some(X86OpHint::VecAlign(X86VecAlign::Aligned));

    let mut wrong_consumer = base.clone();
    wrong_consumer.blocks[0].ops[2].kind = OpKind::VMov {
        dst: x86(X86Reg::Xmm(4)),
        src: temporary,
        width: VecWidth::V128,
    };

    let mut missing_bytes = base.clone();
    missing_bytes.x86_instruction_bytes.clear();

    let mut byte_destination_mismatch = base.clone();
    byte_destination_mismatch.x86_instruction_bytes.insert(
        (BlockId(0), PC),
        X86InstructionBytes::new(
            &MovntdqaMemoryCase {
                destination: 4,
                ..case
            }
            .bytes(),
        )
        .unwrap(),
    );

    let mut byte_width_mismatch = base.clone();
    byte_width_mismatch.x86_instruction_bytes.insert(
        (BlockId(0), PC),
        X86InstructionBytes::new(
            &MovntdqaMemoryCase {
                width: VecWidth::V256,
                ..case
            }
            .bytes(),
        )
        .unwrap(),
    );

    let mut register_bytes = base.clone();
    register_bytes.x86_instruction_bytes.insert(
        (BlockId(0), PC),
        X86InstructionBytes::new(&[0xC4, 0xE2, 0x79, 0x2A, 0xD8]).unwrap(),
    );

    let mut legacy_bytes = base.clone();
    legacy_bytes.x86_instruction_bytes.insert(
        (BlockId(0), PC),
        X86InstructionBytes::new(&[0x66, 0x0F, 0x38, 0x2A, 0x18]).unwrap(),
    );

    let mut evex_bytes = base.clone();
    evex_bytes.x86_instruction_bytes.insert(
        (BlockId(0), PC),
        X86InstructionBytes::new(&[0x62, 0xF2, 0x7D, 0x08, 0x2A, 0x18]).unwrap(),
    );

    let malformed = [
        ("temporary used twice", extra_use),
        ("temporary defined twice", extra_definition),
        ("alignment guard carries a hint", guard_hint),
        ("alignment does not match width", wrong_alignment),
        ("guard has virtual address", invalid_guard_address),
        ("guard and load addresses differ", mismatched_addresses),
        ("load destination is architectural", nonvirtual_load),
        ("load alignment hint missing", no_load_hint),
        ("load marked unaligned", unaligned_load_hint),
        ("load width differs", load_width),
        ("load has virtual address", invalid_load_address),
        ("load has different guest PC", wrong_load_pc),
        ("write has different guest PC", wrong_write_pc),
        ("same-PC operation precedes group", previous_boundary),
        ("same-PC operation follows group", next_boundary),
        ("write bypasses temporary", wrong_source),
        ("high EVEX-only destination", high_destination),
        ("destination register namespace mismatch", wrong_namespace),
        ("write width differs", wrong_write_width),
        ("write carries a hint", write_hint),
        ("encoded destination differs", wrong_consumer),
        ("missing instruction-byte provenance", missing_bytes),
        ("byte destination mismatch", byte_destination_mismatch),
        ("byte width mismatch", byte_width_mismatch),
        ("register-form provenance", register_bytes),
        ("legacy provenance", legacy_bytes),
    ];
    for (name, function) in malformed {
        assert_rejected(name, &function);
    }

    // This graph is also the canonical EVEX.128 VMOVNTDQA decomposition. The
    // VEX family classifier must reject the EVEX bytes, while the complete
    // dispatcher must now route them through the EVEX family rather than
    // treating valid alternate-family provenance as malformed.
    let virtual_definitions = std::collections::HashMap::from([(temporary, 1usize)]);
    let virtual_uses = std::collections::HashMap::from([(temporary, 1usize)]);
    assert!(
        x86_jit_vex_movntdqa_memory_sequence(
            &evex_bytes.blocks[0],
            0,
            true,
            &evex_bytes.x86_instruction_bytes,
            &virtual_definitions,
            &virtual_uses,
        )
        .is_none()
    );
    assert!(
        x86_jit_evex_movntdqa_memory_sequence(
            &evex_bytes.blocks[0],
            0,
            true,
            &evex_bytes.x86_instruction_bytes,
            &virtual_definitions,
            &virtual_uses,
        )
        .is_some()
    );
    let excluded = std::collections::HashMap::new();
    assert!(is_native_clobber_safe_excluding(
        &evex_bytes,
        &excluded,
        true
    ));
    let requirements = x86_native_replay_feature_requirements(&evex_bytes, &excluded);
    assert!(requirements.any);
    assert!(requirements.needs_avx && requirements.needs_avx512vl);
    assert!(requirements.has_k16_opmask_span);

    let mut evex_lowerer = X86_64Lowerer::new();
    evex_lowerer.set_mem_helpers(true);
    evex_lowerer.set_preserve_vector_mem_helpers(true);
    evex_lowerer.set_native_vector_state_active(true);
    evex_lowerer.set_narrow_vector_opmask_helpers(true);
    evex_lowerer.set_avx_ymm16_vector_state(false);
    evex_lowerer.set_jit_fault_deopt_guards(true);
    evex_lowerer
        .lower_function(&evex_bytes)
        .expect("valid EVEX provenance routes through EVEX VMOVNTDQA lowering");

    let mut alternate_wig = base;
    alternate_wig.x86_instruction_bytes.insert(
        (BlockId(0), PC),
        X86InstructionBytes::new(&MovntdqaMemoryCase { w: true, ..case }.bytes()).unwrap(),
    );
    let _ = lower(&alternate_wig);
}

#[test]
fn excluded_blocks_contribute_no_native_vector_or_feature_requirements() {
    let function = lift_case(MovntdqaMemoryCase {
        destination: 9,
        width: VecWidth::V256,
        w: true,
    });
    let excluded = std::collections::HashMap::from([(BlockId(0), PC)]);
    assert!(!uses_x86_native_vectors_excluding(&function, &excluded));
    assert!(
        !x86_native_replay_feature_requirements(&function, &excluded).any,
        "excluded VMOVNTDQA must not contribute host features"
    );
}

fn words_to_bytes(words: [u64; 8]) -> [u8; 64] {
    let mut bytes = [0; 64];
    for (chunk, word) in bytes.chunks_exact_mut(8).zip(words) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    bytes
}

fn source_vector(case: MovntdqaMemoryCase, ordinal: usize) -> [u64; 8] {
    std::array::from_fn(|word| {
        0xF0E1_D2C3_B4A5_9687u64.rotate_left(
            ((usize::from(case.destination) * 7 + word * 11 + usize::from(case.w) + ordinal) & 63)
                as u32,
        ) ^ (word as u64).wrapping_mul(0x0102_0408_1020_4081)
    })
}

#[cfg(target_arch = "x86_64")]
#[derive(Clone, Debug)]
struct VectorMemoryContext {
    value: [u64; 8],
    ok: u64,
    calls: u64,
    last_addr: u64,
    last_index: u32,
    last_size: u32,
    last_zero_upper: u32,
}

#[cfg(target_arch = "x86_64")]
extern "C" fn vector_load_helper(
    state: *mut GuestRegs,
    addr: u64,
    destination: u32,
    size: u32,
    zero_upper: u32,
) -> u64 {
    let state = unsafe { &mut *state };
    let context = unsafe { &mut *(state.ctx as *mut VectorMemoryContext) };
    context.calls += 1;
    context.last_addr = addr;
    context.last_index = destination;
    context.last_size = size;
    context.last_zero_upper = zero_upper;
    if context.ok == 0 || destination >= 16 || !matches!(size, 16 | 32) || zero_upper != 1 {
        return 0;
    }

    let mut value = [0; 8];
    let words = size as usize / 8;
    value[..words].copy_from_slice(&context.value[..words]);
    state.zmm[destination as usize] = value;
    1
}

#[cfg(target_arch = "x86_64")]
fn full_guest_regs(case: MovntdqaMemoryCase, ordinal: usize) -> GuestRegs {
    let mut registers = GuestRegs {
        gpr: std::array::from_fn(|index| {
            0x1000u64
                .wrapping_add((index as u64) * 0x101)
                .wrapping_add((ordinal as u64) * 0x10)
        }),
        rflags: 0x2 | (((ordinal as u64).wrapping_mul(0x145)) & 0x8D5),
        exit_pc: 0xAAAA_BBBB_CCCC_DDDD,
        k: std::array::from_fn(|index| 0x0102_0304_0506_0708u64.rotate_left((index * 7) as u32)),
        vector_active: X86_VECTOR_STATE_YMM16,
        mxcsr: 0x1F80 | ((ordinal as u32) & 0x3F),
        vector_scratch: [0xCCDD_EEFF_0011_2233; 8],
        ..GuestRegs::default()
    };
    for (index, value) in registers.zmm.iter_mut().enumerate() {
        *value = std::array::from_fn(|word| {
            0x8877_6655_4433_2211u64.rotate_left((index * 13 + word * 3) as u32)
                ^ (index as u64).wrapping_mul(0x1111_2222_3333_4444)
                ^ (word as u64).wrapping_mul(0x1020_4081_0204_0810)
        });
    }
    registers.gpr[usize::from(case.base())] = 0x2000 + ((ordinal & 0x7F) as u64) * 0x40;
    registers
}

#[cfg(target_arch = "x86_64")]
fn expected_success(
    mut registers: GuestRegs,
    case: MovntdqaMemoryCase,
    source: [u64; 8],
) -> GuestRegs {
    let words = case.width.bytes() as usize / 8;
    registers.zmm[usize::from(case.destination)] = [0; 8];
    registers.zmm[usize::from(case.destination)][..words].copy_from_slice(&source[..words]);
    registers
}

#[cfg(target_arch = "x86_64")]
fn assert_interpreter_matches(
    function: &SmirFunction,
    initial: &GuestRegs,
    expected: &GuestRegs,
    source: [u64; 8],
    address: u64,
    case: MovntdqaMemoryCase,
    level: OptLevel,
) {
    use crate::smir::interpret::{BlockResult, SmirInterpreter};
    use crate::smir::ir::context::{ArchRegState, ExitReason, SmirContext};
    use crate::smir::ir::flags::MaterializedFlags;
    use crate::smir::ir::memory::FlatMemory;

    let mut context = SmirContext::new_x86_64();
    if let ArchRegState::X86_64(x86) = &mut context.arch_regs {
        x86.gpr = initial.gpr;
        for (index, value) in initial.zmm.iter().enumerate() {
            x86.xmm[index][..8].copy_from_slice(value);
        }
        x86.k = initial.k;
        x86.rflags = initial.rflags;
        x86.mxcsr = initial.mxcsr;
    }
    context.flags.materialized = MaterializedFlags::from_rflags(initial.rflags);
    context.flags.lazy = None;
    let mut memory = FlatMemory::new(0x10000);
    let bytes = words_to_bytes(source);
    memory.load(address as usize, &bytes[..case.width.bytes() as usize]);
    let result =
        SmirInterpreter::new().execute_block(&mut context, &mut memory, &function.blocks[0]);
    assert!(
        matches!(result, BlockResult::Exit(ExitReason::Return { .. })),
        "{level:?} {case:?}: {result:?}"
    );

    let ArchRegState::X86_64(x86) = &context.arch_regs else {
        unreachable!()
    };
    assert_eq!(x86.gpr, expected.gpr, "{level:?} {case:?}: GPRs");
    for (index, value) in expected.zmm.iter().enumerate() {
        assert_eq!(
            &x86.xmm[index][..8],
            value,
            "{level:?} {case:?}: ZMM{index}"
        );
    }
    assert_eq!(x86.k, expected.k, "{level:?} {case:?}: masks");
    assert_eq!(x86.rflags, expected.rflags, "{level:?} {case:?}: RFLAGS");
    assert_eq!(x86.mxcsr, expected.mxcsr, "{level:?} {case:?}: MXCSR");
}

#[cfg(target_arch = "x86_64")]
#[test]
fn native_vmovntdqa_matches_interpreter_and_is_precise_for_faults_and_alignment() {
    use crate::smir::lower::runtime::ExecMem;

    if !std::is_x86_feature_detected!("avx") {
        eprintln!("skipping native VMOVNTDQA memory differential: host lacks AVX");
        return;
    }

    let cases = all_cases();
    let expected_executions = cases.len() * DIFFERENTIAL_LEVELS.len();
    let mut successes = 0usize;
    let mut helper_faults = 0usize;
    let mut alignment_exits = 0usize;
    for (ordinal, case) in cases.into_iter().enumerate() {
        for level in DIFFERENTIAL_LEVELS {
            let function = optimize(lift_case(case), level);
            let (code, entry) = lower(&function);
            let exec =
                ExecMem::new(&code).unwrap_or_else(|error| panic!("{level:?} {case:?}: {error:?}"));
            let source = source_vector(case, ordinal);

            let mut context = VectorMemoryContext {
                value: source,
                ok: 1,
                calls: 0,
                last_addr: 0,
                last_index: 0,
                last_size: 0,
                last_zero_upper: 0,
            };
            let mut registers = full_guest_regs(case, ordinal);
            let address = registers.gpr[usize::from(case.base())].wrapping_add(DISP as u64);
            assert_eq!(address & (u64::from(case.width.bytes()) - 1), 0);
            registers.ctx = (&mut context as *mut VectorMemoryContext) as u64;
            registers.vec_load_fn = vector_load_helper as usize as u64;
            let initial = registers;
            let mut expected = expected_success(registers, case, source);

            exec.run(entry, &mut registers);
            expected.host_mxcsr = registers.host_mxcsr;
            assert_eq!(registers, expected, "{level:?} {case:?}: success");
            assert_eq!(context.calls, 1, "{level:?} {case:?}");
            assert_eq!(context.last_addr, address, "{level:?} {case:?}");
            assert_eq!(
                context.last_index,
                u32::from(case.destination),
                "{level:?} {case:?}"
            );
            assert_eq!(context.last_size, case.width.bytes(), "{level:?} {case:?}");
            assert_eq!(context.last_zero_upper, 1, "{level:?} {case:?}");
            assert_interpreter_matches(
                &function, &initial, &expected, source, address, case, level,
            );
            successes += 1;

            let mut context = VectorMemoryContext {
                value: source,
                ok: 0,
                calls: 0,
                last_addr: 0,
                last_index: 0,
                last_size: 0,
                last_zero_upper: 0,
            };
            let mut registers = full_guest_regs(case, ordinal ^ 0x55);
            let address = registers.gpr[usize::from(case.base())].wrapping_add(DISP as u64);
            registers.ctx = (&mut context as *mut VectorMemoryContext) as u64;
            registers.vec_load_fn = vector_load_helper as usize as u64;
            let mut expected = registers;
            expected.exit_pc = PC;

            exec.run(entry, &mut registers);
            expected.host_mxcsr = registers.host_mxcsr;
            assert_eq!(registers, expected, "{level:?} {case:?}: helper fault");
            assert_eq!(context.calls, 1, "fault {level:?} {case:?}");
            assert_eq!(context.last_addr, address, "fault {level:?} {case:?}");
            assert_eq!(
                context.last_index,
                u32::from(case.destination),
                "fault {level:?} {case:?}"
            );
            assert_eq!(
                context.last_size,
                case.width.bytes(),
                "fault {level:?} {case:?}"
            );
            assert_eq!(context.last_zero_upper, 1, "fault {level:?} {case:?}");
            helper_faults += 1;

            let mut context = VectorMemoryContext {
                value: source,
                ok: 1,
                calls: 0,
                last_addr: 0,
                last_index: 0,
                last_size: 0,
                last_zero_upper: 0,
            };
            let mut registers = full_guest_regs(case, ordinal ^ 0x2A);
            registers.gpr[usize::from(case.base())] =
                registers.gpr[usize::from(case.base())].wrapping_add(1);
            registers.ctx = (&mut context as *mut VectorMemoryContext) as u64;
            registers.vec_load_fn = vector_load_helper as usize as u64;
            let mut expected = registers;
            expected.exit_pc = PC;

            exec.run(entry, &mut registers);
            expected.host_mxcsr = registers.host_mxcsr;
            assert_eq!(registers, expected, "{level:?} {case:?}: alignment exit");
            assert_eq!(
                context.calls, 0,
                "{level:?} {case:?}: helper ran before alignment exit"
            );
            alignment_exits += 1;
        }
    }

    assert_eq!(expected_executions, 128);
    assert_eq!(successes, expected_executions);
    assert_eq!(helper_faults, expected_executions);
    assert_eq!(alignment_exits, expected_executions);
    eprintln!(
        "executed {successes} successful, {helper_faults} helper-faulting, and \
         {alignment_exits} misaligned native VMOVNTDQA cases"
    );
}
