//! Exact helper-backed VEX reciprocal-estimate memory coverage.

use super::*;
use crate::smir::ir::ops::{OpKind, SmirOp, X86OpHint, X86VecAlign};
use crate::smir::ir::types::{
    Address, ArchReg, BlockId, DispSize, FunctionId, MemWidth, OpId, OpWidth, SignExtend,
    SrcOperand, VReg, VecElementType, VecUnaryOp, VecWidth, VirtualId, X86Reg,
};
use crate::smir::ir::{SmirBlock, SmirFunction, Terminator, X86InstructionBytes};
use crate::smir::lift::x86_64::X86_64Lifter;
use crate::smir::lift::{ControlFlow, LiftContext, SmirLifter};
use crate::smir::lower::SmirLowerer;
use crate::smir::lower::runtime::{
    GuestRegs, X86_VECTOR_STATE_YMM16, X86JitVexEstimateMemorySequence,
    is_native_clobber_safe_excluding, is_x86_aarch64_native_clobber_safe_excluding,
    uses_x86_native_vectors_excluding, x86_jit_vex_estimate_memory_sequence,
    x86_native_replay_feature_requirements, x86_native_vector_uses_avx_ymm16_only_excluding,
};
use crate::smir::lower::x86_64::X86_64Lowerer;
use crate::smir::optimize::OptLevel;
use std::collections::HashMap;

mod semantics;

const PC: u64 = 0x52_53;
const DISP: i64 = 0x20;
const LEVELS: [OptLevel; 3] = [OptLevel::O0, OptLevel::O1, OptLevel::O2];
#[cfg(target_arch = "x86_64")]
const DIFFERENTIAL_LEVELS: [OptLevel; 2] = [OptLevel::O0, OptLevel::O2];
// Intel® 64 and IA-32 Architectures Software Developer's Manual, Volume 2,
// revision 092 (June 2026), RCP*/RSQRT*: |Relative Error| <= 1.5 * 2^-12.
const INTEL_RELATIVE_ERROR_BOUND: f64 = 1.5 / 4096.0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Estimate {
    Reciprocal,
    ReciprocalSqrt,
}

impl Estimate {
    const ALL: [Self; 2] = [Self::Reciprocal, Self::ReciprocalSqrt];

    const fn opcode(self) -> u8 {
        match self {
            Self::Reciprocal => 0x53,
            Self::ReciprocalSqrt => 0x52,
        }
    }

    const fn unary(self) -> VecUnaryOp {
        match self {
            Self::Reciprocal => VecUnaryOp::FRecipEstimate,
            Self::ReciprocalSqrt => VecUnaryOp::FRsqrtEstimate,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shape {
    Packed,
    Scalar,
}

impl Shape {
    const ALL: [Self; 2] = [Self::Packed, Self::Scalar];

    const fn scalar(self) -> bool {
        matches!(self, Self::Scalar)
    }

    const fn pp(self) -> u8 {
        if self.scalar() { 2 } else { 0 }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EncodingForm {
    C5,
    C4W0,
    C4W1,
}

impl EncodingForm {
    const ALL: [Self; 3] = [Self::C5, Self::C4W0, Self::C4W1];

    const fn w(self) -> bool {
        matches!(self, Self::C4W1)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EstimateMemoryCase {
    estimate: Estimate,
    shape: Shape,
    encoded_width: VecWidth,
    form: EncodingForm,
    destination: u8,
    source1: u8,
    base: u8,
}

impl EstimateMemoryCase {
    const fn source1(self) -> Option<u8> {
        if self.shape.scalar() {
            Some(self.source1)
        } else {
            None
        }
    }

    const fn logical_width(self) -> VecWidth {
        if self.shape.scalar() {
            VecWidth::V128
        } else {
            self.encoded_width
        }
    }

    const fn memory_size(self) -> u32 {
        if self.shape.scalar() {
            4
        } else {
            self.encoded_width.bytes()
        }
    }

    fn scratch(self) -> u8 {
        (0..16)
            .find(|index| *index != self.destination && self.source1() != Some(*index))
            .expect("at most two VEX operands leave at least fourteen scratch registers")
    }

    fn bytes(self) -> Vec<u8> {
        assert!(self.destination < 16 && self.source1 < 16 && self.base < 16);
        let encoded_vvvv = self.source1().map_or(0x0F, |index| !index & 0x0F);
        let l = u8::from(self.encoded_width == VecWidth::V256);
        let modrm = 0x40 | ((self.destination & 7) << 3) | (self.base & 7);
        match self.form {
            EncodingForm::C5 => {
                assert!(self.base < 8);
                vec![
                    0xC5,
                    (if self.destination < 8 { 0x80 } else { 0 })
                        | (encoded_vvvv << 3)
                        | (l << 2)
                        | self.shape.pp(),
                    self.estimate.opcode(),
                    modrm,
                    DISP as u8,
                ]
            }
            EncodingForm::C4W0 | EncodingForm::C4W1 => vec![
                0xC4,
                (if self.destination < 8 { 0x80 } else { 0 })
                    | 0x40
                    | (if self.base < 8 { 0x20 } else { 0 })
                    | 1,
                (u8::from(self.form.w()) << 7) | (encoded_vvvv << 3) | (l << 2) | self.shape.pp(),
                self.estimate.opcode(),
                modrm,
                DISP as u8,
            ],
        }
    }

    fn emitted_bytes(self) -> Vec<u8> {
        let scratch = self.scratch();
        let encoded_vvvv = self.source1().map_or(0x0F, |index| !index & 0x0F);
        let l = u8::from(self.logical_width() == VecWidth::V256);
        let modrm = 0xC0 | ((self.destination & 7) << 3) | scratch;
        if !self.form.w() {
            vec![
                0xC5,
                (if self.destination < 8 { 0x80 } else { 0 })
                    | (encoded_vvvv << 3)
                    | (l << 2)
                    | self.shape.pp(),
                self.estimate.opcode(),
                modrm,
            ]
        } else {
            vec![
                0xC4,
                (if self.destination < 8 { 0x80 } else { 0 }) | 0x60 | 1,
                0x80 | (encoded_vvvv << 3) | (l << 2) | self.shape.pp(),
                self.estimate.opcode(),
                modrm,
            ]
        }
    }
}

fn scanner_cases() -> Vec<EstimateMemoryCase> {
    let mut cases = Vec::new();
    for estimate in Estimate::ALL {
        for shape in Shape::ALL {
            for encoded_width in [VecWidth::V128, VecWidth::V256] {
                for form in EncodingForm::ALL {
                    for destination in 0..8 {
                        let source1s: &[u8] = if shape.scalar() {
                            &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
                        } else {
                            &[0]
                        };
                        for &source1 in source1s {
                            cases.push(EstimateMemoryCase {
                                estimate,
                                shape,
                                encoded_width,
                                form,
                                destination,
                                source1,
                                base: 2,
                            });
                        }
                    }
                }
            }
        }
    }
    cases
}

#[cfg(target_arch = "x86_64")]
fn semantic_cases() -> Vec<EstimateMemoryCase> {
    let mut cases = Vec::new();
    for estimate in Estimate::ALL {
        for shape in Shape::ALL {
            for encoded_width in [VecWidth::V128, VecWidth::V256] {
                for form in EncodingForm::ALL {
                    let base = match form {
                        EncodingForm::C5 => 3,
                        EncodingForm::C4W0 => 11,
                        EncodingForm::C4W1 => 14,
                    };
                    let operands: &[(u8, u8)] = if shape.scalar() {
                        &[(0, 1), (1, 1), (1, 0), (9, 10), (10, 9), (15, 15)]
                    } else {
                        &[(0, 0), (9, 0), (15, 0)]
                    };
                    for &(destination, source1) in operands {
                        cases.push(EstimateMemoryCase {
                            estimate,
                            shape,
                            encoded_width,
                            form,
                            destination,
                            source1,
                            base,
                        });
                    }
                }
            }
        }
    }
    cases
}

fn x86(reg: X86Reg) -> VReg {
    VReg::Arch(ArchReg::X86(reg))
}

fn vector(index: u8, width: VecWidth) -> VReg {
    x86(match width {
        VecWidth::V128 => X86Reg::Xmm(index),
        VecWidth::V256 => X86Reg::Ymm(index),
        _ => unreachable!("VEX estimates have only 128-/256-bit vector operands"),
    })
}

fn expected_address(case: EstimateMemoryCase) -> Address {
    Address::BaseOffset {
        base: x86(X86Reg::gpr(case.base)),
        offset: DISP,
        disp_size: DispSize::Disp8,
    }
}

fn virtual_counts(block: &SmirBlock) -> (HashMap<VReg, usize>, HashMap<VReg, usize>) {
    let mut definitions = HashMap::new();
    let mut uses = HashMap::new();
    for op in &block.ops {
        for register in op.kind.dests() {
            if matches!(register, VReg::Virtual(_)) {
                *definitions.entry(register).or_insert(0) += 1;
            }
        }
        for register in op.kind.source_vregs() {
            if matches!(register, VReg::Virtual(_)) {
                *uses.entry(register).or_insert(0) += 1;
            }
        }
    }
    (definitions, uses)
}

fn classified_sequence(
    function: &SmirFunction,
    allow_mem: bool,
) -> Option<X86JitVexEstimateMemorySequence> {
    let block = &function.blocks[0];
    let (definitions, uses) = virtual_counts(block);
    x86_jit_vex_estimate_memory_sequence(
        block,
        0,
        allow_mem,
        &function.x86_instruction_bytes,
        &definitions,
        &uses,
    )
}

fn lift_bytes(bytes: &[u8]) -> SmirFunction {
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
        X86InstructionBytes::new(bytes).expect("VEX estimate instruction fits metadata"),
    );
    function
}

fn lift_case(case: EstimateMemoryCase) -> SmirFunction {
    lift_bytes(&case.bytes())
}

fn optimize(mut function: SmirFunction, level: OptLevel) -> SmirFunction {
    crate::smir::optimize::optimize_function(&mut function, level);
    function
}

fn assert_exact_sequence(function: &SmirFunction, case: EstimateMemoryCase) {
    let ops = &function.blocks[0].ops;
    assert_eq!(
        ops.len(),
        if case.shape.scalar() { 13 } else { 3 },
        "{case:?}"
    );
    assert!(
        ops.iter().all(|op| op.guest_pc == PC),
        "{case:?}: split guest-PC provenance"
    );
    assert!(
        ops.iter().all(|op| op.x86_hint.is_none()),
        "{case:?}: reciprocal estimates must have hint-free canonical graphs"
    );

    let source = match &ops[0].kind {
        OpKind::VLoad {
            dst: source @ VReg::Virtual(_),
            addr,
            width,
        } if !case.shape.scalar() => {
            assert_eq!(addr, &expected_address(case), "{case:?}");
            assert_eq!(*width, case.logical_width(), "{case:?}");
            *source
        }
        OpKind::Load {
            dst: source @ VReg::Virtual(_),
            addr,
            width: MemWidth::B4,
            sign: SignExtend::Zero,
        } if case.shape.scalar() => {
            assert_eq!(addr, &expected_address(case), "{case:?}");
            *source
        }
        other => panic!("{case:?}: unexpected memory source {other:?}"),
    };

    let (unary_index, unary_source) = if case.shape.scalar() {
        let source_vector = match ops[1].kind {
            OpKind::VBroadcast {
                dst: vector @ VReg::Virtual(_),
                scalar,
                elem: VecElementType::F32,
                lanes: 1,
            } => {
                assert_eq!(scalar, source, "{case:?}");
                vector
            }
            ref other => panic!("{case:?}: unexpected scalar broadcast {other:?}"),
        };
        (2, source_vector)
    } else {
        (1, source)
    };

    let result = match ops[unary_index].kind {
        OpKind::VUnary {
            dst: result @ VReg::Virtual(_),
            src,
            elem: VecElementType::F32,
            lanes,
            op,
        } => {
            assert_eq!(src, unary_source, "{case:?}");
            assert_eq!(op, case.estimate.unary(), "{case:?}");
            assert_eq!(
                u32::from(lanes),
                if case.shape.scalar() {
                    1
                } else {
                    case.logical_width().lanes(VecElementType::F32)
                },
                "{case:?}"
            );
            result
        }
        ref other => panic!("{case:?}: unexpected estimate operation {other:?}"),
    };

    if !case.shape.scalar() {
        assert!(
            matches!(
                ops[2].kind,
                OpKind::VMov {
                    dst,
                    src,
                    width,
                } if dst == vector(case.destination, case.logical_width())
                    && src == result
                    && width == case.logical_width()
            ),
            "{case:?}: {:?}",
            ops[2].kind
        );
    } else {
        let scalar_result = match ops[3].kind {
            OpKind::VExtractLane {
                dst: scalar @ VReg::Virtual(_),
                vec,
                lane: 0,
                elem: VecElementType::F32,
                sign: SignExtend::Zero,
            } => {
                assert_eq!(vec, result, "{case:?}");
                scalar
            }
            ref other => panic!("{case:?}: unexpected low extraction {other:?}"),
        };
        let source1 = vector(case.source1, VecWidth::V128);
        let mut upper_scalars = Vec::new();
        for lane in 1..4usize {
            match ops[3 + lane].kind {
                OpKind::VExtractLane {
                    dst: scalar @ VReg::Virtual(_),
                    vec,
                    lane: extract_lane,
                    elem: VecElementType::F32,
                    sign: SignExtend::Zero,
                } => {
                    assert_eq!(vec, source1, "{case:?} lane {lane}");
                    assert_eq!(usize::from(extract_lane), lane, "{case:?}");
                    upper_scalars.push(scalar);
                }
                ref other => panic!("{case:?}: unexpected upper extraction {lane}: {other:?}"),
            }
        }
        let zero = match ops[7].kind {
            OpKind::Mov {
                dst: zero @ VReg::Virtual(_),
                src: SrcOperand::Imm(0),
                width: OpWidth::W64,
            } => zero,
            ref other => panic!("{case:?}: unexpected destination-zero value {other:?}"),
        };
        let destination = vector(case.destination, VecWidth::V128);
        assert!(
            matches!(
                ops[8].kind,
                OpKind::VBroadcast {
                    dst,
                    scalar,
                    elem: VecElementType::F32,
                    lanes: 1,
                } if dst == destination && scalar == zero
            ),
            "{case:?}: {:?}",
            ops[8].kind
        );
        assert!(
            matches!(
                ops[9].kind,
                OpKind::VInsertLane {
                    dst,
                    vec,
                    scalar,
                    lane: 0,
                    elem: VecElementType::F32,
                } if dst == destination && vec == destination && scalar == scalar_result
            ),
            "{case:?}: {:?}",
            ops[9].kind
        );
        for (lane, scalar) in upper_scalars.into_iter().enumerate() {
            let lane = lane + 1;
            assert!(
                matches!(
                    ops[9 + lane].kind,
                    OpKind::VInsertLane {
                        dst,
                        vec,
                        scalar: inserted,
                        lane: insert_lane,
                        elem: VecElementType::F32,
                    } if dst == destination
                        && vec == destination
                        && inserted == scalar
                        && usize::from(insert_lane) == lane
                ),
                "{case:?} lane {lane}: {:?}",
                ops[9 + lane].kind
            );
        }
    }

    assert_eq!(
        classified_sequence(function, true),
        Some(X86JitVexEstimateMemorySequence {
            consumed: ops.len(),
            memory_size: case.memory_size(),
            destination: case.destination,
            source1: case.source1(),
            width: case.logical_width(),
            encoded_width: case.encoded_width,
            opcode: case.estimate.opcode(),
            w: case.form.w(),
        }),
        "{case:?}"
    );
    assert_eq!(classified_sequence(function, false), None, "{case:?}");
}

fn lower(
    function: &SmirFunction,
    case: EstimateMemoryCase,
) -> (Vec<u8>, usize, X86JitVexEstimateMemorySequence) {
    let sequence = classified_sequence(function, true).expect("classified VEX estimate");
    let excluded = HashMap::new();
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
    assert!(!requirements.needs_avx2, "{case:?}");
    assert!(!requirements.needs_fma, "{case:?}");
    assert!(!requirements.needs_avx512bw, "{case:?}");
    assert!(!requirements.needs_avx512vl, "{case:?}");
    assert!(!requirements.needs_avx512dq, "{case:?}");
    #[cfg(target_arch = "x86_64")]
    assert_eq!(
        requirements.x86_host_supported(),
        std::is_x86_feature_detected!("avx")
    );

    let mut lowerer = X86_64Lowerer::new();
    lowerer.set_mem_helpers(true);
    lowerer.set_preserve_vector_mem_helpers(true);
    lowerer.set_avx_ymm16_vector_state(true);
    let result = lowerer
        .lower_function(function)
        .unwrap_or_else(|error| panic!("{case:?}: helper-backed VEX estimate failed: {error:?}"));
    assert!(result.relocations.is_empty());
    let code = lowerer
        .finalize()
        .expect("finalize helper-backed VEX estimate");
    let expected = expected_estimate_control_scope(&case.emitted_bytes());
    assert!(
        code.windows(expected.len())
            .any(|window| window == expected),
        "{case:?}: emitted bytes do not contain {expected:02X?}"
    );
    (code, result.entry_offset, sequence)
}

#[test]
fn all_1632_scanner_families_have_stable_o0_o1_o2_graphs_and_native_lowering() {
    let cases = scanner_cases();
    assert_eq!(cases.len(), 1_632);
    let mut lowered = 0usize;
    for case in cases {
        for level in LEVELS {
            let function = optimize(lift_case(case), level);
            assert_exact_sequence(&function, case);
            lower(&function, case);
            lowered += 1;
        }
    }
    assert_eq!(lowered, 1_632 * LEVELS.len());
}

#[test]
fn llvm23_canonical_complete_address_and_ignored_field_encodings_lower() {
    // The first six encodings are LLVM 23 canonical output. The final two
    // exercise complete addr32/FS/SIB/disp32 parsing and architecturally
    // ignored scalar W/L fields that assemblers canonicalize to zero.
    let encodings: &[&[u8]] = &[
        &[0xC5, 0xF8, 0x53, 0x4F, 0x20],
        &[0xC5, 0xFC, 0x53, 0x57, 0x20],
        &[0xC5, 0xF8, 0x52, 0x5F, 0x20],
        &[0xC5, 0xFC, 0x52, 0x67, 0x20],
        &[0xC5, 0xEA, 0x53, 0x6F, 0x20],
        &[0xC5, 0xCA, 0x52, 0x7F, 0x20],
        &[
            0x64, 0x67, 0xC4, 0x01, 0x12, 0x53, 0xB4, 0x7E, 0x44, 0x33, 0x22, 0x11,
        ],
        &[
            0x64, 0x67, 0xC4, 0x01, 0x96, 0x52, 0xB4, 0x7E, 0x44, 0x33, 0x22, 0x11,
        ],
    ];
    let mut lowered = 0usize;
    for bytes in encodings {
        for level in LEVELS {
            let function = optimize(lift_bytes(bytes), level);
            let sequence = classified_sequence(&function, true)
                .unwrap_or_else(|| panic!("{level:?} {bytes:02X?}: address shape rejected"));
            let case = EstimateMemoryCase {
                estimate: if sequence.opcode == 0x53 {
                    Estimate::Reciprocal
                } else {
                    Estimate::ReciprocalSqrt
                },
                shape: if sequence.source1.is_some() {
                    Shape::Scalar
                } else {
                    Shape::Packed
                },
                encoded_width: sequence.encoded_width,
                form: if sequence.w {
                    EncodingForm::C4W1
                } else {
                    EncodingForm::C5
                },
                destination: sequence.destination,
                source1: sequence.source1.unwrap_or(0),
                base: 0,
            };
            lower(&function, case);
            lowered += 1;
        }
    }
    assert_eq!(lowered, encodings.len() * LEVELS.len());
}

fn replace_instruction_bytes(function: &mut SmirFunction, bytes: &[u8]) {
    function.x86_instruction_bytes.insert(
        (BlockId(0), PC),
        X86InstructionBytes::new(bytes).expect("mutated VEX estimate metadata fits"),
    );
}

fn assert_rejected(name: &str, function: &SmirFunction) {
    assert_eq!(
        classified_sequence(function, true),
        None,
        "{name}: classifier admitted malformed VEX estimate graph"
    );
    assert!(
        !is_native_clobber_safe_excluding(function, &HashMap::new(), true),
        "{name}: native clobber gate admitted malformed VEX estimate graph"
    );
    let mut lowerer = X86_64Lowerer::new();
    lowerer.set_mem_helpers(true);
    lowerer.set_preserve_vector_mem_helpers(true);
    lowerer.set_avx_ymm16_vector_state(true);
    assert!(
        lowerer.lower_function(function).is_err(),
        "{name}: lowerer accepted malformed VEX estimate graph"
    );
}

fn arbitrary_hint() -> X86OpHint {
    X86OpHint::VecAlign(X86VecAlign::Unaligned)
}

#[test]
fn packed_graph_and_source_byte_provenance_fail_closed_for_every_invariant() {
    let case = EstimateMemoryCase {
        estimate: Estimate::ReciprocalSqrt,
        shape: Shape::Packed,
        encoded_width: VecWidth::V256,
        form: EncodingForm::C4W1,
        destination: 9,
        source1: 0,
        base: 11,
    };
    let base = optimize(lift_case(case), OptLevel::O2);
    assert_exact_sequence(&base, case);
    let loaded = match base.blocks[0].ops[0].kind {
        OpKind::VLoad { dst, .. } => dst,
        _ => unreachable!(),
    };
    let raw = match base.blocks[0].ops[1].kind {
        OpKind::VUnary { dst, .. } => dst,
        _ => unreachable!(),
    };
    let mut malformed = Vec::new();

    let mut load_hint = base.clone();
    load_hint.blocks[0].ops[0].x86_hint = Some(arbitrary_hint());
    malformed.push(("load hint", load_hint));

    let mut load_width = base.clone();
    if let OpKind::VLoad { width, .. } = &mut load_width.blocks[0].ops[0].kind {
        *width = VecWidth::V128;
    }
    malformed.push(("load width", load_width));

    let mut virtual_address = base.clone();
    if let OpKind::VLoad { addr, .. } = &mut virtual_address.blocks[0].ops[0].kind {
        *addr = Address::Direct(VReg::Virtual(VirtualId(0xE100)));
    }
    malformed.push(("virtual address", virtual_address));

    let mut extra_use = base.clone();
    extra_use.blocks[0].ops.push(SmirOp::new(
        OpId(0xE101),
        PC + 1,
        OpKind::VMov {
            dst: vector(3, VecWidth::V256),
            src: loaded,
            width: VecWidth::V256,
        },
    ));
    malformed.push(("loaded value used twice", extra_use));

    let mut second_definition = base.clone();
    second_definition.blocks[0].ops.push(SmirOp::new(
        OpId(0xE102),
        PC + 1,
        OpKind::VMov {
            dst: loaded,
            src: vector(3, VecWidth::V256),
            width: VecWidth::V256,
        },
    ));
    malformed.push(("loaded value defined twice", second_definition));

    let mut unary_source = base.clone();
    if let OpKind::VUnary { src, .. } = &mut unary_source.blocks[0].ops[1].kind {
        *src = vector(3, VecWidth::V256);
    }
    malformed.push(("unary source bypasses load", unary_source));

    let mut unary_element = base.clone();
    if let OpKind::VUnary { elem, .. } = &mut unary_element.blocks[0].ops[1].kind {
        *elem = VecElementType::F64;
    }
    malformed.push(("unary element", unary_element));

    let mut unary_lanes = base.clone();
    if let OpKind::VUnary { lanes, .. } = &mut unary_lanes.blocks[0].ops[1].kind {
        *lanes -= 1;
    }
    malformed.push(("unary lane geometry", unary_lanes));

    let mut unary_operation = base.clone();
    if let OpKind::VUnary { op, .. } = &mut unary_operation.blocks[0].ops[1].kind {
        *op = VecUnaryOp::FAbs;
    }
    malformed.push(("unary operation", unary_operation));

    let mut unary_hint = base.clone();
    unary_hint.blocks[0].ops[1].x86_hint = Some(arbitrary_hint());
    malformed.push(("unary hint", unary_hint));

    let mut unary_pc = base.clone();
    unary_pc.blocks[0].ops[1].guest_pc += 1;
    malformed.push(("unary guest PC", unary_pc));

    let mut mov_source = base.clone();
    if let OpKind::VMov { src, .. } = &mut mov_source.blocks[0].ops[2].kind {
        *src = loaded;
    }
    malformed.push(("destination move source", mov_source));

    let mut mov_destination = base.clone();
    if let OpKind::VMov { dst, .. } = &mut mov_destination.blocks[0].ops[2].kind {
        *dst = vector(16, VecWidth::V256);
    }
    malformed.push(("EVEX-only destination", mov_destination));

    let mut mov_width = base.clone();
    if let OpKind::VMov { width, .. } = &mut mov_width.blocks[0].ops[2].kind {
        *width = VecWidth::V128;
    }
    malformed.push(("destination move width", mov_width));

    let mut mov_hint = base.clone();
    mov_hint.blocks[0].ops[2].x86_hint = Some(arbitrary_hint());
    malformed.push(("destination move hint", mov_hint));

    let mut raw_extra_use = base.clone();
    raw_extra_use.blocks[0].ops.push(SmirOp::new(
        OpId(0xE103),
        PC + 1,
        OpKind::VMov {
            dst: vector(3, VecWidth::V256),
            src: raw,
            width: VecWidth::V256,
        },
    ));
    malformed.push(("raw estimate used twice", raw_extra_use));

    let mut same_pc_tail = base.clone();
    same_pc_tail.blocks[0].ops.push(SmirOp::new(
        OpId(0xE104),
        PC,
        OpKind::Mov {
            dst: VReg::Virtual(VirtualId(0xE104)),
            src: SrcOperand::Imm(0),
            width: OpWidth::W64,
        },
    ));
    malformed.push(("same-PC tail", same_pc_tail));

    let mut missing_bytes = base.clone();
    missing_bytes.x86_instruction_bytes.clear();
    malformed.push(("missing source bytes", missing_bytes));

    for (name, byte_index, xor) in [
        ("encoded map", 1, 0x03),
        ("encoded prefix", 2, 0x02),
        ("encoded width", 2, 0x04),
        ("encoded opcode", 3, 0x01),
        ("encoded destination", 4, 0x08),
        ("nonreserved packed vvvv", 2, 0x08),
    ] {
        let mut function = base.clone();
        let mut bytes = case.bytes();
        bytes[byte_index] ^= xor;
        replace_instruction_bytes(&mut function, &bytes);
        malformed.push((name, function));
    }

    let mut register_source = base.clone();
    let mut bytes = case.bytes();
    bytes[4] |= 0xC0;
    bytes.remove(5);
    replace_instruction_bytes(&mut register_source, &bytes);
    malformed.push(("encoded register source", register_source));

    let mut trailing = base.clone();
    let mut bytes = case.bytes();
    bytes.push(0);
    replace_instruction_bytes(&mut trailing, &bytes);
    malformed.push(("trailing source byte", trailing));

    for (name, function) in malformed {
        assert_rejected(name, &function);
    }
}

#[test]
fn scalar_graph_and_source_byte_provenance_fail_closed_for_every_invariant() {
    let case = EstimateMemoryCase {
        estimate: Estimate::Reciprocal,
        shape: Shape::Scalar,
        encoded_width: VecWidth::V256,
        form: EncodingForm::C4W1,
        destination: 9,
        source1: 10,
        base: 11,
    };
    let base = optimize(lift_case(case), OptLevel::O2);
    assert_exact_sequence(&base, case);
    let loaded = match base.blocks[0].ops[0].kind {
        OpKind::Load { dst, .. } => dst,
        _ => unreachable!(),
    };
    let source_vector = match base.blocks[0].ops[1].kind {
        OpKind::VBroadcast { dst, .. } => dst,
        _ => unreachable!(),
    };
    let raw = match base.blocks[0].ops[2].kind {
        OpKind::VUnary { dst, .. } => dst,
        _ => unreachable!(),
    };
    let low_scalar = match base.blocks[0].ops[3].kind {
        OpKind::VExtractLane { dst, .. } => dst,
        _ => unreachable!(),
    };
    let upper_scalar = match base.blocks[0].ops[4].kind {
        OpKind::VExtractLane { dst, .. } => dst,
        _ => unreachable!(),
    };
    let zero = match base.blocks[0].ops[7].kind {
        OpKind::Mov { dst, .. } => dst,
        _ => unreachable!(),
    };
    let mut malformed = Vec::new();

    let mut load_hint = base.clone();
    load_hint.blocks[0].ops[0].x86_hint = Some(arbitrary_hint());
    malformed.push(("scalar load hint", load_hint));

    let mut load_width = base.clone();
    if let OpKind::Load { width, .. } = &mut load_width.blocks[0].ops[0].kind {
        *width = MemWidth::B8;
    }
    malformed.push(("scalar load footprint", load_width));

    let mut load_sign = base.clone();
    if let OpKind::Load { sign, .. } = &mut load_sign.blocks[0].ops[0].kind {
        *sign = SignExtend::Sign;
    }
    malformed.push(("scalar load extension", load_sign));

    let mut virtual_address = base.clone();
    if let OpKind::Load { addr, .. } = &mut virtual_address.blocks[0].ops[0].kind {
        *addr = Address::Direct(VReg::Virtual(VirtualId(0xE200)));
    }
    malformed.push(("virtual scalar address", virtual_address));

    let mut broadcast_scalar = base.clone();
    if let OpKind::VBroadcast { scalar, .. } = &mut broadcast_scalar.blocks[0].ops[1].kind {
        *scalar = source_vector;
    }
    malformed.push(("source broadcast scalar", broadcast_scalar));

    let mut broadcast_element = base.clone();
    if let OpKind::VBroadcast { elem, .. } = &mut broadcast_element.blocks[0].ops[1].kind {
        *elem = VecElementType::F64;
    }
    malformed.push(("source broadcast element", broadcast_element));

    let mut broadcast_lanes = base.clone();
    if let OpKind::VBroadcast { lanes, .. } = &mut broadcast_lanes.blocks[0].ops[1].kind {
        *lanes = 2;
    }
    malformed.push(("source broadcast lanes", broadcast_lanes));

    let mut unary_source = base.clone();
    if let OpKind::VUnary { src, .. } = &mut unary_source.blocks[0].ops[2].kind {
        *src = loaded;
    }
    malformed.push(("scalar unary source", unary_source));

    let mut unary_element = base.clone();
    if let OpKind::VUnary { elem, .. } = &mut unary_element.blocks[0].ops[2].kind {
        *elem = VecElementType::F64;
    }
    malformed.push(("scalar unary element", unary_element));

    let mut unary_lanes = base.clone();
    if let OpKind::VUnary { lanes, .. } = &mut unary_lanes.blocks[0].ops[2].kind {
        *lanes = 2;
    }
    malformed.push(("scalar unary lanes", unary_lanes));

    let mut unary_operation = base.clone();
    if let OpKind::VUnary { op, .. } = &mut unary_operation.blocks[0].ops[2].kind {
        *op = VecUnaryOp::FNeg;
    }
    malformed.push(("scalar unary operation", unary_operation));

    let mut low_extract_source = base.clone();
    if let OpKind::VExtractLane { vec, .. } = &mut low_extract_source.blocks[0].ops[3].kind {
        *vec = source_vector;
    }
    malformed.push(("low extraction source", low_extract_source));

    let mut low_extract_lane = base.clone();
    if let OpKind::VExtractLane { lane, .. } = &mut low_extract_lane.blocks[0].ops[3].kind {
        *lane = 1;
    }
    malformed.push(("low extraction lane", low_extract_lane));

    let mut low_extract_sign = base.clone();
    if let OpKind::VExtractLane { sign, .. } = &mut low_extract_sign.blocks[0].ops[3].kind {
        *sign = SignExtend::Sign;
    }
    malformed.push(("low extraction extension", low_extract_sign));

    let mut upper_extract_source = base.clone();
    if let OpKind::VExtractLane { vec, .. } = &mut upper_extract_source.blocks[0].ops[4].kind {
        *vec = vector(11, VecWidth::V128);
    }
    malformed.push(("inconsistent merge source", upper_extract_source));

    let mut upper_extract_lane = base.clone();
    if let OpKind::VExtractLane { lane, .. } = &mut upper_extract_lane.blocks[0].ops[4].kind {
        *lane = 2;
    }
    malformed.push(("upper extraction lane", upper_extract_lane));

    let mut upper_extract_hint = base.clone();
    upper_extract_hint.blocks[0].ops[4].x86_hint = Some(arbitrary_hint());
    malformed.push(("upper extraction hint", upper_extract_hint));

    let mut zero_value = base.clone();
    if let OpKind::Mov { src, .. } = &mut zero_value.blocks[0].ops[7].kind {
        *src = SrcOperand::Imm(1);
    }
    malformed.push(("destination clear value", zero_value));

    let mut zero_width = base.clone();
    if let OpKind::Mov { width, .. } = &mut zero_width.blocks[0].ops[7].kind {
        *width = OpWidth::W32;
    }
    malformed.push(("destination clear width", zero_width));

    let mut destination_broadcast = base.clone();
    if let OpKind::VBroadcast { dst, .. } = &mut destination_broadcast.blocks[0].ops[8].kind {
        *dst = vector(8, VecWidth::V128);
    }
    malformed.push(("destination broadcast register", destination_broadcast));

    let mut destination_scalar = base.clone();
    if let OpKind::VBroadcast { scalar, .. } = &mut destination_scalar.blocks[0].ops[8].kind {
        *scalar = loaded;
    }
    malformed.push(("destination broadcast scalar", destination_scalar));

    let mut low_insert_vector = base.clone();
    if let OpKind::VInsertLane { vec, .. } = &mut low_insert_vector.blocks[0].ops[9].kind {
        *vec = vector(8, VecWidth::V128);
    }
    malformed.push(("low insert vector", low_insert_vector));

    let mut low_insert_scalar = base.clone();
    if let OpKind::VInsertLane { scalar, .. } = &mut low_insert_scalar.blocks[0].ops[9].kind {
        *scalar = upper_scalar;
    }
    malformed.push(("low insert scalar", low_insert_scalar));

    let mut upper_insert_scalar = base.clone();
    if let OpKind::VInsertLane { scalar, .. } = &mut upper_insert_scalar.blocks[0].ops[10].kind {
        *scalar = low_scalar;
    }
    malformed.push(("upper insert scalar", upper_insert_scalar));

    let mut upper_insert_lane = base.clone();
    if let OpKind::VInsertLane { lane, .. } = &mut upper_insert_lane.blocks[0].ops[10].kind {
        *lane = 2;
    }
    malformed.push(("upper insert lane", upper_insert_lane));

    let mut hidden_extra_use = base.clone();
    hidden_extra_use.blocks[0].ops.push(SmirOp::new(
        OpId(0xE201),
        PC + 1,
        OpKind::VMov {
            dst: vector(3, VecWidth::V128),
            src: raw,
            width: VecWidth::V128,
        },
    ));
    malformed.push(("hidden result used twice", hidden_extra_use));

    let mut split_pc = base.clone();
    split_pc.blocks[0].ops[8].guest_pc += 1;
    malformed.push(("split scalar guest PC", split_pc));

    let mut same_pc_tail = base.clone();
    same_pc_tail.blocks[0].ops.push(SmirOp::new(
        OpId(0xE202),
        PC,
        OpKind::Mov {
            dst: VReg::Virtual(VirtualId(0xE202)),
            src: SrcOperand::Imm(0),
            width: OpWidth::W64,
        },
    ));
    malformed.push(("same-PC scalar tail", same_pc_tail));

    let mut missing_bytes = base.clone();
    missing_bytes.x86_instruction_bytes.clear();
    malformed.push(("missing scalar source bytes", missing_bytes));

    for (name, byte_index, xor) in [
        ("encoded map", 1, 0x03),
        ("encoded prefix", 2, 0x01),
        ("encoded opcode", 3, 0x01),
        ("encoded destination", 4, 0x08),
        ("encoded scalar source1", 2, 0x08),
    ] {
        let mut function = base.clone();
        let mut bytes = case.bytes();
        bytes[byte_index] ^= xor;
        replace_instruction_bytes(&mut function, &bytes);
        malformed.push((name, function));
    }

    let mut register_source = base.clone();
    let mut bytes = case.bytes();
    bytes[4] |= 0xC0;
    bytes.remove(5);
    replace_instruction_bytes(&mut register_source, &bytes);
    malformed.push(("encoded scalar register source", register_source));

    let mut trailing = base.clone();
    let mut bytes = case.bytes();
    bytes.push(0);
    replace_instruction_bytes(&mut trailing, &bytes);
    malformed.push(("trailing scalar source byte", trailing));

    assert!(matches!(source_vector, VReg::Virtual(_)));
    assert!(matches!(zero, VReg::Virtual(_)));
    for (name, function) in malformed {
        assert_rejected(name, &function);
    }
}

#[test]
fn scalar_ignored_l_is_canonicalized_while_packed_l_and_all_w_are_preserved() {
    let mut checked = 0usize;
    for estimate in Estimate::ALL {
        for shape in Shape::ALL {
            for encoded_width in [VecWidth::V128, VecWidth::V256] {
                for form in EncodingForm::ALL {
                    let case = EstimateMemoryCase {
                        estimate,
                        shape,
                        encoded_width,
                        form,
                        destination: 14,
                        source1: 13,
                        base: if matches!(form, EncodingForm::C5) {
                            3
                        } else {
                            11
                        },
                    };
                    let function = optimize(lift_case(case), OptLevel::O2);
                    assert_exact_sequence(&function, case);
                    lower(&function, case);
                    checked += 1;
                }
            }
        }
    }
    assert_eq!(checked, 24);
}

fn expected_estimate_control_scope(instruction: &[u8]) -> Vec<u8> {
    let mut bytes = vec![
        0x48, 0x8D, 0x64, 0x24, 0xF0, 0x0F, 0xAE, 0x1C, 0x24, 0xC7, 0x44, 0x24, 0x04,
    ];
    bytes.extend_from_slice(&crate::host::x86_estimate::control().to_le_bytes());
    bytes.extend_from_slice(&[0x0F, 0xAE, 0x54, 0x24, 0x04]);
    bytes.extend_from_slice(instruction);
    bytes.extend_from_slice(&[0x0F, 0xAE, 0x14, 0x24, 0x48, 0x8D, 0x64, 0x24, 0x10]);
    bytes
}
