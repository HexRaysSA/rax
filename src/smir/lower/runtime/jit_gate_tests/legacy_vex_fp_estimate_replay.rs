//! Native replay coverage for legacy/VEX reciprocal and reciprocal-sqrt estimates.

use super::*;
use crate::smir::lower::runtime::*;

const PC: u64 = 0x5253;
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

    fn opcode(self) -> u8 {
        match self {
            Self::Reciprocal => 0x53,
            Self::ReciprocalSqrt => 0x52,
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

    fn pp(self) -> u8 {
        match self {
            Self::Packed => 0,
            Self::Scalar => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EncodingForm {
    Legacy,
    LegacyRex,
    VexC5,
    VexC4W0,
    VexC4W1IgnoredX,
}

impl EncodingForm {
    fn is_vex(self) -> bool {
        matches!(self, Self::VexC5 | Self::VexC4W0 | Self::VexC4W1IgnoredX)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EstimateInstruction {
    estimate: Estimate,
    shape: Shape,
    form: EncodingForm,
    l: bool,
    destination: u8,
    merge: u8,
    source: u8,
}

fn encoding(instruction: EstimateInstruction) -> Vec<u8> {
    assert!(instruction.destination < 16 && instruction.merge < 16 && instruction.source < 16);
    let opcode = instruction.estimate.opcode();
    let modrm = 0xC0 | ((instruction.destination & 7) << 3) | (instruction.source & 7);
    match instruction.form {
        EncodingForm::Legacy | EncodingForm::LegacyRex => {
            assert!(!instruction.l);
            if instruction.form == EncodingForm::Legacy {
                assert!(instruction.destination < 8 && instruction.source < 8);
            }
            let mut bytes = Vec::new();
            if instruction.shape == Shape::Scalar {
                bytes.push(0xF3);
            }
            if instruction.form == EncodingForm::LegacyRex {
                // W and X are ignored; R/B select the architectural registers.
                bytes.push(
                    0x4A | (u8::from(instruction.destination >= 8) << 2)
                        | u8::from(instruction.source >= 8),
                );
            }
            bytes.extend([0x0F, opcode, modrm]);
            bytes
        }
        EncodingForm::VexC5 => {
            assert!(instruction.source < 8);
            let encoded_vvvv = if instruction.shape == Shape::Packed {
                15
            } else {
                !instruction.merge & 15
            };
            vec![
                0xC5,
                (u8::from(instruction.destination < 8) << 7)
                    | (encoded_vvvv << 3)
                    | (u8::from(instruction.l) << 2)
                    | instruction.shape.pp(),
                opcode,
                modrm,
            ]
        }
        EncodingForm::VexC4W0 | EncodingForm::VexC4W1IgnoredX => {
            let mut p0 = 0xE1;
            if instruction.destination >= 8 {
                p0 &= !0x80;
            }
            if instruction.form == EncodingForm::VexC4W1IgnoredX {
                p0 &= !0x40;
            }
            if instruction.source >= 8 {
                p0 &= !0x20;
            }
            let encoded_vvvv = if instruction.shape == Shape::Packed {
                15
            } else {
                !instruction.merge & 15
            };
            vec![
                0xC4,
                p0,
                (u8::from(instruction.form == EncodingForm::VexC4W1IgnoredX) << 7)
                    | (encoded_vvvv << 3)
                    | (u8::from(instruction.l) << 2)
                    | instruction.shape.pp(),
                opcode,
                modrm,
            ]
        }
    }
}

fn function(bytes: &[u8]) -> crate::smir::ir::SmirFunction {
    use crate::smir::ir::{SmirBlock, SmirFunction, X86InstructionBytes};
    use crate::smir::lift::x86_64::X86_64Lifter;
    use crate::smir::lift::{LiftContext, SmirLifter};

    let mut lifter = X86_64Lifter::strict();
    let mut context = LiftContext::new(crate::smir::ir::types::SourceArch::X86_64);
    let result = lifter
        .lift_insn(PC, bytes, &mut context)
        .unwrap_or_else(|error| panic!("{bytes:02X?}: {error:?}"));
    assert_eq!(result.bytes_consumed, bytes.len(), "{bytes:02X?}");

    let mut block = SmirBlock::new(BlockId(0), PC);
    block.ops = result.ops;
    block.set_terminator(Terminator::Return { values: Vec::new() });
    let mut function = SmirFunction::new(FunctionId(0), block.id, PC);
    function.add_block(block);
    function
        .x86_instruction_bytes
        .insert((BlockId(0), PC), X86InstructionBytes::new(bytes).unwrap());
    function
}

fn upper_clear_postlude(destination: u8) -> Vec<u8> {
    assert!(destination < 16);
    let mut bytes = vec![0x9C, 0x50, 0x48, 0x8B, 0x45, X86_STATE_PTR_AT_RBP as u8];
    let upper = X86_GUEST_ZMM_OFFSET + i32::from(destination) * 64 + 32;
    for offset in (upper..upper + 32).step_by(8) {
        bytes.extend_from_slice(&[0x48, 0xC7, 0x80]);
        bytes.extend_from_slice(&(offset as u32).to_le_bytes());
        bytes.extend_from_slice(&[0, 0, 0, 0]);
    }
    bytes.extend_from_slice(&[0x58, 0x9D]);
    bytes
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

fn expected_replay_bytes(bytes: &[u8]) -> Vec<u8> {
    let instruction = crate::smir::ir::X86InstructionBytes::new(bytes).unwrap();
    let mut expected = bytes.to_vec();
    // Derive the canonical scalar prefix independently from the test input.
    match bytes {
        [0xC5, prefix, _, _] if prefix & 3 == 2 => expected[1] &= !4,
        [0xC4, _, prefix, _, _] if prefix & 3 == 2 => expected[2] &= !4,
        _ => {}
    }
    expected = expected_estimate_control_scope(&expected);
    if let Some(destination) = instruction.vex_fp_estimate_destination_index() {
        expected.extend_from_slice(&upper_clear_postlude(destination));
    }
    expected
}

fn assert_admitted_and_emitted(bytes: &[u8]) {
    use crate::smir::lower::SmirLowerer;
    use crate::smir::lower::x86_64::X86_64Lowerer;

    let mut function = function(bytes);
    crate::smir::optimize::optimize_function(&mut function, crate::smir::optimize::OptLevel::O2);
    assert!(is_native_clobber_safe(&function), "{bytes:02X?}");
    assert!(
        x86_native_vector_uses_avx_ymm16_only_excluding(
            &function,
            &std::collections::HashMap::new()
        ),
        "{bytes:02X?}"
    );

    let mut lowerer = X86_64Lowerer::new();
    lowerer.set_avx_ymm16_vector_state(true);
    lowerer
        .lower_function(&function)
        .unwrap_or_else(|error| panic!("{bytes:02X?}: {error:?}"));
    let code = lowerer
        .finalize()
        .unwrap_or_else(|error| panic!("{bytes:02X?}: {error:?}"));
    let expected = expected_replay_bytes(bytes);
    assert!(
        code.windows(expected.len())
            .any(|window| window == expected),
        "source={bytes:02X?} expected={expected:02X?}"
    );
}

#[test]
fn replay_features_use_the_avx_ymm16_boundary_for_legacy_and_vex_forms() {
    for instruction in [
        EstimateInstruction {
            estimate: Estimate::Reciprocal,
            shape: Shape::Packed,
            form: EncodingForm::LegacyRex,
            l: false,
            destination: 9,
            merge: 0,
            source: 11,
        },
        EstimateInstruction {
            estimate: Estimate::ReciprocalSqrt,
            shape: Shape::Scalar,
            form: EncodingForm::VexC5,
            l: true,
            destination: 9,
            merge: 10,
            source: 3,
        },
        EstimateInstruction {
            estimate: Estimate::Reciprocal,
            shape: Shape::Packed,
            form: EncodingForm::VexC4W1IgnoredX,
            l: true,
            destination: 14,
            merge: 0,
            source: 15,
        },
    ] {
        let bytes = encoding(instruction);
        let function = function(&bytes);
        let excluded = std::collections::HashMap::new();
        let requirements = x86_native_replay_feature_requirements(&function, &excluded);
        assert!(requirements.any, "{instruction:?}");
        assert!(requirements.all_spans_support_avx_ymm16, "{instruction:?}");
        // The dedicated state bridge uses AVX even for a legacy SSE source
        // instruction.
        assert!(requirements.needs_avx, "{instruction:?}");
        assert!(!requirements.needs_avx2, "{instruction:?}");
        assert!(!requirements.needs_f16c, "{instruction:?}");
        assert!(!requirements.needs_vex_fp16_narrow, "{instruction:?}");
        assert!(
            !requirements.needs_vex_unaligned_packed_fp_move,
            "{instruction:?}"
        );
        assert!(!requirements.needs_sse3, "{instruction:?}");
        assert!(!requirements.needs_fma, "{instruction:?}");
        assert!(!requirements.needs_fma4, "{instruction:?}");
        assert!(!requirements.needs_xop, "{instruction:?}");
        assert!(!requirements.needs_avx512bw, "{instruction:?}");
        assert!(!requirements.needs_avx512vl, "{instruction:?}");
        assert!(!requirements.needs_avx512dq, "{instruction:?}");
        assert!(!requirements.needs_avx512fp16, "{instruction:?}");
        assert!(!requirements.needs_avx512cd, "{instruction:?}");
        assert!(!requirements.needs_gfni, "{instruction:?}");
        assert!(!requirements.needs_avx512vp2intersect, "{instruction:?}");
        assert!(!requirements.needs_pclmulqdq, "{instruction:?}");
        assert!(!requirements.needs_vpclmulqdq, "{instruction:?}");
        assert!(x86_native_vector_uses_avx_ymm16_only_excluding(
            &function, &excluded
        ));
    }
}

#[test]
fn replay_lifts_admits_and_emits_all_82688_defined_canonical_register_images() {
    let mut emitted = 0usize;
    for scalar in [false, true] {
        for rex in std::iter::once(None).chain((0x40u8..=0x4F).map(Some)) {
            for opcode in [0x52u8, 0x53] {
                for reg_rm in 0u8..=0x3F {
                    let mut bytes = Vec::new();
                    if scalar {
                        bytes.push(0xF3);
                    }
                    if let Some(rex) = rex {
                        bytes.push(rex);
                    }
                    bytes.extend([0x0F, opcode, 0xC0 | reg_rm]);
                    assert_admitted_and_emitted(&bytes);
                    emitted += 1;
                }
            }
        }
    }

    for extension in 0u8..8 {
        let p0 = (extension << 5) | 1;
        for w in [false, true] {
            for l in [false, true] {
                for opcode in [0x52u8, 0x53] {
                    for modrm in 0xC0u8..=0xFF {
                        let packed = [
                            0xC4,
                            p0,
                            (u8::from(w) << 7) | 0x78 | (u8::from(l) << 2),
                            opcode,
                            modrm,
                        ];
                        assert_admitted_and_emitted(&packed);
                        emitted += 1;
                        for encoded_vvvv in 0u8..16 {
                            let scalar = [
                                0xC4,
                                p0,
                                (u8::from(w) << 7) | (encoded_vvvv << 3) | (u8::from(l) << 2) | 2,
                                opcode,
                                modrm,
                            ];
                            assert_admitted_and_emitted(&scalar);
                            emitted += 1;
                        }
                    }
                }
            }
        }
    }

    for encoded_r in [false, true] {
        for l in [false, true] {
            for opcode in [0x52u8, 0x53] {
                for modrm in 0xC0u8..=0xFF {
                    let packed = [
                        0xC5,
                        (u8::from(encoded_r) << 7) | 0x78 | (u8::from(l) << 2),
                        opcode,
                        modrm,
                    ];
                    assert_admitted_and_emitted(&packed);
                    emitted += 1;
                    for encoded_vvvv in 0u8..16 {
                        let scalar = [
                            0xC5,
                            (u8::from(encoded_r) << 7)
                                | (encoded_vvvv << 3)
                                | (u8::from(l) << 2)
                                | 2,
                            opcode,
                            modrm,
                        ];
                        assert_admitted_and_emitted(&scalar);
                        emitted += 1;
                    }
                }
            }
        }
    }
    assert_eq!(emitted, 82_688);
}

#[test]
fn replay_fails_closed_without_exact_defined_source_provenance() {
    let scalar = encoding(EstimateInstruction {
        estimate: Estimate::Reciprocal,
        shape: Shape::Scalar,
        form: EncodingForm::VexC4W1IgnoredX,
        l: true,
        destination: 12,
        merge: 13,
        source: 14,
    });
    let base = function(&scalar);
    let mut candidates = Vec::new();
    let mut missing = base.clone();
    missing.x86_instruction_bytes.clear();
    candidates.push(missing);

    for invalid in [
        {
            let mut bytes = scalar.clone();
            bytes[1] = (bytes[1] & 0xE0) | 2; // Map 0F38.
            bytes
        },
        {
            let mut bytes = scalar.clone();
            bytes[2] = (bytes[2] & !3) | 1; // Wrong mandatory prefix.
            bytes
        },
        {
            let mut bytes = scalar.clone();
            bytes[3] = 0; // Non-family opcode.
            bytes
        },
        {
            let mut bytes = scalar.clone();
            bytes[4] &= 0x3F; // Memory source.
            bytes
        },
        vec![0xC5, 0x70, 0x53, 0xC1], // Packed reserved VEX.vvvv.
    ] {
        let mut malformed = base.clone();
        malformed.x86_instruction_bytes.insert(
            (BlockId(0), PC),
            crate::smir::ir::X86InstructionBytes::new(&invalid).unwrap(),
        );
        candidates.push(malformed);
    }

    for mut candidate in candidates {
        crate::smir::optimize::optimize_function(
            &mut candidate,
            crate::smir::optimize::OptLevel::O2,
        );
        assert!(!is_native_clobber_safe(&candidate));
        assert!(
            !x86_native_replay_feature_requirements(&candidate, &std::collections::HashMap::new())
                .any
        );
    }
}

#[cfg(target_arch = "x86_64")]
#[derive(Clone, Debug, PartialEq, Eq)]
struct EstimateState {
    gprs: [u64; 32],
    vectors: [[u64; 8]; 32],
    masks: [u64; 8],
    rflags: u64,
    mxcsr: u32,
}

#[cfg(target_arch = "x86_64")]
fn set_f32_lane(vector: &mut [u64; 8], lane: u8, value: u32) {
    let word = usize::from(lane / 2);
    let shift = u32::from(lane & 1) * 32;
    vector[word] = (vector[word] & !(u64::from(u32::MAX) << shift)) | (u64::from(value) << shift);
}

#[cfg(target_arch = "x86_64")]
fn get_f32_lane(vector: &[u64; 8], lane: u8) -> u32 {
    let word = usize::from(lane / 2);
    let shift = u32::from(lane & 1) * 32;
    (vector[word] >> shift) as u32
}

#[cfg(target_arch = "x86_64")]
fn active_lanes(instruction: EstimateInstruction) -> u8 {
    match instruction.shape {
        Shape::Scalar => 1,
        Shape::Packed if instruction.l => 8,
        Shape::Packed => 4,
    }
}

#[cfg(target_arch = "x86_64")]
fn initial_state(instruction: EstimateInstruction, ordinal: usize) -> EstimateState {
    const INPUTS: [u32; 16] = [
        7.0f32.to_bits(),
        3.0f32.to_bits(),
        4.0f32.to_bits(),
        (-11.0f32).to_bits(),
        0,
        0x8000_0000,
        1,
        0x8000_0001,
        f32::INFINITY.to_bits(),
        f32::NEG_INFINITY.to_bits(),
        0x7FC1_2345,
        0xFF81_2345,
        f32::MAX.to_bits(),
        f32::MIN_POSITIVE.to_bits(),
        0.5f32.to_bits(),
        (-0.5f32).to_bits(),
    ];
    let mut vectors: [[u64; 8]; 32] = std::array::from_fn(|register| {
        std::array::from_fn(|word| {
            0xF0E1_D2C3_B4A5_9687u64.rotate_left((register * 11 + word * 5) as u32)
                ^ (register as u64).wrapping_mul(0x1111_2222_3333_4444)
                ^ (ordinal as u64).wrapping_mul(0x0102_0408_1020_4081)
        })
    });
    for lane in 0..8u8 {
        set_f32_lane(
            &mut vectors[usize::from(instruction.source)],
            lane,
            INPUTS[(ordinal + usize::from(lane)) % INPUTS.len()],
        );
    }
    EstimateState {
        gprs: std::array::from_fn(|register| {
            0x0123_4567_89AB_CDEFu64.rotate_left((register * 7) as u32)
                ^ (register as u64).wrapping_mul(0x1020_4081_0204_0810)
        }),
        vectors,
        masks: [
            0x6996_F00F_3CC3_A55A,
            0,
            1,
            0x0123_4567_89AB_CDEF,
            0x5555_AAAA_3333_CCCC,
            0x8000_0000_0000_0000,
            0xF0F0_0F0F_A5A5_5A5A,
            u64::MAX,
        ],
        rflags: 0x2 | 0x8D5,
        // These instructions report no SIMD exceptions and ignore RC, but
        // vary every guest control/status field while retaining all masks.
        mxcsr: 0x1F80
            | (1 << (ordinal % 6))
            | (((ordinal & 3) as u32) << 13)
            | if ordinal & 1 == 0 {
                0
            } else {
                (1 << 6) | (1 << 15)
            },
    }
}

#[cfg(target_arch = "x86_64")]
fn optimized_function(
    bytes: &[u8],
    level: crate::smir::optimize::OptLevel,
    halt: bool,
) -> crate::smir::ir::SmirFunction {
    let mut function = function(bytes);
    if halt {
        function.blocks[0].set_terminator(Terminator::Trap {
            kind: crate::smir::ir::TrapKind::Halt,
        });
    }
    crate::smir::optimize::optimize_function(&mut function, level);
    function
}

#[cfg(target_arch = "x86_64")]
fn interpret(
    bytes: &[u8],
    initial: &EstimateState,
    level: crate::smir::optimize::OptLevel,
) -> EstimateState {
    use crate::smir::interpret::{BlockResult, SmirInterpreter};
    use crate::smir::ir::context::{ArchRegState, ExitReason, SmirContext};
    use crate::smir::ir::memory::FlatMemory;

    let function = optimized_function(bytes, level, true);
    let mut context = SmirContext::new_x86_64();
    if let ArchRegState::X86_64(x86) = &mut context.arch_regs {
        x86.gpr = initial.gprs;
        for (index, value) in initial.vectors.iter().enumerate() {
            x86.xmm[index][..8].copy_from_slice(value);
        }
        x86.k = initial.masks;
        x86.rflags = initial.rflags;
        x86.mxcsr = initial.mxcsr;
    }
    let result = SmirInterpreter::new().execute_block(
        &mut context,
        &mut FlatMemory::new(1),
        &function.blocks[0],
    );
    assert!(matches!(result, BlockResult::Exit(ExitReason::Halt)));

    let ArchRegState::X86_64(x86) = &context.arch_regs else {
        unreachable!()
    };
    let mut vectors = [[0u64; 8]; 32];
    for (index, value) in vectors.iter_mut().enumerate() {
        value.copy_from_slice(&x86.xmm[index][..8]);
    }
    EstimateState {
        gprs: x86.gpr,
        vectors,
        masks: x86.k,
        rflags: x86.rflags,
        mxcsr: x86.mxcsr,
    }
}

#[cfg(target_arch = "x86_64")]
fn execute_native(
    bytes: &[u8],
    initial: &EstimateState,
    level: crate::smir::optimize::OptLevel,
) -> EstimateState {
    use crate::smir::lower::SmirLowerer;
    use crate::smir::lower::x86_64::X86_64Lowerer;

    let function = optimized_function(bytes, level, false);
    let mut lowerer = X86_64Lowerer::new();
    lowerer.set_avx_ymm16_vector_state(true);
    let lowered = lowerer
        .lower_function(&function)
        .unwrap_or_else(|error| panic!("{level:?} {bytes:02X?}: {error:?}"));
    let code = lowerer
        .finalize()
        .unwrap_or_else(|error| panic!("{level:?} {bytes:02X?}: {error:?}"));
    let expected = expected_replay_bytes(bytes);
    assert!(
        code.windows(expected.len())
            .any(|window| window == expected),
        "{level:?} source={bytes:02X?} expected={expected:02X?}"
    );
    let exec = ExecMem::new(&code).expect("map legacy/VEX reciprocal-estimate replay");
    let mut registers = GuestRegs {
        gpr: initial.gprs,
        rflags: initial.rflags,
        vector_active: X86_VECTOR_STATE_YMM16,
        k: initial.masks,
        mxcsr: initial.mxcsr,
        ..GuestRegs::default()
    };
    for (index, value) in initial.vectors.iter().enumerate() {
        registers.set_zmm(index, *value);
    }
    exec.run(lowered.entry_offset, &mut registers);

    let mut vectors = [[0u64; 8]; 32];
    for (index, value) in vectors.iter_mut().enumerate() {
        *value = registers.get_zmm(index);
    }
    EstimateState {
        gprs: registers.gpr,
        vectors,
        masks: registers.k,
        rflags: registers.rflags,
        mxcsr: registers.mxcsr,
    }
}

#[cfg(target_arch = "x86_64")]
fn assert_intel_estimate(estimate: Estimate, input: u32, output: u32) {
    let sign = input & 0x8000_0000;
    let exponent = input & 0x7F80_0000;
    let fraction = input & 0x007F_FFFF;
    if exponent == 0 {
        assert_eq!(output, sign | 0x7F80_0000, "input={input:08X}");
        return;
    }
    if exponent == 0x7F80_0000 && fraction != 0 {
        assert_eq!(output, input | 0x0040_0000, "input={input:08X}");
        return;
    }
    if estimate == Estimate::ReciprocalSqrt && sign != 0 {
        assert_eq!(output, 0xFFC0_0000, "input={input:08X}");
        return;
    }
    if exponent == 0x7F80_0000 {
        assert_eq!(
            output,
            if estimate == Estimate::Reciprocal {
                sign
            } else {
                0
            },
            "input={input:08X}"
        );
        return;
    }

    let value = f64::from(f32::from_bits(input));
    let exact = if estimate == Estimate::Reciprocal {
        1.0 / value
    } else {
        1.0 / value.sqrt()
    };
    if exact.abs() < f64::from(f32::MIN_POSITIVE) {
        assert_eq!(output, sign, "tiny input={input:08X}");
        return;
    }
    let actual = f64::from(f32::from_bits(output));
    let relative_error = ((actual - exact) / exact).abs();
    assert!(
        relative_error <= INTEL_RELATIVE_ERROR_BOUND,
        "input={input:08X} output={output:08X} error={relative_error:e} \
         bound={INTEL_RELATIVE_ERROR_BOUND:e}"
    );
}

#[cfg(target_arch = "x86_64")]
fn assert_native_and_smir_are_architecturally_equivalent(
    instruction: EstimateInstruction,
    initial: &EstimateState,
    mut native: EstimateState,
    mut interpreted: EstimateState,
) {
    let destination = usize::from(instruction.destination);
    let source = usize::from(instruction.source);
    for lane in 0..active_lanes(instruction) {
        let input = get_f32_lane(&initial.vectors[source], lane);
        assert_intel_estimate(
            instruction.estimate,
            input,
            get_f32_lane(&native.vectors[destination], lane),
        );
        assert_intel_estimate(
            instruction.estimate,
            input,
            get_f32_lane(&interpreted.vectors[destination], lane),
        );
        set_f32_lane(&mut native.vectors[destination], lane, 0);
        set_f32_lane(&mut interpreted.vectors[destination], lane, 0);
    }
    // Intel constrains finite estimate error but does not select one unique bit
    // pattern. After masking only those result lanes, every other architectural
    // bit must agree exactly.
    assert_eq!(native, interpreted, "{instruction:?}");
}

#[cfg(target_arch = "x86_64")]
fn native_cases() -> Vec<EstimateInstruction> {
    let mut cases = Vec::new();
    for estimate in Estimate::ALL {
        for shape in Shape::ALL {
            for form in [
                EncodingForm::Legacy,
                EncodingForm::LegacyRex,
                EncodingForm::VexC5,
                EncodingForm::VexC4W0,
                EncodingForm::VexC4W1IgnoredX,
            ] {
                let lengths: &[bool] = if form.is_vex() {
                    &[false, true]
                } else {
                    &[false]
                };
                for &l in lengths {
                    let operands: &[(u8, u8, u8)] = match form {
                        EncodingForm::Legacy => &[(1, 0, 3), (1, 0, 1)],
                        EncodingForm::LegacyRex => &[(9, 0, 11), (9, 0, 9)],
                        EncodingForm::VexC5 => &[(1, 2, 3), (9, 10, 3), (1, 1, 2), (1, 2, 1)],
                        EncodingForm::VexC4W0 | EncodingForm::VexC4W1IgnoredX => {
                            &[(1, 2, 3), (9, 10, 11), (1, 1, 2), (1, 2, 1)]
                        }
                    };
                    for &(destination, merge, source) in operands {
                        cases.push(EstimateInstruction {
                            estimate,
                            shape,
                            form,
                            l,
                            destination,
                            merge,
                            source,
                        });
                    }
                }
            }
        }
    }
    assert_eq!(cases.len(), 112);
    cases
}

#[cfg(target_arch = "x86_64")]
const CHILD_RANGE_ENV: &str = "RAX_LEGACY_VEX_FP_ESTIMATE_CHILD_RANGE";

#[cfg(target_arch = "x86_64")]
fn child_range() -> Option<std::ops::Range<usize>> {
    let value = std::env::var(CHILD_RANGE_ENV).ok()?;
    let (start, end) = value
        .split_once(':')
        .unwrap_or_else(|| panic!("invalid {CHILD_RANGE_ENV}: {value}"));
    Some(
        start
            .parse::<usize>()
            .unwrap_or_else(|_| panic!("invalid {CHILD_RANGE_ENV} start: {value}"))
            ..end
                .parse::<usize>()
                .unwrap_or_else(|_| panic!("invalid {CHILD_RANGE_ENV} end: {value}")),
    )
}

#[cfg(target_arch = "x86_64")]
fn execute_native_case_range(cases: &[EstimateInstruction], range: std::ops::Range<usize>) {
    assert!(range.start < range.end && range.end <= cases.len());
    for (ordinal, &instruction) in cases.iter().enumerate().take(range.end).skip(range.start) {
        let bytes = encoding(instruction);
        let initial = initial_state(instruction, ordinal);
        for level in [
            crate::smir::optimize::OptLevel::O0,
            crate::smir::optimize::OptLevel::O2,
        ] {
            assert_native_and_smir_are_architecturally_equivalent(
                instruction,
                &initial,
                execute_native(&bytes, &initial, level),
                interpret(&bytes, &initial, level),
            );
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn run_child_range(test_name: &str, range: std::ops::Range<usize>) -> std::process::Output {
    std::process::Command::new(std::env::current_exe().expect("current unit-test executable"))
        .arg(test_name)
        .arg("--exact")
        .arg("--nocapture")
        .env(CHILD_RANGE_ENV, format!("{}:{}", range.start, range.end))
        .output()
        .expect("run isolated native legacy/VEX reciprocal-estimate differential")
}

#[cfg(target_arch = "x86_64")]
fn run_isolated_native_differential(test_name: &str) {
    let cases = native_cases();
    if let Some(range) = child_range() {
        execute_native_case_range(&cases, range);
        return;
    }

    let whole = run_child_range(test_name, 0..cases.len());
    if whole.status.success() {
        return;
    }
    let mut start = 0usize;
    let mut end = cases.len();
    while end - start > 1 {
        let middle = start + (end - start) / 2;
        if run_child_range(test_name, start..middle).status.success() {
            start = middle;
        } else {
            end = middle;
        }
    }
    let singleton = run_child_range(test_name, start..end);
    let instruction = cases[start];
    let bytes = encoding(instruction);
    panic!(
        "isolated native legacy/VEX reciprocal-estimate failure at case {start}/{}: \
         {instruction:?} {bytes:02X?}; whole status {}; singleton status {}; \
         singleton stdout: {}; singleton stderr: {}",
        cases.len(),
        whole.status,
        singleton.status,
        String::from_utf8_lossy(&singleton.stdout),
        String::from_utf8_lossy(&singleton.stderr),
    );
}

#[cfg(target_arch = "x86_64")]
#[test]
fn replay_obeys_intel_error_bound_special_cases_merges_and_full_state_at_o0_o2() {
    if !std::is_x86_feature_detected!("avx") {
        eprintln!("skipping native legacy/VEX estimate differential: host lacks AVX");
        return;
    }
    run_isolated_native_differential(
        "smir::lower::runtime::jit_gate_tests::legacy_vex_fp_estimate_replay::\
         replay_obeys_intel_error_bound_special_cases_merges_and_full_state_at_o0_o2",
    );
}
