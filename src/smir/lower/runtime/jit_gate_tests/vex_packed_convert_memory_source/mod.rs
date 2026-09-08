//! Exact helper-backed VEX packed-conversion memory-source coverage.

use super::*;
use crate::smir::ir::ops::{OpKind, SmirOp, X86OpHint, X86SsePrefix, X86VecAlign, X86VecMap};
use crate::smir::ir::types::{
    Address, ArchReg, BlockId, FpRoundMode, FunctionId, OpId, VReg, VecElementType, VecWidth,
    VirtualId, X86Reg,
};
use crate::smir::ir::{
    SmirBlock, SmirFunction, Terminator, X86InstructionBytes, X86VexPackedConvertMemoryEncoding,
    X86VexPackedConvertMemoryKind,
};
use crate::smir::lift::x86_64::X86_64Lifter;
use crate::smir::lift::{ControlFlow, LiftContext, SmirLifter};
use crate::smir::lower::runtime::{
    X86JitVexPackedConvertMemorySequence, X86NativeReplayFeatureRequirements,
    is_native_clobber_safe_excluding, is_x86_aarch64_native_clobber_safe_excluding,
    uses_x86_native_vectors_excluding, x86_jit_vex_packed_convert_memory_sequence,
    x86_native_replay_feature_requirements, x86_native_vector_uses_avx_ymm16_only_excluding,
};
use crate::smir::lower::x86_64::X86_64Lowerer;
use crate::smir::lower::{SmirLowerer, X86_GUEST_VECTOR_SCRATCH_OFFSET};
use crate::smir::optimize::OptLevel;
use std::collections::HashMap;

mod semantics;

const PC: u64 = 0x5A5B_E600;
const DISP: i64 = 0x20;
const LEVELS: [OptLevel; 3] = [OptLevel::O0, OptLevel::O1, OptLevel::O2];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConvertKind {
    F16ToF32,
    F32ToF64,
    F64ToF32,
    I32ToF32,
    I32ToF64,
    F32ToI32,
    F32ToI32Truncate,
    F64ToI32,
    F64ToI32Truncate,
}

impl ConvertKind {
    const ALL: [Self; 9] = [
        Self::F16ToF32,
        Self::F32ToF64,
        Self::F64ToF32,
        Self::I32ToF32,
        Self::I32ToF64,
        Self::F32ToI32,
        Self::F32ToI32Truncate,
        Self::F64ToI32,
        Self::F64ToI32Truncate,
    ];

    const fn pp(self) -> u8 {
        match self {
            Self::F16ToF32 => 1,
            Self::F32ToF64 | Self::I32ToF32 => 0,
            Self::F64ToF32 | Self::F32ToI32 | Self::F64ToI32Truncate => 1,
            Self::F32ToI32Truncate | Self::I32ToF64 => 2,
            Self::F64ToI32 => 3,
        }
    }

    const fn map(self) -> X86VecMap {
        match self {
            Self::F16ToF32 => X86VecMap::Map0F38,
            _ => X86VecMap::Map0F,
        }
    }

    const fn map_code(self) -> u8 {
        match self.map() {
            X86VecMap::Map0F => 1,
            X86VecMap::Map0F38 => 2,
            _ => unreachable!(),
        }
    }

    const fn prefix(self) -> X86SsePrefix {
        match self.pp() {
            0 => X86SsePrefix::None,
            1 => X86SsePrefix::OpSize,
            2 => X86SsePrefix::Rep,
            3 => X86SsePrefix::Repne,
            _ => unreachable!(),
        }
    }

    const fn opcode(self) -> u8 {
        match self {
            Self::F16ToF32 => 0x13,
            Self::F32ToF64 | Self::F64ToF32 => 0x5A,
            Self::I32ToF32 | Self::F32ToI32 | Self::F32ToI32Truncate => 0x5B,
            Self::I32ToF64 | Self::F64ToI32 | Self::F64ToI32Truncate => 0xE6,
        }
    }

    const fn expected_kind(self) -> X86VexPackedConvertMemoryKind {
        match self {
            Self::F16ToF32 => X86VexPackedConvertMemoryKind::FpPrecision {
                from: VecElementType::F16,
                to: VecElementType::F32,
            },
            Self::F32ToF64 => X86VexPackedConvertMemoryKind::FpPrecision {
                from: VecElementType::F32,
                to: VecElementType::F64,
            },
            Self::F64ToF32 => X86VexPackedConvertMemoryKind::FpPrecision {
                from: VecElementType::F64,
                to: VecElementType::F32,
            },
            Self::I32ToF32 => X86VexPackedConvertMemoryKind::IntToFp {
                fp_elem: VecElementType::F32,
            },
            Self::I32ToF64 => X86VexPackedConvertMemoryKind::IntToFp {
                fp_elem: VecElementType::F64,
            },
            Self::F32ToI32 => X86VexPackedConvertMemoryKind::FpToInt {
                fp_elem: VecElementType::F32,
                truncate: false,
            },
            Self::F32ToI32Truncate => X86VexPackedConvertMemoryKind::FpToInt {
                fp_elem: VecElementType::F32,
                truncate: true,
            },
            Self::F64ToI32 => X86VexPackedConvertMemoryKind::FpToInt {
                fp_elem: VecElementType::F64,
                truncate: false,
            },
            Self::F64ToI32Truncate => X86VexPackedConvertMemoryKind::FpToInt {
                fp_elem: VecElementType::F64,
                truncate: true,
            },
        }
    }

    const fn source_elem(self) -> VecElementType {
        match self {
            Self::F16ToF32 => VecElementType::F16,
            Self::F32ToF64
            | Self::I32ToF32
            | Self::I32ToF64
            | Self::F32ToI32
            | Self::F32ToI32Truncate => {
                if matches!(self, Self::I32ToF32 | Self::I32ToF64) {
                    VecElementType::I32
                } else {
                    VecElementType::F32
                }
            }
            Self::F64ToF32 | Self::F64ToI32 | Self::F64ToI32Truncate => VecElementType::F64,
        }
    }

    const fn truncates(self) -> bool {
        matches!(self, Self::F32ToI32Truncate | Self::F64ToI32Truncate)
    }

    const fn forms(self) -> &'static [VexForm] {
        match self {
            Self::F16ToF32 => &VexForm::C4_W0_ONLY,
            _ => &VexForm::ALL,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VexForm {
    C5,
    C4W0,
    C4W1,
}

impl VexForm {
    const ALL: [Self; 3] = [Self::C5, Self::C4W0, Self::C4W1];
    const C4_W0_ONLY: [Self; 1] = [Self::C4W0];

    const fn w(self) -> bool {
        matches!(self, Self::C4W1)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ConvertCase {
    kind: ConvertKind,
    width: VecWidth,
    form: VexForm,
    destination: u8,
    base: u8,
}

impl ConvertCase {
    fn source_width(self) -> VecWidth {
        match self.kind {
            ConvertKind::F16ToF32 | ConvertKind::F32ToF64 | ConvertKind::I32ToF64 => {
                if self.width == VecWidth::V128 {
                    VecWidth::V64
                } else {
                    VecWidth::V128
                }
            }
            _ => self.width,
        }
    }

    fn destination_width(self) -> VecWidth {
        match self.kind {
            ConvertKind::F64ToF32 | ConvertKind::F64ToI32 | ConvertKind::F64ToI32Truncate => {
                VecWidth::V128
            }
            _ => self.width,
        }
    }

    fn lanes(self) -> u8 {
        (self.width.bytes()
            / match self.kind {
                ConvertKind::F32ToF64
                | ConvertKind::F64ToF32
                | ConvertKind::I32ToF64
                | ConvertKind::F64ToI32
                | ConvertKind::F64ToI32Truncate => 8,
                _ => 4,
            }) as u8
    }

    fn scratch(self) -> u8 {
        (0..8)
            .find(|candidate| *candidate != self.destination)
            .expect("one destination leaves seven low scratch registers")
    }

    fn bytes(self) -> Vec<u8> {
        assert!(matches!(self.width, VecWidth::V128 | VecWidth::V256));
        assert!(self.destination < 16 && self.base < 16);
        let l = u8::from(self.width == VecWidth::V256);
        let encoded_reg = (self.destination & 7) << 3;
        let rm = self.base & 7;
        let modrm = 0x40 | encoded_reg | if rm == 4 { 4 } else { rm };
        let mut bytes = match self.form {
            VexForm::C5 => {
                assert_eq!(self.kind.map(), X86VecMap::Map0F);
                assert!(self.base < 8);
                vec![
                    0xC5,
                    (if self.destination < 8 { 0x80 } else { 0 })
                        | 0x78
                        | (l << 2)
                        | self.kind.pp(),
                    self.kind.opcode(),
                    modrm,
                ]
            }
            VexForm::C4W0 | VexForm::C4W1 => vec![
                0xC4,
                (if self.destination < 8 { 0x80 } else { 0 })
                    | 0x40
                    | (if self.base < 8 { 0x20 } else { 0 })
                    | self.kind.map_code(),
                (u8::from(self.form.w()) << 7) | 0x78 | (l << 2) | self.kind.pp(),
                self.kind.opcode(),
                modrm,
            ],
        };
        if rm == 4 {
            bytes.push(0x24);
        }
        bytes.push(DISP as u8);
        bytes
    }

    fn expected_replay_bytes(self) -> Vec<u8> {
        let l = u8::from(self.width == VecWidth::V256);
        let modrm = 0xC0 | ((self.destination & 7) << 3) | self.scratch();
        match self.form {
            VexForm::C5 => {
                assert_eq!(self.kind.map(), X86VecMap::Map0F);
                vec![
                    0xC5,
                    (if self.destination < 8 { 0x80 } else { 0 })
                        | 0x78
                        | (l << 2)
                        | self.kind.pp(),
                    self.kind.opcode(),
                    modrm,
                ]
            }
            VexForm::C4W0 | VexForm::C4W1 => vec![
                0xC4,
                (if self.destination < 8 { 0x80 } else { 0 }) | 0x60 | self.kind.map_code(),
                (u8::from(self.form.w()) << 7) | 0x78 | (l << 2) | self.kind.pp(),
                self.kind.opcode(),
                modrm,
            ],
        }
    }

    fn expected_encoding(self) -> X86VexPackedConvertMemoryEncoding {
        X86VexPackedConvertMemoryEncoding {
            kind: self.kind.expected_kind(),
            map: self.kind.map(),
            destination: self.destination,
            scratch: self.scratch(),
            source_width: self.source_width(),
            destination_width: self.destination_width(),
            operation_width: self.width,
            memory_size: self.source_width().bytes(),
            w: self.form.w(),
            pp: self.kind.pp(),
            opcode: self.kind.opcode(),
            register_instruction: X86InstructionBytes::new(&self.expected_replay_bytes()).unwrap(),
        }
    }
}

fn scanner_cases() -> Vec<ConvertCase> {
    let mut cases = Vec::new();
    for kind in ConvertKind::ALL {
        for width in [VecWidth::V128, VecWidth::V256] {
            for &form in kind.forms() {
                for destination in 0..8 {
                    cases.push(ConvertCase {
                        kind,
                        width,
                        form,
                        destination,
                        base: 2,
                    });
                }
            }
        }
    }
    assert_eq!(cases.len(), 400);
    cases
}

fn x86(reg: X86Reg) -> VReg {
    VReg::Arch(ArchReg::X86(reg))
}

fn vector(index: u8, width: VecWidth) -> VReg {
    x86(match width {
        VecWidth::V128 => X86Reg::Xmm(index),
        VecWidth::V256 => X86Reg::Ymm(index),
        _ => unreachable!("classic VEX conversion vector width"),
    })
}

fn expected_address(case: ConvertCase) -> Address {
    Address::BaseOffset {
        base: x86(X86Reg::gpr(case.base)),
        offset: DISP,
        disp_size: crate::smir::ir::types::DispSize::Disp8,
    }
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
        X86InstructionBytes::new(bytes).expect("VEX packed conversion fits metadata"),
    );
    function
}

fn lift_case(case: ConvertCase) -> SmirFunction {
    lift_bytes(&case.bytes())
}

fn optimize(mut function: SmirFunction, level: OptLevel) -> SmirFunction {
    crate::smir::optimize::optimize_function(&mut function, level);
    function
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
) -> Option<X86JitVexPackedConvertMemorySequence> {
    let block = &function.blocks[0];
    let (definitions, uses) = virtual_counts(block);
    x86_jit_vex_packed_convert_memory_sequence(
        block,
        0,
        allow_mem,
        &function.x86_instruction_bytes,
        &definitions,
        &uses,
    )
}

fn assert_exact_lift_and_sequence(function: &SmirFunction, case: ConvertCase, level: OptLevel) {
    let block = &function.blocks[0];
    assert_eq!(block.ops.len(), 2, "{case:?}");
    assert!(block.ops.iter().all(|op| op.guest_pc == PC), "{case:?}");
    let loaded = match &block.ops[0].kind {
        OpKind::VLoad {
            dst: loaded @ VReg::Virtual(_),
            addr,
            width,
        } => {
            assert_eq!(addr, &expected_address(case), "{case:?}");
            assert_eq!(*width, case.source_width(), "{case:?}");
            // Byte provenance owns the absent encoding hint at every level.
            // An incoming RSP/RBP value has no proven local alignment.
            assert_eq!(block.ops[0].x86_hint, None, "{case:?} at {level:?}");
            *loaded
        }
        other => panic!("{case:?}: expected VLoad, got {other:?}"),
    };
    assert_eq!(
        block.ops[1].x86_hint,
        Some(X86OpHint::VexOp {
            map: case.kind.map(),
            pp: case.kind.prefix(),
            opcode: case.kind.opcode(),
            width: case.width,
            w: case.form.w(),
        }),
        "{case:?}"
    );
    let expected_dst = vector(case.destination, case.destination_width());
    match (&block.ops[1].kind, case.kind.expected_kind()) {
        (
            OpKind::X86PackedFpConvert {
                dst,
                src,
                mask,
                from,
                to,
                lanes,
                dst_width,
                mask_zeroing,
                zero_upper,
                round,
                suppress_exceptions,
                report_fp16_denormal,
            },
            X86VexPackedConvertMemoryKind::FpPrecision {
                from: expected_from,
                to: expected_to,
            },
        ) => {
            assert_eq!(*dst, expected_dst, "{case:?}");
            assert_eq!(*src, loaded, "{case:?}");
            assert_eq!(*mask, None, "{case:?}");
            assert_eq!((*from, *to), (expected_from, expected_to), "{case:?}");
            assert_eq!(*lanes, case.lanes(), "{case:?}");
            assert_eq!(*dst_width, case.destination_width(), "{case:?}");
            assert!(!*mask_zeroing && *zero_upper, "{case:?}");
            assert_eq!(*round, FpRoundMode::Dynamic, "{case:?}");
            assert!(!*suppress_exceptions && !*report_fp16_denormal, "{case:?}");
        }
        (
            OpKind::X86PackedIntToFp {
                dst,
                src,
                mask,
                int_elem,
                fp_elem,
                signed,
                lanes,
                src_width,
                dst_width,
                mask_zeroing,
                zero_upper,
                round,
                suppress_exceptions,
            },
            X86VexPackedConvertMemoryKind::IntToFp {
                fp_elem: expected_fp,
            },
        ) => {
            assert_eq!(*dst, expected_dst, "{case:?}");
            assert_eq!(*src, loaded, "{case:?}");
            assert_eq!(*mask, None, "{case:?}");
            assert_eq!(*int_elem, VecElementType::I32, "{case:?}");
            assert_eq!(*fp_elem, expected_fp, "{case:?}");
            assert!(*signed, "{case:?}");
            assert_eq!(*lanes, case.lanes(), "{case:?}");
            assert_eq!(*src_width, case.source_width(), "{case:?}");
            assert_eq!(*dst_width, case.destination_width(), "{case:?}");
            assert!(!*mask_zeroing && *zero_upper, "{case:?}");
            assert_eq!(*round, FpRoundMode::Dynamic, "{case:?}");
            assert!(!*suppress_exceptions, "{case:?}");
        }
        (
            OpKind::X86PackedFpToInt {
                dst,
                src,
                mask,
                fp_elem,
                int_elem,
                signed,
                truncate,
                lanes,
                src_width,
                dst_width,
                mask_zeroing,
                zero_upper,
                round,
                suppress_exceptions,
            },
            X86VexPackedConvertMemoryKind::FpToInt {
                fp_elem: expected_fp,
                truncate: expected_truncate,
            },
        ) => {
            assert_eq!(*dst, expected_dst, "{case:?}");
            assert_eq!(*src, loaded, "{case:?}");
            assert_eq!(*mask, None, "{case:?}");
            assert_eq!(*fp_elem, expected_fp, "{case:?}");
            assert_eq!(*int_elem, VecElementType::I32, "{case:?}");
            assert!(*signed, "{case:?}");
            assert_eq!(*truncate, expected_truncate, "{case:?}");
            assert_eq!(*lanes, case.lanes(), "{case:?}");
            assert_eq!(*src_width, case.source_width(), "{case:?}");
            assert_eq!(*dst_width, case.destination_width(), "{case:?}");
            assert!(!*mask_zeroing && *zero_upper, "{case:?}");
            assert_eq!(
                *round,
                if expected_truncate {
                    FpRoundMode::RoundTowardZero
                } else {
                    FpRoundMode::Dynamic
                },
                "{case:?}"
            );
            assert!(!*suppress_exceptions, "{case:?}");
        }
        (actual, expected) => panic!("{case:?}: {actual:?} does not match {expected:?}"),
    }
    assert_eq!(
        classified_sequence(function, true),
        Some(X86JitVexPackedConvertMemorySequence {
            consumed: 2,
            encoding: case.expected_encoding(),
        }),
        "{case:?}"
    );
    assert_eq!(classified_sequence(function, false), None, "{case:?}");
}

fn assert_feature_requirements(function: &SmirFunction, case: ConvertCase) {
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

    let mut expected = X86NativeReplayFeatureRequirements::default();
    expected.any = true;
    expected.all_spans_support_avx_ymm16 = true;
    expected.needs_avx = true;
    expected.needs_f16c = case.kind == ConvertKind::F16ToF32;
    assert_eq!(
        x86_native_replay_feature_requirements(function, &excluded),
        expected,
        "{case:?}"
    );
}

fn lower(function: &SmirFunction, case: ConvertCase, level: OptLevel) -> (Vec<u8>, usize) {
    assert_exact_lift_and_sequence(function, case, level);
    assert_feature_requirements(function, case);

    let mut lowerer = X86_64Lowerer::new();
    lowerer.set_mem_helpers(true);
    lowerer.set_preserve_vector_mem_helpers(true);
    lowerer.set_avx_ymm16_vector_state(true);
    let result = lowerer
        .lower_function(function)
        .unwrap_or_else(|error| panic!("helper-backed packed conversion failed: {error:?}"));
    assert!(result.relocations.is_empty());
    let code = lowerer
        .finalize()
        .expect("finalize helper-backed VEX packed conversion");
    let expected = case.expected_replay_bytes();
    assert!(
        code.windows(expected.len())
            .any(|window| window == expected),
        "{case:?}: missing replay {expected:02X?}"
    );
    let scratch_offset = X86_GUEST_VECTOR_SCRATCH_OFFSET.to_le_bytes();
    assert!(
        code.windows(scratch_offset.len())
            .any(|window| window == scratch_offset),
        "{case:?}: helper scratch transfer absent"
    );
    (code, result.entry_offset)
}

fn assert_rejected(function: &SmirFunction, label: &str) {
    assert_eq!(classified_sequence(function, true), None, "{label}");
    assert!(
        !is_native_clobber_safe_excluding(function, &HashMap::new(), true),
        "{label}"
    );
}

#[test]
fn all_400_scanner_cells_admit_and_lower_exactly_at_o0_o1_o2() {
    let cases = scanner_cases();
    let mut lowered = 0usize;
    for case in cases {
        for level in LEVELS {
            let function = optimize(lift_case(case), level);
            assert_exact_lift_and_sequence(&function, case, level);
            lower(&function, case, level);
            lowered += 1;
        }
    }
    assert_eq!(lowered, 400 * LEVELS.len());
}

#[test]
fn high_registers_sib_bases_and_wig_encodings_remain_exact() {
    let cases = [
        ConvertCase {
            kind: ConvertKind::F32ToF64,
            width: VecWidth::V128,
            form: VexForm::C5,
            destination: 15,
            base: 4,
        },
        ConvertCase {
            kind: ConvertKind::F64ToF32,
            width: VecWidth::V256,
            form: VexForm::C4W0,
            destination: 9,
            base: 12,
        },
        ConvertCase {
            kind: ConvertKind::I32ToF64,
            width: VecWidth::V256,
            form: VexForm::C4W1,
            destination: 0,
            base: 15,
        },
        ConvertCase {
            kind: ConvertKind::F64ToI32Truncate,
            width: VecWidth::V128,
            form: VexForm::C4W1,
            destination: 14,
            base: 5,
        },
        ConvertCase {
            kind: ConvertKind::F16ToF32,
            width: VecWidth::V256,
            form: VexForm::C4W0,
            destination: 15,
            base: 12,
        },
    ];
    for case in cases {
        for level in LEVELS {
            let function = optimize(lift_case(case), level);
            assert_exact_lift_and_sequence(&function, case, level);
            lower(&function, case, level);
        }
    }
}

#[test]
fn fp16_rip_relative_segment_addr32_sib_and_disp32_shapes_admit_and_lower() {
    let encodings = [
        // VCVTPH2PS xmm1,[rip+0x44332211]
        &[0xC4, 0xE2, 0x79, 0x13, 0x0D, 0x11, 0x22, 0x33, 0x44][..],
        // FS addr32 VCVTPH2PS xmm14,[r14d+r15d*2+0x44332211]
        &[
            0x64, 0x67, 0xC4, 0x02, 0x79, 0x13, 0xB4, 0x7E, 0x11, 0x22, 0x33, 0x44,
        ][..],
        // VCVTPH2PS ymm15,[rsp]
        &[0xC4, 0x62, 0x7D, 0x13, 0x3C, 0x24][..],
    ];
    let mut lowered = 0usize;
    for bytes in encodings {
        for level in LEVELS {
            let function = optimize(lift_bytes(bytes), level);
            let sequence = classified_sequence(&function, true)
                .unwrap_or_else(|| panic!("{level:?} {bytes:02X?}: not classified"));
            assert_eq!(sequence.consumed, 2, "{level:?} {bytes:02X?}");
            assert_eq!(sequence.encoding.map, X86VecMap::Map0F38);
            assert_eq!(
                sequence.encoding.kind,
                X86VexPackedConvertMemoryKind::FpPrecision {
                    from: VecElementType::F16,
                    to: VecElementType::F32,
                }
            );
            assert!(sequence.encoding.needs_f16c());
            assert!(is_native_clobber_safe_excluding(
                &function,
                &HashMap::new(),
                true
            ));
            let requirements = x86_native_replay_feature_requirements(&function, &HashMap::new());
            assert!(requirements.needs_avx && requirements.needs_f16c);
            assert!(requirements.all_spans_support_avx_ymm16);

            let mut lowerer = X86_64Lowerer::new();
            lowerer.set_mem_helpers(true);
            lowerer.set_preserve_vector_mem_helpers(true);
            lowerer.set_avx_ymm16_vector_state(true);
            lowerer
                .lower_function(&function)
                .unwrap_or_else(|error| panic!("{level:?} {bytes:02X?}: {error:?}"));
            let code = lowerer
                .finalize()
                .unwrap_or_else(|error| panic!("{level:?} {bytes:02X?}: {error:?}"));
            assert!(
                code.windows(sequence.encoding.register_instruction.as_slice().len())
                    .any(|window| window == sequence.encoding.register_instruction.as_slice()),
                "{level:?} {bytes:02X?}"
            );
            lowered += 1;
        }
    }
    assert_eq!(lowered, encodings.len() * LEVELS.len());
}

#[test]
fn malformed_bytes_reserved_vvvv_and_non_memory_forms_fail_closed() {
    let case = ConvertCase {
        kind: ConvertKind::F64ToI32,
        width: VecWidth::V256,
        form: VexForm::C4W1,
        destination: 5,
        base: 11,
    };
    let valid = case.bytes();
    let p0 = 1usize;
    let p1 = 2usize;
    let opcode = 3usize;
    let modrm = 4usize;
    let mut malformed = Vec::new();
    for (index, xor) in [(p0, 0x03), (p1, 0x08), (opcode, 0x10)] {
        let mut bytes = valid.clone();
        bytes[index] ^= xor;
        malformed.push(bytes);
    }
    let mut register_source = valid.clone();
    register_source[modrm] = (register_source[modrm] & 0x3F) | 0xC0;
    register_source.truncate(modrm + 1);
    malformed.push(register_source);
    let mut lock = vec![0xF0];
    lock.extend_from_slice(&valid);
    malformed.push(lock);
    let mut trailing = valid.clone();
    trailing.push(0);
    malformed.push(trailing);
    malformed.push(valid[..valid.len() - 1].to_vec());

    for bytes in malformed {
        let instruction = X86InstructionBytes::new(&bytes).unwrap();
        assert_eq!(
            instruction.vex_packed_convert_memory_encoding(),
            None,
            "{bytes:02X?}"
        );
    }

    let f16 = ConvertCase {
        kind: ConvertKind::F16ToF32,
        width: VecWidth::V128,
        form: VexForm::C4W0,
        destination: 13,
        base: 11,
    }
    .bytes();
    assert!(
        X86InstructionBytes::new(&f16)
            .unwrap()
            .vex_packed_convert_memory_encoding()
            .is_some()
    );
    let mut malformed_f16 = Vec::new();
    for (index, xor) in [(1, 0x03), (2, 0x80), (2, 0x08), (2, 0x01), (3, 0x01)] {
        let mut bytes = f16.clone();
        bytes[index] ^= xor;
        malformed_f16.push(bytes);
    }
    let mut register_source = f16.clone();
    register_source[4] = (register_source[4] & 0x3F) | 0xC0;
    register_source.truncate(5);
    malformed_f16.push(register_source);
    malformed_f16.push(f16[..f16.len() - 1].to_vec());
    for bytes in malformed_f16 {
        assert_eq!(
            X86InstructionBytes::new(&bytes)
                .unwrap()
                .vex_packed_convert_memory_encoding(),
            None,
            "{bytes:02X?}"
        );
    }
}

#[test]
fn fp16_graph_hint_and_exception_policy_mutations_fail_closed() {
    let case = ConvertCase {
        kind: ConvertKind::F16ToF32,
        width: VecWidth::V256,
        form: VexForm::C4W0,
        destination: 15,
        base: 12,
    };
    let function = optimize(lift_case(case), OptLevel::O2);

    let mut wrong_map = function.clone();
    let Some(X86OpHint::VexOp { map, .. }) = &mut wrong_map.blocks[0].ops[1].x86_hint else {
        unreachable!()
    };
    *map = X86VecMap::Map0F;
    assert_rejected(&wrong_map, "FP16 wrong map");

    let mut wrong_lanes = function.clone();
    let OpKind::X86PackedFpConvert { lanes, .. } = &mut wrong_lanes.blocks[0].ops[1].kind else {
        unreachable!()
    };
    *lanes -= 1;
    assert_rejected(&wrong_lanes, "FP16 wrong lane count");

    let mut wrong_round = function.clone();
    let OpKind::X86PackedFpConvert { round, .. } = &mut wrong_round.blocks[0].ops[1].kind else {
        unreachable!()
    };
    *round = FpRoundMode::RoundUp;
    assert_rejected(&wrong_round, "FP16 wrong rounding control");

    let mut suppressed = function.clone();
    let OpKind::X86PackedFpConvert {
        suppress_exceptions,
        ..
    } = &mut suppressed.blocks[0].ops[1].kind
    else {
        unreachable!()
    };
    *suppress_exceptions = true;
    assert_rejected(&suppressed, "FP16 suppressed exceptions");

    let mut reports_denormal = function;
    let OpKind::X86PackedFpConvert {
        report_fp16_denormal,
        ..
    } = &mut reports_denormal.blocks[0].ops[1].kind
    else {
        unreachable!()
    };
    *report_fp16_denormal = true;
    assert_rejected(&reports_denormal, "FP16 denormal reporting");
}

#[test]
fn graph_hint_ssa_provenance_and_boundary_mutations_fail_closed() {
    let case = ConvertCase {
        kind: ConvertKind::F32ToI32,
        width: VecWidth::V256,
        form: VexForm::C4W1,
        destination: 9,
        base: 12,
    };
    let function = optimize(lift_case(case), OptLevel::O2);

    let mut missing_provenance = function.clone();
    missing_provenance.x86_instruction_bytes.clear();
    assert_rejected(&missing_provenance, "missing provenance");

    let mut wrong_provenance = function.clone();
    wrong_provenance.x86_instruction_bytes.insert(
        (BlockId(0), PC),
        X86InstructionBytes::new(
            &ConvertCase {
                kind: ConvertKind::F32ToI32Truncate,
                ..case
            }
            .bytes(),
        )
        .unwrap(),
    );
    assert_rejected(&wrong_provenance, "wrong provenance");

    let mut hinted_load = function.clone();
    hinted_load.blocks[0].ops[0].x86_hint = hinted_load.blocks[0].ops[1].x86_hint;
    assert_rejected(&hinted_load, "hinted load");

    let mut unaligned_load = function.clone();
    unaligned_load.blocks[0].ops[0].x86_hint = Some(X86OpHint::VecAlign(X86VecAlign::Unaligned));
    assert_rejected(&unaligned_load, "invented unaligned load hint");

    let mut wrong_load_width = function.clone();
    let OpKind::VLoad { width, .. } = &mut wrong_load_width.blocks[0].ops[0].kind else {
        unreachable!()
    };
    *width = VecWidth::V128;
    assert_rejected(&wrong_load_width, "wrong load width");

    let mut wrong_hint = function.clone();
    let Some(X86OpHint::VexOp { opcode, .. }) = &mut wrong_hint.blocks[0].ops[1].x86_hint else {
        unreachable!()
    };
    *opcode ^= 1;
    assert_rejected(&wrong_hint, "wrong hint");

    let mut wrong_round = function.clone();
    let OpKind::X86PackedFpToInt { round, .. } = &mut wrong_round.blocks[0].ops[1].kind else {
        unreachable!()
    };
    *round = FpRoundMode::RoundDown;
    assert_rejected(&wrong_round, "wrong rounding");

    let mut wrong_destination = function.clone();
    let OpKind::X86PackedFpToInt { dst, .. } = &mut wrong_destination.blocks[0].ops[1].kind else {
        unreachable!()
    };
    *dst = vector(8, VecWidth::V256);
    assert_rejected(&wrong_destination, "wrong destination");

    let mut duplicate_use = function.clone();
    let loaded = duplicate_use.blocks[0].ops[0].kind.dests()[0];
    duplicate_use.blocks[0].ops.push(SmirOp::new(
        OpId(2),
        PC + 1,
        OpKind::VMov {
            dst: VReg::Virtual(VirtualId(99)),
            src: loaded,
            width: case.source_width(),
        },
    ));
    assert_rejected(&duplicate_use, "duplicate use");

    let mut extra_same_pc = function.clone();
    extra_same_pc.blocks[0].ops.push(SmirOp::new(
        OpId(2),
        PC,
        OpKind::VMov {
            dst: vector(7, VecWidth::V128),
            src: vector(7, VecWidth::V128),
            width: VecWidth::V128,
        },
    ));
    assert_rejected(&extra_same_pc, "extra same-PC operation");
}
