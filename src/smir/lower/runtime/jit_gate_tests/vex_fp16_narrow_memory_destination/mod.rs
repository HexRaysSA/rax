//! Exact helper-backed F16C `VCVTPS2PH` memory destinations.

use super::*;
use crate::smir::ir::ops::{OpKind, SmirOp, X86OpHint, X86SsePrefix, X86VecMap};
use crate::smir::ir::types::{
    Address, ArchReg, BlockId, FpRoundMode, FunctionId, OpId, VReg, VecWidth, VirtualId, X86Reg,
};
use crate::smir::ir::{
    SmirBlock, SmirFunction, Terminator, X86InstructionBytes, X86VexFp16NarrowMemoryEncoding,
};
use crate::smir::lift::x86_64::X86_64Lifter;
use crate::smir::lift::{ControlFlow, LiftContext, SmirLifter};
use crate::smir::lower::runtime::{
    X86JitVexFp16NarrowMemorySequence, X86NativeReplayFeatureRequirements,
    is_native_clobber_safe_excluding, is_x86_aarch64_native_clobber_safe_excluding,
    uses_x86_native_vectors_excluding, x86_jit_vex_fp16_narrow_memory_sequence,
    x86_native_replay_feature_requirements, x86_native_vector_uses_avx_ymm16_only_excluding,
};
use crate::smir::lower::x86_64::X86_64Lowerer;
use crate::smir::lower::x86_64::test_support::host_c_helper_reference;
use crate::smir::lower::{
    SmirLowerer, X86_GUEST_MXCSR_OFFSET, X86_GUEST_VEC_STORE_FN_OFFSET,
    X86_GUEST_VECTOR_SCRATCH_OFFSET,
};
use crate::smir::optimize::OptLevel;
use std::collections::HashMap;

mod semantics;

const PC: u64 = 0x1D16_1D16;
const DISP: i64 = 0x20;
const LEVELS: [OptLevel; 3] = [OptLevel::O0, OptLevel::O1, OptLevel::O2];
const POST_MXCSR_OFFSET: i32 = X86_GUEST_VECTOR_SCRATCH_OFFSET + 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NarrowCase {
    width_256: bool,
    source: u8,
    base: u8,
    immediate: u8,
    encoded_x: bool,
}

impl NarrowCase {
    fn source_width(self) -> VecWidth {
        if self.width_256 {
            VecWidth::V256
        } else {
            VecWidth::V128
        }
    }

    fn lanes(self) -> u8 {
        if self.width_256 { 8 } else { 4 }
    }

    fn memory_size(self) -> u32 {
        if self.width_256 { 16 } else { 8 }
    }

    fn round(self) -> FpRoundMode {
        if self.immediate & 4 != 0 {
            FpRoundMode::Dynamic
        } else {
            match self.immediate & 3 {
                0 => FpRoundMode::RoundNearest,
                1 => FpRoundMode::RoundDown,
                2 => FpRoundMode::RoundUp,
                _ => FpRoundMode::RoundTowardZero,
            }
        }
    }

    fn scratch(self) -> u8 {
        if self.source == 0 { 1 } else { 0 }
    }

    fn bytes(self) -> Vec<u8> {
        assert!(self.source < 16 && self.base < 16);
        let mut bytes = vec![
            0xC4,
            (if self.source < 8 { 0x80 } else { 0 })
                | (u8::from(self.encoded_x) << 6)
                | (if self.base < 8 { 0x20 } else { 0 })
                | 3,
            0x79 | (u8::from(self.width_256) << 2),
            0x1D,
            0x40 | ((self.source & 7) << 3) | if self.base & 7 == 4 { 4 } else { self.base & 7 },
        ];
        if self.base & 7 == 4 {
            bytes.push(0x24);
        }
        bytes.extend_from_slice(&[DISP as u8, self.immediate]);
        bytes
    }

    fn register_instruction(self) -> X86InstructionBytes {
        X86InstructionBytes::new(&[
            0xC4,
            (if self.source < 8 { 0x80 } else { 0 }) | (u8::from(self.encoded_x) << 6) | 0x20 | 3,
            0x79 | (u8::from(self.width_256) << 2),
            0x1D,
            0xC0 | ((self.source & 7) << 3) | self.scratch(),
            self.immediate,
        ])
        .unwrap()
    }

    fn expected_sequence(self) -> X86JitVexFp16NarrowMemorySequence {
        X86JitVexFp16NarrowMemorySequence {
            consumed: 1,
            encoding: X86VexFp16NarrowMemoryEncoding {
                source: self.source,
                scratch: self.scratch(),
                source_width: self.source_width(),
                lanes: self.lanes(),
                memory_size: self.memory_size(),
                round: self.round(),
                immediate: self.immediate,
                register_instruction: self.register_instruction(),
            },
        }
    }
}

fn x86(reg: X86Reg) -> VReg {
    VReg::Arch(ArchReg::X86(reg))
}

fn source(case: NarrowCase) -> VReg {
    x86(if case.width_256 {
        X86Reg::Ymm(case.source)
    } else {
        X86Reg::Xmm(case.source)
    })
}

fn address_matches(case: NarrowCase, address: &Address) -> bool {
    let base = x86(X86Reg::gpr(case.base));
    if case.base & 7 == 4 && !case.encoded_x {
        matches!(
            address,
            Address::BaseIndexScale {
                base: Some(actual_base),
                index,
                scale: 1,
                disp: 32,
                ..
            } if *actual_base == base && *index == x86(X86Reg::R12)
        )
    } else {
        matches!(
            address,
            Address::BaseOffset {
                base: actual_base,
                offset: DISP,
                ..
            } if *actual_base == base
        )
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
        X86InstructionBytes::new(bytes).expect("VEX instruction fits source metadata"),
    );
    function
}

fn lift_case(case: NarrowCase) -> SmirFunction {
    let function = lift_bytes(&case.bytes());
    assert_exact_lift_and_sequence(&function, case);
    function
}

fn optimize(mut function: SmirFunction, level: OptLevel) -> SmirFunction {
    crate::smir::optimize::optimize_function(&mut function, level);
    function
}

fn classified_at(
    function: &SmirFunction,
    index: usize,
    allow_mem: bool,
) -> Option<X86JitVexFp16NarrowMemorySequence> {
    x86_jit_vex_fp16_narrow_memory_sequence(
        &function.blocks[0],
        index,
        allow_mem,
        &function.x86_instruction_bytes,
    )
}

fn classified(
    function: &SmirFunction,
    allow_mem: bool,
) -> Option<X86JitVexFp16NarrowMemorySequence> {
    classified_at(function, 0, allow_mem)
}

fn assert_exact_lift_and_sequence(function: &SmirFunction, case: NarrowCase) {
    let [op] = function.blocks[0].ops.as_slice() else {
        panic!("{case:?}: expected one-op conversion store");
    };
    let OpKind::X86PackedFpConvertStore {
        addr,
        src,
        mask,
        lanes,
        round,
    } = &op.kind
    else {
        panic!("{case:?}: {op:#?}");
    };
    assert!(address_matches(case, addr), "{case:?}: {addr:#?}");
    assert_eq!(*src, source(case), "{case:?}: source");
    assert_eq!(*mask, None, "{case:?}: mask");
    assert_eq!(*lanes, case.lanes(), "{case:?}: lanes");
    assert_eq!(*round, case.round(), "{case:?}: rounding");
    assert_eq!(
        op.x86_hint,
        Some(X86OpHint::VexOp {
            map: X86VecMap::Map0F3A,
            pp: X86SsePrefix::OpSize,
            opcode: 0x1D,
            width: case.source_width(),
            w: false,
        })
    );
    assert_eq!(classified(function, true), Some(case.expected_sequence()));
    assert_eq!(classified(function, false), None);
}

fn expected_requirements() -> X86NativeReplayFeatureRequirements {
    X86NativeReplayFeatureRequirements {
        any: true,
        all_spans_support_avx_ymm16: true,
        needs_avx: true,
        needs_f16c: true,
        needs_vex_fp16_narrow: true,
        ..X86NativeReplayFeatureRequirements::default()
    }
}

fn assert_feature_requirements(function: &SmirFunction) {
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
    assert_eq!(
        x86_native_replay_feature_requirements(function, &excluded),
        expected_requirements()
    );
}

fn lower(function: &SmirFunction, case: NarrowCase) -> (Vec<u8>, usize) {
    assert_exact_lift_and_sequence(function, case);
    assert_feature_requirements(function);

    let mut lowerer = X86_64Lowerer::new();
    lowerer.set_mem_helpers(true);
    lowerer.set_preserve_vector_mem_helpers(true);
    lowerer.set_native_vector_state_active(true);
    lowerer.set_avx_ymm16_vector_state(true);
    let result = lowerer
        .lower_function(function)
        .unwrap_or_else(|error| panic!("helper-backed VCVTPS2PH failed: {error:?}"));
    assert!(result.relocations.is_empty());
    let code = lowerer.finalize().expect("finalize VCVTPS2PH memory");
    let register = case.register_instruction();
    assert!(
        code.windows(register.as_slice().len())
            .any(|window| window == register.as_slice()),
        "{case:?}: rewritten conversion absent: {:02X?}",
        register.as_slice()
    );
    (code, result.entry_offset)
}

fn transfer_instruction(store: bool, offset: i32) -> Vec<u8> {
    let mut bytes = vec![0x0F, 0xAE, if store { 0x98 } else { 0x90 }];
    bytes.extend_from_slice(&(offset as u32).to_le_bytes());
    bytes
}

fn call_instruction(offset: i32) -> Vec<u8> {
    host_c_helper_reference(offset)
}

fn first_position(bytes: &[u8], needle: &[u8]) -> usize {
    bytes
        .windows(needle.len())
        .position(|window| window == needle)
        .unwrap_or_else(|| panic!("missing {needle:02X?} in {bytes:02X?}"))
}

#[test]
fn all_16_scanner_cells_admit_and_lower_at_o0_o1_o2() {
    let mut cells = 0usize;
    let mut lowered = 0usize;
    for width_256 in [false, true] {
        for source in 0..8 {
            let case = NarrowCase {
                width_256,
                source,
                base: 2,
                immediate: 0xFF,
                encoded_x: true,
            };
            cells += 1;
            for level in LEVELS {
                lower(&optimize(lift_case(case), level), case);
                lowered += 1;
            }
        }
    }
    assert_eq!(cells, 16);
    assert_eq!(lowered, 16 * LEVELS.len());
}

#[test]
fn high_sources_sib_index_extension_and_all_rounding_controls_remain_exact() {
    let mut checked = 0usize;
    for width_256 in [false, true] {
        for source in [0, 8, 9, 15] {
            for base in [4, 5, 12, 13, 15] {
                for immediate in [0x00, 0x01, 0x02, 0x03, 0x04, 0xA5, 0xFF] {
                    for encoded_x in [false, true] {
                        let case = NarrowCase {
                            width_256,
                            source,
                            base,
                            immediate,
                            encoded_x,
                        };
                        lower(&optimize(lift_case(case), OptLevel::O2), case);
                        checked += 1;
                    }
                }
            }
        }
    }
    assert_eq!(checked, 2 * 4 * 5 * 7 * 2);
}

#[test]
fn lowering_orders_original_and_post_mxcsr_around_the_sole_store_helper() {
    for width_256 in [false, true] {
        let case = NarrowCase {
            width_256,
            source: 9,
            base: 12,
            immediate: 0xA5,
            encoded_x: false,
        };
        let (code, _) = lower(&optimize(lift_case(case), OptLevel::O2), case);
        let original_store =
            first_position(&code, &transfer_instruction(true, X86_GUEST_MXCSR_OFFSET));
        let native = first_position(&code, case.register_instruction().as_slice());
        let post_store = first_position(&code, &transfer_instruction(true, POST_MXCSR_OFFSET));
        let original_load =
            first_position(&code, &transfer_instruction(false, X86_GUEST_MXCSR_OFFSET));
        let helper_call = first_position(&code, &call_instruction(X86_GUEST_VEC_STORE_FN_OFFSET));
        let post_load = first_position(&code, &transfer_instruction(false, POST_MXCSR_OFFSET));

        assert!(original_store < native, "{case:?}");
        assert!(native < post_store, "{case:?}");
        assert!(post_store < original_load, "{case:?}");
        assert!(original_load < helper_call, "{case:?}");
        assert!(helper_call < post_load, "{case:?}");
        assert!(
            code.windows(5)
                .any(|window| { window == [0xB9, case.memory_size() as u8, 0, 0, 0] }),
            "{case:?}: exact helper width absent"
        );
    }
}

fn assert_rejected(name: &str, function: &SmirFunction) {
    assert_eq!(
        classified(function, true),
        None,
        "{name}: sequence classifier admitted malformed input"
    );
    assert!(
        !is_native_clobber_safe_excluding(function, &HashMap::new(), true),
        "{name}: clobber gate admitted malformed input"
    );
}

#[test]
fn reserved_source_images_and_semantically_changed_immediates_fail_closed() {
    let case = NarrowCase {
        width_256: true,
        source: 9,
        base: 11,
        immediate: 0x02,
        encoded_x: false,
    };
    let base = lift_case(case);
    let valid = case.bytes();
    let mut invalid = Vec::new();

    let mut w1 = valid.clone();
    w1[2] |= 0x80;
    invalid.push(("VEX.W=1", w1));
    let mut vvvv = valid.clone();
    vvvv[2] &= !0x08;
    invalid.push(("reserved VEX.vvvv", vvvv));
    let mut map = valid.clone();
    map[1] = (map[1] & !0x1F) | 2;
    invalid.push(("wrong map", map));
    let mut pp = valid.clone();
    pp[2] = (pp[2] & !3) | 2;
    invalid.push(("wrong mandatory prefix", pp));
    let mut opcode = valid.clone();
    opcode[3] = 0x1C;
    invalid.push(("wrong opcode", opcode));
    let mut width = valid.clone();
    width[2] &= !0x04;
    invalid.push(("different VEX.L", width));
    let mut source = valid.clone();
    source[1] ^= 0x80;
    invalid.push(("different source", source));
    let mut immediate = valid.clone();
    *immediate.last_mut().unwrap() = 0x01;
    invalid.push(("different rounding control", immediate));
    let mut register = valid.clone();
    let displacement = register.len() - 2;
    register[4] |= 0xC0;
    register.remove(displacement);
    invalid.push(("register destination", register));
    let mut trailing = valid.clone();
    trailing.push(0);
    invalid.push(("trailing byte", trailing));

    for (name, bytes) in invalid {
        let mut function = base.clone();
        function.x86_instruction_bytes.insert(
            (BlockId(0), PC),
            X86InstructionBytes::new(&bytes).expect("mutated image fits metadata"),
        );
        assert_rejected(name, &function);
    }

    let mut missing = base;
    missing.x86_instruction_bytes.clear();
    assert_rejected("missing source metadata", &missing);
}

#[test]
fn every_semantic_field_hint_address_and_instruction_boundary_fails_closed() {
    let case = NarrowCase {
        width_256: true,
        source: 9,
        base: 11,
        immediate: 0x02,
        encoded_x: false,
    };
    let base = lift_case(case);

    for (name, mutate) in [
        ("source", 0usize),
        ("lanes", 1),
        ("round", 2),
        ("mask", 3),
        ("address", 4),
    ] {
        let mut function = base.clone();
        let op = &mut function.blocks[0].ops[0];
        match mutate {
            0 => {
                if let OpKind::X86PackedFpConvertStore { src, .. } = &mut op.kind {
                    *src = x86(X86Reg::Ymm(8));
                }
            }
            1 => {
                if let OpKind::X86PackedFpConvertStore { lanes, .. } = &mut op.kind {
                    *lanes = 4;
                }
            }
            2 => {
                if let OpKind::X86PackedFpConvertStore { round, .. } = &mut op.kind {
                    *round = FpRoundMode::RoundDown;
                }
            }
            3 => {
                if let OpKind::X86PackedFpConvertStore { mask, .. } = &mut op.kind {
                    *mask = Some(x86(X86Reg::K(1)));
                }
            }
            4 => {
                if let OpKind::X86PackedFpConvertStore { addr, .. } = &mut op.kind {
                    *addr = Address::Direct(VReg::Virtual(VirtualId(0xFF00)));
                }
            }
            _ => unreachable!(),
        }
        assert_rejected(name, &function);
    }

    let mut replaced = base.clone();
    replaced.blocks[0].ops[0].kind = OpKind::Nop;
    assert_eq!(
        classified(&replaced, true),
        None,
        "replacement NOP must not consume stale VCVTPS2PH provenance"
    );

    let mut hint = base.clone();
    hint.blocks[0].ops[0].x86_hint = None;
    assert_rejected("missing exact hint", &hint);

    let mut split_tail = base.clone();
    split_tail.blocks[0]
        .ops
        .push(SmirOp::new(OpId(0x7FF0), PC, OpKind::Nop));
    assert_rejected("same-PC tail", &split_tail);

    let mut split_head = base;
    split_head.blocks[0]
        .ops
        .insert(0, SmirOp::new(OpId(0x7FF1), PC, OpKind::Nop));
    assert_eq!(
        classified_at(&split_head, 1, true),
        None,
        "same-PC head must prevent mid-instruction admission"
    );
}
