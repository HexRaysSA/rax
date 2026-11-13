//! Exact helper-backed EVEX `VCVTPS2PH` memory destinations.

use super::*;
use crate::smir::ir::ops::{OpKind, SmirOp, X86OpHint, X86SsePrefix, X86VecMap};
use crate::smir::ir::types::{
    Address, ArchReg, BlockId, FpRoundMode, FunctionId, OpId, SourceArch, VReg, VecWidth,
    VirtualId, X86Reg,
};
use crate::smir::ir::{
    SmirBlock, SmirFunction, Terminator, X86EvexFp16NarrowMemoryEncoding, X86InstructionBytes,
};
use crate::smir::lift::x86_64::X86_64Lifter;
use crate::smir::lift::{ControlFlow, LiftContext, SmirLifter};
use crate::smir::lower::runtime::{
    X86JitEvexFp16NarrowMemorySequence, X86NativeReplayFeatureRequirements,
    is_native_clobber_safe_excluding, is_x86_aarch64_native_clobber_safe_excluding,
    uses_x86_native_vectors_excluding, x86_jit_evex_fp16_narrow_memory_sequence,
    x86_native_replay_feature_requirements, x86_native_vector_uses_avx_ymm16_only_excluding,
    x86_native_vector_uses_k16_opmasks_excluding,
};
use crate::smir::lower::x86_64::X86_64Lowerer;
use crate::smir::lower::x86_64::test_support::host_c_helper_reference;
use crate::smir::lower::{
    LowerError, SmirLowerer, X86_GUEST_MXCSR_OFFSET, X86_GUEST_VEC_STORE_FN_OFFSET,
    X86_GUEST_VECTOR_SCRATCH_OFFSET, X86_JIT_VECTOR_MASKED_WORD_SCRATCH_BASE,
};
use crate::smir::optimize::OptLevel;
use std::collections::HashMap;

mod semantics;

const PC: u64 = 0x1D_E11_512;
const LEVELS: [OptLevel; 3] = [OptLevel::O0, OptLevel::O1, OptLevel::O2];
const POST_MXCSR_OFFSET: i32 = X86_GUEST_VECTOR_SCRATCH_OFFSET + 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NarrowCase {
    ll: u8,
    source: u8,
    base: u8,
    immediate: u8,
    writemask: Option<u8>,
}

impl NarrowCase {
    fn source_width(self) -> VecWidth {
        match self.ll {
            0 => VecWidth::V128,
            1 => VecWidth::V256,
            2 => VecWidth::V512,
            _ => unreachable!(),
        }
    }

    fn result_width(self) -> VecWidth {
        if self.ll == 2 {
            VecWidth::V256
        } else {
            VecWidth::V128
        }
    }

    fn lanes(self) -> u8 {
        [4, 8, 16][usize::from(self.ll)]
    }

    fn memory_size(self) -> u32 {
        u32::from(self.lanes()) * 2
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
        u8::from(self.source == 0)
    }

    fn p0(self) -> u8 {
        0x43 | (u8::from(self.base < 8) << 5)
            | (u8::from(self.source & 8 == 0) << 7)
            | (u8::from(self.source & 16 == 0) << 4)
    }

    fn p2(self) -> u8 {
        (self.ll << 5) | 0x08 | self.writemask.unwrap_or(0)
    }

    fn prefix(self) -> [u8; 5] {
        [0x62, self.p0(), 0x7D, self.p2(), 0x1D]
    }

    fn bytes(self) -> Vec<u8> {
        assert!(self.ll <= 2 && self.source < 32 && self.base < 16);
        let mut bytes = self.prefix().to_vec();
        bytes.push(0x40 | ((self.source & 7) << 3) | (self.base & 7));
        if self.base & 7 == 4 {
            bytes.push(0x24);
        }
        bytes.extend_from_slice(&[1, self.immediate]);
        bytes
    }

    fn register_instruction(self) -> X86InstructionBytes {
        X86InstructionBytes::new(&[
            0x62,
            (self.p0() & 0x97) | 0x60,
            0x7D,
            self.p2(),
            0x1D,
            0xC0 | ((self.source & 7) << 3) | self.scratch(),
            self.immediate,
        ])
        .unwrap()
    }

    fn expected_sequence(self) -> X86JitEvexFp16NarrowMemorySequence {
        X86JitEvexFp16NarrowMemorySequence {
            consumed: 1,
            encoding: X86EvexFp16NarrowMemoryEncoding {
                source: self.source,
                scratch: self.scratch(),
                source_width: self.source_width(),
                result_width: self.result_width(),
                lanes: self.lanes(),
                memory_size: self.memory_size(),
                writemask: self.writemask,
                round: self.round(),
                immediate: self.immediate,
                register_instruction: self.register_instruction(),
                needs_avx512vl: self.ll != 2,
            },
        }
    }
}

fn x86(reg: X86Reg) -> VReg {
    VReg::Arch(ArchReg::X86(reg))
}

fn source(case: NarrowCase) -> VReg {
    x86(match case.source_width() {
        VecWidth::V128 => X86Reg::Xmm(case.source),
        VecWidth::V256 => X86Reg::Ymm(case.source),
        VecWidth::V512 => X86Reg::Zmm(case.source),
        _ => unreachable!(),
    })
}

fn lift_bytes(bytes: &[u8]) -> SmirFunction {
    let mut lifter = X86_64Lifter::strict();
    let mut context = LiftContext::new(SourceArch::X86_64);
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
        X86InstructionBytes::new(bytes).expect("EVEX instruction provenance"),
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

fn instruction_index(function: &SmirFunction) -> usize {
    usize::from(
        function.blocks[0]
            .ops
            .first()
            .is_some_and(|op| matches!(op.kind, OpKind::X86RequireApx)),
    )
}

fn classified_at(
    function: &SmirFunction,
    index: usize,
    allow_mem: bool,
) -> Option<X86JitEvexFp16NarrowMemorySequence> {
    x86_jit_evex_fp16_narrow_memory_sequence(
        &function.blocks[0],
        index,
        allow_mem,
        &function.x86_instruction_bytes,
    )
}

fn classified(
    function: &SmirFunction,
    allow_mem: bool,
) -> Option<X86JitEvexFp16NarrowMemorySequence> {
    classified_at(function, instruction_index(function), allow_mem)
}

fn assert_exact_lift_and_sequence(function: &SmirFunction, case: NarrowCase) {
    let index = instruction_index(function);
    let op = &function.blocks[0].ops[index];
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
    assert!(
        matches!(
            addr,
            Address::BaseOffset { base, offset, .. }
                if *base == x86(X86Reg::gpr(case.base))
                    && *offset == i64::from(case.memory_size())
        ),
        "{case:?}: {addr:#?}"
    );
    assert_eq!(*src, source(case), "{case:?}: source");
    assert_eq!(
        *mask,
        case.writemask.map(|mask| x86(X86Reg::K(mask))),
        "{case:?}: mask"
    );
    assert_eq!(*lanes, case.lanes(), "{case:?}: lanes");
    assert_eq!(*round, case.round(), "{case:?}: round");
    assert_eq!(
        op.x86_hint,
        Some(X86OpHint::EvexOp {
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

fn expected_requirements(case: NarrowCase) -> X86NativeReplayFeatureRequirements {
    X86NativeReplayFeatureRequirements {
        any: true,
        needs_avx: true,
        needs_vex_fp16_narrow: true,
        needs_avx512vl: case.ll != 2,
        has_k16_opmask_span: true,
        ..X86NativeReplayFeatureRequirements::default()
    }
}

fn assert_feature_requirements(function: &SmirFunction, case: NarrowCase) {
    let excluded = HashMap::new();
    assert!(is_native_clobber_safe_excluding(function, &excluded, true));
    assert!(!is_native_clobber_safe_excluding(
        function, &excluded, false
    ));
    assert!(!is_x86_aarch64_native_clobber_safe_excluding(
        function, &excluded
    ));
    assert!(uses_x86_native_vectors_excluding(function, &excluded));
    assert!(!x86_native_vector_uses_avx_ymm16_only_excluding(
        function, &excluded
    ));
    assert!(x86_native_vector_uses_k16_opmasks_excluding(
        function, &excluded
    ));
    assert_eq!(
        x86_native_replay_feature_requirements(function, &excluded),
        expected_requirements(case)
    );
}

fn configured_lowerer(avx_only: bool) -> X86_64Lowerer {
    let mut lowerer = X86_64Lowerer::new();
    lowerer.set_mem_helpers(true);
    lowerer.set_preserve_vector_mem_helpers(true);
    lowerer.set_native_vector_state_active(true);
    lowerer.set_narrow_vector_opmask_helpers(true);
    lowerer.set_avx_ymm16_vector_state(avx_only);
    lowerer.set_jit_fault_deopt_guards(true);
    lowerer
}

fn lower(function: &SmirFunction, case: NarrowCase) -> (Vec<u8>, usize) {
    assert_exact_lift_and_sequence(function, case);
    assert_feature_requirements(function, case);
    let mut lowerer = configured_lowerer(false);
    let result = lowerer
        .lower_function(function)
        .unwrap_or_else(|error| panic!("{case:?}: EVEX VCVTPS2PH lowering: {error:?}"));
    assert!(result.relocations.is_empty(), "{case:?}");
    let code = lowerer.finalize().expect("finalize EVEX VCVTPS2PH memory");
    let register = case.register_instruction();
    assert!(
        code.windows(register.as_slice().len())
            .any(|window| window == register.as_slice()),
        "{case:?}: missing rewritten conversion {register:?}"
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
        .unwrap_or_else(|| panic!("missing {needle:02X?} in {} bytes", bytes.len()))
}

fn representative_cases() -> Vec<NarrowCase> {
    let mut cases = Vec::with_capacity(6);
    for ll in 0..=2 {
        for writemask in [None, Some([3, 5, 7][usize::from(ll)])] {
            cases.push(NarrowCase {
                ll,
                source: [1, 17, 29][usize::from(ll)],
                base: 2,
                immediate: [0, 2, 0xA5][usize::from(ll)],
                writemask,
            });
        }
    }
    cases
}

#[test]
fn all_six_memory_cells_admit_and_lower_at_o0_o1_o2() {
    let cases = representative_cases();
    assert_eq!(cases.len(), 6);
    let mut lowerings = 0usize;
    for case in cases {
        for level in LEVELS {
            lower(&optimize(lift_case(case), level), case);
            lowerings += 1;
        }
    }
    assert_eq!(lowerings, 6 * LEVELS.len());
}

#[test]
fn all_sources_masks_round_controls_and_ignored_immediate_bits_remain_exact() {
    let mut lowerings = 0usize;
    for ll in 0..=2 {
        for source in 0..32 {
            for writemask in [None, Some(3)] {
                for immediate in 0..=7 {
                    let case = NarrowCase {
                        ll,
                        source,
                        base: 2,
                        immediate,
                        writemask,
                    };
                    lower(&optimize(lift_case(case), OptLevel::O2), case);
                    lowerings += 1;
                }
            }
        }
    }
    assert_eq!(lowerings, 3 * 32 * 2 * 8);

    let base = NarrowCase {
        ll: 2,
        source: 29,
        base: 2,
        immediate: 0,
        writemask: Some(7),
    };
    for immediate in u8::MIN..=u8::MAX {
        let case = NarrowCase { immediate, ..base };
        let instruction = X86InstructionBytes::new(&case.bytes()).unwrap();
        assert_eq!(
            instruction.evex_fp16_narrow_memory_encoding(),
            Some(case.expected_sequence().encoding),
            "{immediate:#04x}"
        );
    }
}

#[test]
fn lowering_orders_mxcsr_restoration_before_the_sole_masked_store_helper() {
    for case in representative_cases() {
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

        let expected_tag =
            X86_JIT_VECTOR_MASKED_WORD_SCRATCH_BASE + u32::from(case.writemask.unwrap_or(0));
        assert!(
            code.windows(5)
                .any(|window| window == [0xBA, expected_tag as u8, 0, 0, 0]),
            "{case:?}: exact helper tag absent"
        );
        assert!(
            code.windows(5)
                .any(|window| window == [0xB9, case.memory_size() as u8, 0, 0, 0]),
            "{case:?}: exact helper width absent"
        );
    }
}

fn assert_rejected(name: &str, function: &SmirFunction) {
    assert_eq!(classified(function, true), None, "{name}: classifier");
    assert!(
        !is_native_clobber_safe_excluding(function, &HashMap::new(), true),
        "{name}: clobber gate"
    );
}

#[test]
fn reserved_byte_images_and_semantic_provenance_mutations_fail_closed() {
    let case = NarrowCase {
        ll: 2,
        source: 29,
        base: 2,
        immediate: 0x02,
        writemask: Some(7),
    };
    let base = lift_case(case);
    let valid = case.bytes();
    let mut invalid = Vec::new();

    let mut w1 = valid.clone();
    w1[2] |= 0x80;
    invalid.push(("EVEX.W=1", w1));
    let mut vvvv = valid.clone();
    vvvv[2] &= !0x08;
    invalid.push(("reserved EVEX.vvvv", vvvv));
    let mut v_prime = valid.clone();
    v_prime[3] &= !0x08;
    invalid.push(("reserved EVEX.V'", v_prime));
    let mut zeroing = valid.clone();
    zeroing[3] |= 0x80;
    invalid.push(("reserved EVEX.z", zeroing));
    let mut broadcast = valid.clone();
    broadcast[3] |= 0x10;
    invalid.push(("reserved EVEX.b", broadcast));
    let mut map = valid.clone();
    map[1] = (map[1] & !7) | 2;
    invalid.push(("wrong map", map));
    let mut pp = valid.clone();
    pp[2] = (pp[2] & !3) | 2;
    invalid.push(("wrong mandatory prefix", pp));
    let mut opcode = valid.clone();
    opcode[4] = 0x1C;
    invalid.push(("wrong opcode", opcode));
    let mut ll3 = valid.clone();
    ll3[3] = (ll3[3] & !0x60) | 0x60;
    invalid.push(("reserved L'L=3", ll3));
    let mut source = valid.clone();
    source[1] ^= 0x10;
    invalid.push(("different source", source));
    let mut mask = valid.clone();
    mask[3] = (mask[3] & !7) | 6;
    invalid.push(("different mask", mask));
    let mut immediate = valid.clone();
    *immediate.last_mut().unwrap() = 0x01;
    invalid.push(("different rounding control", immediate));
    let mut register = valid.clone();
    register[5] |= 0xC0;
    register.remove(register.len() - 2);
    invalid.push(("register destination", register));
    let mut trailing = valid.clone();
    trailing.push(0);
    invalid.push(("trailing byte", trailing));

    for (name, bytes) in invalid {
        let mut function = base.clone();
        function.x86_instruction_bytes.insert(
            (BlockId(0), PC),
            X86InstructionBytes::new(&bytes).expect("mutated provenance fits metadata"),
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
        ll: 2,
        source: 29,
        base: 2,
        immediate: 0x02,
        writemask: Some(7),
    };
    let base = lift_case(case);

    for mutation in 0..5 {
        let mut function = base.clone();
        let op = &mut function.blocks[0].ops[0];
        match mutation {
            0 => {
                if let OpKind::X86PackedFpConvertStore { src, .. } = &mut op.kind {
                    *src = x86(X86Reg::Zmm(28));
                }
            }
            1 => {
                if let OpKind::X86PackedFpConvertStore { lanes, .. } = &mut op.kind {
                    *lanes = 8;
                }
            }
            2 => {
                if let OpKind::X86PackedFpConvertStore { round, .. } = &mut op.kind {
                    *round = FpRoundMode::RoundDown;
                }
            }
            3 => {
                if let OpKind::X86PackedFpConvertStore { mask, .. } = &mut op.kind {
                    *mask = Some(x86(X86Reg::K(6)));
                }
            }
            4 => {
                if let OpKind::X86PackedFpConvertStore { addr, .. } = &mut op.kind {
                    *addr = Address::Direct(VReg::Virtual(VirtualId(0xFF00)));
                }
            }
            _ => unreachable!(),
        }
        assert_rejected("semantic mutation", &function);
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
    assert_eq!(classified_at(&split_head, 1, true), None);
}

#[test]
fn segment_addr32_rip_and_apx_addresses_admit_and_lower() {
    let case = NarrowCase {
        ll: 2,
        source: 17,
        base: 2,
        immediate: 7,
        writemask: Some(3),
    };
    let mut addr32 = case.bytes();
    addr32.insert(0, 0x67);
    let mut fs = case.bytes();
    fs.insert(0, 0x64);
    let mut rip = case.prefix().to_vec();
    rip.push(((case.source & 7) << 3) | 5);
    rip.extend_from_slice(&0x20i32.to_le_bytes());
    rip.push(case.immediate);
    for (name, bytes) in [("addr32", addr32), ("FS", fs), ("RIP", rip)] {
        let base = lift_bytes(&bytes);
        for level in LEVELS {
            let function = optimize(base.clone(), level);
            classified(&function, true)
                .unwrap_or_else(|| panic!("{name} {level:?}: {:#?}", function.blocks[0].ops));
            let mut lowerer = configured_lowerer(false);
            lowerer
                .lower_function(&function)
                .unwrap_or_else(|error| panic!("{name} {level:?}: {error:?}"));
        }
    }

    // [RAX + RCX*2 + disp8] with APX B4/X4 set. The lifter must emit exactly
    // one preceding X86RequireApx guard, while the rewritten native conversion
    // restores ordinary EVEX.U and removes both helper-owned address channels.
    let mut apx = case.prefix().to_vec();
    apx[1] |= 0x08;
    apx[2] &= !0x04;
    apx.push(0x40 | ((case.source & 7) << 3) | 4);
    apx.push(0x48);
    apx.extend_from_slice(&[1, case.immediate]);
    let base = lift_bytes(&apx);
    assert!(matches!(base.blocks[0].ops[0].kind, OpKind::X86RequireApx));
    assert!(classified(&base, true).is_some());
    let mut missing_guard = base.clone();
    missing_guard.blocks[0].ops.remove(0);
    assert_eq!(classified(&missing_guard, true), None);
    for level in LEVELS {
        let function = optimize(base.clone(), level);
        classified(&function, true)
            .unwrap_or_else(|| panic!("APX {level:?}: {:#?}", function.blocks[0].ops));
        let mut lowerer = configured_lowerer(false);
        lowerer
            .lower_function(&function)
            .unwrap_or_else(|error| panic!("APX {level:?}: {error:?}"));
    }
}

#[test]
fn full_vector_bridge_rejects_avx_only_lowering() {
    let case = representative_cases().pop().unwrap();
    let function = optimize(lift_case(case), OptLevel::O2);
    let mut lowerer = configured_lowerer(true);
    assert!(matches!(
        lowerer.lower_function(&function),
        Err(LowerError::InvalidOperand { .. })
    ));
}
