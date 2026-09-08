//! Complete immediate packed-shift memory-family admission and parity tests.

use super::*;
use crate::smir::ir::ops::{OpKind, SmirOp};
use crate::smir::ir::types::{
    Address, ArchReg, BlockId, DispSize, FunctionId, OpId, ShiftOp, SourceArch, VReg,
    VecElementType, VecWidth, VirtualId, X86Reg,
};
use crate::smir::ir::{
    SmirBlock, SmirFunction, Terminator, X86EvexPackedShiftImmMemoryReplay, X86InstructionBytes,
};
use crate::smir::lift::x86_64::X86_64Lifter;
use crate::smir::lift::{LiftContext, SmirLifter};
use crate::smir::lower::SmirLowerer;
use crate::smir::lower::runtime::{
    X86JitEvexPackedShiftImmMemorySequence, is_native_clobber_safe_excluding,
    x86_jit_evex_packed_shift_imm_memory_sequence, x86_native_replay_feature_requirements,
};
use crate::smir::lower::x86_64::X86_64Lowerer;
use crate::smir::optimize::OptLevel;
use std::collections::HashMap;

#[cfg(target_arch = "x86_64")]
mod native;
mod semantics;

const PC: u64 = 0x7B00;
const LEVELS: [OptLevel; 3] = [OptLevel::O0, OptLevel::O1, OptLevel::O2];

#[derive(Clone, Copy, Debug)]
struct Kind {
    opcode: u8,
    group: u8,
    w: bool,
    elem: VecElementType,
    shift: ShiftOp,
    byte_lane: bool,
}

impl Kind {
    fn all() -> Vec<Self> {
        let mut result = Vec::new();
        for (elem, opcode, w) in [
            (VecElementType::I16, 0x71, false),
            (VecElementType::I32, 0x72, false),
            (VecElementType::I64, 0x73, true),
        ] {
            for (shift, group) in [(ShiftOp::Lsr, 2), (ShiftOp::Asr, 4), (ShiftOp::Lsl, 6)] {
                result.push(Self {
                    elem,
                    opcode: if elem == VecElementType::I64 && group == 4 {
                        0x72
                    } else {
                        opcode
                    },
                    group,
                    w,
                    shift,
                    byte_lane: false,
                });
            }
        }
        for (shift, group) in [(ShiftOp::Lsr, 3), (ShiftOp::Lsl, 7)] {
            result.push(Self {
                opcode: 0x73,
                group,
                w: false,
                elem: VecElementType::I8,
                shift,
                byte_lane: true,
            });
        }
        result
    }
    fn e4nf(self) -> bool {
        self.byte_lane || self.elem == VecElementType::I16
    }
}

#[derive(Clone, Copy, Debug)]
struct Case {
    kind: Kind,
    width: VecWidth,
    destination: u8,
    mask: u8,
    zeroing: bool,
    broadcast: bool,
    amount: u8,
}

impl Case {
    fn bytes(self) -> Vec<u8> {
        let ll = match self.width {
            VecWidth::V128 => 0,
            VecWidth::V256 => 1,
            VecWidth::V512 => 2,
            _ => unreachable!(),
        };
        // [RBX], destination encoded in EVEX.vvvv/V'. R/R' are opcode-group bits.
        vec![
            0x62,
            0xF1,
            (u8::from(self.kind.w) << 7) | ((!self.destination & 15) << 3) | 5,
            (u8::from(self.zeroing) << 7)
                | (ll << 5)
                | (u8::from(self.broadcast) << 4)
                | (u8::from(self.destination & 16 == 0) << 3)
                | self.mask,
            self.kind.opcode,
            (self.kind.group << 3) | 3,
            self.amount,
        ]
    }
    fn lanes(self) -> usize {
        self.width.lanes(self.kind.elem) as usize
    }
    fn scalar(self) -> bool {
        self.broadcast || (!self.kind.e4nf() && self.mask != 0)
    }
}

fn cases() -> Vec<Case> {
    let mut result = Vec::new();
    for kind in Kind::all() {
        for width in [VecWidth::V128, VecWidth::V256, VecWidth::V512] {
            for destination in [0, 9, 17, 31] {
                for (mask, zeroing) in [(0, false), (3, false), (3, true)] {
                    if kind.byte_lane && mask != 0 {
                        continue;
                    }
                    for broadcast in [false, true] {
                        if kind.e4nf() && broadcast {
                            continue;
                        }
                        for amount in [
                            0,
                            1,
                            if kind.byte_lane {
                                15
                            } else {
                                kind.elem.bytes() as u8 * 8 - 1
                            },
                            0xFF,
                        ] {
                            result.push(Case {
                                kind,
                                width,
                                destination,
                                mask,
                                zeroing,
                                broadcast,
                                amount,
                            });
                        }
                    }
                }
            }
        }
    }
    result
}

fn lift(bytes: &[u8]) -> SmirFunction {
    let mut lifter = X86_64Lifter::strict();
    let result = lifter
        .lift_insn(PC, bytes, &mut LiftContext::new(SourceArch::X86_64))
        .unwrap_or_else(|error| panic!("{bytes:02X?}: {error:?}"));
    assert_eq!(result.bytes_consumed, bytes.len());
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

fn optimized(mut function: SmirFunction, level: OptLevel) -> SmirFunction {
    crate::smir::optimize::optimize_function(&mut function, level);
    function
}

fn sequence(
    function: &SmirFunction,
    allow_mem: bool,
) -> Option<X86JitEvexPackedShiftImmMemorySequence> {
    let mut definitions = HashMap::new();
    let mut uses = HashMap::new();
    for op in &function.blocks[0].ops {
        for reg in op.kind.dests() {
            if matches!(reg, VReg::Virtual(_)) {
                *definitions.entry(reg).or_insert(0) += 1;
            }
        }
        for reg in op.kind.source_vregs() {
            if matches!(reg, VReg::Virtual(_)) {
                *uses.entry(reg).or_insert(0) += 1;
            }
        }
    }
    let index = usize::from(matches!(
        function.blocks[0].ops.first().map(|op| &op.kind),
        Some(OpKind::X86RequireApx)
    ));
    x86_jit_evex_packed_shift_imm_memory_sequence(
        &function.blocks[0],
        index,
        allow_mem,
        &function.x86_instruction_bytes,
        &definitions,
        &uses,
    )
}

fn lower(function: &SmirFunction) -> (Vec<u8>, usize) {
    assert!(
        is_native_clobber_safe_excluding(function, &HashMap::new(), true),
        "{:#?}",
        function.blocks[0].ops
    );
    assert!(!is_native_clobber_safe_excluding(
        function,
        &HashMap::new(),
        false
    ));
    let mut lowerer = X86_64Lowerer::new();
    lowerer.set_mem_helpers(true);
    lowerer.set_preserve_vector_mem_helpers(true);
    lowerer.set_jit_fault_deopt_guards(true);
    let result = lowerer
        .lower_function(function)
        .expect("helper-backed immediate shift");
    assert!(result.relocations.is_empty());
    (lowerer.finalize().unwrap(), result.entry_offset)
}

#[test]
fn all_immediate_shift_memory_width_mask_broadcast_and_destination_cells_lower_at_o0_o1_o2() {
    let cases = cases();
    assert_eq!(cases.len(), (3 * 3 + 6 * 3 * 2 + 2) * 3 * 4 * 4);
    for case in cases {
        for level in LEVELS {
            let function = optimized(lift(&case.bytes()), level);
            let exact = sequence(&function, true)
                .unwrap_or_else(|| panic!("{case:?} {level:?}: {:#?}", function.blocks[0].ops));
            assert!(!sequence(&function, false).is_some());
            assert_eq!(exact.encoding.destination, case.destination);
            assert_eq!(exact.encoding.immediate, case.amount);
            assert_eq!(
                exact.memory_size,
                if case.broadcast {
                    case.kind.elem.bytes()
                } else {
                    case.width.bytes()
                }
            );
            let features = x86_native_replay_feature_requirements(&function, &HashMap::new());
            assert!(features.any && features.needs_avx && features.needs_avx512bw);
            assert_eq!(features.needs_avx512vl, case.width != VecWidth::V512);
            assert!(!features.needs_avx512dq && !features.needs_avx512fp16);
            let instruction = match exact.encoding.replay {
                X86EvexPackedShiftImmMemoryReplay::Vector {
                    register_instruction,
                    scratch,
                } => {
                    assert_ne!(scratch, case.destination);
                    register_instruction
                }
                X86EvexPackedShiftImmMemoryReplay::Broadcast { stack_instruction }
                | X86EvexPackedShiftImmMemoryReplay::MaskedVector { stack_instruction } => {
                    stack_instruction
                }
            };
            let (code, _) = lower(&function);
            assert!(
                code.windows(instruction.as_slice().len())
                    .any(|bytes| bytes == instruction.as_slice())
            );
        }
    }
}

#[test]
fn immediate_shift_memory_classifier_validates_wig_and_reserved_fields() {
    // Independent encoding oracle: LLVM MC 23.0.0git, verified 2026-09-08
    // with -triple=x86_64 -x86-asm-syntax=intel -show-encoding.
    // VPSLLW zmm17{k3}{z},[rbx],15; VPSLLD ymm17{k3}{z},[rbx]{1to8},31;
    // VPSRAQ xmm17{k3},[rbx]{1to2},63; VPSLLDQ zmm17,[rbx],7.
    for (kind_index, width, mask, zeroing, broadcast, amount, bytes) in [
        (
            2,
            VecWidth::V512,
            3,
            true,
            false,
            15,
            [0x62, 0xF1, 0x75, 0xC3, 0x71, 0x33, 0x0F],
        ),
        (
            5,
            VecWidth::V256,
            3,
            true,
            true,
            31,
            [0x62, 0xF1, 0x75, 0xB3, 0x72, 0x33, 0x1F],
        ),
        (
            7,
            VecWidth::V128,
            3,
            false,
            true,
            63,
            [0x62, 0xF1, 0xF5, 0x13, 0x72, 0x23, 0x3F],
        ),
        (
            10,
            VecWidth::V512,
            0,
            false,
            false,
            7,
            [0x62, 0xF1, 0x75, 0x40, 0x73, 0x3B, 0x07],
        ),
    ] {
        let case = Case {
            kind: Kind::all()[kind_index],
            width,
            destination: 17,
            mask,
            zeroing,
            broadcast,
            amount,
        };
        assert_eq!(case.bytes(), bytes);
        let actual = X86InstructionBytes::new(&bytes)
            .unwrap()
            .evex_packed_shift_imm_memory_encoding()
            .expect("LLVM-assembled immediate shift");
        assert_eq!(actual.destination, 17);
        assert_eq!(actual.width, width);
        assert_eq!(actual.elem, case.kind.elem);
        assert_eq!(actual.shift, case.kind.shift);
        assert_eq!(actual.byte_lane, case.kind.byte_lane);
        assert_eq!(actual.writemask, (mask != 0).then_some(mask));
        assert_eq!(actual.zeroing, zeroing);
        assert_eq!(actual.immediate, amount);
        assert_eq!(
            matches!(
                actual.replay,
                X86EvexPackedShiftImmMemoryReplay::Broadcast { .. }
            ),
            broadcast
        );
    }
    for kind in Kind::all() {
        let case = Case {
            kind,
            width: VecWidth::V512,
            destination: 31,
            mask: 0,
            zeroing: false,
            broadcast: false,
            amount: 255,
        };
        let bytes = case.bytes();
        for r in [0, 0x10, 0x80, 0x90] {
            let mut changed = bytes.clone();
            changed[1] ^= r;
            let classified = X86InstructionBytes::new(&changed)
                .unwrap()
                .evex_packed_shift_imm_memory_encoding()
                .unwrap();
            assert_eq!(
                classified.destination, 31,
                "opcode extensions cannot select destination"
            );
        }
        if kind.e4nf() {
            let mut wig = bytes.clone();
            wig[2] ^= 0x80;
            assert!(
                X86InstructionBytes::new(&wig)
                    .unwrap()
                    .evex_packed_shift_imm_memory_encoding()
                    .is_some()
            );
            for level in LEVELS {
                lower(&optimized(lift(&wig), level));
            }
        }
        let mut rejected = Vec::new();
        for (index, value) in [
            (1, 0xF2),
            (2, bytes[2] ^ 1),
            (3, 0x68),
            (3, 0xC8),
            (5, bytes[5] | 0xC0),
        ] {
            let mut changed = bytes.clone();
            changed[index] = value;
            rejected.push(changed);
        }
        rejected.push(bytes[..6].to_vec());
        let mut tail = bytes.clone();
        tail.push(0);
        rejected.push(tail);
        if kind.e4nf() {
            let mut bcst = bytes.clone();
            bcst[3] |= 0x10;
            rejected.push(bcst);
        }
        if kind.byte_lane {
            let mut mask = bytes.clone();
            mask[3] |= 1;
            rejected.push(mask);
        }
        for bytes in rejected {
            assert!(
                X86InstructionBytes::new(&bytes)
                    .unwrap()
                    .evex_packed_shift_imm_memory_encoding()
                    .is_none(),
                "{bytes:02X?}"
            );
        }
    }
}

#[test]
fn immediate_shift_memory_graph_and_provenance_mutations_fail_closed() {
    for case in cases().into_iter().step_by(37) {
        let function = optimized(lift(&case.bytes()), OptLevel::O2);
        assert!(sequence(&function, true).is_some());
        let mut missing = function.clone();
        missing.x86_instruction_bytes.clear();
        assert!(sequence(&missing, true).is_none());
        let mut altered = function.clone();
        for op in &mut altered.blocks[0].ops {
            if let OpKind::X86PackedShiftImm { amount, .. } = &mut op.kind {
                *amount ^= 1;
            }
        }
        assert!(sequence(&altered, true).is_none());
        let mut tail = function.clone();
        tail.blocks[0].ops.push(SmirOp::new(
            OpId(0xFFFF),
            PC,
            OpKind::Mov {
                dst: VReg::Virtual(VirtualId(0xFFFF)),
                src: crate::smir::ir::types::SrcOperand::Imm(1),
                width: crate::smir::ir::types::OpWidth::W64,
            },
        ));
        assert!(sequence(&tail, true).is_none());
        let mut split = function.clone();
        split.blocks[0].ops[0].guest_pc += 1;
        assert!(sequence(&split, true).is_none());
    }
}

#[test]
fn immediate_shift_memory_address_variants_retain_exact_frontiers() {
    let base = Case {
        kind: Kind::all()[3],
        width: VecWidth::V256,
        destination: 17,
        mask: 3,
        zeroing: true,
        broadcast: false,
        amount: 31,
    };
    let reg = |register| VReg::Arch(ArchReg::X86(register));
    let sib = |disp| Address::BaseIndexScale {
        base: Some(reg(X86Reg::Rax)),
        index: reg(X86Reg::Rcx),
        scale: 4,
        disp,
        disp_size: DispSize::Disp8,
    };
    for (prefix, operand, expected) in [
        (vec![], vec![0x13], Address::Direct(reg(X86Reg::Rbx))),
        (vec![], vec![0x54, 0x88, 0xFF], sib(-32)),
        (
            vec![],
            vec![0x15, 0x10, 0, 0, 0],
            Address::PcRel {
                offset: 16,
                disp_size: DispSize::Disp32,
                base: Some(PC + 11),
            },
        ),
        (
            vec![0x67],
            vec![0x54, 0x88, 1],
            Address::X86Addr32(Box::new(sib(32))),
        ),
        (
            vec![0x64],
            vec![0x13],
            Address::SegmentRel {
                segment: reg(X86Reg::FsBase),
                base: Some(reg(X86Reg::Rbx)),
                index: None,
                scale: 1,
                disp: 0,
            },
        ),
        (
            vec![0x65, 0x67],
            vec![0x54, 0x88, 1],
            Address::X86Addr32(Box::new(Address::SegmentRel {
                segment: reg(X86Reg::GsBase),
                base: Some(reg(X86Reg::Rax)),
                index: Some(reg(X86Reg::Rcx)),
                scale: 4,
                disp: 32,
            })),
        ),
    ] {
        let original = base.bytes();
        let mut bytes = prefix;
        bytes.extend_from_slice(&original[..5]);
        bytes.extend_from_slice(&operand);
        bytes.push(base.amount);
        for level in LEVELS {
            let function = optimized(lift(&bytes), level);
            let exact = sequence(&function, true).expect("address variant sequence");
            assert!(
                matches!(&function.blocks[0].ops[exact.address_offset].kind,
                OpKind::Lea { addr, .. } if *addr == expected),
                "{bytes:02X?} {level:?}: {:#?}",
                function.blocks[0].ops
            );
            lower(&function);
        }
    }
    let mut apx = base.bytes();
    apx[1] |= 8; // B4: [R19]
    let function = lift(&apx);
    assert!(matches!(
        function.blocks[0].ops[0].kind,
        OpKind::X86RequireApx
    ));
    for level in LEVELS {
        lower(&optimized(function.clone(), level));
    }
    let mut missing = function;
    missing.blocks[0].ops.remove(0);
    assert!(sequence(&missing, true).is_none());
    let mut apx_sib = base.bytes();
    apx_sib.truncate(5);
    apx_sib[1] |= 8;
    apx_sib[2] &= !4;
    apx_sib.extend_from_slice(&[0x54, 0x88, 1, base.amount]);
    for level in LEVELS {
        let function = optimized(lift(&apx_sib), level);
        let exact = sequence(&function, true).expect("APX base and index sequence");
        let expected = Address::BaseIndexScale {
            base: Some(reg(X86Reg::R16)),
            index: reg(X86Reg::R17),
            scale: 4,
            disp: 32,
            disp_size: DispSize::Disp8,
        };
        assert!(
            matches!(&function.blocks[0].ops[1 + exact.address_offset].kind,
            OpKind::Lea { addr, .. } if *addr == expected)
        );
        lower(&function);
    }
}

#[test]
fn immediate_shift_memory_stack_bases_remain_native_after_optimization() {
    // VPSRLW xmm1,[rsp],1 and VPSRLW xmm1,[rbp],1. Neither instruction
    // requires the guest stack or frame pointer to be 16-byte aligned.
    for bytes in [
        &[0x62, 0xF1, 0x75, 0x08, 0x71, 0x14, 0x24, 0x01][..],
        &[0x62, 0xF1, 0x75, 0x08, 0x71, 0x55, 0x00, 0x01][..],
    ] {
        for level in LEVELS {
            let function = optimized(lift(bytes), level);
            assert!(
                sequence(&function, true).is_some(),
                "{bytes:02X?} {level:?}: stack-based shift lost native admission: {:#?}",
                function.blocks[0].ops
            );
            lower(&function);
        }
    }
}
