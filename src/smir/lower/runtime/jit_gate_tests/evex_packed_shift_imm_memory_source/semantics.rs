//! SDM-derived immediate-shift results, masking, and precise memory faults.

use super::*;
use crate::smir::interpret::{BlockResult, SmirInterpreter};
use crate::smir::ir::context::{ArchRegState, ExitReason, SmirContext};
use crate::smir::ir::flags::MaterializedFlags;
use crate::smir::ir::memory::FlatMemory;

pub(super) fn source() -> [u8; 64] {
    std::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(0x81))
}

pub(super) fn initial(mask: u64) -> SmirContext {
    let mut context = SmirContext::new_x86_64();
    if let ArchRegState::X86_64(state) = &mut context.arch_regs {
        state.gpr = std::array::from_fn(|i| 0xAA00_0000u64 + i as u64);
        state.gpr[3] = 0x2000;
        state.k = [0x5555_5555_5555_5555; 8];
        state.k[3] = mask;
        state.xmm = std::array::from_fn(|reg| {
            std::array::from_fn(|word| {
                0x89AB_CDEF_0123_4567u64.rotate_left((reg * 11 + word * 7) as u32)
            })
        });
        state.rflags = 0x8D7;
        state.mxcsr = 0x1F80;
    }
    context.flags.materialized = MaterializedFlags::from_rflags(0x8D7);
    context.flags.lazy = None;
    context
}

pub(super) fn expected(case: Case, mask: u64) -> [[u64; 16]; 32] {
    let context = initial(mask);
    let ArchRegState::X86_64(state) = context.arch_regs else {
        unreachable!()
    };
    let mut vectors = state.xmm;
    let input = source();
    let old = vectors[case.destination as usize];
    let mut output = [0u8; 128];
    for lane in 0..case.lanes() {
        let bytes = case.kind.elem.bytes() as usize;
        let dst = lane * bytes;
        if case.mask != 0 && mask & (1u64 << lane) == 0 {
            if !case.zeroing {
                for byte in 0..bytes {
                    output[dst + byte] = (old[(dst + byte) / 8] >> (((dst + byte) % 8) * 8)) as u8;
                }
            }
            continue;
        }
        if case.kind.byte_lane {
            let offset = lane % 16;
            let count = usize::from(case.amount);
            let source_offset = match case.kind.shift {
                ShiftOp::Lsl => offset.checked_sub(count),
                ShiftOp::Lsr => offset.checked_add(count).filter(|i| *i < 16),
                _ => unreachable!(),
            };
            output[dst] = source_offset.map_or(0, |i| input[(lane / 16) * 16 + i]);
            continue;
        }
        let src = if case.broadcast { 0 } else { dst };
        let mut value = 0u64;
        for byte in 0..bytes {
            value |= u64::from(input[src + byte]) << (byte * 8);
        }
        let bits = (bytes * 8) as u32;
        let count = u32::from(case.amount);
        // SDM: logical counts >= element bits yield zero; arithmetic counts
        // saturate to bits-1 and replicate the original sign bit.
        let shifted = match case.kind.shift {
            ShiftOp::Lsl => {
                if count >= bits {
                    0
                } else {
                    value << count
                }
            }
            ShiftOp::Lsr => {
                if count >= bits {
                    0
                } else {
                    value >> count
                }
            }
            ShiftOp::Asr => {
                let signed = ((value << (64 - bits)) as i64) >> (64 - bits);
                (signed >> count.min(bits - 1)) as u64
            }
            _ => unreachable!(),
        };
        output[dst..dst + bytes].copy_from_slice(&shifted.to_le_bytes()[..bytes]);
    }
    vectors[case.destination as usize] = std::array::from_fn(|word| {
        u64::from_le_bytes(output[word * 8..word * 8 + 8].try_into().unwrap())
    });
    vectors
}

pub(super) fn interpret(function: &SmirFunction, case: Case, mask: u64) {
    let mut context = initial(mask);
    let ArchRegState::X86_64(before) = &context.arch_regs else {
        unreachable!()
    };
    let (gpr, k, flags, mxcsr) = (before.gpr, before.k, before.rflags, before.mxcsr);
    let mut memory = FlatMemory::new(0x3000);
    memory.load(0x2000, &source());
    let result =
        SmirInterpreter::new().execute_block(&mut context, &mut memory, &function.blocks[0]);
    assert!(
        matches!(result, BlockResult::Exit(ExitReason::Return { .. })),
        "{case:?}: {result:?}"
    );
    let ArchRegState::X86_64(state) = context.arch_regs else {
        unreachable!()
    };
    assert_eq!(state.xmm, expected(case, mask), "{case:?} mask={mask:#X}");
    assert_eq!(
        (state.gpr, state.k, state.rflags, state.mxcsr),
        (gpr, k, flags, mxcsr)
    );
}

#[test]
fn immediate_shift_memory_sdm_model_matches_every_kind_and_boundary_at_o0_o1_o2() {
    let mut comparisons = 0;
    for mut case in cases().into_iter().step_by(4) {
        let bound = if case.kind.byte_lane {
            16
        } else {
            case.kind.elem.bytes() as u8 * 8
        };
        for amount in [0, 1, bound - 1, bound, bound + 1, 255] {
            case.amount = amount;
            for mask in [0, u64::MAX, 0x8000_0000_0000_0001, 0xA55A] {
                for level in LEVELS {
                    let function = optimized(lift(&case.bytes()), level);
                    interpret(&function, case, mask);
                    comparisons += 1;
                }
            }
        }
    }
    assert_eq!(comparisons, 564 * 6 * 4 * 3);
}

#[test]
fn immediate_shift_memory_e4_suppression_and_e4nf_full_load_faults_preserve_destination() {
    for kind in Kind::all() {
        let case = Case {
            kind,
            width: VecWidth::V512,
            destination: 17,
            mask: if kind.byte_lane { 0 } else { 3 },
            zeroing: !kind.byte_lane,
            broadcast: false,
            amount: 255,
        };
        for level in LEVELS {
            let function = optimized(lift(&case.bytes()), level);
            for (mask, memory_size, should_fault) in [
                (0u64, 0x100usize, kind.e4nf()),
                (1, 0x2000 + kind.elem.bytes() as usize, kind.e4nf()),
                (3, 0x2000 + kind.elem.bytes() as usize, true),
                (u64::MAX, 0x203F, true),
            ] {
                let mut context = initial(mask);
                let ArchRegState::X86_64(before) = &context.arch_regs else {
                    unreachable!()
                };
                let old = before.xmm;
                let mut memory = FlatMemory::new(memory_size);
                let result = SmirInterpreter::new().execute_block(
                    &mut context,
                    &mut memory,
                    &function.blocks[0],
                );
                if should_fault {
                    assert!(
                        matches!(
                            result,
                            BlockResult::Exit(ExitReason::MemoryFault { write: false, .. })
                        ),
                        "{case:?} {level:?} {mask:#x}: {result:?}"
                    );
                    let ArchRegState::X86_64(after) = &context.arch_regs else {
                        unreachable!()
                    };
                    assert_eq!(after.xmm, old, "architectural state committed before fault");
                } else {
                    assert!(
                        matches!(result, BlockResult::Exit(ExitReason::Return { .. })),
                        "{case:?} {level:?}: {result:?}"
                    );
                }
            }
        }
    }
}
