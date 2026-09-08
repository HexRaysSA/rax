//! EVEX VSIB restart-state and optimizer parity regressions.
//!
//! Intel SDM 086, Vol. 2C, VGATHERDPS/DPD pp. 5-370--371,
//! VGATHERQPS/QPD pp. 5-377--378, and VSCATTERQPS/QPD pp. 5-754--755:
//! a completed active lane updates its destination/store and clears its mask
//! bit before a later lane's fault is delivered. This implementation chooses
//! ascending lane order and defers unused-bit clearing until full completion.

use crate::smir::interpret::{BlockResult, SmirInterpreter};
use crate::smir::ir::context::{ArchRegState, ExitReason, SmirContext, VecValue};
use crate::smir::ir::flags::MaterializedFlags;
use crate::smir::ir::memory::{MemoryError, SmirMemory};
use crate::smir::ir::types::{
    AtomicOp, BlockId, FenceKind, FunctionId, MemWidth, MemoryOrder, SourceArch,
};
use crate::smir::ir::{SmirBlock, SmirFunction, Terminator, TrapKind, X86InstructionBytes};
use crate::smir::lift::x86_64::X86_64Lifter;
use crate::smir::lift::{LiftContext, SmirLifter};
use crate::smir::optimize::{OptLevel, optimize_function};

const PC: u64 = 0x1000;
const DATA: u64 = 0x2000;
const FLAGS: u64 = 0xCD7;
const HIGH_MASK: u64 = 0xFEDC_0000_0000_0000;

struct ObservedMemory {
    bytes: Vec<u8>,
    fault: Option<u64>,
    accesses: Vec<(bool, u64, usize)>,
}

impl ObservedMemory {
    fn new(data_size: usize) -> Self {
        let mut bytes = vec![0; 0x3000];
        for lane in 0..16 {
            let offset = DATA as usize + lane * data_size;
            bytes[offset..offset + data_size]
                .copy_from_slice(&payload(lane).to_le_bytes()[..data_size]);
        }
        Self {
            bytes,
            fault: Some(DATA + data_size as u64),
            accesses: Vec::new(),
        }
    }

    fn access(&mut self, write: bool, addr: u64, size: usize) -> Result<usize, MemoryError> {
        self.accesses.push((write, addr, size));
        if self.fault == Some(addr) {
            return Err(MemoryError::PageFault {
                addr,
                write,
                user: false,
            });
        }
        let start = usize::try_from(addr).map_err(|_| MemoryError::OutOfBounds { addr })?;
        if start
            .checked_add(size)
            .is_none_or(|end| end > self.bytes.len())
        {
            return Err(MemoryError::OutOfBounds { addr });
        }
        Ok(start)
    }
}

impl SmirMemory for ObservedMemory {
    fn read(&mut self, addr: u64, buf: &mut [u8]) -> Result<(), MemoryError> {
        let offset = self.access(false, addr, buf.len())?;
        buf.copy_from_slice(&self.bytes[offset..offset + buf.len()]);
        Ok(())
    }

    fn write(&mut self, addr: u64, data: &[u8]) -> Result<(), MemoryError> {
        let offset = self.access(true, addr, data.len())?;
        self.bytes[offset..offset + data.len()].copy_from_slice(data);
        Ok(())
    }

    fn atomic_load(&mut self, _: u64, _: MemWidth, _: MemoryOrder) -> Result<u64, MemoryError> {
        panic!("VSIB must not perform atomic loads")
    }

    fn atomic_store(
        &mut self,
        _: u64,
        _: u64,
        _: MemWidth,
        _: MemoryOrder,
    ) -> Result<(), MemoryError> {
        panic!("VSIB must not perform atomic stores")
    }

    fn compare_and_swap(
        &mut self,
        _: u64,
        _: u64,
        _: u64,
        _: MemWidth,
        _: MemoryOrder,
        _: MemoryOrder,
    ) -> Result<(u64, bool), MemoryError> {
        panic!("VSIB must not perform compare-and-swap")
    }

    fn atomic_rmw(
        &mut self,
        _: u64,
        _: AtomicOp,
        _: u64,
        _: MemWidth,
        _: MemoryOrder,
    ) -> Result<u64, MemoryError> {
        panic!("VSIB must not perform atomic read-modify-write")
    }

    fn load_exclusive(&mut self, _: u64, _: MemWidth) -> Result<u64, MemoryError> {
        panic!("VSIB must not perform exclusive loads")
    }

    fn store_exclusive(&mut self, _: u64, _: u64, _: MemWidth) -> Result<bool, MemoryError> {
        panic!("VSIB must not perform exclusive stores")
    }

    fn clear_exclusive(&mut self) {
        panic!("VSIB must not clear an exclusive monitor")
    }

    fn fence(&mut self, _: FenceKind) {
        panic!("VSIB must not add a memory fence")
    }

    fn probe(&self, addr: u64, size: usize, write: bool) -> Result<(), MemoryError> {
        let start = usize::try_from(addr).map_err(|_| MemoryError::OutOfBounds { addr })?;
        let end = start
            .checked_add(size)
            .ok_or(MemoryError::OutOfBounds { addr })?;
        if end > self.bytes.len() {
            return Err(MemoryError::OutOfBounds { addr });
        }
        if let Some(fault) = self
            .fault
            .filter(|fault| *fault >= addr && *fault < end as u64)
        {
            return Err(MemoryError::PageFault {
                addr: fault,
                write,
                user: false,
            });
        }
        Ok(())
    }
}

fn payload(lane: usize) -> u64 {
    0x0123_4567_AABB_CC00 | lane as u64
}

fn set_lane(value: &mut VecValue, lane: usize, bytes: usize, bits: u64) {
    let word = lane * bytes / 8;
    let shift = (lane * bytes % 8) * 8;
    let mask = if bytes == 8 { u64::MAX } else { 0xFFFF_FFFF };
    value[word] = (value[word] & !(mask << shift)) | ((bits & mask) << shift);
}

fn encoding(scatter: bool, floating: bool, index_size: usize, data_size: usize, ll: u8) -> [u8; 7] {
    // {v[p]gather,v[p]scatter}{d,q}{d,q}/{ps,pd} zmm17,[rax+zmm30]{k3}.
    // The source/destination and index register views depend on element widths.
    [
        0x62,
        0xA2,
        0x7D | (u8::from(data_size == 8) << 7),
        (ll << 5) | 3,
        (if scatter { 0xA0 } else { 0x90 }) | (u8::from(floating) << 1) | u8::from(index_size == 8),
        0x0C,
        0x30,
    ]
}

fn function(bytes: &[u8], level: OptLevel) -> SmirFunction {
    let result = X86_64Lifter::strict()
        .lift_insn(PC, bytes, &mut LiftContext::new(SourceArch::X86_64))
        .unwrap_or_else(|error| panic!("{bytes:02X?}: {error:?}"));
    assert_eq!(result.bytes_consumed, bytes.len());
    let mut block = SmirBlock::new(BlockId(0), PC);
    block.ops = result.ops;
    // x86 Return reads an architectural stack qword. End the test block
    // without an additional memory access so the trace contains VSIB only.
    block.set_terminator(Terminator::Trap {
        kind: TrapKind::Halt,
    });
    let mut function = SmirFunction::new(FunctionId(0), block.id, PC);
    function.add_block(block);
    function
        .x86_instruction_bytes
        .insert((BlockId(0), PC), X86InstructionBytes::new(bytes).unwrap());
    optimize_function(&mut function, level);
    function
}

fn initial_context(lanes: usize, index_size: usize, data_size: usize) -> SmirContext {
    let mut context = SmirContext::new_x86_64();
    context.flags.materialized = MaterializedFlags::from_rflags(FLAGS);
    context.flags.lazy = None;
    let ArchRegState::X86_64(registers) = &mut context.arch_regs else {
        unreachable!()
    };
    registers.gpr[0] = DATA;
    registers.k[3] = HIGH_MASK | 3 | (1 << (lanes - 1));
    registers.xmm[17][..8].fill(0xD00D_F00D_1122_3344);
    for lane in 0..lanes {
        set_lane(
            &mut registers.xmm[30],
            lane,
            index_size,
            (lane * data_size) as u64,
        );
    }
    context
}

#[test]
fn evex_vsib_smir_all_48_shapes_preserve_fault_progress_and_restart_at_o0_o1_o2() {
    let mut cases = 0;
    for scatter in [false, true] {
        for floating in [false, true] {
            for index_size in [4, 8] {
                for data_size in [4, 8] {
                    for ll in 0..3 {
                        let lanes = (16usize << ll) / index_size.max(data_size);
                        let bytes = encoding(scatter, floating, index_size, data_size, ll);
                        for level in [OptLevel::O0, OptLevel::O1, OptLevel::O2] {
                            let function = function(&bytes, level);
                            let mut context = initial_context(lanes, index_size, data_size);
                            let mut memory = ObservedMemory::new(data_size);
                            let ArchRegState::X86_64(initial) = context.arch_regs.clone() else {
                                unreachable!()
                            };
                            let result = SmirInterpreter::new().execute_block(
                                &mut context,
                                &mut memory,
                                &function.blocks[0],
                            );
                            assert!(
                                matches!(result, BlockResult::Exit(ExitReason::MemoryFault { addr, write })
                                    if addr == DATA + data_size as u64 && write == scatter),
                                "{bytes:02X?} {level:?}: {result:?}"
                            );
                            let ArchRegState::X86_64(registers) = &context.arch_regs else {
                                unreachable!()
                            };
                            let mut expected_vector = initial.xmm[17];
                            if !scatter {
                                set_lane(&mut expected_vector, 0, data_size, payload(0));
                            }
                            assert_eq!(
                                registers.xmm[17], expected_vector,
                                "{bytes:02X?} {level:?}: partial destination"
                            );
                            assert_eq!(
                                registers.xmm[30], initial.xmm[30],
                                "{bytes:02X?} {level:?}: index"
                            );
                            assert_eq!(
                                registers.k[3],
                                initial.k[3] & !1,
                                "{bytes:02X?} {level:?}: restart mask including high bits"
                            );
                            assert_eq!(
                                memory.accesses,
                                [
                                    (scatter, DATA, data_size),
                                    (scatter, DATA + data_size as u64, data_size)
                                ]
                            );
                            context.flags.materialize_all();
                            assert_eq!(context.flags.materialized.to_rflags(), FLAGS);

                            // Repair the fault and change the completed source cell. Resumption
                            // must use the cleared k bit rather than access lane zero again.
                            memory.fault = None;
                            memory.accesses.clear();
                            if scatter {
                                let ArchRegState::X86_64(registers) = &mut context.arch_regs else {
                                    unreachable!()
                                };
                                set_lane(&mut registers.xmm[17], 0, data_size, 0xDEAD_BEEF);
                                set_lane(&mut expected_vector, 0, data_size, 0xDEAD_BEEF);
                            } else {
                                memory.bytes[DATA as usize..DATA as usize + data_size].fill(0xEE);
                            }
                            let result = SmirInterpreter::new().execute_block(
                                &mut context,
                                &mut memory,
                                &function.blocks[0],
                            );
                            assert!(
                                matches!(result, BlockResult::Exit(ExitReason::Halt)),
                                "{bytes:02X?} {level:?}: {result:?}"
                            );
                            let active = (1..lanes)
                                .filter(|lane| initial.k[3] & (1 << lane) != 0)
                                .collect::<Vec<_>>();
                            assert_eq!(
                                memory.accesses,
                                active
                                    .iter()
                                    .map(|lane| (
                                        scatter,
                                        DATA + (lane * data_size) as u64,
                                        data_size
                                    ))
                                    .collect::<Vec<_>>()
                            );
                            let ArchRegState::X86_64(registers) = &context.arch_regs else {
                                unreachable!()
                            };
                            assert_eq!(registers.k[3], 0, "{bytes:02X?} {level:?}: completed mask");
                            if scatter {
                                assert_eq!(
                                    &memory.bytes[DATA as usize..DATA as usize + data_size],
                                    &initial.xmm[17][0].to_le_bytes()[..data_size]
                                );
                            } else {
                                for lane in active {
                                    set_lane(&mut expected_vector, lane, data_size, payload(lane));
                                }
                                expected_vector[lanes * data_size / 8..].fill(0);
                            }
                            assert_eq!(
                                registers.xmm[17], expected_vector,
                                "{bytes:02X?} {level:?}: completed destination/source"
                            );
                            cases += 1;
                        }
                    }
                }
            }
        }
    }
    assert_eq!(cases, 48 * 3);
}

#[test]
fn evex_vsib_smir_scatter_accepts_index_source_alias_and_snapshots_each_lane() {
    // SDM Vol. 2A Table 2-63 restricts index/destination alias only for gather.
    // For matching element widths, aliasing makes the stored data equal to its
    // offset; no vector state is modified by scatter.
    for data_size in [4, 8] {
        for floating in [false, true] {
            let mut bytes = encoding(true, floating, data_size, data_size, 0);
            // Select zmm17 as both source and VSIB index (X=1, V'=0).
            bytes[1] |= 0x40;
            bytes[6] = 0x08;
            for level in [OptLevel::O0, OptLevel::O1, OptLevel::O2] {
                let function = function(&bytes, level);
                let mut context = initial_context(16 / data_size, data_size, data_size);
                let ArchRegState::X86_64(registers) = &mut context.arch_regs else {
                    unreachable!()
                };
                registers.xmm[17] = registers.xmm[30];
                registers.k[3] = HIGH_MASK | 3;
                let original_vector = registers.xmm[17];
                let mut memory = ObservedMemory::new(data_size);
                memory.fault = None;
                assert!(matches!(
                    SmirInterpreter::new().execute_block(
                        &mut context,
                        &mut memory,
                        &function.blocks[0]
                    ),
                    BlockResult::Exit(ExitReason::Halt)
                ));
                assert_eq!(
                    memory.accesses,
                    [
                        (true, DATA, data_size),
                        (true, DATA + data_size as u64, data_size)
                    ]
                );
                assert_eq!(
                    &memory.bytes[DATA as usize..DATA as usize + data_size],
                    &0u64.to_le_bytes()[..data_size]
                );
                assert_eq!(
                    &memory.bytes[DATA as usize + data_size..DATA as usize + data_size * 2],
                    &(data_size as u64).to_le_bytes()[..data_size]
                );
                let ArchRegState::X86_64(registers) = &context.arch_regs else {
                    unreachable!()
                };
                assert_eq!(registers.xmm[17], original_vector);
                assert_eq!(registers.k[3], 0);
            }
        }
    }
}

#[test]
fn evex_vsib_smir_addr32_no_base_truncates_index_before_segment_addition() {
    // With no base, scale one and disp32 zero, no address arithmetic is
    // otherwise needed. Nevertheless, the VSIB offset is modulo 2^32 and the
    // FS base is added only afterward (SDM Vol. 2A, section 2.3.12).
    let mut cases = 0;
    for scatter in [false, true] {
        for floating in [false, true] {
            for (index_size, index) in [(4, u64::MAX), (8, u64::MAX), (8, 1u64 << 32)] {
                for data_size in [4, 8] {
                    for ll in 0..3 {
                        let mut bytes =
                            encoding(scatter, floating, index_size, data_size, ll).to_vec();
                        bytes[1] &= !0x20; // B extension is ignored for mod=00/SIB.base=101.
                        bytes[6] |= 5;
                        bytes.extend([0; 4]);
                        bytes.splice(..0, [0x64, 0x67]);
                        for level in [OptLevel::O0, OptLevel::O1, OptLevel::O2] {
                            let function = function(&bytes, level);
                            let lanes = (16usize << ll) / index_size.max(data_size);
                            let mut context = initial_context(lanes, index_size, data_size);
                            let ArchRegState::X86_64(registers) = &mut context.arch_regs else {
                                unreachable!()
                            };
                            registers.fs_base = DATA;
                            registers.k[3] = HIGH_MASK | 1;
                            registers.gpr[13] = 0x5555_5555_5555_5555;
                            set_lane(&mut registers.xmm[30], 0, index_size, index);
                            let expected_addr = DATA + u64::from(index as u32);
                            let mut memory = ObservedMemory::new(data_size);
                            memory.fault = Some(expected_addr);
                            let result = SmirInterpreter::new().execute_block(
                                &mut context,
                                &mut memory,
                                &function.blocks[0],
                            );
                            assert!(
                                matches!(result, BlockResult::Exit(ExitReason::MemoryFault { addr, write })
                                    if addr == expected_addr && write == scatter),
                                "{bytes:02X?} {level:?} index={index:016X}: {result:?}"
                            );
                            assert_eq!(memory.accesses, [(scatter, expected_addr, data_size)]);
                            let ArchRegState::X86_64(registers) = &context.arch_regs else {
                                unreachable!()
                            };
                            assert_eq!(registers.k[3], HIGH_MASK | 1);
                            cases += 1;
                        }
                    }
                }
            }
        }
    }
    assert_eq!(cases, 2 * 2 * 3 * 2 * 3 * 3);
}

#[test]
fn evex_vsib_smir_apx_requires_only_used_egpr_base_not_unused_x4() {
    // Intel APX 355828-007US, section 3.1.2.3.3 and Table 3.3: B4 extends
    // BASE only when present; the vector index remains V'/X/SIB.index. X4
    // and an absent base's B4 are ignored and do not access an EGPR.
    let mut cases = 0;
    for scatter in [false, true] {
        for floating in [false, true] {
            for index_size in [4, 8] {
                for data_size in [4, 8] {
                    for ll in 0..3 {
                        for no_base in [true, false] {
                            for b4 in [false, true] {
                                for x4 in [false, true] {
                                    let mut bytes =
                                        encoding(scatter, floating, index_size, data_size, ll)
                                            .to_vec();
                                    // The initial encoding uses B=1, so B4 chooses RAX/R16.
                                    bytes[1] |= u8::from(b4) << 3;
                                    if x4 {
                                        bytes[2] &= !4;
                                    }
                                    if no_base {
                                        bytes[6] |= 5;
                                        bytes.extend((DATA as i32).to_le_bytes());
                                    }
                                    for level in [OptLevel::O0, OptLevel::O1, OptLevel::O2] {
                                        let function = function(&bytes, level);
                                        let requires_apx = b4 && !no_base;
                                        assert_eq!(
                                            function.blocks[0].ops.iter().any(|op| matches!(
                                                op.kind,
                                                crate::smir::ir::ops::OpKind::X86RequireApx
                                            )),
                                            requires_apx,
                                            "{bytes:02X?} {level:?}: APX frontier"
                                        );
                                        for apx_enabled in [false, true] {
                                            let lanes = (16usize << ll) / index_size.max(data_size);
                                            let mut context =
                                                initial_context(lanes, index_size, data_size);
                                            let ArchRegState::X86_64(registers) =
                                                &mut context.arch_regs
                                            else {
                                                unreachable!()
                                            };
                                            registers.apx_enabled = apx_enabled;
                                            registers.gpr[16] = DATA;
                                            registers.k[3] = HIGH_MASK | 1;
                                            let mut memory = ObservedMemory::new(data_size);
                                            memory.fault = None;
                                            let result = SmirInterpreter::new().execute_block(
                                                &mut context,
                                                &mut memory,
                                                &function.blocks[0],
                                            );
                                            let rejected = requires_apx && !apx_enabled;
                                            if rejected {
                                                assert!(
                                                    matches!(
                                                        result,
                                                        BlockResult::Exit(ExitReason::Undefined {
                                                            addr: PC,
                                                            ..
                                                        })
                                                    ),
                                                    "{bytes:02X?} {level:?}: {result:?}"
                                                );
                                                assert!(memory.accesses.is_empty());
                                            } else {
                                                assert!(
                                                    matches!(
                                                        result,
                                                        BlockResult::Exit(ExitReason::Halt)
                                                    ),
                                                    "{bytes:02X?} {level:?}: {result:?}"
                                                );
                                                assert_eq!(
                                                    memory.accesses,
                                                    [(scatter, DATA, data_size)]
                                                );
                                            }
                                            let ArchRegState::X86_64(registers) =
                                                &context.arch_regs
                                            else {
                                                unreachable!()
                                            };
                                            assert_eq!(
                                                registers.k[3],
                                                if rejected { HIGH_MASK | 1 } else { 0 }
                                            );
                                            cases += 1;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    assert_eq!(cases, 48 * 2 * 2 * 2 * 3 * 2);
}
