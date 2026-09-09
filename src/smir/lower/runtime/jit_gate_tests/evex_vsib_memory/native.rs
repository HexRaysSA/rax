//! Executed x86-64 parity, restart, address, and exact-frontier regressions.

use super::*;
use crate::smir::interpret::{BlockResult, SmirInterpreter};
use crate::smir::ir::TrapKind;
use crate::smir::ir::context::{ArchRegState, ExitReason, SmirContext};
use crate::smir::ir::flags::MaterializedFlags;
use crate::smir::ir::memory::{MemoryError, SmirMemory};
use crate::smir::ir::types::{AtomicOp, FenceKind, MemWidth, MemoryOrder};
use crate::smir::lower::runtime::{ExecMem, GuestRegs, X86_VECTOR_STATE_K16};

const DATA: u64 = 0x2000;
const HIGH: u64 = 0xFEDC_0000_0000_0000;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Memory {
    base: u64,
    bytes: Vec<u8>,
    fail: Option<u64>,
    calls: Vec<(bool, u64, usize)>,
}

impl Memory {
    fn new(base: u64) -> Self {
        Self {
            base,
            bytes: (0..128)
                .map(|byte| (byte as u8).wrapping_mul(37).wrapping_add(19))
                .collect(),
            fail: None,
            calls: Vec::new(),
        }
    }

    fn offset(&self, address: u64, size: usize, write: bool) -> Result<usize, MemoryError> {
        let offset = usize::try_from(address.wrapping_sub(self.base)).ok();
        if self.fail == Some(address)
            || offset.is_none_or(|offset| {
                offset
                    .checked_add(size)
                    .is_none_or(|end| end > self.bytes.len())
            })
        {
            return Err(MemoryError::PageFault {
                addr: address,
                write,
                user: false,
            });
        }
        Ok(offset.unwrap())
    }
}

impl SmirMemory for Memory {
    fn read(&mut self, address: u64, data: &mut [u8]) -> Result<(), MemoryError> {
        self.calls.push((false, address, data.len()));
        let offset = self.offset(address, data.len(), false)?;
        data.copy_from_slice(&self.bytes[offset..offset + data.len()]);
        Ok(())
    }
    fn write(&mut self, address: u64, data: &[u8]) -> Result<(), MemoryError> {
        self.calls.push((true, address, data.len()));
        let offset = self.offset(address, data.len(), true)?;
        self.bytes[offset..offset + data.len()].copy_from_slice(data);
        Ok(())
    }
    fn probe(&self, addr: u64, size: usize, write: bool) -> Result<(), MemoryError> {
        self.offset(addr, size, write).map(|_| ())
    }
    fn atomic_load(&mut self, _: u64, _: MemWidth, _: MemoryOrder) -> Result<u64, MemoryError> {
        panic!("VSIB atomic load")
    }
    fn atomic_store(
        &mut self,
        _: u64,
        _: u64,
        _: MemWidth,
        _: MemoryOrder,
    ) -> Result<(), MemoryError> {
        panic!("VSIB atomic store")
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
        panic!("VSIB compare-and-swap")
    }
    fn atomic_rmw(
        &mut self,
        _: u64,
        _: AtomicOp,
        _: u64,
        _: MemWidth,
        _: MemoryOrder,
    ) -> Result<u64, MemoryError> {
        panic!("VSIB atomic RMW")
    }
    fn load_exclusive(&mut self, _: u64, _: MemWidth) -> Result<u64, MemoryError> {
        panic!("VSIB exclusive load")
    }
    fn store_exclusive(&mut self, _: u64, _: u64, _: MemWidth) -> Result<bool, MemoryError> {
        panic!("VSIB exclusive store")
    }
    fn clear_exclusive(&mut self) {
        panic!("VSIB exclusive monitor")
    }
    fn fence(&mut self, _: FenceKind) {
        panic!("VSIB memory fence")
    }
}

#[repr(C)]
struct LoadResult {
    value: u64,
    ok: u64,
}

extern "C" fn load_helper(
    context: *mut Memory,
    address: u64,
    size: u32,
    signed: u32,
) -> LoadResult {
    let memory = unsafe { &mut *context };
    assert!(matches!(size, 4 | 8));
    assert_eq!(signed, 0);
    let mut value = [0u8; 8];
    let ok = memory.read(address, &mut value[..size as usize]).is_ok();
    LoadResult {
        value: u64::from_le_bytes(value),
        ok: u64::from(ok),
    }
}

extern "C" fn store_helper(context: *mut Memory, address: u64, value: u64, size: u32) -> u64 {
    let memory = unsafe { &mut *context };
    assert!(matches!(size, 4 | 8));
    if size == 4 {
        assert_eq!(value >> 32, 0, "B4 source is exactly zero-extended");
    }
    u64::from(
        memory
            .write(address, &value.to_le_bytes()[..size as usize])
            .is_ok(),
    )
}

fn set_lane(vector: &mut [u64; 8], lane: usize, bytes: u8, value: u64) {
    let bits = usize::from(bytes) * 8;
    let per_word = 64 / bits;
    let shift = (lane % per_word) * bits;
    let mask = if bytes == 8 {
        u64::MAX
    } else {
        u64::from(u32::MAX)
    };
    let word = &mut vector[lane / per_word];
    *word = (*word & !(mask << shift)) | ((value & mask) << shift);
}

fn initial(case: Case) -> GuestRegs {
    let mut registers = GuestRegs {
        gpr: std::array::from_fn(|reg| 0xD000_0000_0000_0010u64.wrapping_add(reg as u64 * 0x0101)),
        zmm: std::array::from_fn(|reg| {
            std::array::from_fn(|word| {
                0xE012_3456_89AB_CDEFu64.rotate_left((reg * 13 + word * 7) as u32)
            })
        }),
        k: [0xF123_4567_89AB_CDEF; 8],
        rflags: 0xCD7,
        mxcsr: 0x3FA1,
        vector_active: X86_VECTOR_STATE_K16,
        apx_enabled: 1,
        cs_l: 1,
        ..GuestRegs::default()
    };
    registers.gpr[0] = DATA;
    registers.k[case.mask as usize] = HIGH | 3 | (1u64 << (case.lanes() - 1));
    for lane in 0..case.lanes() {
        set_lane(
            &mut registers.zmm[case.index as usize],
            lane,
            case.index_bytes,
            (lane * usize::from(case.data_bytes)) as u64,
        );
    }
    registers
}

fn interpret(
    function: &SmirFunction,
    registers: &GuestRegs,
    memory: &mut Memory,
) -> (GuestRegs, bool) {
    let mut context = SmirContext::new_x86_64();
    context.flags.materialized = MaterializedFlags::from_rflags(registers.rflags);
    context.flags.lazy = None;
    let ArchRegState::X86_64(x86) = &mut context.arch_regs else {
        unreachable!()
    };
    x86.gpr = registers.gpr;
    x86.rflags = registers.rflags;
    x86.mxcsr = registers.mxcsr;
    x86.k = registers.k;
    x86.fs_base = registers.fs_base;
    x86.gs_base = registers.gs_base;
    x86.cs_l = registers.cs_l != 0;
    x86.apx_enabled = registers.apx_enabled != 0;
    for reg in 0..32 {
        x86.xmm[reg][..8].copy_from_slice(&registers.zmm[reg]);
    }
    let mut block = function.blocks[0].clone();
    // Native Return is the host-function terminator; interpreting x86 Return
    // would introduce an unrelated guest-stack load after the VSIB sequence.
    block.set_terminator(Terminator::Trap {
        kind: TrapKind::Halt,
    });
    let result = SmirInterpreter::new().execute_block(&mut context, memory, &block);
    let fault = match result {
        BlockResult::Exit(ExitReason::MemoryFault { .. }) => true,
        BlockResult::Exit(ExitReason::Halt) => false,
        other => panic!("unexpected VSIB interpreter exit: {other:?}"),
    };
    let ArchRegState::X86_64(x86) = &context.arch_regs else {
        unreachable!()
    };
    let mut expected = *registers;
    expected.gpr = x86.gpr;
    expected.rflags = x86.rflags;
    expected.mxcsr = x86.mxcsr;
    expected.k = x86.k;
    expected.exit_pc = if fault { PC } else { 0 };
    for reg in 0..32 {
        expected.zmm[reg].copy_from_slice(&x86.xmm[reg][..8]);
    }
    (expected, fault)
}

fn assert_state(actual: &GuestRegs, expected: &GuestRegs, label: &str) {
    assert_eq!(actual.gpr, expected.gpr, "{label}: GPRs");
    assert_eq!(actual.zmm, expected.zmm, "{label}: all ZMM bits");
    assert_eq!(actual.k, expected.k, "{label}: all K bits");
    assert_eq!(actual.rflags, expected.rflags, "{label}: RFLAGS");
    assert_eq!(actual.mxcsr, expected.mxcsr, "{label}: MXCSR");
    assert_eq!(
        actual.exit_pc, expected.exit_pc,
        "{label}: precise frontier"
    );
    assert_eq!(actual.fs_base, expected.fs_base, "{label}: FS.base");
    assert_eq!(actual.gs_base, expected.gs_base, "{label}: GS.base");
    assert_eq!(
        actual.apx_enabled, expected.apx_enabled,
        "{label}: APX profile"
    );
    assert_eq!(actual.cs_l, expected.cs_l, "{label}: CS.L");
}

fn run(exec: &ExecMem, entry: usize, registers: &mut GuestRegs, memory: &mut Memory) {
    registers.ctx = (memory as *mut Memory) as u64;
    registers.load_fn = load_helper as *const () as usize as u64;
    registers.store_fn = store_helper as *const () as usize as u64;
    registers.exit_pc = 0;
    // Match the CPU wrapper, which constructs a fresh GuestRegs per entry.
    registers.x86_vsib_frontier_lane_plus_one = 0;
    registers.x86_vsib_instruction_ordinal = 0;
    exec.run(entry, registers);
}

fn supported() -> bool {
    if std::is_x86_feature_detected!("avx512f") {
        true
    } else {
        eprintln!("skipping executed native VSIB: host lacks AVX512F state bridge");
        false
    }
}

#[test]
fn native_vsib_all_48_shapes_preserve_fault_progress_resume_and_empty_masks() {
    if !supported() {
        return;
    }
    let mut attempts = 0;
    for case in cases() {
        for level in LEVELS {
            let function = lift(&case.bytes(), level);
            let (code, entry) = lower(&function);
            let exec = ExecMem::new(&code).unwrap();
            for fail_lane in [None, Some(0), Some(1)] {
                let mut registers = initial(case);
                let mut memory = Memory::new(DATA);
                memory.fail = fail_lane.map(|lane| DATA + lane * u64::from(case.data_bytes));
                let original = registers;
                let mut expected_memory = memory.clone();
                let (expected, fault) = interpret(&function, &registers, &mut expected_memory);
                run(&exec, entry, &mut registers, &mut memory);
                let label = format!("{case:?} {level:?} {fail_lane:?}");
                assert_state(&registers, &expected, &label);
                assert_eq!(
                    registers.x86_vsib_instruction_ordinal, 1,
                    "one dynamic VSIB occurrence"
                );
                assert_eq!(
                    registers.x86_vsib_frontier_lane_plus_one,
                    fail_lane.map_or(0, |lane| lane + 1),
                    "{label}: explicit failed-lane frontier"
                );
                assert_eq!(memory, expected_memory, "{label}: helper effects/order");
                let selected: Vec<_> = (0..case.lanes())
                    .filter(|lane| original.k[case.mask as usize] & (1 << lane) != 0)
                    .take_while(|lane| fail_lane.is_none_or(|failed| *lane as u64 <= failed))
                    .map(|lane| {
                        (
                            case.scatter,
                            DATA + lane as u64 * u64::from(case.data_bytes),
                            usize::from(case.data_bytes),
                        )
                    })
                    .collect();
                assert_eq!(
                    memory.calls, selected,
                    "{label}: independent ascending lane order"
                );
                attempts += 1;
                if fault {
                    // A repeated successful lane would read/write a different value.
                    // The architectural mask must prevent that helper from recurring.
                    memory.fail = None;
                    memory.calls.clear();
                    memory.bytes[..usize::from(case.data_bytes)].fill(0x79);
                    if case.scatter && fail_lane == Some(1) {
                        set_lane(
                            &mut registers.zmm[case.data as usize],
                            0,
                            case.data_bytes,
                            0x8888_7777_6666_5555,
                        );
                    }
                    let remaining = registers.k[case.mask as usize];
                    let mut expected_memory = memory.clone();
                    let (expected, fault) = interpret(&function, &registers, &mut expected_memory);
                    assert!(!fault);
                    run(&exec, entry, &mut registers, &mut memory);
                    assert_state(&registers, &expected, &format!("{label}: resume"));
                    assert_eq!(memory, expected_memory);
                    assert_eq!(
                        registers.x86_vsib_frontier_lane_plus_one, 0,
                        "successful restart has no frontier marker"
                    );
                    let selected: Vec<_> = (0..case.lanes())
                        .filter(|lane| remaining & (1 << lane) != 0)
                        .map(|lane| {
                            (
                                case.scatter,
                                DATA + lane as u64 * u64::from(case.data_bytes),
                                usize::from(case.data_bytes),
                            )
                        })
                        .collect();
                    assert_eq!(memory.calls, selected, "{label}: no completed lane replay");
                    attempts += 1;
                }
            }
            let mut registers = initial(case);
            registers.k[case.mask as usize] = HIGH;
            let mut memory = Memory::new(DATA);
            memory.bytes.clear(); // Every possible guest access fails.
            let mut expected_memory = memory.clone();
            let (expected, fault) = interpret(&function, &registers, &mut expected_memory);
            assert!(!fault);
            run(&exec, entry, &mut registers, &mut memory);
            assert_state(&registers, &expected, "empty mask");
            assert!(memory.calls.is_empty());
            assert_eq!(
                registers.x86_vsib_instruction_ordinal, 1,
                "zero mask still enters the instruction"
            );
            assert_eq!(
                registers.x86_vsib_frontier_lane_plus_one, 0,
                "zero-mask completion has no failed lane"
            );
            attempts += 1;
        }
    }
    assert_eq!(attempts, 48 * LEVELS.len() * 6);
}

#[test]
fn native_vsib_address_wrap_segments_apx_bases_and_scatter_alias_overlap() {
    if !supported() {
        return;
    }
    let mut comparisons = 0;
    for case in cases() {
        for level in LEVELS {
            for variant in 0..6 {
                let mut case = case;
                if variant == 5 && !case.scatter {
                    continue;
                }
                if variant == 5 {
                    case.data = case.index;
                }
                let (bytes, base, index_value, segment_base) = match variant {
                    0 => (
                        case.address(Some(0), 8, Some(-2), true, Some(0x64), false),
                        0xFFFF_FFF8u64,
                        u64::from(case.data_bytes) / 4 + 1,
                        DATA,
                    ),
                    1 => (
                        case.address(None, 1, None, true, Some(0x65), true),
                        0,
                        u64::MAX,
                        DATA.wrapping_sub(u64::from(u32::MAX)),
                    ),
                    2 => (
                        case.address(Some(29), 4, Some(-1), false, None, true),
                        DATA + 4 + u64::from(case.data_bytes),
                        u64::MAX,
                        0,
                    ),
                    3 => (
                        case.address(Some(5), 2, None, false, Some(0x65), false),
                        2,
                        u64::MAX,
                        DATA,
                    ),
                    4 => (
                        case.address(Some(4), 1, None, false, None, false),
                        DATA,
                        0,
                        0,
                    ),
                    _ => (case.bytes(), DATA, 0, 0),
                };
                let function = lift(&bytes, level);
                let (code, entry) = lower(&function);
                let exec = ExecMem::new(&code).unwrap();
                let mut registers = initial(case);
                registers.gpr[0] = base;
                registers.gpr[29] = base;
                registers.gpr[5] = base;
                registers.gpr[4] = base;
                registers.fs_base = segment_base;
                registers.gs_base = segment_base;
                registers.k[case.mask as usize] = HIGH | 3;
                for lane in 0..case.lanes() {
                    // Overlap every selected scatter lane in the alias variant.
                    let value = if matches!(variant, 1 | 5) {
                        index_value
                    } else {
                        index_value.wrapping_add(lane as u64)
                    };
                    set_lane(
                        &mut registers.zmm[case.index as usize],
                        lane,
                        case.index_bytes,
                        value,
                    );
                }
                let mut memory = Memory::new(DATA);
                let mut expected_memory = memory.clone();
                let (expected, fault) = interpret(&function, &registers, &mut expected_memory);
                assert!(!fault, "{case:?} {level:?} address variant {variant}");
                run(&exec, entry, &mut registers, &mut memory);
                assert_state(
                    &registers,
                    &expected,
                    &format!("{case:?} {level:?} address {variant}"),
                );
                assert_eq!(
                    memory, expected_memory,
                    "{case:?} {level:?} address {variant}"
                );
                assert_eq!(memory.calls[0].1, DATA, "independent lane-zero address");
                comparisons += 1;
            }
        }
    }
    assert_eq!(comparisons, (24 * 5 + 24 * 6) * LEVELS.len());
}

#[test]
fn native_vsib_compatibility_mode_and_disabled_apx_exit_before_any_lane_or_completion() {
    if !supported() {
        return;
    }
    for case in cases() {
        for level in LEVELS {
            for apx_base in [false, true] {
                let bytes = case.address(
                    Some(if apx_base { 24 } else { 8 }),
                    4,
                    Some(-1),
                    true,
                    Some(0x64),
                    true,
                );
                let function = lift(&bytes, level);
                let (code, entry) = lower(&function);
                let exec = ExecMem::new(&code).unwrap();
                for empty in [false, true] {
                    for compatibility in [false, true] {
                        if !apx_base && !compatibility {
                            continue;
                        }
                        let mut registers = initial(case);
                        registers.cs_l = u64::from(!compatibility);
                        registers.apx_enabled = u64::from(compatibility);
                        if empty {
                            registers.k[case.mask as usize] = HIGH;
                        }
                        let mut expected = registers;
                        expected.exit_pc = PC;
                        let mut memory = Memory::new(DATA);
                        run(&exec, entry, &mut registers, &mut memory);
                        assert_state(&registers, &expected, "mode/APX frontier");
                        assert!(memory.calls.is_empty(), "guard precedes every helper");
                        assert_eq!(
                            registers.x86_vsib_instruction_ordinal, 0,
                            "mode/APX guard did not enter VSIB"
                        );
                        assert_eq!(
                            registers.x86_vsib_frontier_lane_plus_one, 0,
                            "mode/APX front-door exits are not partial completion"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn native_vsib_empty_gather_retains_preceding_native_vector_producer() {
    if !supported() {
        return;
    }
    for mut case in cases().into_iter().filter(|case| !case.scatter) {
        case.data = 1;
        case.index = 2;
        for level in LEVELS {
            // VPXOR XMM1,XMM1,XMM1 zeros its low 128 bits and all VEX upper
            // bits. No helper runs between this physical-register producer
            // and a zero-mask gather's final normalization.
            let producer_bytes = [0xC5, 0xF1, 0xEF, 0xC9];
            let mut context = LiftContext::new(SourceArch::X86_64);
            let mut lifter = X86_64Lifter::strict();
            let producer = lifter
                .lift_insn(PC - 4, &producer_bytes, &mut context)
                .unwrap();
            let gather_bytes = case.bytes();
            let gather = lifter.lift_insn(PC, &gather_bytes, &mut context).unwrap();
            let mut block = SmirBlock::new(BlockId(0), PC - 4);
            block.ops = producer.ops;
            block.ops.extend(gather.ops);
            block.set_terminator(Terminator::Return { values: Vec::new() });
            let mut function = SmirFunction::new(FunctionId(0), block.id, PC - 4);
            function.add_block(block);
            function.x86_instruction_bytes.insert(
                (BlockId(0), PC - 4),
                X86InstructionBytes::new(&producer_bytes).unwrap(),
            );
            function.x86_instruction_bytes.insert(
                (BlockId(0), PC),
                X86InstructionBytes::new(&gather_bytes).unwrap(),
            );
            optimize_function(&mut function, level);
            assert!(is_native_clobber_safe_excluding(
                &function,
                &HashMap::new(),
                true
            ));
            // The general mixed-region K16 gate is conservative for VPXOR.
            // This direct lowerer test can select the narrow bridge explicitly:
            // VPXOR does not read any opmask, and gather observes <=16 bits.
            let mut lowerer = X86_64Lowerer::new();
            lowerer.set_mem_helpers(true);
            lowerer.set_preserve_vector_mem_helpers(true);
            lowerer.set_native_vector_state_active(true);
            lowerer.set_narrow_vector_opmask_helpers(true);
            lowerer.set_jit_fault_deopt_guards(true);
            let result = lowerer.lower_function(&function).unwrap();
            assert!(result.relocations.is_empty());
            let code = lowerer.finalize().unwrap();
            let exec = ExecMem::new(&code).unwrap();
            let mut registers = initial(case);
            registers.k[case.mask as usize] = HIGH;
            let mut memory = Memory::new(DATA);
            memory.bytes.clear();
            let mut expected_memory = memory.clone();
            let (expected, fault) = interpret(&function, &registers, &mut expected_memory);
            assert!(!fault);
            run(&exec, result.entry_offset, &mut registers, &mut memory);
            assert_state(&registers, &expected, "native producer -> empty gather");
            assert_eq!(registers.zmm[1], [0; 8]);
            assert!(memory.calls.is_empty());
        }
    }
}
