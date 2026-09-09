//! Independent arithmetic, interpreter, native-state, and fault-frontier checks.

use super::*;
use crate::smir::interpret::{BlockResult, SmirInterpreter};
use crate::smir::ir::TrapKind;
use crate::smir::ir::context::{ArchRegState, ExitReason, SmirContext};
use crate::smir::ir::flags::MaterializedFlags;
use crate::smir::ir::memory::{FlatMemory, SmirMemory};
use crate::smir::lower::runtime::{ExecMem, GuestRegs};

const ARITH: u64 = 0x8D5;
const LEFT_VALUES: [u64; 6] = [
    0,
    1,
    u64::MAX,
    i64::MIN as u64,
    i64::MAX as u64,
    0xFEDC_BA98_7654_3210,
];

/// Independent fixed-width reference: arithmetic is evaluated in 128 bits,
/// reduced modulo 2^64, and flags are derived from value/range predicates.
/// Logical AF is architecturally undefined and is deliberately not compared.
fn reference(group: u8, lhs: u64, rhs: u64, flags: u64, update: FlagUpdate) -> (u64, u64, u64) {
    let carry = u64::from(flags & 1 != 0 && matches!(group, 2 | 3));
    let (value, cf, of) = match group {
        0 | 2 => {
            let unsigned = u128::from(lhs) + u128::from(rhs) + u128::from(carry);
            let signed = i128::from(lhs as i64) + i128::from(rhs as i64) + i128::from(carry);
            (
                unsigned as u64,
                unsigned > u128::from(u64::MAX),
                signed < i128::from(i64::MIN) || signed > i128::from(i64::MAX),
            )
        }
        3 | 5 | 7 => {
            let subtrahend = u128::from(rhs) + u128::from(carry);
            let signed = i128::from(lhs as i64) - i128::from(rhs as i64) - i128::from(carry);
            (
                lhs.wrapping_sub(rhs).wrapping_sub(carry),
                u128::from(lhs) < subtrahend,
                signed < i128::from(i64::MIN) || signed > i128::from(i64::MAX),
            )
        }
        1 => (lhs | rhs, false, false),
        4 | 8 => (lhs & rhs, false, false),
        6 => (lhs ^ rhs, false, false),
        _ => unreachable!("nine scalar test groups"),
    };
    if update == FlagUpdate::None && group < 7 {
        return (value, flags, u64::MAX);
    }
    let logical = matches!(group, 1 | 4 | 6 | 8);
    let defined = if logical { ARITH & !0x10 } else { ARITH };
    let generated = u64::from(cf)
        | (u64::from((value as u8).count_ones() % 2 == 0) << 2)
        | (u64::from((lhs ^ rhs ^ value) & 0x10 != 0) << 4)
        | (u64::from(value == 0) << 6)
        | (u64::from(value >> 63 != 0) << 7)
        | (u64::from(of) << 11);
    (
        value,
        (flags & !defined) | (generated & defined),
        !if logical { 0x10 } else { 0 },
    )
}

fn initial(carry: bool) -> GuestRegs {
    let mut regs = GuestRegs {
        gpr: core::array::from_fn(|index| {
            0x1020_3040_5060_7080u64
                .wrapping_add((index as u64).wrapping_mul(0x0101_1111_2222_3333))
        }),
        rflags: 0x8D6 | u64::from(carry),
        exit_pc: 0xAAAA_BBBB_CCCC_DDDD,
        mxcsr: 0x3FA1,
        k: core::array::from_fn(|index| 0x0123_4567_89AB_CDEFu64.rotate_left(index as u32)),
        ..GuestRegs::default()
    };
    for (index, vector) in regs.zmm.iter_mut().enumerate() {
        *vector = core::array::from_fn(|lane| {
            0x1122_3344_5566_7788u64.wrapping_add((index * 8 + lane) as u64)
        });
    }
    regs
}

fn lower(function: &SmirFunction) -> (ExecMem, usize) {
    assert!(
        is_native_clobber_safe_excluding(function, &HashMap::new(), true),
        "{function:#?}"
    );
    let mut lowerer = X86_64Lowerer::new();
    lowerer.set_mem_helpers(true);
    lowerer.set_jit_fault_deopt_guards(true);
    let lowered = lowerer
        .lower_function(function)
        .expect("lower full-width scalar immediate");
    let code = lowerer
        .finalize()
        .expect("finalize full-width scalar immediate");
    (
        ExecMem::new(&code).expect("map full-width scalar immediate"),
        lowered.entry_offset,
    )
}

fn interpret(
    function: &SmirFunction,
    initial: &GuestRegs,
    memory: &mut FlatMemory,
) -> ([u64; 32], u64) {
    let mut context = SmirContext::new_x86_64();
    let ArchRegState::X86_64(regs) = &mut context.arch_regs else {
        unreachable!()
    };
    regs.gpr = initial.gpr;
    regs.rflags = initial.rflags;
    context.flags.materialized = MaterializedFlags::from_rflags(initial.rflags);
    context.flags.lazy = None;
    let mut block = function.blocks[0].clone();
    block.set_terminator(Terminator::Trap {
        kind: TrapKind::Halt,
    });
    let result = SmirInterpreter::new().execute_block(&mut context, memory, &block);
    assert!(
        matches!(result, BlockResult::Exit(ExitReason::Halt)),
        "{result:?}"
    );
    // Arithmetic status lives in the lazy flag bank until explicitly read;
    // the architectural image alone still contains the incoming status bits.
    context.flags.materialize_all();
    let ArchRegState::X86_64(regs) = &context.arch_regs else {
        unreachable!()
    };
    (
        regs.gpr,
        (regs.rflags & !ARITH) | (context.flags.materialized.to_rflags() & ARITH),
    )
}

fn assert_state(actual: GuestRegs, mut expected: GuestRegs, flag_mask: u64, label: &str) {
    expected.host_mxcsr = actual.host_mxcsr;
    expected.rflags = (expected.rflags & flag_mask) | (actual.rflags & !flag_mask);
    assert_eq!(actual, expected, "{label}");
}

#[test]
fn register_immediates_match_independent_arithmetic_and_interpretation() {
    let mut executions = 0;
    // Every GPR and alias shape sees every boundary value in both operand
    // representations. Input samples rotate across the matrix; two carry
    // values are always exercised, including flag-suppressed ADC/SBB.
    for level in LEVELS {
        for group in 0..=8 {
            for source in 0..32 {
                for destination in [source, (source + 17) & 31] {
                    for (ordinal, value) in VALUES.into_iter().enumerate() {
                        for imm64 in [false, true] {
                            for flags in [FlagUpdate::None, FlagUpdate::All] {
                                let mut function = function(vec![scalar(
                                    group,
                                    gpr(destination),
                                    gpr(source),
                                    immediate(value, imm64),
                                    OpWidth::W64,
                                    flags,
                                )]);
                                optimize_function(&mut function, level);
                                let (exec, entry) = lower(&function);
                                for carry in [false, true] {
                                    let mut regs = initial(carry);
                                    regs.gpr[source as usize] = LEFT_VALUES
                                        [(ordinal + source as usize) % LEFT_VALUES.len()];
                                    let mut expected = regs;
                                    let (result, out_flags, mask) = reference(
                                        group,
                                        regs.gpr[source as usize],
                                        value as u64,
                                        regs.rflags,
                                        flags,
                                    );
                                    if group < 7 {
                                        expected.gpr[destination as usize] = result;
                                    }
                                    expected.rflags = out_flags;
                                    let interpreted =
                                        interpret(&function, &regs, &mut FlatMemory::new(1));
                                    let label = format!(
                                        "{level:?} group={group} r{destination},r{source},{value:#x} imm64={imm64} {flags:?} carry={carry}"
                                    );
                                    assert_eq!(interpreted.0, expected.gpr, "SMIR GPR {label}");
                                    assert_eq!(
                                        interpreted.1 & mask,
                                        expected.rflags & mask,
                                        "SMIR flags {label}"
                                    );
                                    exec.run(entry, &mut regs);
                                    assert_state(regs, expected, mask, &label);
                                    executions += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    assert_eq!(executions, 3 * 9 * 32 * 2 * VALUES.len() * 2 * 2 * 2);
    eprintln!("executed {executions} native W64 immediate register differentials");
}

#[repr(C)]
struct LoadResult {
    value: u64,
    ok: u64,
}

#[derive(Default)]
struct Memory {
    value: u64,
    load_ok: u64,
    store_ok: u64,
    calls: Vec<(bool, u64, u64, u64)>,
}

extern "C" fn load_helper(
    context: *mut Memory,
    address: u64,
    size: u64,
    signed: u64,
) -> LoadResult {
    // SAFETY: memory_regs supplies an aligned pointer to initialized Memory
    // that remains live and unmoved throughout ExecMem::run. Callbacks are
    // synchronous and serial; the caller holds no other active Memory borrow.
    let memory = unsafe { &mut *context };
    memory.calls.push((false, address, size, signed));
    LoadResult {
        value: memory.value,
        ok: memory.load_ok,
    }
}

extern "C" fn store_helper(context: *mut Memory, address: u64, value: u64, size: u64) -> u64 {
    // SAFETY: memory_regs supplies an aligned pointer to initialized Memory
    // that remains live and unmoved throughout ExecMem::run. Callbacks are
    // synchronous and serial; the caller holds no other active Memory borrow.
    let memory = unsafe { &mut *context };
    memory.calls.push((true, address, size, value));
    if memory.store_ok != 0 {
        memory.value = value;
    }
    memory.store_ok
}

fn memory_regs(memory: &mut Memory, base: u8, carry: bool) -> GuestRegs {
    let mut regs = initial(carry);
    regs.gpr[base as usize] = 0x2000;
    regs.ctx = (memory as *mut Memory) as u64;
    regs.load_fn = load_helper as *const () as u64;
    regs.store_fn = store_helper as *const () as u64;
    regs
}

fn source_function(
    group: u8,
    destination: u8,
    value: i64,
    imm64: bool,
    flags: FlagUpdate,
) -> SmirFunction {
    let loaded = VReg::virt(200);
    function(vec![
        OpKind::Load {
            dst: loaded,
            addr: Address::Direct(gpr(destination)),
            width: MemWidth::B8,
            sign: SignExtend::Zero,
        },
        scalar(
            group,
            gpr(destination),
            loaded,
            immediate(value, imm64),
            OpWidth::W64,
            flags,
        ),
    ])
}

#[test]
fn memory_source_immediates_match_interpretation_and_fault_before_destination_commit() {
    let mut successes = 0;
    let mut faults = 0;
    for level in LEVELS {
        for group in 0..=8 {
            for destination in 0..32 {
                for (ordinal, value) in VALUES.into_iter().enumerate() {
                    for imm64 in [false, true] {
                        for flags in [FlagUpdate::None, FlagUpdate::All] {
                            let mut function =
                                source_function(group, destination, value, imm64, flags);
                            optimize_function(&mut function, level);
                            let (exec, entry) = lower(&function);
                            for carry in [false, true] {
                                let old = LEFT_VALUES
                                    [(ordinal + destination as usize) % LEFT_VALUES.len()];
                                let label = format!(
                                    "source {level:?} group={group} r{destination} {value:#x} imm64={imm64} {flags:?} carry={carry}"
                                );
                                let mut memory = Memory {
                                    value: old,
                                    load_ok: 1,
                                    store_ok: 1,
                                    ..Memory::default()
                                };
                                let mut regs = memory_regs(&mut memory, destination, carry);
                                let mut expected = regs;
                                let (result, out_flags, mask) =
                                    reference(group, old, value as u64, regs.rflags, flags);
                                if group < 7 {
                                    expected.gpr[destination as usize] = result;
                                }
                                expected.rflags = out_flags;
                                let mut flat = FlatMemory::with_base(0x2000, 8);
                                flat.load(0, &old.to_le_bytes());
                                let interpreted = interpret(&function, &regs, &mut flat);
                                assert_eq!(interpreted.0, expected.gpr, "SMIR GPR {label}");
                                assert_eq!(
                                    interpreted.1 & mask,
                                    expected.rflags & mask,
                                    "SMIR flags {label}"
                                );
                                exec.run(entry, &mut regs);
                                assert_state(regs, expected, mask, &label);
                                assert_eq!(memory.calls, [(false, 0x2000, 8, 0)], "{label}");
                                assert_eq!(memory.value, old, "{label}");
                                successes += 1;

                                memory.calls.clear();
                                memory.load_ok = 0;
                                let mut regs = memory_regs(&mut memory, destination, carry);
                                let mut expected = regs;
                                expected.exit_pc = PC;
                                exec.run(entry, &mut regs);
                                assert_state(regs, expected, u64::MAX, &format!("fault {label}"));
                                assert_eq!(memory.calls, [(false, 0x2000, 8, 0)], "fault {label}");
                                assert_eq!(memory.value, old, "fault {label}");
                                faults += 1;
                            }
                        }
                    }
                }
            }
        }
    }
    let cases = 3 * 9 * 32 * VALUES.len() * 2 * 2 * 2;
    assert_eq!((successes, faults), (cases, cases));
    eprintln!(
        "executed {successes} successful and {faults} faulting native W64 immediate memory-source cases"
    );
}

fn rmw_function(
    group: u8,
    base: u8,
    value: i64,
    imm64: bool,
    replay: bool,
    atomic: bool,
) -> SmirFunction {
    let old = VReg::virt(200);
    let result = VReg::virt(201);
    let flags_result = VReg::virt(202);
    let source = VReg::virt(203);
    let address = Address::Direct(gpr(base));
    let mut ops = if atomic {
        let op = match group {
            0 => AtomicOp::Add,
            1 => AtomicOp::Or,
            4 => AtomicOp::And,
            5 => AtomicOp::Sub,
            6 => AtomicOp::Xor,
            _ => unreachable!("existing atomic groups"),
        };
        vec![
            OpKind::Mov {
                dst: source,
                src: immediate(value, imm64),
                width: OpWidth::W64,
            },
            OpKind::AtomicRmw {
                dst: old,
                addr: address,
                src: source,
                op,
                width: MemWidth::B8,
                order: MemoryOrder::SeqCst,
            },
        ]
    } else {
        vec![
            OpKind::Load {
                dst: old,
                addr: address.clone(),
                width: MemWidth::B8,
                sign: SignExtend::Zero,
            },
            scalar(
                group,
                result,
                old,
                immediate(value, imm64),
                OpWidth::W64,
                FlagUpdate::None,
            ),
            OpKind::Store {
                src: result,
                addr: address,
                width: MemWidth::B8,
            },
        ]
    };
    if replay {
        ops.push(scalar(
            group,
            flags_result,
            old,
            immediate(value, !imm64),
            OpWidth::W64,
            FlagUpdate::All,
        ));
    }
    function(ops)
}

fn check_rmw(atomic: bool) {
    let mut successes = 0;
    let mut faults = 0;
    let groups: &[u8] = if atomic {
        &[0, 1, 4, 5, 6]
    } else {
        &[0, 1, 2, 3, 4, 5, 6]
    };
    for level in LEVELS {
        for &group in groups {
            for base in [0, 4, 5, 11, 16, 31] {
                for (ordinal, value) in VALUES.into_iter().enumerate() {
                    for imm64 in [false, true] {
                        for replay in [false, true] {
                            let mut function =
                                rmw_function(group, base, value, imm64, replay, atomic);
                            optimize_function(&mut function, level);
                            let (exec, entry) = lower(&function);
                            for carry in [false, true] {
                                let old = LEFT_VALUES[ordinal % LEFT_VALUES.len()];
                                let label = format!(
                                    "RMW atomic={atomic} {level:?} group={group} base=r{base} {value:#x} imm64={imm64} replay={replay} carry={carry}"
                                );
                                let mut memory = Memory {
                                    value: old,
                                    load_ok: 1,
                                    store_ok: 1,
                                    ..Memory::default()
                                };
                                let mut regs = memory_regs(&mut memory, base, carry);
                                let mut expected = regs;
                                let update = if replay {
                                    FlagUpdate::All
                                } else {
                                    FlagUpdate::None
                                };
                                let (result, out_flags, mask) =
                                    reference(group, old, value as u64, regs.rflags, update);
                                expected.rflags = out_flags;
                                let mut flat = FlatMemory::with_base(0x2000, 8);
                                flat.load(0, &old.to_le_bytes());
                                let interpreted = interpret(&function, &regs, &mut flat);
                                assert_eq!(interpreted.0, expected.gpr, "SMIR GPR {label}");
                                assert_eq!(
                                    interpreted.1 & mask,
                                    expected.rflags & mask,
                                    "SMIR flags {label}"
                                );
                                let mut bytes = [0; 8];
                                flat.read(0x2000, &mut bytes).unwrap();
                                assert_eq!(
                                    u64::from_le_bytes(bytes),
                                    result,
                                    "SMIR memory {label}"
                                );
                                exec.run(entry, &mut regs);
                                assert_state(regs, expected, mask, &label);
                                assert_eq!(memory.value, result, "{label}");
                                assert_eq!(
                                    memory.calls,
                                    [(false, 0x2000, 8, 0), (true, 0x2000, 8, result)],
                                    "{label}"
                                );
                                successes += 1;

                                for fault_load in [true, false] {
                                    memory.calls.clear();
                                    memory.value = old;
                                    memory.load_ok = u64::from(!fault_load);
                                    memory.store_ok = 0;
                                    let mut regs = memory_regs(&mut memory, base, carry);
                                    let mut expected = regs;
                                    expected.exit_pc = PC;
                                    exec.run(entry, &mut regs);
                                    assert_state(
                                        regs,
                                        expected,
                                        u64::MAX,
                                        &format!("fault load={fault_load} {label}"),
                                    );
                                    assert_eq!(memory.value, old, "fault {label}");
                                    let mut expected_calls = vec![(false, 0x2000, 8, 0)];
                                    if !fault_load {
                                        expected_calls.push((true, 0x2000, 8, result));
                                    }
                                    assert_eq!(memory.calls, expected_calls, "fault {label}");
                                    faults += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    let cases = 3 * groups.len() * 6 * VALUES.len() * 2 * 2 * 2;
    assert_eq!((successes, faults), (cases, cases * 2));
    eprintln!(
        "executed {successes} successful and {faults} faulting native W64 immediate RMW cases (atomic={atomic})"
    );
}

#[test]
fn unlocked_rmw_immediates_match_interpretation_and_preserve_fault_frontiers() {
    check_rmw(false);
}

#[test]
fn existing_atomic_immediates_match_interpretation_and_preserve_fault_frontiers() {
    check_rmw(true);
}

#[test]
fn existing_atomic_swap_full_width_immediates_preserve_flags_and_fault_frontiers() {
    let source = VReg::virt(200);
    let old = VReg::virt(201);
    let mut executions = 0;
    for level in LEVELS {
        for value in VALUES {
            for imm64 in [false, true] {
                let mut function = function(vec![
                    OpKind::Mov {
                        dst: source,
                        src: immediate(value, imm64),
                        width: OpWidth::W64,
                    },
                    OpKind::AtomicRmw {
                        dst: old,
                        addr: Address::Direct(gpr(5)),
                        src: source,
                        op: AtomicOp::Swap,
                        width: MemWidth::B8,
                        order: MemoryOrder::SeqCst,
                    },
                ]);
                optimize_function(&mut function, level);
                let (exec, entry) = lower(&function);
                for carry in [false, true] {
                    for (load_ok, store_ok) in [(1, 1), (0, 0), (1, 0)] {
                        let label = format!(
                            "atomic swap {level:?} {value:#x} imm64={imm64} carry={carry} load_ok={load_ok} store_ok={store_ok}"
                        );
                        let before = 0xFEDC_BA98_7654_3210;
                        let mut memory = Memory {
                            value: before,
                            load_ok,
                            store_ok,
                            ..Memory::default()
                        };
                        let mut regs = memory_regs(&mut memory, 5, carry);
                        let mut expected = regs;
                        if load_ok == 0 || store_ok == 0 {
                            expected.exit_pc = PC;
                        }
                        if load_ok != 0 && store_ok != 0 {
                            let mut flat = FlatMemory::with_base(0x2000, 8);
                            flat.load(0, &before.to_le_bytes());
                            let interpreted = interpret(&function, &regs, &mut flat);
                            assert_eq!(interpreted, (regs.gpr, regs.rflags), "SMIR state {label}");
                            let mut bytes = [0; 8];
                            flat.read(0x2000, &mut bytes).unwrap();
                            assert_eq!(
                                u64::from_le_bytes(bytes),
                                value as u64,
                                "SMIR memory {label}"
                            );
                        }
                        exec.run(entry, &mut regs);
                        assert_state(regs, expected, u64::MAX, &label);
                        let mut calls = vec![(false, 0x2000, 8, 0)];
                        if load_ok != 0 {
                            calls.push((true, 0x2000, 8, value as u64));
                        }
                        assert_eq!(memory.calls, calls, "{label}");
                        assert_eq!(
                            memory.value,
                            if load_ok != 0 && store_ok != 0 {
                                value as u64
                            } else {
                                before
                            },
                            "{label}"
                        );
                        executions += 1;
                    }
                }
            }
        }
    }
    assert_eq!(executions, 3 * VALUES.len() * 2 * 2 * 3);
    eprintln!("executed {executions} native W64 immediate atomic-swap success/fault cases");
}
