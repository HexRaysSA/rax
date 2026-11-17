//! Machine behaviour on hand-built modules, where each property can be
//! isolated, and on one real object to tie the pieces to the decoder.

use std::collections::BTreeMap;

use super::{Exit, Fault, Outcome, Policy, run};
use crate::Limits;
use crate::ir::{
    Block, BlockIdx, Callee, FuncIdx, Function, IntBinary, IntFlags, Module, Op, Phi, Predicate,
    Signature, Slot, Terminator, Type, TypeId, Value,
};

const I32: TypeId = TypeId(0);
const I1: TypeId = TypeId(1);
/// `i32(i32)` with `noundef` on both sides.
const UNARY: TypeId = TypeId(2);

fn signature(params: usize, noundef: bool) -> Signature {
    Signature {
        params: vec![I32; params],
        results: vec![I32],
        param_noundef: vec![noundef; params],
        result_noundef: vec![noundef],
        variadic: false,
        portable_cc: true,
    }
}

fn module(functions: Vec<Function>) -> Module {
    let function_ids = functions
        .iter()
        .enumerate()
        .map(|(index, f)| (f.id, FuncIdx(index as u32)))
        .collect::<BTreeMap<_, _>>();
    Module {
        identity: [0; 32],
        types: vec![
            Type::Int { bits: 32 },
            Type::Int { bits: 1 },
            Type::Function(signature(1, true)),
        ],
        functions,
        function_ids,
        segments: Vec::new(),
        relocations: Vec::new(),
        exports: BTreeMap::new(),
        capabilities: Default::default(),
        initializers: Vec::new(),
        finalizers: Vec::new(),
    }
}

fn function(id: u32, params: usize, slots: u32, blocks: Vec<Block>) -> Function {
    Function {
        id,
        signature_type: UNARY,
        signature: signature(params, true),
        params: (0..params as u32).map(Slot).collect(),
        entry: BlockIdx(0),
        blocks,
        slots,
    }
}

fn block(id: u32, phis: Vec<Phi>, ops: Vec<Op>, term: Terminator) -> Block {
    Block {
        id,
        phis,
        ops,
        term,
    }
}

fn constant(dst: u32, value: u128) -> Op {
    Op::Const {
        dst: Slot(dst),
        value: Value::Int(value),
    }
}

fn execute(module: &Module, arguments: &[Value], policy: Policy) -> Outcome {
    run(module, FuncIdx(0), arguments, policy).expect("entry request is well formed")
}

/// `swap(n)`: start with (a, b) = (1, 2), exchange them once per iteration
/// through phis, and return `a` after `n` iterations.
fn swapping_loop() -> Module {
    let (n, one, two, zero, a, b, i, next, done) = (0, 1, 2, 3, 4, 5, 6, 7, 8);
    module(vec![function(
        10,
        1,
        9,
        vec![
            block(
                100,
                vec![],
                vec![constant(one, 1), constant(two, 2), constant(zero, 0)],
                Terminator::Jump(BlockIdx(1)),
            ),
            block(
                101,
                vec![
                    Phi {
                        dst: Slot(a),
                        incoming: vec![(BlockIdx(0), Slot(one)), (BlockIdx(1), Slot(b))],
                    },
                    Phi {
                        dst: Slot(b),
                        incoming: vec![(BlockIdx(0), Slot(two)), (BlockIdx(1), Slot(a))],
                    },
                    Phi {
                        dst: Slot(i),
                        incoming: vec![(BlockIdx(0), Slot(zero)), (BlockIdx(1), Slot(next))],
                    },
                ],
                vec![
                    Op::IntBinary {
                        dst: Slot(next),
                        op: IntBinary::Add,
                        bits: 32,
                        flags: IntFlags::default(),
                        lhs: Slot(i),
                        rhs: Slot(one),
                    },
                    Op::Icmp {
                        dst: Slot(done),
                        pred: Predicate::Eq,
                        bits: 32,
                        lhs: Slot(next),
                        rhs: Slot(n),
                    },
                ],
                Terminator::Branch {
                    cond: Slot(done),
                    if_true: BlockIdx(2),
                    if_false: BlockIdx(1),
                },
            ),
            block(102, vec![], vec![], Terminator::Return(vec![Slot(a)])),
        ],
    )])
}

#[test]
fn phis_of_one_block_commit_simultaneously() {
    let module = swapping_loop();
    // A sequential commit would copy b into a and then a back into b, making
    // both 2 from the second iteration on.
    for (iterations, expected) in [(1, 1), (2, 2), (3, 1), (4, 2), (9, 1)] {
        let outcome = execute(&module, &[Value::Int(iterations)], Policy::default());
        assert_eq!(
            outcome.exit,
            Exit::Return(vec![Value::Int(expected)]),
            "{iterations} iterations"
        );
        // Entry: phi commit, three constants, jump. Each iteration: phi
        // commit, two operations, branch. Exit block: phi commit, return.
        assert_eq!(outcome.steps, 5 + 4 * iterations as u64 + 2);
    }
}

#[test]
fn fuel_bounds_the_number_of_steps_exactly() {
    let module = swapping_loop();
    // 0 iterations never reaches equality before wrapping 2^32 times.
    for fuel in [0, 1, 5, 1000] {
        let outcome = execute(
            &module,
            &[Value::Int(0)],
            Policy {
                fuel,
                max_frames: 8,
                ..Policy::default()
            },
        );
        assert_eq!(
            outcome,
            Outcome {
                exit: Exit::Resource("fuel"),
                steps: fuel
            }
        );
    }
    // Exactly enough fuel for one iteration returns; one less does not.
    let enough = execute(
        &module,
        &[Value::Int(1)],
        Policy {
            fuel: 11,
            max_frames: 8,
            ..Policy::default()
        },
    );
    assert_eq!(enough.exit, Exit::Return(vec![Value::Int(1)]));
    let short = execute(
        &module,
        &[Value::Int(1)],
        Policy {
            fuel: 10,
            max_frames: 8,
            ..Policy::default()
        },
    );
    assert_eq!(
        short,
        Outcome {
            exit: Exit::Resource("fuel"),
            steps: 10
        }
    );
}

fn recursion() -> Module {
    module(vec![function(
        20,
        1,
        2,
        vec![block(
            200,
            vec![],
            vec![Op::Call {
                dsts: vec![Slot(1)],
                callee: Callee::Direct(FuncIdx(0)),
                args: vec![Slot(0)],
                arg_noundef: vec![true],
            }],
            Terminator::Return(vec![Slot(1)]),
        )],
    )])
}

#[test]
fn call_depth_is_bounded_by_the_frame_limit() {
    let module = recursion();
    for max_frames in [1, 2, 7] {
        let outcome = execute(
            &module,
            &[Value::Int(5)],
            Policy {
                fuel: 10_000,
                max_frames,
                ..Policy::default()
            },
        );
        assert_eq!(outcome.exit, Exit::Resource("frames"), "limit {max_frames}");
        // Each activation takes a phi-commit step and a call step; the limit
        // is noticed before the step of the frame that exceeds it.
        assert_eq!(outcome.steps, 2 * max_frames as u64);
    }
}

#[test]
fn a_poison_argument_to_a_noundef_parameter_is_undefined_at_the_call() {
    let mut module = recursion();
    module.functions[0].blocks[0].ops.insert(
        0,
        Op::Const {
            dst: Slot(0),
            value: Value::Poison,
        },
    );
    let outcome = execute(&module, &[Value::Int(5)], Policy::default());
    assert_eq!(
        outcome.exit,
        Exit::LanguageUb(Fault {
            code: "ub_noundef_argument".into(),
            function: 20,
            block: 200,
            operation: 1
        })
    );
    assert_eq!(outcome.steps, 3);
}

fn single_block(ops: Vec<Op>, term: Terminator, slots: u32) -> Module {
    module(vec![function(
        30,
        1,
        slots,
        vec![
            block(300, vec![], ops, term),
            block(301, vec![], vec![], Terminator::Return(vec![Slot(0)])),
        ],
    )])
}

#[test]
fn branching_or_switching_on_poison_or_undef_is_undefined() {
    for value in [Value::Poison, Value::Undef] {
        let branch = single_block(
            vec![Op::Const {
                dst: Slot(1),
                value,
            }],
            Terminator::Branch {
                cond: Slot(1),
                if_true: BlockIdx(1),
                if_false: BlockIdx(1),
            },
            2,
        );
        let switch = single_block(
            vec![Op::Const {
                dst: Slot(1),
                value,
            }],
            Terminator::Switch {
                index: Slot(1),
                cases: vec![(0, BlockIdx(1))],
                default: BlockIdx(1),
            },
            2,
        );
        for module in [branch, switch] {
            let outcome = execute(&module, &[Value::Int(1)], Policy::default());
            assert_eq!(
                outcome.exit,
                Exit::LanguageUb(Fault {
                    code: "ub_control_value".into(),
                    function: 30,
                    block: 300,
                    operation: 1
                })
            );
        }
    }
}

#[test]
fn switch_selects_the_matching_case_or_the_default() {
    let build = |selector: u128| {
        module(vec![function(
            40,
            1,
            3,
            vec![
                block(
                    400,
                    vec![],
                    vec![constant(1, 111), constant(2, 222)],
                    Terminator::Switch {
                        index: Slot(0),
                        cases: vec![(selector, BlockIdx(1)), (7, BlockIdx(1))],
                        default: BlockIdx(2),
                    },
                ),
                block(401, vec![], vec![], Terminator::Return(vec![Slot(1)])),
                block(402, vec![], vec![], Terminator::Return(vec![Slot(2)])),
            ],
        )])
    };
    let run_with = |selector, argument| {
        execute(&build(selector), &[Value::Int(argument)], Policy::default()).exit
    };
    assert_eq!(run_with(3, 3), Exit::Return(vec![Value::Int(111)]));
    assert_eq!(run_with(3, 7), Exit::Return(vec![Value::Int(111)]));
    assert_eq!(run_with(3, 4), Exit::Return(vec![Value::Int(222)]));
    assert_eq!(
        run_with(0xffff_ffff, 0xffff_ffff),
        Exit::Return(vec![Value::Int(111)])
    );
}

#[test]
fn returning_poison_from_a_noundef_result_is_undefined_but_freeze_makes_it_zero() {
    let poison = single_block(
        vec![Op::Const {
            dst: Slot(1),
            value: Value::Poison,
        }],
        Terminator::Return(vec![Slot(1)]),
        2,
    );
    let outcome = execute(&poison, &[Value::Int(1)], Policy::default());
    assert_eq!(
        outcome.exit,
        Exit::LanguageUb(Fault {
            code: "ub_noundef_result".into(),
            function: 30,
            block: 300,
            operation: 1
        })
    );
    for value in [Value::Poison, Value::Undef] {
        let frozen = single_block(
            vec![
                Op::Const {
                    dst: Slot(1),
                    value,
                },
                Op::Freeze {
                    dst: Slot(2),
                    src: Slot(1),
                    zero: Value::Int(0),
                },
            ],
            Terminator::Return(vec![Slot(2)]),
            3,
        );
        let outcome = execute(&frozen, &[Value::Int(1)], Policy::default());
        assert_eq!(outcome.exit, Exit::Return(vec![Value::Int(0)]));
    }
}

#[test]
fn select_forwards_the_chosen_arm_and_propagates_a_poison_condition() {
    let build = |condition: Value| {
        single_block(
            vec![
                Op::Const {
                    dst: Slot(1),
                    value: condition,
                },
                Op::Const {
                    dst: Slot(2),
                    value: Value::Int(9),
                },
                Op::Select {
                    dst: Slot(3),
                    cond: Slot(1),
                    if_true: Slot(0),
                    if_false: Slot(2),
                },
                Op::Freeze {
                    dst: Slot(4),
                    src: Slot(3),
                    zero: Value::Int(77),
                },
            ],
            Terminator::Return(vec![Slot(4)]),
            5,
        )
    };
    let result = |condition| execute(&build(condition), &[Value::Int(5)], Policy::default()).exit;
    assert_eq!(result(Value::Int(1)), Exit::Return(vec![Value::Int(5)]));
    assert_eq!(result(Value::Int(0)), Exit::Return(vec![Value::Int(9)]));
    // An undef condition refines to false. A poison condition poisons the
    // result, which the freeze then turns into its zero value (77 here, to
    // tell it apart from either arm).
    assert_eq!(result(Value::Undef), Exit::Return(vec![Value::Int(9)]));
    assert_eq!(result(Value::Poison), Exit::Return(vec![Value::Int(77)]));
}

#[test]
fn division_by_zero_and_explicit_traps_are_located() {
    let divide = single_block(
        vec![
            constant(1, 0),
            Op::IntBinary {
                dst: Slot(2),
                op: IntBinary::UDiv,
                bits: 32,
                flags: IntFlags::default(),
                lhs: Slot(0),
                rhs: Slot(1),
            },
        ],
        Terminator::Return(vec![Slot(2)]),
        3,
    );
    assert_eq!(
        execute(&divide, &[Value::Int(1)], Policy::default()).exit,
        Exit::LanguageUb(Fault {
            code: "ub_div_zero".into(),
            function: 30,
            block: 300,
            operation: 1
        })
    );
    let trap = single_block(
        vec![],
        Terminator::Trap {
            reason: "bounds".into(),
        },
        1,
    );
    assert_eq!(
        execute(&trap, &[Value::Int(1)], Policy::default()).exit,
        Exit::Trap(Fault {
            code: "bounds".into(),
            function: 30,
            block: 300,
            operation: 0
        })
    );
    let unreachable = single_block(vec![], Terminator::Unreachable, 1);
    assert_eq!(
        execute(&unreachable, &[Value::Int(1)], Policy::default()).exit,
        Exit::LanguageUb(Fault {
            code: "ub_unreachable".into(),
            function: 30,
            block: 300,
            operation: 0
        })
    );
}

#[test]
fn entry_arguments_must_match_the_signature() {
    let module = swapping_loop();
    for arguments in [
        vec![],
        vec![Value::Int(1), Value::Int(2)],
        vec![Value::Int(1 << 32)],
        vec![Value::DataPtr(crate::ir::Pointer::originless(0))],
    ] {
        let error = run(&module, FuncIdx(0), &arguments, Policy::default()).unwrap_err();
        assert_eq!(error.code(), "EXEC_ENTRY", "{arguments:?}");
    }
    assert_eq!(
        run(&module, FuncIdx(9), &[Value::Int(1)], Policy::default())
            .unwrap_err()
            .code(),
        "EXEC_ENTRY"
    );
}

#[test]
fn the_reference_call_fixture_loads_and_returns_its_argument_through_a_bound_pointer() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/specifications/smir/portable/conformance/envelope/candidate/reference-execution/call42.smo"
    );
    let bytes = std::fs::read(path).expect("fixture is part of the repository");
    let module = Module::load(&bytes, Limits::default()).expect("fixture verifies and lowers");
    let entry = module.function(1).expect("function 1 is the caller");
    for argument in [42, 0, 0xffff_ffff] {
        let outcome = run(&module, entry, &[Value::Int(argument)], Policy::default()).unwrap();
        // address_of, code_bind and an indirect call into the identity
        // function: seven steps, as the Python reference machine reports.
        assert_eq!(
            outcome,
            Outcome {
                exit: Exit::Return(vec![Value::Int(argument)]),
                steps: 7
            }
        );
    }
}

/// Function 0 returns its argument; function 1, which takes and returns
/// nothing, is the module's one initializer and ends with `term`.
fn initialized(term: Terminator) -> Module {
    let mut module = module(vec![
        function(
            40,
            1,
            1,
            vec![block(
                400,
                vec![],
                vec![],
                Terminator::Return(vec![Slot(0)]),
            )],
        ),
        function(
            41,
            0,
            1,
            vec![block(410, vec![], vec![constant(0, 9)], term)],
        ),
    ]);
    module.initializers = vec![FuncIdx(1)];
    module
}

#[test]
fn initializers_run_first_and_share_the_step_limit() {
    let module = initialized(Terminator::Return(vec![]));
    // Three steps of the initializer, then two of the entry.
    assert_eq!(
        execute(&module, &[Value::Int(5)], Policy::default()),
        Outcome {
            exit: Exit::Return(vec![Value::Int(5)]),
            steps: 5
        }
    );
    for (fuel, exit) in [
        (2, Exit::Resource("fuel")),
        (4, Exit::Resource("fuel")),
        (5, Exit::Return(vec![Value::Int(5)])),
    ] {
        let policy = Policy {
            fuel,
            ..Policy::default()
        };
        assert_eq!(
            execute(&module, &[Value::Int(5)], policy).exit,
            exit,
            "fuel {fuel}"
        );
    }
    // The entry request is checked before anything runs.
    assert_eq!(
        run(&module, FuncIdx(0), &[], Policy::default())
            .unwrap_err()
            .code(),
        "EXEC_ENTRY"
    );
}

#[test]
fn an_initializer_that_does_not_return_ends_the_run() {
    let module = initialized(Terminator::Unreachable);
    let outcome = execute(&module, &[Value::Int(5)], Policy::default());
    assert_eq!(
        outcome,
        Outcome {
            exit: Exit::LanguageUb(Fault {
                code: "ub_unreachable".into(),
                function: 41,
                block: 410,
                operation: 1,
            }),
            steps: 3
        }
    );
}
