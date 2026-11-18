//! Every instruction sequence against the interpreter's code for the same
//! operation, on hand-built functions: each operation at many widths, with
//! every flag, on operands at and around the edges of the width, and on
//! poison and undefined operands, which the sequences must leave to the
//! interpreter's code. The two engines must return the same value or stop
//! with the same fault.

use std::collections::BTreeMap;

use super::Code;
use crate::interp::{Engine, Exit, NoHost, Policy, run_on};
use crate::ir::{
    Block, BlockIdx, Cast, FuncIdx, Function, IntBinary, IntFlags, Module, Op, Phi, Predicate,
    Signature, Slot, Terminator, Type, TypeId, Value,
};

/// A function of no parameters and one result, of the module's one
/// signature: the tests never look at the result's type.
fn function(blocks: Vec<Block>, slots: u32) -> Function {
    Function {
        id: 0,
        signature_type: TypeId(1),
        signature: signature(),
        params: Vec::new(),
        entry: BlockIdx(0),
        blocks,
        slots,
    }
}

fn signature() -> Signature {
    Signature {
        params: Vec::new(),
        results: vec![TypeId(0)],
        param_noundef: Vec::new(),
        result_noundef: vec![false],
        variadic: false,
        portable_cc: true,
    }
}

fn module(mut functions: Vec<Function>) -> Module {
    for (index, function) in functions.iter_mut().enumerate() {
        function.id = index as u32;
    }
    let function_ids = (0..functions.len() as u32)
        .map(|index| (index, FuncIdx(index)))
        .collect::<BTreeMap<_, _>>();
    Module {
        identity: [0; 32],
        types: vec![Type::Int { bits: 128 }, Type::Function(signature())],
        functions,
        function_ids,
        segments: Vec::new(),
        relocations: Vec::new(),
        thread_local: Vec::new(),
        exports: BTreeMap::new(),
        capabilities: Default::default(),
        initializers: Vec::new(),
        finalizers: Vec::new(),
    }
}

fn block(ops: Vec<Op>, term: Terminator) -> Block {
    Block {
        id: 0,
        phis: Vec::new(),
        ops,
        term,
    }
}

fn constant(dst: u32, value: Value) -> Op {
    Op::Const {
        dst: Slot(dst),
        value,
    }
}

/// `return op(first, second)`, the operands being constants.
fn straight(first: Value, second: Value, op: Op) -> Function {
    function(
        vec![block(
            vec![constant(0, first), constant(1, second), op],
            Terminator::Return(vec![Slot(2)]),
        )],
        3,
    )
}

fn mask(bits: u32) -> u128 {
    u128::MAX >> (128 - bits)
}

/// Values of `bits` bits at and around its edges, and the two that are no
/// value.
fn operands(bits: u32) -> Vec<Value> {
    let mask = mask(bits);
    let sign = 1_u128 << (bits - 1);
    let mut values: Vec<u128> = [
        0,
        1,
        2,
        3,
        mask,
        mask - 1,
        sign,
        sign.wrapping_sub(1),
        sign + 1,
        0x5555_5555_5555_5555_5555_5555_5555_5555,
        u128::from(bits),
        u128::from(bits) - 1,
    ]
    .into_iter()
    .map(|value| value & mask)
    .collect();
    values.sort_unstable();
    values.dedup();
    values
        .into_iter()
        .map(Value::Int)
        .chain([Value::Poison, Value::Undef])
        .collect()
}

/// Run every function of `module` on both engines and require the same
/// outcome. Returns how many returned a defined integer, how many returned
/// something else, and how many stopped with a fault.
fn agree(module: &Module, what: impl Fn(usize) -> String) -> (usize, usize, usize) {
    let code = Code::compile(module).expect("the module compiles for this host");
    let (mut integers, mut others, mut faults) = (0, 0, 0);
    for index in 0..module.functions.len() {
        let run = |engine| {
            run_on(
                engine,
                module,
                FuncIdx(index as u32),
                &[],
                Policy::default(),
                &mut NoHost,
            )
            .expect("entry request")
        };
        let (interpreted, native) = (run(Engine::Interpreter), run(Engine::Native(&code)));
        assert_eq!(native, interpreted, "{}", what(index));
        match interpreted.exit {
            Exit::Return(values) if matches!(values[..], [Value::Int(_)]) => integers += 1,
            Exit::Return(_) => others += 1,
            _ => faults += 1,
        }
    }
    (integers, others, faults)
}

const WIDTHS: [u32; 12] = [1, 2, 7, 8, 16, 31, 32, 33, 63, 64, 65, 128];

#[test]
fn two_operand_integer_operations_agree_at_every_width_and_flag() {
    let operations = [
        IntBinary::Add,
        IntBinary::Sub,
        IntBinary::Mul,
        IntBinary::UDiv,
        IntBinary::SDiv,
        IntBinary::URem,
        IntBinary::SRem,
        IntBinary::Shl,
        IntBinary::LShr,
        IntBinary::AShr,
        IntBinary::And,
        IntBinary::Or,
        IntBinary::Xor,
        IntBinary::RotL,
        IntBinary::RotR,
    ];
    let mut functions = Vec::new();
    let mut described = Vec::new();
    for bits in WIDTHS {
        let values = operands(bits);
        for op in operations {
            for flag in 0..8 {
                let flags = IntFlags {
                    nsw: flag & 1 != 0,
                    nuw: flag & 2 != 0,
                    exact: flag & 4 != 0,
                };
                // A flag changes nothing for an operation it does not
                // apply to, so those combinations are left out.
                let wrapping = matches!(
                    op,
                    IntBinary::Add | IntBinary::Sub | IntBinary::Mul | IntBinary::Shl
                );
                let dividing = matches!(
                    op,
                    IntBinary::UDiv | IntBinary::SDiv | IntBinary::LShr | IntBinary::AShr
                );
                if ((flags.nsw || flags.nuw) && !wrapping) || (flags.exact && !dividing) {
                    continue;
                }
                for first in &values {
                    for second in &values {
                        functions.push(straight(
                            *first,
                            *second,
                            Op::IntBinary {
                                dst: Slot(2),
                                op,
                                bits,
                                flags,
                                lhs: Slot(0),
                                rhs: Slot(1),
                            },
                        ));
                        described.push((op, bits, flags, *first, *second));
                    }
                }
            }
        }
    }
    let module = module(functions);
    let (integers, others, faults) = agree(&module, |index| format!("{:?}", described[index]));
    eprintln!(
        "{} two-operand cases agree: {integers} integers, {others} poison, {faults} faults",
        described.len()
    );
    assert!(integers > 20_000 && others > 5_000 && faults > 1_000);
}

#[test]
fn comparisons_and_conversions_agree_at_every_width() {
    let predicates = [
        Predicate::Eq,
        Predicate::Ne,
        Predicate::Ult,
        Predicate::Ule,
        Predicate::Ugt,
        Predicate::Uge,
        Predicate::Slt,
        Predicate::Sle,
        Predicate::Sgt,
        Predicate::Sge,
    ];
    let mut functions = Vec::new();
    let mut described = Vec::new();
    for bits in WIDTHS {
        let values = operands(bits);
        for pred in predicates {
            for first in &values {
                for second in &values {
                    functions.push(straight(
                        *first,
                        *second,
                        Op::Icmp {
                            dst: Slot(2),
                            pred,
                            bits,
                            lhs: Slot(0),
                            rhs: Slot(1),
                        },
                    ));
                    described.push(format!("{pred:?} {bits} {first:?} {second:?}"));
                }
            }
        }
        // To and from every other width.
        for other in WIDTHS {
            for (op, from_bits, to_bits) in [
                (Cast::Trunc, bits.max(other), bits.min(other)),
                (Cast::Zext, bits.min(other), bits.max(other)),
                (Cast::Sext, bits.min(other), bits.max(other)),
            ] {
                if from_bits == to_bits {
                    continue;
                }
                for value in operands(from_bits) {
                    functions.push(straight(
                        value,
                        Value::Undef,
                        Op::Cast {
                            dst: Slot(2),
                            op,
                            from_bits,
                            to_bits,
                            src: Slot(0),
                        },
                    ));
                    described.push(format!("{op:?} {from_bits} to {to_bits} {value:?}"));
                }
            }
        }
    }
    let module = module(functions);
    let (integers, others, faults) = agree(&module, |index| described[index].clone());
    eprintln!(
        "{} comparisons and conversions agree: {integers} integers, {others} poison",
        described.len()
    );
    assert!(integers > 10_000 && others > 2_000);
    assert_eq!(faults, 0);
}

#[test]
fn copies_selections_and_branches_agree_on_every_kind_of_value() {
    let kinds = [
        Value::Int(0),
        Value::Int(1),
        Value::Int(u128::MAX),
        Value::Int(1 << 64),
        Value::Poison,
        Value::Undef,
    ];
    let mut functions = Vec::new();
    for condition in kinds {
        for first in kinds {
            for second in kinds {
                // select(condition, first, second), copied once.
                functions.push(function(
                    vec![block(
                        vec![
                            constant(0, condition),
                            constant(1, first),
                            constant(2, second),
                            Op::Select {
                                dst: Slot(3),
                                cond: Slot(0),
                                if_true: Slot(1),
                                if_false: Slot(2),
                            },
                            Op::Copy {
                                dst: Slot(4),
                                src: Slot(3),
                            },
                        ],
                        Terminator::Return(vec![Slot(4)]),
                    )],
                    5,
                ));
                // The same choice made by a branch, and merged by a phi.
                let mut merge = block(Vec::new(), Terminator::Return(vec![Slot(3)]));
                merge.phis = vec![Phi {
                    dst: Slot(3),
                    incoming: vec![(BlockIdx(1), Slot(1)), (BlockIdx(2), Slot(2))],
                }];
                functions.push(function(
                    vec![
                        block(
                            vec![
                                constant(0, condition),
                                constant(1, first),
                                constant(2, second),
                            ],
                            Terminator::Branch {
                                cond: Slot(0),
                                if_true: BlockIdx(1),
                                if_false: BlockIdx(2),
                            },
                        ),
                        block(Vec::new(), Terminator::Jump(BlockIdx(3))),
                        block(Vec::new(), Terminator::Jump(BlockIdx(3))),
                        merge,
                    ],
                    4,
                ));
            }
        }
    }
    // Phis that read what other phis of the same block write: a rotation of
    // three values, a number of times, must go round and not smear.
    let mut rotate = block(
        vec![
            Op::IntBinary {
                dst: Slot(7),
                op: IntBinary::Add,
                bits: 32,
                flags: IntFlags::default(),
                lhs: Slot(6),
                rhs: Slot(0),
            },
            Op::Icmp {
                dst: Slot(8),
                pred: Predicate::Eq,
                bits: 32,
                lhs: Slot(7),
                rhs: Slot(9),
            },
        ],
        Terminator::Branch {
            cond: Slot(8),
            if_true: BlockIdx(2),
            if_false: BlockIdx(1),
        },
    );
    rotate.phis = vec![
        Phi {
            dst: Slot(3),
            incoming: vec![(BlockIdx(0), Slot(0)), (BlockIdx(1), Slot(4))],
        },
        Phi {
            dst: Slot(4),
            incoming: vec![(BlockIdx(0), Slot(1)), (BlockIdx(1), Slot(5))],
        },
        Phi {
            dst: Slot(5),
            incoming: vec![(BlockIdx(0), Slot(2)), (BlockIdx(1), Slot(3))],
        },
        Phi {
            dst: Slot(6),
            incoming: vec![(BlockIdx(0), Slot(10)), (BlockIdx(1), Slot(7))],
        },
    ];
    for turns in 1..8 {
        functions.push(function(
            vec![
                block(
                    vec![
                        constant(0, Value::Int(1)),
                        constant(1, Value::Int(20)),
                        constant(2, Value::Poison),
                        constant(9, Value::Int(turns)),
                        constant(10, Value::Int(0)),
                    ],
                    Terminator::Jump(BlockIdx(1)),
                ),
                rotate.clone(),
                block(Vec::new(), Terminator::Return(vec![Slot(3)])),
            ],
            11,
        ));
    }
    let module = module(functions);
    let (integers, others, faults) = agree(&module, |index| format!("function {index}"));
    // A branch on poison or on an undefined value is a fault; a selection
    // on poison is poison.
    assert!(integers > 100 && others > 100 && faults > 50);
}
