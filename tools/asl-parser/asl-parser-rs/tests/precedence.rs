//! Expression binding affects the meaning of architectural decode predicates.
//! Arm 111069 A.a, 4.4.5 supplies the independent precedence classes.

use asl_parser::{parse_definitions, BinOp, Definition, Expr, Slice, Stmt, UnOp};

fn expression(source: &str) -> Expr {
    let definitions = parse_definitions(&format!("integer Probe()\n    return {source};\n"))
        .unwrap_or_else(|error| panic!("{source}: {error:?}"));
    let [Definition::Callable { body, .. }] = definitions.as_slice() else {
        panic!("expected one callable: {definitions:?}");
    };
    let [Stmt::Return(Some(value))] = body.as_slice() else {
        panic!("expected one complete return: {body:?}");
    };
    value.clone()
}

fn binary(op: BinOp, lhs: Expr, rhs: Expr) -> Expr {
    Expr::binary(op, lhs, rhs)
}

// Expected classes are independent of BinOp::precedence(). Legacy EOR, QUOT,
// REM, ++ and : retain their existing spelling in the corresponding classes.
const OPERATORS: &[(&str, BinOp, u8)] = &[
    ("||", BinOp::Or, 1),
    ("&&", BinOp::And, 1),
    ("==", BinOp::Eq, 2),
    ("!=", BinOp::Ne, 2),
    (">", BinOp::Gt, 3),
    (">=", BinOp::Ge, 3),
    ("<", BinOp::Lt, 3),
    ("<=", BinOp::Le, 3),
    ("+", BinOp::Add, 4),
    ("-", BinOp::Sub, 4),
    ("AND", BinOp::BitAnd, 4),
    ("OR", BinOp::BitOr, 4),
    ("EOR", BinOp::BitXor, 4),
    ("++", BinOp::Concat, 4),
    (":", BinOp::BitConcat, 4),
    ("*", BinOp::Mul, 5),
    ("/", BinOp::Div, 5),
    ("DIV", BinOp::IntDiv, 5),
    ("QUOT", BinOp::Quot, 5),
    ("REM", BinOp::Rem, 5),
    ("MOD", BinOp::Mod, 5),
    ("<<", BinOp::Shl, 5),
    (">>", BinOp::Shr, 5),
    ("^", BinOp::Pow, 6),
];

#[test]
fn every_cross_class_operator_pair_binds_in_both_orders() {
    let mut cases = 0;
    for &(left_text, left_op, left_class) in OPERATORS {
        for &(right_text, right_op, right_class) in OPERATORS {
            if left_class == right_class {
                continue;
            }
            let source = format!("a {left_text} b {right_text} c");
            let expected = if left_class > right_class {
                binary(
                    right_op,
                    binary(left_op, Expr::var("a"), Expr::var("b")),
                    Expr::var("c"),
                )
            } else {
                binary(
                    left_op,
                    Expr::var("a"),
                    binary(right_op, Expr::var("b"), Expr::var("c")),
                )
            };
            assert_eq!(expression(&source), expected, "{source}");
            cases += 1;
        }
    }
    assert_eq!(cases, 438);
}

#[test]
fn parentheses_override_every_operator_pair() {
    for &(left_text, left_op, _) in OPERATORS {
        for &(right_text, right_op, _) in OPERATORS {
            let left = format!("(a {left_text} b) {right_text} c");
            assert_eq!(
                expression(&left),
                binary(
                    right_op,
                    binary(left_op, Expr::var("a"), Expr::var("b")),
                    Expr::var("c")
                ),
                "{left}"
            );
            let right = format!("a {left_text} (b {right_text} c)");
            assert_eq!(
                expression(&right),
                binary(
                    left_op,
                    Expr::var("a"),
                    binary(right_op, Expr::var("b"), Expr::var("c"))
                ),
                "{right}"
            );
        }
    }
}

#[test]
fn arithmetic_unary_and_explicit_legacy_associativity() {
    assert_eq!(
        expression("1 + 2 * 3"),
        binary(
            BinOp::Add,
            Expr::int(1),
            binary(BinOp::Mul, Expr::int(2), Expr::int(3))
        )
    );
    for &(text, op, _) in OPERATORS {
        let unary = Expr::Unary {
            op: UnOp::Neg,
            operand: Box::new(Expr::var("a")),
        };
        assert_eq!(
            expression(&format!("-a {text} b")),
            binary(op, unary, Expr::var("b")),
            "{text}"
        );
    }
    // The existing permissive legacy parser associates powers to the right
    // and other same-class operators to the left. This repair changes binding
    // between classes; it does not add ASL1 ambiguity rejection.
    assert_eq!(
        expression("a ^ b ^ c"),
        binary(
            BinOp::Pow,
            Expr::var("a"),
            binary(BinOp::Pow, Expr::var("b"), Expr::var("c"))
        )
    );
    assert_eq!(
        expression("a - b - c"),
        binary(
            BinOp::Sub,
            binary(BinOp::Sub, Expr::var("a"), Expr::var("b")),
            Expr::var("c")
        )
    );
}

fn evaluate(value: &Expr, size: i128, l: i128, q: i128) -> i128 {
    match value {
        Expr::LitInt(value) => *value,
        Expr::LitBits(bits) => bits
            .iter()
            .fold(0, |value, bit| (value << 1) | i128::from(*bit)),
        Expr::Var(name) => match name.name.as_str() {
            "size" => size,
            "L" => l,
            "Q" => q,
            _ => panic!("unexpected variable: {name:?}"),
        },
        Expr::Binary { op, lhs, rhs } => {
            let left = evaluate(lhs, size, l, q);
            let right = evaluate(rhs, size, l, q);
            match op {
                BinOp::Eq => i128::from(left == right),
                BinOp::Ne => i128::from(left != right),
                BinOp::And => i128::from(left != 0 && right != 0),
                BinOp::Or => i128::from(left != 0 || right != 0),
                _ => panic!("unexpected operation: {op:?}"),
            }
        }
        _ => panic!("unexpected expression: {value:?}"),
    }
}

#[test]
fn architectural_allocation_predicates_preserve_all_field_combinations() {
    const PRIMARY: &str = include_str!("../../../../docs/architecture/arm/asl/arm_instrs.asl");
    let predicate = "size == '10' && (L == '1' || Q == '0')";
    assert!(PRIMARY.contains(predicate));
    let decoded = expression(predicate);
    let mut cases = 0;
    for size in 0..4 {
        for l in 0..2 {
            for q in 0..2 {
                let expected = size == 2 && (l == 1 || q == 0);
                assert_eq!(
                    evaluate(&decoded, size, l, q),
                    i128::from(expected),
                    "size={size}, L={l}, Q={q}: {decoded:?}"
                );
                cases += 1;
            }
        }
    }
    assert_eq!(cases, 16);
    // Concatenation must bind before equality, including a dynamic slice.
    assert_eq!(
        expression("size:Q == '110'"),
        binary(
            BinOp::Eq,
            binary(BinOp::BitConcat, Expr::var("size"), Expr::var("Q")),
            Expr::LitBits(vec![true, true, false])
        )
    );
    assert_eq!(
        expression("immh<3>:Q == '10'"),
        expression("(immh<3>:Q) == '10'")
    );
}

#[test]
fn dynamic_slice_arithmetic_uses_normal_binding() {
    let arithmetic: Vec<_> = OPERATORS
        .iter()
        .filter(|(_, _, level)| *level >= 4)
        .filter(|(_, op, _)| {
            !matches!(
                op,
                BinOp::BitAnd | BinOp::BitOr | BinOp::BitXor | BinOp::Concat | BinOp::BitConcat
            )
        })
        .collect();
    assert_eq!(arithmetic.len(), 11);
    for &&(left, _, _) in &arithmetic {
        for &&(right, _, _) in &arithmetic {
            let index = format!("a {left} b {right} c");
            assert_eq!(
                expression(&format!("value<{index}>")),
                Expr::Index {
                    base: Box::new(Expr::var("value")),
                    indices: vec![Slice::Single(Box::new(expression(&index)))],
                },
                "{index}"
            );
        }
    }
    assert_eq!(
        expression("value<7+2*3:1, 0+:2^3>"),
        Expr::Slice {
            base: Box::new(Expr::var("value")),
            slices: vec![
                Slice::Range {
                    hi: Box::new(expression("7+2*3")),
                    lo: Box::new(Expr::int(1))
                },
                Slice::Offset {
                    base: Box::new(Expr::int(0)),
                    count: Box::new(expression("2^3"))
                },
            ],
        }
    );
}

#[test]
fn failed_slice_speculation_restores_indentation_and_following_definitions() {
    let definitions = parse_definitions("integer First()\n    if a < F(b || c) then\n        return 1;\n    return 2;\n\ninteger Second()\n    return value<3> + 4;\n").unwrap();
    let [Definition::Callable { body, .. }, Definition::Callable { .. }] = definitions.as_slice()
    else {
        panic!("lost a definition: {definitions:?}");
    };
    let [Stmt::If { branches, .. }, Stmt::Return(Some(Expr::LitInt(2)))] = body.as_slice() else {
        panic!("lost indentation or statement: {body:?}");
    };
    assert_eq!(branches[0].0, expression("a < F(b || c)"));
    assert_eq!(branches[0].1, vec![Stmt::Return(Some(Expr::int(1)))]);
    for invalid in ["value<3+:2", "value<7:>", "value<>", "a < (b ||)"] {
        assert!(
            parse_definitions(&format!("integer Invalid()\n    return {invalid};\n")).is_err(),
            "accepted incomplete expression: {invalid}"
        );
    }
}

#[test]
fn nested_comparisons_do_not_repeat_failed_slice_speculation() {
    let mut source = "z".to_string();
    let mut expected = Expr::var("z");
    for _ in 0..32 {
        source = format!("a < F({source})");
        expected = binary(BinOp::Lt, Expr::var("a"), Expr::call("F", vec![expected]));
    }
    assert_eq!(expression(&source), expected);
}
