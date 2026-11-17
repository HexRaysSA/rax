//! The enum-driven integer semantics are checked against two independent
//! references: the string-driven witness in `src/smir/portable/execution`
//! (itself compared with the Python reference over hundreds of thousands of
//! cases) for the operations both implement, and naive bit-at-a-time models
//! written here for the rest.

use super::{Arg, Computed, binary, cast, compare, mask, unary};
use crate::frozen_format::execution as witness;
use crate::ir::{Cast, IntBinary, IntFlags, IntUnary, Predicate};

/// Deterministic 64-bit generator; the tests must not depend on a seed source.
struct Sequence(u64);

impl Sequence {
    fn next(&mut self) -> u64 {
        // SplitMix64.
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn wide(&mut self) -> u128 {
        (u128::from(self.next()) << 64) | u128::from(self.next())
    }
}

/// Values that exercise carries, sign boundaries and shift limits at `bits`.
fn interesting(bits: u32, random: &mut Sequence) -> Vec<u128> {
    let mask = mask(bits);
    let mut values = vec![
        0,
        1,
        2,
        mask,
        mask - 1,
        mask >> 1,
        (mask >> 1) + 1,
        u128::from(bits),
    ];
    values.push(u128::from(bits - 1));
    for _ in 0..6 {
        values.push(random.wide());
    }
    // Every operand must be representable at this width.
    for value in &mut values {
        *value &= mask;
    }
    values.sort_unstable();
    values.dedup();
    values
}

const BINARY: [(IntBinary, &str); 13] = [
    (IntBinary::Add, "add"),
    (IntBinary::Sub, "sub"),
    (IntBinary::Mul, "mul"),
    (IntBinary::UDiv, "udiv"),
    (IntBinary::SDiv, "sdiv"),
    (IntBinary::URem, "urem"),
    (IntBinary::SRem, "srem"),
    (IntBinary::Shl, "shl"),
    (IntBinary::LShr, "lshr"),
    (IntBinary::AShr, "ashr"),
    (IntBinary::And, "and"),
    (IntBinary::Or, "or"),
    (IntBinary::Xor, "xor"),
];

const PREDICATES: [(Predicate, &str); 10] = [
    (Predicate::Eq, "eq"),
    (Predicate::Ne, "ne"),
    (Predicate::Ult, "ult"),
    (Predicate::Ule, "ule"),
    (Predicate::Ugt, "ugt"),
    (Predicate::Uge, "uge"),
    (Predicate::Slt, "slt"),
    (Predicate::Sle, "sle"),
    (Predicate::Sgt, "sgt"),
    (Predicate::Sge, "sge"),
];

fn to_witness(arg: Arg) -> witness::Value {
    match arg {
        Arg::Bits(bits) => witness::Value::Bits(bits),
        Arg::Poison => witness::Value::Poison,
    }
}

fn from_witness(result: Result<witness::Value, witness::Error>) -> Result<Computed, &'static str> {
    match result {
        Ok(witness::Value::Bits(bits)) => Ok(Computed::Bits(bits)),
        Ok(witness::Value::Poison) => Ok(Computed::Poison),
        Ok(witness::Value::Undef) => panic!("witness produced undef"),
        Err(witness::Error::PoisonDivisor) => Err("ub_poison_divisor"),
        Err(witness::Error::DivisionByZero) => Err("ub_div_zero"),
        Err(witness::Error::SignedDivisionOverflow) => Err("ub_signed_div_overflow"),
        Err(other) => panic!("witness rejected a well-formed case: {other:?}"),
    }
}

/// The flag sets that are valid for `op`.
fn flag_sets(op: IntBinary) -> Vec<IntFlags> {
    let none = IntFlags::default();
    match op {
        IntBinary::Add | IntBinary::Sub | IntBinary::Mul | IntBinary::Shl => vec![
            none,
            IntFlags { nsw: true, ..none },
            IntFlags { nuw: true, ..none },
            IntFlags {
                nsw: true,
                nuw: true,
                ..none
            },
        ],
        IntBinary::UDiv | IntBinary::SDiv | IntBinary::LShr | IntBinary::AShr => {
            vec![
                none,
                IntFlags {
                    exact: true,
                    ..none
                },
            ]
        }
        _ => vec![none],
    }
}

fn check_against_witness(bits: u32, lhs: Arg, rhs: Arg, cases: &mut u64) {
    for (op, name) in BINARY {
        for flags in flag_sets(op) {
            let expected = from_witness(witness::evaluate(
                name,
                bits,
                to_witness(lhs),
                to_witness(rhs),
                witness::Flags {
                    nsw: flags.nsw,
                    nuw: flags.nuw,
                    exact: flags.exact,
                },
            ));
            assert_eq!(
                binary(op, bits, flags, lhs, rhs),
                expected,
                "{name} width {bits} flags {flags:?}: {lhs:?}, {rhs:?}"
            );
            *cases += 1;
        }
    }
    for (pred, name) in PREDICATES {
        let expected = from_witness(witness::evaluate(
            name,
            bits,
            to_witness(lhs),
            to_witness(rhs),
            witness::Flags::default(),
        ));
        assert_eq!(
            Ok(compare(pred, bits, lhs, rhs)),
            expected,
            "{name} width {bits}: {lhs:?}, {rhs:?}"
        );
        *cases += 1;
    }
}

#[test]
fn binary_and_compare_agree_with_the_independent_witness_exhaustively_at_small_widths() {
    let mut cases = 0;
    for bits in 1..=5 {
        let operands: Vec<Arg> = (0..=mask(bits))
            .map(Arg::Bits)
            .chain([Arg::Poison])
            .collect();
        for lhs in &operands {
            for rhs in &operands {
                check_against_witness(bits, *lhs, *rhs, &mut cases);
            }
        }
    }
    // (2^b + 1)^2 operand pairs for b in 1..=5. Each pair runs 29 binary rows
    // (four flag sets for add/sub/mul/shl, two for udiv/sdiv/lshr/ashr, one
    // for the other five) and 10 predicates.
    assert_eq!(cases, (9 + 25 + 81 + 289 + 1089) * 39);
}

#[test]
fn binary_and_compare_agree_with_the_independent_witness_at_every_width() {
    let mut random = Sequence(0x534d_4952_494e_5431);
    let mut cases = 0;
    for bits in 1..=128 {
        let mut operands: Vec<Arg> = interesting(bits, &mut random)
            .into_iter()
            .map(Arg::Bits)
            .collect();
        operands.push(Arg::Poison);
        for lhs in &operands {
            for rhs in &operands {
                check_against_witness(bits, *lhs, *rhs, &mut cases);
            }
        }
    }
    assert!(cases > 500_000, "only {cases} cases ran");
}

fn bit(value: u128, index: u32) -> bool {
    value >> index & 1 == 1
}

fn naive_rotate_left(value: u128, bits: u32, amount: u32) -> u128 {
    (0..bits)
        .filter(|index| bit(value, *index))
        .fold(0, |out, index| out | 1 << ((index + amount) % bits))
}

#[test]
fn rotations_match_a_bit_at_a_time_model_and_never_poison_on_large_amounts() {
    let mut random = Sequence(7);
    for bits in [1, 2, 7, 8, 13, 32, 63, 64, 65, 127, 128] {
        for value in interesting(bits, &mut random) {
            for amount in [0, 1, bits - 1, bits, bits + 1, 2 * bits + 3] {
                let amount_bits = u128::from(amount) & mask(bits);
                // The operand is the amount as representable at this width.
                let effective = (amount_bits % u128::from(bits)) as u32;
                let left = naive_rotate_left(value, bits, effective);
                let right = naive_rotate_left(value, bits, (bits - effective) % bits);
                let flags = IntFlags::default();
                assert_eq!(
                    binary(
                        IntBinary::RotL,
                        bits,
                        flags,
                        Arg::Bits(value),
                        Arg::Bits(amount_bits)
                    ),
                    Ok(Computed::Bits(left)),
                    "rotl width {bits} value {value:#x} by {amount_bits}"
                );
                assert_eq!(
                    binary(
                        IntBinary::RotR,
                        bits,
                        flags,
                        Arg::Bits(value),
                        Arg::Bits(amount_bits)
                    ),
                    Ok(Computed::Bits(right)),
                    "rotr width {bits} value {value:#x} by {amount_bits}"
                );
            }
        }
        let poison = binary(
            IntBinary::RotL,
            bits,
            IntFlags::default(),
            Arg::Poison,
            Arg::Bits(0),
        );
        assert_eq!(poison, Ok(Computed::Poison));
        let poison = binary(
            IntBinary::RotR,
            bits,
            IntFlags::default(),
            Arg::Bits(0),
            Arg::Poison,
        );
        assert_eq!(poison, Ok(Computed::Poison));
    }
}

#[test]
fn unary_operations_match_bit_at_a_time_models() {
    let mut random = Sequence(11);
    for bits in [1, 2, 7, 8, 16, 24, 31, 32, 64, 65, 120, 127, 128] {
        for value in interesting(bits, &mut random) {
            let leading = (0..bits)
                .rev()
                .take_while(|index| !bit(value, *index))
                .count() as u128;
            let trailing = (0..bits).take_while(|index| !bit(value, *index)).count() as u128;
            let ones = (0..bits).filter(|index| bit(value, *index)).count() as u128;
            let reversed = (0..bits)
                .filter(|index| bit(value, *index))
                .fold(0_u128, |out, index| out | 1 << (bits - 1 - index));
            for zero_is_poison in [false, true] {
                let run = |op| unary(op, bits, zero_is_poison, Arg::Bits(value));
                let zero_poison = value == 0 && zero_is_poison;
                assert_eq!(
                    run(IntUnary::Clz),
                    if zero_poison {
                        Computed::Poison
                    } else {
                        Computed::Bits(leading)
                    }
                );
                assert_eq!(
                    run(IntUnary::Ctz),
                    if zero_poison {
                        Computed::Poison
                    } else {
                        Computed::Bits(trailing)
                    }
                );
                assert_eq!(run(IntUnary::Popcount), Computed::Bits(ones));
                assert_eq!(run(IntUnary::BitReverse), Computed::Bits(reversed));
                let minimum = value == 1 << (bits - 1);
                let magnitude = if bit(value, bits - 1) {
                    value.wrapping_neg() & mask(bits)
                } else {
                    value
                };
                assert_eq!(
                    run(IntUnary::Abs),
                    if minimum && zero_is_poison {
                        Computed::Poison
                    } else {
                        Computed::Bits(magnitude)
                    },
                    "abs width {bits} value {value:#x}"
                );
                if bits % 8 == 0 {
                    let bytes = bits / 8;
                    let swapped = (0..bytes).fold(0_u128, |out, index| {
                        out | (value >> (8 * index) & 0xff) << (8 * (bytes - 1 - index))
                    });
                    assert_eq!(run(IntUnary::Bswap), Computed::Bits(swapped));
                }
                for op in [
                    IntUnary::Clz,
                    IntUnary::Ctz,
                    IntUnary::Popcount,
                    IntUnary::Abs,
                    IntUnary::BitReverse,
                ] {
                    assert_eq!(
                        unary(op, bits, zero_is_poison, Arg::Poison),
                        Computed::Poison
                    );
                }
            }
        }
    }
}

#[test]
fn casts_extend_and_truncate_by_value() {
    let mut random = Sequence(13);
    for (from, to) in [
        (1, 2),
        (1, 128),
        (7, 8),
        (8, 32),
        (32, 64),
        (63, 64),
        (64, 65),
        (64, 128),
        (127, 128),
    ] {
        for value in interesting(from, &mut random) {
            assert_eq!(
                cast(Cast::Zext, from, to, Arg::Bits(value)),
                Computed::Bits(value)
            );
            let negative = bit(value, from - 1);
            let extended = if negative {
                value | (mask(to) & !mask(from))
            } else {
                value
            };
            assert_eq!(
                cast(Cast::Sext, from, to, Arg::Bits(value)),
                Computed::Bits(extended)
            );
        }
        for value in interesting(to, &mut random) {
            assert_eq!(
                cast(Cast::Trunc, to, from, Arg::Bits(value)),
                Computed::Bits(value & mask(from))
            );
        }
        for op in [Cast::Trunc, Cast::Zext, Cast::Sext] {
            assert_eq!(cast(op, from, to, Arg::Poison), Computed::Poison);
        }
    }
}

#[test]
fn division_faults_take_precedence_over_a_poison_dividend() {
    let flags = IntFlags::default();
    for op in [
        IntBinary::UDiv,
        IntBinary::SDiv,
        IntBinary::URem,
        IntBinary::SRem,
    ] {
        assert_eq!(
            binary(op, 32, flags, Arg::Poison, Arg::Bits(0)),
            Err("ub_div_zero")
        );
        assert_eq!(
            binary(op, 32, flags, Arg::Bits(1), Arg::Poison),
            Err("ub_poison_divisor")
        );
        assert_eq!(
            binary(op, 32, flags, Arg::Poison, Arg::Bits(3)),
            Ok(Computed::Poison)
        );
    }
    for op in [IntBinary::SDiv, IntBinary::SRem] {
        let minus_one = Arg::Bits(mask(32));
        assert_eq!(
            binary(op, 32, flags, Arg::Bits(1 << 31), minus_one),
            Err("ub_signed_div_overflow")
        );
        assert_eq!(
            binary(op, 32, flags, Arg::Poison, minus_one),
            Err("ub_signed_div_overflow")
        );
        assert_eq!(
            binary(op, 128, flags, Arg::Bits(1 << 127), Arg::Bits(u128::MAX)),
            Err("ub_signed_div_overflow")
        );
    }
    // Unsigned division by all ones is ordinary.
    assert_eq!(
        binary(IntBinary::UDiv, 8, flags, Arg::Bits(0x80), Arg::Bits(0xff)),
        Ok(Computed::Bits(0))
    );
}
