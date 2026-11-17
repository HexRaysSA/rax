//! Known answers for the float operations: facts of IEEE 754 arithmetic and
//! the execution chapter's NaN rule. The differential test compares the same
//! operations with the reference machine on thousands of operand pairs.

use super::evaluate;
use crate::interp::int::Computed;
use crate::ir::{FloatFormat, FloatOp, FloatRelation};

use FloatFormat::{Binary32, Binary64};

fn single(op: FloatOp, operands: &[f32]) -> u32 {
    let bits: Vec<u128> = operands
        .iter()
        .map(|value| u128::from(value.to_bits()))
        .collect();
    raw(op, Binary32, &bits) as u32
}

fn double(op: FloatOp, operands: &[f64]) -> u64 {
    let bits: Vec<u128> = operands
        .iter()
        .map(|value| u128::from(value.to_bits()))
        .collect();
    raw(op, Binary64, &bits) as u64
}

fn raw(op: FloatOp, format: FloatFormat, operands: &[u128]) -> u128 {
    match evaluate(op, format, operands) {
        Some(Computed::Bits(bits)) => bits,
        other => panic!("{op:?} {operands:x?} gave {other:?}"),
    }
}

const QUIET32: u128 = 0x7fc0_0000;
const SIGNALING32: u128 = 0x7f80_0001;
const NEGATIVE_NAN32: u128 = 0xffc1_2345;
const ONE32: u128 = 0x3f80_0000;

#[test]
fn arithmetic_is_correctly_rounded() {
    assert_eq!(double(FloatOp::Add, &[0.1, 0.2]), 0x3fd3_3333_3333_3334);
    assert_eq!(single(FloatOp::Div, &[1.0, 3.0]), 0x3eaa_aaab);
    assert_eq!(double(FloatOp::Sqrt, &[2.0]), 0x3ff6_a09e_667f_3bcd);
    assert_eq!(
        single(FloatOp::Mul, &[f32::MAX, 2.0]),
        f32::INFINITY.to_bits()
    );
    // The smallest subnormal halved rounds to zero; doubled it is exact.
    assert_eq!(single(FloatOp::Div, &[f32::from_bits(1), 2.0]), 0);
    assert_eq!(
        single(FloatOp::Add, &[f32::from_bits(1), f32::from_bits(1)]),
        2
    );
    // An exact zero sum of opposite signs is positive.
    assert_eq!(double(FloatOp::Sub, &[1.5, 1.5]), 0);
    assert_eq!(double(FloatOp::Add, &[-0.0, -0.0]), (-0.0_f64).to_bits());
    assert_eq!(double(FloatOp::Sqrt, &[-0.0]), (-0.0_f64).to_bits());
}

#[test]
fn fused_multiply_add_rounds_once() {
    let a = 1.0 + 2.0_f64.powi(-27);
    let c = -(1.0 + 2.0_f64.powi(-26));
    // The product is 1 + 2^-26 + 2^-54; rounding it first would lose the
    // last term.
    assert_eq!(
        double(FloatOp::Fma, &[a, a, c]),
        2.0_f64.powi(-54).to_bits()
    );
    assert_eq!(a * a + c, 0.0);
}

#[test]
fn the_remainder_is_of_truncating_division() {
    assert_eq!(single(FloatOp::Rem, &[5.5, 2.0]), 1.5_f32.to_bits());
    assert_eq!(single(FloatOp::Rem, &[-5.5, 2.0]), (-1.5_f32).to_bits());
    assert_eq!(single(FloatOp::Rem, &[5.5, -2.0]), 1.5_f32.to_bits());
    assert_eq!(single(FloatOp::Rem, &[-4.0, 2.0]), (-0.0_f32).to_bits());
    assert_eq!(
        single(FloatOp::Rem, &[1.0, f32::INFINITY]),
        1.0_f32.to_bits()
    );
    assert_eq!(u128::from(single(FloatOp::Rem, &[1.0, 0.0])), QUIET32);
    assert_eq!(
        u128::from(single(FloatOp::Rem, &[f32::INFINITY, 1.0])),
        QUIET32
    );
}

#[test]
fn a_nan_result_is_the_first_nan_operand_made_quiet() {
    for op in [
        FloatOp::Add,
        FloatOp::Sub,
        FloatOp::Mul,
        FloatOp::Div,
        FloatOp::Rem,
    ] {
        assert_eq!(
            raw(op, Binary32, &[SIGNALING32, ONE32]),
            0x7fc0_0001,
            "{op:?}"
        );
        assert_eq!(
            raw(op, Binary32, &[ONE32, NEGATIVE_NAN32]),
            NEGATIVE_NAN32,
            "{op:?}"
        );
        assert_eq!(
            raw(op, Binary32, &[NEGATIVE_NAN32, SIGNALING32]),
            NEGATIVE_NAN32,
            "{op:?}"
        );
        assert_eq!(
            raw(op, Binary32, &[SIGNALING32, NEGATIVE_NAN32]),
            0x7fc0_0001,
            "{op:?}"
        );
    }
    assert_eq!(raw(FloatOp::Sqrt, Binary32, &[SIGNALING32]), 0x7fc0_0001);
    assert_eq!(
        raw(FloatOp::Fma, Binary32, &[ONE32, ONE32, NEGATIVE_NAN32]),
        NEGATIVE_NAN32
    );
    assert_eq!(
        raw(
            FloatOp::Fma,
            Binary32,
            &[ONE32, SIGNALING32, NEGATIVE_NAN32]
        ),
        0x7fc0_0001
    );
    // An invalid operation on numbers gives the positive NaN with no payload.
    let infinity = f32::INFINITY;
    assert_eq!(
        u128::from(single(FloatOp::Sub, &[infinity, infinity])),
        QUIET32
    );
    assert_eq!(u128::from(single(FloatOp::Mul, &[0.0, -infinity])), QUIET32);
    assert_eq!(u128::from(single(FloatOp::Div, &[0.0, 0.0])), QUIET32);
    assert_eq!(u128::from(single(FloatOp::Sqrt, &[-1.0])), QUIET32);
    assert_eq!(
        u128::from(single(FloatOp::Fma, &[0.0, infinity, 1.0])),
        QUIET32
    );
    assert_eq!(double(FloatOp::Div, &[-0.0, 0.0]), 0x7ff8_0000_0000_0000);
}

#[test]
fn sign_operations_act_on_the_bits() {
    assert_eq!(raw(FloatOp::Neg, Binary32, &[SIGNALING32]), 0xff80_0001);
    assert_eq!(raw(FloatOp::Abs, Binary32, &[NEGATIVE_NAN32]), 0x7fc1_2345);
    assert_eq!(
        raw(FloatOp::CopySign, Binary32, &[SIGNALING32, NEGATIVE_NAN32]),
        0xff80_0001
    );
    assert_eq!(
        single(FloatOp::CopySign, &[2.0, -0.0]),
        (-2.0_f32).to_bits()
    );
    assert_eq!(double(FloatOp::Neg, &[0.0]), (-0.0_f64).to_bits());
}

#[test]
fn extrema_order_zeros_and_differ_on_nans() {
    let zeros = [0.0_f32, -0.0];
    for op in [FloatOp::Minimum, FloatOp::MinNum, FloatOp::MinimumNum] {
        assert_eq!(single(op, &zeros), (-0.0_f32).to_bits(), "{op:?}");
        assert_eq!(single(op, &[-0.0, 0.0]), (-0.0_f32).to_bits(), "{op:?}");
        assert_eq!(single(op, &[3.0, -7.0]), (-7.0_f32).to_bits(), "{op:?}");
        assert_eq!(
            single(op, &[f32::NEG_INFINITY, 1.0]),
            f32::NEG_INFINITY.to_bits()
        );
    }
    for op in [FloatOp::Maximum, FloatOp::MaxNum, FloatOp::MaximumNum] {
        assert_eq!(single(op, &zeros), 0, "{op:?}");
        assert_eq!(single(op, &[3.0, -7.0]), 3.0_f32.to_bits(), "{op:?}");
    }
    // One NaN: the propagating forms return it, the others the number.
    for op in [FloatOp::Minimum, FloatOp::Maximum] {
        assert_eq!(
            raw(op, Binary32, &[SIGNALING32, ONE32]),
            0x7fc0_0001,
            "{op:?}"
        );
        assert_eq!(
            raw(op, Binary32, &[ONE32, NEGATIVE_NAN32]),
            NEGATIVE_NAN32,
            "{op:?}"
        );
    }
    for op in [
        FloatOp::MinNum,
        FloatOp::MaxNum,
        FloatOp::MinimumNum,
        FloatOp::MaximumNum,
    ] {
        assert_eq!(raw(op, Binary32, &[SIGNALING32, ONE32]), ONE32, "{op:?}");
        assert_eq!(raw(op, Binary32, &[ONE32, NEGATIVE_NAN32]), ONE32, "{op:?}");
        // Two NaNs: the first, made quiet.
        assert_eq!(
            raw(op, Binary32, &[SIGNALING32, NEGATIVE_NAN32]),
            0x7fc0_0001,
            "{op:?}"
        );
    }
}

#[test]
fn comparisons_treat_a_nan_as_unordered() {
    let holds = |relation, unordered, a: f64, b: f64| {
        double(
            FloatOp::Compare {
                relation,
                unordered,
            },
            &[a, b],
        ) == 1
    };
    let nan = f64::NAN;
    use FloatRelation::{
        Equal, False, Greater, GreaterEqual, Less, LessEqual, NotEqual, Ordered, True, Unordered,
    };
    assert!(holds(Equal, false, 0.0, -0.0) && !holds(NotEqual, false, 0.0, -0.0));
    assert!(holds(Less, false, -1.0, 1.0) && holds(LessEqual, false, 1.0, 1.0));
    assert!(holds(Greater, false, f64::INFINITY, 1.0e308) && holds(GreaterEqual, false, 2.0, 2.0));
    for relation in [Equal, NotEqual, Less, LessEqual, Greater, GreaterEqual] {
        for (a, b) in [(nan, 1.0), (1.0, nan), (nan, nan)] {
            assert!(!holds(relation, false, a, b), "ordered {relation:?}");
            assert!(holds(relation, true, a, b), "unordered {relation:?}");
        }
    }
    // The unordered forms of a relation that holds are unchanged.
    assert!(holds(NotEqual, true, 1.0, 2.0) && !holds(Equal, true, 1.0, 2.0));
    assert!(holds(Ordered, false, 1.0, 2.0) && !holds(Ordered, false, nan, 2.0));
    assert!(holds(Unordered, false, 1.0, nan) && !holds(Unordered, false, 1.0, 2.0));
    assert!(holds(True, false, nan, nan) && !holds(False, false, 1.0, 1.0));
}

#[test]
fn conversion_to_an_integer_truncates_and_checks_the_range() {
    let convert = |op, value: f64| evaluate(op, Binary64, &[u128::from(value.to_bits())]).unwrap();
    let signed = |bits| FloatOp::ToSigned {
        bits,
        saturating: false,
    };
    let unsigned = |bits| FloatOp::ToUnsigned {
        bits,
        saturating: false,
    };
    let signed_sat = |bits| FloatOp::ToSigned {
        bits,
        saturating: true,
    };
    let unsigned_sat = |bits| FloatOp::ToUnsigned {
        bits,
        saturating: true,
    };
    let bits = Computed::Bits;

    assert_eq!(convert(unsigned(8), 255.9), bits(255));
    assert_eq!(convert(unsigned(8), 256.0), Computed::Poison);
    assert_eq!(convert(unsigned_sat(8), 256.0), bits(255));
    // A negative fraction truncates to zero, which every type holds.
    assert_eq!(convert(unsigned(8), -0.9), bits(0));
    assert_eq!(convert(unsigned(8), -1.0), Computed::Poison);
    assert_eq!(convert(unsigned_sat(8), -1.0e300), bits(0));
    assert_eq!(convert(signed(8), -128.9), bits(0x80));
    assert_eq!(convert(signed(8), -129.0), Computed::Poison);
    assert_eq!(convert(signed_sat(8), -129.0), bits(0x80));
    assert_eq!(convert(signed(8), 127.5), bits(127));
    assert_eq!(convert(signed(8), 128.0), Computed::Poison);
    assert_eq!(convert(signed(32), -7.99), bits(0xffff_fff9));
    assert_eq!(convert(signed(1), -1.0), bits(1));
    assert_eq!(convert(signed(1), 1.0), Computed::Poison);
    assert_eq!(convert(unsigned(1), 1.5), bits(1));

    let two_63 = 9_223_372_036_854_775_808.0;
    assert_eq!(convert(signed(64), two_63), Computed::Poison);
    assert_eq!(convert(signed(64), -two_63), bits(1 << 63));
    assert_eq!(convert(unsigned(64), two_63), bits(1 << 63));
    assert_eq!(
        convert(signed_sat(64), 1.0e300),
        bits(u128::from(i64::MAX as u64))
    );
    assert_eq!(convert(signed(128), 2.0_f64.powi(127)), Computed::Poison);
    assert_eq!(convert(signed(128), -(2.0_f64.powi(127))), bits(1 << 127));
    assert_eq!(convert(unsigned(128), 2.0_f64.powi(127)), bits(1 << 127));
    assert_eq!(convert(unsigned(128), 2.0_f64.powi(128)), Computed::Poison);
    assert_eq!(
        convert(unsigned_sat(128), 2.0_f64.powi(128)),
        bits(u128::MAX)
    );
    assert_eq!(convert(signed_sat(128), f64::NEG_INFINITY), bits(1 << 127));

    for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        assert_eq!(convert(signed(32), value), Computed::Poison);
        assert_eq!(convert(unsigned(32), value), Computed::Poison);
    }
    assert_eq!(convert(signed_sat(32), f64::NAN), bits(0));
    assert_eq!(convert(unsigned_sat(32), f64::INFINITY), bits(0xffff_ffff));
    assert_eq!(
        convert(signed_sat(32), f64::NEG_INFINITY),
        bits(0x8000_0000)
    );
    // The smallest subnormal is far below one.
    assert_eq!(convert(signed(32), f64::from_bits(1)), bits(0));
}

#[test]
fn conversion_from_an_integer_rounds_to_nearest_even() {
    let signed = |bits| FloatOp::FromSigned { bits };
    let unsigned = |bits| FloatOp::FromUnsigned { bits };
    assert_eq!(
        raw(unsigned(64), Binary32, &[u128::from(u64::MAX)]),
        0x5f80_0000
    );
    assert_eq!(
        raw(signed(64), Binary32, &[u128::from(u64::MAX)]),
        u128::from((-1.0_f32).to_bits())
    );
    // 2^24 + 1 is a tie and rounds to the even neighbour; 2^24 + 3 rounds up.
    assert_eq!(
        raw(unsigned(32), Binary32, &[16_777_217]),
        u128::from(16_777_216.0_f32.to_bits())
    );
    assert_eq!(
        raw(unsigned(32), Binary32, &[16_777_219]),
        u128::from(16_777_220.0_f32.to_bits())
    );
    assert_eq!(
        raw(signed(8), Binary64, &[0x80]),
        u128::from((-128.0_f64).to_bits())
    );
    assert_eq!(
        raw(unsigned(8), Binary64, &[0x80]),
        u128::from(128.0_f64.to_bits())
    );
    assert_eq!(
        raw(signed(1), Binary64, &[1]),
        u128::from((-1.0_f64).to_bits())
    );
    assert_eq!(
        raw(unsigned(128), Binary32, &[u128::MAX]),
        u128::from(f32::INFINITY.to_bits())
    );
    assert_eq!(
        raw(signed(128), Binary64, &[1 << 127]),
        u128::from((-(2.0_f64.powi(127))).to_bits())
    );
}

#[test]
fn conversion_between_formats_keeps_a_nan_recognizable() {
    let widen = FloatOp::Convert { to: Binary64 };
    let narrow = FloatOp::Convert { to: Binary32 };
    assert_eq!(
        raw(widen, Binary32, &[u128::from(0.1_f32.to_bits())]),
        u128::from(f64::from(0.1_f32).to_bits())
    );
    // Halfway between 1 and the next binary32 value: ties to even.
    let tie = 1.0 + 2.0_f64.powi(-24);
    assert_eq!(raw(narrow, Binary64, &[u128::from(tie.to_bits())]), ONE32);
    assert_eq!(
        raw(narrow, Binary64, &[u128::from(1.0e300_f64.to_bits())]),
        0x7f80_0000
    );
    assert_eq!(
        raw(narrow, Binary64, &[u128::from(1.0e-300_f64.to_bits())]),
        0
    );
    // Sign and leading payload bits survive; the result is quiet.
    assert_eq!(raw(widen, Binary32, &[SIGNALING32]), 0x7ff8_0000_2000_0000);
    assert_eq!(
        raw(widen, Binary32, &[NEGATIVE_NAN32]),
        0xfff8_2468_a000_0000
    );
    assert_eq!(raw(narrow, Binary64, &[0xfff0_0000_0000_0001]), 0xffc0_0000);
    assert_eq!(raw(narrow, Binary64, &[0x7ff8_2468_a000_0000]), 0x7fc1_2345);
}

#[test]
fn an_operation_with_the_wrong_operand_count_is_not_evaluated() {
    assert_eq!(evaluate(FloatOp::Add, Binary32, &[ONE32]), None);
    assert_eq!(evaluate(FloatOp::Sqrt, Binary64, &[1, 2]), None);
}
