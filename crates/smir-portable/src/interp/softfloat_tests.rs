//! The software arithmetic against the host's, in the two formats the host
//! computes, and known answers in binary128. The differential test also
//! compares binary128 with the reference machine.

use super::evaluate as soft;
use crate::interp::float::evaluate as native;
use crate::interp::int::Computed;
use crate::ir::{FloatFormat, FloatOp, FloatRelation};

use FloatFormat::{Binary32, Binary64, Binary128};

/// Deterministic generator (SplitMix64).
struct Sequence(u64);

impl Sequence {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

/// Encodings that reach every special case, then pseudo-random ones: any bit
/// pattern, and patterns with exponents close together, where sums cancel
/// and quotients are near one.
fn operands(format: FloatFormat, random: &mut Sequence) -> Vec<u128> {
    let (bits, fraction) = if format == Binary32 {
        (32, 23)
    } else {
        (64, 52)
    };
    let sign = 1_u128 << (bits - 1);
    let exponent = ((1_u128 << (bits - 1)) - 1) & !((1 << fraction) - 1);
    let one = exponent & !(1 << (bits - 2));
    let mut values = vec![
        0,
        1,
        (1 << fraction) - 1,
        1 << fraction,
        one,
        one + 1,
        one - 1,
        one | 1 << (fraction - 1),
        exponent - 1,
        exponent,
        exponent | 1,
        exponent | 1 << (fraction - 1),
        exponent | 1 << (fraction - 1) | 0x1234,
    ];
    let mask = (1_u128 << bits) - 1;
    for _ in 0..40 {
        values.push(u128::from(random.next()) & mask);
        // An exponent within a few of one, with a random fraction.
        let near = one + (u128::from(random.next() % 9) << fraction) - (4 << fraction);
        values.push(
            near & !((1 << fraction) - 1) | u128::from(random.next()) & ((1 << fraction) - 1),
        );
    }
    values
        .iter()
        .flat_map(|value| [*value, value | sign])
        .collect()
}

#[test]
fn software_arithmetic_is_the_host_s_in_binary32_and_binary64() {
    let mut random = Sequence(0x736f_6674_666c_6f61);
    let compare = |relation| FloatOp::Compare {
        relation,
        unordered: false,
    };
    let binary = [
        FloatOp::Add,
        FloatOp::Sub,
        FloatOp::Mul,
        FloatOp::Div,
        FloatOp::Rem,
        FloatOp::Minimum,
        FloatOp::Maximum,
        FloatOp::MinNum,
        FloatOp::MaxNum,
        compare(FloatRelation::Equal),
        compare(FloatRelation::Less),
        compare(FloatRelation::GreaterEqual),
        FloatOp::Compare {
            relation: FloatRelation::NotEqual,
            unordered: true,
        },
    ];
    let mut checked = 0;
    for format in [Binary32, Binary64] {
        let values = operands(format, &mut random);
        for a in &values {
            assert_eq!(
                soft(FloatOp::Sqrt, format, &[*a]).map(Computed::Bits),
                native(FloatOp::Sqrt, format, &[*a]),
                "sqrt {a:x}"
            );
            for b in &values {
                for op in binary {
                    assert_eq!(
                        soft(op, format, &[*a, *b]).map(Computed::Bits),
                        native(op, format, &[*a, *b]),
                        "{op:?} {a:x} {b:x}"
                    );
                    checked += 1;
                }
            }
        }
        // Fused multiply-add on a sample of triples.
        for _ in 0..20_000 {
            let pick =
                |random: &mut Sequence| values[(random.next() % values.len() as u64) as usize];
            let triple = [pick(&mut random), pick(&mut random), pick(&mut random)];
            assert_eq!(
                soft(FloatOp::Fma, format, &triple).map(Computed::Bits),
                native(FloatOp::Fma, format, &triple),
                "fma {triple:x?}"
            );
            checked += 1;
        }
        // Integers of several widths, as signed and as unsigned.
        for _ in 0..5_000 {
            let wide = u128::from(random.next()) << 64 | u128::from(random.next());
            for bits in [1, 8, 31, 32, 53, 64, 65, 127, 128] {
                let value = if bits == 128 {
                    wide
                } else {
                    wide & ((1 << bits) - 1)
                };
                for op in [FloatOp::FromSigned { bits }, FloatOp::FromUnsigned { bits }] {
                    assert_eq!(
                        soft(op, format, &[value]).map(Computed::Bits),
                        native(op, format, &[value]),
                        "{op:?} {value:x}"
                    );
                    checked += 1;
                }
            }
        }
    }
    // Between the two formats, both ways.
    for (from, to) in [(Binary32, Binary64), (Binary64, Binary32)] {
        for value in operands(from, &mut random) {
            let op = FloatOp::Convert { to };
            assert_eq!(
                soft(op, from, &[value]).map(Computed::Bits),
                native(op, from, &[value]),
                "convert {value:x}"
            );
            checked += 1;
        }
    }
    assert!(checked > 900_000, "only {checked} comparisons");
}

/// A binary128 encoding from its sign, unbiased exponent and fraction.
fn quad(negative: bool, exponent: i32, fraction: u128) -> u128 {
    u128::from(negative) << 127 | ((exponent + 16383) as u128) << 112 | fraction
}

#[test]
fn binary128_arithmetic_has_the_known_answers() {
    let eval = |op, operands: &[u128]| soft(op, Binary128, operands).unwrap();
    let (one, two, three) = (
        quad(false, 0, 0),
        quad(false, 1, 0),
        quad(false, 1, 1 << 111),
    );
    assert_eq!(eval(FloatOp::Add, &[one, one]), two);
    assert_eq!(eval(FloatOp::Add, &[one, two]), three);
    assert_eq!(eval(FloatOp::Sub, &[three, two]), one);
    assert_eq!(eval(FloatOp::Mul, &[three, two]), quad(false, 2, 1 << 111));
    // One third: the fraction is 0101... and the last digit rounds down.
    assert_eq!(
        eval(FloatOp::Div, &[one, three]),
        quad(false, -2, 0x5555_5555_5555_5555_5555_5555_5555)
    );
    // The square root of two, to 113 bits.
    assert_eq!(
        eval(FloatOp::Sqrt, &[two]),
        0x3fff_6a09_e667_f3bc_c908_b2fb_1366_ea95
    );
    assert_eq!(eval(FloatOp::Sqrt, &[quad(false, 2, 0)]), two);
    // Seven modulo two, and seven and a half modulo two.
    assert_eq!(eval(FloatOp::Rem, &[quad(false, 2, 3 << 110), two]), one);
    assert_eq!(
        eval(FloatOp::Rem, &[quad(false, 2, 7 << 109), two]),
        quad(false, 0, 1 << 111)
    );
    // (1 + 2^-112)^2 - (1 + 2^-111): only a fused operation keeps 2^-224.
    let next = quad(false, 0, 1);
    let minus = quad(true, 0, 2);
    assert_eq!(
        eval(FloatOp::Fma, &[next, next, minus]),
        quad(false, -224, 0)
    );
    assert_eq!(
        eval(FloatOp::Add, &[eval(FloatOp::Mul, &[next, next]), minus]),
        0
    );

    // The limits: the largest value doubled, the smallest halved.
    let largest = quad(false, 16383, (1 << 112) - 1);
    assert_eq!(eval(FloatOp::Add, &[largest, largest]), 0x7fff << 112);
    assert_eq!(eval(FloatOp::Div, &[1, two]), 0);
    assert_eq!(eval(FloatOp::Add, &[1, 1]), 2);
    // Special operands follow the rules of the other formats.
    let infinity = 0x7fff_u128 << 112;
    let quiet = infinity | 1 << 111;
    assert_eq!(eval(FloatOp::Sub, &[infinity, infinity]), quiet);
    assert_eq!(eval(FloatOp::Mul, &[0, infinity]), quiet);
    assert_eq!(eval(FloatOp::Add, &[infinity | 5, one]), quiet | 5);
    assert_eq!(eval(FloatOp::Sqrt, &[quad(true, 0, 0)]), quiet);
    assert_eq!(eval(FloatOp::Sub, &[one, one]), 0);
    let less = FloatOp::Compare {
        relation: FloatRelation::Less,
        unordered: false,
    };
    assert_eq!(eval(less, &[one, two]), 1);
    assert_eq!(eval(less, &[two, one]), 0);
    assert_eq!(eval(less, &[quiet, one]), 0);

    // Conversions: exact from the narrower formats, rounded to them.
    let widen =
        |from, value: u128| soft(FloatOp::Convert { to: Binary128 }, from, &[value]).unwrap();
    assert_eq!(widen(Binary64, u128::from(1.0_f64.to_bits())), one);
    assert_eq!(
        widen(Binary32, u128::from((-3.0_f32).to_bits())),
        three | 1 << 127
    );
    assert_eq!(
        widen(Binary64, u128::from(f64::from_bits(1).to_bits())),
        quad(false, -1074, 0)
    );
    let narrow =
        |value: u128| soft(FloatOp::Convert { to: Binary64 }, Binary128, &[value]).unwrap();
    assert_eq!(narrow(three), u128::from(3.0_f64.to_bits()));
    assert_eq!(narrow(next), u128::from(1.0_f64.to_bits()));
    assert_eq!(narrow(largest), u128::from(f64::INFINITY.to_bits()));
    assert_eq!(
        soft(
            FloatOp::FromSigned { bits: 64 },
            Binary128,
            &[u128::from(u64::MAX)]
        ),
        Some(one | 1 << 127)
    );
    assert_eq!(
        soft(FloatOp::FromUnsigned { bits: 128 }, Binary128, &[u128::MAX]),
        Some(quad(false, 128, 0))
    );
}
