use super::{Error, Flags, Value, evaluate};

#[test]
fn rejects_unknown_before_poison_propagation() {
    assert_eq!(
        evaluate("unknown", 8, Value::Poison, Value::Poison, Flags::default()),
        Err(Error::Operation)
    );
}

#[test]
fn maximal_width_sign_shift_and_division() {
    let nsw = Flags {
        nsw: true,
        ..Flags::default()
    };
    assert_eq!(
        evaluate("shl", 128, Value::Bits(1), Value::Bits(127), nsw),
        Ok(Value::Poison)
    );
    assert_eq!(
        evaluate("shl", 128, Value::Bits(u128::MAX), Value::Bits(127), nsw),
        Ok(Value::Bits(1 << 127))
    );
    assert_eq!(
        evaluate(
            "srem",
            128,
            Value::Bits(1 << 127),
            Value::Bits(u128::MAX),
            Flags::default()
        ),
        Err(Error::SignedDivisionOverflow)
    );
}

#[test]
fn poison_deferral_freeze_and_divisor() {
    assert_eq!(
        evaluate("add", 8, Value::Poison, Value::Bits(0), Flags::default()),
        Ok(Value::Poison)
    );
    assert_eq!(
        evaluate("freeze", 8, Value::Poison, Value::Bits(0), Flags::default()),
        Ok(Value::Bits(0))
    );
    assert_eq!(
        evaluate("udiv", 8, Value::Poison, Value::Bits(0), Flags::default()),
        Err(Error::DivisionByZero)
    );
    assert_eq!(
        evaluate("udiv", 8, Value::Bits(1), Value::Poison, Flags::default()),
        Err(Error::PoisonDivisor)
    );
}

#[test]
fn invalid_width_operand_and_flags_are_rejected() {
    for width in [0, 129, u32::MAX] {
        assert_eq!(
            evaluate(
                "add",
                width,
                Value::Bits(0),
                Value::Bits(0),
                Flags::default()
            ),
            Err(Error::Width)
        );
    }
    assert_eq!(
        evaluate("add", 1, Value::Bits(2), Value::Bits(0), Flags::default()),
        Err(Error::Operand)
    );
    assert_eq!(
        evaluate(
            "and",
            8,
            Value::Bits(0),
            Value::Bits(0),
            Flags {
                nsw: true,
                ..Flags::default()
            }
        ),
        Err(Error::Flags)
    );
}
