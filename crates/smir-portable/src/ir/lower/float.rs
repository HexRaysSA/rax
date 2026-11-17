//! Lowering of the floating-point operations.

use crate::Error;
use crate::context::field;
use crate::ir::{FloatFormat, FloatOp, FloatRelation, Op, Slot, Type, TypeId};
use crate::wire::RecordValue;

use super::{Body, flag, malformed, require, token, unimplemented};

/// Whether `name` is an operation this module lowers.
pub(super) fn is_float_operation(name: &str) -> bool {
    name.starts_with("fp_")
        || matches!(
            name,
            "fcmp"
                | "sitofp"
                | "uitofp"
                | "fptosi"
                | "fptoui"
                | "fptosi_sat"
                | "fptoui_sat"
                | "fpconvert"
        )
}

fn relation(predicate: &str) -> Result<(FloatRelation, bool), Error> {
    Ok(match predicate {
        "false" => (FloatRelation::False, false),
        "true" => (FloatRelation::True, false),
        "ord" => (FloatRelation::Ordered, false),
        "uno" => (FloatRelation::Unordered, false),
        _ => {
            let (unordered, relation) = match predicate.split_at_checked(1) {
                Some(("o", relation)) => (false, relation),
                Some(("u", relation)) => (true, relation),
                _ => return Err(malformed("float comparison predicate")),
            };
            let relation = match relation {
                "eq" => FloatRelation::Equal,
                "ne" => FloatRelation::NotEqual,
                "lt" => FloatRelation::Less,
                "le" => FloatRelation::LessEqual,
                "gt" => FloatRelation::Greater,
                "ge" => FloatRelation::GreaterEqual,
                _ => return Err(malformed("float comparison predicate")),
            };
            (relation, unordered)
        }
    })
}

impl Body<'_> {
    fn float_format(&self, ty: TypeId) -> Result<FloatFormat, Error> {
        match self.types.scalar(ty)? {
            Type::Float { format } => Ok(*format),
            _ => Err(malformed("float type expected")),
        }
    }

    /// Lower one of the operations [`is_float_operation`] names.
    pub(super) fn float_operation(
        &self,
        name: &str,
        operation: &RecordValue,
        operands: &[(Slot, TypeId)],
        results: &[(Slot, TypeId)],
    ) -> Result<Op, Error> {
        // Only the default environment executes: round to nearest with ties
        // to even, and no exception is observable.
        let mode = field(operation, "mode")?;
        if token(mode, "environment")? != "default" {
            return Err(unimplemented("constrained floating-point environment"));
        }
        require(
            token(mode, "rounding")? == "nearest_even" && token(mode, "exceptions")? == "ignore",
            "default floating-point mode",
        )?;
        let [(dst, result)] = results else {
            return Err(malformed("single result expected"));
        };
        let arity = |count: usize| require(operands.len() == count, "operand count");
        // All operands and the result are floats of one format.
        let uniform = |count: usize| -> Result<FloatFormat, Error> {
            arity(count)?;
            let format = self.float_format(*result)?;
            for (_, ty) in operands {
                require(self.float_format(*ty)? == format, "float operand type")?;
            }
            Ok(format)
        };
        let (op, format) = match name {
            "fp_add" => (FloatOp::Add, uniform(2)?),
            "fp_sub" => (FloatOp::Sub, uniform(2)?),
            "fp_mul" => (FloatOp::Mul, uniform(2)?),
            "fp_div" => (FloatOp::Div, uniform(2)?),
            "fp_frem" => (FloatOp::Rem, uniform(2)?),
            "fp_fma" => (FloatOp::Fma, uniform(3)?),
            "fp_sqrt" => (FloatOp::Sqrt, uniform(1)?),
            "fp_neg" => (FloatOp::Neg, uniform(1)?),
            "fp_abs" => (FloatOp::Abs, uniform(1)?),
            "fp_copysign" => (FloatOp::CopySign, uniform(2)?),
            "fp_minimum" => (FloatOp::Minimum, uniform(2)?),
            "fp_maximum" => (FloatOp::Maximum, uniform(2)?),
            "fp_minnum" => (FloatOp::MinNum, uniform(2)?),
            "fp_maxnum" => (FloatOp::MaxNum, uniform(2)?),
            "fp_minimumnum" => (FloatOp::MinimumNum, uniform(2)?),
            "fp_maximumnum" => (FloatOp::MaximumNum, uniform(2)?),
            "fcmp" => {
                arity(2)?;
                require(self.types.int_bits(*result)? == 1, "comparison result")?;
                let format = self.float_format(operands[0].1)?;
                require(
                    self.float_format(operands[1].1)? == format,
                    "comparison operands",
                )?;
                // A signaling comparison differs only in the exceptions it
                // raises, which the default environment does not observe.
                flag(operation, "signaling")?;
                let (relation, unordered) = relation(token(operation, "predicate")?)?;
                (
                    FloatOp::Compare {
                        relation,
                        unordered,
                    },
                    format,
                )
            }
            "sitofp" | "uitofp" => {
                arity(1)?;
                let bits = self.types.int_bits(operands[0].1)?;
                let op = if name == "sitofp" {
                    FloatOp::FromSigned { bits }
                } else {
                    FloatOp::FromUnsigned { bits }
                };
                (op, self.float_format(*result)?)
            }
            "fptosi" | "fptoui" | "fptosi_sat" | "fptoui_sat" => {
                arity(1)?;
                let bits = self.types.int_bits(*result)?;
                let saturating = name.ends_with("_sat");
                let op = if name.starts_with("fptosi") {
                    FloatOp::ToSigned { bits, saturating }
                } else {
                    FloatOp::ToUnsigned { bits, saturating }
                };
                (op, self.float_format(operands[0].1)?)
            }
            "fpconvert" => {
                arity(1)?;
                (
                    FloatOp::Convert {
                        to: self.float_format(*result)?,
                    },
                    self.float_format(operands[0].1)?,
                )
            }
            other => return Err(unimplemented(format!("operation {other}"))),
        };
        Ok(Op::Float {
            dst: *dst,
            op,
            format,
            args: operands.iter().map(|(slot, _)| *slot).collect(),
        })
    }
}
