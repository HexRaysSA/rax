//! Lowering of the atomic memory operations.
//!
//! The engine runs one thread, so an atomic access is the plain access with
//! the same guards. The ordering an operation names is checked to be one the
//! format allows and otherwise has no effect yet.

use crate::Error;
use crate::ir::{Op, RmwAction, Scalar, Slot, TypeId};
use crate::wire::RecordValue;

use super::{Body, field, malformed, require, token, unimplemented};

/// Whether `name` is an operation this module lowers.
pub(super) fn is_atomic_operation(name: &str) -> bool {
    matches!(
        name,
        "atomic_load" | "atomic_store" | "atomic_rmw" | "cmpxchg" | "fence"
    )
}

impl Body<'_> {
    pub(super) fn atomic_operation(
        &self,
        name: &str,
        operation: &RecordValue,
        operands: &[(Slot, TypeId)],
        results: &[(Slot, TypeId)],
    ) -> Result<Op, Error> {
        if name == "fence" {
            require(
                operands.is_empty() && results.is_empty(),
                "fence has no operands",
            )?;
            return Ok(Op::Fence);
        }
        let Some(((ptr, pointer), values)) = operands.split_first() else {
            return Err(malformed("operand count"));
        };
        self.data_ptr(*pointer, "atomic access address")?;
        let (kind, bytes, alignment, stored) = self.access(operation)?;
        for (_, ty) in values {
            require(self.types.same(*ty, stored), "atomic operand type")?;
        }
        match (name, values, results) {
            ("atomic_load", [], [(dst, ty)]) => {
                require(self.types.same(*ty, stored), "load result type")?;
                Ok(Op::Load {
                    dst: *dst,
                    ptr: *ptr,
                    kind,
                    bytes,
                    alignment,
                })
            }
            ("atomic_store", [(value, _)], []) => Ok(Op::Store {
                ptr: *ptr,
                value: *value,
                kind,
                bytes,
                alignment,
            }),
            ("atomic_rmw", [(value, _)], [(dst, ty)]) => {
                require(self.types.same(*ty, stored), "exchange result type")?;
                let action = match token(operation, "action")? {
                    "exchange" => RmwAction::Exchange,
                    "add" => RmwAction::Add,
                    "sub" => RmwAction::Sub,
                    "and" => RmwAction::And,
                    "nand" => RmwAction::Nand,
                    "or" => RmwAction::Or,
                    "xor" => RmwAction::Xor,
                    "min" => RmwAction::Min,
                    "max" => RmwAction::Max,
                    "umin" => RmwAction::UMin,
                    "umax" => RmwAction::UMax,
                    other => return Err(unimplemented(format!("atomic action {other}"))),
                };
                // Everything but an exchange is integer arithmetic.
                require(
                    action == RmwAction::Exchange || matches!(kind, Scalar::Int { .. }),
                    "atomic arithmetic on a pointer",
                )?;
                Ok(Op::AtomicRmw {
                    dst: *dst,
                    ptr: *ptr,
                    value: *value,
                    action,
                    kind,
                    bytes,
                    alignment,
                })
            }
            ("cmpxchg", [(expected, _), (replacement, _)], [(old, ty), (success, flag)]) => {
                require(self.types.same(*ty, stored), "exchange result type")?;
                require(self.types.int_bits(*flag)? == 1, "exchange success type")?;
                // A weak exchange may fail spuriously; this one never does.
                field(operation, "weak")?;
                Ok(Op::CompareExchange {
                    old: *old,
                    success: *success,
                    ptr: *ptr,
                    expected: *expected,
                    replacement: *replacement,
                    kind,
                    bytes,
                    alignment,
                })
            }
            _ => Err(malformed("atomic operation shape")),
        }
    }
}
