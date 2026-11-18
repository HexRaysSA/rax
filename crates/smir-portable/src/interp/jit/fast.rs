//! Instructions for single operations.
//!
//! Each sequence here does what the interpreter does for one operation in
//! the case it is written for: operands that are integers, of 64 bits or
//! fewer, and a result that is defined. It checks that this is the case it
//! has and otherwise jumps to `slow`, where the engine performs the
//! operation with the interpreter's code. A sequence that has jumped to
//! `slow` has changed no value.
//!
//! An integer of `bits` bits is held zero-extended, so the low 64 bits of a
//! cell are the whole integer and the high 64 are zero.

use crate::ir::{Cast, IntBinary, IntFlags, Op, Predicate, Value};

use super::{Assembler, Condition, INT, Label, POISON, Reg, Shift, UNDEF};

/// Emit instructions for `op` if there are any for it. Returns whether it
/// did; if not, nothing was emitted and the engine performs the operation.
pub(super) fn operation(assembler: &mut Assembler, op: &Op, slow: Label) -> bool {
    match op {
        Op::Const { dst, value } => match value {
            Value::Int(bits) => {
                let fields = (*bits as u64, (*bits >> 64) as u64);
                assembler.store_constant(dst.0, INT, Some(fields));
                true
            }
            Value::Poison => {
                assembler.store_constant(dst.0, POISON, None);
                true
            }
            Value::Undef => {
                assembler.store_constant(dst.0, UNDEF, None);
                true
            }
            // A pointer's fields have no layout that is fixed here.
            _ => false,
        },
        Op::Copy { dst, src } => {
            assembler.copy(dst.0, src.0);
            true
        }
        Op::IntBinary {
            dst,
            op,
            bits,
            flags,
            lhs,
            rhs,
        } if *bits <= 64 => {
            if !binary_has_instructions(*op, *bits, *flags) {
                return false;
            }
            assembler.load_int(Reg::A, lhs.0, slow);
            assembler.load_int(Reg::B, rhs.0, slow);
            binary(assembler, *op, *bits, *flags, slow);
            assembler.store_int(dst.0, Reg::A);
            true
        }
        Op::Icmp {
            dst,
            pred,
            bits,
            lhs,
            rhs,
        } if *bits <= 64 => {
            assembler.load_int(Reg::A, lhs.0, slow);
            assembler.load_int(Reg::B, rhs.0, slow);
            let (condition, signed) = match pred {
                Predicate::Eq => (Condition::Eq, false),
                Predicate::Ne => (Condition::Ne, false),
                Predicate::Ult => (Condition::Ult, false),
                Predicate::Ule => (Condition::Ule, false),
                Predicate::Ugt => (Condition::Ugt, false),
                Predicate::Uge => (Condition::Uge, false),
                Predicate::Slt => (Condition::Slt, true),
                Predicate::Sle => (Condition::Sle, true),
                Predicate::Sgt => (Condition::Sgt, true),
                Predicate::Sge => (Condition::Sge, true),
            };
            if signed {
                assembler.sign_extend(Reg::A, *bits);
                assembler.sign_extend(Reg::B, *bits);
            }
            assembler.set_if(condition, Reg::A, Reg::A, Reg::B);
            assembler.store_int(dst.0, Reg::A);
            true
        }
        Op::Cast {
            dst,
            op,
            from_bits,
            to_bits,
            src,
        } if *from_bits <= 64 && *to_bits <= 64 => {
            assembler.load_int(Reg::A, src.0, slow);
            match op {
                Cast::Trunc => assembler.zero_extend(Reg::A, *to_bits),
                // The operand is zero-extended already.
                Cast::Zext => {}
                Cast::Sext => {
                    assembler.sign_extend(Reg::A, *from_bits);
                    assembler.zero_extend(Reg::A, *to_bits);
                }
            }
            assembler.store_int(dst.0, Reg::A);
            true
        }
        Op::Select {
            dst,
            cond,
            if_true,
            if_false,
        } => {
            // The chosen arm is forwarded as it is, whatever it holds.
            let (otherwise, done) = (assembler.label(), assembler.label());
            assembler.load_truth(Reg::A, cond.0, slow);
            assembler.jump_if_zero(Reg::A, otherwise);
            assembler.copy(dst.0, if_true.0);
            assembler.jump(done);
            assembler.bind(otherwise);
            assembler.copy(dst.0, if_false.0);
            assembler.bind(done);
            true
        }
        _ => false,
    }
}

/// Whether [`binary`] has instructions for the operation with these flags.
fn binary_has_instructions(op: IntBinary, bits: u32, flags: IntFlags) -> bool {
    match op {
        IntBinary::Add | IntBinary::Sub | IntBinary::And | IntBinary::Or | IntBinary::Xor => true,
        // A checked product is formed exactly, which 64 bits can hold for
        // factors of up to 32, or with the host's own check at 64.
        IntBinary::Mul => bits <= 32 || bits == 64 || !(flags.nsw || flags.nuw),
        IntBinary::Shl => true,
        IntBinary::LShr | IntBinary::AShr => !flags.exact,
        IntBinary::UDiv
        | IntBinary::SDiv
        | IntBinary::URem
        | IntBinary::SRem
        | IntBinary::RotL
        | IntBinary::RotR => false,
    }
}

/// `A = A <op> B` for integers of `bits` bits, zero-extended in A and B.
/// Leaves for `slow` where the interpreter's result is not an integer: a
/// result that a flag makes poison, a shift by the width or more.
fn binary(assembler: &mut Assembler, op: IntBinary, bits: u32, flags: IntFlags, slow: Label) {
    let mask = u64::MAX >> (64 - bits);
    match op {
        IntBinary::And => assembler.and(Reg::A, Reg::B),
        IntBinary::Or => assembler.or(Reg::A, Reg::B),
        IntBinary::Xor => assembler.xor(Reg::A, Reg::B),
        IntBinary::Add if bits == 64 => {
            assembler.add_checked(Reg::A, Reg::B, flags.nsw, flags.nuw, slow);
        }
        IntBinary::Sub if bits == 64 => {
            assembler.subtract_checked(Reg::A, Reg::B, flags.nsw, flags.nuw, slow);
        }
        IntBinary::Mul if bits == 64 && (flags.nsw || flags.nuw) => {
            assembler.multiply_checked(flags.nsw, flags.nuw, slow);
        }
        IntBinary::Add | IntBinary::Sub | IntBinary::Mul => {
            // Narrower than a register: the exact unsigned and signed
            // results fit in 64 bits (for a product, of factors of up to 32
            // bits), so each is formed and compared with what `bits` bits
            // hold of it.
            let apply = |assembler: &mut Assembler, target: Reg, source: Reg| match op {
                IntBinary::Add => assembler.add(target, source),
                IntBinary::Sub => assembler.subtract(target, source),
                _ => assembler.multiply(target, source),
            };
            if flags.nuw {
                if op == IntBinary::Sub {
                    assembler.jump_if(Condition::Ult, Reg::A, Reg::B, slow);
                } else {
                    assembler.copy_register(Reg::C, Reg::A);
                    apply(assembler, Reg::C, Reg::B);
                    assembler.jump_if_constant(Condition::Ugt, Reg::C, mask, slow);
                }
            }
            if flags.nsw {
                assembler.sign_extend(Reg::A, bits);
                assembler.sign_extend(Reg::B, bits);
                apply(assembler, Reg::A, Reg::B);
                assembler.copy_register(Reg::C, Reg::A);
                assembler.sign_extend(Reg::C, bits);
                assembler.jump_if(Condition::Ne, Reg::A, Reg::C, slow);
            } else {
                apply(assembler, Reg::A, Reg::B);
            }
            assembler.zero_extend(Reg::A, bits);
        }
        IntBinary::Shl | IntBinary::LShr | IntBinary::AShr => {
            // A shift by the width or more is poison.
            assembler.jump_if_constant(Condition::Uge, Reg::B, u64::from(bits), slow);
            match op {
                IntBinary::Shl => {
                    if flags.nuw {
                        // No bit may be lost: shifted back, what is left of
                        // the operand in `bits` bits is the operand.
                        assembler.copy_register(Reg::C, Reg::A);
                        assembler.shift(Shift::Left, Reg::C);
                        assembler.zero_extend(Reg::C, bits);
                        assembler.shift(Shift::Right, Reg::C);
                        assembler.jump_if(Condition::Ne, Reg::C, Reg::A, slow);
                    }
                    if flags.nsw {
                        // Nor may the sign change: shifted back as a signed
                        // number, the result is the signed operand.
                        assembler.copy_register(Reg::C, Reg::A);
                        assembler.shift(Shift::Left, Reg::C);
                        assembler.sign_extend(Reg::C, bits);
                        assembler.shift(Shift::RightSigned, Reg::C);
                        assembler.sign_extend(Reg::A, bits);
                        assembler.jump_if(Condition::Ne, Reg::C, Reg::A, slow);
                    }
                    assembler.shift(Shift::Left, Reg::A);
                    assembler.zero_extend(Reg::A, bits);
                }
                IntBinary::LShr => assembler.shift(Shift::Right, Reg::A),
                _ => {
                    assembler.sign_extend(Reg::A, bits);
                    assembler.shift(Shift::RightSigned, Reg::A);
                    assembler.zero_extend(Reg::A, bits);
                }
            }
        }
        IntBinary::UDiv
        | IntBinary::SDiv
        | IntBinary::URem
        | IntBinary::SRem
        | IntBinary::RotL
        | IntBinary::RotR => unreachable!("no instructions for this operation"),
    }
}
