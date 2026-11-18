//! One step of one activation: committing phis, an operation, or a
//! terminator. Everything a step shares with other threads it reaches
//! through its [`Context`].

use crate::Error;
use crate::ir::{
    BlockIdx, Callee, CodeRef, FuncIdx, Function, Module, ObjectId, Op, Pointer, Slot, Terminator,
    Type, Value,
};

use super::int::{self, Arg, Computed};
use super::process::Context;
use super::{Fault, atomic, float, memory, services};

pub(super) struct Frame {
    pub(super) function: FuncIdx,
    pub(super) block: BlockIdx,
    pub(super) predecessor: Option<BlockIdx>,
    /// `None` until the block's phis are committed, then the next operation.
    pub(super) position: Option<usize>,
    values: Vec<Value>,
    /// Caller slots that receive this activation's results.
    pub(super) results_to: Vec<Slot>,
    /// Stack objects this activation allocated; they end when it returns.
    pub(super) owned: Vec<ObjectId>,
}

impl Frame {
    pub(super) fn new(
        function: &Function,
        index: FuncIdx,
        arguments: &[Value],
        results_to: Vec<Slot>,
    ) -> Self {
        // The verifier guarantees every use is dominated by its definition, so
        // the initial contents of a slot are never observed.
        let mut values = vec![Value::Undef; function.slots as usize];
        for (slot, argument) in function.params.iter().zip(arguments) {
            values[slot.index()] = *argument;
        }
        Self {
            function: index,
            block: function.entry,
            predecessor: None,
            position: None,
            values,
            results_to,
            owned: Vec::new(),
        }
    }

    pub(super) fn get(&self, slot: Slot) -> Value {
        self.values[slot.index()]
    }

    pub(super) fn set(&mut self, slot: Slot, value: Value) {
        self.values[slot.index()] = value;
    }

    fn branch(&mut self, target: BlockIdx) {
        self.predecessor = Some(self.block);
        self.block = target;
        self.position = None;
    }
}

/// What one step asks the driver to do next.
pub(super) enum Step {
    Continue,
    Call {
        callee: FuncIdx,
        arguments: Vec<Value>,
        results_to: Vec<Slot>,
    },
    Return(Vec<Value>),
    /// A registered trap.
    Trap(&'static str),
    /// An explicit `trap` terminator with the program's own reason token.
    Explicit(String),
    LanguageUb(&'static str),
    Resource(&'static str),
    /// The program asked to end with this status; `clean` if its cleanup is
    /// to run first.
    Exit {
        status: i32,
        clean: bool,
    },
    /// The program asked to end abnormally.
    Abort,
    /// The calling thread asked to end with this result.
    ThreadExit(u64),
    /// The thread would wait for something no thread is left to do.
    Deadlock,
    /// The program is ending; this thread stops here.
    Stop,
}

impl From<memory::Fault> for Step {
    fn from(fault: memory::Fault) -> Self {
        match fault {
            memory::Fault::Trap(code) => Self::Trap(code),
            memory::Fault::Ub(code) => Self::LanguageUb(code),
            memory::Fault::Resource(code) => Self::Resource(code),
        }
    }
}

/// A pointer operand: undef refines to the null pointer, which has no origin.
/// `Err` is the step that ends the run for a poison pointer.
pub(super) fn pointer(value: Value) -> Result<Result<Pointer, Step>, Error> {
    match value {
        Value::DataPtr(pointer) => Ok(Ok(pointer)),
        Value::Undef => Ok(Ok(Pointer::originless(0))),
        Value::Poison => Ok(Err(Step::LanguageUb("ub_pointer"))),
        _ => Err(internal("pointer operand")),
    }
}

/// A 64-bit size or offset operand of a helper: undef refines to zero and
/// poison is undefined behaviour with the given code.
pub(super) fn amount(value: Value, poison: &'static str) -> Result<Result<u64, Step>, Error> {
    match value {
        Value::Int(bits) => Ok(Ok(bits as u64)),
        Value::Undef => Ok(Ok(0)),
        Value::Poison => Ok(Err(Step::LanguageUb(poison))),
        _ => Err(internal("integer operand")),
    }
}

pub(super) fn internal(what: &'static str) -> Error {
    Error::semantic("EXEC_INTERNAL", what)
}

/// An operand of an integer operation, with undef refined to zero.
pub(super) fn integer(value: Value) -> Result<Arg, Error> {
    match value {
        Value::Int(bits) => Ok(Arg::Bits(bits)),
        Value::DataPtr(pointer) => Ok(Arg::Bits(u128::from(pointer.address))),
        Value::Undef => Ok(Arg::Bits(0)),
        Value::Poison => Ok(Arg::Poison),
        // Code pointers take part in equality comparisons by their token.
        Value::CodePtr(target) => Ok(Arg::Bits(u128::from(target.bits()))),
        Value::CodeAddress(_) => Err(internal("code address in integer operation")),
    }
}

pub(super) fn computed(result: Computed) -> Value {
    match result {
        Computed::Bits(bits) => Value::Int(bits),
        Computed::Poison => Value::Poison,
    }
}

/// Whether `value` is a legal runtime value of type `ty`.
pub(super) fn fits(module: &Module, ty: &Type, value: Value) -> bool {
    match (ty, value) {
        (_, Value::Poison | Value::Undef) => !matches!(ty, Type::Function(_) | Type::Other { .. }),
        (Type::Int { bits }, Value::Int(payload)) => *bits <= 128 && payload <= int::mask(*bits),
        (Type::Float { format }, Value::Int(payload)) => payload <= int::mask(format.bits()),
        (Type::DataPtr, Value::DataPtr(_)) => true,
        (Type::CodeAddress, Value::CodeAddress(target))
        | (Type::CodePtr { .. }, Value::CodePtr(target)) => match target {
            CodeRef::Function(index) => index.index() < module.functions.len(),
            CodeRef::Originless(_) => true,
        },
        _ => false,
    }
}

pub(super) fn operation(context: &Context, frame: &mut Frame, op: &Op) -> Result<Step, Error> {
    let module = context.process.module;
    let memory = &context.process.memory;
    let segments = &context.process.segments;
    // Unwrap a checked operand or end the step with its fault.
    macro_rules! checked {
        ($operand:expr) => {
            match $operand? {
                Ok(value) => value,
                Err(step) => return Ok(step),
            }
        };
    }
    macro_rules! guarded {
        ($access:expr) => {
            match $access {
                Ok(value) => value,
                Err(fault) => return Ok(fault.into()),
            }
        };
    }
    match op {
        Op::Load {
            dst,
            ptr,
            kind,
            bytes,
            alignment,
        } => {
            let address = checked!(pointer(frame.get(*ptr)));
            let value = guarded!(memory.load(address, *kind, *bytes, *alignment));
            frame.set(*dst, value);
        }
        Op::Store {
            ptr,
            value,
            kind,
            bytes,
            alignment,
        } => {
            let address = checked!(pointer(frame.get(*ptr)));
            guarded!(memory.store(address, frame.get(*value), *kind, *bytes, *alignment));
        }
        Op::PtrOffset {
            dst,
            ptr,
            delta,
            inbounds,
            check_base,
            nuw,
            nusw,
        } => {
            // Unlike an access, arithmetic on a poison pointer is not
            // undefined; it yields poison.
            let moved = match (frame.get(*ptr), integer(frame.get(*delta))?) {
                (Value::Poison, _) | (_, Arg::Poison) => None,
                (base, Arg::Bits(delta)) => {
                    let base = checked!(pointer(base));
                    memory.offset(
                        base,
                        delta as u64 as i64,
                        *inbounds,
                        *check_base,
                        *nuw,
                        *nusw,
                    )
                }
            };
            frame.set(*dst, moved.map_or(Value::Poison, Value::DataPtr));
        }
        Op::Alloca {
            dst,
            size,
            alignment,
        } => {
            let size = checked!(amount(frame.get(*size), "ub_allocation_size"));
            let object = guarded!(memory.allocate(size, *alignment));
            frame.owned.extend(object.origin);
            frame.set(*dst, Value::DataPtr(object));
        }
        Op::Lifetime { ptr, size, start } => {
            let address = checked!(pointer(frame.get(*ptr)));
            let size = checked!(amount(frame.get(*size), "ub_lifetime_size"));
            guarded!(memory.lifetime(address, size, *start));
        }
        Op::PtrToInt {
            dst,
            src,
            bits,
            expose,
        } => {
            let value = match frame.get(*src) {
                Value::Poison => Value::Poison,
                source => {
                    let source = checked!(pointer(source));
                    if *expose {
                        memory.expose(source);
                    }
                    Value::Int(u128::from(source.address) & int::mask(*bits))
                }
            };
            frame.set(*dst, value);
        }
        Op::AddressOfData { dst, segment } => {
            frame.set(*dst, Value::DataPtr(segments[segment.index()]));
        }
        Op::MemSet {
            dst,
            value,
            count,
            alignment,
        } => {
            // The count must be defined even when the destination is not
            // touched; a zero count touches nothing and checks nothing else.
            let Value::Int(count) = frame.get(*count) else {
                return Ok(Step::LanguageUb("ub_memory_count"));
            };
            if count != 0 {
                let target = frame.get(*dst);
                if !target.is_well_defined() {
                    return Ok(Step::LanguageUb("ub_memory_address"));
                }
                let target = checked!(pointer(target));
                guarded!(memory.fill(target, frame.get(*value), count as u64, *alignment));
            }
        }
        Op::MemCopy {
            dst,
            src,
            count,
            alignment,
            overlapping,
        } => {
            let Value::Int(count) = frame.get(*count) else {
                return Ok(Step::LanguageUb("ub_memory_count"));
            };
            if count != 0 {
                let (target, source) = (frame.get(*dst), frame.get(*src));
                if !target.is_well_defined() || !source.is_well_defined() {
                    return Ok(Step::LanguageUb("ub_memory_address"));
                }
                let (target, source) = (checked!(pointer(target)), checked!(pointer(source)));
                guarded!(memory.copy(target, source, count as u64, *alignment, *overlapping));
            }
        }
        Op::IntToPtr { dst, src } => {
            let value = match integer(frame.get(*src))? {
                Arg::Poison => Value::Poison,
                Arg::Bits(bits) => Value::DataPtr(memory.integer_pointer(bits as u64)),
            };
            frame.set(*dst, value);
        }
        Op::CodeToInt {
            dst,
            src,
            bits,
            expose,
        } => {
            let value = match frame.get(*src) {
                Value::Poison => Value::Poison,
                Value::CodePtr(target) => {
                    if let (true, CodeRef::Function(function)) = (*expose, target) {
                        memory.expose_code(function);
                    }
                    Value::Int(u128::from(target.bits()) & int::mask(*bits))
                }
                // Undef refines to the null pointer.
                Value::Undef => Value::Int(0),
                _ => return Err(internal("code pointer operand")),
            };
            frame.set(*dst, value);
        }
        Op::IntToCode { dst, src } => {
            let value = match integer(frame.get(*src))? {
                Arg::Poison => Value::Poison,
                Arg::Bits(bits) => Value::CodePtr(memory.integer_code(bits as u64)),
            };
            frame.set(*dst, value);
        }
        Op::TlsAddress {
            dst,
            segment,
            offset,
        } => {
            // The address is computed, not accessed: any offset is
            // representable, and a poison offset is a poison address.
            let value = match integer(frame.get(*offset))? {
                Arg::Poison => Value::Poison,
                Arg::Bits(offset) => {
                    let base = guarded!(context.thread_local(*segment));
                    Value::DataPtr(Pointer {
                        address: base.address.wrapping_add(offset as u64),
                        origin: base.origin,
                    })
                }
            };
            frame.set(*dst, value);
        }
        Op::Const { dst, value } => frame.set(*dst, *value),
        Op::Copy { dst, src } => frame.set(*dst, frame.get(*src)),
        Op::Freeze { dst, src, zero } => {
            let value = frame.get(*src);
            frame.set(
                *dst,
                if value.is_well_defined() {
                    value
                } else {
                    *zero
                },
            );
        }
        Op::IntBinary {
            dst,
            op,
            bits,
            flags,
            lhs,
            rhs,
        } => {
            match int::binary(
                *op,
                *bits,
                *flags,
                integer(frame.get(*lhs))?,
                integer(frame.get(*rhs))?,
            ) {
                Ok(result) => frame.set(*dst, computed(result)),
                Err(code) => return Ok(Step::LanguageUb(code)),
            }
        }
        Op::IntUnary {
            dst,
            op,
            bits,
            zero_is_poison,
            src,
        } => {
            let result = int::unary(*op, *bits, *zero_is_poison, integer(frame.get(*src))?);
            frame.set(*dst, computed(result));
        }
        Op::Icmp {
            dst,
            pred,
            bits,
            lhs,
            rhs,
        } => {
            let result = int::compare(
                *pred,
                *bits,
                integer(frame.get(*lhs))?,
                integer(frame.get(*rhs))?,
            );
            frame.set(*dst, computed(result));
        }
        Op::Select {
            dst,
            cond,
            if_true,
            if_false,
        } => {
            // The chosen arm is forwarded as it is, including poison or undef.
            let value = match integer(frame.get(*cond))? {
                Arg::Poison => Value::Poison,
                Arg::Bits(0) => frame.get(*if_false),
                Arg::Bits(_) => frame.get(*if_true),
            };
            frame.set(*dst, value);
        }
        Op::Cast {
            dst,
            op,
            from_bits,
            to_bits,
            src,
        } => {
            let result = int::cast(*op, *from_bits, *to_bits, integer(frame.get(*src))?);
            frame.set(*dst, computed(result));
        }
        Op::AddressOf {
            dst,
            function,
            callable,
        } => {
            let target = CodeRef::Function(*function);
            frame.set(
                *dst,
                if *callable {
                    Value::CodePtr(target)
                } else {
                    Value::CodeAddress(target)
                },
            );
        }
        Op::CodeBind { dst, src } => match frame.get(*src) {
            Value::CodeAddress(CodeRef::Function(function)) => {
                frame.set(*dst, Value::CodePtr(CodeRef::Function(function)));
            }
            // Bits without an origin never become callable, and neither does
            // a poison or undef address.
            Value::CodeAddress(CodeRef::Originless(_)) | Value::Poison | Value::Undef => {
                return Ok(Step::Trap("code_address_unbound"));
            }
            _ => return Err(internal("code_bind operand")),
        },
        Op::CodeErase { dst, src } => match frame.get(*src) {
            Value::CodePtr(target) => frame.set(*dst, Value::CodeAddress(target)),
            Value::Poison | Value::Undef => {
                return Ok(Step::Trap("code_token_invalid"));
            }
            _ => return Err(internal("code_erase operand")),
        },
        Op::Call {
            dsts,
            callee,
            args,
            arg_noundef,
        } => {
            let arguments: Vec<Value> = args.iter().map(|slot| frame.get(*slot)).collect();
            if arguments
                .iter()
                .zip(arg_noundef)
                .any(|(value, noundef)| *noundef && !value.is_well_defined())
            {
                return Ok(Step::LanguageUb("ub_noundef_argument"));
            }
            let function = match callee {
                Callee::Direct(function) => *function,
                Callee::Indirect { value, signature } => match frame.get(*value) {
                    Value::Poison => return Ok(Step::LanguageUb("ub_pointer")),
                    Value::CodePtr(CodeRef::Function(function)) => {
                        if !module.same_type(module.func(function).signature_type, *signature) {
                            return Ok(Step::Trap("code_token_signature"));
                        }
                        function
                    }
                    // Bits with no origin never call anything. If they equal
                    // a real function's token the pointer is stale; any
                    // other pattern, including null, is invalid.
                    Value::CodePtr(CodeRef::Originless(bits)) => {
                        let is_token =
                            bits != 0 && bits % 2 == 0 && bits / 2 <= module.functions.len() as u64;
                        let code = if is_token {
                            "code_token_stale"
                        } else {
                            "code_token_invalid"
                        };
                        return Ok(Step::Trap(code));
                    }
                    // Undef refines to the null pointer.
                    Value::Undef => return Ok(Step::Trap("code_token_invalid")),
                    _ => return Err(internal("indirect callee")),
                },
            };
            // The position advances when the callee returns.
            return Ok(Step::Call {
                callee: function,
                arguments,
                results_to: dsts.clone(),
            });
        }
        Op::AtomicRmw {
            dst,
            ptr,
            value,
            action,
            kind,
            bytes,
            alignment,
        } => {
            let address = checked!(pointer(frame.get(*ptr)));
            let old = guarded!(atomic::read_modify_write(
                memory,
                address,
                *action,
                frame.get(*value),
                *kind,
                *bytes,
                *alignment
            ));
            frame.set(*dst, old);
        }
        Op::CompareExchange {
            old,
            success,
            ptr,
            expected,
            replacement,
            kind,
            bytes,
            alignment,
        } => {
            let address = checked!(pointer(frame.get(*ptr)));
            let (observed, replaced) = guarded!(atomic::compare_exchange(
                memory,
                address,
                frame.get(*expected),
                frame.get(*replacement),
                *kind,
                *bytes,
                *alignment
            ));
            frame.set(*old, observed);
            frame.set(*success, Value::Int(u128::from(replaced)));
        }
        Op::Fence => {}
        Op::Float {
            dst,
            op,
            format,
            args,
        } => {
            let mut operands = Vec::with_capacity(args.len());
            let mut poison = false;
            for slot in args {
                match integer(frame.get(*slot))? {
                    Arg::Bits(bits) => operands.push(bits),
                    Arg::Poison => poison = true,
                }
            }
            let result = if poison {
                Computed::Poison
            } else {
                float::evaluate(*op, *format, &operands)
                    .ok_or_else(|| internal("float operand count"))?
            };
            frame.set(*dst, computed(result));
        }
        Op::Service {
            dsts,
            service,
            args,
        } => {
            let arguments: Vec<Value> = args.iter().map(|slot| frame.get(*slot)).collect();
            let results = checked!(services::call(*service, &arguments, context));
            if results.len() != dsts.len() {
                return Err(internal("service result arity"));
            }
            for (slot, value) in dsts.iter().zip(results) {
                frame.set(*slot, value);
            }
        }
    }
    Ok(Step::Continue)
}

pub(super) fn terminator(
    module: &Module,
    frame: &mut Frame,
    term: &Terminator,
) -> Result<Step, Error> {
    Ok(match term {
        Terminator::Return(slots) => {
            let values: Vec<Value> = slots.iter().map(|slot| frame.get(*slot)).collect();
            let noundef = &module.signature(frame.function).result_noundef;
            if values
                .iter()
                .zip(noundef)
                .any(|(value, required)| *required && !value.is_well_defined())
            {
                Step::LanguageUb("ub_noundef_result")
            } else {
                Step::Return(values)
            }
        }
        Terminator::Jump(target) => {
            frame.branch(*target);
            Step::Continue
        }
        Terminator::Branch {
            cond,
            if_true,
            if_false,
        } => match frame.get(*cond) {
            Value::Int(0) => {
                frame.branch(*if_false);
                Step::Continue
            }
            Value::Int(_) => {
                frame.branch(*if_true);
                Step::Continue
            }
            // Branching on poison or undef is immediate undefined behaviour;
            // undef is not refined here.
            Value::Poison | Value::Undef => Step::LanguageUb("ub_control_value"),
            _ => return Err(internal("branch condition")),
        },
        Terminator::Switch {
            index,
            cases,
            default,
        } => match frame.get(*index) {
            Value::Int(selector) => {
                let target = cases
                    .iter()
                    .find(|(value, _)| *value == selector)
                    .map_or(*default, |(_, target)| *target);
                frame.branch(target);
                Step::Continue
            }
            Value::Poison | Value::Undef => Step::LanguageUb("ub_control_value"),
            _ => return Err(internal("switch index")),
        },
        Terminator::Trap { reason } => Step::Explicit(reason.clone()),
        Terminator::Unreachable => Step::LanguageUb("ub_unreachable"),
    })
}

/// Commit the phis of the block the frame has just entered, for the
/// predecessor it came from, and place the frame at the block's first
/// operation.
pub(super) fn commit_phis(module: &Module, frame: &mut Frame) -> Result<(), Error> {
    let block = &module.func(frame.function).blocks[frame.block.index()];
    // All phis read their inputs before any of them is written.
    let snapshot: Vec<(Slot, Value)> = block
        .phis
        .iter()
        .map(|phi| {
            phi.incoming
                .iter()
                .find(|(predecessor, _)| Some(*predecessor) == frame.predecessor)
                .map(|(_, value)| (phi.dst, frame.get(*value)))
                .ok_or_else(|| internal("phi has no input for the predecessor"))
        })
        .collect::<Result<_, _>>()?;
    for (slot, value) in snapshot {
        frame.set(slot, value);
    }
    frame.position = Some(0);
    Ok(())
}

/// Advance the top frame by one step.
pub(super) fn step(context: &Context, frame: &mut Frame) -> Result<Step, Error> {
    let module = context.process.module;
    let block = &module.func(frame.function).blocks[frame.block.index()];
    let Some(position) = frame.position else {
        commit_phis(module, frame)?;
        return Ok(Step::Continue);
    };
    match block.ops.get(position) {
        Some(op) => {
            let outcome = operation(context, frame, op)?;
            if matches!(outcome, Step::Continue) {
                frame.position = Some(position + 1);
            }
            Ok(outcome)
        }
        None => terminator(module, frame, &block.term),
    }
}

pub(super) fn fault(module: &Module, frame: &Frame, code: String) -> Fault {
    let function = module.func(frame.function);
    Fault {
        code,
        function: function.id,
        block: function.blocks[frame.block.index()].id,
        operation: frame.position.map_or(-1, |position| position as i64),
    }
}
