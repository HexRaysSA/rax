//! Sequential interpreter for the typed IR.
//!
//! Observable behaviour follows chapter 02 and is compared step for step with
//! the Python reference machine: one step commits a block's phis, executes one
//! operation, or executes one terminator. A call's results are bound in the
//! same step as the callee's `return`.
//!
//! Undefined behaviour and traps end execution with a located fault; they are
//! outcomes, not errors. [`run`] returns `Err` only when the entry request
//! itself is unusable.

mod int;

use crate::Error;
use crate::ir::{
    BlockIdx, Callee, CodeRef, FuncIdx, Function, Module, Op, Slot, Terminator, Type, Value,
};

use int::{Arg, Computed};

/// Host limits for one run.
#[derive(Clone, Copy, Debug)]
pub struct Policy {
    /// Maximum number of steps.
    pub fuel: u64,
    /// Maximum call depth.
    pub max_frames: usize,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            fuel: 100_000,
            max_frames: 1024,
        }
    }
}

/// Where and why execution stopped abnormally.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fault {
    pub code: String,
    /// Function and block identifiers as written in the object.
    pub function: u32,
    pub block: u32,
    /// Index of the operation in its block; the block's operation count for
    /// its terminator; -1 while committing phis.
    pub operation: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Exit {
    Return(Vec<Value>),
    /// A defined trap, such as an explicit `trap` terminator.
    Trap(Fault),
    /// The program executed undefined behaviour.
    LanguageUb(Fault),
    /// A host limit from [`Policy`] was reached: `"fuel"` or `"frames"`.
    Resource(&'static str),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub exit: Exit,
    pub steps: u64,
}

struct Frame {
    function: FuncIdx,
    block: BlockIdx,
    predecessor: Option<BlockIdx>,
    /// `None` until the block's phis are committed, then the next operation.
    position: Option<usize>,
    values: Vec<Value>,
    /// Caller slots that receive this activation's results.
    results_to: Vec<Slot>,
}

impl Frame {
    fn new(
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
        }
    }

    fn get(&self, slot: Slot) -> Value {
        self.values[slot.index()]
    }

    fn set(&mut self, slot: Slot, value: Value) {
        self.values[slot.index()] = value;
    }

    fn branch(&mut self, target: BlockIdx) {
        self.predecessor = Some(self.block);
        self.block = target;
        self.position = None;
    }
}

/// What one step asks the driver to do next.
enum Step {
    Continue,
    Call {
        callee: FuncIdx,
        arguments: Vec<Value>,
        results_to: Vec<Slot>,
    },
    Return(Vec<Value>),
    Trap(String),
    LanguageUb(&'static str),
}

fn internal(what: &'static str) -> Error {
    Error::semantic("EXEC_INTERNAL", what)
}

/// An operand of an integer operation, with undef refined to zero.
fn integer(value: Value) -> Result<Arg, Error> {
    match value {
        Value::Int(bits) => Ok(Arg::Bits(bits)),
        Value::DataPtr(address) => Ok(Arg::Bits(u128::from(address))),
        Value::Undef => Ok(Arg::Bits(0)),
        Value::Poison => Ok(Arg::Poison),
        Value::CodeAddress(_) | Value::CodePtr(_) => {
            Err(internal("code value in integer operation"))
        }
    }
}

fn computed(result: Computed) -> Value {
    match result {
        Computed::Bits(bits) => Value::Int(bits),
        Computed::Poison => Value::Poison,
    }
}

/// Whether `value` is a legal runtime value of type `ty`.
fn fits(module: &Module, ty: &Type, value: Value) -> bool {
    match (ty, value) {
        (_, Value::Poison | Value::Undef) => !matches!(ty, Type::Function(_) | Type::Other { .. }),
        (Type::Int { bits }, Value::Int(payload)) => *bits <= 128 && payload <= int::mask(*bits),
        (Type::DataPtr, Value::DataPtr(_)) => true,
        (Type::CodeAddress, Value::CodeAddress(target))
        | (Type::CodePtr { .. }, Value::CodePtr(target)) => match target {
            CodeRef::Function(index) => index.index() < module.functions.len(),
            CodeRef::Originless(_) => true,
        },
        _ => false,
    }
}

fn operation(module: &Module, frame: &mut Frame, op: &Op) -> Result<Step, Error> {
    match op {
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
                return Ok(Step::Trap("code_address_unbound".to_owned()));
            }
            _ => return Err(internal("code_bind operand")),
        },
        Op::CodeErase { dst, src } => match frame.get(*src) {
            Value::CodePtr(target) => frame.set(*dst, Value::CodeAddress(target)),
            Value::Poison | Value::Undef => {
                return Ok(Step::Trap("code_token_invalid".to_owned()));
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
                            return Ok(Step::Trap("code_token_signature".to_owned()));
                        }
                        function
                    }
                    // Undef refines to the null pointer, which like any
                    // originless pointer designates no function.
                    Value::CodePtr(CodeRef::Originless(_)) | Value::Undef => {
                        return Ok(Step::Trap("code_token_invalid".to_owned()));
                    }
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
    }
    Ok(Step::Continue)
}

fn terminator(module: &Module, frame: &mut Frame, term: &Terminator) -> Result<Step, Error> {
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
        Terminator::Trap { reason } => Step::Trap(reason.clone()),
        Terminator::Unreachable => Step::LanguageUb("ub_unreachable"),
    })
}

/// Advance the top frame by one step.
fn step(module: &Module, frame: &mut Frame) -> Result<Step, Error> {
    let block = &module.func(frame.function).blocks[frame.block.index()];
    let Some(position) = frame.position else {
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
        return Ok(Step::Continue);
    };
    match block.ops.get(position) {
        Some(op) => {
            let outcome = operation(module, frame, op)?;
            if matches!(outcome, Step::Continue) {
                frame.position = Some(position + 1);
            }
            Ok(outcome)
        }
        None => terminator(module, frame, &block.term),
    }
}

fn fault(module: &Module, frame: &Frame, code: String) -> Fault {
    let function = module.func(frame.function);
    Fault {
        code,
        function: function.id,
        block: function.blocks[frame.block.index()].id,
        operation: frame.position.map_or(-1, |position| position as i64),
    }
}

/// Run `entry` with `arguments` until it returns, faults, or exhausts `policy`.
///
/// # Errors
///
/// `EXEC_ENTRY` if the arguments do not match the entry function's parameter
/// types in number or shape. `EXEC_INTERNAL` if the module violates an
/// invariant the verifier is relied on to establish; that is a defect in this
/// crate, not a property of the guest program.
pub fn run(
    module: &Module,
    entry: FuncIdx,
    arguments: &[Value],
    policy: Policy,
) -> Result<Outcome, Error> {
    let function = module
        .functions
        .get(entry.index())
        .ok_or_else(|| Error::semantic("EXEC_ENTRY", "unknown entry function"))?;
    let signature = &function.signature;
    if arguments.len() != signature.params.len()
        || !arguments
            .iter()
            .zip(&signature.params)
            .all(|(value, ty)| fits(module, module.ty(*ty), *value))
    {
        return Err(Error::semantic(
            "EXEC_ENTRY",
            "arguments do not match the entry signature",
        ));
    }
    let mut stack = vec![Frame::new(function, entry, arguments, Vec::new())];
    let mut fuel = policy.fuel;
    let mut steps = 0_u64;
    if arguments
        .iter()
        .zip(&signature.param_noundef)
        .any(|(value, noundef)| *noundef && !value.is_well_defined())
    {
        let located = fault(module, &stack[0], "ub_noundef_argument".to_owned());
        return Ok(Outcome {
            exit: Exit::LanguageUb(located),
            steps,
        });
    }
    loop {
        if fuel == 0 {
            return Ok(Outcome {
                exit: Exit::Resource("fuel"),
                steps,
            });
        }
        if stack.len() > policy.max_frames {
            return Ok(Outcome {
                exit: Exit::Resource("frames"),
                steps,
            });
        }
        fuel -= 1;
        steps += 1;
        let frame = stack
            .last_mut()
            .ok_or_else(|| internal("empty call stack"))?;
        let exit = match step(module, frame)? {
            Step::Continue => continue,
            Step::Call {
                callee,
                arguments,
                results_to,
            } => {
                stack.push(Frame::new(
                    module.func(callee),
                    callee,
                    &arguments,
                    results_to,
                ));
                continue;
            }
            Step::Return(values) => {
                let finished = stack.pop().ok_or_else(|| internal("empty call stack"))?;
                let Some(caller) = stack.last_mut() else {
                    return Ok(Outcome {
                        exit: Exit::Return(values),
                        steps,
                    });
                };
                if finished.results_to.len() != values.len() {
                    return Err(internal("call result arity"));
                }
                for (slot, value) in finished.results_to.iter().zip(values) {
                    caller.set(*slot, value);
                }
                caller.position = caller.position.map(|position| position + 1);
                continue;
            }
            Step::Trap(code) => Exit::Trap(fault(module, frame, code)),
            Step::LanguageUb(code) => Exit::LanguageUb(fault(module, frame, code.to_owned())),
        };
        return Ok(Outcome { exit, steps });
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
