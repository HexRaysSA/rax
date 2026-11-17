//! Typed in-memory form of a statically verified portable SMIR module.
//!
//! The decoder and verifier work on ordered records keyed by field name. An
//! interpreter cannot run on that representation, so [`Module::load`] verifies
//! an object and then lowers it once into the dense, typed structures here.
//!
//! Every [`TypeId`], [`FuncIdx`], [`BlockIdx`] and [`Slot`] stored in a
//! [`Module`] is range-checked when lowering creates it, and the fields that
//! hold them are not publicly constructible. Code that walks a `Module` may
//! therefore index with them directly.
//!
//! Only the scalar subset is lowered so far. A module that uses anything else
//! is refused as a whole with [`ErrorClass::Unimplemented`](crate::ErrorClass):
//! unsupported operations never reach an engine.

mod lower;

use std::collections::BTreeMap;

use crate::{Error, Limits};

/// Widest integer the engine evaluates. The format allows up to 2^23 bits.
pub const MAX_INT_BITS: u32 = 128;

/// Index of a type in [`Module::types`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TypeId(pub(crate) u32);

/// Index of a function in [`Module::functions`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FuncIdx(pub(crate) u32);

/// Index of a block within its function.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlockIdx(pub(crate) u32);

/// Dense index of an SSA value within its function's activation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Slot(pub(crate) u32);

impl TypeId {
    pub(crate) fn index(self) -> usize {
        self.0 as usize
    }
}

impl FuncIdx {
    pub(crate) fn index(self) -> usize {
        self.0 as usize
    }
}

impl BlockIdx {
    pub(crate) fn index(self) -> usize {
        self.0 as usize
    }
}

impl Slot {
    pub(crate) fn index(self) -> usize {
        self.0 as usize
    }
}

/// A value type. Kinds outside the scalar subset are kept by name so that a
/// module may declare them, but no function body may use them yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Type {
    Int { bits: u32 },
    DataPtr,
    CodePtr { signature: TypeId },
    CodeAddress,
    Function(Signature),
    Other { kind: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    pub(crate) params: Vec<TypeId>,
    pub(crate) results: Vec<TypeId>,
    pub(crate) param_noundef: Vec<bool>,
    pub(crate) result_noundef: Vec<bool>,
    pub(crate) variadic: bool,
    pub(crate) portable_cc: bool,
}

impl Signature {
    pub fn params(&self) -> &[TypeId] {
        &self.params
    }
    pub fn results(&self) -> &[TypeId] {
        &self.results
    }
}

/// What a code value designates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodeRef {
    /// A function of this module, obtained from `address_of`.
    Function(FuncIdx),
    /// Bits from a literal. They carry no origin and can never be bound or
    /// called, even when they equal a real function's address.
    Originless(u64),
}

/// A runtime scalar. Integer width is a property of the static type, so the
/// payload is always zero-extended to 128 bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Value {
    Int(u128),
    /// A data pointer. Only its address is modelled so far; there is no
    /// provenance and no memory behind it.
    DataPtr(u64),
    /// A non-callable function address.
    CodeAddress(CodeRef),
    /// A callable code pointer produced by `code_bind`.
    CodePtr(CodeRef),
    Poison,
    Undef,
}

impl Value {
    /// Neither poison nor undef. `noundef` positions require this.
    pub fn is_well_defined(self) -> bool {
        !matches!(self, Self::Poison | Self::Undef)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntBinary {
    Add,
    Sub,
    Mul,
    UDiv,
    SDiv,
    URem,
    SRem,
    Shl,
    LShr,
    AShr,
    And,
    Or,
    Xor,
    RotL,
    RotR,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntUnary {
    Clz,
    Ctz,
    Popcount,
    Abs,
    Bswap,
    BitReverse,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IntFlags {
    pub nsw: bool,
    pub nuw: bool,
    pub exact: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Predicate {
    Eq,
    Ne,
    Ult,
    Ule,
    Ugt,
    Uge,
    Slt,
    Sle,
    Sgt,
    Sge,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cast {
    Trunc,
    Zext,
    Sext,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Callee {
    Direct(FuncIdx),
    /// The value must be a bound code pointer whose function has `signature`.
    Indirect {
        value: Slot,
        signature: TypeId,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op {
    Const {
        dst: Slot,
        value: Value,
    },
    Copy {
        dst: Slot,
        src: Slot,
    },
    /// `zero` is the value a poison or undef operand freezes to.
    Freeze {
        dst: Slot,
        src: Slot,
        zero: Value,
    },
    IntBinary {
        dst: Slot,
        op: IntBinary,
        bits: u32,
        flags: IntFlags,
        lhs: Slot,
        rhs: Slot,
    },
    IntUnary {
        dst: Slot,
        op: IntUnary,
        bits: u32,
        zero_is_poison: bool,
        src: Slot,
    },
    /// Operands are both integers of `bits` width or both data pointers
    /// (`bits` is then 64 and only `Eq`/`Ne` are admitted).
    Icmp {
        dst: Slot,
        pred: Predicate,
        bits: u32,
        lhs: Slot,
        rhs: Slot,
    },
    Select {
        dst: Slot,
        cond: Slot,
        if_true: Slot,
        if_false: Slot,
    },
    Cast {
        dst: Slot,
        op: Cast,
        from_bits: u32,
        to_bits: u32,
        src: Slot,
    },
    /// Address of a function symbol, as a callable pointer or a bare address.
    AddressOf {
        dst: Slot,
        function: FuncIdx,
        callable: bool,
    },
    CodeBind {
        dst: Slot,
        src: Slot,
    },
    CodeErase {
        dst: Slot,
        src: Slot,
    },
    Call {
        dsts: Vec<Slot>,
        callee: Callee,
        args: Vec<Slot>,
        /// Per-argument `noundef` from the call's signature.
        arg_noundef: Vec<bool>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Terminator {
    Return(Vec<Slot>),
    Jump(BlockIdx),
    Branch {
        cond: Slot,
        if_true: BlockIdx,
        if_false: BlockIdx,
    },
    Switch {
        index: Slot,
        cases: Vec<(u128, BlockIdx)>,
        default: BlockIdx,
    },
    Trap {
        reason: String,
    },
    Unreachable,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Phi {
    pub(crate) dst: Slot,
    /// One entry per predecessor block.
    pub(crate) incoming: Vec<(BlockIdx, Slot)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    /// Identifier from the object, used only in fault reports.
    pub(crate) id: u32,
    pub(crate) phis: Vec<Phi>,
    pub(crate) ops: Vec<Op>,
    pub(crate) term: Terminator,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Function {
    /// Identifier from the object.
    pub(crate) id: u32,
    /// The function type, and a copy of what it describes.
    pub(crate) signature_type: TypeId,
    pub(crate) signature: Signature,
    pub(crate) params: Vec<Slot>,
    pub(crate) entry: BlockIdx,
    pub(crate) blocks: Vec<Block>,
    /// Number of SSA value slots an activation needs.
    pub(crate) slots: u32,
}

impl Function {
    pub fn id(&self) -> u32 {
        self.id
    }
}

/// A verified module in executable form.
#[derive(Clone, Debug)]
pub struct Module {
    pub(crate) identity: [u8; 32],
    pub(crate) types: Vec<Type>,
    pub(crate) functions: Vec<Function>,
    pub(crate) function_ids: BTreeMap<u32, FuncIdx>,
}

impl Module {
    /// Decode and statically verify `bytes`, then lower the object.
    ///
    /// Fails with the verifier's error if the object is not a valid module, and
    /// with class `Unimplemented` if it is valid but uses constructs this
    /// engine does not execute yet.
    pub fn load(bytes: &[u8], limits: Limits) -> Result<Self, Error> {
        let verified = crate::admission::verify_for_execution(bytes, limits)?;
        lower::lower(verified.requirements().parsed())
    }

    /// SHA-256 content identity of the object this module was loaded from.
    pub fn identity(&self) -> [u8; 32] {
        self.identity
    }

    /// Look up a function by its identifier in the object.
    pub fn function(&self, id: u32) -> Option<FuncIdx> {
        self.function_ids.get(&id).copied()
    }

    pub fn function_ids(&self) -> impl Iterator<Item = u32> + '_ {
        self.function_ids.keys().copied()
    }

    pub fn ty(&self, id: TypeId) -> &Type {
        &self.types[id.index()]
    }

    pub(crate) fn func(&self, index: FuncIdx) -> &Function {
        &self.functions[index.index()]
    }

    pub fn signature(&self, index: FuncIdx) -> &Signature {
        &self.func(index).signature
    }

    /// Structural type equality: distinct identifiers that describe the same
    /// type are equal.
    pub fn same_type(&self, left: TypeId, right: TypeId) -> bool {
        lower::structurally_equal(&self.types, left, right)
    }
}

#[cfg(test)]
mod tests;
