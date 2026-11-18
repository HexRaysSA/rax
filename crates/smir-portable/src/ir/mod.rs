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
//! Only scalars are lowered so far: integers, binary32 and binary64 floats,
//! and pointers. A module that uses anything else
//! is refused as a whole with [`ErrorClass::Unimplemented`](crate::ErrorClass):
//! unsupported operations never reach an engine.

mod data;
mod lower;

use std::collections::{BTreeMap, BTreeSet};

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
/// A binary floating-point format the engine computes in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FloatFormat {
    Binary32,
    Binary64,
    Binary128,
}

impl FloatFormat {
    /// Width of the interchange encoding.
    pub fn bits(self) -> u32 {
        match self {
            Self::Binary32 => 32,
            Self::Binary64 => 64,
            Self::Binary128 => 128,
        }
    }

    pub(crate) fn named(name: &str) -> Option<Self> {
        match name {
            "binary32" => Some(Self::Binary32),
            "binary64" => Some(Self::Binary64),
            "binary128" => Some(Self::Binary128),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Type {
    Int {
        bits: u32,
    },
    /// A float; its values are `Value::Int` of the interchange bits.
    Float {
        format: FloatFormat,
    },
    DataPtr,
    CodePtr {
        signature: TypeId,
    },
    CodeAddress,
    Function(Signature),
    Other {
        kind: String,
    },
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

impl CodeRef {
    /// The 64-bit pattern of the code value. A function's token is twice its
    /// one-based position in the module, so tokens are even and never zero.
    /// The token identifies the function only together with its origin.
    pub fn bits(self) -> u64 {
        match self {
            Self::Function(index) => 2 * (u64::from(index.0) + 1),
            Self::Originless(bits) => bits,
        }
    }
}

/// An allocated memory object of one run. Objects are never reused, so the
/// identifier also distinguishes an object from any later one at an
/// overlapping address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectId(pub(crate) u32);

/// A data pointer: an address and the object it may access.
///
/// Access is granted by `origin`, never by the address. A pointer made from
/// an integer or a literal has no origin unless the integer equals an address
/// inside an object whose address was exposed by `ptrtoint`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pointer {
    pub address: u64,
    pub origin: Option<ObjectId>,
}

impl Pointer {
    /// A pointer with no origin. It can be compared and converted but not
    /// dereferenced.
    pub fn originless(address: u64) -> Self {
        Self {
            address,
            origin: None,
        }
    }
}

/// A runtime scalar. Integer width is a property of the static type, so the
/// payload is always zero-extended to 128 bits.
///
/// The layout is fixed, because native code reads and writes values in
/// place: one byte that says which variant this is, at offset 0, and the
/// variant's fields at offset 16, in 32 bytes in all. The variants are
/// numbered as they are written here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C, u8)]
pub enum Value {
    Int(u128) = 0,
    DataPtr(Pointer) = 1,
    /// A non-callable function address.
    CodeAddress(CodeRef) = 2,
    /// A callable code pointer produced by `code_bind`.
    CodePtr(CodeRef) = 3,
    Poison = 4,
    Undef = 5,
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

/// Index of a data segment in [`Module::segments`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SegIdx(pub(crate) u32);

impl SegIdx {
    pub(crate) fn index(self) -> usize {
        self.0 as usize
    }
}

/// The initial image of a data segment: value bits and, per bit, whether the
/// bit is poison or undef. The three have the same length.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Segment {
    pub(crate) alignment: u64,
    pub(crate) mutable: bool,
    pub(crate) bits: Vec<u8>,
    pub(crate) poison: Vec<u8>,
    pub(crate) undef: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelocationKind {
    /// Eight bytes holding a pointer to `target` plus `addend`, with the
    /// target's origin.
    DataAddress { target: SegIdx, addend: i64 },
    /// The address of `target` plus `addend` as an integer in `bytes` bytes.
    /// It has no origin, but the target becomes reachable from integers.
    DataInteger {
        target: SegIdx,
        addend: i64,
        bytes: u32,
    },
    /// Eight bytes holding a callable pointer to `function`.
    FunctionToken { function: FuncIdx },
    /// The token of `function` as an integer of `bits` bits, plus `addend`
    /// modulo two to that power. It has no origin, but the function becomes
    /// reachable from integers.
    FunctionInteger {
        function: FuncIdx,
        addend: i64,
        bits: u32,
    },
}

/// A patch applied to a segment's image before the program starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Relocation {
    pub(crate) segment: SegIdx,
    pub(crate) offset: u64,
    pub(crate) kind: RelocationKind,
}

/// The scalar shape a memory access reads or writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scalar {
    Int {
        bits: u32,
    },
    DataPtr,
    /// A callable code pointer.
    CodePtr,
}

impl Scalar {
    /// Number of value bits; the rest of the accessed bytes is padding.
    pub fn bits(self) -> u32 {
        match self {
            Self::Int { bits } => bits,
            Self::DataPtr | Self::CodePtr => 64,
        }
    }
}

/// A portable runtime service this engine implements, from the catalogs
/// `services-v1.json` and `services-v2.json`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Service {
    /// `file.read(handle, buffer, length) -> (status, bytes)`
    FileRead,
    /// `file.write(handle, buffer, length) -> (status, bytes)`
    FileWrite,
    /// `process.exit(status, mode)`, which does not return.
    ProcessExit,
    /// `process.abort()`, which does not return.
    ProcessAbort,
    /// `clock.now(clock) -> (status, nanoseconds)`
    ClockNow,
    /// `thread.spawn(entry, argument, stack_bytes) -> (status, handle)`
    ThreadSpawn,
    /// `thread.join(thread) -> (status, result)`
    ThreadJoin,
    /// `thread.detach(thread) -> (status, 0)`
    ThreadDetach,
    /// `thread.yield() -> (status, 0)`
    ThreadYield,
    /// `thread.id() -> (status, identity)`
    ThreadId,
    /// `thread.exit(result)`, which does not return.
    ThreadExit,
    /// `sync.wait32(address, expected, timeout_ns) -> (status, 0)`
    SyncWait32,
    /// `sync.wake32(address, count) -> (status, woken)`
    SyncWake32,
    /// `memory.map(bytes, alignment, permissions) -> (status, base)`
    MemoryMap,
    /// `memory.unmap(address, bytes) -> (status, 0)`
    MemoryUnmap,
    /// `memory.protect(address, bytes, permissions) -> (status, 0)`
    MemoryProtect,
    /// `file.open(path, length, flags, mode) -> (status, handle)`
    FileOpen,
    /// `file.close(handle) -> (status, 0)`
    FileClose,
    /// `file.seek(handle, offset, whence) -> (status, position)`
    FileSeek,
    /// `file.unlink(path, length) -> (status, 0)`
    FileUnlink,
    /// `file.rename(source, source_length, destination,
    /// destination_length) -> (status, 0)`
    FileRename,
    /// `thread.concurrency() -> (status, count)`
    ThreadConcurrency,
}

impl Service {
    pub const ALL: [Self; 22] = [
        Self::FileRead,
        Self::FileWrite,
        Self::ProcessExit,
        Self::ProcessAbort,
        Self::ClockNow,
        Self::ThreadSpawn,
        Self::ThreadJoin,
        Self::ThreadDetach,
        Self::ThreadYield,
        Self::ThreadId,
        Self::ThreadExit,
        Self::SyncWait32,
        Self::SyncWake32,
        Self::MemoryMap,
        Self::MemoryUnmap,
        Self::MemoryProtect,
        Self::FileOpen,
        Self::FileClose,
        Self::FileSeek,
        Self::FileUnlink,
        Self::FileRename,
        Self::ThreadConcurrency,
    ];

    /// The service's name in the catalog.
    pub fn name(self) -> &'static str {
        match self {
            Self::FileRead => "file.read",
            Self::FileWrite => "file.write",
            Self::ProcessExit => "process.exit",
            Self::ProcessAbort => "process.abort",
            Self::ClockNow => "clock.now",
            Self::ThreadSpawn => "thread.spawn",
            Self::ThreadJoin => "thread.join",
            Self::ThreadDetach => "thread.detach",
            Self::ThreadYield => "thread.yield",
            Self::ThreadId => "thread.id",
            Self::ThreadExit => "thread.exit",
            Self::SyncWait32 => "sync.wait32",
            Self::SyncWake32 => "sync.wake32",
            Self::MemoryMap => "memory.map",
            Self::MemoryUnmap => "memory.unmap",
            Self::MemoryProtect => "memory.protect",
            Self::FileOpen => "file.open",
            Self::FileClose => "file.close",
            Self::FileSeek => "file.seek",
            Self::FileUnlink => "file.unlink",
            Self::FileRename => "file.rename",
            Self::ThreadConcurrency => "thread.concurrency",
        }
    }

    pub(crate) fn named(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|service| service.name() == name)
    }
}

/// What an atomic read-modify-write stores, from the old value and its
/// operand.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RmwAction {
    /// The operand itself.
    Exchange,
    Add,
    Sub,
    And,
    Nand,
    Or,
    Xor,
    Min,
    Max,
    UMin,
    UMax,
}

/// What an ordered comparison of two floats asks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FloatRelation {
    False,
    True,
    /// Neither operand is a NaN.
    Ordered,
    /// Either operand is a NaN.
    Unordered,
    Equal,
    NotEqual,
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
}

/// A floating-point operation in the default environment: round to nearest
/// with ties to even, no exception observable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FloatOp {
    Add,
    Sub,
    Mul,
    Div,
    /// The remainder of truncating division, as C's `fmod`.
    Rem,
    /// `a * b + c` rounded once.
    Fma,
    Sqrt,
    Neg,
    Abs,
    CopySign,
    Minimum,
    Maximum,
    MinNum,
    MaxNum,
    MinimumNum,
    MaximumNum,
    /// The result is 1 if `relation` holds, or if `unordered` is set and
    /// either operand is a NaN.
    Compare {
        relation: FloatRelation,
        unordered: bool,
    },
    /// From a signed or unsigned integer of `bits` bits.
    FromSigned {
        bits: u32,
    },
    FromUnsigned {
        bits: u32,
    },
    /// To an integer of `bits` bits, truncating toward zero. A NaN or a
    /// value out of range is poison, unless `saturating`.
    ToSigned {
        bits: u32,
        saturating: bool,
    },
    ToUnsigned {
        bits: u32,
        saturating: bool,
    },
    /// To another format.
    Convert {
        to: FloatFormat,
    },
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
    /// Operands are both integers of `bits` width or both data pointers,
    /// which compare by their 64-bit addresses.
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
    /// Address of the data segment a data symbol is defined by.
    AddressOfData {
        dst: Slot,
        segment: SegIdx,
    },
    /// Copy `count` bytes, shadow and pointer fragments included. Without
    /// `overlapping` (`memcpy`), partially overlapping ranges are undefined.
    MemCopy {
        dst: Slot,
        src: Slot,
        count: Slot,
        alignment: u32,
        overlapping: bool,
    },
    /// Set `count` bytes to the 8-bit `value`.
    MemSet {
        dst: Slot,
        value: Slot,
        count: Slot,
        alignment: u32,
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
    /// Replace the scalar at `ptr` by `action` of it and `value`; `dst` is
    /// the value that was there.
    AtomicRmw {
        dst: Slot,
        ptr: Slot,
        value: Slot,
        action: RmwAction,
        kind: Scalar,
        bytes: u32,
        alignment: u32,
    },
    /// Store `replacement` at `ptr` if the scalar there equals `expected`.
    /// `old` is the value that was there and `success` whether it was
    /// replaced.
    CompareExchange {
        old: Slot,
        success: Slot,
        ptr: Slot,
        expected: Slot,
        replacement: Slot,
        kind: Scalar,
        bytes: u32,
        alignment: u32,
    },
    /// An ordering barrier between threads; nothing to do on one.
    Fence,
    /// A floating-point operation. `format` is the format of the float
    /// operands, or of the result when the operands are integers.
    Float {
        dst: Slot,
        op: FloatOp,
        format: FloatFormat,
        args: Vec<Slot>,
    },
    /// Call a runtime service. The operands and results are those of its
    /// catalog signature, which the verifier checked.
    Service {
        dsts: Vec<Slot>,
        service: Service,
        args: Vec<Slot>,
    },
    /// Read `bytes` bytes at `ptr` as a scalar of `kind`.
    Load {
        dst: Slot,
        ptr: Slot,
        kind: Scalar,
        bytes: u32,
        alignment: u32,
    },
    /// Write `value`, a scalar of `kind`, as `bytes` bytes at `ptr`.
    Store {
        ptr: Slot,
        value: Slot,
        kind: Scalar,
        bytes: u32,
        alignment: u32,
    },
    /// `ptr` moved by the signed 64-bit `delta`. A violated flag makes the
    /// result poison.
    PtrOffset {
        dst: Slot,
        ptr: Slot,
        delta: Slot,
        inbounds: bool,
        check_base: bool,
        nuw: bool,
        nusw: bool,
    },
    /// A new object of `size` bytes owned by the current activation.
    Alloca {
        dst: Slot,
        size: Slot,
        alignment: u64,
    },
    /// Begin (`start`) or end the lifetime of `size` bytes at `ptr`.
    Lifetime {
        ptr: Slot,
        size: Slot,
        start: bool,
    },
    /// The address of a pointer as an integer of `bits` width. With `expose`
    /// (`ptrtoint`) the object may later be reached from an integer.
    PtrToInt {
        dst: Slot,
        src: Slot,
        bits: u32,
        expose: bool,
    },
    IntToPtr {
        dst: Slot,
        src: Slot,
    },
    /// The token of a code pointer as an integer of `bits` width. With
    /// `expose` (`ptrtoint`) the function may later be reached from an
    /// integer.
    CodeToInt {
        dst: Slot,
        src: Slot,
        bits: u32,
        expose: bool,
    },
    /// The code pointer an integer names: the function whose token it is, if
    /// that function has been exposed.
    IntToCode {
        dst: Slot,
        src: Slot,
    },
    /// The address `offset` bytes into the calling thread's copy of a
    /// thread-local segment.
    TlsAddress {
        dst: Slot,
        segment: u32,
        offset: Slot,
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
    /// The types by their identifiers in the object.
    pub(crate) type_ids: BTreeMap<u32, TypeId>,
    pub(crate) functions: Vec<Function>,
    pub(crate) function_ids: BTreeMap<u32, FuncIdx>,
    /// Data segments, in identifier order; each becomes one memory object.
    pub(crate) segments: Vec<Segment>,
    pub(crate) relocations: Vec<Relocation>,
    /// Thread-local segments: the image each thread's copy starts from.
    pub(crate) thread_local: Vec<Segment>,
    /// Functions that a symbol with strong or weak binding names, by name.
    pub(crate) exports: BTreeMap<String, FuncIdx>,
    /// Capabilities the module declares it needs. A run must be granted all
    /// of them.
    pub(crate) capabilities: BTreeSet<String>,
    /// Functions that run before the program's entry, in this order.
    pub(crate) initializers: Vec<FuncIdx>,
    /// Functions that run after the program ends normally, in this order.
    pub(crate) finalizers: Vec<FuncIdx>,
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

    /// Look up a function by the name of the symbol that exports it.
    pub fn export(&self, name: &str) -> Option<FuncIdx> {
        self.exports.get(name).copied()
    }

    /// The capabilities the module declares it needs, in sorted order.
    pub fn capabilities(&self) -> impl Iterator<Item = &str> + '_ {
        self.capabilities.iter().map(String::as_str)
    }

    /// Look up a type by its identifier in the object.
    pub fn type_by_id(&self, id: u32) -> Option<TypeId> {
        self.type_ids.get(&id).copied()
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
