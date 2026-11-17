//! Lowering from verified ordered records to the typed IR.
//!
//! The object has already passed static verification, so a shape mismatch
//! found here means the verifier and this lowering disagree; it is reported as
//! `EXEC_LOWER` instead of being trusted. Constructs that are valid but not
//! executed yet are reported as `EXEC_UNIMPLEMENTED` and refuse the module.

use std::collections::BTreeMap;

use crate::context::{boolean, bytes, field, list, optional, text, unsigned};
use crate::wire::{ParsedObject, RecordValue};
use crate::{Error, ErrorClass};

use super::{
    Block, BlockIdx, Callee, Cast, CodeRef, FuncIdx, Function, IntBinary, IntFlags, IntUnary,
    MAX_INT_BITS, Module, Op, Phi, Pointer, Predicate, Scalar, Signature, Slot, Terminator, Type,
    TypeId, Value,
};

fn unimplemented(what: impl Into<String>) -> Error {
    Error::new(ErrorClass::Unimplemented, "EXEC_UNIMPLEMENTED", what)
}

fn malformed(what: impl Into<String>) -> Error {
    Error::semantic("EXEC_LOWER", what)
}

fn require(condition: bool, what: &str) -> Result<(), Error> {
    if condition {
        Ok(())
    } else {
        Err(malformed(what))
    }
}

fn number(record: &RecordValue, name: &str) -> Result<u32, Error> {
    u32::try_from(unsigned(field(record, name)?)?).map_err(|_| malformed(name))
}

fn token<'a>(record: &'a RecordValue, name: &str) -> Result<&'a str, Error> {
    text(field(record, name)?)
}

fn items<'a>(record: &'a RecordValue, name: &str) -> Result<&'a [RecordValue], Error> {
    list(field(record, name)?)
}

fn flag(record: &RecordValue, name: &str) -> Result<bool, Error> {
    boolean(field(record, name)?)
}

/// Identifier of an entity reference that names this module.
fn local(reference: &RecordValue) -> Result<u32, Error> {
    match token(field(reference, "module")?, "kind")? {
        "self" => number(reference, "id"),
        "dependency" => Err(unimplemented("reference to a dependency module")),
        _ => Err(malformed("module reference kind")),
    }
}

fn index_of(count: usize) -> Result<u32, Error> {
    u32::try_from(count).map_err(|_| malformed("index space exhausted"))
}

/// Little-endian bytes as an unsigned integer that fits `bits`.
fn little_endian(source: &[u8], bits: u32) -> Result<u128, Error> {
    require(source.len() <= 16, "literal wider than 128 bits")?;
    let mut value = 0_u128;
    for (position, byte) in source.iter().enumerate() {
        value |= u128::from(*byte) << (8 * position);
    }
    require(
        bits >= 128 || value >> bits == 0,
        "literal exceeds its type width",
    )?;
    Ok(value)
}

struct Types {
    list: Vec<Type>,
    by_id: BTreeMap<u32, TypeId>,
}

impl Types {
    fn lower(root: &RecordValue) -> Result<Self, Error> {
        let records = items(root, "types")?;
        let mut by_id = BTreeMap::new();
        for (position, record) in records.iter().enumerate() {
            let previous = by_id.insert(number(record, "id")?, TypeId(index_of(position)?));
            require(previous.is_none(), "duplicate type identifier")?;
        }
        let resolve = |reference: &RecordValue| -> Result<TypeId, Error> {
            by_id
                .get(&local(reference)?)
                .copied()
                .ok_or_else(|| malformed("unknown type"))
        };
        let mut lowered = Vec::with_capacity(records.len());
        for record in records {
            lowered.push(match token(record, "kind")? {
                "int" => Type::Int {
                    bits: number(record, "bits")?,
                },
                "data_ptr" if token(record, "space")? == "guest_data" => Type::DataPtr,
                "code_ptr" => Type::CodePtr {
                    signature: resolve(field(record, "signature")?)?,
                },
                "code_address" => Type::CodeAddress,
                "function" => {
                    let bools = |name: &str| -> Result<Vec<bool>, Error> {
                        items(record, name)?.iter().map(boolean).collect()
                    };
                    let refs = |name: &str| -> Result<Vec<TypeId>, Error> {
                        items(record, name)?.iter().map(&resolve).collect()
                    };
                    let signature = Signature {
                        params: refs("params")?,
                        results: refs("results")?,
                        param_noundef: bools("param_noundef")?,
                        result_noundef: bools("result_noundef")?,
                        variadic: flag(record, "variadic")?,
                        portable_cc: token(record, "cc")? == "portable",
                    };
                    require(
                        signature.params.len() == signature.param_noundef.len()
                            && signature.results.len() == signature.result_noundef.len(),
                        "function type noundef arity",
                    )?;
                    Type::Function(signature)
                }
                kind => Type::Other {
                    kind: kind.to_owned(),
                },
            });
        }
        Ok(Self {
            list: lowered,
            by_id,
        })
    }

    fn resolve(&self, reference: &RecordValue) -> Result<TypeId, Error> {
        self.by_id
            .get(&local(reference)?)
            .copied()
            .ok_or_else(|| malformed("unknown type"))
    }

    fn get(&self, id: TypeId) -> &Type {
        &self.list[id.index()]
    }

    /// The type as a scalar this engine executes, or why it is refused.
    fn scalar(&self, id: TypeId) -> Result<&Type, Error> {
        match self.get(id) {
            Type::Int { bits } if *bits > MAX_INT_BITS => Err(unimplemented(format!(
                "integer wider than {MAX_INT_BITS} bits"
            ))),
            Type::Function(_) => Err(malformed("function type used as a value")),
            Type::Other { kind } => Err(unimplemented(format!("value type {kind}"))),
            scalar => Ok(scalar),
        }
    }

    fn int_bits(&self, id: TypeId) -> Result<u32, Error> {
        match self.scalar(id)? {
            Type::Int { bits } => Ok(*bits),
            _ => Err(malformed("integer type expected")),
        }
    }

    fn function(&self, id: TypeId) -> Result<&Signature, Error> {
        match self.get(id) {
            Type::Function(signature) if signature.variadic => {
                Err(unimplemented("variadic function"))
            }
            Type::Function(signature) if !signature.portable_cc => {
                Err(unimplemented("non-portable calling convention"))
            }
            Type::Function(signature) => Ok(signature),
            _ => Err(malformed("function type expected")),
        }
    }

    /// The value a poison or undef operand of this type freezes to.
    fn zero(&self, id: TypeId) -> Result<Value, Error> {
        Ok(match self.scalar(id)? {
            Type::Int { .. } => Value::Int(0),
            Type::DataPtr => Value::DataPtr(Pointer::originless(0)),
            Type::CodeAddress => Value::CodeAddress(CodeRef::Originless(0)),
            Type::CodePtr { .. } => Value::CodePtr(CodeRef::Originless(0)),
            Type::Function(_) | Type::Other { .. } => return Err(malformed("scalar expected")),
        })
    }

    fn same(&self, left: TypeId, right: TypeId) -> bool {
        structurally_equal(&self.list, left, right)
    }
}

/// Structural equality over a type table. Distinct identifiers that describe
/// the same type are equal. Function and code pointer types may refer to each
/// other cyclically, so pairs already under comparison are assumed equal.
fn same_type(
    types: &[Type],
    left: TypeId,
    right: TypeId,
    assumed: &mut Vec<(TypeId, TypeId)>,
) -> bool {
    if left == right || assumed.contains(&(left, right)) {
        return true;
    }
    match (&types[left.index()], &types[right.index()]) {
        (Type::Int { bits: a }, Type::Int { bits: b }) => a == b,
        (Type::DataPtr, Type::DataPtr) | (Type::CodeAddress, Type::CodeAddress) => true,
        (Type::CodePtr { signature: a }, Type::CodePtr { signature: b }) => {
            assumed.push((left, right));
            same_type(types, *a, *b, assumed)
        }
        (Type::Function(a), Type::Function(b)) => {
            if a.params.len() != b.params.len()
                || a.results.len() != b.results.len()
                || a.param_noundef != b.param_noundef
                || a.result_noundef != b.result_noundef
                || a.variadic != b.variadic
                || a.portable_cc != b.portable_cc
            {
                return false;
            }
            assumed.push((left, right));
            a.params
                .iter()
                .zip(&b.params)
                .chain(a.results.iter().zip(&b.results))
                .all(|(x, y)| same_type(types, *x, *y, assumed))
        }
        _ => false,
    }
}

pub(super) fn structurally_equal(types: &[Type], left: TypeId, right: TypeId) -> bool {
    same_type(types, left, right, &mut Vec::new())
}

/// How a type is laid out in memory, from the object's `memory_layouts`.
struct Layout {
    ty: TypeId,
    access_bytes: u64,
    /// No fields and no element: the layout of a scalar.
    scalar: bool,
}

fn layouts(root: &RecordValue, types: &Types) -> Result<BTreeMap<u32, Layout>, Error> {
    let mut result = BTreeMap::new();
    for record in items(root, "memory_layouts")? {
        let layout = Layout {
            ty: types.resolve(field(record, "type")?)?,
            access_bytes: unsigned(field(record, "access_bytes")?)?,
            scalar: items(record, "fields")?.is_empty()
                && optional(field(record, "element")?)?.is_none(),
        };
        let previous = result.insert(number(record, "id")?, layout);
        require(previous.is_none(), "duplicate memory layout identifier")?;
    }
    Ok(result)
}

/// Names of the imported internal runtime helpers, by import identifier.
fn helpers(root: &RecordValue) -> Result<BTreeMap<u32, String>, Error> {
    let mut result = BTreeMap::new();
    for record in items(root, "imports")? {
        if token(record, "kind")? == "internal"
            && text(field(record, "namespace")?)? == "smir.internal.v1"
        {
            result.insert(number(record, "id")?, token(record, "name")?.to_owned());
        }
    }
    Ok(result)
}

/// Function symbols that are defined by a function of this module.
fn function_symbols(root: &RecordValue) -> Result<BTreeMap<u32, u32>, Error> {
    let mut result = BTreeMap::new();
    for symbol in items(root, "symbols")? {
        if token(symbol, "kind")? != "function" {
            continue;
        }
        let Some(definition) = optional(field(symbol, "definition")?)? else {
            continue;
        };
        if token(definition, "kind")? == "function" {
            result.insert(number(symbol, "id")?, local(field(definition, "target")?)?);
        }
    }
    Ok(result)
}

struct Body<'a> {
    types: &'a Types,
    functions: &'a BTreeMap<u32, FuncIdx>,
    signatures: &'a [TypeId],
    symbols: &'a BTreeMap<u32, u32>,
    layouts: &'a BTreeMap<u32, Layout>,
    helpers: &'a BTreeMap<u32, String>,
    data_symbols: &'a BTreeMap<u32, super::SegIdx>,
    slots: BTreeMap<u32, (Slot, TypeId)>,
    blocks: BTreeMap<u32, BlockIdx>,
}

impl Body<'_> {
    fn declare(&mut self, declaration: &RecordValue) -> Result<Slot, Error> {
        let ty = self.types.resolve(field(declaration, "type")?)?;
        self.types.scalar(ty)?;
        let slot = Slot(index_of(self.slots.len())?);
        let previous = self.slots.insert(number(declaration, "id")?, (slot, ty));
        require(previous.is_none(), "duplicate value identifier")?;
        Ok(slot)
    }

    fn value(&self, record: &RecordValue) -> Result<(Slot, TypeId), Error> {
        let id = u32::try_from(unsigned(record)?).map_err(|_| malformed("value identifier"))?;
        self.slots
            .get(&id)
            .copied()
            .ok_or_else(|| malformed("undeclared value"))
    }

    fn named(&self, record: &RecordValue, name: &str) -> Result<(Slot, TypeId), Error> {
        self.value(field(record, name)?)
    }

    fn block(&self, record: &RecordValue, name: &str) -> Result<BlockIdx, Error> {
        self.blocks
            .get(&number(record, name)?)
            .copied()
            .ok_or_else(|| malformed("unknown block"))
    }

    fn function(&self, reference: &RecordValue) -> Result<FuncIdx, Error> {
        self.functions
            .get(&local(reference)?)
            .copied()
            .ok_or_else(|| malformed("unknown function"))
    }

    /// The declared result slots of an operation, in order.
    fn results(&self, operation: &RecordValue) -> Result<Vec<(Slot, TypeId)>, Error> {
        items(operation, "results")?
            .iter()
            .map(|declaration| self.value(field(declaration, "id")?))
            .collect()
    }

    fn operands(&self, operation: &RecordValue) -> Result<Vec<(Slot, TypeId)>, Error> {
        items(operation, "operands")?
            .iter()
            .map(|value| self.value(value))
            .collect()
    }

    fn literal(&self, literal: &RecordValue, ty: TypeId) -> Result<Value, Error> {
        match token(literal, "kind")? {
            "zero" => self.types.zero(ty),
            "poison" => Ok(Value::Poison),
            "undef" => Ok(Value::Undef),
            "bits" => {
                let source = bytes(field(literal, "value")?)?;
                Ok(match self.types.scalar(ty)? {
                    Type::Int { bits } => Value::Int(little_endian(source, *bits)?),
                    pointer => {
                        let address = u64::try_from(little_endian(source, 64)?)
                            .map_err(|_| malformed("pointer literal"))?;
                        match pointer {
                            Type::DataPtr => Value::DataPtr(Pointer::originless(address)),
                            Type::CodeAddress => Value::CodeAddress(CodeRef::Originless(address)),
                            _ => Value::CodePtr(CodeRef::Originless(address)),
                        }
                    }
                })
            }
            "aggregate" => Err(unimplemented("aggregate literal")),
            _ => Err(malformed("literal kind")),
        }
    }

    /// The scalar shape, byte count, alignment and value type of a plain
    /// (non-atomic, non-volatile) memory access.
    fn access(&self, operation: &RecordValue) -> Result<(Scalar, u32, u32, TypeId), Error> {
        let storage = field(operation, "storage")?;
        let ty = self.types.resolve(field(storage, "type")?)?;
        if optional(field(storage, "nominal")?)?.is_some() {
            return Err(unimplemented("memory access bound to a source object"));
        }
        let layout = self
            .layouts
            .get(&local(field(storage, "layout")?)?)
            .ok_or_else(|| malformed("unknown memory layout"))?;
        require(self.types.same(layout.ty, ty), "storage layout type")?;
        let bytes = unsigned(field(storage, "bytes")?)?;
        require(bytes == layout.access_bytes, "storage extent")?;
        let kind = match self.types.scalar(ty)? {
            Type::Int { bits } => Scalar::Int { bits: *bits },
            Type::DataPtr => Scalar::DataPtr,
            _ => return Err(unimplemented("code pointer in memory")),
        };
        if !layout.scalar {
            return Err(unimplemented("aggregate memory access"));
        }
        require(
            bytes * 8 >= u64::from(kind.bits()) && bytes <= 16,
            "scalar storage extent",
        )?;
        let mode = field(operation, "mode")?;
        if flag(mode, "volatile")? {
            return Err(unimplemented("volatile memory access"));
        }
        if flag(mode, "elementwise")? {
            return Err(unimplemented("elementwise memory access"));
        }
        if token(mode, "order")? != "none" {
            return Err(unimplemented("ordered memory access"));
        }
        let alignment = number(mode, "alignment")?;
        require(alignment.is_power_of_two(), "access alignment")?;
        let bytes = u32::try_from(bytes).map_err(|_| malformed("storage extent"))?;
        Ok((kind, bytes, alignment, ty))
    }

    /// Check that a helper operation calls the internal runtime helper `name`.
    fn helper(&self, operation: &RecordValue, name: &str) -> Result<(), Error> {
        let target = field(operation, "helper")?;
        require(token(target, "kind")? == "import", "helper target")?;
        let import = local(field(target, "import")?)?;
        require(
            self.helpers.get(&import).map(String::as_str) == Some(name),
            "helper import",
        )?;
        if optional(field(operation, "binding")?)?.is_some() {
            return Err(unimplemented("helper bound to a source object"));
        }
        Ok(())
    }

    fn data_ptr(&self, ty: TypeId, what: &str) -> Result<(), Error> {
        require(matches!(self.types.scalar(ty)?, Type::DataPtr), what)
    }

    fn operation(&self, operation: &RecordValue) -> Result<Op, Error> {
        let name = token(operation, "op")?;
        let results = self.results(operation)?;
        let operands = self.operands(operation)?;
        let one_result = || -> Result<(Slot, TypeId), Error> {
            require(results.len() == 1, "single result expected")?;
            Ok(results[0])
        };
        let arity = |count: usize| require(operands.len() == count, "operand count");
        if let Some(action) = name.strip_prefix("i_") {
            let (dst, ty) = one_result()?;
            let bits = self.types.int_bits(ty)?;
            let binary = match action {
                "add" => Some(IntBinary::Add),
                "sub" => Some(IntBinary::Sub),
                "mul" => Some(IntBinary::Mul),
                "udiv" => Some(IntBinary::UDiv),
                "sdiv" => Some(IntBinary::SDiv),
                "urem" => Some(IntBinary::URem),
                "srem" => Some(IntBinary::SRem),
                "shl" => Some(IntBinary::Shl),
                "lshr" => Some(IntBinary::LShr),
                "ashr" => Some(IntBinary::AShr),
                "and" => Some(IntBinary::And),
                "or" => Some(IntBinary::Or),
                "xor" => Some(IntBinary::Xor),
                "rotl" => Some(IntBinary::RotL),
                "rotr" => Some(IntBinary::RotR),
                _ => None,
            };
            if let Some(op) = binary {
                arity(2)?;
                require(
                    self.types.same(operands[0].1, ty) && self.types.same(operands[1].1, ty),
                    "integer operand type",
                )?;
                let mut flags = IntFlags::default();
                for item in items(operation, "flags")? {
                    match text(item)? {
                        "nsw" => flags.nsw = true,
                        "nuw" => flags.nuw = true,
                        "exact" => flags.exact = true,
                        _ => return Err(malformed("integer flag")),
                    }
                }
                let wrap = matches!(
                    op,
                    IntBinary::Add | IntBinary::Sub | IntBinary::Mul | IntBinary::Shl
                );
                let exact = matches!(
                    op,
                    IntBinary::UDiv | IntBinary::SDiv | IntBinary::LShr | IntBinary::AShr
                );
                require(
                    (wrap || !(flags.nsw || flags.nuw)) && (exact || !flags.exact),
                    "flag not valid for operation",
                )?;
                return Ok(Op::IntBinary {
                    dst,
                    op,
                    bits,
                    flags,
                    lhs: operands[0].0,
                    rhs: operands[1].0,
                });
            }
            let op = match action {
                "clz" => IntUnary::Clz,
                "ctz" => IntUnary::Ctz,
                "popcount" => IntUnary::Popcount,
                "abs" => IntUnary::Abs,
                "bswap" => IntUnary::Bswap,
                "bitreverse" => IntUnary::BitReverse,
                _ => return Err(malformed("integer operation")),
            };
            arity(1)?;
            require(self.types.same(operands[0].1, ty), "integer operand type")?;
            require(op != IntUnary::Bswap || bits % 8 == 0, "byte swap width")?;
            return Ok(Op::IntUnary {
                dst,
                op,
                bits,
                zero_is_poison: flag(operation, "zero_is_poison")?,
                src: operands[0].0,
            });
        }
        match name {
            "constant" => {
                arity(0)?;
                let (dst, ty) = one_result()?;
                Ok(Op::Const {
                    dst,
                    value: self.literal(field(operation, "literal")?, ty)?,
                })
            }
            "copy" | "freeze" => {
                arity(1)?;
                let (dst, ty) = one_result()?;
                require(self.types.same(operands[0].1, ty), "copy type")?;
                Ok(if name == "copy" {
                    Op::Copy {
                        dst,
                        src: operands[0].0,
                    }
                } else {
                    Op::Freeze {
                        dst,
                        src: operands[0].0,
                        zero: self.types.zero(ty)?,
                    }
                })
            }
            "icmp" => {
                arity(2)?;
                let (dst, ty) = one_result()?;
                require(self.types.int_bits(ty)? == 1, "comparison result")?;
                require(
                    self.types.same(operands[0].1, operands[1].1),
                    "comparison operands",
                )?;
                let pred = match token(operation, "predicate")? {
                    "eq" => Predicate::Eq,
                    "ne" => Predicate::Ne,
                    "ult" => Predicate::Ult,
                    "ule" => Predicate::Ule,
                    "ugt" => Predicate::Ugt,
                    "uge" => Predicate::Uge,
                    "slt" => Predicate::Slt,
                    "sle" => Predicate::Sle,
                    "sgt" => Predicate::Sgt,
                    "sge" => Predicate::Sge,
                    _ => return Err(malformed("comparison predicate")),
                };
                let bits = match self.types.scalar(operands[0].1)? {
                    Type::Int { bits } => *bits,
                    // Pointers compare by address, whatever their origins.
                    Type::DataPtr => 64,
                    _ => return Err(unimplemented("code pointer comparison")),
                };
                Ok(Op::Icmp {
                    dst,
                    pred,
                    bits,
                    lhs: operands[0].0,
                    rhs: operands[1].0,
                })
            }
            "select" => {
                arity(3)?;
                let (dst, ty) = one_result()?;
                match self.types.get(operands[0].1) {
                    Type::Int { bits: 1 } => {}
                    Type::Other { .. } => return Err(unimplemented("vector select")),
                    _ => return Err(malformed("select condition")),
                }
                require(
                    self.types.same(operands[1].1, ty) && self.types.same(operands[2].1, ty),
                    "select arms",
                )?;
                Ok(Op::Select {
                    dst,
                    cond: operands[0].0,
                    if_true: operands[1].0,
                    if_false: operands[2].0,
                })
            }
            "trunc" | "zext" | "sext" => {
                arity(1)?;
                let (dst, ty) = one_result()?;
                let (from_bits, to_bits) = (
                    self.types.int_bits(operands[0].1)?,
                    self.types.int_bits(ty)?,
                );
                let op = match name {
                    "trunc" => Cast::Trunc,
                    "zext" => Cast::Zext,
                    _ => Cast::Sext,
                };
                require(
                    if op == Cast::Trunc {
                        to_bits < from_bits
                    } else {
                        to_bits > from_bits
                    },
                    "cast direction",
                )?;
                Ok(Op::Cast {
                    dst,
                    op,
                    from_bits,
                    to_bits,
                    src: operands[0].0,
                })
            }
            "bitcast" => {
                arity(1)?;
                let (dst, ty) = one_result()?;
                match (self.types.scalar(operands[0].1)?, self.types.scalar(ty)?) {
                    (Type::Int { bits: a }, Type::Int { bits: b }) if a == b => Ok(Op::Copy {
                        dst,
                        src: operands[0].0,
                    }),
                    _ => Err(unimplemented("bitcast other than same-width integers")),
                }
            }
            "address_of" => {
                arity(0)?;
                let (dst, ty) = one_result()?;
                let symbol = local(field(operation, "symbol")?)?;
                let callable = match self.types.scalar(ty)? {
                    Type::CodeAddress => false,
                    Type::CodePtr { .. } => true,
                    Type::DataPtr => {
                        let segment = self.data_symbols.get(&symbol).copied().ok_or_else(|| {
                            unimplemented("address of a symbol with no data definition here")
                        })?;
                        return Ok(Op::AddressOfData { dst, segment });
                    }
                    Type::Int { .. } | Type::Function(_) | Type::Other { .. } => {
                        return Err(malformed("address_of result type"));
                    }
                };
                let function = self
                    .symbols
                    .get(&symbol)
                    .and_then(|id| self.functions.get(id))
                    .copied()
                    .ok_or_else(|| unimplemented("address of an undefined function symbol"))?;
                Ok(Op::AddressOf {
                    dst,
                    function,
                    callable,
                })
            }
            "code_bind" | "code_erase" => {
                arity(1)?;
                let (dst, ty) = one_result()?;
                let bind = name == "code_bind";
                let shapes = (self.types.scalar(operands[0].1)?, self.types.scalar(ty)?);
                require(
                    if bind {
                        matches!(shapes, (Type::CodeAddress, Type::CodePtr { .. }))
                    } else {
                        matches!(shapes, (Type::CodePtr { .. }, Type::CodeAddress))
                    },
                    "code address conversion types",
                )?;
                Ok(if bind {
                    Op::CodeBind {
                        dst,
                        src: operands[0].0,
                    }
                } else {
                    Op::CodeErase {
                        dst,
                        src: operands[0].0,
                    }
                })
            }
            "load" => {
                arity(1)?;
                let (dst, ty) = one_result()?;
                self.data_ptr(operands[0].1, "load address")?;
                let (kind, bytes, alignment, stored) = self.access(operation)?;
                require(self.types.same(stored, ty), "load result type")?;
                Ok(Op::Load {
                    dst,
                    ptr: operands[0].0,
                    kind,
                    bytes,
                    alignment,
                })
            }
            "store" => {
                arity(2)?;
                require(results.is_empty(), "store has no result")?;
                self.data_ptr(operands[0].1, "store address")?;
                let (kind, bytes, alignment, stored) = self.access(operation)?;
                require(self.types.same(stored, operands[1].1), "stored value type")?;
                Ok(Op::Store {
                    ptr: operands[0].0,
                    value: operands[1].0,
                    kind,
                    bytes,
                    alignment,
                })
            }
            "ptr_offset" => {
                arity(2)?;
                let (dst, ty) = one_result()?;
                self.data_ptr(ty, "pointer offset result")?;
                self.data_ptr(operands[0].1, "pointer offset base")?;
                require(
                    self.types.int_bits(operands[1].1)? == 64,
                    "pointer offset amount",
                )?;
                if optional(field(operation, "inrange")?)?.is_some() {
                    return Err(unimplemented("pointer offset with an access range"));
                }
                let inbounds = flag(operation, "inbounds")?;
                let check_base = flag(operation, "check_base")?;
                require(inbounds || !check_base, "pointer base check")?;
                Ok(Op::PtrOffset {
                    dst,
                    ptr: operands[0].0,
                    delta: operands[1].0,
                    inbounds,
                    check_base,
                    nuw: flag(operation, "nuw")?,
                    nusw: flag(operation, "nusw")?,
                })
            }
            "alloca" => {
                arity(1)?;
                let (dst, ty) = one_result()?;
                self.helper(operation, "stack_alloc")?;
                self.data_ptr(ty, "alloca result")?;
                require(self.types.int_bits(operands[0].1)? == 64, "alloca size")?;
                let alignment = u64::from(number(operation, "alignment")?);
                require(alignment.is_power_of_two(), "alloca alignment")?;
                Ok(Op::Alloca {
                    dst,
                    size: operands[0].0,
                    alignment,
                })
            }
            "lifetime_start" | "lifetime_end" => {
                arity(2)?;
                require(results.is_empty(), "lifetime marker has no result")?;
                self.helper(operation, name)?;
                self.data_ptr(operands[0].1, "lifetime address")?;
                require(self.types.int_bits(operands[1].1)? == 64, "lifetime size")?;
                Ok(Op::Lifetime {
                    ptr: operands[0].0,
                    size: operands[1].0,
                    start: name == "lifetime_start",
                })
            }
            "ptrtoint" | "ptrtoaddr" => {
                arity(1)?;
                let (dst, ty) = one_result()?;
                match self.types.scalar(operands[0].1)? {
                    Type::DataPtr => {}
                    _ => return Err(unimplemented("code pointer to integer")),
                }
                let bits = self.types.int_bits(ty)?;
                Ok(Op::PtrToInt {
                    dst,
                    src: operands[0].0,
                    bits,
                    expose: name == "ptrtoint",
                })
            }
            "inttoptr" => {
                arity(1)?;
                let (dst, ty) = one_result()?;
                self.types.int_bits(operands[0].1)?;
                match self.types.scalar(ty)? {
                    Type::DataPtr => {}
                    _ => return Err(unimplemented("integer to code pointer")),
                }
                Ok(Op::IntToPtr {
                    dst,
                    src: operands[0].0,
                })
            }
            "memcpy" | "memmove" | "memset" => {
                arity(3)?;
                require(results.is_empty(), "bulk memory operation has no result")?;
                if flag(operation, "volatile")? {
                    return Err(unimplemented("volatile bulk memory operation"));
                }
                self.data_ptr(operands[0].1, "bulk memory destination")?;
                require(
                    self.types.int_bits(operands[2].1)? == 64,
                    "bulk memory count",
                )?;
                let alignment = number(operation, "alignment")?;
                require(alignment.is_power_of_two(), "bulk memory alignment")?;
                let (dst, count) = (operands[0].0, operands[2].0);
                if name == "memset" {
                    require(self.types.int_bits(operands[1].1)? == 8, "memset value")?;
                    Ok(Op::MemSet {
                        dst,
                        value: operands[1].0,
                        count,
                        alignment,
                    })
                } else {
                    self.data_ptr(operands[1].1, "bulk memory source")?;
                    Ok(Op::MemCopy {
                        dst,
                        src: operands[1].0,
                        count,
                        alignment,
                        overlapping: name == "memmove",
                    })
                }
            }
            "call" => {
                let target = field(operation, "target")?;
                let signature_type = self.types.resolve(field(target, "signature")?)?;
                let signature = self.types.function(signature_type)?;
                require(
                    operands.len() == signature.params.len()
                        && results.len() == signature.results.len(),
                    "call arity",
                )?;
                for ((_, actual), formal) in operands.iter().zip(&signature.params) {
                    require(self.types.same(*actual, *formal), "call argument type")?;
                }
                for ((_, actual), formal) in results.iter().zip(&signature.results) {
                    require(self.types.same(*actual, *formal), "call result type")?;
                }
                let callee = match token(target, "kind")? {
                    "direct" => {
                        let function = self.function(field(target, "function")?)?;
                        require(
                            self.types
                                .same(self.signatures[function.index()], signature_type),
                            "direct call signature",
                        )?;
                        Callee::Direct(function)
                    }
                    "indirect" => {
                        let (value, ty) = self.named(target, "value")?;
                        require(
                            matches!(self.types.scalar(ty)?, Type::CodePtr { .. }),
                            "indirect callee type",
                        )?;
                        Callee::Indirect {
                            value,
                            signature: signature_type,
                        }
                    }
                    "import" => return Err(unimplemented("call to an import")),
                    _ => return Err(malformed("call target kind")),
                };
                Ok(Op::Call {
                    dsts: results.iter().map(|(slot, _)| *slot).collect(),
                    callee,
                    args: operands.iter().map(|(slot, _)| *slot).collect(),
                    arg_noundef: signature.param_noundef.clone(),
                })
            }
            other => Err(unimplemented(format!("operation {other}"))),
        }
    }

    fn terminator(&self, term: &RecordValue, results: &[TypeId]) -> Result<Terminator, Error> {
        match token(term, "op")? {
            "return" => {
                let values = items(term, "values")?
                    .iter()
                    .map(|value| self.value(value))
                    .collect::<Result<Vec<_>, _>>()?;
                require(values.len() == results.len(), "return arity")?;
                for ((_, actual), formal) in values.iter().zip(results) {
                    require(self.types.same(*actual, *formal), "return type")?;
                }
                Ok(Terminator::Return(
                    values.iter().map(|(slot, _)| *slot).collect(),
                ))
            }
            "jump" => Ok(Terminator::Jump(self.block(term, "target")?)),
            "cbranch" => {
                let (cond, ty) = self.named(term, "condition")?;
                require(self.types.int_bits(ty)? == 1, "branch condition")?;
                Ok(Terminator::Branch {
                    cond,
                    if_true: self.block(term, "true")?,
                    if_false: self.block(term, "false")?,
                })
            }
            "switch" => {
                let (index, ty) = self.named(term, "index")?;
                let bits = self.types.int_bits(ty)?;
                let cases = items(term, "cases")?
                    .iter()
                    .map(|case| {
                        Ok((
                            little_endian(bytes(field(case, "value")?)?, bits)?,
                            self.block(case, "target")?,
                        ))
                    })
                    .collect::<Result<Vec<_>, Error>>()?;
                Ok(Terminator::Switch {
                    index,
                    cases,
                    default: self.block(term, "default")?,
                })
            }
            "trap" => Ok(Terminator::Trap {
                reason: token(term, "reason")?.to_owned(),
            }),
            "unreachable" => Ok(Terminator::Unreachable),
            other => Err(unimplemented(format!("terminator {other}"))),
        }
    }
}

fn function(
    record: &RecordValue,
    types: &Types,
    functions: &BTreeMap<u32, FuncIdx>,
    signatures: &[TypeId],
    symbols: &BTreeMap<u32, u32>,
    layouts: &BTreeMap<u32, Layout>,
    helpers: &BTreeMap<u32, String>,
    data_symbols: &BTreeMap<u32, super::SegIdx>,
) -> Result<Function, Error> {
    let signature_type = types.resolve(field(record, "signature")?)?;
    let signature = types.function(signature_type)?;
    let mut body = Body {
        types,
        functions,
        signatures,
        symbols,
        layouts,
        helpers,
        data_symbols,
        slots: BTreeMap::new(),
        blocks: BTreeMap::new(),
    };
    let mut params = Vec::new();
    for (declaration, formal) in items(record, "params")?.iter().zip(&signature.params) {
        let slot = body.declare(declaration)?;
        require(
            types.same(body.slots[&number(declaration, "id")?].1, *formal),
            "parameter type",
        )?;
        params.push(slot);
    }
    require(params.len() == signature.params.len(), "parameter arity")?;
    for result in &signature.results {
        types.scalar(*result)?;
    }
    let blocks = items(record, "blocks")?;
    for (position, block) in blocks.iter().enumerate() {
        let previous = body
            .blocks
            .insert(number(block, "id")?, BlockIdx(index_of(position)?));
        require(previous.is_none(), "duplicate block identifier")?;
        for phi in items(block, "phis")? {
            body.declare(field(phi, "result")?)?;
        }
        for operation in items(block, "ops")? {
            for declaration in items(operation, "results")? {
                body.declare(declaration)?;
            }
        }
    }
    let mut lowered = Vec::with_capacity(blocks.len());
    for block in blocks {
        let mut phis = Vec::new();
        for phi in items(block, "phis")? {
            let (dst, ty) = body.named(field(phi, "result")?, "id")?;
            let mut incoming = Vec::new();
            for edge in items(phi, "incoming")? {
                let (value, actual) = body.named(edge, "value")?;
                require(types.same(actual, ty), "phi input type")?;
                incoming.push((body.block(edge, "predecessor")?, value));
            }
            phis.push(Phi { dst, incoming });
        }
        lowered.push(Block {
            id: number(block, "id")?,
            phis,
            ops: items(block, "ops")?
                .iter()
                .map(|operation| body.operation(operation))
                .collect::<Result<_, _>>()?,
            term: body.terminator(field(block, "term")?, &signature.results)?,
        });
    }
    Ok(Function {
        id: number(record, "id")?,
        signature_type,
        signature: signature.clone(),
        params,
        entry: body.block(record, "entry")?,
        blocks: lowered,
        slots: index_of(body.slots.len())?,
    })
}

pub(super) fn lower(object: &ParsedObject) -> Result<Module, Error> {
    if !items(object.root(8)?, "functions")?.is_empty() {
        return Err(unimplemented("exception regions"));
    }
    let types = Types::lower(object.root(1)?)?;
    let symbols = function_symbols(object.root(2)?)?;
    let layouts = layouts(object.root(1)?, &types)?;
    let helpers = helpers(object.root(6)?)?;
    let data = super::data::lower(object.root(2)?, object.root(4)?, object.root(5)?)?;
    let records = items(object.root(3)?, "functions")?;
    let mut function_ids = BTreeMap::new();
    let mut signatures = Vec::with_capacity(records.len());
    for (position, record) in records.iter().enumerate() {
        let previous = function_ids.insert(number(record, "id")?, FuncIdx(index_of(position)?));
        require(previous.is_none(), "duplicate function identifier")?;
        signatures.push(types.resolve(field(record, "signature")?)?);
    }
    let functions = records
        .iter()
        .map(|record| {
            function(
                record,
                &types,
                &function_ids,
                &signatures,
                &symbols,
                &layouts,
                &helpers,
                &data.symbols,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Module {
        identity: object.identity(),
        types: types.list,
        functions,
        function_ids,
        segments: data.segments,
        relocations: data.relocations,
    })
}
