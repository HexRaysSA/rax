//! Lowering of the bridges between a module and its foreign code: those an
//! import of kind `foreign` names, which portable code calls, and those
//! that go the other way, by which foreign code calls a function of the
//! module.

use std::collections::BTreeMap;

use crate::Error;
use crate::context::{bytes, field, optional, text, unsigned};
use crate::wire::{ParsedObject, RecordValue};

use super::super::{
    Bridge, BridgeArgument, BridgeConvention, Callback, ForeignIsa, FuncIdx, Signature, Type,
    TypeId,
};
use super::{Types, flag, items, local, malformed, number, require, token, unimplemented};

/// The record of a table of the ABI root that has `id`.
fn abi_record<'a>(abi: &'a RecordValue, table: &str, id: u32) -> Result<&'a RecordValue, Error> {
    for record in items(abi, table)? {
        if number(record, "id")? == id {
            return Ok(record);
        }
    }
    Err(malformed(format!("no such record of {table}")))
}

/// The processor of a foreign domain, and how its code takes a frame.
fn processor(domain: &RecordValue) -> Result<(ForeignIsa, BridgeConvention), Error> {
    let isa = match text(field(domain, "isa")?)? {
        "x86_64" => ForeignIsa::X86_64,
        "aarch64" => ForeignIsa::Aarch64,
        _ => return Err(malformed("a bridge of no foreign processor")),
    };
    let convention = match (isa, text(field(domain, "personality")?)?) {
        (ForeignIsa::X86_64, "windows") => BridgeConvention::Win64,
        (ForeignIsa::X86_64, _) => BridgeConvention::SysV64,
        (ForeignIsa::Aarch64, _) => BridgeConvention::Aapcs64,
    };
    Ok((isa, convention))
}

/// Where a bridge's entry is: its symbol is native code of this module, a
/// byte range of an image.
fn entry(object: &ParsedObject, bridge: &RecordValue) -> Result<([u8; 32], u64, u64), Error> {
    let entry = local(field(bridge, "entry")?)?;
    let symbol = items(object.root(2)?, "symbols")?
        .iter()
        .find(|symbol| number(symbol, "id").is_ok_and(|id| id == entry))
        .ok_or_else(|| malformed("a bridge without its symbol"))?;
    let definition = optional(field(symbol, "definition")?)?
        .filter(|definition| token(definition, "kind").is_ok_and(|kind| kind == "native"))
        .ok_or_else(|| malformed("a bridge whose entry is no native code"))?;
    Ok((
        bytes(field(definition, "image")?)?
            .try_into()
            .map_err(|_| malformed("native image identity"))?,
        unsigned(field(definition, "offset")?)?,
        unsigned(field(definition, "size")?)?,
    ))
}

/// What crosses a bridge with the call signature `source`, as the function
/// type `function` has it: scalars, each as its own bytes, and at most one
/// such result. The arguments as they lie in an arena, and the bytes of
/// the result.
fn passed(
    types: &Types,
    source: &RecordValue,
    function: &Signature,
) -> Result<(Vec<BridgeArgument>, u64), Error> {
    if flag(source, "variadic")?
        || flag(source, "vtt")?
        || optional(field(source, "this_type")?)?.is_some()
        || optional(field(source, "varargs")?)?.is_some()
    {
        return Err(unimplemented(
            "a foreign call with other than plain arguments",
        ));
    }
    let scalar = |ty: TypeId| match types.get(ty) {
        Type::Int { bits } if *bits <= 64 => Ok(u64::from(*bits)),
        Type::Float { format } if format.bits() <= 64 => Ok(u64::from(format.bits())),
        _ => Err(unimplemented(
            "a foreign call over other values than integers and floats of up to 64 bits",
        )),
    };
    let lowered = items(source, "lowered_params")?;
    require(
        lowered.len() == function.params.len() && function.results.len() <= 1,
        "foreign call arity",
    )?;
    let mut arguments = Vec::with_capacity(lowered.len());
    for (parameter, ty) in lowered.iter().zip(&function.params) {
        if token(parameter, "mode")? != "direct" || token(parameter, "role")? != "parameter" {
            return Err(unimplemented(
                "a foreign argument that is not passed as its value",
            ));
        }
        let (bytes, alignment) = (
            unsigned(field(parameter, "bytes")?)?,
            unsigned(field(parameter, "align")?)?,
        );
        require(
            matches!(bytes, 1 | 2 | 4 | 8)
                && bytes * 8 >= scalar(*ty)?
                && alignment.is_power_of_two()
                && alignment <= 16,
            "foreign argument storage",
        )?;
        arguments.push(BridgeArgument {
            declaration: local(field(parameter, "value_type")?)?,
            bytes,
            alignment,
        });
    }
    let result_bytes = match function.results.first() {
        Some(ty) => scalar(*ty)?.div_ceil(8).next_power_of_two(),
        None => 0,
    };
    Ok((arguments, result_bytes))
}

/// The bridge an import of kind `foreign` names: from portable code to a
/// function of the module's foreign code, over integers and floats, which
/// lets no exception out. The verifier has checked the records against one
/// another; this says which of the bridges it admits the engine crosses.
pub(super) fn bridge(
    object: &ParsedObject,
    types: &Types,
    import: &RecordValue,
) -> Result<Bridge, Error> {
    let abi = object.root(10)?;
    let id = local(field(import, "descriptor")?)?;
    let record = abi_record(abi, "bridges", id)?;
    let domain = |side: &str| abi_record(abi, "domains", number(record, side)?);
    if text(field(domain("source")?, "isa")?)? != "portable" {
        return Err(malformed("an imported bridge that foreign code calls"));
    }
    let (isa, convention) = processor(domain("target")?)?;
    // Foreign code that calls back does so on the thread that called it.
    let calls_back = match token(record, "callbacks")? {
        "none" => false,
        "owner_thread" => true,
        _ => {
            return Err(unimplemented(
                "a bridge whose foreign code calls back from other threads",
            ));
        }
    };
    if token(record, "exceptions")? != "noexcept" {
        return Err(unimplemented("a bridge that exceptions cross"));
    }
    let (image, offset, size) = entry(object, record)?;
    let source = abi_record(abi, "signatures", number(record, "signature")?)?;
    let signature = types.resolve(field(import, "signature")?)?;
    let (arguments, result_bytes) = passed(types, source, types.function(signature)?)?;
    Ok(Bridge {
        id,
        isa,
        convention,
        image,
        offset,
        size,
        signature,
        arguments,
        result_bytes,
        calls_back,
    })
}

/// The function a callback's recipe for its arguments calls, as a symbol
/// of the module: the recipe is that one call and the return of what it
/// returns.
fn callee(abi: &RecordValue, bridge: &RecordValue) -> Result<u32, Error> {
    let other = || unimplemented("a callback that is more than a call of one function");
    let recipe = abi_record(abi, "recipes", number(bridge, "arguments")?)?;
    let steps = items(recipe, "steps")?;
    let step = |id: u32| {
        steps
            .iter()
            .find(|step| number(step, "id").is_ok_and(|other| other == id))
            .ok_or_else(|| malformed("a recipe without its step"))
    };
    let call = step(number(recipe, "entry")?)?;
    let after = optional(field(call, "normal")?)?
        .map(unsigned)
        .transpose()?
        .and_then(|id| u32::try_from(id).ok())
        .ok_or_else(other)?;
    if steps.len() != 2
        || token(call, "action")? != "call"
        || token(step(after)?, "action")? != "return"
    {
        return Err(other());
    }
    let callee = optional(field(call, "callee")?)?
        .ok_or_else(|| malformed("a call step without what it calls"))?;
    local(callee)
}

/// The bridges of the module that go from its foreign code to a function
/// of its own, which no import names: each has an entry in an image, where
/// foreign code goes to make the call, and a recipe that says which
/// function is called. `defined` has the module's functions by the symbols
/// that define them, and `signatures` the type of each.
pub(super) fn callbacks(
    object: &ParsedObject,
    types: &Types,
    defined: &BTreeMap<u32, FuncIdx>,
    signatures: &[TypeId],
) -> Result<Vec<Callback>, Error> {
    // A module without foreign code may have no such root at all.
    let Ok(abi) = object.root(10) else {
        return Ok(Vec::new());
    };
    let mut callbacks = Vec::new();
    for record in items(abi, "bridges")? {
        let source = abi_record(abi, "domains", number(record, "source")?)?;
        if text(field(source, "isa")?)? == "portable" {
            continue;
        }
        let (isa, convention) = processor(source)?;
        if token(record, "exceptions")? != "noexcept" {
            return Err(unimplemented("a callback that exceptions cross"));
        }
        let function = *defined
            .get(&callee(abi, record)?)
            .ok_or_else(|| unimplemented("a callback of a function of another module"))?;
        let (image, offset, size) = entry(object, record)?;
        let signature = abi_record(abi, "signatures", number(record, "signature")?)?;
        let called = types.function(signatures[function.index()])?;
        let (arguments, result_bytes) = passed(types, signature, called)?;
        callbacks.push(Callback {
            id: number(record, "id")?,
            isa,
            convention,
            image,
            offset,
            size,
            function,
            arguments,
            result_bytes,
        });
    }
    Ok(callbacks)
}
