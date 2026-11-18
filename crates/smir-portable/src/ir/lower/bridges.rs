//! Lowering of an import of kind `foreign`: the bridge it names.

use crate::Error;
use crate::context::{bytes, field, optional, text, unsigned};
use crate::wire::{ParsedObject, RecordValue};

use super::super::{Bridge, BridgeArgument, BridgeConvention, ForeignIsa, Type, TypeId};
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

/// The bridge an import of kind `foreign` names: from portable code to a
/// function of the module's foreign code, over integers and floats, which
/// neither calls back nor lets an exception out. The verifier has checked
/// the records against one another; this says which of the bridges it
/// admits the engine crosses.
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
        return Err(unimplemented("a bridge that foreign code calls"));
    }
    let target = domain("target")?;
    let isa = match text(field(target, "isa")?)? {
        "x86_64" => ForeignIsa::X86_64,
        "aarch64" => ForeignIsa::Aarch64,
        _ => return Err(malformed("a bridge to no foreign processor")),
    };
    let convention = match (isa, text(field(target, "personality")?)?) {
        (ForeignIsa::X86_64, "windows") => BridgeConvention::Win64,
        (ForeignIsa::X86_64, _) => BridgeConvention::SysV64,
        (ForeignIsa::Aarch64, _) => BridgeConvention::Aapcs64,
    };
    if token(record, "callbacks")? != "none" {
        return Err(unimplemented("a bridge whose foreign code calls back"));
    }
    if token(record, "exceptions")? != "noexcept" {
        return Err(unimplemented("a bridge that exceptions cross"));
    }
    // The stub: a native symbol of this module, a byte range of an image.
    let entry = local(field(record, "entry")?)?;
    let symbol = items(object.root(2)?, "symbols")?
        .iter()
        .find(|symbol| number(symbol, "id").is_ok_and(|id| id == entry))
        .ok_or_else(|| malformed("a bridge without its symbol"))?;
    let definition = optional(field(symbol, "definition")?)?
        .filter(|definition| token(definition, "kind").is_ok_and(|kind| kind == "native"))
        .ok_or_else(|| malformed("a bridge whose entry is no native code"))?;
    // What is passed: scalars, each as its own bytes.
    let source = abi_record(abi, "signatures", number(record, "signature")?)?;
    if flag(source, "variadic")?
        || flag(source, "vtt")?
        || optional(field(source, "this_type")?)?.is_some()
        || optional(field(source, "varargs")?)?.is_some()
    {
        return Err(unimplemented(
            "a foreign call with other than plain arguments",
        ));
    }
    let signature = types.resolve(field(import, "signature")?)?;
    let function = types.function(signature)?;
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
    Ok(Bridge {
        id,
        isa,
        convention,
        image: bytes(field(definition, "image")?)?
            .try_into()
            .map_err(|_| malformed("native image identity"))?,
        offset: unsigned(field(definition, "offset")?)?,
        size: unsigned(field(definition, "size")?)?,
        signature,
        arguments,
        result_bytes,
    })
}
