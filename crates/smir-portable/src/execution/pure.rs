//! Static typing for pure integer, aggregate, vector, pointer-cast and FP nodes.

use std::sync::OnceLock;

use crate::context::{bytes, field, unsigned};
use crate::error::Error;
use crate::limits::Budget;
use crate::wire::RecordValue;

use super::records::{flag, require, sequence, token};
use super::{TypeFacts, TypeHandle, TypeKind};

pub(super) fn contract(name: &str) -> Result<&'static serde_json::Value, Error> {
    static CONTRACTS: OnceLock<Result<serde_json::Value, String>> = OnceLock::new();
    let document = CONTRACTS
        .get_or_init(|| {
            serde_json::from_str(include_str!(
                "../../../../docs/specifications/smir/portable/schema/execution/candidate.json"
            ))
            .map_err(|error| error.to_string())
        })
        .as_ref()
        .map_err(|message| Error::semantic("P2_SCHEMA", message.clone()))?;
    document
        .get("operation_contracts")
        .and_then(|contracts| contracts.get(name))
        .ok_or_else(|| Error::semantic("operation", name))
}

pub(super) fn arity(name: &str, args: usize, results: usize) -> Result<(), Error> {
    let contract = contract(name)?;
    if let Some(expected) = contract.get("operands").and_then(serde_json::Value::as_u64) {
        require(args as u64 == expected, "operand_arity")?;
    }
    if let Some(expected) = contract.get("results").and_then(serde_json::Value::as_u64) {
        require(results as u64 == expected, "result_arity")?;
    }
    Ok(())
}

pub(super) fn same(
    types: &TypeFacts,
    a: TypeHandle,
    b: TypeHandle,
    budget: &mut Budget,
) -> Result<(), Error> {
    require(types.type_equivalent(a, b, budget)?, "operand_type")
}

pub(super) fn scalar(types: &TypeFacts, ty: TypeHandle) -> Result<&TypeKind, Error> {
    match types.kind(ty)? {
        TypeKind::Vector { element, .. } => types.kind(types.type_handle(*element)?),
        other => Ok(other),
    }
}

fn boolean(types: &TypeFacts, ty: TypeHandle, source: Option<TypeHandle>) -> Result<(), Error> {
    let mut kind = types.kind(ty)?;
    if let Some(source) = source {
        if let TypeKind::Vector { count, .. } = types.kind(source)? {
            let TypeKind::Vector {
                element,
                count: actual,
            } = kind
            else {
                return Err(Error::semantic("boolean_lanes", "vector result"));
            };
            require(count == actual, "boolean_lanes")?;
            kind = types.kind(types.type_handle(*element)?)?;
        }
    }
    require(matches!(kind, TypeKind::Int(1)), "boolean_type")
}

pub(super) fn same_lanes(
    types: &TypeFacts,
    a: TypeHandle,
    b: TypeHandle,
    code: &'static str,
) -> Result<(), Error> {
    let a = types.kind(a)?;
    let b = types.kind(b)?;
    let valid = match (a, b) {
        (TypeKind::Vector { count: a, .. }, TypeKind::Vector { count: b, .. }) => a == b,
        (TypeKind::Vector { .. }, _) | (_, TypeKind::Vector { .. }) => false,
        _ => true,
    };
    require(valid, code)
}

pub(super) fn fp_mode(mode: &RecordValue, operation: &str) -> Result<(), Error> {
    let environment = token(mode, "environment")?;
    let rounding = token(mode, "rounding")?;
    let exceptions = token(mode, "exceptions")?;
    require(
        ["default", "constrained"].contains(&environment)
            && [
                "nearest_even",
                "nearest_away",
                "toward_zero",
                "upward",
                "downward",
                "dynamic",
            ]
            .contains(&rounding)
            && ["ignore", "maytrap", "strict"].contains(&exceptions),
        "fp_mode",
    )?;
    if environment == "default" {
        require(
            rounding == "nearest_even" && exceptions == "ignore",
            "fp_default",
        )?;
    }
    if environment == "constrained" && ["fptosi", "fptoui"].contains(&operation) {
        require(rounding == "toward_zero", "fp_conversion_rounding")?;
    }
    Ok(())
}

pub(super) fn literal(
    types: &TypeFacts,
    ty: TypeHandle,
    value: &RecordValue,
    budget: &mut Budget,
) -> Result<(), Error> {
    budget.work(1)?;
    let kind = types.kind(ty)?;
    match token(value, "kind")? {
        "poison" | "undef" => require(!matches!(kind, TypeKind::Function { .. }), "literal"),
        "zero" => require(
            !matches!(kind, TypeKind::Function { .. })
                && !types.present_opaque(ty)?.any()
                && !types.present_fenv(ty)?,
            "literal",
        ),
        "aggregate" => {
            let elements = sequence(value, "elements")?;
            match kind {
                TypeKind::Struct { fields } => {
                    require(elements.len() == fields.len(), "literal")?;
                    for (element, child) in elements.iter().zip(fields) {
                        literal(types, types.type_handle(*child)?, element, budget)?;
                    }
                }
                TypeKind::Array { element, count } | TypeKind::Vector { element, count } => {
                    require(elements.len() as u64 == *count, "literal")?;
                    for child in elements {
                        literal(types, types.type_handle(*element)?, child, budget)?;
                    }
                }
                _ => return Err(Error::semantic("literal", "aggregate type")),
            }
            Ok(())
        }
        "bits" => {
            require(kind.scalar(), "literal")?;
            let bits = types.value_bits(ty)?;
            let data = bytes(field(value, "value")?)?;
            require(data.len() as u64 == bits.div_ceil(8), "constant")?;
            if bits % 8 != 0 {
                let last = *data
                    .last()
                    .ok_or_else(|| Error::semantic("constant", "empty scalar"))?;
                require(last >> (bits % 8) == 0, "constant")?;
            }
            if matches!(kind, TypeKind::DataPtr | TypeKind::CodePtr { .. }) {
                budget.work(data.len() as u64)?;
                require(data.iter().all(|byte| *byte == 0), "literal_pointer")?;
            }
            Ok(())
        }
        _ => Err(Error::semantic("literal", "kind")),
    }
}

pub(super) fn check(
    operation: &RecordValue,
    args: &[TypeHandle],
    outputs: &[TypeHandle],
    types: &TypeFacts,
    budget: &mut Budget,
) -> Result<bool, Error> {
    budget.work(1)?;
    let name = token(operation, "op")?;
    arity(name, args.len(), outputs.len())?;
    let family = contract(name)?
        .get("family")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| Error::semantic("P2_SCHEMA", "operation family"))?;
    // Exact arity was checked above; safe extraction still uses fallible get so
    // a schema mismatch cannot turn an untrusted operation into a host panic.
    let arg = |index| {
        args.get(index)
            .copied()
            .ok_or_else(|| Error::semantic("operand_arity", name))
    };
    let out = |index| {
        outputs
            .get(index)
            .copied()
            .ok_or_else(|| Error::semantic("result_arity", name))
    };
    match name {
        "constant" => literal(types, out(0)?, field(operation, "literal")?, budget)?,
        "copy" | "freeze" => {
            same(types, arg(0)?, out(0)?, budget)?;
            if name == "freeze" {
                require(!types.present_opaque(arg(0)?)?.any(), "freeze_opaque")?;
            }
        }
        "icmp" => {
            same(types, arg(0)?, arg(1)?, budget)?;
            if matches!(scalar(types, arg(0)?)?, TypeKind::CodeAddress) {
                require(
                    ["eq", "ne"].contains(&token(operation, "predicate")?),
                    "code_address_predicate",
                )?;
            }
            require(
                matches!(
                    scalar(types, arg(0)?)?,
                    TypeKind::Int(_)
                        | TypeKind::DataPtr
                        | TypeKind::CodePtr { .. }
                        | TypeKind::CodeAddress
                ),
                "operand_class",
            )?;
            require(
                [
                    "eq", "ne", "ult", "ule", "ugt", "uge", "slt", "sle", "sgt", "sge",
                ]
                .contains(&token(operation, "predicate")?),
                "predicate",
            )?;
            boolean(types, out(0)?, Some(arg(0)?))?;
        }
        "select" => {
            same(types, arg(1)?, arg(2)?, budget)?;
            same(types, out(0)?, arg(1)?, budget)?;
            if matches!(types.kind(arg(0)?)?, TypeKind::Vector { .. }) {
                require(
                    matches!(types.kind(arg(1)?)?, TypeKind::Vector { .. }),
                    "select_vector",
                )?;
                boolean(types, arg(0)?, Some(arg(1)?))?;
            } else {
                boolean(types, arg(0)?, None)?;
            }
        }
        "extract" | "insert" => {
            let mut current = arg(0)?;
            let indices = sequence(operation, "indices")?;
            require(!indices.is_empty(), "aggregate_index")?;
            for index in indices {
                budget.work(1)?;
                let index = unsigned(index)?;
                current = match types.kind(current)? {
                    TypeKind::Struct { fields } => types.type_handle(
                        *fields
                            .get(
                                usize::try_from(index)
                                    .map_err(|_| Error::semantic("aggregate_index", "index"))?,
                            )
                            .ok_or_else(|| Error::semantic("aggregate_index", "struct index"))?,
                    )?,
                    TypeKind::Array { element, count } if index < *count => {
                        types.type_handle(*element)?
                    }
                    _ => return Err(Error::semantic("aggregate_index", "aggregate type/index")),
                };
            }
            same(
                types,
                out(0)?,
                if name == "extract" { current } else { arg(0)? },
                budget,
            )?;
            if name == "insert" {
                same(types, current, arg(1)?, budget)?;
            }
        }
        _ => match family {
            "integer" => {
                require(
                    matches!(scalar(types, arg(0)?)?, TypeKind::Int(_)),
                    "operand_class",
                )?;
                same(types, arg(0)?, out(0)?, budget)?;
                for ty in args.iter().skip(1) {
                    same(types, *ty, arg(0)?, budget)?;
                }
                if let Some(flags) = crate::context::record(operation)?.get("flags") {
                    let allowed: &[&str] = match name {
                        "i_add" | "i_sub" | "i_mul" | "i_shl" => &["nsw", "nuw"],
                        "i_lshr" | "i_ashr" | "i_udiv" | "i_sdiv" => &["exact"],
                        _ => &[],
                    };
                    check_flags(
                        crate::context::list(flags)?,
                        allowed,
                        "integer_flags",
                        budget,
                    )?;
                }
                if name == "i_bswap" {
                    require(
                        matches!(scalar(types,arg(0)?)?,TypeKind::Int(bits) if bits % 16 == 0),
                        "bswap_width",
                    )?;
                }
                if ["i_popcount", "i_bswap", "i_bitreverse"].contains(&name) {
                    require(!flag(operation, "zero_is_poison")?, "unused_integer_flag")?;
                }
            }
            "vector" => {
                let TypeKind::Vector { element, count } = types.kind(arg(0)?)? else {
                    return Err(Error::semantic("vector_operand", name));
                };
                let element = types.type_handle(*element)?;
                match name {
                    "extract_element" => {
                        require(
                            matches!(types.kind(arg(1)?)?, TypeKind::Int(_)),
                            "vector_index",
                        )?;
                        same(types, out(0)?, element, budget)?;
                    }
                    "insert_element" => {
                        same(types, arg(1)?, element, budget)?;
                        require(
                            matches!(types.kind(arg(2)?)?, TypeKind::Int(_)),
                            "vector_index",
                        )?;
                        same(types, out(0)?, arg(0)?, budget)?;
                    }
                    "shuffle" => {
                        same(types, arg(1)?, arg(0)?, budget)?;
                        let TypeKind::Vector {
                            element: result_element,
                            count: result_count,
                        } = types.kind(out(0)?)?
                        else {
                            return Err(Error::semantic("shuffle_result", name));
                        };
                        let mask = sequence(operation, "mask")?;
                        require(mask.len() as u64 == *result_count, "shuffle_result")?;
                        same(types, types.type_handle(*result_element)?, element, budget)?;
                        for index in mask {
                            budget.work(1)?;
                            if let Some(index) = crate::context::optional(index)? {
                                require(unsigned(index)? < 2 * count, "shuffle_index")?;
                            }
                        }
                    }
                    _ => return Err(Error::semantic("operation", name)),
                }
            }
            "cast" => {
                let source = scalar(types, arg(0)?)?;
                let destination = scalar(types, out(0)?)?;
                match name {
                    "trunc" | "zext" | "sext" => {
                        let (TypeKind::Int(a), TypeKind::Int(b)) = (source, destination) else {
                            return Err(Error::semantic("cast_type", name));
                        };
                        require(if name == "trunc" { b < a } else { b > a }, "cast_width")?;
                        same_lanes(types, arg(0)?, out(0)?, "cast_lanes")?;
                    }
                    "bitcast" => {
                        require(
                            types.value_bits(arg(0)?)? == types.value_bits(out(0)?)?
                                && source.scalar()
                                && destination.scalar(),
                            "bitcast_width",
                        )?;
                        if matches!(
                            source,
                            TypeKind::DataPtr | TypeKind::CodePtr { .. } | TypeKind::CodeAddress
                        ) {
                            require(
                                matches!(destination, TypeKind::Raw(_))
                                    || source.name() == destination.name(),
                                "bitcast_pointer",
                            )?;
                        }
                    }
                    "ptrtoint" | "ptrtoaddr" => {
                        require(
                            matches!(
                                source,
                                TypeKind::DataPtr
                                    | TypeKind::CodePtr { .. }
                                    | TypeKind::CodeAddress
                            ) && matches!(destination, TypeKind::Int(_)),
                            "pointer_cast",
                        )?;
                        if name == "ptrtoaddr" {
                            require(
                                matches!(destination, TypeKind::Int(64)),
                                "pointer_index_width",
                            )?;
                        }
                        same_lanes(types, arg(0)?, out(0)?, "pointer_cast_lanes")?;
                    }
                    "inttoptr" => {
                        require(
                            matches!(source, TypeKind::Int(_))
                                && matches!(
                                    destination,
                                    TypeKind::DataPtr
                                        | TypeKind::CodePtr { .. }
                                        | TypeKind::CodeAddress
                                ),
                            "pointer_cast",
                        )?;
                        same_lanes(types, arg(0)?, out(0)?, "pointer_cast_lanes")?;
                    }
                    _ => return Err(Error::semantic("operation", name)),
                }
            }
            "fp" | "fp_compare" | "fp_cast" => {
                fp_mode(field(operation, "mode")?, name)?;
                if family == "fp" {
                    require(
                        matches!(scalar(types, arg(0)?)?, TypeKind::Float(_)),
                        "operand_class",
                    )?;
                    same(types, out(0)?, arg(0)?, budget)?;
                    for ty in args.iter().skip(1) {
                        same(types, *ty, arg(0)?, budget)?;
                    }
                } else if family == "fp_compare" {
                    require(
                        matches!(scalar(types, arg(0)?)?, TypeKind::Float(_)),
                        "operand_class",
                    )?;
                    same(types, arg(0)?, arg(1)?, budget)?;
                    boolean(types, out(0)?, Some(arg(0)?))?;
                    require(
                        [
                            "false", "true", "oeq", "one", "olt", "ole", "ogt", "oge", "ord",
                            "ueq", "une", "ult", "ule", "ugt", "uge", "uno",
                        ]
                        .contains(&token(operation, "predicate")?),
                        "predicate",
                    )?;
                } else {
                    let source_integer = ["sitofp", "uitofp"].contains(&name);
                    let destination_integer =
                        ["fptosi", "fptoui", "fptosi_sat", "fptoui_sat"].contains(&name);
                    require(
                        if source_integer {
                            matches!(scalar(types, arg(0)?)?, TypeKind::Int(_))
                        } else {
                            matches!(scalar(types, arg(0)?)?, TypeKind::Float(_))
                        },
                        "operand_class",
                    )?;
                    require(
                        if destination_integer {
                            matches!(scalar(types, out(0)?)?, TypeKind::Int(_))
                        } else {
                            matches!(scalar(types, out(0)?)?, TypeKind::Float(_))
                        },
                        "operand_class",
                    )?;
                    same_lanes(types, arg(0)?, out(0)?, "conversion_lanes")?;
                }
            }
            "environment" => match name {
                "fenv_get" | "fenv_unpack" => {
                    require(matches!(types.kind(out(0)?)?, TypeKind::Fenv), "fenv_type")?;
                    if name == "fenv_unpack" {
                        require(
                            matches!(types.kind(arg(0)?)?, TypeKind::Raw(256)),
                            "fenv_encoding_type",
                        )?;
                        boolean(types, out(1)?, None)?;
                    }
                }
                "fenv_set" => require(matches!(types.kind(arg(0)?)?, TypeKind::Fenv), "fenv_type")?,
                "fenv_pack" => require(
                    matches!(types.kind(arg(0)?)?, TypeKind::Fenv)
                        && matches!(types.kind(out(0)?)?, TypeKind::Raw(256)),
                    "fenv_encoding_type",
                )?,
                _ => {
                    check_flags(
                        sequence(operation, "flags")?,
                        &[
                            "invalid",
                            "divide_by_zero",
                            "overflow",
                            "underflow",
                            "inexact",
                            "denormal",
                        ],
                        "fenv_flags",
                        budget,
                    )?;
                    if name == "fenv_test" {
                        boolean(types, out(0)?, None)?;
                    }
                }
            },
            "effect" => {}
            _ => return Ok(false),
        },
    }
    Ok(true)
}

fn check_flags(
    values: &[RecordValue],
    allowed: &[&str],
    code: &'static str,
    budget: &mut Budget,
) -> Result<(), Error> {
    let mut previous = None;
    for value in values {
        budget.work(1)?;
        let value = crate::context::text(value)?;
        require(
            allowed.contains(&value) && previous.is_none_or(|old| old < value),
            code,
        )?;
        previous = Some(value);
    }
    Ok(())
}
