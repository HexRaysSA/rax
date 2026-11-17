//! Finite ordinary pointer-call coverage after the complete ABI semantic phase.
//!
//! This private predicate issues no facts. Unsupported forms return false so
//! the original audited profiles retain their exact behavior.

use super::value::*;
use crate::{
    Error,
    context::ObjectContext,
    execution::{TypeFacts, TypeKind},
    limits::Budget,
    wire::RecordValue,
};
use std::collections::BTreeMap;

#[derive(Clone, Copy)]
enum Shape {
    Integer { bits: u32, bytes: u64 },
    Pointer,
    Void,
    Function,
}

macro_rules! profile {
    ($condition:expr) => {
        if !$condition {
            return Ok(false);
        }
    };
}

fn local(reference: &RecordValue) -> Result<Option<u32>, Error> {
    if text(field(field(reference, "module")?, "kind")?)? != "self" {
        return Ok(None);
    }
    Ok(Some(id(field(reference, "id")?)?))
}

fn integer(name: &str) -> Option<(u32, bool)> {
    Some(match name {
        "signed char" => (8, true),
        "unsigned char" => (8, false),
        "short" => (16, true),
        "unsigned short" => (16, false),
        "int" => (32, true),
        "unsigned int" => (32, false),
        "long" | "long long" => (64, true),
        "unsigned long" | "unsigned long long" => (64, false),
        _ => return None,
    })
}

fn exact_flags(typ: &RecordValue, expected: &[&str]) -> Result<bool, Error> {
    let values = list(field(typ, "flags")?)?;
    Ok(values.len() == expected.len()
        && expected
            .iter()
            .all(|name| values.iter().any(|value| text(value) == Ok(*name))))
}

fn integer_execution(types: &TypeFacts, reference: &RecordValue, bits: u32) -> Result<bool, Error> {
    if local(reference)?.is_none() {
        return Ok(false);
    }
    Ok(matches!(types.kind(types.type_reference(reference)?)?, TypeKind::Int(n) if *n == bits))
}

#[derive(Clone, Copy)]
enum Physical {
    Integer(u32),
    Pointer,
}

fn physical_execution(
    types: &TypeFacts,
    reference: &RecordValue,
    shape: Physical,
) -> Result<bool, Error> {
    if local(reference)?.is_none() {
        return Ok(false);
    }
    Ok(
        match (types.kind(types.type_reference(reference)?)?, shape) {
            (TypeKind::Int(actual), Physical::Integer(expected)) => *actual == expected,
            (TypeKind::DataPtr, Physical::Pointer) => true,
            _ => false,
        },
    )
}

fn value(
    nodes: &BTreeMap<u32, (&RecordValue, Shape)>,
    reference: &RecordValue,
    budget: &mut Budget,
) -> Result<Option<(Physical, u64)>, Error> {
    budget.work(32)?;
    Ok(match local(reference)?.and_then(|id| nodes.get(&id)) {
        Some((_, Shape::Integer { bits, bytes })) => Some((Physical::Integer(*bits), *bytes)),
        Some((_, Shape::Pointer)) => Some((Physical::Pointer, 8)),
        _ => None,
    })
}

pub(super) fn covered(
    ctx: &ObjectContext,
    types: &TypeFacts,
    budget: &mut Budget,
) -> Result<bool, Error> {
    let root = ctx.root(10)?;
    for name in ["storage_bindings", "journals"] {
        profile!(list(field(root, name)?)?.is_empty());
    }
    let domains = list(field(root, "domains")?)?;
    profile!(domains.len() == 1);
    for name in ["isa", "abi", "personality"] {
        profile!(text(field(&domains[0], name)?)? == "portable");
    }
    let source = list(field(root, "types")?)?;
    let layouts = list(field(root, "layouts")?)?;
    let plans = list(field(root, "signatures")?)?;
    profile!(!plans.is_empty());
    let count = source
        .len()
        .checked_add(layouts.len())
        .and_then(|n| n.checked_add(plans.len()))
        .ok_or_else(|| Error::resource("ABI_CC_PROFILE_LIMIT", "pointer coverage index"))?;
    budget.reserve_bytes(
        count
            .checked_mul(192)
            .ok_or_else(|| Error::resource("ABI_CC_PROFILE_LIMIT", "pointer coverage index"))?,
    )?;
    budget.edges(count)?;
    let mut nodes = BTreeMap::new();
    let mut object_count = 0usize;
    for typ in source {
        budget.work(96)?;
        profile!(field(typ, "domain")? == field(&domains[0], "id")?);
        for name in ["qualifiers", "methods", "enumerators"] {
            profile!(list(field(typ, name)?)?.is_empty());
        }
        profile!(optional(field(typ, "record_input")?)?.is_none());
        let identity = field(typ, "identity")?;
        profile!(
            matches!(text(field(identity, "language")?)?, "c23" | "cpp23")
                && text(field(identity, "linkage")?)? == "builtin"
                && optional(field(identity, "library")?)?.is_none()
                && optional(field(identity, "unit")?)?.is_none()
        );
        let shape = match text(field(typ, "kind")?)? {
            "scalar" => {
                let Some((bits, signed)) = integer(text(field(identity, "entity")?)?) else {
                    return Ok(false);
                };
                profile!(
                    uint(field(typ, "bits")?)? == u64::from(bits)
                        && boolean(field(typ, "signed")?)? == signed
                        && text(field(typ, "representation")?)? == "value"
                        && list(field(typ, "elements")?)?.is_empty()
                        && optional(field(typ, "extent")?)?.is_none()
                        && optional(field(typ, "layout")?)?.is_some()
                        && exact_flags(typ, &["complete", "trivial_copy", "trivial_destroy"])?
                );
                let Some(execution) = optional(field(typ, "execution")?)? else {
                    return Ok(false);
                };
                profile!(integer_execution(types, execution, bits)?);
                object_count += 1;
                Shape::Integer {
                    bits,
                    bytes: u64::from(bits / 8),
                }
            }
            "pointer" => {
                profile!(
                    text(field(identity, "entity")?)? == "pointer"
                        && uint(field(typ, "bits")?)? == 64
                        && !boolean(field(typ, "signed")?)?
                        && text(field(typ, "representation")?)? == "value"
                        && list(field(typ, "elements")?)?.len() == 1
                        && optional(field(typ, "extent")?)?.is_none()
                        && optional(field(typ, "layout")?)?.is_some()
                        && exact_flags(typ, &["complete", "trivial_copy", "trivial_destroy"])?
                );
                let Some(execution) = optional(field(typ, "execution")?)? else {
                    return Ok(false);
                };
                profile!(physical_execution(types, execution, Physical::Pointer)?);
                object_count += 1;
                Shape::Pointer
            }
            "void" => {
                profile!(
                    text(field(identity, "entity")?)? == "void"
                        && uint(field(typ, "bits")?)? == 0
                        && !boolean(field(typ, "signed")?)?
                        && text(field(typ, "representation")?)? == "none"
                        && optional(field(typ, "execution")?)?.is_none()
                        && optional(field(typ, "layout")?)?.is_none()
                        && optional(field(typ, "extent")?)?.is_none()
                        && list(field(typ, "elements")?)?.is_empty()
                );
                for flag in list(field(typ, "flags")?)? {
                    budget.work(1)?;
                    profile!(matches!(
                        text(flag)?,
                        "complete" | "trivial_copy" | "trivial_destroy"
                    ));
                }
                Shape::Void
            }
            "function" => {
                profile!(
                    text(field(identity, "entity")?)? == "function"
                        && uint(field(typ, "bits")?)? == 0
                        && !boolean(field(typ, "signed")?)?
                        && optional(field(typ, "layout")?)?.is_none()
                );
                let execution = optional(field(typ, "execution")?)?;
                profile!(
                    text(field(typ, "representation")?)?
                        == if execution.is_some() {
                            "signature"
                        } else {
                            "none"
                        }
                );
                if let Some(execution) = execution {
                    profile!(local(execution)?.is_some());
                }
                let flags = list(field(typ, "flags")?)?;
                profile!(flags.iter().any(|v| text(v) == Ok("complete")));
                for flag in flags {
                    budget.work(1)?;
                    profile!(matches!(text(flag)?, "complete" | "c_linkage"));
                }
                Shape::Function
            }
            _ => return Ok(false),
        };
        nodes.insert(id(field(typ, "id")?)?, (typ, shape));
    }
    // Pointee source identity stays original; only integer/void pointees are
    // represented here. All source rows were checked before resolving edges.
    for (typ, shape) in nodes.values() {
        if matches!(shape, Shape::Pointer) {
            budget.work(32)?;
            let elements = list(field(typ, "elements")?)?;
            let Some(pointee) = local(&elements[0])? else {
                return Ok(false);
            };
            profile!(matches!(
                nodes.get(&pointee),
                Some((_, Shape::Integer { .. } | Shape::Void))
            ));
        }
    }
    profile!(layouts.len() == object_count);
    for layout in layouts {
        budget.work(96)?;
        let Some(target) = local(field(layout, "type")?)? else {
            return Ok(false);
        };
        let bytes = match nodes.get(&target) {
            Some((_, Shape::Integer { bytes, .. })) => *bytes,
            Some((_, Shape::Pointer)) => 8,
            _ => return Ok(false),
        };
        for name in [
            "size",
            "align",
            "data_size",
            "nonvirtual_size",
            "nonvirtual_align",
        ] {
            profile!(uint(field(layout, name)?)? == bytes);
        }
        for name in ["fields", "bases", "vptrs"] {
            profile!(list(field(layout, name)?)?.is_empty());
        }
    }
    for (typ, shape) in nodes.values() {
        if !matches!(shape, Shape::Function) {
            continue;
        }
        budget.work(32)?;
        let elements = list(field(typ, "elements")?)?;
        budget.edges(elements.len())?;
        profile!(!elements.is_empty());
        profile!(
            optional(field(typ, "extent")?)?.map(uint).transpose()?
                == Some((elements.len() - 1) as u64)
        );
        for (position, reference) in elements.iter().enumerate() {
            budget.work(32)?;
            let Some(target) = local(reference)? else {
                return Ok(false);
            };
            profile!(
                matches!(
                    nodes.get(&target),
                    Some((_, Shape::Integer { .. } | Shape::Pointer))
                ) || (position + 1 == elements.len()
                    && matches!(nodes.get(&target), Some((_, Shape::Void))))
            );
        }
    }
    let mut used_pointer = false;
    for plan in plans {
        budget.work(96)?;
        let Some(function_id) = local(field(plan, "function_type")?)? else {
            return Ok(false);
        };
        let Some((function, Shape::Function)) = nodes.get(&function_id) else {
            return Ok(false);
        };
        profile!(
            optional(field(plan, "this_type")?)?.is_none()
                && optional(field(plan, "varargs")?)?.is_none()
                && !boolean(field(plan, "vtt")?)?
                && !boolean(field(plan, "variadic")?)?
                && !boolean(field(plan, "noexcept")?)?
        );
        let execution = field(plan, "execution")?;
        profile!(local(execution)?.is_some());
        let physical = types.type_record(types.type_reference(execution)?)?;
        profile!(
            text(field(physical, "kind")?)? == "function"
                && text(field(physical, "cc")?)? == "portable"
                && !boolean(field(physical, "variadic")?)?
        );
        let params = list(field(plan, "params")?)?;
        let lowered = list(field(plan, "lowered_params")?)?;
        let physical_params = list(field(physical, "params")?)?;
        budget.edges(
            params
                .len()
                .checked_mul(3)
                .and_then(|n| n.checked_add(2))
                .ok_or_else(|| Error::resource("ABI_CC_PROFILE_LIMIT", "pointer plan edges"))?,
        )?;
        profile!(params.len() == lowered.len() && params.len() == physical_params.len());
        for (position, ((reference, argument), actual)) in
            params.iter().zip(lowered).zip(physical_params).enumerate()
        {
            budget.work(64)?;
            let Some((physical_shape, bytes)) = value(&nodes, reference, budget)? else {
                return Ok(false);
            };
            used_pointer |= matches!(physical_shape, Physical::Pointer);
            profile!(
                value(&nodes, field(argument, "source_type")?, budget)?.is_some()
                    && value(&nodes, field(argument, "value_type")?, budget)?.is_some()
                    && text(field(argument, "role")?)? == "parameter"
                    && text(field(argument, "mode")?)? == "direct"
                    && optional(field(argument, "source_index")?)?
                        .map(uint)
                        .transpose()?
                        == Some(position as u64)
                    && uint(field(argument, "align")?)? == bytes
                    && uint(field(argument, "bytes")?)? == bytes
                    && physical_execution(types, actual, physical_shape)?
            );
            for name in ["copy", "move", "destroy"] {
                profile!(optional(field(argument, name)?)?.is_none());
            }
        }
        let results = list(field(plan, "lowered_results")?)?;
        let physical_results = list(field(physical, "results")?)?;
        if let Some(result) = optional(field(plan, "result")?)? {
            let Some((physical_shape, _)) = value(&nodes, result, budget)? else {
                return Ok(false);
            };
            used_pointer |= matches!(physical_shape, Physical::Pointer);
            profile!(
                results.len() == 1
                    && physical_results.len() == 1
                    && value(&nodes, &results[0], budget)?.is_some()
                    && physical_execution(types, &physical_results[0], physical_shape)?
            );
        } else {
            // The full source verifier already proves this last element is void;
            // this profile retains canonical None, never normalizes Some(void).
            let elements = list(field(function, "elements")?)?;
            let Some(last) = elements.last() else {
                return Ok(false);
            };
            let Some(target) = local(last)? else {
                return Ok(false);
            };
            profile!(
                matches!(nodes.get(&target), Some((_, Shape::Void)))
                    && results.is_empty()
                    && physical_results.is_empty()
            );
        }
    }
    Ok(used_pointer)
}
