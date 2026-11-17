//! Explicit temporary coverage boundary, never a replacement for validation.

use super::{nominal::self_id, value::*};
use crate::{
    Error, ErrorClass,
    context::ObjectContext,
    execution::{TypeFacts, TypeKind},
    limits::Budget,
    wire::RecordValue,
};

fn unknown() -> Error {
    Error::new(
        ErrorClass::UnavailableEvidence,
        "P2_ABI_VERIFIER_INCOMPLETE",
        "present ABI form is outside the audited scalar profile",
    )
}
fn covered(condition: bool) -> Result<(), Error> {
    if condition { Ok(()) } else { Err(unknown()) }
}

pub(super) fn check(
    ctx: &ObjectContext,
    types: &TypeFacts,
    canonical: &super::builtin_state::Coverage,
    budget: &mut Budget,
) -> Result<(), Error> {
    // ABI-PROD016: actual root, runtime and semantics ACKs received. Every
    // source predicate still runs before this explicit coverage boundary.
    let root = ctx.root(10)?;
    for name in ["recipes", "personalities", "unwind", "catches", "bridges"] {
        budget.work(1)?;
        covered(list(field(root, name)?)?.is_empty())?;
    }
    if super::scalar_calls::covered(ctx, types, budget)? {
        return Ok(());
    }
    if super::pointer_calls::covered(ctx, types, budget)? {
        return Ok(());
    }
    if super::nonordinary_entries::covered(ctx, types, budget)? {
        return Ok(());
    }
    let all_source = list(field(root, "types")?)?;
    let all_layouts = list(field(root, "layouts")?)?;
    let declarations = source_address_declarations(root, types, canonical, budget)?;
    budget.reserve_bytes((all_source.len() + all_layouts.len()).checked_mul(16)
        .ok_or_else(|| Error::resource("ABI_CC_PROFILE_LIMIT", "coverage views"))?)?;
    let mut source = Vec::new();
    for value in all_source {
        if !declarations.contains(&id(field(value, "id")?)?) { source.push(value); }
    }
    let mut layouts = Vec::new();
    for value in all_layouts {
        if !declarations.contains(&self_id(field(value, "type")?)?) { layouts.push(value); }
    }
    let signatures = list(field(root, "signatures")?)?;
    let domains = list(field(root, "domains")?)?;
    covered(
        source.len() >= 2
            && layouts.len() == source.len() - 1
            && signatures.len() == 1
            && domains.len() == 1,
    )?;
    let domain = &domains[0];
    for name in ["isa", "abi", "personality"] {
        covered(text(field(domain, name)?)? == "portable")?;
    }
    let mut scalar = None;
    let mut function = None;
    let mut pointer = None;
    for nominal in source {
        budget.work(32)?;
        covered(field(nominal, "domain")? == field(domain, "id")?)?;
        if canonical.nodes.contains(&id(field(nominal, "id")?)?) {
            covered(all_self(nominal, 0, budget)?)?;
            continue;
        }
        for name in ["qualifiers", "methods", "enumerators"] {
            covered(list(field(nominal, name)?)?.is_empty())?;
        }
        let identity = field(nominal, "identity")?;
        covered(
            matches!(text(field(identity, "language")?)?, "c23" | "cpp23")
                && text(field(identity, "linkage")?)? == "builtin"
                && optional(field(identity, "library")?)?.is_none()
                && optional(field(identity, "unit")?)?.is_none(),
        )?;
        let execution = if text(field(nominal, "kind")?)? == "function" {
            covered(signatures.len() == 1 && self_id(field(&signatures[0], "function_type")?).ok()
                == Some(id(field(nominal, "id")?)?))?;
            field(&signatures[0], "execution")?
        } else { optional(field(nominal, "execution")?)?.ok_or_else(unknown)? };
        self_id(execution).map_err(|_| unknown())?;
        match text(field(nominal, "kind")?)? {
            "scalar" => {
                covered(
                    scalar.is_none()
                        && text(field(identity, "entity")?)? == "int"
                        && uint(field(nominal, "bits")?)? == 32
                        && boolean(field(nominal, "signed")?)?
                        && text(field(nominal, "representation")?)? == "value"
                        && list(field(nominal, "elements")?)?.is_empty()
                        && optional(field(nominal, "extent")?)?.is_none()
                        && optional(field(nominal, "layout")?)?.is_some(),
                )?;
                covered(exact_flags(
                    nominal,
                    &["complete", "trivial_copy", "trivial_destroy"],
                )?)?;
                scalar = Some(nominal);
            }
            "pointer" => {
                covered(
                    pointer.is_none()
                        && text(field(identity, "entity")?)? == "pointer"
                        && uint(field(nominal, "bits")?)? == 64
                        && !boolean(field(nominal, "signed")?)?
                        && text(field(nominal, "representation")?)? == "value"
                        && optional(field(nominal, "extent")?)?.is_none()
                        && optional(field(nominal, "layout")?)?.is_some(),
                )?;
                covered(exact_flags(
                    nominal,
                    &["complete", "trivial_copy", "trivial_destroy"],
                )?)?;
                covered(matches!(
                    types.kind(types.type_reference(execution)?)?,
                    TypeKind::DataPtr
                ))?;
                pointer = Some(nominal);
            }
            "function" => {
                covered(
                    function.is_none()
                        && text(field(identity, "entity")?)? == "function"
                        && uint(field(nominal, "bits")?)? == 0
                        && !boolean(field(nominal, "signed")?)?
                        && matches!(text(field(nominal, "representation")?)?, "signature" | "none")
                        && optional(field(nominal, "layout")?)?.is_none()
                        && optional(field(nominal, "extent")?)?.map(uint).transpose()? == Some(1),
                )?;
                covered(exact_flags(nominal, &["complete"])?)?;
                function = Some(nominal);
            }
            _ => return Err(unknown()),
        }
    }
    let scalar = scalar.ok_or_else(unknown)?;
    let function = function.ok_or_else(unknown)?;
    let scalar_execution = optional(field(scalar, "execution")?)?.ok_or_else(unknown)?;
    covered(matches!(
        types.kind(types.type_reference(scalar_execution)?)?,
        TypeKind::Int(32)
    ))?;
    let scalar_id = id(field(scalar, "id")?)?;
    let function_id = id(field(function, "id")?)?;
    let elements = list(field(function, "elements")?)?;
    covered(elements.len() == 2)?;
    for element in elements {
        covered(self_id(element).ok() == Some(scalar_id))?;
    }
    let pointer_id = pointer.map(|value| id(field(value, "id")?)).transpose()?;
    if let Some(pointer) = pointer {
        let elements = list(field(pointer, "elements")?)?;
        covered(elements.len() == 1 && self_id(&elements[0]).ok() == Some(scalar_id))?;
    }
    for layout in layouts {
        budget.work(16)?;
        let target = self_id(field(layout, "type")?).map_err(|_| unknown())?;
        if canonical.nodes.contains(&target) { continue; }
        let size = if target == scalar_id {
            4
        } else {
            covered(Some(target) == pointer_id)?;
            8
        };
        for name in [
            "size",
            "align",
            "data_size",
            "nonvirtual_size",
            "nonvirtual_align",
        ] {
            covered(uint(field(layout, name)?)? == size)?;
        }
        for name in ["fields", "bases", "vptrs"] {
            covered(list(field(layout, name)?)?.is_empty())?;
        }
    }
    for binding in list(field(root, "storage_bindings")?)? {
        budget.work(64)?;
        let target = self_id(field(binding, "nominal")?).map_err(|_| unknown())?;
        self_id(field(binding, "execution_layout")?).map_err(|_| unknown())?;
        let (size, alignment) = if target == scalar_id {
            (4,4)
        } else if Some(target) == pointer_id {
            (8,8)
        } else if declarations.contains(&target) {
            // Declaration coverage includes NONOBJECT nodes. Only an actual
            // complete pointer representation may gain this8B object coverage.
            let mut found_pointer = false;
            for nominal in all_source {
                budget.work(1)?;
                if id(field(nominal, "id")?)? != target { continue; }
                covered(text(field(nominal, "kind")?)? == "pointer"
                    && optional(field(nominal, "layout")?)?.is_some())?;
                let execution = optional(field(nominal, "execution")?)?.ok_or_else(unknown)?;
                let shape = types.kind(types.type_reference(execution)?)?;
                covered(match text(field(nominal, "representation")?)? {
                    "value" => matches!(shape, TypeKind::DataPtr),
                    "code_address" => matches!(shape, TypeKind::CodeAddress),
                    _ => false,
                })?;
                found_pointer = true;
                break;
            }
            covered(found_pointer)?;
            (8,8)
        } else {
            covered(canonical.states.contains(&target) || canonical.wrappers.contains(&target))?;
            (32,8)
        };
        let kind = text(field(binding, "kind")?)?;
        covered(
            matches!(kind, "allocation" | "object_bytes")
                && uint(field(binding, "view_offset_bits")?)? == 0
                && uint(field(binding, "view_width_bits")?)? == size * 8
                && uint(field(binding, "required_alignment")?)? == alignment
                && uint(field(binding, "access_bytes")?)? == size,
        )?;
        let fragments = list(field(binding, "fragments")?)?;
        covered(fragments.len() == 1)?;
        let fragment = &fragments[0];
        covered(
            list(field(fragment, "source_path")?)?.is_empty()
                && uint(field(fragment, "source_offset_bits")?)? == 0
                && uint(field(fragment, "execution_offset_bits")?)? == 0
                && uint(field(fragment, "width_bits")?)? == size * 8
                && text(field(fragment, "role")?)?
                    == if kind == "allocation" {
                        "object_representation"
                    } else {
                        "value"
                    },
        )?;
    }
    let signature = &signatures[0];
    covered(self_id(field(signature, "function_type")?).ok() == Some(function_id))?;
    covered(
        optional(field(signature, "this_type")?)?.is_none()
            && optional(field(signature, "varargs")?)?.is_none(),
    )?;
    for name in ["vtt", "variadic", "noexcept"] {
        covered(!boolean(field(signature, name)?)?)?;
    }
    let params = list(field(signature, "params")?)?;
    let lowered = list(field(signature, "lowered_params")?)?;
    let results = list(field(signature, "lowered_results")?)?;
    covered(params.len() == 1 && lowered.len() == 1 && results.len() == 1)?;
    covered(
        self_id(&params[0]).ok() == Some(scalar_id)
            && self_id(&results[0]).ok() == Some(scalar_id)
            && optional(field(signature, "result")?)?
                .map(self_id)
                .transpose()?
                .is_some_and(|id| id == scalar_id),
    )?;
    let parameter = &lowered[0];
    covered(
        text(field(parameter, "role")?)? == "parameter"
            && text(field(parameter, "mode")?)? == "direct"
            && self_id(field(parameter, "source_type")?).ok() == Some(scalar_id)
            && self_id(field(parameter, "value_type")?).ok() == Some(scalar_id),
    )?;
    for name in ["copy", "move", "destroy"] {
        covered(optional(field(parameter, name)?)?.is_none())?;
    }
    // ABI-PROD018: source-local trivial journals have no lifecycle effects.
    for journal in list(field(root, "journals")?)? {
        budget.work(64)?;
        covered(
            field(journal, "signature")? == field(signature, "id")?
                && list(field(journal, "params")?)?.is_empty(),
        )?;
        let slots = list(field(journal, "slots")?)?;
        covered(slots.len() == 1)?;
        let slot = &slots[0];
        covered(
            self_id(field(slot, "type")?).ok() == Some(scalar_id)
                && field(slot, "owner")? == field(domain, "id")?
                && text(field(slot, "role")?)? == "root"
                && text(field(slot, "destructor_kind")?)? == "none",
        )?;
        for (name, expected) in [
            ("offset", 0),
            ("extent", 4),
            ("align", 4),
            ("count", 1),
            ("stride", 4),
        ] {
            covered(uint(field(slot, name)?)? == expected)?;
        }
        for name in [
            "parent",
            "count_source",
            "constructor",
            "destructor",
            "child_program",
        ] {
            covered(optional(field(slot, name)?)?.is_none())?;
        }
        for name in ["covers", "dependencies"] {
            covered(list(field(slot, name)?)?.is_empty())?;
        }
        for name in ["normal_order", "exception_order"] {
            let order = list(field(journal, name)?)?;
            covered(order.len() == 1 && order[0] == *field(slot, "id")?)?;
        }
    }
    Ok(())
}

// Proposed finite static coverage only. All semantic/layout/default predicates
// execute before this guard. This set supplies no code entry or object instance.
fn source_address_declarations(
    root: &RecordValue,
    types: &TypeFacts,
    canonical: &super::builtin_state::Coverage,
    budget: &mut Budget,
) -> Result<std::collections::BTreeSet<u32>, Error> {
    use std::collections::{BTreeMap, BTreeSet};
    let source = list(field(root, "types")?)?;
    let plans = list(field(root, "signatures")?)?;
    if plans.len() != 1 { return Ok(BTreeSet::new()); }
    let callable = self_id(field(&plans[0], "function_type")?).map_err(|_| unknown())?;
    budget.reserve_bytes(source.len().checked_mul(128).ok_or_else(||
        Error::resource("ABI_CC_PROFILE_LIMIT", "declaration index"))?)?;
    let mut index = BTreeMap::new();
    let mut scalar = None;
    let mut pending = Vec::new();
    for typ in source {
        budget.work(1)?;
        let identifier = id(field(typ, "id")?)?;
        index.insert(identifier, typ);
        if text(field(typ, "kind")?)? == "scalar"
            && text(field(field(typ, "identity")?, "entity")?)? == "int"
            && uint(field(typ, "bits")?)? == 32 && boolean(field(typ, "signed")?)?
        {
            // An extra duplicate remains uncovered by the original scalar guard.
            if scalar.is_none() { scalar = Some(identifier); }
        }
        if text(field(typ, "kind")?)? == "pointer"
            && text(field(typ, "representation")?)? == "code_address"
        {
            budget.reserve_bytes(16)?;
            pending.push(identifier);
        }
    }
    let mut covered_nodes = BTreeSet::new();
    while let Some(identifier) = pending.pop() {
        budget.work(1)?;
        if identifier == callable || Some(identifier) == scalar || canonical.nodes.contains(&identifier) {
            continue;
        }
        budget.reserve_bytes(128)?;
        if !covered_nodes.insert(identifier) { continue; }
        let typ = index.get(&identifier).ok_or_else(unknown)?;
        covered(all_self(typ, 0, budget)?)?;
        for name in ["qualifiers", "methods", "enumerators"] {
            covered(list(field(typ, name)?)?.is_empty())?;
        }
        let identity = field(typ, "identity")?;
        covered(optional(field(identity, "library")?)?.is_none()
            && optional(field(identity, "unit")?)?.is_none())?;
        let kind = text(field(typ, "kind")?)?;
        let execution = optional(field(typ, "execution")?)?;
        match kind {
            "pointer" => {
                covered(text(field(identity, "linkage")?)? == "builtin"
                    && uint(field(typ, "bits")?)? == 64 && !boolean(field(typ, "signed")?)?)?;
                let handle = types.type_reference(execution.ok_or_else(unknown)?)?;
                if text(field(typ, "representation")?)? == "code_address" {
                    covered(matches!(types.kind(handle)?, TypeKind::CodeAddress)
                        && exact_flags(typ, &["complete", "trivial_copy", "trivial_destroy", "code"])?)?;
                } else {
                    covered(text(field(typ, "representation")?)? == "value"
                        && matches!(types.kind(handle)?, TypeKind::DataPtr)
                        && exact_flags(typ, &["complete", "trivial_copy", "trivial_destroy"])?)?;
                }
            }
            "function" => {
                covered(execution.is_none() && text(field(typ, "representation")?)? == "none"
                    && optional(field(typ, "layout")?)?.is_none()
                    && text(field(identity, "linkage")?)? == "builtin"
                    && flags(typ, "flags", "complete")?)?;
                for flag in list(field(typ, "flags")?)? {
                    covered(matches!(text(flag)?, "complete" | "noexcept" | "variadic" | "c_linkage"))?;
                }
            }
            "record" | "array" | "void" => {
                covered(execution.is_none() && text(field(typ, "representation")?)? == "none"
                    && optional(field(typ, "layout")?)?.is_none()
                    && optional(field(typ, "record_input")?)?.is_none()
                    && uint(field(typ, "bits")?)? == 0 && !boolean(field(typ, "signed")?)?)?;
                if kind == "record" {
                    covered(text(field(identity, "linkage")?)? == "external"
                        && list(field(typ, "flags")?)?.is_empty()
                        && list(field(typ, "elements")?)?.is_empty())?;
                } else if kind == "array" {
                    covered(list(field(typ, "flags")?)?.is_empty())?;
                } else {
                    covered(text(field(identity, "linkage")?)? == "builtin"
                        && optional(field(typ, "extent")?)?.is_none()
                        && list(field(typ, "elements")?)?.is_empty())?;
                    for flag in list(field(typ, "flags")?)? {
                        covered(matches!(text(flag)?, "complete" | "trivial_copy" | "trivial_destroy"))?;
                    }
                }
            }
            _ => return Err(unknown()),
        }
        let elements = list(field(typ, "elements")?)?;
        budget.reserve_bytes(elements.len().checked_mul(16).ok_or_else(||
            Error::resource("ABI_CC_PROFILE_LIMIT", "declaration frontier"))?)?;
        budget.edges(elements.len())?;
        for child in elements { pending.push(self_id(child).map_err(|_| unknown())?); }
    }
    Ok(covered_nodes)
}

fn exact_flags(value: &RecordValue, expected: &[&str]) -> Result<bool, Error> {
    let values = list(field(value, "flags")?)?;
    if values.len() != expected.len() {
        return Ok(false);
    }
    Ok(expected
        .iter()
        .all(|name| values.iter().any(|value| text(value).ok() == Some(*name))))
}

// Profile scope only: genuine consumer/provider obligations are retained by the
// semantic phase, but this finite source profile has no dependency-owned forms.
fn all_self(value: &RecordValue, depth: u32, budget: &mut Budget) -> Result<bool, Error> {
    budget.work(1)?;
    if depth >= 128 { return Err(Error::resource("ABI_CC_PROFILE_DEPTH", "source profile traversal")); }
    match value {
        RecordValue::Record(fields) => {
            if fields.contains_key("module") && fields.contains_key("id") {
                return Ok(self_id(value).is_ok());
            }
            for child in fields.values() {
                if !all_self(child, depth+1, budget)? { return Ok(false); }
            }
        }
        RecordValue::Vector(values) => for child in values {
            if !all_self(child, depth+1, budget)? { return Ok(false); }
        },
        RecordValue::Option(Some(child)) => return all_self(child, depth+1, budget),
        _ => {}
    }
    Ok(true)
}
