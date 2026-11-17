//! Exact hidden/source parameter classification and complete call-plan equality.

use super::{
    nominal::{Graph, self_ref},
    value::*,
};
use crate::{
    Error,
    execution::{TypeFacts, TypeKind},
    limits::Budget,
    wire::RecordValue,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

type Table = BTreeMap<u32, Arc<RecordValue>>;

fn same_domain(a: &RecordValue, b: &RecordValue, budget: &mut Budget) -> Result<bool, Error> {
    for name in ["isa", "personality", "abi", "abi_identity"] {
        budget.work(1)?;
        if field(a, name)? != field(b, name)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn source_equal(
    a: &Graph,
    ar: &RecordValue,
    b: &Graph,
    br: &RecordValue,
    c: bool,
    root_noexcept: bool,
    budget: &mut Budget,
) -> Result<bool, Error> {
    let (x, xc, xp) = a.normalized_view(a.resolve(ar)?, false, c, root_noexcept, budget)?;
    let (y, yc, yp) = b.normalized_view(b.resolve(br)?, false, c, root_noexcept, budget)?;
    budget.work(
        (a.family.0.len() + a.family.1.len() + b.family.0.len() + b.family.1.len() + 1) as u64,
    )?;
    if (xp || yp) && a.family != b.family {
        return Ok(false);
    }
    let bytes = x
        .len()
        .checked_add(y.len())
        .ok_or_else(|| Error::resource("ABI_CC_GRAPH_LIMIT", "canonical comparison size"))?;
    budget.work(
        u64::try_from(bytes)
            .map_err(|_| Error::resource("ABI_CC_GRAPH_LIMIT", "comparison work"))?,
    )?;
    Ok((!c || xc && yc) && x == y)
}

fn source_lists(
    a: &Graph,
    xs: &[RecordValue],
    b: &Graph,
    ys: &[RecordValue],
    c: bool,
    budget: &mut Budget,
) -> Result<bool, Error> {
    if xs.len() != ys.len() {
        return Ok(false);
    }
    for (x, y) in xs.iter().zip(ys) {
        budget.work(1)?;
        if !source_equal(a, x, b, y, c, false, budget)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn ordinary_recipe_interface(
    a: &Graph,
    ar: &RecordValue,
    b: &Graph,
    br: &RecordValue,
    at: &Table,
    bt: &Table,
    c: bool,
    budget: &mut Budget,
) -> Result<bool, Error> {
    let (x, y) = match (optional(ar)?, optional(br)?) {
        (None, None) => return Ok(true),
        (Some(x), Some(y)) => (x, y),
        _ => return Ok(false),
    };
    let x = at
        .get(&id(x)?)
        .ok_or_else(|| Error::semantic("ABI_CC_ENTITY_REFERENCE", "actual recipe"))?;
    let y = bt
        .get(&id(y)?)
        .ok_or_else(|| Error::semantic("ABI_CC_ENTITY_REFERENCE", "expected recipe"))?;
    let ad = a
        .domains
        .get(&id(field(x, "domain")?)?)
        .ok_or_else(|| Error::semantic("ABI_CC_TYPE_DOMAIN", "recipe"))?;
    let bd = b
        .domains
        .get(&id(field(y, "domain")?)?)
        .ok_or_else(|| Error::semantic("ABI_CC_TYPE_DOMAIN", "recipe"))?;
    if !same_domain(ad, bd, budget)? {
        return Ok(false);
    }
    let xp = list(field(x, "params")?)?;
    let yp = list(field(y, "params")?)?;
    if xp.len() != yp.len() {
        return Ok(false);
    }
    for (x, y) in xp.iter().zip(yp) {
        if !source_equal(a, field(x, "type")?, b, field(y, "type")?, c, false, budget)? {
            return Ok(false);
        }
    }
    source_lists(
        a,
        list(field(x, "results")?)?,
        b,
        list(field(y, "results")?)?,
        c,
        budget,
    )
}

/// Full paired execution traversal through each immutable TypeFacts. No hashes,
/// shared numeric IDs or synthetic expected Fn can stand in for descriptors.
fn execution_children(value: &RecordValue) -> Result<Vec<&RecordValue>, Error> {
    Ok(match text(field(value, "kind")?)? {
        "function" => list(field(value, "params")?)?
            .iter()
            .chain(list(field(value, "results")?)?)
            .collect(),
        "struct" => list(field(value, "fields")?)?.iter().collect(),
        "array" | "vector" => vec![field(value, "element")?],
        "code_ptr" => vec![field(value, "signature")?],
        "int" | "raw" | "float" | "data_ptr" | "code_address" | "exception" | "fenv"
        | "stack_mark" | "va_list" | "journal" => vec![],
        _ => {
            return Err(Error::new(
                crate::ErrorClass::UnavailableEvidence,
                "ABI_CC_TYPE_UNAVAILABLE",
                "execution constructor",
            ));
        }
    })
}

fn execution_equal(
    a: &TypeFacts,
    ar: &RecordValue,
    b: &TypeFacts,
    br: &RecordValue,
    budget: &mut Budget,
) -> Result<bool, Error> {
    budget.reserve_bytes(128)?;
    let mut pending = vec![(a.type_reference(ar)?, b.type_reference(br)?)];
    let mut seen = BTreeSet::new();
    while let Some((x, y)) = pending.pop() {
        budget.work(1)?;
        budget.reserve_bytes(128)?;
        if !seen.insert((x, y)) {
            continue;
        }
        let xr = a.type_record(x)?;
        let yr = b.type_record(y)?;
        let mut xl = super::nominal::json(xr, budget)?;
        let mut yl = super::nominal::json(yr, budget)?;
        // Reserve child vectors before collecting them; raw records were
        // separately charged by json() above, including all scalar payload.
        let count = |value: &RecordValue| -> Result<usize, Error> {
            Ok(match text(field(value, "kind")?)? {
                "function" => list(field(value, "params")?)?
                    .len()
                    .checked_add(list(field(value, "results")?)?.len())
                    .ok_or_else(|| Error::resource("ABI_CC_GRAPH_LIMIT", "Fn child count"))?,
                "struct" => list(field(value, "fields")?)?.len(),
                "array" | "vector" | "code_ptr" => 1,
                _ => 0,
            })
        };
        let count = count(xr)?
            .checked_add(count(yr)?)
            .ok_or_else(|| Error::resource("ABI_CC_GRAPH_LIMIT", "children"))?;
        budget.reserve_bytes(
            count
                .checked_mul(32)
                .ok_or_else(|| Error::resource("ABI_CC_GRAPH_LIMIT", "children"))?,
        )?;
        let xc = execution_children(xr)?;
        let yc = execution_children(yr)?;
        for (label, raw) in [(&mut xl, xr), (&mut yl, yr)] {
            let map = label
                .as_object_mut()
                .ok_or_else(|| Error::semantic("ABI_CC_RECORD", "type"))?;
            for field in ["id", "fields", "params", "results", "element", "signature"] {
                map.remove(field);
            }
            if text(field(raw, "kind")?)? == "function" {
                map.insert(
                    "parameter_count".into(),
                    serde_json::Value::from(list(field(raw, "params")?)?.len() as u64),
                );
                map.insert(
                    "result_count".into(),
                    serde_json::Value::from(list(field(raw, "results")?)?.len() as u64),
                );
            }
        }
        if xl != yl || xc.len() != yc.len() {
            return Ok(false);
        }
        budget.edges(xc.len())?;
        budget.reserve_bytes(
            xc.len()
                .checked_mul(32)
                .ok_or_else(|| Error::resource("ABI_CC_GRAPH_LIMIT", "pairs"))?,
        )?;
        for (x, y) in xc.into_iter().zip(yc) {
            pending.push((a.type_reference(x)?, b.type_reference(y)?));
        }
    }
    Ok(true)
}

pub(crate) fn ordinary_compatible(
    a: &Graph,
    ar: &RecordValue,
    ax: &TypeFacts,
    b: &Graph,
    br: &RecordValue,
    bx: &TypeFacts,
    recipes_a: &Table,
    recipes_b: &Table,
    budget: &mut Budget,
) -> Result<bool, Error> {
    if optional(field(ar, "this_type")?)?.is_some()
        || optional(field(br, "this_type")?)?.is_some()
        || boolean(field(ar, "vtt")?)?
        || boolean(field(br, "vtt")?)?
    {
        return Ok(false);
    }
    let af = a.typ(field(ar, "function_type")?)?;
    let bf = b.typ(field(br, "function_type")?)?;
    let ad = a.domain(af)?;
    let bd = b.domain(bf)?;
    if text(field(ad, "isa")?)? != "portable" || text(field(bd, "isa")?)? != "portable" {
        return Err(Error::new(
            crate::ErrorClass::UnavailableEvidence,
            "ABI_CC_NATIVE_CALL",
            "actual portable-facing ordinary plans required",
        ));
    }
    if !same_domain(ad, bd, budget)? {
        return Ok(false);
    }
    let c = flags(af, "flags", "c_linkage")?;
    if c != flags(bf, "flags", "c_linkage")?
        || (!boolean(field(ar, "noexcept")?)? && boolean(field(br, "noexcept")?)?)
    {
        return Ok(false);
    }
    if !source_equal(
        a,
        field(ar, "function_type")?,
        b,
        field(br, "function_type")?,
        c,
        true,
        budget,
    )? {
        return Ok(false);
    }
    for name in ["variadic", "return_noundef"] {
        if field(ar, name)? != field(br, name)? {
            return Ok(false);
        }
    }
    for name in ["params", "lowered_results"] {
        if !source_lists(
            a,
            list(field(ar, name)?)?,
            b,
            list(field(br, name)?)?,
            c,
            budget,
        )? {
            return Ok(false);
        }
    }
    match (
        optional(field(ar, "result")?)?,
        optional(field(br, "result")?)?,
    ) {
        (None, None) => (),
        (Some(x), Some(y)) if source_equal(a, x, b, y, c, false, budget)? => (),
        _ => return Ok(false),
    }
    let ap = list(field(ar, "lowered_params")?)?;
    let bp = list(field(br, "lowered_params")?)?;
    if ap.len() != bp.len() {
        return Ok(false);
    }
    for (x, y) in ap.iter().zip(bp) {
        for name in ["source_index", "role", "mode", "align", "bytes", "noundef"] {
            budget.work(1)?;
            if field(x, name)? != field(y, name)? {
                return Ok(false);
            }
        }
        for name in ["source_type", "value_type"] {
            if !source_equal(a, field(x, name)?, b, field(y, name)?, c, false, budget)? {
                return Ok(false);
            }
        }
        for name in ["copy", "move", "destroy"] {
            if !ordinary_recipe_interface(
                a,
                field(x, name)?,
                b,
                field(y, name)?,
                recipes_a,
                recipes_b,
                c,
                budget,
            )? {
                return Ok(false);
            }
        }
    }
    match (
        optional(field(ar, "varargs")?)?,
        optional(field(br, "varargs")?)?,
    ) {
        (None, None) => (),
        (Some(x), Some(y)) => {
            for name in ["header_bytes", "cookie_scope", "type_reference"] {
                if field(x, name)? != field(y, name)? {
                    return Ok(false);
                }
            }
            let al = a
                .layouts
                .get(&id(field(x, "state_layout")?)?)
                .ok_or_else(|| Error::semantic("ABI_CC_LAYOUT_REFERENCE", "varargs"))?;
            let bl = b
                .layouts
                .get(&id(field(y, "state_layout")?)?)
                .ok_or_else(|| Error::semantic("ABI_CC_LAYOUT_REFERENCE", "varargs"))?;
            if !source_equal(
                a,
                field(al, "type")?,
                b,
                field(bl, "type")?,
                c,
                false,
                budget,
            )? {
                return Ok(false);
            }
        }
        _ => return Ok(false),
    }
    execution_equal(
        ax,
        field(ar, "execution")?,
        bx,
        field(br, "execution")?,
        budget,
    )
}

pub(crate) fn verify(
    graph: &Graph,
    signature: &RecordValue,
    recipes: &Table,
    types: &TypeFacts,
    budget: &mut Budget,
) -> Result<(), Error> {
    budget.work(1)?;
    let function = graph.typ(field(signature, "function_type")?)?;
    let params = list(field(signature, "params")?)?;
    let elements = list(field(function, "elements")?)?;
    let this = optional(field(signature, "this_type")?)?;
    require(
        !(flags(function, "flags", "lvalue_ref")? || flags(function, "flags", "rvalue_ref")?)
            || this.is_some(),
        "ABI_CC_REF_QUALIFIED_THIS",
    )?;
    require(
        this.is_some() || list(field(function, "qualifiers")?)?.is_empty(),
        "ABI_CC_REF_QUALIFIED_THIS",
    )?;
    require(
        text(field(function, "kind")?)? == "function"
            && flags(function, "flags", "complete")?
            && optional(field(function, "extent")?)?
                .is_some_and(|v| uint(v).ok() == Some(params.len() as u64))
            && elements.len() == params.len() + 1
            && flags(function, "flags", "variadic")? == boolean(field(signature, "variadic")?)?
            && flags(function, "flags", "noexcept")? == boolean(field(signature, "noexcept")?)?,
        "ABI_CC_SOURCE_SIGNATURE",
    )?;
    for (a, b) in elements.iter().zip(params) {
        require(
            graph.compatible(graph.resolve(a)?, graph.resolve(b)?, false, budget)?,
            "ABI_CC_SOURCE_SIGNATURE",
        )?;
    }
    let result = optional(field(signature, "result")?)?;
    let last = elements
        .last()
        .ok_or_else(|| Error::semantic("ABI_CC_SOURCE_SIGNATURE", "result element"))?;
    if let Some(result) = result {
        require(
            graph.compatible(graph.resolve(result)?, graph.resolve(last)?, false, budget)?,
            "ABI_CC_SOURCE_SIGNATURE",
        )?;
    } else {
        require(
            text(field(graph.typ(last)?, "kind")?)? == "void",
            "ABI_CC_SOURCE_SIGNATURE",
        )?;
    }
    let mut expected = Vec::new();
    let mut results = Vec::new();
    budget.reserve_bytes(
        params
            .len()
            .checked_add(5)
            .and_then(|n| n.checked_mul(64))
            .ok_or_else(|| Error::resource("ABI_CC_CALL_LIMIT", "parameters"))?,
    )?;
    if let Some(result) = result {
        let typ = representation(graph, result)?;
        if text(field(typ, "kind")?)? == "record" {
            expected.push(("sret", Some(result), None));
        } else if text(field(graph.typ(result)?, "kind")?)? != "void" {
            results.push(result);
        }
    }
    require(
        !boolean(field(signature, "vtt")?)? || this.is_some(),
        "ABI_CC_VTT_WITHOUT_THIS",
    )?;
    if let Some(this) = this {
        expected.push(("this", Some(this), None));
    }
    if boolean(field(signature, "vtt")?)? {
        expected.push(("vtt", None, None));
    }
    for (index, source) in params.iter().enumerate() {
        expected.push(("parameter", Some(source), Some(index as u64)));
    }
    if boolean(field(signature, "variadic")?)? {
        expected.push(("varargs_arena", None, None));
        expected.push(("varargs_bytes", None, None));
    }
    let lowered = list(field(signature, "lowered_params")?)?;
    require(
        expected.len() == lowered.len()
            && results.len() == list(field(signature, "lowered_results")?)?.len(),
        "ABI_CC_CALL_SHAPE",
    )?;
    for (a, b) in results
        .iter()
        .zip(list(field(signature, "lowered_results")?)?)
    {
        require(*a == b, "ABI_CC_CALL_SHAPE")?;
    }
    for ((role, source, index), actual) in expected.iter().zip(lowered) {
        budget.work(1)?;
        require(
            text(field(actual, "role")?)? == *role && boolean(field(actual, "noundef")?)?,
            "ABI_CC_CALL_PARAMETER",
        )?;
        let mode = if *role == "sret" {
            "sret"
        } else if let Some(source) = source {
            if text(field(representation(graph, source)?, "kind")?)? == "record" {
                "indirect_copy"
            } else {
                "direct"
            }
        } else {
            "direct"
        };
        require(
            text(field(actual, "mode")?)? == mode,
            "ABI_CC_CALL_PARAMETER",
        )?;
        if let Some(source) = source {
            let typ = representation(graph, source)?;
            require(
                !matches!(text(field(typ, "kind")?)?, "array" | "function" | "void"),
                "ABI_CC_UNADJUSTED_PARAMETER",
            )?;
            let layout = graph.layout(source)?;
            require(
                field(actual, "source_type")? == *source
                    && field(actual, "align")? == field(layout, "align")?
                    && field(actual, "bytes")? == field(layout, "size")?,
                "ABI_CC_CALL_PARAMETER",
            )?;
            let source_index = optional(field(actual, "source_index")?)?
                .map(uint)
                .transpose()?;
            require(source_index == *index, "ABI_CC_CALL_PARAMETER")?;
        }
        let source_type = field(actual, "source_type")?;
        let value_type = field(actual, "value_type")?;
        let value = graph.typ(value_type)?;
        if *role == "varargs_bytes" {
            require(
                text(field(value, "kind")?)? == "scalar"
                    && uint(field(value, "bits")?)? == 64
                    && !boolean(field(value, "signed")?)?,
                "ABI_CC_VARARGS_LENGTH_TYPE",
            )?;
        } else if matches!(mode, "sret" | "indirect_copy")
            || matches!(*role, "this" | "vtt" | "varargs_arena")
        {
            require(
                text(field(value, "kind")?)? == "pointer",
                "ABI_CC_INDIRECT_TYPE",
            )?;
            if matches!(mode, "sret" | "indirect_copy") {
                let elements = list(field(value, "elements")?)?;
                require(
                    elements.len() == 1
                        && graph.compatible(
                            graph.resolve(&elements[0])?,
                            graph.resolve(source_type)?,
                            false,
                            budget,
                        )?,
                    "ABI_CC_INDIRECT_TYPE",
                )?;
            }
        } else {
            require(
                graph.compatible(
                    graph.resolve(value_type)?,
                    graph.resolve(source_type)?,
                    false,
                    budget,
                )?,
                "ABI_CC_DIRECT_TYPE",
            )?;
        }
        let source = graph.typ(source_type)?;
        if text(field(source, "kind")?)? == "record" && !flags(source, "flags", "trivial_destroy")?
        {
            require(
                optional(field(actual, "destroy")?)?.is_some(),
                "ABI_CC_DESTROY_RECIPE",
            )?;
        }
        for name in ["copy", "move", "destroy"] {
            if let Some(recipe) = optional(field(actual, name)?)? {
                require(
                    recipes.contains_key(&id(recipe)?),
                    "ABI_CC_ADAPTER_REFERENCE",
                )?;
            }
        }
    }
    let binding = optional(field(signature, "varargs")?)?;
    require(
        binding.is_some() == boolean(field(signature, "variadic")?)?,
        "ABI_CC_VARARGS_BINDING",
    )?;
    if let Some(binding) = binding {
        require(
            graph.module_reference_exists(field(binding, "table_module")?)?,
            "ABI_CC_VARARGS_BINDING",
        )?;
        let layout = graph
            .layouts
            .get(&id(field(binding, "state_layout")?)?)
            .ok_or_else(|| Error::semantic("ABI_CC_VARARGS_BINDING", "state layout"))?;
        require(
            uint(field(layout, "size")?)? == 32
                && uint(field(layout, "align")?)? == 8
                && uint(field(binding, "header_bytes")?)? == 32
                && text(field(binding, "cookie_scope")?)? == "thread_activation"
                && text(field(binding, "type_reference")?)? == "nominal_declaration_u32",
            "ABI_CC_VARARGS_BINDING",
        )?;
    }
    let function_handle = types.type_reference(field(signature, "execution")?)?;
    let TypeKind::Function {
        params: actual_params,
        results: actual_results,
        param_noundef,
        result_noundef,
    } = types.kind(function_handle)?
    else {
        return Err(Error::semantic(
            "ABI_CC_LOWERED_SIGNATURE",
            "function shape",
        ));
    };
    require(
        actual_params.len() == lowered.len()
            && actual_results.len() == results.len()
            && param_noundef.len() == lowered.len()
            && result_noundef.len() == results.len(),
        "ABI_CC_LOWERED_SIGNATURE",
    )?;
    for ((parameter, actual), noundef) in lowered.iter().zip(actual_params).zip(param_noundef) {
        let typ = graph.typ(field(parameter, "value_type")?)?;
        let execution = optional(field(typ, "execution")?)?
            .ok_or_else(|| Error::semantic("ABI_CC_LOWERED_SIGNATURE", "parameter execution"))?;
        require(
            *noundef == boolean(field(parameter, "noundef")?)?
                && types.type_equivalent(
                    types.type_handle(*actual)?,
                    types.type_reference(execution)?,
                    budget,
                )?,
            "ABI_CC_LOWERED_SIGNATURE",
        )?;
    }
    for ((result, actual), noundef) in results.iter().zip(actual_results).zip(result_noundef) {
        let execution = optional(field(graph.typ(result)?, "execution")?)?
            .ok_or_else(|| Error::semantic("ABI_CC_LOWERED_SIGNATURE", "result execution"))?;
        require(
            *noundef == boolean(field(signature, "return_noundef")?)?
                && types.type_equivalent(
                    types.type_handle(*actual)?,
                    types.type_reference(execution)?,
                    budget,
                )?,
            "ABI_CC_LOWERED_SIGNATURE",
        )?;
    }
    let raw = types.type_record(function_handle)?;
    require(
        !boolean(field(raw, "variadic")?)? && text(field(raw, "cc")?)? == "portable",
        "ABI_CC_OPEN_EXECUTION_VARIADIC",
    )?;
    Ok(())
}

/// Optional source defaults refer only to independently checked local ordinary
/// plans. Prototype completion alone never manufactures an execution signature.
pub(crate) fn verify_defaults(
    graph: &Graph,
    signatures: &Table,
    types: &TypeFacts,
    budget: &mut Budget,
) -> Result<(), Error> {
    for (identifier, function) in &graph.types {
        budget.work(1)?;
        if text(field(function, "kind")?)? != "function" {
            continue;
        }
        let execution = optional(field(function, "execution")?)?;
        let foreign = text(field(graph.domain(function)?, "isa")?)? != "portable";
        require(!foreign || execution.is_none(), "ABI_CC_FUNCTION_DEFAULT")?;
        let Some(execution) = execution else {
            continue;
        };
        let expected = types.type_reference(execution)?;
        let mut found = false;
        for plan in signatures.values() {
            budget.work(1)?;
            if graph.resolve(field(plan, "function_type")?)? == *identifier
                && optional(field(plan, "this_type")?)?.is_none()
                && !boolean(field(plan, "vtt")?)?
                && types.type_equivalent(
                    expected,
                    types.type_reference(field(plan, "execution")?)?,
                    budget,
                )?
            {
                found = true;
                break;
            }
        }
        require(found, "ABI_CC_FUNCTION_DEFAULT")?;
    }
    Ok(())
}

fn representation<'a>(graph: &'a Graph, reference: &RecordValue) -> Result<&'a RecordValue, Error> {
    let value = graph.typ(reference)?;
    if text(field(value, "kind")?)? == "atomic" {
        let elements = list(field(value, "elements")?)?;
        require(elements.len() == 1, "ABI_CC_ATOMIC_TYPE")?;
        graph.typ(&elements[0])
    } else {
        Ok(value)
    }
}

pub(crate) fn compatible(
    graph: &Graph,
    a: &RecordValue,
    b: &RecordValue,
    recipes: &Table,
    budget: &mut Budget,
) -> Result<bool, Error> {
    if !graph.boundary(
        graph.resolve(field(a, "function_type")?)?,
        graph.resolve(field(b, "function_type")?)?,
        budget,
    )? {
        return Ok(false);
    }
    let af = graph.typ(field(a, "function_type")?)?;
    let bf = graph.typ(field(b, "function_type")?)?;
    let c = flags(af, "flags", "c_linkage")? && flags(bf, "flags", "c_linkage")?;
    let compare = |x: &RecordValue, y: &RecordValue, budget: &mut Budget| -> Result<bool, Error> {
        let x = graph.resolve(x)?;
        let y = graph.resolve(y)?;
        if c {
            graph.c_boundary(x, y, true, budget)
        } else {
            graph.boundary(x, y, budget)
        }
    };
    for name in ["vtt", "variadic", "noexcept", "return_noundef"] {
        budget.work(1)?;
        if field(a, name)? != field(b, name)? {
            return Ok(false);
        }
    }
    for name in ["this_type", "result"] {
        match (optional(field(a, name)?)?, optional(field(b, name)?)?) {
            (None, None) => {}
            (Some(x), Some(y)) => {
                if !compare(x, y, budget)? {
                    return Ok(false);
                }
            }
            _ => return Ok(false),
        }
    }
    for name in ["params", "lowered_results"] {
        let x = list(field(a, name)?)?;
        let y = list(field(b, name)?)?;
        if x.len() != y.len() {
            return Ok(false);
        }
        for (x, y) in x.iter().zip(y) {
            if !compare(x, y, budget)? {
                return Ok(false);
            }
        }
    }
    let ap = list(field(a, "lowered_params")?)?;
    let bp = list(field(b, "lowered_params")?)?;
    if ap.len() != bp.len() {
        return Ok(false);
    }
    for (x, y) in ap.iter().zip(bp) {
        budget.work(1)?;
        for name in ["source_index", "role", "mode", "align", "bytes", "noundef"] {
            if field(x, name)? != field(y, name)? {
                return Ok(false);
            }
        }
        for name in ["source_type", "value_type"] {
            if !compare(field(x, name)?, field(y, name)?, budget)? {
                return Ok(false);
            }
        }
        for name in ["copy", "move", "destroy"] {
            match (optional(field(x, name)?)?, optional(field(y, name)?)?) {
                (None, None) => {}
                (Some(x), Some(y)) => {
                    let x = recipes.get(&id(x)?).ok_or_else(|| {
                        Error::semantic("ABI_CC_ADAPTER_REFERENCE", "left lifecycle")
                    })?;
                    let y = recipes.get(&id(y)?).ok_or_else(|| {
                        Error::semantic("ABI_CC_ADAPTER_REFERENCE", "right lifecycle")
                    })?;
                    if !recipe_interface(graph, x, y, budget)? {
                        return Ok(false);
                    }
                }
                _ => return Ok(false),
            }
        }
    }
    match (
        optional(field(a, "varargs")?)?,
        optional(field(b, "varargs")?)?,
    ) {
        (None, None) => Ok(true),
        (Some(x), Some(y)) => {
            for name in ["header_bytes", "cookie_scope", "type_reference"] {
                if field(x, name)? != field(y, name)? {
                    return Ok(false);
                }
            }
            for binding in [x, y] {
                let layout = graph
                    .layouts
                    .get(&id(field(binding, "state_layout")?)?)
                    .ok_or_else(|| Error::semantic("ABI_CC_VARARGS_BINDING", "call comparison"))?;
                if uint(field(layout, "size")?)? != 32 || uint(field(layout, "align")?)? != 8 {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        _ => Ok(false),
    }
}

fn recipe_interface(
    graph: &Graph,
    a: &RecordValue,
    b: &RecordValue,
    budget: &mut Budget,
) -> Result<bool, Error> {
    let ad = graph
        .domains
        .get(&id(field(a, "domain")?)?)
        .ok_or_else(|| Error::semantic("ABI_CC_TYPE_DOMAIN", "recipe"))?;
    let bd = graph
        .domains
        .get(&id(field(b, "domain")?)?)
        .ok_or_else(|| Error::semantic("ABI_CC_TYPE_DOMAIN", "recipe"))?;
    for name in ["isa", "personality", "abi", "abi_identity"] {
        if field(ad, name)? != field(bd, name)? {
            return Ok(false);
        }
    }
    for name in ["params", "results"] {
        let x = list(field(a, name)?)?;
        let y = list(field(b, name)?)?;
        if x.len() != y.len() {
            return Ok(false);
        }
        for (x, y) in x.iter().zip(y) {
            let (x, y) = if name == "params" {
                (field(x, "type")?, field(y, "type")?)
            } else {
                (x, y)
            };
            if !graph.boundary(graph.resolve(x)?, graph.resolve(y)?, budget)? {
                return Ok(false);
            }
        }
    }
    Ok(true)
}
