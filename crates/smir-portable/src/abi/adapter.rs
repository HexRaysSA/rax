//! Typed adapter action graphs and static symbol expectations.

use super::{layout, nominal::Graph, value::*};
use crate::{
    Error,
    context::{DeclaredEntity, EntityKey, Namespace, ObjectContext, entity_ref},
    limits::Budget,
    wire::RecordValue,
};
use std::collections::{BTreeMap, BTreeSet};

pub(super) struct Symbol<'a> {
    pub record: &'a RecordValue,
    pub nominal: u32,
    pub domain: u32,
    pub local: Option<EntityKey>,
}

pub(super) fn symbol<'a>(
    graph: &Graph,
    ctx: &'a ObjectContext,
    reference: &RecordValue,
) -> Result<Symbol<'a>, Error> {
    match ctx.resolve_declaration(Namespace::Symbol, &entity_ref(reference)?)? {
        DeclaredEntity::Local(key) => {
            let record = ctx.entity(key)?;
            require(
                text(field(record, "kind")?)? == "function",
                "ABI_CC_SYMBOL_EVIDENCE",
            )?;
            let nominal = optional(field(record, "nominal")?)?.ok_or_else(|| {
                Error::semantic("ABI_CC_SYMBOL_EVIDENCE", "source function nominal")
            })?;
            let nominal = graph.resolve(nominal)?;
            let typ = graph.typ_id(nominal)?;
            require(
                text(field(typ, "kind")?)? == "function",
                "ABI_CC_SYMBOL_EVIDENCE",
            )?;
            Ok(Symbol {
                record,
                nominal,
                domain: id(field(typ, "domain")?)?,
                local: Some(key),
            })
        }
        DeclaredEntity::Dependency { declaration, .. } => {
            require(
                text(field(declaration, "symbol_kind")?)? == "function",
                "ABI_CC_SYMBOL_EVIDENCE",
            )?;
            let nominal = optional(field(declaration, "nominal")?)?.ok_or_else(|| {
                Error::semantic("ABI_CC_SYMBOL_EVIDENCE", "external source expectation")
            })?;
            let nominal = graph.resolve(nominal)?;
            let typ = graph.typ_id(nominal)?;
            require(
                text(field(typ, "kind")?)? == "function",
                "ABI_CC_SYMBOL_EVIDENCE",
            )?;
            Ok(Symbol {
                record: declaration,
                nominal,
                domain: id(field(typ, "domain")?)?,
                local: None,
            })
        }
    }
}

fn call_action(action: &str) -> bool {
    matches!(
        action,
        "copy"
            | "move"
            | "construct"
            | "destroy"
            | "retain"
            | "release"
            | "convert"
            | "call"
            | "virtual_call"
            | "catch_copy"
            | "checkpoint"
    )
}

fn arity(action: &str) -> Option<(Option<usize>, Option<usize>)> {
    Some(match action {
        "adjust" | "copy" | "move" | "construct" | "convert" | "rtti_cast" | "catch_copy" => {
            (Some(1), Some(1))
        }
        "byte_copy" => (Some(2), Some(0)),
        "destroy" | "retain" | "release" | "raise" => (Some(1), Some(0)),
        "call" | "virtual_call" | "checkpoint" => (None, None),
        "return" => (None, Some(0)),
        "terminate" => (Some(0), Some(0)),
        _ => return None,
    })
}

pub(super) fn verify(
    graph: &Graph,
    ctx: &ObjectContext,
    recipe: &RecordValue,
    budget: &mut Budget,
) -> Result<(), Error> {
    let domain = id(field(recipe, "domain")?)?;
    require(graph.domains.contains_key(&domain), "ABI_CC_ADAPTER_DOMAIN")?;
    let mut steps = BTreeMap::new();
    let mut values = BTreeMap::new();
    let mut initial = BTreeSet::new();
    for value in list(field(recipe, "params")?)? {
        budget.work(1)?;
        budget.reserve_bytes(192)?;
        let identifier = id(field(value, "id")?)?;
        require(
            values.insert(identifier, value).is_none(),
            "ABI_CC_DUPLICATE_VALUE",
        )?;
        initial.insert(identifier);
        graph.resolve(field(value, "type")?)?;
    }
    for step in list(field(recipe, "steps")?)? {
        budget.work(1)?;
        budget.reserve_bytes(128)?;
        require(
            steps.insert(id(field(step, "id")?)?, step).is_none(),
            "ABI_CC_DUPLICATE_STEP",
        )?;
    }
    let entry = id(field(recipe, "entry")?)?;
    require(steps.contains_key(&entry), "ABI_CC_ADAPTER_ENTRY")?;
    let mut predecessors = BTreeMap::<u32, Vec<(u32, bool)>>::new();
    let mut tickets = BTreeSet::new();
    for (identifier, step) in &steps {
        budget.work(1)?;
        let action = text(field(step, "action")?)?;
        let (input_count, output_count) =
            arity(action).ok_or_else(|| Error::semantic("ABI_CC_ADAPTER_ACTION", action))?;
        let inputs = list(field(step, "inputs")?)?;
        let outputs = list(field(step, "outputs")?)?;
        require(
            input_count.is_none_or(|n| inputs.len() == n)
                && output_count.is_none_or(|n| outputs.len() == n),
            "ABI_CC_ADAPTER_ARITY",
        )?;
        layout::alignment(uint(field(step, "align")?)?)?;
        for value in list(field(step, "outputs")?)?
            .iter()
            .chain(optional(field(step, "exception")?)?)
        {
            budget.work(1)?;
            budget.reserve_bytes(128)?;
            require(
                values.insert(id(field(value, "id")?)?, value).is_none(),
                "ABI_CC_ADAPTER_VALUE_REDEFINITION",
            )?;
            graph.resolve(field(value, "type")?)?;
        }
        if call_action(action) || action == "byte_copy" {
            budget.reserve_bytes(64)?;
            require(
                tickets.insert(id(field(step, "ticket")?)?),
                "ABI_CC_ADAPTER_TICKET",
            )?;
        }
        let callee = optional(field(step, "callee")?)?;
        require(
            callee.is_some() == call_action(action),
            "ABI_CC_ADAPTER_CALLEE",
        )?;
        if let Some(callee) = callee {
            require(
                symbol(graph, ctx, callee)?.domain == domain,
                "ABI_CC_ADAPTER_CALLEE",
            )?;
        }
        require(
            optional(field(step, "adjustment")?)?.is_some() == (action == "adjust"),
            "ABI_CC_ADAPTER_ADJUSTMENT",
        )?;
        for name in ["source_type", "target_type"] {
            if let Some(typ) = optional(field(step, name)?)? {
                graph.resolve(typ)?;
            }
        }
        if action == "catch_copy" {
            require(
                optional(field(step, "journal_slot")?)?.is_some(),
                "ABI_CC_CATCH_COPY_JOURNAL",
            )?;
        }
        let normal = optional(field(step, "normal")?)?;
        let unwind = optional(field(step, "unwind")?)?;
        let exception = optional(field(step, "exception")?)?;
        if matches!(action, "return" | "raise" | "terminate") {
            require(
                normal.is_none() && unwind.is_none() && exception.is_none(),
                "ABI_CC_ADAPTER_TERMINATOR",
            )?;
        } else {
            require(normal.is_some(), "ABI_CC_ADAPTER_CONTINUATION")?;
        }
        require(
            unwind.is_some() == exception.is_some(),
            "ABI_CC_ADAPTER_UNWIND_VALUE",
        )?;
        for (target, unwind) in [(normal, false), (unwind, true)] {
            if let Some(target) = target {
                let target = id(target)?;
                require(steps.contains_key(&target), "ABI_CC_ADAPTER_CONTINUATION")?;
                budget.edges(1)?;
                budget.reserve_bytes(128)?;
                predecessors
                    .entry(target)
                    .or_default()
                    .push((*identifier, unwind));
            }
        }
    }
    require(!predecessors.contains_key(&entry), "ABI_CC_ADAPTER_ENTRY")?;
    budget.reserve_bytes(
        initial
            .len()
            .checked_mul(64)
            .and_then(|n| n.checked_add(128))
            .ok_or_else(|| Error::resource("ABI_CC_ADAPTER_RESOURCE", "entry values"))?,
    )?;
    let mut available = BTreeMap::from([(entry, initial)]);
    let mut ready = vec![entry];
    let mut visited = BTreeSet::new();
    while let Some(identifier) = ready.pop() {
        budget.work(1)?;
        if visited.contains(&identifier) {
            continue;
        }
        let step = steps[&identifier];
        let action = text(field(step, "action")?)?;
        let inputs = list(field(step, "inputs")?)?;
        let available_here = available
            .get(&identifier)
            .ok_or_else(|| Error::semantic("ABI_CC_ADAPTER_DOMINANCE", "missing incoming edge"))?;
        for input in inputs {
            require(
                available_here.contains(&id(input)?),
                "ABI_CC_ADAPTER_DOMINANCE",
            )?;
        }
        if call_action(action) {
            let callee = optional(field(step, "callee")?)?
                .ok_or_else(|| Error::semantic("ABI_CC_ADAPTER_CALLEE", "missing callee"))?;
            let callee = symbol(graph, ctx, callee)?;
            let signature = graph.typ_id(callee.nominal)?;
            let elements = list(field(signature, "elements")?)?;
            require(
                text(field(signature, "kind")?)? == "function"
                    && !elements.is_empty()
                    && inputs.len() + 1 == elements.len(),
                "ABI_CC_ADAPTER_SIGNATURE",
            )?;
            for (input, expected) in inputs.iter().zip(elements) {
                let value = values
                    .get(&id(input)?)
                    .ok_or_else(|| Error::semantic("ABI_CC_ADAPTER_DOMINANCE", "input value"))?;
                require(
                    graph.compatible(
                        graph.resolve(field(value, "type")?)?,
                        graph.resolve(expected)?,
                        false,
                        budget,
                    )?,
                    "ABI_CC_ADAPTER_ARGUMENT_TYPE",
                )?;
            }
            let result = elements
                .last()
                .ok_or_else(|| Error::semantic("ABI_CC_ADAPTER_SIGNATURE", "result"))?;
            let is_void = text(field(graph.typ(result)?, "kind")?)? == "void";
            let outputs = list(field(step, "outputs")?)?;
            require(
                outputs.len() == usize::from(!is_void),
                "ABI_CC_ADAPTER_RESULT_TYPE",
            )?;
            if !is_void {
                require(
                    graph.compatible(
                        graph.resolve(field(&outputs[0], "type")?)?,
                        graph.resolve(result)?,
                        false,
                        budget,
                    )?,
                    "ABI_CC_ADAPTER_RESULT_TYPE",
                )?;
            }
            if action == "catch_copy" {
                if let Some(target) = optional(field(step, "unwind")?)? {
                    require(
                        text(field(steps[&id(target)?], "action")?)? == "terminate",
                        "ABI_CC_CATCH_COPY_TERMINATION",
                    )?;
                }
            }
        }
        if action == "return" {
            let results = list(field(recipe, "results")?)?;
            require(inputs.len() == results.len(), "ABI_CC_ADAPTER_RETURN")?;
            for (input, result) in inputs.iter().zip(results) {
                let value = values
                    .get(&id(input)?)
                    .ok_or_else(|| Error::semantic("ABI_CC_ADAPTER_RETURN", "input"))?;
                require(
                    graph.compatible(
                        graph.resolve(field(value, "type")?)?,
                        graph.resolve(result)?,
                        false,
                        budget,
                    )?,
                    "ABI_CC_ADAPTER_RETURN",
                )?;
            }
        }
        let raised =
            if action == "raise" {
                Some(*values.get(&id(&inputs[0])?).ok_or_else(|| {
                    Error::semantic("ABI_CC_ADAPTER_EXCEPTION_TYPE", "raised input")
                })?)
            } else {
                optional(field(step, "exception")?)?
            };
        if let Some(raised) = raised {
            let typ = graph.typ(field(raised, "type")?)?;
            require(
                text(field(typ, "kind")?)? == "handle"
                    && text(field(field(typ, "identity")?, "entity")?)? == "rax.exception_lease",
                "ABI_CC_ADAPTER_EXCEPTION_TYPE",
            )?;
        }
        budget.reserve_bytes(64)?;
        visited.insert(identifier);
        for name in ["normal", "unwind"] {
            let Some(target) = optional(field(step, name)?)? else {
                continue;
            };
            let target = id(target)?;
            if visited.contains(&target) {
                continue;
            }
            let parents = predecessors
                .get(&target)
                .ok_or_else(|| Error::semantic("ABI_CC_ADAPTER_CONTINUATION", "predecessors"))?;
            if !parents.iter().all(|(parent, _)| visited.contains(parent)) {
                continue;
            }
            let mut intersection: Option<BTreeSet<u32>> = None;
            for (parent, unwind) in parents {
                let source = available
                    .get(parent)
                    .ok_or_else(|| Error::semantic("ABI_CC_ADAPTER_DOMINANCE", "parent state"))?;
                budget.work(source.len() as u64)?;
                budget.reserve_bytes(
                    source
                        .len()
                        .checked_add(8)
                        .and_then(|n| n.checked_mul(64))
                        .ok_or_else(|| {
                            Error::resource("ABI_CC_ADAPTER_RESOURCE", "incoming values")
                        })?,
                )?;
                let mut incoming = source.clone();
                if *unwind {
                    let exception = optional(field(steps[parent], "exception")?)?
                        .ok_or_else(|| Error::semantic("ABI_CC_ADAPTER_UNWIND_VALUE", "edge"))?;
                    incoming.insert(id(field(exception, "id")?)?);
                } else {
                    for output in list(field(steps[parent], "outputs")?)? {
                        incoming.insert(id(field(output, "id")?)?);
                    }
                }
                if let Some(current) = &mut intersection {
                    current.retain(|identifier| incoming.contains(identifier));
                } else {
                    intersection = Some(incoming);
                }
            }
            budget.reserve_bytes(128)?;
            available.insert(target, intersection.unwrap_or_default());
            ready.push(target);
        }
    }
    require(
        visited.len() == steps.len(),
        "ABI_CC_ADAPTER_CYCLE_OR_UNREACHABLE",
    )
}
