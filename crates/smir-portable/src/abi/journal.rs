//! Static construction/capture/order graphs. No effect tickets are issued.

use super::{
    facts::Tables,
    layout,
    nominal::{Graph, self_id},
    value::*,
};
use crate::{Error, limits::Budget, wire::RecordValue};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn verify(graph: &Graph, tables: &Tables, budget: &mut Budget) -> Result<(), Error> {
    for program in tables.journals.values() {
        budget.work(1)?;
        require(
            tables
                .signatures
                .contains_key(&id(field(program, "signature")?)?),
            "ABI_CC_JOURNAL_SIGNATURE",
        )?;
        let mut formals = BTreeMap::new();
        for formal in list(field(program, "params")?)? {
            budget.work(1)?;
            budget.reserve_bytes(128)?;
            let identifier = id(field(formal, "id")?)?;
            require(
                identifier != u32::MAX && formals.insert(identifier, formal).is_none(),
                "ABI_CC_DUPLICATE_JOURNAL_PARAMETER",
            )?;
            require(
                optional(field(graph.typ(field(formal, "type")?)?, "execution")?)?.is_some(),
                "ABI_CC_JOURNAL_PARAMETER_TYPE",
            )?;
        }
        let mut slots = BTreeMap::new();
        for slot in list(field(program, "slots")?)? {
            budget.work(1)?;
            budget.reserve_bytes(128)?;
            let identifier = id(field(slot, "id")?)?;
            require(
                identifier != u32::MAX && slots.insert(identifier, slot).is_none(),
                "ABI_CC_DUPLICATE_SLOT",
            )?;
        }
        require(slots.len() <= 4096, "ABI_CC_JOURNAL_LIMIT")?;
        for (identifier, slot) in &slots {
            budget.work(1)?;
            let align = uint(field(slot, "align")?)?;
            layout::alignment(align)?;
            require(
                uint(field(slot, "offset")?)? % align == 0 && uint(field(slot, "stride")?)? > 0,
                "ABI_CC_SUBOBJECT_ALIGNMENT",
            )?;
            require(
                [
                    "root",
                    "base",
                    "virtual_base",
                    "member",
                    "union_member",
                    "array",
                    "vla",
                    "allocation",
                    "catch_object",
                ]
                .contains(&text(field(slot, "role")?)?),
                "ABI_CC_SLOT_ROLE",
            )?;
            if let Some(parent) = optional(field(slot, "parent")?)? {
                let parent_id = id(parent)?;
                require(parent_id != *identifier, "ABI_CC_SLOT_PARENT")?;
                let parent = slots
                    .get(&parent_id)
                    .ok_or_else(|| Error::semantic("ABI_CC_SLOT_PARENT", "parent slot"))?;
                require(
                    uint(field(parent, "count")?)? == 1
                        && optional(field(parent, "count_source")?)?.is_none(),
                    "ABI_CC_ARRAY_PARENT_REQUIRES_INSTANCE",
                )?;
            }
            let mut dependencies = BTreeSet::new();
            for dependency in list(field(slot, "dependencies")?)? {
                budget.work(1)?;
                budget.reserve_bytes(64)?;
                let dependency = id(dependency)?;
                require(
                    dependency != *identifier
                        && slots.contains_key(&dependency)
                        && dependencies.insert(dependency),
                    "ABI_CC_SLOT_DEPENDENCY",
                )?;
                require(
                    optional(field(slot, "parent")?)?.map(id).transpose()? != Some(dependency),
                    "ABI_CC_SLOT_DEPENDENCY",
                )?;
            }
            let destructor = text(field(slot, "destructor_kind")?)?;
            require(
                ["none", "leaf", "base", "complete"].contains(&destructor)
                    && (optional(field(slot, "destructor")?)?.is_none() == (destructor == "none")),
                "ABI_CC_DESTRUCTOR_KIND",
            )?;
            let mut covers = BTreeSet::new();
            for child in list(field(slot, "covers")?)? {
                budget.work(1)?;
                budget.reserve_bytes(64)?;
                let child = id(child)?;
                require(
                    child != *identifier && slots.contains_key(&child) && covers.insert(child),
                    "ABI_CC_DESTRUCTOR_COVERAGE",
                )?;
                let mut cursor = child;
                let mut seen = BTreeSet::new();
                let mut descendant = false;
                loop {
                    budget.work(1)?;
                    budget.reserve_bytes(64)?;
                    require(seen.insert(cursor), "ABI_CC_SLOT_CYCLE")?;
                    let current = slots
                        .get(&cursor)
                        .ok_or_else(|| Error::semantic("ABI_CC_SLOT_PARENT", "coverage parent"))?;
                    let Some(parent) = optional(field(current, "parent")?)? else {
                        break;
                    };
                    cursor = id(parent)?;
                    if cursor == *identifier {
                        descendant = true;
                        break;
                    }
                }
                require(descendant, "ABI_CC_DESTRUCTOR_COVERAGE")?;
            }
            require(
                covers.is_empty() || matches!(destructor, "base" | "complete"),
                "ABI_CC_DESTRUCTOR_COVERAGE",
            )?;
            graph.resolve(field(slot, "type")?)?;
            require(
                graph.domains.contains_key(&id(field(slot, "owner")?)?),
                "ABI_CC_SLOT_OWNER",
            )?;
            if let Some(count) = optional(field(slot, "count_source")?)? {
                let formal = formals.get(&id(count)?).ok_or_else(|| {
                    Error::semantic("ABI_CC_JOURNAL_COUNT_SOURCE", "count formal")
                })?;
                let typ = graph.typ(field(formal, "type")?)?;
                require(
                    text(field(typ, "kind")?)? == "scalar"
                        && uint(field(typ, "bits")?)? == 64
                        && !boolean(field(typ, "signed")?)?,
                    "ABI_CC_JOURNAL_COUNT_SOURCE",
                )?;
            }
            for name in ["constructor", "destructor"] {
                if let Some(recipe) = optional(field(slot, name)?)? {
                    require(
                        tables.recipes.contains_key(&id(recipe)?),
                        "ABI_CC_ADAPTER_REFERENCE",
                    )?;
                }
            }
            if let Some(child) = optional(field(slot, "child_program")?)? {
                require(
                    tables.journals.contains_key(&self_id(child)?),
                    "ABI_CC_UNBOUND_PROGRAM",
                )?;
            }
        }
        let mut colors = BTreeMap::new();
        for identifier in slots.keys() {
            budget.reserve_bytes(128)?;
            let mut stack = vec![(*identifier, false)];
            while let Some((identifier, done)) = stack.pop() {
                budget.work(1)?;
                if done {
                    colors.insert(identifier, 2);
                    continue;
                }
                match colors.get(&identifier) {
                    Some(2) => continue,
                    Some(1) => {
                        return Err(Error::semantic(
                            "ABI_CC_SLOT_CYCLE",
                            "construction dependencies",
                        ));
                    }
                    _ => {}
                }
                budget.reserve_bytes(128)?;
                colors.insert(identifier, 1);
                stack.push((identifier, true));
                let slot = slots
                    .get(&identifier)
                    .ok_or_else(|| Error::semantic("ABI_CC_SLOT_PARENT", "slot graph"))?;
                for dependency in list(field(slot, "dependencies")?)? {
                    budget.edges(1)?;
                    budget.reserve_bytes(16)?;
                    stack.push((id(dependency)?, false));
                }
                if let Some(parent) = optional(field(slot, "parent")?)? {
                    budget.edges(1)?;
                    budget.reserve_bytes(16)?;
                    stack.push((id(parent)?, false));
                }
            }
        }
        for name in ["normal_order", "exception_order"] {
            let mut order = BTreeSet::new();
            for identifier in list(field(program, name)?)? {
                budget.work(1)?;
                budget.reserve_bytes(64)?;
                require(order.insert(id(identifier)?), "ABI_CC_CLEANUP_ORDER")?;
            }
            require(
                order.len() == slots.len()
                    && order
                        .iter()
                        .all(|identifier| slots.contains_key(identifier)),
                "ABI_CC_CLEANUP_ORDER",
            )?;
        }
    }
    Ok(())
}
