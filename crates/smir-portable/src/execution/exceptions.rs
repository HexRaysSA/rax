//! Static EH regions, capture frontiers and selector/source-type associations.

use std::collections::{BTreeMap, BTreeSet};

use crate::abi::AbiFacts;
use crate::context::{
    DeclaredEntity, EntityKey, Namespace, ObjectContext, entity_ref, field, unsigned,
};
use crate::error::Error;
use crate::limits::Budget;
use crate::wire::RecordValue;

use super::cfg::Cfg;
use super::records::{identifier, local_reference, option, ordered, require, sequence, token};
use super::{ProgramRequirement, TypeFacts, TypeKind};

pub(super) fn nominal_key(ctx: &ObjectContext, value: &RecordValue) -> Result<EntityKey, Error> {
    match ctx.resolve_declaration(Namespace::Nominal, &entity_ref(value)?)? {
        DeclaredEntity::Local(key) => Ok(key),
        DeclaredEntity::Dependency { declaration, .. } => {
            let expected = option(declaration, "nominal")?
                .ok_or_else(|| Error::semantic("declaration_nominal", "missing expectation"))?;
            ctx.local(Namespace::Nominal, local_reference(expected)?)
        }
    }
}

fn ids(value: &RecordValue, name: &str, budget: &mut Budget) -> Result<Vec<u32>, Error> {
    let values = sequence(value, name)?;
    budget.reserve_bytes(
        values
            .len()
            .checked_mul(4)
            .ok_or_else(|| Error::resource("reference_resource", "EH IDs"))?,
    )?;
    values
        .iter()
        .map(|value| {
            budget.work(1)?;
            u32::try_from(unsigned(value)?).map_err(|_| Error::semantic("reference", "EH ID"))
        })
        .collect()
}

pub(super) fn verify(
    ctx: &ObjectContext,
    types: &TypeFacts,
    abi: &AbiFacts,
    cfg: &Cfg<'_>,
    function: &RecordValue,
    exception: Option<&RecordValue>,
    requirements: &mut Vec<ProgramRequirement>,
    budget: &mut Budget,
) -> Result<(), Error> {
    let empty = RecordValue::Vector(Vec::new());
    let region_records = match exception {
        Some(exception) => field(exception, "regions")?,
        None => &empty,
    };
    let action_records = match exception {
        Some(exception) => field(exception, "actions")?,
        None => &empty,
    };
    let regions = ordered(crate::context::list(region_records)?, "id", budget)?;
    let actions = ordered(crate::context::list(action_records)?, "id", budget)?;
    require(regions.len() <= 1024, "limit")?;
    for (action_id, action) in &actions {
        budget.work(1)?;
        let program = field(action, "program")?;
        ctx.local(Namespace::Journal, local_reference(program)?)?;
        let recipe = entity_ref(field(action, "recipe")?)?;
        let recipe = ctx.resolve_declaration(Namespace::Recipe, &recipe)?;
        let mut formals = BTreeMap::new();
        let external = match recipe {
            DeclaredEntity::Local(key) => {
                for formal in sequence(ctx.entity(key)?, "params")? {
                    budget.work(1)?;
                    budget.reserve_bytes(96)?;
                    require(
                        formals.insert(identifier(formal, "id")?, formal).is_none(),
                        "cleanup_formal_duplicate",
                    )?;
                }
                false
            }
            DeclaredEntity::Dependency { slot, declaration } => {
                // The absent provider's formal IDs/body are not derivable from
                // an expected signature. Preserve that precise binding check.
                budget.reserve_bytes(std::mem::size_of::<ProgramRequirement>())?;
                requirements.push(ProgramRequirement::ExternalCleanupRecipe {
                    function: identifier(function, "id")?,
                    action: *action_id,
                    slot,
                    declaration: identifier(declaration, "id")?,
                });
                true
            }
        };
        let captures = sequence(action, "captures")?;
        if !external {
            require(captures.len() == formals.len(), "cleanup_capture_bijection")?;
        }
        let mut seen = BTreeSet::new();
        for capture in captures {
            budget.work(1)?;
            let parameter = identifier(capture, "parameter")?;
            budget.reserve_bytes(64)?;
            require(seen.insert(parameter), "cleanup_capture_bijection")?;
            let ty = types.type_reference(field(capture, "type")?)?;
            if !external {
                let formal = formals
                    .get(&parameter)
                    .ok_or_else(|| Error::semantic("cleanup_capture_bijection", "parameter"))?;
                let nominal = ctx.entity(nominal_key(ctx, field(formal, "type")?)?)?;
                let expected = option(nominal, "execution")?
                    .ok_or_else(|| Error::semantic("cleanup_capture_type", "nominal execution"))?;
                require(
                    types.type_equivalent(ty, types.type_reference(expected)?, budget)?,
                    "cleanup_capture_type",
                )?;
            }
            let source = field(capture, "source")?;
            match token(source, "kind")? {
                "value" => require(
                    types.type_equivalent(
                        cfg.value_type(identifier(source, "value")?)?,
                        ty,
                        budget,
                    )?,
                    "cleanup_capture_value_type",
                )?,
                "exception" => require(
                    matches!(types.kind(ty)?, TypeKind::Exception),
                    "cleanup_capture_exception",
                )?,
                "journal" => require(
                    matches!(types.kind(ty)?, TypeKind::Journal)
                        && field(source, "program")? == program,
                    "cleanup_capture_journal",
                )?,
                _ => return Err(Error::semantic("cleanup_capture_source", "kind")),
            }
        }
    }
    budget.reserve_bytes(
        regions
            .len()
            .checked_mul(256)
            .and_then(|n| n.checked_add(cfg.blocks.len().checked_mul(64)?))
            .ok_or_else(|| Error::resource("reference_resource", "EH graph"))?,
    )?;
    let mut ancestry = BTreeMap::<u32, BTreeSet<u32>>::new();
    let mut memberships = vec![Vec::new(); cfg.blocks.len()];
    let mut handlers = BTreeSet::new();
    let mut selector_types = Vec::<(Option<EntityKey>, u32)>::new();
    for (id, region) in &regions {
        budget.work(1)?;
        let parent = option(region, "parent")?
            .map(unsigned)
            .transpose()?
            .map(|id| u32::try_from(id).map_err(|_| Error::semantic("region_parent", "ID")))
            .transpose()?;
        require(
            parent.is_none_or(|id| regions.contains_key(&id)),
            "region_parent",
        )?;
        let blocks = ids(region, "blocks", budget)?;
        require(
            blocks.windows(2).all(|pair| pair[0] < pair[1]),
            "region_blocks",
        )?;
        require(
            ["continue", "terminate"].contains(&token(region, "escape")?),
            "region_escape",
        )?;
        for block in &blocks {
            let index = *cfg
                .indices
                .get(block)
                .ok_or_else(|| Error::semantic("region_blocks", "block"))?;
            budget.reserve_bytes(4)?;
            memberships[index].push(*id);
        }
        let mut current = Some(*id);
        let mut seen = BTreeSet::new();
        while let Some(id) = current {
            budget.work(1)?;
            budget.reserve_bytes(64)?;
            require(seen.insert(id), "region_cycle")?;
            if seen.len() > 64 {
                return Err(Error::resource("reference_resource", "region depth"));
            }
            let region = regions
                .get(&id)
                .ok_or_else(|| Error::semantic("region_parent", "ancestor"))?;
            current = option(region, "parent")?
                .map(unsigned)
                .transpose()?
                .map(|id| u32::try_from(id).map_err(|_| Error::semantic("region_parent", "ID")))
                .transpose()?;
        }
        ancestry.insert(*id, seen);
        if let Some(parent) = parent {
            let parent_blocks = ids(
                regions
                    .get(&parent)
                    .ok_or_else(|| Error::semantic("region_parent", "parent"))?,
                "blocks",
                budget,
            )?;
            for block in &blocks {
                budget.work(1)?;
                require(parent_blocks.binary_search(block).is_ok(), "region_nesting")?;
            }
        }
        let mut catch_all = false;
        for handler in sequence(region, "handlers")? {
            budget.work(1)?;
            let id = identifier(handler, "id")?;
            budget.reserve_bytes(96)?;
            require(
                id < u32::MAX
                    && handlers.insert(id)
                    && cfg.indices.contains_key(&identifier(handler, "entry")?),
                "handler_identity",
            )?;
            if handlers.len() > 1024 {
                return Err(Error::resource(
                    "reference_resource",
                    "handlers per function",
                ));
            }
            let selector = identifier(handler, "selector")?;
            require(
                (1..=i32::MAX as u32).contains(&selector),
                "handler_selector_range",
            )?;
            let kind = token(handler, "kind")?;
            require(
                !catch_all && ["typed", "catch_all"].contains(&kind),
                "handler_order",
            )?;
            let nominal = option(handler, "nominal")?;
            require((kind == "typed") == nominal.is_some(), "handler_nominal")?;
            let nominal = nominal.map(|value| nominal_key(ctx, value)).transpose()?;
            if let Some(nominal) = nominal {
                require(
                    abi.catch_compatible(nominal, nominal, budget)?,
                    "handler_nominal_type",
                )?;
            }
            for (previous, previous_selector) in &selector_types {
                budget.work(1)?;
                let same = match (nominal, *previous) {
                    (None, None) => true,
                    (Some(a), Some(b)) => abi.catch_compatible(a, b, budget)?,
                    _ => false,
                };
                require(
                    same == (selector == *previous_selector),
                    "handler_selector_type",
                )?;
            }
            selector_types.push((nominal, selector));
            catch_all |= kind == "catch_all";
            for action in ids(handler, "cleanup_actions", budget)? {
                require(actions.contains_key(&action), "cleanup_action_reference")?;
            }
            if let Some(copy) = option(handler, "catch_copy")? {
                require(
                    actions.contains_key(
                        &u32::try_from(unsigned(copy)?)
                            .map_err(|_| Error::semantic("catch_copy_reference", "ID"))?,
                    ),
                    "catch_copy_reference",
                )?;
            }
        }
        for action in ids(region, "exit_actions", budget)? {
            require(actions.contains_key(&action), "cleanup_action_reference")?;
        }
    }
    for members in &mut memberships {
        let count = members.len() as u64;
        budget.work(count.saturating_mul(64 - count.max(1).leading_zeros() as u64))?;
        members.sort_by_key(|id| ancestry.get(id).map_or(0, BTreeSet::len));
        for pair in members.windows(2) {
            require(
                ancestry
                    .get(&pair[1])
                    .is_some_and(|chain| chain.contains(&pair[0])),
                "region_overlap",
            )?;
        }
    }
    let protected = |index: usize, budget: &mut Budget| -> Result<bool, Error> {
        for member in &memberships[index] {
            budget.work(1)?;
            let region = regions
                .get(member)
                .ok_or_else(|| Error::semantic("exception_region", "membership"))?;
            if !sequence(region, "handlers")?.is_empty()
                || !sequence(region, "exit_actions")?.is_empty()
            {
                return Ok(true);
            }
        }
        Ok(false)
    };
    let local_obligations = cfg.blocks.iter().try_fold(false, |found, block| {
        let mut result = found;
        for op in sequence(block, "ops")? {
            budget.work(1)?;
            if [
                "journal",
                "catch_begin",
                "catch_end",
                "stack_save",
                "setjmp",
            ]
            .contains(&token(op, "op")?)
            {
                result = true;
            }
        }
        Ok::<_, Error>(result)
    })?;
    for (index, block) in cfg.blocks.iter().enumerate() {
        budget.work(1)?;
        let term = field(block, "term")?;
        match token(term, "op")? {
            "invoke" => {
                let mut current = Some(identifier(term, "region")?);
                require(
                    current.is_some_and(|id| memberships[index].contains(&id)),
                    "invoke_region",
                )?;
                while let Some(id) = current {
                    budget.work(1)?;
                    let region = regions
                        .get(&id)
                        .ok_or_else(|| Error::semantic("invoke_region", "region"))?;
                    let mut action_ids = ids(region, "exit_actions", budget)?;
                    for handler in sequence(region, "handlers")? {
                        let cleanup = ids(handler, "cleanup_actions", budget)?;
                        budget.work(cleanup.len() as u64)?;
                        budget.reserve_bytes(
                            action_ids
                                .len()
                                .checked_add(cleanup.len())
                                .and_then(|n| n.checked_mul(8))
                                .ok_or_else(|| {
                                    Error::resource("reference_resource", "cleanup action frontier")
                                })?,
                        )?;
                        action_ids.extend(cleanup);
                        if let Some(copy) = option(handler, "catch_copy")? {
                            budget.reserve_bytes(
                                action_ids
                                    .len()
                                    .checked_add(1)
                                    .and_then(|n| n.checked_mul(8))
                                    .ok_or_else(|| {
                                        Error::resource("reference_resource", "catch copy frontier")
                                    })?,
                            )?;
                            action_ids.push(
                                u32::try_from(unsigned(copy)?)
                                    .map_err(|_| Error::semantic("catch_copy_reference", "ID"))?,
                            );
                        }
                    }
                    for action_id in action_ids {
                        let action = actions
                            .get(&action_id)
                            .ok_or_else(|| Error::semantic("cleanup_action_reference", "action"))?;
                        for capture in sequence(action, "captures")? {
                            budget.work(1)?;
                            let source = field(capture, "source")?;
                            if token(source, "kind")? == "value" {
                                cfg.check_use(
                                    identifier(source, "value")?,
                                    index,
                                    sequence(block, "ops")?.len() as i64,
                                )?;
                            }
                        }
                    }
                    current = option(region, "parent")?
                        .map(unsigned)
                        .transpose()?
                        .map(|id| {
                            u32::try_from(id).map_err(|_| Error::semantic("region_parent", "ID"))
                        })
                        .transpose()?;
                }
            }
            "throw" | "rethrow" | "resume" | "cleanup_return" => {
                if let Some(region) = option(term, "region")? {
                    require(
                        regions.contains_key(
                            &u32::try_from(unsigned(region)?)
                                .map_err(|_| Error::semantic("exception_region", "ID"))?,
                        ),
                        "exception_region",
                    )?;
                }
                require(!protected(index, budget)?, "raise_requires_invoke")?;
            }
            "tailcall" => {
                require(!protected(index, budget)?, "tail_protected_region")?;
                require(!local_obligations, "tail_local_obligations")?;
            }
            _ => {}
        }
        for operation in sequence(block, "ops")? {
            budget.work(1)?;
            match token(operation, "op")? {
                "call" if token(operation, "unwind")? == "propagate" => {
                    require(!protected(index, budget)?, "call_requires_invoke")?
                }
                "landingpad" => require(
                    regions.contains_key(&identifier(operation, "region")?),
                    "landingpad_region",
                )?,
                "catch_begin" => require(
                    handlers.contains(&identifier(operation, "handler")?),
                    "catch_handler",
                )?,
                _ => {}
            }
            if let Some(helper) = crate::context::record(operation)?.get("helper") {
                if token(helper, "kind")? == "import" {
                    let binding = ctx.entity(ctx.local(
                        Namespace::Import,
                        local_reference(field(helper, "import")?)?,
                    )?)?;
                    if token(binding, "kind")? == "internal" {
                        // The frozen metadata pass validates the full helper
                        // catalog/instantiation; its declaration identifies the
                        // immutable catalog entry whose raising contract is read.
                        if helper_raises(token(binding, "name")?, budget)? {
                            require(!protected(index, budget)?, "helper_requires_invoke")?;
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

fn helper_raises(name: &str, budget: &mut Budget) -> Result<bool, Error> {
    budget.work(177)?;
    static HELPERS: std::sync::OnceLock<Result<serde_json::Value, String>> =
        std::sync::OnceLock::new();
    let catalog = HELPERS
        .get_or_init(|| {
            serde_json::from_str(include_str!(
                "../../../../docs/specifications/smir/portable/schema/runtime/helpers-v1.json"
            ))
            .map_err(|error| error.to_string())
        })
        .as_ref()
        .map_err(|error| Error::semantic("P2_SCHEMA", error.clone()))?;
    let helpers = catalog
        .get("records")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| Error::semantic("P2_SCHEMA", "helper catalog"))?;
    let helper = helpers
        .iter()
        .find(|helper| helper.get("name").and_then(serde_json::Value::as_str) == Some(name))
        .ok_or_else(|| Error::semantic("helper_name", name))?;
    Ok(
        helper.get("completion").and_then(serde_json::Value::as_str) == Some("raises")
            || helper
                .get("traps")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|traps| traps.iter().any(|trap| trap.as_str() == Some("exception"))),
    )
}
