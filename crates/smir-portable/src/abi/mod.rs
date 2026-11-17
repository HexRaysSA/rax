//! Checked portable source ABI declarations. No runtime authority is issued here.

mod adapter;
mod audit_profile;
mod builtin_state;
mod call;
mod catches;
mod facts;
mod foreign;
mod journal;
pub(crate) mod layout;
pub(crate) mod mask;
pub(crate) mod nominal;
mod nonordinary_entries;
mod pointer_calls;
mod scalar_calls;
mod semantic;
mod site;
mod storage;
pub(crate) mod value;
pub(crate) use facts::*;

use crate::{
    Error,
    context::{ModuleRef, Namespace, ObjectContext, entity_ref},
    execution::TypeFacts,
    limits::Budget,
    wire::RecordValue,
};
use std::collections::BTreeMap;
use value::*;

/// Verify the complete source ABI declaration phase. External facts are retained
/// as requirements, never manufactured. This is not module/runtime admission.
pub(crate) fn verify(
    ctx: &ObjectContext,
    types: &TypeFacts,
    budget: &mut Budget,
) -> Result<AbiFacts, Error> {
    verify_with(ctx, types, true, budget)
}

/// Every semantic validator of [`verify`], without the audited-profile gate.
///
/// The gate refuses valid records whose shape has not been individually
/// audited for the static proof. The engine has its own coverage boundary:
/// lowering refuses every construct it does not execute.
pub(crate) fn verify_unaudited(
    ctx: &ObjectContext,
    types: &TypeFacts,
    budget: &mut Budget,
) -> Result<AbiFacts, Error> {
    verify_with(ctx, types, false, budget)
}

fn verify_with(
    ctx: &ObjectContext,
    types: &TypeFacts,
    audited: bool,
    budget: &mut Budget,
) -> Result<AbiFacts, Error> {
    types.assert_context(ctx)?;
    let root = ctx.root(10)?;
    require(
        uint(field(root, "payload_revision")?)? == 3,
        "ABI_CC_REVISION",
    )?;
    let known_site = site::verify_profile(root, budget)?;
    if known_site.source_revision == 2 {
        return Err(Error::new(
            crate::ErrorClass::UnavailableEvidence,
            "ABI_CC_SOURCE_BYTE_EVIDENCE_UNAVAILABLE",
            "genuine original source-category evidence not issued",
        ));
    }
    let site = known_site.identity;
    let graph = nominal::Graph::new(root, ctx.root(2)?, budget)?;
    let tables = facts::Tables::build(root, budget)?;
    semantic::verify_types(&graph, ctx, types, budget)?;
    semantic::verify_layouts(&graph, budget)?;
    let canonical_states = builtin_state::verify_all(&graph, types, budget)?;
    for signature in tables.signatures.values() {
        call::verify(&graph, signature, &tables.recipes, types, budget)?;
    }
    call::verify_defaults(&graph, &tables.signatures, types, budget)?;
    journal::verify(&graph, &tables, budget)?;
    let mut masks = BTreeMap::new();
    for (identifier, binding) in &tables.storage {
        let mask = storage::verify(&graph, types, binding, budget)?;
        budget.reserve_bytes(128)?;
        masks.insert(*identifier, mask);
    }
    let mut requirements = Vec::new();
    foreign::verify(&graph, ctx, &tables, &mut requirements, budget)?;
    // Preserve every source association to a legal unresolved declaration, not
    // only references exercised by an execution path.
    for (namespace, name) in [
        (Namespace::Nominal, "types"),
        (Namespace::ObjectLayout, "layouts"),
        (Namespace::StorageBinding, "storage_bindings"),
        (Namespace::CallSignature, "signatures"),
        (Namespace::Domain, "domains"),
        (Namespace::Recipe, "recipes"),
        (Namespace::Personality, "personalities"),
        (Namespace::Unwind, "unwind"),
        (Namespace::Catch, "catches"),
        (Namespace::Bridge, "bridges"),
        (Namespace::Journal, "journals"),
    ] {
        for record in list(field(root, name)?)? {
            let source = ctx.local(namespace, id(field(record, "id")?)?)?;
            collect_dependencies(
                ctx,
                record,
                source,
                &mut String::new(),
                &mut requirements,
                0,
                budget,
            )?;
        }
    }
    // All validators above run even on unused records. Only the explicitly
    // audited source profile may issue this private, static phase proof.
    // Valid forms outside it remain unavailable, rather than being admitted.
    if audited {
        audit_profile::check(ctx, types, &canonical_states, budget)?;
    }
    AbiFacts::from_checked(ctx, types, site, graph, tables, requirements, masks, budget)
}

fn collect_dependencies(
    ctx: &ObjectContext,
    value: &RecordValue,
    source: crate::context::EntityKey,
    path: &mut String,
    requirements: &mut Vec<AbiRequirement>,
    depth: u32,
    budget: &mut Budget,
) -> Result<(), Error> {
    budget.work(1)?;
    if depth >= 128 {
        return Err(Error::resource(
            "ABI_CC_REQUIREMENT_RESOURCE",
            "source reference depth",
        ));
    }
    if let RecordValue::Record(fields) = value {
        if fields.contains_key("module") && fields.contains_key("id") {
            let reference = entity_ref(value)?;
            if let ModuleRef::Dependency { slot } = reference.module {
                let declaration = ctx.declaration(slot, reference.id)?;
                let kind = match text(field(declaration, "kind")?)? {
                    "nominal" | "type" => AbiRequirementKind::ExternalNominal,
                    "recipe" => AbiRequirementKind::ExternalRecipe,
                    "function" | "symbol" => AbiRequirementKind::ExternalSourcePlan,
                    _ => {
                        return Err(Error::semantic(
                            "ABI_CC_ENTITY_NAMESPACE",
                            "external declaration kind",
                        ));
                    }
                };
                budget.reserve_bytes(256 + path.len())?;
                requirements.push(AbiRequirement {
                    kind,
                    source,
                    field_path: path.clone(),
                    dependency: Some((slot, reference.id)),
                    expected_native_cc: None,
                    expected_packet_cc: None,
                });
            }
            return Ok(());
        }
        for (name, value) in fields {
            let previous = path.len();
            budget.reserve_bytes(name.len() + 1)?;
            path.push('.');
            path.push_str(name);
            collect_dependencies(ctx, value, source, path, requirements, depth + 1, budget)?;
            path.truncate(previous);
        }
    } else if let RecordValue::Vector(values) = value {
        for (index, value) in values.iter().enumerate() {
            let previous = path.len();
            budget.reserve_bytes(32)?;
            path.push_str(&format!("[{index}]"));
            collect_dependencies(ctx, value, source, path, requirements, depth + 1, budget)?;
            path.truncate(previous);
        }
    } else if let RecordValue::Option(Some(value)) = value {
        collect_dependencies(ctx, value, source, path, requirements, depth + 1, budget)?;
    }
    Ok(())
}
