//! Local source ABI and physical-storage joins. External provider equality is deferred.

use super::{
    imports::nominal_expectation,
    records::*,
    symbols::{Definition, SourceLinkage, SymbolFacts, optional_ref, self_id},
};
use crate::context::{
    EntityKey, EntityRef, Namespace, ObjectContext, entity_ref, field, list, optional,
};
use crate::{Error, abi::AbiFacts, execution::TypeFacts, limits::Budget, wire::RecordValue};

/// Existing typed-symbol constraint, including undefined/common definitions.
/// Function-pointer values are objects; a bare function signature is not.
pub(crate) fn verify_execution_category(kind: &str, execution: &RecordValue) -> Result<(), Error> {
    let kind = super::symbols::SymbolKind::parse(kind)?;
    if kind == super::symbols::SymbolKind::FunctionAddress {
        return require(token(execution, "kind")? == "code_address", "RT_SYMBOL_SIGNATURE");
    }
    let callable = matches!(
        kind,
        super::symbols::SymbolKind::Function | super::symbols::SymbolKind::Import
    );
    require(
        (token(execution, "kind")? == "function") == callable,
        "RT_SYMBOL_SIGNATURE",
    )
}

pub(crate) fn verify_nominal_category(
    record: &RecordValue,
    nominal: &RecordValue,
) -> Result<(), Error> {
    let kind = token(record, "kind")?;
    let callable = match kind {
        "function" | "import" | "function_address" => Some(true),
        "data" | "tls" => Some(false),
        "symbol" => Some(matches!(
            super::symbols::SymbolKind::parse(token(record, "symbol_kind")?)?,
            super::symbols::SymbolKind::Function | super::symbols::SymbolKind::Import
                | super::symbols::SymbolKind::FunctionAddress
        )),
        _ => None,
    };
    if let Some(callable) = callable {
        require(
            (token(nominal, "kind")? == "function") == callable,
            "RT_SOURCE_FUNCTION_NOMINAL",
        )?;
    }
    Ok(())
}

fn signature_key(ctx: &ObjectContext, reference: EntityRef) -> Result<EntityKey, Error> {
    ctx.local(
        Namespace::CallSignature,
        self_id(reference, "RT_SOURCE_PLAN_SELF")?,
    )
}

fn source_plan(
    ctx: &ObjectContext,
    abi: &AbiFacts,
    record: &RecordValue,
    required: Option<bool>,
    budget: &mut Budget,
) -> Result<Option<EntityKey>, Error> {
    let nominal = optional(field(record, "nominal")?)?
        .map(|r| nominal_expectation(ctx, r))
        .transpose()?;
    let linkage = token(record, "source_linkage")?;
    require(
        nominal.is_some() || linkage == "none",
        "RT_SOURCE_LINKAGE_WITHOUT_NOMINAL",
    )?;
    if let Some(key) = nominal {
        verify_nominal_category(record, abi.nominal(key)?.record())?;
    }
    let address_only = token(record, "kind")? == "function_address"
        || token(record, "kind")? == "symbol" && token(record, "symbol_kind")? == "function_address";
    if address_only {
        require(nominal.is_some() && linkage != "none"
                && optional_ref(record, "abi_signature")?.is_none(),
                "RT_FUNCTION_ADDRESS_SHAPE")?;
        return Ok(None);
    }
    let required = match required {
        Some(value) => value,
        None => match nominal {
            None => false,
            Some(key) => {
                let record = abi.nominal(key)?.record();
                if token(record, "kind")? == "function" && linkage != "none" {
                    // `key` is the actual local nominal expectation, including
                    // a DEP declaration's explicit SELF mirror. Domain IDs are
                    // owner-local identifiers, never ISA discriminants.
                    let domain = number(record, "domain")?;
                    let domain_id = u32::try_from(domain)
                        .map_err(|_| Error::semantic("RT_SOURCE_PLAN_DOMAIN", "domain ID"))?;
                    budget.work(1)?;
                    let actual = ctx.entity(ctx.local(Namespace::Domain, domain_id)?)?;
                    require(number(actual, "id")? == domain, "RT_SOURCE_PLAN_DOMAIN")?;
                    token(actual, "isa")? == "portable"
                } else {
                    false
                }
            }
        },
    };
    let plan = optional_ref(record, "abi_signature")?
        .map(|r| signature_key(ctx, r))
        .transpose()?;
    require(plan.is_some() == required, "RT_SOURCE_PLAN_PRESENCE")?;
    if let Some(plan) = plan {
        let source =
            nominal.ok_or_else(|| Error::semantic("RT_SOURCE_PLAN_NOMINAL", String::new()))?;
        require(
            abi.nominal_compatible(source, abi.signature(plan)?.function_type(), budget)?,
            "RT_SOURCE_PLAN_NOMINAL",
        )?;
    }
    Ok(plan)
}

fn same_plan(
    abi: &AbiFacts,
    a: Option<EntityKey>,
    b: Option<EntityKey>,
    code: &'static str,
    budget: &mut Budget,
) -> Result<(), Error> {
    require(a.is_some() == b.is_some(), code)?;
    if let (Some(a), Some(b)) = (a, b) {
        require(abi.source_call_compatible(a, b, budget)?, code)?;
    }
    Ok(())
}

fn same_nominal(
    ctx: &ObjectContext,
    abi: &AbiFacts,
    a: Option<&RecordValue>,
    b: Option<&RecordValue>,
    code: &'static str,
    budget: &mut Budget,
) -> Result<(), Error> {
    require(a.is_some() == b.is_some(), code)?;
    if let (Some(a), Some(b)) = (a, b) {
        require(
            abi.nominal_compatible(
                nominal_expectation(ctx, a)?,
                nominal_expectation(ctx, b)?,
                budget,
            )?,
            code,
        )?;
    }
    Ok(())
}

pub(crate) fn verify_storage(
    ctx: &ObjectContext,
    types: &TypeFacts,
    abi: &AbiFacts,
    budget: &mut Budget,
) -> Result<(), Error> {
    types.assert_context(ctx)?;
    abi.assert_context(ctx)?;
    for (section, collection, tls) in [(4, "segments", false), (7, "segments", true)] {
        let root = ctx.root(section)?;
        require(
            number(root, "payload_revision")? == 1,
            "RT_PAYLOAD_REVISION",
        )?;
        let records = list(field(root, collection)?)?;
        let mut previous = None;
        for record in records {
            let record = if tls {
                field(record, "storage")?
            } else {
                record
            };
            let storage = StorageView::parse(record, budget)?;
            require(
                previous.is_none_or(|prior| prior < storage.id),
                "RT_LINK_ORDER",
            )?;
            previous = Some(storage.id);
            let layout = optional_ref(record, "layout")?;
            if let Some(reference) = layout {
                let expected =
                    types.layout(types.layout_handle(self_id(reference, "RT_SEGMENT_LAYOUT")?)?)?;
                require(
                    expected.size_bytes == storage.extent
                        && storage.alignment >= u64::from(expected.alignment_bytes),
                    "RT_SEGMENT_LAYOUT",
                )?;
            }
            let nominal = optional(field(record, "nominal")?)?;
            let binding = optional_ref(record, "abi_binding")?;
            require(
                nominal.is_some() == binding.is_some(),
                "RT_SEGMENT_SOURCE_BINDING",
            )?;
            if let (Some(nominal), Some(binding)) = (nominal, binding) {
                let physical = layout
                    .ok_or_else(|| Error::semantic("RT_SEGMENT_SOURCE_BINDING", String::new()))?;
                let binding = abi.storage_binding(ctx.local(
                    Namespace::StorageBinding,
                    self_id(binding, "RT_SEGMENT_SOURCE_BINDING")?,
                )?)?;
                let actual = binding.record();
                let source = abi.nominal(nominal_expectation(ctx, nominal)?)?;
                let geometry = source
                    .layout()
                    .ok_or_else(|| Error::semantic("RT_SEGMENT_SOURCE_BINDING", String::new()))?;
                let width = storage
                    .extent
                    .checked_mul(8)
                    .ok_or_else(|| Error::semantic("RT_SEGMENT_SOURCE_BINDING", String::new()))?;
                require(
                    field(actual, "nominal")? == nominal
                        && entity_ref(field(actual, "execution_layout")?)? == physical
                        && ["object_bytes", "allocation"].contains(&token(actual, "kind")?)
                        && number(actual, "view_offset_bits")? == 0
                        && number(actual, "view_width_bits")? == width
                        && geometry.size_bytes == storage.extent
                        && u64::from(geometry.alignment_bytes) <= storage.alignment
                        && number(actual, "required_alignment")? <= storage.alignment,
                    "RT_SEGMENT_SOURCE_BINDING",
                )?;
            }
        }
    }
    Ok(())
}

pub(crate) fn verify_symbols(
    ctx: &ObjectContext,
    types: &TypeFacts,
    abi: &AbiFacts,
    symbols: &SymbolFacts,
    budget: &mut Budget,
) -> Result<(), Error> {
    types.assert_context(ctx)?;
    abi.assert_context(ctx)?;
    require(
        symbols.identity() == ctx.identity() && symbols.context_id() == ctx.context_id(),
        "RT_CONTEXT_MISMATCH",
    )?;
    let manifest = field(ctx.root(2)?, "manifest")?;
    for dependency in list(field(manifest, "dependencies")?)? {
        for declaration in list(field(dependency, "declarations")?)? {
            budget.work(16)?;
            let plan = source_plan(ctx, abi, declaration, None, budget)?;
            if let (Some(plan), Some(execution)) =
                (plan, optional(field(declaration, "execution")?)?)
            {
                require(
                    types.type_equivalent(
                        abi.signature(plan)?.execution_signature(),
                        types.type_reference(execution)?,
                        budget,
                    )?,
                    "RT_DECLARATION_SOURCE_PLAN_EXECUTION",
                )?;
            }
        }
    }
    for symbol in symbols.all().values() {
        budget.work(24)?;
        let record = ctx.entity(ctx.local(Namespace::Symbol, symbol.id)?)?;
        let execution = types.type_reference(field(record, "execution")?)?;
        verify_execution_category(symbol.kind.as_str(), types.type_record(execution)?)?;
        let native = matches!(symbol.definition, Some(Definition::Native { .. }));
        let plan = source_plan(
            ctx,
            abi,
            record,
            if native { Some(false) } else { None },
            budget,
        )?;
        match symbol.definition {
            None => {}
            Some(Definition::Native { domain, .. }) => {
                // Independent code bytes/entry/permissions/CFI are explicitly deferred.
                require(
                    token(manifest, "foreign_isa")? != "none",
                    "RT_NATIVE_PROCESS_ISA",
                )?;
                let nominal = nominal_expectation(ctx, optional(field(record, "nominal")?)?
                    .ok_or_else(|| Error::semantic("RT_NATIVE_DEFINITION", String::new()))?)?;
                let source = abi.nominal(nominal)?;
                require(number(source.record(), "domain")? == u64::from(domain), "RT_NATIVE_DEFINITION")?;
                let actual_domain = ctx.entity(ctx.local(Namespace::Domain, domain)?)?;
                require(token(actual_domain, "isa")? == token(manifest, "foreign_isa")?, "RT_NATIVE_PROCESS_ISA")?;
            }
            Some(Definition::Function(function)) => {
                let body = types.function_decl(function)?;
                require(
                    types.type_equivalent(execution, body.signature, budget)?,
                    "RT_DEFINITION_SIGNATURE",
                )?;
                let body_plan = body
                    .abi_signature
                    .map(|id| ctx.local(Namespace::CallSignature, id))
                    .transpose()?;
                require(
                    body_plan.is_some() == symbol.nominal.is_some(),
                    "RT_FUNCTION_SOURCE_PRESENCE",
                )?;
                if let Some(body_plan) = body_plan {
                    let nominal = optional(field(record, "nominal")?)?
                        .ok_or_else(|| Error::semantic("RT_FUNCTION_SOURCE_TYPE", String::new()))?;
                    require(
                        abi.nominal_compatible(
                            nominal_expectation(ctx, nominal)?,
                            abi.signature(body_plan)?.function_type(),
                            budget,
                        )?,
                        "RT_FUNCTION_SOURCE_TYPE",
                    )?;
                }
                same_plan(abi, plan, body_plan, "RT_FUNCTION_SOURCE_PLAN", budget)?;
            }
            Some(Definition::Alias(target)) => {
                let target = ctx.entity(ctx.local(Namespace::Symbol, target)?)?;
                let target_type = types.type_reference(field(target, "execution")?)?;
                require(
                    types.type_equivalent(execution, target_type, budget)?,
                    "RT_DEFINITION_SIGNATURE",
                )?;
                require(
                    token(record, "source_linkage")? == token(target, "source_linkage")?,
                    "RT_ALIAS_SOURCE",
                )?;
                same_nominal(
                    ctx,
                    abi,
                    optional(field(record, "nominal")?)?,
                    optional(field(target, "nominal")?)?,
                    "RT_ALIAS_SOURCE",
                    budget,
                )?;
                same_plan(
                    abi,
                    plan,
                    optional_ref(target, "abi_signature")?
                        .map(|r| signature_key(ctx, r))
                        .transpose()?,
                    "RT_ALIAS_SOURCE_PLAN",
                    budget,
                )?;
            }
            Some(Definition::Data(id)) | Some(Definition::Tls(id)) => {
                let namespace = if symbol.kind.as_str() == "data" {
                    Namespace::Data
                } else {
                    Namespace::Tls
                };
                let storage = ctx.entity(ctx.local(namespace, id)?)?;
                let storage = if namespace == Namespace::Tls {
                    field(storage, "storage")?
                } else {
                    storage
                };
                let view = StorageView::parse(storage, budget)?;
                require(
                    symbol.size == Some(view.extent) && symbol.alignment == view.alignment,
                    "RT_SYMBOL_EXTENT",
                )?;
                require(
                    optional(field(record, "nominal")?)? == optional(field(storage, "nominal")?)?,
                    "RT_SYMBOL_STORAGE_NOMINAL",
                )?;
                if let Some(layout) = optional_ref(storage, "layout")? {
                    let layout = types
                        .layout(types.layout_handle(self_id(layout, "RT_SYMBOL_STORAGE_TYPE")?)?)?;
                    require(
                        types.type_equivalent(execution, layout.execution_type, budget)?,
                        "RT_SYMBOL_STORAGE_TYPE",
                    )?;
                }
                let value = types.type_record(execution)?;
                require(
                    token(value, "kind")? == "array" && number(value, "count")? == view.extent,
                    "RT_SYMBOL_STORAGE_CANONICAL",
                )?;
                let element = types.type_record(types.type_reference(field(value, "element")?)?)?;
                require(
                    token(element, "kind")? == "raw" && number(element, "bits")? == 8,
                    "RT_SYMBOL_STORAGE_CANONICAL",
                )?;
            }
            Some(Definition::Import(id)) => {
                let imported = ctx.entity(ctx.local(Namespace::Import, id)?)?;
                require(
                    types.type_equivalent(
                        execution,
                        types.type_reference(field(imported, "signature")?)?,
                        budget,
                    )?,
                    "RT_IMPORT_SIGNATURE",
                )?;
                let actual = if token(imported, "kind")? == "foreign" {
                    let reference = entity_ref(field(imported, "descriptor")?)?;
                    let bridge = abi.bridge(ctx.local(
                        Namespace::Bridge,
                        self_id(reference, "RT_FOREIGN_BRIDGE_SELF")?,
                    )?)?;
                    Some(ctx.local(
                        Namespace::CallSignature,
                        u32_field(bridge.record(), "signature")?,
                    )?)
                } else {
                    None
                };
                same_plan(abi, plan, actual, "RT_IMPORT_SOURCE_PLAN", budget)?;
            }
            Some(Definition::Common { .. }) => {}
        }
        if symbol.nominal.is_some()
            && ["function", "import"].contains(&symbol.kind.as_str())
            && !native
        {
            let nominal = nominal_expectation(
                ctx,
                optional(field(record, "nominal")?)?
                    .ok_or_else(|| Error::semantic("RT_SYMBOL_NOMINAL_EXECUTION", String::new()))?,
            )?;
            let source = abi.nominal(nominal)?;
            let issued = plan.ok_or_else(|| Error::semantic("RT_SYMBOL_NOMINAL_EXECUTION", String::new()))?;
            require(
                types.type_equivalent(
                    abi.signature(issued)?.execution_signature(),
                    execution,
                    budget,
                )?,
                "RT_SYMBOL_NOMINAL_EXECUTION",
            )?;
            let c = list(field(source.record(), "flags")?)?
                .iter()
                .any(|v| crate::context::text(v).is_ok_and(|s| s == "c_linkage"));
            require(
                symbol.source_linkage
                    == if c {
                        SourceLinkage::C
                    } else {
                        SourceLinkage::Cpp
                    },
                "RT_SYMBOL_SOURCE_LINKAGE",
            )?;
        }
        if let Some(reference) = symbol.fallback {
            match ctx.resolve_declaration(Namespace::Symbol, &reference)? {
                crate::context::DeclaredEntity::Local(key) => {
                    let target = ctx.entity(key)?;
                    require(
                        token(target, "kind")? == symbol.kind.as_str()
                            && types.type_equivalent(
                                execution,
                                types.type_reference(field(target, "execution")?)?,
                                budget,
                            )?,
                        "RT_FALLBACK_TYPE",
                    )?;
                    require(
                        token(record, "source_linkage")? == token(target, "source_linkage")?,
                        "RT_FALLBACK_SOURCE",
                    )?;
                    same_nominal(
                        ctx,
                        abi,
                        optional(field(record, "nominal")?)?,
                        optional(field(target, "nominal")?)?,
                        "RT_FALLBACK_SOURCE",
                        budget,
                    )?;
                    same_plan(
                        abi,
                        plan,
                        optional_ref(target, "abi_signature")?
                            .map(|r| signature_key(ctx, r))
                            .transpose()?,
                        "RT_FALLBACK_SOURCE_PLAN",
                        budget,
                    )?;
                }
                crate::context::DeclaredEntity::Dependency { declaration, .. } => {
                    require(
                        token(declaration, "symbol_kind")? == symbol.kind.as_str(),
                        "RT_FALLBACK_TYPE",
                    )?;
                    if let Some(expected) = optional(field(declaration, "execution")?)? {
                        require(
                            types.type_equivalent(
                                execution,
                                types.type_reference(expected)?,
                                budget,
                            )?,
                            "RT_FALLBACK_TYPE",
                        )?;
                    }
                    require(
                        token(record, "source_linkage")? == token(declaration, "source_linkage")?,
                        "RT_FALLBACK_SOURCE",
                    )?;
                    same_nominal(
                        ctx,
                        abi,
                        optional(field(record, "nominal")?)?,
                        optional(field(declaration, "nominal")?)?,
                        "RT_FALLBACK_SOURCE",
                        budget,
                    )?;
                    same_plan(
                        abi,
                        plan,
                        optional_ref(declaration, "abi_signature")?
                            .map(|r| signature_key(ctx, r))
                            .transpose()?,
                        "RT_FALLBACK_SOURCE_PLAN",
                        budget,
                    )?;
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn verify_exports(
    ctx: &ObjectContext,
    types: &TypeFacts,
    abi: &AbiFacts,
    budget: &mut Budget,
) -> Result<(), Error> {
    types.assert_context(ctx)?;
    abi.assert_context(ctx)?;
    for exported in list(field(field(ctx.root(2)?, "manifest")?, "exports")?)? {
        budget.work(20)?;
        let reference = entity_ref(field(exported, "target")?)?;
        let id = self_id(reference, "RT_EXPORT_SELF")?;
        let claimed_execution = optional(field(exported, "execution")?)?
            .map(|v| types.type_reference(v))
            .transpose()?;
        let claimed_nominal = optional(field(exported, "nominal")?)?
            .map(|v| nominal_expectation(ctx, v))
            .transpose()?;
        let claimed_plan = optional_ref(exported, "abi_signature")?
            .map(|v| signature_key(ctx, v))
            .transpose()?;
        let (execution, nominal, plan) = match token(exported, "kind")? {
            "function" => {
                let function = types.function_decl(id)?;
                let plan = function
                    .abi_signature
                    .map(|id| ctx.local(Namespace::CallSignature, id))
                    .transpose()?;
                let nominal = plan
                    .map(|key| abi.signature(key).map(|p| p.function_type()))
                    .transpose()?;
                let linkage = if let Some(key) = nominal {
                    let source = abi.nominal(key)?.record();
                    if list(field(source, "flags")?)?
                        .iter()
                        .any(|v| crate::context::text(v).is_ok_and(|s| s == "c_linkage"))
                    {
                        "c"
                    } else {
                        "cpp"
                    }
                } else {
                    "none"
                };
                require(
                    token(exported, "source_linkage")? == linkage,
                    "RT_EXPORT_SOURCE_LINKAGE",
                )?;
                (Some(function.signature), nominal, plan)
            }
            "symbol" => {
                let symbol = ctx.entity(ctx.local(Namespace::Symbol, id)?)?;
                require(
                    token(exported, "source_linkage")? == token(symbol, "source_linkage")?,
                    "RT_EXPORT_SOURCE_LINKAGE",
                )?;
                (
                    Some(types.type_reference(field(symbol, "execution")?)?),
                    optional(field(symbol, "nominal")?)?
                        .map(|v| nominal_expectation(ctx, v))
                        .transpose()?,
                    optional_ref(symbol, "abi_signature")?
                        .map(|v| signature_key(ctx, v))
                        .transpose()?,
                )
            }
            "type" => {
                let actual = types.type_handle(id)?;
                if let Some(nominal) = claimed_nominal {
                    let expected = abi.nominal(nominal)?.execution_type().ok_or_else(|| {
                        Error::semantic("RT_EXPORT_NOMINAL_BINDING", String::new())
                    })?;
                    require(
                        types.type_equivalent(actual, expected, budget)?,
                        "RT_EXPORT_NOMINAL_BINDING",
                    )?;
                }
                (Some(actual), claimed_nominal, None)
            }
            "nominal" => {
                let key = ctx.local(Namespace::Nominal, id)?;
                (abi.nominal(key)?.execution_type(), Some(key), None)
            }
            "recipe" => {
                abi.recipe(ctx.local(Namespace::Recipe, id)?)?;
                (None, None, None)
            }
            _ => return Err(Error::semantic("RT_EXPORT_IDENTITY", String::new())),
        };
        require(
            execution.is_some() == claimed_execution.is_some()
                && nominal.is_some() == claimed_nominal.is_some(),
            "RT_EXPORT_TYPE_PRESENCE",
        )?;
        if let (Some(a), Some(b)) = (execution, claimed_execution) {
            require(types.type_equivalent(a, b, budget)?, "RT_EXPORT_EXECUTION")?;
        }
        if let (Some(a), Some(b)) = (nominal, claimed_nominal) {
            require(abi.nominal_compatible(a, b, budget)?, "RT_EXPORT_NOMINAL")?;
        }
        same_plan(abi, claimed_plan, plan, "RT_EXPORT_SOURCE_PLAN", budget)?;
    }
    Ok(())
}
