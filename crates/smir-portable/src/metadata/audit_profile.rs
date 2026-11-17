//! Conservative coverage predicate accepted in R-PROD004 and R-PROD005 REV2.
//! This is not an alternative semantic verifier or a test-only success factory.

use super::{
    imports::nominal_expectation,
    records::*,
    symbols::{Definition, SourceLinkage, SymbolFact, SymbolFacts, SymbolKind, optional_ref},
};
use crate::context::{
    EntityRef, ModuleRef, Namespace, ObjectContext, entity_ref, field, list, optional, signed, text,
};
use crate::{Error, ErrorClass, abi::AbiFacts, execution::TypeFacts, limits::Budget};
use std::collections::BTreeMap;

fn covered(condition: bool, field_name: &'static str) -> Result<(), Error> {
    if condition {
        Ok(())
    } else {
        Err(Error::new(
            ErrorClass::UnavailableEvidence,
            "P2_METADATA_PROFILE_UNAUDITED",
            field_name,
        ))
    }
}

fn int32(
    ctx: &ObjectContext,
    abi: &AbiFacts,
    reference: &crate::wire::RecordValue,
) -> Result<bool, Error> {
    let record = abi.nominal(nominal_expectation(ctx, reference)?)?.record();
    Ok(token(record, "kind")? == "scalar"
        && number(record, "bits")? == 32
        && flag(record, "signed")?
        && token(field(record, "identity")?, "entity")? == "int")
}

pub(super) fn verify(
    ctx: &ObjectContext,
    types: &TypeFacts,
    abi: &AbiFacts,
    symbols: &SymbolFacts,
    budget: &mut Budget,
) -> Result<(), Error> {
    types.assert_context(ctx)?;
    abi.assert_context(ctx)?;
    let root = ctx.root(2)?;
    let manifest = field(root, "manifest")?;
    covered(
        token(manifest, "kind")? == "object"
            && optional(field(manifest, "entry")?)?.is_none()
            && token(manifest, "foreign_isa")? == "none",
        "manifest profile",
    )?;
    for name in ["comdats", "initializers", "finalizers"] {
        covered(list(field(root, name)?)?.is_empty(), name)?;
    }
    let capability_root = ctx.root(9)?;
    for capability in list(field(capability_root, "capabilities")?)? {
        budget.work(1)?;
        covered(text(capability)? == "memory", "capability profile")?;
    }
    for name in ["requirements", "limits"] {
        covered(list(field(capability_root, name)?)?.is_empty(), name)?;
    }
    // Logical EH correctness belongs to the actual ProgramFacts phase. The
    // current ABI profile independently excludes every cleanup journal.
    let mut owners = BTreeMap::new();
    budget.edges(symbols.all().len())?;
    budget.reserve_bytes(
        symbols
            .all()
            .len()
            .checked_mul(128)
            .ok_or_else(|| Error::resource("RT_PROFILE_RESOURCE", "owners"))?,
    )?;
    for symbol in symbols.all().values() {
        budget.work(24)?;
        if symbol.kind == SymbolKind::Function {
            function_symbol(ctx, types, abi, symbol, budget)?;
        } else if symbol.kind == SymbolKind::FunctionAddress {
            // Static unresolved address expectation only. The source nominal
            // must be the same actual SELF entity as the audited ordinary Fn.
            budget.work(symbols.all().len() as u64)?;
            let ordinary = symbols.all().values().find(|s| s.kind == SymbolKind::Function);
            covered(
                symbol.binding == "strong"
                    && symbol.visibility == "default"
                    && symbol.source_linkage == SourceLinkage::Cpp
                    && symbol.definition.is_none()
                    && symbol.abi_signature.is_none()
                    && symbol.size.is_none()
                    && symbol.alignment == 1
                    && symbol.comdat.is_none()
                    && symbol.fallback.is_none()
                    && symbol.nominal.is_some_and(|n| n.module == ModuleRef::SelfModule)
                    && ordinary.is_some_and(|s| s.nominal == symbol.nominal),
                "function address profile",
            )?;
        } else {
            let (kind, id, size) = object_symbol(ctx, types, abi, symbol, budget)?;
            if let Some(prior) = owners.insert((kind, id), size) {
                covered(prior == size, "storage owner agreement")?;
            }
        }
    }
    verify_storage(ctx, abi, &owners, budget)?;
    verify_patches(ctx, types, symbols, &owners, budget)?;
    verify_imports(ctx, types, abi, budget)?;
    Ok(())
}

fn function_symbol(
    ctx: &ObjectContext,
    types: &TypeFacts,
    abi: &AbiFacts,
    symbol: &SymbolFact,
    budget: &mut Budget,
) -> Result<(), Error> {
    budget.work(48)?;
    covered(
        symbol.kind == super::symbols::SymbolKind::Function
            && symbol.binding == "strong"
            && symbol.visibility == "default"
            && symbol.alignment == 1
            && symbol.size.is_none()
            && symbol.comdat.is_none()
            && symbol.fallback.is_none(),
        "symbol profile",
    )?;
    covered(!matches!(symbol.definition, Some(Definition::Native { .. })), "native function profile")?;
    // verify_symbols already checked every actual body/alias/source-plan join.
    // Cardinality and personality are not transport or provider evidence.
    let record = ctx.entity(ctx.local(Namespace::Symbol, symbol.id)?)?;
    let signature = types.type_record(types.type_reference(field(record, "execution")?)?)?;
    covered(
        token(signature, "kind")? == "function"
            && token(signature, "cc")? == "portable"
            && !flag(signature, "variadic")?,
        "execution function profile",
    )?;
    // Generic SELF functions carry no ordinary source ABI. Actual type, body,
    // alias and complete program proofs remain mandatory; arity/width do not
    // supply runtime authority or justify the source-linked transport profile.
    if symbol.source_linkage == SourceLinkage::None
        && symbol.nominal.is_none()
        && symbol.abi_signature.is_none()
        && symbol.execution.module == ModuleRef::SelfModule
    {
        return Ok(());
    }
    if ordinary_scalar_function(ctx, types, abi, symbol, signature, budget)? {
        return Ok(());
    }
    if ordinary_pointer_function(ctx, types, abi, symbol, signature, budget)? {
        return Ok(());
    }
    let params = list(field(signature, "params")?)?;
    let results = list(field(signature, "results")?)?;
    covered(
        params.len() == 1 && results.len() == 1,
        "execution signature profile",
    )?;
    for reference in [&params[0], &results[0]] {
        let record = types.type_record(types.type_reference(reference)?)?;
        covered(
            token(record, "kind")? == "int" && number(record, "bits")? == 32,
            "execution scalar profile",
        )?;
    }
    if symbol.nominal.is_none() && symbol.abi_signature.is_none() {
        return covered(symbol.source_linkage == SourceLinkage::None, "generic source profile");
    }
    covered(symbol.nominal.is_some() && symbol.abi_signature.is_some(), "source plan presence")?;
    covered(symbol.abi_signature.is_some_and(|r| r.module == ModuleRef::SelfModule),
            "source plan namespace")?;
    let EntityRef { id, .. } = symbol.abi_signature.ok_or_else(|| {
        Error::new(
            ErrorClass::UnavailableEvidence,
            "P2_METADATA_PROFILE_UNAUDITED",
            "source plan presence",
        )
    })?;
    let plan = abi
        .signature(ctx.local(Namespace::CallSignature, id)?)?
        .record();
    let params = list(field(plan, "params")?)?;
    let result = optional(field(plan, "result")?)?;
    covered(
        params.len() == 1
            && result.is_some()
            && optional(field(plan, "this_type")?)?.is_none()
            && !flag(plan, "vtt")?
            && !flag(plan, "variadic")?
            && optional(field(plan, "varargs")?)?.is_none(),
        "source signature profile",
    )?;
    covered(
        int32(ctx, abi, &params[0])?
            && int32(
                ctx,
                abi,
                result.ok_or_else(|| {
                    Error::new(
                        ErrorClass::UnavailableEvidence,
                        "P2_METADATA_PROFILE_UNAUDITED",
                        "source result",
                    )
                })?,
            )?,
        "source scalar profile",
    )?;
    let lowered = list(field(plan, "lowered_params")?)?;
    covered(
        lowered.len() == 1
            && token(&lowered[0], "role")? == "parameter"
            && token(&lowered[0], "mode")? == "direct"
            && list(field(plan, "lowered_results")?)?.len() == 1,
        "source lowered profile",
    )?;
    Ok(())
}

// Ordinary scalar transport has a separate coverage predicate. DATA/TLS and
// helper purposes intentionally retain the original int32() boundary.
fn ordinary_scalar(
    ctx: &ObjectContext,
    types: &TypeFacts,
    abi: &AbiFacts,
    reference: &crate::wire::RecordValue,
    budget: &mut Budget,
) -> Result<bool, Error> {
    budget.work(24)?;
    if entity_ref(reference)?.module != ModuleRef::SelfModule {
        return Ok(false);
    }
    let nominal = abi.nominal(nominal_expectation(ctx, reference)?)?.record();
    if token(nominal, "kind")? != "scalar" {
        return Ok(false);
    }
    let (width, signed) = match token(field(nominal, "identity")?, "entity")? {
        "signed char" => (8, true),
        "unsigned char" => (8, false),
        "short" => (16, true),
        "unsigned short" => (16, false),
        "int" => (32, true),
        "unsigned int" => (32, false),
        "long" | "long long" => (64, true),
        "unsigned long" | "unsigned long long" => (64, false),
        _ => return Ok(false),
    };
    if number(nominal, "bits")? != width || flag(nominal, "signed")? != signed {
        return Ok(false);
    }
    let Some(execution) = optional(field(nominal, "execution")?)? else {
        return Ok(false);
    };
    if entity_ref(execution)?.module != ModuleRef::SelfModule {
        return Ok(false);
    }
    let actual = types.type_record(types.type_reference(execution)?)?;
    Ok(token(actual, "kind")? == "int" && number(actual, "bits")? == width)
}

fn ordinary_scalar_function(
    ctx: &ObjectContext,
    types: &TypeFacts,
    abi: &AbiFacts,
    symbol: &SymbolFact,
    execution: &crate::wire::RecordValue,
    budget: &mut Budget,
) -> Result<bool, Error> {
    budget.work(32)?;
    if symbol.execution.module != ModuleRef::SelfModule
        || !matches!(symbol.source_linkage, SourceLinkage::C | SourceLinkage::Cpp)
        || !symbol.nominal.is_some_and(|r| r.module == ModuleRef::SelfModule)
    {
        return Ok(false);
    }
    let Some(reference) = symbol.abi_signature else { return Ok(false); };
    if reference.module != ModuleRef::SelfModule { return Ok(false); }
    let proof = abi.signature(ctx.local(Namespace::CallSignature, reference.id)?)?;
    let plan = proof.record();
    if optional(field(plan, "this_type")?)?.is_some()
        || flag(plan, "vtt")? || flag(plan, "variadic")? || flag(plan, "noexcept")?
        || optional(field(plan, "varargs")?)?.is_some()
    {
        return Ok(false);
    }
    let params = list(field(plan, "params")?)?;
    let lowered = list(field(plan, "lowered_params")?)?;
    let results = list(field(plan, "lowered_results")?)?;
    budget.edges(params.len())?;
    budget.work(params.len() as u64)?;
    if params.len() != lowered.len()
        || params.len() != list(field(execution, "params")?)?.len()
    {
        return Ok(false);
    }
    for (source, transport) in params.iter().zip(lowered) {
        if !ordinary_scalar(ctx, types, abi, source, budget)?
            || token(transport, "role")? != "parameter"
            || token(transport, "mode")? != "direct"
        {
            return Ok(false);
        }
        for action in ["copy", "move", "destroy"] {
            if optional(field(transport, action)?)?.is_some() { return Ok(false); }
        }
    }
    match optional(field(plan, "result")?)? {
        None => {
            let source = abi.nominal(proof.function_type())?.record();
            let elements = list(field(source, "elements")?)?;
            let Some(last) = elements.last() else { return Ok(false); };
            let result = abi.nominal(nominal_expectation(ctx, last)?)?.record();
            Ok(token(result, "kind")? == "void"
                && results.is_empty() && list(field(execution, "results")?)?.is_empty())
        }
        Some(source) => Ok(ordinary_scalar(ctx, types, abi, source, budget)?
            && results.len() == 1 && list(field(execution, "results")?)?.len() == 1),
    }
}

fn object_symbol(
    ctx: &ObjectContext,
    types: &TypeFacts,
    abi: &AbiFacts,
    symbol: &SymbolFact,
    budget: &mut Budget,
) -> Result<(StorageKind, u32, u64), Error> {
    covered(
        symbol.source_linkage == SourceLinkage::C
            && symbol.binding == "strong"
            && symbol.visibility == "default"
            && symbol.abi_signature.is_none()
            && symbol.comdat.is_none()
            && symbol.fallback.is_none()
            && symbol.execution.module == ModuleRef::SelfModule,
        "object symbol profile",
    )?;
    let (kind, id) = match (symbol.kind, symbol.definition) {
        (SymbolKind::Data, Some(Definition::Data(id))) => (StorageKind::Data, id),
        (SymbolKind::Tls, Some(Definition::Tls(id))) => (StorageKind::Tls, id),
        _ => {
            covered(false, "direct object definition")?;
            unreachable!()
        }
    };
    let nominal = symbol.nominal.ok_or_else(|| {
        Error::new(
            ErrorClass::UnavailableEvidence,
            "P2_METADATA_PROFILE_UNAUDITED",
            "object nominal",
        )
    })?;
    covered(
        nominal.module == ModuleRef::SelfModule,
        "object nominal namespace",
    )?;
    let source = abi.nominal(ctx.local(Namespace::Nominal, nominal.id)?)?;
    let layout = source.layout().ok_or_else(|| {
        Error::new(
            ErrorClass::UnavailableEvidence,
            "P2_METADATA_PROFILE_UNAUDITED",
            "object source layout",
        )
    })?;
    let size = layout.size_bytes;
    covered(
        matches!(size, 4 | 8)
            && symbol.size == Some(size)
            && symbol.alignment == size
            && u64::from(layout.alignment_bytes) == size,
        "object geometry profile",
    )?;
    let record = source.record();
    let source_supported = if token(record, "kind")? == "scalar" {
        size == 4
            && number(record, "bits")? == 32
            && flag(record, "signed")?
            && token(field(record, "identity")?, "entity")? == "int"
    } else if token(record, "kind")? == "pointer" {
        let elements = list(field(record, "elements")?)?;
        size == 8 && elements.len() == 1 && int32(ctx, abi, &elements[0])?
    } else {
        false
    };
    covered(source_supported, "object source profile")?;
    let raw = types.type_record(
        types.type_from_entity(ctx.local(Namespace::ExecutionType, symbol.execution.id)?)?,
    )?;
    covered(
        token(raw, "kind")? == "array" && number(raw, "count")? == size,
        "object execution storage profile",
    )?;
    let byte = types.type_record(types.type_reference(field(raw, "element")?)?)?;
    covered(
        token(byte, "kind")? == "raw" && number(byte, "bits")? == 8,
        "object execution byte profile",
    )?;
    budget.work(8)?;
    Ok((kind, id, size))
}

fn verify_storage(
    ctx: &ObjectContext,
    abi: &AbiFacts,
    owners: &BTreeMap<(StorageKind, u32), u64>,
    budget: &mut Budget,
) -> Result<(), Error> {
    for (section, kind) in [(4, StorageKind::Data), (7, StorageKind::Tls)] {
        for entry in list(field(ctx.root(section)?, "segments")?)? {
            budget.work(24)?;
            let record = if kind == StorageKind::Tls {
                covered(
                    token(entry, "initialization")? == "static"
                        && list(field(entry, "initializers")?)?.is_empty()
                        && list(field(entry, "destructors")?)?.is_empty(),
                    "TLS lifecycle profile",
                )?;
                field(entry, "storage")?
            } else {
                entry
            };
            let view = StorageView::parse(record, budget)?;
            covered(
                owners.get(&(kind, view.id)) == Some(&view.extent)
                    && matches!(view.extent, 4 | 8)
                    && view.alignment == view.extent
                    && view.zero_shadow == ZeroShadow::Defined
                    && view.poison.iter().all(|v| *v == 0)
                    && view.undef.iter().all(|v| *v == 0),
                "storage profile",
            )?;
            let layout = optional_ref(record, "layout")?;
            let nominal = optional_ref(record, "nominal")?;
            let binding = optional_ref(record, "abi_binding")?;
            covered(
                [layout, nominal, binding]
                    .iter()
                    .all(|r| r.is_some_and(|r| r.module == ModuleRef::SelfModule)),
                "storage source profile",
            )?;
            let binding = binding.ok_or_else(|| {
                Error::new(
                    ErrorClass::UnavailableEvidence,
                    "P2_METADATA_PROFILE_UNAUDITED",
                    "storage binding",
                )
            })?;
            covered(
                token(
                    abi.storage_binding(ctx.local(Namespace::StorageBinding, binding.id)?)?
                        .record(),
                    "kind",
                )? == "allocation",
                "allocation binding profile",
            )?;
        }
    }
    Ok(())
}

fn verify_patches(
    ctx: &ObjectContext,
    types: &TypeFacts,
    symbols: &SymbolFacts,
    owners: &BTreeMap<(StorageKind, u32), u64>,
    budget: &mut Budget,
) -> Result<(), Error> {
    for patch in list(field(ctx.root(5)?, "relocations")?)? {
        budget.work(24)?;
        let target = entity_ref(field(patch, "target")?)?;
        covered(
            token(patch, "source_kind")? == "data"
                && owners.get(&(StorageKind::Data, u32_field(patch, "source")?)) == Some(&8)
                && (token(patch, "kind")? == "data_address"
                    || token(patch, "kind")? == "code_address"
                        && target.module == ModuleRef::SelfModule
                        && symbols.symbol(target.id)?.kind == SymbolKind::Function
                        && matches!(symbols.symbol(target.id)?.definition, Some(Definition::Function(_))))
                && number(patch, "width")? == 8
                && number(patch, "integer_bits")? == 0
                && number(patch, "offset")? == 0
                && signed(field(patch, "addend")?)? == 0
                && list(field(patch, "derivation")?)?.is_empty()
                && list(field(patch, "flags")?)?.is_empty()
                && !flag(patch, "check_base")?
                && optional(field(patch, "inrange")?)?.is_none()
                && target.module == ModuleRef::SelfModule,
            "relocation profile",
        )?;
        // The semantic pass already proves the target is an actual direct DATA
        // symbol for data_address, or a direct Function for code_address.
        // Profile ownership excludes aliases, common and weak.
    }
    for initializer in list(field(ctx.root(5)?, "constant_initializers")?)? {
        budget.work(16)?;
        let source = owners.get(&(StorageKind::Data, u32_field(initializer, "source")?));
        let layout = entity_ref(field(initializer, "layout")?)?;
        let function = entity_ref(field(initializer, "function")?)?;
        covered(
            token(initializer, "source_kind")? == "data"
                && source.is_some()
                && number(initializer, "offset")? == 0
                && optional(field(initializer, "association")?)?.is_none()
                && layout.module == ModuleRef::SelfModule
                && function.module == ModuleRef::SelfModule,
            "constant initializer profile",
        )?;
        let layout = types.layout(types.layout_handle(layout.id)?)?;
        covered(
            source == Some(&layout.size_bytes) && layout.access_bytes == layout.size_bytes,
            "constant initializer extent",
        )?;
    }
    Ok(())
}

fn verify_imports(
    ctx: &ObjectContext,
    types: &TypeFacts,
    abi: &AbiFacts,
    budget: &mut Budget,
) -> Result<(), Error> {
    for import in list(field(ctx.root(6)?, "imports")?)? {
        budget.work(24)?;
        match token(import, "kind")? {
            "service" => covered(
                token(import, "name")? == "memory.map"
                    && optional(field(import, "abi")?)?.is_none()
                    && optional(field(import, "descriptor")?)?.is_none()
                    && token(import, "capability")? == "memory",
                "service profile",
            )?,
            "internal" => {
                let name = token(import, "name")?;
                let state_abi = [
                    "va_start",
                    "va_copy",
                    "va_end",
                    "setjmp_capture",
                    "longjmp_restore",
                ]
                .contains(&name);
                let scalar_abi = ["va_arg", "tls_address"].contains(&name);
                let journal = name == "journal_advance";
                let no_abi = [
                    "stack_alloc",
                    "tls_address_raw",
                    "eh_begin_catch",
                    "lifetime_start",
                    "lifetime_end",
                    "stack_save",
                    "stack_restore",
                    "eh_end_catch",
                    "eh_release",
                ]
                .contains(&name);
                covered(
                    scalar_abi || state_abi || journal || no_abi,
                    "helper profile",
                )?;
                let contract = token(import, "contract")?;
                covered(
                    if ["setjmp_capture", "longjmp_restore"].contains(&name) {
                        ["setjmp", "sigsetjmp"].contains(&contract)
                    } else if journal {
                        [
                            "construct_begin",
                            "construct_commit",
                            "destroy_begin",
                            "destroy_commit",
                            "ownership_transfer",
                            "retain",
                            "release",
                        ]
                        .contains(&contract)
                    } else {
                        contract == "default"
                    },
                    "helper contract profile",
                )?;
                let source = optional(field(import, "abi")?)?;
                let binding_types = list(field(import, "types")?)?;
                covered(
                    binding_types.len() == if name == "va_arg" { 1 } else { 0 },
                    "helper type arguments profile",
                )?;
                let nominal_key = if scalar_abi || state_abi {
                    let reference = source.ok_or_else(|| {
                        Error::new(
                            ErrorClass::UnavailableEvidence,
                            "P2_METADATA_PROFILE_UNAUDITED",
                            "helper nominal profile",
                        )
                    })?;
                    covered(
                        entity_ref(reference)?.module == ModuleRef::SelfModule,
                        "helper nominal namespace profile",
                    )?;
                    let key = nominal_expectation(ctx, reference)?;
                    if state_abi {
                        // Real admitted ABI facts and the complete source predicate
                        // precede coverage; array/name alone is not source proof.
                        super::source_roles::verify(ctx, types, abi, key, import, budget)?;
                    } else {
                        covered(int32(ctx, abi, reference)?, "helper scalar profile")?;
                    }
                    if name == "va_arg" {
                        let nominal = abi.nominal(key)?.record();
                        let execution =
                            optional(field(nominal, "execution")?)?.ok_or_else(|| {
                                Error::new(
                                    ErrorClass::UnavailableEvidence,
                                    "P2_METADATA_PROFILE_UNAUDITED",
                                    "helper nominal execution",
                                )
                            })?;
                        covered(
                            entity_ref(&binding_types[0])?.module == ModuleRef::SelfModule
                                && types.type_equivalent(
                                    types.type_reference(execution)?,
                                    types.type_reference(&binding_types[0])?,
                                    budget,
                                )?,
                            "va_arg execution/source profile",
                        )?;
                    }
                    Some(key)
                } else if journal {
                    let reference = source.ok_or_else(|| {
                        Error::new(
                            ErrorClass::UnavailableEvidence,
                            "P2_METADATA_PROFILE_UNAUDITED",
                            "helper journal profile",
                        )
                    })?;
                    let reference = entity_ref(reference)?;
                    covered(
                        reference.module == ModuleRef::SelfModule,
                        "helper journal namespace",
                    )?;
                    let checked = abi
                        .journal(ctx.local(Namespace::Journal, reference.id)?)?
                        .record();
                    covered(
                        list(field(checked, "params")?)?.is_empty(),
                        "helper journal captures",
                    )?;
                    None
                } else {
                    covered(source.is_none(), "helper unused ABI")?;
                    None
                };
                let options = field(import, "options")?;
                covered(
                    number(options, "alignment")? == 1
                        && token(options, "scope")? == "process"
                        && token(options, "order")? == "none"
                        && token(options, "failure_order")? == "none"
                        && !flag(options, "weak")?
                        && token(options, "comparison")? == "none"
                        && crate::context::bytes(field(options, "mask")?)?.is_empty()
                        && token(options, "rounding")? == "none"
                        && token(options, "exceptions")? == "none"
                        && token(options, "predicate")? == "none"
                        && list(field(options, "flags")?)?.is_empty(),
                    "helper option profile",
                )?;
                let target = optional_ref(options, "target")?;
                covered(
                    if ["tls_address_raw", "tls_address"].contains(&name) {
                        target.is_some_and(|r| r.module == ModuleRef::SelfModule)
                    } else {
                        target.is_none()
                    },
                    "helper target profile",
                )?;
                if name == "tls_address" {
                    let target = target.ok_or_else(|| {
                        Error::new(
                            ErrorClass::UnavailableEvidence,
                            "P2_METADATA_PROFILE_UNAUDITED",
                            "TLS helper target",
                        )
                    })?;
                    let entry = ctx.entity(ctx.local(Namespace::Tls, target.id)?)?;
                    let storage = field(entry, "storage")?;
                    let actual = optional(field(storage, "nominal")?)?.ok_or_else(|| {
                        Error::new(
                            ErrorClass::UnavailableEvidence,
                            "P2_METADATA_PROFILE_UNAUDITED",
                            "TLS source nominal",
                        )
                    })?;
                    let expected = nominal_key.ok_or_else(|| {
                        Error::new(
                            ErrorClass::UnavailableEvidence,
                            "P2_METADATA_PROFILE_UNAUDITED",
                            "TLS helper nominal",
                        )
                    })?;
                    covered(
                        abi.nominal_compatible(
                            expected,
                            nominal_expectation(ctx, actual)?,
                            budget,
                        )?,
                        "TLS helper source agreement",
                    )?;
                }
            }
            _ => covered(false, "import profile")?,
        }
    }
    Ok(())
}

// Paired pointer transport is deliberately separate from scalar/storage helpers.
fn ordinary_pointer(
    ctx: &ObjectContext, types: &TypeFacts, abi: &AbiFacts,
    reference: &crate::wire::RecordValue, budget: &mut Budget,
) -> Result<bool, Error> {
    budget.work(64)?;
    if entity_ref(reference)?.module != ModuleRef::SelfModule { return Ok(false); }
    let fact = abi.nominal(nominal_expectation(ctx, reference)?)?;
    let nominal = fact.record();
    if token(nominal, "kind")? != "pointer" || number(nominal, "bits")? != 64
        || flag(nominal, "signed")? || token(nominal, "representation")? != "value"
        || optional(field(nominal, "extent")?)?.is_some() { return Ok(false); }
    for name in ["qualifiers", "methods", "enumerators"] {
        if !list(field(nominal, name)?)?.is_empty() { return Ok(false); }
    }
    let identity = field(nominal, "identity")?;
    if token(identity, "entity")? != "pointer" || token(identity, "linkage")? != "builtin"
        || !matches!(token(identity, "language")?, "c23" | "cpp23")
        || optional(field(identity, "library")?)?.is_some()
        || optional(field(identity, "unit")?)?.is_some()
        || optional(field(nominal, "record_input")?)?.is_some() { return Ok(false); }
    let flags = list(field(nominal, "flags")?)?;
    if flags.len() != 3 { return Ok(false); }
    for expected in ["complete", "trivial_copy", "trivial_destroy"] {
        if !flags.iter().any(|v| crate::context::text(v) == Ok(expected)) { return Ok(false); }
    }
    let Some(layout) = fact.layout() else { return Ok(false); };
    if layout.size_bytes != 8 || layout.alignment_bytes != 8
        || layout.data_size_bytes != 8 || layout.nonvirtual_size_bytes != 8
        || layout.nonvirtual_alignment_bytes != 8 { return Ok(false); }
    let Some(execution) = optional(field(nominal, "execution")?)? else { return Ok(false); };
    if entity_ref(execution)?.module != ModuleRef::SelfModule
        || token(types.type_record(types.type_reference(execution)?)?, "kind")? != "data_ptr"
    { return Ok(false); }
    let elements = list(field(nominal, "elements")?)?;
    if elements.len() != 1 || entity_ref(&elements[0])?.module != ModuleRef::SelfModule { return Ok(false); }
    let pointee = abi.nominal(nominal_expectation(ctx, &elements[0])?)?.record();
    if !list(field(pointee, "qualifiers")?)?.is_empty() { return Ok(false); }
    if ordinary_scalar(ctx, types, abi, &elements[0], budget)? { return Ok(true); }
    Ok(token(pointee, "kind")? == "void"
        && token(field(pointee, "identity")?, "entity")? == "void"
        && number(pointee, "bits")? == 0 && !flag(pointee, "signed")?
        && token(pointee, "representation")? == "none"
        && optional(field(pointee, "execution")?)?.is_none()
        && optional(field(pointee, "layout")?)?.is_none()
        && optional(field(pointee, "extent")?)?.is_none()
        && list(field(pointee, "elements")?)?.is_empty())
}

fn ordinary_pointer_function(
    ctx: &ObjectContext, types: &TypeFacts, abi: &AbiFacts, symbol: &SymbolFact,
    execution: &crate::wire::RecordValue, budget: &mut Budget,
) -> Result<bool, Error> {
    budget.work(48)?;
    if symbol.execution.module != ModuleRef::SelfModule
        || !matches!(symbol.source_linkage, SourceLinkage::C | SourceLinkage::Cpp)
        || !symbol.nominal.is_some_and(|r| r.module == ModuleRef::SelfModule)
    { return Ok(false); }
    let Some(reference) = symbol.abi_signature else { return Ok(false); };
    if reference.module != ModuleRef::SelfModule { return Ok(false); }
    let proof = abi.signature(ctx.local(Namespace::CallSignature, reference.id)?)?;
    let plan = proof.record();
    if optional(field(plan, "this_type")?)?.is_some() || flag(plan, "vtt")?
        || flag(plan, "variadic")? || flag(plan, "noexcept")?
        || optional(field(plan, "varargs")?)?.is_some() { return Ok(false); }
    let params = list(field(plan, "params")?)?;
    let lowered = list(field(plan, "lowered_params")?)?;
    let results = list(field(plan, "lowered_results")?)?;
    budget.edges(params.len())?; budget.work(params.len() as u64)?;
    if params.len() != lowered.len() || params.len() != list(field(execution, "params")?)?.len() {
        return Ok(false);
    }
    let mut used_pointer = false;
    for (source, transport) in params.iter().zip(lowered) {
        let pointer = ordinary_pointer(ctx, types, abi, source, budget)?;
        if !pointer && !ordinary_scalar(ctx, types, abi, source, budget)? { return Ok(false); }
        used_pointer |= pointer;
        if token(transport, "role")? != "parameter" || token(transport, "mode")? != "direct" {
            return Ok(false);
        }
        for action in ["copy", "move", "destroy"] {
            if optional(field(transport, action)?)?.is_some() { return Ok(false); }
        }
    }
    match optional(field(plan, "result")?)? {
        None => {
            let source = abi.nominal(proof.function_type())?.record();
            let elements = list(field(source, "elements")?)?;
            let Some(last) = elements.last() else { return Ok(false); };
            let result = abi.nominal(nominal_expectation(ctx, last)?)?.record();
            Ok(used_pointer && token(result, "kind")? == "void"
                && results.is_empty() && list(field(execution, "results")?)?.is_empty())
        }
        Some(source) => {
            let pointer = ordinary_pointer(ctx, types, abi, source, budget)?;
            Ok((used_pointer || pointer)
                && (pointer || ordinary_scalar(ctx, types, abi, source, budget)?)
                && results.len() == 1 && list(field(execution, "results")?)?.len() == 1)
        }
    }
}
