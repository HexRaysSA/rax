//! Type checks against actual immutable function/import/declaration records.
//!
//! Complete ABI and metadata proofs are mandatory at the enclosing phase join;
//! reading a signature here does not assert provider/native/grant availability.

use crate::context::{DeclaredEntity, Namespace, ObjectContext, entity_ref, field};
use crate::error::Error;
use crate::limits::Budget;
use crate::wire::RecordValue;

use super::cfg::Cfg;
use super::pure::same;
use super::records::{identifier, local_reference, option, require, sequence, token};
use super::{TypeFacts, TypeHandle, TypeKind};

pub(super) fn target_signature<'a>(
    ctx: &'a ObjectContext,
    types: &TypeFacts,
    cfg: &Cfg<'_>,
    target: &RecordValue,
    budget: &mut Budget,
) -> Result<(TypeHandle, Option<&'a RecordValue>), Error> {
    budget.work(1)?;
    let signature = types.type_reference(field(target, "signature")?)?;
    require(
        matches!(types.kind(signature)?, TypeKind::Function { .. }),
        "call_signature",
    )?;
    let mut import = None;
    match token(target, "kind")? {
        "direct" => {
            let reference = entity_ref(field(target, "function")?)?;
            let actual = match ctx.resolve_declaration(Namespace::Function, &reference)? {
                DeclaredEntity::Local(key) => types.function_decl(key.id())?.signature,
                DeclaredEntity::Dependency { declaration, .. } => {
                    let expected = option(declaration, "execution")?.ok_or_else(|| {
                        Error::semantic(
                            "declaration_function_signature",
                            "missing expected execution",
                        )
                    })?;
                    local_reference(expected)?;
                    types.type_reference(expected)?
                }
            };
            require(
                types.type_equivalent(actual, signature, budget)?,
                "call_signature",
            )?;
        }
        "indirect" => {
            let pointer = cfg.value_type(identifier(target, "value")?)?;
            let TypeKind::CodePtr { signature: actual } = types.kind(pointer)? else {
                return Err(Error::semantic("call_indirect_signature", "pointer"));
            };
            require(
                types.type_equivalent(types.type_handle(*actual)?, signature, budget)?,
                "call_indirect_signature",
            )?;
        }
        "import" => {
            let id = local_reference(field(target, "import")?)?;
            let binding = ctx.entity(ctx.local(Namespace::Import, id)?)?;
            let actual = types.type_reference(field(binding, "signature")?)?;
            require(
                types.type_equivalent(actual, signature, budget)?,
                "helper_binding_signature",
            )?;
            import = Some(binding);
        }
        _ => return Err(Error::semantic("call_target", "kind")),
    }
    Ok((signature, import))
}

pub(super) fn check_call<'a>(
    ctx: &'a ObjectContext,
    types: &TypeFacts,
    cfg: &Cfg<'_>,
    target: &RecordValue,
    args: &[TypeHandle],
    results: &[TypeHandle],
    budget: &mut Budget,
) -> Result<(TypeHandle, Option<&'a RecordValue>), Error> {
    let (signature, import) = target_signature(ctx, types, cfg, target, budget)?;
    let TypeKind::Function {
        params,
        results: expected,
        ..
    } = types.kind(signature)?
    else {
        return Err(Error::semantic("call_signature", "function"));
    };
    require(params.len() == args.len(), "call_arguments")?;
    require(expected.len() == results.len(), "call_results")?;
    for (arg, param) in args.iter().zip(params) {
        budget.work(1)?;
        require(
            types.type_equivalent(*arg, types.type_handle(*param)?, budget)?,
            "call_argument_type",
        )?;
    }
    for (result, expected) in results.iter().zip(expected) {
        budget.work(1)?;
        require(
            types.type_equivalent(*result, types.type_handle(*expected)?, budget)?,
            "call_result_type",
        )?;
    }
    Ok((signature, import))
}

pub(super) fn helper<'a>(
    ctx: &'a ObjectContext,
    types: &TypeFacts,
    cfg: &Cfg<'_>,
    operation: &RecordValue,
    args: &[TypeHandle],
    results: &[TypeHandle],
    budget: &mut Budget,
) -> Result<&'a RecordValue, Error> {
    let name = token(operation, "op")?;
    let target = field(operation, "helper")?;
    require(token(target, "kind")? == "import", "helper_target")?;
    let (signature, binding) = target_signature(ctx, types, cfg, target, budget)?;
    let binding = binding.ok_or_else(|| Error::semantic("helper_target", "import"))?;
    let helper_name = match name {
        "alloca" => "stack_alloc",
        "setjmp" => "setjmp_capture",
        "longjmp" => "longjmp_restore",
        other => other,
    };
    require(
        token(binding, "kind")? == "internal"
            && token(binding, "name")? == helper_name
            && token(binding, "namespace")? == "smir.internal.v1",
        "helper_name",
    )?;
    if name == "alloca" {
        let TypeKind::Function {
            params,
            results: expected,
            ..
        } = types.kind(signature)?
        else {
            return Err(Error::semantic("alloca_helper_signature", "function"));
        };
        require(
            params.len() == 2 && expected.len() == 1 && args.len() == 1 && results.len() == 1,
            "alloca_helper_signature",
        )?;
        let first = *params
            .first()
            .ok_or_else(|| Error::semantic("alloca_helper_signature", "size"))?;
        let second = *params
            .get(1)
            .ok_or_else(|| Error::semantic("alloca_helper_signature", "alignment"))?;
        let result = *expected
            .first()
            .ok_or_else(|| Error::semantic("alloca_helper_signature", "result"))?;
        same(types, args[0], types.type_handle(first)?, budget)?;
        require(
            matches!(types.kind(types.type_handle(second)?)?, TypeKind::Int(64)),
            "alloca_helper_signature",
        )?;
        same(types, results[0], types.type_handle(result)?, budget)?;
    } else {
        check_call(ctx, types, cfg, target, args, results, budget)?;
    }
    let alignment = super::records::number(operation, "alignment")?;
    require(
        alignment == 0 || alignment.is_power_of_two(),
        "helper_alignment",
    )?;
    require(name != "alloca" || alignment > 0, "alloca_alignment")?;
    let nominal = option(operation, "binding")?;
    if name == "tls_address" {
        let nominal = nominal.ok_or_else(|| Error::semantic("tls_binding", "binding"))?;
        let bound = option(field(binding, "options")?, "target")?
            .ok_or_else(|| Error::semantic("tls_binding", "target"))?;
        require(nominal == bound, "tls_binding")?;
    } else if let Some(nominal) = nominal {
        ctx.resolve_declaration(Namespace::Nominal, &entity_ref(nominal)?)?;
    }
    Ok(binding)
}

pub(super) fn address_of(
    ctx: &ObjectContext,
    types: &TypeFacts,
    operation: &RecordValue,
    result: TypeHandle,
    budget: &mut Budget,
) -> Result<(), Error> {
    let symbol_ref = entity_ref(field(operation, "symbol")?)?;
    let symbol = match ctx.resolve_declaration(Namespace::Symbol, &symbol_ref)? {
        DeclaredEntity::Local(key) => ctx.entity(key)?,
        DeclaredEntity::Dependency { declaration, .. } => declaration,
    };
    let is_declaration = super::records::reference(field(operation, "symbol")?)?.is_dependency();
    let kind = if is_declaration {
        token(symbol, "symbol_kind")?
    } else {
        token(symbol, "kind")?
    };
    if matches!(types.kind(result)?, TypeKind::CodeAddress) {
        require(
            ["function", "import", "function_address"].contains(&kind),
            "symbol_code_address",
        )?;
        let nominal = option(symbol, "nominal")?
            .ok_or_else(|| Error::semantic("symbol_code_source", "missing source function"))?;
        let nominal = match ctx.resolve_declaration(Namespace::Nominal, &entity_ref(nominal)?)? {
            DeclaredEntity::Local(key) => ctx.entity(key)?,
            DeclaredEntity::Dependency { declaration, .. } => {
                let expected = option(declaration, "nominal")?.ok_or_else(|| {
                    Error::semantic("symbol_code_source", "missing local expectation")
                })?;
                ctx.entity(ctx.local(Namespace::Nominal, local_reference(expected)?)?)?
            }
        };
        require(token(nominal, "kind")? == "function", "symbol_code_source")?;
        // Metadata/selection retains provider/native issuer obligations. This
        // local typing check neither resolves nor manufactures a target token.
        return Ok(());
    }
    if !is_declaration {
        if let Some(definition) = option(symbol, "definition")? {
            require(
                token(definition, "kind")? != "native",
                "native_symbol_requires_bridge",
            )?;
        }
    }
    if let Some(nominal) = option(symbol, "nominal")? {
        let nominal = match ctx.resolve_declaration(Namespace::Nominal, &entity_ref(nominal)?)? {
            DeclaredEntity::Local(key) => ctx.entity(key)?,
            DeclaredEntity::Dependency { declaration, .. } => {
                let expected = option(declaration, "nominal")?.ok_or_else(|| {
                    Error::semantic("declaration_nominal", "missing local mirror")
                })?;
                ctx.entity(ctx.local(Namespace::Nominal, local_reference(expected)?)?)?
            }
        };
        for flag in sequence(nominal, "flags")? {
            require(
                crate::context::text(flag)? != "native",
                "native_symbol_requires_bridge",
            )?;
        }
    }
    let execution = if is_declaration {
        option(symbol, "execution")?
    } else {
        Some(field(symbol, "execution")?)
    };
    if ["function", "import"].contains(&kind) {
        let execution = execution
            .ok_or_else(|| Error::semantic("symbol_code_signature", "missing expectation"))?;
        let expected = types.type_reference(execution)?;
        if matches!(types.kind(expected)?, TypeKind::Function { .. }) {
            let TypeKind::CodePtr { signature } = types.kind(result)? else {
                return Err(Error::semantic("symbol_code_signature", "result"));
            };
            require(
                types.type_equivalent(types.type_handle(*signature)?, expected, budget)?,
                "symbol_code_signature",
            )?;
            return Ok(());
        }
    }
    require(
        matches!(types.kind(result)?, TypeKind::DataPtr),
        "symbol_data_address",
    )
}
