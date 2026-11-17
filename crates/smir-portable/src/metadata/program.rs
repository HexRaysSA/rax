//! Header constraints and final actual checked-body joins. No initializer runs.

use super::{
    imports::nominal_expectation,
    records::*,
    relocations::ConstantInitializerFact,
    symbols::{Definition, SymbolFacts, optional_ref, self_id},
};
use crate::context::{
    DeclaredEntity, EntityRef, Namespace, ObjectContext, boolean, entity_ref, field, list, optional,
};
use crate::{
    Error,
    abi::AbiFacts,
    execution::{EscapeKind, ProgramFacts, TypeFacts, TypeHandle},
    limits::Budget,
    wire::RecordValue,
};

fn function_signature(
    ctx: &ObjectContext,
    types: &TypeFacts,
    reference: EntityRef,
) -> Result<TypeHandle, Error> {
    match ctx.resolve_declaration(Namespace::Function, &reference)? {
        DeclaredEntity::Local(key) => Ok(types.function_decl(key.id())?.signature),
        DeclaredEntity::Dependency { declaration, .. } => {
            let expected = optional(field(declaration, "execution")?)?
                .ok_or_else(|| Error::semantic("RT_TLS_HOOK_SIGNATURE", String::new()))?;
            types.type_reference(expected)
        }
    }
}

fn source_scalar(
    ctx: &ObjectContext,
    abi: &AbiFacts,
    value: &RecordValue,
    name: &str,
    bits: u64,
) -> Result<bool, Error> {
    let record = abi.nominal(nominal_expectation(ctx, value)?)?.record();
    Ok(token(record, "kind")? == "scalar"
        && token(field(record, "identity")?, "entity")? == name
        && number(record, "bits")? == bits
        && flag(record, "signed")?)
}

fn startup(
    ctx: &ObjectContext,
    types: &TypeFacts,
    abi: &AbiFacts,
    id: u32,
    budget: &mut Budget,
) -> Result<(), Error> {
    budget.work(48)?;
    let body = types.function_decl(id)?;
    let signature = types.type_record(body.signature)?;
    let params = list(field(signature, "params")?)?;
    let results = list(field(signature, "results")?)?;
    let pp = list(field(signature, "param_noundef")?)?;
    let rp = list(field(signature, "result_noundef")?)?;
    require(
        token(signature, "kind")? == "function"
            && token(signature, "cc")? == "portable"
            && !flag(signature, "variadic")?
            && params.len() == 3
            && results.len() == 1
            && pp.len() == 3
            && rp.len() == 1
            && pp.iter().all(|v| boolean(v) == Ok(true))
            && boolean(&rp[0])?,
        "RT_STARTUP_SIGNATURE",
    )?;
    for reference in [&params[0], &results[0]] {
        let ty = types.type_record(types.type_reference(reference)?)?;
        require(
            token(ty, "kind")? == "int" && number(ty, "bits")? == 32,
            "RT_STARTUP_TYPES",
        )?;
    }
    for reference in [&params[1], &params[2]] {
        let ty = types.type_record(types.type_reference(reference)?)?;
        require(
            token(ty, "kind")? == "data_ptr" && token(ty, "space")? == "guest_data",
            "RT_STARTUP_TYPES",
        )?;
    }
    require(
        body.escape == EscapeKind::Terminate && !body.no_return,
        "RT_STARTUP_ESCAPE",
    )?;
    let plan = body
        .abi_signature
        .ok_or_else(|| Error::semantic("RT_STARTUP_ABI", String::new()))?;
    let plan = abi.signature(ctx.local(Namespace::CallSignature, plan)?)?;
    let source = plan.record();
    let params = list(field(source, "params")?)?;
    let result = optional(field(source, "result")?)?;
    require(
        params.len() == 3
            && result.is_some()
            && optional(field(source, "this_type")?)?.is_none()
            && !flag(source, "vtt")?
            && !flag(source, "variadic")?
            && optional(field(source, "varargs")?)?.is_none(),
        "RT_STARTUP_ABI",
    )?;
    let nominal = abi.nominal(plan.function_type())?.record();
    require(
        token(nominal, "kind")? == "function"
            && list(field(nominal, "flags")?)?
                .iter()
                .any(|v| crate::context::text(v).is_ok_and(|v| v == "c_linkage")),
        "RT_STARTUP_C_LINKAGE",
    )?;
    require(
        source_scalar(ctx, abi, &params[0], "int", 32)?
            && source_scalar(
                ctx,
                abi,
                result.ok_or_else(|| Error::semantic("RT_STARTUP_ABI", String::new()))?,
                "int",
                32,
            )?,
        "RT_STARTUP_C_TYPES",
    )?;
    for reference in &params[1..] {
        let mut reference = reference;
        for _ in 0..2 {
            let pointer = abi.nominal(nominal_expectation(ctx, reference)?)?.record();
            require(
                token(pointer, "kind")? == "pointer"
                    && list(field(pointer, "elements")?)?.len() == 1
                    && list(field(pointer, "qualifiers")?)?.is_empty(),
                "RT_STARTUP_C_POINTERS",
            )?;
            reference = &list(field(pointer, "elements")?)?[0];
        }
        require(
            source_scalar(ctx, abi, reference, "char", 8)?,
            "RT_STARTUP_C_CHAR",
        )?;
    }
    Ok(())
}

pub(crate) fn verify_headers(
    ctx: &ObjectContext,
    types: &TypeFacts,
    abi: &AbiFacts,
    budget: &mut Budget,
) -> Result<(), Error> {
    types.assert_context(ctx)?;
    abi.assert_context(ctx)?;
    let root = ctx.root(7)?;
    require(
        number(root, "payload_revision")? == 1,
        "RT_PAYLOAD_REVISION",
    )?;
    for segment in list(field(root, "segments")?)? {
        budget.work(8)?;
        let initialization = token(segment, "initialization")?;
        require(
            ["static", "namespace_dynamic", "block_dynamic"].contains(&initialization),
            "RT_TLS_INITIALIZATION",
        )?;
        require(
            initialization != "static" || list(field(segment, "initializers")?)?.is_empty(),
            "RT_STATIC_TLS_INITIALIZER",
        )?;
        for side in ["initializers", "destructors"] {
            for reference in list(field(segment, side)?)? {
                budget.work(8)?;
                let reference = entity_ref(reference)?;
                let signature = types.type_record(function_signature(ctx, types, reference)?)?;
                require(
                    token(signature, "kind")? == "function"
                        && token(signature, "cc")? == "portable"
                        && !flag(signature, "variadic")?
                        && list(field(signature, "params")?)?.is_empty()
                        && list(field(signature, "results")?)?.is_empty(),
                    "RT_TLS_HOOK_SIGNATURE",
                )?;
                if side == "destructors" || initialization == "namespace_dynamic" {
                    if let DeclaredEntity::Local(key) =
                        ctx.resolve_declaration(Namespace::Function, &reference)?
                    {
                        require(
                            matches!(
                                types.function_decl(key.id())?.escape,
                                EscapeKind::Terminate | EscapeKind::Nothrow
                            ),
                            "RT_TLS_HOOK_ESCAPE",
                        )?;
                    }
                    // For a DEP hook, exact provider escape semantics are retained, never fabricated.
                }
            }
        }
    }
    if let Some(reference) = optional_ref(field(ctx.root(2)?, "manifest")?, "entry")? {
        startup(ctx, types, abi, self_id(reference, "RT_ENTRY")?, budget)?;
    }
    Ok(())
}

fn checked_function(
    ctx: &ObjectContext,
    program: &ProgramFacts,
    reference: EntityRef,
) -> Result<(), Error> {
    if let DeclaredEntity::Local(key) = ctx.resolve_declaration(Namespace::Function, &reference)? {
        program.function(key.id())?;
    }
    Ok(())
}

pub(crate) fn verify_joins(
    ctx: &ObjectContext,
    types: &TypeFacts,
    abi: &AbiFacts,
    symbols: &SymbolFacts,
    constants: &[ConstantInitializerFact],
    program: &ProgramFacts,
    budget: &mut Budget,
) -> Result<(), Error> {
    types.assert_context(ctx)?;
    abi.assert_context(ctx)?;
    program.assert_context(ctx)?;
    for symbol in symbols.all().values() {
        budget.work(1)?;
        if let Some(Definition::Function(id)) = symbol.definition {
            let function = program.function(id)?;
            let declared = types.function_decl(id)?;
            require(
                types.type_equivalent(function.signature, declared.signature, budget)?
                    && function.abi_signature == declared.abi_signature
                    && function.escape == declared.escape
                    && function.no_return == declared.no_return,
                "RT_FUNCTION_PROGRAM_JOIN",
            )?;
        }
    }
    for record in constants {
        budget.work(8)?;
        let constant = program.constant_program(record.function)?;
        let layout = types.layout(record.layout)?;
        require(
            types.type_equivalent(constant.result_type, layout.execution_type, budget)?,
            "RT_INITIALIZER_SIGNATURE",
        )?;
        let function = program.checked_function_record(record.function)?;
        let blocks = list(field(function, "blocks")?)?;
        require(
            blocks.len() == 1 && list(field(&blocks[0], "phis")?)?.is_empty(),
            "RT_INITIALIZER_CONTROL",
        )?;
        let term = field(&blocks[0], "term")?;
        require(
            token(term, "op")? == "return" && list(field(term, "values")?)?.len() == 1,
            "RT_INITIALIZER_CONTROL",
        )?;
    }
    for side in ["initializers", "finalizers"] {
        for hook in list(field(ctx.root(2)?, side)?)? {
            budget.work(1)?;
            checked_function(ctx, program, entity_ref(field(hook, "function")?)?)?;
        }
    }
    for segment in list(field(ctx.root(7)?, "segments")?)? {
        for side in ["initializers", "destructors"] {
            for hook in list(field(segment, side)?)? {
                budget.work(1)?;
                checked_function(ctx, program, entity_ref(hook)?)?;
            }
        }
    }
    if let Some(entry) = optional_ref(field(ctx.root(2)?, "manifest")?, "entry")? {
        checked_function(ctx, program, entry)?;
    }
    Ok(())
}
