//! Complete function/SSA/operation/EH phase, consuming actual ABI/metadata proofs.

use std::collections::BTreeMap;

use crate::abi::AbiFacts;
use crate::context::{
    ContextId, DeclaredEntity, Namespace, ObjectContext, bytes, entity_ref, field, unsigned,
};
use crate::error::Error;
use crate::limits::Budget;
use crate::metadata::MetadataFacts;
use crate::wire::RecordValue;

use super::cfg::Cfg;
use super::records::{clone_record, identifier, number, ordered, require, sequence, token};
use super::{EscapeKind, TypeFacts, TypeHandle, TypeKind};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProgramRequirement {
    ExternalCleanupRecipe {
        function: u32,
        action: u32,
        slot: u32,
        declaration: u32,
    },
}

pub(crate) struct FunctionFact {
    pub(crate) signature: TypeHandle,
    pub(crate) abi_signature: Option<u32>,
    pub(crate) escape: EscapeKind,
    pub(crate) no_return: bool,
    record: RecordValue,
}

impl FunctionFact {
    pub(crate) fn record(&self) -> &RecordValue {
        &self.record
    }
}

pub(crate) struct ConstantProgramFact {
    pub(crate) result_type: TypeHandle,
    pub(crate) operation_count: u64,
    pub(crate) ssa_bytes: u64,
    /// Saturated at 100001, beyond the frozen 100000-node staging limit.
    pub(crate) ssa_nodes: u64,
}

/// Every body has passed all static execution checks in the same context.
pub(crate) struct ProgramFacts {
    identity: [u8; 32],
    context: ContextId,
    functions: BTreeMap<u32, FunctionFact>,
    constants: BTreeMap<u32, ConstantProgramFact>,
    requirements: Vec<ProgramRequirement>,
}

impl ProgramFacts {
    pub(crate) fn identity(&self) -> [u8; 32] {
        self.identity
    }
    pub(crate) fn context_id(&self) -> ContextId {
        self.context
    }
    pub(crate) fn assert_context(&self, ctx: &ObjectContext) -> Result<(), Error> {
        require(
            ctx.identity() == self.identity && ctx.context_id() == self.context,
            "execution_context",
        )
    }
    pub(crate) fn function(&self, id: u32) -> Result<&FunctionFact, Error> {
        self.functions
            .get(&id)
            .ok_or_else(|| Error::semantic("function_reference", id.to_string()))
    }
    pub(crate) fn constant_program(&self, id: u32) -> Result<&ConstantProgramFact, Error> {
        self.constants
            .get(&id)
            .ok_or_else(|| Error::semantic("initializer_program", id.to_string()))
    }
    pub(crate) fn checked_function_record(&self, id: u32) -> Result<&RecordValue, Error> {
        Ok(self.function(id)?.record())
    }
    pub(crate) fn requirements(&self) -> &[ProgramRequirement] {
        &self.requirements
    }
}

pub(crate) fn verify_program(
    ctx: &ObjectContext,
    types: &TypeFacts,
    abi: &AbiFacts,
    metadata: &MetadataFacts,
    budget: &mut Budget,
) -> Result<ProgramFacts, Error> {
    types.assert_context(ctx)?;
    abi.assert_context(ctx)?;
    metadata.assert_context(ctx)?;
    let functions = ordered(sequence(ctx.root(3)?, "functions")?, "id", budget)?;
    let exception_root = ctx.root(8)?;
    require(number(exception_root, "payload_revision")? == 1, "revision")?;
    let exceptions = ordered(sequence(exception_root, "functions")?, "function", budget)?;
    require(
        exceptions.keys().all(|id| functions.contains_key(id)),
        "eh_function_reference",
    )?;
    let mut facts = BTreeMap::new();
    let mut constants = BTreeMap::new();
    let mut requirements = Vec::new();
    for (id, function) in functions {
        budget.work(1)?;
        let header = types.function_decl(id)?;
        verify_source_signature(ctx, types, abi, id, budget)?;
        let cfg = check_body(ctx, types, function, budget)?;
        verify_source_sites(ctx, types, abi, &cfg, budget)?;
        super::exceptions::verify(
            ctx,
            types,
            abi,
            &cfg,
            function,
            exceptions.get(&id).copied(),
            &mut requirements,
            budget,
        )?;
        if let Some(constant) =
            constant_program(types, function, exceptions.get(&id).copied(), &cfg, budget)?
        {
            budget.reserve_bytes(std::mem::size_of::<ConstantProgramFact>() + 96)?;
            constants.insert(id, constant);
        }
        let record = clone_record(function, budget)?;
        budget.reserve_bytes(std::mem::size_of::<FunctionFact>() + 96)?;
        facts.insert(
            id,
            FunctionFact {
                signature: header.signature,
                abi_signature: header.abi_signature,
                escape: header.escape,
                no_return: header.no_return,
                record,
            },
        );
    }
    // S-PROD004 is accepted by root/ABI/runtime: absent provider formal IDs and
    // body checks survive as exact typed requirements, never synthetic facts.
    Ok(ProgramFacts {
        identity: ctx.identity(),
        context: ctx.context_id(),
        functions: facts,
        constants,
        requirements,
    })
}

fn check_body<'a>(
    ctx: &ObjectContext,
    types: &TypeFacts,
    function: &'a RecordValue,
    budget: &mut Budget,
) -> Result<Cfg<'a>, Error> {
    types.assert_context(ctx)?;
    let cfg = Cfg::build(function, types, budget)?;
    for block in &cfg.blocks {
        for operation in sequence(block, "ops")? {
            budget.work(1)?;
            let args = operand_types(operation, &cfg, budget)?;
            let outputs = result_types(sequence(operation, "results")?, types, budget)?;
            super::operations::check(
                ctx, types, &cfg, function, operation, &args, &outputs, budget,
            )?;
        }
        verify_terminator(ctx, types, &cfg, function, field(block, "term")?, budget)?;
    }
    Ok(cfg)
}

/// Real local body predicates, without inventing ABI/metadata success proofs.
/// Returns no admission fact and deliberately excludes source/EH joins.
#[cfg(test)]
pub(crate) fn check_function_core(
    ctx: &ObjectContext,
    types: &TypeFacts,
    id: u32,
    budget: &mut Budget,
) -> Result<(), Error> {
    let function = ctx.entity(ctx.local(Namespace::Function, id)?)?;
    check_body(ctx, types, function, budget).map(|_| ())
}

/// Test the actual source/body/EH predicates with a genuine ABI proof.
/// No metadata or program proof is constructed, and no admission is implied.
#[cfg(test)]
pub(crate) fn check_function_source_and_eh(
    ctx: &ObjectContext,
    types: &TypeFacts,
    abi: &AbiFacts,
    id: u32,
    budget: &mut Budget,
) -> Result<(), Error> {
    types.assert_context(ctx)?;
    abi.assert_context(ctx)?;
    let function = ctx.entity(ctx.local(Namespace::Function, id)?)?;
    verify_source_signature(ctx, types, abi, id, budget)?;
    let cfg = check_body(ctx, types, function, budget)?;
    verify_source_sites(ctx, types, abi, &cfg, budget)?;
    let exceptions = ordered(sequence(ctx.root(8)?, "functions")?, "function", budget)?;
    let mut requirements = Vec::new();
    super::exceptions::verify(
        ctx,
        types,
        abi,
        &cfg,
        function,
        exceptions.get(&id).copied(),
        &mut requirements,
        budget,
    )
}

fn operand_types(
    node: &RecordValue,
    cfg: &Cfg<'_>,
    budget: &mut Budget,
) -> Result<Vec<TypeHandle>, Error> {
    let operands = sequence(node, "operands")?;
    budget.reserve_bytes(
        operands
            .len()
            .checked_mul(std::mem::size_of::<TypeHandle>())
            .ok_or_else(|| Error::resource("reference_resource", "operand types"))?,
    )?;
    operands
        .iter()
        .map(|value| {
            budget.work(1)?;
            let id = u32::try_from(unsigned(value)?)
                .map_err(|_| Error::semantic("ssa_reference", "operand ID"))?;
            cfg.value_type(id)
        })
        .collect()
}

fn result_types(
    results: &[RecordValue],
    types: &TypeFacts,
    budget: &mut Budget,
) -> Result<Vec<TypeHandle>, Error> {
    budget.reserve_bytes(
        results
            .len()
            .checked_mul(std::mem::size_of::<TypeHandle>())
            .ok_or_else(|| Error::resource("reference_resource", "result types"))?,
    )?;
    results
        .iter()
        .map(|result| {
            budget.work(1)?;
            types.type_reference(field(result, "type")?)
        })
        .collect()
}

fn verify_source_signature(
    ctx: &ObjectContext,
    types: &TypeFacts,
    abi: &AbiFacts,
    id: u32,
    budget: &mut Budget,
) -> Result<(), Error> {
    let header = types.function_decl(id)?;
    let Some(source) = header.abi_signature else {
        return Ok(());
    };
    let fact = abi.signature(ctx.local(Namespace::CallSignature, source)?)?;
    let descriptor = fact.record();
    require(
        types.type_equivalent(header.signature, fact.execution_signature(), budget)?,
        "function_plan_execution",
    )?;
    // DRAFT entry association retains genuine hidden-role ABI checks below.
    let TypeKind::Function {
        params,
        results,
        param_noundef,
        result_noundef,
    } = types.kind(header.signature)?
    else {
        return Err(Error::semantic("function_signature", "function type"));
    };
    let lowered_params = sequence(descriptor, "lowered_params")?;
    let lowered_results = sequence(descriptor, "lowered_results")?;
    require(
        lowered_params.len() == params.len() && lowered_results.len() == results.len(),
        "abi_lowered_arity",
    )?;
    for ((actual, param), noundef) in params.iter().zip(lowered_params).zip(param_noundef) {
        budget.work(1)?;
        let nominal = abi.nominal(super::exceptions::nominal_key(
            ctx,
            field(param, "value_type")?,
        )?)?;
        let expected = nominal
            .execution_type()
            .ok_or_else(|| Error::semantic("abi_parameter_nominal", "no execution view"))?;
        require(
            types.type_equivalent(types.type_handle(*actual)?, expected, budget)?
                && super::records::flag(param, "noundef")? == *noundef,
            "abi_lowered_parameter",
        )?;
    }
    for ((actual, result), noundef) in results.iter().zip(lowered_results).zip(result_noundef) {
        budget.work(1)?;
        let nominal = abi.nominal(super::exceptions::nominal_key(ctx, result)?)?;
        let expected = nominal
            .execution_type()
            .ok_or_else(|| Error::semantic("abi_result_nominal", "no execution view"))?;
        require(
            types.type_equivalent(types.type_handle(*actual)?, expected, budget)?
                && super::records::flag(descriptor, "return_noundef")? == *noundef,
            "abi_lowered_result",
        )?;
    }
    Ok(())
}

fn verify_ordinary_plan(
    ctx: &ObjectContext,
    types: &TypeFacts,
    abi: &AbiFacts,
    reference: &RecordValue,
    execution: TypeHandle,
    budget: &mut Budget,
) -> Result<(), Error> {
    budget.work(1)?;
    let key = match ctx.resolve_declaration(Namespace::CallSignature, &entity_ref(reference)?)? {
        DeclaredEntity::Local(key) => key,
        DeclaredEntity::Dependency { declaration, .. } => {
            let expected =
                super::records::option(declaration, "abi_signature")?.ok_or_else(|| {
                    Error::semantic("source_plan_reference", "missing consumer expectation")
                })?;
            ctx.local(
                Namespace::CallSignature,
                super::records::local_reference(expected)?,
            )?
        }
    };
    let plan = abi.signature(key)?;
    require(
        super::records::option(plan.record(), "this_type")?.is_none()
            && !super::records::flag(plan.record(), "vtt")?,
        "source_plan_ordinary",
    )?;
    require(
        types.type_equivalent(plan.execution_signature(), execution, budget)?,
        "source_plan_execution",
    )
}

fn verify_source_sites(
    ctx: &ObjectContext,
    types: &TypeFacts,
    abi: &AbiFacts,
    cfg: &Cfg<'_>,
    budget: &mut Budget,
) -> Result<(), Error> {
    abi.assert_context(ctx)?;
    for block in &cfg.blocks {
        for node in sequence(block, "ops")? {
            budget.work(1)?;
            match token(node, "op")? {
                "code_bind" => {
                    let output = sequence(node, "results")?
                        .first()
                        .ok_or_else(|| Error::semantic("result_arity", "code_bind"))?;
                    let output = types.type_reference(field(output, "type")?)?;
                    let signature = match super::pure::scalar(types, output)? {
                        TypeKind::CodePtr { signature } => types.type_handle(*signature)?,
                        _ => return Err(Error::semantic("code_bind_type", "output")),
                    };
                    verify_ordinary_plan(ctx, types, abi, field(node, "plan")?, signature, budget)?;
                }
                "call" => {
                    if let Some(plan) = super::records::option(node, "source_plan")? {
                        let execution =
                            types.type_reference(field(field(node, "target")?, "signature")?)?;
                        verify_ordinary_plan(ctx, types, abi, plan, execution, budget)?;
                    }
                }
                _ => {}
            }
        }
        let term = field(block, "term")?;
        if ["invoke", "tailcall"].contains(&token(term, "op")?) {
            if let Some(plan) = super::records::option(term, "source_plan")? {
                let execution =
                    types.type_reference(field(field(term, "target")?, "signature")?)?;
                verify_ordinary_plan(ctx, types, abi, plan, execution, budget)?;
            }
        }
    }
    Ok(())
}

fn verify_terminator(
    ctx: &ObjectContext,
    types: &TypeFacts,
    cfg: &Cfg<'_>,
    function: &RecordValue,
    term: &RecordValue,
    budget: &mut Budget,
) -> Result<(), Error> {
    budget.work(1)?;
    let header = types.function_decl(identifier(function, "id")?)?;
    let TypeKind::Function {
        results: expected,
        result_noundef,
        ..
    } = types.kind(header.signature)?
    else {
        return Err(Error::semantic("function_signature", "signature"));
    };
    match token(term, "op")? {
        "return" => {
            let values = sequence(term, "values")?;
            require(
                !header.no_return && values.len() == expected.len(),
                "return_signature",
            )?;
            for (value, expected) in values.iter().zip(expected) {
                budget.work(1)?;
                let value = u32::try_from(unsigned(value)?)
                    .map_err(|_| Error::semantic("ssa_reference", "return"))?;
                require(
                    types.type_equivalent(
                        cfg.value_type(value)?,
                        types.type_handle(*expected)?,
                        budget,
                    )?,
                    "return_signature",
                )?;
            }
        }
        "cbranch" => require(
            matches!(
                types.kind(cfg.value_type(identifier(term, "condition")?)?)?,
                TypeKind::Int(1)
            ),
            "branch_boolean",
        )?,
        "switch" => {
            let ty = cfg.value_type(identifier(term, "index")?)?;
            let TypeKind::Int(bits) = types.kind(ty)? else {
                return Err(Error::semantic("switch_type", "integer"));
            };
            let mut previous: Option<&[u8]> = None;
            for case in sequence(term, "cases")? {
                budget.work(1)?;
                let value = bytes(field(case, "value")?)?;
                require(
                    value.len() as u64 == u64::from(*bits).div_ceil(8),
                    "constant",
                )?;
                if bits % 8 != 0 {
                    require(
                        value.last().is_some_and(|last| last >> (bits % 8) == 0),
                        "constant",
                    )?;
                }
                budget.work(value.len() as u64)?;
                require(
                    previous.is_none_or(|old| old.iter().rev().cmp(value.iter().rev()).is_lt()),
                    "switch_cases",
                )?;
                previous = Some(value);
            }
        }
        "indirect_branch" => {
            require(
                matches!(
                    types.kind(cfg.value_type(identifier(term, "address")?)?)?,
                    TypeKind::CodePtr { .. }
                ),
                "indirect_branch_targets",
            )?;
            let targets = sequence(term, "targets")?;
            require(!targets.is_empty(), "indirect_branch_targets")?;
            let mut previous = None;
            for target in targets {
                budget.work(1)?;
                let target = u32::try_from(unsigned(target)?)
                    .map_err(|_| Error::semantic("cfg_target", "ID"))?;
                require(
                    previous.is_none_or(|old| old < target)
                        && cfg
                            .indices
                            .get(&target)
                            .is_some_and(|index| *index != cfg.entry),
                    "indirect_branch_targets",
                )?;
                previous = Some(target);
            }
        }
        "invoke" | "tailcall" => {
            let args = operand_types(term, cfg, budget)?;
            let name = token(term, "op")?;
            let outputs = if name == "invoke" {
                result_types(sequence(field(term, "normal")?, "results")?, types, budget)?
            } else {
                budget.reserve_bytes(
                    expected
                        .len()
                        .checked_mul(std::mem::size_of::<TypeHandle>())
                        .ok_or_else(|| Error::resource("reference_resource", "tail results"))?,
                )?;
                expected
                    .iter()
                    .map(|id| types.type_handle(*id))
                    .collect::<Result<Vec<_>, _>>()?
            };
            let (callee, _) = super::calls::check_call(
                ctx,
                types,
                cfg,
                field(term, "target")?,
                &args,
                &outputs,
                budget,
            )?;
            if name == "tailcall" {
                let TypeKind::Function {
                    result_noundef: callee_noundef,
                    ..
                } = types.kind(callee)?
                else {
                    return Err(Error::semantic("call_signature", "callee"));
                };
                require(
                    !header.no_return && callee_noundef == result_noundef,
                    "tail_result_contract",
                )?;
            }
        }
        "throw" | "rethrow" | "resume" | "cleanup_return" | "terminate" => {
            let value = match field(term, "exception")? {
                RecordValue::Unsigned(value) => Some(*value),
                RecordValue::Option(value) => {
                    value.as_ref().map(|value| unsigned(value)).transpose()?
                }
                _ => return Err(Error::semantic("exception_value", "exception operand")),
            };
            require(
                token(term, "op")? != "cleanup_return" || value.is_some(),
                "cleanup_requires_explicit_exception",
            )?;
            if let Some(value) = value {
                let value =
                    u32::try_from(value).map_err(|_| Error::semantic("exception_value", "ID"))?;
                require(
                    matches!(types.kind(cfg.value_type(value)?)?, TypeKind::Exception),
                    "exception_value",
                )?;
            }
        }
        "jump" | "unreachable" | "trap" => {}
        _ => return Err(Error::semantic("terminator", "unknown variant")),
    }
    Ok(())
}

fn constant_program(
    types: &TypeFacts,
    function: &RecordValue,
    exception: Option<&RecordValue>,
    cfg: &Cfg<'_>,
    budget: &mut Budget,
) -> Result<Option<ConstantProgramFact>, Error> {
    let header = types.function_decl(identifier(function, "id")?)?;
    let TypeKind::Function {
        params,
        results,
        result_noundef,
        ..
    } = types.kind(header.signature)?
    else {
        return Err(Error::semantic("function_signature", "signature"));
    };
    if header.abi_signature.is_some()
        || !params.is_empty()
        || !header.params.is_empty()
        || results.len() != 1
        || result_noundef != &[false]
        || header.escape != EscapeKind::Propagate
        || header.no_return
        || cfg.blocks.len() != 1
    {
        return Ok(None);
    }
    let block = cfg.blocks[0];
    let term = field(block, "term")?;
    if !sequence(block, "phis")?.is_empty()
        || token(term, "op")? != "return"
        || sequence(term, "values")?.len() != 1
    {
        return Ok(None);
    }
    if let Some(exception) = exception {
        if !sequence(exception, "regions")?.is_empty()
            || !sequence(exception, "actions")?.is_empty()
        {
            return Ok(None);
        }
    }
    let operations = sequence(block, "ops")?;
    const ALLOWED: &[&str] = &[
        "constant",
        "copy",
        "freeze",
        "i_add",
        "i_sub",
        "i_xor",
        "i_mul",
        "icmp",
        "select",
        "extract",
        "insert",
        "extract_element",
        "insert_element",
        "shuffle",
        "trunc",
        "zext",
        "sext",
        "bitcast",
        "ptrtoint",
        "ptrtoaddr",
        "inttoptr",
        "ptr_offset",
        "address_of",
    ];
    for operation in operations {
        budget.work(1)?;
        if !ALLOWED.contains(&token(operation, "op")?) {
            return Ok(None);
        }
    }
    let result_type = types.type_handle(results[0])?;
    if types.present_opaque(result_type)?.any() || types.present_fenv(result_type)? {
        return Ok(None);
    }
    let mut ssa_bytes = 0u64;
    let mut ssa_nodes = 0u64;
    for definition in cfg.definitions.values() {
        budget.work(1)?;
        if types.present_opaque(definition.ty)?.any() || types.present_fenv(definition.ty)? {
            return Ok(None);
        }
        ssa_bytes = ssa_bytes
            .checked_add(types.value_bits(definition.ty)?.div_ceil(8))
            .ok_or_else(|| Error::resource("reference_resource", "constant SSA working bytes"))?;
        ssa_nodes = ssa_nodes
            .saturating_add(types.value_nodes(definition.ty)?)
            .min(100001);
    }
    Ok(Some(ConstantProgramFact {
        result_type,
        operation_count: operations.len() as u64,
        ssa_bytes,
        ssa_nodes,
    }))
}
