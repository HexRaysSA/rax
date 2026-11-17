//! Frozen catalogs and complete static helper-option policies.

use super::records::{alignment, flag, number, require, token};
use super::requirements::RequirementFacts;
use crate::abi::AbiFacts;
use crate::context::{DeclaredEntity, EntityKey, Namespace, ObjectContext, boolean, entity_ref};
use crate::context::{bytes, field, list, optional, text};
use crate::execution::{TypeFacts, TypeHandle};
use crate::{Error, limits::Budget, wire::RecordValue};
use serde_json::Value as Json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const HELPERS: &str =
    include_str!("../../../../docs/specifications/smir/portable/schema/runtime/helpers-v1.json");
const SERVICES: &str =
    include_str!("../../../../docs/specifications/smir/portable/schema/runtime/services-v1.json");

pub(crate) struct Catalogs {
    helpers: BTreeMap<String, Json>,
    services: BTreeMap<String, Json>,
    helper_digest: [u8; 32],
    service_digest: [u8; 32],
}

fn catalog(
    source: &str,
    prefix: &[u8],
    count: usize,
    budget: &mut Budget,
) -> Result<(BTreeMap<String, Json>, [u8; 32]), Error> {
    budget.work(source.len() as u64)?;
    budget.reserve_bytes(
        source
            .len()
            .checked_mul(16)
            .ok_or_else(|| Error::resource("RT_CATALOG_RESOURCE", String::new()))?,
    )?;
    let value: Json = serde_json::from_str(source)
        .map_err(|_| Error::semantic("RT_CATALOG_CONFIGURATION", String::new()))?;
    let canonical = serde_json::to_vec(&value)
        .map_err(|_| Error::semantic("RT_CATALOG_CONFIGURATION", String::new()))?;
    // Frozen catalogs contain ASCII only; this matches Python's ensure_ascii oracle.
    require(canonical.is_ascii(), "RT_CATALOG_CONFIGURATION")?;
    let mut digest = Sha256::new();
    digest.update(prefix);
    digest.update(&canonical);
    let digest = digest.finalize().into();
    let records = value
        .get("records")
        .and_then(Json::as_array)
        .ok_or_else(|| Error::semantic("RT_CATALOG_CONFIGURATION", String::new()))?;
    require(records.len() == count, "RT_CATALOG_CONFIGURATION")?;
    budget.edges(count)?;
    let mut result = BTreeMap::new();
    for record in records {
        budget.work(1)?;
        let name = json_text(record, "name")?;
        require(
            result.insert(name.to_owned(), record.clone()).is_none(),
            "RT_CATALOG_CONFIGURATION",
        )?;
    }
    Ok((result, digest))
}

impl Catalogs {
    pub(crate) fn load(budget: &mut Budget) -> Result<Self, Error> {
        let (helpers, helper_digest) = catalog(HELPERS, b"SMIR-HELPERS-V1\0", 177, budget)?;
        let (services, service_digest) = catalog(SERVICES, b"SMIR-SERVICES-V1\0", 59, budget)?;
        Ok(Self {
            helpers,
            services,
            helper_digest,
            service_digest,
        })
    }

    pub(crate) fn helper(&self, name: &str) -> Result<&Json, Error> {
        self.helpers
            .get(name)
            .ok_or_else(|| Error::semantic("RT_HELPER_UNKNOWN", name.to_owned()))
    }
    pub(crate) fn service(&self, name: &str) -> Result<&Json, Error> {
        self.services
            .get(name)
            .ok_or_else(|| Error::semantic("RT_SERVICE_UNKNOWN", name.to_owned()))
    }
    pub(crate) fn helper_digest(&self) -> [u8; 32] {
        self.helper_digest
    }
    pub(crate) fn service_digest(&self) -> [u8; 32] {
        self.service_digest
    }
}

pub(crate) fn json_text<'a>(value: &'a Json, name: &str) -> Result<&'a str, Error> {
    value
        .get(name)
        .and_then(Json::as_str)
        .ok_or_else(|| Error::semantic("RT_CATALOG_CONFIGURATION", name.to_owned()))
}

pub(crate) fn json_list<'a>(value: &'a Json, name: &str) -> Result<&'a [Json], Error> {
    value
        .get(name)
        .and_then(Json::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| Error::semantic("RT_CATALOG_CONFIGURATION", name.to_owned()))
}

pub(crate) fn verify_options(
    record: &RecordValue,
    spec: &Json,
    comparison_mask: Option<&[u8]>,
    budget: &mut Budget,
) -> Result<(), Error> {
    verify_options_policy(record, spec, budget)?;
    let options = field(record, "options")?;
    if token(options, "comparison")? == "value_mask" {
        let mask = bytes(field(options, "mask")?)?;
        let actual =
            comparison_mask.ok_or_else(|| Error::semantic("RT_HELPER_ABI_MASK", String::new()))?;
        require(mask.is_empty() || mask == actual, "RT_HELPER_ABI_MASK")?;
    }
    Ok(())
}

pub(crate) fn verify_options_with_abi(
    record: &RecordValue,
    spec: &Json,
    binding: Option<&crate::abi::StorageBindingFact>,
    budget: &mut Budget,
) -> Result<(), Error> {
    verify_options_policy(record, spec, budget)?;
    let options = field(record, "options")?;
    if token(options, "comparison")? == "value_mask" {
        let binding =
            binding.ok_or_else(|| Error::semantic("RT_HELPER_ABI_MASK", String::new()))?;
        require(binding.has_comparison_mask(), "RT_HELPER_ABI_MASK")?;
        let mask = bytes(field(options, "mask")?)?;
        if !mask.is_empty() {
            require(
                binding.comparison_mask_matches(mask, budget)?,
                "RT_HELPER_ABI_MASK",
            )?;
        }
    }
    Ok(())
}

fn verify_options_policy(
    record: &RecordValue,
    spec: &Json,
    budget: &mut Budget,
) -> Result<(), Error> {
    budget.work(48)?;
    let options = field(record, "options")?;
    let align = number(options, "alignment")?;
    let scope = token(options, "scope")?;
    let order = token(options, "order")?;
    let failure = token(options, "failure_order")?;
    let weak = flag(options, "weak")?;
    let comparison = token(options, "comparison")?;
    let mask = bytes(field(options, "mask")?)?;
    let rounding = token(options, "rounding")?;
    let exceptions = token(options, "exceptions")?;
    let predicate = token(options, "predicate")?;
    let flags = list(field(options, "flags")?)?;
    budget.work(flags.len() as u64)?;
    require(alignment(align), "RT_HELPER_ALIGNMENT")?;
    require(
        ["process", "system", "singlethread"].contains(&scope),
        "RT_HELPER_SCOPE",
    )?;
    let orders = [
        "runtime", "none", "relaxed", "consume", "acquire", "release", "acq_rel", "seq_cst",
    ];
    require(
        orders.contains(&order) && orders.contains(&failure),
        "RT_HELPER_ORDER",
    )?;
    require(
        ["none", "full_storage", "value_mask", "llvm_precision"].contains(&comparison),
        "RT_HELPER_COMPARISON",
    )?;
    require(
        [
            "none",
            "dynamic",
            "nearest_even",
            "nearest_away",
            "toward_zero",
            "upward",
            "downward",
        ]
        .contains(&rounding),
        "RT_HELPER_ROUNDING",
    )?;
    require(
        ["none", "ignore", "maytrap", "strict"].contains(&exceptions),
        "RT_HELPER_EXCEPTIONS",
    )?;
    require(
        [
            "none", "false", "oeq", "ogt", "oge", "olt", "ole", "one", "ord", "ueq", "ugt", "uge",
            "ult", "ule", "une", "uno", "true",
        ]
        .contains(&predicate),
        "RT_HELPER_PREDICATE",
    )?;
    optional(field(options, "target")?)?;
    // Three closed flags: constant-size duplicate checking needs no allocated set.
    let mut seen = 0_u8;
    for item in flags {
        let bit = match text(item)? {
            "volatile" => 1,
            "elementwise" => 2,
            "nontemporal" => 4,
            _ => return Err(Error::semantic("RT_HELPER_FLAGS", String::new())),
        };
        require(seen & bit == 0, "RT_HELPER_FLAGS")?;
        seen |= bit;
    }
    let policy = json_text(spec, "policy")?;
    let name = json_text(spec, "name")?;
    let atomic = policy == "atomic" || policy == "atomic_flag";
    if !atomic {
        require(scope == "process", "RT_HELPER_UNUSED_SCOPE")?;
    }
    let memory = ["guarded_value", "bulk", "atomic"].contains(&policy)
        && !["atomic_fence", "atomic_is_lock_free"].contains(&name);
    if !memory {
        require(
            align == 1 && flags.is_empty(),
            "RT_HELPER_UNUSED_MEMORY_OPTIONS",
        )?;
    } else {
        require(
            seen & 2 == 0 || policy == "bulk",
            "RT_HELPER_ELEMENTWISE_POLICY",
        )?;
    }
    if policy == "atomic_flag" || ["atomic_fence", "atomic_is_lock_free"].contains(&name) {
        require(
            comparison == "none" && mask.is_empty(),
            "RT_HELPER_UNUSED_COMPARISON",
        )?;
    }
    if policy == "atomic" && memory {
        let contract = token(record, "contract")?;
        let expected = if ["full_storage", "value_mask", "llvm_precision"].contains(&contract) {
            contract
        } else {
            "none"
        };
        require(comparison == expected, "RT_HELPER_COMPARISON_CONTRACT")?;
    }
    if name == "atomic_is_lock_free" {
        require(
            order == "none" && scope == "process",
            "RT_HELPER_UNUSED_ORDER",
        )?;
    }
    if !atomic {
        require(
            order == "none" && failure == "none" && !weak,
            "RT_HELPER_UNUSED_ORDER",
        )?;
    } else {
        require(
            order != "none" || name == "atomic_is_lock_free",
            "RT_HELPER_ORDER",
        )?;
        if name != "atomic_cmpxchg" {
            require(failure == "none" && !weak, "RT_HELPER_UNUSED_FAILURE")?;
        } else {
            require(
                ["runtime", "relaxed", "consume", "acquire", "seq_cst"].contains(&failure),
                "RT_HELPER_FAILURE_ORDER",
            )?;
        }
        require(
            order != "seq_cst" || seen & 2 == 0,
            "RT_HELPER_ELEMENTWISE_SC",
        )?;
    }
    if !["fp", "libm", "atomic"].contains(&policy) {
        require(
            rounding == "none" && exceptions == "none" && predicate == "none",
            "RT_HELPER_UNUSED_FP",
        )?;
    }
    let type_parameters = json_list(spec, "type_parameters")?;
    let float_atomic = policy == "atomic"
        && type_parameters.len() == 1
        && type_parameters[0].as_str() == Some("float");
    if policy == "fp" || policy == "libm" || float_atomic {
        require(
            rounding != "none" && exceptions != "none",
            "RT_HELPER_FP_CONTEXT",
        )?;
        require(
            if name == "fp_compare" {
                predicate != "none"
            } else {
                predicate == "none"
            },
            "RT_HELPER_PREDICATE",
        )?;
        if ["fp_lround", "fp_llround"].contains(&name) {
            require(rounding == "nearest_away", "RT_HELPER_ROUND_FIXED")?;
        }
    } else if policy == "atomic" {
        require(
            rounding == "none" && exceptions == "none" && predicate == "none",
            "RT_HELPER_UNUSED_FP",
        )?;
    }
    if comparison != "value_mask" && !mask.is_empty() {
        require(comparison == "llvm_precision", "RT_HELPER_UNUSED_MASK")?;
    }
    if !atomic {
        require(
            comparison == "none" && mask.is_empty(),
            "RT_HELPER_UNUSED_COMPARISON",
        )?;
    }
    Ok(())
}

pub(crate) fn nominal_expectation(
    ctx: &ObjectContext,
    reference: &RecordValue,
) -> Result<EntityKey, Error> {
    let reference = entity_ref(reference)?;
    match ctx.resolve_declaration(Namespace::Nominal, &reference)? {
        DeclaredEntity::Local(key) => Ok(key),
        DeclaredEntity::Dependency { declaration, .. } => {
            let mirror = optional(field(declaration, "nominal")?)?
                .ok_or_else(|| Error::semantic("RT_DECLARATION_NOMINAL", String::new()))?;
            let mirror = entity_ref(mirror)?;
            let id = super::symbols::self_id(mirror, "RT_DECLARATION_SELF")?;
            ctx.local(Namespace::Nominal, id)
        }
    }
}

fn matches_template(
    template: &str,
    actual: TypeHandle,
    bindings: &[TypeHandle],
    types: &TypeFacts,
    budget: &mut Budget,
) -> Result<bool, Error> {
    budget.work(1)?;
    if let Some(index) = template.strip_prefix("type") {
        let index = index
            .parse::<usize>()
            .map_err(|_| Error::semantic("RT_CATALOG_CONFIGURATION", String::new()))?;
        let expected = bindings
            .get(index)
            .ok_or_else(|| Error::semantic("RT_CATALOG_CONFIGURATION", String::new()))?;
        return types.type_equivalent(actual, *expected, budget);
    }
    let record = types.type_record(actual)?;
    if ["u8", "u32", "u64", "i1", "i32", "i64"].contains(&template) {
        let bits = template[1..]
            .parse::<u64>()
            .map_err(|_| Error::semantic("RT_CATALOG_CONFIGURATION", String::new()))?;
        return Ok(token(record, "kind")? == "int" && number(record, "bits")? == bits);
    }
    Ok(token(record, "kind")? == template
        && (template != "data_ptr" || token(record, "space")? == "guest_data"))
}

fn portable_signature(types: &TypeFacts, signature: TypeHandle) -> Result<&RecordValue, Error> {
    let signature = types.type_record(signature)?;
    require(
        token(signature, "kind")? == "function"
            && token(signature, "cc")? == "portable"
            && !flag(signature, "variadic")?,
        "RT_HELPER_SIGNATURE",
    )?;
    Ok(signature)
}

/// Complete catalog execution-signature instantiation, including fixed captures.
/// Source ABI/target/option joins are separate mandatory checks, not inferred here.
pub(crate) fn verify_helper_types(
    ctx: &ObjectContext,
    types: &TypeFacts,
    record: &RecordValue,
    spec: &Json,
    budget: &mut Budget,
) -> Result<TypeHandle, Error> {
    types.assert_context(ctx)?;
    budget.work(24)?;
    require(
        token(record, "kind")? == "internal",
        "RT_HELPER_IMPORT_KIND",
    )?;
    require(
        token(record, "name")? == json_text(spec, "name")?
            && token(record, "namespace")? == json_text(spec, "namespace")?
            && number(record, "version")?
                == spec
                    .get("version")
                    .and_then(Json::as_u64)
                    .ok_or_else(|| Error::semantic("RT_CATALOG_CONFIGURATION", String::new()))?,
        "RT_HELPER_VERSION",
    )?;
    let contract = token(record, "contract")?;
    require(
        json_list(spec, "contracts")?
            .iter()
            .any(|v| v.as_str() == Some(contract)),
        "RT_HELPER_CONTRACT",
    )?;
    let signature = types.type_reference(field(record, "signature")?)?;
    let function = portable_signature(types, signature)?;
    let parameters = json_list(spec, "type_parameters")?;
    let references = list(field(record, "types")?)?;
    require(references.len() == parameters.len(), "RT_HELPER_TYPE_ARITY")?;
    budget.reserve_bytes(
        references
            .len()
            .checked_mul(std::mem::size_of::<TypeHandle>())
            .ok_or_else(|| Error::resource("RT_HELPER_RESOURCE", String::new()))?,
    )?;
    let mut bindings = Vec::with_capacity(references.len());
    for (reference, constraint) in references.iter().zip(parameters) {
        budget.work(4)?;
        let actual = types.type_reference(reference)?;
        let value = types.type_record(actual)?;
        let kind = token(value, "kind")?;
        let constraint = constraint
            .as_str()
            .ok_or_else(|| Error::semantic("RT_CATALOG_CONFIGURATION", String::new()))?;
        let accepted = match constraint {
            "storage_value" => [
                "int", "raw", "float", "data_ptr", "code_ptr", "code_address", "vector", "array", "struct",
            ]
            .contains(&kind),
            "integer" => kind == "int",
            "pointer" => ["data_ptr", "code_ptr", "code_address"].contains(&kind),
            "floating_value" | "integer_value" => {
                let leaf = if kind == "vector" {
                    types.type_record(types.type_reference(field(value, "element")?)?)?
                } else {
                    value
                };
                ["float", "int", "vector"].contains(&kind)
                    && token(leaf, "kind")?
                        == if constraint == "floating_value" {
                            "float"
                        } else {
                            "int"
                        }
            }
            _ => kind == constraint,
        };
        require(accepted, "RT_HELPER_TYPE_CONSTRAINT")?;
        bindings.push(actual);
    }
    if contract == "c_fenv" && json_text(spec, "policy")? == "libm" {
        require(
            bindings.first().is_some_and(|ty| {
                types
                    .type_record(*ty)
                    .is_ok_and(|v| token(v, "kind").is_ok_and(|k| k != "vector"))
            }),
            "RT_HELPER_C_LIBM_SCALAR",
        )?;
    }
    if parameters
        .iter()
        .any(|v| v.as_str() == Some("integer_value"))
    {
        require(bindings.len() >= 2, "RT_CATALOG_CONFIGURATION")?;
        let left = types.type_record(bindings[0])?;
        let right = types.type_record(bindings[1])?;
        let vector = token(left, "kind")? == "vector";
        require(
            vector == (token(right, "kind")? == "vector")
                && (!vector || number(left, "count")? == number(right, "count")?),
            "RT_HELPER_VECTOR_SHAPE",
        )?;
    }
    let formal_params = json_list(spec, "params")?;
    let placeholders = formal_params
        .iter()
        .filter(|p| p.get("type").and_then(Json::as_str) == Some("journal_captures"))
        .count();
    require(placeholders <= 1, "RT_HELPER_JOURNAL_TEMPLATE")?;
    let mut captures = Vec::new();
    if placeholders == 1 {
        let reference = optional(field(record, "abi")?)?
            .ok_or_else(|| Error::semantic("RT_HELPER_JOURNAL_CAPTURES", String::new()))?;
        let id = super::symbols::self_id(entity_ref(reference)?, "RT_HELPER_JOURNAL_CAPTURES")?;
        let journal = ctx.entity(ctx.local(Namespace::Journal, id)?)?;
        let params = list(field(journal, "params")?)?;
        budget.reserve_bytes(
            params
                .len()
                .checked_mul(std::mem::size_of::<TypeHandle>())
                .ok_or_else(|| Error::resource("RT_HELPER_RESOURCE", String::new()))?,
        )?;
        captures = Vec::with_capacity(params.len());
        for param in params {
            budget.work(3)?;
            let nominal = ctx.entity(nominal_expectation(ctx, field(param, "type")?)?)?;
            let execution = optional(field(nominal, "execution")?)?
                .ok_or_else(|| Error::semantic("RT_HELPER_JOURNAL_CAPTURES", String::new()))?;
            captures.push(types.type_reference(execution)?);
        }
    }
    for (side, attrs) in [("params", "param_noundef"), ("results", "result_noundef")] {
        let actual = list(field(function, side)?)?;
        let noundef = list(field(function, attrs)?)?;
        let mut index = 0;
        for formal in json_list(spec, side)? {
            let template = json_text(formal, "type")?;
            let expected_noundef = formal
                .get("noundef")
                .and_then(Json::as_bool)
                .ok_or_else(|| Error::semantic("RT_CATALOG_CONFIGURATION", String::new()))?;
            let count = if template == "journal_captures" {
                captures.len()
            } else {
                1
            };
            for capture in 0..count {
                budget.work(3)?;
                let reference = actual
                    .get(index)
                    .ok_or_else(|| Error::semantic("RT_HELPER_ARITY", String::new()))?;
                let actual_type = types.type_reference(reference)?;
                let promise = noundef
                    .get(index)
                    .ok_or_else(|| Error::semantic("RT_HELPER_NOUNDEF", String::new()))?;
                require(
                    boolean(promise)?
                        == if template == "journal_captures" {
                            false
                        } else {
                            expected_noundef
                        },
                    "RT_HELPER_NOUNDEF",
                )?;
                require(
                    if template == "journal_captures" {
                        types.type_equivalent(actual_type, captures[capture], budget)?
                    } else {
                        matches_template(template, actual_type, &bindings, types, budget)?
                    },
                    "RT_HELPER_TYPE",
                )?;
                index += 1;
            }
        }
        require(
            index == actual.len() && index == noundef.len(),
            "RT_HELPER_ARITY",
        )?;
    }
    if ["eh_get_terminate", "eh_set_terminate"].contains(&json_text(spec, "name")?) {
        for side in ["params", "results"] {
            for reference in list(field(function, side)?)? {
                budget.work(4)?;
                let pointer = types.type_record(types.type_reference(reference)?)?;
                require(
                    token(pointer, "kind")? == "code_ptr",
                    "RT_HELPER_TERMINATE_SIGNATURE",
                )?;
                let target =
                    portable_signature(types, types.type_reference(field(pointer, "signature")?)?)?;
                require(
                    list(field(target, "params")?)?.is_empty()
                        && list(field(target, "results")?)?.is_empty(),
                    "RT_HELPER_TERMINATE_SIGNATURE",
                )?;
            }
        }
    }
    Ok(signature)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ImportKind {
    Internal,
    Service,
    Host,
    Foreign,
}

pub(crate) struct ImportFact {
    pub(crate) id: u32,
    pub(crate) kind: ImportKind,
    pub(crate) signature: TypeHandle,
    pub(crate) abi: Option<EntityKey>,
    pub(crate) completion: String,
}

fn local_abi_key(
    ctx: &ObjectContext,
    namespace: Namespace,
    value: &RecordValue,
) -> Result<EntityKey, Error> {
    let reference = entity_ref(value)?;
    match ctx.resolve_declaration(namespace, &reference)? {
        DeclaredEntity::Local(key) => Ok(key),
        DeclaredEntity::Dependency { .. } => {
            Err(Error::semantic("RT_HELPER_ABI_REQUIRED", String::new()))
        }
    }
}

fn abi_namespace(value: &str) -> Result<Namespace, Error> {
    match value {
        "storage_binding" => Ok(Namespace::StorageBinding),
        "signature" => Ok(Namespace::CallSignature),
        "journal" => Ok(Namespace::Journal),
        "bridge" => Ok(Namespace::Bridge),
        "nominal" => Ok(Namespace::Nominal),
        _ => Err(Error::semantic("RT_CATALOG_CONFIGURATION", String::new())),
    }
}

fn verify_abi_key(abi: &AbiFacts, key: EntityKey) -> Result<(), Error> {
    match key.namespace() {
        Namespace::StorageBinding => {
            abi.storage_binding(key)?;
        }
        Namespace::CallSignature => {
            abi.signature(key)?;
        }
        Namespace::Journal => {
            abi.journal(key)?;
        }
        Namespace::Bridge => {
            abi.bridge(key)?;
        }
        Namespace::Nominal => {
            abi.nominal(key)?;
        }
        _ => return Err(Error::semantic("RT_HELPER_ABI_REQUIRED", String::new())),
    }
    Ok(())
}

fn verify_helper_abi(
    ctx: &ObjectContext,
    types: &TypeFacts,
    abi: &AbiFacts,
    record: &RecordValue,
    spec: &Json,
    budget: &mut Budget,
) -> Result<Option<EntityKey>, Error> {
    budget.work(16)?;
    let contract = token(record, "contract")?;
    let namespace = spec
        .get("abi_namespace")
        .and_then(|v| v.get(contract))
        .and_then(Json::as_str)
        .ok_or_else(|| Error::semantic("RT_CATALOG_CONFIGURATION", String::new()))?;
    let optional_abi = namespace.starts_with("optional_");
    let namespace = namespace.strip_prefix("optional_").unwrap_or(namespace);
    let supplied = optional(field(record, "abi")?)?;
    let selected = if namespace == "none" {
        require(supplied.is_none(), "RT_HELPER_UNUSED_ABI")?;
        None
    } else if let Some(reference) = supplied {
        let namespace = abi_namespace(namespace)?;
        let key = if namespace == Namespace::Nominal {
            nominal_expectation(ctx, reference)?
        } else {
            local_abi_key(ctx, namespace, reference)?
        };
        verify_abi_key(abi, key)?;
        Some(key)
    } else {
        require(optional_abi, "RT_HELPER_ABI_REQUIRED")?;
        None
    };
    let target_namespace = spec
        .get("target_namespace")
        .and_then(|v| v.get(contract))
        .and_then(Json::as_str)
        .ok_or_else(|| Error::semantic("RT_CATALOG_CONFIGURATION", String::new()))?;
    let target = optional(field(field(record, "options")?, "target")?)?;
    if target_namespace == "none" {
        require(target.is_none(), "RT_HELPER_UNUSED_TARGET")?;
    } else {
        let target =
            target.ok_or_else(|| Error::semantic("RT_HELPER_TARGET_REQUIRED", String::new()))?;
        let reference = entity_ref(target)?;
        match target_namespace {
            "storage_layout" => {
                let key = local_abi_key(ctx, Namespace::MemoryLayout, target)?;
                let physical = types.layout(types.layout_from_entity(key)?)?;
                let bindings = list(field(record, "types")?)?;
                let first = bindings
                    .first()
                    .ok_or_else(|| Error::semantic("RT_HELPER_STORAGE_TYPE", String::new()))?;
                require(
                    types.type_equivalent(
                        physical.execution_type,
                        types.type_reference(first)?,
                        budget,
                    )?,
                    "RT_HELPER_STORAGE_TYPE",
                )?;
                if let Some(key) = selected {
                    require(
                        key.namespace() == Namespace::StorageBinding,
                        "RT_HELPER_STORAGE_BINDING",
                    )?;
                    let layout = abi.storage_binding(key)?.record();
                    require(
                        token(layout, "kind")? != "allocation",
                        "RT_HELPER_ALLOCATION_NOT_VALUE",
                    )?;
                    require(
                        field(layout, "execution_layout")? == target
                            && number(layout, "access_bytes")? == physical.access_bytes
                            && number(field(record, "options")?, "alignment")?
                                >= number(layout, "required_alignment")?,
                        "RT_HELPER_STORAGE_BINDING",
                    )?;
                }
            }
            "recipe" => match ctx.resolve_declaration(Namespace::Recipe, &reference)? {
                DeclaredEntity::Local(key) => {
                    abi.recipe(key)?;
                }
                DeclaredEntity::Dependency { .. } => {} // Exact provider body/interface is retained as an external condition.
            },
            "tls" => match reference.module {
                crate::context::ModuleRef::SelfModule => {
                    ctx.local(Namespace::Tls, reference.id)?;
                }
                crate::context::ModuleRef::Dependency { .. } => {
                    match ctx.resolve_declaration(Namespace::Symbol, &reference)? {
                        DeclaredEntity::Dependency { declaration, .. } => require(
                            token(declaration, "symbol_kind")? == "tls",
                            "RT_HELPER_TARGET_REQUIRED",
                        )?,
                        DeclaredEntity::Local(_) => {
                            return Err(Error::semantic(
                                "RT_HELPER_TARGET_REQUIRED",
                                String::new(),
                            ));
                        }
                    }
                }
            },
            _ => return Err(Error::semantic("RT_CATALOG_CONFIGURATION", String::new())),
        }
    }
    let binding = selected
        .filter(|key| key.namespace() == Namespace::StorageBinding)
        .map(|key| abi.storage_binding(key))
        .transpose()?;
    verify_options_with_abi(record, spec, binding, budget)?;
    if let Some(key) = selected.filter(|key| key.namespace() == Namespace::Nominal) {
        super::source_roles::verify(ctx, types, abi, key, record, budget)?;
    }
    Ok(selected)
}

fn verify_service(
    ctx: &ObjectContext,
    types: &TypeFacts,
    abi: &AbiFacts,
    record: &RecordValue,
    spec: &Json,
    budget: &mut Budget,
) -> Result<(TypeHandle, Option<EntityKey>), Error> {
    budget.work(12)?;
    require(
        token(record, "namespace")? == json_text(spec, "namespace")?
            && number(record, "version")? == 1,
        "RT_SERVICE_VERSION",
    )?;
    require(
        token(record, "capability")? == json_text(spec, "capability")?,
        "RT_SERVICE_CAPABILITY",
    )?;
    require(
        optional(field(record, "abi")?)?.is_none(),
        "RT_SERVICE_UNUSED_ABI",
    )?;
    let signature = types.type_reference(field(record, "signature")?)?;
    let function = portable_signature(types, signature)?;
    for (side, attrs) in [("params", "param_noundef"), ("results", "result_noundef")] {
        let actual = list(field(function, side)?)?;
        let promises = list(field(function, attrs)?)?;
        let expected = json_list(spec, side)?;
        require(
            actual.len() == expected.len() && promises.len() == expected.len(),
            "RT_SERVICE_SIGNATURE",
        )?;
        for ((reference, promise), expected) in actual.iter().zip(promises).zip(expected) {
            budget.work(3)?;
            require(
                boolean(promise)?
                    == expected
                        .get("noundef")
                        .and_then(Json::as_bool)
                        .ok_or_else(|| {
                            Error::semantic("RT_CATALOG_CONFIGURATION", String::new())
                        })?,
                "RT_SERVICE_SIGNATURE",
            )?;
            require(
                matches_template(
                    json_text(expected, "type")?,
                    types.type_reference(reference)?,
                    &[],
                    types,
                    budget,
                )?,
                "RT_SERVICE_TYPE",
            )?;
        }
    }
    let namespace = json_text(spec, "descriptor_namespace")?;
    let descriptor = optional(field(record, "descriptor")?)?;
    let selected = if namespace == "none" {
        require(descriptor.is_none(), "RT_SERVICE_UNUSED_DESCRIPTOR")?;
        None
    } else {
        let descriptor = descriptor
            .ok_or_else(|| Error::semantic("RT_SERVICE_DESCRIPTOR_REQUIRED", String::new()))?;
        let key = if namespace == "signature" {
            local_abi_key(ctx, Namespace::CallSignature, descriptor)?
        } else if namespace == "nominal" {
            nominal_expectation(ctx, descriptor)?
        } else {
            return Err(Error::semantic("RT_CATALOG_CONFIGURATION", String::new()));
        };
        if namespace == "signature" {
            let nominal = abi.nominal(abi.signature(key)?.function_type())?;
            let lowered = nominal
                .execution_type()
                .ok_or_else(|| Error::semantic("RT_SERVICE_LOOKUP_SIGNATURE", String::new()))?;
            let results = list(field(function, "results")?)?;
            let pointer = results
                .get(1)
                .ok_or_else(|| Error::semantic("RT_SERVICE_LOOKUP_SIGNATURE", String::new()))?;
            let pointer = types.type_record(types.type_reference(pointer)?)?;
            require(
                token(pointer, "kind")? == "code_ptr",
                "RT_SERVICE_LOOKUP_SIGNATURE",
            )?;
            require(
                types.type_equivalent(
                    lowered,
                    types.type_reference(field(pointer, "signature")?)?,
                    budget,
                )?,
                "RT_SERVICE_LOOKUP_SIGNATURE",
            )?;
        } else {
            require(
                !["void", "function"].contains(&abi.nominal(key)?.kind()?),
                "RT_SERVICE_LOOKUP_TYPE",
            )?;
        }
        Some(key)
    };
    Ok((signature, selected))
}

pub(crate) fn verify(
    ctx: &ObjectContext,
    types: &TypeFacts,
    abi: &AbiFacts,
    requirements: &RequirementFacts,
    budget: &mut Budget,
) -> Result<BTreeMap<u32, ImportFact>, Error> {
    types.assert_context(ctx)?;
    abi.assert_context(ctx)?;
    let root = ctx.root(6)?;
    require(
        number(root, "payload_revision")? == 1,
        "RT_PAYLOAD_REVISION",
    )?;
    let records = super::records::ordered(field(root, "imports")?, "id", budget)?;
    if records.is_empty() {
        return Ok(BTreeMap::new());
    }
    let catalogs = Catalogs::load(budget)?;
    budget.reserve_bytes(
        records
            .len()
            .checked_mul(256)
            .ok_or_else(|| Error::resource("RT_IMPORT_RESOURCE", String::new()))?,
    )?;
    let mut facts = BTreeMap::new();
    for (id, record) in records {
        budget.work(16)?;
        let (kind, signature, selected, completion) = match token(record, "kind")? {
            "internal" => {
                let spec = catalogs.helper(token(record, "name")?)?;
                require(
                    bytes(field(record, "catalog")?)? == catalogs.helper_digest(),
                    "RT_HELPER_VERSION",
                )?;
                let signature = verify_helper_types(ctx, types, record, spec, budget)?;
                let selected = verify_helper_abi(ctx, types, abi, record, spec, budget)?;
                (
                    ImportKind::Internal,
                    signature,
                    selected,
                    json_text(spec, "completion")?,
                )
            }
            "service" => {
                require(
                    requirements.requests(token(record, "capability")?),
                    "RT_IMPORT_CAPABILITY",
                )?;
                let spec = catalogs.service(token(record, "name")?)?;
                require(
                    bytes(field(record, "catalog")?)? == catalogs.service_digest(),
                    "RT_SERVICE_VERSION",
                )?;
                let (signature, selected) = verify_service(ctx, types, abi, record, spec, budget)?;
                let terminal = spec
                    .get("terminal")
                    .and_then(Json::as_bool)
                    .ok_or_else(|| Error::semantic("RT_CATALOG_CONFIGURATION", String::new()))?;
                (
                    ImportKind::Service,
                    signature,
                    selected,
                    if terminal { "nonreturning" } else { "returns" },
                )
            }
            "host" => {
                require(
                    token(record, "capability")? == "host_value"
                        && requirements.requests("host_value"),
                    "RT_HOST_IMPORT",
                )?;
                let namespace = token(record, "namespace")?;
                let name = token(record, "name")?;
                super::records::identifier(namespace)?;
                super::records::identifier(name)?;
                require(
                    !namespace.starts_with("smir.") && number(record, "version")? > 0,
                    "RT_HOST_NAME",
                )?;
                require(
                    bytes(field(record, "descriptor")?)?.len() == 32,
                    "RT_HOST_IMPORT",
                )?;
                let signature = types.type_reference(field(record, "signature")?)?;
                let function = portable_signature(types, signature)?;
                for side in ["params", "results"] {
                    for reference in list(field(function, side)?)? {
                        budget.work(2)?;
                        require(
                            ["int", "float", "raw"].contains(&token(
                                types.type_record(types.type_reference(reference)?)?,
                                "kind",
                            )?),
                            "RT_HOST_VALUE_ONLY",
                        )?;
                    }
                }
                (ImportKind::Host, signature, None, "returns")
            }
            "foreign" => {
                require(
                    requirements.requests(token(record, "capability")?),
                    "RT_IMPORT_CAPABILITY",
                )?;
                require(
                    token(field(ctx.root(2)?, "manifest")?, "foreign_isa")? != "none",
                    "RT_FOREIGN_ISA",
                )?;
                let key = local_abi_key(ctx, Namespace::Bridge, field(record, "descriptor")?)?;
                let bridge = abi.bridge(key)?.record();
                let source = abi.signature(ctx.local(
                    Namespace::CallSignature,
                    super::records::u32_field(bridge, "signature")?,
                )?)?;
                let execution = abi
                    .nominal(source.function_type())?
                    .execution_type()
                    .ok_or_else(|| Error::semantic("RT_FOREIGN_SIGNATURE", String::new()))?;
                let signature = types.type_reference(field(record, "signature")?)?;
                require(
                    types.type_equivalent(execution, signature, budget)?,
                    "RT_FOREIGN_SIGNATURE",
                )?;
                (ImportKind::Foreign, signature, Some(key), "returns")
            }
            _ => return Err(Error::semantic("RT_IMPORT_KIND", String::new())),
        };
        budget.reserve_bytes(completion.len())?;
        facts.insert(
            id,
            ImportFact {
                id,
                kind,
                signature,
                abi: selected,
                completion: completion.into(),
            },
        );
    }
    Ok(facts)
}
