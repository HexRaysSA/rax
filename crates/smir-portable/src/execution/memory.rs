//! Static memory-operation checks; no access, mapping or atomic effect occurs.

use crate::context::{Namespace, ObjectContext, field};
use crate::error::Error;
use crate::limits::Budget;
use crate::wire::RecordValue;

use super::pure::{same, scalar};
use super::records::{flag, local_reference, number, option, require, token};
use super::{TypeFacts, TypeHandle, TypeKind};

pub(super) fn check(
    ctx: &ObjectContext,
    types: &TypeFacts,
    operation: &RecordValue,
    args: &[TypeHandle],
    results: &[TypeHandle],
    budget: &mut Budget,
) -> Result<(), Error> {
    let name = token(operation, "op")?;
    let arg = |i| {
        args.get(i)
            .copied()
            .ok_or_else(|| Error::semantic("operand_arity", name))
    };
    let out = |i| {
        results
            .get(i)
            .copied()
            .ok_or_else(|| Error::semantic("result_arity", name))
    };
    if name == "fence" {
        require(
            ["acquire", "release", "acq_rel", "seq_cst"].contains(&token(operation, "order")?)
                && token(operation, "scope")? == "process",
            "fence_order",
        )?;
        return Ok(());
    }
    require(
        matches!(types.kind(arg(0)?)?, TypeKind::DataPtr),
        "memory_address",
    )?;
    let storage = field(operation, "storage")?;
    let ty = types.type_reference(field(storage, "type")?)?;
    let layout_id = local_reference(field(storage, "layout")?)?;
    let layout = types.layout(types.layout_handle(layout_id)?)?;
    same(types, layout.execution_type, ty, budget)?;
    let extent = number(storage, "bytes")?;
    require(layout.access_bytes == extent, "abi_layout_extent")?;
    let nominal = option(storage, "nominal")?;
    let binding = option(storage, "abi_binding")?;
    require(
        nominal.is_some() == binding.is_some(),
        "storage_nominal_binding_pair",
    )?;
    let mut required_alignment = None;
    if let (Some(nominal), Some(binding)) = (nominal, binding) {
        ctx.resolve_declaration(Namespace::Nominal, &crate::context::entity_ref(nominal)?)?;
        let binding =
            ctx.entity(ctx.local(Namespace::StorageBinding, local_reference(binding)?)?)?;
        require(
            token(binding, "kind")? != "allocation",
            "storage_allocation_not_value",
        )?;
        require(
            field(binding, "nominal")? == nominal
                && field(binding, "execution_layout")? == field(storage, "layout")?
                && number(binding, "access_bytes")? == extent,
            "storage_binding_match",
        )?;
        required_alignment = Some(number(binding, "required_alignment")?);
    }
    let mode = field(operation, "mode")?;
    let alignment = number(mode, "alignment")?;
    let order = token(mode, "order")?;
    let failure = token(mode, "failure_order")?;
    require(
        alignment.is_power_of_two()
            && token(mode, "scope")? == "process"
            && [
                "none",
                "unordered",
                "relaxed",
                "acquire",
                "release",
                "acq_rel",
                "seq_cst",
            ]
            .contains(&order),
        "memory_mode",
    )?;
    if let Some(required) = required_alignment {
        require(alignment >= required, "storage_binding_alignment")?;
    }
    let atomic = name.starts_with("atomic_") || name == "cmpxchg";
    if flag(mode, "elementwise")? {
        require(
            ["atomic_load", "atomic_store", "atomic_rmw"].contains(&name) && order != "seq_cst",
            "elementwise_atomic",
        )?;
        let TypeKind::Vector { element, .. } = types.kind(ty)? else {
            return Err(Error::semantic("elementwise_atomic", "vector"));
        };
        let width = types.value_bits(ty)?;
        let element_width = types.value_bits(types.type_handle(*element)?)?;
        require(
            width >= 8
                && width.is_power_of_two()
                && element_width >= 8
                && element_width.is_power_of_two(),
            "elementwise_width",
        )?;
    }
    match name {
        "load" | "store" => require(order == "none" && failure == "none", "ordinary_order")?,
        "atomic_load" => require(
            ["unordered", "relaxed", "acquire", "seq_cst"].contains(&order),
            "atomic_load_order",
        )?,
        "atomic_store" => require(
            ["unordered", "relaxed", "release", "seq_cst"].contains(&order),
            "atomic_store_order",
        )?,
        "atomic_rmw" | "cmpxchg" => require(
            ["relaxed", "acquire", "release", "acq_rel", "seq_cst"].contains(&order),
            "atomic_rmw_order",
        )?,
        _ => return Err(Error::semantic("operation", name)),
    }
    if name == "cmpxchg" {
        // This LLVM pin permits failure stronger than success. Check each order
        // independently; do not import the obsolete stronger-failure ban.
        require(
            ["relaxed", "acquire", "seq_cst"].contains(&failure),
            "cas_failure_order",
        )?;
        require(
            matches!(types.kind(out(1)?)?, TypeKind::Int(1)),
            "boolean_type",
        )?;
    } else {
        require(failure == "none", "failure_order_unused")?;
    }
    if atomic {
        require(extent > 0, "atomic_extent")?;
    }
    for arg in args.iter().skip(1) {
        same(types, *arg, ty, budget)?;
    }
    if !results.is_empty() {
        same(types, out(0)?, ty, budget)?;
    }
    if name == "atomic_rmw" {
        let action = token(operation, "action")?;
        require(
            [
                "exchange",
                "add",
                "sub",
                "and",
                "nand",
                "or",
                "xor",
                "min",
                "max",
                "umin",
                "umax",
                "uinc_wrap",
                "udec_wrap",
                "usub_cond",
                "usub_sat",
                "fadd",
                "fsub",
                "fmin",
                "fmax",
                "fminimum",
                "fmaximum",
                "fminimumnum",
                "fmaximumnum",
            ]
            .contains(&action),
            "atomic_action",
        )?;
        let scalar = scalar(types, ty)?;
        let valid = if action == "exchange" {
            matches!(
                scalar,
                TypeKind::Int(_)
                    | TypeKind::Float(_)
                    | TypeKind::DataPtr
                    | TypeKind::CodePtr { .. }
                    | TypeKind::CodeAddress
            ) || matches!(types.kind(ty)?, TypeKind::Raw(8))
        } else if action.starts_with('f') {
            matches!(scalar, TypeKind::Float(_))
        } else {
            matches!(scalar, TypeKind::Int(_))
        };
        require(valid, "atomic_action_type")?;
    }
    Ok(())
}

pub(super) fn bulk(
    operation: &RecordValue,
    args: &[TypeHandle],
    types: &TypeFacts,
    budget: &mut Budget,
) -> Result<(), Error> {
    let name = token(operation, "op")?;
    let (Some(a), Some(b), Some(count)) = (args.first(), args.get(1), args.get(2)) else {
        return Err(Error::semantic("operand_arity", name));
    };
    require(
        matches!(types.kind(*a)?, TypeKind::DataPtr)
            && matches!(types.kind(*count)?, TypeKind::Int(64))
            && number(operation, "alignment")?.is_power_of_two(),
        "bulk_memory",
    )?;
    if name == "memset" {
        require(matches!(types.kind(*b)?, TypeKind::Int(8)), "memset_byte")?;
    } else {
        same(types, *a, *b, budget)?;
    }
    Ok(())
}
