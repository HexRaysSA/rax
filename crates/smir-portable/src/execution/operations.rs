//! Exhaustive operation-family dispatch over frozen executable records.

use crate::context::{Namespace, ObjectContext, field, signed};
use crate::error::Error;
use crate::limits::Budget;
use crate::wire::RecordValue;

use super::cfg::Cfg;
use super::records::{flag, identifier, local_reference, option, require, token};
use super::{TypeFacts, TypeHandle, TypeKind};

pub(super) fn check(
    ctx: &ObjectContext,
    types: &TypeFacts,
    cfg: &Cfg<'_>,
    function: &RecordValue,
    operation: &RecordValue,
    args: &[TypeHandle],
    outputs: &[TypeHandle],
    budget: &mut Budget,
) -> Result<(), Error> {
    if super::pure::check(operation, args, outputs, types, budget)? {
        return Ok(());
    }
    let name = token(operation, "op")?;
    let family = super::pure::contract(name)?
        .get("family")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| Error::semantic("P2_SCHEMA", "family"))?;
    let arg = |i| {
        args.get(i)
            .copied()
            .ok_or_else(|| Error::semantic("operand_arity", name))
    };
    let out = |i| {
        outputs
            .get(i)
            .copied()
            .ok_or_else(|| Error::semantic("result_arity", name))
    };
    match family {
        "code_address" => {
            let source = super::pure::scalar(types, arg(0)?)?;
            let destination = super::pure::scalar(types, out(0)?)?;
            super::pure::same_lanes(types, arg(0)?, out(0)?, "code_address_lanes")?;
            match name {
                "code_bind" => require(
                    matches!(source, TypeKind::CodeAddress)
                        && matches!(destination, TypeKind::CodePtr { .. }),
                    "code_bind_type",
                )?,
                "code_erase" => require(
                    matches!(source, TypeKind::CodePtr { .. })
                        && matches!(destination, TypeKind::CodeAddress),
                    "code_erase_type",
                )?,
                _ => return Err(Error::semantic("operation", name)),
            }
        }
        "pointer" => {
            require(
                matches!(
                    types.kind(out(0)?)?,
                    TypeKind::DataPtr | TypeKind::CodePtr { .. } | TypeKind::CodeAddress
                ),
                "pointer_result",
            )?;
            match name {
                "ptr_offset" => {
                    require(
                        !flag(operation, "check_base")? || flag(operation, "inbounds")?,
                        "pointer_check_base",
                    )?;
                    require(
                        matches!(types.kind(arg(0)?)?, TypeKind::DataPtr)
                            && matches!(types.kind(arg(1)?)?, TypeKind::Int(64)),
                        "pointer_offset",
                    )?;
                    super::pure::same(types, arg(0)?, out(0)?, budget)?;
                    if let Some(range) = option(operation, "inrange")? {
                        require(
                            signed(field(range, "lower")?)? <= signed(field(range, "upper")?)?,
                            "inrange_bounds",
                        )?;
                    }
                }
                "address_of" => super::calls::address_of(ctx, types, operation, out(0)?, budget)?,
                "block_address" => {
                    require(
                        !matches!(types.kind(out(0)?)?, TypeKind::CodeAddress),
                        "block_address_type",
                    )?;
                    require(
                        identifier(operation, "function")? == identifier(function, "id")?,
                        "block_address",
                    )?;
                    let block = identifier(operation, "block")?;
                    let index = cfg
                        .indices
                        .get(&block)
                        .ok_or_else(|| Error::semantic("block_address", "target"))?;
                    require(*index != cfg.entry, "block_address")?;
                }
                _ => return Err(Error::semantic("operation", name)),
            }
        }
        "memory" => super::memory::check(ctx, types, operation, args, outputs, budget)?,
        "memory_bulk" => super::memory::bulk(operation, args, types, budget)?,
        "call" => {
            require(
                ["nounwind", "propagate"].contains(&token(operation, "unwind")?),
                "call_unwind_policy",
            )?;
            super::calls::check_call(
                ctx,
                types,
                cfg,
                field(operation, "target")?,
                args,
                outputs,
                budget,
            )?;
        }
        "helper" => {
            super::calls::helper(ctx, types, cfg, operation, args, outputs, budget)?;
        }
        "exception" => match name {
            "landingpad" => require(
                matches!(types.kind(arg(0)?)?, TypeKind::Exception)
                    && matches!(types.kind(out(0)?)?, TypeKind::Int(32)),
                "landingpad_type",
            )?,
            "catch_begin" | "catch_end" => {
                require(
                    matches!(types.kind(arg(0)?)?, TypeKind::Exception),
                    "catch_type",
                )?;
                let target = field(operation, "helper")?;
                require(token(target, "kind")? == "import", "catch_helper")?;
                let (_, binding) =
                    super::calls::check_call(ctx, types, cfg, target, args, outputs, budget)?;
                let binding = binding.ok_or_else(|| Error::semantic("catch_helper", "binding"))?;
                require(
                    token(binding, "kind")? == "internal"
                        && token(binding, "name")?
                            == if name == "catch_begin" {
                                "eh_begin_catch"
                            } else {
                                "eh_end_catch"
                            },
                    "catch_helper",
                )?;
            }
            "journal" => {
                let action = token(operation, "action")?;
                require(
                    [
                        "construct_begin",
                        "construct_commit",
                        "destroy_begin",
                        "destroy_commit",
                        "ownership_transfer",
                        "retain",
                        "release",
                    ]
                    .contains(&action),
                    "journal_action",
                )?;
                let program = field(operation, "program")?;
                ctx.local(Namespace::Journal, local_reference(program)?)?;
                let target = field(operation, "helper")?;
                require(token(target, "kind")? == "import", "journal_helper")?;
                let (_, binding) =
                    super::calls::check_call(ctx, types, cfg, target, args, outputs, budget)?;
                let binding =
                    binding.ok_or_else(|| Error::semantic("journal_helper", "binding"))?;
                require(
                    token(binding, "kind")? == "internal"
                        && token(binding, "name")? == "journal_advance"
                        && token(binding, "contract")? == action
                        && option(binding, "abi")? == Some(program),
                    "journal_helper_binding",
                )?;
            }
            _ => return Err(Error::semantic("operation", name)),
        },
        _ => return Err(Error::semantic("operation", name)),
    }
    Ok(())
}
