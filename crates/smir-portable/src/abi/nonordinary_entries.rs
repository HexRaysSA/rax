//! DRAFT finite entry coverage, after every original ABI semantic predicate.
//! No facts, source-call permission or runtime authority are constructed here.
use super::value::*;
use crate::{
    Error,
    context::ObjectContext,
    execution::{TypeFacts, TypeKind},
    limits::Budget,
    wire::RecordValue,
};
use std::collections::BTreeMap;

macro_rules! profile {
    ($c:expr) => {
        if !$c {
            return Ok(false);
        }
    };
}
fn local(v: &RecordValue) -> Result<Option<u32>, Error> {
    if text(field(field(v, "module")?, "kind")?)? != "self" {
        return Ok(None);
    }
    Ok(Some(id(field(v, "id")?)?))
}
fn flags(v: &RecordValue, expected: &[&str]) -> Result<bool, Error> {
    let f = list(field(v, "flags")?)?;
    Ok(f.len() == expected.len() && expected.iter().all(|s| f.iter().any(|x| text(x) == Ok(*s))))
}
fn execution<'a>(t: &RecordValue, types: &'a TypeFacts) -> Result<Option<&'a TypeKind>, Error> {
    let Some(r) = optional(field(t, "execution")?)? else {
        return Ok(None);
    };
    if local(r)?.is_none() {
        return Ok(None);
    }
    Ok(Some(types.kind(types.type_reference(r)?)?))
}
fn node<'a>(
    table: &BTreeMap<u32, &'a RecordValue>,
    r: &RecordValue,
) -> Result<Option<&'a RecordValue>, Error> {
    Ok(local(r)?.and_then(|n| table.get(&n).copied()))
}
fn is_kind(table: &BTreeMap<u32, &RecordValue>, r: &RecordValue, k: &str) -> Result<bool, Error> {
    let Some(t) = node(table, r)? else {
        return Ok(false);
    };
    Ok(text(field(t, "kind")?)? == k)
}
fn scalar(t: &RecordValue) -> Result<bool, Error> {
    Ok(text(field(t, "kind")?)? == "scalar"
        && uint(field(t, "bits")?)? == 32
        && boolean(field(t, "signed")?)?
        && text(field(field(t, "identity")?, "entity")?)? == "int")
}
fn record_size(t: &RecordValue) -> Result<u64, Error> {
    let Some(input) = optional(field(t, "record_input")?)? else {
        return Ok(0);
    };
    Ok((list(field(input, "fields")?)?.len() as u64) * 4)
}
fn geometry(
    t: &RecordValue,
    table: &BTreeMap<u32, &RecordValue>,
) -> Result<Option<(u64, u64)>, Error> {
    Ok(match text(field(t, "kind")?)? {
        "scalar" => Some((4, 4)),
        "pointer" => Some((8, 8)),
        "record" => Some((record_size(t)?, 4)),
        "array" => {
            let es = list(field(t, "elements")?)?;
            if es.len() != 1 {
                return Ok(None);
            }
            let Some(child) = node(table, &es[0])? else {
                return Ok(None);
            };
            let Some(n) = optional(field(t, "extent")?)? else {
                return Ok(None);
            };
            Some((record_size(child)? * uint(n)?, 4))
        }
        _ => None,
    })
}
fn pointer_to(
    table: &BTreeMap<u32, &RecordValue>,
    r: &RecordValue,
    pointee: &str,
) -> Result<bool, Error> {
    let Some(t) = node(table, r)? else {
        return Ok(false);
    };
    let es = list(field(t, "elements")?)?;
    Ok(text(field(t, "kind")?)? == "pointer"
        && text(field(t, "representation")?)? == "value"
        && es.len() == 1
        && is_kind(table, &es[0], pointee)?)
}
fn lowered(p: &RecordValue, role: &str, mode: &str, size: u64, align: u64) -> Result<bool, Error> {
    for name in ["copy", "move", "destroy"] {
        if optional(field(p, name)?)?.is_some() {
            return Ok(false);
        }
    }
    Ok(text(field(p, "role")?)? == role
        && text(field(p, "mode")?)? == mode
        && uint(field(p, "bytes")?)? == size
        && uint(field(p, "align")?)? == align
        && boolean(field(p, "noundef")?)?
        && optional(field(p, "source_index")?)?.is_none())
}

pub(super) fn covered(
    ctx: &ObjectContext,
    types: &TypeFacts,
    budget: &mut Budget,
) -> Result<bool, Error> {
    let root = ctx.root(10)?;
    for name in [
        "recipes",
        "personalities",
        "unwind",
        "catches",
        "bridges",
        "storage_bindings",
    ] {
        budget.work(1)?;
        profile!(list(field(root, name)?)?.is_empty());
    }
    profile!(list(field(field(ctx.root(2)?, "manifest")?, "dependencies")?)?.is_empty());
    let domains = list(field(root, "domains")?)?;
    profile!(domains.len() == 1);
    for name in ["isa", "abi", "personality"] {
        profile!(text(field(&domains[0], name)?)? == "portable");
    }
    let source = list(field(root, "types")?)?;
    let layouts = list(field(root, "layouts")?)?;
    let plans = list(field(root, "signatures")?)?;
    profile!(
        !source.is_empty()
            && source.len() <= 32
            && layouts.len() <= 32
            && !plans.is_empty()
            && plans.len() <= 8
    );
    budget.edges(source.len() + layouts.len() + plans.len())?;
    budget.reserve_bytes(256 * (source.len() + layouts.len() + plans.len()))?;
    let mut table = BTreeMap::new();
    for t in source {
        table.insert(id(field(t, "id")?)?, t);
    }
    let mut records = Vec::new();
    for t in source {
        budget.work(128)?;
        profile!(field(t, "domain")? == field(&domains[0], "id")?);
        let ident = field(t, "identity")?;
        let kind = text(field(t, "kind")?)?;
        profile!(
            matches!(text(field(ident, "language")?)?, "c23" | "cpp23")
                && optional(field(ident, "library")?)?.is_none()
                && optional(field(ident, "unit")?)?.is_none()
        );
        profile!(
            list(field(t, "qualifiers")?)?.is_empty() && list(field(t, "enumerators")?)?.is_empty()
        );
        if kind != "record" {
            profile!(
                list(field(t, "methods")?)?.is_empty()
                    && optional(field(t, "record_input")?)?.is_none()
                    && text(field(ident, "linkage")?)? == "builtin"
            );
        }
        match kind {
            "scalar" => {
                profile!(
                    scalar(t)?
                        && text(field(t, "representation")?)? == "value"
                        && flags(t, &["complete", "trivial_copy", "trivial_destroy"])?
                );
                profile!(
                    list(field(t, "elements")?)?.is_empty()
                        && optional(field(t, "extent")?)?.is_none()
                );
                profile!(matches!(execution(t, types)?, Some(TypeKind::Int(32))));
            }
            "void" => {
                profile!(
                    text(field(ident, "entity")?)? == "void"
                        && uint(field(t, "bits")?)? == 0
                        && !boolean(field(t, "signed")?)?
                        && list(field(t, "elements")?)?.is_empty()
                        && optional(field(t, "extent")?)?.is_none()
                        && optional(field(t, "layout")?)?.is_none()
                        && optional(field(t, "execution")?)?.is_none()
                        && text(field(t, "representation")?)? == "none"
                );
                for f in list(field(t, "flags")?)? {
                    profile!(matches!(
                        text(f)?,
                        "complete" | "trivial_copy" | "trivial_destroy"
                    ));
                }
            }
            "pointer" => {
                profile!(
                    text(field(ident, "entity")?)? == "pointer"
                        && uint(field(t, "bits")?)? == 64
                        && !boolean(field(t, "signed")?)?
                        && optional(field(t, "extent")?)?.is_none()
                );
                let es = list(field(t, "elements")?)?;
                profile!(es.len() == 1);
                let Some(target) = node(&table, &es[0])? else {
                    return Ok(false);
                };
                match text(field(t, "representation")?)? {
                    "value" => {
                        profile!(
                            flags(t, &["complete", "trivial_copy", "trivial_destroy"])?
                                && matches!(execution(t, types)?, Some(TypeKind::DataPtr))
                        );
                        profile!(matches!(
                            text(field(target, "kind")?)?,
                            "scalar" | "void" | "record" | "array"
                        ));
                    }
                    "code_address" => {
                        profile!(
                            flags(t, &["code", "complete", "trivial_copy", "trivial_destroy"])?
                                && matches!(execution(t, types)?, Some(TypeKind::CodeAddress))
                                && text(field(target, "kind")?)? == "function"
                        );
                    }
                    _ => return Ok(false),
                }
            }
            "function" => {
                profile!(
                    text(field(ident, "entity")?)? == "function"
                        && uint(field(t, "bits")?)? == 0
                        && !boolean(field(t, "signed")?)?
                        && optional(field(t, "layout")?)?.is_none()
                );
                let fs = list(field(t, "flags")?)?;
                profile!(fs.iter().any(|x| text(x) == Ok("complete")));
                for f in fs {
                    profile!(matches!(text(f)?, "complete" | "noexcept"));
                }
                let Some(n) = optional(field(t, "extent")?)? else {
                    return Ok(false);
                };
                let n = uint(n)?;
                let es = list(field(t, "elements")?)?;
                profile!(n <= 1 && es.len() == n as usize + 1);
                for (i, e) in es.iter().enumerate() {
                    let Some(v) = node(&table, e)? else {
                        return Ok(false);
                    };
                    let k = text(field(v, "kind")?)?;
                    profile!(
                        matches!(k, "scalar" | "pointer" | "record")
                            || (i == n as usize && k == "void")
                    );
                }
                let present = optional(field(t, "execution")?)?.is_some();
                profile!(
                    text(field(t, "representation")?)?
                        == if present { "signature" } else { "none" }
                );
                if present {
                    profile!(matches!(
                        execution(t, types)?,
                        Some(TypeKind::Function { .. })
                    ));
                }
            }
            "record" => {
                profile!(
                    text(field(ident, "language")?)? == "cpp23"
                        && text(field(ident, "linkage")?)? == "external"
                        && flags(t, &["complete", "trivial_copy", "trivial_destroy"])?
                        && uint(field(t, "bits")?)? == 0
                        && !boolean(field(t, "signed")?)?
                        && list(field(t, "elements")?)?.is_empty()
                        && optional(field(t, "extent")?)?.is_none()
                        && text(field(t, "representation")?)? == "storage"
                );
                let Some(input) = optional(field(t, "record_input")?)? else {
                    return Ok(false);
                };
                profile!(
                    uint(field(input, "revision")?)? == 1
                        && text(field(input, "kind")?)? == "struct"
                        && optional(field(input, "explicit_align")?)?.is_none()
                        && list(field(input, "bases")?)?.is_empty()
                );
                for f in ["pod03", "trivial", "standard_layout"] {
                    profile!(boolean(field(input, f)?)?);
                }
                for f in ["polymorphic", "dynamic", "empty"] {
                    profile!(!boolean(field(input, f)?)?);
                }
                let fields = list(field(input, "fields")?)?;
                profile!(!fields.is_empty() && fields.len() <= 8);
                for f in fields {
                    let Some(v) = node(&table, field(f, "type")?)? else {
                        return Ok(false);
                    };
                    profile!(
                        scalar(v)?
                            && optional(field(f, "name")?)?.is_some()
                            && optional(field(f, "bit_width")?)?.is_none()
                            && optional(field(f, "explicit_align")?)?.is_none()
                            && !boolean(field(f, "no_unique_address")?)?
                            && !boolean(field(f, "anonymous")?)?
                            && text(field(f, "access")?)? == "public"
                    );
                }
                profile!(
                    matches!(execution(t,types)?,Some(TypeKind::Raw(n))if u64::from(*n)==record_size(t)?*8)
                );
                profile!(list(field(t, "methods")?)?.len() <= 1);
                records.push(t);
            }
            "array" => {
                profile!(
                    text(field(ident, "entity")?)? == "array"
                        && flags(t, &["complete", "trivial_copy", "trivial_destroy"])?
                        && uint(field(t, "bits")?)? == 0
                        && !boolean(field(t, "signed")?)?
                        && text(field(t, "representation")?)? == "value"
                );
                let es = list(field(t, "elements")?)?;
                profile!(es.len() == 1 && is_kind(&table, &es[0], "record")?);
                let Some(n) = optional(field(t, "extent")?)? else {
                    return Ok(false);
                };
                let n = uint(n)?;
                profile!((1..=1024).contains(&n));
                let Some(TypeKind::Array { element, count }) = execution(t, types)? else {
                    return Ok(false);
                };
                let Some(child) = node(&table, &es[0])? else {
                    return Ok(false);
                };
                let Some(er) = optional(field(child, "execution")?)? else {
                    return Ok(false);
                };
                profile!(*count == n && *element == types.type_reference(er)?.id());
            }
            _ => return Ok(false),
        }
    }
    profile!(records.len() == 1);
    let record_id = id(field(records[0], "id")?)?;
    for layout in layouts {
        budget.work(128)?;
        let Some(t) = node(&table, field(layout, "type")?)? else {
            return Ok(false);
        };
        let Some((size, align)) = geometry(t, &table)? else {
            return Ok(false);
        };
        let Some(layout_id) = optional(field(t, "layout")?)? else {
            return Ok(false);
        };
        profile!(uint(layout_id)? == uint(field(layout, "id")?)?);
        for f in ["size", "data_size", "nonvirtual_size"] {
            profile!(uint(field(layout, f)?)? == size);
        }
        for f in ["align", "nonvirtual_align"] {
            profile!(uint(field(layout, f)?)? == align);
        }
        profile!(
            list(field(layout, "bases")?)?.is_empty() && list(field(layout, "vptrs")?)?.is_empty()
        );
        if text(field(t, "kind")?)? == "record" {
            let Some(input) = optional(field(t, "record_input")?)? else {
                return Ok(false);
            };
            let decls = list(field(input, "fields")?)?;
            let fields = list(field(layout, "fields")?)?;
            profile!(fields.len() == decls.len());
            for (i, (f, d)) in fields.iter().zip(decls).enumerate() {
                profile!(
                    uint(field(f, "declaration_index")?)? == i as u64
                        && field(f, "type")? == field(d, "type")?
                        && uint(field(f, "offset_bits")?)? == i as u64 * 32
                        && uint(field(f, "width_bits")?)? == 32
                        && list(field(f, "flags")?)?.is_empty()
                );
            }
        } else {
            profile!(list(field(layout, "fields")?)?.is_empty());
        }
    }
    for t in source {
        if geometry(t, &table)?.is_some() {
            profile!(optional(field(t, "layout")?)?.is_some());
        }
    }
    let mut method_plans = Vec::new();
    for p in plans {
        budget.work(256)?;
        profile!(
            !boolean(field(p, "variadic")?)?
                && optional(field(p, "varargs")?)?.is_none()
                && boolean(field(p, "return_noundef")?)?
        );
        let ps = list(field(p, "params")?)?;
        let result = optional(field(p, "result")?)?;
        let ls = list(field(p, "lowered_params")?)?;
        if let Some(this) = optional(field(p, "this_type")?)? {
            profile!(ps.is_empty() && pointer_to(&table, this, "record")?);
            let Some(this_node) = node(&table, this)? else {
                return Ok(false);
            };
            profile!(local(&list(field(this_node, "elements")?)?[0])? == Some(record_id));
            let sret = result.is_some();
            if let Some(r) = result {
                profile!(local(r)? == Some(record_id));
            }
            let vtt = boolean(field(p, "vtt")?)?;
            profile!(
                ls.len() == 1 + usize::from(sret) + usize::from(vtt)
                    && list(field(p, "lowered_results")?)?.is_empty()
            );
            let mut i = 0;
            if let Some(result) = result {
                profile!(
                    lowered(&ls[i], "sret", "sret", record_size(records[0])?, 4)?
                        && field(&ls[i], "source_type")? == result
                        && pointer_to(&table, field(&ls[i], "value_type")?, "record")?
                );
                i += 1;
            }
            profile!(
                lowered(&ls[i], "this", "direct", 8, 8)?
                    && field(&ls[i], "source_type")? == this
                    && field(&ls[i], "value_type")? == this
            );
            i += 1;
            if vtt {
                profile!(
                    lowered(&ls[i], "vtt", "direct", 8, 8)?
                        && field(&ls[i], "source_type")? == field(&ls[i], "value_type")?
                        && pointer_to(&table, field(&ls[i], "value_type")?, "void")?
                );
            }
            method_plans.push(p);
        } else {
            profile!(
                !boolean(field(p, "vtt")?)?
                    && ps.len() == 1
                    && result == Some(&ps[0])
                    && ls.len() == 1
            );
            let Some(n) = node(&table, &ps[0])? else {
                return Ok(false);
            };
            profile!(matches!(text(field(n, "kind")?)?, "scalar" | "pointer"));
            profile!(
                text(field(&ls[0], "role")?)? == "parameter"
                    && text(field(&ls[0], "mode")?)? == "direct"
                    && field(&ls[0], "source_type")? == &ps[0]
                    && field(&ls[0], "value_type")? == &ps[0]
            );
        }
    }
    profile!(!method_plans.is_empty());
    let mut used = false;
    let functions = list(field(ctx.root(3)?, "functions")?)?;
    profile!(!functions.is_empty() && functions.len() <= 8);
    for f in functions {
        budget.work(16)?;
        if let Some(r) = optional(field(f, "abi_signature")?)? {
            for p in &method_plans {
                budget.work(1)?;
                used |= local(r)? == Some(id(field(p, "id")?)?);
            }
        }
    }
    profile!(used);
    for m in list(field(records[0], "methods")?)? {
        profile!(!boolean(field(m, "virtual")?)? && optional(field(m, "slot")?)?.is_none());
        let mut matched = false;
        for p in &method_plans {
            budget.work(1)?;
            matched |= field(p, "function_type")? == field(m, "signature")?
                && boolean(field(p, "noexcept")?)? == boolean(field(m, "noexcept")?)?;
        }
        profile!(matched);
    }
    let journals = list(field(root, "journals")?)?;
    profile!(journals.len() <= 1);
    for j in journals {
        budget.work(16)?;
        for n in ["params", "slots", "normal_order", "exception_order"] {
            profile!(list(field(j, n)?)?.is_empty());
        }
    }
    Ok(true)
}
