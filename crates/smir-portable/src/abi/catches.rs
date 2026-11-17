//! Generic Itanium source matching; native payload adjustment is not performed.

use super::{nominal::Graph, value::*};
use crate::{Error, limits::Budget, wire::RecordValue};
use std::collections::{BTreeMap, BTreeSet};

pub(super) struct Relation {
    pub kind: &'static str,
    pub paths: Vec<Vec<String>>,
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum Subobject {
    Fixed(Vec<String>, i128),
    Virtual([u8; 32], i128),
}

pub(super) fn relation(
    graph: &Graph,
    thrown: u32,
    caught: Option<u32>,
    budget: &mut Budget,
) -> Result<Option<Relation>, Error> {
    let Some(caught) = caught else {
        return Ok(Some(Relation {
            kind: "catch_all",
            paths: vec![],
        }));
    };
    relation_inner(graph, thrown, caught, false, 0, budget)
}

fn relation_inner(
    graph: &Graph,
    thrown: u32,
    caught: u32,
    nested: bool,
    depth: u32,
    budget: &mut Budget,
) -> Result<Option<Relation>, Error> {
    budget.work(1)?;
    if depth >= 128 {
        return Err(Error::resource("ABI_CC_CATCH_RESOURCE", "pointer nesting"));
    }
    if graph.compatible(thrown, caught, true, budget)? {
        return Ok(Some(Relation {
            kind: "exact",
            paths: vec![],
        }));
    }
    let t = graph.typ_id(thrown)?;
    let c = graph.typ_id(caught)?;
    let tk = text(field(t, "kind")?)?;
    let ck = text(field(c, "kind")?)?;
    if tk == "scalar"
        && text(field(field(t, "identity")?, "entity")?)? == "nullptr_t"
        && matches!(ck, "pointer" | "member_pointer")
    {
        return Ok(Some(Relation {
            kind: "nullptr",
            paths: vec![],
        }));
    }
    if tk == "record" && ck == "record" {
        let paths = base_paths(graph, thrown, caught, budget)?;
        if paths.len() == 1 {
            let mut public = Vec::new();
            for entries in paths.into_values() {
                for (access, path) in entries {
                    if access {
                        budget.reserve_bytes(64)?;
                        public.push(path);
                    }
                }
            }
            if !public.is_empty() {
                return Ok(Some(Relation {
                    kind: "base",
                    paths: public,
                }));
            }
        }
        return Ok(None);
    }
    if tk != ck || !matches!(tk, "pointer" | "member_pointer") {
        return Ok(None);
    }
    if nested && !qualifiers_subset(t, c)? {
        return Ok(None);
    }
    let te = list(field(t, "elements")?)?;
    let ce = list(field(c, "elements")?)?;
    if tk == "member_pointer" {
        if te.len() != 2 || ce.len() != 2 {
            return Ok(None);
        }
        for (a, b) in te.iter().zip(ce) {
            if !graph.compatible(graph.resolve(a)?, graph.resolve(b)?, false, budget)? {
                return Ok(None);
            }
        }
        return Ok(Some(Relation {
            kind: "member_pointer",
            paths: vec![],
        }));
    }
    require(te.len() == 1 && ce.len() == 1, "ABI_CC_POINTER_TYPE")?;
    let ti = graph.resolve(&te[0])?;
    let ci = graph.resolve(&ce[0])?;
    let tp = graph.typ_id(ti)?;
    let cp = graph.typ_id(ci)?;
    if !qualifiers_subset(tp, cp)? {
        return Ok(None);
    }
    let tpk = text(field(tp, "kind")?)?;
    let cpk = text(field(cp, "kind")?)?;
    if cpk == "void" && tpk != "function" && !nested {
        return Ok(Some(Relation {
            kind: "pointer",
            paths: vec![],
        }));
    }
    if tpk == "function" && cpk == "function" {
        if !flags(tp, "flags", "noexcept")? && flags(cp, "flags", "noexcept")? {
            return Ok(None);
        }
        let a = list(field(tp, "elements")?)?;
        let b = list(field(cp, "elements")?)?;
        if field(tp, "extent")? != field(cp, "extent")?
            || flags(tp, "flags", "variadic")? != flags(cp, "flags", "variadic")?
            || a.len() != b.len()
        {
            return Ok(None);
        }
        for (a, b) in a.iter().zip(b) {
            if !graph.compatible(graph.resolve(a)?, graph.resolve(b)?, false, budget)? {
                return Ok(None);
            }
        }
        return Ok(Some(Relation {
            kind: "pointer",
            paths: vec![],
        }));
    }
    if tpk == "record" && cpk == "record" && !nested {
        return Ok(
            relation_inner(graph, ti, ci, false, depth + 1, budget)?.map(|r| Relation {
                kind: "pointer",
                paths: r.paths,
            }),
        );
    }
    if matches!(tpk, "pointer" | "member_pointer") && cpk == tpk {
        if !flags(cp, "qualifiers", "const")? {
            return Ok(None);
        }
        return relation_inner(graph, ti, ci, true, depth + 1, budget);
    }
    Ok(if graph.compatible(ti, ci, true, budget)? {
        Some(Relation {
            kind: "pointer",
            paths: vec![],
        })
    } else {
        None
    })
}

fn qualifiers_subset(a: &RecordValue, b: &RecordValue) -> Result<bool, Error> {
    let a = list(field(a, "qualifiers")?)?;
    let b = list(field(b, "qualifiers")?)?;
    Ok(a.iter().all(|value| b.contains(value)))
}

fn base_paths(
    graph: &Graph,
    thrown: u32,
    caught: u32,
    budget: &mut Budget,
) -> Result<BTreeMap<Subobject, Vec<(bool, Vec<String>)>>, Error> {
    struct State {
        current: u32,
        path: Vec<String>,
        public: bool,
        offset: i128,
        virtual_identity: Option<[u8; 32]>,
        ancestors: BTreeSet<u32>,
    }
    budget.reserve_bytes(256)?;
    let mut stack = vec![State {
        current: thrown,
        path: vec![],
        public: true,
        offset: 0,
        virtual_identity: None,
        ancestors: BTreeSet::new(),
    }];
    let mut results = BTreeMap::<Subobject, Vec<(bool, Vec<String>)>>::new();
    while let Some(mut state) = stack.pop() {
        budget.work(1)?;
        budget.reserve_bytes(64)?;
        require(state.ancestors.insert(state.current), "ABI_CC_BASE_CYCLE")?;
        if graph.compatible(state.current, caught, true, budget)? {
            budget.reserve_bytes(
                state
                    .path
                    .len()
                    .checked_mul(48)
                    .and_then(|n| n.checked_add(256))
                    .ok_or_else(|| Error::resource("ABI_CC_CATCH_RESOURCE", "base path"))?,
            )?;
            let identity = if let Some(identity) = state.virtual_identity {
                Subobject::Virtual(identity, state.offset)
            } else {
                Subobject::Fixed(state.path.clone(), state.offset)
            };
            results
                .entry(identity)
                .or_default()
                .push((state.public, state.path));
            continue;
        }
        let typ = graph.typ_id(state.current)?;
        if text(field(typ, "kind")?)? != "record" {
            continue;
        }
        let input = optional(field(typ, "record_input")?)?.ok_or_else(|| Error::new(
            crate::ErrorClass::UnavailableEvidence, "ABI_CC_SOURCE_HIERARCHY_UNAVAILABLE",
            "source direct hierarchy required for base query",
        ))?;
        let placements = list(field(graph.layout_id(state.current)?, "bases")?)?;
        for (index, base) in list(field(input, "bases")?)?.iter().enumerate() {
            budget.work(1)?;
            let child = graph.resolve(field(base, "type")?)?;
            let is_virtual = boolean(field(base, "virtual")?)?;
            let virtual_identity = if is_virtual {
                Some(graph.fingerprint(child, true, budget)?)
            } else { state.virtual_identity };
            let offset = if is_virtual { 0 } else {
                let mut placement = None;
                for candidate in placements {
                    budget.work(1)?;
                    if !boolean(field(candidate, "virtual")?)? &&
                        optional(field(candidate, "declaration_index")?)?
                            .map(id).transpose()? == Some(index as u32) {
                        require(placement.is_none(), "ABI_CC_BASE_DERIVATION")?;
                        placement = Some(candidate);
                    }
                }
                let placement = placement.ok_or_else(|| Error::semantic(
                    "ABI_CC_BASE_DERIVATION", "direct source base placement missing",
                ))?;
                state.offset.checked_add(i128::from(uint(field(placement, "offset")?)?))
                    .ok_or_else(|| Error::semantic("ABI_CC_BASE_ADJUSTMENT", "offset overflow"))?
            };
            let path_name = index.to_string();
            let bytes = state
                .path
                .iter()
                .try_fold(path_name.len() + 256, |n, s| n.checked_add(s.len() + 48))
                .and_then(|n| n.checked_add(state.ancestors.len() * 64))
                .ok_or_else(|| Error::resource("ABI_CC_CATCH_RESOURCE", "path copy"))?;
            budget.reserve_bytes(bytes)?;
            let mut path = state.path.clone();
            path.push(path_name);
            stack.push(State {
                current: child,
                path,
                public: state.public && text(field(base, "access")?)? == "public",
                offset,
                virtual_identity,
                ancestors: state.ancestors.clone(),
            });
        }
    }
    Ok(results)
}
