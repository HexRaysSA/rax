//! Independent INT032 canonical builtin source semantics, not proof eligibility.
//! All data are borrowed from this context's checked graphs; no success marker
//! supplied by a file can replace these source/layout/TypeFacts predicates.

use super::{nominal::Graph, value::*};
use crate::{Error, execution::{TypeFacts, TypeKind}, limits::Budget, wire::RecordValue};
use std::collections::BTreeSet;

const CODE: &str = "ABI_CC_BUILTIN_STATE";
const FLAGS: &[&str] = &["complete", "trivial_copy", "trivial_destroy"];

#[derive(Default)]
pub(super) struct Coverage {
    pub nodes: BTreeSet<u32>,
    pub states: BTreeSet<u32>,
    pub wrappers: BTreeSet<u32>,
}

fn remember(set: &mut BTreeSet<u32>, id: u32, budget: &mut Budget) -> Result<(), Error> {
    budget.work(1)?;
    if !set.contains(&id) { budget.reserve_bytes(64)?; set.insert(id); }
    Ok(())
}

fn identity(graph: &Graph, typ: &RecordValue, entity: &str, allow_top_cv: bool) -> Result<(), Error> {
    let source = field(typ, "identity")?;
    require(text(field(source, "language")?)? == "c23"
        && text(field(source, "linkage")?)? == "builtin"
        && text(field(source, "entity")?)? == entity
        && optional(field(source, "library")?)?.is_none()
        && optional(field(source, "unit")?)?.is_none()
        && (if allow_top_cv {
            list(field(typ,"qualifiers")?)?.iter().all(|q| matches!(text(q),Ok("const" | "volatile")))
        } else { list(field(typ,"qualifiers")?)?.is_empty() })
        && list(field(typ, "methods")?)?.is_empty()
        && list(field(typ, "enumerators")?)?.is_empty()
        && !boolean(field(typ, "signed")?)?
        && exact_flags(typ, FLAGS)?, CODE)?;
    require(text(field(graph.domain(typ)?, "isa")?)? == "portable", CODE)
}

fn exact_flags(typ: &RecordValue, expected: &[&str]) -> Result<bool, Error> {
    let actual = list(field(typ, "flags")?)?;
    if actual.len() != expected.len() { return Ok(false); }
    for (value, expected) in actual.iter().zip(expected) {
        if text(value)? != *expected { return Ok(false); }
    }
    Ok(true)
}

fn geometry(layout: &RecordValue, size: u64, align: u64) -> Result<(), Error> {
    for (name, expected) in [("size", size), ("align", align), ("data_size", size),
                             ("nonvirtual_size", size), ("nonvirtual_align", align)] {
        require(uint(field(layout, name)?)? == expected, CODE)?;
    }
    require(list(field(layout, "bases")?)?.is_empty() && list(field(layout, "vptrs")?)?.is_empty(), CODE)
}

fn execution<'a>(types: &'a TypeFacts, typ: &RecordValue) -> Result<&'a TypeKind, Error> {
    let reference = optional(field(typ, "execution")?)?
        .ok_or_else(|| Error::semantic(CODE, "builtin source transport missing"))?;
    types.kind(types.type_reference(reference)?)
}

fn unsigned(graph: &Graph, types: &TypeFacts, identifier: u32, bits: u32,
            coverage: &mut Coverage, budget: &mut Budget) -> Result<(), Error> {
    budget.work(16)?;
    let typ = graph.typ_id(identifier)?;
    identity(graph, typ, if bits == 32 { "unsigned int" } else { "unsigned long" }, false)?;
    require(text(field(typ, "kind")?)? == "scalar" && uint(field(typ, "bits")?)? == u64::from(bits)
        && text(field(typ, "representation")?)? == "value"
        && list(field(typ, "elements")?)?.is_empty()
        && optional(field(typ, "extent")?)?.is_none()
        && optional(field(typ, "record_input")?)?.is_none(), CODE)?;
    let layout = graph.layout_id(identifier)?;
    geometry(layout, u64::from(bits / 8), u64::from(bits / 8))?;
    require(list(field(layout, "fields")?)?.is_empty()
        && matches!(execution(types, typ)?, TypeKind::Int(width) if *width == bits), CODE)?;
    remember(&mut coverage.nodes, identifier, budget)
}

fn byte_array(types: &TypeFacts, typ: &RecordValue) -> Result<(), Error> {
    if let TypeKind::Array { element, count } = execution(types, typ)? {
        require(*count == 32 && matches!(types.kind(types.type_handle(*element)?)?, TypeKind::Raw(8)), CODE)
    } else { Err(Error::semantic(CODE, "state must use Array32<Raw8>")) }
}

fn state(graph: &Graph, types: &TypeFacts, identifier: u32,
         coverage: &mut Coverage, budget: &mut Budget) -> Result<(), Error> {
    budget.work(64)?;
    let typ = graph.typ_id(identifier)?;
    let name = text(field(field(typ, "identity")?, "entity")?)?;
    require(matches!(name, "rax.va_state" | "rax.jmp_state"), CODE)?;
    identity(graph, typ, name, true)?;
    require(text(field(typ, "kind")?)? == "record" && uint(field(typ, "bits")?)? == 0
        && list(field(typ, "elements")?)?.is_empty()
        && optional(field(typ, "extent")?)?.is_none()
        && text(field(typ, "representation")?)? == "storage", CODE)?;
    let input = optional(field(typ, "record_input")?)?
        .ok_or_else(|| Error::semantic(CODE, "builtin source declarations absent"))?;
    require(uint(field(input, "revision")?)? == 1 && text(field(input, "kind")?)? == "struct"
        && optional(field(input, "explicit_align")?)?.is_none()
        && list(field(input, "bases")?)?.is_empty(), CODE)?;
    for name in ["pod03", "trivial", "standard_layout", "polymorphic", "dynamic", "empty"] {
        require(!boolean(field(input, name)?)?, CODE)?;
    }
    let expected: &[(&str, u32, u64)] = if name == "rax.va_state" {
        &[("area",64,0),("cursor",64,8),("limit",64,16),("cookie",64,24)]
    } else {
        &[("revision",32,0),("reserved",32,4),("process",64,8),("checkpoint",64,16),("generation",64,24)]
    };
    let layout = graph.layout_id(identifier)?;
    geometry(layout,32,8)?;
    let inputs = list(field(input,"fields")?)?;
    let outputs = list(field(layout,"fields")?)?;
    require(inputs.len() == expected.len() && outputs.len() == expected.len(), CODE)?;
    budget.edges(expected.len())?;
    for (index, ((name,bits,offset),(source,selected))) in expected.iter()
        .zip(inputs.iter().zip(outputs)).enumerate() {
        budget.work(32)?;
        require(optional(field(source,"name")?)?.map(text).transpose()? == Some(*name)
            && optional(field(source,"bit_width")?)?.is_none()
            && optional(field(source,"explicit_align")?)?.is_none()
            && !boolean(field(source,"no_unique_address")?)?
            && !boolean(field(source,"anonymous")?)?
            && text(field(source,"access")?)? == "public", CODE)?;
        let field_id = graph.resolve(field(source,"type")?)?;
        unsigned(graph,types,field_id,*bits,coverage,budget)?;
        require(uint(field(selected,"declaration_index")?)? == index as u64
            && text(field(selected,"name")?)? == *name
            && uint(field(selected,"offset_bits")?)? == offset*8
            && uint(field(selected,"width_bits")?)? == u64::from(*bits)
            && list(field(selected,"flags")?)?.is_empty()
            && graph.compatible(field_id,graph.resolve(field(selected,"type")?)?,false,budget)?, CODE)?;
    }
    byte_array(types,typ)?;
    // Qualified source types are globally valid declarations, but not part of
    // the exact unqualified helper/profile contract. Retain their real hash.
    if list(field(typ,"qualifiers")?)?.is_empty() {
        remember(&mut coverage.nodes,identifier,budget)?;
        remember(&mut coverage.states,identifier,budget)?;
    }
    Ok(())
}

pub(super) fn verify_all(graph: &Graph, types: &TypeFacts, budget: &mut Budget) -> Result<Coverage, Error> {
    let mut coverage = Coverage::default();
    for (identifier, typ) in &graph.types {
        budget.work(1)?;
        let source = field(typ,"identity")?;
        if text(field(source,"linkage")?)? == "builtin"
            && matches!(text(field(source,"entity")?)?, "rax.va_state" | "rax.jmp_state") {
            state(graph,types,*identifier,&mut coverage,budget)?;
        }
    }
    // Array wrappers are recognized through ACTUAL checked child source nodes.
    // Unrelated array declarations remain outside coverage, not semantic errors.
    for (identifier,typ) in &graph.types {
        budget.work(1)?;
        if text(field(typ,"kind")?)? != "array" { continue; }
        let elements = list(field(typ,"elements")?)?;
        if elements.len() != 1 { continue; }
        let child = graph.resolve(&elements[0])?;
        if !coverage.states.contains(&child) { continue; }
        // These are ordinary source arrays, not separately reserved identities.
        // A valid array-of-two/qualified/other-language form is outside this
        // profile, not malformed just because its element is a builtin state.
        let source=field(typ,"identity")?;
        if text(field(source,"language")?)? != "c23"
            || text(field(source,"linkage")?)? != "builtin"
            || text(field(source,"entity")?)? != "array"
            || optional(field(source,"library")?)?.is_some()
            || optional(field(source,"unit")?)?.is_some()
            || !list(field(typ,"qualifiers")?)?.is_empty()
            || !list(field(typ,"methods")?)?.is_empty()
            || !list(field(typ,"enumerators")?)?.is_empty()
            || boolean(field(typ,"signed")?)?
            || !exact_flags(typ,FLAGS)?
            || uint(field(typ,"bits")?)? != 0
            || optional(field(typ,"extent")?)?.map(uint).transpose()? != Some(1)
            || optional(field(typ,"record_input")?)?.is_some()
            || text(field(typ,"representation")?)? != "value"
            || text(field(graph.domain(typ)?,"isa")?)? != "portable" { continue; }
        let layout=graph.layout_id(*identifier)?;
        geometry(layout,32,8)?;
        if !list(field(layout,"fields")?)?.is_empty() { continue; }
        let actual=execution(types,typ)?;
        require(matches!(actual, TypeKind::Array { count:1, .. }),CODE)?;
        if let TypeKind::Array { element,.. } = actual {
            let source_execution=optional(field(graph.typ_id(child)?,"execution")?)?
                .ok_or_else(|| Error::semantic(CODE,"child state transport"))?;
            require(types.type_equivalent(types.type_handle(*element)?,types.type_reference(source_execution)?,budget)?,CODE)?;
        }
        remember(&mut coverage.nodes,*identifier,budget)?;
        remember(&mut coverage.wrappers,*identifier,budget)?;
    }
    Ok(coverage)
}
