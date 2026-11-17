//! Exact finite type-graph validation and coinductive structural equality.

use std::collections::{BTreeMap, BTreeSet};

use crate::context::{boolean, field};
use crate::error::Error;
use crate::limits::Budget;
use crate::wire::RecordValue;

use super::model::{FloatFormat, OpaqueSet, TypeKind, TypeNode};
use super::records::{
    Reference, clone_record, flag, identifier, local_reference, number, option, ordered, reference,
    require, sequence, token,
};

pub(crate) struct TypeGraph {
    pub(super) nodes: BTreeMap<u32, TypeNode>,
    pub(super) declarations: BTreeMap<(u32, u32), u32>,
}

impl TypeGraph {
    pub(crate) fn logical_bits(&self, id: u32) -> Result<u64, Error> {
        Ok(self.node(id)?.width)
    }

    pub(crate) fn opaque(&self, id: u32) -> Result<OpaqueSet, Error> {
        Ok(self.node(id)?.opaque)
    }

    pub(crate) fn materialization_cost(&self, id: u32) -> Result<u64, Error> {
        Ok(self.node(id)?.value_nodes)
    }

    pub(crate) fn digest(&self, id: u32, budget: &mut Budget) -> Result<[u8; 32], Error> {
        super::identity::type_digest(self, id, budget)
    }

    #[cfg(test)]
    pub(crate) fn check_layouts(
        &self,
        root: &RecordValue,
        budget: &mut Budget,
    ) -> Result<(), Error> {
        super::layout::build(root, self, budget).map(|_| ())
    }
    pub fn build(
        root: &RecordValue,
        symbols: &RecordValue,
        budget: &mut Budget,
    ) -> Result<Self, Error> {
        require(number(root, "payload_revision")? == 2, "revision")?;
        let local = ordered(sequence(root, "types")?, "id", budget)?;
        let mut declarations = BTreeMap::new();
        let manifest = field(symbols, "manifest")?;
        for (slot, dependency) in ordered(sequence(manifest, "dependencies")?, "slot", budget)? {
            for (id, declaration) in ordered(sequence(dependency, "declarations")?, "id", budget)? {
                budget.work(1)?;
                if token(declaration, "kind")? != "type" {
                    continue;
                }
                if let Some(expected) = option(declaration, "execution")? {
                    let target = local_reference(expected)?;
                    require(local.contains_key(&target), "declaration_execution")?;
                    budget.reserve_bytes(96)?;
                    declarations.insert((slot, id), target);
                }
            }
        }
        let resolve = |value: &RecordValue| -> Result<u32, Error> {
            match reference(value)? {
                Reference::Local(id) => {
                    require(local.contains_key(&id), "type_reference")?;
                    Ok(id)
                }
                Reference::Dependency { slot, declaration } => declarations
                    .get(&(slot, declaration))
                    .copied()
                    .ok_or_else(|| Error::semantic("type_reference", "consumer type declaration")),
            }
        };
        let mut nodes = BTreeMap::new();
        for (id, record) in &local {
            budget.work(1)?;
            let refs = |name: &str, budget: &mut Budget| -> Result<Vec<u32>, Error> {
                let values = sequence(record, name)?;
                budget.reserve_bytes(
                    values
                        .len()
                        .checked_mul(4)
                        .ok_or_else(|| Error::resource("reference_resource", "type edges"))?,
                )?;
                budget.edges(values.len())?;
                budget.work(values.len() as u64)?;
                values.iter().map(&resolve).collect()
            };
            let booleans = |name: &str, budget: &mut Budget| -> Result<Vec<bool>, Error> {
                let values = sequence(record, name)?;
                budget.reserve_bytes(values.len())?;
                budget.work(values.len() as u64)?;
                values.iter().map(boolean).collect()
            };
            let kind = match token(record, "kind")? {
                "int" | "raw" => {
                    let bits = identifier(record, "bits")?;
                    require((1..=1 << 23).contains(&bits), "type_width")?;
                    if token(record, "kind")? == "int" {
                        TypeKind::Int(bits)
                    } else {
                        TypeKind::Raw(bits)
                    }
                }
                "float" => TypeKind::Float(match token(record, "format")? {
                    "binary16" => FloatFormat::Binary16,
                    "bfloat16" => FloatFormat::Bfloat16,
                    "binary32" => FloatFormat::Binary32,
                    "binary64" => FloatFormat::Binary64,
                    "binary128" => FloatFormat::Binary128,
                    _ => return Err(Error::semantic("type_float", "format")),
                }),
                "data_ptr" => {
                    require(token(record, "space")? == "guest_data", "type_space")?;
                    TypeKind::DataPtr
                }
                "code_address" => TypeKind::CodeAddress,
                "code_ptr" => {
                    budget.edges(1)?;
                    TypeKind::CodePtr {
                        signature: resolve(field(record, "signature")?)?,
                    }
                }
                "array" | "vector" => {
                    budget.edges(1)?;
                    let element = resolve(field(record, "element")?)?;
                    let count = number(record, "count")?;
                    if token(record, "kind")? == "array" {
                        TypeKind::Array { element, count }
                    } else {
                        TypeKind::Vector { element, count }
                    }
                }
                "struct" => TypeKind::Struct {
                    fields: refs("fields", budget)?,
                },
                "function" => {
                    require(
                        token(record, "cc")? == "portable" && !flag(record, "variadic")?,
                        "calling_convention",
                    )?;
                    let params = refs("params", budget)?;
                    let results = refs("results", budget)?;
                    let param_noundef = booleans("param_noundef", budget)?;
                    let result_noundef = booleans("result_noundef", budget)?;
                    require(
                        params.len() == param_noundef.len()
                            && results.len() == result_noundef.len(),
                        "type_signature",
                    )?;
                    TypeKind::Function {
                        params,
                        results,
                        param_noundef,
                        result_noundef,
                    }
                }
                "exception" => TypeKind::Exception,
                "fenv" => TypeKind::Fenv,
                "stack_mark" => TypeKind::StackMark,
                "va_list" => TypeKind::VaList,
                "journal" => TypeKind::Journal,
                _ => return Err(Error::semantic("type", "unknown type kind")),
            };
            budget.reserve_bytes(
                std::mem::size_of::<TypeNode>()
                    .checked_add(96)
                    .ok_or_else(|| Error::resource("reference_resource", "type index"))?,
            )?;
            nodes.insert(
                *id,
                TypeNode {
                    kind,
                    raw: clone_record(record, budget)?,
                    width: 0,
                    opaque: OpaqueSet::default(),
                    fenv: false,
                    value_nodes: 1,
                },
            );
        }
        let mut graph = Self {
            nodes,
            declarations,
        };
        graph.validate_children(budget)?;
        graph.compute_extents(budget)?;
        Ok(graph)
    }

    pub fn resolve(&self, value: &RecordValue) -> Result<u32, Error> {
        let id = match reference(value)? {
            Reference::Local(id) => id,
            Reference::Dependency { slot, declaration } => *self
                .declarations
                .get(&(slot, declaration))
                .ok_or_else(|| Error::semantic("type_reference", "consumer type declaration"))?,
        };
        require(self.nodes.contains_key(&id), "type_reference")?;
        Ok(id)
    }

    pub(super) fn node(&self, id: u32) -> Result<&TypeNode, Error> {
        self.nodes
            .get(&id)
            .ok_or_else(|| Error::semantic("type_reference", id.to_string()))
    }

    fn validate_children(&self, budget: &mut Budget) -> Result<(), Error> {
        for node in self.nodes.values() {
            budget.work(1)?;
            match &node.kind {
                TypeKind::CodePtr { signature } => require(
                    matches!(self.node(*signature)?.kind, TypeKind::Function { .. }),
                    "type_signature",
                )?,
                TypeKind::Array { element, .. } => require(
                    !matches!(self.node(*element)?.kind, TypeKind::Function { .. }),
                    "type_value",
                )?,
                TypeKind::Vector { element, count } => require(
                    (1..=65535).contains(count) && self.node(*element)?.kind.scalar(),
                    "type_vector",
                )?,
                TypeKind::Struct { fields } => {
                    for child in fields {
                        budget.work(1)?;
                        require(
                            !matches!(self.node(*child)?.kind, TypeKind::Function { .. }),
                            "type_value",
                        )?;
                    }
                }
                TypeKind::Function {
                    params, results, ..
                } => {
                    for child in params.iter().chain(results) {
                        budget.work(1)?;
                        require(
                            !matches!(self.node(*child)?.kind, TypeKind::Function { .. }),
                            "type_signature",
                        )?;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn compute_extents(&mut self, budget: &mut Budget) -> Result<(), Error> {
        // Each non-finished node's by-value children are visited before it. Code
        // pointers/signatures cut storage cycles, but never structural identity.
        budget.reserve_bytes(
            self.nodes
                .len()
                .checked_mul(256)
                .ok_or_else(|| Error::resource("reference_resource", "type DFS"))?,
        )?;
        let mut complete = BTreeSet::new();
        let mut active = BTreeSet::new();
        let mut depths = BTreeMap::<u32, u32>::new();
        let roots: Vec<u32> = self.nodes.keys().copied().collect();
        for root in roots {
            let mut pending = vec![(root, false)];
            while let Some((id, finish)) = pending.pop() {
                budget.work(1)?;
                if complete.contains(&id) {
                    continue;
                }
                let node = self.node(id)?;
                if !finish {
                    require(active.insert(id), "type_cycle")?;
                    pending.push((id, true));
                    let children = node.kind.children(true);
                    budget.reserve_bytes(
                        children
                            .len()
                            .checked_mul(16)
                            .ok_or_else(|| Error::resource("reference_resource", "DFS stack"))?,
                    )?;
                    pending.extend(children.iter().rev().map(|child| (*child, false)));
                    continue;
                }
                let mut depth = 1;
                let mut opaque = 0;
                let mut fenv = false;
                for child in node.kind.children(true) {
                    budget.work(1)?;
                    depth = depth.max(
                        depths
                            .get(child)
                            .copied()
                            .ok_or_else(|| Error::semantic("type_cycle", "child depth"))?
                            .saturating_add(1),
                    );
                    opaque |= self.node(*child)?.opaque.0;
                    fenv |= self.node(*child)?.fenv;
                }
                if depth > 64 {
                    return Err(Error::resource("reference_resource", "by-value type depth"));
                }
                let extent_error =
                    || Error::semantic("type_extent", "logical bit extent exceeds u64");
                let width = match &node.kind {
                    TypeKind::Int(bits) | TypeKind::Raw(bits) => u64::from(*bits),
                    TypeKind::Float(format) => u64::from(format.bits()),
                    TypeKind::DataPtr | TypeKind::CodePtr { .. } | TypeKind::CodeAddress => 64,
                    TypeKind::Array { element, count } | TypeKind::Vector { element, count } => {
                        if *count == 0 {
                            opaque = 0;
                            fenv = false;
                        }
                        count
                            .checked_mul(self.node(*element)?.width)
                            .ok_or_else(extent_error)?
                    }
                    TypeKind::Struct { fields } => {
                        budget.work(fields.len() as u64)?;
                        let mut total = 0u64;
                        for child in fields {
                            total = total
                                .checked_add(self.node(*child)?.width)
                                .ok_or_else(extent_error)?;
                        }
                        total
                    }
                    TypeKind::Exception => {
                        opaque = 1;
                        0
                    }
                    TypeKind::Journal => {
                        opaque = 2;
                        0
                    }
                    TypeKind::StackMark => {
                        opaque = 4;
                        0
                    }
                    TypeKind::VaList => {
                        opaque = 8;
                        0
                    }
                    TypeKind::Fenv => {
                        fenv = true;
                        0
                    }
                    TypeKind::Function { .. } => 0,
                };
                let value_nodes = match &node.kind {
                    TypeKind::Array { element, count } | TypeKind::Vector { element, count } => {
                        1u64.saturating_add(count.saturating_mul(self.node(*element)?.value_nodes))
                            .min(100001)
                    }
                    TypeKind::Struct { fields } => {
                        budget.work(fields.len() as u64)?;
                        let mut count = 1u64;
                        for child in fields {
                            count = count
                                .saturating_add(self.node(*child)?.value_nodes)
                                .min(100001);
                        }
                        count
                    }
                    _ => 1,
                };
                let output = self
                    .nodes
                    .get_mut(&id)
                    .ok_or_else(|| Error::semantic("type_reference", id.to_string()))?;
                output.width = width;
                output.opaque = OpaqueSet(opaque);
                output.fenv = fenv;
                output.value_nodes = value_nodes;
                active.remove(&id);
                complete.insert(id);
                depths.insert(id, depth);
            }
        }
        Ok(())
    }

    /// Coinductive equality of actual deterministic labeled graphs. Neither
    /// numeric IDs nor digests alone establish structural equivalence.
    pub fn equivalent(&self, left: u32, right: u32, budget: &mut Budget) -> Result<bool, Error> {
        budget.reserve_bytes(16)?;
        let mut pending = vec![(left, right)];
        let mut seen = BTreeSet::new();
        while let Some((a, b)) = pending.pop() {
            budget.work(1)?;
            if seen.contains(&(a, b)) {
                continue;
            }
            budget.reserve_bytes(96)?;
            seen.insert((a, b));
            let a = &self.node(a)?.kind;
            let b = &self.node(b)?.kind;
            budget.reserve_bytes(16)?;
            let pairs: Vec<(u32, u32)> = match (a, b) {
                (TypeKind::Int(a), TypeKind::Int(b)) | (TypeKind::Raw(a), TypeKind::Raw(b))
                    if a == b =>
                {
                    Vec::new()
                }
                (TypeKind::Float(a), TypeKind::Float(b)) if a == b => Vec::new(),
                (TypeKind::DataPtr, TypeKind::DataPtr)
                | (TypeKind::CodeAddress, TypeKind::CodeAddress)
                | (TypeKind::Exception, TypeKind::Exception)
                | (TypeKind::Fenv, TypeKind::Fenv)
                | (TypeKind::Journal, TypeKind::Journal)
                | (TypeKind::StackMark, TypeKind::StackMark)
                | (TypeKind::VaList, TypeKind::VaList) => Vec::new(),
                (TypeKind::CodePtr { signature: a }, TypeKind::CodePtr { signature: b }) => {
                    vec![(*a, *b)]
                }
                (
                    TypeKind::Array {
                        element: a,
                        count: ac,
                    },
                    TypeKind::Array {
                        element: b,
                        count: bc,
                    },
                )
                | (
                    TypeKind::Vector {
                        element: a,
                        count: ac,
                    },
                    TypeKind::Vector {
                        element: b,
                        count: bc,
                    },
                ) if ac == bc => vec![(*a, *b)],
                (TypeKind::Struct { fields: a }, TypeKind::Struct { fields: b })
                    if a.len() == b.len() =>
                {
                    budget.reserve_bytes(a.len().checked_mul(8).ok_or_else(|| {
                        Error::resource("reference_resource", "equality edges")
                    })?)?;
                    a.iter().copied().zip(b.iter().copied()).collect()
                }
                (
                    TypeKind::Function {
                        params: ap,
                        results: ar,
                        param_noundef: an,
                        result_noundef: ax,
                    },
                    TypeKind::Function {
                        params: bp,
                        results: br,
                        param_noundef: bn,
                        result_noundef: bx,
                    },
                ) if ap.len() == bp.len() && ar.len() == br.len() && an == bn && ax == bx => {
                    budget.reserve_bytes((ap.len() + ar.len()).checked_mul(8).ok_or_else(
                        || Error::resource("reference_resource", "equality edges"),
                    )?)?;
                    ap.iter()
                        .chain(ar)
                        .copied()
                        .zip(bp.iter().chain(br).copied())
                        .collect()
                }
                _ => return Ok(false),
            };
            budget.edges(pairs.len())?;
            budget.reserve_bytes(
                pending
                    .len()
                    .checked_add(pairs.len())
                    .and_then(|n| n.checked_mul(16))
                    .ok_or_else(|| Error::resource("reference_resource", "equality stack"))?,
            )?;
            pending.extend(pairs);
        }
        Ok(true)
    }
}
