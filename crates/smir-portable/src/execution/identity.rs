//! ID-independent SHA-256 of the frozen labeled-bisimulation quotient.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::error::Error;
use crate::limits::Budget;

use super::model::TypeKind;
use super::types::TypeGraph;

fn children(kind: &TypeKind, budget: &mut Budget) -> Result<Vec<u32>, Error> {
    let count = match kind {
        TypeKind::Function {
            params, results, ..
        } => params.len().checked_add(results.len()),
        _ => Some(kind.children(false).len()),
    }
    .ok_or_else(|| Error::resource("reference_resource", "identity edges"))?;
    budget.reserve_bytes(
        count
            .checked_mul(4)
            .ok_or_else(|| Error::resource("reference_resource", "identity edges"))?,
    )?;
    budget.work(count as u64)?;
    Ok(match kind {
        TypeKind::Function {
            params, results, ..
        } => params.iter().chain(results).copied().collect(),
        _ => kind.children(false).to_vec(),
    })
}

fn label(kind: &TypeKind, budget: &mut Budget) -> Result<Value, Error> {
    budget.work(1)?;
    let attributes = match kind {
        TypeKind::Function {
            params, results, ..
        } => params.len().checked_add(results.len()),
        _ => Some(0),
    }
    .ok_or_else(|| Error::resource("reference_resource", "identity label"))?;
    budget.reserve_bytes(
        attributes
            .checked_mul(128)
            .and_then(|n| n.checked_add(4096))
            .ok_or_else(|| Error::resource("reference_resource", "identity label"))?,
    )?;
    Ok(match kind {
        TypeKind::Int(bits) | TypeKind::Raw(bits) => json!({"kind":kind.name(),"bits":bits}),
        TypeKind::Float(format) => json!({"kind":"float","format":format.token()}),
        TypeKind::DataPtr => json!({"kind":"data_ptr","space":"guest_data"}),
        TypeKind::Array { count, .. } | TypeKind::Vector { count, .. } => {
            json!({"kind":kind.name(),"count":count})
        }
        TypeKind::Function {
            params,
            results,
            param_noundef,
            result_noundef,
        } => json!({
            "kind":"function", "cc":"portable", "variadic":false,
            "param_noundef":param_noundef, "result_noundef":result_noundef,
            "parameter_count":params.len(), "result_count":results.len(),
        }),
        _ => json!({"kind":kind.name()}),
    })
}

pub(super) fn type_digest(
    graph: &TypeGraph,
    root: u32,
    budget: &mut Budget,
) -> Result<[u8; 32], Error> {
    let mut pending = vec![root];
    let mut reachable = BTreeSet::new();
    let mut labels = BTreeMap::new();
    let mut edges = BTreeMap::new();
    budget.reserve_bytes(16)?;
    while let Some(id) = pending.pop() {
        budget.work(1)?;
        if reachable.contains(&id) {
            continue;
        }
        budget.reserve_bytes(384)?;
        reachable.insert(id);
        let kind = &graph.node(id)?.kind;
        let child_ids = children(kind, budget)?;
        budget.reserve_bytes(
            child_ids
                .len()
                .checked_mul(4)
                .ok_or_else(|| Error::resource("reference_resource", "identity stack"))?,
        )?;
        pending.extend(child_ids.iter().copied());
        edges.insert(id, child_ids);
        labels.insert(id, label(kind, budget)?);
    }
    // Canonical JSON's sorted object keys and compact separators are identical
    // to the independent Python oracle; only closed ASCII labels occur here.
    let mut strings = BTreeMap::new();
    let mut distinct = BTreeSet::new();
    for (id, label) in &labels {
        budget.work(1)?;
        let bound = 4096usize
            .checked_add(match &graph.node(*id)?.kind {
                TypeKind::Function {
                    params, results, ..
                } => (params.len() + results.len())
                    .checked_mul(8)
                    .ok_or_else(|| Error::resource("reference_resource", "identity JSON"))?,
                _ => 0,
            })
            .ok_or_else(|| Error::resource("reference_resource", "identity JSON"))?;
        budget.reserve_bytes(
            bound
                .checked_mul(2)
                .ok_or_else(|| Error::resource("reference_resource", "identity JSON"))?,
        )?;
        let encoded = serde_json::to_string(label)
            .map_err(|_| Error::semantic("type_identity", "JSON label"))?;
        budget.work(encoded.len() as u64)?;
        distinct.insert(encoded.clone());
        strings.insert(*id, encoded);
    }
    budget.reserve_bytes(
        distinct
            .len()
            .checked_mul(128)
            .ok_or_else(|| Error::resource("reference_resource", "identity classes"))?,
    )?;
    let classes: BTreeMap<_, _> = distinct
        .into_iter()
        .enumerate()
        .map(|(index, label)| (label, index))
        .collect();
    let mut groups = BTreeMap::new();
    for (id, label) in strings {
        groups.insert(
            id,
            *classes
                .get(&label)
                .ok_or_else(|| Error::semantic("type_identity", "label class"))?,
        );
    }
    loop {
        budget.reserve_bytes(
            reachable
                .len()
                .checked_mul(512)
                .ok_or_else(|| Error::resource("reference_resource", "identity refinement"))?,
        )?;
        let mut signatures = BTreeMap::new();
        let mut distinct = BTreeSet::new();
        for id in &reachable {
            budget.work(1)?;
            let child_ids = edges
                .get(id)
                .ok_or_else(|| Error::semantic("type_identity", "edges"))?;
            budget.reserve_bytes(
                child_ids
                    .len()
                    .checked_mul(24)
                    .ok_or_else(|| Error::resource("reference_resource", "identity signatures"))?,
            )?;
            budget.work(child_ids.len() as u64)?;
            let mut child_groups = Vec::with_capacity(child_ids.len());
            for child in child_ids {
                child_groups.push(
                    *groups
                        .get(child)
                        .ok_or_else(|| Error::semantic("type_identity", "child class"))?,
                );
            }
            let signature = (
                *groups
                    .get(id)
                    .ok_or_else(|| Error::semantic("type_identity", "class"))?,
                child_groups,
            );
            distinct.insert(signature.clone());
            signatures.insert(*id, signature);
        }
        let old_count = groups.values().copied().collect::<BTreeSet<_>>().len();
        let new_count = distinct.len();
        let numbering: BTreeMap<_, _> = distinct
            .into_iter()
            .enumerate()
            .map(|(index, signature)| (signature, index))
            .collect();
        let mut refined = BTreeMap::new();
        for (id, signature) in signatures {
            refined.insert(
                id,
                *numbering
                    .get(&signature)
                    .ok_or_else(|| Error::semantic("type_identity", "refined class"))?,
            );
        }
        groups = refined;
        if old_count == new_count {
            break;
        }
    }
    budget.reserve_bytes(
        reachable
            .len()
            .checked_mul(512)
            .ok_or_else(|| Error::resource("reference_resource", "identity quotient"))?,
    )?;
    let mut representatives = BTreeMap::new();
    for (id, group) in &groups {
        representatives.entry(*group).or_insert(*id);
    }
    let root_group = *groups
        .get(&root)
        .ok_or_else(|| Error::semantic("type_identity", "root class"))?;
    let mut order = vec![root_group];
    let mut indices = BTreeMap::from([(root_group, 0usize)]);
    let mut output = Vec::new();
    let mut position = 0;
    while position < order.len() {
        budget.work(1)?;
        let id = *representatives
            .get(&order[position])
            .ok_or_else(|| Error::semantic("type_identity", "representative"))?;
        let child_ids = edges
            .get(&id)
            .ok_or_else(|| Error::semantic("type_identity", "quotient edges"))?;
        budget.reserve_bytes(
            child_ids
                .len()
                .checked_mul(128)
                .and_then(|n| n.checked_add(1024))
                .ok_or_else(|| Error::resource("reference_resource", "identity output"))?,
        )?;
        let mut children = Vec::new();
        for child in child_ids {
            budget.work(1)?;
            let group = *groups
                .get(child)
                .ok_or_else(|| Error::semantic("type_identity", "quotient child"))?;
            if !indices.contains_key(&group) {
                indices.insert(group, order.len());
                order.push(group);
            }
            children.push(
                *indices
                    .get(&group)
                    .ok_or_else(|| Error::semantic("type_identity", "quotient index"))?,
            );
        }
        output.push(json!({"label":labels.get(&id).ok_or_else(|| Error::semantic("type_identity", "quotient label"))?,"children":children}));
        position += 1;
    }
    let encoded_bound = output.iter().try_fold(0usize, |sum, node| {
        // serde_json serializes only bounded quotient labels and edge indices.
        let object = node
            .as_object()
            .ok_or_else(|| Error::semantic("type_identity", "output record"))?;
        let children = object
            .get("children")
            .and_then(Value::as_array)
            .ok_or_else(|| Error::semantic("type_identity", "output edges"))?;
        sum.checked_add(4096)
            .and_then(|n| n.checked_add(children.len().checked_mul(32)?))
            .ok_or_else(|| Error::resource("reference_resource", "identity encoding"))
    })?;
    // Include boolean signature attributes independently of child edge count.
    let attribute_bound = labels.values().try_fold(0usize, |sum, label| {
        let count = label
            .get("param_noundef")
            .and_then(Value::as_array)
            .map_or(0, Vec::len)
            + label
                .get("result_noundef")
                .and_then(Value::as_array)
                .map_or(0, Vec::len);
        sum.checked_add(
            count
                .checked_mul(8)
                .ok_or_else(|| Error::resource("reference_resource", "identity attrs"))?,
        )
        .ok_or_else(|| Error::resource("reference_resource", "identity attrs"))
    })?;
    budget.reserve_bytes(
        encoded_bound
            .checked_add(attribute_bound)
            .ok_or_else(|| Error::resource("reference_resource", "identity encoding"))?,
    )?;
    let encoded = serde_json::to_vec(&output)
        .map_err(|_| Error::semantic("type_identity", "JSON quotient"))?;
    budget.work(encoded.len() as u64)?;
    let mut hash = Sha256::new();
    hash.update(b"SMIR-TYPE-SHAPE-V1\0");
    hash.update(encoded);
    Ok(hash.finalize().into())
}
