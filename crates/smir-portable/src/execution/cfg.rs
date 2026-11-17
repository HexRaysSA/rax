//! Activation-local SSA, simultaneous phi and invoke continuation dominance.

use std::collections::{BTreeMap, BTreeSet};

use crate::context::{field, unsigned};
use crate::error::Error;
use crate::limits::Budget;
use crate::wire::RecordValue;

use super::records::{identifier, ordered, require, sequence, token};
use super::{TypeFacts, TypeHandle, TypeKind};

pub(super) struct Definition {
    pub ty: TypeHandle,
    origin: Option<usize>,
    position: i64,
}

pub(super) struct Cfg<'a> {
    pub blocks: Vec<&'a RecordValue>,
    pub indices: BTreeMap<u32, usize>,
    pub definitions: BTreeMap<u32, Definition>,
    pub entry: usize,
    predecessors: Vec<BTreeSet<usize>>,
    dominators: Vec<Vec<u64>>,
}

fn value_id(value: &RecordValue) -> Result<u32, Error> {
    u32::try_from(unsigned(value)?).map_err(|_| Error::semantic("ssa_reference", "value ID"))
}

pub(super) fn targets(term: &RecordValue, budget: &mut Budget) -> Result<Vec<u32>, Error> {
    budget.work(1)?;
    budget.reserve_bytes(32)?;
    let result = match token(term, "op")? {
        "jump" => vec![identifier(term, "target")?],
        "cbranch" => vec![identifier(term, "true")?, identifier(term, "false")?],
        "switch" => {
            let cases = sequence(term, "cases")?;
            budget.reserve_bytes(
                cases
                    .len()
                    .checked_add(1)
                    .and_then(|n| n.checked_mul(4))
                    .ok_or_else(|| Error::resource("reference_resource", "switch edges"))?,
            )?;
            let mut result = vec![identifier(term, "default")?];
            for case in cases {
                budget.work(1)?;
                result.push(identifier(case, "target")?);
            }
            result
        }
        "invoke" => vec![
            identifier(field(term, "normal")?, "target")?,
            identifier(field(term, "unwind")?, "target")?,
        ],
        "indirect_branch" => {
            let values = sequence(term, "targets")?;
            budget.reserve_bytes(
                values
                    .len()
                    .checked_mul(4)
                    .ok_or_else(|| Error::resource("reference_resource", "indirect edges"))?,
            )?;
            values.iter().map(value_id).collect::<Result<_, _>>()?
        }
        _ => Vec::new(),
    };
    budget.edges(result.len())?;
    Ok(result)
}

pub(super) fn uses(node: &RecordValue, budget: &mut Budget) -> Result<Vec<u32>, Error> {
    let members = crate::context::record(node)?;
    let count = members
        .get("operands")
        .map(crate::context::list)
        .transpose()?
        .map_or(0, |v| v.len());
    budget.reserve_bytes(
        count
            .checked_add(8)
            .and_then(|n| n.checked_mul(16))
            .ok_or_else(|| Error::resource("reference_resource", "SSA uses"))?,
    )?;
    let mut values = Vec::new();
    if let Some(operands) = members.get("operands") {
        for value in crate::context::list(operands)? {
            budget.work(1)?;
            values.push(value_id(value)?);
        }
    }
    match token(node, "op")? {
        "cbranch" => values.push(identifier(node, "condition")?),
        "switch" => values.push(identifier(node, "index")?),
        "indirect_branch" => values.push(identifier(node, "address")?),
        "return" => {
            let returns = sequence(node, "values")?;
            budget.reserve_bytes(
                returns
                    .len()
                    .checked_mul(4)
                    .ok_or_else(|| Error::resource("reference_resource", "return uses"))?,
            )?;
            for value in returns {
                budget.work(1)?;
                values.push(value_id(value)?);
            }
        }
        _ => {}
    }
    if let Some(exception) = members.get("exception") {
        match exception {
            RecordValue::Unsigned(_) => values.push(value_id(exception)?),
            RecordValue::Option(Some(value)) => values.push(value_id(value)?),
            RecordValue::Option(None) => {}
            _ => return Err(Error::semantic("exception_value", "exception operand")),
        }
    }
    for name in ["target", "helper"] {
        if let Some(RecordValue::Record(target)) = members.get(name) {
            if target
                .get("kind")
                .and_then(|value| crate::context::text(value).ok())
                == Some("indirect")
            {
                values.push(value_id(
                    target
                        .get("value")
                        .ok_or_else(|| Error::semantic("call_target", "indirect value"))?,
                )?);
            }
        }
    }
    Ok(values)
}

impl<'a> Cfg<'a> {
    pub fn build(
        function: &'a RecordValue,
        types: &TypeFacts,
        budget: &mut Budget,
    ) -> Result<Self, Error> {
        let table = ordered(sequence(function, "blocks")?, "id", budget)?;
        require(!table.is_empty(), "cfg_entry")?;
        budget.reserve_bytes(
            table
                .len()
                .checked_mul(256)
                .ok_or_else(|| Error::resource("reference_resource", "CFG tables"))?,
        )?;
        let blocks: Vec<_> = table.values().copied().collect();
        let indices: BTreeMap<_, _> = table
            .keys()
            .copied()
            .enumerate()
            .map(|(index, id)| (id, index))
            .collect();
        let entry = *indices
            .get(&identifier(function, "entry")?)
            .ok_or_else(|| Error::semantic("cfg_entry", "entry"))?;
        let mut predecessors = vec![BTreeSet::new(); blocks.len()];
        let mut successors = vec![Vec::new(); blocks.len()];
        let mut edges = BTreeMap::new();
        for (index, block) in blocks.iter().enumerate() {
            budget.work(1)?;
            let term = field(block, "term")?;
            for target in targets(term, budget)? {
                let target = *indices
                    .get(&target)
                    .ok_or_else(|| Error::semantic("cfg_target", "target"))?;
                budget.reserve_bytes(112)?;
                predecessors[target].insert(index);
                successors[index].push(target);
            }
            if token(term, "op")? == "invoke" {
                let normal = field(term, "normal")?;
                let unwind = field(term, "unwind")?;
                require(
                    identifier(normal, "target")? != identifier(unwind, "target")?,
                    "invoke_edge_alias",
                )?;
                for (edge, is_unwind) in [(normal, false), (unwind, true)] {
                    let target = *indices
                        .get(&identifier(edge, "target")?)
                        .ok_or_else(|| Error::semantic("cfg_target", "invoke target"))?;
                    budget.reserve_bytes(128)?;
                    require(
                        edges.insert(target, (index, edge, is_unwind)).is_none(),
                        "invoke_shared_edge",
                    )?;
                }
            }
        }
        require(
            predecessors[entry].is_empty() && sequence(blocks[entry], "phis")?.is_empty(),
            "entry_predecessor",
        )?;
        for (target, (origin, _, _)) in &edges {
            require(
                predecessors[*target].len() == 1
                    && predecessors[*target].contains(origin)
                    && sequence(blocks[*target], "phis")?.is_empty(),
                "invoke_edge_canonical",
            )?;
        }
        let mut reached = vec![false; blocks.len()];
        let mut pending = vec![entry];
        while let Some(index) = pending.pop() {
            budget.work(1)?;
            if reached[index] {
                continue;
            }
            reached[index] = true;
            budget.reserve_bytes(
                successors[index]
                    .len()
                    .checked_mul(std::mem::size_of::<usize>())
                    .ok_or_else(|| Error::resource("reference_resource", "CFG worklist"))?,
            )?;
            pending.extend(successors[index].iter().copied());
        }
        require(reached.iter().all(|value| *value), "cfg_unreachable")?;
        let words = blocks.len().div_ceil(64);
        budget.reserve_bytes(
            blocks
                .len()
                .checked_add(1)
                .and_then(|n| n.checked_mul(words))
                .and_then(|n| n.checked_mul(8))
                .ok_or_else(|| Error::resource("reference_resource", "dominators"))?,
        )?;
        let mut dominators = vec![vec![u64::MAX; words]; blocks.len()];
        dominators[entry].fill(0);
        dominators[entry][entry / 64] = 1u64 << (entry % 64);
        let mut scratch = vec![u64::MAX; words];
        loop {
            let mut changed = false;
            for block in 0..blocks.len() {
                if block == entry {
                    continue;
                }
                budget.work(words as u64)?;
                scratch.fill(u64::MAX);
                for predecessor in &predecessors[block] {
                    budget.work(words as u64)?;
                    for (output, input) in scratch.iter_mut().zip(&dominators[*predecessor]) {
                        *output &= input;
                    }
                }
                scratch[block / 64] |= 1u64 << (block % 64);
                budget.work(2 * words as u64)?;
                if scratch != dominators[block] {
                    dominators[block].copy_from_slice(&scratch);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        let mut result = Self {
            blocks,
            indices,
            definitions: BTreeMap::new(),
            entry,
            predecessors,
            dominators,
        };
        for param in sequence(function, "params")? {
            result.define(param, None, -1, types, budget)?;
        }
        for (target, (_, edge, is_unwind)) in edges {
            if is_unwind {
                let declaration = field(edge, "exception")?;
                let ty = types.type_reference(field(declaration, "type")?)?;
                require(
                    matches!(types.kind(ty)?, TypeKind::Exception),
                    "invoke_exception_type",
                )?;
                result.define(declaration, Some(target), -2, types, budget)?;
            } else {
                for declaration in sequence(edge, "results")? {
                    result.define(declaration, Some(target), -2, types, budget)?;
                }
            }
        }
        // Collect before uses so forward phi backedges resolve. Definitions
        // become visible according to dominance/position, not record order.
        for index in 0..result.blocks.len() {
            let block = result.blocks[index];
            for phi in sequence(block, "phis")? {
                result.define(field(phi, "result")?, Some(index), -1, types, budget)?;
            }
            let operations = sequence(block, "ops")?;
            for (position, operation) in operations.iter().enumerate() {
                if token(operation, "op")? == "longjmp" {
                    require(
                        position + 1 == operations.len()
                            && token(field(block, "term")?, "op")? == "unreachable",
                        "longjmp_normal_continuation",
                    )?;
                }
                for declaration in sequence(operation, "results")? {
                    result.define(declaration, Some(index), position as i64, types, budget)?;
                }
            }
        }
        result.validate_uses(types, budget)?;
        Ok(result)
    }

    fn define(
        &mut self,
        declaration: &RecordValue,
        origin: Option<usize>,
        position: i64,
        types: &TypeFacts,
        budget: &mut Budget,
    ) -> Result<(), Error> {
        budget.work(1)?;
        let id = identifier(declaration, "id")?;
        let ty = types.type_reference(field(declaration, "type")?)?;
        require(
            !matches!(types.kind(ty)?, TypeKind::Function { .. }),
            "ssa_type",
        )?;
        budget.reserve_bytes(128)?;
        require(
            self.definitions
                .insert(
                    id,
                    Definition {
                        ty,
                        origin,
                        position,
                    },
                )
                .is_none(),
            "ssa_duplicate",
        )
    }

    pub fn value_type(&self, id: u32) -> Result<TypeHandle, Error> {
        self.definitions
            .get(&id)
            .map(|definition| definition.ty)
            .ok_or_else(|| Error::semantic("ssa_reference", id.to_string()))
    }

    pub fn check_use(&self, id: u32, block: usize, position: i64) -> Result<(), Error> {
        let definition = self
            .definitions
            .get(&id)
            .ok_or_else(|| Error::semantic("ssa_reference", id.to_string()))?;
        let valid = match definition.origin {
            None => true,
            Some(origin) if origin == block => definition.position < position,
            Some(origin) => self.dominators[block][origin / 64] & (1 << (origin % 64)) != 0,
        };
        require(valid, "ssa_dominance")
    }

    fn validate_uses(&self, types: &TypeFacts, budget: &mut Budget) -> Result<(), Error> {
        for (index, block) in self.blocks.iter().enumerate() {
            for phi in sequence(block, "phis")? {
                budget.work(1)?;
                let incoming = sequence(phi, "incoming")?;
                require(
                    incoming.len() == self.predecessors[index].len(),
                    "phi_edges",
                )?;
                let mut seen = BTreeSet::new();
                let ty = types.type_reference(field(field(phi, "result")?, "type")?)?;
                for source in incoming {
                    budget.work(1)?;
                    let pred = *self
                        .indices
                        .get(&identifier(source, "predecessor")?)
                        .ok_or_else(|| Error::semantic("phi_edges", "predecessor"))?;
                    budget.reserve_bytes(64)?;
                    require(
                        self.predecessors[index].contains(&pred) && seen.insert(pred),
                        "phi_edges",
                    )?;
                    let id = identifier(source, "value")?;
                    self.check_use(id, pred, sequence(self.blocks[pred], "ops")?.len() as i64)?;
                    require(
                        types.type_equivalent(self.value_type(id)?, ty, budget)?,
                        "phi_type",
                    )?;
                }
            }
            let operations = sequence(block, "ops")?;
            for (position, node) in operations.iter().enumerate() {
                for value in uses(node, budget)? {
                    self.check_use(value, index, position as i64)?;
                }
            }
            for value in uses(field(block, "term")?, budget)? {
                self.check_use(value, index, operations.len() as i64)?;
            }
        }
        Ok(())
    }
}
