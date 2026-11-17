//! Symbolic source value bits. No buffer or loop scales with array cardinality.

use super::{nominal::Graph, value::*};
use crate::{Error, limits::Budget, wire::RecordValue};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

#[derive(Clone)]
pub(crate) struct Mask {
    bound: u64,
    kind: Kind,
}

#[derive(Clone)]
enum Kind {
    Bits(u64),
    Union(Vec<(u64, Arc<Mask>)>),
    Repeat {
        count: u64,
        stride: u64,
        child: Arc<Mask>,
    },
    Clip {
        width: u64,
        child: Arc<Mask>,
    },
}

fn overflow() -> Error {
    Error::semantic("ABI_CC_MASK_EXTENT", "symbolic bit extent")
}

fn bits(width: u64, budget: &mut Budget) -> Result<Arc<Mask>, Error> {
    budget.reserve_bytes(128)?;
    Ok(Arc::new(Mask {
        bound: width,
        kind: Kind::Bits(width),
    }))
}

pub(crate) fn build(graph: &Graph, root: u32, budget: &mut Budget) -> Result<Arc<Mask>, Error> {
    let mut cache = BTreeMap::<u32, Arc<Mask>>::new();
    let mut active = BTreeSet::new();
    budget.reserve_bytes(128)?;
    let mut stack = vec![(root, false)];
    while let Some((identifier, ready)) = stack.pop() {
        budget.work(1)?;
        if cache.contains_key(&identifier) {
            continue;
        }
        let typ = graph.typ_id(identifier)?;
        let kind = text(field(typ, "kind")?)?;
        let layout = graph.layout_id(identifier)?;
        let extent = uint(field(layout, "size")?)?
            .checked_mul(8)
            .ok_or_else(overflow)?;
        if !ready {
            budget.reserve_bytes(128)?;
            require(active.insert(identifier), "ABI_CC_VALUE_CYCLE")?;
            stack.push((identifier, true));
            let mut push = |reference: &RecordValue| -> Result<(), Error> {
                budget.edges(1)?;
                budget.reserve_bytes(16)?;
                stack.push((graph.resolve(reference)?, false));
                Ok(())
            };
            if matches!(kind, "atomic" | "array" | "vector" | "complex") {
                let children = list(field(typ, "elements")?)?;
                require(children.len() == 1, "ABI_CC_ELEMENT_TYPE")?;
                push(&children[0])?;
            } else if kind == "record" {
                for category in ["fields", "bases"] {
                    for entry in list(field(layout, category)?)? {
                        push(field(entry, "type")?)?;
                    }
                }
            }
            continue;
        }
        active.remove(&identifier);
        let mut children = Vec::new();
        let value =
            match kind {
                "atomic_flag" => bits(1, budget)?,
                "scalar" | "bitint" | "enum" | "pointer" | "reference" | "member_pointer"
                | "handle" | "snapshot" => bits(uint(field(typ, "bits")?)?, budget)?,
                "atomic" => {
                    let child = graph.resolve(&list(field(typ, "elements")?)?[0])?;
                    Arc::clone(
                        cache
                            .get(&child)
                            .ok_or_else(|| Error::semantic("ABI_CC_MASK_GRAPH", "atomic child"))?,
                    )
                }
                "array" | "vector" | "complex" => {
                    let child = graph.resolve(&list(field(typ, "elements")?)?[0])?;
                    let child =
                        Arc::clone(cache.get(&child).ok_or_else(|| {
                            Error::semantic("ABI_CC_MASK_GRAPH", "aggregate child")
                        })?);
                    let stride = uint(field(
                        graph.layout(&list(field(typ, "elements")?)?[0])?,
                        "size",
                    )?)?
                    .checked_mul(8)
                    .ok_or_else(overflow)?;
                    let count = if kind == "complex" {
                        2
                    } else {
                        uint(optional(field(typ, "extent")?)?.ok_or_else(|| {
                            Error::semantic("ABI_CC_INCOMPLETE_VALUE", "mask count")
                        })?)?
                    };
                    require(stride > 0, "ABI_CC_MASK_EXTENT")?;
                    let bound = if count == 0 {
                        0
                    } else {
                        (count - 1)
                            .checked_mul(stride)
                            .and_then(|n| n.checked_add(child.bound))
                            .ok_or_else(overflow)?
                    };
                    budget.reserve_bytes(128)?;
                    if matches!(child.kind,Kind::Bits(width)if width==stride) {
                        bits(count.checked_mul(stride).ok_or_else(overflow)?, budget)?
                    } else {
                        Arc::new(Mask {
                            bound,
                            kind: Kind::Repeat {
                                count,
                                stride,
                                child,
                            },
                        })
                    }
                }
                "record" => {
                    let fields = list(field(layout, "fields")?)?;
                    let bases = list(field(layout, "bases")?)?;
                    let vptrs = list(field(layout, "vptrs")?)?;
                    let count = fields
                        .len()
                        .checked_add(bases.len())
                        .and_then(|n| n.checked_add(vptrs.len()))
                        .ok_or_else(overflow)?;
                    budget.reserve_bytes(count.checked_mul(64).ok_or_else(overflow)?)?;
                    for entry in fields {
                        budget.work(1)?;
                        let child = graph.resolve(field(entry, "type")?)?;
                        let mut child =
                            Arc::clone(cache.get(&child).ok_or_else(|| {
                                Error::semantic("ABI_CC_MASK_GRAPH", "field child")
                            })?);
                        if flags(entry, "flags", "bitfield")? {
                            let width = uint(field(entry, "width_bits")?)?;
                            budget.reserve_bytes(128)?;
                            child = Arc::new(Mask {
                                bound: child.bound.min(width),
                                kind: Kind::Clip { width, child },
                            });
                        }
                        children.push((uint(field(entry, "offset_bits")?)?, child));
                    }
                    for entry in bases {
                        budget.work(1)?;
                        let adjustment = field(entry, "adjustment")?;
                        require(
                            text(field(adjustment, "kind")?)? == "fixed",
                            "ABI_CC_MASK_DYNAMIC_LAYOUT",
                        )?;
                        let offset = u64::try_from(sint(field(adjustment, "offset")?)?)
                            .map_err(|_| overflow())?
                            .checked_mul(8)
                            .ok_or_else(overflow)?;
                        let child = graph.resolve(field(entry, "type")?)?;
                        children.push((
                            offset,
                            Arc::clone(cache.get(&child).ok_or_else(|| {
                                Error::semantic("ABI_CC_MASK_GRAPH", "base child")
                            })?),
                        ));
                    }
                    for entry in vptrs {
                        children.push((
                            uint(field(entry, "offset")?)?
                                .checked_mul(8)
                                .ok_or_else(overflow)?,
                            bits(64, budget)?,
                        ));
                    }
                    let mut bound = 0;
                    for (offset, child) in &children {
                        bound = bound.max(offset.checked_add(child.bound).ok_or_else(overflow)?);
                    }
                    budget.reserve_bytes(128)?;
                    Arc::new(Mask {
                        bound,
                        kind: Kind::Union(children),
                    })
                }
                _ => return Err(Error::semantic("ABI_CC_NOT_OBJECT", "logical source mask")),
            };
        require(value.bound <= extent, "ABI_CC_MASK_EXTENT")?;
        budget.reserve_bytes(128)?;
        cache.insert(identifier, value);
    }
    cache
        .remove(&root)
        .ok_or_else(|| Error::semantic("ABI_CC_MASK_GRAPH", "root mask"))
}

impl Mask {
    /// Test an interval without enumerating repeated elements. At most three
    /// representative child intervals are visited per repeat node.
    pub(crate) fn any(&self, start: u64, end: u64, budget: &mut Budget) -> Result<bool, Error> {
        budget.reserve_bytes(128)?;
        let mut stack = vec![(self, start, end)];
        while let Some((node, start, end)) = stack.pop() {
            budget.work(1)?;
            if start >= end || start >= node.bound {
                continue;
            }
            let mut push = |node, start, end| -> Result<(), Error> {
                if stack.len() == stack.capacity() {
                    let extra = stack.capacity().max(8);
                    budget.reserve_bytes(extra.checked_mul(32).ok_or_else(overflow)?)?;
                    stack
                        .try_reserve_exact(extra)
                        .map_err(|_| Error::resource("ABI_CC_MASK_RESOURCE", "interval stack"))?;
                }
                stack.push((node, start, end));
                Ok(())
            };
            match &node.kind {
                Kind::Bits(width) => {
                    if start < *width {
                        return Ok(true);
                    }
                }
                Kind::Clip { width, child } => push(child.as_ref(), start, end.min(*width))?,
                Kind::Union(children) => {
                    for (offset, child) in children {
                        if end > *offset {
                            push(child.as_ref(), start.saturating_sub(*offset), end - *offset)?;
                        }
                    }
                }
                Kind::Repeat {
                    count,
                    stride,
                    child,
                } => {
                    if *count == 0 {
                        continue;
                    }
                    let first = start / stride;
                    if first >= *count {
                        continue;
                    }
                    let last = ((end - 1) / stride).min(count - 1);
                    if first == last {
                        push(child.as_ref(), start - first * stride, end - first * stride)?;
                    } else {
                        push(child.as_ref(), start - first * stride, *stride)?;
                        push(child.as_ref(), 0, end - last * stride)?;
                        if last > first + 1 {
                            push(child.as_ref(), 0, *stride)?;
                        }
                    }
                }
            }
        }
        Ok(false)
    }

    /// End of the consecutive value-bit run beginning at start. Repeats are
    /// handled algebraically, never by iterating count. Complex unions have a
    /// structural iteration bound and reject Resource rather than guess.
    fn run_end(&self, start: u64, depth: u32, budget: &mut Budget) -> Result<u64, Error> {
        budget.work(1)?;
        if depth >= 128 {
            return Err(Error::resource(
                "ABI_CC_MASK_RESOURCE",
                "symbolic query depth",
            ));
        }
        if start >= self.bound {
            return Ok(start);
        }
        match &self.kind {
            Kind::Bits(width) => Ok(if start < *width { *width } else { start }),
            Kind::Clip { width, child } => {
                if start >= *width {
                    Ok(start)
                } else {
                    Ok(child.run_end(start, depth + 1, budget)?.min(*width))
                }
            }
            Kind::Repeat {
                count,
                stride,
                child,
            } => {
                let index = start / stride;
                if index >= *count {
                    return Ok(start);
                }
                let end = child.run_end(start % stride, depth + 1, budget)?;
                if end < *stride {
                    return Ok(index * stride + end);
                }
                if index + 1 == *count {
                    return Ok(count * stride);
                }
                let prefix = child.run_end(0, depth + 1, budget)?;
                if prefix >= *stride {
                    Ok(count * stride)
                } else {
                    Ok((index + 1) * stride + prefix)
                }
            }
            Kind::Union(children) => {
                let mut end = start;
                let limit = children
                    .len()
                    .checked_mul(2)
                    .and_then(|n| n.checked_add(1))
                    .ok_or_else(overflow)?;
                for _ in 0..limit {
                    let previous = end;
                    for (offset, child) in children {
                        budget.work(1)?;
                        if end >= *offset {
                            end = end.max(
                                offset
                                    .checked_add(child.run_end(end - offset, depth + 1, budget)?)
                                    .ok_or_else(overflow)?,
                            );
                        }
                    }
                    if end == previous {
                        return Ok(end);
                    }
                }
                Err(Error::resource(
                    "ABI_CC_MASK_RESOURCE",
                    "union symbolic closure",
                ))
            }
        }
    }

    pub(crate) fn all(&self, start: u64, end: u64, budget: &mut Budget) -> Result<bool, Error> {
        Ok(start >= end || self.run_end(start, 0, budget)? >= end)
    }
}

pub(crate) struct ComparisonMask {
    source: Arc<Mask>,
    offset: u64,
    width: u64,
    bytes: u64,
}

impl ComparisonMask {
    pub(crate) fn new(source: Arc<Mask>, offset: u64, width: u64, bytes: u64) -> Self {
        Self {
            source,
            offset,
            width,
            bytes,
        }
    }
    pub(crate) fn matches(&self, mask: &[u8], budget: &mut Budget) -> Result<bool, Error> {
        if u64::try_from(mask.len()).ok() != Some(self.bytes) {
            return Ok(false);
        }
        let bits = self.bytes.checked_mul(8).ok_or_else(overflow)?;
        budget.work(bits)?;
        for (index, byte) in mask.iter().enumerate() {
            let mut expected = 0u8;
            for bit in 0..8 {
                let position = (index as u64) * 8 + bit;
                if position < self.width
                    && self.source.any(
                        self.offset.checked_add(position).ok_or_else(overflow)?,
                        self.offset.checked_add(position + 1).ok_or_else(overflow)?,
                        budget,
                    )?
                {
                    expected |= 1 << bit;
                }
            }
            if *byte != expected {
                return Ok(false);
            }
        }
        Ok(true)
    }
}
