//! Explicit physical access layouts. All strides and field offsets are in bits.

use std::collections::{BTreeMap, BTreeSet};

use crate::context::field;
use crate::error::Error;
use crate::limits::Budget;
use crate::wire::RecordValue;

use super::model::{RawMemoryField, RawMemoryLayout, TypeKind};
use super::records::{identifier, local_reference, number, option, ordered, require, sequence};
use super::types::TypeGraph;

pub(super) fn build(
    root: &RecordValue,
    types: &TypeGraph,
    budget: &mut Budget,
) -> Result<BTreeMap<u32, RawMemoryLayout>, Error> {
    let mut layouts = BTreeMap::new();
    for (id, record) in ordered(sequence(root, "memory_layouts")?, "id", budget)? {
        budget.work(1)?;
        let mut fields = Vec::new();
        let source_fields = sequence(record, "fields")?;
        budget.reserve_bytes(
            source_fields
                .len()
                .checked_mul(std::mem::size_of::<RawMemoryField>())
                .ok_or_else(|| Error::resource("reference_resource", "layout fields"))?,
        )?;
        budget.edges(source_fields.len())?;
        for child in source_fields {
            budget.work(1)?;
            fields.push(RawMemoryField {
                value_index: identifier(child, "value_index")?,
                bit_offset: number(child, "bit_offset")?,
                bit_width: number(child, "bit_width")?,
                layout: local_reference(field(child, "layout")?)?,
            });
        }
        let element = option(record, "element")?
            .map(local_reference)
            .transpose()?;
        if element.is_some() {
            budget.edges(1)?;
        }
        budget.reserve_bytes(std::mem::size_of::<RawMemoryLayout>() + 96)?;
        layouts.insert(
            id,
            RawMemoryLayout {
                id,
                execution_type: types.resolve(field(record, "type")?)?,
                size_bytes: number(record, "size")?,
                alignment_bytes: identifier(record, "alignment")?,
                access_bytes: number(record, "access_bytes")?,
                fields,
                element,
                stride_bits: number(record, "stride")?,
            },
        );
    }
    for layout in layouts.values() {
        validate(layout, &layouts, types, budget)?;
    }
    check_finite(&layouts, budget)?;
    Ok(layouts)
}

fn get(layouts: &BTreeMap<u32, RawMemoryLayout>, id: u32) -> Result<&RawMemoryLayout, Error> {
    layouts
        .get(&id)
        .ok_or_else(|| Error::semantic("layout_reference", id.to_string()))
}

fn validate(
    layout: &RawMemoryLayout,
    layouts: &BTreeMap<u32, RawMemoryLayout>,
    types: &TypeGraph,
    budget: &mut Budget,
) -> Result<(), Error> {
    budget.work(1)?;
    require(
        layout.alignment_bytes.is_power_of_two()
            && layout.alignment_bytes <= 1 << 31
            && layout.size_bytes % u64::from(layout.alignment_bytes) == 0
            && layout.access_bytes <= layout.size_bytes,
        "layout_extent",
    )?;
    let node = types.node(layout.execution_type)?;
    let capacity = u128::from(layout.access_bytes) * 8;
    match &node.kind {
        kind if kind.scalar() => {
            if matches!(kind, TypeKind::CodeAddress) {
                require(
                    layout.size_bytes == 8
                        && layout.alignment_bytes == 8
                        && layout.access_bytes == 8,
                    "code_address_layout",
                )?;
            }
            let access = node.width.div_ceil(8);
            require(
                layout.access_bytes == access
                    && layout.fields.is_empty()
                    && layout.element.is_none()
                    && layout.stride_bits == 0,
                "layout_scalar",
            )?;
        }
        TypeKind::Struct { fields } => {
            require(
                fields.len() == layout.fields.len()
                    && layout.element.is_none()
                    && layout.stride_bits == 0
                    && layout.access_bytes == layout.size_bytes,
                "layout_struct",
            )?;
            budget.reserve_bytes(
                fields
                    .len()
                    .checked_mul(32)
                    .ok_or_else(|| Error::resource("reference_resource", "field intervals"))?,
            )?;
            let mut spans = Vec::with_capacity(fields.len());
            for (index, field) in layout.fields.iter().enumerate() {
                budget.work(1)?;
                require(field.value_index as usize == index, "layout_struct")?;
                let child = get(layouts, field.layout)?;
                let expected = *fields
                    .get(index)
                    .ok_or_else(|| Error::semantic("layout_struct", "field index"))?;
                require(
                    types.equivalent(child.execution_type, expected, budget)?,
                    "layout_child_type",
                )?;
                let end = u128::from(field.bit_offset) + u128::from(field.bit_width);
                require(
                    types.node(expected)?.width <= field.bit_width
                        && u128::from(field.bit_width) <= 8 * u128::from(child.access_bytes)
                        && end <= capacity,
                    "layout_field_extent",
                )?;
                spans.push((u128::from(field.bit_offset), end));
            }
            let n = spans.len() as u64;
            budget.work(n.saturating_mul(64 - n.max(1).leading_zeros() as u64))?;
            spans.sort_unstable();
            require(
                spans.windows(2).all(|pair| pair[0].1 <= pair[1].0),
                "layout_overlap",
            )?;
        }
        TypeKind::Array { element, count } | TypeKind::Vector { element, count } => {
            require(layout.fields.is_empty(), "layout_sequence")?;
            let child = get(
                layouts,
                layout
                    .element
                    .ok_or_else(|| Error::semantic("layout_sequence", "missing element"))?,
            )?;
            require(
                types.equivalent(child.execution_type, *element, budget)?,
                "layout_child_type",
            )?;
            if matches!(node.kind, TypeKind::Array { .. }) {
                require(
                    u128::from(layout.stride_bits) == 8 * u128::from(child.size_bytes)
                        && layout.access_bytes == layout.size_bytes,
                    "layout_array_stride",
                )?;
            } else {
                require(
                    layout.stride_bits == types.node(*element)?.width,
                    "layout_vector_stride",
                )?;
                let occupied = u128::from(*count) * u128::from(layout.stride_bits);
                require(
                    u128::from(layout.access_bytes) == occupied.div_ceil(8),
                    "layout_vector_access",
                )?;
            }
            let occupied = u128::from(*count) * u128::from(layout.stride_bits);
            require(
                occupied <= 8 * u128::from(layout.size_bytes),
                "layout_sequence_extent",
            )?;
        }
        _ => {
            return Err(Error::semantic(
                "layout_opaque",
                "opaque/signature memory layout",
            ));
        }
    }
    Ok(())
}

fn check_finite(
    layouts: &BTreeMap<u32, RawMemoryLayout>,
    budget: &mut Budget,
) -> Result<(), Error> {
    budget.reserve_bytes(
        layouts
            .len()
            .checked_mul(256)
            .ok_or_else(|| Error::resource("reference_resource", "layout DFS"))?,
    )?;
    let mut complete = BTreeSet::new();
    let mut active = BTreeSet::new();
    for root in layouts.keys().copied() {
        let mut pending = vec![(root, false)];
        while let Some((id, finish)) = pending.pop() {
            budget.work(1)?;
            if complete.contains(&id) {
                continue;
            }
            if finish {
                active.remove(&id);
                complete.insert(id);
                continue;
            }
            require(active.insert(id), "layout_cycle")?;
            pending.push((id, true));
            let layout = get(layouts, id)?;
            budget.reserve_bytes(
                layout
                    .fields
                    .len()
                    .checked_add(1)
                    .and_then(|n| n.checked_mul(16))
                    .ok_or_else(|| Error::resource("reference_resource", "layout DFS stack"))?,
            )?;
            if let Some(child) = layout.element {
                pending.push((child, false));
            }
            pending.extend(
                layout
                    .fields
                    .iter()
                    .rev()
                    .map(|field| (field.layout, false)),
            );
        }
    }
    Ok(())
}
