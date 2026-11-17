//! Source views, actual physical effects and derived symbolic value masks.

use super::{
    layout::{alignment, gcd},
    mask::{self, ComparisonMask},
    nominal::{Graph, self_id},
    value::*,
};
use crate::{Error, execution::TypeFacts, limits::Budget, wire::RecordValue};

pub(super) fn verify(
    graph: &Graph,
    types: &TypeFacts,
    binding: &RecordValue,
    budget: &mut Budget,
) -> Result<Option<ComparisonMask>, Error> {
    budget.work(1)?;
    let reference = field(binding, "nominal")?;
    let source = graph.layout(reference)?;
    let physical =
        types.layout(types.layout_handle(self_id(field(binding, "execution_layout")?)?)?)?;
    let kind = text(field(binding, "kind")?)?;
    require(
        ["allocation", "object_bytes", "fieldwise", "bit_container"].contains(&kind),
        "ABI_CC_STORAGE_VIEW",
    )?;
    let source_size = uint(field(source, "size")?)?;
    let source_align = uint(field(source, "align")?)?;
    let required = uint(field(binding, "required_alignment")?)?;
    alignment(required)?;
    let access = uint(field(binding, "access_bytes")?)?;
    require(
        required <= source_align
            && access == physical.access_bytes
            && access <= physical.size_bytes,
        "ABI_CC_STORAGE_ACCESS",
    )?;
    let start = uint(field(binding, "view_offset_bits")?)?;
    let width = uint(field(binding, "view_width_bits")?)?;
    let end = start
        .checked_add(width)
        .ok_or_else(|| Error::semantic("ABI_CC_STORAGE_VIEW_EXTENT", "source view overflow"))?;
    require(
        width > 0 && source_size.checked_mul(8).is_some_and(|size| end <= size),
        "ABI_CC_STORAGE_VIEW_EXTENT",
    )?;
    require(
        start % 8 == 0 && required <= gcd(source_align, start / 8),
        "ABI_CC_STORAGE_VIEW_ALIGNMENT",
    )?;
    let fragments = list(field(binding, "fragments")?)?;
    if matches!(kind, "allocation" | "object_bytes") {
        require(
            start == 0 && width == source_size * 8 && physical.size_bytes == source_size,
            "ABI_CC_STORAGE_ALLOCATION",
        )?;
    }
    if kind == "allocation" {
        require(fragments.len() == 1, "ABI_CC_STORAGE_ALLOCATION_FRAGMENT")?;
        let fragment = &fragments[0];
        require(
            list(field(fragment, "source_path")?)?.is_empty()
                && uint(field(fragment, "source_offset_bits")?)? == 0
                && uint(field(fragment, "execution_offset_bits")?)? == 0
                && uint(field(fragment, "width_bits")?)? == width
                && text(field(fragment, "role")?)? == "object_representation",
            "ABI_CC_STORAGE_ALLOCATION_FRAGMENT",
        )?;
        return Ok(None);
    }
    let effect_end = start
        .checked_add(
            access.checked_mul(8).ok_or_else(|| {
                Error::semantic("ABI_CC_STORAGE_EFFECT_RANGE", "physical bit span")
            })?,
        )
        .ok_or_else(|| Error::semantic("ABI_CC_STORAGE_EFFECT_RANGE", "physical bit endpoint"))?;
    require(effect_end <= source_size * 8, "ABI_CC_STORAGE_EFFECT_RANGE")?;
    let source_mask = mask::build(graph, graph.resolve(reference)?, budget)?;
    if effect_end > end {
        require(
            !source_mask.any(end, effect_end, budget)?,
            "ABI_CC_STORAGE_EFFECT_VALUE_CLOBBER",
        )?;
    }
    budget.reserve_bytes(
        fragments
            .len()
            .checked_mul(48)
            .ok_or_else(|| Error::resource("ABI_CC_STORAGE_RESOURCE", "fragment intervals"))?,
    )?;
    let mut intervals = Vec::new();
    for fragment in fragments {
        budget.work(1)?;
        let role = text(field(fragment, "role")?)?;
        require(
            ["value", "padding", "base", "vptr"].contains(&role),
            "ABI_CC_STORAGE_FRAGMENT_ROLE",
        )?;
        let src = uint(field(fragment, "source_offset_bits")?)?;
        let dst = uint(field(fragment, "execution_offset_bits")?)?;
        let count = uint(field(fragment, "width_bits")?)?;
        let src_end = src.checked_add(count).ok_or_else(|| {
            Error::semantic("ABI_CC_STORAGE_FRAGMENT_EXTENT", "source fragment endpoint")
        })?;
        let dst_end = dst.checked_add(count).ok_or_else(|| {
            Error::semantic(
                "ABI_CC_STORAGE_FRAGMENT_EXTENT",
                "physical fragment endpoint",
            )
        })?;
        require(
            count > 0
                && start <= src
                && src_end <= end
                && physical
                    .size_bytes
                    .checked_mul(8)
                    .is_some_and(|size| dst_end <= size),
            "ABI_CC_STORAGE_FRAGMENT_EXTENT",
        )?;
        require(dst == src - start, "ABI_CC_STORAGE_POSITION")?;
        if role == "padding" {
            require(
                !source_mask.any(src, src_end, budget)?,
                "ABI_CC_STORAGE_VALUE_AS_PADDING",
            )?;
        } else {
            require(dst_end <= access * 8, "ABI_CC_STORAGE_EFFECT_EXTENT")?;
            require(
                source_mask.all(src, src_end, budget)?,
                "ABI_CC_STORAGE_VALUE_COVERAGE",
            )?;
        }
        let path = list(field(fragment, "source_path")?)?;
        if !path.is_empty() {
            let mut current = graph.resolve(reference)?;
            let mut offset = 0u64;
            let mut bound = source_size * 8;
            for component in path {
                let name = text(component)?;
                let layout = graph.layout_id(current)?;
                let mut found = None;
                for candidate in list(field(layout, "fields")?)? {
                    budget.work(1)?;
                    if text(field(candidate, "name")?)? == name {
                        require(found.is_none(), "ABI_CC_STORAGE_SOURCE_PATH")?;
                        found = Some(candidate);
                    }
                }
                let selected = found.ok_or_else(|| {
                    Error::semantic("ABI_CC_STORAGE_SOURCE_PATH", "field path missing")
                })?;
                offset = offset
                    .checked_add(uint(field(selected, "offset_bits")?)?)
                    .ok_or_else(|| Error::semantic("ABI_CC_STORAGE_SOURCE_PATH", "path offset"))?;
                bound = uint(field(selected, "width_bits")?)?;
                current = graph.resolve(field(selected, "type")?)?;
            }
            require(
                offset <= src && offset.checked_add(bound).is_some_and(|end| src_end <= end),
                "ABI_CC_STORAGE_SOURCE_PATH",
            )?;
        }
        intervals.push((src, src_end));
    }
    let units = fragments
        .len()
        .checked_mul((usize::BITS - fragments.len().max(1).leading_zeros()) as usize)
        .ok_or_else(|| Error::resource("ABI_CC_STORAGE_RESOURCE", "interval sort"))?;
    budget.work(units as u64)?;
    intervals.sort_unstable();
    let mut cursor = start;
    for (begin, finish) in intervals {
        require(begin >= cursor, "ABI_CC_STORAGE_FRAGMENT_OVERLAP")?;
        require(
            !source_mask.any(cursor, begin, budget)?,
            "ABI_CC_STORAGE_VALUE_COVERAGE",
        )?;
        cursor = finish;
    }
    require(
        !source_mask.any(cursor, end, budget)?,
        "ABI_CC_STORAGE_VALUE_COVERAGE",
    )?;
    Ok(Some(ComparisonMask::new(source_mask, start, width, access)))
}
