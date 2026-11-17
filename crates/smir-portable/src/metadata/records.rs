//! Bounded runtime record projections. These are static facts, never addresses.

use crate::context::{boolean, bytes, field, list, optional, text, unsigned};
use crate::error::Error;
use crate::limits::Budget;
use crate::wire::RecordValue;
use std::collections::BTreeMap;

pub(crate) fn require(ok: bool, code: &'static str) -> Result<(), Error> {
    if ok {
        Ok(())
    } else {
        Err(Error::semantic(code, String::new()))
    }
}

pub(crate) fn u32_field(value: &RecordValue, name: &str) -> Result<u32, Error> {
    u32::try_from(unsigned(field(value, name)?)?)
        .map_err(|_| Error::semantic("RT_ID_RANGE", name.to_owned()))
}

pub(crate) fn token<'a>(value: &'a RecordValue, name: &str) -> Result<&'a str, Error> {
    text(field(value, name)?)
}

pub(crate) fn number(value: &RecordValue, name: &str) -> Result<u64, Error> {
    unsigned(field(value, name)?)
}

pub(crate) fn flag(value: &RecordValue, name: &str) -> Result<bool, Error> {
    boolean(field(value, name)?)
}

pub(crate) fn identifier(value: &str) -> Result<(), Error> {
    require(
        !value.is_empty() && !value.as_bytes().contains(&0),
        "RT_LINK_NAME",
    )
}

pub(crate) fn alignment(value: u64) -> bool {
    value.is_power_of_two() && value <= (1_u64 << 63)
}

pub(crate) fn add(a: u64, b: u64, code: &'static str) -> Result<u64, Error> {
    a.checked_add(b)
        .ok_or_else(|| Error::semantic(code, String::new()))
}

/// Index actual records, charging before index allocation. No ID is a provider ID.
pub(crate) fn ordered<'a>(
    records: &'a RecordValue,
    key: &str,
    budget: &mut Budget,
) -> Result<BTreeMap<u32, &'a RecordValue>, Error> {
    let records = list(records)?;
    budget.edges(records.len())?;
    budget.reserve_bytes(
        records
            .len()
            .checked_mul(96)
            .ok_or_else(|| Error::resource("RT_INDEX_RESOURCE", String::new()))?,
    )?;
    let mut result = BTreeMap::new();
    let mut previous = None;
    for record in records {
        budget.work(1)?;
        let id = u32_field(record, key)?;
        require(previous.is_none_or(|prior| prior < id), "RT_LINK_ORDER")?;
        previous = Some(id);
        result.insert(id, record);
    }
    Ok(result)
}

pub(crate) fn optional_number(record: &RecordValue, name: &str) -> Result<Option<u64>, Error> {
    optional(field(record, name)?)?.map(unsigned).transpose()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum StorageKind {
    Data,
    Tls,
}

impl StorageKind {
    pub(crate) fn parse(value: &str) -> Result<Self, Error> {
        match value {
            "data" => Ok(Self::Data),
            "tls" => Ok(Self::Tls),
            _ => Err(Error::semantic("RT_RELOCATION_SOURCE", value.to_owned())),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ZeroShadow {
    Defined,
    Poison,
    Undef,
}

impl ZeroShadow {
    pub(crate) fn parse(value: &str) -> Result<Self, Error> {
        match value {
            "defined" => Ok(Self::Defined),
            "poison" => Ok(Self::Poison),
            "undef" => Ok(Self::Undef),
            _ => Err(Error::semantic("RT_SEGMENT_ZERO_SHADOW", value.to_owned())),
        }
    }
}

#[derive(Debug)]
pub(crate) struct StorageView<'a> {
    pub(crate) id: u32,
    pub(crate) extent: u64,
    pub(crate) alignment: u64,
    pub(crate) mutable: bool,
    pub(crate) initial: &'a [u8],
    pub(crate) poison: &'a [u8],
    pub(crate) undef: &'a [u8],
    pub(crate) zero_fill: u64,
    pub(crate) zero_shadow: ZeroShadow,
}

impl<'a> StorageView<'a> {
    pub(crate) fn parse(value: &'a RecordValue, budget: &mut Budget) -> Result<Self, Error> {
        budget.work(12)?;
        let initial = bytes(field(value, "initial")?)?;
        let poison = bytes(field(value, "poison")?)?;
        let undef = bytes(field(value, "undef")?)?;
        require(
            initial.len() == poison.len() && initial.len() == undef.len(),
            "RT_SEGMENT_SHADOW",
        )?;
        budget.work(
            u64::try_from(initial.len())
                .map_err(|_| Error::resource("RT_SEGMENT_RESOURCE", String::new()))?,
        )?;
        require(
            poison.iter().zip(undef).all(|(a, b)| a & b == 0),
            "RT_SEGMENT_SHADOW",
        )?;
        let zero_fill = number(value, "zero_fill")?;
        let extent = add(initial.len() as u64, zero_fill, "RT_SEGMENT_EXTENT")?;
        let align = number(value, "alignment")?;
        require(alignment(align), "RT_SEGMENT_EXTENT")?;
        Ok(Self {
            id: u32_field(value, "id")?,
            extent,
            alignment: align,
            mutable: flag(value, "mutable")?,
            initial,
            poison,
            undef,
            zero_fill,
            zero_shadow: ZeroShadow::parse(token(value, "zero_shadow")?)?,
        })
    }

    pub(crate) fn range(&self, offset: u64, length: u64) -> Result<StaticBytes<'a>, Error> {
        let end = add(offset, length, "RT_METADATA_EXTENT")?;
        require(end <= self.extent, "RT_METADATA_EXTENT")?;
        let prefix = self.initial.len() as u64;
        // These indices are <= a real slice length, even for enormous symbolic tails.
        let start = offset.min(prefix) as usize;
        let finish = end.min(prefix) as usize;
        Ok(StaticBytes {
            initial: &self.initial[start..finish],
            poison: &self.poison[start..finish],
            undef: &self.undef[start..finish],
            zero_tail_bytes: end.saturating_sub(prefix).min(length),
            zero_tail_shadow: self.zero_shadow,
        })
    }

    pub(crate) fn fully_defined_readonly(&self, budget: &mut Budget) -> Result<bool, Error> {
        budget.work(
            (self.initial.len() as u64)
                .checked_mul(2)
                .ok_or_else(|| Error::resource("RT_METADATA_RESOURCE", String::new()))?,
        )?;
        Ok(!self.mutable
            && self.poison.iter().all(|v| *v == 0)
            && self.undef.iter().all(|v| *v == 0)
            && (self.zero_fill == 0 || self.zero_shadow == ZeroShadow::Defined))
    }
}

#[derive(Debug)]
pub(crate) struct StaticBytes<'a> {
    pub(crate) initial: &'a [u8],
    pub(crate) poison: &'a [u8],
    pub(crate) undef: &'a [u8],
    pub(crate) zero_tail_bytes: u64,
    pub(crate) zero_tail_shadow: ZeroShadow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PatchInterval {
    pub(crate) kind: StorageKind,
    pub(crate) source: u32,
    pub(crate) start: u64,
    pub(crate) end: u64,
}

impl PatchInterval {
    pub(crate) fn new(
        kind: StorageKind,
        source: u32,
        start: u64,
        length: u64,
        extent: u64,
    ) -> Result<Self, Error> {
        require(length > 0, "RT_PATCH_EXTENT")?;
        let end = add(start, length, "RT_PATCH_EXTENT")?;
        require(end <= extent, "RT_RELOCATION_BOUNDS")?;
        Ok(Self {
            kind,
            source,
            start,
            end,
        })
    }

    pub(crate) fn intersects(&self, kind: StorageKind, source: u32, start: u64, end: u64) -> bool {
        self.kind == kind && self.source == source && self.start < end && start < self.end
    }
}

/// O(P log P) time, no pairwise scan. Zero-width patches were rejected at creation.
pub(crate) fn reject_overlaps(
    intervals: &mut [PatchInterval],
    budget: &mut Budget,
) -> Result<(), Error> {
    reject_overlaps_code(intervals, "RT_INITIALIZER_OVERLAP", budget)
}

pub(crate) fn reject_overlaps_code(
    intervals: &mut [PatchInterval],
    code: &'static str,
    budget: &mut Budget,
) -> Result<(), Error> {
    let n = intervals.len();
    let height = if n < 2 {
        0
    } else {
        usize::BITS - (n - 1).leading_zeros()
    };
    let work = (n as u64)
        .checked_mul(u64::from(height) + 1)
        .ok_or_else(|| Error::resource("RT_PATCH_RESOURCE", String::new()))?;
    budget.work(work)?;
    intervals.sort_unstable_by_key(|p| (p.kind, p.source, p.start, p.end));
    for pair in intervals.windows(2) {
        require(
            pair[0].kind != pair[1].kind
                || pair[0].source != pair[1].source
                || pair[0].end <= pair[1].start,
            code,
        )?;
    }
    Ok(())
}
