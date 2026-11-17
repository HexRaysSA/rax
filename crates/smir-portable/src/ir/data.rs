//! Lowering of data segments and their relocations.

use std::collections::BTreeMap;

use crate::context::{boolean, bytes, field, list, optional, signed, text, unsigned};
use crate::wire::RecordValue;
use crate::{Error, ErrorClass};

use super::{Relocation, RelocationKind, SegIdx, Segment};

fn unimplemented(what: impl Into<String>) -> Error {
    Error::new(ErrorClass::Unimplemented, "EXEC_UNIMPLEMENTED", what)
}

fn malformed(what: impl Into<String>) -> Error {
    Error::semantic("EXEC_LOWER", what)
}

fn require(condition: bool, what: &str) -> Result<(), Error> {
    if condition {
        Ok(())
    } else {
        Err(malformed(what))
    }
}

fn number(record: &RecordValue, name: &str) -> Result<u32, Error> {
    u32::try_from(unsigned(field(record, name)?)?).map_err(|_| malformed(name))
}

/// Largest initial image of one segment, including its zero fill.
const MAX_SEGMENT_BYTES: u64 = 1 << 30;

/// The module's data: segments in identifier order, the segment each data
/// symbol is defined by, and the relocations to apply.
pub(super) struct Data {
    pub(super) segments: Vec<Segment>,
    /// Segment by data symbol identifier.
    pub(super) symbols: BTreeMap<u32, SegIdx>,
    pub(super) relocations: Vec<Relocation>,
}

fn segments(root: &RecordValue) -> Result<(Vec<Segment>, BTreeMap<u32, SegIdx>), Error> {
    let mut lowered = Vec::new();
    let mut by_id = BTreeMap::new();
    for record in list(field(root, "segments")?)? {
        let initial = bytes(field(record, "initial")?)?;
        let poison = bytes(field(record, "poison")?)?;
        let undef = bytes(field(record, "undef")?)?;
        require(
            poison.len() == initial.len() && undef.len() == initial.len(),
            "segment shadow extent",
        )?;
        let zero_fill = unsigned(field(record, "zero_fill")?)?;
        if initial.len() as u64 + zero_fill > MAX_SEGMENT_BYTES {
            return Err(Error::resource(
                "EXEC_SEGMENT_SIZE",
                "data segment image is too large",
            ));
        }
        let zero_fill = zero_fill as usize;
        // The zero-filled tail has value bits of zero and one shadow for all
        // of its bits.
        let (tail_poison, tail_undef) = match text(field(record, "zero_shadow")?)? {
            "defined" => (0, 0),
            "poison" => (0xff, 0),
            "undef" => (0, 0xff),
            _ => return Err(malformed("segment zero shadow")),
        };
        let extend = |image: &[u8], fill: u8| {
            let mut whole = image.to_vec();
            whole.resize(image.len() + zero_fill, fill);
            whole
        };
        let alignment = unsigned(field(record, "alignment")?)?;
        require(alignment.is_power_of_two(), "segment alignment")?;
        let index = SegIdx(u32::try_from(lowered.len()).map_err(|_| malformed("segment count"))?);
        let previous = by_id.insert(number(record, "id")?, index);
        require(previous.is_none(), "duplicate segment identifier")?;
        lowered.push(Segment {
            alignment,
            mutable: boolean(field(record, "mutable")?)?,
            bits: extend(initial, 0),
            poison: extend(poison, tail_poison),
            undef: extend(undef, tail_undef),
        });
    }
    Ok((lowered, by_id))
}

/// Data symbols defined by a segment of this module.
fn symbols(
    root: &RecordValue,
    segments: &BTreeMap<u32, SegIdx>,
) -> Result<BTreeMap<u32, SegIdx>, Error> {
    let mut result = BTreeMap::new();
    for symbol in list(field(root, "symbols")?)? {
        if text(field(symbol, "kind")?)? != "data" {
            continue;
        }
        let Some(definition) = optional(field(symbol, "definition")?)? else {
            continue;
        };
        if text(field(definition, "kind")?)? == "data" {
            let segment = segments
                .get(&number(definition, "segment")?)
                .ok_or_else(|| malformed("data symbol names an unknown segment"))?;
            result.insert(number(symbol, "id")?, *segment);
        }
    }
    Ok(result)
}

fn relocations(
    root: &RecordValue,
    segments: &[Segment],
    segment_ids: &BTreeMap<u32, SegIdx>,
    symbols: &BTreeMap<u32, SegIdx>,
) -> Result<Vec<Relocation>, Error> {
    if !list(field(root, "constant_initializers")?)?.is_empty() {
        return Err(unimplemented("constant initializer functions"));
    }
    let mut lowered = Vec::new();
    for record in list(field(root, "relocations")?)? {
        if text(field(record, "source_kind")?)? != "data" {
            return Err(unimplemented("relocation in thread-local storage"));
        }
        let segment = *segment_ids
            .get(&number(record, "source")?)
            .ok_or_else(|| malformed("relocation in an unknown segment"))?;
        if !list(field(record, "derivation")?)?.is_empty()
            || !list(field(record, "flags")?)?.is_empty()
            || boolean(field(record, "check_base")?)?
            || optional(field(record, "inrange")?)?.is_some()
        {
            return Err(unimplemented("relocation with a pointer derivation"));
        }
        let width = number(record, "width")?;
        let kind = match text(field(record, "kind")?)? {
            "data_address" => {
                require(width == 8, "data address relocation width")?;
                RelocationKind::DataAddress
            }
            "data_integer" => {
                let bits = number(record, "integer_bits")?;
                require(
                    (1..=64).contains(&bits) && width == bits.div_ceil(8),
                    "data integer relocation width",
                )?;
                RelocationKind::DataInteger { bytes: width }
            }
            other => return Err(unimplemented(format!("relocation kind {other}"))),
        };
        let target_reference = field(record, "target")?;
        if text(field(field(target_reference, "module")?, "kind")?)? != "self" {
            return Err(unimplemented("relocation against a dependency module"));
        }
        let target = *symbols
            .get(&number(target_reference, "id")?)
            .ok_or_else(|| {
                unimplemented("relocation against a symbol with no data definition here")
            })?;
        let offset = unsigned(field(record, "offset")?)?;
        require(
            offset
                .checked_add(u64::from(width))
                .is_some_and(|end| end <= segments[segment.index()].bits.len() as u64),
            "relocation outside its segment",
        )?;
        lowered.push(Relocation {
            segment,
            offset,
            kind,
            target,
            addend: signed(field(record, "addend")?)?,
        });
    }
    Ok(lowered)
}

/// Lower the data roots: symbols (2), segments (4) and relocations (5).
pub(super) fn lower(
    symbol_root: &RecordValue,
    data_root: &RecordValue,
    relocation_root: &RecordValue,
) -> Result<Data, Error> {
    let (segments, segment_ids) = segments(data_root)?;
    let symbols = symbols(symbol_root, &segment_ids)?;
    let relocations = relocations(relocation_root, &segments, &segment_ids, &symbols)?;
    Ok(Data {
        segments,
        symbols,
        relocations,
    })
}
