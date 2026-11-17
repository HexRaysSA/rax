//! Fallible ABI record access and precharged owned projections.

use crate::{Error, limits::Budget, wire::RecordValue};
use std::collections::BTreeMap;

pub(crate) fn require(condition: bool, code: &'static str) -> Result<(), Error> {
    if condition {
        Ok(())
    } else {
        Err(Error::semantic(code, "portable ABI"))
    }
}

pub(crate) fn record(value: &RecordValue) -> Result<&BTreeMap<String, RecordValue>, Error> {
    match value {
        RecordValue::Record(value) => Ok(value),
        _ => Err(Error::semantic("ABI_CC_RECORD", "expected ABI record")),
    }
}

pub(crate) fn field<'a>(value: &'a RecordValue, name: &str) -> Result<&'a RecordValue, Error> {
    record(value)?
        .get(name)
        .ok_or_else(|| Error::semantic("ABI_CC_FIELD", name))
}

pub(crate) fn list(value: &RecordValue) -> Result<&[RecordValue], Error> {
    match value {
        RecordValue::Vector(value) => Ok(value),
        _ => Err(Error::semantic("ABI_CC_LIST", "expected ABI vector")),
    }
}

pub(crate) fn text(value: &RecordValue) -> Result<&str, Error> {
    match value {
        RecordValue::Text(value) => Ok(value),
        _ => Err(Error::semantic("ABI_CC_TEXT", "expected ABI text")),
    }
}

pub(crate) fn uint(value: &RecordValue) -> Result<u64, Error> {
    match value {
        RecordValue::Unsigned(value) => Ok(*value),
        _ => Err(Error::semantic(
            "ABI_CC_UNSIGNED",
            "expected ABI unsigned integer",
        )),
    }
}

pub(crate) fn id(value: &RecordValue) -> Result<u32, Error> {
    u32::try_from(uint(value)?).map_err(|_| Error::semantic("ABI_CC_ID", "ID exceeds u32"))
}

pub(crate) fn sint(value: &RecordValue) -> Result<i64, Error> {
    match value {
        RecordValue::Signed(value) => Ok(*value),
        _ => Err(Error::semantic(
            "ABI_CC_SIGNED",
            "expected ABI signed integer",
        )),
    }
}

pub(crate) fn boolean(value: &RecordValue) -> Result<bool, Error> {
    match value {
        RecordValue::Boolean(value) => Ok(*value),
        _ => Err(Error::semantic("ABI_CC_BOOLEAN", "expected ABI boolean")),
    }
}

pub(crate) fn optional(value: &RecordValue) -> Result<Option<&RecordValue>, Error> {
    match value {
        RecordValue::Option(value) => Ok(value.as_deref()),
        _ => Err(Error::semantic(
            "ABI_CC_OPTION",
            "expected explicit ABI option",
        )),
    }
}

pub(crate) fn bytes(value: &RecordValue) -> Result<&[u8], Error> {
    match value {
        RecordValue::Bytes(value) => Ok(value),
        _ => Err(Error::semantic("ABI_CC_BYTES", "expected ABI bytes")),
    }
}

pub(crate) fn flags(value: &RecordValue, name: &str, flag: &str) -> Result<bool, Error> {
    for value in list(field(value, name)?)? {
        if text(value)? == flag {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Conservatively precharge a bounded projection before cloning it. The 512-B
/// per-node reservation includes tree/vector/string bookkeeping and spare room;
/// this is deterministic verification accounting, not an allocator measurement.
pub(crate) fn owned(value: &RecordValue, budget: &mut Budget) -> Result<RecordValue, Error> {
    fn visit(value: &RecordValue, depth: usize, budget: &mut Budget) -> Result<(), Error> {
        require(depth <= 128, "ABI_CC_DEPTH")?;
        budget.work(1)?;
        budget.reserve_bytes(512)?;
        match value {
            RecordValue::Text(value) => budget.reserve_bytes(value.len())?,
            RecordValue::Bytes(value) => budget.reserve_bytes(value.len())?,
            RecordValue::Vector(values) => {
                budget.edges(values.len())?;
                for value in values {
                    visit(value, depth + 1, budget)?;
                }
            }
            RecordValue::Record(values) => {
                budget.edges(values.len())?;
                for (key, value) in values {
                    budget.reserve_bytes(key.len())?;
                    visit(value, depth + 1, budget)?;
                }
            }
            RecordValue::Option(Some(value)) => visit(value, depth + 1, budget)?,
            _ => {}
        }
        Ok(())
    }
    visit(value, 0, budget)?;
    Ok(value.clone())
}
