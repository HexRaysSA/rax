//! Checked projections of the frozen ordered records, without runtime authority.

use std::collections::BTreeMap;

use crate::context::{boolean, field, list, optional, text, unsigned};
use crate::error::Error;
use crate::limits::Budget;
use crate::wire::RecordValue;

pub(super) fn require(condition: bool, code: &'static str) -> Result<(), Error> {
    if condition {
        Ok(())
    } else {
        Err(Error::semantic(code, "execution"))
    }
}

pub(super) fn number(value: &RecordValue, name: &str) -> Result<u64, Error> {
    unsigned(field(value, name)?)
}

pub(super) fn identifier(value: &RecordValue, name: &str) -> Result<u32, Error> {
    u32::try_from(number(value, name)?).map_err(|_| Error::semantic("reference", name))
}

pub(super) fn token<'a>(value: &'a RecordValue, name: &str) -> Result<&'a str, Error> {
    text(field(value, name)?)
}

pub(super) fn sequence<'a>(value: &'a RecordValue, name: &str) -> Result<&'a [RecordValue], Error> {
    list(field(value, name)?)
}

pub(super) fn flag(value: &RecordValue, name: &str) -> Result<bool, Error> {
    boolean(field(value, name)?)
}

pub(super) fn option<'a>(
    value: &'a RecordValue,
    name: &str,
) -> Result<Option<&'a RecordValue>, Error> {
    optional(field(value, name)?)
}

/// The encoded reference is syntax. DEP identifiers name consumer declarations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Reference {
    Local(u32),
    Dependency { slot: u32, declaration: u32 },
}

impl Reference {
    pub(super) fn is_dependency(self) -> bool {
        matches!(self, Self::Dependency { .. })
    }
}

pub(super) fn reference(value: &RecordValue) -> Result<Reference, Error> {
    let id = identifier(value, "id")?;
    let module = field(value, "module")?;
    match token(module, "kind")? {
        "self" => Ok(Reference::Local(id)),
        "dependency" => Ok(Reference::Dependency {
            slot: identifier(module, "slot")?,
            declaration: id,
        }),
        _ => Err(Error::semantic("reference", "module kind")),
    }
}

pub(super) fn local_reference(value: &RecordValue) -> Result<u32, Error> {
    match reference(value)? {
        Reference::Local(id) => Ok(id),
        Reference::Dependency { .. } => Err(Error::semantic("reference_self", "execution")),
    }
}

pub(super) fn ordered<'a>(
    values: &'a [RecordValue],
    key: &str,
    budget: &mut Budget,
) -> Result<BTreeMap<u32, &'a RecordValue>, Error> {
    budget.reserve_bytes(
        values
            .len()
            .checked_mul(96)
            .ok_or_else(|| Error::resource("reference_resource", "index allocation"))?,
    )?;
    let mut result = BTreeMap::new();
    let mut previous = None;
    for value in values {
        budget.work(1)?;
        let id = identifier(value, key)?;
        require(previous.is_none_or(|last| last < id), "duplicate_order")?;
        previous = Some(id);
        result.insert(id, value);
    }
    Ok(result)
}

/// Charge each owned byte/node before cloning immutable source records.
pub(super) fn clone_record(value: &RecordValue, budget: &mut Budget) -> Result<RecordValue, Error> {
    fn charge(value: &RecordValue, budget: &mut Budget) -> Result<(), Error> {
        budget.work(1)?;
        budget.reserve_bytes(std::mem::size_of::<RecordValue>())?;
        match value {
            RecordValue::Bytes(bytes) => budget.reserve_bytes(bytes.len())?,
            RecordValue::Text(text) => budget.reserve_bytes(text.len())?,
            RecordValue::Vector(values) => {
                for child in values {
                    charge(child, budget)?;
                }
            }
            RecordValue::Option(Some(child)) => charge(child, budget)?,
            RecordValue::Record(fields) => {
                for (name, child) in fields {
                    budget.reserve_bytes(name.len().checked_add(768).ok_or_else(|| {
                        Error::resource("reference_resource", "record allocation")
                    })?)?;
                    charge(child, budget)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    charge(value, budget)?;
    Ok(value.clone())
}
