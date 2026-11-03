//! Exact UTF-16 software-policy names and immutable native query results.
//! ProductPolicy supplies names, not authoritative values: native handlers can
//! override the bytes or return an error for an existing registry entry.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::user::windows::nt::status::{STATUS_BUFFER_TOO_SMALL, STATUS_OBJECT_NAME_NOT_FOUND};

const MAX_BLOB: usize = 8 << 20;
const MAX_ENTRIES: usize = 4096;
const MAX_VALUE: usize = 1 << 20;
const MAX_TOTAL: usize = 16 << 20;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Value {
    pub(super) kind: u32,
    pub(super) data: Arc<[u8]>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Catalog {
    values: BTreeMap<Vec<u16>, Result<Value, u32>>,
}

impl Catalog {
    #[cfg(test)]
    pub(crate) fn fixture(entries: impl IntoIterator<Item = (&'static str, u32, Vec<u8>)>) -> Self {
        Self {
            values: entries
                .into_iter()
                .map(|(name, kind, data)| {
                    (
                        name.encode_utf16().collect(),
                        Ok(Value {
                            kind,
                            data: data.into(),
                        }),
                    )
                })
                .collect(),
        }
    }

    pub(super) fn value(&self, name: &[u16]) -> Result<&Value, u32> {
        self.values
            .get(name)
            .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?
            .as_ref()
            .map_err(|status| *status)
    }
}

fn u16_at(bytes: &[u8], at: usize) -> Result<u16, String> {
    Ok(u16::from_le_bytes(
        bytes
            .get(at..at + 2)
            .ok_or("truncated policy catalog word")?
            .try_into()
            .unwrap(),
    ))
}

fn u32_at(bytes: &[u8], at: usize) -> Result<u32, String> {
    Ok(u32::from_le_bytes(
        bytes
            .get(at..at + 4)
            .ok_or("truncated policy catalog length")?
            .try_into()
            .unwrap(),
    ))
}

/// Parse only host-declared names. Entry padding is not a source of values.
fn names(bytes: &[u8]) -> Result<BTreeSet<Vec<u16>>, String> {
    if !(24..=MAX_BLOB).contains(&bytes.len())
        || u32_at(bytes, 0)? as usize != bytes.len()
        || u32_at(bytes, 12)? != 0
        || u32_at(bytes, 16)? != 1
    {
        return Err("unsupported native ProductPolicy header or size".into());
    }
    let payload = u32_at(bytes, 4)? as usize;
    let trailer = u32_at(bytes, 8)? as usize;
    if 20usize
        .checked_add(payload)
        .and_then(|n| n.checked_add(trailer))
        != Some(bytes.len())
    {
        return Err("native ProductPolicy extents disagree".into());
    }
    let end = 20 + payload;
    let mut at = 20;
    let mut result = BTreeSet::new();
    while at < end {
        if end - at < 16 || result.len() >= MAX_ENTRIES {
            return Err("native ProductPolicy entry count or header exceeds bounds".into());
        }
        let size = usize::from(u16_at(bytes, at)?);
        let name_bytes = usize::from(u16_at(bytes, at + 2)?);
        let data_bytes = usize::from(u16_at(bytes, at + 6)?);
        if size < 16
            || size % 4 != 0
            || size > end - at
            || name_bytes == 0
            || name_bytes % 2 != 0
            || 16 + name_bytes + data_bytes > size
        {
            return Err("native ProductPolicy entry extent is invalid".into());
        }
        let name: Vec<_> = bytes[at + 16..at + 16 + name_bytes]
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        if name.contains(&0) || !result.insert(name) {
            return Err("native ProductPolicy name is empty, duplicated, or contains NUL".into());
        }
        at += size;
    }
    Ok(result)
}

/// Capture fixed host names before guest execution. No guest name, pointer,
/// class, or length is accepted by this acquisition interface.
#[cfg(any(windows, test))]
fn capture_with(
    names: &BTreeSet<Vec<u16>>,
    mut query: impl FnMut(&[u16], &mut [u8], &mut u32, &mut u32) -> u32,
) -> Result<Catalog, String> {
    if names.len() > MAX_ENTRIES {
        return Err("native software policy name count exceeds bounds".into());
    }
    let mut values = BTreeMap::new();
    let mut total = 0usize;
    for name in names {
        let mut captured = None;
        for _ in 0..3 {
            let (mut kind, mut required) = (u32::MAX, 0);
            let status = query(name, &mut [], &mut kind, &mut required);
            if status != 0 && status != STATUS_BUFFER_TOO_SMALL {
                let (mut verify_kind, mut verify_size) = (u32::MAX, 0);
                if query(name, &mut [], &mut verify_kind, &mut verify_size) == status {
                    captured = Some(Err(status));
                    break;
                }
                continue;
            }
            let size = required as usize;
            if size > MAX_VALUE || status == STATUS_BUFFER_TOO_SMALL && size == 0 {
                return Err("native software policy value size exceeds bounds".into());
            }
            let mut first = vec![0xA5; size];
            let mut second = vec![0x5A; size];
            let (mut first_kind, mut first_size) = (u32::MAX, 0);
            let (mut second_kind, mut second_size) = (0, 0);
            let a = query(name, &mut first, &mut first_kind, &mut first_size);
            let b = query(name, &mut second, &mut second_kind, &mut second_size);
            if a == 0
                && b == 0
                && first_size == required
                && second_size == required
                && first_kind == second_kind
                && first == second
            {
                captured = Some(Ok(Value {
                    kind: first_kind,
                    data: first.into(),
                }));
                break;
            }
        }
        let entry = captured.ok_or(
            "native software policy changed or left undefined bytes during bounded capture",
        )?;
        total = total
            .checked_add(name.len() * 2)
            .and_then(|n| n.checked_add(entry.as_ref().map_or(0, |value| value.data.len())))
            .ok_or("native software policy total overflow")?;
        if total > MAX_TOTAL {
            return Err("native software policy catalog exceeds total size bound".into());
        }
        values.insert(name.clone(), entry);
    }
    Ok(Catalog { values })
}

#[cfg(windows)]
mod installed;

#[cfg(windows)]
pub(crate) use installed::capture;

#[cfg(not(windows))]
pub(crate) fn capture() -> Result<Arc<Catalog>, String> {
    Err("native software policy inputs require a Windows host".into())
}

#[cfg(test)]
mod tests;
