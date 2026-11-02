//! Selection-only capture of complete records for the fixed CustomLocale tree.
//! All output buffers are private/aligned; no guest argument reaches NTDLL.
use super::super::key_information::MAX_RECORD_BYTES;
use super::super::tree::{MAX_TREE_KEYS, TreeBudget, child_path};
use super::super::{InformationTree, KeyInformation, NameTail, TreeRoot};
use super::*;
use std::collections::BTreeMap;

fn native_record(
    key: &OwnedKey,
    class: u32,
    length: usize,
    poison: u8,
) -> io::Result<(u32, u32, Vec<u8>)> {
    if length > MAX_RECORD_BYTES {
        return Err(invalid("native key query scratch exceeds record bound"));
    }
    // u64 storage also bypasses the native x86 unaligned conversion path.
    let mut words = vec![u64::from_le_bytes([poison; 8]); length.div_ceil(8)];
    let mut returned = u32::from_le_bytes([poison; 4]);
    // SAFETY: selection-owned query/enumerate HKEY, fixed metadata selector,
    // exclusive initialized 8-byte-aligned storage of the declared byte length
    // and a separate ULONG output. Neither pointer survives the native call.
    let output = if length == 0 {
        null_mut()
    } else {
        words.as_mut_ptr().cast()
    };
    let status = unsafe { NtQueryKey(key.0, class, output, length as u32, &mut returned) };
    let bytes = words
        .into_iter()
        .flat_map(u64::to_le_bytes)
        .take(length)
        .collect();
    Ok((status as u32, returned, bytes))
}

fn records(key: &OwnedKey) -> io::Result<KeyInformation> {
    let mut records: [Vec<u8>; 9] = std::array::from_fn(|_| Vec::new());
    for class in [0, 1, 2, 3, 4, 5, 6, 8] {
        let (probe_status, required, _) = native_record(key, class, 0, 0xA5)?;
        if probe_status != 0xC000_0023
            || required as usize > MAX_RECORD_BYTES
            || (required as usize) < KeyInformation::minimum(class).expect("fixed native class")
        {
            return Err(invalid(&format!(
                "native key class {class} has an uncaptured required length/status: 0x{probe_status:08X}"
            )));
        }
        let (status, length, first) = native_record(key, class, required as usize, 0xA5)?;
        let (other_status, other_length, second) =
            native_record(key, class, required as usize, 0x5A)?;
        if status != 0
            || other_status != 0
            || length != other_length
            || length != required
            || first[..length as usize] != second[..length as usize]
        {
            return Err(invalid(&format!(
                "native key class {class} lacks a stable fully defined record: 0x{status:08X}"
            )));
        }
        records[class as usize] = first[..length as usize].to_vec();
    }
    let mut tails = [NameTail::Raw; 2];
    for class in 0..2 {
        let offset = if class == 0 { 16 } else { 24 };
        let name_offset = if class == 0 { 12 } else { 20 };
        let record = &records[class];
        let name_bytes = u32::from_le_bytes(
            record[name_offset..name_offset + 4]
                .try_into()
                .expect("native header"),
        ) as usize;
        if name_bytes % 2 != 0 || name_bytes > record.len() - offset {
            return Err(invalid("native key calibration name exceeds record"));
        }
        // A nonzero low UTF-16 byte distinguishes a raw odd prefix from the
        // compressed-name copier's zero final byte. With all low bytes zero,
        // these two plans are observationally identical for every name cut.
        if let Some(index) = (offset..offset + name_bytes)
            .step_by(2)
            .find(|&i| record[i] != 0)
        {
            let length = index + 1;
            let a = native_record(key, class as u32, length, 0xA5)?;
            let b = native_record(key, class as u32, length, 0x5A)?;
            if a != b || a.0 != 0x8000_0005 || a.1 as usize != record.len() {
                return Err(invalid(
                    "native short key record changed during calibration",
                ));
            }
            if a.2 != record[..length] {
                if a.2[..length - 1] != record[..length - 1] || a.2[length - 1] != 0 {
                    return Err(invalid("native key short-copy plan is uncaptured"));
                }
                tails[class] = NameTail::ZeroOdd;
            }
        }
    }
    KeyInformation::new(records, tails)
}

pub(super) fn capture(registry: &Registry) -> io::Result<Option<InformationTree>> {
    capture_with(registry, |path| tree::open(TreeRoot::NlsCustomLocale, path))
}

pub(super) fn capture_with(
    registry: &Registry,
    mut opener: impl FnMut(&[u16]) -> io::Result<OwnedKey>,
) -> io::Result<Option<InformationTree>> {
    let path: Vec<_> = TreeRoot::NlsCustomLocale.path().encode_utf16().collect();
    let key = match opener(&path) {
        Ok(key) => key,
        Err(error) if error.raw_os_error() == Some(2) => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut values = registry.value_budget()?;
    let mut paths = TreeBudget::default();
    let mut information = BTreeMap::new();
    let mut reserved = 1;
    let tree = node(
        path,
        0,
        key,
        &mut values,
        &mut paths,
        &mut reserved,
        &mut information,
        &mut opener,
    )?;
    Ok(Some(InformationTree { tree, information }))
}

#[allow(clippy::too_many_arguments)]
fn node(
    path: Vec<u16>,
    depth: usize,
    key: OwnedKey,
    budget: &mut super::super::ValueBudget,
    paths: &mut TreeBudget,
    reserved: &mut usize,
    information: &mut BTreeMap<Vec<u16>, KeyInformation>,
    opener: &mut impl FnMut(&[u16]) -> io::Result<OwnedKey>,
) -> io::Result<super::super::KeyTree> {
    paths.charge(&path, depth)?;
    let mut selected = None;
    for _ in 0..3 {
        let before = info(&key)?;
        let first = records(&key)?;
        let contents = super::key_enumeration::stable(&key, budget, *reserved)?;
        let second = records(&key)?;
        if before == info(&key)? && first == second {
            selected = Some((contents, first));
            break;
        }
    }
    let ((values, entries), record) =
        selected.ok_or_else(|| invalid("native key metadata changed during bounded snapshot"))?;
    drop(key); // Every native parent closes before any child is opened.
    let names: Vec<_> = entries.iter().map(|entry| entry.name.clone()).collect();
    *reserved = reserved
        .checked_add(names.len())
        .filter(|&n| n <= MAX_TREE_KEYS)
        .ok_or_else(|| invalid("native key metadata child reservation exceeds bounds"))?;
    for value in &values {
        budget.charge(value)?;
    }
    budget.charge_information(&record)?;
    budget.charge_enumeration(&entries)?;
    paths.charge_alias(&record.canonical())?;
    if information
        .insert(path.clone(), record.with_enumeration(entries))
        .is_some()
    {
        return Err(invalid("duplicate native key metadata path"));
    }
    let mut children = Vec::with_capacity(names.len());
    for name in names {
        let next = child_path(&path, &name)?;
        let key = opener(&next)?;
        children.push((
            name,
            node(
                next,
                depth + 1,
                key,
                budget,
                paths,
                reserved,
                information,
                opener,
            )?,
        ));
    }
    Ok(super::super::KeyTree { values, children })
}

#[cfg(test)]
#[path = "key_information_tests.rs"]
mod tests;
