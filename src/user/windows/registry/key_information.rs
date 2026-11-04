//! Immutable native key records. Class7 is per-key-body mutable state and is
//! deliberately absent. No native handle or callback survives acquisition.
use super::*;

pub(crate) const NLS_CUSTOM_LOCALE_KEY: &str =
    "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Nls\\CustomLocale";
pub(super) const MAX_RECORD_BYTES: usize = 128 << 10;
const HEADERS: [usize; 9] = [16, 24, 44, 4, 40, 12, 4, 4, 4];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NameTail {
    Raw,
    ZeroOdd,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct KeyInformation {
    records: [Vec<u8>; 9],
    tails: [NameTail; 2],
    enumeration: Option<Vec<BasicChild>>,
}

pub(crate) struct InformationTree {
    pub(crate) tree: KeyTree,
    pub(crate) information: BTreeMap<Vec<u16>, KeyInformation>,
}

fn word(bytes: &[u8], offset: usize) -> usize {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("validated header"),
    ) as usize
}

impl KeyInformation {
    pub(crate) fn new(records: [Vec<u8>; 9], tails: [NameTail; 2]) -> io::Result<Self> {
        for (class, record) in records.iter().enumerate() {
            if class == 7 {
                if !record.is_empty() {
                    return Err(invalid("key-body tags cannot be immutable metadata"));
                }
            } else if record.len() < HEADERS[class] || record.len() > MAX_RECORD_BYTES {
                return Err(invalid("native key record exceeds bounded layout"));
            }
        }
        for class in [0, 1] {
            let record = &records[class];
            let length = word(record, if class == 0 { 12 } else { 20 });
            if length == 0 || length % 2 != 0 || length > record.len() - HEADERS[class] {
                return Err(invalid("native key record name exceeds returned bytes"));
            }
            if class == 0 && record.len() != 16 + length {
                return Err(invalid("native basic key record has trailing bytes"));
            }
        }
        for class in [1, 2] {
            let record = &records[class];
            let length = word(record, 16);
            let offset = word(record, 12);
            if length % 2 != 0
                || length != 0
                    && (offset < HEADERS[class]
                        || offset > record.len()
                        || length > record.len() - offset)
            {
                return Err(invalid("native key class string exceeds returned bytes"));
            }
        }
        let name = &records[3];
        let length = word(name, 0);
        if length % 2 != 0 || length != name.len() - 4 || length > 2 * 32_767 {
            return Err(invalid("native canonical key name exceeds returned bytes"));
        }
        for class in [4, 5, 6, 8] {
            if records[class].len() != HEADERS[class] {
                return Err(invalid("native fixed key record has an unknown layout"));
            }
        }
        if [1, 2, 4]
            .iter()
            .any(|&class| records[class][..8] != records[0][..8])
        {
            return Err(invalid(
                "native key record timestamps changed during capture",
            ));
        }
        let result = Self {
            records,
            tails,
            enumeration: None,
        };
        let canonical = result.canonical();
        if canonical.first() != Some(&92)
            || canonical.get(1) == Some(&92)
            || canonical.last() == Some(&92)
            || canonical.contains(&0)
            || canonical.windows(2).any(|pair| pair == [92, 92])
        {
            return Err(invalid("native canonical key name has invalid grammar"));
        }
        Ok(result)
    }

    pub(crate) fn record(&self, class: u32) -> Option<&[u8]> {
        self.records
            .get(class as usize)
            .filter(|r| !r.is_empty())
            .map(Vec::as_slice)
    }

    pub(super) fn with_enumeration(mut self, children: Vec<BasicChild>) -> Self {
        self.enumeration = Some(children);
        self
    }

    pub(crate) fn minimum(class: u32) -> Option<usize> {
        HEADERS.get(class as usize).copied()
    }

    pub(crate) fn zero_partial_name_tail(&self, class: u32, length: usize) -> bool {
        if class > 1 || self.tails[class as usize] != NameTail::ZeroOdd {
            return false;
        }
        let class = class as usize;
        let offset = HEADERS[class];
        let name_bytes = word(&self.records[class], if class == 0 { 12 } else { 20 });
        offset < length && length < offset + name_bytes && (length - offset) % 2 != 0
    }

    pub(super) fn bytes(&self) -> usize {
        self.records.iter().map(Vec::len).sum()
    }

    pub(super) fn canonical(&self) -> Vec<u16> {
        self.records[3][4..]
            .chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect()
    }

    pub(super) fn check_contents(&self, key: &Key) -> io::Result<()> {
        if word(&self.records[2], 20) != key.children as usize
            || word(&self.records[2], 32) != key.values.len()
            || word(&self.records[4], 12) != key.children as usize
            || word(&self.records[4], 20) != key.values.len()
        {
            return Err(invalid("native key records contradict captured contents"));
        }
        let canonical = self.canonical();
        let name = canonical.rsplit(|u| *u == 92).next().unwrap_or_default();
        for class in [0, 1] {
            let offset = HEADERS[class];
            let length = word(&self.records[class], if class == 0 { 12 } else { 20 });
            let basic: Vec<_> = self.records[class][offset..offset + length]
                .chunks_exact(2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .collect();
            if key.fold(&basic) != key.fold(name) {
                return Err(invalid("native key record names disagree"));
            }
        }
        Ok(())
    }
}

impl Key {
    pub(crate) fn information(&self) -> Option<&KeyInformation> {
        self.information.as_deref()
    }
}

fn same_subject(key: &Key, logical: &[u16], canonical: &[u16]) -> bool {
    let logical = key.fold(logical);
    let canonical = key.fold(canonical);
    let left: Vec<_> = logical.split(|u| *u == 92).collect();
    let right: Vec<_> = canonical.split(|u| *u == 92).collect();
    left.len() == right.len()
        && left.iter().zip(right).all(|(a, b)| {
            *a == b
                || *a == "CURRENTCONTROLSET".encode_utf16().collect::<Vec<_>>()
                    && b.len() > 10
                    && b[..10] == "CONTROLSET".encode_utf16().collect::<Vec<_>>()
                    && b[10..].iter().all(|u| (48..=57).contains(u))
        })
}

pub(super) fn attach(
    key: &mut Arc<Key>,
    information: &mut BTreeMap<Vec<u16>, KeyInformation>,
    values: &mut ValueBudget,
    paths: &mut tree::TreeBudget,
    parent: Option<&[u16]>,
) -> io::Result<()> {
    let key = Arc::get_mut(key).ok_or_else(|| invalid("key metadata was shared before binding"))?;
    let mut record = information
        .remove(&key.path)
        .ok_or_else(|| invalid("captured key metadata is incomplete"))?;
    record.check_contents(key)?;
    let canonical = record.canonical();
    if !same_subject(key, &key.path, &canonical)
        || parent.is_some_and(|parent| {
            canonical.get(parent.len()) != Some(&92)
                || canonical.len() <= parent.len() + 1
                || key.fold(&canonical[..parent.len()]) != key.fold(parent)
                || canonical[parent.len() + 1..].contains(&92)
        })
    {
        return Err(invalid("canonical key alias is outside fixed selection"));
    }
    values.charge_information(&record)?;
    paths.charge_alias(&canonical)?;
    key.enumeration = super::key_enumeration::bounded(
        &key.upcase,
        record.enumeration.take(),
        key.children,
        values,
    )?;
    if key.children != 0 && key.enumeration.is_none() {
        return Err(invalid("complete key metadata lacks ordered children"));
    }
    key.logical_path = Some(std::mem::replace(&mut key.path, canonical).into());
    key.information = Some(Arc::new(record));
    if let Some(children) = &mut key.subkeys {
        for child in children.values_mut() {
            attach(child, information, values, paths, Some(&key.path))?;
        }
        if let Some(entries) = &key.enumeration {
            for entry in entries.iter() {
                let folded: Vec<_> = entry
                    .name
                    .iter()
                    .map(|&u| key.upcase[usize::from(u)])
                    .collect();
                let child = children
                    .get(&folded)
                    .ok_or_else(|| invalid("ordered key metadata names an uncaptured child"))?;
                let record = child
                    .information
                    .as_ref()
                    .ok_or_else(|| invalid("ordered child lacks captured key metadata"))?;
                let timestamp = u64::from_le_bytes(
                    record.records[0][..8]
                        .try_into()
                        .expect("validated basic header"),
                );
                if entry.last_write != timestamp {
                    return Err(invalid("child key changed after ordered enumeration"));
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "key_information_tests.rs"]
pub(crate) mod tests;
