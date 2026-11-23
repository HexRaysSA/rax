//! Immutable base compatibility-database name flags; no guest host operation.
//!
//! SDB TAGIDs returned by native APIs are opaque. This parser uses independently
//! checked file extents and string references relative to the string-table tag.

use std::collections::BTreeMap;
use std::io::{self, Read};
use std::path::Path;
use std::sync::Arc;

const MAX_FILE_BYTES: usize = 64 << 20;
const MAX_TAGS: usize = 1_000_000;
const MAX_NAMES: usize = 65_536;

#[derive(Clone, Debug, Default)]
pub(crate) struct Catalog {
    flags: BTreeMap<Vec<u16>, u32>,
    upcase: Arc<[u16]>,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[derive(Clone, Copy)]
struct Tag<'a> {
    kind: u16,
    offset: usize,
    payload: &'a [u8],
}

struct Tags<'a> {
    remaining: &'a [u8],
    offset: usize,
}

impl<'a> Iterator for Tags<'a> {
    type Item = io::Result<Tag<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining.is_empty() {
            return None;
        }
        let parsed = (|| {
            let bytes = self.remaining;
            let kind = u16::from_le_bytes(
                bytes
                    .get(..2)
                    .ok_or_else(|| invalid("truncated SDB tag"))?
                    .try_into()
                    .unwrap(),
            );
            let (header, length): (usize, usize) = match kind >> 12 {
                1 => (2, 0),
                2 => (2, 1),
                3 => (2, 2),
                4 | 6 => (2, 4),
                5 => (2, 8),
                7..=9 => (
                    6,
                    u32::from_le_bytes(
                        bytes
                            .get(2..6)
                            .ok_or_else(|| invalid("truncated SDB extent"))?
                            .try_into()
                            .unwrap(),
                    ) as usize,
                ),
                _ => return Err(invalid("unknown SDB tag type")),
            };
            let end = header
                .checked_add(length)
                .ok_or_else(|| invalid("SDB extent overflow"))?;
            let payload = bytes
                .get(header..end)
                .ok_or_else(|| invalid("SDB tag exceeds its owner"))?;
            let result = Tag {
                kind,
                offset: self.offset,
                payload,
            };
            // Version3 byte/binary data may have odd length. Its payload
            // excludes the arbitrary pad byte before the next 2-byte tag.
            let next = end
                .checked_add(1)
                .ok_or_else(|| invalid("SDB padded extent overflow"))?
                & !1;
            self.remaining = bytes
                .get(next..)
                .ok_or_else(|| invalid("truncated SDB alignment padding"))?;
            self.offset += next;
            Ok(result)
        })();
        if parsed.is_err() {
            self.remaining = &[];
        }
        Some(parsed)
    }
}

impl<'a> Tag<'a> {
    fn children(self) -> Tags<'a> {
        Tags {
            remaining: self.payload,
            offset: self.offset + 6,
        }
    }

    fn number(self) -> u32 {
        u32::from_le_bytes(self.payload.try_into().unwrap())
    }
}

fn validate(tags: Tags<'_>, depth: usize, count: &mut usize) -> io::Result<()> {
    if depth > 32 {
        return Err(invalid("SDB nesting exceeds 32 lists"));
    }
    for tag in tags {
        let tag = tag?;
        *count += 1;
        if *count > MAX_TAGS {
            return Err(invalid("SDB tag count exceeds bounds"));
        }
        if tag.kind >> 12 == 7 {
            validate(tag.children(), depth + 1, count)?;
        }
    }
    Ok(())
}

impl Catalog {
    fn fold(&self, units: &[u16]) -> Vec<u16> {
        units
            .iter()
            .map(|&unit| self.upcase[usize::from(unit)])
            .collect()
    }

    pub(crate) fn lookup(&self, name: &[u16]) -> u32 {
        if self.flags.is_empty() {
            return 0;
        }
        self.flags.get(&self.fold(name)).copied().unwrap_or(0)
    }

    pub(crate) fn observed_names(&self) -> impl Iterator<Item = &[u16]> {
        self.flags.keys().map(Vec::as_slice)
    }

    /// O(B + E*log(S) + E*L*log(E+1)) work and O(B + E*L) storage for B
    /// bytes, S table strings, E flagged entries and L maximum name units.
    pub(crate) fn parse(bytes: &[u8], upcase: Arc<[u16]>) -> io::Result<Self> {
        if bytes.len() > MAX_FILE_BYTES
            || bytes.get(..12) != Some(b"\x03\0\0\0\0\0\0\0sdbf")
            || upcase.len() != 65_536
        {
            return Err(invalid("invalid SDB header, size or upcase table"));
        }
        validate(
            Tags {
                remaining: &bytes[12..],
                offset: 12,
            },
            0,
            &mut 0,
        )?;
        let roots = Tags {
            remaining: &bytes[12..],
            offset: 12,
        }
        .collect::<io::Result<Vec<_>>>()?;
        let unique = |kind| -> io::Result<Tag<'_>> {
            let mut found = roots.iter().copied().filter(|tag| tag.kind == kind);
            let tag = found
                .next()
                .ok_or_else(|| invalid("SDB lacks database or string table"))?;
            if found.next().is_some() {
                return Err(invalid("duplicate SDB database or string table"));
            }
            Ok(tag)
        };
        let database = unique(0x7001)?;
        let table = unique(0x7801)?;
        let strings = table.children().collect::<io::Result<Vec<_>>>()?;
        if strings.iter().any(|tag| {
            tag.kind != 0x8801
                || tag.payload.len() < 2
                || tag.payload.len() % 2 != 0
                || !tag.payload.ends_with(&[0, 0])
        }) {
            return Err(invalid("invalid SDB string-table item"));
        }
        let mut result = Self {
            flags: BTreeMap::new(),
            upcase,
        };
        let mut names_bytes = 0usize;
        let mut entries = 0usize;
        for entry in database.children() {
            let entry = entry?;
            if entry.kind != 0x7007 {
                continue;
            }
            let (mut name, mut flags) = (None, None);
            for child in entry.children() {
                let child = child?;
                let slot = match child.kind {
                    0x6001 => &mut name,
                    0x4032 => &mut flags,
                    _ => continue,
                };
                if slot.replace(child.number()).is_some() {
                    return Err(invalid("duplicate SDB name or compatibility flags"));
                }
            }
            let Some(flags) = flags else { continue };
            let reference = name.ok_or_else(|| invalid("flagged SDB entry lacks a name"))?;
            let offset = table
                .offset
                .checked_add(reference as usize)
                .ok_or_else(|| invalid("SDB string reference overflow"))?;
            let index = strings
                .binary_search_by_key(&offset, |tag| tag.offset)
                .map_err(|_| invalid("SDB string reference is not an item boundary"))?;
            let text = strings[index].payload;
            if text.len() > 65_534 || text.len() == 2 {
                return Err(invalid("SDB name length exceeds bounds"));
            }
            entries += 1;
            names_bytes += text.len();
            if entries > MAX_NAMES || names_bytes > 4 << 20 {
                return Err(invalid("SDB names exceed bounds"));
            }
            let units: Vec<_> = text[..text.len() - 2]
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes(pair.try_into().unwrap()))
                .collect();
            let key = result.fold(&units);
            *result.flags.entry(key).or_default() |= flags;
        }
        Ok(result)
    }

    pub(crate) fn snapshot(root: &Path, upcase: Arc<[u16]>) -> io::Result<Self> {
        let root = root.canonicalize()?;
        let directory = root.join("AppPatch").canonicalize()?;
        let path = directory.join("sysmain.sdb").canonicalize()?;
        if !directory.starts_with(&root) || !path.starts_with(&directory) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "installed SDB escapes the selected Windows root",
            ));
        }
        let file = std::fs::File::open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() > MAX_FILE_BYTES as u64 {
            return Err(invalid("installed SDB exceeds regular-file bounds"));
        }
        let mut bytes = Vec::new();
        file.take(MAX_FILE_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        Self::parse(&bytes, upcase)
    }

    #[cfg(test)]
    pub(crate) fn fixture(entries: &[(&str, u32)]) -> Self {
        let upcase: Arc<[u16]> = (0..=u16::MAX)
            .map(|unit| {
                if unit >= u16::from(b'a') && unit <= u16::from(b'z') {
                    unit - 32
                } else {
                    unit
                }
            })
            .collect::<Vec<_>>()
            .into();
        let mut result = Self {
            flags: BTreeMap::new(),
            upcase,
        };
        for (name, value) in entries {
            result.flags.insert(
                result.fold(&name.encode_utf16().collect::<Vec<_>>()),
                *value,
            );
        }
        result
    }
}

#[cfg(test)]
mod tests;
