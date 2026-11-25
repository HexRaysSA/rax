//! Immutable installed compatibility-database name flags.
//!
//! SDB TAGIDs returned by native APIs are opaque. This parser uses independently
//! checked file extents and string references relative to the string-table tag.

use std::collections::BTreeMap;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[cfg(any(test, all(windows, target_arch = "aarch64")))]
mod executable;
#[cfg(all(windows, target_arch = "aarch64"))]
pub(crate) use executable::ExecutableReply;
#[cfg(windows)]
mod native;

#[cfg(all(windows, target_arch = "aarch64"))]
pub(crate) use native::query_executable;

pub(crate) const EXECUTABLE_REPLY_CAPACITY: usize = 4096;
// Each item is a u32 type and byte length followed by a payload.
pub(crate) const EXECUTABLE_REPLY_GROUP: [u32; 14] = [2, 0, 8, 8, 0, 0, 4, 8, 0, 0, 16, 8, 0, 0];

const MAX_FILE_BYTES: usize = 64 << 20;
const MAX_TAGS: usize = 1_000_000;
const MAX_NAMES: usize = 65_536;
const MAX_NAME_BYTES: usize = 4 << 20;

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
            if entries > MAX_NAMES || names_bytes > MAX_NAME_BYTES {
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

    fn installed_directory(root: &Path) -> io::Result<PathBuf> {
        let root = root.canonicalize()?;
        let directory = root.join("AppPatch").canonicalize()?;
        if !directory.starts_with(&root) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "AppPatch escapes the selected Windows root",
            ));
        }
        Ok(directory)
    }

    fn read_installed_file(directory: &Path, path: &Path, limit: usize) -> io::Result<Vec<u8>> {
        let path = path.canonicalize()?;
        if !path.starts_with(directory) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "installed SDB escapes AppPatch",
            ));
        }
        let file = std::fs::File::open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() > limit as u64 {
            return Err(invalid("installed SDB exceeds regular-file bounds"));
        }
        let mut bytes = Vec::new();
        file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > limit {
            return Err(invalid("installed SDB exceeds its capture byte budget"));
        }
        Ok(bytes)
    }

    pub(crate) fn snapshot(root: &Path, upcase: Arc<[u16]>) -> io::Result<Self> {
        let directory = Self::installed_directory(root)?;
        let bytes =
            Self::read_installed_file(&directory, &directory.join("sysmain.sdb"), MAX_FILE_BYTES)?;
        Self::parse(&bytes, upcase)
    }

    #[cfg(any(windows, test))]
    fn with_installed_lookup(
        mut self,
        root: &Path,
        mut lookup: impl FnMut(&[u16]) -> io::Result<u32>,
    ) -> io::Result<Self> {
        const MAX_UPDATES: usize = 8;
        let directory = Self::installed_directory(root)?;
        let mut updates = Vec::new();
        for entry in std::fs::read_dir(&directory)? {
            let entry = entry?;
            let filename = entry.file_name();
            let lowercase = filename.to_string_lossy().to_ascii_lowercase();
            if let Some(timestamp) = lowercase.strip_suffix(".sysmain.sdb")
                && timestamp.len() == 16
                && timestamp.bytes().all(|byte| byte.is_ascii_hexdigit())
                && entry.file_type()?.is_file()
            {
                updates.push(entry.path());
                if updates.len() > MAX_UPDATES {
                    return Err(invalid("installed SDB update count exceeds eight"));
                }
            }
        }
        updates.sort_unstable();
        let mut remaining = MAX_FILE_BYTES;
        let mut name_bytes = self.flags.keys().map(|name| name.len() * 2).sum::<usize>();
        for path in updates {
            let bytes = Self::read_installed_file(&directory, &path, remaining)?;
            remaining -= bytes.len();
            let update = Self::parse(&bytes, self.upcase.clone())?;
            for name in update.flags.into_keys() {
                let length = name.len() * 2;
                if let std::collections::btree_map::Entry::Vacant(entry) = self.flags.entry(name) {
                    name_bytes += length;
                    entry.insert(0);
                    if self.flags.len() > MAX_NAMES || name_bytes > MAX_NAME_BYTES {
                        return Err(invalid("installed SDB candidate names exceed bounds"));
                    }
                }
            }
        }
        for (name, flags) in &mut self.flags {
            *flags = lookup(name)?;
        }
        Ok(self)
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
