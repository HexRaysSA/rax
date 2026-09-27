//! The resource tree (`.rsrc`): a three-level directory of type, name, and
//! language, whose leaves are data entries (PE specification, "The .rsrc
//! Section"). All offsets inside the tree are relative to the start of the
//! resource directory; data entries hold RVAs.
//!
//! This format-level decoder follows the PE specification's 32-bit Integer
//! ID and case-sensitive name ordering, preserving exact UTF-16 code units.
//! The SDK's `winnt.h` instead declares a 16-bit `Id` union member and describes
//! case-insensitive names. This API does not implement or claim equivalence
//! to the Windows `FindResource` name-matching policy.

use super::{DataDirectory, RvaFault, RvaSource};

/// `RT_MANIFEST`.
pub const RT_MANIFEST: u32 = 24;
/// `RT_STRING`.
pub const RT_STRING: u32 = 6;
/// `RT_VERSION`.
pub const RT_VERSION: u32 = 16;

/// Upper bound on the entries of one directory table.
const MAX_ENTRIES: u32 = 1 << 16;
/// Longest resource name read.
const MAX_NAME: usize = 1024;

/// A resource type, name, or language identifier.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ResId {
    /// An integer identifier.
    Id(u32),
    /// A name, matched by exact UTF-16 code units, without case folding.
    Name(Vec<u16>),
}

/// A leaf of the tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceData {
    /// RVA of the data.
    pub rva: u32,
    /// Size in bytes.
    pub size: u32,
    /// `Codepage`.
    pub codepage: u32,
    /// The language identifier of the leaf.
    pub language: u32,
}

/// One directory entry.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry {
    id: ResId,
    /// Offset (from the tree root) of the subdirectory or data entry.
    target: u32,
    subdirectory: bool,
}

/// The resource tree of an image.
#[derive(Clone, Copy, Debug)]
pub struct ResourceTree {
    range: DataDirectory,
}

impl ResourceTree {
    /// The tree of data directory `range`, if the image has one.
    pub fn new(range: DataDirectory) -> Option<Self> {
        range.is_present().then_some(ResourceTree { range })
    }

    fn entries(
        &self,
        src: &(impl RvaSource + ?Sized),
        offset: u32,
    ) -> Result<Vec<Entry>, RvaFault> {
        let at = self.range.extent_at(u64::from(offset), 16)?;
        let named = u32::from(src.u16_at(at + 12)?);
        let ids = u32::from(src.u16_at(at + 14)?);
        let count = named + ids;
        if count > MAX_ENTRIES {
            return Err(RvaFault { rva: at + 12 });
        }
        self.range
            .extent_at(u64::from(offset), 16 + 8 * u64::from(count))?;
        let mut out = Vec::with_capacity(count as usize);
        for i in 0..u64::from(count) {
            let e = at + 16 + 8 * i;
            let name = src.u32_at(e)?;
            let target = src.u32_at(e + 4)?;
            // The PE format specifies that named entries precede integer
            // entries, selected by the directory counts. Do not interpret
            // an integer's bit 31 as a string flag or truncate it to WORD.
            let id = if i < u64::from(named) {
                let off = u64::from(name & 0x7FFF_FFFF);
                let s = self.range.extent_at(off, 2)?;
                let len = usize::from(src.u16_at(s)?);
                if len > MAX_NAME {
                    return Err(RvaFault { rva: s });
                }
                self.range.extent_at(off, 2 + 2 * len as u64)?;
                let mut units = Vec::with_capacity(len);
                for k in 0..len as u64 {
                    units.push(src.u16_at(s + 2 + 2 * k)?);
                }
                ResId::Name(units)
            } else {
                ResId::Id(name)
            };
            out.push(Entry {
                id,
                target: target & 0x7FFF_FFFF,
                subdirectory: target & 0x8000_0000 != 0,
            });
        }
        Ok(out)
    }

    fn find(entries: &[Entry], id: &ResId) -> Option<Entry> {
        entries.iter().find(|e| &e.id == id).cloned()
    }

    fn leaf(
        &self,
        src: &(impl RvaSource + ?Sized),
        e: &Entry,
        language: u32,
    ) -> Result<ResourceData, RvaFault> {
        let at = self.range.extent_at(u64::from(e.target), 16)?;
        Ok(ResourceData {
            rva: src.u32_at(at)?,
            size: src.u32_at(at + 4)?,
            codepage: src.u32_at(at + 8)?,
            language,
        })
    }

    /// Finds resource `name` of type `kind`. With `language`, only that
    /// language matches; without, the language-neutral entry (0) is
    /// preferred, then U.S. English (0x409), then the first entry.
    /// Names use exact UTF-16 equality, not Windows API case folding.
    /// This numeric-language API rejects named language identifiers.
    pub fn find_resource(
        &self,
        src: &(impl RvaSource + ?Sized),
        kind: &ResId,
        name: &ResId,
        language: Option<u32>,
    ) -> Result<Option<ResourceData>, RvaFault> {
        let types = self.entries(src, 0)?;
        let Some(t) = Self::find(&types, kind).filter(|e| e.subdirectory) else {
            return Ok(None);
        };
        let names = self.entries(src, t.target)?;
        let Some(n) = Self::find(&names, name).filter(|e| e.subdirectory) else {
            return Ok(None);
        };
        let langs = self.entries(src, n.target)?;
        if langs.iter().any(|e| matches!(e.id, ResId::Name(_))) {
            return Err(RvaFault {
                rva: u64::from(self.range.rva) + u64::from(n.target),
            });
        }
        let leaf_lang = |e: &Entry| match e.id {
            ResId::Id(l) => l,
            ResId::Name(_) => 0,
        };
        let chosen = match language {
            Some(l) => langs.iter().find(|e| leaf_lang(e) == l),
            None => langs
                .iter()
                .find(|e| leaf_lang(e) == 0)
                .or_else(|| langs.iter().find(|e| leaf_lang(e) == 0x409))
                .or_else(|| langs.first()),
        };
        match chosen.filter(|e| !e.subdirectory) {
            Some(e) => self.leaf(src, e, leaf_lang(e)).map(Some),
            None => Ok(None),
        }
    }

    /// The identifiers of every resource of type `kind`.
    pub fn names_of_type(
        &self,
        src: &(impl RvaSource + ?Sized),
        kind: &ResId,
    ) -> Result<Vec<ResId>, RvaFault> {
        let types = self.entries(src, 0)?;
        let Some(t) = Self::find(&types, kind).filter(|e| e.subdirectory) else {
            return Ok(Vec::new());
        };
        Ok(self
            .entries(src, t.target)?
            .into_iter()
            .map(|e| e.id)
            .collect())
    }
}
