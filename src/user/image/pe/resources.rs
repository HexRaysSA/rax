//! The resource tree (`.rsrc`): a three-level directory of type, name, and
//! language, whose leaves are data entries (PE specification, "The .rsrc
//! Section"). All offsets inside the tree are relative to the start of the
//! resource directory; data entries hold RVAs.

use super::{DataDirectory, RvaFault, RvaSource};

/// `RT_MANIFEST`.
pub const RT_MANIFEST: u16 = 24;
/// `RT_STRING`.
pub const RT_STRING: u16 = 6;
/// `RT_VERSION`.
pub const RT_VERSION: u16 = 16;

/// Upper bound on the entries of one directory table.
const MAX_ENTRIES: u32 = 1 << 16;
/// Longest resource name read.
const MAX_NAME: usize = 1024;

/// A resource type, name, or language identifier.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ResId {
    /// An integer identifier.
    Id(u16),
    /// A name, compared case-insensitively (names are stored upper-cased by
    /// resource compilers).
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
    pub language: u16,
}

/// One directory entry.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry {
    id: ResId,
    /// Offset (from the tree root) of the subdirectory or data entry.
    target: u32,
    subdirectory: bool,
}

fn upper(c: u16) -> u16 {
    if (u16::from(b'a')..=u16::from(b'z')).contains(&c) {
        c - 32
    } else {
        c
    }
}

fn same_name(a: &[u16], b: &[u16]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(&x, &y)| upper(x) == upper(y))
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
            let id = if name & 0x8000_0000 != 0 {
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
                ResId::Id(name as u16)
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
        entries
            .iter()
            .find(|e| match (&e.id, id) {
                (ResId::Id(a), ResId::Id(b)) => a == b,
                (ResId::Name(a), ResId::Name(b)) => same_name(a, b),
                _ => false,
            })
            .cloned()
    }

    fn leaf(
        &self,
        src: &(impl RvaSource + ?Sized),
        e: &Entry,
        language: u16,
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
    pub fn find_resource(
        &self,
        src: &(impl RvaSource + ?Sized),
        kind: &ResId,
        name: &ResId,
        language: Option<u16>,
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
