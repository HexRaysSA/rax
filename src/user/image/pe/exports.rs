//! The export directory (`.edata`): lookups by name and by ordinal, and
//! forwarder detection, as the PE specification's "The .edata Section"
//! describes them.

use super::{DataDirectory, RvaFault, RvaSource};

/// Longest export or forwarder name the decoder reads.
pub const MAX_EXPORT_NAME: usize = 4096;

/// `IMAGE_EXPORT_DIRECTORY`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExportDirectory {
    /// RVA and size of the directory itself: an export address inside this
    /// range is a forwarder string.
    pub range: DataDirectory,
    /// `Name` RVA.
    pub name_rva: u32,
    /// `Base`: the ordinal of the first export address table entry.
    pub ordinal_base: u32,
    /// `NumberOfFunctions`.
    pub number_of_functions: u32,
    /// `NumberOfNames`.
    pub number_of_names: u32,
    /// `AddressOfFunctions`.
    pub functions_rva: u32,
    /// `AddressOfNames`.
    pub names_rva: u32,
    /// `AddressOfNameOrdinals`.
    pub ordinals_rva: u32,
}

/// What an export address table entry designates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExportTarget {
    /// An address in the image.
    Rva(u32),
    /// A forwarder: `"DLL.Name"` or `"DLL.#ordinal"`.
    Forwarder(Vec<u8>),
}

/// A forwarder string split into its module and symbol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Forwarder {
    /// Module name before the last dot (without an extension).
    pub module: Vec<u8>,
    /// The symbol.
    pub symbol: ForwardSymbol,
}

/// The symbol part of a forwarder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ForwardSymbol {
    /// By name.
    Name(Vec<u8>),
    /// By ordinal (`#n`).
    Ordinal(u32),
}

/// Splits `"MODULE.Symbol"` or `"MODULE.#123"` at its last dot. A module
/// name may itself contain dots (`"api-ms-win-core-x-l1-1-0.Func"`).
pub fn parse_forwarder(text: &[u8]) -> Option<Forwarder> {
    let dot = text.iter().rposition(|&b| b == b'.')?;
    let (module, symbol) = (&text[..dot], &text[dot + 1..]);
    if module.is_empty() || symbol.is_empty() {
        return None;
    }
    let symbol = match symbol.strip_prefix(b"#") {
        Some(digits) => ForwardSymbol::Ordinal(std::str::from_utf8(digits).ok()?.parse().ok()?),
        None => ForwardSymbol::Name(symbol.to_vec()),
    };
    Some(Forwarder {
        module: module.to_vec(),
        symbol,
    })
}

impl ExportDirectory {
    /// Reads the directory described by data directory `range`, or `None`
    /// when the image has none.
    pub fn read(
        src: &(impl RvaSource + ?Sized),
        range: DataDirectory,
    ) -> Result<Option<Self>, RvaFault> {
        if !range.is_present() {
            return Ok(None);
        }
        let at = range.extent_at(0, 40)?;
        Ok(Some(ExportDirectory {
            range,
            name_rva: src.u32_at(at + 12)?,
            ordinal_base: src.u32_at(at + 16)?,
            number_of_functions: src.u32_at(at + 20)?,
            number_of_names: src.u32_at(at + 24)?,
            functions_rva: src.u32_at(at + 28)?,
            names_rva: src.u32_at(at + 32)?,
            ordinals_rva: src.u32_at(at + 36)?,
        }))
    }

    /// The module name the directory records.
    pub fn module_name(
        &self,
        src: &(impl RvaSource + ?Sized),
    ) -> Result<Option<Vec<u8>>, RvaFault> {
        src.cstr_at(u64::from(self.name_rva), MAX_EXPORT_NAME)
    }

    /// Whether `rva` lies inside the export directory (a forwarder).
    fn is_forwarder(&self, rva: u32) -> bool {
        let start = u64::from(self.range.rva);
        let end = start + u64::from(self.range.size);
        (start..end).contains(&u64::from(rva))
    }

    /// The target of export address table entry `index` (an unbiased
    /// ordinal), or `None` for an index outside the table or an empty
    /// (zero) entry.
    pub fn by_index(
        &self,
        src: &(impl RvaSource + ?Sized),
        index: u32,
    ) -> Result<Option<ExportTarget>, RvaFault> {
        if index >= self.number_of_functions {
            return Ok(None);
        }
        let rva = src.u32_at(u64::from(self.functions_rva) + 4 * u64::from(index))?;
        if rva == 0 {
            return Ok(None);
        }
        if self.is_forwarder(rva) {
            let remaining = u64::from(self.range.rva) + u64::from(self.range.size) - u64::from(rva);
            let max = remaining.min(MAX_EXPORT_NAME as u64) as usize;
            let text = src.cstr_at(u64::from(rva), max)?.ok_or(RvaFault {
                rva: u64::from(rva) + max as u64,
            })?;
            return Ok(Some(ExportTarget::Forwarder(text)));
        }
        Ok(Some(ExportTarget::Rva(rva)))
    }

    /// The target of biased ordinal `ordinal`.
    pub fn by_ordinal(
        &self,
        src: &(impl RvaSource + ?Sized),
        ordinal: u32,
    ) -> Result<Option<ExportTarget>, RvaFault> {
        match ordinal.checked_sub(self.ordinal_base) {
            Some(index) => self.by_index(src, index),
            None => Ok(None),
        }
    }

    /// Name pointer table entry `i`.
    pub fn name_at(
        &self,
        src: &(impl RvaSource + ?Sized),
        i: u32,
    ) -> Result<Option<Vec<u8>>, RvaFault> {
        if i >= self.number_of_names {
            return Ok(None);
        }
        let rva = src.u32_at(u64::from(self.names_rva) + 4 * u64::from(i))?;
        src.cstr_at(u64::from(rva), MAX_EXPORT_NAME)
    }

    /// Ordinal table entry `i` (an unbiased index).
    pub fn ordinal_at(&self, src: &(impl RvaSource + ?Sized), i: u32) -> Result<u16, RvaFault> {
        if i >= self.number_of_names {
            return Err(RvaFault {
                rva: u64::from(self.ordinals_rva) + 2 * u64::from(i),
            });
        }
        src.u16_at(u64::from(self.ordinals_rva) + 2 * u64::from(i))
    }

    /// Looks `name` up: first at name-table position `hint`, then by binary
    /// search of the name pointer table, which "are ordered lexically"
    /// (byte-wise, case-sensitive). Returns the unbiased ordinal and target.
    pub fn by_name(
        &self,
        src: &(impl RvaSource + ?Sized),
        name: &[u8],
        hint: Option<u16>,
    ) -> Result<Option<(u32, ExportTarget)>, RvaFault> {
        let resolve = |i: u32| -> Result<Option<(u32, ExportTarget)>, RvaFault> {
            let index = u32::from(self.ordinal_at(src, i)?);
            Ok(self.by_index(src, index)?.map(|t| (index, t)))
        };
        if let Some(h) = hint.map(u32::from).filter(|&h| h < self.number_of_names)
            && self.name_at(src, h)?.as_deref() == Some(name)
        {
            return resolve(h);
        }
        let (mut lo, mut hi) = (0u32, self.number_of_names);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let Some(candidate) = self.name_at(src, mid)? else {
                return Ok(None);
            };
            match candidate.as_slice().cmp(name) {
                std::cmp::Ordering::Equal => return resolve(mid),
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
            }
        }
        Ok(None)
    }

    /// Every named export as `(name, unbiased ordinal)`, in table order.
    pub fn names(&self, src: &(impl RvaSource + ?Sized)) -> Result<Vec<(Vec<u8>, u32)>, RvaFault> {
        if self.number_of_names > 1 << 20 {
            return Err(RvaFault {
                rva: u64::from(self.names_rva),
            });
        }
        let mut out = Vec::new();
        for i in 0..self.number_of_names {
            if let Some(name) = self.name_at(src, i)? {
                out.push((name, u32::from(self.ordinal_at(src, i)?)));
            }
        }
        Ok(out)
    }
}
