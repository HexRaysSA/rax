//! The import directory (`.idata`) and delay-load descriptors.
//!
//! Descriptor walking stops at the first entry whose `Name` or `FirstThunk`
//! is zero (the PE specification's null directory entry ends the table;
//! loaders stop as soon as either field that binding needs is absent). An
//! import lookup table of zero (`OriginalFirstThunk`) means the import
//! address table holds the lookup entries itself, as images from linkers
//! that emit no separate lookup table do.

use super::{DataDirectory, PeKind, RvaFault, RvaSource};

/// Longest DLL or symbol name the decoder reads.
pub const MAX_IMPORT_NAME: usize = 4096;
/// Upper bound on descriptors or thunks walked, against hostile tables.
pub const MAX_IMPORT_ENTRIES: usize = 1 << 20;

/// Size of `IMAGE_IMPORT_DESCRIPTOR`.
pub const IMPORT_DESCRIPTOR_SIZE: u64 = 20;
/// Size of `IMAGE_DELAYLOAD_DESCRIPTOR`.
pub const DELAY_DESCRIPTOR_SIZE: u64 = 32;

/// `IMAGE_IMPORT_DESCRIPTOR`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImportDescriptor {
    /// `OriginalFirstThunk`: the import lookup table.
    pub lookup_rva: u32,
    /// `TimeDateStamp` (non-zero for a bound image).
    pub time_date_stamp: u32,
    /// `ForwarderChain`.
    pub forwarder_chain: u32,
    /// `Name`: the DLL name.
    pub name_rva: u32,
    /// `FirstThunk`: the import address table.
    pub iat_rva: u32,
}

/// How one import names its symbol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImportRef {
    /// By ordinal.
    Ordinal(u16),
    /// By name, with the export name table position to try first.
    Name {
        /// The hint.
        hint: u16,
        /// The symbol name.
        name: Vec<u8>,
    },
}

/// One import: the IAT slot to bind and what to bind it to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportThunk {
    /// RVA of the import address table slot.
    pub iat_slot: u32,
    /// The symbol.
    pub symbol: ImportRef,
}

/// Decodes an import lookup table entry of a `kind` image. Bits 30-15
/// (62-15) of an ordinal entry "must be 0" and are ignored; the ordinal is
/// the low 16 bits. A name entry's hint/name RVA is the low 31 bits.
pub fn decode_lookup(
    src: &(impl RvaSource + ?Sized),
    kind: PeKind,
    entry: u64,
) -> Result<ImportRef, RvaFault> {
    if entry & kind.ordinal_flag() != 0 {
        return Ok(ImportRef::Ordinal(entry as u16));
    }
    let rva = entry & 0x7FFF_FFFF;
    let hint = src.u16_at(rva)?;
    let name = src
        .cstr_at(rva + 2, MAX_IMPORT_NAME)?
        .ok_or(RvaFault { rva: rva + 2 })?;
    Ok(ImportRef::Name { hint, name })
}

/// The import descriptors of data directory `range`.
pub fn descriptors(
    src: &(impl RvaSource + ?Sized),
    range: DataDirectory,
) -> Result<Vec<ImportDescriptor>, RvaFault> {
    let mut out = Vec::new();
    if !range.is_present() {
        return Ok(out);
    }
    for i in 0..=MAX_IMPORT_ENTRIES {
        let at = range.extent_at(i as u64 * IMPORT_DESCRIPTOR_SIZE, IMPORT_DESCRIPTOR_SIZE)?;
        let d = ImportDescriptor {
            lookup_rva: src.u32_at(at)?,
            time_date_stamp: src.u32_at(at + 4)?,
            forwarder_chain: src.u32_at(at + 8)?,
            name_rva: src.u32_at(at + 12)?,
            iat_rva: src.u32_at(at + 16)?,
        };
        if d.name_rva == 0 || d.iat_rva == 0 {
            return Ok(out);
        }
        if i == MAX_IMPORT_ENTRIES {
            return Err(RvaFault { rva: at });
        }
        out.push(d);
    }
    Err(RvaFault {
        rva: u64::from(range.rva),
    })
}

impl ImportDescriptor {
    /// The DLL name.
    pub fn dll_name(&self, src: &(impl RvaSource + ?Sized)) -> Result<Vec<u8>, RvaFault> {
        src.cstr_at(u64::from(self.name_rva), MAX_IMPORT_NAME)?
            .ok_or(RvaFault {
                rva: u64::from(self.name_rva),
            })
    }

    /// The imports up to the null lookup entry.
    pub fn thunks(
        &self,
        src: &(impl RvaSource + ?Sized),
        kind: PeKind,
    ) -> Result<Vec<ImportThunk>, RvaFault> {
        let lookup = if self.lookup_rva != 0 {
            self.lookup_rva
        } else {
            self.iat_rva
        };
        thunk_table(src, kind, lookup, self.iat_rva)
    }
}

/// Walks a lookup table at `lookup` whose slots bind into `iat`.
fn thunk_table(
    src: &(impl RvaSource + ?Sized),
    kind: PeKind,
    lookup: u32,
    iat: u32,
) -> Result<Vec<ImportThunk>, RvaFault> {
    let step = kind.pointer_size() as u64;
    let mut out = Vec::new();
    for i in 0..=MAX_IMPORT_ENTRIES as u64 {
        let at = u64::from(lookup) + i * step;
        let slot = u64::from(iat) + i * step;
        if at + step > 1u64 << 32 || slot + step > 1u64 << 32 {
            return Err(RvaFault { rva: at.max(slot) });
        }
        let entry = src.word_at(kind, at)?;
        if entry == 0 {
            return Ok(out);
        }
        if i == MAX_IMPORT_ENTRIES as u64 {
            return Err(RvaFault { rva: at });
        }
        out.push(ImportThunk {
            iat_slot: u32::try_from(slot).map_err(|_| RvaFault { rva: slot })?,
            symbol: decode_lookup(src, kind, entry)?,
        });
    }
    Err(RvaFault {
        rva: u64::from(lookup),
    })
}

/// `IMAGE_DELAYLOAD_DESCRIPTOR` (the "Delay-Load Directory Table").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DelayDescriptor {
    /// `Attributes` (bit 0: RVA-based descriptor).
    pub attributes: u32,
    /// `DllNameRVA`, or a legacy VA when attributes bit 0 is clear.
    pub name_rva: u32,
    /// `ModuleHandleRVA`, or a legacy VA when attributes bit 0 is clear.
    pub module_handle_rva: u32,
    /// `ImportAddressTableRVA`, or a legacy VA when attributes bit 0 is clear.
    pub iat_rva: u32,
    /// `ImportNameTableRVA`, or a legacy VA when attributes bit 0 is clear.
    pub name_table_rva: u32,
    /// `BoundImportAddressTableRVA`, or a legacy VA when bit 0 is clear.
    pub bound_iat_rva: u32,
    /// `UnloadInformationTableRVA`, or a legacy VA when bit 0 is clear.
    pub unload_iat_rva: u32,
    /// `TimeDateStamp`.
    pub time_date_stamp: u32,
}

/// The delay-load descriptors of data directory `range`, up to the first
/// descriptor without a DLL name.
pub fn delay_descriptors(
    src: &(impl RvaSource + ?Sized),
    range: DataDirectory,
) -> Result<Vec<DelayDescriptor>, RvaFault> {
    let mut out = Vec::new();
    if !range.is_present() {
        return Ok(out);
    }
    for i in 0..=MAX_IMPORT_ENTRIES {
        let at = range.extent_at(i as u64 * DELAY_DESCRIPTOR_SIZE, DELAY_DESCRIPTOR_SIZE)?;
        let d = DelayDescriptor {
            attributes: src.u32_at(at)?,
            name_rva: src.u32_at(at + 4)?,
            module_handle_rva: src.u32_at(at + 8)?,
            iat_rva: src.u32_at(at + 12)?,
            name_table_rva: src.u32_at(at + 16)?,
            bound_iat_rva: src.u32_at(at + 20)?,
            unload_iat_rva: src.u32_at(at + 24)?,
            time_date_stamp: src.u32_at(at + 28)?,
        };
        if d.name_rva == 0 {
            return Ok(out);
        }
        if i == MAX_IMPORT_ENTRIES {
            return Err(RvaFault { rva: at });
        }
        out.push(d);
    }
    Err(RvaFault {
        rva: u64::from(range.rva),
    })
}

impl DelayDescriptor {
    /// The delay-loaded imports of an RVA-based descriptor.
    ///
    /// A legacy VA-based descriptor cannot be decoded without the image's
    /// actual base. This RVA-only API rejects it instead of silently
    /// reporting no imports. Reserved attribute bits are also rejected.
    pub fn thunks(
        &self,
        src: &(impl RvaSource + ?Sized),
        kind: PeKind,
    ) -> Result<Vec<ImportThunk>, RvaFault> {
        if self.attributes != 1 {
            return Err(RvaFault {
                rva: u64::from(self.name_table_rva),
            });
        }
        thunk_table(src, kind, self.name_table_rva, self.iat_rva)
    }
}
