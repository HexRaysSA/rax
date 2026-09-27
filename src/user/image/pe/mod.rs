//! PE/COFF image parser.
//!
//! Decodes Portable Executable images (PE32 and PE32+) as the Microsoft PE
//! Format specification describes them
//! (`docs/specifications/windows/microsoft-docs/pe-format.md`) and computes
//! the memory image a loader maps. The acceptance set is the specification's
//! structural requirements that a mapping depends on:
//!
//! - the MS-DOS and `PE\0\0` signatures, and `e_lfanew` inside the file;
//! - a PE32 or PE32+ optional header that covers every Windows-specific
//!   field, with a machine of the matching word size;
//! - `IMAGE_FILE_EXECUTABLE_IMAGE` ("If this flag is not set, it indicates a
//!   linker error");
//! - power-of-two alignments with `SectionAlignment >= FileAlignment`, and
//!   `FileAlignment == SectionAlignment` below the page size;
//! - at most 96 sections ("the Windows loader limits the number of sections
//!   to 96"), each aligned to `SectionAlignment`, in ascending order without
//!   overlap, clear of the headers, and inside `SizeOfImage`;
//! - file data of every mapped byte inside the file, and, for low-alignment
//!   images, file offsets equal to RVAs.
//!
//! Advisory fields the specification only recommends (`FileAlignment`
//! between 512 and 64 KiB, checksums) are not enforced. `SizeOfImage` must
//! be a multiple of `SectionAlignment`; `SizeOfHeaders` must cover the
//! complete header and section tables and be a multiple of `FileAlignment`.
//! `ImageBase` must be aligned to 64 KiB. The Windows loader's exact acceptance set is
//! not published; where it is stricter or looser than the specification,
//! this parser follows the specification.
//!
//! Every offset computation is checked: a hostile image produces a
//! [`PeError`], never a panic or an out-of-bounds access.
//!
//! Directory decoders ([`exports`], [`imports`], [`relocs`], [`tls`],
//! [`loadcfg`], [`resources`], [`pdata`]) read through [`RvaSource`], so they
//! work on a mapped image buffer as well as on an image in guest memory.

pub mod exports;
pub mod imports;
pub mod loadcfg;
pub mod pdata;
pub mod relocs;
pub mod resources;
pub mod tls;
mod types;

#[cfg(test)]
mod tests;

pub use types::*;

use std::fmt;
use std::sync::Arc;

/// Page size the mapping rules refer to ("the page size of the
/// architecture": 4 KiB for x86, x64, and ARM64).
pub const PAGE_SIZE: u32 = 0x1000;

/// Reasons an image is rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeError {
    /// A structure extends past the end of the file.
    Truncated { needed: u64, available: u64 },
    /// `e_magic` is not "MZ".
    BadDosMagic,
    /// The `PE\0\0` signature is missing at `e_lfanew`.
    BadNtSignature { offset: u32 },
    /// The optional header's magic is neither PE32 nor PE32+.
    BadOptionalMagic(u16),
    /// `SizeOfOptionalHeader` does not cover the Windows-specific fields.
    OptionalHeaderTooSmall { size: u16, needed: u16 },
    /// `IMAGE_FILE_EXECUTABLE_IMAGE` is clear.
    NotExecutable,
    /// The machine's word size does not match the optional header.
    MachineKindMismatch { machine: u16, kind: PeKind },
    /// An alignment rule is violated.
    BadAlignment {
        section_alignment: u32,
        file_alignment: u32,
    },
    /// More sections than the loader accepts.
    TooManySections(u16),
    /// `SizeOfImage` or `SizeOfHeaders` is inconsistent.
    BadImageSize {
        size_of_image: u32,
        size_of_headers: u32,
    },
    /// `ImageBase` is not aligned to 64 KiB.
    BadImageBase(u64),
    /// Section `index` is misplaced (unaligned, overlapping the headers or
    /// the previous section, out of order, or outside the image).
    BadSectionLayout { index: usize },
    /// Section `index`'s file data lies outside the file.
    SectionDataOutOfFile { index: usize },
    /// `AddressOfEntryPoint` lies outside the image.
    BadEntryPoint(u32),
}

impl fmt::Display for PeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeError::Truncated { needed, available } => write!(
                f,
                "truncated PE image: need {needed} bytes, file has {available}"
            ),
            PeError::BadDosMagic => f.write_str("not a PE image (no MZ signature)"),
            PeError::BadNtSignature { offset } => {
                write!(f, "no PE signature at e_lfanew {offset:#x}")
            }
            PeError::BadOptionalMagic(m) => write!(f, "unknown optional header magic {m:#x}"),
            PeError::OptionalHeaderTooSmall { size, needed } => write!(
                f,
                "optional header of {size} bytes is shorter than the {needed} its fields need"
            ),
            PeError::NotExecutable => f.write_str("IMAGE_FILE_EXECUTABLE_IMAGE is clear"),
            PeError::MachineKindMismatch { machine, kind } => {
                write!(f, "machine {machine:#06x} does not match a {kind:?} header")
            }
            PeError::BadAlignment {
                section_alignment,
                file_alignment,
            } => write!(
                f,
                "invalid alignment: SectionAlignment {section_alignment:#x}, FileAlignment {file_alignment:#x}"
            ),
            PeError::TooManySections(n) => write!(f, "{n} sections exceed the loader limit of 96"),
            PeError::BadImageSize {
                size_of_image,
                size_of_headers,
            } => write!(
                f,
                "invalid image size: SizeOfImage {size_of_image:#x}, SizeOfHeaders {size_of_headers:#x}"
            ),
            PeError::BadImageBase(base) => {
                write!(f, "image base {base:#x} is not aligned to 64 KiB")
            }
            PeError::BadSectionLayout { index } => write!(f, "section {index} is misplaced"),
            PeError::SectionDataOutOfFile { index } => {
                write!(f, "section {index}'s data lies outside the file")
            }
            PeError::BadEntryPoint(rva) => write!(f, "entry point {rva:#x} lies outside the image"),
        }
    }
}

impl std::error::Error for PeError {}

/// A byte range of the file read with bounds checks.
#[derive(Clone, Copy)]
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn slice(&self, off: u64, len: u64) -> Result<&'a [u8], PeError> {
        let available = self.0.len() as u64;
        match off.checked_add(len) {
            Some(end) if end <= available => Ok(&self.0[off as usize..end as usize]),
            Some(end) => Err(PeError::Truncated {
                needed: end,
                available,
            }),
            None => Err(PeError::Truncated {
                needed: u64::MAX,
                available,
            }),
        }
    }

    fn u8(&self, off: u64) -> Result<u8, PeError> {
        Ok(self.slice(off, 1)?[0])
    }

    fn u16(&self, off: u64) -> Result<u16, PeError> {
        Ok(u16::from_le_bytes(self.slice(off, 2)?.try_into().unwrap()))
    }

    fn u32(&self, off: u64) -> Result<u32, PeError> {
        Ok(u32::from_le_bytes(self.slice(off, 4)?.try_into().unwrap()))
    }

    fn u64(&self, off: u64) -> Result<u64, PeError> {
        Ok(u64::from_le_bytes(self.slice(off, 8)?.try_into().unwrap()))
    }

    /// A pointer-sized field of a `kind` optional header.
    fn word(&self, kind: PeKind, off: u64) -> Result<u64, PeError> {
        match kind {
            PeKind::Pe32 => self.u32(off).map(u64::from),
            PeKind::Pe32Plus => self.u64(off),
        }
    }
}

/// Rounds `value` up to a multiple of the power of two `align`, or `None`
/// on overflow or when `align` is not a nonzero power of two.
pub fn align_up(value: u64, align: u64) -> Option<u64> {
    if !align.is_power_of_two() {
        return None;
    }
    value.checked_add(align - 1).map(|v| v & !(align - 1))
}

/// Memory protection of a mapped image range, as the loader derives it from
/// section characteristics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ImageProtection {
    /// Readable.
    pub read: bool,
    /// Writable (copy-on-write for image sections).
    pub write: bool,
    /// Executable.
    pub execute: bool,
}

impl ImageProtection {
    /// The protection of a section with `characteristics`: the section's
    /// `IMAGE_SCN_MEM_{READ,WRITE,EXECUTE}` flags, where execute or write
    /// access implies read access. x86 and x64 page tables cannot express
    /// write-only or execute-only pages, so `PAGE_EXECUTE` and
    /// `PAGE_WRITECOPY` are readable there; the same is assumed for ARM64.
    pub fn from_characteristics(characteristics: u32) -> Self {
        let execute = characteristics & IMAGE_SCN_MEM_EXECUTE != 0;
        let write = characteristics & IMAGE_SCN_MEM_WRITE != 0;
        let read = characteristics & IMAGE_SCN_MEM_READ != 0 || execute || write;
        ImageProtection {
            read,
            write,
            execute,
        }
    }

    /// Read-only (the headers).
    pub const READONLY: ImageProtection = ImageProtection {
        read: true,
        write: false,
        execute: false,
    };

    /// Read, write, and execute (a low-alignment image).
    pub const ALL: ImageProtection = ImageProtection {
        read: true,
        write: true,
        execute: true,
    };
}

/// One contiguous range of a mapped image with a single protection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageRegion {
    /// First RVA (page-aligned).
    pub rva: u32,
    /// Length in bytes (a multiple of the page size).
    pub len: u32,
    /// Protection.
    pub protection: ImageProtection,
    /// The section the range belongs to, `None` for the headers or a
    /// low-alignment image.
    pub section: Option<usize>,
}

/// A parsed PE image.
#[derive(Clone, Debug)]
pub struct PeImage {
    bytes: Arc<[u8]>,
    headers: PeHeaders,
    sections: Vec<SectionHeader>,
}

/// Returns whether `bytes` begins with an MS-DOS header that points at a PE
/// signature: the check a personality uses to choose a loader.
pub fn is_pe(bytes: &[u8]) -> bool {
    let r = Reader(bytes);
    if r.u16(0).ok() != Some(IMAGE_DOS_SIGNATURE) {
        return false;
    }
    match r.u32(E_LFANEW_OFFSET as u64) {
        Ok(off) => r.u32(u64::from(off)).ok() == Some(IMAGE_NT_SIGNATURE),
        Err(_) => false,
    }
}

impl PeImage {
    /// Parses and validates an image file.
    pub fn parse(bytes: impl Into<Arc<[u8]>>) -> Result<Self, PeError> {
        let bytes: Arc<[u8]> = bytes.into();
        let (headers, sections) = decode(&bytes)?;
        Ok(PeImage {
            bytes,
            headers,
            sections,
        })
    }

    /// The decoded headers.
    pub fn headers(&self) -> &PeHeaders {
        &self.headers
    }

    /// The section table in file order.
    pub fn sections(&self) -> &[SectionHeader] {
        &self.sections
    }

    /// The file bytes.
    pub fn bytes(&self) -> &Arc<[u8]> {
        &self.bytes
    }

    /// Whether the image uses low alignment (`SectionAlignment` below the
    /// page size): the file is mapped as-is and every page is writable and
    /// executable.
    pub fn low_alignment(&self) -> bool {
        self.headers.section_alignment < PAGE_SIZE
    }

    /// `SizeOfImage` rounded up to the page size.
    pub fn mapped_size(&self) -> u32 {
        // decode() checked that this fits in 32 bits.
        align_up(u64::from(self.headers.size_of_image), u64::from(PAGE_SIZE)).unwrap() as u32
    }

    /// The image as a loader lays it out in memory, relative to its base:
    /// `SizeOfHeaders` bytes of headers, then each section's initialized
    /// data at its RVA, zero elsewhere.
    ///
    /// A section contributes `min(SizeOfRawData, memory size)` file bytes,
    /// where the memory size is `VirtualSize` (or `SizeOfRawData` when that
    /// is zero) rounded up to `SectionAlignment`: "If this is less than
    /// VirtualSize, the remainder of the section is zero-filled." A
    /// low-alignment image is the file's first `SizeOfImage` bytes.
    pub fn memory_image(&self) -> Vec<u8> {
        let size = self.mapped_size() as usize;
        let mut image = vec![0u8; size];
        if self.low_alignment() {
            let n = self.bytes.len().min(self.headers.size_of_image as usize);
            image[..n].copy_from_slice(&self.bytes[..n]);
            return image;
        }
        let h = (self.headers.size_of_headers as usize)
            .min(self.bytes.len())
            .min(size);
        image[..h].copy_from_slice(&self.bytes[..h]);
        for s in &self.sections {
            let (off, len) = section_file_range(&self.headers, s);
            if len == 0 {
                continue;
            }
            let dst = s.virtual_address as usize;
            image[dst..dst + len as usize]
                .copy_from_slice(&self.bytes[off as usize..(off + len) as usize]);
        }
        image
    }

    /// The protection layout of the mapped image: the headers read-only,
    /// each section with its characteristics' protection, and any gaps
    /// inaccessible (omitted). Ranges are page-aligned; where two ranges
    /// share a page (possible only with a `SectionAlignment` equal to the
    /// page size and an unaligned `SizeOfHeaders`), the later one wins.
    pub fn regions(&self) -> Vec<ImageRegion> {
        if self.low_alignment() {
            return vec![ImageRegion {
                rva: 0,
                len: self.mapped_size(),
                protection: ImageProtection::ALL,
                section: None,
            }];
        }
        let page = u64::from(PAGE_SIZE);
        let mut out = Vec::with_capacity(self.sections.len() + 1);
        let headers_end = align_up(u64::from(self.headers.size_of_headers), page).unwrap();
        out.push(ImageRegion {
            rva: 0,
            len: headers_end as u32,
            protection: ImageProtection::READONLY,
            section: None,
        });
        let salign = u64::from(self.headers.section_alignment);
        for (i, s) in self.sections.iter().enumerate() {
            let size = align_up(u64::from(s.memory_size()), salign).unwrap();
            let size = align_up(size, page).unwrap();
            if size == 0 {
                continue;
            }
            out.push(ImageRegion {
                rva: s.virtual_address,
                len: size as u32,
                protection: ImageProtection::from_characteristics(s.characteristics),
                section: Some(i),
            });
        }
        out
    }

    /// The file offset holding the byte at `rva`, if a mapped file byte
    /// backs it.
    pub fn rva_to_file_offset(&self, rva: u32) -> Option<u64> {
        if rva >= self.headers.size_of_image {
            return None;
        }
        if self.low_alignment() {
            return (u64::from(rva) < self.bytes.len() as u64).then_some(u64::from(rva));
        }
        if rva < self.headers.size_of_headers {
            return (u64::from(rva) < self.bytes.len() as u64).then_some(u64::from(rva));
        }
        self.sections.iter().find_map(|s| {
            let (off, len) = section_file_range(&self.headers, s);
            let delta = rva.checked_sub(s.virtual_address)?;
            (u64::from(delta) < len).then(|| off + u64::from(delta))
        })
    }

    /// The section containing `rva` in memory.
    pub fn section_at(&self, rva: u32) -> Option<&SectionHeader> {
        let salign = u64::from(self.headers.section_alignment);
        self.sections.iter().find(|s| {
            let size = align_up(u64::from(s.memory_size()), salign).unwrap_or(0);
            u64::from(rva) >= u64::from(s.virtual_address)
                && u64::from(rva) < u64::from(s.virtual_address) + size
        })
    }
}

/// The `(file offset, length)` of the file bytes a section maps.
fn section_file_range(headers: &PeHeaders, s: &SectionHeader) -> (u64, u64) {
    let salign = u64::from(headers.section_alignment);
    let mem = align_up(u64::from(s.memory_size()), salign).unwrap_or(0);
    let len = u64::from(s.size_of_raw_data).min(mem);
    (u64::from(s.pointer_to_raw_data), len)
}

/// Decodes and validates the headers and the section table.
fn decode(bytes: &[u8]) -> Result<(PeHeaders, Vec<SectionHeader>), PeError> {
    let r = Reader(bytes);
    // The MS-DOS header is 64 bytes; e_lfanew is its last field.
    r.slice(0, 64)?;
    if r.u16(0)? != IMAGE_DOS_SIGNATURE {
        return Err(PeError::BadDosMagic);
    }
    let nt = r.u32(E_LFANEW_OFFSET as u64)?;
    let nt64 = u64::from(nt);
    if r.u32(nt64)? != IMAGE_NT_SIGNATURE {
        return Err(PeError::BadNtSignature { offset: nt });
    }
    let coff = nt64 + 4;
    r.slice(coff, COFF_HEADER_SIZE as u64)?;
    let machine = r.u16(coff)?;
    let number_of_sections = r.u16(coff + 2)?;
    let time_date_stamp = r.u32(coff + 4)?;
    let size_of_optional_header = r.u16(coff + 16)?;
    let characteristics = r.u16(coff + 18)?;

    let opt = coff + COFF_HEADER_SIZE as u64;
    let magic = r.u16(opt)?;
    let kind = match magic {
        PE32_MAGIC => PeKind::Pe32,
        PE32_PLUS_MAGIC => PeKind::Pe32Plus,
        m => return Err(PeError::BadOptionalMagic(m)),
    };
    let fixed = kind.directories_offset() as u16;
    if size_of_optional_header < fixed {
        return Err(PeError::OptionalHeaderTooSmall {
            size: size_of_optional_header,
            needed: fixed,
        });
    }
    r.slice(opt, u64::from(fixed))?;
    if characteristics & IMAGE_FILE_EXECUTABLE_IMAGE == 0 {
        return Err(PeError::NotExecutable);
    }
    let word_matches = match machine {
        IMAGE_FILE_MACHINE_I386 | IMAGE_FILE_MACHINE_ARMNT => kind == PeKind::Pe32,
        IMAGE_FILE_MACHINE_AMD64
        | IMAGE_FILE_MACHINE_ARM64
        | IMAGE_FILE_MACHINE_ARM64EC
        | IMAGE_FILE_MACHINE_ARM64X => kind == PeKind::Pe32Plus,
        // Other machines are reported by the personality, which knows
        // which it can run.
        _ => true,
    };
    if !word_matches {
        return Err(PeError::MachineKindMismatch { machine, kind });
    }

    // Offsets differ between PE32 and PE32+ only where BaseOfData (PE32)
    // and the 8-byte words (PE32+) shift them (specification tables).
    let (base_off, sizes_off, sizes_step) = match kind {
        PeKind::Pe32 => (28u64, 72u64, 4u64),
        PeKind::Pe32Plus => (24u64, 72u64, 8u64),
    };
    let image_base = r.word(kind, opt + base_off)?;
    let section_alignment = r.u32(opt + 32)?;
    let file_alignment = r.u32(opt + 36)?;
    let size_of_image = r.u32(opt + 56)?;
    let size_of_headers = r.u32(opt + 60)?;
    let tail = opt + sizes_off + 4 * sizes_step;
    let number_of_rva_and_sizes = r.u32(tail + 4)?;

    let mut directories = [DataDirectory::default(); dir::COUNT];
    let room = (usize::from(size_of_optional_header) - usize::from(fixed)) / DATA_DIRECTORY_SIZE;
    let count = (number_of_rva_and_sizes as usize).min(dir::COUNT).min(room);
    let dirs = opt + u64::from(fixed);
    for (i, d) in directories.iter_mut().enumerate().take(count) {
        let at = dirs + (i * DATA_DIRECTORY_SIZE) as u64;
        *d = DataDirectory {
            rva: r.u32(at)?,
            size: r.u32(at + 4)?,
        };
    }

    let headers = PeHeaders {
        nt_offset: nt,
        machine,
        number_of_sections,
        time_date_stamp,
        size_of_optional_header,
        characteristics,
        kind,
        linker_version: (r.u8(opt + 2)?, r.u8(opt + 3)?),
        entry_rva: r.u32(opt + 16)?,
        image_base,
        section_alignment,
        file_alignment,
        os_version: (r.u16(opt + 40)?, r.u16(opt + 42)?),
        image_version: (r.u16(opt + 44)?, r.u16(opt + 46)?),
        subsystem_version: (r.u16(opt + 48)?, r.u16(opt + 50)?),
        win32_version_value: r.u32(opt + 52)?,
        size_of_image,
        size_of_headers,
        checksum: r.u32(opt + 64)?,
        subsystem: r.u16(opt + 68)?,
        dll_characteristics: r.u16(opt + 70)?,
        stack_reserve: r.word(kind, opt + sizes_off)?,
        stack_commit: r.word(kind, opt + sizes_off + sizes_step)?,
        heap_reserve: r.word(kind, opt + sizes_off + 2 * sizes_step)?,
        heap_commit: r.word(kind, opt + sizes_off + 3 * sizes_step)?,
        loader_flags: r.u32(tail)?,
        number_of_rva_and_sizes,
        directories,
    };

    // Alignment: powers of two, SectionAlignment >= FileAlignment, and
    // equal below the page size.
    let bad_alignment = !section_alignment.is_power_of_two()
        || !file_alignment.is_power_of_two()
        || section_alignment < file_alignment
        || (section_alignment < PAGE_SIZE && file_alignment != section_alignment);
    if bad_alignment {
        return Err(PeError::BadAlignment {
            section_alignment,
            file_alignment,
        });
    }
    if number_of_sections > MAX_SECTIONS {
        return Err(PeError::TooManySections(number_of_sections));
    }
    if image_base & 0xFFFF != 0 {
        return Err(PeError::BadImageBase(image_base));
    }
    let salign = u64::from(section_alignment);
    let image_end = u64::from(size_of_image);
    if size_of_image == 0
        || size_of_image % section_alignment != 0
        || size_of_headers == 0
        || size_of_headers % file_alignment != 0
        || u64::from(size_of_headers) > image_end
        || align_up(image_end, u64::from(PAGE_SIZE)).is_none_or(|end| end > u64::from(u32::MAX))
    {
        return Err(PeError::BadImageSize {
            size_of_image,
            size_of_headers,
        });
    }
    // Header bytes past the end of the file map as zeros, as file pages
    // past end of file do; `memory_image` copies only what the file holds.
    let table = opt + u64::from(size_of_optional_header);
    let table_size = u64::from(number_of_sections) * SECTION_HEADER_SIZE as u64;
    if table + table_size > u64::from(size_of_headers) {
        return Err(PeError::BadImageSize {
            size_of_image,
            size_of_headers,
        });
    }
    r.slice(table, table_size)?;
    let mut sections = Vec::with_capacity(usize::from(number_of_sections));
    for i in 0..u64::from(number_of_sections) {
        let at = table + i * SECTION_HEADER_SIZE as u64;
        sections.push(SectionHeader {
            name: r.slice(at, 8)?.try_into().unwrap(),
            virtual_size: r.u32(at + 8)?,
            virtual_address: r.u32(at + 12)?,
            size_of_raw_data: r.u32(at + 16)?,
            pointer_to_raw_data: r.u32(at + 20)?,
            characteristics: r.u32(at + 36)?,
        });
    }

    let low = section_alignment < PAGE_SIZE;
    // Sections start after the headers, are aligned, ascend without
    // overlap, and end inside the image.
    let mut next_free = if low {
        0
    } else {
        align_up(u64::from(size_of_headers), salign).unwrap()
    };
    for (index, s) in sections.iter().enumerate() {
        let va = u64::from(s.virtual_address);
        let size = align_up(u64::from(s.memory_size()), salign)
            .ok_or(PeError::BadSectionLayout { index })?;
        let misplaced = va % salign != 0 || va < next_free || va + size > image_end;
        if misplaced {
            return Err(PeError::BadSectionLayout { index });
        }
        next_free = va + size;
        let (off, len) = section_file_range(&headers, s);
        if low {
            // "the physical offset for section data is the same as the RVA".
            if s.size_of_raw_data != 0 && s.pointer_to_raw_data != s.virtual_address {
                return Err(PeError::BadSectionLayout { index });
            }
        }
        if len != 0 && r.slice(off, len).is_err() {
            return Err(PeError::SectionDataOutOfFile { index });
        }
    }
    if u64::from(headers.entry_rva) >= image_end {
        return Err(PeError::BadEntryPoint(headers.entry_rva));
    }
    Ok((headers, sections))
}

/// A fault reading an RVA through an [`RvaSource`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RvaFault {
    /// First RVA that could not be read.
    pub rva: u64,
}

/// Read access to a mapped image by RVA: a host buffer holding the memory
/// image, or an image in guest memory.
pub trait RvaSource {
    /// Reads `buf.len()` bytes at `rva`.
    fn read_rva(&self, rva: u64, buf: &mut [u8]) -> Result<(), RvaFault>;

    /// Reads a little-endian `u16`.
    fn u16_at(&self, rva: u64) -> Result<u16, RvaFault> {
        let mut b = [0u8; 2];
        self.read_rva(rva, &mut b)?;
        Ok(u16::from_le_bytes(b))
    }

    /// Reads a little-endian `u32`.
    fn u32_at(&self, rva: u64) -> Result<u32, RvaFault> {
        let mut b = [0u8; 4];
        self.read_rva(rva, &mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    /// Reads a little-endian `u64`.
    fn u64_at(&self, rva: u64) -> Result<u64, RvaFault> {
        let mut b = [0u8; 8];
        self.read_rva(rva, &mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    /// Reads a pointer-sized field of a `kind` image.
    fn word_at(&self, kind: PeKind, rva: u64) -> Result<u64, RvaFault> {
        match kind {
            PeKind::Pe32 => self.u32_at(rva).map(u64::from),
            PeKind::Pe32Plus => self.u64_at(rva),
        }
    }

    /// Reads a NUL-terminated byte string of at most `max` bytes (without
    /// the NUL); `None` when no NUL occurs within `max` bytes.
    fn cstr_at(&self, rva: u64, max: usize) -> Result<Option<Vec<u8>>, RvaFault> {
        let mut out = Vec::new();
        let mut at = rva;
        while out.len() < max {
            let mut b = [0u8; 1];
            self.read_rva(at, &mut b)?;
            if b[0] == 0 {
                return Ok(Some(out));
            }
            out.push(b[0]);
            at = at.checked_add(1).ok_or(RvaFault { rva: at })?;
        }
        Ok(None)
    }
}

impl RvaSource for [u8] {
    fn read_rva(&self, rva: u64, buf: &mut [u8]) -> Result<(), RvaFault> {
        let start = usize::try_from(rva).map_err(|_| RvaFault { rva })?;
        let end = start
            .checked_add(buf.len())
            .filter(|&e| e <= self.len())
            .ok_or(RvaFault {
                rva: rva.max(self.len() as u64),
            })?;
        buf.copy_from_slice(&self[start..end]);
        Ok(())
    }
}

impl RvaSource for Vec<u8> {
    fn read_rva(&self, rva: u64, buf: &mut [u8]) -> Result<(), RvaFault> {
        self.as_slice().read_rva(rva, buf)
    }
}
