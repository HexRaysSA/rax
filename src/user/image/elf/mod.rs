//! ELF executable parser with Linux `binfmt_elf` acceptance semantics.
//!
//! Linux (fs/binfmt_elf.c, 6.19) decodes an executable's header in the
//! *kernel's native* class and byte order, and validates only a small set of
//! properties before mapping it: the magic, `e_type`, the architecture check,
//! `e_phentsize`, the program-header table size, the `PT_INTERP` string, and
//! per-`PT_LOAD` address arithmetic. Everything else — `EI_VERSION`,
//! `e_version`, `e_ehsize`, section headers — is ignored, and deliberately
//! corrupted values in those fields are a common anti-analysis technique. The
//! parser therefore mirrors exactly that acceptance set: an image Linux would
//! run parses, and an image Linux rejects at the same stage fails with a
//! distinct [`ElfError`].
//!
//! Address-space checks that depend on the guest's task size (`BAD_ADDR`,
//! `p_memsz > TASK_SIZE`, file/page congruence of mappings) belong to the
//! loader in [`crate::user::image::load`], which knows the guest layout.
//!
//! All offset/size arithmetic is checked: a hostile header can produce an
//! error but never a panic or an out-of-bounds slice.

mod types;

#[cfg(test)]
mod tests;

pub use types::*;

use std::fmt;

/// Reasons an image is rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ElfError {
    /// The file is shorter than a structure that must be read.
    Truncated { needed: u64, available: u64 },
    /// `EI_MAG0..EI_MAG3` is not `\x7fELF`.
    BadMagic,
    /// `e_type` is neither `ET_EXEC` nor `ET_DYN`.
    NotExecutable(u16),
    /// `e_phentsize` does not equal `sizeof(ElfN_Phdr)` for the decode class.
    BadPhentsize(u16),
    /// The program-header table is empty or larger than 64 KiB.
    BadPhnum(u16),
    /// The program-header table lies (partly) outside the file.
    PhdrTableOutOfBounds { offset: u64, size: u64 },
    /// `PT_INTERP` is shorter than two bytes or longer than `PATH_MAX`.
    BadInterpreterSize(u64),
    /// The `PT_INTERP` bytes lie (partly) outside the file.
    InterpreterOutOfFile { offset: u64, size: u64 },
    /// The last `PT_INTERP` byte is not NUL.
    InterpreterNotTerminated,
}

impl fmt::Display for ElfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ElfError::Truncated { needed, available } => write!(
                f,
                "truncated ELF image: need {needed} bytes, file has {available}"
            ),
            ElfError::BadMagic => f.write_str("not an ELF image (bad magic)"),
            ElfError::NotExecutable(t) => {
                write!(f, "ELF type {t} is neither ET_EXEC nor ET_DYN")
            }
            ElfError::BadPhentsize(s) => write!(f, "invalid program header entry size {s}"),
            ElfError::BadPhnum(n) => write!(f, "invalid program header count {n}"),
            ElfError::PhdrTableOutOfBounds { offset, size } => write!(
                f,
                "program header table [{offset:#x}, +{size:#x}) lies outside the file"
            ),
            ElfError::BadInterpreterSize(s) => {
                write!(f, "PT_INTERP size {s} is outside [2, PATH_MAX]")
            }
            ElfError::InterpreterOutOfFile { offset, size } => write!(
                f,
                "PT_INTERP bytes [{offset:#x}, +{size:#x}) lie outside the file"
            ),
            ElfError::InterpreterNotTerminated => {
                f.write_str("PT_INTERP string is not NUL-terminated")
            }
        }
    }
}

impl std::error::Error for ElfError {}

/// The identification fields needed to choose a guest ABI before decoding.
///
/// `e_type` and `e_machine` sit at the same offsets (16 and 18) in both
/// classes. They are decoded with the byte order named by `EI_DATA`, falling
/// back to little-endian when `EI_DATA` is not a defined encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ElfIdent {
    /// Raw `EI_CLASS` byte.
    pub class: u8,
    /// Raw `EI_DATA` byte.
    pub data: u8,
    /// Raw `EI_OSABI` byte.
    pub osabi: u8,
    /// `e_type`.
    pub e_type: u16,
    /// `e_machine`.
    pub e_machine: u16,
    /// `e_flags`, read at the offset implied by a *valid* `EI_CLASS`, or zero.
    pub e_flags: u32,
}

impl ElfIdent {
    /// The `EI_CLASS` byte as an [`ElfClass`], if defined.
    pub fn elf_class(&self) -> Option<ElfClass> {
        match self.class {
            1 => Some(ElfClass::Elf32),
            2 => Some(ElfClass::Elf64),
            _ => None,
        }
    }

    /// The `EI_DATA` byte as an [`ElfData`], if defined.
    pub fn elf_data(&self) -> Option<ElfData> {
        match self.data {
            1 => Some(ElfData::Lsb),
            2 => Some(ElfData::Msb),
            _ => None,
        }
    }
}

/// Reads the identification fields of an ELF file.
pub fn identify(bytes: &[u8]) -> Result<ElfIdent, ElfError> {
    if bytes.len() < 4 {
        return Err(ElfError::Truncated {
            needed: 4,
            available: bytes.len() as u64,
        });
    }
    if bytes[..4] != ELF_MAGIC {
        return Err(ElfError::BadMagic);
    }
    // The shortest header (Elf32_Ehdr) is 52 bytes; e_machine ends at 20.
    if bytes.len() < 20 {
        return Err(ElfError::Truncated {
            needed: 20,
            available: bytes.len() as u64,
        });
    }
    let data = if bytes[EI_DATA] == 2 {
        ElfData::Msb
    } else {
        ElfData::Lsb
    };
    let r = Reader { bytes, data };
    let e_flags = match bytes[EI_CLASS] {
        1 => r.u32(36).unwrap_or(0),
        2 => r.u32(48).unwrap_or(0),
        _ => 0,
    };
    Ok(ElfIdent {
        class: bytes[EI_CLASS],
        data: bytes[EI_DATA],
        osabi: bytes[EI_OSABI],
        e_type: r.u16(16)?,
        e_machine: r.u16(18)?,
        e_flags,
    })
}

/// A parsed ELF executable borrowed from its file bytes.
#[derive(Clone, Debug)]
pub struct ElfImage<'a> {
    bytes: &'a [u8],
    header: ElfHeader,
    phdrs: Vec<ProgramHeader>,
    interp: Option<Vec<u8>>,
}

/// Endian-aware field reader over a bounds-checked slice.
#[derive(Clone, Copy)]
struct Reader<'a> {
    bytes: &'a [u8],
    data: ElfData,
}

impl<'a> Reader<'a> {
    fn slice(&self, off: u64, len: u64) -> Result<&'a [u8], ElfError> {
        let available = self.bytes.len() as u64;
        match off.checked_add(len) {
            Some(end) if end <= available => Ok(&self.bytes[off as usize..end as usize]),
            Some(end) => Err(ElfError::Truncated {
                needed: end,
                available,
            }),
            None => Err(ElfError::Truncated {
                needed: u64::MAX,
                available,
            }),
        }
    }

    fn u16(&self, off: u64) -> Result<u16, ElfError> {
        let b: [u8; 2] = self.slice(off, 2)?.try_into().expect("length checked");
        Ok(match self.data {
            ElfData::Lsb => u16::from_le_bytes(b),
            ElfData::Msb => u16::from_be_bytes(b),
        })
    }

    fn u32(&self, off: u64) -> Result<u32, ElfError> {
        let b: [u8; 4] = self.slice(off, 4)?.try_into().expect("length checked");
        Ok(match self.data {
            ElfData::Lsb => u32::from_le_bytes(b),
            ElfData::Msb => u32::from_be_bytes(b),
        })
    }

    fn u64(&self, off: u64) -> Result<u64, ElfError> {
        let b: [u8; 8] = self.slice(off, 8)?.try_into().expect("length checked");
        Ok(match self.data {
            ElfData::Lsb => u64::from_le_bytes(b),
            ElfData::Msb => u64::from_be_bytes(b),
        })
    }

    /// Reads an `ElfN_Addr`/`ElfN_Off`-class field.
    fn word(&self, class: ElfClass, off: u64) -> Result<u64, ElfError> {
        match class {
            ElfClass::Elf32 => self.u32(off).map(u64::from),
            ElfClass::Elf64 => self.u64(off),
        }
    }
}

/// Decodes the file header in the given class and byte order.
fn decode_header(bytes: &[u8], class: ElfClass, data: ElfData) -> Result<ElfHeader, ElfError> {
    if bytes.len() < 4 {
        return Err(ElfError::Truncated {
            needed: 4,
            available: bytes.len() as u64,
        });
    }
    if bytes[..4] != ELF_MAGIC {
        return Err(ElfError::BadMagic);
    }
    let r = Reader { bytes, data };
    r.slice(0, class.header_size() as u64)?;
    // Offsets of the class-dependent tail of ElfN_Ehdr (gABI figure 4-3).
    let (entry, phoff, shoff, flags) = match class {
        ElfClass::Elf32 => (24, 28, 32, 36),
        ElfClass::Elf64 => (24, 32, 40, 48),
    };
    let tail = flags + 4;
    Ok(ElfHeader {
        class,
        data,
        osabi: bytes[EI_OSABI],
        abi_version: bytes[EI_ABIVERSION],
        e_type: r.u16(16)?,
        e_machine: r.u16(18)?,
        e_version: r.u32(20)?,
        e_entry: r.word(class, entry)?,
        e_phoff: r.word(class, phoff)?,
        e_shoff: r.word(class, shoff)?,
        e_flags: r.u32(flags)?,
        e_ehsize: r.u16(tail)?,
        e_phentsize: r.u16(tail + 2)?,
        e_phnum: r.u16(tail + 4)?,
        e_shentsize: r.u16(tail + 6)?,
        e_shnum: r.u16(tail + 8)?,
        e_shstrndx: r.u16(tail + 10)?,
    })
}

impl<'a> ElfImage<'a> {
    /// Parses an executable in the guest ABI's native `class` and `data`
    /// encoding, applying Linux's acceptance checks.
    pub fn parse(bytes: &'a [u8], class: ElfClass, data: ElfData) -> Result<Self, ElfError> {
        let header = decode_header(bytes, class, data)?;
        if header.e_type != ET_EXEC && header.e_type != ET_DYN {
            return Err(ElfError::NotExecutable(header.e_type));
        }
        // elf_read_phdrs(): the entry size must match the native structure and
        // the whole table must be non-empty and at most 64 KiB.
        if usize::from(header.e_phentsize) != class.phdr_size() {
            return Err(ElfError::BadPhentsize(header.e_phentsize));
        }
        let phdr_size = class.phdr_size() as u64;
        let table = u64::from(header.e_phnum) * phdr_size;
        if table == 0 || table > MAX_PHDR_TABLE_BYTES {
            return Err(ElfError::BadPhnum(header.e_phnum));
        }
        let r = Reader { bytes, data };
        if r.slice(header.e_phoff, table).is_err() {
            return Err(ElfError::PhdrTableOutOfBounds {
                offset: header.e_phoff,
                size: table,
            });
        }

        let mut phdrs = Vec::with_capacity(usize::from(header.e_phnum));
        for i in 0..u64::from(header.e_phnum) {
            let base = header.e_phoff + i * phdr_size;
            phdrs.push(match class {
                // Elf32_Phdr: type, offset, vaddr, paddr, filesz, memsz, flags, align.
                ElfClass::Elf32 => ProgramHeader {
                    p_type: r.u32(base)?,
                    p_offset: u64::from(r.u32(base + 4)?),
                    p_vaddr: u64::from(r.u32(base + 8)?),
                    p_paddr: u64::from(r.u32(base + 12)?),
                    p_filesz: u64::from(r.u32(base + 16)?),
                    p_memsz: u64::from(r.u32(base + 20)?),
                    p_flags: r.u32(base + 24)?,
                    p_align: u64::from(r.u32(base + 28)?),
                },
                // Elf64_Phdr: type, flags, offset, vaddr, paddr, filesz, memsz, align.
                ElfClass::Elf64 => ProgramHeader {
                    p_type: r.u32(base)?,
                    p_flags: r.u32(base + 4)?,
                    p_offset: r.u64(base + 8)?,
                    p_vaddr: r.u64(base + 16)?,
                    p_paddr: r.u64(base + 24)?,
                    p_filesz: r.u64(base + 32)?,
                    p_memsz: r.u64(base + 40)?,
                    p_align: r.u64(base + 48)?,
                },
            });
        }

        // load_elf_binary() consults only the first PT_INTERP. The string is
        // used as a C string, so an embedded NUL truncates it.
        let mut interp = None;
        if let Some(ph) = phdrs.iter().find(|p| p.p_type == PT_INTERP) {
            if ph.p_filesz < 2 || ph.p_filesz > PATH_MAX {
                return Err(ElfError::BadInterpreterSize(ph.p_filesz));
            }
            let raw =
                r.slice(ph.p_offset, ph.p_filesz)
                    .map_err(|_| ElfError::InterpreterOutOfFile {
                        offset: ph.p_offset,
                        size: ph.p_filesz,
                    })?;
            if raw.last() != Some(&0) {
                return Err(ElfError::InterpreterNotTerminated);
            }
            let len = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
            interp = Some(raw[..len].to_vec());
        }

        Ok(ElfImage {
            bytes,
            header,
            phdrs,
            interp,
        })
    }

    /// Parses using the class and byte order named by `EI_CLASS`/`EI_DATA`.
    /// Intended for tools and tests; execution uses [`ElfImage::parse`] with
    /// the guest ABI's native encoding.
    pub fn parse_self_described(bytes: &'a [u8]) -> Result<Self, ElfError> {
        let ident = identify(bytes)?;
        let class = ident.elf_class().unwrap_or(ElfClass::Elf64);
        let data = ident.elf_data().unwrap_or(ElfData::Lsb);
        Self::parse(bytes, class, data)
    }

    /// The decoded file header.
    pub fn header(&self) -> &ElfHeader {
        &self.header
    }

    /// All program headers in file order.
    pub fn program_headers(&self) -> &[ProgramHeader] {
        &self.phdrs
    }

    /// `PT_LOAD` program headers in file order.
    pub fn load_segments(&self) -> impl Iterator<Item = &ProgramHeader> {
        self.phdrs.iter().filter(|p| p.p_type == PT_LOAD)
    }

    /// The `PT_INTERP` path up to its first NUL, if present.
    pub fn interpreter(&self) -> Option<&[u8]> {
        self.interp.as_deref()
    }

    /// The first program header of type `p_type`, if any.
    pub fn find(&self, p_type: u32) -> Option<&ProgramHeader> {
        self.phdrs.iter().find(|p| p.p_type == p_type)
    }

    /// The executable-stack request expressed by the *last* `PT_GNU_STACK`
    /// (Linux iterates every header and the final one wins): `Some(true)` for
    /// `PF_X`, `Some(false)` without it, `None` when absent.
    pub fn gnu_stack_executable(&self) -> Option<bool> {
        self.phdrs
            .iter()
            .filter(|p| p.p_type == PT_GNU_STACK)
            .last()
            .map(|p| p.executable())
    }

    /// The file bytes backing the image.
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Linux `maximum_alignment()`: the largest power-of-two `p_align` of any
    /// `PT_LOAD`, rounded up to the page size, or zero when no `PT_LOAD` has a
    /// power-of-two alignment.
    pub fn max_load_alignment(&self, page_size: u64) -> u64 {
        let align = self
            .load_segments()
            .map(|p| p.p_align)
            .filter(|a| a.is_power_of_two())
            .max()
            .unwrap_or(0);
        align.div_ceil(page_size) * page_size
    }

    /// Linux `total_mapping_size()`: the span from the page containing the
    /// first `PT_LOAD`'s `p_vaddr` to the end of the *last* `PT_LOAD` in file
    /// order. `None` means there is no `PT_LOAD`, or the span wraps (Linux then
    /// fails the reservation mapping).
    pub fn total_mapping_size(&self, page_size: u64) -> Option<u64> {
        let first = self.load_segments().next()?;
        let last = self.load_segments().last()?;
        last.p_vaddr
            .checked_add(last.p_memsz)?
            .checked_sub(first.p_vaddr & !(page_size - 1))
    }
}
