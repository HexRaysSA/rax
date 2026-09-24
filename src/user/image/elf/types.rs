//! ELF identification, file-header, and program-header definitions.
//!
//! Field names and constants follow the System V gABI and the Linux UAPI
//! header `linux/elf.h` (see `docs/specifications/linux/uapi-6.19/`). Only the
//! structures needed to *execute* an image are modelled; section headers are
//! consulted solely for validation of the header table geometry.

/// `EI_NIDENT`: size of the identification prefix in bytes.
pub const EI_NIDENT: usize = 16;
/// `ELFMAG`: `\x7fELF`.
pub const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

/// `EI_CLASS` byte offset.
pub const EI_CLASS: usize = 4;
/// `EI_DATA` byte offset.
pub const EI_DATA: usize = 5;
/// `EI_VERSION` byte offset.
pub const EI_VERSION: usize = 6;
/// `EI_OSABI` byte offset.
pub const EI_OSABI: usize = 7;
/// `EI_ABIVERSION` byte offset.
pub const EI_ABIVERSION: usize = 8;

/// `EV_CURRENT`.
pub const EV_CURRENT: u32 = 1;

/// `ELFOSABI_NONE` (System V).
pub const ELFOSABI_NONE: u8 = 0;
/// `ELFOSABI_LINUX` / `ELFOSABI_GNU`.
pub const ELFOSABI_LINUX: u8 = 3;

/// `ET_EXEC`: fixed-address executable.
pub const ET_EXEC: u16 = 2;
/// `ET_DYN`: position-independent executable or shared object.
pub const ET_DYN: u16 = 3;

/// `EM_386`.
pub const EM_386: u16 = 3;
/// `EM_ARM`.
pub const EM_ARM: u16 = 40;
/// `EM_X86_64`.
pub const EM_X86_64: u16 = 62;
/// `EM_HEXAGON`.
pub const EM_HEXAGON: u16 = 164;
/// `EM_AARCH64`.
pub const EM_AARCH64: u16 = 183;
/// `EM_RISCV`.
pub const EM_RISCV: u16 = 243;

/// `PT_NULL`.
pub const PT_NULL: u32 = 0;
/// `PT_LOAD`.
pub const PT_LOAD: u32 = 1;
/// `PT_DYNAMIC`.
pub const PT_DYNAMIC: u32 = 2;
/// `PT_INTERP`.
pub const PT_INTERP: u32 = 3;
/// `PT_NOTE`.
pub const PT_NOTE: u32 = 4;
/// `PT_PHDR`.
pub const PT_PHDR: u32 = 6;
/// `PT_TLS`.
pub const PT_TLS: u32 = 7;
/// `PT_GNU_EH_FRAME`.
pub const PT_GNU_EH_FRAME: u32 = 0x6474_e550;
/// `PT_GNU_STACK`.
pub const PT_GNU_STACK: u32 = 0x6474_e551;
/// `PT_GNU_RELRO`.
pub const PT_GNU_RELRO: u32 = 0x6474_e552;
/// `PT_GNU_PROPERTY`.
pub const PT_GNU_PROPERTY: u32 = 0x6474_e553;

/// `PF_X`.
pub const PF_X: u32 = 1;
/// `PF_W`.
pub const PF_W: u32 = 2;
/// `PF_R`.
pub const PF_R: u32 = 4;

/// `PN_XNUM`: escape value for more than 0xfffe program headers. Linux's
/// `elf_read_phdrs` does not honour the escape, so neither does RAX.
pub const PN_XNUM: u16 = 0xffff;

/// Linux `PATH_MAX`, the bound applied to `PT_INTERP` by `load_elf_binary`.
pub const PATH_MAX: u64 = 4096;

/// Upper bound for the whole program-header table (`elf_read_phdrs`).
pub const MAX_PHDR_TABLE_BYTES: u64 = 65536;

/// ELF file class (`EI_CLASS`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ElfClass {
    /// `ELFCLASS32`.
    Elf32,
    /// `ELFCLASS64`.
    Elf64,
}

impl ElfClass {
    /// Size of `ElfN_Ehdr` in bytes.
    pub const fn header_size(self) -> usize {
        match self {
            ElfClass::Elf32 => 52,
            ElfClass::Elf64 => 64,
        }
    }

    /// Size of `ElfN_Phdr` in bytes.
    pub const fn phdr_size(self) -> usize {
        match self {
            ElfClass::Elf32 => 32,
            ElfClass::Elf64 => 56,
        }
    }

    /// Size of `ElfN_Shdr` in bytes.
    pub const fn shdr_size(self) -> usize {
        match self {
            ElfClass::Elf32 => 40,
            ElfClass::Elf64 => 64,
        }
    }

    /// Size of an address (`ElfN_Addr`) in bytes.
    pub const fn addr_size(self) -> usize {
        match self {
            ElfClass::Elf32 => 4,
            ElfClass::Elf64 => 8,
        }
    }
}

/// ELF data encoding (`EI_DATA`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ElfData {
    /// `ELFDATA2LSB`: two's complement, little-endian.
    Lsb,
    /// `ELFDATA2MSB`: two's complement, big-endian.
    Msb,
}

/// Decoded ELF file header (`ElfN_Ehdr`), widened to 64-bit fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ElfHeader {
    pub class: ElfClass,
    pub data: ElfData,
    pub osabi: u8,
    pub abi_version: u8,
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_shoff: u64,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

/// Decoded program header (`ElfN_Phdr`), widened to 64-bit fields.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProgramHeader {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

impl ProgramHeader {
    /// Whether the segment requests read access.
    pub const fn readable(&self) -> bool {
        self.p_flags & PF_R != 0
    }

    /// Whether the segment requests write access.
    pub const fn writable(&self) -> bool {
        self.p_flags & PF_W != 0
    }

    /// Whether the segment requests execute access.
    pub const fn executable(&self) -> bool {
        self.p_flags & PF_X != 0
    }
}
