//! PE/COFF constants and decoded header structures.
//!
//! Names and values follow the Microsoft PE Format specification
//! (`docs/specifications/windows/microsoft-docs/pe-format.md`, revision
//! 07/14/2025) and the `IMAGE_*` definitions of `winnt.h`.

/// `IMAGE_DOS_SIGNATURE` ("MZ").
pub const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
/// `IMAGE_NT_SIGNATURE` ("PE\0\0").
pub const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550;
/// Offset of `e_lfanew` in the MS-DOS header ("At location 0x3c, the stub
/// has the file offset to the PE signature").
pub const E_LFANEW_OFFSET: usize = 0x3C;

/// Size of the COFF file header.
pub const COFF_HEADER_SIZE: usize = 20;
/// Size of one section header.
pub const SECTION_HEADER_SIZE: usize = 40;
/// Size of one data-directory entry.
pub const DATA_DIRECTORY_SIZE: usize = 8;
/// "Note that the Windows loader limits the number of sections to 96."
pub const MAX_SECTIONS: u16 = 96;

/// `IMAGE_NT_OPTIONAL_HDR32_MAGIC`.
pub const PE32_MAGIC: u16 = 0x10B;
/// `IMAGE_NT_OPTIONAL_HDR64_MAGIC`.
pub const PE32_PLUS_MAGIC: u16 = 0x20B;

/// `IMAGE_FILE_MACHINE_I386`.
pub const IMAGE_FILE_MACHINE_I386: u16 = 0x014C;
/// `IMAGE_FILE_MACHINE_AMD64`.
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
/// `IMAGE_FILE_MACHINE_ARM64`.
pub const IMAGE_FILE_MACHINE_ARM64: u16 = 0xAA64;
/// `IMAGE_FILE_MACHINE_ARM64EC`.
pub const IMAGE_FILE_MACHINE_ARM64EC: u16 = 0xA641;
/// `IMAGE_FILE_MACHINE_ARM64X`.
pub const IMAGE_FILE_MACHINE_ARM64X: u16 = 0xA64E;
/// `IMAGE_FILE_MACHINE_ARMNT`.
pub const IMAGE_FILE_MACHINE_ARMNT: u16 = 0x01C4;

/// `IMAGE_FILE_RELOCS_STRIPPED`.
pub const IMAGE_FILE_RELOCS_STRIPPED: u16 = 0x0001;
/// `IMAGE_FILE_EXECUTABLE_IMAGE`.
pub const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
/// `IMAGE_FILE_LARGE_ADDRESS_AWARE`.
pub const IMAGE_FILE_LARGE_ADDRESS_AWARE: u16 = 0x0020;
/// `IMAGE_FILE_32BIT_MACHINE`.
pub const IMAGE_FILE_32BIT_MACHINE: u16 = 0x0100;
/// `IMAGE_FILE_DLL`.
pub const IMAGE_FILE_DLL: u16 = 0x2000;

/// `IMAGE_SUBSYSTEM_NATIVE`.
pub const IMAGE_SUBSYSTEM_NATIVE: u16 = 1;
/// `IMAGE_SUBSYSTEM_WINDOWS_GUI`.
pub const IMAGE_SUBSYSTEM_WINDOWS_GUI: u16 = 2;
/// `IMAGE_SUBSYSTEM_WINDOWS_CUI`.
pub const IMAGE_SUBSYSTEM_WINDOWS_CUI: u16 = 3;

/// `IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA`.
pub const IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA: u16 = 0x0020;
/// `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE`.
pub const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: u16 = 0x0040;
/// `IMAGE_DLLCHARACTERISTICS_NX_COMPAT`.
pub const IMAGE_DLLCHARACTERISTICS_NX_COMPAT: u16 = 0x0100;
/// `IMAGE_DLLCHARACTERISTICS_NO_SEH`.
pub const IMAGE_DLLCHARACTERISTICS_NO_SEH: u16 = 0x0400;
/// `IMAGE_DLLCHARACTERISTICS_GUARD_CF`.
pub const IMAGE_DLLCHARACTERISTICS_GUARD_CF: u16 = 0x4000;

/// Data-directory indices (`IMAGE_DIRECTORY_ENTRY_*`).
pub mod dir {
    /// Export table.
    pub const EXPORT: usize = 0;
    /// Import table.
    pub const IMPORT: usize = 1;
    /// Resource table.
    pub const RESOURCE: usize = 2;
    /// Exception table (`.pdata`).
    pub const EXCEPTION: usize = 3;
    /// Attribute certificate table (a file offset, not an RVA).
    pub const SECURITY: usize = 4;
    /// Base relocation table.
    pub const BASERELOC: usize = 5;
    /// Debug directory.
    pub const DEBUG: usize = 6;
    /// Global pointer register value.
    pub const GLOBALPTR: usize = 8;
    /// Thread-local storage directory.
    pub const TLS: usize = 9;
    /// Load configuration directory.
    pub const LOAD_CONFIG: usize = 10;
    /// Bound import table.
    pub const BOUND_IMPORT: usize = 11;
    /// Import address table.
    pub const IAT: usize = 12;
    /// Delay-load import descriptors.
    pub const DELAY_IMPORT: usize = 13;
    /// CLR runtime header.
    pub const COM_DESCRIPTOR: usize = 14;
    /// `IMAGE_NUMBEROF_DIRECTORY_ENTRIES`.
    pub const COUNT: usize = 16;
}

/// `IMAGE_SCN_CNT_CODE`.
pub const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
/// `IMAGE_SCN_CNT_INITIALIZED_DATA`.
pub const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
/// `IMAGE_SCN_CNT_UNINITIALIZED_DATA`.
pub const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
/// `IMAGE_SCN_MEM_DISCARDABLE`.
pub const IMAGE_SCN_MEM_DISCARDABLE: u32 = 0x0200_0000;
/// `IMAGE_SCN_MEM_SHARED`.
pub const IMAGE_SCN_MEM_SHARED: u32 = 0x1000_0000;
/// `IMAGE_SCN_MEM_EXECUTE`.
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
/// `IMAGE_SCN_MEM_READ`.
pub const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
/// `IMAGE_SCN_MEM_WRITE`.
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

/// Base relocation types (`IMAGE_REL_BASED_*`).
pub mod reloc {
    /// Padding; skipped.
    pub const ABSOLUTE: u8 = 0;
    /// High 16 bits of the delta added to a 16-bit field.
    pub const HIGH: u8 = 1;
    /// Low 16 bits of the delta added to a 16-bit field.
    pub const LOW: u8 = 2;
    /// The 32-bit delta added to a 32-bit field.
    pub const HIGHLOW: u8 = 3;
    /// High half of a 32-bit value whose low half is the next entry.
    pub const HIGHADJ: u8 = 4;
    /// `IMAGE_REL_BASED_ARM_MOV32` (ARM/Thumb machines only).
    pub const ARM_MOV32: u8 = 5;
    /// `IMAGE_REL_BASED_THUMB_MOV32` (Thumb machines only).
    pub const THUMB_MOV32: u8 = 7;
    /// The 64-bit delta added to a 64-bit field.
    pub const DIR64: u8 = 10;
}

/// Whether the image is PE32 or PE32+.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PeKind {
    /// 32-bit (`0x10B`).
    Pe32,
    /// 64-bit (`0x20B`).
    Pe32Plus,
}

impl PeKind {
    /// Size of a pointer (and of an import lookup table entry) in bytes.
    pub fn pointer_size(self) -> usize {
        match self {
            PeKind::Pe32 => 4,
            PeKind::Pe32Plus => 8,
        }
    }

    /// Offset of the data directories in the optional header (96/112).
    pub fn directories_offset(self) -> usize {
        match self {
            PeKind::Pe32 => 96,
            PeKind::Pe32Plus => 112,
        }
    }

    /// The ordinal flag of an import lookup table entry (bit 31/63).
    pub fn ordinal_flag(self) -> u64 {
        match self {
            PeKind::Pe32 => 1 << 31,
            PeKind::Pe32Plus => 1 << 63,
        }
    }
}

/// `IMAGE_DATA_DIRECTORY`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DataDirectory {
    /// RVA of the table (a file offset for the certificate table).
    pub rva: u32,
    /// Size in bytes.
    pub size: u32,
}

impl DataDirectory {
    /// Whether the entry describes a table.
    pub fn is_present(&self) -> bool {
        self.rva != 0 && self.size != 0
    }

    /// Validates an extent within this directory and the 32-bit RVA space.
    /// Referenced strings and tables may be outside a directory; callers
    /// use this only for the structures the directory itself contains.
    pub(super) fn extent_at(&self, offset: u64, len: u64) -> Result<u64, super::RvaFault> {
        let at = u64::from(self.rva).saturating_add(offset);
        let limit = (u64::from(self.rva) + u64::from(self.size)).min(1u64 << 32);
        if offset
            .checked_add(len)
            .is_none_or(|end| end > u64::from(self.size))
            || at.checked_add(len).is_none_or(|end| end > limit)
        {
            return Err(super::RvaFault { rva: at.max(limit) });
        }
        Ok(at)
    }
}

/// The COFF file header and the optional header's fields a loader uses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeHeaders {
    /// File offset of the `PE\0\0` signature (`e_lfanew`).
    pub nt_offset: u32,
    /// `Machine`.
    pub machine: u16,
    /// `NumberOfSections`.
    pub number_of_sections: u16,
    /// `TimeDateStamp`.
    pub time_date_stamp: u32,
    /// `SizeOfOptionalHeader`.
    pub size_of_optional_header: u16,
    /// `Characteristics`.
    pub characteristics: u16,
    /// PE32 or PE32+ (optional-header `Magic`).
    pub kind: PeKind,
    /// `MajorLinkerVersion`, `MinorLinkerVersion`.
    pub linker_version: (u8, u8),
    /// `AddressOfEntryPoint`.
    pub entry_rva: u32,
    /// `ImageBase`.
    pub image_base: u64,
    /// `SectionAlignment`.
    pub section_alignment: u32,
    /// `FileAlignment`.
    pub file_alignment: u32,
    /// `MajorOperatingSystemVersion`, `MinorOperatingSystemVersion`.
    pub os_version: (u16, u16),
    /// `MajorImageVersion`, `MinorImageVersion`.
    pub image_version: (u16, u16),
    /// `MajorSubsystemVersion`, `MinorSubsystemVersion`.
    pub subsystem_version: (u16, u16),
    /// `Win32VersionValue`.
    pub win32_version_value: u32,
    /// `SizeOfImage`.
    pub size_of_image: u32,
    /// `SizeOfHeaders`.
    pub size_of_headers: u32,
    /// `CheckSum`.
    pub checksum: u32,
    /// `Subsystem`.
    pub subsystem: u16,
    /// `DllCharacteristics`.
    pub dll_characteristics: u16,
    /// `SizeOfStackReserve`.
    pub stack_reserve: u64,
    /// `SizeOfStackCommit`.
    pub stack_commit: u64,
    /// `SizeOfHeapReserve`.
    pub heap_reserve: u64,
    /// `SizeOfHeapCommit`.
    pub heap_commit: u64,
    /// `LoaderFlags`.
    pub loader_flags: u32,
    /// `NumberOfRvaAndSizes` as stored.
    pub number_of_rva_and_sizes: u32,
    /// The data directories present in the optional header (at most 16;
    /// entries beyond `NumberOfRvaAndSizes` or beyond `SizeOfOptionalHeader`
    /// read as absent).
    pub directories: [DataDirectory; dir::COUNT],
}

impl PeHeaders {
    /// Data directory `index`, absent when out of range.
    pub fn directory(&self, index: usize) -> DataDirectory {
        self.directories.get(index).copied().unwrap_or_default()
    }

    /// Whether `IMAGE_FILE_DLL` is set.
    pub fn is_dll(&self) -> bool {
        self.characteristics & IMAGE_FILE_DLL != 0
    }

    /// Whether the image may be loaded away from its preferred base: it has
    /// relocations and does not declare them stripped.
    pub fn is_relocatable(&self) -> bool {
        self.characteristics & IMAGE_FILE_RELOCS_STRIPPED == 0
            && self.directory(dir::BASERELOC).is_present()
    }
}

/// `IMAGE_SECTION_HEADER`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SectionHeader {
    /// `Name` (8 bytes, NUL-padded, not necessarily terminated).
    pub name: [u8; 8],
    /// `VirtualSize` (`Misc.VirtualSize`).
    pub virtual_size: u32,
    /// `VirtualAddress` (an RVA).
    pub virtual_address: u32,
    /// `SizeOfRawData`.
    pub size_of_raw_data: u32,
    /// `PointerToRawData`.
    pub pointer_to_raw_data: u32,
    /// `Characteristics`.
    pub characteristics: u32,
}

impl SectionHeader {
    /// The name up to its first NUL, lossily decoded.
    pub fn name_str(&self) -> String {
        let len = self.name.iter().position(|&b| b == 0).unwrap_or(8);
        String::from_utf8_lossy(&self.name[..len]).into_owned()
    }

    /// Bytes the section occupies in memory before section alignment:
    /// `VirtualSize`, or `SizeOfRawData` when `VirtualSize` is zero (the
    /// convention of linkers that leave `VirtualSize` unset).
    pub fn memory_size(&self) -> u32 {
        if self.virtual_size != 0 {
            self.virtual_size
        } else {
            self.size_of_raw_data
        }
    }

    /// Whether `IMAGE_SCN_MEM_EXECUTE` is set.
    pub fn executable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
    }

    /// Whether `IMAGE_SCN_MEM_READ` is set.
    pub fn readable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_READ != 0
    }

    /// Whether `IMAGE_SCN_MEM_WRITE` is set.
    pub fn writable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_WRITE != 0
    }
}
