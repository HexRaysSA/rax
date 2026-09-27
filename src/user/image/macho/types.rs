//! Mach-O constants and decoded structures.
//!
//! Values are those of the XNU 12377.121.6 headers `EXTERNAL_HEADERS/mach-o/loader.h`,
//! `EXTERNAL_HEADERS/mach-o/fat.h`, `osfmk/mach/machine.h`,
//! `osfmk/mach/vm_prot.h`, and the thread-state headers under
//! `osfmk/mach/{i386,arm}/thread_status.h`.

/// `FAT_MAGIC`, stored big-endian.
pub const FAT_MAGIC: u32 = 0xcafe_babe;
/// `FAT_MAGIC_64`, stored big-endian. XNU's `exec_fat_imgact` does not claim
/// it: a 64-bit fat header is not an executable format of the kernel.
pub const FAT_MAGIC_64: u32 = 0xcafe_babf;
/// `MH_MAGIC`: 32-bit Mach-O in host byte order.
pub const MH_MAGIC: u32 = 0xfeed_face;
/// `MH_CIGAM`: 32-bit Mach-O in the opposite byte order.
pub const MH_CIGAM: u32 = 0xcefa_edfe;
/// `MH_MAGIC_64`: 64-bit Mach-O in host byte order.
pub const MH_MAGIC_64: u32 = 0xfeed_facf;
/// `MH_CIGAM_64`: 64-bit Mach-O in the opposite byte order.
pub const MH_CIGAM_64: u32 = 0xcffa_edfe;

/// `sizeof(struct fat_header)`.
pub const FAT_HEADER_SIZE: u64 = 8;
/// `sizeof(struct fat_arch)`.
pub const FAT_ARCH_SIZE: u64 = 20;
/// `sizeof(struct mach_header)`.
pub const MACH_HEADER_SIZE: u64 = 28;
/// `sizeof(struct mach_header_64)`.
pub const MACH_HEADER_64_SIZE: u64 = 32;
/// `sizeof(struct load_command)`.
pub const LOAD_COMMAND_SIZE: u64 = 8;
/// `sizeof(struct segment_command_64)`.
pub const SEGMENT_COMMAND_64_SIZE: u64 = 72;
/// `sizeof(struct segment_command)`.
pub const SEGMENT_COMMAND_SIZE: u64 = 56;
/// `sizeof(struct section_64)`.
pub const SECTION_64_SIZE: u64 = 80;
/// `sizeof(struct thread_command)`.
pub const THREAD_COMMAND_SIZE: u64 = 8;
/// `sizeof(struct entry_point_command)`.
pub const ENTRY_POINT_COMMAND_SIZE: u64 = 24;
/// `sizeof(struct dylinker_command)`.
pub const DYLINKER_COMMAND_SIZE: u64 = 12;
/// `sizeof(struct uuid_command)`.
pub const UUID_COMMAND_SIZE: u64 = 24;
/// `sizeof(struct version_min_command)`.
pub const VERSION_MIN_COMMAND_SIZE: u64 = 16;
/// `sizeof(struct build_version_command)`.
pub const BUILD_VERSION_COMMAND_SIZE: u64 = 24;
/// `sizeof(struct linkedit_data_command)`.
pub const LINKEDIT_DATA_COMMAND_SIZE: u64 = 16;
/// `sizeof(struct encryption_info_command)`.
pub const ENCRYPTION_INFO_COMMAND_SIZE: u64 = 20;
/// `sizeof(struct encryption_info_command_64)`.
pub const ENCRYPTION_INFO_COMMAND_64_SIZE: u64 = 24;

/// `CPU_ARCH_MASK`.
pub const CPU_ARCH_MASK: u32 = 0xff00_0000;
/// `CPU_ARCH_ABI64`.
pub const CPU_ARCH_ABI64: u32 = 0x0100_0000;
/// `CPU_SUBTYPE_MASK`: the capability bits of a CPU subtype.
pub const CPU_SUBTYPE_MASK: u32 = 0xff00_0000;
/// `CPU_SUBTYPE_PTRAUTH_ABI`: an arm64e slice with a versioned ABI.
pub const CPU_SUBTYPE_PTRAUTH_ABI: u32 = 0x8000_0000;
/// `CPU_SUBTYPE_ARM64_PTR_AUTH_MASK`.
pub const CPU_SUBTYPE_ARM64_PTR_AUTH_MASK: u32 = 0x0f00_0000;
/// `CPU_SUBTYPE_ARM64_PTR_AUTH_MAX_PREFERRED_VERSION` on macOS.
pub const CPU_SUBTYPE_ARM64_PTR_AUTH_MAX_PREFERRED_VERSION: u32 = 1;

/// `CPU_TYPE_X86`.
pub const CPU_TYPE_X86: u32 = 7;
/// `CPU_TYPE_X86_64`.
pub const CPU_TYPE_X86_64: u32 = CPU_TYPE_X86 | CPU_ARCH_ABI64;
/// `CPU_TYPE_ARM`.
pub const CPU_TYPE_ARM: u32 = 12;
/// `CPU_TYPE_ARM64`.
pub const CPU_TYPE_ARM64: u32 = CPU_TYPE_ARM | CPU_ARCH_ABI64;
/// `CPU_TYPE_ANY`.
pub const CPU_TYPE_ANY: u32 = u32::MAX;

/// `CPU_SUBTYPE_X86_64_ALL`.
pub const CPU_SUBTYPE_X86_64_ALL: u32 = 3;
/// `CPU_SUBTYPE_X86_ARCH1`.
pub const CPU_SUBTYPE_X86_ARCH1: u32 = 4;
/// `CPU_SUBTYPE_X86_64_H` (Haswell feature subset).
pub const CPU_SUBTYPE_X86_64_H: u32 = 8;
/// `CPU_SUBTYPE_ARM64_ALL`.
pub const CPU_SUBTYPE_ARM64_ALL: u32 = 0;
/// `CPU_SUBTYPE_ARM64_V8`.
pub const CPU_SUBTYPE_ARM64_V8: u32 = 1;
/// `CPU_SUBTYPE_ARM64E`.
pub const CPU_SUBTYPE_ARM64E: u32 = 2;
/// `CPU_SUBTYPE_ANY`.
pub const CPU_SUBTYPE_ANY: u32 = u32::MAX;

/// `MH_OBJECT`.
pub const MH_OBJECT: u32 = 1;
/// `MH_EXECUTE`.
pub const MH_EXECUTE: u32 = 2;
/// `MH_DYLIB`.
pub const MH_DYLIB: u32 = 6;
/// `MH_DYLINKER`.
pub const MH_DYLINKER: u32 = 7;
/// `MH_BUNDLE`.
pub const MH_BUNDLE: u32 = 8;

/// `MH_NOUNDEFS`.
pub const MH_NOUNDEFS: u32 = 0x1;
/// `MH_DYLDLINK`: input for the dynamic linker.
pub const MH_DYLDLINK: u32 = 0x4;
/// `MH_TWOLEVEL`.
pub const MH_TWOLEVEL: u32 = 0x80;
/// `MH_ALLOW_STACK_EXECUTION`.
pub const MH_ALLOW_STACK_EXECUTION: u32 = 0x2_0000;
/// `MH_PIE`: load at a random address.
pub const MH_PIE: u32 = 0x20_0000;
/// `MH_NO_HEAP_EXECUTION`.
pub const MH_NO_HEAP_EXECUTION: u32 = 0x100_0000;

/// `LC_REQ_DYLD`.
pub const LC_REQ_DYLD: u32 = 0x8000_0000;
/// `LC_SEGMENT`.
pub const LC_SEGMENT: u32 = 0x1;
/// `LC_SYMTAB`.
pub const LC_SYMTAB: u32 = 0x2;
/// `LC_THREAD`.
pub const LC_THREAD: u32 = 0x4;
/// `LC_UNIXTHREAD`.
pub const LC_UNIXTHREAD: u32 = 0x5;
/// `LC_DYSYMTAB`.
pub const LC_DYSYMTAB: u32 = 0xb;
/// `LC_LOAD_DYLIB`.
pub const LC_LOAD_DYLIB: u32 = 0xc;
/// `LC_ID_DYLIB`.
pub const LC_ID_DYLIB: u32 = 0xd;
/// `LC_LOAD_DYLINKER`.
pub const LC_LOAD_DYLINKER: u32 = 0xe;
/// `LC_ID_DYLINKER`.
pub const LC_ID_DYLINKER: u32 = 0xf;
/// `LC_SEGMENT_64`.
pub const LC_SEGMENT_64: u32 = 0x19;
/// `LC_UUID`.
pub const LC_UUID: u32 = 0x1b;
/// `LC_CODE_SIGNATURE`.
pub const LC_CODE_SIGNATURE: u32 = 0x1d;
/// `LC_ENCRYPTION_INFO`.
pub const LC_ENCRYPTION_INFO: u32 = 0x21;
/// `LC_DYLD_INFO`.
pub const LC_DYLD_INFO: u32 = 0x22;
/// `LC_DYLD_INFO_ONLY`.
pub const LC_DYLD_INFO_ONLY: u32 = 0x22 | LC_REQ_DYLD;
/// `LC_VERSION_MIN_MACOSX`.
pub const LC_VERSION_MIN_MACOSX: u32 = 0x24;
/// `LC_VERSION_MIN_IPHONEOS`.
pub const LC_VERSION_MIN_IPHONEOS: u32 = 0x25;
/// `LC_FUNCTION_STARTS`.
pub const LC_FUNCTION_STARTS: u32 = 0x26;
/// `LC_MAIN`.
pub const LC_MAIN: u32 = 0x28 | LC_REQ_DYLD;
/// `LC_DATA_IN_CODE`.
pub const LC_DATA_IN_CODE: u32 = 0x29;
/// `LC_SOURCE_VERSION`.
pub const LC_SOURCE_VERSION: u32 = 0x2a;
/// `LC_ENCRYPTION_INFO_64`.
pub const LC_ENCRYPTION_INFO_64: u32 = 0x2c;
/// `LC_VERSION_MIN_TVOS`.
pub const LC_VERSION_MIN_TVOS: u32 = 0x2f;
/// `LC_VERSION_MIN_WATCHOS`.
pub const LC_VERSION_MIN_WATCHOS: u32 = 0x30;
/// `LC_BUILD_VERSION`.
pub const LC_BUILD_VERSION: u32 = 0x32;
/// `LC_DYLD_EXPORTS_TRIE`.
pub const LC_DYLD_EXPORTS_TRIE: u32 = 0x33 | LC_REQ_DYLD;
/// `LC_DYLD_CHAINED_FIXUPS`.
pub const LC_DYLD_CHAINED_FIXUPS: u32 = 0x34 | LC_REQ_DYLD;

/// `VM_PROT_READ`.
pub const VM_PROT_READ: u32 = 0x1;
/// `VM_PROT_WRITE`.
pub const VM_PROT_WRITE: u32 = 0x2;
/// `VM_PROT_EXECUTE`.
pub const VM_PROT_EXECUTE: u32 = 0x4;
/// `VM_PROT_ALL`.
pub const VM_PROT_ALL: u32 = VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE;

/// `SG_PROTECTED_VERSION_1`: the segment is Apple-protected (DSMOS).
pub const SG_PROTECTED_VERSION_1: u32 = 0x8;
/// `SG_READ_ONLY`: read-only after fixups (`__DATA_CONST`).
pub const SG_READ_ONLY: u32 = 0x10;

/// `x86_THREAD_STATE64`.
pub const X86_THREAD_STATE64: u32 = 4;
/// `x86_THREAD_STATE64_COUNT`: 21 64-bit registers in 32-bit words.
pub const X86_THREAD_STATE64_COUNT: u32 = 42;
/// `x86_THREAD_FULL_STATE64`.
pub const X86_THREAD_FULL_STATE64: u32 = 23;
/// `x86_THREAD_FULL_STATE64_COUNT`: `x86_thread_state64_t` followed by
/// `ds`, `es`, `ss`, and `gsbase` (four 64-bit words).
pub const X86_THREAD_FULL_STATE64_COUNT: u32 = X86_THREAD_STATE64_COUNT + 8;
/// `ARM_THREAD_STATE64`.
pub const ARM_THREAD_STATE64: u32 = 6;
/// `ARM_THREAD_STATE64_COUNT`: X0-X28, FP, LR, SP, PC, CPSR, and a pad
/// word, in 32-bit words.
pub const ARM_THREAD_STATE64_COUNT: u32 = 68;

/// `PLATFORM_MACOS`.
pub const PLATFORM_MACOS: u32 = 1;
/// `PLATFORM_IOS`.
pub const PLATFORM_IOS: u32 = 2;
/// `PLATFORM_TVOS`.
pub const PLATFORM_TVOS: u32 = 3;
/// `PLATFORM_WATCHOS`.
pub const PLATFORM_WATCHOS: u32 = 4;
/// `PLATFORM_MACCATALYST`.
pub const PLATFORM_MACCATALYST: u32 = 6;
/// `PLATFORM_DRIVERKIT`.
pub const PLATFORM_DRIVERKIT: u32 = 10;

/// One entry of a fat header's architecture table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FatArch {
    /// `cputype`.
    pub cputype: u32,
    /// `cpusubtype`, including the capability bits.
    pub cpusubtype: u32,
    /// Offset of the slice in the file.
    pub offset: u32,
    /// Size of the slice in bytes.
    pub size: u32,
    /// Alignment of the slice as a power of two.
    pub align: u32,
}

/// `struct mach_header_64` (or `struct mach_header`, widened).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MachHeader {
    /// `MH_MAGIC_64` or `MH_MAGIC`.
    pub magic: u32,
    /// `cputype`.
    pub cputype: u32,
    /// `cpusubtype`, including the capability bits.
    pub cpusubtype: u32,
    /// `filetype`.
    pub filetype: u32,
    /// `ncmds`.
    pub ncmds: u32,
    /// `sizeofcmds`.
    pub sizeofcmds: u32,
    /// `flags`.
    pub flags: u32,
}

impl MachHeader {
    /// `sizeof` the header this magic denotes.
    pub fn size(&self) -> u64 {
        if self.magic == MH_MAGIC_64 {
            MACH_HEADER_64_SIZE
        } else {
            MACH_HEADER_SIZE
        }
    }

    /// Whether the CPU type selects a 64-bit ABI.
    pub fn is_64bit(&self) -> bool {
        self.cputype & CPU_ARCH_ABI64 != 0
    }
}

/// `struct section_64`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Section {
    /// `sectname`, without trailing NULs.
    pub sectname: String,
    /// `segname`, without trailing NULs.
    pub segname: String,
    /// `addr`.
    pub addr: u64,
    /// `size`.
    pub size: u64,
    /// `offset`.
    pub offset: u32,
    /// `align` (power of two).
    pub align: u32,
    /// `flags`.
    pub flags: u32,
}

/// `struct segment_command_64`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Segment {
    /// `segname`, without trailing NULs.
    pub segname: String,
    /// `vmaddr`.
    pub vmaddr: u64,
    /// `vmsize`.
    pub vmsize: u64,
    /// `fileoff`, relative to the slice.
    pub fileoff: u64,
    /// `filesize`.
    pub filesize: u64,
    /// `maxprot`.
    pub maxprot: u32,
    /// `initprot`.
    pub initprot: u32,
    /// `nsects`.
    pub nsects: u32,
    /// `flags`.
    pub flags: u32,
    /// The sections that follow the command.
    pub sections: Vec<Section>,
}

/// The register state an `LC_UNIXTHREAD` command supplies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ThreadState {
    /// `x86_THREAD_STATE64` or `x86_THREAD_FULL_STATE64`: `rax`, `rbx`,
    /// `rcx`, `rdx`, `rdi`, `rsi`, `rbp`, `rsp`, `r8`-`r15`, `rip`,
    /// `rflags`, `cs`, `fs`, `gs`.
    X86_64 {
        /// The flavor the command used.
        flavor: u32,
        /// The 21 registers in `x86_thread_state64_t` order.
        regs: [u64; 21],
    },
    /// `ARM_THREAD_STATE64`: X0-X28, FP, LR, SP, PC, and CPSR.
    Arm64 {
        /// X0-X28, FP (X29), and LR (X30).
        x: [u64; 31],
        /// SP.
        sp: u64,
        /// PC.
        pc: u64,
        /// CPSR.
        cpsr: u32,
    },
}

impl ThreadState {
    /// The instruction pointer the state selects.
    pub fn pc(&self) -> u64 {
        match self {
            ThreadState::X86_64 { regs, .. } => regs[16],
            ThreadState::Arm64 { pc, .. } => *pc,
        }
    }

    /// The stack pointer the state selects.
    pub fn sp(&self) -> u64 {
        match self {
            ThreadState::X86_64 { regs, .. } => regs[7],
            ThreadState::Arm64 { sp, .. } => *sp,
        }
    }
}

/// How the image starts executing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EntryCommand {
    /// `LC_MAIN`: the dynamic linker calls `entryoff` (relative to the
    /// `__TEXT` segment); the kernel uses only `stacksize`.
    Main {
        /// Offset of `main` in `__TEXT`.
        entryoff: u64,
        /// Requested main-thread stack size, or zero for the default.
        stacksize: u64,
    },
    /// `LC_UNIXTHREAD`: the register state of the initial thread.
    UnixThread(ThreadState),
}

/// The platform and versions an image was built for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BuildVersion {
    /// `PLATFORM_*`.
    pub platform: u32,
    /// Minimum OS version, `xxxx.yy.zz` nibble-encoded.
    pub minos: u32,
    /// SDK version, same encoding.
    pub sdk: u32,
}

/// `struct encryption_info_command(_64)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncryptionInfo {
    /// `cryptoff`.
    pub cryptoff: u32,
    /// `cryptsize`.
    pub cryptsize: u32,
    /// `cryptid`: 0 unencrypted, 1 FairPlay, 0x10 the null crypter.
    pub cryptid: u32,
}

/// `struct linkedit_data_command`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkeditData {
    /// `dataoff`.
    pub dataoff: u32,
    /// `datasize`.
    pub datasize: u32,
}

/// A load command the parser does not interpret, kept for tools.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawCommand {
    /// `cmd`.
    pub cmd: u32,
    /// Offset of the command in the slice.
    pub offset: u64,
    /// `cmdsize`.
    pub cmdsize: u32,
}

/// Reads a fixed-size, NUL-padded Mach-O name.
pub(crate) fn fixed_name(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// Compares a NUL-padded 16-byte name with `name` as `strncmp(a, b, 16)`.
pub(crate) fn name_is(stored: &str, name: &str) -> bool {
    stored == name
}
