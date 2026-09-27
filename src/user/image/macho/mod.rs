//! Mach-O executable parser with XNU `exec_mach_imgact` acceptance semantics.
//!
//! XNU (`bsd/kern/kern_exec.c`, `bsd/kern/mach_fat.c`, and
//! `bsd/kern/mach_loader.c`, 12377.121.6) accepts an executable in stages:
//!
//! 1. `exec_fat_imgact` validates a fat header's architecture table
//!    (`fatfile_validate_fatarches`, over the first page of the file) and
//!    picks the best-graded slice (`fatfile_getbestarch`);
//! 2. `exec_mach_imgact` claims a thin `MH_MAGIC`/`MH_MAGIC_64` image of type
//!    `MH_EXECUTE` whose CPU type the machine grades as runnable;
//! 3. `parse_machfile` walks the load commands in four passes: version
//!    commands (pass 0); `LC_UNIXTHREAD`, `LC_MAIN`, `LC_UUID`, and
//!    `LC_CODE_SIGNATURE` (pass 1); segments through `load_segment`
//!    (pass 2); and the dynamic linker, encryption, and the entry-point and
//!    header-segment checks (pass 3);
//! 4. `load_machfile` requires a hard page zero.
//!
//! [`MachOImage::parse`] performs stages 2-4 for one image (the main
//! executable at depth 1 or `dyld` at depth 2) and returns both the decoded
//! commands and the exact mappings `load_segment` would make, without
//! touching an address space. [`select_slice`] performs stage 1. Mapping,
//! the stack, and the dynamic linker's placement belong to the Darwin
//! personality's loader.
//!
//! The kernel is modelled as a DEVELOPMENT build in one respect: static
//! (non-`MH_DYLDLINK`) arm64 executables are accepted, as they are there,
//! so that programs without `dyld` can run. Code signatures are not
//! validated (a kernel without global code-signing enforcement ignores
//! signature errors); FairPlay-encrypted images are rejected because
//! nothing can decrypt them.
//!
//! All offset and size arithmetic is checked: a hostile image produces an
//! error, never a panic or an out-of-bounds slice.

mod types;

#[cfg(test)]
mod tests;

pub use types::*;

use std::fmt;

/// The kernel's classification of a load failure (`LOAD_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoadReturn {
    /// `LOAD_BADARCH`: no runnable CPU type (`EBADARCH`).
    BadArch,
    /// `LOAD_BADMACHO`: malformed image (`EBADMACHO`).
    BadMachO,
    /// `LOAD_FAILURE`: otherwise unacceptable (`EBADEXEC`).
    Failure,
    /// `LOAD_DECRYPTFAIL`: encrypted with keys the system lacks (`EAUTH`).
    DecryptFail,
}

/// Why an image is rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MachOError {
    /// Neither a fat header nor a Mach-O header: no image activator claims
    /// the file (`ENOEXEC`).
    NotMachO,
    /// A reverse-endian Mach-O header (`EBADARCH`).
    ReverseEndian,
    /// A 32-bit (`MH_MAGIC`) image; RAX emulates only 64-bit processes.
    Unsupported32Bit,
    /// The file is shorter than a structure that must be read.
    Truncated {
        /// Bytes required.
        needed: u64,
        /// Bytes present.
        available: u64,
    },
    /// A rejection the kernel makes, with the reason.
    Load(LoadReturn, &'static str),
}

impl MachOError {
    /// The Darwin `errno` `execve` returns for this rejection.
    pub fn errno(&self) -> i32 {
        match self {
            MachOError::NotMachO => 8,          // ENOEXEC
            MachOError::ReverseEndian => 86,    // EBADARCH
            MachOError::Unsupported32Bit => 86, // EBADARCH
            MachOError::Truncated { .. } => 88, // EBADMACHO
            MachOError::Load(LoadReturn::BadArch, _) => 86,
            MachOError::Load(LoadReturn::BadMachO, _) => 88,
            MachOError::Load(LoadReturn::Failure, _) => 85, // EBADEXEC
            MachOError::Load(LoadReturn::DecryptFail, _) => 80, // EAUTH
        }
    }
}

impl fmt::Display for MachOError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MachOError::NotMachO => f.write_str("not a Mach-O image"),
            MachOError::ReverseEndian => f.write_str("reverse-endian Mach-O image"),
            MachOError::Unsupported32Bit => f.write_str("32-bit Mach-O images are not supported"),
            MachOError::Truncated { needed, available } => write!(
                f,
                "truncated Mach-O image: need {needed} bytes, file has {available}"
            ),
            MachOError::Load(kind, why) => {
                let what = match kind {
                    LoadReturn::BadArch => "bad CPU type in executable",
                    LoadReturn::BadMachO => "malformed Mach-O image",
                    LoadReturn::Failure => "bad executable",
                    LoadReturn::DecryptFail => "encrypted executable",
                };
                write!(f, "{what}: {why}")
            }
        }
    }
}

impl std::error::Error for MachOError {}

fn bad_macho(why: &'static str) -> MachOError {
    MachOError::Load(LoadReturn::BadMachO, why)
}

fn failure(why: &'static str) -> MachOError {
    MachOError::Load(LoadReturn::Failure, why)
}

fn bad_arch(why: &'static str) -> MachOError {
    MachOError::Load(LoadReturn::BadArch, why)
}

/// Bounds-checked little- and big-endian field reader.
#[derive(Clone, Copy)]
struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    fn slice(&self, off: u64, len: u64) -> Result<&'a [u8], MachOError> {
        let available = self.bytes.len() as u64;
        match off.checked_add(len) {
            Some(end) if end <= available => Ok(&self.bytes[off as usize..end as usize]),
            Some(end) => Err(MachOError::Truncated {
                needed: end,
                available,
            }),
            None => Err(MachOError::Truncated {
                needed: u64::MAX,
                available,
            }),
        }
    }

    fn u32(&self, off: u64) -> Result<u32, MachOError> {
        let b: [u8; 4] = self.slice(off, 4)?.try_into().expect("length checked");
        Ok(u32::from_le_bytes(b))
    }

    fn u32_be(&self, off: u64) -> Result<u32, MachOError> {
        let b: [u8; 4] = self.slice(off, 4)?.try_into().expect("length checked");
        Ok(u32::from_be_bytes(b))
    }

    fn u64(&self, off: u64) -> Result<u64, MachOError> {
        let b: [u8; 8] = self.slice(off, 8)?.try_into().expect("length checked");
        Ok(u64::from_le_bytes(b))
    }
}

/// What the first bytes of a file are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Identity {
    /// A fat (universal) file.
    Fat,
    /// A thin Mach-O image with this header.
    Thin(MachHeader),
}

/// Whether `bytes` begin with a Mach-O or fat magic number (in either byte
/// order), so a Darwin personality should claim the file.
pub fn is_macho(bytes: &[u8]) -> bool {
    if bytes.len() < 4 {
        return false;
    }
    let le = u32::from_le_bytes(bytes[..4].try_into().expect("four bytes"));
    let be = u32::from_be_bytes(bytes[..4].try_into().expect("four bytes"));
    matches!(le, MH_MAGIC | MH_MAGIC_64 | MH_CIGAM | MH_CIGAM_64) || be == FAT_MAGIC
}

/// Classifies a file the way `exec_activate_image` tries its activators:
/// a big-endian `FAT_MAGIC` is a fat file; `MH_MAGIC`/`MH_MAGIC_64` a thin
/// image; `MH_CIGAM`/`MH_CIGAM_64` is recognized but refused.
pub fn identify(bytes: &[u8]) -> Result<Identity, MachOError> {
    let r = Reader { bytes };
    let magic_be = r.u32_be(0).map_err(|_| MachOError::NotMachO)?;
    if magic_be == FAT_MAGIC {
        return Ok(Identity::Fat);
    }
    let magic = r.u32(0).map_err(|_| MachOError::NotMachO)?;
    match magic {
        MH_CIGAM | MH_CIGAM_64 => Err(MachOError::ReverseEndian),
        MH_MAGIC | MH_MAGIC_64 => Ok(Identity::Thin(read_header(bytes)?)),
        _ => Err(MachOError::NotMachO),
    }
}

/// Reads a (thin) Mach-O header.
pub fn read_header(bytes: &[u8]) -> Result<MachHeader, MachOError> {
    let r = Reader { bytes };
    let magic = r.u32(0)?;
    Ok(MachHeader {
        magic,
        cputype: r.u32(4)?,
        cpusubtype: r.u32(8)?,
        filetype: r.u32(12)?,
        ncmds: r.u32(16)?,
        sizeofcmds: r.u32(20)?,
        flags: r.u32(24)?,
    })
}

/// The CPU an emulated kernel runs on, for grading images.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostCpu {
    /// `cpu_type()`.
    pub cputype: u32,
    /// `cpu_subtype()`.
    pub cpusubtype: u32,
}

impl HostCpu {
    /// An Apple silicon Mac: arm64e with pointer authentication.
    pub const ARM64E: HostCpu = HostCpu {
        cputype: CPU_TYPE_ARM64,
        cpusubtype: CPU_SUBTYPE_ARM64E,
    };
    /// An Intel Mac with the Haswell feature subset.
    pub const X86_64H: HostCpu = HostCpu {
        cputype: CPU_TYPE_X86_64,
        cpusubtype: CPU_SUBTYPE_X86_64_H,
    };
    /// An Intel Mac without the Haswell feature subset.
    pub const X86_64: HostCpu = HostCpu {
        cputype: CPU_TYPE_X86_64,
        cpusubtype: CPU_SUBTYPE_X86_ARCH1,
    };

    /// The kernel's page size on this machine: 16 KiB on Apple silicon,
    /// 4 KiB on Intel.
    pub fn page_size(&self) -> u64 {
        if self.cputype == CPU_TYPE_ARM64 {
            16 << 10
        } else {
            4 << 10
        }
    }
}

/// `ml_grade_binary`: the preference for running an image of this CPU type
/// and subtype on `host`; zero means it cannot run. `subtype` excludes the
/// capability bits, `features` holds only them.
pub fn grade(host: HostCpu, cputype: u32, subtype: u32, features: u32) -> u32 {
    match (host.cputype, cputype) {
        (CPU_TYPE_ARM64, CPU_TYPE_ARM64) => match host.cpusubtype {
            CPU_SUBTYPE_ARM64_V8 => match subtype {
                CPU_SUBTYPE_ARM64_V8 => 10,
                CPU_SUBTYPE_ARM64_ALL => 9,
                _ => 0,
            },
            CPU_SUBTYPE_ARM64E => match subtype {
                // grade_arm64e_binary (macOS): the preferred ABI versions
                // outrank arm64; others still run.
                CPU_SUBTYPE_ARM64E => {
                    if (features & CPU_SUBTYPE_ARM64_PTR_AUTH_MASK) >> 24
                        <= CPU_SUBTYPE_ARM64_PTR_AUTH_MAX_PREFERRED_VERSION
                    {
                        12
                    } else {
                        11
                    }
                }
                CPU_SUBTYPE_ARM64_V8 => 10,
                CPU_SUBTYPE_ARM64_ALL => 9,
                _ => 0,
            },
            _ => 0,
        },
        (CPU_TYPE_X86_64, CPU_TYPE_X86_64) => match host.cpusubtype {
            CPU_SUBTYPE_X86_64_H => match subtype {
                CPU_SUBTYPE_X86_64_H => 3,
                CPU_SUBTYPE_X86_64_ALL => 2,
                _ => 0,
            },
            CPU_SUBTYPE_X86_ARCH1 => match subtype {
                CPU_SUBTYPE_X86_64_ALL => 2,
                _ => 0,
            },
            _ => 0,
        },
        _ => 0,
    }
}

/// `fatfile_validate_fatarches` followed by reading the table: the header
/// data is the file's first `page_size` bytes (zero-filled past the end of a
/// shorter file), every slice must lie after the table and inside the file,
/// no two may overlap, and no CPU type/subtype pair may repeat.
pub fn fat_arches(bytes: &[u8], page_size: u64) -> Result<Vec<FatArch>, MachOError> {
    let r = Reader { bytes };
    if r.u32_be(0).map_err(|_| MachOError::NotMachO)? != FAT_MAGIC {
        return Err(MachOError::NotMachO);
    }
    let file_size = bytes.len() as u64;
    let nfat = u64::from(r.u32_be(4).map_err(|_| failure("short fat header"))?);
    let max = (page_size - FAT_HEADER_SIZE) / FAT_ARCH_SIZE;
    if nfat > max {
        return Err(bad_macho("fat architecture count exceeds the header page"));
    }
    // Entries past the end of a short file read as zero, as the kernel's
    // zero-filled header page does.
    let word = |off: u64| -> u32 {
        let mut b = [0u8; 4];
        for (i, byte) in b.iter_mut().enumerate() {
            *byte = bytes.get((off + i as u64) as usize).copied().unwrap_or(0);
        }
        u32::from_be_bytes(b)
    };
    let header_size = FAT_HEADER_SIZE + nfat * FAT_ARCH_SIZE;
    let arches: Vec<FatArch> = (0..nfat)
        .map(|i| {
            let base = FAT_HEADER_SIZE + i * FAT_ARCH_SIZE;
            FatArch {
                cputype: word(base),
                cpusubtype: word(base + 4),
                offset: word(base + 8),
                size: word(base + 12),
                align: word(base + 16),
            }
        })
        .collect();
    for (i, a) in arches.iter().enumerate() {
        if u64::from(a.offset) < header_size {
            return Err(bad_macho("fat slice overlaps the fat header"));
        }
        let a_end = a
            .offset
            .checked_add(a.size)
            .ok_or_else(|| bad_macho("fat slice end overflows"))?;
        if u64::from(a_end) > file_size {
            return Err(bad_macho("fat slice extends past the end of the file"));
        }
        for b in &arches[i + 1..] {
            if a.cputype == b.cputype && a.cpusubtype == b.cpusubtype {
                return Err(bad_macho("duplicate fat slice CPU type"));
            }
            let b_end = b
                .offset
                .checked_add(b.size)
                .ok_or_else(|| bad_macho("fat slice end overflows"))?;
            let overlap = if a.offset <= b.offset {
                a_end > b.offset
            } else {
                a.offset < b_end
            };
            if overlap {
                return Err(bad_macho("overlapping fat slices"));
            }
        }
    }
    Ok(arches)
}

/// `fatfile_getbestarch`: the highest-graded slice whose CPU type matches
/// `host` ignoring the ABI bits.
pub fn best_arch(arches: &[FatArch], host: HostCpu) -> Result<FatArch, MachOError> {
    let mut best: Option<(u32, FatArch)> = None;
    for a in arches {
        if a.cputype & !CPU_ARCH_MASK != host.cputype & !CPU_ARCH_MASK {
            continue;
        }
        let g = grade(
            host,
            a.cputype,
            a.cpusubtype & !CPU_SUBTYPE_MASK,
            a.cpusubtype & CPU_SUBTYPE_MASK,
        );
        if g > best.map_or(0, |(bg, _)| bg) {
            best = Some((g, *a));
        }
    }
    best.map(|(_, a)| a)
        .ok_or_else(|| bad_arch("no slice for this CPU"))
}

/// `fatfile_getbestarch_for_cputype`: the highest-graded slice with exactly
/// this CPU type (the kernel's choice of `dyld` slice).
pub fn arch_for_cputype(
    arches: &[FatArch],
    host: HostCpu,
    cputype: u32,
) -> Result<FatArch, MachOError> {
    let mut best: Option<(u32, FatArch)> = None;
    for a in arches {
        if a.cputype != cputype {
            continue;
        }
        let g = grade(
            host,
            a.cputype,
            a.cpusubtype & !CPU_SUBTYPE_MASK,
            a.cpusubtype & CPU_SUBTYPE_MASK,
        );
        if g > best.map_or(0, |(bg, _)| bg) {
            best = Some((g, *a));
        }
    }
    best.map(|(_, a)| a)
        .ok_or_else(|| bad_arch("no slice for this CPU type"))
}

/// The slice of `bytes` the kernel executes on `host`: the whole file for a
/// thin image, the best-graded slice of a fat one. Returns the slice's
/// offset and bytes.
pub fn select_slice(bytes: &[u8], host: HostCpu) -> Result<(u64, &[u8]), MachOError> {
    match identify(bytes)? {
        Identity::Thin(_) => Ok((0, bytes)),
        Identity::Fat => {
            let arches = fat_arches(bytes, host.page_size())?;
            let arch = best_arch(&arches, host)?;
            let start = arch.offset as usize;
            let slice = &bytes[start..start + arch.size as usize];
            // A fat file inside a fat file is not claimed.
            match identify(slice) {
                Ok(Identity::Thin(h)) => {
                    // exec_mach_imgact: the thin header must agree with the
                    // fat table.
                    if h.cputype != arch.cputype || h.cpusubtype != arch.cpusubtype {
                        return Err(bad_arch("slice header disagrees with the fat table"));
                    }
                    Ok((u64::from(arch.offset), slice))
                }
                Ok(Identity::Fat) => Err(MachOError::NotMachO),
                Err(e) => Err(e),
            }
        }
    }
}

/// Which image of a process is being loaded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImageRole {
    /// The main executable (`parse_machfile` depth 1).
    Executable,
    /// The dynamic linker (`parse_machfile` depth 2).
    Dylinker {
        /// The main executable's `max_vm_addr`, where a `dyld` without a
        /// load address is placed.
        main_max_vm_addr: u64,
    },
}

/// Parameters of one image load.
#[derive(Clone, Copy, Debug)]
pub struct LoadOptions {
    /// The machine.
    pub host: HostCpu,
    /// Which image this is.
    pub role: ImageRole,
    /// The ASLR slide for PIE executables and `dyld` (zero with ASLR
    /// disabled).
    pub slide: u64,
    /// Offset of the image in its file (a fat slice's offset); segment file
    /// offsets must be page-aligned in the file, not only in the slice.
    pub slice_offset: u64,
}

/// One segment's mappings: `map_segment` of the file pages, then an
/// anonymous zero-fill mapping for the rest of the segment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SegmentMapping {
    /// The segment's name.
    pub segname: String,
    /// First mapped address (page-aligned).
    pub vm_start: u64,
    /// Offset in the slice of the first file byte mapped (page-aligned).
    pub file_start: u64,
    /// Bytes mapped from the file at `vm_start` (page-aligned; the file
    /// range rounded out to pages, which may exceed the segment's size).
    pub file_len: u64,
    /// Zero-filled bytes after the file part (page-aligned).
    pub zero_len: u64,
    /// `initprot & VM_PROT_ALL`.
    pub initprot: u32,
    /// `maxprot & VM_PROT_ALL`.
    pub maxprot: u32,
}

impl SegmentMapping {
    /// End of the mapping's highest byte plus one.
    pub fn end(&self) -> u64 {
        self.vm_start + self.file_len + self.zero_len
    }
}

/// A parsed image and the mappings loading it makes.
#[derive(Clone, Debug)]
pub struct MachOImage {
    /// The header.
    pub header: MachHeader,
    /// The 64-bit segments in command order.
    pub segments: Vec<Segment>,
    /// `LC_MAIN` or `LC_UNIXTHREAD`.
    pub entry: Option<EntryCommand>,
    /// `LC_LOAD_DYLINKER`'s path.
    pub dylinker: Option<String>,
    /// `LC_ID_DYLINKER`'s path.
    pub dylinker_id: Option<String>,
    /// `LC_UUID`.
    pub uuid: Option<[u8; 16]>,
    /// `LC_BUILD_VERSION` or `LC_VERSION_MIN_*`.
    pub build: Option<BuildVersion>,
    /// `LC_CODE_SIGNATURE`.
    pub code_signature: Option<LinkeditData>,
    /// `LC_ENCRYPTION_INFO(_64)`.
    pub encryption: Option<EncryptionInfo>,
    /// Every load command, in order.
    pub commands: Vec<RawCommand>,
    /// The slide applied.
    pub slide: u64,
    /// The mappings, in segment order.
    pub mappings: Vec<SegmentMapping>,
    /// End of the page-zero reservation (the map's raised minimum address).
    pub pagezero_end: u64,
    /// Address of the Mach-O header in memory.
    pub mach_header: u64,
    /// Lowest segment address.
    pub min_vm_addr: u64,
    /// End of the highest segment.
    pub max_vm_addr: u64,
    /// `LC_UNIXTHREAD`'s entry point, slid.
    pub entry_point: Option<u64>,
    /// The initial stack top: `LC_UNIXTHREAD`'s stack pointer or the default
    /// `USRSTACK64`, slid down and truncated to a page.
    pub user_stack: u64,
    /// Whether the image chose the stack (`LC_MAIN` stack size or an
    /// `LC_UNIXTHREAD` stack pointer).
    pub custom_stack: bool,
    /// Bytes to reserve below `user_stack` (the maximum stack plus guard);
    /// zero when an `LC_UNIXTHREAD` stack pointer supplies the stack.
    pub user_stack_alloc_size: u64,
    /// `LC_MAIN`'s stack size, or zero.
    pub user_stack_size: u64,
    /// `dyld`'s `__DATA,__all_image_info` section (address, size), slid.
    pub all_image_info: Option<(u64, u64)>,
    /// The `SG_READ_ONLY` segment's range.
    pub ro_range: Option<(u64, u64)>,
}

/// `USRSTACK64` on Apple silicon.
pub const USRSTACK64_ARM64: u64 = 0x0000_0001_6FE0_0000;
/// `VM_USRSTACK64` on Intel: `0x00007FF7C0000000 - 1 MiB`.
pub const USRSTACK64_X86_64: u64 = 0x0000_7FF7_C000_0000 - (1 << 20);
/// `MAXSSIZ`: the largest stack, 64 MiB.
pub const MAXSSIZ: u64 = 64 << 20;

fn round_up(v: u64, mask: u64) -> Option<u64> {
    v.checked_add(mask).map(|x| x & !mask)
}

/// The walk `parse_machfile` repeats in each pass.
struct Walk<'a> {
    r: Reader<'a>,
    /// `(cmd, offset, cmdsize)` of every command.
    cmds: Vec<(u32, u64, u32)>,
    opts: LoadOptions,
    page_mask: u64,
    is_dyld: bool,
    needs_dynlinker: bool,
    thread_count: u32,
    using_lcmain: bool,
    valid_entry: bool,
}

impl MachOImage {
    /// Parses and plans the load of the thin image `bytes` (a whole file, or
    /// a fat file's slice) as `exec_mach_imgact`, `parse_machfile`, and
    /// `load_machfile` would.
    pub fn parse(bytes: &[u8], opts: &LoadOptions) -> Result<Self, MachOError> {
        let header = match identify(bytes)? {
            Identity::Thin(h) => h,
            Identity::Fat => return Err(MachOError::NotMachO),
        };
        if header.magic == MH_MAGIC {
            return Err(MachOError::Unsupported32Bit);
        }
        let host = opts.host;
        let is_dyld = matches!(opts.role, ImageRole::Dylinker { .. });
        // exec_mach_imgact claims only MH_EXECUTE images as programs.
        if !is_dyld && header.filetype != MH_EXECUTE {
            return Err(MachOError::NotMachO);
        }
        if header.cputype & !CPU_ARCH_MASK != host.cputype & !CPU_ARCH_MASK {
            return Err(bad_arch("CPU type does not match the machine"));
        }
        if grade(
            host,
            header.cputype,
            header.cpusubtype & !CPU_SUBTYPE_MASK,
            header.cpusubtype & CPU_SUBTYPE_MASK,
        ) == 0
        {
            return Err(bad_arch("CPU subtype cannot run on the machine"));
        }
        let mut needs_dynlinker = false;
        match header.filetype {
            MH_EXECUTE if !is_dyld => {
                if header.flags & MH_DYLDLINK != 0 {
                    if header.flags & MH_PIE == 0 && header.cputype == CPU_TYPE_ARM64 {
                        return Err(failure("dynamic arm64 executables must be PIE"));
                    }
                    needs_dynlinker = true;
                }
                // Static executables are allowed for x86-64 and, as on a
                // DEVELOPMENT kernel, for arm64.
            }
            MH_DYLINKER if is_dyld => {}
            _ => return Err(failure("unexpected file type at this depth")),
        }

        let cmds_size = header
            .size()
            .checked_add(u64::from(header.sizeofcmds))
            .filter(|&s| s <= bytes.len() as u64)
            .ok_or_else(|| bad_macho("load commands extend past the image"))?;
        let r = Reader { bytes };
        let mut cmds = Vec::with_capacity(header.ncmds.min(4096) as usize);
        let mut offset = header.size();
        for _ in 0..header.ncmds {
            if offset + LOAD_COMMAND_SIZE > cmds_size {
                return Err(bad_macho("load command table is truncated"));
            }
            let cmd = r.u32(offset)?;
            let cmdsize = r.u32(offset + 4)?;
            let next = offset + u64::from(cmdsize);
            if u64::from(cmdsize) < LOAD_COMMAND_SIZE || next > cmds_size {
                return Err(bad_macho("load command size is invalid"));
            }
            cmds.push((cmd, offset, cmdsize));
            offset = next;
        }

        let mut image = MachOImage {
            header,
            segments: Vec::new(),
            entry: None,
            dylinker: None,
            dylinker_id: None,
            uuid: None,
            build: None,
            code_signature: None,
            encryption: None,
            commands: cmds
                .iter()
                .map(|&(cmd, offset, cmdsize)| RawCommand {
                    cmd,
                    offset,
                    cmdsize,
                })
                .collect(),
            slide: if header.flags & MH_PIE != 0 || is_dyld {
                opts.slide
            } else {
                0
            },
            mappings: Vec::new(),
            pagezero_end: 0,
            mach_header: 0,
            min_vm_addr: u64::MAX,
            max_vm_addr: 0,
            entry_point: None,
            user_stack: 0,
            custom_stack: false,
            user_stack_alloc_size: 0,
            user_stack_size: 0,
            all_image_info: None,
            ro_range: None,
        };
        let mut walk = Walk {
            r,
            cmds,
            opts: *opts,
            page_mask: host.page_size() - 1,
            is_dyld,
            needs_dynlinker,
            thread_count: 0,
            using_lcmain: false,
            valid_entry: false,
        };
        image.pass0(&mut walk)?;
        image.pass1(&mut walk)?;
        image.pass2(&mut walk)?;
        image.pass3(&mut walk)?;

        if walk.needs_dynlinker && image.dylinker.is_none() {
            return Err(failure("a dynamic executable names no dynamic linker"));
        }
        if !is_dyld {
            if walk.thread_count == 0 {
                return Err(failure("no initial thread"));
            }
            // load_machfile: a hard page zero covering the 32-bit address
            // space for arm64, at least one page for x86-64.
            let need = if header.cputype == CPU_TYPE_ARM64 {
                1 << 32
            } else {
                0x1000
            };
            if image.pagezero_end < need {
                return Err(bad_macho("no hard page zero"));
            }
        }
        if image.min_vm_addr == u64::MAX {
            image.min_vm_addr = 0;
        }
        Ok(image)
    }

    /// Pass 0: a `dyld` without a load address; the version commands.
    fn pass0(&mut self, w: &mut Walk<'_>) -> Result<(), MachOError> {
        let r = w.r;
        let mut dyld_no_load_addr = false;
        let mut found_version = false;
        for &(cmd, off, size) in &w.cmds {
            match cmd {
                LC_SEGMENT_64 => {
                    if u64::from(size) < SEGMENT_COMMAND_64_SIZE {
                        return Err(bad_macho("segment command is too small"));
                    }
                    if w.is_dyld && r.u64(off + 24)? == 0 && r.u64(off + 40)? == 0 {
                        dyld_no_load_addr = true;
                    }
                }
                LC_SEGMENT => {
                    if u64::from(size) < SEGMENT_COMMAND_SIZE {
                        return Err(bad_macho("segment command is too small"));
                    }
                }
                LC_VERSION_MIN_MACOSX
                | LC_VERSION_MIN_IPHONEOS
                | LC_VERSION_MIN_WATCHOS
                | LC_VERSION_MIN_TVOS
                    if !w.is_dyld =>
                {
                    if u64::from(size) < VERSION_MIN_COMMAND_SIZE {
                        return Err(bad_macho("version command is too small"));
                    }
                    if found_version {
                        return Err(bad_macho("more than one version command"));
                    }
                    found_version = true;
                    let platform = match cmd {
                        LC_VERSION_MIN_MACOSX => PLATFORM_MACOS,
                        LC_VERSION_MIN_IPHONEOS => PLATFORM_IOS,
                        LC_VERSION_MIN_WATCHOS => PLATFORM_WATCHOS,
                        _ => PLATFORM_TVOS,
                    };
                    self.build = Some(BuildVersion {
                        platform,
                        minos: r.u32(off + 8)?,
                        sdk: r.u32(off + 12)?,
                    });
                }
                LC_BUILD_VERSION if !w.is_dyld => {
                    if u64::from(size) < BUILD_VERSION_COMMAND_SIZE {
                        return Err(bad_macho("build version command is too small"));
                    }
                    if found_version {
                        return Err(bad_macho("more than one version command"));
                    }
                    found_version = true;
                    self.build = Some(BuildVersion {
                        platform: r.u32(off + 8)?,
                        minos: r.u32(off + 12)?,
                        sdk: r.u32(off + 16)?,
                    });
                }
                _ => {}
            }
        }
        // A dyld linked at zero goes right after the main executable.
        if let ImageRole::Dylinker { main_max_vm_addr } = w.opts.role
            && dyld_no_load_addr
        {
            self.slide = round_up(self.slide.wrapping_add(main_max_vm_addr), w.page_mask)
                .ok_or_else(|| bad_macho("dyld placement overflows"))?;
        }
        Ok(())
    }

    /// Pass 1: the initial thread (`LC_UNIXTHREAD`, `LC_MAIN`), the UUID,
    /// and the code signature.
    fn pass1(&mut self, w: &mut Walk<'_>) -> Result<(), MachOError> {
        let r = w.r;
        let host = w.opts.host;
        let default_stack = if host.cputype == CPU_TYPE_ARM64 {
            USRSTACK64_ARM64
        } else {
            USRSTACK64_X86_64
        };
        let page_mask = w.page_mask;
        for &(cmd, off, size) in &w.cmds {
            match cmd {
                LC_UNIXTHREAD => {
                    if w.thread_count != 0 {
                        return Err(failure("more than one initial thread"));
                    }
                    let (state, sp, pc) = parse_thread_state(
                        &r,
                        off + THREAD_COMMAND_SIZE,
                        u64::from(size) - THREAD_COMMAND_SIZE,
                        host,
                    )?;
                    if sp != 0 {
                        self.custom_stack = true;
                    } else {
                        self.user_stack_alloc_size = MAXSSIZ;
                    }
                    let sp = if sp != 0 { sp } else { default_stack };
                    self.user_stack = sp.wrapping_sub(self.slide) & !page_mask;
                    if w.using_lcmain || self.entry_point.is_some() {
                        return Err(failure("LC_MAIN and LC_UNIXTHREAD both present"));
                    }
                    self.entry_point = Some(pc.wrapping_add(self.slide));
                    self.entry = Some(EntryCommand::UnixThread(state));
                    w.thread_count += 1;
                }
                LC_MAIN if !w.is_dyld => {
                    if u64::from(size) < ENTRY_POINT_COMMAND_SIZE {
                        return Err(bad_macho("LC_MAIN is too small"));
                    }
                    if w.thread_count != 0 {
                        return Err(failure("more than one initial thread"));
                    }
                    let entryoff = r.u64(off + 8)?;
                    let stacksize = r.u64(off + 16)?;
                    if stacksize != 0 {
                        stacksize
                            .checked_add(4 * host.page_size())
                            .ok_or_else(|| bad_macho("LC_MAIN stack size overflows"))?;
                        self.user_stack_size = stacksize;
                        self.user_stack_alloc_size = stacksize
                            .checked_add(host.page_size())
                            .ok_or_else(|| bad_macho("LC_MAIN stack size overflows"))?;
                        self.custom_stack = true;
                    } else {
                        self.user_stack_alloc_size = MAXSSIZ;
                    }
                    self.user_stack = default_stack.wrapping_sub(self.slide) & !page_mask;
                    if w.using_lcmain || self.entry_point.is_some() {
                        return Err(failure("LC_MAIN and LC_UNIXTHREAD both present"));
                    }
                    w.needs_dynlinker = true;
                    w.using_lcmain = true;
                    self.entry = Some(EntryCommand::Main {
                        entryoff,
                        stacksize,
                    });
                    w.thread_count += 1;
                }
                LC_UUID if !w.is_dyld => {
                    if u64::from(size) < UUID_COMMAND_SIZE {
                        return Err(bad_macho("UUID command is too small"));
                    }
                    let mut uuid = [0u8; 16];
                    uuid.copy_from_slice(r.slice(off + 8, 16)?);
                    self.uuid = Some(uuid);
                }
                LC_CODE_SIGNATURE => {
                    // Signatures are recorded, not validated.
                    if u64::from(size) >= LINKEDIT_DATA_COMMAND_SIZE {
                        self.code_signature = Some(LinkeditData {
                            dataoff: r.u32(off + 8)?,
                            datasize: r.u32(off + 12)?,
                        });
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Pass 2: every segment through `load_segment`; exactly one readable,
    /// executable segment may map the start of the file.
    fn pass2(&mut self, w: &mut Walk<'_>) -> Result<(), MachOError> {
        let abi64 = self.header.is_64bit();
        let macho_size = w.r.bytes.len() as u64;
        let mut found_header_segment = false;
        let cmds = std::mem::take(&mut w.cmds);
        for &(cmd, off, size) in &cmds {
            match cmd {
                LC_SEGMENT if abi64 => {
                    return Err(bad_macho("32-bit segment in a 64-bit image"));
                }
                LC_SEGMENT_64 => {
                    if !abi64 {
                        return Err(bad_macho("64-bit segment in a 32-bit image"));
                    }
                    let seg = parse_segment(&w.r, off, size)?;
                    self.load_segment(&seg, w, macho_size)?;
                    if seg.fileoff == 0 && seg.filesize > 0 {
                        if found_header_segment
                            || seg.initprot & (VM_PROT_READ | VM_PROT_EXECUTE)
                                != VM_PROT_READ | VM_PROT_EXECUTE
                        {
                            return Err(bad_macho(
                                "the header segment must be unique, readable, and executable",
                            ));
                        }
                        found_header_segment = true;
                    }
                    self.segments.push(seg);
                }
                _ => {}
            }
        }
        w.cmds = cmds;
        if !w.using_lcmain && !w.valid_entry {
            return Err(failure("the entry point is not in an executable segment"));
        }
        if !found_header_segment {
            return Err(bad_macho("no segment maps the Mach-O header"));
        }
        Ok(())
    }

    /// Pass 3: the dynamic linker and encryption.
    fn pass3(&mut self, w: &mut Walk<'_>) -> Result<(), MachOError> {
        let r = w.r;
        for &(cmd, off, size) in &w.cmds {
            match cmd {
                LC_LOAD_DYLINKER => {
                    if w.is_dyld || self.dylinker.is_some() {
                        return Err(failure("unexpected LC_LOAD_DYLINKER"));
                    }
                    self.dylinker = Some(parse_dylinker(&r, off, size)?);
                }
                LC_ID_DYLINKER => {
                    self.dylinker_id = parse_dylinker(&r, off, size).ok();
                }
                LC_ENCRYPTION_INFO | LC_ENCRYPTION_INFO_64 => {
                    let min = if cmd == LC_ENCRYPTION_INFO_64 {
                        ENCRYPTION_INFO_COMMAND_64_SIZE
                    } else {
                        ENCRYPTION_INFO_COMMAND_SIZE
                    };
                    if u64::from(size) < min {
                        return Err(bad_macho("encryption command is too small"));
                    }
                    let info = EncryptionInfo {
                        cryptoff: r.u32(off + 8)?,
                        cryptsize: r.u32(off + 12)?,
                        cryptid: r.u32(off + 16)?,
                    };
                    match info.cryptid {
                        // Unencrypted; the null crypter leaves the bytes as
                        // they are; an empty FairPlay range is ignored.
                        0 | 0x10 => {}
                        1 if info.cryptsize == 0 => {}
                        1 => {
                            return Err(MachOError::Load(
                                LoadReturn::DecryptFail,
                                "FairPlay-encrypted image",
                            ));
                        }
                        _ => return Err(bad_macho("unknown encryption ID")),
                    }
                    self.encryption = Some(info);
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// `load_segment` for one 64-bit segment.
    fn load_segment(
        &mut self,
        seg: &Segment,
        w: &mut Walk<'_>,
        macho_size: u64,
    ) -> Result<(), MachOError> {
        let page_mask = w.page_mask;
        let slide = self.slide;
        let file_end_raw = seg
            .fileoff
            .checked_add(seg.filesize)
            .filter(|&e| e <= macho_size)
            .ok_or_else(|| bad_macho("segment extends past the image"))?;
        let file_offset = w
            .opts
            .slice_offset
            .checked_add(seg.fileoff)
            .ok_or_else(|| bad_macho("segment file offset overflows"))?;
        if file_offset & page_mask != 0 {
            return Err(bad_macho("segment is not page-aligned in the file"));
        }
        let vm_offset = seg
            .vmaddr
            .checked_add(slide)
            .ok_or_else(|| bad_macho("segment address overflows"))?;
        if seg.vmsize == 0 {
            return Ok(());
        }
        if seg.vmaddr == 0
            && seg.filesize == 0
            && seg.initprot & VM_PROT_ALL == 0
            && seg.maxprot & VM_PROT_ALL == 0
        {
            // Page zero raises the map's minimum address.
            let end = vm_offset
                .checked_add(seg.vmsize)
                .and_then(|e| round_up(e, page_mask))
                .ok_or_else(|| bad_macho("page zero overflows"))?;
            self.pagezero_end = self.pagezero_end.max(end);
            return Ok(());
        }
        let file_start = seg.fileoff & !page_mask;
        let file_end =
            round_up(file_end_raw, page_mask).ok_or_else(|| bad_macho("segment end overflows"))?;
        let vm_start = vm_offset & !page_mask;
        let vm_end = vm_offset
            .checked_add(seg.vmsize)
            .and_then(|e| round_up(e, page_mask))
            .ok_or_else(|| bad_macho("segment end overflows"))?;
        if seg.fileoff - file_start > page_mask || file_end - seg.fileoff - seg.filesize > page_mask
        {
            return Err(bad_macho("segment file range wraps"));
        }
        self.min_vm_addr = self.min_vm_addr.min(vm_start);
        self.max_vm_addr = self.max_vm_addr.max(vm_end);
        if seg.flags & SG_READ_ONLY != 0 {
            if self.ro_range.is_some() {
                return Err(bad_macho("more than one SG_READ_ONLY segment"));
            }
            self.ro_range = Some((vm_start, vm_end));
        }
        // map_segment maps the whole rounded file range, even past vm_end;
        // the rest of the segment is zero fill.
        let file_len = file_end - file_start;
        let zero_len = (vm_end - vm_start).saturating_sub(file_len);
        vm_start
            .checked_add(file_len)
            .and_then(|e| e.checked_add(zero_len))
            .ok_or_else(|| bad_macho("segment end overflows"))?;
        self.mappings.push(SegmentMapping {
            segname: seg.segname.clone(),
            vm_start,
            file_start,
            file_len,
            zero_len,
            initprot: seg.initprot & VM_PROT_ALL,
            maxprot: seg.maxprot & VM_PROT_ALL,
        });
        if seg.fileoff == 0 && seg.filesize != 0 {
            self.mach_header = vm_offset;
        }
        if self.header.filetype == MH_DYLINKER
            && self.all_image_info.is_none()
            && (seg.segname == "__DATA" || seg.segname == "__DATA_DIRTY")
            && let Some(s) = seg
                .sections
                .iter()
                .find(|s| s.sectname == "__all_image_info")
        {
            self.all_image_info = Some((s.addr.wrapping_add(slide), s.size));
        }
        // The entry point is valid when the last segment containing it is
        // readable and executable.
        if let Some(entry) = self.entry_point
            && entry != 0
            && entry >= vm_offset
            && entry - vm_offset < seg.vmsize
        {
            w.valid_entry =
                seg.initprot & (VM_PROT_READ | VM_PROT_EXECUTE) == VM_PROT_READ | VM_PROT_EXECUTE;
        }
        Ok(())
    }

    /// The segment named `name`.
    pub fn segment(&self, name: &str) -> Option<&Segment> {
        self.segments.iter().find(|s| name_is(&s.segname, name))
    }

    /// The section `segname,sectname`.
    pub fn section(&self, segname: &str, sectname: &str) -> Option<&Section> {
        self.segment(segname)?
            .sections
            .iter()
            .find(|s| name_is(&s.sectname, sectname))
    }

    /// The address `LC_MAIN` names: its offset from the start of `__TEXT`.
    pub fn main_address(&self) -> Option<u64> {
        match self.entry {
            Some(EntryCommand::Main { entryoff, .. }) => {
                let text = self.segment("__TEXT")?;
                Some(text.vmaddr.wrapping_add(self.slide).wrapping_add(entryoff))
            }
            _ => None,
        }
    }
}

fn parse_segment(r: &Reader<'_>, off: u64, size: u32) -> Result<Segment, MachOError> {
    if u64::from(size) < SEGMENT_COMMAND_64_SIZE {
        return Err(bad_macho("segment command is too small"));
    }
    let nsects = r.u32(off + 64)?;
    let room = u64::from(size) - SEGMENT_COMMAND_64_SIZE;
    if room / SECTION_64_SIZE < u64::from(nsects) {
        return Err(bad_macho("sections do not fit the segment command"));
    }
    let mut sections = Vec::with_capacity(nsects as usize);
    for i in 0..u64::from(nsects) {
        let s = off + SEGMENT_COMMAND_64_SIZE + i * SECTION_64_SIZE;
        sections.push(Section {
            sectname: fixed_name(r.slice(s, 16)?),
            segname: fixed_name(r.slice(s + 16, 16)?),
            addr: r.u64(s + 32)?,
            size: r.u64(s + 40)?,
            offset: r.u32(s + 48)?,
            align: r.u32(s + 52)?,
            flags: r.u32(s + 64)?,
        });
    }
    Ok(Segment {
        segname: fixed_name(r.slice(off + 8, 16)?),
        vmaddr: r.u64(off + 24)?,
        vmsize: r.u64(off + 32)?,
        fileoff: r.u64(off + 40)?,
        filesize: r.u64(off + 48)?,
        maxprot: r.u32(off + 56)?,
        initprot: r.u32(off + 60)?,
        nsects,
        flags: r.u32(off + 68)?,
        sections,
    })
}

fn parse_dylinker(r: &Reader<'_>, off: u64, size: u32) -> Result<String, MachOError> {
    if u64::from(size) < DYLINKER_COMMAND_SIZE {
        return Err(bad_macho("dylinker command is too small"));
    }
    let name_off = r.u32(off + 8)?;
    if name_off >= size {
        return Err(bad_macho("dylinker name lies outside its command"));
    }
    let bytes = r.slice(off + u64::from(name_off), u64::from(size - name_off))?;
    let Some(len) = bytes.iter().position(|&b| b == 0) else {
        return Err(bad_macho("dylinker name is not NUL-terminated"));
    };
    Ok(String::from_utf8_lossy(&bytes[..len]).into_owned())
}

/// Walks an `LC_UNIXTHREAD` command's flavors as `load_threadstack` and
/// `load_threadentry` do. Returns the last state of the machine's flavor
/// with the stack pointer `thread_userstack` takes and the entry point
/// `thread_entrypoint` takes (each from the last flavor that supplies one).
///
/// Two kernel behaviors are kept as they are: an x86-64
/// `x86_THREAD_FULL_STATE64` supplies a stack but no entry point, and arm64
/// `thread_userstack` reads `ARM_THREAD_STATE64` through the 32-bit state
/// layout, so the stack pointer it takes is the 32-bit word at byte 52, the
/// upper half of X6.
fn parse_thread_state(
    r: &Reader<'_>,
    mut off: u64,
    mut total: u64,
    host: HostCpu,
) -> Result<(ThreadState, u64, u64), MachOError> {
    if total == 0 {
        return Err(bad_macho("thread command carries no state"));
    }
    let mut found: Option<ThreadState> = None;
    let mut sp = 0u64;
    let mut pc = 0u64;
    while total > 0 {
        if total < 8 {
            return Err(bad_macho("thread state header is truncated"));
        }
        let flavor = r.u32(off)?;
        let count = r.u32(off + 4)?;
        let bytes = (u64::from(count) + 2) * 4;
        if bytes > total {
            return Err(bad_macho("thread state exceeds its command"));
        }
        let state = off + 8;
        match (host.cputype, flavor) {
            (CPU_TYPE_X86_64, X86_THREAD_STATE64 | X86_THREAD_FULL_STATE64) => {
                let want = if flavor == X86_THREAD_STATE64 {
                    X86_THREAD_STATE64_COUNT
                } else {
                    X86_THREAD_FULL_STATE64_COUNT
                };
                if count != want {
                    return Err(failure("x86-64 thread state has the wrong size"));
                }
                let mut regs = [0u64; 21];
                for (i, reg) in regs.iter_mut().enumerate() {
                    *reg = r.u64(state + 8 * i as u64)?;
                }
                sp = regs[7];
                if flavor == X86_THREAD_STATE64 {
                    pc = regs[16];
                }
                found = Some(ThreadState::X86_64 { flavor, regs });
            }
            (CPU_TYPE_ARM64, ARM_THREAD_STATE64) => {
                if count != ARM_THREAD_STATE64_COUNT {
                    return Err(failure("arm64 thread state has the wrong size"));
                }
                let mut x = [0u64; 31];
                for (i, reg) in x.iter_mut().enumerate() {
                    *reg = r.u64(state + 8 * i as u64)?;
                }
                let st = ThreadState::Arm64 {
                    x,
                    sp: r.u64(state + 248)?,
                    pc: r.u64(state + 256)?,
                    cpsr: r.u32(state + 264)?,
                };
                sp = u64::from(r.u32(state + 52)?);
                pc = st.pc();
                found = Some(st);
            }
            _ => return Err(failure("thread state flavor is not this machine's")),
        }
        total -= bytes;
        off += bytes;
    }
    let state = found.ok_or_else(|| failure("no thread state for this machine"))?;
    Ok((state, sp, pc))
}
