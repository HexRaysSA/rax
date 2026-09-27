//! Mach-O acceptance tests. Expectations follow XNU 12377.121.6
//! `bsd/kern/{mach_fat,mach_loader,kern_exec}.c` and
//! `bsd/dev/{arm,i386}/kern_machdep.c`.

use super::*;

const PAGE16K: u64 = 16 << 10;
const PAGE4K: u64 = 4 << 10;

/// A segment for [`Builder`].
#[derive(Clone)]
struct Seg {
    name: &'static str,
    vmaddr: u64,
    vmsize: u64,
    fileoff: u64,
    filesize: u64,
    maxprot: u32,
    initprot: u32,
    flags: u32,
    sections: Vec<(&'static str, u64, u64)>,
}

fn seg(
    name: &'static str,
    vmaddr: u64,
    vmsize: u64,
    fileoff: u64,
    filesize: u64,
    prot: u32,
) -> Seg {
    Seg {
        name,
        vmaddr,
        vmsize,
        fileoff,
        filesize,
        maxprot: prot,
        initprot: prot,
        flags: 0,
        sections: Vec::new(),
    }
}

/// Builds thin 64-bit Mach-O images command by command.
struct Builder {
    cputype: u32,
    cpusubtype: u32,
    filetype: u32,
    flags: u32,
    cmds: Vec<Vec<u8>>,
    size: usize,
}

fn name16(s: &str) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..s.len()].copy_from_slice(s.as_bytes());
    out
}

impl Builder {
    fn new(cputype: u32, cpusubtype: u32, filetype: u32, flags: u32) -> Self {
        Builder {
            cputype,
            cpusubtype,
            filetype,
            flags,
            cmds: Vec::new(),
            size: 0,
        }
    }

    fn arm64_exe() -> Self {
        Builder::new(
            CPU_TYPE_ARM64,
            CPU_SUBTYPE_ARM64_ALL,
            MH_EXECUTE,
            MH_DYLDLINK | MH_PIE | MH_TWOLEVEL,
        )
    }

    fn x86_exe(flags: u32) -> Self {
        Builder::new(CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, MH_EXECUTE, flags)
    }

    fn raw(mut self, cmd: u32, body: &[u8]) -> Self {
        let mut c = Vec::new();
        c.extend_from_slice(&cmd.to_le_bytes());
        c.extend_from_slice(&((8 + body.len()) as u32).to_le_bytes());
        c.extend_from_slice(body);
        self.cmds.push(c);
        self
    }

    fn segment(self, s: Seg) -> Self {
        let mut b = Vec::new();
        b.extend_from_slice(&name16(s.name));
        for v in [s.vmaddr, s.vmsize, s.fileoff, s.filesize] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        b.extend_from_slice(&s.maxprot.to_le_bytes());
        b.extend_from_slice(&s.initprot.to_le_bytes());
        b.extend_from_slice(&(s.sections.len() as u32).to_le_bytes());
        b.extend_from_slice(&s.flags.to_le_bytes());
        for (sect, addr, size) in &s.sections {
            b.extend_from_slice(&name16(sect));
            b.extend_from_slice(&name16(s.name));
            b.extend_from_slice(&addr.to_le_bytes());
            b.extend_from_slice(&size.to_le_bytes());
            b.extend_from_slice(&[0u8; 32]);
        }
        self.raw(LC_SEGMENT_64, &b)
    }

    fn pagezero(self, size: u64) -> Self {
        self.segment(seg("__PAGEZERO", 0, size, 0, 0, 0))
    }

    fn main(self, entryoff: u64, stacksize: u64) -> Self {
        let mut b = Vec::new();
        b.extend_from_slice(&entryoff.to_le_bytes());
        b.extend_from_slice(&stacksize.to_le_bytes());
        self.raw(LC_MAIN, &b)
    }

    fn dylinker(self, cmd: u32, path: &str) -> Self {
        let mut b = Vec::new();
        b.extend_from_slice(&12u32.to_le_bytes());
        b.extend_from_slice(path.as_bytes());
        b.push(0);
        while (b.len() + 8) % 8 != 0 {
            b.push(0);
        }
        self.raw(cmd, &b)
    }

    fn x86_thread(self, flavor: u32, rip: u64, rsp: u64) -> Self {
        let count = if flavor == X86_THREAD_STATE64 {
            X86_THREAD_STATE64_COUNT
        } else {
            X86_THREAD_FULL_STATE64_COUNT
        };
        let mut regs = vec![0u64; count as usize / 2];
        regs[7] = rsp;
        regs[16] = rip;
        let mut b = Vec::new();
        b.extend_from_slice(&flavor.to_le_bytes());
        b.extend_from_slice(&count.to_le_bytes());
        for r in regs {
            b.extend_from_slice(&r.to_le_bytes());
        }
        self.raw(LC_UNIXTHREAD, &b)
    }

    fn arm64_thread(self, x: [u64; 31], sp: u64, pc: u64) -> Self {
        let mut b = Vec::new();
        b.extend_from_slice(&ARM_THREAD_STATE64.to_le_bytes());
        b.extend_from_slice(&ARM_THREAD_STATE64_COUNT.to_le_bytes());
        for r in x {
            b.extend_from_slice(&r.to_le_bytes());
        }
        b.extend_from_slice(&sp.to_le_bytes());
        b.extend_from_slice(&pc.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        self.raw(LC_UNIXTHREAD, &b)
    }

    fn build_version(self, platform: u32) -> Self {
        let mut b = Vec::new();
        for v in [platform, 0x000f_0000, 0x001a_0000, 0] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        self.raw(LC_BUILD_VERSION, &b)
    }

    fn encryption(self, cryptid: u32, cryptsize: u32) -> Self {
        let mut b = Vec::new();
        for v in [0x4000u32, cryptsize, cryptid, 0] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        self.raw(LC_ENCRYPTION_INFO_64, &b)
    }

    /// Total file size (zero-padded); at least the header and commands.
    fn size(mut self, size: usize) -> Self {
        self.size = size;
        self
    }

    fn bytes(&self) -> Vec<u8> {
        let sizeofcmds: usize = self.cmds.iter().map(Vec::len).sum();
        let mut out = Vec::new();
        for v in [
            MH_MAGIC_64,
            self.cputype,
            self.cpusubtype,
            self.filetype,
            self.cmds.len() as u32,
            sizeofcmds as u32,
            self.flags,
            0,
        ] {
            out.extend_from_slice(&v.to_le_bytes());
        }
        for c in &self.cmds {
            out.extend_from_slice(c);
        }
        if out.len() < self.size {
            out.resize(self.size, 0);
        }
        out
    }
}

fn opts(host: HostCpu) -> LoadOptions {
    LoadOptions {
        host,
        role: ImageRole::Executable,
        slide: 0,
        slice_offset: 0,
    }
}

fn dyld_opts(host: HostCpu, main_max_vm_addr: u64) -> LoadOptions {
    LoadOptions {
        role: ImageRole::Dylinker { main_max_vm_addr },
        ..opts(host)
    }
}

/// A minimal dynamic arm64 executable: 4 GiB page zero, one 16 KiB text
/// page holding the header, a data segment with zero fill.
fn arm64_dynamic() -> Builder {
    Builder::arm64_exe()
        .pagezero(1 << 32)
        .segment(seg(
            "__TEXT",
            1 << 32,
            PAGE16K,
            0,
            PAGE16K,
            VM_PROT_READ | VM_PROT_EXECUTE,
        ))
        .segment(seg(
            "__DATA",
            (1 << 32) + PAGE16K,
            3 * PAGE16K,
            PAGE16K,
            PAGE16K,
            VM_PROT_READ | VM_PROT_WRITE,
        ))
        .main(0x3f80, 0)
        .dylinker(LC_LOAD_DYLINKER, "/usr/lib/dyld")
        .build_version(PLATFORM_MACOS)
        .size(2 * PAGE16K as usize)
}

fn load_err(e: MachOError) -> Option<LoadReturn> {
    match e {
        MachOError::Load(kind, _) => Some(kind),
        _ => None,
    }
}

#[test]
fn identify_distinguishes_fat_thin_reversed_and_foreign() {
    assert_eq!(identify(&0xcafe_babeu32.to_be_bytes()), Ok(Identity::Fat));
    let thin = arm64_dynamic().bytes();
    assert!(matches!(identify(&thin), Ok(Identity::Thin(h)) if h.cputype == CPU_TYPE_ARM64));
    assert_eq!(
        identify(&MH_CIGAM_64.to_le_bytes()),
        Err(MachOError::ReverseEndian)
    );
    assert_eq!(
        identify(&MH_CIGAM.to_le_bytes()),
        Err(MachOError::ReverseEndian)
    );
    assert_eq!(identify(b"\x7fELF\x02\x01\x01"), Err(MachOError::NotMachO));
    assert_eq!(identify(b"#!"), Err(MachOError::NotMachO));
    // FAT_MAGIC_64 is not an executable format of the kernel.
    assert_eq!(
        identify(&FAT_MAGIC_64.to_be_bytes()),
        Err(MachOError::NotMachO)
    );
    assert!(is_macho(&thin));
    assert!(is_macho(&FAT_MAGIC.to_be_bytes()));
    assert!(!is_macho(b"\x7fELF"));
    assert_eq!(MachOError::NotMachO.errno(), 8);
    assert_eq!(MachOError::ReverseEndian.errno(), 86);
}

fn fat(entries: &[(u32, u32, u32, u32)], file_size: usize) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&FAT_MAGIC.to_be_bytes());
    out.extend_from_slice(&(entries.len() as u32).to_be_bytes());
    for &(cputype, cpusubtype, offset, size) in entries {
        for v in [cputype, cpusubtype, offset, size, 14] {
            out.extend_from_slice(&v.to_be_bytes());
        }
    }
    out.resize(file_size.max(out.len()), 0);
    out
}

#[test]
fn fat_table_validation_matches_fatfile_validate_fatarches() {
    let ok = fat(
        &[
            (CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, 0x4000, 0x100),
            (
                CPU_TYPE_ARM64,
                CPU_SUBTYPE_ARM64E | 0x8000_0000,
                0x8000,
                0x100,
            ),
        ],
        0x8100,
    );
    assert_eq!(fat_arches(&ok, PAGE16K).unwrap().len(), 2);
    // A slice overlapping the table itself.
    let e = fat_arches(&fat(&[(CPU_TYPE_ARM64, 0, 8, 0x10)], 0x100), PAGE16K).unwrap_err();
    assert_eq!(load_err(e), Some(LoadReturn::BadMachO));
    // Past the end of the file.
    let e = fat_arches(&fat(&[(CPU_TYPE_ARM64, 0, 0x4000, 0x100)], 0x4000), PAGE16K).unwrap_err();
    assert_eq!(load_err(e), Some(LoadReturn::BadMachO));
    // Offset + size overflowing 32 bits.
    let e = fat_arches(
        &fat(&[(CPU_TYPE_ARM64, 0, 0x4000, u32::MAX)], 0x4000),
        PAGE16K,
    )
    .unwrap_err();
    assert_eq!(load_err(e), Some(LoadReturn::BadMachO));
    // Duplicate type/subtype pairs.
    let dup = fat(
        &[
            (CPU_TYPE_ARM64, 0, 0x4000, 0x100),
            (CPU_TYPE_ARM64, 0, 0x8000, 0x100),
        ],
        0x8100,
    );
    assert_eq!(
        load_err(fat_arches(&dup, PAGE16K).unwrap_err()),
        Some(LoadReturn::BadMachO)
    );
    // Overlapping slices, in either order.
    for entries in [
        [
            (CPU_TYPE_ARM64, 0, 0x4000, 0x200),
            (CPU_TYPE_X86_64, 3, 0x4100, 0x100),
        ],
        [
            (CPU_TYPE_ARM64, 0, 0x4100, 0x100),
            (CPU_TYPE_X86_64, 3, 0x4000, 0x200),
        ],
    ] {
        let e = fat_arches(&fat(&entries, 0x4400), PAGE16K).unwrap_err();
        assert_eq!(load_err(e), Some(LoadReturn::BadMachO));
    }
    // Adjacent slices do not overlap.
    let adjacent = fat(
        &[
            (CPU_TYPE_ARM64, 0, 0x4000, 0x100),
            (CPU_TYPE_X86_64, 3, 0x4100, 0x100),
        ],
        0x4200,
    );
    assert!(fat_arches(&adjacent, PAGE16K).is_ok());
    // The table must fit the first page: (4096 - 8) / 20 = 204 entries on a
    // 4 KiB kernel.
    let mut many = Vec::new();
    many.extend_from_slice(&FAT_MAGIC.to_be_bytes());
    many.extend_from_slice(&205u32.to_be_bytes());
    many.resize(PAGE4K as usize, 0);
    assert_eq!(
        load_err(fat_arches(&many, PAGE4K).unwrap_err()),
        Some(LoadReturn::BadMachO)
    );
}

#[test]
fn grading_follows_ml_grade_binary() {
    let h = HostCpu::ARM64E;
    // arm64e with ABI version 0 or 1 outranks arm64; later versions rank 11.
    assert_eq!(
        grade(h, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E, 0x8000_0000),
        12
    );
    assert_eq!(
        grade(h, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E, 0x8100_0000),
        12
    );
    assert_eq!(
        grade(h, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E, 0x8200_0000),
        11
    );
    assert_eq!(grade(h, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_V8, 0), 10);
    assert_eq!(grade(h, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, 0), 9);
    // Subtypes the machine does not know do not run.
    assert_eq!(grade(h, CPU_TYPE_ARM64, 12, 0x8000_0000), 0);
    assert_eq!(grade(h, CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, 0), 0);
    let hx = HostCpu::X86_64H;
    assert_eq!(grade(hx, CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_H, 0), 3);
    assert_eq!(grade(hx, CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, 0), 2);
    let generic = HostCpu::X86_64;
    assert_eq!(grade(generic, CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_H, 0), 0);
    assert_eq!(
        grade(generic, CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, 0),
        2
    );
    assert_eq!(HostCpu::ARM64E.page_size(), PAGE16K);
    assert_eq!(HostCpu::X86_64H.page_size(), PAGE4K);
}

#[test]
fn best_arch_prefers_the_highest_grade() {
    let arches = [
        FatArch {
            cputype: CPU_TYPE_X86_64,
            cpusubtype: 3,
            offset: 0x4000,
            size: 1,
            align: 14,
        },
        FatArch {
            cputype: CPU_TYPE_ARM64,
            cpusubtype: 0,
            offset: 0x8000,
            size: 1,
            align: 14,
        },
        FatArch {
            cputype: CPU_TYPE_ARM64,
            cpusubtype: CPU_SUBTYPE_ARM64E | 0x8000_0000,
            offset: 0xc000,
            size: 1,
            align: 14,
        },
        FatArch {
            cputype: CPU_TYPE_ARM64,
            cpusubtype: 12 | 0x8000_0000,
            offset: 0x1_0000,
            size: 1,
            align: 14,
        },
        FatArch {
            cputype: CPU_TYPE_X86_64,
            cpusubtype: 8,
            offset: 0x1_4000,
            size: 1,
            align: 14,
        },
    ];
    assert_eq!(best_arch(&arches, HostCpu::ARM64E).unwrap().offset, 0xc000);
    assert_eq!(
        best_arch(&arches, HostCpu::X86_64H).unwrap().offset,
        0x1_4000
    );
    assert_eq!(best_arch(&arches, HostCpu::X86_64).unwrap().offset, 0x4000);
    assert_eq!(
        arch_for_cputype(&arches, HostCpu::ARM64E, CPU_TYPE_ARM64)
            .unwrap()
            .offset,
        0xc000
    );
    assert_eq!(
        load_err(best_arch(&arches[..1], HostCpu::ARM64E).unwrap_err()),
        Some(LoadReturn::BadArch)
    );
}

#[test]
fn select_slice_requires_the_thin_header_to_agree() {
    let thin = arm64_dynamic().bytes();
    let offset = 0x8000usize;
    let mut file = fat(
        &[(
            CPU_TYPE_ARM64,
            CPU_SUBTYPE_ARM64_ALL,
            offset as u32,
            thin.len() as u32,
        )],
        offset,
    );
    file.extend_from_slice(&thin);
    let (off, slice) = select_slice(&file, HostCpu::ARM64E).unwrap();
    assert_eq!(off, offset as u64);
    assert_eq!(slice, &thin[..]);
    // The fat table says arm64e but the slice is arm64: EBADARCH.
    let mut lying = fat(
        &[(
            CPU_TYPE_ARM64,
            CPU_SUBTYPE_ARM64E,
            offset as u32,
            thin.len() as u32,
        )],
        offset,
    );
    lying.extend_from_slice(&thin);
    let e = select_slice(&lying, HostCpu::ARM64E).unwrap_err();
    assert_eq!(e.errno(), 86);
    // A thin image is its own slice.
    assert_eq!(select_slice(&thin, HostCpu::ARM64E).unwrap().0, 0);
}

#[test]
fn dynamic_arm64_executable_plans_its_mappings() {
    let bytes = arm64_dynamic().bytes();
    let img = MachOImage::parse(&bytes, &opts(HostCpu::ARM64E)).unwrap();
    assert_eq!(img.pagezero_end, 1 << 32);
    assert_eq!(img.mach_header, 1 << 32);
    assert_eq!(img.dylinker.as_deref(), Some("/usr/lib/dyld"));
    assert_eq!(
        img.entry,
        Some(EntryCommand::Main {
            entryoff: 0x3f80,
            stacksize: 0
        })
    );
    assert_eq!(img.main_address(), Some((1 << 32) + 0x3f80));
    assert_eq!(img.entry_point, None);
    assert_eq!(img.user_stack, USRSTACK64_ARM64);
    assert!(!img.custom_stack);
    assert_eq!(img.user_stack_alloc_size, MAXSSIZ);
    assert_eq!(img.min_vm_addr, 1 << 32);
    assert_eq!(img.max_vm_addr, (1 << 32) + 4 * PAGE16K);
    assert_eq!(img.build.unwrap().platform, PLATFORM_MACOS);
    assert_eq!(img.mappings.len(), 2);
    let data = &img.mappings[1];
    assert_eq!(
        (data.vm_start, data.file_start),
        ((1 << 32) + PAGE16K, PAGE16K)
    );
    assert_eq!((data.file_len, data.zero_len), (PAGE16K, 2 * PAGE16K));
    assert_eq!(data.initprot, VM_PROT_READ | VM_PROT_WRITE);
    assert_eq!(img.segments.len(), 3);
    assert_eq!(img.segment("__DATA").unwrap().vmsize, 3 * PAGE16K);
}

#[test]
fn pie_executables_slide_and_their_stack_slides_down() {
    let bytes = arm64_dynamic().bytes();
    let o = LoadOptions {
        slide: 0x4000_0000,
        ..opts(HostCpu::ARM64E)
    };
    let img = MachOImage::parse(&bytes, &o).unwrap();
    assert_eq!(img.mach_header, (1 << 32) + 0x4000_0000);
    // Page zero is extended by the slide, not moved.
    assert_eq!(img.pagezero_end, (1 << 32) + 0x4000_0000);
    assert_eq!(img.user_stack, USRSTACK64_ARM64 - 0x4000_0000);
    // A non-PIE image ignores the slide.
    let x = Builder::x86_exe(0)
        .pagezero(0x1000)
        .segment(seg("__TEXT", 0x1000, 0x1000, 0, 0x1000, 5))
        .x86_thread(X86_THREAD_STATE64, 0x1800, 0)
        .size(0x1000)
        .bytes();
    let o = LoadOptions {
        slide: 0x10_0000,
        ..opts(HostCpu::X86_64H)
    };
    let img = MachOImage::parse(&x, &o).unwrap();
    assert_eq!(img.slide, 0);
    assert_eq!(img.entry_point, Some(0x1800));
}

#[test]
fn dynamic_arm64_executables_must_be_pie() {
    let mut b = arm64_dynamic();
    b.flags &= !MH_PIE;
    let e = MachOImage::parse(&b.bytes(), &opts(HostCpu::ARM64E)).unwrap_err();
    assert_eq!(load_err(e.clone()), Some(LoadReturn::Failure));
    assert_eq!(e.errno(), 85);
}

#[test]
fn a_hard_page_zero_is_required() {
    // arm64: the page zero must cover the low 4 GiB.
    let b = Builder::arm64_exe()
        .pagezero(0x1000_0000)
        .segment(seg("__TEXT", 1 << 32, PAGE16K, 0, PAGE16K, 5))
        .main(0, 0)
        .dylinker(LC_LOAD_DYLINKER, "/usr/lib/dyld")
        .size(PAGE16K as usize);
    let e = MachOImage::parse(&b.bytes(), &opts(HostCpu::ARM64E)).unwrap_err();
    assert_eq!(load_err(e), Some(LoadReturn::BadMachO));
    // x86-64: one page is enough, none is not.
    let make = |pz: bool| {
        let mut b = Builder::x86_exe(0);
        if pz {
            b = b.pagezero(0x1000);
        }
        b.segment(seg("__TEXT", 0x1000, 0x1000, 0, 0x1000, 5))
            .x86_thread(X86_THREAD_STATE64, 0x1100, 0)
            .size(0x1000)
            .bytes()
    };
    assert!(MachOImage::parse(&make(true), &opts(HostCpu::X86_64H)).is_ok());
    let e = MachOImage::parse(&make(false), &opts(HostCpu::X86_64H)).unwrap_err();
    assert_eq!(load_err(e), Some(LoadReturn::BadMachO));
}

#[test]
fn the_header_segment_must_be_unique_readable_and_executable() {
    let b = Builder::arm64_exe()
        .pagezero(1 << 32)
        .segment(seg("__TEXT", 1 << 32, PAGE16K, 0, PAGE16K, VM_PROT_READ))
        .main(0, 0)
        .dylinker(LC_LOAD_DYLINKER, "/usr/lib/dyld")
        .size(PAGE16K as usize);
    let e = MachOImage::parse(&b.bytes(), &opts(HostCpu::ARM64E)).unwrap_err();
    assert_eq!(load_err(e), Some(LoadReturn::BadMachO));
    let b = Builder::arm64_exe()
        .pagezero(1 << 32)
        .segment(seg("__TEXT", 1 << 32, PAGE16K, 0, PAGE16K, 5))
        .segment(seg("__TEXT2", (1 << 32) + PAGE16K, PAGE16K, 0, PAGE16K, 5))
        .main(0, 0)
        .dylinker(LC_LOAD_DYLINKER, "/usr/lib/dyld")
        .size(PAGE16K as usize);
    let e = MachOImage::parse(&b.bytes(), &opts(HostCpu::ARM64E)).unwrap_err();
    assert_eq!(load_err(e), Some(LoadReturn::BadMachO));
    // No segment maps the header at all.
    let b = Builder::arm64_exe()
        .pagezero(1 << 32)
        .segment(seg("__DATA", 1 << 32, PAGE16K, PAGE16K, PAGE16K, 3))
        .main(0, 0)
        .dylinker(LC_LOAD_DYLINKER, "/usr/lib/dyld")
        .size(2 * PAGE16K as usize);
    let e = MachOImage::parse(&b.bytes(), &opts(HostCpu::ARM64E)).unwrap_err();
    assert_eq!(load_err(e), Some(LoadReturn::BadMachO));
}

#[test]
fn segment_file_offsets_must_be_kernel_page_aligned() {
    // A 4 KiB-aligned second segment: fine on Intel, rejected on Apple
    // silicon whose kernel pages are 16 KiB.
    let make = |cputype: u32, subtype: u32| {
        Builder::new(cputype, subtype, MH_EXECUTE, 0)
            .pagezero(1 << 32)
            .segment(seg("__TEXT", 1 << 32, 0x1000, 0, 0x1000, 5))
            .segment(seg("__DATA", (1 << 32) + 0x4000, 0x1000, 0x1000, 0x1000, 3))
            .size(0x2000)
    };
    let x = make(CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL)
        .x86_thread(X86_THREAD_STATE64, (1 << 32) + 0x100, 0)
        .bytes();
    assert!(MachOImage::parse(&x, &opts(HostCpu::X86_64H)).is_ok());
    let a = make(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL)
        .arm64_thread([0; 31], 0, (1 << 32) + 0x100)
        .bytes();
    let e = MachOImage::parse(&a, &opts(HostCpu::ARM64E)).unwrap_err();
    assert_eq!(load_err(e), Some(LoadReturn::BadMachO));
    // The alignment is of the file offset: a fat slice at an unaligned
    // offset makes every segment unaligned.
    let o = LoadOptions {
        slice_offset: 0x800,
        ..opts(HostCpu::X86_64H)
    };
    let e = MachOImage::parse(&x, &o).unwrap_err();
    assert_eq!(load_err(e), Some(LoadReturn::BadMachO));
}

#[test]
fn segments_must_lie_inside_the_image() {
    let b = Builder::arm64_exe()
        .pagezero(1 << 32)
        .segment(seg("__TEXT", 1 << 32, PAGE16K, 0, 2 * PAGE16K, 5))
        .main(0, 0)
        .dylinker(LC_LOAD_DYLINKER, "/usr/lib/dyld")
        .size(PAGE16K as usize);
    let e = MachOImage::parse(&b.bytes(), &opts(HostCpu::ARM64E)).unwrap_err();
    assert_eq!(load_err(e), Some(LoadReturn::BadMachO));
    // vmaddr + slide overflowing.
    let b = Builder::arm64_exe()
        .pagezero(1 << 32)
        .segment(seg("__TEXT", u64::MAX - 0x100, PAGE16K, 0, PAGE16K, 5))
        .main(0, 0)
        .dylinker(LC_LOAD_DYLINKER, "/usr/lib/dyld")
        .size(PAGE16K as usize);
    let o = LoadOptions {
        slide: 0x4000,
        ..opts(HostCpu::ARM64E)
    };
    let e = MachOImage::parse(&b.bytes(), &o).unwrap_err();
    assert_eq!(load_err(e), Some(LoadReturn::BadMachO));
}

#[test]
fn file_mapping_can_exceed_the_segment_and_zero_fill_follows_it() {
    // filesize > vmsize: the kernel maps the rounded file range anyway.
    let x = Builder::x86_exe(0)
        .pagezero(0x1000)
        .segment(seg("__TEXT", 0x1000, 0x1000, 0, 0x2000, 5))
        .x86_thread(X86_THREAD_STATE64, 0x1100, 0)
        .size(0x2000)
        .bytes();
    let img = MachOImage::parse(&x, &opts(HostCpu::X86_64H)).unwrap();
    let m = &img.mappings[0];
    assert_eq!((m.file_len, m.zero_len, m.end()), (0x2000, 0, 0x3000));
    assert_eq!(img.max_vm_addr, 0x2000);
    // A segment with no file bytes is all zero fill.
    let x = Builder::x86_exe(0)
        .pagezero(0x1000)
        .segment(seg("__TEXT", 0x1000, 0x1000, 0, 0x1000, 5))
        .segment(seg("__BSS", 0x2000, 0x2800, 0, 0, 3))
        .x86_thread(X86_THREAD_STATE64, 0x1100, 0)
        .size(0x1000)
        .bytes();
    let img = MachOImage::parse(&x, &opts(HostCpu::X86_64H)).unwrap();
    let m = &img.mappings[1];
    assert_eq!((m.vm_start, m.file_len, m.zero_len), (0x2000, 0, 0x3000));
}

#[test]
fn lc_main_and_lc_unixthread_are_exclusive() {
    let b = arm64_dynamic().arm64_thread([0; 31], 0, (1 << 32) + 0x100);
    let e = MachOImage::parse(&b.bytes(), &opts(HostCpu::ARM64E)).unwrap_err();
    assert_eq!(load_err(e), Some(LoadReturn::Failure));
    let b = arm64_dynamic().main(0, 0);
    let e = MachOImage::parse(&b.bytes(), &opts(HostCpu::ARM64E)).unwrap_err();
    assert_eq!(load_err(e), Some(LoadReturn::Failure));
}

#[test]
fn static_x86_64_thread_state_sets_entry_and_stack() {
    let make = |rip: u64, rsp: u64| {
        Builder::x86_exe(0)
            .pagezero(0x1000)
            .segment(seg("__TEXT", 0x1000, 0x1000, 0, 0x1000, 5))
            .segment(seg("__DATA", 0x2000, 0x1000, 0x1000, 0x1000, 3))
            .x86_thread(X86_THREAD_STATE64, rip, rsp)
            .size(0x2000)
            .bytes()
    };
    let img = MachOImage::parse(&make(0x1234, 0), &opts(HostCpu::X86_64H)).unwrap();
    assert_eq!(img.entry_point, Some(0x1234));
    assert_eq!(img.user_stack, USRSTACK64_X86_64);
    assert!(!img.custom_stack);
    assert_eq!(img.user_stack_alloc_size, MAXSSIZ);
    assert!(img.dylinker.is_none());
    let img = MachOImage::parse(&make(0x1234, 0x7000_1234), &opts(HostCpu::X86_64H)).unwrap();
    assert_eq!(img.user_stack, 0x7000_1000);
    assert!(img.custom_stack);
    assert_eq!(img.user_stack_alloc_size, 0);
    // An entry point in a non-executable segment, or nowhere.
    for rip in [0x2100, 0x9000, 0] {
        let e = MachOImage::parse(&make(rip, 0), &opts(HostCpu::X86_64H)).unwrap_err();
        assert_eq!(load_err(e), Some(LoadReturn::Failure), "rip {rip:#x}");
    }
    // x86_THREAD_FULL_STATE64 supplies a stack but no entry point.
    let full = Builder::x86_exe(0)
        .pagezero(0x1000)
        .segment(seg("__TEXT", 0x1000, 0x1000, 0, 0x1000, 5))
        .x86_thread(X86_THREAD_FULL_STATE64, 0x1100, 0)
        .size(0x1000)
        .bytes();
    let e = MachOImage::parse(&full, &opts(HostCpu::X86_64H)).unwrap_err();
    assert_eq!(load_err(e), Some(LoadReturn::Failure));
}

#[test]
fn thread_state_flavors_are_validated() {
    // The other machine's flavor, a wrong count, and a truncated state.
    let a = Builder::x86_exe(0)
        .pagezero(0x1000)
        .segment(seg("__TEXT", 0x1000, 0x1000, 0, 0x1000, 5))
        .arm64_thread([0; 31], 0, 0x1100)
        .size(0x1000)
        .bytes();
    let e = MachOImage::parse(&a, &opts(HostCpu::X86_64H)).unwrap_err();
    assert_eq!(load_err(e), Some(LoadReturn::Failure));
    let mut body = Vec::new();
    body.extend_from_slice(&X86_THREAD_STATE64.to_le_bytes());
    body.extend_from_slice(&40u32.to_le_bytes());
    body.extend_from_slice(&[0u8; 160]);
    let b = Builder::x86_exe(0)
        .pagezero(0x1000)
        .segment(seg("__TEXT", 0x1000, 0x1000, 0, 0x1000, 5))
        .raw(LC_UNIXTHREAD, &body)
        .size(0x1000)
        .bytes();
    let e = MachOImage::parse(&b, &opts(HostCpu::X86_64H)).unwrap_err();
    assert_eq!(load_err(e), Some(LoadReturn::Failure));
    let mut body = Vec::new();
    body.extend_from_slice(&X86_THREAD_STATE64.to_le_bytes());
    body.extend_from_slice(&X86_THREAD_STATE64_COUNT.to_le_bytes());
    body.extend_from_slice(&[0u8; 16]);
    let b = Builder::x86_exe(0)
        .pagezero(0x1000)
        .segment(seg("__TEXT", 0x1000, 0x1000, 0, 0x1000, 5))
        .raw(LC_UNIXTHREAD, &body)
        .size(0x1000)
        .bytes();
    let e = MachOImage::parse(&b, &opts(HostCpu::X86_64H)).unwrap_err();
    assert_eq!(load_err(e), Some(LoadReturn::BadMachO));
}

#[test]
fn arm64_thread_stack_is_read_through_the_32_bit_layout() {
    // thread_userstack reads arm_thread_state32_t.sp: bytes 52..56, the
    // upper half of X6. The 64-bit SP field is not consulted.
    let mut x = [0u64; 31];
    x[6] = 0x7000_4000_u64 << 32;
    let b = Builder::new(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, MH_EXECUTE, 0)
        .pagezero(1 << 32)
        .segment(seg("__TEXT", 1 << 32, PAGE16K, 0, PAGE16K, 5))
        .arm64_thread(x, 0x1_0000_0000_8000, (1 << 32) + 0x100)
        .size(PAGE16K as usize)
        .bytes();
    let img = MachOImage::parse(&b, &opts(HostCpu::ARM64E)).unwrap();
    assert_eq!(img.user_stack, 0x7000_4000);
    assert!(img.custom_stack);
    assert_eq!(img.entry_point, Some((1 << 32) + 0x100));
    let b = Builder::new(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, MH_EXECUTE, 0)
        .pagezero(1 << 32)
        .segment(seg("__TEXT", 1 << 32, PAGE16K, 0, PAGE16K, 5))
        .arm64_thread([0; 31], 0x1_0000_0000_8000, (1 << 32) + 0x100)
        .size(PAGE16K as usize)
        .bytes();
    let img = MachOImage::parse(&b, &opts(HostCpu::ARM64E)).unwrap();
    assert_eq!(img.user_stack, USRSTACK64_ARM64);
    assert!(!img.custom_stack);
}

fn dyld_image(host: HostCpu, vmaddr: u64) -> Vec<u8> {
    let (cputype, subtype, page) = if host.cputype == CPU_TYPE_ARM64 {
        (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E, PAGE16K)
    } else {
        (CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, PAGE4K)
    };
    let mut data = seg("__DATA", vmaddr + page, page, page, page, 3);
    data.sections
        .push(("__all_image_info", vmaddr + page + 0x40, 0x170));
    let b = Builder::new(cputype, subtype, MH_DYLINKER, MH_DYLDLINK)
        .segment(seg("__TEXT", vmaddr, page, 0, page, 5))
        .segment(data)
        .dylinker(LC_ID_DYLINKER, "/usr/lib/dyld");
    let b = if cputype == CPU_TYPE_ARM64 {
        b.arm64_thread([0; 31], 0, vmaddr + 0x200)
    } else {
        b.x86_thread(X86_THREAD_STATE64, vmaddr + 0x200, 0)
    };
    b.size(2 * page as usize).bytes()
}

#[test]
fn dyld_without_a_load_address_follows_the_main_executable() {
    let main_end = (1 << 32) + 0x2_3456;
    let img = MachOImage::parse(
        &dyld_image(HostCpu::ARM64E, 0),
        &dyld_opts(HostCpu::ARM64E, main_end),
    )
    .unwrap();
    // Rounded up to a 16 KiB page after the executable.
    assert_eq!(img.slide, (1 << 32) + 0x2_4000);
    assert_eq!(img.entry_point, Some(img.slide + 0x200));
    assert_eq!(img.mach_header, img.slide);
    assert_eq!(
        img.all_image_info,
        Some((img.slide + PAGE16K + 0x40, 0x170))
    );
    assert_eq!(img.dylinker_id.as_deref(), Some("/usr/lib/dyld"));
    assert_eq!(img.uuid, None);
    // A dyld with a load address takes only the (dyld) slide.
    let img = MachOImage::parse(
        &dyld_image(HostCpu::X86_64H, 0x7ff8_0000_0000),
        &dyld_opts(HostCpu::X86_64H, main_end),
    )
    .unwrap();
    assert_eq!(img.slide, 0);
    assert_eq!(img.entry_point, Some(0x7ff8_0000_0200));
}

#[test]
fn file_types_are_checked_at_each_depth() {
    // A dyld is not a program, and a program is not a dyld.
    let d = dyld_image(HostCpu::ARM64E, 0);
    assert_eq!(
        MachOImage::parse(&d, &opts(HostCpu::ARM64E)).unwrap_err(),
        MachOError::NotMachO
    );
    let e =
        MachOImage::parse(&arm64_dynamic().bytes(), &dyld_opts(HostCpu::ARM64E, 0)).unwrap_err();
    assert_eq!(load_err(e), Some(LoadReturn::Failure));
    // A dylib is not claimed as a program.
    let mut b = arm64_dynamic();
    b.filetype = MH_DYLIB;
    assert_eq!(
        MachOImage::parse(&b.bytes(), &opts(HostCpu::ARM64E)).unwrap_err(),
        MachOError::NotMachO
    );
    // The wrong machine.
    let e = MachOImage::parse(&arm64_dynamic().bytes(), &opts(HostCpu::X86_64H)).unwrap_err();
    assert_eq!(load_err(e), Some(LoadReturn::BadArch));
    // 32-bit images.
    let mut thirty_two = arm64_dynamic().bytes();
    thirty_two[..4].copy_from_slice(&MH_MAGIC.to_le_bytes());
    assert_eq!(
        MachOImage::parse(&thirty_two, &opts(HostCpu::ARM64E)).unwrap_err(),
        MachOError::Unsupported32Bit
    );
}

#[test]
fn a_dynamic_executable_needs_a_dynamic_linker() {
    let b = Builder::arm64_exe()
        .pagezero(1 << 32)
        .segment(seg("__TEXT", 1 << 32, PAGE16K, 0, PAGE16K, 5))
        .main(0, 0)
        .size(PAGE16K as usize);
    let e = MachOImage::parse(&b.bytes(), &opts(HostCpu::ARM64E)).unwrap_err();
    assert_eq!(load_err(e), Some(LoadReturn::Failure));
    // Two dynamic linkers.
    let b = arm64_dynamic().dylinker(LC_LOAD_DYLINKER, "/usr/lib/dyld");
    let e = MachOImage::parse(&b.bytes(), &opts(HostCpu::ARM64E)).unwrap_err();
    assert_eq!(load_err(e), Some(LoadReturn::Failure));
    // A name that is not NUL-terminated inside its command.
    let mut body = Vec::new();
    body.extend_from_slice(&12u32.to_le_bytes());
    body.extend_from_slice(b"/usr/lib/d");
    body.extend_from_slice(b"yl");
    let b = Builder::arm64_exe()
        .pagezero(1 << 32)
        .segment(seg("__TEXT", 1 << 32, PAGE16K, 0, PAGE16K, 5))
        .main(0, 0)
        .raw(LC_LOAD_DYLINKER, &body)
        .size(PAGE16K as usize);
    let e = MachOImage::parse(&b.bytes(), &opts(HostCpu::ARM64E)).unwrap_err();
    assert_eq!(load_err(e), Some(LoadReturn::BadMachO));
}

#[test]
fn lc_main_stack_size_selects_a_custom_stack() {
    let b = Builder::arm64_exe()
        .pagezero(1 << 32)
        .segment(seg("__TEXT", 1 << 32, PAGE16K, 0, PAGE16K, 5))
        .main(0x100, 1 << 20)
        .dylinker(LC_LOAD_DYLINKER, "/usr/lib/dyld")
        .size(PAGE16K as usize);
    let img = MachOImage::parse(&b.bytes(), &opts(HostCpu::ARM64E)).unwrap();
    assert!(img.custom_stack);
    assert_eq!(img.user_stack_size, 1 << 20);
    assert_eq!(img.user_stack_alloc_size, (1 << 20) + PAGE16K);
    let b = Builder::arm64_exe()
        .pagezero(1 << 32)
        .segment(seg("__TEXT", 1 << 32, PAGE16K, 0, PAGE16K, 5))
        .main(0x100, u64::MAX - 0x1000)
        .dylinker(LC_LOAD_DYLINKER, "/usr/lib/dyld")
        .size(PAGE16K as usize);
    let e = MachOImage::parse(&b.bytes(), &opts(HostCpu::ARM64E)).unwrap_err();
    assert_eq!(load_err(e), Some(LoadReturn::BadMachO));
}

#[test]
fn version_commands_may_appear_once() {
    let b = arm64_dynamic().build_version(PLATFORM_MACOS);
    let e = MachOImage::parse(&b.bytes(), &opts(HostCpu::ARM64E)).unwrap_err();
    assert_eq!(load_err(e), Some(LoadReturn::BadMachO));
    let mut body = Vec::new();
    body.extend_from_slice(&0x000a_0f00u32.to_le_bytes());
    body.extend_from_slice(&0x000a_0f00u32.to_le_bytes());
    let b = arm64_dynamic().raw(LC_VERSION_MIN_MACOSX, &body);
    let e = MachOImage::parse(&b.bytes(), &opts(HostCpu::ARM64E)).unwrap_err();
    assert_eq!(load_err(e), Some(LoadReturn::BadMachO));
}

#[test]
fn encryption_ids_follow_set_code_unprotect() {
    for (id, size, ok) in [(0, 0x1000, true), (0x10, 0x1000, true), (1, 0, true)] {
        let b = arm64_dynamic().encryption(id, size);
        assert_eq!(
            MachOImage::parse(&b.bytes(), &opts(HostCpu::ARM64E)).is_ok(),
            ok
        );
    }
    let e = MachOImage::parse(
        &arm64_dynamic().encryption(1, 0x1000).bytes(),
        &opts(HostCpu::ARM64E),
    )
    .unwrap_err();
    assert_eq!(load_err(e.clone()), Some(LoadReturn::DecryptFail));
    assert_eq!(e.errno(), 80);
    let e = MachOImage::parse(
        &arm64_dynamic().encryption(2, 0x1000).bytes(),
        &opts(HostCpu::ARM64E),
    )
    .unwrap_err();
    assert_eq!(load_err(e), Some(LoadReturn::BadMachO));
}

#[test]
fn malformed_command_tables_are_rejected() {
    // sizeofcmds past the end of the file.
    let mut bytes = arm64_dynamic().size(0).bytes();
    bytes.truncate(100);
    let e = MachOImage::parse(&bytes, &opts(HostCpu::ARM64E)).unwrap_err();
    assert_eq!(load_err(e), Some(LoadReturn::BadMachO));
    // A command smaller than a load_command, and one running past
    // sizeofcmds.
    for bad_size in [4u32, 0x10_0000] {
        let mut bytes = arm64_dynamic().bytes();
        bytes[36..40].copy_from_slice(&bad_size.to_le_bytes());
        let e = MachOImage::parse(&bytes, &opts(HostCpu::ARM64E)).unwrap_err();
        assert_eq!(load_err(e), Some(LoadReturn::BadMachO));
    }
    // More commands than sizeofcmds holds.
    let mut bytes = arm64_dynamic().bytes();
    bytes[16..20].copy_from_slice(&100u32.to_le_bytes());
    let e = MachOImage::parse(&bytes, &opts(HostCpu::ARM64E)).unwrap_err();
    assert_eq!(load_err(e), Some(LoadReturn::BadMachO));
    // Sections that do not fit the segment command.
    let mut bytes = arm64_dynamic().bytes();
    // The first command is __PAGEZERO; set its nsects to 1.
    bytes[32 + 64..32 + 68].copy_from_slice(&1u32.to_le_bytes());
    let e = MachOImage::parse(&bytes, &opts(HostCpu::ARM64E)).unwrap_err();
    assert_eq!(load_err(e), Some(LoadReturn::BadMachO));
}

#[test]
fn only_one_segment_may_be_read_only_after_fixups() {
    let mut c1 = seg(
        "__DATA_CONST",
        (1 << 32) + PAGE16K,
        PAGE16K,
        PAGE16K,
        PAGE16K,
        3,
    );
    c1.flags = SG_READ_ONLY;
    let img = MachOImage::parse(
        &Builder::arm64_exe()
            .pagezero(1 << 32)
            .segment(seg("__TEXT", 1 << 32, PAGE16K, 0, PAGE16K, 5))
            .segment(c1.clone())
            .main(0, 0)
            .dylinker(LC_LOAD_DYLINKER, "/usr/lib/dyld")
            .size(2 * PAGE16K as usize)
            .bytes(),
        &opts(HostCpu::ARM64E),
    )
    .unwrap();
    assert_eq!(
        img.ro_range,
        Some(((1 << 32) + PAGE16K, (1 << 32) + 2 * PAGE16K))
    );
    let mut c2 = c1.clone();
    c2.name = "__AUTH_CONST";
    c2.vmaddr += PAGE16K;
    let e = MachOImage::parse(
        &Builder::arm64_exe()
            .pagezero(1 << 32)
            .segment(seg("__TEXT", 1 << 32, PAGE16K, 0, PAGE16K, 5))
            .segment(c1)
            .segment(c2)
            .main(0, 0)
            .dylinker(LC_LOAD_DYLINKER, "/usr/lib/dyld")
            .size(2 * PAGE16K as usize)
            .bytes(),
        &opts(HostCpu::ARM64E),
    )
    .unwrap_err();
    assert_eq!(load_err(e), Some(LoadReturn::BadMachO));
}

/// The host's own `dyld` and `/bin/ls`, when this is a Mac: every slice the
/// emulated machines select parses in its role.
#[test]
fn host_system_images_parse() {
    let (Ok(dyld), Ok(ls)) = (std::fs::read("/usr/lib/dyld"), std::fs::read("/bin/ls")) else {
        eprintln!("skipped: no /usr/lib/dyld or /bin/ls on this host");
        return;
    };
    let mut checked = 0;
    for host in [HostCpu::ARM64E, HostCpu::X86_64H] {
        let Ok((off, slice)) = select_slice(&ls, host) else {
            continue;
        };
        let img = MachOImage::parse(
            slice,
            &LoadOptions {
                slice_offset: off,
                ..opts(host)
            },
        )
        .unwrap();
        assert_eq!(img.dylinker.as_deref(), Some("/usr/lib/dyld"));
        assert!(matches!(img.entry, Some(EntryCommand::Main { .. })));
        assert!(img.main_address().is_some());
        let arches = fat_arches(&dyld, host.page_size()).unwrap();
        let arch = arch_for_cputype(&arches, host, host.cputype).unwrap();
        let slice = &dyld[arch.offset as usize..(arch.offset + arch.size) as usize];
        let d = MachOImage::parse(
            slice,
            &LoadOptions {
                slice_offset: u64::from(arch.offset),
                ..dyld_opts(host, img.max_vm_addr)
            },
        )
        .unwrap();
        assert!(d.entry_point.is_some());
        assert!(d.all_image_info.is_some());
        checked += 1;
    }
    assert!(
        checked > 0,
        "no slice of /bin/ls runs on an emulated machine"
    );
}
