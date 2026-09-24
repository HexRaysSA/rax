//! `binfmt_elf` loading. Expected addresses are computed from the Linux
//! 6.19 algorithm (`load_elf_binary`, `elf_load`, `load_elf_interp`) with
//! randomization disabled, not from the implementation.

use std::sync::Arc;

use crate::user::image::elf::{
    ET_DYN, ET_EXEC, PF_R, PF_W, PF_X, PT_GNU_STACK, PT_INTERP, PT_LOAD,
};
use crate::user::linux::abi::{DEFAULT_STACK_LIMIT, LinuxAbi};
use crate::user::linux::loader::{ImageFile, LoadError, load_program};
use crate::user::linux::stack::map_stack;
use crate::user::mm::{AddressSpace, Backing, Perms, SpaceConfig};

const P: u64 = 4096;

#[derive(Clone, Copy)]
pub(crate) struct Seg {
    pub p_type: u32,
    pub vaddr: u64,
    pub offset: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub flags: u32,
    pub align: u64,
}

impl Seg {
    pub fn load(vaddr: u64, offset: u64, filesz: u64, memsz: u64, flags: u32) -> Self {
        Seg {
            p_type: PT_LOAD,
            vaddr,
            offset,
            filesz,
            memsz,
            flags,
            align: P,
        }
    }
}

/// File byte at `off`: a pattern that makes every offset distinguishable.
pub(crate) fn pattern(off: u64) -> u8 {
    (off.wrapping_mul(0x9d) >> 3) as u8 ^ 0xa5
}

/// Builds an ELF64 little-endian image: header, program headers at 64,
/// an optional interpreter string, and pattern bytes everywhere else.
pub(crate) fn image(
    machine: u16,
    e_type: u16,
    entry: u64,
    segs: &[Seg],
    interp: Option<&str>,
) -> Vec<u8> {
    let mut phdrs: Vec<Seg> = segs.to_vec();
    let interp_off = 64 + 56 * (segs.len() as u64 + u64::from(interp.is_some()));
    if let Some(path) = interp {
        phdrs.insert(
            0,
            Seg {
                p_type: PT_INTERP,
                vaddr: 0,
                offset: interp_off,
                filesz: path.len() as u64 + 1,
                memsz: path.len() as u64 + 1,
                flags: PF_R,
                align: 1,
            },
        );
    }
    let end = phdrs
        .iter()
        .filter(|s| s.p_type == PT_LOAD)
        .map(|s| s.offset + s.filesz)
        .max()
        .unwrap_or(0)
        .max(interp_off + 64);
    let mut out: Vec<u8> = (0..end).map(pattern).collect();
    let mut h = Vec::new();
    h.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]);
    h.resize(16, 0);
    h.extend_from_slice(&e_type.to_le_bytes());
    h.extend_from_slice(&machine.to_le_bytes());
    h.extend_from_slice(&1u32.to_le_bytes());
    h.extend_from_slice(&entry.to_le_bytes());
    h.extend_from_slice(&64u64.to_le_bytes());
    h.extend_from_slice(&0u64.to_le_bytes());
    h.extend_from_slice(&0u32.to_le_bytes());
    h.extend_from_slice(&64u16.to_le_bytes());
    h.extend_from_slice(&56u16.to_le_bytes());
    h.extend_from_slice(&(phdrs.len() as u16).to_le_bytes());
    h.extend_from_slice(&[64, 0, 0, 0, 0, 0]);
    for s in &phdrs {
        h.extend_from_slice(&s.p_type.to_le_bytes());
        h.extend_from_slice(&s.flags.to_le_bytes());
        for v in [s.offset, s.vaddr, s.vaddr, s.filesz, s.memsz, s.align] {
            h.extend_from_slice(&v.to_le_bytes());
        }
    }
    out[..h.len()].copy_from_slice(&h);
    if let Some(path) = interp {
        let at = interp_off as usize;
        out[at..at + path.len()].copy_from_slice(path.as_bytes());
        out[at + path.len()] = 0;
    }
    out
}

fn space(abi: LinuxAbi) -> AddressSpace {
    let s = AddressSpace::new(SpaceConfig {
        va_limit: abi.task_size(),
        arena_bytes: 1 << 30,
        reserved_phys: vec![],
    })
    .unwrap();
    map_stack(abi, &s, DEFAULT_STACK_LIMIT, false).unwrap();
    s
}

fn no_interp(_: &[u8]) -> std::io::Result<ImageFile> {
    Err(std::io::Error::from(std::io::ErrorKind::NotFound))
}

fn load(
    abi: LinuxAbi,
    bytes: Vec<u8>,
) -> Result<(AddressSpace, crate::user::linux::loader::LoadedProgram), LoadError> {
    let s = space(abi);
    let file = ImageFile::new(bytes, "/prog");
    let loaded = load_program(abi, &s, &file, &mut no_interp, DEFAULT_STACK_LIMIT)?;
    Ok((s, loaded))
}

fn read(s: &AddressSpace, addr: u64, len: usize) -> Vec<u8> {
    let mut b = vec![0u8; len];
    s.read_raw(addr, &mut b).unwrap();
    b
}

#[test]
fn et_exec_segments_bss_and_break() {
    // text: file [0, 0x1234) at 0x400000 R-X; data: file [0x2010, +0x100) at
    // 0x402010 RW- with 0x3000 bytes of memory.
    let bytes = image(
        62,
        ET_EXEC,
        0x401000,
        &[
            Seg::load(0x400000, 0, 0x1234, 0x1234, PF_R | PF_X),
            Seg::load(0x402010, 0x2010, 0x100, 0x3000, PF_R | PF_W),
        ],
        None,
    );
    let (s, l) = load(LinuxAbi::X86_64, bytes).unwrap();
    assert_eq!(l.entry, 0x401000);
    assert_eq!(l.program_entry, 0x401000);
    assert_eq!(l.load_bias, 0);
    assert_eq!(l.interp_base, 0);
    // AT_PHDR: e_phoff (64) lies in the first PT_LOAD, file offset 0.
    assert_eq!(l.phdr, 0x400040);
    assert_eq!((l.phent, l.phnum), (56, 2));
    // brk = PAGE_ALIGN(0x402010 + 0x3000).
    assert_eq!(l.brk, 0x406000);

    let text = s.vma_at(0x400000).unwrap();
    assert_eq!((text.start, text.end), (0x400000, 0x402000));
    assert_eq!(text.perms, Perms::READ | Perms::EXEC);
    assert!(matches!(text.backing, Backing::Source { offset: 0, .. }));
    // The file-backed text mapping shows file bytes past p_filesz up to the
    // page end (elf_map maps whole pages).
    assert_eq!(
        read(&s, 0x401234, 4),
        (0x1234..0x1238).map(pattern).collect::<Vec<_>>()
    );

    let data = s.vma_at(0x402010).unwrap();
    assert_eq!((data.start, data.end), (0x402000, 0x403000));
    assert_eq!(data.perms, Perms::READ | Perms::WRITE);
    assert_eq!(
        read(&s, 0x402010, 4),
        (0x2010..0x2014).map(pattern).collect::<Vec<_>>()
    );
    // padzero(): the writable segment's last file page is cleared after
    // p_filesz, including bytes the file continues with.
    assert!(read(&s, 0x402110, 0x1000 - 0x110).iter().all(|&b| b == 0));
    // vm_brk_flags(): anonymous RW pages cover the rest of p_memsz.
    let bss = s.vma_at(0x403000).unwrap();
    assert_eq!((bss.start, bss.end), (0x403000, 0x406000));
    assert!(matches!(bss.backing, Backing::Anonymous));
    assert_eq!(bss.perms, Perms::READ | Perms::WRITE);
    assert!(s.vma_at(0x406000).is_none(), "the break starts unmapped");
}

#[test]
fn readonly_segment_with_bss_keeps_file_tail() {
    // A read-only PT_LOAD with p_memsz > p_filesz: padzero's write fails and
    // is ignored, so the tail of the last file page keeps file bytes; the
    // pages beyond are anonymous RW (vm_brk_flags without VM_EXEC).
    let bytes = image(
        62,
        ET_EXEC,
        0x400000,
        &[
            Seg::load(0x400000, 0, 0x1800, 0x4000, PF_R),
            // A second segment extends the file past the first one's tail.
            Seg::load(0x600000, 0x3000, 0x10, 0x10, PF_R),
        ],
        None,
    );
    let (s, _) = load(LinuxAbi::X86_64, bytes).unwrap();
    assert_eq!(
        read(&s, 0x401800, 2),
        vec![pattern(0x1800), pattern(0x1801)]
    );
    let anon = s.vma_at(0x402000).unwrap();
    assert_eq!(anon.perms, Perms::READ | Perms::WRITE);
    assert_eq!((anon.start, anon.end), (0x402000, 0x404000));
}

#[test]
fn executable_bss_pages_stay_executable() {
    let bytes = image(
        183,
        ET_EXEC,
        0x400000,
        &[Seg::load(0x400000, 0, 0x800, 0x3000, PF_R | PF_X)],
        None,
    );
    let (s, _) = load(LinuxAbi::Aarch64, bytes).unwrap();
    assert_eq!(s.vma_at(0x401000).unwrap().perms, Perms::all());
}

#[test]
fn pie_with_interpreter_loads_at_elf_et_dyn_base() {
    let prog = image(
        62,
        ET_DYN,
        0x1040,
        &[
            Seg::load(0, 0, 0x2000, 0x2000, PF_R | PF_X),
            Seg::load(0x3000, 0x2000, 0x100, 0x1100, PF_R | PF_W),
        ],
        Some("/lib/ld.so"),
    );
    let interp = image(
        62,
        ET_DYN,
        0x800,
        &[
            Seg::load(0, 0, 0x1500, 0x1500, PF_R | PF_X),
            Seg::load(0x3000, 0x2000, 0x80, 0x200, PF_R | PF_W),
        ],
        None,
    );
    let s = space(LinuxAbi::X86_64);
    let mut resolver = |path: &[u8]| {
        assert_eq!(path, b"/lib/ld.so");
        Ok(ImageFile::new(interp.clone(), "/lib/ld.so"))
    };
    let l = load_program(
        LinuxAbi::X86_64,
        &s,
        &ImageFile::new(prog, "/prog"),
        &mut resolver,
        DEFAULT_STACK_LIMIT,
    )
    .unwrap();
    // ELF_ET_DYN_BASE = 0x7ffffffff000 / 3 * 2 = 0x555555554aaa;
    // maximum_alignment() = 4 KiB; ELF_PAGESTART(0x555555554000 - 0).
    assert_eq!(l.load_bias, 0x5555_5555_4000);
    assert_eq!(l.program_entry, 0x5555_5555_5040);
    assert_eq!(l.phdr, 0x5555_5555_4040);
    assert_eq!(l.brk, 0x5555_5555_9000);
    // The interpreter's whole span (0x3200 -> 0x4000 bytes) lands top-down
    // directly below mmap_base = 0x7ffff7fff000.
    assert_eq!(l.interp_base, 0x7fff_f7ff_f000 - 0x4000);
    assert_eq!(l.entry, l.interp_base + 0x800);
    assert_eq!(l.interp_path.as_deref(), Some(&b"/lib/ld.so"[..]));
    assert!(s.vma_at(l.interp_base).is_some());
}

#[test]
fn large_alignment_rounds_the_pie_base() {
    // arm64 binaries commonly use 64 KiB p_align: 0xaaaaaaaaaaaa & ~0xffff.
    let mut seg = Seg::load(0, 0, 0x100, 0x100, PF_R | PF_X);
    seg.align = 0x10000;
    let prog = image(183, ET_DYN, 0x40, &[seg], Some("/ld"));
    let interp = image(
        183,
        ET_DYN,
        0,
        &[Seg::load(0, 0, 0x100, 0x100, PF_R | PF_X)],
        None,
    );
    let s = space(LinuxAbi::Aarch64);
    let mut resolver = |_: &[u8]| Ok(ImageFile::new(interp.clone(), "/ld"));
    let l = load_program(
        LinuxAbi::Aarch64,
        &s,
        &ImageFile::new(prog, "/p"),
        &mut resolver,
        DEFAULT_STACK_LIMIT,
    )
    .unwrap();
    assert_eq!(l.load_bias, 0xaaaa_aaaa_0000);
}

#[test]
fn static_pie_loads_top_down_below_mmap_base() {
    let bytes = image(
        243,
        ET_DYN,
        0x100,
        &[
            Seg::load(0, 0, 0x1000, 0x1000, PF_R | PF_X),
            Seg::load(0x1000, 0x1000, 0x10, 0x2000, PF_R | PF_W),
        ],
        None,
    );
    let (s, l) = load(LinuxAbi::Riscv64, bytes).unwrap();
    let mmap_base = LinuxAbi::Riscv64.mmap_base(DEFAULT_STACK_LIMIT);
    assert_eq!(l.load_bias, mmap_base - 0x3000);
    assert_eq!(l.entry, l.load_bias + 0x100);
    assert!(s.vma_at(l.load_bias).is_some());
}

#[test]
fn rejects_images_linux_rejects() {
    let x86 = LinuxAbi::X86_64;
    // Wrong machine.
    let b = image(
        183,
        ET_EXEC,
        0x400000,
        &[Seg::load(0x400000, 0, 0x10, 0x10, PF_R)],
        None,
    );
    assert_eq!(load(x86, b).unwrap_err().errno(), 8); // ENOEXEC
    // p_filesz > p_memsz.
    let b = image(
        62,
        ET_EXEC,
        0x400000,
        &[Seg::load(0x400000, 0, 0x20, 0x10, PF_R)],
        None,
    );
    assert_eq!(load(x86, b).unwrap_err().errno(), 22); // EINVAL
    // Offset not congruent to vaddr modulo the page size.
    let b = image(
        62,
        ET_EXEC,
        0x400000,
        &[Seg::load(0x400010, 0x20, 0x10, 0x10, PF_R)],
        None,
    );
    assert_eq!(load(x86, b).unwrap_err().errno(), 22);
    // Below vm.mmap_min_addr.
    let b = image(
        62,
        ET_EXEC,
        0x1000,
        &[Seg::load(0x1000, 0, 0x10, 0x10, PF_R)],
        None,
    );
    assert_eq!(load(x86, b).unwrap_err().errno(), 1); // EPERM
    // Beyond TASK_SIZE.
    let b = image(
        62,
        ET_EXEC,
        0x7fff_ffff_f000,
        &[Seg::load(0x7fff_ffff_f000, 0, 0x10, 0x2000, PF_R)],
        None,
    );
    assert_eq!(load(x86, b).unwrap_err().errno(), 22);
    // Overlapping the stack: MAP_FIXED_NOREPLACE fails with EEXIST.
    let top = x86.stack_top();
    let b = image(
        62,
        ET_EXEC,
        top - 0x2000,
        &[Seg::load(top - 0x2000, 0, 0x10, 0x10, PF_R)],
        None,
    );
    assert_eq!(load(x86, b).unwrap_err().errno(), 17); // EEXIST
    // Missing interpreter: the open's errno.
    let b = image(
        62,
        ET_DYN,
        0,
        &[Seg::load(0, 0, 0x10, 0x10, PF_R)],
        Some("/missing"),
    );
    assert_eq!(load(x86, b).unwrap_err().errno(), 2); // ENOENT
    // RV64 requires ELFCLASS64 (elf_check_arch).
    let mut b = image(
        243,
        ET_EXEC,
        0x10000,
        &[Seg::load(0x10000, 0, 0x10, 0x10, PF_R)],
        None,
    );
    b[4] = 1;
    assert_eq!(load(LinuxAbi::Riscv64, b).unwrap_err().errno(), 8);
}

#[test]
fn later_overlapping_segments_replace_earlier_pages() {
    // Linux maps PT_LOADs in file order with MAP_FIXED: a later segment
    // sharing a page with an earlier one replaces that page.
    let bytes = image(
        62,
        ET_EXEC,
        0x400000,
        &[
            Seg::load(0x400000, 0, 0x1800, 0x1800, PF_R | PF_X),
            Seg::load(0x401800, 0x3800, 0x100, 0x100, PF_R | PF_W),
        ],
        None,
    );
    let (s, _) = load(LinuxAbi::X86_64, bytes).unwrap();
    let shared = s.vma_at(0x401000).unwrap();
    assert_eq!(shared.perms, Perms::READ | Perms::WRITE);
    // The shared page now holds file bytes from offset 0x3000.
    assert_eq!(read(&s, 0x401000, 1), vec![pattern(0x3000)]);
}

#[test]
fn gnu_stack_selects_stack_executability() {
    let stack = Seg {
        p_type: PT_GNU_STACK,
        vaddr: 0,
        offset: 0,
        filesz: 0,
        memsz: 0,
        flags: PF_R | PF_W | PF_X,
        align: 16,
    };
    let b = image(
        62,
        ET_EXEC,
        0x400000,
        &[Seg::load(0x400000, 0, 0x10, 0x10, PF_R), stack],
        None,
    );
    let (_, l) = load(LinuxAbi::X86_64, b).unwrap();
    assert!(l.exec_stack);
    let b = image(
        62,
        ET_EXEC,
        0x400000,
        &[Seg::load(0x400000, 0, 0x10, 0x10, PF_R)],
        None,
    );
    let (_, l) = load(LinuxAbi::X86_64, b).unwrap();
    assert!(!l.exec_stack);
}

#[test]
fn mapping_names_carry_the_image_name() {
    let b = image(
        62,
        ET_EXEC,
        0x400000,
        &[Seg::load(0x400000, 0, 0x10, 0x10, PF_R)],
        None,
    );
    let s = space(LinuxAbi::X86_64);
    let file = ImageFile::new(Arc::<[u8]>::from(b), "/usr/bin/tool");
    load_program(
        LinuxAbi::X86_64,
        &s,
        &file,
        &mut no_interp,
        DEFAULT_STACK_LIMIT,
    )
    .unwrap();
    assert_eq!(
        s.vma_at(0x400000).unwrap().name.as_deref(),
        Some("/usr/bin/tool")
    );
}
