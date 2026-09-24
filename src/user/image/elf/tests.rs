//! ELF parser acceptance tests. Expected outcomes follow Linux 6.19
//! `load_elf_binary`/`elf_read_phdrs` rather than the parser's own output.

use super::*;

/// Minimal ELF writer for synthetic headers.
struct Builder {
    class: ElfClass,
    data: ElfData,
    e_type: u16,
    machine: u16,
    entry: u64,
    phentsize: Option<u16>,
    phnum_override: Option<u16>,
    phoff_override: Option<u64>,
    phdrs: Vec<ProgramHeader>,
    tail: Vec<u8>,
}

impl Builder {
    fn new(class: ElfClass, data: ElfData) -> Self {
        Builder {
            class,
            data,
            e_type: ET_EXEC,
            machine: EM_X86_64,
            entry: 0x401000,
            phentsize: None,
            phnum_override: None,
            phoff_override: None,
            phdrs: Vec::new(),
            tail: Vec::new(),
        }
    }

    fn phdr(mut self, ph: ProgramHeader) -> Self {
        self.phdrs.push(ph);
        self
    }

    fn put16(&self, out: &mut Vec<u8>, v: u16) {
        match self.data {
            ElfData::Lsb => out.extend_from_slice(&v.to_le_bytes()),
            ElfData::Msb => out.extend_from_slice(&v.to_be_bytes()),
        }
    }

    fn put32(&self, out: &mut Vec<u8>, v: u32) {
        match self.data {
            ElfData::Lsb => out.extend_from_slice(&v.to_le_bytes()),
            ElfData::Msb => out.extend_from_slice(&v.to_be_bytes()),
        }
    }

    fn put64(&self, out: &mut Vec<u8>, v: u64) {
        match self.data {
            ElfData::Lsb => out.extend_from_slice(&v.to_le_bytes()),
            ElfData::Msb => out.extend_from_slice(&v.to_be_bytes()),
        }
    }

    fn word(&self, out: &mut Vec<u8>, v: u64) {
        match self.class {
            ElfClass::Elf32 => self.put32(out, v as u32),
            ElfClass::Elf64 => self.put64(out, v),
        }
    }

    fn build(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&ELF_MAGIC);
        out.push(match self.class {
            ElfClass::Elf32 => 1,
            ElfClass::Elf64 => 2,
        });
        out.push(match self.data {
            ElfData::Lsb => 1,
            ElfData::Msb => 2,
        });
        out.push(1);
        out.resize(EI_NIDENT, 0);
        let ehsize = self.class.header_size() as u64;
        let phoff = self.phoff_override.unwrap_or(ehsize);
        self.put16(&mut out, self.e_type);
        self.put16(&mut out, self.machine);
        self.put32(&mut out, 1);
        self.word(&mut out, self.entry);
        self.word(&mut out, phoff);
        self.word(&mut out, 0);
        self.put32(&mut out, 0);
        self.put16(&mut out, ehsize as u16);
        self.put16(
            &mut out,
            self.phentsize.unwrap_or(self.class.phdr_size() as u16),
        );
        self.put16(
            &mut out,
            self.phnum_override.unwrap_or(self.phdrs.len() as u16),
        );
        self.put16(&mut out, self.class.shdr_size() as u16);
        self.put16(&mut out, 0);
        self.put16(&mut out, 0);
        assert_eq!(out.len() as u64, ehsize);
        for ph in &self.phdrs {
            match self.class {
                ElfClass::Elf32 => {
                    self.put32(&mut out, ph.p_type);
                    self.put32(&mut out, ph.p_offset as u32);
                    self.put32(&mut out, ph.p_vaddr as u32);
                    self.put32(&mut out, ph.p_paddr as u32);
                    self.put32(&mut out, ph.p_filesz as u32);
                    self.put32(&mut out, ph.p_memsz as u32);
                    self.put32(&mut out, ph.p_flags);
                    self.put32(&mut out, ph.p_align as u32);
                }
                ElfClass::Elf64 => {
                    self.put32(&mut out, ph.p_type);
                    self.put32(&mut out, ph.p_flags);
                    self.put64(&mut out, ph.p_offset);
                    self.put64(&mut out, ph.p_vaddr);
                    self.put64(&mut out, ph.p_paddr);
                    self.put64(&mut out, ph.p_filesz);
                    self.put64(&mut out, ph.p_memsz);
                    self.put64(&mut out, ph.p_align);
                }
            }
        }
        out.extend_from_slice(&self.tail);
        out
    }
}

fn load(vaddr: u64, offset: u64, filesz: u64, memsz: u64, flags: u32) -> ProgramHeader {
    ProgramHeader {
        p_type: PT_LOAD,
        p_flags: flags,
        p_offset: offset,
        p_vaddr: vaddr,
        p_paddr: vaddr,
        p_filesz: filesz,
        p_memsz: memsz,
        p_align: 0x1000,
    }
}

fn parse64(bytes: &[u8]) -> Result<ElfImage<'_>, ElfError> {
    ElfImage::parse(bytes, ElfClass::Elf64, ElfData::Lsb)
}

#[test]
fn parses_minimal_elf64_executable() {
    let bytes = Builder::new(ElfClass::Elf64, ElfData::Lsb)
        .phdr(load(0x400000, 0, 0x100, 0x100, PF_R | PF_X))
        .build();
    let img = parse64(&bytes).unwrap();
    assert_eq!(img.header().e_machine, EM_X86_64);
    assert_eq!(img.header().e_entry, 0x401000);
    assert_eq!(img.load_segments().count(), 1);
    assert_eq!(img.interpreter(), None);
    assert_eq!(img.gnu_stack_executable(), None);
}

#[test]
fn parses_elf32_big_endian_fields() {
    let mut b = Builder::new(ElfClass::Elf32, ElfData::Msb);
    b.machine = 0x1234;
    b.entry = 0x8000_1234;
    let bytes = b.phdr(load(0x8000_0000, 0, 0x40, 0x2000, PF_R)).build();
    let img = ElfImage::parse(&bytes, ElfClass::Elf32, ElfData::Msb).unwrap();
    assert_eq!(img.header().e_machine, 0x1234);
    assert_eq!(img.header().e_entry, 0x8000_1234);
    let ph = img.load_segments().next().unwrap();
    assert_eq!(
        (ph.p_vaddr, ph.p_filesz, ph.p_memsz),
        (0x8000_0000, 0x40, 0x2000)
    );
}

#[test]
fn identify_reads_machine_with_declared_byte_order() {
    let mut b = Builder::new(ElfClass::Elf32, ElfData::Msb);
    b.machine = EM_ARM;
    let bytes = b.phdr(load(0x10000, 0, 0, 0, PF_R)).build();
    let id = identify(&bytes).unwrap();
    assert_eq!(id.e_machine, EM_ARM);
    assert_eq!(id.elf_class(), Some(ElfClass::Elf32));
    assert_eq!(id.elf_data(), Some(ElfData::Msb));
}

#[test]
fn rejects_bad_magic_and_short_files() {
    assert_eq!(parse64(b"\x7fELG").unwrap_err(), ElfError::BadMagic);
    assert!(matches!(
        parse64(b"\x7fEL").unwrap_err(),
        ElfError::Truncated { .. }
    ));
    let mut bytes = Builder::new(ElfClass::Elf64, ElfData::Lsb)
        .phdr(load(0x400000, 0, 0, 0, PF_R))
        .build();
    bytes.truncate(63);
    assert!(matches!(
        parse64(&bytes).unwrap_err(),
        ElfError::Truncated {
            needed: 64,
            available: 63
        }
    ));
}

#[test]
fn ignores_fields_linux_does_not_validate() {
    // Anti-analysis corruptions that Linux tolerates: EI_VERSION, e_version,
    // e_ehsize, garbage section-header geometry, and an undefined EI_CLASS.
    let mut bytes = Builder::new(ElfClass::Elf64, ElfData::Lsb)
        .phdr(load(0x400000, 0, 0x40, 0x40, PF_R | PF_X))
        .build();
    bytes[EI_CLASS] = 0x7f;
    bytes[EI_VERSION] = 0xee;
    bytes[20..24].copy_from_slice(&0xdead_beefu32.to_le_bytes()); // e_version
    bytes[40..48].copy_from_slice(&u64::MAX.to_le_bytes()); // e_shoff
    bytes[52..54].copy_from_slice(&3u16.to_le_bytes()); // e_ehsize
    bytes[60..62].copy_from_slice(&0xffffu16.to_le_bytes()); // e_shnum
    let img = parse64(&bytes).unwrap();
    assert_eq!(img.header().e_version, 0xdead_beef);
}

#[test]
fn rejects_non_executable_types() {
    for e_type in [0u16, 1, 4, 0xfe00] {
        let mut b = Builder::new(ElfClass::Elf64, ElfData::Lsb);
        b.e_type = e_type;
        let bytes = b.phdr(load(0x400000, 0, 0, 0, PF_R)).build();
        assert_eq!(
            parse64(&bytes).unwrap_err(),
            ElfError::NotExecutable(e_type)
        );
    }
    let mut b = Builder::new(ElfClass::Elf64, ElfData::Lsb);
    b.e_type = ET_DYN;
    let bytes = b.phdr(load(0, 0, 0, 0, PF_R)).build();
    assert!(parse64(&bytes).is_ok());
}

#[test]
fn enforces_phentsize_and_table_bounds() {
    let mut b = Builder::new(ElfClass::Elf64, ElfData::Lsb);
    b.phentsize = Some(32);
    let bytes = b.phdr(load(0x400000, 0, 0, 0, PF_R)).build();
    assert_eq!(parse64(&bytes).unwrap_err(), ElfError::BadPhentsize(32));

    // Linux decodes in the native class: a 52+32-byte ELF32 image read as
    // Elf64_Ehdr takes e_phentsize from offset 58, inside the first program
    // header (the high half of the 32-bit p_offset, zero here).
    let bytes = Builder::new(ElfClass::Elf32, ElfData::Lsb)
        .phdr(load(0x10000, 0, 0, 0, PF_R))
        .build();
    assert_eq!(bytes.len(), 84);
    assert_eq!(
        ElfImage::parse(&bytes, ElfClass::Elf64, ElfData::Lsb).unwrap_err(),
        ElfError::BadPhentsize(0)
    );
    // An ELF32 file shorter than Elf64_Ehdr is truncated for a 64-bit ABI.
    assert_eq!(
        ElfImage::parse(&bytes[..60], ElfClass::Elf64, ElfData::Lsb).unwrap_err(),
        ElfError::Truncated {
            needed: 64,
            available: 60
        }
    );

    let bytes = Builder::new(ElfClass::Elf64, ElfData::Lsb).build();
    assert_eq!(parse64(&bytes).unwrap_err(), ElfError::BadPhnum(0));

    // 65536 / 56 = 1170 entries fit; 1171 exceed the 64 KiB table bound.
    let mut b = Builder::new(ElfClass::Elf64, ElfData::Lsb);
    b.phnum_override = Some(1171);
    let bytes = b.phdr(load(0x400000, 0, 0, 0, PF_R)).build();
    assert_eq!(parse64(&bytes).unwrap_err(), ElfError::BadPhnum(1171));

    let mut b = Builder::new(ElfClass::Elf64, ElfData::Lsb);
    b.phnum_override = Some(PN_XNUM);
    let bytes = b.phdr(load(0x400000, 0, 0, 0, PF_R)).build();
    assert_eq!(parse64(&bytes).unwrap_err(), ElfError::BadPhnum(PN_XNUM));

    let mut b = Builder::new(ElfClass::Elf64, ElfData::Lsb);
    b.phnum_override = Some(2);
    let bytes = b.phdr(load(0x400000, 0, 0, 0, PF_R)).build();
    assert_eq!(
        parse64(&bytes).unwrap_err(),
        ElfError::PhdrTableOutOfBounds {
            offset: 64,
            size: 112
        }
    );

    let mut b = Builder::new(ElfClass::Elf64, ElfData::Lsb);
    b.phoff_override = Some(u64::MAX - 8);
    let bytes = b.phdr(load(0x400000, 0, 0, 0, PF_R)).build();
    assert!(matches!(
        parse64(&bytes).unwrap_err(),
        ElfError::PhdrTableOutOfBounds { .. }
    ));
}

#[test]
fn table_limit_is_exactly_64_kib() {
    // 1170 * 56 = 65520 <= 65536: accepted when the bytes are present.
    let mut b = Builder::new(ElfClass::Elf64, ElfData::Lsb);
    for i in 0..1170u64 {
        b = b.phdr(ProgramHeader {
            p_type: PT_NOTE,
            p_offset: i,
            ..Default::default()
        });
    }
    let bytes = b.phdr_zero_loads_allowed().build();
    let img = parse64(&bytes).unwrap();
    assert_eq!(img.program_headers().len(), 1170);
    assert_eq!(img.load_segments().count(), 0);
}

impl Builder {
    /// Linux accepts an image with no `PT_LOAD` at the parse stage; this
    /// helper documents that the builder does not add one implicitly.
    fn phdr_zero_loads_allowed(self) -> Self {
        self
    }
}

fn with_interp(path: &[u8], filesz_adjust: i64) -> Vec<u8> {
    let ehsize = 64u64;
    let table = 2 * 56u64;
    let offset = ehsize + table;
    let mut b = Builder::new(ElfClass::Elf64, ElfData::Lsb)
        .phdr(ProgramHeader {
            p_type: PT_INTERP,
            p_flags: PF_R,
            p_offset: offset,
            p_filesz: (path.len() as i64 + filesz_adjust) as u64,
            p_memsz: path.len() as u64,
            ..Default::default()
        })
        .phdr(load(0x400000, 0, 0, 0, PF_R));
    b.tail = path.to_vec();
    b.build()
}

#[test]
fn reads_first_interpreter_as_c_string() {
    let bytes = with_interp(b"/lib/ld-musl-x86_64.so.1\0", 0);
    let img = parse64(&bytes).unwrap();
    assert_eq!(img.interpreter(), Some(&b"/lib/ld-musl-x86_64.so.1"[..]));

    // Embedded NUL truncates exactly as the kernel's C-string use does.
    let bytes = with_interp(b"/lib/ld\0garbage\0", 0);
    assert_eq!(
        parse64(&bytes).unwrap().interpreter(),
        Some(&b"/lib/ld"[..])
    );
}

#[test]
fn rejects_malformed_interpreters() {
    assert_eq!(
        parse64(&with_interp(b"/lib/ld.so", 0)).unwrap_err(),
        ElfError::InterpreterNotTerminated
    );
    assert_eq!(
        parse64(&with_interp(b"\0", 0)).unwrap_err(),
        ElfError::BadInterpreterSize(1)
    );
    assert_eq!(
        parse64(&with_interp(b"/x\0", 5)).unwrap_err(),
        ElfError::InterpreterOutOfFile {
            offset: 176,
            size: 8
        }
    );
    let long = vec![b'a'; 4097];
    assert_eq!(
        parse64(&with_interp(&long, 0)).unwrap_err(),
        ElfError::BadInterpreterSize(4097)
    );
    // Exactly PATH_MAX bytes (including the NUL) is accepted.
    let mut max = vec![b'a'; 4095];
    max.push(0);
    assert_eq!(
        parse64(&with_interp(&max, 0))
            .unwrap()
            .interpreter()
            .unwrap()
            .len(),
        4095
    );
}

#[test]
fn only_first_interpreter_is_consulted() {
    // A second, malformed PT_INTERP is never read by Linux.
    let path = b"/ld\0";
    let mut b = Builder::new(ElfClass::Elf64, ElfData::Lsb)
        .phdr(ProgramHeader {
            p_type: PT_INTERP,
            p_offset: 64 + 3 * 56,
            p_filesz: 4,
            ..Default::default()
        })
        .phdr(ProgramHeader {
            p_type: PT_INTERP,
            p_offset: u64::MAX,
            p_filesz: 1,
            ..Default::default()
        })
        .phdr(load(0x400000, 0, 0, 0, PF_R));
    b.tail = path.to_vec();
    let bytes = b.build();
    assert_eq!(parse64(&bytes).unwrap().interpreter(), Some(&b"/ld"[..]));
}

#[test]
fn last_gnu_stack_wins() {
    let stack = |flags| ProgramHeader {
        p_type: PT_GNU_STACK,
        p_flags: flags,
        ..Default::default()
    };
    let bytes = Builder::new(ElfClass::Elf64, ElfData::Lsb)
        .phdr(load(0x400000, 0, 0, 0, PF_R))
        .phdr(stack(PF_R | PF_W | PF_X))
        .phdr(stack(PF_R | PF_W))
        .build();
    assert_eq!(parse64(&bytes).unwrap().gnu_stack_executable(), Some(false));
    let bytes = Builder::new(ElfClass::Elf64, ElfData::Lsb)
        .phdr(load(0x400000, 0, 0, 0, PF_R))
        .phdr(stack(PF_R | PF_W | PF_X))
        .build();
    assert_eq!(parse64(&bytes).unwrap().gnu_stack_executable(), Some(true));
}

#[test]
fn mapping_geometry_matches_linux_helpers() {
    let mut a = load(0x1234, 0x234, 0x10, 0x10, PF_R);
    a.p_align = 0x10000;
    let mut b = load(0x21000, 0x1000, 0x10, 0x3000, PF_R | PF_W);
    b.p_align = 3; // not a power of two: ignored
    let mut e = Builder::new(ElfClass::Elf64, ElfData::Lsb);
    e.e_type = ET_DYN;
    let bytes = e.phdr(a).phdr(b).build();
    let img = parse64(&bytes).unwrap();
    assert_eq!(img.max_load_alignment(0x1000), 0x10000);
    // 0x21000 + 0x3000 - ELF_PAGESTART(0x1234) = 0x24000 - 0x1000.
    assert_eq!(img.total_mapping_size(0x1000), Some(0x23000));
}

#[test]
fn total_mapping_size_uses_file_order_like_linux() {
    // Unsorted PT_LOADs are accepted; the span uses the first and the last
    // entry in file order, and a wrapping span is reported as None.
    let bytes = Builder::new(ElfClass::Elf64, ElfData::Lsb)
        .phdr(load(0x50000, 0, 0x10, 0x10, PF_R))
        .phdr(load(0x10000, 0, 0x10, 0x10, PF_R))
        .build();
    let img = parse64(&bytes).unwrap();
    assert_eq!(img.total_mapping_size(0x1000), None);
    assert_eq!(img.max_load_alignment(0x1000), 0x1000);
}

#[test]
fn hostile_program_headers_never_panic() {
    // Deterministic pseudo-random corruption of a valid image.
    let base = with_interp(b"/lib/ld.so\0", 0);
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    for _ in 0..20_000 {
        let mut bytes = base.clone();
        for _ in 0..4 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let idx = (state as usize) % bytes.len();
            bytes[idx] = (state >> 32) as u8;
        }
        if let Ok(img) = parse64(&bytes) {
            let _ = img.total_mapping_size(0x1000);
            let _ = img.max_load_alignment(0x1000);
            let _ = img.gnu_stack_executable();
        }
        let _ = identify(&bytes);
        let _ = ElfImage::parse(&bytes, ElfClass::Elf32, ElfData::Msb);
    }
}
