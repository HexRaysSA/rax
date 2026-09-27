//! PE parser tests. Expected outcomes follow the PE Format specification
//! (field offsets, acceptance rules, directory layouts), not the parser's
//! own output.

use super::exports::{ExportDirectory, ExportTarget, ForwardSymbol, parse_forwarder};
use super::imports::{self, ImportRef};
use super::loadcfg::LoadConfig;
use super::pdata;
use super::relocs::{self, RelocError};
use super::resources::{ResId, ResourceTree};
use super::tls::{self, TlsDirectory};
use super::*;

#[path = "audit_tests.rs"]
mod audit;

/// One section of a synthetic image.
#[derive(Clone)]
struct Sec {
    name: &'static str,
    va: u32,
    vsize: u32,
    data: Vec<u8>,
    raw_size: Option<u32>,
    raw_ptr: Option<u32>,
    chars: u32,
}

impl Sec {
    fn new(name: &'static str, va: u32, vsize: u32, data: Vec<u8>, chars: u32) -> Self {
        Sec {
            name,
            va,
            vsize,
            data,
            raw_size: None,
            raw_ptr: None,
            chars,
        }
    }
}

/// Minimal PE writer for synthetic headers.
struct Builder {
    kind: PeKind,
    machine: u16,
    characteristics: u16,
    image_base: u64,
    section_alignment: u32,
    file_alignment: u32,
    size_of_image: Option<u32>,
    size_of_headers: Option<u32>,
    size_of_optional_header: Option<u16>,
    number_of_rva_and_sizes: u32,
    entry: u32,
    dirs: [DataDirectory; 16],
    sections: Vec<Sec>,
    lfanew: u32,
}

const CODE_RX: u32 = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
const DATA_RW: u32 = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
const DATA_R: u32 = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;

impl Builder {
    fn new(kind: PeKind) -> Self {
        Builder {
            kind,
            machine: match kind {
                PeKind::Pe32 => IMAGE_FILE_MACHINE_I386,
                PeKind::Pe32Plus => IMAGE_FILE_MACHINE_AMD64,
            },
            characteristics: IMAGE_FILE_EXECUTABLE_IMAGE,
            image_base: match kind {
                PeKind::Pe32 => 0x40_0000,
                PeKind::Pe32Plus => 0x1_4000_0000,
            },
            section_alignment: 0x1000,
            file_alignment: 0x200,
            size_of_image: None,
            size_of_headers: None,
            size_of_optional_header: None,
            number_of_rva_and_sizes: 16,
            entry: 0x1000,
            dirs: [DataDirectory::default(); 16],
            sections: vec![Sec::new(".text", 0x1000, 0x10, vec![0xC3; 0x10], CODE_RX)],
            lfanew: 0x40,
        }
    }

    fn section(mut self, s: Sec) -> Self {
        self.sections.push(s);
        self
    }

    fn opt_size(&self) -> u16 {
        self.size_of_optional_header
            .unwrap_or(self.kind.directories_offset() as u16 + 16 * 8)
    }

    fn headers_len(&self) -> u32 {
        self.lfanew + 24 + u32::from(self.opt_size()) + 40 * self.sections.len() as u32
    }

    fn build(&self) -> Vec<u8> {
        let fa = self.file_alignment;
        let size_of_headers = self
            .size_of_headers
            .unwrap_or_else(|| self.headers_len().div_ceil(fa) * fa);
        let last_end = self
            .sections
            .iter()
            .map(|s| s.va + s.vsize.max(s.data.len() as u32))
            .max()
            .unwrap_or(size_of_headers);
        let sa = self.section_alignment;
        let size_of_image = self
            .size_of_image
            .unwrap_or_else(|| last_end.div_ceil(sa) * sa);

        let mut out = vec![0u8; size_of_headers as usize];
        out[0..2].copy_from_slice(b"MZ");
        out[0x3C..0x40].copy_from_slice(&self.lfanew.to_le_bytes());
        let mut h = Vec::new();
        h.extend_from_slice(b"PE\0\0");
        h.extend_from_slice(&self.machine.to_le_bytes());
        h.extend_from_slice(&(self.sections.len() as u16).to_le_bytes());
        h.extend_from_slice(&0x6000_0000u32.to_le_bytes()); // timestamp
        h.extend_from_slice(&0u32.to_le_bytes());
        h.extend_from_slice(&0u32.to_le_bytes());
        h.extend_from_slice(&self.opt_size().to_le_bytes());
        h.extend_from_slice(&self.characteristics.to_le_bytes());
        let opt_start = h.len();
        let magic = match self.kind {
            PeKind::Pe32 => PE32_MAGIC,
            PeKind::Pe32Plus => PE32_PLUS_MAGIC,
        };
        h.extend_from_slice(&magic.to_le_bytes());
        h.extend_from_slice(&[14, 0]); // linker version
        h.extend_from_slice(&[0u8; 12]); // code/data sizes
        h.extend_from_slice(&self.entry.to_le_bytes());
        h.extend_from_slice(&0x1000u32.to_le_bytes()); // BaseOfCode
        match self.kind {
            PeKind::Pe32 => {
                h.extend_from_slice(&0u32.to_le_bytes()); // BaseOfData
                h.extend_from_slice(&(self.image_base as u32).to_le_bytes());
            }
            PeKind::Pe32Plus => h.extend_from_slice(&self.image_base.to_le_bytes()),
        }
        h.extend_from_slice(&self.section_alignment.to_le_bytes());
        h.extend_from_slice(&self.file_alignment.to_le_bytes());
        for v in [6u16, 0, 0, 0, 6, 0] {
            h.extend_from_slice(&v.to_le_bytes());
        }
        h.extend_from_slice(&0u32.to_le_bytes()); // Win32VersionValue
        h.extend_from_slice(&size_of_image.to_le_bytes());
        h.extend_from_slice(&size_of_headers.to_le_bytes());
        h.extend_from_slice(&0u32.to_le_bytes()); // CheckSum
        h.extend_from_slice(&IMAGE_SUBSYSTEM_WINDOWS_CUI.to_le_bytes());
        h.extend_from_slice(&0x8160u16.to_le_bytes());
        for v in [0x10_0000u64, 0x1000, 0x10_0000, 0x1000] {
            match self.kind {
                PeKind::Pe32 => h.extend_from_slice(&(v as u32).to_le_bytes()),
                PeKind::Pe32Plus => h.extend_from_slice(&v.to_le_bytes()),
            }
        }
        h.extend_from_slice(&0u32.to_le_bytes()); // LoaderFlags
        h.extend_from_slice(&self.number_of_rva_and_sizes.to_le_bytes());
        for d in &self.dirs {
            h.extend_from_slice(&d.rva.to_le_bytes());
            h.extend_from_slice(&d.size.to_le_bytes());
        }
        h.resize(opt_start + usize::from(self.opt_size()), 0);
        let mut raw = size_of_headers;
        let mut placed = Vec::new();
        for s in &self.sections {
            let raw_size = s
                .raw_size
                .unwrap_or_else(|| (s.data.len() as u32).div_ceil(fa) * fa);
            let ptr = s.raw_ptr.unwrap_or(if raw_size == 0 { 0 } else { raw });
            let mut name = [0u8; 8];
            name[..s.name.len()].copy_from_slice(s.name.as_bytes());
            h.extend_from_slice(&name);
            h.extend_from_slice(&s.vsize.to_le_bytes());
            h.extend_from_slice(&s.va.to_le_bytes());
            h.extend_from_slice(&raw_size.to_le_bytes());
            h.extend_from_slice(&ptr.to_le_bytes());
            h.extend_from_slice(&[0u8; 12]);
            h.extend_from_slice(&s.chars.to_le_bytes());
            placed.push((ptr, raw_size, s.data.clone()));
            if s.raw_ptr.is_none() {
                raw += raw_size;
            }
        }
        let start = self.lfanew as usize;
        if out.len() < start + h.len() {
            out.resize(start + h.len(), 0);
        }
        out[start..start + h.len()].copy_from_slice(&h);
        for (ptr, raw_size, data) in placed {
            let end = (ptr + raw_size) as usize;
            if out.len() < end {
                out.resize(end, 0);
            }
            let n = data.len().min(raw_size as usize);
            out[ptr as usize..ptr as usize + n].copy_from_slice(&data[..n]);
        }
        out
    }
}

fn parse(b: &Builder) -> Result<PeImage, PeError> {
    PeImage::parse(b.build())
}

// ---------------------------------------------------------------- headers

#[test]
fn parses_minimal_pe32_and_pe32_plus_field_offsets() {
    for kind in [PeKind::Pe32, PeKind::Pe32Plus] {
        let mut b = Builder::new(kind);
        b.dirs[dir::IMPORT] = DataDirectory {
            rva: 0x1234,
            size: 0x28,
        };
        let img = parse(&b).unwrap();
        let h = img.headers();
        assert_eq!(h.kind, kind);
        assert_eq!(h.nt_offset, 0x40);
        assert_eq!(h.image_base, b.image_base);
        assert_eq!(h.entry_rva, 0x1000);
        assert_eq!(h.section_alignment, 0x1000);
        assert_eq!(h.file_alignment, 0x200);
        assert_eq!(h.size_of_image, 0x2000);
        assert_eq!(h.subsystem, IMAGE_SUBSYSTEM_WINDOWS_CUI);
        assert_eq!(h.dll_characteristics, 0x8160);
        assert_eq!(h.stack_reserve, 0x10_0000);
        assert_eq!(h.stack_commit, 0x1000);
        assert_eq!(h.heap_reserve, 0x10_0000);
        assert_eq!(h.heap_commit, 0x1000);
        assert_eq!(h.subsystem_version, (6, 0));
        assert_eq!(h.os_version, (6, 0));
        assert_eq!(
            h.directory(dir::IMPORT),
            DataDirectory {
                rva: 0x1234,
                size: 0x28
            }
        );
        assert_eq!(img.sections().len(), 1);
        assert_eq!(img.sections()[0].name_str(), ".text");
        assert!(is_pe(img.bytes()));
    }
}

#[test]
fn rejects_bad_signatures_and_magic() {
    let good = Builder::new(PeKind::Pe32Plus).build();
    let mut b = good.clone();
    b[0] = b'X';
    assert_eq!(PeImage::parse(b.clone()).unwrap_err(), PeError::BadDosMagic);
    assert!(!is_pe(&b));
    let mut b = good.clone();
    b[0x40] = b'X';
    assert_eq!(
        PeImage::parse(b).unwrap_err(),
        PeError::BadNtSignature { offset: 0x40 }
    );
    let mut b = good.clone();
    b[0x58..0x5A].copy_from_slice(&0x107u16.to_le_bytes()); // ROM magic
    assert_eq!(
        PeImage::parse(b).unwrap_err(),
        PeError::BadOptionalMagic(0x107)
    );
    // e_lfanew beyond the file.
    let mut b = good.clone();
    b[0x3C..0x40].copy_from_slice(&0xFFFF_FFF0u32.to_le_bytes());
    assert!(matches!(
        PeImage::parse(b).unwrap_err(),
        PeError::Truncated { .. }
    ));
    assert!(matches!(
        PeImage::parse(good[..0x30].to_vec()).unwrap_err(),
        PeError::Truncated { .. }
    ));
}

#[test]
fn optional_header_must_cover_windows_fields() {
    for kind in [PeKind::Pe32, PeKind::Pe32Plus] {
        let mut b = Builder::new(kind);
        let needed = kind.directories_offset() as u16;
        b.size_of_optional_header = Some(needed - 1);
        assert_eq!(
            parse(&b).unwrap_err(),
            PeError::OptionalHeaderTooSmall {
                size: needed - 1,
                needed
            }
        );
        // Exactly the fixed part: no directories at all.
        b.size_of_optional_header = Some(needed);
        b.dirs[dir::IMPORT] = DataDirectory { rva: 1, size: 1 };
        let img = parse(&b).unwrap();
        assert!(!img.headers().directory(dir::IMPORT).is_present());
    }
}

#[test]
fn number_of_rva_and_sizes_limits_directories() {
    let mut b = Builder::new(PeKind::Pe32Plus);
    b.dirs[dir::EXPORT] = DataDirectory { rva: 8, size: 8 };
    b.dirs[dir::IMPORT] = DataDirectory { rva: 16, size: 8 };
    b.number_of_rva_and_sizes = 1;
    let img = parse(&b).unwrap();
    assert!(img.headers().directory(dir::EXPORT).is_present());
    assert!(!img.headers().directory(dir::IMPORT).is_present());
    // A count above 16 is clamped to the 16 defined entries.
    b.number_of_rva_and_sizes = 0x1000;
    let img = parse(&b).unwrap();
    assert!(img.headers().directory(dir::IMPORT).is_present());
    assert_eq!(img.headers().number_of_rva_and_sizes, 0x1000);
}

#[test]
fn executable_flag_and_machine_word_size_are_required() {
    let mut b = Builder::new(PeKind::Pe32);
    b.characteristics = 0;
    assert_eq!(parse(&b).unwrap_err(), PeError::NotExecutable);
    let mut b = Builder::new(PeKind::Pe32);
    b.machine = IMAGE_FILE_MACHINE_AMD64;
    assert_eq!(
        parse(&b).unwrap_err(),
        PeError::MachineKindMismatch {
            machine: IMAGE_FILE_MACHINE_AMD64,
            kind: PeKind::Pe32
        }
    );
    let mut b = Builder::new(PeKind::Pe32Plus);
    b.machine = IMAGE_FILE_MACHINE_I386;
    assert!(matches!(
        parse(&b).unwrap_err(),
        PeError::MachineKindMismatch { .. }
    ));
    let mut b = Builder::new(PeKind::Pe32Plus);
    b.machine = IMAGE_FILE_MACHINE_ARM64;
    assert_eq!(
        parse(&b).unwrap().headers().machine,
        IMAGE_FILE_MACHINE_ARM64
    );
}

#[test]
fn alignment_rules() {
    // SectionAlignment below FileAlignment.
    let mut b = Builder::new(PeKind::Pe32);
    b.section_alignment = 0x100;
    b.file_alignment = 0x200;
    assert!(matches!(
        parse(&b).unwrap_err(),
        PeError::BadAlignment { .. }
    ));
    // Not a power of two.
    let mut b = Builder::new(PeKind::Pe32);
    b.file_alignment = 0x300;
    assert!(matches!(
        parse(&b).unwrap_err(),
        PeError::BadAlignment { .. }
    ));
    // Below the page size, FileAlignment must equal SectionAlignment.
    let mut b = Builder::new(PeKind::Pe32);
    b.section_alignment = 0x200;
    b.file_alignment = 0x100;
    assert!(matches!(
        parse(&b).unwrap_err(),
        PeError::BadAlignment { .. }
    ));
    // FileAlignment below 512 is only advisory ("should be").
    let mut b = Builder::new(PeKind::Pe32);
    b.file_alignment = 0x20;
    assert!(parse(&b).is_ok());
}

#[test]
fn section_count_limit_is_96() {
    let mut b = Builder::new(PeKind::Pe32Plus);
    b.sections.clear();
    for i in 0..96u32 {
        // The 96 section headers push SizeOfHeaders past 0x1000.
        b.sections.push(Sec::new(
            ".d",
            0x1000 * (i + 2),
            0x10,
            vec![1; 0x10],
            DATA_R,
        ));
    }
    b.entry = 0;
    assert!(parse(&b).is_ok());
    b.sections
        .push(Sec::new(".d", 0x1000 * 98, 0x10, vec![1; 0x10], DATA_R));
    assert_eq!(parse(&b).unwrap_err(), PeError::TooManySections(97));
}

#[test]
fn section_layout_rules() {
    // Unaligned VirtualAddress.
    let mut b = Builder::new(PeKind::Pe32);
    b.sections[0].va = 0x1800;
    b.entry = 0x1800;
    assert_eq!(
        parse(&b).unwrap_err(),
        PeError::BadSectionLayout { index: 0 }
    );
    // Overlapping the headers.
    let mut b = Builder::new(PeKind::Pe32);
    b.sections[0].va = 0;
    b.entry = 0;
    assert_eq!(
        parse(&b).unwrap_err(),
        PeError::BadSectionLayout { index: 0 }
    );
    // Descending order.
    let b = Builder::new(PeKind::Pe32).section(Sec::new(".d", 0x0000, 0x10, vec![1], DATA_R));
    assert_eq!(
        parse(&b).unwrap_err(),
        PeError::BadSectionLayout { index: 1 }
    );
    // Overlapping the previous section: .text spans 0x1000..0x3000.
    let mut b = Builder::new(PeKind::Pe32).section(Sec::new(".d", 0x2000, 0x10, vec![1], DATA_R));
    b.sections[0].vsize = 0x1001;
    assert_eq!(
        parse(&b).unwrap_err(),
        PeError::BadSectionLayout { index: 1 }
    );
    // Past SizeOfImage.
    let mut b = Builder::new(PeKind::Pe32);
    b.size_of_image = Some(0x1000);
    assert_eq!(
        parse(&b).unwrap_err(),
        PeError::BadSectionLayout { index: 0 }
    );
    // File data outside the file (the builder writes it; cut the file).
    let mut b = Builder::new(PeKind::Pe32);
    b.sections[0].raw_ptr = Some(0x1000);
    b.sections[0].raw_size = Some(0x200);
    let mut bytes = b.build();
    bytes.truncate(0x1100);
    assert_eq!(
        PeImage::parse(bytes).unwrap_err(),
        PeError::SectionDataOutOfFile { index: 0 }
    );
}

#[test]
fn image_size_and_entry_point_bounds() {
    let mut b = Builder::new(PeKind::Pe32);
    b.size_of_image = Some(0);
    assert!(matches!(
        parse(&b).unwrap_err(),
        PeError::BadImageSize { .. } | PeError::BadSectionLayout { .. }
    ));
    let mut b = Builder::new(PeKind::Pe32);
    b.entry = 0x2000;
    assert_eq!(parse(&b).unwrap_err(), PeError::BadEntryPoint(0x2000));
    // PE Format requires SizeOfImage to be a multiple of SectionAlignment.
    let mut b = Builder::new(PeKind::Pe32);
    b.size_of_image = Some(0x1801);
    assert!(matches!(parse(&b), Err(PeError::BadImageSize { .. })));
}

// ---------------------------------------------------------------- mapping

#[test]
fn memory_image_places_sections_and_zero_fills() {
    let mut data = vec![0xAAu8; 0x300];
    data[0] = 0x11;
    let mut b = Builder::new(PeKind::Pe32Plus)
        // VirtualSize < SizeOfRawData: only VirtualSize rounded to the
        // section alignment is mapped (all 0x400 raw bytes fit in a page).
        .section(Sec::new(".data", 0x2000, 0x100, data.clone(), DATA_RW))
        // Uninitialized: no file data, VirtualSize bytes of zeros.
        .section(Sec::new(".bss", 0x3000, 0x1800, Vec::new(), DATA_RW));
    b.sections[2].raw_size = Some(0);
    let img = parse(&b).unwrap();
    assert_eq!(img.mapped_size(), 0x5000);
    let mem = img.memory_image();
    assert_eq!(mem.len(), 0x5000);
    assert_eq!(&mem[0..2], b"MZ");
    assert_eq!(mem[0x1000], 0xC3);
    assert_eq!(mem[0x1010], 0, "past the section's raw data");
    assert_eq!(mem[0x2000], 0x11);
    assert_eq!(mem[0x22FF], 0xAA, "raw data past VirtualSize, same page");
    assert_eq!(mem[0x2300], 0, "raw size 0x400 includes zero padding");
    assert!(mem[0x3000..0x5000].iter().all(|&b| b == 0));
    assert_eq!(img.rva_to_file_offset(0x2000), Some(0x400));
    assert_eq!(img.rva_to_file_offset(0x3000), None);
    assert_eq!(img.rva_to_file_offset(0x10), Some(0x10));
    assert_eq!(img.section_at(0x3FFF).unwrap().name_str(), ".bss");
    assert!(img.section_at(0x5000).is_none());
}

#[test]
fn regions_follow_section_characteristics() {
    let b = Builder::new(PeKind::Pe32)
        .section(Sec::new(".rdata", 0x2000, 0x10, vec![1], DATA_R))
        .section(Sec::new(".data", 0x3000, 0x1001, vec![1], DATA_RW))
        .section(Sec::new(".x", 0x5000, 0x10, vec![1], IMAGE_SCN_MEM_EXECUTE))
        .section(Sec::new(".none", 0x6000, 0x10, vec![1], 0));
    let img = parse(&b).unwrap();
    let r = img.regions();
    let p = |read, write, execute| ImageProtection {
        read,
        write,
        execute,
    };
    assert_eq!(r[0].rva, 0);
    assert_eq!(r[0].len, 0x1000);
    assert_eq!(r[0].protection, ImageProtection::READONLY);
    assert_eq!((r[1].rva, r[1].protection), (0x1000, p(true, false, true)));
    assert_eq!((r[2].rva, r[2].protection), (0x2000, p(true, false, false)));
    assert_eq!(
        (r[3].rva, r[3].len, r[3].protection),
        (0x3000, 0x2000, p(true, true, false))
    );
    assert_eq!((r[4].rva, r[4].protection), (0x5000, p(true, false, true)));
    assert_eq!(
        (r[5].rva, r[5].protection),
        (0x6000, p(false, false, false))
    );
}

#[test]
fn low_alignment_images_map_the_file_as_is() {
    let mut b = Builder::new(PeKind::Pe32);
    b.section_alignment = 0x200;
    b.file_alignment = 0x200;
    b.size_of_headers = Some(0x200);
    b.sections = vec![Sec::new(".text", 0x200, 0x10, vec![0x90; 0x10], CODE_RX)];
    b.sections[0].raw_ptr = Some(0x200);
    b.entry = 0x200;
    let img = parse(&b).unwrap();
    assert!(img.low_alignment());
    let r = img.regions();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].protection, ImageProtection::ALL);
    assert_eq!(img.memory_image()[0x200], 0x90);
    // The section's file offset must equal its RVA.
    b.sections[0].raw_ptr = Some(0x400);
    b.size_of_image = Some(0x800);
    assert_eq!(
        parse(&b).unwrap_err(),
        PeError::BadSectionLayout { index: 0 }
    );
}

#[test]
fn hostile_headers_never_panic() {
    let good = Builder::new(PeKind::Pe32Plus)
        .section(Sec::new(".d", 0x2000, 0x10, vec![1; 0x10], DATA_RW))
        .build();
    // Flip every byte of the headers to a few extreme values.
    for i in 0..0x200 {
        for v in [0x00u8, 0x7F, 0x80, 0xFF] {
            let mut b = good.clone();
            b[i] = v;
            if let Ok(img) = PeImage::parse(b) {
                let _ = img.memory_image();
                let _ = img.regions();
            }
        }
    }
    for len in 0..good.len() {
        let _ = PeImage::parse(good[..len].to_vec());
    }
}

// ------------------------------------------------------------ directories

/// A memory image with little-endian writers.
struct Mem(Vec<u8>);

impl Mem {
    fn new(len: usize) -> Self {
        Mem(vec![0; len])
    }
    fn u16(&mut self, at: usize, v: u16) {
        self.0[at..at + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn u32(&mut self, at: usize, v: u32) {
        self.0[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn u64(&mut self, at: usize, v: u64) {
        self.0[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }
    fn str(&mut self, at: usize, s: &str) {
        self.0[at..at + s.len()].copy_from_slice(s.as_bytes());
        self.0[at + s.len()] = 0;
    }
}

/// An export directory at 0x100 (size 0x200) with functions at ordinals
/// base 5: [0x1000, 0 (unused), forwarder, 0x2000], names sorted
/// ["Alpha" -> 0, "Fwd" -> 2, "Zeta" -> 3].
fn export_image() -> (Mem, DataDirectory) {
    let mut m = Mem::new(0x1000);
    let dirr = DataDirectory {
        rva: 0x100,
        size: 0x200,
    };
    m.u32(0x100 + 12, 0x280); // Name
    m.str(0x280, "test.dll");
    m.u32(0x100 + 16, 5); // Base
    m.u32(0x100 + 20, 4); // NumberOfFunctions
    m.u32(0x100 + 24, 3); // NumberOfNames
    m.u32(0x100 + 28, 0x140); // AddressOfFunctions
    m.u32(0x100 + 32, 0x160); // AddressOfNames
    m.u32(0x100 + 36, 0x170); // AddressOfNameOrdinals
    m.u32(0x140, 0x1000);
    m.u32(0x144, 0);
    m.u32(0x148, 0x290); // inside the directory: forwarder
    m.u32(0x14C, 0x2000);
    m.str(0x290, "NTDLL.RtlAllocateHeap");
    m.u32(0x160, 0x2B0);
    m.u32(0x164, 0x2C0);
    m.u32(0x168, 0x2D0);
    m.str(0x2B0, "Alpha");
    m.str(0x2C0, "Fwd");
    m.str(0x2D0, "Zeta");
    m.u16(0x170, 0);
    m.u16(0x172, 2);
    m.u16(0x174, 3);
    (m, dirr)
}

#[test]
fn exports_by_name_ordinal_hint_and_forwarder() {
    let (m, range) = export_image();
    let e = ExportDirectory::read(&m.0, range).unwrap().unwrap();
    assert_eq!(e.module_name(&m.0).unwrap().unwrap(), b"test.dll");
    assert_eq!(
        e.by_name(&m.0, b"Alpha", None).unwrap(),
        Some((0, ExportTarget::Rva(0x1000)))
    );
    assert_eq!(
        e.by_name(&m.0, b"Zeta", None).unwrap(),
        Some((3, ExportTarget::Rva(0x2000)))
    );
    // A correct hint and a wrong one resolve alike.
    assert_eq!(
        e.by_name(&m.0, b"Zeta", Some(2)).unwrap(),
        Some((3, ExportTarget::Rva(0x2000)))
    );
    assert_eq!(
        e.by_name(&m.0, b"Zeta", Some(0)).unwrap(),
        Some((3, ExportTarget::Rva(0x2000)))
    );
    // Names are case-sensitive.
    assert_eq!(e.by_name(&m.0, b"alpha", None).unwrap(), None);
    assert_eq!(e.by_name(&m.0, b"Beta", None).unwrap(), None);
    // Ordinals are biased by Base.
    assert_eq!(
        e.by_ordinal(&m.0, 5).unwrap(),
        Some(ExportTarget::Rva(0x1000))
    );
    assert_eq!(e.by_ordinal(&m.0, 6).unwrap(), None, "empty entry");
    assert_eq!(e.by_ordinal(&m.0, 4).unwrap(), None, "below Base");
    assert_eq!(e.by_ordinal(&m.0, 9).unwrap(), None, "past the table");
    let fwd = e.by_ordinal(&m.0, 7).unwrap().unwrap();
    assert_eq!(
        fwd,
        ExportTarget::Forwarder(b"NTDLL.RtlAllocateHeap".to_vec())
    );
    assert_eq!(e.names(&m.0).unwrap().len(), 3);
}

#[test]
fn forwarder_strings_split_at_the_last_dot() {
    let f = parse_forwarder(b"NTDLL.RtlAllocateHeap").unwrap();
    assert_eq!(f.module, b"NTDLL");
    assert_eq!(f.symbol, ForwardSymbol::Name(b"RtlAllocateHeap".to_vec()));
    let f = parse_forwarder(b"api-ms-win-core-a-l1-1-0.Foo").unwrap();
    assert_eq!(f.module, b"api-ms-win-core-a-l1-1-0");
    let f = parse_forwarder(b"WS2_32.#115").unwrap();
    assert_eq!(f.symbol, ForwardSymbol::Ordinal(115));
    assert!(parse_forwarder(b"NoDot").is_none());
    assert!(parse_forwarder(b"X.").is_none());
    assert!(parse_forwarder(b"X.#abc").is_none());
}

#[test]
fn imports_by_name_and_ordinal_for_both_widths() {
    for kind in [PeKind::Pe32, PeKind::Pe32Plus] {
        let w = kind.pointer_size();
        let mut m = Mem::new(0x1000);
        // Two descriptors, then a terminator.
        let d0 = 0x100;
        m.u32(d0, 0x200); // OriginalFirstThunk
        m.u32(d0 + 12, 0x300); // Name
        m.u32(d0 + 16, 0x400); // FirstThunk
        let d1 = d0 + 20;
        m.u32(d1, 0); // no lookup table: use the IAT
        m.u32(d1 + 12, 0x310);
        m.u32(d1 + 16, 0x500);
        m.str(0x300, "KERNEL32.dll");
        m.str(0x310, "user32.dll");
        let put = |m: &mut Mem, at: usize, v: u64| match kind {
            PeKind::Pe32 => m.u32(at, v as u32),
            PeKind::Pe32Plus => m.u64(at, v),
        };
        put(&mut m, 0x200, 0x600); // by name
        put(&mut m, 0x200 + w, kind.ordinal_flag() | 0x1_0007); // ordinal 7
        m.u16(0x600, 42);
        m.str(0x602, "ExitProcess");
        put(&mut m, 0x500, kind.ordinal_flag() | 3);
        let range = DataDirectory {
            rva: 0x100,
            size: 60,
        };
        let ds = imports::descriptors(&m.0, range).unwrap();
        assert_eq!(ds.len(), 2);
        assert_eq!(ds[0].dll_name(&m.0).unwrap(), b"KERNEL32.dll");
        let t = ds[0].thunks(&m.0, kind).unwrap();
        assert_eq!(t.len(), 2);
        assert_eq!(t[0].iat_slot, 0x400);
        assert_eq!(
            t[0].symbol,
            ImportRef::Name {
                hint: 42,
                name: b"ExitProcess".to_vec()
            }
        );
        assert_eq!(t[1].iat_slot, 0x400 + w as u32);
        assert_eq!(t[1].symbol, ImportRef::Ordinal(7), "low 16 bits");
        let t = ds[1].thunks(&m.0, kind).unwrap();
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].iat_slot, 0x500);
        assert_eq!(t[0].symbol, ImportRef::Ordinal(3));
    }
}

#[test]
fn import_walk_stops_at_missing_name_or_iat() {
    let mut m = Mem::new(0x400);
    m.u32(0x100 + 12, 0x300);
    m.u32(0x100 + 16, 0); // FirstThunk 0 ends the table
    m.u32(0x114 + 12, 0x300);
    m.u32(0x114 + 16, 0x200);
    let ds = imports::descriptors(
        &m.0,
        DataDirectory {
            rva: 0x100,
            size: 40,
        },
    )
    .unwrap();
    assert!(ds.is_empty());
}

#[test]
fn delay_descriptors_are_rva_based() {
    let mut m = Mem::new(0x1000);
    m.u32(0x100, 1); // RvaBased
    m.u32(0x104, 0x300);
    m.u32(0x10C, 0x400); // IAT
    m.u32(0x110, 0x500); // INT
    m.str(0x300, "delayed.dll");
    m.u64(0x500, 0x600);
    m.u16(0x600, 0);
    m.str(0x602, "Later");
    let ds = imports::delay_descriptors(
        &m.0,
        DataDirectory {
            rva: 0x100,
            size: 64,
        },
    )
    .unwrap();
    assert_eq!(ds.len(), 1);
    let t = ds[0].thunks(&m.0, PeKind::Pe32Plus).unwrap();
    assert_eq!(t[0].iat_slot, 0x400);
    assert_eq!(
        t[0].symbol,
        ImportRef::Name {
            hint: 0,
            name: b"Later".to_vec()
        }
    );
}

#[test]
fn base_relocations_apply_each_type() {
    let mut m = Mem::new(0x2000);
    // Block for page 0x1000: HIGHLOW @0x10, DIR64 @0x20, HIGH @0x30,
    // LOW @0x34, HIGHADJ @0x38 (+ low half 0x8000), ABSOLUTE padding.
    m.u32(0x100, 0x1000);
    m.u32(0x104, 8 + 2 * 7);
    let entries = [0x3010u16, 0xA020, 0x1030, 0x2034, 0x4038, 0x8000, 0x0000];
    for (i, e) in entries.iter().enumerate() {
        m.u16(0x108 + 2 * i, *e);
    }
    m.u32(0x1010, 0x0040_1000);
    m.u64(0x1020, 0x1_4000_1000);
    m.u16(0x1030, 0x0040);
    m.u16(0x1034, 0xFFF0);
    m.u16(0x1038, 0x0040);
    let range = DataDirectory {
        rva: 0x100,
        size: 8 + 14,
    };
    let delta = 0x0001_0010u64;
    relocs::apply(&mut m.0, range, delta).unwrap();
    let rd = |at: usize, n: usize| {
        let mut v = [0u8; 8];
        v[..n].copy_from_slice(&m.0[at..at + n]);
        u64::from_le_bytes(v)
    };
    assert_eq!(rd(0x1010, 4), 0x0041_1010);
    assert_eq!(rd(0x1020, 8), 0x1_4001_1010);
    assert_eq!(rd(0x1030, 2), 0x0041, "HIGH adds delta >> 16");
    assert_eq!(rd(0x1034, 2), 0x0000, "LOW adds delta, wrapping");
    // HIGHADJ: 0x0040_0000 - 0x8000 + 0x0001_0010 + 0x8000
    // = 0x0041_0010 -> rounded high 0x0041.
    assert_eq!(rd(0x1038, 2), 0x0041);
}

#[test]
fn base_relocations_reject_malformed_input() {
    let mut m = Mem::new(0x2000);
    m.u32(0x100, 0x1000);
    m.u32(0x104, 7); // smaller than the header
    let range = DataDirectory {
        rva: 0x100,
        size: 16,
    };
    assert_eq!(
        relocs::apply(&mut m.0, range, 1),
        Err(RelocError::BadBlock { rva: 0x100 })
    );
    m.u32(0x104, 10);
    m.u16(0x108, 0x3FFE); // HIGHLOW at 0x1FFE: crosses the end
    let range = DataDirectory {
        rva: 0x100,
        size: 10,
    };
    assert_eq!(
        relocs::apply(&mut m.0, range, 1),
        Err(RelocError::TargetOutOfImage { rva: 0x1FFE })
    );
    m.u16(0x108, 0x5000); // ARM_MOV32 is not applied to these machines
    assert_eq!(
        relocs::apply(&mut m.0, range, 1),
        Err(RelocError::UnsupportedType {
            kind: 5,
            rva: 0x1000
        })
    );
    // HIGHADJ without its second slot.
    m.u16(0x108, 0x4000);
    assert_eq!(
        relocs::apply(&mut m.0, range, 1),
        Err(RelocError::BadBlock { rva: 0x100 })
    );
    // A zero delta still validates but changes nothing.
    m.u16(0x108, 0x3010);
    let before = m.0.clone();
    relocs::apply(&mut m.0, range, 0).unwrap();
    assert_eq!(before, m.0);
}

#[test]
fn tls_directory_and_callbacks() {
    for kind in [PeKind::Pe32, PeKind::Pe32Plus] {
        let w = kind.pointer_size();
        let mut m = Mem::new(0x1000);
        let put = |m: &mut Mem, at: usize, v: u64| match kind {
            PeKind::Pe32 => m.u32(at, v as u32),
            PeKind::Pe32Plus => m.u64(at, v),
        };
        let base = 0x40_0000u64;
        put(&mut m, 0x100, base + 0x800);
        put(&mut m, 0x100 + w, base + 0x810);
        put(&mut m, 0x100 + 2 * w, base + 0x900);
        put(&mut m, 0x100 + 3 * w, base + 0x200);
        m.u32(0x100 + 4 * w, 0x30);
        m.u32(0x100 + 4 * w + 4, 0x0050_0000); // IMAGE_SCN_ALIGN_16BYTES
        put(&mut m, 0x200, base + 0x1111);
        put(&mut m, 0x200 + w, base + 0x2222);
        let t = TlsDirectory::read(
            &m.0,
            kind,
            DataDirectory {
                rva: 0x100,
                size: (4 * w + 8) as u32,
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(t.raw_size(), 0x10);
        assert_eq!(t.block_size(), 0x40);
        assert_eq!(t.address_of_index, base + 0x900);
        assert_eq!(t.alignment(), Some(16));
        let cbs = tls::callbacks(&m.0, kind, t.address_of_callbacks - base).unwrap();
        assert_eq!(cbs, vec![base + 0x1111, base + 0x2222]);
    }
}

#[test]
fn load_config_fields_respect_size() {
    let mut m = Mem::new(0x1000);
    // PE32+: SecurityCookie at 88, GuardFlags at 144.
    m.u32(0x100, 148);
    m.u64(0x100 + 88, 0x1_4000_3000);
    m.u32(0x100 + 144, 0x100);
    let c = LoadConfig::read(
        &m.0,
        PeKind::Pe32Plus,
        DataDirectory {
            rva: 0x100,
            size: 148,
        },
    )
    .unwrap()
    .unwrap();
    assert_eq!(c.security_cookie, Some(0x1_4000_3000));
    assert_eq!(c.guard_flags, Some(0x100));
    // A structure that ends before SecurityCookie.
    m.u32(0x100, 88);
    let c = LoadConfig::read(
        &m.0,
        PeKind::Pe32Plus,
        DataDirectory {
            rva: 0x100,
            size: 88,
        },
    )
    .unwrap()
    .unwrap();
    assert_eq!(c.security_cookie, None);
    // PE32: SecurityCookie at 60, SEHandlerTable 64, SEHandlerCount 68.
    let mut m = Mem::new(0x1000);
    m.u32(0x100, 72);
    m.u32(0x100 + 60, 0x40_3000);
    m.u32(0x100 + 64, 0x40_4000);
    m.u32(0x100 + 68, 3);
    let c = LoadConfig::read(
        &m.0,
        PeKind::Pe32,
        DataDirectory {
            rva: 0x100,
            size: 72,
        },
    )
    .unwrap()
    .unwrap();
    assert_eq!(c.security_cookie, Some(0x40_3000));
    assert_eq!(c.se_handler_table, Some(0x40_4000));
    assert_eq!(c.se_handler_count, Some(3));
    assert_eq!(c.guard_cf_check_function_pointer, None);
}

#[test]
fn resource_lookup_by_id_name_and_language() {
    let mut m = Mem::new(0x1000);
    let root = 0x100usize;
    // Root: one named type "MYTYPE", one id type 24 (RT_MANIFEST).
    m.u16(root + 12, 1);
    m.u16(root + 14, 1);
    m.u32(root + 16, 0x8000_0000 | 0x200); // name string at +0x200
    m.u32(root + 20, 0x8000_0000 | 0x40); // subdir
    m.u32(root + 24, 24);
    m.u32(root + 28, 0x8000_0000 | 0x80);
    let s = root + 0x200;
    m.u16(s, 6);
    for (i, c) in "MYTYPE".encode_utf16().enumerate() {
        m.u16(s + 2 + 2 * i, c);
    }
    // MYTYPE -> id 7 -> lang 0x407 data at +0x300.
    let d = root + 0x40;
    m.u16(d + 14, 1);
    m.u32(d + 16, 7);
    m.u32(d + 20, 0x8000_0000 | 0x60);
    let l = root + 0x60;
    m.u16(l + 14, 1);
    m.u32(l + 16, 0x407);
    m.u32(l + 20, 0x300);
    m.u32(root + 0x300, 0x900);
    m.u32(root + 0x304, 5);
    // RT_MANIFEST -> id 1 -> langs 0x409 and 0 (neutral preferred).
    let d = root + 0x80;
    m.u16(d + 14, 1);
    m.u32(d + 16, 1);
    m.u32(d + 20, 0x8000_0000 | 0xA0);
    let l = root + 0xA0;
    m.u16(l + 14, 2);
    m.u32(l + 16, 0x409);
    m.u32(l + 20, 0x310);
    m.u32(l + 24, 0);
    m.u32(l + 28, 0x320);
    m.u32(root + 0x310, 0xA00);
    m.u32(root + 0x314, 10);
    m.u32(root + 0x320, 0xB00);
    m.u32(root + 0x324, 20);
    let tree = ResourceTree::new(DataDirectory {
        rva: 0x100,
        size: 0x400,
    })
    .unwrap();
    let name: Vec<u16> = "mytype".encode_utf16().collect();
    let r = tree
        .find_resource(&m.0, &ResId::Name(name), &ResId::Id(7), None)
        .unwrap()
        .unwrap();
    assert_eq!((r.rva, r.size, r.language), (0x900, 5, 0x407));
    let r = tree
        .find_resource(&m.0, &ResId::Id(24), &ResId::Id(1), None)
        .unwrap()
        .unwrap();
    assert_eq!((r.rva, r.language), (0xB00, 0), "neutral first");
    let r = tree
        .find_resource(&m.0, &ResId::Id(24), &ResId::Id(1), Some(0x409))
        .unwrap()
        .unwrap();
    assert_eq!(r.rva, 0xA00);
    assert_eq!(
        tree.find_resource(&m.0, &ResId::Id(24), &ResId::Id(2), None)
            .unwrap(),
        None
    );
    assert_eq!(
        tree.names_of_type(&m.0, &ResId::Id(24)).unwrap(),
        vec![ResId::Id(1)]
    );
}

#[test]
fn pdata_lookup_x64_and_arm64() {
    let mut m = Mem::new(0x1000);
    for (i, (b, e)) in [(0x1000u32, 0x1010u32), (0x1020, 0x1080), (0x1100, 0x1101)]
        .iter()
        .enumerate()
    {
        m.u32(0x100 + 12 * i, *b);
        m.u32(0x104 + 12 * i, *e);
        m.u32(0x108 + 12 * i, 0x800 + i as u32);
    }
    let table = DataDirectory {
        rva: 0x100,
        size: 36,
    };
    let hit = |rva| {
        pdata::lookup_x64(&m.0, table, rva)
            .unwrap()
            .map(|(_, f)| f.begin)
    };
    assert_eq!(hit(0x1000), Some(0x1000));
    assert_eq!(hit(0x100F), Some(0x1000));
    assert_eq!(hit(0x1010), None, "EndAddress is exclusive");
    assert_eq!(hit(0x107F), Some(0x1020));
    assert_eq!(hit(0x1100), Some(0x1100));
    assert_eq!(hit(0xFFF), None);

    // ARM64: packed (Flag 1, length 4*8 = 32 bytes) and an .xdata record
    // whose header gives length 4 * 0x10 = 64 bytes.
    let mut m = Mem::new(0x1000);
    m.u32(0x100, 0x2000);
    m.u32(0x104, 1 | (8 << 2));
    m.u32(0x108, 0x2040);
    m.u32(0x10C, 0x600);
    m.u32(0x600, 0x10);
    let table = DataDirectory {
        rva: 0x100,
        size: 16,
    };
    let hit = |rva| {
        pdata::lookup_arm64(&m.0, table, rva)
            .unwrap()
            .map(|(_, f)| f.begin)
    };
    assert_eq!(hit(0x2000), Some(0x2000));
    assert_eq!(hit(0x201C), Some(0x2000));
    assert_eq!(hit(0x2020), None, "past the packed length");
    assert_eq!(hit(0x2040), Some(0x2040));
    assert_eq!(hit(0x207C), Some(0x2040));
    assert_eq!(hit(0x2080), None);
    assert_eq!(hit(0x1FFF), None);
}
