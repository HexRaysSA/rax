//! Built-in DLL images.
//!
//! A built-in DLL is synthesized as a well-formed PE image, so that
//! `GetModuleHandle`, `GetModuleFileName`, `VirtualQuery`, the loader's
//! module lists, and any code that reads a module's headers or export
//! directory observe an ordinary DLL:
//!
//! | Section | Content | Mapping |
//! |---|---|---|
//! | headers | MS-DOS header, PE32/PE32+ headers, section table | read-only |
//! | `.text` | 16-byte trap slots, then room for stubs of unimplemented imports | read-only (reported `PAGE_EXECUTE_READ`) |
//! | `.rdata` | export directory, name tables, forwarder strings | read-only |
//! | `.data` | data exports | read-write |
//!
//! The code section is mapped without execute permission, so fetching a
//! slot faults; that fault is the call into built-in code (see
//! [`crate::user::windows::traps`]).

use crate::user::image::pe::{
    IMAGE_FILE_32BIT_MACHINE, IMAGE_FILE_DLL, IMAGE_FILE_EXECUTABLE_IMAGE,
    IMAGE_FILE_LARGE_ADDRESS_AWARE, IMAGE_SCN_CNT_CODE, IMAGE_SCN_CNT_INITIALIZED_DATA,
    IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE, PE32_MAGIC, PE32_PLUS_MAGIC,
    dir,
};
use crate::user::windows::arch::WinArch;
use crate::user::windows::dll::BuiltinDll;
use crate::user::windows::hle::{DataSize, Item};
use crate::user::windows::traps::{SLOT_SIZE, SlotKind};

const PAGE: u32 = 0x1000;
/// Slots reserved for stubs of imports the DLL does not implement.
pub const MISSING_SLOTS: usize = 512;

/// Where an export of a built-in image points.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuiltinSym {
    /// An RVA in the image.
    Rva(u32),
    /// A forwarder.
    Forward(&'static str),
}

/// A synthesized image.
pub struct BuiltinImage {
    /// The memory image.
    pub bytes: Vec<u8>,
    /// RVA of the code section.
    pub text_rva: u32,
    /// Bytes of the code section.
    pub text_size: u32,
    /// Slot contents, in order.
    pub slots: Vec<SlotKind>,
    /// Slot capacity of the code section.
    pub capacity: usize,
    /// RVA and size of the read-only data section.
    pub rdata: (u32, u32),
    /// RVA and size of the data section.
    pub data: (u32, u32),
    /// Exports by name, in table order.
    pub symbols: Vec<(&'static str, BuiltinSym)>,
    /// Ordinal base (ordinal of the first export).
    pub ordinal_base: u32,
    /// The export directory's data-directory entry.
    pub export_dir: (u32, u32),
}

fn align(v: u32, a: u32) -> u32 {
    v.div_ceil(a) * a
}

fn put16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}

fn put32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

fn put64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

/// Builds the image of `dll` for `arch` at `base`, with `specials` slots
/// (the private `ntdll` callback-return, thread/fiber-start and retry traps) before the
/// function exports.
pub fn build(dll: &BuiltinDll, arch: WinArch, base: u64, specials: &[SlotKind]) -> BuiltinImage {
    // Exports for this architecture, first definition of a name winning.
    let mut exports = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for table in dll.exports {
        for e in table.iter() {
            if e.archs.has(arch) && seen.insert(e.name) {
                exports.push(e);
            }
        }
    }

    // .text: special slots, one slot per function, then the stub area.
    let mut slots: Vec<SlotKind> = specials.to_vec();
    let mut func_slot = Vec::with_capacity(exports.len());
    for e in &exports {
        if let Item::Func(api) = &e.item {
            func_slot.push(Some(slots.len()));
            slots.push(SlotKind::Api(api));
        } else {
            func_slot.push(None);
        }
    }
    let capacity = slots.len() + MISSING_SLOTS;
    let text_rva = PAGE;
    let text_size = align((capacity as u64 * SLOT_SIZE) as u32, PAGE);

    // .data: data exports, 16-byte aligned.
    let psize = arch.ptr_size() as u32;
    let mut data_off = Vec::with_capacity(exports.len());
    let mut data_len = 0u32;
    for e in &exports {
        if let Item::Data(size) = &e.item {
            let bytes = match size {
                DataSize::Bytes(n) => *n,
                DataSize::Ptrs(n) => n * psize,
            };
            data_len = align(data_len, 16);
            data_off.push(Some(data_len));
            data_len += bytes.max(1);
        } else {
            data_off.push(None);
        }
    }
    let rdata_rva = text_rva + text_size;

    // .rdata: IMAGE_EXPORT_DIRECTORY, EAT, name pointers, ordinals, then
    // strings (the DLL name, export names, forwarders).
    let n = exports.len() as u32;
    let mut names: Vec<(usize, &str)> = exports
        .iter()
        .enumerate()
        .map(|(i, e)| (i, e.name))
        .collect();
    names.sort_by(|a, b| a.1.as_bytes().cmp(b.1.as_bytes()));
    let dir_size = 40;
    let eat = dir_size;
    let npt = eat + 4 * n;
    let ot = npt + 4 * n;
    let mut strings = Vec::new();
    let strings_start = align(ot + 2 * n, 4);
    let mut string_at = |s: &str, strings: &mut Vec<u8>| -> u32 {
        let at = strings_start + strings.len() as u32;
        strings.extend_from_slice(s.as_bytes());
        strings.push(0);
        at
    };
    let dll_name = string_at(dll.display, &mut strings);
    let name_rvas: Vec<u32> = names
        .iter()
        .map(|(_, s)| rdata_rva + string_at(s, &mut strings))
        .collect();
    let forward_rvas: Vec<Option<u32>> = exports
        .iter()
        .map(|e| match &e.item {
            Item::Forward(to) => Some(rdata_rva + string_at(to, &mut strings)),
            _ => None,
        })
        .collect();
    let rdata_len = strings_start + strings.len() as u32;
    let rdata_size = align(rdata_len.max(1), PAGE);
    let data_rva = rdata_rva + rdata_size;
    let data_size = align(data_len.max(1), PAGE);
    let size_of_image = data_rva + data_size;

    let mut img = vec![0u8; size_of_image as usize];
    let fill: &[u8] = match arch {
        // INT3
        WinArch::X86 | WinArch::X64 => &[0xCC],
        // BRK #0xF000
        WinArch::Arm64 => &[0x00, 0x00, 0x3E, 0xD4],
    };
    for (i, b) in img[text_rva as usize..(text_rva + text_size) as usize]
        .iter_mut()
        .enumerate()
    {
        *b = fill[i % fill.len()];
    }

    // Export directory.
    let r = rdata_rva as usize;
    put32(&mut img, r + 4, 0); // TimeDateStamp
    put32(&mut img, r + 12, rdata_rva + dll_name);
    put32(&mut img, r + 16, 1); // Base
    put32(&mut img, r + 20, n);
    put32(&mut img, r + 24, n);
    put32(&mut img, r + 28, rdata_rva + eat);
    put32(&mut img, r + 32, rdata_rva + npt);
    put32(&mut img, r + 36, rdata_rva + ot);
    let mut symbols = Vec::with_capacity(exports.len());
    for (i, e) in exports.iter().enumerate() {
        let sym = if let Some(slot) = func_slot[i] {
            BuiltinSym::Rva(text_rva + (slot as u64 * SLOT_SIZE) as u32)
        } else if let Some(off) = data_off[i] {
            BuiltinSym::Rva(data_rva + off)
        } else if let Item::Forward(to) = &e.item {
            BuiltinSym::Forward(to)
        } else {
            unreachable!("every export is a function, data, or a forwarder")
        };
        let eat_value = match sym {
            BuiltinSym::Rva(rva) => rva,
            BuiltinSym::Forward(_) => forward_rvas[i].expect("forwarder string placed"),
        };
        put32(&mut img, r + (eat + 4 * i as u32) as usize, eat_value);
        symbols.push((e.name, sym));
    }
    for (k, (i, _)) in names.iter().enumerate() {
        put32(&mut img, r + (npt + 4 * k as u32) as usize, name_rvas[k]);
        put16(&mut img, r + (ot + 2 * k as u32) as usize, *i as u16);
    }
    img[r + strings_start as usize..r + strings_start as usize + strings.len()]
        .copy_from_slice(&strings);

    // Headers.
    img[0..2].copy_from_slice(b"MZ");
    put32(&mut img, 0x3C, 0x40);
    let nt = 0x40usize;
    img[nt..nt + 4].copy_from_slice(b"PE\0\0");
    let coff = nt + 4;
    put16(&mut img, coff, arch.machine());
    put16(&mut img, coff + 2, 3);
    let opt_size: u16 = if arch.is64() { 240 } else { 224 };
    put16(&mut img, coff + 16, opt_size);
    let characteristics = IMAGE_FILE_EXECUTABLE_IMAGE
        | IMAGE_FILE_DLL
        | if arch.is64() {
            IMAGE_FILE_LARGE_ADDRESS_AWARE
        } else {
            IMAGE_FILE_32BIT_MACHINE
        };
    put16(&mut img, coff + 18, characteristics);
    let opt = coff + 20;
    put16(
        &mut img,
        opt,
        if arch.is64() {
            PE32_PLUS_MAGIC
        } else {
            PE32_MAGIC
        },
    );
    img[opt + 2] = 14; // linker version 14.0
    put32(&mut img, opt + 4, text_size); // SizeOfCode
    put32(&mut img, opt + 8, rdata_size + data_size);
    put32(&mut img, opt + 20, text_rva); // BaseOfCode
    if arch.is64() {
        put64(&mut img, opt + 24, base);
    } else {
        put32(&mut img, opt + 24, rdata_rva); // BaseOfData
        put32(&mut img, opt + 28, base as u32);
    }
    put32(&mut img, opt + 32, PAGE); // SectionAlignment
    put32(&mut img, opt + 36, 0x200); // FileAlignment
    for (off, v) in [(40, 10u16), (42, 0), (44, 10), (46, 0), (48, 10), (50, 0)] {
        put16(&mut img, opt + off, v);
    }
    put32(&mut img, opt + 56, size_of_image);
    put32(&mut img, opt + 60, 0x400); // SizeOfHeaders
    put16(&mut img, opt + 68, dll.subsystem);
    // DYNAMIC_BASE | NX_COMPAT (| HIGH_ENTROPY_VA for 64-bit).
    let dllchar = 0x0040 | 0x0100 | if arch.is64() { 0x0020 } else { 0 };
    put16(&mut img, opt + 70, dllchar);
    let (sizes, step) = (opt + 72, if arch.is64() { 8 } else { 4 });
    for (i, v) in [0x4_0000u64, 0x1000, 0x10_0000, 0x1000].iter().enumerate() {
        if arch.is64() {
            put64(&mut img, sizes + i * step, *v);
        } else {
            put32(&mut img, sizes + i * step, *v as u32);
        }
    }
    let dirs = opt + if arch.is64() { 112 } else { 96 };
    put32(&mut img, dirs - 4, 16); // NumberOfRvaAndSizes
    put32(&mut img, dirs + 8 * dir::EXPORT, rdata_rva);
    put32(&mut img, dirs + 8 * dir::EXPORT + 4, rdata_len);
    let sections = opt + opt_size as usize;
    let section = |img: &mut Vec<u8>, i: usize, name: &[u8], rva: u32, size: u32, ch: u32| {
        let s = sections + 40 * i;
        img[s..s + name.len()].copy_from_slice(name);
        put32(img, s + 8, size);
        put32(img, s + 12, rva);
        put32(img, s + 16, size);
        put32(img, s + 20, rva);
        put32(img, s + 36, ch);
    };
    section(
        &mut img,
        0,
        b".text",
        text_rva,
        text_size,
        IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
    );
    section(
        &mut img,
        1,
        b".rdata",
        rdata_rva,
        rdata_size,
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
    );
    section(
        &mut img,
        2,
        b".data",
        data_rva,
        data_size,
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
    );

    BuiltinImage {
        bytes: img,
        text_rva,
        text_size,
        slots,
        capacity,
        rdata: (rdata_rva, rdata_size),
        data: (data_rva, data_size),
        symbols,
        ordinal_base: 1,
        export_dir: (rdata_rva, rdata_len),
    }
}
