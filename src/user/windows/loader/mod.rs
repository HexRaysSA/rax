//! The image loader: executable and DLL mapping, import binding, and the
//! module registry.
//!
//! Loading follows the Windows loader's observable behavior:
//!
//! - **Search order.** A name without an extension gets `.dll`. API set
//!   names resolve to their host DLL ([`apiset`]). A module already loaded
//!   under the same base name (case-insensitive) is reused. Names on the
//!   `KnownDLLs` list resolve to the built-in implementation; other names
//!   are searched in the application directory, then among the built-in
//!   DLLs (the system directory), then in the configured DLL directories
//!   and the current directory.
//! - **Mapping.** An image is mapped at its preferred base when that range
//!   is free (address-space layout randomization is not applied);
//!   otherwise it is relocated to the lowest free 64 KiB-aligned range, or
//!   fails with `STATUS_CONFLICTING_ADDRESSES` when it has no relocations.
//!   Sections take the protections of their characteristics.
//! - **Imports.** Descriptors are bound in order; each DLL is loaded (and
//!   its own imports bound) before its symbols are resolved. Names are
//!   looked up with their hint, then by binary search; forwarders are
//!   followed. A native DLL that lacks a symbol fails the load with
//!   `STATUS_ENTRYPOINT_NOT_FOUND` or `STATUS_ORDINAL_NOT_FOUND`. A
//!   built-in DLL that lacks one binds a stub that ends the process with a
//!   diagnostic when called: the gap is this implementation's, not the
//!   program's.
//! - **Initialization order.** A native DLL is initialized after the DLLs
//!   it imports (post-order of the import graph), as `DllMain` order is.
//! - **Security cookie.** A `/GS` cookie still holding its default value
//!   (0xBB40E64E, or 0x00002B992DDFA232 for PE32+) is replaced with a
//!   random value, whose upper 16 bits are clear for PE32+.

pub mod apiset;
pub mod builtin;
mod dynamic;
pub mod ldr;
pub(crate) use dynamic::{
    LoadPlan, LookupPlan, UnloadPlan, attach_started, attach_succeeded, begin_load, begin_lookup,
    begin_rollback, begin_unload, commit_load, detach_completed, detach_started,
    discard_transactions, finish_rollback, finish_unload, reference_module,
};

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use builtin::{BuiltinImage, BuiltinSym};

use super::arch::WinArch;
use super::dll::{self, BuiltinDll};
use super::memory::{AllocKind, Mem, prot};
use super::nt::status::*;
use super::process::Proc;
use super::traps::{SLOT_SIZE, SlotKind};
use crate::user::image::pe::exports::{
    ExportDirectory, ExportTarget, ForwardSymbol, parse_forwarder,
};
use crate::user::image::pe::imports::{self, ImportRef};
use crate::user::image::pe::loadcfg::LoadConfig;
use crate::user::image::pe::tls::TlsDirectory;
use crate::user::image::pe::{DataDirectory, PeImage, RvaFault, RvaSource, dir, relocs};

/// RAX admission profile: stable module IDs retain at most this many historical
/// slots, including EXE, built-ins, live native/data images and tombstones.
/// This finite host bookkeeping bound is not a native Windows loader limit.
pub(crate) const MAX_MODULE_HISTORY: usize = 4096;

fn admit_new_module(p: &Proc) -> Result<(), LoadError> {
    if p.modules.list.len() >= MAX_MODULE_HISTORY {
        return Err(LoadError::new(
            STATUS_NO_MEMORY,
            "RAX module history limit reached",
        ));
    }
    Ok(())
}

/// A load failure: the `NTSTATUS` the loader reports and a description.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadError {
    /// The status.
    pub status: u32,
    /// What failed.
    pub message: String,
}

impl LoadError {
    fn new(status: u32, message: impl Into<String>) -> Self {
        LoadError {
            status,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (status {:#010x})", self.message, self.status)
    }
}

/// What kind of module an entry is.
#[derive(Clone, Copy, Debug)]
pub enum ModuleKind {
    /// The process's executable.
    Exe,
    /// A DLL mapped from a file.
    Native,
    /// Executable loaded as an image without resolving imports or calling entry.
    Data,
    /// A built-in DLL.
    Builtin(&'static BuiltinDll),
}

/// Static TLS of a module.
#[derive(Clone, Copy, Debug)]
pub struct ModuleTls {
    /// The TLS index (position in `ThreadLocalStoragePointer`).
    pub index: u32,
    /// The template's VA.
    pub template: u64,
    /// Initialized bytes of the template.
    pub raw_size: u64,
    /// Zero-filled bytes after them.
    pub zero_fill: u64,
    /// VA of the callback array (0 when absent).
    pub callbacks: u64,
}

/// A loaded module.
#[derive(Debug)]
pub struct Module {
    /// Base name as the loader reports it (`KERNEL32.DLL`, `app.exe`).
    pub name: String,
    /// Full Windows path.
    pub path: String,
    /// Host path for a file-backed module.
    pub host_path: Option<PathBuf>,
    /// Image base.
    pub base: u64,
    /// Mapped size.
    pub size: u64,
    /// Entry point VA (0 when none).
    pub entry: u64,
    /// Kind.
    pub kind: ModuleKind,
    /// `TimeDateStamp` of the file header.
    pub timestamp: u32,
    /// The export directory.
    pub exports: DataDirectory,
    /// The exception directory (`.pdata`).
    pub pdata: DataDirectory,
    /// Whether the image has `IMAGE_DLLCHARACTERISTICS_NO_SEH`.
    pub no_seh: bool,
    /// x86 SafeSEH handler table: sorted handler RVAs, when present.
    pub safe_seh: Option<Vec<u32>>,
    /// Static TLS.
    pub tls: Option<ModuleTls>,
    /// `LDR_DATA_TABLE_ENTRY` address.
    pub ldr_entry: u64,
    /// Explicit `LoadLibrary` references; EXE/built-in roots use `u32::MAX`.
    /// Import dependency ownership is tracked separately.
    pub load_count: u32,
    /// `DisableThreadLibraryCalls` has not been called.
    pub thread_calls: bool,
    /// `DllMain(DLL_PROCESS_ATTACH)` has run (or is not needed).
    pub initialized: bool,
    /// Built-in exports by name.
    pub builtin_symbols: HashMap<&'static str, BuiltinSym>,
    /// Built-in exports in ordinal order (ordinal = base + index).
    pub builtin_ordinals: Vec<BuiltinSym>,
    /// For a built-in DLL: its code section's start (the trap range).
    pub text: u64,
    /// Stubs bound for missing imports, by name.
    pub stubs: HashMap<String, u64>,
}

impl Module {
    /// Whether `addr` lies inside the image.
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.base + self.size
    }

    /// Whether this is a DLL whose `DllMain` the loader calls.
    pub fn has_dll_main(&self) -> bool {
        matches!(self.kind, ModuleKind::Native) && self.entry != 0
    }
}

/// The module registry.
#[derive(Default)]
pub struct Modules {
    /// Modules in load order.
    pub list: Vec<Module>,
    /// Native DLLs in initialization order (indices into `list`).
    pub init_order: Vec<usize>,
    /// Next address for a built-in image.
    next_builtin: u64,
    /// `PEB_LDR_DATA`.
    pub ldr_data: u64,
    /// Next static TLS index.
    pub next_tls_index: u32,
    /// Failed native loads remain failures even though their partially
    /// mapped module is registered to break import cycles during loading.
    failures: HashMap<String, LoadError>,
    /// Index-based admission prevents aliases or explicit paths from
    /// exposing a failed module through address or symbol lookup.
    failed_indices: HashMap<usize, LoadError>,
    pub(crate) dynamic: dynamic::DynamicState,
}

impl Modules {
    /// A stable module index that has not failed or been unloaded.
    pub fn is_live(&self, idx: usize) -> bool {
        idx < self.list.len()
            && !self.failed_indices.contains_key(&idx)
            && !self.dynamic.unloaded.contains(&idx)
    }
    /// Successfully attached native modules in actual completion order.
    /// Separate from mapping post-order so nested callback loads are retained.
    pub(crate) fn ready_order(&self) -> Vec<usize> {
        self.dynamic
            .attached_order
            .iter()
            .copied()
            .filter(|&idx| self.is_live(idx) && self.list[idx].initialized)
            .collect()
    }
    /// The executable.
    pub fn exe(&self) -> &Module {
        &self.list[0]
    }

    /// The module containing `addr`.
    pub fn by_address(&self, addr: u64) -> Option<(usize, &Module)> {
        self.list
            .iter()
            .enumerate()
            .find(|(idx, m)| self.is_live(*idx) && m.contains(addr))
    }

    /// The module whose base is `base`.
    pub fn by_base(&self, base: u64) -> Option<usize> {
        self.list
            .iter()
            .enumerate()
            .find_map(|(idx, m)| (self.is_live(idx) && m.base == base).then_some(idx))
    }

    /// The module whose base name matches `name` (case-insensitive, with
    /// or without an extension as given).
    pub fn by_name(&self, name: &str) -> Option<usize> {
        let want = name.to_ascii_lowercase();
        self.list.iter().enumerate().find_map(|(idx, m)| {
            (self.is_live(idx) && m.name.to_ascii_lowercase() == want).then_some(idx)
        })
    }
}

/// Normalizes a module name as `LoadLibrary` does: the last path component,
/// with `.dll` appended when there is no extension, and a trailing dot
/// meaning "no extension".
pub fn normalize_name(name: &str) -> String {
    let base = name.rsplit(['\\', '/']).next().unwrap_or(name).trim();
    if let Some(stripped) = base.strip_suffix('.') {
        return stripped.to_string();
    }
    if base.contains('.') {
        base.to_string()
    } else {
        format!("{base}.dll")
    }
}

/// Reads an RVA of a mapped image in guest memory.
struct GuestImage<'a> {
    mem: &'a dyn Mem,
    base: u64,
    size: u64,
}

impl RvaSource for GuestImage<'_> {
    fn read_rva(&self, rva: u64, buf: &mut [u8]) -> Result<(), RvaFault> {
        let end = rva
            .checked_add(buf.len() as u64)
            .filter(|end| *end <= self.size)
            .ok_or(RvaFault { rva })?;
        let _ = end;
        let address = self.base.checked_add(rva).ok_or(RvaFault { rva })?;
        self.mem.rd(address, buf).map_err(|_| RvaFault { rva })
    }
}

/// The Windows system directory for `arch` (WoW64 processes see their
/// DLLs in `SysWOW64`).
pub fn system_dir(arch: WinArch) -> &'static str {
    match arch {
        WinArch::X86 => "C:\\Windows\\SysWOW64",
        _ => "C:\\Windows\\System32",
    }
}

/// Maps a PE image into the process: reserves the image range, writes the
/// relocated memory image, and applies section protections. Returns the
/// base.
fn map_pe(p: &mut Proc, pe: &PeImage, name: &str) -> Result<u64, LoadError> {
    let h = pe.headers();
    let size = u64::from(pe.mapped_size());
    let preferred = h.image_base;
    let label: Arc<str> = Arc::from(name);
    let base = if preferred % 0x1_0000 == 0 && p.vm.is_free(preferred, size) {
        p.vm.reserve(
            Some(preferred),
            size,
            prot::EXECUTE_WRITECOPY,
            AllocKind::Image,
            false,
            Some(label),
        )
        .map_err(|e| LoadError::new(e.status(), format!("{name}: cannot map at {preferred:#x}")))?
    } else if h.is_relocatable() {
        p.vm.reserve(
            None,
            size,
            prot::EXECUTE_WRITECOPY,
            AllocKind::Image,
            false,
            Some(label),
        )
        .map_err(|e| LoadError::new(e.status(), format!("{name}: no room for the image")))?
    } else {
        return Err(LoadError::new(
            STATUS_CONFLICTING_ADDRESSES,
            format!(
                "{name}: preferred base {preferred:#x} is unavailable and the image has no relocations"
            ),
        ));
    };
    let result = (|| {
        // Reject insufficient guest backing before allocating SizeOfImage
        // host bytes for an untrusted image.
        p.vm.commit(base, size, prot::READWRITE)
            .map_err(|e| LoadError::new(e.status(), format!("{name}: cannot commit the image")))?;
        let mut image = pe.memory_image();
        if base != preferred {
            relocs::apply(
                &mut image,
                h.directory(dir::BASERELOC),
                base.wrapping_sub(preferred),
            )
            .map_err(|e| LoadError::new(STATUS_INVALID_IMAGE_FORMAT, format!("{name}: {e}")))?;
            // Parser validation proves that the optional header lies in
            // the mapped image. ImageBase reflects the actual base.
            let off = h.nt_offset as usize + 24 + if p.arch.is64() { 24 } else { 28 };
            if p.arch.is64() {
                image[off..off + 8].copy_from_slice(&base.to_le_bytes());
            } else {
                image[off..off + 4].copy_from_slice(&(base as u32).to_le_bytes());
            }
        }
        p.vm.poke(base, &image).map_err(|_| {
            LoadError::new(STATUS_NO_MEMORY, format!("{name}: cannot write the image"))
        })?;
        Ok(base)
    })();
    if result.is_err() {
        // Release only the reservation created above. Cleanup must not
        // replace the primary commit/relocation/write error.
        let _ = p.vm.release(base);
    }
    result
}

/// The `PAGE_*` value of an image region's protection.
fn region_protect(r: &crate::user::image::pe::ImageProtection) -> u32 {
    match (r.read, r.write, r.execute) {
        (_, false, false) if r.read => prot::READONLY,
        (false, false, false) => prot::NOACCESS,
        (_, true, false) => prot::WRITECOPY,
        (false, false, true) => prot::EXECUTE,
        (true, false, true) => prot::EXECUTE_READ,
        (_, true, true) => prot::EXECUTE_WRITECOPY,
        _ => prot::READONLY,
    }
}

/// Applies the section protections of `pe` mapped at `base`.
fn protect_sections(p: &mut Proc, pe: &PeImage, base: u64) -> Result<(), LoadError> {
    for r in pe.regions() {
        p.vm.protect(
            base + u64::from(r.rva),
            u64::from(r.len),
            region_protect(&r.protection),
        )
        .map_err(|e| LoadError::new(e.status(), "cannot apply image section protection"))?;
    }
    Ok(())
}

/// A pointer-bearing image field must not access another allocation or
/// wrap its VA extent. Empty/absent optional fields are handled by callers.
fn image_extent(base: u64, size: u64, va: u64, len: u64, field: &str) -> Result<(), LoadError> {
    let valid = va
        .checked_sub(base)
        .and_then(|rva| rva.checked_add(len))
        .is_some_and(|end| end <= size);
    if valid {
        Ok(())
    } else {
        Err(LoadError::new(
            STATUS_INVALID_IMAGE_FORMAT,
            format!("{field} outside its image"),
        ))
    }
}

/// Replaces a default `/GS` cookie with a random one.
fn init_security_cookie(p: &mut Proc, pe: &PeImage, base: u64) -> Result<(), LoadError> {
    let img = GuestImage {
        mem: &p.space,
        base,
        size: u64::from(pe.mapped_size()),
    };
    let Some(cfg) = LoadConfig::read(
        &img,
        pe.headers().kind,
        pe.headers().directory(dir::LOAD_CONFIG),
    )
    .map_err(|_| LoadError::new(STATUS_INVALID_IMAGE_FORMAT, "malformed load configuration"))?
    else {
        return Ok(());
    };
    let Some(va) = cfg.security_cookie.filter(|&v| v != 0) else {
        return Ok(());
    };
    let is64 = p.arch.is64();
    image_extent(
        base,
        u64::from(pe.mapped_size()),
        va,
        if is64 { 8 } else { 4 },
        "security cookie",
    )?;
    let current = if is64 {
        p.space.u64(va)
    } else {
        p.space.u32(va).map(u64::from)
    }
    .map_err(|_| LoadError::new(STATUS_INVALID_IMAGE_FORMAT, "unreadable security cookie"))?;
    let default = if is64 {
        0x0000_2B99_2DDF_A232
    } else {
        0xBB40_E64E
    };
    if current != default {
        return Ok(());
    }
    let mut cookie = p.random();
    if is64 {
        cookie &= 0x0000_FFFF_FFFF_FFFF;
    } else {
        cookie &= 0xFFFF_FFFF;
    }
    if cookie == default || cookie == 0 {
        cookie ^= 0x1234_5678;
    }
    let bytes = cookie.to_le_bytes();
    p.vm.poke(va, &bytes[..if is64 { 8 } else { 4 }])
        .map_err(|_| LoadError::new(STATUS_INVALID_IMAGE_FORMAT, "unwritable security cookie"))
}

/// Reads the SafeSEH table of an x86 image, if it declares one.
fn safe_seh(p: &Proc, pe: &PeImage, base: u64) -> Result<Option<Vec<u32>>, LoadError> {
    if p.arch != WinArch::X86 {
        return Ok(None);
    }
    let img = GuestImage {
        mem: &p.space,
        base,
        size: u64::from(pe.mapped_size()),
    };
    let Some(cfg) = LoadConfig::read(
        &img,
        pe.headers().kind,
        pe.headers().directory(dir::LOAD_CONFIG),
    )
    .map_err(|_| LoadError::new(STATUS_INVALID_IMAGE_FORMAT, "malformed load configuration"))?
    else {
        return Ok(None);
    };
    let (Some(table), Some(count)) = (cfg.se_handler_table, cfg.se_handler_count) else {
        return Ok(None);
    };
    if table == 0 && count == 0 {
        return Ok(None);
    }
    if count > 1 << 16 {
        return Err(LoadError::new(
            STATUS_INVALID_IMAGE_FORMAT,
            "SafeSEH table exceeds loader limit",
        ));
    }
    image_extent(
        base,
        u64::from(pe.mapped_size()),
        table,
        4 * count,
        "SafeSEH table",
    )?;
    let mut v = Vec::with_capacity(count as usize);
    for i in 0..count {
        let handler = p
            .space
            .u32(table + 4 * i)
            .map_err(|_| LoadError::new(STATUS_INVALID_IMAGE_FORMAT, "unreadable SafeSEH table"))?;
        if u64::from(handler) >= u64::from(pe.mapped_size()) {
            return Err(LoadError::new(
                STATUS_INVALID_IMAGE_FORMAT,
                "SafeSEH handler outside image",
            ));
        }
        v.push(handler);
    }
    v.sort_unstable();
    Ok(Some(v))
}

/// Registers static TLS for a module.
fn setup_tls(p: &mut Proc, pe: &PeImage, base: u64) -> Result<Option<ModuleTls>, LoadError> {
    let img = GuestImage {
        mem: &p.space,
        base,
        size: u64::from(pe.mapped_size()),
    };
    let Some(dirv) = TlsDirectory::read(&img, pe.headers().kind, pe.headers().directory(dir::TLS))
        .map_err(|_| LoadError::new(STATUS_INVALID_IMAGE_FORMAT, "malformed TLS directory"))?
    else {
        return Ok(None);
    };
    // The PE text reserves the low 20 bits, but winnt.h names bit 0
    // IMAGE_SCN_SCALE_INDEX. Reject this recognized but unsupported form
    // deliberately, without claiming that it is malformed.
    let alignment = (dirv.characteristics >> 20) & 0xF;
    if alignment == 15 || dirv.characteristics & !0x00F0_0001 != 0 {
        return Err(LoadError::new(
            STATUS_INVALID_IMAGE_FORMAT,
            "reserved TLS characteristics",
        ));
    }
    if dirv.characteristics & 1 != 0 {
        return Err(LoadError::new(
            STATUS_NOT_IMPLEMENTED,
            "scaled TLS indices are not implemented",
        ));
    }
    let heap_alignment = if p.arch.is64() { 16 } else { 8 };
    if dirv
        .alignment()
        .is_some_and(|alignment| alignment > heap_alignment)
    {
        return Err(LoadError::new(
            STATUS_NOT_IMPLEMENTED,
            "over-aligned static TLS is not implemented",
        ));
    }
    let size = u64::from(pe.mapped_size());
    if dirv.raw_size() != 0 {
        image_extent(
            base,
            size,
            dirv.raw_data_start,
            dirv.raw_size(),
            "TLS template",
        )?;
    }
    image_extent(base, size, dirv.address_of_index, 4, "TLS index")?;
    if dirv.address_of_callbacks != 0 {
        image_extent(
            base,
            size,
            dirv.address_of_callbacks,
            p.arch.ptr_size(),
            "TLS callback array",
        )?;
        crate::user::image::pe::tls::callbacks(
            &img,
            pe.headers().kind,
            dirv.address_of_callbacks - base,
        )
        .map_err(|_| LoadError::new(STATUS_INVALID_IMAGE_FORMAT, "malformed TLS callback array"))?;
    }
    let recycled = p.modules.dynamic.free_tls.pop_first();
    let index = recycled.unwrap_or(p.modules.next_tls_index);
    let next = if recycled.is_some() {
        p.modules.next_tls_index
    } else {
        index
            .checked_add(1)
            .ok_or_else(|| LoadError::new(STATUS_INVALID_IMAGE_FORMAT, "TLS index overflow"))?
    };
    if p.vm
        .poke(dirv.address_of_index, &index.to_le_bytes())
        .is_err()
    {
        if recycled.is_some() {
            p.modules.dynamic.free_tls.insert(index);
        }
        return Err(LoadError::new(
            STATUS_INVALID_IMAGE_FORMAT,
            "unwritable TLS index",
        ));
    }
    p.modules.next_tls_index = next;
    Ok(Some(ModuleTls {
        index,
        template: dirv.raw_data_start,
        raw_size: dirv.raw_size(),
        zero_fill: u64::from(dirv.size_of_zero_fill),
        callbacks: dirv.address_of_callbacks,
    }))
}

/// Loads the executable `pe` from `host_path`; its imports are bound.
pub fn load_exe(
    p: &mut Proc,
    pe: &PeImage,
    host_path: &Path,
    win_path: String,
) -> Result<usize, LoadError> {
    let name = win_path
        .rsplit('\\')
        .next()
        .unwrap_or(&win_path)
        .to_string();
    let base = map_pe(p, pe, &name)?;
    let h = pe.headers();
    let module = Module {
        name,
        path: win_path,
        host_path: Some(host_path.to_path_buf()),
        base,
        size: u64::from(pe.mapped_size()),
        entry: if h.entry_rva != 0 {
            base + u64::from(h.entry_rva)
        } else {
            0
        },
        kind: ModuleKind::Exe,
        timestamp: h.time_date_stamp,
        exports: h.directory(dir::EXPORT),
        pdata: h.directory(dir::EXCEPTION),
        no_seh: h.dll_characteristics & crate::user::image::pe::IMAGE_DLLCHARACTERISTICS_NO_SEH
            != 0,
        safe_seh: None,
        tls: None,
        ldr_entry: 0,
        load_count: u32::MAX,
        thread_calls: true,
        initialized: true,
        builtin_symbols: HashMap::new(),
        builtin_ordinals: Vec::new(),
        text: 0,
        stubs: HashMap::new(),
    };
    p.modules.list.push(module);
    let idx = p.modules.list.len() - 1;
    Ok(idx)
}

/// Completes the executable's load once the process heap and loader data
/// exist: loader entry, cookie, SafeSEH, TLS, imports, protections.
pub fn finish_exe(p: &mut Proc, pe: &PeImage) -> Result<(), LoadError> {
    let base = p.modules.list[0].base;
    ldr::add_entry(p, 0)?;
    init_security_cookie(p, pe, base)?;
    p.modules.list[0].safe_seh = safe_seh(p, pe, base)?;
    p.modules.list[0].tls = setup_tls(p, pe, base)?;
    bind_imports(p, 0, pe)?;
    protect_sections(p, pe, base)?;
    Ok(())
}

/// The base address for the next built-in image of `size` bytes.
fn builtin_base(p: &mut Proc, size: u64) -> Result<u64, LoadError> {
    if p.modules.next_builtin == 0 {
        p.modules.next_builtin = super::layout::builtin_dll_base(p.arch);
    }
    let limit = super::layout::builtin_dll_limit(p.arch);
    let mut at = p.modules.next_builtin;
    while at + size <= limit {
        if p.vm.is_free(at, size) {
            p.modules.next_builtin = (at + size + 0xFFFF) & !0xFFFF;
            return Ok(at);
        }
        at += 0x1_0000;
    }
    Err(LoadError::new(
        STATUS_NO_MEMORY,
        "no room for built-in DLL images",
    ))
}

/// Maps built-in DLL `dll`.
fn load_builtin(p: &mut Proc, dll: &'static BuiltinDll) -> Result<usize, LoadError> {
    admit_new_module(p)?;
    let specials: &[SlotKind] = if dll.name == "ntdll.dll" {
        &[SlotKind::CallbackReturn, SlotKind::ThreadStart]
    } else {
        &[]
    };
    // Build once to learn the size, then at the chosen base.
    let probe = builtin::build(dll, p.arch, 0, specials);
    let size = probe.bytes.len() as u64;
    let base = builtin_base(p, size)?;
    let img: BuiltinImage = builtin::build(dll, p.arch, base, specials);
    let label: Arc<str> = Arc::from(dll.display);
    p.vm.reserve(
        Some(base),
        size,
        prot::EXECUTE_WRITECOPY,
        AllocKind::Image,
        false,
        Some(label),
    )
    .map_err(|e| LoadError::new(e.status(), format!("{}: cannot map", dll.display)))?;
    let mapped: Result<(), LoadError> = (|| {
        p.vm.commit(base, size, prot::READWRITE)
            .map_err(|e| LoadError::new(e.status(), format!("{}: cannot commit", dll.display)))?;
        p.vm.poke(base, &img.bytes).map_err(|_| {
            LoadError::new(STATUS_NO_MEMORY, format!("{}: cannot write", dll.display))
        })?;
        let text = base + u64::from(img.text_rva);
        p.vm.protect(base, 0x1000, prot::READONLY)
            .map_err(|e| LoadError::new(e.status(), "cannot protect built-in headers"))?;
        p.vm.protect(text, u64::from(img.text_size), prot::READONLY)
            .map_err(|e| LoadError::new(e.status(), "cannot protect built-in code"))?;
        p.vm.set_reported(text, u64::from(img.text_size), prot::EXECUTE_READ);
        p.vm.protect(
            base + u64::from(img.rdata.0),
            u64::from(img.rdata.1),
            prot::READONLY,
        )
        .map_err(|e| LoadError::new(e.status(), "cannot protect built-in read-only data"))?;
        p.vm.protect(
            base + u64::from(img.data.0),
            u64::from(img.data.1),
            prot::READWRITE,
        )
        .map_err(|e| LoadError::new(e.status(), "cannot protect built-in data"))?;
        Ok(())
    })();
    if let Err(error) = mapped {
        if let Err(cleanup) = p.vm.release(base) {
            p.fail(format!(
                "built-in mapping cleanup failed: {cleanup:?}; original: {error}"
            ));
        }
        return Err(error);
    }
    let text = base + u64::from(img.text_rva);
    let mut symbols = HashMap::new();
    let mut ordinals = Vec::new();
    for (name, sym) in &img.symbols {
        symbols.insert(*name, *sym);
        ordinals.push(*sym);
    }
    let module = Module {
        name: dll.display.to_string(),
        path: format!("{}\\{}", system_dir(p.arch), dll.display),
        host_path: None,
        base,
        size,
        entry: 0,
        kind: ModuleKind::Builtin(dll),
        timestamp: 0,
        exports: DataDirectory {
            rva: img.export_dir.0,
            size: img.export_dir.1,
        },
        pdata: DataDirectory::default(),
        no_seh: false,
        safe_seh: None,
        tls: None,
        ldr_entry: 0,
        load_count: u32::MAX,
        thread_calls: false,
        initialized: true,
        builtin_symbols: symbols,
        builtin_ordinals: ordinals,
        text,
        stubs: HashMap::new(),
    };
    p.modules.list.push(module);
    let idx = p.modules.list.len() - 1;
    if let Err(error) = ldr::add_entry(p, idx).and_then(|_| ldr::link_init_order(p, idx)) {
        p.modules.failed_indices.insert(idx, error.clone());
        if let Err(cleanup) = ldr::remove_entry(p, idx).and_then(|_| {
            p.vm.release(base)
                .map_err(|e| LoadError::new(e.status(), "cannot release failed built-in"))
        }) {
            p.fail(format!(
                "built-in cleanup failed: {cleanup}; original: {error}"
            ));
        }
        p.modules.dynamic.unloaded.insert(idx);
        return Err(error);
    }
    p.traps.add(text, img.slots, img.capacity);
    dll::init_data_exports(p, idx);
    Ok(idx)
}

/// Whether `name` (lower-case) is on the `KnownDLLs` list: such DLLs always
/// come from the system directory.
fn known_dll(name: &str) -> bool {
    const KNOWN: &[&str] = &[
        "advapi32.dll",
        "combase.dll",
        "comdlg32.dll",
        "gdi32.dll",
        "imagehlp.dll",
        "imm32.dll",
        "kernel32.dll",
        "kernelbase.dll",
        "msvcrt.dll",
        "normaliz.dll",
        "nsi.dll",
        "ntdll.dll",
        "ole32.dll",
        "oleaut32.dll",
        "psapi.dll",
        "rpcrt4.dll",
        "sechost.dll",
        "setupapi.dll",
        "shcore.dll",
        "shell32.dll",
        "shlwapi.dll",
        "user32.dll",
        "wldap32.dll",
        "ws2_32.dll",
        "ucrtbase.dll",
        "bcrypt.dll",
        "bcryptprimitives.dll",
    ];
    KNOWN.contains(&name)
}

/// Finds a DLL file for `name` in the search path.
fn search_native(p: &Proc, name: &str) -> Option<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Some(parent) = p.cfg.exe_host_path.parent() {
        dirs.push(parent.to_path_buf());
    }
    let app_only = dirs.len();
    dirs.extend(p.cfg.dll_paths.iter().cloned());
    if let Some(cwd) = p
        .cfg
        .drives
        .to_host(&String::from_utf16_lossy(&p.cwd), &p.cwd)
    {
        dirs.push(cwd);
    }
    let lower = name.to_ascii_lowercase();
    for (i, d) in dirs.iter().enumerate() {
        if i >= app_only && dll::find(&lower).is_some() {
            // The system directory (built-in DLLs) precedes these.
            return None;
        }
        if let Some(found) = super::fs::find_case_insensitive(d, name) {
            return Some(found);
        }
    }
    None
}

fn loaded_path(p: &Proc, path: &Path) -> Option<usize> {
    let key = p.cfg.drives.to_windows(path);
    p.modules.list.iter().enumerate().find_map(|(idx, m)| {
        (p.modules.is_live(idx) && m.path.eq_ignore_ascii_case(&key)).then_some(idx)
    })
}

/// Loads DLL `name` (as named by an import or `LoadLibrary`), returning its
/// module index. Import/forwarder callers record their dependency separately.
pub fn load_dll(p: &mut Proc, name: &str) -> Result<usize, LoadError> {
    let mut norm = normalize_name(name);
    let explicit =
        name.contains('\\') || name.contains('/') || name.as_bytes().get(1) == Some(&b':');
    if explicit {
        let prefix = name.rfind(['\\', '/']).map_or("", |at| &name[..at + 1]);
        let requested = if prefix.is_empty() && name.as_bytes().get(1) == Some(&b':') {
            format!("{}{}", &name[..2], normalize_name(&name[2..]))
        } else {
            format!("{prefix}{norm}")
        };
        let absolute =
            requested.starts_with(['\\', '/']) || requested.as_bytes().get(1) == Some(&b':');
        let file = if absolute {
            p.cfg
                .drives
                .to_host(&requested, &p.cwd)
                .filter(|path| path.is_file() || loaded_path(p, path).is_some())
        } else {
            // A relative path is appended to each directory, not reduced to
            // its basename. Configured search directories are host paths.
            let mut dirs = Vec::new();
            if let Some(parent) = p.cfg.exe_host_path.parent() {
                dirs.push(parent.to_path_buf());
            }
            dirs.extend(p.cfg.dll_paths.iter().cloned());
            if let Some(cwd) = p
                .cfg
                .drives
                .to_host(&String::from_utf16_lossy(&p.cwd), &p.cwd)
            {
                dirs.push(cwd);
            }
            dirs.into_iter().find_map(|dir| {
                let guest = format!("{}\\{}", p.cfg.drives.to_windows(&dir), requested);
                p.cfg
                    .drives
                    .to_host(&guest, &p.cwd)
                    .filter(|path| path.is_file() || loaded_path(p, path).is_some())
            })
        }
        .ok_or_else(|| LoadError::new(STATUS_DLL_NOT_FOUND, format!("{name} was not found")))?;
        let key = p.cfg.drives.to_windows(&file).to_ascii_lowercase();
        if let Some(error) = p.modules.failures.get(&key) {
            return Err(error.clone());
        }
        if let Some(idx) = loaded_path(p, &file) {
            return Ok(idx);
        }
        return load_native(p, &file, &key);
    }
    let lower = norm.to_ascii_lowercase();
    if apiset::is_api_set(&lower) {
        match apiset::host(&lower) {
            Some(host) => norm = host.to_string(),
            None => {
                return Err(LoadError::new(
                    STATUS_DLL_NOT_FOUND,
                    format!("{name} was not found"),
                ));
            }
        }
    }
    let lower = norm.to_ascii_lowercase();
    if let Some(error) = p.modules.failures.get(&lower) {
        return Err(error.clone());
    }
    if let Some(i) = p.modules.by_name(&norm) {
        return Ok(i);
    }
    let builtin = dll::find(&lower);
    if let Some(b) = builtin
        && known_dll(&lower)
    {
        return load_builtin(p, b);
    }
    let file = search_native(p, &norm);
    match (file, builtin) {
        (Some(path), _) => load_native(p, &path, &norm),
        (None, Some(b)) => load_builtin(p, b),
        (None, None) => Err(LoadError::new(
            STATUS_DLL_NOT_FOUND,
            format!("{norm} was not found"),
        )),
    }
}

/// Maps a DLL file.
fn load_native(p: &mut Proc, path: &Path, name: &str) -> Result<usize, LoadError> {
    admit_new_module(p)?;
    let bytes = std::fs::read(path)
        .map_err(|e| LoadError::new(STATUS_DLL_NOT_FOUND, format!("{}: {e}", path.display())))?;
    let pe = PeImage::parse(bytes).map_err(|e| {
        LoadError::new(
            STATUS_INVALID_IMAGE_FORMAT,
            format!("{}: {e}", path.display()),
        )
    })?;
    let h = pe.headers();
    if WinArch::from_machine(h.machine) != Some(p.arch) {
        return Err(LoadError::new(
            STATUS_INVALID_IMAGE_FORMAT,
            format!(
                "{}: machine {:#06x} does not match a {} process",
                path.display(),
                h.machine,
                p.arch
            ),
        ));
    }
    let base = map_pe(p, &pe, name)?;
    let file_name = path
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_else(|| name.to_string());
    let module = Module {
        name: file_name,
        path: p.cfg.drives.to_windows(path),
        host_path: Some(path.to_path_buf()),
        base,
        size: u64::from(pe.mapped_size()),
        entry: if h.entry_rva != 0 {
            base + u64::from(h.entry_rva)
        } else {
            0
        },
        kind: if h.is_dll() {
            ModuleKind::Native
        } else {
            ModuleKind::Data
        },
        timestamp: h.time_date_stamp,
        exports: h.directory(dir::EXPORT),
        pdata: h.directory(dir::EXCEPTION),
        no_seh: h.dll_characteristics & crate::user::image::pe::IMAGE_DLLCHARACTERISTICS_NO_SEH
            != 0,
        safe_seh: None,
        tls: None,
        ldr_entry: 0,
        load_count: 0,
        thread_calls: true,
        initialized: !h.is_dll(),
        builtin_symbols: HashMap::new(),
        builtin_ordinals: Vec::new(),
        text: 0,
        stubs: HashMap::new(),
    };
    p.modules.list.push(module);
    let idx = p.modules.list.len() - 1;
    let result: Result<usize, LoadError> = (|| {
        ldr::add_entry(p, idx)?;
        if h.is_dll() {
            init_security_cookie(p, &pe, base)?;
            p.modules.list[idx].safe_seh = safe_seh(p, &pe, base)?;
            p.modules.list[idx].tls = setup_tls(p, &pe, base)?;
            bind_imports(p, idx, &pe)?;
        }
        protect_sections(p, &pe, base)?;
        if h.is_dll() {
            p.modules.init_order.push(idx);
        }
        Ok(idx)
    })();
    if let Err(error) = &result {
        // Record only after failure: in-progress modules must remain
        // discoverable so a legal cyclic import graph can bind its exports.
        p.modules
            .failures
            .insert(name.to_ascii_lowercase(), error.clone());
        p.modules.failed_indices.insert(idx, error.clone());
    }
    result
}

/// How an import names its symbol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SymRef {
    /// By name, with an optional hint.
    Name(Vec<u8>, Option<u16>),
    /// By ordinal.
    Ordinal(u32),
}

impl std::fmt::Display for SymRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SymRef::Name(n, _) => f.write_str(&String::from_utf8_lossy(n)),
            SymRef::Ordinal(o) => write!(f, "#{o}"),
        }
    }
}

/// Resolves `sym` in module `idx`, following forwarders. `None` when the
/// module does not export it.
pub fn lookup(p: &mut Proc, idx: usize, sym: &SymRef) -> Result<Option<u64>, LoadError> {
    lookup_depth(p, idx, sym, 0)
}

fn lookup_depth(
    p: &mut Proc,
    idx: usize,
    sym: &SymRef,
    depth: u32,
) -> Result<Option<u64>, LoadError> {
    if let Some(error) = p.modules.failed_indices.get(&idx) {
        return Err(error.clone());
    }
    if !p.modules.is_live(idx) {
        return Err(LoadError::new(
            STATUS_INVALID_PARAMETER,
            "unloaded module index",
        ));
    }
    if depth > 32 {
        return Err(LoadError::new(
            STATUS_INVALID_IMAGE_FORMAT,
            "forwarder chain too long",
        ));
    }
    let m = &p.modules.list[idx];
    let base = m.base;
    let size = m.size;
    let target = if let ModuleKind::Builtin(_) = m.kind {
        let s = match sym {
            SymRef::Name(n, _) => std::str::from_utf8(n)
                .ok()
                .and_then(|n| m.builtin_symbols.get(n).copied()),
            SymRef::Ordinal(o) => o
                .checked_sub(1)
                .and_then(|i| m.builtin_ordinals.get(i as usize).copied()),
        };
        match s {
            Some(BuiltinSym::Rva(rva)) => ExportTarget::Rva(rva),
            Some(BuiltinSym::Forward(f)) => ExportTarget::Forwarder(f.as_bytes().to_vec()),
            None => return Ok(None),
        }
    } else {
        let exports = m.exports;
        let img = GuestImage {
            mem: &p.space,
            base,
            size: m.size,
        };
        let Ok(Some(d)) = ExportDirectory::read(&img, exports) else {
            return Ok(None);
        };
        let found = match sym {
            SymRef::Name(n, hint) => d.by_name(&img, n, *hint).ok().flatten().map(|(_, t)| t),
            SymRef::Ordinal(o) => d.by_ordinal(&img, *o).ok().flatten(),
        };
        match found {
            Some(t) => t,
            None => return Ok(None),
        }
    };
    match target {
        ExportTarget::Rva(rva) => {
            let address = base.checked_add(u64::from(rva)).ok_or_else(|| {
                LoadError::new(STATUS_INVALID_IMAGE_FORMAT, "export address overflow")
            })?;
            image_extent(base, size, address, 1, "export target")?;
            Ok(Some(address))
        }
        ExportTarget::Forwarder(text) => {
            let fwd = parse_forwarder(&text).ok_or_else(|| {
                LoadError::new(
                    STATUS_INVALID_IMAGE_FORMAT,
                    format!("malformed forwarder {}", String::from_utf8_lossy(&text)),
                )
            })?;
            let module = String::from_utf8_lossy(&fwd.module).into_owned();
            let target_idx = load_dll(p, &module)?;
            dynamic::dependency(p, idx, target_idx);
            let sym = match fwd.symbol {
                ForwardSymbol::Name(n) => SymRef::Name(n, None),
                ForwardSymbol::Ordinal(o) => SymRef::Ordinal(o),
            };
            lookup_depth(p, target_idx, &sym, depth + 1)
        }
    }
}

/// The address of a stub for `sym` missing from built-in module `idx`.
pub fn missing_stub(p: &mut Proc, idx: usize, sym: &SymRef) -> Result<u64, LoadError> {
    let key = sym.to_string();
    if let Some(&a) = p.modules.list[idx].stubs.get(&key) {
        return Ok(a);
    }
    let text = p.modules.list[idx].text;
    let label: Arc<str> = Arc::from(format!("{}!{}", p.modules.list[idx].name, key));
    let addr = p
        .traps
        .append(text, SlotKind::Missing(label))
        .ok_or_else(|| {
            LoadError::new(
                STATUS_NO_MEMORY,
                format!(
                    "{}: too many unimplemented imports",
                    p.modules.list[idx].name
                ),
            )
        })?;
    debug_assert_eq!(addr % SLOT_SIZE, 0);
    p.modules.list[idx].stubs.insert(key, addr);
    Ok(addr)
}

/// Binds the import address table of module `idx`.
fn bind_imports(p: &mut Proc, idx: usize, pe: &PeImage) -> Result<(), LoadError> {
    let base = p.modules.list[idx].base;
    let kind = pe.headers().kind;
    let mname = p.modules.list[idx].name.clone();
    let descs = {
        let img = GuestImage {
            mem: &p.space,
            base,
            size: u64::from(pe.mapped_size()),
        };
        imports::descriptors(&img, pe.headers().directory(dir::IMPORT)).map_err(|f| {
            LoadError::new(
                STATUS_INVALID_IMAGE_FORMAT,
                format!("{mname}: import table at RVA {:#x} unreadable", f.rva),
            )
        })?
    };
    for d in descs {
        let (dll_name, thunks) = {
            let img = GuestImage {
                mem: &p.space,
                base,
                size: u64::from(pe.mapped_size()),
            };
            let n = d.dll_name(&img).map_err(|_| {
                LoadError::new(
                    STATUS_INVALID_IMAGE_FORMAT,
                    format!("{mname}: bad import name"),
                )
            })?;
            let t = d.thunks(&img, kind).map_err(|_| {
                LoadError::new(
                    STATUS_INVALID_IMAGE_FORMAT,
                    format!("{mname}: bad import thunks"),
                )
            })?;
            (String::from_utf8_lossy(&n).into_owned(), t)
        };
        let dep = load_dll(p, &dll_name).map_err(|e| {
            if e.status == STATUS_DLL_NOT_FOUND {
                LoadError::new(
                    e.status,
                    format!("{mname} imports {dll_name}, which was not found"),
                )
            } else {
                e
            }
        })?;
        dynamic::dependency(p, idx, dep);
        for t in thunks {
            let sym = match &t.symbol {
                ImportRef::Name { hint, name } => SymRef::Name(name.clone(), Some(*hint)),
                ImportRef::Ordinal(o) => SymRef::Ordinal(u32::from(*o)),
            };
            let addr = match lookup(p, dep, &sym)? {
                Some(a) => a,
                None if matches!(p.modules.list[dep].kind, ModuleKind::Builtin(_)) => {
                    missing_stub(p, dep, &sym)?
                }
                None => {
                    let status = match sym {
                        SymRef::Name(..) => STATUS_ENTRYPOINT_NOT_FOUND,
                        SymRef::Ordinal(_) => STATUS_ORDINAL_NOT_FOUND,
                    };
                    return Err(LoadError::new(
                        status,
                        format!(
                            "the procedure entry point {sym} could not be located in {}",
                            p.modules.list[dep].name
                        ),
                    ));
                }
            };
            let slot = base.checked_add(u64::from(t.iat_slot)).ok_or_else(|| {
                LoadError::new(STATUS_INVALID_IMAGE_FORMAT, "IAT address overflow")
            })?;
            image_extent(
                base,
                p.modules.list[idx].size,
                slot,
                p.arch.ptr_size(),
                "IAT slot",
            )?;
            let bytes = addr.to_le_bytes();
            p.vm.poke(slot, &bytes[..p.arch.ptr_size() as usize])
                .map_err(|_| {
                    LoadError::new(
                        STATUS_ACCESS_VIOLATION,
                        format!("{mname}: IAT slot unwritable"),
                    )
                })?;
        }
    }
    Ok(())
}

/// Loads the DLLs every Win32 process has, in the loader-list order a
/// console process shows: `ntdll.dll`, `KERNEL32.DLL`, `KERNELBASE.dll`.
pub fn load_system_dlls(p: &mut Proc) -> Result<(), LoadError> {
    for name in ["ntdll.dll", "kernel32.dll", "kernelbase.dll"] {
        load_dll(p, name)?;
    }
    Ok(())
}
