//! Engine handle: lifecycle, configuration, and shared state.

use std::os::raw::{c_char, c_int};
use std::sync::Arc;

use rax_engine::memory::vm::GuestMemoryMmap;
use rax_engine::riscv::RiscVConfig;

use crate::arch::{self, RaxArch};
use crate::guard;
use crate::hook::HookTable;
use crate::mem::Region;
use crate::run::ExitInfo;
use crate::status::RaxStatus;
use crate::user::{RaxExceptionInfo, RegionTranslation};
use crate::vcpu::Vcpu;

/// Magic value stamped into a live [`Engine`] so the ABI can reject NULL,
/// already-closed, and obviously-bogus handles instead of dereferencing them.
const ENGINE_MAGIC: u64 = 0x5241_5845_4E47_4E31; // "RAXENGN1"

/// Default initial RAM size for the convenience opener: 256 MiB, anonymous and
/// demand-paged, so it costs almost nothing until touched.
pub const DEFAULT_MEM_SIZE: u64 = 256 * 1024 * 1024;

/// Guest page size used for mapping-alignment checks.
pub const PAGE: u64 = 4096;

// Open flags. Mirror `RAX_OPEN_*` in `rax.h`.
/// Do not install a default architectural state on open (registers start zero).
pub const RAX_OPEN_NO_DEFAULT_STATE: u32 = 1 << 0;

/// The live engine object. Opaque to C (`rax_engine *`).
pub struct Engine {
    magic: u64,
    pub(crate) arch: RaxArch,
    pub(crate) mode: u32,
    pub(crate) riscv_config: Option<RiscVConfig>,
    /// Mapped regions, kept sorted by base address and non-overlapping. The
    /// engine maintains the invariant that at least one region is always
    /// mapped (so the backing `GuestMemoryMmap` is never empty).
    pub(crate) regions: Vec<Region>,
    /// Backing store reflecting `regions`; rebuilt when the mapping set changes.
    pub(crate) mem: Arc<GuestMemoryMmap>,
    /// User mode: the address space every guest access is checked against,
    /// kept equal to `regions`. `None` in system mode.
    pub(crate) translation: Option<Arc<RegionTranslation>>,
    /// The architectural vCPU driven by the run/step API.
    pub(crate) vcpu: Vcpu,
    /// Registered execution hooks.
    pub(crate) hooks: HookTable,
    /// The most recent execution stop/exit descriptor.
    pub(crate) last_exit: ExitInfo,
    pub(crate) last_fault: crate::fault::RaxFaultInfo,
    /// The exception the last run/step reported (`rax_emu_last_exception`).
    pub(crate) last_exception: RaxExceptionInfo,
    pub(crate) last_syscall: crate::user::RaxSyscallInfo,
    pub(crate) icount_base: u64,
    /// Cooperative stop flag honoured by the run loop.
    pub(crate) stop_flag: std::cell::Cell<bool>,
    /// True while inside the run loop (re-entrancy guard for control calls).
    pub(crate) running: bool,
    /// Detailed message for the most recent failure on this engine.
    pub(crate) err_msg: String,
}

impl Engine {
    /// Records a detailed error message and returns the status unchanged.
    pub(crate) fn fail(&mut self, status: RaxStatus, msg: impl Into<String>) -> RaxStatus {
        self.err_msg = msg.into();
        status
    }

    /// Records an engine error and maps it to a status.
    pub(crate) fn fail_engine(&mut self, e: &rax_engine::Error) -> RaxStatus {
        self.err_msg = e.to_string();
        crate::status::status_from_engine_error(e)
    }

    /// Clears the stored error message (called at the start of fallible ops).
    pub(crate) fn clear_err(&mut self) {
        self.err_msg.clear();
    }

    /// Whether the engine executes in user mode (`RAX_MODE_USER`).
    pub(crate) fn is_user(&self) -> bool {
        arch::is_user(self.mode)
    }

    /// A fresh vCPU for this engine's architecture and mode over `mem`, with
    /// the power-on state installed. User mode installs its unprivileged
    /// environment instead of the system-mode default state.
    pub(crate) fn fresh_vcpu(&self, mem: Arc<GuestMemoryMmap>) -> rax_engine::Result<Vcpu> {
        let mut vcpu = arch::build_vcpu(
            self.arch,
            self.mode,
            mem,
            self.riscv_config,
            self.translation.as_ref(),
        )?;
        if !self.is_user() {
            vcpu.set_state(&arch::default_state(self.arch, self.mode))?;
        }
        Ok(vcpu)
    }
}

/// Converts a raw handle to a mutable reference, validating the magic.
pub(crate) unsafe fn engine_mut<'a>(p: *mut Engine) -> Option<&'a mut Engine> {
    if p.is_null() {
        return None;
    }
    let e = unsafe { &mut *p };
    if e.magic != ENGINE_MAGIC {
        return None;
    }
    Some(e)
}

/// Converts a raw handle to a shared reference, validating the magic.
pub(crate) unsafe fn engine_ref<'a>(p: *const Engine) -> Option<&'a Engine> {
    if p.is_null() {
        return None;
    }
    let e = unsafe { &*p };
    if e.magic != ENGINE_MAGIC {
        return None;
    }
    Some(e)
}

/// Internal constructor shared by both openers.
fn open_internal(
    arch: RaxArch,
    mode: u32,
    riscv_config: Option<RiscVConfig>,
    mem_base: u64,
    mem_size: u64,
    mem_perms: u32,
    flags: u32,
) -> Result<Box<Engine>, RaxStatus> {
    let mode = arch::normalize_mode(arch, mode).ok_or(RaxStatus::Mode)?;

    if mem_size == 0 {
        return Err(RaxStatus::Arg);
    }
    if mem_base % PAGE != 0 || mem_size % PAGE != 0 {
        return Err(RaxStatus::Arg);
    }
    if mem_base.checked_add(mem_size).is_none() {
        return Err(RaxStatus::Bounds);
    }
    let perms = mem_perms & crate::mem::RAX_PROT_ALL;

    let backing = crate::mem::alloc_backing(mem_base, mem_size).map_err(|_| RaxStatus::NoMem)?;
    let region = Region {
        base: mem_base,
        size: mem_size,
        perms,
        backing,
    };
    let mem = Arc::new(
        GuestMemoryMmap::from_arc_regions(vec![region.backing.clone()])
            .map_err(|_| RaxStatus::Map)?,
    );

    let translation = arch::is_user(mode)
        .then(|| Arc::new(RegionTranslation::new(vec![(mem_base, mem_size, perms)])));
    let mut vcpu = arch::build_vcpu(arch, mode, mem.clone(), riscv_config, translation.as_ref())
        .map_err(|_| RaxStatus::Backend)?;

    // User mode always installs its unprivileged environment; there is no
    // system-mode default state to skip.
    if flags & RAX_OPEN_NO_DEFAULT_STATE == 0 && !arch::is_user(mode) {
        let st = arch::default_state(arch, mode);
        vcpu.set_state(&st).map_err(|_| RaxStatus::Backend)?;
    }

    Ok(Box::new(Engine {
        magic: ENGINE_MAGIC,
        arch,
        mode,
        riscv_config,
        regions: vec![region],
        mem,
        translation,
        vcpu,
        hooks: HookTable::new(),
        last_exit: ExitInfo::none(),
        last_fault: crate::fault::RaxFaultInfo::default(),
        last_exception: RaxExceptionInfo::default(),
        last_syscall: crate::user::RaxSyscallInfo::default(),
        icount_base: 0,
        stop_flag: std::cell::Cell::new(false),
        running: false,
        err_msg: String::new(),
    }))
}

/// C configuration struct for [`rax_engine_open_config`]. ABI-stable; the
/// leading `size` field carries `sizeof(rax_engine_config)` for forward
/// compatibility (newer fields appended; older callers pass a smaller `size`).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RaxEngineConfig {
    pub size: u32,
    pub arch: i32,
    pub mode: u32,
    pub backend: i32,
    pub mem_base: u64,
    pub mem_size: u64,
    pub mem_perms: u32,
    pub flags: u32,
    pub riscv_ext: u64,
}

#[repr(C)]
struct RaxEngineConfigBase {
    size: u32,
    arch: i32,
    mode: u32,
    backend: i32,
    mem_base: u64,
    mem_size: u64,
    mem_perms: u32,
    flags: u32,
}

const RAX_ENGINE_CONFIG_BASE_SIZE: usize = core::mem::size_of::<RaxEngineConfigBase>();
const RAX_ENGINE_CONFIG_RISCV_EXT_OFFSET: usize = RAX_ENGINE_CONFIG_BASE_SIZE;

fn read_config_riscv_ext(cfg: *const RaxEngineConfig, size: usize) -> u64 {
    if size < RAX_ENGINE_CONFIG_RISCV_EXT_OFFSET + core::mem::size_of::<u64>() {
        return 0;
    }
    unsafe {
        (cfg as *const u8)
            .add(RAX_ENGINE_CONFIG_RISCV_EXT_OFFSET)
            .cast::<u64>()
            .read_unaligned()
    }
}

// ===========================================================================
// FFI: lifecycle
// ===========================================================================

/// Opens an engine for `arch` in `mode`, pre-mapping a default RAM region.
///
/// On success writes a non-NULL handle to `*out` and returns `RAX_OK`.
#[unsafe(no_mangle)]
pub extern "C" fn rax_engine_open(arch: c_int, mode: u32, out: *mut *mut Engine) -> RaxStatus {
    guard(|| {
        if out.is_null() {
            return RaxStatus::Arg;
        }
        unsafe {
            *out = std::ptr::null_mut();
        }
        let a = match RaxArch::from_i32(arch) {
            Some(a) => a,
            None => return RaxStatus::Arch,
        };
        match open_internal(
            a,
            mode,
            None,
            0,
            DEFAULT_MEM_SIZE,
            crate::mem::RAX_PROT_ALL,
            0,
        ) {
            Ok(e) => {
                unsafe {
                    *out = Box::into_raw(e);
                }
                RaxStatus::Ok
            }
            Err(s) => s,
        }
    })
}

/// Opens an engine from a fully specified configuration struct.
#[unsafe(no_mangle)]
pub extern "C" fn rax_engine_open_config(
    cfg: *const RaxEngineConfig,
    out: *mut *mut Engine,
) -> RaxStatus {
    guard(|| {
        if out.is_null() || cfg.is_null() {
            return RaxStatus::Arg;
        }
        unsafe {
            *out = std::ptr::null_mut();
        }
        // Read the caller-provided struct defensively: only fields covered by
        // the caller's declared `size` are trusted; the rest take defaults.
        let cfg_size = unsafe { (cfg as *const u32).read_unaligned() as usize };
        if cfg_size < RAX_ENGINE_CONFIG_BASE_SIZE {
            return RaxStatus::Arg;
        }
        let base = unsafe { &*(cfg.cast::<RaxEngineConfigBase>()) };
        let riscv_ext = read_config_riscv_ext(cfg, cfg_size);
        let a = match RaxArch::from_i32(base.arch) {
            Some(a) => a,
            None => return RaxStatus::Arch,
        };
        // Backend selection: only the software emulator is exposed via the C
        // API for portable, fully deterministic embedding; 0 == default/auto.
        if base.backend != crate::arch::RAX_BACKEND_DEFAULT
            && base.backend != crate::arch::RAX_BACKEND_EMULATOR
        {
            return RaxStatus::Backend;
        }
        let riscv_config = if riscv_ext == 0 {
            None
        } else if a == RaxArch::Riscv64 {
            match arch::riscv_config_from_ext(riscv_ext) {
                Some(cfg) => Some(cfg),
                None => return RaxStatus::Arg,
            }
        } else {
            return RaxStatus::Arg;
        };
        let mem_size = if base.mem_size == 0 {
            DEFAULT_MEM_SIZE
        } else {
            base.mem_size
        };
        match open_internal(
            a,
            base.mode,
            riscv_config,
            base.mem_base,
            mem_size,
            base.mem_perms,
            base.flags,
        ) {
            Ok(e) => {
                unsafe {
                    *out = Box::into_raw(e);
                }
                RaxStatus::Ok
            }
            Err(s) => s,
        }
    })
}

/// Closes an engine and releases all of its resources. NULL is a no-op.
/// The handle must not be used again.
#[unsafe(no_mangle)]
pub extern "C" fn rax_engine_close(engine: *mut Engine) {
    let _ = guard(|| {
        if engine.is_null() {
            return RaxStatus::Ok;
        }
        unsafe {
            // Validate before reclaiming; if the magic is wrong this is not a
            // live engine and we must not free it.
            if (*engine).magic != ENGINE_MAGIC {
                return RaxStatus::Handle;
            }
            (*engine).magic = 0;
            drop(Box::from_raw(engine));
        }
        RaxStatus::Ok
    });
}

/// Resets the engine to power-on architectural state, preserving all memory
/// mappings and their contents.
#[unsafe(no_mangle)]
pub extern "C" fn rax_engine_reset(engine: *mut Engine) -> RaxStatus {
    guard(|| {
        let e = match unsafe { engine_mut(engine) } {
            Some(e) => e,
            None => return RaxStatus::Handle,
        };
        if e.running {
            return e.fail(RaxStatus::State, "cannot reset while the engine is running");
        }
        e.clear_err();
        // A fresh vCPU guarantees pristine transient state (halt flags, caches).
        let vcpu = match e.fresh_vcpu(e.mem.clone()) {
            Ok(v) => v,
            Err(err) => return e.fail_engine(&err),
        };
        e.vcpu = vcpu;
        e.last_exit = ExitInfo::none();
        e.last_fault = crate::fault::RaxFaultInfo::default();
        e.last_exception = RaxExceptionInfo::default();
        e.last_syscall = crate::user::RaxSyscallInfo::default();
        e.icount_base = 0;
        e.stop_flag.set(false);
        RaxStatus::Ok
    })
}

// ===========================================================================
// FFI: queries
// ===========================================================================

/// Returns the engine's architecture (`rax_arch`), or a negative status code on
/// an invalid handle.
#[unsafe(no_mangle)]
pub extern "C" fn rax_engine_arch(engine: *const Engine) -> c_int {
    guard_int(|| unsafe {
        match engine_ref(engine) {
            Some(e) => e.arch as c_int,
            None => -(RaxStatus::Handle as c_int),
        }
    })
}

/// Returns the engine's normalized mode flags, or 0 on an invalid handle.
#[unsafe(no_mangle)]
pub extern "C" fn rax_engine_mode(engine: *const Engine) -> u32 {
    crate::guard_val(0, || unsafe {
        match engine_ref(engine) {
            Some(e) => e.mode,
            None => 0,
        }
    })
}

/// Whether the engine's backend supports single-instruction stepping.
#[unsafe(no_mangle)]
pub extern "C" fn rax_engine_supports_stepping(engine: *const Engine) -> c_int {
    guard_int(|| unsafe {
        match engine_ref(engine) {
            Some(e) => e.vcpu.supports_stepping() as c_int,
            None => 0,
        }
    })
}

/// Copies the most recent detailed error message for `engine` into `buf`
/// (NUL-terminated, truncated to `cap`). Returns the full message length
/// (excluding the NUL), or a negative status on an invalid handle.
#[unsafe(no_mangle)]
pub extern "C" fn rax_engine_errmsg(engine: *const Engine, buf: *mut c_char, cap: usize) -> c_int {
    guard_int(|| unsafe {
        let e = match engine_ref(engine) {
            Some(e) => e,
            None => return -(RaxStatus::Handle as c_int),
        };
        let bytes = e.err_msg.as_bytes();
        if !buf.is_null() && cap > 0 {
            let n = bytes.len().min(cap - 1);
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf as *mut u8, n);
            *buf.add(n) = 0;
        }
        bytes.len() as c_int
    })
}

#[inline]
fn guard_int<F: FnOnce() -> c_int>(f: F) -> c_int {
    crate::guard_val(-(RaxStatus::Internal as c_int), f)
}
