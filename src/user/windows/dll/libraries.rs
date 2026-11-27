//! Checked module services and loader-lock continuations.
//!
//! Loader journals live in Modules; dropping an abandoned callback continuation
//! only queues cleanup. Cleanup runs with exclusive process access before the
//! next guest instruction, rather than mutating process state from Rust Drop.

#[cfg(test)]
mod tests;

use std::cell::RefCell;
use std::collections::{HashSet, VecDeque};
use std::rc::Rc;

use crate::error::MemoryAccessKind;
use crate::user::windows::hle::{ApiErr, ApiResult, Arg::*, Conv::Stdcall, Ctx, Export, Flow};
use crate::user::windows::loader::delay_import::{self, DelaySlots};
use crate::user::windows::loader::{self, DllSearch, LoadError, SymRef};
use crate::user::windows::memory::{Mem, MemFault};
use crate::user::windows::nt::{error::*, status::*, status_to_error};
use crate::user::windows::process::{Proc, Thread};
use crate::user::windows::registry::IFEO_KEY;
use crate::user::windows::sync::{self, Wait};

/// Disjoint from every guest u64 address and the condition-variable namespace.
const LOADER_WAIT_KEY: u128 = 1 << 65;

pub(super) static IMAGE_OPTIONS_EXPORTS: &[Export] = &[Export::func(
    "LdrQueryImageFileExecutionOptions",
    Stdcall,
    &[Ptr, Ptr, I32, Ptr, I32, Ptr],
    query_image_file_execution_options,
)];

fn query_image_file_execution_options(c: &mut Ctx) -> ApiResult {
    const REG_DWORD: u32 = 4;
    let (image, option, kind, output, capacity, result_size) = (
        c.ptr(0)?,
        c.ptr(1)?,
        c.u32(2)?,
        c.ptr(3)?,
        c.u32(4)?,
        c.ptr(5)?,
    );
    if kind != REG_DWORD {
        return Err(c.unsupported("LdrQueryImageFileExecutionOptions value type"));
    }
    if image == 0 || option == 0 {
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    }
    let bytes = c.mem().u16(image)?;
    if bytes == 0 || bytes % 2 != 0 || bytes > c.mem().u16(image + 2)? {
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    }
    let path = c
        .mem()
        .wunits(c.read_ptr(image + c.psize())?, usize::from(bytes / 2))?;
    let name = path
        .rsplit(|unit| matches!(*unit, 0x2f | 0x5c))
        .next()
        .unwrap_or_default();
    if name.is_empty() || name.contains(&0) {
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    }
    let mut key: Vec<_> = IFEO_KEY.encode_utf16().collect();
    key.push(b'\\' as u16);
    key.extend_from_slice(name);
    let Some(key) = c.p.registry.key(&key) else {
        return Flow::ret(STATUS_OBJECT_NAME_NOT_FOUND.into());
    };
    let option = c.mem().wstr(option, 16_384)?;
    let Some(value) = key.value(&option) else {
        return Flow::ret(STATUS_OBJECT_NAME_NOT_FOUND.into());
    };
    if value.kind != REG_DWORD || value.data.len() != 4 {
        return Flow::ret(STATUS_OBJECT_TYPE_MISMATCH.into());
    }
    if result_size != 0 {
        c.mem().w32(result_size, 4)?;
    }
    if capacity < 4 {
        return Flow::ret(STATUS_BUFFER_TOO_SMALL.into());
    }
    c.mem().wr(output, &value.data)?;
    Flow::ret(STATUS_SUCCESS.into())
}

pub(super) static API_SET_QUERY_EXPORTS: &[Export] = &[Export::func(
    "ApiSetQueryApiSetPresence",
    Stdcall,
    &[Ptr, Ptr],
    api_set_query_presence,
)];

pub(super) static API_SET_QUERY_FORWARDS: &[Export] = &[Export::forward(
    "ApiSetQueryApiSetPresence",
    "NTDLL.ApiSetQueryApiSetPresence",
)];

pub(super) static DLL_SHUTDOWN_EXPORTS: &[Export] = &[Export::func(
    "RtlDllShutdownInProgress",
    Stdcall,
    &[],
    |c| Flow::bool(c.p.loader.exiting_process),
)];

fn api_set_query_presence(c: &mut Ctx) -> ApiResult {
    let (descriptor, out) = (c.ptr(0)?, c.ptr(1)?);
    if descriptor == 0 || out == 0 {
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    }
    let len = c.mem().u16(descriptor)?;
    let max = c.mem().u16(descriptor + 2)?;
    if len > max || len % 2 != 0 {
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    }
    let buffer = c.read_ptr(descriptor + c.psize())?;
    let units = c.mem().wunits(buffer, usize::from(len / 2))?;
    let present = String::from_utf16(&units).is_ok_and(|name| {
        if name.is_empty() || name.contains(['\\', '/', ':', '\0']) {
            return false;
        }
        let name = loader::normalize_name(&name).to_ascii_lowercase();
        if let Some(runtime) = &c.p.native {
            runtime.apisets.host(&name, None).is_some()
        } else {
            loader::apiset::present(&name)
        }
    });
    c.mem().w8(out, u8::from(present))?;
    Flow::ret(STATUS_SUCCESS.into())
}

pub(super) static EXPORTS: &[Export] = &[
    Export::func("GetModuleHandleW", Stdcall, &[Ptr], module_handle_w),
    Export::func("GetModuleHandleA", Stdcall, &[Ptr], module_handle_a),
    Export::func(
        "GetModuleHandleExW",
        Stdcall,
        &[I32, Ptr, Ptr],
        module_handle_ex_w,
    ),
    Export::func(
        "GetModuleHandleExA",
        Stdcall,
        &[I32, Ptr, Ptr],
        module_handle_ex_a,
    ),
    Export::func("LoadLibraryW", Stdcall, &[Ptr], load_library_w),
    Export::func("LoadLibraryA", Stdcall, &[Ptr], load_library_a),
    Export::func("GetProcAddress", Stdcall, &[Ptr, Ptr], get_proc_address),
    Export::func("FreeLibrary", Stdcall, &[Ptr], free_library),
    Export::func(
        "FreeLibraryAndExitThread",
        Stdcall,
        &[Ptr, I32],
        free_and_exit,
    ),
    Export::func(
        "DisableThreadLibraryCalls",
        Stdcall,
        &[Ptr],
        disable_thread_calls,
    ),
];

pub(super) static FILE_NAME_EXPORTS: &[Export] = &[
    Export::func(
        "GetModuleFileNameW",
        Stdcall,
        &[Ptr, Ptr, I32],
        module_file_name_w,
    ),
    Export::func(
        "GetModuleFileNameA",
        Stdcall,
        &[Ptr, Ptr, I32],
        module_file_name_a,
    ),
];

pub(super) static LOAD_EX_EXPORTS: &[Export] = &[
    Export::func(
        "LoadLibraryExW",
        Stdcall,
        &[Ptr, Ptr, I32],
        load_library_ex_w,
    ),
    Export::func(
        "LoadLibraryExA",
        Stdcall,
        &[Ptr, Ptr, I32],
        load_library_ex_a,
    ),
];

pub(super) static NTDLL_EXPORTS: &[Export] = &[Export::func(
    "LdrDisableThreadCalloutsForDll",
    Stdcall,
    &[Ptr],
    ldr_disable_thread_calls,
)];

pub(super) static DELAY_EXPORTS: &[Export] = &[Export::func(
    "ResolveDelayLoadedAPI",
    Stdcall,
    &[Ptr, Ptr, Ptr, Ptr, Ptr, I32],
    resolve_delay_loaded_api,
)];

#[derive(Clone, Copy, Debug)]
enum Journal {
    Load(u64),
    Unload(u64),
}

#[derive(Debug)]
struct Abandoned {
    tid: u32,
    journal: Option<Journal>,
}

/// Serialization and normal-exit stages, separate from architectural state.
#[derive(Debug, Default)]
pub struct LoaderState {
    owner: Option<(u32, u32)>,
    /// The process-owned critical section published through the portable PEB.
    pub(crate) guest_lock: Option<u64>,
    abandoned: Rc<RefCell<Vec<Abandoned>>>,
    /// Threads already running their normal DLL_THREAD_DETACH continuations.
    pub(crate) exiting_threads: HashSet<u32>,
    /// Normal process DLL_PROCESS_DETACH has already begun.
    pub(crate) exiting_process: bool,
}

impl LoaderState {
    /// No DLL entrypoint continuation currently holds serialization.
    pub(crate) fn is_idle(&self) -> bool {
        self.owner.is_none()
    }

    /// A parked startup/dynamic loader continuation remains thread-bound even
    /// when its outer synthetic frame has an ordinary thread-start name.
    pub(crate) fn held_by(&self, tid: u32) -> bool {
        self.owner.is_some_and(|(owner, _)| owner == tid)
    }
}

/// A held reentrant loader-lock level and its optional resource journal.
pub(crate) struct LoaderGuard {
    tid: u32,
    journal: Option<Journal>,
    abandoned: Rc<RefCell<Vec<Abandoned>>>,
    armed: bool,
}

impl Drop for LoaderGuard {
    fn drop(&mut self) {
        if self.armed {
            self.abandoned.borrow_mut().push(Abandoned {
                tid: self.tid,
                journal: self.journal,
            });
        }
    }
}

impl LoaderGuard {
    /// Releases one level only after commit or completed rollback/teardown.
    pub(crate) fn finish(&mut self, c: &mut Ctx) -> Result<(), ApiErr> {
        release(c.p, self.tid)?;
        self.armed = false;
        self.journal = None;
        Ok(())
    }
}

fn release(p: &mut Proc, tid: u32) -> Result<(), ApiErr> {
    if !p.loader.held_by(tid) {
        return Err(ApiErr::Internal("loader-lock ownership mismatch".into()));
    }
    if let Some(addr) = p.loader.guest_lock
        && !sync::cs_leave(p, addr, tid)?
    {
        return Err(ApiErr::Internal(
            "guest loader-lock ownership mismatch".into(),
        ));
    }
    match p.loader.owner {
        Some((owner, depth)) if owner == tid && depth > 1 => {
            p.loader.owner = Some((owner, depth - 1));
        }
        Some((owner, 1)) if owner == tid => {
            p.loader.owner = None;
            p.sync.wake(LOADER_WAIT_KEY, usize::MAX);
        }
        _ => return Err(ApiErr::Internal("loader-lock ownership mismatch".into())),
    }
    Ok(())
}

type Locked = Box<dyn FnOnce(&mut Ctx, LoaderGuard) -> ApiResult>;

/// Serializes entrypoints, not ordinary execution of already attached threads.
pub(crate) fn with_lock(c: &mut Ctx, then: Locked) -> ApiResult {
    let tid = c.t.tid;
    if let Some(addr) = c.p.loader.guest_lock {
        if !sync::cs_try_enter(c.p, addr, tid)? {
            // The scheduler grants the critical section before resuming.
            return Flow::block(Wait::CritSec { addr }, move |c, _| in_lock(c, then));
        }
        return in_lock(c, then);
    }
    if c.p.loader.owner.is_some_and(|(owner, _)| owner != tid) {
        return Flow::block(
            Wait::Address {
                key: LOADER_WAIT_KEY,
                deadline: None,
            },
            move |c, _| with_lock(c, then),
        );
    }
    in_lock(c, then)
}

fn in_lock(c: &mut Ctx, then: Locked) -> ApiResult {
    let tid = c.t.tid;
    match c.p.loader.owner {
        None => c.p.loader.owner = Some((tid, 1)),
        Some((owner, depth)) if owner == tid => {
            let depth = depth
                .checked_add(1)
                .ok_or_else(|| ApiErr::Internal("loader-lock recursion overflow".into()))?;
            c.p.loader.owner = Some((tid, depth));
        }
        Some(_) => {
            if let Some(addr) = c.p.loader.guest_lock {
                sync::cs_leave(c.p, addr, tid)?;
            }
            return Err(ApiErr::Internal("loader-lock ownership mismatch".into()));
        }
    }
    let guard = LoaderGuard {
        tid,
        journal: None,
        abandoned: Rc::clone(&c.p.loader.abandoned),
        armed: true,
    };
    then(c, guard)
}

/// Preflight the fallible error output before any module/lock mutation.
fn error_output(c: &mut Ctx) -> Result<(), ApiErr> {
    let previous = c.last_error()?;
    c.set_last_error(previous)?;
    Ok(())
}

fn name(c: &Ctx, pointer: u64, wide: bool) -> Result<String, ApiErr> {
    Ok(if wide {
        String::from_utf16_lossy(&c.mem().wstr(pointer, 32768)?)
    } else {
        String::from_utf8_lossy(&c.mem().cstr(pointer, 32768)?).into_owned()
    })
}

fn find(c: &Ctx, pointer: u64, wide: bool) -> Result<Option<usize>, ApiErr> {
    if pointer == 0 {
        Ok(Some(0))
    } else {
        Ok(c.p
            .modules
            .by_name(&loader::normalize_name(&name(c, pointer, wide)?)))
    }
}

fn module_handle(c: &mut Ctx, wide: bool) -> ApiResult {
    let index = find(c, c.ptr(0)?, wide)?;
    match index {
        Some(index) => Flow::ret(c.p.modules.list[index].base),
        None => c.fail(ERROR_MOD_NOT_FOUND, 0),
    }
}
fn module_handle_w(c: &mut Ctx) -> ApiResult {
    module_handle(c, true)
}
fn module_handle_a(c: &mut Ctx) -> ApiResult {
    module_handle(c, false)
}

fn module_file_name_w(c: &mut Ctx) -> ApiResult {
    module_file_name(c, true)
}

fn module_file_name_a(c: &mut Ctx) -> ApiResult {
    module_file_name(c, false)
}

fn module_file_name(c: &mut Ctx, wide: bool) -> ApiResult {
    let (module, out, capacity) = (c.ptr(0)?, c.ptr(1)?, c.u32(2)? as usize);
    let index = if module == 0 {
        Some(0)
    } else {
        c.p.modules.by_base(module)
    };
    let Some(index) = index else {
        return c.fail(ERROR_MOD_NOT_FOUND, 0);
    };
    if capacity == 0 {
        return c.fail(ERROR_INSUFFICIENT_BUFFER, 0);
    }
    let path = c.p.modules.list[index].path.encode_utf16();
    let (written, truncated) = if wide {
        let mut path = path;
        let units: Vec<u16> = path.by_ref().take(capacity - 1).collect();
        c.mem().put_wstr(out, &units)?;
        (units.len(), path.next().is_some())
    } else {
        let units: Vec<u16> = path.collect();
        let bytes = super::crt::startup::encode_process_ansi(&units);
        let written = bytes.len().min(capacity - 1);
        c.mem().put_cstr(out, &bytes[..written])?;
        (written, written < bytes.len())
    };
    if truncated {
        c.fail(ERROR_INSUFFICIENT_BUFFER, capacity as u64)
    } else {
        Flow::ret(written as u64)
    }
}

fn module_handle_ex(c: &mut Ctx, wide: bool) -> ApiResult {
    let (flags, pointer, out) = (c.u32(0)?, c.ptr(1)?, c.ptr(2)?);
    error_output(c)?;
    // The public contract clears a valid output on every failure, including
    // invalid flags. Null-output/invalid-flags priority is a profile choice.
    if out != 0 {
        c.write_ptr(out, 0)?;
    }
    if flags & !7 != 0 || flags & 3 == 3 {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    }
    let bytes = c.mem().bytes(out, c.psize() as usize)?;
    c.mem().wr(out, &bytes)?;
    // Resolve while locked, including FROM_ADDRESS, so another thread cannot
    // unload between lookup and publication of the counted reference.
    let requested_name = if flags & 4 == 0 && pointer != 0 {
        Some(loader::normalize_name(&name(c, pointer, wide)?))
    } else {
        None
    };
    with_lock(
        c,
        Box::new(move |c, mut guard| {
            let bytes = c.mem().bytes(out, c.psize() as usize)?;
            c.mem().wr(out, &bytes)?;
            let index = if flags & 4 != 0 {
                c.p.modules.by_address(pointer).map(|(index, _)| index)
            } else if let Some(requested) = requested_name {
                c.p.modules.by_name(&requested)
            } else {
                Some(0)
            };
            let Some(index) = index else {
                guard.finish(c)?;
                c.write_ptr(out, 0)?;
                return c.fail(ERROR_MOD_NOT_FOUND, 0);
            };
            if flags & 2 == 0 {
                if let Err(error) = acquire_module_handle(c.p, index, flags & 1 != 0) {
                    guard.finish(c)?;
                    return c.fail(status_to_error(error.status), 0);
                }
            }
            c.write_ptr(out, c.p.modules.list[index].base)?;
            guard.finish(c)?;
            Flow::bool(true)
        }),
    )
}

fn acquire_module_handle(p: &mut Proc, index: usize, pin: bool) -> Result<(), LoadError> {
    if matches!(p.modules.list[index].kind, loader::ModuleKind::Native)
        && !p.modules.list[index].initialized
        && !loader::startup_attach_can_reference(p, index)
    {
        if pin && loader::defer_attach_pin(p, index)? {
            return Ok(());
        }
        return Err(LoadError {
            status: STATUS_NOT_SUPPORTED,
            message: "module is not initialized".into(),
        });
    }
    loader::reference_module(p, index, pin)
}
fn module_handle_ex_w(c: &mut Ctx) -> ApiResult {
    module_handle_ex(c, true)
}
fn module_handle_ex_a(c: &mut Ctx) -> ApiResult {
    module_handle_ex(c, false)
}

fn load_library(c: &mut Ctx, wide: bool, search: DllSearch) -> ApiResult {
    let requested = name(c, c.ptr(0)?, wide)?;
    error_output(c)?;
    with_lock(
        c,
        Box::new(move |c, mut guard| {
            let plan = match loader::begin_load_with_search(c.p, c.t, &requested, search) {
                Ok(plan) => plan,
                Err(error) => {
                    if c.p.cfg.trace {
                        eprintln!("[{:04x}] DLL load {}: {error}", c.t.tid, requested);
                    }
                    guard.finish(c)?;
                    return c.fail(status_to_error(error.status), 0);
                }
            };
            let base = c.p.modules.list[plan.root].base;
            guard.journal = Some(Journal::Load(plan.id));
            initialize(c, guard, Init::new(plan.initialize), base)
        }),
    )
}
fn load_library_w(c: &mut Ctx) -> ApiResult {
    load_library(c, true, DllSearch::Default)
}
fn load_library_a(c: &mut Ctx) -> ApiResult {
    load_library(c, false, DllSearch::Default)
}

fn load_library_ex(c: &mut Ctx, wide: bool) -> ApiResult {
    const APPLICATION_DIR: u32 = 0x200;
    const SYSTEM32: u32 = 0x800;
    const APPLICATION_AND_SYSTEM: u32 = APPLICATION_DIR | SYSTEM32;

    if c.ptr(1)? != 0 || c.ptr(0)? == 0 {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    }
    let search = match c.u32(2)? {
        0 => DllSearch::Default,
        APPLICATION_DIR => DllSearch::Application,
        SYSTEM32 => DllSearch::System,
        APPLICATION_AND_SYSTEM => DllSearch::ApplicationAndSystem,
        _ => return c.fail(ERROR_NOT_SUPPORTED, 0),
    };
    load_library(c, wide, search)
}

fn load_library_ex_w(c: &mut Ctx) -> ApiResult {
    load_library_ex(c, true)
}

fn load_library_ex_a(c: &mut Ctx) -> ApiResult {
    load_library_ex(c, false)
}

fn get_proc_address(c: &mut Ctx) -> ApiResult {
    let (base, pointer) = (c.ptr(0)?, c.ptr(1)?);
    let symbol = if pointer <= 0xFFFF {
        SymRef::Ordinal(pointer as u32)
    } else {
        SymRef::Name(c.mem().cstr(pointer, 32768)?, None)
    };
    error_output(c)?;
    with_lock(
        c,
        Box::new(move |c, mut guard| {
            let Some(index) = c.p.modules.by_base(base) else {
                guard.finish(c)?;
                return c.fail(ERROR_INVALID_HANDLE, 0);
            };
            let plan = match loader::begin_lookup(c.p, c.t, index, &symbol) {
                Ok(plan) => plan,
                Err(error) => {
                    guard.finish(c)?;
                    return c.fail(status_to_error(error.status), 0);
                }
            };
            guard.journal = Some(Journal::Load(plan.id));
            // A missing forwarded export may already have mapped fresh DLLs
            // and installed TLS. Roll back its journal, not an uninitialized
            // dependency that would otherwise remain admitted on failure.
            if let Some(address) = plan.address {
                initialize(c, guard, Init::new(plan.initialize), address)
            } else {
                rollback(
                    c,
                    guard,
                    LoadError {
                        status: STATUS_ENTRYPOINT_NOT_FOUND,
                        message: "export not found; lookup resources rolled back".into(),
                    },
                    None,
                )
            }
        }),
    )
}

fn resolve_delay_loaded_api(c: &mut Ctx) -> ApiResult {
    let (base, descriptor, thunk) = (c.ptr(0)?, c.ptr(1)?, c.ptr(4)?);
    if c.u32(5)? != 0 {
        return Flow::ret(0);
    }
    with_lock(
        c,
        Box::new(move |c, mut guard| {
            let import = match delay_import::read(c.p, base, descriptor, thunk) {
                Ok(import) => import,
                Err(error) => {
                    if c.p.cfg.trace {
                        eprintln!("[{:04x}] delay import 0x{descriptor:x}: {error}", c.t.tid);
                    }
                    guard.finish(c)?;
                    return Flow::ret(0);
                }
            };
            probe_delay_slots(c, import.slots)?;
            let plan = match loader::begin_delay_lookup(c.p, c.t, &import) {
                Ok(plan) => plan,
                Err(error) => {
                    if c.p.cfg.trace {
                        eprintln!(
                            "[{:04x}] delay import {}!{}: {error}",
                            c.t.tid, import.library, import.symbol
                        );
                    }
                    guard.finish(c)?;
                    return Flow::ret(0);
                }
            };
            guard.journal = Some(Journal::Load(plan.id));
            let mut init = Init::new(plan.initialize);
            init.delay = Some((import.slots, plan.base));
            initialize(c, guard, init, plan.address)
        }),
    )
}

fn probe_delay_slots(c: &Ctx, slots: DelaySlots) -> Result<(), MemFault> {
    for address in [slots.module, slots.thunk] {
        c.mem()
            .probe(address, c.psize() as usize, MemoryAccessKind::Write)
            .map_err(|fault| MemFault {
                addr: fault.address,
                write: true,
            })?;
    }
    Ok(())
}

struct Init {
    modules: std::vec::IntoIter<usize>,
    current: Option<usize>,
    callbacks: VecDeque<(u64, bool)>,
    delay: Option<(DelaySlots, u64)>,
}

impl Init {
    fn new(modules: Vec<usize>) -> Self {
        Self {
            modules: modules.into_iter(),
            current: None,
            callbacks: VecDeque::new(),
            delay: None,
        }
    }
}

pub(crate) fn tls_callbacks(c: &Ctx, index: usize) -> Result<Vec<u64>, ApiErr> {
    let Some(tls) = c.p.modules.list[index].tls else {
        return Ok(Vec::new());
    };
    if tls.callbacks == 0 {
        return Ok(Vec::new());
    }
    let mut callbacks = Vec::new();
    for offset in 0..4096 {
        let address = tls
            .callbacks
            .checked_add(offset * c.psize())
            .ok_or_else(|| ApiErr::Internal("TLS callback array address overflow".into()))?;
        let target = c.read_ptr(address)?;
        if target == 0 {
            return Ok(callbacks);
        }
        callbacks.push(target);
    }
    Err(ApiErr::Internal("unterminated TLS callback array".into()))
}

fn initialize(c: &mut Ctx, guard: LoaderGuard, mut init: Init, value: u64) -> ApiResult {
    loop {
        if let Some((target, entry)) = init.callbacks.pop_front() {
            let index = init.current.expect("callbacks have a module");
            if entry {
                loader::attach_started(c.p, index, true).map_err(internal)?;
            }
            let base = c.p.modules.list[index].base;
            return Flow::call(target, vec![base, 1, 0], move |c, result| {
                if entry && result as u32 == 0 {
                    return rollback(
                        c,
                        guard,
                        LoadError {
                            status: STATUS_DLL_INIT_FAILED,
                            message: format!(
                                "{} rejected DLL_PROCESS_ATTACH",
                                c.p.modules.list[index].name
                            ),
                        },
                        Some(index),
                    );
                }
                initialize(c, guard, init, value)
            });
        }
        if let Some(index) = init.current.take() {
            loader::attach_succeeded(c.p, index).map_err(internal)?;
        }
        let Some(index) = init.modules.next() else {
            let Some(Journal::Load(id)) = guard.journal else {
                return Err(ApiErr::Internal("missing load journal".into()));
            };
            if let Some((slots, _)) = init.delay {
                probe_delay_slots(c, slots)?;
            }
            loader::commit_load(c.p, id).map_err(internal)?;
            if let Some((slots, base)) = init.delay {
                c.write_ptr(slots.module, base)?;
                c.write_ptr(slots.thunk, value)?;
            }
            let mut guard = guard;
            guard.finish(c)?;
            return Flow::ret(value);
        };
        if !c.p.modules.is_live(index) || c.p.modules.list[index].initialized {
            continue;
        }
        init.current = Some(index);
        init.callbacks.extend(
            tls_callbacks(c, index)?
                .into_iter()
                .map(|target| (target, false)),
        );
        if c.p.modules.list[index].has_dll_main() {
            init.callbacks
                .push_back((c.p.modules.list[index].entry, true));
        }
        loader::attach_started(c.p, index, false).map_err(internal)?;
    }
}

enum Finish {
    Rollback(LoadError),
    Unload(Option<u32>),
}

fn rollback(
    c: &mut Ctx,
    guard: LoaderGuard,
    error: LoadError,
    failing_entry: Option<usize>,
) -> ApiResult {
    let Some(Journal::Load(id)) = guard.journal else {
        return Err(ApiErr::Internal("missing rollback journal".into()));
    };
    if c.p.cfg.trace {
        eprintln!("[{:04x}] DLL load rollback: {error}", c.t.tid);
    }
    let modules =
        loader::begin_rollback(c.p, id, error.clone(), failing_entry).map_err(internal)?;
    detach(
        c,
        guard,
        modules.into_iter(),
        VecDeque::new(),
        Finish::Rollback(error),
    )
}

fn detach(
    c: &mut Ctx,
    mut guard: LoaderGuard,
    mut modules: std::vec::IntoIter<usize>,
    mut callbacks: VecDeque<(u64, u64)>,
    finish: Finish,
) -> ApiResult {
    loop {
        if let Some((base, target)) = callbacks.pop_front() {
            return Flow::call(target, vec![base, 0, 0], move |c, _| {
                detach(c, guard, modules, callbacks, finish)
            });
        }
        if let Some(index) = modules.next() {
            let module = &c.p.modules.list[index];
            let (base, entry) = (module.base, module.has_dll_main().then_some(module.entry));
            if let Some(entry) = entry {
                callbacks.push_back((base, entry));
            }
            callbacks.extend(
                tls_callbacks(c, index)?
                    .into_iter()
                    .map(|target| (base, target)),
            );
            continue;
        }
        match finish {
            Finish::Rollback(error) => {
                let Some(Journal::Load(id)) = guard.journal else {
                    return Err(ApiErr::Internal("missing rollback journal".into()));
                };
                loader::finish_rollback(c.p, c.t, id).map_err(internal)?;
                guard.finish(c)?;
                return c.fail(status_to_error(error.status), 0);
            }
            Finish::Unload(exit) => {
                let Some(Journal::Unload(id)) = guard.journal else {
                    return Err(ApiErr::Internal("missing unload journal".into()));
                };
                loader::finish_unload(c.p, c.t, id).map_err(internal)?;
                guard.finish(c)?;
                return match exit {
                    Some(code) => Ok(Flow::ExitThread(code)),
                    None => Flow::bool(true),
                };
            }
        }
    }
}

fn unload(c: &mut Ctx, base: u64, exit: Option<u32>) -> ApiResult {
    error_output(c)?;
    with_lock(
        c,
        Box::new(move |c, mut guard| {
            let plan = match loader::begin_unload(c.p, base) {
                Ok(plan) => plan,
                Err(error) => {
                    guard.finish(c)?;
                    return match exit {
                        Some(code) => {
                            c.set_last_error(status_to_error(error.status))?;
                            Ok(Flow::ExitThread(code))
                        }
                        None => c.fail(status_to_error(error.status), 0),
                    };
                }
            };
            guard.journal = Some(Journal::Unload(plan.id));
            detach(
                c,
                guard,
                plan.detach.into_iter(),
                VecDeque::new(),
                Finish::Unload(exit),
            )
        }),
    )
}
fn free_library(c: &mut Ctx) -> ApiResult {
    unload(c, c.ptr(0)?, None)
}
fn free_and_exit(c: &mut Ctx) -> ApiResult {
    unload(c, c.ptr(0)?, Some(c.u32(1)?))
}

fn disable_thread_calls(c: &mut Ctx) -> ApiResult {
    error_output(c)?;
    disable_callouts(c, false)
}

fn ldr_disable_thread_calls(c: &mut Ctx) -> ApiResult {
    disable_callouts(c, true)
}

fn disable_callouts(c: &mut Ctx, native: bool) -> ApiResult {
    let base = c.ptr(0)?;
    with_lock(
        c,
        Box::new(move |c, mut guard| {
            let module = c.p.modules.by_base(base).and_then(|index| {
                let module = &mut c.p.modules.list[index];
                matches!(
                    module.kind,
                    loader::ModuleKind::Native | loader::ModuleKind::Builtin(_)
                )
                .then_some(module)
            });
            let status = match module {
                None => STATUS_DLL_NOT_FOUND,
                Some(module) if module.tls.is_some() && !native => STATUS_INVALID_PARAMETER,
                Some(module) => {
                    if module.tls.is_none() {
                        module.thread_calls = false;
                    }
                    STATUS_SUCCESS
                }
            };
            guard.finish(c)?;
            if native {
                Flow::ret(u64::from(status))
            } else if status == STATUS_SUCCESS {
                Flow::bool(true)
            } else {
                c.fail(ERROR_INVALID_PARAMETER, 0)
            }
        }),
    )
}

fn internal(error: LoadError) -> ApiErr {
    ApiErr::Internal(format!("loader transaction failed: {error}"))
}

/// Called only after forced process termination has dropped every guest frame.
/// No more guest instructions can run; do not invoke callbacks or write private
/// guest loader/TLS data merely to abandon transactions in a dying process.
/// Image/private allocations remain owned by the process arena for postmortem
/// inspection until Proc is dropped, as with the existing shutdown profile.
pub(crate) fn abort_process(p: &mut Proc) {
    loader::discard_transactions(p);
    p.loader = LoaderState::default();
}

/// Abandoned initializers do not silently leave a held lock or an admitted image.
pub(crate) fn cleanup_abandoned(p: &mut Proc, current: &mut Thread) -> Result<(), String> {
    let pending = std::mem::take(&mut *p.loader.abandoned.borrow_mut());
    let abandoned_any = !pending.is_empty();
    let mut first_error = None;
    for abandoned in pending {
        let result = if abandoned.tid == current.tid {
            cleanup_one(p, current, abandoned.journal)
        } else if let Some(mut owner) = p.threads.remove(&abandoned.tid) {
            let result = cleanup_one(p, &mut owner, abandoned.journal);
            p.threads.insert(owner.tid, owner);
            result
        } else {
            Err("abandoned loader journal has no live owner".into())
        };
        let released = release(p, abandoned.tid).map_err(|error| format!("{error:?}"));
        if first_error.is_none() {
            first_error = result.err().or_else(|| released.err());
        }
    }
    if let Some(error) = first_error {
        return Err(error);
    }
    // Escaping an entrypoint continuation is not a successful load/unload.
    // Native exception containment/status is not established by public docs.
    if abandoned_any {
        Err("guest abandoned a DLL lifecycle continuation; resource journals cleaned".into())
    } else {
        Ok(())
    }
}

fn cleanup_one(p: &mut Proc, t: &mut Thread, journal: Option<Journal>) -> Result<(), String> {
    match journal {
        Some(Journal::Load(id)) => {
            let error = LoadError {
                status: STATUS_UNSUCCESSFUL,
                message: "abandoned DLL entrypoint".into(),
            };
            loader::begin_rollback(p, id, error, None).map_err(|error| error.to_string())?;
            loader::finish_rollback(p, t, id).map_err(|error| error.to_string())
        }
        Some(Journal::Unload(id)) => {
            loader::finish_unload(p, t, id).map_err(|error| error.to_string())
        }
        None => Ok(()),
    }
}
