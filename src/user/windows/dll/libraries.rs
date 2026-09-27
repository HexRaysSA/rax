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

use crate::user::windows::hle::{ApiErr, ApiResult, Arg::*, Conv::Stdcall, Ctx, Export, Flow};
use crate::user::windows::loader::{self, LoadError, SymRef};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::{error::*, status::*, status_to_error};
use crate::user::windows::process::{Proc, Thread};
use crate::user::windows::sync::Wait;

/// Disjoint from every guest u64 address and the condition-variable namespace.
const LOADER_WAIT_KEY: u128 = 1 << 65;

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
    match c.p.loader.owner {
        None => c.p.loader.owner = Some((tid, 1)),
        Some((owner, depth)) if owner == tid => {
            let depth = depth
                .checked_add(1)
                .ok_or_else(|| ApiErr::Internal("loader-lock recursion overflow".into()))?;
            c.p.loader.owner = Some((tid, depth));
        }
        Some(_) => {
            return Flow::block(
                Wait::Address {
                    key: LOADER_WAIT_KEY,
                    deadline: None,
                },
                move |c, _| with_lock(c, then),
            );
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
                // A later failed attach must be able to remove an unready
                // image. Do not promise counted/PIN lifetime from a reentrant
                // query before that attach has committed. Native behavior for
                // this entrypoint branch is unknown; rejection is a profile.
                if matches!(c.p.modules.list[index].kind, loader::ModuleKind::Native)
                    && !c.p.modules.list[index].initialized
                {
                    guard.finish(c)?;
                    return c.fail(ERROR_NOT_SUPPORTED, 0);
                }
                if let Err(error) = loader::reference_module(c.p, index, flags & 1 != 0) {
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
fn module_handle_ex_w(c: &mut Ctx) -> ApiResult {
    module_handle_ex(c, true)
}
fn module_handle_ex_a(c: &mut Ctx) -> ApiResult {
    module_handle_ex(c, false)
}

fn load_library(c: &mut Ctx, wide: bool) -> ApiResult {
    let requested = name(c, c.ptr(0)?, wide)?;
    error_output(c)?;
    with_lock(
        c,
        Box::new(move |c, mut guard| {
            let plan = match loader::begin_load(c.p, c.t, &requested) {
                Ok(plan) => plan,
                Err(error) => {
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
    load_library(c, true)
}
fn load_library_a(c: &mut Ctx) -> ApiResult {
    load_library(c, false)
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

struct Init {
    modules: std::vec::IntoIter<usize>,
    current: Option<usize>,
    callbacks: VecDeque<(u64, bool)>,
}

impl Init {
    fn new(modules: Vec<usize>) -> Self {
        Self {
            modules: modules.into_iter(),
            current: None,
            callbacks: VecDeque::new(),
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
                            message: "DllMain rejected DLL_PROCESS_ATTACH".into(),
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
            loader::commit_load(c.p, id).map_err(internal)?;
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
    let base = c.ptr(0)?;
    error_output(c)?;
    with_lock(
        c,
        Box::new(move |c, mut guard| {
            let Some(index) = c.p.modules.by_base(base) else {
                guard.finish(c)?;
                return c.fail(ERROR_INVALID_PARAMETER, 0);
            };
            if !matches!(
                c.p.modules.list[index].kind,
                loader::ModuleKind::Native | loader::ModuleKind::Builtin(_)
            ) || c.p.modules.list[index].tls.is_some()
            {
                guard.finish(c)?;
                return c.fail(ERROR_INVALID_PARAMETER, 0);
            }
            c.p.modules.list[index].thread_calls = false;
            guard.finish(c)?;
            Flow::bool(true)
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
