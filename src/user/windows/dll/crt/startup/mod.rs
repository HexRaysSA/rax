//! Guest-authoritative CRT startup cells and actual argument/environment services.
//! Private timing/identity profiles and falsification probes are recorded in
//! docs/architecture/user-mode/windows-crt-startup.md; no native-equivalence claim.

mod codepage;
mod exports;
mod parse;
mod storage;
mod wildcard;

use crate::user::windows::context::ExceptionRecord;
use crate::user::windows::dll::BuiltinDll;
use crate::user::windows::hle::{ApiErr, ApiResult, Ctx, Flow};
use crate::user::windows::loader::{LoadError, builtin::BuiltinSym};
use crate::user::windows::memory::{Mem, MemFault};
use crate::user::windows::nt::status::{STATUS_DLL_INIT_FAILED, STATUS_NO_MEMORY};
use crate::user::windows::process::Proc;

use super::{RuntimeKind, invalid, runtime, state};
pub(crate) use exports::{MSVCRT_STARTUP_EXPORTS, UCRT_STARTUP_EXPORTS};
pub(super) use storage::StartupState;

const ARGC: usize = 0;
const ARGV: usize = 1;
const WARGV: usize = 2;
const ENVIRON: usize = 3;
const WENVIRON: usize = 4;
const INITENV: usize = 5;
const WINITENV: usize = 6;
const ACMDLN: usize = 7;
const WCMDLN: usize = 8;
const PGMPTR: usize = 9;
const WPGMPTR: usize = 10;

/// Unpublished VM-owned candidate, independent of an importing DLL journal.
pub(crate) struct PreparedStartup {
    kind: RuntimeKind,
    state: StartupState,
}

impl PreparedStartup {
    pub(crate) fn commit(self, p: &mut Proc) {
        p.crt.runtimes[self.kind.index()].startup = Some(self.state);
    }

    pub(crate) fn abort(self, p: &mut Proc) -> Result<(), LoadError> {
        storage::release(p, self.state)
    }
}

pub(crate) fn prepare(
    p: &mut Proc,
    dll: &'static BuiltinDll,
    base: u64,
    symbols: &[(&'static str, BuiltinSym)],
) -> Result<PreparedStartup, LoadError> {
    let kind = match dll.name {
        "msvcrt.dll" => RuntimeKind::Msvcrt,
        "ucrtbase.dll" => RuntimeKind::Ucrt,
        _ => {
            return Err(LoadError {
                status: STATUS_DLL_INIT_FAILED,
                message: "not a CRT runtime".into(),
            });
        }
    };
    if p.crt.runtimes[kind.index()].startup.is_some() {
        return Err(LoadError {
            status: STATUS_DLL_INIT_FAILED,
            message: "CRT startup already installed".into(),
        });
    }
    storage::prepare(p, dll, base, symbols).map(|state| PreparedStartup { kind, state })
}

fn startup(p: &Proc, kind: RuntimeKind) -> Result<&StartupState, ApiErr> {
    p.crt.runtimes[kind.index()]
        .startup
        .as_ref()
        .ok_or_else(|| ApiErr::Internal("CRT startup called before data publication".into()))
}

fn cell(c: &Ctx, kind: RuntimeKind, index: usize) -> Result<u64, ApiErr> {
    Ok(startup(c.p, kind)?.cells[index])
}

fn pointer(c: &mut Ctx, index: usize) -> ApiResult {
    Flow::ret(cell(c, runtime(c)?, index)?)
}

macro_rules! accessor {
    ($($function:ident => $index:ident),* $(,)?) => {
        $(fn $function(c: &mut Ctx) -> ApiResult { pointer(c, $index) })*
    };
}
accessor! {
    argc_pointer => ARGC, argv_pointer => ARGV, wargv_pointer => WARGV,
    environ_pointer => ENVIRON, wenviron_pointer => WENVIRON,
    initenv_pointer => INITENV, winitenv_pointer => WINITENV,
    acmdln_pointer => ACMDLN, wcmdln_pointer => WCMDLN,
    pgmptr_pointer => PGMPTR, wpgmptr_pointer => WPGMPTR,
}

fn no_memory() -> ApiErr {
    ApiErr::Raise(ExceptionRecord::new(STATUS_NO_MEMORY, 0, Vec::new()))
}

fn allocation_failure(error: ApiErr) -> Result<(), ApiErr> {
    match error {
        ApiErr::Raise(record) if record.code == STATUS_NO_MEMORY => Ok(()),
        error => Err(error),
    }
}

/// Retain decoded guest-call inputs across guard/SEH repair. Atomic startup
/// work restarts its checked preflight; it does not reread clobbered ABI args.
fn checked(
    result: ApiResult,
    retry: impl FnOnce(&mut Ctx, u64) -> ApiResult + 'static,
) -> ApiResult {
    match result {
        Err(ApiErr::Fault(fault)) => Ok(Flow::RetryFault {
            fault,
            retry: Box::new(retry),
        }),
        result => result,
    }
}

#[derive(Clone, Copy)]
enum Invocation {
    Configure(bool),
    Program(bool),
    Environment(bool),
    MainArgs(bool),
    NewMode,
}

fn begin(c: &mut Ctx, invocation: Invocation) -> ApiResult {
    decode(c, runtime(c)?, invocation, [0; 5], 0)
}

/// A later stack-formal fault must not lose earlier decoded register/stack
/// values. Inaccessible unread formals are read only after actual repair.
fn decode(
    c: &mut Ctx,
    kind: RuntimeKind,
    invocation: Invocation,
    mut values: [u64; 5],
    mut cursor: usize,
) -> ApiResult {
    let count = if matches!(invocation, Invocation::MainArgs(_)) {
        5
    } else {
        1
    };
    while cursor < count {
        match c.arg(cursor) {
            Ok(value) => {
                values[cursor] = value;
                cursor += 1;
            }
            Err(fault) => {
                return Ok(Flow::RetryFault {
                    fault,
                    retry: Box::new(move |c, _| decode(c, kind, invocation, values, cursor)),
                });
            }
        }
    }
    match invocation {
        Invocation::Configure(wide) => configure_complete(c, kind, wide, values[0] as u32 as i32),
        Invocation::Program(wide) => get_program_complete(c, kind, wide, values[0]),
        Invocation::Environment(wide) => get_environment_complete(c, kind, wide, values[0]),
        Invocation::MainArgs(wide) => mainargs_complete(
            c,
            kind,
            wide,
            MainArgs {
                outputs: [values[0], values[1], values[2]],
                expanded: values[3] as u32 != 0,
                info: values[4],
                new_mode: None,
            },
        ),
        Invocation::NewMode => set_new_mode_complete(c, kind, values[0] as u32),
    }
}

fn invalid_result(c: &mut Ctx, kind: RuntimeKind, result: u32) -> ApiResult {
    invalid::invoke(
        c,
        kind,
        [0; 5],
        Box::new(move |c, _| invalid_finish(c, kind, result)),
    )
}

fn invalid_finish(c: &mut Ctx, kind: RuntimeKind, result: u32) -> ApiResult {
    match state::set_errno(c, kind, 22) {
        Ok(()) => Flow::ret(u64::from(result)),
        Err(ApiErr::Fault(fault)) => Ok(Flow::RetryFault {
            fault,
            retry: Box::new(move |c, _| invalid_finish(c, kind, result)),
        }),
        Err(error) => Err(error),
    }
}

/// Unbounded checked NUL scan: no silent truncation/cfg.args reconstruction.
/// O(N) reads/storage; all pointer arithmetic respects the guest pointer width.
fn read_string(c: &Ctx, mut address: u64, wide: bool) -> Result<Vec<u16>, ApiErr> {
    let mut units = Vec::new();
    let stride = if wide { 2 } else { 1 };
    loop {
        state::probe(c, address, stride, false)?;
        let unit = if wide {
            c.mem().u16(address)?
        } else {
            u16::from(c.mem().u8(address)?)
        };
        if unit == 0 {
            return Ok(units);
        }
        units.try_reserve(1).map_err(|_| no_memory())?;
        units.push(unit);
        address = address
            .checked_add(stride as u64)
            .filter(|&next| c.arch().ptr(next) == next)
            .ok_or(MemFault {
                addr: address,
                write: false,
            })?;
    }
}

/// Build one null-terminated P-byte-pointer vector and its terminated strings.
/// O(B+A) time/output bytes for B string bytes and A entries. Checked exact
/// layout: (A+1)*P bytes followed by each (L+1)*(wide?2:1)-byte string.
fn vector(c: &mut Ctx, kind: RuntimeKind, values: &[Vec<u16>], wide: bool) -> Result<u64, ApiErr> {
    let ptr = c.psize() as usize;
    let header = values
        .len()
        .checked_add(1)
        .and_then(|n| n.checked_mul(ptr))
        .ok_or_else(no_memory)?;
    let stride = if wide { 2 } else { 1 };
    let mut size = header;
    for value in values {
        size = value
            .len()
            .checked_add(1)
            .and_then(|n| n.checked_mul(stride))
            .and_then(|n| size.checked_add(n))
            .ok_or_else(no_memory)?;
    }
    if c.arch().ptr(size as u64) != size as u64 {
        return Err(no_memory());
    }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(size).map_err(|_| no_memory())?;
    bytes.resize(header, 0);
    for value in values {
        for &unit in value {
            if wide {
                bytes.extend_from_slice(&unit.to_le_bytes());
            } else {
                bytes.push(unit as u8);
            }
        }
        bytes.extend(std::iter::repeat_n(0, stride));
    }
    c.p.crt.runtimes[kind.index()]
        .startup
        .as_mut()
        .unwrap()
        .blocks
        .try_reserve(1)
        .map_err(|_| no_memory())?;
    let base = storage::allocate(c.p, &bytes)?;
    let result = (|| {
        let mut offset = header as u64;
        for (index, value) in values.iter().enumerate() {
            let address = base
                .checked_add(offset)
                .filter(|&last| c.arch().ptr(last) == last)
                .ok_or_else(no_memory)?;
            c.mem()
                .wptr(base + (index * ptr) as u64, ptr as u64, address)?;
            offset += ((value.len() + 1) * stride) as u64;
        }
        Ok(base)
    })();
    if result.is_err() {
        if let Err(cleanup) = c.p.vm.release(base) {
            c.p.fail(format!("CRT vector cleanup failed: {cleanup:?}"));
        }
    } else {
        c.p.crt.runtimes[kind.index()]
            .startup
            .as_mut()
            .unwrap()
            .blocks
            .push(base);
    }
    result
}

fn configure(c: &mut Ctx, kind: RuntimeKind, wide: bool, mode: i32) -> Result<(), ApiErr> {
    let index = kind.index();
    let width = usize::from(wide);
    if c.p.crt.runtimes[index].argv_modes[width] == Some(mode)
        && c.p.crt.runtimes[index].argv_active == Some(width)
    {
        return Ok(());
    }
    let argc = cell(c, kind, ARGC)?;
    let argv = cell(c, kind, if wide { WARGV } else { ARGV })?;
    state::probe(c, argc, 4, true)?;
    state::probe(c, argv, c.psize() as usize, true)?;
    let (count, pointer) = if mode == 0 {
        (0, 0)
    } else {
        let raw = c.read_ptr(cell(c, kind, if wide { WCMDLN } else { ACMDLN })?)?;
        let units = read_string(c, raw, wide)?;
        let args = parse::arguments(&units);
        let values = if mode == 2 {
            wildcard::expand(c.p, args, !wide)?
        } else {
            args.into_iter().map(|arg| arg.units).collect()
        };
        let count = u32::try_from(values.len())
            .ok()
            .filter(|&n| n <= i32::MAX as u32)
            .ok_or_else(no_memory)?;
        (count, vector(c, kind, &values, wide)?)
    };
    c.mem().w32(argc, count)?;
    c.mem().wptr(argv, c.psize(), pointer)?;
    c.p.crt.runtimes[index].argv_modes[width] = Some(mode);
    c.p.crt.runtimes[index].argv_active = Some(width);
    Ok(())
}

fn configure_api(c: &mut Ctx, wide: bool) -> ApiResult {
    begin(c, Invocation::Configure(wide))
}
fn configure_complete(c: &mut Ctx, kind: RuntimeKind, wide: bool, mode: i32) -> ApiResult {
    let result = (|| {
        if !(0..=2).contains(&mode) {
            return invalid_result(c, kind, 22);
        }
        state::ensure_writable_context(c, kind)?;
        match configure(c, kind, wide, mode) {
            Ok(()) => Flow::ret(0),
            Err(error) => {
                allocation_failure(error)?;
                state::set_errno(c, kind, 12)?;
                Flow::ret(12)
            }
        }
    })();
    checked(result, move |c, _| configure_complete(c, kind, wide, mode))
}
fn configure_narrow(c: &mut Ctx) -> ApiResult {
    configure_api(c, false)
}
fn configure_wide(c: &mut Ctx) -> ApiResult {
    configure_api(c, true)
}

fn initialize_environment(c: &mut Ctx, kind: RuntimeKind, wide: bool) -> Result<(), ApiErr> {
    let width = usize::from(wide);
    if startup(c.p, kind)?.initial_env[width] != 0 {
        return Ok(());
    }
    let current = cell(c, kind, if wide { WENVIRON } else { ENVIRON })?;
    let initial = cell(c, kind, if wide { WINITENV } else { INITENV })?;
    state::probe(c, current, c.psize() as usize, true)?;
    state::probe(c, initial, c.psize() as usize, true)?;
    let values = startup(c.p, kind)?
        .environment
        .iter()
        .map(|value| {
            if wide {
                value.clone()
            } else {
                codepage::encode(value).into_iter().map(u16::from).collect()
            }
        })
        .collect::<Vec<_>>();
    let pointer = vector(c, kind, &values, wide)?;
    c.mem().wptr(current, c.psize(), pointer)?;
    c.mem().wptr(initial, c.psize(), pointer)?;
    c.p.crt.runtimes[kind.index()]
        .startup
        .as_mut()
        .unwrap()
        .initial_env[width] = pointer;
    Ok(())
}
fn initialize_environment_api(c: &mut Ctx, wide: bool) -> ApiResult {
    let kind = runtime(c)?;
    initialize_environment_complete(c, kind, wide)
}
fn initialize_environment_complete(c: &mut Ctx, kind: RuntimeKind, wide: bool) -> ApiResult {
    let result = (|| {
        state::ensure_writable_context(c, kind)?;
        match initialize_environment(c, kind, wide) {
            Ok(()) => Flow::ret(0),
            Err(error) => {
                allocation_failure(error)?;
                state::set_errno(c, kind, 12)?;
                // Selected internal int failure profile; unlike configure's
                // errno_t, initialization reports negative failure.
                Flow::ret(u64::from(u32::MAX))
            }
        }
    })();
    checked(result, move |c, _| {
        initialize_environment_complete(c, kind, wide)
    })
}
fn initialize_narrow_environment(c: &mut Ctx) -> ApiResult {
    initialize_environment_api(c, false)
}
fn initialize_wide_environment(c: &mut Ctx) -> ApiResult {
    initialize_environment_api(c, true)
}
fn initial_environment(c: &mut Ctx, wide: bool) -> ApiResult {
    Flow::ret(startup(c.p, runtime(c)?)?.initial_env[usize::from(wide)])
}
fn initial_narrow_environment(c: &mut Ctx) -> ApiResult {
    initial_environment(c, false)
}
fn initial_wide_environment(c: &mut Ctx) -> ApiResult {
    initial_environment(c, true)
}

fn get_environment(c: &mut Ctx, wide: bool) -> ApiResult {
    begin(c, Invocation::Environment(wide))
}
fn get_environment_complete(c: &mut Ctx, kind: RuntimeKind, wide: bool, output: u64) -> ApiResult {
    let result = (|| {
        state::probe(c, output, c.psize() as usize, true)?;
        let pointer = c.read_ptr(cell(c, kind, if wide { WENVIRON } else { ENVIRON })?)?;
        c.mem().wptr(output, c.psize(), pointer)?;
        Flow::void()
    })();
    checked(result, move |c, _| {
        get_environment_complete(c, kind, wide, output)
    })
}
fn get_environ(c: &mut Ctx) -> ApiResult {
    get_environment(c, false)
}
fn get_wenviron(c: &mut Ctx) -> ApiResult {
    get_environment(c, true)
}

fn get_program(c: &mut Ctx, wide: bool) -> ApiResult {
    begin(c, Invocation::Program(wide))
}
fn get_program_complete(c: &mut Ctx, kind: RuntimeKind, wide: bool, output: u64) -> ApiResult {
    let result = (|| {
        if output == 0 {
            return invalid_result(c, kind, 22);
        }
        state::probe(c, output, c.psize() as usize, true)?;
        let pointer = c.read_ptr(cell(c, kind, if wide { WPGMPTR } else { PGMPTR })?)?;
        c.mem().wptr(output, c.psize(), pointer)?;
        Flow::ret(0)
    })();
    checked(result, move |c, _| {
        get_program_complete(c, kind, wide, output)
    })
}
fn get_pgmptr(c: &mut Ctx) -> ApiResult {
    get_program(c, false)
}
fn get_wpgmptr(c: &mut Ctx) -> ApiResult {
    get_program(c, true)
}

/// Return an interior pointer, without reading argument/tail contents. O(P)
/// checked reads for P program-name/padding units; O(1) auxiliary space.
fn winmain(c: &mut Ctx, wide: bool) -> ApiResult {
    let kind = runtime(c)?;
    let mut pointer = c.read_ptr(cell(c, kind, if wide { WCMDLN } else { ACMDLN })?)?;
    let stride = if wide { 2 } else { 1 };
    let unit = |c: &Ctx, address| -> Result<u16, ApiErr> {
        state::probe(c, address, stride, false)?;
        Ok(if wide {
            c.mem().u16(address)?
        } else {
            u16::from(c.mem().u8(address)?)
        })
    };
    let advance = |c: &Ctx, address: u64| -> Result<u64, ApiErr> {
        address
            .checked_add(stride as u64)
            .filter(|&a| c.arch().ptr(a) == a)
            .ok_or_else(|| {
                MemFault {
                    addr: address,
                    write: false,
                }
                .into()
            })
    };
    let mut quote = false;
    loop {
        let ch = unit(c, pointer)?;
        if ch == 0 || (!quote && ch <= 0x20) {
            break;
        }
        if ch == 0x22 {
            quote = !quote;
        }
        pointer = advance(c, pointer)?;
    }
    loop {
        let ch = unit(c, pointer)?;
        if ch == 0 || ch > 0x20 {
            break;
        }
        pointer = advance(c, pointer)?;
    }
    Flow::ret(pointer)
}
fn narrow_winmain(c: &mut Ctx) -> ApiResult {
    winmain(c, false)
}
fn wide_winmain(c: &mut Ctx) -> ApiResult {
    winmain(c, true)
}

fn set_new_mode(c: &mut Ctx) -> ApiResult {
    begin(c, Invocation::NewMode)
}
fn set_new_mode_complete(c: &mut Ctx, kind: RuntimeKind, mode: u32) -> ApiResult {
    let result = (|| {
        if mode > 1 {
            return invalid_result(c, kind, u32::MAX);
        }
        let old = std::mem::replace(&mut c.p.crt.runtimes[kind.index()].new_mode, mode);
        Flow::ret(u64::from(old))
    })();
    checked(result, move |c, _| set_new_mode_complete(c, kind, mode))
}
fn query_new_mode(c: &mut Ctx) -> ApiResult {
    Flow::ret(u64::from(c.p.crt.runtimes[runtime(c)?.index()].new_mode))
}

fn mainargs(c: &mut Ctx, wide: bool) -> ApiResult {
    begin(c, Invocation::MainArgs(wide))
}

#[derive(Clone, Copy)]
struct MainArgs {
    outputs: [u64; 3],
    expanded: bool,
    info: u64,
    new_mode: Option<u32>,
}

fn mainargs_complete(
    c: &mut Ctx,
    kind: RuntimeKind,
    wide: bool,
    mut request: MainArgs,
) -> ApiResult {
    let result = mainargs_action(c, kind, wide, &mut request);
    checked(result, move |c, _| {
        mainargs_complete(c, kind, wide, request)
    })
}

fn mainargs_action(
    c: &mut Ctx,
    kind: RuntimeKind,
    wide: bool,
    request: &mut MainArgs,
) -> ApiResult {
    let MainArgs {
        outputs,
        expanded,
        info,
        ..
    } = *request;
    if outputs.contains(&0) || info == 0 {
        return invalid_result(c, kind, u32::MAX);
    }
    state::probe(c, outputs[0], 4, true)?;
    state::probe(c, outputs[1], c.psize() as usize, true)?;
    state::probe(c, outputs[2], c.psize() as usize, true)?;
    let new_mode = if let Some(mode) = request.new_mode {
        mode
    } else {
        state::probe(c, info, 4, false)?;
        let mode = c.mem().u32(info)?;
        request.new_mode = Some(mode);
        mode
    };
    if new_mode > 1 {
        return invalid_result(c, kind, u32::MAX);
    }
    state::ensure_writable_context(c, kind)?;
    // Probe cells needed after configuration BEFORE committing any vector.
    let argc = cell(c, kind, ARGC)?;
    let argv = cell(c, kind, if wide { WARGV } else { ARGV })?;
    let env = cell(c, kind, if wide { WENVIRON } else { ENVIRON })?;
    state::probe(c, argc, 4, false)?;
    state::probe(c, argv, c.psize() as usize, false)?;
    state::probe(c, env, c.psize() as usize, false)?;
    let result = initialize_environment(c, kind, wide)
        .and_then(|_| configure(c, kind, wide, if expanded { 2 } else { 1 }));
    if let Err(error) = result {
        allocation_failure(error)?;
        state::set_errno(c, kind, 12)?;
        return Flow::ret(u64::from(u32::MAX));
    }
    // Capture all values before caller output aliases overwrite a CRT cell.
    let count = c.mem().u32(argc)?;
    let arguments = c.read_ptr(argv)?;
    let environment = c.read_ptr(env)?;
    c.mem().w32(outputs[0], count)?;
    c.mem().wptr(outputs[1], c.psize(), arguments)?;
    c.mem().wptr(outputs[2], c.psize(), environment)?;
    c.p.crt.runtimes[kind.index()].new_mode = new_mode;
    Flow::ret(0)
}
fn getmainargs(c: &mut Ctx) -> ApiResult {
    mainargs(c, false)
}
fn wgetmainargs(c: &mut Ctx) -> ApiResult {
    mainargs(c, true)
}

#[cfg(test)]
mod tests;
