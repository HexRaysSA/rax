//! The host C interface of the portable SMIR runtime: the functions that
//! `rax_portable_contract_v1.h` declares, for programs in C and C++ that
//! carry the runtime in them.
//!
//! A host makes a context, which says what its programs may use; has a
//! module verified; makes a process of the module; and runs it. Everything
//! it gets is a handle: three numbers that name a slot of this runtime's
//! table and say which use of the slot they are for, so that a handle
//! released, or made up, names nothing. No handle is a pointer.
//!
//! A process is used in one of two ways. As an image, `process_run` runs its
//! program from the entry to the end, once. As a library, `start` calls one
//! of the functions its module exports (`symbol`) with values made for it
//! (`value_bits`), any number of times, each call on what the earlier ones
//! left; `result_count`, `result_at` and `value_read_bits` read what a call
//! returned. Either way the work is done on another thread: `process_run`
//! and `start` return at once, and `poll` never waits.
//!
//! Values are scalars: integers and floats, by their bits. The functions for
//! aggregates and pointers (`value_aggregate`, `value_pointer`) and those
//! that answer host imports (`call_result_bits`, `call_return`,
//! `host_complete`) return `ENOSYS`.
//!
//! No function unwinds into its caller: a panic inside one is `EIO`.

use std::collections::BTreeSet;
use std::ffi::c_void;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};

use rax_smir_portable::interp::{
    Called, Clock, Code, Directory, Engine, Errno, Exit, Host, Instance, OpenFlags, Outcome,
    Policy, StandardStreams, Whence, run_program_on,
};
use rax_smir_portable::ir::{FuncIdx, Module, Type, Value};
use rax_smir_portable::{Limits, carrier};

mod link;
mod runtime;
pub use link::rax_portable_x1_module_link;
pub use runtime::{
    RAX_PORTABLE_ABI_MAJOR, RAX_PORTABLE_ABI_MINOR, RAX_PORTABLE_SERVICE_CATALOGS,
    RaxPortableRuntimeX1, rax_portable_x1_runtime,
};

/// The status of every function: zero, or a portable error number.
pub type Status = u32;

const ENOENT: Status = 2;
const EIO: Status = 5;
const ENOEXEC: Status = 8;
const EBADF: Status = 9;
const EACCES: Status = 13;
const EBUSY: Status = 16;
const ENOTDIR: Status = 20;
const EINVAL: Status = 22;
const ERANGE: Status = 34;
const ENOSYS: Status = 38;
const ENOTSUP: Status = 95;

/// A handle: this runtime, a slot of its table, and which use of the slot.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RaxPortableHandleV1 {
    pub instance: u64,
    pub slot: u64,
    pub generation: u64,
}

/// Bytes the caller lends for the call.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RaxPortableBytesV1 {
    pub data: *const u8,
    pub length: u64,
}

/// Room of the caller's for bytes to be written to.
#[repr(C)]
#[derive(Debug)]
pub struct RaxPortableBufferV1 {
    pub data: *mut u8,
    pub capacity: u64,
    pub written: u64,
}

/// What became of a request.
#[repr(C)]
#[derive(Debug)]
pub struct RaxPortablePollV1 {
    pub size: u32,
    pub version: u32,
    /// `pending`, `exited` or `failed`: bytes of this runtime's, not the
    /// caller's to free.
    pub state: RaxPortableBytesV1,
    /// The record of how it ended, to be read and released; zeros while it
    /// is pending.
    pub result: RaxPortableHandleV1,
    pub error: Status,
    pub reserved0: u32,
}

/// A host function a module may import. None is accepted yet.
#[repr(C)]
pub struct RaxPortableHostImportV1 {
    pub size: u32,
    pub version: u32,
    pub name: RaxPortableBytesV1,
    pub admitted_descriptor: RaxPortableBytesV1,
    pub call: *const c_void,
    pub release: *const c_void,
    pub user: *mut c_void,
}

/// What the programs of a context may use.
#[repr(C)]
pub struct RaxPortableConfigV1 {
    pub size: u32,
    pub version: u32,
    /// How many threads a program is told run at one time; 0 for what the
    /// machine runs.
    pub workers: u64,
    /// Most bytes of memory objects a process holds; 0 for 16 MiB.
    pub memory_bytes: u64,
    /// Not used: an activation's storage is not carved out of a stack.
    pub stack_bytes: u64,
    /// Not used.
    pub atomic_bytes: u64,
    /// Not used.
    pub code_bytes: u64,
    /// Empty or `interpreter`, or `native` for code compiled for this host.
    pub profile: RaxPortableBytesV1,
    /// Empty or `portable`.
    pub personality: RaxPortableBytesV1,
    /// The capabilities granted: names in ascending order, none twice.
    pub capabilities: *const RaxPortableBytesV1,
    pub capability_count: u64,
    pub imports: *const RaxPortableHostImportV1,
    pub import_count: u64,
}

const _: () = {
    assert!(size_of::<RaxPortableHandleV1>() == 24);
    assert!(size_of::<RaxPortableBytesV1>() == 16);
    assert!(size_of::<RaxPortableBufferV1>() == 24);
    assert!(size_of::<RaxPortablePollV1>() == 56);
    assert!(size_of::<RaxPortableHostImportV1>() == 64);
    assert!(size_of::<RaxPortableConfigV1>() == 112);
};

/// The capabilities a context can grant.
const CAPABILITIES: [&str; 6] = ["clock", "file", "memory", "process", "sync", "thread"];
/// Memory of a process when the context names none.
const DEFAULT_MEMORY_BYTES: u64 = 16 * 1024 * 1024;

/// What verifying a module may cost: enough for a program linked with a C
/// and a C++ library.
const LIMITS: Limits = Limits {
    max_object_bytes: 256 * 1024 * 1024,
    max_payload_bytes: 128 * 1024 * 1024,
    max_record_nodes: 50_000_000,
    max_record_depth: 64,
    max_list_items: 4_000_000,
    max_string_bytes: 16 * 1024 * 1024,
    max_semantic_work: 20_000_000_000,
    max_graph_edges: 50_000_000,
    max_derived_bytes: 8 * 1024 * 1024 * 1024,
};

struct Context {
    policy: Policy,
    grants: BTreeSet<&'static str>,
    native: bool,
    /// The directory whose files the context's processes have.
    files: Mutex<Option<PathBuf>>,
}

struct Loaded {
    module: Arc<Module>,
    /// Code for this host, where the context asked for it.
    code: Option<Arc<Code>>,
}

/// How a process stands.
enum Stage {
    Created,
    /// Running as an image.
    Running,
    /// Called as a library: the process that lasts between the calls.
    Library(Arc<Instance>),
    /// Ended, with the state token and the record of it.
    Ended(&'static [u8], Arc<Vec<u8>>),
}

struct Process {
    context: Arc<Context>,
    loaded: Arc<Loaded>,
    arguments: Vec<Vec<u8>>,
    files: Option<PathBuf>,
    stage: Mutex<Stage>,
    changed: Condvar,
}

/// A call of a library process, and how it came out once it has: what the
/// function returned or how the program ended, or the status of a call
/// that could not be made.
struct Pending {
    process: Arc<Process>,
    entry: FuncIdx,
    done: Mutex<Option<Result<Called, Status>>>,
    changed: Condvar,
}

/// A scalar and how many bits it has.
#[derive(Clone, Copy)]
struct Scalar {
    value: Value,
    bits: u32,
}

enum Object {
    Context(Arc<Context>),
    Module(Arc<Context>, Arc<Loaded>),
    Process(Arc<Process>),
    /// The run of an image.
    Request(Arc<Process>),
    /// A call of a library.
    Call(Arc<Pending>),
    Record(Arc<Vec<u8>>),
    /// A function of a module, not yet of any process.
    Code(Arc<Loaded>, FuncIdx),
    Value(Scalar),
    /// What a call returned.
    Results(Arc<Vec<Scalar>>),
}

#[derive(Default)]
struct Slot {
    generation: u64,
    references: u64,
    object: Option<Object>,
}

#[derive(Default)]
struct Registry {
    slots: Vec<Slot>,
    free: Vec<usize>,
}

static REGISTRY: Mutex<Registry> = Mutex::new(Registry {
    slots: Vec::new(),
    free: Vec::new(),
});

/// What tells this runtime's handles from another's: where its table is.
fn instance() -> u64 {
    std::ptr::from_ref(&REGISTRY) as u64
}

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Registry {
    fn insert(&mut self, object: Object) -> RaxPortableHandleV1 {
        let slot = self.free.pop().unwrap_or_else(|| {
            self.slots.push(Slot::default());
            self.slots.len() - 1
        });
        let entry = &mut self.slots[slot];
        entry.references = 1;
        entry.object = Some(object);
        RaxPortableHandleV1 {
            instance: instance(),
            slot: slot as u64,
            generation: entry.generation,
        }
    }

    fn slot(&mut self, handle: RaxPortableHandleV1) -> Result<&mut Slot, Status> {
        if handle.instance != instance() {
            return Err(EBADF);
        }
        usize::try_from(handle.slot)
            .ok()
            .and_then(|slot| self.slots.get_mut(slot))
            .filter(|slot| slot.object.is_some() && slot.generation == handle.generation)
            .ok_or(EBADF)
    }

    fn object(&mut self, handle: RaxPortableHandleV1) -> Result<&Object, Status> {
        self.slot(handle)
            .map(|slot| slot.object.as_ref().expect("checked"))
    }
}

fn insert(object: Object) -> RaxPortableHandleV1 {
    locked(&REGISTRY).insert(object)
}

fn context_of(handle: RaxPortableHandleV1) -> Result<Arc<Context>, Status> {
    match locked(&REGISTRY).object(handle)? {
        Object::Context(context) => Ok(Arc::clone(context)),
        _ => Err(EBADF),
    }
}

fn process_of(handle: RaxPortableHandleV1) -> Result<Arc<Process>, Status> {
    match locked(&REGISTRY).object(handle)? {
        Object::Process(process) => Ok(Arc::clone(process)),
        _ => Err(EBADF),
    }
}

fn loaded_of(handle: RaxPortableHandleV1) -> Result<Arc<Loaded>, Status> {
    match locked(&REGISTRY).object(handle)? {
        Object::Module(_, loaded) => Ok(Arc::clone(loaded)),
        _ => Err(EBADF),
    }
}

/// The bytes a caller lent. A null pointer is good for no bytes only.
///
/// # Safety
///
/// `bytes.data` points to `bytes.length` readable bytes, unless the length
/// is zero.
unsafe fn borrowed<'call>(bytes: RaxPortableBytesV1) -> Result<&'call [u8], Status> {
    if bytes.length == 0 {
        return Ok(&[]);
    }
    let length = usize::try_from(bytes.length).map_err(|_| EINVAL)?;
    if bytes.data.is_null() {
        return Err(EINVAL);
    }
    // SAFETY: the caller's promise.
    Ok(unsafe { std::slice::from_raw_parts(bytes.data, length) })
}

/// Run an exported function's body: its status, or `EIO` if it panicked.
fn guarded(body: impl FnOnce() -> Result<(), Status>) -> Status {
    match catch_unwind(AssertUnwindSafe(body)) {
        Ok(Ok(())) => 0,
        Ok(Err(status)) => status,
        Err(_) => EIO,
    }
}

/// Make a context from `config`, which is copied.
///
/// `EINVAL` for a size or version that is not this structure's, a profile
/// or personality that is not known, or capabilities that are not known
/// names in ascending order; `ENOTSUP` for host imports.
///
/// # Safety
///
/// `config` points to a `RaxPortableConfigV1` whose counted fields are what
/// they say, and `context` to room for a handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rax_portable_v1_context_create(
    config: *const RaxPortableConfigV1,
    context: *mut RaxPortableHandleV1,
) -> Status {
    guarded(|| {
        if config.is_null() || context.is_null() {
            return Err(EINVAL);
        }
        // The size and version come first, and are read before anything
        // that a structure of another size would not have.
        // SAFETY: the caller's promise covers at least these two fields.
        let (size, version) = unsafe { ((*config).size, (*config).version) };
        if size as usize != size_of::<RaxPortableConfigV1>() || version != 1 {
            return Err(EINVAL);
        }
        // SAFETY: the structure is this one.
        let config = unsafe { &*config };
        // SAFETY: counted bytes of the caller's.
        let (profile, personality) =
            unsafe { (borrowed(config.profile)?, borrowed(config.personality)?) };
        let native = match profile {
            b"" | b"interpreter" => false,
            b"native" => true,
            _ => return Err(EINVAL),
        };
        if !matches!(personality, b"" | b"portable") {
            return Err(EINVAL);
        }
        if config.import_count != 0 {
            return Err(ENOTSUP);
        }
        let mut grants = BTreeSet::new();
        let mut last: Option<&[u8]> = None;
        for index in 0..usize::try_from(config.capability_count).map_err(|_| EINVAL)? {
            if config.capabilities.is_null() {
                return Err(EINVAL);
            }
            // SAFETY: `capabilities` has `capability_count` elements.
            let name = unsafe { borrowed(*config.capabilities.add(index))? };
            let known = CAPABILITIES
                .iter()
                .find(|known| known.as_bytes() == name)
                .ok_or(EINVAL)?;
            if last.is_some_and(|last| last >= name) {
                return Err(EINVAL);
            }
            last = Some(name);
            grants.insert(*known);
        }
        let policy = Policy {
            fuel: u64::MAX,
            max_memory_bytes: match config.memory_bytes {
                0 => DEFAULT_MEMORY_BYTES,
                bytes => bytes,
            },
            processors: u32::try_from(config.workers).map_err(|_| EINVAL)?,
            ..Policy::default()
        };
        let handle = insert(Object::Context(Arc::new(Context {
            policy,
            grants,
            native,
            files: Mutex::new(None),
        })));
        // SAFETY: room for a handle, by the caller's promise.
        unsafe { context.write(handle) };
        Ok(())
    })
}

/// Give the processes a context makes from now on the files under a
/// directory of this machine. See `rax_portable_extensions_v1.h`.
///
/// # Safety
///
/// `path` is counted bytes of the caller's.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rax_portable_x1_context_files(
    context: RaxPortableHandleV1,
    path: RaxPortableBytesV1,
) -> Status {
    guarded(|| {
        let context = context_of(context)?;
        // SAFETY: the caller's promise.
        let path = std::str::from_utf8(unsafe { borrowed(path)? }).map_err(|_| EINVAL)?;
        let directory = std::fs::canonicalize(path).map_err(|_| ENOENT)?;
        if !directory.is_dir() {
            return Err(ENOTDIR);
        }
        *locked(&context.files) = Some(directory);
        Ok(())
    })
}

/// Verify a module, of which the runtime keeps its own copy. The bytes are
/// an object, or a native file that carries one. Nothing of it runs.
///
/// `ENOEXEC` if it is not a module this runtime can run.
///
/// # Safety
///
/// `bytes` is counted bytes of the caller's and `module` room for a handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rax_portable_v1_module_verify(
    context: RaxPortableHandleV1,
    bytes: RaxPortableBytesV1,
    module: *mut RaxPortableHandleV1,
) -> Status {
    guarded(|| {
        let context = context_of(context)?;
        if module.is_null() {
            return Err(EINVAL);
        }
        // SAFETY: the caller's promise.
        let bytes = unsafe { borrowed(bytes)? };
        let payload = carrier::payload(bytes).map_err(|_| ENOEXEC)?;
        let loaded = Module::load(payload, LIMITS).map_err(|_| ENOEXEC)?;
        let handle = admitted(context, loaded)?;
        // SAFETY: room for a handle, by the caller's promise.
        unsafe { module.write(handle) };
        Ok(())
    })
}

/// A module of a context, with code for this host where the context asked
/// for it. `ENOTSUP` if there is no such code to be had. A module that
/// calls functions of others is no program yet and gets no code: what is
/// linked of it does (`rax_portable_x1_module_link`).
fn admitted(context: Arc<Context>, module: Module) -> Result<RaxPortableHandleV1, Status> {
    let code = if context.native && !module.needs_linking() {
        Some(Arc::new(Code::compile(&module).map_err(|_| ENOTSUP)?))
    } else {
        None
    };
    Ok(insert(Object::Module(
        context,
        Arc::new(Loaded {
            module: Arc::new(module),
            code,
        }),
    )))
}

/// The fields of a `runtime_spawn_spec` record this runtime acts on: the
/// program's arguments. `None` if the bytes are no such record, name another
/// module, or ask for what there is not: an environment, a working
/// directory, handles to inherit beyond the standard streams. The record
/// names its module by the module's identity, or by 32 zero bytes, which
/// stand for the module the process is made of.
fn spawn_arguments(spec: &[u8], identity: [u8; 32]) -> Option<Vec<Vec<u8>>> {
    struct Cursor<'spec>(&'spec [u8]);
    impl<'spec> Cursor<'spec> {
        fn take(&mut self, count: usize) -> Option<&'spec [u8]> {
            let (taken, rest) = self.0.split_at_checked(count)?;
            self.0 = rest;
            Some(taken)
        }
        fn number(&mut self) -> Option<u32> {
            Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
        }
        fn text(&mut self) -> Option<&'spec [u8]> {
            let length = self.number()?;
            let text = self.take(length as usize)?;
            std::str::from_utf8(text).ok()?;
            Some(text)
        }
    }
    let mut cursor = Cursor(spec);
    if cursor.number()? != 1 {
        return None;
    }
    let artifact = cursor.take(32)?;
    if artifact != identity && artifact != [0; 32] {
        return None;
    }
    let mut arguments = Vec::new();
    for _ in 0..cursor.number()? {
        let argument = cursor.text()?;
        if argument.contains(&0) {
            return None;
        }
        arguments.push(argument.to_vec());
    }
    let environment = cursor.number()?;
    let directory = cursor.text()?;
    let inherited = cursor.number()?;
    let mut last = None;
    for _ in 0..inherited {
        let handle = u64::from_le_bytes(cursor.take(8)?.try_into().ok()?);
        if handle > 2 || last.is_some_and(|last| last >= handle) {
            return None;
        }
        last = Some(handle);
    }
    (environment == 0 && directory.is_empty() && cursor.0.is_empty()).then_some(arguments)
}

/// Make a process of a module. It does not run yet.
///
/// `spawn_spec` is a canonical `runtime_spawn_spec` record, whose arguments
/// are the program's, the first by convention its name; or no bytes, for a
/// program with one argument, `program`. `EINVAL` for a record that is none,
/// that is for another module, or that asks for an environment, a working
/// directory or other handles than the standard streams. `ENOEXEC` for a
/// module that calls functions of others and is not linked with them.
///
/// # Safety
///
/// `spawn_spec` is counted bytes of the caller's and `process` room for a
/// handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rax_portable_v1_process_create(
    context: RaxPortableHandleV1,
    module: RaxPortableHandleV1,
    spawn_spec: RaxPortableBytesV1,
    process: *mut RaxPortableHandleV1,
) -> Status {
    guarded(|| {
        let context = context_of(context)?;
        let loaded = match locked(&REGISTRY).object(module)? {
            // A module is of the context that verified it.
            Object::Module(owner, loaded) if Arc::ptr_eq(owner, &context) => Arc::clone(loaded),
            _ => return Err(EBADF),
        };
        if process.is_null() {
            return Err(EINVAL);
        }
        // A module that calls functions of others is a program only once
        // it is linked with them.
        if loaded.module.needs_linking() {
            return Err(ENOEXEC);
        }
        // SAFETY: the caller's promise.
        let spec = unsafe { borrowed(spawn_spec)? };
        let arguments = if spec.is_empty() {
            vec![b"program".to_vec()]
        } else {
            spawn_arguments(spec, loaded.module.identity()).ok_or(EINVAL)?
        };
        let files = locked(&context.files).clone();
        let handle = insert(Object::Process(Arc::new(Process {
            context,
            loaded,
            arguments,
            files,
            stage: Mutex::new(Stage::Created),
            changed: Condvar::new(),
        })));
        // SAFETY: room for a handle, by the caller's promise.
        unsafe { process.write(handle) };
        Ok(())
    })
}

/// A host that grants what the context grants, and no more than the host
/// inside it has.
struct Granted<H> {
    inner: H,
    grants: BTreeSet<&'static str>,
}

impl<H: Host> Host for Granted<H> {
    fn grants(&self, capability: &str) -> bool {
        self.grants.contains(capability) && self.inner.grants(capability)
    }
    fn read(&mut self, handle: u64, buffer: &mut [u8]) -> Result<usize, Errno> {
        self.inner.read(handle, buffer)
    }
    fn write(&mut self, handle: u64, bytes: &[u8]) -> Result<usize, Errno> {
        self.inner.write(handle, bytes)
    }
    fn now(&mut self, clock: Clock) -> Result<u64, Errno> {
        self.inner.now(clock)
    }
    fn open(&mut self, path: &str, flags: OpenFlags, mode: u32) -> Result<u64, Errno> {
        self.inner.open(path, flags, mode)
    }
    fn close(&mut self, handle: u64) -> Result<(), Errno> {
        self.inner.close(handle)
    }
    fn seek(&mut self, handle: u64, offset: i64, whence: Whence) -> Result<u64, Errno> {
        self.inner.seek(handle, offset, whence)
    }
    fn unlink(&mut self, path: &str) -> Result<(), Errno> {
        self.inner.unlink(path)
    }
    fn rename(&mut self, from: &str, to: &str) -> Result<(), Errno> {
        self.inner.rename(from, to)
    }
}

/// The record of how a process ended, as the canonical JSON `record_read`
/// gives out, with the state token that goes with it.
fn record(outcome: Result<Outcome, rax_smir_portable::Error>) -> (&'static [u8], Vec<u8>) {
    let plain = |reason: &str, code: i64| {
        format!(r#"{{"version":1,"reason":"{reason}","code":{code},"thread":1,"trap":null}}"#)
    };
    let stopped = |reason: &str, code: i64, trap: String| {
        format!(r#"{{"version":1,"reason":"{reason}","code":{code},"thread":1,"trap":{trap}}}"#)
    };
    let (state, text): (&'static [u8], String) = match outcome {
        Ok(Outcome { exit, .. }) => match exit {
            // What `main` returned is the status the program exits with;
            // one it left unspecified is zero.
            Exit::Return(values) => match values.as_slice() {
                [Value::Int(status)] => (b"exited", plain("normal", i64::from(*status as i32))),
                [Value::Undef] | [] => (b"exited", plain("normal", 0)),
                _ => (
                    b"failed",
                    stopped("trap", 0, r#"{"code":"poison_status"}"#.into()),
                ),
            },
            Exit::Exited(status) => (b"exited", plain("normal", i64::from(status))),
            Exit::Aborted => (b"exited", plain("abort", 134)),
            Exit::Trap(fault) | Exit::LanguageUb(fault) => (
                b"failed",
                stopped(
                    "trap",
                    0,
                    format!(
                        r#"{{"code":"{}","function":{},"block":{},"operation":{}}}"#,
                        fault.code, fault.function, fault.block, fault.operation
                    ),
                ),
            ),
            Exit::Resource(code) => (
                b"failed",
                stopped("trap", 0, format!(r#"{{"code":"{code}"}}"#)),
            ),
            Exit::Deadlock => (
                b"failed",
                stopped("trap", 0, r#"{"code":"deadlock"}"#.into()),
            ),
        },
        // Refused before it ran: a capability the context does not grant,
        // or no entry.
        Err(error) => (
            b"failed",
            stopped(
                "failed",
                i64::from(if error.code() == "EXEC_CAPABILITY" {
                    EACCES
                } else {
                    ENOEXEC
                }),
                format!(r#"{{"code":"{}"}}"#, error.code()),
            ),
        ),
    };
    (state, text.into_bytes())
}

/// The host a process runs against: the standard streams of the host
/// program, the files of the context's directory if it has one, and of all
/// that what the context grants.
fn host_of(process: &Process) -> std::io::Result<Box<dyn Host>> {
    let streams = StandardStreams {
        input: std::io::stdin(),
        output: std::io::stdout(),
        error: std::io::stderr(),
    };
    let grants = process.context.grants.clone();
    Ok(match &process.files {
        None => Box::new(Granted {
            inner: streams,
            grants,
        }),
        Some(files) => Box::new(Granted {
            inner: Directory::new(streams, files)?,
            grants,
        }),
    })
}

/// What the program wrote and the host program has not seen yet.
fn flush() {
    use std::io::Write;
    let _ = std::io::stdout().flush();
}

/// The record of a runtime that failed, not the program.
fn defect() -> (&'static [u8], Vec<u8>) {
    (
        b"failed",
        br#"{"version":1,"reason":"failed","code":5,"thread":1,"trap":{"code":"runtime_panic"}}"#
            .to_vec(),
    )
}

/// What an image's thread does: run the program and note how it ended.
fn run(process: &Process) {
    let engine = match &process.loaded.code {
        Some(code) => Engine::Native(code),
        None => Engine::Interpreter,
    };
    let outcome = catch_unwind(AssertUnwindSafe(|| match host_of(process) {
        Ok(mut host) => run_program_on(
            engine,
            &process.loaded.module,
            &process.arguments,
            process.context.policy,
            &mut *host,
        ),
        // The directory was there when the context was given it.
        Err(_) => Ok(Outcome {
            exit: Exit::Resource("files"),
            steps: 0,
        }),
    }));
    flush();
    let (state, text) = match outcome {
        Ok(outcome) => record(outcome),
        Err(_) => defect(),
    };
    *locked(&process.stage) = Stage::Ended(state, Arc::new(text));
    process.changed.notify_all();
}

/// Start a process as an image: its program runs from its entry, on a
/// thread of its own, once. `request` is for `poll` and `cancel`. `EBUSY`
/// if the process was started before, as an image or as a library.
///
/// # Safety
///
/// `request` is room for a handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rax_portable_v1_process_run(
    process: RaxPortableHandleV1,
    request: *mut RaxPortableHandleV1,
) -> Status {
    guarded(|| {
        let process = process_of(process)?;
        if request.is_null() {
            return Err(EINVAL);
        }
        {
            let mut stage = locked(&process.stage);
            if !matches!(*stage, Stage::Created) {
                return Err(EBUSY);
            }
            *stage = Stage::Running;
        }
        let running = Arc::clone(&process);
        let started = std::thread::Builder::new()
            .name("portable process".into())
            .spawn(move || run(&running));
        if started.is_err() {
            *locked(&process.stage) = Stage::Created;
            return Err(EBUSY);
        }
        let handle = insert(Object::Request(process));
        // SAFETY: room for a handle, by the caller's promise.
        unsafe { request.write(handle) };
        Ok(())
    })
}

/// The function of a module that a symbol exports, by the symbol's name.
/// The namespace is not compared: a module's exported names are distinct
/// whatever their namespaces. What comes back is of the module, not of a
/// process: any process of the module can be asked to run it. `ENOENT` if
/// the module exports no such function.
///
/// # Safety
///
/// The names are counted bytes of the caller's and `code` room for a
/// handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rax_portable_v1_symbol(
    module: RaxPortableHandleV1,
    name_space: RaxPortableBytesV1,
    name: RaxPortableBytesV1,
    code: *mut RaxPortableHandleV1,
) -> Status {
    guarded(|| {
        let loaded = loaded_of(module)?;
        if code.is_null() {
            return Err(EINVAL);
        }
        // SAFETY: the caller's promise.
        let (_, name) = unsafe { (borrowed(name_space)?, borrowed(name)?) };
        let name = std::str::from_utf8(name).map_err(|_| EINVAL)?;
        let entry = loaded.module.export(name).ok_or(ENOENT)?;
        let handle = insert(Object::Code(loaded, entry));
        // SAFETY: room for a handle, by the caller's promise.
        unsafe { code.write(handle) };
        Ok(())
    })
}

/// How many bits a value of a type has, if it is a scalar a host can make:
/// an integer or a float.
fn scalar_bits(ty: &Type) -> Option<u32> {
    match ty {
        Type::Int { bits } if *bits <= 128 => Some(*bits),
        Type::Float { format } => Some(format.bits()),
        _ => None,
    }
}

/// A value of one of a module's types from its bits: `execution_type` is
/// the type's identifier in the module, and `bits` the value in as many
/// bytes as the type has, least significant first. `EINVAL` for a type the
/// module has not, one that is no integer or float, bytes of another
/// length, or bits beyond the type's width.
///
/// # Safety
///
/// `bits` is counted bytes of the caller's and `value` room for a handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rax_portable_v1_value_bits(
    module: RaxPortableHandleV1,
    execution_type: u32,
    reserved0: u32,
    bits: RaxPortableBytesV1,
    value: *mut RaxPortableHandleV1,
) -> Status {
    guarded(|| {
        let loaded = loaded_of(module)?;
        if value.is_null() || reserved0 != 0 {
            return Err(EINVAL);
        }
        let module = &loaded.module;
        let width = module
            .type_by_id(execution_type)
            .and_then(|ty| scalar_bits(module.ty(ty)))
            .ok_or(EINVAL)?;
        // SAFETY: the caller's promise.
        let given = unsafe { borrowed(bits)? };
        if given.len() != width.div_ceil(8) as usize {
            return Err(EINVAL);
        }
        let mut wide = [0_u8; 16];
        wide[..given.len()].copy_from_slice(given);
        let number = u128::from_le_bytes(wide);
        if width < 128 && number >> width != 0 {
            return Err(EINVAL);
        }
        let handle = insert(Object::Value(Scalar {
            value: Value::Int(number),
            bits: width,
        }));
        // SAFETY: room for a handle, by the caller's promise.
        unsafe { value.write(handle) };
        Ok(())
    })
}

/// The lasting process of a library, which its first call starts: the
/// module's initializers run then.
fn instance_of(process: &Process) -> Result<Arc<Instance>, Status> {
    let mut stage = locked(&process.stage);
    match &*stage {
        Stage::Library(instance) => Ok(Arc::clone(instance)),
        Stage::Created => {
            let host = host_of(process).map_err(|_| EIO)?;
            let instance = Instance::start(
                Arc::clone(&process.loaded.module),
                process.loaded.code.clone(),
                process.context.policy,
                host,
            )
            .map_err(|error| match error.code() {
                "EXEC_CAPABILITY" => EACCES,
                _ => ENOEXEC,
            })?;
            let instance = Arc::new(instance);
            *stage = Stage::Library(Arc::clone(&instance));
            Ok(instance)
        }
        // An image runs its own entry and nothing else, and a process that
        // has ended runs nothing.
        Stage::Running | Stage::Ended(..) => Err(EBUSY),
    }
}

/// Call a function of a process's module with values for its parameters.
/// The process is then a library: it lasts from its first call, which runs
/// its module's initializers, to `process_join`, and each call finds what
/// the earlier ones left. The calls of one process run one after another.
///
/// `EBADF` if `code` is of another module; `EINVAL` if the values are not
/// in number and width what the function takes; `ENOTSUP` if it takes or
/// returns anything but integers and floats; `EBUSY` if the process runs
/// as an image or has ended; `EACCES` if the module needs a capability the
/// context does not grant.
///
/// # Safety
///
/// `arguments` points to `count` handles and `request` to room for one.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rax_portable_v1_start(
    process: RaxPortableHandleV1,
    code: RaxPortableHandleV1,
    arguments: *const RaxPortableHandleV1,
    count: u64,
    request: *mut RaxPortableHandleV1,
) -> Status {
    guarded(|| {
        let process = process_of(process)?;
        let entry = match locked(&REGISTRY).object(code)? {
            Object::Code(loaded, entry) if Arc::ptr_eq(loaded, &process.loaded) => *entry,
            _ => return Err(EBADF),
        };
        if request.is_null() || (count != 0 && arguments.is_null()) {
            return Err(EINVAL);
        }
        let module = &process.loaded.module;
        let signature = module.signature(entry);
        let widths = |types: &[_]| -> Result<Vec<u32>, Status> {
            types
                .iter()
                .map(|ty| scalar_bits(module.ty(*ty)).ok_or(ENOTSUP))
                .collect()
        };
        let takes = widths(signature.params())?;
        widths(signature.results())?;
        if usize::try_from(count).ok() != Some(takes.len()) {
            return Err(EINVAL);
        }
        let mut values = Vec::with_capacity(takes.len());
        for (index, width) in takes.iter().enumerate() {
            // SAFETY: `arguments` has `count` handles.
            let handle = unsafe { *arguments.add(index) };
            match locked(&REGISTRY).object(handle)? {
                Object::Value(scalar) if scalar.bits == *width => values.push(scalar.value),
                Object::Value(_) => return Err(EINVAL),
                _ => return Err(EBADF),
            }
        }
        let instance = instance_of(&process)?;
        let pending = Arc::new(Pending {
            process,
            entry,
            done: Mutex::new(None),
            changed: Condvar::new(),
        });
        let calling = Arc::clone(&pending);
        std::thread::Builder::new()
            .name("portable call".into())
            .spawn(move || {
                let outcome =
                    catch_unwind(AssertUnwindSafe(|| instance.call(calling.entry, &values)));
                // The call's hold on the process ends before its outcome
                // shows, so that whoever sees the outcome can join.
                drop(instance);
                flush();
                *locked(&calling.done) = Some(match outcome {
                    Ok(Ok(called)) => Ok(called),
                    Ok(Err(_)) | Err(_) => Err(EIO),
                });
                calling.changed.notify_all();
            })
            .map_err(|_| EBUSY)?;
        let handle = insert(Object::Call(pending));
        // SAFETY: room for a handle, by the caller's promise.
        unsafe { request.write(handle) };
        Ok(())
    })
}

/// Check that `result` is a poll structure of this version.
///
/// # Safety
///
/// `result` points to a `RaxPortablePollV1` of the caller's, or is null.
unsafe fn poll_structure(result: *mut RaxPortablePollV1) -> Result<(), Status> {
    if result.is_null() {
        return Err(EINVAL);
    }
    // SAFETY: the caller's promise covers at least these two fields.
    let (size, version) = unsafe { ((*result).size, (*result).version) };
    if size as usize != size_of::<RaxPortablePollV1>() || version != 1 {
        return Err(EINVAL);
    }
    Ok(())
}

/// Write an observation into a poll structure.
///
/// # Safety
///
/// `result` passed [`poll_structure`].
unsafe fn observed(
    result: *mut RaxPortablePollV1,
    state: &'static [u8],
    handle: RaxPortableHandleV1,
    error: Status,
) {
    // SAFETY: the structure is this one.
    unsafe {
        (*result).state = RaxPortableBytesV1 {
            data: state.as_ptr(),
            length: state.len() as u64,
        };
        (*result).result = handle;
        (*result).error = error;
        (*result).reserved0 = 0;
    }
}

/// Write how a process stands into `result`.
///
/// # Safety
///
/// `result` passed [`poll_structure`].
unsafe fn observe(stage: &Stage, result: *mut RaxPortablePollV1) {
    let (state, handle): (&'static [u8], RaxPortableHandleV1) = match stage {
        Stage::Created | Stage::Running | Stage::Library(_) => {
            (b"pending", RaxPortableHandleV1::default())
        }
        // Each observation of the end owns a handle to its record.
        Stage::Ended(state, record) => (*state, insert(Object::Record(Arc::clone(record)))),
    };
    // SAFETY: the caller's promise.
    unsafe { observed(result, state, handle, 0) };
}

/// How a request stands, without waiting.
///
/// The run of an image is `pending`, or `exited` or `failed` with a record
/// of how. A call of a library is `pending`; `returned`, with what the
/// function returned, for `result_count` and `result_at`; or `exited` or
/// `failed` with a record, if the call ended the program. What `result`
/// names is the caller's to release.
///
/// # Safety
///
/// `result` points to a `RaxPortablePollV1` of the caller's, with its size
/// and version set.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rax_portable_v1_poll(
    request: RaxPortableHandleV1,
    result: *mut RaxPortablePollV1,
) -> Status {
    enum Asked {
        Image(Arc<Process>),
        Call(Arc<Pending>),
    }
    guarded(|| {
        // SAFETY: the caller's promise.
        unsafe { poll_structure(result)? };
        let asked = match locked(&REGISTRY).object(request)? {
            Object::Request(process) => Asked::Image(Arc::clone(process)),
            Object::Call(pending) => Asked::Call(Arc::clone(pending)),
            _ => return Err(EBADF),
        };
        match asked {
            // SAFETY: the structure was checked.
            Asked::Image(process) => unsafe { observe(&locked(&process.stage), result) },
            Asked::Call(pending) => {
                let done = locked(&pending.done).clone();
                let (state, handle, error): (&'static [u8], _, Status) = match done {
                    None => (b"pending", RaxPortableHandleV1::default(), 0),
                    Some(Ok(Called::Returned(values))) => {
                        let module = &pending.process.loaded.module;
                        let results = values
                            .iter()
                            .zip(module.signature(pending.entry).results())
                            .map(|(value, ty)| Scalar {
                                value: *value,
                                bits: scalar_bits(module.ty(*ty)).unwrap_or(0),
                            })
                            .collect();
                        (b"returned", insert(Object::Results(Arc::new(results))), 0)
                    }
                    Some(Ok(Called::Ended(exit))) => {
                        let (state, text) = record(Ok(Outcome { exit, steps: 0 }));
                        (state, insert(Object::Record(Arc::new(text))), 0)
                    }
                    Some(Err(status)) => {
                        let (state, text) = defect();
                        (state, insert(Object::Record(Arc::new(text))), status)
                    }
                };
                // SAFETY: the structure was checked.
                unsafe { observed(result, state, handle, error) };
            }
        }
        Ok(())
    })
}

/// How many values a call returned.
///
/// # Safety
///
/// `count` is room for a number.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rax_portable_v1_result_count(
    result: RaxPortableHandleV1,
    count: *mut u64,
) -> Status {
    guarded(|| {
        let length = match locked(&REGISTRY).object(result)? {
            Object::Results(values) => values.len() as u64,
            _ => return Err(EBADF),
        };
        if count.is_null() {
            return Err(EINVAL);
        }
        // SAFETY: room for a number, by the caller's promise.
        unsafe { count.write(length) };
        Ok(())
    })
}

/// One of the values a call returned, as a value of its own that the
/// caller releases. `ERANGE` for an index beyond the last.
///
/// # Safety
///
/// `value` is room for a handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rax_portable_v1_result_at(
    result: RaxPortableHandleV1,
    index: u64,
    value: *mut RaxPortableHandleV1,
) -> Status {
    guarded(|| {
        let scalar = match locked(&REGISTRY).object(result)? {
            Object::Results(values) => usize::try_from(index)
                .ok()
                .and_then(|index| values.get(index).copied())
                .ok_or(ERANGE)?,
            _ => return Err(EBADF),
        };
        if value.is_null() {
            return Err(EINVAL);
        }
        let handle = insert(Object::Value(scalar));
        // SAFETY: room for a handle, by the caller's promise.
        unsafe { value.write(handle) };
        Ok(())
    })
}

/// The bits of a scalar value, in as many bytes as its type has, least
/// significant first. `written` is set to that number; with a capacity of
/// zero that is all, and with too small a one the status is `ERANGE`. Bits
/// the program left unspecified read as zero; `EINVAL` for a value that is
/// poison.
///
/// # Safety
///
/// `buffer` points to a `RaxPortableBufferV1` whose `data` has `capacity`
/// writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rax_portable_v1_value_read_bits(
    value: RaxPortableHandleV1,
    buffer: *mut RaxPortableBufferV1,
) -> Status {
    guarded(|| {
        let scalar = match locked(&REGISTRY).object(value)? {
            Object::Value(scalar) => *scalar,
            _ => return Err(EBADF),
        };
        let number = match scalar.value {
            Value::Int(number) => number,
            Value::Undef => 0,
            _ => return Err(EINVAL),
        };
        if buffer.is_null() || scalar.bits == 0 {
            return Err(EINVAL);
        }
        let bytes = scalar.bits.div_ceil(8) as usize;
        // SAFETY: the caller's promise.
        let buffer = unsafe { &mut *buffer };
        buffer.written = bytes as u64;
        if buffer.capacity == 0 {
            return Ok(());
        }
        if buffer.capacity < bytes as u64 {
            return Err(ERANGE);
        }
        if buffer.data.is_null() {
            return Err(EINVAL);
        }
        // SAFETY: `data` has room for `capacity` bytes, which are enough.
        unsafe {
            std::ptr::copy_nonoverlapping(number.to_le_bytes().as_ptr(), buffer.data, bytes);
        }
        Ok(())
    })
}

/// End a process and say how it ended, as `poll` says it of an image.
///
/// An image that was started is waited for. A library is finished: its
/// finalizers run, unless a call has ended the program already, and its
/// threads stop; `EBUSY` while one of its calls is still running. `EINVAL`
/// for a process that was never started or called.
///
/// # Safety
///
/// As for [`rax_portable_v1_poll`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rax_portable_v1_process_join(
    process: RaxPortableHandleV1,
    result: *mut RaxPortablePollV1,
) -> Status {
    guarded(|| {
        let process = process_of(process)?;
        // SAFETY: the caller's promise.
        unsafe { poll_structure(result)? };
        let mut stage = locked(&process.stage);
        if let Stage::Library(instance) = &*stage {
            // The last owner finishes it; a call in flight is another.
            if Arc::strong_count(instance) != 1 {
                return Err(EBUSY);
            }
            let Stage::Library(instance) = std::mem::replace(&mut *stage, Stage::Running) else {
                return Err(EIO);
            };
            let instance = Arc::try_unwrap(instance).map_err(|_| EIO)?;
            let ended = catch_unwind(AssertUnwindSafe(|| instance.finish()));
            flush();
            let (state, text) = match ended {
                Ok(outcome) => record(outcome),
                Err(_) => defect(),
            };
            *stage = Stage::Ended(state, Arc::new(text));
        }
        if matches!(*stage, Stage::Created) {
            // Nothing will end a process that was never started.
            return Err(EINVAL);
        }
        while !matches!(*stage, Stage::Ended(..)) {
            stage = process
                .changed
                .wait(stage)
                .unwrap_or_else(PoisonError::into_inner);
        }
        // SAFETY: the structure was checked.
        unsafe { observe(&stage, result) };
        Ok(())
    })
}

/// Ask that a request not happen. A program that has started is not
/// stopped: `*won_before_effect` is 0.
///
/// # Safety
///
/// `won_before_effect` is room for a number.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rax_portable_v1_cancel(
    request: RaxPortableHandleV1,
    won_before_effect: *mut u32,
) -> Status {
    guarded(|| {
        if !matches!(
            locked(&REGISTRY).object(request)?,
            Object::Request(_) | Object::Call(_)
        ) {
            return Err(EBADF);
        }
        if won_before_effect.is_null() {
            return Err(EINVAL);
        }
        // SAFETY: room for a number, by the caller's promise.
        unsafe { won_before_effect.write(0) };
        Ok(())
    })
}

/// Read a record: one line of ASCII JSON with `version`, `reason`
/// (`normal`, `abort`, `trap` or `failed`), `code`, `thread` and `trap`.
///
/// `written` is set to the record's size. With a capacity of zero that is
/// all; with too small a one the status is `ERANGE` and nothing is copied.
///
/// # Safety
///
/// `buffer` points to a `RaxPortableBufferV1` whose `data` has `capacity`
/// writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rax_portable_v1_record_read(
    record: RaxPortableHandleV1,
    buffer: *mut RaxPortableBufferV1,
) -> Status {
    guarded(|| {
        let text = match locked(&REGISTRY).object(record)? {
            Object::Record(text) => Arc::clone(text),
            _ => return Err(EBADF),
        };
        if buffer.is_null() {
            return Err(EINVAL);
        }
        // SAFETY: the caller's promise.
        let buffer = unsafe { &mut *buffer };
        buffer.written = text.len() as u64;
        if buffer.capacity == 0 {
            return Ok(());
        }
        if buffer.capacity < text.len() as u64 {
            return Err(ERANGE);
        }
        if buffer.data.is_null() {
            return Err(EINVAL);
        }
        // SAFETY: `data` has room for `capacity` bytes, which are enough.
        unsafe { std::ptr::copy_nonoverlapping(text.as_ptr(), buffer.data, text.len()) };
        Ok(())
    })
}

/// Add an owner to a handle: it is good until it has been released once
/// more.
#[unsafe(no_mangle)]
pub extern "C" fn rax_portable_v1_retain(handle: RaxPortableHandleV1) -> Status {
    guarded(|| {
        let mut registry = locked(&REGISTRY);
        let slot = registry.slot(handle)?;
        slot.references = slot.references.checked_add(1).ok_or(EINVAL)?;
        Ok(())
    })
}

/// Give up a handle. When its last owner has, it names nothing any more;
/// what it named lasts as long as something else needs it, as a running
/// process needs its module.
#[unsafe(no_mangle)]
pub extern "C" fn rax_portable_v1_release(handle: RaxPortableHandleV1) -> Status {
    guarded(|| {
        let released = {
            let mut registry = locked(&REGISTRY);
            let slot = registry.slot(handle)?;
            slot.references -= 1;
            if slot.references != 0 {
                return Ok(());
            }
            slot.generation += 1;
            let object = slot.object.take();
            registry.free.push(handle.slot as usize);
            object
        };
        // Dropped outside the table's lock.
        drop(released);
        Ok(())
    })
}

/// The functions for aggregates and pointers, and those that answer host
/// imports. Each checks nothing and does nothing.
macro_rules! unimplemented_exports {
    ($($name:ident($($argument:ident: $kind:ty),*);)*) => {
        $(
            /// Not implemented: `ENOSYS`.
            #[unsafe(no_mangle)]
            pub extern "C" fn $name($($argument: $kind),*) -> Status {
                $(let _ = $argument;)*
                ENOSYS
            }
        )*
    };
}

unimplemented_exports! {
    rax_portable_v1_value_aggregate(module: RaxPortableHandleV1, execution_type: u32, reserved0: u32,
                                    elements: *const RaxPortableHandleV1, count: u64,
                                    value: *mut RaxPortableHandleV1);
    rax_portable_v1_value_pointer(pointer_value: RaxPortableHandleV1, offset: u64,
                                  value: *mut RaxPortableHandleV1);
    rax_portable_v1_call_result_bits(call: RaxPortableHandleV1, result_index: u64,
                                     bits: RaxPortableBytesV1, value: *mut RaxPortableHandleV1);
    rax_portable_v1_call_return(call: RaxPortableHandleV1, values: *const RaxPortableHandleV1,
                                count: u64, completion: *mut RaxPortablePollV1);
    rax_portable_v1_host_complete(call: RaxPortableHandleV1, result: *const RaxPortablePollV1);
}
