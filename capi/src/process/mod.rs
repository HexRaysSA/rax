//! ABI 1.8: bounded full-process embedding on a dedicated owner thread.
//! Guest filesystem access is disabled; all images and console bytes are copied.
mod options;
mod runtime;

use crate::{RaxStatus, guard};
use runtime::{Command, Response, Work};
use std::cell::RefCell;
use std::os::raw::c_char;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::JoinHandle;

pub const RAX_PROCESS_RESULT_VERSION: u32 = 1;
pub const RAX_PROCESS_READY: u32 = 0;
pub const RAX_PROCESS_BUDGET: u32 = 1;
pub const RAX_PROCESS_BLOCKED: u32 = 2;
pub const RAX_PROCESS_CANCELLED: u32 = 3;
pub const RAX_PROCESS_EXITED: u32 = 4;
pub const RAX_PROCESS_FAILED: u32 = 5;
pub const RAX_PROCESS_TIMEOUT: u32 = 6;
pub const RAX_PROCESS_STDOUT: u32 = 1;
pub const RAX_PROCESS_STDERR: u32 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RaxProcessImage {
    pub path: *const c_char,
    pub path_size: usize,
    pub data: *const u8,
    pub data_size: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RaxProcessResult {
    pub struct_size: u32,
    pub version: u32,
    pub reason: u32,
    pub exit_code: u32,
    pub turns_started: u64,
    pub elapsed_us: u64,
}
impl Default for RaxProcessResult {
    fn default() -> Self {
        Self {
            struct_size: std::mem::size_of::<Self>() as u32,
            version: RAX_PROCESS_RESULT_VERSION,
            reason: RAX_PROCESS_READY,
            exit_code: 0,
            turns_started: 0,
            elapsed_us: 0,
        }
    }
}

#[derive(Debug)]
struct Failure(RaxStatus, String);
type Result<T> = std::result::Result<T, Failure>;
fn bad(message: impl Into<String>) -> Failure {
    Failure(RaxStatus::Arg, message.into())
}
fn internal(message: impl Into<String>) -> Failure {
    Failure(RaxStatus::Internal, message.into())
}
thread_local! { static LAST_ERROR: RefCell<String> = const { RefCell::new(String::new()) }; }

fn ffi(f: impl FnOnce() -> Result<()>) -> RaxStatus {
    guard(|| match f() {
        Ok(()) => RaxStatus::Ok,
        Err(Failure(status, message)) => {
            LAST_ERROR.with(|e| *e.borrow_mut() = message);
            status
        }
    })
}

/// The exported handle contains only Send/Sync messaging primitives. The
/// non-Send personality state is constructed, used, and destroyed by its worker.
pub struct Process {
    sender: mpsc::Sender<Work>,
    worker: Option<JoinHandle<()>>,
    cancelled: Arc<AtomicBool>,
    busy: Mutex<()>,
}

impl Process {
    fn request(&self, command: Command) -> Result<Response> {
        let _lock = self.busy.try_lock().map_err(|_| {
            Failure(
                RaxStatus::State,
                "another process operation is active".into(),
            )
        })?;
        let (sender, receiver) = mpsc::sync_channel(0);
        self.sender
            .send((command, Some(sender)))
            .map_err(|_| internal("process worker is unavailable"))?;
        receiver
            .recv()
            .map_err(|_| internal("process worker terminated without a response"))?
    }
    fn shutdown(&mut self) -> Result<()> {
        self.cancelled.store(true, Ordering::Release);
        let _ = self.sender.send((Command::Shutdown, None));
        if let Some(worker) = self.worker.take() {
            worker
                .join()
                .map_err(|_| internal("process worker panicked during shutdown"))?;
        }
        Ok(())
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

unsafe fn handle<'a>(p: *const Process) -> Result<&'a Process> {
    // SAFETY: non-null handles must be live values created by this API. The
    // caller excludes close for the entire call; no reference escapes the call.
    unsafe { p.as_ref() }.ok_or_else(|| Failure(RaxStatus::Handle, "null process handle".into()))
}

unsafe fn bytes<'a>(p: *const u8, size: usize, max: usize) -> Result<&'a [u8]> {
    if size > max || size > isize::MAX as usize {
        return Err(Failure(
            RaxStatus::Bounds,
            "input byte bound exceeded".into(),
        ));
    }
    if size == 0 {
        return Ok(&[]);
    }
    if p.is_null() {
        return Err(bad("null input buffer"));
    }
    // SAFETY: the C contract requires `size` readable initialized bytes, with
    // no concurrent mutation. u8 has alignment one; lengths are bounded above.
    Ok(unsafe { std::slice::from_raw_parts(p, size) })
}

unsafe fn copy_output(
    data: &[u8],
    out: *mut u8,
    capacity: usize,
    required: *mut usize,
) -> Result<()> {
    if required.is_null() || (out.is_null() && capacity != 0) {
        return Err(bad("invalid output buffer/count"));
    }
    // SAFETY: caller supplies a writable, aligned size_t. It does not overlap
    // `out` or live handle storage. Queries publish only this initialized count.
    unsafe {
        required.write(data.len());
    }
    if out.is_null() {
        return Ok(());
    }
    if capacity < data.len() {
        return Err(Failure(RaxStatus::Bounds, "output buffer too small".into()));
    }
    // SAFETY: caller provides capacity writable bytes, disjoint from `data` and
    // the count/handle. Only the bounded initialized result bytes are copied.
    unsafe {
        std::ptr::copy_nonoverlapping(data.as_ptr(), out, data.len());
    }
    Ok(())
}

fn response_bytes(response: Response) -> Result<Vec<u8>> {
    match response {
        Response::Bytes(bytes) => Ok(bytes),
        _ => Err(internal("invalid process worker response")),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn rax_process_open_image(
    image: *const u8,
    image_size: usize,
    options_json: *const c_char,
    options_size: usize,
    images: *const RaxProcessImage,
    image_count: usize,
    out: *mut *mut Process,
) -> RaxStatus {
    ffi(|| {
        if out.is_null() {
            return Err(bad("null process output handle"));
        }
        // SAFETY: the caller supplies writable aligned handle storage, disjoint
        // from all input buffers. Failed creation always publishes a null handle.
        unsafe {
            out.write(std::ptr::null_mut());
        }
        // SAFETY: input pointer/length pairs obey the read-only C buffer contract.
        let executable = unsafe { bytes(image, image_size, options::MAX_IMAGE)? }.to_vec();
        if executable.is_empty() {
            return Err(bad("empty executable image"));
        }
        let mut cfg = options::config(unsafe {
            bytes(options_json.cast(), options_size, options::MAX_OPTIONS)?
        })?;
        if image_count > options::MAX_IMAGES || (image_count != 0 && images.is_null()) {
            return Err(bad("invalid supplied image array"));
        }
        let mut total = executable.len();
        for index in 0..image_count {
            // SAFETY: caller supplies image_count initialized/aligned v1 image
            // records; count is bounded to 64 and pointer arithmetic cannot wrap.
            let entry = unsafe { images.add(index).read() };
            let path =
                std::str::from_utf8(unsafe { bytes(entry.path.cast(), entry.path_size, 4096)? })
                    .map_err(|_| bad("supplied image path is not UTF-8"))?;
            if path.is_empty() || path.contains('\0') {
                return Err(bad("invalid supplied image path"));
            }
            let data = unsafe { bytes(entry.data, entry.data_size, options::MAX_IMAGE)? };
            if data.is_empty() {
                return Err(bad("empty supplied image"));
            }
            total = total
                .checked_add(data.len())
                .filter(|n| *n <= options::MAX_TOTAL_IMAGES)
                .ok_or_else(|| {
                    Failure(RaxStatus::Bounds, "supplied images exceed 256 MiB".into())
                })?;
            if cfg
                .supplied_dlls
                .insert(path.to_owned(), Arc::from(data))
                .is_some()
            {
                return Err(bad("duplicate supplied image path"));
            }
        }
        let cancelled = Arc::new(AtomicBool::new(false));
        let signal = cancelled.clone();
        let (sender, commands) = mpsc::channel();
        let (ready, startup) = mpsc::sync_channel(0);
        let worker = std::thread::Builder::new()
            .name("rax-process".into())
            .spawn(move || runtime::worker(cfg, executable, signal, ready, commands))
            .map_err(|e| Failure(RaxStatus::Io, format!("cannot create process worker: {e}")))?;
        let mut process = Box::new(Process {
            sender,
            worker: Some(worker),
            cancelled,
            busy: Mutex::new(()),
        });
        match startup.recv() {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                let _ = process.shutdown();
                return Err(error);
            }
            Err(_) => {
                let _ = process.shutdown();
                return Err(internal("process creation worker terminated"));
            }
        }
        // SAFETY: output storage was validated above; ownership transfers to the
        // caller, who must close exactly once after all operations have returned.
        unsafe {
            out.write(Box::into_raw(process));
        }
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn rax_process_close(p: *mut Process) -> RaxStatus {
    ffi(|| {
        if p.is_null() {
            return Err(Failure(RaxStatus::Handle, "null process handle".into()));
        }
        // SAFETY: the C contract transfers one live handle back exactly once,
        // excluding every concurrent operation, including cancellation.
        let mut process = unsafe { Box::from_raw(p) };
        process.shutdown()
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn rax_process_set_cancelled(p: *const Process, cancelled: i32) -> RaxStatus {
    ffi(|| {
        if !(0..=1).contains(&cancelled) {
            return Err(bad("cancelled must be zero or one"));
        }
        // SAFETY: live shared handle; close is excluded. Only an AtomicBool is
        // touched, so this entry point may overlap an active run on another thread.
        unsafe { handle(p)? }
            .cancelled
            .store(cancelled != 0, Ordering::Release);
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn rax_process_run(
    p: *const Process,
    max_turns: u64,
    timeout_us: u64,
    out: *mut RaxProcessResult,
) -> RaxStatus {
    ffi(|| {
        if max_turns > 1_000_000 || timeout_us > 60_000_000 {
            return Err(Failure(
                RaxStatus::Bounds,
                "run exceeds 1000000 turns or 60000000 microseconds".into(),
            ));
        }
        if out.is_null() {
            return Err(bad("null process run result"));
        }
        // SAFETY: the caller initializes an aligned record header. Read only the
        // size before requiring all v1 bytes; do not execute on invalid output.
        unsafe {
            if (*out).struct_size < std::mem::size_of::<RaxProcessResult>() as u32 {
                return Err(bad("short process run result"));
            }
            if (*out).version != RAX_PROCESS_RESULT_VERSION {
                return Err(Failure(
                    RaxStatus::Unsupported,
                    "unsupported process result version".into(),
                ));
            }
        }
        // SAFETY: live handle for the call, excluding close.
        let response = unsafe { handle(p)? }.request(Command::Run {
            turns: max_turns,
            timeout_us,
        })?;
        let Response::Run(result) = response else {
            return Err(internal("invalid run response"));
        };
        // SAFETY: full v1 writable record was established before execution; only
        // the initialized v1 bytes are written, leaving any future tail untouched.
        unsafe {
            out.write(result);
        }
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn rax_process_info_json(
    p: *const Process,
    out: *mut c_char,
    capacity: usize,
    required: *mut usize,
) -> RaxStatus {
    ffi(|| {
        if required.is_null() || (out.is_null() && capacity != 0) {
            return Err(bad("invalid inspection output"));
        }
        // SAFETY: live handle and caller-owned output buffers, per the C contract.
        let data = response_bytes(unsafe { handle(p)? }.request(Command::Info)?)?;
        unsafe { copy_output(&data, out.cast(), capacity, required) }
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn rax_process_last_error(
    out: *mut c_char,
    capacity: usize,
    required: *mut usize,
) -> RaxStatus {
    ffi(|| {
        let mut data = LAST_ERROR.with(|e| e.borrow().as_bytes().to_vec());
        data.push(0);
        // SAFETY: caller-owned output/count buffers obey the C query/fill contract.
        unsafe { copy_output(&data, out.cast(), capacity, required) }
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn rax_process_mem_read(
    p: *const Process,
    address: u64,
    out: *mut u8,
    size: usize,
) -> RaxStatus {
    ffi(|| {
        if size > options::MAX_TRANSFER {
            return Err(Failure(
                RaxStatus::Bounds,
                "memory transfer exceeds 16 MiB".into(),
            ));
        }
        if out.is_null() && size != 0 {
            return Err(bad("null memory output"));
        }
        if address.checked_add(size as u64).is_none() {
            return Err(Failure(RaxStatus::Bounds, "guest range wraps".into()));
        }
        // SAFETY: live handle; output has size writable bytes and excludes aliases.
        let data =
            response_bytes(unsafe { handle(p)? }.request(Command::ReadMemory { address, size })?)?;
        if size != 0 {
            unsafe {
                std::ptr::copy_nonoverlapping(data.as_ptr(), out, size);
            }
        }
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn rax_process_mem_write(
    p: *const Process,
    address: u64,
    data: *const u8,
    size: usize,
) -> RaxStatus {
    ffi(|| {
        if address.checked_add(size as u64).is_none() {
            return Err(Failure(RaxStatus::Bounds, "guest range wraps".into()));
        }
        // SAFETY: input is readable for size bytes and handle remains live.
        let bytes = unsafe { bytes(data, size, options::MAX_TRANSFER)? }.to_vec();
        unsafe { handle(p)? }.request(Command::WriteMemory { address, bytes })?;
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn rax_process_context_read(
    p: *const Process,
    tid: u32,
    out: *mut u8,
    capacity: usize,
    required: *mut usize,
) -> RaxStatus {
    ffi(|| {
        if required.is_null() || (out.is_null() && capacity != 0) {
            return Err(bad("invalid context output"));
        }
        // SAFETY: live handle and caller-owned query/fill buffers.
        let data = response_bytes(unsafe { handle(p)? }.request(Command::ReadContext(tid))?)?;
        unsafe { copy_output(&data, out, capacity, required) }
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn rax_process_context_write(
    p: *const Process,
    tid: u32,
    data: *const u8,
    size: usize,
) -> RaxStatus {
    ffi(|| {
        // SAFETY: caller-owned input copied before dispatch; live handle. Contexts
        // are smaller than 4096 bytes and exact architecture size is checked below.
        let bytes = unsafe { bytes(data, size, 4096)? }.to_vec();
        unsafe { handle(p)? }.request(Command::WriteContext { tid, bytes })?;
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn rax_process_stdin_feed(
    p: *const Process,
    data: *const u8,
    size: usize,
) -> RaxStatus {
    ffi(|| {
        // SAFETY: readable caller input and live handle; all data is copied.
        let bytes = unsafe { bytes(data, size, options::MAX_TRANSFER)? }.to_vec();
        unsafe { handle(p)? }.request(Command::Feed(bytes))?;
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn rax_process_output_read(
    p: *const Process,
    stream: u32,
    out: *mut u8,
    capacity: usize,
    written: *mut usize,
) -> RaxStatus {
    ffi(|| {
        use rax_engine::user::console::OutputStream;
        let stream = match stream {
            RAX_PROCESS_STDOUT => OutputStream::Stdout,
            RAX_PROCESS_STDERR => OutputStream::Stderr,
            _ => return Err(bad("output stream must be 1 (stdout) or 2 (stderr)")),
        };
        if written.is_null() || (out.is_null() && capacity != 0) {
            return Err(bad("invalid console output"));
        }
        if capacity > options::MAX_TRANSFER {
            return Err(Failure(
                RaxStatus::Bounds,
                "console transfer exceeds 16 MiB".into(),
            ));
        }
        // SAFETY: live handle and validated output/count storage; no byte is
        // consumed until argument validation completes. Zero capacity is a no-op.
        let data = response_bytes(unsafe { handle(p)? }.request(Command::Drain {
            stream,
            size: capacity,
        })?)?;
        unsafe { copy_output(&data, out, capacity, written) }
    })
}
