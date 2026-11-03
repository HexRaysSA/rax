//! Native FIFO reads whose completion cannot be inferred from readiness.
//!
//! A job owns its descriptor, buffer and completion socket. It never changes
//! the shared fileglob flags or installs a signal handler. Pause joins the
//! native worker before a host fork; unperformed reads can then be resumed
//! only in the parent. Drop interrupts and joins every remaining worker.

use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

type Completion = io::Result<Vec<u8>>;

#[cfg(test)]
#[path = "fifo_read_tests.rs"]
mod tests;

unsafe extern "C" {
    fn thread_abort(thread: u32) -> i32;
    fn mach_port_deallocate(task: u32, name: u32) -> i32;
}

#[derive(Debug)]
struct Shared {
    result: Mutex<Option<Completion>>,
    cancelled: AtomicBool,
    in_read: AtomicBool,
    port: AtomicU32,
}

#[derive(Debug)]
struct Control {
    worker: Option<JoinHandle<()>>,
    paused: bool,
}

pub(super) struct Job {
    file: OwnedFd,
    readable: UnixStream,
    writable: Arc<UnixStream>,
    shared: Arc<Shared>,
    control: Mutex<Control>,
    capacity: usize,
}

impl Job {
    pub(super) fn start(file: BorrowedFd<'_>, capacity: usize) -> io::Result<Self> {
        if capacity > i32::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "FIFO transfer exceeds Darwin IO_MAX",
            ));
        }
        let file = file.try_clone_to_owned()?;
        let (readable, writable) = UnixStream::pair()?;
        readable.set_nonblocking(true)?;
        writable.set_nonblocking(true)?;
        let job = Self {
            file,
            readable,
            writable: Arc::new(writable),
            shared: Arc::new(Shared {
                result: Mutex::new(None),
                cancelled: AtomicBool::new(false),
                in_read: AtomicBool::new(false),
                port: AtomicU32::new(0),
            }),
            control: Mutex::new(Control {
                worker: None,
                paused: true,
            }),
            capacity,
        };
        job.resume()?;
        Ok(job)
    }

    pub(super) fn fd(&self) -> i32 {
        self.readable.as_raw_fd()
    }

    pub(super) fn ready(&self) -> bool {
        self.shared.result.lock().unwrap().is_some()
    }

    /// A published completion is owned exactly once by its guest kernel entry.
    pub(super) fn take(&self) -> Option<Completion> {
        self.shared.result.lock().unwrap().take()
    }

    /// Stop a native call and retain its actual result, including bytes that
    /// won a race with cancellation. The caller chooses guest EINTR/ERESTART.
    pub(super) fn interrupt(&self) {
        let mut control = self.control.lock().unwrap();
        self.join(&mut control);
    }

    /// No native worker or held result mutex may cross the host fork.
    /// Completed bytes remain parent-owned; only an unperformed EINTR is rearmed.
    pub(super) fn pause(&self) {
        let mut control = self.control.lock().unwrap();
        self.join(&mut control);
        let mut result = self.shared.result.lock().unwrap();
        if result.as_ref().is_some_and(|r| {
            r.as_ref()
                .is_err_and(|e| e.raw_os_error() == Some(libc::EINTR))
        }) {
            *result = None;
            control.paused = true;
        }
    }

    pub(super) fn resume(&self) -> io::Result<()> {
        let mut control = self.control.lock().unwrap();
        if !control.paused || control.worker.is_some() {
            return Ok(());
        }
        let mut buffer = Vec::<u8>::new();
        buffer
            .try_reserve_exact(self.capacity)
            .map_err(|_| io::Error::from_raw_os_error(libc::ENOMEM))?;
        let mut reader = &self.readable;
        let mut drained = [0; 32];
        loop {
            match reader.read(&mut drained) {
                Ok(0) => break,
                Ok(_) => continue,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
        self.shared.cancelled.store(false, Ordering::Release);
        let shared = self.shared.clone();
        let notify = self.writable.clone();
        let fd = self.file.as_raw_fd();
        let capacity = self.capacity;
        control.worker = Some(
            std::thread::Builder::new()
                .name("rax-fifo-read".into())
                .stack_size(128 * 1024)
                .spawn(move || {
                    // SAFETY: returns a new send reference for this native thread.
                    #[allow(deprecated)]
                    let port = unsafe { libc::mach_thread_self() };
                    shared.port.store(port, Ordering::Release);
                    shared.in_read.store(true, Ordering::Release);
                    let result = if shared.cancelled.load(Ordering::Acquire) {
                        Err(io::Error::from_raw_os_error(libc::EINTR))
                    } else if port == 0 {
                        Err(io::Error::from_raw_os_error(libc::EIO))
                    } else {
                        loop {
                            if shared.cancelled.load(Ordering::Acquire) {
                                break Err(io::Error::from_raw_os_error(libc::EINTR));
                            }
                            // SAFETY: Job owns fd until this worker has joined.
                            // Buffer exclusively owns capacity writable spare bytes.
                            let count =
                                unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), capacity) };
                            if count >= 0 {
                                // SAFETY: read initialized exactly this prefix of
                                // the allocation. EOF touches no spare pages.
                                unsafe {
                                    buffer.set_len(count as usize);
                                }
                                break Ok(buffer);
                            }
                            let error = io::Error::last_os_error();
                            if error.kind() == io::ErrorKind::Interrupted {
                                continue;
                            }
                            if error.kind() != io::ErrorKind::WouldBlock {
                                break Err(error);
                            }
                            // This kernel entry was blocking before an internal
                            // pause. A caller can change shared O_NONBLOCK while
                            // it is pending; rearming must preserve the entry's
                            // semantics without restoring or hiding those flags.
                            let mut descriptor = libc::pollfd {
                                fd,
                                events: libc::POLLIN,
                                revents: 0,
                            };
                            // SAFETY: this one live descriptor is owned by Job.
                            if unsafe { libc::poll(&mut descriptor, 1, 10) } < 0 {
                                let error = io::Error::last_os_error();
                                if error.kind() != io::ErrorKind::Interrupted {
                                    break Err(error);
                                }
                            }
                            // Read again even when poll stayed quiet: native FIFO
                            // EOF can have no readiness event after a prior read.
                        }
                    };
                    shared.in_read.store(false, Ordering::Release);
                    *shared.result.lock().unwrap() = Some(result);
                    let mut writer = &*notify;
                    if let Err(error) = writer.write_all(&[1])
                        && error.kind() != io::ErrorKind::WouldBlock
                    {
                        // A shutdown also wakes poll; never leave a published
                        // completion silent if the private socket fails.
                        let _ = notify.shutdown(std::net::Shutdown::Write);
                    }
                })?,
        );
        control.paused = false;
        Ok(())
    }

    fn join(&self, control: &mut Control) {
        self.shared.cancelled.store(true, Ordering::Release);
        if let Some(worker) = control.worker.take() {
            while !worker.is_finished() {
                let port = self.shared.port.load(Ordering::Acquire);
                if port != 0 && self.shared.in_read.load(Ordering::Acquire) {
                    // SAFETY: the worker published an owned thread send right.
                    // Repeating covers cancellation before native read entry.
                    // No user registers or signal dispositions are changed.
                    unsafe {
                        thread_abort(port);
                    }
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            if worker.join().is_err() {
                *self.shared.result.lock().unwrap() =
                    Some(Err(io::Error::from_raw_os_error(libc::EIO)));
            }
            let port = self.shared.port.swap(0, Ordering::AcqRel);
            if port != 0 {
                // SAFETY: the joined worker created exactly this owned send
                // reference. Its name cannot be reused before deallocation.
                #[allow(deprecated)]
                unsafe {
                    mach_port_deallocate(libc::mach_task_self(), port);
                }
            }
        }
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        self.interrupt();
    }
}

impl std::fmt::Debug for Job {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FifoRead")
            .field("fd", &self.file.as_raw_fd())
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}
