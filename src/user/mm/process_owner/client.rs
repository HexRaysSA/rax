//! Worker-side synchronous owner sessions. The canonical native lease spans
//! Begin acknowledgement, operations and End acknowledgement. A panic or lost
//! reply closes the endpoint; a mutation is never silently retried.

use std::fmt;
use std::io;
use std::marker::PhantomData;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::thread::ThreadId;

use super::broker::invalid;
use super::wire::{Operation, Request, Response, Value};
use super::{Channel, Frame, MemoryFailure, PreparationFailure};
use crate::user::mm::process_lease::ProcessLease;

mod access;
pub(crate) use access::Access;

#[derive(Debug)]
pub(crate) enum RemoteError {
    Transport(io::Error),
    Memory(MemoryFailure),
    Preparation(PreparationFailure),
}

impl fmt::Display for RemoteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(error) => fmt::Display::fmt(error, f),
            Self::Memory(error) => write!(f, "owner memory operation failed: {error:?}"),
            Self::Preparation(error) => write!(f, "owner endpoint preparation failed: {error:?}"),
        }
    }
}

impl std::error::Error for RemoteError {}

impl From<io::Error> for RemoteError {
    fn from(error: io::Error) -> Self {
        Self::Transport(error)
    }
}

pub(crate) struct Client {
    endpoint: Arc<Endpoint>,
}

impl Client {
    pub(crate) fn new(channel: Channel) -> Self {
        Self {
            endpoint: Arc::new(Endpoint {
                channel: Mutex::new(channel),
                active: Mutex::new(None),
                host: AtomicI32::new(0),
                mutation: AtomicU64::new(0),
                cpu_memory: Mutex::new(Weak::new()),
            }),
        }
    }

    /// Transfer this unshared endpoint to a host-fork child. The parent must
    /// close its copy; the child must close inherited parent/sibling clients.
    pub(crate) fn into_channel(self) -> io::Result<Channel> {
        self.endpoint.check_transfer_host()?;
        let endpoint = Arc::try_unwrap(self.endpoint).map_err(|endpoint| {
            endpoint.close();
            io::Error::other("memory-owner endpoint still in use")
        })?;
        endpoint
            .channel
            .into_inner()
            .map_err(|_| io::Error::other("memory-owner channel poisoned"))
    }

    pub(crate) fn with<R>(
        &mut self,
        lease: &ProcessLease,
        run: impl FnOnce(&mut Session<'_>) -> Result<R, RemoteError>,
    ) -> Result<R, RemoteError> {
        lease
            .with(|| {
                let (serial, space) = self.endpoint.begin()?;
                let mut session = Session {
                    endpoint: self.endpoint.clone(),
                    serial,
                    space,
                    ended: false,
                    borrow: PhantomData,
                };
                let result = run(&mut session);
                let end = session.end();
                match (result, end) {
                    (Err(error @ (RemoteError::Transport(_) | RemoteError::Preparation(_))), _) => {
                        Err(error)
                    }
                    (_, Err(error)) => Err(error),
                    (result, Ok(())) => result,
                }
            })
            .map_err(RemoteError::Transport)?
    }
}

pub(crate) struct Session<'a> {
    endpoint: Arc<Endpoint>,
    serial: u64,
    space: u64,
    ended: bool,
    borrow: PhantomData<&'a mut Client>,
}

impl Session<'_> {
    /// This identity selects an MM; it does not import physical storage or
    /// establish a CPU memory view. CPU entry needs its separate import gate.
    pub(crate) fn space(&self) -> u64 {
        self.space
    }

    /// An owned callback capability for this MM. It retains no descriptor
    /// and authorizes calls only on the active session's host thread.
    pub(crate) fn cpu_memory(&self) -> Result<super::OwnerMemory, RemoteError> {
        self.access().cpu_memory()
    }

    pub(crate) fn access(&self) -> Access {
        Access::new(&self.endpoint, self.space)
    }

    pub(crate) fn call(&mut self, operation: Operation) -> Result<Value, RemoteError> {
        self.endpoint
            .memory(self.space, Some(self.serial), operation)
    }

    /// Prepare a child endpoint under the current turn, then end the session
    /// before host fork. The returned client cannot bind to the parent's PID.
    /// Unpublished transport preparation failure retains the session and
    /// reports native diagnostics separately from guest errno policy.
    pub(crate) fn fork(&mut self, private: bool) -> Result<Client, RemoteError> {
        self.endpoint.current(self.space, Some(self.serial))?;
        let (response, mut frame) = self.endpoint.exchange(&Request::Fork {
            serial: self.serial,
            private,
        })?;
        match response {
            Response::Forked if frame.files.len() == 1 => {
                let stream = UnixStream::from(frame.files.pop().unwrap());
                let child = Channel::new(stream).inspect_err(|_| self.endpoint.close())?;
                let (response, frame) = self.endpoint.exchange(&Request::ConfirmFork {
                    serial: self.serial,
                })?;
                if !matches!(response, Response::ForkConfirmed) || !frame.files.is_empty() {
                    return Err(self.endpoint.reject().into());
                }
                Ok(Client::new(child))
            }
            Response::Result { result: Err(error) } if frame.files.is_empty() => {
                Err(RemoteError::Memory(error))
            }
            Response::ForkFailed { failure } if frame.files.is_empty() => {
                Err(RemoteError::Preparation(failure))
            }
            _ => Err(self.endpoint.reject().into()),
        }
    }

    fn end(&mut self) -> Result<(), RemoteError> {
        self.endpoint.current(self.space, Some(self.serial))?;
        let memory = {
            self.endpoint
                .cpu_memory
                .lock()
                .map_err(|_| poisoned())?
                .upgrade()
        };
        if let Some(inner) = memory {
            let memory = super::OwnerMemory::from_inner(inner);
            if memory.space() == self.space {
                // Capture final trace metadata under the same native lease.
                // CPU destruction after End must not perform an owner RPC.
                memory.finish_trace_turn()?;
            }
        }
        let (response, frame) = self.endpoint.exchange(&Request::End {
            serial: self.serial,
        })?;
        if !matches!(response, Response::Ended) || !frame.files.is_empty() {
            return Err(self.endpoint.reject().into());
        }
        *self.endpoint.active.lock().map_err(|_| poisoned())? = None;
        self.ended = true;
        Ok(())
    }
}

fn valid_value(value: &Value, operation: &Operation) -> bool {
    match operation {
        Operation::Read { len, .. } => {
            matches!(value, Value::Bytes { bytes } if bytes.len() == *len as usize)
        }
        Operation::Translate { .. } => matches!(value, Value::Physical { .. }),
        Operation::CodeChanges { .. } => matches!(value, Value::Code { .. }),
        Operation::ResidentAccessible { .. } => matches!(value, Value::ResidentAccessible { .. }),
        Operation::Stats => matches!(value, Value::Stats { .. }),
        Operation::Mappings { offset } => matches!(value, Value::Mappings { total, bytes }
            if !bytes.is_empty() && bytes.len() <= super::wire::TRANSFER_BYTES
                && offset.checked_add(bytes.len() as u64).is_some_and(|end| end <= *total)),
        _ => matches!(value, Value::Unit),
    }
}

impl Drop for Session<'_> {
    fn drop(&mut self) {
        if !self.ended {
            self.endpoint.close();
        }
    }
}

#[derive(Clone, Copy)]
struct Active {
    pid: libc::pid_t,
    thread: ThreadId,
    serial: u64,
    space: u64,
}

/// Never hold either mutex across a user callback. The lease, endpoint PID
/// binding and active host thread govern the complete execution window; the
/// channel mutex governs exactly one synchronous request/reply exchange.
struct Endpoint {
    channel: Mutex<Channel>,
    active: Mutex<Option<Active>>,
    host: AtomicI32,
    mutation: AtomicU64,
    cpu_memory: Mutex<Weak<super::cpu::Inner>>,
}

impl Endpoint {
    fn begin(&self) -> io::Result<(u64, u64)> {
        let pid = host_pid();
        match self
            .host
            .compare_exchange(0, pid, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => (),
            Err(bound) if bound == pid => (),
            Err(_) => return Err(inactive()),
        }
        if self.active.lock().map_err(|_| poisoned())?.is_some() {
            return Err(inactive());
        }
        let (response, frame) = self.exchange(&Request::Begin { pid })?;
        let Response::Grant { serial, space } = response else {
            return Err(self.reject());
        };
        if !frame.files.is_empty() || serial == 0 || space == 0 {
            return Err(self.reject());
        }
        *self.active.lock().map_err(|_| poisoned())? = Some(Active {
            pid,
            thread: std::thread::current().id(),
            serial,
            space,
        });
        Ok((serial, space))
    }

    fn current(&self, space: u64, serial: Option<u64>) -> io::Result<Active> {
        if self.host.load(Ordering::Acquire) != host_pid() {
            return Err(inactive());
        }
        let active = self
            .active
            .lock()
            .map_err(|_| poisoned())?
            .ok_or_else(inactive)?;
        if active.pid != host_pid()
            || active.thread != std::thread::current().id()
            || active.space != space
            || serial.is_some_and(|serial| serial != active.serial)
        {
            return Err(inactive());
        }
        Ok(active)
    }

    fn memory(
        &self,
        space: u64,
        serial: Option<u64>,
        operation: Operation,
    ) -> Result<Value, RemoteError> {
        let active = self.current(space, serial)?;
        if !operation.valid_size() {
            return Err(io::Error::from(io::ErrorKind::InvalidInput).into());
        }
        if operation.mutates() {
            self.mutation
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |epoch| {
                    epoch.checked_add(1)
                })
                .map_err(|_| self.reject())?;
        }
        let request = Request::Memory {
            serial: active.serial,
            operation,
        };
        let (response, frame) = self.exchange(&request)?;
        if !frame.files.is_empty() {
            return Err(self.reject().into());
        }
        match response {
            Response::Result { result: Ok(value) } => {
                let Request::Memory { operation, .. } = &request else {
                    unreachable!()
                };
                if !valid_value(&value, operation) {
                    return Err(self.reject().into());
                }
                Ok(value)
            }
            Response::Result { result: Err(error) } => Err(RemoteError::Memory(error)),
            _ => Err(self.reject().into()),
        }
    }

    fn exchange(&self, request: &Request) -> io::Result<(Response, Frame)> {
        if self.host.load(Ordering::Acquire) != host_pid() {
            return Err(inactive());
        }
        let result = match self.channel.lock() {
            Ok(mut channel) => exchange(&mut channel, request),
            Err(_) => Err(poisoned()),
        };
        if result.is_err() {
            // Release the exchange guard before revoking the entire window.
            // A CPU callback must lose its rights as soon as transport fails.
            self.close();
        }
        result
    }

    fn personality<Q: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self,
        space: u64,
        operation: &Q,
    ) -> Result<R, RemoteError> {
        let active = self.current(space, None)?;
        let bytes = serde_json::to_vec(operation)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        if bytes.len() > super::wire::PERSONALITY_BYTES {
            return Err(io::Error::from(io::ErrorKind::InvalidInput).into());
        }
        self.mutation
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |epoch| {
                epoch.checked_add(1)
            })
            .map_err(|_| self.reject())?;
        let (response, frame) = self.exchange(&Request::Personality {
            serial: active.serial,
            bytes,
        })?;
        let Response::Personality { bytes } = response else {
            return Err(self.reject().into());
        };
        if !frame.files.is_empty() || bytes.len() > super::wire::PERSONALITY_BYTES {
            return Err(self.reject().into());
        }
        serde_json::from_slice(&bytes).map_err(|_| self.reject().into())
    }

    fn check_transfer_host(&self) -> io::Result<()> {
        let bound = self.host.load(Ordering::Acquire);
        if bound == 0 || bound == host_pid() {
            Ok(())
        } else {
            Err(inactive())
        }
    }

    fn close(&self) {
        // Never shutdown an inherited socket: that would also affect its
        // legitimate caller in the original host process.
        if self.check_transfer_host().is_err() {
            return;
        }
        // Poison remains set: this only revokes rights and closes resources;
        // it never restores a poisoned endpoint to service.
        *self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        self.channel
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .close();
    }

    fn reject(&self) -> io::Error {
        self.close();
        invalid()
    }
}

fn host_pid() -> libc::pid_t {
    // SAFETY: getpid has no pointers or mutable caller-owned state.
    unsafe { libc::getpid() }
}

fn inactive() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "inactive memory-owner execution window",
    )
}

fn poisoned() -> io::Error {
    io::Error::other("memory-owner endpoint synchronization poisoned")
}

fn exchange(channel: &mut Channel, request: &Request) -> io::Result<(Response, Frame)> {
    let bytes = serde_json::to_vec(request).map_err(|_| invalid())?;
    channel.send(&bytes, &[])?;
    let frame = channel.receive()?;
    let response = serde_json::from_slice(&frame.bytes).map_err(|_| reject(channel))?;
    Ok((response, frame))
}

fn reject(channel: &mut Channel) -> io::Error {
    channel.close();
    invalid()
}
