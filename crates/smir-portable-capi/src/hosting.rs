//! The host a process of a context runs against.

use std::collections::BTreeSet;
use std::sync::Arc;

use rax_smir_portable::interp::{
    Clock, Directory, Errno, Host, OpenFlags, StandardStreams, Whence,
};
use rax_smir_portable::ir::HostImport;

use super::Process;
use super::imports::{Registered, perform};

/// A host that grants what the context grants, and no more than the host
/// inside it has; and that has the functions the context registered.
struct Granted<H> {
    inner: H,
    grants: BTreeSet<&'static str>,
    functions: Vec<Arc<Registered>>,
}

impl<H> Granted<H> {
    /// The registered function an import is of: the one whose descriptor
    /// the import quotes.
    fn function(&self, import: &HostImport) -> Option<&Arc<Registered>> {
        self.functions
            .iter()
            .find(|function| function.identity() == import.descriptor)
    }
}

impl<H: Host> Host for Granted<H> {
    fn grants(&self, capability: &str) -> bool {
        // Having registered functions is the grant of calling them.
        if capability == "host_value" {
            return !self.functions.is_empty();
        }
        self.grants.contains(capability) && self.inner.grants(capability)
    }
    fn provides(&self, import: &HostImport) -> bool {
        self.function(import).is_some()
    }
    fn call(&mut self, import: &HostImport, arguments: &[u128]) -> Result<Vec<u128>, Errno> {
        let function = self.function(import).ok_or(Errno::EIO)?;
        perform(function, arguments).ok_or(Errno::EIO)
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

/// The host a process runs against: the standard streams of the host
/// program, the files of the context's directory if it has one, the
/// functions the context registered, and of all that what the context
/// grants.
pub(super) fn host_of(process: &Process) -> std::io::Result<Box<dyn Host>> {
    let streams = StandardStreams {
        input: std::io::stdin(),
        output: std::io::stdout(),
        error: std::io::stderr(),
    };
    let grants = process.context.grants.clone();
    let functions = process.context.imports.clone();
    Ok(match &process.files {
        None => Box::new(Granted {
            inner: streams,
            grants,
            functions,
        }),
        Some(files) => Box::new(Granted {
            inner: Directory::new(streams, files)?,
            grants,
            functions,
        }),
    })
}
