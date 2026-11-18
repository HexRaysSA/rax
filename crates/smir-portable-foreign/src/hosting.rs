//! A host with a processor: any host, and a [`Processor`] for the foreign
//! code of the program it runs.

use rax_smir_portable::interp::{Clock, Errno, Foreign, Host, OpenFlags, Whence};
use rax_smir_portable::ir::HostImport;

use crate::Processor;

/// The host `H`, which also grants `foreign` and has a processor to hand
/// over to the process it starts. In everything else it is `H`.
///
/// The processor goes to the first process started under this host; a
/// second would find none, and a program with foreign code would not start.
pub struct Hosting<H> {
    host: H,
    processor: Option<Box<dyn Foreign>>,
}

impl<H: Host> Hosting<H> {
    pub fn new(host: H, processor: Processor) -> Self {
        Self {
            host,
            processor: Some(Box::new(processor)),
        }
    }

    /// The host this is in everything else.
    pub fn host(&mut self) -> &mut H {
        &mut self.host
    }
}

impl<H: Host> Host for Hosting<H> {
    fn grants(&self, capability: &str) -> bool {
        capability == "foreign" || self.host.grants(capability)
    }

    fn provides(&self, import: &HostImport) -> bool {
        self.host.provides(import)
    }

    fn call(&mut self, import: &HostImport, arguments: &[u128]) -> Result<Vec<u128>, Errno> {
        self.host.call(import, arguments)
    }

    fn foreign(&mut self) -> Option<Box<dyn Foreign>> {
        self.processor.take()
    }

    fn read(&mut self, handle: u64, buffer: &mut [u8]) -> Result<usize, Errno> {
        self.host.read(handle, buffer)
    }

    fn write(&mut self, handle: u64, bytes: &[u8]) -> Result<usize, Errno> {
        self.host.write(handle, bytes)
    }

    fn now(&mut self, clock: Clock) -> Result<u64, Errno> {
        self.host.now(clock)
    }

    fn open(&mut self, path: &str, flags: OpenFlags, mode: u32) -> Result<u64, Errno> {
        self.host.open(path, flags, mode)
    }

    fn close(&mut self, handle: u64) -> Result<(), Errno> {
        self.host.close(handle)
    }

    fn seek(&mut self, handle: u64, offset: i64, whence: Whence) -> Result<u64, Errno> {
        self.host.seek(handle, offset, whence)
    }

    fn unlink(&mut self, path: &str) -> Result<(), Errno> {
        self.host.unlink(path)
    }

    fn rename(&mut self, from: &str, to: &str) -> Result<(), Errno> {
        self.host.rename(from, to)
    }
}
