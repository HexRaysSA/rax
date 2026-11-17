//! What a run may reach outside the guest program.
//!
//! The interpreter implements the runtime services itself: it validates the
//! arguments and every guest buffer, and only then asks the [`Host`] for the
//! effect, with host-owned byte slices. No guest pointer reaches a host.

use std::io::{ErrorKind, Read, Write};

/// A portable error number: the status a service returns when it fails.
///
/// The numbers are those of `errno-v1.json`, which pins the Linux values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Errno(u32);

impl Errno {
    pub const EINTR: Self = Self(4);
    pub const EIO: Self = Self(5);
    pub const EBADF: Self = Self(9);
    pub const EAGAIN: Self = Self(11);
    pub const ENOSPC: Self = Self(28);
    pub const EPIPE: Self = Self(32);

    /// The status value, which is never zero.
    pub fn code(self) -> u32 {
        self.0
    }
}

impl From<&std::io::Error> for Errno {
    /// An error with no portable counterpart is reported as `EIO`.
    fn from(error: &std::io::Error) -> Self {
        match error.kind() {
            ErrorKind::Interrupted => Self::EINTR,
            ErrorKind::WouldBlock => Self::EAGAIN,
            ErrorKind::StorageFull => Self::ENOSPC,
            ErrorKind::BrokenPipe => Self::EPIPE,
            _ => Self::EIO,
        }
    }
}

/// The embedder's side of the runtime services.
pub trait Host {
    /// Whether the program is granted `capability`. A module runs only if
    /// every capability it declares is granted.
    fn grants(&self, capability: &str) -> bool;

    /// Read up to `buffer.len()` bytes from `handle` and return how many were
    /// read; zero is end of input.
    fn read(&mut self, handle: u64, buffer: &mut [u8]) -> Result<usize, Errno>;

    /// Write a prefix of `bytes` to `handle` and return its length.
    fn write(&mut self, handle: u64, bytes: &[u8]) -> Result<usize, Errno>;
}

/// A host that grants nothing. Modules that need no capability run under it.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoHost;

impl Host for NoHost {
    fn grants(&self, _capability: &str) -> bool {
        false
    }

    fn read(&mut self, _handle: u64, _buffer: &mut [u8]) -> Result<usize, Errno> {
        Err(Errno::EBADF)
    }

    fn write(&mut self, _handle: u64, _bytes: &[u8]) -> Result<usize, Errno> {
        Err(Errno::EBADF)
    }
}

/// The handle of the standard input stream.
pub const STANDARD_INPUT: u64 = 0;
/// The handle of the standard output stream.
pub const STANDARD_OUTPUT: u64 = 1;
/// The handle of the standard error stream.
pub const STANDARD_ERROR: u64 = 2;

/// A host with the three standard streams and nothing else.
///
/// It grants the `file` capability, for those three handles only, and the
/// `process` capability, which lets the program end itself.
#[derive(Debug)]
pub struct StandardStreams<I, O, E> {
    pub input: I,
    pub output: O,
    pub error: E,
}

impl<I: Read, O: Write, E: Write> Host for StandardStreams<I, O, E> {
    fn grants(&self, capability: &str) -> bool {
        matches!(capability, "file" | "process")
    }

    fn read(&mut self, handle: u64, buffer: &mut [u8]) -> Result<usize, Errno> {
        if handle != STANDARD_INPUT {
            return Err(Errno::EBADF);
        }
        self.input.read(buffer).map_err(|error| Errno::from(&error))
    }

    fn write(&mut self, handle: u64, bytes: &[u8]) -> Result<usize, Errno> {
        let written = match handle {
            STANDARD_OUTPUT => self.output.write(bytes),
            STANDARD_ERROR => self.error.write(bytes),
            _ => return Err(Errno::EBADF),
        };
        written.map_err(|error| Errno::from(&error))
    }
}
