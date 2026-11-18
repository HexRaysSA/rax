//! What a run may reach outside the guest program.
//!
//! The interpreter implements the runtime services itself: it validates the
//! arguments and every guest buffer, and only then asks the [`Host`] for the
//! effect, with host-owned byte slices. No guest pointer reaches a host.

use std::io::{ErrorKind, Read, Write};
use std::sync::OnceLock;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::ir::HostImport;

use super::foreign::Foreign;

/// A portable error number: the status a service returns when it fails.
///
/// The numbers are those of `errno-v1.json`, which pins the Linux values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Errno(u32);

impl Errno {
    pub const ENOENT: Self = Self(2);
    pub const EINTR: Self = Self(4);
    pub const EIO: Self = Self(5);
    pub const EBADF: Self = Self(9);
    pub const EAGAIN: Self = Self(11);
    pub const ENOMEM: Self = Self(12);
    pub const EACCES: Self = Self(13);
    pub const EEXIST: Self = Self(17);
    pub const ENOTDIR: Self = Self(20);
    pub const EISDIR: Self = Self(21);
    pub const EINVAL: Self = Self(22);
    pub const EFBIG: Self = Self(27);
    pub const ENOSPC: Self = Self(28);
    pub const ESPIPE: Self = Self(29);
    pub const EROFS: Self = Self(30);
    pub const EPIPE: Self = Self(32);
    pub const EDEADLK: Self = Self(35);
    pub const ENAMETOOLONG: Self = Self(36);
    pub const ENOTEMPTY: Self = Self(39);
    pub const EILSEQ: Self = Self(84);
    pub const ETIMEDOUT: Self = Self(110);

    /// The status value, which is never zero.
    pub fn code(self) -> u32 {
        self.0
    }
}

impl From<&std::io::Error> for Errno {
    /// An error with no portable counterpart is reported as `EIO`.
    fn from(error: &std::io::Error) -> Self {
        match error.kind() {
            ErrorKind::NotFound => Self::ENOENT,
            ErrorKind::Interrupted => Self::EINTR,
            ErrorKind::WouldBlock => Self::EAGAIN,
            ErrorKind::PermissionDenied => Self::EACCES,
            ErrorKind::AlreadyExists => Self::EEXIST,
            ErrorKind::NotADirectory => Self::ENOTDIR,
            ErrorKind::IsADirectory => Self::EISDIR,
            ErrorKind::InvalidInput | ErrorKind::InvalidFilename => Self::EINVAL,
            ErrorKind::FileTooLarge => Self::EFBIG,
            ErrorKind::StorageFull => Self::ENOSPC,
            ErrorKind::NotSeekable => Self::ESPIPE,
            ErrorKind::ReadOnlyFilesystem => Self::EROFS,
            ErrorKind::BrokenPipe => Self::EPIPE,
            ErrorKind::DirectoryNotEmpty => Self::ENOTEMPTY,
            _ => Self::EIO,
        }
    }
}

/// The clocks of the `clock` services, by their identifiers in the catalog.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Clock {
    /// Time since an arbitrary start; never goes back.
    Monotonic,
    /// Time since the Unix epoch, without leap seconds.
    Utc,
    /// Processor time the program has used.
    ProcessCpu,
    /// Processor time the calling thread has used.
    ThreadCpu,
}

/// How `file.open` opens a file: for reading, writing or both; whether the
/// file is made if there is none, emptied if there is one, and whether every
/// write goes to its end.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OpenFlags {
    pub read: bool,
    pub write: bool,
    pub create: bool,
    pub truncate: bool,
    pub append: bool,
}

impl OpenFlags {
    /// The flags of the service's `flags` argument: bit 0 read, bit 1
    /// write, bit 2 create, bit 3 truncate, bit 4 append. A file is opened
    /// for reading or writing at least, and is emptied or appended to only
    /// if it is written; anything else is `None`.
    pub fn from_bits(bits: u64) -> Option<Self> {
        let valid = bits & !31 == 0 && bits & 3 != 0 && (bits & 24 == 0 || bits & 2 != 0);
        valid.then_some(Self {
            read: bits & 1 != 0,
            write: bits & 2 != 0,
            create: bits & 4 != 0,
            truncate: bits & 8 != 0,
            append: bits & 16 != 0,
        })
    }
}

/// What the offset of `file.seek` counts from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Whence {
    Start,
    Current,
    End,
}

/// The embedder's side of the runtime services.
///
/// A program's threads run on host threads of their own and share the host,
/// one call at a time, so a host can be sent to another thread. Threads and
/// waiting need nothing from a host but the grant of the `thread` and `sync`
/// capabilities.
///
/// A host has files only if it implements the methods for them; the
/// defaults are those of a host whose file namespace is empty and cannot be
/// written. A path is the guest's: a string of names separated by `/`, which
/// the host interprets in the namespace it gives the program, never as a
/// path of the machine.
pub trait Host: Send {
    /// Whether the program is granted `capability`. A module runs only if
    /// every capability it declares is granted.
    fn grants(&self, capability: &str) -> bool;

    /// Whether the host has the function a module imports from it: the one
    /// registered under the identity of the descriptor the import quotes,
    /// which says what it takes and returns. A module runs only if its host
    /// has every function it imports. A host has none unless it says so.
    fn provides(&self, _import: &HostImport) -> bool {
        false
    }

    /// Call the host function `import` with the bits of its arguments, and
    /// return the bits of its results, each within the width of its type.
    /// An error says that the host failed; the function's results have no
    /// room for that, so the program ends there, with the trap `host_call`.
    fn call(&mut self, _import: &HostImport, _arguments: &[u128]) -> Result<Vec<u128>, Errno> {
        Err(Errno::EIO)
    }

    /// The processor for the program's foreign code, if the host has one:
    /// handed over when a process starts, once, to be the process's own
    /// until it ends. A module with bridges to foreign code runs only under
    /// a host that has a processor of the module's kind with the images
    /// the bridges name, and that grants `foreign`.
    fn foreign(&mut self) -> Option<Box<dyn Foreign>> {
        None
    }

    /// Read up to `buffer.len()` bytes from `handle` and return how many were
    /// read; zero is end of input.
    fn read(&mut self, handle: u64, buffer: &mut [u8]) -> Result<usize, Errno>;

    /// Write a prefix of `bytes` to `handle` and return its length.
    fn write(&mut self, handle: u64, bytes: &[u8]) -> Result<usize, Errno>;

    /// The reading of `clock`, in nanoseconds.
    fn now(&mut self, clock: Clock) -> Result<u64, Errno>;

    /// Open the file `path` names and return a handle for it, which no
    /// other open file has or had. `mode` is the permissions of a file this
    /// makes.
    fn open(&mut self, _path: &str, flags: OpenFlags, _mode: u32) -> Result<u64, Errno> {
        Err(if flags.create {
            Errno::EROFS
        } else {
            Errno::ENOENT
        })
    }

    /// Close `handle`, which is then no handle.
    fn close(&mut self, _handle: u64) -> Result<(), Errno> {
        Err(Errno::EBADF)
    }

    /// Move the position of `handle` and return it, counted from the start.
    fn seek(&mut self, _handle: u64, _offset: i64, _whence: Whence) -> Result<u64, Errno> {
        Err(Errno::EBADF)
    }

    /// Remove the name `path` of a file.
    fn unlink(&mut self, _path: &str) -> Result<(), Errno> {
        Err(Errno::ENOENT)
    }

    /// Give the file `from` names the name `to`, in place of any file that
    /// has it.
    fn rename(&mut self, _from: &str, _to: &str) -> Result<(), Errno> {
        Err(Errno::ENOENT)
    }
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

    fn now(&mut self, _clock: Clock) -> Result<u64, Errno> {
        Err(Errno::EINVAL)
    }
}

/// The handle of the standard input stream.
pub const STANDARD_INPUT: u64 = 0;
/// The handle of the standard output stream.
pub const STANDARD_OUTPUT: u64 = 1;
/// The handle of the standard error stream.
pub const STANDARD_ERROR: u64 = 2;

/// A host with the three standard streams and the host's clocks.
///
/// It grants the `file` capability, for those three handles only, the
/// `process` capability, which lets the program end itself, the `clock`
/// capability, the `thread` and `sync` capabilities, which let it start
/// threads and wait for them, and the `memory` capability, which lets it
/// map memory within the run's limit. The two processor-time clocks read the time since the first
/// reading of any clock in this process: an interpreted program's processor
/// time is the time it has been running.
#[derive(Debug)]
pub struct StandardStreams<I, O, E> {
    pub input: I,
    pub output: O,
    pub error: E,
}

impl<I: Read + Send, O: Write + Send, E: Write + Send> Host for StandardStreams<I, O, E> {
    fn grants(&self, capability: &str) -> bool {
        matches!(
            capability,
            "clock" | "file" | "memory" | "process" | "sync" | "thread"
        )
    }

    fn now(&mut self, clock: Clock) -> Result<u64, Errno> {
        static START: OnceLock<Instant> = OnceLock::new();
        let elapsed = match clock {
            Clock::Utc => SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| Errno::EINVAL)?,
            Clock::Monotonic | Clock::ProcessCpu | Clock::ThreadCpu => {
                START.get_or_init(Instant::now).elapsed()
            }
        };
        u64::try_from(elapsed.as_nanos()).map_err(|_| Errno::EINVAL)
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

    /// A stream has no position.
    fn seek(&mut self, handle: u64, _offset: i64, _whence: Whence) -> Result<u64, Errno> {
        Err(if handle <= STANDARD_ERROR {
            Errno::ESPIPE
        } else {
            Errno::EBADF
        })
    }
}
