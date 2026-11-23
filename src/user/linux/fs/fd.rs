//! File descriptions and descriptor tables.
//!
//! An [`OpenFile`] is a Linux *open file description*: it owns the host
//! object, the status flags (`O_APPEND`, `O_NONBLOCK`, ...), and the file
//! position. Descriptors created by `dup` share one description; the
//! close-on-exec flag belongs to the descriptor. This mirrors
//! `include/linux/fdtable.h`.

use crate::user::supplied_fs::Device;
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::{Arc, Mutex, MutexGuard};

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::abi::open::*;

mod mapping;
mod pipe;

pub use pipe::PipeEnd;
pub(crate) use pipe::PipeWait;

/// A directory entry captured for `getdents64`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry {
    /// Inode number.
    pub ino: u64,
    /// `DT_*` type.
    pub dtype: u8,
    /// Name bytes.
    pub name: Vec<u8>,
}

/// `DT_*` directory-entry types (`include/linux/fs_types.h` values shared by
/// `dirent.h`).
pub mod dt {
    /// Unknown.
    pub const DT_UNKNOWN: u8 = 0;
    /// FIFO.
    pub const DT_FIFO: u8 = 1;
    /// Character device.
    pub const DT_CHR: u8 = 2;
    /// Directory.
    pub const DT_DIR: u8 = 4;
    /// Block device.
    pub const DT_BLK: u8 = 6;
    /// Regular file.
    pub const DT_REG: u8 = 8;
    /// Symbolic link.
    pub const DT_LNK: u8 = 10;
    /// Socket.
    pub const DT_SOCK: u8 = 12;
}

/// The object behind an open file description.
pub enum FileObject {
    /// A host file, directory, or device.
    Host(std::fs::File),
    /// Bounded embedded stream. `None` is finite stdin; outputs are write-only.
    /// No host descriptor is held, including after `dup` or `fork`.
    Console {
        console: crate::user::console::CapturedConsole,
        stream: Option<crate::user::console::OutputStream>,
    },
    /// The read end of a pipe.
    PipeRead(std::io::PipeReader),
    /// The write end of a pipe.
    PipeWrite(std::io::PipeWriter),
    /// One end of an anonymous pipe with guest-owned storage.
    GuestPipe(PipeEnd),
    /// Synthesized read-only content (`/proc` files and directories).
    Synthetic(Arc<[u8]>),
    /// Guest namespace entry, including demand-read selected backing and the
    /// synthetic null device. No ordinary guest descriptor exposes a host handle.
    Supplied(crate::user::supplied_fs::Entry),
    /// An `O_PATH` reference: identifies a file without I/O capability.
    PathOnly,
    /// An anonymous-inode object (`eventfd`, `timerfd`, `signalfd`),
    /// whose I/O the system calls perform.
    Anon(super::anon::Anon),
    /// A socket, whose transfers the socket calls perform.
    #[cfg(unix)]
    Socket(super::super::net::Socket),
    /// A POSIX message queue (`ipc/mqueue.c`).
    Mqueue(super::super::ipc::mqueue::Handle),
}

/// What kind of file an open description refers to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileType {
    /// Regular file.
    Regular,
    /// Directory.
    Directory,
    /// Character device (terminals, `/dev/null`, ...).
    CharDevice,
    /// Block device.
    BlockDevice,
    /// Pipe or FIFO.
    Fifo,
    /// Socket.
    Socket,
    /// Symbolic link (`O_PATH | O_NOFOLLOW` only).
    Symlink,
    /// An anonymous inode: no file type (`alloc_anon_inode`).
    Anon,
}

/// Mutable state of an open file description.
#[derive(Debug, Default)]
pub struct FileState {
    /// Status flags that `F_GETFL`/`F_SETFL` manage, plus the access mode.
    pub flags: u32,
    /// Directory listing snapshot and cursor for `getdents64`.
    pub dir: Option<(Vec<DirEntry>, usize)>,
    /// Position within synthetic content, or before a guest directory snapshot.
    pub synth_pos: u64,
    /// The thread whose `/proc` `comm` file this description writes.
    pub comm_of: Option<i32>,
    /// Lazily allocated for an OFD lock on a private workspace inode.
    pub(crate) workspace_lock_owner: Option<Box<super::locks::workspace::LockOwner>>,
}

/// An `epoll` item watching a description: its instance and item.
#[derive(Clone, Debug)]
pub struct Watch {
    /// The instance's description.
    pub ep: std::sync::Weak<OpenFile>,
    /// The item.
    pub id: u64,
}

/// A Linux open file description.
pub struct OpenFile {
    /// The underlying object.
    pub object: FileObject,
    /// File type.
    pub ftype: FileType,
    /// Guest path the file was opened by (for `/proc/self/fd/N`).
    pub path: String,
    /// Host path, when the object came from the host file system.
    pub host_path: Option<std::path::PathBuf>,
    /// Immutable metadata for a caller-supplied file or inferred directory.
    pub supplied_stat: Option<super::super::abi::types::Stat>,
    /// Mutable state.
    pub state: Mutex<FileState>,
    /// The other end of a pipe the guest created, whose readers or writers
    /// a transfer here wakes.
    pub peer: Mutex<std::sync::Weak<OpenFile>>,
    /// The `epoll` items watching this description (its wait queue).
    pub watchers: Mutex<Vec<Watch>>,
    /// The inode state of a `memfd` (its seals).
    pub memfd: Option<Arc<super::memfd::Memfd>>,
    /// Independent position for a reopened anonymous host file.
    #[cfg(unix)]
    pub(crate) reopen_cursor: Option<super::reopen::Cursor>,
    /// What reports file-system events on the file, and its close when it
    /// and its mappings are gone (the emulated notification backend).
    #[cfg(unix)]
    pub notify: std::sync::OnceLock<Arc<super::super::fsnotify::hub::Token>>,
}

impl Drop for OpenFile {
    /// The last descriptor of a pipe end is closed: the other end's
    /// readers see a hang-up, its writers an error (`pipe_release`).
    fn drop(&mut self) {
        // Dropping the owned host descriptor releases this process's POSIX
        // locks too. Retire its bookkeeping and kept mapping descriptors
        // before the file closes, including teardown without a guest close.
        #[cfg(unix)]
        super::locks::filp_close(self);
        match self.object {
            FileObject::PipeWrite(_) => self.wake_peer(0x010),
            FileObject::PipeRead(_) => self.wake_peer(0x008),
            FileObject::GuestPipe(ref end) => self.wake_peer(end.close()),
            _ => {}
        }
    }
}

impl std::fmt::Debug for OpenFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenFile")
            .field("path", &self.path)
            .field("ftype", &self.ftype)
            .finish_non_exhaustive()
    }
}

impl OpenFile {
    /// Whether this open description is a socket. Native sockets are part of
    /// the Unix host-service profile; closed embedding cannot create them.
    pub fn is_socket(&self) -> bool {
        match &self.object {
            #[cfg(unix)]
            FileObject::Socket(_) => true,
            _ => false,
        }
    }

    /// Creates a description with status `flags`.
    pub fn new(
        object: FileObject,
        ftype: FileType,
        path: impl Into<String>,
        host_path: Option<std::path::PathBuf>,
        flags: u32,
    ) -> Arc<Self> {
        Self::with_memfd(object, ftype, path, host_path, flags, None)
    }

    /// Creates a description of a `memfd` (`memfd` set) or of any other
    /// file.
    pub fn with_memfd(
        object: FileObject,
        ftype: FileType,
        path: impl Into<String>,
        host_path: Option<std::path::PathBuf>,
        flags: u32,
        memfd: Option<Arc<super::memfd::Memfd>>,
    ) -> Arc<Self> {
        Arc::new(OpenFile {
            object,
            ftype,
            path: path.into(),
            host_path,
            supplied_stat: None,
            state: Mutex::new(FileState {
                flags,
                ..Default::default()
            }),
            peer: Mutex::new(std::sync::Weak::new()),
            watchers: Mutex::new(Vec::new()),
            memfd,
            #[cfg(unix)]
            reopen_cursor: None,
            #[cfg(unix)]
            notify: std::sync::OnceLock::new(),
        })
    }

    /// The bytes of a write of `data` at `pos` (the position when `None`)
    /// a `memfd`'s seals allow.
    fn sealed_len(&self, f: &std::fs::File, pos: Option<u64>, len: usize) -> Result<usize, Errno> {
        let Some(m) = &self.memfd else {
            return Ok(len);
        };
        let pos = match pos {
            Some(p) => p,
            None => (&*f).stream_position()?,
        };
        m.write_len(pos, len, f.metadata()?.len())
    }

    /// Registers an `epoll` item as a watcher (`ep_ptable_queue_proc`).
    pub fn watch(&self, w: Watch) {
        self.watchers.lock().unwrap().push(w);
    }

    /// A wake-up of the description's waiters with the events `key`
    /// (`wake_up_poll`): each watching `epoll` item that wants one of them
    /// joins its instance's ready list (`ep_poll_callback`).
    pub fn woke(&self, key: u32) {
        let watchers: Vec<Watch> = {
            let mut w = self.watchers.lock().unwrap();
            w.retain(|x| x.ep.strong_count() > 0);
            w.clone()
        };
        for w in watchers {
            if let Some(ep) = w.ep.upgrade()
                && let FileObject::Anon(super::anon::Anon::Epoll(inst)) = &ep.object
                && inst.callback(w.id, self, key)
            {
                // The instance became readable: its own watchers wake.
                ep.woke(0x001 | 0x040);
            }
        }
    }

    /// Wakes the other end of a pipe with `key`.
    fn wake_peer(&self, key: u32) {
        let peer = self.peer.lock().unwrap().upgrade();
        if let Some(p) = peer {
            p.woke(key);
        }
    }

    /// Status flags.
    pub fn flags(&self) -> u32 {
        self.state.lock().unwrap().flags
    }

    /// The access mode (`O_RDONLY`, `O_WRONLY`, `O_RDWR`).
    pub fn access_mode(&self) -> u32 {
        self.flags() & O_ACCMODE
    }

    pub(crate) fn device(&self) -> Option<Device> {
        match &self.object {
            FileObject::Supplied(entry) => entry.device(),
            _ => None,
        }
    }

    /// Whether the description permits reading.
    pub fn readable(&self) -> bool {
        let flags = self.flags();
        let access = flags & O_ACCMODE;
        flags & O_PATH == 0
            && access != O_WRONLY
            && (access != O_ACCMODE || self.device().is_none())
    }

    /// Whether the description permits writing.
    pub fn writable(&self) -> bool {
        let flags = self.flags();
        let access = flags & O_ACCMODE;
        flags & O_PATH == 0
            && access != O_RDONLY
            && (access != O_ACCMODE || self.device().is_none())
    }

    /// `read(2)` at the current position.
    pub fn read(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        if !self.readable() {
            return Err(Errno(EBADF));
        }
        if self.ftype == FileType::Directory {
            return Err(Errno(EISDIR));
        }
        match &self.object {
            FileObject::Host(f) => {
                #[cfg(unix)]
                if let Some(cursor) = &self.reopen_cursor {
                    return cursor.read(f, buf);
                }
                Ok((&*f).read(buf)?)
            }
            FileObject::Console {
                console,
                stream: None,
            } => Ok(crate::user::console::Console::Captured(console.clone()).read(buf)?),
            FileObject::Console { .. } => Err(Errno(EBADF)),
            FileObject::PipeRead(p) => {
                let n = (&*p).read(buf)?;
                // Room for writers (EPOLLOUT | EPOLLWRNORM).
                self.wake_peer(0x004 | 0x100);
                Ok(n)
            }
            FileObject::GuestPipe(end) => {
                let n = end.read(buf)?;
                if n != 0 {
                    self.wake_peer(0x004 | 0x100);
                }
                Ok(n)
            }
            FileObject::PipeWrite(_) | FileObject::PathOnly => Err(Errno(EBADF)),
            FileObject::Anon(_) => Err(Errno(EINVAL)),
            #[cfg(unix)]
            FileObject::Socket(s) => Ok((&s.file).read(buf)?),
            FileObject::Supplied(entry) => {
                if let Some(device) = entry.device() {
                    return device.read_constant(buf).ok_or(Errno(EOPNOTSUPP));
                }
                let mut st = self.state.lock().unwrap();
                let n = entry.source()?.read_at(st.synth_pos, buf)?;
                st.synth_pos = st.synth_pos.checked_add(n as u64).ok_or(Errno(EOVERFLOW))?;
                Ok(n)
            }
            FileObject::Synthetic(data) => {
                let mut st = self.state.lock().unwrap();
                let pos = st.synth_pos.min(data.len() as u64) as usize;
                let n = buf.len().min(data.len() - pos);
                buf[..n].copy_from_slice(&data[pos..pos + n]);
                st.synth_pos += n as u64;
                Ok(n)
            }
            FileObject::Mqueue(h) => {
                let pos = self.state.lock().unwrap().synth_pos;
                let n = self.mq_status(h, buf, pos)?;
                self.state.lock().unwrap().synth_pos = pos + n as u64;
                Ok(n)
            }
        }
    }

    /// Whether the description was opened for reading and for writing
    /// (`FMODE_READ`, `FMODE_WRITE`): access mode 3 gives neither.
    pub fn fmode(&self) -> (bool, bool) {
        match self.access_mode() {
            O_RDONLY => (true, false),
            O_WRONLY => (false, true),
            O_RDWR => (true, true),
            _ => (false, false),
        }
    }

    /// A queue file's contents from `pos` (`mqueue_read_file`: its status
    /// line), marking the queue accessed and changed when anything is read.
    fn mq_status(
        &self,
        h: &super::super::ipc::mqueue::Handle,
        buf: &mut [u8],
        pos: u64,
    ) -> Result<usize, Errno> {
        if !self.fmode().0 {
            return Err(Errno(EBADF));
        }
        h.with(|q| {
            let text = q.status().into_bytes();
            let at = pos.min(text.len() as u64) as usize;
            let n = buf.len().min(text.len() - at);
            buf[..n].copy_from_slice(&text[at..at + n]);
            if n > 0 {
                let (sec, nsec) =
                    super::super::host::clock_gettime(super::super::host::HostClock::Realtime);
                q.touch(1 | 4, (sec, nsec));
            }
            Ok(n)
        })
    }

    /// `write(2)` at the current position (or at end of file with
    /// `O_APPEND`).
    pub fn write(&self, data: &[u8]) -> Result<usize, Errno> {
        if !self.writable() {
            return Err(Errno(EBADF));
        }
        match &self.object {
            FileObject::Console {
                console,
                stream: Some(stream),
            } => {
                crate::user::console::Console::Captured(console.clone())
                    .write_all(*stream, data)?;
                Ok(data.len())
            }
            FileObject::Console { .. } => Err(Errno(EBADF)),
            FileObject::Host(f) => {
                #[cfg(unix)]
                if let Some(cursor) = &self.reopen_cursor {
                    return cursor.write(f, data, self.flags() & O_APPEND != 0, |pos, len| {
                        self.sealed_len(f, Some(pos), len)
                    });
                }
                if self.flags() & O_APPEND != 0 && self.ftype == FileType::Regular {
                    (&*f).seek(SeekFrom::End(0))?;
                }
                let n = self.sealed_len(f, None, data.len())?;
                Ok((&*f).write(&data[..n])?)
            }
            FileObject::PipeWrite(p) => {
                let n = (&*p).write(data)?;
                // Data for readers (EPOLLIN | EPOLLRDNORM).
                self.wake_peer(0x001 | 0x040);
                Ok(n)
            }
            FileObject::GuestPipe(end) => {
                let n = end.write(data, self.flags() & end.packet_flag() != 0)?;
                if n != 0 {
                    self.wake_peer(0x001 | 0x040);
                }
                Ok(n)
            }
            FileObject::PipeRead(_) | FileObject::PathOnly => Err(Errno(EBADF)),
            FileObject::Supplied(entry) if entry.device().is_some() => Ok(data.len()),
            FileObject::Supplied(entry) if entry.workspace_file().is_some() => {
                let file = entry.workspace_file().expect("checked workspace file");
                let mut state = self.state.lock().unwrap();
                if !data.is_empty() {
                    let offset = (state.flags & O_APPEND == 0).then_some(state.synth_pos);
                    state.synth_pos = file.write(offset, data)?;
                }
                Ok(data.len())
            }
            FileObject::Synthetic(_) | FileObject::Supplied(_) => Err(Errno(EACCES)),
            FileObject::Anon(_) => Err(Errno(EINVAL)),
            #[cfg(unix)]
            FileObject::Socket(s) => Ok((&s.file).write(data)?),
            // No write operation (FMODE_CAN_WRITE is clear).
            FileObject::Mqueue(_) if !self.fmode().1 => Err(Errno(EBADF)),
            FileObject::Mqueue(_) => Err(Errno(EINVAL)),
        }
    }

    /// `pread64`.
    pub fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<usize, Errno> {
        if !self.readable() {
            return Err(Errno(EBADF));
        }
        if self.ftype == FileType::Directory {
            return Err(Errno(EISDIR));
        }
        match &self.object {
            #[cfg(not(unix))]
            FileObject::Host(_) => Err(Errno(EPERM)),
            #[cfg(unix)]
            FileObject::Host(f) if self.ftype == FileType::Regular => {
                use std::os::unix::fs::FileExt;
                Ok(f.read_at(buf, offset)?)
            }
            FileObject::Host(_) if self.ftype == FileType::Directory => Err(Errno(EISDIR)),
            FileObject::Supplied(entry) => match entry.device() {
                Some(device) => device.read_constant(buf).ok_or(Errno(EOPNOTSUPP)),
                None => Ok(entry.source()?.read_at(offset, buf)?),
            },
            FileObject::Synthetic(data) => {
                let pos = offset.min(data.len() as u64) as usize;
                let n = buf.len().min(data.len() - pos);
                buf[..n].copy_from_slice(&data[pos..pos + n]);
                Ok(n)
            }
            FileObject::Mqueue(h) => self.mq_status(h, buf, offset),
            FileObject::PathOnly => Err(Errno(EBADF)),
            _ => Err(Errno(ESPIPE)),
        }
    }

    /// `pwrite64`. Linux ignores `O_APPEND` positioning here only for
    /// non-append files; with `O_APPEND` the data goes to the end.
    pub fn write_at(&self, data: &[u8], offset: u64) -> Result<usize, Errno> {
        if !self.writable() {
            return Err(Errno(EBADF));
        }
        match &self.object {
            #[cfg(not(unix))]
            FileObject::Host(_) => Err(Errno(EPERM)),
            #[cfg(unix)]
            FileObject::Host(f) if self.ftype == FileType::Regular => {
                use std::os::unix::fs::FileExt;
                if self.flags() & O_APPEND != 0 {
                    (&*f).seek(SeekFrom::End(0))?;
                    let n = self.sealed_len(f, None, data.len())?;
                    return Ok((&*f).write(&data[..n])?);
                }
                let n = self.sealed_len(f, Some(offset), data.len())?;
                Ok(f.write_at(&data[..n], offset)?)
            }
            FileObject::Supplied(entry) if entry.device().is_some() => Ok(data.len()),
            FileObject::Supplied(entry) if entry.workspace_file().is_some() => {
                let file = entry.workspace_file().expect("checked workspace file");
                file.write((self.flags() & O_APPEND == 0).then_some(offset), data)?;
                Ok(data.len())
            }
            FileObject::Synthetic(_) | FileObject::Supplied(_) => Err(Errno(EACCES)),
            FileObject::Mqueue(_) if !self.fmode().1 => Err(Errno(EBADF)),
            FileObject::Mqueue(_) => Err(Errno(EINVAL)),
            FileObject::PathOnly => Err(Errno(EBADF)),
            _ => Err(Errno(ESPIPE)),
        }
    }

    /// `lseek`.
    pub fn seek(&self, offset: i64, whence: u32) -> Result<u64, Errno> {
        const SEEK_SET: u32 = 0;
        const SEEK_CUR: u32 = 1;
        const SEEK_END: u32 = 2;
        if self.flags() & O_PATH != 0 {
            return Err(Errno(EBADF));
        }
        match &self.object {
            FileObject::Host(f)
                if matches!(self.ftype, FileType::Regular | FileType::BlockDevice) =>
            {
                #[cfg(unix)]
                if let Some(cursor) = &self.reopen_cursor {
                    return cursor.seek(f, offset, whence);
                }
                let pos = match whence {
                    SEEK_SET => {
                        if offset < 0 {
                            return Err(Errno(EINVAL));
                        }
                        SeekFrom::Start(offset as u64)
                    }
                    SEEK_CUR => SeekFrom::Current(offset),
                    SEEK_END => SeekFrom::End(offset),
                    _ => return Err(Errno(EINVAL)),
                };
                Ok((&*f).seek(pos)?)
            }
            FileObject::Host(_) | FileObject::Synthetic(_) | FileObject::Supplied(_)
                if self.ftype == FileType::Directory =>
            {
                // Directories support rewinding and absolute cursor positions
                // (the d_off values getdents64 returned).
                let workspace = matches!(&self.object, FileObject::Supplied(entry) if entry.workspace_directory().is_some());
                let mut st = self.state.lock().unwrap();
                let base = match whence {
                    SEEK_SET => 0i64,
                    SEEK_CUR => st.dir.as_ref().map_or(st.synth_pos as i64, |d| d.1 as i64),
                    _ => return Err(Errno(EINVAL)),
                };
                let target = base
                    .checked_add(offset)
                    .filter(|t| *t >= 0)
                    .ok_or(Errno(EINVAL))?;
                if target == 0 && (self.host_path.is_some() || workspace) {
                    st.dir = None;
                    st.synth_pos = 0;
                } else if let Some(d) = st.dir.as_mut() {
                    d.1 = (target as usize).min(d.0.len());
                } else if workspace {
                    st.synth_pos = target as u64;
                }
                Ok(target as u64)
            }
            // pidfs and io_uring have no llseek operation.
            FileObject::Anon(super::anon::Anon::Pid(_) | super::anon::Anon::Uring(_)) => {
                Err(Errno(ESPIPE))
            }
            // default_llseek, against the queue file's size.
            FileObject::Mqueue(h) => {
                const SEEK_DATA: u32 = 3;
                const SEEK_HOLE: u32 = 4;
                let size = h.get()?.size;
                let mut st = self.state.lock().unwrap();
                let target = match whence {
                    SEEK_SET => Some(offset),
                    SEEK_CUR => (st.synth_pos as i64).checked_add(offset),
                    SEEK_END => size.checked_add(offset),
                    SEEK_DATA if offset >= size => return Err(Errno(ENXIO)),
                    SEEK_DATA => Some(offset),
                    SEEK_HOLE if offset >= size => return Err(Errno(ENXIO)),
                    SEEK_HOLE => Some(size),
                    _ => return Err(Errno(EINVAL)),
                };
                let target = target.filter(|t| *t >= 0).ok_or(Errno(EINVAL))?;
                st.synth_pos = target as u64;
                Ok(target as u64)
            }
            // noop_llseek: the position stays 0.
            FileObject::Anon(_) => Ok(0),
            FileObject::Supplied(entry) if entry.device().is_some() => {
                // null_lseek resets the position for every valid seek origin.
                if whence <= 4 {
                    Ok(0)
                } else {
                    Err(Errno(EINVAL))
                }
            }
            FileObject::Supplied(entry) => {
                let mut st = self.state.lock().unwrap();
                let base = match whence {
                    SEEK_SET => 0,
                    SEEK_CUR => i64::try_from(st.synth_pos).map_err(|_| Errno(EOVERFLOW))?,
                    SEEK_END => i64::try_from(entry.len()).map_err(|_| Errno(EOVERFLOW))?,
                    _ => return Err(Errno(EINVAL)),
                };
                let target = base
                    .checked_add(offset)
                    .filter(|t| *t >= 0)
                    .ok_or(Errno(EINVAL))?;
                st.synth_pos = target as u64;
                Ok(st.synth_pos)
            }
            FileObject::Synthetic(data) => {
                let mut st = self.state.lock().unwrap();
                let base = match whence {
                    SEEK_SET => 0i64,
                    SEEK_CUR => st.synth_pos as i64,
                    SEEK_END => data.len() as i64,
                    _ => return Err(Errno(EINVAL)),
                };
                let target = base
                    .checked_add(offset)
                    .filter(|t| *t >= 0)
                    .ok_or(Errno(EINVAL))?;
                st.synth_pos = target as u64;
                Ok(target as u64)
            }
            _ => Err(Errno(ESPIPE)),
        }
    }

    /// The host file, if the description wraps one.
    pub fn host_file(&self) -> Option<&std::fs::File> {
        match &self.object {
            FileObject::Host(f) => Some(f),
            _ => None,
        }
    }
}

/// `filp_close`'s file-specific work as a descriptor of `file` closes:
/// `locks_remove_posix`, and a message queue's `flush` (its notification
/// dropped if this process registered it).
fn filp_close(file: &OpenFile) {
    #[cfg(unix)]
    super::locks::filp_close(file);
    if let FileObject::Mqueue(h) = &file.object {
        super::super::syscall::mqueue::flush(h, super::super::host::pid());
    }
}

/// One descriptor-table slot.
#[derive(Clone, Debug)]
pub struct Fd {
    /// The shared open file description.
    pub file: Arc<OpenFile>,
    /// `FD_CLOEXEC`.
    pub cloexec: bool,
}

/// Default `RLIMIT_NOFILE` soft limit.
pub const NOFILE_SOFT: u64 = 1024;
/// Default `RLIMIT_NOFILE` hard limit (`nr_open` default is 1 << 20; the
/// usual distribution hard limit is 4096 or higher).
pub const NOFILE_HARD: u64 = 1 << 20;

/// A Linux descriptor table. Fork copies the slots. CLONE_FILES shares them.
#[derive(Debug, Default)]
pub struct FdTable {
    slots: Arc<Mutex<Vec<Option<Fd>>>>,
    pipes: Arc<pipe::PipePool>,
    pub(crate) workspace_lock_owner: Arc<super::locks::workspace::LockOwner>,
}

impl Clone for FdTable {
    fn clone(&self) -> Self {
        Self {
            slots: Arc::new(Mutex::new(self.slots().clone())),
            pipes: Arc::clone(&self.pipes),
            workspace_lock_owner: Arc::new(self.workspace_lock_owner.independent()),
        }
    }
}

impl FdTable {
    fn slots(&self) -> MutexGuard<'_, Vec<Option<Fd>>> {
        self.slots.lock().expect("descriptor table lock poisoned")
    }

    pub(in crate::user::linux) fn share(&self) -> Self {
        Self {
            slots: Arc::clone(&self.slots),
            pipes: Arc::clone(&self.pipes),
            workspace_lock_owner: self.workspace_lock_owner.clone(),
        }
    }

    pub(in crate::user::linux) fn is_shared(&self) -> bool {
        Arc::strong_count(&self.slots) > 1
    }

    pub(in crate::user::linux) fn unshare(&mut self) {
        if self.is_shared() {
            *self = self.clone();
        }
    }

    /// An empty table.
    pub fn new() -> Self {
        FdTable::default()
    }

    pub(crate) fn open_pipe(
        &self,
        status: u32,
        packet_flag: u32,
        owner: (u32, u32),
    ) -> Result<(Arc<OpenFile>, Arc<OpenFile>), Errno> {
        self.pipes.open(status, packet_flag, owner)
    }

    /// The descriptor `fd`.
    pub fn get(&self, fd: i32) -> Result<Fd, Errno> {
        let index = usize::try_from(fd).map_err(|_| Errno(EBADF))?;
        self.slots()
            .get(index)
            .and_then(Option::as_ref)
            .cloned()
            .ok_or(Errno(EBADF))
    }

    /// Updates this slot's close-on-exec flag.
    pub fn set_cloexec(&mut self, fd: i32, enabled: bool) -> Result<(), Errno> {
        let index = usize::try_from(fd).map_err(|_| Errno(EBADF))?;
        let mut slots = self.slots();
        let entry = slots
            .get_mut(index)
            .and_then(Option::as_mut)
            .ok_or(Errno(EBADF))?;
        entry.cloexec = enabled;
        Ok(())
    }

    /// The open file behind `fd`.
    pub fn file(&self, fd: i32) -> Result<Arc<OpenFile>, Errno> {
        Ok(self.get(fd)?.file)
    }

    /// Installs `file` at the lowest free descriptor `>= min` below `limit`
    /// (`get_unused_fd_flags`/`F_DUPFD`); `EMFILE` when none is free.
    pub fn install_from(
        &mut self,
        min: usize,
        file: Arc<OpenFile>,
        cloexec: bool,
        limit: u64,
    ) -> Result<i32, Errno> {
        let limit = limit.min(i32::MAX as u64) as usize;
        if min >= limit {
            return Err(Errno(if min > i32::MAX as usize {
                EINVAL
            } else {
                EMFILE
            }));
        }
        let mut slots = self.slots();
        let fd = (min..limit)
            .find(|&i| slots.get(i).is_none_or(Option::is_none))
            .ok_or(Errno(EMFILE))?;
        if slots.len() <= fd {
            slots.resize(fd + 1, None);
        }
        slots[fd] = Some(Fd { file, cloexec });
        Ok(fd as i32)
    }

    /// The `n` lowest free descriptors below `limit` (`EMFILE` when there
    /// are fewer), for a call that reserves descriptors before it creates
    /// their files.
    pub fn free_fds(&self, n: usize, limit: u64) -> Result<Vec<i32>, Errno> {
        let limit = limit.min(i32::MAX as u64) as usize;
        let slots = self.slots();
        let free: Vec<i32> = (0..limit)
            .filter(|&i| slots.get(i).is_none_or(Option::is_none))
            .take(n)
            .map(|i| i as i32)
            .collect();
        if free.len() < n {
            return Err(Errno(EMFILE));
        }
        Ok(free)
    }

    /// Installs at the lowest free descriptor.
    pub fn install(
        &mut self,
        file: Arc<OpenFile>,
        cloexec: bool,
        limit: u64,
    ) -> Result<i32, Errno> {
        self.install_from(0, file, cloexec, limit)
    }

    /// Places `file` at exactly `fd`, closing what was there (`dup2`).
    pub fn install_at(
        &mut self,
        fd: i32,
        file: Arc<OpenFile>,
        cloexec: bool,
        limit: u64,
    ) -> Result<(), Errno> {
        if fd < 0 || fd as u64 >= limit {
            return Err(Errno(EBADF));
        }
        let fd = fd as usize;
        let previous = {
            let mut slots = self.slots();
            if slots.len() <= fd {
                slots.resize(fd + 1, None);
            }
            slots[fd].replace(Fd { file, cloexec })
        };
        if let Some(old) = previous {
            self.close_file(&old.file);
        }
        Ok(())
    }

    /// Closes `fd`.
    pub fn close(&mut self, fd: i32) -> Result<Fd, Errno> {
        if fd < 0 {
            return Err(Errno(EBADF));
        }
        let old = self
            .slots()
            .get_mut(fd as usize)
            .and_then(Option::take)
            .ok_or(Errno(EBADF))?;
        self.close_file(&old.file);
        Ok(old)
    }

    /// `fdt->max_fds`: the table holds `BITS_PER_LONG` (64) descriptors
    /// until one above that is allocated, then the smallest power of two
    /// covering the highest descriptor ever allocated (`alloc_fdtable`).
    pub fn max_fds(&self) -> usize {
        self.slots().len().max(64).next_power_of_two()
    }

    /// Descriptors currently open, ascending.
    pub fn open_fds(&self) -> Vec<i32> {
        self.slots()
            .iter()
            .enumerate()
            .filter(|(_, s)| s.is_some())
            .map(|(i, _)| i as i32)
            .collect()
    }

    /// Exec leaves a shared table before closing its close-on-exec descriptors.
    pub fn close_on_exec(&mut self) {
        self.unshare();
        let closed: Vec<Fd> = self
            .slots()
            .iter_mut()
            .filter(|slot| slot.as_ref().is_some_and(|fd| fd.cloexec))
            .filter_map(Option::take)
            .collect();
        for old in closed {
            self.close_file(&old.file);
        }
    }

    fn close_file(&self, file: &OpenFile) {
        if let Some(ino) = super::locks::workspace::inode(file) {
            self.workspace_lock_owner.close(ino);
        }
        filp_close(file);
    }
}
