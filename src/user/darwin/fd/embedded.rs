//! Descriptor storage for embedding. Duplicates share the open description's
//! cursor; positional reads do not change it. No operation opens a host file.

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

use super::{FdTable, FileKind, OpenFile};
use crate::user::console::{CapturedConsole, Console, OutputStream};
use crate::user::darwin::abi::Errno;
use crate::user::darwin::abi::types::Stat;
use crate::user::darwin::io::{O_ACCMODE, O_APPEND, O_RDONLY, O_WRONLY};
use crate::user::mm::{PageSource, SourceIdentity};
use crate::user::supplied_fs::{Device, Entry};

#[derive(Debug)]
pub enum EmbeddedFile {
    Supplied {
        entry: Entry,
        cursor: Mutex<u64>,
        access: u32,
    },
    Workspace {
        entry: Entry,
        cursor: Mutex<u64>,
        access: u32,
        append: AtomicBool,
    },
    Null {
        ino: u64,
        access: u32,
        cursor: Mutex<u64>,
    },
    Zero {
        ino: u64,
        access: u32,
        cursor: Mutex<u64>,
    },
    Pipe(super::pipe::PipeEnd),
    Input(CapturedConsole),
    Output(CapturedConsole, OutputStream),
}

impl EmbeddedFile {
    pub(crate) fn entry(&self) -> Option<&Entry> {
        match self {
            Self::Supplied { entry, .. } | Self::Workspace { entry, .. } => Some(entry),
            _ => None,
        }
    }

    pub(crate) fn workspace(&self) -> Option<(&crate::user::supplied_fs::WorkspaceFile, u32)> {
        match self {
            Self::Workspace { entry, access, .. } => Some((entry.workspace_file()?, *access)),
            _ => None,
        }
    }

    pub(crate) fn set_append(&self, flags: u32) {
        if let Self::Workspace { append, .. } = self {
            append.store(flags & O_APPEND != 0, Ordering::Relaxed);
        }
    }

    pub(crate) fn device_access(&self) -> Option<u32> {
        match self {
            Self::Null { access, .. } | Self::Zero { access, .. } => Some(*access),
            _ => None,
        }
    }

    /// Bytes available without consuming input or changing the file offset.
    pub fn available(&self) -> Result<u64, Errno> {
        match self {
            Self::Supplied { entry, cursor, .. } | Self::Workspace { entry, cursor, .. } => {
                if entry.is_dir() {
                    return Err(Errno::EISDIR);
                }
                Ok(entry
                    .len()
                    .saturating_sub(*cursor.lock().map_err(|_| Errno::EIO)?))
            }
            Self::Input(console) => Ok(console.pending()?.0 as u64),
            Self::Pipe(end) => Ok(end.available()),
            Self::Output(..) | Self::Null { .. } | Self::Zero { .. } => Ok(0),
        }
    }

    /// Virtual metadata. Supplied files are immutable, and guest-created
    /// files retain the mode and ownership of their creation.
    pub fn stat(&self) -> Result<Stat, Errno> {
        let (uid, gid) = self
            .entry()
            .and_then(Entry::workspace_owner)
            .unwrap_or((0, 0));
        let (ino, mode, size) = match self {
            Self::Supplied { entry, .. } | Self::Workspace { entry, .. } => {
                let permissions = entry.workspace_mode().unwrap_or(0o555) as u16;
                if entry.is_dir() {
                    (entry.ino, 0o040000 | permissions, 0)
                } else {
                    let mode = if entry.link_target().is_some() {
                        0o120000 | entry.workspace_mode().unwrap_or(0o755) as u16
                    } else {
                        0o100000 | permissions
                    };
                    (
                        entry.ino,
                        mode,
                        i64::try_from(entry.len()).map_err(|_| Errno::EOVERFLOW)?,
                    )
                }
            }
            Self::Input(_) => (1, 0o020444, 0),
            Self::Output(_, OutputStream::Stdout) => (2, 0o020222, 0),
            Self::Output(_, OutputStream::Stderr) => (3, 0o020222, 0),
            Self::Null { ino, .. } => return Ok(Self::device_stat(Device::Null, *ino)),
            Self::Zero { ino, .. } => return Ok(Self::device_stat(Device::Zero, *ino)),
            Self::Pipe(end) => return Ok(end.stat()),
        };
        Ok(Stat {
            dev: if self.entry().is_some() {
                0x524158
            } else {
                0x524159
            },
            ino,
            mode,
            size,
            uid,
            gid,
            nlink: self
                .entry()
                .and_then(Entry::workspace_directory)
                .map_or_else(
                    || {
                        self.entry()
                            .and_then(Entry::workspace_leaf_links)
                            .unwrap_or(1) as u16
                    },
                    |directory| {
                        directory.link_count(crate::user::supplied_fs::WorkspaceFlavor::Darwin)
                            as u16
                    },
                ),
            blksize: 4096,
            blocks: (size as u64).div_ceil(512) as i64,
            ..Default::default()
        })
    }

    pub(crate) fn device_stat(device: Device, ino: u64) -> Stat {
        Stat {
            dev: 0x524159,
            ino,
            mode: 0o020666,
            nlink: 1,
            rdev: match device {
                Device::Null => 0x0300_0002,
                Device::Zero => 0x0300_0003,
            },
            blksize: 65_536,
            ..Default::default()
        }
    }

    /// Transfer at most `out.len()` bytes. `offset` is a positional read;
    /// captured streams reject positional operations with `ESPIPE`.
    pub fn read(&self, out: &mut [u8], offset: Option<i64>) -> Result<usize, Errno> {
        match self {
            Self::Workspace { access, .. } if *access == O_WRONLY => Err(Errno::EBADF),
            Self::Supplied { entry, access, .. } if entry.link_target().is_some() => {
                Err(if *access == O_WRONLY {
                    Errno::EBADF
                } else {
                    Errno::EPERM
                })
            }
            Self::Supplied { entry, cursor, .. } | Self::Workspace { entry, cursor, .. } => {
                let source = entry.source()?;
                let mut cursor = cursor.lock().map_err(|_| Errno::EIO)?;
                let start = match offset {
                    Some(n) => u64::try_from(n).map_err(|_| Errno::EINVAL)?,
                    None => *cursor,
                };
                let n = source.read_at(start, out).map_err(Errno::from)?;
                if offset.is_none() {
                    *cursor = start.checked_add(n as u64).ok_or(Errno::EOVERFLOW)?;
                }
                Ok(n)
            }
            Self::Input(console) => {
                if offset.is_some() {
                    return Err(Errno::ESPIPE);
                }
                Console::Captured(console.clone())
                    .read(out)
                    .map_err(Errno::from)
            }
            Self::Output(..) => Err(Errno::EBADF),
            Self::Pipe(end) => {
                end.check(true, offset)?;
                end.read_with(out.len(), |bytes| {
                    out[..bytes.len()].copy_from_slice(bytes);
                    Ok(())
                })
            }
            Self::Null { access, .. } | Self::Zero { access, .. } if *access == O_WRONLY => {
                Err(Errno::EBADF)
            }
            Self::Null { .. } => Ok(0),
            Self::Zero { cursor, .. } => {
                if offset.is_none() {
                    Self::advance_device_cursor(cursor, out.len() as u64)?;
                }
                Ok(Device::Zero.read(out))
            }
        }
    }

    /// Captured writes are atomic with respect to the shared output bound.
    pub fn write(&self, bytes: &[u8], offset: Option<i64>) -> Result<usize, Errno> {
        match self {
            Self::Output(console, stream) => {
                if offset.is_some() {
                    return Err(Errno::ESPIPE);
                }
                Console::Captured(console.clone()).write_all(*stream, bytes)?;
                Ok(bytes.len())
            }
            Self::Workspace {
                entry,
                cursor,
                access,
                append,
            } => {
                if *access == O_RDONLY {
                    return Err(Errno::EBADF);
                }
                let file = entry.workspace_file().expect("guest workspace descriptor");
                let offset = offset
                    .map(|value| u64::try_from(value).map_err(|_| Errno::EINVAL))
                    .transpose()?;
                if bytes.is_empty() {
                    return Ok(0);
                }
                let mut position = cursor.lock().map_err(|_| Errno::EIO)?;
                let at = offset.or_else(|| (!append.load(Ordering::Relaxed)).then_some(*position));
                let end = file.write(at, bytes)?;
                if offset.is_none() {
                    *position = end;
                }
                Ok(bytes.len())
            }
            Self::Supplied { entry, access, .. }
                if entry.link_target().is_some() && *access != O_RDONLY =>
            {
                Err(Errno::EPERM)
            }
            Self::Input(_) | Self::Supplied { .. } => Err(Errno::EBADF),
            Self::Pipe(end) => {
                end.check(false, offset)?;
                end.write_with(
                    bytes.len(),
                    bytes.len() <= super::pipe::PIPE_BUF,
                    true,
                    |n| Ok(bytes[..n].to_vec()),
                )
            }
            Self::Null { .. } | Self::Zero { .. } => self
                .discard_device_write(bytes.len() as u64, offset)
                .map(|n| n as usize),
        }
    }

    /// Device writes accept the count without reading the guest buffer.
    /// Positional writes leave the open description's cursor unchanged.
    pub(crate) fn discard_device_write(
        &self,
        length: u64,
        offset: Option<i64>,
    ) -> Result<u64, Errno> {
        let (Self::Null { access, cursor, .. } | Self::Zero { access, cursor, .. }) = self else {
            return Err(Errno::EBADF);
        };
        if offset.is_some_and(|n| n < 0) {
            return Err(Errno::EINVAL);
        }
        if *access == O_RDONLY {
            return Err(Errno::EBADF);
        }
        if offset.is_none() {
            Self::advance_device_cursor(cursor, length)?;
        }
        Ok(length)
    }

    fn advance_device_cursor(cursor: &Mutex<u64>, length: u64) -> Result<(), Errno> {
        let mut cursor = cursor.lock().map_err(|_| Errno::EIO)?;
        *cursor = cursor
            .checked_add(length)
            .filter(|&end| i64::try_from(end).is_ok())
            .ok_or(Errno::EOVERFLOW)?;
        Ok(())
    }

    /// Darwin `SEEK_SET` (0), `SEEK_CUR` (1), and `SEEK_END` (2). An
    /// unrepresentable or negative resulting offset leaves the cursor intact.
    pub fn seek(&self, offset: i64, whence: i32) -> Result<u64, Errno> {
        let (cursor, entry) = match self {
            Self::Supplied { entry, cursor, .. } | Self::Workspace { entry, cursor, .. } => {
                (cursor, Some(entry))
            }
            Self::Null { cursor, .. } | Self::Zero { cursor, .. } => (cursor, None),
            _ => return Err(Errno::ESPIPE),
        };
        let mut cursor = cursor.lock().map_err(|_| Errno::EIO)?;
        let base = match whence {
            0 => 0,
            1 => i64::try_from(*cursor).map_err(|_| Errno::EOVERFLOW)?,
            2 if entry.is_none_or(|entry| !entry.is_dir()) => {
                i64::try_from(entry.map_or(0, Entry::len)).map_err(|_| Errno::EOVERFLOW)?
            }
            3 | 4 if self.device_access().is_some() => return Err(Errno::ENODEV),
            _ => return Err(Errno::EINVAL),
        };
        let result = base.checked_add(offset).ok_or(Errno::EOVERFLOW)?;
        *cursor = u64::try_from(result).map_err(|_| Errno::EINVAL)?;
        Ok(*cursor)
    }
}

impl OpenFile {
    pub(crate) fn device(path: String, device: Device, ino: u64, flags: u32) -> Self {
        let access = flags & O_ACCMODE;
        let cursor = Mutex::new(0);
        let file = match device {
            Device::Null => EmbeddedFile::Null {
                ino,
                access,
                cursor,
            },
            Device::Zero => EmbeddedFile::Zero {
                ino,
                access,
                cursor,
            },
        };
        Self {
            kind: FileKind::Embedded(file),
            path: Some(path.into_bytes()),
            flags: Mutex::new(flags),
        }
    }

    pub(crate) fn workspace(path: String, entry: Entry, flags: u32) -> Self {
        Self {
            kind: FileKind::Embedded(EmbeddedFile::Workspace {
                entry,
                cursor: Mutex::new(0),
                access: flags & O_ACCMODE,
                append: AtomicBool::new(flags & O_APPEND != 0),
            }),
            path: Some(path.into_bytes()),
            flags: Mutex::new(flags),
        }
    }

    pub fn supplied(path: String, entry: Entry) -> Self {
        Self::supplied_with_flags(path, entry, O_RDONLY)
    }

    pub(crate) fn supplied_with_flags(path: String, entry: Entry, flags: u32) -> Self {
        Self {
            kind: FileKind::Embedded(EmbeddedFile::Supplied {
                entry,
                cursor: Mutex::new(0),
                access: flags & O_ACCMODE,
            }),
            path: Some(path.into_bytes()),
            flags: Mutex::new(flags),
        }
    }
}

impl FdTable {
    /// Standard descriptors referring only to caller-owned, bounded buffers.
    pub fn with_captured(console: CapturedConsole) -> Self {
        let mut table = Self::new();
        for (index, file) in [
            EmbeddedFile::Input(console.clone()),
            EmbeddedFile::Output(console.clone(), OutputStream::Stdout),
            EmbeddedFile::Output(console, OutputStream::Stderr),
        ]
        .into_iter()
        .enumerate()
        {
            table.install_at(
                index,
                Arc::new(OpenFile {
                    kind: FileKind::Embedded(file),
                    path: None,
                    flags: Mutex::new(if index == 0 { 0 } else { 1 }),
                }),
                false,
            );
        }
        table
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::supplied_fs::Files;

    fn embedded(file: &OpenFile) -> &EmbeddedFile {
        let FileKind::Embedded(file) = &file.kind else {
            panic!("not embedded")
        };
        file
    }

    #[test]
    fn selected_large_runtime_file_uses_demand_reads_and_guest_page_eof_padding() {
        let fixture =
            crate::user::supplied_fs::test_backing::TestFile::new(b"dyld-cache", (64 << 20) + 1);
        let files = Files::default()
            .with_host_file("/cache".into(), &fixture.path)
            .unwrap();
        let (path, entry) = files.lookup("/cache").unwrap();
        assert!(entry.bytes().is_err());
        let source = supplied_source(&entry, 16384).unwrap();
        assert_eq!(source.len(), (64 << 20) + 16384);
        assert_eq!(source.identity().ino, entry.ino);
        let file = OpenFile::supplied(path, entry);
        assert!(file.host_fd().is_none());
        let f = embedded(&file);
        assert_eq!(f.stat().unwrap().size, (64 << 20) + 1);
        assert_eq!(f.available().unwrap(), (64 << 20) + 1);
        let mut out = [0xaa; 10];
        assert_eq!(f.read(&mut out, None), Ok(10));
        assert_eq!(&out, b"dyld-cache");
        assert_eq!(f.seek(0, 1), Ok(10));
        assert_eq!(f.read(&mut out, Some(0)), Ok(10));
        assert_eq!(f.seek(0, 1), Ok(10));
        assert_eq!(f.seek(-1, 2), Ok(64 << 20));
        assert_eq!(f.read(&mut out, None), Ok(1));
        assert_eq!(f.read(&mut out, None), Ok(0));
        assert_eq!(f.write(b"x", None), Err(Errno::EBADF));
        let mut page = [0xaa; 16384];
        assert_eq!(source.read_at(64 << 20, &mut page).unwrap(), page.len());
        assert!(page.iter().all(|&b| b == 0));
        assert_eq!(source.read_at(source.len(), &mut page).unwrap(), 0);
        std::fs::OpenOptions::new()
            .write(true)
            .open(&fixture.path)
            .unwrap()
            .set_len(10)
            .unwrap();
        assert_eq!(source.len(), 16384);
        assert_eq!(source.read_at(16384, &mut page).unwrap(), 0);
        for page in [0, 3, u64::MAX] {
            assert_eq!(
                supplied_source(&files.lookup("/cache").unwrap().1, page).unwrap_err(),
                Errno::EINVAL
            );
        }
    }

    #[test]
    fn supplied_duplicates_share_cursor_but_positional_reads_do_not() {
        let files = Files::new(std::collections::BTreeMap::from([(
            "/data".into(),
            Arc::<[u8]>::from(&b"abcdef"[..]),
        )]))
        .unwrap();
        let (path, entry) = files.lookup("/data").unwrap();
        let mut table = FdTable::new();
        let fd = table
            .install(Arc::new(OpenFile::supplied(path, entry)), false, 0, 256)
            .unwrap();
        let file = table.file(fd).unwrap();
        let dup = table.install(file.clone(), false, 0, 256).unwrap();
        assert!(file.host_fd().is_none());
        let mut out = [0; 2];
        assert_eq!(embedded(&file).read(&mut out, None), Ok(2));
        assert_eq!(&out, b"ab");
        assert_eq!(
            embedded(&table.file(dup).unwrap()).read(&mut out, Some(4)),
            Ok(2)
        );
        assert_eq!(&out, b"ef");
        assert_eq!(embedded(&file).read(&mut out, None), Ok(2));
        assert_eq!(&out, b"cd");
        assert_eq!(embedded(&file).seek(-5, 1), Err(Errno::EINVAL));
        assert_eq!(embedded(&file).seek(0, 1), Ok(4));
        assert_eq!(embedded(&file).seek(i64::MAX, 0), Ok(i64::MAX as u64));
        assert_eq!(embedded(&file).seek(1, 1), Err(Errno::EOVERFLOW));
        assert_eq!(embedded(&file).read(&mut out, None), Ok(0));
        assert_eq!(embedded(&file).seek(-1, 2), Ok(5));
        assert_eq!(embedded(&file).read(&mut out, None), Ok(1));
        assert_eq!(out[0], b'f');
        assert_eq!(embedded(&file).read(&mut out, Some(-1)), Err(Errno::EINVAL));
        assert_eq!(embedded(&file).write(b"x", None), Err(Errno::EBADF));
        table.remove(fd).unwrap();
        assert_eq!(embedded(&table.file(dup).unwrap()).seek(0, 0), Ok(0));
    }

    #[test]
    fn captured_descriptors_enforce_direction_bounds_eof_and_stream_identity() {
        let console = CapturedConsole::new(b"in".to_vec(), 3).unwrap();
        let table = FdTable::with_captured(console.clone());
        assert_eq!(table.len(), 3);
        let input = table.file(0).unwrap();
        let output = table.file(1).unwrap();
        let error = table.file(2).unwrap();
        assert!(table.iter().all(|(_, slot)| slot.file.host_fd().is_none()));
        let mut out = [0; 3];
        assert_eq!(embedded(&input).read(&mut out, Some(0)), Err(Errno::ESPIPE));
        assert_eq!(embedded(&input).read(&mut out, None), Ok(2));
        assert_eq!(&out[..2], b"in");
        assert_eq!(embedded(&input).read(&mut out, None), Ok(0));
        assert_eq!(embedded(&output).read(&mut out, None), Err(Errno::EBADF));
        assert_eq!(embedded(&input).write(b"x", None), Err(Errno::EBADF));
        assert_eq!(embedded(&output).write(b"ab", None), Ok(2));
        assert_eq!(embedded(&error).write(b"cd", None), Err(Errno::EIO));
        assert_eq!(console.pending().unwrap(), (0, 2, 0));
        assert_eq!(embedded(&error).write(b"c", None), Ok(1));
        assert_eq!(console.drain(OutputStream::Stderr, &mut out).unwrap(), 1);
        assert_eq!(out[0], b'c');
        assert_eq!(embedded(&output).seek(0, 0), Err(Errno::ESPIPE));
        assert_eq!(embedded(&output).write(b"", Some(0)), Err(Errno::ESPIPE));
    }
}

#[derive(Debug)]
struct SuppliedSource {
    source: Arc<dyn PageSource>,
    page: u64,
    ino: u64,
}

impl PageSource for SuppliedSource {
    fn len(&self) -> u64 {
        self.source
            .len()
            .checked_add(self.page - 1)
            .map(|end| end & !(self.page - 1))
            .unwrap_or(0)
    }
    fn identity(&self) -> SourceIdentity {
        SourceIdentity {
            dev: 0x524158,
            ino: self.ino,
        }
    }
    fn read_at(&self, offset: u64, out: &mut [u8]) -> std::io::Result<usize> {
        let n = (self.len().saturating_sub(offset)).min(out.len() as u64) as usize;
        out[..n].fill(0);
        let len = self.source.len();
        if offset < len {
            let count = (len - offset).min(n as u64) as usize;
            let mut done = 0;
            while done < count {
                let got = self
                    .source
                    .read_at(offset + done as u64, &mut out[done..count])?;
                if got == 0 || got > count - done {
                    return Err(std::io::ErrorKind::UnexpectedEof.into());
                }
                done += got;
            }
        }
        Ok(n)
    }
}

/// Read-only mapping source with stable guest identity and guest-page EOF padding.
pub(crate) fn supplied_source(entry: &Entry, page: u64) -> Result<Arc<dyn PageSource>, Errno> {
    if !page.is_power_of_two() {
        return Err(Errno::EINVAL);
    }
    let source = entry.source()?;
    source.len().checked_add(page - 1).ok_or(Errno::EINVAL)?;
    Ok(Arc::new(SuppliedSource {
        source,
        page,
        ino: entry.ino,
    }))
}
