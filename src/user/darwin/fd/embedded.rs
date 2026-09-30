//! Descriptor storage for embedding. Duplicates share the open description's
//! cursor; positional reads do not change it. No operation opens a host file.

use std::sync::{Arc, Mutex};

use super::{FdTable, FileKind, OpenFile};
use crate::user::console::{CapturedConsole, Console, OutputStream};
use crate::user::darwin::abi::Errno;
use crate::user::mm::{PageSource, SourceIdentity};
use crate::user::supplied_fs::Entry;

#[derive(Debug)]
pub enum EmbeddedFile {
    Supplied { entry: Entry, cursor: Mutex<u64> },
    Input(CapturedConsole),
    Output(CapturedConsole, OutputStream),
}

impl EmbeddedFile {
    /// Bytes available without consuming input or changing the file offset.
    pub fn available(&self) -> Result<u64, Errno> {
        match self {
            Self::Supplied { entry, cursor } => {
                let bytes = entry.bytes()?;
                Ok((bytes.len() as u64).saturating_sub(*cursor.lock().map_err(|_| Errno::EIO)?))
            }
            Self::Input(console) => Ok(console.pending()?.0 as u64),
            Self::Output(..) => Ok(0),
        }
    }

    /// Stable virtual metadata. Supplied files are readable/executable and
    /// immutable; directories are searchable. Timestamps and ownership are
    /// virtual zero values, never taken from the embedding host.
    pub fn stat(&self) -> Result<crate::user::darwin::abi::types::Stat, Errno> {
        use crate::user::darwin::abi::types::Stat;
        let (ino, mode, size) = match self {
            Self::Supplied { entry, .. } => {
                if entry.is_dir() {
                    (entry.ino, 0o040555, 0)
                } else {
                    (
                        entry.ino,
                        0o100555,
                        i64::try_from(entry.bytes()?.len()).map_err(|_| Errno::EOVERFLOW)?,
                    )
                }
            }
            Self::Input(_) => (1, 0o020444, 0),
            Self::Output(_, OutputStream::Stdout) => (2, 0o020222, 0),
            Self::Output(_, OutputStream::Stderr) => (3, 0o020222, 0),
        };
        Ok(Stat {
            dev: if matches!(self, Self::Supplied { .. }) {
                0x524158
            } else {
                0x524159
            },
            ino,
            mode,
            size,
            nlink: 1,
            blksize: 4096,
            blocks: (size as u64).div_ceil(512) as i64,
            ..Default::default()
        })
    }

    /// Transfer at most `out.len()` bytes. `offset` is a positional read;
    /// captured streams reject positional operations with `ESPIPE`.
    pub fn read(&self, out: &mut [u8], offset: Option<i64>) -> Result<usize, Errno> {
        match self {
            Self::Supplied { entry, cursor } => {
                let bytes = entry.bytes()?;
                let mut cursor = cursor.lock().map_err(|_| Errno::EIO)?;
                let start = match offset {
                    Some(n) => u64::try_from(n).map_err(|_| Errno::EINVAL)?,
                    None => *cursor,
                };
                let start_index = start.min(bytes.len() as u64) as usize;
                let n = out.len().min(bytes.len() - start_index);
                out[..n].copy_from_slice(&bytes[start_index..start_index + n]);
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
            Self::Input(_) | Self::Supplied { .. } => Err(Errno::EBADF),
        }
    }

    /// Darwin `SEEK_SET` (0), `SEEK_CUR` (1), and `SEEK_END` (2). An
    /// unrepresentable or negative resulting offset leaves the cursor intact.
    pub fn seek(&self, offset: i64, whence: i32) -> Result<u64, Errno> {
        let Self::Supplied { entry, cursor } = self else {
            return Err(Errno::ESPIPE);
        };
        let bytes = entry.bytes()?;
        let mut cursor = cursor.lock().map_err(|_| Errno::EIO)?;
        let base = match whence {
            0 => 0,
            1 => i64::try_from(*cursor).map_err(|_| Errno::EOVERFLOW)?,
            2 => i64::try_from(bytes.len()).map_err(|_| Errno::EOVERFLOW)?,
            _ => return Err(Errno::EINVAL),
        };
        let result = base.checked_add(offset).ok_or(Errno::EOVERFLOW)?;
        *cursor = u64::try_from(result).map_err(|_| Errno::EINVAL)?;
        Ok(*cursor)
    }
}

impl OpenFile {
    pub fn supplied(path: String, entry: Entry) -> Self {
        Self {
            kind: FileKind::Embedded(EmbeddedFile::Supplied {
                entry,
                cursor: Mutex::new(0),
            }),
            path: Some(path.into_bytes()),
            flags: Mutex::new(0), // Darwin O_RDONLY.
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
    bytes: Arc<[u8]>,
    extent: u64,
    ino: u64,
}

impl PageSource for SuppliedSource {
    fn len(&self) -> u64 {
        self.extent
    }
    fn identity(&self) -> SourceIdentity {
        SourceIdentity {
            dev: 0x524158,
            ino: self.ino,
        }
    }
    fn read_at(&self, offset: u64, out: &mut [u8]) -> std::io::Result<usize> {
        let n = (self.extent.saturating_sub(offset)).min(out.len() as u64) as usize;
        out[..n].fill(0);
        if offset < self.bytes.len() as u64 {
            let count = n.min(self.bytes.len() - offset as usize);
            out[..count].copy_from_slice(&self.bytes[offset as usize..offset as usize + count]);
        }
        Ok(n)
    }
}

/// Immutable mapping source with stable guest identity and guest-page EOF padding.
pub(crate) fn supplied_source(entry: &Entry, page: u64) -> Result<Arc<dyn PageSource>, Errno> {
    if !page.is_power_of_two() {
        return Err(Errno::EINVAL);
    }
    let bytes = entry.bytes()?;
    let extent = (bytes.len() as u64)
        .checked_add(page - 1)
        .ok_or(Errno::EINVAL)?
        & !(page - 1);
    Ok(Arc::new(SuppliedSource {
        bytes,
        extent,
        ino: entry.ino,
    }))
}
