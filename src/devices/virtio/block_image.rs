//! Shared raw-image media for virtio-blk, NVMe and AHCI.
//!
//! Loaded media retain a byte-addressable view. Persistent images write through
//! and synchronize before success; COW writes modify only the instance's bytes.
//! The file lock coordinates cooperating image users, not arbitrary host writers.
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::ops::{Deref, Range};
use std::path::{Path, PathBuf};

/// Maximum explicitly permitted raw-image extent (64 GiB).
pub const MAX_IMAGE_BYTES: u64 = 64 * 1024 * 1024 * 1024;
/// Host effects selected when opening an image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImageMode {
    /// Guest modifications are rejected.
    ReadOnly,
    /// Guest writes reach the opened file and synchronize before success.
    ReadWrite,
    /// Guest modifications belong only to this in-memory instance.
    CopyOnWrite,
}
#[derive(Debug)]
struct Backing {
    path: PathBuf,
    mode: ImageMode,
    // Only persistent images retain a writable descriptor and exclusive lock.
    file: Option<File>,
}
/// A bounded, byte-addressable medium, optionally associated with a raw image.
#[derive(Debug)]
pub struct BlockImage {
    bytes: Vec<u8>,
    backing: Option<Backing>,
}
impl BlockImage {
    /// Preserve the existing in-memory media semantics, including empty media.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            backing: None,
        }
    }
    /// Open a nonempty, sector-aligned regular raw image within the caller's
    /// explicit byte budget. No file is created, truncated or resized.
    pub fn open(path: impl AsRef<Path>, mode: ImageMode, max_bytes: u64) -> io::Result<Self> {
        if max_bytes == 0 || max_bytes > MAX_IMAGE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid image byte budget",
            ));
        }
        let path = path.as_ref().canonicalize()?;
        if !std::fs::metadata(&path)?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "image path is not a regular file",
            ));
        }
        let mut file = OpenOptions::new()
            .read(true)
            .write(mode == ImageMode::ReadWrite)
            .open(&path)?;
        if mode == ImageMode::ReadWrite {
            file.try_lock()?;
        } else {
            file.try_lock_shared()?;
        }
        let metadata = file.metadata()?;
        let size = metadata.len();
        if !metadata.is_file() || size == 0 || size % 512 != 0 || size > max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "image must be a nonempty sector-aligned regular file within its byte budget",
            ));
        }
        let mut bytes = Vec::new();
        let mut buffer = [0; 64 * 1024];
        // Incremental bounded allocation avoids reserving a declared huge size
        // before reading actual bytes. A changing length is rejected.
        let mut remaining = size;
        while remaining != 0 {
            let count = (remaining.min(buffer.len() as u64)) as usize;
            file.read_exact(&mut buffer[..count])?;
            bytes.try_reserve(count).map_err(io::Error::other)?;
            bytes.extend_from_slice(&buffer[..count]);
            remaining -= count as u64;
        }
        let mut extra = [0];
        if file.read(&mut extra)? != 0 || file.metadata()?.len() != size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "image length changed while loading",
            ));
        }
        Ok(Self {
            bytes,
            backing: Some(Backing {
                path,
                mode,
                file: (mode == ImageMode::ReadWrite).then_some(file),
            }),
        })
    }
    /// Selected raw-image mode; in-memory media use the COW host-effect model.
    pub fn mode(&self) -> ImageMode {
        self.backing
            .as_ref()
            .map_or(ImageMode::CopyOnWrite, |b| b.mode)
    }
    /// Canonical source path, if this medium was loaded from a file.
    pub fn path(&self) -> Option<&Path> {
        self.backing.as_ref().map(|b| b.path.as_path())
    }
    pub fn is_read_only(&self) -> bool {
        self.mode() == ImageMode::ReadOnly
    }
    fn bounds(&self, start: usize, length: usize) -> io::Result<Range<usize>> {
        let end = start
            .checked_add(length)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "media extent exceeds capacity")
            })?;
        if self.is_read_only() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "image is read-only",
            ));
        }
        Ok(start..end)
    }
    fn write_inner(&mut self, start: usize, data: &[u8]) -> io::Result<()> {
        if let Some(file) = self.backing.as_mut().and_then(|b| b.file.as_mut()) {
            if file.metadata()?.len() != self.bytes.len() as u64 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "image capacity changed while attached",
                ));
            }
            file.seek(SeekFrom::Start(start as u64))?;
            write_accepted(file, &mut self.bytes[start..start + data.len()], data)?;
        } else {
            self.bytes[start..start + data.len()].copy_from_slice(data);
        }
        Ok(())
    }
    /// Apply a checked write. Persistent success includes host synchronization.
    /// Host I/O failure can leave an accepted prefix; the error is propagated.
    pub fn write_bytes(&mut self, start: usize, data: &[u8]) -> io::Result<()> {
        self.bounds(start, data.len())?;
        self.write_inner(start, data)?;
        self.flush()
    }
    /// Clear a checked extent without a proportional temporary allocation.
    pub fn zero_bytes(&mut self, range: Range<usize>) -> io::Result<()> {
        let length = range
            .end
            .checked_sub(range.start)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "reversed media extent"))?;
        self.bounds(range.start, length)?;
        let zeroes = [0; 64 * 1024];
        let mut start = range.start;
        while start < range.end {
            let count = zeroes.len().min(range.end - start);
            self.write_inner(start, &zeroes[..count])?;
            start += count;
        }
        self.flush()
    }
    /// Synchronize persistent writes. COW/readonly/memory modes have no host
    /// mutations to publish; dropping an instance never commits a COW image.
    pub fn flush(&mut self) -> io::Result<()> {
        if let Some(file) = self.backing.as_mut().and_then(|b| b.file.as_mut()) {
            if file.metadata()?.len() != self.bytes.len() as u64 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "image capacity changed while attached",
                ));
            }
            file.sync_all()?;
        }
        Ok(())
    }
}
// Update only bytes accepted by the host, including a prefix before failure.
fn write_accepted(file: &mut impl Write, cache: &mut [u8], data: &[u8]) -> io::Result<()> {
    let mut done = 0;
    while done < data.len() {
        let count = match file.write(&data[done..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "image write made no progress",
                ));
            }
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        cache[done..done + count].copy_from_slice(&data[done..done + count]);
        done += count;
    }
    Ok(())
}

impl Deref for BlockImage {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Host {
        accepted: Vec<u8>,
        limit: usize,
        chunk: usize,
        interrupt: bool,
        zero: bool,
    }
    impl Write for Host {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            if self.interrupt {
                self.interrupt = false;
                return Err(io::ErrorKind::Interrupted.into());
            }
            if self.accepted.len() == self.limit {
                return if self.zero {
                    Ok(0)
                } else {
                    Err(io::Error::other("injected host media failure"))
                };
            }
            let count = self
                .chunk
                .min(data.len())
                .min(self.limit - self.accepted.len());
            self.accepted.extend_from_slice(&data[..count]);
            Ok(count)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    #[test]
    fn failed_host_write_preserves_exact_accepted_prefix_in_cache() {
        let mut host = Host {
            accepted: vec![],
            limit: 5,
            chunk: 3,
            interrupt: false,
            zero: false,
        };
        let mut cache = [0xaa; 12];
        assert!(write_accepted(&mut host, &mut cache, &[7; 12]).is_err());
        assert_eq!(host.accepted, [7; 5]);
        assert_eq!(&cache[..5], &[7; 5]);
        assert_eq!(&cache[5..], &[0xaa; 7]);
    }
    #[test]
    fn zero_progress_after_prefix_is_an_error_without_false_remaining_bytes() {
        let mut host = Host {
            accepted: vec![],
            limit: 4,
            chunk: 2,
            interrupt: false,
            zero: true,
        };
        let mut cache = [0xaa; 12];
        assert_eq!(
            write_accepted(&mut host, &mut cache, &[9; 12])
                .unwrap_err()
                .kind(),
            io::ErrorKind::WriteZero
        );
        assert_eq!(&cache[..4], &[9; 4]);
        assert_eq!(&cache[4..], &[0xaa; 8]);
    }
    #[test]
    fn interrupted_and_short_host_writes_resume_without_duplication() {
        let mut host = Host {
            accepted: vec![],
            limit: 12,
            chunk: 3,
            interrupt: true,
            zero: false,
        };
        let mut cache = [0xaa; 12];
        let data = std::array::from_fn::<u8, 12, _>(|i| i as u8);
        write_accepted(&mut host, &mut cache, &data).unwrap();
        assert_eq!(host.accepted, data);
        assert_eq!(cache, data);
    }
    #[test]
    fn immediate_host_failure_preserves_every_cached_byte() {
        let mut host = Host {
            accepted: vec![],
            limit: 0,
            chunk: 3,
            interrupt: false,
            zero: false,
        };
        let mut cache = [0xaa; 12];
        assert!(write_accepted(&mut host, &mut cache, &[7; 12]).is_err());
        assert!(host.accepted.is_empty());
        assert_eq!(cache, [0xaa; 12]);
    }
}
