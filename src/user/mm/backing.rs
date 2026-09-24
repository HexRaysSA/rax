//! Page-content sources for mapped ranges.

use std::fmt;
use std::sync::Arc;

use super::PAGE_SIZE;
use super::shared::SharedObject;

/// Identity of a mapped object, shown in `/proc/self/maps`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SourceIdentity {
    /// Device number (`st_dev`).
    pub dev: u64,
    /// Inode number (`st_ino`).
    pub ino: u64,
}

/// A file-like object whose bytes back a mapping.
///
/// Reads happen on first touch of each page, as with demand paging. A page
/// whose file offset lies at or beyond the end of the object rounded up to a
/// page is inaccessible (Linux raises `SIGBUS` for it); bytes past the end
/// inside the final partial page read as zero.
pub trait PageSource: Send + Sync + fmt::Debug {
    /// Current size of the object in bytes.
    fn len(&self) -> u64;

    /// Whether the object is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Reads up to `buf.len()` bytes at `offset`; returns the count read,
    /// short only at end of object.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize>;

    /// Device/inode identity for diagnostics.
    fn identity(&self) -> SourceIdentity {
        SourceIdentity::default()
    }
}

/// An in-memory byte buffer used as a mapping source.
#[derive(Clone)]
pub struct BytesSource {
    bytes: Arc<[u8]>,
}

impl BytesSource {
    /// Wraps `bytes`.
    pub fn new(bytes: Arc<[u8]>) -> Self {
        BytesSource { bytes }
    }
}

impl fmt::Debug for BytesSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BytesSource({} bytes)", self.bytes.len())
    }
}

impl PageSource for BytesSource {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let len = self.bytes.len() as u64;
        if offset >= len {
            return Ok(0);
        }
        let n = ((len - offset) as usize).min(buf.len());
        buf[..n].copy_from_slice(&self.bytes[offset as usize..offset as usize + n]);
        Ok(n)
    }
}

/// A host file used as a mapping source.
#[derive(Debug)]
pub struct HostFileSource {
    file: std::fs::File,
    identity: SourceIdentity,
}

impl HostFileSource {
    /// Wraps an open host file.
    pub fn new(file: std::fs::File) -> std::io::Result<Self> {
        let identity = file_identity(&file)?;
        Ok(HostFileSource { file, identity })
    }
}

#[cfg(unix)]
fn file_identity(file: &std::fs::File) -> std::io::Result<SourceIdentity> {
    use std::os::unix::fs::MetadataExt;
    let m = file.metadata()?;
    Ok(SourceIdentity {
        dev: m.dev(),
        ino: m.ino(),
    })
}

#[cfg(not(unix))]
fn file_identity(_file: &std::fs::File) -> std::io::Result<SourceIdentity> {
    Ok(SourceIdentity::default())
}

impl PageSource for HostFileSource {
    fn len(&self) -> u64 {
        self.file.metadata().map(|m| m.len()).unwrap_or(0)
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut done = 0;
        while done < buf.len() {
            #[cfg(unix)]
            let n = {
                use std::os::unix::fs::FileExt;
                self.file.read_at(&mut buf[done..], offset + done as u64)?
            };
            #[cfg(windows)]
            let n = {
                use std::os::windows::fs::FileExt;
                self.file
                    .seek_read(&mut buf[done..], offset + done as u64)?
            };
            if n == 0 {
                break;
            }
            done += n;
        }
        Ok(done)
    }

    fn identity(&self) -> SourceIdentity {
        self.identity
    }
}

/// Where a mapped range's page contents come from on first touch.
#[derive(Clone, Debug)]
pub enum Backing {
    /// Zero-filled anonymous memory.
    Anonymous,
    /// Bytes of `source`; the range's first byte maps `offset`.
    Source {
        source: Arc<dyn PageSource>,
        offset: u64,
    },
    /// The pages of a shared object themselves; the range's first byte is
    /// at `offset`.
    Shared {
        object: Arc<SharedObject>,
        offset: u64,
    },
}

impl Backing {
    /// The backing seen `delta` bytes further into the range.
    pub fn advanced(&self, delta: u64) -> Backing {
        match self {
            Backing::Anonymous => Backing::Anonymous,
            Backing::Source { source, offset } => Backing::Source {
                source: source.clone(),
                offset: offset + delta,
            },
            Backing::Shared { object, offset } => Backing::Shared {
                object: object.clone(),
                offset: offset + delta,
            },
        }
    }

    /// Whether `next`, placed directly after a range of `len` bytes with this
    /// backing, continues it.
    pub fn continues_into(&self, len: u64, next: &Backing) -> bool {
        match (self, next) {
            (Backing::Anonymous, Backing::Anonymous) => true,
            (
                Backing::Source { source, offset },
                Backing::Source {
                    source: next_source,
                    offset: next_offset,
                },
            ) => Arc::ptr_eq(source, next_source) && offset + len == *next_offset,
            (
                Backing::Shared { object, offset },
                Backing::Shared {
                    object: next_object,
                    offset: next_offset,
                },
            ) => Arc::ptr_eq(object, next_object) && offset + len == *next_offset,
            _ => false,
        }
    }

    /// The object's size a page lies beyond when an access to it is a bus
    /// error: the source's or shared object's size, rounded up to a page.
    pub fn end(&self) -> Option<u64> {
        match self {
            Backing::Anonymous => None,
            Backing::Source { source, .. } => Some(source.len().div_ceil(PAGE_SIZE) * PAGE_SIZE),
            Backing::Shared { object, .. } => Some(object.len().div_ceil(PAGE_SIZE) * PAGE_SIZE),
        }
    }

    /// Fills `page` (one page) with the contents at `delta` bytes into the
    /// range. Returns `Ok(false)` when the page lies wholly past the end of
    /// the source (an access raises a bus error).
    pub fn fill_page(&self, delta: u64, page: &mut [u8]) -> std::io::Result<bool> {
        debug_assert_eq!(page.len() as u64, PAGE_SIZE);
        match self {
            Backing::Anonymous => {
                page.fill(0);
                Ok(true)
            }
            Backing::Source { source, offset } => {
                let file_offset = offset + delta;
                let len = source.len();
                if file_offset >= len.div_ceil(PAGE_SIZE) * PAGE_SIZE {
                    return Ok(false);
                }
                let n = source.read_at(file_offset, page)?;
                page[n..].fill(0);
                Ok(true)
            }
            Backing::Shared { object, offset } => {
                let file_offset = offset + delta;
                if file_offset >= object.len().div_ceil(PAGE_SIZE) * PAGE_SIZE {
                    return Ok(false);
                }
                let n = object.read_at(file_offset, page)?;
                page[n..].fill(0);
                Ok(true)
            }
        }
    }

    /// Source identity for diagnostics.
    pub fn identity(&self) -> SourceIdentity {
        match self {
            Backing::Anonymous => SourceIdentity::default(),
            Backing::Source { source, .. } => source.identity(),
            Backing::Shared { object, .. } => object.identity(),
        }
    }

    /// Offset of the range start within the source (zero for anonymous).
    pub fn offset(&self) -> u64 {
        match self {
            Backing::Anonymous => 0,
            Backing::Source { offset, .. } | Backing::Shared { offset, .. } => *offset,
        }
    }
}
