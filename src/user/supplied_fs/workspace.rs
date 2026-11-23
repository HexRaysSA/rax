//! Bounded, session-owned files. A removed name releases its file only after
//! the last descriptor or mapping closes, so a later create gets a new inode.

use super::Error;
use crate::user::mm::{PageSource, SourceIdentity};
use std::collections::BTreeMap;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

const MAX_BYTES: usize = 16 << 20;
const MAX_FILES: usize = 1024;
const FIRST_INODE: u32 = 0x5258_0001;
pub(super) const ROOT_INODE: u64 = (FIRST_INODE - 1) as u64;

#[derive(Debug)]
pub(super) struct Workspace {
    namespace: Mutex<Namespace>,
    budget: Arc<Mutex<Budget>>,
}

#[derive(Debug)]
struct Namespace {
    files: BTreeMap<String, Arc<WorkspaceFile>>,
    inode: u32,
}

#[derive(Debug, Default)]
struct Budget {
    files: usize,
    bytes: usize,
}

/// A regular file in the guest's private temporary directory.
#[derive(Debug)]
pub struct WorkspaceFile {
    pub(super) ino: u64,
    mode: u32,
    owner: (u32, u32),
    linked: AtomicBool,
    budget: Arc<Mutex<Budget>>,
    contents: Mutex<Vec<u8>>,
}

impl Workspace {
    pub(super) fn new() -> Self {
        Self {
            namespace: Mutex::new(Namespace {
                files: BTreeMap::new(),
                inode: FIRST_INODE,
            }),
            budget: Arc::default(),
        }
    }

    pub(super) fn get(&self, path: &str) -> Result<Option<Arc<WorkspaceFile>>, Error> {
        let namespace = self.namespace.lock().map_err(|_| Error::Io)?;
        Ok(namespace.files.get(path).cloned())
    }

    /// Atomically resolves an existing name or publishes a newly created inode.
    pub(super) fn create(
        &self,
        path: String,
        mode: u32,
        owner: (u32, u32),
        exclusive: bool,
    ) -> Result<Arc<WorkspaceFile>, Error> {
        let mut namespace = self.namespace.lock().map_err(|_| Error::Io)?;
        if let Some(file) = namespace.files.get(&path) {
            if exclusive {
                return Err(Error::Exists);
            }
            return Ok(file.clone());
        }
        let mut budget = self.budget.lock().map_err(|_| Error::Io)?;
        if budget.files >= MAX_FILES {
            return Err(Error::NoSpace);
        }
        let ino = namespace.inode;
        namespace.inode = ino.checked_add(1).ok_or(Error::NoSpace)?;
        let file = Arc::new(WorkspaceFile {
            ino: u64::from(ino),
            mode: mode & 0o7777,
            owner,
            linked: AtomicBool::new(true),
            budget: self.budget.clone(),
            contents: Mutex::new(Vec::new()),
        });
        budget.files += 1;
        namespace.files.insert(path, file.clone());
        Ok(file)
    }

    pub(super) fn unlink(&self, path: &str, uid: u32) -> Result<(), Error> {
        let mut namespace = self.namespace.lock().map_err(|_| Error::Io)?;
        let file = namespace.files.get(path).ok_or(Error::NotFound)?;
        // The workspace directory is owned by uid 0 and has its sticky bit set.
        if uid != 0 && uid != file.owner.0 {
            return Err(Error::PermissionDenied);
        }
        file.linked.store(false, Ordering::Relaxed);
        namespace.files.remove(path);
        Ok(())
    }

    pub(super) fn children(&self) -> Result<Vec<String>, Error> {
        let namespace = self.namespace.lock().map_err(|_| Error::Io)?;
        Ok(namespace.files.keys().cloned().collect())
    }
}

impl WorkspaceFile {
    pub(crate) fn mode(&self) -> u32 {
        self.mode
    }

    pub(crate) fn ownership(&self) -> (u32, u32) {
        self.owner
    }

    pub(crate) fn linked(&self) -> bool {
        self.linked.load(Ordering::Relaxed)
    }

    pub(crate) fn permits(&self, need: u32, ids: (u32, u32), groups: &[u32]) -> bool {
        if ids.0 == 0 {
            return need & 1 == 0 || self.mode & 0o111 != 0;
        }
        let shift = if ids.0 == self.owner.0 {
            6
        } else if ids.1 == self.owner.1 || groups.contains(&self.owner.1) {
            3
        } else {
            0
        };
        need & !(self.mode >> shift) == 0
    }

    pub(super) fn snapshot(&self) -> Result<Arc<[u8]>, Error> {
        let contents = self.contents.lock().map_err(|_| Error::Io)?;
        Ok(Arc::from(contents.as_slice()))
    }

    pub(crate) fn resize(&self, len: u64) -> Result<(), Error> {
        let len = usize::try_from(len).map_err(|_| Error::TooLarge)?;
        let mut bytes = self.contents.lock().map_err(|_| Error::Io)?;
        self.resize_locked(&mut bytes, len)
    }

    fn resize_locked(&self, bytes: &mut Vec<u8>, len: usize) -> Result<(), Error> {
        if len > MAX_BYTES {
            return Err(Error::TooLarge);
        }
        let old = bytes.len();
        if len == old {
            return Ok(());
        }
        let mut budget = self.budget.lock().map_err(|_| Error::Io)?;
        if len > old {
            let additional = len - old;
            if additional > MAX_BYTES - budget.bytes {
                return Err(Error::NoSpace);
            }
            bytes
                .try_reserve_exact(additional)
                .map_err(|_| Error::NoSpace)?;
            bytes.resize(len, 0);
            budget.bytes += additional;
        } else {
            bytes.truncate(len);
            // Give the allocator an opportunity to release spare capacity;
            // the quota accounts for logical bytes.
            bytes.shrink_to_fit();
            budget.bytes -= old - len;
        }
        Ok(())
    }

    /// Positional or append writes return the end offset. Selecting the end of
    /// file and writing happen under the same lock for distinct descriptions.
    pub(crate) fn write(&self, offset: Option<u64>, input: &[u8]) -> Result<u64, Error> {
        let mut bytes = self.contents.lock().map_err(|_| Error::Io)?;
        let offset = offset.unwrap_or(bytes.len() as u64);
        if input.is_empty() {
            return Ok(offset);
        }
        let start = usize::try_from(offset).map_err(|_| Error::TooLarge)?;
        let end = start.checked_add(input.len()).ok_or(Error::TooLarge)?;
        if end > bytes.len() {
            self.resize_locked(&mut bytes, end)?;
        }
        bytes[start..end].copy_from_slice(input);
        Ok(end as u64)
    }
}

impl Drop for WorkspaceFile {
    fn drop(&mut self) {
        if let Ok(mut budget) = self.budget.lock() {
            let bytes = self
                .contents
                .get_mut()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            budget.bytes -= bytes.len();
            budget.files -= 1;
        }
    }
}

impl PageSource for WorkspaceFile {
    fn len(&self) -> u64 {
        self.contents
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len() as u64
    }

    fn read_at(&self, offset: u64, out: &mut [u8]) -> io::Result<usize> {
        let bytes = self
            .contents
            .lock()
            .map_err(|_| io::Error::other(Error::Io))?;
        if offset >= bytes.len() as u64 {
            return Ok(0);
        }
        let start = offset as usize;
        let count = out.len().min(bytes.len() - start);
        out[..count].copy_from_slice(&bytes[start..start + count]);
        Ok(count)
    }

    fn identity(&self) -> SourceIdentity {
        SourceIdentity {
            dev: 0x524158,
            ino: self.ino,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removed_storage_survives_recreation_until_the_last_descriptor_closes() {
        let files = Workspace::new();
        let name = "value";
        let before = files.create(name.into(), 0o600, (101, 102), true).unwrap();
        assert!(matches!(
            files.create(name.into(), 0o600, (103, 104), true),
            Err(Error::Exists)
        ));
        assert!(Arc::ptr_eq(
            &files.create(name.into(), 0, (103, 104), false).unwrap(),
            &before
        ));
        assert_eq!(before.mode(), 0o600);
        assert_eq!(before.write(Some(2), b"first").unwrap(), 7);
        assert_eq!(before.write(None, b"!").unwrap(), 8);
        assert_eq!(before.snapshot().unwrap().as_ref(), b"\0\0first!");
        assert_eq!(before.ownership(), (101, 102));
        assert!(before.permits(6, (101, 102), &[]));
        assert!(!before.permits(4, (103, 102), &[]));
        assert!(!before.permits(1, (0, 0), &[]));
        assert!(matches!(
            files.unlink(name, 103),
            Err(Error::PermissionDenied)
        ));
        files.unlink(name, 101).unwrap();
        assert!(!before.linked());
        assert!(files.get(name).unwrap().is_none());
        let after = files.create(name.into(), 0o640, (103, 104), true).unwrap();
        assert!(after.linked());
        assert!(after.permits(4, (101, 102), &[104]));
        assert_ne!(before.ino, after.ino);
        assert_eq!(after.len(), 0);
        assert_eq!(before.len(), 8);
        assert_eq!(files.children().unwrap(), [name]);
        assert!(matches!(
            after.resize(MAX_BYTES as u64),
            Err(Error::NoSpace)
        ));
        drop(before);
        after.resize(MAX_BYTES as u64).unwrap();
        assert_eq!(after.len(), MAX_BYTES as u64);
        after.resize(3).unwrap();
        assert_eq!(after.snapshot().unwrap().as_ref(), b"\0\0\0");
        assert!(matches!(
            after.write(Some(u64::MAX), b"x"),
            Err(Error::TooLarge)
        ));
        assert_eq!(after.len(), 3);
    }
}
