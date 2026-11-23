//! Bounded, session-owned files. A removed name releases its file only after
//! the last descriptor or mapping closes, so a later create gets a new inode.

use super::Error;
use crate::user::mm::{PageSource, SourceIdentity};
use std::collections::BTreeMap;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

const MAX_BYTES: usize = 16 << 20;
const MAX_NODES: usize = 1024;
const FIRST_INODE: u32 = 0x5258_0001;
pub(super) const ROOT_INODE: u64 = (FIRST_INODE - 1) as u64;

#[derive(Debug)]
pub(super) struct Workspace {
    namespace: Mutex<Namespace>,
    budget: Arc<Mutex<Budget>>,
    pub(super) root: Arc<Directory>,
    pub(super) flavor: WorkspaceFlavor,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::user) enum WorkspaceFlavor {
    Linux,
    Darwin,
}

#[derive(Debug)]
struct Namespace {
    nodes: BTreeMap<String, Node>,
    inode: u32,
}

pub(in crate::user) struct Capacity {
    pub bytes_total: u64,
    pub bytes_available: u64,
    pub nodes_total: u64,
    pub nodes_available: u64,
}

#[derive(Debug, Default)]
struct Budget {
    nodes: usize,
    bytes: usize,
}

#[derive(Clone, Debug)]
pub(super) enum Node {
    File(Arc<WorkspaceFile>),
    Directory(Arc<Directory>),
}

/// Identity and permissions of a guest-created directory.
#[derive(Debug)]
pub struct Directory {
    pub(super) ino: u64,
    pub(super) mode: u32,
    pub(super) owner: (u32, u32),
    pub(super) parent: Option<Arc<Self>>,
    linked: AtomicBool,
    links: AtomicU32,
    budget: Option<Arc<Mutex<Budget>>>,
}

impl Directory {
    pub(crate) fn linked(&self) -> bool {
        self.linked.load(Ordering::Relaxed)
    }

    pub(crate) fn link_count(&self, flavor: WorkspaceFlavor) -> u32 {
        if flavor == WorkspaceFlavor::Linux && !self.linked() {
            return 0;
        }
        self.links.load(Ordering::Relaxed)
    }

    fn check_sticky(&self, uid: u32, child_owner: u32) -> Result<(), Error> {
        if self.mode & 0o1000 != 0 && uid != 0 && uid != self.owner.0 && uid != child_owner {
            return Err(Error::PermissionDenied);
        }
        Ok(())
    }

    pub(crate) fn permits(&self, need: u32, ids: (u32, u32), groups: &[u32]) -> bool {
        ids.0 == 0 || permitted(self.mode, self.owner, need, ids, groups)
    }

    pub(super) fn child_owner(&self, flavor: WorkspaceFlavor, ids: (u32, u32)) -> (u32, u32) {
        if flavor == WorkspaceFlavor::Darwin || self.mode & 0o2000 != 0 {
            (ids.0, self.owner.1)
        } else {
            ids
        }
    }
}

/// A regular file in the guest's private temporary workspace.
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
    pub(super) fn new(flavor: WorkspaceFlavor) -> Self {
        Self {
            namespace: Mutex::new(Namespace {
                nodes: BTreeMap::new(),
                inode: FIRST_INODE,
            }),
            budget: Arc::default(),
            root: Arc::new(Directory {
                ino: ROOT_INODE,
                mode: 0o1777,
                owner: (0, 0),
                parent: None,
                linked: AtomicBool::new(true),
                links: AtomicU32::new(2),
                budget: None,
            }),
            flavor,
        }
    }

    pub(super) fn capacity(&self) -> Result<Capacity, Error> {
        let used = self.budget.lock().map_err(|_| Error::Io)?;
        Ok(Capacity {
            bytes_total: MAX_BYTES as u64,
            bytes_available: (MAX_BYTES - used.bytes) as u64,
            nodes_total: MAX_NODES as u64,
            nodes_available: (MAX_NODES - used.nodes) as u64,
        })
    }

    pub(super) fn get(&self, path: &str) -> Result<Option<Node>, Error> {
        let namespace = self.namespace.lock().map_err(|_| Error::Io)?;
        Ok(namespace.nodes.get(path).cloned())
    }

    pub(super) fn create_directory(
        &self,
        path: String,
        mode: u32,
        owner: (u32, u32),
        parent: &Arc<Directory>,
    ) -> Result<(), Error> {
        let mut namespace = self.namespace.lock().map_err(|_| Error::Io)?;
        if !parent.linked() {
            return Err(Error::NotFound);
        }
        if namespace.nodes.contains_key(&path) {
            return Err(Error::Exists);
        }
        let mut budget = self.budget.lock().map_err(|_| Error::Io)?;
        let ino = allocate_inode(&mut namespace, &mut budget)?;
        let directory = Arc::new(Directory {
            ino,
            mode: mode & 0o7777,
            owner,
            parent: Some(parent.clone()),
            linked: AtomicBool::new(true),
            links: AtomicU32::new(2),
            budget: Some(self.budget.clone()),
        });
        namespace.nodes.insert(path, Node::Directory(directory));
        parent.links.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Atomically resolves an existing name or publishes a newly created inode.
    pub(super) fn create(
        &self,
        path: String,
        mode: u32,
        owner: (u32, u32),
        exclusive: bool,
        parent: &Directory,
    ) -> Result<Arc<WorkspaceFile>, Error> {
        let mut namespace = self.namespace.lock().map_err(|_| Error::Io)?;
        if !parent.linked() {
            return Err(Error::NotFound);
        }
        if let Some(entry) = namespace.nodes.get(&path) {
            return match (exclusive, entry) {
                (true, _) => Err(Error::Exists),
                (false, Node::File(file)) => Ok(file.clone()),
                (false, Node::Directory(_)) => Err(Error::IsDirectory),
            };
        }
        let mut budget = self.budget.lock().map_err(|_| Error::Io)?;
        let ino = allocate_inode(&mut namespace, &mut budget)?;
        let file = Arc::new(WorkspaceFile {
            ino,
            mode: mode & 0o7777,
            owner,
            linked: AtomicBool::new(true),
            budget: self.budget.clone(),
            contents: Mutex::new(Vec::new()),
        });
        namespace.nodes.insert(path, Node::File(file.clone()));
        Ok(file)
    }

    pub(super) fn unlink(&self, path: &str, uid: u32, parent: &Directory) -> Result<(), Error> {
        let mut namespace = self.namespace.lock().map_err(|_| Error::Io)?;
        if !parent.linked() {
            return Err(Error::NotFound);
        }
        let Node::File(file) = namespace.nodes.get(path).ok_or(Error::NotFound)? else {
            return Err(Error::IsDirectory);
        };
        parent.check_sticky(uid, file.owner.0)?;
        file.linked.store(false, Ordering::Relaxed);
        namespace.nodes.remove(path);
        Ok(())
    }

    pub(super) fn remove_directory(
        &self,
        path: &str,
        uid: u32,
        parent: &Directory,
    ) -> Result<(), Error> {
        let mut namespace = self.namespace.lock().map_err(|_| Error::Io)?;
        if !parent.linked() {
            return Err(Error::NotFound);
        }
        let Node::Directory(directory) = namespace.nodes.get(path).ok_or(Error::NotFound)? else {
            return Err(Error::NotDirectory);
        };
        parent.check_sticky(uid, directory.owner.0)?;
        let prefix = format!("{path}/");
        if namespace
            .nodes
            .range(prefix.clone()..)
            .next()
            .is_some_and(|(name, _)| name.starts_with(&prefix))
        {
            return Err(Error::NotEmpty);
        }
        directory.linked.store(false, Ordering::Relaxed);
        parent.links.fetch_sub(1, Ordering::Relaxed);
        namespace.nodes.remove(path);
        Ok(())
    }

    pub(super) fn children(&self, directory: &str) -> Result<Vec<String>, Error> {
        let namespace = self.namespace.lock().map_err(|_| Error::Io)?;
        let prefix = if directory.is_empty() {
            String::new()
        } else {
            format!("{directory}/")
        };
        Ok(namespace
            .nodes
            .range(prefix.clone()..)
            .map(|(name, _)| name)
            .take_while(|name| name.starts_with(&prefix))
            .map(|name| &name[prefix.len()..])
            .filter(|rest| !rest.contains('/'))
            .map(str::to_owned)
            .collect())
    }
}

fn allocate_inode(namespace: &mut Namespace, budget: &mut Budget) -> Result<u64, Error> {
    if budget.nodes >= MAX_NODES {
        return Err(Error::NoSpace);
    }
    let ino = namespace.inode;
    namespace.inode = ino.checked_add(1).ok_or(Error::NoSpace)?;
    budget.nodes += 1;
    Ok(u64::from(ino))
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
        permitted(self.mode, self.owner, need, ids, groups)
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

fn permitted(mode: u32, owner: (u32, u32), need: u32, ids: (u32, u32), groups: &[u32]) -> bool {
    let shift = if ids.0 == owner.0 {
        6
    } else if ids.1 == owner.1 || groups.contains(&owner.1) {
        3
    } else {
        0
    };
    need & !(mode >> shift) == 0
}

impl Drop for Directory {
    fn drop(&mut self) {
        if let Some(budget) = &self.budget
            && let Ok(mut budget) = budget.lock()
        {
            budget.nodes -= 1;
        }
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
            budget.nodes -= 1;
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
        let files = Workspace::new(WorkspaceFlavor::Linux);
        let name = "value";
        let before = files
            .create(name.into(), 0o600, (101, 102), true, &files.root)
            .unwrap();
        assert!(matches!(
            files.create(name.into(), 0o600, (103, 104), true, &files.root),
            Err(Error::Exists)
        ));
        assert!(Arc::ptr_eq(
            &files
                .create(name.into(), 0, (103, 104), false, &files.root)
                .unwrap(),
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
            files.unlink(name, 103, &files.root),
            Err(Error::PermissionDenied)
        ));
        files.unlink(name, 101, &files.root).unwrap();
        assert!(!before.linked());
        assert!(files.get(name).unwrap().is_none());
        let after = files
            .create(name.into(), 0o640, (103, 104), true, &files.root)
            .unwrap();
        assert!(after.linked());
        assert!(after.permits(4, (101, 102), &[104]));
        assert_ne!(before.ino, after.ino);
        assert_eq!(after.len(), 0);
        assert_eq!(before.len(), 8);
        assert_eq!(files.children("").unwrap(), [name]);
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
