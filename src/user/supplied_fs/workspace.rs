//! Bounded, session-owned files. A removed name releases its file only after
//! the last descriptor or mapping closes, so a later create gets a new inode.

use super::Error;
use crate::user::mm::{
    MappedFile, PageSource, SharedFileExtent, SharedObject, SourceIdentity, anonymous_file,
};
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, Weak};

#[cfg(target_os = "macos")]
mod darwin_allocation;
#[cfg(target_os = "linux")]
mod linux_allocation;
#[cfg(windows)]
mod mapped_windows;
mod metadata;
mod xattr;
pub(super) use metadata::Attributes;
pub(in crate::user) use metadata::{SetTime, TimeUpdate, Timestamp, Timestamps};
pub(in crate::user) use xattr::{
    MAX_VALUE as MAX_XATTR_VALUE, RESOURCE_FORK, Set as SetXattr, Xattrs,
};

const MAX_BYTES: usize = 16 << 20;
const MAX_NODES: usize = 1024;
const DARWIN_BLOCK_BYTES: usize = 4096;
const SHARED_CAPACITY: Option<u64> = if cfg!(windows) {
    Some(MAX_BYTES as u64)
} else {
    None
};
const FIRST_INODE: u32 = 0x5258_0001;
const WORKSPACE_DEVICE: u64 = 0x524158;
const DETACHED_DEVICE: u64 = 1 << 32;
static NEXT_DETACHED_INODE: AtomicU32 = AtomicU32::new(1);
const ROOT_INODE: u64 = (FIRST_INODE - 1) as u64;
const DARWIN_FOLDERS_INODE: u64 = ROOT_INODE - 1;
pub(super) const DARWIN_VAR_INODE: u64 = ROOT_INODE - 2;
pub(super) const DARWIN_FOLDERS: &str = "/var/folders";

// The installed Darwin dirhelper computes this component for the closed
// guest's virtual UID when it has no directory-service identity.
const DARWIN_USER_FOLDER: &str = "zyxvpxvq6csfxvn_n00003x00000z8";
pub(in crate::user) const DARWIN_GUEST_OWNER: (u32, u32) = (1000, 1000);

#[derive(Debug)]
pub(super) struct Workspace {
    namespace: Arc<Mutex<Namespace>>,
    budget: Arc<Mutex<Budget>>,
    pub(super) root: Arc<Directory>,
    darwin_folders: Option<Arc<Directory>>,
    pub(super) flavor: WorkspaceFlavor,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::user) enum WorkspaceFlavor {
    Linux,
    Darwin,
}

#[derive(Debug)]
struct Namespace {
    children: BTreeMap<u64, BTreeMap<String, Node>>,
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
    Symlink(Arc<WorkspaceSymlink>),
    Directory(Arc<Directory>),
}

#[derive(Clone, Debug)]
struct Location {
    parent: Arc<Directory>,
    name: String,
}

#[derive(Debug)]
enum LeafLocation {
    Linked(Location),
    Unlinked(String),
    Detached(String),
    Temporary(Location),
}

#[derive(Debug)]
struct Placement {
    namespace: Weak<Mutex<Namespace>>,
    location: Mutex<LeafLocation>,
    budget: Arc<Mutex<Budget>>,
}

impl Placement {
    fn new(workspace: &Workspace, parent: &Arc<Directory>, name: &str) -> Self {
        Self::with_location(
            workspace,
            LeafLocation::Linked(Location {
                parent: parent.clone(),
                name: name.to_owned(),
            }),
        )
    }

    fn with_location(workspace: &Workspace, location: LeafLocation) -> Self {
        Self {
            namespace: Arc::downgrade(&workspace.namespace),
            location: Mutex::new(location),
            budget: workspace.budget.clone(),
        }
    }

    fn path(&self, mark_unlinked: bool) -> Result<String, Error> {
        let namespace = self.namespace.upgrade().ok_or(Error::Io)?;
        let _namespace = namespace.lock().map_err(|_| Error::Io)?;
        let location = self.location.lock().map_err(|_| Error::Io)?;
        Ok(match &*location {
            LeafLocation::Linked(location) => location.clone().path(),
            LeafLocation::Unlinked(path) if mark_unlinked => format!("{path} (deleted)"),
            LeafLocation::Unlinked(path) | LeafLocation::Detached(path) => path.clone(),
            LeafLocation::Temporary(location) => format!("{} (deleted)", location.clone().path()),
        })
    }

    fn detach(&self) {
        let mut placement = self.location.lock().expect("workspace leaf location");
        let LeafLocation::Linked(location) = &*placement else {
            unreachable!("named workspace leaf");
        };
        *placement = LeafLocation::Unlinked(location.clone().path());
    }

    fn relocate(&self, location: Location) {
        *self.location.lock().expect("workspace leaf location") = LeafLocation::Linked(location);
    }
}

impl Drop for Placement {
    fn drop(&mut self) {
        if let Ok(mut budget) = self.budget.lock() {
            budget.nodes -= 1;
        }
    }
}

/// A rename changes the entry's location while leaving its inode and children intact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::user) enum Rename {
    Replace,
    Exclusive,
    Exchange,
}

/// Identity and permissions of a guest-created directory.
#[derive(Debug)]
pub struct Directory {
    pub(super) ino: u64,
    pub(super) attributes: Attributes,
    pub(super) root_path: &'static str,
    namespace: Weak<Mutex<Namespace>>,
    location: Option<Mutex<Location>>,
    linked: AtomicBool,
    links: AtomicU32,
    budget: Option<Arc<Mutex<Budget>>>,
}

impl Directory {
    pub(super) fn parent(&self) -> Option<Arc<Self>> {
        self.location.as_ref().map(|location| {
            location
                .lock()
                .expect("workspace directory location")
                .parent
                .clone()
        })
    }

    /// Return the current path, or the retained name of a detached directory.
    pub(crate) fn path(&self) -> Result<String, Error> {
        let namespace = self.namespace.upgrade().ok_or(Error::Io)?;
        let _namespace = namespace.lock().map_err(|_| Error::Io)?;
        match &self.location {
            Some(location) => Ok(location.lock().map_err(|_| Error::Io)?.clone().path()),
            None => Ok(self.root_path.into()),
        }
    }

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
        if self.attributes.mode() & 0o1000 != 0
            && uid != 0
            && uid != self.attributes.owner().0
            && uid != child_owner
        {
            return Err(Error::PermissionDenied);
        }
        Ok(())
    }

    pub(crate) fn permits(&self, need: u32, ids: (u32, u32), groups: &[u32]) -> bool {
        ids.0 == 0
            || permitted(
                self.attributes.mode(),
                self.attributes.owner(),
                need,
                ids,
                groups,
            )
    }

    pub(super) fn child_owner(&self, flavor: WorkspaceFlavor, ids: (u32, u32)) -> (u32, u32) {
        if flavor == WorkspaceFlavor::Darwin || self.attributes.mode() & 0o2000 != 0 {
            (ids.0, self.attributes.owner().1)
        } else {
            ids
        }
    }
}

/// A regular file in the guest's private temporary workspace.
#[derive(Debug)]
pub struct WorkspaceFile {
    inode: Arc<RegularFile>,
    placement: Placement,
}

#[derive(Debug)]
struct Inode {
    ino: u64,
    dev: u64,
    attributes: Attributes,
    links: AtomicU32,
    linkable_without_name: AtomicBool,
    budget: Arc<Mutex<Budget>>,
}

#[derive(Debug)]
struct RegularFile {
    metadata: Inode,
    contents: Mutex<Contents>,
    flavor: WorkspaceFlavor,
}

#[derive(Debug)]
enum Contents {
    Bytes(ByteContents),
    Shared(SharedContents),
}

#[derive(Clone, Debug)]
struct ByteContents {
    data: Arc<Vec<u8>>,
    blocks: Option<MemoryBlocks>,
}

#[derive(Clone, Debug)]
struct MemoryBlocks {
    bytes: usize,
    written: Arc<BTreeSet<usize>>,
}

impl MemoryBlocks {
    fn sectors(&self) -> i64 {
        (self.written.len() * (self.bytes / 512)) as i64
    }
}

#[derive(Debug)]
struct SharedContents {
    file: MappedFile,
    extent: Arc<SharedFileExtent>,
    reservation: usize,
    #[cfg(target_os = "linux")]
    linux_tail: Option<linux_allocation::Tail>,
    #[cfg(unix)]
    storage_page: u64,
}

impl ByteContents {
    fn new(data: Arc<Vec<u8>>, flavor: WorkspaceFlavor) -> Self {
        let block_bytes = match flavor {
            WorkspaceFlavor::Darwin if cfg!(target_os = "macos") => Some(DARWIN_BLOCK_BYTES),
            #[cfg(target_os = "linux")]
            WorkspaceFlavor::Linux => Some(crate::user::mm::native_page_size() as usize),
            _ => None,
        };
        let blocks = block_bytes.map(|bytes| MemoryBlocks {
            bytes,
            written: Arc::new((0..data.len().div_ceil(bytes)).collect()),
        });
        Self { data, blocks }
    }

    fn resize(&mut self, len: usize) -> Result<(), Error> {
        let old = self.data.len();
        if len > old {
            let data = Arc::make_mut(&mut self.data);
            data.try_reserve_exact(len - old)
                .map_err(|_| Error::NoSpace)?;
            data.resize(len, 0);
        } else {
            if len == 0 {
                self.data = Arc::default();
            } else {
                let data = Arc::make_mut(&mut self.data);
                data.truncate(len);
                data.shrink_to_fit();
            }
            if let Some(blocks) = &mut self.blocks {
                let first_discarded = len.div_ceil(blocks.bytes);
                if blocks.written.range(first_discarded..).next().is_some() {
                    Arc::make_mut(&mut blocks.written).split_off(&first_discarded);
                }
            }
        }
        Ok(())
    }

    fn write(&mut self, start: usize, input: &[u8]) {
        let end = start + input.len();
        Arc::make_mut(&mut self.data)[start..end].copy_from_slice(input);
        if let Some(blocks) = &mut self.blocks {
            let touched = start / blocks.bytes..end.div_ceil(blocks.bytes);
            Arc::make_mut(&mut blocks.written).extend(touched);
        }
    }
}

impl Contents {
    fn empty(flavor: WorkspaceFlavor) -> Self {
        Self::Bytes(ByteContents::new(Arc::default(), flavor))
    }

    fn len(&self) -> usize {
        match self {
            Self::Bytes(bytes) => bytes.data.len(),
            Self::Shared(shared) => shared.extent.len() as usize,
        }
    }

    fn reservation(&self) -> usize {
        match self {
            Self::Bytes(_) => 0,
            Self::Shared(shared) => shared.reservation,
        }
    }

    fn reservation_after_resize(&self, old: usize, new: usize) -> usize {
        #[cfg(target_os = "linux")]
        if let Self::Shared(shared) = self
            && let Some(tail) = &shared.linux_tail
        {
            return tail.charge_after_resize(old, new);
        }
        if new > old {
            self.reservation().saturating_sub(new - old)
        } else {
            0
        }
    }

    fn shared(&mut self) -> Result<&mut SharedContents, Error> {
        if let Self::Bytes(bytes) = self {
            *self = Self::Shared(SharedContents::new(bytes)?);
        }
        match self {
            Self::Shared(shared) => Ok(shared),
            Self::Bytes(_) => unreachable!("workspace file backing initialized"),
        }
    }

    fn snapshot(&self) -> Result<Arc<Vec<u8>>, Error> {
        match self {
            Self::Bytes(bytes) => Ok(bytes.data.clone()),
            Self::Shared(shared) => {
                let mut bytes = Vec::new();
                bytes
                    .try_reserve_exact(self.len())
                    .map_err(|_| Error::NoSpace)?;
                bytes.resize(self.len(), 0);
                let count = shared.file.read_at(0, &mut bytes).map_err(|_| Error::Io)?;
                if count != bytes.len() {
                    return Err(Error::Io);
                }
                Ok(Arc::new(bytes))
            }
        }
    }
}

impl SharedContents {
    fn new(bytes: &ByteContents) -> Result<Self, Error> {
        let file = anonymous_file().map_err(|_| Error::Io)?;
        #[cfg(windows)]
        mapped_windows::mark_sparse(&file).map_err(|_| Error::Io)?;
        let len = bytes.data.len();
        file.set_len(SHARED_CAPACITY.unwrap_or(len as u64))
            .map_err(|_| Error::Io)?;
        let file = MappedFile::new(file);
        if let Some(blocks) = &bytes.blocks {
            for block in blocks.written.iter() {
                let start = block * blocks.bytes;
                let end = (start + blocks.bytes).min(len);
                file.write_all_at(start as u64, &bytes.data[start..end])
                    .map_err(|_| Error::Io)?;
            }
        } else {
            file.write_all_at(0, &bytes.data).map_err(|_| Error::Io)?;
        }
        Ok(Self {
            file,
            extent: Arc::new(SharedFileExtent::new(len as u64)),
            reservation: 0,
            #[cfg(target_os = "linux")]
            linux_tail: None,
            #[cfg(unix)]
            storage_page: 1,
        })
    }

    #[cfg(unix)]
    fn ensure_mapping_page(&mut self, guest_page: u64) -> io::Result<()> {
        // Hosts with smaller pages need real backing for every page of a
        // guest's partial final page. Equal or larger native pages already
        // supply that padding through the file mapping.
        if guest_page > crate::user::mm::native_page_size() && guest_page > self.storage_page {
            let len = self.extent.len().div_ceil(guest_page) * guest_page;
            self.file.set_len(len)?;
            self.storage_page = guest_page;
        }
        Ok(())
    }

    fn resize(&self, identity: SourceIdentity, old: usize, new: usize) -> Result<(), Error> {
        if new < old {
            // Drop resident pages in every alias before the native storage
            // can cease to back them. Closed guest processes run serially.
            self.extent.set_len(new as u64);
            self.extent.invalidate(identity, new as u64);
        }
        if self.resize_storage(old, new).is_err() {
            self.extent.set_len(old as u64);
            return Err(Error::Io);
        }
        self.extent.set_len(new as u64);
        Ok(())
    }

    #[cfg(unix)]
    fn resize_storage(&self, old: usize, new: usize) -> io::Result<()> {
        let old = old as u64;
        let new = new as u64;
        let rounded = new.div_ceil(self.storage_page) * self.storage_page;
        // Native ftruncate clears tails when physical size changes. Clear
        // the surviving tail explicitly when the file has extra padding.
        if new < old && rounded > new {
            let zeros = [0; crate::user::mm::PAGE_SIZE as usize];
            let mut offset = new;
            while offset < rounded {
                let count = (rounded - offset).min(zeros.len() as u64);
                self.file.write_all_at(offset, &zeros[..count as usize])?;
                offset += count;
            }
        }
        self.file.set_len(rounded)
    }

    #[cfg(not(any(unix, windows)))]
    fn resize_storage(&self, _old: usize, new: usize) -> io::Result<()> {
        self.file.set_len(new as u64)
    }

    #[cfg(windows)]
    fn resize_storage(&self, old: usize, new: usize) -> io::Result<()> {
        // A Windows file with a section cannot change its native length.
        // Clear both a truncated tail and the part of a partial guest page
        // that becomes visible on extension.
        mapped_windows::zero_range(&self.file, old.min(new) as u64, old.max(new) as u64)
    }
}

/// A symbolic link created in the guest's private temporary workspace.
#[derive(Debug)]
pub struct WorkspaceSymlink {
    inode: Arc<SymbolicLink>,
    placement: Placement,
}

#[derive(Debug)]
struct SymbolicLink {
    metadata: Inode,
    target: Vec<u8>,
}

impl Workspace {
    pub(super) fn new(flavor: WorkspaceFlavor) -> Self {
        let mut children = BTreeMap::from([(ROOT_INODE, BTreeMap::new())]);
        if flavor == WorkspaceFlavor::Darwin {
            children.insert(DARWIN_FOLDERS_INODE, BTreeMap::new());
        }
        let namespace = Arc::new(Mutex::new(Namespace {
            children,
            inode: FIRST_INODE,
        }));
        let budget = Arc::new(Mutex::new(Budget::default()));
        let root = |ino, root_path, mode| {
            Arc::new(Directory {
                ino,
                attributes: Attributes::new(mode, (0, 0), budget.clone()),
                root_path,
                namespace: Arc::downgrade(&namespace),
                location: None,
                linked: AtomicBool::new(true),
                links: AtomicU32::new(2),
                budget: None,
            })
        };
        let workspace = Self {
            namespace: namespace.clone(),
            budget: budget.clone(),
            root: root(ROOT_INODE, super::TEMP_DIRECTORY, 0o1777),
            darwin_folders: (flavor == WorkspaceFlavor::Darwin)
                .then(|| root(DARWIN_FOLDERS_INODE, DARWIN_FOLDERS, 0o755)),
            flavor,
        };
        if let Some(folders) = &workspace.darwin_folders {
            let prefix = workspace.seed_directory(folders, "zz", 0o755, (0, 0));
            let user =
                workspace.seed_directory(&prefix, DARWIN_USER_FOLDER, 0o755, DARWIN_GUEST_OWNER);
            for (name, mode) in [("0", 0o755), ("T", 0o700), ("C", 0o700)] {
                workspace.seed_directory(&user, name, mode, DARWIN_GUEST_OWNER);
            }
        }
        workspace
    }

    fn seed_directory(
        &self,
        parent: &Arc<Directory>,
        name: &str,
        mode: u32,
        owner: (u32, u32),
    ) -> Arc<Directory> {
        self.create_directory(name.into(), mode, owner, parent)
            .expect("preallocated workspace has room for its default directories");
        let Some(Node::Directory(directory)) = self
            .get(parent, name)
            .expect("new workspace directory is readable")
        else {
            unreachable!("new workspace directory");
        };
        directory
    }

    pub(super) fn roots(&self) -> impl Iterator<Item = &Arc<Directory>> {
        std::iter::once(&self.root).chain(self.darwin_folders.iter())
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

    pub(super) fn get(
        &self,
        directory: &Arc<Directory>,
        path: &str,
    ) -> Result<Option<Node>, Error> {
        let namespace = self.namespace.lock().map_err(|_| Error::Io)?;
        let mut parent = directory.ino;
        let mut components = path.split('/').peekable();
        while let Some(name) = components.next() {
            let node = namespace.children[&parent].get(name);
            if components.peek().is_none() {
                return Ok(node.cloned());
            }
            let Some(Node::Directory(directory)) = node else {
                return Ok(None);
            };
            parent = directory.ino;
        }
        Ok(None)
    }

    pub(super) fn create_directory(
        &self,
        name: String,
        mode: u32,
        owner: (u32, u32),
        parent: &Arc<Directory>,
    ) -> Result<(), Error> {
        let mut namespace = self.namespace.lock().map_err(|_| Error::Io)?;
        if namespace.directory(parent)?.contains_key(&name) {
            return Err(Error::Exists);
        }
        let mut budget = self.budget.lock().map_err(|_| Error::Io)?;
        let ino = allocate_inode(&mut namespace, &mut budget)?;
        let location = Location {
            parent: parent.clone(),
            name: name.clone(),
        };
        let directory = Arc::new(Directory {
            ino,
            attributes: Attributes::new(mode, owner, self.budget.clone()),
            root_path: parent.root_path,
            namespace: Arc::downgrade(&self.namespace),
            location: Some(Mutex::new(location)),
            linked: AtomicBool::new(true),
            links: AtomicU32::new(2),
            budget: Some(self.budget.clone()),
        });
        namespace.children.insert(ino, BTreeMap::new());
        namespace
            .directory_mut(parent)
            .insert(name, Node::Directory(directory));
        parent.links.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Atomically resolves an existing name or publishes a newly created inode.
    pub(super) fn create(
        &self,
        name: String,
        mode: u32,
        owner: (u32, u32),
        exclusive: bool,
        parent: &Arc<Directory>,
    ) -> Result<(Arc<WorkspaceFile>, bool), Error> {
        let mut namespace = self.namespace.lock().map_err(|_| Error::Io)?;
        if let Some(entry) = namespace.directory(parent)?.get(&name) {
            return match (exclusive, entry) {
                (true, _) => Err(Error::Exists),
                (false, Node::File(file)) => Ok((file.clone(), false)),
                (false, Node::Directory(_)) => Err(Error::IsDirectory),
                (false, Node::Symlink(_)) => Err(Error::LinkLoop),
            };
        }
        let mut budget = self.budget.lock().map_err(|_| Error::Io)?;
        let ino = allocate_inode(&mut namespace, &mut budget)?;
        let file = Arc::new(WorkspaceFile {
            inode: Arc::new(RegularFile {
                metadata: self.inode(ino, mode & 0o7777, owner),
                contents: Mutex::new(Contents::empty(self.flavor)),
                flavor: self.flavor,
            }),
            placement: Placement::new(self, parent, &name),
        });
        namespace
            .directory_mut(parent)
            .insert(name, Node::File(file.clone()));
        if self.flavor == WorkspaceFlavor::Darwin {
            parent.links.fetch_add(1, Ordering::Relaxed);
        }
        Ok((file, true))
    }

    pub(super) fn create_detached(
        &self,
        display_path: String,
        mode: u32,
        owner: (u32, u32),
    ) -> Result<Arc<WorkspaceFile>, Error> {
        let mut budget = self.budget.lock().map_err(|_| Error::Io)?;
        if budget.nodes >= MAX_NODES {
            return Err(Error::NoSpace);
        }
        // A detached inode can be registered across guest sessions. Its
        // device and monotonic inode distinguish it from any named workspace.
        let ino = NEXT_DETACHED_INODE
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |ino| {
                ino.checked_add(1)
            })
            .map_err(|_| Error::NoSpace)?;
        budget.nodes += 1;
        let mut metadata = self.inode(u64::from(ino), mode, owner);
        metadata.dev = DETACHED_DEVICE;
        metadata.links = AtomicU32::new(0);
        Ok(Arc::new(WorkspaceFile {
            inode: Arc::new(RegularFile {
                metadata,
                contents: Mutex::new(Contents::empty(self.flavor)),
                flavor: self.flavor,
            }),
            placement: Placement::with_location(self, LeafLocation::Detached(display_path)),
        }))
    }

    pub(super) fn create_tmpfile(
        &self,
        parent: &Arc<Directory>,
        mode: u32,
        ids: (u32, u32),
        groups: &[u32],
        exclusive: bool,
    ) -> Result<Arc<WorkspaceFile>, Error> {
        let mut namespace = self.namespace.lock().map_err(|_| Error::Io)?;
        if !parent.namespace.ptr_eq(&Arc::downgrade(&self.namespace)) {
            return Err(Error::CrossDevice);
        }
        namespace.directory(parent)?;
        if !parent.permits(3, ids, groups) {
            return Err(Error::AccessDenied);
        }
        let owner = parent.child_owner(self.flavor, ids);
        let mut budget = self.budget.lock().map_err(|_| Error::Io)?;
        let ino = allocate_inode(&mut namespace, &mut budget)?;
        let mut metadata = self.inode(ino, mode & 0o7777, owner);
        metadata.links = AtomicU32::new(0);
        metadata.linkable_without_name = AtomicBool::new(!exclusive);
        Ok(Arc::new(WorkspaceFile {
            inode: Arc::new(RegularFile {
                metadata,
                contents: Mutex::new(Contents::empty(self.flavor)),
                flavor: self.flavor,
            }),
            placement: Placement::with_location(
                self,
                LeafLocation::Temporary(Location {
                    parent: parent.clone(),
                    name: format!("#{ino}"),
                }),
            ),
        }))
    }

    pub(super) fn create_symlink(
        &self,
        name: String,
        target: Vec<u8>,
        mode: u32,
        owner: (u32, u32),
        parent: &Arc<Directory>,
    ) -> Result<(), Error> {
        let mut namespace = self.namespace.lock().map_err(|_| Error::Io)?;
        if namespace.directory(parent)?.contains_key(&name) {
            return Err(Error::Exists);
        }
        let mut budget = self.budget.lock().map_err(|_| Error::Io)?;
        if target.len() > MAX_BYTES - budget.bytes {
            return Err(Error::NoSpace);
        }
        let ino = allocate_inode(&mut namespace, &mut budget)?;
        budget.bytes += target.len();
        let link = Arc::new(WorkspaceSymlink {
            inode: Arc::new(SymbolicLink {
                metadata: self.inode(ino, mode, owner),
                target,
            }),
            placement: Placement::new(self, parent, &name),
        });
        namespace
            .directory_mut(parent)
            .insert(name, Node::Symlink(link));
        if self.flavor == WorkspaceFlavor::Darwin {
            parent.links.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Clone one guest leaf and publish it only after its full quota charge.
    pub(super) fn clone_leaf(
        &self,
        source: &Node,
        parent: &Arc<Directory>,
        name: String,
        ids: (u32, u32),
        copy_owner: bool,
        opened_for_read: bool,
    ) -> Result<(), Error> {
        enum Data {
            File(ByteContents),
            Symlink(Vec<u8>),
        }
        let mut namespace = self.namespace.lock().map_err(|_| Error::Io)?;
        if namespace.directory(parent)?.contains_key(&name) {
            return Err(Error::Exists);
        }
        let (data, attributes, size) = match source {
            Node::File(file) => {
                if !opened_for_read && !file.permits(4, ids, &[]) {
                    return Err(Error::AccessDenied);
                }
                let contents = file.inode.contents.lock().map_err(|_| Error::Io)?;
                let bytes = match &*contents {
                    Contents::Bytes(bytes) => bytes.clone(),
                    Contents::Shared(_) => ByteContents::new(contents.snapshot()?, self.flavor),
                };
                (Data::File(bytes), file.attributes(), contents.len())
            }
            Node::Symlink(link) => {
                let target = link.target();
                (
                    Data::Symlink(target.to_vec()),
                    link.attributes(),
                    target.len(),
                )
            }
            Node::Directory(_) => return Err(Error::IsDirectory),
        };
        let (mode, times, values, extra_bytes) = attributes.clone_values()?;
        let charge = size + extra_bytes;
        let owner = if copy_owner && ids.0 == 0 {
            attributes.owner()
        } else {
            parent.child_owner(self.flavor, ids)
        };
        let mut budget = self.budget.lock().map_err(|_| Error::Io)?;
        if charge > MAX_BYTES - budget.bytes {
            return Err(Error::NoSpace);
        }
        let ino = allocate_inode(&mut namespace, &mut budget)?;
        budget.bytes += charge;
        drop(budget);
        let metadata = Inode {
            ino,
            dev: WORKSPACE_DEVICE,
            attributes: Attributes::from_clone(
                mode,
                times,
                owner,
                Xattrs::from_charged_values(values, self.budget.clone()),
            ),
            links: AtomicU32::new(1),
            linkable_without_name: AtomicBool::new(false),
            budget: self.budget.clone(),
        };
        let placement = Placement::new(self, parent, &name);
        let node = match data {
            Data::File(contents) => Node::File(Arc::new(WorkspaceFile {
                inode: Arc::new(RegularFile {
                    metadata,
                    contents: Mutex::new(Contents::Bytes(contents)),
                    flavor: self.flavor,
                }),
                placement,
            })),
            Data::Symlink(target) => Node::Symlink(Arc::new(WorkspaceSymlink {
                inode: Arc::new(SymbolicLink { metadata, target }),
                placement,
            })),
        };
        namespace.directory_mut(parent).insert(name, node);
        parent.links.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn inode(&self, ino: u64, mode: u32, owner: (u32, u32)) -> Inode {
        Inode {
            ino,
            dev: WORKSPACE_DEVICE,
            attributes: Attributes::new(mode, owner, self.budget.clone()),
            links: AtomicU32::new(1),
            linkable_without_name: AtomicBool::new(false),
            budget: self.budget.clone(),
        }
    }

    pub(super) fn link(
        &self,
        source: &Node,
        parent: &Arc<Directory>,
        name: String,
        ids: (u32, u32),
        groups: &[u32],
    ) -> Result<(), Error> {
        let mut namespace = self.namespace.lock().map_err(|_| Error::Io)?;
        if namespace.directory(parent)?.contains_key(&name) {
            return Err(Error::Exists);
        }
        let (metadata, placement) = source.leaf().ok_or(Error::PermissionDenied)?;
        if !placement.namespace.ptr_eq(&Arc::downgrade(&self.namespace)) {
            return Err(Error::CrossDevice);
        }
        if metadata.links.load(Ordering::Relaxed) == 0
            && !metadata.linkable_without_name.load(Ordering::Relaxed)
        {
            return Err(Error::NotFound);
        }
        if self.flavor == WorkspaceFlavor::Linux
            && ids.0 != 0
            && ids.0 != metadata.attributes.owner().0
            && !source.permits_unowned_link(ids, groups)
        {
            return Err(Error::PermissionDenied);
        }
        let mut budget = self.budget.lock().map_err(|_| Error::Io)?;
        if budget.nodes >= MAX_NODES {
            return Err(Error::NoSpace);
        }
        budget.nodes += 1;
        let location = Placement::new(self, parent, &name);
        let node = match source {
            Node::File(file) => Node::File(Arc::new(WorkspaceFile {
                inode: file.inode.clone(),
                placement: location,
            })),
            Node::Symlink(link) => Node::Symlink(Arc::new(WorkspaceSymlink {
                inode: link.inode.clone(),
                placement: location,
            })),
            Node::Directory(_) => unreachable!("hard-link source is a leaf"),
        };
        metadata.links.fetch_add(1, Ordering::Relaxed);
        metadata
            .linkable_without_name
            .store(false, Ordering::Relaxed);
        namespace.directory_mut(parent).insert(name, node);
        if self.flavor == WorkspaceFlavor::Darwin {
            parent.links.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    pub(super) fn unlink(&self, name: &str, uid: u32, parent: &Directory) -> Result<(), Error> {
        let mut namespace = self.namespace.lock().map_err(|_| Error::Io)?;
        let node = namespace
            .directory(parent)?
            .get(name)
            .ok_or(Error::NotFound)?;
        if matches!(node, Node::Directory(_)) {
            return Err(Error::IsDirectory);
        }
        parent.check_sticky(uid, node.uid())?;
        namespace.detach(parent, name, self.flavor);
        Ok(())
    }

    pub(super) fn remove_directory(
        &self,
        name: &str,
        uid: u32,
        parent: &Directory,
    ) -> Result<(), Error> {
        let mut namespace = self.namespace.lock().map_err(|_| Error::Io)?;
        let Node::Directory(directory) = namespace
            .directory(parent)?
            .get(name)
            .ok_or(Error::NotFound)?
        else {
            return Err(Error::NotDirectory);
        };
        parent.check_sticky(uid, directory.attributes.owner().0)?;
        if !namespace.directory(directory)?.is_empty() {
            return Err(Error::NotEmpty);
        }
        namespace.detach(parent, name, self.flavor);
        Ok(())
    }

    pub(super) fn rename(
        &self,
        from: (&Arc<Directory>, &str),
        to: (&Arc<Directory>, &str),
        uid: u32,
        how: Rename,
    ) -> Result<(), Error> {
        let (old_parent, old_name) = from;
        let (new_parent, new_name) = to;
        let mut namespace = self.namespace.lock().map_err(|_| Error::Io)?;
        let source = namespace
            .directory(old_parent)?
            .get(old_name)
            .ok_or(Error::NotFound)?;
        let target = namespace.directory(new_parent)?.get(new_name);
        if how == Rename::Exchange && target.is_none() {
            return Err(Error::NotFound);
        }
        let same = Arc::ptr_eq(old_parent, new_parent) && old_name == new_name;
        if target.is_some()
            && how == Rename::Exclusive
            && (!same || self.flavor == WorkspaceFlavor::Linux)
        {
            return Err(Error::Exists);
        }
        if same {
            return Ok(());
        }
        if target.is_some_and(|target| source.same_inode(target))
            && (how == Rename::Replace
                || (how == Rename::Exchange && self.flavor == WorkspaceFlavor::Linux))
        {
            return Ok(());
        }
        old_parent.check_sticky(uid, source.uid())?;
        source.reject_ancestor(new_parent)?;
        if let Some(target) = target {
            new_parent.check_sticky(uid, target.uid())?;
            if how == Rename::Exchange {
                target.reject_ancestor(old_parent)?;
            } else {
                match (source, target) {
                    (Node::Directory(_), Node::Directory(directory)) => {
                        if !namespace.directory(directory)?.is_empty() {
                            return Err(Error::NotEmpty);
                        }
                    }
                    (Node::Directory(_), _) => return Err(Error::NotDirectory),
                    (_, Node::Directory(_)) => return Err(Error::IsDirectory),
                    _ => {}
                }
                namespace.detach(new_parent, new_name, self.flavor);
            }
        }
        let source = namespace
            .directory_mut(old_parent)
            .remove(old_name)
            .expect("checked source");
        if how == Rename::Exchange {
            let target = namespace
                .directory_mut(new_parent)
                .remove(new_name)
                .expect("checked exchange target");
            target.relocate(new_parent, old_parent, old_name, self.flavor);
            namespace
                .directory_mut(old_parent)
                .insert(old_name.into(), target);
        }
        source.relocate(old_parent, new_parent, new_name, self.flavor);
        namespace
            .directory_mut(new_parent)
            .insert(new_name.into(), source);
        Ok(())
    }

    pub(super) fn children(&self, directory: &Directory) -> Result<Vec<String>, Error> {
        let namespace = self.namespace.lock().map_err(|_| Error::Io)?;
        Ok(namespace.directory(directory)?.keys().cloned().collect())
    }
}

impl Namespace {
    fn directory(&self, directory: &Directory) -> Result<&BTreeMap<String, Node>, Error> {
        self.children.get(&directory.ino).ok_or(Error::NotFound)
    }

    fn directory_mut(&mut self, directory: &Directory) -> &mut BTreeMap<String, Node> {
        self.children
            .get_mut(&directory.ino)
            .expect("checked directory")
    }

    fn detach(&mut self, parent: &Directory, name: &str, flavor: WorkspaceFlavor) {
        let node = self
            .directory_mut(parent)
            .remove(name)
            .expect("checked directory entry");
        if node.contributes_parent_link(flavor) {
            parent.links.fetch_sub(1, Ordering::Relaxed);
        }
        match node {
            Node::Directory(directory) => {
                self.children.remove(&directory.ino);
                directory.linked.store(false, Ordering::Relaxed);
            }
            Node::File(file) => {
                file.placement.detach();
                file.inode.metadata.links.fetch_sub(1, Ordering::Relaxed);
            }
            Node::Symlink(link) => {
                link.placement.detach();
                link.inode.metadata.links.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }
}

impl Location {
    /// The caller holds the namespace lock while walking parent identities.
    fn path(self) -> String {
        let mut names = vec![self.name];
        let mut parent = self.parent;
        while let Some(location) = &parent.location {
            let location = location
                .lock()
                .expect("workspace ancestor location")
                .clone();
            names.push(location.name);
            parent = location.parent;
        }
        let mut path = String::from(parent.root_path);
        for name in names.iter().rev() {
            path.push('/');
            path.push_str(name);
        }
        path
    }
}

impl Node {
    fn uid(&self) -> u32 {
        match self {
            Self::File(file) => file.ownership().0,
            Self::Symlink(link) => link.owner().0,
            Self::Directory(directory) => directory.attributes.owner().0,
        }
    }

    fn leaf(&self) -> Option<(&Inode, &Placement)> {
        match self {
            Self::File(file) => Some((&file.inode.metadata, &file.placement)),
            Self::Symlink(link) => Some((&link.inode.metadata, &link.placement)),
            Self::Directory(_) => None,
        }
    }

    fn permits_unowned_link(&self, ids: (u32, u32), groups: &[u32]) -> bool {
        matches!(self, Self::File(file)
            if file.mode() & 0o4000 == 0
                && file.mode() & 0o2010 != 0o2010
                && file.permits(6, ids, groups))
    }

    fn same_inode(&self, other: &Self) -> bool {
        match (self.leaf(), other.leaf()) {
            (Some((left, _)), Some((right, _))) => std::ptr::eq(left, right),
            _ => false,
        }
    }
    fn reject_ancestor(&self, new_parent: &Arc<Directory>) -> Result<(), Error> {
        if let Self::Directory(directory) = self {
            let mut ancestor = Some(new_parent.clone());
            while let Some(parent) = ancestor {
                if Arc::ptr_eq(&parent, directory) {
                    return Err(Error::InvalidPath);
                }
                ancestor = parent.parent();
            }
        }
        Ok(())
    }

    /// APFS reports 2 plus all immediate entries. Linux counts subdirectories.
    fn contributes_parent_link(&self, flavor: WorkspaceFlavor) -> bool {
        flavor == WorkspaceFlavor::Darwin || matches!(self, Self::Directory(_))
    }

    fn relocate(
        &self,
        old_parent: &Arc<Directory>,
        new_parent: &Arc<Directory>,
        name: &str,
        flavor: WorkspaceFlavor,
    ) {
        if !Arc::ptr_eq(old_parent, new_parent) && self.contributes_parent_link(flavor) {
            old_parent.links.fetch_sub(1, Ordering::Relaxed);
            new_parent.links.fetch_add(1, Ordering::Relaxed);
        }
        let location = Location {
            parent: new_parent.clone(),
            name: name.to_owned(),
        };
        match self {
            Self::Directory(directory) => {
                *directory
                    .location
                    .as_ref()
                    .expect("non-root directory")
                    .lock()
                    .expect("workspace directory location") = location;
            }
            Self::File(file) => file.placement.relocate(location),
            Self::Symlink(link) => link.placement.relocate(location),
        }
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
    #[cfg(target_os = "linux")]
    pub(in crate::user) fn linux_allocated_blocks(&self) -> Option<i64> {
        use std::os::unix::fs::MetadataExt;
        if self.inode.flavor != WorkspaceFlavor::Linux {
            return None;
        }
        let contents = self.inode.contents.lock().ok()?;
        match &*contents {
            Contents::Bytes(bytes) => bytes.blocks.as_ref().map(MemoryBlocks::sectors),
            Contents::Shared(shared) => Some(shared.file.metadata().ok()?.blocks() as i64),
        }
    }

    #[cfg(target_os = "linux")]
    pub(in crate::user) fn linux_allocate(
        &self,
        mode: i32,
        offset: i64,
        length: i64,
        end: u64,
    ) -> io::Result<()> {
        let mut contents = self
            .inode
            .contents
            .lock()
            .map_err(|_| io::Error::other(Error::Io))?;
        let old = contents.len();
        let new = if mode == 0 {
            let end = usize::try_from(end)
                .ok()
                .filter(|&end| end <= MAX_BYTES)
                .ok_or_else(|| io::Error::from_raw_os_error(libc::EFBIG))?;
            old.max(end)
        } else {
            old
        };
        let mut tail = match &*contents {
            Contents::Shared(shared) => shared.linux_tail.clone().unwrap_or_default(),
            Contents::Bytes(_) => linux_allocation::Tail::default(),
        };
        if mode == libc::FALLOC_FL_KEEP_SIZE {
            tail.reserve(offset as u64, end, new)?;
        }
        let retained = tail.charge_after_resize(old, new);
        tail.resize(old, new);
        let current_charge = old + contents.reservation();
        let new_charge = new + retained;
        let mut budget = self
            .inode
            .metadata
            .budget
            .lock()
            .map_err(|_| io::Error::other(Error::Io))?;
        if new_charge.saturating_sub(current_charge) > MAX_BYTES - budget.bytes {
            return Err(io::Error::from_raw_os_error(libc::ENOSPC));
        }
        let shared = contents.shared().map_err(io::Error::other)?;
        linux_allocation::allocate(&shared.file, mode, offset, length)?;
        shared.extent.set_len(new as u64);
        shared.linux_tail = Some(tail);
        shared.reservation = retained;
        budget.bytes = budget.bytes - current_charge + new_charge;
        drop(budget);
        self.attributes().modified();
        Ok(())
    }

    fn uses_darwin_backing(&self) -> bool {
        cfg!(target_os = "macos") && self.inode.flavor == WorkspaceFlavor::Darwin
    }

    pub(in crate::user) fn darwin_allocated_blocks(&self) -> Result<Option<i64>, Error> {
        #[cfg(target_os = "macos")]
        if self.uses_darwin_backing() {
            use std::os::unix::fs::MetadataExt;
            let blocks = match &*self.inode.contents.lock().map_err(|_| Error::Io)? {
                Contents::Bytes(bytes) => bytes.blocks.as_ref().map_or(0, MemoryBlocks::sectors),
                Contents::Shared(shared) => {
                    shared.file.metadata().map_err(|_| Error::Io)?.blocks() as i64
                }
            };
            let fork_blocks = self
                .attributes()
                .xattrs(0, (0, 0), &[])?
                .resource_parent_blocks()?;
            return Ok(Some(blocks + fork_blocks));
        }
        Ok(None)
    }

    /// Reserve native storage on this guest-owned data fork. The workspace
    /// charges a whole block per touched allocation unit. File growth uses
    /// that credit and a shrinking truncate releases it.
    #[cfg(target_os = "macos")]
    pub(in crate::user) fn darwin_preallocate(
        &self,
        flags: u32,
        length: u64,
    ) -> (io::Result<()>, i64) {
        let allocate = || {
            if !self.uses_darwin_backing() {
                return Err(io::Error::from_raw_os_error(libc::ENOTSUP));
            }
            let mut contents = self
                .inode
                .contents
                .lock()
                .map_err(|_| io::Error::other(Error::Io))?;
            let mut budget = self
                .inode
                .metadata
                .budget
                .lock()
                .map_err(|_| io::Error::other(Error::Io))?;
            let request = darwin_allocation::Request::new(flags, length, budget.bytes)?;
            let shared = contents.shared().map_err(io::Error::other)?;
            let (result, allocated, credit) = request.reserve(&shared.file);
            shared.reservation += credit;
            budget.bytes += credit;
            Ok((result, allocated))
        };
        allocate().unwrap_or_else(|error| (Err(error), 0))
    }

    pub(crate) fn is_tmpfile(&self) -> bool {
        self.placement
            .location
            .lock()
            .is_ok_and(|location| matches!(*location, LeafLocation::Temporary(_)))
    }

    pub(crate) fn path(&self) -> Result<String, Error> {
        self.placement.path(false)
    }

    /// The pathname shown by a Linux procfs descriptor link.
    pub(crate) fn proc_path(&self) -> Result<String, Error> {
        self.placement.path(true)
    }

    pub(crate) fn mode(&self) -> u32 {
        self.inode.metadata.attributes.mode()
    }

    pub(crate) fn ownership(&self) -> (u32, u32) {
        self.inode.metadata.attributes.owner()
    }

    pub(super) fn attributes(&self) -> &Attributes {
        &self.inode.metadata.attributes
    }

    pub(super) fn ino(&self) -> u64 {
        self.inode.metadata.ino
    }

    pub(super) fn link_count(&self) -> u32 {
        self.inode.metadata.links.load(Ordering::Relaxed)
    }

    pub(crate) fn permits(&self, need: u32, ids: (u32, u32), groups: &[u32]) -> bool {
        if ids.0 == 0 {
            return need & 1 == 0 || self.mode() & 0o111 != 0;
        }
        permitted(self.mode(), self.ownership(), need, ids, groups)
    }

    pub(super) fn snapshot(&self) -> Result<Arc<[u8]>, Error> {
        let contents = self.inode.contents.lock().map_err(|_| Error::Io)?;
        Ok(Arc::from(contents.snapshot()?.as_slice()))
    }

    /// The mapping retains this leaf and its quota after the last descriptor
    /// closes. The inode has a single backing even when accessed via aliases.
    pub(in crate::user) fn shared_mapping(
        self: &Arc<Self>,
        writable: bool,
        guest_page: u64,
    ) -> Result<Arc<SharedObject>, Error> {
        self.shared_mapping_keeping(writable, guest_page, None)
    }

    pub(in crate::user) fn shared_mapping_keeping(
        self: &Arc<Self>,
        writable: bool,
        guest_page: u64,
        keep: Option<crate::user::mm::Keep>,
    ) -> Result<Arc<SharedObject>, Error> {
        let mut contents = self.inode.contents.lock().map_err(|_| Error::Io)?;
        let shared = contents.shared()?;
        #[cfg(unix)]
        shared
            .ensure_mapping_page(guest_page)
            .map_err(|_| Error::Io)?;
        let file = shared.file.try_clone().map_err(|_| Error::Io)?;
        let owner: crate::user::mm::Keep = match keep {
            Some(keep) => Arc::new((self.clone(), keep)),
            None => self.clone(),
        };
        Ok(Arc::new(SharedObject::bounded_file(
            file,
            SHARED_CAPACITY,
            shared.extent.clone(),
            self.identity(),
            writable,
            owner,
            guest_page,
        )))
    }

    pub(in crate::user) fn any_shared_mapping(
        &self,
        predicate: impl Fn(&crate::user::mm::Vma) -> bool,
    ) -> Result<bool, Error> {
        let extent = match &*self.inode.contents.lock().map_err(|_| Error::Io)? {
            Contents::Bytes(_) => return Ok(false),
            Contents::Shared(shared) => shared.extent.clone(),
        };
        Ok(extent.any_mapping(self.identity(), predicate))
    }

    pub(crate) fn resize(&self, len: u64) -> Result<(), Error> {
        let len = usize::try_from(len).map_err(|_| Error::TooLarge)?;
        let mut bytes = self.inode.contents.lock().map_err(|_| Error::Io)?;
        self.resize_locked(&mut bytes, len)?;
        self.attributes().modified();
        Ok(())
    }

    pub(in crate::user) fn punch_hole(&self, start: u64, end: u64) -> Result<(), Error> {
        let mut contents = self.inode.contents.lock().map_err(|_| Error::Io)?;
        let end = end.min(contents.len() as u64);
        if start >= end {
            return Ok(());
        }
        match &mut *contents {
            Contents::Bytes(bytes) => {
                let start = start as usize;
                let end = end as usize;
                Arc::make_mut(&mut bytes.data)[start..end].fill(0);
                if let Some(blocks) = &mut bytes.blocks {
                    let removed = start.div_ceil(blocks.bytes)..end / blocks.bytes;
                    Arc::make_mut(&mut blocks.written).retain(|page| !removed.contains(page));
                }
            }
            #[cfg(target_os = "linux")]
            Contents::Shared(shared) if self.inode.flavor == WorkspaceFlavor::Linux => {
                linux_allocation::allocate(
                    &shared.file,
                    libc::FALLOC_FL_KEEP_SIZE | libc::FALLOC_FL_PUNCH_HOLE,
                    start as i64,
                    (end - start) as i64,
                )
                .map_err(|_| Error::Io)?;
            }
            Contents::Shared(shared) => {
                let zeros = [0; 4096];
                let mut offset = start;
                while offset < end {
                    let count = (end - offset).min(zeros.len() as u64) as usize;
                    shared
                        .file
                        .write_all_at(offset, &zeros[..count])
                        .map_err(|_| Error::Io)?;
                    offset += count as u64;
                }
            }
        }
        self.attributes().modified();
        Ok(())
    }

    fn resize_locked(&self, contents: &mut Contents, len: usize) -> Result<(), Error> {
        if len > MAX_BYTES {
            return Err(Error::TooLarge);
        }
        let old = contents.len();
        if len == old {
            return Ok(());
        }
        let mut budget = self.inode.metadata.budget.lock().map_err(|_| Error::Io)?;
        let reserved = contents.reservation();
        let retained = contents.reservation_after_resize(old, len);
        let current_charge = old + reserved;
        let new_charge = len + retained;
        if new_charge.saturating_sub(current_charge) > MAX_BYTES - budget.bytes {
            return Err(Error::NoSpace);
        }
        match contents {
            Contents::Bytes(bytes) => bytes.resize(len)?,
            Contents::Shared(shared) => {
                shared.resize(self.identity(), old, len)?;
                #[cfg(target_os = "linux")]
                if let Some(tail) = &mut shared.linux_tail {
                    tail.resize(old, len);
                }
                shared.reservation = retained;
            }
        }
        budget.bytes = budget.bytes - current_charge + new_charge;
        Ok(())
    }

    /// Positional or append writes return the end offset. Selecting the end of
    /// file and writing happen under the same lock for distinct descriptions.
    pub(crate) fn write(&self, offset: Option<u64>, input: &[u8]) -> Result<u64, Error> {
        let mut bytes = self.inode.contents.lock().map_err(|_| Error::Io)?;
        let offset = offset.unwrap_or(bytes.len() as u64);
        if input.is_empty() {
            return Ok(offset);
        }
        let start = usize::try_from(offset).map_err(|_| Error::TooLarge)?;
        let end = start.checked_add(input.len()).ok_or(Error::TooLarge)?;
        if end > bytes.len() {
            self.resize_locked(&mut bytes, end)?;
        }
        match &mut *bytes {
            Contents::Bytes(bytes) => bytes.write(start, input),
            Contents::Shared(shared) => shared
                .file
                .write_all_at(offset, input)
                .map_err(|_| Error::Io)?,
        }
        self.attributes().modified();
        Ok(end as u64)
    }
}

impl WorkspaceSymlink {
    pub(super) fn path(&self) -> Result<String, Error> {
        self.placement.path(false)
    }

    pub(super) fn attributes(&self) -> &Attributes {
        &self.inode.metadata.attributes
    }

    pub(super) fn ino(&self) -> u64 {
        self.inode.metadata.ino
    }

    pub(super) fn owner(&self) -> (u32, u32) {
        self.inode.metadata.attributes.owner()
    }

    pub(super) fn mode(&self) -> u32 {
        self.inode.metadata.attributes.mode()
    }

    pub(super) fn target(&self) -> &[u8] {
        &self.inode.target
    }

    pub(super) fn link_count(&self) -> u32 {
        self.inode.metadata.links.load(Ordering::Relaxed)
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

impl Drop for RegularFile {
    fn drop(&mut self) {
        if let Ok(mut budget) = self.metadata.budget.lock() {
            let bytes = self
                .contents
                .get_mut()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            budget.bytes -= bytes.len() + bytes.reservation();
        }
    }
}

impl Drop for SymbolicLink {
    fn drop(&mut self) {
        if let Ok(mut budget) = self.metadata.budget.lock() {
            budget.bytes -= self.target.len();
        }
    }
}

impl PageSource for WorkspaceFile {
    fn len(&self) -> u64 {
        self.inode
            .contents
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len() as u64
    }

    fn read_at(&self, offset: u64, out: &mut [u8]) -> io::Result<usize> {
        let bytes = self
            .inode
            .contents
            .lock()
            .map_err(|_| io::Error::other(Error::Io))?;
        if offset >= bytes.len() as u64 {
            return Ok(0);
        }
        let start = offset as usize;
        let count = out.len().min(bytes.len() - start);
        match &*bytes {
            Contents::Bytes(bytes) => {
                out[..count].copy_from_slice(&bytes.data[start..start + count]);
                Ok(count)
            }
            Contents::Shared(shared) => shared.file.read_at(offset, &mut out[..count]),
        }
    }

    fn identity(&self) -> SourceIdentity {
        SourceIdentity {
            dev: self.inode.metadata.dev,
            ino: self.ino(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hard_link_names_consume_entry_quota_and_share_data_until_last_close() {
        let workspace = Workspace::new(WorkspaceFlavor::Linux);
        let root = &workspace.root;
        let owner = (101, 102);
        let (original, _) = workspace
            .create("source".into(), 0o600, owner, true, root)
            .unwrap();
        original.write(None, b"data").unwrap();
        let source = Node::File(original.clone());
        assert_eq!(
            workspace.link(&source, root, "blocked".into(), (103, 102), &[]),
            Err(Error::PermissionDenied)
        );
        workspace
            .link(&source, root, "alias".into(), owner, &[])
            .unwrap();
        let Node::File(alias) = workspace.get(&workspace.root, "alias").unwrap().unwrap() else {
            panic!("expected a file hard link");
        };
        assert_eq!(original.ino(), alias.ino());
        assert_eq!(original.link_count(), 2);
        assert_eq!(
            workspace.capacity().unwrap().nodes_available,
            MAX_NODES as u64 - 2
        );
        assert_eq!(
            workspace.capacity().unwrap().bytes_available,
            MAX_BYTES as u64 - 4
        );
        workspace.unlink("source", owner.0, root).unwrap();
        alias.write(None, b"!").unwrap();
        assert_eq!(original.snapshot().unwrap().as_ref(), b"data!");
        assert_eq!(original.link_count(), 1);
        drop(source);
        drop(original);
        workspace.unlink("alias", owner.0, root).unwrap();
        assert_eq!(alias.link_count(), 0);
        assert_eq!(
            workspace.link(
                &Node::File(alias.clone()),
                root,
                "revived".into(),
                owner,
                &[]
            ),
            Err(Error::NotFound)
        );
        assert_eq!(
            workspace.capacity().unwrap().bytes_available,
            MAX_BYTES as u64 - 5
        );
        drop(alias);
        assert_eq!(
            workspace.capacity().unwrap().nodes_available,
            MAX_NODES as u64
        );
        assert_eq!(
            workspace.capacity().unwrap().bytes_available,
            MAX_BYTES as u64
        );
    }

    #[test]
    fn clone_reserves_quota_atomically_and_detaches_contents_on_write() {
        let workspace = Workspace::new(WorkspaceFlavor::Darwin);
        let root = &workspace.root;
        let owner = (101, 102);
        let (source, _) = workspace
            .create("source".into(), 0o600, owner, true, root)
            .unwrap();
        let node = Node::File(source.clone());
        let source_len = (3 * MAX_BYTES / 4) as u64;
        source.resize(source_len).unwrap();
        let before = workspace.capacity().unwrap();
        assert_eq!(
            workspace.clone_leaf(&node, root, "copy".into(), owner, false, false),
            Err(Error::NoSpace)
        );
        assert!(workspace.get(&workspace.root, "copy").unwrap().is_none());
        let after = workspace.capacity().unwrap();
        assert_eq!(after.bytes_available, before.bytes_available);
        assert_eq!(after.nodes_available, before.nodes_available);

        source.resize(4).unwrap();
        source.write(Some(0), b"data").unwrap();
        workspace
            .clone_leaf(&node, root, "copy".into(), owner, false, false)
            .unwrap();
        let Node::File(copy) = workspace.get(&workspace.root, "copy").unwrap().unwrap() else {
            panic!("expected a file clone");
        };
        assert_ne!(source.ino(), copy.ino());
        assert!(Arc::ptr_eq(
            &source.inode.contents.lock().unwrap().snapshot().unwrap(),
            &copy.inode.contents.lock().unwrap().snapshot().unwrap()
        ));
        source.write(Some(0), b"next").unwrap();
        assert_eq!(copy.snapshot().unwrap().as_ref(), b"data");
        assert_eq!(
            workspace.capacity().unwrap().bytes_available,
            MAX_BYTES as u64 - 8
        );
        source.resize(0).unwrap();
        assert_eq!(copy.snapshot().unwrap().as_ref(), b"data");
        assert_eq!(
            workspace.capacity().unwrap().bytes_available,
            MAX_BYTES as u64 - 4
        );
    }

    #[test]
    fn removed_storage_survives_recreation_until_the_last_descriptor_closes() {
        let files = Workspace::new(WorkspaceFlavor::Linux);
        let name = "value";
        let (before, created) = files
            .create(name.into(), 0o600, (101, 102), true, &files.root)
            .unwrap();
        assert!(created);
        assert!(matches!(
            files.create(name.into(), 0o600, (103, 104), true, &files.root),
            Err(Error::Exists)
        ));
        let (existing, created) = files
            .create(name.into(), 0, (103, 104), false, &files.root)
            .unwrap();
        assert!(!created);
        assert!(Arc::ptr_eq(&existing, &before));
        drop(existing);
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
        assert_eq!(before.link_count(), 0);
        assert!(files.get(&files.root, name).unwrap().is_none());
        let (after, _) = files
            .create(name.into(), 0o640, (103, 104), true, &files.root)
            .unwrap();
        assert_eq!(after.link_count(), 1);
        assert!(after.permits(4, (101, 102), &[104]));
        assert_ne!(before.ino(), after.ino());
        assert_eq!(after.len(), 0);
        assert_eq!(before.len(), 8);
        assert_eq!(files.children(&files.root).unwrap(), [name]);
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
