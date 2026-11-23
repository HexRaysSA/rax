//! Read-only POSIX guest files selected by an embedder, independent of host paths.
//!
//! File keys are canonical absolute UTF-8 guest paths. Directories are inferred;
//! there is no unselected host fallback or writable backing. Explicit directory
//! roots allow on-demand lookup; their host symlinks must target selected roots.
//! Selected open files can back entries without copying their complete contents. Lookup walks
//! components before interpreting `..`, so `/file/../other` is `NotDirectory`.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::user::mm::{BytesSource, HostFileSource, PageSource, SourceIdentity};
mod roots;
mod workspace;
use roots::Roots;
pub(super) use workspace::Capacity as WorkspaceCapacity;
use workspace::{Attributes, Node, Workspace};
pub use workspace::{Directory as WorkspaceDirectory, WorkspaceFile};
pub(in crate::user) use workspace::{
    MAX_XATTR_VALUE, RESOURCE_FORK, SetTime as WorkspaceSetTime, SetXattr,
    TimeUpdate as WorkspaceTimeUpdate, Timestamp as WorkspaceTimestamp,
    Timestamps as WorkspaceTimestamps, Xattrs,
};
pub(super) use workspace::{Rename as WorkspaceRename, WorkspaceFlavor};

const TEMP_DIRECTORY: &str = "/tmp";

#[derive(Clone, Copy, Eq, PartialEq)]
enum MissingLast {
    Reject,
    File,
    Directory,
}

enum WalkEnd {
    Found(Entry),
    Missing { parent: Entry },
}

impl WalkEnd {
    fn found(self) -> Result<Entry, Error> {
        match self {
            Self::Found(entry) => Ok(entry),
            Self::Missing { .. } => Err(Error::NotFound),
        }
    }
}

/// Maximum path bytes, including the terminating NUL in a guest syscall.
pub const PATH_MAX: usize = 4096;
/// Maximum UTF-8 bytes in one guest filename component.
pub const NAME_MAX: usize = 255;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidPath,
    TooLong,
    Exists,
    NotFound,
    NotDirectory,
    NotEmpty,
    Busy,
    CrossDevice,
    IsDirectory,
    NotRegular,
    LinkLoop,
    Io,
    TooLarge,
    ReadOnly,
    PermissionDenied,
    AccessDenied,
    NoSpace,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidPath => "invalid supplied guest path",
            Self::TooLong => "supplied guest path exceeds PATH_MAX",
            Self::Exists => "conflicting supplied file or directory",
            Self::NotFound => "guest path is not supplied",
            Self::NotDirectory => "guest path component is not a directory",
            Self::NotEmpty => "guest directory contains entries",
            Self::Busy => "guest mount or root directory is busy",
            Self::CrossDevice => "hard links cannot cross guest filesystems",
            Self::IsDirectory => "guest path is a directory",
            Self::NotRegular => "guest path does not refer to a regular file",
            Self::LinkLoop => "guest pathname encountered a symbolic link without following it",
            Self::Io => "selected guest backing file read failed",
            Self::TooLarge => "guest file exceeds its size limit",
            Self::ReadOnly => "the selected guest backing is read-only",
            Self::PermissionDenied => "guest identity cannot remove the workspace entry",
            Self::AccessDenied => "guest identity cannot modify the workspace directory",
            Self::NoSpace => "the private guest workspace is full",
        })
    }
}
impl std::error::Error for Error {}

#[derive(Clone, Debug)]
pub enum Kind {
    File(Arc<[u8]>),
    /// Read-only backing selected by the embedder, never by a guest pathname.
    Backed(Arc<HostFileSource>),
    /// A regular file created by this guest session.
    Workspace(Arc<WorkspaceFile>),
    WorkspaceSymlink(Arc<workspace::WorkspaceSymlink>),
    WorkspaceDirectory(Arc<WorkspaceDirectory>),
    Directory,
    /// The closed runtime's synthetic null character device.
    NullDevice,
    /// The closed runtime's synthetic zero-filled character device.
    ZeroDevice,
    /// The closed Linux runtime's synthetic guest entropy device.
    UrandomDevice,
    /// Link bytes from a selected runtime namespace.
    Symlink(Arc<[u8]>),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Device {
    Null,
    Zero,
    Urandom,
}

impl Device {
    pub(crate) fn read_constant(self, buffer: &mut [u8]) -> Option<usize> {
        match self {
            Self::Null => Some(0),
            Self::Zero => {
                buffer.fill(0);
                Some(buffer.len())
            }
            Self::Urandom => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Entry {
    /// Stable within this namespace; static entries use sorted path order and
    /// mounted entries use a disjoint, shared allocation sequence.
    pub ino: u64,
    pub kind: Kind,
}
impl Entry {
    pub fn is_dir(&self) -> bool {
        matches!(self.kind, Kind::Directory | Kind::WorkspaceDirectory(_))
    }
    pub(crate) fn device(&self) -> Option<Device> {
        match self.kind {
            Kind::NullDevice => Some(Device::Null),
            Kind::ZeroDevice => Some(Device::Zero),
            Kind::UrandomDevice => Some(Device::Urandom),
            _ => None,
        }
    }
    pub(crate) fn workspace_file(&self) -> Option<&WorkspaceFile> {
        match &self.kind {
            Kind::Workspace(file) => Some(file),
            _ => None,
        }
    }

    pub(crate) fn workspace_directory(&self) -> Option<&Arc<WorkspaceDirectory>> {
        match &self.kind {
            Kind::WorkspaceDirectory(directory) => Some(directory),
            _ => None,
        }
    }

    pub(crate) fn workspace_path(&self) -> Result<Option<String>, Error> {
        match &self.kind {
            Kind::WorkspaceDirectory(directory) => directory.path().map(Some),
            Kind::Workspace(file) => file.path().map(Some),
            Kind::WorkspaceSymlink(link) => link.path().map(Some),
            _ => Ok(None),
        }
    }

    fn workspace_attributes(&self) -> Option<&Attributes> {
        match &self.kind {
            Kind::WorkspaceDirectory(directory) => Some(&directory.attributes),
            Kind::Workspace(file) => Some(file.attributes()),
            Kind::WorkspaceSymlink(link) => Some(link.attributes()),
            _ => None,
        }
    }

    pub(crate) fn workspace_mode(&self) -> Option<u32> {
        self.workspace_attributes().map(Attributes::mode)
    }

    pub(super) fn workspace_xattrs(
        &self,
        need: u32,
        ids: (u32, u32),
        groups: &[u32],
    ) -> Result<&Arc<workspace::Xattrs>, Error> {
        self.workspace_attributes()
            .ok_or(Error::ReadOnly)?
            .xattrs(need, ids, groups)
    }

    pub(super) fn workspace_xattrs_changed(&self) {
        if let Some(attributes) = self.workspace_attributes() {
            attributes.xattrs_changed();
        }
    }

    pub(crate) fn workspace_owner(&self) -> Option<(u32, u32)> {
        self.workspace_attributes().map(Attributes::owner)
    }

    pub(crate) fn workspace_timestamps(&self) -> Option<WorkspaceTimestamps> {
        self.workspace_attributes().map(Attributes::timestamps)
    }

    pub(crate) fn set_workspace_mode(
        &self,
        mode: u32,
        ids: (u32, u32),
        groups: &[u32],
    ) -> Result<(), Error> {
        self.workspace_attributes()
            .ok_or(Error::ReadOnly)?
            .set_mode(mode, ids, groups)
    }

    pub(in crate::user) fn set_workspace_times(
        &self,
        update: WorkspaceTimeUpdate,
        ids: (u32, u32),
        groups: &[u32],
    ) -> Result<(), Error> {
        self.workspace_attributes()
            .ok_or(Error::ReadOnly)?
            .set_times(update, ids, groups)
    }

    pub(crate) fn link_target(&self) -> Option<&[u8]> {
        match &self.kind {
            Kind::Symlink(target) => Some(target),
            Kind::WorkspaceSymlink(link) => Some(link.target()),
            _ => None,
        }
    }

    pub(crate) fn workspace_leaf_links(&self) -> Option<u32> {
        match &self.kind {
            Kind::Workspace(file) => Some(file.link_count()),
            Kind::WorkspaceSymlink(link) => Some(link.link_count()),
            _ => None,
        }
    }
    pub fn bytes(&self) -> Result<Arc<[u8]>, Error> {
        match &self.kind {
            Kind::File(bytes) => Ok(bytes.clone()),
            Kind::Workspace(file) => file.snapshot(),
            Kind::Backed(source) => {
                // Image parsers require contiguous bytes; mapping and descriptor
                // reads use source() instead and do not impose this copy bound.
                const MAX_COPY: u64 = 64 << 20;
                let len = source.len();
                if len > MAX_COPY {
                    return Err(Error::TooLarge);
                }
                let mut bytes = Vec::new();
                bytes
                    .try_reserve_exact(len as usize)
                    .map_err(|_| Error::TooLarge)?;
                bytes.resize(len as usize, 0);
                let mut done = 0;
                while done < bytes.len() {
                    let n = source
                        .read_at(done as u64, &mut bytes[done..])
                        .map_err(|_| Error::Io)?;
                    if n == 0 || n > bytes.len() - done {
                        return Err(Error::Io);
                    }
                    done += n;
                }
                Ok(bytes.into())
            }
            Kind::Directory | Kind::WorkspaceDirectory(_) => Err(Error::IsDirectory),
            Kind::NullDevice | Kind::ZeroDevice | Kind::UrandomDevice => Err(Error::NotRegular),
            Kind::Symlink(_) | Kind::WorkspaceSymlink(_) => Err(Error::LinkLoop),
        }
    }

    /// File or link length without materializing its contents. Directories have size zero.
    pub fn len(&self) -> u64 {
        match &self.kind {
            Kind::File(bytes) => bytes.len() as u64,
            Kind::Backed(source) => source.len(),
            Kind::Workspace(file) => file.len(),
            Kind::Directory
            | Kind::WorkspaceDirectory(_)
            | Kind::NullDevice
            | Kind::ZeroDevice
            | Kind::UrandomDevice => 0,
            Kind::Symlink(target) => target.len() as u64,
            Kind::WorkspaceSymlink(link) => link.target().len() as u64,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Selected read-only handle for native runtime metadata operations.
    /// The guest descriptor table never publishes this host descriptor.
    pub(crate) fn host_file(&self) -> Option<&std::fs::File> {
        match &self.kind {
            Kind::Backed(source) => Some(source.file()),
            _ => None,
        }
    }

    /// Read-only backing with namespace identity, sharing any selected file handle.
    pub fn source(&self) -> Result<Arc<dyn PageSource>, Error> {
        let source: Arc<dyn PageSource> = match &self.kind {
            Kind::File(bytes) => Arc::new(BytesSource::new(bytes.clone())),
            Kind::Backed(source) => source.clone(),
            Kind::Workspace(file) => return Ok(file.clone()),
            Kind::Directory | Kind::WorkspaceDirectory(_) => return Err(Error::IsDirectory),
            Kind::NullDevice | Kind::ZeroDevice | Kind::UrandomDevice => {
                return Err(Error::NotRegular);
            }
            Kind::Symlink(_) | Kind::WorkspaceSymlink(_) => return Err(Error::LinkLoop),
        };
        Ok(Arc::new(GuestSource {
            source,
            ino: self.ino,
        }))
    }
}

#[derive(Debug)]
struct GuestSource {
    source: Arc<dyn PageSource>,
    ino: u64,
}
impl PageSource for GuestSource {
    fn len(&self) -> u64 {
        self.source.len()
    }
    fn identity(&self) -> SourceIdentity {
        SourceIdentity {
            dev: 0x524158,
            ino: self.ino,
        }
    }
    fn read_at(&self, offset: u64, out: &mut [u8]) -> std::io::Result<usize> {
        self.source.read_at(offset, out)
    }
}

/// A closed namespace. Clones share copied bytes or selected read-only handles.
#[derive(Clone, Debug)]
pub struct Files {
    entries: Arc<BTreeMap<String, Entry>>,
    caller_roots: Option<Arc<Roots>>,
    native_libraries: Option<Arc<Roots>>,
    workspace: Option<Arc<Workspace>>,
}
impl Default for Files {
    fn default() -> Self {
        Self::new(BTreeMap::new()).expect("empty supplied namespace is valid")
    }
}

fn validate(path: &str) -> Result<(), Error> {
    if path.is_empty() {
        return Err(Error::NotFound);
    }
    if path.len() >= PATH_MAX || path.split('/').any(|component| component.len() > NAME_MAX) {
        return Err(Error::TooLong);
    }
    if !path.starts_with('/') || path.as_bytes().contains(&0) {
        return Err(Error::InvalidPath);
    }
    Ok(())
}

fn workspace_name(path: &str) -> &str {
    path.rsplit('/').next().expect("guest path components")
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum LinkPolicy {
    Follow,
    NoFollowLast,
    NoFollowAny,
    NoFollowAncestors,
}

type WorkspaceAccess<'a> = ((u32, u32), &'a [u32]);

/// Form an absolute guest path while preserving a removed base directory's
/// identity. Only dot and dot-dot can traverse a detached directory. The
/// optional entry is present when the path still ends at a detached directory.
pub(super) fn relative_workspace_path(
    base: &str,
    directory: Option<&Arc<WorkspaceDirectory>>,
    path: &str,
    ids: (u32, u32),
    groups: &[u32],
) -> Result<(String, Option<Entry>), Error> {
    let mut rest = path;
    let mut directory = directory.cloned();
    while let Some(detached) = directory.as_ref().filter(|directory| !directory.linked()) {
        rest = rest.trim_start_matches('/');
        if rest.is_empty() {
            return Ok((
                detached.path()?,
                Some(Entry {
                    ino: detached.ino,
                    kind: Kind::WorkspaceDirectory(detached.clone()),
                }),
            ));
        }
        if !detached.permits(1, ids, groups) {
            return Err(Error::AccessDenied);
        }
        let (name, tail) = rest.split_once('/').unwrap_or((rest, ""));
        match name {
            "." => {}
            ".." => {
                directory = detached.parent();
            }
            _ => return Err(Error::NotFound),
        }
        rest = tail;
    }
    let base = match directory {
        Some(dir) => dir.path()?,
        None => base.to_owned(),
    };
    if rest.is_empty() {
        Ok((base, None))
    } else {
        Ok((format!("{}/{rest}", base.trim_end_matches('/')), None))
    }
}

impl Files {
    /// File keys must be canonical: absolute, no empty, `.` or `..` components,
    /// no trailing slash. Reject file/directory collisions before publication.
    /// For N final entries, K stored key bytes and maximum key length L,
    /// construction is bounded by O(K L log(N+1)) time and O(K+N) space.
    /// Payload bytes remain shared.
    pub fn new(files: BTreeMap<String, Arc<[u8]>>) -> Result<Self, Error> {
        Self::from_kinds(
            files
                .into_iter()
                .map(|(path, bytes)| (path, Kind::File(bytes)))
                .collect(),
        )
    }

    fn from_kinds(files: BTreeMap<String, Kind>) -> Result<Self, Error> {
        let mut entries = BTreeMap::new();
        entries.insert(
            "/".to_string(),
            Entry {
                ino: 0,
                kind: Kind::Directory,
            },
        );
        for (path, kind) in files {
            validate(&path)?;
            let components: Vec<_> = path[1..].split('/').collect();
            if components
                .iter()
                .any(|c| c.is_empty() || *c == "." || *c == "..")
            {
                return Err(Error::InvalidPath);
            }
            let mut parent = String::new();
            for component in &components[..components.len() - 1] {
                parent.push('/');
                parent.push_str(component);
                match entries.get(&parent) {
                    Some(entry) if !entry.is_dir() => return Err(Error::Exists),
                    Some(_) => {}
                    None => {
                        entries.insert(
                            parent.clone(),
                            Entry {
                                ino: 0,
                                kind: Kind::Directory,
                            },
                        );
                    }
                }
            }
            if entries.insert(path, Entry { ino: 0, kind }).is_some() {
                return Err(Error::Exists);
            }
        }
        for (index, entry) in entries.values_mut().enumerate() {
            entry.ino = 0x5241_5900 + index as u64;
        }
        Ok(Self {
            entries: Arc::new(entries),
            caller_roots: None,
            native_libraries: None,
            workspace: None,
        })
    }

    /// Produces a new namespace with an additional file. Used to include the
    /// executable itself before starting a process; existing paths are refused.
    pub fn with_file(&self, path: String, bytes: Arc<[u8]>) -> Result<Self, Error> {
        self.with_kind(path, Kind::File(bytes))
    }

    #[cfg(any(target_os = "linux", target_os = "macos", test))]
    pub(super) fn with_device(&self, device: Device) -> Result<Self, Error> {
        let (path, kind) = match device {
            Device::Null => ("/dev/null", Kind::NullDevice),
            Device::Zero => ("/dev/zero", Kind::ZeroDevice),
            Device::Urandom => ("/dev/urandom", Kind::UrandomDevice),
        };
        if self.caller_roots.as_ref().is_some_and(|roots| {
            roots
                .paths()
                .any(|root| root == "/" || root == "/dev" || root == path)
        }) {
            return Ok(self.clone());
        }
        match self.lookup(path) {
            Err(Error::NotFound) => self.with_kind(path.into(), kind),
            Ok(_) | Err(Error::NotDirectory) => Ok(self.clone()),
            Err(error) => Err(error),
        }
    }

    /// Add an installed link whose absolute target is resolved in the guest.
    #[cfg(any(target_os = "macos", test))]
    pub(super) fn with_native_symlink(&self, path: &str, target: &str) -> Result<Self, Error> {
        validate(target)?;
        if self.caller_roots.as_ref().is_some_and(|roots| {
            roots.paths().any(|root| {
                root == "/"
                    || root == path
                    || path
                        .strip_prefix(root)
                        .is_some_and(|tail| tail.starts_with('/'))
            })
        }) {
            return Ok(self.clone());
        }
        match self.lookup_with_follow(path, false) {
            Err(Error::NotFound) => {
                self.with_kind(path.into(), Kind::Symlink(Arc::from(target.as_bytes())))
            }
            Ok(_) | Err(Error::NotDirectory) => Ok(self.clone()),
            Err(error) => Err(error),
        }
    }

    /// Select exactly one host file as read-only guest backing. No host path is
    /// exposed to the guest and missing guest names never trigger host lookup.
    /// The open handle remains shared across clones and namespace extensions.
    /// Backing bytes are live, not a snapshot: external in-place writes/truncation
    /// remain observable. Atomic pathname replacement does not retarget the handle.
    pub fn with_host_file(&self, path: String, host: &std::path::Path) -> std::io::Result<Self> {
        self.with_host_files(BTreeMap::from([(path, host.to_path_buf())]))
    }

    /// Atomically extend a namespace with caller-selected read-only host files.
    /// Aliases of the same supplied host path share one open handle.
    pub fn with_host_files(
        &self,
        selected: BTreeMap<String, std::path::PathBuf>,
    ) -> std::io::Result<Self> {
        let mut files: BTreeMap<_, _> = self
            .entries
            .iter()
            .filter_map(|(path, entry)| {
                (!entry.is_dir()).then(|| (path.clone(), entry.kind.clone()))
            })
            .collect();
        let mut sources: BTreeMap<std::path::PathBuf, Arc<HostFileSource>> = BTreeMap::new();
        for (path, host) in selected {
            if self.entries.contains_key(&path) {
                return Err(std::io::Error::other(Error::Exists));
            }
            let source = if let Some(source) = sources.get(&host) {
                source.clone()
            } else {
                let mut options = std::fs::OpenOptions::new();
                options.read(true);
                // A caller-selected FIFO must be rejected rather than blocking open.
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.custom_flags(libc::O_NONBLOCK);
                }
                let file = options.open(&host)?;
                if !file.metadata()?.is_file() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "guest backing must be a regular file",
                    ));
                }
                let source = Arc::new(HostFileSource::new(file)?);
                sources.insert(host, source.clone());
                source
            };
            files.insert(path, Kind::Backed(source));
        }
        let mut next = Self::from_kinds(files).map_err(std::io::Error::other)?;
        next.caller_roots = self.caller_roots.clone();
        next.native_libraries = self.native_libraries.clone();
        next.workspace = self.workspace.clone();
        next.restore_roots().map_err(std::io::Error::other)?;
        Ok(next)
    }

    #[cfg(target_os = "linux")]
    pub(super) fn with_selected_backings(
        &self,
        files: BTreeMap<String, Arc<HostFileSource>>,
    ) -> Result<Self, Error> {
        if files.is_empty() {
            return Ok(self.clone());
        }
        self.with_kinds(
            files
                .into_iter()
                .map(|(path, source)| (path, Kind::Backed(source))),
        )
    }

    fn with_kind(&self, path: String, kind: Kind) -> Result<Self, Error> {
        self.with_kinds([(path, kind)])
    }

    fn with_kinds(
        &self,
        additions: impl IntoIterator<Item = (String, Kind)>,
    ) -> Result<Self, Error> {
        let mut files: BTreeMap<_, _> = self
            .entries
            .iter()
            .filter_map(|(path, entry)| {
                (!entry.is_dir()).then(|| (path.clone(), entry.kind.clone()))
            })
            .collect();
        for (path, kind) in additions {
            if self.entries.contains_key(&path) {
                return Err(Error::Exists);
            }
            files.insert(path, kind);
        }
        let mut next = Self::from_kinds(files)?;
        next.caller_roots = self.caller_roots.clone();
        next.native_libraries = self.native_libraries.clone();
        next.workspace = self.workspace.clone();
        next.restore_roots()?;
        Ok(next)
    }

    /// Select read-only library directory roots. Missing names outside these
    /// roots still have no host fallback. Symlink targets must stay within the
    /// union of canonical selected roots. Explicit files take precedence.
    pub fn with_host_roots(
        &self,
        roots: BTreeMap<String, std::path::PathBuf>,
    ) -> std::io::Result<Self> {
        if self.caller_roots.is_some() {
            return Err(std::io::Error::other(Error::Exists));
        }
        let mut next = self.clone();
        next.caller_roots = Some(Arc::new(Roots::new(roots, roots::Origin::CALLER)?));
        next.restore_roots().map_err(std::io::Error::other)?;
        Ok(next)
    }

    /// Add installed native library mounts behind explicit entries and caller mounts.
    #[cfg(any(target_os = "macos", test))]
    pub(super) fn with_native_library_roots(
        &self,
        roots: BTreeMap<String, std::path::PathBuf>,
        accept: Option<roots::AcceptFile>,
    ) -> std::io::Result<Self> {
        self.with_library_roots(roots, roots::Origin::installed(accept, false))
    }

    #[cfg(any(target_os = "linux", test))]
    pub(super) fn with_linux_library_roots(
        &self,
        roots: BTreeMap<String, std::path::PathBuf>,
    ) -> std::io::Result<Self> {
        self.with_library_roots(roots, roots::Origin::installed(None, true))
    }

    #[cfg(any(target_os = "linux", target_os = "macos", test))]
    fn with_library_roots(
        &self,
        mut roots: BTreeMap<String, std::path::PathBuf>,
        origin: roots::Origin,
    ) -> std::io::Result<Self> {
        if self.native_libraries.is_some() {
            return Ok(self.clone());
        }
        let mut blocked = Vec::new();
        for path in roots.keys() {
            // A supplied file or caller mount can occupy this mount point
            // or one of its ancestors.
            let mut ancestor = path.as_str();
            while !ancestor.is_empty() {
                match self.entry(ancestor, true) {
                    Ok(entry) => {
                        if !entry.is_dir() {
                            blocked.push(path.clone());
                        }
                        break;
                    }
                    Err(Error::NotDirectory) => {
                        blocked.push(path.clone());
                        break;
                    }
                    Err(Error::NotFound) => {}
                    Err(error) => return Err(std::io::Error::other(error)),
                }
                let Some((parent, _)) = ancestor.rsplit_once('/') else {
                    break;
                };
                ancestor = parent;
            }
        }
        for path in blocked {
            roots.remove(&path);
        }
        if roots.is_empty() {
            return Ok(self.clone());
        }
        let mut next = self.clone();
        next.native_libraries = Some(Arc::new(Roots::new(roots, origin)?));
        next.restore_roots().map_err(std::io::Error::other)?;
        Ok(next)
    }

    fn restore_roots(&mut self) -> Result<(), Error> {
        let entries = Arc::make_mut(&mut self.entries);
        for roots in self.caller_roots.iter().chain(&self.native_libraries) {
            for root in roots.paths() {
                let mut parent = String::new();
                for component in root.split('/').filter(|s| !s.is_empty()) {
                    parent.push('/');
                    parent.push_str(component);
                    match entries.get(&parent) {
                        Some(entry) if !entry.is_dir() => return Err(Error::Exists),
                        Some(_) => {}
                        None => {
                            entries.insert(
                                parent.clone(),
                                Entry {
                                    ino: roots.directory_ino(&parent)?,
                                    kind: Kind::Directory,
                                },
                            );
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Enable ephemeral storage for closed native-runtime sessions.
    /// Explicit files and mounts retain their contents and precedence.
    pub(super) fn with_temp_workspace(&self, flavor: WorkspaceFlavor) -> Self {
        Self {
            workspace: Some(Arc::new(Workspace::new(flavor))),
            ..self.clone()
        }
    }

    pub(crate) fn fresh_session(&self) -> Self {
        if let Some(workspace) = &self.workspace {
            self.with_temp_workspace(workspace.flavor)
        } else {
            self.clone()
        }
    }

    pub(crate) fn has_workspace(&self) -> bool {
        self.workspace.is_some()
    }

    pub(super) fn workspace_capacity(&self) -> Result<WorkspaceCapacity, Error> {
        self.workspace.as_ref().ok_or(Error::ReadOnly)?.capacity()
    }

    fn workspace_at(&self, path: &str) -> Option<&Workspace> {
        self.workspace.as_deref().filter(|_| {
            !self
                .caller_roots
                .iter()
                .chain(&self.native_libraries)
                .flat_map(|mounts| mounts.paths())
                .any(|mount| {
                    mount == "/"
                        || path == mount
                        || path
                            .strip_prefix(mount)
                            .is_some_and(|tail| tail.starts_with('/'))
                })
        })
    }

    fn workspace_destination(
        &self,
        path: &str,
        ids: (u32, u32),
        groups: &[u32],
    ) -> Result<(&Workspace, String, Arc<WorkspaceDirectory>), Error> {
        validate(path)?;
        let (parent, name) = path.rsplit_once('/').expect("validated absolute path");
        if name.is_empty() {
            return Err(Error::IsDirectory);
        }
        let parent = if parent.is_empty() { "/" } else { parent };
        let (parent, entry) = self.lookup_for_guest(parent, LinkPolicy::Follow, ids, groups)?;
        if !entry.is_dir() {
            return Err(Error::NotDirectory);
        }
        if matches!(name, "." | "..") {
            return Err(Error::Exists);
        }
        let directory = entry.workspace_directory().ok_or(Error::ReadOnly)?.clone();
        if !directory.permits(3, ids, groups) {
            return Err(Error::AccessDenied);
        }
        let path = format!("{parent}/{name}");
        let workspace = self.workspace_at(&path).ok_or(Error::ReadOnly)?;
        Ok((workspace, path, directory))
    }

    pub(crate) fn create_workspace_file(
        &self,
        path: &str,
        mode: u32,
        ids: (u32, u32),
        groups: &[u32],
        exclusive: bool,
    ) -> Result<(String, Entry), Error> {
        let (path, entry, _) =
            self.create_workspace_file_with_status(path, mode, ids, groups, exclusive)?;
        Ok((path, entry))
    }

    pub(super) fn create_workspace_file_with_status(
        &self,
        path: &str,
        mode: u32,
        ids: (u32, u32),
        groups: &[u32],
        exclusive: bool,
    ) -> Result<(String, Entry, bool), Error> {
        let (workspace, path, directory) = self.workspace_destination(path, ids, groups)?;
        self.publish_workspace_file(workspace, path, &directory, mode, ids, exclusive)
    }

    fn publish_workspace_file(
        &self,
        workspace: &Workspace,
        path: String,
        directory: &Arc<WorkspaceDirectory>,
        mode: u32,
        ids: (u32, u32),
        exclusive: bool,
    ) -> Result<(String, Entry, bool), Error> {
        if self.entries.contains_key(&path) {
            return Err(if exclusive {
                Error::Exists
            } else {
                Error::ReadOnly
            });
        }
        let owner = directory.child_owner(workspace.flavor, ids);
        let name = workspace_name(&path);
        let (file, created) =
            workspace.create(name.to_owned(), mode, owner, exclusive, directory)?;
        Ok((
            path,
            Entry {
                ino: file.ino(),
                kind: Kind::Workspace(file),
            },
            created,
        ))
    }

    pub(crate) fn create_workspace_directory(
        &self,
        path: &str,
        mode: u32,
        ids: (u32, u32),
        groups: &[u32],
    ) -> Result<(), Error> {
        validate(path)?;
        let name_path = path.trim_end_matches('/');
        if name_path.is_empty() {
            return Err(Error::Exists);
        }
        let flavor = self.workspace.as_ref().ok_or(Error::ReadOnly)?.flavor;
        let lookup_path = if flavor == WorkspaceFlavor::Darwin {
            path
        } else {
            name_path
        };
        match self.lookup_for_guest(lookup_path, LinkPolicy::NoFollowLast, ids, groups) {
            Ok(_) => return Err(Error::Exists),
            Err(Error::NotFound) => {}
            Err(error) => return Err(error),
        }
        let resolved;
        let name_path = if flavor == WorkspaceFlavor::Darwin && path.ends_with('/') {
            resolved = self.resolve_create_path(path, ids, groups, MissingLast::Directory)?;
            &resolved
        } else {
            name_path
        };
        let (workspace, path, directory) = self.workspace_destination(name_path, ids, groups)?;
        let owner = directory.child_owner(flavor, ids);
        let mode = match flavor {
            WorkspaceFlavor::Linux => (mode & 0o1777) | (directory.attributes.mode() & 0o2000),
            WorkspaceFlavor::Darwin => mode & 0o777,
        };
        workspace.create_directory(workspace_name(&path).to_owned(), mode, owner, &directory)
    }

    pub(super) fn create_workspace_symlink(
        &self,
        path: &str,
        target: Vec<u8>,
        umask: u32,
        ids: (u32, u32),
        groups: &[u32],
    ) -> Result<(), Error> {
        let flavor = self.workspace.as_ref().ok_or(Error::ReadOnly)?.flavor;
        if target.is_empty() && flavor == WorkspaceFlavor::Linux {
            return Err(Error::NotFound);
        }
        validate(path)?;
        let trimmed = path.trim_end_matches('/');
        let lookup_path = if flavor == WorkspaceFlavor::Linux && !trimmed.is_empty() {
            trimmed
        } else {
            path
        };
        match self.lookup_for_guest(lookup_path, LinkPolicy::NoFollowLast, ids, groups) {
            Ok(_) => return Err(Error::Exists),
            Err(Error::NotFound) => {}
            Err(error) => return Err(error),
        }
        if path.ends_with('/') {
            return Err(Error::NotFound);
        }
        let (workspace, name, directory) = self.workspace_destination(path, ids, groups)?;
        let owner = directory.child_owner(flavor, ids);
        let mode = match flavor {
            WorkspaceFlavor::Linux => 0o777,
            WorkspaceFlavor::Darwin => 0o777 & !umask,
        };
        workspace.create_symlink(
            workspace_name(&name).into(),
            target,
            mode,
            owner,
            &directory,
        )
    }

    pub(crate) fn unlink_workspace_file(
        &self,
        path: &str,
        ids: (u32, u32),
        groups: &[u32],
    ) -> Result<(), Error> {
        validate(path)?;
        let trailing_slash = path.ends_with('/');
        let name = path.trim_end_matches('/');
        let darwin = self
            .workspace
            .as_ref()
            .is_some_and(|ws| ws.flavor == WorkspaceFlavor::Darwin);
        let (path, entry) = self.lookup_for_guest(
            if darwin || name.is_empty() {
                path
            } else {
                name
            },
            LinkPolicy::NoFollowLast,
            ids,
            groups,
        )?;
        if !entry.is_dir() && trailing_slash {
            return Err(Error::NotDirectory);
        }
        if entry.is_dir() {
            return Err(Error::IsDirectory);
        }
        if entry.workspace_leaf_links().is_none() {
            return Err(Error::ReadOnly);
        }
        let (workspace, path, directory) = self.workspace_destination(&path, ids, groups)?;
        workspace.unlink(workspace_name(&path), ids.0, &directory)
    }

    pub(super) fn link_workspace_entry(
        &self,
        source: Entry,
        path: &str,
        ids: (u32, u32),
        groups: &[u32],
    ) -> Result<(), Error> {
        let source = match source.kind {
            Kind::Workspace(file) => Node::File(file),
            Kind::WorkspaceSymlink(link) => Node::Symlink(link),
            Kind::Directory | Kind::WorkspaceDirectory(_) => {
                return Err(Error::PermissionDenied);
            }
            _ => return Err(Error::CrossDevice),
        };
        validate(path)?;
        let linux = self
            .workspace
            .as_ref()
            .is_some_and(|ws| ws.flavor == WorkspaceFlavor::Linux);
        let lookup = if linux && !path.trim_end_matches('/').is_empty() {
            path.trim_end_matches('/')
        } else {
            path
        };
        match self.lookup_for_guest(lookup, LinkPolicy::NoFollowLast, ids, groups) {
            Ok(_) => return Err(Error::Exists),
            Err(Error::NotFound) => {}
            Err(error) => return Err(error),
        }
        if path.ends_with('/') {
            return Err(Error::NotFound);
        }
        let (workspace, path, directory) = self.workspace_destination(path, ids, groups)?;
        workspace.link(
            &source,
            &directory,
            workspace_name(&path).into(),
            ids,
            groups,
        )
    }

    pub(crate) fn remove_workspace_directory(
        &self,
        path: &str,
        ids: (u32, u32),
        groups: &[u32],
    ) -> Result<(), Error> {
        validate(path)?;
        let trimmed = path.trim_end_matches('/');
        if trimmed.is_empty() {
            return Err(Error::Busy);
        }
        match trimmed.rsplit('/').next() {
            Some(".") => return Err(Error::InvalidPath),
            Some("..") => {
                return Err(
                    if self
                        .workspace
                        .as_ref()
                        .is_some_and(|ws| ws.flavor == WorkspaceFlavor::Linux)
                    {
                        Error::NotEmpty
                    } else {
                        Error::InvalidPath
                    },
                );
            }
            _ => {}
        }
        let darwin = self
            .workspace
            .as_ref()
            .is_some_and(|ws| ws.flavor == WorkspaceFlavor::Darwin);
        let lookup = if darwin { path } else { trimmed };
        let (path, entry) = self.lookup_for_guest(lookup, LinkPolicy::NoFollowLast, ids, groups)?;
        if !entry.is_dir() {
            return Err(Error::NotDirectory);
        }
        if entry.workspace_directory().is_none() || path == TEMP_DIRECTORY {
            return Err(Error::ReadOnly);
        }
        let (workspace, path, directory) = self.workspace_destination(&path, ids, groups)?;
        workspace.remove_directory(workspace_name(&path), ids.0, &directory)
    }

    /// Rename workspace entries atomically, retaining open inode identities.
    pub(super) fn rename_workspace_entry(
        &self,
        from: &str,
        to: &str,
        ids: (u32, u32),
        groups: &[u32],
        how: WorkspaceRename,
    ) -> Result<(), Error> {
        validate(from)?;
        validate(to)?;
        let old = from.trim_end_matches('/');
        let new = to.trim_end_matches('/');
        if old.is_empty() || new.is_empty() {
            return Err(Error::Busy);
        }
        if [old, new]
            .iter()
            .any(|path| matches!(workspace_name(path), "." | ".."))
        {
            return Err(Error::InvalidPath);
        }
        let darwin = self
            .workspace
            .as_ref()
            .is_some_and(|ws| ws.flavor == WorkspaceFlavor::Darwin);
        let old_lookup = if darwin { from } else { old };
        let (old, entry) =
            self.lookup_for_guest(old_lookup, LinkPolicy::NoFollowLast, ids, groups)?;
        if !entry.is_dir() && from.ends_with('/') {
            return Err(Error::NotDirectory);
        }
        if entry.workspace_leaf_links().is_none() && entry.workspace_directory().is_none() {
            return Err(Error::ReadOnly);
        }
        if !entry.is_dir() && to.ends_with('/') {
            return Err(Error::NotDirectory);
        }
        let resolved;
        let new = if to.ends_with('/') {
            if darwin {
                resolved = self.resolve_create_path(to, ids, groups, MissingLast::Directory)?;
                &resolved
            } else {
                match self.lookup_for_guest(new, LinkPolicy::NoFollowLast, ids, groups) {
                    Ok((_, entry)) if !entry.is_dir() => return Err(Error::NotDirectory),
                    Ok(_) | Err(Error::NotFound) => {}
                    Err(error) => return Err(error),
                }
                new
            }
        } else {
            new
        };
        let (_, old_path, old_parent) = self.workspace_destination(&old, ids, groups)?;
        let (workspace, new_path, new_parent) = self.workspace_destination(new, ids, groups)?;
        let name = workspace_name(&new_path);
        if name.len() > NAME_MAX {
            return Err(Error::TooLong);
        }
        if self.entries.contains_key(&new_path) {
            return Err(if how == WorkspaceRename::Exclusive {
                Error::Exists
            } else {
                Error::ReadOnly
            });
        }
        workspace.rename(
            (&old_parent, workspace_name(&old_path)),
            (&new_parent, name),
            ids.0,
            how,
        )
    }

    fn entry(&self, path: &str, follow: bool) -> Result<Entry, Error> {
        if path == TEMP_DIRECTORY
            && let Some(scratch) = self.workspace_at(path)
            && self.entries.get(path).is_none_or(Entry::is_dir)
        {
            return Ok(Entry {
                ino: workspace::ROOT_INODE,
                kind: Kind::WorkspaceDirectory(scratch.root.clone()),
            });
        }
        if let Some(entry) = self.entries.get(path) {
            if !follow
                && let Some(roots) = &self.native_libraries
                && roots.owns(entry)
                && let Some(link) = roots.mount_link(path)?
            {
                return Ok(link);
            }
            return Ok(entry.clone());
        }
        if let Some(name) = path.strip_prefix("/tmp/")
            && let Some(scratch) = self.workspace_at(path)
            && let Some(entry) = scratch.get(name)?
        {
            return Ok(match entry {
                Node::File(file) => Entry {
                    ino: file.ino(),
                    kind: Kind::Workspace(file),
                },
                Node::Symlink(link) => Entry {
                    ino: link.ino(),
                    kind: Kind::WorkspaceSymlink(link),
                },
                Node::Directory(directory) => Entry {
                    ino: directory.ino,
                    kind: Kind::WorkspaceDirectory(directory),
                },
            });
        }
        for roots in self.caller_roots.iter().chain(&self.native_libraries) {
            if !follow && let Some(link) = roots.symlink(path)? {
                return Ok(link);
            }
            match roots.lookup(path) {
                Err(Error::NotFound) => continue,
                result => return result,
            }
        }
        Err(Error::NotFound)
    }

    /// Resolves an absolute guest path, retaining directory checks before `..`.
    /// Returns its canonical guest name and a shared entry; never a host path.
    pub fn lookup(&self, path: &str) -> Result<(String, Entry), Error> {
        self.lookup_with_follow(path, true)
    }

    pub(crate) fn lookup_with_follow(
        &self,
        path: &str,
        follow_last: bool,
    ) -> Result<(String, Entry), Error> {
        let policy = if follow_last {
            LinkPolicy::Follow
        } else {
            LinkPolicy::NoFollowLast
        };
        self.lookup_with_policy(path, policy)
    }

    pub(super) fn lookup_with_policy(
        &self,
        path: &str,
        policy: LinkPolicy,
    ) -> Result<(String, Entry), Error> {
        self.lookup_with_access(path, policy, None)
    }

    pub(super) fn lookup_for_guest(
        &self,
        path: &str,
        policy: LinkPolicy,
        ids: (u32, u32),
        groups: &[u32],
    ) -> Result<(String, Entry), Error> {
        self.lookup_with_access(path, policy, Some((ids, groups)))
    }

    fn lookup_with_access(
        &self,
        path: &str,
        policy: LinkPolicy,
        access: Option<WorkspaceAccess<'_>>,
    ) -> Result<(String, Entry), Error> {
        let mut links_left = self.symlink_limit();
        let (path, entry) = self.walk(
            path,
            policy,
            &mut links_left,
            access,
            MissingLast::Reject,
            None,
        )?;
        Ok((path, entry.found()?))
    }

    /// A Darwin search descriptor authorizes the first traversal from its held
    /// directory. A later traversal must check the current guest permissions.
    pub(super) fn lookup_from_workspace_search(
        &self,
        path: &str,
        relative: &str,
        directory: &Arc<WorkspaceDirectory>,
        policy: LinkPolicy,
        ids: (u32, u32),
    ) -> Result<(String, Entry), Error> {
        let mut links_left = self.symlink_limit();
        let (path, entry) = self.walk(
            path,
            policy,
            &mut links_left,
            Some((ids, &[])),
            MissingLast::Reject,
            Some((relative, directory)),
        )?;
        Ok((path, entry.found()?))
    }

    pub(super) fn create_from_workspace_search(
        &self,
        path: &str,
        search_from: (&str, &Arc<WorkspaceDirectory>),
        policy: LinkPolicy,
        mode: u32,
        ids: (u32, u32),
        exclusive: bool,
    ) -> Result<(String, Entry, bool), Error> {
        let mut links_left = self.symlink_limit();
        let (path, end) = self.walk(
            path,
            policy,
            &mut links_left,
            Some((ids, &[])),
            MissingLast::File,
            Some(search_from),
        )?;
        let parent = match end {
            WalkEnd::Found(_) if exclusive => return Err(Error::Exists),
            WalkEnd::Found(entry) => return Ok((path, entry, false)),
            WalkEnd::Missing { parent } => parent,
        };
        let directory = parent.workspace_directory().ok_or(Error::ReadOnly)?;
        // The walk has already applied the search permission (or the descriptor's grant).
        if !directory.permits(2, ids, &[]) {
            return Err(Error::AccessDenied);
        }
        let workspace = self.workspace_at(&path).ok_or(Error::ReadOnly)?;
        self.publish_workspace_file(workspace, path, directory, mode, ids, exclusive)
    }

    /// Resolve the final component of a followed create, including a dangling link target.
    pub(super) fn workspace_create_path(
        &self,
        path: &str,
        ids: (u32, u32),
        groups: &[u32],
    ) -> Result<String, Error> {
        self.resolve_create_path(path, ids, groups, MissingLast::File)
    }

    fn resolve_create_path(
        &self,
        path: &str,
        ids: (u32, u32),
        groups: &[u32],
        missing: MissingLast,
    ) -> Result<String, Error> {
        let mut links_left = self.symlink_limit();
        let (path, _) = self.walk(
            path,
            LinkPolicy::Follow,
            &mut links_left,
            Some((ids, groups)),
            missing,
            None,
        )?;
        Ok(path)
    }

    fn symlink_limit(&self) -> u8 {
        if self
            .workspace
            .as_ref()
            .is_some_and(|ws| ws.flavor == WorkspaceFlavor::Linux)
        {
            40
        } else {
            32
        }
    }

    fn walk(
        &self,
        path: &str,
        policy: LinkPolicy,
        links_left: &mut u8,
        access: Option<WorkspaceAccess<'_>>,
        missing_last: MissingLast,
        search_from: Option<(&str, &Arc<WorkspaceDirectory>)>,
    ) -> Result<(String, WalkEnd), Error> {
        validate(path)?;
        let reject_traversal = matches!(
            policy,
            LinkPolicy::NoFollowAny | LinkPolicy::NoFollowAncestors
        );
        let follow_last = matches!(policy, LinkPolicy::Follow | LinkPolicy::NoFollowAny);
        let (relative, mut current, mut entry) = match search_from {
            Some((relative, directory)) => {
                let base = path
                    .strip_suffix(relative)
                    .and_then(|prefix| prefix.strip_suffix('/'))
                    .ok_or(Error::InvalidPath)?;
                let entry = Entry {
                    ino: directory.ino,
                    kind: Kind::WorkspaceDirectory(directory.clone()),
                };
                (relative, base.to_owned(), entry)
            }
            None => (path, String::from("/"), self.entry("/", true)?),
        };
        let mut components = relative
            .split('/')
            .filter(|c| !c.is_empty())
            .enumerate()
            .peekable();
        while let Some((index, component)) = components.next() {
            if !entry.is_dir() {
                return Err(Error::NotDirectory);
            }
            if let Some((ids, groups)) = access
                && let Some(directory) = entry.workspace_directory()
                && (index != 0 || search_from.is_none())
                && !directory.permits(1, ids, groups)
            {
                return Err(Error::AccessDenied);
            }
            let follow = match component {
                "." => true,
                ".." => {
                    if let Some(roots) = &self.native_libraries
                        && roots.owns(&entry)
                        && let Some(parent) = roots.parent_after_following(&current)?
                    {
                        current = parent;
                    } else {
                        let end = current.rfind('/').expect("absolute path");
                        current.truncate(end.max(1));
                    }
                    true
                }
                name => {
                    if current != "/" {
                        current.push('/');
                    }
                    current.push_str(name);
                    follow_last || components.peek().is_some() || path.ends_with('/')
                }
            };
            if current.len() >= PATH_MAX {
                return Err(Error::TooLong);
            }
            let missing = if components.peek().is_some()
                || (missing_last == MissingLast::File && path.ends_with('/'))
            {
                MissingLast::Reject
            } else {
                missing_last
            };
            entry = match self.entry(&current, follow && !reject_traversal) {
                Err(Error::NotFound) if missing != MissingLast::Reject => {
                    return Ok((current, WalkEnd::Missing { parent: entry }));
                }
                result => result?,
            };
            if follow && let Some(target) = entry.link_target() {
                if reject_traversal {
                    return Err(Error::LinkLoop);
                }
                *links_left = links_left.checked_sub(1).ok_or(Error::LinkLoop)?;
                let target = std::str::from_utf8(target).map_err(|_| Error::InvalidPath)?;
                if target.is_empty() {
                    return Err(Error::NotFound);
                }
                let target = if target.starts_with('/') {
                    std::borrow::Cow::Borrowed(target)
                } else {
                    let (parent, _) = current.rsplit_once('/').expect("absolute link path");
                    std::borrow::Cow::Owned(format!("{parent}/{target}"))
                };
                let (resolved, target) = self.walk(
                    &target,
                    LinkPolicy::Follow,
                    links_left,
                    access,
                    missing,
                    None,
                )?;
                current = resolved;
                match target {
                    WalkEnd::Found(target) => entry = target,
                    missing @ WalkEnd::Missing { .. } => return Ok((current, missing)),
                }
            }
        }
        if path.ends_with('/') && !entry.is_dir() {
            return Err(Error::NotDirectory);
        }
        Ok((current, WalkEnd::Found(entry)))
    }

    pub fn read(&self, path: &str) -> Result<Arc<[u8]>, Error> {
        self.lookup(path)?.1.bytes()
    }

    pub(super) fn directory_entries(
        &self,
        path: &str,
        entry: &Entry,
    ) -> Result<Vec<(String, Entry)>, Error> {
        if entry
            .workspace_directory()
            .is_some_and(|directory| !directory.linked())
        {
            return Ok(Vec::new());
        }
        let current;
        let path = match entry.workspace_directory() {
            Some(directory) => {
                current = directory.path()?;
                &current
            }
            None => path,
        };
        let parent = self.lookup(&format!("{path}/.."))?.1;
        let mut entries = vec![(".".to_owned(), entry.clone()), ("..".to_owned(), parent)];
        entries.extend(self.children(path)?);
        Ok(entries)
    }

    /// Immediate children in byte-sorted name order, excluding `.` and `..`.
    pub fn children(&self, path: &str) -> Result<Vec<(String, Entry)>, Error> {
        let (canonical, entry) = self.lookup(path)?;
        if !entry.is_dir() {
            return Err(Error::NotDirectory);
        }
        let prefix = if canonical == "/" {
            "/".to_owned()
        } else {
            format!("{canonical}/")
        };
        let mut names: BTreeSet<String> = self
            .entries
            .range(prefix.clone()..)
            .take_while(|(key, _)| key.starts_with(&prefix))
            .filter_map(|(key, _)| {
                let name = &key[prefix.len()..];
                (!name.is_empty() && !name.contains('/')).then(|| name.to_string())
            })
            .collect();
        if let Some(scratch) = self.workspace_at(TEMP_DIRECTORY) {
            match canonical.as_str() {
                "/" => {
                    names.insert("tmp".to_owned());
                }
                _ => {
                    if let Some(directory) = entry.workspace_directory() {
                        names.extend(scratch.children(directory)?);
                    }
                }
            }
        }
        for roots in self.caller_roots.iter().chain(&self.native_libraries) {
            names.extend(roots.children(prefix.trim_end_matches('/'))?);
        }
        let mut children = Vec::new();
        for name in names {
            match self.entry(&format!("{prefix}{name}"), false) {
                Ok(entry) => children.push((name, entry)),
                Err(Error::NotFound) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(children)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_symlinks_preserve_the_supplied_namespace_permissions() {
        let files = Files::new(BTreeMap::from([(
            "/selected/readable".into(),
            Arc::from(b"caller bytes".as_slice()),
        )]))
        .unwrap()
        .with_temp_workspace(WorkspaceFlavor::Linux);
        let owner = (1000, 1000);
        files
            .create_workspace_symlink(
                "/tmp/readable",
                b"../selected/readable".to_vec(),
                0o077,
                owner,
                &[],
            )
            .unwrap();
        assert_eq!(
            files.read("/tmp/readable").unwrap().as_ref(),
            b"caller bytes"
        );
        assert_eq!(
            files.unlink_workspace_file("/selected/readable", owner, &[]),
            Err(Error::ReadOnly)
        );
        files
            .create_workspace_symlink(
                "/tmp/outside",
                b"../selected/new".to_vec(),
                0o077,
                owner,
                &[],
            )
            .unwrap();
        let target = files
            .workspace_create_path("/tmp/outside", owner, &[])
            .unwrap();
        assert_eq!(target, "/selected/new");
        assert!(matches!(
            files.create_workspace_file(&target, 0o600, owner, &[], false),
            Err(Error::ReadOnly)
        ));
        assert!(matches!(files.lookup(&target), Err(Error::NotFound)));
        files
            .unlink_workspace_file("/tmp/readable", owner, &[])
            .unwrap();
        assert_eq!(
            files.read("/selected/readable").unwrap().as_ref(),
            b"caller bytes"
        );
    }

    #[test]
    fn native_workspace_preserves_supplied_names_and_starts_each_session_empty() {
        let inputs = Files::new(BTreeMap::from([(
            "/tmp/owned".into(),
            Arc::from(&b"caller bytes"[..]),
        )]))
        .unwrap()
        .with_temp_workspace(WorkspaceFlavor::Linux);
        let first = inputs.fresh_session();
        let second = inputs.fresh_session();
        assert_eq!(
            first.lookup("/tmp").unwrap().1.workspace_mode(),
            Some(0o1777)
        );
        assert!(matches!(
            first.create_workspace_file("/tmp/owned", 0o600, (0, 0), &[], true),
            Err(Error::Exists)
        ));
        assert!(matches!(
            first.unlink_workspace_file("/tmp/owned", (0, 0), &[]),
            Err(Error::ReadOnly)
        ));
        assert!(matches!(
            first.create_workspace_file("/outside", 0o600, (0, 0), &[], true),
            Err(Error::ReadOnly)
        ));
        let (_, entry) = first
            .create_workspace_file("/tmp/created", 0o600, (0, 0), &[], true)
            .unwrap();
        entry
            .workspace_file()
            .unwrap()
            .write(None, b"guest bytes")
            .unwrap();
        assert_eq!(first.read("/tmp/created").unwrap().as_ref(), b"guest bytes");
        assert!(matches!(
            second.lookup("/tmp/created"),
            Err(Error::NotFound)
        ));
        assert!(matches!(
            inputs.lookup("/tmp/created"),
            Err(Error::NotFound)
        ));
        assert_eq!(first.read("/tmp/owned").unwrap().as_ref(), b"caller bytes");
        assert_eq!(
            first
                .children("/tmp")
                .unwrap()
                .into_iter()
                .map(|(name, _)| name)
                .collect::<Vec<_>>(),
            ["created", "owned"]
        );
    }

    #[test]
    fn native_workspace_creates_named_subdirectories_with_guest_ownership() {
        let files = Files::default().with_temp_workspace(WorkspaceFlavor::Linux);
        let group = "/tmp/group";
        let child = "/tmp/group/child";
        let file = "/tmp/group/child/data";
        let workspace = files.workspace.as_ref().unwrap();
        workspace
            .create_directory("group".to_owned(), 0o2770, (40, 50), &workspace.root)
            .unwrap();
        assert!(matches!(
            files.create_workspace_directory(child, 0o700, (41, 51), &[]),
            Err(Error::AccessDenied)
        ));
        files
            .create_workspace_directory(child, 0o700, (41, 51), &[50])
            .unwrap();
        let metadata = files.lookup(child).unwrap().1;
        assert!(metadata.is_dir());
        assert_eq!(metadata.workspace_mode(), Some(0o2700));
        assert_eq!(metadata.workspace_owner(), Some((41, 50)));
        assert!(matches!(
            files.create_workspace_directory(child, 0o700, (41, 51), &[50]),
            Err(Error::Exists)
        ));
        assert!(matches!(
            files.create_workspace_file(file, 0o600, (41, 51), &[], true),
            Err(Error::AccessDenied)
        ));
        let (path, entry) = files
            .create_workspace_file(file, 0o600, (41, 51), &[50], true)
            .unwrap();
        assert_eq!(path, file);
        assert_eq!(entry.workspace_owner(), Some((41, 50)));
        let group_nodes = files.children(group).unwrap();
        assert_eq!(group_nodes.len(), 1);
        assert_eq!(group_nodes[0].0, "child");
        assert_eq!(files.children(child).unwrap().len(), 1);
        assert!(matches!(
            files.lookup_for_guest(file, LinkPolicy::Follow, (41, 51), &[]),
            Err(Error::AccessDenied)
        ));
        files.unlink_workspace_file(file, (41, 51), &[50]).unwrap();
        assert!(files.children(child).unwrap().is_empty());
        assert!(matches!(
            files.create_workspace_directory("/separate", 0o700, (41, 51), &[]),
            Err(Error::ReadOnly)
        ));
    }

    #[test]
    fn native_workspace_removes_only_empty_owned_directories() {
        let files = Files::new(BTreeMap::from([(
            "/tmp/supplied/retained".to_owned(),
            Arc::from(&b"input"[..]),
        )]))
        .unwrap()
        .with_temp_workspace(WorkspaceFlavor::Linux);
        let owner = (51, 52);
        let name = "/tmp/removed";
        files
            .create_workspace_directory(name, 0o755, owner, &[])
            .unwrap();
        let before = files.lookup(name).unwrap().1;
        files
            .create_workspace_directory("/tmp/removed/nested", 0o700, owner, &[])
            .unwrap();
        assert_eq!(
            before
                .workspace_directory()
                .unwrap()
                .link_count(WorkspaceFlavor::Linux),
            3
        );
        assert_eq!(
            files.remove_workspace_directory(name, owner, &[]),
            Err(Error::NotEmpty)
        );
        assert_eq!(
            files.remove_workspace_directory("/tmp/supplied", owner, &[]),
            Err(Error::ReadOnly)
        );
        assert_eq!(
            files.remove_workspace_directory(name, (100, 0), &[]),
            Err(Error::PermissionDenied)
        );
        files
            .remove_workspace_directory("/tmp/removed/nested", owner, &[])
            .unwrap();
        files.remove_workspace_directory(name, owner, &[]).unwrap();
        assert_eq!(
            before
                .workspace_directory()
                .unwrap()
                .link_count(WorkspaceFlavor::Linux),
            0
        );
        assert!(files.directory_entries(name, &before).unwrap().is_empty());
        files
            .create_workspace_directory(name, 0o700, owner, &[])
            .unwrap();
        assert_ne!(files.lookup(name).unwrap().1.ino, before.ino);
        assert!(matches!(
            relative_workspace_path(name, before.workspace_directory(), "new-child", owner, &[]),
            Err(Error::NotFound)
        ));
    }

    #[test]
    fn native_darwin_workspace_inherits_parent_group() {
        let files = Files::default().with_temp_workspace(WorkspaceFlavor::Darwin);
        files
            .create_workspace_directory("/tmp/private", 0o7777, (41, 51), &[])
            .unwrap();
        let dir = files.lookup("/tmp/private").unwrap().1;
        assert_eq!(dir.workspace_mode(), Some(0o777));
        assert_eq!(dir.workspace_owner(), Some((41, 0)));
        let (_, file) = files
            .create_workspace_file("/tmp/private/data", 0o600, (41, 51), &[], true)
            .unwrap();
        assert_eq!(file.workspace_owner(), Some((41, 0)));
        assert!(matches!(
            files.create_workspace_directory("/tmp/private/data/", 0o700, (41, 51), &[]),
            Err(Error::NotDirectory)
        ));
    }

    fn files() -> Files {
        Files::new(BTreeMap::from([
            ("/bin/prog".into(), Arc::from(&b"program"[..])),
            ("/lib/libc.so".into(), Arc::from(&b"library"[..])),
            ("/LIB".into(), Arc::from(&b"case"[..])),
            ("/unicode/\u{3bb}".into(), Arc::from(&b"utf8"[..])),
        ]))
        .unwrap()
    }
    #[test]
    fn selected_roots_are_lazy_read_only_and_preserved_by_extensions() {
        let fixture = super::test_backing::TestFile::new(b"host-library", 12);
        let files = Files::default()
            .with_host_roots(BTreeMap::from([("/usr/lib".into(), fixture.dir.clone())]))
            .unwrap();
        // A file created after root selection is discoverable on demand.
        std::fs::write(fixture.dir.join("later"), b"late").unwrap();
        assert_eq!(&*files.read("/usr/lib/later").unwrap(), b"late");
        let entry = files.lookup("/usr/lib/backing").unwrap().1;
        assert!(matches!(entry.kind, Kind::Backed(_)));
        assert_eq!(&*entry.bytes().unwrap(), b"host-library");
        assert!(matches!(
            files.lookup("/usr/lib/BACKING"),
            Err(Error::NotFound)
        ));
        for name in ["/usr/lib/..\\backing", "/usr/lib/C:backing"] {
            assert!(matches!(files.lookup(name), Err(Error::NotFound)));
        }
        assert!(matches!(files.lookup("/etc/hosts"), Err(Error::NotFound)));
        assert!(matches!(
            files.lookup("/usr/libextra/backing"),
            Err(Error::NotFound)
        ));
        let extended = files
            .with_file("/usr/lib/backing".into(), Arc::from(&b"override"[..]))
            .unwrap()
            .with_file("/program".into(), Arc::from(&b"program"[..]))
            .unwrap();
        assert_eq!(&*extended.read("/usr/lib/backing").unwrap(), b"override");
        assert_eq!(&*files.read("/usr/lib/backing").unwrap(), b"host-library");
        assert_eq!(&*extended.read("/usr/lib/later").unwrap(), b"late");
        assert_eq!(
            extended
                .children("/usr/lib")
                .unwrap()
                .into_iter()
                .map(|(name, _)| name)
                .collect::<Vec<_>>(),
            ["backing", "later"]
        );
        assert!(files.with_host_roots(BTreeMap::new()).is_err());
        assert!(
            Files::default()
                .with_host_roots(BTreeMap::from([("/".into(), fixture.dir.clone())]))
                .is_err()
        );
        assert!(
            Files::default()
                .with_host_roots(BTreeMap::from([("/lib".into(), fixture.path.clone())]))
                .is_err()
        );
        assert!(files.with_file("/usr".into(), Arc::from([])).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn selected_roots_reject_symlink_escape_and_nonregular_backing() {
        use std::os::unix::fs::symlink;
        let fixture = super::test_backing::TestFile::new(b"allowed", 7);
        let outside = super::test_backing::TestFile::new(b"outside", 7);
        symlink(&outside.path, fixture.dir.join("escape")).unwrap();
        symlink(&fixture.path, fixture.dir.join("alias")).unwrap();
        let fifo = fixture.dir.join("fifo");
        let name = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let files = Files::default()
            .with_host_roots(BTreeMap::from([("/lib".into(), fixture.dir.clone())]))
            .unwrap();
        assert_eq!(&*files.read("/lib/alias").unwrap(), b"allowed");
        assert!(matches!(files.lookup("/lib/escape"), Err(Error::NotFound)));
        assert!(matches!(files.lookup("/lib/fifo"), Err(Error::NotFound)));
        assert_eq!(
            files
                .children("/lib")
                .unwrap()
                .into_iter()
                .map(|(name, _)| name)
                .collect::<Vec<_>>(),
            ["alias", "backing"]
        );
        let both = Files::default()
            .with_host_roots(BTreeMap::from([
                ("/lib".into(), fixture.dir.clone()),
                ("/other".into(), outside.dir.clone()),
            ]))
            .unwrap();
        assert_eq!(&*both.read("/lib/escape").unwrap(), b"outside");
    }
    #[test]
    fn selected_backing_is_demand_read_and_survives_namespace_extension() {
        let fixture = super::test_backing::TestFile::new(b"native-runtime", (64 << 20) + 1);
        let files = Files::default()
            .with_host_file("/cache".into(), &fixture.path)
            .unwrap();
        let entry = files.lookup("/cache").unwrap().1;
        assert_eq!(entry.len(), (64 << 20) + 1);
        assert!(matches!(entry.bytes(), Err(Error::TooLarge)));
        let source = entry.source().unwrap();
        let mut out = [0xaa; 14];
        assert_eq!(source.read_at(0, &mut out).unwrap(), 14);
        assert_eq!(&out, b"native-runtime");
        assert_eq!(source.identity().ino, entry.ino);
        assert_eq!(source.identity().dev, 0x524158);
        assert_eq!(source.read_at(entry.len(), &mut out).unwrap(), 0);
        assert!(source.read_at(u64::MAX, &mut out).is_err());
        let next = files
            .clone()
            .with_file("/program".into(), Arc::from(&b"program"[..]))
            .unwrap();
        drop(files);
        assert!(matches!(
            next.lookup("/cache").unwrap().1.kind,
            Kind::Backed(_)
        ));
        let source = next.lookup("/cache").unwrap().1.source().unwrap();
        assert_eq!(source.read_at(0, &mut out).unwrap(), 14);
        assert_eq!(&out, b"native-runtime");
        assert!(matches!(
            next.lookup("/host/not-selected"),
            Err(Error::NotFound)
        ));
        assert!(matches!(
            next.with_host_file("/cache".into(), &fixture.path)
                .unwrap_err()
                .get_ref()
                .unwrap()
                .downcast_ref::<Error>(),
            Some(Error::Exists)
        ));
    }

    #[test]
    fn selected_file_images_are_bounded_and_only_regular_files_are_admitted() {
        let fixture = super::test_backing::TestFile::new(b"image", 5);
        let files = Files::default()
            .with_host_file("/dyld".into(), &fixture.path)
            .unwrap();
        assert_eq!(&*files.read("/dyld").unwrap(), b"image");
        assert!(
            Files::default()
                .with_host_file("/directory".into(), &fixture.dir)
                .is_err()
        );
        assert!(
            Files::default()
                .with_host_file("relative".into(), &fixture.path)
                .is_err()
        );
        assert!(
            Files::default()
                .with_host_file("/missing".into(), &fixture.dir.join("missing"))
                .is_err()
        );
        let source = files.lookup("/dyld").unwrap().1.source().unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&fixture.path)
            .unwrap()
            .set_len(2)
            .unwrap();
        assert_eq!(source.len(), 2); // Explicit live-backing boundary.
        assert_eq!(&*files.read("/dyld").unwrap(), b"im");
    }

    #[test]
    fn supplied_lookup_is_posix_case_sensitive_and_never_normalizes_host_paths() {
        let files = files();
        assert_eq!(&*files.read("//bin/./prog").unwrap(), b"program");
        assert_eq!(&*files.read("/lib/../LIB").unwrap(), b"case");
        assert_eq!(&*files.read("/unicode/\u{3bb}").unwrap(), b"utf8");
        assert!(matches!(files.read("/Lib"), Err(Error::NotFound)));
        assert!(matches!(
            files.read("C:\\bin\\prog"),
            Err(Error::InvalidPath)
        ));
        assert!(files.lookup("/../../").unwrap().1.is_dir());
        assert_eq!(
            files
                .children("/")
                .unwrap()
                .iter()
                .map(|(n, _)| n.as_str())
                .collect::<Vec<_>>(),
            ["LIB", "bin", "lib", "unicode"]
        );
    }
    #[test]
    fn components_must_exist_and_be_directories_before_dot_dot() {
        let files = files();
        for path in ["/bin/prog/", "/bin/prog/.", "/bin/prog/../prog", "/LIB/lib"] {
            assert!(
                matches!(files.lookup(path), Err(Error::NotDirectory)),
                "{path}"
            );
        }
        assert!(matches!(
            files.lookup("/missing/../bin"),
            Err(Error::NotFound)
        ));
        assert!(matches!(files.read("/bin"), Err(Error::IsDirectory)));
    }
    #[test]
    fn supplied_keys_are_validated_and_inferred_directory_collisions_rejected() {
        for path in [
            "", "/", "relative", "/a/", "/a//b", "/a/./b", "/a/../b", "/a\0b",
        ] {
            assert!(
                Files::new(BTreeMap::from([(path.into(), Arc::from([]))])).is_err(),
                "{path}"
            );
        }
        let long = format!("/{}", "a".repeat(PATH_MAX - 1));
        assert!(matches!(
            Files::new(BTreeMap::from([(long, Arc::from([]))])),
            Err(Error::TooLong)
        ));
        assert!(matches!(
            Files::new(BTreeMap::from([
                ("/a".into(), Arc::from([])),
                ("/a/b".into(), Arc::from([]))
            ])),
            Err(Error::Exists)
        ));
    }
    #[test]
    fn namespace_clones_share_payload_and_new_images_do_not_change_old_namespace() {
        let original = files();
        let cloned = original.clone();
        assert!(Arc::ptr_eq(
            &original.read("/bin/prog").unwrap(),
            &cloned.read("/bin/prog").unwrap()
        ));
        let extended = original
            .with_file("/new/image".into(), Arc::from(&b"new"[..]))
            .unwrap();
        assert!(matches!(original.read("/new/image"), Err(Error::NotFound)));
        assert_eq!(&*extended.read("/new/image").unwrap(), b"new");
        assert!(matches!(
            original.with_file("/bin/prog".into(), Arc::from([])),
            Err(Error::Exists)
        ));
        assert!(matches!(
            original.with_file("/bin".into(), Arc::from([])),
            Err(Error::Exists)
        ));
    }
    #[test]
    fn utf8_component_and_total_path_byte_limits_are_exact() {
        let name = format!("{}a", "é".repeat(127));
        assert_eq!(name.len(), NAME_MAX);
        let path = format!("/{name}");
        let namespace = Files::new(BTreeMap::from([(path.clone(), Arc::from([]))])).unwrap();
        assert!(namespace.lookup(&path).is_ok());
        assert!(matches!(
            namespace.lookup(&format!("/{}", "é".repeat(128))),
            Err(Error::TooLong)
        ));
        let path = format!(
            "/{}/{}",
            vec!["a".repeat(255); 15].join("/"),
            "b".repeat(254)
        );
        assert_eq!(path.len(), PATH_MAX - 1);
        let namespace = Files::new(BTreeMap::from([(path.clone(), Arc::from([]))])).unwrap();
        assert!(namespace.lookup(&path).is_ok());
        assert!(matches!(
            namespace.lookup(&format!("{path}b")),
            Err(Error::TooLong)
        ));
        assert!(matches!(
            Files::new(BTreeMap::from([(format!("{path}b"), Arc::from([]))])),
            Err(Error::TooLong)
        ));
    }
}

#[cfg(test)]
pub(crate) mod test_backing {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    pub(crate) struct TestFile {
        pub path: PathBuf,
        pub dir: PathBuf,
    }
    impl TestFile {
        pub(crate) fn new(bytes: &[u8], size: u64) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "rax-selected-file-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&dir).unwrap();
            let value = Self {
                path: dir.join("backing"),
                dir,
            };
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&value.path)
                .unwrap();
            std::io::Write::write_all(&mut file, bytes).unwrap();
            file.set_len(size).unwrap();
            value
        }
    }
    impl Drop for TestFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}
