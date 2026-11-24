//! Demand-read mounts of caller-selected library directories. The guest can
//! only read regular files in these roots; it never receives host descriptors.
use super::{Entry, Error, Kind, validate};
use crate::user::mm::HostFileSource;
use std::{
    collections::BTreeMap,
    ffi::OsStr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

const MAX_ENTRIES: usize = 2048;
pub(super) type AcceptFile = fn(&str, &std::fs::File) -> std::io::Result<bool>;

#[derive(Debug)]
pub(super) struct Origin {
    inode_base: u64,
    accept: Option<AcceptFile>,
    observe_symlinks: bool,
    confined_mounts: &'static [&'static str],
    max_entries: usize,
}

impl Origin {
    pub(super) const CALLER: Self = Self {
        inode_base: 0x8000_0000_0000_0000,
        accept: None,
        observe_symlinks: false,
        confined_mounts: &[],
        max_entries: MAX_ENTRIES,
    };

    #[cfg(any(target_os = "linux", test))]
    pub(super) const LINUX_INSTALLED: Self = Self {
        inode_base: 0xc000_0000_0000_0000,
        accept: None,
        observe_symlinks: true,
        confined_mounts: &[],
        max_entries: MAX_ENTRIES,
    };

    #[cfg(any(target_os = "macos", test))]
    pub(super) fn darwin_installed(
        accept: Option<AcceptFile>,
        confined_mounts: &'static [&'static str],
    ) -> Self {
        Self {
            inode_base: 0xc000_0000_0000_0000,
            accept,
            observe_symlinks: false,
            confined_mounts,
            // The system locale tree alone can contain over 2048 entries.
            max_entries: 4096,
        }
    }
}

#[derive(Debug, Default)]
struct Entries {
    files: BTreeMap<String, Entry>,
    links: BTreeMap<String, Entry>,
}

#[derive(Debug)]
pub(super) struct Roots {
    roots: BTreeMap<String, PathBuf>,
    mount_links: BTreeMap<String, Arc<[u8]>>,
    entries: Mutex<Entries>,
    origin: Origin,
}
impl Roots {
    pub(super) fn new(roots: BTreeMap<String, PathBuf>, origin: Origin) -> std::io::Result<Self> {
        let mut canonical = BTreeMap::new();
        let mut mount_links = BTreeMap::new();
        for (guest, host) in roots {
            validate(&guest).map_err(std::io::Error::other)?;
            if guest == "/"
                || guest
                    .split('/')
                    .skip(1)
                    .any(|c| c.is_empty() || c == "." || c == "..")
            {
                return Err(std::io::Error::other(Error::InvalidPath));
            }
            let host_directory = std::fs::canonicalize(&host)?;
            if !host_directory.is_dir() {
                return Err(std::io::Error::other(Error::NotDirectory));
            }
            if origin.observe_symlinks
                && let Some(target) = link_target(&host).map_err(std::io::Error::other)?
            {
                mount_links.insert(guest.clone(), target);
            }
            canonical.insert(guest, host_directory);
        }
        Ok(Self {
            roots: canonical,
            mount_links,
            entries: Mutex::new(Entries::default()),
            origin,
        })
    }
    pub(super) fn paths(&self) -> impl Iterator<Item = &str> {
        self.roots.keys().map(String::as_str)
    }
    fn mount(&self, guest: &str) -> Option<(&str, &Path)> {
        self.roots
            .iter()
            .filter(|(root, _)| {
                guest == root.as_str()
                    || guest
                        .strip_prefix(root.as_str())
                        .is_some_and(|rest| rest.starts_with('/'))
            })
            .max_by_key(|(root, _)| root.len())
            .map(|(root, host)| (root.as_str(), host.as_path()))
    }
    fn host(&self, guest: &str) -> Result<PathBuf, Error> {
        let (root, host) = self.mount(guest).ok_or(Error::NotFound)?;
        let relative = guest[root.len()..].trim_start_matches('/');
        // These are POSIX guest components, not a Windows path or ADS name.
        // Reject native separators/drive syntax before any host resolution.
        #[cfg(windows)]
        if relative.split('/').any(|name| name.contains(['\\', ':'])) {
            return Err(Error::NotFound);
        }
        let path = host.join(relative);
        let canonical = std::fs::canonicalize(path).map_err(path_error)?;
        let confined = self.origin.confined_mounts.contains(&root);
        let allowed = if confined {
            canonical.starts_with(host)
        } else {
            self.roots.values().any(|root| canonical.starts_with(root))
        };
        if !allowed {
            return Err(Error::NotFound);
        }
        // Compare the guest spelling with the directory entries even when
        // native lookup folds case. Canonical containment above checks the
        // resolved target independently of its guest-visible name.
        let mut parent = host.to_path_buf();
        for name in relative.split('/').filter(|name| !name.is_empty()) {
            if !host_entry_has_name(&parent, name).map_err(|_| Error::Io)? {
                return Err(Error::NotFound);
            }
            parent.push(name);
        }
        Ok(canonical)
    }

    pub(super) fn parent_after_following(&self, guest: &str) -> Result<Option<String>, Error> {
        if !self.origin.observe_symlinks {
            return Ok(None);
        }
        let Some((mount, host)) = self.mount(guest) else {
            return Ok(None);
        };
        let canonical = match self.host(guest) {
            Ok(path) => path,
            Err(Error::NotFound) => return Ok(None),
            Err(error) => return Err(error),
        };
        let relative = guest[mount.len()..].trim_start_matches('/');
        if !self.mount_links.contains_key(guest) && canonical == host.join(relative) {
            return Ok(None);
        }

        // Translate the selected target back to a guest mount. For /lib64 ->
        // usr/lib64, prefer /usr/lib64 so its parent is /usr in the guest.
        let (target_mount, suffix) = self
            .roots
            .iter()
            .filter_map(|(root, host)| {
                let suffix = canonical.strip_prefix(host).ok()?;
                Some((root, host, suffix))
            })
            .max_by_key(|(root, host, _)| {
                (
                    !self.mount_links.contains_key(*root),
                    host.as_os_str().len(),
                )
            })
            .map(|(root, _, suffix)| (root, suffix))
            .ok_or(Error::NotFound)?;
        let Some(suffix_parent) = suffix.parent() else {
            let end = target_mount.rfind('/').expect("absolute mount");
            return Ok(Some(target_mount[..end.max(1)].to_owned()));
        };
        let mut parent = target_mount.clone();
        for component in suffix_parent {
            parent.push('/');
            parent.push_str(component.to_str().ok_or(Error::NotFound)?);
        }
        validate(&parent)?;
        Ok(Some(parent))
    }

    pub(super) fn directory_ino(&self, path: &str) -> Result<u64, Error> {
        self.insert(path, Kind::Directory).map(|entry| entry.ino)
    }
    pub(super) fn owns(&self, entry: &Entry) -> bool {
        let base = self.origin.inode_base;
        (base..base + self.origin.max_entries as u64).contains(&entry.ino)
    }

    fn insert(&self, path: &str, kind: Kind) -> Result<Entry, Error> {
        let mut entries = self.entries.lock().map_err(|_| Error::Io)?;
        let index = entries.files.len() + entries.links.len();
        let table = if matches!(kind, Kind::Symlink(_)) {
            &mut entries.links
        } else {
            &mut entries.files
        };
        if let Some(entry) = table.get(path) {
            return Ok(entry.clone());
        }
        if index >= self.origin.max_entries {
            return Err(Error::TooLarge);
        }
        let entry = Entry {
            ino: self.origin.inode_base | index as u64,
            kind,
        };
        table.insert(path.to_owned(), entry.clone());
        Ok(entry)
    }

    pub(super) fn mount_link(&self, path: &str) -> Result<Option<Entry>, Error> {
        self.mount_links
            .get(path)
            .map(|target| self.insert(path, Kind::Symlink(target.clone())))
            .transpose()
    }

    pub(super) fn symlink(&self, path: &str) -> Result<Option<Entry>, Error> {
        if !self.origin.observe_symlinks {
            return Ok(None);
        }
        if let Some(entry) = self
            .entries
            .lock()
            .map_err(|_| Error::Io)?
            .links
            .get(path)
            .cloned()
        {
            return Ok(Some(entry));
        }
        let Some((parent, name)) = path.rsplit_once('/') else {
            return Ok(None);
        };
        // Resolve and confine the parent before reading the directory entry.
        // The target bytes may describe a missing or unselected destination.
        let parent = match self.host(parent) {
            Ok(parent) => parent,
            Err(Error::NotFound) => return Ok(None),
            Err(error) => return Err(error),
        };
        if !host_entry_has_name(&parent, name).map_err(path_error)? {
            return Ok(None);
        }
        link_target(&parent.join(name))?
            .map(|target| self.insert(path, Kind::Symlink(target)))
            .transpose()
    }

    pub(super) fn lookup(&self, path: &str) -> Result<Entry, Error> {
        if let Some(entry) = self
            .entries
            .lock()
            .map_err(|_| Error::Io)?
            .files
            .get(path)
            .cloned()
        {
            return Ok(entry);
        }
        let host = self.host(path)?;
        if host.is_dir() {
            return self.insert(path, Kind::Directory);
        }
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NONBLOCK);
        }
        let file = options.open(host).map_err(|_| Error::Io)?;
        if !file.metadata().map_err(|_| Error::Io)?.is_file() {
            return Err(Error::NotFound);
        }
        if let Some(accept) = self.origin.accept
            && !accept(path, &file).map_err(|_| Error::Io)?
        {
            return Err(Error::NotFound);
        }
        self.insert(
            path,
            Kind::Backed(Arc::new(HostFileSource::new(file).map_err(|_| Error::Io)?)),
        )
    }
    pub(super) fn children(&self, path: &str) -> Result<Vec<String>, Error> {
        let host = match self.host(path) {
            Ok(host) => host,
            Err(Error::NotFound) => return Ok(vec![]),
            Err(e) => return Err(e),
        };
        let mut names = Vec::new();
        for entry in std::fs::read_dir(host).map_err(|_| Error::Io)? {
            let entry = entry.map_err(|_| Error::Io)?;
            if let Some(name) = entry.file_name().to_str() {
                names.push(name.to_owned());
            }
            if names.len() > MAX_ENTRIES {
                return Err(Error::TooLarge);
            }
        }
        Ok(names)
    }
}

fn host_entry_has_name(parent: &Path, name: &str) -> std::io::Result<bool> {
    let mut entries = match std::fs::read_dir(parent) {
        Ok(entries) => entries,
        // Search-only Linux directories can resolve a known name even when
        // they cannot be listed. Preserve native lookup in that case.
        #[cfg(target_os = "linux")]
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return Ok(true),
        Err(error) => return Err(error),
    };
    let name = OsStr::new(name);
    Ok(entries.any(|entry| entry.is_ok_and(|entry| entry.file_name() == name)))
}

fn path_error(error: std::io::Error) -> Error {
    #[cfg(unix)]
    if error.raw_os_error() == Some(libc::ELOOP) {
        return Error::LinkLoop;
    }
    match error.kind() {
        std::io::ErrorKind::NotADirectory => Error::NotDirectory,
        std::io::ErrorKind::NotFound => Error::NotFound,
        _ => Error::Io,
    }
}

fn link_target(path: &std::path::Path) -> Result<Option<Arc<[u8]>>, Error> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        match std::fs::read_link(path) {
            Ok(target) => Ok(Some(Arc::from(target.as_os_str().as_bytes()))),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::InvalidInput | std::io::ErrorKind::NotFound
                ) =>
            {
                Ok(None)
            }
            Err(error) => Err(path_error(error)),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(None)
    }
}
