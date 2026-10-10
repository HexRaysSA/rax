//! Demand-read mounts of caller-selected library directories. The guest can
//! only read regular files in these roots; it never receives host descriptors.
use super::{Entry, Error, Kind, validate};
use crate::user::mm::HostFileSource;
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};

const MAX_ENTRIES: usize = 2048;
#[derive(Debug)]
pub(super) struct Roots {
    roots: BTreeMap<String, PathBuf>,
    entries: Mutex<BTreeMap<String, Entry>>,
}
impl Roots {
    pub(super) fn new(roots: BTreeMap<String, PathBuf>) -> std::io::Result<Self> {
        let mut canonical = BTreeMap::new();
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
            let host = std::fs::canonicalize(host)?;
            if !host.is_dir() {
                return Err(std::io::Error::other(Error::NotDirectory));
            }
            canonical.insert(guest, host);
        }
        Ok(Self {
            roots: canonical,
            entries: Mutex::new(BTreeMap::new()),
        })
    }
    pub(super) fn paths(&self) -> impl Iterator<Item = &str> {
        self.roots.keys().map(String::as_str)
    }
    fn host(&self, guest: &str) -> Result<PathBuf, Error> {
        let (root, host) = self
            .roots
            .iter()
            .filter(|(root, _)| {
                guest == root.as_str()
                    || guest
                        .strip_prefix(root.as_str())
                        .is_some_and(|rest| rest.starts_with('/'))
            })
            .max_by_key(|(root, _)| root.len())
            .ok_or(Error::NotFound)?;
        let relative = guest[root.len()..].trim_start_matches('/');
        // These are POSIX guest components, not a Windows path or ADS name.
        // Reject native separators/drive syntax before any host resolution.
        #[cfg(windows)]
        if relative.split('/').any(|name| name.contains(['\\', ':'])) {
            return Err(Error::NotFound);
        }
        let path = host.join(relative);
        let canonical = std::fs::canonicalize(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotADirectory {
                Error::NotDirectory
            } else if e.kind() == std::io::ErrorKind::NotFound {
                Error::NotFound
            } else {
                Error::Io
            }
        })?;
        if !self.roots.values().any(|root| canonical.starts_with(root)) {
            return Err(Error::NotFound);
        }
        // POSIX guest names remain byte-case-sensitive even on a host volume
        // whose native lookup folds case. Native symlink targets are checked by
        // canonical containment above; this checks each guest-requested name.
        #[cfg(any(target_os = "macos", windows))]
        {
            let mut parent = host.clone();
            for name in guest[root.len()..]
                .split('/')
                .filter(|name| !name.is_empty())
            {
                let found = std::fs::read_dir(&parent)
                    .map_err(|_| Error::Io)?
                    .any(|entry| {
                        entry.is_ok_and(|entry| entry.file_name() == std::ffi::OsStr::new(name))
                    });
                if !found {
                    return Err(Error::NotFound);
                }
                parent.push(name);
            }
        }
        Ok(canonical)
    }
    pub(super) fn directory_ino(&self, path: &str) -> Result<u64, Error> {
        self.insert(path, Kind::Directory).map(|entry| entry.ino)
    }
    fn insert(&self, path: &str, kind: Kind) -> Result<Entry, Error> {
        let mut entries = self.entries.lock().map_err(|_| Error::Io)?;
        if let Some(entry) = entries.get(path) {
            return Ok(entry.clone());
        }
        if entries.len() >= MAX_ENTRIES {
            return Err(Error::TooLarge);
        }
        let entry = Entry {
            ino: 0x8000_0000_0000_0000 | entries.len() as u64,
            kind,
        };
        entries.insert(path.to_owned(), entry.clone());
        Ok(entry)
    }
    pub(super) fn lookup(&self, path: &str) -> Result<Entry, Error> {
        if let Some(entry) = self
            .entries
            .lock()
            .map_err(|_| Error::Io)?
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
