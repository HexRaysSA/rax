//! Read-only POSIX guest files selected by an embedder, independent of host paths.
//!
//! File keys are canonical absolute UTF-8 guest paths. Directories are inferred;
//! there is no unselected host fallback or writable object. Explicit directory
//! roots allow on-demand lookup; their host symlinks must target selected roots.
//! Selected open files can back entries without copying their complete contents. Lookup walks
//! components before interpreting `..`, so `/file/../other` is `NotDirectory`.
use std::collections::BTreeMap;
use std::sync::Arc;

use crate::user::mm::{BytesSource, HostFileSource, PageSource, SourceIdentity};
mod roots;
use roots::Roots;

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
    IsDirectory,
    Io,
    TooLarge,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidPath => "invalid supplied guest path",
            Self::TooLong => "supplied guest path exceeds PATH_MAX",
            Self::Exists => "conflicting supplied file or directory",
            Self::NotFound => "guest path is not supplied",
            Self::NotDirectory => "guest path component is not a directory",
            Self::IsDirectory => "guest path is a directory",
            Self::Io => "selected guest backing file read failed",
            Self::TooLarge => "selected guest backing exceeds its image or namespace limit",
        })
    }
}
impl std::error::Error for Error {}

#[derive(Clone, Debug)]
pub enum Kind {
    File(Arc<[u8]>),
    /// Read-only backing selected by the embedder, never by a guest pathname.
    Backed(Arc<HostFileSource>),
    Directory,
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
        matches!(self.kind, Kind::Directory)
    }
    pub fn bytes(&self) -> Result<Arc<[u8]>, Error> {
        match &self.kind {
            Kind::File(bytes) => Ok(bytes.clone()),
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
            Kind::Directory => Err(Error::IsDirectory),
        }
    }

    /// File length without materializing its contents. Directories have size zero.
    pub fn len(&self) -> u64 {
        match &self.kind {
            Kind::File(bytes) => bytes.len() as u64,
            Kind::Backed(source) => source.len(),
            Kind::Directory => 0,
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
            Kind::Directory => return Err(Error::IsDirectory),
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
pub struct Files(Arc<BTreeMap<String, Entry>>, Option<Arc<Roots>>);
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
        Ok(Self(Arc::new(entries), None))
    }

    /// Produces a new namespace with an additional file. Used to include the
    /// executable itself before starting a process; existing paths are refused.
    pub fn with_file(&self, path: String, bytes: Arc<[u8]>) -> Result<Self, Error> {
        self.with_kind(path, Kind::File(bytes))
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
            .0
            .iter()
            .filter_map(|(path, entry)| {
                (!entry.is_dir()).then(|| (path.clone(), entry.kind.clone()))
            })
            .collect();
        let mut sources: BTreeMap<std::path::PathBuf, Arc<HostFileSource>> = BTreeMap::new();
        for (path, host) in selected {
            if self.0.contains_key(&path) {
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
        next.1 = self.1.clone();
        next.restore_roots().map_err(std::io::Error::other)?;
        Ok(next)
    }

    fn with_kind(&self, path: String, kind: Kind) -> Result<Self, Error> {
        if self.0.contains_key(&path) {
            return Err(Error::Exists);
        }
        let mut files: BTreeMap<_, _> = self
            .0
            .iter()
            .filter_map(|(path, entry)| {
                (!entry.is_dir()).then(|| (path.clone(), entry.kind.clone()))
            })
            .collect();
        files.insert(path, kind);
        let mut next = Self::from_kinds(files)?;
        next.1 = self.1.clone();
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
        if self.1.is_some() {
            return Err(std::io::Error::other(Error::Exists));
        }
        let roots = Arc::new(Roots::new(roots)?);
        let mut next = Self(self.0.clone(), Some(roots));
        next.restore_roots().map_err(std::io::Error::other)?;
        Ok(next)
    }

    fn restore_roots(&mut self) -> Result<(), Error> {
        let Some(roots) = &self.1 else { return Ok(()) };
        let entries = Arc::make_mut(&mut self.0);
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
        Ok(())
    }

    fn entry(&self, path: &str) -> Result<Entry, Error> {
        if let Some(entry) = self.0.get(path) {
            return Ok(entry.clone());
        }
        self.1.as_ref().ok_or(Error::NotFound)?.lookup(path)
    }

    /// Resolves an absolute guest path, retaining directory checks before `..`.
    /// Returns its canonical guest name and a shared entry; never a host path.
    pub fn lookup(&self, path: &str) -> Result<(String, Entry), Error> {
        validate(path)?;
        let mut current = String::from("/");
        let mut entry = self.entry("/")?;
        for component in path.split('/').filter(|c| !c.is_empty()) {
            if !entry.is_dir() {
                return Err(Error::NotDirectory);
            }
            match component {
                "." => {}
                ".." => {
                    let end = current.rfind('/').expect("absolute path");
                    current.truncate(end.max(1));
                }
                name => {
                    if current != "/" {
                        current.push('/');
                    }
                    current.push_str(name);
                }
            }
            entry = self.entry(&current)?;
        }
        if path.ends_with('/') && !entry.is_dir() {
            return Err(Error::NotDirectory);
        }
        Ok((current, entry))
    }

    pub fn read(&self, path: &str) -> Result<Arc<[u8]>, Error> {
        self.lookup(path)?.1.bytes()
    }

    /// Immediate children in byte-sorted name order, excluding `.` and `..`.
    pub fn children(&self, path: &str) -> Result<Vec<(String, Entry)>, Error> {
        let (canonical, entry) = self.lookup(path)?;
        if !entry.is_dir() {
            return Err(Error::NotDirectory);
        }
        let prefix = if canonical == "/" {
            canonical
        } else {
            format!("{canonical}/")
        };
        let mut children: BTreeMap<String, Entry> = self
            .0
            .range(prefix.clone()..)
            .take_while(|(key, _)| key.starts_with(&prefix))
            .filter_map(|(key, value)| {
                let name = &key[prefix.len()..];
                (!name.is_empty() && !name.contains('/')).then(|| (name.to_string(), value.clone()))
            })
            .collect();
        if let Some(roots) = &self.1 {
            for name in roots.children(prefix.trim_end_matches('/'))? {
                let path = format!("{prefix}{name}");
                match self.entry(&path) {
                    Ok(entry) => {
                        children.entry(name).or_insert(entry);
                    }
                    // Broken links and targets outside the selected roots are absent.
                    Err(Error::NotFound) => {}
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(children.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
