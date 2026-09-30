//! Immutable POSIX guest files supplied by an embedder, independent of host paths.
//!
//! File keys are canonical absolute UTF-8 guest paths. Directories are inferred;
//! there are no host lookups, symbolic links, or writable objects. Lookup walks
//! components before interpreting `..`, so `/file/../other` is `NotDirectory`.
use std::collections::BTreeMap;
use std::sync::Arc;

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
        })
    }
}
impl std::error::Error for Error {}

#[derive(Clone, Debug)]
pub enum Kind {
    File(Arc<[u8]>),
    Directory,
}
#[derive(Clone, Debug)]
pub struct Entry {
    /// Stable within this immutable namespace; assigned in sorted path order.
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
            Kind::Directory => Err(Error::IsDirectory),
        }
    }
}

/// A closed namespace. Clones and file reads share immutable content.
#[derive(Clone, Debug)]
pub struct Files(Arc<BTreeMap<String, Entry>>);
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
        let mut entries = BTreeMap::new();
        entries.insert(
            "/".to_string(),
            Entry {
                ino: 0,
                kind: Kind::Directory,
            },
        );
        for (path, bytes) in files {
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
            if entries
                .insert(
                    path,
                    Entry {
                        ino: 0,
                        kind: Kind::File(bytes),
                    },
                )
                .is_some()
            {
                return Err(Error::Exists);
            }
        }
        for (index, entry) in entries.values_mut().enumerate() {
            entry.ino = 0x5241_5900 + index as u64;
        }
        Ok(Self(Arc::new(entries)))
    }

    /// Produces a new namespace with an additional file. Used to include the
    /// executable itself before starting a process; existing paths are refused.
    pub fn with_file(&self, path: String, bytes: Arc<[u8]>) -> Result<Self, Error> {
        if self.0.contains_key(&path) {
            return Err(Error::Exists);
        }
        let mut files: BTreeMap<_, _> = self
            .0
            .iter()
            .filter_map(|(path, entry)| match &entry.kind {
                Kind::File(bytes) => Some((path.clone(), bytes.clone())),
                Kind::Directory => None,
            })
            .collect();
        files.insert(path, bytes);
        Self::new(files)
    }

    /// Resolves an absolute guest path, retaining directory checks before `..`.
    /// Returns its canonical guest name and a shared entry; never a host path.
    pub fn lookup(&self, path: &str) -> Result<(String, Entry), Error> {
        validate(path)?;
        let mut current = String::from("/");
        let mut entry = self.0.get("/").expect("root exists");
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
            entry = self.0.get(&current).ok_or(Error::NotFound)?;
        }
        if path.ends_with('/') && !entry.is_dir() {
            return Err(Error::NotDirectory);
        }
        Ok((current, entry.clone()))
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
        Ok(self
            .0
            .range(prefix.clone()..)
            .take_while(|(key, _)| key.starts_with(&prefix))
            .filter_map(|(key, value)| {
                let name = &key[prefix.len()..];
                (!name.is_empty() && !name.contains('/')).then(|| (name.to_string(), value.clone()))
            })
            .collect())
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
