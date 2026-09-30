//! Guest paths and the root overlay.
//!
//! The legacy host profile sees the host's file system, optionally overlaid by a
//! guest root (`rax-user --sysroot`, QEMU's `-L`): an absolute guest path
//! that exists under the root resolves there, anything else resolves on
//! the host. Programs on a macOS host normally use no root, so `dyld` and
//! the shared cache are the host's own; on another host the root must hold
//! them. A supplied resolver instead owns an immutable guest namespace and
//! refuses all host-path resolution, including paths missing from its inputs.

use std::io;
use std::path::PathBuf;
#[cfg(unix)]
use std::{ffi::OsStr, os::unix::ffi::OsStrExt, path::Path};

use crate::user::supplied_fs::{Entry, Error, Files};

/// Path resolution for one process.
#[derive(Clone, Debug, Default)]
pub struct Vfs {
    /// The guest root overlay.
    pub root: Option<PathBuf>,
    supplied: Option<Files>,
}

impl Vfs {
    /// A resolver with an optional root overlay.
    pub fn new(root: Option<PathBuf>) -> Self {
        Vfs {
            root,
            supplied: None,
        }
    }

    /// A closed namespace, with no host path or root-overlay fallback.
    pub fn supplied(files: Files) -> Self {
        Self {
            root: None,
            supplied: Some(files),
        }
    }

    pub fn is_closed(&self) -> bool {
        self.supplied.is_some()
    }

    pub fn files(&self) -> Option<&Files> {
        self.supplied.as_ref()
    }

    /// Resolve guest path components against the immutable supplied namespace.
    /// Separators and `..` are guest POSIX syntax on every host.
    pub fn lookup(&self, path: &[u8], cwd: &[u8]) -> io::Result<(String, Entry)> {
        let files = self.supplied.as_ref().ok_or(io::ErrorKind::Unsupported)?;
        let parse = |bytes| {
            std::str::from_utf8(bytes)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, Error::InvalidPath))
        };
        let path = parse(path)?;
        if path.is_empty() {
            return Err(io::Error::new(io::ErrorKind::NotFound, Error::NotFound));
        }
        let absolute = if path.starts_with('/') {
            path.to_owned()
        } else {
            format!("{}/{path}", parse(cwd)?.trim_end_matches('/'))
        };
        files.lookup(&absolute).map_err(io::Error::other)
    }

    fn require_host(&self) -> io::Result<()> {
        if self.is_closed() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "supplied Darwin files have no host path",
            ));
        }
        if !cfg!(unix) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Darwin host filesystem services require a Unix host",
            ));
        }
        Ok(())
    }

    /// The host path of guest path `path`, relative paths taken against
    /// `cwd` (an absolute guest path).
    pub fn host_path(&self, path: &[u8], cwd: &[u8]) -> io::Result<PathBuf> {
        self.require_host()?;
        #[cfg(unix)]
        {
            let guest: Vec<u8> = if path.first() == Some(&b'/') {
                path.to_vec()
            } else {
                let mut p = cwd.to_vec();
                if p.last() != Some(&b'/') {
                    p.push(b'/');
                }
                p.extend_from_slice(path);
                p
            };
            let host = PathBuf::from(OsStr::from_bytes(&guest));
            if let Some(root) = &self.root
                && path.first() == Some(&b'/')
            {
                let under = root.join(Path::new(OsStr::from_bytes(&guest[1..])));
                if std::fs::symlink_metadata(&under).is_ok() {
                    return Ok(under);
                }
            }
            Ok(host)
        }
        #[cfg(not(unix))]
        {
            let _ = (path, cwd);
            Err(io::ErrorKind::Unsupported.into())
        }
    }

    /// The guest path of an absolute host path: below the root overlay,
    /// the part under it.
    pub fn guest_path(&self, host: &[u8]) -> Vec<u8> {
        if self.is_closed() {
            return host.to_vec();
        }
        #[cfg(unix)]
        if let Some(root) = &self.root {
            let root = std::fs::canonicalize(root).unwrap_or_else(|_| root.clone());
            if let Some(rest) = host.strip_prefix(root.as_os_str().as_bytes())
                && rest.first() == Some(&b'/')
            {
                return rest.to_vec();
            }
        }
        host.to_vec()
    }

    /// The host path of an absolute guest path that must come from the root
    /// when there is one (the dynamic linker, the shared cache).
    pub fn system_path(&self, path: &str) -> io::Result<PathBuf> {
        self.require_host()?;
        Ok(match &self.root {
            Some(root) => root.join(path.trim_start_matches('/')),
            None => PathBuf::from(path),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supplied_errors_survive_process_and_linker_boundaries() {
        use crate::user::darwin::{abi::Errno, loader::LoadError, process::SpawnError};
        for (source, expected) in [
            (Error::NotFound, Errno::ENOENT),
            (Error::NotDirectory, Errno::ENOTDIR),
            (Error::IsDirectory, Errno::EISDIR),
            (Error::InvalidPath, Errno::EINVAL),
            (Error::TooLong, Errno::ENAMETOOLONG),
        ] {
            let spawn = SpawnError::Io("/guest".into(), io::Error::other(source));
            assert_eq!(spawn.errno(), expected.0, "{source:?}");
        }
        let missing =
            LoadError::Dylinker("/usr/lib/dyld".into(), io::Error::other(Error::NotFound));
        assert_eq!(missing.errno(), Errno::ENOENT.0);
        let directory =
            LoadError::Dylinker("/usr/lib/dyld".into(), io::Error::other(Error::IsDirectory));
        assert_eq!(directory.errno(), Errno::EBADEXEC.0);
    }

    #[test]
    fn supplied_paths_preserve_directory_checks_and_never_resolve_host_paths() {
        use crate::user::darwin::{abi::Errno, loader::ImageFile};
        let files = Files::new(std::collections::BTreeMap::from([
            (
                "/dir/file".into(),
                std::sync::Arc::<[u8]>::from(&b"supplied"[..]),
            ),
            (
                "/usr/lib/dyld".into(),
                std::sync::Arc::<[u8]>::from(&b"linker"[..]),
            ),
        ]))
        .unwrap();
        let v = Vfs::supplied(files);
        let (path, entry) = v.lookup(b"../dir/./file", b"/dir").unwrap();
        assert_eq!(path, "/dir/file");
        assert_eq!(&*entry.bytes().unwrap(), b"supplied");
        for (path, expected) in [
            (&b"/dir/file/../file"[..], Errno::ENOTDIR),
            (&b"/not-supplied"[..], Errno::ENOENT),
            (&b""[..], Errno::ENOENT),
            (&b"/\xff"[..], Errno::EINVAL),
        ] {
            assert_eq!(Errno::from(v.lookup(path, b"/").unwrap_err()), expected);
        }
        assert_eq!(
            v.host_path(b"/dir/file", b"/").unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            v.system_path("/usr/lib/dyld").unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        let image = ImageFile::from_supplied("/usr/lib/dyld", &v).unwrap();
        assert_eq!(&*image.bytes, b"linker");
        assert!(image.host_path.as_os_str().is_empty());
        assert_eq!(
            &*ImageFile::read_system("/usr/lib/dyld", &v).unwrap().bytes,
            b"linker"
        );
        assert_eq!(
            Errno::from(ImageFile::read_system("/not-supplied", &v).unwrap_err()),
            Errno::ENOENT
        );
        assert_eq!(
            image.file_id,
            ImageFile::from_supplied("/usr/lib/dyld", &v)
                .unwrap()
                .file_id
        );
        assert_eq!(
            Errno::from(ImageFile::from_supplied("/dir", &v).unwrap_err()),
            Errno::EISDIR
        );
        let real = std::env::current_exe().unwrap();
        assert_eq!(
            ImageFile::read("/host-executable", &real, &v)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        #[cfg(unix)]
        assert_eq!(
            crate::user::darwin::host::path(&v, b"/dir/file").unwrap_err(),
            Errno::EPERM
        );
    }

    #[cfg(not(unix))]
    #[test]
    fn host_paths_report_unavailable() {
        let v = Vfs::default();
        assert_eq!(
            v.host_path(b"/file", b"/").unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(
            v.system_path("/file").unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[cfg(unix)]
    #[test]
    fn host_paths_under_the_root_are_guest_paths() {
        let dir = std::env::temp_dir().join(format!("rax-vfs-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("usr")).unwrap();
        let root = std::fs::canonicalize(&dir).unwrap();
        let v = Vfs::new(Some(dir.clone()));
        let under = root.join("usr/lib");
        assert_eq!(v.guest_path(under.as_os_str().as_bytes()), b"/usr/lib");
        assert_eq!(v.guest_path(b"/etc/hosts"), b"/etc/hosts");
        // A sibling sharing the root's prefix is not under it.
        let sibling = format!("{}x/a", root.display());
        assert_eq!(v.guest_path(sibling.as_bytes()), sibling.as_bytes());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn relative_paths_join_the_working_directory() {
        let v = Vfs::default();
        assert_eq!(
            v.host_path(b"a/b", b"/tmp").unwrap(),
            PathBuf::from("/tmp/a/b")
        );
        assert_eq!(v.host_path(b"a", b"/").unwrap(), PathBuf::from("/a"));
        assert_eq!(
            v.host_path(b"/etc/hosts", b"/tmp").unwrap(),
            PathBuf::from("/etc/hosts")
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_root_overlays_existing_absolute_paths() {
        let dir = std::env::temp_dir().join(format!("rax-darwin-vfs-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("usr/lib")).unwrap();
        std::fs::write(dir.join("usr/lib/dyld"), b"x").unwrap();
        let v = Vfs::new(Some(dir.clone()));
        assert_eq!(
            v.host_path(b"/usr/lib/dyld", b"/").unwrap(),
            dir.join("usr/lib/dyld")
        );
        assert_eq!(
            v.host_path(b"/nonexistent-rax", b"/").unwrap(),
            PathBuf::from("/nonexistent-rax")
        );
        assert_eq!(
            v.system_path("/usr/lib/dyld").unwrap(),
            dir.join("usr/lib/dyld")
        );
        assert_eq!(
            &*crate::user::darwin::loader::ImageFile::read_system("/usr/lib/dyld", &v)
                .unwrap()
                .bytes,
            b"x"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
