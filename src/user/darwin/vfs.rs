//! Guest paths and the root overlay.
//!
//! A Darwin guest sees the host's file system, optionally overlaid by a
//! guest root (`rax-user --sysroot`, QEMU's `-L`): an absolute guest path
//! that exists under the root resolves there, anything else resolves on
//! the host. Programs on a macOS host normally use no root, so `dyld` and
//! the shared cache are the host's own; on another host the root must hold
//! them.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// Path resolution for one process.
#[derive(Clone, Debug, Default)]
pub struct Vfs {
    /// The guest root overlay.
    pub root: Option<PathBuf>,
}

impl Vfs {
    /// A resolver with an optional root overlay.
    pub fn new(root: Option<PathBuf>) -> Self {
        Vfs { root }
    }

    /// The host path of guest path `path`, relative paths taken against
    /// `cwd` (an absolute guest path).
    pub fn host_path(&self, path: &[u8], cwd: &[u8]) -> PathBuf {
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
                return under;
            }
        }
        host
    }

    /// The host path of an absolute guest path that must come from the root
    /// when there is one (the dynamic linker, the shared cache).
    pub fn system_path(&self, path: &str) -> PathBuf {
        match &self.root {
            Some(root) => root.join(path.trim_start_matches('/')),
            None => PathBuf::from(path),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_paths_join_the_working_directory() {
        let v = Vfs::default();
        assert_eq!(v.host_path(b"a/b", b"/tmp"), PathBuf::from("/tmp/a/b"));
        assert_eq!(v.host_path(b"a", b"/"), PathBuf::from("/a"));
        assert_eq!(
            v.host_path(b"/etc/hosts", b"/tmp"),
            PathBuf::from("/etc/hosts")
        );
    }

    #[test]
    fn the_root_overlays_existing_absolute_paths() {
        let dir = std::env::temp_dir().join(format!("rax-darwin-vfs-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("usr/lib")).unwrap();
        std::fs::write(dir.join("usr/lib/dyld"), b"x").unwrap();
        let v = Vfs::new(Some(dir.clone()));
        assert_eq!(
            v.host_path(b"/usr/lib/dyld", b"/"),
            dir.join("usr/lib/dyld")
        );
        assert_eq!(
            v.host_path(b"/nonexistent-rax", b"/"),
            PathBuf::from("/nonexistent-rax")
        );
        assert_eq!(v.system_path("/usr/lib/dyld"), dir.join("usr/lib/dyld"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
