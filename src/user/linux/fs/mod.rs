//! Guest file-system view.
//!
//! The guest sees the host file system, optionally overlaid by a *sysroot*:
//! a directory holding the guest's own root file system (its dynamic
//! loader, libraries, and configuration files). Resolution follows QEMU's
//! `-L` semantics — a guest path that exists under the sysroot resolves
//! there, anything else resolves on the host — with one improvement:
//! symbolic links inside the sysroot are resolved component by component
//! against the sysroot, so an absolute link such as
//! `/lib/ld-musl-x86_64.so.1 -> /lib/libc.so` stays inside it. `/dev`,
//! `/proc`, and `/sys` always resolve on the host (or are synthesized by the
//! personality).

pub mod anon;
pub mod epoll;
pub mod fd;
pub mod locks;
pub mod memfd;
pub mod pidfd;
pub mod xattr;

use std::path::{Component, Path, PathBuf};

use super::abi::errno::Errno;
use super::abi::errno_table::*;
use super::abi::types::{Stat, Timespec};

/// Linux `PATH_MAX`, including the terminating NUL.
pub const PATH_MAX: usize = 4096;

/// Maximum symbolic links followed during one lookup (`MAXSYMLINKS`).
pub const MAX_SYMLINKS: usize = 40;

/// Guest path resolution state.
#[derive(Clone, Debug)]
pub struct Vfs {
    sysroot: Option<PathBuf>,
    cwd: String,
}

/// Lexically joins `path` onto the absolute guest directory `base` and
/// removes `.` components and duplicate separators. `..` is kept: its meaning
/// depends on symbolic links, which the host (or sysroot resolution) handles.
pub fn join_guest(base: &str, path: &str) -> String {
    let mut out = if path.starts_with('/') {
        String::from("/")
    } else {
        base.to_string()
    };
    for part in path.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if !out.ends_with('/') {
            out.push('/');
        }
        out.push_str(part);
    }
    if path.ends_with('/') && !out.ends_with('/') {
        out.push('/');
    }
    out
}

/// Whether a guest path is always resolved on the host.
fn host_only(guest: &str) -> bool {
    ["/dev", "/proc", "/sys"]
        .iter()
        .any(|p| guest == *p || guest.starts_with(&format!("{p}/")))
}

impl Vfs {
    /// A view with the given sysroot and absolute guest working directory.
    pub fn new(sysroot: Option<PathBuf>, cwd: String) -> Self {
        Vfs { sysroot, cwd }
    }

    /// The sysroot, if any.
    pub fn sysroot(&self) -> Option<&Path> {
        self.sysroot.as_deref()
    }

    /// The guest working directory (absolute).
    pub fn cwd(&self) -> &str {
        &self.cwd
    }

    /// Sets the guest working directory (absolute).
    pub fn set_cwd(&mut self, cwd: String) {
        self.cwd = cwd;
    }

    /// Converts a guest path argument to text. Linux paths are byte strings;
    /// a non-UTF-8 path is rejected with `EINVAL` on hosts whose `Path` is not
    /// byte-transparent, and accepted verbatim on Unix.
    pub fn path_str(bytes: &[u8]) -> Result<String, Errno> {
        if bytes.is_empty() {
            return Err(Errno(ENOENT));
        }
        if bytes.len() >= PATH_MAX {
            return Err(Errno(ENAMETOOLONG));
        }
        String::from_utf8(bytes.to_vec()).map_err(|_| Errno(EINVAL))
    }

    /// The host path for an absolute guest path. `follow_last` selects
    /// whether a final symbolic link inside the sysroot is resolved.
    pub fn host_path(&self, guest: &str, follow_last: bool) -> PathBuf {
        match &self.sysroot {
            Some(root) if !host_only(guest) => self
                .resolve_in_sysroot(root, guest, follow_last)
                .unwrap_or_else(|| PathBuf::from(guest)),
            _ => PathBuf::from(guest),
        }
    }

    /// Resolves `guest` inside `root`, returning `None` when some component
    /// does not exist there (the host path is used instead).
    fn resolve_in_sysroot(&self, root: &Path, guest: &str, follow_last: bool) -> Option<PathBuf> {
        let mut pending: Vec<String> = guest
            .split('/')
            .filter(|c| !c.is_empty())
            .rev()
            .map(str::to_string)
            .collect();
        let mut resolved = root.to_path_buf();
        let mut links = 0usize;
        while let Some(component) = pending.pop() {
            match component.as_str() {
                "." => continue,
                ".." => {
                    if resolved != root {
                        resolved.pop();
                    }
                    continue;
                }
                _ => {}
            }
            let candidate = resolved.join(&component);
            let last = pending.is_empty();
            let meta = std::fs::symlink_metadata(&candidate).ok()?;
            if meta.file_type().is_symlink() && (!last || follow_last) {
                links += 1;
                if links > MAX_SYMLINKS {
                    // Let the host report ELOOP on the original path.
                    return Some(candidate);
                }
                let target = std::fs::read_link(&candidate).ok()?;
                let target = target.to_str()?;
                if target.starts_with('/') {
                    resolved = root.to_path_buf();
                }
                for part in target.split('/').filter(|c| !c.is_empty()).rev() {
                    pending.push(part.to_string());
                }
            } else {
                resolved = candidate;
            }
        }
        Some(resolved)
    }

    /// Maps a host path back to the guest view (inverse of the sysroot
    /// prefix), for `getcwd` and `/proc/self/fd` links.
    pub fn guest_path_of(&self, host: &Path) -> String {
        if let Some(root) = &self.sysroot {
            if let Ok(rest) = host.strip_prefix(root) {
                let mut s = String::from("/");
                s.push_str(&rest.to_string_lossy());
                return s;
            }
        }
        host.to_string_lossy().into_owned()
    }
}

/// Gives the host object the guest just created at `path` exactly the
/// permission bits `bits` its umask left, which the host's umask may have
/// narrowed.
pub fn created_mode(path: &Path, bits: u32) -> Result<(), Errno> {
    use std::os::unix::fs::PermissionsExt;
    if bits & super::host::umask() != 0 {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(bits))?;
    }
    Ok(())
}

/// A host file's identity (device, inode), as the address space knows the
/// objects of shared mappings.
pub fn identity(f: &std::fs::File) -> Result<crate::user::mm::SourceIdentity, Errno> {
    use std::os::unix::fs::MetadataExt;
    let m = f.metadata()?;
    Ok(crate::user::mm::SourceIdentity {
        dev: m.dev(),
        ino: m.ino(),
    })
}

/// Splits a host `dev_t` into Linux major/minor numbers.
#[cfg(target_os = "linux")]
fn host_dev(dev: u64) -> (u32, u32) {
    // glibc gnu_dev_major/gnu_dev_minor encoding.
    let major = ((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfff);
    let minor = (dev & 0xff) | ((dev >> 12) & !0xff);
    (major as u32, minor as u32)
}

/// Splits a host `dev_t` into major/minor numbers (BSD encoding:
/// major in bits 24..31, minor in bits 0..23).
#[cfg(not(target_os = "linux"))]
fn host_dev(dev: u64) -> (u32, u32) {
    (((dev >> 24) & 0xff) as u32, (dev & 0xff_ffff) as u32)
}

/// Converts host metadata to a Linux [`Stat`]. File-type and permission
/// bits share the POSIX encoding on every supported host.
pub fn stat_from_metadata(m: &std::fs::Metadata) -> Stat {
    use std::os::unix::fs::MetadataExt;
    let (dev_major, dev_minor) = host_dev(m.dev());
    let (rdev_major, rdev_minor) = host_dev(m.rdev());
    let ts = |sec: i64, nsec: i64| Timespec { sec, nsec };
    Stat {
        dev_major,
        dev_minor,
        ino: m.ino(),
        mode: m.mode(),
        nlink: m.nlink(),
        uid: m.uid(),
        gid: m.gid(),
        rdev_major,
        rdev_minor,
        size: m.size() as i64,
        blksize: m.blksize() as i64,
        blocks: m.blocks() as i64,
        atime: ts(m.atime(), m.atime_nsec()),
        mtime: ts(m.mtime(), m.mtime_nsec()),
        ctime: ts(m.ctime(), m.ctime_nsec()),
        btime: m
            .created()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(Timespec::from_duration),
    }
}

/// The [`fd::FileType`] of host metadata.
pub fn file_type_of(m: &std::fs::Metadata) -> fd::FileType {
    use std::os::unix::fs::FileTypeExt;
    let t = m.file_type();
    if t.is_dir() {
        fd::FileType::Directory
    } else if t.is_symlink() {
        fd::FileType::Symlink
    } else if t.is_char_device() {
        fd::FileType::CharDevice
    } else if t.is_block_device() {
        fd::FileType::BlockDevice
    } else if t.is_fifo() {
        fd::FileType::Fifo
    } else if t.is_socket() {
        fd::FileType::Socket
    } else {
        fd::FileType::Regular
    }
}

/// The `DT_*` value for host metadata.
pub fn dtype_of(t: &std::fs::FileType) -> u8 {
    use std::os::unix::fs::FileTypeExt;
    if t.is_dir() {
        fd::dt::DT_DIR
    } else if t.is_symlink() {
        fd::dt::DT_LNK
    } else if t.is_file() {
        fd::dt::DT_REG
    } else if t.is_char_device() {
        fd::dt::DT_CHR
    } else if t.is_block_device() {
        fd::dt::DT_BLK
    } else if t.is_fifo() {
        fd::dt::DT_FIFO
    } else if t.is_socket() {
        fd::dt::DT_SOCK
    } else {
        fd::dt::DT_UNKNOWN
    }
}

/// Reads a host directory into `getdents64` entries, including `.` and
/// `..`, which `std::fs::read_dir` omits but Linux reports.
pub fn read_directory(host: &Path) -> Result<Vec<fd::DirEntry>, Errno> {
    use std::os::unix::fs::{DirEntryExt, MetadataExt};
    let dot = std::fs::metadata(host)?;
    let dotdot = std::fs::metadata(host.join("..")).unwrap_or_else(|_| dot.clone());
    let mut out = vec![
        fd::DirEntry {
            ino: dot.ino(),
            dtype: fd::dt::DT_DIR,
            name: b".".to_vec(),
        },
        fd::DirEntry {
            ino: dotdot.ino(),
            dtype: fd::dt::DT_DIR,
            name: b"..".to_vec(),
        },
    ];
    for entry in std::fs::read_dir(host)? {
        let entry = entry?;
        let dtype = entry
            .file_type()
            .map(|t| dtype_of(&t))
            .unwrap_or(fd::dt::DT_UNKNOWN);
        use std::os::unix::ffi::OsStrExt;
        out.push(fd::DirEntry {
            ino: entry.ino(),
            dtype,
            name: entry.file_name().as_bytes().to_vec(),
        });
    }
    Ok(out)
}

/// Normalizes a host path for display (no `..` resolution).
pub fn display_path(p: &Path) -> String {
    p.components()
        .filter(|c| !matches!(c, Component::CurDir))
        .collect::<PathBuf>()
        .to_string_lossy()
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_is_lexical() {
        assert_eq!(join_guest("/home/u", "a/./b"), "/home/u/a/b");
        assert_eq!(join_guest("/home/u", "/etc//passwd"), "/etc/passwd");
        assert_eq!(join_guest("/", "x"), "/x");
        assert_eq!(join_guest("/a", "../b"), "/a/../b");
        assert_eq!(join_guest("/a", "dir/"), "/a/dir/");
        assert_eq!(join_guest("/a", "."), "/a");
    }

    #[test]
    fn sysroot_prefers_existing_paths_and_follows_links_inside() {
        let root = std::env::temp_dir().join(format!("rax-user-vfs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("lib")).unwrap();
        std::fs::write(root.join("lib/libc.so"), b"libc").unwrap();
        std::os::unix::fs::symlink("/lib/libc.so", root.join("lib/ld.so")).unwrap();
        std::os::unix::fs::symlink("libc.so", root.join("lib/rel.so")).unwrap();
        let vfs = Vfs::new(Some(root.clone()), "/".into());
        // An absolute link inside the sysroot resolves inside it.
        assert_eq!(vfs.host_path("/lib/ld.so", true), root.join("lib/libc.so"));
        assert_eq!(vfs.host_path("/lib/rel.so", true), root.join("lib/libc.so"));
        // Without following, the link itself is returned.
        assert_eq!(vfs.host_path("/lib/ld.so", false), root.join("lib/ld.so"));
        // Missing paths fall back to the host (QEMU -L semantics).
        assert_eq!(
            vfs.host_path("/lib/missing.so", true),
            PathBuf::from("/lib/missing.so")
        );
        // /dev is always the host's.
        assert_eq!(vfs.host_path("/dev/null", true), PathBuf::from("/dev/null"));
        assert_eq!(vfs.guest_path_of(&root.join("lib/libc.so")), "/lib/libc.so");
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn directory_listing_includes_dot_entries() {
        let entries = read_directory(Path::new("/")).unwrap();
        assert_eq!(entries[0].name, b".");
        assert_eq!(entries[1].name, b"..");
        assert!(entries.len() > 2);
    }

    #[test]
    fn metadata_converts_to_linux_stat() {
        use super::super::abi::types::mode;
        let m = std::fs::metadata("/").unwrap();
        let s = stat_from_metadata(&m);
        assert_eq!(s.mode & mode::S_IFMT, mode::S_IFDIR);
        assert!(s.nlink >= 1);
        assert_eq!(file_type_of(&m), fd::FileType::Directory);
    }
}
