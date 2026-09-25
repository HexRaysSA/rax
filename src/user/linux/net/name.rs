//! Socket names between the guest and the host.
//!
//! IP addresses carry over unchanged. A Unix path is a guest path: it is
//! resolved through the VFS (the guest working directory, the sysroot) to
//! an absolute host path, and one longer than the host's `sun_path` (104
//! bytes on Darwin, 108 on Linux) is bound or connected through its
//! directory ([`sys::unix_at`]). Names the host reports are mapped back
//! (the sysroot prefix removed); a socket's own name is the one the guest
//! bound, but its peers see the absolute path (and a long path as the
//! directory link it was reached by).
//!
//! Linux's abstract namespace (a name whose first byte is NUL) is the
//! host's own on Linux hosts. Darwin has none: there an abstract name is a
//! socket file in a per-user directory, named by a hash of the name, with
//! the name beside it (for the addresses reported back) and a lock file the
//! binding socket holds (`flock`) while it is open anywhere, so a name is in
//! use exactly while its socket lives, as in `unix_bind_abstract`.

use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::fs::{Vfs, join_guest};
use super::Socket;
use super::addr::{Addr, UnixName};
use super::sys::{self, HostAddr};

/// Where a bind or connect goes on the host.
#[derive(Debug)]
pub enum Place {
    /// A host address.
    Addr(HostAddr),
    /// A Unix path too long for the host's `sun_path`: its directory and
    /// last component.
    At(PathBuf, Vec<u8>),
}

/// The host path of the guest Unix path `path`; `create` for a bind, which
/// makes the last component (`mknod` does not follow it).
pub fn unix_path(vfs: &Vfs, path: &[u8], create: bool) -> Result<PathBuf, Errno> {
    let s = Vfs::path_str(path)?;
    let guest = join_guest(vfs.cwd(), &s);
    Ok(vfs.host_path(&guest, !create))
}

/// The place of host path `host`: itself when it fits in `sun_path`, else
/// its directory and name.
fn fit(host: &Path) -> Result<Place, Errno> {
    let bytes = host.as_os_str().as_bytes();
    let max = sys::sun_path_max();
    if bytes.len() < max {
        return Ok(Place::Addr(HostAddr::Unix {
            name: bytes.to_vec(),
            abstract_: false,
        }));
    }
    let name = host.file_name().ok_or(Errno(ENAMETOOLONG))?.as_bytes();
    if name.len() >= max {
        return Err(Errno(ENAMETOOLONG));
    }
    let dir = host.parent().ok_or(Errno(ENOENT))?;
    Ok(Place::At(dir.to_path_buf(), name.to_vec()))
}

/// The host place of guest address `a`; `create` for a bind.
pub fn place(vfs: &Vfs, a: &Addr, create: bool) -> Result<Place, Errno> {
    Ok(match a {
        Addr::Unspec => Place::Addr(HostAddr::Unspec),
        Addr::V4 { ip, port } => Place::Addr(HostAddr::V4(*ip, *port)),
        Addr::V6 {
            ip,
            port,
            flow,
            scope,
        } => Place::Addr(HostAddr::V6(*ip, *port, *flow, *scope)),
        Addr::Netlink { pid, groups } => Place::Addr(HostAddr::Netlink(*pid, *groups)),
        Addr::Unix(UnixName::Path(p)) => fit(&unix_path(vfs, p, create)?)?,
        Addr::Unix(UnixName::Abstract(n)) if cfg!(target_os = "linux") => {
            Place::Addr(HostAddr::Unix {
                name: n.clone(),
                abstract_: true,
            })
        }
        Addr::Unix(UnixName::Abstract(n)) => fit(&abstract_path(n)?)?,
        Addr::Unix(UnixName::Unnamed) => return Err(Errno(EINVAL)),
    })
}

/// Makes a socket node at host path `host`, as `mknod` with `S_IFSOCK`
/// does, by binding a socket there and closing it.
pub fn socket_node(host: &Path) -> Result<(), Errno> {
    let s = sys::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0)?;
    match fit(host)? {
        Place::Addr(a) => sys::bind(&s, &a),
        Place::At(dir, name) => sys::unix_at(&s, &dir, &name, false),
    }
}

/// Binds `s` at `p`.
pub fn bind(s: &Socket, p: &Place) -> Result<(), Errno> {
    match p {
        Place::Addr(a) => sys::bind(&s.file, a),
        Place::At(dir, name) => sys::unix_at(&s.file, dir, name, false),
    }
}

/// Connects `s` to `p`.
pub fn connect(s: &Socket, p: &Place) -> Result<(), Errno> {
    match p {
        Place::Addr(a) => sys::connect(&s.file, a),
        Place::At(dir, name) => sys::unix_at(&s.file, dir, name, true),
    }
}

/// The guest address of host address `h`.
pub fn guest_addr(vfs: &Vfs, h: HostAddr) -> Addr {
    match h {
        HostAddr::Unspec => Addr::Unspec,
        HostAddr::V4(ip, port) => Addr::V4 { ip, port },
        HostAddr::V6(ip, port, flow, scope) => Addr::V6 {
            ip,
            port,
            flow,
            scope,
        },
        HostAddr::Netlink(pid, groups) => Addr::Netlink { pid, groups },
        HostAddr::Unix {
            name,
            abstract_: true,
        } => Addr::Unix(UnixName::Abstract(name)),
        HostAddr::Unix { name, .. } if name.is_empty() => Addr::Unix(UnixName::Unnamed),
        HostAddr::Unix { name, .. } => match abstract_name_of(&name) {
            Some(n) => Addr::Unix(UnixName::Abstract(n)),
            None => {
                let p = Path::new(std::ffi::OsStr::from_bytes(&name));
                Addr::Unix(UnixName::Path(vfs.guest_path_of(p).into_bytes()))
            }
        },
    }
}

/// Where emulated abstract names live (Darwin hosts).
fn abstract_dir() -> PathBuf {
    // SAFETY: getuid has no failure mode.
    let uid = unsafe { libc::getuid() };
    std::env::temp_dir().join(format!("rax-abstract-{uid}"))
}

/// FNV-1a, 64-bit: an abstract name's file name.
fn fnv(name: &[u8]) -> u64 {
    name.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, &b| {
        (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
    })
}

/// The host path standing for abstract name `name` (Darwin), creating its
/// directory.
pub fn abstract_path(name: &[u8]) -> Result<PathBuf, Errno> {
    use std::os::unix::fs::DirBuilderExt;
    let dir = abstract_dir();
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)?;
    Ok(dir.join(format!("{:016x}", fnv(name))))
}

/// Claims abstract name `name` for a binding socket (Darwin): the lock
/// file's lock, held while the returned descriptor is open, or `None` when
/// a live socket holds the name. A stale socket file is removed, and the
/// name is recorded for the addresses reported back.
fn claim_abstract(name: &[u8]) -> Result<Option<OwnedFd>, Errno> {
    use std::os::unix::fs::OpenOptionsExt;
    let path = abstract_path(name)?;
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC)
        .open(path.with_extension("lock"))?;
    // SAFETY: flock on a descriptor this function owns.
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Ok(None);
    }
    let _ = std::fs::remove_file(&path);
    std::fs::write(path.with_extension("name"), name)?;
    Ok(Some(OwnedFd::from(lock)))
}

/// Releases emulated abstract name `name` as its binding socket closes
/// (Darwin): the socket's lock is dropped, and when no other process still
/// holds the name (the lock can be taken again) its files are removed,
/// under the lock, so a later bind starts afresh.
pub fn release_abstract(name: &[u8], lock: OwnedFd) {
    use std::os::unix::fs::OpenOptionsExt;
    drop(lock);
    let Ok(path) = abstract_path(name) else {
        return;
    };
    let lock_path = path.with_extension("lock");
    let Ok(again) = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC)
        .open(&lock_path)
    else {
        return;
    };
    // SAFETY: flock on a descriptor this function owns.
    if unsafe { libc::flock(again.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return;
    }
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(path.with_extension("name"));
    let _ = std::fs::remove_file(&lock_path);
}

/// The abstract name a host name in the emulated namespace stands for: a
/// socket file of its directory (reached directly or through a directory
/// link), with its recorded name beside it.
fn abstract_name_of(host: &[u8]) -> Option<Vec<u8>> {
    if cfg!(target_os = "linux") {
        return None;
    }
    let file = Path::new(std::ffi::OsStr::from_bytes(host)).file_name()?;
    let hex = file.as_bytes();
    if hex.len() != 16 || !hex.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    std::fs::read(abstract_dir().join(file).with_extension("name")).ok()
}

/// Binds `s` to abstract name `name` (`unix_bind_abstract`): `EADDRINUSE`
/// while another socket holds it. On Darwin the returned lock keeps the
/// name.
pub fn bind_abstract(vfs: &Vfs, s: &Socket, name: &[u8]) -> Result<Option<OwnedFd>, Errno> {
    let addr = Addr::Unix(UnixName::Abstract(name.to_vec()));
    if cfg!(target_os = "linux") {
        bind(s, &place(vfs, &addr, true)?)?;
        return Ok(None);
    }
    let lock = claim_abstract(name)?.ok_or(Errno(EADDRINUSE))?;
    bind(s, &place(vfs, &addr, true)?)?;
    Ok(Some(lock))
}

/// `unix_autobind`: binds `s` to a free abstract name of five hex digits,
/// trying them in order from a random one; `ENOSPC` when all are taken.
pub fn autobind(vfs: &Vfs, s: &Socket) -> Result<(UnixName, Option<OwnedFd>), Errno> {
    if cfg!(target_os = "linux") {
        // A bare family: the host kernel autobinds.
        sys::bind(
            &s.file,
            &HostAddr::Unix {
                name: Vec::new(),
                abstract_: false,
            },
        )?;
        let name = match sys::sockname(&s.file)? {
            HostAddr::Unix { name, .. } => name,
            _ => return Err(Errno(EINVAL)),
        };
        return Ok((UnixName::Abstract(name), None));
    }
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos())
        ^ std::process::id().rotate_left(12);
    let last = seed & 0xF_FFFF;
    let mut n = last;
    loop {
        n = (n + 1) & 0xF_FFFF;
        let name = format!("{n:05x}").into_bytes();
        match bind_abstract(vfs, s, &name) {
            Ok(lock) => return Ok((UnixName::Abstract(name), lock)),
            Err(Errno(EADDRINUSE)) if n != last => {}
            Err(Errno(EADDRINUSE)) => return Err(Errno(ENOSPC)),
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_names_map_back_through_the_sysroot() {
        let vfs = Vfs::new(Some(PathBuf::from("/sysroot")), "/".into());
        let h = HostAddr::Unix {
            name: b"/sysroot/run/x.sock".to_vec(),
            abstract_: false,
        };
        assert_eq!(
            guest_addr(&vfs, h),
            Addr::Unix(UnixName::Path(b"/run/x.sock".to_vec()))
        );
        let unnamed = HostAddr::Unix {
            name: Vec::new(),
            abstract_: false,
        };
        assert_eq!(guest_addr(&vfs, unnamed), Addr::Unix(UnixName::Unnamed));
        assert_eq!(
            guest_addr(&vfs, HostAddr::V4([127, 0, 0, 1], 80)),
            Addr::V4 {
                ip: [127, 0, 0, 1],
                port: 80
            }
        );
    }

    #[test]
    fn relative_paths_resolve_against_the_guest_directory() {
        let vfs = Vfs::new(None, "/tmp/d".into());
        assert_eq!(
            unix_path(&vfs, b"s.sock", true).unwrap(),
            PathBuf::from("/tmp/d/s.sock")
        );
        assert_eq!(unix_path(&vfs, b"", true), Err(Errno(ENOENT)));
    }

    #[test]
    fn long_paths_go_through_their_directory() {
        let dir = std::env::temp_dir();
        let long = dir.join("x".repeat(sys::sun_path_max()));
        match fit(&long) {
            Err(Errno(ENAMETOOLONG)) => {}
            other => panic!("{other:?}"),
        }
        let name = "y".repeat(40);
        let mut deep = dir.clone();
        while deep.as_os_str().len() < sys::sun_path_max() {
            deep = deep.join("..").join(dir.file_name().unwrap_or_default());
        }
        match fit(&deep.join(&name)) {
            Ok(Place::At(_, n)) => assert_eq!(n, name.as_bytes()),
            other => panic!("{other:?}"),
        }
        match fit(Path::new("/tmp/short")) {
            Ok(Place::Addr(HostAddr::Unix { name, .. })) => assert_eq!(name, b"/tmp/short"),
            other => panic!("{other:?}"),
        }
    }
}
