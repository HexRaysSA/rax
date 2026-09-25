//! Extended attributes (`fs/xattr.c`): `setxattr`, `getxattr`,
//! `listxattr`, and `removexattr`, their `l` (not following a final link)
//! and `f` (descriptor) forms, and the `*xattrat` calls.
//!
//! The kernel's checks come in its order: the flags, the name
//! (`import_xattr_name`: `ERANGE` for an empty or over-long one), the value
//! (`setxattr_copy`), then the object, then `xattr_permission` and the
//! capability hooks for the name's namespace, then the file system's
//! handler for it. Host files have the handlers of a disk file system
//! mounted without POSIX ACLs: `user.*` (on regular files and directories
//! only), `trusted.*` (for the privileged: root here), `security.*` (set
//! only by the privileged, as `cap_inode_setxattr` requires), and none for
//! other names (`EOPNOTSUPP`), `system.posix_acl_*` included. The
//! attributes themselves live on the host object
//! ([`fs::xattr`](super::super::fs::xattr)); the names a macOS host keeps
//! for itself are not shown. Pipes, anonymous inodes, and synthesized
//! `/proc` files have no attributes; a socket has `sockfs`'s
//! `system.sockprotoname`, its protocol's name; a pidfd has `pidfs`'s
//! `trusted.*` handler, whose attributes are not kept.

use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::Arc;

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::abi::types::mode;
use super::super::fs::anon::Anon;
use super::super::fs::fd::{FileObject, FileType, OpenFile};
use super::super::fs::xattr::{self, Obj};
use super::super::procfs::ProcEntry;
use super::path::{AT_EMPTY_PATH, AT_FDCWD, AT_SYMLINK_NOFOLLOW, Target, resolve, resolve_str};
use super::{Ctx, SysResult};

/// `XATTR_NAME_MAX`.
const NAME_MAX: usize = 255;
/// `XATTR_SIZE_MAX`.
const SIZE_MAX: usize = 65536;
/// `XATTR_LIST_MAX`.
const LIST_MAX: usize = 65536;
/// `XATTR_ARGS_SIZE_VER0`, the size of `struct xattr_args`.
const ARGS_SIZE: u64 = 16;
/// `PAGE_SIZE`, the largest `struct xattr_args` accepted.
const ARGS_MAX: u64 = 4096;

/// A name's namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Space {
    User,
    Trusted,
    Security,
    System,
    Other,
}

const PREFIXES: [(&[u8], Space); 4] = [
    (b"user.", Space::User),
    (b"trusted.", Space::Trusted),
    (b"security.", Space::Security),
    (b"system.", Space::System),
];

/// The namespace of `name` and what follows its prefix.
fn space(name: &[u8]) -> (Space, &[u8]) {
    PREFIXES
        .iter()
        .find_map(|(p, s)| name.strip_prefix(*p).map(|rest| (*s, rest)))
        .unwrap_or((Space::Other, name))
}

/// `is_posix_acl_xattr`.
fn is_acl(name: &[u8]) -> bool {
    name == b"system.posix_acl_access" || name == b"system.posix_acl_default"
}

/// The pseudo file systems' inodes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Pseudo {
    /// `pipefs`.
    Pipe,
    /// `sockfs`, with the protocol's name.
    Socket(&'static str),
    /// `anon_inodefs`.
    Anon,
    /// `pidfs`.
    Pid,
    /// `proc`.
    Proc,
}

/// What an attribute call acts on.
enum Node {
    /// A host object, by path (following a final link or not) or by
    /// descriptor, with its type and permission bits and owner.
    Host {
        path: Option<(PathBuf, bool)>,
        file: Option<Arc<OpenFile>>,
        mode: u32,
        uid: u32,
    },
    /// An inode of a pseudo file system, with its type and permission bits.
    Pseudo(Pseudo, u32),
}

impl Node {
    fn obj(&self) -> Option<Obj<'_>> {
        match self {
            Node::Host {
                path: Some((p, f)), ..
            } => Some(Obj::Path(p, *f)),
            Node::Host { file: Some(f), .. } => match &f.object {
                FileObject::Host(h) => Some(Obj::Fd(std::os::fd::AsRawFd::as_raw_fd(h))),
                _ => None,
            },
            _ => None,
        }
    }

    fn mode(&self) -> u32 {
        match self {
            Node::Host { mode, .. } | Node::Pseudo(_, mode) => *mode,
        }
    }
}

/// `sk->sk_prot_creator->name`, the name `sockfs` gives a socket's inode.
fn proto_name(s: &super::super::net::Socket) -> &'static str {
    use super::super::net::lx::*;
    let v6 = s.domain == AF_INET6;
    match (s.domain, s.stype) {
        (AF_UNIX, SOCK_STREAM) => "UNIX-STREAM",
        (AF_UNIX, _) => "UNIX",
        (_, SOCK_STREAM) if v6 => "TCPv6",
        (_, SOCK_STREAM) => "TCP",
        (_, SOCK_DGRAM) if s.protocol == IPPROTO_ICMP || s.protocol == IPPROTO_ICMPV6 => {
            if v6 {
                "PINGv6"
            } else {
                "PING"
            }
        }
        (_, SOCK_DGRAM) if v6 => "UDPv6",
        (_, SOCK_DGRAM) => "UDP",
        _ if v6 => "RAWv6",
        _ => "RAW",
    }
}

/// The node of an open file; `by_fd` for `fdget`, which refuses `O_PATH`.
fn file_node(file: Arc<OpenFile>, by_fd: bool) -> Result<Node, Errno> {
    let pseudo = |p, m| Ok(Node::Pseudo(p, m));
    match &file.object {
        FileObject::Host(f) => {
            let m = f.metadata()?;
            Ok(Node::Host {
                path: None,
                mode: m.mode(),
                uid: m.uid(),
                file: Some(file.clone()),
            })
        }
        FileObject::PathOnly if by_fd => Err(Errno(EBADF)),
        FileObject::PathOnly => {
            let h = file.host_path.clone().ok_or(Errno(EBADF))?;
            let follow = file.ftype != FileType::Symlink;
            let m = if follow {
                std::fs::metadata(&h)?
            } else {
                std::fs::symlink_metadata(&h)?
            };
            Ok(Node::Host {
                path: Some((h, follow)),
                file: None,
                mode: m.mode(),
                uid: m.uid(),
            })
        }
        FileObject::PipeRead(_) | FileObject::PipeWrite(_) => {
            pseudo(Pseudo::Pipe, mode::S_IFIFO | 0o600)
        }
        FileObject::Socket(s) => pseudo(Pseudo::Socket(proto_name(s)), mode::S_IFSOCK | 0o777),
        FileObject::Anon(Anon::Pid(_)) => pseudo(Pseudo::Pid, mode::S_IFREG | 0o700),
        FileObject::Anon(_) => pseudo(Pseudo::Anon, 0o600),
        FileObject::Synthetic(_) if file.ftype == FileType::Directory => {
            pseudo(Pseudo::Proc, mode::S_IFDIR | 0o555)
        }
        FileObject::Synthetic(_) => pseudo(Pseudo::Proc, mode::S_IFREG | 0o444),
    }
}

/// `filename_lookup` of a path argument (known not to be empty with
/// `AT_EMPTY_PATH`, which `lookup_null` handles).
fn lookup_path(c: &Ctx<'_>, dirfd: i32, path: u64, at_flags: u32) -> Result<Node, Errno> {
    let follow = at_flags & AT_SYMLINK_NOFOLLOW == 0;
    let mut target = resolve(c, dirfd, path, at_flags, follow)?;
    while let (Target::Proc(ProcEntry::Link(link), _), true) = (&target, follow) {
        target = resolve_str(c, AT_FDCWD, link, true)?;
    }
    match target {
        Target::Host { host, .. } => {
            let m = if follow {
                std::fs::metadata(&host)?
            } else {
                std::fs::symlink_metadata(&host)?
            };
            Ok(Node::Host {
                path: Some((host, follow)),
                file: None,
                mode: m.mode(),
                uid: m.uid(),
            })
        }
        Target::Fd(file) => file_node(file, false),
        Target::Proc(ProcEntry::Dir(_), _) => Ok(Node::Pseudo(Pseudo::Proc, mode::S_IFDIR | 0o555)),
        Target::Proc(ProcEntry::Link(_), _) => {
            Ok(Node::Pseudo(Pseudo::Proc, mode::S_IFLNK | 0o777))
        }
        Target::Proc(_, _) => Ok(Node::Pseudo(Pseudo::Proc, mode::S_IFREG | 0o444)),
    }
}

/// `getname_maybe_null`: whether the path argument is absent (a null or
/// empty path with `AT_EMPTY_PATH`).
fn absent(c: &Ctx<'_>, path: u64, at_flags: u32) -> Result<bool, Errno> {
    if at_flags & AT_EMPTY_PATH == 0 {
        return Ok(false);
    }
    if path == 0 {
        return Ok(true);
    }
    Ok(c.read_mem(path, 1)?[0] == 0)
}

/// The object of a set or get: an absent path means descriptor `dirfd`
/// when it is one, else the lookup of nothing from `dirfd` (the working
/// directory for `AT_FDCWD`).
fn node_for_value(c: &Ctx<'_>, dirfd: i32, path: u64, at_flags: u32) -> Result<Node, Errno> {
    if absent(c, path, at_flags)? {
        if dirfd >= 0 {
            return file_node(c.p.fds.file(dirfd)?, true);
        }
        if dirfd != AT_FDCWD {
            return Err(Errno(EBADF));
        }
        let cwd = c.p.vfs.cwd().to_string();
        let t = resolve_str(c, AT_FDCWD, &cwd, true)?;
        return match t {
            Target::Host { host, .. } => {
                let m = std::fs::metadata(&host)?;
                Ok(Node::Host {
                    path: Some((host, true)),
                    file: None,
                    mode: m.mode(),
                    uid: m.uid(),
                })
            }
            _ => Ok(Node::Pseudo(Pseudo::Proc, mode::S_IFDIR | 0o555)),
        };
    }
    lookup_path(c, dirfd, path, at_flags)
}

/// The object of a list or remove: an absent path means descriptor
/// `dirfd`.
fn node_for_name(c: &Ctx<'_>, dirfd: i32, path: u64, at_flags: u32) -> Result<Node, Errno> {
    if absent(c, path, at_flags)? {
        return file_node(c.p.fds.file(dirfd)?, true);
    }
    lookup_path(c, dirfd, path, at_flags)
}

/// `import_xattr_name`.
fn import_name(c: &Ctx<'_>, addr: u64) -> Result<Vec<u8>, Errno> {
    match c.p.space.read_cstr(addr, NAME_MAX) {
        Ok(Some(n)) if !n.is_empty() => Ok(n),
        Ok(_) => Err(Errno(ERANGE)),
        Err(_) => Err(Errno(EFAULT)),
    }
}

/// Whether the caller has the capability checks ask for (root here).
fn privileged(c: &Ctx<'_>) -> bool {
    c.p.creds.1 == 0
}

/// `inode_permission` for reading or writing an inode the host cannot
/// check for us.
fn inode_permission(c: &Ctx<'_>, node: &Node, write: bool) -> Result<(), Errno> {
    match node {
        Node::Host { path, file, .. } => {
            let p = path
                .as_ref()
                .map(|(p, _)| p.clone())
                .or_else(|| file.as_ref().and_then(|f| f.host_path.clone()));
            if let Some(p) = p {
                let bits = if write { 2 } else { 4 };
                super::super::host::access(&p, bits, true, true)?;
            }
            Ok(())
        }
        // Read-only /proc files; a root-owned pidfs inode of mode 0700.
        Node::Pseudo(Pseudo::Proc, m) if write && m & 0o222 == 0 && !privileged(c) => {
            Err(Errno(EACCES))
        }
        Node::Pseudo(Pseudo::Pid, _) if !privileged(c) => Err(Errno(EACCES)),
        Node::Pseudo(..) => Ok(()),
    }
}

/// `xattr_permission` and, for changes, `cap_inode_setxattr`/
/// `cap_inode_removexattr`. The ordinary permission to read or write a
/// host object's `user.*` names is the host call's, which follows.
fn permission(c: &Ctx<'_>, node: &Node, name: &[u8], write: bool) -> Result<(), Errno> {
    let (sp, _) = space(name);
    let refuse = || Errno(if write { EPERM } else { ENODATA });
    match sp {
        Space::Security | Space::System => {}
        Space::Trusted => {
            if !privileged(c) {
                return Err(refuse());
            }
        }
        Space::User => {
            let t = node.mode() & mode::S_IFMT;
            if t != mode::S_IFREG && t != mode::S_IFDIR {
                return Err(refuse());
            }
            if let Node::Host { mode: m, uid, .. } = node
                && t == mode::S_IFDIR
                && m & 0o1000 != 0
                && write
                && *uid != c.p.creds.1
                && !privileged(c)
            {
                return Err(Errno(EPERM));
            }
            if !matches!(node, Node::Host { .. }) {
                inode_permission(c, node, write)?;
            }
        }
        Space::Other => inode_permission(c, node, write)?,
    }
    // cap_inode_setxattr, cap_inode_removexattr.
    if write && sp == Space::Security && !privileged(c) {
        return Err(Errno(EPERM));
    }
    Ok(())
}

/// `xattr_resolve_name` on the node's file system: `Ok` when a handler
/// takes the name and it stores values on the host.
fn resolve_name(node: &Node, name: &[u8]) -> Result<(), Errno> {
    let (sp, rest) = space(name);
    let handled = match node {
        Node::Host { .. } => matches!(sp, Space::User | Space::Trusted | Space::Security),
        Node::Pseudo(Pseudo::Socket(_), _) => {
            if name == b"system.sockprotoname" {
                return Ok(());
            }
            sp == Space::Security
        }
        Node::Pseudo(Pseudo::Pid, _) => sp == Space::Trusted,
        Node::Pseudo(..) => return Err(Errno(EOPNOTSUPP)),
    };
    if !handled {
        return Err(Errno(EOPNOTSUPP));
    }
    // A prefix handler needs a suffix.
    if rest.is_empty() {
        return Err(Errno(EINVAL));
    }
    Ok(())
}

/// Checks `at_flags` (`AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH` only).
fn check_at_flags(at_flags: u32) -> Result<(), Errno> {
    if at_flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return Err(Errno(EINVAL));
    }
    Ok(())
}

/// `path_setxattrat`.
#[allow(clippy::too_many_arguments)]
fn setxattr_at(
    c: &mut Ctx<'_>,
    dirfd: i32,
    path: u64,
    at_flags: u32,
    uname: u64,
    value: u64,
    size: u64,
    flags: u32,
) -> SysResult {
    check_at_flags(at_flags)?;
    // setxattr_copy.
    if flags & !(xattr::CREATE | xattr::REPLACE) != 0 {
        return Err(Errno(EINVAL));
    }
    let name = import_name(c, uname)?;
    if size > SIZE_MAX as u64 {
        return Err(Errno(E2BIG));
    }
    let data = if size > 0 {
        c.read_mem(value, size as usize)?
    } else {
        Vec::new()
    };
    let node = node_for_value(c, dirfd, path, at_flags)?;
    if is_acl(&name) {
        return Err(Errno(EOPNOTSUPP));
    }
    permission(c, &node, &name, true)?;
    resolve_name(&node, &name)?;
    match node.obj() {
        Some(o) => xattr::set(o, &name, &data, flags)?,
        // sockfs's security handler defers to a security module, of which
        // there is none; the others keep nothing.
        None => return Err(Errno(EOPNOTSUPP)),
    }
    Ok(0)
}

/// `path_getxattrat`: the value's length, the value copied to `value`
/// when `size` is not 0.
fn getxattr_at(
    c: &mut Ctx<'_>,
    dirfd: i32,
    path: u64,
    at_flags: u32,
    uname: u64,
    value: u64,
    size: u64,
) -> SysResult {
    check_at_flags(at_flags)?;
    let name = import_name(c, uname)?;
    let node = node_for_value(c, dirfd, path, at_flags)?;
    let size = (size as usize).min(SIZE_MAX);
    if is_acl(&name) {
        return Err(Errno(EOPNOTSUPP));
    }
    permission(c, &node, &name, false)?;
    // Without a security module, security.* is the file system's.
    resolve_name(&node, &name)?;
    let data = match (&node, node.obj()) {
        (Node::Pseudo(Pseudo::Socket(proto), _), _) if name == b"system.sockprotoname" => {
            let mut v = proto.as_bytes().to_vec();
            v.push(0);
            v
        }
        (_, Some(o)) => {
            let mut buf = vec![0u8; size];
            let n = match xattr::get(o, &name, (size > 0).then_some(&mut buf[..])) {
                Err(Errno(ERANGE)) if size >= SIZE_MAX => return Err(Errno(E2BIG)),
                r => r?,
            };
            if size == 0 {
                return Ok(n as u64);
            }
            buf.truncate(n);
            buf
        }
        (_, None) => return Err(Errno(EOPNOTSUPP)),
    };
    if size > 0 {
        if data.len() > size {
            return Err(Errno(ERANGE));
        }
        if !data.is_empty() {
            c.write_mem(value, &data)?;
        }
    }
    Ok(data.len() as u64)
}

/// The names `vfs_listxattr` shows for the node, each with its NUL.
fn names(c: &Ctx<'_>, node: &Node) -> Result<Vec<u8>, Errno> {
    let mut out = Vec::new();
    match (node, node.obj()) {
        (Node::Pseudo(Pseudo::Socket(_), _), _) => out.extend_from_slice(b"system.sockprotoname\0"),
        (_, Some(o)) => {
            for n in xattr::list(o)? {
                let (sp, rest) = space(&n);
                // The host's own names, and trusted.* for the unprivileged
                // (ext4_xattr_trusted_list), are not shown.
                let shown = match sp {
                    Space::User | Space::Security => true,
                    Space::Trusted => privileged(c),
                    Space::System => is_acl(&n),
                    Space::Other => false,
                };
                if shown && !rest.is_empty() {
                    out.extend_from_slice(&n);
                    out.push(0);
                }
            }
        }
        (_, None) => {}
    }
    Ok(out)
}

/// `path_listxattrat`: the length of the name list, the list copied to
/// `list` when `size` is not 0.
fn listxattr_at(
    c: &mut Ctx<'_>,
    dirfd: i32,
    path: u64,
    at_flags: u32,
    list: u64,
    size: u64,
) -> SysResult {
    check_at_flags(at_flags)?;
    let node = node_for_name(c, dirfd, path, at_flags)?;
    let size = (size as usize).min(LIST_MAX);
    let all = names(c, &node)?;
    if size == 0 {
        return Ok(all.len() as u64);
    }
    if all.len() > size {
        return Err(Errno(if size >= LIST_MAX { E2BIG } else { ERANGE }));
    }
    if !all.is_empty() {
        c.write_mem(list, &all)?;
    }
    Ok(all.len() as u64)
}

/// `path_removexattrat`.
fn removexattr_at(c: &mut Ctx<'_>, dirfd: i32, path: u64, at_flags: u32, uname: u64) -> SysResult {
    check_at_flags(at_flags)?;
    let name = import_name(c, uname)?;
    let node = node_for_name(c, dirfd, path, at_flags)?;
    if is_acl(&name) {
        return Err(Errno(EOPNOTSUPP));
    }
    permission(c, &node, &name, true)?;
    resolve_name(&node, &name)?;
    match node.obj() {
        Some(o) => xattr::remove(o, &name)?,
        None => return Err(Errno(EOPNOTSUPP)),
    }
    Ok(0)
}

/// `setxattr`, `lsetxattr`: `at_flags` 0 or `AT_SYMLINK_NOFOLLOW`.
pub fn setxattr(c: &mut Ctx<'_>, path: u64, at_flags: u32, a: [u64; 6]) -> SysResult {
    setxattr_at(c, AT_FDCWD, path, at_flags, a[1], a[2], a[3], a[4] as u32)
}

/// `fsetxattr`.
pub fn fsetxattr(c: &mut Ctx<'_>, a: [u64; 6]) -> SysResult {
    setxattr_at(
        c,
        a[0] as i32,
        0,
        AT_EMPTY_PATH,
        a[1],
        a[2],
        a[3],
        a[4] as u32,
    )
}

/// `getxattr`, `lgetxattr`.
pub fn getxattr(c: &mut Ctx<'_>, path: u64, at_flags: u32, a: [u64; 6]) -> SysResult {
    getxattr_at(c, AT_FDCWD, path, at_flags, a[1], a[2], a[3])
}

/// `fgetxattr`.
pub fn fgetxattr(c: &mut Ctx<'_>, a: [u64; 6]) -> SysResult {
    getxattr_at(c, a[0] as i32, 0, AT_EMPTY_PATH, a[1], a[2], a[3])
}

/// `listxattr`, `llistxattr`.
pub fn listxattr(c: &mut Ctx<'_>, path: u64, at_flags: u32, list: u64, size: u64) -> SysResult {
    listxattr_at(c, AT_FDCWD, path, at_flags, list, size)
}

/// `flistxattr`.
pub fn flistxattr(c: &mut Ctx<'_>, fd: i32, list: u64, size: u64) -> SysResult {
    listxattr_at(c, fd, 0, AT_EMPTY_PATH, list, size)
}

/// `removexattr`, `lremovexattr`.
pub fn removexattr(c: &mut Ctx<'_>, path: u64, at_flags: u32, name: u64) -> SysResult {
    removexattr_at(c, AT_FDCWD, path, at_flags, name)
}

/// `fremovexattr`.
pub fn fremovexattr(c: &mut Ctx<'_>, fd: i32, name: u64) -> SysResult {
    removexattr_at(c, fd, 0, AT_EMPTY_PATH, name)
}

/// `struct xattr_args` (`copy_struct_from_user`): its value pointer,
/// size, and flags.
fn read_args(c: &Ctx<'_>, uargs: u64, usize: u64) -> Result<(u64, u64, u32), Errno> {
    if usize < ARGS_SIZE {
        return Err(Errno(EINVAL));
    }
    if usize > ARGS_MAX {
        return Err(Errno(E2BIG));
    }
    if usize > ARGS_SIZE {
        let rest = c.read_mem(uargs + ARGS_SIZE, (usize - ARGS_SIZE) as usize)?;
        if rest.iter().any(|&b| b != 0) {
            return Err(Errno(E2BIG));
        }
    }
    let b = c.read_mem(uargs, ARGS_SIZE as usize)?;
    Ok((
        u64::from_le_bytes(b[..8].try_into().unwrap()),
        u64::from(u32::from_le_bytes(b[8..12].try_into().unwrap())),
        u32::from_le_bytes(b[12..16].try_into().unwrap()),
    ))
}

/// `setxattrat(dirfd, path, at_flags, name, args, usize)`.
pub fn setxattrat(c: &mut Ctx<'_>, a: [u64; 6]) -> SysResult {
    let (value, size, flags) = read_args(c, a[4], a[5])?;
    setxattr_at(c, a[0] as i32, a[1], a[2] as u32, a[3], value, size, flags)
}

/// `getxattrat(dirfd, path, at_flags, name, args, usize)`: the flags of
/// `struct xattr_args` must be 0.
pub fn getxattrat(c: &mut Ctx<'_>, a: [u64; 6]) -> SysResult {
    let (value, size, flags) = read_args(c, a[4], a[5])?;
    if flags != 0 {
        return Err(Errno(EINVAL));
    }
    getxattr_at(c, a[0] as i32, a[1], a[2] as u32, a[3], value, size)
}

/// `listxattrat(dirfd, path, at_flags, list, size)`.
pub fn listxattrat(c: &mut Ctx<'_>, a: [u64; 6]) -> SysResult {
    listxattr_at(c, a[0] as i32, a[1], a[2] as u32, a[3], a[4])
}

/// `removexattrat(dirfd, path, at_flags, name)`.
pub fn removexattrat(c: &mut Ctx<'_>, a: [u64; 6]) -> SysResult {
    removexattr_at(c, a[0] as i32, a[1], a[2] as u32, a[3])
}
