//! Path-based system calls: opening, metadata, names, and directories.

use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::Arc;

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::abi::open::*;
use super::super::abi::types::{Stat, Timespec, mode};
use super::super::fs::fd::{FileObject, FileType, OpenFile};
use super::super::fs::{self, join_guest};
use super::super::procfs::{self, ProcEntry};
use super::{Ctx, SysResult};

/// `AT_FDCWD`.
pub const AT_FDCWD: i32 = -100;
/// `AT_SYMLINK_NOFOLLOW`.
pub const AT_SYMLINK_NOFOLLOW: u32 = 0x100;
/// `AT_EACCESS`.
pub const AT_EACCESS: u32 = 0x200;
/// `AT_REMOVEDIR`.
pub const AT_REMOVEDIR: u32 = 0x200;
/// `AT_SYMLINK_FOLLOW`.
pub const AT_SYMLINK_FOLLOW: u32 = 0x400;
/// `AT_NO_AUTOMOUNT`.
pub const AT_NO_AUTOMOUNT: u32 = 0x800;
/// `AT_EMPTY_PATH`.
pub const AT_EMPTY_PATH: u32 = 0x1000;
/// `AT_STATX_SYNC_TYPE`.
pub const AT_STATX_SYNC_TYPE: u32 = 0x6000;

/// What a path argument names.
pub enum Target {
    /// A synthesized `/proc` or `/sys` entry.
    Proc(ProcEntry, String),
    /// A host file-system object.
    Host {
        /// Guest path (absolute, lexically joined).
        guest: String,
        /// Host path.
        host: PathBuf,
    },
    /// The descriptor itself (`AT_EMPTY_PATH` with an empty path).
    Fd(Arc<OpenFile>),
}

/// The guest directory a relative path is resolved against.
fn base_dir(c: &Ctx<'_>, dirfd: i32) -> Result<String, Errno> {
    if dirfd == AT_FDCWD {
        return Ok(c.p.vfs.cwd().to_string());
    }
    let file = c.p.fds.file(dirfd)?;
    if file.ftype != FileType::Directory {
        return Err(Errno(ENOTDIR));
    }
    Ok(match &file.host_path {
        Some(h) => c.p.vfs.guest_path_of(h),
        None => file.path.clone(),
    })
}

/// Resolves a guest path string relative to `dirfd`.
pub fn resolve_str(c: &Ctx<'_>, dirfd: i32, path: &str, follow: bool) -> Result<Target, Errno> {
    let guest = if path.starts_with('/') {
        join_guest("/", path)
    } else {
        join_guest(&base_dir(c, dirfd)?, path)
    };
    if let Some(entry) = procfs::lookup(c.p, c.t, &c.thread_refs(), &guest) {
        return Ok(Target::Proc(entry, guest));
    }
    let host = c.p.vfs.host_path(&guest, follow);
    Ok(Target::Host { guest, host })
}

/// Resolves a path argument, honoring `AT_EMPTY_PATH`.
pub fn resolve(
    c: &Ctx<'_>,
    dirfd: i32,
    path_addr: u64,
    flags: u32,
    follow: bool,
) -> Result<Target, Errno> {
    let raw = c.read_cstr_raw(path_addr, fs::PATH_MAX - 1)?;
    if raw.is_empty() {
        if flags & AT_EMPTY_PATH != 0 {
            if dirfd == AT_FDCWD {
                let cwd = c.p.vfs.cwd().to_string();
                return resolve_str(c, AT_FDCWD, &cwd, true);
            }
            return Ok(Target::Fd(c.p.fds.file(dirfd)?));
        }
        return Err(Errno(ENOENT));
    }
    let path = fs::Vfs::path_str(&raw)?;
    resolve_str(c, dirfd, &path, follow)
}

/// Metadata of a synthesized entry.
fn proc_stat(c: &Ctx<'_>, e: &ProcEntry) -> Stat {
    let (m, size) = match e {
        ProcEntry::File(d) => (mode::S_IFREG | 0o444, d.len() as i64),
        ProcEntry::Comm { .. } => (mode::S_IFREG | 0o644, 0),
        ProcEntry::Link(t) => (mode::S_IFLNK | 0o777, t.len() as i64),
        ProcEntry::Dir(_) => (mode::S_IFDIR | 0o555, 0),
    };
    let (sec, nsec) = super::super::host::clock_gettime(super::super::host::HostClock::Realtime);
    let now = Timespec { sec, nsec };
    Stat {
        dev_major: 0,
        dev_minor: 0x16,
        ino: 0x5241_5800,
        mode: m,
        nlink: 1,
        uid: c.p.creds.1,
        gid: c.p.creds.3,
        size,
        blksize: 1024,
        blocks: 0,
        atime: now,
        mtime: now,
        ctime: now,
        ..Default::default()
    }
}

/// Metadata of an open file.
pub fn stat_file(c: &Ctx<'_>, file: &OpenFile) -> Result<Stat, Errno> {
    match &file.object {
        FileObject::Host(f) => Ok(fs::stat_from_metadata(&f.metadata()?)),
        FileObject::PathOnly => {
            let h = file.host_path.as_ref().ok_or(Errno(EBADF))?;
            Ok(fs::stat_from_metadata(&std::fs::symlink_metadata(h)?))
        }
        FileObject::PipeRead(_) | FileObject::PipeWrite(_) => Ok(Stat {
            dev_minor: 0xe,
            mode: mode::S_IFIFO | 0o600,
            nlink: 1,
            uid: c.p.creds.1,
            gid: c.p.creds.3,
            blksize: 4096,
            ..Default::default()
        }),
        // alloc_anon_inode: mode 0600 without a file type, one link, the
        // caller's IDs; the one anon_inode_fs inode all of them share (its
        // device and inode numbers are fixed at boot).
        FileObject::Anon(_) => Ok(Stat {
            dev_minor: 0x10,
            ino: 0x5241_5801,
            mode: 0o600,
            nlink: 1,
            uid: c.p.creds.1,
            gid: c.p.creds.3,
            blksize: 4096,
            ..Default::default()
        }),
        // sock_alloc: S_IFSOCK with every permission, the caller's IDs,
        // on sockfs.
        FileObject::Socket(s) => Ok(Stat {
            dev_minor: 0x8,
            ino: s.ino,
            mode: mode::S_IFSOCK | 0o777,
            nlink: 1,
            uid: c.p.creds.1,
            gid: c.p.creds.3,
            blksize: 4096,
            ..Default::default()
        }),
        FileObject::Synthetic(d) => Ok(proc_stat(
            c,
            &if file.ftype == FileType::Directory {
                ProcEntry::Dir(Vec::new())
            } else {
                ProcEntry::File(d.to_vec())
            },
        )),
    }
}

/// Metadata of a resolved target.
fn stat_target(c: &Ctx<'_>, t: &Target, follow: bool) -> Result<Stat, Errno> {
    match t {
        Target::Fd(f) => stat_file(c, f),
        Target::Proc(ProcEntry::Link(link), _) if follow => {
            let target = resolve_str(c, AT_FDCWD, link, true)?;
            stat_target(c, &target, true)
        }
        Target::Proc(e, _) => Ok(proc_stat(c, e)),
        Target::Host { host, .. } => {
            let m = if follow {
                std::fs::metadata(host)?
            } else {
                std::fs::symlink_metadata(host)?
            };
            Ok(fs::stat_from_metadata(&m))
        }
    }
}

/// Opens a resolved target.
fn open_target(
    c: &mut Ctx<'_>,
    target: Target,
    flags: u32,
    create_mode: u32,
) -> Result<Arc<OpenFile>, Errno> {
    let layout = c.p.abi.open_flags();
    let accmode = flags & O_ACCMODE;
    // f_flags (build_open_how, build_open_flags, do_dentry_open): the
    // valid open flags with O_LARGEFILE forced, as on every 64-bit kernel,
    // less the creation-time flags and O_CLOEXEC; an O_PATH open keeps
    // only O_PATH, O_DIRECTORY, and O_NOFOLLOW.
    let valid = O_ACCMODE
        | O_CREAT
        | O_EXCL
        | O_NOCTTY
        | O_TRUNC
        | O_APPEND
        | O_NONBLOCK
        | O_DSYNC
        | O_SYNC_BIT
        | FASYNC
        | O_NOATIME
        | O_CLOEXEC
        | O_PATH
        | O_TMPFILE_BIT
        | layout.direct
        | layout.largefile
        | layout.directory
        | layout.nofollow;
    let status = if flags & O_PATH != 0 {
        flags & (O_PATH | layout.directory | layout.nofollow)
    } else {
        (flags & valid | layout.largefile) & !(O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC | O_CLOEXEC)
    };
    match target {
        Target::Fd(file) => Ok(file),
        Target::Proc(ProcEntry::File(data), guest) => {
            if accmode != O_RDONLY {
                return Err(Errno(EACCES));
            }
            if flags & layout.directory != 0 {
                return Err(Errno(ENOTDIR));
            }
            Ok(OpenFile::new(
                FileObject::Synthetic(data.into()),
                FileType::Regular,
                guest,
                None,
                status,
            ))
        }
        Target::Proc(ProcEntry::Comm { tid, text }, guest) => {
            if flags & layout.directory != 0 {
                return Err(Errno(ENOTDIR));
            }
            let f = OpenFile::new(
                FileObject::Synthetic(text.into()),
                FileType::Regular,
                guest,
                None,
                status,
            );
            if accmode != O_RDONLY {
                f.state.lock().unwrap().comm_of = Some(tid);
            }
            Ok(f)
        }
        Target::Proc(ProcEntry::Dir(entries), guest) => {
            if accmode != O_RDONLY {
                return Err(Errno(EISDIR));
            }
            let f = OpenFile::new(
                FileObject::Synthetic(Arc::from(Vec::new())),
                FileType::Directory,
                guest,
                None,
                status,
            );
            f.state.lock().unwrap().dir = Some((entries, 0));
            Ok(f)
        }
        Target::Proc(ProcEntry::Link(link), _) => {
            if flags & layout.nofollow != 0 {
                return Err(Errno(ELOOP));
            }
            // /proc/self/fd/N reopens the same object.
            let target = resolve_str(c, AT_FDCWD, &link, true)?;
            open_target(c, target, flags, create_mode)
        }
        Target::Host { guest, host } => {
            if flags & O_TMPFILE_BIT != 0 {
                return Err(Errno(EOPNOTSUPP));
            }
            if flags & O_PATH != 0 {
                let m = if flags & layout.nofollow != 0 {
                    std::fs::symlink_metadata(&host)?
                } else {
                    std::fs::metadata(&host)?
                };
                let ftype = fs::file_type_of(&m);
                if flags & layout.directory != 0 && ftype != FileType::Directory {
                    return Err(Errno(ENOTDIR));
                }
                return Ok(OpenFile::new(
                    FileObject::PathOnly,
                    ftype,
                    guest,
                    Some(host),
                    status,
                ));
            }
            let mut opts = std::fs::OpenOptions::new();
            match accmode {
                O_WRONLY => opts.write(true),
                O_RDWR => opts.read(true).write(true),
                _ => opts.read(true),
            };
            let mut custom = 0;
            if flags & O_CREAT != 0 {
                if flags & O_EXCL != 0 {
                    opts.create_new(true);
                } else {
                    custom |= libc::O_CREAT;
                }
                opts.mode(create_mode & 0o7777 & !c.p.umask);
            }
            if flags & O_TRUNC != 0 {
                custom |= libc::O_TRUNC;
            }
            if flags & O_NONBLOCK != 0 {
                custom |= libc::O_NONBLOCK;
            }
            if flags & layout.nofollow != 0 {
                custom |= libc::O_NOFOLLOW;
            }
            if flags & layout.directory != 0 {
                custom |= libc::O_DIRECTORY;
            }
            if flags & O_NOCTTY != 0 {
                custom |= libc::O_NOCTTY;
            }
            opts.custom_flags(custom);
            let file = opts.open(&host)?;
            if flags & O_TRUNC != 0 && file.metadata().is_ok_and(|m| m.is_file()) {
                c.p.space.truncated(fs::identity(&file)?, 0);
            }
            let ftype = fs::file_type_of(&file.metadata()?);
            if flags & layout.directory != 0 && ftype != FileType::Directory {
                return Err(Errno(ENOTDIR));
            }
            Ok(OpenFile::new(
                FileObject::Host(file),
                ftype,
                guest,
                Some(host),
                status,
            ))
        }
    }
}

/// `openat` (and `open`, `creat`).
pub fn openat(c: &mut Ctx<'_>, dirfd: i32, path: u64, flags: u32, create_mode: u32) -> SysResult {
    let nofollow = flags & c.p.abi.open_flags().nofollow != 0;
    let target = resolve(c, dirfd, path, 0, !nofollow)?;
    let file = open_target(c, target, flags, create_mode)?;
    super::io::install(c, file, flags & O_CLOEXEC != 0)
}

/// `openat2` with `struct open_how` (resolution restrictions are not
/// supported and are rejected with `EINVAL`).
pub fn openat2(c: &mut Ctx<'_>, dirfd: i32, path: u64, how: u64, size: u64) -> SysResult {
    const OPEN_HOW_SIZE_VER0: u64 = 24;
    if size < OPEN_HOW_SIZE_VER0 || size > 4096 {
        return Err(Errno(if size > 4096 { E2BIG } else { EINVAL }));
    }
    let raw = c.read_mem(how, size as usize)?;
    if raw[24..].iter().any(|&b| b != 0) {
        return Err(Errno(E2BIG));
    }
    let flags = u64::from_le_bytes(raw[..8].try_into().unwrap());
    let mode = u64::from_le_bytes(raw[8..16].try_into().unwrap());
    let resolve_flags = u64::from_le_bytes(raw[16..24].try_into().unwrap());
    let layout = c.p.abi.open_flags();
    let valid = u64::from(
        O_ACCMODE
            | O_CREAT
            | O_EXCL
            | O_NOCTTY
            | O_TRUNC
            | O_APPEND
            | O_NONBLOCK
            | O_DSYNC
            | FASYNC
            | O_NOATIME
            | O_CLOEXEC
            | O_SYNC_BIT
            | O_PATH
            | O_TMPFILE_BIT
            | layout.directory
            | layout.nofollow
            | layout.direct
            | layout.largefile,
    );
    if flags & !valid != 0 || mode & !0o7777 != 0 {
        return Err(Errno(EINVAL));
    }
    if mode != 0 && flags & u64::from(O_CREAT | O_TMPFILE_BIT) == 0 {
        return Err(Errno(EINVAL));
    }
    if resolve_flags != 0 {
        return Err(Errno(EINVAL));
    }
    openat(c, dirfd, path, flags as u32, mode as u32)
}

/// `newfstatat` (and `stat`, `lstat`).
pub fn fstatat(c: &mut Ctx<'_>, dirfd: i32, path: u64, buf: u64, flags: u32) -> SysResult {
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH | AT_NO_AUTOMOUNT) != 0 {
        return Err(Errno(EINVAL));
    }
    let follow = flags & AT_SYMLINK_NOFOLLOW == 0;
    let target = resolve(c, dirfd, path, flags, follow)?;
    let st = stat_target(c, &target, follow)?;
    c.write_mem(buf, &st.encode(c.p.abi))?;
    Ok(0)
}

/// `fstat`.
pub fn fstat(c: &mut Ctx<'_>, fd: i32, buf: u64) -> SysResult {
    let file = c.p.fds.file(fd)?;
    let st = stat_file(c, &file)?;
    c.write_mem(buf, &st.encode(c.p.abi))?;
    Ok(0)
}

/// `statx`.
pub fn statx(c: &mut Ctx<'_>, dirfd: i32, path: u64, flags: u32, mask: u32, buf: u64) -> SysResult {
    const STATX_RESERVED: u32 = 0x8000_0000;
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT | AT_EMPTY_PATH | AT_STATX_SYNC_TYPE) != 0
        || flags & AT_STATX_SYNC_TYPE == AT_STATX_SYNC_TYPE
        || mask & STATX_RESERVED != 0
    {
        return Err(Errno(EINVAL));
    }
    let follow = flags & AT_SYMLINK_NOFOLLOW == 0;
    let target = resolve(c, dirfd, path, flags, follow)?;
    let st = stat_target(c, &target, follow)?;
    c.write_mem(buf, &st.encode_statx())?;
    Ok(0)
}

/// `faccessat`/`faccessat2` (and `access`).
pub fn faccessat(c: &mut Ctx<'_>, dirfd: i32, path: u64, amode: u32, flags: u32) -> SysResult {
    if amode & !7 != 0 || flags & !(AT_EACCESS | AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return Err(Errno(EINVAL));
    }
    let follow = flags & AT_SYMLINK_NOFOLLOW == 0;
    match resolve(c, dirfd, path, flags, follow)? {
        Target::Proc(ProcEntry::File(_), _) => {
            // Synthesized files are readable only: W_OK and X_OK fail.
            if amode & 3 != 0 {
                return Err(Errno(EACCES));
            }
            Ok(0)
        }
        Target::Proc(..) => Ok(0),
        Target::Fd(f) => match &f.host_path {
            Some(h) => {
                super::super::host::access(h, amode, flags & AT_EACCESS != 0, follow).map(|_| 0)
            }
            None => Ok(0),
        },
        Target::Host { host, .. } => {
            super::super::host::access(&host, amode, flags & AT_EACCESS != 0, follow).map(|_| 0)
        }
    }
}

/// `readlinkat` (and `readlink`).
pub fn readlinkat(c: &mut Ctx<'_>, dirfd: i32, path: u64, buf: u64, size: u64) -> SysResult {
    if (size as i64) <= 0 {
        return Err(Errno(EINVAL));
    }
    let bytes = match resolve(c, dirfd, path, AT_EMPTY_PATH, false)? {
        Target::Proc(ProcEntry::Link(t), _) => t.into_bytes(),
        Target::Proc(..) | Target::Fd(_) => return Err(Errno(EINVAL)),
        Target::Host { host, .. } => {
            use std::os::unix::ffi::OsStrExt;
            std::fs::read_link(&host)?.as_os_str().as_bytes().to_vec()
        }
    };
    let n = bytes.len().min(size as usize);
    c.write_mem(buf, &bytes[..n])?;
    Ok(n as u64)
}

/// `getcwd`: returns the length including the NUL.
pub fn getcwd(c: &mut Ctx<'_>, buf: u64, size: u64) -> SysResult {
    let mut cwd = c.p.vfs.cwd().as_bytes().to_vec();
    cwd.push(0);
    if (size as usize) < cwd.len() {
        return Err(Errno(ERANGE));
    }
    c.write_mem(buf, &cwd)?;
    Ok(cwd.len() as u64)
}

fn set_cwd_from(c: &mut Ctx<'_>, target: Target) -> SysResult {
    match target {
        Target::Host { host, .. } => {
            let m = std::fs::metadata(&host)?;
            if !m.is_dir() {
                return Err(Errno(ENOTDIR));
            }
            let canonical = std::fs::canonicalize(&host)?;
            let guest = c.p.vfs.guest_path_of(&canonical);
            c.p.vfs.set_cwd(guest);
            Ok(0)
        }
        Target::Proc(ProcEntry::Dir(_), guest) => {
            c.p.vfs.set_cwd(guest);
            Ok(0)
        }
        Target::Proc(ProcEntry::Link(link), _) => {
            let t = resolve_str(c, AT_FDCWD, &link, true)?;
            set_cwd_from(c, t)
        }
        Target::Proc(..) => Err(Errno(ENOTDIR)),
        Target::Fd(f) => match &f.host_path {
            Some(h) => {
                let guest = c.p.vfs.guest_path_of(h);
                let t = resolve_str(c, AT_FDCWD, &guest, true)?;
                set_cwd_from(c, t)
            }
            None if f.ftype == FileType::Directory => {
                c.p.vfs.set_cwd(f.path.clone());
                Ok(0)
            }
            None => Err(Errno(ENOTDIR)),
        },
    }
}

/// `chdir`.
pub fn chdir(c: &mut Ctx<'_>, path: u64) -> SysResult {
    let target = resolve(c, AT_FDCWD, path, 0, true)?;
    set_cwd_from(c, target)
}

/// `fchdir`.
pub fn fchdir(c: &mut Ctx<'_>, fd: i32) -> SysResult {
    let file = c.p.fds.file(fd)?;
    if file.ftype != FileType::Directory {
        return Err(Errno(ENOTDIR));
    }
    set_cwd_from(c, Target::Fd(file))
}

fn host_target(c: &Ctx<'_>, dirfd: i32, path: u64, follow: bool) -> Result<PathBuf, Errno> {
    match resolve(c, dirfd, path, 0, follow)? {
        Target::Host { host, .. } => Ok(host),
        // Synthesized entries are read-only.
        Target::Proc(..) | Target::Fd(_) => Err(Errno(EACCES)),
    }
}

/// `mkdirat` (and `mkdir`).
pub fn mkdirat(c: &mut Ctx<'_>, dirfd: i32, path: u64, perm: u32) -> SysResult {
    let host = host_target(c, dirfd, path, false)?;
    std::fs::DirBuilder::new()
        .mode(perm & 0o7777 & !c.p.umask)
        .create(&host)?;
    Ok(0)
}

/// `unlinkat` (and `unlink`, `rmdir`).
pub fn unlinkat(c: &mut Ctx<'_>, dirfd: i32, path: u64, flags: u32) -> SysResult {
    if flags & !AT_REMOVEDIR != 0 {
        return Err(Errno(EINVAL));
    }
    let host = host_target(c, dirfd, path, false)?;
    if flags & AT_REMOVEDIR != 0 {
        std::fs::remove_dir(&host)?;
    } else {
        // Linux reports EISDIR for unlink(dir); some hosts report EPERM.
        if std::fs::symlink_metadata(&host)?.is_dir() {
            return Err(Errno(EISDIR));
        }
        std::fs::remove_file(&host)?;
    }
    Ok(0)
}

/// `renameat2` (and `rename`, `renameat`).
pub fn renameat2(
    c: &mut Ctx<'_>,
    olddir: i32,
    old: u64,
    newdir: i32,
    new: u64,
    flags: u32,
) -> SysResult {
    const RENAME_NOREPLACE: u32 = 1;
    if flags & !RENAME_NOREPLACE != 0 {
        return Err(Errno(EINVAL));
    }
    let from = host_target(c, olddir, old, false)?;
    let to = host_target(c, newdir, new, false)?;
    if flags & RENAME_NOREPLACE != 0 && std::fs::symlink_metadata(&to).is_ok() {
        return Err(Errno(EEXIST));
    }
    std::fs::rename(&from, &to)?;
    Ok(0)
}

/// `linkat` (and `link`).
pub fn linkat(
    c: &mut Ctx<'_>,
    olddir: i32,
    old: u64,
    newdir: i32,
    new: u64,
    flags: u32,
) -> SysResult {
    if flags & !(AT_SYMLINK_FOLLOW | AT_EMPTY_PATH) != 0 {
        return Err(Errno(EINVAL));
    }
    let from = host_target(c, olddir, old, flags & AT_SYMLINK_FOLLOW != 0)?;
    let to = host_target(c, newdir, new, false)?;
    std::fs::hard_link(&from, &to)?;
    Ok(0)
}

/// `symlinkat` (and `symlink`). The target is stored verbatim.
pub fn symlinkat(c: &mut Ctx<'_>, target: u64, newdir: i32, linkpath: u64) -> SysResult {
    let raw = c.read_cstr_raw(target, fs::PATH_MAX - 1)?;
    if raw.is_empty() {
        return Err(Errno(ENOENT));
    }
    let target = fs::Vfs::path_str(&raw)?;
    let link = host_target(c, newdir, linkpath, false)?;
    std::os::unix::fs::symlink(target, &link)?;
    Ok(0)
}

/// `fchmodat`/`fchmodat2` (and `chmod`).
pub fn fchmodat(c: &mut Ctx<'_>, dirfd: i32, path: u64, perm: u32, flags: u32) -> SysResult {
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return Err(Errno(EINVAL));
    }
    let follow = flags & AT_SYMLINK_NOFOLLOW == 0;
    let host = match resolve(c, dirfd, path, flags, follow)? {
        Target::Host { host, .. } => host,
        Target::Fd(f) => f.host_path.clone().ok_or(Errno(EBADF))?,
        Target::Proc(..) => return Err(Errno(EPERM)),
    };
    if !follow && std::fs::symlink_metadata(&host)?.file_type().is_symlink() {
        // Linux cannot change a symbolic link's mode.
        return Err(Errno(EOPNOTSUPP));
    }
    std::fs::set_permissions(&host, std::fs::Permissions::from_mode(perm & 0o7777))?;
    Ok(0)
}

/// `fchmod`.
pub fn fchmod(c: &mut Ctx<'_>, fd: i32, perm: u32) -> SysResult {
    let file = c.p.fds.file(fd)?;
    match &file.object {
        FileObject::Host(f) => {
            f.set_permissions(std::fs::Permissions::from_mode(perm & 0o7777))?;
            Ok(0)
        }
        FileObject::PathOnly => Err(Errno(EBADF)),
        _ => Ok(0),
    }
}

fn opt_id(id: u32) -> Option<u32> {
    (id != u32::MAX).then_some(id)
}

/// `fchownat` (and `chown`, `lchown`).
pub fn fchownat(
    c: &mut Ctx<'_>,
    dirfd: i32,
    path: u64,
    uid: u32,
    gid: u32,
    flags: u32,
) -> SysResult {
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return Err(Errno(EINVAL));
    }
    let follow = flags & AT_SYMLINK_NOFOLLOW == 0;
    let host = match resolve(c, dirfd, path, flags, follow)? {
        Target::Host { host, .. } => host,
        Target::Fd(f) => f.host_path.clone().ok_or(Errno(EBADF))?,
        Target::Proc(..) => return Err(Errno(EPERM)),
    };
    if follow {
        std::os::unix::fs::chown(&host, opt_id(uid), opt_id(gid))?;
    } else {
        std::os::unix::fs::lchown(&host, opt_id(uid), opt_id(gid))?;
    }
    Ok(0)
}

/// `fchown`.
pub fn fchown(c: &mut Ctx<'_>, fd: i32, uid: u32, gid: u32) -> SysResult {
    let file = c.p.fds.file(fd)?;
    match &file.object {
        FileObject::Host(f) => {
            std::os::unix::fs::fchown(f, opt_id(uid), opt_id(gid))?;
            Ok(0)
        }
        FileObject::PathOnly => Err(Errno(EBADF)),
        _ => Ok(0),
    }
}

/// `truncate`.
pub fn truncate(c: &mut Ctx<'_>, path: u64, len: i64) -> SysResult {
    if len < 0 {
        return Err(Errno(EINVAL));
    }
    let host = host_target(c, AT_FDCWD, path, true)?;
    if std::fs::metadata(&host)?.is_dir() {
        return Err(Errno(EISDIR));
    }
    let f = std::fs::OpenOptions::new().write(true).open(&host)?;
    f.set_len(len as u64)?;
    c.p.space.truncated(fs::identity(&f)?, len as u64);
    Ok(0)
}

/// `utimensat` (a null path with a descriptor is `futimens`).
pub fn utimensat(c: &mut Ctx<'_>, dirfd: i32, path: u64, times: u64, flags: u32) -> SysResult {
    const UTIME_NOW: i64 = (1 << 30) - 1;
    const UTIME_OMIT: i64 = (1 << 30) - 2;
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return Err(Errno(EINVAL));
    }
    let now = std::time::SystemTime::now();
    let mut ts = [Some(now), Some(now)];
    if times != 0 {
        let raw = c.read_mem(times, 32)?;
        for (i, chunk) in raw.chunks_exact(16).enumerate() {
            let t = Timespec::decode(chunk.try_into().unwrap());
            ts[i] = match t.nsec {
                UTIME_NOW => Some(now),
                UTIME_OMIT => None,
                n if (0..1_000_000_000).contains(&n) => {
                    let d = std::time::Duration::new(t.sec.max(0) as u64, n as u32);
                    Some(std::time::UNIX_EPOCH + d)
                }
                _ => return Err(Errno(EINVAL)),
            };
        }
    }
    if ts == [None, None] {
        return Ok(0);
    }
    let file = if path == 0 {
        match &c.p.fds.file(dirfd)?.object {
            FileObject::Host(f) => f.try_clone()?,
            _ => return Err(Errno(EBADF)),
        }
    } else {
        let host = host_target(c, dirfd, path, flags & AT_SYMLINK_NOFOLLOW == 0)?;
        std::fs::File::open(&host)?
    };
    let mut ft = std::fs::FileTimes::new();
    if let Some(a) = ts[0] {
        ft = ft.set_accessed(a);
    }
    if let Some(m) = ts[1] {
        ft = ft.set_modified(m);
    }
    file.set_times(ft)?;
    Ok(0)
}

/// `EXT4_SUPER_MAGIC`, reported for host file systems.
const EXT4_SUPER_MAGIC: u64 = 0xEF53;
/// `PROC_SUPER_MAGIC`.
const PROC_SUPER_MAGIC: u64 = 0x9fa0;
/// `ST_VALID` (`f_flags` is meaningful).
const ST_VALID: u64 = 0x20;

fn encode_statfs(magic: u64, st: &super::super::host::FsStats) -> Vec<u8> {
    let mut e = super::super::abi::types::Encoder::new();
    e.u64(magic)
        .u64(st.bsize)
        .u64(st.blocks)
        .u64(st.bfree)
        .u64(st.bavail)
        .u64(st.files)
        .u64(st.ffree)
        .u64(0) // f_fsid
        .u64(st.namemax)
        .u64(st.frsize)
        .u64(ST_VALID | (st.flags & 0x3))
        .zeros(32);
    e.finish()
}

/// `statfs` (`struct statfs`, 120 bytes on every 64-bit ABI).
pub fn statfs(c: &mut Ctx<'_>, path: u64, buf: u64) -> SysResult {
    match resolve(c, AT_FDCWD, path, 0, true)? {
        Target::Proc(..) => {
            let st = super::super::host::FsStats {
                bsize: 4096,
                frsize: 4096,
                namemax: 255,
                ..Default::default()
            };
            c.write_mem(buf, &encode_statfs(PROC_SUPER_MAGIC, &st))?;
        }
        Target::Host { host, .. } => {
            let st = super::super::host::statvfs(&host)?;
            c.write_mem(buf, &encode_statfs(EXT4_SUPER_MAGIC, &st))?;
        }
        Target::Fd(_) => return Err(Errno(ENOENT)),
    }
    Ok(0)
}

/// `fstatfs`.
pub fn fstatfs(c: &mut Ctx<'_>, fd: i32, buf: u64) -> SysResult {
    let file = c.p.fds.file(fd)?;
    let st = match &file.host_path {
        Some(h) => super::super::host::statvfs(h)?,
        None => super::super::host::FsStats {
            bsize: 4096,
            frsize: 4096,
            namemax: 255,
            ..Default::default()
        },
    };
    let magic = if file.host_path.is_some() {
        EXT4_SUPER_MAGIC
    } else {
        PROC_SUPER_MAGIC
    };
    c.write_mem(buf, &encode_statfs(magic, &st))?;
    Ok(0)
}

/// `umask`.
pub fn umask(c: &mut Ctx<'_>, mask: u32) -> SysResult {
    let old = c.p.umask;
    c.p.umask = mask & 0o777;
    Ok(u64::from(old))
}
