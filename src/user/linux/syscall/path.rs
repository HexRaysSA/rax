//! Path-based system calls: opening, metadata, names, and directories.

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::Arc;

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::abi::open::*;
use super::super::abi::types::{Kstatfs, MAX_NON_LFS, Stat, Timespec, mode};
use super::super::fs::fd::{FileObject, FileType, OpenFile};
use super::super::fs::{self, join_guest};
use super::super::fsnotify::bits::{IN_ATTRIB, IN_MODIFY};
use super::super::procfs::{self, Directory, ProcEntry};
use super::{Ctx, SysResult};
use crate::user::supplied_fs::{Entry, LinkPolicy, WorkspaceRename, WorkspaceTimestamp};

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
    /// Immutable caller-supplied bytes or an inferred guest directory.
    Supplied(crate::user::supplied_fs::Entry, String),
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
        return Ok(c.p.working_directory().into_owned());
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

fn supplied_relative_path(
    c: &Ctx<'_>,
    dirfd: i32,
    path: &str,
    ids: (u32, u32),
) -> Result<(String, Option<crate::user::supplied_fs::Entry>), Errno> {
    let base = base_dir(c, dirfd)?;
    let directory = if dirfd == AT_FDCWD {
        c.p.workspace_working_directory()
    } else if let FileObject::Supplied(entry) = &c.p.fds.file(dirfd)?.object {
        entry.workspace_directory().cloned()
    } else {
        None
    };
    Ok(crate::user::supplied_fs::relative_workspace_path(
        &base,
        directory.as_ref(),
        path,
        ids,
        &c.p.groups,
    )?)
}

/// Resolves a guest path string relative to `dirfd`.
pub fn resolve_str(c: &Ctx<'_>, dirfd: i32, path: &str, follow: bool) -> Result<Target, Errno> {
    resolve_str_as(c, dirfd, path, follow, (c.p.creds.1, c.p.creds.3))
}

fn resolve_str_as(
    c: &Ctx<'_>,
    dirfd: i32,
    path: &str,
    follow: bool,
    ids: (u32, u32),
) -> Result<Target, Errno> {
    // Preserve components until the closed namespace has checked directory
    // traversal. Lexically erasing `.` would mis-handle `/regular-file/.`.
    let guest = if c.p.vfs.supplied().is_some() {
        if path.starts_with('/') {
            path.to_string()
        } else {
            let (guest, retained) = supplied_relative_path(c, dirfd, path, ids)?;
            if let Some(entry) = retained {
                return Ok(Target::Supplied(entry, guest));
            }
            guest
        }
    } else if path.starts_with('/') {
        join_guest("/", path)
    } else {
        join_guest(&base_dir(c, dirfd)?, path)
    };
    if let Some(files) = c.p.vfs.supplied() {
        let policy = if follow {
            LinkPolicy::Follow
        } else {
            LinkPolicy::NoFollowLast
        };
        match files.lookup_for_guest(&guest, policy, ids, &c.p.groups) {
            Ok((canonical, entry)) => return Ok(Target::Supplied(entry, canonical)),
            Err(crate::user::supplied_fs::Error::NotFound) => {}
            Err(error) => return Err(error.into()),
        }
    }
    // Supply conventional devfs links in the closed namespace. Caller files
    // have already been considered and the hosted profile keeps its devfs.
    let guest = if c.p.config.host_services {
        guest
    } else {
        let alias = match guest.trim_end_matches('/') {
            "/dev/fd" => Some("/proc/self/fd"),
            "/dev/stdin" => Some("/proc/self/fd/0"),
            "/dev/stdout" => Some("/proc/self/fd/1"),
            "/dev/stderr" => Some("/proc/self/fd/2"),
            _ => None,
        };
        if let Some(alias) = alias {
            if !follow && !guest.ends_with('/') {
                return Ok(Target::Proc(ProcEntry::Link(alias.into()), guest));
            }
            if guest.ends_with('/') {
                format!("{alias}/")
            } else {
                alias.into()
            }
        } else if let Some(slot) = guest.strip_prefix("/dev/fd/") {
            format!("/proc/self/fd/{slot}")
        } else {
            guest
        }
    };
    let threads = c.thread_refs();
    if let Some(entry) = procfs::lookup(c.p, c.t, &threads, &guest) {
        if guest.ends_with('/') && matches!(entry, ProcEntry::Descriptor { .. }) {
            return Err(Errno(ENOTDIR));
        }
        return Ok(Target::Proc(entry, guest));
    }
    if procfs::owned(c.p, &threads, &guest) {
        return Err(Errno(ENOENT));
    }
    if c.p.vfs.supplied().is_some() {
        return Err(Errno(ENOENT));
    }
    let host = c.p.vfs.host_path(&guest, follow)?;
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
    resolve_as(
        c,
        dirfd,
        path_addr,
        flags,
        follow,
        (c.p.creds.1, c.p.creds.3),
    )
}

fn resolve_as(
    c: &Ctx<'_>,
    dirfd: i32,
    path_addr: u64,
    flags: u32,
    follow: bool,
    ids: (u32, u32),
) -> Result<Target, Errno> {
    let raw = c.read_cstr_raw(path_addr, fs::PATH_MAX - 1)?;
    if raw.is_empty() {
        if flags & AT_EMPTY_PATH != 0 {
            if dirfd == AT_FDCWD {
                return resolve_str_as(c, AT_FDCWD, ".", true, ids);
            }
            return Ok(Target::Fd(c.p.fds.file(dirfd)?));
        }
        return Err(Errno(ENOENT));
    }
    let path = fs::Vfs::path_str(&raw)?;
    resolve_str_as(c, dirfd, &path, follow, ids)
}

/// Metadata of a synthesized entry, owned by `ids` (effective UID and
/// GID).
fn proc_stat(ids: (u32, u32), e: &ProcEntry) -> Stat {
    let (m, size) = match e {
        ProcEntry::File(d) => (mode::S_IFREG | 0o444, d.len() as i64),
        ProcEntry::Comm { .. } => (mode::S_IFREG | 0o644, 0),
        ProcEntry::Link(t) => (mode::S_IFLNK | 0o777, t.len() as i64),
        ProcEntry::Descriptor { target, .. } => (mode::S_IFLNK | 0o777, target.len() as i64),
        ProcEntry::Dir(_) => (mode::S_IFDIR | 0o555, 0),
        ProcEntry::TraceeFile { .. } => (mode::S_IFREG | 0o444, 0),
    };
    let (sec, nsec) = super::super::host::clock_gettime(super::super::host::HostClock::Realtime);
    let now = Timespec { sec, nsec };
    Stat {
        dev_major: 0,
        dev_minor: 0x16,
        ino: 0x5241_5800,
        mode: m,
        nlink: 1,
        uid: ids.0,
        gid: ids.1,
        size,
        blksize: 1024,
        blocks: 0,
        atime: now,
        mtime: now,
        ctime: now,
        ..Default::default()
    }
}

/// Metadata of a supplied entry, including guest character devices.
fn supplied_stat(entry: &Entry) -> Stat {
    let size = entry.len().min(i64::MAX as u64) as i64;
    let blocks = (size as u64).div_ceil(512) as i64;
    #[cfg(target_os = "linux")]
    let blocks = entry
        .workspace_file()
        .and_then(|file| file.linux_allocated_blocks())
        .unwrap_or(blocks);
    let (uid, gid) = entry.workspace_owner().unwrap_or((0, 0));
    let timestamps = entry.workspace_timestamps();
    let times = timestamps.unwrap_or_default();
    let to_timespec = |time: WorkspaceTimestamp| Timespec {
        sec: time.seconds,
        nsec: time.nanoseconds,
    };
    Stat {
        ino: entry.ino,
        mode: match &entry.kind {
            crate::user::supplied_fs::Kind::Directory
            | crate::user::supplied_fs::Kind::WorkspaceDirectory(_) => {
                mode::S_IFDIR | entry.workspace_mode().unwrap_or(0o555)
            }
            crate::user::supplied_fs::Kind::Workspace(file) => mode::S_IFREG | file.mode(),
            crate::user::supplied_fs::Kind::Symlink(_)
            | crate::user::supplied_fs::Kind::WorkspaceSymlink(_) => mode::S_IFLNK | 0o777,
            crate::user::supplied_fs::Kind::NullDevice
            | crate::user::supplied_fs::Kind::ZeroDevice
            | crate::user::supplied_fs::Kind::UrandomDevice => mode::S_IFCHR | 0o666,
            _ => mode::S_IFREG | 0o555,
        },
        nlink: if let Some(directory) = entry.workspace_directory() {
            u64::from(directory.link_count(crate::user::supplied_fs::WorkspaceFlavor::Linux))
        } else if entry.is_dir() {
            2
        } else {
            u64::from(entry.workspace_leaf_links().unwrap_or(1))
        },
        uid,
        gid,
        rdev_major: u32::from(entry.device().is_some()),
        rdev_minor: match entry.device() {
            Some(crate::user::supplied_fs::Device::Null) => 3,
            Some(crate::user::supplied_fs::Device::Zero) => 5,
            Some(crate::user::supplied_fs::Device::Urandom) => 9,
            None => 0,
        },
        size,
        blksize: 4096,
        blocks,
        atime: to_timespec(times.accessed),
        mtime: to_timespec(times.modified),
        ctime: to_timespec(times.changed),
        btime: timestamps.map(|times| to_timespec(times.created)),
        ..Default::default()
    }
}

/// Metadata of an open file.
pub fn stat_file(c: &Ctx<'_>, file: &OpenFile) -> Result<Stat, Errno> {
    stat_open(file, (c.p.creds.1, c.p.creds.3))
}

/// Metadata of an open file of a process whose effective UID and GID are
/// `ids` (the owner of the inodes it creates).
pub fn stat_open(file: &OpenFile, ids: (u32, u32)) -> Result<Stat, Errno> {
    if let FileObject::Supplied(entry) = &file.object {
        return Ok(supplied_stat(entry));
    }
    if let Some(stat) = file.supplied_stat {
        return Ok(stat);
    }
    match &file.object {
        FileObject::Console { stream, .. } => Ok(Stat {
            ino: 0x5241_5810
                + match stream {
                    None => 0,
                    Some(crate::user::console::OutputStream::Stdout) => 1,
                    Some(crate::user::console::OutputStream::Stderr) => 2,
                },
            mode: mode::S_IFCHR | 0o600,
            nlink: 1,
            uid: ids.0,
            gid: ids.1,
            blksize: 4096,
            ..Default::default()
        }),
        FileObject::Mqueue(h) => Ok(super::mqueue::stat(&h.get()?)),
        #[cfg(unix)]
        FileObject::Host(f) => Ok(fs::stat_from_metadata(&f.metadata()?)),
        #[cfg(not(unix))]
        FileObject::Host(_) | FileObject::PathOnly => Err(Errno(EPERM)),
        #[cfg(unix)]
        FileObject::PathOnly => {
            let h = file.host_path.as_ref().ok_or(Errno(EBADF))?;
            Ok(fs::stat_from_metadata(&std::fs::symlink_metadata(h)?))
        }
        FileObject::PipeRead(_) | FileObject::PipeWrite(_) | FileObject::GuestPipe(_) => {
            let (ino, (uid, gid)) = match &file.object {
                FileObject::GuestPipe(end) => (end.inode(), end.owner()),
                _ => (0, ids),
            };
            Ok(Stat {
                dev_minor: 0xe,
                ino,
                mode: mode::S_IFIFO | 0o600,
                nlink: 1,
                uid,
                gid,
                blksize: 4096,
                ..Default::default()
            })
        }
        // pidfs_init_inode: mode 0700 shown without a file type
        // (anon_inode_getattr), owned by root, one inode per task.
        FileObject::Anon(super::super::fs::anon::Anon::Pid(t)) => Ok(Stat {
            dev_minor: super::pidfd::PIDFS_DEV_MINOR,
            ino: t.ino(),
            mode: 0o700,
            nlink: 1,
            blksize: 4096,
            ..Default::default()
        }),
        // anon_inode_create_getfile: an io_uring's own anon_inode_fs inode,
        // otherwise as below.
        FileObject::Anon(super::super::fs::anon::Anon::Uring(r)) => Ok(Stat {
            dev_minor: 0x10,
            ino: r.ino,
            mode: 0o600,
            nlink: 1,
            uid: ids.0,
            gid: ids.1,
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
            uid: ids.0,
            gid: ids.1,
            blksize: 4096,
            ..Default::default()
        }),
        // sock_alloc: S_IFSOCK with every permission, the caller's IDs,
        // on sockfs.
        #[cfg(unix)]
        FileObject::Socket(s) => Ok(Stat {
            dev_minor: 0x8,
            ino: s.ino,
            mode: mode::S_IFSOCK | 0o777,
            nlink: 1,
            uid: ids.0,
            gid: ids.1,
            blksize: 4096,
            ..Default::default()
        }),
        FileObject::Supplied(entry) => Ok(supplied_stat(entry)),
        FileObject::Synthetic(d) => Ok(proc_stat(
            ids,
            &if file.ftype == FileType::Directory {
                ProcEntry::Dir(Directory::Snapshot(Vec::new()))
            } else {
                ProcEntry::File(d.to_vec())
            },
        )),
    }
}

/// Metadata of a resolved target.
pub(super) fn stat_target(c: &Ctx<'_>, t: &Target, follow: bool) -> Result<Stat, Errno> {
    match t {
        Target::Fd(f) => stat_file(c, f),
        Target::Supplied(entry, _) => Ok(supplied_stat(entry)),
        Target::Proc(ProcEntry::Descriptor { file, .. }, _) if follow => stat_file(c, file),
        Target::Proc(ProcEntry::Link(link), _) if follow => {
            let target = resolve_str(c, AT_FDCWD, link, true)?;
            stat_target(c, &target, true)
        }
        Target::Proc(e, _) => Ok(proc_stat((c.p.creds.1, c.p.creds.3), e)),
        #[cfg(not(unix))]
        Target::Host { .. } => Err(Errno(EPERM)),
        #[cfg(unix)]
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

fn open_proc_link(guest: String, target: Arc<[u8]>, flags: u32) -> Arc<OpenFile> {
    let entry = Entry {
        ino: 0x5241_5800,
        kind: crate::user::supplied_fs::Kind::Symlink(target),
    };
    OpenFile::new(
        FileObject::Supplied(entry),
        FileType::Symlink,
        guest,
        None,
        flags,
    )
}

/// Opens a resolved target.
pub(super) fn open_target(
    c: &mut Ctx<'_>,
    target: Target,
    flags: u32,
    create_mode: u32,
) -> Result<Arc<OpenFile>, Errno> {
    let layout = c.p.abi.open_flags();
    let accmode = flags & O_ACCMODE;
    // f_flags (build_open_how, build_open_flags, do_dentry_open): the
    // valid open flags less the creation-time flags and O_CLOEXEC; an
    // O_PATH open keeps only O_PATH, O_DIRECTORY, and O_NOFOLLOW. The
    // caller has added O_LARGEFILE where the call forces it.
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
        flags & valid & !(O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC | O_CLOEXEC)
    };
    match target {
        Target::Proc(ProcEntry::TraceeFile { tid, name }, guest) => {
            let request = super::super::ptrace::procfs::OpenRequest {
                tid,
                name,
                guest: guest.clone(),
                flags,
                create_mode,
            };
            let (bytes, descriptor) = super::super::ptrace::procfs::read(c, request)?;
            #[cfg(unix)]
            if let Some(descriptor) = descriptor {
                return super::super::fs::reopen::adopt(descriptor, &bytes, status);
            }
            open_target(
                c,
                Target::Proc(ProcEntry::File(bytes), guest),
                flags,
                create_mode,
            )
        }
        Target::Fd(file) => Ok(file),
        Target::Supplied(entry, guest) => {
            if flags & (O_TMPFILE_BIT | O_PATH) == O_TMPFILE_BIT {
                if !entry.is_dir() {
                    return Err(Errno(ENOTDIR));
                }
                let directory = entry.workspace_directory().ok_or(Errno(EROFS))?;
                // The temporary inode has tmpfs semantics, including buffered I/O
                // for descriptors opened with O_DIRECT.
                let files = c.p.vfs.supplied().expect("supplied target has a namespace");
                let entry = files.create_workspace_tmpfile(
                    directory,
                    create_mode & !c.p.file_creation_mask(),
                    (c.p.creds.1, c.p.creds.3),
                    &c.p.groups,
                    flags & O_EXCL != 0,
                )?;
                let path = entry.workspace_path()?.expect("unnamed workspace path");
                return Ok(OpenFile::new(
                    FileObject::Supplied(entry),
                    FileType::Regular,
                    path,
                    None,
                    status,
                ));
            }
            let device = entry.device().is_some();
            let workspace = entry.workspace_file();
            if flags & (O_CREAT | O_EXCL) == (O_CREAT | O_EXCL) {
                return Err(Errno(EEXIST));
            }
            if entry.link_target().is_some() && flags & O_PATH == 0 {
                return Err(Errno(ELOOP));
            }
            if !device
                && workspace.is_none()
                && flags & O_PATH == 0
                && (accmode != O_RDONLY || flags & (O_TRUNC | O_TMPFILE_BIT) != 0)
            {
                return Err(Errno(EROFS));
            }
            if flags & layout.directory != 0 && !entry.is_dir() {
                return Err(Errno(ENOTDIR));
            }
            if let Some(directory) = entry.workspace_directory()
                && flags & O_PATH == 0
                && !directory.permits(4, (c.p.creds.1, c.p.creds.3), &c.p.groups)
            {
                return Err(Errno(EACCES));
            }
            if (device || workspace.is_some()) && flags & O_PATH == 0 && flags & layout.direct != 0
            {
                return Err(Errno(EINVAL));
            }
            if let Some(file) = workspace
                && flags & O_PATH == 0
                && flags & O_TRUNC != 0
            {
                file.resize(0)?;
                c.p.space
                    .truncated(crate::user::mm::PageSource::identity(file), 0);
            }
            let mut directory = None;
            let (object, kind) = if device {
                let object = if flags & O_PATH == 0 {
                    FileObject::Supplied(entry.clone())
                } else {
                    FileObject::PathOnly
                };
                (object, FileType::CharDevice)
            } else if entry.is_dir() {
                let object = if entry.workspace_directory().is_some() {
                    FileObject::Supplied(entry.clone())
                } else {
                    let files = c.p.vfs.supplied().expect("supplied target has a namespace");
                    let entries = super::dirents::supplied_entries(files, &guest, &entry)?;
                    directory = Some((entries, 0));
                    FileObject::Synthetic(Arc::from([]))
                };
                (object, FileType::Directory)
            } else if entry.link_target().is_some() {
                (FileObject::Supplied(entry.clone()), FileType::Symlink)
            } else {
                (FileObject::Supplied(entry.clone()), FileType::Regular)
            };
            let mut file = OpenFile::new(object, kind, guest, None, status);
            let unique = Arc::get_mut(&mut file).expect("new unpublished file");
            unique.supplied_stat = Some(supplied_stat(&entry));
            unique.state.get_mut().unwrap().dir = directory;
            Ok(file)
        }
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
        Target::Proc(ProcEntry::Dir(directory), guest) => {
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
            let mut state = f.state.lock().unwrap();
            match directory {
                Directory::Snapshot(entries) => state.dir = Some((entries, 0)),
                Directory::Descriptors(entry) => {
                    state.proc_dir = Some(c.p.fds.proc_directory(c.p.pid, entry));
                }
            }
            drop(state);
            Ok(f)
        }
        Target::Proc(ProcEntry::Descriptor { file, target }, guest) => {
            if flags & (O_CREAT | O_EXCL | O_PATH) == (O_CREAT | O_EXCL) {
                return Err(Errno(EEXIST));
            }
            if flags & layout.directory != 0 {
                return Err(Errno(ENOTDIR));
            }
            if flags & layout.nofollow != 0 {
                if flags & O_PATH == 0 {
                    return Err(Errno(ELOOP));
                }
                return Ok(open_proc_link(guest, target, status));
            }
            if flags & O_TMPFILE_BIT != 0 && flags & O_PATH == 0 {
                return Err(Errno(EINVAL));
            }
            if let FileObject::Console { console, stream } = &file.object {
                if flags & O_PATH == 0 {
                    let allowed = if stream.is_none() { O_RDONLY } else { O_WRONLY };
                    if accmode != allowed {
                        return Err(Errno(EACCES));
                    }
                    if flags & layout.direct != 0 {
                        return Err(Errno(EINVAL));
                    }
                }
                return Ok(OpenFile::new(
                    FileObject::Console {
                        console: console.clone(),
                        stream: *stream,
                    },
                    file.ftype,
                    file.path.clone(),
                    None,
                    status,
                ));
            }
            if let FileObject::GuestPipe(end) = &file.object {
                if flags & O_PATH == 0 {
                    let need = match accmode {
                        O_RDONLY => 4,
                        O_WRONLY => 2,
                        O_RDWR => 6,
                        _ => return Err(Errno(EINVAL)),
                    };
                    if !end.permits(c.p.creds.1, need) {
                        return Err(Errno(EACCES));
                    }
                    if flags & layout.direct != 0 {
                        return Err(Errno(EINVAL));
                    }
                }
                return end.reopen(status);
            }
            let FileObject::Supplied(entry) = &file.object else {
                return Err(Errno(ENOENT));
            };
            if flags & O_PATH == 0 {
                let workspace = entry.workspace_file().expect("workspace descriptor");
                let is_tmpfile = workspace.is_tmpfile();
                if flags & layout.direct != 0 && !is_tmpfile {
                    return Err(Errno(EINVAL));
                }
                let mut need = match accmode {
                    O_RDONLY => 4,
                    O_WRONLY => 2,
                    O_RDWR => 6,
                    O_ACCMODE if is_tmpfile => 6,
                    _ => return Err(Errno(EINVAL)),
                };
                if flags & O_TRUNC != 0 {
                    need |= 2;
                }
                if !workspace.permits(need, (c.p.creds.1, c.p.creds.3), &c.p.groups) {
                    return Err(Errno(EACCES));
                }
                if flags & O_TRUNC != 0 {
                    let _operation = file.lock_workspace_memfd()?;
                    if let Some(memfd) = &file.memfd {
                        memfd.check_resize(entry.len(), 0)?;
                    }
                    workspace.resize(0)?;
                    c.p.space
                        .truncated(crate::user::mm::PageSource::identity(workspace), 0);
                }
            }
            Ok(OpenFile::with_memfd(
                FileObject::Supplied(entry.clone()),
                FileType::Regular,
                file.path.clone(),
                None,
                status,
                file.memfd.clone(),
            ))
        }
        Target::Proc(ProcEntry::Link(link), guest) => {
            if flags & (O_CREAT | O_EXCL | O_PATH) == (O_CREAT | O_EXCL) {
                return Err(Errno(EEXIST));
            }
            if flags & layout.nofollow != 0 {
                if flags & (O_PATH | layout.directory) == O_PATH {
                    return Ok(open_proc_link(guest, link.into_bytes().into(), status));
                }
                return Err(Errno(if flags & layout.directory != 0 {
                    ENOTDIR
                } else {
                    ELOOP
                }));
            }
            let target = resolve_str(c, AT_FDCWD, &link, true)?;
            open_target(c, target, flags, create_mode)
        }
        #[cfg(not(unix))]
        Target::Host { .. } => Err(Errno(EPERM)),
        #[cfg(unix)]
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
            // generic_file_open (do_dentry_open) runs after the lookup and
            // permission checks and before handle_truncate: without
            // O_LARGEFILE a regular file past MAX_NON_LFS is EOVERFLOW and
            // stays untruncated, so such an open truncates only after the
            // size check.
            let size_checked = status & layout.largefile == 0;
            // Whether this open may create the file (it does not exist).
            let creates = flags & O_CREAT != 0 && std::fs::metadata(&host).is_err();
            if flags & O_CREAT != 0 {
                if flags & O_EXCL != 0 {
                    opts.create_new(true);
                } else {
                    custom |= libc::O_CREAT;
                }
                opts.mode(create_mode & 0o7777 & !c.p.file_creation_mask());
            }
            if flags & O_TRUNC != 0 && !size_checked {
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
            if size_checked && file.metadata().is_ok_and(|m| m.is_file()) {
                if file.metadata()?.len() > MAX_NON_LFS as u64 {
                    return Err(Errno(EOVERFLOW));
                }
                if flags & O_TRUNC != 0 {
                    truncate_opened(&file, &host, accmode)?;
                }
            }
            let bits = create_mode & 0o7777 & !c.p.file_creation_mask();
            if creates && bits & super::super::host::umask() != 0 {
                file.set_permissions(std::fs::Permissions::from_mode(bits))?;
            }
            if flags & O_TRUNC != 0 && file.metadata().is_ok_and(|m| m.is_file()) {
                c.p.space.truncated(fs::identity(&file)?, 0);
            }
            let meta = file.metadata()?;
            let ftype = fs::file_type_of(&meta);
            if flags & layout.directory != 0 && ftype != FileType::Directory {
                return Err(Errno(ENOTDIR));
            }
            let open = OpenFile::new(
                FileObject::Host(file),
                ftype,
                guest,
                Some(host.clone()),
                status,
            );
            // handle_truncate follows the open of an existing regular file.
            let truncated = flags & O_TRUNC != 0 && !creates && ftype == FileType::Regular;
            super::notify::opened(c, &open, &host, &meta, creates, truncated, false);
            Ok(open)
        }
    }
}

/// Truncates the regular file just opened as `file` (`handle_truncate`),
/// through a second, writable open when `accmode` is `O_RDONLY` (which
/// `O_TRUNC` truncates as well, `may_open` having required write access).
fn truncate_opened(
    file: &std::fs::File,
    host: &std::path::Path,
    accmode: u32,
) -> Result<(), Errno> {
    if accmode == O_RDONLY {
        std::fs::OpenOptions::new()
            .write(true)
            .open(host)?
            .set_len(0)?;
    } else {
        file.set_len(0)?;
    }
    Ok(())
}

/// `openat` (and `open`, `creat`, `openat2`) as a 64-bit kernel's native
/// entry points run it: `force_o_largefile()` holds, so the file is opened
/// with `O_LARGEFILE`.
pub fn openat(c: &mut Ctx<'_>, dirfd: i32, path: u64, flags: u32, create_mode: u32) -> SysResult {
    let largefile = c.p.abi.open_flags().largefile;
    open_at(c, dirfd, path, flags | largefile, create_mode)
}

/// `compat_sys_openat` (and `compat_sys_open`): `O_LARGEFILE` only if the
/// caller passes it.
pub fn compat_openat(
    c: &mut Ctx<'_>,
    dirfd: i32,
    path: u64,
    flags: u32,
    create_mode: u32,
) -> SysResult {
    open_at(c, dirfd, path, flags, create_mode)
}

fn open_at(c: &mut Ctx<'_>, dirfd: i32, path: u64, flags: u32, create_mode: u32) -> SysResult {
    if flags & (O_CREAT | O_TRUNC | O_TMPFILE_BIT) != 0
        && c.p.vfs.supplied().is_some_and(|f| f.has_workspace())
    {
        c.p.fds.free_fds(1, super::io::nofile(c))?;
    }
    let file = open_file(c, dirfd, path, flags, create_mode)?;
    super::io::install(c, file, flags & O_CLOEXEC != 0)
}

/// `do_filp_open`: the file `path` names, opened with `flags` (as they
/// stand: no `O_LARGEFILE` is added) but not installed.
pub(super) fn open_file(
    c: &mut Ctx<'_>,
    dirfd: i32,
    path: u64,
    flags: u32,
    create_mode: u32,
) -> Result<Arc<OpenFile>, Errno> {
    if let Some(super::super::wait::Resume::TraceeFile { request, .. }) = c.resume.as_ref() {
        let request = request.clone();
        let target = Target::Proc(
            ProcEntry::TraceeFile {
                tid: request.tid,
                name: request.name,
            },
            request.guest,
        );
        return open_target(c, target, request.flags, request.create_mode);
    }
    let layout = c.p.abi.open_flags();
    if flags & (O_TMPFILE_BIT | O_PATH) == O_TMPFILE_BIT
        && (flags & layout.directory == 0 || flags & O_CREAT != 0 || flags & O_ACCMODE == O_RDONLY)
    {
        return Err(Errno(EINVAL));
    }
    let create = flags & (O_CREAT | O_PATH) == O_CREAT;
    let exclusive = create && flags & O_EXCL != 0;
    let nofollow = flags & layout.nofollow != 0;
    let target = match resolve(c, dirfd, path, 0, !(nofollow || exclusive)) {
        Err(Errno(ENOENT))
            if create
                && c.p
                    .vfs
                    .supplied()
                    .is_some_and(|files| files.has_workspace()) =>
        {
            if flags
                & (c.p.abi.open_flags().directory | O_TMPFILE_BIT | c.p.abi.open_flags().direct)
                != 0
            {
                return Err(Errno(EINVAL));
            }
            let absolute = supplied_path(c, dirfd, path)?;
            let files = c.p.vfs.supplied().expect("checked supplied namespace");
            let mode = create_mode & !c.p.file_creation_mask();
            let owner = (c.p.creds.1, c.p.creds.3);
            let absolute = if nofollow || exclusive {
                absolute
            } else {
                files.workspace_create_path(&absolute, owner, &c.p.groups)?
            };
            let (path, entry) =
                files.create_workspace_file(&absolute, mode, owner, &c.p.groups, exclusive)?;
            return open_target(
                c,
                Target::Supplied(entry, path),
                flags & !O_EXCL,
                create_mode,
            );
        }
        result => result?,
    };
    if let Target::Supplied(entry, _) = &target
        && let Some(file) = entry.workspace_file()
        && flags & O_PATH == 0
        && !exclusive
    {
        let mut need = match flags & O_ACCMODE {
            O_RDONLY => 4,
            O_WRONLY => 2,
            _ => 6,
        };
        if flags & O_TRUNC != 0 {
            need |= 2;
        }
        if !file.permits(need, (c.p.creds.1, c.p.creds.3), &c.p.groups) {
            return Err(Errno(EACCES));
        }
    }
    open_target(c, target, flags, create_mode)
}

fn supplied_path(c: &Ctx<'_>, dirfd: i32, address: u64) -> Result<String, Errno> {
    let raw = c.read_cstr_raw(address, fs::PATH_MAX - 1)?;
    if raw.is_empty() {
        return Err(Errno(ENOENT));
    }
    let path = fs::Vfs::path_str(&raw)?;
    if path.starts_with('/') {
        return Ok(path.to_owned());
    }
    let (absolute, retained) = supplied_relative_path(c, dirfd, &path, (c.p.creds.1, c.p.creds.3))?;
    if retained.is_some() {
        return Err(Errno(ENOENT));
    }
    Ok(absolute)
}

/// `openat2` with `struct open_how` (resolution restrictions are not
/// supported and are rejected with `EINVAL`).
pub fn openat2(c: &mut Ctx<'_>, dirfd: i32, path: u64, how: u64, size: u64) -> SysResult {
    if let Some(super::super::wait::Resume::TraceeFile { request, .. }) = c.resume.as_ref() {
        let (flags, mode) = (request.flags, request.create_mode);
        return open_at(c, dirfd, path, flags, mode);
    }
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
    let (flags, mode) = open_how_flags(c, flags, mode, resolve_flags)?;
    openat(c, dirfd, path, flags, mode)
}

/// `build_open_flags` for a `struct open_how`: known flags only, a mode
/// only with `O_CREAT` or `O_TMPFILE` and only permission bits, and no
/// resolution restrictions (not supported); the flags and mode to open
/// with.
pub(super) fn open_how_flags(
    c: &Ctx<'_>,
    flags: u64,
    mode: u64,
    resolve_flags: u64,
) -> Result<(u32, u32), Errno> {
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
    Ok((flags as u32, mode as u32))
}

/// `vfs_fstatat`: the status of `path` relative to `dirfd`.
pub(super) fn stat_at(c: &mut Ctx<'_>, dirfd: i32, path: u64, flags: u32) -> Result<Stat, Errno> {
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH | AT_NO_AUTOMOUNT) != 0 {
        return Err(Errno(EINVAL));
    }
    let follow = flags & AT_SYMLINK_NOFOLLOW == 0;
    let target = resolve(c, dirfd, path, flags, follow)?;
    stat_target(c, &target, follow)
}

/// `vfs_fstat`: the status of `fd`'s file.
pub(super) fn stat_fd(c: &Ctx<'_>, fd: i32) -> Result<Stat, Errno> {
    let file = c.p.fds.file(fd)?;
    stat_file(c, &file)
}

/// `newfstatat` (and `stat`, `lstat`).
pub fn fstatat(c: &mut Ctx<'_>, dirfd: i32, path: u64, buf: u64, flags: u32) -> SysResult {
    let st = stat_at(c, dirfd, path, flags)?;
    c.write_mem(buf, &st.encode(c.p.abi))?;
    Ok(0)
}

/// `fstat`.
pub fn fstat(c: &mut Ctx<'_>, fd: i32, buf: u64) -> SysResult {
    let st = stat_fd(c, fd)?;
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
    let (uid, euid, gid, egid) = c.p.creds;
    let ids = if flags & AT_EACCESS != 0 {
        (euid, egid)
    } else {
        (uid, gid)
    };
    match resolve_as(c, dirfd, path, flags, follow, ids)? {
        Target::Proc(ProcEntry::File(_), _) => {
            // Synthesized files are readable only: W_OK and X_OK fail.
            if amode & 3 != 0 {
                return Err(Errno(EACCES));
            }
            Ok(0)
        }
        Target::Supplied(entry, _) => supplied_entry_access(c, &entry, amode, ids),
        Target::Proc(ProcEntry::Descriptor { file, .. }, _) if follow => {
            descriptor_access(c, &file, amode, ids, follow, flags)
        }
        Target::Proc(..) => Ok(0),
        Target::Fd(file) => descriptor_access(c, &file, amode, ids, follow, flags),
        #[cfg(not(unix))]
        Target::Host { .. } => Err(Errno(EPERM)),
        #[cfg(unix)]
        Target::Host { host, .. } => {
            super::super::host::access(&host, amode, flags & AT_EACCESS != 0, follow).map(|_| 0)
        }
    }
}

fn descriptor_access(
    c: &Ctx<'_>,
    file: &OpenFile,
    amode: u32,
    ids: (u32, u32),
    follow: bool,
    flags: u32,
) -> SysResult {
    match (&file.object, &file.host_path) {
        (FileObject::Supplied(entry), _) => supplied_entry_access(c, entry, amode, ids),
        (FileObject::Console { stream, .. }, _) => console_access(stream.is_none(), amode),
        (FileObject::GuestPipe(end), _) => {
            if end.permits(ids.0, amode) {
                Ok(0)
            } else {
                Err(Errno(EACCES))
            }
        }
        (_, _) if file.supplied_stat.is_some() => {
            supplied_access(amode, file.ftype == FileType::CharDevice)
        }
        #[cfg(unix)]
        (_, Some(host)) => {
            super::super::host::access(host, amode, flags & AT_EACCESS != 0, follow).map(|_| 0)
        }
        #[cfg(not(unix))]
        (_, Some(_)) => Err(Errno(EPERM)),
        (_, None) => Ok(0),
    }
}

fn console_access(input: bool, amode: u32) -> SysResult {
    let allowed = if input { 4 } else { 2 };
    if amode & !allowed == 0 {
        Ok(0)
    } else {
        Err(Errno(EACCES))
    }
}

fn supplied_entry_access(
    c: &Ctx<'_>,
    entry: &crate::user::supplied_fs::Entry,
    amode: u32,
    ids: (u32, u32),
) -> SysResult {
    let allowed = if let Some(file) = entry.workspace_file() {
        file.permits(amode, ids, &c.p.groups)
    } else if let Some(directory) = entry.workspace_directory() {
        directory.permits(amode, ids, &c.p.groups)
    } else {
        return supplied_access(amode, entry.device().is_some());
    };
    if allowed { Ok(0) } else { Err(Errno(EACCES)) }
}

fn supplied_access(amode: u32, device: bool) -> SysResult {
    let denied = if device { 1 } else { 2 };
    if amode & denied != 0 {
        Err(Errno(EACCES))
    } else {
        Ok(0)
    }
}

/// `readlinkat` (and `readlink`).
pub fn readlinkat(c: &mut Ctx<'_>, dirfd: i32, path: u64, buf: u64, size: u64) -> SysResult {
    if (size as i64) <= 0 {
        return Err(Errno(EINVAL));
    }
    let bytes = match resolve(c, dirfd, path, AT_EMPTY_PATH, false)? {
        Target::Proc(ProcEntry::Link(t), _) => t.into_bytes(),
        Target::Proc(ProcEntry::Descriptor { target, .. }, _) => target.to_vec(),
        Target::Proc(..) => return Err(Errno(EINVAL)),
        Target::Supplied(entry, _) => entry.link_target().ok_or(Errno(EINVAL))?.to_vec(),
        Target::Fd(file) => match &file.object {
            FileObject::Supplied(entry) => entry.link_target().ok_or(Errno(EINVAL))?.to_vec(),
            _ => return Err(Errno(EINVAL)),
        },
        #[cfg(not(unix))]
        Target::Host { .. } => return Err(Errno(EPERM)),
        #[cfg(unix)]
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
    if c.p
        .workspace_working_directory()
        .is_some_and(|directory| !directory.linked())
    {
        return Err(Errno(ENOENT));
    }
    let mut cwd = c.p.working_directory().as_bytes().to_vec();
    cwd.push(0);
    if (size as usize) < cwd.len() {
        return Err(Errno(ERANGE));
    }
    c.write_mem(buf, &cwd)?;
    Ok(cwd.len() as u64)
}

fn set_cwd_from(c: &mut Ctx<'_>, target: Target) -> SysResult {
    match target {
        Target::Supplied(entry, guest) => {
            if !entry.is_dir() {
                return Err(Errno(ENOTDIR));
            }
            if let Some(directory) = entry.workspace_directory()
                && !directory.permits(1, (c.p.creds.1, c.p.creds.3), &c.p.groups)
            {
                return Err(Errno(EACCES));
            }
            c.p.set_working_directory(guest, entry.workspace_directory().cloned());
            Ok(0)
        }
        Target::Host { host, .. } => {
            let m = std::fs::metadata(&host)?;
            if !m.is_dir() {
                return Err(Errno(ENOTDIR));
            }
            let canonical = std::fs::canonicalize(&host)?;
            let guest = c.p.vfs.guest_path_of(&canonical);
            c.p.set_working_directory(guest, None);
            Ok(0)
        }
        Target::Proc(ProcEntry::Dir(_), guest) => {
            c.p.set_working_directory(guest, None);
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
                let directory = match &f.object {
                    FileObject::Supplied(entry) => entry.workspace_directory().cloned(),
                    _ => None,
                };
                if directory.as_ref().is_some_and(|directory| {
                    !directory.permits(1, (c.p.creds.1, c.p.creds.3), &c.p.groups)
                }) {
                    return Err(Errno(EACCES));
                }
                c.p.set_working_directory(f.path.clone(), directory);
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
        Target::Supplied(..) => Err(Errno(EROFS)),
        Target::Proc(..) | Target::Fd(_) => Err(Errno(EACCES)),
    }
}

/// `mkdirat` (and `mkdir`).
pub fn mkdirat(c: &mut Ctx<'_>, dirfd: i32, path: u64, perm: u32) -> SysResult {
    let bits = perm & 0o7777 & !c.p.file_creation_mask();
    if let Some(files) = c.p.vfs.supplied() {
        let path = supplied_path(c, dirfd, path)?;
        let ids = (c.p.creds.1, c.p.creds.3);
        files.create_workspace_directory(&path, bits, ids, &c.p.groups)?;
        return Ok(0);
    }
    #[cfg(unix)]
    {
        let host = host_target(c, dirfd, path, false)?;
        std::fs::DirBuilder::new().mode(bits).create(&host)?;
        fs::created_mode(&host, bits)?;
        super::notify::created(c, &host, true);
        Ok(0)
    }
    #[cfg(not(unix))]
    {
        Err(Errno(ENOSYS))
    }
}

/// `mknodat` (and `mknod`; `do_mknodat`): a regular file, FIFO, or socket
/// node, or a device node (with `CAP_MKNOD`, which only root has here),
/// its permissions masked by the umask. The type is checked first
/// (`may_mknod`: a directory is `EPERM`, an unknown type `EINVAL`), then the
/// name (`filename_create`: `EEXIST` for an existing one, `ENOENT` for a
/// new one with a trailing slash), then the device privilege. A host that
/// refuses unprivileged socket nodes (macOS) gets one by binding a socket
/// there.
#[cfg(unix)]
pub fn mknodat(c: &mut Ctx<'_>, dirfd: i32, path: u64, perm: u32, dev: u32) -> SysResult {
    use mode::*;
    let kind = perm & S_IFMT;
    match kind {
        0 | S_IFREG | S_IFCHR | S_IFBLK | S_IFIFO | S_IFSOCK => {}
        S_IFDIR => return Err(Errno(EPERM)),
        _ => return Err(Errno(EINVAL)),
    }
    let raw = c.read_cstr_raw(path, fs::PATH_MAX - 1)?;
    let host = host_target(c, dirfd, path, false)?;
    // The last component is looked up without its trailing slashes.
    let bare = host.to_string_lossy().trim_end_matches('/').to_string();
    if std::fs::symlink_metadata(if bare.is_empty() { "/" } else { &bare }).is_ok() {
        return Err(Errno(EEXIST));
    }
    if raw.ends_with(b"/") {
        return Err(Errno(ENOENT));
    }
    let bits = perm & 0o7777 & !c.p.file_creation_mask();
    let host_mode = |t: libc::mode_t| u32::from(t) | bits;
    match kind {
        0 | S_IFREG => {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(bits)
                .open(&host)?;
        }
        S_IFIFO => super::super::host::mknod(&host, host_mode(libc::S_IFIFO), 0, 0)?,
        S_IFSOCK => match super::super::host::mknod(&host, host_mode(libc::S_IFSOCK), 0, 0) {
            Err(Errno(EPERM)) if cfg!(not(target_os = "linux")) => {
                super::super::net::name::socket_node(&host)?;
                std::fs::set_permissions(&host, std::fs::Permissions::from_mode(bits))?;
            }
            r => r?,
        },
        _ => {
            // vfs_mknod: a whiteout (a character device 0:0) needs no
            // privilege; may_create comes first.
            let whiteout = kind == S_IFCHR && dev == 0;
            if !whiteout && c.p.creds.1 != 0 {
                let parent = host.parent().unwrap_or(std::path::Path::new("/"));
                return Err(Errno(
                    match super::super::host::access(parent, 3, true, true) {
                        Err(e) => e.0,
                        Ok(()) => EPERM,
                    },
                ));
            }
            // new_decode_dev.
            let (major, minor) = ((dev & 0xfff00) >> 8, (dev & 0xff) | ((dev >> 12) & 0xfff00));
            let t = if kind == S_IFCHR {
                libc::S_IFCHR
            } else {
                libc::S_IFBLK
            };
            super::super::host::mknod(&host, host_mode(t), major, minor)?;
        }
    }
    fs::created_mode(&host, bits)?;
    super::notify::created(c, &host, false);
    Ok(0)
}

/// `unlinkat` (and `unlink`, `rmdir`).
pub fn unlinkat(c: &mut Ctx<'_>, dirfd: i32, path: u64, flags: u32) -> SysResult {
    if flags & !AT_REMOVEDIR != 0 {
        return Err(Errno(EINVAL));
    }
    if let Some(files) = c.p.vfs.supplied() {
        let path = supplied_path(c, dirfd, path)?;
        let ids = (c.p.creds.1, c.p.creds.3);
        if flags == AT_REMOVEDIR {
            files.remove_workspace_directory(&path, ids, &c.p.groups)?;
        } else {
            files.unlink_workspace_file(&path, ids, &c.p.groups)?;
        }
        return Ok(0);
    }
    #[cfg(not(unix))]
    {
        Err(Errno(ENOSYS))
    }
    #[cfg(unix)]
    {
        let host = host_target(c, dirfd, path, false)?;
        let was = super::notify::before(c, &host);
        if flags & AT_REMOVEDIR != 0 {
            std::fs::remove_dir(&host)?;
        } else {
            // Linux reports EISDIR for unlink(dir); some hosts report EPERM.
            if std::fs::symlink_metadata(&host)?.is_dir() {
                return Err(Errno(EISDIR));
            }
            std::fs::remove_file(&host)?;
        }
        super::notify::removed(c, &host, was);
        Ok(0)
    }
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
    const RENAME_EXCHANGE: u32 = 2;
    if let Some(files) = c.p.vfs.supplied() {
        let how = match flags {
            0 => WorkspaceRename::Replace,
            RENAME_NOREPLACE => WorkspaceRename::Exclusive,
            RENAME_EXCHANGE => WorkspaceRename::Exchange,
            _ => return Err(Errno(EINVAL)),
        };
        let from = supplied_path(c, olddir, old)?;
        let to = supplied_path(c, newdir, new)?;
        files.rename_workspace_entry(&from, &to, (c.p.creds.1, c.p.creds.3), &c.p.groups, how)?;
        return Ok(0);
    }
    if flags & !RENAME_NOREPLACE != 0 {
        return Err(Errno(EINVAL));
    }
    #[cfg(not(unix))]
    {
        Err(Errno(ENOSYS))
    }
    #[cfg(unix)]
    {
        let from = host_target(c, olddir, old, false)?;
        let to = host_target(c, newdir, new, false)?;
        if flags & RENAME_NOREPLACE != 0 && std::fs::symlink_metadata(&to).is_ok() {
            return Err(Errno(EEXIST));
        }
        let moved = super::notify::moving(c, &from);
        let target = super::notify::before(c, &to);
        std::fs::rename(&from, &to)?;
        // vfs_rename: two links of one inode are left as they are, unreported.
        let same = matches!((moved, target), (Some((m, _)), Some((t, _))) if m.key == t.key);
        if !same {
            super::notify::renamed(c, &from, &to, moved, target);
        }
        Ok(0)
    }
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
    let follow = flags & AT_SYMLINK_FOLLOW != 0;
    if let Some(files) = c.p.vfs.supplied() {
        let ids = (c.p.creds.1, c.p.creds.3);
        let allow_empty = if ids.0 == 0 { flags & AT_EMPTY_PATH } else { 0 };
        let source = match resolve(c, olddir, old, allow_empty, follow)? {
            Target::Supplied(entry, _) => entry,
            target => {
                let file = match target {
                    Target::Fd(file) => file,
                    Target::Proc(ProcEntry::Descriptor { file, .. }, _) if follow => file,
                    _ => return Err(Errno(EXDEV)),
                };
                match &file.object {
                    FileObject::Supplied(entry) => entry.clone(),
                    _ => return Err(Errno(EXDEV)),
                }
            }
        };
        let to = supplied_path(c, newdir, new)?;
        files.link_workspace_entry(source, &to, ids, &c.p.groups)?;
        return Ok(0);
    }
    #[cfg(unix)]
    {
        let from = host_target(c, olddir, old, follow)?;
        let to = host_target(c, newdir, new, false)?;
        std::fs::hard_link(&from, &to)?;
        super::notify::linked(c, &to);
        Ok(0)
    }
    #[cfg(not(unix))]
    {
        Err(Errno(ENOSYS))
    }
}

/// `symlinkat` (and `symlink`). The target is stored verbatim.
pub fn symlinkat(c: &mut Ctx<'_>, target: u64, newdir: i32, linkpath: u64) -> SysResult {
    let raw = c.read_cstr_raw(target, fs::PATH_MAX - 1)?;
    if raw.is_empty() {
        return Err(Errno(ENOENT));
    }
    if let Some(files) = c.p.vfs.supplied() {
        let link = supplied_path(c, newdir, linkpath)?;
        let ids = (c.p.creds.1, c.p.creds.3);
        files.create_workspace_symlink(&link, raw, c.p.file_creation_mask(), ids, &c.p.groups)?;
        return Ok(0);
    }
    #[cfg(unix)]
    {
        let target = fs::Vfs::path_str(&raw)?;
        let link = host_target(c, newdir, linkpath, false)?;
        std::os::unix::fs::symlink(target, &link)?;
        super::notify::created(c, &link, false);
        Ok(0)
    }
    #[cfg(not(unix))]
    {
        Err(Errno(ENOSYS))
    }
}

/// `fchmodat`/`fchmodat2` (and `chmod`).
pub fn fchmodat(c: &mut Ctx<'_>, dirfd: i32, path: u64, perm: u32, flags: u32) -> SysResult {
    #[cfg(not(unix))]
    if c.p.vfs.supplied().is_none() {
        return Err(Errno(ENOSYS));
    }
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return Err(Errno(EINVAL));
    }
    let follow = flags & AT_SYMLINK_NOFOLLOW == 0;
    match resolve(c, dirfd, path, flags, follow)? {
        Target::Supplied(entry, _) => chmod_supplied(c, &entry, perm),
        Target::Proc(ProcEntry::Descriptor { file, .. }, _) if follow => match &file.object {
            FileObject::Supplied(entry) => chmod_open_workspace(c, &file, entry, perm),
            _ => Err(Errno(EPERM)),
        },
        Target::Fd(f) => match &f.object {
            FileObject::Supplied(entry) => chmod_open_workspace(c, &f, entry, perm),
            _ => chmod_host_path(c, f.host_path.as_deref().ok_or(Errno(EBADF))?, perm, follow),
        },
        Target::Host { host, .. } => chmod_host_path(c, &host, perm, follow),
        Target::Proc(..) => Err(Errno(EPERM)),
    }
}

fn chmod_supplied(c: &Ctx<'_>, entry: &Entry, perm: u32) -> SysResult {
    if entry.workspace_mode().is_some() && entry.link_target().is_some() {
        return Err(Errno(EOPNOTSUPP));
    }
    entry.set_workspace_mode(perm, (c.p.creds.1, c.p.creds.3), &c.p.groups)?;
    Ok(0)
}

fn chmod_open_workspace(c: &Ctx<'_>, file: &OpenFile, entry: &Entry, perm: u32) -> SysResult {
    let _operation = file.lock_workspace_memfd()?;
    if let Some(memfd) = &file.memfd {
        memfd.check_mode(entry.workspace_mode().expect("workspace memfd"), perm)?;
    }
    chmod_supplied(c, entry, perm)
}

fn chmod_host_path(c: &Ctx<'_>, host: &std::path::Path, perm: u32, follow: bool) -> SysResult {
    #[cfg(unix)]
    {
        if !follow && std::fs::symlink_metadata(host)?.file_type().is_symlink() {
            return Err(Errno(EOPNOTSUPP));
        }
        std::fs::set_permissions(host, std::fs::Permissions::from_mode(perm & 0o7777))?;
        super::notify::changed(c, host, follow, IN_ATTRIB);
        Ok(0)
    }
    #[cfg(not(unix))]
    {
        let _ = (c, host, perm, follow);
        Err(Errno(ENOSYS))
    }
}

/// `fchmod`.
pub fn fchmod(c: &mut Ctx<'_>, fd: i32, perm: u32) -> SysResult {
    #[cfg(not(unix))]
    if c.p.vfs.supplied().is_none() {
        return Err(Errno(ENOSYS));
    }
    let file = c.p.fds.file(fd)?;
    match &file.object {
        #[cfg(unix)]
        FileObject::Host(f) => {
            if let Some(m) = &file.memfd {
                m.check_mode(f.metadata()?.permissions().mode(), perm)?;
            }
            f.set_permissions(std::fs::Permissions::from_mode(perm & 0o7777))?;
            super::notify::changed_file(&file, IN_ATTRIB);
            Ok(0)
        }
        FileObject::Supplied(entry) => {
            if file.flags() & O_PATH != 0 {
                return Err(Errno(EBADF));
            }
            chmod_open_workspace(c, &file, entry, perm)
        }
        _ if file.supplied_stat.is_some() => Err(Errno(EROFS)),
        FileObject::PathOnly => Err(Errno(EBADF)),
        // anon_inode_setattr (pidfs_setattr calls it too).
        FileObject::Anon(_) => Err(Errno(EOPNOTSUPP)),
        FileObject::Mqueue(h) => super::mqueue::chmod(c, h, perm),
        _ => Ok(0),
    }
}

fn opt_id(id: u32) -> Option<u32> {
    (id != u32::MAX).then_some(id)
}

/// `fchownat` (and `chown`, `lchown`).
#[cfg(unix)]
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
        Target::Supplied(..) => return Err(Errno(EROFS)),
        Target::Proc(..) => return Err(Errno(EPERM)),
    };
    if follow {
        std::os::unix::fs::chown(&host, opt_id(uid), opt_id(gid))?;
    } else {
        std::os::unix::fs::lchown(&host, opt_id(uid), opt_id(gid))?;
    }
    super::notify::changed(c, &host, follow, owner_mask(uid, gid));
    Ok(0)
}

/// `fsnotify_change`'s mask for an ownership change: `ATTR_UID` or
/// `ATTR_GID` are an attribute change; neither is nothing.
fn owner_mask(uid: u32, gid: u32) -> u32 {
    if opt_id(uid).is_some() || opt_id(gid).is_some() {
        IN_ATTRIB
    } else {
        0
    }
}

/// `fchown`.
#[cfg(unix)]
pub fn fchown(c: &mut Ctx<'_>, fd: i32, uid: u32, gid: u32) -> SysResult {
    let file = c.p.fds.file(fd)?;
    match &file.object {
        FileObject::Host(f) => {
            std::os::unix::fs::fchown(f, opt_id(uid), opt_id(gid))?;
            super::notify::changed_file(&file, owner_mask(uid, gid));
            Ok(0)
        }
        FileObject::PathOnly => Err(Errno(EBADF)),
        // anon_inode_setattr.
        FileObject::Anon(_) => Err(Errno(EOPNOTSUPP)),
        FileObject::Mqueue(h) => super::mqueue::chown(c, h, uid, gid),
        _ => Ok(0),
    }
}

/// `truncate`.
#[cfg(unix)]
pub fn truncate(c: &mut Ctx<'_>, path: u64, len: i64) -> SysResult {
    if len < 0 {
        return Err(Errno(EINVAL));
    }
    let host = host_target(c, AT_FDCWD, path, true)?;
    let m = std::fs::metadata(&host)?;
    if m.is_dir() {
        return Err(Errno(EISDIR));
    }
    // By path, as the guest asked: an open of the file would be one more
    // thing a host watcher sees.
    let p =
        std::ffi::CString::new(host.as_os_str().as_encoded_bytes()).map_err(|_| Errno(EINVAL))?;
    // SAFETY: a NUL-terminated path and a length.
    if unsafe { libc::truncate(p.as_ptr(), len) } != 0 {
        return Err(Errno::from(std::io::Error::last_os_error()));
    }
    use std::os::unix::fs::MetadataExt;
    let identity = crate::user::mm::SourceIdentity {
        dev: m.dev(),
        ino: m.ino(),
    };
    c.p.space.truncated(identity, len as u64);
    super::notify::changed(c, &host, true, IN_MODIFY);
    Ok(0)
}

/// `EXT4_SUPER_MAGIC`, reported for host file systems.
const EXT4_SUPER_MAGIC: u64 = 0xEF53;
/// `PROC_SUPER_MAGIC`.
const PROC_SUPER_MAGIC: u64 = 0x9fa0;
/// `RAMFS_MAGIC` (`include/uapi/linux/magic.h`), mounted read-only here.
const RAMFS_MAGIC: u64 = 0x8584_58f6;
/// `PIPEFS_MAGIC` for guest-owned anonymous pipes.
const PIPEFS_MAGIC: u64 = 0x5049_5045;
/// `ST_VALID` (`f_flags` is meaningful).
const ST_VALID: u64 = 0x20;

/// `struct kstatfs` of a file system of magic `kind`.
#[cfg(unix)]
fn kstatfs(kind: u64, st: &super::super::host::FsStats) -> Kstatfs {
    Kstatfs {
        kind,
        bsize: st.bsize,
        blocks: st.blocks,
        bfree: st.bfree,
        bavail: st.bavail,
        files: st.files,
        ffree: st.ffree,
        fsid: [0, 0],
        namelen: st.namemax,
        frsize: st.frsize,
        flags: ST_VALID | (st.flags & 0x3),
    }
}

/// The statistics of a synthesized file system.
fn synthetic_fs(kind: u64) -> Kstatfs {
    Kstatfs {
        kind,
        bsize: 4096,
        frsize: 4096,
        namelen: 255,
        flags: ST_VALID,
        ..Default::default()
    }
}

fn supplied_statfs(
    c: &Ctx<'_>,
    entry: Option<&crate::user::supplied_fs::Entry>,
) -> Result<Kstatfs, Errno> {
    let mut stat = synthetic_fs(RAMFS_MAGIC);
    if !entry.is_some_and(|entry| entry.workspace_mode().is_some()) {
        stat.flags |= 1; // ST_RDONLY
        return Ok(stat);
    }
    let capacity = c.p.vfs.supplied().ok_or(Errno(EIO))?.workspace_capacity()?;
    stat.blocks = capacity.bytes_total / stat.bsize;
    stat.bfree = capacity.bytes_available / stat.bsize;
    stat.bavail = stat.bfree;
    stat.files = capacity.nodes_total;
    stat.ffree = capacity.nodes_available;
    stat.fsid = [0x524158, 0];
    Ok(stat)
}

/// `user_statfs`: the statistics of the file system holding `path`.
pub(super) fn statfs_path(c: &mut Ctx<'_>, path: u64) -> Result<Kstatfs, Errno> {
    match resolve(c, AT_FDCWD, path, 0, true)? {
        Target::Supplied(entry, _) => supplied_statfs(c, Some(&entry)),
        Target::Proc(ProcEntry::Descriptor { file, .. }, _)
            if matches!(file.object, FileObject::GuestPipe(_)) =>
        {
            Ok(synthetic_fs(PIPEFS_MAGIC))
        }
        Target::Proc(..) => Ok(synthetic_fs(PROC_SUPER_MAGIC)),
        #[cfg(not(unix))]
        Target::Host { .. } => Err(Errno(EPERM)),
        #[cfg(unix)]
        Target::Host { host, .. } => Ok(kstatfs(
            EXT4_SUPER_MAGIC,
            &super::super::host::statvfs(&host)?,
        )),
        Target::Fd(_) => Err(Errno(ENOENT)),
    }
}

/// `fd_statfs`: the statistics of the file system holding `fd`'s file.
pub(super) fn statfs_fd(c: &Ctx<'_>, fd: i32) -> Result<Kstatfs, Errno> {
    let file = c.p.fds.file(fd)?;
    if file.supplied_stat.is_some() {
        let entry = match &file.object {
            FileObject::Supplied(entry) => Some(entry),
            _ => None,
        };
        return supplied_statfs(c, entry);
    }
    Ok(match &file.host_path {
        #[cfg(unix)]
        Some(h) => kstatfs(EXT4_SUPER_MAGIC, &super::super::host::statvfs(h)?),
        #[cfg(not(unix))]
        Some(_) => return Err(Errno(EPERM)),
        None if super::pidfd::target_of(&file).is_some() => {
            synthetic_fs(super::pidfd::PID_FS_MAGIC)
        }
        None if matches!(file.object, FileObject::GuestPipe(_)) => synthetic_fs(PIPEFS_MAGIC),
        None => synthetic_fs(PROC_SUPER_MAGIC),
    })
}

/// `statfs` (`struct statfs`, 120 bytes on every 64-bit ABI).
pub fn statfs(c: &mut Ctx<'_>, path: u64, buf: u64) -> SysResult {
    let k = statfs_path(c, path)?;
    c.write_mem(buf, &k.encode())?;
    Ok(0)
}

/// `fstatfs`.
pub fn fstatfs(c: &mut Ctx<'_>, fd: i32, buf: u64) -> SysResult {
    let k = statfs_fd(c, fd)?;
    c.write_mem(buf, &k.encode())?;
    Ok(0)
}

/// `umask`.
pub fn umask(c: &mut Ctx<'_>, mask: u32) -> SysResult {
    Ok(u64::from(c.p.set_file_creation_mask(mask & 0o777)))
}
