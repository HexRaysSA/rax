//! inotify (`fs/notify/inotify/inotify_user.c`): `inotify_init1`,
//! `inotify_add_watch`, and `inotify_rm_watch`, and an instance's `read`,
//! `poll`, `ioctl`, and `fdinfo`, over the backend the configuration
//! chose ([`Backend`](super::super::fsnotify::Backend)).
//!
//! An instance has only a `read` operation, so `readv` reads each vector
//! in turn (`do_loop_readv_writev`), stopping at one that comes back
//! short. A vector after the first that finds nothing queued ends the call
//! with what the earlier ones read, where the kernel would sleep in it.

use std::sync::Arc;

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::abi::open::*;
use super::super::fs::anon::Anon;
use super::super::fs::fd::{FileObject, FileType, OpenFile};
use super::super::fsnotify::bits::*;
use super::super::fsnotify::hub::Read;
use super::super::fsnotify::{Instance, Key, Obj};
use super::super::fsnotify::{sys, tempfile_path::TempPath};
use super::super::procfs::ProcEntry;
use super::super::wait::Wait;
use super::events::{copy_out, wait_or};
use super::io::install;
use super::path::{Target, resolve};
use super::ready::Polled;
use super::{Ctx, SysResult};

/// `AT_FDCWD`.
const AT_FDCWD: i32 = -100;
/// `FIONREAD`.
const FIONREAD: u32 = 0x541B;
/// The device synthesized `/proc` entries report.
const PROC_DEV: u64 = 0x16;
/// `INOTIFY_IOC_SETNEXTWD`: `_IOW('I', 0, __s32)`.
const INOTIFY_IOC_SETNEXTWD: u32 = 0x4004_4900;

/// An `ioctl` of a host instance with an integer argument.
fn host_ioctl(fd: &std::os::fd::OwnedFd, req: u32, arg: u64) -> Result<(), Errno> {
    use std::os::fd::AsRawFd;
    // SAFETY: a descriptor, a request, and an integer argument; the
    // request reads no memory.
    if unsafe { libc::ioctl(fd.as_raw_fd(), req as _, arg as libc::c_ulong) } < 0 {
        return Err(Errno::from(std::io::Error::last_os_error()));
    }
    Ok(())
}

/// `inotify_init1` (`inotify_init` is flags 0).
pub fn init1(c: &mut Ctx<'_>, flags: u32) -> SysResult {
    if flags & !(O_CLOEXEC | O_NONBLOCK) != 0 {
        return Err(Errno(EINVAL));
    }
    let inst = match &c.p.fsnotify {
        Some(hub) => Instance::Emulated(hub.create(c.p.creds.1)?),
        None => host_instance()?,
    };
    // anon_inode_getfd("inotify", ..., O_RDONLY | flags).
    let file = OpenFile::new(
        FileObject::Anon(Anon::Inotify(inst)),
        FileType::Anon,
        "anon_inode:inotify",
        None,
        O_RDONLY | (flags & O_NONBLOCK),
    );
    install(c, file, flags & O_CLOEXEC != 0)
}

#[cfg(target_os = "linux")]
fn host_instance() -> Result<Instance, Errno> {
    Ok(Instance::Host {
        fd: sys::host::init(true)?,
        stand_ins: Default::default(),
    })
}

/// The emulated backend's namespace could not be opened: a kernel
/// without inotify.
#[cfg(not(target_os = "linux"))]
fn host_instance() -> Result<Instance, Errno> {
    Err(Errno(ENOSYS))
}

/// The instance descriptor `fd` refers to: `EBADF`, or `EINVAL` for
/// another kind of file.
fn instance(c: &Ctx<'_>, fd: i32) -> Result<Arc<OpenFile>, Errno> {
    let file = c.p.fds.file(fd)?;
    if !matches!(file.object, FileObject::Anon(Anon::Inotify(_))) {
        return Err(Errno(EINVAL));
    }
    Ok(file)
}

fn inst(file: &OpenFile) -> &Instance {
    let FileObject::Anon(Anon::Inotify(i)) = &file.object else {
        unreachable!("checked by `instance`");
    };
    i
}

/// A synthesized entry's inode: one per path.
fn proc_key(guest: &str) -> Key {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    guest.hash(&mut h);
    Key {
        dev: PROC_DEV,
        ino: h.finish() | 1 << 63,
    }
}

/// The inode of a host file (not following a final symbolic link unless
/// `follow`).
pub fn host_obj(path: &std::path::Path, follow: bool) -> Result<Obj, Errno> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let m = if follow {
        std::fs::metadata(path)?
    } else {
        std::fs::symlink_metadata(path)?
    };
    let t = m.file_type();
    Ok(Obj {
        key: Key {
            dev: m.dev(),
            ino: m.ino(),
        },
        dir: t.is_dir(),
        special: t.is_fifo() || t.is_socket() || t.is_char_device() || t.is_block_device(),
    })
}

/// `inotify_add_watch`.
pub fn add_watch(c: &mut Ctx<'_>, fd: i32, path: u64, mask: u32) -> SysResult {
    if mask & !ALL_INOTIFY_BITS != 0 || mask & ALL_INOTIFY_BITS == 0 {
        return Err(Errno(EINVAL));
    }
    let file = c.p.fds.file(fd)?;
    if mask & IN_MASK_ADD != 0 && mask & IN_MASK_CREATE != 0 {
        return Err(Errno(EINVAL));
    }
    let FileObject::Anon(Anon::Inotify(inst)) = &file.object else {
        return Err(Errno(EINVAL));
    };
    // inotify_find_inode: LOOKUP_FOLLOW unless IN_DONT_FOLLOW,
    // LOOKUP_DIRECTORY with IN_ONLYDIR, then MAY_READ.
    let follow = mask & IN_DONT_FOLLOW == 0;
    let target = resolve(c, AT_FDCWD, path, 0, follow)?;
    let (obj, host, guest) = match target {
        Target::Host { guest, host } => (host_obj(&host, follow)?, Some(host), guest),
        Target::Proc(e, guest) => {
            let dir = matches!(e, ProcEntry::Dir(_));
            let obj = Obj {
                key: proc_key(&guest),
                dir,
                special: false,
            };
            (obj, None, guest)
        }
        Target::Fd(_) => return Err(Errno(ENOENT)),
    };
    if mask & IN_ONLYDIR != 0 && !obj.dir {
        return Err(Errno(ENOTDIR));
    }
    if let Some(h) = &host {
        super::super::host::access(h, libc::R_OK as u32, true, follow)?;
    }
    let wd = match inst {
        Instance::Emulated(h) => h.add_watch(obj, mask, c.p.creds.1)?,
        Instance::Host { fd, stand_ins } => host_add_watch(fd, stand_ins, host, &guest, mask)?,
    };
    Ok(wd as u64)
}

/// A host instance's watch: the host file, or a stand-in for a
/// synthesized entry (which reports nothing but its removal).
#[cfg(target_os = "linux")]
fn host_add_watch(
    fd: &std::os::fd::OwnedFd,
    stand_ins: &std::sync::Mutex<Vec<(String, TempPath)>>,
    host: Option<std::path::PathBuf>,
    guest: &str,
    mask: u32,
) -> Result<i32, Errno> {
    let path = match host {
        Some(h) => h,
        None => {
            let mut s = stand_ins.lock().unwrap();
            match s.iter().find(|(g, _)| g == guest) {
                Some((_, p)) => p.0.clone(),
                None => {
                    let p = std::env::temp_dir().join(format!(
                        "rax-user-inotify-{}-{}",
                        std::process::id(),
                        proc_key(guest).ino
                    ));
                    std::fs::write(&p, b"")?;
                    s.push((guest.to_string(), TempPath(p.clone())));
                    p
                }
            }
        }
    };
    // The resolution above already applied IN_DONT_FOLLOW and IN_ONLYDIR
    // to the guest's path; the host's own checks see the same file.
    sys::host::add_watch(fd, &path, mask)
}

#[cfg(not(target_os = "linux"))]
fn host_add_watch(
    _: &std::os::fd::OwnedFd,
    _: &std::sync::Mutex<Vec<(String, TempPath)>>,
    _: Option<std::path::PathBuf>,
    _: &str,
    _: u32,
) -> Result<i32, Errno> {
    Err(Errno(ENOSYS))
}

/// `inotify_rm_watch`.
pub fn rm_watch(c: &mut Ctx<'_>, fd: i32, wd: i32) -> SysResult {
    let file = instance(c, fd)?;
    match inst(&file) {
        Instance::Emulated(h) => h.rm_watch(wd)?,
        Instance::Host { fd, .. } => host_rm_watch(fd, wd)?,
    }
    Ok(0)
}

#[cfg(target_os = "linux")]
fn host_rm_watch(fd: &std::os::fd::OwnedFd, wd: i32) -> Result<(), Errno> {
    sys::host::rm_watch(fd, wd)
}

#[cfg(not(target_os = "linux"))]
fn host_rm_watch(_: &std::os::fd::OwnedFd, _: i32) -> Result<(), Errno> {
    Err(Errno(ENOSYS))
}

/// One `inotify_read` of `count` bytes: the records, or `None` when
/// nothing is queued.
fn read_once(inst: &Instance, count: usize) -> Result<Option<Vec<u8>>, Errno> {
    match inst {
        Instance::Emulated(h) => match h.read(count)? {
            Read::Events(b) => Ok(Some(b)),
            Read::TooSmall => Err(Errno(EINVAL)),
            Read::Empty => Ok(None),
        },
        Instance::Host { fd, .. } => {
            use std::os::fd::AsRawFd;
            let mut buf = vec![0u8; count];
            // SAFETY: a descriptor and a writable buffer of `count` bytes.
            let n = unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), count) };
            if n < 0 {
                let e = std::io::Error::last_os_error();
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    return Ok(None);
                }
                return Err(Errno::from(e));
            }
            buf.truncate(n as usize);
            Ok(Some(buf))
        }
    }
}

/// The descriptor that is readable while events are queued.
fn level_fd(inst: &Instance) -> Result<i32, Errno> {
    use std::os::fd::AsRawFd;
    match inst {
        Instance::Emulated(h) => h.level_fd(),
        Instance::Host { fd, .. } => Ok(fd.as_raw_fd()),
    }
}

/// `read`/`readv` of an instance into `vecs`.
pub fn read(c: &mut Ctx<'_>, file: &OpenFile, vecs: &[(u64, u64)]) -> SysResult {
    let inst = inst(file);
    let mut done = 0u64;
    for &(base, len) in vecs {
        let got = match read_once(inst, len as usize) {
            Ok(Some(b)) => b,
            Ok(None) if done == 0 => {
                return Err(wait_or(c, file, Wait::fd(level_fd(inst)?, true, false)));
            }
            Ok(None) => break,
            Err(e) if done == 0 => return Err(e),
            Err(_) => break,
        };
        // The events are taken even if the copy then faults.
        if copy_out(c, &[(base, len)], 0, &got) != got.len() as u64 {
            return if done == 0 {
                Err(Errno(EFAULT))
            } else {
                Ok(done)
            };
        }
        done += got.len() as u64;
        if (got.len() as u64) < len {
            break;
        }
    }
    Ok(done)
}

/// `inotify_poll`: readable while events are queued.
pub fn poll(inst: &Instance, events: u32) -> (Polled, Wait) {
    use super::ready::ev::*;
    let mut p = Polled::default();
    let mut wait = Wait::event();
    let ready = match inst {
        Instance::Emulated(h) => h.ready().unwrap_or(false),
        Instance::Host { fd, .. } => {
            use std::os::fd::AsRawFd;
            super::super::host::poll(&[(fd.as_raw_fd(), true, false)], 0)
                .is_ok_and(|r| r[0].readable)
        }
    };
    if ready {
        p.mask |= IN | RDNORM;
        p.level = 1;
    }
    if events & (IN | RDNORM) != 0
        && let Ok(fd) = level_fd(inst)
    {
        wait.fds.push((fd, true, false));
    }
    (p, wait)
}

/// `inotify_ioctl`: `FIONREAD`, and `INOTIFY_IOC_SETNEXTWD`
/// (`CONFIG_CHECKPOINT_RESTORE`): the next watch descriptor is sought from
/// one in `1..=INT_MAX`.
pub fn ioctl(c: &mut Ctx<'_>, inst: &Instance, req: u32, arg: u64) -> SysResult {
    if req == INOTIFY_IOC_SETNEXTWD {
        if !(1..=i32::MAX as u64).contains(&arg) {
            return Err(Errno(EINVAL));
        }
        match inst {
            Instance::Emulated(h) => h.set_next_wd(arg as i32)?,
            Instance::Host { fd, .. } => host_ioctl(fd, req, arg)?,
        }
        return Ok(0);
    }
    if req != FIONREAD {
        return Err(Errno(ENOTTY));
    }
    let n = match inst {
        Instance::Emulated(h) => h.pending_bytes()?,
        Instance::Host { fd, .. } => super::super::host::bytes_readable(fd)? as u64,
    };
    c.write_u32(arg, n as u32)?;
    Ok(0)
}

/// `inotify_show_fdinfo`: a line per watch, newest first. The emulated
/// backend shows no file handle (as for a file system that cannot encode
/// one); a host instance shows the host's lines.
pub fn fdinfo(inst: &Instance) -> String {
    match inst {
        Instance::Emulated(h) => {
            let mut s = String::new();
            for (wd, key, mask) in h.watches().unwrap_or_default() {
                let (major, minor) = super::super::fs::host_dev(key.dev);
                let sdev = if key.dev == PROC_DEV {
                    PROC_DEV as u32
                } else {
                    major << 20 | minor
                };
                s.push_str(&format!(
                    "inotify wd:{wd:x} ino:{:x} sdev:{sdev:x} mask:{mask:x} ignored_mask:0 \n",
                    key.ino
                ));
            }
            s
        }
        Instance::Host { fd, .. } => {
            use std::os::fd::AsRawFd;
            std::fs::read_to_string(format!("/proc/self/fdinfo/{}", fd.as_raw_fd()))
                .unwrap_or_default()
                .lines()
                .filter(|l| l.starts_with("inotify "))
                .map(|l| format!("{l}\n"))
                .collect()
        }
    }
}
