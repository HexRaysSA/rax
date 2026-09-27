//! `posix_spawn` (`bsd/kern/kern_exec.c`: `posix_spawn`,
//! `exec_handle_file_actions`, `exec_handle_port_actions`; the layouts of
//! `bsd/sys/spawn_internal.h`).
//!
//! A spawn is a fork and an exec in one call: the child starts as a
//! forked copy of the caller, its file actions and port actions are
//! applied, and it runs the new image with the spawn attributes' signal
//! mask and defaults, process group, and session. With
//! `POSIX_SPAWN_SETEXEC` there is no child: the caller runs the image, as
//! `execve` with options.
//!
//! Everything that can fail before the point of no return is done in the
//! caller before anything is forked, on a copy of its descriptor table and
//! with a directory descriptor standing in for a changed working
//! directory, so that a failed spawn (`posix_spawnp` tries every `PATH`
//! entry) creates no child at all, as XNU's reaps its half-made child
//! without a trace. The new image is built in the caller too; the host
//! fork then carries it into the child, which takes it up at once. Only
//! setting the process group or session can fail in the child: it
//! reports the error through a pipe, the caller reaps it, and its
//! `SIGCHLD` never reaches the guest.

use std::collections::BTreeSet;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use std::time::Instant;

use super::image::{self, Binprefs, Dir, NBINPREFS};
use super::{Swap, args, build, build_errno, carry, exec_task, swap_or_kill, without_kqueues};
use crate::user::darwin::abi::Errno;
use crate::user::darwin::arch::{Rv, SysResult};
use crate::user::darwin::fd::{FdTable, OpenFile};
use crate::user::darwin::host::{self, check};
use crate::user::darwin::io::O_CLOEXEC;
use crate::user::darwin::mach::ipc::{MACH_PORT_DEAD, MACH_PORT_NULL, Port};
use crate::user::darwin::mach::task::{EXC_TYPES_COUNT, TaskState, special};
use crate::user::darwin::process::{self, Proc};
use crate::user::darwin::signal::{self, SigAction};
use crate::user::darwin::syscall::Ctx;
use crate::user::darwin::syscall::bsd::path::normalize;
use crate::user::darwin::syscall::util::MAXPATHLEN;

/// `posix_spawnattr` flags (`bsd/sys/spawn.h`).
pub mod flag {
    pub const RESETIDS: u16 = 0x0001;
    pub const SETPGROUP: u16 = 0x0002;
    pub const SETSIGDEF: u16 = 0x0004;
    pub const SETSIGMASK: u16 = 0x0008;
    pub const SETEXEC: u16 = 0x0040;
    pub const START_SUSPENDED: u16 = 0x0080;
    pub const SETSID: u16 = 0x0400;
    pub const CLOEXEC_DEFAULT: u16 = 0x4000;
}

/// `sizeof(struct _posix_spawn_args_desc)` (18 64-bit words).
const DESC_SIZE: usize = 144;
/// `offsetof(struct _posix_spawnattr, psa_ports)`: what the kernel copies.
const ATTR_SIZE: usize = 192;
/// `sizeof(struct _posix_spawn_file_actions)`.
const PSFA_HEADER: u64 = 8;
/// `sizeof(_psfa_action_t)`.
const PSFA_ACTION: u64 = 1040;
/// `sizeof(struct _posix_spawn_port_actions)`.
const PSPA_HEADER: u64 = 8;
/// `sizeof(_ps_port_action_t)`.
const PSPA_ACTION: u64 = 24;
/// `sizeof(struct _posix_spawn_persona_info)`.
const PERSONA_INFO_SIZE: u64 = 88;
/// `sizeof(struct _posix_spawn_posix_cred_info)`.
const POSIX_CRED_INFO_SIZE: u64 = 340;
/// `sizeof(struct _posix_spawn_coalition_info)`.
const COALITION_INFO_SIZE: u64 = 48;
/// `POSIX_SPAWN_PROC_TYPE_MASK` and `POSIX_SPAWN_PROC_TYPE_DRIVER`.
const PROC_TYPE_MASK: i32 = 0xf00;
const PROC_TYPE_DRIVER: i32 = 0x700;
/// `TASK_PORT_REGISTER_MAX`, `TASK_MAX_WATCHPORT_COUNT`.
const TASK_PORT_REGISTER_MAX: u32 = 3;
const TASK_MAX_WATCHPORT_COUNT: u32 = 128;

/// `PS_ACTION_SIZE`: a header and `count` entries (0 on overflow).
fn action_size(count: i32, header: u64, entry: u64) -> u64 {
    (count as i64 as u64)
        .checked_mul(entry)
        .and_then(|n| n.checked_add(header))
        .unwrap_or(0)
}

/// `struct _posix_spawn_args_desc`.
#[derive(Clone, Copy, Debug, Default)]
struct Desc {
    attr_size: u64,
    attrp: u64,
    file_actions_size: u64,
    file_actions: u64,
    port_actions_size: u64,
    port_actions: u64,
    coal_info_size: u64,
    coal_info: u64,
    persona_info_size: u64,
    persona_info: u64,
    posix_cred_info_size: u64,
    posix_cred_info: u64,
}

impl Desc {
    fn read(ctx: &Ctx<'_>, addr: u64) -> Result<Desc, Errno> {
        let b = ctx.read(addr, DESC_SIZE)?;
        let w = |i: usize| u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().expect("8 bytes"));
        Ok(Desc {
            attr_size: w(0),
            attrp: w(1),
            file_actions_size: w(2),
            file_actions: w(3),
            port_actions_size: w(4),
            port_actions: w(5),
            // mac_extensions (6, 7): no MAC policy looks at them.
            coal_info_size: w(8),
            coal_info: w(9),
            persona_info_size: w(10),
            persona_info: w(11),
            posix_cred_info_size: w(12),
            posix_cred_info: w(13),
        })
    }
}

/// The spawn attributes the emulation acts on (`struct _posix_spawnattr`).
#[derive(Clone, Copy, Debug, Default)]
struct Attrs {
    flags: u16,
    sigdefault: u32,
    sigmask: u32,
    pgroup: i32,
    apptype: i32,
    binprefs: Binprefs,
}

impl Attrs {
    fn parse(b: &[u8]) -> Attrs {
        let u32_at = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().expect("4 bytes"));
        let mut binprefs = Binprefs::default();
        for i in 0..NBINPREFS {
            binprefs.cpu[i] = u32_at(16 + 4 * i);
            binprefs.sub[i] = u32_at(112 + 4 * i);
        }
        Attrs {
            flags: u16::from_le_bytes([b[0], b[1]]),
            sigdefault: u32_at(4),
            sigmask: u32_at(8),
            pgroup: u32_at(12) as i32,
            apptype: u32_at(36) as i32,
            binprefs,
        }
    }
}

/// A file action (`_psfa_action_t`).
#[derive(Clone, Debug, PartialEq, Eq)]
enum FileAction {
    Open {
        fd: i32,
        oflag: u32,
        mode: u32,
        path: Result<Vec<u8>, Errno>,
    },
    Close(i32),
    Dup2(i32, i32),
    Inherit(i32),
    FileportDup2(u32, i32),
    Chdir(Result<Vec<u8>, Errno>),
    Fchdir(i32),
    Unknown,
}

/// A path in a fixed kernel buffer: up to its NUL (`ENAMETOOLONG`
/// without one).
fn fixed_path(b: &[u8]) -> Result<Vec<u8>, Errno> {
    let b = &b[..b.len().min(MAXPATHLEN)];
    b.iter()
        .position(|&c| c == 0)
        .map(|n| b[..n].to_vec())
        .ok_or(Errno::ENAMETOOLONG)
}

impl FileAction {
    fn parse(e: &[u8]) -> FileAction {
        let i32_at = |o: usize| i32::from_le_bytes(e[o..o + 4].try_into().expect("4 bytes"));
        let fd = i32_at(4);
        match i32_at(0) {
            0 => FileAction::Open {
                fd,
                oflag: i32_at(8) as u32,
                mode: u32::from(u16::from_le_bytes([e[12], e[13]])),
                path: fixed_path(&e[14..]),
            },
            1 => FileAction::Close(fd),
            2 => FileAction::Dup2(fd, i32_at(8)),
            3 => FileAction::Inherit(fd),
            4 => FileAction::FileportDup2(fd as u32, i32_at(8)),
            5 => FileAction::Chdir(fixed_path(&e[8..])),
            6 => FileAction::Fchdir(fd),
            _ => FileAction::Unknown,
        }
    }

    /// The descriptor `POSIX_SPAWN_CLOEXEC_DEFAULT` keeps for this action.
    fn inherited(&self) -> Option<i32> {
        match *self {
            FileAction::Open { fd, .. } | FileAction::Inherit(fd) => Some(fd),
            FileAction::Dup2(_, to) | FileAction::FileportDup2(_, to) => Some(to),
            _ => None,
        }
    }
}

/// Reads the file actions, checking their size against their count and
/// against `RLIMIT_NOFILE` entries.
fn read_file_actions(ctx: &Ctx<'_>, d: &Desc) -> Result<Vec<FileAction>, Errno> {
    let nofile = ctx.proc.rlimits[8].0.min(i32::MAX as u64) as i32;
    let max = action_size(nofile, PSFA_HEADER, PSFA_ACTION);
    let size = d.file_actions_size;
    if size < action_size(1, PSFA_HEADER, PSFA_ACTION) || max == 0 || size > max {
        return Err(Errno::EINVAL);
    }
    let b = ctx.read(d.file_actions, size as usize)?;
    let count = i32::from_le_bytes(b[4..8].try_into().expect("4 bytes"));
    let want = action_size(count, PSFA_HEADER, PSFA_ACTION);
    if want == 0 || want != size {
        return Err(Errno::EINVAL);
    }
    Ok((0..count as usize)
        .map(|i| {
            let at = (PSFA_HEADER + i as u64 * PSFA_ACTION) as usize;
            FileAction::parse(&b[at..at + PSFA_ACTION as usize])
        })
        .collect())
}

/// A port action (`_ps_port_action_t`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PortAction {
    kind: u32,
    mask: u32,
    port: u32,
    behavior: i32,
    flavor: i32,
    which: i32,
}

/// `pspa_t`.
mod pspa {
    pub const SPECIAL: u32 = 0;
    pub const EXCEPTION: u32 = 1;
    pub const AU_SESSION: u32 = 2;
    pub const IMP_WATCHPORTS: u32 = 3;
    pub const REGISTERED_PORTS: u32 = 4;
    pub const PTRAUTH_TASK_PORT: u32 = 5;
}

/// Reads the port actions (at most a page of them).
fn read_port_actions(ctx: &Ctx<'_>, d: &Desc) -> Result<Vec<PortAction>, Errno> {
    let size = d.port_actions_size;
    if size < action_size(1, PSPA_HEADER, PSPA_ACTION) || size > ctx.proc.abi.page_size() {
        return Err(Errno::EINVAL);
    }
    let b = ctx.read(d.port_actions, size as usize)?;
    let count = i32::from_le_bytes(b[4..8].try_into().expect("4 bytes"));
    let want = action_size(count, PSPA_HEADER, PSPA_ACTION);
    if want == 0 || want != size {
        return Err(Errno::EINVAL);
    }
    Ok((0..count as usize)
        .map(|i| {
            let at = (PSPA_HEADER + i as u64 * PSPA_ACTION) as usize;
            let w = |o: usize| u32::from_le_bytes(b[at + o..at + o + 4].try_into().expect("4"));
            PortAction {
                kind: w(0),
                mask: w(4),
                port: w(8),
                behavior: w(12) as i32,
                flavor: w(16) as i32,
                which: w(20) as i32,
            }
        })
        .collect())
}

/// The child's descriptor table and working directory while the file
/// actions run.
struct Scratch {
    fds: FdTable,
    /// The guest working directory.
    cwd: Vec<u8>,
    /// The host directory standing for it, once an action changed it.
    dir: Option<OwnedFd>,
    /// `UF_INHERIT` marks (`POSIX_SPAWN_CLOEXEC_DEFAULT`).
    inherit: Option<BTreeSet<i32>>,
}

impl Scratch {
    fn dir(&self) -> Dir {
        self.dir
            .as_ref()
            .map_or(Dir::Cwd, |d| Dir::Fd(d.as_raw_fd()))
    }

    /// The guest path `path` names from the working directory.
    fn absolute(&self, path: &[u8]) -> Vec<u8> {
        if path.first() == Some(&b'/') {
            return normalize(path);
        }
        let mut p = self.cwd.clone();
        p.push(b'/');
        p.extend_from_slice(path);
        normalize(&p)
    }
}

/// `exec_handle_file_actions`: the actions in order, the first failure
/// failing the spawn.
fn file_actions(
    ctx: &Ctx<'_>,
    s: &mut Scratch,
    actions: &[FileAction],
    cloexec_default: bool,
) -> Result<(), Errno> {
    let nofile = ctx.proc.rlimits[8].0;
    for a in actions {
        match a {
            FileAction::Open {
                fd,
                oflag,
                mode,
                path,
            } => {
                let path = path.clone()?;
                let orig = open(ctx, s, &path, *oflag, *mode, nofile)?;
                if orig != *fd {
                    dup2(s, orig, *fd, nofile)?;
                    s.fds.remove(orig)?;
                }
            }
            FileAction::Close(fd) => {
                s.fds.remove(*fd)?;
            }
            FileAction::Dup2(from, to) => dup2(s, *from, *to, nofile)?,
            FileAction::Inherit(fd) => s.fds.get_mut(*fd)?.cloexec = false,
            // No fileports: no name can be one.
            FileAction::FileportDup2(..) => return Err(Errno::EINVAL),
            FileAction::Chdir(path) => {
                let path = path.clone()?;
                let d = open_dir(ctx, s.dir(), &path)?;
                s.cwd = s.absolute(&path);
                s.dir = Some(d);
            }
            FileAction::Fchdir(fd) => {
                // fchdir resolves the descriptor in the caller's table.
                let file = ctx.proc.fds.file(*fd)?;
                let h = file.host_fd().ok_or(Errno::EINVAL)?;
                let st = host::fstat(h)?;
                if st.st_mode & libc::S_IFMT != libc::S_IFDIR {
                    return Err(if is_vnode(h, &st) {
                        Errno::ENOTDIR
                    } else {
                        Errno::EINVAL
                    });
                }
                // SAFETY: "." is NUL-terminated; `h` is a live descriptor.
                check(unsafe { libc::faccessat(h, c".".as_ptr(), libc::X_OK, libc::AT_EACCESS) })?;
                // SAFETY: F_DUPFD_CLOEXEC takes an integer argument.
                let dup = check(unsafe { libc::fcntl(h, libc::F_DUPFD_CLOEXEC, 0) })?;
                // SAFETY: `dup` was just created and is owned here.
                s.dir = Some(unsafe { OwnedFd::from_raw_fd(dup) });
                s.cwd = file
                    .path
                    .clone()
                    .map(|p| normalize(&p))
                    .or_else(|| host::fd_path(h))
                    .unwrap_or_else(|| s.cwd.clone());
            }
            FileAction::Unknown => return Err(Errno::EINVAL),
        }
    }
    if cloexec_default {
        s.inherit = Some(actions.iter().filter_map(FileAction::inherited).collect());
    }
    Ok(())
}

/// `open1` for a file action: the lowest free descriptor, the mode less
/// the file-creation mask.
fn open(
    ctx: &Ctx<'_>,
    s: &mut Scratch,
    path: &[u8],
    oflag: u32,
    mode: u32,
    nofile: u64,
) -> Result<i32, Errno> {
    let cpath = host::path(&ctx.proc.vfs, path)?;
    let mode = mode & 0o777 & !ctx.proc.umask;
    let hflags = host::open_flags(oflag) | libc::O_CLOEXEC;
    // SAFETY: `cpath` is NUL-terminated for the call's duration.
    let fd = check(unsafe {
        libc::openat(s.dir().raw(), cpath.as_ptr(), hflags, mode as libc::c_uint)
    })?;
    // SAFETY: `fd` was just returned by the host and is owned here.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let file = Arc::new(OpenFile::host(
        owned,
        oflag & !O_CLOEXEC,
        Some(s.absolute(path)),
    ));
    s.fds.install(file, oflag & O_CLOEXEC != 0, 0, nofile)
}

/// `dup2` in the child's table: the new descriptor is not close-on-exec.
fn dup2(s: &mut Scratch, from: i32, to: i32, nofile: u64) -> Result<(), Errno> {
    let file = s.fds.file(from)?;
    if to < 0 || to as u64 >= nofile {
        return Err(Errno::EBADF);
    }
    if from != to {
        s.fds.install_at(to as usize, file, false);
    }
    Ok(())
}

/// A directory to change to (`chdir_internal`): search permission on it
/// is required.
fn open_dir(ctx: &Ctx<'_>, dir: Dir, path: &[u8]) -> Result<OwnedFd, Errno> {
    if path.is_empty() {
        return Err(Errno::ENOENT);
    }
    let cpath = host::path(&ctx.proc.vfs, path)?;
    #[cfg(target_vendor = "apple")]
    let flags = libc::O_SEARCH | libc::O_CLOEXEC;
    #[cfg(not(target_vendor = "apple"))]
    let flags = libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC;
    // SAFETY: `cpath` is NUL-terminated for the call's duration.
    let fd = check(unsafe { libc::openat(dir.raw(), cpath.as_ptr(), flags) })?;
    // SAFETY: `fd` was just returned by the host and is owned here.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: "." is NUL-terminated; `fd` is live.
    check(unsafe { libc::faccessat(fd, c".".as_ptr(), libc::X_OK, libc::AT_EACCESS) })?;
    Ok(owned)
}

/// Whether a host descriptor is a vnode (`DTYPE_VNODE`: a file, a
/// directory, a device, a named pipe) rather than a pipe, socket, or other
/// object, for `file_vnode`'s `EINVAL`.
fn is_vnode(h: RawFd, st: &libc::stat) -> bool {
    match st.st_mode & libc::S_IFMT {
        libc::S_IFSOCK => false,
        // A pipe and a named pipe look alike; only the named one has a
        // path.
        libc::S_IFIFO => host::fd_path(h).is_some(),
        _ => true,
    }
}

/// `exec_handle_port_actions` and `exec_handle_exception_port_actions`:
/// ports named in the caller's space become the new task's special ports
/// and exception handlers. (Registered, watch, audit-session, and
/// pointer-authentication ports are checked and otherwise have no effect
/// here.)
fn port_actions(ctx: &Ctx<'_>, task: &mut TaskState, actions: &[PortAction]) -> Result<(), Errno> {
    let (mut exc, mut watch, mut registered, mut ptrauth) = (0, 0, 0, 0);
    for a in actions {
        let (count, max) = match a.kind {
            pspa::SPECIAL | pspa::AU_SESSION => continue,
            pspa::EXCEPTION => (&mut exc, EXC_TYPES_COUNT as u32),
            pspa::IMP_WATCHPORTS => (&mut watch, TASK_MAX_WATCHPORT_COUNT),
            pspa::REGISTERED_PORTS => (&mut registered, TASK_PORT_REGISTER_MAX),
            pspa::PTRAUTH_TASK_PORT => (&mut ptrauth, 1),
            _ => return Err(Errno::EINVAL),
        };
        *count += 1;
        if *count > max {
            return Err(Errno::EINVAL);
        }
    }
    for a in actions {
        let port = if a.port != MACH_PORT_NULL && a.port != MACH_PORT_DEAD {
            // ipc_typed_port_copyin_send: a send right, made from a receive
            // right if need be.
            let e = ctx.proc.ipc.lookup(a.port).map_err(|_| Errno::EINVAL)?;
            if e.send == 0 && !e.receive {
                return Err(Errno::EINVAL);
            }
            Some(e.port().cloned().ok_or(Errno::EINVAL)?)
        } else {
            None
        };
        match a.kind {
            pspa::SPECIAL => set_special_port(task, a.which, port)?,
            pspa::EXCEPTION => {
                // task_set_exception_ports on the new task.
                use crate::user::darwin::mach::exception::Handler;
                use crate::user::darwin::mig::exception;
                let handler = port.map_or(Handler::None, Handler::Port);
                exception::validate(ctx.proc.abi, a.mask, &handler, a.behavior, a.flavor)
                    .map_err(|_| Errno::EINVAL)?;
                exception::install(&mut task.exc, a.mask, &handler, a.behavior, a.flavor);
            }
            _ => {}
        }
    }
    Ok(())
}

/// `task_set_special_port` on the new task.
fn set_special_port(
    task: &mut TaskState,
    which: i32,
    port: Option<Arc<Port>>,
) -> Result<(), Errno> {
    match which {
        special::ACCESS if task.special[special::ACCESS as usize].is_some() => Err(Errno::EINVAL),
        special::BOOTSTRAP
        | special::ACCESS
        | special::DEBUG_CONTROL
        | special::RESOURCE_NOTIFY => {
            task.special[which as usize] = port;
            Ok(())
        }
        // The kernel and host ports need SIP's exemption; others are not
        // settable.
        _ => Err(Errno::EINVAL),
    }
}

/// `posix_spawn(pid, path, adesc, argv, envp)`.
pub fn posix_spawn(
    ctx: &mut Ctx<'_>,
    pid_addr: u64,
    path: u64,
    adesc: u64,
    argv: u64,
    envp: u64,
) -> SysResult {
    let desc = if adesc != 0 {
        Desc::read(ctx, adesc)?
    } else {
        Desc::default()
    };
    let attrs = if desc.attr_size != 0 {
        Some(Attrs::parse(&ctx.read(desc.attrp, ATTR_SIZE)?))
    } else {
        None
    };
    let actions = if desc.file_actions_size != 0 {
        read_file_actions(ctx, &desc)?
    } else {
        Vec::new()
    };
    let ports = if desc.port_actions_size != 0 {
        read_port_actions(ctx, &desc)?
    } else {
        Vec::new()
    };
    if desc.persona_info_size != 0 && desc.persona_info != 0 {
        if desc.persona_info_size != PERSONA_INFO_SIZE {
            return Err(Errno::ERANGE);
        }
        ctx.read(desc.persona_info, PERSONA_INFO_SIZE as usize)?;
        // spawn_validate_persona: the persona-management entitlement.
        return Err(Errno::EPERM);
    }
    if desc.posix_cred_info_size != 0 && desc.posix_cred_info != 0 {
        if desc.posix_cred_info_size != POSIX_CRED_INFO_SIZE {
            return Err(Errno::ERANGE);
        }
        if ctx.proc.creds.1 != 0 {
            return Err(Errno::EPERM);
        }
        // Adopting other credentials is not modelled.
        return Err(Errno::ENOTSUP);
    }
    let a = attrs.unwrap_or_default();
    if attrs.is_some() && a.apptype & PROC_TYPE_MASK == PROC_TYPE_DRIVER {
        // exec_validate_spawnattr_policy: the driver entitlement.
        return Err(Errno::EPERM);
    }
    let setexec = a.flags & flag::SETEXEC != 0;
    if !setexec && attrs.is_some() && desc.coal_info != 0 {
        let n = desc.coal_info_size.min(COALITION_INFO_SIZE) as usize;
        let mut info = ctx.read(desc.coal_info, n)?;
        info.resize(COALITION_INFO_SIZE as usize, 0);
        // Only a task in a privileged coalition may spawn into another.
        if info.chunks(24).any(|c| c[..8] != [0; 8]) {
            return Err(Errno::EPERM);
        }
    }

    // The new process's descriptors and working directory.
    let mut scratch = Scratch {
        fds: without_kqueues(&ctx.proc.fds),
        cwd: ctx.proc.cwd.clone(),
        dir: None,
        inherit: None,
    };
    file_actions(
        ctx,
        &mut scratch,
        &actions,
        a.flags & flag::CLOEXEC_DEFAULT != 0,
    )?;
    let mut task = exec_task(&ctx.proc.task);
    port_actions(ctx, &mut task, &ports)?;
    let mut creds = ctx.proc.creds;
    if a.flags & flag::RESETIDS != 0 {
        creds.1 = creds.0;
        creds.3 = creds.2;
    }
    let act = image::activate(ctx, path, scratch.dir(), &a.binprefs)?;
    let strings = args::extract(ctx, &act.interp, &act.user_path, argv, envp)?;

    let Scratch {
        fds,
        cwd,
        dir,
        inherit,
    } = scratch;
    let mut carried = carry(ctx.proc, ctx.thread, fds, inherit.as_ref());
    carried.cwd = cwd;
    carried.creds = creds;
    carried.task = task;
    if !setexec {
        // A forked child: its own parent is the caller; no children,
        // interval timers, or pending signals; its thread's mask is the
        // caller's.
        carried.ppid = ctx.proc.pid;
        carried.children.clear();
        carried.itimers = Default::default();
        carried.pending = 0;
        carried.mask = ctx.thread.sig.oldmask.unwrap_or(ctx.thread.sig.mask);
        carried.started = Instant::now();
        ctx.proc.next_tid += 1;
    }
    if a.flags & flag::SETSIGMASK != 0 {
        carried.mask = a.sigmask & !signal::CANTMASK;
    }
    if a.flags & flag::SETSIGDEF != 0 {
        for sig in 1..signal::NSIG {
            if a.sigdefault & signal::bit(sig) != 0
                && carried.sigacts.set(sig, &SigAction::default())
            {
                carried.pending &= !signal::bit(sig);
            }
        }
    }
    let suspend = a.flags & flag::START_SUSPENDED != 0;
    let pgroup = (a.flags & flag::SETPGROUP != 0).then_some(a.pgroup);
    let setsid = a.flags & flag::SETSID != 0;
    if setexec {
        let built = build(ctx.proc, act, strings, carried);
        if built.is_ok() {
            // After the switch: a failure leaves the new image running as
            // it is.
            set_session(pgroup, setsid).ok();
        }
        return swap_or_kill(ctx, built, dir, suspend);
    }
    let new = build(ctx.proc, act, strings, carried).map_err(|e| build_errno(&e))?;
    fork_child(ctx, new, dir, suspend, pgroup, setsid, pid_addr)
}

/// `setpgid(0, pgroup)` and `setsid()` for the calling (new) process.
fn set_session(pgroup: Option<i32>, setsid: bool) -> Result<(), Errno> {
    if let Some(pg) = pgroup {
        // SAFETY: setpgid takes integer arguments.
        check(unsafe { libc::setpgid(0, pg) })?;
    }
    if setsid {
        // SAFETY: setsid takes no arguments.
        check(unsafe { libc::setsid() })?;
    }
    Ok(())
}

/// Forks the child that runs `new`; returns in the caller with the
/// child's pid stored at `pid_addr`.
fn fork_child(
    ctx: &mut Ctx<'_>,
    mut new: Proc,
    chdir: Option<OwnedFd>,
    suspend: bool,
    pgroup: Option<i32>,
    setsid: bool,
    pid_addr: u64,
) -> SysResult {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `fds` has room for the two descriptors.
    check(unsafe { libc::pipe(fds.as_mut_ptr()) })?;
    // SAFETY: both descriptors were just created and are owned here.
    let (rd, wr) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    for fd in fds {
        // SAFETY: F_SETFD takes an integer argument.
        unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
    }
    let parent = ctx.proc.pid;
    match signal::host::fork_host()? {
        Some(pid) => {
            drop(wr);
            drop(new);
            ctx.proc.hidden.remove(&pid);
            if let Some(e) = read_report(&rd) {
                // The child could not become the new process: it is reaped
                // here and was never the guest's.
                reap(pid);
                ctx.proc.hidden.insert(pid);
                return Err(e);
            }
            ctx.proc.children.insert(pid);
            if pid_addr != 0 {
                let _ = ctx.write_u32(pid_addr, pid as u32);
            }
            Ok(Rv::one(0))
        }
        None => {
            drop(rd);
            // SAFETY: getpid takes no arguments.
            let pid = unsafe { libc::getpid() };
            new.pid = pid;
            new.ppid = parent;
            new.audit = process::host_audit_token(pid, new.creds);
            new.next_tid = ((pid as u64) << 20) | 1;
            if let Err(e) = set_session(pgroup, setsid) {
                let b = e.0.to_le_bytes();
                // SAFETY: `b` is valid for its length; the process ends at
                // once without running anything of the caller's.
                unsafe {
                    libc::write(wr.as_raw_fd(), b.as_ptr().cast(), b.len());
                    libc::_exit(127);
                }
            }
            // The caller's kqueues are the host's and stay with it.
            std::mem::forget(std::mem::take(&mut ctx.proc.kq));
            drop(wr);
            ctx.proc.exec = Some(Box::new(Swap {
                proc: new,
                chdir,
                suspend,
            }));
            Err(Errno::EJUSTRETURN)
        }
    }
}

/// The child's report: an errno, or `None` when the pipe closed empty.
fn read_report(rd: &OwnedFd) -> Option<Errno> {
    let mut b = [0u8; 4];
    loop {
        // SAFETY: `b` is writable for its length.
        let n = unsafe { libc::read(rd.as_raw_fd(), b.as_mut_ptr().cast(), b.len()) };
        if n < 0 && Errno::last() == Errno::EINTR {
            continue;
        }
        return (n == 4).then(|| Errno(i32::from_le_bytes(b)));
    }
}

/// Waits for the child that failed.
fn reap(pid: i32) {
    let mut status = 0;
    // SAFETY: `status` is valid for the host to write.
    while unsafe { libc::waitpid(pid, &mut status, 0) } < 0 && Errno::last() == Errno::EINTR {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_sizes_match_the_kernel() {
        assert_eq!(action_size(1, PSFA_HEADER, PSFA_ACTION), 1048);
        assert_eq!(action_size(2, PSFA_HEADER, PSFA_ACTION), 2088);
        assert_eq!(action_size(1, PSPA_HEADER, PSPA_ACTION), 32);
        // A negative count overflows to no size at all.
        assert_eq!(action_size(-1, PSFA_HEADER, PSFA_ACTION), 0);
    }

    #[test]
    fn file_actions_parse() {
        let mut e = vec![0u8; PSFA_ACTION as usize];
        e[4..8].copy_from_slice(&5i32.to_le_bytes());
        e[8..12].copy_from_slice(&0x601i32.to_le_bytes());
        e[12..14].copy_from_slice(&0o644u16.to_le_bytes());
        e[14..20].copy_from_slice(b"/tmp/x");
        assert_eq!(
            FileAction::parse(&e),
            FileAction::Open {
                fd: 5,
                oflag: 0x601,
                mode: 0o644,
                path: Ok(b"/tmp/x".to_vec())
            }
        );
        e[0] = 2;
        assert_eq!(FileAction::parse(&e), FileAction::Dup2(5, 0x601));
        e[0] = 5;
        e[8..].fill(b'a');
        assert_eq!(
            FileAction::parse(&e),
            FileAction::Chdir(Err(Errno::ENAMETOOLONG))
        );
        e[0] = 9;
        assert_eq!(FileAction::parse(&e), FileAction::Unknown);
    }

    #[test]
    fn attributes_parse_at_their_offsets() {
        let mut b = vec![0u8; ATTR_SIZE];
        b[0..2].copy_from_slice(&0x40c2u16.to_le_bytes());
        b[4..8].copy_from_slice(&0x10u32.to_le_bytes());
        b[8..12].copy_from_slice(&0x20u32.to_le_bytes());
        b[12..16].copy_from_slice(&7i32.to_le_bytes());
        b[16..20].copy_from_slice(&0x0100_0007u32.to_le_bytes());
        b[112..116].copy_from_slice(&u32::MAX.to_le_bytes());
        let a = Attrs::parse(&b);
        assert_eq!(
            (a.flags, a.sigdefault, a.sigmask, a.pgroup),
            (0x40c2, 0x10, 0x20, 7)
        );
        assert_eq!(a.binprefs.cpu, [0x0100_0007, 0, 0, 0]);
        assert_eq!(a.binprefs.sub[0], u32::MAX);
    }
}
