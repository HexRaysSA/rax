//! Ancillary data of the socket transfers: what a sender attaches
//! (`__scm_send`, and for IP sockets `sock_cmsg_send`/`ip_cmsg_send`) and
//! what a receiver is given (`scm_recv`, `scm_detach_fds`).
//!
//! | Message | Sending | Receiving |
//! |---|---|---|
//! | `SCM_RIGHTS` (Unix) | up to `SCM_MAX_FD` (253) open descriptors, passed as host descriptors ([`net::msg`](super::super::super::net::msg)) | installed from the lowest free descriptor, close-on-exec with `MSG_CMSG_CLOEXEC`; what does not fit is closed and `MSG_CTRUNC` set |
//! | `SCM_CREDENTIALS` (Unix, netlink) | checked (`scm_check_creds`: the caller's PID, one of its user and group IDs); the host carries its own | with `SO_PASSCRED`, the connected peer's credentials (Unix) |
//! | IP-level and `SOL_SOCKET` options of IP sockets (`IP_TTL`, `IP_TOS`, `IP_PKTINFO`, `SO_MARK`, ...) | accepted and not applied | none |

use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::Arc;

use super::super::super::abi::errno::Errno;
use super::super::super::abi::errno_table::*;
use super::super::super::abi::open::*;
use super::super::super::fs::fd::{FileObject, FileType, OpenFile};
use super::super::super::fs::file_type_of;
use super::super::super::net::msg::{self, Cmsg, Key, Out};
use super::super::super::net::{Socket, linux_domain, linux_type, lx, opts, sys};
use super::super::Ctx;
use super::socket_file;

/// The IP-level control messages `ip_cmsg_send` and `ip6_datagram_send_ctl`
/// take: `IP_TOS`, `IP_TTL`, `IP_RETOPTS`, `IP_PKTINFO`, `IP_PROTOCOL`;
/// `IPV6_PKTINFO`, `IPV6_HOPLIMIT`, `IPV6_TCLASS`, `IPV6_DONTFRAG`.
fn ip_cmsg_known(level: i32, kind: i32) -> bool {
    match level {
        lx::IPPROTO_IP => matches!(kind, 1 | 2 | 7 | 8 | 52),
        lx::IPPROTO_IPV6 => matches!(kind, 50 | 52 | 67 | 62),
        _ => true,
    }
}

/// What a sender's control data carries.
#[derive(Default)]
pub struct Sending {
    /// `SCM_RIGHTS`: the descriptions to pass.
    pub files: Vec<Arc<OpenFile>>,
}

/// Checks a sender's control data for socket `s`.
pub fn parse(c: &Ctx<'_>, s: &Socket, ctl: &[u8]) -> Result<Sending, Errno> {
    let mut out = Sending::default();
    for m in msg::split(ctl)? {
        // Netlink takes __scm_send's messages, less SCM_RIGHTS.
        if !s.unix() && s.domain != lx::AF_NETLINK {
            inet_cmsg(c, s, &m)?;
            continue;
        }
        if m.level != lx::SOL_SOCKET {
            continue;
        }
        match m.kind {
            lx::SCM_RIGHTS if s.unix() => {
                // scm_fp_copy: the whole ints the message holds.
                let fds: Vec<i32> = m
                    .data
                    .chunks_exact(4)
                    .map(|b| i32::from_le_bytes(b.try_into().unwrap()))
                    .collect();
                if fds.is_empty() {
                    continue;
                }
                if fds.len() > msg::MAX_FDS || out.files.len() + fds.len() > msg::MAX_FDS {
                    return Err(Errno(EINVAL));
                }
                for fd in fds {
                    out.files.push(c.p.fds.file(fd)?);
                }
            }
            lx::SCM_CREDENTIALS => {
                if m.data.len() != 12 {
                    return Err(Errno(EINVAL));
                }
                check_creds(c, &m.data)?;
            }
            _ => return Err(Errno(EINVAL)),
        }
    }
    Ok(out)
}

/// `sock_cmsg_send` and `ip_cmsg_send` for an IP socket.
fn inet_cmsg(c: &Ctx<'_>, s: &Socket, m: &Cmsg) -> Result<(), Errno> {
    const SO_MARK: i32 = 36;
    const SO_PRIORITY: i32 = 12;
    const SO_TIMESTAMPING_OLD: i32 = 37;
    const SO_TIMESTAMPING_NEW: i32 = 65;
    const SCM_TXTIME: i32 = 61;
    if m.level == lx::SOL_SOCKET {
        return match m.kind {
            SO_MARK if c.p.creds.1 != 0 => Err(Errno(EPERM)),
            SO_MARK | SO_PRIORITY | SO_TIMESTAMPING_OLD | SO_TIMESTAMPING_NEW | SCM_TXTIME => {
                Ok(())
            }
            _ => Err(Errno(EINVAL)),
        };
    }
    let own =
        m.level == lx::IPPROTO_IP || (m.level == lx::IPPROTO_IPV6 && s.domain == lx::AF_INET6);
    if own && !ip_cmsg_known(m.level, m.kind) {
        return Err(Errno(EINVAL));
    }
    Ok(())
}

/// `scm_check_creds`: valid IDs, the caller's PID, and IDs among the
/// caller's own, unless privileged.
fn check_creds(c: &Ctx<'_>, data: &[u8]) -> Result<(), Errno> {
    let w = |i: usize| u32::from_le_bytes(data[i..i + 4].try_into().unwrap());
    let (pid, uid, gid) = (w(0) as i32, w(4), w(8));
    if uid == u32::MAX || gid == u32::MAX {
        return Err(Errno(EINVAL));
    }
    let (ruid, euid, rgid, egid) = c.p.creds;
    let admin = euid == 0;
    let ok = (pid == c.p.pid || admin)
        && (uid == ruid || uid == euid || admin)
        && (gid == rgid || gid == egid || admin);
    if !ok {
        return Err(Errno(EPERM));
    }
    Ok(())
}

/// The host descriptors carrying descriptions to another socket, and
/// what keeps the stand-ins open until they are sent.
#[derive(Default)]
pub struct Carried {
    /// The host descriptors to pass.
    pub raw: Vec<RawFd>,
    /// Stand-ins for descriptions without a host descriptor.
    keep: Vec<OwnedFd>,
    /// The records made.
    keys: Vec<Key>,
}

impl Carried {
    /// The send failed: the records are dropped.
    pub fn failed(self) {
        for k in self.keys {
            msg::unregister(k);
        }
    }
}

/// The host descriptor of a description, if it has one.
fn host_fd(f: &OpenFile) -> Option<RawFd> {
    match &f.object {
        FileObject::Host(h) => Some(h.as_raw_fd()),
        FileObject::PipeRead(p) => Some(p.as_raw_fd()),
        FileObject::PipeWrite(p) => Some(p.as_raw_fd()),
        // An emulated netlink socket's descriptor is its readiness level,
        // which no other process may read.
        FileObject::Socket(s) if s.netlink.is_some() => None,
        FileObject::Socket(s) => Some(s.raw()),
        FileObject::Synthetic(_)
        | FileObject::PathOnly
        | FileObject::Anon(_)
        | FileObject::Mqueue(_) => None,
    }
}

/// Prepares `files` for passing: each description's host descriptor, or a
/// stand-in socket, recorded for a receiver in this process.
pub fn carry(files: &[Arc<OpenFile>]) -> Result<Carried, Errno> {
    let mut out = Carried::default();
    for f in files {
        let (raw, strong) = match host_fd(f) {
            Some(raw) => (raw, false),
            None => {
                let (stand_in, _) = sys::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0)?;
                let raw = stand_in.as_raw_fd();
                out.keep.push(stand_in);
                (raw, true)
            }
        };
        if let Some(key) = msg::key_of(&raw) {
            msg::register(key, f, strong);
            out.keys.push(key);
        }
        out.raw.push(raw);
    }
    Ok(out)
}

/// The descriptions for host descriptors received: the recorded ones
/// passed within this process, new ones for the others.
pub fn receive(c: &Ctx<'_>, fds: Vec<OwnedFd>) -> Vec<Arc<OpenFile>> {
    fds.into_iter()
        .map(|fd| match msg::key_of(&fd).and_then(msg::claim) {
            Some(f) => f,
            None => adopt(c, fd),
        })
        .collect()
}

/// Discards descriptors a receiver had no room for (or a `read`, which
/// takes no control data): their records are claimed so nothing stays
/// held.
pub fn discard(fds: Vec<OwnedFd>) {
    for fd in fds {
        if let Some(k) = msg::key_of(&fd) {
            drop(msg::claim(k));
        }
    }
}

/// A new description for a host descriptor another process passed: a
/// socket, pipe, or file with the host's access mode and `O_APPEND` (the
/// sender's other status flags are its own).
fn adopt(c: &Ctx<'_>, fd: OwnedFd) -> Arc<OpenFile> {
    let file = std::fs::File::from(fd);
    let meta = file.metadata().ok();
    let ftype = meta.as_ref().map_or(FileType::Regular, file_type_of);
    // SAFETY: F_GETFL on a descriptor this function owns.
    let hflags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    let acc = match hflags & libc::O_ACCMODE {
        libc::O_WRONLY => O_WRONLY,
        libc::O_RDWR => O_RDWR,
        _ => O_RDONLY,
    };
    let append = if hflags & libc::O_APPEND != 0 {
        O_APPEND
    } else {
        0
    };
    match ftype {
        FileType::Socket => {
            let fd = sys::adopt(OwnedFd::from(file));
            let (d, t, p) = sys::describe(&fd).unwrap_or((libc::AF_UNIX, libc::SOCK_STREAM, 0));
            socket_file(Socket::new(fd, linux_domain(d), linux_type(t), p), false)
        }
        FileType::Fifo if acc != O_RDWR => {
            let fd = sys::adopt(OwnedFd::from(file));
            let object = if acc == O_WRONLY {
                FileObject::PipeWrite(std::io::PipeWriter::from(fd))
            } else {
                FileObject::PipeRead(std::io::PipeReader::from(fd))
            };
            OpenFile::new(object, FileType::Fifo, "pipe:", None, acc)
        }
        _ => {
            let host = host_path(&file);
            let guest = host
                .as_ref()
                .map_or_else(String::new, |h| c.p.vfs.guest_path_of(h));
            let large = if ftype == FileType::Regular {
                c.p.abi.open_flags().largefile
            } else {
                0
            };
            OpenFile::new(
                FileObject::Host(file),
                ftype,
                guest,
                host,
                acc | append | large,
            )
        }
    }
}

/// The host path an open file was reached by, where the host tells.
fn host_path(f: &std::fs::File) -> Option<std::path::PathBuf> {
    #[cfg(target_vendor = "apple")]
    {
        use std::os::unix::ffi::OsStrExt;
        let mut buf = vec![0u8; libc::PATH_MAX as usize];
        // SAFETY: F_GETPATH writes a NUL-terminated path of at most
        // PATH_MAX bytes into the buffer.
        if unsafe { libc::fcntl(f.as_raw_fd(), libc::F_GETPATH, buf.as_mut_ptr()) } < 0 {
            return None;
        }
        let end = buf.iter().position(|&b| b == 0)?;
        Some(std::path::PathBuf::from(std::ffi::OsStr::from_bytes(
            &buf[..end],
        )))
    }
    #[cfg(not(target_vendor = "apple"))]
    {
        std::fs::read_link(format!("/proc/self/fd/{}", f.as_raw_fd())).ok()
    }
}

/// Writes the control data of a receive into `out` (`scm_recv`): with
/// `SO_PASSCRED`, the peer's credentials; then the descriptions received,
/// installed as new descriptors. `null` is a null control pointer, which
/// takes nothing.
pub fn deliver(
    c: &mut Ctx<'_>,
    s: &Socket,
    out: &mut Out,
    null: bool,
    files: Vec<Arc<OpenFile>>,
    cloexec: bool,
) {
    let passcred = s.unix()
        && s.state
            .lock()
            .unwrap()
            .ints
            .iter()
            .any(|&(l, o, v)| l == lx::SOL_SOCKET && o == opts::so::PASSCRED && v != 0);
    let creds = passcred.then(|| s.peer_cred()).flatten();
    if null {
        if passcred || !files.is_empty() {
            out.truncated = true;
        }
        return;
    }
    if let Some((pid, uid, gid)) = creds {
        let mut d = pid.to_le_bytes().to_vec();
        d.extend_from_slice(&uid.to_le_bytes());
        d.extend_from_slice(&gid.to_le_bytes());
        out.put(lx::SOL_SOCKET, lx::SCM_CREDENTIALS, &d);
    }
    if files.is_empty() {
        return;
    }
    // scm_detach_fds.
    let fdmax = out.max_fds().min(files.len());
    let limit = c.p.rlimits[7].0;
    let mut installed = Vec::new();
    for f in files.iter().take(fdmax) {
        match c.p.fds.install(f.clone(), cloexec, limit) {
            Ok(fd) => installed.push(fd),
            Err(_) => break,
        }
    }
    if !installed.is_empty() {
        let data: Vec<u8> = installed.iter().flat_map(|fd| fd.to_le_bytes()).collect();
        let before = out.truncated;
        out.put(lx::SOL_SOCKET, lx::SCM_RIGHTS, &data);
        out.truncated = before;
    }
    if installed.len() < files.len() {
        out.truncated = true;
    }
}
