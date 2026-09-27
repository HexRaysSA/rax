//! `proc_info` and `proc_info_extended_id` (`bsd/kern/proc_info.c`).
//!
//! The guest's processes are host processes, so what `proc_info` says
//! about another process is the host kernel's answer: those calls pass
//! through, the host checking the flavor, the buffer size, the target,
//! and the caller's permission in XNU's order, and the result is copied
//! into the guest's buffer (the host writes into a copy of it, so bytes
//! the kernel leaves alone stay as they were). About the calling process
//! the host would describe the emulator, so those questions are answered
//! from the emulated process — its image, threads, descriptors, memory,
//! kqueues, and work queue — with what only the host knows (session and
//! terminal, start time, unique identifier, task-policy flags) taken from
//! the host's own answer. A thread's name is the guest thread's, and
//! dyld's image-info registration is the guest task's.

mod fdinfo;
mod pidinfo;
mod selfctl;

pub(crate) use pidinfo::image_name;

use crate::user::darwin::abi::Errno;
use crate::user::darwin::arch::{Rv, SysResult};
use crate::user::darwin::syscall::Ctx;

/// `PROC_INFO_CALL_*`.
pub mod call {
    pub const LISTPIDS: i32 = 0x1;
    pub const PIDINFO: i32 = 0x2;
    pub const PIDFDINFO: i32 = 0x3;
    pub const SETCONTROL: i32 = 0x5;
    pub const PIDFILEPORTINFO: i32 = 0x6;
    pub const PIDRUSAGE: i32 = 0x9;
    pub const CANUSEFGHW: i32 = 0xc;
    pub const PIDDYNKQUEUEINFO: i32 = 0xd;
    pub const SET_DYLD_IMAGES: i32 = 0xf;
}

/// `PIF_COMPARE_IDVERSION`, `PIF_COMPARE_UNIQUEID`.
pub mod pif {
    pub const COMPARE_IDVERSION: u32 = 0x1;
    pub const COMPARE_UNIQUEID: u32 = 0x2;
}

/// The host's `SYS_proc_info` and `SYS_proc_info_extended_id`.
const SYS_PROC_INFO: libc::c_int = 336;
const SYS_PROC_INFO_EXTENDED_ID: libc::c_int = 545;

/// The largest buffer a host call is given: every answer fits (the
/// longest are process lists, a few KiB).
const MIRROR_MAX: usize = 1 << 20;

/// One call's arguments.
#[derive(Clone, Copy, Debug)]
pub struct Args {
    pub callnum: i32,
    pub pid: i32,
    pub flavor: i32,
    /// `proc_info_extended_id`'s flags and identifier (0 for `proc_info`).
    pub flags: u32,
    pub ext_id: u64,
    /// Whether the call is `proc_info_extended_id`.
    pub extended: bool,
    pub arg: u64,
    pub buffer: u64,
    /// `buffersize`, which the kernel takes as unsigned.
    pub size: u32,
}

/// `proc_info(callnum, pid, flavor, arg, buffer, buffersize)`.
pub fn proc_info(
    ctx: &mut Ctx<'_>,
    callnum: i32,
    pid: i32,
    flavor: u32,
    arg: u64,
    buffer: u64,
    size: i32,
) -> SysResult {
    dispatch(
        ctx,
        Args {
            callnum,
            pid,
            flavor: flavor as i32,
            flags: 0,
            ext_id: 0,
            extended: false,
            arg,
            buffer,
            size: size as u32,
        },
    )
}

/// `proc_info_extended_id(callnum, pid, flavor, flags, ext_id, arg,
/// buffer, buffersize)`.
#[allow(clippy::too_many_arguments)]
pub fn proc_info_extended_id(
    ctx: &mut Ctx<'_>,
    callnum: i32,
    pid: i32,
    flavor: u32,
    flags: u32,
    ext_id: u64,
    arg: u64,
    buffer: u64,
    size: i32,
) -> SysResult {
    if flags & pif::COMPARE_IDVERSION != 0 && flags & pif::COMPARE_UNIQUEID != 0 {
        return Err(Errno::EINVAL);
    }
    dispatch(
        ctx,
        Args {
            callnum,
            pid,
            flavor: flavor as i32,
            flags,
            ext_id,
            extended: true,
            arg,
            buffer,
            size: size as u32,
        },
    )
}

fn dispatch(ctx: &mut Ctx<'_>, a: Args) -> SysResult {
    let own = a.pid == ctx.proc.pid;
    match a.callnum {
        call::PIDINFO if own => pidinfo::own(ctx, &a),
        call::PIDFDINFO if own => fdinfo::own(ctx, &a),
        call::SETCONTROL => selfctl::setcontrol(ctx, &a),
        call::SET_DYLD_IMAGES => selfctl::set_dyld_images(ctx, &a),
        call::PIDFILEPORTINFO if own => selfctl::fileportinfo(ctx, &a),
        call::PIDDYNKQUEUEINFO if own => selfctl::dynkqueueinfo(ctx, &a),
        call::PIDRUSAGE if own => {
            let uuid = ctx.proc.program.main.uuid.unwrap_or_default();
            passthrough(ctx, &a, |buf| {
                // ri_uuid is the executable's.
                if buf.len() >= 16 {
                    buf[..16].copy_from_slice(&uuid);
                }
            })
        }
        _ => passthrough(ctx, &a, |_| {}),
    }
}

/// The host's `proc_info` (or `proc_info_extended_id`) with `buf`.
fn host_call(a: &Args, buf: *mut u8, size: u32) -> Result<i32, Errno> {
    // SAFETY: `buf` is NULL or valid for `size` bytes the host may write;
    // the other arguments are integers.
    let r = unsafe {
        if a.extended {
            libc::syscall(
                SYS_PROC_INFO_EXTENDED_ID,
                a.callnum,
                a.pid,
                a.flavor,
                a.flags,
                a.ext_id,
                a.arg,
                buf,
                size as i32,
            )
        } else {
            libc::syscall(
                SYS_PROC_INFO,
                a.callnum,
                a.pid,
                a.flavor,
                a.arg,
                buf,
                size as i32,
            )
        }
    };
    if r < 0 { Err(Errno::last()) } else { Ok(r) }
}

/// The host's answer for another process: the host writes into a copy of
/// the guest's buffer, `patch` adjusts it, and the copy goes back.
fn passthrough(ctx: &mut Ctx<'_>, a: &Args, patch: impl FnOnce(&mut [u8])) -> SysResult {
    if a.buffer == 0 {
        return host_call(a, std::ptr::null_mut(), a.size).map(|r| Rv::one(r as u64));
    }
    // PIDRUSAGE ignores the buffer's size and writes a whole record.
    let len = match a.callnum {
        call::PIDRUSAGE => rusage_size(a.flavor),
        _ => (a.size as usize).min(MIRROR_MAX),
    };
    let (mut buf, readable) = match ctx.read(a.buffer, len) {
        Ok(b) => (b, true),
        Err(_) => (vec![0u8; len], false),
    };
    let r = host_call(a, buf.as_mut_ptr(), len as u32);
    let written = match r {
        Ok(v) => written(a, v, len),
        // CANUSEFGHW reports its reason even when it fails.
        Err(_) if a.callnum == call::CANUSEFGHW && readable => len.min(4),
        Err(e) => return Err(e),
    };
    patch(&mut buf[..written]);
    let back = if readable { len } else { written };
    ctx.write(a.buffer, &buf[..back])?;
    r.map(|v| Rv::one(v as u64))
}

/// How many bytes of the buffer a successful host call wrote, for a
/// guest buffer that could not be mirrored whole.
fn written(a: &Args, retval: i32, len: usize) -> usize {
    let r = retval.max(0) as usize;
    let n = match (a.callnum, a.flavor) {
        // PROC_PIDPATHINFO fills the whole buffer and returns 0.
        (call::PIDINFO, 11) => len,
        // Counts rather than bytes.
        (call::PIDINFO, 26 | 27) => r * 8,
        (call::PIDINFO, 29) => r * 56,
        (call::PIDFDINFO, 9) => r * 104,
        (call::PIDRUSAGE, f) => rusage_size(f),
        _ => r,
    };
    n.min(len)
}

/// `sizeof(rusage_info_vN)`.
fn rusage_size(flavor: i32) -> usize {
    match flavor {
        0 => 96,
        1 => 144,
        2 => 160,
        3 => 232,
        4 => 296,
        5 => 304,
        6 => 464,
        _ => 0,
    }
}

/// Little-endian field writers for the `proc_info` structures.
pub(super) struct Out(pub Vec<u8>);

impl Out {
    pub fn new(size: usize) -> Self {
        Out(vec![0u8; size])
    }
    pub fn u16(&mut self, off: usize, v: u16) -> &mut Self {
        self.0[off..off + 2].copy_from_slice(&v.to_le_bytes());
        self
    }
    pub fn u32(&mut self, off: usize, v: u32) -> &mut Self {
        self.0[off..off + 4].copy_from_slice(&v.to_le_bytes());
        self
    }
    pub fn u64(&mut self, off: usize, v: u64) -> &mut Self {
        self.0[off..off + 8].copy_from_slice(&v.to_le_bytes());
        self
    }
    /// A NUL-terminated string in a field of `len` bytes (at most
    /// `len - 1` characters).
    pub fn str(&mut self, off: usize, len: usize, s: &[u8]) -> &mut Self {
        let n = s.len().min(len - 1);
        self.0[off..off + n].copy_from_slice(&s[..n]);
        self.0[off + n..off + len].fill(0);
        self
    }
    /// A path in a field of `len` bytes as `vn_getpath` leaves it: built
    /// backwards from the field's end, then moved to its start, so a
    /// copy stays at the end with zeros between.
    pub fn path(&mut self, off: usize, len: usize, s: &[u8]) -> &mut Self {
        let n = s.len().min(len - 1) + 1;
        let field = &mut self.0[off..off + len];
        field.fill(0);
        field[len - n..len - 1].copy_from_slice(&s[..n - 1]);
        field.copy_within(len - n..len, 0);
        self
    }
    pub fn bytes(&mut self, off: usize, b: &[u8]) -> &mut Self {
        self.0[off..off + b.len()].copy_from_slice(b);
        self
    }
}

/// The host's answer about the calling process itself (the emulator's
/// host process), for what only the host knows.
fn host_self(pid: i32, flavor: i32, size: usize) -> Result<Vec<u8>, Errno> {
    let mut buf = vec![0u8; size];
    let a = Args {
        callnum: call::PIDINFO,
        pid,
        flavor,
        flags: 0,
        ext_id: 0,
        extended: false,
        arg: 0,
        buffer: 0,
        size: size as u32,
    };
    host_call(&a, buf.as_mut_ptr(), size as u32)?;
    Ok(buf)
}

/// A file's `vinfo_stat`, `vi_type`, and `vi_fsid` (`struct vnode_info`,
/// 152 bytes) from the host's status of `path` (not following a last
/// symbolic link when `nofollow`).
fn vnode_info(path: &std::path::Path, nofollow: bool) -> Option<Out> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let flag = if nofollow {
        libc::AT_SYMLINK_NOFOLLOW
    } else {
        0
    };
    let st = crate::user::darwin::host::fstatat(libc::AT_FDCWD, &c, flag).ok()?;
    let mut o = Out::new(152);
    put_vinfo_stat(&mut o, 0, &st);
    o.u32(136, vtype(st.st_mode as u32));
    // SAFETY: an all-zero statfs is valid to overwrite; `c` is
    // NUL-terminated.
    let mut sfs: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    if unsafe { libc::statfs(c.as_ptr(), &mut sfs) } == 0 {
        // SAFETY: fsid_t is two 32-bit integers.
        let fsid: [i32; 2] = unsafe { std::mem::transmute(sfs.f_fsid) };
        o.u32(144, fsid[0] as u32).u32(148, fsid[1] as u32);
    }
    Some(o)
}

/// `munge_vinfo_stat` of a host status.
fn put_vinfo_stat(o: &mut Out, at: usize, st: &libc::stat) {
    o.u32(at, st.st_dev as u32)
        .u16(at + 4, st.st_mode as u16)
        .u16(at + 6, st.st_nlink as u16)
        .u64(at + 8, st.st_ino as u64)
        .u32(at + 16, st.st_uid)
        .u32(at + 20, st.st_gid)
        .u64(at + 24, st.st_atime as u64)
        .u64(at + 32, st.st_atime_nsec as u64)
        .u64(at + 40, st.st_mtime as u64)
        .u64(at + 48, st.st_mtime_nsec as u64)
        .u64(at + 56, st.st_ctime as u64)
        .u64(at + 64, st.st_ctime_nsec as u64);
    o.u64(at + 72, st.st_birthtime as u64)
        .u64(at + 80, st.st_birthtime_nsec as u64)
        .u32(at + 108, st.st_flags)
        .u32(at + 112, st.st_gen);
    o.u64(at + 88, st.st_size as u64)
        .u64(at + 96, st.st_blocks as u64)
        .u32(at + 104, st.st_blksize as u32)
        .u32(at + 116, st.st_rdev as u32);
}

/// `enum vtype` of a file mode.
fn vtype(mode: u32) -> u32 {
    match mode & 0o170000 {
        0o100000 => 1, // VREG
        0o040000 => 2, // VDIR
        0o060000 => 3, // VBLK
        0o020000 => 4, // VCHR
        0o120000 => 5, // VLNK
        0o140000 => 6, // VSOCK
        0o010000 => 7, // VFIFO
        _ => 0,
    }
}

/// The canonical guest path of a host path (`vn_getpath`: symbolic links
/// resolved, `/tmp` as `/private/tmp`), the root overlay's prefix removed.
fn canonical(ctx: &Ctx<'_>, host: &std::path::Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    let real = std::fs::canonicalize(host).unwrap_or_else(|_| host.to_path_buf());
    ctx.proc.vfs.guest_path(real.as_os_str().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_keep_their_backward_copy() {
        let mut o = Out::new(12);
        o.0.fill(0xa5);
        o.path(0, 12, b"/a/b");
        assert_eq!(&o.0, b"/a/b\0\0\0/a/b\0");
        // A path longer than half the field overlaps its copy.
        let mut o = Out::new(8);
        o.path(0, 8, b"/abcde");
        assert_eq!(&o.0, b"/abcde\0\0");
        let mut o = Out::new(10);
        o.path(0, 10, b"/abcdef");
        assert_eq!(&o.0, b"/abcdef\0f\0");
    }

    #[test]
    fn strings_are_truncated_and_terminated() {
        let mut o = Out::new(16);
        o.str(0, 16, b"a very long command name");
        assert_eq!(&o.0[..15], b"a very long com");
        assert_eq!(o.0[15], 0);
    }

    #[test]
    fn host_writes_are_sized_by_callnum() {
        let a = |callnum, flavor| Args {
            callnum,
            pid: 1,
            flavor,
            flags: 0,
            ext_id: 0,
            extended: false,
            arg: 0,
            buffer: 1,
            size: 4096,
        };
        assert_eq!(written(&a(call::PIDINFO, 11), 0, 4096), 4096);
        assert_eq!(written(&a(call::PIDINFO, 3), 136, 4096), 136);
        assert_eq!(written(&a(call::PIDINFO, 26), 3, 4096), 24);
        assert_eq!(written(&a(call::PIDRUSAGE, 6), 0, 4096), 464);
        assert_eq!(vtype(0o100644), 1);
        assert_eq!(vtype(0o040755), 2);
        assert_eq!(vtype(0o010600), 7);
    }
}
