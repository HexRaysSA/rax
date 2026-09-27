//! The audit calls (`audit_syscalls.c`): `audit`, `auditon`, `getauid`,
//! `setauid`, `getaudit_addr`, `setaudit_addr`, and `auditctl`.
//!
//! The guest's audit state is its host process's: its credential (audit
//! user, session, terminal, and mask) is the host credential the emulator
//! runs under, and the audit subsystem is the host kernel's. Each call is
//! made on the host with the guest's buffers copied through, in the order
//! the kernel reads and writes them, so that its checks (privilege, then
//! lengths, then the copies) report the kernel's errors: where the guest's
//! buffer cannot be read, the host is handed a pointer that faults at the
//! same step.

use std::ffi::c_void;

use crate::user::darwin::abi::Errno;
use crate::user::darwin::arch::{Rv, SysResult};
use crate::user::darwin::host::{self, check};
use crate::user::darwin::syscall::Ctx;

/// `sizeof(struct auditinfo_addr)`: `ai_auid`, `ai_mask`, `ai_termid`
/// (`at_port`, `at_type`, `at_addr[4]`), `ai_asid`, then the 8-byte-aligned
/// `ai_flags`: 4 + 8 + 24 + 4 + 4 (padding) + 8 = 48 bytes.
const AUDITINFO_ADDR: usize = 48;
/// The offset of `ai_asid` in `struct auditinfo_addr`: 4 + 8 + 24 = 36.
const AI_ASID: usize = 36;
/// `AU_DEFAUDITSID`.
const AU_DEFAUDITSID: i32 = 0;
/// `AU_ASSIGN_ASID`.
const AU_ASSIGN_ASID: i32 = -1;
/// `MAX_AUDIT_RECORD_SIZE` (`MAXAUDITDATA`, 0x7fff): no longer record is
/// taken (`EINVAL` before the record is read).
const MAX_AUDIT_RECORD_SIZE: usize = 0x7fff;
/// A bound on `union auditon_udata` (its largest member, `au_stat_t`, is
/// under 256 bytes): a longer `length` is refused (`EINVAL`) before the
/// data is read.
const AUDITON_MAX: usize = 4096;
/// A host address in the unmapped first page that is not null: the host
/// faults on it where it would fault on the guest's buffer, without the
/// meaning the kernel gives a null pointer.
const FAULT: usize = 1;

/// The `auditon` commands whose data the kernel copies out on success.
const AUDITON_GETS: &[i32] = &[
    2,  // A_OLDGETPOLICY
    4,  // A_GETKMASK
    6,  // A_OLDGETQCTRL
    8,  // A_GETCWD
    9,  // A_GETCAR
    12, // A_GETSTAT
    20, // A_OLDGETCOND
    22, // A_GETCLASS
    24, // A_GETPINFO
    27, // A_GETFSIZE
    28, // A_GETPINFO_ADDR
    29, // A_GETKAUDIT
    32, // A_GETSINFO_ADDR
    33, // A_GETPOLICY
    35, // A_GETQCTRL
    37, // A_GETCOND
    39, // A_GETSFLAGS
    41, // A_GETCTLMODE
    43, // A_GETEXPAFTER
];

unsafe extern "C" {
    fn audit(record: *const c_void, length: libc::c_int) -> libc::c_int;
    fn auditon(cmd: libc::c_int, data: *mut c_void, length: libc::c_int) -> libc::c_int;
    fn getauid(auid: *mut u32) -> libc::c_int;
    fn setauid(auid: *const u32) -> libc::c_int;
    fn getaudit_addr(aia: *mut c_void, length: libc::c_int) -> libc::c_int;
    fn setaudit_addr(aia: *const c_void, length: libc::c_int) -> libc::c_int;
    fn auditctl(path: *const libc::c_char) -> libc::c_int;
}

/// The guest's `len` bytes at `addr` when they can be read and `len` is
/// at most `max`; `None` otherwise, for which the host is handed a
/// faulting pointer (a longer `len` is refused before any read).
fn copy_in(ctx: &Ctx<'_>, addr: u64, len: usize, max: usize) -> Option<Vec<u8>> {
    (len <= max).then(|| ctx.read(addr, len).ok()).flatten()
}

/// `audit(record, length)`: submits a user audit record.
pub fn submit(ctx: &mut Ctx<'_>, record: u64, length: u32) -> SysResult {
    let rec = copy_in(ctx, record, length as usize, MAX_AUDIT_RECORD_SIZE);
    let p = rec.as_ref().map_or(std::ptr::null(), |r| r.as_ptr().cast());
    // SAFETY: `p` is null (the host faults on it) or holds `length` bytes.
    check(unsafe { audit(p, length as libc::c_int) })?;
    Ok(Rv::one(0))
}

/// `auditon(cmd, data, length)`: the host's audit controls.
pub fn control(ctx: &mut Ctx<'_>, cmd: i32, data: u64, length: u32) -> SysResult {
    let len = length as usize;
    let mut buf = copy_in(ctx, data, len, AUDITON_MAX);
    let p = buf
        .as_mut()
        .map_or(std::ptr::null_mut(), |b| b.as_mut_ptr().cast());
    // SAFETY: `p` is null (the host faults on it) or holds `length` bytes.
    check(unsafe { auditon(cmd, p, length as libc::c_int) })?;
    if let Some(b) = buf.filter(|_| AUDITON_GETS.contains(&cmd)) {
        // The kernel fails a copy-out of a command's data with ENOSYS.
        ctx.write(data, &b).map_err(|_| Errno::ENOSYS)?;
    }
    Ok(Rv::one(0))
}

/// `getauid(auid)`: the audit user of the credential.
pub fn get_auid(ctx: &mut Ctx<'_>, auid: u64) -> SysResult {
    let mut id = 0u32;
    // SAFETY: `id` is a writable `au_id_t`.
    check(unsafe { getauid(&mut id) })?;
    ctx.write(auid, &id.to_le_bytes())?;
    Ok(Rv::one(0))
}

/// `setauid(auid)`.
pub fn set_auid(ctx: &mut Ctx<'_>, auid: u64) -> SysResult {
    let b = ctx.read(auid, 4)?;
    let id = u32::from_le_bytes(b[..].try_into().expect("4 bytes"));
    // SAFETY: `id` is a readable `au_id_t`.
    check(unsafe { setauid(&id) })?;
    Ok(Rv::one(0))
}

/// `getaudit_addr(aia, length)`: the credential's `auditinfo_addr`, its
/// first `min(length, 48)` bytes.
pub fn get_audit_addr(ctx: &mut Ctx<'_>, aia: u64, length: u32) -> SysResult {
    let mut buf = [0u8; AUDITINFO_ADDR];
    // SAFETY: `buf` holds a whole `auditinfo_addr`, of which the host
    // writes at most `length` bytes.
    check(unsafe { getaudit_addr(buf.as_mut_ptr().cast(), length as libc::c_int) })?;
    ctx.write(aia, &buf[..AUDITINFO_ADDR.min(length as usize)])?;
    Ok(Rv::one(0))
}

/// `setaudit_addr(aia, length)`: when it assigns a session, the kernel
/// writes the credential back.
pub fn set_audit_addr(ctx: &mut Ctx<'_>, aia: u64, length: u32) -> SysResult {
    let n = AUDITINFO_ADDR.min(length as usize);
    let mut buf = [0u8; AUDITINFO_ADDR];
    ctx.read_into(aia, &mut buf[..n])?;
    let asid = i32::from_le_bytes(buf[AI_ASID..AI_ASID + 4].try_into().expect("4 bytes"));
    // SAFETY: `buf` holds a whole `auditinfo_addr`, which the host reads
    // and may write back (at most `length` bytes of it).
    check(unsafe { setaudit_addr(buf.as_mut_ptr().cast(), length as libc::c_int) })?;
    if matches!(asid, AU_DEFAUDITSID | AU_ASSIGN_ASID) {
        ctx.write(aia, &buf[..n])?;
    }
    Ok(Rv::one(0))
}

/// `auditctl(path)`: the file audit records go to. The kernel checks
/// privilege before it reads the path: a path the guest cannot name is
/// handed to the host as a faulting pointer, and its error reported only
/// where the host got as far as reading it.
pub fn control_file(ctx: &mut Ctx<'_>, path: u64) -> SysResult {
    if path == 0 {
        // SAFETY: a null path is refused (EINVAL) after the checks.
        check(unsafe { auditctl(std::ptr::null()) })?;
        return Ok(Rv::one(0));
    }
    let hpath = ctx.path(path).and_then(|p| host::path(&ctx.proc.vfs, &p));
    match hpath {
        Ok(c) => {
            // SAFETY: `c` is NUL-terminated for the call's duration.
            check(unsafe { auditctl(c.as_ptr()) })?;
        }
        Err(e) => {
            // SAFETY: the host faults on `FAULT` when it reads the path.
            return match check(unsafe { auditctl(FAULT as *const libc::c_char) }) {
                Err(Errno::EFAULT) | Ok(_) => Err(e),
                Err(other) => Err(other),
            };
        }
    }
    Ok(Rv::one(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auditinfo_addr_layout_is_the_hosts() {
        // A host `getaudit_addr` writes exactly the struct's 48 bytes: a
        // longer length leaves the bytes after them as they were.
        let mut buf = [0xa5u8; AUDITINFO_ADDR + 8];
        // SAFETY: `buf` holds more than the host writes.
        let r = unsafe { getaudit_addr(buf.as_mut_ptr().cast(), buf.len() as libc::c_int) };
        assert_eq!(r, 0);
        assert!(buf[AUDITINFO_ADDR..].iter().all(|&b| b == 0xa5));
        // `at_type` (at 16) is AU_IPv4 (4) or AU_IPv6 (16).
        let at_type = u32::from_le_bytes(buf[16..20].try_into().unwrap());
        assert!(matches!(at_type, 4 | 16), "at_type {at_type}");
    }
}
