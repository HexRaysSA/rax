//! Code signing: what `csops` and `csops_audittoken` report of the
//! process's executable (`csops_internal` in `bsd/kern/kern_proc.c`; the
//! operations of `bsd/sys/codesign.h` and the flags of
//! `osfmk/kern/cs_blobs.h`).
//!
//! What the kernel reports follows its validation of the executable at
//! exec and the code-signing policy that decides which flags a platform
//! binary, a hardened runtime, or an entitlement brings. The emulated
//! process is a host process, so the answers are the host kernel's own for
//! the same executable: the first query of an image spawns the executable
//! (the slice loaded) suspended on the host, asks every question `csops`
//! answers about it, and kills it before any of its code runs. The
//! process's flags then change as `csops` asks (marking it invalid, hard,
//! killable, or restricted, setting flags, clearing library validation or
//! the installer flag). Without a macOS host, or when the host refuses to
//! spawn the executable, the process is reported as an ad hoc, linker-signed
//! program without entitlements.
//!
//! A query about another process is the host's: another emulated process
//! is a host process running the emulator, whose signature it reports.

use std::sync::Arc;

use crate::user::darwin::abi::Errno;
use crate::user::darwin::arch::{Rv, SysResult};
use crate::user::darwin::process::Proc;
use crate::user::darwin::syscall::Ctx;

/// `CS_OPS_*` (`bsd/sys/codesign.h`).
pub mod ops {
    pub const STATUS: u32 = 0;
    pub const MARKINVALID: u32 = 1;
    pub const MARKHARD: u32 = 2;
    pub const MARKKILL: u32 = 3;
    pub const CDHASH: u32 = 5;
    pub const PIDOFFSET: u32 = 6;
    pub const ENTITLEMENTS_BLOB: u32 = 7;
    pub const MARKRESTRICT: u32 = 8;
    pub const SET_STATUS: u32 = 9;
    pub const BLOB: u32 = 10;
    pub const IDENTITY: u32 = 11;
    pub const CLEARINSTALLER: u32 = 12;
    pub const CLEARPLATFORM: u32 = 13;
    pub const TEAMID: u32 = 14;
    pub const CLEAR_LV: u32 = 15;
    pub const DER_ENTITLEMENTS_BLOB: u32 = 16;
    pub const VALIDATION_CATEGORY: u32 = 17;
    pub const CDHASH_WITH_INFO: u32 = 18;
}

/// Code-signing status flags (`osfmk/kern/cs_blobs.h`).
pub mod cs {
    pub const VALID: u32 = 0x0000_0001;
    pub const ADHOC: u32 = 0x0000_0002;
    pub const INSTALLER: u32 = 0x0000_0008;
    pub const FORCED_LV: u32 = 0x0000_0010;
    pub const HARD: u32 = 0x0000_0100;
    pub const KILL: u32 = 0x0000_0200;
    pub const RESTRICT: u32 = 0x0000_0800;
    pub const ENFORCEMENT: u32 = 0x0000_1000;
    pub const REQUIRE_LV: u32 = 0x0000_2000;
    pub const LINKER_SIGNED: u32 = 0x0002_0000;
    pub const EXEC_SET_HARD: u32 = 0x0010_0000;
    pub const EXEC_SET_KILL: u32 = 0x0020_0000;
    pub const EXEC_SET_ENFORCEMENT: u32 = 0x0040_0000;
    pub const EXEC_INHERIT_SIP: u32 = 0x0080_0000;
    pub const KILLED: u32 = 0x0100_0000;
    pub const DEBUGGED: u32 = 0x1000_0000;
    pub const SIGNED: u32 = 0x2000_0000;
    pub const DATAVAULT_CONTROLLER: u32 = 0x8000_0000;
}

/// `CLEAR_LV_ENTITLEMENT`.
const CLEAR_LV_ENTITLEMENT: &str = "com.apple.private.security.clear-library-validation";

/// A blob `csops` copies out, or the error the host gave: `Ok(None)` when
/// the call succeeds without writing anything (no entitlements).
type Blob = Result<Option<Vec<u8>>, Errno>;

/// What the host kernel reports of an executable.
#[derive(Clone, Debug)]
pub struct Signature {
    /// `CS_OPS_STATUS` at exec.
    pub flags: u32,
    /// `CS_OPS_CDHASH`.
    pub cdhash: Result<[u8; 20], Errno>,
    /// `CS_OPS_CDHASH_WITH_INFO`: the hash and its type
    /// (`csops_cdhash_t`, 21 bytes); the macOS 27 kernel refuses it.
    pub cdhash_info: Result<([u8; 20], u8), Errno>,
    /// `CS_OPS_PIDOFFSET`: the slice's offset in the file.
    pub pidoffset: u64,
    /// `CS_OPS_ENTITLEMENTS_BLOB`.
    pub entitlements: Blob,
    /// `CS_OPS_DER_ENTITLEMENTS_BLOB`.
    pub der: Blob,
    /// `CS_OPS_BLOB`.
    pub blob: Blob,
    /// `CS_OPS_IDENTITY`, without its NUL.
    pub identity: Result<Vec<u8>, Errno>,
    /// `CS_OPS_TEAMID`, without its NUL.
    pub teamid: Result<Vec<u8>, Errno>,
    /// `CS_OPS_VALIDATION_CATEGORY`.
    pub category: Result<u32, Errno>,
}

impl Signature {
    /// An ad hoc, linker-signed executable without entitlements, when the
    /// host cannot tell.
    fn fallback() -> Self {
        Signature {
            flags: cs::VALID | cs::ADHOC | cs::LINKER_SIGNED | cs::SIGNED,
            cdhash: Err(Errno::ENOENT),
            cdhash_info: Err(Errno::EINVAL),
            pidoffset: 0,
            entitlements: Ok(None),
            der: Ok(None),
            blob: Err(Errno::ENOENT),
            identity: Err(Errno::ENOENT),
            teamid: Err(Errno::ENOENT),
            category: Err(Errno::EINVAL),
        }
    }

    /// Whether the entitlements hold `key` with the value true
    /// (`IOTaskHasEntitlement`).
    fn has_entitlement(&self, key: &str) -> bool {
        let Ok(Some(xml)) = &self.entitlements else {
            return false;
        };
        let text = String::from_utf8_lossy(xml.get(8..).unwrap_or_default());
        let tag = format!("<key>{key}</key>");
        text.find(&tag)
            .is_some_and(|i| text[i + tag.len()..].trim_start().starts_with("<true/>"))
    }
}

/// A process's code signing: the signature of its executable and its
/// flags now.
#[derive(Clone, Debug)]
pub struct CodeSign {
    pub flags: u32,
    pub sig: Arc<Signature>,
}

/// The process's code signing, learned on first use.
fn state(proc: &mut Proc) -> &mut CodeSign {
    if proc.codesign.is_none() {
        let sig = harvest(proc).unwrap_or_else(Signature::fallback);
        proc.codesign = Some(CodeSign {
            flags: sig.flags,
            sig: Arc::new(sig),
        });
    }
    proc.codesign.as_mut().expect("just set")
}

/// `csops(pid, ops, useraddr, usersize)`, and `csops_audittoken` with the
/// audit token at `token`.
pub fn csops(
    ctx: &mut Ctx<'_>,
    pid: i32,
    op: u32,
    uaddr: u64,
    usize: u64,
    token: Option<u64>,
) -> SysResult {
    let me = ctx.proc.pid;
    let pid = if pid == 0 { me } else { pid };
    let forself = pid == me;
    let query = matches!(
        op,
        ops::STATUS
            | ops::CDHASH
            | ops::CDHASH_WITH_INFO
            | ops::PIDOFFSET
            | ops::ENTITLEMENTS_BLOB
            | ops::DER_ENTITLEMENTS_BLOB
            | ops::IDENTITY
            | ops::BLOB
            | ops::TEAMID
            | ops::CLEAR_LV
            | ops::VALIDATION_CATEGORY
    );
    if !query && !forself && ctx.proc.creds.1 != 0 {
        return Err(Errno::EPERM);
    }
    if !forself {
        return host_csops(ctx, pid, op, uaddr, usize, token);
    }
    if let Some(t) = token {
        let b = ctx.read(t, 32)?;
        let word = |i: usize| u32::from_le_bytes(b[4 * i..4 * i + 4].try_into().expect("4 bytes"));
        // The token's pid and pid version must be the process's.
        if word(5) != me as u32 || word(7) != ctx.proc.audit[7] {
            return Err(Errno::ESRCH);
        }
    }
    let cs = state(ctx.proc).clone();
    let (flags, sig) = (cs.flags, cs.sig);
    let set = |ctx: &mut Ctx<'_>, f: u32| {
        if let Some(c) = &mut ctx.proc.codesign {
            c.flags = f;
        }
    };
    let signed = flags & (cs::VALID | cs::DEBUGGED) != 0;
    match op {
        ops::STATUS => {
            // Library validation the kernel forced on is reported only as
            // forced.
            let shown = if flags & cs::FORCED_LV != 0 {
                flags & !cs::REQUIRE_LV
            } else {
                flags
            };
            if uaddr != 0 {
                ctx.write(uaddr, &shown.to_le_bytes())?;
            }
        }
        ops::MARKINVALID => {
            if flags & cs::VALID != 0 {
                let kill = flags & cs::KILL != 0;
                set(
                    ctx,
                    (flags & !cs::VALID) | if kill { cs::KILLED } else { 0 },
                );
                if kill {
                    kill_self(ctx);
                }
            }
        }
        ops::MARKHARD => {
            set(ctx, flags | cs::HARD);
            if flags & cs::VALID == 0 {
                return Err(Errno::EINVAL);
            }
        }
        ops::MARKKILL => {
            set(ctx, flags | cs::KILL);
            if flags & cs::VALID == 0 {
                kill_self(ctx);
            }
        }
        ops::MARKRESTRICT => set(ctx, flags | cs::RESTRICT),
        ops::SET_STATUS => {
            if usize < 4 {
                return Err(Errno::ERANGE);
            }
            let want = ctx.read_u32(uaddr)?
                & (cs::HARD
                    | cs::EXEC_SET_HARD
                    | cs::KILL
                    | cs::EXEC_SET_KILL
                    | cs::RESTRICT
                    | cs::REQUIRE_LV
                    | cs::ENFORCEMENT
                    | cs::EXEC_SET_ENFORCEMENT);
            if flags & cs::VALID == 0 {
                return Err(Errno::EINVAL);
            }
            set(ctx, flags | want);
        }
        ops::CLEAR_LV => {
            // macOS drops library validation for a process entitled to.
            if !sig.has_entitlement(CLEAR_LV_ENTITLEMENT) || flags & cs::INSTALLER != 0 {
                return Err(Errno::EPERM);
            }
            set(ctx, flags & !(cs::REQUIRE_LV | cs::FORCED_LV));
        }
        ops::CLEARINSTALLER => set(
            ctx,
            flags & !(cs::INSTALLER | cs::DATAVAULT_CONTROLLER | cs::EXEC_INHERIT_SIP),
        ),
        // Only a development kernel clears it.
        ops::CLEARPLATFORM => return Err(Errno::ENOTSUP),
        ops::PIDOFFSET => ctx.write(uaddr, &sig.pidoffset.to_le_bytes())?,
        ops::CDHASH | ops::CDHASH_WITH_INFO => {
            let size = if op == ops::CDHASH { 20 } else { 21 };
            if usize != size {
                return Err(Errno::EINVAL);
            }
            let out = if op == ops::CDHASH {
                sig.cdhash.clone()?.to_vec()
            } else {
                let (hash, kind) = sig.cdhash_info.clone()?;
                let mut out = hash.to_vec();
                out.push(kind);
                out
            };
            ctx.write(uaddr, &out)?;
        }
        ops::ENTITLEMENTS_BLOB | ops::DER_ENTITLEMENTS_BLOB | ops::BLOB => {
            if !signed {
                return Err(Errno::EINVAL);
            }
            let blob = match op {
                ops::ENTITLEMENTS_BLOB => &sig.entitlements,
                ops::DER_ENTITLEMENTS_BLOB => &sig.der,
                _ => &sig.blob,
            };
            if let Some(b) = blob.clone()? {
                copy_token(ctx, &b, uaddr, usize)?;
            }
        }
        ops::IDENTITY | ops::TEAMID => {
            if usize < 8 {
                return Err(Errno::ERANGE);
            }
            if !signed {
                return Err(Errno::EINVAL);
            }
            let id = if op == ops::IDENTITY {
                sig.identity.clone()?
            } else {
                sig.teamid.clone()?
            };
            // A blob header with the length, NUL and header included.
            let len = id.len() as u64 + 1;
            let mut header = [0u8; 8];
            header[4..8].copy_from_slice(&((len + 8) as u32).to_be_bytes());
            ctx.write(uaddr, &header)?;
            if usize < 8 + len {
                return Err(Errno::ERANGE);
            }
            let mut text = id;
            text.push(0);
            ctx.write(uaddr + 8, &text)?;
        }
        ops::VALIDATION_CATEGORY => {
            let c = sig.category?;
            ctx.write(uaddr, &c.to_le_bytes())?;
        }
        _ => return Err(Errno::EINVAL),
    }
    Ok(Rv::one(0))
}

/// `csops_copy_token`: the blob, or (a buffer too small for it) a blob
/// header with its length and `ERANGE`.
fn copy_token(ctx: &mut Ctx<'_>, blob: &[u8], uaddr: u64, usize: u64) -> Result<(), Errno> {
    if usize < 8 {
        return Err(Errno::ERANGE);
    }
    if usize < blob.len() as u64 {
        let mut header = [0u8; 8];
        header[4..8].copy_from_slice(&(blob.len() as u32).to_be_bytes());
        ctx.write(uaddr, &header)?;
        return Err(Errno::ERANGE);
    }
    ctx.write(uaddr, blob)
}

/// A process whose signature went invalid while it had `CS_KILL` dies.
fn kill_self(ctx: &mut Ctx<'_>) {
    let origin = crate::user::darwin::signal::Origin::KERNEL;
    crate::user::darwin::signal::psignal(
        ctx.proc,
        Some(&mut *ctx.thread),
        crate::user::darwin::signal::SIGKILL,
        origin,
    );
}

/// A query about another process: the host's.
fn host_csops(
    ctx: &mut Ctx<'_>,
    pid: i32,
    op: u32,
    uaddr: u64,
    usize: u64,
    token: Option<u64>,
) -> SysResult {
    #[cfg(target_os = "macos")]
    {
        unsafe extern "C" {
            fn csops(pid: i32, ops: u32, addr: *mut u8, size: usize) -> i32;
            fn csops_audittoken(
                pid: i32,
                ops: u32,
                addr: *mut u8,
                size: usize,
                token: *mut u8,
            ) -> i32;
        }
        // The guest's buffer, as the host may leave parts of it alone.
        let n = usize.min(64 << 20) as usize;
        let mut buf = if uaddr != 0 && n > 0 {
            ctx.read(uaddr, n)?
        } else {
            Vec::new()
        };
        let mut t = match token {
            Some(t) => Some(ctx.read(t, 32)?),
            None => None,
        };
        let p = if buf.is_empty() {
            std::ptr::null_mut()
        } else {
            buf.as_mut_ptr()
        };
        // SAFETY: `p` holds `buf.len()` bytes (or is null for none) and
        // the token 32 bytes, both live for the call.
        let r = unsafe {
            match &mut t {
                Some(t) => csops_audittoken(pid, op, p, buf.len(), t.as_mut_ptr()),
                None => csops(pid, op, p, buf.len()),
            }
        };
        let err = (r != 0).then(Errno::last);
        if !buf.is_empty() {
            ctx.write(uaddr, &buf)?;
        }
        match err {
            Some(e) => Err(e),
            None => Ok(Rv::one(0)),
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (ctx, pid, op, uaddr, usize, token);
        Err(Errno::ESRCH)
    }
}

/// Spawns the process's executable suspended on the host and asks the
/// host kernel what `csops` tells about it; `None` when the host cannot.
fn harvest(proc: &mut Proc) -> Option<Signature> {
    #[cfg(target_os = "macos")]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        unsafe extern "C" {
            fn posix_spawnattr_setarchpref_np(
                attr: *mut libc::posix_spawnattr_t,
                count: usize,
                pref: *const i32,
                subpref: *const i32,
                ocount: *mut usize,
            ) -> i32;
        }
        let path = CString::new(proc.program.image.host_path.as_os_str().as_bytes()).ok()?;
        let header = &proc.program.main.header;
        let (cpu, sub) = (header.cputype as i32, header.cpusubtype as i32);
        let mut pid: libc::pid_t = 0;
        // SAFETY: the attributes are initialized before use and destroyed
        // after; `argv` and `envp` are NULL-terminated arrays of live C
        // strings.
        let r = unsafe {
            let mut attr: libc::posix_spawnattr_t = std::mem::zeroed();
            libc::posix_spawnattr_init(&mut attr);
            // POSIX_SPAWN_START_SUSPENDED | POSIX_SPAWN_CLOEXEC_DEFAULT.
            libc::posix_spawnattr_setflags(&mut attr, (0x0080 | 0x4000) as libc::c_short);
            let mut done = 0usize;
            posix_spawnattr_setarchpref_np(&mut attr, 1, &cpu, &sub, &mut done);
            let argv = [path.as_ptr() as *mut libc::c_char, std::ptr::null_mut()];
            let envp = [std::ptr::null_mut::<libc::c_char>()];
            let r = libc::posix_spawn(
                &mut pid,
                path.as_ptr(),
                std::ptr::null(),
                &attr,
                argv.as_ptr(),
                envp.as_ptr(),
            );
            libc::posix_spawnattr_destroy(&mut attr);
            r
        };
        if r != 0 {
            return None;
        }
        // Its SIGCHLD is not the guest's.
        proc.hidden.insert(pid);
        let sig = ask(pid);
        // SAFETY: `pid` is the suspended child spawned above.
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            // Reaped here, never the guest's to wait for: the emulator's
            // signal handlers (its SIGCHLD's among them) interrupt the wait.
            let mut status = 0;
            while libc::waitpid(pid, &mut status, 0) < 0
                && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR)
            {}
        }
        sig
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = proc;
        None
    }
}

/// Every answer `csops` gives about host process `pid`.
#[cfg(target_os = "macos")]
fn ask(pid: i32) -> Option<Signature> {
    unsafe extern "C" {
        fn csops(pid: i32, ops: u32, addr: *mut u8, size: usize) -> i32;
    }
    let call = |op: u32, buf: &mut [u8]| -> Result<(), Errno> {
        // SAFETY: `buf` holds `buf.len()` writable bytes.
        let r = unsafe { csops(pid, op, buf.as_mut_ptr(), buf.len()) };
        if r == 0 { Ok(()) } else { Err(Errno::last()) }
    };
    let mut word = [0u8; 4];
    call(ops::STATUS, &mut word).ok()?;
    let flags = u32::from_le_bytes(word);
    let mut hash = [0u8; 20];
    let cdhash = call(ops::CDHASH, &mut hash).map(|()| hash);
    let mut info = [0u8; 21];
    let cdhash_info = call(ops::CDHASH_WITH_INFO, &mut info).map(|()| {
        let mut h = [0u8; 20];
        h.copy_from_slice(&info[..20]);
        (h, info[20])
    });
    let mut off = [0u8; 8];
    let pidoffset = call(ops::PIDOFFSET, &mut off).map_or(0, |()| u64::from_le_bytes(off));
    // A blob: an 8-byte probe first; ERANGE says how long it is.
    let blob = |op: u32| -> Blob {
        const MARK: u8 = 0xa5;
        let mut probe = [MARK; 8];
        match call(op, &mut probe) {
            Ok(()) if probe == [MARK; 8] => Ok(None),
            Ok(()) => Ok(Some(probe.to_vec())),
            Err(e) if e == Errno::ERANGE => {
                let len = u32::from_be_bytes(probe[4..8].try_into().expect("4 bytes")) as usize;
                let mut full = vec![0u8; len.max(8)];
                call(op, &mut full)?;
                Ok(Some(full))
            }
            Err(e) => Err(e),
        }
    };
    // An identity: the header gives the length, NUL and header included.
    let text = |op: u32| -> Result<Vec<u8>, Errno> {
        let mut probe = [0u8; 8];
        match call(op, &mut probe) {
            Err(e) if e == Errno::ERANGE => {}
            Err(e) => return Err(e),
            Ok(()) => return Ok(Vec::new()),
        }
        let len = u32::from_be_bytes(probe[4..8].try_into().expect("4 bytes")) as usize;
        let mut full = vec![0u8; len.max(9)];
        call(op, &mut full)?;
        let s = &full[8..];
        Ok(s[..s.iter().position(|&c| c == 0).unwrap_or(s.len())].to_vec())
    };
    let category = call(ops::VALIDATION_CATEGORY, &mut word).map(|()| u32::from_le_bytes(word));
    Some(Signature {
        flags,
        cdhash,
        cdhash_info,
        pidoffset,
        entitlements: blob(ops::ENTITLEMENTS_BLOB),
        der: blob(ops::DER_ENTITLEMENTS_BLOB),
        blob: blob(ops::BLOB),
        identity: text(ops::IDENTITY),
        teamid: text(ops::TEAMID),
        category,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entitlements_are_found_by_key_and_value() {
        let xml = b"<?xml version=\"1.0\"?><plist><dict>\
            <key>com.apple.private.security.clear-library-validation</key>\n <true/>\
            <key>com.apple.security.cs.allow-jit</key><false/></dict></plist>";
        let mut blob = vec![0xfa, 0xde, 0x71, 0x71, 0, 0, 0, 0];
        blob.extend_from_slice(xml);
        let sig = Signature {
            entitlements: Ok(Some(blob)),
            ..Signature::fallback()
        };
        assert!(sig.has_entitlement(CLEAR_LV_ENTITLEMENT));
        assert!(!sig.has_entitlement("com.apple.security.cs.allow-jit"));
        assert!(!sig.has_entitlement("com.apple.security.get-task-allow"));
        assert!(!Signature::fallback().has_entitlement(CLEAR_LV_ENTITLEMENT));
    }
}
