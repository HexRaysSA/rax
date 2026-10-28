//! Code signing: what `csops` and `csops_audittoken` report of the
//! process's executable (`csops_internal` in `bsd/kern/kern_proc.c`; the
//! operations of `bsd/sys/codesign.h` and the flags of
//! `osfmk/kern/cs_blobs.h`).
//!
//! What the kernel reports follows its validation of the executable at
//! exec and the code-signing policy that decides which flags a platform
//! binary, a hardened runtime, or an entitlement brings. The emulated
//! legacy host-services process is a host process, so the answers are the
//! host kernel's own for the same executable: the first query of an image,
//! or trace setup, spawns
//! the executable (the slice loaded) suspended on the host, asks every
//! question `csops` answers about it, and kills it before any of its code runs. The
//! process's flags then change as `csops` asks (marking it invalid, hard,
//! killable, or restricted, setting flags, clearing library validation or
//! the installer flag). Without a macOS host, or when the host refuses to
//! spawn the executable, the process is reported as an ad hoc, linker-signed
//! program without entitlements.
//!
//! Closed processes retain supplied signing state or the existing fallback;
//! they never spawn a host image to sample it. Foreign-process queries in the
//! closed profile return ESRCH before forwarding guest buffers to the host.
//! In the host-services profile, a status query about a connected guest child
//! uses published guest flags when available. Other cross-process queries are
//! the host's.

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
    pub const GET_TASK_ALLOW: u32 = 0x0000_0004;
    pub const INSTALLER: u32 = 0x0000_0008;
    pub const FORCED_LV: u32 = 0x0000_0010;
    pub const INVALID_ALLOWED: u32 = 0x0000_0020;
    pub const HARD: u32 = 0x0000_0100;
    pub const KILL: u32 = 0x0000_0200;
    pub const RESTRICT: u32 = 0x0000_0800;
    pub const ENFORCEMENT: u32 = 0x0000_1000;
    pub const REQUIRE_LV: u32 = 0x0000_2000;
    pub const RUNTIME: u32 = 0x0001_0000;
    pub const LINKER_SIGNED: u32 = 0x0002_0000;
    pub const EXEC_SET_HARD: u32 = 0x0010_0000;
    pub const EXEC_SET_KILL: u32 = 0x0020_0000;
    pub const EXEC_SET_ENFORCEMENT: u32 = 0x0040_0000;
    pub const EXEC_INHERIT_SIP: u32 = 0x0080_0000;
    pub const KILLED: u32 = 0x0100_0000;
    pub const PLATFORM_BINARY: u32 = 0x0400_0000;
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
    #[cfg(unix)]
    if let Some(signing) = &proc.codesign {
        super::syscall::bsd::ptrace::publish_codesign(&proc.tracing, signing.flags);
    }
    #[cfg(unix)]
    super::syscall::bsd::ptrace::sync_codesign(proc);
    proc.codesign.as_mut().expect("just set")
}

/// Makes the new image's signing status visible before a traced exec stop.
pub(crate) fn prepare_traced_exec(proc: &mut Proc) {
    let _ = state(proc);
}

/// Loads signing state before `PT_TRACE_ME` checks, carrying host-observed
/// flags and debugging policy rather than treating fallback flags as evidence.
pub(crate) fn prepare_trace_me(proc: &mut Proc) -> Option<TraceObservation> {
    let observed = harvest(proc);
    let flags = prepare_trace_signing(proc, observed)?;
    Some(TraceObservation {
        flags,
        unrestricted_debugging: host_debugging_allowed(proc),
    })
}

/// Signing flags checked against a comparable cached CDHash, plus the host's
/// read-only debugging-policy check. Missing/fallback signing and a detected
/// CDHash replacement cannot create this observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TraceObservation {
    flags: u32,
    unrestricted_debugging: bool,
}

impl TraceObservation {
    pub(crate) fn allows_unrestricted_debugging(self) -> bool {
        // The qualified native samples are third-party images. Do not extend
        // their policy result to platform binaries without a native oracle.
        self.unrestricted_debugging && self.flags & cs::PLATFORM_BINARY == 0
    }
}

fn host_debugging_allowed(proc: &Proc) -> bool {
    if !proc.config.host_services {
        return false;
    }
    #[cfg(target_os = "macos")]
    {
        unsafe extern "C" {
            fn csr_check(mask: u32) -> i32;
        }
        // bsd/sys/csr.h: CSR_ALLOW_TASK_FOR_PID. Only a successful check
        // selects the observed unrestricted debugging profile; errors retain
        // the existing restricted profile. This does not change host policy.
        // SAFETY: a scalar, read-only libSystem query with no retained pointers.
        unsafe { csr_check(1 << 2) == 0 }
    }
    #[cfg(not(target_os = "macos"))]
    false
}

fn prepare_trace_signing(proc: &mut Proc, observed: Option<Signature>) -> Option<u32> {
    let observed_flags = observed.as_ref().and_then(|signature| {
        if let Some(current) = &proc.codesign
            && let (Ok(original), Ok(fresh)) = (&current.sig.cdhash, &signature.cdhash)
            && original != fresh
        {
            // The path now names a different image; its policy is not
            // evidence for the image already running in the guest.
            return None;
        }
        Some(signature.flags)
    });
    if proc.codesign.is_none() {
        let signature = observed.unwrap_or_else(Signature::fallback);
        proc.codesign = Some(CodeSign {
            flags: signature.flags,
            sig: Arc::new(signature),
        });
    }
    #[cfg(unix)]
    if let Some(current) = &proc.codesign {
        super::syscall::bsd::ptrace::publish_codesign(&proc.tracing, current.flags);
    }
    #[cfg(unix)]
    super::syscall::bsd::ptrace::sync_codesign(proc);
    observed_flags
}

/// Applies the observed `cs_allow_invalid` transition after `PT_TRACE_ME`.
/// Policy admission generalizes limited host probes; a fallback signature
/// is not evidence that the hook would allow the transition.
pub(crate) fn trace_me_allow_invalid(proc: &mut Proc, observed: Option<TraceObservation>) {
    if !proc.config.host_services {
        return;
    }
    let Some(observed) = observed else {
        return;
    };
    let observed_flags = observed.flags;
    let unrestricted_debugging = observed.allows_unrestricted_debugging();
    let rosetta_zero = cfg!(all(target_os = "macos", target_arch = "aarch64"))
        && proc.abi == crate::user::darwin::abi::DarwinAbi::X86_64
        && observed_flags == 0;
    let Some(current) = &mut proc.codesign else {
        return;
    };
    let allowed = (unrestricted_debugging || observed_trace_policy(observed_flags, rosetta_zero))
        && current.flags & cs::PLATFORM_BINARY == 0
        && (unrestricted_debugging
            || current.flags & cs::RESTRICT == 0
            || current.flags & cs::GET_TASK_ALLOW != 0);
    if allowed {
        current.flags = trace_invalid_flags(current.flags);
    }
    #[cfg(unix)]
    super::syscall::bsd::ptrace::publish_codesign(&proc.tracing, current.flags);
    #[cfg(unix)]
    super::syscall::bsd::ptrace::sync_codesign(proc);
}

fn observed_trace_policy(signature_flags: u32, rosetta_zero: bool) -> bool {
    let platform = signature_flags & cs::PLATFORM_BINARY != 0;
    let restricted = signature_flags & cs::RESTRICT != 0;
    !platform
        && (signature_flags & cs::GET_TASK_ALLOW != 0
            || (!restricted
                && ((signature_flags & cs::VALID != 0 && signature_flags & cs::RUNTIME == 0)
                    || (rosetta_zero && signature_flags == 0))))
}

/// The flags after the policy hook permits debugging invalid pages.
fn trace_invalid_flags(flags: u32) -> u32 {
    let mut result = (flags & !(cs::KILL | cs::HARD)) | cs::INVALID_ALLOWED;
    if flags & cs::VALID != 0 {
        result |= cs::DEBUGGED;
    }
    result
}

/// `CS_OPS_STATUS` reports forced library validation without the redundant
/// ordinary library-validation bit.
fn shown_flags(flags: u32) -> u32 {
    if flags & cs::FORCED_LV != 0 {
        flags & !cs::REQUIRE_LV
    } else {
        flags
    }
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
        let result = host_csops(ctx, pid, op, uaddr, usize, token);
        #[cfg(unix)]
        if result.is_ok()
            && op == ops::STATUS
            && uaddr != 0
            && usize >= 4
            && let Some(flags) =
                super::syscall::bsd::ptrace::known_child_codesign(&ctx.proc.tracing, pid)
        {
            ctx.write_u32(uaddr, shown_flags(flags))?;
        }
        return result;
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
        #[cfg(unix)]
        super::syscall::bsd::ptrace::publish_codesign(&ctx.proc.tracing, f);
        #[cfg(unix)]
        super::syscall::bsd::ptrace::sync_codesign(ctx.proc);
    };
    let signed = flags & (cs::VALID | cs::DEBUGGED) != 0;
    match op {
        ops::STATUS => {
            // Library validation the kernel forced on is reported only as
            // forced.
            let shown = shown_flags(flags);
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
    if !ctx.proc.config.host_services {
        return Err(Errno::ESRCH);
    }
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
    if !proc.config.host_services {
        return None;
    }
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
        // Reaped here, never the guest's to wait for. A SIGKILL can race
        // the new process's suspension and be lost (psignal's SIGKILL case
        // notes such races), leaving it suspended forever, so the signal
        // is sent again until the child is gone; the unreaped child keeps
        // its pid, so every signal reaches it. The emulator's signal
        // handlers (its SIGCHLD's among them) may interrupt the wait.
        let mut status = 0;
        loop {
            // SAFETY: `pid` is the unreaped child spawned above.
            let r = unsafe {
                libc::kill(pid, libc::SIGKILL);
                libc::waitpid(pid, &mut status, libc::WNOHANG)
            };
            if r == pid
                || (r < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR))
            {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
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
    fn closed_trace_preparation_does_not_spawn_a_host_image() {
        use crate::user::darwin::abi::DarwinAbi;
        use crate::user::darwin::process::bounded_tests::process;

        let host_image = std::env::current_exe().unwrap();
        for abi in [DarwinAbi::Arm64, DarwinAbi::X86_64] {
            let mut guest = process(abi);
            assert!(!guest.proc.config.host_services);
            // Even an existing host image must not enable native sampling
            // for caller-supplied guest bytes in the closed profile.
            guest.proc.program.image.host_path = host_image.clone();
            assert_eq!(prepare_trace_me(&mut guest.proc), None);
            assert_eq!(
                guest.proc.codesign.as_ref().unwrap().flags,
                Signature::fallback().flags
            );
            assert!(guest.proc.hidden.is_empty());
        }
    }

    #[test]
    fn closed_foreign_signing_query_stops_before_host_buffer_forwarding() {
        use crate::user::darwin::abi::DarwinAbi;
        use crate::user::darwin::process::bounded_tests::process;

        let mut guest = process(DarwinAbi::Arm64);
        guest.proc.pid = 1;
        let (_, mut thread) = guest.proc.threads.pop_first().unwrap();
        let mut ctx = Ctx {
            proc: &mut guest.proc,
            thread: &mut thread,
            nr: 169,
            pc: 0,
        };
        assert_eq!(
            csops(&mut ctx, 2, ops::STATUS, u64::MAX, 4, None),
            Err(Errno::ESRCH)
        );
        assert!(ctx.proc.codesign.is_none());
    }

    #[test]
    fn trace_preparation_initializes_signing_without_replacing_existing_flags() {
        use crate::user::darwin::abi::DarwinAbi;
        use crate::user::darwin::process::bounded_tests::process;

        let mut guest = process(DarwinAbi::Arm64);
        let mut signature = Signature::fallback();
        signature.flags = cs::VALID | cs::RESTRICT;
        assert_eq!(
            prepare_trace_signing(&mut guest.proc, Some(signature.clone())),
            Some(cs::VALID | cs::RESTRICT)
        );
        assert_eq!(
            guest.proc.codesign.as_ref().unwrap().flags,
            cs::VALID | cs::RESTRICT
        );
        guest.proc.codesign.as_mut().unwrap().flags |= cs::HARD;
        assert_eq!(
            prepare_trace_signing(&mut guest.proc, Some(signature)),
            Some(cs::VALID | cs::RESTRICT)
        );
        assert_eq!(
            guest.proc.codesign.as_ref().unwrap().flags,
            cs::VALID | cs::RESTRICT | cs::HARD
        );
        let mut unknown = process(DarwinAbi::Arm64);
        assert_eq!(prepare_trace_signing(&mut unknown.proc, None), None);
        assert!(unknown.proc.codesign.is_some());

        let mut original = Signature::fallback();
        original.cdhash = Ok([1; 20]);
        let mut replacement = original.clone();
        replacement.cdhash = Ok([2; 20]);
        let mut replaced = process(DarwinAbi::Arm64);
        assert_eq!(
            prepare_trace_signing(&mut replaced.proc, Some(original)),
            Some(Signature::fallback().flags)
        );
        assert_eq!(
            prepare_trace_signing(&mut replaced.proc, Some(replacement)),
            None
        );
    }

    #[test]
    fn trace_flags_change_only_the_observed_fields() {
        let initial = 0x2202_0201;
        assert_eq!(trace_invalid_flags(initial), 0x3202_0021);
        assert_eq!(trace_invalid_flags(0), cs::INVALID_ALLOWED);
        assert_eq!(
            trace_invalid_flags(cs::HARD | cs::KILL | cs::RUNTIME),
            cs::RUNTIME | cs::INVALID_ALLOWED
        );
        assert!(observed_trace_policy(cs::VALID | cs::LINKER_SIGNED, false));
        assert!(observed_trace_policy(cs::VALID | cs::SIGNED, false));
        assert!(!observed_trace_policy(
            cs::VALID | cs::LINKER_SIGNED | cs::RUNTIME,
            false
        ));
        assert!(!observed_trace_policy(
            cs::VALID | cs::PLATFORM_BINARY,
            false
        ));
        assert!(!observed_trace_policy(cs::VALID | cs::RESTRICT, false));
        assert!(observed_trace_policy(
            cs::RESTRICT | cs::GET_TASK_ALLOW,
            false
        ));
        assert!(!observed_trace_policy(
            cs::GET_TASK_ALLOW | cs::PLATFORM_BINARY,
            false
        ));
        assert!(observed_trace_policy(
            cs::GET_TASK_ALLOW | cs::RUNTIME,
            false
        ));
        assert!(!observed_trace_policy(0, false));
        assert!(observed_trace_policy(0, true));
        assert!(!observed_trace_policy(cs::RUNTIME, true));
    }

    #[test]
    fn native_trace_transitions_follow_the_observed_debugging_profile() {
        use crate::user::darwin::abi::DarwinAbi;
        use crate::user::darwin::process::bounded_tests::process;

        // Captured native CI transitions: hardened runtime, signature-restricted,
        // runtime-restricted ARM64, and runtime-restricted Rosetta x86-64.
        for abi in [DarwinAbi::Arm64, DarwinAbi::X86_64] {
            for (before, after) in [
                (0x2201_0001, 0x3201_0021),
                (0x2200_0801, 0x3200_0821),
                (0x2202_0801, 0x3202_0821),
                (0x0000_0800, 0x0000_0820),
            ] {
                for unrestricted_debugging in [false, true] {
                    let mut guest = process(abi);
                    guest.proc.config.host_services = true;
                    let mut signature = Signature::fallback();
                    signature.flags = before;
                    guest.proc.codesign = Some(CodeSign {
                        flags: before,
                        sig: Arc::new(signature),
                    });
                    let observed = TraceObservation {
                        flags: before,
                        unrestricted_debugging,
                    };
                    trace_me_allow_invalid(&mut guest.proc, Some(observed));
                    assert_eq!(
                        guest.proc.codesign.as_ref().unwrap().flags,
                        if unrestricted_debugging {
                            after
                        } else {
                            before
                        },
                        "{abi:?} before={before:08x} unrestricted={unrestricted_debugging}"
                    );
                }
            }
        }
    }

    #[test]
    fn unrestricted_debugging_keeps_platform_and_closed_boundaries() {
        use crate::user::darwin::abi::DarwinAbi;
        use crate::user::darwin::process::bounded_tests::process;

        for closed in [false, true] {
            for platform in [false, true] {
                let mut guest = process(DarwinAbi::Arm64);
                guest.proc.config.host_services = !closed;
                let before =
                    cs::VALID | cs::RUNTIME | if platform { cs::PLATFORM_BINARY } else { 0 };
                let mut signature = Signature::fallback();
                signature.flags = before;
                guest.proc.codesign = Some(CodeSign {
                    flags: before,
                    sig: Arc::new(signature),
                });
                let observed = TraceObservation {
                    flags: before,
                    unrestricted_debugging: true,
                };
                assert_eq!(observed.allows_unrestricted_debugging(), !platform);
                trace_me_allow_invalid(&mut guest.proc, None);
                assert_eq!(guest.proc.codesign.as_ref().unwrap().flags, before);
                trace_me_allow_invalid(&mut guest.proc, Some(observed));
                assert_eq!(
                    guest.proc.codesign.as_ref().unwrap().flags,
                    if closed || platform {
                        before
                    } else {
                        0x1001_0021
                    }
                );
                if closed {
                    assert!(!host_debugging_allowed(&guest.proc));
                }
            }
        }
    }

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
