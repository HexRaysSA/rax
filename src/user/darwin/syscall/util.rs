//! The system-call context and guest-memory helpers.

use super::super::abi::Errno;
use super::super::arch::SysResult;
use super::super::process::{Proc, Thread};
use crate::user::mm::AddressSpace;

/// `MAXPATHLEN`.
pub const MAXPATHLEN: usize = 1024;

/// What a handler works with: the process, the calling thread, and the
/// call's identity.
pub struct Ctx<'a> {
    /// The process.
    pub proc: &'a mut Proc,
    /// The calling thread (not in `proc.threads` while it runs).
    pub thread: &'a mut Thread,
    /// The call's number (BSD number, or the negated Mach trap).
    pub nr: i64,
    /// PC of the trap instruction's successor.
    pub pc: u64,
}

impl Ctx<'_> {
    /// The address space.
    pub fn space(&self) -> &AddressSpace {
        &self.proc.space
    }

    /// Copies `len` bytes from the guest (`EFAULT` when unmapped or
    /// unreadable).
    pub fn read(&self, addr: u64, len: usize) -> Result<Vec<u8>, Errno> {
        let mut buf = vec![0u8; len];
        self.read_into(addr, &mut buf)?;
        Ok(buf)
    }

    /// Copies guest bytes into `buf`.
    pub fn read_into(&self, addr: u64, buf: &mut [u8]) -> Result<(), Errno> {
        if buf.is_empty() {
            return Ok(());
        }
        self.proc.space.read(addr, buf).map_err(|_| Errno::EFAULT)
    }

    /// Copies `data` to the guest (`EFAULT` when unmapped or read-only).
    pub fn write(&self, addr: u64, data: &[u8]) -> Result<(), Errno> {
        if data.is_empty() {
            return Ok(());
        }
        self.proc.space.write(addr, data).map_err(|_| Errno::EFAULT)
    }

    /// Reads a little-endian `u32`.
    pub fn read_u32(&self, addr: u64) -> Result<u32, Errno> {
        let mut b = [0u8; 4];
        self.read_into(addr, &mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    /// Reads a little-endian `u64`.
    pub fn read_u64(&self, addr: u64) -> Result<u64, Errno> {
        let mut b = [0u8; 8];
        self.read_into(addr, &mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    /// Writes a little-endian `u32`.
    pub fn write_u32(&self, addr: u64, v: u32) -> Result<(), Errno> {
        self.write(addr, &v.to_le_bytes())
    }

    /// Writes a little-endian `u64`.
    pub fn write_u64(&self, addr: u64, v: u64) -> Result<(), Errno> {
        self.write(addr, &v.to_le_bytes())
    }

    /// Reads a NUL-terminated string of at most `max` bytes including the
    /// NUL (`copyinstr`): `ENAMETOOLONG` when longer, `EFAULT` when
    /// unreadable.
    pub fn cstr(&self, addr: u64, max: usize) -> Result<Vec<u8>, Errno> {
        match self.proc.space.read_cstr(addr, max.saturating_sub(1)) {
            Ok(Some(s)) => Ok(s),
            Ok(None) => Err(Errno::ENAMETOOLONG),
            Err(_) => Err(Errno::EFAULT),
        }
    }

    /// Reads a path argument (`MAXPATHLEN` including the NUL).
    pub fn path(&self, addr: u64) -> Result<Vec<u8>, Errno> {
        self.cstr(addr, MAXPATHLEN)
    }
}

/// Logs one BSD call in `strace` style.
pub fn trace_unix(ctx: &Ctx<'_>, name: &str, args: &[u64], r: &SysResult) {
    let args: Vec<String> = args.iter().map(|a| fmt_arg(*a)).collect();
    let res = match r {
        Ok(v) => fmt_arg(v.0),
        Err(e) if *e == Errno::ERESTART && ctx.thread.wait.is_some() => "? (sleeping)".into(),
        Err(e) => format!("-1 {e:?}"),
    };
    eprintln!(
        "[{:#x}] {name}({}) = {res}",
        ctx.thread.tid,
        args.join(", ")
    );
}

/// Formats an argument: small values in decimal, others in hex.
pub fn fmt_arg(a: u64) -> String {
    if a < 0x1_0000 || (a as i64) > -0x1_0000 && (a as i64) < 0 {
        format!("{}", a as i64)
    } else {
        format!("{a:#x}")
    }
}
