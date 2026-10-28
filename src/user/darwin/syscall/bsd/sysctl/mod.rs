//! `sysctl` and `sysctlbyname` (`bsd/kern/kern_newsysctl.c`).
//!
//! The `hw` and `machdep` subtrees describe the machine RAX emulates and
//! are answered here ([`tree`], [`machine`]): the arm64 kernel's nodes as a
//! host probe recorded them, and an Intel kernel's for an x86-64 guest. The
//! other subtrees describe the operating system, which the guest shares
//! with the host (it runs on the host's user space): on a macOS host their
//! requests go to the host ([`host`]), except for the few nodes the
//! emulation decides (the boot time, the stack, the argument limit, ...).
//! Writes are refused (`EPERM`) once the node is found: the emulated
//! machine's settings are fixed and the host's are not the guest's to
//! change.
//! Embedded processes resolve only emulated nodes and explicit overrides;
//! host node discovery, enumeration, and value queries are disabled.
//!
//! The metadata nodes (`sysctl.name`, `.next`, `.name2oid`, `.oidfmt`,
//! `.oiddescr`) cover both, `next` merging the two walks. Copy-out follows
//! `sysctl_old_user`: a value too large for the buffer is not copied
//! (`ENOMEM`, the length reported being what was copied before it), and
//! `sysctl_io_number` gives a 32-bit buffer the value of a 64-bit number
//! that fits (`ERANGE` otherwise).

mod arm64;
mod host;
mod intel;
mod machine;
mod procargs;
pub mod tree;

use crate::user::darwin::abi::Errno;
use crate::user::darwin::arch::{Rv, SysResult};
use crate::user::darwin::syscall::Ctx;

/// Read the fixed host pressure node through the existing bounded adapter.
/// Only the reclaim host-services selector calls this; embedded selection never
/// invokes it. Missing or malformed host data has no valid advertised level.
pub(in crate::user::darwin) fn vm_pressure_level() -> Option<u32> {
    if !host::AVAILABLE {
        return None;
    }
    let oid = host::oid_of("kern.memorystatus_vm_pressure_level").ok()?;
    let reply = host::sysctl(&oid, Some(4), None)?;
    reply.result.ok()?;
    if reply.len != 4 {
        return None;
    }
    Some(u32::from_ne_bytes(reply.data.try_into().ok()?))
}

/// `CTL_MAXNAME`.
const CTL_MAXNAME: u64 = 12;
/// `MAXPATHLEN`.
const MAXPATHLEN: u64 = 1024;
/// The largest buffer a request passed to the host gets.
const HOST_ROOM_MAX: u64 = 256 << 20;

/// How a node's handler produces its value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// These bytes exactly (`SYSCTL_OUT`, `SYSCTL_RETURN`).
    Out(Vec<u8>),
    /// `sysctl_io_number(value, size)`.
    Number(i64, usize),
    /// A C string (without its NUL) through `sysctl_io_string` with
    /// truncation: a short buffer receives what fits, NUL-terminated.
    Truncated(Vec<u8>),
    /// The handler fails.
    Err(Errno),
    /// The host's node of the same name.
    Host,
}

impl Value {
    /// `SYSCTL_RETURN` of an `int`.
    pub fn int(v: i32) -> Self {
        Value::Out(v.to_le_bytes().to_vec())
    }

    /// `SYSCTL_RETURN` of a 64-bit value.
    pub fn quad(v: u64) -> Self {
        Value::Out(v.to_le_bytes().to_vec())
    }

    /// An `int` through `sysctl_io_number` (`SYSCTL_INT`).
    pub fn io_int(v: i32) -> Self {
        Value::Number(i64::from(v), 4)
    }

    /// A 64-bit value through `sysctl_io_number` (`SYSCTL_QUAD`).
    pub fn io_quad(v: u64) -> Self {
        Value::Number(v as i64, 8)
    }

    /// A C string with its NUL.
    pub fn string(s: &[u8]) -> Self {
        let mut b = s.to_vec();
        b.push(0);
        Value::Out(b)
    }
}

/// A request (`struct sysctl_req`): the caller's old and new buffers and
/// how much has been copied out.
#[derive(Debug)]
pub struct Req {
    oldptr: u64,
    oldlen: u64,
    oldidx: u64,
    newptr: u64,
    newlen: u64,
}

impl Req {
    fn new(oldptr: u64, oldlen: u64, newptr: u64, newlen: u64) -> Self {
        Req {
            oldptr,
            oldlen,
            oldidx: 0,
            // sysctl_create_user_req: no new value without a length.
            newptr: if newlen != 0 { newptr } else { 0 },
            newlen,
        }
    }

    /// `sysctl_old_user`: `data` at the cursor, or `ENOMEM` (nothing
    /// copied, the cursor kept) when it does not fit; a size query only
    /// moves the cursor.
    fn out(&mut self, ctx: &Ctx<'_>, data: &[u8]) -> Result<(), Errno> {
        let l = data.len() as u64;
        if self.oldptr != 0 {
            if self.oldlen.saturating_sub(self.oldidx) < l {
                return Err(Errno::ENOMEM);
            }
            ctx.write(self.oldptr + self.oldidx, data)?;
        }
        self.oldidx += l;
        Ok(())
    }

    /// `sysctl_io_number`: a 32-bit value, or a 64-bit one into anything but
    /// a 32-bit buffer.
    fn number(&mut self, ctx: &Ctx<'_>, value: i64, size: usize) -> Result<(), Errno> {
        if (size == 4 || (self.oldlen == 4 && size == 8)) && self.oldptr != 0 {
            let small = value as i32;
            if i64::from(small) != value {
                return Err(Errno::ERANGE);
            }
            self.out(ctx, &small.to_le_bytes())
        } else {
            self.out(ctx, &value.to_le_bytes()[..size])
        }
    }

    /// The length `*oldlenp` receives (`userland_sysctl`).
    fn reported(&self) -> u64 {
        if self.oldptr != 0 && self.oldidx > self.oldlen {
            self.oldlen
        } else {
            self.oldidx
        }
    }
}

/// `sysctl(name, namelen, oldp, oldlenp, newp, newlen)`.
pub fn sysctl(ctx: &mut Ctx<'_>, a: &[u64; 8]) -> SysResult {
    let (name, namelen, oldp, oldlenp, newp, newlen) =
        (a[0], a[1] as u32 as u64, a[2], a[3], a[4], a[5]);
    // Every top-level name is a node.
    if !(2..=CTL_MAXNAME).contains(&namelen) {
        return Err(Errno::EINVAL);
    }
    let oid = ints(&ctx.read(name, 4 * namelen as usize)?);
    let oldlen = if oldlenp != 0 {
        ctx.read_u64(oldlenp)?
    } else {
        0
    };
    let mut req = Req::new(oldp, oldlen, newp, newlen);
    let r = root(ctx, &oid, &mut req);
    finish(ctx, r, &req, oldlenp)
}

/// `sysctlbyname(name, namelen, oldp, oldlenp, newp, newlen)`: the name's
/// OID (`name2oid`), then as `sysctl`.
pub fn sysctlbyname(ctx: &mut Ctx<'_>, a: &[u64; 8]) -> SysResult {
    let (name, namelen, oldp, oldlenp, newp, newlen) = (a[0], a[1], a[2], a[3], a[4], a[5]);
    if namelen >= MAXPATHLEN {
        return Err(Errno::ENAMETOOLONG);
    }
    let n = ctx.read(name, namelen as usize)?;
    let oldlen = if oldlenp != 0 {
        ctx.read_u64(oldlenp)?
    } else {
        0
    };
    let mut req = Req::new(oldp, oldlen, newp, newlen);
    let r = oid_of_name(ctx, &c_string(n)).and_then(|oid| root(ctx, &oid, &mut req));
    finish(ctx, r, &req, oldlenp)
}

/// The end of a call: the length copied out is reported unless the call
/// failed otherwise than by `ENOMEM`.
fn finish(ctx: &Ctx<'_>, r: Result<(), Errno>, req: &Req, oldlenp: u64) -> SysResult {
    if let Err(e) = r
        && e != Errno::ENOMEM
    {
        return Err(e);
    }
    if oldlenp != 0 {
        ctx.write_u64(oldlenp, req.reported())?;
    }
    r.map(|()| Rv::one(0))
}

/// A name up to its first NUL.
fn c_string(mut n: Vec<u8>) -> String {
    if let Some(z) = n.iter().position(|&b| b == 0) {
        n.truncate(z);
    }
    String::from_utf8_lossy(&n).into_owned()
}

fn ints(b: &[u8]) -> Vec<i32> {
    b.chunks_exact(4)
        .map(|c| i32::from_le_bytes(c.try_into().expect("4 bytes")))
        .collect()
}

fn bytes(oid: &[i32]) -> Vec<u8> {
    oid.iter().flat_map(|v| v.to_le_bytes()).collect()
}

/// `sysctl_root`: the node `oid` names handles the request.
fn root(ctx: &mut Ctx<'_>, oid: &[i32], req: &mut Req) -> Result<(), Errno> {
    // A top-level name is a node, which has no value.
    if oid.len() < 2 {
        return Err(Errno::ENOENT);
    }
    if tree::owns(oid[0]) {
        return emulated(ctx, oid, req);
    }
    if oid[0] == 0 {
        let args = &oid[2..];
        let owned = args.first().is_some_and(|&t| tree::owns(t));
        match oid[1] {
            1 if owned => return meta_name(ctx, args, req),
            2 => return meta_next(ctx, args, req),
            3 => return meta_name2oid(ctx, req),
            4 | 5 if owned => return meta_format(ctx, oid[1], args, req),
            _ => {}
        }
    }
    system(ctx, oid, req)
}

/// A node of the emulated machine.
fn emulated(ctx: &mut Ctx<'_>, oid: &[i32], req: &mut Req) -> Result<(), Errno> {
    let row = tree::leaf(tree::rows(ctx.proc.abi), oid)?;
    if req.newptr != 0 {
        return Err(Errno::EPERM);
    }
    let v = machine::value(ctx, row.name);
    emit(ctx, req, v, row.name)
}

/// Copies out `v`, the value of the node called `name`.
fn emit(ctx: &mut Ctx<'_>, req: &mut Req, v: Value, name: &str) -> Result<(), Errno> {
    match v {
        Value::Out(b) => req.out(ctx, &b),
        Value::Number(n, size) => req.number(ctx, n, size),
        Value::Truncated(s) => {
            if req.oldptr != 0 && req.oldlen != 0 && req.oldlen < s.len() as u64 + 1 {
                req.out(ctx, &s[..req.oldlen as usize - 1])?;
                req.out(ctx, b"\0")
            } else {
                req.out(ctx, &c_bytes_of(&s))
            }
        }
        Value::Err(e) => Err(e),
        Value::Host if !ctx.proc.config.host_services => Err(Errno::ENOENT),
        Value::Host => match host::oid_of(name) {
            Ok(oid) => passthrough(ctx, &oid, req),
            Err(_) => Err(Errno::ENOENT),
        },
    }
}

/// A node of the operating system: one the emulation decides, or the
/// host's.
fn system(ctx: &mut Ctx<'_>, oid: &[i32], req: &mut Req) -> Result<(), Errno> {
    // The calling process's arguments are in its own memory.
    if procargs::own(ctx, oid) {
        if req.newptr != 0 {
            return Err(Errno::EPERM);
        }
        return procargs::procargs(ctx, oid[1] == procargs::KERN_PROCARGS2, req);
    }
    let name = if ctx.proc.config.host_services {
        host::name_of(oid)
    } else {
        None
    }
    .or_else(|| {
        OVERRIDES
            .iter()
            .find(|o| o.oid == oid)
            .map(|o| o.name.to_string())
    });
    if let Some(o) = name.and_then(|n| OVERRIDES.iter().find(|o| o.name == n)) {
        if req.newptr != 0 {
            return Err(Errno::EPERM);
        }
        let v = (o.value)(ctx);
        return emit(ctx, req, v, o.name);
    }
    if !ctx.proc.config.host_services {
        return Err(Errno::ENOENT);
    }
    if req.newptr != 0 {
        // Whether the node exists decides the error.
        let probe = host::sysctl(oid, None, None).ok_or(Errno::ENOENT)?;
        return match probe.result {
            Err(e) if e != Errno::ENOMEM => Err(e),
            _ => Err(Errno::EPERM),
        };
    }
    passthrough(ctx, oid, req)
}

/// The host answers `oid` into the caller's buffer.
fn passthrough(ctx: &Ctx<'_>, oid: &[i32], req: &mut Req) -> Result<(), Errno> {
    if !ctx.proc.config.host_services {
        return Err(Errno::ENOENT);
    }
    let room = (req.oldptr != 0).then(|| req.oldlen.min(HOST_ROOM_MAX));
    let mut r = host::sysctl(oid, room, None).ok_or(Errno::ENOENT)?;
    if matches!(oid, [1, 14, command, ..] if matches!(*command, 0 | 1 | 2 | 4 | 5 | 6)) {
        project_kern_proc(&mut r.data, |pid| {
            let (traced, parent, current_parent, exit) = super::ptrace::known_process_info(
                &ctx.proc.tracing,
                ctx.proc.pid,
                ctx.proc.ppid,
                pid,
            )?;
            let signal = super::ptrace::known_signal_status(&ctx.proc.tracing, ctx.proc.pid, pid);
            Some((traced, parent, signal, current_parent, exit))
        });
    }
    if req.oldptr != 0 && !r.data.is_empty() {
        ctx.write(req.oldptr, &r.data)?;
    }
    req.oldidx = r.len;
    r.result
}

/// `user64_kinfo_proc`: project known guest trace state. Both supported guest
/// ABIs use the 64-bit layout (648 bytes, p_flag at 32, p_pid at 40).
fn project_kern_proc(
    bytes: &mut [u8],
    mut trace: impl FnMut(i32) -> Option<(bool, i32, Option<(bool, i32)>, Option<i32>, Option<i32>)>,
) {
    const SIZE: usize = 648;
    const FLAG: usize = 32;
    const STATUS: usize = 36;
    const PID: usize = 40;
    const ORIGINAL_PARENT: usize = 44;
    const XSTATUS: usize = 280;
    const P_TRACED: u32 = 0x800;
    const SZOMB: u8 = 5;
    for record in bytes.chunks_exact_mut(SIZE) {
        let pid = i32::from_le_bytes(record[PID..PID + 4].try_into().expect("pid bytes"));
        if let Some((traced, original_parent, signal, parent, exit)) = trace(pid) {
            let flags = u32::from_le_bytes(record[FLAG..FLAG + 4].try_into().expect("flag bytes"));
            // exit1 clears P_LTRACED before the process becomes a zombie;
            // the host can observe exit before the link's EOF is pumped.
            if let Some(parent) = parent {
                record[560..564].copy_from_slice(&parent.to_le_bytes());
            }
            if let Some(status) = exit {
                record[STATUS] = SZOMB;
                record[XSTATUS..XSTATUS + 2].copy_from_slice(&(status as u16).to_le_bytes());
            }
            let zombie = record[STATUS] == SZOMB;
            let traced = traced && !zombie;
            let flags = (flags & !P_TRACED) | if traced { P_TRACED } else { 0 };
            record[FLAG..FLAG + 4].copy_from_slice(&flags.to_le_bytes());
            record[ORIGINAL_PARENT..ORIGINAL_PARENT + 4]
                .copy_from_slice(&original_parent.to_le_bytes());
            if let Some((stopped, xstatus)) = signal
                && !zombie
            {
                if stopped {
                    record[STATUS] = 4;
                }
                record[XSTATUS..XSTATUS + 2].copy_from_slice(&(xstatus as u16).to_le_bytes());
            }
        }
    }
}

/// The OID of `name` (`name2oid`).
fn oid_of_name(ctx: &Ctx<'_>, name: &str) -> Result<Vec<i32>, Errno> {
    if name.is_empty() {
        return Err(Errno::ENOENT);
    }
    if tree::owns_name(name) {
        return tree::oid_of(tree::rows(ctx.proc.abi), name).map(<[i32]>::to_vec);
    }
    let host_oid = if ctx.proc.config.host_services {
        host::oid_of(name)
    } else {
        Err(Errno::ENOENT)
    };
    host_oid.or_else(|e| {
        let n = name.strip_suffix('.').unwrap_or(name);
        OVERRIDES
            .iter()
            .find(|o| o.name == n)
            .map(|o| o.oid.to_vec())
            .ok_or(e)
    })
}

/// `sysctl.name` of an OID of the emulated machine.
fn meta_name(ctx: &Ctx<'_>, args: &[i32], req: &mut Req) -> Result<(), Errno> {
    if req.newptr != 0 {
        return Err(Errno::EPERM);
    }
    for part in tree::name_parts(tree::rows(ctx.proc.abi), args) {
        if req.oldidx != 0 {
            req.out(ctx, b".")?;
        }
        req.out(ctx, part.as_bytes())?;
    }
    req.out(ctx, b"\0")
}

/// `sysctl.next`: the leaf after `args` in either walk.
fn meta_next(ctx: &Ctx<'_>, args: &[i32], req: &mut Req) -> Result<(), Errno> {
    if req.newptr != 0 {
        return Err(Errno::EPERM);
    }
    let emulated = tree::next(tree::rows(ctx.proc.abi), args).map(<[i32]>::to_vec);
    let system = system_next(args, ctx.proc.config.host_services);
    let next = match (emulated, system) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    };
    req.out(ctx, &bytes(&next.ok_or(Errno::ENOENT)?))
}

/// The operating system's leaf after `oid`, past the emulated subtrees.
fn system_next(oid: &[i32], host_services: bool) -> Option<Vec<i32>> {
    if !host_services || !host::AVAILABLE {
        let mut own: Vec<&[i32]> = OVERRIDES.iter().map(|o| o.oid).collect();
        own.sort();
        return own.into_iter().find(|o| *o > oid).map(<[i32]>::to_vec);
    }
    let mut n = host::next(oid)?;
    while tree::owns(n[0]) {
        n = host::next(&[tree::CTL_MACHDEP, i32::MAX])?;
    }
    Some(n)
}

/// `sysctl.name2oid`: the OID of the name in the new value.
fn meta_name2oid(ctx: &Ctx<'_>, req: &mut Req) -> Result<(), Errno> {
    if req.newlen < 1 {
        return Err(Errno::ENOENT);
    }
    if req.newlen >= MAXPATHLEN {
        return Err(Errno::ENAMETOOLONG);
    }
    let n = ctx.read(req.newptr, req.newlen as usize)?;
    let oid = oid_of_name(ctx, &c_string(n))?;
    req.out(ctx, &bytes(&oid))
}

/// `sysctl.oidfmt` (the kind, then the format) and `sysctl.oiddescr` of
/// an OID of the emulated machine.
fn meta_format(ctx: &Ctx<'_>, which: i32, args: &[i32], req: &mut Req) -> Result<(), Errno> {
    if req.newptr != 0 {
        return Err(Errno::EPERM);
    }
    let row = tree::node(tree::rows(ctx.proc.abi), args)?;
    if which == 4 {
        req.out(ctx, &row.kind.to_le_bytes())?;
        req.out(ctx, &c_bytes(row.fmt))
    } else {
        req.out(ctx, &c_bytes(row.descr))
    }
}

/// `s` with its NUL.
fn c_bytes(s: &str) -> Vec<u8> {
    c_bytes_of(s.as_bytes())
}

fn c_bytes_of(s: &[u8]) -> Vec<u8> {
    let mut b = s.to_vec();
    b.push(0);
    b
}

/// An operating-system node whose value the emulation decides, with its
/// OID for a host that cannot name it.
struct Override {
    name: &'static str,
    oid: &'static [i32],
    value: fn(&Ctx<'_>) -> Value,
}

static OVERRIDES: &[Override] = &[
    Override {
        name: "sysctl.proc_translated",
        oid: &[0, 100],
        value: |_| Value::int(0),
    },
    Override {
        name: "kern.ostype",
        oid: &[1, 1],
        value: |_| Value::string(b"Darwin"),
    },
    Override {
        name: "kern.version",
        oid: &[1, 4],
        value: |ctx| {
            if ctx.proc.config.host_services {
                Value::Host
            } else {
                Value::string(crate::user::darwin::abi::CLOSED_KERNEL_VERSION)
            }
        },
    },
    Override {
        name: "kern.osrevision",
        oid: &[1, 3],
        value: |_| Value::io_int(199_506),
    },
    Override {
        name: "kern.argmax",
        oid: &[1, 8],
        value: |_| Value::io_int(crate::user::darwin::stack::NCARGS as i32),
    },
    Override {
        name: "kern.ngroups",
        oid: &[1, 18],
        value: |_| Value::io_int(16),
    },
    Override {
        name: "kern.boottime",
        oid: &[1, 21],
        value: |c| {
            let us = c.proc.machine.boottime_usec;
            let tv = crate::user::darwin::abi::types::Timeval {
                sec: (us / 1_000_000) as i64,
                usec: (us % 1_000_000) as i32,
            };
            Value::Out(tv.bytes().to_vec())
        },
    },
    // p_name: the image's name, at most 2 * MAXCOMLEN bytes.
    Override {
        name: "kern.procname",
        oid: &[1, 62],
        value: |c| {
            let mut n = crate::user::darwin::syscall::bsd::proc::image_name(c);
            n.truncate(32);
            Value::Truncated(n)
        },
    },
    Override {
        name: "kern.usrstack64",
        oid: &[1, 59],
        value: |c| Value::io_quad(c.proc.program.stack.top),
    },
    Override {
        name: "kern.hv_support",
        oid: &[1, 106],
        value: |_| Value::io_int(0),
    },
    Override {
        name: "kern.hv_vmm_present",
        oid: &[1, 107],
        value: |_| Value::io_int(0),
    },
    Override {
        name: "kern.pthread_mutex_default_policy",
        oid: &[1, 108],
        value: |_| Value::io_int(0),
    },
    Override {
        name: "kern.bootargs",
        oid: &[1, 110],
        value: |_| Value::string(b""),
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_projection_changes_only_known_complete_records() {
        let mut records = vec![0u8; 4 * 648 + 20];
        records[40..44].copy_from_slice(&1001i32.to_le_bytes());
        records[32..36].copy_from_slice(&0x55u32.to_le_bytes());
        records[648 + 40..648 + 44].copy_from_slice(&1002i32.to_le_bytes());
        records[648 + 32..648 + 36].copy_from_slice(&0x855u32.to_le_bytes());
        records[2 * 648 + 40..2 * 648 + 44].copy_from_slice(&1003i32.to_le_bytes());
        records[2 * 648 + 32..2 * 648 + 36].copy_from_slice(&0x123u32.to_le_bytes());
        records[3 * 648 + 40..3 * 648 + 44].copy_from_slice(&1004i32.to_le_bytes());
        records[3 * 648 + 32..3 * 648 + 36].copy_from_slice(&0x855u32.to_le_bytes());
        records[3 * 648 + 36] = 5;
        records[4 * 648..].fill(0xa5);
        project_kern_proc(&mut records, |pid| match pid {
            1001 => Some((true, 700, Some((true, 30)), Some(900), None)),
            1002 => Some((false, 0, Some((false, 31)), Some(901), Some(0x2a00))),
            1004 => Some((true, 701, Some((true, 30)), None, None)),
            _ => None,
        });
        assert_eq!(
            u32::from_le_bytes(records[32..36].try_into().unwrap()),
            0x855
        );
        assert_eq!(
            u32::from_le_bytes(records[680..684].try_into().unwrap()),
            0x55
        );
        assert_eq!(
            u32::from_le_bytes(records[1328..1332].try_into().unwrap()),
            0x123
        );
        assert_eq!(
            u32::from_le_bytes(records[1976..1980].try_into().unwrap()),
            0x55
        );
        assert_eq!(i32::from_le_bytes(records[44..48].try_into().unwrap()), 700);
        assert_eq!(
            i32::from_le_bytes(records[1988..1992].try_into().unwrap()),
            701
        );
        assert_eq!(records[36], 4);
        assert_eq!(
            i32::from_le_bytes(records[560..564].try_into().unwrap()),
            900
        );
        assert_eq!(records[648 + 36], 5);
        assert_eq!(
            u16::from_le_bytes(records[648 + 280..648 + 282].try_into().unwrap()),
            0x2a00
        );
        assert_eq!(
            u16::from_le_bytes(records[280..282].try_into().unwrap()),
            30
        );
        assert_eq!(
            u16::from_le_bytes(records[928..930].try_into().unwrap()),
            0x2a00
        );
        assert_eq!(records[1980], 5);
        assert!(records[4 * 648..].iter().all(|&byte| byte == 0xa5));
    }

    #[test]
    fn override_names_and_oids_are_unique() {
        let mut names = std::collections::HashSet::new();
        let mut oids = std::collections::HashSet::new();
        for o in OVERRIDES {
            assert!(names.insert(o.name), "{}", o.name);
            assert!(oids.insert(o.oid), "{:?}", o.oid);
            assert!(!tree::owns(o.oid[0]));
        }
    }

    #[test]
    fn copy_out_follows_sysctl_old_user() {
        let mut r = Req::new(0, 0, 0, 0);
        assert_eq!(r.reported(), 0);
        r.oldidx = 7;
        assert_eq!(r.reported(), 7);
        let mut r = Req::new(0x1000, 4, 0x2000, 0);
        // No new value without a length.
        assert_eq!(r.newptr, 0);
        r.oldidx = 9;
        assert_eq!(r.reported(), 4);
        assert_eq!(Value::string(b"ab"), Value::Out(b"ab\0".to_vec()));
    }
}
