//! `sysctl` and `sysctlbyname`.
//!
//! Nodes that describe the machine RAX emulates (CPU type, features, and
//! count, page size, memory, caches, the timebase, the process's stack) are
//! answered here. Nodes that describe the operating system (release,
//! version, host name, boot session) are read from the host on a macOS host,
//! whose user space the guest runs on; writes to those are refused
//! (`EPERM`). Unknown `hw` and `machdep` nodes do not exist (`ENOENT`).
//!
//! Output follows `userland_sysctl`: with no buffer the size is reported;
//! a buffer too small receives what fits and the call fails with
//! `ENOMEM`, the size reported being the full one.

use crate::user::darwin::abi::{DarwinAbi, Errno};
use crate::user::darwin::arch::{ARM64_COUNTER_HZ, Rv, SysResult};
use crate::user::darwin::commpage;
use crate::user::darwin::process::MEMSIZE;
use crate::user::darwin::syscall::Ctx;

/// `CTL_MAXNAME`.
const CTL_MAXNAME: u64 = 12;

/// A node's value.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Val {
    Int(i32),
    Quad(u64),
    Str(Vec<u8>),
    Bytes(Vec<u8>),
}

impl Val {
    fn bytes(&self) -> Vec<u8> {
        match self {
            Val::Int(v) => v.to_le_bytes().to_vec(),
            Val::Quad(v) => v.to_le_bytes().to_vec(),
            Val::Str(s) => {
                let mut b = s.clone();
                b.push(0);
                b
            }
            Val::Bytes(b) => b.clone(),
        }
    }
}

/// Where a node's value comes from.
#[derive(Clone, Copy)]
enum Src {
    /// Computed from the emulated machine and process.
    Emu(fn(&Ctx<'_>) -> Val),
    /// The host's node of the same name (read-only).
    Host,
}

/// A node: its OID path, full name, and source.
struct Node {
    oid: &'static [i32],
    name: &'static str,
    src: Src,
}

fn is_arm(ctx: &Ctx<'_>) -> bool {
    ctx.proc.abi == DarwinAbi::Arm64
}

fn page_size(ctx: &Ctx<'_>) -> Val {
    Val::Int(ctx.proc.abi.user_page_size() as i32)
}

fn one(_: &Ctx<'_>) -> Val {
    Val::Int(i32::from(commpage::NCPUS))
}

/// The arm64 features the emulated CPU advertises (`hw.optional.arm.*`):
/// the `apple_arm64_config` profile.
const ARM_FEATURES: &[&str] = &[
    "FEAT_CRC32",
    "FEAT_FlagM",
    "FEAT_FlagM2",
    "FEAT_FHM",
    "FEAT_DotProd",
    "FEAT_SHA3",
    "FEAT_RDM",
    "FEAT_LSE",
    "FEAT_SHA256",
    "FEAT_SHA512",
    "FEAT_SHA1",
    "FEAT_AES",
    "FEAT_PMULL",
    "FEAT_SB",
    "FEAT_FRINTTS",
    "FEAT_PACIMP",
    "FEAT_LRCPC",
    "FEAT_LRCPC2",
    "FEAT_FCMA",
    "FEAT_JSCVT",
    "FEAT_PAuth",
    "FEAT_DPB",
    "FEAT_DPB2",
    "FEAT_LSE2",
    "FEAT_CSV2",
    "FEAT_CSV3",
    "FEAT_DIT",
    "AdvSIMD",
    "AdvSIMD_HPFPCvt",
    "FEAT_FP16",
    "FEAT_BTI",
];

/// The x86 features the emulated CPU advertises (`hw.optional.*`): the
/// Haswell profile of the commpage.
const X86_FEATURES: &[&str] = &[
    "mmx",
    "sse",
    "sse2",
    "sse3",
    "supplementalsse3",
    "sse4_1",
    "sse4_2",
    "x86_64",
    "aes",
    "avx1_0",
    "rdrand",
    "f16c",
    "enfstrg",
    "fma",
    "avx2_0",
    "bmi1",
    "bmi2",
    "adx",
    "rdseed",
];

static NODES: &[Node] = &[
    Node {
        oid: &[1, 1],
        name: "kern.ostype",
        src: Src::Emu(|_| Val::Str(b"Darwin".to_vec())),
    },
    Node {
        oid: &[1, 2],
        name: "kern.osrelease",
        src: Src::Host,
    },
    Node {
        oid: &[1, 3],
        name: "kern.osrevision",
        src: Src::Emu(|_| Val::Int(199_506)),
    },
    Node {
        oid: &[1, 4],
        name: "kern.version",
        src: Src::Host,
    },
    Node {
        oid: &[1, 6],
        name: "kern.maxproc",
        src: Src::Host,
    },
    Node {
        oid: &[1, 7],
        name: "kern.maxfiles",
        src: Src::Host,
    },
    Node {
        oid: &[1, 8],
        name: "kern.argmax",
        src: Src::Emu(|_| Val::Int(crate::user::darwin::stack::NCARGS as i32)),
    },
    Node {
        oid: &[1, 10],
        name: "kern.hostname",
        src: Src::Host,
    },
    Node {
        oid: &[1, 18],
        name: "kern.ngroups",
        src: Src::Emu(|_| Val::Int(16)),
    },
    Node {
        oid: &[1, 21],
        name: "kern.boottime",
        src: Src::Emu(|c| {
            let us = c.proc.machine.boottime_usec;
            let tv = crate::user::darwin::abi::types::Timeval {
                sec: (us / 1_000_000) as i64,
                usec: (us % 1_000_000) as i32,
            };
            Val::Bytes(tv.bytes().to_vec())
        }),
    },
    Node {
        oid: &[1, 29],
        name: "kern.maxfilesperproc",
        src: Src::Host,
    },
    Node {
        oid: &[1, 30],
        name: "kern.maxprocperuid",
        src: Src::Host,
    },
    Node {
        oid: &[1, 59],
        name: "kern.usrstack64",
        src: Src::Emu(|c| Val::Quad(c.proc.program.stack.top)),
    },
    Node {
        oid: &[1, 65],
        name: "kern.osversion",
        src: Src::Host,
    },
    Node {
        oid: &[1, 100],
        name: "kern.osproductversion",
        src: Src::Host,
    },
    Node {
        oid: &[1, 101],
        name: "kern.osvariant_status",
        src: Src::Host,
    },
    Node {
        oid: &[1, 102],
        name: "kern.bootsessionuuid",
        src: Src::Host,
    },
    Node {
        oid: &[1, 103],
        name: "kern.uuid",
        src: Src::Host,
    },
    Node {
        oid: &[1, 104],
        name: "kern.secure_kernel",
        src: Src::Host,
    },
    Node {
        oid: &[1, 105],
        name: "kern.iossupportversion",
        src: Src::Host,
    },
    Node {
        oid: &[1, 106],
        name: "kern.hv_support",
        src: Src::Emu(|_| Val::Int(0)),
    },
    Node {
        oid: &[1, 107],
        name: "kern.hv_vmm_present",
        src: Src::Emu(|_| Val::Int(0)),
    },
    Node {
        oid: &[1, 108],
        name: "kern.pthread_mutex_default_policy",
        src: Src::Emu(|_| Val::Int(0)),
    },
    Node {
        oid: &[1, 109],
        name: "kern.osproductversioncompat",
        src: Src::Host,
    },
    Node {
        oid: &[1, 110],
        name: "kern.bootargs",
        src: Src::Emu(|_| Val::Str(Vec::new())),
    },
    Node {
        oid: &[6, 1],
        name: "hw.machine",
        src: Src::Emu(|c| Val::Str(c.proc.abi.name().as_bytes().to_vec())),
    },
    Node {
        oid: &[6, 2],
        name: "hw.model",
        src: Src::Emu(|c| {
            if is_arm(c) {
                host_string("hw.model").map_or(Val::Str(b"MacBookPro17,1".to_vec()), Val::Str)
            } else {
                Val::Str(b"MacPro7,1".to_vec())
            }
        }),
    },
    Node {
        oid: &[6, 3],
        name: "hw.ncpu",
        src: Src::Emu(one),
    },
    Node {
        oid: &[6, 4],
        name: "hw.byteorder",
        src: Src::Emu(|_| Val::Int(1234)),
    },
    Node {
        oid: &[6, 5],
        name: "hw.physmem",
        src: Src::Emu(|_| Val::Int(i32::MAX)),
    },
    Node {
        oid: &[6, 6],
        name: "hw.usermem",
        src: Src::Emu(|_| Val::Int(i32::MAX)),
    },
    Node {
        oid: &[6, 7],
        name: "hw.pagesize",
        src: Src::Emu(page_size),
    },
    Node {
        oid: &[6, 24],
        name: "hw.memsize",
        src: Src::Emu(|_| Val::Quad(MEMSIZE)),
    },
    Node {
        oid: &[6, 25],
        name: "hw.availcpu",
        src: Src::Emu(one),
    },
    Node {
        oid: &[6, 100],
        name: "hw.activecpu",
        src: Src::Emu(one),
    },
    Node {
        oid: &[6, 101],
        name: "hw.physicalcpu",
        src: Src::Emu(one),
    },
    Node {
        oid: &[6, 102],
        name: "hw.physicalcpu_max",
        src: Src::Emu(one),
    },
    Node {
        oid: &[6, 103],
        name: "hw.logicalcpu",
        src: Src::Emu(one),
    },
    Node {
        oid: &[6, 104],
        name: "hw.logicalcpu_max",
        src: Src::Emu(one),
    },
    Node {
        oid: &[6, 105],
        name: "hw.cputype",
        src: Src::Emu(|c| Val::Int(c.proc.abi.host_cpu().cputype as i32)),
    },
    Node {
        oid: &[6, 106],
        name: "hw.cpusubtype",
        src: Src::Emu(|c| Val::Int(c.proc.abi.host_cpu().cpusubtype as i32)),
    },
    Node {
        oid: &[6, 107],
        name: "hw.cpu64bit_capable",
        src: Src::Emu(|_| Val::Int(1)),
    },
    Node {
        oid: &[6, 108],
        name: "hw.cpufamily",
        src: Src::Emu(|c| {
            Val::Int(if is_arm(c) {
                commpage::CPUFAMILY_ARM_FIRESTORM_ICESTORM as i32
            } else {
                commpage::CPUFAMILY_INTEL_HASWELL as i32
            })
        }),
    },
    Node {
        oid: &[6, 109],
        name: "hw.cachelinesize",
        src: Src::Emu(|c| Val::Quad(if is_arm(c) { 128 } else { 64 })),
    },
    Node {
        oid: &[6, 110],
        name: "hw.l1icachesize",
        src: Src::Emu(|c| Val::Quad(if is_arm(c) { 131_072 } else { 32_768 })),
    },
    Node {
        oid: &[6, 111],
        name: "hw.l1dcachesize",
        src: Src::Emu(|c| Val::Quad(if is_arm(c) { 65_536 } else { 32_768 })),
    },
    Node {
        oid: &[6, 112],
        name: "hw.l2cachesize",
        src: Src::Emu(|c| Val::Quad(if is_arm(c) { 4_194_304 } else { 262_144 })),
    },
    Node {
        oid: &[6, 113],
        name: "hw.tbfrequency",
        src: Src::Emu(|c| {
            Val::Quad(if is_arm(c) {
                ARM64_COUNTER_HZ
            } else {
                1_000_000_000
            })
        }),
    },
    Node {
        oid: &[6, 114],
        name: "hw.packages",
        src: Src::Emu(one),
    },
    Node {
        oid: &[6, 115],
        name: "hw.cpufrequency",
        src: Src::Emu(|_| Val::Quad(3_000_000_000)),
    },
    Node {
        oid: &[6, 116],
        name: "hw.nperflevels",
        src: Src::Emu(one),
    },
    Node {
        oid: &[0, 100],
        name: "sysctl.proc_translated",
        src: Src::Emu(|_| Val::Int(0)),
    },
    Node {
        oid: &[8, 1],
        name: "user.cs_path",
        src: Src::Emu(|_| Val::Str(b"/usr/bin:/bin:/usr/sbin:/sbin".to_vec())),
    },
];

/// First OID of the generated `hw.optional` nodes.
const OPTIONAL_BASE: i32 = 200;

/// The value of an `hw.optional` name for `abi`: 1 for an advertised
/// feature, `None` for a name the machine does not have.
fn optional(abi: DarwinAbi, name: &str) -> Option<i32> {
    match abi {
        DarwinAbi::Arm64 => {
            let f = name.strip_prefix("hw.optional.arm.")?;
            Some(i32::from(ARM_FEATURES.contains(&f)))
        }
        DarwinAbi::X86_64 => {
            let f = name.strip_prefix("hw.optional.")?;
            Some(i32::from(X86_FEATURES.contains(&f)))
        }
    }
}

fn optional_names(abi: DarwinAbi) -> Vec<String> {
    match abi {
        DarwinAbi::Arm64 => ARM_FEATURES
            .iter()
            .map(|f| format!("hw.optional.arm.{f}"))
            .collect(),
        DarwinAbi::X86_64 => X86_FEATURES
            .iter()
            .map(|f| format!("hw.optional.{f}"))
            .collect(),
    }
}

/// A host sysctl string (macOS hosts).
fn host_string(name: &str) -> Option<Vec<u8>> {
    let mut v = host_bytes(name)?;
    while v.last() == Some(&0) {
        v.pop();
    }
    Some(v)
}

/// A host sysctl's raw bytes (macOS hosts).
fn host_bytes(name: &str) -> Option<Vec<u8>> {
    #[cfg(target_os = "macos")]
    {
        let c = std::ffi::CString::new(name).ok()?;
        let mut len = 0usize;
        // SAFETY: a size query with a NUL-terminated name and no buffers.
        if unsafe {
            libc::sysctlbyname(
                c.as_ptr(),
                std::ptr::null_mut(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        } != 0
        {
            return None;
        }
        let mut buf = vec![0u8; len];
        // SAFETY: `buf` holds `len` bytes.
        if unsafe {
            libc::sysctlbyname(
                c.as_ptr(),
                buf.as_mut_ptr().cast(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        } != 0
        {
            return None;
        }
        buf.truncate(len);
        Some(buf)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = name;
        None
    }
}

/// The value of the node called `name`.
fn lookup_name(ctx: &Ctx<'_>, name: &str) -> Result<Val, Errno> {
    if let Some(n) = NODES.iter().find(|n| n.name == name) {
        return value(ctx, n);
    }
    if let Some(v) = optional(ctx.proc.abi, name) {
        return Ok(Val::Int(v));
    }
    if name.starts_with("hw.") || name.starts_with("machdep.") {
        return Err(Errno::ENOENT);
    }
    host_bytes(name).map(Val::Bytes).ok_or(Errno::ENOENT)
}

fn value(ctx: &Ctx<'_>, n: &Node) -> Result<Val, Errno> {
    match n.src {
        Src::Emu(f) => Ok(f(ctx)),
        Src::Host => host_bytes(n.name).map(Val::Bytes).ok_or(Errno::ENOENT),
    }
}

/// The name of an OID path.
fn name_of(ctx: &Ctx<'_>, oid: &[i32]) -> Option<String> {
    if let Some(n) = NODES.iter().find(|n| n.oid == oid) {
        return Some(n.name.to_string());
    }
    if oid.len() == 3 && oid[0] == 6 && oid[1] == 99 {
        return optional_names(ctx.proc.abi)
            .get(usize::try_from(oid[2] - OPTIONAL_BASE).ok()?)
            .cloned();
    }
    None
}

/// The OID path of a name (`name2oid`).
fn oid_of(ctx: &Ctx<'_>, name: &str) -> Option<Vec<i32>> {
    if let Some(n) = NODES.iter().find(|n| n.name == name) {
        return Some(n.oid.to_vec());
    }
    optional_names(ctx.proc.abi)
        .iter()
        .position(|n| n == name)
        .map(|i| vec![6, 99, OPTIONAL_BASE + i as i32])
}

/// Copies `data` out per the sysctl protocol.
fn out(ctx: &Ctx<'_>, oldp: u64, oldlenp: u64, data: &[u8]) -> Result<(), Errno> {
    if oldlenp == 0 {
        return Ok(());
    }
    let avail = ctx.read_u64(oldlenp)? as usize;
    let mut r = Ok(());
    if oldp != 0 {
        let n = avail.min(data.len());
        ctx.write(oldp, &data[..n])?;
        if n < data.len() {
            r = Err(Errno::ENOMEM);
        }
    }
    ctx.write_u64(oldlenp, data.len() as u64)?;
    r
}

/// `sysctl(name, namelen, oldp, oldlenp, newp, newlen)`.
pub fn sysctl(ctx: &mut Ctx<'_>, a: &[u64; 8]) -> SysResult {
    let (name, namelen, oldp, oldlenp, newp, newlen) =
        (a[0], a[1] as u32 as u64, a[2], a[3], a[4], a[5]);
    if !(2..=CTL_MAXNAME).contains(&namelen) {
        return Err(Errno::EINVAL);
    }
    let raw = ctx.read(name, 4 * namelen as usize)?;
    let oid: Vec<i32> = raw
        .chunks(4)
        .map(|c| i32::from_le_bytes(c.try_into().expect("4 bytes")))
        .collect();
    // CTL_UNSPEC: the sysctl metadata calls.
    if oid[0] == 0 {
        match oid[1] {
            // sysctl.name: the name of oid[2..].
            1 => {
                let n = name_of(ctx, &oid[2..]).ok_or(Errno::ENOENT)?;
                out(ctx, oldp, oldlenp, &Val::Str(n.into_bytes()).bytes())?;
                return Ok(Rv::one(0));
            }
            // sysctl.name2oid: the OID of the name in newp.
            3 => {
                if newp == 0 || newlen == 0 || newlen > 1024 {
                    return Err(Errno::ENOENT);
                }
                let mut n = ctx.read(newp, newlen as usize)?;
                while n.last() == Some(&0) {
                    n.pop();
                }
                let name = String::from_utf8(n).map_err(|_| Errno::ENOENT)?;
                let oidv = oid_of(ctx, &name).ok_or(Errno::ENOENT)?;
                let b: Vec<u8> = oidv.iter().flat_map(|v| v.to_le_bytes()).collect();
                out(ctx, oldp, oldlenp, &b)?;
                return Ok(Rv::one(0));
            }
            _ => {}
        }
    }
    let name = name_of(ctx, &oid);
    if newp != 0 {
        // Settings of the emulated machine and the host's are refused.
        return Err(if name.is_some() {
            Errno::EPERM
        } else {
            Errno::ENOENT
        });
    }
    let v = match &name {
        Some(n) => lookup_name(ctx, n)?,
        None => host_mib(&oid).map(Val::Bytes).ok_or(Errno::ENOENT)?,
    };
    out(ctx, oldp, oldlenp, &v.bytes())?;
    Ok(Rv::one(0))
}

/// A host sysctl by numeric name, for OS nodes RAX does not define
/// (`kern`, `vm`, `net`, `user`; never `hw` or `machdep`).
fn host_mib(oid: &[i32]) -> Option<Vec<u8>> {
    #[cfg(target_os = "macos")]
    {
        if !matches!(oid.first(), Some(1) | Some(2) | Some(4) | Some(8)) {
            return None;
        }
        let mut mib = oid.to_vec();
        let mut len = 0usize;
        // SAFETY: a size query over a live MIB array and no buffers.
        if unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as u32,
                std::ptr::null_mut(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        } != 0
        {
            return None;
        }
        let mut buf = vec![0u8; len];
        // SAFETY: `buf` holds `len` bytes.
        if unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as u32,
                buf.as_mut_ptr().cast(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        } != 0
        {
            return None;
        }
        buf.truncate(len);
        Some(buf)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = oid;
        None
    }
}

/// `sysctlbyname(name, namelen, oldp, oldlenp, newp, newlen)`.
pub fn sysctlbyname(ctx: &mut Ctx<'_>, a: &[u64; 8]) -> SysResult {
    let (name, namelen, oldp, oldlenp, newp) = (a[0], a[1], a[2], a[3], a[4]);
    if namelen == 0 || namelen > 1024 {
        return Err(Errno::ENAMETOOLONG);
    }
    let mut n = ctx.read(name, namelen as usize)?;
    if let Some(z) = n.iter().position(|&b| b == 0) {
        n.truncate(z);
    }
    let name = String::from_utf8(n).map_err(|_| Errno::ENOENT)?;
    if newp != 0 {
        return Err(if lookup_name(ctx, &name).is_ok() {
            Errno::EPERM
        } else {
            Errno::ENOENT
        });
    }
    let v = lookup_name(ctx, &name)?;
    out(ctx, oldp, oldlenp, &v.bytes())?;
    Ok(Rv::one(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_names_and_oids_are_unique() {
        let mut names = std::collections::HashSet::new();
        let mut oids = std::collections::HashSet::new();
        for n in NODES {
            assert!(names.insert(n.name), "{}", n.name);
            assert!(oids.insert(n.oid), "{:?}", n.oid);
        }
    }

    #[test]
    fn optional_features_follow_the_cpu_profiles() {
        assert_eq!(
            optional(DarwinAbi::Arm64, "hw.optional.arm.FEAT_PAuth"),
            Some(1)
        );
        assert_eq!(
            optional(DarwinAbi::Arm64, "hw.optional.arm.FEAT_SME"),
            Some(0)
        );
        assert_eq!(optional(DarwinAbi::X86_64, "hw.optional.avx2_0"), Some(1));
        assert_eq!(optional(DarwinAbi::X86_64, "hw.optional.avx512f"), Some(0));
        assert_eq!(optional(DarwinAbi::X86_64, "kern.ostype"), None);
        assert_eq!(Val::Str(b"ab".to_vec()).bytes(), b"ab\0");
    }
}
