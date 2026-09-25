//! Process-level system calls: identity, limits, and process attributes.

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::abi::types::{Encoder, SysInfo, encode_utsname};
use super::super::abi::{LinuxAbi, Sysno};
use super::super::arch::GuestCpu;
use super::super::host;
use super::super::process::RLIM_INFINITY;
use super::{Ctx, SysResult};

fn is_self(c: &Ctx<'_>, pid: i32) -> bool {
    pid == 0 || pid == c.p.pid || c.is_own_tid(pid)
}

/// Returns `value` for the calling process (`pid` 0 or its own ID), else
/// `ESRCH`.
pub fn for_self(c: &mut Ctx<'_>, pid: i32, value: u64) -> SysResult {
    if pid < 0 {
        return Err(Errno(EINVAL));
    }
    if is_self(c, pid) {
        Ok(value)
    } else {
        Err(Errno(ESRCH))
    }
}

/// `getresuid`/`getresgid`.
pub fn getres(c: &mut Ctx<'_>, r: u64, e: u64, s: u64, user: bool) -> SysResult {
    let (real, eff) = if user {
        (c.p.creds.0, c.p.creds.1)
    } else {
        (c.p.creds.2, c.p.creds.3)
    };
    c.write_u32(r, real)?;
    c.write_u32(e, eff)?;
    c.write_u32(s, eff)?;
    Ok(0)
}

/// `getgroups`: the number of supplementary groups, and with a nonzero
/// `size` the groups themselves (`EINVAL` if they do not fit).
pub fn getgroups(c: &mut Ctx<'_>, size: i32, list: u64) -> SysResult {
    if size < 0 {
        return Err(Errno(EINVAL));
    }
    let n = c.p.groups.len();
    if size != 0 {
        if n > size as usize {
            return Err(Errno(EINVAL));
        }
        let b: Vec<u8> = c.p.groups.iter().flat_map(|g| g.to_le_bytes()).collect();
        c.write_mem(list, &b)?;
    }
    Ok(n as u64)
}

/// `setgroups`: with `CAP_SETGID` (root here), replaces the supplementary
/// groups with the `size` IDs at `list`, sorted (`groups_sort`); at most
/// `NGROUPS_MAX`, none of them `-1`.
pub fn setgroups(c: &mut Ctx<'_>, size: i32, list: u64) -> SysResult {
    const NGROUPS_MAX: u32 = 65536;
    if c.p.creds.1 != 0 {
        return Err(Errno(EPERM));
    }
    if size as u32 > NGROUPS_MAX {
        return Err(Errno(EINVAL));
    }
    let mut groups = Vec::with_capacity(size as usize);
    for i in 0..size as u64 {
        let g = c.read_u32(list + 4 * i)?;
        if g == u32::MAX {
            return Err(Errno(EINVAL));
        }
        groups.push(g);
    }
    groups.sort_unstable();
    c.p.groups = groups;
    Ok(0)
}

/// The `set*id` family. An unprivileged process may only switch among its
/// current real and effective IDs (`-1` leaves an ID unchanged); a
/// privileged process may set any value.
pub fn setid(c: &mut Ctx<'_>, s: Sysno, a: [u64; 6]) -> SysResult {
    let (uid, euid, gid, egid) = c.p.creds;
    let privileged = euid == 0;
    let arg = |i: usize| a[i] as u32;
    let allowed = |v: u32, cur: (u32, u32)| v == u32::MAX || privileged || v == cur.0 || v == cur.1;
    let pick = |v: u32, old: u32| if v == u32::MAX { old } else { v };
    match s {
        Sysno::Setuid => {
            let v = arg(0);
            if v == u32::MAX {
                return Err(Errno(EINVAL));
            }
            if !allowed(v, (uid, euid)) {
                return Err(Errno(EPERM));
            }
            if privileged {
                c.p.creds.0 = v;
            }
            c.p.creds.1 = v;
        }
        Sysno::Setgid => {
            let v = arg(0);
            if v == u32::MAX {
                return Err(Errno(EINVAL));
            }
            if !allowed(v, (gid, egid)) {
                return Err(Errno(EPERM));
            }
            if privileged {
                c.p.creds.2 = v;
            }
            c.p.creds.3 = v;
        }
        Sysno::Setreuid | Sysno::Setresuid => {
            let (r, e) = (arg(0), arg(1));
            if !allowed(r, (uid, euid)) || !allowed(e, (uid, euid)) {
                return Err(Errno(EPERM));
            }
            c.p.creds.0 = pick(r, uid);
            c.p.creds.1 = pick(e, euid);
        }
        Sysno::Setregid | Sysno::Setresgid => {
            let (r, e) = (arg(0), arg(1));
            if !allowed(r, (gid, egid)) || !allowed(e, (gid, egid)) {
                return Err(Errno(EPERM));
            }
            c.p.creds.2 = pick(r, gid);
            c.p.creds.3 = pick(e, egid);
        }
        _ => return Err(Errno(ENOSYS)),
    }
    Ok(0)
}

/// `getpgid`/`getsid`: the process is its own group and session leader.
pub fn getpgid(c: &mut Ctx<'_>, pid: i32) -> SysResult {
    // A thread of this process names the process (find_task_by_vpid).
    let pid = if c.is_own_tid(pid) { 0 } else { pid };
    host::getpgid(pid).map(|g| g as u64)
}

/// `getsid`.
pub fn getsid(c: &mut Ctx<'_>, pid: i32) -> SysResult {
    let pid = if c.is_own_tid(pid) { 0 } else { pid };
    host::getsid(pid).map(|g| g as u64)
}

/// `setpgid`: a thread other than the leader is `EINVAL`.
pub fn setpgid(c: &mut Ctx<'_>, pid: i32, pgid: i32) -> SysResult {
    if pgid < 0 {
        return Err(Errno(EINVAL));
    }
    let pid = if pid == c.p.pid {
        0
    } else if c.is_own_tid(pid) {
        return Err(Errno(EINVAL));
    } else {
        pid
    };
    host::setpgid(pid, pgid).map(|()| 0)
}

/// `uname`.
pub fn uname(c: &mut Ctx<'_>, buf: u64) -> SysResult {
    let host = host::hostname();
    let release = c.p.config.kernel_release.clone();
    let b = encode_utsname([
        "Linux",
        &host,
        &release,
        "#1 SMP PREEMPT_DYNAMIC rax-user",
        c.p.abi.machine(),
        "(none)",
    ]);
    c.write_mem(buf, &b)?;
    Ok(0)
}

/// `sysinfo`: memory figures describe the guest arena.
pub fn sysinfo(c: &mut Ctx<'_>, buf: u64) -> SysResult {
    let total = c.p.config.arena_bytes;
    let used = c.p.space.resident_pages() * 4096;
    let (uptime, _) = host::clock_gettime(host::HostClock::Monotonic);
    let info = SysInfo {
        uptime,
        totalram: total,
        freeram: total.saturating_sub(used),
        procs: 1,
        mem_unit: 1,
        ..Default::default()
    };
    c.write_mem(buf, &info.encode())?;
    Ok(0)
}

/// `prlimit64` (and `getrlimit`/`setrlimit` with `pid` 0).
pub fn prlimit(c: &mut Ctx<'_>, pid: i32, resource: u32, new: u64, old: u64) -> SysResult {
    const RLIMIT_NOFILE: usize = 7;
    const NR_OPEN: u64 = 1 << 20;
    if resource >= 16 {
        return Err(Errno(EINVAL));
    }
    if !is_self(c, pid) {
        return Err(Errno(ESRCH));
    }
    let r = resource as usize;
    let current = c.p.rlimits[r];
    let requested = if new != 0 {
        let b = c.read_mem(new, 16)?;
        let cur = u64::from_le_bytes(b[..8].try_into().unwrap());
        let max = u64::from_le_bytes(b[8..].try_into().unwrap());
        if cur > max {
            return Err(Errno(EINVAL));
        }
        if max > current.1 && c.p.creds.1 != 0 {
            return Err(Errno(EPERM));
        }
        if r == RLIMIT_NOFILE && max != RLIM_INFINITY && max > NR_OPEN {
            return Err(Errno(EPERM));
        }
        Some((cur, max))
    } else {
        None
    };
    if old != 0 {
        let mut e = Encoder::new();
        e.u64(current.0).u64(current.1);
        c.write_mem(old, &e.finish())?;
    }
    if let Some(v) = requested {
        c.p.rlimits[r] = v;
    }
    Ok(0)
}

/// `getrusage` (`struct rusage`, 144 bytes). The emulator's own usage
/// stands for the guest's.
pub fn getrusage(c: &mut Ctx<'_>, who: i32, buf: u64) -> SysResult {
    const RUSAGE_SELF: i32 = 0;
    const RUSAGE_CHILDREN: i32 = -1;
    const RUSAGE_THREAD: i32 = 1;
    let (user_us, sys_us, maxrss) = match who {
        RUSAGE_SELF | RUSAGE_THREAD => host::rusage_self(),
        RUSAGE_CHILDREN => (0, 0, 0),
        _ => return Err(Errno(EINVAL)),
    };
    let mut e = Encoder::new();
    e.u64(user_us / 1_000_000)
        .u64(user_us % 1_000_000)
        .u64(sys_us / 1_000_000)
        .u64(sys_us % 1_000_000)
        .u64(maxrss)
        .zeros(13 * 8);
    c.write_mem(buf, &e.finish())?;
    Ok(0)
}

/// `times`: returns clock ticks (`USER_HZ` = 100) since an arbitrary point.
pub fn times(c: &mut Ctx<'_>, buf: u64) -> SysResult {
    let (user_us, sys_us, _) = host::rusage_self();
    if buf != 0 {
        let mut e = Encoder::new();
        e.u64(user_us / 10_000).u64(sys_us / 10_000).u64(0).u64(0);
        c.write_mem(buf, &e.finish())?;
    }
    let (s, ns) = host::clock_gettime(host::HostClock::Monotonic);
    Ok((s as u64) * 100 + (ns as u64) / 10_000_000)
}

/// `prctl`.
pub fn prctl(c: &mut Ctx<'_>, option: i32, a2: u64, a3: u64, a4: u64, a5: u64) -> SysResult {
    const PR_SET_PDEATHSIG: i32 = 1;
    const PR_GET_PDEATHSIG: i32 = 2;
    const PR_GET_DUMPABLE: i32 = 3;
    const PR_SET_DUMPABLE: i32 = 4;
    const PR_GET_KEEPCAPS: i32 = 7;
    const PR_SET_KEEPCAPS: i32 = 8;
    const PR_SET_NAME: i32 = 15;
    const PR_GET_NAME: i32 = 16;
    const PR_GET_SECCOMP: i32 = 21;
    const PR_SET_SECCOMP: i32 = 22;
    const PR_GET_TSC: i32 = 25;
    const PR_SET_TSC: i32 = 26;
    const PR_TSC_ENABLE: u64 = 1;
    const PR_TSC_SIGSEGV: u64 = 2;
    const PR_CAPBSET_READ: i32 = 23;
    const PR_SET_TIMERSLACK: i32 = 29;
    const PR_GET_TIMERSLACK: i32 = 30;
    const PR_SET_CHILD_SUBREAPER: i32 = 36;
    const PR_GET_CHILD_SUBREAPER: i32 = 37;
    const PR_SET_NO_NEW_PRIVS: i32 = 38;
    const PR_GET_NO_NEW_PRIVS: i32 = 39;
    const PR_GET_TID_ADDRESS: i32 = 40;
    const PR_SET_THP_DISABLE: i32 = 41;
    const PR_GET_THP_DISABLE: i32 = 42;
    const PR_GET_AUXV: i32 = 0x4155_5856;
    let _ = (a4, a5);
    match option {
        PR_SET_PDEATHSIG => {
            if a2 > 64 {
                return Err(Errno(EINVAL));
            }
            c.p.pdeathsig = a2 as i32;
            Ok(0)
        }
        PR_GET_PDEATHSIG => c.write_u32(a2, c.p.pdeathsig as u32).map(|_| 0),
        PR_GET_DUMPABLE => Ok(c.p.dumpable),
        PR_SET_DUMPABLE => {
            if a2 > 1 {
                return Err(Errno(EINVAL));
            }
            c.p.dumpable = a2;
            Ok(0)
        }
        PR_GET_KEEPCAPS => Ok(0),
        PR_SET_KEEPCAPS => {
            if a2 > 1 {
                return Err(Errno(EINVAL));
            }
            Ok(0)
        }
        PR_SET_NAME => {
            // strncpy_from_user of at most 15 bytes: no NUL is required.
            let mut name = match c.p.space.read_cstr(a2, 15) {
                Ok(Some(s)) => s,
                Ok(None) => c.read_mem(a2, 15)?,
                Err(_) => return Err(Errno(EFAULT)),
            };
            name.truncate(15);
            if c.t.tid == c.p.pid {
                c.p.comm = name.clone();
            }
            c.t.comm = name;
            Ok(0)
        }
        PR_GET_NAME => {
            let mut b = c.t.comm.clone();
            b.resize(16, 0);
            c.write_mem(a2, &b)?;
            Ok(0)
        }
        PR_GET_SECCOMP => Ok(u64::from(c.t.seccomp.mode)),
        PR_SET_SECCOMP => super::seccomp::prctl_set(c, a2, a3),
        // get_tsc_mode and set_tsc_mode (x86); other architectures define
        // neither (EINVAL).
        PR_GET_TSC | PR_SET_TSC if c.p.abi != LinuxAbi::X86_64 => Err(Errno(EINVAL)),
        PR_GET_TSC => {
            let mode = if c.t.notsc {
                PR_TSC_SIGSEGV
            } else {
                PR_TSC_ENABLE
            };
            c.write_u32(a2, mode as u32).map(|_| 0)
        }
        PR_SET_TSC => {
            // set_tsc_mode takes an unsigned int.
            let mode = u64::from(a2 as u32);
            if mode != PR_TSC_ENABLE && mode != PR_TSC_SIGSEGV {
                return Err(Errno(EINVAL));
            }
            c.t.notsc = mode == PR_TSC_SIGSEGV;
            c.t.cpu.set_tsc_disabled(c.t.notsc);
            Ok(0)
        }
        PR_CAPBSET_READ => {
            if a2 > 63 {
                return Err(Errno(EINVAL));
            }
            Ok(u64::from(a2 <= 40))
        }
        PR_SET_TIMERSLACK => {
            c.p.timerslack = if a2 == 0 { 50_000 } else { a2 };
            Ok(0)
        }
        PR_GET_TIMERSLACK => Ok(c.p.timerslack),
        PR_SET_CHILD_SUBREAPER => Ok(0),
        PR_GET_CHILD_SUBREAPER => c.write_u32(a2, 0).map(|_| 0),
        PR_SET_NO_NEW_PRIVS => {
            if a2 != 1 || a3 != 0 || a4 != 0 || a5 != 0 {
                return Err(Errno(EINVAL));
            }
            c.t.no_new_privs = true;
            Ok(0)
        }
        PR_GET_NO_NEW_PRIVS => {
            if a2 != 0 || a3 != 0 || a4 != 0 || a5 != 0 {
                return Err(Errno(EINVAL));
            }
            Ok(u64::from(c.t.no_new_privs))
        }
        PR_GET_TID_ADDRESS => c.write_u64(a2, c.t.clear_child_tid).map(|_| 0),
        PR_SET_THP_DISABLE | PR_GET_THP_DISABLE => Ok(0),
        PR_GET_AUXV => {
            if a4 != 0 || a5 != 0 {
                return Err(Errno(EINVAL));
            }
            let bytes = super::super::procfs::auxv(c.p);
            let n = bytes.len().min(a3 as usize);
            c.write_mem(a2, &bytes[..n])?;
            Ok(bytes.len() as u64)
        }
        _ => Err(Errno(EINVAL)),
    }
}

/// `arch_prctl` (x86-64).
pub fn arch_prctl(c: &mut Ctx<'_>, code: u32, addr: u64) -> SysResult {
    const ARCH_SET_GS: u32 = 0x1001;
    const ARCH_SET_FS: u32 = 0x1002;
    const ARCH_GET_FS: u32 = 0x1003;
    const ARCH_GET_GS: u32 = 0x1004;
    const ARCH_GET_CPUID: u32 = 0x1011;
    const ARCH_SET_CPUID: u32 = 0x1012;
    const ARCH_GET_XCOMP_SUPP: u32 = 0x1021;
    const ARCH_GET_XCOMP_PERM: u32 = 0x1022;
    let GuestCpu::X86_64(cpu) = &mut c.t.cpu else {
        return Err(Errno(ENOSYS));
    };
    let task_size_max = LinuxAbi::X86_64.task_size();
    match code {
        ARCH_SET_FS | ARCH_SET_GS => {
            if addr >= task_size_max {
                return Err(Errno(EPERM));
            }
            if code == ARCH_SET_FS {
                cpu.vcpu_mut().set_fs_base(addr);
            } else {
                cpu.vcpu_mut().set_gs_base(addr);
            }
            Ok(0)
        }
        ARCH_GET_FS | ARCH_GET_GS => {
            let v = if code == ARCH_GET_FS {
                cpu.vcpu().fs_base()
            } else {
                cpu.vcpu().gs_base()
            };
            c.write_u64(addr, v)?;
            Ok(0)
        }
        // CPUID faulting is not available on the emulated CPU.
        ARCH_GET_CPUID => Ok(1),
        ARCH_SET_CPUID => {
            if addr != 0 {
                Ok(0)
            } else {
                Err(Errno(ENODEV))
            }
        }
        ARCH_GET_XCOMP_SUPP | ARCH_GET_XCOMP_PERM => {
            let xcr0 = cpu.vcpu().xcr0();
            c.write_u64(addr, xcr0)?;
            Ok(0)
        }
        _ => Err(Errno(EINVAL)),
    }
}

/// `personality`: returns the previous value and, unless the argument is
/// `0xffffffff`, installs the new one. `PER_LINUX` is the only execution
/// domain; `READ_IMPLIES_EXEC` is honored by `mmap` and `mprotect`, and
/// `ADDR_NO_RANDOMIZE` changes nothing because the layout is never
/// randomized.
pub fn personality(c: &mut Ctx<'_>, persona: u32) -> SysResult {
    let old = c.p.persona;
    if persona != u32::MAX {
        c.p.persona = persona;
    }
    Ok(u64::from(old))
}

/// `getrandom`.
pub fn getrandom(c: &mut Ctx<'_>, buf: u64, len: u64, flags: u32) -> SysResult {
    const GRND_NONBLOCK: u32 = 1;
    const GRND_RANDOM: u32 = 2;
    const GRND_INSECURE: u32 = 4;
    if flags & !(GRND_NONBLOCK | GRND_RANDOM | GRND_INSECURE) != 0
        || flags & (GRND_RANDOM | GRND_INSECURE) == GRND_RANDOM | GRND_INSECURE
    {
        return Err(Errno(EINVAL));
    }
    let len = len.min(i32::MAX as u64) as usize;
    let mut done = 0usize;
    let mut chunk = vec![0u8; len.min(1 << 16)];
    while done < len {
        let n = (len - done).min(chunk.len());
        c.p.entropy.fill(&mut chunk[..n])?;
        if c.write_mem(buf + done as u64, &chunk[..n]).is_err() {
            return if done > 0 {
                Ok(done as u64)
            } else {
                Err(Errno(EFAULT))
            };
        }
        done += n;
    }
    Ok(done as u64)
}

/// `sched_getaffinity`: one CPU (CPU 0) executes every guest thread.
pub fn sched_getaffinity(c: &mut Ctx<'_>, pid: i32, len: u64, mask: u64) -> SysResult {
    if !is_self(c, pid) {
        return Err(Errno(ESRCH));
    }
    if len * 8 < 1 || len & 7 != 0 {
        return Err(Errno(EINVAL));
    }
    c.write_u64(mask, 1)?;
    Ok(8)
}

/// `sched_setaffinity`: the mask must include CPU 0.
pub fn sched_setaffinity(c: &mut Ctx<'_>, pid: i32, len: u64, mask: u64) -> SysResult {
    if !is_self(c, pid) {
        return Err(Errno(ESRCH));
    }
    if len == 0 {
        return Err(Errno(EINVAL));
    }
    let first = c.read_mem(mask, 1)?;
    if first[0] & 1 == 0 {
        return Err(Errno(EINVAL));
    }
    Ok(0)
}

/// `getcpu`.
pub fn getcpu(c: &mut Ctx<'_>, cpu: u64, node: u64) -> SysResult {
    if cpu != 0 {
        c.write_u32(cpu, 0)?;
    }
    if node != 0 {
        c.write_u32(node, 0)?;
    }
    Ok(0)
}

/// `sched_getparam`.
pub fn sched_getparam(c: &mut Ctx<'_>, pid: i32, param: u64) -> SysResult {
    for_self(c, pid, 0)?;
    c.write_u32(param, 0)?;
    Ok(0)
}

/// `sched_get_priority_max`/`min`.
pub fn sched_priority(policy: i32) -> SysResult {
    match policy {
        0 | 3 | 5 | 6 => Ok(0),
        1 | 2 => Ok(99),
        _ => Err(Errno(EINVAL)),
    }
}

/// `capget`: an unprivileged process holds no capabilities.
pub fn capget(c: &mut Ctx<'_>, hdr: u64, data: u64) -> SysResult {
    const V1: u32 = 0x1998_0330;
    const V2: u32 = 0x2007_1026;
    const V3: u32 = 0x2008_0522;
    let version = c.read_u32(hdr)?;
    let words = match version {
        V1 => 1,
        V2 | V3 => 2,
        _ => {
            c.write_u32(hdr, V3)?;
            return if data == 0 { Ok(0) } else { Err(Errno(EINVAL)) };
        }
    };
    if data != 0 {
        let full = c.p.creds.1 == 0;
        let mut e = Encoder::new();
        for i in 0..words {
            let bits = if full {
                if i == 0 { u32::MAX } else { 0x1ff }
            } else {
                0
            };
            e.u32(bits).u32(bits).u32(0);
        }
        c.write_mem(data, &e.finish())?;
    }
    Ok(0)
}

/// `riscv_hwprobe`.
pub fn riscv_hwprobe(
    c: &mut Ctx<'_>,
    pairs: u64,
    count: u64,
    _cpusetsize: u64,
    _cpus: u64,
    flags: u32,
) -> SysResult {
    let GuestCpu::Riscv64(cpu) = &c.t.cpu else {
        return Err(Errno(ENOSYS));
    };
    if flags != 0 {
        return Err(Errno(EINVAL));
    }
    let isa = cpu.core().config().isa;
    let mut ext = 0u64;
    let mut set = |on: bool, bit: u32| {
        if on {
            ext |= 1 << bit;
        }
    };
    set(isa.f && isa.d, 0);
    set(isa.c, 1);
    set(isa.v, 2);
    set(isa.zba, 3);
    set(isa.zbb, 4);
    set(isa.zbs, 5);
    set(isa.zicboz, 6);
    set(isa.zbc, 7);
    set(isa.zbkb, 8);
    set(isa.zbkx, 10);
    set(isa.zknd, 11);
    set(isa.zkne, 12);
    set(isa.zknh, 13);
    set(isa.zksed, 14);
    set(isa.zksh, 15);
    set(isa.zfh, 27);
    set(isa.zihintntl, 29);
    set(isa.zfa, 32);
    set(isa.zacas, 34);
    set(isa.zicond, 35);
    set(isa.zihintpause, 36);
    set(isa.c, 43);
    set(isa.zcb, 44);
    set(isa.c && isa.d, 45);
    set(isa.zawrs, 48);
    set(isa.zicbom, 55);
    set(isa.a, 56);
    set(isa.a, 57);
    set(isa.zicbop, 60);
    let task = c.p.abi.task_size();
    for i in 0..count {
        let addr = pairs + i * 16;
        let key = c.read_u64(addr)? as i64;
        let value: Option<u64> = match key {
            0..=2 => Some(0),
            3 => Some(1),
            4 => Some(ext),
            // Misaligned-access performance is unknown for an emulator.
            5 | 9 | 10 => Some(0),
            6 | 12 | 15 => Some(64),
            7 => Some(task - 1),
            8 => Some(crate::user::cpu::riscv64::TIMEBASE_HZ),
            _ => None,
        };
        match value {
            Some(v) => c.write_u64(addr + 8, v)?,
            None => {
                c.write_u64(addr, u64::MAX)?;
                c.write_u64(addr + 8, 0)?;
            }
        }
    }
    Ok(0)
}

/// `membarrier`: with one CPU executing every thread, each barrier is
/// already satisfied.
pub fn membarrier(cmd: i32, flags: u32) -> SysResult {
    const QUERY: i32 = 0;
    const SUPPORTED: u64 = 1 | 2 | 4 | 8 | 16 | 32 | 64;
    if flags != 0 {
        return Err(Errno(EINVAL));
    }
    match cmd {
        QUERY => Ok(SUPPORTED),
        c if c > 0 && (c as u64) & SUPPORTED == c as u64 && (c as u64).is_power_of_two() => Ok(0),
        _ => Err(Errno(EINVAL)),
    }
}
