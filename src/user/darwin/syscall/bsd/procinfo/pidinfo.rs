//! `PROC_INFO_CALL_PIDINFO` about the calling process (`proc_pidinfo`).

use super::{Args, Out, canonical, host_self, pif, vnode_info};
use crate::user::darwin::abi::{DarwinAbi, Errno};
use crate::user::darwin::arch::{Rv, SysResult};
use crate::user::darwin::process::Thread;
use crate::user::darwin::syscall::Ctx;
use crate::user::darwin::vm::VmFlags;
use crate::user::mm::{Backing, Vma};

/// `PROC_PID*` flavors.
mod f {
    pub const LISTFDS: i32 = 1;
    pub const TASKALLINFO: i32 = 2;
    pub const TBSDINFO: i32 = 3;
    pub const TASKINFO: i32 = 4;
    pub const THREADINFO: i32 = 5;
    pub const LISTTHREADS: i32 = 6;
    pub const REGIONINFO: i32 = 7;
    pub const REGIONPATHINFO: i32 = 8;
    pub const VNODEPATHINFO: i32 = 9;
    pub const THREADPATHINFO: i32 = 10;
    pub const PATHINFO: i32 = 11;
    pub const WORKQUEUEINFO: i32 = 12;
    pub const SHORTBSDINFO: i32 = 13;
    pub const LISTFILEPORTS: i32 = 14;
    pub const THREADID64INFO: i32 = 15;
    pub const UNIQIDENTIFIERINFO: i32 = 17;
    pub const BSDINFOWITHUNIQID: i32 = 18;
    pub const ARCHINFO: i32 = 19;
    pub const COALITIONINFO: i32 = 20;
    pub const NOTEEXIT: i32 = 21;
    pub const REGIONPATHINFO2: i32 = 22;
    pub const REGIONPATHINFO3: i32 = 23;
    pub const EXITREASONINFO: i32 = 24;
    pub const EXITREASONBASICINFO: i32 = 25;
    pub const LISTUPTRS: i32 = 26;
    pub const LISTDYNKQUEUES: i32 = 27;
    pub const LISTTHREADIDS: i32 = 28;
    pub const VMRTFAULTINFO: i32 = 29;
    pub const PLATFORMINFO: i32 = 30;
    pub const REGIONPATH: i32 = 31;
    pub const IPCTABLEINFO: i32 = 32;
    pub const THREADSCHEDINFO: i32 = 33;
    pub const THREADCOUNTS: i32 = 34;
}

/// `PROC_FLAG_EXEC`, `PROC_FLAG_SLEADER`, `PROC_FLAG_CTTY`.
const PROC_FLAG_EXEC: u32 = 0x4000;
const PROC_FLAG_SLEADER: u32 = 0x20;
const PROC_FLAG_CTTY: u32 = 0x40;

/// `PROC_REGION_SHARED`.
const PROC_REGION_SHARED: u32 = 2;

/// The size a flavor's buffer must have (`proc_pidinfo`'s size switch);
/// `None` for an unknown flavor.
fn min_size(flavor: i32, null: bool) -> Option<u32> {
    Some(match flavor {
        f::LISTFDS | f::LISTFILEPORTS | f::LISTUPTRS | f::LISTDYNKQUEUES if null => 0,
        f::VMRTFAULTINFO if null => 0,
        f::LISTFDS | f::LISTFILEPORTS | f::LISTUPTRS | f::LISTDYNKQUEUES => 8,
        f::TASKALLINFO => 232,
        f::TBSDINFO => 136,
        f::TASKINFO => 96,
        f::THREADINFO | f::THREADID64INFO => 112,
        f::LISTTHREADS | f::LISTTHREADIDS => 8,
        f::REGIONINFO => 96,
        f::REGIONPATHINFO | f::REGIONPATHINFO2 | f::REGIONPATHINFO3 => 1272,
        f::VNODEPATHINFO => 2352,
        f::THREADPATHINFO => 1288,
        f::PATHINFO => 1024,
        f::WORKQUEUEINFO => 16,
        f::SHORTBSDINFO => 64,
        f::UNIQIDENTIFIERINFO => 56,
        f::BSDINFOWITHUNIQID => 192,
        f::ARCHINFO => 8,
        f::COALITIONINFO => 40,
        f::NOTEEXIT => 4,
        f::EXITREASONINFO => 32,
        f::EXITREASONBASICINFO => 24,
        f::VMRTFAULTINFO => 56,
        f::PLATFORMINFO => 4,
        f::REGIONPATH => 1040,
        f::IPCTABLEINFO | f::THREADSCHEDINFO | f::THREADCOUNTS => 8,
        _ => return None,
    })
}

/// `proc_pidinfo` for the calling process.
pub fn own(ctx: &mut Ctx<'_>, a: &Args) -> SysResult {
    let null = a.buffer == 0;
    let size = min_size(a.flavor, null).ok_or(Errno::EINVAL)?;
    if a.size < size {
        return Err(Errno::ENOMEM);
    }
    if a.flavor == f::PATHINFO && a.size > 4096 {
        return Err(Errno::EOVERFLOW);
    }
    // The target is live and the caller's own; extended identifiers must
    // match.
    if a.flags & pif::COMPARE_IDVERSION != 0 && a.ext_id != u64::from(ctx.proc.audit[7]) {
        return Err(Errno::ESRCH);
    }
    if a.flags & pif::COMPARE_UNIQUEID != 0 && a.ext_id != uniqueid(ctx) {
        return Err(Errno::ESRCH);
    }
    match a.flavor {
        f::LISTFDS => listfds(ctx, a),
        f::TASKALLINFO => {
            let mut o = Out::new(232);
            o.bytes(0, &bsdinfo(ctx)?.0).bytes(136, &taskinfo(ctx).0);
            copyout(ctx, a, &o.0)
        }
        f::TBSDINFO => copyout(ctx, a, &bsdinfo(ctx)?.0),
        f::TASKINFO => copyout(ctx, a, &taskinfo(ctx).0),
        f::THREADINFO | f::THREADID64INFO => {
            let by_id = a.flavor == f::THREADID64INFO;
            let o = with_thread(ctx, a.arg, by_id, threadinfo).ok_or(Errno::ESRCH)?;
            copyout(ctx, a, &o.0)
        }
        f::LISTTHREADS | f::LISTTHREADIDS => listthreads(ctx, a),
        f::REGIONINFO | f::REGIONPATHINFO => {
            let v = region_at(ctx, a.arg).ok_or(Errno::EINVAL)?;
            let mut o = Out::new(if a.flavor == f::REGIONINFO { 96 } else { 1272 });
            regioninfo(ctx, &v, &mut o, true);
            if a.flavor == f::REGIONPATHINFO {
                region_vnode(ctx, &v, &mut o, 96);
            }
            copyout(ctx, a, &o.0)
        }
        f::REGIONPATHINFO2 | f::REGIONPATHINFO3 => {
            let v = if a.flavor == f::REGIONPATHINFO2 {
                file_region_from(ctx, a.arg)
            } else {
                file_region_on_volume(ctx, a.arg)
            }
            .ok_or(Errno::EINVAL)?;
            let mut o = Out::new(1272);
            regioninfo(ctx, &v, &mut o, false);
            if !region_vnode(ctx, &v, &mut o, 96) {
                return Err(Errno::EINVAL);
            }
            copyout(ctx, a, &o.0)
        }
        f::REGIONPATH => {
            let page = ctx.proc.vm.page;
            let v = file_region_from(ctx, a.arg & !(page - 1)).ok_or(Errno::EINVAL)?;
            let mut o = Out::new(1040);
            o.u64(0, v.start).u64(8, v.end - v.start);
            let path = region_path(&v).unwrap_or_default();
            o.path(16, 1024, &path);
            copyout(ctx, a, &o.0)
        }
        f::VNODEPATHINFO => {
            let mut o = Out::new(2352);
            let cwd = std::path::PathBuf::from(std::ffi::OsStr::new(
                &String::from_utf8_lossy(&ctx.proc.cwd).into_owned(),
            ));
            let host = ctx.proc.vfs.host_path(&ctx.proc.cwd, b"/");
            if let Some(vi) = vnode_info(&host, false) {
                o.bytes(0, &vi.0);
                o.path(152, 1024, &canonical(ctx, &host));
            } else {
                o.path(152, 1024, cwd.as_os_str().as_encoded_bytes());
            }
            copyout(ctx, a, &o.0)
        }
        f::THREADPATHINFO => {
            let t = with_thread(ctx, a.arg, false, threadinfo).ok_or(Errno::ESRCH)?;
            let mut o = Out::new(1288);
            o.bytes(0, &t.0);
            copyout(ctx, a, &o.0)
        }
        f::PATHINFO => {
            let path = ctx.proc.program.image.vnode_path.clone().into_bytes();
            let mut o = Out::new(a.size as usize);
            o.path(0, a.size as usize, &path);
            ctx.write(a.buffer, &o.0)?;
            // The handler never sets a return value.
            Ok(Rv::one(0))
        }
        f::WORKQUEUEINFO => {
            let o = workqueueinfo(ctx).ok_or(Errno::ESRCH)?;
            copyout(ctx, a, &o.0)
        }
        f::SHORTBSDINFO => copyout(ctx, a, &shortbsdinfo(ctx)?.0),
        f::LISTFILEPORTS => Ok(Rv::one(0)),
        f::UNIQIDENTIFIERINFO => copyout(ctx, a, &uniqidentifierinfo(ctx)?.0),
        f::BSDINFOWITHUNIQID => {
            let mut o = Out::new(192);
            o.bytes(0, &bsdinfo(ctx)?.0)
                .bytes(136, &uniqidentifierinfo(ctx)?.0);
            copyout(ctx, a, &o.0)
        }
        f::ARCHINFO => {
            let h = &ctx.proc.program.main.header;
            let mut o = Out::new(8);
            o.u32(0, h.cputype).u32(4, h.cpusubtype);
            copyout(ctx, a, &o.0)
        }
        f::COALITIONINFO => {
            let o = host_self(ctx.proc.pid, f::COALITIONINFO, 40)?;
            copyout(ctx, a, &o)
        }
        // The caller is not its own parent.
        f::NOTEEXIT | f::EXITREASONINFO | f::EXITREASONBASICINFO => Err(Errno::EACCES),
        f::LISTUPTRS => {
            let uptrs: Vec<u64> = ctx
                .proc
                .kq
                .kqueues
                .values()
                .flat_map(|k| k.knotes.values().map(|n| n.udata))
                .collect();
            counted(ctx, a, &uptrs, 16392)
        }
        f::LISTDYNKQUEUES => {
            let ids: Vec<u64> = ctx.proc.kq.workloops.keys().copied().collect();
            counted(ctx, a, &ids, 131_072)
        }
        f::VMRTFAULTINFO => {
            // No real-time faults are recorded; nothing to hold them is
            // a shortage.
            if null {
                return Err(Errno::ENOMEM);
            }
            Ok(Rv::one(0))
        }
        f::PLATFORMINFO => {
            let platform = ctx
                .proc
                .program
                .main
                .build
                .as_ref()
                .map_or(0, |b| b.platform);
            let mut o = Out::new(4);
            o.u32(0, platform);
            copyout(ctx, a, &o.0)
        }
        f::IPCTABLEINFO => {
            let names = ctx.proc.ipc.names().len() as u32;
            let size = ctx.proc.ipc.table_size();
            let mut o = Out::new(8);
            o.u32(0, size).u32(4, size.saturating_sub(names + 1));
            copyout(ctx, a, &o.0)
        }
        f::THREADSCHEDINFO => {
            if a.arg != ctx.thread.tid {
                return Err(Errno::EINVAL);
            }
            copyout(ctx, a, &[0u8; 8])
        }
        f::THREADCOUNTS => {
            let o = with_thread(ctx, a.arg, true, |t, abi, _| threadcounts(t, abi))
                .ok_or(Errno::ESRCH)?;
            let n = o.0.len().min(a.size as usize);
            ctx.write(a.buffer, &o.0[..n])?;
            Ok(Rv::one(n as u64))
        }
        _ => Err(Errno::EINVAL),
    }
}

/// Copies a fixed-size answer out; the return value is its size.
fn copyout(ctx: &Ctx<'_>, a: &Args, data: &[u8]) -> SysResult {
    ctx.write(a.buffer, data)?;
    Ok(Rv::one(data.len() as u64))
}

/// A list returned as a count (`PROC_PIDLISTUPTRS`,
/// `PROC_PIDLISTDYNKQUEUES`): as many values as fit (at most `cap`), and
/// the whole count.
fn counted(ctx: &Ctx<'_>, a: &Args, values: &[u64], cap: usize) -> SysResult {
    if a.buffer != 0 {
        let n = values.len().min(a.size as usize / 8).min(cap);
        let bytes: Vec<u8> = values[..n].iter().flat_map(|v| v.to_le_bytes()).collect();
        ctx.write(a.buffer, &bytes)?;
    }
    Ok(Rv::one(values.len().min(cap) as u64))
}

/// `fd_nfiles`: the descriptor table's allocated size (25, then 50 and
/// doubling as it grows).
fn fd_nfiles(ctx: &Ctx<'_>) -> u32 {
    let len = ctx.proc.fds.len() as u32;
    let mut n = 25;
    if len > 25 {
        n = 50;
        while n < len {
            n *= 2;
        }
    }
    n
}

/// `PROC_PIDLISTFDS`: the open descriptors in order with their types.
fn listfds(ctx: &Ctx<'_>, a: &Args) -> SysResult {
    let nfiles = fd_nfiles(ctx);
    if a.buffer == 0 {
        return Ok(Rv::one(u64::from(nfiles + 20) * 8));
    }
    let room = (a.size / 8).min(nfiles) as usize;
    let mut out = Vec::new();
    for (fd, slot) in ctx.proc.fds.iter().take(room) {
        out.extend_from_slice(&fd.to_le_bytes());
        out.extend_from_slice(&super::fdinfo::dtype(&slot.file).to_le_bytes());
    }
    ctx.write(a.buffer, &out)?;
    Ok(Rv::one(out.len() as u64))
}

/// The emulated process's image name (`p_comm`, `p_name`): the last
/// component of the path it was executed by.
pub(crate) fn image_name(ctx: &Ctx<'_>) -> Vec<u8> {
    let path = ctx.proc.program.image.path.as_bytes();
    let name = path.rsplit(|&c| c == b'/').next().unwrap_or(path);
    name.to_vec()
}

/// `PROC_PIDTBSDINFO` (`proc_pidbsdinfo`): the host's record of this
/// process with the emulated image's name, whether it has executed an
/// image, and its descriptor table.
fn bsdinfo(ctx: &Ctx<'_>) -> Result<Out, Errno> {
    let mut o = Out(host_self(ctx.proc.pid, f::TBSDINFO, 136)?);
    let flags = u32::from_le_bytes(o.0[0..4].try_into().expect("4 bytes"));
    let flags = (flags & !PROC_FLAG_EXEC) | if ctx.proc.execed { PROC_FLAG_EXEC } else { 0 };
    let name = image_name(ctx);
    o.u32(0, flags)
        .u32(8, 0)
        .str(48, 16, &name)
        .str(64, 32, &name)
        .u32(96, fd_nfiles(ctx));
    Ok(o)
}

/// `PROC_PIDT_SHORTBSDINFO`: as the full record's, without the session
/// flags.
fn shortbsdinfo(ctx: &Ctx<'_>) -> Result<Out, Errno> {
    let b = bsdinfo(ctx)?;
    let w = |off: usize| u32::from_le_bytes(b.0[off..off + 4].try_into().expect("4 bytes"));
    let mut o = Out::new(64);
    o.u32(0, w(12))
        .u32(4, w(16))
        .u32(8, w(100))
        .u32(12, w(4))
        .bytes(16, &b.0[48..64])
        .u32(32, w(0) & !(PROC_FLAG_SLEADER | PROC_FLAG_CTTY))
        .u32(36, w(20))
        .u32(40, w(24))
        .u32(44, w(28))
        .u32(48, w(32))
        .u32(52, w(36))
        .u32(56, w(40));
    Ok(o)
}

/// The host's unique identifier of this process.
fn uniqueid(ctx: &Ctx<'_>) -> u64 {
    host_self(ctx.proc.pid, f::UNIQIDENTIFIERINFO, 56)
        .map(|b| u64::from_le_bytes(b[16..24].try_into().expect("8 bytes")))
        .unwrap_or(0)
}

/// `PROC_PIDUNIQIDENTIFIERINFO`: the executable's UUID, the host's unique
/// identifiers, and the task's pid version.
fn uniqidentifierinfo(ctx: &Ctx<'_>) -> Result<Out, Errno> {
    let mut o = Out(host_self(ctx.proc.pid, f::UNIQIDENTIFIERINFO, 56)?);
    o.bytes(0, &ctx.proc.program.main.uuid.unwrap_or_default())
        .u32(32, ctx.proc.audit[7]);
    Ok(o)
}

/// Nanoseconds to Mach absolute-time units.
fn to_abs(abi: DarwinAbi, ns: u64) -> u64 {
    match abi {
        DarwinAbi::X86_64 => ns,
        DarwinAbi::Arm64 => {
            (u128::from(ns) * u128::from(crate::user::darwin::arch::ARM64_COUNTER_HZ)
                / 1_000_000_000) as u64
        }
    }
}

/// Every live thread: the calling one and the others.
fn threads<'a>(ctx: &'a Ctx<'_>) -> Vec<(&'a Thread, bool)> {
    let mut v: Vec<(&Thread, bool)> = ctx
        .proc
        .threads
        .values()
        .filter(|t| !t.exited)
        .map(|t| (t, false))
        .collect();
    v.push((&*ctx.thread, true));
    v.sort_by_key(|(t, _)| t.tid);
    v
}

/// `PROC_PIDTASKINFO` (`fill_taskprocinfo`): the address space's size and
/// resident memory, CPU time in Mach units (all threads, then the live
/// ones), the task's counters, and its threads.
fn taskinfo(ctx: &Ctx<'_>) -> Out {
    let abi = ctx.proc.abi;
    let vsize: u64 = ctx.proc.space.vma_snapshot().iter().map(|v| v.len()).sum();
    let resident = ctx.proc.space.resident_pages() * crate::user::mm::PAGE_SIZE;
    let live = threads(ctx);
    let (lu, ls) = live.iter().fold((0, 0), |(u, s), (t, _)| {
        (u + t.mach.user_ns, s + t.mach.system_ns)
    });
    let (du, ds) = ctx.proc.task.dead_times;
    let csw: u64 = live.iter().map(|(t, _)| t.mach.csw).sum();
    let running = live.iter().filter(|(t, own)| *own || t.runnable()).count();
    let clamp = |v: u64| v.min(i32::MAX as u64) as u32;
    let mut o = Out::new(96);
    o.u64(0, vsize)
        .u64(8, resident)
        .u64(16, to_abs(abi, lu + du))
        .u64(24, to_abs(abi, ls + ds))
        .u64(32, to_abs(abi, lu))
        .u64(40, to_abs(abi, ls))
        .u32(48, 1) // POLICY_TIMESHARE
        .u32(64, clamp(ctx.proc.task.messages.0))
        .u32(68, clamp(ctx.proc.task.messages.1))
        .u32(72, clamp(ctx.proc.task.syscalls.0))
        .u32(76, clamp(ctx.proc.task.syscalls.1))
        .u32(80, clamp(csw))
        .u32(84, live.len() as u32)
        .u32(88, running as u32)
        .u32(92, 31);
    o
}

/// Runs `f` on the live thread `key` names: its TSD base (`cthread_self`)
/// or, with `by_id`, its 64-bit identifier.
fn with_thread<R>(
    ctx: &Ctx<'_>,
    key: u64,
    by_id: bool,
    f: impl FnOnce(&Thread, DarwinAbi, bool) -> R,
) -> Option<R> {
    threads(ctx)
        .into_iter()
        .find(|(t, _)| {
            if by_id {
                t.tid == key
            } else {
                t.cpu.tsd_base() == key
            }
        })
        .map(|(t, own)| f(t, ctx.proc.abi, own))
}

/// `proc_threadinfo` (`fill_taskthreadinfo`): the thread's basic
/// information (its times at microsecond granularity), priorities, and
/// name.
fn threadinfo(t: &Thread, _: DarwinAbi, running: bool) -> Out {
    use crate::user::darwin::mig::thread as mt;
    let b = mt::basic_info(t, running);
    let time = |w: usize| u64::from(b[w]) * 1_000_000_000 + u64::from(b[w + 1]) * 1000;
    let mut o = Out::new(112);
    o.u64(0, time(0))
        .u64(8, time(2))
        .u32(16, b[4])
        .u32(20, b[5])
        .u32(24, b[6])
        .u32(28, b[7])
        .u32(32, b[9])
        .u32(36, mt::BASEPRI_DEFAULT)
        .u32(40, mt::BASEPRI_DEFAULT)
        .u32(44, mt::MAXPRI_USER)
        .str(48, 64, &t.name);
    o
}

/// `PROC_PIDLISTTHREADS` and `PROC_PIDLISTTHREADIDS`: the threads in
/// creation order, by TSD base or identifier.
fn listthreads(ctx: &Ctx<'_>, a: &Args) -> SysResult {
    let ids = a.flavor == f::LISTTHREADIDS;
    let all = threads(ctx);
    let n = all.len().min(a.size as usize / 8);
    let bytes: Vec<u8> = all[..n]
        .iter()
        .flat_map(|(t, _)| if ids { t.tid } else { t.cpu.tsd_base() }.to_le_bytes())
        .collect();
    ctx.write(a.buffer, &bytes)?;
    Ok(Rv::one(bytes.len() as u64))
}

/// `PROC_PIDTHREADCOUNTS`: the header and one record per performance
/// level (Apple silicon has two, an Intel Mac one); only the times are
/// kept.
fn threadcounts(t: &Thread, abi: DarwinAbi) -> Out {
    let levels: u16 = match abi {
        DarwinAbi::Arm64 => 2,
        DarwinAbi::X86_64 => 1,
    };
    let mut o = Out::new(8 + 40 * levels as usize);
    o.u16(0, levels)
        .u64(8 + 16, to_abs(abi, t.mach.user_ns))
        .u64(8 + 24, to_abs(abi, t.mach.system_ns));
    o
}

/// `PROC_PIDWORKQUEUEINFO` (`fill_procworkqueue`), once the process has
/// a work queue.
fn workqueueinfo(ctx: &Ctx<'_>) -> Option<Out> {
    if !ctx.proc.wq.opened {
        return None;
    }
    let [n, running, blocked, state] = crate::user::darwin::workq::info(ctx.proc, ctx.thread.tid);
    let mut o = Out::new(16);
    o.u32(0, n).u32(4, running).u32(8, blocked).u32(12, state);
    Some(o)
}

/// The mapping containing `addr` or the first above it.
fn region_at(ctx: &Ctx<'_>, addr: u64) -> Option<Vma> {
    ctx.proc
        .space
        .vmas_in(addr, u64::MAX)
        .into_iter()
        .find(|v| v.end > addr)
}

/// Whether a mapping is a file's (named by the file's path; the
/// commpage and the shared region are not files).
fn is_file(v: &Vma) -> bool {
    !matches!(v.backing, Backing::Anonymous) && v.name.as_ref().is_some_and(|n| n.starts_with('/'))
}

/// The first file mapping containing `addr` or above it.
fn file_region_from(ctx: &Ctx<'_>, addr: u64) -> Option<Vma> {
    ctx.proc
        .space
        .vmas_in(addr, u64::MAX)
        .into_iter()
        .find(|v| v.end > addr && is_file(v))
}

/// The first file mapping of a file on the volume `fsid64`
/// (`val[0] | val[1] << 32`).
fn file_region_on_volume(ctx: &Ctx<'_>, fsid64: u64) -> Option<Vma> {
    ctx.proc
        .space
        .vmas_in(0, u64::MAX)
        .into_iter()
        .filter(is_file)
        .find(|v| {
            region_vnode_info(ctx, v).is_some_and(|vi| {
                let lo = u64::from(u32::from_le_bytes(vi.0[144..148].try_into().expect("4")));
                let hi = u64::from(u32::from_le_bytes(vi.0[148..152].try_into().expect("4")));
                lo | hi << 32 == fsid64
            })
        })
}

/// A file mapping's host path.
fn region_host_path(ctx: &Ctx<'_>, v: &Vma) -> Option<std::path::PathBuf> {
    let name = v.name.as_ref()?;
    Some(ctx.proc.vfs.host_path(name.as_bytes(), b"/"))
}

/// A file mapping's path (its vnode's, from when it was mapped).
fn region_path(v: &Vma) -> Option<Vec<u8>> {
    Some(v.name.as_ref()?.as_bytes().to_vec())
}

fn region_vnode_info(ctx: &Ctx<'_>, v: &Vma) -> Option<Out> {
    vnode_info(&region_host_path(ctx, v)?, false)
}

/// Fills `proc_regioninfo` for mapping `v` (`fill_procregioninfo`); the
/// page counts only with `counts` (the vnode-only flavors leave them 0).
fn regioninfo(ctx: &Ctx<'_>, v: &Vma, o: &mut Out, counts: bool) {
    use crate::user::darwin::mig::vm as mv;
    let fl = VmFlags::from_bits(v.flags);
    o.u32(0, crate::user::darwin::vm::prot(v.perms))
        .u32(4, fl.max_prot())
        .u32(8, fl.inheritance())
        .u32(12, if v.shared { PROC_REGION_SHARED } else { 0 })
        .u64(16, mv::backing_offset(v))
        .u32(32, fl.tag())
        .u64(80, v.start)
        .u64(88, v.end - v.start);
    if counts {
        let r = mv::resident(ctx, v);
        let (private, shared) = if v.shared { (0, r) } else { (r, 0) };
        o.u32(36, r)
            .u32(52, 1)
            .u32(60, mv::share_mode(v, r))
            .u32(64, private)
            .u32(68, shared);
    }
}

/// Fills a region's `vnode_info_path` at `at` for a file mapping; whether
/// it is one.
fn region_vnode(ctx: &Ctx<'_>, v: &Vma, o: &mut Out, at: usize) -> bool {
    if !is_file(v) {
        return false;
    }
    let Some(vi) = region_vnode_info(ctx, v) else {
        return false;
    };
    o.bytes(at, &vi.0);
    let path = region_path(v).unwrap_or_default();
    o.path(at + 152, 1024, &path);
    true
}
