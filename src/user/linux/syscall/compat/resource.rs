//! Process resources of a compatibility task (`kernel/sys.c`,
//! `kernel/compat.c`): `struct compat_rlimit` with `COMPAT_RLIM_INFINITY`
//! (`compat_sys_getrlimit`, `compat_sys_setrlimit`) and the old
//! `getrlimit`'s 2^31 - 1 ceiling (`compat_sys_old_getrlimit`), and the
//! CPU masks of `compat_sys_sched_getaffinity` and
//! `compat_sys_sched_setaffinity`, read and written in 32-bit words
//! (`compat_get_bitmap`, `compat_put_bitmap`).

use super::super::super::abi::errno::Errno;
use super::super::super::abi::errno_table::*;
use super::super::super::process::RLIM_INFINITY;
use super::super::process;
use super::super::{Ctx, SysResult};

/// `COMPAT_RLIM_INFINITY`.
const COMPAT_RLIM_INFINITY: u64 = 0xFFFF_FFFF;
/// The old `getrlimit`'s ceiling.
const OLD_RLIM_MAX: u64 = 0x7FFF_FFFF;
/// `RLIM_NLIMITS`.
const RLIM_NLIMITS: u32 = 16;

/// `compat_sys_getrlimit` (`ugetrlimit`): the limits clamped to
/// `COMPAT_RLIM_INFINITY`.
pub fn getrlimit(c: &mut Ctx<'_>, resource: u32, rlim: u64) -> SysResult {
    let (cur, max) = process::do_prlimit(c, 0, resource, None)?;
    let clamp = |v: u64| v.min(COMPAT_RLIM_INFINITY) as u32;
    c.write_mem(
        rlim,
        &[clamp(cur).to_le_bytes(), clamp(max).to_le_bytes()].concat(),
    )?;
    Ok(0)
}

/// `compat_sys_setrlimit`: the structure, `COMPAT_RLIM_INFINITY` read as
/// `RLIM_INFINITY`, then `do_prlimit`.
pub fn setrlimit(c: &mut Ctx<'_>, resource: u32, rlim: u64) -> SysResult {
    let b = c.read_mem(rlim, 8)?;
    let widen = |i: usize| match u64::from(u32::from_le_bytes(b[i..i + 4].try_into().unwrap())) {
        COMPAT_RLIM_INFINITY => RLIM_INFINITY,
        v => v,
    };
    process::do_prlimit(c, 0, resource, Some((widen(0), widen(4))))?;
    Ok(0)
}

/// `compat_sys_old_getrlimit` (`getrlimit`): the limits clamped to
/// 2^31 - 1, stored one at a time.
pub fn old_getrlimit(c: &mut Ctx<'_>, resource: u32, rlim: u64) -> SysResult {
    if resource >= RLIM_NLIMITS {
        return Err(Errno(EINVAL));
    }
    let (cur, max) = c.p.rlimits[resource as usize];
    c.write_u32(rlim, cur.min(OLD_RLIM_MAX) as u32)?;
    c.write_u32(rlim + 4, max.min(OLD_RLIM_MAX) as u32)?;
    Ok(0)
}

/// `sizeof(compat_ulong_t)`, the unit of a 32-bit CPU mask.
const COMPAT_LONG: u32 = 4;

/// `compat_sys_sched_getaffinity`: the length checks (`EINVAL`: shorter
/// than the CPUs, or not whole `compat_ulong_t`s) before the task's; the
/// mask's first `min(len, cpumask_size())` bytes, and that length returned.
pub fn sched_getaffinity(c: &mut Ctx<'_>, pid: i32, len: u32, mask: u64) -> SysResult {
    process::getaffinity(c, pid, len, mask, COMPAT_LONG)
}

/// `compat_sys_sched_setaffinity`: `compat_get_user_cpu_mask` reads whole
/// 32-bit words covering `min(len, cpumask_size())` bytes, then
/// `sched_setaffinity`.
pub fn sched_setaffinity(c: &mut Ctx<'_>, pid: i32, len: u32, mask: u64) -> SysResult {
    process::setaffinity(c, pid, len, mask, COMPAT_LONG)
}
