//! The 16-bit user- and group-ID calls of a compatibility task
//! (`kernel/uid16.c`, `CONFIG_UID16`): an ID argument is the register's
//! low 16 bits, whose all-ones value is -1 (`low2highuid`); an ID result
//! past 16 bits reads as the overflow ID 65534 (`high2lowuid`).

use super::super::super::abi::Sysno as S;
use super::super::super::abi::errno::Errno;
use super::super::super::abi::errno_table::*;
use super::super::super::abi::types::low_id;
use super::super::{Ctx, Outcome, SysResult, call_handler};

/// `low2highuid` of an `old_uid_t` argument.
fn high(v: u64) -> u64 {
    match v as u16 {
        u16::MAX => u64::from(u32::MAX),
        id => u64::from(id),
    }
}

/// A call taking 16-bit IDs in the argument positions `ids`: the native
/// call with them widened.
pub fn widened(
    c: &mut Ctx<'_>,
    native: S,
    mut a: [u64; 6],
    ids: &[usize],
) -> Result<Outcome, Errno> {
    for &i in ids {
        a[i] = high(a[i]);
    }
    call_handler(c, native, a)
}

/// `getuid16`, `geteuid16`, `getgid16`, `getegid16`.
pub fn get(id: u32) -> SysResult {
    Ok(u64::from(low_id(id)))
}

/// `getresuid16` and `getresgid16`: three `old_uid_t`s, stored in order
/// until one faults.
pub fn getres(c: &mut Ctx<'_>, a: [u64; 6], user: bool) -> SysResult {
    let (real, eff) = if user {
        (c.p.creds.0, c.p.creds.1)
    } else {
        (c.p.creds.2, c.p.creds.3)
    };
    for (at, id) in [(a[0], real), (a[1], eff), (a[2], eff)] {
        c.write_mem(at, &low_id(id).to_le_bytes())?;
    }
    Ok(0)
}

/// `getgroups16`: as `getgroups`, with `old_gid_t` entries.
pub fn getgroups(c: &mut Ctx<'_>, size: i32, list: u64) -> SysResult {
    if size < 0 {
        return Err(Errno(EINVAL));
    }
    let n = c.p.groups.len();
    if size != 0 {
        if n > size as usize {
            return Err(Errno(EINVAL));
        }
        let b: Vec<u8> =
            c.p.groups
                .iter()
                .flat_map(|&g| low_id(g).to_le_bytes())
                .collect();
        c.write_mem(list, &b)?;
    }
    Ok(n as u64)
}

/// `setgroups16`: as `setgroups`, reading `old_gid_t`s (`groups16_from_user`).
pub fn setgroups(c: &mut Ctx<'_>, size: i32, list: u64) -> SysResult {
    super::super::process::set_groups(c, size, |c, i| {
        let mut b = [0u8; 2];
        b.copy_from_slice(&c.read_mem(list + 2 * i, 2)?);
        Ok(high(u64::from(u16::from_le_bytes(b))) as u32)
    })
}
