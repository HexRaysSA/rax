//! `ioctl` on sockets where the generic copy is not enough: requests
//! whose argument points at more guest memory (the host is given its
//! own buffers and the results are copied back), requests the emulator
//! cannot give the host that way (refused), and `FIOGETOWN`, whose
//! result a socket never copies out (`sys_generic.c`).

use std::os::fd::RawFd;

use crate::user::darwin::abi::Errno;
use crate::user::darwin::arch::{Rv, SysResult};
use crate::user::darwin::host::check;
use crate::user::darwin::syscall::Ctx;

/// `_IOC` fields.
const IOC_OUT: u32 = 0x4000_0000;
const IOC_IN: u32 = 0x8000_0000;

const fn iowr(group: u8, num: u8, size: u32) -> u32 {
    IOC_IN | IOC_OUT | (size << 16) | ((group as u32) << 8) | num as u32
}

const fn iow(group: u8, num: u8, size: u32) -> u32 {
    IOC_IN | (size << 16) | ((group as u32) << 8) | num as u32
}

/// `FIOGETOWN`.
const FIOGETOWN: u32 = 0x4004_667b;
/// `SIOCGIFCONF` (`struct ifconf`, 12 bytes packed).
const SIOCGIFCONF: u32 = iowr(b'i', 36, 12);
/// `SIOCGIFMEDIA`, `SIOCGIFXMEDIA` (`struct ifmediareq`, 44 bytes).
const SIOCGIFMEDIA: u32 = iowr(b'i', 56, 44);
const SIOCGIFXMEDIA: u32 = iowr(b'i', 72, 44);
/// `SIOCSDRVSPEC`, `SIOCGDRVSPEC` (`struct ifdrv`, 40 bytes).
const SIOCSDRVSPEC: u32 = iow(b'i', 123, 40);
const SIOCGDRVSPEC: u32 = iowr(b'i', 123, 40);
/// `SIOCIFGCLONERS` (`struct if_clonereq`, 16 bytes).
const SIOCIFGCLONERS: u32 = iowr(b'i', 129, 16);
/// `SIOCIFCREATE2` (`struct ifreq` whose `ifr_data` holds the cloner's
/// parameters).
const SIOCIFCREATE2: u32 = iowr(b'i', 122, 32);

/// The most a pointed-at buffer is given to the host.
const BUF_MAX: usize = 1 << 20;
/// `IFNAMSIZ`.
const IFNAMSIZ: usize = 16;

/// Requests whose argument carries a user pointer the emulator does not
/// translate, by group and number: the deprecated `OSIOCGIFCONF`,
/// `SIOCRSLVMULTI`, and the private association, connection, agent, and
/// protocol lists (`sys/sockio_private.h`).
fn untranslated(req: u32) -> bool {
    let group = (req >> 8) as u8;
    let num = req as u8;
    matches!(
        (group, num),
        (b'i', 20) | (b'i', 59) | (b'i', 167) | (b'i', 168) | (b'i', 190) | (b'i', 196)
    ) || (group == b's' && (150..=152).contains(&num))
}

fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().expect("4 bytes"))
}

fn u64_at(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().expect("8 bytes"))
}

/// Calls the host with `arg` as the request's structure.
fn host_ioctl(h: RawFd, req: u32, arg: &mut [u8]) -> Result<i32, Errno> {
    // SAFETY: `arg` holds the request's structure, whose pointers (set
    // by the caller) point at live buffers of the sizes it states.
    check(unsafe { libc::ioctl(h, req as libc::c_ulong, arg.as_mut_ptr()) })
}

/// A socket `ioctl` the generic copy cannot serve; `None` for the rest.
pub fn ioctl(ctx: &mut Ctx<'_>, h: RawFd, req: u32, arg: u64) -> Option<SysResult> {
    Some(match req {
        FIOGETOWN => {
            let mut owner = [0u8; 4];
            host_ioctl(h, req, &mut owner).map(|r| Rv::one(r as u64))
        }
        SIOCGIFCONF => ifconf(ctx, h, arg),
        SIOCGIFMEDIA | SIOCGIFXMEDIA => ifmedia(ctx, h, req, arg),
        SIOCSDRVSPEC | SIOCGDRVSPEC => drvspec(ctx, h, req, arg),
        SIOCIFGCLONERS => cloners(ctx, h, arg),
        // Unprivileged callers are refused first (proc_suser); the
        // parameters' layout is the cloner's own.
        // SAFETY: geteuid takes no arguments.
        SIOCIFCREATE2 if unsafe { libc::geteuid() } != 0 => Err(Errno::EPERM),
        SIOCIFCREATE2 => Err(Errno::EOPNOTSUPP),
        _ if untranslated(req) => Err(Errno::EOPNOTSUPP),
        _ => return None,
    })
}

/// `SIOCGIFCONF`: `ifc_len` bytes of interface records into `ifc_buf`;
/// `ifc_len` becomes the bytes written.
fn ifconf(ctx: &Ctx<'_>, h: RawFd, arg: u64) -> SysResult {
    let mut s = ctx.read(arg, 12)?;
    let len = u32_at(&s, 0) as i32;
    let ubuf = u64_at(&s, 4);
    let mut buf = vec![0u8; (len.max(0) as usize).min(BUF_MAX)];
    s[0..4].copy_from_slice(&(buf.len() as i32).to_le_bytes());
    s[4..12].copy_from_slice(&(buf.as_mut_ptr() as u64).to_le_bytes());
    let r = host_ioctl(h, SIOCGIFCONF, &mut s)?;
    let out = (u32_at(&s, 0) as usize).min(buf.len());
    ctx.write(ubuf, &buf[..out])?;
    s[4..12].copy_from_slice(&ubuf.to_le_bytes());
    ctx.write(arg, &s)?;
    Ok(Rv::one(r as u64))
}

/// `SIOCGIFMEDIA`, `SIOCGIFXMEDIA`: the media words into `ifm_ulist` (at
/// most `ifm_count` of them); `ifm_count` becomes how many there are.
fn ifmedia(ctx: &Ctx<'_>, h: RawFd, req: u32, arg: u64) -> SysResult {
    let mut s = ctx.read(arg, 44)?;
    let count = (u32_at(&s, 32) as i32).max(0) as usize;
    let ulist = u64_at(&s, 36);
    let mut words = vec![0u8; (count * 4).min(BUF_MAX)];
    let ptr = if ulist == 0 {
        0
    } else {
        words.as_mut_ptr() as u64
    };
    s[32..36].copy_from_slice(&((words.len() / 4) as i32).to_le_bytes());
    s[36..44].copy_from_slice(&ptr.to_le_bytes());
    let r = host_ioctl(h, req, &mut s)?;
    if ulist != 0 {
        let n = (u32_at(&s, 32) as usize * 4).min(words.len());
        ctx.write(ulist, &words[..n])?;
    }
    s[36..44].copy_from_slice(&ulist.to_le_bytes());
    ctx.write(arg, &s)?;
    Ok(Rv::one(r as u64))
}

/// `SIOCSDRVSPEC`, `SIOCGDRVSPEC`: `ifd_len` bytes at `ifd_data` to the
/// driver, and back for the get.
fn drvspec(ctx: &Ctx<'_>, h: RawFd, req: u32, arg: u64) -> SysResult {
    let mut s = ctx.read(arg, 40)?;
    let len = (u64_at(&s, 24) as usize).min(BUF_MAX);
    let data = u64_at(&s, 32);
    let mut buf = if data == 0 {
        Vec::new()
    } else {
        ctx.read(data, len)?
    };
    let ptr = if data == 0 {
        0
    } else {
        buf.as_mut_ptr() as u64
    };
    s[24..32].copy_from_slice(&(buf.len() as u64).to_le_bytes());
    s[32..40].copy_from_slice(&ptr.to_le_bytes());
    let r = host_ioctl(h, req, &mut s)?;
    if req == SIOCGDRVSPEC {
        ctx.write(data, &buf)?;
        s[32..40].copy_from_slice(&data.to_le_bytes());
        ctx.write(arg, &s)?;
    }
    Ok(Rv::one(r as u64))
}

/// `SIOCIFGCLONERS`: the cloner names into `ifcr_buffer` (at most
/// `ifcr_count`); `ifcr_total` is how many there are.
fn cloners(ctx: &Ctx<'_>, h: RawFd, arg: u64) -> SysResult {
    let mut s = ctx.read(arg, 16)?;
    let count = (u32_at(&s, 4) as i32).max(0) as usize;
    let ubuf = u64_at(&s, 8);
    let mut names = vec![0u8; (count * IFNAMSIZ).min(BUF_MAX)];
    let ptr = if ubuf == 0 {
        0
    } else {
        names.as_mut_ptr() as u64
    };
    s[4..8].copy_from_slice(&((names.len() / IFNAMSIZ) as i32).to_le_bytes());
    s[8..16].copy_from_slice(&ptr.to_le_bytes());
    let r = host_ioctl(h, SIOCIFGCLONERS, &mut s)?;
    if ubuf != 0 {
        let total = u32_at(&s, 0) as usize;
        let n = (total.min(count) * IFNAMSIZ).min(names.len());
        ctx.write(ubuf, &names[..n])?;
    }
    s[4..8].copy_from_slice(&(count as i32).to_le_bytes());
    s[8..16].copy_from_slice(&ubuf.to_le_bytes());
    ctx.write(arg, &s)?;
    Ok(Rv::one(r as u64))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_encode_as_the_headers_do() {
        assert_eq!(SIOCGIFCONF, 0xc00c_6924);
        assert_eq!(SIOCGIFMEDIA, 0xc02c_6938);
        assert_eq!(SIOCGIFXMEDIA, 0xc02c_6948);
        assert_eq!(SIOCGDRVSPEC, 0xc028_697b);
        assert_eq!(SIOCSDRVSPEC, 0x8028_697b);
        assert_eq!(SIOCIFGCLONERS, 0xc010_6981);
        assert_eq!(SIOCIFCREATE2, 0xc020_697a);
        assert!(untranslated(iowr(b's', 151, 16)));
        assert!(!untranslated(iowr(b'i', 17, 32)));
    }
}
