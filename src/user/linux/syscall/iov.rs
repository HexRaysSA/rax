//! `struct iovec` arrays as the kernel imports them (`lib/iov_iter.c`,
//! Linux 6.19: `__import_iovec`, `import_ubuf`, `iovec_from_user`,
//! `copy_iovec_from_user`).

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::Ctx;
use super::events::access_ok;
use super::io::MAX_RW_COUNT;

/// `UIO_MAXIOV`.
pub const UIO_MAXIOV: u64 = 1024;

/// `copy_iovec_from_user`: `nr` vectors at `uvec`, read in order. The
/// array must lie in user space and each vector be readable (`EFAULT`);
/// a length negative as an `ssize_t` is `EINVAL` once its vector is read.
fn copy_iovec_from_user(c: &Ctx<'_>, uvec: u64, nr: u64) -> Result<Vec<(u64, u64)>, Errno> {
    if !access_ok(c, uvec, nr * 16) {
        return Err(Errno(EFAULT));
    }
    let mut out = Vec::with_capacity(nr as usize);
    for i in 0..nr {
        let b = c.read_mem(uvec + 16 * i, 16)?;
        let base = u64::from_le_bytes(b[..8].try_into().unwrap());
        let len = u64::from_le_bytes(b[8..].try_into().unwrap());
        if (len as i64) < 0 {
            return Err(Errno(EINVAL));
        }
        out.push((base, len));
    }
    Ok(out)
}

/// `iovec_from_user`: no vectors for 0, `EINVAL` beyond `UIO_MAXIOV`.
/// Neither the vectors' ranges nor their total are checked.
pub fn iovec_from_user(c: &Ctx<'_>, uvec: u64, nr: u64) -> Result<Vec<(u64, u64)>, Errno> {
    if nr == 0 {
        return Ok(Vec::new());
    }
    if nr > UIO_MAXIOV {
        return Err(Errno(EINVAL));
    }
    copy_iovec_from_user(c, uvec, nr)
}

/// `import_iovec`: the vectors a transfer uses, `nr` taken as the
/// `unsigned int` the kernel's parameter is. One vector is capped at
/// `MAX_RW_COUNT` before `access_ok` checks it (`import_ubuf`); of
/// several, each must lie in user space at its full length, and the
/// lengths are then capped so their total is at most `MAX_RW_COUNT`.
pub fn import_iovec(c: &Ctx<'_>, uvec: u64, nr: u64) -> Result<Vec<(u64, u64)>, Errno> {
    let nr = u64::from(nr as u32);
    if nr == 1 {
        let (base, len) = copy_iovec_from_user(c, uvec, 1)?[0];
        let len = len.min(MAX_RW_COUNT);
        if !access_ok(c, base, len) {
            return Err(Errno(EFAULT));
        }
        return Ok(vec![(base, len)]);
    }
    let mut iov = iovec_from_user(c, uvec, nr)?;
    let mut total = 0u64;
    for (base, len) in iov.iter_mut() {
        if !access_ok(c, *base, *len) {
            return Err(Errno(EFAULT));
        }
        *len = (*len).min(MAX_RW_COUNT - total);
        total += *len;
    }
    Ok(iov)
}
