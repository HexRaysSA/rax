//! Bounded guest-memory transfers for descriptors without a host handle.

use super::{CHUNK, Ctx, Errno, Rv, SysResult};
use crate::error::MemoryAccessKind;
use crate::user::darwin::fd::EmbeddedFile;

fn position(offset: Option<i64>, done: u64) -> Result<Option<i64>, Errno> {
    offset
        .map(|n| n.checked_add(done as i64).ok_or(Errno::EOVERFLOW))
        .transpose()
}

/// The caller validates the vector count and aggregate byte limit. Transfers
/// use O(CHUNK) scratch space, including when an iovec spans most of IO_MAX.
pub(super) fn vector(
    ctx: &Ctx<'_>,
    file: &EmbeddedFile,
    vectors: &[(u64, u64)],
    offset: Option<i64>,
    reading: bool,
) -> SysResult {
    let transfer = if reading { read } else { write };
    // Empty vectors still validate the descriptor and positional operation.
    transfer(ctx, file, 0, 0, offset)?;
    let mut done = 0;
    for &(base, len) in vectors {
        let result = position(offset, done).and_then(|pos| transfer(ctx, file, base, len, pos));
        let n = match result {
            Ok(value) => value.0,
            Err(e) if done == 0 => return Err(e),
            Err(_) => break,
        };
        done += n;
        if n < len {
            break;
        }
    }
    Ok(Rv::one(done))
}

pub(super) fn read(
    ctx: &Ctx<'_>,
    file: &EmbeddedFile,
    buf: u64,
    nbyte: u64,
    offset: Option<i64>,
) -> SysResult {
    // Validate descriptor direction and positional semantics even for an empty
    // transfer, without consuming bytes.
    file.read(&mut [], offset)?;
    ctx.space()
        .probe(buf, nbyte as usize, MemoryAccessKind::Write)
        .map_err(|_| Errno::EFAULT)?;
    let mut chunk = vec![0; (nbyte as usize).min(CHUNK)];
    let mut done = 0;
    while done < nbyte {
        let want = ((nbyte - done) as usize).min(CHUNK);
        let result = position(offset, done).and_then(|pos| file.read(&mut chunk[..want], pos));
        let n = match result {
            Ok(n) => n,
            Err(e) if done == 0 => return Err(e),
            Err(_) => break,
        };
        ctx.write(buf.checked_add(done).ok_or(Errno::EFAULT)?, &chunk[..n])?;
        done += n as u64;
        if n < want {
            break;
        }
    }
    Ok(Rv::one(done))
}

pub(super) fn write(
    ctx: &Ctx<'_>,
    file: &EmbeddedFile,
    buf: u64,
    nbyte: u64,
    offset: Option<i64>,
) -> SysResult {
    file.write(&[], offset)?;
    let mut done = 0;
    while done < nbyte {
        let want = ((nbyte - done) as usize).min(CHUNK);
        let result = (|| {
            let address = buf.checked_add(done).ok_or(Errno::EFAULT)?;
            let data = ctx.read(address, want)?;
            file.write(&data, position(offset, done)?)
        })();
        let n = match result {
            Ok(n) => n,
            Err(e) if done == 0 => return Err(e),
            Err(_) => break,
        };
        done += n as u64;
        if n < want {
            break;
        }
    }
    Ok(Rv::one(done))
}
