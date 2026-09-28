//! `kern.procargs` and `kern.procargs2` of the calling process
//! (`sysctl_procargsx` in `bsd/kern/kern_sysctl.c`).
//!
//! The answer is the string area `exec` wrote below `user_stack`: its top
//! `p_argslen` bytes less the `executable_path=` key, so the executable's
//! path, its padding, and the argument, environment, and `apple[]` strings,
//! read from the process's memory as it is now. `procargs2` puts `argc`
//! first; `procargs` may append a copy of the path after a marker. The
//! guest's area is the guest's own memory, so the calling process is
//! answered here; another process is the host's to describe.

use super::Req;
use crate::user::darwin::abi::Errno;
use crate::user::darwin::stack::{EXECUTABLE_KEY, NCARGS};
use crate::user::darwin::syscall::Ctx;

/// `KERN_PROCARGS`.
pub const KERN_PROCARGS: i32 = 38;
/// `KERN_PROCARGS2`.
pub const KERN_PROCARGS2: i32 = 49;
/// `PATH_MAX`.
const PATH_MAX: u64 = 1024;
/// The marker `procargs` writes before the appended path.
const PATH_MARKER: u32 = 0xBFFF_0000;

/// Whether `oid` asks for the calling process's arguments.
pub fn own(ctx: &Ctx<'_>, oid: &[i32]) -> bool {
    oid.len() >= 3
        && oid[0] == 1
        && matches!(oid[1], KERN_PROCARGS | KERN_PROCARGS2)
        && oid[2] == ctx.proc.pid
}

/// Padding that brings `n` to a multiple of 4 bytes.
fn pad4(n: u64) -> u64 {
    (4 - (n & 3)) & 3
}

/// `sysctl_procargsx` for the calling process: `argc` first when
/// `argc_yes` (`procargs2`). The length the handler reports is both the
/// request's length and its cursor, as `sysctl_doprocargs` sets them.
pub fn procargs(ctx: &mut Ctx<'_>, argc_yes: bool, req: &mut Req) -> Result<(), Errno> {
    let place = req.oldptr;
    let mut buflen = if place != 0 { req.oldlen } else { 0 };
    if argc_yes {
        // A size_t: a buffer under the argc word wraps and is refused.
        buflen = buflen.wrapping_sub(4);
    }
    if place != 0 && (buflen == 0 || buflen > NCARGS as u64) {
        return Err(Errno::EINVAL);
    }
    let layout = &ctx.proc.program.layout;
    let argc = ((layout.envp_addr - layout.argv_addr) / 8 - 1) as u32;
    // The executable_path= key the string area starts with is left out.
    let argslen = layout.argslen - EXECUTABLE_KEY.len() as u64;
    let top = ctx.proc.program.stack.top;

    let size = if place == 0 {
        // The calling process may read its environment: only the length.
        let mut size = argslen + if argc_yes { 4 } else { PATH_MAX + 24 };
        size += pad4(size);
        size
    } else {
        // The whole pages holding the area (vm_map_copyin), as they are now.
        let page = ctx.proc.abi.page_size();
        let round = |n: u64| (n + page - 1) & !(page - 1);
        let arg_size = round(argslen);
        let mut area = ctx
            .read(top - arg_size, arg_size as usize)
            .map_err(|_| Errno::EIO)?;
        let (from, len) = if buflen >= argslen {
            (arg_size - argslen, argslen)
        } else {
            // A short buffer gets the top buflen bytes as the kernel's old
            // copy left them: a page-rounded buffer holding the first
            // buflen bytes, copied out from its end, zero past them.
            let start = arg_size.saturating_sub(round(buflen));
            area[(start + buflen) as usize..].fill(0);
            (arg_size - buflen, buflen)
        };
        let data = &area[from as usize..(from + len) as usize];
        if argc_yes {
            let _ = ctx.write(place, &argc.to_le_bytes());
            ctx.write(place + 4, data)?;
            len + 4
        } else {
            ctx.write(place, data)?;
            len + append_path(ctx, place, buflen, len, data)?
        }
    };
    req.oldlen = size;
    req.oldidx += size;
    Ok(())
}

/// `procargs` appends the executable's path (the data's first string, at
/// most `PATH_MAX` bytes with its NUL) after a zero word, the marker, and
/// a zero word, and a zero word after it, when the buffer has room for all
/// of it word-aligned; returns the bytes added. Only the path's copy-out
/// can fail the call (the words are stored as `suword` stores them).
fn append_path(
    ctx: &mut Ctx<'_>,
    place: u64,
    buflen: u64,
    size: u64,
    data: &[u8],
) -> Result<u64, Errno> {
    if buflen <= size {
        return Ok(0);
    }
    let max_len = size.min(PATH_MAX);
    let mut path = 0;
    while path < max_len - 1 && data[path as usize] != 0 {
        path += 1;
    }
    if path < max_len - 1 {
        path += 1;
    }
    let mut at = place + size;
    let align = pad4(at);
    let extra = pad4(path) + align + path + 16;
    if buflen & !3 < size + extra {
        return Ok(0);
    }
    at += align;
    for word in [0, PATH_MARKER, 0] {
        let _ = ctx.write(at, &word.to_le_bytes());
        at += 4;
    }
    ctx.write(at, &data[..path as usize])?;
    let _ = ctx.write(at + path, &0u32.to_le_bytes());
    Ok(extra)
}
