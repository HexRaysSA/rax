//! `persona(operation, flags, info, id, idlen, path)` (`sys_persona.c`):
//! the host's, for the guest's process is the host process and runs with
//! its persona. The guest's buffers are copied in before the call and out
//! after it, as the operation reads and writes them: a `kpersona_info` of
//! the size its version gives (344 or 348 bytes), persona IDs, their
//! count, and a path.

use crate::user::darwin::abi::Errno;
use crate::user::darwin::arch::{Rv, SysResult};
use crate::user::darwin::syscall::Ctx;
use crate::user::darwin::syscall::util::MAXPATHLEN;

/// `PERSONA_OP_*`.
mod op {
    pub const ALLOC: u32 = 1;
    pub const PALLOC: u32 = 2;
    pub const GET: u32 = 4;
    pub const INFO: u32 = 5;
    pub const PIDINFO: u32 = 6;
    pub const FIND: u32 = 7;
    pub const GETPATH: u32 = 8;
    pub const FIND_BY_TYPE: u32 = 9;
}

/// `sizeof(struct kpersona_info)` by version (`PERSONA_INFO_V1_SIZE`,
/// `PERSONA_INFO_V2_SIZE`).
fn info_size(version: u32) -> usize {
    match version {
        1 => 344,
        2 => 348,
        _ => 4,
    }
}

unsafe extern "C" {
    fn __persona(
        op: u32,
        flags: u32,
        info: *mut u8,
        id: *mut u32,
        idlen: *mut usize,
        path: *mut libc::c_char,
    ) -> i32;
}

/// `persona(operation, flags, info, id, idlen, path)`.
pub fn persona(
    ctx: &mut Ctx<'_>,
    operation: u32,
    flags: u32,
    info: u64,
    id: u64,
    idlen: u64,
    path: u64,
) -> SysResult {
    // The info block: its version decides its size.
    let mut hinfo = [0u8; 348];
    let isize = if info != 0 {
        let v = u32::from_le_bytes(ctx.read(info, 4)?[..].try_into().expect("4 bytes"));
        let n = info_size(v);
        ctx.read_into(info, &mut hinfo[..n])?;
        n
    } else {
        0
    };
    // The IDs: one, or as many as the count says (a search's results).
    let mut count = 0usize;
    if idlen != 0 {
        count = ctx.read_u64(idlen)? as usize;
    }
    let slots = if matches!(operation, op::FIND | op::FIND_BY_TYPE) {
        count.min(1 << 16)
    } else {
        1
    };
    let mut ids = vec![0u32; slots.max(1)];
    if id != 0 && !matches!(operation, op::FIND | op::FIND_BY_TYPE) {
        ids[0] = ctx.read_u32(id)?;
    }
    let mut hpath = vec![0u8; MAXPATHLEN];
    if path != 0 && matches!(operation, op::ALLOC | op::PALLOC) {
        let p = ctx.path(path)?;
        let n = p.len().min(MAXPATHLEN - 1);
        hpath[..n].copy_from_slice(&p[..n]);
    }
    let null_or = |present: bool, p: *mut u8| if present { p } else { std::ptr::null_mut() };
    // SAFETY: every pointer is null or a buffer as large as the operation
    // reads or writes.
    let r = unsafe {
        __persona(
            operation,
            flags,
            null_or(info != 0, hinfo.as_mut_ptr()),
            null_or(id != 0, ids.as_mut_ptr().cast()).cast(),
            if idlen != 0 {
                &mut count
            } else {
                std::ptr::null_mut()
            },
            null_or(path != 0, hpath.as_mut_ptr()).cast(),
        )
    };
    let failed = (r < 0).then(Errno::last);
    // A search reports its count even when it fails for want of room.
    if idlen != 0 && matches!(operation, op::FIND | op::FIND_BY_TYPE) {
        ctx.write_u64(idlen, count as u64)?;
    }
    if let Some(e) = failed {
        return Err(e);
    }
    match operation {
        op::ALLOC | op::PALLOC | op::GET if id != 0 => ctx.write_u32(id, ids[0])?,
        op::FIND | op::FIND_BY_TYPE if id != 0 => {
            let n = count.min(ids.len());
            let bytes: Vec<u8> = ids[..n].iter().flat_map(|v| v.to_le_bytes()).collect();
            ctx.write(id, &bytes)?;
        }
        _ => {}
    }
    if info != 0 && matches!(operation, op::ALLOC | op::PALLOC | op::INFO | op::PIDINFO) {
        ctx.write(info, &hinfo[..isize])?;
    }
    if path != 0 && operation == op::GETPATH {
        let n = hpath.iter().position(|&b| b == 0).unwrap_or(MAXPATHLEN - 1);
        ctx.write(path, &hpath[..=n])?;
    }
    Ok(Rv::one(r as u64))
}
