//! Extended stat on private inodes, which have no ACL or explicit GUIDs.

use super::{Ctx, Errno, Rv, SysResult, path};
use crate::user::darwin::abi::tables::nr;
use crate::user::darwin::fd::FileKind;
use crate::user::darwin::host::AT_FDCWD;
use crate::user::supplied_fs::LinkPolicy;

/// `KAUTH_FILESEC_MAGIC`.
pub(super) const FILESEC_MAGIC: u32 = 0x012c_c16d;
/// `KAUTH_FILESEC_NOACL`: the ACL is absent.
pub(super) const FILESEC_NOACL: u32 = u32::MAX;
/// `KAUTH_FILESEC_SIZE(0)`: magic, owner and group GUIDs, entry count, flags.
pub(super) const FILESEC_HEADER: usize = 44;

pub(super) fn stat(ctx: &Ctx<'_>, number: u32, args: &[u64; 8]) -> SysResult {
    let [target, stat_buffer, security, security_size, ..] = *args;
    let stat = if number == nr::FSTAT64_EXTENDED {
        let file = ctx.proc.fds.file(target as i32)?;
        let FileKind::Embedded(data) = &file.kind else {
            return Err(Errno::EPERM);
        };
        if !data
            .entry()
            .is_some_and(|entry| entry.workspace_mode().is_some())
        {
            return Err(Errno::EPERM);
        }
        data.stat()?
    } else {
        let policy = if number == nr::LSTAT64_EXTENDED {
            LinkPolicy::NoFollowLast
        } else {
            LinkPolicy::Follow
        };
        path::embedded::path_stat(ctx, AT_FDCWD, target, policy, true)?
    };
    ctx.write(stat_buffer, &stat.bytes())?;
    if security != 0 {
        let capacity = ctx.read_u64(security_size).unwrap_or(u64::MAX);
        ctx.write_u64(security_size, FILESEC_HEADER as u64)?;
        if capacity >= FILESEC_HEADER as u64 {
            let mut header = [0; FILESEC_HEADER];
            header[..4].copy_from_slice(&FILESEC_MAGIC.to_le_bytes());
            header[36..40].copy_from_slice(&FILESEC_NOACL.to_le_bytes());
            ctx.write(security, &header)?;
        }
    }
    Ok(Rv::one(0))
}
