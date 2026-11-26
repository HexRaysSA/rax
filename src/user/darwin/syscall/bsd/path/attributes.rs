//! Single-object attribute records in the closed guest namespace.
use super::{Ctx, Errno, Rv, SysResult, embedded};
use crate::user::darwin::abi::types::Stat;
use crate::user::darwin::fd::FileKind;
use crate::user::darwin::host::{AT_SYMLINK_NOFOLLOW, AT_SYMLINK_NOFOLLOW_ANY};

const NAME: u32 = 0x0000_0001;
const DEVID: u32 = 0x0000_0002;
const OBJTYPE: u32 = 0x0000_0008;
const OBJID: u32 = 0x0000_0020;
const FILEID: u32 = 0x0200_0000;
const RETURNED: u32 = 0x8000_0000;
const COMMON: u32 = NAME | DEVID | OBJTYPE | OBJID | FILEID | RETURNED;

const FSOPT_NOFOLLOW: u64 = 0x0001;
const FSOPT_REPORT_FULLSIZE: u64 = 0x0004;
const FSOPT_PACK_INVAL_ATTRS: u64 = 0x0008;
const FSOPT_NOFOLLOW_ANY: u64 = 0x0800;

pub(in crate::user::darwin::syscall::bsd) fn get(
    ctx: &Ctx<'_>,
    dirfd: i32,
    path: Option<u64>,
    attrlist: u64,
    buffer: u64,
    size: u64,
    options: u64,
) -> SysResult {
    let data = ctx.read(attrlist, 24)?;
    let count = u16::from_le_bytes(data[..2].try_into().expect("attrlist count"));
    let requested = u32::from_le_bytes(data[4..8].try_into().expect("common attributes"));
    if count != 5 || options & FSOPT_PACK_INVAL_ATTRS != 0 && requested & RETURNED == 0 {
        return Err(Errno::EINVAL);
    }
    if requested & !COMMON != 0
        || data[8..].iter().any(|&byte| byte != 0)
        || options
            & !(FSOPT_NOFOLLOW
                | FSOPT_REPORT_FULLSIZE
                | FSOPT_PACK_INVAL_ATTRS
                | FSOPT_NOFOLLOW_ANY)
            != 0
    {
        return Err(Errno::ENOTSUP);
    }

    let (path, stat) = if let Some(addr) = path {
        let mut flags = 0;
        if options & FSOPT_NOFOLLOW != 0 {
            flags |= AT_SYMLINK_NOFOLLOW;
        }
        if options & FSOPT_NOFOLLOW_ANY != 0 {
            flags |= AT_SYMLINK_NOFOLLOW_ANY;
        }
        let (resolved, entry) = embedded::lookup(ctx, dirfd, addr, embedded::link_policy(flags))?;
        (Some(resolved.into_bytes()), embedded::entry_stat(entry)?)
    } else {
        let file = ctx.proc.fds.file(dirfd)?;
        let FileKind::Embedded(object) = &file.kind else {
            return Err(Errno::EBADF);
        };
        let path = match object.entry() {
            Some(entry) => entry.workspace_path()?.map(String::into_bytes),
            None => None,
        }
        .or_else(|| file.path.clone());
        (path, object.stat()?)
    };

    if size < 4 {
        return Err(Errno::ERANGE);
    }
    let name = path.as_deref().map(|p| {
        if p == b"/" {
            p
        } else {
            p.rsplit(|&byte| byte == b'/')
                .next()
                .expect("path component")
        }
    });
    if requested & NAME != 0 && name.is_none() {
        return Err(Errno::ENOTSUP);
    }
    let record = pack(requested, name.unwrap_or_default(), stat);
    // The installed APFS attribute calls report the full record length and
    // copy only the bytes that fit in the caller's buffer.
    let copied = size.min(record.len() as u64) as usize;
    ctx.write(buffer, &record[..copied])?;
    Ok(Rv::one(0))
}

fn pack(requested: u32, name: &[u8], stat: Stat) -> Vec<u8> {
    let mut record = vec![0; 4];
    if requested & RETURNED != 0 {
        record.extend_from_slice(&requested.to_le_bytes());
        record.extend_from_slice(&[0; 16]);
    }
    let name_offset = record.len();
    if requested & NAME != 0 {
        record.extend_from_slice(&[0; 8]);
    }
    for (attribute, bytes) in [
        (DEVID, stat.dev.to_le_bytes().as_slice()),
        (OBJTYPE, stat.vnode_type().to_le_bytes().as_slice()),
        (OBJID, stat.ino.to_le_bytes().as_slice()),
        (FILEID, stat.ino.to_le_bytes().as_slice()),
    ] {
        if requested & attribute != 0 {
            record.extend_from_slice(bytes);
        }
    }
    if requested & NAME != 0 {
        let relative = (record.len() - name_offset) as u32;
        let length = (name.len() + 1) as u32;
        record[name_offset..name_offset + 4].copy_from_slice(&relative.to_le_bytes());
        record[name_offset + 4..name_offset + 8].copy_from_slice(&length.to_le_bytes());
        record.extend_from_slice(name);
        record.resize((record.len() + 1).next_multiple_of(4), 0);
    }
    let length = record.len() as u32;
    record[..4].copy_from_slice(&length.to_le_bytes());
    record
}
