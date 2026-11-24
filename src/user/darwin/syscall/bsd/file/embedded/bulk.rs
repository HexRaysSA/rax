//! Bulk attribute records for directories in the closed Darwin filesystem.
use super::{Ctx, END_OF_DIRECTORY, EmbeddedFile, Errno, FileKind, Rv, SysResult};
use crate::user::darwin::abi::types::Stat;
use crate::user::darwin::syscall::bsd::path::embedded::{check_search, entry_stat};

const RETURNED: u32 = 0x8000_0000;
const NAME: u32 = 0x0000_0001;
const DEVID: u32 = 0x0000_0002;
const OBJTYPE: u32 = 0x0000_0008;
const CRTIME: u32 = 0x0000_0200;
const MODTIME: u32 = 0x0000_0400;
const CHGTIME: u32 = 0x0000_0800;
const ACCTIME: u32 = 0x0000_1000;
const OWNERID: u32 = 0x0000_8000;
const GRPID: u32 = 0x0001_0000;
const ACCESSMASK: u32 = 0x0002_0000;
const FLAGS: u32 = 0x0004_0000;
const FILEID: u32 = 0x0200_0000;
const COMMON: u32 = RETURNED
    | NAME
    | DEVID
    | OBJTYPE
    | CRTIME
    | MODTIME
    | CHGTIME
    | ACCTIME
    | OWNERID
    | GRPID
    | ACCESSMASK
    | FLAGS
    | FILEID;

const LINKCOUNT: u32 = 0x01;
const ALLOCSIZE: u32 = 0x04;
const IOBLOCKSIZE: u32 = 0x08;
const DEVTYPE: u32 = 0x20;
const DATALENGTH: u32 = 0x200;
const FILE: u32 = LINKCOUNT | ALLOCSIZE | IOBLOCKSIZE | DEVTYPE | DATALENGTH;

const PACK_INVAL_ATTRS: u64 = 0x08;
const MAX_BUFFER: u64 = 16 << 20;

struct Request {
    common: u32,
    file: u32,
}

impl Request {
    fn read(ctx: &Ctx<'_>, attrlist: u64, options: u64) -> Result<Self, Errno> {
        let data = ctx.read(attrlist, 24)?;
        let word = |start: usize| {
            u32::from_le_bytes(data[start..start + 4].try_into().expect("attrlist field"))
        };
        let common = word(4);
        let file = word(16);
        if u16::from_le_bytes(data[..2].try_into().expect("attrlist bitmap count")) != 5
            || common & (RETURNED | NAME) != (RETURNED | NAME)
            || common & !COMMON != 0
            || file & !FILE != 0
            || word(8) != 0
            || word(12) != 0
            || word(20) != 0
            || options & !PACK_INVAL_ATTRS != 0
        {
            return Err(Errno::EINVAL);
        }
        Ok(Self { common, file })
    }

    fn append_record(&self, out: &mut Vec<u8>, name: &str, stat: Stat) {
        let object_type: u32 = match stat.mode & 0o170000 {
            0o100000 => 1, // VREG
            0o040000 => 2, // VDIR
            0o060000 => 3, // VBLK
            0o020000 => 4, // VCHR
            0o120000 => 5, // VLNK
            0o140000 => 6, // VSOCK
            0o010000 => 7, // VFIFO
            _ => 0,        // VNON
        };
        // Native directory records omit the file group even with
        // FSOPT_PACK_INVAL_ATTRS.
        let file = if object_type == 2 { 0 } else { self.file };
        let start = out.len();
        out.extend_from_slice(&0u32.to_le_bytes()); // Overall record length.
        for mask in [self.common, 0, 0, file, 0] {
            out.extend_from_slice(&mask.to_le_bytes());
        }
        let reference = out.len();
        out.extend_from_slice(&[0; 8]); // Name offset and terminated byte length.
        for (bit, bytes) in [
            (DEVID, stat.dev.to_le_bytes().as_slice()),
            (OBJTYPE, object_type.to_le_bytes().as_slice()),
            (CRTIME, stat.birthtime.bytes().as_slice()),
            (MODTIME, stat.mtime.bytes().as_slice()),
            (CHGTIME, stat.ctime.bytes().as_slice()),
            (ACCTIME, stat.atime.bytes().as_slice()),
            (OWNERID, stat.uid.to_le_bytes().as_slice()),
            (GRPID, stat.gid.to_le_bytes().as_slice()),
            (ACCESSMASK, u32::from(stat.mode).to_le_bytes().as_slice()),
            (FLAGS, stat.flags.to_le_bytes().as_slice()),
            (FILEID, stat.ino.to_le_bytes().as_slice()),
        ] {
            if self.common & bit != 0 {
                out.extend_from_slice(bytes);
            }
        }
        for (bit, bytes) in [
            (LINKCOUNT, u32::from(stat.nlink).to_le_bytes().as_slice()),
            (
                ALLOCSIZE,
                stat.blocks.saturating_mul(512).to_le_bytes().as_slice(),
            ),
            (IOBLOCKSIZE, stat.blksize.to_le_bytes().as_slice()),
            (DEVTYPE, stat.rdev.to_le_bytes().as_slice()),
            (DATALENGTH, stat.size.to_le_bytes().as_slice()),
        ] {
            if file & bit != 0 {
                out.extend_from_slice(bytes);
            }
        }
        let offset = (out.len() - reference) as u32;
        let name_len = (name.len() + 1) as u32;
        out[reference..reference + 4].copy_from_slice(&offset.to_le_bytes());
        out[reference + 4..reference + 8].copy_from_slice(&name_len.to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.resize((out.len() + 1).next_multiple_of(8), 0);
        let length = (out.len() - start) as u32;
        out[start..start + 4].copy_from_slice(&length.to_le_bytes());
    }
}

pub(in crate::user::darwin::syscall::bsd) fn getattrlistbulk(
    ctx: &Ctx<'_>,
    fd: i32,
    attrlist: u64,
    buffer: u64,
    size: u64,
    options: u64,
) -> SysResult {
    if size == 0 {
        return Err(Errno::EINVAL);
    }
    let file = ctx.proc.fds.file(fd)?;
    let FileKind::Embedded(data) = &file.kind else {
        return Err(Errno::EBADF);
    };
    if data.search_only() {
        return Err(Errno::EBADF);
    }
    let EmbeddedFile::Supplied { entry, cursor, .. } = data else {
        return Err(Errno::ENOTDIR);
    };
    check_search(ctx, entry)?;
    let request = Request::read(ctx, attrlist, options)?;
    let path = file.path.as_deref().ok_or(Errno::EIO)?;
    let path = std::str::from_utf8(path).map_err(|_| Errno::EIO)?;
    let files = ctx.proc.vfs.files().ok_or(Errno::EIO)?;
    let mut cursor = cursor.lock().map_err(|_| Errno::EIO)?;
    if *cursor == END_OF_DIRECTORY {
        return Ok(Rv::one(0));
    }
    let entries = files.directory_entries(path, entry)?;
    // The shared directory index includes '.' and '..', which bulk reads omit.
    let first = usize::try_from(*cursor).unwrap_or(usize::MAX).max(2);
    let mut next = first;
    let mut output = Vec::new();
    let limit = size.min(MAX_BUFFER) as usize;
    for (name, child) in entries.iter().skip(first) {
        let start = output.len();
        request.append_record(&mut output, name, entry_stat(child.clone())?);
        if output.len() > limit {
            output.truncate(start);
            if output.is_empty() {
                return Err(Errno::ERANGE);
            }
            break;
        }
        next += 1;
    }
    ctx.write(buffer, &output)?;
    *cursor = if next >= entries.len() {
        END_OF_DIRECTORY
    } else {
        next as u64
    };
    Ok(Rv::one((next - first) as u64))
}
