//! Single-object attribute records in the closed guest namespace.
use super::{Ctx, Errno, Rv, SysResult, embedded};
use crate::user::darwin::abi::types::Stat;
use crate::user::darwin::fd::FileKind;
use crate::user::darwin::host::{AT_SYMLINK_NOFOLLOW, AT_SYMLINK_NOFOLLOW_ANY};
use crate::user::darwin::vfs::ClosedVolume;

const NAME: u32 = 0x0000_0001;
const DEVID: u32 = 0x0000_0002;
const FSID: u32 = 0x0000_0004;
const OBJTYPE: u32 = 0x0000_0008;
const OBJID: u32 = 0x0000_0020;
const CRTIME: u32 = 0x0000_0200;
const MODTIME: u32 = 0x0000_0400;
const CHGTIME: u32 = 0x0000_0800;
const ACCTIME: u32 = 0x0000_1000;
const OWNERID: u32 = 0x0000_8000;
const GRPID: u32 = 0x0001_0000;
const ACCESSMASK: u32 = 0x0002_0000;
const FLAGS: u32 = 0x0004_0000;
const GEN_COUNT: u32 = 0x0008_0000;
const DOCUMENT_ID: u32 = 0x0010_0000;
const FILEID: u32 = 0x0200_0000;
const FULLPATH: u32 = 0x0800_0000;
const ADDEDTIME: u32 = 0x1000_0000;
const ERROR: u32 = 0x2000_0000;
const DATA_PROTECT_FLAGS: u32 = 0x4000_0000;
const RETURNED: u32 = 0x8000_0000;
const COMMON: u32 = NAME
    | DEVID
    | FSID
    | OBJTYPE
    | OBJID
    | CRTIME
    | MODTIME
    | CHGTIME
    | ACCTIME
    | OWNERID
    | GRPID
    | ACCESSMASK
    | FLAGS
    | FILEID
    | FULLPATH
    | RETURNED;
const COMMON_UNAVAILABLE: u32 = GEN_COUNT | DOCUMENT_ID | ADDEDTIME | DATA_PROTECT_FLAGS;

const VOL_CAPABILITIES: u32 = 0x0002_0000;
const VOL_ATTRIBUTES: u32 = 0x4000_0000;
const VOL_INFO: u32 = 0x8000_0000;
const LINKCOUNT: u32 = 0x0000_0001;
const DIR_MOUNTSTATUS: u32 = 0x0000_0004;
const REALDEVID: u32 = 0x0000_0040;
const EXT_FLAGS: u32 = 0x0000_0200;

const FSOPT_NOFOLLOW: u64 = 0x0001;
const FSOPT_REPORT_FULLSIZE: u64 = 0x0004;
const FSOPT_PACK_INVAL_ATTRS: u64 = 0x0008;
pub(in crate::user::darwin::syscall::bsd) const FSOPT_ATTR_CMN_EXTENDED: u64 = 0x0020;
const FSOPT_NOFOLLOW_ANY: u64 = 0x0800;

pub(in crate::user::darwin::syscall::bsd) struct Request {
    common: u32,
    volume: u32,
    dir: u32,
    file: u32,
    extended: u32,
    pack_invalid: bool,
}

impl Request {
    pub(in crate::user::darwin::syscall::bsd) fn read_bulk(
        ctx: &Ctx<'_>,
        addr: u64,
        options: u64,
    ) -> Result<Self, Errno> {
        if options & !(FSOPT_ATTR_CMN_EXTENDED | FSOPT_PACK_INVAL_ATTRS) != 0 {
            return Err(Errno::EINVAL);
        }
        let request = Self::read(&ctx.read(addr, 24)?, options)?;
        if request.volume != 0 || request.common & (RETURNED | NAME) != (RETURNED | NAME) {
            return Err(Errno::EINVAL);
        }
        Ok(request)
    }

    fn read(data: &[u8], options: u64) -> Result<Self, Errno> {
        let word = |offset| {
            u32::from_le_bytes(data[offset..offset + 4].try_into().expect("attribute word"))
        };
        let count = u16::from_le_bytes(data[..2].try_into().expect("attrlist count"));
        let common = word(4);
        let volume = word(8);
        let dir = word(12);
        let file = word(16);
        let extended = word(20);
        let pack_invalid = options & FSOPT_PACK_INVAL_ATTRS != 0;
        let has_extended = options & FSOPT_ATTR_CMN_EXTENDED != 0;
        if count != 5
            || pack_invalid && common & RETURNED == 0
            || !has_extended && (extended != 0 || common & (GEN_COUNT | DOCUMENT_ID) != 0)
        {
            return Err(Errno::EINVAL);
        }
        if options
            & !(FSOPT_NOFOLLOW
                | FSOPT_REPORT_FULLSIZE
                | FSOPT_PACK_INVAL_ATTRS
                | FSOPT_ATTR_CMN_EXTENDED
                | FSOPT_NOFOLLOW_ANY)
            != 0
            || common & !(COMMON | COMMON_UNAVAILABLE | ERROR) != 0
            || dir & !(LINKCOUNT | DIR_MOUNTSTATUS) != 0
            || file & !LINKCOUNT != 0
            || extended & !(REALDEVID | EXT_FLAGS) != 0
            || common & RETURNED == 0
                && (common & COMMON_UNAVAILABLE != 0 || extended & EXT_FLAGS != 0)
            || volume != 0
                && (volume & !(VOL_INFO | VOL_CAPABILITIES | VOL_ATTRIBUTES) != 0
                    || common & !RETURNED != 0
                    || dir != 0
                    || file != 0
                    || extended != 0)
        {
            return Err(Errno::ENOTSUP);
        }
        Ok(Self {
            common,
            volume,
            dir,
            file,
            extended,
            pack_invalid,
        })
    }
}

pub(in crate::user::darwin::syscall::bsd) fn get(
    ctx: &Ctx<'_>,
    dirfd: i32,
    path: Option<u64>,
    attrlist: u64,
    buffer: u64,
    size: u64,
    options: u64,
) -> SysResult {
    let request = Request::read(&ctx.read(attrlist, 24)?, options)?;

    let (path, stat, volume) = if let Some(addr) = path {
        let mut flags = 0;
        if options & FSOPT_NOFOLLOW != 0 {
            flags |= AT_SYMLINK_NOFOLLOW;
        }
        if options & FSOPT_NOFOLLOW_ANY != 0 {
            flags |= AT_SYMLINK_NOFOLLOW_ANY;
        }
        let (resolved, entry) = embedded::lookup(ctx, dirfd, addr, embedded::link_policy(flags))?;
        let volume = ClosedVolume::for_entry(Some(resolved.as_bytes()), Some(&entry));
        let stat = embedded::entry_stat(&resolved, entry)?;
        (Some(resolved.into_bytes()), stat, volume)
    } else {
        let file = ctx.proc.fds.file(dirfd)?;
        let FileKind::Embedded(object) = &file.kind else {
            return Err(Errno::EBADF);
        };
        let entry = object.entry();
        let path = match entry {
            Some(entry) => entry.workspace_path()?.map(String::into_bytes),
            None => None,
        }
        .or_else(|| file.path.clone());
        let volume = ClosedVolume::for_entry(path.as_deref(), entry);
        let stat = object.stat_at_path(path.as_deref())?;
        (path, stat, volume)
    };

    if size < 4 {
        return Err(Errno::ERANGE);
    }
    if request.common & (NAME | FULLPATH) != 0 && path.is_none() {
        return Err(Errno::ENOTSUP);
    }
    let files = ctx.proc.vfs.files().ok_or(Errno::ENOTSUP)?;
    let path = path.as_deref().unwrap_or_default();
    let record = pack(
        &request,
        path,
        stat,
        volume.fsid(),
        path == volume.mountpoint(files).as_bytes(),
    );
    // The installed APFS attribute calls report the full record length and
    // copy only the bytes that fit in the caller's buffer.
    let copied = size.min(record.len() as u64) as usize;
    ctx.write(buffer, &record[..copied])?;
    Ok(Rv::one(0))
}

pub(in crate::user::darwin::syscall::bsd) fn pack(
    request: &Request,
    path: &[u8],
    stat: Stat,
    fsid: [i32; 2],
    mountpoint: bool,
) -> Vec<u8> {
    let requested = request.common;
    let report_mask = requested & RETURNED != 0;
    let pack_error = requested & ERROR != 0 && (!report_mask || request.pack_invalid);
    let common = (requested & COMMON) | if pack_error { ERROR } else { 0 };
    let dir = if stat.vnode_type() == 2 {
        request.dir
    } else {
        0
    };
    let file = if stat.vnode_type() == 2 {
        0
    } else {
        request.file
    };
    let mut record = vec![0; 4];
    if report_mask {
        for mask in [
            common,
            request.volume & !VOL_INFO,
            dir,
            file,
            request.extended & REALDEVID,
        ] {
            record.extend_from_slice(&mask.to_le_bytes());
        }
    }
    if request.volume != 0 {
        // The virtual volumes preserve case and support attribute queries.
        const CASE_SENSITIVE: u32 = 0x100;
        const CASE_PRESERVING: u32 = 0x200;
        const ATTRLIST: u32 = 0x2;
        if request.volume & VOL_CAPABILITIES != 0 {
            let supported = [CASE_SENSITIVE | CASE_PRESERVING, ATTRLIST, 0, 0];
            for word in supported.into_iter().chain(supported) {
                record.extend_from_slice(&word.to_le_bytes());
            }
        }
        if request.volume & VOL_ATTRIBUTES != 0 {
            let supported = [
                COMMON | ERROR,
                VOL_INFO | VOL_CAPABILITIES | VOL_ATTRIBUTES,
                LINKCOUNT | DIR_MOUNTSTATUS,
                LINKCOUNT,
                REALDEVID,
            ];
            for word in supported.into_iter().chain(supported) {
                record.extend_from_slice(&word.to_le_bytes());
            }
        }
        return finish(record);
    }
    if pack_error {
        record.extend_from_slice(&[0; 4]);
    }
    let name_offset = record.len();
    if requested & NAME != 0 {
        record.extend_from_slice(&[0; 8]);
    }
    let mut fsid_bytes = [0; 8];
    fsid_bytes[..4].copy_from_slice(&fsid[0].to_le_bytes());
    fsid_bytes[4..].copy_from_slice(&fsid[1].to_le_bytes());
    let packed_common = if request.pack_invalid {
        requested
    } else {
        common
    };
    for (attribute, bytes) in [
        (DEVID, stat.dev.to_le_bytes().as_slice()),
        (FSID, fsid_bytes.as_slice()),
        (OBJTYPE, stat.vnode_type().to_le_bytes().as_slice()),
        (OBJID, stat.ino.to_le_bytes().as_slice()),
        (CRTIME, stat.birthtime.bytes().as_slice()),
        (MODTIME, stat.mtime.bytes().as_slice()),
        (CHGTIME, stat.ctime.bytes().as_slice()),
        (ACCTIME, stat.atime.bytes().as_slice()),
        (OWNERID, stat.uid.to_le_bytes().as_slice()),
        (GRPID, stat.gid.to_le_bytes().as_slice()),
        (ACCESSMASK, u32::from(stat.mode).to_le_bytes().as_slice()),
        (FLAGS, stat.flags.to_le_bytes().as_slice()),
        (GEN_COUNT, [0; 4].as_slice()),
        (DOCUMENT_ID, [0; 4].as_slice()),
        (FILEID, stat.ino.to_le_bytes().as_slice()),
    ] {
        if packed_common & attribute != 0 {
            record.extend_from_slice(bytes);
        }
    }
    let fullpath_offset = record.len();
    if requested & FULLPATH != 0 {
        record.extend_from_slice(&[0; 8]);
    }
    if request.pack_invalid && requested & ADDEDTIME != 0 {
        record.extend_from_slice(&[0; 16]);
    }
    if request.pack_invalid && requested & DATA_PROTECT_FLAGS != 0 {
        record.extend_from_slice(&[0; 4]);
    }
    if (dir | file) & LINKCOUNT != 0 {
        record.extend_from_slice(&u32::from(stat.nlink).to_le_bytes());
    }
    if dir & DIR_MOUNTSTATUS != 0 {
        record.extend_from_slice(&u32::from(mountpoint).to_le_bytes());
    }
    if request.extended & REALDEVID != 0 {
        record.extend_from_slice(&fsid[0].to_le_bytes());
    }
    if request.pack_invalid && request.extended & EXT_FLAGS != 0 {
        record.extend_from_slice(&[0; 8]);
    }
    if requested & NAME != 0 {
        let name = if path == b"/" {
            path
        } else {
            path.rsplit(|&byte| byte == b'/')
                .next()
                .expect("path component")
        };
        append_string(&mut record, name_offset, name);
    }
    if requested & FULLPATH != 0 {
        append_string(&mut record, fullpath_offset, path);
    }
    finish(record)
}

fn finish(mut record: Vec<u8>) -> Vec<u8> {
    let length = record.len() as u32;
    record[..4].copy_from_slice(&length.to_le_bytes());
    record
}

fn append_string(record: &mut Vec<u8>, reference: usize, value: &[u8]) {
    let relative = (record.len() - reference) as u32;
    let length = (value.len() + 1) as u32;
    record[reference..reference + 4].copy_from_slice(&relative.to_le_bytes());
    record[reference + 4..reference + 8].copy_from_slice(&length.to_le_bytes());
    record.extend_from_slice(value);
    record.resize((record.len() + 1).next_multiple_of(4), 0);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(masks: [u32; 5], options: u64) -> Result<Request, Errno> {
        let mut data = vec![5, 0, 0, 0];
        for mask in masks {
            data.extend_from_slice(&mask.to_le_bytes());
        }
        Request::read(&data, options)
    }

    fn word(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
    }

    #[test]
    fn directory_attribute_records_describe_the_guest_mount() {
        let selected = RETURNED | NAME | FSID | OBJTYPE | MODTIME;
        let requested = selected | COMMON_UNAVAILABLE | ERROR;
        let masks = [
            requested,
            0,
            LINKCOUNT | DIR_MOUNTSTATUS,
            LINKCOUNT,
            REALDEVID | EXT_FLAGS,
        ];
        let fsid = [0x524158, 1];
        let stat = Stat {
            mode: 0o40555,
            nlink: 3,
            ..Stat::default()
        };
        let path = b"/Developer/Toolchains";
        let compact = request(masks, FSOPT_ATTR_CMN_EXTENDED).unwrap();
        let record = pack(&compact, path, stat, fsid, false);
        assert_eq!(word(&record, 0), 84);
        for (offset, expected) in [
            (4, selected),
            (12, LINKCOUNT | DIR_MOUNTSTATUS),
            (16, 0),
            (20, REALDEVID),
            (24, 48),
            (28, 11),
            (32, 0x524158),
            (36, 1),
            (40, 2),
            (60, 3),
            (64, 0),
            (68, 0x524158),
        ] {
            assert_eq!(word(&record, offset), expected, "offset {offset}");
        }
        assert_eq!(&record[72..83], b"Toolchains\0");

        let packed = request(masks, FSOPT_ATTR_CMN_EXTENDED | FSOPT_PACK_INVAL_ATTRS).unwrap();
        let record = pack(&packed, path, stat, fsid, true);
        assert_eq!(word(&record, 0), 124);
        assert_eq!(word(&record, 4), selected | ERROR);
        assert_eq!(word(&record, 20), REALDEVID);
        assert_eq!(word(&record, 24), 0);
        assert_eq!(word(&record, 28), 84);
        assert_eq!(word(&record, 100), 0x524158);
        assert_eq!(word(&record, 96), 1);
        assert_eq!(&record[104..112], &[0; 8]);
        assert_eq!(&record[112..123], b"Toolchains\0");

        let file = Stat {
            mode: 0o100444,
            nlink: 1,
            ..Stat::default()
        };
        let record = pack(&compact, b"/usr/bin/true", file, fsid, false);
        assert_eq!(word(&record, 12), 0);
        assert_eq!(word(&record, 16), LINKCOUNT);
        assert_eq!(word(&record, 40), 1);
        assert_eq!(word(&record, 60), 1);
    }

    #[test]
    fn volume_capabilities_only_advertise_guest_behavior() {
        let volume = VOL_INFO | VOL_CAPABILITIES;
        let query = request([0, volume, 0, 0, 0], 0).unwrap();
        let record = pack(&query, b"/", Stat::default(), [0x524158, 1], true);
        assert_eq!(word(&record, 0), 36);
        assert_eq!(&record[4..20], &record[20..36]);
        assert_eq!(word(&record, 4), 0x300);
        assert_eq!(word(&record, 8), 2);

        let query = request([RETURNED, volume, 0, 0, 0], 0).unwrap();
        let record = pack(&query, b"/", Stat::default(), [0x524158, 1], true);
        assert_eq!(word(&record, 0), 56);
        assert_eq!(word(&record, 4), RETURNED);
        assert_eq!(word(&record, 8), VOL_CAPABILITIES);
        assert_eq!(word(&record, 24), 0x300);

        let query = request([0, VOL_CAPABILITIES, 0, 0, 0], 0).unwrap();
        let capabilities = pack(&query, b"/", Stat::default(), [0x524158, 1], true);
        assert_eq!(&record[24..], &capabilities[4..]);

        let query = request(
            [0, VOL_INFO | VOL_ATTRIBUTES, 0, 0, 0],
            FSOPT_ATTR_CMN_EXTENDED,
        )
        .unwrap();
        let record = pack(&query, b"/", Stat::default(), [0x524158, 1], true);
        assert_eq!(word(&record, 0), 44);
        assert_eq!(&record[4..24], &record[24..44]);
        assert_eq!(word(&record, 20), REALDEVID);
    }

    #[test]
    fn extended_option_is_valid_with_or_without_extended_fields() {
        let masks = [RETURNED | DEVID | OBJTYPE | FULLPATH, 0, 0, 0, 0];
        let options = FSOPT_NOFOLLOW | FSOPT_PACK_INVAL_ATTRS | FSOPT_ATTR_CMN_EXTENDED;
        assert!(request(masks, options).is_ok());
        assert!(matches!(
            request([RETURNED, 0, 0, 0, REALDEVID], 0),
            Err(Errno::EINVAL)
        ));
        assert!(matches!(
            request([0, 0, 0, 0, EXT_FLAGS], options),
            Err(Errno::EINVAL)
        ));
    }
}
