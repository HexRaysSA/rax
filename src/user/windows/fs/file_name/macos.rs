//! Darwin path lookup uses the captured link ID, not a vnode's arbitrary alias.
use std::ffi::{CString, OsStr};
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

#[repr(C)]
struct Attrs {
    count: u16,
    reserved: u16,
    common: u32,
    volume: u32,
    directory: u32,
    file: u32,
    extended: u32,
}

unsafe extern "C" {
    fn getattrlist(
        path: *const libc::c_char,
        attrs: *mut Attrs,
        result: *mut libc::c_void,
        bytes: usize,
        options: libc::c_ulong,
    ) -> libc::c_int;
    fn fsgetpath(
        result: *mut libc::c_char,
        bytes: usize,
        fsid: *mut libc::fsid_t,
        link: u64,
    ) -> libc::ssize_t;
}

#[derive(Clone, Debug)]
pub(super) struct Link {
    fsid: [i32; 2],
    id: u64,
}

impl Link {
    pub(super) fn capture(file: &File, opened: &Path) -> io::Result<Self> {
        let path = CString::new(opened.as_os_str().as_bytes())
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        // ATTR_CMN_RETURNED_ATTRS, FSID, FILEID; extended LINKID.
        let mut attrs = Attrs {
            count: 5,
            reserved: 0,
            common: 0x8200_0004,
            volume: 0,
            directory: 0,
            file: 0,
            extended: 0x10,
        };
        let mut bytes = [0u8; 48];
        // SAFETY: the terminated path, repr(C) attrlist and initialized writable
        // result remain live through the synchronous call. FSOPT_ATTR_CMN_EXTENDED
        // selects LINKID; all returned masks and byte bounds are checked below.
        if unsafe {
            getattrlist(
                path.as_ptr(),
                &mut attrs,
                bytes.as_mut_ptr().cast(),
                bytes.len(),
                0x20,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let word = |i| u32::from_ne_bytes(bytes[i..i + 4].try_into().unwrap());
        if word(0) != 48 || word(4) & 0x0200_0004 != 0x0200_0004 || word(20) & 0x10 == 0 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "filesystem link identity is unavailable",
            ));
        }
        let metadata = file.metadata()?;
        let fileid = u64::from_ne_bytes(bytes[32..40].try_into().unwrap());
        if fileid != metadata.ino() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "opened name identity changed",
            ));
        }
        let fsid = [
            i32::from_ne_bytes(bytes[24..28].try_into().unwrap()),
            i32::from_ne_bytes(bytes[28..32].try_into().unwrap()),
        ];
        let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
        // SAFETY: fstatfs writes the complete native structure for the retained
        // descriptor. No field is read before a successful return.
        if unsafe { libc::fstatfs(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the successful call initialized stat. Darwin fsid_t is the
        // asserted 8-byte pair; read_unaligned copies it without an aliasing cast.
        let retained_fsid = unsafe {
            let stat = stat.assume_init();
            assert_eq!(std::mem::size_of::<libc::fsid_t>(), 8);
            std::ptr::addr_of!(stat.f_fsid)
                .cast::<[i32; 2]>()
                .read_unaligned()
        };
        if fsid != retained_fsid {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "opened name volume changed",
            ));
        }
        Ok(Self {
            fsid,
            id: u64::from_ne_bytes(bytes[40..48].try_into().unwrap()),
        })
    }

    pub(super) fn current(&self, file: &File) -> io::Result<PathBuf> {
        let mut bytes = [0u8; 4096];
        let mut fsid = self.fsid;
        // SAFETY: the asserted Darwin fsid_t layout matches this initialized
        // local pair. fsgetpath writes at most the 4096-byte private buffer and
        // retains no pointer. The stored ID identifies the opened directory entry.
        let length = unsafe {
            fsgetpath(
                bytes.as_mut_ptr().cast(),
                bytes.len(),
                fsid.as_mut_ptr().cast(),
                self.id,
            )
        };
        if length < 0 {
            return Err(io::Error::last_os_error());
        }
        let length = length as usize;
        if length == 0 || length > bytes.len() || bytes[length - 1] != 0 {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        let path = Path::new(OsStr::from_bytes(&bytes[..length - 1])).to_owned();
        let candidate = path.metadata()?;
        let retained = file.metadata()?;
        if candidate.dev() != retained.dev() || candidate.ino() != retained.ino() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "resolved link identity changed",
            ));
        }
        Ok(path)
    }
}
