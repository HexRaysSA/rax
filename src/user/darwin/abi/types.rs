//! Darwin structure layouts (LP64, identical on x86-64 and arm64).
//!
//! Offsets and sizes were measured with `offsetof`/`sizeof` against the
//! macOS SDK for both architectures (see the unit tests); the encoders fill
//! the guest's byte layout from host values field by field, so a host with
//! other layouts (Linux) produces the same guest bytes.

/// `sizeof(struct stat64)`.
pub const STAT64_SIZE: usize = 144;
/// `sizeof(struct statfs64)`.
pub const STATFS64_SIZE: usize = 2168;
/// `sizeof(struct timeval)` and `struct timespec`.
pub const TIMEVAL_SIZE: usize = 16;
/// `sizeof(struct rusage)`.
pub const RUSAGE_SIZE: usize = 144;
/// `sizeof(struct utsname)`: five 256-byte fields.
pub const UTSNAME_SIZE: usize = 1280;

fn put_u16(b: &mut [u8], off: usize, v: u16) {
    b[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

fn put_u32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn put_u64(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

/// A `struct timespec`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Timespec {
    /// Seconds.
    pub sec: i64,
    /// Nanoseconds.
    pub nsec: i64,
}

impl Timespec {
    /// The guest bytes.
    pub fn bytes(&self) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[..8].copy_from_slice(&self.sec.to_le_bytes());
        b[8..].copy_from_slice(&self.nsec.to_le_bytes());
        b
    }

    /// Decodes guest bytes.
    pub fn from_bytes(b: &[u8; 16]) -> Self {
        Timespec {
            sec: i64::from_le_bytes(b[..8].try_into().expect("8 bytes")),
            nsec: i64::from_le_bytes(b[8..].try_into().expect("8 bytes")),
        }
    }
}

/// A `struct timeval` (`tv_usec` is an `int` padded to 8 bytes).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Timeval {
    /// Seconds.
    pub sec: i64,
    /// Microseconds.
    pub usec: i32,
}

impl Timeval {
    /// The guest bytes.
    pub fn bytes(&self) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[..8].copy_from_slice(&self.sec.to_le_bytes());
        b[8..12].copy_from_slice(&self.usec.to_le_bytes());
        b
    }

    /// Decodes guest bytes.
    pub fn from_bytes(b: &[u8; 16]) -> Self {
        Timeval {
            sec: i64::from_le_bytes(b[..8].try_into().expect("8 bytes")),
            usec: i32::from_le_bytes(b[8..12].try_into().expect("4 bytes")),
        }
    }
}

/// The fields of a `struct stat64`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stat {
    pub dev: i32,
    pub mode: u16,
    pub nlink: u16,
    pub ino: u64,
    pub uid: u32,
    pub gid: u32,
    pub rdev: i32,
    pub atime: Timespec,
    pub mtime: Timespec,
    pub ctime: Timespec,
    pub birthtime: Timespec,
    pub size: i64,
    pub blocks: i64,
    pub blksize: i32,
    pub flags: u32,
    pub generation: u32,
}

impl Stat {
    /// The guest's `struct stat64` bytes.
    pub fn bytes(&self) -> [u8; STAT64_SIZE] {
        let mut b = [0u8; STAT64_SIZE];
        put_u32(&mut b, 0, self.dev as u32);
        put_u16(&mut b, 4, self.mode);
        put_u16(&mut b, 6, self.nlink);
        put_u64(&mut b, 8, self.ino);
        put_u32(&mut b, 16, self.uid);
        put_u32(&mut b, 20, self.gid);
        put_u32(&mut b, 24, self.rdev as u32);
        b[32..48].copy_from_slice(&self.atime.bytes());
        b[48..64].copy_from_slice(&self.mtime.bytes());
        b[64..80].copy_from_slice(&self.ctime.bytes());
        b[80..96].copy_from_slice(&self.birthtime.bytes());
        put_u64(&mut b, 96, self.size as u64);
        put_u64(&mut b, 104, self.blocks as u64);
        put_u32(&mut b, 112, self.blksize as u32);
        put_u32(&mut b, 116, self.flags);
        put_u32(&mut b, 120, self.generation);
        b
    }

    /// The fields of a host `stat`.
    #[cfg(unix)]
    pub fn from_host(st: &libc::stat) -> Self {
        #[cfg(target_os = "macos")]
        let (birth, flags, generation) = (
            Timespec {
                sec: st.st_birthtime,
                nsec: st.st_birthtime_nsec,
            },
            st.st_flags,
            st.st_gen,
        );
        #[cfg(not(target_os = "macos"))]
        let (birth, flags, generation) = (
            Timespec {
                sec: st.st_ctime as i64,
                nsec: st.st_ctime_nsec as i64,
            },
            0u32,
            0u32,
        );
        Stat {
            dev: st.st_dev as i32,
            mode: st.st_mode as u16,
            nlink: st.st_nlink as u16,
            ino: st.st_ino as u64,
            uid: st.st_uid,
            gid: st.st_gid,
            rdev: st.st_rdev as i32,
            atime: Timespec {
                sec: st.st_atime as i64,
                nsec: st.st_atime_nsec as i64,
            },
            mtime: Timespec {
                sec: st.st_mtime as i64,
                nsec: st.st_mtime_nsec as i64,
            },
            ctime: Timespec {
                sec: st.st_ctime as i64,
                nsec: st.st_ctime_nsec as i64,
            },
            birthtime: birth,
            size: st.st_size as i64,
            blocks: st.st_blocks as i64,
            blksize: st.st_blksize as i32,
            flags,
            generation,
        }
    }
}

/// The fields of a `struct statfs64`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Statfs {
    pub bsize: u32,
    pub iosize: i32,
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
    pub files: u64,
    pub ffree: u64,
    pub fsid: [i32; 2],
    pub owner: u32,
    pub fstype: u32,
    pub flags: u32,
    pub fssubtype: u32,
    pub fstypename: Vec<u8>,
    pub mntonname: Vec<u8>,
    pub mntfromname: Vec<u8>,
    pub flags_ext: u32,
}

impl Statfs {
    /// The guest's `struct statfs64` bytes.
    pub fn bytes(&self) -> Vec<u8> {
        let mut b = vec![0u8; STATFS64_SIZE];
        put_u32(&mut b, 0, self.bsize);
        put_u32(&mut b, 4, self.iosize as u32);
        put_u64(&mut b, 8, self.blocks);
        put_u64(&mut b, 16, self.bfree);
        put_u64(&mut b, 24, self.bavail);
        put_u64(&mut b, 32, self.files);
        put_u64(&mut b, 40, self.ffree);
        put_u32(&mut b, 48, self.fsid[0] as u32);
        put_u32(&mut b, 52, self.fsid[1] as u32);
        put_u32(&mut b, 56, self.owner);
        put_u32(&mut b, 60, self.fstype);
        put_u32(&mut b, 64, self.flags);
        put_u32(&mut b, 68, self.fssubtype);
        let n = self.fstypename.len().min(15);
        b[72..72 + n].copy_from_slice(&self.fstypename[..n]);
        let n = self.mntonname.len().min(1023);
        b[88..88 + n].copy_from_slice(&self.mntonname[..n]);
        let n = self.mntfromname.len().min(1023);
        b[1112..1112 + n].copy_from_slice(&self.mntfromname[..n]);
        put_u32(&mut b, 2136, self.flags_ext);
        b
    }

    /// The fields of a host `statfs`.
    #[cfg(target_os = "macos")]
    pub fn from_host(s: &libc::statfs) -> Self {
        let cstr = |a: &[libc::c_char]| -> Vec<u8> {
            a.iter()
                .take_while(|&&c| c != 0)
                .map(|&c| c as u8)
                .collect()
        };
        // SAFETY: fsid_t is two 32-bit integers.
        let fsid: [i32; 2] = unsafe { std::mem::transmute(s.f_fsid) };
        Statfs {
            bsize: s.f_bsize,
            iosize: s.f_iosize,
            blocks: s.f_blocks,
            bfree: s.f_bfree,
            bavail: s.f_bavail,
            files: s.f_files,
            ffree: s.f_ffree,
            fsid,
            owner: s.f_owner,
            fstype: s.f_type,
            flags: s.f_flags,
            fssubtype: s.f_fssubtype,
            fstypename: cstr(&s.f_fstypename),
            mntonname: cstr(&s.f_mntonname),
            mntfromname: cstr(&s.f_mntfromname),
            flags_ext: s.f_flags_ext,
        }
    }
}

/// A `struct rusage` from host usage.
#[cfg(unix)]
pub fn rusage_bytes(r: &libc::rusage) -> [u8; RUSAGE_SIZE] {
    let mut b = [0u8; RUSAGE_SIZE];
    let tv = |t: &libc::timeval| Timeval {
        sec: t.tv_sec as i64,
        usec: t.tv_usec as i32,
    };
    b[0..16].copy_from_slice(&tv(&r.ru_utime).bytes());
    b[16..32].copy_from_slice(&tv(&r.ru_stime).bytes());
    let longs = [
        r.ru_maxrss,
        r.ru_ixrss,
        r.ru_idrss,
        r.ru_isrss,
        r.ru_minflt,
        r.ru_majflt,
        r.ru_nswap,
        r.ru_inblock,
        r.ru_oublock,
        r.ru_msgsnd,
        r.ru_msgrcv,
        r.ru_nsignals,
        r.ru_nvcsw,
        r.ru_nivcsw,
    ];
    for (i, v) in longs.iter().enumerate() {
        put_u64(&mut b, 32 + 8 * i, *v as u64);
    }
    b
}

/// A `struct utsname`.
pub fn utsname_bytes(fields: [&[u8]; 5]) -> Vec<u8> {
    let mut b = vec![0u8; UTSNAME_SIZE];
    for (i, f) in fields.iter().enumerate() {
        let n = f.len().min(255);
        b[256 * i..256 * i + n].copy_from_slice(&f[..n]);
    }
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Offsets measured with the macOS SDK (`offsetof`), identical for
    /// arm64 and x86_64.
    #[test]
    fn stat64_layout() {
        let s = Stat {
            dev: 0x0101_0203,
            mode: 0o100644,
            nlink: 2,
            ino: 0x1122_3344_5566_7788,
            uid: 501,
            gid: 20,
            rdev: 7,
            atime: Timespec { sec: 1, nsec: 2 },
            mtime: Timespec { sec: 3, nsec: 4 },
            ctime: Timespec { sec: 5, nsec: 6 },
            birthtime: Timespec { sec: 7, nsec: 8 },
            size: 4096,
            blocks: 8,
            blksize: 4096,
            flags: 0x20,
            generation: 9,
        };
        let b = s.bytes();
        assert_eq!(u32::from_le_bytes(b[0..4].try_into().unwrap()), 0x0101_0203);
        assert_eq!(u16::from_le_bytes([b[4], b[5]]), 0o100644);
        assert_eq!(u16::from_le_bytes([b[6], b[7]]), 2);
        assert_eq!(
            u64::from_le_bytes(b[8..16].try_into().unwrap()),
            0x1122_3344_5566_7788
        );
        assert_eq!(u32::from_le_bytes(b[16..20].try_into().unwrap()), 501);
        assert_eq!(u32::from_le_bytes(b[20..24].try_into().unwrap()), 20);
        assert_eq!(i64::from_le_bytes(b[32..40].try_into().unwrap()), 1);
        assert_eq!(i64::from_le_bytes(b[88..96].try_into().unwrap()), 8);
        assert_eq!(i64::from_le_bytes(b[96..104].try_into().unwrap()), 4096);
        assert_eq!(i64::from_le_bytes(b[104..112].try_into().unwrap()), 8);
        assert_eq!(u32::from_le_bytes(b[116..120].try_into().unwrap()), 0x20);
        assert_eq!(&b[124..144], &[0u8; 20]);
    }

    #[test]
    fn statfs64_layout() {
        let s = Statfs {
            bsize: 4096,
            fstypename: b"apfs".to_vec(),
            mntonname: b"/".to_vec(),
            mntfromname: b"/dev/disk3s1".to_vec(),
            ..Default::default()
        };
        let b = s.bytes();
        assert_eq!(b.len(), 2168);
        assert_eq!(&b[72..76], b"apfs");
        assert_eq!(b[88], b'/');
        assert_eq!(&b[1112..1124], b"/dev/disk3s1");
    }

    #[test]
    fn timevals_round_trip() {
        let t = Timeval {
            sec: -5,
            usec: 999_999,
        };
        assert_eq!(Timeval::from_bytes(&t.bytes()), t);
        let s = Timespec {
            sec: 1 << 40,
            nsec: 1,
        };
        assert_eq!(Timespec::from_bytes(&s.bytes()), s);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn host_stat_bytes_are_the_guests_on_macos() {
        // On a Mac the host's struct stat is the guest's stat64: the
        // encoder must reproduce the host's own bytes.
        // SAFETY: stat writes a complete struct on success.
        let st = unsafe {
            let mut st: libc::stat = std::mem::zeroed();
            assert_eq!(libc::stat(c"/".as_ptr(), &mut st), 0);
            st
        };
        // SAFETY: reading the struct's bytes; libc::stat is 144 bytes.
        let raw: [u8; STAT64_SIZE] = unsafe { std::mem::transmute(st) };
        let mine = Stat::from_host(&st).bytes();
        // Padding and spares are zero in the encoder.
        assert_eq!(&mine[..28], &raw[..28]);
        assert_eq!(&mine[32..124], &raw[32..124]);
    }
}
