//! Structures copied across the Linux system-call boundary.
//!
//! Each encoder produces the exact byte image of the kernel structure for a
//! [`LinuxAbi`], little-endian, with padding zeroed. Layouts follow the
//! vendored UAPI headers: `asm/stat.h` (x86-64) and `asm-generic/stat.h`
//! (arm64, riscv) for `struct stat`, `linux/stat.h` for `struct statx`,
//! `linux/sysinfo.h`, `linux/utsname.h` (`struct new_utsname`), and
//! `linux/time_types.h`.

use super::LinuxAbi;

/// Little-endian structure writer.
#[derive(Default)]
pub struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    /// An empty encoder.
    pub fn new() -> Self {
        Encoder::default()
    }

    /// Appends a `u8`.
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.bytes.push(v);
        self
    }

    /// Appends a little-endian `u16`.
    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.bytes.extend_from_slice(&v.to_le_bytes());
        self
    }

    /// Appends a little-endian `u32`.
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.bytes.extend_from_slice(&v.to_le_bytes());
        self
    }

    /// Appends a little-endian `u64`.
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.bytes.extend_from_slice(&v.to_le_bytes());
        self
    }

    /// Appends a little-endian `i64`.
    pub fn i64(&mut self, v: i64) -> &mut Self {
        self.u64(v as u64)
    }

    /// Appends raw bytes.
    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.bytes.extend_from_slice(b);
        self
    }

    /// Appends zero bytes up to a multiple of `align`.
    pub fn align(&mut self, align: usize) -> &mut Self {
        while self.bytes.len() % align != 0 {
            self.bytes.push(0);
        }
        self
    }

    /// Appends `n` zero bytes.
    pub fn zeros(&mut self, n: usize) -> &mut Self {
        self.bytes.resize(self.bytes.len() + n, 0);
        self
    }

    /// Appends `s` NUL-padded to exactly `len` bytes (truncating so a NUL
    /// always terminates).
    pub fn cstr_field(&mut self, s: &str, len: usize) -> &mut Self {
        let n = s.len().min(len - 1);
        self.bytes.extend_from_slice(&s.as_bytes()[..n]);
        self.zeros(len - n)
    }

    /// Bytes written so far.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether nothing was written.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// The encoded bytes.
    pub fn finish(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.bytes)
    }
}

/// A `struct timespec` value (64-bit `time_t`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Timespec {
    /// Seconds.
    pub sec: i64,
    /// Nanoseconds in `[0, 1e9)`.
    pub nsec: i64,
}

impl Timespec {
    /// Size of the encoding in bytes.
    pub const SIZE: usize = 16;

    /// Encodes as `struct timespec`/`struct __kernel_timespec`.
    pub fn encode(self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&self.sec.to_le_bytes());
        out[8..].copy_from_slice(&self.nsec.to_le_bytes());
        out
    }

    /// Decodes a `struct timespec`.
    pub fn decode(b: &[u8; 16]) -> Self {
        Timespec {
            sec: i64::from_le_bytes(b[..8].try_into().unwrap()),
            nsec: i64::from_le_bytes(b[8..].try_into().unwrap()),
        }
    }

    /// From a duration since some epoch.
    pub fn from_duration(d: std::time::Duration) -> Self {
        Timespec {
            sec: d.as_secs() as i64,
            nsec: i64::from(d.subsec_nanos()),
        }
    }
}

/// File metadata in ABI-neutral form.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stat {
    /// Device major number.
    pub dev_major: u32,
    /// Device minor number.
    pub dev_minor: u32,
    /// Inode number.
    pub ino: u64,
    /// File type and permission bits (Linux `S_IF*` encoding).
    pub mode: u32,
    /// Hard-link count.
    pub nlink: u64,
    /// Owner.
    pub uid: u32,
    /// Group.
    pub gid: u32,
    /// Represented device major number (for device files).
    pub rdev_major: u32,
    /// Represented device minor number.
    pub rdev_minor: u32,
    /// Size in bytes.
    pub size: i64,
    /// Preferred I/O block size.
    pub blksize: i64,
    /// 512-byte blocks allocated.
    pub blocks: i64,
    /// Last access.
    pub atime: Timespec,
    /// Last modification.
    pub mtime: Timespec,
    /// Last status change.
    pub ctime: Timespec,
    /// Creation time, when known.
    pub btime: Option<Timespec>,
}

/// Linux `new_encode_dev()`: the 32-bit `dev_t` placed in `struct stat`.
pub fn encode_dev(major: u32, minor: u32) -> u64 {
    u64::from((minor & 0xff) | ((major & 0xfff) << 8) | ((minor & !0xff) << 12))
}

/// Linux `S_IF*` file-type bits.
pub mod mode {
    /// `S_IFMT`.
    pub const S_IFMT: u32 = 0o170000;
    /// `S_IFSOCK`.
    pub const S_IFSOCK: u32 = 0o140000;
    /// `S_IFLNK`.
    pub const S_IFLNK: u32 = 0o120000;
    /// `S_IFREG`.
    pub const S_IFREG: u32 = 0o100000;
    /// `S_IFBLK`.
    pub const S_IFBLK: u32 = 0o060000;
    /// `S_IFDIR`.
    pub const S_IFDIR: u32 = 0o040000;
    /// `S_IFCHR`.
    pub const S_IFCHR: u32 = 0o020000;
    /// `S_IFIFO`.
    pub const S_IFIFO: u32 = 0o010000;
}

/// `STATX_BASIC_STATS`.
pub const STATX_BASIC_STATS: u32 = 0x7ff;
/// `STATX_BTIME`.
pub const STATX_BTIME: u32 = 0x800;

/// `DEFAULT_OVERFLOWUID` (`linux/highuid.h`): what a 16-bit ID field shows
/// for an ID that does not fit (`high2lowuid`).
pub const OVERFLOW_ID: u32 = 65534;

/// `MAX_NON_LFS` (`linux/fs.h`): the largest size a non-LFS field holds.
pub const MAX_NON_LFS: i64 = (1 << 31) - 1;

/// `high2lowuid`: an ID in a 16-bit field.
pub fn low_id(id: u32) -> u16 {
    if id & !0xFFFF != 0 {
        OVERFLOW_ID as u16
    } else {
        id as u16
    }
}

impl Stat {
    /// Whether `cp_compat_stat` refuses the status (`EOVERFLOW`): an inode
    /// number or link count that its 32- and 16-bit fields cannot hold, or a
    /// size past `MAX_NON_LFS`.
    pub fn compat_overflow(&self) -> bool {
        self.ino > u64::from(u32::MAX)
            || self.nlink > u64::from(u16::MAX)
            || self.size > MAX_NON_LFS
    }

    /// Encodes `struct stat` for `abi`: 144 bytes on x86-64, 128 bytes in the
    /// asm-generic layout used by arm64 and riscv, and i386's 64-byte
    /// `struct compat_stat` as `cp_compat_stat` fills it (the caller checks
    /// [`Stat::compat_overflow`] first).
    pub fn encode(&self, abi: LinuxAbi) -> Vec<u8> {
        let dev = encode_dev(self.dev_major, self.dev_minor);
        let rdev = encode_dev(self.rdev_major, self.rdev_minor);
        let mut e = Encoder::new();
        match abi {
            LinuxAbi::X86_64 => {
                e.u64(dev)
                    .u64(self.ino)
                    .u64(self.nlink)
                    .u32(self.mode)
                    .u32(self.uid)
                    .u32(self.gid)
                    .u32(0)
                    .u64(rdev)
                    .i64(self.size)
                    .i64(self.blksize)
                    .i64(self.blocks)
                    .i64(self.atime.sec)
                    .i64(self.atime.nsec)
                    .i64(self.mtime.sec)
                    .i64(self.mtime.nsec)
                    .i64(self.ctime.sec)
                    .i64(self.ctime.nsec)
                    .zeros(24);
                debug_assert_eq!(e.len(), 144);
            }
            LinuxAbi::Aarch64 | LinuxAbi::Riscv64 => {
                e.u64(dev)
                    .u64(self.ino)
                    .u32(self.mode)
                    .u32(self.nlink.min(u64::from(u32::MAX)) as u32)
                    .u32(self.uid)
                    .u32(self.gid)
                    .u64(rdev)
                    .u64(0)
                    .i64(self.size)
                    .u32(self.blksize as u32)
                    .u32(0)
                    .i64(self.blocks)
                    .i64(self.atime.sec)
                    .i64(self.atime.nsec)
                    .i64(self.mtime.sec)
                    .i64(self.mtime.nsec)
                    .i64(self.ctime.sec)
                    .i64(self.ctime.nsec)
                    .u32(0)
                    .u32(0);
                debug_assert_eq!(e.len(), 128);
            }
            LinuxAbi::I386 => {
                e.u32(dev as u32)
                    .u32(self.ino as u32)
                    .u16(self.mode as u16)
                    .u16(self.nlink as u16)
                    .u16(low_id(self.uid))
                    .u16(low_id(self.gid))
                    .u32(rdev as u32)
                    .u32(self.size as u32)
                    .u32(self.blksize as u32)
                    .u32(self.blocks as u32)
                    .u32(self.atime.sec as u32)
                    .u32(self.atime.nsec as u32)
                    .u32(self.mtime.sec as u32)
                    .u32(self.mtime.nsec as u32)
                    .u32(self.ctime.sec as u32)
                    .u32(self.ctime.nsec as u32)
                    .zeros(8);
                debug_assert_eq!(e.len(), 64);
            }
        }
        e.finish()
    }

    /// Encodes `struct statx` (256 bytes, identical on every ABI) reporting
    /// the fields RAX knows: `STATX_BASIC_STATS`, plus `STATX_BTIME` when the
    /// host supplied a creation time.
    pub fn encode_statx(&self) -> Vec<u8> {
        let mask = STATX_BASIC_STATS | if self.btime.is_some() { STATX_BTIME } else { 0 };
        let ts = |e: &mut Encoder, t: Timespec| {
            e.i64(t.sec).u32(t.nsec as u32).u32(0);
        };
        let mut e = Encoder::new();
        e.u32(mask)
            .u32(self.blksize as u32)
            .u64(0)
            .u32(self.nlink.min(u64::from(u32::MAX)) as u32)
            .u32(self.uid)
            .u32(self.gid)
            .u16(self.mode as u16)
            .u16(0)
            .u64(self.ino)
            .u64(self.size as u64)
            .u64(self.blocks as u64)
            .u64(0);
        ts(&mut e, self.atime);
        ts(&mut e, self.btime.unwrap_or_default());
        ts(&mut e, self.ctime);
        ts(&mut e, self.mtime);
        e.u32(self.rdev_major)
            .u32(self.rdev_minor)
            .u32(self.dev_major)
            .u32(self.dev_minor);
        e.zeros(256 - e.len());
        debug_assert_eq!(e.len(), 256);
        e.finish()
    }
}

/// `struct new_utsname` (six 65-byte fields).
pub fn encode_utsname(fields: [&str; 6]) -> Vec<u8> {
    let mut e = Encoder::new();
    for f in fields {
        e.cstr_field(f, 65);
    }
    e.finish()
}

/// `struct sysinfo` for a 64-bit ABI (112 bytes).
#[derive(Clone, Copy, Debug, Default)]
pub struct SysInfo {
    /// Seconds since boot.
    pub uptime: i64,
    /// Load averages scaled by 65536.
    pub loads: [u64; 3],
    /// Total RAM in `mem_unit`s.
    pub totalram: u64,
    /// Free RAM in `mem_unit`s.
    pub freeram: u64,
    /// Shared RAM.
    pub sharedram: u64,
    /// Buffer RAM.
    pub bufferram: u64,
    /// Total swap.
    pub totalswap: u64,
    /// Free swap.
    pub freeswap: u64,
    /// Number of processes.
    pub procs: u16,
    /// Unit of the memory fields in bytes.
    pub mem_unit: u32,
}

impl SysInfo {
    /// Encodes the structure.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.i64(self.uptime);
        for l in self.loads {
            e.u64(l);
        }
        e.u64(self.totalram)
            .u64(self.freeram)
            .u64(self.sharedram)
            .u64(self.bufferram)
            .u64(self.totalswap)
            .u64(self.freeswap)
            .u16(self.procs)
            .u16(0)
            .align(8)
            .u64(0)
            .u64(0)
            .u32(self.mem_unit)
            .align(8);
        debug_assert_eq!(e.len(), 112);
        e.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Stat {
        Stat {
            dev_major: 8,
            dev_minor: 0x123,
            ino: 0x1122_3344_5566_7788,
            mode: mode::S_IFREG | 0o644,
            nlink: 2,
            uid: 1000,
            gid: 100,
            rdev_major: 0,
            rdev_minor: 0,
            size: 4097,
            blksize: 4096,
            blocks: 16,
            atime: Timespec { sec: 1, nsec: 2 },
            mtime: Timespec { sec: 3, nsec: 4 },
            ctime: Timespec { sec: 5, nsec: 6 },
            btime: None,
        }
    }

    fn u64_at(b: &[u8], off: usize) -> u64 {
        u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
    }

    fn u32_at(b: &[u8], off: usize) -> u32 {
        u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
    }

    #[test]
    fn dev_t_uses_new_encode_dev() {
        // new_encode_dev: minor low byte, major bits 8..19, minor high bits
        // from 20 upward.
        assert_eq!(encode_dev(8, 1), 0x801);
        // 0x23 | (8 << 8) | ((0x123 & !0xff) << 12) = 0x10_0823.
        assert_eq!(encode_dev(8, 0x123), 0x10_0823);
        assert_eq!(encode_dev(259, 0x10000), 0x1000_0000 | (259 << 8));
    }

    #[test]
    fn x86_64_stat_field_offsets() {
        // arch/x86/include/uapi/asm/stat.h (64-bit): nlink before mode.
        let b = sample().encode(LinuxAbi::X86_64);
        assert_eq!(b.len(), 144);
        assert_eq!(u64_at(&b, 0), encode_dev(8, 0x123));
        assert_eq!(u64_at(&b, 8), 0x1122_3344_5566_7788);
        assert_eq!(u64_at(&b, 16), 2); // st_nlink
        assert_eq!(u32_at(&b, 24), 0o100644); // st_mode
        assert_eq!(u32_at(&b, 28), 1000);
        assert_eq!(u32_at(&b, 32), 100);
        assert_eq!(u64_at(&b, 48), 4097); // st_size
        assert_eq!(u64_at(&b, 56), 4096); // st_blksize
        assert_eq!(u64_at(&b, 64), 16); // st_blocks
        assert_eq!((u64_at(&b, 72), u64_at(&b, 80)), (1, 2));
        assert_eq!((u64_at(&b, 104), u64_at(&b, 112)), (5, 6));
    }

    #[test]
    fn generic_stat_field_offsets() {
        // include/uapi/asm-generic/stat.h: mode before a 32-bit nlink.
        for abi in [LinuxAbi::Aarch64, LinuxAbi::Riscv64] {
            let b = sample().encode(abi);
            assert_eq!(b.len(), 128);
            assert_eq!(u32_at(&b, 16), 0o100644); // st_mode
            assert_eq!(u32_at(&b, 20), 2); // st_nlink
            assert_eq!(u32_at(&b, 24), 1000);
            assert_eq!(u64_at(&b, 48), 4097); // st_size
            assert_eq!(u32_at(&b, 56), 4096); // st_blksize
            assert_eq!(u64_at(&b, 64), 16); // st_blocks
            assert_eq!((u64_at(&b, 72), u64_at(&b, 80)), (1, 2));
            assert_eq!((u64_at(&b, 104), u64_at(&b, 112)), (5, 6));
        }
    }

    #[test]
    fn statx_field_offsets() {
        let mut s = sample();
        s.btime = Some(Timespec { sec: 9, nsec: 10 });
        let b = s.encode_statx();
        assert_eq!(b.len(), 256);
        assert_eq!(u32_at(&b, 0), STATX_BASIC_STATS | STATX_BTIME);
        assert_eq!(u32_at(&b, 4), 4096);
        assert_eq!(u32_at(&b, 16), 2);
        assert_eq!(u16::from_le_bytes([b[28], b[29]]), 0o100644);
        assert_eq!(u64_at(&b, 32), 0x1122_3344_5566_7788);
        assert_eq!(u64_at(&b, 40), 4097);
        assert_eq!((u64_at(&b, 64), u32_at(&b, 72)), (1, 2)); // atime
        assert_eq!((u64_at(&b, 80), u32_at(&b, 88)), (9, 10)); // btime
        assert_eq!((u64_at(&b, 96), u32_at(&b, 104)), (5, 6)); // ctime
        assert_eq!((u64_at(&b, 112), u32_at(&b, 120)), (3, 4)); // mtime
        assert_eq!((u32_at(&b, 136), u32_at(&b, 140)), (8, 0x123)); // dev
    }

    #[test]
    fn utsname_and_sysinfo_sizes() {
        let u = encode_utsname(["Linux", "host", "6.19.0", "#1", "x86_64", "(none)"]);
        assert_eq!(u.len(), 390);
        assert_eq!(&u[..6], b"Linux\0");
        assert_eq!(&u[4 * 65..4 * 65 + 7], b"x86_64\0");
        let long = "x".repeat(100);
        let u = encode_utsname([&long, "", "", "", "", ""]);
        assert_eq!(u[64], 0, "fields are always NUL-terminated");
        let s = SysInfo {
            uptime: 7,
            mem_unit: 1,
            procs: 3,
            ..Default::default()
        }
        .encode();
        assert_eq!(s.len(), 112);
        assert_eq!(u64_at(&s, 0), 7);
        assert_eq!(u16::from_le_bytes([s[80], s[81]]), 3);
        assert_eq!(u32_at(&s, 104), 1);
    }
}
