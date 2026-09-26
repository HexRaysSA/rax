//! Structures of the i386 compatibility ABI (`CONFIG_IA32_EMULATION`)
//! without a native structure of the same layout, as a 64-bit kernel fills
//! them. i386 aligns 64-bit fields to 4 bytes.
//!
//! | Structure | Layout | Filled by |
//! |---|---|---|
//! | `struct stat64` (96 bytes) | `arch/x86/include/uapi/asm/stat.h` | `cp_stat64` (`arch/x86/kernel/sys_ia32.c`) |
//! | `struct __old_kernel_stat` (32 bytes) | `asm/stat.h`, the 64-bit branch | `cp_old_stat` (`fs/stat.c`) |
//! | `struct compat_statfs` (64 bytes) | `arch/x86/include/asm/compat.h` | `put_compat_statfs` (`fs/statfs.c`) |
//! | `struct compat_statfs64` (84 bytes, packed) | `asm-generic/statfs.h` | `put_compat_statfs64` |
//!
//! `struct compat_stat` is [`Stat::encode`] for [`super::LinuxAbi::I386`].

use super::types::{Encoder, Kstatfs, Stat, encode_dev, low_id};

/// The bytes of `struct stat64` that `cp_stat64` does not store (`__pad0`
/// and `__pad3`): they keep what the buffer held.
pub const STAT64_PADS: [std::ops::Range<usize>; 2] = [8..12, 40..44];

/// `struct stat64` as `cp_stat64` fills it: the device numbers in 64-bit
/// fields (`huge_encode_dev`), the inode number both truncated
/// (`__st_ino`) and whole (`st_ino`), 32-bit IDs, and 32-bit times. The
/// pads ([`STAT64_PADS`]) are zero here.
pub fn encode_stat64(st: &Stat) -> Vec<u8> {
    let mut e = Encoder::new();
    e.u64(encode_dev(st.dev_major, st.dev_minor))
        .zeros(4)
        .u32(st.ino as u32)
        .u32(st.mode)
        .u32(st.nlink as u32)
        .u32(st.uid)
        .u32(st.gid)
        .u64(encode_dev(st.rdev_major, st.rdev_minor))
        .zeros(4)
        .i64(st.size)
        .u32(st.blksize as u32)
        .i64(st.blocks)
        .u32(st.atime.sec as u32)
        .u32(st.atime.nsec as u32)
        .u32(st.mtime.sec as u32)
        .u32(st.mtime.nsec as u32)
        .u32(st.ctime.sec as u32)
        .u32(st.ctime.nsec as u32)
        .u64(st.ino);
    debug_assert_eq!(e.len(), 96);
    e.finish()
}

/// `struct __old_kernel_stat` as a 64-bit kernel's `cp_old_stat` fills it:
/// 16-bit device numbers (`old_encode_dev`), inode number, mode, link
/// count, and IDs (`high2lowuid`), then the size and the seconds of the
/// times as `unsigned int`s, the size truncated (the `MAX_NON_LFS` check
/// is for `BITS_PER_LONG == 32` only). `None` (`EOVERFLOW`) for an inode
/// number or link count that 16 bits cannot hold.
pub fn encode_old_stat(st: &Stat) -> Option<Vec<u8>> {
    let old_dev = |major: u32, minor: u32| ((major << 8) | minor) as u16;
    let ino = u16::try_from(st.ino).ok()?;
    let nlink = u16::try_from(st.nlink).ok()?;
    let mut e = Encoder::new();
    e.u16(old_dev(st.dev_major, st.dev_minor))
        .u16(ino)
        .u16(st.mode as u16)
        .u16(nlink)
        .u16(low_id(st.uid))
        .u16(low_id(st.gid))
        .u16(old_dev(st.rdev_major, st.rdev_minor))
        .align(4)
        .u32(st.size as u32)
        .u32(st.atime.sec as u32)
        .u32(st.mtime.sec as u32)
        .u32(st.ctime.sec as u32);
    debug_assert_eq!(e.len(), 32);
    Some(e.finish())
}

const HIGH: u64 = 0xFFFF_FFFF_0000_0000;

/// `struct compat_statfs` as `put_compat_statfs` fills it: `None`
/// (`EOVERFLOW`) when a block count or size needs more than 32 bits, or an
/// inode count does and is not -1 (which fits as all ones).
pub fn encode_compat_statfs(k: &Kstatfs) -> Option<Vec<u8>> {
    if (k.blocks | k.bfree | k.bavail | k.bsize | k.frsize) & HIGH != 0
        || (k.files != u64::MAX && k.files & HIGH != 0)
        || (k.ffree != u64::MAX && k.ffree & HIGH != 0)
    {
        return None;
    }
    let mut e = Encoder::new();
    for v in [
        k.kind, k.bsize, k.blocks, k.bfree, k.bavail, k.files, k.ffree,
    ] {
        e.u32(v as u32);
    }
    e.u32(k.fsid[0])
        .u32(k.fsid[1])
        .u32(k.namelen as u32)
        .u32(k.frsize as u32)
        .u32(k.flags as u32)
        .zeros(16);
    debug_assert_eq!(e.len(), 64);
    Some(e.finish())
}

/// `sizeof(struct compat_statfs64)`, which `statfs64` and `fstatfs64`
/// require as their size argument.
pub const COMPAT_STATFS64_SIZE: u64 = 84;

/// `struct compat_statfs64` as `put_compat_statfs64` fills it: `None`
/// (`EOVERFLOW`) when the block or fragment size needs more than 32 bits.
pub fn encode_compat_statfs64(k: &Kstatfs) -> Option<Vec<u8>> {
    if (k.bsize | k.frsize) & HIGH != 0 {
        return None;
    }
    let mut e = Encoder::new();
    e.u32(k.kind as u32).u32(k.bsize as u32);
    for v in [k.blocks, k.bfree, k.bavail, k.files, k.ffree] {
        e.u64(v);
    }
    e.u32(k.fsid[0])
        .u32(k.fsid[1])
        .u32(k.namelen as u32)
        .u32(k.frsize as u32)
        .u32(k.flags as u32)
        .zeros(16);
    debug_assert_eq!(e.len() as u64, COMPAT_STATFS64_SIZE);
    Some(e.finish())
}

#[cfg(test)]
#[path = "compat_tests.rs"]
mod tests;
