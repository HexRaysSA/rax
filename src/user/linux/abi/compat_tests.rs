//! The i386 structures against `asm/stat.h`, `asm/statfs.h`, and
//! `asm-generic/statfs.h` (offsets as i386 lays them out, 64-bit fields
//! 4-byte aligned) and the conversion rules of `cp_stat64`, `cp_old_stat`,
//! and `put_compat_statfs{,64}`.

use super::*;
use crate::user::linux::abi::types::{Timespec, mode};

fn sample() -> Stat {
    Stat {
        dev_major: 8,
        dev_minor: 0x123,
        ino: 0x1_2345_6789,
        mode: mode::S_IFREG | 0o644,
        nlink: 3,
        uid: 70000,
        gid: 100,
        rdev_major: 1,
        rdev_minor: 5,
        size: 0x1_0000_0001,
        blksize: 4096,
        blocks: 0x2_0000_0000,
        atime: Timespec { sec: 11, nsec: 12 },
        mtime: Timespec { sec: 13, nsec: 14 },
        ctime: Timespec { sec: 15, nsec: 16 },
        btime: None,
    }
}

fn u16_at(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes(b[o..o + 2].try_into().unwrap())
}

fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

fn u64_at(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

#[test]
fn stat64_has_the_i386_offsets() {
    let b = encode_stat64(&sample());
    assert_eq!(b.len(), 96);
    // huge_encode_dev(8:0x123) = 0x23 | 8 << 8 | 0x100 << 12.
    assert_eq!(u64_at(&b, 0), 0x10_0823);
    // __st_ino is the truncated inode number, st_ino the whole one.
    assert_eq!(
        (u32_at(&b, 12), u64_at(&b, 88)),
        (0x2345_6789, 0x1_2345_6789)
    );
    assert_eq!((u32_at(&b, 16), u32_at(&b, 20)), (0o100644, 3));
    // 32-bit IDs: no 16-bit overflow ID.
    assert_eq!((u32_at(&b, 24), u32_at(&b, 28)), (70000, 100));
    assert_eq!(u64_at(&b, 32), 0x105);
    assert_eq!(u64_at(&b, 44), 0x1_0000_0001, "a 64-bit size");
    assert_eq!(u32_at(&b, 52), 4096);
    assert_eq!(u64_at(&b, 56), 0x2_0000_0000, "64-bit blocks");
    let times: Vec<u32> = (0..6).map(|i| u32_at(&b, 64 + 4 * i)).collect();
    assert_eq!(times, [11, 12, 13, 14, 15, 16]);
    for pad in STAT64_PADS {
        assert!(b[pad].iter().all(|&x| x == 0));
    }
}

#[test]
fn old_stat_is_16_bit_and_refuses_what_does_not_fit() {
    let st = Stat {
        ino: 0x4321,
        size: 0x1_0000_0002,
        ..sample()
    };
    let b = encode_old_stat(&st).unwrap();
    assert_eq!(b.len(), 32);
    // old_encode_dev(8:0x123) = 8 << 8 | 0x123, in 16 bits.
    assert_eq!(u16_at(&b, 0), ((8u32 << 8) | 0x123) as u16);
    assert_eq!(
        (u16_at(&b, 2), u16_at(&b, 4), u16_at(&b, 6)),
        (0x4321, 0o100644, 3)
    );
    // high2lowuid: 70000 does not fit.
    assert_eq!((u16_at(&b, 8), u16_at(&b, 10)), (65534, 100));
    assert_eq!(u16_at(&b, 12), 0x105);
    assert_eq!(u16_at(&b, 14), 0, "padding");
    // A 64-bit kernel truncates the size instead of EOVERFLOW.
    assert_eq!(u32_at(&b, 16), 2);
    assert_eq!(
        (u32_at(&b, 20), u32_at(&b, 24), u32_at(&b, 28)),
        (11, 13, 15)
    );
    assert!(
        encode_old_stat(&Stat {
            ino: 0x1_0000,
            ..st
        })
        .is_none()
    );
    assert!(
        encode_old_stat(&Stat {
            nlink: 0x1_0000,
            ..st
        })
        .is_none()
    );
}

fn fs() -> Kstatfs {
    Kstatfs {
        kind: 0xEF53,
        bsize: 4096,
        blocks: 1000,
        bfree: 500,
        bavail: 400,
        files: 300,
        ffree: 200,
        fsid: [7, 8],
        namelen: 255,
        frsize: 4096,
        flags: 0x20,
    }
}

#[test]
fn compat_statfs_is_32_bit_with_its_overflow_rules() {
    let b = encode_compat_statfs(&fs()).unwrap();
    assert_eq!(b.len(), 64);
    let words: Vec<u32> = (0..11).map(|i| u32_at(&b, 4 * i)).collect();
    assert_eq!(
        words,
        [0xEF53, 4096, 1000, 500, 400, 300, 200, 7, 8, 255, 4096]
    );
    assert_eq!(u32_at(&b, 44), 0x20);
    assert!(b[48..].iter().all(|&x| x == 0), "f_spare");
    // Block counts and sizes past 32 bits: EOVERFLOW.
    for big in [
        Kstatfs {
            blocks: 1 << 32,
            ..fs()
        },
        Kstatfs {
            bavail: 1 << 32,
            ..fs()
        },
        Kstatfs {
            frsize: 1 << 32,
            ..fs()
        },
        Kstatfs {
            files: 1 << 32,
            ..fs()
        },
        Kstatfs {
            ffree: 1 << 32,
            ..fs()
        },
    ] {
        assert!(encode_compat_statfs(&big).is_none(), "{big:?}");
    }
    // An inode count of -1 fits as all ones.
    let b = encode_compat_statfs(&Kstatfs {
        files: u64::MAX,
        ffree: u64::MAX,
        ..fs()
    })
    .unwrap();
    assert_eq!((u32_at(&b, 20), u32_at(&b, 24)), (u32::MAX, u32::MAX));
}

#[test]
fn compat_statfs64_is_packed_with_64_bit_counts() {
    let k = Kstatfs {
        blocks: 1 << 40,
        files: 1 << 33,
        ..fs()
    };
    let b = encode_compat_statfs64(&k).unwrap();
    assert_eq!(b.len() as u64, COMPAT_STATFS64_SIZE);
    assert_eq!((u32_at(&b, 0), u32_at(&b, 4)), (0xEF53, 4096));
    assert_eq!((u64_at(&b, 8), u64_at(&b, 16)), (1 << 40, 500));
    assert_eq!((u64_at(&b, 32), u64_at(&b, 40)), (1 << 33, 200));
    assert_eq!((u32_at(&b, 48), u32_at(&b, 52)), (7, 8));
    assert_eq!(
        (u32_at(&b, 56), u32_at(&b, 60), u32_at(&b, 64)),
        (255, 4096, 0x20)
    );
    // Only the sizes must fit.
    assert!(
        encode_compat_statfs64(&Kstatfs {
            bsize: 1 << 32,
            ..fs()
        })
        .is_none()
    );
}
