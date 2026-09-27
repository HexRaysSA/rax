//! Ancillary data (`struct cmsghdr`, `net/core/scm.c`) and descriptor
//! passing.
//!
//! On the 64-bit ABIs a control message is a 16-byte header (`cmsg_len`
//! as a `size_t`, `cmsg_level`, `cmsg_type`) and its data, each message
//! padded to 8 bytes (`CMSG_ALIGN`). A 32-bit caller's (`MSG_CMSG_COMPAT`,
//! `net/compat.c`) has a 12-byte `struct compat_cmsghdr` and is padded to 4
//! bytes (`CMSG_COMPAT_*`): [`from_compat`] converts what it sends, and an
//! [`Out`] made with [`Out::compat`] writes what it receives.
//!
//! `SCM_RIGHTS` descriptors travel as host descriptors, so they reach other
//! processes as they do on Linux. A description has more than its host
//! descriptor (its status flags, the personality's objects), so a send also
//! records each description here, keyed by its host object's identity: a
//! receiver in the same process gets the same description back, as Linux
//! gives it. A description without a host descriptor (an `eventfd`,
//! `timerfd`, `signalfd`, `epoll` instance, or synthesized `/proc` file)
//! travels as a stand-in socket that only this record resolves, so it
//! reaches only its own process; another receives the stand-in.

use std::collections::VecDeque;
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex, Weak};

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::fs::fd::OpenFile;

/// `sizeof(struct cmsghdr)`.
pub const HDR: usize = 16;
/// `SCM_MAX_FD`.
pub const MAX_FDS: usize = 253;

/// `CMSG_ALIGN`.
pub fn align(n: usize) -> usize {
    (n + 7) & !7
}

/// `CMSG_LEN`.
pub fn cmsg_len(n: usize) -> usize {
    HDR + n
}

/// `CMSG_SPACE`.
pub fn cmsg_space(n: usize) -> usize {
    HDR + align(n)
}

/// One control message a sender attached.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cmsg {
    /// `cmsg_level`.
    pub level: i32,
    /// `cmsg_type`.
    pub kind: i32,
    /// The data (`cmsg_len - HDR` bytes).
    pub data: Vec<u8>,
}

/// Splits control data into messages (`for_each_cmsghdr`), rejecting a
/// header whose length is below the header's or beyond the data
/// (`CMSG_OK`) with `EINVAL`.
pub fn split(ctl: &[u8]) -> Result<Vec<Cmsg>, Errno> {
    let mut out = Vec::new();
    let mut off = 0usize;
    // __CMSG_FIRSTHDR and __cmsg_nxthdr: a header must fit entirely.
    while off + HDR <= ctl.len() {
        let len = u64::from_le_bytes(ctl[off..off + 8].try_into().unwrap());
        if len < HDR as u64 || len > (ctl.len() - off) as u64 {
            return Err(Errno(EINVAL));
        }
        let len = len as usize;
        out.push(Cmsg {
            level: i32::from_le_bytes(ctl[off + 8..off + 12].try_into().unwrap()),
            kind: i32::from_le_bytes(ctl[off + 12..off + 16].try_into().unwrap()),
            data: ctl[off + HDR..off + len].to_vec(),
        });
        off += align(len);
    }
    Ok(out)
}

/// `sizeof(struct compat_cmsghdr)`.
pub const COMPAT_HDR: usize = 12;

/// `CMSG_COMPAT_ALIGN`.
fn compat_align(n: usize) -> usize {
    (n + 3) & !3
}

/// `cmsghdr_from_user_compat_to_kern`: a 32-bit caller's control data as
/// the kernel's 64-bit messages. Each `compat_cmsghdr` must pass
/// `CMSG_COMPAT_OK` (`EINVAL`); after a message the next header starts at
/// its 4-byte-aligned end if any byte remains there, so trailing bytes too
/// few for a header are refused too, and control data without a message is
/// `EINVAL`.
pub fn from_compat(ctl: &[u8]) -> Result<Vec<u8>, Errno> {
    let mut out = Vec::new();
    let mut off = 0usize;
    // CMSG_COMPAT_FIRSTHDR, then cmsg_compat_nxthdr.
    let mut more = ctl.len() >= COMPAT_HDR;
    while more {
        let rest = ctl.len() - off;
        if rest < COMPAT_HDR {
            return Err(Errno(EINVAL));
        }
        let word = |at: usize| u32::from_le_bytes(ctl[off + at..off + at + 4].try_into().unwrap());
        let len = word(0) as usize;
        if len < COMPAT_HDR || len > rest {
            return Err(Errno(EINVAL));
        }
        let data = &ctl[off + COMPAT_HDR..off + len];
        out.extend_from_slice(&(cmsg_len(data.len()) as u64).to_le_bytes());
        out.extend_from_slice(&word(4).to_le_bytes());
        out.extend_from_slice(&word(8).to_le_bytes());
        out.extend_from_slice(data);
        out.resize(align(out.len()), 0);
        off += compat_align(len);
        more = off < ctl.len();
    }
    if out.is_empty() {
        return Err(Errno(EINVAL));
    }
    Ok(out)
}

/// Control data being written back to a receiver: the bytes and the room
/// left (`msg_controllen`), and whether anything did not fit
/// (`MSG_CTRUNC`), in the native layout or a 32-bit caller's.
#[derive(Debug, Default)]
pub struct Out {
    /// The bytes written so far.
    pub bytes: Vec<u8>,
    /// The room left.
    pub room: usize,
    /// `MSG_CTRUNC`.
    pub truncated: bool,
    /// `struct compat_cmsghdr` messages (`put_cmsg_compat`).
    compat: bool,
}

impl Out {
    /// Room for `room` bytes.
    pub fn new(room: usize) -> Self {
        Out {
            bytes: Vec::new(),
            room,
            truncated: false,
            compat: false,
        }
    }

    /// Room for `room` bytes of a 32-bit caller's messages.
    pub fn compat(room: usize) -> Self {
        Out {
            compat: true,
            ..Out::new(room)
        }
    }

    fn hdr(&self) -> usize {
        if self.compat { COMPAT_HDR } else { HDR }
    }

    /// `put_cmsg` (or `put_cmsg_compat`): the message, cut to the room left
    /// (setting `MSG_CTRUNC`), or nothing when not even a header fits.
    pub fn put(&mut self, level: i32, kind: i32, data: &[u8]) {
        let hdr = self.hdr();
        if self.room < hdr {
            self.truncated = true;
            return;
        }
        let mut len = hdr + data.len();
        if self.room < len {
            self.truncated = true;
            len = self.room;
        }
        if self.compat {
            self.bytes.extend_from_slice(&(len as u32).to_le_bytes());
        } else {
            self.bytes.extend_from_slice(&(len as u64).to_le_bytes());
        }
        self.bytes.extend_from_slice(&level.to_le_bytes());
        self.bytes.extend_from_slice(&kind.to_le_bytes());
        self.bytes.extend_from_slice(&data[..len - hdr]);
        let space = if self.compat {
            hdr + compat_align(data.len())
        } else {
            cmsg_space(data.len())
        };
        let used = space.min(self.room);
        self.bytes.resize(self.bytes.len() + (used - len), 0);
        self.room -= used;
    }

    /// `scm_max_fds` (`scm_max_fds_compat`): the descriptors the room left
    /// can take.
    pub fn max_fds(&self) -> usize {
        let hdr = self.hdr();
        if self.room <= hdr {
            0
        } else {
            (self.room - hdr) / 4
        }
    }
}

/// A host object's identity (`st_dev`, `st_ino`).
pub type Key = (u64, u64);

/// The identity of host descriptor `fd`; none for an object the host
/// gives no inode (Darwin reports inode 0 for every IP socket), which is
/// therefore never recorded and arrives as a new description.
pub fn key_of(fd: &impl AsRawFd) -> Option<Key> {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: the descriptor is borrowed for the duration of the call and
    // the ManuallyDrop keeps the File from closing it.
    let f = std::mem::ManuallyDrop::new(unsafe {
        <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(fd.as_raw_fd())
    });
    f.metadata()
        .ok()
        .filter(|m| m.ino() != 0)
        .map(|m| (m.dev(), m.ino()))
}

/// A description in flight.
enum Held {
    /// One with a host descriptor, which keeps its host object alive.
    Weak(Weak<OpenFile>),
    /// One sent by its stand-in, kept alive here until received.
    Strong(Arc<OpenFile>),
}

/// Descriptions sent from this process, oldest first. Past [`MAX_INFLIGHT`]
/// the oldest are forgotten (a receiver then gets a new description).
static INFLIGHT: Mutex<VecDeque<(Key, Held)>> = Mutex::new(VecDeque::new());

/// Records kept at most.
const MAX_INFLIGHT: usize = 1024;

/// Records `file`, sent as the host object `key`; `strong` for a stand-in.
pub fn register(key: Key, file: &Arc<OpenFile>, strong: bool) {
    let mut q = INFLIGHT.lock().unwrap();
    q.retain(|(_, h)| !matches!(h, Held::Weak(w) if w.strong_count() == 0));
    if q.len() >= MAX_INFLIGHT {
        q.pop_front();
    }
    let held = if strong {
        Held::Strong(file.clone())
    } else {
        Held::Weak(Arc::downgrade(file))
    };
    q.push_back((key, held));
}

/// Forgets the most recent record of `key` (a send that failed).
pub fn unregister(key: Key) {
    let mut q = INFLIGHT.lock().unwrap();
    if let Some(i) = q.iter().rposition(|(k, _)| *k == key) {
        q.remove(i);
    }
}

/// Takes the oldest live description recorded as `key`.
pub fn claim(key: Key) -> Option<Arc<OpenFile>> {
    let mut q = INFLIGHT.lock().unwrap();
    while let Some(i) = q.iter().position(|(k, _)| *k == key) {
        let (_, held) = q.remove(i).unwrap();
        match held {
            Held::Strong(f) => return Some(f),
            Held::Weak(w) => {
                if let Some(f) = w.upgrade() {
                    return Some(f);
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(level: i32, kind: i32, data: &[u8], len: u64) -> Vec<u8> {
        let mut b = len.to_le_bytes().to_vec();
        b.extend_from_slice(&level.to_le_bytes());
        b.extend_from_slice(&kind.to_le_bytes());
        b.extend_from_slice(data);
        b.resize(align(b.len()), 0);
        b
    }

    #[test]
    fn split_follows_cmsg_ok_and_nxthdr() {
        let mut ctl = raw(1, 1, &7i32.to_le_bytes(), 20);
        ctl.extend(raw(0, 2, &[9], 17));
        let m = split(&ctl).unwrap();
        assert_eq!(m.len(), 2);
        assert_eq!(m[0].data, 7i32.to_le_bytes());
        assert_eq!((m[1].level, m[1].kind, m[1].data.clone()), (0, 2, vec![9]));
        // Shorter than a header, or longer than the data left.
        assert_eq!(split(&raw(1, 1, &[], 15)), Err(Errno(EINVAL)));
        assert_eq!(split(&raw(1, 1, &[0; 8], 25)), Err(Errno(EINVAL)));
        // Trailing bytes too short for a header are ignored.
        let mut short = raw(1, 1, &[], 16);
        short.extend_from_slice(&[0xff; 15]);
        assert_eq!(split(&short).unwrap().len(), 1);
        assert!(split(&[]).unwrap().is_empty());
    }

    #[test]
    fn put_truncates_as_put_cmsg() {
        let mut o = Out::new(64);
        o.put(1, 2, &[1; 12]);
        assert_eq!(o.bytes.len(), 32);
        assert_eq!(o.room, 32);
        assert!(!o.truncated);
        // 20 bytes of room for a 28-byte message: cut, flagged.
        let mut o = Out::new(20);
        o.put(1, 2, &[1; 12]);
        assert_eq!(u64::from_le_bytes(o.bytes[..8].try_into().unwrap()), 20);
        assert_eq!((o.bytes.len(), o.room, o.truncated), (20, 0, true));
        // No room for a header.
        let mut o = Out::new(15);
        o.put(1, 2, &[]);
        assert!(o.bytes.is_empty() && o.truncated && o.room == 15);
        assert_eq!(Out::new(16).max_fds(), 0);
        assert_eq!(Out::new(24).max_fds(), 2);
    }

    /// A `struct compat_cmsghdr` message: `len`, then 4-byte padding.
    fn raw32(level: i32, kind: i32, data: &[u8], len: u32) -> Vec<u8> {
        let mut b = len.to_le_bytes().to_vec();
        b.extend_from_slice(&level.to_le_bytes());
        b.extend_from_slice(&kind.to_le_bytes());
        b.extend_from_slice(data);
        b.resize(compat_align(b.len()), 0);
        b
    }

    #[test]
    fn compat_messages_become_kernel_ones() {
        // Two rights messages, one of one descriptor (16 bytes) and one of
        // three (24 bytes, no padding at 4-byte alignment).
        let mut ctl = raw32(1, 1, &5i32.to_le_bytes(), 16);
        let three: Vec<u8> = [6i32, 7, 8].iter().flat_map(|v| v.to_le_bytes()).collect();
        ctl.extend(raw32(1, 1, &three, 24));
        let k = from_compat(&ctl).unwrap();
        let m = split(&k).unwrap();
        assert_eq!(m.len(), 2);
        assert_eq!(m[0].data, 5i32.to_le_bytes());
        assert_eq!(m[1].data, three);
        // The kernel lengths: CMSG_LEN of each, the second at an 8-byte
        // boundary (24 bytes after 20 rounded).
        assert_eq!(u64::from_le_bytes(k[..8].try_into().unwrap()), 20);
        assert_eq!(u64::from_le_bytes(k[24..32].try_into().unwrap()), 28);
        // CMSG_COMPAT_OK, trailing bytes (1 is enough), and nothing at all.
        assert_eq!(from_compat(&raw32(1, 1, &[], 11)), Err(Errno(EINVAL)));
        assert_eq!(from_compat(&raw32(1, 1, &[0; 4], 20)), Err(Errno(EINVAL)));
        let mut tail = raw32(1, 1, &[], 12);
        tail.push(0);
        assert_eq!(from_compat(&tail), Err(Errno(EINVAL)));
        assert_eq!(from_compat(&[0; 11]), Err(Errno(EINVAL)));
    }

    #[test]
    fn put_cmsg_compat_uses_the_32_bit_header() {
        let mut o = Out::compat(64);
        o.put(1, 2, &[1; 5]);
        // A 17-byte message padded to 20.
        assert_eq!(o.bytes.len(), 20);
        assert_eq!(u32::from_le_bytes(o.bytes[..4].try_into().unwrap()), 17);
        assert_eq!(o.room, 44);
        let mut o = Out::compat(15);
        o.put(1, 2, &[1; 4]);
        assert_eq!((o.bytes.len(), o.room, o.truncated), (15, 0, true));
        assert_eq!(Out::compat(12).max_fds(), 0);
        assert_eq!(Out::compat(20).max_fds(), 2);
    }
}
