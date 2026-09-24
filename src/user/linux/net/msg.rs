//! Ancillary data (`struct cmsghdr`, `net/core/scm.c`) and descriptor
//! passing.
//!
//! On the 64-bit ABIs a control message is a 16-byte header (`cmsg_len`
//! as a `size_t`, `cmsg_level`, `cmsg_type`) and its data, each message
//! padded to 8 bytes (`CMSG_ALIGN`).
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

/// Control data being written back to a receiver: the bytes and the room
/// left (`msg_controllen`), and whether anything did not fit
/// (`MSG_CTRUNC`).
#[derive(Debug, Default)]
pub struct Out {
    /// The bytes written so far.
    pub bytes: Vec<u8>,
    /// The room left.
    pub room: usize,
    /// `MSG_CTRUNC`.
    pub truncated: bool,
}

impl Out {
    /// Room for `room` bytes.
    pub fn new(room: usize) -> Self {
        Out {
            bytes: Vec::new(),
            room,
            truncated: false,
        }
    }

    /// `put_cmsg`: the message, cut to the room left (setting
    /// `MSG_CTRUNC`), or nothing when not even a header fits.
    pub fn put(&mut self, level: i32, kind: i32, data: &[u8]) {
        if self.room < HDR {
            self.truncated = true;
            return;
        }
        let mut len = cmsg_len(data.len());
        if self.room < len {
            self.truncated = true;
            len = self.room;
        }
        self.bytes.extend_from_slice(&(len as u64).to_le_bytes());
        self.bytes.extend_from_slice(&level.to_le_bytes());
        self.bytes.extend_from_slice(&kind.to_le_bytes());
        self.bytes.extend_from_slice(&data[..len - HDR]);
        let used = cmsg_space(data.len()).min(self.room);
        self.bytes.resize(self.bytes.len() + (used - len), 0);
        self.room -= used;
    }

    /// `scm_max_fds`: the descriptors the room left can take.
    pub fn max_fds(&self) -> usize {
        if self.room <= HDR {
            0
        } else {
            (self.room - HDR) / 4
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
}
