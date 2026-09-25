//! System V IPC (`ipc/`): the objects every emulated process of a user
//! shares, as the processes of an IPC namespace share them.
//!
//! | Module | Contents |
//! |---|---|
//! | this one | the namespace, identifiers, permissions, `struct ipc64_perm` |
//! | [`shm`] | shared memory segments |
//! | [`sem`] | semaphore sets |
//!
//! The namespace is a directory on the host (by default one per host user
//! under the temporary directory, which a reboot clears as it clears a
//! kernel's IPC objects). Each object type keeps its table there as a text
//! file, read and replaced whole under an exclusive `flock` of the type's
//! lock file, so every process of every guest sees one table and a
//! process that dies mid-change leaves the old one. Objects outlive their
//! creators until removed, as the kernel's do.
//!
//! Identifiers are allocated as `ipc_idr_alloc` allocates them: the next
//! free index after the last one handed out, cycling within
//! `max(in_use * 3 / 2, 64)` indexes (at most `IPCMNI`), the sequence
//! number advancing when the index wraps; an identifier is the sequence
//! number shifted past the index's 15 bits (`IPCMNI_SHIFT`). A process
//! holds `CAP_IPC_OWNER`, `CAP_IPC_LOCK`, and `CAP_SYS_ADMIN` when its
//! effective user is root.

pub mod sem;
pub mod shm;

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

use super::abi::errno::Errno;
use super::abi::errno_table::*;

/// `IPC_PRIVATE`.
pub const IPC_PRIVATE: i32 = 0;
/// `IPC_CREAT`, `IPC_EXCL`, `IPC_NOWAIT`.
pub const IPC_CREAT: i32 = 0o1000;
pub const IPC_EXCL: i32 = 0o2000;
pub const IPC_NOWAIT: i32 = 0o4000;
/// `IPC_RMID`, `IPC_SET`, `IPC_STAT`, `IPC_INFO`.
pub const IPC_RMID: i32 = 0;
pub const IPC_SET: i32 = 1;
pub const IPC_STAT: i32 = 2;
pub const IPC_INFO: i32 = 3;
/// `IPCMNI_SHIFT`: an identifier's index bits.
const IPCMNI_SHIFT: u32 = 15;
/// `IPCMNI`: the most objects of a type.
pub const IPCMNI: u32 = 1 << IPCMNI_SHIFT;
/// `ipc_min_cycle` (`RADIX_TREE_MAP_SIZE`).
const IPC_MIN_CYCLE: u32 = 64;
/// `S_IRWXUGO`.
pub const S_IRWXUGO: u32 = 0o777;
/// `sizeof(struct ipc64_perm)` on the 64-bit ABIs.
pub const IPC64_PERM: usize = 48;

/// The index of identifier `id` (`ipcid_to_idx`).
pub fn idx_of(id: i32) -> u32 {
    (id as u32) & (IPCMNI - 1)
}

/// The sequence number of identifier `id` (`ipcid_to_seqx`).
pub fn seq_of(id: i32) -> u32 {
    (id as u32) >> IPCMNI_SHIFT
}

/// The identifier of index `idx` with sequence number `seq`.
pub fn build_id(idx: u32, seq: u32) -> i32 {
    ((seq << IPCMNI_SHIFT) + idx) as i32
}

/// The caller's credentials, as the IPC checks use them.
#[derive(Clone, Debug)]
pub struct Caller {
    pub pid: i32,
    pub euid: u32,
    pub egid: u32,
    /// Supplementary groups.
    pub groups: Vec<u32>,
}

impl Caller {
    /// Whether the caller holds the capabilities (root).
    pub fn capable(&self) -> bool {
        self.euid == 0
    }

    /// `in_group_p`.
    fn in_group(&self, gid: u32) -> bool {
        gid == self.egid || self.groups.contains(&gid)
    }
}

/// `struct kern_ipc_perm`: what every object has.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Perm {
    pub key: i32,
    pub uid: u32,
    pub gid: u32,
    pub cuid: u32,
    pub cgid: u32,
    /// Permission bits, and the type's state bits above them.
    pub mode: u32,
    pub seq: u32,
}

impl Perm {
    /// A new object's: the caller's effective IDs (`ipc_addid`).
    pub fn new(key: i32, mode: u32, who: &Caller) -> Self {
        Perm {
            key,
            uid: who.euid,
            gid: who.egid,
            cuid: who.euid,
            cgid: who.egid,
            mode,
            seq: 0,
        }
    }

    /// `ipcperms`: whether `who` may have access `flag` (`S_I*UGO` bits).
    pub fn allows(&self, who: &Caller, flag: u32) -> bool {
        let requested = (flag >> 6) | (flag >> 3) | flag;
        let mut granted = self.mode;
        if who.euid == self.cuid || who.euid == self.uid {
            granted >>= 6;
        } else if who.in_group(self.cgid) || who.in_group(self.gid) {
            granted >>= 3;
        }
        requested & !granted & 0o7 == 0 || who.capable()
    }

    /// `ipcctl_obtain_check`'s test: the owner, the creator, or
    /// `CAP_SYS_ADMIN`.
    pub fn owned_by(&self, who: &Caller) -> bool {
        who.euid == self.cuid || who.euid == self.uid || who.capable()
    }

    /// `kernel_to_ipc64_perm`: `struct ipc64_perm` (48 bytes).
    pub fn encode(&self) -> [u8; IPC64_PERM] {
        let mut b = [0u8; IPC64_PERM];
        b[0..4].copy_from_slice(&self.key.to_le_bytes());
        b[4..8].copy_from_slice(&self.uid.to_le_bytes());
        b[8..12].copy_from_slice(&self.gid.to_le_bytes());
        b[12..16].copy_from_slice(&self.cuid.to_le_bytes());
        b[16..20].copy_from_slice(&self.cgid.to_le_bytes());
        b[20..24].copy_from_slice(&self.mode.to_le_bytes());
        b[24..26].copy_from_slice(&(self.seq as u16).to_le_bytes());
        b
    }

    /// `ipc_update_perm` from a guest `struct ipc64_perm`: the owner, the
    /// group, and the permission bits; an invalid ID (-1) is `EINVAL`.
    pub fn update(&mut self, b: &[u8]) -> Result<(), Errno> {
        let uid = u32::from_le_bytes(b[4..8].try_into().unwrap());
        let gid = u32::from_le_bytes(b[8..12].try_into().unwrap());
        let mode = u32::from_le_bytes(b[20..24].try_into().unwrap());
        if uid == u32::MAX || gid == u32::MAX {
            return Err(Errno(EINVAL));
        }
        self.uid = uid;
        self.gid = gid;
        self.mode = (self.mode & !S_IRWXUGO) | (mode & S_IRWXUGO);
        Ok(())
    }

    fn fields(&self) -> String {
        format!(
            "{} {} {} {} {} {} {}",
            self.key, self.uid, self.gid, self.cuid, self.cgid, self.mode, self.seq
        )
    }

    fn parse(f: &mut std::str::SplitWhitespace<'_>) -> Option<Self> {
        Some(Perm {
            key: f.next()?.parse().ok()?,
            uid: f.next()?.parse().ok()?,
            gid: f.next()?.parse().ok()?,
            cuid: f.next()?.parse().ok()?,
            cgid: f.next()?.parse().ok()?,
            mode: f.next()?.parse().ok()?,
            seq: f.next()?.parse().ok()?,
        })
    }
}

/// `struct ipc_ids`: the allocation state of a type's identifiers.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ids {
    /// The index handed out last (-1: none yet).
    pub last_idx: i32,
    /// The current sequence number.
    pub seq: u32,
}

impl Ids {
    /// `ipc_idr_alloc`: an index free among `used`, and its sequence
    /// number; `None` when the cycle has no free index.
    pub fn alloc(&mut self, used: &[u32]) -> Option<(u32, u32)> {
        let max = (used.len() as u32 * 3 / 2).clamp(IPC_MIN_CYCLE, IPCMNI);
        // idr_alloc_cyclic: from the one after the last, wrapping to 0.
        let start = (self.last_idx + 1) as u32;
        let idx = (start..max)
            .chain(0..start.min(max))
            .find(|i| !used.contains(i))?;
        if idx as i32 <= self.last_idx {
            self.seq += 1;
            if self.seq >= (i32::MAX as u32 >> IPCMNI_SHIFT) {
                self.seq = 0;
            }
        }
        self.last_idx = idx as i32;
        Some((idx, self.seq))
    }
}

/// The namespace: a directory shared by every process that names it.
#[derive(Clone, Debug)]
pub struct Namespace {
    dir: PathBuf,
}

impl Namespace {
    /// The namespace in `dir` (made, owner-only, if missing).
    pub fn at(dir: PathBuf) -> Self {
        Namespace { dir }
    }

    /// The default namespace: one per host user under the temporary
    /// directory.
    pub fn default_dir() -> PathBuf {
        // SAFETY: geteuid has no failure mode.
        let uid = unsafe { libc::geteuid() };
        std::env::temp_dir().join(format!("rax-user-ipc-{uid}"))
    }

    /// The directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn ensure(&self) -> Result<(), Errno> {
        use std::os::unix::fs::DirBuilderExt;
        match std::fs::DirBuilder::new().mode(0o700).create(&self.dir) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(e) => Err(Errno::from(e)),
        }
    }

    /// Runs `f` on table `name` under its lock, writing back what `f`
    /// leaves unless it fails.
    pub fn with_table<T, R>(
        &self,
        name: &str,
        f: impl FnOnce(&mut T) -> Result<R, Errno>,
    ) -> Result<R, Errno>
    where
        T: Table,
    {
        self.ensure()?;
        let lock = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.dir.join(format!("{name}.lock")))
            .map_err(Errno::from)?;
        // SAFETY: flock takes the descriptor and an integer operation; the
        // lock is released when `lock` is closed.
        while unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
            if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                return Err(Errno(EIO));
            }
        }
        let path = self.dir.join(format!("{name}.table"));
        let mut text = String::new();
        match File::open(&path) {
            Ok(mut file) => {
                file.read_to_string(&mut text).map_err(Errno::from)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(Errno::from(e)),
        }
        let mut table = T::parse(&text);
        let before = table.clone();
        let r = f(&mut table)?;
        if table != before {
            let tmp = self
                .dir
                .join(format!("{name}.table.{}", std::process::id()));
            let mut out = File::create(&tmp).map_err(Errno::from)?;
            out.write_all(table.render().as_bytes())
                .map_err(Errno::from)?;
            std::fs::rename(&tmp, &path).map_err(Errno::from)?;
        }
        drop(lock);
        Ok(r)
    }
}

/// A process's System V IPC state.
#[derive(Debug)]
pub struct IpcState {
    /// Its namespace.
    pub ns: Namespace,
    /// How many mappings of each segment it last published.
    pub shm_published: BTreeMap<i32, u32>,
    /// Whether it has semaphore undo adjustments (`current->sysvsem`).
    pub sem_undo: bool,
}

impl IpcState {
    /// The state of a process in the namespace at `dir` (the default one
    /// without).
    pub fn new(dir: Option<PathBuf>) -> Self {
        IpcState {
            ns: Namespace::at(dir.unwrap_or_else(Namespace::default_dir)),
            shm_published: BTreeMap::new(),
            sem_undo: false,
        }
    }
}

/// A type's table as the namespace stores it.
pub trait Table: Clone + PartialEq {
    /// The table in `text` (an empty one for none).
    fn parse(text: &str) -> Self;
    /// The table as text.
    fn render(&self) -> String;
}

/// Whether process `pid` is alive (a zombie counts as gone to the
/// kernel's IPC, which it no longer holds anything in).
pub fn alive(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    // SAFETY: kill with signal 0 only checks that the process exists.
    let r = unsafe { libc::kill(pid, 0) };
    r == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// The real time in seconds (`ktime_get_real_seconds`).
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caller(euid: u32, egid: u32, groups: &[u32]) -> Caller {
        Caller {
            pid: 1,
            euid,
            egid,
            groups: groups.to_vec(),
        }
    }

    #[test]
    fn identifiers_follow_ipc_idr_alloc() {
        let mut ids = Ids {
            last_idx: -1,
            seq: 0,
        };
        assert_eq!(ids.alloc(&[]), Some((0, 0)));
        assert_eq!(ids.alloc(&[0]), Some((1, 0)));
        // The index after the last, even with a lower one free.
        assert_eq!(ids.alloc(&[1]), Some((2, 0)));
        // Past the cycle (64 while few are used): back to 0, a new
        // sequence number.
        ids.last_idx = 63;
        assert_eq!(ids.alloc(&[]), Some((0, 1)));
        assert_eq!(build_id(0, 1), 32768);
        assert_eq!((idx_of(32769), seq_of(32769)), (1, 1));
        // Every index of the cycle in use.
        let all: Vec<u32> = (0..64).collect();
        let mut full = Ids {
            last_idx: 10,
            seq: 0,
        };
        assert_eq!(full.alloc(&all[..63]), Some((63, 0)));
        let used: Vec<u32> = (0..64).collect();
        // With 64 used the cycle grows to 96.
        assert_eq!(full.alloc(&used), Some((64, 0)));
    }

    #[test]
    fn permissions_follow_ipcperms() {
        let p = Perm {
            key: 5,
            uid: 100,
            gid: 50,
            cuid: 101,
            cgid: 51,
            mode: 0o640,
            seq: 0,
        };
        // Owner (or creator): the user bits.
        assert!(p.allows(&caller(100, 1, &[]), 0o600));
        assert!(p.allows(&caller(101, 1, &[]), 0o400));
        assert!(!p.allows(&caller(100, 1, &[]), 0o700));
        // A group member (by a supplementary group, or the creator's
        // group): the group bits.
        assert!(p.allows(&caller(7, 1, &[50]), 0o444));
        assert!(!p.allows(&caller(7, 1, &[50]), 0o222));
        assert!(p.allows(&caller(7, 51, &[]), 0o040));
        // Others: the other bits (none); root: every access.
        assert!(!p.allows(&caller(7, 9, &[]), 0o004));
        assert!(p.allows(&caller(0, 0, &[]), 0o777));
        assert!(p.owned_by(&caller(101, 0, &[])) && !p.owned_by(&caller(7, 0, &[])));
        let mut q = p.clone();
        let mut b = [0u8; IPC64_PERM];
        b[4..8].copy_from_slice(&7u32.to_le_bytes());
        b[8..12].copy_from_slice(&8u32.to_le_bytes());
        b[20..24].copy_from_slice(&0o7777u32.to_le_bytes());
        q.mode |= 0o1000;
        q.update(&b).unwrap();
        assert_eq!((q.uid, q.gid, q.mode), (7, 8, 0o1777));
        b[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(q.update(&b), Err(Errno(EINVAL)));
        let e = p.encode();
        assert_eq!(i32::from_le_bytes(e[..4].try_into().unwrap()), 5);
        assert_eq!(u32::from_le_bytes(e[20..24].try_into().unwrap()), 0o640);
    }
}
