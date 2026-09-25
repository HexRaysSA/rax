//! System V shared memory segments (`ipc/shm.c`).
//!
//! A segment's pages are a host file in the namespace directory, which
//! every attaching process maps shared, so stores reach every process at
//! once. Attaches are the kernel's: each mapping (VMA) of a segment counts
//! one (`shm_open`, `shm_close`), a fork copies them, `munmap`, `execve`,
//! and exit drop them. A process publishes how many mappings of each
//! segment it has after the calls that change its mappings ([`sync`]);
//! `shm_nattch` is the sum over processes still alive, so a process killed
//! before it could publish its exit stops counting once it is gone. A
//! segment marked for removal (`SHM_DEST`, its key made private) goes when
//! its last attach does.

use std::collections::BTreeMap;
use std::path::PathBuf;

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::{
    Caller, IPC_CREAT, IPC_EXCL, IPC_PRIVATE, IPCMNI, Ids, Namespace, Perm, Table, alive, build_id,
    idx_of, now, seq_of,
};

/// `SHMMIN`, `SHMMNI`, `SHMMAX`, `SHMALL` (the defaults of `shm_init_ns`).
pub const SHMMIN: u64 = 1;
pub const SHMMNI: u32 = 4096;
pub const SHMMAX: u64 = u64::MAX - (1 << 24);
pub const SHMALL: u64 = u64::MAX - (1 << 24);
/// `SHM_DEST`, `SHM_LOCKED`: state bits of the mode.
pub const SHM_DEST: u32 = 0o1000;
pub const SHM_LOCKED: u32 = 0o2000;
/// `shmget` flags.
pub const SHM_HUGETLB: i32 = 0o4000;
/// `SHM_HUGE_SHIFT`, `SHM_HUGE_MASK` (`HUGETLB_FLAG_ENCODE_*`).
const SHM_HUGE_SHIFT: u32 = 26;
const SHM_HUGE_MASK: i32 = 0x3F;
/// `shmat` flags.
pub const SHM_RDONLY: i32 = 0o10000;
pub const SHM_RND: i32 = 0o20000;
pub const SHM_REMAP: i32 = 0o40000;
pub const SHM_EXEC: i32 = 0o100000;
/// `shmctl` commands.
pub const SHM_LOCK: i32 = 11;
pub const SHM_UNLOCK: i32 = 12;
pub const SHM_STAT: i32 = 13;
pub const SHM_INFO: i32 = 14;
pub const SHM_STAT_ANY: i32 = 15;
/// `sizeof(struct shmid64_ds)` on the 64-bit ABIs.
pub const SHMID64_DS: usize = 112;
/// `sizeof(struct shminfo64)`, `sizeof(struct shm_info)`.
pub const SHMINFO64: usize = 72;
pub const SHM_INFO_SIZE: usize = 48;
/// The table's name in the namespace.
const TABLE: &str = "shm";

const PAGE_SIZE: u64 = 4096;

/// A segment (`struct shmid_kernel`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Segment {
    pub idx: u32,
    pub perm: Perm,
    pub segsz: u64,
    pub atime: i64,
    pub dtime: i64,
    pub ctime: i64,
    pub cpid: i32,
    pub lpid: i32,
    /// The host file of its pages, in the namespace directory.
    pub file: String,
    /// The processes with mappings of it, and how many each has.
    pub attachers: Vec<(i32, u32)>,
}

impl Segment {
    /// Its identifier.
    pub fn id(&self) -> i32 {
        build_id(self.idx, self.perm.seq)
    }

    /// `shm_nattch`: the mappings of the processes still alive.
    pub fn nattch(&self) -> u64 {
        self.attachers
            .iter()
            .filter(|(pid, _)| alive(*pid))
            .map(|&(_, n)| u64::from(n))
            .sum()
    }

    fn pages(&self) -> u64 {
        self.segsz.div_ceil(PAGE_SIZE)
    }

    /// `struct shmid64_ds`.
    pub fn encode(&self) -> [u8; SHMID64_DS] {
        let mut b = [0u8; SHMID64_DS];
        b[..super::IPC64_PERM].copy_from_slice(&self.perm.encode());
        b[48..56].copy_from_slice(&self.segsz.to_le_bytes());
        b[56..64].copy_from_slice(&self.atime.to_le_bytes());
        b[64..72].copy_from_slice(&self.dtime.to_le_bytes());
        b[72..80].copy_from_slice(&self.ctime.to_le_bytes());
        b[80..84].copy_from_slice(&self.cpid.to_le_bytes());
        b[84..88].copy_from_slice(&self.lpid.to_le_bytes());
        b[88..96].copy_from_slice(&self.nattch().to_le_bytes());
        b
    }
}

/// The segments of a namespace (`shm_ids`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShmTable {
    pub ids: Ids,
    pub segs: Vec<Segment>,
}

impl Table for ShmTable {
    fn parse(text: &str) -> Self {
        let mut t = ShmTable {
            ids: Ids {
                last_idx: -1,
                seq: 0,
            },
            segs: Vec::new(),
        };
        for line in text.lines() {
            let mut f = line.split_whitespace();
            match f.next() {
                Some("ids") => {
                    if let (Some(Ok(last)), Some(Ok(seq))) =
                        (f.next().map(str::parse), f.next().map(str::parse))
                    {
                        t.ids = Ids {
                            last_idx: last,
                            seq,
                        };
                    }
                }
                Some("seg") => {
                    if let Some(s) = parse_segment(&mut f) {
                        t.segs.push(s);
                    }
                }
                _ => {}
            }
        }
        t
    }

    fn render(&self) -> String {
        let mut out = format!("ids {} {}\n", self.ids.last_idx, self.ids.seq);
        for s in &self.segs {
            out.push_str(&format!(
                "seg {} {} {} {} {} {} {} {} {} {}",
                s.idx,
                s.perm.fields(),
                s.segsz,
                s.atime,
                s.dtime,
                s.ctime,
                s.cpid,
                s.lpid,
                s.file,
                s.attachers.len()
            ));
            for (pid, n) in &s.attachers {
                out.push_str(&format!(" {pid}:{n}"));
            }
            out.push('\n');
        }
        out
    }
}

fn parse_segment(f: &mut std::str::SplitWhitespace<'_>) -> Option<Segment> {
    let idx = f.next()?.parse().ok()?;
    let perm = Perm::parse(f)?;
    let mut s = Segment {
        idx,
        perm,
        segsz: f.next()?.parse().ok()?,
        atime: f.next()?.parse().ok()?,
        dtime: f.next()?.parse().ok()?,
        ctime: f.next()?.parse().ok()?,
        cpid: f.next()?.parse().ok()?,
        lpid: f.next()?.parse().ok()?,
        file: f.next()?.to_string(),
        attachers: Vec::new(),
    };
    let n: usize = f.next()?.parse().ok()?;
    for _ in 0..n {
        let (pid, count) = f.next()?.split_once(':')?;
        s.attachers.push((pid.parse().ok()?, count.parse().ok()?));
    }
    Some(s)
}

impl ShmTable {
    /// The segment of identifier `id`, checking its sequence number
    /// (`shm_obtain_object_check`): `EINVAL` for none.
    fn by_id(&mut self, id: i32) -> Result<&mut Segment, Errno> {
        let (idx, seq) = (idx_of(id), seq_of(id));
        self.segs
            .iter_mut()
            .find(|s| s.idx == idx && s.perm.seq == seq)
            .ok_or(Errno(EINVAL))
    }

    /// `shm_tot`: the pages of every segment.
    fn total_pages(&self) -> u64 {
        self.segs.iter().map(Segment::pages).sum()
    }

    /// `ipc_get_maxidx`: the highest index in use, 0 for none.
    fn max_idx(&self) -> i32 {
        self.segs.iter().map(|s| s.idx as i32).max().unwrap_or(0)
    }

    /// Removes the segments marked for removal that no living process
    /// maps any more, and forgets the attaches of processes gone.
    fn collect(&mut self, ns: &Namespace) {
        for s in &mut self.segs {
            s.attachers.retain(|&(pid, n)| n > 0 && alive(pid));
        }
        let dir = ns.dir().to_path_buf();
        self.segs.retain(|s| {
            let dead = s.perm.mode & SHM_DEST != 0 && s.attachers.is_empty();
            if dead {
                let _ = std::fs::remove_file(dir.join(&s.file));
            }
            !dead
        });
    }
}

/// What a caller attaches: the segment's host file and size.
#[derive(Clone, Debug)]
pub struct Attach {
    pub id: i32,
    pub key: i32,
    pub path: PathBuf,
    pub segsz: u64,
}

/// `shmget` (`ksys_shmget`, `ipcget`, `newseg`).
pub fn get(ns: &Namespace, key: i32, size: u64, flags: i32, who: &Caller) -> Result<i32, Errno> {
    ns.with_table::<ShmTable, _>(TABLE, |t| {
        t.collect(ns);
        if key != IPC_PRIVATE
            && let Some(s) = t.segs.iter().find(|s| s.perm.key == key)
        {
            if flags & IPC_CREAT != 0 && flags & IPC_EXCL != 0 {
                return Err(Errno(EEXIST));
            }
            // shm_more_checks, then ipc_check_perms.
            if s.segsz < size {
                return Err(Errno(EINVAL));
            }
            if !s.perm.allows(who, flags as u16 as u32) {
                return Err(Errno(EACCES));
            }
            return Ok(s.id());
        }
        if key != IPC_PRIVATE && flags & IPC_CREAT == 0 {
            return Err(Errno(ENOENT));
        }
        newseg(ns, t, key, size, flags, who)
    })
}

/// `newseg`.
fn newseg(
    ns: &Namespace,
    t: &mut ShmTable,
    key: i32,
    size: u64,
    flags: i32,
    who: &Caller,
) -> Result<i32, Errno> {
    if !(SHMMIN..=SHMMAX).contains(&size) {
        return Err(Errno(EINVAL));
    }
    let pages = size.div_ceil(PAGE_SIZE);
    if t.total_pages()
        .checked_add(pages)
        .is_none_or(|n| n > SHMALL)
    {
        return Err(Errno(ENOSPC));
    }
    if flags & SHM_HUGETLB != 0 {
        // hugetlb_file_setup: the default or a supported huge page size
        // has no pages reserved (vm.nr_hugepages = 0); others are unknown.
        let log = (flags >> SHM_HUGE_SHIFT) & SHM_HUGE_MASK;
        return Err(Errno(if matches!(log, 0 | 21 | 30) {
            ENOMEM
        } else {
            EINVAL
        }));
    }
    // ipc_addid.
    if t.segs.len() as u32 >= SHMMNI.min(IPCMNI) {
        return Err(Errno(ENOSPC));
    }
    let used: Vec<u32> = t.segs.iter().map(|s| s.idx).collect();
    let (idx, seq) = t.ids.alloc(&used).ok_or(Errno(ENOSPC))?;
    let file = format!("shm-{idx}-{seq}-{}-{}", who.pid, now_nanos());
    let path = ns.dir().join(&file);
    let host = std::fs::File::options()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|_| Errno(ENOMEM))?;
    host.set_len(size).map_err(|_| Errno(ENOSPC))?;
    let mut perm = Perm::new(key, flags as u32 & super::S_IRWXUGO, who);
    perm.seq = seq;
    let s = Segment {
        idx,
        perm,
        segsz: size,
        atime: 0,
        dtime: 0,
        ctime: now(),
        cpid: who.pid,
        lpid: 0,
        file,
        attachers: Vec::new(),
    };
    let id = s.id();
    t.segs.push(s);
    Ok(id)
}

fn now_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos())
}

/// `do_shmat`'s lookup and permission check for access `acc_mode`
/// (`S_I*UGO` bits): the segment to map.
pub fn lookup_for_attach(
    ns: &Namespace,
    id: i32,
    acc_mode: u32,
    who: &Caller,
) -> Result<Attach, Errno> {
    ns.with_table::<ShmTable, _>(TABLE, |t| {
        let dir = ns.dir().to_path_buf();
        let s = t.by_id(id)?;
        if !s.perm.allows(who, acc_mode) {
            return Err(Errno(EACCES));
        }
        Ok(Attach {
            id,
            key: s.perm.key,
            path: dir.join(&s.file),
            segsz: s.segsz,
        })
    })
}

/// Publishes that process `pid` now has `now` mappings of each segment
/// (and none of the others it had, `before`): an increase is an attach
/// (`shm_open`: the attach time and last process), a decrease a detach
/// (`shm_close`: the detach time and last process); a segment marked for
/// removal goes with its last attach.
pub fn publish(
    ns: &Namespace,
    pid: i32,
    before: &BTreeMap<i32, u32>,
    now_counts: &BTreeMap<i32, u32>,
) -> Result<(), Errno> {
    ns.with_table::<ShmTable, _>(TABLE, |t| {
        let ids: Vec<i32> = before.keys().chain(now_counts.keys()).copied().collect();
        let stamp = now();
        for id in ids {
            let Ok(s) = t.by_id(id) else { continue };
            let old = s
                .attachers
                .iter()
                .find(|(p, _)| *p == pid)
                .map_or(0, |&(_, n)| n);
            let new = now_counts.get(&id).copied().unwrap_or(0);
            if new == old {
                continue;
            }
            if new > old {
                s.atime = stamp;
            } else {
                s.dtime = stamp;
            }
            s.lpid = pid;
            s.attachers.retain(|(p, _)| *p != pid);
            if new > 0 {
                s.attachers.push((pid, new));
            }
        }
        t.collect(ns);
        Ok(())
    })
}

/// `shmctl`'s `IPC_STAT`, `SHM_STAT`, and `SHM_STAT_ANY` (`shmctl_stat`):
/// the `struct shmid64_ds` and the call's result (0, or for the `SHM_STAT`
/// forms, which take an index, the identifier).
pub fn stat(
    ns: &Namespace,
    id: i32,
    cmd: i32,
    who: &Caller,
) -> Result<([u8; SHMID64_DS], i32), Errno> {
    ns.with_table::<ShmTable, _>(TABLE, |t| {
        t.collect(ns);
        let s = if cmd == super::IPC_STAT {
            t.by_id(id)?
        } else {
            // shm_obtain_object: by index, whatever the sequence number.
            let idx = idx_of(id);
            t.segs
                .iter_mut()
                .find(|s| s.idx == idx)
                .ok_or(Errno(EINVAL))?
        };
        if cmd != SHM_STAT_ANY && !s.perm.allows(who, 0o444) {
            return Err(Errno(EACCES));
        }
        let r = if cmd == super::IPC_STAT { 0 } else { s.id() };
        Ok((s.encode(), r))
    })
}

/// `IPC_INFO` (`shmctl_ipc_info`): `struct shminfo64` and the highest
/// index in use.
pub fn ipc_info(ns: &Namespace) -> Result<([u8; SHMINFO64], i32), Errno> {
    ns.with_table::<ShmTable, _>(TABLE, |t| {
        t.collect(ns);
        let mut b = [0u8; SHMINFO64];
        b[0..8].copy_from_slice(&SHMMAX.to_le_bytes());
        b[8..16].copy_from_slice(&SHMMIN.to_le_bytes());
        b[16..24].copy_from_slice(&u64::from(SHMMNI).to_le_bytes());
        b[24..32].copy_from_slice(&u64::from(SHMMNI).to_le_bytes());
        b[32..40].copy_from_slice(&SHMALL.to_le_bytes());
        Ok((b, t.max_idx()))
    })
}

/// `SHM_INFO` (`shmctl_shm_info`): `struct shm_info` and the highest
/// index in use. Resident pages are the host files' allocated blocks.
pub fn shm_info(ns: &Namespace) -> Result<([u8; SHM_INFO_SIZE], i32), Errno> {
    use std::os::unix::fs::MetadataExt;
    ns.with_table::<ShmTable, _>(TABLE, |t| {
        t.collect(ns);
        let rss: u64 = t
            .segs
            .iter()
            .filter_map(|s| std::fs::metadata(ns.dir().join(&s.file)).ok())
            .map(|m| (m.blocks() * 512).div_ceil(PAGE_SIZE))
            .sum();
        let mut b = [0u8; SHM_INFO_SIZE];
        b[0..4].copy_from_slice(&(t.segs.len() as i32).to_le_bytes());
        b[8..16].copy_from_slice(&t.total_pages().to_le_bytes());
        b[16..24].copy_from_slice(&rss.to_le_bytes());
        Ok((b, t.max_idx()))
    })
}

/// `IPC_SET` (`shmctl_down`): the owner, group, and permissions from the
/// guest's `struct ipc64_perm`.
pub fn set(ns: &Namespace, id: i32, perm: &[u8], who: &Caller) -> Result<(), Errno> {
    ns.with_table::<ShmTable, _>(TABLE, |t| {
        let s = t.by_id(id)?;
        if !s.perm.owned_by(who) {
            return Err(Errno(EPERM));
        }
        s.perm.update(perm)?;
        s.ctime = now();
        Ok(())
    })
}

/// `IPC_RMID` (`do_shm_rmid`): removed now if nothing maps it, else
/// marked (`SHM_DEST`) and its key made private.
pub fn rmid(ns: &Namespace, id: i32, who: &Caller) -> Result<(), Errno> {
    ns.with_table::<ShmTable, _>(TABLE, |t| {
        let s = t.by_id(id)?;
        if !s.perm.owned_by(who) {
            return Err(Errno(EPERM));
        }
        s.perm.mode |= SHM_DEST;
        s.perm.key = IPC_PRIVATE;
        t.collect(ns);
        Ok(())
    })
}

/// `SHM_LOCK` and `SHM_UNLOCK` (`shmctl_do_lock`): the owner (or
/// `CAP_IPC_LOCK`), and for locking a memory-lock limit, set the
/// `SHM_LOCKED` bit; pages stay where the host keeps them.
pub fn lock(ns: &Namespace, id: i32, cmd: i32, who: &Caller, memlock: u64) -> Result<(), Errno> {
    ns.with_table::<ShmTable, _>(TABLE, |t| {
        let s = t.by_id(id)?;
        if !who.capable() {
            if who.euid != s.perm.uid && who.euid != s.perm.cuid {
                return Err(Errno(EPERM));
            }
            if cmd == SHM_LOCK && memlock == 0 {
                return Err(Errno(EPERM));
            }
        }
        if cmd == SHM_LOCK {
            s.perm.mode |= SHM_LOCKED;
        } else {
            s.perm.mode &= !SHM_LOCKED;
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ns(tag: &str) -> Namespace {
        let d = std::env::temp_dir().join(format!("rax-ipc-shm-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        Namespace::at(d)
    }

    fn me(euid: u32) -> Caller {
        Caller {
            pid: std::process::id() as i32,
            euid,
            egid: euid,
            groups: Vec::new(),
        }
    }

    #[test]
    fn segments_follow_shmget() {
        let n = ns("get");
        let who = me(1000);
        let a = get(&n, IPC_PRIVATE, 100, 0o600, &who).unwrap();
        let b = get(&n, IPC_PRIVATE, 100, 0o600, &who).unwrap();
        assert_eq!((a, b), (0, 1));
        assert_eq!(get(&n, IPC_PRIVATE, 0, 0o600, &who), Err(Errno(EINVAL)));
        assert_eq!(get(&n, 42, 10, 0o600, &who), Err(Errno(ENOENT)));
        let k = get(&n, 42, 10, IPC_CREAT | 0o640, &who).unwrap();
        assert_eq!(get(&n, 42, 5, 0, &who), Ok(k));
        assert_eq!(get(&n, 42, 11, 0, &who), Err(Errno(EINVAL)));
        assert_eq!(
            get(&n, 42, 10, IPC_CREAT | IPC_EXCL | 0o600, &who),
            Err(Errno(EEXIST))
        );
        // Another user: the other bits (none).
        assert_eq!(get(&n, 42, 10, 0o004, &me(7)), Err(Errno(EACCES)));
        assert_eq!(get(&n, 42, 10, 0, &me(7)), Ok(k));
        assert_eq!(
            get(&n, IPC_PRIVATE, 4096, SHM_HUGETLB | 0o600, &who),
            Err(Errno(ENOMEM))
        );
        let (ds, r) = stat(&n, k, super::super::IPC_STAT, &who).unwrap();
        assert_eq!(r, 0);
        assert_eq!(i32::from_le_bytes(ds[..4].try_into().unwrap()), 42);
        assert_eq!(u32::from_le_bytes(ds[20..24].try_into().unwrap()), 0o640);
        assert_eq!(u64::from_le_bytes(ds[48..56].try_into().unwrap()), 10);
        assert_eq!(i32::from_le_bytes(ds[80..84].try_into().unwrap()), who.pid);
        // SHM_STAT takes an index and returns the identifier.
        assert_eq!(stat(&n, 2, SHM_STAT, &who).unwrap().1, k);
        assert_eq!(
            stat(&n, k + IPCMNI as i32, super::super::IPC_STAT, &who).err(),
            Some(Errno(EINVAL))
        );
        let _ = std::fs::remove_dir_all(n.dir());
    }

    #[test]
    fn attaches_and_removal_follow_shm_open_and_shm_close() {
        let n = ns("attach");
        let who = me(1000);
        let id = get(&n, 7, 8192, IPC_CREAT | 0o600, &who).unwrap();
        let nattch = |n: &Namespace| {
            let (ds, _) = stat(n, id, super::super::IPC_STAT, &who).unwrap();
            u64::from_le_bytes(ds[88..96].try_into().unwrap())
        };
        let none = BTreeMap::new();
        let two = BTreeMap::from([(id, 2)]);
        publish(&n, who.pid, &none, &two).unwrap();
        assert_eq!(nattch(&n), 2);
        // A dead process's attaches do not count.
        let gone = BTreeMap::from([(id, 1)]);
        publish(&n, 999_999_999, &none, &gone).unwrap();
        assert_eq!(nattch(&n), 2);
        // Removal while attached: marked, its key private.
        rmid(&n, id, &who).unwrap();
        let (ds, _) = stat(&n, id, super::super::IPC_STAT, &who).unwrap();
        assert_eq!(i32::from_le_bytes(ds[..4].try_into().unwrap()), IPC_PRIVATE);
        assert_eq!(
            u32::from_le_bytes(ds[20..24].try_into().unwrap()) & SHM_DEST,
            SHM_DEST
        );
        assert_eq!(get(&n, 7, 1, 0, &who), Err(Errno(ENOENT)));
        // The last detach removes it, and its file.
        let path = lookup_for_attach(&n, id, 0o444, &who).unwrap().path;
        publish(&n, who.pid, &two, &none).unwrap();
        assert_eq!(
            stat(&n, id, super::super::IPC_STAT, &who).err(),
            Some(Errno(EINVAL))
        );
        assert!(!path.exists());
        // Ownership for changes.
        let id = get(&n, IPC_PRIVATE, 1, 0o600, &who).unwrap();
        assert_eq!(rmid(&n, id, &me(7)), Err(Errno(EPERM)));
        assert_eq!(lock(&n, id, SHM_LOCK, &who, 0), Err(Errno(EPERM)));
        lock(&n, id, SHM_LOCK, &who, 65536).unwrap();
        let mut perm = [0u8; super::super::IPC64_PERM];
        perm[4..8].copy_from_slice(&5u32.to_le_bytes());
        perm[20..24].copy_from_slice(&0o644u32.to_le_bytes());
        set(&n, id, &perm, &who).unwrap();
        let (ds, _) = stat(&n, id, super::super::IPC_STAT, &who).unwrap();
        assert_eq!(
            u32::from_le_bytes(ds[20..24].try_into().unwrap()),
            0o644 | SHM_LOCKED
        );
        assert_eq!(u32::from_le_bytes(ds[4..8].try_into().unwrap()), 5);
        rmid(&n, id, &who).unwrap();
        assert_eq!(ipc_info(&n).unwrap().1, 0);
        let _ = std::fs::remove_dir_all(n.dir());
    }
}
