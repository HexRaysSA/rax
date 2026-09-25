//! System V semaphore sets (`ipc/sem.c`).
//!
//! A set lives in the namespace's table: its values, each semaphore's last
//! process and operation time, the processes waiting on it, and the undo
//! adjustments (`SEM_UNDO`) of each process. An operation list is applied
//! as `perform_atomic_semop_slow` applies it: each operation in turn on the
//! values the earlier ones left, all of them or none (a range error or an
//! operation that would block undoes the others). A caller that must wait
//! records which operation blocks it (for `GETNCNT` and `GETZCNT`) and
//! tries again, as other processes' operations are not signalled to it;
//! the first to find its operations possible performs them. A process's
//! undo adjustments are applied at its exit (`exit_sem`), or, if it was
//! killed, when the table is next read after it is gone.

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::{
    Caller, IPC_CREAT, IPC_EXCL, IPC_NOWAIT, IPC_PRIVATE, IPCMNI, Ids, Namespace, Perm, Table,
    alive, build_id, idx_of, now, seq_of,
};

/// `SEMMSL`, `SEMMNS`, `SEMOPM`, `SEMMNI`, `SEMVMX`, `SEMAEM`, and the
/// informational `SEMMNU`, `SEMMAP`, `SEMUME`, `SEMUSZ` (`linux/sem.h`).
pub const SEMMSL: i32 = 32000;
pub const SEMMNI: u32 = 32000;
pub const SEMMNS: i64 = SEMMNI as i64 * SEMMSL as i64;
pub const SEMOPM: u32 = 500;
pub const SEMVMX: i32 = 32767;
pub const SEMAEM: i32 = SEMVMX;
const SEMUME: i32 = SEMOPM as i32;
const SEMUSZ: i32 = 20;
/// `SEM_UNDO`.
pub const SEM_UNDO: i16 = 0x1000;
/// `semctl` commands.
pub const GETPID: i32 = 11;
pub const GETVAL: i32 = 12;
pub const GETALL: i32 = 13;
pub const GETNCNT: i32 = 14;
pub const GETZCNT: i32 = 15;
pub const SETVAL: i32 = 16;
pub const SETALL: i32 = 17;
pub const SEM_STAT: i32 = 18;
pub const SEM_INFO: i32 = 19;
pub const SEM_STAT_ANY: i32 = 20;
/// `sizeof(struct seminfo)`.
pub const SEMINFO: usize = 40;
const TABLE: &str = "sem";

/// One `struct sembuf`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SemBuf {
    pub num: u16,
    pub op: i16,
    pub flg: i16,
}

/// A semaphore (`struct sem`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sem {
    pub val: i32,
    pub pid: i32,
    pub otime: i64,
}

/// A process waiting on a set: the semaphore its blocking operation is on,
/// and whether that operation waits for zero.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Waiter {
    pub pid: i32,
    pub tid: i32,
    pub num: u16,
    pub zero: bool,
}

/// A set (`struct sem_array`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SemSet {
    pub idx: u32,
    pub perm: Perm,
    pub ctime: i64,
    pub sems: Vec<Sem>,
    pub waiters: Vec<Waiter>,
    /// Each process's undo adjustments (`struct sem_undo`).
    pub undos: Vec<(i32, Vec<i32>)>,
}

impl SemSet {
    pub fn id(&self) -> i32 {
        build_id(self.idx, self.perm.seq)
    }

    /// `get_semotime`: the latest operation time of any semaphore.
    fn otime(&self) -> i64 {
        self.sems.iter().map(|s| s.otime).max().unwrap_or(0)
    }

    /// `struct semid64_ds`, whose x86-64 form keeps a word of padding after
    /// each time.
    pub fn encode(&self, x86_64: bool) -> Vec<u8> {
        let mut b = self.perm.encode().to_vec();
        let word = |b: &mut Vec<u8>, v: i64| b.extend_from_slice(&v.to_le_bytes());
        word(&mut b, self.otime());
        if x86_64 {
            word(&mut b, 0);
        }
        word(&mut b, self.ctime);
        if x86_64 {
            word(&mut b, 0);
        }
        word(&mut b, self.sems.len() as i64);
        word(&mut b, 0);
        word(&mut b, 0);
        b
    }

    /// `count_semcnt`: the waiting processes still alive whose blocking
    /// operation is on `num` and waits for zero (`zero`) or for an
    /// increase.
    fn count(&self, num: u16, zero: bool) -> i32 {
        self.waiters
            .iter()
            .filter(|w| w.num == num && w.zero == zero && alive(w.pid))
            .count() as i32
    }

    fn undo_of(&mut self, pid: i32) -> &mut Vec<i32> {
        let n = self.sems.len();
        if let Some(i) = self.undos.iter().position(|(p, _)| *p == pid) {
            return &mut self.undos[i].1;
        }
        self.undos.push((pid, vec![0; n]));
        &mut self.undos.last_mut().unwrap().1
    }

    /// `exit_sem` for process `pid`: its adjustments added to the values,
    /// clamped to `0..=SEMVMX`.
    fn apply_undo(&mut self, pid: i32) {
        let Some(i) = self.undos.iter().position(|(p, _)| *p == pid) else {
            return;
        };
        let (_, adj) = self.undos.remove(i);
        if adj.iter().all(|&a| a == 0) {
            return;
        }
        for (s, a) in self.sems.iter_mut().zip(adj) {
            if a != 0 {
                s.val = (s.val + a).clamp(0, SEMVMX);
                s.pid = pid;
            }
        }
        self.sems[0].otime = now();
    }
}

/// The sets of a namespace (`sem_ids`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SemTable {
    pub ids: Ids,
    pub sets: Vec<SemSet>,
}

impl Table for SemTable {
    fn parse(text: &str) -> Self {
        let mut t = SemTable {
            ids: Ids {
                last_idx: -1,
                seq: 0,
            },
            sets: Vec::new(),
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
                Some("set") => {
                    if let Some(s) = parse_set(&mut f) {
                        t.sets.push(s);
                    }
                }
                _ => {}
            }
        }
        t
    }

    fn render(&self) -> String {
        let mut out = format!("ids {} {}\n", self.ids.last_idx, self.ids.seq);
        for s in &self.sets {
            out.push_str(&format!(
                "set {} {} {} {}",
                s.idx,
                s.perm.fields(),
                s.ctime,
                s.sems.len()
            ));
            for m in &s.sems {
                out.push_str(&format!(" {}:{}:{}", m.val, m.pid, m.otime));
            }
            out.push_str(&format!(" {}", s.waiters.len()));
            for w in &s.waiters {
                out.push_str(&format!(
                    " {}:{}:{}:{}",
                    w.pid,
                    w.tid,
                    w.num,
                    u8::from(w.zero)
                ));
            }
            out.push_str(&format!(" {}", s.undos.len()));
            for (pid, adj) in &s.undos {
                let a: Vec<String> = adj.iter().map(i32::to_string).collect();
                out.push_str(&format!(" {pid}={}", a.join(",")));
            }
            out.push('\n');
        }
        out
    }
}

fn parse_set(f: &mut std::str::SplitWhitespace<'_>) -> Option<SemSet> {
    let idx = f.next()?.parse().ok()?;
    let perm = Perm::parse(f)?;
    let ctime = f.next()?.parse().ok()?;
    let n: usize = f.next()?.parse().ok()?;
    let mut sems = Vec::with_capacity(n);
    for _ in 0..n {
        let mut p = f.next()?.split(':');
        sems.push(Sem {
            val: p.next()?.parse().ok()?,
            pid: p.next()?.parse().ok()?,
            otime: p.next()?.parse().ok()?,
        });
    }
    let nw: usize = f.next()?.parse().ok()?;
    let mut waiters = Vec::with_capacity(nw);
    for _ in 0..nw {
        let mut p = f.next()?.split(':');
        waiters.push(Waiter {
            pid: p.next()?.parse().ok()?,
            tid: p.next()?.parse().ok()?,
            num: p.next()?.parse().ok()?,
            zero: p.next()? == "1",
        });
    }
    let nu: usize = f.next()?.parse().ok()?;
    let mut undos = Vec::with_capacity(nu);
    for _ in 0..nu {
        let (pid, adj) = f.next()?.split_once('=')?;
        let adj: Option<Vec<i32>> = adj.split(',').map(|a| a.parse().ok()).collect();
        undos.push((pid.parse().ok()?, adj?));
    }
    Some(SemSet {
        idx,
        perm,
        ctime,
        sems,
        waiters,
        undos,
    })
}

impl SemTable {
    /// `sem_obtain_object_check`.
    fn by_id(&mut self, id: i32) -> Result<&mut SemSet, Errno> {
        let (idx, seq) = (idx_of(id), seq_of(id));
        self.sets
            .iter_mut()
            .find(|s| s.idx == idx && s.perm.seq == seq)
            .ok_or(Errno(EINVAL))
    }

    fn used_sems(&self) -> i64 {
        self.sets.iter().map(|s| s.sems.len() as i64).sum()
    }

    fn max_idx(&self) -> i32 {
        self.sets.iter().map(|s| s.idx as i32).max().unwrap_or(0)
    }

    /// Applies the undo adjustments of processes gone, and forgets their
    /// waits.
    fn collect(&mut self) {
        for s in &mut self.sets {
            s.waiters.retain(|w| alive(w.pid));
            let dead: Vec<i32> = s
                .undos
                .iter()
                .map(|(p, _)| *p)
                .filter(|p| !alive(*p))
                .collect();
            for pid in dead {
                s.apply_undo(pid);
            }
        }
    }
}

/// `semget` (`ksys_semget`, `ipcget`, `newary`).
pub fn get(ns: &Namespace, key: i32, nsems: i32, flags: i32, who: &Caller) -> Result<i32, Errno> {
    if !(0..=SEMMSL).contains(&nsems) {
        return Err(Errno(EINVAL));
    }
    ns.with_table::<SemTable, _>(TABLE, |t| {
        t.collect();
        if key != IPC_PRIVATE
            && let Some(s) = t.sets.iter().find(|s| s.perm.key == key)
        {
            if flags & IPC_CREAT != 0 && flags & IPC_EXCL != 0 {
                return Err(Errno(EEXIST));
            }
            if nsems as usize > s.sems.len() {
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
        // newary.
        if nsems == 0 {
            return Err(Errno(EINVAL));
        }
        if t.used_sems() + i64::from(nsems) > SEMMNS {
            return Err(Errno(ENOSPC));
        }
        if t.sets.len() as u32 >= SEMMNI.min(IPCMNI) {
            return Err(Errno(ENOSPC));
        }
        let used: Vec<u32> = t.sets.iter().map(|s| s.idx).collect();
        let (idx, seq) = t.ids.alloc(&used).ok_or(Errno(ENOSPC))?;
        let mut perm = Perm::new(key, flags as u32 & super::S_IRWXUGO, who);
        perm.seq = seq;
        let s = SemSet {
            idx,
            perm,
            ctime: now(),
            sems: vec![
                Sem {
                    val: 0,
                    pid: 0,
                    otime: 0,
                };
                nsems as usize
            ],
            waiters: Vec::new(),
            undos: Vec::new(),
        };
        let id = s.id();
        t.sets.push(s);
        Ok(id)
    })
}

/// What an attempt at an operation list came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Done.
    Done,
    /// It must wait; the caller is recorded as waiting.
    Wait,
}

/// One attempt at `semtimedop`'s operations `sops` (`__do_semtimedop`
/// after its argument checks) by thread `tid`: `waiting` says whether the
/// caller was already waiting (a set removed meanwhile is then `EIDRM`).
/// A wait the caller gives up must be ended with [`stop_waiting`].
pub fn semop(
    ns: &Namespace,
    id: i32,
    sops: &[SemBuf],
    who: &Caller,
    tid: i32,
    waiting: bool,
) -> Result<Outcome, Errno> {
    ns.with_table::<SemTable, _>(TABLE, |t| {
        t.collect();
        let s = match t.by_id(id) {
            Ok(s) => s,
            Err(_) if waiting => return Err(Errno(EIDRM)),
            Err(e) => return Err(e),
        };
        let max = sops.iter().map(|o| o.num).max().unwrap_or(0);
        if usize::from(max) >= s.sems.len() {
            return Err(Errno(EFBIG));
        }
        let alter = sops.iter().any(|o| o.op != 0);
        if !s.perm.allows(who, if alter { 0o222 } else { 0o444 }) {
            return Err(Errno(EACCES));
        }
        s.waiters.retain(|w| !(w.pid == who.pid && w.tid == tid));
        // perform_atomic_semop_slow.
        let mut vals: Vec<i32> = s.sems.iter().map(|m| m.val).collect();
        let undo_used = sops.iter().any(|o| o.flg & SEM_UNDO != 0);
        let mut adj = if undo_used {
            s.undo_of(who.pid).clone()
        } else {
            Vec::new()
        };
        for o in sops {
            let n = usize::from(o.num);
            let op = i32::from(o.op);
            let v = vals[n];
            let result = v + op;
            if (op == 0 && v != 0) || result < 0 {
                if o.flg as i32 & IPC_NOWAIT != 0 {
                    return Err(Errno(EAGAIN));
                }
                s.waiters.push(Waiter {
                    pid: who.pid,
                    tid,
                    num: o.num,
                    zero: op == 0,
                });
                return Ok(Outcome::Wait);
            }
            if result > SEMVMX {
                return Err(Errno(ERANGE));
            }
            if o.flg & SEM_UNDO != 0 {
                let u = adj[n] - op;
                if !(-SEMAEM - 1..=SEMAEM).contains(&u) {
                    return Err(Errno(ERANGE));
                }
                adj[n] = u;
            }
            vals[n] = result;
        }
        for (m, v) in s.sems.iter_mut().zip(&vals) {
            m.val = *v;
        }
        for o in sops {
            s.sems[usize::from(o.num)].pid = who.pid;
        }
        // set_semotime: the first operation's semaphore.
        s.sems[usize::from(sops[0].num)].otime = now();
        if undo_used {
            *s.undo_of(who.pid) = adj;
        }
        Ok(Outcome::Done)
    })
}

/// Ends thread `tid`'s wait on set `id` (a timeout or a signal).
pub fn stop_waiting(ns: &Namespace, id: i32, pid: i32, tid: i32) {
    let _ = ns.with_table::<SemTable, _>(TABLE, |t| {
        if let Ok(s) = t.by_id(id) {
            s.waiters.retain(|w| !(w.pid == pid && w.tid == tid));
        }
        Ok(())
    });
}

/// `IPC_STAT`, `SEM_STAT`, `SEM_STAT_ANY` (`semctl_stat`).
pub fn stat(
    ns: &Namespace,
    id: i32,
    cmd: i32,
    who: &Caller,
    x86_64: bool,
) -> Result<(Vec<u8>, i32), Errno> {
    ns.with_table::<SemTable, _>(TABLE, |t| {
        t.collect();
        let s = if cmd == super::IPC_STAT {
            t.by_id(id)?
        } else {
            let idx = idx_of(id);
            t.sets
                .iter_mut()
                .find(|s| s.idx == idx)
                .ok_or(Errno(EINVAL))?
        };
        if cmd != SEM_STAT_ANY && !s.perm.allows(who, 0o444) {
            return Err(Errno(EACCES));
        }
        let r = if cmd == super::IPC_STAT { 0 } else { s.id() };
        Ok((s.encode(x86_64), r))
    })
}

/// `IPC_INFO` and `SEM_INFO` (`semctl_info`): `struct seminfo` and the
/// highest index in use.
pub fn info(ns: &Namespace, cmd: i32) -> Result<([u8; SEMINFO], i32), Errno> {
    ns.with_table::<SemTable, _>(TABLE, |t| {
        t.collect();
        let (usz, aem) = if cmd == SEM_INFO {
            (t.sets.len() as i32, t.used_sems() as i32)
        } else {
            (SEMUSZ, SEMAEM)
        };
        // semmap, semmni, semmns, semmnu, semmsl, semopm, semume, semusz,
        // semvmx, semaem.
        let semmns = SEMMNS.min(i64::from(i32::MAX)) as i32;
        let fields = [
            semmns,
            SEMMNI as i32,
            semmns,
            semmns,
            SEMMSL,
            SEMOPM as i32,
            SEMUME,
            usz,
            SEMVMX,
            aem,
        ];
        let mut b = [0u8; SEMINFO];
        for (i, v) in fields.iter().enumerate() {
            b[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
        }
        Ok((b, t.max_idx()))
    })
}

/// `GETVAL`, `GETPID`, `GETNCNT`, `GETZCNT`, and `GETALL` (`semctl_main`):
/// the value (or, for `GETALL`, every value).
pub fn read(
    ns: &Namespace,
    id: i32,
    num: i32,
    cmd: i32,
    who: &Caller,
) -> Result<(i32, Vec<u16>), Errno> {
    ns.with_table::<SemTable, _>(TABLE, |t| {
        t.collect();
        let s = t.by_id(id)?;
        if !s.perm.allows(who, 0o444) {
            return Err(Errno(EACCES));
        }
        if cmd == GETALL {
            return Ok((0, s.sems.iter().map(|m| m.val as u16).collect()));
        }
        if num < 0 || num as usize >= s.sems.len() {
            return Err(Errno(EINVAL));
        }
        let m = &s.sems[num as usize];
        let v = match cmd {
            GETVAL => m.val,
            GETPID => m.pid,
            GETNCNT => s.count(num as u16, false),
            _ => s.count(num as u16, true),
        };
        Ok((v, Vec::new()))
    })
}

/// The number of semaphores in set `id` (for `SETALL`'s copy), with read
/// access not required.
pub fn nsems(ns: &Namespace, id: i32, who: &Caller) -> Result<usize, Errno> {
    ns.with_table::<SemTable, _>(TABLE, |t| {
        let s = t.by_id(id)?;
        if !s.perm.allows(who, 0o222) {
            return Err(Errno(EACCES));
        }
        Ok(s.sems.len())
    })
}

/// `SETVAL` (`semctl_setval`) and `SETALL`: the values (checked for
/// `SEMVMX`), every process's adjustments of them cleared.
pub fn write(
    ns: &Namespace,
    id: i32,
    num: Option<i32>,
    vals: &[i32],
    who: &Caller,
) -> Result<(), Errno> {
    if vals.iter().any(|v| !(0..=SEMVMX).contains(v)) {
        return Err(Errno(ERANGE));
    }
    ns.with_table::<SemTable, _>(TABLE, |t| {
        let s = t.by_id(id)?;
        if let Some(n) = num
            && (n < 0 || n as usize >= s.sems.len())
        {
            return Err(Errno(EINVAL));
        }
        if !s.perm.allows(who, 0o222) {
            return Err(Errno(EACCES));
        }
        match num {
            Some(n) => {
                let n = n as usize;
                s.sems[n].val = vals[0];
                s.sems[n].pid = who.pid;
                for (_, adj) in &mut s.undos {
                    adj[n] = 0;
                }
            }
            None => {
                for (m, v) in s.sems.iter_mut().zip(vals) {
                    m.val = *v;
                    m.pid = who.pid;
                }
                for (_, adj) in &mut s.undos {
                    adj.fill(0);
                }
            }
        }
        s.ctime = now();
        Ok(())
    })
}

/// `IPC_SET` (`semctl_down`).
pub fn set(ns: &Namespace, id: i32, perm: &[u8], who: &Caller) -> Result<(), Errno> {
    ns.with_table::<SemTable, _>(TABLE, |t| {
        let s = t.by_id(id)?;
        if !s.perm.owned_by(who) {
            return Err(Errno(EPERM));
        }
        s.perm.update(perm)?;
        s.ctime = now();
        Ok(())
    })
}

/// `IPC_RMID` (`freeary`): the set goes; its waiters find it removed.
pub fn rmid(ns: &Namespace, id: i32, who: &Caller) -> Result<(), Errno> {
    ns.with_table::<SemTable, _>(TABLE, |t| {
        let s = t.by_id(id)?;
        if !s.perm.owned_by(who) {
            return Err(Errno(EPERM));
        }
        let idx = s.idx;
        t.sets.retain(|s| s.idx != idx);
        Ok(())
    })
}

/// `exit_sem` for process `pid`.
pub fn exit(ns: &Namespace, pid: i32) {
    let _ = ns.with_table::<SemTable, _>(TABLE, |t| {
        for s in &mut t.sets {
            s.apply_undo(pid);
            s.waiters.retain(|w| w.pid != pid);
        }
        Ok(())
    });
}

/// Whether process `pid` has undo adjustments or waits in the namespace.
pub fn involved(ns: &Namespace, pid: i32) -> bool {
    ns.with_table::<SemTable, _>(TABLE, |t| {
        Ok(t.sets
            .iter()
            .any(|s| s.undos.iter().any(|(p, _)| *p == pid)))
    })
    .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ns(tag: &str) -> Namespace {
        let d = std::env::temp_dir().join(format!("rax-ipc-sem-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        Namespace::at(d)
    }

    fn me() -> Caller {
        Caller {
            pid: std::process::id() as i32,
            euid: 1000,
            egid: 1000,
            groups: Vec::new(),
        }
    }

    fn op(num: u16, op: i16, flg: i16) -> SemBuf {
        SemBuf { num, op, flg }
    }

    #[test]
    fn operations_follow_perform_atomic_semop() {
        let n = ns("op");
        let who = me();
        assert_eq!(get(&n, IPC_PRIVATE, 0, 0o600, &who), Err(Errno(EINVAL)));
        assert_eq!(
            get(&n, IPC_PRIVATE, SEMMSL + 1, 0o600, &who),
            Err(Errno(EINVAL))
        );
        let id = get(&n, IPC_PRIVATE, 3, 0o600, &who).unwrap();
        let nowait = IPC_NOWAIT as i16;
        // All or nothing: the second would block, so the first is undone.
        assert_eq!(
            semop(&n, id, &[op(0, 2, 0), op(1, -1, nowait)], &who, 1, false),
            Err(Errno(EAGAIN))
        );
        assert_eq!(read(&n, id, 0, GETVAL, &who).unwrap().0, 0);
        // In order: +2 then -1 on one semaphore.
        assert_eq!(
            semop(&n, id, &[op(0, 2, 0), op(0, -1, 0)], &who, 1, false),
            Ok(Outcome::Done)
        );
        assert_eq!(read(&n, id, 0, GETVAL, &who).unwrap().0, 1);
        assert_eq!(read(&n, id, 0, GETPID, &who).unwrap().0, who.pid);
        // Waiting: recorded for GETNCNT (a decrement) and GETZCNT.
        assert_eq!(
            semop(&n, id, &[op(1, -1, 0)], &who, 7, false),
            Ok(Outcome::Wait)
        );
        assert_eq!(read(&n, id, 1, GETNCNT, &who).unwrap().0, 1);
        assert_eq!(
            semop(&n, id, &[op(0, 0, 0)], &who, 8, false),
            Ok(Outcome::Wait)
        );
        assert_eq!(read(&n, id, 0, GETZCNT, &who).unwrap().0, 1);
        stop_waiting(&n, id, who.pid, 8);
        assert_eq!(read(&n, id, 0, GETZCNT, &who).unwrap().0, 0);
        // The value it waits for arrives: the retry succeeds.
        write(&n, id, Some(1), &[1], &who).unwrap();
        assert_eq!(
            semop(&n, id, &[op(1, -1, 0)], &who, 7, true),
            Ok(Outcome::Done)
        );
        assert_eq!(read(&n, id, 1, GETNCNT, &who).unwrap().0, 0);
        // Range: SEMVMX, and the semaphore number.
        write(&n, id, Some(2), &[SEMVMX], &who).unwrap();
        assert_eq!(
            semop(&n, id, &[op(2, 1, 0)], &who, 1, false),
            Err(Errno(ERANGE))
        );
        assert_eq!(
            semop(&n, id, &[op(3, 1, 0)], &who, 1, false),
            Err(Errno(EFBIG))
        );
        assert_eq!(
            write(&n, id, Some(0), &[SEMVMX + 1], &who),
            Err(Errno(ERANGE))
        );
        // A set removed while waiting.
        rmid(&n, id, &who).unwrap();
        assert_eq!(
            semop(&n, id, &[op(0, -1, 0)], &who, 7, true),
            Err(Errno(EIDRM))
        );
        assert_eq!(
            semop(&n, id, &[op(0, -1, 0)], &who, 7, false),
            Err(Errno(EINVAL))
        );
        let _ = std::fs::remove_dir_all(n.dir());
    }

    #[test]
    fn undo_follows_exit_sem() {
        let n = ns("undo");
        let who = me();
        let id = get(&n, 77, 2, IPC_CREAT | 0o600, &who).unwrap();
        write(&n, id, None, &[5, 0], &who).unwrap();
        let undo = SEM_UNDO;
        semop(&n, id, &[op(0, -3, undo), op(1, 2, undo)], &who, 1, false).unwrap();
        assert!(involved(&n, who.pid));
        // exit_sem: +3 and -2 back.
        exit(&n, who.pid);
        let (_, all) = read(&n, id, 0, GETALL, &who).unwrap();
        assert_eq!(all, [5, 0]);
        // Clamped at 0: +2 undone after the value dropped to 0.
        semop(&n, id, &[op(0, 2, undo)], &who, 1, false).unwrap();
        semop(&n, id, &[op(0, -7, 0)], &who, 1, false).unwrap();
        exit(&n, who.pid);
        assert_eq!(read(&n, id, 0, GETVAL, &who).unwrap().0, 0);
        // A dead process's adjustments apply when the table is next read.
        let ghost = Caller {
            pid: 999_999_999,
            ..who.clone()
        };
        semop(&n, id, &[op(0, 3, undo)], &ghost, 1, false).unwrap();
        assert_eq!(read(&n, id, 0, GETVAL, &who).unwrap().0, 0);
        // SETVAL clears the adjustments of that semaphore.
        semop(&n, id, &[op(1, 1, undo)], &who, 1, false).unwrap();
        write(&n, id, Some(1), &[4], &who).unwrap();
        exit(&n, who.pid);
        assert_eq!(read(&n, id, 1, GETVAL, &who).unwrap().0, 4);
        // The x86-64 status layout.
        let (ds, _) = stat(&n, id, super::super::IPC_STAT, &who, true).unwrap();
        assert_eq!(ds.len(), 104);
        assert_eq!(u64::from_le_bytes(ds[80..88].try_into().unwrap()), 2);
        let (ds, _) = stat(&n, id, super::super::IPC_STAT, &who, false).unwrap();
        assert_eq!(ds.len(), 88);
        assert_eq!(u64::from_le_bytes(ds[64..72].try_into().unwrap()), 2);
        let _ = std::fs::remove_dir_all(n.dir());
    }
}
