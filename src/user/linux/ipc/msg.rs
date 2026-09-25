//! System V message queues (`ipc/msg.c`).
//!
//! A queue lives in the namespace's table with its messages (their bytes
//! hex-encoded), so any process may send to it or receive from it. A send
//! that does not fit (`msg_fits_inqueue`) and a receive that finds no
//! message wait, trying again, until they can, the queue is removed
//! (`EIDRM`), or a signal ends them (`-ERESTARTNOHAND`). A waiting receiver
//! is not handed a message as it is sent (`pipelined_send`): it finds it on
//! its next try, and so may another receiver first. `MSG_COPY` is answered
//! as by a kernel without `CONFIG_CHECKPOINT_RESTORE` (`ENOSYS`).

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::{
    Caller, IPC_CREAT, IPC_EXCL, IPC_NOWAIT, IPC_PRIVATE, IPCMNI, Ids, Namespace, Perm, Table,
    build_id, idx_of, now, seq_of,
};

/// `MSGMNI`, `MSGMAX`, `MSGMNB`, and the informational `MSGPOOL`,
/// `MSGMAP`, `MSGTQL`, `MSGSSZ`, `MSGSEG` (`linux/msg.h`).
pub const MSGMNI: u32 = 32000;
pub const MSGMAX: i64 = 8192;
pub const MSGMNB: u64 = 16384;
const MSGPOOL: i32 = (MSGMNI as i64 * MSGMNB as i64 / 1024) as i32;
const MSGMAP: i32 = MSGMNB as i32;
const MSGTQL: i32 = MSGMNB as i32;
const MSGSSZ: i32 = 16;
const MSGSEG: u16 = 0xFFFF;
/// `msgrcv` flags.
pub const MSG_NOERROR: i32 = 0o10000;
pub const MSG_EXCEPT: i32 = 0o20000;
pub const MSG_COPY: i32 = 0o40000;
/// `msgctl` commands.
pub const MSG_STAT: i32 = 11;
pub const MSG_INFO: i32 = 12;
pub const MSG_STAT_ANY: i32 = 13;
/// `sizeof(struct msqid64_ds)`, `sizeof(struct msginfo)`.
pub const MSQID64_DS: usize = 120;
pub const MSGINFO: usize = 32;
const TABLE: &str = "msg";

/// A queued message (`struct msg_msg`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub mtype: i64,
    pub text: Vec<u8>,
}

/// A queue (`struct msg_queue`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Queue {
    pub idx: u32,
    pub perm: Perm,
    pub stime: i64,
    pub rtime: i64,
    pub ctime: i64,
    pub qbytes: u64,
    pub lspid: i32,
    pub lrpid: i32,
    pub messages: Vec<Message>,
}

impl Queue {
    pub fn id(&self) -> i32 {
        build_id(self.idx, self.perm.seq)
    }

    fn cbytes(&self) -> u64 {
        self.messages.iter().map(|m| m.text.len() as u64).sum()
    }

    /// `msg_fits_inqueue`.
    fn fits(&self, size: u64) -> bool {
        // 1 + q_qnum <= q_qbytes.
        size + self.cbytes() <= self.qbytes && (self.messages.len() as u64) < self.qbytes
    }

    /// `struct msqid64_ds`.
    pub fn encode(&self) -> [u8; MSQID64_DS] {
        let mut b = [0u8; MSQID64_DS];
        b[..super::IPC64_PERM].copy_from_slice(&self.perm.encode());
        b[48..56].copy_from_slice(&self.stime.to_le_bytes());
        b[56..64].copy_from_slice(&self.rtime.to_le_bytes());
        b[64..72].copy_from_slice(&self.ctime.to_le_bytes());
        b[72..80].copy_from_slice(&self.cbytes().to_le_bytes());
        b[80..88].copy_from_slice(&(self.messages.len() as u64).to_le_bytes());
        b[88..96].copy_from_slice(&self.qbytes.to_le_bytes());
        b[96..100].copy_from_slice(&self.lspid.to_le_bytes());
        b[100..104].copy_from_slice(&self.lrpid.to_le_bytes());
        b
    }
}

/// The queues of a namespace (`msg_ids`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MsgTable {
    pub ids: Ids,
    pub queues: Vec<Queue>,
}

fn hex(b: &[u8]) -> String {
    if b.is_empty() {
        return "-".into();
    }
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s == "-" {
        return Some(Vec::new());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

impl Table for MsgTable {
    fn parse(text: &str) -> Self {
        let mut t = MsgTable {
            ids: Ids {
                last_idx: -1,
                seq: 0,
            },
            queues: Vec::new(),
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
                Some("queue") => {
                    if let Some(q) = parse_queue(&mut f) {
                        t.queues.push(q);
                    }
                }
                _ => {}
            }
        }
        t
    }

    fn render(&self) -> String {
        let mut out = format!("ids {} {}\n", self.ids.last_idx, self.ids.seq);
        for q in &self.queues {
            out.push_str(&format!(
                "queue {} {} {} {} {} {} {} {} {}",
                q.idx,
                q.perm.fields(),
                q.stime,
                q.rtime,
                q.ctime,
                q.qbytes,
                q.lspid,
                q.lrpid,
                q.messages.len()
            ));
            for m in &q.messages {
                out.push_str(&format!(" {}:{}", m.mtype, hex(&m.text)));
            }
            out.push('\n');
        }
        out
    }
}

fn parse_queue(f: &mut std::str::SplitWhitespace<'_>) -> Option<Queue> {
    let idx = f.next()?.parse().ok()?;
    let perm = Perm::parse(f)?;
    let mut q = Queue {
        idx,
        perm,
        stime: f.next()?.parse().ok()?,
        rtime: f.next()?.parse().ok()?,
        ctime: f.next()?.parse().ok()?,
        qbytes: f.next()?.parse().ok()?,
        lspid: f.next()?.parse().ok()?,
        lrpid: f.next()?.parse().ok()?,
        messages: Vec::new(),
    };
    let n: usize = f.next()?.parse().ok()?;
    for _ in 0..n {
        let (t, text) = f.next()?.split_once(':')?;
        q.messages.push(Message {
            mtype: t.parse().ok()?,
            text: unhex(text)?,
        });
    }
    Some(q)
}

impl MsgTable {
    /// `msq_obtain_object_check`.
    fn by_id(&mut self, id: i32) -> Result<&mut Queue, Errno> {
        let (idx, seq) = (idx_of(id), seq_of(id));
        self.queues
            .iter_mut()
            .find(|q| q.idx == idx && q.perm.seq == seq)
            .ok_or(Errno(EINVAL))
    }

    fn max_idx(&self) -> i32 {
        self.queues.iter().map(|q| q.idx as i32).max().unwrap_or(0)
    }
}

/// `msgget` (`ksys_msgget`, `ipcget`, `newque`).
pub fn get(ns: &Namespace, key: i32, flags: i32, who: &Caller) -> Result<i32, Errno> {
    ns.with_table::<MsgTable, _>(TABLE, |t| {
        if key != IPC_PRIVATE
            && let Some(q) = t.queues.iter().find(|q| q.perm.key == key)
        {
            if flags & IPC_CREAT != 0 && flags & IPC_EXCL != 0 {
                return Err(Errno(EEXIST));
            }
            if !q.perm.allows(who, flags as u16 as u32) {
                return Err(Errno(EACCES));
            }
            return Ok(q.id());
        }
        if key != IPC_PRIVATE && flags & IPC_CREAT == 0 {
            return Err(Errno(ENOENT));
        }
        if t.queues.len() as u32 >= MSGMNI.min(IPCMNI) {
            return Err(Errno(ENOSPC));
        }
        let used: Vec<u32> = t.queues.iter().map(|q| q.idx).collect();
        let (idx, seq) = t.ids.alloc(&used).ok_or(Errno(ENOSPC))?;
        let mut perm = Perm::new(key, flags as u32 & super::S_IRWXUGO, who);
        perm.seq = seq;
        let q = Queue {
            idx,
            perm,
            stime: 0,
            rtime: 0,
            ctime: now(),
            qbytes: MSGMNB,
            lspid: 0,
            lrpid: 0,
            messages: Vec::new(),
        };
        let id = q.id();
        t.queues.push(q);
        Ok(id)
    })
}

/// What an attempt at a send or receive came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome<T> {
    Done(T),
    /// It must wait.
    Wait,
}

/// One attempt at `do_msgsnd` after its argument checks: `waiting` says
/// whether the caller was already waiting (a queue removed meanwhile is
/// then `EIDRM`).
pub fn send(
    ns: &Namespace,
    id: i32,
    msg: &Message,
    flags: i32,
    who: &Caller,
    waiting: bool,
) -> Result<Outcome<()>, Errno> {
    ns.with_table::<MsgTable, _>(TABLE, |t| {
        let q = match t.by_id(id) {
            Ok(q) => q,
            Err(_) if waiting => return Err(Errno(EIDRM)),
            Err(e) => return Err(e),
        };
        if !q.perm.allows(who, 0o222) {
            return Err(Errno(EACCES));
        }
        if !q.fits(msg.text.len() as u64) {
            if flags & IPC_NOWAIT != 0 {
                return Err(Errno(EAGAIN));
            }
            return Ok(Outcome::Wait);
        }
        q.lspid = who.pid;
        q.stime = now();
        q.messages.push(msg.clone());
        Ok(Outcome::Done(()))
    })
}

/// `convert_mode` and `find_msg`: the index of the message `msgtyp` and
/// `flags` select.
fn find(q: &Queue, msgtyp: i64, flags: i32) -> Option<usize> {
    if msgtyp == 0 {
        return (!q.messages.is_empty()).then_some(0);
    }
    if msgtyp < 0 {
        // SEARCH_LESSEQUAL: the first of the least type at most |msgtyp|.
        let mut bound = if msgtyp == i64::MIN {
            i64::MAX
        } else {
            -msgtyp
        };
        let mut found = None;
        for (i, m) in q.messages.iter().enumerate() {
            if m.mtype <= bound {
                if m.mtype == 1 {
                    return Some(i);
                }
                bound = m.mtype - 1;
                found = Some(i);
            }
        }
        return found;
    }
    if flags & MSG_EXCEPT != 0 {
        return q.messages.iter().position(|m| m.mtype != msgtyp);
    }
    q.messages.iter().position(|m| m.mtype == msgtyp)
}

/// One attempt at `do_msgrcv` after its argument checks: the message
/// (cut to `bufsz` with `MSG_NOERROR`).
pub fn receive(
    ns: &Namespace,
    id: i32,
    bufsz: u64,
    msgtyp: i64,
    flags: i32,
    who: &Caller,
    waiting: bool,
) -> Result<Outcome<Message>, Errno> {
    ns.with_table::<MsgTable, _>(TABLE, |t| {
        let q = match t.by_id(id) {
            Ok(q) => q,
            Err(_) if waiting => return Err(Errno(EIDRM)),
            Err(e) => return Err(e),
        };
        if !q.perm.allows(who, 0o444) {
            return Err(Errno(EACCES));
        }
        let Some(i) = find(q, msgtyp, flags) else {
            if flags & IPC_NOWAIT != 0 {
                return Err(Errno(ENOMSG));
            }
            return Ok(Outcome::Wait);
        };
        if bufsz < q.messages[i].text.len() as u64 && flags & MSG_NOERROR == 0 {
            return Err(Errno(E2BIG));
        }
        let mut m = q.messages.remove(i);
        q.rtime = now();
        q.lrpid = who.pid;
        m.text.truncate(bufsz.min(m.text.len() as u64) as usize);
        Ok(Outcome::Done(m))
    })
}

/// `IPC_STAT`, `MSG_STAT`, `MSG_STAT_ANY` (`msgctl_stat`).
pub fn stat(
    ns: &Namespace,
    id: i32,
    cmd: i32,
    who: &Caller,
) -> Result<([u8; MSQID64_DS], i32), Errno> {
    ns.with_table::<MsgTable, _>(TABLE, |t| {
        let q = if cmd == super::IPC_STAT {
            t.by_id(id)?
        } else {
            let idx = idx_of(id);
            t.queues
                .iter_mut()
                .find(|q| q.idx == idx)
                .ok_or(Errno(EINVAL))?
        };
        if cmd != MSG_STAT_ANY && !q.perm.allows(who, 0o444) {
            return Err(Errno(EACCES));
        }
        let r = if cmd == super::IPC_STAT { 0 } else { q.id() };
        Ok((q.encode(), r))
    })
}

/// `IPC_INFO` and `MSG_INFO` (`msgctl_info`): `struct msginfo` and the
/// highest index in use.
pub fn info(ns: &Namespace, cmd: i32) -> Result<([u8; MSGINFO], i32), Errno> {
    ns.with_table::<MsgTable, _>(TABLE, |t| {
        let (pool, map, tql) = if cmd == MSG_INFO {
            let hdrs: usize = t.queues.iter().map(|q| q.messages.len()).sum();
            let bytes: u64 = t.queues.iter().map(Queue::cbytes).sum();
            (
                t.queues.len() as i32,
                hdrs.min(i32::MAX as usize) as i32,
                bytes.min(i32::MAX as u64) as i32,
            )
        } else {
            (MSGPOOL, MSGMAP, MSGTQL)
        };
        // msgpool, msgmap, msgmax, msgmnb, msgmni, msgssz, msgtql, msgseg.
        let fields = [
            pool,
            map,
            MSGMAX as i32,
            MSGMNB as i32,
            MSGMNI as i32,
            MSGSSZ,
            tql,
        ];
        let mut b = [0u8; MSGINFO];
        for (i, v) in fields.iter().enumerate() {
            b[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
        }
        b[28..30].copy_from_slice(&MSGSEG.to_le_bytes());
        Ok((b, t.max_idx()))
    })
}

/// `IPC_SET` (`msgctl_down`): the owner, group, permissions, and the
/// queue's size (past `MSGMNB` only with `CAP_SYS_RESOURCE`).
pub fn set(ns: &Namespace, id: i32, ds: &[u8], who: &Caller) -> Result<(), Errno> {
    let qbytes = u64::from_le_bytes(ds[88..96].try_into().unwrap());
    ns.with_table::<MsgTable, _>(TABLE, |t| {
        let q = t.by_id(id)?;
        if !q.perm.owned_by(who) {
            return Err(Errno(EPERM));
        }
        if qbytes > MSGMNB && !who.capable() {
            return Err(Errno(EPERM));
        }
        q.perm.update(&ds[..super::IPC64_PERM])?;
        q.qbytes = qbytes;
        q.ctime = now();
        Ok(())
    })
}

/// `IPC_RMID` (`freeque`): the queue and its messages go; its waiters find
/// it removed.
pub fn rmid(ns: &Namespace, id: i32, who: &Caller) -> Result<(), Errno> {
    ns.with_table::<MsgTable, _>(TABLE, |t| {
        let q = t.by_id(id)?;
        if !q.perm.owned_by(who) {
            return Err(Errno(EPERM));
        }
        let idx = q.idx;
        t.queues.retain(|q| q.idx != idx);
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ns(tag: &str) -> Namespace {
        let d = std::env::temp_dir().join(format!("rax-ipc-msg-{}-{tag}", std::process::id()));
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

    fn msg(mtype: i64, text: &[u8]) -> Message {
        Message {
            mtype,
            text: text.to_vec(),
        }
    }

    #[test]
    fn receives_follow_find_msg() {
        let n = ns("find");
        let who = me();
        let id = get(&n, IPC_PRIVATE, 0o600, &who).unwrap();
        for (t, s) in [(3, b"c"), (1, b"a"), (2, b"b"), (1, b"d")] {
            assert_eq!(
                send(&n, id, &msg(t, s), 0, &who, false),
                Ok(Outcome::Done(()))
            );
        }
        let rcv = |typ: i64, flags: i32| match receive(&n, id, 10, typ, flags, &who, false) {
            Ok(Outcome::Done(m)) => (m.mtype, m.text),
            r => panic!("{r:?}"),
        };
        // The least type at most 2: the first 1.
        assert_eq!(rcv(-2, 0), (1, b"a".to_vec()));
        assert_eq!(rcv(2, 0), (2, b"b".to_vec()));
        assert_eq!(rcv(1, MSG_EXCEPT), (3, b"c".to_vec()));
        assert_eq!(
            receive(&n, id, 10, 5, IPC_NOWAIT, &who, false),
            Err(Errno(ENOMSG))
        );
        assert_eq!(receive(&n, id, 10, 5, 0, &who, false), Ok(Outcome::Wait));
        assert_eq!(rcv(0, 0), (1, b"d".to_vec()));
        // Too big: E2BIG, the message kept; cut with MSG_NOERROR.
        send(&n, id, &msg(9, b"hello"), 0, &who, false).unwrap();
        assert_eq!(receive(&n, id, 3, 0, 0, &who, false), Err(Errno(E2BIG)));
        assert_eq!(
            receive(&n, id, 3, 0, MSG_NOERROR, &who, false),
            Ok(Outcome::Done(msg(9, b"hel")))
        );
        rmid(&n, id, &who).unwrap();
        assert_eq!(receive(&n, id, 3, 0, 0, &who, true), Err(Errno(EIDRM)));
        let _ = std::fs::remove_dir_all(n.dir());
    }

    #[test]
    fn sends_follow_msg_fits_inqueue() {
        let n = ns("fit");
        let who = me();
        let id = get(&n, 5, IPC_CREAT | 0o600, &who).unwrap();
        let big = vec![7u8; 8192];
        assert_eq!(
            send(&n, id, &msg(1, &big), 0, &who, false),
            Ok(Outcome::Done(()))
        );
        assert_eq!(
            send(&n, id, &msg(1, &big), 0, &who, false),
            Ok(Outcome::Done(()))
        );
        // 16384 bytes queued: full.
        assert_eq!(
            send(&n, id, &msg(1, b"x"), IPC_NOWAIT, &who, false),
            Err(Errno(EAGAIN))
        );
        assert_eq!(
            send(&n, id, &msg(1, b"x"), 0, &who, false),
            Ok(Outcome::Wait)
        );
        // Zero-length messages count against msg_qbytes too.
        let (ds, _) = stat(&n, id, super::super::IPC_STAT, &who).unwrap();
        assert_eq!(u64::from_le_bytes(ds[72..80].try_into().unwrap()), 16384);
        assert_eq!(u64::from_le_bytes(ds[80..88].try_into().unwrap()), 2);
        assert_eq!(i32::from_le_bytes(ds[96..100].try_into().unwrap()), who.pid);
        // IPC_SET: past MSGMNB needs CAP_SYS_RESOURCE.
        let mut ds = ds.to_vec();
        ds[88..96].copy_from_slice(&20000u64.to_le_bytes());
        assert_eq!(set(&n, id, &ds, &who), Err(Errno(EPERM)));
        ds[88..96].copy_from_slice(&2u64.to_le_bytes());
        set(&n, id, &ds, &who).unwrap();
        let (b, _) = info(&n, MSG_INFO).unwrap();
        assert_eq!(
            i32::from_le_bytes(b[4..8].try_into().unwrap()),
            2,
            "msgmap: headers"
        );
        rmid(&n, id, &who).unwrap();
        let _ = std::fs::remove_dir_all(n.dir());
    }
}
