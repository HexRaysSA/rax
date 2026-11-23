//! Process groups, sessions and signal routing inside a closed Linux session.

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::{EACCES, EINVAL, EPERM, ESRCH};
use super::super::signal::{SIGCONT, SIGRTMIN, SigInfo, valid_signal};
use super::{Children, Namespace};

const REALTIME_QUEUE_LIMIT: usize = 128;

#[derive(Debug)]
pub(super) struct GroupMember {
    pgid: i32,
    sid: i32,
    uid: u32,
    euid: u32,
    execed: bool,
    zombie: bool,
    signals: Vec<SigInfo>,
}

impl GroupMember {
    pub(super) fn initial(pid: i32) -> Self {
        Self {
            pgid: pid,
            sid: pid,
            uid: 0,
            euid: 0,
            execed: false,
            zombie: false,
            signals: Vec::new(),
        }
    }

    pub(super) fn forked(&self) -> Self {
        Self {
            pgid: self.pgid,
            sid: self.sid,
            uid: self.uid,
            euid: self.euid,
            ..Self::initial(0)
        }
    }

    fn queue_signal(&mut self, signal: SigInfo) {
        if self.zombie || signal.signo == 0 {
            return;
        }
        // These opposing pending effects cancel at generation, even if the
        // recipient has not had a scheduler turn to handle them.
        use super::super::signal::{SIGSTOP, SIGTSTP, SIGTTIN, SIGTTOU};
        let stop = |sig| matches!(sig, SIGSTOP | SIGTSTP | SIGTTIN | SIGTTOU);
        if signal.signo == SIGCONT {
            self.signals.retain(|queued| !stop(queued.signo));
        } else if stop(signal.signo) {
            self.signals.retain(|queued| queued.signo != SIGCONT);
        }
        // Standard signals coalesce. After the queue bound, kill still
        // leaves each real-time signal pending at least once.
        if (signal.signo < SIGRTMIN || self.signals.len() >= REALTIME_QUEUE_LIMIT)
            && self
                .signals
                .iter()
                .any(|queued| queued.signo == signal.signo)
        {
            return;
        }
        self.signals.push(signal);
    }
}

impl Namespace {
    pub(super) fn id_in_use(&self, id: i32) -> bool {
        self.tasks.contains_key(&id)
            || self
                .processes
                .values()
                .any(|group| group.pgid == id || group.sid == id)
    }
}

impl Children {
    fn guest_namespace(&self) -> std::sync::MutexGuard<'_, Namespace> {
        self.namespace
            .as_ref()
            .expect("closed guest namespace")
            .lock()
            .unwrap()
    }

    pub(in super::super) fn guest_group(&self, tid: i32) -> Option<(i32, i32)> {
        let ns = self.guest_namespace();
        let group = ns.processes.get(ns.tasks.get(&tid)?)?;
        Some((group.pgid, group.sid))
    }

    pub(in super::super) fn guest_setpgid(&self, pid: i32, pgid: i32) -> Result<(), Errno> {
        let pid = if pid == 0 { self.owner } else { pid };
        let pgid = if pgid == 0 { pid } else { pgid };
        if pgid < 0 {
            return Err(Errno(EINVAL));
        }
        let mut ns = self.guest_namespace();
        let owner = ns.tasks.get(&pid).ok_or(Errno(ESRCH))?;
        if *owner != pid {
            return Err(Errno(EINVAL));
        }
        let target = ns.processes.get(&pid).ok_or(Errno(ESRCH))?;
        let sid = ns.processes[&self.owner].sid;
        if pid != self.owner {
            if !self.list.iter().any(|child| child.pid == pid) {
                return Err(Errno(ESRCH));
            }
            if target.sid != sid {
                return Err(Errno(EPERM));
            }
            if target.execed {
                return Err(Errno(EACCES));
            }
        }
        if target.sid == pid
            || (pgid != pid
                && !ns
                    .processes
                    .values()
                    .any(|group| group.pgid == pgid && group.sid == sid))
        {
            return Err(Errno(EPERM));
        }
        ns.processes.get_mut(&pid).unwrap().pgid = pgid;
        Ok(())
    }

    pub(in super::super) fn guest_setsid(&self) -> Result<i32, Errno> {
        let mut ns = self.guest_namespace();
        let pid = self.owner;
        if ns.processes.values().any(|group| group.pgid == pid) {
            return Err(Errno(EPERM));
        }
        let current = ns.processes.get_mut(&pid).unwrap();
        current.pgid = pid;
        current.sid = pid;
        Ok(pid)
    }

    pub(in super::super) fn guest_exec(&self) {
        self.guest_namespace()
            .processes
            .get_mut(&self.owner)
            .unwrap()
            .execed = true;
    }

    pub(in super::super) fn guest_update_uid(&self, uid: u32, euid: u32) {
        let mut ns = self.guest_namespace();
        let current = ns.processes.get_mut(&self.owner).unwrap();
        current.uid = uid;
        current.euid = euid;
    }

    pub(in super::super) fn refresh_guest_groups(&mut self) {
        let namespace = self.namespace.as_ref().expect("closed guest namespace");
        let ns = namespace.lock().unwrap();
        for child in &mut self.list {
            child.pgid = ns.processes[&child.pid].pgid;
        }
    }

    pub(super) fn mark_guest_zombie(&self) {
        let mut ns = self.guest_namespace();
        let current = ns.processes.get_mut(&self.owner).unwrap();
        current.zombie = true;
        current.signals.clear();
    }

    pub(in super::super) fn take_guest_signals(&self) -> Vec<SigInfo> {
        let mut ns = self.guest_namespace();
        std::mem::take(&mut ns.processes.get_mut(&self.owner).unwrap().signals)
    }

    /// Queue a process-directed signal on selected guest members. Returns
    /// whether the caller should deliver to itself before returning.
    pub(in super::super) fn guest_kill(&self, pid: i32, signal: SigInfo) -> Result<bool, Errno> {
        let mut ns = self.guest_namespace();
        let sender = &ns.processes[&self.owner];
        let (pgid, sid, uid, euid) = (sender.pgid, sender.sid, sender.uid, sender.euid);
        let task = ns.tasks.get(&pid).copied();
        let matching = |id, group: &GroupMember| match pid {
            1.. => task == Some(id),
            0 => group.pgid == pgid,
            -1 => id != self.owner,
            _ => group.pgid == -pid,
        };
        let mut deliver_here = false;
        let mut found = false;
        let mut permitted = false;
        for (&id, target) in &mut ns.processes {
            if !matching(id, target) {
                continue;
            }
            if signal.signo != 0 && !valid_signal(signal.signo) {
                return Err(Errno(EINVAL));
            }
            found = true;
            let allowed = euid == 0
                || [uid, euid].contains(&target.uid)
                || [uid, euid].contains(&target.euid)
                || (signal.signo == SIGCONT && target.sid == sid);
            if !allowed {
                continue;
            }
            permitted = true;
            if id == self.owner {
                deliver_here = signal.signo != 0;
            } else {
                target.queue_signal(signal);
            }
        }
        if permitted {
            Ok(deliver_here)
        } else {
            Err(Errno(if found { EPERM } else { ESRCH }))
        }
    }
}
