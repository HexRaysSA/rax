//! Process identities, scheduling, and wait records for a closed Darwin session.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use super::{DarwinProcess, ExitStatus, Proc, RunStatus, wait};
use crate::user::darwin::abi::Errno;
use crate::user::darwin::signal::{self, frame::code};

pub(super) const ROOT_PID: i32 = 1000;
const MAX_CHILDREN: usize = 32;
const CHILD_ARENA_BUDGET: u64 = 2 << 30;

#[derive(Clone)]
pub(crate) struct Member {
    registry: Arc<Mutex<Registry>>,
    pid: i32,
    // The proposed identity is used only when publishing a new child.
    initial: Identity,
    stopped: bool,
}

#[derive(Clone, Copy)]
pub(crate) struct Identity {
    pub(crate) group: i32,
    pub(crate) session: i32,
}

const ROOT_IDENTITY: Identity = Identity {
    group: ROOT_PID,
    session: ROOT_PID,
};

struct Registry {
    next_pid: i32,
    children: BTreeMap<i32, Child>,
    pending_signals: Vec<Delivery>,
    job_changes: Vec<JobChange>,
}

struct Delivery {
    pid: i32,
    signal: signal::Signal,
    origin: signal::Origin,
}

struct JobChange {
    parent: i32,
    origin: signal::Origin,
}

struct Child {
    parent: i32,
    identity: Identity,
    execed: bool,
    report: Option<Report>,
    job: Job,
}

#[derive(Clone, Copy)]
enum Job {
    Running,
    Stopped {
        signal: signal::Signal,
        waited: bool,
    },
    Continued,
}

impl Job {
    fn report(self, wanted: WaitFor) -> Option<Report> {
        match self {
            Self::Stopped {
                signal,
                waited: false,
            } if wanted.stopped => Some(Report::job(signal, code::CLD_STOPPED)),
            Self::Continued if wanted.continued => {
                Some(Report::job(signal::SIGCONT, code::CLD_CONTINUED))
            }
            _ => None,
        }
    }
}

impl Registry {
    fn live_child(&self, pid: i32) -> Result<&Child, Errno> {
        self.children
            .get(&pid)
            .filter(|child| child.report.is_none())
            .ok_or(Errno::ESRCH)
    }

    fn identity(&self, pid: i32) -> Result<Identity, Errno> {
        if pid == ROOT_PID {
            return Ok(ROOT_IDENTITY);
        }
        Ok(self.live_child(pid)?.identity)
    }

    fn group_session(&self, group: i32) -> Option<i32> {
        if group == ROOT_PID {
            return Some(ROOT_PID);
        }
        self.children
            .values()
            .find(|child| child.identity.group == group)
            .map(|child| child.identity.session)
    }

    fn descends_from(&self, mut pid: i32, ancestor: i32) -> bool {
        while let Some(child) = self.children.get(&pid) {
            if child.parent == ancestor {
                return true;
            }
            pid = child.parent;
        }
        false
    }

    fn has_job_control(&self, pid: i32) -> Result<bool, Errno> {
        let identity = self.identity(pid)?;
        // A live member with a parent in another group of the same session
        // keeps this group from becoming orphaned.
        Ok(self.children.values().any(|child| {
            child.report.is_none()
                && child.identity.group == identity.group
                && self.identity(child.parent).is_ok_and(|parent| {
                    parent.session == identity.session && parent.group != identity.group
                })
        }))
    }

    fn record_job(&mut self, pid: i32, job: Job, origin: Option<signal::Origin>) {
        let Some(child) = self.children.get_mut(&pid) else {
            return;
        };
        child.job = job;
        if let Some(origin) = origin {
            self.job_changes.push(JobChange {
                parent: child.parent,
                origin,
            });
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum Selector {
    Any,
    Pid(i32),
    Group(i32),
}

impl Selector {
    fn contains(self, pid: i32, identity: Identity) -> bool {
        match self {
            Self::Any => true,
            Self::Pid(wanted) => wanted == pid,
            Self::Group(wanted) => wanted == identity.group,
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct WaitFor {
    pub(crate) exited: bool,
    pub(crate) stopped: bool,
    pub(crate) continued: bool,
}

#[derive(Clone, Copy)]
pub(crate) struct Report {
    pub(crate) status: i32,
    pub(crate) code: i32,
    pub(crate) value: i32,
    pub(crate) user_ns: u64,
    pub(crate) system_ns: u64,
}

impl Member {
    pub(super) fn root() -> Self {
        Self {
            registry: Arc::new(Mutex::new(Registry {
                next_pid: ROOT_PID + 1,
                children: BTreeMap::new(),
                pending_signals: Vec::new(),
                job_changes: Vec::new(),
            })),
            pid: ROOT_PID,
            initial: ROOT_IDENTITY,
            stopped: false,
        }
    }

    pub(crate) fn prepare_child(
        &self,
        arena_bytes: u64,
        process_limit: u64,
        group: Option<i32>,
        setsid: bool,
    ) -> Result<(i32, Self), Errno> {
        let mut registry = self.registry.lock().unwrap();
        let live = registry
            .children
            .values()
            .filter(|c| c.report.is_none())
            .count() as u64;
        if registry.children.len() >= MAX_CHILDREN
            || live + 1 >= process_limit
            || (live + 1).saturating_mul(arena_bytes) > CHILD_ARENA_BUDGET.max(arena_bytes)
        {
            return Err(Errno::EAGAIN);
        }
        let pid = registry.next_pid;
        let mut identity = registry.identity(self.pid)?;
        if let Some(group) = group {
            if group < 0 {
                return Err(Errno::EINVAL);
            }
            identity.group = if group == 0 { pid } else { group };
            if identity.group != pid
                && registry.group_session(identity.group) != Some(identity.session)
            {
                return Err(Errno::EPERM);
            }
        }
        if setsid {
            if identity.group == pid {
                return Err(Errno::EPERM);
            }
            identity = Identity {
                group: pid,
                session: pid,
            };
        }
        registry.next_pid = pid.checked_add(1).ok_or(Errno::EAGAIN)?;
        Ok((
            pid,
            Self {
                registry: Arc::clone(&self.registry),
                pid,
                initial: identity,
                stopped: false,
            },
        ))
    }

    pub(crate) fn publish(&self, parent: i32, execed: bool) {
        let previous = self.registry.lock().unwrap().children.insert(
            self.pid,
            Child {
                parent,
                identity: self.initial,
                execed,
                report: None,
                job: Job::Running,
            },
        );
        debug_assert!(previous.is_none());
    }

    pub(crate) fn report(
        &self,
        parent: i32,
        selector: Selector,
        wanted: WaitFor,
    ) -> Result<Option<(i32, Report)>, Errno> {
        let registry = self.registry.lock().unwrap();
        let mut found = false;
        for (&pid, child) in registry.children.iter().rev() {
            if child.parent != parent || !selector.contains(pid, child.identity) {
                continue;
            }
            found = true;
            let report = match child.report {
                Some(report) => wanted.exited.then_some(report),
                None => child.job.report(wanted),
            };
            if let Some(report) = report {
                return Ok(Some((pid, report)));
            }
        }
        if found { Ok(None) } else { Err(Errno::ECHILD) }
    }

    pub(crate) fn consume_job(&self, pid: i32, report: Report) {
        let mut registry = self.registry.lock().unwrap();
        let child = registry.children.get_mut(&pid).expect("reported child");
        match (&mut child.job, report.code) {
            (Job::Stopped { waited, .. }, code::CLD_STOPPED) => *waited = true,
            (Job::Continued, code::CLD_CONTINUED) => child.job = Job::Running,
            _ => unreachable!("wait report no longer belongs to the child"),
        }
    }

    /// Returns whether any children remain after reaping.
    pub(crate) fn reap(&self, parent: i32, pid: i32) -> bool {
        let mut registry = self.registry.lock().unwrap();
        debug_assert_eq!(registry.children.get(&pid).map(|c| c.parent), Some(parent));
        registry.children.remove(&pid);
        registry.children.values().any(|c| c.parent == parent)
    }

    pub(crate) fn identity(&self, pid: i32) -> Result<Identity, Errno> {
        let pid = if pid == 0 { self.pid } else { pid };
        self.registry.lock().unwrap().identity(pid)
    }

    /// Resolve a closed kill target and enqueue other guest recipients. The
    /// issuing syscall delivers to its own process with its current thread.
    pub(crate) fn send_signal(
        &self,
        pid: i32,
        sig: signal::Signal,
        origin: signal::Origin,
    ) -> Result<bool, Errno> {
        // Keep the closed profile's self-only broadcast and permit the
        // synthetic self PID used by standalone dispatcher tests.
        if pid == -1 || pid == origin.pid {
            return Ok(true);
        }
        let mut registry = self.registry.lock().unwrap();
        let selector = match pid {
            0 => Selector::Group(registry.identity(self.pid)?.group),
            1.. => Selector::Pid(pid),
            _ => Selector::Group(pid.checked_neg().ok_or(Errno::EPERM)?),
        };
        let subjects = std::iter::once((ROOT_PID, ROOT_IDENTITY, true)).chain(
            registry
                .children
                .iter()
                .map(|(&pid, child)| (pid, child.identity, child.report.is_none())),
        );
        let mut matched = false;
        let mut local = false;
        let mut deliveries = Vec::new();
        for (pid, identity, live) in subjects {
            // An unreaped zombie still exists for a positive PID query.
            if !selector.contains(pid, identity) || !live && !matches!(selector, Selector::Pid(_)) {
                continue;
            }
            matched = true;
            local |= pid == self.pid;
            if sig != 0 && live && pid != self.pid {
                deliveries.push(Delivery {
                    pid,
                    signal: sig,
                    origin,
                });
            }
        }
        if !matched {
            return Err(Errno::EPERM);
        }
        registry.pending_signals.extend(deliveries);
        Ok(local)
    }

    pub(crate) fn job_stopped(&self) -> bool {
        self.stopped
    }

    pub(crate) fn stop_job(&mut self, uid: u32, sig: signal::Signal) {
        if self.stopped {
            return;
        }
        let mut registry = self.registry.lock().unwrap();
        if sig != signal::SIGSTOP && !registry.has_job_control(self.pid).unwrap_or(false) {
            return;
        }
        self.stopped = true;
        let report = Report::job(sig, code::CLD_STOPPED);
        registry.record_job(
            self.pid,
            Job::Stopped {
                signal: sig,
                waited: false,
            },
            Some(report.origin(self.pid, uid)),
        );
    }

    pub(crate) fn resume_job(&mut self, uid: u32, sig: signal::Signal) {
        if !std::mem::take(&mut self.stopped) {
            return;
        }
        let (state, origin) = if sig == signal::SIGCONT {
            let report = Report::job(sig, code::CLD_CONTINUED);
            (Job::Continued, Some(report.origin(self.pid, uid)))
        } else {
            (Job::Running, None)
        };
        self.registry
            .lock()
            .unwrap()
            .record_job(self.pid, state, origin);
    }

    fn take_signals(&self) -> Vec<Delivery> {
        std::mem::take(&mut self.registry.lock().unwrap().pending_signals)
    }

    fn take_job_changes(&self) -> Vec<JobChange> {
        std::mem::take(&mut self.registry.lock().unwrap().job_changes)
    }

    pub(crate) fn setpgid(&self, pid: i32, group: i32) -> Result<(), Errno> {
        let mut registry = self.registry.lock().unwrap();
        let caller_session = registry.identity(self.pid)?.session;
        let pid = if pid == 0 { self.pid } else { pid };
        let target = registry.identity(pid)?;
        if pid != self.pid {
            if !registry.descends_from(pid, self.pid) {
                return Err(Errno::ESRCH);
            }
            if target.session != caller_session {
                return Err(Errno::EPERM);
            }
            if registry.live_child(pid)?.execed {
                return Err(Errno::EACCES);
            }
        }
        if target.session == pid {
            return Err(Errno::EPERM);
        }
        if group < 0 {
            return Err(Errno::EINVAL);
        }
        let group = if group == 0 { pid } else { group };
        if group != pid && registry.group_session(group) != Some(caller_session) {
            return Err(Errno::EPERM);
        }
        registry
            .children
            .get_mut(&pid)
            .expect("live child")
            .identity
            .group = group;
        Ok(())
    }

    pub(crate) fn setsid(&self) -> Result<i32, Errno> {
        let mut registry = self.registry.lock().unwrap();
        if registry.group_session(self.pid).is_some() {
            return Err(Errno::EPERM);
        }
        registry
            .children
            .get_mut(&self.pid)
            .expect("live child")
            .identity = Identity {
            group: self.pid,
            session: self.pid,
        };
        Ok(self.pid)
    }

    pub(super) fn mark_execed(&self) {
        if self.pid != ROOT_PID {
            self.registry
                .lock()
                .unwrap()
                .children
                .get_mut(&self.pid)
                .expect("live child")
                .execed = true;
        }
    }

    fn exit(&self, pid: i32, report: Option<Report>) {
        let mut registry = self.registry.lock().unwrap();
        if let Some(report) = report {
            registry.children.get_mut(&pid).expect("live child").report = Some(report);
        } else {
            registry.children.remove(&pid);
        }
        // Process 1 has no guest task in this session. It reaps orphans.
        registry.children.retain(|_, child| {
            if child.parent != pid {
                return true;
            }
            child.parent = 1;
            child.report.is_none()
        });
    }
}

impl Report {
    fn job(signal: signal::Signal, code: i32) -> Self {
        Self {
            status: (signal << 8) | 0x7f,
            code,
            value: signal,
            user_ns: 0,
            system_ns: 0,
        }
    }

    pub(crate) fn is_exit(self) -> bool {
        matches!(
            self.code,
            code::CLD_EXITED | code::CLD_KILLED | code::CLD_DUMPED
        )
    }

    fn origin(self, pid: i32, uid: u32) -> signal::Origin {
        signal::Origin {
            pid,
            uid,
            status: self.status,
            code: self.code,
        }
    }

    fn exit(proc: &Proc, status: ExitStatus) -> Self {
        let (status, code, value) = match status {
            ExitStatus::Exited(value) => ((value & 0xff) << 8, code::CLD_EXITED, value),
            ExitStatus::Signaled { signo, core, .. } => (
                signo | if core { 0x80 } else { 0 },
                if core {
                    code::CLD_DUMPED
                } else {
                    code::CLD_KILLED
                },
                signo,
            ),
            ExitStatus::Internal(_) => unreachable!("internal failure stops the session"),
        };
        let (mut user_ns, mut system_ns) = proc.task.dead_times;
        for thread in proc.threads.values() {
            user_ns = user_ns.saturating_add(thread.mach.user_ns);
            system_ns = system_ns.saturating_add(thread.mach.system_ns);
        }
        Self {
            status,
            code,
            value,
            user_ns,
            system_ns,
        }
    }
}

#[derive(Default)]
pub(super) struct Scheduler {
    active: BTreeMap<i32, DarwinProcess>,
    last: i32,
    blocked: usize,
}

impl Scheduler {
    pub(super) fn drive(
        &mut self,
        root: &mut DarwinProcess,
        turns: Option<u64>,
        cancelled: Option<&AtomicBool>,
    ) -> RunStatus {
        for _ in 0..turns.unwrap_or(u64::MAX) {
            if let Some(status) = &root.terminal {
                return RunStatus::Complete(status.clone());
            }
            if cancelled.is_some_and(|flag| flag.load(Ordering::Acquire)) {
                return RunStatus::Cancelled;
            }
            let next = self
                .active
                .range((self.last + 1)..)
                .next()
                .map(|(&pid, _)| pid);
            let pid = next.unwrap_or(root.proc.pid);
            let process = if pid == root.proc.pid {
                &mut *root
            } else {
                self.active.get_mut(&pid).expect("selected process")
            };
            if self.last != pid
                && let Some(thread) = process.proc.threads.get_mut(&process.last)
            {
                super::clear_exclusive_on_switch(0, thread.tid, &mut thread.cpu);
            }
            self.last = pid;
            let outcome = process.drive(Some(1), cancelled);
            let spawned = std::mem::take(&mut process.proc.spawned);
            let deliveries = process
                .proc
                .family
                .as_ref()
                .expect("closed process")
                .take_signals();
            for child in spawned {
                self.active
                    .insert(child.pid, DarwinProcess::from_proc(child));
            }
            for delivery in deliveries {
                let target = if delivery.pid == ROOT_PID {
                    &mut *root
                } else {
                    self.active
                        .get_mut(&delivery.pid)
                        .expect("live signal target")
                };
                signal::psignal(&mut target.proc, None, delivery.signal, delivery.origin);
            }
            let changes = root
                .proc
                .family
                .as_ref()
                .expect("closed root")
                .take_job_changes();
            for change in changes {
                let parent = if change.parent == root.proc.pid {
                    Some(&mut *root)
                } else {
                    self.active.get_mut(&change.parent)
                };
                if let Some(parent) = parent {
                    self.blocked = 0;
                    parent.proc.post(wait::WaitKey::Child);
                    if change.origin.code == code::CLD_STOPPED && !parent.proc.sigacts.nocldstop {
                        parent.proc.sigacts.origin = change.origin;
                        signal::psignal(&mut parent.proc, None, signal::SIGCHLD, change.origin);
                    }
                }
            }
            match outcome {
                RunStatus::Complete(status) if pid == root.proc.pid => {
                    self.active.clear();
                    return RunStatus::Complete(status);
                }
                RunStatus::Complete(ExitStatus::Internal(error)) => {
                    let status = ExitStatus::Internal(format!("Darwin child {pid}: {error}"));
                    root.proc.exit_with(status.clone());
                    root.terminal = Some(status.clone());
                    self.active.clear();
                    return RunStatus::Complete(status);
                }
                RunStatus::Complete(status) => {
                    self.finish(root, pid, status);
                    self.blocked = 0;
                }
                RunStatus::Cancelled => return RunStatus::Cancelled,
                RunStatus::BudgetExhausted => self.blocked = 0,
                RunStatus::Blocked => {
                    self.blocked += 1;
                    if self.blocked == self.active.len() + 1 {
                        self.blocked = 0;
                        if turns.is_some() {
                            return RunStatus::Blocked;
                        }
                        // The closed profile supplies no host wake descriptors.
                        let deadline = std::iter::once(&*root)
                            .chain(self.active.values())
                            .filter_map(|process| process.idle_deadline())
                            .min();
                        if deadline.is_none() {
                            root.proc.exit_with(ExitStatus::Internal(
                                "deadlock: every guest process is waiting".into(),
                            ));
                        } else {
                            wait::sleep(&[], deadline);
                        }
                    }
                }
            }
        }
        RunStatus::BudgetExhausted
    }

    fn finish(&mut self, root: &mut DarwinProcess, pid: i32, status: ExitStatus) {
        let process = self.active.remove(&pid).expect("finished child");
        let parent = process.proc.ppid;
        let member = process.proc.family.as_ref().expect("closed child");
        let report = Report::exit(&process.proc, status);
        for child in self.active.values_mut().filter(|c| c.proc.ppid == pid) {
            child.proc.ppid = 1;
        }
        let parent = if parent == root.proc.pid {
            Some(root)
        } else {
            self.active.get_mut(&parent)
        };
        member.exit(
            pid,
            parent
                .as_ref()
                .filter(|p| !p.proc.sigacts.nocldwait)
                .map(|_| report),
        );
        if let Some(parent) = parent {
            parent.proc.post(wait::WaitKey::Child);
            if !parent.proc.sigacts.nocldwait {
                let origin = report.origin(pid, process.proc.creds.0);
                signal::psignal(&mut parent.proc, None, signal::SIGCHLD, origin);
            }
        }
    }
}
