//! Guest-owned child address spaces and a single cooperative family scheduler.
//! The runnable queue is the only long-lived owner of each live child.
//! Parent handles retain a small exit record after the address space is gone.

use super::{ExitStatus, Proc, RunStatus, Thread, WindowsConfig, sched, start};
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::{ObjId, Object, Objects};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, VecDeque};
use std::fs::File;
use std::rc::{Rc, Weak};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

type Live = Rc<RefCell<Member>>;

#[derive(Default)]
pub(crate) struct Children {
    records: BTreeMap<u32, Record>,
    newborn: Vec<Live>,
}

struct Record {
    process_object: ObjId,
    thread_object: ObjId,
    info: ChildInfo,
    exit: Rc<Cell<ExitCodes>>,
    live: Weak<RefCell<Member>>,
    csr_registered: bool,
}

#[derive(Clone, Copy)]
pub(crate) struct ChildInfo {
    pub pid: u32,
    pub primary_tid: u32,
    pub peb: u64,
    pub parameters: u64,
}

#[derive(Clone, Copy, Default)]
struct ExitCodes {
    process: Option<u32>,
    thread: Option<u32>,
}

pub(crate) struct Prepared {
    proc: Proc,
    primary_object: ObjId,
    pub info: ChildInfo,
}

pub(crate) struct Handles {
    pub process: u32,
    pub thread: u32,
    process_object: ObjId,
    thread_object: ObjId,
}

#[derive(Default)]
pub(crate) struct ChildIo {
    pub(crate) objects: Objects,
    pub(crate) standard: [Option<u32>; 3],
}

impl Prepared {
    pub(crate) fn spawn(
        parent: &mut Proc,
        config: WindowsConfig,
        file: &File,
        environment: &[u8],
        image_flags: u32,
        suspended: bool,
        io: ChildIo,
    ) -> Result<Self, u32> {
        let pid = parent.allocate_client_id().ok_or(STATUS_NO_MEMORY)?;
        let ids = parent
            .family_ids
            .get_or_insert_with(|| Rc::new(Cell::new(parent.next_tid)))
            .clone();
        let child = start::ChildStart {
            pid,
            parent_pid: parent.pid,
            ids,
            environment,
            detect_manifest: image_flags & 2 != 0,
            prohibited_characteristics: (image_flags >> 16) as u16,
            io,
        };
        let proc = start::spawn_file(config, file, Some(child)).map_err(|error| {
            tracing::debug!(pid, %error, "guest child initialization failed");
            match error {
                super::SpawnError::Io(error) => file_status(&error),
                super::SpawnError::BadImage(_) => STATUS_INVALID_IMAGE_FORMAT,
                super::SpawnError::Load { status, .. } => status,
                super::SpawnError::Memory(_) => STATUS_NO_MEMORY,
            }
        })?;
        Ok(Self::new(proc, suspended))
    }

    fn new(mut proc: Proc, suspended: bool) -> Self {
        let (&primary_tid, primary) = proc.threads.first_key_value().expect("initial thread");
        let primary_object = primary.obj;
        proc.threads.get_mut(&primary_tid).unwrap().suspend = u32::from(suspended);
        // Keep the primary thread's exit code observable while other threads run.
        proc.objects.retain(primary_object);
        let info = ChildInfo {
            pid: proc.pid,
            primary_tid,
            peb: proc.peb,
            parameters: proc.params,
        };
        Self {
            proc,
            primary_object,
            info,
        }
    }

    pub(crate) fn state(&self) -> &Proc {
        &self.proc
    }

    pub(crate) fn wow64_creation_addresses(&mut self) -> Result<(u64, u64), u32> {
        let native_peb = self
            .proc
            .wow64
            .as_ref()
            .ok_or(STATUS_NOT_SUPPORTED)?
            .native_peb;
        let native_parameters = start::wow64_child_parameters(&mut self.proc, native_peb)
            .map_err(|_| STATUS_NO_MEMORY)?;
        Ok((native_parameters, native_peb))
    }

    pub(crate) fn manifest(&self) -> Option<(u64, u32)> {
        self.proc.creation_manifest
    }

    pub(crate) fn handles(
        &self,
        objects: &mut Objects,
        process_access: u32,
        thread_access: u32,
    ) -> Option<Handles> {
        let (process_object, process) = create_handle(
            objects,
            Object::Process {
                pid: self.info.pid,
                exit_code: None,
            },
            process_access,
        )?;
        let Some((thread_object, thread)) = create_handle(
            objects,
            Object::Thread {
                tid: self.info.primary_tid,
                exit_code: None,
            },
            thread_access,
        ) else {
            let _ = objects.close(process.into());
            return None;
        };
        Some(Handles {
            process,
            thread,
            process_object,
            thread_object,
        })
    }

    pub(crate) fn install(self, parent: &mut Proc, handles: Handles) {
        let Self {
            proc,
            primary_object,
            info,
        } = self;
        let exit = Rc::new(Cell::new(ExitCodes::default()));
        let live = Rc::new(RefCell::new(Member {
            proc,
            primary_object,
            scheduler: sched::Scheduler::default(),
            exit: Rc::clone(&exit),
        }));
        let record = Record {
            process_object: handles.process_object,
            thread_object: handles.thread_object,
            info,
            exit,
            live: Rc::downgrade(&live),
            csr_registered: false,
        };
        let previous = parent.children.records.insert(info.pid, record);
        debug_assert!(previous.is_none());
        parent.children.newborn.push(live);
    }
}

pub(crate) fn create_handle(
    objects: &mut Objects,
    object: Object,
    access: u32,
) -> Option<(ObjId, u32)> {
    let id = objects.try_create(object)?;
    if let Some(handle) = objects.open_access(id, false, access) {
        return Some((id, handle));
    }
    objects.release(id);
    None
}

pub(crate) fn file_status(error: &std::io::Error) -> u32 {
    use std::io::ErrorKind;
    match error.kind() {
        ErrorKind::NotFound => STATUS_OBJECT_NAME_NOT_FOUND,
        ErrorKind::NotADirectory => STATUS_OBJECT_PATH_NOT_FOUND,
        ErrorKind::PermissionDenied => STATUS_ACCESS_DENIED,
        ErrorKind::OutOfMemory => STATUS_NO_MEMORY,
        _ => STATUS_UNSUCCESSFUL,
    }
}

impl Handles {
    pub(crate) fn close(self, objects: &mut Objects) {
        let _ = objects.close(self.thread.into());
        let _ = objects.close(self.process.into());
    }
}

impl Children {
    pub(crate) fn basic(&self, pid: u32) -> Option<(ChildInfo, Option<u32>)> {
        let record = self.records.get(&pid)?;
        Some((record.info, record.exit.get().process))
    }

    pub(crate) fn with_process<T>(&self, pid: u32, f: impl FnOnce(&mut Proc) -> T) -> Option<T> {
        let live = self.records.get(&pid)?.live.upgrade()?;
        Some(f(&mut live.borrow_mut().proc))
    }

    pub(crate) fn with_csr_start<T>(
        &self,
        pid: u32,
        process: ObjId,
        thread: ObjId,
        f: impl FnOnce(&Proc) -> T,
    ) -> Option<T> {
        let record = self.records.get(&pid)?;
        if record.process_object != process
            || record.thread_object != thread
            || record.csr_registered
        {
            return None;
        }
        let live = record.live.upgrade()?;
        let member = live.borrow();
        let primary = member.proc.threads.get(&record.info.primary_tid)?;
        (primary.suspend != 0).then(|| f(&member.proc))
    }

    pub(crate) fn finish_csr_start(&mut self, pid: u32) {
        let record = self.records.get_mut(&pid).expect("validated CSR child");
        debug_assert!(!record.csr_registered);
        record.csr_registered = true;
    }

    pub(crate) fn with_thread<T>(
        &self,
        object: ObjId,
        tid: u32,
        f: impl FnOnce(&mut Thread) -> T,
    ) -> Option<T> {
        let record = self
            .records
            .values()
            .find(|record| record.thread_object == object)?;
        let live = record.live.upgrade()?;
        let mut member = live.borrow_mut();
        let thread = member.proc.threads.get_mut(&tid)?;
        Some(f(thread))
    }

    fn refresh(&mut self, objects: &mut Objects) {
        self.records.retain(|_, record| {
            let exit = record.exit.get();
            let process = objects.obj_mut(record.process_object);
            if let Some(Object::Process { exit_code, .. }) = process {
                *exit_code = exit.process;
            }
            let has_process = process.is_some();
            let thread = objects.obj_mut(record.thread_object);
            if let Some(Object::Thread { exit_code, .. }) = thread {
                *exit_code = exit.thread;
            }
            has_process || thread.is_some()
        });
    }
}

struct Member {
    proc: Proc,
    primary_object: ObjId,
    scheduler: sched::Scheduler,
    exit: Rc<Cell<ExitCodes>>,
}

impl Member {
    fn turn(&mut self, cancelled: &AtomicBool) -> RunStatus {
        self.proc.children.refresh(&mut self.proc.objects);
        let result = self.scheduler.run_slice(&mut self.proc, 1, cancelled);
        let mut exit = self.exit.get();
        if let Some(Object::Thread { exit_code, .. }) = self.proc.objects.obj(self.primary_object) {
            exit.thread = *exit_code;
        }
        if let RunStatus::Complete(ExitStatus::Exited(code)) = result {
            exit.process = Some(code);
            exit.thread.get_or_insert(code);
        }
        self.exit.set(exit);
        result
    }
}

#[derive(Default)]
pub(super) struct Scheduler {
    pub(super) root: sched::Scheduler,
    running: VecDeque<Live>,
    turns_to_root: usize,
    blocked: usize,
    terminal: Option<ExitStatus>,
}

impl Scheduler {
    pub(super) fn run(&mut self, root: &mut Proc) -> ExitStatus {
        let cancelled = AtomicBool::new(false);
        loop {
            match self.run_slice(root, 1, &cancelled) {
                RunStatus::Complete(status) => return status,
                RunStatus::Blocked => std::thread::sleep(Duration::from_millis(1)),
                RunStatus::BudgetExhausted => {}
                RunStatus::Cancelled => unreachable!("local cancellation flag"),
            }
        }
    }

    pub(super) fn run_slice(
        &mut self,
        root: &mut Proc,
        turns: u64,
        cancelled: &AtomicBool,
    ) -> RunStatus {
        if let Some(exit) = &self.terminal {
            return RunStatus::Complete(exit.clone());
        }
        for _ in 0..turns {
            if cancelled.load(Ordering::Acquire) {
                return RunStatus::Cancelled;
            }
            let result = if self.turns_to_root == 0 || self.running.is_empty() {
                root.children.refresh(&mut root.objects);
                let result = self.root.run_slice(root, 1, cancelled);
                self.running.extend(root.children.newborn.drain(..));
                self.turns_to_root = self.running.len();
                if let RunStatus::Complete(status) = result {
                    return self.finish(status);
                }
                result
            } else {
                self.turns_to_root -= 1;
                let live = self.running.pop_front().expect("scheduled child");
                let (pid, result) = {
                    let mut child = live.borrow_mut();
                    let result = child.turn(cancelled);
                    self.running.extend(child.proc.children.newborn.drain(..));
                    (child.proc.pid, result)
                };
                match result {
                    RunStatus::Complete(ExitStatus::Internal(error)) => {
                        return self.finish(ExitStatus::Internal(format!(
                            "child process {pid}: {error}"
                        )));
                    }
                    RunStatus::Complete(ExitStatus::Exited(_)) => RunStatus::BudgetExhausted,
                    _ => {
                        self.running.push_back(live);
                        result
                    }
                }
            };
            match result {
                RunStatus::Blocked => {
                    self.blocked += 1;
                    if self.blocked > self.running.len() {
                        self.blocked = 0;
                        return RunStatus::Blocked;
                    }
                }
                RunStatus::Cancelled => return result,
                _ => self.blocked = 0,
            }
        }
        RunStatus::BudgetExhausted
    }

    fn finish(&mut self, exit: ExitStatus) -> RunStatus {
        self.running.clear();
        self.terminal = Some(exit.clone());
        RunStatus::Complete(exit)
    }
}
