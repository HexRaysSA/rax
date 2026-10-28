//! Legacy task holds and the caller's hidden resume-port send rights.

use super::{MigResult, Out, Req, ids, is_task};
use crate::user::darwin::mach::{
    ipc::{KObject, Port, Right},
    kr::{self, KernReturn},
    suspend::Hold,
};
use crate::user::darwin::process::Proc;
use crate::user::darwin::syscall::{
    Ctx,
    mach::{kmsg, port},
};
use std::sync::Arc;

/// A remote server transfers this effect to the caller's IPC space.
#[derive(Debug)]
pub(crate) enum LegacyEffect {
    Suspend(Right),
    Resume {
        port: Option<Arc<Port>>,
        result: KernReturn,
    },
}

impl LegacyEffect {
    pub(crate) fn result(&self) -> KernReturn {
        match self {
            Self::Suspend(_) => 0,
            Self::Resume { result, .. } => *result,
        }
    }
}

pub(crate) fn is_legacy(id: i32) -> bool {
    matches!(id, ids::task::TASK_SUSPEND | ids::task::TASK_RESUME)
}

/// Validation precedes the hold change; a resume's namespace cleanup occurs
/// even if its hold release fails (task.c: task_resume).
pub(crate) fn perform(ctx: &mut Ctx<'_>, req: &Req) -> Result<LegacyEffect, KernReturn> {
    req.simple(24)?;
    if !is_task(ctx, req) && req.port.kobject != KObject::TaskRead {
        return Err(kr::KERN_INVALID_ARGUMENT);
    }
    match req.id {
        ids::task::TASK_SUSPEND => {
            crate::user::darwin::mach::suspend::legacy_send(ctx.proc).map(LegacyEffect::Suspend)
        }
        ids::task::TASK_RESUME => {
            let result = ctx
                .proc
                .task
                .suspension
                .release(Hold::Legacy)
                .err()
                .unwrap_or(0);
            Ok(LegacyEffect::Resume {
                port: ctx.proc.task.suspension.resume.clone(),
                result,
            })
        }
        _ => Err(kr::MIG_BAD_ID),
    }
}

/// Install one hidden uref, or consume one/all existing urefs on resume.
pub(crate) fn finish_local(proc: &mut Proc, effect: LegacyEffect) -> MigResult {
    match effect {
        LegacyEffect::Suspend(right) => {
            let port = right.port().expect("a legacy suspend makes a send").clone();
            if let Err(error) = proc.ipc.insert(right) {
                kmsg::release_send(proc, &port);
                return Err(error);
            }
        }
        LegacyEffect::Resume {
            port: Some(resume),
            result,
        } => {
            if let Some(name) = proc.ipc.name_of(&resume)
                && proc.ipc.lookup(name).is_ok_and(|entry| entry.send > 0)
            {
                if result == 0 {
                    port::deallocate(proc, name);
                } else {
                    port::destroy(proc, name);
                }
            }
            if result != 0 {
                return Err(result);
            }
        }
        LegacyEffect::Resume { port: None, result } => {
            if result != 0 {
                return Err(result);
            }
        }
    }
    Ok(Out::Simple(Vec::new()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::darwin::{
        abi::DarwinAbi,
        mach::{
            ipc::disp,
            msg::{self, Sender, bits},
        },
        process::{DarwinProcess, RunStatus, bounded_tests::process},
    };

    fn call(process: &mut DarwinProcess, id: i32, body: Vec<u8>) -> Vec<u8> {
        let reply = Port::new(KObject::None);
        reply.state.lock().unwrap().sorights = 1;
        let task = process.proc.task_port.clone();
        task.state.lock().unwrap().srights += 1;
        let request = msg::Message {
            bits: bits::set(disp::MOVE_SEND, disp::MOVE_SEND_ONCE, 0, 0),
            dest: Right::Send(task),
            reply: Some(Right::SendOnce(reply.clone())),
            voucher: None,
            voucher_name: 0,
            id,
            body,
            items: Vec::new(),
            sender: Sender::KERNEL,
            aux: Vec::new(),
        };
        let tid = *process.proc.threads.keys().next().unwrap();
        let mut thread = process.proc.threads.remove(&tid).unwrap();
        let pc = thread.cpu.pc();
        kmsg::deliver(
            &mut Ctx {
                proc: &mut process.proc,
                thread: &mut thread,
                nr: -1,
                pc,
            },
            request,
        );
        process.proc.threads.insert(tid, thread);
        let mut response = reply.state.lock().unwrap().queue.pop_front().unwrap();
        let destination = std::mem::replace(&mut response.dest, Right::Dead);
        kmsg::consume_dest(&mut process.proc, destination);
        let body = response.body.clone();
        kmsg::destroy(&mut process.proc, response);
        body
    }

    #[test]
    fn legacy_mig_installs_hidden_urefs_and_last_deallocation_releases_holds() {
        let mut process = process(DarwinAbi::Arm64);
        for count in [1, 2] {
            let reply = call(&mut process, ids::task::TASK_SUSPEND, Vec::new());
            assert_eq!(i32::from_le_bytes(reply[8..12].try_into().unwrap()), 0);
            assert_eq!(process.proc.task.suspension.count(), count);
        }
        let resume = process.proc.task.suspension.resume.clone().unwrap();
        assert_eq!(port::kobject_type(&resume.kobject), 36);
        let name = process.proc.ipc.name_of(&resume).unwrap();
        assert_eq!(process.proc.ipc.lookup(name).unwrap().send, 2);
        assert_eq!(resume.state.lock().unwrap().srights, 1);
        let pc = process.proc.threads.values().next().unwrap().cpu.pc();
        let cancelled = std::sync::atomic::AtomicBool::new(false);
        assert_eq!(process.run_slice(1, &cancelled), RunStatus::Blocked);
        assert_eq!(process.proc.threads.values().next().unwrap().cpu.pc(), pc);
        let mut info = msg::NDR_RECORD.to_vec();
        info.extend_from_slice(&20i32.to_le_bytes());
        info.extend_from_slice(&12u32.to_le_bytes());
        let reply = call(&mut process, ids::task::TASK_INFO, info);
        assert_eq!(u32::from_le_bytes(reply[60..64].try_into().unwrap()), 2);
        assert_eq!(port::deallocate(&mut process.proc, name), 0);
        assert_eq!(process.proc.task.suspension.count(), 2);
        assert_eq!(port::deallocate(&mut process.proc, name), 0);
        assert_eq!(process.proc.task.suspension.count(), 0);
        assert_eq!(resume.state.lock().unwrap().srights, 0);
        let reply = call(&mut process, ids::task::TASK_RESUME, Vec::new());
        assert_eq!(
            i32::from_le_bytes(reply[8..12].try_into().unwrap()),
            kr::KERN_FAILURE
        );
    }

    #[test]
    fn legacy_resume_consumes_one_uref_and_failed_resume_destroys_stale_urefs() {
        let mut process = process(DarwinAbi::Arm64);
        call(&mut process, ids::task::TASK_SUSPEND, Vec::new());
        call(&mut process, ids::task::TASK_SUSPEND, Vec::new());
        let resume = process.proc.task.suspension.resume.clone().unwrap();
        let name = process.proc.ipc.name_of(&resume).unwrap();
        let reply = call(&mut process, ids::task::TASK_RESUME, Vec::new());
        assert_eq!(i32::from_le_bytes(reply[8..12].try_into().unwrap()), 0);
        assert_eq!(process.proc.task.suspension.count(), 1);
        assert_eq!(process.proc.ipc.lookup(name).unwrap().send, 1);
        process.proc.task.suspension.release(Hold::Legacy).unwrap();
        let reply = call(&mut process, ids::task::TASK_RESUME, Vec::new());
        assert_eq!(
            i32::from_le_bytes(reply[8..12].try_into().unwrap()),
            kr::KERN_FAILURE
        );
        assert!(process.proc.ipc.name_of(&resume).is_none());
        assert_eq!(resume.state.lock().unwrap().srights, 0);
    }
}
