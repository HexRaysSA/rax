//! Exercise closed child creation and wait through the portable BSD dispatcher.

use super::*;
use crate::user::darwin::abi::{Errno, tables::nr};
use crate::user::darwin::arch::{Rv, SysResult};
use crate::user::darwin::exec::spawn::flag;
use crate::user::darwin::syscall::{Ctx, bsd};

fn call(proc: &mut Proc, thread: &mut Thread, number: u32, registers: &[u64]) -> SysResult {
    let mut ctx = Ctx {
        proc,
        thread,
        nr: i64::from(number),
        pc: ENTRY,
    };
    let mut args = [0; 8];
    args[..registers.len()].copy_from_slice(registers);
    bsd::call(&mut ctx, number, &args)
}

fn read_u32(proc: &Proc, address: u64) -> u32 {
    let mut bytes = [0; 4];
    proc.space.read(address, &mut bytes).unwrap();
    u32::from_le_bytes(bytes)
}

#[test]
fn closed_spawn_inherits_pipe_and_wait_reaps_only_after_copyout() {
    for abi in [DarwinAbi::Arm64, DarwinAbi::X86_64] {
        let mut process = process(abi);
        let (tid, mut parent) = process.proc.threads.pop_first().unwrap();
        let path = parent.cpu.sp() - 0xc00;
        let pid_out = path + 0x40;
        let status = path + 0x48;
        let info = path + 0x50;
        let descriptor = path + 0xd0;
        let attributes = path + 0x170;
        let actions = path + 0x250;
        let proc = &mut process.proc;
        let parent_pid = proc.pid;
        proc.space.write(path, b"/missing\0").unwrap();
        proc.space.write(pid_out, &u32::MAX.to_le_bytes()).unwrap();
        assert_eq!(
            call(
                proc,
                &mut parent,
                nr::POSIX_SPAWN,
                &[pid_out, path, 0, 0, 0]
            ),
            Err(Errno::ENOENT)
        );
        assert_eq!(read_u32(proc, pid_out), u32::MAX);
        assert_eq!(
            call(proc, &mut parent, nr::WAIT4, &[u64::MAX, 0, 1, 0]),
            Err(Errno::ECHILD)
        );

        proc.space.write(path, b"/bounded-test\0").unwrap();
        let (_, saved_limit) = proc.rlimits[7];
        let limit = proc.rlimits[7].0;
        proc.rlimits[7] = (1, saved_limit);
        assert_eq!(
            call(
                proc,
                &mut parent,
                nr::POSIX_SPAWN,
                &[pid_out, path, 0, 0, 0]
            ),
            Err(Errno::EAGAIN)
        );
        proc.rlimits[7] = (limit, saved_limit);

        let Rv(reader, writer) = call(proc, &mut parent, nr::PIPE, &[]).unwrap();
        let mut file_actions = [0; 1048];
        file_actions[4..8].copy_from_slice(&1i32.to_le_bytes());
        file_actions[8..12].copy_from_slice(&2i32.to_le_bytes()); // dup2
        file_actions[12..16].copy_from_slice(&(writer as i32).to_le_bytes());
        file_actions[16..20].copy_from_slice(&1i32.to_le_bytes());
        proc.space.write(actions, &file_actions).unwrap();
        let mut attrs = [0; 192];
        attrs[..2].copy_from_slice(&(flag::SETPGROUP | flag::CLOEXEC_DEFAULT).to_le_bytes());
        proc.space.write(attributes, &attrs).unwrap();
        let mut desc = [0; 144];
        for (slot, word) in desc
            .chunks_exact_mut(8)
            .zip([192u64, attributes, 1048, actions])
        {
            slot.copy_from_slice(&word.to_le_bytes());
        }
        proc.space.write(descriptor, &desc).unwrap();
        assert_eq!(
            call(
                proc,
                &mut parent,
                nr::POSIX_SPAWN,
                &[pid_out, path, descriptor, 0, 0]
            ),
            Ok(Rv::one(0))
        );
        let child = u64::from(read_u32(proc, pid_out));
        assert_ne!(child, parent_pid as u64);
        let started = &proc.spawned[0];
        assert_eq!(started.ppid, parent_pid);
        assert!(Arc::ptr_eq(
            &started.fds.file(1).unwrap(),
            &proc.fds.file(writer as i32).unwrap(),
        ));
        assert!(started.fds.get(reader as i32).is_err());
        assert_eq!(
            call(proc, &mut parent, nr::GETPGID, &[child]),
            Ok(Rv::one(child))
        );
        assert_eq!(
            call(proc, &mut parent, nr::GETSID, &[child]),
            Ok(Rv::one(parent_pid as u64))
        );
        assert_eq!(
            call(proc, &mut parent, nr::WAIT4, &[0, status, 1, 0]),
            Err(Errno::ECHILD),
        );
        assert_eq!(
            call(
                proc,
                &mut parent,
                nr::WAIT4_NOCANCEL,
                &[child, status, 1, 0]
            ),
            Ok(Rv::one(0)),
        );
        assert_eq!(
            call(proc, &mut parent, nr::CLOSE, &[writer]),
            Ok(Rv::one(0))
        );
        parent.wait = Some(Wait::key(WaitKey::Address(0), None));
        proc.threads.insert(tid, parent);
        let cancelled = AtomicBool::new(true);
        assert_eq!(process.run_slice(1, &cancelled), RunStatus::Cancelled);
        cancelled.store(false, Ordering::Release);
        let outcome = (0..100)
            .map(|_| process.run_slice(1, &cancelled))
            .find(|result| *result != RunStatus::BudgetExhausted);
        assert_eq!(outcome, Some(RunStatus::Blocked));

        let proc = &mut process.proc;
        let (_, mut parent) = proc.threads.pop_first().unwrap();
        assert_eq!(
            call(proc, &mut parent, nr::READ, &[reader, path, 1]),
            Ok(Rv::one(0)),
        );
        assert_eq!(
            call(proc, &mut parent, nr::WAIT4, &[child, 1, 0, 0]),
            Err(Errno::EFAULT),
        );
        assert_eq!(
            call(proc, &mut parent, nr::WAITID, &[2, child, info, 0x24]),
            Ok(Rv::one(0)),
        );
        assert_eq!(read_u32(proc, info), signal::SIGCHLD as u32);
        assert_eq!(read_u32(proc, info + 8), 1); // CLD_EXITED
        assert_eq!(read_u32(proc, info + 12), child as u32);
        assert_eq!(read_u32(proc, info + 20), 37);
        assert_eq!(
            call(proc, &mut parent, nr::GETPGID, &[child]),
            Err(Errno::ESRCH)
        );
        assert_eq!(
            call(proc, &mut parent, nr::GETSID, &[child]),
            Err(Errno::ESRCH)
        );
        assert_eq!(
            call(proc, &mut parent, nr::WAIT4, &[child, status, 0, actions]),
            Ok(Rv::one(child)),
        );
        assert_eq!(read_u32(proc, status), 37 << 8);
        assert_eq!(
            call(proc, &mut parent, nr::WAIT4, &[child, status, 0, 0]),
            Err(Errno::ECHILD),
        );
        assert_eq!(
            call(proc, &mut parent, nr::GETPGID, &[child]),
            Err(Errno::ESRCH)
        );
    }
}
