//! Process creation in the closed Linux personality.

use super::super::super::process::{LinuxProcess, Thread};
use super::super::super::signal::AltStack;
use super::*;
use std::sync::{Arc, Mutex};

pub(super) fn fork(c: &mut Ctx<'_>, args: ForkArgs) -> Result<Outcome, Errno> {
    let flags = args.flags;
    let shared = flags & CLONE_VM != 0;
    if shared && c.p.shares_mm() {
        return Err(Errno(ENOSYS));
    }
    if flags & (CLONE_FS | CLONE_SIGHAND | CLONE_PARENT | CLONE_INTO_CGROUP) != 0 {
        return Err(Errno(EINVAL));
    }
    let requested = super::super::thread::requested_tid(c, &args.set_tid)?;
    if flags & CLONE_PIDFD != 0 {
        super::super::pidfd::clone_check(c, args.pidfd)?;
    }
    let sched = c.t.sched.forked(flags & CLONE_IO != 0)?;
    let tls = if flags & CLONE_SETTLS != 0 {
        Some(super::super::thread::NewTls::new(c, args.tls)?)
    } else {
        None
    };
    let tid =
        c.p.children
            .reserve_guest_id(requested, Some(c.p.config.arena_bytes))?;
    let pid = tid.id();

    let (space, mm) = if shared {
        (c.p.space.clone(), Arc::clone(&c.p.mm))
    } else {
        // Snapshot failure leaves the source address space and child list intact.
        let space = c.p.space.process_snapshot().map_err(|_| Errno(ENOMEM))?;
        let mm = c.p.mm().fork_private(&space).map_err(|_| Errno(ENOMEM))?;
        (space, Arc::new(Mutex::new(mm)))
    };
    let mut cpu = c.t.cpu.clone_to_space(&space);
    cpu.set_syscall_result(0);
    if args.stack != 0 {
        cpu.set_sp(args.stack);
    }
    if let Some(tls) = tls {
        tls.apply(&mut cpu);
    }
    let mut leader = Thread::new(pid, cpu);
    leader.sigmask = c.t.sigmask;
    leader.altstack = if shared && flags & CLONE_VFORK == 0 {
        AltStack::DISABLED
    } else {
        c.t.altstack
    };
    leader.comm = c.t.comm.clone();
    leader.no_new_privs = c.t.no_new_privs;
    leader.notsc = c.t.notsc;
    leader.cpu.set_tsc_disabled(leader.notsc);
    leader.seccomp = c.t.seccomp.clone();
    leader.sched = sched;
    if !shared {
        leader.rseq = c.t.rseq.clone();
    }
    if flags & CLONE_CHILD_SETTID != 0 {
        leader.set_child_tid = args.child_tid;
    }
    if flags & CLONE_CHILD_CLEARTID != 0 {
        leader.clear_child_tid = args.child_tid;
    }
    let mut sigactions = c.p.sigactions;
    if flags & CLONE_CLEAR_SIGHAND != 0 {
        clear_sighand(&mut sigactions);
    }

    let p = &mut *c.p;
    let state = ProcState {
        abi: p.abi,
        space,
        vfs: p.vfs.clone(),
        fds: if flags & CLONE_FILES != 0 {
            p.fds.share()
        } else {
            p.fds.clone()
        },
        #[cfg(unix)]
        socket_paths: Default::default(),
        pid,
        ppid: p.pid,
        creds: p.creds,
        groups: p.groups.clone(),
        mm,
        rlimits: p.rlimits,
        umask: p.umask,
        sigactions,
        comm: leader.comm.clone(),
        exe_path: p.exe_path.clone(),
        exe_host_path: None,
        auxv: p.auxv.clone(),
        cmdline: p.cmdline.clone(),
        environ: p.environ.clone(),
        entropy: p.entropy.forked(pid),
        config: p.config.clone(),
        exit: None,
        next_tid: pid + 1,
        procfs_thread_ids: super::super::super::procfs::ThreadIds::new(pid),
        persona: p.persona,
        dumpable: p.dumpable,
        pdeathsig: 0,
        shared_pending: Default::default(),
        sigtramp: p.sigtramp,
        unkillable: false,
        itimers: Default::default(),
        timers: Default::default(),
        futex: if shared {
            Arc::clone(&p.futex)
        } else {
            Default::default()
        },
        curr_target: pid,
        leader_exit: None,
        last_user: None,
        children: p.children.guest_scope(pid),
        pidfds: Default::default(),
        forked: None,
        exec_id: p.exec_id,
        ipc: super::super::super::ipc::IpcState::disabled(),
        aio: Default::default(),
        parent_link: None,
        tracees: Default::default(),
        adopted: Vec::new(),
        ancestor_pids: Vec::new(),
        tracer_link: None,
        group_stop: None,
        #[cfg(unix)]
        fsnotify: None,
        exec_keep: p.exec_keep.clone(),
        locked_vm_users: Default::default(),
        uring_parked: Vec::new(),
    };
    let child = LinuxProcess {
        state,
        threads: vec![leader],
        scheduler: Default::default(),
    };
    // A copied table and private address space predate this PIDFD
    // installation and TID write. Shared resources observe them.
    if flags & CLONE_PIDFD != 0 {
        super::super::pidfd::clone_install(c, pid, pid, args.pidfd)?;
    }
    if flags & CLONE_PARENT_SETTID != 0 {
        let _ = c.write_u32(args.parent_tid, pid as u32);
    }
    c.p.children
        .add_guest(child, tid, args.exit_signal as i32, c.t.tid, c.p.exec_id);
    if flags & CLONE_VFORK != 0 {
        return vfork_wait(c, pid);
    }
    Ok(Outcome::Return(pid as u64))
}
