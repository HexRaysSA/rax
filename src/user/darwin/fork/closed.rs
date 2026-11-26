//! Ordinary fork inside an isolated Darwin session.

use std::collections::BTreeMap;

use super::{VM_INHERIT_NONE, inherited_task};
use crate::host::time::Instant;
use crate::user::darwin::abi::Errno;
use crate::user::darwin::abi::{self, tables::nr};
use crate::user::darwin::arch::{DarwinCpu, Rv, SysResult};
use crate::user::darwin::mach::ipc::{IpcSpace, KObject, Port, Right};
use crate::user::darwin::mach::task::ThreadMach;
use crate::user::darwin::process::{Proc, Thread};
use crate::user::darwin::signal::ThreadSig;
use crate::user::darwin::syscall::{Ctx, bsd::pthread::tag};
use crate::user::darwin::vm::{VM_INHERIT_COPY, VM_INHERIT_SHARE, VM_PROT_WRITE, VmFlags};
use crate::user::mm::{Backing, Perms};

pub(super) fn fork(ctx: &mut Ctx<'_>) -> SysResult {
    let parent = &*ctx.proc;
    let running = &*ctx.thread;
    let mappings = parent.space.vma_snapshot();
    for mapping in &mappings {
        let flags = VmFlags::from_bits(mapping.flags);
        if flags.default_shared_region_inheritance() {
            continue;
        }
        // A change between private and shared inheritance needs a new
        // backing object. Reject it until both views can be changed together.
        let can_write =
            flags.max_prot() & VM_PROT_WRITE != 0 || mapping.perms.contains(Perms::WRITE);
        let needs_new_backing = match flags.inheritance() {
            VM_INHERIT_SHARE => !mapping.shared && can_write,
            VM_INHERIT_COPY => {
                mapping.shared && (can_write || matches!(&mapping.backing, Backing::Shared { .. }))
            }
            _ => false,
        };
        if needs_new_backing {
            return Err(Errno::ENOTSUP);
        }
    }
    let member = parent.family.as_ref().expect("closed process");
    let (pid, child_member) =
        member.prepare_child(parent.config.arena_bytes, parent.rlimits[7].0, None, false)?;

    // Every other guest thread is paused in this scheduler turn. A
    // failed snapshot leaves the caller's mappings and descriptors intact.
    let space = parent.space.process_snapshot().map_err(|_| Errno::ENOMEM)?;
    for vma in mappings {
        if VmFlags::from_bits(vma.flags).inheritance() == VM_INHERIT_NONE {
            space
                .unmap(vma.start, vma.len())
                .map_err(|_| Errno::ENOMEM)?;
        }
    }
    space.track_residency();
    let mut cpu = match &running.cpu {
        DarwinCpu::Arm64(cpu) => DarwinCpu::Arm64(cpu.clone_to_space(&space)),
        DarwinCpu::X86_64(cpu) => DarwinCpu::X86_64(cpu.clone_to_space(&space)),
    };
    cpu.set_unix_result(abi::bsd_syscall(nr::FORK).ret, Ok(Rv(pid as u64, 1)));

    let tid = ((pid as u64) << 20) | 1;
    let mut ipc = IpcSpace::new();
    let task_port = Port::new(KObject::Task);
    task_port.state.lock().unwrap().srights += 1;
    ipc.insert(Right::Send(task_port.clone()))
        .expect("a fresh space has room");
    let kport = Port::new(KObject::Thread(tid));
    kport.state.lock().unwrap().srights += 1;
    let thread_port = ipc
        .insert(Right::Send(kport.clone()))
        .expect("a fresh space has room");
    let thread = Thread {
        tid,
        port: thread_port,
        kport,
        cpu,
        sig: ThreadSig {
            mask: running.sig.oldmask.unwrap_or(running.sig.mask),
            ..Default::default()
        },
        wait: None,
        resume: None,
        pending_unix: None,
        file_io: None,
        pending_spawn: None,
        pthread: running.pthread,
        exited: false,
        woken: false,
        wake_event: false,
        mach: ThreadMach {
            tag: tag::MAINTHREAD,
            ..Default::default()
        },
        name: Vec::new(),
        pw: Default::default(),
        assumed: None,
    };
    let mut sigacts = parent.sigacts.clone();
    sigacts.origin = Default::default();
    sigacts.nocldstop = false;
    sigacts.nocldwait = false;
    let mut audit = parent.audit;
    audit[5] = pid as u32;
    audit[7] = 1;
    let child = Proc {
        abi: parent.abi,
        space,
        vm: parent.vm,
        vfs: parent.vfs.clone(),
        cwd: parent.cwd.clone(),
        cwd_directory: parent.cwd_directory.clone(),
        fds: crate::user::darwin::exec::fdt_fork(&parent.fds, false),
        closers: Default::default(),
        pid,
        ppid: parent.pid,
        creds: parent.creds,
        program: parent.program.clone(),
        config: parent.config.clone(),
        exit: None,
        ipc,
        task_port,
        host_port: parent.host_port.clone(),
        threads: BTreeMap::from([(tid, thread)]),
        next_tid: tid + 1,
        entropy: parent.entropy.for_child(pid),
        pauth: parent.pauth.clone(),
        rlimits: parent.rlimits,
        exec_cpu_ns: Default::default(),
        child_usage: Default::default(),
        umask: parent.umask,
        sigacts,
        itimers: Default::default(),
        mk_timers: Default::default(),
        vouchers: Default::default(),
        pthread: parent.pthread,
        psynch: Default::default(),
        kq: Default::default(),
        wq: Default::default(),
        children: Default::default(),
        family: Some(child_member),
        spawned: Vec::new(),
        hidden: Default::default(),
        machine: parent.machine,
        shared_region: parent.shared_region.clone(),
        started: Instant::now(),
        posted: Vec::new(),
        task: inherited_task(&parent.task),
        audit,
        exec: None,
        execed: false,
        tracing: Default::default(),
        guard_ast: None,
        bridge: crate::user::darwin::bridge::Bridge::isolated(),
        codesign: parent.codesign.clone(),
    };
    ctx.proc.enqueue_child(child, false);
    Ok(Rv(pid as u64, 0))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::user::darwin::abi::DarwinAbi;
    use crate::user::darwin::process::bounded_tests;
    use crate::user::darwin::syscall::bsd;
    use crate::user::darwin::vm;

    fn map(proc: &mut Proc, thread: &mut Thread, shared: bool) -> u64 {
        let length = proc.vm.page;
        let mut ctx = Ctx {
            proc,
            thread,
            nr: i64::from(nr::MMAP),
            pc: 0,
        };
        let flags = 0x1000 | if shared { 1 } else { 2 }; // MAP_ANON | MAP_{SHARED,PRIVATE}
        bsd::call(
            &mut ctx,
            nr::MMAP,
            &[0, length, 3, flags, u64::MAX, 0, 0, 0],
        )
        .unwrap()
        .0
    }

    #[test]
    fn fork_copies_private_pages_preserves_shared_pages_and_omits_none() {
        for abi in [DarwinAbi::Arm64, DarwinAbi::X86_64] {
            let mut process = bounded_tests::process(abi);
            let (_, mut current) = process.proc.threads.pop_first().unwrap();
            let proc = &mut process.proc;
            let private = map(proc, &mut current, false);
            let shared = map(proc, &mut current, true);
            let omitted = map(proc, &mut current, false);
            let cache_data = map(proc, &mut current, false);
            let cache_flags = VmFlags::new(VM_PROT_WRITE, VM_INHERIT_SHARE, 0).in_shared_region();
            proc.space
                .set_flags(cache_data, proc.vm.page, u32::MAX, cache_flags.bits())
                .unwrap();
            proc.space.write(private, &[17]).unwrap();
            proc.space.write(shared, &[19]).unwrap();
            proc.space.write(omitted, &[13]).unwrap();
            proc.space.write(cache_data, &[21]).unwrap();

            let mut ctx = Ctx {
                proc,
                thread: &mut current,
                nr: i64::from(nr::FORK),
                pc: 0,
            };
            let page = ctx.proc.vm.page;
            let inherit = |ctx: &mut Ctx<'_>, addr, policy| {
                bsd::call(
                    ctx,
                    nr::MINHERIT,
                    &[addr, page, policy as u64, 0, 0, 0, 0, 0],
                )
                .unwrap();
            };
            inherit(&mut ctx, omitted, VM_INHERIT_NONE);
            inherit(&mut ctx, cache_data, VM_INHERIT_SHARE);
            assert_eq!(bsd::call(&mut ctx, nr::FORK, &[0; 8]), Err(Errno::ENOTSUP));
            assert!(ctx.proc.spawned.is_empty());
            // Recreate the default loader attributes, without the guest override.
            ctx.proc
                .space
                .set_flags(cache_data, page, u32::MAX, cache_flags.bits())
                .unwrap();
            let Rv(pid, other) = bsd::call(&mut ctx, nr::FORK, &[0; 8]).unwrap();
            assert_ne!(pid, ctx.proc.pid as u64);
            assert_eq!(other, 0);
            let child = &ctx.proc.spawned[0];
            assert_eq!(child.ppid, ctx.proc.pid);
            assert_eq!(child.threads.len(), 1);
            assert!(!child.execed);
            assert!(Arc::ptr_eq(
                &child.fds.file(1).unwrap(),
                &ctx.proc.fds.file(1).unwrap()
            ));
            let cpu = &child.threads.first_key_value().unwrap().1.cpu;
            let returned = match cpu {
                DarwinCpu::Arm64(cpu) => (cpu.core().get_x(0), cpu.core().get_x(1)),
                DarwinCpu::X86_64(cpu) => {
                    let regs = cpu.vcpu().user_regs();
                    (regs.rax, regs.rdx)
                }
            };
            assert_eq!(returned, (pid, 1));
            let mut observed = [0; 1];
            child.space.read(private, &mut observed).unwrap();
            assert_eq!(observed, [17]);
            child.space.read(shared, &mut observed).unwrap();
            assert_eq!(observed, [19]);
            assert!(child.space.read(omitted, &mut observed).is_err());
            ctx.proc.space.read(omitted, &mut observed).unwrap();
            assert_eq!(observed, [13]);
            child.space.write(private, &[23]).unwrap();
            child.space.write(shared, &[29]).unwrap();
            child.space.read(cache_data, &mut observed).unwrap();
            assert_eq!(observed, [21]);
            child.space.write(cache_data, &[31]).unwrap();
            ctx.proc.space.read(private, &mut observed).unwrap();
            assert_eq!(observed, [17]);
            ctx.proc.space.read(shared, &mut observed).unwrap();
            assert_eq!(observed, [29]);
            ctx.proc.space.read(cache_data, &mut observed).unwrap();
            assert_eq!(observed, [21]);
        }
    }
}
