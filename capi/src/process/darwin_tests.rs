//! Context commits use the personality's completed-return ownership.
use super::*;
use crate::tests::macho_fixture::{ENTRY, image};
use rax_engine::user::darwin::abi::{Errno, tables::nr};
use rax_engine::user::darwin::arch::Rv;
use rax_engine::user::darwin::kevent::{Kev, Layout, ev, evfilt, kflag};
use rax_engine::user::darwin::syscall::{Ctx, bsd, bsd::file};
use rax_engine::user::darwin::workq::{priority, wqops};
use rax_engine::user::image::macho::MH_EXECUTE;

fn process(arm: bool) -> Process {
    let mut config = DarwinConfig::embedded(
        "/pipe-context",
        vec![b"/pipe-context".to_vec()],
        vec![],
        rax_engine::user::supplied_fs::Files::new(Default::default()).unwrap(),
        rax_engine::user::console::CapturedConsole::new(Vec::new(), 4096).unwrap(),
    );
    config.seed = Some(1);
    config.arena_bytes = 64 << 20;
    config.slice_insns = 1;
    Process::new(config, image(arm, &[], false, MH_EXECUTE)).unwrap()
}

#[test]
fn closed_workqueue_dispatch_setup_updates_only_guest_state() {
    for arm in [false, true] {
        let mut p = process(arm);
        let (_, mut thread) = p.0.proc.threads.pop_first().unwrap();
        assert!(!p.0.proc.config.host_services);
        let config_address = thread.cpu.sp() - 1024;
        let config = [2u64, 24, 40].map(u64::to_le_bytes).concat();
        p.0.proc.space.write(config_address, &config).unwrap();
        let mut ctx = Ctx {
            proc: &mut p.0.proc,
            thread: &mut thread,
            nr: i64::from(nr::WORKQ_OPEN),
            pc: ENTRY,
        };
        assert_eq!(
            bsd::call(&mut ctx, nr::WORKQ_OPEN, &[0; 8]),
            Err(Errno::EINVAL)
        );

        ctx.nr = i64::from(nr::BSDTHREAD_REGISTER);
        bsd::call(
            &mut ctx,
            nr::BSDTHREAD_REGISTER,
            &[ENTRY, ENTRY, 0x400, 0, 0, 0, 0, 0],
        )
        .unwrap();
        ctx.nr = i64::from(nr::WORKQ_KERNRETURN);
        let args = [
            wqops::SETUP_DISPATCH as u64,
            config_address,
            config.len() as u64,
            0,
            0,
            0,
            0,
            0,
        ];
        assert_eq!(
            bsd::call(&mut ctx, nr::WORKQ_KERNRETURN, &args),
            Ok(Rv::one(0))
        );
        assert_eq!(ctx.proc.wq.serialno_offset, 24);
        assert_eq!(ctx.proc.wq.label_offset, 40);
        assert!(!ctx.proc.wq.opened);

        ctx.nr = i64::from(nr::WORKQ_OPEN);
        assert_eq!(bsd::call(&mut ctx, nr::WORKQ_OPEN, &[0; 8]), Ok(Rv::one(0)));
        assert!(ctx.proc.wq.opened);
    }
}

#[test]
fn closed_workqueue_kevent_registers_user_events_and_rejects_host_knote() {
    for arm in [false, true] {
        let mut p = process(arm);
        let (_, mut thread) = p.0.proc.threads.pop_first().unwrap();
        let change_address = thread.cpu.sp() - 1024;
        let mut ctx = Ctx {
            proc: &mut p.0.proc,
            thread: &mut thread,
            nr: i64::from(nr::KEVENT_QOS),
            pc: ENTRY,
        };
        let mut args = [u64::MAX, change_address, 1, 0, 0, 0, 0, 0];
        assert_eq!(
            bsd::call(&mut ctx, nr::KEVENT_QOS, &args),
            Err(Errno::EPERM)
        );
        let mut change = Kev {
            ident: 1,
            filter: evfilt::USER,
            flags: ev::ADD | ev::CLEAR,
            qos: priority::EVENT_MANAGER_FLAG as i32,
            ..Default::default()
        };
        ctx.write(change_address, &change.encode(Layout::Qos))
            .unwrap();
        args[7] = u64::from(kflag::WORKQ | kflag::IMMEDIATE);
        assert_eq!(bsd::call(&mut ctx, nr::KEVENT_QOS, &args), Ok(Rv::one(0)));
        let queue = ctx.proc.kq.workq.unwrap();

        change.filter = evfilt::PROC;
        change.ident = i32::MAX as u64;
        ctx.write(change_address, &change.encode(Layout::Qos))
            .unwrap();
        assert_eq!(
            bsd::call(&mut ctx, nr::KEVENT_QOS, &args),
            Err(Errno::EPERM)
        );
        let queue = &ctx.proc.kq.kqueues[&queue];
        assert!(queue.host.is_none());
        assert_eq!(queue.knotes.len(), 1);
        assert_eq!(queue.knotes.values().next().unwrap().filter, evfilt::USER);
    }
}

#[test]
fn closed_workloop_kevent_registers_guest_events_and_rejects_host_knote() {
    for arm in [false, true] {
        let mut p = process(arm);
        let (_, mut thread) = p.0.proc.threads.pop_first().unwrap();
        let change_address = thread.cpu.sp() - 1024;
        let mut ctx = Ctx {
            proc: &mut p.0.proc,
            thread: &mut thread,
            nr: i64::from(nr::KEVENT_ID),
            pc: ENTRY,
        };
        let workloop = 1;
        let mut args = [workloop, change_address, 1, 0, 0, 0, 0, 0];
        assert_eq!(
            bsd::call(&mut ctx, nr::KEVENT_ID, &args),
            Err(Errno::EINVAL)
        );
        let mut change = Kev {
            ident: 1,
            filter: evfilt::USER,
            flags: ev::ADD | ev::CLEAR,
            qos: priority::make_from_thread_qos(priority::thread_qos::LEGACY, 0, 0) as i32,
            ..Default::default()
        };
        ctx.write(change_address, &change.encode(Layout::Qos))
            .unwrap();
        args[7] = u64::from(kflag::WORKLOOP);
        assert_eq!(bsd::call(&mut ctx, nr::KEVENT_ID, &args), Ok(Rv::one(0)));
        let queue = ctx.proc.kq.workloops[&workloop];

        change.filter = evfilt::PROC;
        change.ident = i32::MAX as u64;
        ctx.write(change_address, &change.encode(Layout::Qos))
            .unwrap();
        assert_eq!(bsd::call(&mut ctx, nr::KEVENT_ID, &args), Err(Errno::EPERM));
        let queue = &ctx.proc.kq.kqueues[&queue];
        assert!(queue.host.is_none());
        assert_eq!(queue.knotes.len(), 1);
        assert_eq!(queue.knotes.values().next().unwrap().filter, evfilt::USER);
    }
}

#[test]
fn completed_pipe_context_writes_preserve_edits_and_identical_snapshots() {
    for arm in [false, true] {
        for mode in 0..4 {
            let mut p = process(arm);
            let (tid, mut reader) = p.0.proc.threads.pop_first().unwrap();
            let mut closer = process(arm).0.proc.threads.pop_first().unwrap().1;
            let mut ctx = Ctx {
                proc: &mut p.0.proc,
                thread: &mut closer,
                nr: 42,
                pc: ENTRY,
            };
            let Rv(fd, _writer) = file::pipe(&mut ctx).unwrap();
            let buffer = reader.cpu.sp() - 1024;
            p.0.proc.space.write(buffer, &[0xa5]).unwrap();
            let next = if arm {
                p.0.proc
                    .space
                    .write_raw(ENTRY, &0xd400_1001u32.to_le_bytes())
                    .unwrap();
                for (i, value) in [fd, buffer, 1].into_iter().enumerate() {
                    reader.cpu.set_reg(i, value);
                }
                reader.cpu.set_reg(16, 3);
                ENTRY + 4
            } else {
                p.0.proc
                    .space
                    .write_raw(ENTRY, &[0x0f, 0x05, 0x90])
                    .unwrap();
                reader.cpu.set_reg(0, 0x200_0003);
                for (i, value) in [(7, fd), (6, buffer), (2, 1)] {
                    reader.cpu.set_reg(i, value);
                }
                ENTRY + 2
            };
            reader.cpu.set_pc(ENTRY);
            p.0.proc.threads.insert(tid, reader);
            assert_eq!(
                p.0.run_slice(1, &AtomicBool::new(false)),
                RunStatus::BudgetExhausted
            );
            let reader = p.0.proc.threads.get_mut(&tid).unwrap();
            assert!(reader.wait.is_some());
            assert_eq!(reader.cpu.pc(), next);
            reader.mach.suspend_count = 1;
            let mut ctx = Ctx {
                proc: &mut p.0.proc,
                thread: &mut closer,
                nr: 6,
                pc: ENTRY + 64,
            };
            assert_eq!(file::close(&mut ctx, fd as i32), Ok(Rv::one(0)));
            let tid32 = u32::try_from(tid).unwrap();
            let mut state = p.read_context(tid32).unwrap();
            let held_value = u64::from_le_bytes(state[..8].try_into().unwrap());
            let (flags, carry) = if arm { (264, 1 << 29) } else { (136, 1) };
            let held_flags = u32::from_le_bytes(state[flags..flags + 4].try_into().unwrap());
            if mode == 1 {
                state[..8].copy_from_slice(&0x1234u64.to_le_bytes());
                state[flags..flags + 4].copy_from_slice(&(held_flags | carry).to_le_bytes());
            }
            if mode == 3 {
                let original = state.clone();
                state.pop();
                assert!(p.write_context(tid32, &state).is_err());
                assert_eq!(p.read_context(tid32).unwrap(), original);
            } else if mode != 0 {
                p.write_context(tid32, &state).unwrap();
            }
            assert_eq!(
                p.0.run_slice(1, &AtomicBool::new(false)),
                RunStatus::Blocked
            );
            p.0.proc.threads.get_mut(&tid).unwrap().mach.suspend_count = 0;
            assert_eq!(
                p.0.run_slice(1, &AtomicBool::new(false)),
                RunStatus::BudgetExhausted
            );
            let state = p.read_context(tid32).unwrap();
            let value = u64::from_le_bytes(state[..8].try_into().unwrap());
            let flags = u32::from_le_bytes(state[flags..flags + 4].try_into().unwrap());
            let expected = match mode {
                1 => 0x1234,
                2 => held_value,
                _ => 0,
            };
            assert_eq!(value, expected, "arm={arm} mode={mode}");
            assert_eq!(
                flags & carry != 0,
                mode == 1 || mode == 2 && held_flags & carry != 0
            );
            assert_eq!(p.0.proc.threads[&tid].cpu.pc(), next);
            let mut byte = [0];
            p.0.proc.space.read(buffer, &mut byte).unwrap();
            assert_eq!(byte, [0xa5]);
        }
    }
}
