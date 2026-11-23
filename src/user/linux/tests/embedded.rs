//! Closed embedding boundary through each guest's actual syscall dispatch.
use super::harness::Harness;
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::{LinuxAbi, Sysno};
use crate::user::linux::sched::RunStatus;
use crate::user::linux::{LinuxConfig, LinuxProcess};
use std::sync::atomic::AtomicBool;
const ABIS: [LinuxAbi; 5] = [
    LinuxAbi::X86_64,
    LinuxAbi::I386,
    LinuxAbi::Aarch64,
    LinuxAbi::Arm,
    LinuxAbi::Riscv64,
];

#[test]
fn closed_linux_identity_console_and_external_service_denial_all_abis() {
    for abi in ABIS {
        let mut h = Harness::embedded(abi);
        assert!(!h.proc.state.config.host_services);
        assert_eq!(h.proc.state.creds, (0, 0, 0, 0));
        assert!(h.proc.state.groups.is_empty());
        assert_eq!(h.proc.state.umask, 0o022);
        assert_eq!(
            h.proc.state.config.fsnotify,
            crate::user::linux::fsnotify::Backend::Disabled
        );
        #[cfg(unix)]
        assert!(h.proc.state.fsnotify.is_none());
        assert!(h.proc.state.ipc.ns.dir().as_os_str().is_empty());
        assert_eq!(
            h.proc
                .state
                .ipc
                .ns
                .locked("probe", || Ok(()))
                .unwrap_err()
                .0,
            EPERM
        );
        assert_eq!(h.ok(Sysno::Getpid, &[]), 100);
        assert_eq!(h.ok(Sysno::Gettid, &[]), 100);
        assert_eq!(h.ok(Sysno::Getppid, &[]), 1);
        assert_eq!(h.ok(Sysno::Getpgid, &[0]), 100);
        assert_eq!(h.ok(Sysno::Getsid, &[0]), 100);
        assert_eq!(h.call(Sysno::Getpgid, &[123456]), -(ESRCH as i64));
        let at = h.scratch;
        h.ok(Sysno::Uname, &[at]);
        let mut node = [0; 65];
        h.proc.space().read(at + 65, &mut node).unwrap();
        assert_eq!(&node[..13], b"rax-embedded\0");
        h.proc.space().write_raw(at, b"closed output").unwrap();
        assert_eq!(h.ok(Sysno::Write, &[1, at, 13]), 13);
        let crate::user::console::Console::Captured(console) = &h.proc.state.config.console else {
            panic!()
        };
        let mut output = [0; 13];
        assert_eq!(
            console
                .drain(crate::user::console::OutputStream::Stdout, &mut output)
                .unwrap(),
            13
        );
        assert_eq!(&output, b"closed output");
        // Exercise each available ABI number; absence in an ABI is asserted by
        // its syscall table tests, not treated as runtime support here.
        for syscall in [
            Sysno::Socket,
            Sysno::Socketcall,
            Sysno::Ipc,
            Sysno::Shmget,
            Sysno::Semget,
            Sysno::Msgget,
            Sysno::MqOpen,
            Sysno::InotifyInit1,
            Sysno::IoSetup,
            Sysno::IoUringSetup,
            Sysno::Ptrace,
            Sysno::ProcessVmReadv,
            Sysno::ProcessVmWritev,
            Sysno::Mount,
        ] {
            if abi.number(syscall).is_some() {
                assert_eq!(
                    h.call(syscall, &[0; 6]),
                    -(EPERM as i64),
                    "{abi:?} {syscall:?}"
                );
            }
        }
        assert_eq!(h.err(Sysno::PidfdOpen, &[123456, 0]), ESRCH);
        assert_eq!(h.err(Sysno::PidfdOpen, &[1, 0]), ESRCH);
        assert_eq!(h.err(Sysno::PidfdOpen, &[0, 0]), EINVAL);
        assert_eq!(h.call(Sysno::Kill, &[123456, 0]), -(ESRCH as i64));
        assert_eq!(h.call(Sysno::Kill, &[100, 0]), 0);
    }
}

#[test]
fn closed_linux_process_groups_isolate_signals_and_select_waiters_all_abis() {
    use crate::user::linux::signal::{SIGCHLD, SIGKILL};
    use crate::user::linux::syscall::Call;

    for abi in ABIS {
        let mut h = Harness::embedded(abi);
        let entry = super::harness::CODE + 0x1000;
        h.proc.space().write_raw(entry, &exit_37(abi)).unwrap();
        let [first, second, separate] =
            std::array::from_fn(|_| h.ok(Sysno::Clone, &[SIGCHLD as u64, 0, 0, 0, 0]));
        assert_eq!(h.err(Sysno::Setpgid, &[0, 0]), EPERM);
        assert_eq!(h.err(Sysno::Setsid, &[]), EPERM);
        assert_eq!(h.err(Sysno::Setpgid, &[u64::MAX, 0]), EINVAL);
        assert_eq!(h.err(Sysno::Setpgid, &[u64::MAX, 1]), ESRCH);
        assert_eq!(h.err(Sysno::Getpgid, &[u64::MAX]), ESRCH);
        assert_eq!(h.err(Sysno::Getsid, &[u64::MAX]), ESRCH);
        assert_eq!(h.err(Sysno::Setpgid, &[first, 98765]), EPERM);
        assert_eq!(h.err(Sysno::Setpgid, &[123456, 0]), ESRCH);
        assert_eq!(h.ok(Sysno::Getpgid, &[first]), 100);
        assert_eq!(h.ok(Sysno::Setpgid, &[first, 0]), 0);
        assert_eq!(h.ok(Sysno::Setpgid, &[second, first]), 0);
        assert_eq!(h.ok(Sysno::Getpgid, &[second]), first);
        assert_eq!(h.ok(Sysno::Getsid, &[second]), 100);
        {
            let child = h.proc.state.children.list[2].guest.as_mut().unwrap();
            child.syscall(0, Call::new(abi.number(Sysno::Setsid).unwrap(), [0; 6]));
            assert_eq!(child.threads[0].cpu.syscall_return_value(), separate);
        }
        assert_eq!(h.ok(Sysno::Getsid, &[separate]), separate);
        assert_eq!(h.ok(Sysno::Getpgid, &[separate]), separate);
        assert_eq!(h.err(Sysno::Setpgid, &[separate, first]), EPERM);
        assert_eq!(h.err(Sysno::Setpgid, &[first, separate]), EPERM);
        assert_eq!(h.err(Sysno::Wait4, &[0, 0, 1, 0]), ECHILD);

        let group = (-(first as i64)) as u64;
        assert_eq!(h.ok(Sysno::Kill, &[group, 0]), 0);
        assert_eq!(h.ok(Sysno::Kill, &[group, SIGKILL as u64]), 0);
        let status_address = h.scratch;
        let cancel = AtomicBool::new(false);
        for (selector, expected_pid, expected_status) in [
            (group, first, SIGKILL as u32),
            (group, second, SIGKILL as u32),
            (separate, separate, 37 << 8),
        ] {
            if h.start(0, Sysno::Wait4, &[selector, status_address, 0, 0])
                .is_none()
            {
                for _ in 0..12 {
                    assert_eq!(h.proc.run_slice(1, &cancel), RunStatus::BudgetExhausted);
                    if h.proc.threads[0].blocked.is_none() {
                        break;
                    }
                }
                assert!(
                    h.proc.threads[0].blocked.is_none(),
                    "{abi:?}/{expected_pid}"
                );
            }
            assert_eq!(h.result(0), expected_pid as i64);
            let mut status = [0; 4];
            h.proc.space().read(status_address, &mut status).unwrap();
            assert_eq!(u32::from_le_bytes(status), expected_status, "{abi:?}");
        }
        assert_eq!(h.err(Sysno::Kill, &[group, 0]), ESRCH);
        assert_eq!(h.err(Sysno::Getpgid, &[first]), ESRCH);
    }
}

#[test]
fn closed_linux_pidfds_poll_wait_and_keep_identity_across_pid_reuse_all_abis() {
    use crate::user::linux::signal::SIGCHLD;
    use crate::user::linux::syscall::Call;
    use crate::user::linux::syscall::thread::cf::CLONE_PIDFD;

    const POLLIN: u16 = 1;
    const POLLHUP: u16 = 0x10;
    const P_PIDFD: u64 = 3;
    const WEXITED: u64 = 4;
    const WNOWAIT: u64 = 0x0100_0000;
    const FD_CLOEXEC: u64 = 1;
    const F_GETFD: u64 = 1;

    for abi in ABIS {
        let mut h = Harness::embedded(abi);
        let entry = super::harness::CODE + 0x1000;
        h.proc.space().write_raw(entry, &exit_37(abi)).unwrap();
        let root_pid = h.ok(Sysno::Getpid, &[]);
        let root_fd = h.ok(Sysno::PidfdOpen, &[root_pid, 0]);
        let at = h.scratch;
        let args_at = at + 64;
        let mut clone_args = [0; 88];
        clone_args[..8].copy_from_slice(&CLONE_PIDFD.to_le_bytes());
        clone_args[8..16].copy_from_slice(&at.to_le_bytes());
        clone_args[32..40].copy_from_slice(&(SIGCHLD as u64).to_le_bytes());
        h.proc.space().write_raw(args_at, &clone_args).unwrap();
        assert_eq!(
            h.err(Sysno::Clone, &[CLONE_PIDFD | SIGCHLD as u64, 0, 0, 0, 0]),
            EFAULT
        );
        assert!(h.proc.state.children.list.is_empty());
        let pid = h.ok(Sysno::Clone3, &[args_at, clone_args.len() as u64]);
        let mut fd_number = [0; 4];
        h.proc.space().read(at, &mut fd_number).unwrap();
        let fd = u64::from(u32::from_le_bytes(fd_number));
        assert_eq!(h.ok(Sysno::Fcntl, &[fd, F_GETFD]), FD_CLOEXEC);
        let alias = h.ok(Sysno::PidfdOpen, &[pid, 0]);
        let original_file = h.proc.state.fds.file(fd as i32).unwrap();
        let original = crate::user::linux::syscall::pidfd::target_of(&original_file).unwrap();
        let alias_file = h.proc.state.fds.file(alias as i32).unwrap();
        assert!(std::sync::Arc::ptr_eq(
            original,
            crate::user::linux::syscall::pidfd::target_of(&alias_file).unwrap()
        ));
        {
            let child = h.proc.state.children.list[0].guest.as_mut().unwrap();
            assert!(child.state.fds.file(fd as i32).is_err());
            let nr = abi.number(Sysno::PidfdSendSignal).unwrap();
            child.syscall(0, Call::new(nr, [root_fd, 0, 0, 0, 0, 0]));
            assert_eq!(child.threads[0].cpu.syscall_return_value(), 0, "{abi:?}");
        }

        let poll_at = at + 192;
        let mut poll_record = [0; 8];
        poll_record[..4].copy_from_slice(&(fd as u32).to_le_bytes());
        poll_record[4..6].copy_from_slice(&POLLIN.to_le_bytes());
        h.proc.space().write_raw(poll_at, &poll_record).unwrap();
        assert_eq!(h.start(0, Sysno::Ppoll, &[poll_at, 1, 0, 0, 0]), None);
        let cancel = AtomicBool::new(false);
        for _ in 0..16 {
            assert_eq!(h.proc.run_slice(1, &cancel), RunStatus::BudgetExhausted);
            if h.proc.threads[0].blocked.is_none() {
                break;
            }
        }
        assert!(h.proc.threads[0].blocked.is_none(), "{abi:?}");
        assert_eq!(h.result(0), 1);
        h.proc.space().read(poll_at, &mut poll_record).unwrap();
        assert_eq!(
            u16::from_le_bytes(poll_record[6..].try_into().unwrap()),
            POLLIN
        );

        let siginfo = at + 256;
        assert_eq!(
            h.ok(Sysno::Waitid, &[P_PIDFD, fd, siginfo, WEXITED | WNOWAIT, 0]),
            0
        );
        assert!(
            matches!(original.guest_state(), Some(crate::user::linux::syscall::pidfd::Task::Zombie(s)) if s == 37 << 8)
        );
        assert_eq!(
            h.ok(Sysno::Waitid, &[P_PIDFD, alias, siginfo, WEXITED, 0]),
            0
        );
        assert_eq!(
            h.err(Sysno::Waitid, &[P_PIDFD, fd, siginfo, WEXITED, 0]),
            ECHILD
        );
        assert_eq!(h.err(Sysno::PidfdOpen, &[pid, 0]), ESRCH);
        assert_eq!(h.ok(Sysno::Ppoll, &[poll_at, 1, 0, 0, 0]), 1);
        h.proc.space().read(poll_at, &mut poll_record).unwrap();
        assert_eq!(
            u16::from_le_bytes(poll_record[6..].try_into().unwrap()),
            POLLIN | POLLHUP
        );

        clone_args[..16].fill(0);
        clone_args[64..72].copy_from_slice(&(at + 160).to_le_bytes());
        clone_args[72..80].copy_from_slice(&1u64.to_le_bytes());
        h.proc.space().write_raw(args_at, &clone_args).unwrap();
        h.proc
            .space()
            .write_raw(at + 160, &(pid as u32).to_le_bytes())
            .unwrap();
        assert_eq!(
            h.ok(Sysno::Clone3, &[args_at, clone_args.len() as u64]),
            pid
        );
        let replacement_fd = h.ok(Sysno::PidfdOpen, &[pid, 0]);
        let replacement_file = h.proc.state.fds.file(replacement_fd as i32).unwrap();
        let replacement = crate::user::linux::syscall::pidfd::target_of(&replacement_file).unwrap();
        assert_ne!(original.ino(), replacement.ino());
        assert_eq!(h.err(Sysno::PidfdSendSignal, &[fd, 0, 0, 0]), ESRCH);
        assert_eq!(h.ok(Sysno::PidfdSendSignal, &[replacement_fd, 0, 0, 0]), 0);
    }
}

#[test]
fn closed_linux_stop_continue_and_kill_never_stop_the_host() {
    for abi in ABIS {
        let mut h = Harness::embedded(abi);
        let cancel = AtomicBool::new(false);
        assert_eq!(h.call(Sysno::Kill, &[100, 19]), 0); // SIGSTOP
        let pc = h.proc.threads[0].cpu.pc();
        assert_eq!(h.proc.run_slice(4, &cancel), RunStatus::Blocked);
        assert_eq!(h.proc.threads[0].cpu.pc(), pc);
        assert_eq!(h.proc.state.group_stop, Some(19));
        assert_eq!(h.call(Sysno::Kill, &[100, 18]), 0); // SIGCONT
        assert!(h.proc.state.group_stop.is_none());
        assert_eq!(h.call(Sysno::Kill, &[100, 19]), 0);
        assert_eq!(h.proc.run_slice(4, &cancel), RunStatus::Blocked);
        assert_eq!(h.call(Sysno::Kill, &[100, 9]), 0);
        let result = h.proc.run_slice(4, &cancel);
        assert!(
            matches!(result, RunStatus::Complete(crate::user::linux::ExitStatus::Signaled { ref info, .. }) if info.signo == 9)
        );
        assert_eq!(h.proc.run_slice(1, &cancel), result);
    }
}

#[test]
fn closed_linux_rejects_inconsistent_configuration_before_image_loading() {
    let config = LinuxConfig::embedded("/program", vec![], vec![], vec![], 64).unwrap();
    assert_eq!(config.arena_bytes, 128 << 20);
    for change in 0..8 {
        let mut c = config.clone();
        match change {
            0 => c.supplied_files = None,
            1 => c.sysroot = Some("/".into()),
            2 => c.processes = true,
            3 => c.ipc_dir = Some("unused".into()),
            4 => c.fsnotify = crate::user::linux::fsnotify::Backend::Host,
            5 => c.strace = true,
            6 => c.seed = None,
            7 => c.console = crate::user::console::Console::Host,
            _ => unreachable!(),
        }
        let result = LinuxProcess::spawn(
            c,
            crate::user::linux::loader::ImageFile::new(vec![], "/program"),
        );
        assert!(
            matches!(result, Err(crate::user::linux::process::SpawnError::Unsupported(ref why)) if why.starts_with("closed Linux embedding requires"))
        );
    }
}

fn exit_37(abi: LinuxAbi) -> Vec<u8> {
    let words = |code: &[u32]| {
        code.iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<u8>>()
    };
    match abi {
        LinuxAbi::X86_64 => vec![0xb8, 60, 0, 0, 0, 0xbf, 37, 0, 0, 0, 0x0f, 0x05],
        LinuxAbi::I386 => vec![0xb8, 1, 0, 0, 0, 0xbb, 37, 0, 0, 0, 0xcd, 0x80],
        LinuxAbi::Aarch64 => words(&[0xd280_0ba8, 0xd280_04a0, 0xd400_0001]),
        LinuxAbi::Arm => words(&[0xe3a0_7001, 0xe3a0_0025, 0xef00_0000]),
        LinuxAbi::Riscv64 => words(&[0x05d0_0893, 0x0250_0513, 0x0000_0073]),
    }
}

#[test]
fn closed_linux_executes_and_finalizes_real_guest_exit_all_abis() {
    for abi in ABIS {
        let mut h = Harness::embedded(abi);
        let code = exit_37(abi);
        h.proc
            .space()
            .write_raw(super::harness::CODE + 0x1000, &code)
            .unwrap();
        let cancel = AtomicBool::new(false);
        let result = h.proc.run_slice(100, &cancel);
        assert_eq!(
            result,
            RunStatus::Complete(crate::user::linux::ExitStatus::Exited(37)),
            "{abi:?}"
        );
        assert_eq!(h.proc.run_slice(1, &cancel), result);
    }
}

#[test]
fn closed_linux_threads_and_futex_continuations_remain_guest_local() {
    use crate::user::linux::syscall::thread::cf::*;
    let mut h = Harness::embedded(LinuxAbi::Aarch64);
    h.proc.state.config.slice_insns = 1;
    let entry = super::harness::CODE + 0x1000;
    h.proc
        .space()
        .write_raw(entry, &0xd503_201fu32.to_le_bytes().repeat(8))
        .unwrap();
    let flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM;
    assert_eq!(h.ok(Sysno::Clone, &[flags, 0, 0, 0, 0]), 101);
    for thread in &mut h.proc.threads {
        thread.cpu.set_pc(entry);
    }
    let cancel = AtomicBool::new(false);
    for (first, second) in [(1, 0), (1, 1), (2, 1), (2, 2)] {
        assert_eq!(h.proc.run_slice(1, &cancel), RunStatus::BudgetExhausted);
        assert_eq!(h.proc.threads[0].cpu.pc(), entry + first * 4);
        assert_eq!(h.proc.threads[1].cpu.pc(), entry + second * 4);
    }
    let at = h.scratch;
    h.proc.space().write_raw(at, &0u32.to_le_bytes()).unwrap();
    assert_eq!(h.start(0, Sysno::Futex, &[at, 0, 0, 0, 0, 0]), None);
    assert_eq!(h.start(1, Sysno::Futex, &[at, 0, 0, 0, 0, 0]), None);
    assert_eq!(h.proc.run_slice(4, &cancel), RunStatus::Blocked);
    assert_eq!(h.proc.threads.len(), 2);
}

#[test]
fn closed_linux_eventfd_wakes_every_reader_of_the_same_level_all_abis() {
    use crate::user::linux::fs::anon::Anon;
    use crate::user::linux::fs::fd::FileObject;
    use crate::user::linux::syscall::thread::cf::*;
    for abi in ABIS {
        let mut h = Harness::embedded(abi);
        // Semaphore reads each take one count, so both readers can finish.
        let fd = h.ok(Sysno::Eventfd2, &[0, 1]);
        let flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD;
        assert_eq!(h.ok(Sysno::Clone, &[flags, 0, 0, 0, 0]), 101);
        let at = h.scratch;
        assert_eq!(h.start(0, Sysno::Read, &[fd, at, 8]), None);
        assert_eq!(h.start(1, Sysno::Read, &[fd, at + 8, 8]), None);
        let file = h.proc.state.fds.file(fd as i32).unwrap();
        let FileObject::Anon(Anon::Event(event)) = &file.object else {
            panic!()
        };
        assert!(event.write(2));
        crate::user::linux::wait::poll_ready(
            h.proc
                .threads
                .iter_mut()
                .filter_map(|thread| thread.blocked.as_mut()),
        );
        assert!(
            h.proc
                .threads
                .iter()
                .all(|thread| thread.blocked.as_ref().unwrap().ready),
            "{abi:?}"
        );
        for idx in 0..2 {
            // The scheduler takes the saved continuation before retrying the
            // blocked read. A fresh Harness::start does not take it for us.
            h.proc.threads[idx].blocked.take().unwrap();
            assert_eq!(
                h.start(idx, Sysno::Read, &[fd, at + idx as u64 * 8, 8]),
                Some(8)
            );
            let mut bytes = [0; 8];
            h.proc
                .space()
                .read(at + idx as u64 * 8, &mut bytes)
                .unwrap();
            assert_eq!(u64::from_le_bytes(bytes), 1);
        }
        assert_eq!(event.count(), 0);
        assert!(
            !crate::user::linux::host::poll(&[(event.readable_fd(), true, false)], 0).unwrap()[0]
                .readable
        );
    }
}

#[test]
fn closed_linux_xattrs_use_supplied_nodes_and_preserve_validation_all_abis() {
    const AT_FDCWD: u64 = -100i64 as u64;
    for abi in ABIS {
        let mut h = Harness::embedded(abi);
        let path = h.scratch;
        let name = path + 64;
        let output = path + 512;
        h.proc.space().write_raw(path, b"/\0").unwrap();
        h.proc.space().write_raw(name, b"user.test\0").unwrap();
        h.proc.space().write_raw(output, &[0xa5; 16]).unwrap();
        let fd = h.ok(Sysno::Openat, &[AT_FDCWD, path, 0, 0]);
        for syscall in [Sysno::Getxattr, Sysno::Lgetxattr] {
            assert_eq!(
                h.call(syscall, &[path, name, output, 16]),
                -(EOPNOTSUPP as i64),
                "{abi:?} {syscall:?}"
            );
            assert_eq!(h.call(syscall, &[path, 8, output, 16]), -(EFAULT as i64));
        }
        assert_eq!(
            h.call(Sysno::Fgetxattr, &[fd, name, output, 16]),
            -(EOPNOTSUPP as i64)
        );
        assert_eq!(
            h.call(Sysno::Fgetxattr, &[9999, name, output, 16]),
            -(EBADF as i64)
        );
        for syscall in [Sysno::Listxattr, Sysno::Llistxattr] {
            assert_eq!(h.call(syscall, &[path, output, 16]), 0);
        }
        assert_eq!(h.call(Sysno::Flistxattr, &[fd, output, 16]), 0);
        assert_eq!(
            h.call(Sysno::Flistxattr, &[9999, output, 16]),
            -(EBADF as i64)
        );
        // Reading an empty list does not write into the caller's buffer.
        let mut bytes = [0; 16];
        h.proc.space().read(output, &mut bytes).unwrap();
        assert_eq!(bytes, [0xa5; 16]);
        // Host attribute mutation remains outside the closed profile, even
        // with malformed pointers. The policy gate owns this ordering.
        for syscall in [Sysno::Setxattr, Sysno::Fsetxattr, Sysno::Removexattr] {
            assert_eq!(h.call(syscall, &[0; 6]), -(EPERM as i64));
        }
    }
}

#[test]
fn closed_linux_ofd_locks_do_not_depend_on_native_lock_support_all_abis() {
    for abi in ABIS {
        let mut h = Harness::embedded(abi);
        let path = h.scratch;
        let arg = path + 64;
        h.proc.space().write_raw(path, b"/\0").unwrap();
        let fd = h.ok(Sysno::Openat, &[-100i64 as u64, path, 0, 0]);
        let call = if abi.number(Sysno::Fcntl64).is_some() {
            Sysno::Fcntl64
        } else {
            Sysno::Fcntl
        };
        // A zero-filled flock64 requests a read lock from offset 0 to EOF.
        // Its PID is at 20 for packed i386 and 24 for the other ABIs.
        let mut flock = [0u8; 32];
        h.proc.space().write_raw(arg, &flock).unwrap();
        assert_eq!(h.call(call, &[fd, 37, arg]), 0, "{abi:?}"); // F_OFD_SETLK
        assert_eq!(h.call(call, &[fd, 36, arg]), 0, "{abi:?}"); // F_OFD_GETLK
        let mut kind = [0; 2];
        h.proc.space().read(arg, &mut kind).unwrap();
        assert_eq!(u16::from_le_bytes(kind), 2); // F_UNLCK: no conflicting reader.
        flock[0] = 1; // F_WRLCK on the read-only supplied descriptor.
        h.proc.space().write_raw(arg, &flock).unwrap();
        assert_eq!(h.call(call, &[fd, 37, arg]), -(EBADF as i64));
        flock[0] = 0;
        let pid_offset = if abi == LinuxAbi::I386 { 20 } else { 24 };
        flock[pid_offset] = 1;
        h.proc.space().write_raw(arg, &flock).unwrap();
        assert_eq!(h.call(call, &[fd, 37, arg]), -(EINVAL as i64));
        assert_eq!(h.call(call, &[9999, 37, arg]), -(EBADF as i64));
    }
}

#[test]
fn closed_linux_shared_anonymous_mapping_aliases_and_survives_unmapping_all_abis() {
    for abi in ABIS {
        let mut h = Harness::embedded(abi);
        let mmap = if abi.is_compat() {
            Sysno::Mmap2
        } else {
            Sysno::Mmap
        };
        let first = h.ok(mmap, &[0, 3 * 4096, 3, 0x21, u64::from(u32::MAX), 0]);
        // old_size=0 duplicates a shared mapping, preserving the same object.
        let alias = h.ok(Sysno::Mremap, &[first, 0, 3 * 4096, 1, 0]);
        assert_ne!(first, alias);
        h.proc.space().write(first + 3 * 4096 - 1, &[0x83]).unwrap();
        let mut byte = [0];
        h.proc
            .space()
            .read(alias + 3 * 4096 - 1, &mut byte)
            .unwrap();
        assert_eq!(byte, [0x83], "{abi:?}");
        h.ok(Sysno::Msync, &[alias, 3 * 4096, 4]);
        h.ok(Sysno::Munmap, &[first, 3 * 4096]);
        h.proc
            .space()
            .read(alias + 3 * 4096 - 1, &mut byte)
            .unwrap();
        assert_eq!(byte, [0x83], "{abi:?}");
        h.ok(Sysno::Munmap, &[alias, 3 * 4096]);
        let fresh = h.ok(mmap, &[0, 4096, 3, 0x21, u64::from(u32::MAX), 0]);
        h.proc.space().read(fresh, &mut byte).unwrap();
        assert_eq!(byte, [0], "{abi:?}");
        // The closed profile does not accidentally admit mutable host files.
        for syscall in [Sysno::MemfdCreate, Sysno::Ftruncate] {
            assert_eq!(
                h.call(syscall, &[0; 6]),
                -(EPERM as i64),
                "{abi:?} {syscall:?}"
            );
        }
    }
}

#[test]
fn closed_linux_missing_host_capability_is_explicit() {
    let closed = LinuxConfig::embedded("/program", vec![], vec![], vec![], 64).unwrap();
    let result = crate::user::linux::embedding::validate_host(&closed, false, false);
    assert!(
        matches!(result, Err(crate::user::linux::process::SpawnError::Unsupported(ref why))
        if why.contains("fixed-address shared memory") && why.contains("VirtualAlloc2"))
    );
    assert!(crate::user::linux::embedding::validate_host(&closed, false, true).is_ok());
    let host = LinuxConfig::new("/program", vec![], vec![]);
    assert!(
        matches!(crate::user::linux::embedding::validate_host(&host, false, true),
        Err(crate::user::linux::process::SpawnError::Unsupported(ref why)) if why.contains("Unix host services"))
    );
}

#[test]
fn closed_linux_fork_wait_and_snapshot_all_abis() {
    use crate::user::linux::signal::SIGCHLD;
    use crate::user::linux::syscall::child::wf::{WEXITED, WNOHANG, WNOWAIT};
    for abi in ABIS {
        let mut h = Harness::embedded(abi);
        let word = h.scratch + 256;
        let shared = if abi.is_compat() {
            h.ok(Sysno::Mmap2, &[0, 4096, 3, 0x21, u32::MAX.into(), 0])
        } else {
            h.anon(4096, 3, true)
        };
        h.fill(word, 1, 20);
        h.fill(shared, 1, 21);
        let at = h.scratch;
        h.ok(Sysno::Pipe2, &[at, 0]);
        let mut pipe = [0; 8];
        h.proc.space().read(at, &mut pipe).unwrap();
        let write = u32::from_le_bytes(pipe[4..].try_into().unwrap());
        let entry = super::harness::CODE + 0x1000;
        h.proc.space().write_raw(entry, &exit_37(abi)).unwrap();
        let pid = if abi.number(Sysno::Fork).is_some() {
            h.ok(Sysno::Fork, &[])
        } else {
            h.ok(Sysno::Clone, &[SIGCHLD as u64, 0, 0, 0, 0])
        };
        assert_eq!(pid, 101, "{abi:?}");
        let child = h.proc.state.children.list[0].guest.as_mut().unwrap();
        assert_eq!(child.state.ppid, 100);
        assert_eq!(child.threads.len(), 1);
        assert_eq!(child.threads[0].cpu.syscall_return_value(), 0);
        child.space().write(word, &[41]).unwrap();
        child.space().write(shared, &[42]).unwrap();
        let file = child.state.fds.file(write as i32).unwrap();
        assert!(std::sync::Arc::ptr_eq(
            &file,
            &h.proc.state.fds.file(write as i32).unwrap()
        ));
        drop(file);
        h.ok(Sysno::Close, &[write.into()]);
        let child = h.proc.state.children.list[0].guest.as_ref().unwrap();
        assert!(child.state.fds.file(write as i32).is_ok());
        assert_eq!(h.byte(word), 20);
        assert_eq!(h.byte(shared), 42);
        assert_eq!(h.ok(Sysno::Getpgid, &[pid]), 100);

        assert_eq!(h.ok(Sysno::Wait4, &[pid, at, WNOHANG.into(), 0]), 0);
        let cancel = AtomicBool::new(true);
        assert_eq!(h.start(0, Sysno::Wait4, &[0, at, 0, 0]), None);
        assert_eq!(h.proc.run_slice(0, &cancel), RunStatus::BudgetExhausted);
        assert_eq!(h.proc.run_slice(1, &cancel), RunStatus::Cancelled);
        assert!(h.proc.state.children.list[0].zombie.is_none());
        cancel.store(false, std::sync::atomic::Ordering::Release);
        assert_eq!(h.proc.run_slice(1, &cancel), RunStatus::BudgetExhausted);
        assert_eq!(h.proc.state.children.list[0].zombie.unwrap().0, 37 << 8);
        // WNOWAIT observes the child without consuming the parent's wait4.
        assert_eq!(
            h.ok(
                Sysno::Waitid,
                &[1, pid, at + 16, (WEXITED | WNOWAIT).into(), 0]
            ),
            0
        );
        let mut status = [0; 4];
        let where_status = at + 16 + if abi.is_compat() { 12 } else { 16 } + 8;
        h.proc.space().read(where_status, &mut status).unwrap();
        assert_eq!(u32::from_le_bytes(status), 37, "{abi:?}");
        assert_eq!(h.proc.run_slice(1, &cancel), RunStatus::BudgetExhausted);
        assert_eq!(h.result(0), pid as i64);
        h.proc.space().read(at, &mut status).unwrap();
        assert_eq!(u32::from_le_bytes(status), 37 << 8);
        assert!(h.proc.state.children.list.is_empty());
        assert_eq!(h.err(Sysno::Wait4, &[pid, at, 0, 0]), ECHILD);
        assert_eq!(h.err(Sysno::Getpgid, &[pid]), ESRCH);
    }
}

#[test]
fn closed_linux_private_vfork_blocks_until_child_exit_all_abis() {
    use crate::user::linux::{signal::SIGCHLD, syscall::thread::cf::CLONE_VFORK};

    for abi in ABIS {
        let mut h = Harness::embedded(abi);
        let at = h.scratch;
        let entry = super::harness::CODE + 0x1000;
        h.proc.space().write_raw(entry, &exit_37(abi)).unwrap();
        h.fill(at + 16, 1, 9);
        let flags = CLONE_VFORK | SIGCHLD as u64;
        assert_eq!(h.start(0, Sysno::Clone, &[flags, 0, 0, 0, 0]), None);
        let child = &h.proc.state.children.list[0];
        assert!(!child.released);
        child
            .guest
            .as_ref()
            .unwrap()
            .space()
            .write(at + 16, &[3])
            .unwrap();
        assert_eq!(h.byte(at + 16), 9);
        let cancel = AtomicBool::new(false);
        assert_eq!(h.proc.run_slice(1, &cancel), RunStatus::BudgetExhausted);
        assert_eq!(h.proc.state.children.list[0].zombie.unwrap().0, 37 << 8);
        assert_eq!(h.proc.run_slice(1, &cancel), RunStatus::BudgetExhausted);
        assert_eq!(h.result(0), 101);
        assert_eq!(h.ok(Sysno::Wait4, &[101, at, 0, 0]), 101);
        let mut status = [0; 4];
        h.proc.space().read(at, &mut status).unwrap();
        assert_eq!(u32::from_le_bytes(status), 37 << 8);
        assert!(h.proc.state.children.list.is_empty());
    }
}

#[test]
fn closed_linux_private_vfork_releases_at_exec_before_child_exit() {
    assert_closed_linux_vfork_exec(false);
}

#[test]
fn closed_linux_shared_vfork_detaches_at_exec_before_child_exit() {
    assert_closed_linux_vfork_exec(true);
}

fn assert_closed_linux_vfork_exec(shared: bool) {
    use super::harness::{CODE, DATA};
    use super::loader::{Seg, image};
    use crate::user::image::elf::{EM_AARCH64, ET_EXEC, PF_R, PF_X};
    use crate::user::linux::signal::SIGCHLD;
    use crate::user::linux::syscall::{
        child::wf::WNOHANG,
        thread::cf::{CLONE_VFORK, CLONE_VM},
    };
    use crate::user::supplied_fs::Files;
    use std::sync::Arc;

    let entry = CODE + 0x1000;
    let abi = LinuxAbi::Aarch64;
    let mut next = image(
        EM_AARCH64,
        ET_EXEC,
        entry,
        &[Seg::load(CODE, 0, 0x2000, 0x2000, PF_R | PF_X)],
        None,
    );
    let exit = exit_37(abi);
    next[0x1000..0x1000 + exit.len()].copy_from_slice(&exit);
    let files = Files::default()
        .with_file("/replacement".into(), Arc::from(next))
        .unwrap();
    let mut h = Harness::embedded_with_supplied(abi, files);
    let original_program = [
        0xd2a0_0c00u32, // mov x0, #0x600000 (DATA)
        0xd280_0001,    // mov x1, #0 (argv)
        0xd280_0002,    // mov x2, #0 (envp)
        0xd280_1ba8,    // mov x8, #221 (execve)
        0xd400_0001,    // svc #0
    ];
    let code: Vec<_> = original_program
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect();
    h.proc.space().write_raw(entry, &code).unwrap();
    h.proc.space().write_raw(DATA, b"/replacement\0").unwrap();
    let at = h.scratch;
    let mut clone_args = [0; 88];
    let flags = CLONE_VFORK | if shared { CLONE_VM } else { 0 };
    clone_args[..8].copy_from_slice(&flags.to_le_bytes());
    clone_args[32..40].copy_from_slice(&(SIGCHLD as u64).to_le_bytes());
    h.proc.space().write_raw(at, &clone_args).unwrap();
    assert_eq!(
        h.start(0, Sysno::Clone3, &[at, clone_args.len() as u64]),
        None
    );
    assert_eq!(h.proc.state.shares_mm(), shared);
    let cancel = AtomicBool::new(false);
    assert_eq!(h.proc.run_slice(1, &cancel), RunStatus::BudgetExhausted);
    let child = &h.proc.state.children.list[0];
    assert!(child.released);
    assert!(child.zombie.is_none());
    let guest = child.guest.as_ref().unwrap();
    assert_eq!(guest.state.exe_path, "/replacement");
    assert!(!guest.state.shares_mm());
    assert!(!h.proc.state.shares_mm());
    assert!(guest.space().read(at, &mut [0]).is_err());
    assert!(h.proc.space().read(at, &mut [0]).is_ok());
    assert_eq!(h.proc.run_slice(1, &cancel), RunStatus::BudgetExhausted);
    assert_eq!(h.result(0), 101);
    assert_eq!(h.ok(Sysno::Wait4, &[101, at, WNOHANG.into(), 0]), 0);
    assert_eq!(h.start(0, Sysno::Wait4, &[101, at, 0, 0]), None);
    assert_eq!(h.proc.run_slice(1, &cancel), RunStatus::BudgetExhausted);
    assert_eq!(h.proc.run_slice(1, &cancel), RunStatus::BudgetExhausted);
    assert_eq!(h.result(0), 101);
    let mut status = [0; 4];
    h.proc.space().read(at, &mut status).unwrap();
    assert_eq!(u32::from_le_bytes(status), 37 << 8);
}

#[test]
fn closed_linux_shared_vfork_preserves_child_memory_and_brk_all_abis() {
    use crate::user::linux::signal::SIGCHLD;
    use crate::user::linux::syscall::{Call, thread::cf::*};

    for abi in ABIS {
        for call in [Sysno::Clone, Sysno::Vfork] {
            if abi.number(call).is_none() {
                continue;
            }
            let mut h = Harness::embedded(abi);
            let at = h.scratch;
            let entry = super::harness::CODE + 0x1000;
            h.proc.space().write_raw(entry, &exit_37(abi)).unwrap();
            h.fill(at + 16, 1, 9);
            let arguments = [CLONE_VM | CLONE_VFORK | SIGCHLD as u64, 0, 0, 0, 0];
            assert_eq!(h.start(0, call, &arguments), None);
            assert!(h.proc.state.shares_mm());
            let initial = h.proc.state.mm().brk;
            let new_brk = initial + 4096;
            let child = h.proc.state.children.list[0].guest.as_mut().unwrap();
            child.space().write(at + 16, &[3]).unwrap();
            child.syscall(
                0,
                Call::new(abi.number(Sysno::Brk).unwrap(), [new_brk, 0, 0, 0, 0, 0]),
            );
            assert_eq!(child.threads[0].cpu.syscall_return_value(), new_brk);
            assert_eq!(h.byte(at + 16), 3);
            assert_eq!(h.proc.state.mm().brk, new_brk);

            let cancel = AtomicBool::new(false);
            assert_eq!(h.proc.run_slice(1, &cancel), RunStatus::BudgetExhausted);
            assert!(!h.proc.state.shares_mm());
            assert_eq!(h.proc.run_slice(1, &cancel), RunStatus::BudgetExhausted);
            assert_eq!(h.result(0), 101);
            assert_eq!(h.ok(Sysno::Wait4, &[101, at, 0, 0]), 101);
            assert_eq!(h.ok(Sysno::Brk, &[0]), new_brk);
            assert_eq!(h.byte(at + 16), 3);
        }
    }
}

#[test]
fn closed_linux_shared_vfork_wakes_a_sibling_futex_waiter_all_abis() {
    use crate::user::linux::signal::SIGCHLD;
    use crate::user::linux::syscall::{Call, thread::cf::*};

    const WAIT_PRIVATE: u64 = 128;
    const WAKE_PRIVATE: u64 = WAIT_PRIVATE | 1;
    for abi in ABIS {
        let mut h = Harness::embedded(abi);
        let args = |addr, op, val| [addr, op, val, 0, 0, 0];
        let at = h.scratch;
        let vm = CLONE_VM | SIGCHLD as u64;
        let vfork = vm | CLONE_VFORK;
        assert_eq!(h.err(Sysno::Clone, &[vm, 0, 0, 0, 0]), ENOSYS);
        let thread = CLONE_VM | CLONE_FILES | CLONE_FS | CLONE_SIGHAND | CLONE_THREAD;
        assert_eq!(h.ok(Sysno::Clone, &[thread, 0, 0, 0, 0]), 101);
        h.proc.space().write_raw(at, &9u32.to_le_bytes()).unwrap();
        assert_eq!(h.start(1, Sysno::Futex, &args(at, WAIT_PRIVATE, 9)), None);

        let entry = super::harness::CODE + 0x1000;
        h.proc.space().write_raw(entry, &exit_37(abi)).unwrap();
        assert_eq!(h.start(0, Sysno::Clone, &[vfork, 0, 0, 0, 0]), None);
        assert!(h.proc.state.shares_mm());
        let child = h.proc.state.children.list[0].guest.as_mut().unwrap();
        child.space().write(at, &3u32.to_le_bytes()).unwrap();
        child.syscall(
            0,
            Call::new(abi.number(Sysno::Futex).unwrap(), args(at, WAKE_PRIVATE, 1)),
        );
        assert_eq!(child.threads[0].cpu.syscall_return_value(), 1);

        assert_eq!(h.proc.wake_sleepers(), 1);
        assert_eq!(h.result(1), 0);
        assert!(h.proc.threads[0].blocked.is_some());
        assert_eq!(h.start(1, Sysno::Futex, &args(at, WAIT_PRIVATE, 3)), None);

        let cancel = AtomicBool::new(false);
        for _ in 0..8 {
            if h.proc.state.children.list[0].guest.is_none() {
                break;
            }
            assert_eq!(h.proc.run_slice(1, &cancel), RunStatus::BudgetExhausted);
        }
        assert!(!h.proc.state.shares_mm());
        h.proc.wake_sleepers();
        assert_eq!(h.result(0), 102);
        assert_eq!(h.ok(Sysno::Wait4, &[102, at + 4, 0, 0]), 102);
        assert_eq!(h.byte(at), 3);
        assert_eq!(h.byte(at + 5), 37);
    }
}

#[test]
fn closed_linux_fork_namespace_reserves_processes_until_reap() {
    use crate::user::linux::signal::SIGCHLD;
    use crate::user::linux::syscall::thread::cf::*;
    let mut h = Harness::embedded(LinuxAbi::Aarch64);
    let pid = h.ok(Sysno::Clone, &[SIGCHLD as u64, 0, 0, 0, 0]);
    let flags = CLONE_VM | CLONE_FILES | CLONE_FS | CLONE_SIGHAND | CLONE_THREAD;
    assert_eq!(h.ok(Sysno::Clone, &[flags, 0, 0, 0, 0]), pid + 1);

    let at = h.scratch;
    let mut clone_args = [0; 88];
    clone_args[..8].copy_from_slice(&flags.to_le_bytes());
    clone_args[64..72].copy_from_slice(&(at + 128).to_le_bytes());
    clone_args[72..80].copy_from_slice(&1u64.to_le_bytes());
    h.proc.space().write_raw(at, &clone_args).unwrap();
    h.proc
        .space()
        .write_raw(at + 128, &(pid as u32).to_le_bytes())
        .unwrap();
    assert_eq!(h.err(Sysno::Clone3, &[at, clone_args.len() as u64]), EEXIST);
}

#[test]
fn closed_linux_reparents_live_descendants_to_guest_init() {
    use crate::user::linux::signal::SIGCHLD;
    use crate::user::linux::syscall::Call;

    let abi = LinuxAbi::Aarch64;
    let mut h = Harness::embedded(abi);
    let entry = super::harness::CODE + 0x1000;
    h.proc.space().write_raw(entry, &exit_37(abi)).unwrap();
    let parent_pid = h.ok(Sysno::Clone, &[SIGCHLD as u64, 0, 0, 0, 0]);
    let child = h.proc.state.children.list[0].guest.as_mut().unwrap();
    let call = Call::new(
        abi.number(Sysno::Clone).unwrap(),
        [SIGCHLD as u64, 0, 0, 0, 0, 0],
    );
    child.syscall(0, call);
    let orphan_pid = child.state.children.list[0].pid;
    assert_eq!(
        child.threads[0].cpu.syscall_return_value(),
        orphan_pid as u64
    );
    assert_eq!(
        child.state.children.list[0]
            .guest
            .as_ref()
            .unwrap()
            .state
            .ppid,
        parent_pid as i32
    );

    assert_eq!(h.start(0, Sysno::Wait4, &[parent_pid, 0, 0, 0]), None);
    let cancel = AtomicBool::new(false);
    assert_eq!(h.proc.run_slice(1, &cancel), RunStatus::BudgetExhausted);
    let adopted = &h.proc.state.children.orphans[0];
    assert_eq!(adopted.pid, orphan_pid);
    assert_eq!(adopted.guest.as_ref().unwrap().state.ppid, 1);
    assert_eq!(h.err(Sysno::Wait4, &[orphan_pid as u64, 0, 0, 0]), ECHILD);
    assert_eq!(
        h.proc.run_slice(3, &cancel),
        RunStatus::Complete(crate::user::linux::ExitStatus::Exited(37))
    );
    assert!(h.proc.state.children.orphans.is_empty());
}
