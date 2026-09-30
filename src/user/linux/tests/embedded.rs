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
            Sysno::PidfdOpen,
            Sysno::ProcessVmReadv,
            Sysno::ProcessVmWritev,
            Sysno::Setpgid,
            Sysno::Setsid,
            Sysno::Mount,
            Sysno::Fork,
            Sysno::Vfork,
            Sysno::Pipe2,
        ] {
            if abi.number(syscall).is_some() {
                assert_eq!(
                    h.call(syscall, &[0; 6]),
                    -(EPERM as i64),
                    "{abi:?} {syscall:?}"
                );
            }
        }
        assert_eq!(h.call(Sysno::Kill, &[123456, 0]), -(ESRCH as i64));
        assert_eq!(h.call(Sysno::Kill, &[100, 0]), 0);
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

#[test]
fn closed_linux_executes_and_finalizes_real_guest_exit_all_abis() {
    for abi in ABIS {
        let mut h = Harness::embedded(abi);
        let words = |code: &[u32]| {
            code.iter()
                .flat_map(|word| word.to_le_bytes())
                .collect::<Vec<u8>>()
        };
        let code = match abi {
            LinuxAbi::X86_64 => vec![0xb8, 60, 0, 0, 0, 0xbf, 37, 0, 0, 0, 0x0f, 0x05],
            LinuxAbi::I386 => vec![0xb8, 1, 0, 0, 0, 0xbb, 37, 0, 0, 0, 0xcd, 0x80],
            LinuxAbi::Aarch64 => words(&[0xd280_0ba8, 0xd280_04a0, 0xd400_0001]),
            LinuxAbi::Arm => words(&[0xe3a0_7001, 0xe3a0_0025, 0xef00_0000]),
            LinuxAbi::Riscv64 => words(&[0x05d0_0893, 0x0250_0513, 0x0000_0073]),
        };
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
