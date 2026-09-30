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
