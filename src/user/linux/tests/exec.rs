//! `execve`/`execveat` driven through the system calls: the kernel's error
//! order (`do_execveat_common`, `do_open_execat`, `bprm_stack_limits`,
//! `exec_binprm`), `#!` parsing (`load_script`), and what the point of no
//! return keeps and resets (`begin_new_exec`, `flush_signal_handlers`,
//! `de_thread`); plus the wait calls' argument checks (`kernel_wait4`,
//! `kernel_waitid_prepare`) and new processes being unavailable without
//! host processes. Expectations follow those Linux 6.19 functions.

use super::harness::{Harness, each_abi};
use super::loader::{Seg, image};
use crate::user::image::elf::{EM_AARCH64, EM_RISCV, EM_X86_64, ET_EXEC, PF_R, PF_W, PF_X};
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::{LinuxAbi, Sysno};
use crate::user::linux::exec::{ScriptError, comm_of, parse_script};
use crate::user::linux::signal::*;
use crate::user::linux::syscall::Outcome;

fn put_u64s(h: &Harness, at: u64, words: &[u64]) {
    let b: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    h.proc.state.space.write_raw(at, &b).unwrap();
}

fn put_str(h: &Harness, at: u64, s: &str) {
    let mut b = s.as_bytes().to_vec();
    b.push(0);
    h.proc.state.space.write_raw(at, &b).unwrap();
}

/// A temporary host file with `bytes` and `mode`, removed on drop.
struct TempFile(std::path::PathBuf);

impl TempFile {
    fn new(name: &str, bytes: &[u8], mode: u32) -> Self {
        use std::os::unix::fs::PermissionsExt;
        let path =
            std::env::temp_dir().join(format!("rax-exec-test-{}-{name}", std::process::id()));
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        TempFile(path)
    }

    fn path(&self) -> &str {
        self.0.to_str().unwrap()
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// A minimal static program for `abi`.
fn program(abi: LinuxAbi) -> Vec<u8> {
    let machine = match abi {
        LinuxAbi::X86_64 => EM_X86_64,
        LinuxAbi::Aarch64 => EM_AARCH64,
        LinuxAbi::Riscv64 => EM_RISCV,
    };
    image(
        machine,
        ET_EXEC,
        0x40_1000,
        &[
            Seg::load(0x40_0000, 0, 0x2000, 0x2000, PF_R | PF_X),
            Seg::load(0x60_0000, 0x2000, 0x1000, 0x2000, PF_R | PF_W),
        ],
        None,
    )
}

/// Writes `strs` as a NULL-terminated pointer array at `at` (strings from
/// `at + 0x100`).
fn put_argv(h: &Harness, at: u64, strs: &[&str]) {
    let mut ptrs = Vec::new();
    let mut s = at + 0x100;
    for x in strs {
        put_str(h, s, x);
        ptrs.push(s);
        s += x.len() as u64 + 1;
    }
    ptrs.push(0);
    put_u64s(h, at, &ptrs);
}

#[test]
fn script_lines_parse_as_load_script_does() {
    let ok = |line: &[u8], name: &[u8], arg: Option<&[u8]>| {
        assert_eq!(
            parse_script(line),
            Ok((name.to_vec(), arg.map(<[u8]>::to_vec))),
            "{:?}",
            String::from_utf8_lossy(line)
        );
    };
    ok(b"#!/bin/sh\n", b"/bin/sh", None);
    ok(b"#! \t/bin/sh  -e -x \t\nrest", b"/bin/sh", Some(b"-e -x"));
    ok(
        b"#!/usr/bin/env python3\n",
        b"/usr/bin/env",
        Some(b"python3"),
    );
    // A NUL ends the interpreter name.
    ok(b"#!/bin/a\0b\n", b"/bin/a", None);
    // Without a newline, a later space proves the name complete.
    ok(b"#!/bin/sh -x", b"/bin/sh", Some(b"-x"));
    let long = [b"#!/".as_slice(), &[b'a'; 300]].concat();
    assert_eq!(parse_script(&long), Err(ScriptError::Bad), "truncated name");
    assert_eq!(parse_script(b"#!\n"), Err(ScriptError::Bad));
    assert_eq!(parse_script(b"#!   \t \n"), Err(ScriptError::Bad));
    assert_eq!(parse_script(b"\x7fELF"), Err(ScriptError::NotScript));
    assert_eq!(parse_script(b"#"), Err(ScriptError::NotScript));
    assert_eq!(
        comm_of(b"/usr/bin/a-rather-long-program-name"),
        b"a-rather-long-p"
    );
    assert_eq!(comm_of(b"relative"), b"relative");
}

#[test]
fn execve_checks_in_the_kernel_order() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let (path, argv) = (h.scratch, h.scratch + 0x200);
        put_argv(&h, argv, &["prog"]);
        put_str(&h, path, "/nonexistent/program");
        assert_eq!(h.err(Sysno::Execve, &[path, argv, 0]), ENOENT);
        // The file is opened before the arguments are counted.
        assert_eq!(h.err(Sysno::Execve, &[path, 8, 0]), ENOENT);
        put_str(&h, path, "/");
        assert_eq!(h.err(Sysno::Execve, &[path, argv, 0]), EACCES, "directory");
        let not_x = TempFile::new(&format!("{abi:?}-nox"), &program(abi), 0o644);
        put_str(&h, path, not_x.path());
        assert_eq!(h.err(Sysno::Execve, &[path, argv, 0]), EACCES);
        let junk = TempFile::new(&format!("{abi:?}-junk"), b"not a program", 0o755);
        put_str(&h, path, junk.path());
        assert_eq!(
            h.err(Sysno::Execve, &[path, 8, 0]),
            EFAULT,
            "argv after the open"
        );
        assert_eq!(h.err(Sysno::Execve, &[path, argv, 0]), ENOEXEC);
        // A string longer than MAX_ARG_STRLEN.
        let big = h.anon(0x40000, 3, false);
        let long = "a".repeat(32 * 4096);
        put_argv(&h, big, &["prog", &long]);
        assert_eq!(h.err(Sysno::Execve, &[path, big, 0]), E2BIG);
        // Scripts: a missing interpreter, a loop, a bad line.
        let missing = TempFile::new(&format!("{abi:?}-missing"), b"#!/nonexistent/sh\n", 0o755);
        put_str(&h, path, missing.path());
        assert_eq!(h.err(Sysno::Execve, &[path, argv, 0]), ENOENT);
        let lp =
            std::env::temp_dir().join(format!("rax-exec-test-{}-{abi:?}-loop", std::process::id()));
        let line = format!("#!{}\n", lp.display());
        let looped = TempFile::new(&format!("{abi:?}-loop"), line.as_bytes(), 0o755);
        put_str(&h, path, looped.path());
        assert_eq!(h.err(Sysno::Execve, &[path, argv, 0]), ELOOP);
        let empty = TempFile::new(&format!("{abi:?}-empty"), b"#!\n", 0o755);
        put_str(&h, path, empty.path());
        assert_eq!(h.err(Sysno::Execve, &[path, argv, 0]), ENOEXEC);
        // execveat: unknown flags, an empty name without AT_EMPTY_PATH.
        put_str(&h, path, "/proc/self/exe");
        assert_eq!(
            h.err(Sysno::Execveat, &[-100i64 as u64, path, argv, 0, 1]),
            EINVAL
        );
        put_str(&h, path, "");
        assert_eq!(
            h.err(Sysno::Execveat, &[-100i64 as u64, path, argv, 0, 0]),
            ENOENT
        );
    });
}

/// Writes argument pointers for `strs` at `at`, the strings following the
/// array.
fn put_strings(h: &Harness, at: u64, strs: &[String]) {
    let mut ptrs = Vec::new();
    let mut s = at + (strs.len() as u64 + 1) * 8;
    for x in strs {
        put_str(h, s, x);
        ptrs.push(s);
        s += x.len() as u64 + 1;
    }
    ptrs.push(0);
    put_u64s(h, at, &ptrs);
}

/// Two filler strings of `total` bytes, NULs included.
fn fillers(total: usize) -> Vec<String> {
    let first = total / 2;
    vec!["a".repeat(first - 1), "b".repeat(total - first - 1)]
}

#[test]
fn execve_charges_every_string_against_the_argument_space() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        // RLIMIT_STACK of 1 MiB: a quarter, 256 KiB, holds the strings and
        // their pointers (bprm_stack_limits).
        h.proc.state.rlimits[3].0 = 1 << 20;
        const LIMIT: usize = 256 * 1024;
        let path = h.scratch;
        let (argv, envp) = (h.anon(0x80000, 3, false), h.anon(0x80000, 3, false));
        let prog = TempFile::new(&format!("{abi:?}-cprog"), &program(abi), 0o755);
        let line = format!("#!{}\n", prog.path());
        let script = TempFile::new(&format!("{abi:?}-cscript"), line.as_bytes(), 0o755);
        let run = |h: &mut Harness, target: &str, a: u64, e: u64| {
            put_str(h, path, target);
            match h.dispatch(Sysno::Execve, &[path, a, e]) {
                Outcome::Exec(_) => 0,
                Outcome::Return(r) => -(r as i64) as i32,
                o => panic!("{abi:?}: {o:?}"),
            }
        };
        // argv "x" and two fillers exactly fill the space after the
        // pointers (3 × 8 bytes) and the file name: the program runs.
        let space = |name: &str| LIMIT - 3 * 8 - (name.len() + 1) - 2;
        let mut args = vec!["x".to_string()];
        args.extend(fillers(space(prog.path())));
        put_strings(&h, argv, &args);
        assert_eq!(run(&mut h, prog.path(), argv, 0), 0, "{abi:?}: exact fit");
        // A script's strings are charged too: argv[0]'s two bytes come
        // back, the script's name and the interpreter's are taken. One
        // byte more than fits is E2BIG, although the new image's strings
        // alone (without the pointers) would fit its stack.
        let extra = prog.path().len() + 1 + script.path().len() + 1 - 2;
        for (over, want) in [(1, E2BIG), (0, 0)] {
            let mut args = vec!["x".to_string()];
            args.extend(fillers(space(script.path()) - extra + over));
            put_strings(&h, argv, &args);
            assert_eq!(
                run(&mut h, script.path(), argv, 0),
                want,
                "{abi:?}: script, {over} over"
            );
        }
        // An empty argv: one pointer is reserved and "" takes a byte.
        let exact = LIMIT - 3 * 8 - (prog.path().len() + 1);
        put_strings(&h, envp, &fillers(exact));
        assert_eq!(
            run(&mut h, prog.path(), 0, envp),
            E2BIG,
            "{abi:?}: empty argv"
        );
        put_strings(&h, envp, &fillers(exact - 1));
        assert_eq!(
            run(&mut h, prog.path(), 0, envp),
            0,
            "{abi:?}: empty argv fits"
        );
    });
}

#[test]
fn a_script_named_by_a_close_on_exec_descriptor_is_not_run() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let (path, argv) = (h.scratch, h.scratch + 0x200);
        put_argv(&h, argv, &["prog"]);
        let prog = TempFile::new(&format!("{abi:?}-fprog"), &program(abi), 0o755);
        let line = format!("#!{}\n", prog.path());
        let script = TempFile::new(&format!("{abi:?}-fscript"), line.as_bytes(), 0o755);
        const O_CLOEXEC: u64 = 0o2000000;
        const AT_EMPTY_PATH: u64 = 0x1000;
        let exec_fd = |h: &mut Harness, target: &str, oflags: u64| {
            put_str(h, path, target);
            let fd = h.ok(Sysno::Openat, &[-100i64 as u64, path, oflags, 0]);
            put_str(h, path, "");
            let out = h.dispatch(Sysno::Execveat, &[fd, path, argv, 0, AT_EMPTY_PATH]);
            h.ok(Sysno::Close, &[fd]);
            match out {
                Outcome::Exec(_) => 0,
                Outcome::Return(r) => -(r as i64) as i32,
                o => panic!("{abi:?}: {o:?}"),
            }
        };
        // /dev/fd/N would be closed before the interpreter opens it.
        assert_eq!(exec_fd(&mut h, script.path(), O_CLOEXEC), ENOENT, "{abi:?}");
        assert_eq!(exec_fd(&mut h, script.path(), 0), 0, "{abi:?}");
        // A program needs no name: it runs either way.
        assert_eq!(exec_fd(&mut h, prog.path(), O_CLOEXEC), 0, "{abi:?}");
        // The check follows the #! line's: a bad line is still ENOEXEC.
        let bad = TempFile::new(&format!("{abi:?}-fbad"), b"#!\n", 0o755);
        assert_eq!(exec_fd(&mut h, bad.path(), O_CLOEXEC), ENOEXEC, "{abi:?}");
    });
}

#[test]
fn execve_replaces_the_image_and_keeps_what_the_kernel_keeps() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let (path, argv, envp) = (h.scratch, h.scratch + 0x200, h.scratch + 0x600);
        // Carried state: a blocked pending signal, an ignored signal, a
        // handled one, an alternate stack, a close-on-exec descriptor.
        h.proc.threads[0].sigmask = sigmask(SIGHUP);
        let pid = h.proc.state.pid as u64;
        h.ok(Sysno::Tgkill, &[pid, pid, SIGHUP as u64]);
        h.proc.state.sigactions[(SIGUSR2 - 1) as usize].handler = SIG_IGN;
        h.proc.state.sigactions[(SIGUSR1 - 1) as usize].handler = 0x40_1000;
        h.proc.threads[0].altstack = AltStack {
            sp: 0x60_1000,
            flags: 0,
            size: 0x1000,
        };
        // A POSIX timer (deleted by exit_itimers) and its queued signal
        // (flush_itimer_signals).
        h.ok(Sysno::TimerCreate, &[1, 0, h.scratch + 0x800]);
        h.proc
            .state
            .shared_pending
            .enqueue_timer(SigInfo::timer(SIGRTMIN, 0, 0), 1);
        put_str(&h, path, "/dev/null");
        let kept = h.ok(Sysno::Openat, &[-100i64 as u64, path, 0, 0]);
        let closed = h.ok(Sysno::Openat, &[-100i64 as u64, path, 0o2000000, 0]);
        let file = TempFile::new(&format!("{abi:?}-prog"), &program(abi), 0o755);
        let script_line = format!("#!{} first-arg\n", file.path());
        let script = TempFile::new(&format!("{abi:?}-script"), script_line.as_bytes(), 0o755);
        put_str(&h, path, script.path());
        put_argv(&h, argv, &["ignored", "tail"]);
        put_argv(&h, envp, &["K=V"]);
        let out = h.dispatch(Sysno::Execve, &[path, argv, envp]);
        let Outcome::Exec(image) = out else {
            panic!("{abi:?}: {out:?}");
        };
        h.proc.commit_exec(0, *image.0);
        let p = &h.proc.state;
        let t = &h.proc.threads[0];
        // The interpreter's argument list: its name, its argument, the
        // script, then the original arguments after argv[0].
        let cmdline = format!("{}\0first-arg\0{}\0tail\0", file.path(), script.path());
        assert_eq!(p.cmdline, cmdline.as_bytes(), "{abi:?}");
        assert_eq!(p.environ, b"K=V\0");
        assert_eq!(t.comm, comm_of(script.path().as_bytes()));
        assert!(
            p.exe_path.ends_with(&format!("{abi:?}-prog")),
            "{}",
            p.exe_path
        );
        assert_eq!(t.sigmask, sigmask(SIGHUP), "mask kept");
        assert!(t.pending.contains(SIGHUP), "pending kept");
        assert_eq!(p.sigactions[(SIGUSR2 - 1) as usize].handler, SIG_IGN);
        assert_eq!(p.sigactions[(SIGUSR1 - 1) as usize].handler, SIG_DFL);
        assert_eq!(t.altstack, AltStack::DISABLED);
        assert!(p.fds.get(kept as i32).is_ok());
        assert!(p.fds.get(closed as i32).is_err(), "close-on-exec");
        assert_eq!(p.exec_id, 1);
        assert!(p.timers.is_empty(), "exit_itimers");
        assert!(!p.shared_pending.contains(SIGRTMIN), "flush_itimer_signals");
    });
}

#[test]
fn waits_check_their_arguments_and_find_no_children() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    // kernel_wait4: unknown options, INT_MIN, then no children.
    assert_eq!(h.err(Sysno::Wait4, &[u64::MAX, 0, 0x10, 0]), EINVAL);
    assert_eq!(
        h.err(Sysno::Wait4, &[i32::MIN as u32 as u64, 0, 0, 0]),
        ESRCH
    );
    assert_eq!(h.err(Sysno::Wait4, &[u64::MAX, 0, 1, 0]), ECHILD);
    // kernel_waitid_prepare: no event type, bad ids and types.
    assert_eq!(h.err(Sysno::Waitid, &[0, 0, 0, 1, 0]), EINVAL);
    assert_eq!(h.err(Sysno::Waitid, &[1, 0, 0, 4, 0]), EINVAL);
    assert_eq!(h.err(Sysno::Waitid, &[2, u32::MAX as u64, 0, 4, 0]), EINVAL);
    assert_eq!(h.err(Sysno::Waitid, &[3, 5, 0, 4, 0]), EBADF);
    assert_eq!(h.err(Sysno::Waitid, &[9, 0, 0, 4, 0]), EINVAL);
    assert_eq!(h.err(Sysno::Waitid, &[0, 0, 0, 4 | 1, 0]), ECHILD);
    // waitid writes the siginfo_t fields on errors too, and only them.
    let info = h.scratch;
    let bytes = |h: &Harness| (0..32).map(|i| h.byte(info + i)).collect::<Vec<_>>();
    let mut want = [0u8; 32];
    want[12..16].fill(0xa5);
    want[28..].fill(0xa5);
    h.fill(info, 32, 0xa5);
    assert_eq!(h.err(Sysno::Waitid, &[0, 0, info, 4, 0]), ECHILD);
    assert_eq!(bytes(&h), want);
    h.fill(info, 32, 0xa5);
    assert_eq!(h.err(Sysno::Waitid, &[0, 0, info, 0, 0]), EINVAL);
    assert_eq!(bytes(&h), want);
    assert_eq!(h.err(Sysno::Waitid, &[0, 0, (1 << 47) - 64, 4, 0]), EFAULT);
    // Without host processes, a new process cannot be created.
    assert_eq!(h.err(Sysno::Fork, &[]), ENOSYS);
    assert_eq!(h.err(Sysno::Vfork, &[]), ENOSYS);
    assert_eq!(h.err(Sysno::Clone, &[SIGCHLD as u64, 0, 0, 0, 0]), ENOSYS);
}

#[test]
fn children_pass_to_a_live_thread_and_to_an_executing_one() {
    use crate::user::linux::host;
    use crate::user::linux::syscall::child::wf::*;
    use crate::user::linux::syscall::thread::cf::*;
    const THREAD: u64 =
        CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM;
    // Child records whose PIDs name no host process: the first wait finds
    // them ended, and WNOWAIT keeps them.
    const A: i32 = i32::MAX - 1;
    const B: i32 = i32::MAX - 2;
    const P_PID: u64 = 1;
    let mine = (WEXITED | WNOHANG | WNOWAIT | WNOTHREAD) as u64;
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let pid = h.proc.state.pid;
        let tid = h.ok(Sysno::Clone, &[THREAD, 0, 0, 0, 0]) as i32;
        for (child, creator) in [(A, pid), (B, tid)] {
            let (status, _) = host::status_pipe().unwrap();
            h.proc
                .state
                .children
                .add(child, status, SIGCHLD, creator, 0);
        }
        // The siginfo_t goes to the new program's data after execve.
        let wait = |h: &mut Harness, by: i32, child: i32| {
            let idx = h.index_of(by);
            let info = if h.proc.state.exec_id == 0 {
                h.scratch
            } else {
                0x60_0000
            };
            h.start(idx, Sysno::Waitid, &[P_PID, child as u64, info, mine, 0])
        };
        // __WNOTHREAD: only the calling thread's own children.
        assert_eq!(wait(&mut h, pid, B), Some(-(ECHILD as i64)), "{abi:?}");
        assert_eq!(wait(&mut h, tid, B), Some(0), "{abi:?}");
        assert_eq!(wait(&mut h, tid, A), Some(-(ECHILD as i64)), "{abi:?}");
        // The leader exits: its child passes to the first live thread.
        assert_eq!(h.start(0, Sysno::Exit, &[0]), None);
        assert_eq!(wait(&mut h, tid, A), Some(0), "{abi:?}");

        // execve from a second thread: every child is then the caller's,
        // under the leader's ID.
        let mut h = Harness::new(abi);
        let tid = h.ok(Sysno::Clone, &[THREAD, 0, 0, 0, 0]) as i32;
        for (child, creator) in [(A, pid), (B, tid)] {
            let (status, _) = host::status_pipe().unwrap();
            h.proc
                .state
                .children
                .add(child, status, SIGCHLD, creator, 0);
        }
        let file = TempFile::new(&format!("{abi:?}-heir"), &program(abi), 0o755);
        let (path, argv) = (h.scratch + 0x100, h.scratch + 0x200);
        put_str(&h, path, file.path());
        put_argv(&h, argv, &["prog"]);
        let w = h.index_of(tid);
        let Outcome::Exec(image) = h.dispatch_on(w, Sysno::Execve, &[path, argv, 0]) else {
            panic!("{abi:?}: execve");
        };
        h.proc.commit_exec(w, *image.0);
        assert_eq!(wait(&mut h, pid, A), Some(0), "{abi:?}");
        assert_eq!(wait(&mut h, pid, B), Some(0), "{abi:?}");
    });
}

#[test]
fn a_zombie_child_is_found_without_asking_the_host() {
    use crate::user::linux::host;
    // A PID and group no host process has: only the record exists, as for
    // a child the host reaped and whose PID it may reuse.
    const Z: i32 = i32::MAX - 3;
    let mut h = Harness::new(LinuxAbi::Aarch64);
    h.proc.state.config.processes = true;
    let (status, _) = host::status_pipe().unwrap();
    h.proc
        .state
        .children
        .add(Z, status, SIGCHLD, h.proc.state.pid, 0);
    let ch = h.proc.state.children.get_mut(Z).unwrap();
    ch.pgid = Z;
    ch.zombie = Some((0, (0, 0, 0)));
    let z = Z as u64;
    // kill, a group kill, tgkill, and rt_sigqueueinfo find it; an invalid
    // signal is still EINVAL.
    assert_eq!(h.call(Sysno::Kill, &[z, SIGTERM as u64]), 0);
    assert_eq!(h.call(Sysno::Kill, &[z, 0]), 0);
    assert_eq!(h.err(Sysno::Kill, &[z, 65]), EINVAL);
    assert_eq!(h.call(Sysno::Kill, &[-Z as i64 as u64, SIGTERM as u64]), 0);
    assert_eq!(h.call(Sysno::Tgkill, &[z, z, SIGTERM as u64]), 0);
    let info = h.scratch;
    h.fill(info, 128, 0);
    h.proc
        .state
        .space
        .write_raw(info + 8, &code::SI_QUEUE.to_le_bytes())
        .unwrap();
    assert_eq!(h.call(Sysno::RtSigqueueinfo, &[z, SIGUSR1 as u64, info]), 0);
    // Once waited for, it is gone.
    assert_eq!(h.call(Sysno::Wait4, &[z, 0, 0, 0]), z as i64);
    assert_eq!(h.err(Sysno::Kill, &[z, SIGTERM as u64]), ESRCH);
    assert_eq!(h.err(Sysno::Kill, &[-Z as i64 as u64, 0]), ESRCH);
}

#[test]
fn child_status_records_carry_linux_wait_statuses() {
    use crate::user::linux::children::{exited_status, signaled_status};
    assert_eq!(exited_status(7), 0x0700);
    assert_eq!(exited_status(-1), 0xff00);
    assert_eq!(signaled_status(11, false), 11);
    assert_eq!(signaled_status(6, true), 0x86);
}
