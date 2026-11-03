//! Native timed-lock outcomes and entered fileproc lifetime.
use super::*;
use crate::host::time::Duration;
use crate::user::darwin::abi::{Errno, tables::nr};
use crate::user::darwin::arch::Rv;
use crate::user::darwin::fd::{FileRef, OpenFile};
use crate::user::darwin::syscall::{Ctx, bsd::file};
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::atomic::AtomicU64;

fn files() -> (std::fs::File, std::fs::File) {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let name = std::env::temp_dir().join(format!(
        "rax-timed-lock-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let holder = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&name)
        .unwrap();
    let target = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&name)
        .unwrap();
    std::fs::remove_file(name).unwrap();
    (holder, target)
}

fn hold(holder: &std::fs::File, enabled: bool) {
    // SAFETY: zero initialization is valid, and every relevant field follows.
    let mut lock: libc::flock = unsafe { std::mem::zeroed() };
    lock.l_start = 0;
    lock.l_len = 1;
    lock.l_type = if enabled {
        libc::F_WRLCK as _
    } else {
        libc::F_UNLCK as _
    };
    lock.l_whence = libc::SEEK_SET as _;
    #[cfg(target_os = "macos")]
    let command = file::cmd::F_OFD_SETLK;
    #[cfg(not(target_os = "macos"))]
    let command = libc::F_OFD_SETLK;
    // SAFETY: holder is live and lock is the native flock layout.
    assert_eq!(
        unsafe { libc::fcntl(holder.as_raw_fd(), command, &mut lock) },
        0
    );
}

fn request(kind: i16, seconds: i64, nanos: i64) -> [u8; 40] {
    let mut raw = [0; 40];
    raw[8..16].copy_from_slice(&1i64.to_le_bytes());
    raw[20..22].copy_from_slice(&kind.to_le_bytes());
    raw[24..32].copy_from_slice(&seconds.to_le_bytes());
    raw[32..40].copy_from_slice(&nanos.to_le_bytes());
    raw
}

#[test]
fn timed_lock_replays_272_native_unconfined_results_on_both_guest_abis() {
    for (abi, input) in [
        (
            DarwinAbi::Arm64,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/darwin/native-timed-record-locks/timed-lock-records-arm64-v13.json"
            )),
        ),
        (
            DarwinAbi::X86_64,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/darwin/native-timed-record-locks/timed-lock-records-x86_64-v13.json"
            )),
        ),
    ] {
        let records: serde_json::Value = serde_json::from_str(input).unwrap();
        assert_eq!(records.as_array().unwrap().len(), 144);
        let mut count = 0;
        let mut process = bounded_tests::process_with_profile(abi, false);
        let (_, mut thread) = process.proc.threads.pop_first().unwrap();
        let at = thread.cpu.sp() - 1024;
        for native in records
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| !r["input"]["confined"].as_bool().unwrap())
        {
            let fields = &native["input"];
            let (holder, target) = files();
            let raw = request(
                fields["lock_type"].as_i64().unwrap() as i16,
                fields["seconds"].as_i64().unwrap(),
                fields["nanoseconds"].as_i64().unwrap(),
            );
            let target: OwnedFd = target.into();
            let file: FileRef = Arc::new(OpenFile::host(target, 2, None));
            let fd = process.proc.fds.install(file, true, 0, 256).unwrap();
            if fields["conflict"].as_bool().unwrap() {
                hold(&holder, true);
            }
            process.proc.space.write(at, &raw).unwrap();
            let mut ctx = Ctx {
                proc: &mut process.proc,
                thread: &mut thread,
                nr: i64::from(nr::FCNTL),
                pc: 0x1_0000_1004,
            };
            let expected = &native["records"].as_array().unwrap().last().unwrap();
            let expected = if expected["result"].as_i64().unwrap() < 0 {
                Err(Errno(expected["errno"].as_i64().unwrap() as i32))
            } else {
                Ok(Rv::one(0))
            };
            let argument = if fields["bad_pointer"].as_bool().unwrap() {
                1
            } else {
                at
            };
            let target = if fields["bad_fd"].as_bool().unwrap() {
                -1
            } else {
                fd
            };
            let command = fields["command"].as_i64().unwrap() as i32;
            let mut result = file::fcntl(&mut ctx, target, command, argument);
            let stop = Instant::now() + Duration::from_secs(1);
            while result == Err(Errno::ERESTART) && ctx.thread.wait.is_some() {
                assert!(Instant::now() < stop, "{abi:?}/{native}");
                if expected.is_ok() {
                    hold(&holder, false);
                }
                let deadline = ctx.thread.wait.take().unwrap().deadline.unwrap();
                std::thread::sleep(deadline.saturating_duration_since(Instant::now()));
                result = file::fcntl(&mut ctx, target, command, argument);
            }
            assert_eq!(result, expected, "{abi:?}/{native}");
            assert_eq!(ctx.read(at, 40).unwrap(), raw);
            ctx.thread.file_io = None;
            ctx.thread.wait = None;
            ctx.thread.resume = None;
            ctx.proc.fds.remove(fd).unwrap();
            count += 1;
        }
        assert_eq!(count, 136);
    }
}

fn entered(thread: &mut Thread, command: u32, args: [u64; 8]) {
    thread.pending_unix = Some(syscall::PendingUnix {
        nr: command,
        args,
        pc: 0x1_0000_1004,
        completed: None,
        result_prepared: false,
        guard_cookie: None,
    });
}

#[test]
fn timed_lock_replays_16_native_request_mutation_and_close_lifetimes() {
    for (abi, input) in [
        (
            DarwinAbi::Arm64,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/darwin/native-timed-record-locks/timed-lock-lifetime-records-arm64-v14.json"
            )),
        ),
        (
            DarwinAbi::X86_64,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/darwin/native-timed-record-locks/timed-lock-lifetime-records-x86_64-v14.json"
            )),
        ),
    ] {
        let records: serde_json::Value = serde_json::from_str(input).unwrap();
        assert_eq!(records.as_array().unwrap().len(), 8);
        for native in records.as_array().unwrap() {
            let (holder, target) = files();
            hold(&holder, true);
            let mut process = bounded_tests::process_with_profile(abi, false);
            let (tid, mut thread) = process.proc.threads.pop_first().unwrap();
            let file = Arc::new(OpenFile::host(target.into(), 2, None));
            let fd = process
                .proc
                .fds
                .install(file.clone(), true, 0, 256)
                .unwrap();
            let at = thread.cpu.sp() - 1024;
            process
                .proc
                .space
                .write(at, &request(3, 0, 200_000_000))
                .unwrap();
            entered(
                &mut thread,
                nr::FCNTL,
                [
                    fd as u64,
                    native["input"]["command"].as_u64().unwrap(),
                    at,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
            );
            syscall::resume_unix(&mut process.proc, &mut thread);
            assert!(thread.wait.is_some() && thread.file_io.is_some());
            thread.mach.suspend_count = 1;
            process.proc.threads.insert(tid, thread);
            if native["input"]["mutate"].as_bool().unwrap() {
                process.proc.space.write(at, &request(0, 0, 1)).unwrap();
            }
            let close_it = native["input"]["close"].as_bool().unwrap();
            if close_it {
                let mut closer = bounded_tests::process(abi)
                    .proc
                    .threads
                    .pop_first()
                    .unwrap()
                    .1;
                closer.tid = tid + 1;
                entered(&mut closer, nr::CLOSE, [fd as u64, 0, 0, 0, 0, 0, 0, 0]);
                syscall::resume_unix(&mut process.proc, &mut closer);
                assert!(closer.wait.is_some());
                assert_eq!(process.proc.fds.get(fd).unwrap_err(), Errno::EBADF);
                assert!(process.proc.fds.lowest_free(fd as usize, 256).unwrap() > fd as usize);
                closer.mach.suspend_count = 1;
                process.proc.threads.insert(tid + 1, closer);
            }
            hold(&holder, false);
            let stop = Instant::now() + Duration::from_secs(1);
            while process.proc.threads[&tid]
                .pending_unix
                .unwrap()
                .completed
                .is_none()
            {
                file::lifetime::progress(&mut process.proc);
                assert!(Instant::now() < stop, "{abi:?}/{native}");
                std::thread::sleep(Duration::from_millis(1));
            }
            let expected = &native["records"][0];
            assert_eq!(expected["lock_result"], 0);
            assert_eq!(expected["lock_errno"], 0);
            assert_eq!(
                process.proc.threads[&tid].pending_unix.unwrap().completed,
                Some(Ok(Rv::one(0)))
            );
            if close_it {
                assert_eq!(expected["close_done_before_unlock"], 0);
                assert_eq!(expected["flags_errno"], 9);
                assert!(
                    expected["duplicate_fd"].as_i64().unwrap()
                        > expected["original_fd"].as_i64().unwrap()
                );
                assert_eq!(
                    process.proc.threads[&(tid + 1)]
                        .pending_unix
                        .unwrap()
                        .completed,
                    Some(Ok(Rv::one(0)))
                );
                assert_eq!(
                    process.proc.fds.lowest_free(fd as usize, 256).unwrap(),
                    fd as usize
                );
            }
        }
    }
}

#[test]
fn timed_lock_deadline_survives_wakes_and_expires_before_late_unlock() {
    for abi in [DarwinAbi::Arm64, DarwinAbi::X86_64] {
        let (holder, target) = files();
        hold(&holder, true);
        let mut process = bounded_tests::process_with_profile(abi, false);
        let (_, mut thread) = process.proc.threads.pop_first().unwrap();
        let fd = process
            .proc
            .fds
            .install(
                Arc::new(OpenFile::host(target.into(), 2, None)),
                true,
                0,
                256,
            )
            .unwrap();
        let at = thread.cpu.sp() - 1024;
        process
            .proc
            .space
            .write(at, &request(3, 0, 10_000_000))
            .unwrap();
        let mut ctx = Ctx {
            proc: &mut process.proc,
            thread: &mut thread,
            nr: i64::from(nr::FCNTL),
            pc: 0x1_0000_1004,
        };
        assert_eq!(file::fcntl(&mut ctx, fd, 93, at), Err(Errno::ERESTART));
        // Replacing the user request with an unlimited timeout cannot extend
        // a copied kernel-entry deadline, including after spurious wakes.
        ctx.write(at, &request(3, 0, 0)).unwrap();
        for _ in 0..3 {
            ctx.thread.wait = None;
            assert_eq!(file::fcntl(&mut ctx, fd, 93, at), Err(Errno::ERESTART));
        }
        std::thread::sleep(Duration::from_millis(20));
        hold(&holder, false);
        ctx.thread.wait = None;
        assert_eq!(file::fcntl(&mut ctx, fd, 93, at), Err(Errno::ETIMEDOUT));
        assert!(ctx.thread.file_io.is_none());
    }
}

#[test]
fn timed_lock_signal_interruption_retires_entry_and_releases_fileproc() {
    for abi in [DarwinAbi::Arm64, DarwinAbi::X86_64] {
        for restart in [false, true] {
            let (holder, target) = files();
            hold(&holder, true);
            let mut process = bounded_tests::process_with_profile(abi, false);
            let (_, mut thread) = process.proc.threads.pop_first().unwrap();
            let fd = process
                .proc
                .fds
                .install(
                    Arc::new(OpenFile::host(target.into(), 2, None)),
                    true,
                    0,
                    256,
                )
                .unwrap();
            let at = thread.cpu.sp() - 1024;
            process.proc.space.write(at, &request(3, 0, 0)).unwrap();
            thread.cpu.set_pc(0x1_0000_1004);
            entered(&mut thread, nr::FCNTL, [fd as u64, 93, at, 0, 0, 0, 0, 0]);
            syscall::resume_unix(&mut process.proc, &mut thread);
            assert!(thread.wait.is_some() && thread.file_io.is_some());
            let bit = signal::bit(signal::SIGUSR1);
            thread.sig.pending |= bit;
            process.proc.sigacts.ignore &= !bit;
            process.proc.sigacts.handler[signal::SIGUSR1 as usize] = 0x1_0000_1010;
            if restart {
                process.proc.sigacts.intr &= !bit;
            } else {
                process.proc.sigacts.intr |= bit;
            }
            thread.wait = None;
            syscall::resume_unix(&mut process.proc, &mut thread);
            assert!(
                thread.pending_unix.is_none() && thread.file_io.is_none() && thread.wait.is_none()
            );
            if restart {
                assert_eq!(
                    thread.cpu.pc(),
                    0x1_0000_1004 - if abi == DarwinAbi::Arm64 { 4 } else { 2 }
                );
            } else {
                assert_eq!(thread.cpu.reg(0), Errno::EINTR.0 as u64);
            }
            assert_ne!(thread.sig.pending & bit, 0);
        }
    }
}

#[test]
fn timed_lock_retains_entry_offset_and_eof_after_host_changes() {
    let native: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/darwin/native-timed-record-locks/offset-native-v1.json"
    )))
    .unwrap();
    for (abi, name) in [(DarwinAbi::Arm64, "arm64"), (DarwinAbi::X86_64, "x86_64")] {
        for case in native["cases"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["arch"] == name)
        {
            let expected: serde_json::Value =
                serde_json::from_str(case["stdout"].as_str().unwrap()).unwrap();
            let command = expected["command"].as_i64().unwrap() as i32;
            let whence = expected["whence"].as_i64().unwrap() as i16;
            let original = expected["original_offset"].as_i64().unwrap();
            let changed = expected["changed_offset"].as_i64().unwrap();
            let (holder, target) = files();
            holder.set_len(64).unwrap();
            let host_fd = target.as_raw_fd();
            // SAFETY: live owned target descriptor, scalar offset query/update.
            assert_eq!(unsafe { libc::lseek(host_fd, 16, libc::SEEK_SET) }, 16);
            // SAFETY: zero initialization is valid and all lock fields follow.
            let mut lock: libc::flock = unsafe { std::mem::zeroed() };
            lock.l_start = original;
            lock.l_len = 1;
            lock.l_type = libc::F_WRLCK as _;
            lock.l_whence = libc::SEEK_SET as _;
            #[cfg(target_os = "macos")]
            let (set, get) = (file::cmd::F_OFD_SETLK, file::cmd::F_OFD_GETLK);
            #[cfg(not(target_os = "macos"))]
            let (set, get) = (libc::F_OFD_SETLK, libc::F_OFD_GETLK);
            // SAFETY: live holder and a complete native flock.
            assert_eq!(
                unsafe { libc::fcntl(holder.as_raw_fd(), set, &mut lock) },
                0
            );
            let mut process = bounded_tests::process_with_profile(abi, false);
            let (_, mut thread) = process.proc.threads.pop_first().unwrap();
            let fd = process
                .proc
                .fds
                .install(
                    Arc::new(OpenFile::host(target.into(), 2, None)),
                    true,
                    0,
                    256,
                )
                .unwrap();
            let at = thread.cpu.sp() - 1024;
            let mut raw = request(3, 2, 0);
            raw[22..24].copy_from_slice(&whence.to_le_bytes());
            process.proc.space.write(at, &raw).unwrap();
            let mut ctx = Ctx {
                proc: &mut process.proc,
                thread: &mut thread,
                nr: i64::from(nr::FCNTL),
                pc: 0x1_0000_1004,
            };
            assert_eq!(file::fcntl(&mut ctx, fd, command, at), Err(Errno::ERESTART));
            if whence == libc::SEEK_CUR as i16 {
                // SAFETY: retained target is still live inside the guest fd table.
                assert_eq!(
                    unsafe { libc::lseek(host_fd, changed, libc::SEEK_SET) },
                    changed
                );
            } else {
                holder.set_len(changed as u64).unwrap();
            }
            lock.l_type = libc::F_UNLCK as _;
            // SAFETY: matching holder range is released with a native flock.
            assert_eq!(
                unsafe { libc::fcntl(holder.as_raw_fd(), set, &mut lock) },
                0
            );
            ctx.thread.wait = None;
            assert_eq!(file::fcntl(&mut ctx, fd, command, at), Ok(Rv::one(0)));
            assert_eq!(ctx.read(at, 40).unwrap(), raw);
            for (offset, key) in [
                (original, "original_lock_type"),
                (changed, "changed_lock_type"),
            ] {
                lock.l_start = offset;
                lock.l_len = 1;
                lock.l_pid = 0;
                lock.l_type = libc::F_WRLCK as _;
                lock.l_whence = libc::SEEK_SET as _;
                // SAFETY: the live inspector queries one bounded native range.
                assert_eq!(
                    unsafe { libc::fcntl(holder.as_raw_fd(), get, &mut lock) },
                    0
                );
                let kind = if lock.l_type == libc::F_WRLCK as i16 {
                    3
                } else if lock.l_type == libc::F_UNLCK as i16 {
                    2
                } else {
                    1
                };
                assert_eq!(kind, expected[key].as_i64().unwrap(), "{abi:?}/{expected}");
            }
        }
    }
}

#[test]
fn timed_lock_replays_32_native_relative_range_boundaries() {
    let native: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/darwin/native-timed-record-locks/range-errors-native-v1.json"
    )))
    .unwrap();
    assert_eq!(native["cases"].as_array().unwrap().len(), 32);
    for (abi, name) in [(DarwinAbi::Arm64, "arm64"), (DarwinAbi::X86_64, "x86_64")] {
        for case in native["cases"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["arch"] == name)
        {
            let expected: serde_json::Value =
                serde_json::from_str(case["stdout"].as_str().unwrap()).unwrap();
            let command = expected["command"].as_i64().unwrap() as i32;
            let whence = expected["whence"].as_i64().unwrap() as i16;
            let (holder, target) = files();
            holder.set_len(64).unwrap();
            // SAFETY: the owned descriptor is live; offset is a bounded scalar.
            assert_eq!(
                unsafe { libc::lseek(target.as_raw_fd(), 16, libc::SEEK_SET) },
                16
            );
            let mut process = bounded_tests::process_with_profile(abi, false);
            let (_, mut thread) = process.proc.threads.pop_first().unwrap();
            let fd = process
                .proc
                .fds
                .install(
                    Arc::new(OpenFile::host(target.into(), 2, None)),
                    true,
                    0,
                    256,
                )
                .unwrap();
            let at = thread.cpu.sp() - 1024;
            let mut raw = request(3, 0, 0);
            raw[..8].copy_from_slice(&expected["start"].as_i64().unwrap().to_le_bytes());
            raw[22..24].copy_from_slice(&whence.to_le_bytes());
            process.proc.space.write(at, &raw).unwrap();
            let mut ctx = Ctx {
                proc: &mut process.proc,
                thread: &mut thread,
                nr: i64::from(nr::FCNTL),
                pc: 0x1_0000_1004,
            };
            let result = if expected["result"].as_i64().unwrap() < 0 {
                Err(Errno(expected["errno"].as_i64().unwrap() as i32))
            } else {
                Ok(Rv::one(0))
            };
            assert_eq!(
                file::fcntl(&mut ctx, fd, command, at),
                result,
                "{abi:?}/{expected}"
            );
            assert_eq!(ctx.read(at, 40).unwrap(), raw);
            assert!(ctx.thread.file_io.is_none() && ctx.thread.wait.is_none());
        }
    }
}

#[test]
fn timed_lock_replays_36_native_pid_and_error_precedence_results() {
    let native: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/darwin/native-timed-record-locks/field-precedence-native-v1.json"
    )))
    .unwrap();
    assert_eq!(native["cases"].as_array().unwrap().len(), 36);
    for (abi, name) in [(DarwinAbi::Arm64, "arm64"), (DarwinAbi::X86_64, "x86_64")] {
        for case in native["cases"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["arch"] == name)
        {
            let expected: serde_json::Value =
                serde_json::from_str(case["stdout"].as_str().unwrap()).unwrap();
            let command = expected["command"].as_i64().unwrap() as i32;
            let whence = expected["whence"].as_i64().unwrap() as i16;
            let (holder, target) = files();
            holder.set_len(64).unwrap();
            // SAFETY: the owned descriptor is live; the offset is a bounded scalar.
            assert_eq!(
                unsafe { libc::lseek(target.as_raw_fd(), 16, libc::SEEK_SET) },
                16
            );
            let mut process = bounded_tests::process_with_profile(abi, false);
            let (_, mut thread) = process.proc.threads.pop_first().unwrap();
            let fd = process
                .proc
                .fds
                .install(
                    Arc::new(OpenFile::host(target.into(), 2, None)),
                    true,
                    0,
                    256,
                )
                .unwrap();
            let at = thread.cpu.sp() - 1024;
            let mut raw = request(expected["type"].as_i64().unwrap() as i16, 0, 0);
            raw[..8].copy_from_slice(&expected["start"].as_i64().unwrap().to_le_bytes());
            raw[16..20].copy_from_slice(&(expected["pid"].as_i64().unwrap() as i32).to_le_bytes());
            raw[22..24].copy_from_slice(&whence.to_le_bytes());
            process.proc.space.write(at, &raw).unwrap();
            let mut ctx = Ctx {
                proc: &mut process.proc,
                thread: &mut thread,
                nr: i64::from(nr::FCNTL),
                pc: 0x1_0000_1004,
            };
            let result = if expected["result"].as_i64().unwrap() < 0 {
                Err(Errno(expected["errno"].as_i64().unwrap() as i32))
            } else {
                Ok(Rv::one(0))
            };
            assert_eq!(
                file::fcntl(&mut ctx, fd, command, at),
                result,
                "{abi:?}/{expected}"
            );
            assert_eq!(ctx.read(at, 40).unwrap(), raw);
            assert!(ctx.thread.file_io.is_none() && ctx.thread.wait.is_none());
        }
    }
}
