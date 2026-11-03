//! Entered FIFO reads keep the closing slot reserved until kernel I/O ends.
use super::*;
use crate::user::darwin::abi::{Errno, tables::nr};
use crate::user::darwin::fd::{FileRef, OpenFile};
use crate::user::darwin::syscall::{Ctx, bsd::file};
use std::ffi::CString;
use std::os::fd::{FromRawFd, OwnedFd};
use std::sync::Arc;

const ENTRY: u64 = 0x1_0000_1000;

fn fifo(proc: &mut Proc) -> (i32, OwnedFd) {
    let (fd, writer, path) = named_fifo(proc, true);
    std::fs::remove_file(path).unwrap();
    (fd, writer.unwrap())
}

fn named_fifo(proc: &mut Proc, with_writer: bool) -> (i32, Option<OwnedFd>, std::path::PathBuf) {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let path = std::env::temp_dir().join(format!(
        "rax-fifo-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    use std::os::unix::ffi::OsStrExt;
    let native = CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: a fresh task-owned pathname and a valid terminated string.
    assert_eq!(unsafe { libc::mkfifo(native.as_ptr(), 0o600) }, 0);
    // SAFETY: both opens use the live FIFO path; successful handles are owned below.
    let read = unsafe { libc::open(native.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK) };
    assert!(read >= 0);
    let write = if with_writer {
        let fd = unsafe { libc::open(native.as_ptr(), libc::O_WRONLY | libc::O_NONBLOCK) };
        assert!(fd >= 0);
        // SAFETY: the successful writer open has one owning wrapper.
        Some(unsafe { OwnedFd::from_raw_fd(fd) })
    } else {
        None
    };
    // SAFETY: the read handle is live; F_SETFL has an integer third argument.
    assert_eq!(unsafe { libc::fcntl(read, libc::F_SETFL, 0) }, 0);
    // SAFETY: the successful reader open has exactly one owning wrapper.
    let read = unsafe { OwnedFd::from_raw_fd(read) };
    let file: FileRef = Arc::new(OpenFile::host(read, 0, None));
    (proc.fds.install(file, false, 0, 256).unwrap(), write, path)
}

fn start_read(process: &mut DarwinProcess, fd: i32, number: u32) -> (u64, u64, u64) {
    let result = enter_read(process, fd, number, 1);
    assert!(process.proc.threads[&result.0].wait.is_some());
    result
}

fn enter_read(process: &mut DarwinProcess, fd: i32, number: u32, capacity: u64) -> (u64, u64, u64) {
    let (tid, mut reading) = process.proc.threads.pop_first().unwrap();
    let buffer = reading.cpu.sp() - 1024;
    let vector = buffer + 64;
    process.proc.space.write(buffer, &[0xa5]).unwrap();
    process.proc.space.write(buffer + 8, &[0x5a]).unwrap();
    process
        .proc
        .space
        .write(
            vector,
            &[buffer.to_le_bytes(), capacity.to_le_bytes()].concat(),
        )
        .unwrap();
    let argument = if matches!(number, nr::READV | nr::READV_NOCANCEL) {
        vector
    } else {
        buffer
    };
    let instruction: &[u8] = match process.proc.abi {
        DarwinAbi::Arm64 => &[1, 16, 0, 212],
        DarwinAbi::X86_64 => &[15, 5, 144, 144],
    };
    process.proc.space.write_raw(ENTRY, instruction).unwrap();
    arguments(
        &mut reading,
        process.proc.abi,
        number,
        &[
            fd as u64,
            argument,
            if matches!(number, nr::READV | nr::READV_NOCANCEL) {
                1
            } else {
                capacity
            },
        ],
    );
    reading.cpu.set_pc(ENTRY);
    process.proc.threads.insert(tid, reading);
    assert_eq!(
        process.run_slice(1, &AtomicBool::new(false)),
        RunStatus::BudgetExhausted
    );
    (tid, buffer, vector)
}

fn arguments(thread: &mut Thread, abi: DarwinAbi, number: u32, values: &[u64]) {
    match abi {
        DarwinAbi::Arm64 => {
            for (index, &value) in values.iter().enumerate() {
                thread.cpu.set_reg(index, value);
            }
            thread.cpu.set_reg(16, u64::from(number));
        }
        DarwinAbi::X86_64 => {
            thread.cpu.set_reg(0, 0x200_0000 | u64::from(number));
            for (&index, &value) in [7, 6, 2, 10, 8, 9].iter().zip(values) {
                thread.cpu.set_reg(index, value);
            }
        }
    }
}

fn caller(proc: &mut Proc, tid: u64, number: u32, values: &[u64]) -> Thread {
    let mut thread = bounded_tests::process(proc.abi)
        .proc
        .threads
        .pop_first()
        .unwrap()
        .1;
    thread.tid = tid;
    thread.cpu = proc.new_thread_cpu();
    thread.kport = Port::new(KObject::Thread(tid));
    thread.port = proc.insert_send(&thread.kport);
    arguments(&mut thread, proc.abi, number, values);
    thread.cpu.set_pc(ENTRY + 64);
    syscall::dispatch(proc, &mut thread, Trap::Unix { code: number });
    thread
}

fn release(process: &DarwinProcess, writer: &OwnedFd) {
    use std::os::fd::AsRawFd;
    // SAFETY: this test owns a live FIFO writer and retains its entered reader.
    assert_eq!(
        unsafe { libc::write(writer.as_raw_fd(), b"a".as_ptr().cast(), 1) },
        1
    );
    wait_read_completions(process);
}

/// Native completion runs on the OS scheduler. Observe its actual descriptor
/// before asserting what one guest scheduler turn does with that completion.
fn wait_read_completions(process: &DarwinProcess) {
    for thread in process.proc.threads.values() {
        if thread.file_io.as_ref().is_some_and(|entry| entry.read)
            && let Some(wait) = &thread.wait
        {
            let deadline = Instant::now() + crate::host::time::Duration::from_secs(10);
            assert!(
                crate::user::darwin::wait::sleep(&wait.fds, Some(deadline))
                    .iter()
                    .any(|ready| *ready)
            );
        }
    }
}

fn finish_read(process: &mut DarwinProcess, tid: u64) {
    if process.proc.threads[&tid].pending_unix.is_some() {
        wait_read_completions(process);
        assert_eq!(
            process.run_slice(1, &AtomicBool::new(false)),
            RunStatus::BudgetExhausted
        );
    }
    assert!(process.proc.threads[&tid].pending_unix.is_none());
}

#[test]
fn fifo_eof_reads_and_a_reopened_writer_follow_native_state_on_both_abis() {
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    for abi in [DarwinAbi::Arm64, DarwinAbi::X86_64] {
        for number in [nr::READ, nr::READ_NOCANCEL, nr::READV, nr::READV_NOCANCEL] {
            let mut process = bounded_tests::process(abi);
            let (fd, writer, path) = named_fifo(&mut process.proc, false);
            assert!(writer.is_none());
            for _ in 0..3 {
                let (tid, buffer, _) = enter_read(&mut process, fd, number, 1);
                finish_read(&mut process, tid);
                assert_eq!(process.proc.threads[&tid].cpu.reg(0), 0);
                let mut observed = [0];
                process.proc.space.read(buffer, &mut observed).unwrap();
                assert_eq!(observed, [0xa5]);
            }
            let native = CString::new(path.as_os_str().as_bytes()).unwrap();
            // SAFETY: the owned FIFO pathname and reader remain live.
            let raw = unsafe { libc::open(native.as_ptr(), libc::O_WRONLY | libc::O_NONBLOCK) };
            assert!(raw >= 0);
            // SAFETY: this successful open has one owner.
            let writer = unsafe { OwnedFd::from_raw_fd(raw) };
            let host = process.proc.fds.file(fd).unwrap();
            // SAFETY: this test retains the native reader throughout the call.
            let initial_flags = unsafe { libc::fcntl(host.host_fd().unwrap(), libc::F_GETFL) };
            let (tid, buffer, _) = start_read(&mut process, fd, number);
            assert_eq!(
                process.run_slice(1, &AtomicBool::new(false)),
                RunStatus::Blocked
            );
            // SAFETY: this live descriptor belongs to the test's FileRef.
            assert_eq!(
                unsafe { libc::fcntl(host.host_fd().unwrap(), libc::F_GETFL) },
                initial_flags
            );
            assert_eq!(
                unsafe { libc::write(writer.as_raw_fd(), b"a".as_ptr().cast(), 1) },
                1
            );
            finish_read(&mut process, tid);
            assert_eq!(process.proc.threads[&tid].cpu.reg(0), 1);
            let mut observed = [0];
            process.proc.space.read(buffer, &mut observed).unwrap();
            assert_eq!(observed, *b"a");
            drop(writer);
            for _ in 0..3 {
                let (tid, _, _) = enter_read(&mut process, fd, number, 1);
                finish_read(&mut process, tid);
                assert_eq!(process.proc.threads[&tid].cpu.reg(0), 0);
            }
            std::fs::remove_file(path).unwrap();
        }
    }
}

#[test]
fn an_empty_fifo_zero_byte_read_returns_without_waiting_for_its_writer() {
    for abi in [DarwinAbi::Arm64, DarwinAbi::X86_64] {
        for number in [nr::READ, nr::READ_NOCANCEL, nr::READV, nr::READV_NOCANCEL] {
            let mut process = bounded_tests::process(abi);
            let (fd, _writer) = fifo(&mut process.proc);
            let (tid, _, _) = enter_read(&mut process, fd, number, 0);
            finish_read(&mut process, tid);
            assert_eq!(process.proc.threads[&tid].cpu.reg(0), 0);
        }
    }
}

#[test]
fn a_signal_completes_a_held_fifo_read_and_releases_its_close_drain() {
    for abi in [DarwinAbi::Arm64, DarwinAbi::X86_64] {
        let mut process = bounded_tests::process(abi);
        let (fd, _writer) = fifo(&mut process.proc);
        let (tid, _, _) = start_read(&mut process, fd, nr::READ);
        let mut closer = caller(&mut process.proc, tid + 1, nr::CLOSE, &[fd as u64]);
        closer.mach.suspend_count = 1;
        process.proc.threads.insert(tid + 1, closer);
        process.proc.sigacts.handler[signal::SIGUSR1 as usize] = ENTRY + 512;
        process.proc.sigacts.intr |= signal::bit(signal::SIGUSR1);
        let reader = process.proc.threads.get_mut(&tid).unwrap();
        reader.mach.suspend_count = 1;
        reader.sig.pending |= signal::bit(signal::SIGUSR1);
        reader.woken = true;
        assert_eq!(
            process.run_slice(1, &AtomicBool::new(false)),
            RunStatus::Blocked
        );
        let reader = &process.proc.threads[&tid];
        assert_eq!(
            reader.pending_unix.unwrap().completed,
            Some(Err(Errno::EINTR))
        );
        assert!(reader.wait.is_none());
        assert!(process.proc.threads[&(tid + 1)].wait.is_none());
        assert_eq!(process.proc.fds.lowest_free(0, 256).unwrap(), fd as usize);
    }
}

#[test]
fn guest_exit_joins_a_native_read_while_the_library_object_remains_inspectable() {
    for abi in [DarwinAbi::Arm64, DarwinAbi::X86_64] {
        let mut process = bounded_tests::process(abi);
        let (fd, _writer) = fifo(&mut process.proc);
        start_read(&mut process, fd, nr::READ);
        process.proc.exit_with(ExitStatus::Exited(7));
        assert_eq!(
            process.run_slice(1, &AtomicBool::new(false)),
            RunStatus::Complete(ExitStatus::Exited(7))
        );
    }
}

#[test]
fn draining_close_reports_native_uninterruptible_state_until_kernel_completion() {
    use crate::user::darwin::mig::thread::basic_info;
    for abi in [DarwinAbi::Arm64, DarwinAbi::X86_64] {
        let mut process = bounded_tests::process(abi);
        let (fd, writer) = fifo(&mut process.proc);
        let (reader, _, _) = start_read(&mut process, fd, nr::READ);
        let mut closer = caller(&mut process.proc, reader + 1, nr::CLOSE, &[fd as u64]);
        assert_eq!(basic_info(&closer, false, false, false)[6], 4);
        closer.mach.suspend_count = 1;
        assert_eq!(basic_info(&closer, false, false, false)[6], 4);
        process.proc.threads.insert(closer.tid, closer);
        release(&process, &writer);
        assert_eq!(
            process.run_slice(1, &AtomicBool::new(false)),
            RunStatus::BudgetExhausted
        );
        let closer = &process.proc.threads[&(reader + 1)];
        assert!(
            closer.wait.is_none(),
            "kernel close completes while user return is held"
        );
        assert_eq!(basic_info(closer, false, false, false)[6], 3);
        assert_eq!(basic_info(closer, false, false, false)[8], 1);
    }
}

#[test]
fn entered_fifo_close_waits_for_read_and_keeps_the_descriptor_reserved() {
    for abi in [DarwinAbi::Arm64, DarwinAbi::X86_64] {
        let mut process = bounded_tests::process(abi);
        let (fd, writer) = fifo(&mut process.proc);
        let (tid, buffer, _) = start_read(&mut process, fd, nr::READ);
        let mut closing = bounded_tests::process(abi)
            .proc
            .threads
            .pop_first()
            .unwrap()
            .1;
        closing.tid = tid + 1;
        let mut ctx = Ctx {
            proc: &mut process.proc,
            thread: &mut closing,
            nr: 6,
            pc: ENTRY + 64,
        };
        assert_eq!(
            file::close(&mut ctx, fd),
            Err(Errno::ERESTART),
            "{abi:?}: native close waits for entered FIFO I/O"
        );
        assert_eq!(ctx.proc.fds.file(fd).unwrap_err(), Errno::EBADF);
        assert_ne!(ctx.proc.fds.lowest_free(0, 256).unwrap(), fd as usize);
        let inherited = crate::user::darwin::exec::fdt_fork(&ctx.proc.fds, false);
        assert_eq!(inherited.lowest_free(0, 256).unwrap(), fd as usize);
        release(&process, &writer);
        assert_eq!(
            process.run_slice(1, &AtomicBool::new(false)),
            RunStatus::BudgetExhausted
        );
        assert_eq!(process.proc.threads[&tid].cpu.reg(0), 1);
        let mut observed = [0];
        process.proc.space.read(buffer, &mut observed).unwrap();
        assert_eq!(&observed, b"a");
        assert_eq!(process.proc.fds.lowest_free(0, 256).unwrap(), fd as usize);
    }
}

#[test]
fn entered_fifo_readv_keeps_the_vector_copied_before_sleep() {
    for abi in [DarwinAbi::Arm64, DarwinAbi::X86_64] {
        for number in [nr::READV, nr::READV_NOCANCEL] {
            let mut process = bounded_tests::process(abi);
            let (fd, writer) = fifo(&mut process.proc);
            let (tid, buffer, vector) = start_read(&mut process, fd, number);
            process
                .proc
                .space
                .write(vector, &(buffer + 8).to_le_bytes())
                .unwrap();
            release(&process, &writer);
            assert_eq!(
                process.run_slice(1, &AtomicBool::new(false)),
                RunStatus::BudgetExhausted
            );
            assert_eq!(process.proc.threads[&tid].cpu.reg(0), 1);
            let mut original = [0];
            let mut redirected = [0];
            process.proc.space.read(buffer, &mut original).unwrap();
            process
                .proc
                .space
                .read(buffer + 8, &mut redirected)
                .unwrap();
            assert_eq!(original, [b'a']);
            assert_eq!(redirected, [0x5a]);
        }
    }
}

#[test]
fn fifo_kernel_completion_releases_close_when_reader_or_closer_is_held() {
    for abi in [DarwinAbi::Arm64, DarwinAbi::X86_64] {
        for number in [nr::READ, nr::READ_NOCANCEL, nr::READV, nr::READV_NOCANCEL] {
            for hold_reader in [false, true] {
                let mut process = bounded_tests::process(abi);
                let (fd, writer) = fifo(&mut process.proc);
                let (tid, _, _) = start_read(&mut process, fd, number);
                let mut closing = caller(&mut process.proc, tid + 1, nr::CLOSE, &[fd as u64]);
                assert!(
                    closing
                        .wait
                        .as_ref()
                        .is_some_and(|wait| !wait.interruptible)
                );
                if hold_reader {
                    process
                        .proc
                        .threads
                        .get_mut(&tid)
                        .unwrap()
                        .mach
                        .suspend_count = 1;
                } else {
                    closing.mach.suspend_count = 1;
                }
                process.proc.threads.insert(tid + 1, closing);
                release(&process, &writer);
                assert_eq!(
                    process.run_slice(1, &AtomicBool::new(false)),
                    RunStatus::BudgetExhausted
                );
                assert_eq!(process.proc.fds.lowest_free(0, 256).unwrap(), fd as usize);
                let held = if hold_reader { tid } else { tid + 1 };
                let completed = process.proc.threads[&held].pending_unix.unwrap();
                assert!(completed.completed.is_some());
                assert_eq!(completed.result_prepared, abi == DarwinAbi::Arm64);
                process
                    .proc
                    .threads
                    .get_mut(&held)
                    .unwrap()
                    .mach
                    .suspend_count = 0;
                assert_eq!(
                    process.run_slice(1, &AtomicBool::new(false)),
                    RunStatus::BudgetExhausted
                );
                assert!(process.proc.threads[&held].pending_unix.is_none());
                assert_eq!(process.proc.threads[&tid].cpu.reg(0), 1);
                assert_eq!(process.proc.threads[&(tid + 1)].cpu.reg(0), 0);
            }
        }
    }
}

#[test]
fn a_dup2_source_close_waits_and_invalidates_installation_after_target_drain() {
    for abi in [DarwinAbi::Arm64, DarwinAbi::X86_64] {
        let mut process = bounded_tests::process(abi);
        let (fd, writer) = fifo(&mut process.proc);
        let (source, _source_writer) = fifo(&mut process.proc);
        let (tid, _, _) = start_read(&mut process, fd, nr::READ);
        let duplicate = caller(
            &mut process.proc,
            tid + 1,
            nr::DUP2,
            &[source as u64, fd as u64],
        );
        assert!(duplicate.wait.is_some());
        process.proc.threads.insert(tid + 1, duplicate);
        let closing_source = caller(&mut process.proc, tid + 2, nr::CLOSE, &[source as u64]);
        assert!(closing_source.wait.is_some());
        process.proc.threads.insert(tid + 2, closing_source);
        release(&process, &writer);
        assert_eq!(
            process.run_slice(3, &AtomicBool::new(false)),
            RunStatus::BudgetExhausted
        );
        assert_eq!(process.proc.threads[&(tid + 1)].cpu.reg(0), 9);
        assert_eq!(process.proc.threads[&(tid + 2)].cpu.reg(0), 0);
        assert_eq!(process.proc.fds.file(fd).unwrap_err(), Errno::EBADF);
        assert_eq!(process.proc.fds.file(source).unwrap_err(), Errno::EBADF);
        assert_eq!(process.proc.fds.lowest_free(0, 256).unwrap(), fd as usize);
    }
}

#[test]
fn terminating_an_entered_reader_releases_its_file_reference_and_close_barrier() {
    for abi in [DarwinAbi::Arm64, DarwinAbi::X86_64] {
        let mut process = bounded_tests::process(abi);
        let (fd, _writer) = fifo(&mut process.proc);
        let retained = Arc::downgrade(&process.proc.fds.file(fd).unwrap());
        let (tid, _, _) = start_read(&mut process, fd, nr::READ);
        let closing = caller(&mut process.proc, tid + 1, nr::CLOSE, &[fd as u64]);
        process.proc.threads.insert(tid + 1, closing);
        process.proc.threads.get_mut(&tid).unwrap().exited = true;
        assert_eq!(
            process.run_slice(1, &AtomicBool::new(false)),
            RunStatus::BudgetExhausted
        );
        assert!(retained.upgrade().is_none());
        assert_eq!(process.proc.fds.lowest_free(0, 256).unwrap(), fd as usize);
        assert_eq!(process.proc.threads[&(tid + 1)].cpu.reg(0), 0);
    }
}
