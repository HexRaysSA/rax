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
    let write = unsafe { libc::open(native.as_ptr(), libc::O_WRONLY | libc::O_NONBLOCK) };
    assert!(write >= 0);
    std::fs::remove_file(path).unwrap();
    // SAFETY: the read handle is live; F_SETFL has an integer third argument.
    assert_eq!(unsafe { libc::fcntl(read, libc::F_SETFL, 0) }, 0);
    // SAFETY: each successful open above has exactly one owning wrapper.
    let (read, write) = unsafe { (OwnedFd::from_raw_fd(read), OwnedFd::from_raw_fd(write)) };
    let file: FileRef = Arc::new(OpenFile::host(read, 0, None));
    (proc.fds.install(file, false, 0, 256).unwrap(), write)
}

fn start_read(process: &mut DarwinProcess, fd: i32, number: u32) -> (u64, u64, u64) {
    let (tid, mut reading) = process.proc.threads.pop_first().unwrap();
    let buffer = reading.cpu.sp() - 1024;
    let vector = buffer + 64;
    process.proc.space.write(buffer, &[0xa5]).unwrap();
    process.proc.space.write(buffer + 8, &[0x5a]).unwrap();
    process
        .proc
        .space
        .write(vector, &[buffer.to_le_bytes(), 1u64.to_le_bytes()].concat())
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
        &[fd as u64, argument, 1],
    );
    reading.cpu.set_pc(ENTRY);
    process.proc.threads.insert(tid, reading);
    assert_eq!(
        process.run_slice(1, &AtomicBool::new(false)),
        RunStatus::BudgetExhausted
    );
    assert!(process.proc.threads[&tid].wait.is_some());
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

fn release(writer: &OwnedFd) {
    use std::os::fd::AsRawFd;
    // SAFETY: this test owns a live FIFO writer and retains its entered reader.
    assert_eq!(
        unsafe { libc::write(writer.as_raw_fd(), b"a".as_ptr().cast(), 1) },
        1
    );
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
        release(&writer);
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
            release(&writer);
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
                release(&writer);
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
        release(&writer);
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
