//! Replay guarded pipe/FIFO entered-write snapshots and close results.
use super::*;
use crate::user::darwin::arch::Rv;

fn full_writer(proc: &mut Proc, named: bool) -> (i32, OwnedFd, usize) {
    use std::os::fd::AsRawFd;
    let (reader, writer) = if named {
        let (fd, writer) = fifo(proc);
        let file = Arc::try_unwrap(proc.fds.remove(fd).unwrap().file).unwrap();
        let crate::user::darwin::fd::FileKind::Host(reader) = file.kind else {
            unreachable!()
        };
        (reader, writer)
    } else {
        let mut raw = [-1; 2];
        // SAFETY: two writable descriptor slots; successful results are owned.
        assert_eq!(unsafe { libc::pipe(raw.as_mut_ptr()) }, 0);
        unsafe { (OwnedFd::from_raw_fd(raw[0]), OwnedFd::from_raw_fd(raw[1])) }
    };
    let host = writer.as_raw_fd();
    // SAFETY: this test owns the live pipe/FIFO writer.
    assert_eq!(
        unsafe { libc::fcntl(host, libc::F_SETFL, libc::O_NONBLOCK) },
        0
    );
    let bytes = [b'.'; 4096];
    let mut filled = 0;
    loop {
        // SAFETY: bytes is readable for its complete length.
        let count = unsafe { libc::write(host, bytes.as_ptr().cast(), bytes.len()) };
        if count < 0 {
            assert_eq!(Errno::last(), Errno::EAGAIN);
            break;
        }
        assert!(count > 0);
        filled += count as usize;
        assert!(filled <= 1 << 20);
    }
    // SAFETY: restore the blocking mode selected by the native control.
    assert_eq!(unsafe { libc::fcntl(host, libc::F_SETFL, 0) }, 0);
    let file = Arc::new(OpenFile::host(
        writer,
        crate::user::darwin::io::O_WRONLY,
        None,
    ));
    (
        proc.fds.install(file, false, 0, 256).unwrap(),
        reader,
        filled,
    )
}

use crate::user::darwin::fd::DescriptorGuard;
use crate::user::darwin::signal::{self, SigAction};
use std::os::fd::AsRawFd;

fn replay(
    abi: DarwinAbi,
    native: &serde_json::Value,
    handler: u64,
    suppress_sigpipe: bool,
) -> usize {
    let mut process = bounded_tests::process(abi);
    process.proc.sigacts.set(
        signal::SIGPIPE,
        &SigAction {
            handler,
            ..SigAction::default()
        },
    );
    let (fd, reader, filled) = full_writer(&mut process.proc, native["kind"] == "fifo");
    #[cfg(target_os = "macos")]
    if suppress_sigpipe {
        let host = process.proc.fds.file(fd).unwrap().host_fd().unwrap();
        // SAFETY: this test owns the live native pipe/FIFO open file.
        assert_eq!(
            unsafe { libc::fcntl(host, file::cmd::F_SETNOSIGPIPE, 1) },
            0
        );
    }
    #[cfg(not(target_os = "macos"))]
    assert!(
        !suppress_sigpipe,
        "native F_SETNOSIGPIPE control requires macOS"
    );
    let slot = process.proc.fds.get_mut(fd).unwrap();
    slot.guard = Some(DescriptorGuard {
        cookie: 0x1122_3344_5566_7788,
        attributes: 19,
    });
    slot.cloexec = true;
    slot.clofork = true;
    let (tid, mut writing) = process.proc.threads.pop_first().unwrap();
    let at = writing.cpu.sp() - 1024;
    process.proc.space.write(at, b"AB").unwrap();
    process
        .proc
        .space
        .write(at + 16, &0x1122_3344_5566_7788u64.to_le_bytes())
        .unwrap();
    process
        .proc
        .space
        .write(at + 128, &0x1122_3344_5566_7788u64.to_le_bytes())
        .unwrap();
    process
        .proc
        .space
        .write(at + 32, &[at.to_le_bytes(), 1u64.to_le_bytes()].concat())
        .unwrap();
    let vector = native["vector"].as_bool().unwrap();
    let number = if vector {
        nr::GUARDED_WRITEV_NP
    } else {
        nr::GUARDED_WRITE_NP
    };
    let instruction: &[u8] = match abi {
        DarwinAbi::Arm64 => &[1, 16, 0, 212],
        DarwinAbi::X86_64 => &[15, 5, 144, 144],
    };
    process.proc.space.write_raw(ENTRY, instruction).unwrap();
    arguments(
        &mut writing,
        abi,
        number,
        &[fd as u64, at + 16, if vector { at + 32 } else { at }, 1],
    );
    writing.cpu.set_pc(ENTRY);
    process.proc.threads.insert(tid, writing);
    assert_eq!(
        process.run_slice(1, &AtomicBool::new(false)),
        RunStatus::BudgetExhausted
    );
    assert!(
        process.proc.threads[&tid].wait.is_some(),
        "{abi:?}/{native}"
    );
    process
        .proc
        .threads
        .get_mut(&tid)
        .unwrap()
        .mach
        .suspend_count = 1;
    let mutation = native["mutation"].as_u64().unwrap();
    if mutation & 1 != 0 {
        process
            .proc
            .space
            .write(at + 16, &0x8877_6655_4433_2211u64.to_le_bytes())
            .unwrap();
    }
    if mutation & 2 != 0 {
        process
            .proc
            .space
            .write(at + 32, &(at + 1).to_le_bytes())
            .unwrap();
    }
    let rows = native["records"].as_array().unwrap();
    if native["concurrent_close"].as_bool().unwrap() {
        let mut closing = caller(
            &mut process.proc,
            tid + 1,
            nr::GUARDED_CLOSE_NP,
            &[fd as u64, at + 128],
        );
        // The native producer owns fd 0-2 plus reader 3 and writer 4.
        // Reuse of writer 4 means close completed; 5 means reserved.
        let duplicate = rows
            .iter()
            .find(|r| r["kind"] == "during-close-duplicate")
            .unwrap()["result"]
            .as_i64()
            .unwrap();
        let reusable = duplicate == 4;
        assert_eq!(closing.wait.is_none(), reusable, "{abi:?}/{native}");
        assert_eq!(
            process.proc.fds.lowest_free(fd as usize, 256).unwrap() == fd as usize,
            reusable
        );
        assert_eq!(process.proc.fds.get(fd).unwrap_err(), Errno::EBADF);
        closing.mach.suspend_count = 1;
        process.proc.threads.insert(tid + 1, closing);
    }
    let mut bytes = [0u8; 4096];
    // SAFETY: the test retains its reader and supplies a writable buffer.
    let count = unsafe { libc::read(reader.as_raw_fd(), bytes.as_mut_ptr().cast(), bytes.len()) };
    assert!(count > 0);
    let mut received = count as usize;
    let mut last = bytes[count as usize - 1];
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        file::lifetime::progress(&mut process.proc);
        if process.proc.threads[&tid]
            .pending_unix
            .unwrap()
            .completed
            .is_some()
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "entered write did not complete: {abi:?}/{native}"
        );
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    let expected = rows.iter().find(|r| r["kind"] == "write-result").unwrap();
    let written = expected["result"].as_i64().unwrap();
    let expected = if written < 0 {
        Err(Errno(expected["errno"].as_i64().unwrap() as i32))
    } else {
        Ok(Rv::one(written as u64))
    };
    assert_eq!(
        process.proc.threads[&tid].pending_unix.unwrap().completed,
        Some(expected),
        "{abi:?}/{native}"
    );
    if native["concurrent_close"].as_bool().unwrap() {
        assert!(process.proc.threads[&(tid + 1)].wait.is_none());
        assert_eq!(
            process.proc.fds.lowest_free(fd as usize, 256).unwrap(),
            fd as usize
        );
    } else {
        let closing = caller(
            &mut process.proc,
            tid + 1,
            nr::GUARDED_CLOSE_NP,
            &[fd as u64, at + 128],
        );
        assert!(closing.wait.is_none());
        assert_eq!(closing.cpu.reg(0), 0);
    }
    loop {
        // SAFETY: same retained reader and writable buffer; all writers closed.
        let count =
            unsafe { libc::read(reader.as_raw_fd(), bytes.as_mut_ptr().cast(), bytes.len()) };
        assert!(count >= 0);
        if count == 0 {
            break;
        }
        received += count as usize;
        last = bytes[count as usize - 1];
    }
    // Host pipe capacities differ; the observed payload/close relationship does not.
    assert_eq!(received, filled + usize::from(written == 1));
    assert_eq!(
        u64::from(last),
        rows.iter().find(|r| r["kind"] == "last-byte").unwrap()["result"]
            .as_u64()
            .unwrap()
    );
    assert!(process.proc.guard_ast.is_none());
    process
        .proc
        .threads
        .values()
        .filter(|thread| thread.sig.pending & signal::bit(signal::SIGPIPE) != 0)
        .count()
}

#[test]
fn guarded_fd_replays_64_native_blocked_writes_cookie_vectors_and_close() {
    for (abi, input) in [
        (
            DarwinAbi::Arm64,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/darwin/native-guarded-fd/blocked-write-records-arm64-v12.json"
            )),
        ),
        (
            DarwinAbi::X86_64,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/darwin/native-guarded-fd/blocked-write-records-x86_64-v12.json"
            )),
        ),
    ] {
        let records: serde_json::Value = serde_json::from_str(input).unwrap();
        assert_eq!(records.as_array().unwrap().len(), 32);
        for native in records.as_array().unwrap() {
            assert_eq!(replay(abi, native, signal::SIG_IGN, false), 0);
        }
    }
}

fn replay_signal_controls(suppressed: bool) {
    let corpus: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/darwin/native-pipe-close-write/native-signal-v1.json"
    )))
    .unwrap();
    let mut cases = 0;
    for native in corpus["cases"].as_array().unwrap() {
        if native["suppress_sigpipe"].as_bool().unwrap() != suppressed {
            continue;
        }
        let abi = match native["architecture"].as_str().unwrap() {
            "arm64" => DarwinAbi::Arm64,
            "x86_64" => DarwinAbi::X86_64,
            other => panic!("unknown native ABI {other}"),
        };
        let records: Vec<serde_json::Value> = native["stdout"]
            .as_str()
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let expected = records
            .iter()
            .find(|row| row["kind"] == "observed-sigpipe")
            .unwrap()["result"]
            .as_u64()
            .unwrap();
        let fixture = serde_json::json!({"kind": native["kind"], "vector": native["vector"], "mutation": 0,
            "concurrent_close": true, "records": records});
        let pending = replay(abi, &fixture, ENTRY + 128, suppressed);
        assert_eq!(pending as u64, expected, "{abi:?}/{native}");
        cases += 1;
    }
    assert_eq!(cases, 8);
}

#[test]
fn entered_pipe_close_queues_the_native_sigpipe_outcome() {
    replay_signal_controls(false);
}

#[cfg(target_os = "macos")]
#[test]
fn entered_pipe_close_respects_native_nosigpipe() {
    replay_signal_controls(true);
}
