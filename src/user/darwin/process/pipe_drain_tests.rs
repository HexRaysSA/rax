//! Native-derived pipe drain semantics distinguish a descriptor from its aliases.
use super::*;
use crate::user::darwin::abi::tables::nr;
use crate::user::darwin::arch::Rv;
use crate::user::darwin::syscall::{Ctx, bsd::file};

const ENTRY: u64 = 0x1_0000_1000;

fn pipe(proc: &mut Proc, thread: &mut Thread) -> (i32, i32) {
    let mut ctx = Ctx {
        proc,
        thread,
        nr: i64::from(nr::PIPE),
        pc: ENTRY,
    };
    let Rv(read, write) = file::pipe(&mut ctx).unwrap();
    (read as i32, write as i32)
}

fn write(proc: &Proc, fd: i32, byte: u8) {
    let file = proc.fds.file(fd).unwrap();
    let host = file.host_fd().unwrap();
    // SAFETY: live owned pipe writer and one readable byte. Each caller retains
    // a live read descriptor; closed-reader EPIPE is covered by the native probe.
    assert_eq!(
        unsafe { libc::write(host, (&byte as *const u8).cast(), 1) },
        1
    );
}

#[test]
fn entered_bsd_pipe_close_and_replacement_keep_eof_separate_from_other_aliases() {
    for abi in [DarwinAbi::Arm64, DarwinAbi::X86_64] {
        for number in [nr::READ, nr::READ_NOCANCEL, nr::READV, nr::READV_NOCANCEL] {
            for action in 0..6 {
                let mut process = bounded_tests::process(abi);
                let (tid, mut reading) = process.proc.threads.pop_first().unwrap();
                let mut other = bounded_tests::process(abi)
                    .proc
                    .threads
                    .pop_first()
                    .unwrap()
                    .1;
                other.tid = tid + 1;
                let (original, writer) = pipe(&mut process.proc, &mut other);
                let (replacement, replacement_writer) = pipe(&mut process.proc, &mut other);
                write(&process.proc, replacement_writer, b'b');
                let mut fd = original;
                let mut closing = original;
                if (2..=4).contains(&action) {
                    let file = process.proc.fds.file(original).unwrap();
                    let alias = process.proc.fds.install(file, false, 0, 256).unwrap();
                    if action == 2 {
                        closing = alias;
                    } else {
                        fd = alias;
                    }
                }
                let buffer = reading.cpu.sp() - 1024;
                let vector = buffer + 64;
                process.proc.space.write(buffer, &[0xa5]).unwrap();
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
                let next = match abi {
                    DarwinAbi::Arm64 => {
                        process
                            .proc
                            .space
                            .write_raw(ENTRY, &0xd400_1001u32.to_le_bytes())
                            .unwrap();
                        for (i, value) in [fd as u64, argument, 1].into_iter().enumerate() {
                            reading.cpu.set_reg(i, value);
                        }
                        reading.cpu.set_reg(16, u64::from(number));
                        ENTRY + 4
                    }
                    DarwinAbi::X86_64 => {
                        process
                            .proc
                            .space
                            .write_raw(ENTRY, &[0x0f, 0x05, 0x90, 0x90])
                            .unwrap();
                        reading.cpu.set_reg(0, 0x200_0000 | u64::from(number));
                        for (i, value) in [(7, fd as u64), (6, argument), (2, 1)] {
                            reading.cpu.set_reg(i, value);
                        }
                        ENTRY + 2
                    }
                };
                reading.cpu.set_pc(ENTRY);
                process.proc.threads.insert(tid, reading);
                assert_eq!(
                    process.run_slice(1, &AtomicBool::new(false)),
                    RunStatus::BudgetExhausted
                );
                assert!(process.proc.threads[&tid].wait.is_some());
                assert_eq!(
                    process.proc.threads[&tid].cpu.pc(),
                    next,
                    "{abi:?}/{number}/{action}: entered PC"
                );
                {
                    let mut ctx = Ctx {
                        proc: &mut process.proc,
                        thread: &mut other,
                        nr: 6,
                        pc: ENTRY + 64,
                    };
                    match action {
                        1 | 4 => assert_eq!(
                            file::dup2(&mut ctx, replacement, closing),
                            Ok(Rv::one(closing as u64))
                        ),
                        5 => assert_eq!(
                            file::dup2(&mut ctx, original, original),
                            Ok(Rv::one(original as u64))
                        ),
                        _ => assert_eq!(file::close(&mut ctx, closing), Ok(Rv::one(0))),
                    }
                }
                let cancelled = action <= 1;
                if !cancelled {
                    write(&process.proc, writer, b'a');
                }
                assert_eq!(
                    process.run_slice(1, &AtomicBool::new(false)),
                    RunStatus::BudgetExhausted
                );
                let thread = &process.proc.threads[&tid];
                assert_eq!(
                    thread.cpu.reg(0),
                    u64::from(!cancelled),
                    "{abi:?}/{number}/{action}"
                );
                assert_eq!(
                    thread.cpu.pc(),
                    next,
                    "a continuation retires no user instruction"
                );
                assert!(
                    thread.wait.is_none()
                        && thread.resume.is_none()
                        && thread.pending_unix.is_none()
                );
                let mut byte = [0];
                process.proc.space.read(buffer, &mut byte).unwrap();
                assert_eq!(byte, [if cancelled { 0xa5 } else { b'a' }]);
                assert_eq!(
                    process.proc.task.syscalls.1, 1,
                    "one entered syscall across the wait"
                );
            }
        }
    }
}
