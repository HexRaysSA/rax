//! Exercise the closed BSD dispatcher and scheduler for both native guest ABIs.

use super::*;
use crate::user::darwin::abi::{Errno, tables::nr};
use crate::user::darwin::arch::{Rv, SysResult};
use crate::user::darwin::io::{O_CLOEXEC, O_CLOFORK, O_NONBLOCK};
use crate::user::darwin::syscall::{Ctx, bsd};

fn call(proc: &mut Proc, thread: &mut Thread, number: u32, args: &[u64]) -> SysResult {
    let mut ctx = Ctx {
        proc,
        thread,
        nr: i64::from(number),
        pc: ENTRY,
    };
    let mut registers = [0; 8];
    registers[..args.len()].copy_from_slice(args);
    bsd::call(&mut ctx, number, &registers)
}

fn read<const N: usize>(proc: &Proc, address: u64) -> [u8; N] {
    let mut bytes = [0; N];
    proc.space.read(address, &mut bytes).unwrap();
    bytes
}

#[test]
fn embedded_pipe_bounds_descriptor_state_and_vector_io() {
    for abi in [DarwinAbi::Arm64, DarwinAbi::X86_64] {
        let mut process = process(abi);
        let proc = &mut process.proc;
        let (_, mut thread) = proc.threads.pop_first().unwrap();
        let buffer = thread.cpu.sp() - 0x300;
        let vector = buffer + 64;
        let flags = u64::from(O_CLOEXEC | O_CLOFORK | O_NONBLOCK);
        assert_eq!(
            call(proc, &mut thread, nr::PIPE2, &[0, u64::from(u32::MAX)]),
            Err(Errno::EINVAL)
        );
        let limit = proc.rlimits[8].0;
        proc.rlimits[8].0 = proc.fds.len() as u64 + 1;
        let before = proc.fds.len();
        assert_eq!(
            call(proc, &mut thread, nr::PIPE2, &[0, flags]),
            Err(Errno::EMFILE)
        );
        assert_eq!(proc.fds.len(), before);
        proc.rlimits[8].0 = limit;

        let Rv(reader, writer) = call(proc, &mut thread, nr::PIPE2, &[0, flags]).unwrap();
        for fd in [reader, writer] {
            let slot = proc.fds.get(fd as i32).unwrap();
            assert!(slot.cloexec && slot.clofork && slot.file.host_fd().is_none());
            assert_eq!(
                call(proc, &mut thread, nr::FPATHCONF, &[fd, 6]),
                Ok(Rv::one(512))
            );
        }
        assert_eq!(
            call(proc, &mut thread, nr::READ, &[reader, buffer, 1]),
            Err(Errno::EAGAIN)
        );
        assert_eq!(
            call(proc, &mut thread, nr::READ, &[writer, buffer, 1]),
            Err(Errno::EBADF)
        );
        proc.space.write(buffer, b"abcd").unwrap();
        let iov = [
            buffer.to_le_bytes(),
            2u64.to_le_bytes(),
            (buffer + 2).to_le_bytes(),
            2u64.to_le_bytes(),
        ];
        proc.space.write(vector, &iov.concat()).unwrap();
        assert_eq!(
            call(proc, &mut thread, nr::WRITEV, &[writer, vector, 2]),
            Ok(Rv::one(4))
        );
        assert_eq!(
            call(proc, &mut thread, nr::READ, &[reader, 0, 4]),
            Err(Errno::EFAULT)
        );
        assert_eq!(
            call(
                proc,
                &mut thread,
                nr::IOCTL,
                &[reader, 0x4004_667f, buffer + 8]
            ),
            Ok(Rv::one(0))
        );
        assert_eq!(u32::from_le_bytes(read(proc, buffer + 8)), 4);
        assert_eq!(
            call(proc, &mut thread, nr::FSTAT64, &[reader, buffer + 128]),
            Ok(Rv::one(0))
        );
        assert_eq!(u16::from_le_bytes(read(proc, buffer + 132)), 0o010660);
        assert_eq!(i64::from_le_bytes(read(proc, buffer + 128 + 96)), 4);
        assert_eq!(i32::from_le_bytes(read(proc, buffer + 128 + 112)), 16384);
        assert_eq!(
            call(proc, &mut thread, nr::LSEEK, &[reader, 0, 0]),
            Err(Errno::ESPIPE)
        );

        let mut pollfds = [0; 8 * 4];
        for (entry, fd) in pollfds
            .chunks_exact_mut(8)
            .zip([reader as i32, writer as i32, -1, 1024])
        {
            entry[..4].copy_from_slice(&fd.to_le_bytes());
            entry[4..6].copy_from_slice(&5i16.to_le_bytes());
        }
        let poll = buffer + 256;
        proc.space.write(poll, &pollfds).unwrap();
        assert_eq!(
            call(proc, &mut thread, nr::POLL, &[poll, 4, 0]),
            Ok(Rv::one(3))
        );
        let states = read::<32>(proc, poll);
        assert_eq!(
            [states[6], states[14], states[22], states[30]],
            [1, 4, 0, 0x20]
        );

        let alias = call(proc, &mut thread, nr::DUP, &[writer]).unwrap().0;
        assert_eq!(
            call(proc, &mut thread, nr::CLOSE, &[writer]),
            Ok(Rv::one(0))
        );
        assert_eq!(
            call(proc, &mut thread, nr::POLL, &[poll, 1, 0]),
            Ok(Rv::one(1))
        );
        assert_eq!(read::<1>(proc, poll + 6), [1]);
        assert_eq!(call(proc, &mut thread, nr::CLOSE, &[alias]), Ok(Rv::one(0)));
        assert_eq!(
            call(proc, &mut thread, nr::POLL, &[poll, 1, 0]),
            Ok(Rv::one(1))
        );
        assert_eq!(read::<1>(proc, poll + 6), [17]);
        for (fd, mask, expected) in [
            (reader as i32, 0i16, 0),
            (reader as i32, 2, 18),
            (reader as i32, 16, 16),
            (reader as i32, 512, 32),
            (1024, 0, 0),
        ] {
            proc.space.write(poll, &fd.to_le_bytes()).unwrap();
            proc.space.write(poll + 4, &mask.to_le_bytes()).unwrap();
            assert_eq!(
                call(proc, &mut thread, nr::POLL, &[poll, 1, 0]),
                Ok(Rv::one(u64::from(expected != 0)))
            );
            assert_eq!(read::<1>(proc, poll + 6), [expected]);
        }
        proc.rlimits[8].0 = 4;
        assert_eq!(
            call(proc, &mut thread, nr::POLL, &[0, 5, 0]),
            Err(Errno::EINVAL)
        );
        proc.rlimits[8].0 = limit;
        proc.space.write(buffer, b"xxxx").unwrap();
        assert_eq!(
            call(proc, &mut thread, nr::READV, &[reader, vector, 2]),
            Ok(Rv::one(4))
        );
        assert_eq!(&read::<4>(proc, buffer), b"abcd");
        assert_eq!(
            call(proc, &mut thread, nr::READ, &[reader, 0, 8]),
            Ok(Rv::one(0))
        );

        let Rv(reader, writer) = call(proc, &mut thread, nr::PIPE, &[]).unwrap();
        assert_eq!(
            call(proc, &mut thread, nr::FCNTL, &[writer, 73, 1]),
            Ok(Rv::one(0))
        );
        let alias = call(proc, &mut thread, nr::DUP, &[writer]).unwrap().0;
        assert_eq!(
            call(proc, &mut thread, nr::FCNTL, &[alias, 74, 0]),
            Ok(Rv::one(1))
        );
        assert_eq!(
            call(proc, &mut thread, nr::CLOSE, &[reader]),
            Ok(Rv::one(0))
        );
        assert_eq!(
            call(proc, &mut thread, nr::WRITE, &[alias, buffer, 1]),
            Err(Errno::EPIPE)
        );
        assert_eq!(thread.sig.pending, 0);
    }
}

fn set_syscall(proc: &Proc, thread: &mut Thread, number: u32, args: [u64; 3]) {
    match proc.abi {
        DarwinAbi::Arm64 => {
            proc.space
                .write_raw(ENTRY, &0xd400_1001u32.to_le_bytes())
                .unwrap();
            for (i, arg) in args.into_iter().enumerate() {
                thread.cpu.set_reg(i, arg);
            }
            thread.cpu.set_reg(16, u64::from(number));
        }
        DarwinAbi::X86_64 => {
            proc.space.write_raw(ENTRY, &[0x0f, 0x05]).unwrap();
            thread.cpu.set_reg(0, 0x200_0000 | u64::from(number));
            for (reg, arg) in [7, 6, 2].into_iter().zip(args) {
                thread.cpu.set_reg(reg, arg);
            }
        }
    }
    thread.cpu.set_pc(ENTRY);
}

#[test]
fn embedded_pipe_blocking_write_resumes_after_guest_reader_drains() {
    for abi in [DarwinAbi::Arm64, DarwinAbi::X86_64] {
        check_parked_writer(abi, false);
        check_parked_writer(abi, true);
    }
}

fn check_parked_writer(abi: DarwinAbi, close_reader: bool) {
    let mut p = process(abi);
    let (tid, mut writer_thread) = p.proc.threads.pop_first().unwrap();
    let (_, mut other) = process(abi).proc.threads.pop_first().unwrap();
    let Rv(reader, writer) = call(&mut p.proc, &mut other, nr::PIPE, &[]).unwrap();
    let source = writer_thread.cpu.sp() - 0x20000;
    let target = source - 0x20000;
    let bytes = [vec![0x5a; 65536], b"tail".to_vec()].concat();
    p.proc.space.write(source, &bytes).unwrap();
    set_syscall(
        &p.proc,
        &mut writer_thread,
        nr::WRITE,
        [writer, source, bytes.len() as u64],
    );
    p.proc.threads.insert(tid, writer_thread);
    let cancel = AtomicBool::new(false);
    assert_eq!(p.run_slice(1, &cancel), RunStatus::BudgetExhausted);
    let wait = p.proc.threads[&tid].wait.as_ref().unwrap();
    assert!(wait.fds.is_empty() && wait.pipes.len() == 1 && !wait.pipes[0].ready());
    assert_eq!(p.run_slice(1, &cancel), RunStatus::Blocked);
    if close_reader {
        assert_eq!(
            call(&mut p.proc, &mut other, nr::FCNTL, &[writer, 73, 1]),
            Ok(Rv::one(0))
        );
        assert_eq!(
            call(&mut p.proc, &mut other, nr::CLOSE, &[reader]),
            Ok(Rv::one(0))
        );
        assert_eq!(p.run_slice(1, &cancel), RunStatus::BudgetExhausted);
        let thread = &p.proc.threads[&tid];
        assert!(thread.wait.is_none() && thread.pending_unix.is_none());
        assert_eq!(thread.cpu.reg(0), Errno::EPIPE.0 as u64);
        assert_eq!(thread.sig.pending, 0);
        return;
    }
    assert_eq!(
        call(&mut p.proc, &mut other, nr::READ, &[reader, target, 65536]),
        Ok(Rv::one(65536))
    );
    let mut prefix = vec![0; 65536];
    p.proc.space.read(target, &mut prefix).unwrap();
    assert_eq!(prefix, bytes[..65536]);
    assert_eq!(p.run_slice(1, &cancel), RunStatus::BudgetExhausted);
    let thread = &p.proc.threads[&tid];
    assert!(thread.wait.is_none() && thread.pending_unix.is_none());
    assert_eq!(thread.cpu.reg(0), bytes.len() as u64);
    assert_eq!(p.proc.task.syscalls.1, 1);
    assert_eq!(
        call(&mut p.proc, &mut other, nr::READ, &[reader, target, 4]),
        Ok(Rv::one(4))
    );
    assert_eq!(&read::<4>(&p.proc, target), b"tail");
}
