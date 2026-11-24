//! Static Mach-O fixtures exercise bounded execution without a host dyld.
use super::*;
use crate::user::image::macho::*;

#[path = "closed_pipe_tests.rs"]
mod closed_pipe_tests;
#[path = "closed_spawn_tests.rs"]
mod closed_spawn_tests;

const TEXT: u64 = 0x1_0000_0000;
const ENTRY: u64 = TEXT + 0x1000;
const PAGE: u64 = 0x4000;

fn command(kind: u32, body: &[u8]) -> Vec<u8> {
    [
        kind.to_le_bytes().to_vec(),
        ((8 + body.len()) as u32).to_le_bytes().to_vec(),
        body.to_vec(),
    ]
    .concat()
}
fn segment(name: &[u8], address: u64, size: u64, file_size: u64, protection: u32) -> Vec<u8> {
    let mut body = vec![0; 16];
    body[..name.len()].copy_from_slice(name);
    for value in [address, size, 0, file_size] {
        body.extend_from_slice(&value.to_le_bytes());
    }
    for value in [protection, protection, 0, 0] {
        body.extend_from_slice(&value.to_le_bytes());
    }
    command(LC_SEGMENT_64, &body)
}
pub(crate) fn process(abi: DarwinAbi) -> DarwinProcess {
    process_with_profile(abi, true)
}

pub(crate) fn process_with_profile(abi: DarwinAbi, embedded: bool) -> DarwinProcess {
    let (kind, subtype, flavor, count, pc_index) = match abi {
        DarwinAbi::X86_64 => (
            CPU_TYPE_X86_64,
            CPU_SUBTYPE_X86_64_ALL,
            X86_THREAD_STATE64,
            X86_THREAD_STATE64_COUNT,
            16,
        ),
        DarwinAbi::Arm64 => (
            CPU_TYPE_ARM64,
            CPU_SUBTYPE_ARM64_ALL,
            ARM_THREAD_STATE64,
            ARM_THREAD_STATE64_COUNT,
            32,
        ),
    };
    let mut thread = Vec::new();
    thread.extend_from_slice(&flavor.to_le_bytes());
    thread.extend_from_slice(&count.to_le_bytes());
    thread.resize(8 + count as usize * 4, 0);
    thread[8 + pc_index * 8..8 + (pc_index + 1) * 8].copy_from_slice(&ENTRY.to_le_bytes());
    let commands = [
        segment(b"__PAGEZERO", 0, TEXT, 0, 0),
        segment(b"__TEXT", TEXT, PAGE, PAGE, VM_PROT_READ | VM_PROT_EXECUTE),
        command(LC_UNIXTHREAD, &thread),
    ];
    let mut bytes = Vec::new();
    for value in [
        MH_MAGIC_64,
        kind,
        subtype,
        MH_EXECUTE,
        commands.len() as u32,
        commands.iter().map(Vec::len).sum::<usize>() as u32,
        0,
        0,
    ] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    for command in commands {
        bytes.extend(command);
    }
    bytes.resize(PAGE as usize, 0);
    // exit(37): BSD class 2 / syscall 1 on x86-64, x16=1 on arm64.
    let code = match abi {
        DarwinAbi::X86_64 => vec![0xb8, 1, 0, 0, 2, 0xbf, 37, 0, 0, 0, 0x0f, 0x05],
        DarwinAbi::Arm64 => [0xd280_0030u32, 0xd280_04a0, 0xd400_0001]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect(),
    };
    bytes[0x1000..0x1000 + code.len()].copy_from_slice(&code);
    let mut config = if embedded {
        DarwinConfig::embedded(
            "/bounded-test",
            vec![b"/bounded-test".to_vec()],
            vec![],
            crate::user::supplied_fs::Files::new(BTreeMap::new()).unwrap(),
            crate::user::console::CapturedConsole::new(Vec::new(), 4096).unwrap(),
        )
    } else {
        DarwinConfig::new("/bounded-test", vec![b"/bounded-test".to_vec()], vec![])
    };
    config.abi = Some(abi);
    config.seed = Some(1);
    config.arena_bytes = 64 << 20;
    config.slice_insns = 1;
    DarwinProcess::spawn(
        config,
        ImageFile {
            path: "/bounded-test".into(),
            host_path: "/bounded-test".into(),
            vnode_path: "/bounded-test".into(),
            bytes: bytes.into(),
            file_id: (0, 0),
            slice: None,
        },
    )
    .unwrap()
}
fn finish(p: &mut DarwinProcess) {
    for _ in 0..100 {
        match p.run_slice(1, &AtomicBool::new(false)) {
            RunStatus::BudgetExhausted => {}
            RunStatus::Complete(status) => {
                assert_eq!(status, ExitStatus::Exited(37));
                return;
            }
            other => panic!("unexpected result: {other:?}"),
        }
    }
    panic!("exit did not complete within 100 turns");
}

#[cfg(unix)]
#[test]
fn ptrace_step_state_preserves_other_architectural_bits() {
    use crate::user::darwin::syscall::bsd::ptrace::set_step_state;
    let mut x86 = process(DarwinAbi::X86_64);
    let thread = x86.proc.threads.values_mut().next().unwrap();
    let DarwinCpu::X86_64(cpu) = &mut thread.cpu else {
        unreachable!()
    };
    cpu.vcpu_mut().set_user_rflags(0x203);
    set_step_state(thread, true);
    let DarwinCpu::X86_64(cpu) = &thread.cpu else {
        unreachable!()
    };
    assert_eq!(cpu.vcpu().user_rflags(), 0x303);
    set_step_state(thread, false);
    let DarwinCpu::X86_64(cpu) = &thread.cpu else {
        unreachable!()
    };
    assert_eq!(cpu.vcpu().user_rflags(), 0x203);

    let mut arm = process(DarwinAbi::Arm64);
    let thread = arm.proc.threads.values_mut().next().unwrap();
    thread.mach.debug_state = vec![0; 130];
    thread.mach.debug_state[3] = 0x1234;
    thread.mach.debug_state[128] = 0x10;
    set_step_state(thread, true);
    assert_eq!(thread.mach.debug_state[128], 0x11);
    set_step_state(thread, false);
    assert_eq!(thread.mach.debug_state[128], 0x10);
    assert_eq!(thread.mach.debug_state[3], 0x1234);
}

#[test]
fn x86_single_step_reports_debug_exception_entry() {
    let mut process = process(DarwinAbi::X86_64);
    let tid = *process.proc.threads.keys().next().unwrap();
    let mut thread = process.proc.threads.remove(&tid).unwrap();
    thread.sig.entry.trapno = 0xdd;
    thread.sig.entry.err = 0x42;
    crate::user::darwin::exception::raise_single_step(&mut process.proc, &mut thread);
    assert_eq!(thread.sig.entry.trapno, 1);
    assert_eq!(thread.sig.entry.err, 0);
    assert_ne!(thread.sig.pending & signal::bit(signal::SIGTRAP), 0);
}

#[test]
fn ptrace_self_requests_and_exec_flag_projection() {
    use crate::user::darwin::{
        abi::Errno,
        arch::Rv,
        syscall::{Ctx, bsd},
    };
    for abi in [DarwinAbi::X86_64, DarwinAbi::Arm64] {
        let mut p = process(abi);
        let (_, mut thread) = p.proc.threads.pop_first().unwrap();
        let pid = p.proc.pid;
        let mut ctx = Ctx {
            proc: &mut p.proc,
            thread: &mut thread,
            nr: i64::from(crate::user::darwin::abi::tables::nr::PTRACE),
            pc: ENTRY,
        };
        let call =
            |ctx: &mut Ctx<'_>, request, target| bsd::ptrace::ptrace(ctx, request, target, 1, 0);
        assert_eq!(call(&mut ctx, 12, 0), Err(Errno::EINVAL));
        assert_eq!(call(&mut ctx, 7, 1), Err(Errno::EPERM));
        assert_eq!(call(&mut ctx, 7, pid), Err(Errno::EPERM));
        assert_eq!(call(&mut ctx, 14, pid), Err(Errno::EINVAL));
        assert_eq!(call(&mut ctx, 31, 0), Ok(Rv::one(0)));
        assert_eq!(call(&mut ctx, 31, 0), Ok(Rv::one(0)));
        assert!(ctx.proc.tracing.deny_attach);
        assert_eq!(call(&mut ctx, 14, pid), Err(Errno::EINVAL));
        assert_ne!(ctx.thread.sig.pending & signal::bit(signal::SIGSEGV), 0);
        let after_exec = ctx.proc.tracing.for_exec();
        assert!(after_exec.deny_attach);

        ctx.proc.creds.1 = 1;
        assert_eq!(call(&mut ctx, 30, 0), Err(Errno::EPERM));
        assert!(!ctx.proc.tracing.force_quota);
        ctx.proc.creds.1 = 0;
        ctx.thread.assumed = Some((1, 1));
        assert_eq!(call(&mut ctx, 30, 0), Err(Errno::EPERM));
        ctx.thread.assumed = None;
        assert_eq!(call(&mut ctx, 30, 0), Ok(Rv::one(0)));
        assert!(ctx.proc.tracing.force_quota);
        let after_exec = ctx.proc.tracing.for_exec();
        assert!(!after_exec.force_quota);
        ctx.proc.tracing.tracer = Some(42);
        assert_eq!(call(&mut ctx, 12, 0), Ok(Rv::one(0)));
        assert!(ctx.proc.tracing.signal_exceptions);
        assert_eq!(call(&mut ctx, 31, 0), Err(Errno::EJUSTRETURN));
        assert_eq!(ctx.proc.exit, Some(ExitStatus::Exited(Errno::ENOTSUP.0)));
        assert!(ctx.thread.exited);
    }
}

#[test]
fn embedded_descriptor_syscalls_use_guest_memory_and_preserve_failed_read_input() {
    use crate::user::console::{CapturedConsole, OutputStream};
    use crate::user::darwin::{
        abi::Errno,
        arch::Rv,
        syscall::{Ctx, bsd::file},
    };
    for abi in [DarwinAbi::X86_64, DarwinAbi::Arm64] {
        let mut p = process(abi);
        let console = CapturedConsole::new(b"input".to_vec(), 16).unwrap();
        p.proc.fds = FdTable::with_captured(console.clone());
        let (_, mut thread) = p.proc.threads.pop_first().unwrap();
        let buffer = thread.cpu.sp() - 64;
        let mut ctx = Ctx {
            proc: &mut p.proc,
            thread: &mut thread,
            nr: 3,
            pc: ENTRY,
        };
        assert_eq!(
            file::ioctl(&mut ctx, 0, 0x4004_667f, buffer),
            Ok(Rv::one(0))
        );
        assert_eq!(ctx.read_u32(buffer).unwrap(), 5);
        assert_eq!(file::ioctl(&mut ctx, 0, 0x4004_667f, 0), Err(Errno::EFAULT));
        ctx.write_u32(buffer, 1).unwrap();
        assert_eq!(
            file::ioctl(&mut ctx, 0, 0x8004_667e, buffer),
            Ok(Rv::one(0))
        );
        let input_alias = file::dup(&mut ctx, 0).unwrap().0 as i32;
        assert_eq!(
            file::fcntl(&mut ctx, input_alias, file::cmd::F_GETFL, 0),
            Ok(Rv::one(4))
        );
        assert_eq!(file::ioctl(&mut ctx, 0, 0x8004_667e, 0), Err(Errno::EFAULT));
        ctx.write_u32(buffer, 0).unwrap();
        assert_eq!(
            file::ioctl(&mut ctx, input_alias, 0x8004_667e, buffer),
            Ok(Rv::one(0))
        );
        assert_eq!(
            file::fcntl(&mut ctx, 0, file::cmd::F_GETFL, 0),
            Ok(Rv::one(0))
        );
        assert_eq!(file::ioctl(&mut ctx, 0, 0, buffer), Err(Errno::ENOTTY));
        assert_eq!(file::close(&mut ctx, input_alias), Ok(Rv::one(0)));
        assert_eq!(file::read(&mut ctx, 0, 0, 5, None), Err(Errno::EFAULT));
        assert_eq!(console.pending().unwrap().0, 5);
        assert_eq!(file::read(&mut ctx, 0, buffer, 5, None), Ok(Rv::one(5)));
        assert_eq!(ctx.read(buffer, 5).unwrap(), b"input");
        assert_eq!(file::write(&mut ctx, 1, buffer, 5, None), Ok(Rv::one(5)));
        let mut output = [0; 8];
        assert_eq!(console.drain(OutputStream::Stdout, &mut output).unwrap(), 5);
        assert_eq!(&output[..5], b"input");
        assert_eq!(file::read(&mut ctx, 1, buffer, 0, None), Err(Errno::EBADF));
        assert_eq!(file::write(&mut ctx, 0, buffer, 0, None), Err(Errno::EBADF));
        assert_eq!(file::lseek(&mut ctx, 0, 0, 0), Err(Errno::ESPIPE));
        assert_eq!(
            file::read(&mut ctx, 0, buffer, 1, Some(0)),
            Err(Errno::ESPIPE)
        );
        assert_eq!(file::read(&mut ctx, 0, buffer, 1, None), Ok(Rv::one(0)));
        assert_eq!(
            file::read(&mut ctx, 0, buffer, (i32::MAX as u64) + 1, None),
            Err(Errno::EINVAL)
        );
        let supplied = crate::user::supplied_fs::Files::new(BTreeMap::from([(
            "/data".into(),
            Arc::<[u8]>::from(&b"abcdef"[..]),
        )]))
        .unwrap();
        let (path, entry) = supplied.lookup("/data").unwrap();
        let fd = ctx
            .proc
            .fds
            .install(
                Arc::new(super::super::fd::OpenFile::supplied(path, entry)),
                false,
                0,
                256,
            )
            .unwrap();
        let duplicate = file::dup(&mut ctx, fd).unwrap().0 as i32;
        assert_eq!(file::read(&mut ctx, fd, buffer, 2, None), Ok(Rv::one(2)));
        assert_eq!(ctx.read(buffer, 2).unwrap(), b"ab");
        assert_eq!(
            file::read(&mut ctx, duplicate, buffer, 2, Some(4)),
            Ok(Rv::one(2))
        );
        assert_eq!(ctx.read(buffer, 2).unwrap(), b"ef");
        assert_eq!(file::lseek(&mut ctx, fd, 0, 1), Ok(Rv::one(2)));
        assert_eq!(
            file::read(&mut ctx, duplicate, buffer, 2, None),
            Ok(Rv::one(2))
        );
        assert_eq!(ctx.read(buffer, 2).unwrap(), b"cd");
        assert_eq!(
            file::ioctl(&mut ctx, fd, 0x4004_667f, buffer),
            Ok(Rv::one(0))
        );
        assert_eq!(ctx.read_u32(buffer).unwrap(), 2);
        assert_eq!(
            file::write(&mut ctx, fd, buffer, 1, None),
            Err(Errno::EBADF)
        );
    }
}

#[test]
fn embedded_vectored_io_preserves_offsets_limits_and_partial_prefixes() {
    use crate::user::console::{CapturedConsole, OutputStream};
    use crate::user::darwin::{
        abi::Errno,
        arch::Rv,
        syscall::{Ctx, bsd::file},
    };
    for abi in [DarwinAbi::X86_64, DarwinAbi::Arm64] {
        let mut p = process(abi);
        let console = CapturedConsole::new(b"xyz".to_vec(), 3).unwrap();
        p.proc.fds = FdTable::with_captured(console.clone());
        let (_, mut thread) = p.proc.threads.pop_first().unwrap();
        let buffer = thread.cpu.sp() - 256;
        let iov = buffer + 128;
        let mut ctx = Ctx {
            proc: &mut p.proc,
            thread: &mut thread,
            nr: 120,
            pc: ENTRY,
        };
        let supplied = crate::user::supplied_fs::Files::new(BTreeMap::from([(
            "/data".into(),
            Arc::<[u8]>::from(&b"abcdef"[..]),
        )]))
        .unwrap();
        let (path, entry) = supplied.lookup("/data").unwrap();
        let fd = ctx
            .proc
            .fds
            .install(
                Arc::new(super::super::fd::OpenFile::supplied(path, entry)),
                false,
                0,
                256,
            )
            .unwrap();
        let vectors = [buffer, 2, buffer + 16, 2]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect::<Vec<_>>();
        ctx.write(iov, &vectors).unwrap();
        assert_eq!(file::readv(&mut ctx, fd, iov, 2, Some(1)), Ok(Rv::one(4)));
        assert_eq!(ctx.read(buffer, 2).unwrap(), b"bc");
        assert_eq!(ctx.read(buffer + 16, 2).unwrap(), b"de");
        assert_eq!(file::lseek(&mut ctx, fd, 0, 1), Ok(Rv::one(0)));
        assert_eq!(file::readv(&mut ctx, fd, iov, 2, None), Ok(Rv::one(4)));
        assert_eq!(file::lseek(&mut ctx, fd, 0, 1), Ok(Rv::one(4)));
        assert_eq!(file::writev(&mut ctx, 1, iov, 2, None), Ok(Rv::one(2)));
        let mut output = [0; 4];
        assert_eq!(console.drain(OutputStream::Stdout, &mut output).unwrap(), 2);
        assert_eq!(&output[..2], b"ab");
        assert_eq!(file::readv(&mut ctx, fd, iov, -1, None), Err(Errno::EINVAL));
        assert_eq!(
            file::readv(&mut ctx, fd, iov, 1025, None),
            Err(Errno::EINVAL)
        );
        assert_eq!(file::readv(&mut ctx, 1, 0, 0, None), Err(Errno::EBADF));
        // Native writev rejects an empty array before descriptor lookup.
        assert_eq!(file::writev(&mut ctx, 0, 0, 0, None), Err(Errno::EINVAL));
        assert_eq!(
            file::readv(&mut ctx, 0, iov, 2, Some(0)),
            Err(Errno::ESPIPE)
        );
        ctx.write_u64(iov + 16, 0).unwrap();
        assert_eq!(file::readv(&mut ctx, 0, iov, 2, None), Ok(Rv::one(2)));
        assert_eq!(ctx.read(buffer, 2).unwrap(), b"xy");
        assert_eq!(console.pending().unwrap().0, 1);
        ctx.write_u64(iov + 8, i32::MAX as u64).unwrap();
        assert_eq!(file::readv(&mut ctx, 0, iov, 2, None), Err(Errno::EINVAL));
        assert_eq!(console.pending().unwrap().0, 1);
    }
}

#[test]
fn native_null_device_has_guest_only_path_and_descriptor_semantics() {
    use crate::user::darwin::{
        abi::Errno,
        arch::Rv,
        host::AT_FDCWD,
        io::*,
        syscall::{
            Ctx,
            bsd::{file, path},
        },
    };
    use crate::user::supplied_fs::{Device, Files};

    let files = Files::default();
    let supplied = files
        .with_file("/dev/null".into(), Arc::<[u8]>::from(&b"caller"[..]))
        .unwrap();
    assert_eq!(
        supplied
            .with_device(Device::Null)
            .unwrap()
            .read("/dev/null")
            .unwrap()
            .as_ref(),
        b"caller"
    );
    assert!(files.lookup("/dev/null").is_err());
    for abi in [DarwinAbi::X86_64, DarwinAbi::Arm64] {
        let mut p = process_with_profile(abi, true);
        p.proc.vfs = Vfs::supplied(files.with_device(Device::Null).unwrap());
        let (_, mut thread) = p.proc.threads.pop_first().unwrap();
        let buffer = thread.cpu.sp() - 4096;
        let name = buffer + 512;
        let mut ctx = Ctx {
            proc: &mut p.proc,
            thread: &mut thread,
            nr: 5,
            pc: ENTRY,
        };
        ctx.write(name, b"/dev/null\0").unwrap();
        assert_eq!(
            path::faccessat(&mut ctx, AT_FDCWD, name, 6, 0),
            Ok(Rv::one(0))
        );
        assert_eq!(
            path::faccessat(&mut ctx, AT_FDCWD, name, 1, 0),
            Err(Errno::EACCES)
        );
        assert_eq!(
            path::openat(&mut ctx, AT_FDCWD, name, O_DIRECTORY, 0),
            Err(Errno::ENOTDIR)
        );
        assert_eq!(
            path::openat(&mut ctx, AT_FDCWD, name, O_CREAT | O_EXCL, 0),
            Err(Errno::EEXIST)
        );
        let fd = path::openat(&mut ctx, AT_FDCWD, name, O_RDWR, 0).unwrap().0 as i32;
        assert!(ctx.proc.fds.file(fd).unwrap().host_fd().is_none());
        assert_eq!(
            file::fcntl(&mut ctx, fd, file::cmd::F_GETFL, 0),
            Ok(Rv::one(O_RDWR.into()))
        );
        assert_eq!(path::stat64(&mut ctx, name, buffer), Ok(Rv::one(0)));
        let stat = ctx.read(buffer, 144).unwrap();
        assert_eq!(u16::from_le_bytes(stat[4..6].try_into().unwrap()), 0o020666);
        assert_eq!(
            u32::from_le_bytes(stat[24..28].try_into().unwrap()),
            0x0300_0002
        );
        assert_eq!(file::fstat64(&mut ctx, fd, buffer), Ok(Rv::one(0)));
        assert_eq!(ctx.read(buffer, 144).unwrap(), stat);
        assert_eq!(file::read(&mut ctx, fd, 1, 5, Some(-1)), Ok(Rv::one(0)));
        assert_eq!(file::write(&mut ctx, fd, 1, 5, None), Ok(Rv::one(5)));
        assert_eq!(file::write(&mut ctx, fd, 1, 7, Some(10)), Ok(Rv::one(7)));
        let duplicate = file::dup(&mut ctx, fd).unwrap().0 as i32;
        assert_eq!(file::lseek(&mut ctx, duplicate, 0, 1), Ok(Rv::one(5)));
        assert_eq!(file::lseek(&mut ctx, duplicate, 2, 2), Ok(Rv::one(2)));
        assert_eq!(file::lseek(&mut ctx, fd, 0, 1), Ok(Rv::one(2)));
        assert_eq!(file::lseek(&mut ctx, fd, 0, 3), Err(Errno::ENODEV));
        assert_eq!(file::lseek(&mut ctx, fd, 0, 4), Err(Errno::ENODEV));
        assert_eq!(
            file::ioctl(&mut ctx, fd, 0x4004_667f, buffer),
            Err(Errno::ENODEV)
        );
        ctx.write_u32(buffer, 1).unwrap();
        assert_eq!(
            file::ioctl(&mut ctx, fd, 0x8004_667d, buffer),
            Ok(Rv::one(0))
        );
        assert_eq!(
            file::ioctl(&mut ctx, fd, 0x8004_667e, buffer),
            Ok(Rv::one(0))
        );
        assert_eq!(
            file::fcntl(&mut ctx, duplicate, file::cmd::F_GETFL, 0),
            Ok(Rv::one((O_RDWR | O_ASYNC | O_NONBLOCK).into()))
        );
        ctx.write_u32(buffer, 0).unwrap();
        assert_eq!(
            file::ioctl(&mut ctx, duplicate, 0x8004_667d, buffer),
            Ok(Rv::one(0))
        );
        assert_eq!(
            file::fcntl(&mut ctx, fd, file::cmd::F_GETFL, 0),
            Ok(Rv::one((O_RDWR | O_NONBLOCK).into()))
        );
        let input = path::openat(&mut ctx, AT_FDCWD, name, O_RDONLY, 0)
            .unwrap()
            .0 as i32;
        assert_eq!(file::write(&mut ctx, input, 1, 5, None), Err(Errno::EBADF));
        let output = path::openat(&mut ctx, AT_FDCWD, name, O_WRONLY, 0)
            .unwrap()
            .0 as i32;
        assert_eq!(file::read(&mut ctx, output, 1, 5, None), Err(Errno::EBADF));
        ctx.write(name, b"/dev/null/..\0").unwrap();
        assert_eq!(
            path::openat(&mut ctx, AT_FDCWD, name, O_RDONLY, 0),
            Err(Errno::ENOTDIR)
        );
    }
}

#[test]
fn native_zero_device_reads_into_guest_memory_on_both_abis() {
    use crate::user::darwin::{
        abi::{Errno, tables::nr},
        arch::Rv,
        host::AT_FDCWD,
        io::{O_RDONLY, O_RDWR},
        syscall::{
            Ctx,
            bsd::{self, file, path},
        },
    };
    use crate::user::supplied_fs::{Device, Files};

    let files = Files::default()
        .with_device(Device::Zero)
        .unwrap()
        .with_device(Device::Null)
        .unwrap()
        .with_file("/regular".into(), Arc::from(&b"supplied"[..]))
        .unwrap();
    for abi in [DarwinAbi::X86_64, DarwinAbi::Arm64] {
        let mut p = process_with_profile(abi, true);
        p.proc.vfs = Vfs::supplied(files.clone());
        let (_, mut thread) = p.proc.threads.pop_first().unwrap();
        let buffer = thread.cpu.sp() - 4096;
        let name = buffer + 512;
        let mut ctx = Ctx {
            proc: &mut p.proc,
            thread: &mut thread,
            nr: 5,
            pc: ENTRY,
        };
        ctx.write(name, b"/dev/zero\0").unwrap();
        let fd = path::openat(&mut ctx, AT_FDCWD, name, O_RDWR, 0).unwrap().0 as i32;
        assert!(ctx.proc.fds.file(fd).unwrap().host_fd().is_none());
        assert_eq!(file::fstat64(&mut ctx, fd, buffer), Ok(Rv::one(0)));
        let stat = ctx.read(buffer, 144).unwrap();
        assert_eq!(u16::from_le_bytes(stat[4..6].try_into().unwrap()), 0o020666);
        assert_eq!(
            u32::from_le_bytes(stat[24..28].try_into().unwrap()),
            0x0300_0003
        );

        ctx.write(buffer, &[0xa5; 12]).unwrap();
        assert_eq!(file::read(&mut ctx, fd, 1, 4, None), Err(Errno::EFAULT));
        assert_eq!(file::read(&mut ctx, fd, buffer, 4, None), Ok(Rv::one(4)));
        assert_eq!(
            file::read(&mut ctx, fd, buffer + 4, 4, Some(-1)),
            Ok(Rv::one(4))
        );
        assert_eq!(
            ctx.read(buffer, 12).unwrap(),
            [&[0; 8][..], &[0xa5; 4]].concat()
        );
        let duplicate = file::dup(&mut ctx, fd).unwrap().0 as i32;
        assert_eq!(file::lseek(&mut ctx, duplicate, 0, 1), Ok(Rv::one(4)));
        assert_eq!(file::write(&mut ctx, fd, 1, 5, None), Ok(Rv::one(5)));
        assert_eq!(file::lseek(&mut ctx, duplicate, 0, 1), Ok(Rv::one(9)));
        let args = |fd: i32, len: i64| [fd as u64, len as u64, 0, 0, 0, 0, 0, 0];
        for number in [nr::FSYNC, nr::FSYNC_NOCANCEL, nr::FDATASYNC] {
            assert_eq!(bsd::call(&mut ctx, number, &args(fd, 0)), Ok(Rv::one(0)));
        }
        assert_eq!(
            bsd::call(&mut ctx, nr::FTRUNCATE, &args(fd, 3)),
            Ok(Rv::one(0))
        );
        assert_eq!(
            bsd::call(&mut ctx, nr::FTRUNCATE, &args(fd, -1)),
            Err(Errno::EINVAL)
        );
        let readonly = path::openat(&mut ctx, AT_FDCWD, name, O_RDONLY, 0)
            .unwrap()
            .0 as i32;
        assert_eq!(
            bsd::call(&mut ctx, nr::FTRUNCATE, &args(readonly, 3)),
            Err(Errno::EINVAL)
        );
        ctx.write(name, b"/dev/null\0").unwrap();
        let null = path::openat(&mut ctx, AT_FDCWD, name, O_RDWR, 0).unwrap().0 as i32;
        assert_eq!(
            bsd::call(&mut ctx, nr::FSYNC, &args(null, 0)),
            Ok(Rv::one(0))
        );
        ctx.write(name, b"/regular\0").unwrap();
        let regular = path::openat(&mut ctx, AT_FDCWD, name, O_RDONLY, 0)
            .unwrap()
            .0 as i32;
        for number in [nr::FSYNC, nr::FSYNC_NOCANCEL, nr::FDATASYNC, nr::FTRUNCATE] {
            assert_eq!(
                bsd::call(&mut ctx, number, &args(regular, 3)),
                Err(Errno::EPERM)
            );
            assert_eq!(bsd::call(&mut ctx, number, &args(-1, 3)), Err(Errno::EPERM));
        }
    }
}

#[test]
fn supplied_openat_metadata_and_flags_use_only_the_guest_namespace() {
    use crate::user::darwin::{
        abi::Errno,
        arch::Rv,
        host::AT_FDCWD,
        io::*,
        syscall::{
            Ctx,
            bsd::{file, path},
        },
    };
    for abi in [DarwinAbi::X86_64, DarwinAbi::Arm64] {
        let mut p = process(abi);
        p.proc.vfs = Vfs::supplied(
            crate::user::supplied_fs::Files::new(BTreeMap::from([(
                "/dir/data".into(),
                Arc::<[u8]>::from(&b"abcdef"[..]),
            )]))
            .unwrap(),
        );
        p.proc.cwd = b"/dir".to_vec();
        p.proc.fds = FdTable::new();
        let (_, mut thread) = p.proc.threads.pop_first().unwrap();
        let buffer = thread.cpu.sp() - 4096;
        let name = buffer + 2048;
        let mut ctx = Ctx {
            proc: &mut p.proc,
            thread: &mut thread,
            nr: 5,
            pc: ENTRY,
        };
        ctx.write(name, b"data\0").unwrap();
        let fd = path::openat(&mut ctx, AT_FDCWD, name, O_CLOEXEC, 0)
            .unwrap()
            .0 as i32;
        assert!(ctx.proc.fds.file(fd).unwrap().host_fd().is_none());
        assert_eq!(
            file::fcntl(&mut ctx, fd, file::cmd::F_GETFD, 0),
            Ok(Rv::one(1))
        );
        assert_eq!(
            file::fcntl(&mut ctx, fd, file::cmd::F_GETFL, 0),
            Ok(Rv::one(0))
        );
        assert_eq!(
            file::fcntl(
                &mut ctx,
                fd,
                file::cmd::F_SETFL,
                (O_NONBLOCK | O_WRONLY) as u64
            ),
            Ok(Rv::one(0))
        );
        assert_eq!(
            file::fcntl(&mut ctx, fd, file::cmd::F_GETFL, 0),
            Ok(Rv::one(O_NONBLOCK as u64))
        );
        assert_eq!(file::fstat64(&mut ctx, fd, buffer), Ok(Rv::one(0)));
        let stat = ctx.read(buffer, 144).unwrap();
        assert_eq!(u16::from_le_bytes(stat[4..6].try_into().unwrap()), 0o100555);
        assert_eq!(u64::from_le_bytes(stat[96..104].try_into().unwrap()), 6);
        assert_eq!(path::stat64(&mut ctx, name, buffer), Ok(Rv::one(0)));
        assert_eq!(ctx.read(buffer, 144).unwrap(), stat);
        assert_eq!(
            file::fcntl(&mut ctx, fd, file::cmd::F_GETPATH, buffer),
            Ok(Rv::one(0))
        );
        assert_eq!(ctx.read(buffer, 10).unwrap(), b"/dir/data\0");
        for (flags, error) in [
            (O_WRONLY, Errno::EROFS),
            (O_TRUNC, Errno::EROFS),
            (O_CREAT | O_EXCL, Errno::EEXIST),
            (O_DIRECTORY, Errno::ENOTDIR),
        ] {
            assert_eq!(path::openat(&mut ctx, AT_FDCWD, name, flags, 0), Err(error));
        }
        assert_eq!(ctx.proc.fds.len(), 1);
        assert_eq!(path::openat(&mut ctx, fd, name, 0, 0), Err(Errno::ENOTDIR));
        ctx.write(name, b".\0").unwrap();
        let dirfd = path::openat(&mut ctx, AT_FDCWD, name, O_DIRECTORY, 0)
            .unwrap()
            .0 as i32;
        assert_eq!(
            file::read(&mut ctx, dirfd, buffer, 1, None),
            Err(Errno::EISDIR)
        );
        ctx.write(name, b"data\0").unwrap();
        let relative = path::openat(&mut ctx, dirfd, name, 0, 0).unwrap().0 as i32;
        assert_eq!(
            file::read(&mut ctx, relative, buffer, 6, None),
            Ok(Rv::one(6))
        );
        assert_eq!(ctx.read(buffer, 6).unwrap(), b"abcdef");
        ctx.write(name, b"/dir/data\0").unwrap();
        assert!(path::openat(&mut ctx, -99, name, 0, 0).is_ok());
        ctx.write(name, b"data/..\0").unwrap();
        assert_eq!(
            path::openat(&mut ctx, AT_FDCWD, name, 0, 0),
            Err(Errno::ENOTDIR)
        );
        ctx.write(name, b"/not-supplied\0").unwrap();
        assert_eq!(
            path::openat(&mut ctx, AT_FDCWD, name, 0, 0),
            Err(Errno::ENOENT)
        );
        assert_eq!(
            path::openat(&mut ctx, AT_FDCWD, name, O_CREAT, 0),
            Err(Errno::EROFS)
        );
        let host_cwd = std::env::current_dir().unwrap();
        ctx.write(name, b"/dir/data\0").unwrap();
        assert_eq!(
            path::faccessat(&mut ctx, AT_FDCWD, name, 5, 0),
            Ok(Rv::one(0))
        );
        assert_eq!(
            path::faccessat(&mut ctx, AT_FDCWD, name, 2, 0),
            Err(Errno::EROFS)
        );
        assert_eq!(
            path::faccessat(&mut ctx, AT_FDCWD, name, 8, 0),
            Err(Errno::EINVAL)
        );
        assert_eq!(
            path::readlinkat(&mut ctx, AT_FDCWD, name, buffer, 32),
            Err(Errno::EINVAL)
        );
        assert_eq!(path::chdir(&mut ctx, name), Err(Errno::ENOTDIR));
        assert_eq!(path::fchdir(&mut ctx, fd), Err(Errno::ENOTDIR));
        assert_eq!(ctx.proc.cwd, b"/dir");
        ctx.write(name, b"/dir/..\0").unwrap();
        assert_eq!(path::chdir(&mut ctx, name), Ok(Rv::one(0)));
        assert_eq!(ctx.proc.cwd, b"/");
        ctx.write(name, b"dir/data\0").unwrap();
        assert!(path::openat(&mut ctx, AT_FDCWD, name, 0, 0).is_ok());
        assert_eq!(path::fchdir(&mut ctx, dirfd), Ok(Rv::one(0)));
        assert_eq!(ctx.proc.cwd, b"/dir");
        ctx.write(name, b"/not-supplied\0").unwrap();
        assert_eq!(
            path::readlinkat(&mut ctx, AT_FDCWD, name, buffer, 32),
            Err(Errno::ENOENT)
        );
        assert_eq!(path::chdir(&mut ctx, name), Err(Errno::ENOENT));
        assert_eq!(ctx.proc.cwd, b"/dir");
        assert_eq!(std::env::current_dir().unwrap(), host_cwd);
    }
}

#[test]
fn supplied_symlink_syscalls_follow_only_the_guest_namespace() {
    use crate::user::darwin::{
        abi::Errno,
        arch::Rv,
        host::{AT_FDCWD, AT_SYMLINK_NOFOLLOW, AT_SYMLINK_NOFOLLOW_ANY},
        io::*,
        syscall::{
            Ctx,
            bsd::{file, path},
        },
    };
    use crate::user::supplied_fs::Files;

    let files = Files::default()
        .with_file("/bin/dash".into(), Arc::from(b"guest".as_slice()))
        .unwrap()
        .with_native_symlink("/private/var/select/sh", "/bin/dash")
        .unwrap()
        .with_native_symlink("/alias", "/private/var/select")
        .unwrap()
        .with_native_symlink("/unsupplied", "/bin/cat")
        .unwrap()
        .with_native_symlink("/loop", "/loop")
        .unwrap();
    for abi in [DarwinAbi::X86_64, DarwinAbi::Arm64] {
        let mut p = process(abi);
        p.proc.vfs = Vfs::supplied(files.clone());
        p.proc.fds = FdTable::new();
        let (_, mut thread) = p.proc.threads.pop_first().unwrap();
        let buffer = thread.cpu.sp() - 4096;
        let name = buffer + 2048;
        let mut ctx = Ctx {
            proc: &mut p.proc,
            thread: &mut thread,
            nr: 58,
            pc: ENTRY,
        };
        ctx.write(name, b"/alias\0").unwrap();
        let dirfd = path::openat(&mut ctx, AT_FDCWD, name, O_DIRECTORY, 0)
            .unwrap()
            .0 as i32;
        ctx.write(name, b"sh\0").unwrap();
        ctx.write(buffer, &[0xa5; 16]).unwrap();
        assert_eq!(
            path::readlinkat(&mut ctx, dirfd, name, buffer, 4),
            Ok(Rv::one(4))
        );
        assert_eq!(ctx.read(buffer, 5).unwrap(), b"/bin\xa5");
        assert_eq!(
            path::readlinkat(&mut ctx, dirfd, name, 0, 0),
            Ok(Rv::one(0))
        );
        assert_eq!(
            path::readlinkat(&mut ctx, dirfd, name, 0, 1),
            Err(Errno::EFAULT)
        );
        assert_eq!(
            path::readlinkat(&mut ctx, dirfd, name, buffer, i32::MAX as u64),
            Ok(Rv::one(9))
        );
        assert_eq!(
            path::readlinkat(&mut ctx, dirfd, name, buffer, i32::MAX as u64 + 1),
            Err(Errno::EINVAL)
        );
        assert_eq!(ctx.read(buffer, 10).unwrap(), b"/bin/dash\xa5");
        assert_eq!(
            path::readlinkat(&mut ctx, -99, name, buffer, 10),
            Err(Errno::EBADF)
        );

        for (flags, mode, size) in [
            (0, 0o100000, 5),
            (AT_SYMLINK_NOFOLLOW, 0o120000, 9),
            (AT_SYMLINK_NOFOLLOW_ANY, 0o120000, 9),
        ] {
            assert_eq!(
                path::fstatat64(&mut ctx, dirfd, name, buffer, flags),
                Ok(Rv::one(0))
            );
            let stat = ctx.read(buffer, 144).unwrap();
            assert_eq!(
                u16::from_le_bytes(stat[4..6].try_into().unwrap()) & 0o170000,
                mode
            );
            assert_eq!(u64::from_le_bytes(stat[96..104].try_into().unwrap()), size);
        }

        assert_eq!(
            path::openat(&mut ctx, dirfd, name, O_NOFOLLOW, 0),
            Err(Errno::ELOOP)
        );
        assert_eq!(
            path::openat(&mut ctx, dirfd, name, O_CREAT | O_EXCL, 0),
            Err(Errno::EEXIST)
        );
        let fd = path::openat(&mut ctx, dirfd, name, O_RDONLY, 0).unwrap().0 as i32;
        assert_eq!(file::read(&mut ctx, fd, buffer, 5, None), Ok(Rv::one(5)));
        assert_eq!(ctx.read(buffer, 5).unwrap(), b"guest");
        assert_eq!(
            path::faccessat(&mut ctx, dirfd, name, 0, AT_SYMLINK_NOFOLLOW_ANY),
            Ok(Rv::one(0))
        );
        ctx.write(name, b"/alias/sh\0").unwrap();
        assert_eq!(
            path::faccessat(&mut ctx, AT_FDCWD, name, 0, AT_SYMLINK_NOFOLLOW_ANY),
            Err(Errno::ELOOP)
        );
        assert_eq!(
            path::fstatat64(&mut ctx, AT_FDCWD, name, buffer, AT_SYMLINK_NOFOLLOW_ANY),
            Err(Errno::ELOOP)
        );
        assert_eq!(
            path::openat(&mut ctx, AT_FDCWD, name, O_NOFOLLOW_ANY, 0),
            Err(Errno::ELOOP)
        );
        ctx.write(name, b"/alias/sh/\0").unwrap();
        assert_eq!(
            path::readlinkat(&mut ctx, AT_FDCWD, name, buffer, 9),
            Err(Errno::ENOTDIR)
        );

        ctx.write(name, b"/unsupplied\0").unwrap();
        assert_eq!(
            path::readlinkat(&mut ctx, AT_FDCWD, name, buffer, 9),
            Ok(Rv::one(8))
        );
        assert_eq!(ctx.read(buffer, 8).unwrap(), b"/bin/cat");
        assert_eq!(path::stat64(&mut ctx, name, buffer), Err(Errno::ENOENT));
        ctx.write(name, b"/loop\0").unwrap();
        assert_eq!(path::stat64(&mut ctx, name, buffer), Err(Errno::ELOOP));
        assert_eq!(path::lstat64(&mut ctx, name, buffer), Ok(Rv::one(0)));
    }
}

#[test]
fn supplied_mmap_preserves_copy_on_write_eof_and_guest_page_granularity() {
    use crate::user::darwin::{
        abi::Errno,
        arch::Rv,
        syscall::{Ctx, bsd::file, mem},
        vm,
    };
    for abi in [DarwinAbi::X86_64, DarwinAbi::Arm64] {
        let mut p = process(abi);
        let (_, mut thread) = p.proc.threads.pop_first().unwrap();
        let mut ctx = Ctx {
            proc: &mut p.proc,
            thread: &mut thread,
            nr: 197,
            pc: ENTRY,
        };
        let files = crate::user::supplied_fs::Files::new(BTreeMap::from([(
            "/data".into(),
            Arc::<[u8]>::from(&b"abcdef"[..]),
        )]))
        .unwrap();
        let (path, entry) = files.lookup("/data").unwrap();
        let fd = ctx
            .proc
            .fds
            .install(
                Arc::new(super::super::fd::OpenFile::supplied(path, entry)),
                false,
                0,
                256,
            )
            .unwrap();
        let page = ctx.proc.vm.page;
        let private = mem::mmap(
            &mut ctx,
            0,
            2 * page,
            vm::VM_PROT_WRITE,
            mem::MAP_PRIVATE | mem::MAP_UNIX03,
            fd,
            0,
        )
        .unwrap()
        .0;
        assert_eq!(ctx.read(private, 6).unwrap(), b"abcdef");
        assert_eq!(ctx.read(private + page - 1, 1).unwrap(), [0]);
        assert_eq!(ctx.read(private + page, 1), Err(Errno::EFAULT));
        ctx.write(private, b"z").unwrap();
        let shared = mem::mmap(
            &mut ctx,
            0,
            page,
            vm::VM_PROT_READ,
            mem::MAP_SHARED | mem::MAP_UNIX03,
            fd,
            0,
        )
        .unwrap()
        .0;
        assert_eq!(ctx.read(shared, 6).unwrap(), b"abcdef");
        assert_eq!(ctx.write(shared, b"x"), Err(Errno::EFAULT));
        assert_eq!(
            mem::mprotect(&mut ctx, shared, page, vm::VM_PROT_WRITE),
            Err(Errno::EACCES)
        );
        assert_eq!(
            mem::mmap(
                &mut ctx,
                0,
                page,
                vm::VM_PROT_WRITE,
                mem::MAP_SHARED | mem::MAP_UNIX03,
                fd,
                0
            ),
            Err(Errno::EACCES)
        );
        assert_eq!(
            mem::mmap(
                &mut ctx,
                0,
                page,
                vm::VM_PROT_READ,
                mem::MAP_PRIVATE | mem::MAP_UNIX03,
                fd,
                1
            ),
            Err(Errno::EINVAL)
        );
        assert_eq!(
            mem::mmap(
                &mut ctx,
                0,
                u64::MAX,
                vm::VM_PROT_READ,
                mem::MAP_PRIVATE,
                fd,
                0
            ),
            Err(Errno::EINVAL)
        );
        assert_eq!(file::close(&mut ctx, fd), Ok(Rv::one(0)));
        assert_eq!(ctx.read(private, 6).unwrap(), b"zbcdef");
        assert_eq!(ctx.read(shared, 6).unwrap(), b"abcdef");
        assert_eq!(mem::munmap(&mut ctx, private, 2 * page), Ok(Rv::one(0)));
        assert_eq!(ctx.read(private, 1), Err(Errno::EFAULT));
    }
}

#[test]
fn closed_workspace_sync_commands_accept_vnodes_and_reject_pipes() {
    use crate::user::darwin::{
        abi::{Errno, tables::nr},
        io::{O_CREAT, O_RDONLY, O_RDWR, O_SEARCH},
        syscall::{
            Ctx, bsd,
            bsd::file::{self, cmd},
        },
    };
    use crate::user::supplied_fs::WorkspaceFlavor;

    for abi in [DarwinAbi::X86_64, DarwinAbi::Arm64] {
        let mut p = process(abi);
        let files = p
            .proc
            .vfs
            .files()
            .unwrap()
            .with_temp_workspace(WorkspaceFlavor::Darwin);
        p.proc.vfs = Vfs::supplied(files);
        let (_, mut thread) = p.proc.threads.pop_first().unwrap();
        let path = thread.cpu.sp() - 512;
        let data = path + 128;
        let mut ctx = Ctx {
            proc: &mut p.proc,
            thread: &mut thread,
            nr: i64::from(nr::FCNTL),
            pc: ENTRY,
        };
        let mut open = |name: &[u8], flags| {
            ctx.write(path, name).unwrap();
            bsd::call(
                &mut ctx,
                nr::OPEN,
                &[path, u64::from(flags), 0o600, 0, 0, 0, 0, 0],
            )
            .unwrap()
            .0 as i32
        };
        let writable = open(b"/tmp/journal\0", O_CREAT | O_RDWR);
        let readonly = open(b"/tmp/journal\0", O_RDONLY);
        let directory = open(b"/tmp\0", O_RDONLY);
        let search = open(b"/tmp\0", O_SEARCH);
        let resource = open(b"/tmp/journal/..namedfork/rsrc\0", O_CREAT | O_RDWR);
        let pipe_read = file::pipe(&mut ctx).unwrap().0 as i32;
        ctx.write(data, b"data").unwrap();
        assert_eq!(file::write(&mut ctx, writable, data, 4, None).unwrap().0, 4);

        for command in [cmd::F_FULLFSYNC, cmd::F_BARRIERFSYNC] {
            for fd in [writable, readonly, directory, search, resource] {
                assert_eq!(file::fcntl(&mut ctx, fd, command, u64::MAX).unwrap().0, 0);
            }
            for fd in [-1, pipe_read] {
                assert_eq!(file::fcntl(&mut ctx, fd, command, 0), Err(Errno::EBADF));
            }
        }

        assert_eq!(file::lseek(&mut ctx, writable, 0, 1).unwrap().0, 4);
        assert_eq!(
            file::read(&mut ctx, readonly, data + 8, 4, None).unwrap().0,
            4
        );
        assert_eq!(ctx.read(data + 8, 4).unwrap(), b"data");

        file::close(&mut ctx, writable).unwrap();
        assert_eq!(
            file::fcntl(&mut ctx, writable, cmd::F_FULLFSYNC, 0),
            Err(Errno::EBADF)
        );
    }
}

#[test]
fn closed_workspace_preallocation_reserves_blocks_without_changing_eof() {
    use crate::user::darwin::{
        abi::{Errno, tables::nr},
        fd::FileKind,
        io::{O_CREAT, O_RDONLY, O_RDWR},
        syscall::{
            Ctx, bsd,
            bsd::file::{self, cmd},
        },
    };
    use crate::user::supplied_fs::WorkspaceFlavor;

    for abi in [DarwinAbi::X86_64, DarwinAbi::Arm64] {
        let mut p = process(abi);
        let files = p
            .proc
            .vfs
            .files()
            .unwrap()
            .with_temp_workspace(WorkspaceFlavor::Darwin);
        p.proc.vfs = Vfs::supplied(files);
        let (_, mut thread) = p.proc.threads.pop_first().unwrap();
        let path = thread.cpu.sp() - 512;
        let buffer = path + 128;
        let mut ctx = Ctx {
            proc: &mut p.proc,
            thread: &mut thread,
            nr: i64::from(nr::FCNTL),
            pc: ENTRY,
        };
        ctx.write(path, b"/tmp/preallocate\0").unwrap();
        let mut open = |flags| {
            bsd::call(
                &mut ctx,
                nr::OPEN,
                &[path, u64::from(flags), 0o600, 0, 0, 0, 0, 0],
            )
            .unwrap()
            .0 as i32
        };
        let writable = open(O_CREAT | O_RDWR);
        let readonly = open(O_RDONLY);
        let pipe = file::pipe(&mut ctx).unwrap().0 as i32;
        let call = |ctx: &mut Ctx<'_>, fd, argument| {
            bsd::call(
                ctx,
                nr::FCNTL,
                &[
                    fd as u64,
                    cmd::F_PREALLOCATE as u64,
                    argument,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
            )
        };
        let mut request = [0; 32];
        request[..4].copy_from_slice(&4u32.to_le_bytes());
        request[16..24].copy_from_slice(&4096i64.to_le_bytes());
        request[24..].copy_from_slice(&0x123456_i64.to_le_bytes());
        ctx.write(buffer, &request).unwrap();
        assert_eq!(call(&mut ctx, writable, buffer), Err(Errno::EINVAL));
        assert_eq!(ctx.read(buffer, 32).unwrap(), request);
        for fd in [readonly, pipe, -1] {
            assert_eq!(call(&mut ctx, fd, u64::MAX), Err(Errno::EBADF));
        }
        assert_eq!(call(&mut ctx, writable, u64::MAX), Err(Errno::EFAULT));

        request[4..8].copy_from_slice(&3i32.to_le_bytes());
        request[16..24].copy_from_slice(&((16i64 << 20) + 1).to_le_bytes());
        ctx.write(buffer, &request).unwrap();
        let unsupported = if cfg!(target_os = "macos") {
            Errno::ENOSPC
        } else {
            Errno::ENOTSUP
        };
        assert_eq!(call(&mut ctx, writable, buffer), Err(unsupported));
        assert_eq!(ctx.read(buffer + 24, 8).unwrap(), [0; 8]);
        request[16..24].copy_from_slice(&4096i64.to_le_bytes());
        ctx.write(buffer, &request).unwrap();
        if !cfg!(target_os = "macos") {
            assert_eq!(call(&mut ctx, writable, buffer), Err(Errno::ENOTSUP));
            assert_eq!(ctx.read(buffer + 24, 8).unwrap(), [0; 8]);
            continue;
        }

        let capacity = |ctx: &Ctx<'_>| {
            ctx.proc
                .vfs
                .files()
                .unwrap()
                .workspace_capacity()
                .unwrap()
                .bytes_available
        };
        let initial = capacity(&ctx);
        file::lseek(&mut ctx, writable, 7, 0).unwrap();
        assert_eq!(call(&mut ctx, writable, buffer).unwrap().0, 0);
        assert_eq!(ctx.read(buffer + 24, 8).unwrap(), 4096i64.to_le_bytes());
        assert_eq!(file::lseek(&mut ctx, writable, 0, 1).unwrap().0, 7);
        assert_eq!(capacity(&ctx), initial - 4096);
        let opened = ctx.proc.fds.file(readonly).unwrap();
        let FileKind::Embedded(object) = &opened.kind else {
            panic!("private workspace descriptor expected");
        };
        let info = object.stat().unwrap();
        assert_eq!((info.size, info.blocks), (0, 8));
        file::ftruncate(&mut ctx, writable, 4096).unwrap();
        assert_eq!(capacity(&ctx), initial - 4096);
        file::ftruncate(&mut ctx, writable, 0).unwrap();
        assert_eq!(
            (object.stat().unwrap().size, object.stat().unwrap().blocks),
            (0, 0)
        );
        assert_eq!(capacity(&ctx), initial);
    }
}

#[test]
fn closed_workspace_shared_mappings_follow_darwin_guest_pages() {
    use crate::user::darwin::{
        abi::{Errno, tables::nr},
        io::{O_CREAT, O_RDONLY, O_RDWR, O_WRONLY},
        syscall::{Ctx, bsd, bsd::file, mem},
        vm,
    };
    use crate::user::supplied_fs::WorkspaceFlavor;

    for abi in [DarwinAbi::X86_64, DarwinAbi::Arm64] {
        let mut p = process(abi);
        let files = p
            .proc
            .vfs
            .files()
            .unwrap()
            .with_temp_workspace(WorkspaceFlavor::Darwin);
        p.proc.vfs = Vfs::supplied(files);
        let (_, mut thread) = p.proc.threads.pop_first().unwrap();
        let name = thread.cpu.sp() - 512;
        let byte = name + 64;
        let mut ctx = Ctx {
            proc: &mut p.proc,
            thread: &mut thread,
            nr: i64::from(nr::MMAP),
            pc: ENTRY,
        };
        ctx.write(name, b"/tmp/mapped\0").unwrap();
        let mut open = |flags: u32| {
            bsd::call(
                &mut ctx,
                nr::OPEN,
                &[name, u64::from(flags), 0o600, 0, 0, 0, 0, 0],
            )
            .unwrap()
            .0 as i32
        };
        let writer = open(O_RDWR | O_CREAT);
        let reader = open(O_RDONLY);
        let write_only = open(O_WRONLY);
        let page = ctx.proc.vm.page;
        file::ftruncate(&mut ctx, writer, (2 * page) as i64).unwrap();
        let rw = vm::VM_PROT_READ | vm::VM_PROT_WRITE;
        let shared = mem::MAP_SHARED | mem::MAP_UNIX03;

        assert_eq!(
            mem::mmap(&mut ctx, 0, page, rw, shared, reader, 0),
            Err(Errno::EACCES)
        );
        assert_eq!(
            mem::mmap(&mut ctx, 0, page, vm::VM_PROT_READ, shared, write_only, 0),
            Err(Errno::EACCES)
        );
        let alias = mem::mmap(&mut ctx, 0, 2 * page, vm::VM_PROT_READ, shared, reader, 0)
            .unwrap()
            .0;
        let mapping = mem::mmap(&mut ctx, 0, 2 * page, vm::VM_PROT_READ, shared, writer, 0)
            .unwrap()
            .0;
        assert_eq!(mem::mprotect(&mut ctx, alias, page, rw), Err(Errno::EACCES));
        mem::mprotect(&mut ctx, mapping, 2 * page, rw).unwrap();

        let child = ctx.proc.space.process_snapshot().unwrap();
        ctx.write(mapping, b"a").unwrap();
        assert_eq!(ctx.read(alias, 1).unwrap(), b"a");
        assert_eq!(file::read(&mut ctx, reader, byte, 1, Some(0)).unwrap().0, 1);
        assert_eq!(ctx.read(byte, 1).unwrap(), b"a");
        ctx.write(byte, b"b").unwrap();
        assert_eq!(
            file::write(&mut ctx, writer, byte, 1, Some(1)).unwrap().0,
            1
        );
        assert_eq!(ctx.read(mapping, 2).unwrap(), b"ab");

        ctx.write(mapping + page - 1, b"c").unwrap();
        child.write(mapping + page, b"d").unwrap();
        assert_eq!(ctx.read(alias + page, 1).unwrap(), b"d");
        file::ftruncate(&mut ctx, writer, 2).unwrap();
        assert_eq!(ctx.read(alias + page - 1, 1).unwrap(), [0]);
        assert_eq!(ctx.read(mapping + page, 1), Err(Errno::EFAULT));
        assert!(child.read(mapping + page, &mut [0]).is_err());
        file::ftruncate(&mut ctx, writer, (2 * page) as i64).unwrap();
        assert_eq!(ctx.read(mapping + page, 1).unwrap(), [0]);

        bsd::call(&mut ctx, nr::UNLINK, &[name, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        for fd in [writer, reader, write_only] {
            file::close(&mut ctx, fd).unwrap();
        }
        ctx.write(mapping, b"e").unwrap();
        assert_eq!(ctx.read(alias, 2).unwrap(), b"eb");
        let mut retained = [0; 2];
        child.read(mapping, &mut retained).unwrap();
        assert_eq!(&retained, b"eb");
    }
}

#[test]
fn selected_runtime_metadata_controls_do_not_admit_copied_files_or_bad_buffers() {
    use crate::user::darwin::{
        abi::Errno,
        arch::Rv,
        fd::OpenFile,
        syscall::{
            Ctx,
            bsd::file::{self, cmd},
        },
    };
    for selected in [false, true] {
        let fixture = crate::user::supplied_fs::test_backing::TestFile::new(b"runtime", 7);
        let files = if selected {
            crate::user::supplied_fs::Files::default()
                .with_host_file("/runtime".into(), &fixture.path)
                .unwrap()
        } else {
            crate::user::supplied_fs::Files::default()
                .with_file("/runtime".into(), Arc::from(&b"runtime"[..]))
                .unwrap()
        };
        let mut process = process(DarwinAbi::Arm64);
        let (_, mut thread) = process.proc.threads.pop_first().unwrap();
        let buffer = thread.cpu.sp() - 256;
        let mut ctx = Ctx {
            proc: &mut process.proc,
            thread: &mut thread,
            nr: 92,
            pc: ENTRY,
        };
        let (path, entry) = files.lookup("/runtime").unwrap();
        let fd = ctx
            .proc
            .fds
            .install(Arc::new(OpenFile::supplied(path, entry)), false, 0, 256)
            .unwrap();
        ctx.write(buffer, &[0; 32]).unwrap();
        assert_eq!(
            file::fcntl(&mut ctx, fd, cmd::F_CHECK_LV, buffer),
            if selected {
                Ok(Rv::one(0))
            } else {
                Err(Errno::ENOTSUP)
            }
        );
        assert_eq!(
            file::fcntl(&mut ctx, fd, cmd::F_CHECK_LV, 0),
            if selected {
                Err(Errno::EFAULT)
            } else {
                Err(Errno::ENOTSUP)
            }
        );
        assert_eq!(
            file::fcntl(&mut ctx, fd, cmd::F_ADDFILESIGS_RETURN, 0),
            if selected && cfg!(unix) {
                Err(Errno::EFAULT)
            } else {
                Err(Errno::ENOTSUP)
            }
        );
        assert!(!ctx.proc.config.host_services);
        assert!(ctx.proc.fds.file(fd).unwrap().host_fd().is_none());
    }
}

#[test]
fn isolated_bridge_denies_guest_forwarding_and_releases_consumed_rights() {
    use crate::user::darwin::{
        bridge,
        mach::{
            ipc::disp,
            kr,
            msg::{Message, Sender, bits},
        },
    };
    for abi in [DarwinAbi::X86_64, DarwinAbi::Arm64] {
        let mut p = process(abi);
        p.proc.bridge = bridge::Bridge::isolated();
        assert!(bridge::io_main(&mut p.proc).is_none());
        bridge::pump(&mut p.proc);
        assert!(p.proc.bridge.fd().is_none());
        let port = Port::new(KObject::None);
        let message = || {
            port.state.lock().unwrap().srights += 1;
            Message {
                bits: bits::set(disp::MOVE_SEND, 0, 0, 0),
                dest: Right::Send(port.clone()),
                reply: None,
                voucher: None,
                voucher_name: 0,
                id: 123,
                body: Vec::new(),
                items: Vec::new(),
                sender: Sender::KERNEL,
                aux: Vec::new(),
            }
        };
        assert_eq!(
            bridge::send(&mut p.proc, message(), Some(0), 0),
            Err(kr::MACH_SEND_INVALID_DEST)
        );
        assert_eq!(port.state.lock().unwrap().srights, 0);
        bridge::forward(&mut p.proc, message());
        assert_eq!(port.state.lock().unwrap().srights, 0);
        assert!(!p.proc.bridge.allows_host_services());
    }
}

#[test]
fn bounded_zero_cancel_resume_and_cached_exit_both_darwin_abis() {
    for abi in [DarwinAbi::X86_64, DarwinAbi::Arm64] {
        let mut p = process(abi);
        let cancelled = AtomicBool::new(true);
        assert_eq!(p.run_slice(0, &cancelled), RunStatus::BudgetExhausted);
        assert_eq!(p.run_slice(10, &cancelled), RunStatus::Cancelled);
        assert_eq!(p.proc.threads.values().next().unwrap().cpu.pc(), ENTRY);
        cancelled.store(false, Ordering::Release);
        finish(&mut p);
        assert_eq!(
            p.run_slice(0, &cancelled),
            RunStatus::Complete(ExitStatus::Exited(37))
        );
        p.proc.exit = None;
        assert_eq!(p.run(), ExitStatus::Exited(37));
    }
}

#[test]
fn bounded_indefinite_wait_cancellation_and_posted_wake_both_darwin_abis() {
    for abi in [DarwinAbi::X86_64, DarwinAbi::Arm64] {
        let mut p = process(abi);
        let tid = *p.proc.threads.keys().next().unwrap();
        let key = WaitKey::Address(0x1234);
        p.proc.threads.get_mut(&tid).unwrap().wait = Some(Wait::key(key, None));
        let cancelled = AtomicBool::new(false);
        assert_eq!(p.run_slice(u64::MAX, &cancelled), RunStatus::Blocked);
        assert!(p.proc.threads[&tid].wait.is_some());
        cancelled.store(true, Ordering::Release);
        assert_eq!(p.run_slice(10, &cancelled), RunStatus::Cancelled);
        assert!(p.proc.threads[&tid].wait.is_some());
        p.proc.post(key);
        cancelled.store(false, Ordering::Release);
        finish(&mut p);
    }
}

#[test]
fn embedded_process_runs_with_virtual_identity_and_denies_host_syscalls() {
    use crate::user::darwin::{
        abi::{Errno, tables::nr},
        arch::Rv,
        syscall::{Ctx, bsd},
    };
    for abi in [DarwinAbi::X86_64, DarwinAbi::Arm64] {
        let mut p = process_with_profile(abi, true);
        assert!(p.proc.vfs.is_closed());
        assert!(!p.proc.bridge.allows_host_services());
        assert_eq!(p.proc.bridge.fd(), None);
        assert_eq!(p.proc.pid, 1000);
        assert_eq!(p.proc.ppid, 0);
        assert_eq!(p.proc.creds, (1000, 1000, 1000, 1000));
        assert_eq!(p.proc.umask, 0o022);
        assert!(!p.proc.config.warn_unhandled());
        assert!(p.proc.vfs.lookup(b"/bounded-test", b"/").is_ok());
        let (tid, mut thread) = p.proc.threads.pop_first().unwrap();
        let mut ctx = Ctx {
            proc: &mut p.proc,
            thread: &mut thread,
            nr: 0,
            pc: ENTRY,
        };
        assert_eq!(bsd::call(&mut ctx, nr::GETPID, &[0; 8]), Ok(Rv::one(1000)));
        assert_eq!(bsd::call(&mut ctx, nr::GETPPID, &[0; 8]), Ok(Rv::one(0)));
        for number in [nr::PTRACE, nr::SOCKET] {
            assert_eq!(
                bsd::call(&mut ctx, number, &[u64::MAX; 8]),
                Err(Errno::EPERM)
            );
        }
        assert_eq!(
            bsd::call(&mut ctx, nr::POSIX_SPAWN, &[u64::MAX; 8]),
            Err(Errno::EFAULT)
        );
        p.proc.threads.insert(tid, thread);
        finish(&mut p);
    }
}

#[test]
fn embedded_exec_uses_supplied_images_and_inherits_guest_state() {
    use crate::user::darwin::{
        abi::{Errno, tables::nr},
        io::O_CLOEXEC,
        syscall::{Ctx, bsd},
    };
    use crate::user::supplied_fs::Device;

    for abi in [DarwinAbi::X86_64, DarwinAbi::Arm64] {
        let mut p = process(abi);
        let (_, original) = p.proc.vfs.lookup(b"/bounded-test", b"/").unwrap();
        let mut image = original.bytes().unwrap().to_vec();
        // Change the exit status in the fixture's existing `exit` sequence.
        match abi {
            DarwinAbi::X86_64 => image[0x1006] = 52,
            DarwinAbi::Arm64 => {
                image[0x1004..0x1008].copy_from_slice(&(0xd280_0000u32 | (52 << 5)).to_le_bytes())
            }
        }
        let files = p
            .proc
            .vfs
            .files()
            .unwrap()
            .with_file("/work/next".into(), Arc::from(image))
            .unwrap()
            .with_file("/work/start".into(), Arc::from(&b"#!/work/next -arg\n"[..]))
            .unwrap()
            .with_file("/work/empty".into(), Arc::from(&b""[..]))
            .unwrap()
            .with_device(Device::Null)
            .unwrap();
        p.proc.vfs = Vfs::supplied(files);
        p.proc.cwd = b"/work".to_vec();
        let pid = p.proc.pid;
        let output = p.proc.fds.file(1).unwrap();
        let (_, mut thread) = p.proc.threads.pop_first().unwrap();
        let name = thread.cpu.sp() - 4096;
        let mut ctx = Ctx {
            proc: &mut p.proc,
            thread: &mut thread,
            nr: i64::from(nr::EXECVE),
            pc: ENTRY,
        };
        for (path, errno) in [
            (&b"/usr/bin/printf\0"[..], Errno::ENOENT),
            (&b".\0"[..], Errno::EACCES),
            (&b"/dev/null\0"[..], Errno::EACCES),
            (&b"empty\0"[..], Errno::ENOEXEC),
        ] {
            ctx.write(name, path).unwrap();
            assert_eq!(
                bsd::call(&mut ctx, nr::EXECVE, &[name, 0, 0, 0, 0, 0, 0, 0]),
                Err(errno)
            );
            assert!(ctx.proc.exec.is_none());
        }
        ctx.write(name, b"next\0").unwrap();
        let closed = bsd::call(
            &mut ctx,
            nr::OPEN,
            &[name, u64::from(O_CLOEXEC), 0, 0, 0, 0, 0, 0],
        )
        .unwrap()
        .0 as i32;
        ctx.write(name, b"start\0").unwrap();
        assert_eq!(
            bsd::call(&mut ctx, nr::EXECVE, &[name, 0, 0, 0, 0, 0, 0, 0]),
            Err(Errno::EJUSTRETURN)
        );
        let swap = ctx.proc.exec.take().unwrap();
        assert!(!ctx.proc.bridge.allows_host_services());
        p.swap(*swap);
        assert_eq!(p.proc.pid, pid);
        assert_eq!(p.proc.cwd, b"/work");
        assert!(p.proc.vfs.lookup(b"/bounded-test", b"/").is_ok());
        assert_eq!(p.proc.config.exec_path, "/work/next");
        assert_eq!(
            p.proc.config.argv,
            [b"/work/next".to_vec(), b"-arg".to_vec(), b"start".to_vec()]
        );
        assert!(Arc::ptr_eq(&p.proc.fds.file(1).unwrap(), &output));
        assert!(p.proc.fds.file(closed).is_err());
        assert!(!p.proc.bridge.allows_host_services());
        assert_eq!(
            p.run_slice(100, &AtomicBool::new(false)),
            RunStatus::Complete(ExitStatus::Exited(52))
        );
    }
}

#[test]
fn embedded_process_rejects_inconsistent_profiles_before_loading() {
    use crate::user::{
        console::{CapturedConsole, Console},
        supplied_fs::Files,
    };
    let base = DarwinConfig::embedded(
        "/test",
        vec![],
        vec![],
        Files::new(BTreeMap::new()).unwrap(),
        CapturedConsole::new(vec![], 32).unwrap(),
    );
    let mut cases = Vec::new();
    let mut c = base.clone();
    c.host_services = true;
    cases.push(c);
    let mut c = base.clone();
    c.root = Some("/".into());
    cases.push(c);
    let mut c = base.clone();
    c.host_job_control = true;
    cases.push(c);
    let mut c = base.clone();
    c.strace = true;
    cases.push(c);
    let mut c = base.clone();
    c.console = Console::Host;
    cases.push(c);
    let mut c = base.clone();
    c.seed = None;
    cases.push(c);
    let mut c = base.clone();
    c.supplied_files = None;
    cases.push(c);
    let mut c = base.clone();
    c.cwd = ".".into();
    cases.push(c);
    let mut c = base;
    c.cwd = "/test".into();
    cases.push(c);
    for config in cases {
        let image = ImageFile {
            path: "/test".into(),
            host_path: "/test".into(),
            vnode_path: "/test".into(),
            bytes: Arc::from(&b"not a Mach-O"[..]),
            file_id: (0, 0),
            slice: None,
        };
        assert!(matches!(
            DarwinProcess::spawn(config, image),
            Err(SpawnError::Configuration(_))
        ));
    }
}

#[test]
fn embedded_signals_and_creation_mask_are_process_local() {
    use crate::user::darwin::{
        abi::{Errno, tables::nr},
        arch::Rv,
        signal::{SIGKILL, SIGUSR1, bit},
        syscall::{Ctx, bsd},
    };
    for abi in [DarwinAbi::X86_64, DarwinAbi::Arm64] {
        let mut p = process_with_profile(abi, true);
        let other = process_with_profile(abi, true);
        let (tid, mut thread) = p.proc.threads.pop_first().unwrap();
        let buf = thread.cpu.sp() - 128;
        let port = thread.port;
        let mut ctx = Ctx {
            proc: &mut p.proc,
            thread: &mut thread,
            nr: 0,
            pc: ENTRY,
        };
        ctx.write_u32(buf, bit(SIGUSR1) | bit(SIGKILL)).unwrap();
        assert_eq!(
            bsd::call(&mut ctx, nr::PTHREAD_SIGMASK, &[1, buf, 0, 0, 0, 0, 0, 0]),
            Ok(Rv::one(0))
        );
        assert_eq!(ctx.thread.sig.mask, bit(SIGUSR1));
        assert_eq!(
            bsd::call(&mut ctx, nr::KILL, &[1001, 0, 0, 0, 0, 0, 0, 0]),
            Err(Errno::EPERM)
        );
        for pid in [1000i64, 0, -1, -1000] {
            assert_eq!(
                bsd::call(&mut ctx, nr::KILL, &[pid as u64, 0, 0, 0, 0, 0, 0, 0]),
                Ok(Rv::one(0))
            );
        }
        assert_eq!(
            bsd::call(
                &mut ctx,
                nr::PTHREAD_KILL,
                &[port as u64, SIGUSR1 as u64, 0, 0, 0, 0, 0, 0]
            ),
            Ok(Rv::one(0))
        );
        assert_eq!(
            bsd::call(&mut ctx, nr::SIGPENDING, &[buf + 4, 0, 0, 0, 0, 0, 0, 0]),
            Ok(Rv::one(0))
        );
        assert_eq!(ctx.read_u32(buf + 4).unwrap(), bit(SIGUSR1));
        assert_eq!(
            bsd::call(&mut ctx, nr::SIGWAIT, &[buf, buf + 8, 0, 0, 0, 0, 0, 0]),
            Ok(Rv::one(0))
        );
        assert_eq!(ctx.read_u32(buf + 8).unwrap(), SIGUSR1 as u32);
        assert_eq!(ctx.thread.sig.pending, 0);
        assert_eq!(
            bsd::call(&mut ctx, nr::UMASK, &[0o1077, 0, 0, 0, 0, 0, 0, 0]),
            Ok(Rv::one(0o022))
        );
        assert_eq!(ctx.proc.umask, 0o077);
        assert_eq!(other.proc.umask, 0o022);
        assert!(
            other
                .proc
                .threads
                .values()
                .all(|t| t.sig.pending == 0 && t.sig.mask == 0)
        );
        p.proc.threads.insert(tid, thread);
        finish(&mut p);
    }
}

#[test]
fn embedded_thread_registration_creation_and_ulock_wake_use_guest_state() {
    use crate::user::darwin::{
        abi::{Errno, tables::nr},
        arch::Rv,
        syscall::{Ctx, bsd},
    };
    for abi in [DarwinAbi::X86_64, DarwinAbi::Arm64] {
        let mut p = process_with_profile(abi, true);
        let (tid, mut thread) = p.proc.threads.pop_first().unwrap();
        let buf = thread.cpu.sp() - 1024;
        let mut ctx = Ctx {
            proc: &mut p.proc,
            thread: &mut thread,
            nr: i64::from(nr::ULOCK_WAIT),
            pc: ENTRY,
        };
        ctx.write(buf, &[0; 56]).unwrap();
        ctx.write_u64(buf, 56).unwrap();
        assert!(
            bsd::call(
                &mut ctx,
                nr::BSDTHREAD_REGISTER,
                &[ENTRY, 0, 256, buf, 56, 0, 0, 0]
            )
            .is_ok()
        );
        assert_eq!(ctx.read_u64(buf + 16).unwrap(), 0x8ff);
        assert_eq!(
            bsd::call(&mut ctx, nr::THREAD_SELFID, &[0; 8]),
            Ok(Rv::one(tid))
        );
        assert_eq!(
            bsd::call(
                &mut ctx,
                nr::BSDTHREAD_CREATE,
                &[ENTRY, 0, buf - 256, buf + 128, 0x2100_0000, 0, 0, 0]
            ),
            Ok(Rv::one(buf + 128))
        );
        let (child_tid, mut child) = ctx.proc.threads.pop_first().unwrap();
        assert_ne!(child_tid, tid);
        assert_eq!(child.mach.suspend_count, 1);
        ctx.write_u32(buf, 7).unwrap();
        assert_eq!(
            bsd::call(&mut ctx, nr::ULOCK_WAIT, &[1, buf, 7, 0, 0, 0, 0, 0]),
            Err(Errno::ERESTART)
        );
        assert!(ctx.thread.wait.as_ref().unwrap().fds.is_empty());
        p.proc.threads.insert(tid, thread);
        let mut ctx = Ctx {
            proc: &mut p.proc,
            thread: &mut child,
            nr: i64::from(nr::ULOCK_WAKE),
            pc: ENTRY,
        };
        assert_eq!(
            bsd::call(&mut ctx, nr::ULOCK_WAKE, &[1, buf, 0, 0, 0, 0, 0, 0]),
            Ok(Rv::one(0))
        );
        assert!(ctx.proc.threads[&tid].woken);
        assert_eq!(
            bsd::call(&mut ctx, nr::BSDTHREAD_TERMINATE, &[0; 8]),
            Err(Errno::EJUSTRETURN)
        );
        assert!(ctx.thread.exited);
        let mut thread = p.proc.threads.remove(&tid).unwrap();
        let mut ctx = Ctx {
            proc: &mut p.proc,
            thread: &mut thread,
            nr: i64::from(nr::ULOCK_WAIT),
            pc: ENTRY,
        };
        assert_eq!(
            bsd::call(&mut ctx, nr::ULOCK_WAIT, &[1, buf, 7, 0, 0, 0, 0, 0]),
            Ok(Rv::one(0))
        );
        thread.wait = None;
        thread.resume = None;
        p.proc.threads.insert(tid, thread);
        finish(&mut p);
    }
}

#[test]
fn embedded_sysctl_answers_guest_nodes_without_host_discovery() {
    use crate::user::darwin::{
        abi::{Errno, tables::nr},
        arch::Rv,
        syscall::{Ctx, bsd},
    };
    for abi in [DarwinAbi::X86_64, DarwinAbi::Arm64] {
        let mut p = process_with_profile(abi, true);
        let (_, mut thread) = p.proc.threads.pop_first().unwrap();
        let buf = thread.cpu.sp() - 1024;
        let mut ctx = Ctx {
            proc: &mut p.proc,
            thread: &mut thread,
            nr: 0,
            pc: ENTRY,
        };
        for (name, expected) in [
            ("kern.ostype", b"Darwin\0".to_vec()),
            ("hw.memsize", MEMSIZE.to_le_bytes().to_vec()),
        ] {
            ctx.write(buf, name.as_bytes()).unwrap();
            ctx.write_u64(buf + 128, 64).unwrap();
            assert_eq!(
                bsd::call(
                    &mut ctx,
                    nr::SYSCTLBYNAME,
                    &[buf, name.len() as u64, buf + 256, buf + 128, 0, 0, 0, 0]
                ),
                Ok(Rv::one(0))
            );
            assert_eq!(ctx.read_u64(buf + 128).unwrap(), expected.len() as u64);
            assert_eq!(ctx.read(buf + 256, expected.len()).unwrap(), expected);
        }
        // Host-owned names and their numeric OIDs are unavailable even on macOS.
        let name = b"kern.hostname";
        ctx.write(buf, name).unwrap();
        ctx.write_u64(buf + 128, 64).unwrap();
        assert_eq!(
            bsd::call(
                &mut ctx,
                nr::SYSCTLBYNAME,
                &[buf, name.len() as u64, buf + 256, buf + 128, 0, 0, 0, 0]
            ),
            Err(Errno::ENOENT)
        );
        ctx.write_u32(buf, 1).unwrap();
        ctx.write_u32(buf + 4, 10).unwrap(); // KERN_HOSTNAME
        assert_eq!(
            bsd::call(
                &mut ctx,
                nr::SYSCTL,
                &[buf, 2, buf + 256, buf + 128, 0, 0, 0, 0]
            ),
            Err(Errno::ENOENT)
        );
        // Enumeration after kern.ostype selects the next emulated override,
        // skipping the host's kern.osrelease OID [1, 2].
        for (i, n) in [0, 2, 1, 1].into_iter().enumerate() {
            ctx.write_u32(buf + i as u64 * 4, n).unwrap();
        }
        assert_eq!(
            bsd::call(
                &mut ctx,
                nr::SYSCTL,
                &[buf, 4, buf + 256, buf + 128, 0, 0, 0, 0]
            ),
            Ok(Rv::one(0))
        );
        assert_eq!(ctx.read_u64(buf + 128).unwrap(), 8);
        assert_eq!(ctx.read_u32(buf + 256).unwrap(), 1);
        assert_eq!(ctx.read_u32(buf + 260).unwrap(), 3);
        // Override writes remain denied; undersized value buffers report zero copied.
        ctx.write(buf, b"kern.ostype").unwrap();
        ctx.write_u64(buf + 128, 1).unwrap();
        assert_eq!(
            bsd::call(
                &mut ctx,
                nr::SYSCTLBYNAME,
                &[buf, 11, buf + 256, buf + 128, buf + 512, 1, 0, 0]
            ),
            Err(Errno::EPERM)
        );
        assert_eq!(
            bsd::call(
                &mut ctx,
                nr::SYSCTLBYNAME,
                &[buf, 11, buf + 256, buf + 128, 0, 0, 0, 0]
            ),
            Err(Errno::ENOMEM)
        );
        assert_eq!(ctx.read_u64(buf + 128).unwrap(), 0);
    }
}

#[test]
fn embedded_kernel_version_is_guest_owned_and_has_exact_copyout_boundaries() {
    use crate::user::darwin::{
        abi::{Errno, tables::nr},
        arch::Rv,
        syscall::{Ctx, bsd},
    };
    // Match the existing closed Mach host_kernel_version identity, including one NUL.
    let expected = b"Darwin Kernel Version 25.0.0: root:xnu-12377.121.6/RELEASE\0";
    let expected_len = expected.len() as u64;
    for abi in [DarwinAbi::X86_64, DarwinAbi::Arm64] {
        let mut process = process_with_profile(abi, true);
        let (_, mut thread) = process.proc.threads.pop_first().unwrap();
        let buf = thread.cpu.sp() - 1024;
        let mut ctx = Ctx {
            proc: &mut process.proc,
            thread: &mut thread,
            nr: 0,
            pc: ENTRY,
        };
        ctx.write_u32(buf, 1).unwrap(); // CTL_KERN
        ctx.write_u32(buf + 4, 4).unwrap(); // KERN_VERSION
        ctx.write(buf + 32, b"kern.version").unwrap();
        for named in [false, true] {
            for capacity in [0, expected_len - 1, expected_len, 128] {
                ctx.write(buf + 256, &[0xa5; 128]).unwrap();
                ctx.write_u64(buf + 128, capacity).unwrap();
                let output = if capacity == 0 { 0 } else { buf + 256 };
                let (number, address, length) = if named {
                    (nr::SYSCTLBYNAME, buf + 32, 12)
                } else {
                    (nr::SYSCTL, buf, 2)
                };
                let result = bsd::call(
                    &mut ctx,
                    number,
                    &[address, length, output, buf + 128, 0, 0, 0, 0],
                );
                assert_eq!(
                    result,
                    if capacity == expected_len - 1 {
                        Err(Errno::ENOMEM)
                    } else {
                        Ok(Rv::one(0))
                    },
                    "{abi:?} named={named} capacity={capacity}"
                );
                assert_eq!(
                    ctx.read_u64(buf + 128).unwrap(),
                    if capacity == expected_len - 1 {
                        0
                    } else {
                        expected_len
                    }
                );
                let mut bytes = [0xa5; 128];
                if capacity >= expected_len {
                    bytes[..expected.len()].copy_from_slice(expected);
                }
                assert_eq!(ctx.read(buf + 256, 128).unwrap(), bytes);
            }
            ctx.write_u64(buf + 128, 128).unwrap();
            let (number, address, length) = if named {
                (nr::SYSCTLBYNAME, buf + 32, 12)
            } else {
                (nr::SYSCTL, buf, 2)
            };
            assert_eq!(
                bsd::call(
                    &mut ctx,
                    number,
                    &[address, length, buf + 256, buf + 128, buf + 512, 1, 0, 0]
                ),
                Err(Errno::EPERM)
            );
        }
    }
}

#[test]
fn embedded_proc_info_reports_only_the_guest_process_identity() {
    use crate::user::darwin::{
        abi::{Errno, tables::nr},
        arch::Rv,
        syscall::{Ctx, bsd},
    };

    for abi in [DarwinAbi::X86_64, DarwinAbi::Arm64] {
        let mut process = process_with_profile(abi, true);
        let uuid = *b"guest-image-uuid";
        process.proc.program.main.uuid = Some(uuid);
        let pid = process.proc.pid as u64;
        let version = u64::from(process.proc.audit[7]);
        let unique_id = (version << 32) | pid;
        let (_, mut thread) = process.proc.threads.pop_first().unwrap();
        let buf = thread.cpu.sp() - 1024;
        let mut ctx = Ctx {
            proc: &mut process.proc,
            thread: &mut thread,
            nr: 0,
            pc: ENTRY,
        };
        let sentinel = [0xa5; 64];
        let mut expected = sentinel;
        expected[..16].copy_from_slice(&uuid);
        expected[16..24].copy_from_slice(&unique_id.to_le_bytes());
        expected[24..32].fill(0);
        expected[32..36].copy_from_slice(&(version as u32).to_le_bytes());
        expected[36..56].fill(0);
        for (number, args) in [
            (nr::PROC_INFO, [2, pid, 17, 1, buf, 64, 0, 0]),
            (
                nr::PROC_INFO_EXTENDED_ID,
                [2, pid, 17, 1, version, 1, buf, 56],
            ),
            (
                nr::PROC_INFO_EXTENDED_ID,
                [2, pid, 17, 2, unique_id, 0, buf, 64],
            ),
        ] {
            ctx.write(buf, &sentinel).unwrap();
            assert_eq!(
                bsd::call(&mut ctx, number, &args),
                Ok(Rv::one(56)),
                "{abi:?}"
            );
            assert_eq!(ctx.read(buf, 64).unwrap(), expected, "{abi:?}");
        }

        for (number, args, error) in [
            (nr::PROC_INFO, [1, pid, 17, 1, buf, 64, 0, 0], Errno::EPERM),
            (
                nr::PROC_INFO,
                [2, pid + 1, 17, 1, buf, 64, 0, 0],
                Errno::EPERM,
            ),
            (nr::PROC_INFO, [2, pid, 18, 1, buf, 64, 0, 0], Errno::EPERM),
            (nr::PROC_INFO, [2, pid, 17, 1, buf, 55, 0, 0], Errno::ENOMEM),
            (nr::PROC_INFO, [2, pid, 17, 1, 0, 56, 0, 0], Errno::EFAULT),
            (
                nr::PROC_INFO_EXTENDED_ID,
                [2, pid, 17, 1, version + 1, 0, buf, 64],
                Errno::ESRCH,
            ),
            (
                nr::PROC_INFO_EXTENDED_ID,
                [2, pid, 17, 2, unique_id + 1, 0, buf, 64],
                Errno::ESRCH,
            ),
            (
                nr::PROC_INFO_EXTENDED_ID,
                [2, pid, 17, 3, unique_id, 0, buf, 64],
                Errno::EINVAL,
            ),
        ] {
            ctx.write(buf, &sentinel).unwrap();
            assert_eq!(bsd::call(&mut ctx, number, &args), Err(error), "{abi:?}");
            assert_eq!(ctx.read(buf, 64).unwrap(), sentinel, "{abi:?}");
        }
    }
}

#[test]
fn embedded_vm_queries_and_advice_reject_rounding_overflow() {
    use crate::user::darwin::{
        abi::{Errno, tables::nr},
        arch::Rv,
        syscall::{Ctx, bsd, mem},
        vm,
    };
    for abi in [DarwinAbi::X86_64, DarwinAbi::Arm64] {
        let mut p = process_with_profile(abi, true);
        let (_, mut thread) = p.proc.threads.pop_first().unwrap();
        let buf = thread.cpu.sp() - 128;
        let mut ctx = Ctx {
            proc: &mut p.proc,
            thread: &mut thread,
            nr: 0,
            pc: ENTRY,
        };
        let page = ctx.proc.vm.page;
        let addr = bsd::call(
            &mut ctx,
            nr::MMAP,
            &[
                0,
                page,
                u64::from(vm::VM_PROT_READ | vm::VM_PROT_WRITE),
                u64::from(mem::MAP_PRIVATE | mem::MAP_ANON),
                u64::MAX,
                0,
                0,
                0,
            ],
        )
        .unwrap()
        .0;
        ctx.write(addr, b"data").unwrap();
        assert_eq!(
            bsd::call(&mut ctx, nr::MINCORE, &[addr, page, buf, 0, 0, 0, 0, 0]),
            Ok(Rv::one(0))
        );
        assert_ne!(ctx.read(buf, 1).unwrap()[0] & 1, 0);
        for call in [nr::MLOCK, nr::MUNLOCK, nr::MSYNC, nr::MSYNC_NOCANCEL] {
            assert_eq!(
                bsd::call(&mut ctx, call, &[addr, page, 0, 0, 0, 0, 0, 0]),
                Ok(Rv::one(0))
            );
        }
        assert_eq!(
            bsd::call(&mut ctx, nr::MINHERIT, &[addr, page, 2, 0, 0, 0, 0, 0]),
            Ok(Rv::one(0))
        );
        assert_eq!(
            bsd::call(&mut ctx, nr::MADVISE, &[addr, page, 11, 0, 0, 0, 0, 0]),
            Ok(Rv::one(0))
        );
        assert_eq!(ctx.read(addr, 4).unwrap(), [0; 4]);
        assert_eq!(
            bsd::call(&mut ctx, nr::MSYNC, &[addr, u64::MAX, 0, 0, 0, 0, 0, 0]),
            Err(Errno::EINVAL)
        );
        assert_eq!(
            bsd::call(&mut ctx, nr::MINCORE, &[u64::MAX, 0, buf, 0, 0, 0, 0, 0]),
            Err(Errno::ENOMEM)
        );
        for call in [nr::MLOCK, nr::MUNLOCK] {
            assert_eq!(
                bsd::call(&mut ctx, call, &[u64::MAX, 0, 0, 0, 0, 0, 0, 0]),
                Err(Errno::EINVAL)
            );
        }
    }
}

#[test]
fn embedded_shared_region_maps_supplied_cache_before_reading_slide_info() {
    use crate::user::darwin::{
        abi::{Errno, tables::nr},
        arch::Rv,
        fd::OpenFile,
        syscall::{Ctx, bsd},
    };
    for abi in [DarwinAbi::X86_64, DarwinAbi::Arm64] {
        let mut p = process_with_profile(abi, true);
        let (_, mut thread) = p.proc.threads.pop_first().unwrap();
        let buf = thread.cpu.sp() - 2048;
        let mut ctx = Ctx {
            proc: &mut p.proc,
            thread: &mut thread,
            nr: 0,
            pc: ENTRY,
        };
        let page = ctx.proc.vm.page;
        let base = 0x2_0000_0000u64;
        let mut bytes = vec![0u8; 2 * page as usize];
        bytes[8..16].copy_from_slice(&0x10u64.to_le_bytes());
        let info = &mut bytes[page as usize..];
        info[0..4].copy_from_slice(&5u32.to_le_bytes());
        info[4..8].copy_from_slice(&(page as u32).to_le_bytes());
        info[8..12].copy_from_slice(&1u32.to_le_bytes());
        info[16..24].copy_from_slice(&0x1_8000_0000u64.to_le_bytes());
        info[24..26].copy_from_slice(&8u16.to_le_bytes());
        let bytes: Arc<[u8]> = bytes.into();
        let files = crate::user::supplied_fs::Files::new(BTreeMap::from([(
            "/cache".into(),
            bytes.clone(),
        )]))
        .unwrap();
        let (path, entry) = files.lookup("/cache").unwrap();
        let ino = entry.ino;
        let fd = ctx
            .proc
            .fds
            .install(Arc::new(OpenFile::supplied(path, entry)), false, 0, 256)
            .unwrap();
        let mut fraw = [0; 12];
        fraw[..4].copy_from_slice(&(fd as i32).to_le_bytes());
        fraw[4..8].copy_from_slice(&2u32.to_le_bytes());
        ctx.write(buf, &fraw).unwrap();
        let mut maps = Vec::new();
        for (address, offset, slide_size, slide_start) in
            [(base, 0, 26, base + page), (base + page, page, 0, 0)]
        {
            for n in [address, page, offset, slide_size, slide_start] {
                maps.extend_from_slice(&n.to_le_bytes());
            }
            maps.extend_from_slice(&1u32.to_le_bytes());
            maps.extend_from_slice(&1u32.to_le_bytes());
        }
        ctx.write(buf + 128, &maps).unwrap();
        assert_eq!(
            bsd::call(
                &mut ctx,
                nr::SHARED_REGION_CHECK_NP,
                &[buf + 256, 0, 0, 0, 0, 0, 0, 0]
            ),
            Err(Errno::ENOMEM)
        );
        ctx.write_u32(buf, 0).unwrap(); // Captured stdin cannot back a cache mapping.
        assert_eq!(
            bsd::call(
                &mut ctx,
                nr::SHARED_REGION_MAP_AND_SLIDE_2_NP,
                &[1, buf, 2, buf + 128, 0, 0, 0, 0]
            ),
            Err(Errno::EPERM)
        );
        assert!(ctx.proc.space.vma_at(base).is_none());
        ctx.write_u32(buf, fd as u32).unwrap();
        assert_eq!(
            bsd::call(
                &mut ctx,
                nr::SHARED_REGION_MAP_AND_SLIDE_2_NP,
                &[1, buf, 2, buf + 128, 0, 0, 0, 0]
            ),
            Ok(Rv::one(0))
        );
        assert_eq!(ctx.read_u64(base + 8).unwrap(), 0x1_8000_0010);
        assert_eq!(u64::from_le_bytes(bytes[8..16].try_into().unwrap()), 0x10);
        assert_eq!(
            ctx.proc.space.vma_at(base).unwrap().backing.identity().ino,
            ino
        );
        assert_eq!(
            bsd::call(
                &mut ctx,
                nr::SHARED_REGION_CHECK_NP,
                &[buf + 256, 0, 0, 0, 0, 0, 0, 0]
            ),
            Ok(Rv::one(0))
        );
        assert_eq!(ctx.read_u64(buf + 256).unwrap(), base);
        assert_eq!(
            bsd::call(&mut ctx, nr::SHARED_REGION_CHECK_NP, &[0; 8]),
            Ok(Rv::one(0))
        );
        assert!(ctx.proc.shared_region.is_none());
        assert!(ctx.proc.space.vma_at(base).is_none());
        assert!(ctx.proc.space.vma_at(base + page).is_none());
        ctx.write_u32(buf, u32::MAX).unwrap();
        ctx.write_u32(buf + 4, 1).unwrap();
        ctx.write_u64(buf + 136, ctx.proc.config.arena_bytes + page)
            .unwrap();
        assert_eq!(
            bsd::call(
                &mut ctx,
                nr::SHARED_REGION_MAP_AND_SLIDE_2_NP,
                &[1, buf, 1, buf + 128, 0, 0, 0, 0]
            ),
            Err(Errno::ENOMEM)
        );
        assert!(ctx.proc.space.vma_at(base).is_none());
    }
}

#[cfg(not(unix))]
#[test]
fn native_host_profile_is_explicitly_unavailable() {
    assert!(!crate::user::darwin::HOST_SERVICES_AVAILABLE);
    let config = DarwinConfig::new("/unavailable", vec![], vec![]);
    let image = ImageFile {
        path: "/unavailable".into(),
        host_path: "/unavailable".into(),
        vnode_path: "/unavailable".into(),
        bytes: Vec::new().into(),
        file_id: (0, 0),
        slice: None,
    };
    assert!(matches!(
        DarwinProcess::spawn(config, image),
        Err(SpawnError::Configuration(
            "the host-backed Darwin profile requires Unix host services"
        ))
    ));
}

#[cfg(unix)]
#[test]
fn legacy_host_profile_still_executes_static_images() {
    assert!(crate::user::darwin::HOST_SERVICES_AVAILABLE);
    for abi in [DarwinAbi::X86_64, DarwinAbi::Arm64] {
        let mut process = process_with_profile(abi, false);
        assert!(process.proc.config.host_services);
        finish(&mut process);
    }
}
