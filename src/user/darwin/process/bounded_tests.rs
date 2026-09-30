//! Static Mach-O fixtures exercise bounded execution without a host dyld.
use super::*;
use crate::user::image::macho::*;

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
fn process(abi: DarwinAbi) -> DarwinProcess {
    process_with_profile(abi, true)
}

fn process_with_profile(abi: DarwinAbi, embedded: bool) -> DarwinProcess {
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
        assert_eq!(file::writev(&mut ctx, 0, 0, 0, None), Err(Errno::EBADF));
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
        for number in [nr::FORK, nr::EXECVE, nr::SOCKET] {
            assert_eq!(
                bsd::call(&mut ctx, number, &[u64::MAX; 8]),
                Err(Errno::EPERM)
            );
        }
        p.proc.threads.insert(tid, thread);
        finish(&mut p);
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
