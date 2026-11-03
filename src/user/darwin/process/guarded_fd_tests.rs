//! Native guarded-fd validation replay and descriptor/exception lifecycle.
use super::*;
use crate::user::darwin::abi::{Errno, tables::nr};
use crate::user::darwin::arch::{Rv, SysResult};
use crate::user::darwin::fd::DescriptorGuard;
use crate::user::darwin::io;
use crate::user::darwin::syscall::{Ctx, bsd};

const COOKIE: u64 = 0x1122_3344_5566_7788;
const OTHER: u64 = 0x8877_6655_4433_2211;

#[test]
fn guarded_fd_replays_396_native_devfd_open_cases_on_both_guest_abis() {
    let inputs = [
        (
            DarwinAbi::Arm64,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/darwin/native-guarded-fd/devfd-records-arm64-v7.json"
            )),
        ),
        (
            DarwinAbi::X86_64,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/darwin/native-guarded-fd/devfd-records-x86_64-v7.json"
            )),
        ),
    ];
    let mut replayed = 0;
    for (abi, input) in inputs {
        let records: serde_json::Value = serde_json::from_str(input).unwrap();
        assert_eq!(records.as_array().unwrap().len(), 198);
        let mut process = bounded_tests::process(abi);
        let (_, mut thread) = process.proc.threads.pop_first().unwrap();
        let mut ctx = Ctx {
            proc: &mut process.proc,
            thread: &mut thread,
            nr: 0,
            pc: 0x1_0000_1000,
        };
        for native in records.as_array().unwrap() {
            let original_mode = native["original_mode"].as_u64().unwrap() as u32;
            let original_flags = native["original_fd_flags"].as_u64().unwrap();
            let file = ctx.proc.fds.file(1).unwrap();
            *file.flags.lock().unwrap() = original_mode;
            let fd = ctx
                .proc
                .fds
                .install_with(
                    file.clone(),
                    original_flags & 1 != 0,
                    original_flags & 2 != 0,
                    9,
                    256,
                )
                .unwrap();
            if native["guarded"].as_bool().unwrap() {
                ctx.proc.fds.get_mut(fd).unwrap().guard = Some(DescriptorGuard {
                    cookie: COOKIE,
                    attributes: 2,
                });
            }
            let flags = native["open_flags"].as_u64().unwrap() as u32;
            let expected = &native["records"][0];
            let result = bsd::path::open_descriptor(&mut ctx, fd, flags);
            if expected["result"].as_i64().unwrap() < 0 {
                assert_eq!(
                    result,
                    Err(Errno(expected["errno"].as_i64().unwrap() as i32)),
                    "{abi:?}/{native}"
                );
            } else {
                let clone = result.unwrap().0 as i32;
                let records = native["records"].as_array().unwrap();
                let expected_flags = records
                    .iter()
                    .find(|row| row["kind"] == "cloned-fd-flags")
                    .unwrap()["result"]
                    .as_u64()
                    .unwrap();
                assert_eq!(
                    call(&mut ctx, nr::FCNTL, [clone as u64, 1, 0, 0, 0, 0, 0, 0]),
                    Ok(Rv::one(expected_flags)),
                    "{abi:?}/{native}"
                );
                let expected_file_flags = records
                    .iter()
                    .find(|row| row["kind"] == "cloned-file-flags")
                    .unwrap()["result"]
                    .as_u64()
                    .unwrap();
                assert_eq!(
                    call(&mut ctx, nr::FCNTL, [clone as u64, 3, 0, 0, 0, 0, 0, 0]),
                    Ok(Rv::one(expected_file_flags)),
                    "{abi:?}/{native}"
                );
                // fdescfs duplicates the same open description; it does not
                // reopen or truncate the file and therefore shares its offset.
                assert!(Arc::ptr_eq(&file, &ctx.proc.fds.file(clone).unwrap()));
                ctx.proc.fds.remove(clone).unwrap();
            }
            assert!(
                ctx.proc.guard_ast.is_none(),
                "fdescfs refuses guarded duplication without an exception"
            );
            ctx.proc.fds.remove(fd).unwrap();
            replayed += 1;
        }
    }
    assert_eq!(replayed, 396);
}

#[test]
fn guarded_fd_replays_16_native_fork_inheritance_cases_on_both_guest_abis() {
    for (abi, input) in [
        (
            DarwinAbi::Arm64,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/darwin/native-guarded-fd/inherit-records-arm64-v6.json"
            )),
        ),
        (
            DarwinAbi::X86_64,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/darwin/native-guarded-fd/inherit-records-x86_64-v6.json"
            )),
        ),
    ] {
        let records: serde_json::Value = serde_json::from_str(input).unwrap();
        assert_eq!(records.as_array().unwrap().len(), 8);
        let mut process = bounded_tests::process(abi);
        let (_, mut thread) = process.proc.threads.pop_first().unwrap();
        let mut ctx = Ctx {
            proc: &mut process.proc,
            thread: &mut thread,
            nr: 0,
            pc: 0x1_0000_1000,
        };
        for native in records.as_array().unwrap() {
            let attributes = native["attributes"].as_u64().unwrap() as u32;
            let file = ctx.proc.fds.file(1).unwrap();
            let fd = ctx.proc.fds.install_with(file, true, true, 9, 256).unwrap();
            ctx.proc.fds.get_mut(fd).unwrap().guard = Some(DescriptorGuard {
                cookie: COOKIE,
                attributes,
            });
            if native["clear_clofork"].as_bool().unwrap() {
                assert_eq!(
                    call(&mut ctx, nr::FCNTL, [fd as u64, 2, 1, 0, 0, 0, 0, 0]),
                    Ok(Rv::one(0))
                );
            }
            let child = crate::user::darwin::exec::fdt_fork(&ctx.proc.fds, false);
            let flags = &native["records"][0];
            match child.get(fd) {
                Ok(slot) => {
                    assert_eq!(flags["result"], 1, "{abi:?}/{native}");
                    assert!(slot.cloexec && !slot.clofork && slot.guard.is_none());
                }
                Err(error) => {
                    assert_eq!(flags["result"], -1, "{abi:?}/{native}");
                    assert_eq!(error, Errno(flags["errno"].as_i64().unwrap() as i32));
                }
            }
            assert_eq!(
                ctx.proc.fds.get(fd).unwrap().guard.unwrap().attributes,
                attributes
            );
            ctx.proc.fds.remove(fd).unwrap();
        }
    }
}

#[cfg(target_os = "macos")]
#[test]
fn guarded_fd_replays_96_native_devfd_alias_cases_on_both_guest_abis() {
    use std::os::unix::{ffi::OsStrExt, fs::symlink};
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    for (abi, input) in [
        (
            DarwinAbi::Arm64,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/darwin/native-guarded-fd/devfd-alias-records-arm64-v9.json"
            )),
        ),
        (
            DarwinAbi::X86_64,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/darwin/native-guarded-fd/devfd-alias-records-x86_64-v9.json"
            )),
        ),
    ] {
        let records: serde_json::Value = serde_json::from_str(input).unwrap();
        assert_eq!(records.as_array().unwrap().len(), 48);
        let directory = std::fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "rax-devfd-alias-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        std::fs::create_dir(&directory).unwrap();
        let mut process = bounded_tests::process_with_profile(abi, false);
        let (_, mut thread) = process.proc.threads.pop_first().unwrap();
        let at = thread.cpu.sp() - 8192;
        let mut ctx = Ctx {
            proc: &mut process.proc,
            thread: &mut thread,
            nr: 0,
            pc: 0x1_0000_1000,
        };
        let device_directory = std::fs::File::open("/dev/fd").unwrap();
        let open =
            crate::user::darwin::fd::OpenFile::host(device_directory.into(), io::O_RDONLY, None);
        let dirfd = ctx.proc.fds.install(Arc::new(open), true, 20, 256).unwrap();
        for (index, native) in records.as_array().unwrap().iter().enumerate() {
            let data = directory.join(format!("{index}.data"));
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&data)
                .unwrap();
            let open = crate::user::darwin::fd::OpenFile::host(file.into(), io::O_RDWR, None);
            let fd = ctx
                .proc
                .fds
                .install_with(Arc::new(open), true, false, 9, 256)
                .unwrap();
            if native["guarded"].as_bool().unwrap() {
                let slot = ctx.proc.fds.get_mut(fd).unwrap();
                slot.guard = Some(DescriptorGuard {
                    cookie: COOKIE,
                    attributes: 2,
                });
                slot.clofork = true;
            }
            let link = directory.join(format!("{index}.link"));
            let direct = std::path::PathBuf::from(format!("/dev/fd/{fd}"));
            let kind = native["path_kind"].as_str().unwrap();
            let (path, dir) = match kind {
                "directory-alias" => {
                    symlink("/dev/fd", &link).unwrap();
                    (
                        link.join(fd.to_string()),
                        crate::user::darwin::host::AT_FDCWD,
                    )
                }
                "file-alias" => {
                    symlink(&direct, &link).unwrap();
                    (link.clone(), crate::user::darwin::host::AT_FDCWD)
                }
                "relative" => (std::path::PathBuf::from(fd.to_string()), dirfd),
                "direct" => (direct, crate::user::darwin::host::AT_FDCWD),
                _ => unreachable!(),
            };
            let mut bytes = path.as_os_str().as_bytes().to_vec();
            bytes.push(0);
            ctx.write(at, &bytes).unwrap();
            let result = bsd::path::openat(
                &mut ctx,
                dir,
                at,
                native["open_flags"].as_u64().unwrap() as u32,
                0o600,
            );
            let expected = &native["records"][0];
            if expected["result"].as_i64().unwrap() < 0 {
                assert_eq!(
                    result,
                    Err(Errno(expected["errno"].as_i64().unwrap() as i32)),
                    "{abi:?}/{native}"
                );
            } else {
                let duplicate = result
                    .unwrap_or_else(|error| panic!("{abi:?}/{native}: {error:?}"))
                    .0 as i32;
                bsd::file::close(&mut ctx, duplicate).unwrap();
            }
            assert!(ctx.proc.guard_ast.is_none());
            ctx.proc.fds.remove(fd).unwrap();
            if matches!(kind, "directory-alias" | "file-alias") {
                std::fs::remove_file(link).unwrap();
            }
            std::fs::remove_file(data).unwrap();
        }
        ctx.proc.fds.remove(dirfd).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }
}

fn call(ctx: &mut Ctx<'_>, number: u32, arguments: [u64; 8]) -> SysResult {
    ctx.nr = i64::from(number);
    bsd::call(ctx, number, &arguments)
}

#[cfg(target_os = "macos")]
#[test]
fn guarded_fd_replays_64_native_file_and_kqueue_info_records_on_both_guest_abis() {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    for (abi, input) in [
        (
            DarwinAbi::Arm64,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/darwin/native-guarded-fd/fdinfo-records-arm64-v4.json"
            )),
        ),
        (
            DarwinAbi::X86_64,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/darwin/native-guarded-fd/fdinfo-records-x86_64-v4.json"
            )),
        ),
    ] {
        let records: serde_json::Value = serde_json::from_str(input).unwrap();
        assert_eq!(records.as_array().unwrap().len(), 32);
        let mut process = bounded_tests::process_with_profile(abi, false);
        // Host vnode metadata must name the process owning the native handle.
        process.proc.pid = std::process::id() as i32;
        let (_, mut thread) = process.proc.threads.pop_first().unwrap();
        let at = thread.cpu.sp() - 512;
        let mut ctx = Ctx {
            proc: &mut process.proc,
            thread: &mut thread,
            nr: 0,
            pc: 0x1_0000_1000,
        };
        ctx.write_u64(at, COOKIE).unwrap();
        for native in records.as_array().unwrap() {
            let attributes = native["guard_attributes"].as_u64().unwrap();
            let is_kqueue = native["kind"] == "kqueue";
            let fd = if is_kqueue {
                call(
                    &mut ctx,
                    nr::GUARDED_KQUEUE_NP,
                    [at, attributes, 0, 0, 0, 0, 0, 0],
                )
                .unwrap()
                .0 as i32
            } else {
                let path = std::env::temp_dir().join(format!(
                    "rax-guard-info-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
                let file = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .open(&path)
                    .unwrap();
                std::fs::remove_file(path).unwrap();
                let open = crate::user::darwin::fd::OpenFile::host(file.into(), io::O_RDWR, None);
                let fd = ctx
                    .proc
                    .fds
                    .install_with(Arc::new(open), true, true, 9, 256)
                    .unwrap();
                ctx.proc.fds.get_mut(fd).unwrap().guard = Some(DescriptorGuard {
                    cookie: COOKIE,
                    attributes: attributes as u32,
                });
                fd
            };
            let expected = &native["record"];
            let bytes = expected["bytes"].as_u64().unwrap();
            let pid = ctx.proc.pid;
            assert_eq!(
                bsd::procinfo::proc_info(
                    &mut ctx,
                    3,
                    pid,
                    if is_kqueue { 7 } else { 1 },
                    fd as u64,
                    at + 64,
                    bytes as i32
                ),
                Ok(Rv::one(bytes)),
                "{abi:?}/{native}"
            );
            for (offset, field) in [
                (0, "open_flags"),
                (4, "status"),
                (16, "type"),
                (20, "guard_flags"),
            ] {
                assert_eq!(
                    u64::from(ctx.read_u32(at + 64 + offset).unwrap()),
                    expected[field].as_u64().unwrap(),
                    "{abi:?}/{field}/{native}"
                );
            }
            assert_eq!(
                call(
                    &mut ctx,
                    nr::GUARDED_CLOSE_NP,
                    [fd as u64, at, 0, 0, 0, 0, 0, 0]
                ),
                Ok(Rv::one(0))
            );
        }
    }
}

#[test]
fn guarded_fd_replays_592_native_write_validation_cases_on_both_guest_abis() {
    let inputs = [
        (
            DarwinAbi::Arm64,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/darwin/native-guarded-fd/edge-records-arm64-v3.json"
            )),
        ),
        (
            DarwinAbi::X86_64,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/darwin/native-guarded-fd/edge-records-x86_64-v3.json"
            )),
        ),
    ];
    let mut replayed = 0;
    for (abi, input) in inputs {
        let records: serde_json::Value = serde_json::from_str(input).unwrap();
        assert_eq!(records.as_array().unwrap().len(), 296);
        let mut process = bounded_tests::process(abi);
        let (_, mut thread) = process.proc.threads.pop_first().unwrap();
        let at = thread.cpu.sp() - 1024;
        let mut ctx = Ctx {
            proc: &mut process.proc,
            thread: &mut thread,
            nr: 0,
            pc: 0x1_0000_1000,
        };
        let file = ctx.proc.fds.file(1).unwrap();
        let fd = ctx.proc.fds.install(file, true, 9, 256).unwrap();
        for native in records.as_array().unwrap() {
            let fields = native["input"].as_array().unwrap();
            let operation = fields[0].as_str().unwrap();
            let attributes = fields[1].as_u64().unwrap() as u32;
            let readonly = fields[2].as_u64().unwrap() != 0;
            let target = if fields[3].as_u64().unwrap() != 0 {
                -1
            } else {
                fd
            };
            let mode = fields[4].as_u64().unwrap();
            let argument = fields[5].as_i64().unwrap();
            ctx.proc.guard_ast = None;
            let slot = ctx.proc.fds.get_mut(fd).unwrap();
            slot.guard = Some(DescriptorGuard {
                cookie: COOKIE,
                attributes,
            });
            *slot.file.flags.lock().unwrap() = if readonly { io::O_RDONLY } else { io::O_RDWR };
            ctx.write_u64(at, COOKIE).unwrap();
            ctx.write_u64(at + 8, OTHER).unwrap();
            ctx.write(at + 128, b"xy").unwrap();
            let vectors = if operation == "large-vector" {
                [at + 128, i32::MAX as u64, at + 129, 1]
            } else {
                [at + 128, 1, at + 129, 1]
            };
            for (index, value) in vectors.into_iter().enumerate() {
                ctx.write_u64(at + 32 + index as u64 * 8, value).unwrap();
            }
            let pointer = match mode {
                0 => at,
                1 => at + 8,
                2 => 0,
                3 => 1,
                _ => unreachable!(),
            };
            let fd_word = target as i64 as u64;
            let result = if operation == "scalar" {
                let length = if argument == 0 {
                    1
                } else {
                    i32::MAX as u64 + 1
                };
                call(
                    &mut ctx,
                    nr::GUARDED_WRITE_NP,
                    [fd_word, pointer, at + 128, length, 0, 0, 0, 0],
                )
            } else {
                let address = if operation.starts_with("bad-") {
                    1
                } else {
                    at + 32
                };
                let count = if operation == "large-vector" {
                    2
                } else {
                    argument as u64
                };
                if operation.contains("ordinary") {
                    call(
                        &mut ctx,
                        nr::WRITEV,
                        [fd_word, address, count, 0, 0, 0, 0, 0],
                    )
                } else {
                    call(
                        &mut ctx,
                        nr::GUARDED_WRITEV_NP,
                        [fd_word, pointer, address, count, 0, 0, 0, 0],
                    )
                }
            };
            let output: Vec<serde_json::Value> = native["stdout"]
                .as_str()
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect();
            if native["exit_code"].as_i64() == Some(-9) {
                assert_eq!(result, Err(Errno::EPERM), "{abi:?}/{fields:?}");
                let actual = ctx.proc.guard_ast.take().expect("fatal descriptor guard");
                if let Some(packet) = output.iter().find(|row| row["kind"] == "guard-exception") {
                    let code = u64::from_str_radix(
                        packet["code"].as_str().unwrap().trim_start_matches("0x"),
                        16,
                    )
                    .unwrap();
                    assert_eq!(actual.code, (code & 0xffff_ffff_0000_0000) | fd as u64);
                    assert_eq!(actual.subcode, COOKIE);
                    assert!(actual.sticky);
                }
            } else {
                let expected = output.iter().find(|row| row["kind"] == operation).unwrap();
                let value = expected["result"].as_i64().unwrap();
                let expected = if value < 0 {
                    Err(Errno(expected["errno"].as_i64().unwrap() as i32))
                } else {
                    Ok(Rv::one(value as u64))
                };
                assert_eq!(result, expected, "{abi:?}/{fields:?}");
                assert!(ctx.proc.guard_ast.is_none());
            }
            replayed += 1;
        }
    }
    assert_eq!(replayed, 592);
}

#[test]
fn guarded_fd_open_captures_guard_and_forces_native_initial_flags() {
    for abi in [DarwinAbi::Arm64, DarwinAbi::X86_64] {
        let mut process = bounded_tests::process(abi);
        let (_, mut thread) = process.proc.threads.pop_first().unwrap();
        let at = thread.cpu.sp() - 512;
        let mut ctx = Ctx {
            proc: &mut process.proc,
            thread: &mut thread,
            nr: 0,
            pc: 0x1_0000_1000,
        };
        ctx.write(at, b"/bounded-test\0").unwrap();
        ctx.write_u64(at + 64, COOKIE).unwrap();
        for attributes in 0..64 {
            let result = call(
                &mut ctx,
                nr::GUARDED_OPEN_NP,
                [
                    at,
                    at + 64,
                    attributes,
                    u64::from(io::O_CLOEXEC),
                    0,
                    0,
                    0,
                    0,
                ],
            );
            if attributes & 2 == 0 || attributes & !31 != 0 {
                assert_eq!(result, Err(Errno::EINVAL));
                continue;
            }
            let fd = result.unwrap().0 as i32;
            let slot = ctx.proc.fds.get(fd).unwrap();
            assert_eq!(
                slot.guard,
                Some(DescriptorGuard {
                    cookie: COOKIE,
                    attributes: attributes as u32
                })
            );
            assert!(slot.cloexec && slot.clofork);
            assert_eq!(
                call(
                    &mut ctx,
                    nr::GUARDED_CLOSE_NP,
                    [fd as u64, at + 64, 0, 0, 0, 0, 0, 0]
                ),
                Ok(Rv::one(0))
            );
            assert!(ctx.proc.fds.get(fd).is_err());
        }
        assert_eq!(
            call(&mut ctx, nr::GUARDED_OPEN_NP, [1, 1, 31, 0, 0, 0, 0, 0]),
            Err(Errno::EINVAL)
        );
        assert_eq!(
            call(
                &mut ctx,
                nr::GUARDED_OPEN_NP,
                [1, 1, 31, u64::from(io::O_CLOEXEC), 0, 0, 0, 0]
            ),
            Err(Errno::EFAULT)
        );
        assert_eq!(
            call(
                &mut ctx,
                nr::GUARDED_CLOSE_NP,
                [u64::MAX, 1, 0, 0, 0, 0, 0, 0]
            ),
            Err(Errno::EFAULT)
        );
        assert_eq!(
            call(
                &mut ctx,
                nr::GUARDED_CLOSE_NP,
                [u64::MAX, at + 64, 0, 0, 0, 0, 0, 0]
            ),
            Err(Errno::EBADF)
        );
    }
}

#[test]
fn guarded_fd_wrong_cookie_retains_slot_and_change_returns_old_flags_before_error() {
    for abi in [DarwinAbi::Arm64, DarwinAbi::X86_64] {
        let mut process = bounded_tests::process(abi);
        let (_, mut thread) = process.proc.threads.pop_first().unwrap();
        let at = thread.cpu.sp() - 512;
        let mut ctx = Ctx {
            proc: &mut process.proc,
            thread: &mut thread,
            nr: 0,
            pc: 0x1_0000_1000,
        };
        ctx.write_u64(at, COOKIE).unwrap();
        ctx.write_u64(at + 8, OTHER).unwrap();
        let file = ctx.proc.fds.file(1).unwrap();
        let fd = ctx.proc.fds.install(file, false, 9, 256).unwrap() as u64;
        ctx.write_u32(at + 16, 0).unwrap();
        assert_eq!(
            call(
                &mut ctx,
                nr::CHANGE_FDGUARD_NP,
                [fd, 0, 0, at, 3, at + 16, 0, 0]
            ),
            Ok(Rv::one(0))
        );
        assert_eq!(ctx.read_u32(at + 16).unwrap(), 0);
        assert_eq!(
            call(
                &mut ctx,
                nr::GUARDED_CLOSE_NP,
                [fd, at + 8, 0, 0, 0, 0, 0, 0]
            ),
            Err(Errno::EPERM)
        );
        assert!(ctx.proc.guard_ast.is_none());
        ctx.write_u32(at + 16, 0).unwrap();
        assert_eq!(
            call(
                &mut ctx,
                nr::CHANGE_FDGUARD_NP,
                [fd, at + 8, 3, 0, 0, at + 16, 0, 0]
            ),
            Err(Errno::EPERM)
        );
        assert_eq!(ctx.read_u32(at + 16).unwrap(), 3);
        assert_eq!(
            call(&mut ctx, nr::FCNTL, [fd, 2, 1, 0, 0, 0, 0, 0]),
            Ok(Rv::one(0))
        );
        assert!(ctx.proc.fds.get(fd as i32).unwrap().clofork);
        ctx.write_u32(at + 16, 0).unwrap();
        assert_eq!(
            call(
                &mut ctx,
                nr::CHANGE_FDGUARD_NP,
                [fd, at, 3, at + 8, 2, at + 16, 0, 0]
            ),
            Ok(Rv::one(0))
        );
        let slot = ctx.proc.fds.get(fd as i32).unwrap();
        assert!(slot.cloexec && !slot.clofork);
        assert_eq!(slot.guard.unwrap().cookie, OTHER);
        let mut child = crate::user::darwin::exec::fdt_fork(&ctx.proc.fds, false);
        assert!(child.get(fd as i32).unwrap().guard.is_none());
        assert!(
            crate::user::darwin::exec::fdt_fork(&ctx.proc.fds, true)
                .get(fd as i32)
                .is_err()
        );
        child.close_on_exec();
        assert!(child.get(fd as i32).is_err());
        ctx.write_u32(at + 16, 0).unwrap();
        assert_eq!(
            call(
                &mut ctx,
                nr::CHANGE_FDGUARD_NP,
                [fd, at + 8, 2, 0, 0, at + 16, 0, 0]
            ),
            Ok(Rv::one(0))
        );
        let slot = ctx.proc.fds.get(fd as i32).unwrap();
        assert!(slot.guard.is_none() && !slot.cloexec && !slot.clofork);
        assert_eq!(
            call(&mut ctx, nr::CLOSE, [fd, 0, 0, 0, 0, 0, 0, 0]),
            Ok(Rv::one(0))
        );
    }
}

#[test]
fn guarded_fd_close_violation_terminates_only_the_guest_on_both_abis() {
    for abi in [DarwinAbi::Arm64, DarwinAbi::X86_64] {
        let mut process = bounded_tests::process(abi);
        let (tid, mut thread) = process.proc.threads.pop_first().unwrap();
        let at = thread.cpu.sp() - 512;
        let fd = {
            let mut ctx = Ctx {
                proc: &mut process.proc,
                thread: &mut thread,
                nr: 0,
                pc: 0x1_0000_1000,
            };
            ctx.write(at, b"/bounded-test\0").unwrap();
            ctx.write_u64(at + 64, COOKIE).unwrap();
            call(
                &mut ctx,
                nr::GUARDED_OPEN_NP,
                [at, at + 64, 3, u64::from(io::O_CLOEXEC), 0, 0, 0, 0],
            )
            .unwrap()
            .0
        };
        let code = match abi {
            DarwinAbi::Arm64 => [
                0xd280_0000u32 | ((fd as u32) << 5),
                0xd280_00d0,
                0xd400_1001,
                0xd280_04a0,
                0xd280_0030,
                0xd400_1001,
            ]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>(),
            DarwinAbi::X86_64 => [
                vec![0xb8, 6, 0, 0, 2, 0xbf],
                (fd as u32).to_le_bytes().to_vec(),
                vec![0x0f, 0x05, 0xb8, 1, 0, 0, 2, 0xbf, 37, 0, 0, 0, 0x0f, 0x05],
            ]
            .concat(),
        };
        process.proc.space.write_raw(0x1_0000_1000, &code).unwrap();
        thread.cpu.set_pc(0x1_0000_1000);
        process.proc.threads.insert(tid, thread);
        let mut terminal = None;
        for _ in 0..100 {
            if let RunStatus::Complete(status) = process.run_slice(1, &AtomicBool::new(false)) {
                terminal = Some(status);
                break;
            }
        }
        assert!(
            matches!(
                terminal,
                Some(ExitStatus::Signaled {
                    signo: 9,
                    core: false,
                    ..
                })
            ),
            "{abi:?}: {terminal:?}"
        );
    }
}
