//! Actual HLE origins and guest calling conventions, all three guest ABIs.

use super::*;
use crate::user::mm::PAGE_SIZE;
use crate::user::windows::arch::WinArch;
use crate::user::windows::dll::crt::tests::{area, int, invoke, run, void};
use crate::user::windows::fs::{FileIdentity, FileLifetime};
use crate::user::windows::hle::{ApiResult, Flow, Value};
use crate::user::windows::memory::{Mem, mem, prot};
use crate::user::windows::objects::{FileObj, Object};
use std::io::{Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

pub(super) struct File(pub(super) PathBuf);
impl File {
    pub(super) fn new(c: &mut Ctx, contents: &[u8]) -> (Self, u64) {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let (path, mut host) = loop {
            let path = std::env::temp_dir().join(format!(
                "rax-crt-stdio-unit-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(host) => break (path, host),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("owned test file: {error}"),
            }
        };
        host.write_all(contents).unwrap();
        host.seek(SeekFrom::Start(0)).unwrap();
        let identity = FileIdentity::of(&path, &host.metadata().unwrap()).unwrap();
        let handle = u64::from(c.p.objects.insert(Object::File(FileObj {
            host: Some(host),
            host_path: path.clone(),
            path: "C:\\owned-unit.dat".into(),
            access: 0xC000_0000,
            share: 7,
            lifetime: Arc::new(FileLifetime::new(identity)),
            null: false,
            append: false,
            delete_on_close: false,
            directory: false,
            overlapped: false,
        })));
        (Self(path), handle)
    }
    pub(super) fn bytes(&self) -> Vec<u8> {
        std::fs::read(&self.0).unwrap()
    }
}
impl Drop for File {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

pub(super) fn attach(
    c: &mut Ctx,
    kind: RuntimeKind,
    handle: u64,
    flags: u64,
    mode: &[u8],
) -> (i32, u64) {
    let fd = int(invoke(c, kind, "_open_osfhandle", &[handle, flags])) as i32;
    assert!(fd >= 3);
    let at = area(c);
    c.mem().put_cstr(at, mode).unwrap();
    let file = int(invoke(c, kind, "_fdopen", &[fd as u32 as u64, at]));
    assert_ne!(file, 0);
    (fd, file)
}

pub(super) fn clobber_formals(c: &mut Ctx, count: usize) {
    for index in 0..count {
        match c.arch() {
            WinArch::X86 => c.mem().w32(c.entry_sp + 4 + index as u64 * 4, 0).unwrap(),
            WinArch::X64 if index < 4 => c.t.cpu.set_gpr([1, 2, 8, 9][index], 0),
            WinArch::X64 => c.mem().w64(c.entry_sp + 8 + index as u64 * 8, 0).unwrap(),
            WinArch::Arm64 => c.t.cpu.set_gpr(index, 0),
        }
    }
}

pub(super) fn retry(
    result: ApiResult,
) -> (
    crate::user::windows::memory::MemFault,
    crate::user::windows::hle::Cont,
) {
    match result.unwrap() {
        Flow::RetryFault { fault, retry } => (fault, retry),
        _ => panic!("captured fault"),
    }
}

#[test]
fn real_user_buffer_rounding_full_flush_and_close_preserve_caller_storage() {
    run(|c| {
        for kind in [RuntimeKind::Msvcrt, RuntimeKind::Ucrt] {
            let (host, handle) = File::new(c, &[]);
            let (fd, file) = attach(c, kind, handle, (O_BINARY | 2) as u64, b"wb");
            let memory = area(c);
            c.mem().wr(memory, &[0xAA; 32]).unwrap();
            c.mem().wr(memory + 64, b"abcdef").unwrap();
            assert_eq!(int(invoke(c, kind, "setvbuf", &[file, memory, 0x40, 7])), 0);
            assert_eq!(
                int(invoke(c, kind, "fwrite", &[memory + 64, 1, 5, file])),
                5
            );
            assert!(host.bytes().is_empty());
            assert_eq!(c.mem().bytes(memory, 6).unwrap(), b"abcde\xAA");
            assert_eq!(
                int(invoke(c, kind, "fwrite", &[memory + 69, 1, 1, file])),
                1
            );
            assert_eq!(host.bytes(), b"abcdef");
            assert_eq!(int(invoke(c, kind, "fclose", &[file])), 0);
            assert!(c.p.objects.id(handle).is_none());
            assert!(state(c, kind).unwrap().descriptor(fd).is_err());
            c.mem().w8(memory, 0xCC).unwrap();
            assert_eq!(c.mem().u8(memory).unwrap(), 0xCC);
        }
    });
}

#[test]
fn fdopen_w_mode_attaches_without_truncating_and_append_moves_to_end() {
    run(|c| {
        for kind in [RuntimeKind::Msvcrt, RuntimeKind::Ucrt] {
            let (host, handle) = File::new(c, b"old");
            let (_, file) = attach(c, kind, handle, (O_BINARY | 2) as u64, b"ab");
            assert_eq!(host.bytes(), b"old");
            let data = area(c);
            c.mem().w8(data, b'!').unwrap();
            assert_eq!(int(invoke(c, kind, "fwrite", &[data, 1, 1, file])), 1);
            assert_eq!(int(invoke(c, kind, "fclose", &[file])), 0);
            assert_eq!(host.bytes(), b"old!");
            let (host, handle) = File::new(c, b"old");
            let (_, file) = attach(c, kind, handle, (O_BINARY | 2) as u64, b"wb");
            assert_eq!(host.bytes(), b"old");
            assert_eq!(int(invoke(c, kind, "fclose", &[file])), 0);
            assert_eq!(host.bytes(), b"old");
        }
    });
}

#[test]
fn read_buffer_is_retained_by_fflush_and_eof_is_set_only_after_attempt_past_end() {
    run(|c| {
        for kind in [RuntimeKind::Msvcrt, RuntimeKind::Ucrt] {
            let (host, handle) = File::new(c, b"ABC");
            let (_, file) = attach(c, kind, handle, O_BINARY as u64, b"rb");
            let data = area(c);
            assert_eq!(int(invoke(c, kind, "fread", &[data, 1, 1, file])), 1);
            let before = state(c, kind).unwrap().stream(file).unwrap();
            assert_eq!(before.read_end - before.read_cursor, 2);
            assert_eq!(int(invoke(c, kind, "fflush", &[file])), 0);
            let after = state(c, kind).unwrap().stream(file).unwrap();
            assert_eq!(after.read_cursor, before.read_cursor);
            assert_eq!(after.read_end, before.read_end);
            assert_eq!(after.last, storage::Direction::Read);
            assert_eq!(int(invoke(c, kind, "fread", &[data + 1, 1, 2, file])), 2);
            assert_eq!(c.mem().bytes(data, 3).unwrap(), b"ABC");
            assert_eq!(int(invoke(c, kind, "feof", &[file])), 0);
            assert_eq!(int(invoke(c, kind, "fread", &[data, 1, 1, file])), 0);
            assert_eq!(int(invoke(c, kind, "feof", &[file])), 1);
            void(invoke(c, kind, "clearerr", &[file]));
            assert_eq!(int(invoke(c, kind, "feof", &[file])), 0);
            assert_eq!(int(invoke(c, kind, "ferror", &[file])), 0);
            assert_eq!(int(invoke(c, kind, "fclose", &[file])), 0);
            assert_eq!(host.bytes(), b"ABC");
        }
    });
}

#[test]
fn text_read_handles_crlf_chunk_edge_bare_cr_and_ctrl_z_without_binary_translation() {
    run(|c| {
        for kind in [RuntimeKind::Msvcrt, RuntimeKind::Ucrt] {
            let mut raw = vec![b'a'; 255];
            raw.extend_from_slice(b"\r\nB\rX\r\x1aQ");
            let (host, handle) = File::new(c, &raw);
            let fd = int(invoke(c, kind, "_open_osfhandle", &[handle, O_TEXT as u64]));
            let data = area(c);
            let a = int(invoke(c, kind, "_read", &[fd, data, 256]));
            assert_eq!(a, 256);
            let b = int(invoke(c, kind, "_read", &[fd, data + a, 256]));
            assert_eq!(b, 4);
            let mut expected = vec![b'a'; 255];
            expected.extend_from_slice(b"\nB\rX\r");
            assert_eq!(c.mem().bytes(data, expected.len()).unwrap(), expected);
            assert_eq!(int(invoke(c, kind, "_read", &[fd, data, 1])), 0);
            assert_eq!(int(invoke(c, kind, "_close", &[fd])), 0);
            assert_eq!(host.bytes(), raw);
        }
    });
}

#[test]
fn zero_stdio_requests_leave_buffer_and_flags_unchanged() {
    run(|c| {
        let kind = RuntimeKind::Ucrt;
        let streams = state(c, kind).unwrap();
        let file = streams.standard_file(1).unwrap();
        let before = streams.stream(file).unwrap();
        assert_eq!(int(invoke(c, kind, "fwrite", &[0, 0, u64::MAX, file])), 0);
        assert_eq!(int(invoke(c, kind, "fread", &[0, 1, 0, 0])), 0);
        let after = streams.stream(file).unwrap();
        assert_eq!(after.revision, before.revision);
        assert_eq!(after.buffer, before.buffer);
        assert!(!after.io_started);
    });
}

#[test]
fn unbuffered_write_fault_retains_host_prefix_and_captured_formals() {
    run(|c| {
        for kind in [RuntimeKind::Msvcrt, RuntimeKind::Ucrt] {
            let (host, handle) = File::new(c, &[]);
            let (_, file) = attach(c, kind, handle, (O_BINARY | 2) as u64, b"wb");
            assert_eq!(
                int(invoke(c, kind, "setvbuf", &[file, u64::MAX, 4, u64::MAX])),
                0
            );
            let base =
                c.p.vm
                    .allocate(
                        None,
                        PAGE_SIZE * 2,
                        mem::RESERVE | mem::COMMIT,
                        prot::READWRITE,
                    )
                    .unwrap()
                    .0;
            let data = base + PAGE_SIZE - 256;
            let expected: Vec<_> = (0..768).map(|i| (i * 7 + 3) as u8).collect();
            c.mem().wr(data, &expected).unwrap();
            c.p.vm
                .protect(base + PAGE_SIZE, PAGE_SIZE, prot::NOACCESS)
                .unwrap();
            let (fault, then) = retry(invoke(c, kind, "fwrite", &[data, 1, 768, file]));
            assert!(!fault.write);
            assert_eq!(fault.addr, base + PAGE_SIZE);
            assert_eq!(host.bytes(), expected[..256]);
            c.mem().wr(data, &[0xCC; 256]).unwrap();
            c.p.vm
                .protect(base + PAGE_SIZE, PAGE_SIZE, prot::READWRITE)
                .unwrap();
            clobber_formals(c, 4);
            assert_eq!(int(then(c, 0)), 768);
            assert_eq!(host.bytes(), expected);
            assert_eq!(int(invoke(c, kind, "fclose", &[file])), 0);
        }
    });
}

#[test]
fn read_fault_preserves_consumed_file_offset_and_overwritten_output_witness() {
    run(|c| {
        for kind in [RuntimeKind::Msvcrt, RuntimeKind::Ucrt] {
            let expected: Vec<_> = (0..768).map(|i| (i * 7 + 3) as u8).collect();
            let (host, handle) = File::new(c, &expected);
            let fd = int(invoke(
                c,
                kind,
                "_open_osfhandle",
                &[handle, O_BINARY as u64],
            ));
            let base =
                c.p.vm
                    .allocate(
                        None,
                        PAGE_SIZE * 2,
                        mem::RESERVE | mem::COMMIT,
                        prot::READWRITE,
                    )
                    .unwrap()
                    .0;
            let data = base + PAGE_SIZE - 256;
            c.p.vm
                .protect(base + PAGE_SIZE, PAGE_SIZE, prot::READONLY)
                .unwrap();
            let (fault, then) = retry(invoke(c, kind, "_read", &[fd, data, 768]));
            assert!(fault.write);
            assert_eq!(fault.addr, base + PAGE_SIZE);
            assert_eq!(c.mem().bytes(data, 256).unwrap(), expected[..256]);
            c.mem().wr(data, &[0xCC; 256]).unwrap();
            c.p.vm
                .protect(base + PAGE_SIZE, PAGE_SIZE, prot::READWRITE)
                .unwrap();
            clobber_formals(c, 3);
            assert_eq!(int(then(c, 0)), 768);
            assert_eq!(c.mem().bytes(data, 256).unwrap(), [0xCC; 256]);
            assert_eq!(c.mem().bytes(data + 256, 512).unwrap(), expected[256..]);
            assert_eq!(int(invoke(c, kind, "_close", &[fd])), 0);
            assert_eq!(host.bytes(), expected);
        }
    });
}

#[test]
fn unicode_even_byte_requests_reject_before_buffer_or_host_effects_and_odd_ones_validate() {
    run(|c| {
        let kind = RuntimeKind::Ucrt;
        let (host, handle) = File::new(c, &[]);
        let (fd, file) = attach(c, kind, handle, (O_BINARY | 2) as u64, b"wb");
        assert_eq!(
            int(invoke(c, kind, "_setmode", &[fd as u64, O_U8TEXT as u64])),
            O_BINARY as u64
        );
        let data = area(c);
        c.mem().wr(data, b"AB").unwrap();
        let before = state(c, kind).unwrap().stream(file).unwrap();
        assert!(matches!(
            invoke(c, kind, "fwrite", &[data, 1, 2, file]),
            Err(ApiErr::Unimplemented(_))
        ));
        let after = state(c, kind).unwrap().stream(file).unwrap();
        assert_eq!(after.buffer, before.buffer);
        assert_eq!(after.revision, before.revision);
        assert!(host.bytes().is_empty());
        int(invoke(c, kind, "_set_invalid_parameter_handler", &[0x1234]));
        let result = invoke(c, kind, "fwrite", &[data, 1, 1, file]).unwrap();
        match result {
            Flow::CallChecked { target, args, then } => {
                assert_eq!(target, 0x1234);
                assert_eq!(args, [0; 5]);
                assert_eq!(int(then(c, 0)), 0);
            }
            _ => panic!("actual returning handler"),
        }
        assert!(host.bytes().is_empty());
        assert_eq!(int(invoke(c, kind, "fclose", &[file])), 0);
    });
}

#[test]
fn returning_invalid_handler_result_survives_errno_store_fault_without_reinvocation() {
    run(|c| {
        let kind = RuntimeKind::Ucrt;
        int(invoke(c, kind, "_set_invalid_parameter_handler", &[0x1234]));
        let cells = int(invoke(c, kind, "_errno", &[]));
        let then = match invoke(c, kind, "setvbuf", &[0, 0, 0, 2]).unwrap() {
            Flow::CallChecked { then, .. } => then,
            _ => panic!("checked handler"),
        };
        let page = cells & !(PAGE_SIZE - 1);
        c.p.vm.protect(page, PAGE_SIZE, prot::READONLY).unwrap();
        let (fault, retry) = retry(then(c, 0));
        assert!(fault.write);
        assert_eq!(fault.addr, cells);
        c.p.vm.protect(page, PAGE_SIZE, prot::READWRITE).unwrap();
        assert_eq!(int(retry(c, 0)), u32::MAX as u64);
        assert_eq!(c.mem().u32(cells).unwrap(), 22);
    });
}

#[test]
fn same_stream_reconfiguration_during_fault_repair_is_rejected_without_prefix_replay() {
    run(|c| {
        let kind = RuntimeKind::Ucrt;
        let (host, handle) = File::new(c, &[]);
        let (_, file) = attach(c, kind, handle, (O_BINARY | 2) as u64, b"wb");
        int(invoke(c, kind, "setvbuf", &[file, 0, 4, 0]));
        let base =
            c.p.vm
                .allocate(
                    None,
                    PAGE_SIZE * 2,
                    mem::RESERVE | mem::COMMIT,
                    prot::READWRITE,
                )
                .unwrap()
                .0;
        let data = base + PAGE_SIZE - 256;
        c.mem().wr(data, &[7; 512]).unwrap();
        c.p.vm
            .protect(base + PAGE_SIZE, PAGE_SIZE, prot::NOACCESS)
            .unwrap();
        let (_, then) = retry(invoke(c, kind, "fwrite", &[data, 1, 512, file]));
        assert_eq!(host.bytes(), [7; 256]);
        void(invoke(c, kind, "clearerr", &[file]));
        c.p.vm
            .protect(base + PAGE_SIZE, PAGE_SIZE, prot::READWRITE)
            .unwrap();
        assert!(matches!(then(c, 0), Err(ApiErr::Unimplemented(_))));
        assert_eq!(host.bytes(), [7; 256]);
        int(invoke(c, kind, "fclose", &[file]));
    });
}

#[test]
fn low_level_text_read_budgets_raw_bytes_without_refilling_contracted_output() {
    run(|c| {
        for kind in [RuntimeKind::Msvcrt, RuntimeKind::Ucrt] {
            let (host, handle) = File::new(c, b"\r\nX");
            let fd = int(invoke(c, kind, "_open_osfhandle", &[handle, O_TEXT as u64]));
            let output = area(c);
            assert_eq!(int(invoke(c, kind, "_read", &[fd, output, 2])), 1);
            assert_eq!(c.mem().u8(output).unwrap(), b'\n');
            let position = match c.p.objects.get_mut(handle).unwrap() {
                Object::File(file) => file.host.as_mut().unwrap().stream_position().unwrap(),
                _ => panic!("host file"),
            };
            assert_eq!(position, 2);
            assert_eq!(int(invoke(c, kind, "_read", &[fd, output, 1])), 1);
            assert_eq!(c.mem().u8(output).unwrap(), b'X');
            int(invoke(c, kind, "_close", &[fd]));
            assert_eq!(host.bytes(), b"\r\nX");
        }
    });
}

#[test]
fn append_only_reduced_handle_grant_cannot_overwrite_shared_file_cursor() {
    run(|c| {
        for kind in [RuntimeKind::Msvcrt, RuntimeKind::Ucrt] {
            let (host, handle) = File::new(c, b"old");
            let id = c.p.objects.id(handle).unwrap();
            let reduced = u64::from(c.p.objects.open_access(id, false, 4).unwrap());
            let fd = int(invoke(
                c,
                kind,
                "_open_osfhandle",
                &[reduced, (O_BINARY | 1) as u64],
            ));
            let source = area(c);
            c.mem().w8(source, b'!').unwrap();
            assert_eq!(int(invoke(c, kind, "_write", &[fd, source, 1])), 1);
            assert_eq!(host.bytes(), b"old!");
            assert_eq!(int(invoke(c, kind, "_close", &[fd])), 0);
            assert!(c.p.objects.id(handle).is_some());
            crate::user::windows::dll::finish_close(c.p.objects.close(handle).unwrap()).unwrap();
        }
    });
}

#[test]
fn get_osfhandle_error_returns_guest_intptr_minus_one_on_every_abi() {
    run(|c| {
        let kind = RuntimeKind::Ucrt;
        int(invoke(c, kind, "_set_invalid_parameter_handler", &[0x1234]));
        let then = match invoke(c, kind, "_get_osfhandle", &[u32::MAX as u64]).unwrap() {
            Flow::CallChecked { then, .. } => then,
            _ => panic!("checked invalid handler"),
        };
        assert_eq!(int(then(c, 0)), c.arch().ptr(u64::MAX));
        let cells = int(invoke(c, kind, "_errno", &[]));
        assert_eq!(c.mem().u32(cells).unwrap(), 9);
    });
}

#[test]
fn text_output_ctrl_z_terminates_this_request_at_exact_logical_item_frontier() {
    run(|c| {
        for kind in [RuntimeKind::Msvcrt, RuntimeKind::Ucrt] {
            for marker in [0usize, 1, 255, 256] {
                for buffered in [false, true] {
                    let (host, handle) = File::new(c, &[]);
                    let (_, file) = attach(c, kind, handle, (O_TEXT | 2) as u64, b"wt");
                    if !buffered {
                        int(invoke(c, kind, "setvbuf", &[file, 0, 4, 0]));
                    }
                    let data = area(c);
                    let mut bytes = vec![b'A'; 512];
                    bytes[marker] = 0x1A;
                    c.mem().wr(data, &bytes).unwrap();
                    assert_eq!(
                        int(invoke(c, kind, "fwrite", &[data, 2, 256, file])),
                        (marker / 2) as u64
                    );
                    c.mem().w8(data, b'!').unwrap();
                    assert_eq!(int(invoke(c, kind, "fwrite", &[data, 1, 1, file])), 1);
                    int(invoke(c, kind, "fclose", &[file]));
                    let mut expected = vec![b'A'; marker];
                    expected.push(b'!');
                    assert_eq!(host.bytes(), expected);
                }
                let (host, handle) = File::new(c, &[]);
                let fd = int(invoke(
                    c,
                    kind,
                    "_open_osfhandle",
                    &[handle, (O_TEXT | 1) as u64],
                ));
                let data = area(c);
                let mut bytes = vec![b'A'; 512];
                bytes[marker] = 0x1A;
                c.mem().wr(data, &bytes).unwrap();
                assert_eq!(
                    int(invoke(c, kind, "_write", &[fd, data, 512])),
                    marker as u64
                );
                assert_eq!(host.bytes(), vec![b'A'; marker]);
                int(invoke(c, kind, "_close", &[fd]));
            }
        }
    });
}

#[test]
fn host_read_failure_preserves_cached_lookahead_and_sets_sticky_stream_error() {
    run(|c| {
        for kind in [RuntimeKind::Msvcrt, RuntimeKind::Ucrt] {
            let (host, handle) = File::new(c, b"unused");
            let (fd, file) = attach(c, kind, handle, (O_TEXT | 2) as u64, b"rt");
            // Explicit host-failure injection: the logical object retains its
            // guest read grant, but its host File is replaced by a write-only File.
            match c.p.objects.get_mut(handle).unwrap() {
                Object::File(file) => {
                    file.host = Some(
                        std::fs::OpenOptions::new()
                            .write(true)
                            .open(&host.0)
                            .unwrap(),
                    )
                }
                _ => panic!("host file"),
            }
            let s = state(c, kind).unwrap();
            let mut d = s.descriptor(fd).unwrap();
            d.lookahead = Some(b'X');
            s.publish_descriptor(fd, d.generation, d).unwrap();
            let output = area(c);
            assert_eq!(int(invoke(c, kind, "fread", &[output, 1, 2, file])), 0);
            assert_eq!(s.descriptor(fd).unwrap().lookahead, Some(b'X'));
            assert_eq!(int(invoke(c, kind, "ferror", &[file])), 1);
            assert_eq!(int(invoke(c, kind, "feof", &[file])), 0);
            void(invoke(c, kind, "clearerr", &[file]));
            assert_eq!(int(invoke(c, kind, "ferror", &[file])), 0);
            int(invoke(c, kind, "fclose", &[file]));
        }
    });
}

#[test]
fn update_stream_can_write_after_eof_without_discarding_input_on_fflush() {
    run(|c| {
        for kind in [RuntimeKind::Msvcrt, RuntimeKind::Ucrt] {
            let (host, handle) = File::new(c, b"A");
            let (_, file) = attach(c, kind, handle, (O_BINARY | 2) as u64, b"r+b");
            let data = area(c);
            assert_eq!(int(invoke(c, kind, "fread", &[data, 1, 2, file])), 1);
            assert_eq!(int(invoke(c, kind, "feof", &[file])), 1);
            c.mem().w8(data, b'B').unwrap();
            assert_eq!(int(invoke(c, kind, "fwrite", &[data, 1, 1, file])), 1);
            int(invoke(c, kind, "fclose", &[file]));
            assert_eq!(host.bytes(), b"AB");
        }
    });
}

#[test]
fn low_level_text_internal_scratch_boundaries_do_not_expand_whole_call_raw_budget() {
    run(|c| {
        for kind in [RuntimeKind::Msvcrt, RuntimeKind::Ucrt] {
            for next in [b'\n', b'X'] {
                let mut bytes = vec![b'A'; 1024];
                bytes[255] = b'\r';
                bytes[256] = next;
                let (host, handle) = File::new(c, &bytes);
                let fd = int(invoke(c, kind, "_open_osfhandle", &[handle, O_TEXT as u64]));
                let output = area(c);
                let expected_count = if next == b'\n' { 767 } else { 768 };
                assert_eq!(
                    int(invoke(c, kind, "_read", &[fd, output, 768])),
                    expected_count
                );
                let position = match c.p.objects.get_mut(handle).unwrap() {
                    Object::File(file) => file.host.as_mut().unwrap().stream_position().unwrap(),
                    _ => panic!("file"),
                };
                assert_eq!(position, 768);
                let mut expected = bytes[..768].to_vec();
                if next == b'\n' {
                    expected.remove(255);
                }
                assert_eq!(c.mem().bytes(output, expected.len()).unwrap(), expected);
                int(invoke(c, kind, "_close", &[fd]));
                assert_eq!(host.bytes(), bytes);
            }
        }
    });
}

#[test]
fn mandatory_buffer_flush_failure_does_not_report_current_unwritten_items() {
    run(|c| {
        for kind in [RuntimeKind::Msvcrt, RuntimeKind::Ucrt] {
            for prior in [false, true] {
                let (host, handle) = File::new(c, &[]);
                let (_, file) = attach(c, kind, handle, (O_BINARY | 2) as u64, b"wb");
                int(invoke(c, kind, "setvbuf", &[file, 0, 0, 2]));
                let input = area(c);
                c.mem().wr(input, b"AB").unwrap();
                if prior {
                    assert_eq!(int(invoke(c, kind, "fwrite", &[input, 1, 1, file])), 1);
                }
                // Host-failure injection: retain logical guest write access but
                // replace the host File by a read-only handle before actual I/O.
                match c.p.objects.get_mut(handle).unwrap() {
                    Object::File(file) => file.host = Some(std::fs::File::open(&host.0).unwrap()),
                    _ => panic!("file"),
                }
                let count = if prior { 1 } else { 2 };
                assert_eq!(int(invoke(c, kind, "fwrite", &[input, 1, count, file])), 0);
                assert!(host.bytes().is_empty());
                assert_eq!(int(invoke(c, kind, "ferror", &[file])), 1);
                assert_eq!(int(invoke(c, kind, "feof", &[file])), 0);
                assert_eq!(
                    state(c, kind).unwrap().stream(file).unwrap().write_pending,
                    0
                );
                int(invoke(c, kind, "fclose", &[file]));
            }
        }
    });
}
