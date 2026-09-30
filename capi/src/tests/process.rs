//! Real PE processes exercised entirely through the stable C entry points.
use crate::*;
use rax_engine::user::windows::arch::WinArch;
use rax_engine::user::windows::context::RegContext;
use std::ptr;
use std::time::{Duration, Instant};

struct Owned(*mut Process);
impl Drop for Owned {
    fn drop(&mut self) {
        let _ = rax_process_close(self.0);
    }
}
fn fixtures() -> [(WinArch, &'static [u8]); 3] {
    [
        (
            WinArch::X86,
            include_bytes!("../../../tests/fixtures/user/windows/bin/x86/smoke.exe"),
        ),
        (
            WinArch::X64,
            include_bytes!("../../../tests/fixtures/user/windows/bin/x64/smoke.exe"),
        ),
        (
            WinArch::Arm64,
            include_bytes!("../../../tests/fixtures/user/windows/bin/arm64/smoke.exe"),
        ),
    ]
}
fn open(image: &[u8], options: &str) -> Owned {
    let mut p = ptr::null_mut();
    assert_eq!(
        rax_process_open_image(
            image.as_ptr(),
            image.len(),
            options.as_ptr().cast(),
            options.len(),
            ptr::null(),
            0,
            &mut p
        ),
        RaxStatus::Ok,
        "{}",
        error()
    );
    assert!(!p.is_null());
    Owned(p)
}
fn error() -> String {
    let mut required = 0;
    assert_eq!(
        rax_process_last_error(ptr::null_mut(), 0, &mut required),
        RaxStatus::Ok
    );
    let mut text = vec![0; required];
    assert_eq!(
        rax_process_last_error(text.as_mut_ptr().cast(), text.len(), &mut required),
        RaxStatus::Ok
    );
    String::from_utf8_lossy(&text[..required - 1]).into_owned()
}
fn info(p: &Owned) -> serde_json::Value {
    let mut required = 0;
    assert_eq!(
        rax_process_info_json(p.0, ptr::null_mut(), 0, &mut required),
        RaxStatus::Ok
    );
    let mut text = vec![0; required];
    assert_eq!(
        rax_process_info_json(p.0, text.as_mut_ptr().cast(), text.len(), &mut required),
        RaxStatus::Ok
    );
    serde_json::from_slice(&text[..required - 1]).unwrap()
}
fn context(p: &Owned, tid: u32) -> Vec<u8> {
    let mut required = 0;
    assert_eq!(
        rax_process_context_read(p.0, tid, ptr::null_mut(), 0, &mut required),
        RaxStatus::Ok
    );
    let mut bytes = vec![0; required];
    assert_eq!(
        rax_process_context_read(p.0, tid, bytes.as_mut_ptr(), bytes.len(), &mut required),
        RaxStatus::Ok
    );
    bytes
}
fn address(v: &serde_json::Value) -> u64 {
    u64::from_str_radix(v.as_str().unwrap().strip_prefix("0x").unwrap(), 16).unwrap()
}

#[test]
fn process_open_inspect_context_memory_run_and_repeat_all_abis() {
    for (arch, image) in fixtures() {
        let p = open(
            image,
            r#"{"memory_bytes":67108864,"slice_instructions":32}"#,
        );
        let before = info(&p);
        assert_eq!(before["architecture"], arch.name());
        assert_eq!(before["status"], "ready");
        assert_eq!(before["capabilities"]["host_filesystem"], false);
        let tid = before["threads"][0]["id"].as_u64().unwrap() as u32;
        let original = context(&p, tid);
        assert_eq!(original.len(), RegContext::size(arch));
        let mut edit = RegContext::from_bytes(arch, original.clone());
        edit.set_gpr(0, 0x1234);
        assert_eq!(
            rax_process_context_write(p.0, tid, edit.bytes().as_ptr(), edit.bytes().len()),
            RaxStatus::Ok
        );
        assert_eq!(info(&p)["threads"][0]["registers"][0], "0x1234");
        let current = context(&p, tid);
        let mut invalid = RegContext::from_bytes(arch, current.clone());
        invalid.set_flags(u32::MAX);
        assert_eq!(
            rax_process_context_write(p.0, tid, invalid.bytes().as_ptr(), invalid.bytes().len()),
            RaxStatus::Arg
        );
        assert_eq!(
            context(&p, tid),
            current,
            "failed context write must be atomic"
        );
        assert_eq!(
            rax_process_context_write(p.0, tid, original.as_ptr(), original.len()),
            RaxStatus::Ok
        );
        let base = address(&before["modules"][0]["base"]);
        let mut header = [0; 2];
        assert_eq!(
            rax_process_mem_read(p.0, base, header.as_mut_ptr(), 2),
            RaxStatus::Ok
        );
        assert_eq!(&header, b"MZ");
        assert_eq!(
            rax_process_mem_write(p.0, base, b"XX".as_ptr(), 2),
            RaxStatus::Perm
        );
        let sp = address(&before["threads"][0]["sp"]);
        let at = sp - 128;
        assert_eq!(
            rax_process_mem_write(p.0, at, b"data".as_ptr(), 4),
            RaxStatus::Ok
        );
        let mut bytes = [0; 4];
        assert_eq!(
            rax_process_mem_read(p.0, at, bytes.as_mut_ptr(), 4),
            RaxStatus::Ok
        );
        assert_eq!(&bytes, b"data");
        let mut result = RaxProcessResult::default();
        assert_eq!(rax_process_run(p.0, 0, 0, &mut result), RaxStatus::Ok);
        assert_eq!(result.reason, RAX_PROCESS_BUDGET);
        assert_eq!(result.turns_started, 0);
        assert_eq!(context(&p, tid), original);
        assert_eq!(
            rax_process_run(p.0, 100_000, 5_000_000, &mut result),
            RaxStatus::Ok
        );
        assert_eq!(result.reason, RAX_PROCESS_EXITED, "{}", info(&p));
        assert_eq!(result.exit_code, 0);
        assert_eq!(info(&p)["status"], "exited");
        assert_eq!(rax_process_run(p.0, 1, 0, &mut result), RaxStatus::Ok);
        assert_eq!(result.reason, RAX_PROCESS_EXITED);
        assert_eq!(result.turns_started, 0);
    }
}

#[test]
fn process_arguments_and_result_headers_fail_before_guest_mutation() {
    let image = fixtures()[1].1;
    for options in [
        r#"[]"#,
        r#"{"unknown":true}"#,
        r#"{"memory_bytes":8388609}"#,
        r#"{"slice_instructions":0}"#,
        r#"{"arguments":[1]}"#,
        r#"{"environment":{"X":1}}"#,
        r#"{"guest_path":"a\u0000b"}"#,
    ] {
        let mut handle = ptr::dangling_mut();
        assert_eq!(
            rax_process_open_image(
                image.as_ptr(),
                image.len(),
                options.as_ptr().cast(),
                options.len(),
                ptr::null(),
                0,
                &mut handle
            ),
            RaxStatus::Arg,
            "{options}"
        );
        assert!(handle.is_null());
        assert!(!error().is_empty());
    }
    let p = open(image, "{}");
    let before = info(&p);
    let mut result = RaxProcessResult::default();
    result.struct_size = 4;
    assert_eq!(rax_process_run(p.0, 1, 0, &mut result), RaxStatus::Arg);
    assert_eq!(result.struct_size, 4);
    result = RaxProcessResult::default();
    result.version = 99;
    assert_eq!(
        rax_process_run(p.0, 1, 0, &mut result),
        RaxStatus::Unsupported
    );
    assert_eq!(before, info(&p));
    #[repr(C)]
    struct ExtendedResult {
        v1: RaxProcessResult,
        tail: [u8; 16],
    }
    let mut extended = ExtendedResult {
        v1: RaxProcessResult::default(),
        tail: [0xA5; 16],
    };
    extended.v1.struct_size = std::mem::size_of::<ExtendedResult>() as u32;
    assert_eq!(rax_process_run(p.0, 0, 0, &mut extended.v1), RaxStatus::Ok);
    assert_eq!(
        extended.tail, [0xA5; 16],
        "v1 must preserve a caller's extension tail"
    );
    assert_eq!(extended.v1.turns_started, 0);
    let mut required = 0;
    let mut sentinel = [0xAA; 4];
    assert_eq!(
        rax_process_info_json(
            p.0,
            sentinel.as_mut_ptr().cast(),
            sentinel.len(),
            &mut required
        ),
        RaxStatus::Bounds
    );
    assert!(required > 4);
    assert_eq!(sentinel, [0xAA; 4]);
    assert_eq!(
        rax_process_mem_read(p.0, u64::MAX, sentinel.as_mut_ptr(), 1),
        RaxStatus::Bounds
    );
    assert_eq!(sentinel, [0xAA; 4]);
    assert_eq!(
        rax_process_mem_read(p.0, 0, sentinel.as_mut_ptr(), 4),
        RaxStatus::Map
    );
    assert_eq!(sentinel, [0xAA; 4]);
}

fn patched_entry(code: &[u8]) -> Vec<u8> {
    let mut image = fixtures()[1].1.to_vec();
    let u16_at = |bytes: &[u8], at: usize| {
        u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap()) as usize
    };
    let u32_at = |bytes: &[u8], at: usize| {
        u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) as usize
    };
    let pe = u32_at(&image, 0x3c);
    let entry = u32_at(&image, pe + 24 + 16);
    let sections = pe + 24 + u16_at(&image, pe + 20);
    for index in 0..u16_at(&image, pe + 6) {
        let s = sections + 40 * index;
        let rva = u32_at(&image, s + 12);
        let size = u32_at(&image, s + 16);
        if (rva..rva + size).contains(&entry) {
            let offset = u32_at(&image, s + 20) + entry - rva;
            image[offset..offset + code.len()].copy_from_slice(code);
            return image;
        }
    }
    panic!("fixture entry must have raw bytes")
}

#[test]
fn process_cancellation_overlaps_run_and_timeout_is_resumable() {
    let p = open(
        &patched_entry(&[0xEB, 0xFE]),
        r#"{"memory_bytes":67108864,"slice_instructions":32}"#,
    );
    let mut result = RaxProcessResult::default();
    assert_eq!(
        rax_process_run(p.0, 1_000_000, 10_000, &mut result),
        RaxStatus::Ok
    );
    assert_eq!(result.reason, RAX_PROCESS_TIMEOUT);
    // SAFETY: p owns this handle until the scoped caller joins. Process contains
    // only Sync channel/atomic primitives, and close is excluded by the scope.
    let shared = unsafe { &*p.0 };
    std::thread::scope(|scope| {
        let run = scope.spawn(move || {
            let mut result = RaxProcessResult::default();
            loop {
                let status = rax_process_run(shared, 1_000_000, 60_000_000, &mut result);
                if status == RaxStatus::State {
                    // The inspection probe may acquire the operation guard
                    // first. A rejected call has submitted no guest work.
                    std::thread::yield_now();
                    continue;
                }
                assert_eq!(status, RaxStatus::Ok);
                break result;
            }
        });
        let start = Instant::now();
        let mut busy = false;
        while start.elapsed() < Duration::from_secs(5) {
            let mut count = 0;
            if rax_process_info_json(p.0, ptr::null_mut(), 0, &mut count) == RaxStatus::State {
                busy = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(busy, "run caller must hold the operation guard");
        assert_eq!(rax_process_set_cancelled(p.0, 1), RaxStatus::Ok);
        assert_eq!(run.join().unwrap().reason, RAX_PROCESS_CANCELLED);
    });
    assert_eq!(rax_process_run(p.0, 1, 0, &mut result), RaxStatus::Ok);
    assert_eq!(result.reason, RAX_PROCESS_CANCELLED);
    assert_eq!(rax_process_set_cancelled(p.0, 0), RaxStatus::Ok);
    assert_eq!(rax_process_run(p.0, 1, 0, &mut result), RaxStatus::Ok);
    assert_eq!(result.reason, RAX_PROCESS_BUDGET);
}

#[test]
fn process_input_capacity_and_invalid_output_do_not_consume_bytes() {
    let p = open(
        fixtures()[1].1,
        r#"{"console_capacity":3,"memory_bytes":67108864}"#,
    );
    assert_eq!(
        rax_process_stdin_feed(p.0, b"abc".as_ptr(), 3),
        RaxStatus::Ok
    );
    assert_eq!(
        rax_process_stdin_feed(p.0, b"d".as_ptr(), 1),
        RaxStatus::Bounds
    );
    assert_eq!(info(&p)["console"]["stdin_pending"], 3);
    let mut count = 99;
    assert_eq!(
        rax_process_output_read(p.0, 3, ptr::null_mut(), 0, &mut count),
        RaxStatus::Arg
    );
    assert_eq!(count, 99);
    assert_eq!(
        rax_process_output_read(p.0, 1, ptr::null_mut(), 0, &mut count),
        RaxStatus::Ok
    );
    assert_eq!(count, 0);
}

#[test]
fn process_supplied_dll_array_loads_real_imports_all_abis() {
    for arch in ["x86", "x64", "arm64"] {
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../tests/fixtures/user/windows/lifecycle/bin")
            .join(arch);
        let exe = std::fs::read(dir.join("startup.exe")).unwrap();
        let paths: Vec<_> = ["root.dll", "leaf.dll", "observer.dll"]
            .into_iter()
            .map(|n| format!("C:\\app\\{n}"))
            .collect();
        let data: Vec<_> = ["root.dll", "leaf.dll", "observer.dll"]
            .into_iter()
            .map(|n| std::fs::read(dir.join(n)).unwrap())
            .collect();
        let images: Vec<_> = paths
            .iter()
            .zip(data.iter())
            .map(|(path, data)| RaxProcessImage {
                path: path.as_ptr().cast(),
                path_size: path.len(),
                data: data.as_ptr(),
                data_size: data.len(),
            })
            .collect();
        let options = r#"{"guest_path":"C:\\app\\program.exe","memory_bytes":67108864}"#;
        let mut raw = ptr::null_mut();
        assert_eq!(
            rax_process_open_image(
                exe.as_ptr(),
                exe.len(),
                options.as_ptr().cast(),
                options.len(),
                images.as_ptr(),
                images.len(),
                &mut raw
            ),
            RaxStatus::Ok,
            "{}",
            error()
        );
        let p = Owned(raw);
        let mut result = RaxProcessResult::default();
        assert_eq!(
            rax_process_run(p.0, 100_000, 5_000_000, &mut result),
            RaxStatus::Ok
        );
        assert_eq!(
            (result.reason, result.exit_code),
            (RAX_PROCESS_EXITED, 0),
            "{arch}: {}",
            info(&p)
        );
    }
}

#[test]
fn process_captures_real_crt_stdout_and_stderr_after_exit_all_abis() {
    for arch in ["x86", "x64", "arm64"] {
        for binding in ["msvcrt", "ucrtbase", "apiset"] {
            let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../tests/fixtures/user/windows/crt_stdio/bin")
                .join(arch)
                .join(binding)
                .join("streams.exe");
            let p = open(
                &std::fs::read(path).unwrap(),
                r#"{"memory_bytes":67108864,"console_capacity":64}"#,
            );
            let mut result = RaxProcessResult::default();
            assert_eq!(
                rax_process_run(p.0, 100_000, 5_000_000, &mut result),
                RaxStatus::Ok
            );
            assert_eq!(
                (result.reason, result.exit_code),
                (RAX_PROCESS_EXITED, 0),
                "{arch}/{binding}: {}",
                info(&p)
            );
            for (stream, expected) in [
                (RAX_PROCESS_STDOUT, b"stdio-out\r\n".as_slice()),
                (RAX_PROCESS_STDERR, b"stdio-err\r\n".as_slice()),
            ] {
                let mut output = Vec::new();
                loop {
                    let mut chunk = [0; 3];
                    let mut written = 0;
                    assert_eq!(
                        rax_process_output_read(
                            p.0,
                            stream,
                            chunk.as_mut_ptr(),
                            chunk.len(),
                            &mut written
                        ),
                        RaxStatus::Ok
                    );
                    if written == 0 {
                        break;
                    }
                    output.extend_from_slice(&chunk[..written]);
                }
                assert_eq!(output, expected, "{arch}/{binding}");
            }
            assert_eq!(info(&p)["console"]["stdout_pending"], 0);
            assert_eq!(info(&p)["console"]["stderr_pending"], 0);
        }
    }
}

#[test]
fn process_personality_failure_has_a_terminal_diagnostic() {
    let p = open(
        &patched_entry(&[0x0F, 0x05]),
        r#"{"memory_bytes":67108864}"#,
    );
    let mut result = RaxProcessResult::default();
    assert_eq!(
        rax_process_run(p.0, 1000, 1_000_000, &mut result),
        RaxStatus::Ok
    );
    assert_eq!(result.reason, RAX_PROCESS_FAILED);
    let snapshot = info(&p);
    assert_eq!(snapshot["status"], "failed");
    assert!(!snapshot["diagnostic"].as_str().unwrap().is_empty());
    assert_eq!(rax_process_run(p.0, 1, 0, &mut result), RaxStatus::Ok);
    assert_eq!(result.reason, RAX_PROCESS_FAILED);
    assert_eq!(result.turns_started, 0);
}
