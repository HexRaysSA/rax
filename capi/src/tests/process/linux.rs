//! ELF fixtures are assembled here so these C ABI tests need no host compiler.
use super::*;

// (ELF e_machine, ELFCLASS32, expected NT_PRSTATUS bytes, architecture name).
const ABIS: [(u16, bool, usize, &str); 5] = [
    (62, false, 216, "x86_64"),
    (3, true, 68, "x86"),
    (183, false, 272, "aarch64"),
    (40, true, 72, "arm"),
    (243, false, 256, "riscv64"),
];
fn elf(machine: u16, compat: bool, code: &[u8]) -> Vec<u8> {
    let mut b = vec![0; 8192];
    b[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', if compat { 1 } else { 2 }, 1, 1]);
    b[16..18].copy_from_slice(&2u16.to_le_bytes());
    b[18..20].copy_from_slice(&machine.to_le_bytes());
    b[20..24].copy_from_slice(&1u32.to_le_bytes());
    if compat {
        b[24..28].copy_from_slice(&0x401000u32.to_le_bytes());
        b[28..32].copy_from_slice(&52u32.to_le_bytes());
        if machine == 40 {
            b[36..40].copy_from_slice(&0x05000400u32.to_le_bytes());
        }
        b[40..46].copy_from_slice(&[52, 0, 32, 0, 1, 0]);
        for (i, w) in [1u32, 0, 0x400000, 0x400000, 8192, 8192, 5, 4096]
            .iter()
            .enumerate()
        {
            b[52 + i * 4..56 + i * 4].copy_from_slice(&w.to_le_bytes());
        }
    } else {
        b[24..32].copy_from_slice(&0x401000u64.to_le_bytes());
        b[32..40].copy_from_slice(&64u64.to_le_bytes());
        b[52..58].copy_from_slice(&[64, 0, 56, 0, 1, 0]);
        b[64..68].copy_from_slice(&1u32.to_le_bytes());
        b[68..72].copy_from_slice(&5u32.to_le_bytes());
        for (i, w) in [0u64, 0x400000, 0x400000, 8192, 8192, 4096]
            .iter()
            .enumerate()
        {
            b[72 + i * 8..80 + i * 8].copy_from_slice(&w.to_le_bytes());
        }
    }
    b[4096..4096 + code.len()].copy_from_slice(code);
    b
}
fn exit_code(machine: u16) -> Vec<u8> {
    let words: &[u32] = match machine {
        62 => return vec![0xb8, 60, 0, 0, 0, 0xbf, 37, 0, 0, 0, 0x0f, 0x05],
        3 => return vec![0xb8, 1, 0, 0, 0, 0xbb, 37, 0, 0, 0, 0xcd, 0x80],
        183 => &[0xd280_0ba8, 0xd280_04a0, 0xd400_0001],
        40 => &[0xe3a0_7001, 0xe3a0_0025, 0xef00_0000],
        243 => &[0x05d0_0893, 0x0250_0513, 0x0000_0073],
        _ => unreachable!(),
    };
    words.iter().flat_map(|w| w.to_le_bytes()).collect()
}
#[test]
fn elf_all_abis_context_memory_exit_and_cached_terminal() {
    for (machine, compat, size, name) in ABIS {
        let p = open(
            &elf(machine, compat, &exit_code(machine)),
            r#"{"personality":"linux","slice_instructions":32}"#,
        );
        let state = info(&p);
        assert_eq!(state["personality"], "linux");
        assert_eq!(state["architecture"], name);
        assert_eq!(state["capabilities"]["host_services"], false);
        let tid = state["threads"][0]["id"].as_u64().unwrap() as u32;
        let original = context(&p, tid);
        assert_eq!(original.len(), size, "{name}");
        assert_eq!(
            rax_process_context_write(p.0, tid, original.as_ptr(), original.len()),
            RaxStatus::Ok,
            "{}",
            error()
        );
        assert_eq!(context(&p, tid), original);
        let mut edited = original.clone();
        let offset = if machine == 243 { 8 } else { 0 };
        let width = if compat { 4 } else { 8 };
        edited[offset..offset + width].copy_from_slice(&0x1234u64.to_le_bytes()[..width]);
        assert_eq!(
            rax_process_context_write(p.0, tid, edited.as_ptr(), edited.len()),
            RaxStatus::Ok
        );
        assert_eq!(context(&p, tid), edited);
        assert_eq!(
            rax_process_context_write(p.0, tid, original.as_ptr(), original.len()),
            RaxStatus::Ok
        );

        assert_eq!(
            rax_process_context_write(p.0, tid, original.as_ptr(), original.len() - 1),
            RaxStatus::Arg
        );
        assert_eq!(context(&p, tid), original);
        let sp = address(&state["threads"][0]["sp"]);
        let bytes = [1, 2, 3, 4];
        assert_eq!(
            rax_process_mem_write(p.0, sp - 32, bytes.as_ptr(), bytes.len()),
            RaxStatus::Ok
        );
        let mut read = [0; 4];
        assert_eq!(
            rax_process_mem_read(p.0, sp - 32, read.as_mut_ptr(), read.len()),
            RaxStatus::Ok
        );
        assert_eq!(read, bytes);
        assert_eq!(rax_process_set_cancelled(p.0, 1), RaxStatus::Ok);
        let mut result = RaxProcessResult::default();
        assert_eq!(rax_process_run(p.0, 16, 0, &mut result), RaxStatus::Ok);
        assert_eq!(result.reason, RAX_PROCESS_CANCELLED);
        assert_eq!(rax_process_set_cancelled(p.0, 0), RaxStatus::Ok);
        assert_eq!(rax_process_run(p.0, 16, 0, &mut result), RaxStatus::Ok);
        assert_eq!(result.reason, RAX_PROCESS_EXITED, "{}", info(&p));
        assert_eq!(result.exit_code, 37);
        assert_eq!(info(&p)["exit_code"], 37);
        assert_eq!(rax_process_run(p.0, 1, 0, &mut result), RaxStatus::Ok);
        assert_eq!(result.reason, RAX_PROCESS_EXITED);
        assert_eq!(result.turns_started, 0);
    }
}
#[test]
fn elf_rejected_late_selector_does_not_apply_prefix() {
    let p = open(
        &elf(62, false, &exit_code(62)),
        r#"{"personality":"linux"}"#,
    );
    let tid = info(&p)["threads"][0]["id"].as_u64().unwrap() as u32;
    let original = context(&p, tid);
    let mut invalid = original.clone();
    invalid[0..8].copy_from_slice(&0x1234u64.to_le_bytes());
    // x86-64 user_regs_struct: cs follows rip, at word 17.
    invalid[17 * 8..18 * 8].copy_from_slice(&0x10u64.to_le_bytes());
    assert_eq!(
        rax_process_context_write(p.0, tid, invalid.as_ptr(), invalid.len()),
        RaxStatus::Arg
    );
    // The refusal names its errno, as `EINVAL (22)` does, not as a Rust value.
    let refusal = error();
    assert!(
        refusal.starts_with("invalid Linux NT_PRSTATUS: E"),
        "{refusal}"
    );
    assert!(!refusal.contains("Errno("), "{refusal}");
    assert_eq!(context(&p, tid), original);
}
#[test]
fn elf_signal_is_terminal_failure_with_linux_details() {
    let p = open(&elf(62, false, &[0x0f, 0x0b]), r#"{"personality":"linux"}"#); // UD2
    let mut result = RaxProcessResult::default();
    assert_eq!(rax_process_run(p.0, 16, 0, &mut result), RaxStatus::Ok);
    assert_eq!(result.reason, RAX_PROCESS_FAILED);
    assert_eq!(info(&p)["signal"]["number"], 4); // SIGILL
    assert_eq!(info(&p)["signal"]["name"], "SIGILL");
    assert_eq!(info(&p)["signal"]["code_name"], "ILL_ILLOPN"); // ud2's si_code 2
    assert!(info(&p)["exit_code"].is_null());
    assert_eq!(rax_process_run(p.0, 1, 0, &mut result), RaxStatus::Ok);
    assert_eq!(result.reason, RAX_PROCESS_FAILED);
    assert_eq!(result.turns_started, 0);
}

#[test]
fn elf_supplied_interpreter_is_copied_and_required_all_abis() {
    let path = "/lib/ld.so";
    for (machine, compat, _, _) in ABIS {
        let mut main = elf(machine, compat, &exit_code(machine));
        let mut interpreter = main.clone();
        interpreter[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
        if compat {
            interpreter[24..28].copy_from_slice(&0x1000u32.to_le_bytes());
            interpreter[60..68].fill(0); // p_vaddr and p_paddr
            main[44..46].copy_from_slice(&2u16.to_le_bytes());
            for (i, w) in [3u32, 512, 0, 0, 11, 11, 4, 1].iter().enumerate() {
                main[84 + i * 4..88 + i * 4].copy_from_slice(&w.to_le_bytes());
            }
        } else {
            interpreter[24..32].copy_from_slice(&0x1000u64.to_le_bytes());
            interpreter[80..96].fill(0);
            main[56..58].copy_from_slice(&2u16.to_le_bytes());
            main[120..124].copy_from_slice(&3u32.to_le_bytes());
            main[124..128].copy_from_slice(&4u32.to_le_bytes());
            for (i, w) in [512u64, 0, 0, 11, 11, 1].iter().enumerate() {
                main[128 + i * 8..136 + i * 8].copy_from_slice(&w.to_le_bytes());
            }
        }
        main[512..522].copy_from_slice(path.as_bytes());
        let options = br#"{"personality":"linux"}"#;
        let mut handle = ptr::null_mut();
        assert_eq!(
            rax_process_open_image(
                main.as_ptr(),
                main.len(),
                options.as_ptr().cast(),
                options.len(),
                ptr::null(),
                0,
                &mut handle
            ),
            RaxStatus::Format
        );
        assert!(handle.is_null());
        let image = RaxProcessImage {
            path: path.as_ptr().cast(),
            path_size: path.len(),
            data: interpreter.as_ptr(),
            data_size: interpreter.len(),
        };
        assert_eq!(
            rax_process_open_image(
                main.as_ptr(),
                main.len(),
                options.as_ptr().cast(),
                options.len(),
                &image,
                1,
                &mut handle
            ),
            RaxStatus::Ok,
            "{}",
            error()
        );
        let p = Owned(handle);
        interpreter.fill(0);
        main.fill(0);
        let before = info(&p);
        let base = address(&before["loaded_program"]["interpreter_base"]);
        assert_ne!(base, 0);
        assert_eq!(address(&before["threads"][0]["pc"]), base + 4096);
        let mut result = RaxProcessResult::default();
        assert_eq!(rax_process_run(p.0, 16, 0, &mut result), RaxStatus::Ok);
        assert_eq!(result.reason, RAX_PROCESS_EXITED, "{}", info(&p));
        assert_eq!(result.exit_code, 37);
    }
}

#[test]
fn elf_stdout_is_captured_and_posix_namespace_rejects_noncanonical_keys() {
    // write(1, 0x401100, 4), then exit(37).
    let mut code = vec![
        0xb8, 1, 0, 0, 0, 0xbf, 1, 0, 0, 0, 0xbe, 0, 0x11, 0x40, 0, 0xba, 4, 0, 0, 0, 0x0f, 0x05,
    ];
    code.extend(exit_code(62));
    let mut bytes = elf(62, false, &code);
    bytes[0x1100..0x1104].copy_from_slice(b"elf\n");
    let p = open(&bytes, r#"{"personality":"linux"}"#);
    let mut result = RaxProcessResult::default();
    assert_eq!(rax_process_run(p.0, 16, 0, &mut result), RaxStatus::Ok);
    assert_eq!(result.reason, RAX_PROCESS_EXITED);
    let mut out = [0; 4];
    let mut count = 0;
    assert_eq!(
        rax_process_output_read(
            p.0,
            RAX_PROCESS_STDOUT,
            out.as_mut_ptr(),
            out.len(),
            &mut count
        ),
        RaxStatus::Ok
    );
    assert_eq!(count, 4);
    assert_eq!(&out, b"elf\n");
    for path in ["relative", "/a/../b", "/a//b", "C:\\a"] {
        let image = RaxProcessImage {
            path: path.as_ptr().cast(),
            path_size: path.len(),
            data: bytes.as_ptr(),
            data_size: bytes.len(),
        };
        let options = br#"{"personality":"linux"}"#;
        let mut handle = ptr::null_mut();
        assert_eq!(
            rax_process_open_image(
                bytes.as_ptr(),
                bytes.len(),
                options.as_ptr().cast(),
                options.len(),
                &image,
                1,
                &mut handle
            ),
            RaxStatus::Arg
        );
        assert!(handle.is_null());
    }
}
