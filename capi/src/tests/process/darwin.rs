//! Self-contained Mach-O fixtures exercise the exported process API on every host.
use super::*;
use rax_engine::user::image::macho::*;

const BASE: u64 = 0x1_0000_0000;
const ENTRY: u64 = BASE + 0x1000;
const DATA: u64 = BASE + 0x1200;
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
fn image(arm: bool, code: &[u8], dyld: bool, file_type: u32) -> Vec<u8> {
    let (kind, subtype, flavor, words, pc_offset) = if arm {
        (
            CPU_TYPE_ARM64,
            CPU_SUBTYPE_ARM64_ALL,
            ARM_THREAD_STATE64,
            ARM_THREAD_STATE64_COUNT,
            256,
        )
    } else {
        (
            CPU_TYPE_X86_64,
            CPU_SUBTYPE_X86_64_ALL,
            X86_THREAD_STATE64,
            X86_THREAD_STATE64_COUNT,
            128,
        )
    };
    let mut state = vec![0; words as usize * 4];
    state[pc_offset..pc_offset + 8].copy_from_slice(&ENTRY.to_le_bytes());
    let state = [
        flavor.to_le_bytes().to_vec(),
        words.to_le_bytes().to_vec(),
        state,
    ]
    .concat();
    let mut commands = vec![
        segment(b"__PAGEZERO", 0, BASE, 0, 0),
        segment(b"__TEXT", BASE, PAGE, PAGE, VM_PROT_READ | VM_PROT_EXECUTE),
        command(LC_UNIXTHREAD, &state),
    ];
    if dyld {
        let mut body = 12u32.to_le_bytes().to_vec();
        body.extend_from_slice(b"/usr/lib/dyld\0");
        body.resize((body.len() + 7) & !7, 0);
        commands.push(command(LC_LOAD_DYLINKER, &body));
    }
    let mut bytes = Vec::new();
    for word in [
        MH_MAGIC_64,
        kind,
        subtype,
        file_type,
        commands.len() as u32,
        commands.iter().map(Vec::len).sum::<usize>() as u32,
        0,
        0,
    ] {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    for command in commands {
        bytes.extend(command);
    }
    bytes.resize(PAGE as usize, 0);
    bytes[0x1000..0x1000 + code.len()].copy_from_slice(code);
    bytes[0x1200..0x1204].copy_from_slice(b"rax\n");
    bytes
}
fn exit(arm: bool, code: u8) -> Vec<u8> {
    if arm {
        [
            0xd280_0030,
            0xd280_0000 | (u32::from(code) << 5),
            0xd400_0001,
        ]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect()
    } else {
        vec![0xb8, 1, 0, 0, 2, 0xbf, code, 0, 0, 0, 0x0f, 0x05]
    }
}
fn run(p: &Owned) -> RaxProcessResult {
    let mut result = RaxProcessResult::default();
    assert_eq!(
        rax_process_run(p.0, 32, 1_000_000, &mut result),
        RaxStatus::Ok
    );
    result
}

#[test]
fn macho_both_abis_context_memory_cancellation_and_terminal_cache() {
    for arm in [false, true] {
        let p = open(
            &image(arm, &exit(arm, 37), false, MH_EXECUTE),
            r#"{"personality":"darwin","slice_instructions":32}"#,
        );
        let before = info(&p);
        assert_eq!(before["personality"], "darwin");
        assert_eq!(
            before["architecture"],
            if arm { "aarch64" } else { "x86_64" }
        );
        assert_eq!(before["capabilities"]["host_services"], false);
        assert_eq!(before["capabilities"]["host_filesystem"], false);
        assert_eq!(
            before["threads"][0]["context_format"],
            "darwin_thread_state64"
        );
        assert_eq!(
            before["threads"][0]["context_flavor"],
            if arm { 6 } else { 4 }
        );
        assert_eq!(address(&before["threads"][0]["pc"]), ENTRY);
        let tid = u32::try_from(before["threads"][0]["id"].as_u64().unwrap()).unwrap();
        let original = context(&p, tid);
        assert_eq!(original.len(), if arm { 272 } else { 168 });
        assert_eq!(
            rax_process_context_write(p.0, tid, original.as_ptr(), original.len() - 1),
            RaxStatus::Arg
        );
        assert_eq!(context(&p, tid), original);
        let mut changed = original.clone();
        changed[..8].copy_from_slice(&0x1234u64.to_le_bytes());
        assert_eq!(
            rax_process_context_write(p.0, tid, changed.as_ptr(), changed.len()),
            RaxStatus::Ok
        );
        assert_eq!(&context(&p, tid)[..8], &0x1234u64.to_le_bytes());
        if !arm {
            let mut invalid = changed.clone();
            invalid[128..136].copy_from_slice(&u64::MAX.to_le_bytes());
            assert_eq!(
                rax_process_context_write(p.0, tid, invalid.as_ptr(), invalid.len()),
                RaxStatus::Arg
            );
            assert_eq!(context(&p, tid), changed);
        }
        let sp = address(&before["threads"][0]["sp"]);
        let data = [1, 2, 3, 4];
        assert_eq!(
            rax_process_mem_write(p.0, sp - 32, data.as_ptr(), data.len()),
            RaxStatus::Ok
        );
        let mut copied = [0; 4];
        assert_eq!(
            rax_process_mem_read(p.0, sp - 32, copied.as_mut_ptr(), copied.len()),
            RaxStatus::Ok
        );
        assert_eq!(copied, data);
        assert_eq!(
            rax_process_mem_write(p.0, ENTRY, data.as_ptr(), data.len()),
            RaxStatus::Perm
        );
        assert_eq!(rax_process_set_cancelled(p.0, 1), RaxStatus::Ok);
        assert_eq!(run(&p).reason, RAX_PROCESS_CANCELLED);
        assert_eq!(rax_process_set_cancelled(p.0, 0), RaxStatus::Ok);
        let result = run(&p);
        assert_eq!((result.reason, result.exit_code), (RAX_PROCESS_EXITED, 37));
        let cached = run(&p);
        assert_eq!(
            (cached.reason, cached.exit_code, cached.turns_started),
            (RAX_PROCESS_EXITED, 37, 0)
        );
    }
}

#[test]
fn macho_both_abis_capture_stdout_and_reject_host_syscalls() {
    for arm in [false, true] {
        let mut write = if arm {
            [
                0xd280_0090u32,
                0xd280_0020,
                0xd282_4001,
                0xf2c0_0021,
                0xd280_0082,
                0xd400_0001,
            ]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>()
        } else {
            let mut code = vec![0xb8, 4, 0, 0, 2, 0xbf, 1, 0, 0, 0, 0x48, 0xbe];
            code.extend_from_slice(&DATA.to_le_bytes());
            code.extend_from_slice(&[0xba, 4, 0, 0, 0, 0x0f, 0x05]);
            code
        };
        write.extend(exit(arm, 0));
        let p = open(
            &image(arm, &write, false, MH_EXECUTE),
            r#"{"personality":"darwin"}"#,
        );
        assert_eq!(run(&p).reason, RAX_PROCESS_EXITED);
        let mut out = [0; 16];
        let mut written = 0;
        assert_eq!(
            rax_process_output_read(
                p.0,
                RAX_PROCESS_STDOUT,
                out.as_mut_ptr(),
                out.len(),
                &mut written
            ),
            RaxStatus::Ok
        );
        assert_eq!(&out[..written], b"rax\n");
        // socket(97) is rejected before argument processing; exit with its errno.
        let denied = if arm {
            [0xd280_0c30u32, 0xd400_0001, 0xd280_0030, 0xd400_0001]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect()
        } else {
            vec![
                0xb8, 97, 0, 0, 2, 0x0f, 0x05, 0x48, 0x89, 0xc7, 0xb8, 1, 0, 0, 2, 0x0f, 0x05,
            ]
        };
        let p = open(
            &image(arm, &denied, false, MH_EXECUTE),
            r#"{"personality":"darwin"}"#,
        );
        assert_eq!(
            (run(&p).reason, info(&p)["exit_code"].as_u64()),
            (RAX_PROCESS_EXITED, Some(1))
        );
    }
}

#[test]
fn macho_supplied_dyld_has_no_host_fallback() {
    for arm in [false, true] {
        let main = image(arm, &exit(arm, 37), true, MH_EXECUTE);
        let dyld = image(arm, &exit(arm, 43), false, MH_DYLINKER);
        let options = br#"{"personality":"darwin"}"#;
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
        assert!(error().contains("/usr/lib/dyld"));
        let name = b"/usr/lib/dyld";
        let supplied = RaxProcessImage {
            path: name.as_ptr().cast(),
            path_size: name.len(),
            data: dyld.as_ptr(),
            data_size: dyld.len(),
        };
        assert_eq!(
            rax_process_open_image(
                main.as_ptr(),
                main.len(),
                options.as_ptr().cast(),
                options.len(),
                &supplied,
                1,
                &mut handle
            ),
            RaxStatus::Ok,
            "{}",
            error()
        );
        let p = Owned(handle);
        assert_eq!(info(&p)["loaded_program"]["has_dyld"], true);
        let result = run(&p);
        assert_eq!((result.reason, result.exit_code), (RAX_PROCESS_EXITED, 43));
    }
}

#[test]
fn macho_signal_failure_is_inspectable() {
    let p = open(
        &image(false, &[0x0f, 0x0b], false, MH_EXECUTE),
        r#"{"personality":"darwin"}"#,
    );
    assert_eq!(run(&p).reason, RAX_PROCESS_FAILED);
    let state = info(&p);
    assert_eq!(state["signal"]["number"], 4);
    assert_eq!(address(&state["signal"]["pc"]), ENTRY);
    assert!(state["diagnostic"].as_str().unwrap().contains("SIGILL"));
}

#[test]
fn macho_fat_slice_selection_is_explicit_and_host_independent() {
    let x86 = image(false, &exit(false, 37), false, MH_EXECUTE);
    let arm = image(true, &exit(true, 43), false, MH_EXECUTE);
    let mut fat = vec![0; 0xc000];
    fat[..4].copy_from_slice(&0xcafe_babeu32.to_be_bytes());
    fat[4..8].copy_from_slice(&2u32.to_be_bytes());
    for (index, (cpu, subtype, offset)) in [
        (CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, 0x4000u32),
        (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, 0x8000u32),
    ]
    .into_iter()
    .enumerate()
    {
        for (word, value) in [cpu, subtype, offset, 0x4000, 14].into_iter().enumerate() {
            let start = 8 + index * 20 + word * 4;
            fat[start..start + 4].copy_from_slice(&value.to_be_bytes());
        }
    }
    fat[0x4000..0x8000].copy_from_slice(&x86);
    fat[0x8000..].copy_from_slice(&arm);
    for (options, architecture, code) in [
        (r#"{"personality":"darwin"}"#, "x86_64", 37),
        (
            r#"{"personality":"darwin","architecture":"x86_64"}"#,
            "x86_64",
            37,
        ),
        (
            r#"{"personality":"darwin","architecture":"aarch64"}"#,
            "aarch64",
            43,
        ),
    ] {
        let p = open(&fat, options);
        assert_eq!(info(&p)["architecture"], architecture);
        assert_eq!(run(&p).exit_code, code);
    }
    for options in [
        r#"{"personality":"darwin","architecture":"arm"}"#,
        r#"{"personality":"darwin","architecture":3}"#,
        r#"{"personality":"linux","architecture":"x86_64"}"#,
    ] {
        let mut handle = ptr::null_mut();
        assert_eq!(
            rax_process_open_image(
                fat.as_ptr(),
                fat.len(),
                options.as_ptr().cast(),
                options.len(),
                ptr::null(),
                0,
                &mut handle
            ),
            RaxStatus::Arg
        );
        assert!(handle.is_null());
    }
}
