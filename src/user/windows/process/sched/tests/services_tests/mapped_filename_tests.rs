//! Replay independently captured NT status, length, padding and probe effects.
use super::*;
use crate::user::windows::mapped_filename::Filename;
use crate::user::windows::memory::AllocKind;
use crate::user::windows::objects::Object;

fn decode_hex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn captured_name(row: &serde_json::Value) -> Vec<u16> {
    decode_hex(row["observation"]["name_hex"].as_str().unwrap())
        .chunks_exact(2)
        .map(|unit| u16::from_le_bytes([unit[0], unit[1]]))
        .collect()
}

fn map(p: &mut Proc, kind: AllocKind, size: u64, name: Option<Vec<u16>>) -> u64 {
    let base =
        p.vm.reserve(None, size, prot::READWRITE, kind, false, None)
            .unwrap();
    p.vm.commit(base, size, prot::READWRITE).unwrap();
    if let Some(name) = name {
        p.vm.record_mapped_filename(base, Filename::Captured(name.into()))
            .unwrap();
    }
    base
}

#[test]
fn mapped_filename_replays_native_status_lengths_copy_and_fault_priority() {
    let sources = [
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-mapped-filename/observations-v1.json"
        )),
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-mapped-filename/observations-v2.json"
        )),
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-mapped-filename/observations-v3.json"
        )),
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-mapped-filename/observations-v4.json"
        )),
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-mapped-filename/observations-v5.json"
        )),
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-mapped-filename/observations-v6.json"
        )),
    ];
    let mut retained: Vec<(usize, serde_json::Value)> = sources
        .iter()
        .enumerate()
        .map(|(version, text)| (version, serde_json::from_str(text).unwrap()))
        .collect();
    retained.push((
        7,
        serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-mapped-filename/observations-v8.json"
        )))
        .unwrap(),
    ));
    retained.push((
        8,
        serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-mapped-filename/observations-v9.json"
        )))
        .unwrap(),
    ));
    replay(&retained, 3, 1359, 29695, 0xaa64, false);
    let amd64: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-mapped-filename/amd64-26100-projected-v1.json"
    )))
    .unwrap();
    let amd64: Vec<_> = amd64["groups"]
        .as_array()
        .unwrap()
        .iter()
        .cloned()
        .enumerate()
        .collect();
    replay(&amd64, 2, 266, 26100, 0x8664, false);
    let profiles: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-mapped-filename/amd64-profiles-v2.json"
    )))
    .unwrap();
    for profile in profiles["profiles"].as_array().unwrap() {
        let corpora: Vec<_> = profile["groups"]
            .as_array()
            .unwrap()
            .iter()
            .map(|group| {
                (
                    group["version"].as_u64().unwrap() as usize - 1,
                    group["corpus"].clone(),
                )
            })
            .collect();
        replay(
            &corpora,
            2,
            394,
            profile["build"].as_u64().unwrap() as u32,
            profile["native_machine"].as_u64().unwrap() as u16,
            true,
        );
    }
    let short: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-mapped-filename/amd64-short-profiles-v3.json"
    )))
    .unwrap();
    for profile in short["profiles"].as_array().unwrap() {
        let corpora = [(8, profile["groups"][0]["corpus"].clone())];
        // The short-name subject is KERNEL32, so the baseline executable path
        // is irrelevant to these rows. Rebind its native file metadata to the
        // matching kernel's retained baseline before evaluating the subject.
        let baselines: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-mapped-filename/amd64-profiles-v2.json"
        )))
        .unwrap();
        let baseline = baselines["profiles"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["build"] == profile["build"])
            .unwrap();
        replay_with_baseline(
            &corpora,
            2,
            512,
            profile["build"].as_u64().unwrap() as u32,
            0x8664,
            false,
            &baseline["groups"][0]["corpus"],
        );
    }
    if let Some(directory) = std::env::var_os("RAX_NATIVE_MAPPED_FILENAME_OBSERVATIONS") {
        let external: Vec<_> = [0, 1, 2, 3, 4, 5, 7, 8]
            .into_iter()
            .map(|version| {
                let text = std::fs::read_to_string(
                    std::path::Path::new(&directory)
                        .join(format!("observations-v{}.json", version + 1)),
                )
                .unwrap();
                (
                    version,
                    serde_json::from_str::<serde_json::Value>(&text).unwrap(),
                )
            })
            .collect();
        let build = external[0].1["build"].as_u64().unwrap() as u32;
        replay(&external, 2, 906, build, 0x8664, true);
    }
}

fn kernel_profile(p: &mut Proc, build: u32, machine: u16) {
    use crate::user::windows::{loader::apiset_schema::ApiSetSchema, native::NativeRuntime};
    let schema: Vec<u8> = [6u32, 28, 0, 0, 28, 28, 0]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    let mut native = NativeRuntime {
        directory: Default::default(),
        guest_root: "C:\\Windows".into(),
        guest_directory: "C:\\Windows\\System32".into(),
        version: Default::default(),
        apisets: ApiSetSchema::parse(&schema).unwrap(),
        registry: Default::default(),
        object_namespace: Default::default(),
        nls: None,
        appcompat: Default::default(),
        wnf_catalog: Default::default(),
        startup: None,
        gui: Default::default(),
        code_integrity: Err("controlled filename query profile".into()),
    };
    native.version.build = build;
    native.object_namespace.native_machine = Some(machine);
    p.native = Some(native);
    std::sync::Arc::make_mut(&mut p.cfg).version.build = 12345;
}

fn replay(
    corpora: &[(usize, serde_json::Value)],
    architectures: usize,
    cases: usize,
    build: u32,
    machine: u16,
    external: bool,
) {
    replay_with_baseline(
        corpora,
        architectures,
        cases,
        build,
        machine,
        external,
        &corpora[0].1,
    );
}

fn replay_with_baseline(
    corpora: &[(usize, serde_json::Value)],
    architectures: usize,
    cases: usize,
    build: u32,
    machine: u16,
    external: bool,
    baseline: &serde_json::Value,
) {
    let selected: std::collections::BTreeSet<_> = corpora[0].1["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["arch"].as_str().unwrap())
        .collect();
    assert_eq!(selected.len(), architectures);
    assert_eq!(
        corpora
            .iter()
            .map(|(_, corpus)| corpus["cases"].as_array().unwrap().len())
            .sum::<usize>(),
        cases
    );
    let mut failures = Vec::new();
    for (version, corpus) in corpora {
        for row in corpus["cases"].as_array().unwrap() {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let arch_name = row["arch"].as_str().unwrap();
                let arch = match arch_name {
                    "x86" => WinArch::X86,
                    "x64" => WinArch::X64,
                    "arm64" => WinArch::Arm64,
                    other => panic!("unknown architecture {other}"),
                };
                let which = row["case"].as_u64().unwrap();
                let observation = &row["observation"];
                assert_eq!(row["exit_code"], 0);
                assert_eq!(observation["raised"], 0);
                if external && *version == 0 && which == 44 {
                    assert_eq!(observation["delete_attempted"], true);
                    let deleted = observation["delete_success"].as_bool().unwrap();
                    let error = observation["delete_error"].as_u64().unwrap();
                    assert_eq!(deleted, error == 0, "{arch} deletion setup receipt");
                }
                let find = |case: u64| {
                    baseline["cases"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|row| {
                            row["arch"].as_str() == Some(arch_name)
                                && row["case"].as_u64() == Some(case)
                        })
                        .unwrap()
                };
                let exe_name = String::from_utf16(&captured_name(find(0)))
                    .unwrap()
                    .replace("observation-v1", &format!("observation-v{}", version + 1))
                    .encode_utf16()
                    .collect::<Vec<_>>();
                let (mut process, mut thread, base) = setup(arch);
                let p = process.state_mut();
                kernel_profile(p, build, machine);
                let exe = p.modules.exe().base;
                p.vm.record_mapped_filename(exe, Filename::Captured(exe_name.into()))
                    .unwrap();
                p.space.wr(base, &vec![0xCC; 16384]).unwrap();
                let mut address = exe;
                let mut handle = arch.ptr(u64::MAX);
                let mut output = base + 128;
                let mut returned = base + 64;
                let length = observation["length"].as_u64().unwrap();
                let protect = |p: &mut Proc, page: u64, protection| {
                    p.vm.protect(base + page * PAGE_SIZE, PAGE_SIZE, protection)
                        .unwrap();
                };
                match which {
                    8 | 9 | 63 => output = 0,
                    10 => output += 1,
                    11 | 48 | 49 => output = 1,
                    12 => protect(p, 0, prot::READONLY),
                    13 => protect(p, 0, prot::NOACCESS),
                    14 => protect(p, 0, prot::READWRITE | prot::GUARD),
                    15 | 34 => {
                        output = base + PAGE_SIZE - 2 * arch.ptr_size();
                        protect(
                            p,
                            1,
                            if which == 15 {
                                prot::NOACCESS
                            } else {
                                prot::READWRITE | prot::GUARD
                            },
                        );
                    }
                    16 | 60 => returned = 0,
                    17 | 50 => returned = 1,
                    18 => returned += 1,
                    19 | 20 | 51 | 52 => {
                        returned = base + 2 * PAGE_SIZE;
                        protect(
                            p,
                            2,
                            if matches!(which, 19 | 51) {
                                prot::READONLY
                            } else {
                                prot::READWRITE | prot::GUARD
                            },
                        );
                    }
                    21 | 61 => returned = output,
                    22 => returned = output + arch.ptr_size(),
                    23 | 45 => handle = 0x1234,
                    24 => {
                        handle = 0x1234;
                        output = 0;
                    }
                    25 => handle = arch.ptr(u64::MAX - 1),
                    26 | 27 => {
                        let object = p.objects.create(Object::Process {
                            pid: p.pid,
                            exit_code: None,
                        });
                        handle = u64::from(
                            p.objects
                                .open_access(object, false, if which == 26 { 0x1000 } else { 0x10 })
                                .unwrap(),
                        );
                    }
                    28 | 46 => address = 0,
                    29 => {
                        address = p
                            .vm
                            .allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                            .unwrap()
                            .0
                    }
                    30 => {
                        address =
                            p.vm.reserve(
                                None,
                                PAGE_SIZE,
                                prot::NOACCESS,
                                AllocKind::Private,
                                false,
                                None,
                            )
                            .unwrap()
                    }
                    31 => address = arch.ptr(u64::MAX),
                    32 => {
                        address = map(p, AllocKind::Private, PAGE_SIZE, None);
                        p.vm.release(address).unwrap();
                    }
                    33 => protect(p, 1, prot::NOACCESS),
                    35 => address += 1,
                    36 | 40 => {
                        address = map(
                            p,
                            AllocKind::Image,
                            PAGE_SIZE,
                            Some(captured_name(find(36))),
                        )
                    }
                    37 | 38 | 41 | 42 | 43 | 44 => {
                        address = map(
                            p,
                            AllocKind::Mapped,
                            32 * PAGE_SIZE,
                            Some(captured_name(find(if which == 41 { 37 } else { which }))),
                        );
                        if which == 38 {
                            address += 65536;
                        }
                        if which == 41 {
                            p.vm.release(address).unwrap();
                        }
                    }
                    39 => address = map(p, AllocKind::Mapped, PAGE_SIZE, None),
                    53 => {
                        output = 1;
                        handle = 0x1234;
                    }
                    54 | 55 => {
                        output = 1;
                        address = if which == 54 { 0 } else { arch.ptr(u64::MAX) };
                    }
                    62 => {
                        handle = 0x1234;
                        protect(p, 0, prot::READONLY);
                    }
                    64 | 65 => {
                        returned = base + PAGE_SIZE - 2;
                        protect(
                            p,
                            1,
                            if which == 64 {
                                prot::NOACCESS
                            } else {
                                prot::READWRITE | prot::GUARD
                            },
                        );
                    }
                    91..=95 => {
                        address = map(
                            p,
                            AllocKind::Image,
                            PAGE_SIZE,
                            Some(captured_name(find(36))),
                        )
                    }
                    124..=129 => {
                        output = base + PAGE_SIZE - (64 + ((which - 124) / 2) * 64);
                        protect(
                            p,
                            1,
                            if which % 2 == 0 {
                                prot::NOACCESS
                            } else {
                                prot::READWRITE | prot::GUARD
                            },
                        );
                    }
                    130 | 131 => {
                        returned = base + PAGE_SIZE - 2;
                        protect(
                            p,
                            1,
                            if which == 130 {
                                prot::READONLY
                            } else {
                                prot::READONLY | prot::GUARD
                            },
                        );
                    }
                    132 => returned = output + 2 * arch.ptr_size() + 4,
                    133..=388 => {
                        output = base + PAGE_SIZE - (1 + (which - 133) / 2);
                        protect(
                            p,
                            1,
                            if (which - 133) % 2 == 0 {
                                prot::NOACCESS
                            } else {
                                prot::READWRITE | prot::GUARD
                            },
                        );
                    }
                    _ => {}
                }
                if *version == 8 {
                    address = map(
                        p,
                        AllocKind::Image,
                        PAGE_SIZE,
                        Some(captured_name(find(36))),
                    );
                }
                let last_error =
                    thread.teb + crate::user::windows::layout::offsets(arch).teb_last_error;
                p.space.w32(last_error, 0x1234_5678).unwrap();
                arguments(
                    p,
                    &mut thread,
                    &[handle, address, 2, output, length, returned],
                );
                assert_eq!(
                    dispatch(p, &mut thread),
                    Outcome::Continue,
                    "{arch} v{} case {which}",
                    version + 1
                );
                let status = thread.cpu.gpr(0) as u32;
                assert_eq!(
                    status,
                    observation["status"].as_u64().unwrap() as u32,
                    "{arch} v{} case {which}",
                    version + 1
                );
                assert_eq!(p.space.u32(last_error).unwrap(), 0x1234_5678);
                for page in 0..3 {
                    assert_eq!(
                        p.vm.query(base + page * PAGE_SIZE).unwrap().protect,
                        observation["protect"][page as usize].as_u64().unwrap() as u32,
                        "{arch} case {which} page {page}"
                    );
                }
                p.vm.protect(base, 4 * PAGE_SIZE, prot::READWRITE).unwrap();
                let actual_return =
                    if returned >= base && returned + arch.ptr_size() <= base + 16384 {
                        p.space.ptr(returned, arch.ptr_size()).unwrap()
                    } else {
                        0
                    };
                assert_eq!(
                    actual_return,
                    observation["returned"].as_u64().unwrap(),
                    "{arch} v{} case {which} ReturnLength",
                    version + 1
                );
                let mut expected = decode_hex(observation["output_hex"].as_str().unwrap());
                if !expected.is_empty() {
                    let mut actual = p.space.bytes(output, expected.len()).unwrap();
                    let pointer = arch.ptr_size() as usize;
                    if expected[pointer..2 * pointer]
                        .iter()
                        .any(|&byte| byte != 0xCC)
                        && which != 22
                    {
                        expected[pointer..2 * pointer].fill(0);
                        actual[pointer..2 * pointer].fill(0);
                        let value = p
                            .space
                            .ptr(output + pointer as u64, pointer as u64)
                            .unwrap();
                        if (matches!(which, 15 | 34)
                            || (124..=129).contains(&which)
                            || (133..=388).contains(&which))
                            && status != STATUS_SUCCESS
                            && arch == WinArch::X86
                        {
                            assert!(value >= p.vm.low() && value < p.vm.high());
                            assert!(
                                p.vm.allocation(value).is_none(),
                                "conversion backing leaked"
                            );
                        } else {
                            assert_eq!(
                                value,
                                output + 2 * pointer as u64,
                                "{arch} case {which} Buffer"
                            );
                        }
                    }
                    assert_eq!(
                        actual,
                        expected,
                        "{arch} v{} case {which} output",
                        version + 1
                    );
                }
            }));
            if result.is_err() {
                failures.push(format!(
                    "machine {machine:#06x} build {build}: {} v{} case {}",
                    row["arch"],
                    version + 1,
                    row["case"]
                ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} native replay failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn mapped_filename_is_retired_before_reusing_the_same_allocation_address() {
    for arch in WinArch::ALL {
        let (mut process, mut thread, output) = setup(arch);
        let p = process.state_mut();
        let image = map(
            p,
            AllocKind::Image,
            PAGE_SIZE,
            Some("\\Device\\Example\\one.exe".encode_utf16().collect()),
        );
        assert_eq!(
            query(p, &mut thread, image, 2, output, 1024, 0),
            STATUS_SUCCESS
        );
        p.vm.release(image).unwrap();
        p.vm.reserve(
            Some(image),
            PAGE_SIZE,
            prot::READWRITE,
            AllocKind::Mapped,
            false,
            None,
        )
        .unwrap();
        p.vm.commit(image, PAGE_SIZE, prot::READWRITE).unwrap();
        assert_eq!(
            query(p, &mut thread, image, 2, output, 1024, 0),
            STATUS_FILE_INVALID
        );
    }
}

#[test]
fn mapped_filename_conversion_cannot_make_an_invalid_caller_buffer_valid() {
    let (mut process, mut thread, _) = setup(WinArch::X86);
    let p = process.state_mut();
    let image = p.modules.exe().base;
    p.vm.record_mapped_filename(
        image,
        Filename::Captured(
            "\\Device\\Example\\image.exe"
                .encode_utf16()
                .collect::<Vec<_>>()
                .into(),
        ),
    )
    .unwrap();
    let vacant =
        p.vm.allocate(
            None,
            2 * PAGE_SIZE,
            mem::RESERVE | mem::COMMIT,
            prot::READWRITE,
        )
        .unwrap()
        .0;
    p.vm.release(vacant).unwrap();
    assert_eq!(
        query(p, &mut thread, image, 2, vacant, 4096, 0),
        STATUS_ACCESS_VIOLATION
    );
    assert!(p.vm.allocation(vacant).is_none());
}

#[cfg(windows)]
#[test]
fn mapped_filename_installed_ntdll_leaf_reports_the_selected_file_all_available_abis() {
    use crate::user::windows::loader::{self, SymRef};
    let archs = if cfg!(target_arch = "aarch64") {
        // The selected ARM64 catalog supplies ARM64 and pure x86 files.
        // x64 guest startup through ARM64X projections is a separate frontier.
        vec![WinArch::Arm64, WinArch::X86]
    } else if cfg!(target_arch = "x86_64") {
        vec![WinArch::X64, WinArch::X86]
    } else {
        vec![WinArch::X86]
    };
    for arch in archs {
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/user/windows/bin")
            .join(arch.to_string())
            .join("smoke.exe");
        let bytes = std::fs::read(fixture).unwrap();
        let mut config = crate::user::windows::WindowsConfig::embedded(
            "C:\\mapped-filename-leaf.exe",
            vec![],
            vec![],
            4096,
        )
        .unwrap();
        config.native_libraries = true;
        let mut process = crate::user::windows::WindowsProcess::spawn_image(config, bytes).unwrap();
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut thread = p.threads.remove(&tid).unwrap();
        let module = loader::load_dll(p, "ntdll.dll").unwrap();
        let target = p.modules.list[module].base;
        assert!(
            loader::lookup(
                p,
                module,
                &SymRef::Name(b"NtQueryVirtualMemory".to_vec(), None)
            )
            .unwrap()
            .is_some()
        );
        let file = std::fs::File::open(p.modules.list[module].host_path.as_ref().unwrap()).unwrap();
        let expected =
            crate::user::windows::mapped_filename::native::tests::independent_name(&file);
        let output =
            p.vm.allocate(
                None,
                4 * PAGE_SIZE,
                mem::RESERVE | mem::COMMIT,
                prot::READWRITE,
            )
            .unwrap()
            .0;
        for address in [target, target + 1] {
            assert_eq!(
                super::installed::invoke(
                    p,
                    &mut thread,
                    module,
                    "NtQueryVirtualMemory",
                    &[arch.ptr(u64::MAX), address, 2, output, 8192, output + 12288],
                ),
                STATUS_SUCCESS,
                "{arch}"
            );
            let width = arch.ptr_size();
            let buffer = p.space.ptr(output + width, width).unwrap();
            assert_eq!(buffer, output + 2 * width);
            assert_eq!(
                p.space.wunits(buffer, expected.len()).unwrap(),
                expected,
                "{arch}"
            );
            assert_eq!(p.space.u16(buffer + 2 * expected.len() as u64).unwrap(), 0);
            assert_eq!(
                p.space.ptr(output + 12288, width).unwrap(),
                2 * width + 2 * (expected.len() as u64 + 1)
            );
        }
    }
}
