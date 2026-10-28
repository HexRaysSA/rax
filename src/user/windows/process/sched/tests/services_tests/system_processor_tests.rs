//! Execute native processor queries and replay the independent Windows control.

use super::*;
use crate::user::windows::nt::status::STATUS_INVALID_INFO_CLASS;

fn kernel_profile(p: &mut Proc, machine: u16) {
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
        code_integrity: Err("controlled processor query profile".into()),
    };
    native.version.build = if machine == 0xaa64 { 29683 } else { 26100 };
    native.object_namespace.native_machine = Some(machine);
    p.native = Some(native);
    // Guest version spoofing must not select the kernel architecture.
    std::sync::Arc::make_mut(&mut p.cfg).version.build = 20348;
}

fn query_process(
    arch: WinArch,
    api: &str,
    machine: u16,
) -> (super::super::super::super::WindowsProcess, Thread) {
    let (mut process, thread) = fixture(arch, api, 0x36);
    kernel_profile(process.state_mut(), machine);
    (process, thread)
}

#[test]
fn native_system_processor_export_appends_without_moving_prior_ordinals() {
    use crate::user::windows::dll::{self, BuiltinDll};
    use crate::user::windows::loader::builtin;
    let current = dll::find("ntdll.dll").unwrap();
    for (tail, name, x86_only) in [
        (
            current.exports.len() - 4,
            "NtWow64GetNativeSystemInformation",
            true,
        ),
        (
            current.exports.len() - 3,
            "NtWow64CsrClientConnectToServer",
            true,
        ),
        (current.exports.len() - 2, "NtOpenThread", false),
        (
            current.exports.len() - 1,
            "NtSetInformationVirtualMemory",
            false,
        ),
    ] {
        assert_eq!(current.exports[tail].len(), 1);
        assert_eq!(current.exports[tail][0].name, name);
        let previous = BuiltinDll {
            name: current.name,
            display: current.display,
            subsystem: current.subsystem,
            exports: &current.exports[..tail],
        };
        let appended = BuiltinDll {
            exports: &current.exports[..=tail],
            ..previous
        };
        for arch in WinArch::ALL {
            let available = !x86_only || arch == WinArch::X86;
            let before = builtin::build(&previous, arch, 0, &[]);
            let after = builtin::build(&appended, arch, 0, &[]);
            assert_eq!(after.ordinal_base, before.ordinal_base);
            assert_eq!(
                &after.symbols[..before.symbols.len()],
                before.symbols.as_slice()
            );
            assert_eq!(
                after.symbols.len() - before.symbols.len(),
                usize::from(available)
            );
            assert_eq!(dll::nt_service(name, arch).is_some(), available);
        }
    }
}

#[test]
fn native_system_processor_separates_caller_kernel_and_legacy_views() {
    for machine in [0xaa64, 0x8664] {
        for arch in WinArch::ALL {
            if machine == 0x8664 && arch == WinArch::Arm64 {
                continue;
            }
            for native in [false, true] {
                if native && arch != WinArch::X86 {
                    continue;
                }
                let api = if native {
                    "NtWow64GetNativeSystemInformation"
                } else {
                    "NtQuerySystemInformation"
                };
                let (mut process, mut t) = query_process(arch, api, machine);
                let p = process.state_mut();
                let out =
                    p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                        .unwrap()
                        .0;
                let sp = t.cpu.sp();
                for class in [1, 63] {
                    p.space.wr(out, &[0xa5; 128]).unwrap();
                    t.cpu.set_sp(sp);
                    query_arguments(p, &mut t, class, out, 64, out + 96);
                    assert_eq!(dispatch_query(p, &mut t), Outcome::Continue);
                    assert_eq!(t.cpu.gpr(0), 0, "{machine:#x}/{arch}/{native}/{class}");
                    let expected_arch = if arch == WinArch::X86 && !native {
                        0
                    } else if class == 63 {
                        if machine == 0xaa64 { 5 } else { 0 }
                    } else if native {
                        if machine == 0xaa64 { 12 } else { 9 }
                    } else {
                        arch.processor_architecture()
                    };
                    assert_eq!(p.space.u16(out).unwrap(), expected_arch);
                    let x86_identity = matches!(expected_arch, 0 | 9);
                    assert_eq!(
                        p.space.u16(out + 2).unwrap(),
                        if x86_identity { 6 } else { 0 }
                    );
                    assert_eq!(
                        p.space.u16(out + 4).unwrap(),
                        if x86_identity { 0x0f01 } else { 0 }
                    );
                    assert_eq!(p.space.u16(out + 6).unwrap(), 1);
                    let features = p.space.u32(out + 8).unwrap();
                    if machine == 0xaa64 {
                        assert_eq!(
                            features,
                            if arch == WinArch::X86 && !native {
                                0
                            } else {
                                0xa000_0000
                            }
                        );
                    } else {
                        assert_eq!(features & 0xa100_0000, 0xa100_0000); // NX and guest GenuineIntel.
                        assert_eq!(features & 0x0020_0000, 0); // Never copy host AuthenticAMD.
                    }
                    assert_eq!(p.space.bytes(out + 12, 84).unwrap(), [0xa5; 84]);
                    assert_eq!(p.space.u32(out + 96).unwrap(), 12);
                    assert_eq!(t.cpu.pc(), 0x1234_0004);
                    assert_eq!(t.cpu.sp(), sp + if arch == WinArch::X86 { 4 } else { 0 });
                    assert!(t.frames.is_empty());
                }
            }
        }
    }
}

fn decode(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&value[at..at + 2], 16).unwrap())
        .collect()
}

#[test]
fn native_system_processor_replays_768_independent_copy_probe_and_guard_rows() {
    let capture: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-system-processor-information/local-29683-v1.json"
    )))
    .unwrap();
    let mut count = 0;
    for sample in capture["samples"].as_array().unwrap() {
        let arch = match sample["arch"].as_str().unwrap() {
            "arm64" => WinArch::Arm64,
            "x64" => WinArch::X64,
            "x86" => WinArch::X86,
            _ => unreachable!(),
        };
        for native in [false, true] {
            if native && arch != WinArch::X86 {
                continue;
            }
            let name = if native {
                "NtWow64GetNativeSystemInformation"
            } else {
                "NtQuerySystemInformation"
            };
            let (mut process, mut t) = query_process(arch, name, 0xaa64);
            let p = process.state_mut();
            let data =
                p.vm.allocate(
                    None,
                    2 * PAGE_SIZE,
                    mem::RESERVE | mem::COMMIT,
                    prot::READWRITE,
                )
                .unwrap()
                .0;
            let ret =
                p.vm.allocate(
                    None,
                    2 * PAGE_SIZE,
                    mem::RESERVE | mem::COMMIT,
                    prot::READWRITE,
                )
                .unwrap()
                .0;
            let sp = t.cpu.sp();
            for row in sample["rows"].as_array().unwrap() {
                let cls = row[1].as_u64().unwrap() as u32;
                if row[0].as_u64().unwrap() != u64::from(native) || !matches!(cls, 1 | 63) {
                    continue;
                }
                let length = row[2].as_u64().unwrap() as u32;
                let mode = row[3].as_str().unwrap();
                p.vm.protect(data, 2 * PAGE_SIZE, prot::READWRITE).unwrap();
                p.vm.protect(ret, 2 * PAGE_SIZE, prot::READWRITE).unwrap();
                p.space.wr(data, &[0xa5; 8192]).unwrap();
                p.space.wr(ret, &[0xcc; 8192]).unwrap();
                let mut output = data + 128;
                let mut returned = ret + 128;
                match mode {
                    "valid" => {}
                    "null_output" => output = 0,
                    "misaligned_output" => output += 1,
                    "null_return" => returned = 0,
                    "misaligned_return" => returned += 1,
                    "bad_return" => {
                        returned = ret + PAGE_SIZE;
                        p.vm.protect(ret + PAGE_SIZE, PAGE_SIZE, prot::NOACCESS)
                            .unwrap();
                    }
                    "readonly_output" => {
                        p.vm.protect(data, PAGE_SIZE, prot::READONLY).unwrap();
                    }
                    "guard_output" => {
                        p.vm.protect(data, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                            .unwrap();
                    }
                    "readonly_guard_output" => {
                        p.vm.protect(data, PAGE_SIZE, prot::READONLY | prot::GUARD)
                            .unwrap();
                    }
                    "cross12" | "cross44" => {
                        output = data + PAGE_SIZE - if mode == "cross12" { 12 } else { 44 };
                        p.vm.protect(data + PAGE_SIZE, PAGE_SIZE, prot::NOACCESS)
                            .unwrap();
                    }
                    "alias_return" => returned = output,
                    "guard_return" => {
                        p.vm.protect(ret, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                            .unwrap();
                    }
                    "both_guard" => {
                        p.vm.protect(data, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                            .unwrap();
                        p.vm.protect(ret, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                            .unwrap();
                    }
                    "readonly_return" => {
                        p.vm.protect(ret, PAGE_SIZE, prot::READONLY).unwrap();
                    }
                    "return_cross2" => {
                        returned = ret + PAGE_SIZE - 2;
                        p.vm.protect(ret + PAGE_SIZE, PAGE_SIZE, prot::NOACCESS)
                            .unwrap();
                    }
                    _ => panic!("unknown independent mode {mode}"),
                }
                t.cpu.set_sp(sp);
                query_arguments(p, &mut t, cls, output, length, returned);
                let label = format!("{arch}/{name}/{cls}/{length}/{mode}");
                assert_eq!(dispatch_query(p, &mut t), Outcome::Continue, "{label}");
                let status = row[4].as_u64().unwrap();
                assert_eq!(t.cpu.gpr(0), status, "{label}");
                assert_eq!(
                    row[5].as_u64().unwrap(),
                    0,
                    "{label}: no native raised exception"
                );
                assert!(t.frames.is_empty(), "{label}");
                assert_eq!(
                    p.vm.query(data).unwrap().protect & prot::GUARD != 0,
                    row[7].as_bool().unwrap(),
                    "{label}"
                );
                assert_eq!(
                    p.vm.query(ret).unwrap().protect & prot::GUARD != 0,
                    row[8].as_bool().unwrap(),
                    "{label}"
                );
                p.vm.protect(data, 2 * PAGE_SIZE, prot::READWRITE).unwrap();
                p.vm.protect(ret, 2 * PAGE_SIZE, prot::READWRITE).unwrap();
                let mut expected = decode(row[9].as_str().unwrap());
                if status == 0 {
                    // Project only CPU identity and the one-CPU topology.
                    // The oracle still owns status, bytes written, aliases,
                    // output/return fault order and both guard transitions.
                    if (arch == WinArch::X86 && !native) || (cls == 1 && arch == WinArch::X64) {
                        expected[2..4].copy_from_slice(&6u16.to_le_bytes());
                        expected[4..6].copy_from_slice(&0x0f01u16.to_le_bytes());
                    }
                    expected[6..8].copy_from_slice(&1u16.to_le_bytes());
                }
                let expected_returned = if mode == "alias_return" {
                    u32::from_le_bytes(expected[..4].try_into().unwrap()) as u64
                } else {
                    row[6].as_u64().unwrap()
                };
                assert_eq!(
                    if returned == 0 {
                        0
                    } else {
                        p.space.u32(returned).unwrap() as u64
                    },
                    expected_returned,
                    "{label}"
                );
                assert_eq!(
                    if output == 0 {
                        vec![]
                    } else {
                        p.space.bytes(output, 80).unwrap()
                    },
                    expected,
                    "{label}"
                );
                count += 1;
            }
        }
    }
    assert_eq!(count, 768);
}

#[test]
fn native_system_processor_replays_135_successful_owned_alias_cases_and_retains_one_native_failure()
{
    let capture: serde_json::Value = serde_json::from_str(include_str!(concat!(env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-system-processor-information/processor-alias-29683-v2.json"))).unwrap();
    let mut completed = 0;
    let mut native_failures = Vec::new();
    for sample in capture["samples"].as_array().unwrap() {
        let arch = match sample["arch"].as_str().unwrap() {
            "arm64" => WinArch::Arm64,
            "x64" => WinArch::X64,
            "x86" => WinArch::X86,
            _ => unreachable!(),
        };
        for native in [false, true] {
            if native && arch != WinArch::X86 {
                continue;
            }
            let name = if native {
                "NtWow64GetNativeSystemInformation"
            } else {
                "NtQuerySystemInformation"
            };
            let (mut process, mut t) = query_process(arch, name, 0xaa64);
            let p = process.state_mut();
            let out =
                p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                    .unwrap()
                    .0;
            let sp = t.cpu.sp();
            for row in sample["cases"].as_array().unwrap() {
                if row[0].as_u64().unwrap() != u64::from(native) {
                    continue;
                }
                let class = row[1].as_u64().unwrap() as u32;
                let offset = row[2].as_u64().unwrap() as usize;
                if row[3].as_i64().unwrap() != 0 {
                    // The owned host child exited without a result. Keep its
                    // identity explicit; there is no fabricated guest oracle.
                    native_failures.push((arch, native, class, offset, row[3].as_i64().unwrap()));
                    assert!([4, 5, 6, 7].into_iter().all(|index| row[index].is_null()));
                    continue;
                }
                assert_eq!(row[4].as_u64().unwrap(), 0);
                assert_eq!(row[5].as_u64().unwrap(), 0);
                let mut expected = decode(row[7].as_str().unwrap());
                let translated =
                    (arch == WinArch::X86 && !native) || (arch == WinArch::X64 && class == 1);
                if translated {
                    // These identity bytes are rewritten after ReturnLength.
                    expected[2..4].copy_from_slice(&6u16.to_le_bytes());
                    expected[4..6].copy_from_slice(&0x0f01u16.to_le_bytes());
                }
                for (index, byte) in 1u16.to_le_bytes().into_iter().enumerate() {
                    let at = 6 + index;
                    if !(offset..offset + 4).contains(&at) {
                        expected[at] = byte;
                    }
                }
                p.space.wr(out, &[0xa5; 80]).unwrap();
                t.cpu.set_sp(sp);
                query_arguments(p, &mut t, class, out, 12, out + offset as u64);
                let label = format!("{arch}/{name}/{class}/alias+{offset}");
                assert_eq!(dispatch_query(p, &mut t), Outcome::Continue, "{label}");
                assert_eq!(t.cpu.gpr(0), 0, "{label}");
                assert_eq!(p.space.bytes(out, 80).unwrap(), expected, "{label}");
                assert_eq!(
                    p.space.u32(out + offset as u64).unwrap(),
                    u32::from_le_bytes(expected[offset..offset + 4].try_into().unwrap()),
                    "{label}"
                );
                assert!(t.frames.is_empty());
                completed += 1;
            }
        }
    }
    assert_eq!(completed, 135);
    assert_eq!(native_failures, [(WinArch::X64, false, 1, 1, 255)]);
}

#[test]
fn native_system_processor_wow64_basic_views_keep_distinct_widths_and_bounds() {
    for machine in [0xaa64, 0x8664] {
        for (class, required) in [(0, 44u32), (62, 44), (114, 64)] {
            let (mut process, mut t) =
                query_process(WinArch::X86, "NtWow64GetNativeSystemInformation", machine);
            let p = process.state_mut();
            let out =
                p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                    .unwrap()
                    .0;
            let sp = t.cpu.sp();
            for length in [0, 12, required - 1, required, required + 1, 128] {
                p.space.wr(out, &[0xa5; 128]).unwrap();
                t.cpu.set_sp(sp);
                query_arguments(p, &mut t, class, out, length, out + 96);
                assert_eq!(dispatch_query(p, &mut t), Outcome::Continue);
                assert_eq!(
                    t.cpu.gpr(0),
                    if length == required {
                        0
                    } else {
                        STATUS_INFO_LENGTH_MISMATCH.into()
                    }
                );
                assert_eq!(p.space.u32(out + 96).unwrap(), required);
                if length != required {
                    assert_eq!(p.space.bytes(out, 80).unwrap(), [0xa5; 80]);
                    continue;
                }
                assert_eq!(p.space.u32(out + 8).unwrap(), 4096);
                let high = if class == 62 {
                    p.vm.high() - 1
                } else {
                    0x7fff_fffe_ffff
                };
                if class == 114 {
                    assert_eq!(p.space.u64(out + 32).unwrap(), 0x10000);
                    assert_eq!(p.space.u64(out + 40).unwrap(), high);
                    assert_eq!(p.space.u64(out + 48).unwrap(), 1);
                    assert_eq!(p.space.u8(out + 56).unwrap(), 1);
                    let pad = if machine == 0xaa64 { 0 } else { 0xa5 };
                    assert_eq!(p.space.bytes(out + 28, 4).unwrap(), [pad; 4]);
                    assert_eq!(p.space.bytes(out + 57, 7).unwrap(), [pad; 7]);
                } else {
                    assert_eq!(p.space.u32(out + 28).unwrap(), 0x10000);
                    assert_eq!(p.space.u32(out + 32).unwrap(), high as u32);
                    assert_eq!(p.space.u32(out + 36).unwrap(), 1);
                    assert_eq!(p.space.u8(out + 40).unwrap(), 1);
                    assert_eq!(p.space.bytes(out + 41, 3).unwrap(), [0xa5; 3]);
                }
                assert_eq!(
                    p.space
                        .bytes(out + required as u64, (96 - required) as usize)
                        .unwrap(),
                    vec![0xa5; (96 - required) as usize]
                );
            }
        }
    }
}

#[test]
fn native_system_processor_wow64_rejects_other_classes_before_visiting_pointers() {
    for class in [2, 50, 55, 250, u32::MAX] {
        let (mut process, mut t) =
            query_process(WinArch::X86, "NtWow64GetNativeSystemInformation", 0xaa64);
        let p = process.state_mut();
        query_arguments(p, &mut t, class, 1, u32::MAX, 1);
        assert_eq!(dispatch_query(p, &mut t), Outcome::Continue);
        assert_eq!(t.cpu.gpr(0), u64::from(STATUS_INVALID_INFO_CLASS));
        assert!(t.frames.is_empty());
    }
    let (mut process, mut t, scratch) = query_fixture(WinArch::X86);
    let p = process.state_mut();
    query_arguments(p, &mut t, 114, 1, u32::MAX, scratch);
    assert_eq!(dispatch_query(p, &mut t), Outcome::Continue);
    assert_eq!(t.cpu.gpr(0), u64::from(STATUS_INVALID_INFO_CLASS));
    assert_eq!(p.space.u32(scratch).unwrap(), 0xa5a5_a5a5);
}

#[cfg(windows)]
#[test]
fn native_system_processor_installed_wow64_leaf_uses_native_view_and_four_arguments() {
    use crate::user::windows::{
        layout::{KUSER_SHARED_DATA, kuser},
        loader::{self, SymRef},
        process::{WindowsConfig, WindowsProcess},
    };
    let image =
        include_bytes!("../../../../../../../tests/fixtures/user/windows/bin/x86/smoke.exe");
    let mut config =
        WindowsConfig::embedded("C:\\native-processor.exe", vec![], vec![], 4096).unwrap();
    config.native_libraries = true;
    config.arena_bytes = 256 << 20;
    let mut process = WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
    let p = process.state_mut();
    let tid = *p.threads.keys().next().unwrap();
    let mut t = p.threads.remove(&tid).unwrap();
    let kernel = crate::user::windows::process::processor::native_arch(p).unwrap();
    assert!(matches!(kernel, WinArch::X64 | WinArch::Arm64));
    assert_eq!(
        p.space
            .u16(KUSER_SHARED_DATA + kuser::NATIVE_PROCESSOR_ARCHITECTURE)
            .unwrap(),
        kernel.processor_architecture()
    );
    let module = loader::load_dll(p, "ntdll.dll").unwrap();
    let entry = loader::lookup(
        p,
        module,
        &SymRef::Name(b"NtWow64GetNativeSystemInformation".to_vec(), None),
    )
    .unwrap()
    .unwrap();
    let sp = t.cpu.sp();
    let output = sp - 128;
    let returned = output + 96;
    let resume = p.traps.callback_return();
    for (class, architecture) in [
        (1, kernel.processor_architecture()),
        (63, if kernel == WinArch::Arm64 { 5 } else { 0 }),
    ] {
        p.space.wr(output, &[0xa5; 104]).unwrap();
        t.cpu.set_sp(sp);
        p.space.w32(sp, resume as u32).unwrap();
        for (index, value) in [class, output, 12, returned].into_iter().enumerate() {
            p.space
                .w32(sp + 4 + 4 * index as u64, value as u32)
                .unwrap();
        }
        t.cpu.set_pc(entry);
        assert_eq!(execute_to_return(p, &mut t, resume), 0);
        assert_eq!(p.space.u16(output).unwrap(), architecture);
        assert_eq!(p.space.u16(output + 6).unwrap(), 1);
        assert_eq!(p.space.u32(returned).unwrap(), 12);
        assert_eq!(p.space.bytes(output + 12, 84).unwrap(), [0xa5; 84]);
        assert_eq!(t.cpu.sp(), sp + 20);
        assert!(t.frames.is_empty());
    }
}

#[cfg(windows)]
fn execute_to_return(p: &mut Proc, t: &mut Thread, resume: u64) -> u64 {
    for _ in 0..32 {
        let boundary = t.cpu.run(64);
        if t.cpu.pc() == resume {
            return t.cpu.gpr(0);
        }
        let description = format!(
            "{} PC={:#x}, SP={:#x}, boundary={boundary:?}",
            p.arch,
            t.cpu.pc(),
            t.cpu.sp()
        );
        assert!(
            matches!(
                handle_stop(p, t, boundary),
                Outcome::Continue | Outcome::Yield
            ),
            "{description}"
        );
    }
    panic!("installed native processor query did not return within 2048 instructions");
}
