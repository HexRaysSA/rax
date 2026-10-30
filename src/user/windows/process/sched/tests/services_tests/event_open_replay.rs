//! Independently captured NT statuses, stores, grants and guard transitions.
use super::*;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Case {
    phase: String,
    index: u32,
    output: u32,
    attribute: u32,
    access: u32,
    flags: u32,
    status: u32,
    exception: u32,
    grant: u32,
    handle_attributes: u32,
    query: u32,
    event_type: i32,
    event_state: i32,
    protections: Vec<u32>,
    bytes: String,
}

fn pointer(p: &Proc, at: u64, value: u64) {
    p.space.wptr(at, p.arch.ptr_size(), value).unwrap();
}

fn prepare(
    p: &mut Proc,
    base: u64,
    case: &Case,
    root: u64,
    creator: u64,
    parent: &str,
    leaf: &str,
) -> u64 {
    let width = p.arch.ptr_size();
    let size = if p.arch.is64() { 48 } else { 24 };
    let descriptor = base + 8192;
    let buffer = base + 16384;
    let mut oa = base + 4096;
    let (text, root) = match (case.phase.as_str(), case.index) {
        ("access-missing", _) | ("name", 1) => (format!("{leaf}-missing"), root),
        ("access-type", _) | ("name", 3) => (format!("{leaf}-sem"), root),
        ("name", 0) => (format!("{parent}\\{leaf}"), 0),
        ("name", 2) => ("missing\\leaf".into(), root),
        ("name", 4) => (leaf.into(), 0),
        ("name", 5) => ("HookSwitchHookEnabledEvent".into(), root),
        _ => (leaf.into(), root),
    };
    let units: Vec<_> = text.encode_utf16().collect();
    p.space.wr(base, &vec![0xA5; 65536]).unwrap();
    p.space.put_wstr(buffer, &units).unwrap();
    p.space.wr(descriptor, &[0; 16]).unwrap();
    p.space.w16(descriptor, (units.len() * 2) as u16).unwrap();
    p.space
        .w16(descriptor + 2, (units.len() * 2) as u16)
        .unwrap();
    pointer(p, descriptor + width, buffer);
    attrs(p, oa, size, case.flags, root);
    pointer(p, oa + 2 * width, descriptor);
    match case.attribute {
        0 => {}
        1 => oa = 0,
        2 => oa = 1,
        3 => p.space.w32(oa, 0).unwrap(),
        4 => p.space.w32(oa, size + 4).unwrap(),
        5 | 6 => {
            let bytes = p.space.bytes(oa, size as usize).unwrap();
            oa += if case.attribute == 5 { 1 } else { 4 };
            p.space.wr(oa, &bytes).unwrap();
        }
        7 => {
            pointer(p, oa + 2 * width, 0);
            pointer(p, oa + width, 0);
        }
        8 => pointer(p, oa + 2 * width, 0),
        9 => p.space.w16(descriptor, 0).unwrap(),
        10 => {
            p.space.w16(descriptor, 0).unwrap();
            pointer(p, oa + width, 0);
        }
        11 => p.space.w16(descriptor, 3).unwrap(),
        12 => {
            pointer(p, descriptor + width, buffer + 1);
            p.space.w16(descriptor, 2).unwrap();
        }
        13 => pointer(p, oa + 2 * width, 1),
        14 => pointer(p, descriptor + width, 1),
        15 | 18 => {
            let absolute: Vec<_> = format!("{parent}\\{leaf}").encode_utf16().collect();
            p.space.put_wstr(buffer, &absolute).unwrap();
            p.space
                .w16(descriptor, (absolute.len() * 2) as u16)
                .unwrap();
            if case.attribute == 15 {
                pointer(p, oa + width, 0x1234);
            }
        }
        16 => pointer(p, oa + width, 0x1234),
        17 => pointer(p, oa + width, creator),
        19 | 20 => {
            p.space.w32(oa + 3 * width, 0x8000_0000).unwrap();
            if case.attribute == 20 {
                pointer(p, oa + 2 * width, 1);
            }
        }
        21 => {
            p.vm.protect(base + 4096, 4096, prot::READWRITE | prot::GUARD)
                .unwrap();
        }
        22 => {
            p.vm.protect(base + 4096, 4096, prot::NOACCESS).unwrap();
        }
        23 => {
            p.vm.protect(base + 4096, 4096, prot::READONLY).unwrap();
        }
        24 => {
            p.vm.protect(base + 8192, 4096, prot::READWRITE | prot::GUARD)
                .unwrap();
        }
        25 => {
            p.vm.protect(base + 16384, 4096, prot::READWRITE | prot::GUARD)
                .unwrap();
        }
        26 => pointer(p, oa + if p.arch.is64() { 32 } else { 16 }, 1),
        27 => pointer(p, oa + if p.arch.is64() { 40 } else { 20 }, 1),
        28 => pointer(p, oa + width, p.arch.ptr(u64::MAX)),
        29 => p.space.w16(descriptor, 65534).unwrap(),
        30 => p.space.w16(descriptor + 2, 0).unwrap(),
        31 => {
            p.space.w16(descriptor, 0).unwrap();
            pointer(p, descriptor + width, 1);
        }
        32 => {
            p.space.w32(oa + 3 * width, 0x20).unwrap();
            pointer(p, oa + 2 * width, 1);
        }
        33 => {
            p.space.w32(oa + 3 * width, 0x20).unwrap();
            p.vm.protect(buffer, 4096, prot::READWRITE | prot::GUARD)
                .unwrap();
        }
        34..=36 => {
            p.space
                .w16(
                    descriptor,
                    match case.attribute {
                        34 => 3,
                        35 => 65534,
                        _ => 65535,
                    },
                )
                .unwrap();
            pointer(p, descriptor + width, 1);
        }
        37..=39 => {
            p.space
                .w16(descriptor, if case.attribute == 38 { 65534 } else { 3 })
                .unwrap();
            p.vm.protect(
                buffer,
                4096,
                if case.attribute == 39 {
                    prot::NOACCESS
                } else {
                    prot::READWRITE | prot::GUARD
                },
            )
            .unwrap();
        }
        40..=42 => {
            p.space
                .w16(
                    descriptor,
                    match case.attribute {
                        40 => 3,
                        41 => 2,
                        _ => 4,
                    },
                )
                .unwrap();
            pointer(p, descriptor + width, base + 20478);
            p.vm.protect(base + 20480, 4096, prot::NOACCESS).unwrap();
        }
        _ => panic!("unknown native attribute case"),
    }
    oa
}

#[test]
fn native_open_event_replays_independent_fault_access_and_name_records_all_abis() {
    let mut reports: Vec<_> = [
        (
            WinArch::Arm64,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-open-event/arm64.jsonl"
            )),
        ),
        (
            WinArch::X64,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-open-event/x64.jsonl"
            )),
        ),
        (
            WinArch::X86,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-open-event/x86.jsonl"
            )),
        ),
    ]
    .into_iter()
    .map(|(arch, text)| (arch, text.to_owned(), false))
    .collect();
    if let Some(path) = std::env::var_os("RAX_OPEN_EVENT_CORPUS") {
        let path = std::path::PathBuf::from(path);
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(manifest["schema"], "rax-native-open-event-v1");
        assert_eq!(manifest["state"], "complete");
        let mut seen = std::collections::BTreeSet::new();
        for report in manifest["reports"].as_array().unwrap() {
            let label = report["architecture"].as_str().unwrap();
            assert!(seen.insert(label.to_owned()));
            let arch = match label {
                "arm64" => WinArch::Arm64,
                "x64" => WinArch::X64,
                "x86" => WinArch::X86,
                _ => panic!("unknown native process ABI: {label}"),
            };
            assert_eq!(report["file"], format!("{label}.jsonl"));
            reports.push((
                arch,
                std::fs::read_to_string(path.parent().unwrap().join(format!("{label}.jsonl")))
                    .unwrap(),
                true,
            ));
        }
        assert!((2..=3).contains(&seen.len()));
    }
    let fresh = reports.len() - 3;
    let mut compared = 0;
    let mut policy = 0;
    for (arch, report, fresh) in reports {
        let lines: Vec<serde_json::Value> = report
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(lines.len(), 509);
        let absolute =
            String::from_utf16(&hex_units(lines[0]["name_utf16"].as_str().unwrap())).unwrap();
        let parent =
            String::from_utf16(&hex_units(lines[0]["parent_utf16"].as_str().unwrap())).unwrap();
        let session = if parent == "\\BaseNamedObjects" {
            0
        } else {
            parent
                .strip_prefix("\\Sessions\\")
                .unwrap()
                .strip_suffix("\\BaseNamedObjects")
                .unwrap()
                .parse::<u32>()
                .unwrap()
        };
        let prefix = format!("{parent}\\");
        let leaf = absolute.strip_prefix(&prefix).unwrap();
        for raw in &lines[1..lines.len() - 1] {
            let case: Case = serde_json::from_value(raw.clone()).unwrap();
            assert_eq!(case.exception, 0, "{arch}: {case:?}");
            let (mut process, mut thread, _) = setup(arch);
            let p = process.state_mut();
            p.object_namespace = reparse_tests::sample(session);
            let directory = p
                .object_namespace
                .lookup(None, &parent.encode_utf16().collect::<Vec<_>>(), 0)
                .unwrap();
            let root = p.objects.open_directory(directory, false, 0xF).unwrap() as u64;
            let (manual, signaled) = if case.phase == "kind" {
                (case.index & 1 != 0, (case.index >> 1) as i32)
            } else {
                (true, 0)
            };
            let name = p
                .object_namespace
                .named_win32(session, &leaf.encode_utf16().collect::<Vec<_>>())
                .unwrap();
            let (id, _) = p
                .objects
                .try_create_native_named(name, Object::Event { manual, signaled })
                .unwrap();
            let creator = p.objects.open_access(id, false, 0x1F0003).unwrap() as u64;
            let name = p
                .object_namespace
                .named_win32(
                    session,
                    &format!("{leaf}-sem").encode_utf16().collect::<Vec<_>>(),
                )
                .unwrap();
            let (sem_id, _) = p
                .objects
                .try_create_native_named(name, Object::Semaphore { count: 0, max: 2 })
                .unwrap();
            let sem = p.objects.open_access(sem_id, false, 0x1F0003).unwrap() as u64;
            let base =
                p.vm.allocate(None, 65536, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                    .unwrap()
                    .0;
            let oa = prepare(p, base, &case, root, creator, &parent, leaf);
            let mut offset = 0;
            let output = match case.output {
                0 => base,
                1 => 0,
                2 => 1,
                3 => {
                    offset = 1;
                    base + offset
                }
                4 => {
                    offset = 4;
                    base + offset
                }
                5 | 6 => {
                    p.vm.protect(
                        base,
                        4096,
                        if case.output == 5 {
                            prot::READONLY
                        } else {
                            prot::READWRITE | prot::GUARD
                        },
                    )
                    .unwrap();
                    base
                }
                7..=9 => {
                    p.vm.protect(
                        base + 12288,
                        4096,
                        match case.output {
                            7 => prot::NOACCESS,
                            8 => prot::READWRITE | prot::GUARD,
                            _ => prot::READONLY,
                        },
                    )
                    .unwrap();
                    offset = 12284;
                    base + offset
                }
                _ => panic!("unknown native output case"),
            };
            let handles = p.objects.handle_count();
            let outcome = call(
                p,
                &mut thread,
                "NtOpenEvent",
                &[output, u64::from(case.access), oa],
            );
            if case.phase == "access" && case.access == 0x0100_0000 {
                assert_eq!(case.status, STATUS_PRIVILEGE_NOT_HELD);
                assert!(
                    matches!(outcome, Outcome::Fail(ref message) if message.contains("NT event ACCESS_SYSTEM_SECURITY privilege")),
                    "{arch}: {case:?}: {outcome:?}"
                );
                assert_eq!(p.objects.handle_count(), handles);
                assert_eq!(p.space.bytes(base, 16).unwrap(), vec![0xA5; 16]);
                policy += 1;
                continue;
            }
            assert_eq!(outcome, Outcome::Continue, "{arch}: {case:?}");
            let actual = thread.cpu.gpr(0) as u32;
            // This one observation names a foreign host event, not the private
            // observer-owned object. Fresh hosts may contain it. The guest must
            // retain its independent namespace, regardless of that host state.
            if fresh && case.phase == "name" && case.index == 5 {
                assert_eq!(actual, STATUS_OBJECT_NAME_NOT_FOUND);
                assert_eq!(p.objects.handle_count(), handles);
                let mut expected = vec![0xA5; 16];
                if arch == WinArch::X86 {
                    expected[..4].fill(0);
                }
                assert_eq!(p.space.bytes(base, 16).unwrap(), expected);
                policy += 1;
                continue;
            }
            assert_eq!(actual, case.status, "{arch}: {case:?}");
            let protections: Vec<_> = [offset, 4096, 8192, 16384]
                .iter()
                .map(|n| p.vm.query(base + n).unwrap().protect)
                .collect();
            assert_eq!(protections, case.protections, "{arch}: {case:?}");
            p.vm.protect(base, 65536, prot::READWRITE).unwrap();
            let mut bytes = p.space.bytes(base + offset, 16).unwrap();
            if actual as i32 >= 0 {
                let opened = handle(p, output);
                assert_eq!(p.objects.id(opened), Some(id), "{arch}: {case:?}");
                assert_eq!(p.objects.access(opened), Some(case.grant));
                assert_eq!(p.objects.flags(opened).unwrap() * 2, case.handle_attributes);
                if case.query == 0 {
                    assert_eq!(case.event_type, i32::from(!manual));
                    assert_eq!(case.event_state, signaled);
                    assert!(
                        matches!(p.objects.get(opened), Some(Object::Event { manual: m, signaled: s }) if *m == manual && *s == signaled)
                    );
                } else {
                    assert_eq!(case.query, STATUS_ACCESS_DENIED);
                    assert_eq!((case.event_type, case.event_state), (-99, -99));
                }
                bytes[..arch.ptr_size() as usize].fill(0x42);
                p.objects.close(opened).unwrap();
            }
            assert_eq!(bytes, hex_bytes(&case.bytes), "{arch}: {case:?}");
            assert_eq!(p.objects.handle_count(), handles, "{arch}: {case:?}");
            for h in [creator, sem, root] {
                p.objects.close(h).unwrap();
            }
            compared += 1;
        }
    }
    assert_eq!(compared, 1518 + fresh * 505);
    assert_eq!(policy, 3 + fresh * 2);
}

fn hex_bytes(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect()
}

fn hex_units(text: &str) -> Vec<u16> {
    hex_bytes(text)
        .chunks_exact(2)
        .map(|p| u16::from_le_bytes([p[0], p[1]]))
        .collect()
}
