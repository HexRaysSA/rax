//! Frozen native controls: relocation-aware bytes, status, guards and handles.
use super::*;
use crate::user::windows::{
    registry::{HiveHeader, Lookup, UserPolicyRoot},
    security::{Privilege, Subject},
    wnf::Catalog,
};
use serde_json::Value as Json;

fn number(row: &Json, field: &str) -> u64 {
    row[field]
        .as_u64()
        .unwrap_or_else(|| panic!("missing numeric {field} in {row}"))
}
fn corpus(encoded: &[u8]) -> Vec<Json> {
    let bytes = zstd::stream::decode_all(encoded).unwrap();
    String::from_utf8(bytes)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}
fn subject(p: &mut Proc, profile: u32) {
    let subject = Subject {
        user_attributes: 0,
        user: vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0],
        groups: vec![],
        restricted: vec![],
        app_container: false,
        privileges: [17, 18]
            .into_iter()
            .enumerate()
            .map(|(index, luid)| Privilege {
                luid,
                attributes: if profile & (1 << index) != 0 { 2 } else { 0 },
            })
            .collect(),
        attributes: None,
    };
    p.objects
        .select_wnf_catalog(Catalog::selected(vec![], subject).unwrap());
}
fn put(bytes: &mut [u8], at: usize, width: usize, value: u64) {
    bytes[at..at + width].copy_from_slice(&value.to_le_bytes()[..width]);
}

// Reconstruct both address domains from the frozen producer. Comparing writes
// relative to each initialized image avoids treating native pointers/handles as
// guest addresses, including the deliberately overlapping/misaligned layouts.
fn image(
    arch: WinArch,
    base: u64,
    root: u64,
    event: u64,
    path: u64,
    role: u64,
) -> (Vec<u8>, u64, u64) {
    let width = arch.ptr_size() as usize;
    let attrs_size = if arch.is64() { 48 } else { 24 };
    let mut bytes = vec![0xA5; PAGE_SIZE as usize * 3];
    let text = match path {
        0 => NLS_KEY,
        1 => "Software\\Policies\\Microsoft\\Windows\\System",
        2 => "Software\\\\Policies\\\\Microsoft\\\\Windows\\\\System",
        _ => panic!("unselected exploratory path"),
    };
    let units: Vec<_> = text.encode_utf16().collect();
    bytes[384..384 + if arch.is64() { 16 } else { 8 }].fill(0);
    put(&mut bytes, 384, 2, (units.len() * 2) as u64);
    put(&mut bytes, 386, 2, (units.len() * 2 + 2) as u64);
    put(
        &mut bytes,
        384 + if arch.is64() { 8 } else { 4 },
        width,
        base + 512,
    );
    for (index, unit) in units.iter().chain([0].iter()).enumerate() {
        put(&mut bytes, 512 + index * 2, 2, u64::from(*unit));
    }
    bytes[256..256 + attrs_size].fill(0);
    put(&mut bytes, 256, 4, attrs_size as u64);
    put(
        &mut bytes,
        256 + width,
        width,
        if path == 0 { 0 } else { root },
    );
    put(&mut bytes, 256 + width * 2, width, base + 384);
    put(&mut bytes, 256 + width * 3, 4, 0x40);
    let mut out = base + 128;
    let mut attrs = base + 256;
    match role {
        0 => {}
        1 => out = 0,
        2 => out = 1,
        3 => out += 1,
        4 | 5 => out = base + PAGE_SIZE,
        6 | 7 => out = base + PAGE_SIZE - if role == 6 { 1 } else { 4 },
        8 => attrs = 0,
        9 => attrs = 1,
        10 => {
            bytes.copy_within(256..256 + attrs_size, 257);
            attrs += 1;
        }
        11 | 12 => put(
            &mut bytes,
            256,
            4,
            if role == 11 { 0 } else { attrs_size as u64 - 1 },
        ),
        13 => put(&mut bytes, 256 + width * 3, 4, 0x8000_0000),
        14 | 15 => put(&mut bytes, 256 + width * 2, width, u64::from(role == 15)),
        16 | 26 => {
            put(&mut bytes, 384, 2, (units.len() * 2 + 1) as u64);
            if role == 26 {
                out = 0;
            }
        }
        17 | 18 => put(
            &mut bytes,
            384 + if arch.is64() { 8 } else { 4 },
            width,
            u64::from(role == 18),
        ),
        19 | 20 => put(
            &mut bytes,
            256 + width,
            width,
            if role == 19 { 0xDEAD_BEE0 } else { event },
        ),
        21 => out = attrs,
        22 => out = base + 384,
        23 => out = base + 512,
        24 => {
            attrs = 0;
            out = 0;
        }
        25 => {
            put(&mut bytes, 256, 4, 0);
            out = 0;
        }
        27 | 28 => {
            bytes.copy_within(256..256 + attrs_size, PAGE_SIZE as usize);
            attrs = base + PAGE_SIZE;
        }
        29 => put(
            &mut bytes,
            256 + if arch.is64() { 32 } else { 16 },
            width,
            1,
        ),
        _ => panic!("unknown native role"),
    }
    (bytes, out, attrs)
}
fn policy_present(rows: &[Json]) -> bool {
    let status = rows
        .iter()
        .find(|row| {
            row["kind"] == "open"
                && number(row, "path_kind") == 1
                && number(row, "role") == 0
                && number(row, "options") == 0
                && number(row, "extended") == 0
                && number(row, "access") == 0x20019
        })
        .unwrap();
    match number(status, "status") as u32 {
        STATUS_SUCCESS => true,
        STATUS_OBJECT_NAME_NOT_FOUND => false,
        other => panic!("uncaptured policy selection status {other:x}"),
    }
}
fn replay_order(
    arch: WinArch,
    rows: &[Json],
    privilege_profile: u32,
    policy_present: bool,
    expected: (usize, usize, usize),
) {
    let machine = &rows[0];
    assert_eq!(number(machine, "page_bytes"), PAGE_SIZE);
    assert_eq!(number(machine, "pointer_bytes"), arch.ptr_size());
    let (mut process, mut t, base) = setup(arch);
    let p = process.state_mut();
    subject(p, privilege_profile);
    let sid = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
    let policy = policy_present.then_some(crate::user::windows::registry::KeyTree {
        values: vec![],
        children: vec![],
    });
    p.registry = p
        .registry
        .clone()
        .with_primary_hive(
            &sid,
            Some(HiveHeader {
                canonical: "\\REGISTRY\\USER\\.DEFAULT".encode_utf16().collect(),
                children: 9,
                values: vec![],
            }),
        )
        .unwrap()
        .with_user_policy_root(UserPolicyRoot::System, &sid, policy)
        .unwrap();
    let Lookup::Present(key) = p.registry.lookup(
        &"\\Registry\\User\\S-1-5-18"
            .encode_utf16()
            .collect::<Vec<_>>(),
    ) else {
        panic!("missing fixture hive")
    };
    let root = p.objects.insert(Object::Key(key)) as u64;
    let event = p.objects.insert(Object::Event {
        manual: true,
        signaled: 0,
    }) as u64;
    let last_error = t.teb + crate::user::windows::layout::offsets(arch).teb_last_error;
    let mut count = 0;
    let mut excluded = 0;
    let mut frontiers = 0;
    for (ordinal, pair) in rows[1..].chunks_exact(2).enumerate() {
        let row = &pair[0];
        let delta = &pair[1];
        assert_eq!(row["kind"], "open");
        assert_eq!(delta["kind"], "handle_delta");
        assert_eq!(number(delta, "ordinal"), ordinal as u64);
        let path = number(row, "path_kind");
        if path == 3 {
            // This sibling is not a selected absence. Preserve its raw native
            // record without authorizing a broader snapshot in the emulator.
            excluded += 1;
            continue;
        }
        let role = number(row, "role");
        let (initial, out, attrs) = image(arch, base, root, event, path, role);
        let (native, _, _) = image(
            arch,
            number(machine, "memory_base"),
            number(machine, "root_handle"),
            number(machine, "wrong_type_handle"),
            path,
            role,
        );
        p.vm.protect(base, PAGE_SIZE * 3, prot::READWRITE).unwrap();
        p.space.wr(base, &initial).unwrap();
        if matches!(role, 4..=7 | 27 | 28) {
            let protection = match role {
                4 => prot::READONLY,
                5 | 28 => prot::READWRITE | prot::GUARD,
                _ => prot::NOACCESS,
            };
            p.vm.protect(base + PAGE_SIZE, PAGE_SIZE, protection)
                .unwrap();
        }
        p.space.w32(last_error, 0x1234_5678).unwrap();
        let before = p.objects.handle_count();
        let extended = number(row, "extended") != 0;
        let args = [out, number(row, "access"), attrs, number(row, "options")];
        let context = format!(
            "{arch}/case{ordinal}/Ex{extended}/option{:x}/role{role}/path{path}/access{:x}",
            args[3], args[1]
        );
        let service = if extended { "NtOpenKeyEx" } else { "NtOpenKey" };
        if arch.is64() && path == 1 && role == 23 && (!extended || args[3] & !0x1C == 0) {
            // Native64 zeroes output before capturing the pathname. This alias
            // changes the selected suffix into an uncaptured relative name.
            // Native absence is not authority to invent a wider guest snapshot.
            let module = p.modules.nt_services.as_ref().unwrap().0;
            p.modules.nt_services = Some((module, table(arch, service, 0x12)));
            let sp = t.cpu.sp();
            arguments(p, &mut t, &args[..if extended { 4 } else { 3 }]);
            let outcome = dispatch(p, &mut t);
            assert!(
                matches!(outcome, Outcome::Fail(ref text) if text.contains("unsnapshotted registry subkey")),
                "{context}/{outcome:?}"
            );
            assert!(t.frames.is_empty(), "{context}");
            t.cpu.set_sp(sp);
            assert_eq!(
                number(row, "status"),
                u64::from(STATUS_OBJECT_NAME_NOT_FOUND),
                "{context}"
            );
            assert_eq!(p.objects.handle_count(), before, "{context}");
            frontiers += 1;
            continue;
        }
        let actual = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            call(p, &mut t, service, &args[..if extended { 4 } else { 3 }])
        }))
        .unwrap_or_else(|error| {
            eprintln!("native replay failed: {context}");
            std::panic::resume_unwind(error)
        });
        assert_eq!(u64::from(actual), number(row, "status"), "{context}");
        assert_eq!(number(row, "exception"), 0, "{context}");
        assert_eq!(
            p.space.u32(last_error).unwrap() as u64,
            number(row, "last_error"),
            "{context}"
        );
        assert_eq!(
            p.vm.query(base + PAGE_SIZE).unwrap().protect as u64,
            number(row, "page1_protect"),
            "{context}"
        );
        p.vm.protect(base, PAGE_SIZE * 3, prot::READWRITE).unwrap();
        if actual == STATUS_SUCCESS {
            let handle = p.space.ptr(out, arch.ptr_size()).unwrap();
            assert_eq!(
                p.objects.registry_tags(handle).unwrap() as u64,
                number(row, "tags"),
                "{context}"
            );
            let granted = p.objects.access(handle).unwrap() as u64;
            if args[1] & 0x0200_0000 != 0 && (!extended || args[3] & 4 == 0) {
                // Existing bounded read policy: retain the measured disparity,
                // rather than calling MAXIMUM_ALLOWED grant bytes native-equal.
                assert_eq!(number(row, "granted_access"), 0xF003F, "{context}");
                assert_eq!(granted, 0x20019, "{context}");
            } else {
                assert_eq!(granted, number(row, "granted_access"), "{context}");
            }
            assert_eq!(call(p, &mut t, "NtClose", &[handle]), STATUS_SUCCESS);
        }
        assert_eq!(
            p.objects.handle_count() - before,
            (number(delta, "after") - number(delta, "before")) as usize,
            "{context}"
        );
        for (field, offset) in [
            ("output", 128),
            ("attributes", 256),
            ("name", 384),
            ("boundary", PAGE_SIZE as usize - 8),
        ] {
            let hex = row[field].as_str().unwrap();
            let captured: Vec<_> = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect();
            let observed = p.space.bytes(base + offset as u64, captured.len()).unwrap();
            for (index, &byte) in captured.iter().enumerate() {
                let at = offset + index;
                let address = base + at as u64;
                if actual == STATUS_SUCCESS && (out..out + arch.ptr_size()).contains(&address) {
                    continue; // Volatile handle was independently validated above.
                }
                let expected = if byte == native[at] {
                    initial[at]
                } else {
                    byte
                };
                assert_eq!(observed[index], expected, "{context}/{field}+{index}");
            }
        }
        count += 1;
    }
    assert_eq!((count, excluded, frontiers), expected);
}
fn replay_grants(arch: WinArch, rows: &[Json]) {
    let (mut process, mut t, base) = setup(arch);
    let p = process.state_mut();
    let attrs = base + 256;
    unicode(p, base + 384, base + 512, NLS_KEY);
    attributes(p, attrs, base + 384, 0, 0x40);
    let profile_key = |row: &Json| {
        ["profile", "path", "options", "access", "view"].map(|field| number(row, field))
    };
    let tags: std::collections::BTreeMap<_, _> = rows
        .iter()
        .filter(|row| row["kind"] == "profile_tags")
        .map(|row| (profile_key(row), row))
        .collect();
    let mut current = None;
    let mut count = 0;
    for row in rows {
        if row["kind"] != "open_profile"
            || number(row, "path") != 0
            || number(row, "options") & 4 == 0
        {
            continue;
        }
        let profile = number(row, "profile") as u32;
        if current != Some(profile) {
            subject(p, profile);
            current = Some(profile);
        }
        let before = p.objects.handle_count();
        p.space
            .w32(
                t.teb + crate::user::windows::layout::offsets(arch).teb_last_error,
                0x1234_5678,
            )
            .unwrap();
        let actual = call(
            p,
            &mut t,
            "NtOpenKeyEx",
            &[
                base + 128,
                number(row, "access") | number(row, "view"),
                attrs,
                number(row, "options"),
            ],
        );
        let context = format!("{arch}/{row}");
        assert_eq!(actual as u64, number(row, "status"), "{context}");
        if actual == STATUS_SUCCESS {
            let h = p.space.ptr(base + 128, arch.ptr_size()).unwrap();
            assert_eq!(
                p.objects.access(h).unwrap() as u64,
                number(row, "granted_access"),
                "{context}"
            );
            let tags = tags[&profile_key(row)];
            assert_eq!(
                p.objects.registry_tags(h).unwrap() as u64,
                number(tags, "tags"),
                "{context}"
            );
            assert_eq!(call(p, &mut t, "NtClose", &[h]), STATUS_SUCCESS);
        }
        assert_eq!(p.objects.handle_count(), before, "{context}");
        assert_eq!(
            p.space
                .u32(t.teb + crate::user::windows::layout::offsets(arch).teb_last_error)
                .unwrap() as u64,
            number(row, "last_error"),
            "{context}"
        );
        count += 1;
    }
    assert_eq!(count, 640);
}
#[test]
fn native_open_key_ex_replays_frozen_order_bytes_guards_leaks_and_privileges() {
    macro_rules! replay {
        ($arch:expr,$label:literal) => {
            let order = corpus(include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-open-key-ex/",
                $label,
                "-29695-v3.jsonl.zst"
            )));
            let present = policy_present(&order);
            replay_order(
                $arch,
                &order,
                0,
                present,
                if $arch.is64() {
                    (3256, 32, 24)
                } else {
                    (3280, 32, 0)
                },
            );
            replay_order(
                $arch,
                &corpus(include_bytes!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/docs/specifications/windows/native-open-key-ex/",
                    $label,
                    "-29695-v7.jsonl.zst"
                ))),
                0,
                present,
                if $arch.is64() {
                    (710, 0, 10)
                } else {
                    (720, 0, 0)
                },
            );
            replay_grants(
                $arch,
                &corpus(include_bytes!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/docs/specifications/windows/native-open-key-ex/",
                    $label,
                    "-29695-v5.jsonl.zst"
                ))),
            );
        };
    }
    replay!(WinArch::Arm64, "arm64");
    replay!(WinArch::X64, "x64");
    replay!(WinArch::X86, "x86");
    replay!(WinArch::X86, "x86-laa");
}

#[test]
fn native_open_key_ex_replays_fresh_controls_when_requested() {
    let order = std::env::var_os("RAX_NATIVE_OPEN_KEY_EX_ORDER");
    let grants = std::env::var_os("RAX_NATIVE_OPEN_KEY_EX_GRANTS");
    let views = std::env::var_os("RAX_NATIVE_OPEN_KEY_EX_VIEWS");
    if order.is_none() && grants.is_none() && views.is_none() {
        eprintln!("fresh NtOpenKeyEx controls not requested; zero fresh cases");
        return; // Retained controls always run in the separate test above.
    }
    let order: Json = serde_json::from_slice(&std::fs::read(order.unwrap()).unwrap()).unwrap();
    let grants: Json = serde_json::from_slice(&std::fs::read(grants.unwrap()).unwrap()).unwrap();
    let views: Json = serde_json::from_slice(&std::fs::read(views.unwrap()).unwrap()).unwrap();
    for receipt in [&order, &grants, &views] {
        assert_eq!(receipt["state"], "finished");
        assert_eq!(number(receipt, "exit_code"), 0);
        assert_eq!(
            number(receipt, "native_machine"),
            number(&order, "native_machine")
        );
    }
    let mut count = 0;
    for entry in order["rows"].as_array().unwrap() {
        let label = entry["label"].as_str().unwrap();
        let arch = match label {
            "arm64" => WinArch::Arm64,
            "x64" => WinArch::X64,
            "x86" | "x86-laa" => WinArch::X86,
            _ => panic!("unexpected capture label {label}"),
        };
        let paired = grants["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["label"] == label)
            .unwrap();
        let parse = |item: &Json, version: &str| -> Vec<Json> {
            let probe = &item["probes"][version];
            assert_eq!(number(probe, "run_returncode"), 0);
            assert_eq!(probe["exe_before_sha256"], probe["exe_after_sha256"]);
            assert_eq!(probe["source_sha256"], probe["source_after_sha256"]);
            probe["text"]
                .as_str()
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect()
        };
        let grant_rows = parse(paired, "v5");
        let machine = &grant_rows[0];
        let profile = u32::from(number(machine, "original_backup") & 2 != 0)
            | (u32::from(number(machine, "original_restore") & 2 != 0) << 1);
        let order_rows = parse(entry, "v3");
        let present = policy_present(&order_rows);
        replay_order(
            arch,
            &order_rows,
            profile,
            present,
            if arch.is64() {
                (3256, 32, 24)
            } else {
                (3280, 32, 0)
            },
        );
        let view_entry = views["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["label"] == label)
            .unwrap();
        replay_order(
            arch,
            &parse(view_entry, "v7"),
            profile,
            present,
            if arch.is64() {
                (710, 0, 10)
            } else {
                (720, 0, 0)
            },
        );
        replay_grants(arch, &grant_rows);
        count += 1;
    }
    assert_eq!(
        count,
        if number(&order, "native_machine") == 0xAA64 {
            4
        } else {
            3
        }
    );
    eprintln!(
        "fresh NtOpenKeyEx: {count} ABIs; {} open-order/view cases including explicit namespace frontiers, and {} privilege cases",
        count * 4000,
        count * 640
    );
}
