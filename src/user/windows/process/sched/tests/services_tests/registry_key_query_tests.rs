//! Native key-body tags, result-buffer order, and stable export identity.
use super::*;

#[path = "registry_key_query_replay_tests.rs"]
mod replay;

#[cfg(windows)]
#[path = "registry_key_query_installed_tests.rs"]
mod installed;

#[test]
fn native_query_key_views_duplicates_and_snapshot_lifetime_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        let attrs = base + 2 * PAGE_SIZE;
        unicode(p, attrs + 64, attrs + 128, NLS_KEY);
        attributes(p, attrs, attrs + 64, 0, 0x240);
        let mut handles = Vec::new();
        for (view, wow_tags) in [(0, 0x400), (0x100, 0x100), (0x200, 0x600), (0x300, 0)] {
            for access in [1, 8, 0x10, 0x20000, 0x20019] {
                let opened = call(p, &mut t, "NtOpenKey", &[base, access | view, attrs]);
                if arch == WinArch::X86 && view == 0x300 {
                    assert_eq!(opened, STATUS_INVALID_PARAMETER);
                    continue;
                }
                assert_eq!(opened, STATUS_SUCCESS);
                let h = p.space.ptr(base, arch.ptr_size()).unwrap();
                let duplicate = p.objects.duplicate(h, false).unwrap() as u64;
                assert_eq!(p.objects.id(h), p.objects.id(duplicate));
                assert_eq!(call(p, &mut t, "NtClose", &[h]), STATUS_SUCCESS);
                handles.push((duplicate, if arch == WinArch::X86 { wow_tags } else { 0 }));
            }
        }
        p.registry = Registry::default();
        for (h, expected) in handles {
            for low in 0..4 {
                p.space.wr(base + 128, &[0xA5; 16]).unwrap();
                p.space.w32(base + 64, 0xA5A5_A5A5).unwrap();
                assert_eq!(
                    call(
                        p,
                        &mut t,
                        "NtQueryKey",
                        &[h | low, 7, base + 128, 4, base + 64]
                    ),
                    STATUS_SUCCESS
                );
                assert_eq!(p.space.u32(base + 128).unwrap(), expected);
                assert_eq!(p.space.u32(base + 64).unwrap(), 4);
                assert_eq!(p.space.bytes(base + 132, 12).unwrap(), vec![0xA5; 12]);
            }
            assert_eq!(call(p, &mut t, "NtClose", &[h]), STATUS_SUCCESS);
            assert_eq!(
                call(p, &mut t, "NtQueryKey", &[h, 7, base + 128, 4, base + 64]),
                STATUS_INVALID_HANDLE
            );
        }
    }
}

#[test]
fn native_query_key_appends_five_slot_export_without_moving_prior_symbols_all_abis() {
    use crate::user::windows::dll::{self, BuiltinDll};
    use crate::user::windows::hle::{Arg, Item};
    use crate::user::windows::loader::builtin;
    let current = dll::find("ntdll.dll").unwrap();
    let family = current
        .exports
        .iter()
        .position(|table| table.iter().any(|e| e.name == "NtQueryKey"))
        .unwrap();
    assert_eq!(family + 1, current.exports.len());
    let previous = BuiltinDll {
        name: current.name,
        display: current.display,
        subsystem: current.subsystem,
        exports: &current.exports[..family],
    };
    for arch in WinArch::ALL {
        let before = builtin::build(&previous, arch, 0, &[]);
        let after = builtin::build(current, arch, 0, &[]);
        assert_eq!(after.ordinal_base, before.ordinal_base);
        assert_eq!(
            &after.symbols[..before.symbols.len()],
            before.symbols.as_slice()
        );
        assert_eq!(after.symbols.len(), before.symbols.len() + 1);
        let api = dll::nt_service("NtQueryKey", arch).unwrap();
        assert_eq!(
            api.args,
            &[Arg::Ptr, Arg::I32, Arg::Ptr, Arg::I32, Arg::Ptr]
        );
        assert!(matches!(&current.exports[family][0].item, Item::Func(_)));
    }
}

fn view_corpus(arch: WinArch, rows: &[serde_json::Value]) {
    let (mut process, mut t, base) = setup(arch);
    let p = process.state_mut();
    let attrs = base + 2 * PAGE_SIZE;
    unicode(p, attrs + 64, attrs + 128, NLS_KEY);
    attributes(p, attrs, attrs + 64, 0, 0x240);
    let mut count = 0;
    for row in rows.iter().filter(|row| row["kind"] == "view") {
        let access = row["access"].as_u64().unwrap();
        let view = row["view"].as_u64().unwrap();
        let opened = call(p, &mut t, "NtOpenKey", &[base, access | view, attrs]);
        assert_eq!(
            opened as u64,
            row["open_status"].as_u64().unwrap(),
            "{arch}/access{access:x}/view{view:x}"
        );
        if opened != STATUS_SUCCESS {
            count += 1;
            continue;
        }
        let h = p.space.ptr(base, arch.ptr_size()).unwrap();
        let duplicate = p.objects.duplicate(h, false).unwrap() as u64;
        assert_eq!(call(p, &mut t, "NtClose", &[h]), STATUS_SUCCESS);
        let actual = call(
            p,
            &mut t,
            "NtQueryKey",
            &[duplicate, 7, base + 128, 4, base + 64],
        );
        assert_eq!(actual as u64, row["query_status"].as_u64().unwrap());
        assert_eq!(
            p.space.u32(base + 128).unwrap() as u64,
            row["tags"].as_u64().unwrap()
        );
        assert_eq!(
            p.space.u32(base + 64).unwrap() as u64,
            row["returned"].as_u64().unwrap()
        );
        assert_eq!(call(p, &mut t, "NtClose", &[duplicate]), STATUS_SUCCESS);
        count += 1;
    }
    assert_eq!(count, 28);
}

#[test]
fn native_query_key_replays_retained_and_fresh_view_controls() {
    let retained: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-query-key/view-controls-v4.json"
    )))
    .unwrap();
    assert_eq!(retained["state"], "complete");
    for (label, arch) in [
        ("arm64", WinArch::Arm64),
        ("x64", WinArch::X64),
        ("x86", WinArch::X86),
        ("x86-laa", WinArch::X86),
    ] {
        view_corpus(arch, retained["observations"][label].as_array().unwrap());
    }
    if let Some(path) = std::env::var_os("RAX_NATIVE_QUERY_KEY_CORPUS") {
        let fresh: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        assert_eq!(fresh["state"], "finished");
        assert_eq!(fresh["exit_code"], 0);
        for row in fresh["rows"].as_array().unwrap() {
            let arch = match row["label"].as_str().unwrap() {
                "arm64" => WinArch::Arm64,
                "x64" => WinArch::X64,
                "x86" | "x86-laa" => WinArch::X86,
                _ => panic!("unexpected native view ABI"),
            };
            let probe = &row["probes"]["v4"];
            assert_eq!(probe["build_returncode"], 0);
            assert_eq!(probe["run_returncode"], 0);
            assert_eq!(probe["exe_before_sha256"], probe["exe_after_sha256"]);
            let rows = probe["text"]
                .as_str()
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect::<Vec<_>>();
            view_corpus(arch, &rows);
        }
    }
}
