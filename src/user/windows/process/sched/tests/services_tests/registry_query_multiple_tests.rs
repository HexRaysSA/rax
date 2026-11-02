//! Lossless replay of independently measured native bulk registry queries.
use super::*;
use crate::user::windows::layout;
use serde_json::Value as Json;

#[path = "registry_query_multiple_input.rs"]
mod input;

#[path = "registry_query_multiple_overflow_tests.rs"]
mod overflow;

#[cfg(windows)]
#[path = "registry_query_multiple_installed_tests.rs"]
mod installed;

struct Case<'a> {
    report: &'a Json,
    row: &'a Json,
}

impl Case<'_> {
    fn optional_number(&self, key: &str, default: u64) -> u64 {
        if self.report["columns"]
            .as_array()
            .unwrap()
            .iter()
            .any(|name| name == key)
        {
            self.get(key).as_u64().unwrap_or(default)
        } else {
            default
        }
    }

    fn get(&self, key: &str) -> &Json {
        let column = self.report["columns"]
            .as_array()
            .unwrap()
            .iter()
            .position(|name| name == key)
            .unwrap();
        &self.report["values"][column][self.row[column].as_u64().unwrap() as usize]
    }

    fn number(&self, key: &str) -> u64 {
        self.get(key).as_u64().unwrap()
    }
}

fn replay(corpus: &Json) -> usize {
    assert_eq!(
        corpus["schema"],
        "rax-native-query-multiple-values-columnar-v1"
    );
    let mut checked = 0;
    for report in corpus["reports"].as_array().unwrap() {
        let arch = match report["architecture"].as_str().unwrap() {
            "arm64" => WinArch::Arm64,
            "x64" => WinArch::X64,
            "x86" => WinArch::X86,
            other => panic!("unknown oracle ABI: {other}"),
        };
        let cases = if let Some(reference) = report["case_set"].as_str() {
            corpus["reports"]
                .as_array()
                .unwrap()
                .iter()
                .find(|candidate| candidate["architecture"] == reference)
                .unwrap()
        } else {
            report
        };
        let (mut process, mut t, _) = setup(arch);
        let p = process.state_mut();
        let base = report["host"]["arena_base"].as_u64().unwrap();
        assert_eq!(
            p.vm.allocate(
                Some(base),
                65536 + PAGE_SIZE,
                mem::RESERVE | mem::COMMIT,
                prot::READWRITE
            )
            .unwrap()
            .0,
            base
        );
        let handles = input::handles(p);
        p.registry = Registry::default();
        let kernel = report["host"]["kernel"].as_array().unwrap();
        super::super::native_profile::kernel_profile(
            p,
            kernel[2].as_u64().unwrap() as u32,
            report["native_machine"].as_u64().unwrap() as u16,
        );
        p.native.as_mut().unwrap().version.major = kernel[0].as_u64().unwrap() as u32;
        p.native.as_mut().unwrap().version.minor = kernel[1].as_u64().unwrap() as u32;
        let offsets = layout::offsets(arch);
        for (index, row) in cases["rows"].as_array().unwrap().iter().enumerate() {
            let case = Case { report: cases, row };
            assert_eq!(case.number("exception"), 0);
            assert_eq!(case.get("arena_reconstruction_verified"), true);
            let (initial, protections) = input::arena(&case, arch, base);
            p.vm.protect(base, 65536 + PAGE_SIZE, prot::READWRITE)
                .unwrap();
            p.space.wr(base, &initial).unwrap();
            for (page, protection) in protections.into_iter().enumerate() {
                p.vm.protect(base + page as u64 * PAGE_SIZE, PAGE_SIZE, protection)
                    .unwrap();
            }
            p.space
                .w32(t.teb + offsets.teb_last_error, 0x1234_5678)
                .unwrap();
            p.space
                .w32(
                    t.teb + offsets.teb_last_status,
                    STATUS_OBJECT_NAME_NOT_FOUND,
                )
                .unwrap();
            let args = case.get("arguments").as_array().unwrap();
            let actual = call(
                p,
                &mut t,
                "NtQueryMultipleValueKey",
                &[
                    handles[case.number("handle") as usize],
                    args[0].as_u64().unwrap(),
                    case.number("count"),
                    args[1].as_u64().unwrap(),
                    args[2].as_u64().unwrap(),
                    args[3].as_u64().unwrap(),
                ],
            );
            assert_eq!(
                u64::from(actual),
                case.number("status"),
                "{arch}/{index}/{}",
                case.get("phase")
            );
            assert_eq!(
                u64::from(p.space.u32(t.teb + offsets.teb_last_error).unwrap()),
                case.number("last_error"),
                "{arch}/{index}/last error"
            );
            assert_eq!(
                u64::from(p.space.u32(t.teb + offsets.teb_last_status).unwrap()),
                case.number("last_status"),
                "{arch}/{index}/last status"
            );
            let mut expected = initial;
            for (region, key) in ["entries", "data", "length", "required"]
                .into_iter()
                .enumerate()
            {
                let at = case.get("watch_offsets")[region].as_u64().unwrap() as usize;
                let bytes = input::unhex(case.get(key).as_str().unwrap());
                expected[at..at + bytes.len()].copy_from_slice(&bytes);
            }
            if case.report["columns"]
                .as_array()
                .unwrap()
                .iter()
                .any(|name| name == "arena_after")
            {
                if let Some(raw) = case.get("arena_after").as_str() {
                    expected = input::unhex(raw);
                }
            }
            let mut observed = vec![0; 65536];
            p.space.read_raw(base, &mut observed).unwrap();
            if observed != expected {
                let at = observed
                    .iter()
                    .zip(&expected)
                    .position(|(a, b)| a != b)
                    .unwrap();
                panic!(
                    "{arch}/{index}/arena offset {at:#x}: actual={:#x} expected={:#x}",
                    observed[at], expected[at]
                );
            }
            for page in 0..17 {
                assert_eq!(
                    u64::from(p.vm.query(base + page as u64 * PAGE_SIZE).unwrap().protect),
                    case.get("protections")[page].as_u64().unwrap(),
                    "{arch}/{index}/page{page}"
                );
            }
            checked += 1;
        }
        assert_eq!(
            cases["rows"].as_array().unwrap().len() as u64,
            report["records"].as_u64().unwrap()
        );
    }
    assert_eq!(checked as u64, corpus["native_calls"].as_u64().unwrap());
    checked
}

#[test]
fn native_query_multiple_value_key_replays_all_retained_and_fresh_calls() {
    let retained: Json = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-query-multiple-values/controls-v6.json"
    )))
    .unwrap();
    assert_eq!(replay(&retained), 148956);
    if let Some(path) = std::env::var_os("RAX_NATIVE_QUERY_MULTIPLE_VALUE_KEY_CORPUS") {
        let fresh: Json = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert!(replay(&fresh) > 0);
    }
}

#[test]
fn native_query_multiple_value_key_appends_six_slots_and_preserves_prior_exports() {
    use crate::user::windows::dll::{self, BuiltinDll};
    use crate::user::windows::hle::Arg;
    use crate::user::windows::loader::builtin;
    let current = dll::find("ntdll.dll").unwrap();
    let family = current
        .exports
        .iter()
        .position(|table| table.iter().any(|e| e.name == "NtQueryMultipleValueKey"))
        .unwrap();
    assert_eq!(current.exports[family - 1][0].name, "NtOpenEvent");
    let previous = BuiltinDll {
        name: current.name,
        display: current.display,
        subsystem: current.subsystem,
        exports: &current.exports[..family],
    };
    let appended = BuiltinDll {
        exports: &current.exports[..=family],
        ..previous
    };
    for arch in WinArch::ALL {
        let before = builtin::build(&previous, arch, 0, &[]);
        let after = builtin::build(&appended, arch, 0, &[]);
        assert_eq!(after.ordinal_base, before.ordinal_base);
        assert_eq!(
            &after.symbols[..before.symbols.len()],
            before.symbols.as_slice()
        );
        assert_eq!(after.symbols.len(), before.symbols.len() + 1);
        assert_eq!(
            dll::nt_service("NtQueryMultipleValueKey", arch)
                .unwrap()
                .args,
            &[Arg::Ptr, Arg::Ptr, Arg::I32, Arg::Ptr, Arg::Ptr, Arg::Ptr]
        );
    }
}
