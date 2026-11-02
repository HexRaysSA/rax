//! Independent native TOKEN_STATISTICS matrices and selected-subject ownership.
use super::*;
use crate::user::windows::security::token::statistics::Statistics;
use crate::user::windows::{
    layout,
    security::{Group, Privilege, Subject},
};
use serde::Deserialize;
use std::sync::Arc;

#[derive(Deserialize)]
struct Header {
    arena: u64,
    returned_page: u64,
    required: u32,
}

#[derive(Deserialize)]
struct Case {
    index: u32,
    output: u32,
    returned: u32,
    length: u32,
    poison: u8,
    status: u32,
    exception: u32,
    handle: usize,
    boundary: u64,
    last_error: u32,
    last_status: u32,
    protections: [u32; 6],
    output_bytes: String,
    returned_bytes: String,
    arena_reconstruction_verified: bool,
}

fn decode(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks_exact(2)
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect()
}

fn selected(raw: &[u8]) -> Subject {
    let value = Statistics::selected(raw.try_into().unwrap()).unwrap();
    let mut subject = crate::user::windows::wnf::tests::empty_subject_catalog(false)
        .primary_subject()
        .unwrap()
        .as_ref()
        .clone();
    let word = |at| u32::from_le_bytes(raw[at..at + 4].try_into().unwrap()) as usize;
    assert!(word(40) <= 4096 && word(44) <= 4096);
    subject.groups = vec![
        Group {
            sid: subject.user.clone(),
            attributes: 4
        };
        word(40)
    ];
    subject.privileges = vec![
        Privilege {
            luid: 0,
            attributes: 0
        };
        word(44)
    ];
    assert!(value.matches_counts(subject.groups.len(), subject.privileges.len()));
    subject.statistics = Some(value);
    subject
}

fn destinations(p: &mut Proc, base: u64, head: &Header, row: &Case) -> (u64, u64, usize, usize) {
    p.vm.protect(base, head.arena, prot::READWRITE).unwrap();
    p.space
        .wr(base, &vec![row.poison; head.arena as usize])
        .unwrap();
    let (mut out_at, mut ret_at) = (0, head.returned_page);
    let mut output = base;
    let mut protect = |offset, flags| {
        p.vm.protect(base + offset, PAGE_SIZE, flags).unwrap();
    };
    match row.output {
        0 => {}
        1 => output = 0,
        2 => output = 1,
        3 | 4 | 13 => {
            out_at = match row.output {
                3 => 1,
                4 => 4,
                _ => 2,
            };
            output = base + out_at;
        }
        5 | 6 | 7 | 11 | 14 | 15 | 16 => protect(
            0,
            match row.output {
                5 | 16 => prot::READONLY,
                6 | 15 => prot::READWRITE | prot::GUARD,
                11 => prot::READONLY | prot::GUARD,
                _ => prot::NOACCESS,
            },
        ),
        8 | 9 | 10 | 18 => {
            out_at = 4096 - if row.boundary == 0 { 4 } else { row.boundary };
            output = base + out_at;
            protect(
                4096,
                match row.output {
                    8 => prot::NOACCESS,
                    9 => prot::READWRITE | prot::GUARD,
                    18 => prot::READONLY | prot::GUARD,
                    _ => prot::READONLY,
                },
            );
        }
        12 => {
            output = if p.arch.is64() {
                u64::MAX - 15
            } else {
                u64::from(u32::MAX - 15)
            }
        }
        17 => protect(4096, prot::NOACCESS),
        _ => panic!("unknown native output role"),
    }
    let mut returned = base + ret_at;
    match row.returned {
        0 => {}
        1 => returned = 0,
        2 => returned = 1,
        3 => {
            ret_at += 1;
            returned = base + ret_at;
        }
        4 | 5 | 6 | 12 => protect(
            head.returned_page,
            match row.returned {
                4 => prot::READONLY,
                5 => prot::READWRITE | prot::GUARD,
                12 => prot::READONLY | prot::GUARD,
                _ => prot::NOACCESS,
            },
        ),
        7..=10 => {
            ret_at = out_at
                + match row.returned {
                    7 => 0,
                    8 => 4,
                    9 => 52,
                    _ => 56,
                };
            returned = base + ret_at;
        }
        11 => {
            ret_at = head.returned_page + 4094;
            returned = base + ret_at;
            protect(head.returned_page + PAGE_SIZE, prot::NOACCESS);
        }
        _ => panic!("unknown native ReturnLength role"),
    }
    (output, returned, out_at as usize, ret_at as usize)
}

fn corpus(label: &str) -> (String, Vec<u8>) {
    if let Some(dir) = std::env::var_os("RAX_TOKEN_STATISTICS_CORPUS") {
        let dir = std::path::PathBuf::from(dir);
        return (
            std::fs::read_to_string(dir.join(format!("{label}.jsonl"))).unwrap(),
            std::fs::read(dir.join(format!("statistics-{label}.bin"))).unwrap(),
        );
    }
    macro_rules! retained {
        ($label:literal) => {
            (
                include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/docs/specifications/windows/native-token-statistics/",
                    $label,
                    ".jsonl"
                ))
                .to_owned(),
                include_bytes!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/docs/specifications/windows/native-token-statistics/statistics-",
                    $label,
                    ".bin"
                ))
                .to_vec(),
            )
        };
    }
    match label {
        "arm64" => retained!("arm64"),
        "x64" => retained!("x64"),
        "x86" => retained!("x86"),
        _ => panic!("unknown ABI"),
    }
}

#[test]
fn token_statistics_replays_complete_native_arenas_and_all_handle_fault_orders() {
    let labels: Vec<String> = if let Some(dir) = std::env::var_os("RAX_TOKEN_STATISTICS_CORPUS") {
        let m: serde_json::Value = serde_json::from_slice(
            &std::fs::read(std::path::PathBuf::from(dir).join("observations.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(m["schema"], "rax-native-token-statistics-v1");
        assert_eq!(m["state"], "complete");
        m["reports"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["architecture"].as_str().unwrap().to_owned())
            .collect()
    } else {
        vec!["arm64".into(), "x64".into(), "x86".into()]
    };
    let unique: std::collections::BTreeSet<_> = labels.iter().map(String::as_str).collect();
    assert_eq!(unique.len(), labels.len());
    assert!(unique.contains("x64") && unique.contains("x86") && unique.len() <= 3);
    let expected = labels.len() * 9412;
    let mut cases = 0;
    for label in labels {
        let arch = match label.as_str() {
            "arm64" => WinArch::Arm64,
            "x64" => WinArch::X64,
            "x86" => WinArch::X86,
            _ => unreachable!(),
        };
        let (text, raw) = corpus(&label);
        assert_eq!(raw.len(), 112);
        let mut lines = text.lines();
        let header: serde_json::Value = serde_json::from_str(lines.next().unwrap()).unwrap();
        assert_eq!(header["schema"], "rax-native-token-statistics-v1");
        let head: Header = serde_json::from_value(header).unwrap();
        assert_eq!(head.required, 56);
        assert_eq!(head.returned_page, 12288);
        assert_eq!(head.arena, 77824);
        let rows: Vec<Case> = lines
            .filter_map(|s| {
                let v: serde_json::Value = serde_json::from_str(s).unwrap();
                (v["kind"] == "case").then(|| serde_json::from_value(v).unwrap())
            })
            .collect();
        assert_eq!(rows.len(), 9412);
        let (mut process, mut t, _, old) = setup(arch, false);
        let p = process.state_mut();
        p.objects.select_wnf_catalog(
            crate::user::windows::wnf::Catalog::selected(vec![], selected(&raw[..56])).unwrap(),
        );
        let id = p.objects.id(old[1]).unwrap();
        let mut handles = [0u64; 14];
        handles[0] = old[1];
        handles[2] = 0xDEADBEEF;
        handles[3] = arch.ptr(u64::MAX);
        handles[4] = arch.ptr(u64::MAX - 1);
        handles[5] = arch.ptr(u64::MAX - 3);
        handles[6] = arch.ptr(u64::MAX - 4);
        handles[7] = arch.ptr(u64::MAX - 5);
        handles[8] = old[2];
        handles[9] = u64::from(p.objects.open_access(id, false, 16).unwrap());
        handles[10] = old[0];
        let imp = p
            .objects
            .create(Object::ImpersonationToken(Arc::new(selected(&raw[56..]))));
        handles[11] = u64::from(p.objects.open_access(imp, false, 8).unwrap());
        handles[12] = u64::from(p.objects.open_access(id, false, 8).unwrap());
        handles[13] = u64::from(p.objects.open_access(id, false, 0x20000).unwrap());
        let base =
            p.vm.allocate(
                None,
                head.arena + PAGE_SIZE,
                mem::RESERVE | mem::COMMIT,
                prot::READWRITE,
            )
            .unwrap()
            .0;
        p.vm.protect(base + head.arena, PAGE_SIZE, prot::NOACCESS)
            .unwrap();
        let sp = t.cpu.sp();
        let offsets = layout::offsets(arch);
        for row in rows {
            assert!(row.arena_reconstruction_verified && row.handle < handles.len());
            let (output, returned, out_at, ret_at) = destinations(p, base, &head, &row);
            t.cpu.set_sp(sp);
            p.space
                .w32(t.teb + offsets.teb_last_error, 0x12345678)
                .unwrap();
            p.space
                .w32(t.teb + offsets.teb_last_status, 0xC0000034)
                .unwrap();
            let message = format!(
                "{arch}/{} handle={} length={} output={} returned={} boundary={}",
                row.index, row.handle, row.length, row.output, row.returned, row.boundary
            );
            assert_eq!(
                invoke(
                    p,
                    &mut t,
                    &[
                        handles[row.handle],
                        10,
                        output,
                        u64::from(row.length),
                        returned
                    ]
                ),
                Outcome::Continue,
                "{message}"
            );
            assert_eq!(t.cpu.gpr(0), u64::from(row.status), "{message}");
            assert_eq!(row.exception, 0, "{message}");
            for (at, flags) in [
                0,
                4096,
                0,
                4096,
                head.returned_page,
                head.returned_page + PAGE_SIZE,
            ]
            .into_iter()
            .zip(row.protections)
            {
                assert_eq!(
                    p.vm.query(base + at).unwrap().protect,
                    flags,
                    "{message}/{at}"
                );
            }
            assert_eq!(
                p.vm.query(base + head.arena).unwrap().protect,
                prot::NOACCESS
            );
            p.vm.protect(base, head.arena, prot::READWRITE).unwrap();
            let mut expected = vec![row.poison; head.arena as usize];
            let out = decode(&row.output_bytes);
            let ret = decode(&row.returned_bytes);
            assert_eq!(out.len(), 56);
            assert_eq!(ret.len(), 8);
            expected[out_at..out_at + 56].copy_from_slice(&out);
            expected[ret_at..ret_at + 8].copy_from_slice(&ret);
            let actual = p.space.bytes(base, head.arena as usize).unwrap();
            assert!(
                actual == expected,
                "{message}: byte {:?}",
                actual.iter().zip(&expected).position(|(a, b)| a != b)
            );
            assert_eq!(
                p.space.u32(t.teb + offsets.teb_last_error).unwrap(),
                row.last_error,
                "{message}"
            );
            assert_eq!(
                p.space.u32(t.teb + offsets.teb_last_status).unwrap(),
                row.last_status,
                "{message}"
            );
            cases += 1;
        }
    }
    assert_eq!(cases, expected);
}

#[test]
fn token_statistics_missing_capture_and_wrong_subject_type_remain_explicit() {
    for arch in WinArch::ALL {
        let (mut process, mut t, base, handles) = setup(arch, false);
        let p = process.state_mut();
        let sp = t.cpu.sp();
        assert!(
            matches!(invoke(p,&mut t,&[handles[1],10,base,56,base+512]),Outcome::Fail(s) if s.contains("statistics are not captured"))
        );
        assert_eq!(p.space.bytes(base, 64).unwrap(), vec![0; 64]);
        let raw = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-token-statistics/statistics-arm64.bin"
        ));
        let subject = selected(&raw[56..]);
        p.objects.select_wnf_catalog(
            crate::user::windows::wnf::Catalog::selected(vec![], subject).unwrap(),
        );
        t.cpu.set_sp(sp);
        assert!(
            matches!(invoke(p,&mut t,&[handles[1],10,base,56,base+512]),Outcome::Fail(s) if s.contains("selected token type"))
        );
        assert_eq!(p.space.bytes(base, 64).unwrap(), vec![0; 64]);
    }
}

#[cfg(windows)]
#[test]
fn token_statistics_installed_ntdll_leaves_match_the_selected_host_subject() {
    let host = if cfg!(target_arch = "aarch64") {
        WinArch::Arm64
    } else if cfg!(target_arch = "x86_64") {
        WinArch::X64
    } else {
        WinArch::X86
    };
    let arches = if host == WinArch::X86 {
        vec![host]
    } else {
        vec![host, WinArch::X86]
    };
    for arch in arches {
        let (mut process, mut t, base, handles) = setup_runtime(arch, false, true);
        let p = process.state_mut();
        let value = p
            .objects
            .primary_token_subject()
            .unwrap()
            .statistics
            .expect("qualified host statistics");
        let expected = native_host_profile::primary_token_subject()
            .statistics
            .unwrap();
        assert_eq!(value, expected);
        let module = crate::user::windows::loader::load_dll(p, "ntdll.dll").unwrap();
        p.space.wr(base, &[0xa5; 1024]).unwrap();
        assert_eq!(
            super::super::virtual_memory_tests::installed::invoke(
                p,
                &mut t,
                module,
                "NtQueryInformationToken",
                &[handles[1], 10, 0, 0, base + 512]
            ),
            STATUS_BUFFER_TOO_SMALL
        );
        assert_eq!(p.space.u32(base + 512).unwrap(), 56);
        assert_eq!(
            super::super::virtual_memory_tests::installed::invoke(
                p,
                &mut t,
                module,
                "NtQueryInformationToken",
                &[handles[1], 10, base, 73, base + 512]
            ),
            0
        );
        assert_eq!(p.space.bytes(base, 56).unwrap(), value.bytes().as_slice());
        assert_eq!(p.space.bytes(base + 56, 17).unwrap(), [0xa5; 17]);
        assert_eq!(p.space.u32(base + 512).unwrap(), 56);
    }
}
