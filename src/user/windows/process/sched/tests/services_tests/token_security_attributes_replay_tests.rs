//! Replay every independent native status, payload, alias and page-state row.
use super::token_security_attributes_tests::call;
use super::{Outcome, PAGE_SIZE, Proc, WinArch, fixture, mem, prot};
use crate::user::windows::memory::Mem;
use crate::user::windows::objects::Object;
use crate::user::windows::security::{
    Subject,
    token::attributes::{Attribute, Attributes, Values},
};
use crate::user::windows::{layout, wnf::Catalog};
use serde_json::Value;

pub(super) fn profile_fixture(
    arch: WinArch,
    laa: bool,
) -> (crate::user::windows::process::WindowsProcess, super::Thread) {
    if !laa {
        return fixture(arch, "NtQuerySecurityAttributesToken", 0x167);
    }
    use crate::user::windows::process::{WindowsConfig, WindowsProcess};
    assert_eq!(arch, WinArch::X86);
    let mut image =
        include_bytes!("../../../../../../../tests/fixtures/user/windows/bin/x86/smoke.exe")
            .to_vec();
    let pe = u32::from_le_bytes(image[60..64].try_into().unwrap()) as usize;
    let flags = u16::from_le_bytes(image[pe + 22..pe + 24].try_into().unwrap()) | 0x20;
    image[pe + 22..pe + 24].copy_from_slice(&flags.to_le_bytes());
    let mut config =
        WindowsConfig::embedded("C:\\attribute-replay.exe", vec![], vec![], 4096).unwrap();
    config.arena_bytes = 64 << 20;
    let mut process = WindowsProcess::spawn_image(config, image).unwrap();
    let p = process.state_mut();
    let tid = *p.threads.keys().next().unwrap();
    let mut thread = p.threads.remove(&tid).unwrap();
    thread.attached = true;
    thread.main = false;
    thread.cpu.set_sp(thread.cpu.sp() - 0x100);
    let module = p.modules.by_name("ntdll.dll").unwrap();
    p.modules.nt_services = Some((
        module,
        super::table(arch, "NtQuerySecurityAttributesToken", 0x167),
    ));
    (process, thread)
}

fn hex(row: &Value, key: &str) -> u64 {
    u64::from_str_radix(row[key].as_str().unwrap(), 16).unwrap()
}

fn decimal(row: &Value, key: &str) -> u32 {
    row[key].as_str().unwrap().parse().unwrap()
}

fn select(p: &mut Proc, attribute: Attribute) {
    let subject = Subject {
        statistics: None,
        user_attributes: 0,
        user: vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0],
        groups: vec![],
        restricted: vec![],
        app_container: false,
        privileges: vec![],
        attributes: Some(Attributes::new(vec![attribute]).unwrap()),
    };
    p.objects
        .select_wnf_catalog(Catalog::selected(vec![], subject).unwrap());
}

fn protect(p: &mut Proc, at: u64, value: u32) {
    p.vm.protect(at, PAGE_SIZE, value).unwrap();
}

fn names(p: &Proc, input: u64, mode: u32, advanced: bool) -> (u64, u32) {
    let (first, second, count) = if advanced {
        (
            if matches!(mode, 2 | 20) {
                "TSA://ProcUnique"
            } else {
                "WIN://SYSAPPID"
            },
            if mode == 20 {
                "TSA://ProcUnique"
            } else {
                "WIN://PKG"
            },
            if matches!(mode, 1 | 19) {
                0
            } else if mode == 2 {
                1
            } else {
                2
            },
        )
    } else {
        let list = match mode {
            0 => vec![],
            1 => vec![""],
            2 => vec!["WIN://SYSAPPID"],
            3 => vec!["WIN://PKG"],
            4 => vec!["WIN://BNOISOLATION"],
            5 => vec!["Assist.Probe.Absent"],
            6 => vec!["WIN://SYSAPPID", "WIN://PKG"],
            7 => vec!["TSA://ProcUnique"],
            8 => vec!["tsa://procunique"],
            9 => vec!["TSA://ProcUnique", "TSA://ProcUnique"],
            10 => vec!["TSA://ProcUnique", "WIN://SYSAPPID"],
            11 => vec!["WIN://SYSAPPID", "TSA://ProcUnique"],
            12 => vec!["TSA://ProcUnique", ""],
            13 => vec!["", "TSA://ProcUnique"],
            _ => panic!("unrecognized recorded mode"),
        };
        (
            list.first().copied().unwrap_or(""),
            list.get(1).copied().unwrap_or(""),
            list.len() as u32,
        )
    };
    let mut pointer = if count == 0 { 0 } else { input };
    if advanced {
        pointer = match mode {
            1 | 3 => 0,
            4 | 19 => 1,
            5 => input + 1,
            16 => input + PAGE_SIZE - 4,
            _ => input,
        };
    }
    let width = p.arch.ptr_size();
    for (i, text) in [first, second].into_iter().enumerate() {
        let mut buffer = input + 2 * PAGE_SIZE + if i == 0 { 64 } else { 128 };
        let value: Vec<_> = text.encode_utf16().collect();
        let mut size = value.len() as u16 * 2;
        if advanced && i == 0 {
            buffer = match mode {
                8 => 0,
                9 => 1,
                10 => buffer + 1,
                17 => input + 3 * PAGE_SIZE - 2,
                _ => buffer,
            };
            if mode == 11 {
                size -= 1;
            }
            if mode == 13 {
                size = 0;
            }
        }
        if buffer > 1 {
            p.space.put_wstr(buffer, &value).unwrap();
        }
        if pointer > 1 {
            let at = pointer + i as u64 * 2 * width;
            p.space.w16(at, size).unwrap();
            p.space
                .w16(
                    at + 2,
                    if advanced && mode == 12 && i == 0 {
                        0
                    } else {
                        value.len() as u16 * 2 + 2
                    },
                )
                .unwrap();
            if width == 8 {
                p.space.w64(at + 8, buffer).unwrap();
            } else {
                p.space.w32(at + 4, buffer as u32).unwrap();
            }
        }
    }
    (pointer, count)
}

#[test]
fn native_token_security_attributes_replays_all_22048_native_cases() {
    let data: Value = serde_json::from_str(include_str!(
        "../../../../../../../docs/specifications/windows/native-token-security-attributes/cases.json"
    )).unwrap();
    let mut calls = 0;
    for group in data["groups"].as_array().unwrap() {
        let profile = group["profile"].as_str().unwrap();
        let arch = match profile {
            "arm64" => WinArch::Arm64,
            "x64" => WinArch::X64,
            _ => WinArch::X86,
        };
        let version = group["version"].as_str().unwrap();
        let advanced = matches!(version, "v3" | "v5" | "v6");
        let (mut process, mut t) = profile_fixture(arch, profile == "x86-laa");
        let p = process.state_mut();
        let mut upcase: Vec<_> = (0..=u16::MAX).collect();
        for unit in b'a'..=b'z' {
            upcase[usize::from(unit)] = u16::from(unit - 32);
        }
        p.registry = crate::user::windows::registry::Registry::selected(upcase, vec![]).unwrap();
        let real = p.objects.insert(Object::PrimaryToken);
        let id = p.objects.create(Object::PrimaryToken);
        let denied = p.objects.open_access(id, false, 0).unwrap();
        let event = p.objects.insert(Object::Event {
            manual: true,
            signaled: 0,
        });
        for row in group["cases"].as_array().unwrap() {
            let attribute = if version == "v4b" {
                crate::user::windows::security::token::attributes::tests::fixture(decimal(
                    row, "type",
                )
                    as u16)
            } else {
                Attribute {
                    name: "TSA://ProcUnique".encode_utf16().collect(),
                    flags: 0x41,
                    values: Values::Uint64(
                        group["opaque"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|v| v.as_u64().unwrap())
                            .collect(),
                    ),
                }
            };
            select(p, attribute);
            let output = hex(row, "output");
            let length = hex(row, "length");
            let out_base = if advanced {
                hex(row, "out-base")
            } else {
                output & !0xFFFF
            };
            let input = if advanced {
                hex(row, "input")
            } else {
                0x3000_0000
            };
            let ret_base = if advanced {
                hex(row, "ret-base")
            } else {
                0x3001_0000
            };
            let allocations = [input, out_base, ret_base];
            for base in allocations {
                assert_eq!(
                    p.vm.allocate(
                        Some(base),
                        0x10000,
                        mem::RESERVE | mem::COMMIT,
                        prot::READWRITE
                    )
                    .unwrap()
                    .0,
                    base
                );
                p.space.wr(base, &vec![0xA5; 0x10000]).unwrap();
            }
            let mode = if advanced {
                decimal(row, "names-mode")
            } else if version == "v4b" {
                7
            } else {
                decimal(row, "mode")
            };
            let (names, count) = names(p, input, mode, advanced);
            if version == "v4b" {
                p.space
                    .put_wstr(
                        input + 2 * PAGE_SIZE + 64,
                        &"Assist.Fixture".encode_utf16().collect::<Vec<_>>(),
                    )
                    .unwrap();
                p.space.w16(input, 28).unwrap();
                p.space.w16(input + 2, 30).unwrap();
            }
            let rm = if advanced {
                decimal(row, "returned-mode")
            } else {
                0
            };
            let returned = match rm {
                1 => 0,
                2 => 1,
                3..=5 => ret_base,
                6 => ret_base + 1,
                7 => output,
                8 => output + 4,
                9 => ret_base + PAGE_SIZE - 2,
                _ => ret_base + PAGE_SIZE + 64,
            };
            if rm == 0 || matches!(rm, 3..=6 | 9) || (matches!(rm, 7 | 8) && output == out_base) {
                p.space.w32(returned, 0x11223344).unwrap();
            }
            if advanced {
                match mode {
                    6 => protect(p, input, prot::NOACCESS),
                    7 => protect(p, input, prot::READWRITE | prot::GUARD),
                    14 => protect(p, input + 2 * PAGE_SIZE, prot::READWRITE | prot::GUARD),
                    15 => protect(p, input + 2 * PAGE_SIZE, prot::NOACCESS),
                    16 => protect(p, input + PAGE_SIZE, prot::NOACCESS),
                    17 => protect(p, input + 3 * PAGE_SIZE, prot::NOACCESS),
                    _ => {}
                }
                match decimal(row, "output-mode") {
                    3 => protect(p, out_base, prot::READONLY),
                    4 => protect(p, out_base, prot::NOACCESS),
                    5 | 11 => protect(p, out_base, prot::READWRITE | prot::GUARD),
                    9 => protect(p, out_base, prot::READONLY | prot::GUARD),
                    _ => {}
                }
                match decimal(row, "output-mode") {
                    8 | 11 => protect(p, out_base + PAGE_SIZE, prot::NOACCESS),
                    10 => protect(p, out_base + PAGE_SIZE, prot::READWRITE | prot::GUARD),
                    _ => {}
                }
                match rm {
                    3 => protect(p, ret_base, prot::READONLY),
                    4 => protect(p, ret_base, prot::NOACCESS),
                    5 => protect(p, ret_base, prot::READWRITE | prot::GUARD),
                    9 => protect(p, ret_base + PAGE_SIZE, prot::NOACCESS),
                    _ => {}
                }
            }
            let hm = if advanced {
                decimal(row, "handle-mode")
            } else {
                0
            };
            let handle = match hm {
                0 => arch.ptr(u64::MAX - 3),
                1 => u64::from(real),
                2 => 0,
                3 => 0x13572468,
                4 => u64::from(event),
                5 => u64::from(denied),
                6 => arch.ptr(u64::MAX),
                7 => arch.ptr(u64::MAX - 1),
                8 => arch.ptr(u64::MAX - 4),
                9 => arch.ptr(u64::MAX - 5),
                _ => panic!("unrecognized recorded handle"),
            };
            let last_error = t.teb + layout::offsets(arch).teb_last_error;
            p.space.w32(last_error, 0xC0DE).unwrap();
            let before = (
                p.rng,
                p.objects.handle_count(),
                p.objects.iter().count(),
                p.vm.committed_bytes(),
            );
            assert_eq!(
                call(
                    p,
                    &mut t,
                    [handle, names, u64::from(count), output, length, returned]
                ),
                Outcome::Continue,
                "{profile}/{version}/{row}"
            );
            assert_eq!(
                t.cpu.gpr(0),
                hex(row, "status"),
                "{profile}/{version}/{row}"
            );
            assert_eq!(p.space.u32(last_error).unwrap(), 0xC0DE);
            assert_eq!(
                (
                    p.rng,
                    p.objects.handle_count(),
                    p.objects.iter().count(),
                    p.vm.committed_bytes()
                ),
                before
            );
            if advanced {
                for (base, field, pages) in [
                    (input, "input-protect", 4),
                    (out_base, "out-protect", 2),
                    (ret_base, "ret-protect", 2),
                ] {
                    for (i, expected) in row[field].as_str().unwrap().split(',').enumerate() {
                        assert!(i < pages);
                        assert_eq!(
                            p.vm.query(base + i as u64 * PAGE_SIZE).unwrap().protect,
                            u32::from_str_radix(expected, 16).unwrap(),
                            "{profile}/{version}/{row}/{field}/{i}"
                        );
                    }
                }
            }
            for base in allocations {
                p.vm.protect(base, 0x10000, prot::READWRITE).unwrap();
            }
            let valid_output = !advanced || (out_base..out_base + 8192).contains(&output);
            let dump = if valid_output { output } else { out_base };
            let expected = crate::user::windows::wnf::tests::hex(row["bytes"].as_str().unwrap());
            assert_eq!(
                p.space.bytes(dump, expected.len()).unwrap(),
                expected,
                "bytes {profile}/{version}/{}",
                row["case"]
            );
            if !advanced || row["readable"] == "1" {
                assert_eq!(
                    u64::from(p.space.u32(returned).unwrap()),
                    hex(row, if advanced { "returned" } else { "required" }),
                    "returned {profile}/{version}/{row}"
                );
            }
            for base in allocations {
                p.vm.release(base).unwrap();
            }
            calls += 1;
        }
    }
    assert_eq!(calls, 22048);
}
