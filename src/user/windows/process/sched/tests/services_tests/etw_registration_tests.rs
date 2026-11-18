//! Installed-kernel EtwRegisterGuids capture, reply and resource matrices.
use super::*;
use crate::user::windows::nt::status::*;
use std::collections::HashMap;
#[path = "etw_provider_configuration_tests.rs"]
mod etw_provider_configuration_tests;
#[path = "etw_provider_traits_tests.rs"]
mod etw_provider_traits_tests;
const SERVICE: u32 = 0x1D6;
macro_rules! corpus {
    ($file:literal) => {
        include_str!(concat!(
            "../../../../../../../docs/specifications/windows/native-etw-register-guids/",
            $file
        ))
    };
}
#[path = "etw_registration_boundary_tests.rs"]
mod boundary_tests;
#[cfg(windows)]
#[path = "etw_registration_leaf_tests.rs"]
mod leaf_tests;

fn rows<'a>(text: &'a str, prefix: &str) -> Vec<HashMap<&'a str, &'a str>> {
    text.lines()
        .filter(|l| l.starts_with(prefix))
        .map(|l| {
            l.split_whitespace()
                .filter_map(|f| f.split_once('='))
                .collect()
        })
        .collect()
}
fn field(row: &HashMap<&str, &str>, key: &str, radix: u32) -> u64 {
    u64::from_str_radix(row[key], radix).unwrap()
}
fn hex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}
fn call(p: &mut Proc, t: &mut Thread, args: [u64; 6]) -> Outcome {
    let sp = t.cpu.sp();
    t.cpu.set_pc(0x1234_0004);
    match p.arch {
        WinArch::X86 => {
            for (i, value) in [0x1234_0004, 0x1234_0000]
                .into_iter()
                .chain(args)
                .enumerate()
            {
                p.space.w32(sp + i as u64 * 4, value as u32).unwrap();
            }
            t.cpu.set_gpr(0, SERVICE.into());
        }
        WinArch::X64 => {
            t.cpu.set_gpr(0, SERVICE.into());
            t.cpu.set_gpr(1, 0x1234_0004);
            for (i, value) in args.into_iter().enumerate() {
                if i < 4 {
                    t.cpu.set_gpr([10, 2, 8, 9][i], value);
                } else {
                    p.space.w64(sp + 40 + (i - 4) as u64 * 8, value).unwrap();
                }
            }
        }
        WinArch::Arm64 => {
            for (i, value) in args.into_iter().enumerate() {
                t.cpu.set_gpr(i, value);
            }
        }
    }
    let outcome = if p.arch == WinArch::X86 {
        super::super::super::super::services::wow64(p, t, 0x1234_0000)
    } else {
        handle_stop(p, t, stop(p.arch, SERVICE))
    };
    if outcome == Outcome::Continue {
        assert_eq!(t.cpu.pc(), 0x1234_0004);
        assert_eq!(t.cpu.sp(), sp + if p.arch == WinArch::X86 { 4 } else { 0 });
        assert!(t.frames.is_empty());
    }
    t.cpu.set_sp(sp);
    outcome
}
fn check(p: &mut Proc, t: &mut Thread, args: [u64; 6], expected: u64) {
    assert_eq!(call(p, t, args), Outcome::Continue);
    assert_eq!(t.cpu.gpr(0), expected, "{} args={args:X?}", p.arch);
}
fn scratch(p: &mut Proc, pages: u64) -> u64 {
    p.vm.allocate(
        None,
        pages * PAGE_SIZE,
        mem::RESERVE | mem::COMMIT,
        prot::READWRITE,
    )
    .unwrap()
    .0
}
fn header() -> [u8; 160] {
    let mut b = [0; 160];
    b[..16].copy_from_slice(&[
        0x21, 0xDC, 0xBC, 0xD4, 0x9A, 0x92, 0xC1, 0x43, 0x8D, 0x2D, 0x5B, 0x75, 0x38, 0xA6, 0x62,
        0xF1,
    ]);
    b[16..20].copy_from_slice(&3u32.to_le_bytes());
    b[20..24].copy_from_slice(&1u32.to_le_bytes());
    b
}
fn registration(p: &Proc, h: u64, request: &[u8]) {
    assert_eq!(p.objects.access(h), Some(0x804));
    assert_eq!(p.objects.flags(h), Some(0));
    assert!(
        matches!(p.objects.get(h),Some(Object::EtwRegistration{request:r,traits:None,..}) if r.as_slice()==request)
    );
    assert_eq!(p.objects.get(h).unwrap().type_name(), "EtwRegistration");
}
#[test]
fn native_etw_registration_replays_all_736_header_length_and_resource_rows() {
    let profiles = [
        (
            WinArch::Arm64,
            corpus!("native-etw-register-guids-matrix-arm64.log"),
        ),
        (
            WinArch::X64,
            corpus!("native-etw-register-guids-matrix-x64.log"),
        ),
        (
            WinArch::X86,
            corpus!("native-etw-register-guids-matrix-x86.log"),
        ),
        (
            WinArch::X86,
            corpus!("native-etw-register-guids-matrix-x86-laa.log"),
        ),
    ];
    let mut total = 0;
    for (arch, text) in profiles {
        let rs = rows(text, "case=");
        assert_eq!(rs.len(), 184);
        assert!(text.contains("complete cases=184"));
        let (mut process, mut t) = fixture(arch, "NtTraceControl", SERVICE);
        let p = process.state_mut();
        let b = scratch(p, 1);
        let baseline = (p.objects.handle_count(), p.objects.iter().count());
        for row in rs {
            p.space.wr(b, &vec![0; 512]).unwrap();
            let request = hex(row["input-before"]);
            p.space.wr(b, &request).unwrap();
            p.space.wr(b + 1024, &vec![0xA5; 512]).unwrap();
            p.space.w32(b + 2048, 0xA5A5A5A5).unwrap();
            p.space.w32(b + 2052, 0xB6B6B6B6).unwrap();
            let mode = field(&row, "mode", 10);
            let input = if mode == 1 { 0 } else { b };
            let output = match mode {
                2 => 0,
                3 => b,
                _ => b + 1024,
            };
            let returned = if mode == 4 { 0 } else { b + 2048 };
            let status = field(&row, "status", 16);
            check(
                p,
                &mut t,
                [
                    15,
                    input,
                    field(&row, "input-length", 10),
                    output,
                    field(&row, "output-length", 10),
                    returned,
                ],
                status,
            );
            let h = if status == 0 {
                let h = p.space.u64(output + 24).unwrap();
                registration(p, h, &request[..160]);
                h
            } else {
                0
            };
            let mut actual_input = p.space.bytes(b, 192).unwrap();
            let mut actual_output = p.space.bytes(b + 1024, 192).unwrap();
            if h != 0 {
                let slot = if mode == 3 {
                    &mut actual_input
                } else {
                    &mut actual_output
                };
                slot[24..32].copy_from_slice(&field(&row, "handle", 16).to_le_bytes());
            }
            assert_eq!(actual_input, hex(row["input-after"]), "input row={row:?}");
            assert_eq!(actual_output, hex(row["output"]), "output row={row:?}");
            assert_eq!(
                p.space.u32(b + 2048).unwrap() as u64,
                field(&row, "returned", 16)
            );
            assert_eq!(p.space.u32(b + 2052).unwrap(), 0xB6B6B6B6);
            if h != 0 {
                let id = p.objects.id(h).unwrap();
                assert!(p.objects.close(h).unwrap().is_some());
                assert!(p.objects.obj(id).is_none());
            }
            assert_eq!(
                (p.objects.handle_count(), p.objects.iter().count()),
                baseline
            );
            total += 1;
        }
    }
    assert_eq!(total, 736);
}
#[test]
fn native_etw_registration_replays_all_576_overlapping_header_and_returned_rows() {
    let profiles = [
        (
            WinArch::Arm64,
            corpus!("native-etw-register-guids-alias-duplicate-arm64.log"),
        ),
        (
            WinArch::X64,
            corpus!("native-etw-register-guids-alias-duplicate-x64.log"),
        ),
        (
            WinArch::X86,
            corpus!("native-etw-register-guids-alias-duplicate-x86.log"),
        ),
        (
            WinArch::X86,
            corpus!("native-etw-register-guids-alias-duplicate-x86-laa.log"),
        ),
    ];
    let mut total = 0;
    for (arch, text) in profiles {
        let rs = rows(text, "alias case=");
        assert_eq!(rs.len(), 144);
        let (mut process, mut t) = fixture(arch, "NtTraceControl", SERVICE);
        let p = process.state_mut();
        let b = scratch(p, 1);
        let baseline = (p.objects.handle_count(), p.objects.iter().count());
        for row in rs {
            let before = hex(row["before"]);
            assert_eq!(before.len(), 480);
            p.space.wr(b, &before).unwrap();
            let input = b + 112;
            let output = input
                .checked_add_signed(row["output-delta"].parse().unwrap())
                .unwrap();
            let returned = input
                .checked_add_signed(row["returned-delta"].parse().unwrap())
                .unwrap();
            let ids: Vec<_> = p.objects.iter().map(|(id, _)| id).collect();
            check(
                p,
                &mut t,
                [15, input, 160, output, 160, returned],
                field(&row, "status", 16),
            );
            let created: Vec<_> = p
                .objects
                .iter()
                .filter(|(id, _)| !ids.contains(id))
                .map(|(id, _)| id)
                .collect();
            assert_eq!(created.len(), 1);
            let id = created[0];
            let h = (4..=4 * (p.objects.handle_count() as u64 + 1))
                .step_by(4)
                .find(|h| p.objects.id(*h) == Some(id))
                .unwrap();
            registration(p, h, &before[112..272]);
            let mut expected = hex(row["after"]);
            let handle_bytes = h.to_le_bytes();
            for (i, byte) in handle_bytes.into_iter().enumerate() {
                let at = output + 24 + i as u64;
                if !(returned..returned + 4).contains(&at) {
                    expected[(at - b) as usize] = byte;
                }
            }
            assert_eq!(
                p.space.bytes(b, 480).unwrap(),
                expected,
                "alias row={row:?}"
            );
            assert_eq!(
                p.space.u32(returned).unwrap() as u64,
                field(&row, "returned", 16)
            );
            p.objects.close(h).unwrap();
            assert_eq!(
                (p.objects.handle_count(), p.objects.iter().count()),
                baseline
            );
            total += 1;
        }
    }
    assert_eq!(total, 576);
}
#[test]
fn native_etw_registration_replays_all_8240_simultaneous_guid_and_drain_rows() {
    let profiles = [
        (
            WinArch::Arm64,
            corpus!("native-etw-register-guids-capacity-arm64.log"),
        ),
        (
            WinArch::X64,
            corpus!("native-etw-register-guids-capacity-x64.log"),
        ),
        (
            WinArch::X86,
            corpus!("native-etw-register-guids-capacity-x86.log"),
        ),
        (
            WinArch::X86,
            corpus!("native-etw-register-guids-capacity-x86-laa.log"),
        ),
    ];
    let mut total = 0;
    for (arch, text) in profiles {
        let rs = rows(text, "case=");
        assert_eq!(rs.len(), 2060);
        assert!(text.contains("complete cases=2060"));
        let (mut process, mut t) = fixture(arch, "NtTraceControl", SERVICE);
        let p = process.state_mut();
        let b = scratch(p, 1);
        let baseline = (p.objects.handle_count(), p.objects.iter().count());
        for group in rs.chunks(1030) {
            let mut hs = vec![];
            for row in group {
                let mut request = header();
                if field(row, "unique", 10) != 0 {
                    request[..4].copy_from_slice(&(field(row, "ordinal", 10) as u32).to_le_bytes());
                }
                p.space.wr(b, &request).unwrap();
                p.space.wr(b + 512, &vec![0xA5; 160]).unwrap();
                p.space.w32(b + 1024, 0xA5A5A5A5).unwrap();
                p.space.w32(b + 1028, 0xB6B6B6B6).unwrap();
                check(
                    p,
                    &mut t,
                    [15, b, 160, b + 512, 160, b + 1024],
                    field(row, "status", 16),
                );
                let h = p.space.u64(b + 536).unwrap();
                registration(p, h, &request);
                hs.push(h);
                assert_eq!(
                    p.objects.handle_count() - baseline.0,
                    field(row, "successful", 10) as usize
                );
                assert_eq!(p.objects.iter().count() - baseline.1, hs.len());
                assert_eq!(
                    p.space.u32(b + 1024).unwrap() as u64,
                    field(row, "returned", 16)
                );
                assert_eq!(p.space.u32(b + 1028).unwrap(), 0xB6B6B6B6);
                total += 1;
            }
            for parity in 0..2 {
                for h in hs.iter().skip(parity).step_by(2) {
                    assert!(p.objects.close(*h).unwrap().is_some());
                }
            }
            assert_eq!(
                (p.objects.handle_count(), p.objects.iter().count()),
                baseline
            );
        }
    }
    assert_eq!(total, 8240);
}
#[test]
fn native_etw_registration_unknown_classes_preserve_memory_and_objects() {
    for arch in WinArch::ALL {
        let (mut process, mut t) = fixture(arch, "NtTraceControl", SERVICE);
        let p = process.state_mut();
        let b = scratch(p, 1);
        p.space.wr(b, &vec![0xA5; 512]).unwrap();
        let baseline = (p.objects.handle_count(), p.objects.iter().count());
        for function in [0, 14, 16, 26, 28, u32::MAX] {
            assert!(
                matches!(call(p,&mut t,[function.into(),1,u32::MAX.into(),1,u32::MAX.into(),1]),Outcome::Fail(message) if message.contains("NtTraceControl function"))
            );
            assert_eq!(p.space.bytes(b, 512).unwrap(), vec![0xA5; 512]);
            assert_eq!(
                (p.objects.handle_count(), p.objects.iter().count()),
                baseline
            );
        }
    }
}
fn duplicate(p: &mut Proc, t: &mut Thread, args: [u64; 7]) -> crate::user::windows::hle::ApiResult {
    use crate::user::windows::hle::{Ctx, Item};
    let api = crate::user::windows::dll::find("kernel32.dll")
        .unwrap()
        .exports
        .iter()
        .flat_map(|e| e.iter())
        .find_map(|e| match &e.item {
            Item::Func(api) if api.name == "DuplicateHandle" => Some(api),
            _ => None,
        })
        .unwrap();
    let sp = t.cpu.sp();
    for (i, arg) in args.into_iter().enumerate() {
        match p.arch {
            WinArch::X86 => p.space.w32(sp + 4 + 4 * i as u64, arg as u32).unwrap(),
            WinArch::X64 if i < 4 => t.cpu.set_gpr([1, 2, 8, 9][i], arg),
            WinArch::X64 => p.space.w64(sp + 0x28 + 8 * (i - 4) as u64, arg).unwrap(),
            WinArch::Arm64 => t.cpu.set_gpr(i, arg),
        }
    }
    let mut c = Ctx {
        p,
        t,
        api,
        entry_pc: 0x1234,
        entry_sp: sp,
        ret_addr: 0,
        cursor: sp - 256,
    };
    (api.imp)(&mut c)
}
#[test]
fn native_etw_registration_replays_all_1152_duplicate_access_close_and_output_rows() {
    use crate::user::windows::hle::{Flow, Value};
    let profiles = [
        (
            WinArch::Arm64,
            corpus!("native-etw-register-guids-duplicate-arm64.log"),
        ),
        (
            WinArch::X64,
            corpus!("native-etw-register-guids-duplicate-x64.log"),
        ),
        (
            WinArch::X86,
            corpus!("native-etw-register-guids-duplicate-x86.log"),
        ),
        (
            WinArch::X86,
            corpus!("native-etw-register-guids-duplicate-x86-laa.log"),
        ),
    ];
    let mut total = 0;
    for (arch, text) in profiles {
        let rs = rows(text, "duplicate case=");
        assert_eq!(rs.len(), 288);
        assert!(text.contains("duplicate-complete cases=288"));
        let (mut process, mut t) = fixture(arch, "NtTraceControl", SERVICE);
        let p = process.state_mut();
        let b = scratch(p, 1);
        let baseline = (p.objects.handle_count(), p.objects.iter().count());
        let request = header();
        let pseudo = if arch == WinArch::X86 {
            u64::from(u32::MAX)
        } else {
            u64::MAX
        };
        let ptr_size = if arch == WinArch::X86 { 4 } else { 8 };
        let error_at = t.teb + crate::user::windows::layout::offsets(arch).teb_last_error;
        for row in rs {
            p.space.wr(b, &request).unwrap();
            check(p, &mut t, [15, b, 160, b + 512, 160, b + 1024], 0);
            let h = p.space.u64(b + 536).unwrap();
            let id = p.objects.id(h).unwrap();
            let out = match field(&row, "output-mode", 10) {
                0 => b + 2048,
                1 => 0,
                _ => 1,
            };
            let target = if field(&row, "target-mode", 10) == 0 {
                pseudo
            } else {
                0
            };
            p.space.wptr(b + 2048, ptr_size, 0xA5A5A5A5).unwrap();
            p.space.w32(error_at, 0xB6B6B6B6).unwrap();
            let result = duplicate(
                p,
                &mut t,
                [
                    pseudo,
                    h,
                    target,
                    out,
                    field(&row, "grant", 16),
                    0,
                    field(&row, "options", 10),
                ],
            )
            .unwrap();
            assert!(
                matches!(result,Flow::Ret(Value::Int(v)) if v==field(&row,"ok",10)),
                "result row={row:?}"
            );
            assert_eq!(
                p.space.u32(error_at).unwrap() as u64,
                field(&row, "error", 16),
                "error row={row:?}"
            );
            assert_eq!(
                p.space.ptr(b + 2048, ptr_size).unwrap(),
                field(&row, "output", 16),
                "output row={row:?}"
            );
            let live = p.objects.get(h).is_some();
            assert_eq!(
                u64::from(live),
                field(&row, "source-live", 10),
                "lifetime row={row:?}"
            );
            if live {
                assert_eq!(p.objects.flags(h).unwrap() as u64, field(&row, "flags", 10));
                p.objects.close(h).unwrap();
            }
            assert!(p.objects.obj(id).is_none());
            assert_eq!(
                (p.objects.handle_count(), p.objects.iter().count()),
                baseline
            );
            total += 1;
        }
    }
    assert_eq!(total, 1152);
}
#[test]
fn native_etw_registration_independent_event_pin_and_complete_drain() {
    for arch in WinArch::ALL {
        let (mut process, mut t) = fixture(arch, "NtTraceControl", SERVICE);
        let p = process.state_mut();
        let b = scratch(p, 1);
        let request = header();
        let event = p.objects.insert(Object::Event {
            manual: true,
            signaled: 1,
        }) as u64;
        let event_id = p.objects.id(event).unwrap();
        assert_eq!(p.objects.register_etw_event(event_id), Ok(true));
        assert_eq!(p.objects.register_wnf_event(event_id), Ok(true));
        p.objects.close(event).unwrap();
        let mut hs = vec![];
        for _ in 0..4 {
            p.space.wr(b, &request).unwrap();
            check(p, &mut t, [15, b, 160, b + 512, 160, b + 1024], 0);
            let h = p.space.u64(b + 536).unwrap();
            registration(p, h, &request);
            hs.push(h);
        }
        for h in hs.iter().take(2) {
            p.objects.close(*h).unwrap();
        }
        assert!(matches!(
            p.objects.obj(event_id),
            Some(Object::Event {
                manual: true,
                signaled: 1
            })
        ));
        p.objects.drain().for_each(drop);
        assert_eq!(p.objects.handle_count(), 0);
        assert_eq!(p.objects.iter().count(), 0);
        for h in hs {
            assert!(p.objects.get(h).is_none());
        }
        let next = p.objects.insert(Object::Event {
            manual: false,
            signaled: 0,
        });
        assert_eq!(
            p.objects
                .register_etw_event(p.objects.id(next.into()).unwrap()),
            Ok(true)
        );
    }
}
#[test]
fn native_etw_registration_replays_all_640_duplicate_protection_guard_and_crossing_rows() {
    use crate::user::windows::hle::{Flow, Value};
    let profiles = [
        (
            WinArch::Arm64,
            corpus!("native-etw-register-guids-duplicate-buffers-arm64.log"),
        ),
        (
            WinArch::X64,
            corpus!("native-etw-register-guids-duplicate-buffers-x64.log"),
        ),
        (
            WinArch::X86,
            corpus!("native-etw-register-guids-duplicate-buffers-x86.log"),
        ),
        (
            WinArch::X86,
            corpus!("native-etw-register-guids-duplicate-buffers-x86-laa.log"),
        ),
    ];
    let mut total = 0;
    for (arch, text) in profiles {
        let rs = rows(text, "case=");
        assert_eq!(rs.len(), 160);
        let (mut process, mut t) = fixture(arch, "NtTraceControl", SERVICE);
        let p = process.state_mut();
        let b = scratch(p, 3);
        let baseline = (p.objects.handle_count(), p.objects.iter().count());
        let request = header();
        let pseudo = if arch == WinArch::X86 {
            u64::from(u32::MAX)
        } else {
            u64::MAX
        };
        let ptr_size = if arch == WinArch::X86 { 4 } else { 8 };
        let error_at = t.teb + crate::user::windows::layout::offsets(arch).teb_last_error;
        for row in rs {
            p.vm.protect(b, 3 * PAGE_SIZE, prot::READWRITE).unwrap();
            p.space
                .wr(b, &vec![0xA5; (2 * PAGE_SIZE) as usize])
                .unwrap();
            let aux = b + 2 * PAGE_SIZE;
            p.space.wr(aux, &request).unwrap();
            check(p, &mut t, [15, aux, 160, aux + 512, 160, aux + 1024], 0);
            let h = p.space.u64(aux + 536).unwrap();
            let id = p.objects.id(h).unwrap();
            let kind = field(&row, "kind", 10);
            let out = if kind == 4 {
                b + PAGE_SIZE - ptr_size + 2
            } else {
                b + field(&row, "offset", 10)
            };
            if (1..=3).contains(&kind) {
                p.vm.protect(
                    b,
                    PAGE_SIZE,
                    match kind {
                        1 => prot::READONLY,
                        2 => prot::NOACCESS,
                        _ => prot::READWRITE | prot::GUARD,
                    },
                )
                .unwrap();
            }
            if kind == 4 {
                p.vm.protect(b + PAGE_SIZE, PAGE_SIZE, prot::NOACCESS)
                    .unwrap();
            }
            p.space.w32(error_at, 0xB6B6B6B6).unwrap();
            let result = duplicate(
                p,
                &mut t,
                [
                    pseudo,
                    h,
                    pseudo,
                    out,
                    field(&row, "grant", 16),
                    0,
                    field(&row, "options", 10),
                ],
            )
            .unwrap();
            assert!(matches!(result,Flow::Ret(Value::Int(v)) if v==field(&row,"ok",10)));
            assert_eq!(
                p.space.u32(error_at).unwrap() as u64,
                field(&row, "error", 16),
                "error row={row:?}"
            );
            assert_eq!(
                p.vm.query(b).unwrap().protect as u64,
                field(&row, "protect", 16)
            );
            p.vm.protect(b, 2 * PAGE_SIZE, prot::READWRITE).unwrap();
            assert_eq!(
                p.space.ptr(out, ptr_size).unwrap(),
                field(&row, "output", 16),
                "output row={row:?}"
            );
            let live = p.objects.get(h).is_some();
            assert_eq!(
                u64::from(live),
                field(&row, "source-live", 10),
                "lifetime row={row:?}"
            );
            if live {
                p.objects.close(h).unwrap();
            }
            assert!(p.objects.obj(id).is_none());
            assert_eq!(
                (p.objects.handle_count(), p.objects.iter().count()),
                baseline
            );
            total += 1;
        }
    }
    assert_eq!(total, 640);
}
