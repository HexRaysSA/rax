//! Installed-kernel security-attribute argument and guard ordering.
use super::{Outcome, PAGE_SIZE, Proc, Thread, WinArch, fixture, handle_stop, mem, prot, stop};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::{
    STATUS_ACCESS_VIOLATION, STATUS_DATATYPE_MISALIGNMENT, STATUS_GUARD_PAGE_VIOLATION,
    STATUS_INVALID_PARAMETER,
};

const SERVICE: u32 = 0x167;

pub(super) fn call(p: &mut Proc, t: &mut Thread, args: [u64; 6]) -> Outcome {
    let sp = t.cpu.sp();
    t.cpu.set_pc(0x1234_0004);
    match p.arch {
        WinArch::X86 => {
            for (index, value) in [0x1234_0004, 0x1234_0000]
                .into_iter()
                .chain(args)
                .enumerate()
            {
                p.space.w32(sp + index as u64 * 4, value as u32).unwrap();
            }
            t.cpu.set_gpr(0, SERVICE.into());
        }
        WinArch::X64 => {
            t.cpu.set_gpr(0, SERVICE.into());
            t.cpu.set_gpr(1, 0x1234_0004);
            for (register, value) in [10, 2, 8, 9].into_iter().zip(args[..4].iter().copied()) {
                t.cpu.set_gpr(register, value);
            }
            p.space.w64(sp + 40, args[4]).unwrap();
            p.space.w64(sp + 48, args[5]).unwrap();
        }
        WinArch::Arm64 => {
            for (index, value) in args.into_iter().enumerate() {
                t.cpu.set_gpr(index, value);
            }
        }
    }
    let result = if p.arch == WinArch::X86 {
        super::super::super::super::services::wow64(p, t, 0x1234_0000)
    } else {
        handle_stop(p, t, stop(p.arch, SERVICE))
    };
    if result == Outcome::Continue {
        assert_eq!(t.cpu.pc(), 0x1234_0004);
        assert_eq!(t.cpu.sp(), sp + if p.arch == WinArch::X86 { 4 } else { 0 });
        assert!(t.frames.is_empty());
    }
    t.cpu.set_sp(sp);
    result
}

#[test]
fn native_token_security_attributes_rejects_inconsistent_name_array_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t) = fixture(arch, "NtQuerySecurityAttributesToken", SERVICE);
        let p = process.state_mut();
        let returned = t.cpu.sp() - 64;
        p.space.w32(returned, 0x11223344).unwrap();
        let handle = arch.ptr(u64::MAX - 3);
        assert_eq!(
            call(p, &mut t, [handle, 0, 1, 0, 0, returned]),
            Outcome::Continue
        );
        assert_eq!(t.cpu.gpr(0), u64::from(STATUS_INVALID_PARAMETER));
        assert_eq!(p.space.u32(returned).unwrap(), 0x11223344);
    }
}

#[test]
fn native_token_security_attributes_name_capture_and_output_guard_priority_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t) = fixture(arch, "NtQuerySecurityAttributesToken", SERVICE);
        let p = process.state_mut();
        let returned = t.cpu.sp() - 64;
        let output =
            p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        p.space.w32(returned, 0x11223344).unwrap();
        p.vm.protect(output, PAGE_SIZE, prot::READWRITE | prot::GUARD)
            .unwrap();
        let handle = arch.ptr(u64::MAX - 3);
        assert_eq!(
            call(p, &mut t, [handle, 1, 2, output, 816, returned]),
            Outcome::Continue
        );
        assert_eq!(
            t.cpu.gpr(0),
            u64::from(if arch == WinArch::X86 {
                STATUS_ACCESS_VIOLATION
            } else {
                STATUS_GUARD_PAGE_VIOLATION
            })
        );
        assert_eq!(
            p.vm.query(output).unwrap().protect,
            prot::READWRITE | if arch == WinArch::X86 { prot::GUARD } else { 0 }
        );
        assert_eq!(p.space.u32(returned).unwrap(), 0x11223344);
    }
}

#[test]
fn native_token_security_attributes_returned_alignment_precedes_handle_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t) = fixture(arch, "NtQuerySecurityAttributesToken", SERVICE);
        let p = process.state_mut();
        assert_eq!(
            call(p, &mut t, [0x13572468, 0, 0, 0, 0, 1]),
            Outcome::Continue
        );
        assert_eq!(t.cpu.gpr(0), u64::from(STATUS_DATATYPE_MISALIGNMENT));
    }
}

#[test]
fn native_token_security_attributes_impersonation_alias_owns_values_without_primary_subject() {
    use crate::user::windows::objects::Object;
    use crate::user::windows::security::{
        Subject,
        token::attributes::{Attributes, tests::fixture as attribute_fixture},
    };
    use std::sync::Arc;
    for arch in WinArch::ALL {
        let (mut process, mut t) = fixture(arch, "NtQuerySecurityAttributesToken", SERVICE);
        let p = process.state_mut();
        assert!(p.objects.primary_token_subject().is_none());
        let subject = Arc::new(Subject {
            statistics: None,
            user_attributes: 0,
            user: vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0],
            groups: vec![],
            restricted: vec![],
            app_container: false,
            privileges: vec![],
            attributes: Some(Attributes::new(vec![attribute_fixture(2)]).unwrap()),
        });
        let id = p
            .objects
            .create(Object::ImpersonationToken(subject.clone()));
        let first = p.objects.open_access(id, false, 8).unwrap();
        let alias = p.objects.duplicate(u64::from(first), false).unwrap();
        p.objects.close(u64::from(first)).unwrap();
        drop(subject);
        let output = t.cpu.sp() - 512;
        let returned = output + 256;
        assert_eq!(
            call(p, &mut t, [u64::from(alias), 0, 0, output, 128, returned]),
            Outcome::Continue
        );
        assert_eq!(t.cpu.gpr(0), 0);
        assert_eq!(
            p.space.u32(returned).unwrap(),
            if arch == WinArch::X86 { 88 } else { 112 }
        );
        let values = if arch == WinArch::X86 {
            output + 64
        } else {
            output + 88
        };
        assert_eq!(p.space.u64(values).unwrap(), 0);
        assert_eq!(p.space.u64(values + 8).unwrap(), 0x0123_4567_89AB_CDEF);
        assert_eq!(p.space.u64(values + 16).unwrap(), u64::MAX);
        assert!(p.objects.primary_token_subject().is_none());
    }
}

#[test]
fn native_token_security_attributes_missing_capture_is_explicit_and_preserves_destinations() {
    use crate::user::windows::wnf;
    for arch in WinArch::ALL {
        let (mut process, mut t) = fixture(arch, "NtQuerySecurityAttributesToken", SERVICE);
        let p = process.state_mut();
        p.objects
            .select_wnf_catalog(wnf::tests::empty_subject_catalog(false));
        let output = t.cpu.sp() - 512;
        let returned = output + 256;
        p.space.wr(output, &[0xA5; 128]).unwrap();
        p.space.w32(returned, 0x11223344).unwrap();
        let result = call(
            p,
            &mut t,
            [arch.ptr(u64::MAX - 3), 0, 0, output, 128, returned],
        );
        assert!(
            matches!(result, Outcome::Fail(ref message) if message.contains("token security attributes are not captured")),
            "{result:?}"
        );
        assert_eq!(p.space.bytes(output, 128).unwrap(), vec![0xA5; 128]);
        assert_eq!(p.space.u32(returned).unwrap(), 0x11223344);
    }
}

#[test]
fn native_token_security_attributes_empty_set_matches_all_32_native_rows() {
    use crate::user::windows::security::{Subject, token::attributes::Attributes};
    use crate::user::windows::wnf::Catalog;
    let data: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../../docs/specifications/windows/native-token-security-attributes/empty-cases.json"
    )).unwrap();
    let mut calls = 0;
    for group in data["groups"].as_array().unwrap() {
        let profile = group["profile"].as_str().unwrap();
        let arch = match profile {
            "arm64" => WinArch::Arm64,
            "x64" => WinArch::X64,
            _ => WinArch::X86,
        };
        let (mut process, mut t) = super::token_security_attributes_replay_tests::profile_fixture(
            arch,
            profile == "x86-laa",
        );
        let p = process.state_mut();
        let subject = Subject {
            statistics: None,
            user_attributes: 0,
            user: vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0],
            groups: vec![],
            restricted: vec![],
            app_container: false,
            privileges: vec![],
            attributes: Some(Attributes::new(vec![]).unwrap()),
        };
        p.objects
            .select_wnf_catalog(Catalog::selected(vec![], subject).unwrap());
        let output =
            p.vm.allocate(None, 8192, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        let returned = output + 4096;
        for row in group["cases"].as_array().unwrap() {
            let number = |name: &str| u32::from_str_radix(row[name].as_str().unwrap(), 16).unwrap();
            p.space.wr(output, &[0xA5; 4096]).unwrap();
            p.space.w32(returned, 0x11223344).unwrap();
            assert_eq!(
                call(
                    p,
                    &mut t,
                    [
                        arch.ptr(u64::MAX - 3),
                        0,
                        0,
                        output,
                        u64::from(number("length")),
                        returned
                    ]
                ),
                Outcome::Continue
            );
            assert_eq!(t.cpu.gpr(0), u64::from(number("status")), "{profile}/{row}");
            assert_eq!(p.space.u32(returned).unwrap(), number("required"));
            let bytes = crate::user::windows::wnf::tests::hex(row["bytes"].as_str().unwrap());
            assert_eq!(
                p.space.bytes(output, bytes.len()).unwrap(),
                bytes,
                "{profile}/{row}"
            );
            if number("status") == 0 {
                let bytes = p.space.bytes(output, number("required") as usize).unwrap();
                assert_eq!(
                    Attributes::from_native(&bytes, output, arch.ptr_size() as usize),
                    Attributes::new(vec![])
                );
            }
            calls += 1;
        }
    }
    assert_eq!(calls, 32);
}

#[test]
fn native_token_security_attributes_upper_output_faults_match_all_576_native_rows() {
    use crate::user::windows::security::{
        Subject,
        token::attributes::{Attribute, Attributes, Values},
    };
    use crate::user::windows::{registry::Registry, wnf::Catalog};
    let corpus: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../../docs/specifications/windows/native-token-security-attributes/upper-cases.json"
    )).unwrap();
    let mut calls = 0;
    for group in corpus["groups"].as_array().unwrap() {
        let profile = group["profile"].as_str().unwrap();
        let arch = match profile {
            "arm64" => WinArch::Arm64,
            "x64" => WinArch::X64,
            _ => WinArch::X86,
        };
        let (mut process, mut t) = super::token_security_attributes_replay_tests::profile_fixture(
            arch,
            profile == "x86-laa",
        );
        let p = process.state_mut();
        let subject = Subject {
            statistics: None,
            user_attributes: 0,
            user: vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0],
            groups: vec![],
            restricted: vec![],
            app_container: false,
            privileges: vec![],
            attributes: Some(
                Attributes::new(vec![Attribute {
                    name: "TSA://ProcUnique".encode_utf16().collect(),
                    flags: 0x41,
                    // No upper-address case publishes values: only their count
                    // contributes to the independently captured native capacity.
                    values: Values::Uint64(vec![0x12345678, u64::MAX]),
                }])
                .unwrap(),
            ),
        };
        p.objects
            .select_wnf_catalog(Catalog::selected(vec![], subject).unwrap());
        let mut upcase: Vec<_> = (0..=u16::MAX).collect();
        for unit in b'a'..=b'z' {
            upcase[usize::from(unit)] = u16::from(unit - 32);
        }
        p.registry = Registry::selected(upcase, vec![]).unwrap();
        let base =
            p.vm.allocate(None, 8192, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        p.space.wr(base, &[0xA5; 4096]).unwrap();
        let text: Vec<_> = "TSA://ProcUnique".encode_utf16().collect();
        p.space.put_wstr(base + 512, &text).unwrap();
        for i in 0..2 {
            let at = base + 256 + i * arch.ptr_size() * 2;
            p.space.w16(at, 32).unwrap();
            p.space.w16(at + 2, 34).unwrap();
            if arch == WinArch::X86 {
                p.space.w32(at + 4, (base + 512) as u32).unwrap();
            } else {
                p.space.w64(at + 8, base + 512).unwrap();
            }
        }
        for row in group["cases"].as_array().unwrap() {
            let number = |name: &str| u64::from_str_radix(row[name].as_str().unwrap(), 16).unwrap();
            let mode: u32 = row["names-mode"].as_str().unwrap().parse().unwrap();
            let count = if mode == 1 {
                0
            } else if mode == 2 {
                1
            } else {
                2
            };
            let token = if row["handle-mode"] == "0" {
                arch.ptr(u64::MAX - 3)
            } else {
                0
            };
            let returned = if row["returned-mode"] == "0" {
                base + 1024
            } else {
                0
            };
            p.space.w32(base + 1024, 0x11223344).unwrap();
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
                    [
                        token,
                        if count == 0 { 0 } else { base + 256 },
                        count,
                        number("output"),
                        number("length"),
                        returned
                    ]
                ),
                Outcome::Continue,
                "{profile}/{row}"
            );
            assert_eq!(t.cpu.gpr(0), number("status"), "{profile}/{row}");
            assert_eq!(
                u64::from(p.space.u32(base + 1024).unwrap()),
                if returned == 0 {
                    0x11223344
                } else {
                    number("returned")
                },
                "{profile}/{row}"
            );
            assert_eq!(
                (
                    p.rng,
                    p.objects.handle_count(),
                    p.objects.iter().count(),
                    p.vm.committed_bytes()
                ),
                before
            );
            assert_eq!(p.space.bytes(base, 128).unwrap(), vec![0xA5; 128]);
            calls += 1;
        }
    }
    assert_eq!(calls, 576);
}

#[test]
fn native_token_security_attributes_name_budget_is_explicit_and_preserves_reached_faults() {
    use crate::user::windows::nt::status::STATUS_INVALID_HANDLE;
    for arch in WinArch::ALL {
        let (mut process, mut t) = fixture(arch, "NtQuerySecurityAttributesToken", SERVICE);
        let p = process.state_mut();
        let base =
            p.vm.allocate(None, 131072, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        let array = base + 512;
        let text = base + 65536;
        p.space.wr(text, &vec![0x41; 65534]).unwrap();
        for i in 0..17 {
            let at = array + i * 2 * arch.ptr_size();
            p.space.w16(at, 65534).unwrap();
            p.space.w16(at + 2, 65534).unwrap();
            if arch == WinArch::X86 {
                p.space.w32(at + 4, text as u32).unwrap();
            } else {
                p.space.w64(at + 8, text).unwrap();
            }
        }
        let output = base + 1024;
        let returned = base + 2048;
        // 16*65534 = 1048544 bytes, 32 below 1 MiB. The next descriptor
        // exceeds the aggregate capture budget without allocating its text.
        for (count, guarded) in [(16, false), (17, false), (17, true)] {
            if guarded {
                let at = array + 16 * 2 * arch.ptr_size() + arch.ptr_size();
                if arch == WinArch::X86 {
                    p.space.w32(at, (base + PAGE_SIZE) as u32).unwrap();
                } else {
                    p.space.w64(at, base + PAGE_SIZE).unwrap();
                }
                p.vm.protect(base + PAGE_SIZE, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                    .unwrap();
            }
            p.space.wr(output, &[0xA5; 128]).unwrap();
            p.space.w32(returned, 0x11223344).unwrap();
            let before = (
                p.rng,
                p.objects.handle_count(),
                p.objects.iter().count(),
                p.vm.committed_bytes(),
            );
            let result = call(p, &mut t, [0, array, count, output, 128, returned]);
            if count == 17 && !guarded {
                assert!(
                    matches!(result, Outcome::Fail(ref message) if message.contains("names exceed 1 MiB")),
                    "{result:?}"
                );
            } else {
                assert_eq!(result, Outcome::Continue);
                assert_eq!(
                    t.cpu.gpr(0),
                    u64::from(if guarded {
                        STATUS_GUARD_PAGE_VIOLATION
                    } else {
                        STATUS_INVALID_HANDLE
                    })
                );
            }
            assert_eq!(p.space.bytes(output, 128).unwrap(), vec![0xA5; 128]);
            assert_eq!(p.space.u32(returned).unwrap(), 0x11223344);
            assert_eq!(
                (
                    p.rng,
                    p.objects.handle_count(),
                    p.objects.iter().count(),
                    p.vm.committed_bytes()
                ),
                before
            );
            if guarded {
                assert_eq!(
                    p.vm.query(base + PAGE_SIZE).unwrap().protect,
                    prot::READWRITE
                );
            }
        }
    }
}
