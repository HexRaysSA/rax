//! Nine original arguments, selected namespace and unpublished success paths.
use super::*;
use crate::user::windows::object_namespace::{CapturedEntry, Namespace, SelectedDirectory};
use std::sync::Arc;

const SERVICE: u32 = 0x194;

#[path = "secure_connect_csr_tests.rs"]
pub(super) mod csr;
#[cfg(windows)]
#[path = "secure_connect_leaf_tests.rs"]
pub(super) mod installed;
#[path = "secure_connect_readonly_tests.rs"]
mod readonly;
#[path = "secure_connect_replay_tests.rs"]
mod replay;

pub(super) fn selected_namespace() -> Namespace {
    let entry = |name: &str, kind: &str| CapturedEntry {
        name: name.encode_utf16().collect(),
        kind: kind.encode_utf16().collect(),
        target: None,
        link_access: None,
        section: None,
    };
    let upcase: Arc<[u16]> = (0..=u16::MAX)
        .map(|unit| {
            if (97..=122).contains(&unit) {
                unit - 32
            } else {
                unit
            }
        })
        .collect::<Vec<_>>()
        .into();
    Namespace::selected(
        upcase,
        vec![
            SelectedDirectory {
                path: vec![92],
                maximum_access: 0xF000F,
                system_security_status: STATUS_PRIVILEGE_NOT_HELD,
                force_case_insensitive: false,
                entries: vec![entry("Windows", "Directory"), entry("Other", "Directory")],
            },
            SelectedDirectory {
                path: "\\Windows".encode_utf16().collect(),
                maximum_access: 0xF000F,
                system_security_status: STATUS_PRIVILEGE_NOT_HELD,
                force_case_insensitive: false,
                entries: vec![
                    entry("ApiPort", "ALPC Port"),
                    entry("SharedSection", "Section"),
                ],
            },
        ],
    )
    .unwrap()
}

fn invoke(p: &mut Proc, t: &mut Thread, args: &[u64]) -> Outcome {
    assert_eq!(args.len(), 9);
    let sp = t.cpu.sp();
    t.cpu.set_pc(0x1234_0004);
    match p.arch {
        WinArch::X86 => {
            p.space.w32(sp, 0x1234_0004).unwrap();
            p.space.w32(sp + 4, 0x1234_0000).unwrap();
            for (i, &value) in args.iter().enumerate() {
                p.space.w32(sp + 8 + i as u64 * 4, value as u32).unwrap();
            }
            t.cpu.set_gpr(0, SERVICE.into());
        }
        WinArch::X64 => {
            t.cpu.set_gpr(0, SERVICE.into());
            t.cpu.set_gpr(1, 0x1234_0004);
            for (i, &value) in args.iter().enumerate() {
                if i < 4 {
                    t.cpu.set_gpr([10, 2, 8, 9][i], value);
                } else {
                    p.space.w64(sp + 40 + (i - 4) as u64 * 8, value).unwrap();
                }
            }
        }
        WinArch::Arm64 => {
            for (i, &value) in args.iter().enumerate() {
                if i < 8 {
                    t.cpu.set_gpr(i, value);
                } else {
                    p.space.w64(sp + (i - 8) as u64 * 8, value).unwrap();
                }
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

fn scratch(p: &mut Proc, bytes: u64) -> u64 {
    p.vm.allocate(None, bytes, mem::RESERVE | mem::COMMIT, prot::READWRITE)
        .unwrap()
        .0
}

fn name(p: &Proc, header: u64, buffer: u64, value: &str) {
    let units: Vec<_> = value.encode_utf16().collect();
    let bytes: Vec<_> = units.iter().flat_map(|unit| unit.to_le_bytes()).collect();
    p.space.wr(buffer, &bytes).unwrap();
    p.space.w16(header, bytes.len() as u16).unwrap();
    p.space.w16(header + 2, bytes.len() as u16).unwrap();
    p.space
        .wptr(
            header + if p.arch.is64() { 8 } else { 4 },
            p.arch.ptr_size(),
            buffer,
        )
        .unwrap();
}

#[test]
fn native_secure_connect_never_publishes_a_handle_for_unselected_or_present_servers() {
    for arch in WinArch::ALL {
        let (mut process, mut thread) = fixture(arch, "NtSecureConnectPort", SERVICE);
        let p = process.state_mut();
        let b = scratch(p, 32768);
        let initial_handles = p.objects.handle_count();
        let initial_objects = p.objects.iter().count();
        for selected in [false, true] {
            p.object_namespace = if selected {
                selected_namespace()
            } else {
                Namespace::default()
            };
            for value in ["\\Windows\\ApiPort", "\\Other\\Port"] {
                p.space.wr(b, &[0xA5; 64]).unwrap();
                name(p, b + 128, b + 256, value);
                let outcome = invoke(p, &mut thread, &[b, b + 128, 0, 0, 0, 0, 0, 0, 0]);
                let Outcome::Fail(reason) = outcome else {
                    panic!("{arch} {value}: {outcome:?}")
                };
                assert!(
                    reason.contains("unselected") || reason.contains("selected guest server"),
                    "{reason}"
                );
                assert_eq!(p.space.bytes(b, 64).unwrap(), vec![0xA5; 64]);
                assert_eq!(p.objects.handle_count(), initial_handles);
                assert_eq!(p.objects.iter().count(), initial_objects);
            }
        }
    }
}

#[test]
fn native_secure_connect_namespace_presence_preserves_type_case_and_selection_boundaries() {
    let namespace = selected_namespace();
    let lookup = |value: &str| namespace.lookup_port(&value.encode_utf16().collect::<Vec<_>>());
    assert_eq!(lookup("\\Windows\\ApiPort"), Ok(()));
    assert_eq!(
        lookup("\\Windows\\Missing"),
        Err(crate::user::windows::object_namespace::LookupError::Status(
            STATUS_OBJECT_NAME_NOT_FOUND
        ))
    );
    assert_eq!(
        lookup("\\windows\\ApiPort"),
        Err(crate::user::windows::object_namespace::LookupError::Status(
            STATUS_OBJECT_PATH_NOT_FOUND
        ))
    );
    for value in ["\\Windows", "\\Windows\\SharedSection", "\\"] {
        assert_eq!(
            lookup(value),
            Err(crate::user::windows::object_namespace::LookupError::Status(
                STATUS_OBJECT_TYPE_MISMATCH
            ))
        );
    }
    assert_eq!(
        lookup("\\Other\\Port"),
        Err(crate::user::windows::object_namespace::LookupError::Unselected)
    );
}

#[test]
fn native_secure_connect_capture_bound_is_explicit_and_publishes_no_failure_handle() {
    for arch in WinArch::ALL {
        let (mut process, mut thread) = fixture(arch, "NtSecureConnectPort", SERVICE);
        let p = process.state_mut();
        let b = scratch(p, 32768);
        p.space.wr(b, &[0xA5; 64]).unwrap();
        name(p, b + 128, b + 256, "\\Windows\\RaxLpcMissing-bounded");
        p.space.w32(b + 80, 1048577).unwrap();
        let outcome = invoke(p, &mut thread, &[b, b + 128, 0, 0, 0, 0, 0, 0, b + 80]);
        let Outcome::Fail(reason) = outcome else {
            panic!("{arch}: {outcome:?}")
        };
        assert!(reason.contains("1 MiB capture bound"), "{reason}");
        assert_eq!(p.space.bytes(b, 64).unwrap(), vec![0xA5; 64]);
        assert_eq!(p.space.u32(b + 80).unwrap(), 1048577);
    }
}

#[test]
fn native_secure_connect_invalid_sid_translation_matches_installed_ntdll() {
    assert_eq!(crate::user::windows::nt::status_to_error(0xC0000078), 1337);
}
