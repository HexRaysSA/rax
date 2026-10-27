//! Measured AMD64 CSR startup with independent current/global section owners.
use super::*;
use crate::user::mm::SharedObject;
use crate::user::windows::object_namespace::csr::{CsrMetadata, CsrServer};
use crate::user::windows::object_namespace::data::{DataRegion, DataSection};
use crate::user::windows::object_namespace::{CapturedEntry, Namespace, SelectedDirectory};
use serde_json::Value;
use std::sync::Arc;

const SERVICE: u32 = 0x193;
#[cfg(all(windows, target_arch = "x86_64"))]
#[path = "connect_csr_leaf_tests.rs"]
mod installed;

fn captures() -> Value {
    serde_json::from_str(include_str!("../../../../../../../docs/specifications/windows/native-session-csr-connect/profiles-v3.json")).unwrap()
}
fn bytes(row: &Value, field: &str) -> Vec<u8> {
    let s = row[field].as_str().unwrap();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn word(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}
fn namespace(session: u32) -> Namespace {
    let entry = |name: &str, kind: &str| CapturedEntry {
        name: name.encode_utf16().collect(),
        kind: kind.encode_utf16().collect(),
        target: None,
        link_access: None,
        section: None,
    };
    let directory = |path: &str, entries| SelectedDirectory {
        path: path.encode_utf16().collect(),
        maximum_access: 0xF000F,
        system_security_status: STATUS_PRIVILEGE_NOT_HELD,
        force_case_insensitive: false,
        entries,
    };
    let table: Arc<[u16]> = (0..=u16::MAX)
        .map(|c| if (97..=122).contains(&c) { c - 32 } else { c })
        .collect::<Vec<_>>()
        .into();
    Namespace::selected_for_session(
        table,
        vec![
            directory(
                "\\",
                vec![
                    entry("Windows", "Directory"),
                    entry("Sessions", "Directory"),
                ],
            ),
            directory(
                "\\Windows",
                vec![
                    entry("ApiPort", "ALPC Port"),
                    entry("SharedSection", "Section"),
                ],
            ),
            directory("\\Sessions", vec![entry(&session.to_string(), "Directory")]),
            directory(
                &format!("\\Sessions\\{session}"),
                vec![entry("Windows", "Directory")],
            ),
            directory(
                &format!("\\Sessions\\{session}\\Windows"),
                vec![
                    entry("ApiPort", "ALPC Port"),
                    entry("SharedSection", "Section"),
                ],
            ),
        ],
        Some(session),
    )
    .unwrap()
}
fn data(session: Option<u32>, base: u64) -> Arc<DataSection> {
    let mut prefix = vec![0; 5 * 4096];
    prefix[40..48].copy_from_slice(&base.to_le_bytes());
    prefix[48..56].copy_from_slice(&base.to_le_bytes());
    DataSection::selected_for_session(
        session,
        0x20004,
        STATUS_PRIVILEGE_NOT_HELD,
        false,
        1 << 20,
        vec![
            DataRegion {
                offset: 0,
                size: 5 * 4096,
                bytes: Some(prefix.into()),
            },
            DataRegion {
                offset: 5 * 4096,
                size: (1 << 20) - 5 * 4096,
                bytes: None,
            },
        ],
    )
    .unwrap()
}
fn setup(p: &mut Proc, b: u64, row: &Value) -> [u64; 8] {
    let reply = bytes(row, "information_after_hex");
    let base = word(&reply, 0);
    let pid = word(&reply, 16) as u32;
    let current = data(Some(2), base);
    let global = data(None, 0x1234_0000);
    p.object_namespace = namespace(2);
    p.object_namespace.select_data_section(global).unwrap();
    p.object_namespace
        .select_data_section(current.clone())
        .unwrap();
    let kernel = (10, 0, row["kernel"][2].as_u64().unwrap() as u32);
    p.object_namespace
        .select_csr_server(
            CsrServer::selected(
                current,
                CsrMetadata {
                    arch: WinArch::X64,
                    kernel,
                    session: 2,
                    server_base: base,
                    statics_offset: 0x750,
                    server_pid: pid,
                },
            )
            .unwrap(),
        )
        .unwrap();
    Arc::make_mut(&mut p.cfg).version.major = kernel.0;
    Arc::make_mut(&mut p.cfg).version.minor = kernel.1;
    Arc::make_mut(&mut p.cfg).version.build = kernel.2;
    p.space.w32(p.peb + 0x2C0, 2).unwrap();
    packet(p, b, None, row, 2)
}
fn packet(p: &mut Proc, b: u64, section: Option<u32>, row: &Value, session: u32) -> [u64; 8] {
    let section = section.unwrap_or_else(|| {
        let backing = Arc::new(SharedObject::anonymous(65536).unwrap());
        let id = p.objects.create(Object::Mapping {
            file: None,
            size: 65536,
            protect: prot::READWRITE,
            attributes: 0x0800_0000,
            shared: Some(backing),
        });
        p.objects.open_access(id, false, 0xF001F).unwrap()
    });
    let port = if session == 0 {
        "\\Windows\\ApiPort".into()
    } else {
        format!("\\Sessions\\{session}\\Windows\\ApiPort")
    };
    name(p, b + 128, b + 256, &port);
    p.space.wr(b + 512, &bytes(row, "qos_hex")).unwrap();
    p.space
        .wr(b + 1024, &bytes(row, "client_before_hex"))
        .unwrap();
    p.space.w64(b + 1032, section.into()).unwrap();
    p.space.w32(b + 2048, 24).unwrap();
    p.space
        .wr(b + 5120, &bytes(row, "information_before_hex"))
        .unwrap();
    p.space.w32(b + 12288, 48).unwrap();
    [
        b,
        b + 128,
        b + 512,
        b + 1024,
        b + 2048,
        b + 4096,
        b + 5120,
        b + 12288,
    ]
}

fn invoke(p: &mut Proc, t: &mut Thread, args: &[u64]) -> Outcome {
    assert_eq!(args.len(), 8);
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
fn native_connect_csr_matches_measured_replies_and_owns_both_mapped_views() {
    let captures = captures();
    for row in captures["projections"].as_array().unwrap() {
        let (mut process, mut thread) = fixture(WinArch::X64, "NtConnectPort", SERVICE);
        let p = process.state_mut();
        let b = scratch(p, 65536);
        let args = setup(p, b, row);
        let before = p.vm.committed_bytes();
        let client = p.space.bytes(args[3], 32).unwrap();
        assert_eq!(invoke(p, &mut thread, &args), Outcome::Continue);
        assert_eq!(thread.cpu.gpr(0), 0);
        assert_eq!(
            p.space.bytes(args[6], 48).unwrap(),
            bytes(row, "information_after_hex")
        );
        assert_eq!(p.space.bytes(args[3], 32).unwrap(), client);
        assert_eq!(p.space.bytes(args[4], 24).unwrap(), vec![0; 24]);
        assert_eq!(p.space.u32(args[5]).unwrap(), 952);
        assert_eq!(p.space.u32(args[7]).unwrap(), 48);
        let handle = p.space.u64(args[0]).unwrap();
        let local = p.space.u64(args[3] + 32).unwrap();
        let remote = p.space.u64(args[3] + 40).unwrap();
        assert_ne!(local, remote);
        assert!(p.vm.is_shared_view(local));
        assert_eq!(p.vm.committed_bytes(), before + 65536);
        let Some(Object::LpcPort(port)) = p.objects.get(handle) else {
            panic!("owned typed endpoint")
        };
        let peer = port.peer().unwrap();
        assert_eq!(peer.base, remote);
        assert!(!peer.vm.space().same_space(&p.space));
        p.space.w32(local + 4094, 0xAABBCCDD).unwrap();
        assert_eq!(peer.vm.space().u32(remote + 4094).unwrap(), 0xAABBCCDD);
        peer.vm.space().w32(remote + 16, 0x12345678).unwrap();
        assert_eq!(p.space.u32(local + 16).unwrap(), 0x12345678);
        let base = word(&bytes(row, "information_after_hex"), 0);
        assert_eq!(peer.vm.space().u64(base + 40).unwrap(), base);
        assert!(peer.vm.space().w8(base, 1).is_err());
        let duplicate = p.objects.duplicate(handle, false).unwrap();
        p.objects.close(handle).unwrap();
        p.reclaim_scheduler_views().unwrap();
        assert!(p.vm.is_shared_view(local));
        p.objects.close(duplicate.into()).unwrap();
        p.reclaim_scheduler_views().unwrap();
        assert!(p.vm.allocation(local).is_none());
        assert_eq!(p.vm.committed_bytes(), before);
    }
}

#[test]
fn native_connect_csr_rejects_foreign_session_profile_and_geometry_without_publication() {
    let captures = captures();
    let row = &captures["projections"][0];
    for variant in 0..10 {
        let (mut process, mut thread) = fixture(WinArch::X64, "NtConnectPort", SERVICE);
        let p = process.state_mut();
        let b = scratch(p, 65536);
        let mut args = setup(p, b, row);
        match variant {
            0 => p.space.w32(p.peb + 0x2C0, 3).unwrap(),
            1 => p.space.w64(args[6] + 32, 2).unwrap(),
            2 => p.space.w32(args[2] + 4, 3).unwrap(),
            3 => p.space.w32(args[3] + 16, 1).unwrap(),
            4 => Arc::make_mut(&mut p.cfg).version.build = 26100,
            5 => args[5] = args[0],
            6 => name(p, args[1], b + 256, "\\Windows\\ApiPort"),
            7 => p.space.w64(args[3] + 24, 4096).unwrap(),
            8 => p.space.w64(args[3] + 32, 1).unwrap(),
            9 => {
                p.vm.protect(b + 12288, 4096, prot::READONLY).unwrap();
            }
            _ => unreachable!(),
        }
        let before = p.space.bytes(b, 65536).unwrap();
        let counts = (
            p.objects.handle_count(),
            p.objects.iter().count(),
            p.vm.committed_bytes(),
        );
        assert!(
            matches!(invoke(p, &mut thread, &args), Outcome::Fail(_)),
            "variant{variant}"
        );
        assert_eq!(p.space.bytes(b, 65536).unwrap(), before, "variant{variant}");
        assert_eq!(
            (
                p.objects.handle_count(),
                p.objects.iter().count(),
                p.vm.committed_bytes()
            ),
            counts,
            "variant{variant}"
        );
    }
}
