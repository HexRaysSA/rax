//! The independent normal native request crosses all three guest ABI adapters.
use super::*;
use crate::user::windows::object_namespace::cache::{
    CacheMetadata, CacheServer, PORT_NAME, SECTION_BYTES, SERVICE_SID,
};
use crate::user::windows::object_namespace::{CapturedEntry, Namespace, SelectedDirectory};
use std::sync::Arc;

const SERVICE: u32 = 0x7C;

#[path = "alpc_connect_tests/map.rs"]
mod native_map;

#[path = "alpc_connect_tests/release.rs"]
mod release;

fn selected() -> Namespace {
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
    let mut namespace = Namespace::selected(
        upcase,
        vec![SelectedDirectory {
            path: vec![92],
            maximum_access: 0xF000F,
            system_security_status: STATUS_PRIVILEGE_NOT_HELD,
            force_case_insensitive: false,
            entries: vec![CapturedEntry {
                name: PORT_NAME[1..].encode_utf16().collect(),
                kind: "ALPC Port".encode_utf16().collect(),
                target: None,
                link_access: None,
                section: None,
            }],
        }],
    )
    .unwrap();
    namespace.native_machine = Some(0xAA64);
    namespace
        .select_cache_server(
            CacheServer::selected(CacheMetadata {
                kernel: (10, 0, 29704),
                native_machine: 0xAA64,
                server_pid: 0x898,
            })
            .unwrap(),
        )
        .unwrap();
    namespace
}

fn packet(p: &mut Proc, base: u64) -> [u64; 11] {
    let w = p.arch.ptr_size();
    let wow = p.arch == WinArch::X86;
    p.space.wr(base, &[0; 2048]).unwrap();
    p.space.w32(base + 128, if wow { 24 } else { 48 }).unwrap();
    p.space.wptr(base + 128 + 2 * w, w, base + 256).unwrap();
    let name: Vec<u8> = PORT_NAME
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    p.space.w16(base + 256, name.len() as u16).unwrap();
    p.space.w16(base + 258, name.len() as u16 + 2).unwrap();
    p.space.wptr(base + 256 + w, w, base + 320).unwrap();
    p.space.wr(base + 320, &name).unwrap();
    p.space.w32(base + 512, 0x80000).unwrap();
    p.space.w32(base + 516, 12).unwrap();
    p.space.wr(base + 524, &[1, 1]).unwrap();
    for (i, value) in [
        80u64,
        0,
        u32::MAX.into(),
        u32::MAX.into(),
        u32::MAX.into(),
        u32::MAX.into(),
    ]
    .into_iter()
    .enumerate()
    {
        p.space.wptr(base + 528 + i as u64 * w, w, value).unwrap();
    }
    p.space.w32(base + 528 + 6 * w, 0x80).unwrap();
    // Independent stopped-guest descriptor, including the complete service SID.
    p.space
        .wr(
            base + 768,
            &[
                1, 0, 20, 128, 0, 0, 0, 0, 0, 0, 0, 0, 20, 0, 0, 0, 52, 0, 0, 0, 2, 0, 32, 0, 1, 0,
                0, 0, 20, 0, 24, 0, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 0, 19, 0, 2, 0, 0, 0, 16, 0, 0,
                2, 0, 48, 0, 1, 0, 0, 0, 0, 0, 40, 0, 1, 0, 0, 0,
            ],
        )
        .unwrap();
    p.space.wr(base + 836, &SERVICE_SID).unwrap();
    let header = if wow { 24 } else { 40 };
    p.space.w16(base + 1024, 40).unwrap();
    p.space.w16(base + 1026, header + 40).unwrap();
    p.space.w32(base + 1024 + u64::from(header) + 8, 7).unwrap();
    p.space
        .wptr(base + 1280, w, u64::from(header) + 40)
        .unwrap();
    p.space.w32(base + 1536, 0x10000000).unwrap();
    p.space.wr(base + 1544, &[0xA5; 24]).unwrap();
    [
        base,
        base + 128,
        0,
        base + 512,
        0x20000,
        base + 768,
        base + 1024,
        base + 1280,
        0,
        base + 1536,
        0,
    ]
}

fn invoke(p: &mut Proc, t: &mut Thread, args: &[u64; 11]) -> Outcome {
    let sp = t.cpu.sp();
    super::nls_tests::arguments(p, t, args);
    if p.arch == WinArch::Arm64 {
        for (i, value) in args[8..].iter().enumerate() {
            p.space.w64(sp + i as u64 * 8, *value).unwrap();
        }
    } else {
        t.cpu.set_gpr(0, SERVICE.into());
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
fn native_alpc_connect_transfers_real_shared_section_and_typed_peer_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut thread) = fixture(arch, "NtAlpcConnectPortEx", SERVICE);
        let p = process.state_mut();
        p.object_namespace = selected();
        let b =
            p.vm.allocate(None, 4096, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        let args = packet(p, b);
        assert_eq!(invoke(p, &mut thread, &args), Outcome::Continue);
        assert_eq!(thread.cpu.gpr(0), 0);
        let w = arch.ptr_size();
        let port = p.space.ptr(b, w).unwrap();
        let section = p
            .space
            .ptr(b + 1536 + if arch.is64() { 16 } else { 12 }, w)
            .unwrap();
        assert_eq!(p.objects.access(port), Some(0x1F0001));
        assert_eq!(p.objects.access(section), Some(6));
        assert_eq!(p.objects.get(section).unwrap().type_name(), "Section");
        assert_eq!(
            p.space.u16(b + 1028).unwrap(),
            if arch.is64() { 0x200B } else { 0x300B }
        );
        let header = if arch.is64() { 40 } else { 24 };
        assert_eq!(p.space.u32(b + 1024 + header).unwrap(), 1);
        assert_eq!(p.space.u32(b + 1024 + header + 8).unwrap(), 7);
        assert_eq!(p.space.u32(b + 1540).unwrap(), 0x10000000);
        assert_eq!(p.space.u32(b + 1544).unwrap(), 0);
        if arch.is64() {
            assert_eq!(p.space.u32(b + 1548).unwrap(), 0);
        }
        let Some(Object::Mapping {
            size,
            shared: Some(backing),
            ..
        }) = p.objects.get(section)
        else {
            panic!("backed Section")
        };
        assert_eq!(*size, SECTION_BYTES);
        let backing = backing.clone();
        let view =
            p.vm.map_shared_view(backing.clone(), None, 0, SECTION_BYTES)
                .unwrap();
        let alias =
            p.vm.map_shared_view(backing, None, 0, SECTION_BYTES)
                .unwrap();
        let Some(Object::LpcPort(endpoint)) = p.objects.get(port) else {
            panic!("typed port")
        };
        assert!(endpoint.peer().is_none());
        let peer = endpoint.cache_peer().unwrap();
        p.space.w32(view.base + 4094, 0x12345678).unwrap();
        assert_eq!(peer.vm.space().u32(peer.base + 4094).unwrap(), 0x12345678);
        p.objects.close(port).unwrap();
        p.objects.close(section).unwrap();
        assert_eq!(p.space.u32(alias.base + 4094).unwrap(), 0x12345678);
        p.vm.retire_shared_view(&view).unwrap();
        p.vm.retire_shared_view(&alias).unwrap();
    }
}

#[test]
fn native_alpc_connect_unselected_profile_and_overlapping_outputs_publish_nothing() {
    for arch in WinArch::ALL {
        for overlap in [false, true] {
            let (mut process, mut thread) = fixture(arch, "NtAlpcConnectPortEx", SERVICE);
            let p = process.state_mut();
            if overlap {
                p.object_namespace = selected();
            }
            let b =
                p.vm.allocate(None, 4096, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                    .unwrap()
                    .0;
            let mut args = packet(p, b);
            if overlap {
                args[0] = args[6];
            }
            let original = p.space.bytes(b, 2048).unwrap();
            let handles = p.objects.handle_count();
            let objects = p.objects.iter().count();
            assert!(matches!(invoke(p, &mut thread, &args), Outcome::Fail(_)));
            assert_eq!(p.space.bytes(b, 2048).unwrap(), original);
            assert_eq!(p.objects.handle_count(), handles);
            assert_eq!(p.objects.iter().count(), objects);
        }
    }
}
