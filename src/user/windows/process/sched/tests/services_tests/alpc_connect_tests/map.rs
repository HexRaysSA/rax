//! Independent current-kernel mapping results cross the actual guest SVC path.
use super::super::section_map_tests::{call, get, ptr, scratch};
use super::*;

fn number(row: &serde_json::Value, name: &str, radix: u32) -> u64 {
    u64::from_str_radix(row[name].as_str().unwrap(), radix).unwrap()
}

#[test]
fn native_cache_section_replays_all_36_direct_mapping_results_and_owned_view_lifetimes() {
    let capture: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-alpc-connect-ex-cache/native-controls-v1.json"
    )))
    .unwrap();
    assert_eq!(capture["kernel"], "10.0.29704.0");
    let mut cases = 0;
    for profile in capture["profiles"].as_array().unwrap() {
        let arch = match profile["architecture"].as_str().unwrap() {
            "arm64" => WinArch::Arm64,
            "x64" => WinArch::X64,
            "x86" => WinArch::X86,
            other => panic!("unexpected native caller {other}"),
        };
        for row in profile["maps"].as_array().unwrap() {
            let (mut process, mut thread) = fixture(arch, "NtMapViewOfSection", 0x28);
            let p = process.state_mut();
            let b = scratch(p);
            let server = selected()
                .cache_server(&PORT_NAME.encode_utf16().collect::<Vec<_>>())
                .unwrap();
            let peer = server.peer().unwrap();
            let id = p.objects.create(Object::Mapping {
                file: None,
                size: SECTION_BYTES,
                protect: prot::READWRITE,
                attributes: 0x0800_0000,
                shared: Some(peer.backing.clone()),
            });
            let handle = p.objects.open_access(id, false, 6).unwrap();
            let before = p.vm.committed_bytes();
            let requested = number(row, "requested", 10);
            let protection = number(row, "protection", 16);
            ptr(p, b, 0);
            ptr(p, b + 16, requested);
            let status = call(
                p,
                &mut thread,
                &[
                    handle.into(),
                    arch.ptr(u64::MAX),
                    b,
                    0,
                    0,
                    0,
                    b + 16,
                    2,
                    0,
                    protection,
                ],
            );
            assert_eq!(u64::from(status), number(row, "status", 16), "{arch} {row}");
            assert_eq!(get(p, b + 16), number(row, "returned_size", 10));
            let base = get(p, b);
            if status == STATUS_SUCCESS {
                assert_ne!(base, 0);
                let region = p.vm.query(base).unwrap();
                assert_eq!(region.size, number(row, "region_bytes", 10));
                assert_eq!(u64::from(region.protect), number(row, "view_protect", 16));
                assert_eq!(
                    u64::from(region.allocation_protect),
                    number(row, "allocation_protect", 16)
                );
                assert_eq!(p.space.u32(base).unwrap(), 0);
                assert!(p.vm.is_shared_view(base));
                if protection == u64::from(prot::READONLY) {
                    assert!(p.space.w32(base, 7).is_err());
                } else {
                    p.space.w32(base, 0x1122_3344).unwrap();
                    assert_eq!(peer.vm.space().u32(peer.base).unwrap(), 0x1122_3344);
                }
                peer.vm.space().w32(peer.base, 0xAABB_CCDD).unwrap();
                assert_eq!(p.space.u32(base).unwrap(), 0xAABB_CCDD);
                p.objects.close(handle.into()).unwrap();
                drop(peer);
                assert_eq!(p.space.u32(base).unwrap(), 0xAABB_CCDD);
                let module = p.modules.nt_services.as_ref().unwrap().0;
                p.modules.nt_services = Some((module, table(arch, "NtUnmapViewOfSection", 0x28)));
                assert_eq!(
                    u64::from(call(p, &mut thread, &[arch.ptr(u64::MAX), base])),
                    number(row, "unmap_status", 16)
                );
                assert_eq!(p.vm.committed_bytes(), before);
                assert!(!p.vm.is_shared_view(base));
            } else {
                assert_eq!(base, 0);
                assert_eq!(p.vm.committed_bytes(), before);
                p.objects.close(handle.into()).unwrap();
            }
            cases += 1;
        }
    }
    assert_eq!(cases, 36);
}
