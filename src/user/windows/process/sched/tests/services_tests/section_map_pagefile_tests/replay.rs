use super::*;

#[test]
fn native_pagefile_map_replays_496_measured_zero_bits_zero_results() {
    let profile: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../../../docs/specifications/windows/native-pagefile-options/profile-29704-v1.json"
    ))
    .unwrap();
    assert_eq!(profile["native_cases"], 552);
    assert_eq!(profile["native_views_mapped_and_released"], 264);
    let cases = profile["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 138);
    let mut replayed = 0;
    for (arch, laa) in [
        (WinArch::Arm64, false),
        (WinArch::X64, false),
        (WinArch::X86, false),
        (WinArch::X86, true),
    ] {
        let (mut process, mut t) = process(arch, laa);
        let p = process.state_mut();
        if arch == WinArch::X86 {
            assert_eq!(p.vm.high(), if laa { 0xffff0000 } else { 0x7fff0000 });
        }
        let b = scratch(p);
        let (handle, weak) = backed_section(p);
        let handles = p.objects.handle_count();
        let objects = p.objects.iter().count();
        let commitment = p.vm.committed_bytes();
        for row in cases.iter().filter(|row| row["zero"] == 0) {
            let n = |key: &str| row[key].as_u64().unwrap();
            let reservation = if n("base-kind") == 0 {
                None
            } else {
                Some(
                    p.vm.allocate(None, 65536, mem::RESERVE, prot::NOACCESS)
                        .unwrap()
                        .0,
                )
            };
            let base = reservation.map_or(0, |base| base + u64::from(n("base-kind") == 2));
            ptr(p, b, base);
            ptr(p, b + 16, n("size-in"));
            p.space.w64(b + 32, n("offset-in")).unwrap();
            let expected = n("status") as u32;
            assert_eq!(
                call(
                    p,
                    &mut t,
                    &[
                        handle,
                        arch.ptr(u64::MAX),
                        b,
                        0,
                        n("commit"),
                        if n("offset-present") != 0 { b + 32 } else { 0 },
                        b + 16,
                        n("inherit"),
                        n("flags"),
                        n("protect"),
                    ]
                ),
                expected,
                "{arch} LAA={laa} ordinal={}",
                n("ordinal")
            );
            assert_eq!(get(p, b + 16), n("size-out"));
            assert_eq!(p.space.u64(b + 32).unwrap(), n("offset-out"));
            if expected == STATUS_SUCCESS {
                let address = get(p, b);
                assert_ne!(address, 0);
                assert_eq!(address % 65536, 0);
                let q = p.vm.query(address).unwrap();
                assert_eq!(
                    (q.state, q.kind, q.protect),
                    (mem::COMMIT, mem::MAPPED, prot::READWRITE)
                );
                assert!(
                    p.space
                        .bytes(address, n("size-out") as usize)
                        .unwrap()
                        .iter()
                        .all(|&b| b == 0)
                );
                p.vm.release(address).unwrap();
                assert!(!p.vm.is_shared_view(address));
            } else {
                assert_eq!(get(p, b), base);
            }
            if let Some(address) = reservation {
                p.vm.release(address).unwrap();
            }
            assert_eq!(p.objects.handle_count(), handles);
            assert_eq!(p.objects.iter().count(), objects);
            assert_eq!(p.vm.committed_bytes(), commitment);
            assert_eq!(weak.strong_count(), 1);
            replayed += 1;
        }
        p.objects.close(handle).unwrap();
        assert!(weak.upgrade().is_none());
    }
    assert_eq!(replayed, 496);
}
