use super::*;

#[test]
fn native_pagefile_map_top_and_ordinary_aliases_outlive_the_section_handle() {
    for arch in WinArch::ALL {
        let (mut process, mut t) = process(arch, false);
        let p = process.state_mut();
        let b = scratch(p);
        let (handle, weak) = backed_section(p);
        let commitment = p.vm.committed_bytes();
        let mut addresses = Vec::new();
        for (commit, flags, protection) in [
            (16384, mem::TOP_DOWN, prot::READWRITE),
            (0, 0, prot::READONLY),
        ] {
            ptr(p, b, 0);
            ptr(p, b + 16, 0);
            assert_eq!(
                call(
                    p,
                    &mut t,
                    &[
                        handle,
                        arch.ptr(u64::MAX),
                        b,
                        0,
                        commit,
                        0,
                        b + 16,
                        2,
                        flags.into(),
                        protection.into()
                    ]
                ),
                STATUS_SUCCESS
            );
            assert_eq!(get(p, b + 16), 65536);
            addresses.push(get(p, b));
        }
        assert!(addresses[0] > addresses[1]);
        p.space.w32(addresses[0], 0x5a17c0de).unwrap();
        assert_eq!(p.space.u32(addresses[1]).unwrap(), 0x5a17c0de);
        assert!(p.space.w32(addresses[1], 1).is_err());
        p.vm.release(addresses[0]).unwrap();
        p.objects.close(handle).unwrap();
        assert_eq!(p.space.u32(addresses[1]).unwrap(), 0x5a17c0de);
        assert!(weak.upgrade().is_some());
        p.vm.release(addresses[1]).unwrap();
        assert!(weak.upgrade().is_none());
        assert_eq!(p.vm.committed_bytes(), commitment);
    }
}

#[test]
fn native_pagefile_map_keeps_common_early_and_wow64_late_copy_fault_ownership() {
    for arch in WinArch::ALL {
        for target in [0, 2] {
            let (mut process, mut t) = process(arch, false);
            let p = process.state_mut();
            let b = scratch(p);
            let (handle, weak) = backed_section(p);
            ptr(p, b, 0);
            ptr(p, b + 8192, 0);
            let planned =
                p.vm.find_free(65536, 65536, p.vm.low(), p.vm.high(), true)
                    .unwrap();
            p.vm.protect(b + target * 4096, 4096, prot::READONLY)
                .unwrap();
            assert_eq!(
                call(
                    p,
                    &mut t,
                    &[
                        handle,
                        arch.ptr(u64::MAX),
                        b,
                        0,
                        16384,
                        0,
                        b + 8192,
                        2,
                        mem::TOP_DOWN.into(),
                        prot::READWRITE.into()
                    ]
                ),
                STATUS_ACCESS_VIOLATION
            );
            assert_eq!(p.vm.is_shared_view(planned), arch == WinArch::X86);
            assert_eq!(
                get(p, b),
                if arch == WinArch::X86 && target == 2 {
                    planned
                } else {
                    0
                }
            );
            assert_eq!(get(p, b + 8192), 0);
            p.objects.close(handle).unwrap();
            if arch == WinArch::X86 {
                assert!(weak.upgrade().is_some());
                p.vm.release(planned).unwrap();
            }
            assert!(weak.upgrade().is_none());
        }
    }
}
