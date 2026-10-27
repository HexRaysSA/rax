//! Native section services retain reserved padding only for full image views.
use super::*;
use crate::user::windows::object_namespace::ImageTemplate;

#[test]
fn native_section_image_reserved_tail_unmaps_through_padding_after_handle_close_all_abis() {
    for arch in WinArch::ALL {
        for requested in [0, 4096, 0xf0000] {
            let (mut process, mut thread) = fixture(arch, "NtMapViewOfSection", SERVICE);
            let p = process.state_mut();
            let b = scratch(p);
            let image = image_tests::template_sized(0x7000_0000, 0xf0000);
            let image = ImageTemplate::with_reserved_tail(image, 0x4000).unwrap();
            let selected = ImageSection::with_test_image(image);
            let handles_before = p.objects.handle_count();
            let handle = u64::from(p.objects.open_image_section(selected, false, 0xd).unwrap());
            ptr(p, b, 0x5000_0000);
            ptr(p, b + 16, requested);
            let expected_status = match arch {
                // The valid template is ARM64. The native AMD64 wrapper reports
                // machine mismatch; WoW64 reports the relocated-view warning.
                WinArch::X64 => STATUS_IMAGE_MACHINE_TYPE_MISMATCH,
                WinArch::Arm64 | WinArch::X86 => STATUS_IMAGE_AT_DIFFERENT_BASE,
            };
            assert_eq!(
                call(
                    p,
                    &mut thread,
                    &[
                        handle,
                        arch.ptr(u64::MAX),
                        b,
                        0,
                        0,
                        0,
                        b + 16,
                        1,
                        0x800000,
                        0x80
                    ]
                ),
                expected_status
            );
            let logical = if requested == 0 { 0xf0000 } else { requested };
            assert_eq!((get(p, b), get(p, b + 16)), (0x5000_0000, logical));
            let address = if logical == 0xf0000 {
                let q = p.vm.query(0x500f_0000).unwrap();
                assert_eq!(
                    (q.allocation_base, q.state, q.kind, q.protect),
                    (0x5000_0000, mem::RESERVE, mem::IMAGE, 0)
                );
                assert!(p.space.u8(0x500f_0000).is_err());
                0x500f_3fff
            } else {
                assert_eq!(p.vm.query(0x5000_1000).unwrap().state, mem::FREE);
                0x5000_0000
            };
            p.objects.close(handle).unwrap();
            assert_eq!(p.objects.handle_count(), handles_before);
            p.modules.nt_services = Some((
                p.modules.nt_services.as_ref().unwrap().0,
                table(arch, "NtUnmapViewOfSection", SERVICE),
            ));
            assert_eq!(
                call(p, &mut thread, &[arch.ptr(u64::MAX), address]),
                STATUS_SUCCESS
            );
            assert_eq!(p.vm.query(0x5000_0000).unwrap().state, mem::FREE);
            assert_eq!(p.vm.query(0x500f_3000).unwrap().state, mem::FREE);
            assert!(p.vm.section_view(address).is_none());
        }
    }
}
