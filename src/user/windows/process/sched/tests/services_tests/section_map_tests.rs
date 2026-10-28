//! Original SVC 0x28 and ten-argument native/WoW64 transport.
use super::*;
use crate::user::windows::object_namespace::{ImageSection, image_tests};

const SERVICE: u32 = 0x28;
#[cfg(windows)]
#[path = "section_map_leaf_tests.rs"]
mod installed;
#[path = "section_map_padding_tests.rs"]
mod padding;
#[path = "section_map_replay_tests.rs"]
mod replay;
pub(super) fn call(p: &mut Proc, t: &mut Thread, args: &[u64]) -> u32 {
    let sp = t.cpu.sp();
    t.cpu.set_pc(0x1234_0004);
    match p.arch {
        WinArch::X86 => {
            p.space.w32(sp, 0x1234_0004).unwrap();
            p.space.w32(sp + 4, 0x1234_0000).unwrap();
            for (i, &v) in args.iter().enumerate() {
                p.space.w32(sp + 8 + i as u64 * 4, v as u32).unwrap();
            }
            t.cpu.set_gpr(0, SERVICE.into());
        }
        WinArch::X64 => {
            t.cpu.set_gpr(0, SERVICE.into());
            t.cpu.set_gpr(1, 0x1234_0004);
            for (i, &v) in args.iter().enumerate() {
                if i < 4 {
                    t.cpu.set_gpr([10, 2, 8, 9][i], v);
                } else {
                    p.space.w64(sp + 40 + (i - 4) as u64 * 8, v).unwrap();
                }
            }
        }
        WinArch::Arm64 => {
            for (i, &v) in args.iter().enumerate() {
                if i < 8 {
                    t.cpu.set_gpr(i, v);
                } else {
                    p.space.w32(sp + (i - 8) as u64 * 8, v as u32).unwrap();
                }
            }
        }
    }
    let out = if p.arch == WinArch::X86 {
        super::super::super::super::services::wow64(p, t, 0x1234_0000)
    } else {
        handle_stop(p, t, stop(p.arch, SERVICE))
    };
    assert_eq!(out, Outcome::Continue, "{} {args:X?}", p.arch);
    assert_eq!(t.cpu.pc(), 0x1234_0004);
    assert_eq!(t.cpu.sp(), sp + if p.arch == WinArch::X86 { 4 } else { 0 });
    assert!(t.frames.is_empty());
    t.cpu.set_sp(sp);
    t.cpu.gpr(0) as u32
}
pub(super) fn scratch(p: &mut Proc) -> u64 {
    p.vm.allocate(None, 8 * 4096, mem::RESERVE | mem::COMMIT, prot::READWRITE)
        .unwrap()
        .0
}
pub(super) fn ptr(p: &Proc, at: u64, value: u64) {
    p.space.wptr(at, p.arch.ptr_size(), value).unwrap();
}
pub(super) fn get(p: &Proc, at: u64) -> u64 {
    p.space.ptr(at, p.arch.ptr_size()).unwrap()
}
fn section(p: &mut Proc, grant: u32) -> u64 {
    let mut image = image_tests::template_sized(0x7000_0000, 0x30000);
    if p.arch == WinArch::X64 {
        let mut bytes = image.bytes.to_vec();
        bytes[132..134].copy_from_slice(&0x8664u16.to_le_bytes());
        image = crate::user::windows::object_namespace::ImageTemplate::selected(
            bytes,
            image.regions.clone(),
        )
        .unwrap();
    }
    p.objects
        .open_image_section(ImageSection::with_test_image(image), false, grant)
        .unwrap()
        .into()
}
#[test]
fn native_section_map_original_ten_argument_service_returns_owned_rebased_view() {
    for arch in [WinArch::Arm64, WinArch::X64, WinArch::X86] {
        let (mut process, mut t) = fixture(arch, "NtMapViewOfSection", SERVICE);
        let p = process.state_mut();
        let b = scratch(p);
        let h = section(p, 0xD);
        ptr(p, b, 0x5000_0000);
        ptr(p, b + 16, 0);
        let before_modules = p.modules.list.len();
        assert_eq!(
            call(
                p,
                &mut t,
                &[h, arch.ptr(u64::MAX), b, 0, 0, 0, b + 16, 1, 0x800000, 0x80]
            ),
            STATUS_IMAGE_AT_DIFFERENT_BASE
        );
        assert_eq!((get(p, b), get(p, b + 16)), (0x5000_0000, 0x30000));
        assert_eq!(p.space.u64(0x5000_1000).unwrap(), 0x5000_1234);
        assert_eq!(p.space.u64(0x5000_00B0).unwrap(), 0x5000_0000);
        assert_eq!(p.modules.list.len(), before_modules);
        p.objects.close(h).unwrap();
        assert!(p.vm.section_view(0x5000_0000).is_some());
        assert_eq!(
            p.vm.free(0x5000_0000, 0, mem::RELEASE),
            Err(crate::user::windows::memory::VmError::CannotDeleteSection)
        );
        p.modules.nt_services = Some((
            p.modules.nt_services.as_ref().unwrap().0,
            table(arch, "NtUnmapViewOfSection", SERVICE),
        ));
        assert_eq!(
            call(p, &mut t, &[arch.ptr(u64::MAX), 0x5000_1000]),
            STATUS_SUCCESS
        );
        assert!(p.vm.section_view(0x5000_0000).is_none());
        assert_eq!(p.vm.query(0x5000_0000).unwrap().state, mem::FREE);
    }
}
#[test]
fn native_section_map_protection_requires_exact_section_access_before_geometry() {
    for arch in [WinArch::Arm64, WinArch::X64, WinArch::X86] {
        for grant in [0, 1, 2, 4, 8, 0xD, 0xF] {
            for (protection, required) in [
                (1, 4),
                (2, 4),
                (4, 2),
                (8, 4),
                (0x10, 8),
                (0x20, 12),
                (0x40, 10),
                (0x80, 12),
            ] {
                let (mut process, mut t) = fixture(arch, "NtMapViewOfSection", SERVICE);
                let p = process.state_mut();
                let b = scratch(p);
                let h = section(p, grant);
                ptr(p, b, 0x5000_0000);
                ptr(p, b + 16, 4096);
                let expected = if grant & required == required {
                    STATUS_IMAGE_NOT_AT_BASE
                } else {
                    STATUS_ACCESS_DENIED
                };
                assert_eq!(
                    call(
                        p,
                        &mut t,
                        &[h, arch.ptr(u64::MAX), b, 0, 0, 0, b + 16, 1, 0, protection]
                    ),
                    expected,
                    "{arch} grant={grant:X} PAGE={protection:X}"
                );
                assert_eq!(
                    p.vm.section_view(0x5000_0000).is_some(),
                    expected == STATUS_IMAGE_NOT_AT_BASE
                );
                if expected == STATUS_IMAGE_NOT_AT_BASE {
                    assert_eq!(p.vm.query(0x5000_0000).unwrap().protect, prot::READONLY);
                } else {
                    assert_eq!((get(p, b), get(p, b + 16)), (0x5000_0000, 4096));
                }
            }
        }
    }
}
#[test]
fn native_section_map_wow64_late_output_fault_keeps_view_and_copyback_order() {
    for arch in [WinArch::Arm64, WinArch::X64, WinArch::X86] {
        for target in [0, 2] {
            let (mut process, mut t) = fixture(arch, "NtMapViewOfSection", SERVICE);
            let p = process.state_mut();
            let b = scratch(p);
            let h = section(p, 0xD);
            ptr(p, b, 0);
            ptr(p, b + 8192, 4096);
            p.vm.protect(b + target * 4096, 4096, prot::READONLY)
                .unwrap();
            assert_eq!(
                call(
                    p,
                    &mut t,
                    &[
                        h,
                        arch.ptr(u64::MAX),
                        b,
                        0,
                        0,
                        0,
                        b + 8192,
                        1,
                        0x800000,
                        0x80
                    ]
                ),
                STATUS_ACCESS_VIOLATION
            );
            let base = if arch == WinArch::X86 { 0x7000_0000 } else { 0 };
            if base != 0 {
                assert!(p.vm.section_view(base).is_some());
                assert_eq!(get(p, b), if target == 0 { 0 } else { base });
            } else {
                assert!(p.vm.section_view(0x7000_0000).is_none());
            }
        }
    }
}
