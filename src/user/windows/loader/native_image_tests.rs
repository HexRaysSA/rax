use super::*;
use crate::user::windows::memory::mem;
use crate::user::windows::object_namespace::{ImageExtension, ImageRegion};
use crate::user::windows::process::{WindowsConfig, WindowsProcess};

fn fixture(arch: WinArch) -> (WindowsProcess, PeImage, Arc<ImageTemplate>) {
    let input: &[u8] = match arch {
        WinArch::Arm64 => {
            include_bytes!("../../../../tests/fixtures/user/windows/bin/arm64/smoke.exe")
        }
        WinArch::X64 => include_bytes!("../../../../tests/fixtures/user/windows/bin/x64/smoke.exe"),
        WinArch::X86 => include_bytes!("../../../../tests/fixtures/user/windows/bin/x86/smoke.exe"),
    };
    let pe = PeImage::parse(input.to_vec()).unwrap();
    let cfg = WindowsConfig::embedded("C:\\native-image-test.exe", vec![], vec![], 4096).unwrap();
    let process = WindowsProcess::spawn_image(cfg, input.to_vec()).unwrap();
    let mut bytes = pe.memory_image();
    let preferred = 0x6000_0000u64;
    let at = pe.headers().nt_offset as usize + if arch.is64() { 48 } else { 52 };
    let width = arch.ptr_size() as usize;
    bytes[at..at + width].copy_from_slice(&preferred.to_le_bytes()[..width]);
    let size = bytes.len() as u64;
    let image = ImageTemplate::selected_extended(
        bytes,
        vec![ImageRegion {
            offset: 0,
            size,
            state: mem::COMMIT,
            protection: prot::EXECUTE_READ,
        }],
        [
            Some(ImageExtension {
                rva: size,
                bytes: vec![0x5A; 4096].into(),
            }),
            None,
        ],
    )
    .unwrap();
    (process, pe, image)
}
#[test]
fn image_extension_bootstrap_uses_selected_base_and_keeps_module_size_separate() {
    for arch in WinArch::ALL {
        let (mut process, pe, image) = fixture(arch);
        let p = process.state_mut();
        let section = ImageSection::with_test_image(image.clone());
        let base = map_selected(p, &pe, section, &image).unwrap();
        assert_eq!(base, 0x6000_0000);
        assert_eq!(
            p.vm.section_image_information(base),
            Some((base, image.bytes.len() as u64, 0x40))
        );
        assert_eq!(p.space.u8(base + image.bytes.len() as u64).unwrap(), 0x5A);
        p.vm.release(base).unwrap();
        assert!(p.vm.section_image_extension(base, 0).is_none());
    }
}
#[test]
fn image_extension_bootstrap_rejects_identity_mismatch_and_occupied_range_without_fallback() {
    let (mut process, pe, image) = fixture(WinArch::Arm64);
    let p = process.state_mut();
    let mut bytes = image.bytes.to_vec();
    bytes[pe.headers().nt_offset as usize + 8] ^= 1;
    let wrong =
        ImageTemplate::selected_extended(bytes, image.regions.clone(), image.extensions.clone())
            .unwrap();
    assert_eq!(
        map_selected(p, &pe, ImageSection::with_test_image(wrong.clone()), &wrong)
            .unwrap_err()
            .status,
        STATUS_INVALID_IMAGE_FORMAT
    );
    assert!(p.vm.is_free(image.preferred, image.allocation_size()));
    p.vm.reserve(
        Some(image.preferred),
        4096,
        prot::READONLY,
        AllocKind::Private,
        false,
        None,
    )
    .unwrap();
    assert_eq!(
        map_selected(p, &pe, ImageSection::with_test_image(image.clone()), &image)
            .unwrap_err()
            .status,
        STATUS_CONFLICTING_ADDRESSES
    );
    assert!(p.vm.section_image_information(image.preferred).is_none());
}
#[test]
fn image_extension_bootstrap_does_not_reclassify_supplied_ntdll_name() {
    let (mut process, pe, _) = fixture(WinArch::Arm64);
    assert!(
        select(
            process.state_mut(),
            &pe,
            Some(Path::new("C:\\supplied\\ntdll.dll"))
        )
        .unwrap()
        .is_none()
    );
}
