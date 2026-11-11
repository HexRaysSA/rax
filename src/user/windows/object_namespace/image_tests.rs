use super::*;
use crate::user::windows::memory::{mem, prot};

pub(crate) fn template(preferred: u64) -> Arc<ImageTemplate> {
    template_sized(preferred, 8192)
}
pub(crate) fn template_sized(preferred: u64, size: usize) -> Arc<ImageTemplate> {
    assert!(size >= 8192 && size % 4096 == 0);
    let mut bytes = vec![0u8; size];
    bytes[..2].copy_from_slice(b"MZ");
    bytes[0x3C..0x40].copy_from_slice(&128u32.to_le_bytes());
    bytes[128..132].copy_from_slice(b"PE\0\0");
    bytes[132..134].copy_from_slice(&0xAA64u16.to_le_bytes());
    bytes[152..154].copy_from_slice(&0x20Bu16.to_le_bytes());
    bytes[176..184].copy_from_slice(&preferred.to_le_bytes());
    bytes[208..212].copy_from_slice(&(size as u32).to_le_bytes());
    bytes[304..308].copy_from_slice(&0x1800u32.to_le_bytes());
    bytes[308..312].copy_from_slice(&12u32.to_le_bytes());
    bytes[0x1800..0x1804].copy_from_slice(&4096u32.to_le_bytes());
    bytes[0x1804..0x1808].copy_from_slice(&12u32.to_le_bytes());
    bytes[0x1808..0x180A].copy_from_slice(&0xA000u16.to_le_bytes());
    bytes[4096..4104].copy_from_slice(&preferred.wrapping_add(0x1234).to_le_bytes());
    ImageTemplate::selected(
        bytes,
        vec![
            ImageRegion {
                offset: 0,
                size: 4096,
                state: mem::COMMIT,
                protection: prot::READONLY,
            },
            ImageRegion {
                offset: 4096,
                size: size as u64 - 4096,
                state: mem::COMMIT,
                protection: prot::WRITECOPY,
            },
        ],
    )
    .unwrap()
}

#[test]
fn different_image_base_flag_rebases_header_and_dir64_without_changing_source() {
    let image = template(0x7FFA_1000_0000);
    let untouched = image.view_bytes(0x5000_0000, false).unwrap();
    assert!(matches!(untouched, std::borrow::Cow::Borrowed(_)));
    assert_eq!(&untouched[4096..4104], &0x7FFA_1000_1234u64.to_le_bytes());
    let rebased = image.view_bytes(0x5000_0000, true).unwrap();
    assert_eq!(&rebased[176..184], &0x5000_0000u64.to_le_bytes());
    assert_eq!(&rebased[4096..4104], &0x5000_1234u64.to_le_bytes());
    assert_eq!(&image.bytes[176..184], &0x7FFA_1000_0000u64.to_le_bytes());
    assert_eq!(&image.bytes[4096..4104], &0x7FFA_1000_1234u64.to_le_bytes());
}

#[test]
fn image_template_preserves_kernel_relocation_words_and_page_policy() {
    let image = template(0x7FFA_1000_0000);
    assert_eq!(image.preferred, 0x7FFA_1000_0000);
    assert_eq!(image.machine, 0xAA64);
    assert_eq!(&image.bytes[4096..4104], &0x7FFA_1000_1234u64.to_le_bytes());
    assert_eq!(image.regions[1].protection, prot::WRITECOPY);
    let bytes = image.bytes.to_vec();
    for regions in [
        vec![],
        vec![ImageRegion {
            offset: 4096,
            size: 4096,
            state: mem::COMMIT,
            protection: prot::READONLY,
        }],
        vec![ImageRegion {
            offset: 0,
            size: 8192,
            state: mem::COMMIT,
            protection: 3,
        }],
        vec![ImageRegion {
            offset: 0,
            size: 8192,
            state: mem::RESERVE,
            protection: prot::READONLY,
        }],
        vec![ImageRegion {
            offset: 0,
            size: u64::MAX,
            state: mem::COMMIT,
            protection: prot::READONLY,
        }],
    ] {
        assert!(ImageTemplate::selected(bytes.clone(), regions).is_err());
    }
    for (at, value) in [(0, 0u8), (128, 0), (152, 0), (208, 1)] {
        let mut altered = bytes.clone();
        altered[at] = value;
        assert!(ImageTemplate::selected(altered, image.regions.clone()).is_err());
    }
    assert!(ImageTemplate::selected(bytes[..4096].to_vec(), image.regions.clone()).is_err());
}

#[test]
fn section_template_is_shared_across_virtual_handles_without_relocation() {
    let section = ImageSection::selected(
        vec![92, 65],
        CapturedSection {
            maximum_access: 0xD,
            system_security_status: STATUS_PRIVILEGE_NOT_HELD,
            attributes: 0x0180_0000,
            size: 8192,
            force_case_insensitive: true,
        },
    );
    let image = template(0x7FFA_1000_0000);
    section.image.set(Ok(image.clone())).unwrap();
    assert!(Arc::ptr_eq(&section.image().unwrap(), &image));
    assert!(Arc::ptr_eq(&section.image().unwrap(), &image));
    let unselected = ImageSection::selected(
        vec![92, 66],
        CapturedSection {
            maximum_access: 0xD,
            system_security_status: STATUS_PRIVILEGE_NOT_HELD,
            attributes: 0x0180_0000,
            size: 8192,
            force_case_insensitive: true,
        },
    );
    assert!(unselected.image().is_err());
}

#[test]
fn native_rebase_views_require_the_same_captured_extension_machine() {
    for machine in [None, Some(0xAA64), Some(0x8664)] {
        let original =
            ImageTemplate::with_native_machine(template(0x7000_0000), Some(0xAA64)).unwrap();
        let first = ImageTemplate::with_native_machine(template(0x5000_0000), machine).unwrap();
        let second =
            ImageTemplate::with_native_machine(template(0x5100_0000), Some(0xAA64)).unwrap();
        let result = ImageTemplate::with_rebase(original, &first, &second);
        assert_eq!(result.is_ok(), machine == Some(0xAA64));
        if let Ok(image) = result {
            assert_eq!(image.native_machine, Some(0xAA64));
        }
    }
}
