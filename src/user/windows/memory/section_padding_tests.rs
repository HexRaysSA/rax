use super::*;
use crate::user::mm::SpaceConfig;
use crate::user::windows::object_namespace::{
    ImageRegion, ImageSection, ImageTemplate, image_tests,
};

fn memory() -> VirtualMemory {
    VirtualMemory::new(
        AddressSpace::new(SpaceConfig {
            va_limit: 1 << 32,
            arena_bytes: 16 << 20,
            reserved_phys: vec![],
        })
        .unwrap(),
        65536,
        1 << 32,
    )
}

fn image() -> Arc<ImageTemplate> {
    let image = image_tests::template_sized(0x7000_0000, 0xf0000);
    let image = ImageTemplate::selected(
        image.bytes.to_vec(),
        vec![
            ImageRegion {
                offset: 0,
                size: 4096,
                state: mem::COMMIT,
                protection: prot::READONLY,
            },
            ImageRegion {
                offset: 4096,
                size: 0xe4000,
                state: mem::COMMIT,
                protection: prot::WRITECOPY,
            },
            ImageRegion {
                offset: 0xe5000,
                size: 0xb000,
                state: mem::RESERVE,
                protection: 0,
            },
        ],
    )
    .unwrap();
    ImageTemplate::with_reserved_tail(image, 0x4000).unwrap()
}

#[test]
fn image_reserved_tail_full_owner_preserves_logical_size_and_releases_padding() {
    let mut vm = memory();
    let image = image();
    let section = ImageSection::with_test_image(image.clone());
    assert_eq!(image.allocation_size(), 0xf4000);
    assert_eq!(image.bytes.len(), 0xf0000);
    let base = 0x5000_0000;
    vm.map_section_image(
        section, &image, base, base, 0xf4000, 0, 0xf0000, false, false,
    )
    .unwrap();
    let native_last = vm.query(base + 0xe5000).unwrap();
    assert_eq!(
        (native_last.base, native_last.size),
        (base + 0xe5000, 0xf000)
    );
    for offset in [0xf0000, 0xf1000, 0xf3fff] {
        let q = vm.query(base + offset).unwrap();
        assert_eq!(
            (q.allocation_base, q.state, q.kind, q.protect),
            (base, mem::RESERVE, mem::IMAGE, 0)
        );
        assert!(vm.space().u8(base + offset).is_err());
        assert_eq!(
            vm.section_image_information(base + offset),
            Some((base, 0xf0000, 0x40))
        );
        assert_eq!(vm.section_image_extension(base + offset, 0), None);
        assert!(vm.section_view(base + offset).is_some());
    }
    assert_eq!(vm.query(base + 0xf4000).unwrap().state, mem::FREE);
    let owner = vm.query(base + 0xf0000).unwrap().allocation_base;
    vm.release(owner).unwrap();
    assert_eq!(vm.query(base + 0xf3fff).unwrap().state, mem::FREE);
    assert!(vm.section_view(base + 0xf0000).is_none());
}

#[test]
fn image_reserved_tail_rejects_short_full_owner_and_omits_partial_tail() {
    let mut vm = memory();
    let image = image();
    let section = ImageSection::with_test_image(image.clone());
    let base = 0x5000_0000;
    assert_eq!(
        vm.map_section_image(
            section.clone(),
            &image,
            base,
            base,
            0xf0000,
            0,
            0xf0000,
            false,
            false
        ),
        Err(VmError::InvalidParameter)
    );
    assert_eq!(vm.query(base).unwrap().state, mem::FREE);
    vm.map_section_image(section, &image, base, base, 4096, 0, 4096, false, false)
        .unwrap();
    assert_eq!(vm.section_image_information(base), Some((base, 0xf0000, 1)));
    assert_eq!(vm.query(base + 4096).unwrap().state, mem::FREE);
    vm.release(base).unwrap();
}

#[test]
fn image_reserved_tail_metadata_is_bounded_and_rebase_views_must_agree() {
    for bytes in [1, 4095, 65537, 69632, u64::MAX] {
        assert!(
            ImageTemplate::with_reserved_tail(image_tests::template(0x7000_0000), bytes).is_err()
        );
    }
    let original =
        ImageTemplate::with_reserved_tail(image_tests::template(0x7000_0000), 4096).unwrap();
    let one = ImageTemplate::with_reserved_tail(image_tests::template(0x5000_0000), 4096).unwrap();
    let two = ImageTemplate::with_reserved_tail(image_tests::template(0x5100_0000), 4096).unwrap();
    assert!(ImageTemplate::with_rebase(original, &one, &two).is_ok());
    assert!(
        ImageTemplate::with_rebase(
            ImageTemplate::with_reserved_tail(image_tests::template(0x7000_0000), 4096).unwrap(),
            &one,
            &image_tests::template(0x5100_0000)
        )
        .is_err()
    );
}

#[test]
fn image_reserved_tail_follows_committed_extensions_without_changing_their_metadata() {
    use crate::user::windows::object_namespace::image_extension_tests;
    let image =
        ImageTemplate::with_reserved_tail(image_extension_tests::template(0x7000_0000), 0x3000)
            .unwrap();
    assert_eq!(image.allocation_size(), 0x7000);
    let mut vm = memory();
    let section = ImageSection::with_test_image(image.clone());
    let base = 0x5000_0000;
    vm.map_section_image(section, &image, base, base, 0x7000, 0, 8192, false, false)
        .unwrap();
    assert_eq!(
        (
            vm.query(base + 0x3000).unwrap().state,
            vm.query(base + 0x3000).unwrap().protect
        ),
        (mem::COMMIT, prot::EXECUTE_READ)
    );
    assert_eq!(
        (
            vm.query(base + 0x4000).unwrap().state,
            vm.query(base + 0x4000).unwrap().size
        ),
        (mem::RESERVE, 0x3000)
    );
    assert_eq!(
        vm.section_image_information(base + 0x6000),
        Some((base, 8192, 0x40))
    );
    assert_eq!(
        vm.section_image_extension(base + 0x6000, 1),
        Some((12288, 4096))
    );
    vm.release(base).unwrap();
    assert_eq!(vm.query(base + 0x6000).unwrap().state, mem::FREE);
}
