use super::*;

fn reader(base: u64) -> Vec<u8> {
    let mut words = [
        0xd280_0010,
        0xf2a0_0010,
        0xf2c0_0010,
        0xf2e0_0010,
        0xaa10_03ec,
        0xd34f_fd71,
        0x3871_6a11,
        0xd34c_3970,
        0x9ad0_2630,
        0xf240_021f,
    ];
    for (n, word) in words[..4].iter_mut().enumerate() {
        *word |= ((base >> (n * 16)) as u32 & 0xffff) << 5;
    }
    words.into_iter().flat_map(u32::to_le_bytes).collect()
}

#[test]
fn reader_requires_the_complete_aligned_instruction_contract_and_one_data_owner() {
    let base = 0x7df4_51a1_0000;
    let bytes = reader(base);
    assert_eq!(reader_base(&bytes).unwrap(), Some(base));
    for length in 0..40 {
        assert_eq!(reader_base(&bytes[..length]).unwrap(), None);
    }
    for index in 0..10 {
        let mut changed = bytes.clone();
        changed[index * 4] ^= 1; // Change an opcode/register, not an immediate.
        assert_eq!(reader_base(&changed).unwrap(), None, "word {index}");
    }
    let mut unaligned = vec![0];
    unaligned.extend_from_slice(&bytes);
    assert_eq!(reader_base(&unaligned).unwrap(), None);
    let mut twice = bytes.clone();
    twice.extend_from_slice(&bytes);
    assert_eq!(reader_base(&twice).unwrap(), Some(base));
    twice.extend_from_slice(&reader(base + 65536));
    assert!(reader_base(&twice).is_err());
    for invalid in [0, 1, (1 << 47) - 65536, u64::MAX & !65535] {
        assert!(reader_base(&reader(invalid)).is_err());
    }
}

fn selected(version: u32, machine: u16) -> Arc<ImageTemplate> {
    let source =
        crate::user::windows::object_namespace::image_tests::template_sized(0x7000_0000, 0x5000);
    let mut bytes = source.bytes.to_vec();
    bytes[132..134].copy_from_slice(&machine.to_le_bytes());
    for (at, value) in [
        (344, 0x200u32),
        (348, 208),
        (0x200, 208),
        (0x300, version),
        (0x304, 0x400),
        (0x308, 3),
        (0x400, 0x1000),
        (0x404, 0x1000),
        (0x408, 0x2001),
        (0x40c, 0x1001),
        (0x410, 0x4002),
        (0x414, 0x1000),
    ] {
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    bytes[0x2c8..0x2d0].copy_from_slice(&0x7000_0300u64.to_le_bytes());
    let mut extension = vec![0; 4096];
    extension[128..168].copy_from_slice(&reader(0x7df4_51a1_0000));
    ImageTemplate::selected_extended(
        bytes,
        source.regions.clone(),
        [
            Some(ImageExtension {
                rva: 0x5000,
                bytes: extension.into(),
            }),
            None,
        ],
    )
    .unwrap()
}

#[test]
fn selected_view_keeps_classic_arm64_and_amd64_pages_out_of_ec_tags() {
    for version in [1, 2] {
        let image = selected(version, 0x8664);
        let plan = image.arm64ec_code_bitmap().unwrap().unwrap();
        assert_eq!(plan.base, Some(0x7df4_51a1_0000));
        assert_eq!(plan.ranges, [(0x2000, 0x3001)]);
        assert_eq!(
            image.extensions[0].as_ref().unwrap().bytes[128..168],
            reader(plan.base.unwrap())
        );
        assert!(
            selected(version, 0xaa64)
                .arm64ec_code_bitmap()
                .unwrap()
                .is_none()
        );
    }
}

#[test]
fn full_and_partial_image_mapping_publish_guest_pages_and_preserve_extension_bytes() {
    use crate::user::mm::{AddressSpace, SpaceConfig};
    use crate::user::windows::memory::{Mem, VirtualMemory};
    use crate::user::windows::object_namespace::ImageSection;
    for (offset, size, allocation_size, expected) in
        [(0, 0x5000, 0x6000, 0x0c), (0x1000, 0x3000, 0x3000, 0x06)]
    {
        let mut vm = VirtualMemory::new(
            AddressSpace::new(SpaceConfig {
                va_limit: 1 << 47,
                arena_bytes: 4 << 20,
                reserved_phys: vec![],
            })
            .unwrap(),
            65536,
            1 << 47,
        );
        let image = selected(2, 0x8664);
        let section = ImageSection::with_test_image(image.clone());
        let base = 0x5000_0000;
        vm.map_section_image(
            section,
            &image,
            base,
            base,
            allocation_size,
            offset,
            size,
            false,
            false,
        )
        .unwrap();
        let byte = 0x7df4_51a1_0000 + (base >> 15);
        assert_eq!(vm.space().u8(byte).unwrap(), expected);
        if offset == 0 {
            assert_eq!(
                vm.space().bytes(base + 0x5000 + 128, 40).unwrap(),
                reader(0x7df4_51a1_0000)
            );
        }
        vm.release(base).unwrap();
        assert_eq!(vm.space().u8(byte).unwrap(), expected);
    }
}
