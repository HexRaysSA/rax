//! Malformed-image and boundary regressions for the PE audit.

use super::*;

#[test]
fn legacy_delay_descriptors_do_not_silently_discard_imports() {
    let descriptor = imports::DelayDescriptor {
        attributes: 0,
        name_rva: 0x0040_0300,
        module_handle_rva: 0x0040_0350,
        iat_rva: 0x0040_0400,
        name_table_rva: 0x0040_0500,
        bound_iat_rva: 0,
        unload_iat_rva: 0,
        time_date_stamp: 0,
    };
    let m = Mem::new(0x1000);
    assert!(descriptor.thunks(&m.0, PeKind::Pe32).is_err());
}

#[test]
fn delay_descriptor_reserved_attributes_are_not_accepted_as_rvas() {
    let descriptor = imports::DelayDescriptor {
        attributes: 3,
        name_rva: 0x300,
        module_handle_rva: 0x350,
        iat_rva: 0x400,
        name_table_rva: 0x500,
        bound_iat_rva: 0,
        unload_iat_rva: 0,
        time_date_stamp: 0,
    };
    let m = Mem::new(0x1000);
    assert!(descriptor.thunks(&m.0, PeKind::Pe32).is_err());
}

fn resource_id_tree(type_id: u32, name_id: u32, language_id: u32) -> (Mem, ResourceTree) {
    let mut m = Mem::new(0x1000);
    for (offset, id, target) in [
        (0x100, type_id, 0x8000_0040),
        (0x140, name_id, 0x8000_0080),
        (0x180, language_id, 0xC0),
    ] {
        m.u16(offset + 14, 1);
        m.u32(offset + 16, id);
        m.u32(offset + 20, target);
    }
    m.u32(0x1C0, 0x800);
    m.u32(0x1C4, 4);
    let tree = ResourceTree::new(DataDirectory {
        rva: 0x100,
        size: 0x400,
    })
    .unwrap();
    (m, tree)
}

#[test]
fn resource_ids_are_not_aliases_of_their_low_16_bits() {
    let (m, tree) = resource_id_tree(0x0001_0018, 1, 0);
    assert_eq!(
        tree.find_resource(&m.0, &ResId::Id(24), &ResId::Id(1), None)
            .unwrap(),
        None
    );
    assert!(
        tree.find_resource(&m.0, &ResId::Id(0x0001_0018), &ResId::Id(1), None)
            .unwrap()
            .is_some()
    );
    let (m, tree) = resource_id_tree(24, 0x0001_0001, 0);
    assert_eq!(
        tree.names_of_type(&m.0, &ResId::Id(24)).unwrap(),
        vec![ResId::Id(0x0001_0001)]
    );
}

#[test]
fn resource_integer_ids_use_the_full_word_even_when_bit_31_is_set() {
    let (m, tree) = resource_id_tree(24, 0x8000_0001, 0);
    assert_eq!(
        tree.names_of_type(&m.0, &ResId::Id(24)).unwrap(),
        vec![ResId::Id(0x8000_0001)]
    );
}

#[test]
fn resource_language_ids_are_not_truncated() {
    let (m, tree) = resource_id_tree(24, 1, 0x0001_0409);
    let data = tree
        .find_resource(&m.0, &ResId::Id(24), &ResId::Id(1), None)
        .unwrap()
        .unwrap();
    assert_eq!(data.language, 0x0001_0409);
    assert!(
        tree.find_resource(&m.0, &ResId::Id(24), &ResId::Id(1), Some(0x409))
            .unwrap()
            .is_none()
    );
    assert!(
        tree.find_resource(&m.0, &ResId::Id(24), &ResId::Id(1), Some(0x0001_0409))
            .unwrap()
            .is_some()
    );
}

#[test]
fn named_language_identifiers_are_not_treated_as_numeric_neutral() {
    let (mut m, tree) = resource_id_tree(24, 1, 0);
    m.u16(0x18C, 1);
    m.u16(0x18E, 0);
    m.u32(0x190, 0x8000_0100);
    m.u16(0x200, 1);
    m.u16(0x202, u16::from(b'X'));
    for language in [None, Some(0)] {
        assert!(
            tree.find_resource(&m.0, &ResId::Id(24), &ResId::Id(1), language)
                .is_err()
        );
    }
}

#[test]
fn resource_names_match_exact_utf16_code_units_without_ascii_case_folding() {
    let (mut m, tree) = resource_id_tree(24, 1, 0);
    m.u16(0x10C, 1);
    m.u16(0x10E, 0);
    m.u32(0x110, 0x8000_0100);
    let name = vec![u16::from(b'A'), 0x00C4, 0xD83D, 0xDE00];
    m.u16(0x200, name.len() as u16);
    for (i, &unit) in name.iter().enumerate() {
        m.u16(0x202 + 2 * i, unit);
    }
    assert!(
        tree.find_resource(&m.0, &ResId::Name(name.clone()), &ResId::Id(1), None)
            .unwrap()
            .is_some()
    );
    for changed in [
        vec![u16::from(b'a'), 0x00C4, 0xD83D, 0xDE00],
        vec![u16::from(b'A'), 0x00E4, 0xD83D, 0xDE00],
        vec![u16::from(b'A'), 0x00C4, 0xD83D, 0xDE01],
    ] {
        assert_eq!(
            tree.find_resource(&m.0, &ResId::Name(changed), &ResId::Id(1), None)
                .unwrap(),
            None
        );
    }
}

#[test]
fn image_alignment_cannot_expand_sections_beyond_the_allocated_buffer() {
    let mut b = Builder::new(PeKind::Pe32Plus);
    b.section_alignment = 0x1_0000;
    b.sections[0].va = 0x1_0000;
    b.sections[0].vsize = 0xFFFF;
    b.sections[0].data = vec![0xA5; 0xFFFF];
    b.entry = 0x1_0000;
    b.size_of_image = Some(0x1_0001);
    assert!(matches!(parse(&b), Err(PeError::BadImageSize { .. })));
}

#[test]
fn headers_must_contain_the_section_table_and_obey_file_alignment() {
    for size in [0x100, 0x201] {
        let mut b = Builder::new(PeKind::Pe32Plus);
        b.size_of_headers = Some(size);
        b.sections[0].raw_ptr = Some(0x400);
        assert!(matches!(parse(&b), Err(PeError::BadImageSize { .. })));
    }
}

#[test]
fn preferred_image_base_obeys_64_kib_alignment() {
    for kind in [PeKind::Pe32, PeKind::Pe32Plus] {
        let mut b = Builder::new(kind);
        b.image_base += 1;
        assert!(parse(&b).is_err());
    }
}

#[test]
fn low_alignment_rvas_exclude_overlay_and_truncated_section_data() {
    let mut b = Builder::new(PeKind::Pe32);
    b.section_alignment = 0x200;
    b.file_alignment = 0x200;
    b.sections[0].va = 0x200;
    b.sections[0].raw_ptr = Some(0x200);
    b.entry = 0x200;
    b.size_of_image = Some(0x400);
    let mut bytes = b.build();
    bytes.resize(0x1000, 0xAA);
    let pe = PeImage::parse(bytes).unwrap();
    assert_eq!(pe.rva_to_file_offset(0x400), None);
    let mut bytes = b.build();
    bytes.truncate(0x210);
    assert_eq!(
        PeImage::parse(bytes).unwrap_err(),
        PeError::SectionDataOutOfFile { index: 0 }
    );
}

#[test]
fn alignment_helper_rejects_invalid_alignments_without_panicking() {
    for alignment in [0, 3, u64::MAX] {
        assert_eq!(align_up(1, alignment), None);
    }
    assert_eq!(align_up(u64::MAX, 2), None);
    assert_eq!(align_up(0xFFFF_F000, 0x1000), Some(0xFFFF_F000));
}

#[test]
fn highadj_second_slot_is_bounds_checked() {
    let mut m = Mem::new(0x10A);
    m.u32(0x100, 0);
    m.u32(0x104, 12);
    m.u16(0x108, 0x4020);
    assert_eq!(
        relocs::fixups(
            &m.0,
            DataDirectory {
                rva: 0x100,
                size: 12
            }
        ),
        Err(RelocError::BadBlock { rva: 0x100 })
    );
}

#[test]
fn highadj_preserves_signed_adjustment_and_rounding_carry() {
    // HIGHADJ reconstructs a rounded high half with a signed low half.
    // (high * 2^16 + sign_extend(low) + delta + 2^15) mod 2^32,
    // then takes bits 31:16. These boundaries distinguish sign extension
    // and the rounding carry from unsigned concatenation.
    for (low, delta, expected) in [
        (0x7FFF, 1u64, 0x0041),
        (0xFFFF, 1, 0x0040),
        (0x8000, u64::MAX, 0x003F),
        (0, 0x8000, 0x0041),
    ] {
        let mut m = Mem::new(0x200);
        m.u32(0x100, 0);
        m.u32(0x104, 12);
        m.u16(0x108, 0x4020);
        m.u16(0x10A, low);
        m.u16(0x20, 0x0040);
        relocs::apply(
            &mut m.0,
            DataDirectory {
                rva: 0x100,
                size: 12,
            },
            delta,
        )
        .unwrap();
        assert_eq!(
            m.0.u16_at(0x20).unwrap(),
            expected,
            "low {low:#x}, delta {delta:#x}"
        );
    }
}

#[test]
fn relocation_directory_cannot_silently_ignore_a_partial_block() {
    let mut m = Mem::new(0x200);
    m.u32(0x100, 0);
    m.u32(0x104, 12);
    assert_eq!(
        relocs::fixups(
            &m.0,
            DataDirectory {
                rva: 0x100,
                size: 14
            }
        ),
        Err(RelocError::BadBlock { rva: 0x10C })
    );
}

#[test]
fn failed_relocation_does_not_partially_modify_an_image() {
    let mut m = Mem::new(0x200);
    m.u32(0x100, 0);
    m.u32(0x104, 12);
    m.u16(0x108, 0x3020);
    m.u16(0x10A, 0x5024);
    m.u32(0x20, 0x40_0000);
    let before = m.0.clone();
    assert!(
        relocs::apply(
            &mut m.0,
            DataDirectory {
                rva: 0x100,
                size: 12
            },
            0x1_0000
        )
        .is_err()
    );
    assert_eq!(m.0, before);
}

#[test]
fn descriptor_terminators_must_fit_the_declared_directory() {
    let mut m = Mem::new(0x400);
    m.u32(0x10C, 0x300);
    m.u32(0x110, 0x200);
    assert!(
        imports::descriptors(
            &m.0,
            DataDirectory {
                rva: 0x100,
                size: 20
            }
        )
        .is_err()
    );
    m.u32(0x100, 1);
    m.u32(0x104, 0x300);
    assert!(
        imports::delay_descriptors(
            &m.0,
            DataDirectory {
                rva: 0x100,
                size: 32
            }
        )
        .is_err()
    );
}

#[test]
fn fixed_directories_do_not_read_past_their_declared_sizes() {
    let m = Mem::new(0x400);
    assert!(
        ExportDirectory::read(
            &m.0,
            DataDirectory {
                rva: 0x100,
                size: 39
            }
        )
        .is_err()
    );
    for kind in [PeKind::Pe32, PeKind::Pe32Plus] {
        let size = (4 * kind.pointer_size() + 8) as u32;
        assert!(
            TlsDirectory::read(
                &m.0,
                kind,
                DataDirectory {
                    rva: 0x100,
                    size: size - 1
                }
            )
            .is_err()
        );
    }
}

#[test]
fn tls_callbacks_reject_overflow_and_unterminated_arrays() {
    assert!(tls::callbacks(&[1u8; 8][..], PeKind::Pe32Plus, u64::MAX).is_err());
    let image = vec![1u8; tls::MAX_TLS_CALLBACKS * 8];
    assert!(tls::callbacks(&image, PeKind::Pe32Plus, 0).is_err());
}

#[test]
fn arm64_reserved_pdata_flag_is_not_packed_unwind_data() {
    let entry = pdata::Arm64RuntimeFunction {
        begin: 0x1000,
        unwind: 3 | (16 << 2),
    };
    assert_eq!(entry.packed_length(), None);
    let mut m = Mem::new(0x200);
    m.u32(0x100, entry.begin);
    m.u32(0x104, entry.unwind);
    assert!(
        pdata::lookup_arm64(
            &m.0,
            DataDirectory {
                rva: 0x100,
                size: 8
            },
            0x1000
        )
        .is_err()
    );
}

#[test]
fn load_config_declared_extent_bounds_fields() {
    let mut m = Mem::new(0x200);
    m.u32(0x100, 148);
    m.u64(0x158, 0x1_4000_3000);
    let config = LoadConfig::read(
        &m.0,
        PeKind::Pe32Plus,
        DataDirectory {
            rva: 0x100,
            size: 88,
        },
    )
    .unwrap()
    .unwrap();
    assert_eq!(config.security_cookie, None);
    assert_eq!(config.guard_flags, None);
}

#[test]
fn resource_directory_entries_cannot_escape_the_directory() {
    let mut m = Mem::new(0x200);
    m.u16(0x10E, 1);
    m.u32(0x110, 24);
    m.u32(0x114, 0x8000_0040);
    let tree = ResourceTree::new(DataDirectory {
        rva: 0x100,
        size: 16,
    })
    .unwrap();
    assert!(tree.names_of_type(&m.0, &ResId::Id(24)).is_err());
}

#[test]
fn forwarder_string_must_terminate_inside_the_export_directory() {
    let (mut m, range) = export_image();
    m.u32(0x148, 0x2FE);
    m.0[0x2FE..0x301].copy_from_slice(b"XYZ");
    let exports = ExportDirectory::read(&m.0, range).unwrap().unwrap();
    assert!(exports.by_index(&m.0, 2).is_err());
}

#[test]
fn partial_function_table_records_are_rejected() {
    let m = Mem::new(0x400);
    assert!(
        pdata::lookup_x64(
            &m.0,
            DataDirectory {
                rva: 0x100,
                size: 13
            },
            0
        )
        .is_err()
    );
    assert!(
        pdata::lookup_arm64(
            &m.0,
            DataDirectory {
                rva: 0x100,
                size: 9
            },
            0
        )
        .is_err()
    );
}

#[test]
fn tls_template_extent_rejects_reverse_addresses_and_overflow() {
    let mut m = Mem::new(0x200);
    m.u64(0x100, 0x1000);
    m.u64(0x108, 0xFFF);
    assert!(
        TlsDirectory::read(
            &m.0,
            PeKind::Pe32Plus,
            DataDirectory {
                rva: 0x100,
                size: 40
            }
        )
        .is_err()
    );
    m.u64(0x100, 0);
    m.u64(0x108, u64::MAX);
    m.u32(0x120, 1);
    assert!(
        TlsDirectory::read(
            &m.0,
            PeKind::Pe32Plus,
            DataDirectory {
                rva: 0x100,
                size: 40
            }
        )
        .is_err()
    );
}
