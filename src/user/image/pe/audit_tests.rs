//! Malformed-image and boundary regressions for the PE audit.

use super::*;

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
