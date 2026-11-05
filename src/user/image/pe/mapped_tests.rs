//! Mapped-view metadata and byte layout must come from the same projection.
use super::*;

#[test]
fn projected_headers_and_rva_bytes_preserve_the_original_file() {
    let mut builder = Builder::new(PeKind::Pe32Plus);
    builder.machine = IMAGE_FILE_MACHINE_ARM64;
    let file = builder.build();
    let original = PeImage::parse(file.clone()).unwrap();
    let mut memory = original.memory_image();
    let nt = builder.lfanew as usize;
    memory[nt + 4..nt + 6].copy_from_slice(&IMAGE_FILE_MACHINE_AMD64.to_le_bytes());
    // The projected entry point is an x64 syscall leaf at a different RVA.
    memory[nt + 40..nt + 44].copy_from_slice(&0x1008u32.to_le_bytes());
    memory[0x1008..0x100C].copy_from_slice(&[0x4C, 0x8B, 0xD1, 0xC3]);
    let projected = original.with_mapped_view(memory.clone().into()).unwrap();
    assert_eq!(projected.headers().machine, IMAGE_FILE_MACHINE_AMD64);
    assert_eq!(projected.headers().entry_rva, 0x1008);
    assert_eq!(projected.memory_image(), memory);
    assert_eq!(projected.bytes().as_ref(), file.as_slice());
    assert_eq!(original.headers().machine, IMAGE_FILE_MACHINE_ARM64);
    assert_eq!(&original.memory_image()[0x1008..0x100C], &[0xC3; 4]);
}

#[test]
fn mapped_view_rejects_truncation_identity_and_section_geometry_changes() {
    let source = PeImage::parse(Builder::new(PeKind::Pe32Plus).build()).unwrap();
    let memory = source.memory_image();
    for length in [0, 63, memory.len() - 1, memory.len() + 1] {
        let mut altered = memory.clone();
        altered.resize(length, 0);
        assert!(source.with_mapped_view(altered.into()).is_err(), "{length}");
    }
    let nt = source.headers().nt_offset as usize;
    let section = nt + 24 + source.headers().size_of_optional_header as usize;
    for at in [nt + 8, section, section + 8, section + 20, section + 36] {
        let mut altered = memory.clone();
        altered[at] ^= 1;
        assert!(source.with_mapped_view(altered.into()).is_err(), "{at:#x}");
    }
}

#[test]
fn mapped_views_do_not_validate_raw_file_offsets_against_the_mapped_extent() {
    let mut builder = Builder::new(PeKind::Pe32Plus);
    // A valid file can have padding beyond SizeOfImage before its section data.
    builder.sections[0].raw_ptr = Some(0x4000);
    let source = PeImage::parse(builder.build()).unwrap();
    assert!(source.bytes().len() > source.mapped_size() as usize);
    let memory = source.memory_image();
    assert_eq!(
        source
            .with_mapped_view(memory.clone().into())
            .unwrap()
            .memory_image(),
        memory
    );
}

#[test]
fn file_rva_reads_match_mapping_across_headers_sections_gaps_and_zero_fill() {
    for kind in [PeKind::Pe32, PeKind::Pe32Plus] {
        let mut builder = Builder::new(kind);
        builder.sections[0].vsize = 0x30;
        builder.sections[0].raw_ptr = Some(0x4000);
        builder
            .sections
            .push(Sec::new(".data", 0x3000, 0x40, vec![0xA5; 19], DATA_RW));
        let image = PeImage::parse(builder.build()).unwrap();
        let expected = image.memory_image();
        for start in [
            0, 1, 0x1FF, 0x200, 0xFFF, 0x1000, 0x100F, 0x1010, 0x2FF0, 0x3000, 0x3013,
        ] {
            for count in [0, 1, 2, 31, 4096] {
                if start + count > expected.len() {
                    continue;
                }
                let mut bytes = vec![0xCC; count];
                image.read_rva(start as u64, &mut bytes).unwrap();
                assert_eq!(
                    bytes,
                    expected[start..start + count],
                    "{kind:?} {start:#x}+{count}"
                );
            }
        }
        assert!(image.read_rva(expected.len() as u64, &mut []).is_ok());
        assert!(image.read_rva(expected.len() as u64, &mut [0]).is_err());
        assert!(image.read_rva(u64::MAX, &mut [0]).is_err());
        let projected = image.with_mapped_view(expected.clone().into()).unwrap();
        let mut bytes = vec![0xCC; expected.len()];
        projected.read_rva(0, &mut bytes).unwrap();
        assert_eq!(bytes, expected);
    }
}

#[test]
fn sparse_rva_reads_do_not_expand_an_oversized_declared_image() {
    let mut builder = Builder::new(PeKind::Pe32Plus);
    builder.size_of_image = Some(0xFFFF_F000);
    let image = PeImage::parse(builder.build()).unwrap();
    assert!(image.bytes().len() < 4096);
    assert_eq!(image.mapped_size(), 0xFFFF_F000);
    let mut tail = [0xCC; 16];
    image.read_rva(0xFFFF_EFF0, &mut tail).unwrap();
    assert_eq!(tail, [0; 16]);
    assert!(image.read_rva(0xFFFF_EFF1, &mut tail).is_err());
}

#[test]
fn low_alignment_rva_reads_use_file_bytes_without_section_reinterpretation() {
    let mut builder = Builder::new(PeKind::Pe32);
    builder.section_alignment = 0x200;
    builder.sections[0].va = 0x200;
    builder.entry = 0x200;
    let image = PeImage::parse(builder.build()).unwrap();
    let expected = image.memory_image();
    let mut actual = vec![0xCC; expected.len()];
    image.read_rva(0, &mut actual).unwrap();
    assert_eq!(actual, expected);
}
