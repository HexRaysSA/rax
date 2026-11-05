use super::*;

fn header() -> Vec<u8> {
    // Independently written header: 48 bytes, object, profile 1, no entry.
    let mut bytes = vec![0; HEADER_SIZE];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[10..12].copy_from_slice(&1u16.to_le_bytes());
    bytes[12..14].copy_from_slice(&1u16.to_le_bytes());
    bytes[16..20].copy_from_slice(&1u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&48u64.to_le_bytes());
    bytes[32..40].copy_from_slice(&48u64.to_le_bytes());
    bytes[40..44].copy_from_slice(&NO_ENTRY.to_le_bytes());
    bytes
}

fn section(kind: u16, flags: u16, payload: &[u8]) -> Vec<u8> {
    let mut bytes = header();
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&(72u64 + payload.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&kind.to_le_bytes());
    bytes.extend_from_slice(&flags.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&72u64.to_le_bytes());
    bytes.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

fn error(bytes: &[u8]) -> DecodeError {
    decode(bytes, DecodeLimits::default()).unwrap_err()
}

#[test]
fn empty_envelope_is_not_an_executable_module() {
    let bytes = header();
    let decoded = decode(&bytes, DecodeLimits::default()).unwrap();
    assert_eq!(decoded.kind, ModuleKind::Object);
    assert_eq!(decoded.entry_function, None);
    assert!(decoded.sections.is_empty());
}

#[test]
fn every_truncated_header_is_rejected() {
    let bytes = header();
    for size in 0..HEADER_SIZE {
        assert_eq!(error(&bytes[..size]), DecodeError::Truncated);
    }
}

#[test]
fn header_fields_are_checked() {
    for (offset, expected) in [
        (0, DecodeError::Magic),
        (8, DecodeError::Version),
        (10, DecodeError::Version),
        (12, DecodeError::Header),
        (14, DecodeError::Header),
        (16, DecodeError::Header),
        (24, DecodeError::Header),
        (32, DecodeError::Header),
        (40, DecodeError::Header),
        (44, DecodeError::Header),
    ] {
        let mut bytes = header();
        bytes[offset] ^= 0x80;
        assert_eq!(error(&bytes), expected, "offset {offset}");
    }
}

#[test]
fn resource_limits_precede_allocations() {
    let bytes = header();
    assert_eq!(
        decode(
            &bytes,
            DecodeLimits {
                max_bytes: 47,
                max_sections: 0
            }
        )
        .unwrap_err(),
        DecodeError::Limit
    );
    let bytes = section(1, 1, b"abc");
    assert_eq!(
        decode(
            &bytes,
            DecodeLimits {
                max_bytes: 100,
                max_sections: 0
            }
        )
        .unwrap_err(),
        DecodeError::Limit
    );
}

#[test]
fn optional_metadata_is_borrowed_and_preserved() {
    let bytes = section(0x9000, 0, b"extension");
    let decoded = decode(&bytes, DecodeLimits::default()).unwrap();
    assert_eq!(decoded.sections[0].bytes, b"extension");
    assert_eq!(decoded.sections[0].bytes.as_ptr(), bytes[72..].as_ptr());
}

#[test]
fn executable_extensions_and_wrong_section_flags_are_rejected() {
    for (kind, flags) in [(10, 1), (10, 0), (1, 0), (0x9000, 1), (0x8000, 1)] {
        assert_eq!(
            error(&section(kind, flags, b"")),
            DecodeError::RequiredSection
        );
    }
}

#[test]
fn directory_and_ranges_are_checked_without_panicking() {
    for (offset, value, expected) in [
        (50, 2, DecodeError::Directory),
        (52, 1, DecodeError::Directory),
        (56, 0, DecodeError::Section),
        (56, u64::MAX, DecodeError::Section),
        (64, u64::MAX, DecodeError::Section),
    ] {
        let mut bytes = section(1, 1, b"x");
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        assert_eq!(error(&bytes), expected);
    }
    let mut bytes = header();
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    assert_eq!(error(&bytes), DecodeError::Directory);
}

#[test]
fn trailing_bytes_are_not_ignored() {
    let mut bytes = header();
    bytes.push(0);
    bytes[24..32].copy_from_slice(&49u64.to_le_bytes());
    assert_eq!(error(&bytes), DecodeError::Padding);
}
