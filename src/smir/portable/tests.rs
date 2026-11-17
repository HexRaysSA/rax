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

fn candidate_header() -> Vec<u8> {
    // Independent zero-payload directory. This is framing, not a valid module.
    let mut bytes = header();
    bytes[10..12].copy_from_slice(&2u16.to_le_bytes());
    bytes[16..20].copy_from_slice(&2u32.to_le_bytes());
    bytes[20..24].copy_from_slice(&10u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&288u64.to_le_bytes());
    for kind in 1u16..=10 {
        bytes.extend_from_slice(&kind.to_le_bytes());
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&288u64.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());
    }
    bytes
}

#[test]
fn candidate_framing_is_explicit_and_unverified() {
    let bytes = candidate_header();
    let candidate = decode_candidate(&bytes, DecodeLimits::default()).unwrap();
    assert_eq!(candidate.sections.len(), 10);
    assert!(candidate.sections.iter().all(|s| s.bytes.is_empty()));
    assert_eq!(
        decode(&bytes, DecodeLimits::default()),
        Err(DecodeError::Version)
    );
    assert_eq!(
        decode_candidate(&header(), DecodeLimits::default()),
        Err(DecodeError::Version)
    );
    let mut wrong_profile = bytes;
    wrong_profile[16..20].copy_from_slice(&1u32.to_le_bytes());
    assert_eq!(
        decode_candidate(&wrong_profile, DecodeLimits::default()),
        Err(DecodeError::Header)
    );
}

#[test]
fn candidate_requires_every_semantic_section() {
    for missing in 0..10 {
        let mut bytes = candidate_header();
        bytes.drain(48 + missing * 24..72 + missing * 24);
        bytes[20..24].copy_from_slice(&9u32.to_le_bytes());
        bytes[24..32].copy_from_slice(&264u64.to_le_bytes());
        for record in 0..9 {
            bytes[56 + record * 24..64 + record * 24].copy_from_slice(&264u64.to_le_bytes());
        }
        assert_eq!(
            decode_candidate(&bytes, DecodeLimits::default()),
            Err(DecodeError::RequiredSection),
            "missing section {}",
            missing + 1
        );
    }
}

fn record_schema() -> records::Schema {
    use records::Definition;
    std::collections::BTreeMap::from([
        (
            "sample".into(),
            Definition {
                fields: vec![
                    ("signed".into(), "i64".into()),
                    ("flag".into(), "bool".into()),
                    ("nested".into(), "opt:opt:u16".into()),
                ],
                ..Definition::default()
            },
        ),
        (
            "node".into(),
            Definition {
                fields: vec![("next".into(), "opt:node".into())],
                ..Definition::default()
            },
        ),
    ])
}

#[test]
fn record_wire_golden_and_integer_boundaries() {
    use records::{Codec, Limits, Value};
    let codec = Codec::new(record_schema(), Limits::default()).unwrap();
    let value = Value::Record(std::collections::BTreeMap::from([
        ("signed".into(), Value::Signed(i64::MIN)),
        ("flag".into(), Value::Boolean(true)),
        (
            "nested".into(),
            Value::Option(Some(Box::new(Value::Option(None)))),
        ),
    ]));
    let golden = [0, 0, 0, 0, 0, 0, 0, 128, 1, 1, 0];
    assert_eq!(codec.encode("sample", &value).unwrap(), golden);
    assert_eq!(codec.decode("sample", &golden).unwrap(), value);
    for end in 0..golden.len() {
        assert!(codec.decode("sample", &golden[..end]).is_err());
    }
    for bits in [8, 16, 32, 64] {
        let width = bits / 8;
        let unsigned = if bits == 64 {
            u64::MAX
        } else {
            (1u64 << bits) - 1
        };
        let signed = if bits == 64 {
            i64::MIN
        } else {
            -(1i64 << (bits - 1))
        };
        assert_eq!(
            codec
                .encode(&format!("u{bits}"), &Value::Unsigned(unsigned))
                .unwrap(),
            vec![255; width]
        );
        let mut golden = vec![0; width];
        golden[width - 1] = 128;
        assert_eq!(
            codec
                .encode(&format!("i{bits}"), &Value::Signed(signed))
                .unwrap(),
            golden
        );
        assert_eq!(
            codec.decode(&format!("i{bits}"), &golden).unwrap(),
            Value::Signed(signed)
        );
    }
}

#[test]
fn record_decoder_rejections_and_encoder_limits() {
    use records::{Codec, Error, Limits, Value};
    let codec = Codec::new(record_schema(), Limits::default()).unwrap();
    for (kind, bytes, expected) in [
        ("bool", &[2][..], "WIRE-RANGE"),
        ("opt:u8", &[2][..], "WIRE-TAG"),
        ("token", &[0][..], "WIRE-TEXT"),
        ("utf8", &[3, 0, 0, 0, 0xed, 0xa0, 0x80][..], "WIRE-TEXT"),
        ("u8", &[0, 0][..], "WIRE-TRAILING"),
    ] {
        assert_eq!(codec.decode(kind, bytes), Err(Error(expected)));
    }
    assert_eq!(
        codec.encode("i8", &Value::Signed(128)),
        Err(Error("WIRE-RANGE"))
    );
    assert_eq!(
        codec.encode("u8", &Value::Unsigned(256)),
        Err(Error("WIRE-RANGE"))
    );
    assert_eq!(
        codec.encode("bool", &Value::Unsigned(1)),
        Err(Error("WIRE-TYPE"))
    );
    let tiny = Codec::new(
        record_schema(),
        Limits {
            bytes: 1,
            ..Limits::default()
        },
    )
    .unwrap();
    assert_eq!(
        tiny.encode("u16", &Value::Unsigned(0)),
        Err(Error("WIRE-LIMIT"))
    );
    let shallow = Codec::new(
        record_schema(),
        Limits {
            depth: 2,
            ..Limits::default()
        },
    )
    .unwrap();
    assert_eq!(shallow.decode("node", &[1, 1, 0]), Err(Error("WIRE-LIMIT")));
    let mut bad = record_schema();
    bad.get_mut("sample")
        .unwrap()
        .fields
        .push(("signed".into(), "u8".into()));
    assert!(matches!(
        Codec::new(bad, Limits::default()),
        Err(Error("WIRE-SCHEMA"))
    ));
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

#[test]
fn zero_length_sections_can_share_the_canonical_offset() {
    let mut bytes = header();
    bytes[20..24].copy_from_slice(&2u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&96u64.to_le_bytes());
    for (kind, flags) in [(1u16, 1u16), (u16::MAX, 0)] {
        bytes.extend_from_slice(&kind.to_le_bytes());
        bytes.extend_from_slice(&flags.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&96u64.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());
    }
    let decoded = decode(&bytes, DecodeLimits::default()).unwrap();
    assert_eq!(decoded.sections.len(), 2);
    assert!(
        decoded
            .sections
            .iter()
            .all(|section| section.bytes.is_empty())
    );
    assert_eq!(decoded.sections[1].kind, u16::MAX);
}

#[test]
fn byte_and_section_limits_are_inclusive() {
    let bytes = section(1, 1, b"x");
    let limits = DecodeLimits {
        max_bytes: bytes.len(),
        max_sections: 1,
    };
    assert!(decode(&bytes, limits).is_ok());
    assert_eq!(
        decode(
            &bytes,
            DecodeLimits {
                max_bytes: bytes.len() - 1,
                ..limits
            }
        ),
        Err(DecodeError::Limit)
    );
    assert_eq!(
        decode(
            &bytes,
            DecodeLimits {
                max_sections: 0,
                ..limits
            }
        ),
        Err(DecodeError::Limit)
    );
}

#[test]
fn resource_limits_precede_malformed_header_diagnostics() {
    let bytes = [0u8; HEADER_SIZE];
    assert_eq!(error(&bytes), DecodeError::Magic);
    assert_eq!(
        decode(
            &bytes,
            DecodeLimits {
                max_bytes: HEADER_SIZE - 1,
                max_sections: 0,
            }
        ),
        Err(DecodeError::Limit)
    );
}

fn refined_schema() -> records::Schema {
    std::collections::BTreeMap::from([("subject".into(), records::Definition {
        fields: vec![("ids".into(), "vec:u32".into()), ("view".into(), "opt:utf8".into())],
        ..records::Definition::default()
    })])
}

fn refinements() -> records::Refinements {
    use records::{CountBounds, Refinements, ScalarRule};
    Refinements {
        counts: std::collections::BTreeMap::from([("subject.ids".into(), CountBounds { minimum: 0, maximum: 1 })]),
        scalars: std::collections::BTreeMap::from([
            ("subject.ids[]".into(), vec![ScalarRule::UnsignedRange { minimum: 0, maximum: u32::MAX as u64 - 1 }]),
            ("subject.view".into(), vec![ScalarRule::TextOneOf(vec!["complete".into(), "nonvirtual".into()])]),
        ]),
    }
}

#[test]
fn refined_vector_count_precedes_elements() {
    let codec = records::Codec::new_refined(refined_schema(), records::Limits::default(), refinements()).unwrap();
    assert_eq!(codec.decode("subject", &2u32.to_le_bytes()), Err(records::Error("WIRE-REFINEMENT-COUNT")));
    assert_eq!(records::Codec::new(refined_schema(), records::Limits::default()).unwrap().decode("subject", &2u32.to_le_bytes()), Err(records::Error("WIRE-TRUNCATED")));
}

#[test]
fn refined_vector_leaf_and_option_leaf_are_symmetric() {
    use records::{Codec, Limits, Value, Error};
    let generic = Codec::new(refined_schema(), Limits::default()).unwrap();
    let refined = Codec::new_refined(refined_schema(), Limits::default(), refinements()).unwrap();
    for (id, view, valid) in [(0xfffffffe, None, true), (0xfffffffe, Some("complete"), true), (0xfffffffe, Some("nonvirtual"), true), (0xffffffff, None, false), (0, Some("bogus"), false)] {
        let value = Value::Record(std::collections::BTreeMap::from([
            ("ids".into(), Value::Vector(vec![Value::Unsigned(id)])),
            ("view".into(), Value::Option(view.map(|v| Box::new(Value::Text(v.into()))))),
        ]));
        let raw = generic.encode("subject", &value).unwrap();
        if valid {
            assert_eq!(refined.decode("subject", &raw).unwrap(), value);
            assert_eq!(refined.encode("subject", &value).unwrap(), raw);
        } else {
            assert_eq!(refined.decode("subject", &raw), Err(Error("WIRE-REFINEMENT-SCALAR")));
            assert_eq!(refined.encode("subject", &value), Err(Error("WIRE-REFINEMENT-SCALAR")));
        }
    }
}

#[test]
fn refined_configuration_rejects_unknown_and_incompatible_rules() {
    use records::{Codec, Limits, ScalarRule};
    for path in ["subject.unknown", "missing.ids", "subject.ids[][]", "subject.ids.bad"] {
        let mut policy = refinements();
        policy.scalars.insert(path.into(), vec![ScalarRule::UnsignedEquals(0)]);
        assert_eq!(Codec::new_refined(refined_schema(), Limits::default(), policy).err(), Some(records::Error("WIRE-REFINEMENT-CONFIG")));
    }
    let mut policy = refinements(); policy.scalars.insert("subject.view".into(), vec![ScalarRule::BooleanEquals(true)]);
    assert_eq!(Codec::new_refined(refined_schema(), Limits::default(), policy).err(), Some(records::Error("WIRE-REFINEMENT-CONFIG")));
    let mut policy = refinements(); policy.counts.get_mut("subject.ids").unwrap().minimum = 2;
    assert_eq!(Codec::new_refined(refined_schema(), Limits::default(), policy).err(), Some(records::Error("WIRE-REFINEMENT-CONFIG")));
}

#[test]
fn refined_nested_options_skip_only_absent_values() {
    use records::{Codec, Limits, ScalarRule, Value};
    let mut policy = records::Refinements::default();
    policy.scalars.insert("sample.flag".into(), vec![ScalarRule::BooleanEquals(true)]);
    policy.scalars.insert("sample.nested".into(), vec![ScalarRule::UnsignedRange { minimum: 0, maximum: 7 }]);
    let codec = Codec::new_refined(record_schema(), Limits::default(), policy).unwrap();
    let generic = Codec::new(record_schema(), Limits::default()).unwrap();
    for (flag, nested, valid) in [(true, Value::Option(None), true), (true, Value::Option(Some(Box::new(Value::Option(None)))), true), (true, Value::Option(Some(Box::new(Value::Option(Some(Box::new(Value::Unsigned(7))))))), true), (false, Value::Option(None), false), (true, Value::Option(Some(Box::new(Value::Option(Some(Box::new(Value::Unsigned(8))))))), false)] {
        let value = Value::Record(std::collections::BTreeMap::from([("signed".into(), Value::Signed(0)), ("flag".into(), Value::Boolean(flag)), ("nested".into(), nested)]));
        let raw = generic.encode("sample", &value).unwrap();
        assert_eq!(codec.encode("sample", &value).is_ok(), valid);
        assert_eq!(codec.decode("sample", &raw).is_ok(), valid);
    }
}

#[test]
fn refined_variant_and_nested_vector_paths_are_exact() {
    use records::{Codec, CountBounds, Definition, Limits, Refinements, ScalarRule, Value};
    let schema = std::collections::BTreeMap::from([("choice".into(), Definition { discriminator: Some("kind".into()), variants: std::collections::BTreeMap::from([("grid".into(), vec![("cells".into(), "vec:vec:u8".into())])]), ..Definition::default() })]);
    let policy = Refinements { counts: std::collections::BTreeMap::from([("choice.grid.cells[]".into(), CountBounds { minimum: 0, maximum: 1 })]), scalars: std::collections::BTreeMap::from([("choice.grid.cells[][]".into(), vec![ScalarRule::UnsignedEquals(7)])]) };
    let codec = Codec::new_refined(schema.clone(), Limits::default(), policy).unwrap();
    let generic = Codec::new(schema, Limits::default()).unwrap();
    for (cells, valid) in [(vec![Value::Unsigned(7)], true), (vec![Value::Unsigned(8)], false), (vec![Value::Unsigned(7), Value::Unsigned(7)], false)] {
        let value = Value::Record(std::collections::BTreeMap::from([("kind".into(), Value::Text("grid".into())), ("cells".into(), Value::Vector(vec![Value::Vector(cells)]))]));
        let raw = generic.encode("choice", &value).unwrap();
        assert_eq!(codec.encode("choice", &value).is_ok(), valid);
        assert_eq!(codec.decode("choice", &raw).is_ok(), valid);
    }
}
