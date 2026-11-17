use crate::{Limits, abi::layout::*, limits::Budget};

mod ordinary_scalar;
mod ordinary_pointer;
mod nonordinary_entry;

#[test]
fn bitint_every_precision_and_signedness() {
    for bits in 1..=65_535 {
        for signed in [false, true] {
            if bits == 1 && signed {
                assert!(bitint(bits, signed).is_err());
                continue;
            }
            let expected_align = match bits {
                1..=8 => 1,
                9..=16 => 2,
                17..=32 => 4,
                _ => 8,
            };
            let expected_size = u64::from(bits).div_ceil(expected_align * 8) * expected_align;
            assert_eq!(
                bitint(bits, signed).unwrap(),
                Geometry {
                    size: expected_size,
                    align: expected_align
                }
            );
        }
    }
    assert!(bitint(0, false).is_err());
    assert!(bitint(65_536, false).is_err());
}

#[test]
fn source_extent_is_symbolic_and_overflow_checked() {
    assert_eq!(
        array(Geometry { size: 1, align: 1 }, MAX_OBJECT_BYTES)
            .unwrap()
            .size,
        MAX_OBJECT_BYTES
    );
    assert!(array(Geometry { size: 8, align: 8 }, MAX_OBJECT_BYTES).is_err());
    assert!(bit_extent(u64::MAX, 1, 1).is_err());
    assert!(bit_extent(MAX_OBJECT_BYTES * 8, 1, MAX_OBJECT_BYTES).is_err());
    assert!(bit_extent(MAX_OBJECT_BYTES * 8 - 1, 1, MAX_OBJECT_BYTES).is_ok());
    assert_eq!(
        array(
            Geometry {
                size: 16,
                align: 16
            },
            0
        )
        .unwrap()
        .size,
        0
    );
}

#[test]
fn vector_atomic_and_scalar_policy() {
    assert_eq!(
        scalar("long double"),
        Some(Geometry {
            size: 16,
            align: 16
        })
    );
    assert_eq!(
        scalar("function_member_pointer"),
        Some(Geometry { size: 16, align: 8 })
    );
    assert_eq!(
        vector(Geometry { size: 4, align: 4 }, 3).unwrap(),
        Geometry {
            size: 16,
            align: 16
        }
    );
    assert!(vector(Geometry { size: 8, align: 8 }, 9).is_err());
    assert!(vector(Geometry { size: 1, align: 1 }, 0).is_err());
    assert_eq!(
        atomic(Geometry { size: 9, align: 8 }).unwrap(),
        Geometry {
            size: 16,
            align: 16
        }
    );
    assert_eq!(
        atomic(Geometry { size: 24, align: 8 }).unwrap(),
        Geometry { size: 24, align: 8 }
    );
    assert!(signed_name("char"));
    assert!(!signed_name("wint_t"));
}

#[test]
fn invalid_alignment_and_projection_budget_fail_before_clone() {
    for align in [0, 3, 65_537, 1 << 32] {
        assert!(alignment(align).is_err());
    }
    assert!(align_up(u64::MAX, 8).is_err());
    let limits = Limits {
        max_derived_bytes: 0,
        ..Limits::default()
    };
    let mut budget = Budget::new(&limits);
    let value = crate::wire::RecordValue::Text("source".into());
    assert!(crate::abi::value::owned(&value, &mut budget).is_err());
}

#[test]
fn canonical_ascii_preserves_utf16_surrogates_and_exact_json() {
    let mut budget = Budget::new(&Limits::default());
    let value = serde_json::json!({"z": "\u{00c5}\u{1f600}", "a": [1, true, null]});
    assert_eq!(
        crate::abi::nominal::ascii_json(&value, &mut budget).unwrap(),
        br#"{"a":[1,true,null],"z":"\u00c5\ud83d\ude00"}"#
    );
}

#[test]
fn graph_quotient_erases_sharing_and_preserves_edge_order() {
    use crate::abi::nominal::canonical_quotient;
    use serde_json::json;
    let mut budget = Budget::new(&Limits::default());
    let one = canonical_quotient(&[json!({"kind":"p"})], &[vec![0]], &mut budget).unwrap();
    let two = canonical_quotient(
        &[json!({"kind":"p"}), json!({"kind":"p"})],
        &[vec![1], vec![0]],
        &mut budget,
    )
    .unwrap();
    assert_eq!(one, two);
    assert_eq!(one, br#"[{"children":[0],"label":{"kind":"p"}}]"#);
    let labels = [
        json!({"kind":"r"}),
        json!({"kind":"a"}),
        json!({"kind":"b"}),
    ];
    let a = canonical_quotient(&labels, &[vec![1, 2], vec![], vec![]], &mut budget).unwrap();
    let b = canonical_quotient(&labels, &[vec![2, 1], vec![], vec![]], &mut budget).unwrap();
    assert_ne!(a, b);
}

// Test-only conversion follows the independent frozen JSON/schema fixtures.
// Production verification consumes the actual Rust ordered decoder, never JSON.
fn fixture_value(
    kind: &str,
    value: &serde_json::Value,
    schema: &serde_json::Value,
) -> crate::wire::RecordValue {
    use crate::wire::RecordValue as V;
    if let Some(child) = kind.strip_prefix("vec:") {
        return V::Vector(
            value
                .as_array()
                .unwrap()
                .iter()
                .map(|v| fixture_value(child, v, schema))
                .collect(),
        );
    }
    if let Some(child) = kind.strip_prefix("opt:") {
        return V::Option(if value.is_null() {
            None
        } else {
            Some(Box::new(fixture_value(child, &value["some"], schema)))
        });
    }
    match kind {
        "utf8" | "token" => return V::Text(value.as_str().unwrap().into()),
        "bool" => return V::Boolean(value.as_bool().unwrap()),
        "bytes" | "hex" | "digest32" => {
            let text = value.as_str().unwrap();
            return V::Bytes(
                (0..text.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
                    .collect(),
            );
        }
        "u8" | "u16" | "u32" | "u64" => return V::Unsigned(value.as_u64().unwrap()),
        "i8" | "i16" | "i32" | "i64" => return V::Signed(value.as_i64().unwrap()),
        _ => {}
    }
    let definition = &schema["records"][kind];
    let mut result = std::collections::BTreeMap::new();
    let fields = if let Some(discriminator) = definition.get("discriminator") {
        let name = discriminator.as_str().unwrap();
        let variant = value[name].as_str().unwrap();
        result.insert(name.into(), V::Text(variant.into()));
        &definition["variants"][variant]
    } else {
        &definition["fields"]
    };
    for pair in fields.as_array().unwrap() {
        let name = pair[0].as_str().unwrap();
        let kind = pair[1].as_str().unwrap();
        result.insert(name.into(), fixture_value(kind, &value[name], schema));
    }
    V::Record(result)
}

#[test]
fn every_frozen_complete_nominal_fingerprint_matches_independent_oracle() {
    use crate::abi::{
        nominal::Graph,
        value::{bytes, field, flags, id},
    };
    use crate::wire::RecordValue as V;
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../docs/specifications/smir/portable/schema/abi/candidate.json"
    ))
    .unwrap();
    let document: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../docs/specifications/smir/portable/conformance/abi/candidate/complete.json"
    ))
    .unwrap();
    let root = fixture_value("abi_contract", &document, &schema);
    let symbols = fixture_module_symbols();
    let mut budget = Budget::new(&Limits::default());
    let graph = Graph::new(&root, &symbols, &mut budget).unwrap();
    let mut checked = 0;
    for typ in graph.types.values() {
        if flags(typ, "flags", "complete").unwrap() {
            let actual = graph
                .fingerprint(id(field(typ, "id").unwrap()).unwrap(), false, &mut budget)
                .unwrap();
            let expected =
                bytes(field(field(typ, "identity").unwrap(), "definition").unwrap()).unwrap();
            assert_eq!(
                actual.as_slice(),
                expected,
                "nominal {:?}",
                field(typ, "id").unwrap()
            );
            checked += 1;
        }
    }
    assert!(checked >= 20);
}

fn fixture_module_symbols() -> crate::wire::RecordValue {
    use crate::wire::RecordValue as V;
    use std::collections::BTreeMap;
    // Explicit mathematical fixture data, not an ObjectContext/phase issuer.
    V::Record(BTreeMap::from([(
        "manifest".into(),
        V::Record(BTreeMap::from([
            ("dependencies".into(), V::Vector(vec![])),
            (
                "key".into(),
                V::Record(BTreeMap::from([
                    ("namespace".into(), V::Text("abi".into())),
                    ("name".into(), V::Text("fixture".into())),
                    ("abi_major".into(), V::Unsigned(1)),
                    ("abi_minor".into(), V::Unsigned(0)),
                ])),
            ),
        ])),
    )]))
}

fn fixture_graph(budget: &mut Budget) -> crate::abi::nominal::Graph {
    use crate::wire::RecordValue as V;
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../docs/specifications/smir/portable/schema/abi/candidate.json"
    ))
    .unwrap();
    let document: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../docs/specifications/smir/portable/conformance/abi/candidate/complete.json"
    ))
    .unwrap();
    let root = fixture_value("abi_contract", &document, &schema);
    let symbols = fixture_module_symbols();
    crate::abi::nominal::Graph::new(&root, &symbols, budget).unwrap()
}

#[test]
fn symbolic_value_masks_match_seventeen_independent_reference_cases() {
    use crate::abi::{
        mask::{ComparisonMask, build},
        nominal::self_ref,
        value::{field, uint},
    };
    let cases: serde_json::Value = serde_json::from_str(include_str!("value-masks.json")).unwrap();
    let mut budget = Budget::new(&Limits::default());
    let graph = fixture_graph(&mut budget);
    let mut count = 0;
    for case in cases["cases"].as_array().unwrap() {
        let identifier = case["id"].as_u64().unwrap() as u32;
        let text = case["mask"].as_str().unwrap();
        let expected = (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect::<Vec<_>>();
        let size =
            uint(field(graph.layout(&self_ref(identifier)).unwrap(), "size").unwrap()).unwrap();
        let source = build(&graph, identifier, &mut budget).unwrap();
        let view = ComparisonMask::new(source, 0, size * 8, size);
        assert!(
            view.matches(&expected, &mut budget).unwrap(),
            "nominal {identifier}"
        );
        let mut wrong = expected.clone();
        wrong[0] ^= 1;
        assert!(
            !view.matches(&wrong, &mut budget).unwrap(),
            "mutated nominal {identifier}"
        );
        count += 1;
    }
    assert_eq!(count, 17);
}

#[test]
fn huge_repeated_padding_mask_queries_do_not_expand_count() {
    use crate::{
        abi::{
            mask::{ComparisonMask, build},
            nominal::self_ref,
            value::{field, uint},
        },
        wire::RecordValue as V,
    };
    use std::{collections::BTreeMap, sync::Arc};
    let mut budget = Budget::new(&Limits::default());
    let mut graph = fixture_graph(&mut budget);
    let count = MAX_OBJECT_BYTES / 16;
    // A huge array of unsigned _BitInt(65): 65 value bits, 63 padding bits
    // per 16-B element. This unit tests geometry without issuing an ABI proof.
    let mut typ = match graph.typ_id(10).unwrap().clone() {
        V::Record(record) => record,
        _ => unreachable!(),
    };
    typ.insert("id".into(), V::Unsigned(500));
    typ.insert("kind".into(), V::Text("array".into()));
    typ.insert("layout".into(), V::Option(Some(Box::new(V::Unsigned(500)))));
    typ.insert(
        "extent".into(),
        V::Option(Some(Box::new(V::Unsigned(count)))),
    );
    typ.insert("elements".into(), V::Vector(vec![self_ref(10)]));
    graph.types.insert(500, Arc::new(V::Record(typ)));
    let layout = graph.layout_id(10).unwrap();
    let mut layout = match layout.clone() {
        V::Record(record) => record,
        _ => unreachable!(),
    };
    layout.insert("id".into(), V::Unsigned(500));
    layout.insert("size".into(), V::Unsigned(count * 16));
    graph.layouts.insert(500, Arc::new(V::Record(layout)));
    let source = build(&graph, 500, &mut budget).unwrap();
    let offset = (count - 1) * 128 + 64;
    let view = ComparisonMask::new(source, offset, 8, 1);
    assert!(view.matches(&[1], &mut budget).unwrap());
    assert!(!view.matches(&[0xff], &mut budget).unwrap());
    let source = build(&graph, 500, &mut budget).unwrap();
    assert!(
        !source
            .any((count - 1) * 128 + 65, count * 128, &mut budget)
            .unwrap()
    );
    assert!(
        source
            .any((count - 1) * 128 + 64, count * 128, &mut budget)
            .unwrap()
    );
    assert!(!source.all(0, count * 128, &mut budget).unwrap());
    let _ = BTreeMap::<u32, u32>::new();
    let _ = uint(field(graph.layout_id(500).unwrap(), "size").unwrap()).unwrap();
}

#[test]
fn actual_all_root_source_records_reach_complete_abi_predicates() {
    let cases: serde_json::Value = serde_json::from_str(include_str!("phase-cases.json")).unwrap();
    let mut checked = 0;
    for case in cases["cases"].as_array().unwrap() {
        let text = case["encoded_hex"].as_str().unwrap();
        let data = (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect::<Vec<_>>();
        let limits = Limits::default();
        let parsed = crate::decode_object(&data, limits).unwrap();
        let mut budget = Budget::new(&limits);
        let ctx = crate::context::ObjectContext::new(parsed, &mut budget).unwrap();
        let types = crate::execution::verify_types(&ctx, &mut budget).unwrap();
        let result = crate::abi::verify(&ctx, &types, &mut budget);
        // Preserve the historical corpus/bytes. The two explicitly released
        // scalar-coverage transitions have separate actual-factory witnesses.
        let current_scalar = matches!(case["name"].as_str(),
            Some("unused-valid-extra-nominal" | "unused-valid-extra-signature"));
        if case["expected"] == "verified-abi" || current_scalar {
            let facts = result.unwrap_or_else(|error| panic!("case {}: {error}", case["name"]));
            facts.assert_context(&ctx).unwrap();
            assert_eq!(facts.identity(), ctx.identity());
            assert!(facts.requirements().is_empty());
            checked += 1;
            continue;
        }
        let error = match result {
            Ok(_) => panic!("unexpected ABI proof for {}", case["name"]),
            Err(error) => error,
        };
        assert_eq!(
            error.code(),
            case["expected"].as_str().unwrap(),
            "case {}: {error}",
            case["name"]
        );
        assert_eq!(
            error.class(),
            if error.code() == "P2_ABI_VERIFIER_INCOMPLETE" {
                crate::ErrorClass::UnavailableEvidence
            } else {
                crate::ErrorClass::Semantic
            }
        );
        checked += 1;
    }
    assert_eq!(checked, 103);
}

#[test]
fn genuine_scalar_abi_proof_rejects_equal_bytes_context_substitution() {
    use crate::context::{Namespace, ObjectContext};
    let cases: serde_json::Value = serde_json::from_str(include_str!("phase-cases.json")).unwrap();
    let case = &cases["cases"][0];
    assert_eq!(case["name"], "portable-identity");
    let text = case["encoded_hex"].as_str().unwrap();
    let bytes = (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect::<Vec<_>>();
    let limits = Limits::default();
    let mut budget = Budget::new(&limits);
    let first =
        ObjectContext::new(crate::decode_object(&bytes, limits).unwrap(), &mut budget).unwrap();
    let second =
        ObjectContext::new(crate::decode_object(&bytes, limits).unwrap(), &mut budget).unwrap();
    assert_eq!(first.identity(), second.identity());
    assert_ne!(first.context_id(), second.context_id());
    let types = crate::execution::verify_types(&first, &mut budget).unwrap();
    let facts = crate::abi::verify(&first, &types, &mut budget).unwrap();
    assert_eq!(
        facts.assert_context(&second).unwrap_err().code(),
        "ABI_CC_CONTEXT"
    );
    let actual = first.local(Namespace::CallSignature, 0).unwrap();
    let foreign = second.local(Namespace::CallSignature, 0).unwrap();
    assert!(facts.signature(actual).is_ok());
    assert_eq!(
        facts.signature(foreign).err().unwrap().code(),
        "ABI_CC_ENTITY_NAMESPACE"
    );
    assert!(
        facts
            .source_call_compatible(actual, actual, &mut budget)
            .unwrap()
    );
    let scalar = first.local(Namespace::Nominal, 1).unwrap();
    let function = first.local(Namespace::Nominal, 12).unwrap();
    assert!(
        facts
            .source_compatible(scalar, scalar, &mut budget)
            .unwrap()
    );
    assert!(
        !facts
            .source_compatible(scalar, function, &mut budget)
            .unwrap()
    );
    let other_context = second.local(Namespace::Nominal, 1).unwrap();
    assert_eq!(
        facts
            .source_compatible(scalar, other_context, &mut budget)
            .unwrap_err()
            .code(),
        "ABI_CC_ENTITY_NAMESPACE"
    );
}

#[test]
fn supported_abi_profiles_reach_actual_all_phase_factory() {
    let cases: serde_json::Value = serde_json::from_str(include_str!("phase-cases.json")).unwrap();
    let mut positives = 0;
    for case in cases["cases"].as_array().unwrap() {
        if case["all_phase"] != true {
            continue;
        }
        let text = case["encoded_hex"].as_str().unwrap();
        let bytes = (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect::<Vec<_>>();
        let verified = crate::verify_object(&bytes, Limits::default())
            .unwrap_or_else(|error| panic!("actual factory case {}: {error}", case["name"]));
        let decoded = crate::decode_object(&bytes, Limits::default()).unwrap();
        assert_eq!(verified.identity(), decoded.identity());
        assert_eq!(verified.requirements().iter().count(), 7);
        positives += 1;
    }
    assert_eq!(positives, 20);
}

#[test]
fn genuine_whole_object_storage_facts_match_independent_value_masks() {
    use crate::context::{Namespace, ObjectContext};
    let cases: serde_json::Value = serde_json::from_str(include_str!("phase-cases.json")).unwrap();
    let mut checked = 0;
    for case in cases["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| case["storage_masks"].is_array())
    {
        let text = case["encoded_hex"].as_str().unwrap();
        let data = (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect::<Vec<_>>();
        let limits = Limits::default();
        let mut budget = Budget::new(&limits);
        let ctx =
            ObjectContext::new(crate::decode_object(&data, limits).unwrap(), &mut budget).unwrap();
        let types = crate::execution::verify_types(&ctx, &mut budget).unwrap();
        let facts = crate::abi::verify(&ctx, &types, &mut budget).unwrap();
        for oracle in case["storage_masks"].as_array().unwrap() {
            let key = ctx
                .local(
                    Namespace::StorageBinding,
                    oracle["id"].as_u64().unwrap() as u32,
                )
                .unwrap();
            let binding = facts.storage_binding(key).unwrap();
            assert!(facts.nominal(binding.nominal()).is_ok());
            types.layout(binding.execution_layout()).unwrap();
            if oracle["mask"].is_null() {
                assert!(!binding.has_comparison_mask());
                assert_eq!(
                    binding
                        .comparison_mask_matches(&[], &mut budget)
                        .unwrap_err()
                        .code(),
                    "ABI_CC_NO_COMPARISON_MASK"
                );
            } else {
                assert!(binding.has_comparison_mask());
                let text = oracle["mask"].as_str().unwrap();
                let mut mask = (0..text.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
                    .collect::<Vec<_>>();
                assert!(binding.comparison_mask_matches(&mask, &mut budget).unwrap());
                mask[0] ^= 1;
                assert!(!binding.comparison_mask_matches(&mask, &mut budget).unwrap());
            }
            checked += 1;
        }
    }
    assert_eq!(checked, 12);
}

#[test]
fn genuine_trivial_journal_is_context_bound_and_retains_external_obligations() {
    use crate::context::{Namespace, ObjectContext};
    let cases: serde_json::Value = serde_json::from_str(include_str!("phase-cases.json")).unwrap();
    let case = cases["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "actual-sem-external-cleanup-local-journal")
        .unwrap();
    let text = case["encoded_hex"].as_str().unwrap();
    let data = (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect::<Vec<_>>();
    let limits = Limits::default();
    let mut budget = Budget::new(&limits);
    let ctx =
        ObjectContext::new(crate::decode_object(&data, limits).unwrap(), &mut budget).unwrap();
    let other =
        ObjectContext::new(crate::decode_object(&data, limits).unwrap(), &mut budget).unwrap();
    let types = crate::execution::verify_types(&ctx, &mut budget).unwrap();
    let facts = crate::abi::verify(&ctx, &types, &mut budget).unwrap();
    let own_key = ctx.local(Namespace::Journal, 0).unwrap();
    assert!(facts.journal(own_key).is_ok());
    let other_key = other.local(Namespace::Journal, 0).unwrap();
    assert_eq!(
        facts.journal(other_key).err().unwrap().code(),
        "ABI_CC_ENTITY_NAMESPACE"
    );
    let metadata = crate::metadata::verify(&ctx, &types, &facts, &mut budget).unwrap();
    let program =
        crate::execution::verify_program(&ctx, &types, &facts, &metadata, &mut budget).unwrap();
    crate::metadata::verify_program_joins(&ctx, &types, &facts, &metadata, &program, &mut budget)
        .unwrap();
    assert_eq!(
        program.requirements(),
        &[
            crate::execution::ProgramRequirement::ExternalCleanupRecipe {
                function: 1,
                action: 0,
                slot: 0,
                declaration: 9
            }
        ]
    );
    assert!(
        metadata
            .requirements()
            .obligations()
            .iter()
            .any(|r| matches!(
                r,
                crate::metadata::requirements::RuntimeRequirement::Dependency { slot: 0 }
            ))
    );
    let verified = crate::verify_object(&data, limits).unwrap();
    assert_eq!(verified.identity(), ctx.identity());
    assert_eq!(verified.requirements().iter().count(), 7);
}

#[test]
fn genuine_canonical_states_keep_distinct_sources_context_and_budget() {
    use crate::context::{Namespace, ObjectContext};
    let cases: serde_json::Value = serde_json::from_str(include_str!("phase-cases.json")).unwrap();
    let case = cases["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "canonical-state-closure")
        .unwrap();
    let text = case["encoded_hex"].as_str().unwrap();
    let bytes = (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect::<Vec<_>>();
    let limits = Limits::default();
    let mut budget = Budget::new(&limits);
    let ctx =
        ObjectContext::new(crate::decode_object(&bytes, limits).unwrap(), &mut budget).unwrap();
    let other =
        ObjectContext::new(crate::decode_object(&bytes, limits).unwrap(), &mut budget).unwrap();
    let types = crate::execution::verify_types(&ctx, &mut budget).unwrap();
    let facts = crate::abi::verify(&ctx, &types, &mut budget).unwrap();
    let va = ctx.local(Namespace::Nominal, 2103).unwrap();
    let jump = ctx.local(Namespace::Nominal, 2104).unwrap();
    for key in [va, jump] {
        let source = facts.nominal(key).unwrap();
        let layout = source.layout().unwrap();
        assert_eq!((layout.size_bytes, layout.alignment_bytes), (32, 8));
        assert!(matches!(
            types.kind(source.execution_type().unwrap()).unwrap(),
            crate::execution::TypeKind::Array { count: 32, .. }
        ));
    }
    assert!(!facts.source_compatible(va, jump, &mut budget).unwrap());
    let wrong = other.local(Namespace::Nominal, 2103).unwrap();
    assert_eq!(
        facts
            .source_compatible(va, wrong, &mut budget)
            .unwrap_err()
            .code(),
        "ABI_CC_ENTITY_NAMESPACE"
    );
    let mut exhausted = limits;
    exhausted.max_semantic_work = 0;
    let mut zero = Budget::new(&exhausted);
    assert_eq!(
        facts
            .source_compatible(va, va, &mut zero)
            .unwrap_err()
            .class(),
        crate::ErrorClass::Resource
    );
}

#[test]
fn source_abi040_counterparts_reach_actual_semantic_factory_predicates() {
    let cases: serde_json::Value = serde_json::from_str(include_str!("phase-cases.json")).unwrap();
    let mut checked = 0;
    for case in cases["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["factory_expected"].is_string())
    {
        let text = case["encoded_hex"].as_str().unwrap();
        let bytes = (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect::<Vec<_>>();
        let error = match crate::verify_object(&bytes, Limits::default()) {
            Ok(_) => panic!("whole factory accepted {}", case["name"]),
            Err(error) => error,
        };
        assert_eq!(error.class(), crate::ErrorClass::Semantic);
        assert_eq!(error.code(), case["factory_expected"].as_str().unwrap());
        checked += 1;
    }
    assert_eq!(checked, 2);
}

#[test]
fn preserved_abi040_raw_bytes_reject_before_new_layout_decoding() {
    for data in [
        include_bytes!("../../../../docs/specifications/smir/portable/conformance/abi/record-layout/reject-nonrecord-source-field.smo").as_slice(),
        include_bytes!("../../../../docs/specifications/smir/portable/conformance/abi/record-layout/reject-function-object-layout.smo").as_slice(),
    ] {
        let error = crate::decode_object(data, Limits::default()).err().unwrap();
        assert_eq!(error.class(), crate::ErrorClass::Wire);
        assert_eq!(error.code(), "WIRE-REVISION");
    }
}

#[test]
fn genuine_ordinary_comparison_keeps_both_contexts_and_types_branded() {
    use crate::context::{Namespace, ObjectContext};
    let cases: serde_json::Value = serde_json::from_str(include_str!("phase-cases.json")).unwrap();
    let encoded = cases["cases"][0]["encoded_hex"].as_str().unwrap();
    let data = (0..encoded.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&encoded[i..i + 2], 16).unwrap())
        .collect::<Vec<_>>();
    let limits = Limits::default();
    let mut budget = Budget::new(&limits);
    let a = ObjectContext::new(crate::decode_object(&data, limits).unwrap(), &mut budget).unwrap();
    let b = ObjectContext::new(crate::decode_object(&data, limits).unwrap(), &mut budget).unwrap();
    let at = crate::execution::verify_types(&a, &mut budget).unwrap();
    let bt = crate::execution::verify_types(&b, &mut budget).unwrap();
    let af = crate::abi::verify(&a, &at, &mut budget).unwrap();
    let bf = crate::abi::verify(&b, &bt, &mut budget).unwrap();
    let ak = a.local(Namespace::CallSignature, 0).unwrap();
    let bk = b.local(Namespace::CallSignature, 0).unwrap();
    assert!(
        crate::abi::AbiFacts::ordinary_address_call_compatible(
            &af,
            &at,
            ak,
            &bf,
            &bt,
            bk,
            &mut budget
        )
        .unwrap()
    );
    assert_eq!(
        crate::abi::AbiFacts::ordinary_address_call_compatible(
            &af,
            &bt,
            ak,
            &bf,
            &bt,
            bk,
            &mut budget
        )
        .unwrap_err()
        .code(),
        "ABI_CC_CONTEXT"
    );
    assert_eq!(
        crate::abi::AbiFacts::ordinary_address_call_compatible(
            &af,
            &at,
            bk,
            &bf,
            &bt,
            bk,
            &mut budget
        )
        .unwrap_err()
        .code(),
        "ABI_CC_ENTITY_NAMESPACE"
    );
    let mut exhausted = limits;
    exhausted.max_semantic_work = 0;
    assert_eq!(
        crate::abi::AbiFacts::ordinary_address_call_compatible(
            &af,
            &at,
            ak,
            &bf,
            &bt,
            bk,
            &mut Budget::new(&exhausted)
        )
        .unwrap_err()
        .class(),
        crate::ErrorClass::Resource
    );
}

#[test]
fn source_address_declarations_have_real_static_facts_without_object_or_call_grants() {
    use crate::context::{Namespace, ObjectContext};
    let corpus: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../docs/specifications/smir/portable/conformance/abi/function-address/source-only.json")).unwrap();
    let cases = corpus["profile_cases"].as_array().unwrap();
    assert_eq!(cases.len(), 13);
    for case in cases {
        let encoded = case["encoded_hex"].as_str().unwrap();
        let bytes = (0..encoded.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&encoded[i..i + 2], 16).unwrap())
            .collect::<Vec<_>>();
        let limits = Limits::default();
        if case["expected"] == "verified-object" {
            crate::verify_object(&bytes, limits)
                .unwrap_or_else(|error| panic!("{}: {error}", case["name"]));
            let mut budget = Budget::new(&limits);
            let ctx =
                ObjectContext::new(crate::decode_object(&bytes, limits).unwrap(), &mut budget)
                    .unwrap();
            let types = crate::execution::verify_types(&ctx, &mut budget).unwrap();
            let facts = crate::abi::verify(&ctx, &types, &mut budget).unwrap();
            for identifier in [100, 101, 103, 106] {
                let declaration = facts
                    .nominal(ctx.local(Namespace::Nominal, identifier).unwrap())
                    .unwrap();
                assert!(declaration.layout().is_none());
                assert!(declaration.execution_type().is_none());
            }
            let pointer = facts
                .nominal(ctx.local(Namespace::Nominal, 107).unwrap())
                .unwrap();
            assert_eq!(pointer.layout().unwrap().size_bytes, 8);
            assert_eq!(pointer.layout().unwrap().alignment_bytes, 8);
            assert!(matches!(
                types.kind(pointer.execution_type().unwrap()).unwrap(),
                crate::execution::TypeKind::CodeAddress
            ));
            assert!(ctx.local(Namespace::CallSignature, 106).is_err());
            if case["name"] == "source-pointer-object-storage-8B-A8" {
                assert!(
                    facts
                        .storage_binding(ctx.local(Namespace::StorageBinding, 3000).unwrap())
                        .unwrap()
                        .comparison_mask_matches(&[0xff; 8], &mut budget)
                        .unwrap()
                );
            }
        } else {
            let error = crate::verify_object(&bytes, limits)
                .err()
                .unwrap_or_else(|| panic!("unexpected success {}", case["name"]));
            assert_eq!(
                error.code(),
                case["expected"].as_str().unwrap(),
                "{}: {error}",
                case["name"]
            );
            assert_eq!(
                error.class(),
                if case["expected"] == "P2_ABI_VERIFIER_INCOMPLETE" {
                    crate::ErrorClass::UnavailableEvidence
                } else {
                    crate::ErrorClass::Semantic
                }
            );
        }
    }
}
