//! Independent Python-produced bytes and cross-context authority boundaries.
use crate::context::{
    DeclaredEntity, EntityRef, ModuleRef, Namespace, ObjectContext, field, list, unsigned,
};
use crate::limits::Budget;
use crate::{ErrorClass, Limits, canonical_bytes, decode_object};
use serde_json::Value;

fn cases() -> Vec<Value> {
    serde_json::from_str::<Value>(include_str!("wire-cases.json")).unwrap()["cases"]
        .as_array()
        .unwrap()
        .clone()
}
fn hex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks_exact(2)
        .map(|part| u8::from_str_radix(std::str::from_utf8(part).unwrap(), 16).unwrap())
        .collect()
}
fn fixture(name: &str) -> Value {
    cases()
        .into_iter()
        .find(|case| case["name"] == name)
        .unwrap()
}
fn context(input: &[u8]) -> ObjectContext {
    ObjectContext::new(
        decode_object(input, Limits::default()).unwrap(),
        &mut Budget::new(&Limits::default()),
    )
    .unwrap()
}

#[test]
fn archived_abi1_object_is_rejected_before_changed_record_members() {
    let document: Value = serde_json::from_str(include_str!("wire-cases.json")).unwrap();
    let legacy = document["legacy_revision_cases"].as_array().unwrap();
    assert!(!legacy.is_empty());
    for case in legacy {
        let input = hex(case["encoded_hex"].as_str().unwrap());
        assert_eq!(
            crate::wire::sha256(&input).as_slice(),
            hex(case["sha256"].as_str().unwrap())
        );
        let error = decode_object(&input, Limits::default()).err().unwrap();
        assert_eq!(error.class(), ErrorClass::Wire);
        assert_eq!(error.code(), case["expected_error"].as_str().unwrap());
        assert_eq!(error.code(), "WIRE-REVISION");
    }
}

#[test]
fn archived_pre_code_address_object_keeps_its_original_bytes() {
    let document: Value = serde_json::from_str(include_str!("wire-cases.json")).unwrap();
    let legacy = document["legacy_revision_cases"].as_array().unwrap();
    let case = legacy
        .iter()
        .find(|case| case["name"] == "archived-pre-CodeAddress-identity")
        .expect("the pre-CodeAddress identity object must remain a rejection control");
    assert_eq!(case["payload_revisions"]["1"], 1);
    assert_eq!(case["payload_revisions"]["10"], 2);
    let input = hex(case["encoded_hex"].as_str().unwrap());
    assert_eq!(
        crate::wire::sha256(&input).as_slice(),
        hex(case["sha256"].as_str().unwrap())
    );
    let error = decode_object(&input, Limits::default()).err().unwrap();
    assert_eq!(error.class(), ErrorClass::Wire);
    assert_eq!(error.code(), "WIRE-REVISION");
}

#[test]
fn dependency_call_plan_uses_the_original_consumer_signature_expectation() {
    let corpus: Value = serde_json::from_str(include_str!(
        "../execution/function-address-cases.json"
    ))
    .unwrap();
    let case = corpus["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "genuine-original-DEP-caller-plan")
        .unwrap();
    let input = hex(case["encoded_hex"].as_str().unwrap());
    let ctx = context(&input);
    let expected = EntityRef {
        module: ModuleRef::Dependency { slot: 0 },
        id: 1,
    };
    let DeclaredEntity::Dependency { slot, declaration } = ctx
        .resolve_declaration(Namespace::CallSignature, &expected)
        .unwrap()
    else {
        panic!("a consumer dependency declaration is not a local/provider key");
    };
    assert_eq!(slot, 0);
    assert_eq!(unsigned(field(declaration, "id").unwrap()).unwrap(), 1);
    let signature = crate::context::optional(field(declaration, "abi_signature").unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(
        crate::context::entity_ref(signature).unwrap(),
        EntityRef {
            module: ModuleRef::SelfModule,
            id: 0,
        }
    );
    let wrong_namespace = EntityRef { id: 2, ..expected };
    let error = ctx
        .resolve_declaration(Namespace::CallSignature, &wrong_namespace)
        .err()
        .unwrap();
    assert_eq!(error.code(), "P2_DEPENDENCY_NAMESPACE");
    // The real all-phase factory must retain the provider obligation while
    // admitting this valid static consumer plan. Lookup alone issues no proof.
    assert!(crate::verify_object(&input, Limits::default()).is_ok());
}

#[test]
fn every_root_revision_precedes_identity_and_semantic_admission() {
    let document: Value = serde_json::from_str(include_str!("wire-cases.json")).unwrap();
    let cases = document["revision_word_cases"].as_array().unwrap();
    assert_eq!(cases.len(), 30);
    let original = hex(fixture("identity")["encoded_hex"].as_str().unwrap());
    assert!(crate::verify_object(&original, Limits::default()).is_ok());
    let mut per_section = [0usize; 10];
    for case in cases {
        let section = case["section"].as_u64().unwrap() as usize;
        let offset = case["offset"].as_u64().unwrap() as usize;
        let replacement = hex(case["replacement_hex"].as_str().unwrap());
        assert_eq!(replacement.len(), 4);
        assert_eq!(
            original[offset..offset + 4],
            hex(case["original_hex"].as_str().unwrap())
        );
        let mut input = original.clone();
        input[offset..offset + 4].copy_from_slice(&replacement);
        assert_eq!(
            crate::wire::sha256(&input).as_slice(),
            hex(case["sha256"].as_str().unwrap())
        );
        for diagnostic in [
            decode_object(&input, Limits::default()).err().unwrap(),
            crate::verify_object(&input, Limits::default())
                .err()
                .unwrap(),
        ] {
            assert_eq!(diagnostic.class(), ErrorClass::Wire);
            assert_eq!(diagnostic.code(), case["expected_error"].as_str().unwrap());
            assert_eq!(diagnostic.code(), "WIRE-REVISION");
        }
        per_section[section - 1] += 1;
    }
    assert_eq!(per_section, [3; 10]);
}

#[test]
fn short_revision_and_missing_body_keep_distinct_wrapper_errors() {
    let document: Value = serde_json::from_str(include_str!("wire-cases.json")).unwrap();
    let cases = document["payload_prefix_cases"].as_array().unwrap();
    assert_eq!(cases.len(), 50);
    let original = hex(fixture("identity")["encoded_hex"].as_str().unwrap());
    let mut per_section = [[0usize; 5]; 10];
    for case in cases {
        let mut input = Vec::new();
        for segment in case["segments"].as_array().unwrap() {
            if let Some(literal) = segment["hex"].as_str() {
                input.extend_from_slice(&hex(literal));
            } else {
                let start = segment["source_offset"].as_u64().unwrap() as usize;
                let length = segment["source_length"].as_u64().unwrap() as usize;
                input.extend_from_slice(&original[start..start + length]);
            }
        }
        assert_eq!(
            crate::wire::sha256(&input).as_slice(),
            hex(case["sha256"].as_str().unwrap())
        );
        for diagnostic in [
            decode_object(&input, Limits::default()).err().unwrap(),
            crate::verify_object(&input, Limits::default())
                .err()
                .unwrap(),
        ] {
            assert_eq!(diagnostic.class(), ErrorClass::Wire);
            assert_eq!(diagnostic.code(), case["expected_error"].as_str().unwrap());
        }
        let section = case["section"].as_u64().unwrap() as usize;
        let length = case["prefix_bytes"].as_u64().unwrap() as usize;
        assert_eq!(
            case["expected_error"],
            if length < 4 {
                "WIRE-REVISION"
            } else {
                "WIRE-TRUNCATED"
            }
        );
        per_section[section - 1][length] += 1;
    }
    assert_eq!(per_section, [[1; 5]; 10]);
}

#[test]
fn independent_wire_bytes_roundtrip_and_identity_corruption() {
    for case in cases() {
        let input = hex(case["encoded_hex"].as_str().unwrap());
        let parsed = decode_object(&input, Limits::default()).unwrap();
        assert_eq!(canonical_bytes(&parsed).unwrap(), input);
        assert_eq!(
            parsed.identity().as_slice(),
            hex(case["identity"].as_str().unwrap())
        );
        let mut corrupt = input.clone();
        let manifest = u64::from_le_bytes(input[80..88].try_into().unwrap()) as usize;
        corrupt[manifest + 4] ^= 1;
        assert_eq!(
            decode_object(&corrupt, Limits::default())
                .err()
                .unwrap()
                .code(),
            "WIRE-IDENTITY"
        );
        corrupt[0] ^= 1;
        assert_eq!(
            decode_object(&corrupt, Limits::default())
                .err()
                .unwrap()
                .class(),
            ErrorClass::Framing
        );
    }
    assert_eq!(
        fixture("identity")["identity"],
        fixture("metadata")["identity"]
    );
}

#[test]
fn aggregate_node_boundary_and_output_preflight() {
    let case = fixture("identity");
    let input = hex(case["encoded_hex"].as_str().unwrap());
    let nodes = case["nodes"].as_u64().unwrap() as usize;
    assert!(
        decode_object(
            &input,
            Limits {
                max_record_nodes: nodes,
                ..Limits::default()
            }
        )
        .is_ok()
    );
    assert_eq!(
        decode_object(
            &input,
            Limits {
                max_record_nodes: nodes - 1,
                ..Limits::default()
            }
        )
        .err()
        .unwrap()
        .class(),
        ErrorClass::Resource
    );
    assert_eq!(
        decode_object(
            &input,
            Limits {
                max_object_bytes: input.len() - 1,
                ..Limits::default()
            }
        )
        .err()
        .unwrap()
        .class(),
        ErrorClass::Resource
    );
    let parsed = decode_object(
        &input,
        Limits {
            max_derived_bytes: 0,
            ..Limits::default()
        },
    )
    .unwrap();
    assert_eq!(
        canonical_bytes(&parsed).err().unwrap().code(),
        "P2_DERIVED_LIMIT"
    );
    for limit in [0, 1, 8, 128] {
        assert!(
            decode_object(
                &input,
                Limits {
                    max_payload_bytes: limit,
                    ..Limits::default()
                }
            )
            .is_err()
        );
    }
}

#[test]
fn same_bytes_cannot_mix_context_handles_and_namespaces() {
    let input = hex(fixture("identity")["encoded_hex"].as_str().unwrap());
    let first = context(&input);
    let second = context(&input);
    assert_eq!(first.identity(), second.identity());
    assert_ne!(first.context_id(), second.context_id());
    let ty = &list(field(first.root(1).unwrap(), "types").unwrap()).unwrap()[0];
    let id = unsigned(field(ty, "id").unwrap()).unwrap() as u32;
    let handle = first.local(Namespace::ExecutionType, id).unwrap();
    assert_eq!(first.entity(handle).unwrap(), ty);
    assert_eq!(
        second.entity(handle).err().unwrap().code(),
        "P2_CONTEXT_MISMATCH"
    );
    if let Ok(nominal) = first.local(Namespace::Nominal, id) {
        assert_ne!(handle, nominal);
    }
    let duplicate = hex(fixture("duplicate-type")["encoded_hex"].as_str().unwrap());
    assert_eq!(
        ObjectContext::new(
            decode_object(&duplicate, Limits::default()).unwrap(),
            &mut Budget::new(&Limits::default())
        )
        .err()
        .unwrap()
        .code(),
        "P2_DUPLICATE_ID"
    );
}

#[test]
fn dependency_id_is_a_consumer_declaration_not_local_definition() {
    let input = hex(fixture("dependency")["encoded_hex"].as_str().unwrap());
    let ctx = context(&input);
    let reference = EntityRef {
        module: ModuleRef::Dependency { slot: 7 },
        id: 99,
    };
    match ctx
        .resolve_declaration(Namespace::ExecutionType, &reference)
        .unwrap()
    {
        DeclaredEntity::Dependency { slot, declaration } => {
            assert_eq!(slot, 7);
            assert_eq!(unsigned(field(declaration, "id").unwrap()).unwrap(), 99);
        }
        DeclaredEntity::Local(_) => panic!("dependency became local authority"),
    }
    assert_eq!(
        ctx.resolve_declaration(Namespace::Function, &reference)
            .err()
            .unwrap()
            .code(),
        "P2_DECLARATION_KIND"
    );
    for namespace in [
        Namespace::MemoryLayout,
        Namespace::CallSignature,
        Namespace::Tls,
        Namespace::Import,
    ] {
        assert_eq!(
            ctx.resolve_declaration(namespace, &reference)
                .err()
                .unwrap()
                .code(),
            "P2_DEPENDENCY_NAMESPACE"
        );
    }
    let zero = Limits {
        max_derived_bytes: 0,
        ..Limits::default()
    };
    assert_eq!(
        ObjectContext::new(
            decode_object(&input, Limits::default()).unwrap(),
            &mut Budget::new(&zero)
        )
        .err()
        .unwrap()
        .class(),
        ErrorClass::Resource
    );
}

#[test]
fn immutable_context_reads_on_two_actual_host_threads() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ObjectContext>();
    let input = hex(fixture("identity")["encoded_hex"].as_str().unwrap());
    let ctx = context(&input);
    let barrier = std::sync::Barrier::new(3);
    std::thread::scope(|scope| {
        let workers: Vec<_> = (0..2)
            .map(|_| {
                scope.spawn(|| {
                    barrier.wait();
                    for _ in 0..100 {
                        assert_eq!(ctx.identity().len(), 32);
                        assert!(ctx.root(10).is_ok());
                    }
                    ctx.context_id()
                })
            })
            .collect();
        barrier.wait();
        for worker in workers {
            assert_eq!(worker.join().unwrap(), ctx.context_id());
        }
    });
}

#[test]
fn actual_static_factory_retains_lossless_owner_contracts() {
    for name in ["identity", "metadata"] {
        let case = fixture(name);
        let input = hex(case["encoded_hex"].as_str().unwrap());
        let parsed = decode_object(&input, Limits::default()).unwrap();
        let proof = crate::verify_object(&input, Limits::default()).unwrap();
        assert_eq!(proof.identity(), parsed.identity());
        let views: Vec<_> = proof.requirements().iter().collect();
        assert_eq!(
            views.iter().map(|view| view.section()).collect::<Vec<_>>(),
            [2, 4, 5, 6, 7, 9, 10]
        );
        for view in views {
            let bytes = view.canonical_bytes().unwrap();
            assert_eq!(bytes, parsed.payload(view.section()).unwrap());
            assert_eq!(view.encoded_length().unwrap(), bytes.len());
            assert_eq!(
                view.kind(),
                if view.section() == 10 {
                    "abi-contract"
                } else {
                    "runtime-contract"
                }
            );
        }
    }
}

#[test]
fn static_factory_applies_cumulative_resources_before_issuing_proof() {
    let input = hex(fixture("identity")["encoded_hex"].as_str().unwrap());
    // The exact same independently encoded input is admissible under the
    // audited static profile. These policies prevent any partial proof result.
    assert!(crate::verify_object(&input, Limits::default()).is_ok());
    for limits in [
        Limits {
            max_semantic_work: 0,
            ..Limits::default()
        },
        Limits {
            max_derived_bytes: 0,
            ..Limits::default()
        },
    ] {
        let diagnostic = crate::verify_object(&input, limits).err().unwrap();
        assert_eq!(diagnostic.class(), ErrorClass::Resource);
    }
}
