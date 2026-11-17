//! Independent static type/layout boundaries. These tests do not execute SMIR.

mod atomic_bytes;
mod function_addresses;
mod profile;

use crate::execution::types::TypeGraph;
use crate::{ErrorClass, Limits, RecordValue, limits::Budget};
use serde_json::{Value, json};

fn value(input: Value) -> RecordValue {
    match input {
        Value::Null => RecordValue::Option(None),
        Value::Bool(value) => RecordValue::Boolean(value),
        Value::Number(value) => RecordValue::Unsigned(value.as_u64().unwrap()),
        Value::String(value) => RecordValue::Text(value),
        Value::Array(values) => RecordValue::Vector(values.into_iter().map(value).collect()),
        Value::Object(values) if values.len() == 1 && values.contains_key("some") => {
            RecordValue::Option(Some(Box::new(value(values.into_values().next().unwrap()))))
        }
        Value::Object(values) => RecordValue::Record(
            values
                .into_iter()
                .map(|(key, child)| (key, value(child)))
                .collect(),
        ),
    }
}

fn reference(id: u32) -> Value {
    json!({"module":{"kind":"self"},"id":id})
}
fn root(types: Vec<Value>, layouts: Vec<Value>) -> RecordValue {
    value(json!({"payload_revision":2,"types":types,"memory_layouts":layouts}))
}
fn symbols() -> RecordValue {
    value(json!({"manifest":{"dependencies":[]}}))
}
fn budget() -> Budget {
    Budget::new(&Limits::default())
}

#[test]
fn integer_precision_and_record_offset_domain_boundaries() {
    for width in [1u32, 64, 65, 128, 65535, 65536, 1 << 23] {
        let mut budget = budget();
        let graph = TypeGraph::build(
            &root(vec![json!({"kind":"int","id":0,"bits":width})], vec![]),
            &symbols(),
            &mut budget,
        )
        .unwrap();
        assert_eq!(graph.logical_bits(0).unwrap(), u64::from(width));
    }
    for width in [0, (1 << 23) + 1] {
        assert_eq!(
            TypeGraph::build(
                &root(vec![json!({"kind":"int","id":0,"bits":width})], vec![]),
                &symbols(),
                &mut budget()
            )
            .err()
            .unwrap()
            .code(),
            "type_width"
        );
    }
    let max = root(
        vec![
            json!({"kind":"int","id":0,"bits":1}),
            json!({"kind":"array","id":1,"element":reference(0),"count":u64::MAX}),
        ],
        vec![],
    );
    assert_eq!(
        TypeGraph::build(&max, &symbols(), &mut budget())
            .unwrap()
            .logical_bits(1)
            .unwrap(),
        u64::MAX
    );
    let overflow = root(
        vec![
            json!({"kind":"int","id":0,"bits":2}),
            json!({"kind":"array","id":1,"element":reference(0),"count":u64::MAX}),
        ],
        vec![],
    );
    assert_eq!(
        TypeGraph::build(&overflow, &symbols(), &mut budget())
            .err()
            .unwrap()
            .code(),
        "type_extent"
    );
}

#[test]
fn recursive_code_signatures_compare_coinductively() {
    let function = |id, ptr| json!({"kind":"function","id":id,"params":[reference(ptr)],"results":[],"param_noundef":[false],"result_noundef":[],"variadic":false,"cc":"portable"});
    let types = root(
        vec![
            function(0, 1),
            json!({"kind":"code_ptr","id":1,"signature":reference(0)}),
            function(2, 3),
            json!({"kind":"code_ptr","id":3,"signature":reference(2)}),
        ],
        vec![],
    );
    let graph = TypeGraph::build(&types, &symbols(), &mut budget()).unwrap();
    assert!(graph.equivalent(0, 2, &mut budget()).unwrap());
    assert_eq!(
        graph.digest(0, &mut budget()).unwrap(),
        graph.digest(2, &mut budget()).unwrap()
    );
    assert_eq!(
        graph.digest(0, &mut budget()).unwrap().as_slice(),
        unhex("82055310b1e7ede198c07f4cff516b6f2a3e9f3cfecf06a0a1aef86473ae11f8")
    );
    assert_eq!(graph.logical_bits(1).unwrap(), 64);
    let cycle = root(
        vec![json!({"kind":"array","id":0,"element":reference(0),"count":0})],
        vec![],
    );
    assert_eq!(
        TypeGraph::build(&cycle, &symbols(), &mut budget())
            .err()
            .unwrap()
            .code(),
        "type_cycle"
    );
}

#[test]
fn zero_length_arrays_have_no_present_opaque_leaves() {
    for kind in ["exception", "journal", "stack_mark", "va_list"] {
        let types = root(
            vec![
                json!({"kind":kind,"id":0}),
                json!({"kind":"array","id":1,"element":reference(0),"count":0}),
                json!({"kind":"array","id":2,"element":reference(0),"count":1}),
            ],
            vec![],
        );
        let graph = TypeGraph::build(&types, &symbols(), &mut budget()).unwrap();
        assert!(graph.opaque(0).unwrap().any());
        assert!(!graph.opaque(1).unwrap().any());
        assert!(graph.opaque(2).unwrap().any());
        assert_eq!(graph.materialization_cost(1).unwrap(), 1);
        assert_eq!(graph.materialization_cost(2).unwrap(), 2);
    }
}

#[test]
fn every_float_format_and_fixed_execution_signature_policy() {
    for (format, width) in [
        ("binary16", 16),
        ("bfloat16", 16),
        ("binary32", 32),
        ("binary64", 64),
        ("binary128", 128),
    ] {
        let types = root(vec![json!({"kind":"float","id":0,"format":format})], vec![]);
        assert_eq!(
            TypeGraph::build(&types, &symbols(), &mut budget())
                .unwrap()
                .logical_bits(0)
                .unwrap(),
            width
        );
    }
    let ellipsis = root(
        vec![
            json!({"kind":"function","id":0,"params":[],"results":[],"param_noundef":[],"result_noundef":[],"variadic":true,"cc":"portable"}),
        ],
        vec![],
    );
    assert_eq!(
        TypeGraph::build(&ellipsis, &symbols(), &mut budget())
            .err()
            .unwrap()
            .code(),
        "calling_convention"
    );
}

#[test]
fn scalar_layout_uses_ceil_bits_bytes_and_independent_alignment() {
    let layout = |access| json!({"id":0,"type":reference(0),"size":16,"alignment":8,"access_bytes":access,"fields":[],"element":null,"stride":0});
    let correct = root(
        vec![json!({"kind":"int","id":0,"bits":65})],
        vec![layout(9)],
    );
    let graph = TypeGraph::build(&correct, &symbols(), &mut budget()).unwrap();
    graph.check_layouts(&correct, &mut budget()).unwrap();
    let wrong = root(
        vec![json!({"kind":"int","id":0,"bits":65})],
        vec![layout(8)],
    );
    assert_eq!(
        graph
            .check_layouts(&wrong, &mut budget())
            .unwrap_err()
            .code(),
        "layout_scalar"
    );
}

#[test]
fn type_and_layout_limits_are_explicit_resource_errors() {
    let limits = Limits {
        max_derived_bytes: 0,
        ..Limits::default()
    };
    let types = root(vec![json!({"kind":"int","id":0,"bits":32})], vec![]);
    assert_eq!(
        TypeGraph::build(&types, &symbols(), &mut Budget::new(&limits))
            .err()
            .unwrap()
            .class(),
        ErrorClass::Resource
    );
    let limits = Limits {
        max_semantic_work: 0,
        ..Limits::default()
    };
    assert_eq!(
        TypeGraph::build(&types, &symbols(), &mut Budget::new(&limits))
            .err()
            .unwrap()
            .class(),
        ErrorClass::Resource
    );
}

fn unhex(value: &str) -> Vec<u8> {
    assert!(value.len().is_multiple_of(2));
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                _ => panic!("noncanonical hex test input"),
            };
            (digit(pair[0]) << 4) | digit(pair[1])
        })
        .collect()
}

#[test]
fn structural_identity_matches_independent_python_quotient() {
    // Captured by running the unchanged candidate.type_system.Types.digest;
    // source identity is retained by generate_core_cases.py's source manifest.
    let graph = TypeGraph::build(
        &root(vec![json!({"kind":"int","id":9,"bits":65})], vec![]),
        &symbols(),
        &mut budget(),
    )
    .unwrap();
    assert_eq!(
        graph.digest(9, &mut budget()).unwrap().as_slice(),
        unhex("e44ccc4b1d37ccd8db10fc631f551ac27785414b9143f8a4e9f62274c20b1bb8")
    );
}

#[test]
fn local_execution_core_matches_independent_python_cases() {
    let fixture: Value = serde_json::from_str(include_str!("core-cases.json")).unwrap();
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 261);
    let mut accept = 0;
    let mut reject = 0;
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let expected = case["expected"].as_str().unwrap();
        let encoded = unhex(case["encoded_hex"].as_str().unwrap());
        let limits = Limits::default();
        let object = crate::decode_object(&encoded, limits).unwrap();
        let mut budget = Budget::new(&limits);
        let context = crate::context::ObjectContext::new(object, &mut budget).unwrap();
        let actual = crate::execution::verify_types(&context, &mut budget).and_then(|types| {
            let function = case.get("function").and_then(Value::as_u64).unwrap_or(0) as u32;
            crate::execution::check_function_core(&context, &types, function, &mut budget)
        });
        if expected == "ok" {
            assert!(actual.is_ok(), "{name}: {actual:?}");
            accept += 1;
        } else {
            assert_eq!(
                actual
                    .err()
                    .unwrap_or_else(|| panic!("{name}: accepted invalid core"))
                    .code(),
                expected,
                "{name}"
            );
            reject += 1;
        }
    }
    assert_eq!((accept, reject), (115, 146));
}

#[test]
fn actual_all_role_factories_accept_reference_abi_execution_positives() {
    let fixture: Value = serde_json::from_str(include_str!("core-cases.json")).unwrap();
    let mut count = 0;
    for case in fixture["cases"].as_array().unwrap() {
        if case["oracle_scope"] != "abi-and-execution" || case["expected"] != "ok" {
            continue;
        }
        let name = case["name"].as_str().unwrap();
        let limits = Limits::default();
        let object =
            crate::decode_object(&unhex(case["encoded_hex"].as_str().unwrap()), limits).unwrap();
        let mut budget = Budget::new(&limits);
        let ctx = crate::context::ObjectContext::new(object, &mut budget).unwrap();
        let result = (|| -> Result<(), crate::Error> {
            let types = crate::execution::verify_types(&ctx, &mut budget)?;
            let abi = crate::abi::verify(&ctx, &types, &mut budget)?;
            let metadata = crate::metadata::verify(&ctx, &types, &abi, &mut budget)?;
            let program =
                crate::execution::verify_program(&ctx, &types, &abi, &metadata, &mut budget)?;
            crate::metadata::verify_program_joins(
                &ctx,
                &types,
                &abi,
                &metadata,
                &program,
                &mut budget,
            )?;
            Ok(())
        })();
        assert!(result.is_ok(), "{name}: {result:?}");
        count += 1;
    }
    assert_eq!(count, 18);
}

fn verify_all_phases(encoded: &[u8]) -> Result<crate::execution::ProgramFacts, crate::Error> {
    let limits = Limits::default();
    let mut budget = Budget::new(&limits);
    let ctx =
        crate::context::ObjectContext::new(crate::decode_object(encoded, limits)?, &mut budget)?;
    let types = crate::execution::verify_types(&ctx, &mut budget)?;
    let abi = crate::abi::verify(&ctx, &types, &mut budget)?;
    let metadata = crate::metadata::verify(&ctx, &types, &abi, &mut budget)?;
    let program = crate::execution::verify_program(&ctx, &types, &abi, &metadata, &mut budget)?;
    crate::metadata::verify_program_joins(&ctx, &types, &abi, &metadata, &program, &mut budget)?;
    // INT028: source cleanup checks retain a separate provider/module obligation.
    for requirement in program.requirements() {
        let crate::execution::ProgramRequirement::ExternalCleanupRecipe { slot, .. } = requirement;
        assert!(metadata.requirements().obligations().contains(
            &crate::metadata::requirements::RuntimeRequirement::Dependency { slot: *slot }
        ));
    }
    Ok(program)
}

#[test]
fn full_phase_regions_constants_and_explicit_external_obligations() {
    let fixture: Value = serde_json::from_str(include_str!("phase-cases.json")).unwrap();
    let mut accept = 0;
    let mut reject = 0;
    for case in fixture["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let expected = case["expected"].as_str().unwrap();
        let actual = verify_all_phases(&unhex(case["encoded_hex"].as_str().unwrap()));
        if expected == "ok" {
            let program = actual.unwrap_or_else(|error| panic!("{name}: {error:?}"));
            if name == "constant_initializer_restricted_graph" {
                let constant = program.constant_program(7).unwrap();
                assert_eq!(constant.operation_count, 5);
                assert_eq!(constant.ssa_bytes, 40);
                assert_eq!(constant.ssa_nodes, 5);
            }
            if name == "static_external_recipe_obligation" {
                assert_eq!(
                    program.requirements(),
                    &[
                        crate::execution::ProgramRequirement::ExternalCleanupRecipe {
                            function: 1,
                            action: 0,
                            slot: 0,
                            declaration: 9,
                        }
                    ]
                );
            }
            accept += 1;
        } else {
            let error = actual
                .err()
                .unwrap_or_else(|| panic!("{name}: invalid EH accepted"));
            assert_eq!(error.code(), expected, "{name}");
            reject += 1;
        }
    }
    assert_eq!((accept, reject), (5, 15));
}

#[test]
fn facts_and_handles_reject_same_bytes_from_another_context() {
    let fixture: Value = serde_json::from_str(include_str!("core-cases.json")).unwrap();
    let case = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "full_joint_identity")
        .unwrap();
    let encoded = unhex(case["encoded_hex"].as_str().unwrap());
    let limits = Limits::default();
    let mut work = budget();
    let a = crate::context::ObjectContext::new(
        crate::decode_object(&encoded, limits).unwrap(),
        &mut work,
    )
    .unwrap();
    let b = crate::context::ObjectContext::new(
        crate::decode_object(&encoded, limits).unwrap(),
        &mut work,
    )
    .unwrap();
    let types_a = crate::execution::verify_types(&a, &mut work).unwrap();
    let types_b = crate::execution::verify_types(&b, &mut work).unwrap();
    assert_eq!(types_a.identity(), types_b.identity());
    assert_ne!(types_a.context_id(), types_b.context_id());
    assert!(types_a.assert_context(&b).is_err());
    assert!(
        types_b
            .type_record(types_a.type_handle(1).unwrap())
            .is_err()
    );
    assert!(
        types_a
            .type_from_entity(
                b.local(crate::context::Namespace::ExecutionType, 1)
                    .unwrap()
            )
            .is_err()
    );
}

#[test]
fn zero_width_repeated_values_have_symbolic_capped_materialization_cost() {
    let types = root(
        vec![
            json!({"kind":"struct","id":0,"fields":[]}),
            json!({"kind":"array","id":1,"element":reference(0),"count":u64::MAX}),
        ],
        vec![],
    );
    let graph = TypeGraph::build(&types, &symbols(), &mut budget()).unwrap();
    assert_eq!(graph.logical_bits(1).unwrap(), 0);
    assert_eq!(graph.materialization_cost(1).unwrap(), 100001);
}

#[test]
fn all_type_reference_classes_and_signature_invariants_reject() {
    let cases = [
        (
            vec![json!({"kind":"data_ptr","id":0,"space":"host"})],
            "type_space",
        ),
        (
            vec![
                json!({"kind":"int","id":0,"bits":32}),
                json!({"kind":"code_ptr","id":1,"signature":reference(0)}),
            ],
            "type_signature",
        ),
        (
            vec![
                json!({"kind":"int","id":0,"bits":8}),
                json!({"kind":"vector","id":1,"element":reference(0),"count":0}),
            ],
            "type_vector",
        ),
        (
            vec![
                json!({"kind":"int","id":0,"bits":8}),
                json!({"kind":"vector","id":1,"element":reference(0),"count":65536}),
            ],
            "type_vector",
        ),
        (
            vec![
                json!({"kind":"struct","id":0,"fields":[]}),
                json!({"kind":"vector","id":1,"element":reference(0),"count":1}),
            ],
            "type_vector",
        ),
        (
            vec![json!({"kind":"array","id":0,"element":reference(9),"count":0})],
            "type_reference",
        ),
        (
            vec![
                json!({"kind":"int","id":1,"bits":8}),
                json!({"kind":"int","id":0,"bits":32}),
            ],
            "duplicate_order",
        ),
        (
            vec![
                json!({"kind":"int","id":0,"bits":8}),
                json!({"kind":"function","id":1,"params":[reference(0)],"results":[],"param_noundef":[],"result_noundef":[],"cc":"portable","variadic":false}),
            ],
            "type_signature",
        ),
    ];
    for (types, expected) in cases {
        assert_eq!(
            TypeGraph::build(&root(types, vec![]), &symbols(), &mut budget())
                .err()
                .unwrap()
                .code(),
            expected
        );
    }
}

#[test]
fn physical_field_bit_offsets_and_padding_are_independent_of_ssa_order() {
    let types = vec![
        json!({"kind":"int","id":0,"bits":65}),
        json!({"kind":"struct","id":1,"fields":[reference(0)]}),
    ];
    let scalar = json!({"id":0,"type":reference(0),"size":9,"alignment":1,"access_bytes":9,"fields":[],"element":null,"stride":0});
    let aggregate = json!({"id":1,"type":reference(1),"size":9,"alignment":1,"access_bytes":9,"fields":[{"value_index":0,"bit_offset":7,"bit_width":65,"layout":reference(0)}],"element":null,"stride":0});
    let good = root(types.clone(), vec![scalar.clone(), aggregate.clone()]);
    let graph = TypeGraph::build(&good, &symbols(), &mut budget()).unwrap();
    graph.check_layouts(&good, &mut budget()).unwrap();
    let mut bad = aggregate;
    bad["fields"][0]["bit_offset"] = json!(8);
    assert_eq!(
        graph
            .check_layouts(&root(types, vec![scalar, bad]), &mut budget())
            .unwrap_err()
            .code(),
        "layout_field_extent"
    );
}

#[test]
fn physical_layout_overlap_and_alignment_reject_before_access() {
    let types = vec![
        json!({"kind":"int","id":0,"bits":8}),
        json!({"kind":"struct","id":1,"fields":[reference(0),reference(0)]}),
    ];
    let scalar = json!({"id":0,"type":reference(0),"size":1,"alignment":1,"access_bytes":1,"fields":[],"element":null,"stride":0});
    let aggregate = json!({"id":1,"type":reference(1),"size":2,"alignment":1,"access_bytes":2,"fields":[{"value_index":0,"bit_offset":0,"bit_width":8,"layout":reference(0)},{"value_index":1,"bit_offset":4,"bit_width":8,"layout":reference(0)}],"element":null,"stride":0});
    let root_record = root(types.clone(), vec![scalar.clone(), aggregate]);
    let graph = TypeGraph::build(&root_record, &symbols(), &mut budget()).unwrap();
    assert_eq!(
        graph
            .check_layouts(&root_record, &mut budget())
            .unwrap_err()
            .code(),
        "layout_overlap"
    );
    for alignment in [0, 3] {
        let mut bad = scalar.clone();
        bad["alignment"] = json!(alignment);
        assert_eq!(
            graph
                .check_layouts(&root(types.clone(), vec![bad]), &mut budget())
                .unwrap_err()
                .code(),
            "layout_extent"
        );
    }
}

#[test]
fn historical_abi1_bytes_fail_revision_preflight() {
    let case: Value = serde_json::from_str(include_str!("legacy-abi1-case.json")).unwrap();
    let encoded = unhex(case["encoded_hex"].as_str().unwrap());
    let error = crate::decode_object(&encoded, Limits::default())
        .err()
        .expect("historical ABI1 bytes must not be interpreted as ABI2");
    assert_eq!(error.class(), ErrorClass::Wire);
    assert_eq!(error.code(), "WIRE-REVISION");
}
