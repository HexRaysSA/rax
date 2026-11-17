//! Full-factory checks of the genuine finite scalar proof profile.
//! Broader helper/EH expectations remain in the separate full-grammar tests.

use super::unhex;
use crate::{ErrorClass, Limits, limits::Budget};
use serde_json::Value;

fn cases() -> Vec<Value> {
    let fixture: Value = serde_json::from_str(include_str!("profile-cases.json")).unwrap();
    fixture["cases"].as_array().unwrap().clone()
}

#[test]
fn supported_profile_positives_reach_real_all_phase_factory() {
    let mut count = 0;
    for case in cases().iter().filter(|case| case["expected"] == "ok") {
        let name = case["name"].as_str().unwrap();
        let encoded = unhex(case["encoded_hex"].as_str().unwrap());
        let verified = crate::verify_object(&encoded, Limits::default())
            .unwrap_or_else(|error| panic!("{name}: {error:?}"));
        assert_eq!(verified.requirements().iter().count(), 7, "{name}");
        count += 1;
    }
    assert_eq!(count, 12);
}

#[test]
fn supported_profile_semantic_negatives_match_independent_reference() {
    let mut count = 0;
    for case in cases()
        .iter()
        .filter(|case| case["expected"] != "ok" && case["expected"] != "unavailable")
    {
        let name = case["name"].as_str().unwrap();
        let expected = case["expected"].as_str().unwrap();
        let encoded = unhex(case["encoded_hex"].as_str().unwrap());
        let error = crate::verify_object(&encoded, Limits::default())
            .err()
            .unwrap_or_else(|| panic!("{name}: invalid object accepted"));
        assert_eq!(error.class(), ErrorClass::Semantic, "{name}: {error}");
        assert_eq!(error.code(), expected, "{name}: {error}");
        count += 1;
    }
    assert_eq!(count, 21);
}

#[test]
fn legal_out_of_profile_objects_are_unavailable_not_semantic_rejections() {
    let mut count = 0;
    for case in cases()
        .iter()
        .filter(|case| case["expected"] == "unavailable")
    {
        let name = case["name"].as_str().unwrap();
        assert_eq!(case["reference"], "ok", "{name}");
        let encoded = unhex(case["encoded_hex"].as_str().unwrap());
        let error = crate::verify_object(&encoded, Limits::default())
            .err()
            .unwrap_or_else(|| panic!("{name}: unqualified profile issued proof"));
        assert_eq!(
            error.class(),
            ErrorClass::UnavailableEvidence,
            "{name}: {error}"
        );
        assert!(
            [
                "P2_ABI_VERIFIER_INCOMPLETE",
                "P2_METADATA_PROFILE_UNAUDITED"
            ]
            .contains(&error.code()),
            "{name}: {error}"
        );
        count += 1;
    }
    assert_eq!(count, 2);
}

#[test]
fn program_factory_rejects_real_other_context_phase_facts() {
    let fixture = cases();
    let encoded = unhex(fixture[0]["encoded_hex"].as_str().unwrap());
    let mut work = Budget::new(&Limits::default());
    let a = crate::context::ObjectContext::new(
        crate::decode_object(&encoded, Limits::default()).unwrap(),
        &mut work,
    )
    .unwrap();
    let b = crate::context::ObjectContext::new(
        crate::decode_object(&encoded, Limits::default()).unwrap(),
        &mut work,
    )
    .unwrap();
    let types_a = crate::execution::verify_types(&a, &mut work).unwrap();
    let abi_a = crate::abi::verify(&a, &types_a, &mut work).unwrap();
    let metadata_a = crate::metadata::verify(&a, &types_a, &abi_a, &mut work).unwrap();
    let types_b = crate::execution::verify_types(&b, &mut work).unwrap();
    let abi_b = crate::abi::verify(&b, &types_b, &mut work).unwrap();
    let metadata_b = crate::metadata::verify(&b, &types_b, &abi_b, &mut work).unwrap();
    assert_eq!(a.identity(), b.identity());
    assert_ne!(a.context_id(), b.context_id());
    for (types, abi, metadata) in [
        (&types_b, &abi_a, &metadata_a),
        (&types_a, &abi_b, &metadata_a),
        (&types_a, &abi_a, &metadata_b),
    ] {
        let error = crate::execution::verify_program(&a, types, abi, metadata, &mut work)
            .err()
            .expect("mixed real phase facts must fail");
        assert_eq!(error.class(), ErrorClass::Semantic);
    }
    crate::execution::verify_program(&a, &types_a, &abi_a, &metadata_a, &mut work).unwrap();
}

#[test]
fn eh_predicates_match_reference_with_real_abi_without_issuing_program_proof() {
    let fixture: Value = serde_json::from_str(include_str!("phase-cases.json")).unwrap();
    let mut accepted = 0;
    let mut rejected = 0;
    for case in fixture["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        // These two cases require source ABI profiles beyond the scalar proof.
        // Their complete-factory expectations remain in the broad phase suite.
        if [
            "constant_initializer_restricted_graph",
            "static_external_recipe_obligation",
        ]
        .contains(&name)
        {
            continue;
        }
        let encoded = unhex(case["encoded_hex"].as_str().unwrap());
        let mut work = Budget::new(&Limits::default());
        let ctx = crate::context::ObjectContext::new(
            crate::decode_object(&encoded, Limits::default()).unwrap(),
            &mut work,
        )
        .unwrap();
        let types = crate::execution::verify_types(&ctx, &mut work).unwrap();
        let abi = crate::abi::verify(&ctx, &types, &mut work).unwrap();
        let mut actual = Ok(());
        for function in
            crate::context::list(crate::context::field(ctx.root(3).unwrap(), "functions").unwrap())
                .unwrap()
        {
            let id = crate::context::unsigned(crate::context::field(function, "id").unwrap())
                .unwrap() as u32;
            if let Err(error) =
                crate::execution::check_function_source_and_eh(&ctx, &types, &abi, id, &mut work)
            {
                actual = Err(error);
                break;
            }
        }
        let expected = case["expected"].as_str().unwrap();
        if expected == "ok" {
            actual.unwrap_or_else(|error| panic!("{name}: {error}"));
            accepted += 1;
        } else {
            let error = actual
                .err()
                .unwrap_or_else(|| panic!("{name}: malformed EH accepted"));
            assert_eq!(error.class(), ErrorClass::Semantic, "{name}: {error}");
            assert_eq!(error.code(), expected, "{name}: {error}");
            rejected += 1;
        }
    }
    assert_eq!((accepted, rejected), (3, 15));
}

#[test]
fn embedded_execution_corpus_matches_full_ten_root_reference_factory() {
    let fixture: Value = serde_json::from_str(include_str!("embedded-cases.json")).unwrap();
    let mut accepted = 0;
    let mut rejected = 0;
    for case in fixture["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let expected = case["expected"].as_str().unwrap();
        assert_eq!(case["expected"], case["original_local_result"], "{name}");
        let encoded = unhex(case["encoded_hex"].as_str().unwrap());
        let actual = crate::verify_object(&encoded, Limits::default());
        if expected == "ok" {
            actual.unwrap_or_else(|error| panic!("{name}: {error}"));
            accepted += 1;
        } else {
            let error = actual
                .err()
                .unwrap_or_else(|| panic!("{name}: invalid object accepted"));
            assert_eq!(error.class(), ErrorClass::Semantic, "{name}: {error}");
            assert_eq!(error.code(), expected, "{name}: {error}");
            rejected += 1;
        }
    }
    assert_eq!((accepted, rejected), (97, 125));
}

#[test]
fn conditional_cleanup_captures_check_local_types_and_pre_frontier() {
    let fixture: Value = serde_json::from_str(include_str!("capture-cases.json")).unwrap();
    let mut accepted = 0;
    let mut rejected = 0;
    for case in fixture["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let expected = case["expected"].as_str().unwrap();
        let encoded = unhex(case["encoded_hex"].as_str().unwrap());
        let actual = crate::verify_object(&encoded, Limits::default());
        if expected == "ok" {
            actual.unwrap_or_else(|error| panic!("{name}: {error}"));
            // This second actual phase chain exposes the private requirements;
            // it constructs no test facts and also checks the R dependency.
            let program = super::verify_all_phases(&encoded).unwrap();
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
            accepted += 1;
        } else {
            let error = actual
                .err()
                .unwrap_or_else(|| panic!("{name}: invalid capture accepted"));
            assert_eq!(error.class(), ErrorClass::Semantic, "{name}: {error}");
            assert_eq!(error.code(), expected, "{name}: {error}");
            rejected += 1;
        }
    }
    assert_eq!((accepted, rejected), (4, 8));
}

#[test]
fn bound_helper_rejections_reach_real_all_phase_factory() {
    let fixture: Value = serde_json::from_str(include_str!("core-cases.json")).unwrap();
    let mut rejected = 0;
    for case in fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| case["oracle_scope"] == "abi-and-execution" && case["expected"] != "ok")
    {
        let name = case["name"].as_str().unwrap();
        let encoded = unhex(case["encoded_hex"].as_str().unwrap());
        let error = crate::verify_object(&encoded, Limits::default())
            .err()
            .unwrap_or_else(|| panic!("{name}: invalid bound operation accepted"));
        assert_eq!(error.class(), ErrorClass::Semantic, "{name}: {error}");
        assert_eq!(
            error.code(),
            case["expected"].as_str().unwrap(),
            "{name}: {error}"
        );
        rejected += 1;
    }
    assert_eq!(rejected, 21);
}
