//! Real phase-factory tests for the accepted finite R-PROD004 profile.
//! No constructor, callback or parser-only result substitutes for another phase.

use crate::{ErrorClass, Limits, context::ObjectContext, limits::Budget};

fn context(bytes: &[u8]) -> ObjectContext {
    ObjectContext::new(
        crate::decode_object(bytes, Limits::default()).unwrap(),
        &mut Budget::new(&Limits::default()),
    )
    .unwrap()
}

#[test]
fn genuine_supported_scalar_profile_reaches_all_real_phase_proofs() {
    let bytes = include_bytes!("fixtures/scalar-profile.smo");
    let ctx = context(bytes);
    let mut budget = Budget::new(&Limits::default());
    let types = crate::execution::verify_types(&ctx, &mut budget).unwrap();
    let abi = crate::abi::verify(&ctx, &types, &mut budget).unwrap();
    let metadata = crate::metadata::verify(&ctx, &types, &abi, &mut budget).unwrap();
    let program =
        crate::execution::verify_program(&ctx, &types, &abi, &metadata, &mut budget).unwrap();
    crate::metadata::verify_program_joins(&ctx, &types, &abi, &metadata, &program, &mut budget)
        .unwrap();
    assert_eq!(metadata.context_id(), ctx.context_id());
    assert_eq!(metadata.identity(), ctx.identity());
    assert!(
        metadata
            .requirements()
            .obligations()
            .iter()
            .any(|v| matches!(
                v,
                crate::metadata::requirements::RuntimeRequirement::ProcessProfile
            ))
    );
    assert!(
        metadata
            .requirements()
            .obligations()
            .iter()
            .any(|v| matches!(
                v,
                crate::metadata::requirements::RuntimeRequirement::SymbolBinding { .. }
            ))
    );
    let verified = crate::verify_object(bytes, Limits::default()).unwrap();
    assert_eq!(verified.identity(), ctx.identity());
}

#[test]
fn otherwise_valid_unused_runtime_forms_are_coverage_unknown() {
    for bytes in [
        include_bytes!("fixtures/scalar-profile-hidden.smo").as_slice(),
        include_bytes!("fixtures/scalar-profile-unused-capability.smo").as_slice(),
        include_bytes!("fixtures/scalar-profile-unused-data.smo").as_slice(),
    ] {
        let error = match crate::verify_object(bytes, Limits::default()) {
            Err(error) => error,
            Ok(_) => panic!("unaudited metadata was accepted"),
        };
        assert_eq!(error.class(), ErrorClass::UnavailableEvidence);
        assert_eq!(error.code(), "P2_METADATA_PROFILE_UNAUDITED");
    }
}

#[test]
fn actual_semantic_errors_do_not_become_generic_audit_rejections() {
    for (bytes, expected) in [
        (
            include_bytes!("fixtures/scalar-profile-function-as-data.smo").as_slice(),
            Some("RT_DEFINITION_DOMAIN"),
        ),
        (
            include_bytes!("fixtures/scalar-profile-bad-execution.smo").as_slice(),
            Some("RT_SYMBOL_SIGNATURE"),
        ),
        (
            include_bytes!("fixtures/scalar-profile-bad-source.smo").as_slice(),
            Some("RT_SOURCE_FUNCTION_NOMINAL"),
        ),
        (
            include_bytes!("fixtures/scalar-profile-bad-ssa.smo").as_slice(),
            None,
        ),
    ] {
        let error = match crate::verify_object(bytes, Limits::default()) {
            Err(error) => error,
            Ok(_) => panic!("actual malformed object was accepted"),
        };
        assert_eq!(error.class(), ErrorClass::Semantic);
        if let Some(expected) = expected {
            assert_eq!(error.code(), expected);
        }
        assert!(
            !error.code().starts_with("P2_"),
            "placeholder is not a semantic negative"
        );
    }
}

#[test]
fn complete_metadata_proof_from_equal_bytes_cannot_cross_contexts() {
    let bytes = include_bytes!("fixtures/scalar-profile.smo");
    let a = context(bytes);
    let b = context(bytes);
    let mut budget = Budget::new(&Limits::default());
    let ta = crate::execution::verify_types(&a, &mut budget).unwrap();
    let aa = crate::abi::verify(&a, &ta, &mut budget).unwrap();
    let ma = crate::metadata::verify(&a, &ta, &aa, &mut budget).unwrap();
    let tb = crate::execution::verify_types(&b, &mut budget).unwrap();
    let ab = crate::abi::verify(&b, &tb, &mut budget).unwrap();
    let mb = crate::metadata::verify(&b, &tb, &ab, &mut budget).unwrap();
    let pb = crate::execution::verify_program(&b, &tb, &ab, &mb, &mut budget).unwrap();
    assert_ne!(a.context_id(), b.context_id());
    assert_eq!(a.identity(), b.identity());
    assert_eq!(
        crate::metadata::verify_program_joins(&b, &tb, &ab, &ma, &pb, &mut budget)
            .unwrap_err()
            .code(),
        "RT_CONTEXT_MISMATCH"
    );
}

#[test]
fn actual_portable_domain_id_does_not_change_source_plan_requirement() {
    for bytes in [
        include_bytes!("fixtures/scalar-profile-domain-0.smo").as_slice(),
        include_bytes!("fixtures/scalar-profile-domain-1.smo").as_slice(),
        include_bytes!("fixtures/scalar-profile-domain-19.smo").as_slice(),
        include_bytes!("fixtures/scalar-profile-domain-65537.smo").as_slice(),
        include_bytes!("fixtures/scalar-profile-domain-4294967294.smo").as_slice(),
    ] {
        crate::verify_object(bytes, Limits::default()).unwrap();
    }
    for bytes in [
        include_bytes!("fixtures/scalar-profile-domain-0-missing-plan.smo").as_slice(),
        include_bytes!("fixtures/scalar-profile-domain-1-missing-plan.smo").as_slice(),
        include_bytes!("fixtures/scalar-profile-domain-19-missing-plan.smo").as_slice(),
        include_bytes!("fixtures/scalar-profile-domain-65537-missing-plan.smo").as_slice(),
        include_bytes!("fixtures/scalar-profile-domain-4294967294-missing-plan.smo").as_slice(),
    ] {
        let error = match crate::verify_object(bytes, Limits::default()) {
            Err(error) => error,
            Ok(_) => panic!("missing source plan admitted"),
        };
        assert_eq!(error.class(), ErrorClass::Semantic);
        assert_eq!(error.code(), "RT_SOURCE_PLAN_PRESENCE");
    }
}
