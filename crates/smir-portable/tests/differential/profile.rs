use crate::support::harness;
use serde_json::json;
use std::fs;

#[test]
fn genuine_scalar_profile_and_valid_unused_extras_have_distinct_outcomes() {
    let test = harness();
    let mut observations = Vec::new();
    let mut positives = 0;
    let mut unknowns = 0;
    for case in &test.cases {
        if !case.id.starts_with("scalar-profile/") {
            continue;
        }
        let reference = test.reference(case);
        let (process, report) = test.cli("verify", case);
        let expected_unknown = case.expectation == "profile-unavailable";
        let production_matches = if expected_unknown {
            unknowns += 1;
            process.status.code() == Some(1)
                && report.as_object().is_some_and(|members| members.len() == 3)
                && report["status"] == "rejected"
                && report["class"] == "unavailable-evidence"
                && report["code"] == case.document["coverage_code"]
        } else {
            positives += 1;
            process.status.success()
                && report.as_object().is_some_and(|members| members.len() == 4)
                && report["status"] == "verified-object"
                && report["executable_admitted"] == false
                && report["identity"] == reference["identity"]
                && report["required_admission"]["format"] == "smir-required-admission-v1"
                && report["required_admission"]["entries"]
                    == case.document["python_wire"]["owner_entries"]
        };
        observations.push(json!({
            "id": case.id,
            "expected": if expected_unknown { "valid-but-coverage-unavailable" } else { "verified-object" },
            "matched": reference["outcome"] == "reference-verified" && production_matches,
            "reference": reference,
            "production_status": process.status.code(),
            "production": report,
        }));
    }
    assert_eq!(positives, 11);
    assert_eq!(unknowns, 6);
    let failures = observations
        .iter()
        .filter(|row| row["matched"] != true)
        .count();
    fs::write(
        test.scratch.join("scalar-profile-observations.json"),
        serde_json::to_vec_pretty(&json!({
            "scope": "Finite scalar proof profile and honest coverage boundary only",
            "full_p2_qualified": false,
            "positives": positives,
            "valid_unsupported": unknowns,
            "failed": failures,
            "observations": observations,
        }))
        .unwrap(),
    )
    .unwrap();
    test.assert_inputs_stable();
    eprintln!(
        "Scalar profile: {positives} positives, {unknowns} valid unsupported objects, {failures} disagreements"
    );
    assert_eq!(
        failures, 0,
        "independent scalar profile mismatch; complete receipt retained"
    );
}
