use crate::support::{harness, text};
use serde_json::{Value, json};
use std::fs;

fn finish(name: &str, observations: &[Value]) {
    let test = harness();
    let failed: Vec<_> = observations
        .iter()
        .filter(|row| row["matched"] != true)
        .collect();
    let receipt = json!({
        "scope": "Static differential comparisons; no executable admission",
        "observations": observations,
        "attempted": observations.len(),
        "matched": observations.len() - failed.len(),
        "failed": failed.len(),
    });
    fs::write(
        test.scratch.join(format!("{name}-observations.json")),
        serde_json::to_vec_pretty(&receipt).unwrap(),
    )
    .unwrap();
    test.assert_inputs_stable();
    eprintln!(
        "Actual {name}: {} comparisons, {} matched, {} failed",
        observations.len(),
        observations.len() - failed.len(),
        failed.len()
    );
    assert!(
        failed.is_empty(),
        "{name}: {} independent disagreements; first failures: {:?}; complete receipt retained",
        failed.len(),
        failed
            .iter()
            .take(8)
            .map(|row| &row["id"])
            .collect::<Vec<_>>()
    );
}

#[test]
fn actual_all_root_static_positives_retain_exact_seven_owner_records() {
    let test = harness();
    let mut observations = Vec::new();
    for case in &test.cases {
        if case.expectation != "verified-object" {
            continue;
        }
        let reference = test.reference(case);
        let (process, report) = test.cli("verify", case);
        let reference_status = if case.scope == "static-local" {
            "static-reference-verified"
        } else {
            "reference-verified"
        };
        let matched = reference["outcome"] == reference_status
            && process.status.success()
            && report.as_object().is_some_and(|fields| fields.len() == 4)
            && report["status"] == "verified-object"
            && report["executable_admitted"] == false
            && report["identity"] == reference["identity"]
            && report["required_admission"]["format"] == "smir-required-admission-v1"
            && report["required_admission"]["entries"]
                == case.document["python_wire"]["owner_entries"];
        observations.push(json!({
            "id": case.id,
            "matched": matched,
            "reference": reference,
            "production_status": process.status.code(),
            "production": report,
        }));
    }
    assert!(observations.len() >= 5);
    finish("static-positive", &observations);
}

#[test]
fn actual_rehashed_semantic_mutations_match_independent_rejection_rules() {
    let test = harness();
    let mut observations = Vec::new();
    for case in &test.cases {
        if !["reference-common", "static-local"].contains(&case.scope.as_str())
            || case.expectation != "rejected"
        {
            continue;
        }
        assert_eq!(text(&case.document["python_wire"], "outcome"), "decoded");
        let reference = test.reference(case);
        let (process, report) = test.cli("verify", case);
        let matched = reference["outcome"] == "rejected"
            && reference["code"]
                .as_str()
                .is_some_and(|code| test.reviewed_diagnostic(case, code, true))
            && process.status.code() == Some(1)
            && report.as_object().is_some_and(|fields| fields.len() == 3)
            && report["status"] == "rejected"
            && report["class"] == "semantic"
            && report["code"]
                .as_str()
                .is_some_and(|code| test.reviewed_diagnostic(case, code, false));
        observations.push(json!({
            "id": case.id,
            "matched": matched,
            "reference": reference,
            "production_status": process.status.code(),
            "production": report,
        }));
    }
    assert!(observations.len() >= 20);
    finish("semantic-negative", &observations);
}
