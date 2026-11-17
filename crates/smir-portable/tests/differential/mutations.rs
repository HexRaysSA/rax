use crate::support::{harness, text};
use std::collections::BTreeSet;

#[test]
fn actual_malformed_envelopes_reject_before_semantic_verification() {
    let test = harness();
    let mut measured = 0;
    for case in &test.cases {
        if !["wire-rejection", "payload-rejection"].contains(&case.scope.as_str()) {
            continue;
        }
        let expected = &case.document["python_wire"];
        assert_eq!(text(expected, "outcome"), "rejected");
        for operation in ["roundtrip", "verify"] {
            let (process, report) = test.cli(operation, case);
            assert_eq!(process.status.code(), Some(1), "{}: {report}", case.id);
            assert_eq!(report.as_object().unwrap().len(), 3);
            assert_eq!(text(&report, "status"), "rejected");
            let class = if case.scope == "wire-rejection" {
                "framing"
            } else if text(expected, "code") == "WIRE-LIMIT" {
                "resource"
            } else {
                "wire"
            };
            assert_eq!(text(&report, "class"), class, "{}: {report}", case.id);
            assert_eq!(text(&report, "code"), text(expected, "code"), "{}", case.id);
            measured += 1;
        }
    }
    assert!(measured >= 16);
    eprintln!("Actual malformed framing/payload outcomes compared at two CLI entries: {measured}");
    test.assert_inputs_stable();
}

#[test]
fn generated_wire_inventory_is_measured_separately_from_static_proofs() {
    let test = harness();
    let inventory = &test.prepared["record_inventory"];
    let (expected, outside) = crate::corpus::expected_wire_ids(&test.root);
    let actual: BTreeSet<_> = test.cases.iter().filter(|case| case.scope == "wire-only")
        .map(|case| case.id.clone()).collect();
    assert_eq!(actual, expected, "generated cases must cover every reachable schema variant exactly");
    assert_eq!(inventory["wire_variant_cases"].as_u64(), Some(expected.len() as u64));
    let reported_outside: BTreeSet<_> = inventory["outside_object_roots"].as_array().unwrap()
        .iter().map(|name| name.as_str().unwrap().to_owned()).collect();
    assert_eq!(reported_outside, outside);
    for case in test.cases.iter().filter(|case| case.scope == "wire-only") {
        assert_eq!(case.expectation, "not-compared");
        assert!(case.document["record"].is_string());
        assert!(case.document["schema_section"].is_u64());
    }
    test.assert_inputs_stable();
}
