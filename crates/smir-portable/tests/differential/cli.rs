//! Development declaration adapters preserve unresolved deployment obligations.
use crate::support::harness;

#[test]
fn original_dependency_call_plan_has_a_bounded_static_adapter() {
    let test = harness();
    for (id, outcome, code) in [
        ("genuine-original-DEP-caller-plan", "static-reference-verified", None),
        ("reject-DEP-nominal-is-not-plan", "rejected", Some("source_plan_reference: ")),
        ("unavailable-DEP-used-as-target", "oracle-unavailable", Some("STATIC_ORACLE_USED_DEPENDENCY")),
    ] {
        let name = format!("function-addresses/{id}");
        let case = test.cases.iter().find(|case| case.id == name).expect("actual declaration countercase");
        let report = test.reference(case);
        assert_eq!(report["outcome"], outcome, "{name}: {report}");
        if let Some(code) = code {
            assert_eq!(report["code"], code, "{name}: {report}");
        } else {
            assert_eq!(report["unresolved_provider_deployment"], true);
        }
    }
    test.assert_inputs_stable();
}
