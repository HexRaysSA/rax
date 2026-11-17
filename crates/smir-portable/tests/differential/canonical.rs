use crate::support::{harness, text};
use std::fs;

#[test]
fn actual_rust_cli_roundtrips_all_python_canonical_object_variants() {
    let test = harness();
    let mut measured = 0;
    for case in &test.cases {
        let expected = &case.document["python_wire"];
        if text(expected, "outcome") != "decoded" {
            continue;
        }
        let (process, report) = test.cli("roundtrip", case);
        assert!(process.status.success(), "{}: {}", case.id, report);
        assert_eq!(report.as_object().unwrap().len(), 4, "{}", case.id);
        assert_eq!(text(&report, "status"), "decoded-object", "{}", case.id);
        assert_eq!(report["executable_admitted"], false, "{}", case.id);
        assert_eq!(
            text(&report, "identity"),
            text(expected, "identity"),
            "{}",
            case.id
        );
        let source = fs::read(&case.path).unwrap();
        let canonical = text(&report, "canonical_hex");
        let expected_hex: String = source.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(
            canonical, expected_hex,
            "{}: changed canonical bytes",
            case.id
        );
        measured += 1;
    }
    assert!(measured > 238, "no whole-root specimens measured");
    eprintln!("Rust/Python canonical whole objects actually compared: {measured}");
    test.assert_inputs_stable();
}

#[test]
fn actual_independent_cpp_reencodes_every_reachable_record_variant() {
    let test = harness();
    let mut measured = 0;
    for case in &test.cases {
        if text(&case.document["python_wire"], "outcome") != "decoded" {
            continue;
        }
        for section in case.document["python_wire"]["sections"].as_array().unwrap() {
            if let Some(selected) = case.document.get("schema_section") {
                if &section["section"] != selected {
                    continue;
                }
            }
            let actual = test.cpp(case, section);
            assert_eq!(actual, section["value"], "{}: C++ record differs", case.id);
            measured += 1;
        }
    }
    assert!(
        measured >= 238,
        "record inventory did not reach the C++ oracle"
    );
    eprintln!("Independent C++/Python decoded and reencoded root records: {measured}");
    test.assert_inputs_stable();
}
