//! Static binding proofs and actual malformed-unused-import rejection.
use crate::{ErrorClass, Limits};

#[test]
fn independent_state_helper_objects_and_unused_mutations_use_real_factory() {
    let manifest: serde_json::Value =
        serde_json::from_str(include_str!("state-helper-fixtures/manifest.json")).unwrap();
    let folder = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/metadata/state-helper-fixtures");
    let mut positive = 0;
    let mut negative = 0;
    let mut unknown = 0;
    for (name, case) in manifest["cases"].as_object().unwrap() {
        let data = std::fs::read(folder.join(format!("{name}.smo"))).unwrap();
        let result = crate::verify_object(&data, Limits::default());
        if case["accept"] == true {
            assert!(result.is_ok(), "{name}: {:?}", result.err());
            println!("state-helper {name}: static-verified");
            positive += 1;
        } else if case["expected_class"] == "unavailable-evidence" {
            let error = result
                .err()
                .unwrap_or_else(|| panic!("unaudited source issued facts: {name}"));
            assert_eq!(
                error.class(),
                ErrorClass::UnavailableEvidence,
                "{name}: {error:?}"
            );
            println!("state-helper {name}: unavailable {}", error.code());
            unknown += 1;
        } else {
            let error = result
                .err()
                .unwrap_or_else(|| panic!("malformed unused {name} accepted"));
            assert_eq!(error.class(), ErrorClass::Semantic, "{name}: {error:?}");
            println!("state-helper {name}: semantic {}", error.code());
            negative += 1;
        }
    }
    assert_eq!(positive, 15);
    assert_eq!(unknown, 0);
    assert!(
        negative == 75,
        "all supported-source mutations remain semantic, without fake record facts"
    );
}
