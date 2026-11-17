//! Actual generator/input/object hashes and non-writing byte-exact reproduction.
use sha2::{Digest, Sha256};
fn hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|v| format!("{v:02x}"))
        .collect()
}
#[test]
fn all_owned_generated_corpora_have_reproducible_provenance_and_size_accounts() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    for folder in [
        "fixtures",
        "profile-fixtures",
        "state-helper-fixtures",
        "service-fixtures",
        "helper-catalog-fixtures",
        "source-role-fixtures",
        "canonical-profile-fixtures",
        "eh-release-fixtures",
        "function-address-fixtures",
        "manifest-symbol-fixtures",
        "generic-shape-fixtures",
        "ordinary-scalar-fixtures",
    ] {
        let directory = root
            .join("crates/smir-portable/tests/metadata")
            .join(folder);
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(directory.join("manifest.json")).unwrap())
                .unwrap();
        let provenance = &manifest["provenance"];
        let generator = provenance["generator"].as_str().unwrap();
        assert!(generator.starts_with("crates/smir-portable/tests/metadata/"));
        assert_eq!(
            hash(&std::fs::read(root.join(generator)).unwrap()),
            provenance["generator_sha256"].as_str().unwrap()
        );
        for (relative, expected) in provenance["input_sha256"].as_object().unwrap() {
            assert!(!std::path::Path::new(relative).is_absolute());
            assert!(!relative.split('/').any(|v| v == ".."));
            assert_eq!(
                hash(&std::fs::read(root.join(relative)).unwrap()),
                expected.as_str().unwrap(),
                "{folder}: {relative}"
            );
        }
        let mut size = 0u64;
        for (name, case) in manifest["cases"].as_object().unwrap() {
            let data = std::fs::read(directory.join(format!("{name}.smo"))).unwrap();
            assert_eq!(
                hash(&data),
                case["sha256"].as_str().unwrap(),
                "{folder}/{name}"
            );
            assert_eq!(data.len() as u64, case["bytes"].as_u64().unwrap());
            size += data.len() as u64;
        }
        assert_eq!(size, provenance["encoded_object_bytes"].as_u64().unwrap());
        assert_eq!(
            manifest["cases"].as_object().unwrap().len() as u64,
            provenance["object_count"].as_u64().unwrap()
        );
        assert!(
            !provenance["size_justification"]
                .as_str()
                .unwrap()
                .is_empty()
        );
        let result = std::process::Command::new("python3")
            .arg("-B")
            .arg(root.join(generator))
            .arg("--check")
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{folder}: {}{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
    }
}
