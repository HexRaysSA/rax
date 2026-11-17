//! Immutable old controls must fail revision before their old records are read.
use crate::support::inspect;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn folder() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("conformance/differential/legacy-abi2")
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn scratch(name: &str) -> PathBuf {
    let parent = std::env::var_os("SMIR_DIFF_SCRATCH")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let result = parent.join(format!("legacy-{name}-{}-{nonce}", std::process::id()));
    fs::create_dir_all(&result).unwrap();
    result
}

#[test]
fn all_six_old_controls_reject_revision_before_old_semantics() {
    let folder = folder();
    let manifest_bytes = fs::read(folder.join("manifest.json")).unwrap();
    let manifest: Value = serde_json::from_slice(&manifest_bytes).unwrap();
    let entries = manifest["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 6);
    let mut observations = Vec::new();
    for entry in entries {
        let path = folder.join(entry["path"].as_str().unwrap());
        let bytes = fs::read(&path).unwrap();
        assert_eq!(bytes.len() as u64, entry["bytes"].as_u64().unwrap());
        assert_eq!(digest(&bytes), entry["sha256"]);
        for operation in ["roundtrip", "verify"] {
            let (process, report) = inspect(operation, &path);
            assert_eq!(process.status.code(), Some(1), "{entry}: {report}");
            assert_eq!(report, json!({"status":"rejected", "class":"wire", "code":"WIRE-REVISION"}),
                       "old source-plan/SSA/profile outcome must not replace revision preflight");
            observations.push(json!({"id":entry["id"], "operation":operation, "report":report}));
        }
        assert_eq!(fs::read(&path).unwrap(), bytes, "legacy bytes changed");
    }
    assert_eq!(fs::read(folder.join("manifest.json")).unwrap(), manifest_bytes);
    let output = scratch("revision");
    fs::write(output.join("observations.json"), serde_json::to_vec_pretty(&json!({
        "scope":"Actual current CLI revision rejection only; no new semantic or executable coverage",
        "observations":observations, "old_reader_added":false,
        "compiler_freeze_passed":false, "full_p2_qualified":false
    })).unwrap()).unwrap();
    eprintln!("Actual old-control revision observations retained: {}", output.display());
}

#[test]
fn malformed_envelope_precedes_old_payload_revision() {
    let source = folder().join("raw/portable-identity.smo");
    let original = fs::read(&source).unwrap();
    let mut damaged = original.clone();
    damaged[0] ^= 1;
    let output = scratch("bad-magic");
    let path = output.join("bad-magic.smo");
    fs::write(&path, damaged).unwrap();
    let (process, report) = inspect("roundtrip", &path);
    assert_eq!(process.status.code(), Some(1));
    assert_eq!(report["status"], "rejected");
    assert_eq!(report["class"], "framing");
    assert_ne!(report["code"], "WIRE-REVISION");
    assert_eq!(fs::read(&source).unwrap(), original);
    fs::write(output.join("observations.json"), serde_json::to_vec_pretty(&report).unwrap()).unwrap();
}
