//! Check installed Darwin name resolution and closed attribute calls.
use super::*;
use std::process::Command;

#[test]
#[ignore = "requires Rosetta and the locally built closed_path_attributes fixtures"]
fn installed_darwin_path_attributes_match_native() {
    let dir = std::env::var("RAX_DARWIN_PATH_ATTRIBUTE_FIXTURES")
        .expect("directory containing arm64 and x86_64 fixture binaries");
    for (file, abi) in [("arm64", "aarch64"), ("x86_64", "x86_64")] {
        let path = std::path::Path::new(&dir)
            .join(file)
            .canonicalize()
            .unwrap();
        let path = path.to_str().unwrap();
        let native = Command::new(path).env_clear().output().unwrap();
        assert!(native.status.success());
        assert_eq!(native.stdout, b"path attributes and realpath match\n");
        assert!(native.stderr.is_empty());

        let options = serde_json::json!({
            "personality": "darwin",
            "architecture": abi,
            "guest_path": path,
            "native_runtime": true,
            "memory_bytes": 268435456,
        });
        let process = open(&std::fs::read(path).unwrap(), &options.to_string());
        let state = info(&process);
        assert_eq!(state["capabilities"]["native_runtime"], true);
        assert_eq!(state["capabilities"]["host_services"], false);
        assert_eq!(state["capabilities"]["host_filesystem"], false);
        let result = run_installed_posix_with_turn_limit(&process, path, 100_000);
        let stderr = capture_installed_posix_stream(&process, RAX_PROCESS_STDERR);
        assert_eq!(
            result.exit_code,
            0,
            "{abi}: {}",
            String::from_utf8_lossy(&stderr)
        );
        assert_eq!(
            capture_installed_posix_stream(&process, RAX_PROCESS_STDOUT),
            native.stdout,
        );
        assert_eq!(stderr, native.stderr);
    }
}
