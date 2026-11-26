//! Compare mixed-architecture exec and spawn with dynamically linked fixtures.
use super::*;
use std::path::Path;
use std::process::Command;

#[test]
#[ignore = "requires Rosetta and the locally built arm64, x86_64 and universal fixtures"]
fn installed_darwin_exec_and_spawn_switch_abis() {
    let dir = std::env::var("RAX_DARWIN_MIXED_ABI_FIXTURES")
        .expect("directory containing arm64, x86_64 and universal fixture binaries");
    let dir = std::fs::canonicalize(dir).unwrap();
    let arm64 = Fixture::read(&dir.join("arm64"));
    let x86_64 = Fixture::read(&dir.join("x86_64"));
    let universal = Fixture::read(&dir.join("universal"));
    for (caller, abi, target, mode, after_abi, stdout, exit) in [
        (
            &x86_64,
            "x86_64",
            &arm64,
            "exec",
            "aarch64",
            "child=arm64 inherited=1 closed=1 arg=token\n",
            17,
        ),
        (
            &arm64,
            "aarch64",
            &x86_64,
            "spawn",
            "aarch64",
            "child=x86_64 inherited=1 closed=1 arg=token\nwait=17\n",
            0,
        ),
        (
            &x86_64,
            "x86_64",
            &universal,
            "prefer-arm64",
            "x86_64",
            "child=arm64 inherited=1 closed=1 arg=token\nwait=17\n",
            0,
        ),
    ] {
        let arguments = [mode, &target.path];
        let native = Command::new(&caller.path)
            .args(arguments)
            .env_clear()
            .output()
            .unwrap();
        assert_eq!(native.status.code(), Some(exit));
        assert_eq!(native.stdout, stdout.as_bytes());
        assert!(native.stderr.is_empty());

        let options = serde_json::json!({
            "personality": "darwin",
            "native_runtime": true,
            "architecture": abi,
            "guest_path": caller.path,
            "arguments": arguments,
            "memory_bytes": 268435456,
        })
        .to_string();
        let supplied = RaxProcessImage {
            path: target.path.as_ptr().cast(),
            path_size: target.path.len(),
            data: target.bytes.as_ptr(),
            data_size: target.bytes.len(),
        };
        let mut handle = ptr::null_mut();
        assert_eq!(
            rax_process_open_image(
                caller.bytes.as_ptr(),
                caller.bytes.len(),
                options.as_ptr().cast(),
                options.len(),
                &supplied,
                1,
                &mut handle,
            ),
            RaxStatus::Ok,
            "{}",
            error()
        );
        let process = Owned(handle);
        let state = info(&process);
        assert_eq!(state["architecture"], abi);
        assert_eq!(state["capabilities"]["native_runtime"], true);
        assert_eq!(state["capabilities"]["host_filesystem"], false);
        assert_eq!(state["capabilities"]["host_services"], false);

        let result = run_installed_posix_with_turn_limit(&process, &caller.path, 100_000);
        assert_eq!(result.exit_code, exit as u32);
        assert_eq!(
            capture_installed_posix_stream(&process, RAX_PROCESS_STDOUT),
            native.stdout
        );
        assert_eq!(
            capture_installed_posix_stream(&process, RAX_PROCESS_STDERR),
            native.stderr
        );
        let after = info(&process);
        assert_eq!(after["architecture"], after_abi);
        let expected_path = if mode == "exec" {
            &target.path
        } else {
            &caller.path
        };
        assert_eq!(after["loaded_program"]["path"], expected_path.as_str());
        assert_eq!(after["loaded_program"]["has_dyld"], true);
    }
}

struct Fixture {
    path: String,
    bytes: Vec<u8>,
}

impl Fixture {
    fn read(path: &Path) -> Self {
        Self {
            path: path.to_str().unwrap().to_owned(),
            bytes: std::fs::read(path).unwrap(),
        }
    }
}
