//! Actual genuine-import startup-policy/FP bodies; custom entry is explicit.

use std::collections::BTreeSet;
use std::path::PathBuf;

use rax::user::image::pe::{PeImage, dir, imports};
use rax::user::windows::WinArch;

const BASELINE: &str = "9bc8ccdca85a5b0c9c74a7c446c85194efdc780d";
const OLD_CLI: &str = "7823ddd8837f729dc62f2f3af02fe4bc31d65c571e0140a04cdb7c5606179612";
const CONTRACTS: [(u32, &str); 11] = [
    (0, "control\n"),
    (0, "app\n"),
    (0, "locale\n"),
    (0, "invalid\n"),
    (0, "math\n"),
    (0, "fp\n"),
    (0, "context\n"),
    (0, "threads\n"),
    (0xC000_0409, ""),
    (0, "cell\n"),
    (0, "fp-control\n"),
];

fn root() -> PathBuf {
    super::fixtures().join("crt_bootstrap")
}
fn manifest() -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(root().join("manifest.json")).unwrap()).unwrap()
}

fn run(arch: &str, binding: &str, mode: usize) {
    let metadata = manifest();
    let entries: Vec<_> = metadata["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["arch"] == arch && c["binding"] == binding && c["mode"] == mode)
        .collect();
    assert_eq!(entries.len(), 1);
    let entry = entries[0];
    let (status, trace) = CONTRACTS[mode];
    assert_eq!(entry["expected_status"], status);
    assert_eq!(entry["expected_shell_exit"], status & 0xFF);
    assert_eq!(entry["expected_stdout"], trace);
    let data = std::fs::read(root().join(entry["image_path"].as_str().unwrap())).unwrap();
    for slice in [1, 4096] {
        let input = super::TemporaryImage::new(
            &format!("bootstrap-{arch}-{binding}-{mode}-{slice}"),
            &data,
        );
        let command_line = format!("graph.exe {mode}");
        assert_eq!(entry["command_line"], command_line);
        let drive = format!("C={}", input.directory.display());
        let output = super::cli_support::run(
            &[
                "--os",
                "windows",
                "--memory",
                "64M",
                "--drive",
                &drive,
                "--cwd",
                "C:\\",
                "--slice",
                &slice.to_string(),
                "--seed",
                "1",
                "--clear-env",
                "--command-line",
                &command_line,
                input.path.to_str().unwrap(),
            ],
            &[("RAX_NO_JIT", "1")],
            None,
            std::time::Duration::from_secs(30),
        );
        assert_eq!(
            output.status,
            Some((status & 0xFF) as i32),
            "{arch}/{binding}/{mode} slice={slice}: {output:?}"
        );
        assert!(output.signal.is_none());
        assert_eq!(output.stdout, trace.as_bytes());
        assert_eq!(
            output.stderr,
            if status == 0 {
                String::new()
            } else {
                format!(
                    "rax-user: {}: {}\n",
                    input.path.display(),
                    rax::user::windows::ExitStatus::Exited(status)
                )
            }
        );
        assert_eq!(std::fs::read(&input.path).unwrap(), data);
    }
}

macro_rules! cases {
    ($arch:literal, $binding:literal) => {
        #[test]
        fn raw_exit_control() {
            run($arch, $binding, 0);
        }
        #[test]
        fn app_extrema_shared() {
            run($arch, $binding, 1);
        }
        #[test]
        fn locale_transitions() {
            run($arch, $binding, 2);
        }
        #[test]
        fn locale_invalid_returning_handler() {
            run($arch, $binding, 3);
        }
        #[test]
        fn math_registration_not_eager_call() {
            run($arch, $binding, 4);
        }
        #[test]
        fn fp_raw_snapshot_and_resumed_scalar() {
            run($arch, $binding, 5);
        }
        #[test]
        fn exposed_saved_context() {
            run($arch, $binding, 6);
        }
        #[test]
        fn locale_thread_isolation() {
            run($arch, $binding, 7);
        }
        #[test]
        fn locale_invalid_forced_exit() {
            run($arch, $binding, 8);
        }
        #[test]
        fn exception_pointer_thread_cell() {
            run($arch, $binding, 9);
        }
        #[test]
        fn private_isa_instrumentation_control() {
            run($arch, $binding, 10);
        }
    };
}
mod x86 {
    use super::*;
    mod ucrtbase {
        use super::*;
        cases!("x86", "ucrtbase");
    }
    mod apiset {
        use super::*;
        cases!("x86", "apiset");
    }
}
mod x64 {
    use super::*;
    mod ucrtbase {
        use super::*;
        cases!("x64", "ucrtbase");
    }
    mod apiset {
        use super::*;
        cases!("x64", "apiset");
    }
}
mod arm64 {
    use super::*;
    mod ucrtbase {
        use super::*;
        cases!("arm64", "ucrtbase");
    }
    mod apiset {
        use super::*;
        cases!("arm64", "apiset");
    }
}

fn expected_imports(binding: &str) -> BTreeSet<(String, String)> {
    let mut result = BTreeSet::new();
    for (family, names) in [
        (
            "kernel32",
            &[
                "CloseHandle",
                "CreateThread",
                "ExitProcess",
                "GetCommandLineW",
                "GetExitCodeThread",
                "GetLastError",
                "GetStdHandle",
                "SetLastError",
                "WaitForSingleObject",
                "WriteFile",
            ][..],
        ),
        (
            "runtime",
            &[
                "__pxcptinfoptrs",
                "_errno",
                "_fpreset",
                "_query_app_type",
                "_set_app_type",
                "_set_invalid_parameter_handler",
            ][..],
        ),
        ("locale", &["_configthreadlocale"][..]),
        ("math", &["__setusermatherr"][..]),
    ] {
        let dll = if family == "kernel32" {
            "kernel32.dll".into()
        } else if binding == "apiset" {
            format!("api-ms-win-crt-{family}-l1-1-0.dll")
        } else {
            "ucrtbase.dll".into()
        };
        result.extend(names.iter().map(|name| (dll.clone(), (*name).into())));
    }
    result
}

#[test]
fn independent_corpus_inputs_iats_baseline_and_double_build_are_exact() {
    let bytes = std::fs::read(root().join("manifest.json")).unwrap();
    let metadata: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let hash = super::sha256::hex(&bytes);
    assert_eq!(metadata["source_baseline"], BASELINE);
    assert_eq!(metadata["physical_pe_count"], 6);
    assert_eq!(metadata["semantic_case_count"], 66);
    assert_eq!(metadata["required_execution_count"], 132);
    assert_eq!(metadata["slices"], serde_json::json!([1, 4096]));
    let primary =
        std::fs::read(root().join(metadata["primary_sources_path"].as_str().unwrap())).unwrap();
    assert_eq!(
        metadata["primary_sources_sha256"],
        super::sha256::hex(&primary)
    );
    for source in metadata["sources"].as_array().unwrap() {
        let data = std::fs::read(root().join(source["path"].as_str().unwrap())).unwrap();
        assert_eq!(source["sha256"], super::sha256::hex(&data));
        assert_eq!(source["bytes"], data.len());
    }
    let mut physical = BTreeSet::new();
    for entry in metadata["fixtures"].as_array().unwrap() {
        let arch = entry["arch"].as_str().unwrap();
        let binding = entry["binding"].as_str().unwrap();
        assert!(["x86", "x64", "arm64"].contains(&arch));
        assert!(["ucrtbase", "apiset"].contains(&binding));
        assert!(physical.insert((arch, binding)));
        let data = std::fs::read(root().join(entry["path"].as_str().unwrap())).unwrap();
        assert_eq!(entry["sha256"], super::sha256::hex(&data));
        assert_eq!(entry["bytes"], data.len());
        let image = PeImage::parse(data).unwrap();
        assert_eq!(
            WinArch::from_machine(image.headers().machine),
            Some(match arch {
                "x86" => WinArch::X86,
                "x64" => WinArch::X64,
                _ => WinArch::Arm64,
            })
        );
        assert_eq!(image.headers().time_date_stamp, 0);
        let memory = image.memory_image();
        let mut actual = BTreeSet::new();
        for descriptor in
            imports::descriptors(&memory, image.headers().directory(dir::IMPORT)).unwrap()
        {
            let dll = String::from_utf8(descriptor.dll_name(&memory).unwrap())
                .unwrap()
                .to_ascii_lowercase();
            for thunk in descriptor.thunks(&memory, image.headers().kind).unwrap() {
                let imports::ImportRef::Name { name, .. } = thunk.symbol else {
                    panic!("unexpected ordinal import")
                };
                assert!(actual.insert((dll.clone(), String::from_utf8(name).unwrap())));
            }
        }
        assert_eq!(actual, expected_imports(binding));
        let recorded: BTreeSet<_> = entry["imports"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|d| {
                d["symbols"].as_array().unwrap().iter().map(move |s| {
                    (
                        d["dll"].as_str().unwrap().to_lowercase(),
                        s.as_str().unwrap().to_owned(),
                    )
                })
            })
            .collect();
        assert_eq!(actual, recorded);
        for (path, digest) in [
            ("iat_path", "iat_sha256"),
            ("instructions_path", "instructions_sha256"),
        ] {
            assert_eq!(
                entry[digest],
                super::sha256::hex(
                    &std::fs::read(root().join(entry[path].as_str().unwrap())).unwrap()
                )
            );
        }
    }
    assert_eq!(physical.len(), 6);
    let mut cells = BTreeSet::new();
    for case in metadata["cases"].as_array().unwrap() {
        let arch = case["arch"].as_str().unwrap();
        let binding = case["binding"].as_str().unwrap();
        let mode = case["mode"].as_u64().unwrap() as usize;
        assert!(physical.contains(&(arch, binding)));
        assert!(cells.insert((arch, binding, mode)));
        let (status, stdout) = CONTRACTS[mode];
        assert_eq!(case["expected_status"], status);
        assert_eq!(case["expected_shell_exit"], status & 0xFF);
        assert_eq!(case["expected_stdout"], stdout);
    }
    assert_eq!(cells.len(), 66);
    let baseline: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root().join("baseline.json")).unwrap()).unwrap();
    assert_eq!(baseline["source_baseline"], BASELINE);
    assert_eq!(baseline["executable_sha256"], OLD_CLI);
    assert_eq!(baseline["fixture_manifest_sha256"], hash);
    let runs = baseline["runs"].as_array().unwrap();
    assert_eq!(runs.len(), 132);
    let mut executions = BTreeSet::new();
    let mut controls = 0;
    for r in runs {
        let arch = r["arch"].as_str().unwrap();
        let binding = r["binding"].as_str().unwrap();
        let mode = r["mode"].as_u64().unwrap() as usize;
        let slice = r["slice_instructions"].as_u64().unwrap();
        assert!([1, 4096].contains(&slice));
        assert!(cells.contains(&(arch, binding, mode)));
        assert!(executions.insert((arch, binding, mode, slice)));
        assert_eq!(r["watchdog_expired"], false);
        assert!(r["signal"].is_null());
        if [0, 10].contains(&mode) {
            controls += 1;
            assert_eq!(r["shell_exit"], 0);
            assert_eq!(r["stdout"], CONTRACTS[mode].1);
            assert!(r["missing_export"].is_null());
        } else {
            assert_eq!(r["shell_exit"], 125);
            assert_eq!(r["stdout"], "");
            let missing = match mode {
                1 => "_query_app_type",
                2 | 3 | 7 | 8 => "_configthreadlocale",
                4 => "__setusermatherr",
                5 => "_fpreset",
                6 | 9 => "__pxcptinfoptrs",
                _ => panic!("missing-export cell must not be a control"),
            };
            assert_eq!(r["missing_export"], format!("ucrtbase.dll!{missing}"));
            assert!(r["stderr"].as_str().unwrap().contains(&format!(
                "unimplemented Windows export: ucrtbase.dll!{missing} at "
            )));
        }
    }
    assert_eq!(controls, 24);
    assert_eq!(executions.len(), 132);
    let rebuild: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root().join("rebuild.json")).unwrap()).unwrap();
    assert_eq!(rebuild["manifest_sha256"], hash);
    assert_eq!(rebuild["second_build_exit"], 0);
    assert_eq!(rebuild["physical_pe_count"], 6);
    assert_eq!(rebuild["pe_bytes"], 39_936);
    let inputs = rebuild["verified_inputs"].as_array().unwrap();
    assert_eq!(inputs.len(), 30);
    for input in inputs {
        assert_eq!(
            input["sha256"],
            super::sha256::hex(
                &std::fs::read(root().join(input["path"].as_str().unwrap())).unwrap()
            )
        );
    }
}
