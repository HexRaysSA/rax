//! Compiled dynamic UCRT cleanup graphs, not ordinary compiler startup.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use rax::user::image::pe::{PeImage, dir, imports};
use rax::user::windows::WinArch;

const ARCHES: [&str; 3] = ["x86", "x64", "arm64"];
const BINDINGS: [&str; 2] = ["ucrtbase", "apiset"];
const BASELINE: &str = "02f28dbb4b6cc51e394987b7784ca34de965e2f5";
const OLD_CLI: &str = "b3e53f095c865ebc4435f1ac1cd71739ea4fc8c95097d92f0f693b43fb70fcaa";

// Independent expectations from the compiled producer control flow and the
// selected SDK contracts, not inferred from current emulator observations.
const CONTRACTS: [(u32, &str, bool); 21] = [
    (17, "TBCAD", true),
    (18, "RSQD", true),
    (19, "D", true),
    (20, "D", true),
    (21, "D", true),
    (22, "", false),
    (0, "TBCATVD", true),
    (0, "VD", true),
    (23, "H", false),
    (0xC000_0409, "", false),
    (3, "HD", true),
    (3, "HD", true),
    (3, "SD", true),
    (3, "D", true),
    (0, "ABZIVD", true),
    (3, "D", true),
    (24, "TXH", false),
    (25, "TXO", false),
    (3, "HIRD", true),
    (26, "TXIRAD", true),
    (24, "TXUH", false),
];

fn root() -> PathBuf {
    super::fixtures().join("crt_exit")
}

fn manifest() -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(root().join("manifest.json")).unwrap()).unwrap()
}

fn case<'a>(
    manifest: &'a serde_json::Value,
    arch: &str,
    binding: &str,
    mode: usize,
) -> &'a serde_json::Value {
    let matches: Vec<_> = manifest["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|entry| {
            entry["arch"] == arch && entry["binding"] == binding && entry["mode"] == mode
        })
        .collect();
    assert_eq!(matches.len(), 1);
    matches[0]
}

struct Bundle {
    directory: PathBuf,
    image: PathBuf,
    companion: PathBuf,
}

impl Bundle {
    fn new(entry: &serde_json::Value, slice: u64) -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let sequence = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "rax-crt-exit-{}-{}-{slice}-{stamp}-{sequence}",
            std::process::id(),
            entry["mode"]
        ));
        std::fs::create_dir(&directory).unwrap();
        let image = directory.join("graph.exe");
        let companion = directory.join("companion.dll");
        std::fs::copy(root().join(entry["image_path"].as_str().unwrap()), &image).unwrap();
        std::fs::copy(
            root().join(entry["companion_path"].as_str().unwrap()),
            &companion,
        )
        .unwrap();
        Self {
            directory,
            image,
            companion,
        }
    }
}

impl Drop for Bundle {
    fn drop(&mut self) {
        // Exact files in this freshly created, exclusively owned directory.
        let _ = std::fs::remove_file(self.directory.join("pending.bin"));
        let _ = std::fs::remove_file(&self.companion);
        let _ = std::fs::remove_file(&self.image);
        let _ = std::fs::remove_dir(&self.directory);
    }
}

fn run(arch: &str, binding: &str, mode: usize) {
    let metadata = manifest();
    let entry = case(&metadata, arch, binding, mode);
    let (status, trace, detach) = CONTRACTS[mode];
    assert_eq!(entry["expected_status"], status);
    assert_eq!(entry["expected_shell_exit"], status & 0xFF);
    assert_eq!(entry["expected_stdout"], trace);
    assert_eq!(entry["expected_detach"], detach);
    assert_eq!(
        entry["expected_files"]["pending.bin"],
        if detach { "B" } else { "" }
    );
    for slice in [1u64, 4096] {
        let bundle = Bundle::new(entry, slice);
        let image_bytes = std::fs::read(&bundle.image).unwrap();
        let dll_bytes = std::fs::read(&bundle.companion).unwrap();
        let drive = format!("C={}", bundle.directory.display());
        let command_line = format!("graph.exe {mode}");
        assert_eq!(entry["command_line"], command_line);
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
                bundle.image.to_str().unwrap(),
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
        assert_eq!(
            output.stdout,
            trace.as_bytes(),
            "{arch}/{binding}/{mode} slice={slice}"
        );
        if status == 0 {
            assert!(output.stderr.is_empty());
        } else {
            let terminal = rax::user::windows::ExitStatus::Exited(status).to_string();
            assert_eq!(
                output.stderr,
                format!("rax-user: {}: {terminal}\n", bundle.image.display()),
                "full 32-bit status, not only shell truncation"
            );
        }
        assert_eq!(
            std::fs::read(bundle.directory.join("pending.bin")).unwrap(),
            if detach {
                b"B".as_slice()
            } else {
                b"".as_slice()
            }
        );
        assert_eq!(std::fs::read(&bundle.image).unwrap(), image_bytes);
        assert_eq!(std::fs::read(&bundle.companion).unwrap(), dll_bytes);
        let files: BTreeSet<_> = std::fs::read_dir(&bundle.directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(
            files,
            ["graph.exe", "companion.dll", "pending.bin"]
                .map(std::ffi::OsString::from)
                .into_iter()
                .collect()
        );
    }
}

macro_rules! cases {
    ($arch:literal, $binding:literal) => {
        #[test]
        fn full_exit() {
            run($arch, $binding, 0)
        }
        #[test]
        fn quick_exit() {
            run($arch, $binding, 1)
        }
        #[test]
        fn minimal_exit() {
            run($arch, $binding, 2)
        }
        #[test]
        fn minimal_capital_exit() {
            run($arch, $binding, 3)
        }
        #[test]
        fn raw_normal_exit() {
            run($arch, $binding, 4)
        }
        #[test]
        fn raw_forced_exit() {
            run($arch, $binding, 5)
        }
        #[test]
        fn repeat_returning_cleanup() {
            run($arch, $binding, 6)
        }
        #[test]
        fn minimal_returning_cleanup() {
            run($arch, $binding, 7)
        }
        #[test]
        fn duplicate_tls_custom_terminate() {
            run($arch, $binding, 8)
        }
        #[test]
        fn duplicate_tls_default_fastfail() {
            run($arch, $binding, 9)
        }
        #[test]
        fn returning_terminate_handler() {
            run($arch, $binding, 10)
        }
        #[test]
        fn escaping_terminate_handler() {
            run($arch, $binding, 11)
        }
        #[test]
        fn custom_abort_handler() {
            run($arch, $binding, 12)
        }
        #[test]
        fn ignored_abort_still_exits() {
            run($arch, $binding, 13)
        }
        #[test]
        fn software_signal_roundtrip() {
            run($arch, $binding, 14)
        }
        #[test]
        fn default_term_signal() {
            run($arch, $binding, 15)
        }
        #[test]
        fn escaping_cpp_filter() {
            run($arch, $binding, 16)
        }
        #[test]
        fn escaping_other_outer_search() {
            run($arch, $binding, 17)
        }
        #[test]
        fn terminate_inner_guest_handler() {
            run($arch, $binding, 18)
        }
        #[test]
        fn cpp_inner_guest_handler() {
            run($arch, $binding, 19)
        }
        #[test]
        fn cpp_guest_unwind_before_terminate() {
            run($arch, $binding, 20)
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

fn inventory(base: &Path) -> BTreeSet<String> {
    fn visit(base: &Path, directory: &Path, files: &mut BTreeSet<String>) {
        for entry in std::fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let kind = entry.file_type().unwrap();
            if kind.is_dir() {
                visit(base, &entry.path(), files);
            } else {
                assert!(kind.is_file());
                assert!(
                    files.insert(
                        entry
                            .path()
                            .strip_prefix(base)
                            .unwrap()
                            .to_str()
                            .unwrap()
                            .into()
                    )
                );
            }
        }
    }
    let mut files = BTreeSet::new();
    visit(base, base, &mut files);
    files
}

fn imports(image: &PeImage) -> BTreeSet<(String, String)> {
    let memory = image.memory_image();
    let mut result = BTreeSet::new();
    for descriptor in imports::descriptors(&memory, image.headers().directory(dir::IMPORT)).unwrap()
    {
        let dll = String::from_utf8(descriptor.dll_name(&memory).unwrap())
            .unwrap()
            .to_ascii_lowercase();
        for thunk in descriptor.thunks(&memory, image.headers().kind).unwrap() {
            let imports::ImportRef::Name { name, .. } = thunk.symbol else {
                panic!("unexpected ordinal")
            };
            assert!(result.insert((dll.clone(), String::from_utf8(name).unwrap())));
        }
    }
    result
}

fn expected_imports(binding: &str, role: &str) -> BTreeSet<(String, String)> {
    let mut result = BTreeSet::new();
    let mut insert = |dll: &str, names: &[&str]| {
        result.extend(
            names
                .iter()
                .map(|name| (dll.to_owned(), (*name).to_owned())),
        );
    };
    insert(
        "kernel32.dll",
        &["GetStdHandle", "TerminateProcess", "WriteFile"],
    );
    if role == "companion" {
        return result;
    }
    insert(
        "kernel32.dll",
        &[
            "ExitProcess",
            "CreateFileW",
            "GetFileSizeEx",
            "GetCommandLineW",
            "LoadLibraryW",
            "GetProcAddress",
            "RaiseException",
        ],
    );
    insert(
        if binding == "apiset" {
            "api-ms-win-crt-runtime-l1-1-0.dll"
        } else {
            "ucrtbase.dll"
        },
        &[
            "_crt_atexit",
            "_crt_at_quick_exit",
            "exit",
            "quick_exit",
            "_exit",
            "_Exit",
            "_cexit",
            "_c_exit",
            "_register_thread_local_exe_atexit_callback",
            "set_terminate",
            "_get_terminate",
            "terminate",
            "abort",
            "_set_abort_behavior",
            "signal",
            "raise",
            "_errno",
            "_set_invalid_parameter_handler",
        ],
    );
    insert(
        if binding == "apiset" {
            "api-ms-win-crt-stdio-l1-1-0.dll"
        } else {
            "ucrtbase.dll"
        },
        &["_open_osfhandle", "_wfdopen", "fwrite", "setvbuf"],
    );
    result
}

#[test]
fn compiled_exit_corpus_imports_contract_matrix_and_baseline_are_exact() {
    let bytes = std::fs::read(root().join("manifest.json")).unwrap();
    let metadata: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(metadata["source_baseline"], BASELINE);
    assert_eq!(metadata["physical_pe_count"], 12);
    assert_eq!(metadata["semantic_case_count"], 126);
    assert_eq!(metadata["required_execution_count"], 252);
    assert_eq!(metadata["slices"], serde_json::json!([1, 4096]));
    let primary_sources =
        std::fs::read(root().join(metadata["primary_sources_path"].as_str().unwrap())).unwrap();
    assert_eq!(
        metadata["primary_sources_sha256"],
        super::sha256::hex(&primary_sources)
    );
    let fixtures = metadata["fixtures"].as_array().unwrap();
    assert_eq!(fixtures.len(), 12);
    let mut artifacts = BTreeMap::new();
    let mut physical = BTreeSet::new();
    let mut fixture_matrix = BTreeSet::new();
    for entry in fixtures {
        let arch = entry["arch"].as_str().unwrap();
        let binding = entry["binding"].as_str().unwrap();
        let role = entry["role"].as_str().unwrap();
        assert!(
            ARCHES.contains(&arch)
                && BINDINGS.contains(&binding)
                && ["graph", "companion"].contains(&role)
        );
        assert!(fixture_matrix.insert((arch, binding, role)));
        let path = entry["path"].as_str().unwrap();
        let data = std::fs::read(root().join(path)).unwrap();
        let hash = super::sha256::hex(&data);
        assert_eq!(entry["sha256"], hash);
        assert_eq!(entry["bytes"], data.len());
        assert!(artifacts.insert(path.to_owned(), hash).is_none());
        assert!(physical.insert(path.to_owned()));
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
        let actual = imports(&image);
        assert_eq!(actual, expected_imports(binding, role));
        let recorded: BTreeSet<_> = entry["imports"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|dll| {
                dll["symbols"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(move |symbol| {
                        (
                            dll["dll"].as_str().unwrap().to_ascii_lowercase(),
                            symbol.as_str().unwrap().to_owned(),
                        )
                    })
            })
            .collect();
        assert_eq!(actual, recorded);
        assert!(actual.iter().all(|(dll, _)| dll == "kernel32.dll"
            || dll == "ucrtbase.dll"
            || dll == "api-ms-win-crt-runtime-l1-1-0.dll"
            || dll == "api-ms-win-crt-stdio-l1-1-0.dll"));
        for (dll, name) in &actual {
            if binding == "apiset"
                && ["_open_osfhandle", "_wfdopen", "fwrite", "setvbuf"].contains(&name.as_str())
            {
                assert_eq!(dll, "api-ms-win-crt-stdio-l1-1-0.dll");
            }
        }
        let iat = entry["iat_path"].as_str().unwrap();
        let observation = std::fs::read(root().join(iat)).unwrap();
        assert_eq!(entry["iat_sha256"], super::sha256::hex(&observation));
        let mut dll = "";
        let mut observed = BTreeSet::new();
        for line in std::str::from_utf8(&observation)
            .unwrap()
            .lines()
            .map(str::trim)
        {
            if let Some(name) = line.strip_prefix("Name: ") {
                dll = name;
            } else if let Some(symbol) = line.strip_prefix("Symbol: ") {
                assert!(observed.insert((
                    dll.to_ascii_lowercase(),
                    symbol.rsplit_once(" (").unwrap().0.to_owned()
                )));
            }
        }
        assert_eq!(observed, actual);
        if role == "companion" {
            assert!(
                std::str::from_utf8(&observation)
                    .unwrap()
                    .contains("Name: configure\n")
            );
        }
        assert!(physical.insert(iat.into()));
    }
    assert_eq!(fixture_matrix.len(), 12);
    let mut matrix = BTreeSet::new();
    for entry in metadata["cases"].as_array().unwrap() {
        let arch = entry["arch"].as_str().unwrap();
        let binding = entry["binding"].as_str().unwrap();
        let mode = entry["mode"].as_u64().unwrap() as usize;
        assert!(ARCHES.contains(&arch) && BINDINGS.contains(&binding) && mode < CONTRACTS.len());
        assert!(matrix.insert((arch, binding, mode)));
        let (status, trace, detach) = CONTRACTS[mode];
        assert_eq!(entry["expected_status"], status);
        assert_eq!(entry["expected_shell_exit"], status & 0xFF);
        assert_eq!(entry["expected_stdout"], trace);
        assert_eq!(entry["expected_detach"], detach);
        assert_eq!(entry["expected_files"].as_object().unwrap().len(), 1);
        assert_eq!(
            entry["expected_files"]["pending.bin"],
            if detach { "B" } else { "" }
        );
        assert!(artifacts.contains_key(entry["image_path"].as_str().unwrap()));
        assert!(artifacts.contains_key(entry["companion_path"].as_str().unwrap()));
    }
    assert_eq!(matrix.len(), 126);
    for entry in metadata["sources"].as_array().unwrap() {
        let path = entry["path"].as_str().unwrap();
        let data = std::fs::read(root().join(path)).unwrap();
        assert_eq!(entry["sha256"], super::sha256::hex(&data));
        assert_eq!(entry["bytes"], data.len());
        assert!(physical.insert(path.into()));
    }
    physical.extend(["manifest.json".into(), "baseline.json".into()]);
    assert_eq!(inventory(&root()), physical);
    let baseline: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root().join("baseline.json")).unwrap()).unwrap();
    assert_eq!(baseline["source_baseline"], BASELINE);
    assert_eq!(baseline["executable_sha256"], OLD_CLI);
    assert_eq!(baseline["seed"], 1);
    assert_eq!(baseline["arena_bytes"], 67_108_864);
    assert_eq!(baseline["watchdog_seconds"], 30);
    assert_eq!(baseline["environment"]["RAX_NO_JIT"], "1");
    assert_eq!(
        baseline["fixture_manifest_sha256"],
        super::sha256::hex(&bytes)
    );
    let mut old_runs = BTreeSet::new();
    for entry in baseline["runs"].as_array().unwrap() {
        let arch = entry["arch"].as_str().unwrap();
        let binding = entry["binding"].as_str().unwrap();
        let mode = entry["mode"].as_u64().unwrap() as usize;
        let slice = entry["slice_instructions"].as_u64().unwrap();
        assert!(matrix.contains(&(arch, binding, mode)) && [1, 4096].contains(&slice));
        assert!(old_runs.insert((arch, binding, mode, slice)));
        let declared = case(&metadata, arch, binding, mode);
        assert_eq!(
            entry["input_sha256"],
            artifacts[declared["image_path"].as_str().unwrap()]
        );
        assert_eq!(
            entry["companion_sha256"],
            artifacts[declared["companion_path"].as_str().unwrap()]
        );
        assert_eq!(entry["signal"], serde_json::Value::Null);
        assert_eq!(entry["watchdog_expired"], false);
        assert_eq!(entry["files"], serde_json::json!({"pending.bin": ""}));
        match mode {
            4 => {
                assert_eq!(entry["shell_exit"], 21);
                assert_eq!(entry["stdout"], "D");
                assert_eq!(entry["missing_export"], serde_json::Value::Null);
                assert_ne!(
                    entry["files"], declared["expected_files"],
                    "observed old detach-flush defect"
                );
            }
            5 => {
                assert_eq!(entry["shell_exit"], 22);
                assert_eq!(entry["stdout"], "");
                assert_eq!(entry["missing_export"], serde_json::Value::Null);
                assert_eq!(
                    entry["files"], declared["expected_files"],
                    "unchanged forced-exit control"
                );
            }
            _ => {
                let missing = match mode {
                    0..=3 | 6 | 7 | 9 => "_register_thread_local_exe_atexit_callback",
                    8 | 10 | 11 | 16..=20 => "set_terminate",
                    12..=15 => "signal",
                    _ => unreachable!(),
                };
                assert_eq!(entry["shell_exit"], 125);
                assert_eq!(entry["stdout"], "");
                let export = format!("ucrtbase.dll!{missing}");
                assert_eq!(entry["missing_export"], export);
                assert!(
                    entry["stderr"]
                        .as_str()
                        .unwrap()
                        .contains(&format!("unimplemented Windows export: {export}"))
                );
            }
        }
    }
    assert_eq!(old_runs.len(), 252);
}
