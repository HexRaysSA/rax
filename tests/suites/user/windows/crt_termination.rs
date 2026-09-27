//! Global registration witnesses, not admission of CRT termination exports.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use rax::user::image::pe::{PeImage, dir, imports};
use rax::user::windows::WinArch;

const ARCHES: [&str; 3] = ["x86", "x64", "arm64"];
const BINDINGS: [&str; 2] = ["ucrtbase", "apiset"];
const PROGRAMS: [&str; 5] = [
    "register_zero",
    "register_65",
    "register_1057",
    "explicit",
    "concurrent",
];
const BASELINE: &str = "06e90d4bb41e0390a877819ed41ed98e369558a3";
const BASELINE_CLI_SHA: &str = "690e076e084a3590005fe0aec2d8723e9095954afee2531a227e0bb9e4eaf924";

fn root() -> PathBuf {
    super::fixtures().join("crt_termination")
}
fn stdout(program: &str) -> &'static [u8] {
    match program {
        "explicit" => b"explicit\n",
        "concurrent" => b"concurrent\n",
        _ => b"registered\n",
    }
}

struct Bundle {
    directory: PathBuf,
    image: PathBuf,
}
impl Bundle {
    fn new(arch: &str, binding: &str, program: &str, slice: &str) -> Self {
        static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let number = SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "rax-crt-global-{}-{arch}-{binding}-{program}-{slice}-{stamp}-{number}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).unwrap();
        let image = directory.join("probe.exe");
        std::fs::copy(
            root().join(format!("bin/{arch}/{binding}/{program}.exe")),
            &image,
        )
        .unwrap();
        Self { directory, image }
    }
}
impl Drop for Bundle {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.image);
        let _ = std::fs::remove_dir(&self.directory);
    }
}

fn run(arch: &str, binding: &str, program: &str) {
    assert!(ARCHES.contains(&arch) && BINDINGS.contains(&binding) && PROGRAMS.contains(&program));
    let original =
        std::fs::read(root().join(format!("bin/{arch}/{binding}/{program}.exe"))).unwrap();
    for slice in ["1", "4096"] {
        let bundle = Bundle::new(arch, binding, program, slice);
        let drive = format!("C={}", bundle.directory.display());
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
                slice,
                "--seed",
                "1",
                "--clear-env",
                bundle.image.to_str().unwrap(),
            ],
            &[("RAX_NO_JIT", "1")],
            None,
            std::time::Duration::from_secs(30),
        );
        assert_eq!(
            output.status,
            Some(0),
            "{arch}/{binding}/{program} slice={slice}: stderr={}, stdout={:?}, signal={:?}",
            output.stderr,
            output.stdout,
            output.signal
        );
        assert_eq!(output.stdout, stdout(program));
        assert!(output.stderr.is_empty());
        assert_eq!(std::fs::read(&bundle.image).unwrap(), original);
        let files: Vec<_> = std::fs::read_dir(&bundle.directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(files, [std::ffi::OsString::from("probe.exe")]);
    }
}

macro_rules! cases {
    ($arch:literal, $( $name:ident => ($binding:literal, $program:literal) ),+ $(,)?) => {
        $( #[test] fn $name() { run($arch, $binding, $program); } )+
    };
}
cases!("x86",
    x86_ucrt_null => ("ucrtbase", "register_zero"), x86_apiset_null => ("apiset", "register_zero"),
    x86_ucrt_growth65 => ("ucrtbase", "register_65"), x86_apiset_growth65 => ("apiset", "register_65"),
    x86_ucrt_growth1057 => ("ucrtbase", "register_1057"), x86_apiset_growth1057 => ("apiset", "register_1057"),
    x86_ucrt_recursive => ("ucrtbase", "explicit"), x86_apiset_recursive => ("apiset", "explicit"),
    x86_ucrt_concurrent => ("ucrtbase", "concurrent"), x86_apiset_concurrent => ("apiset", "concurrent"),
);
cases!("x64",
    x64_ucrt_null => ("ucrtbase", "register_zero"), x64_apiset_null => ("apiset", "register_zero"),
    x64_ucrt_growth65 => ("ucrtbase", "register_65"), x64_apiset_growth65 => ("apiset", "register_65"),
    x64_ucrt_growth1057 => ("ucrtbase", "register_1057"), x64_apiset_growth1057 => ("apiset", "register_1057"),
    x64_ucrt_recursive => ("ucrtbase", "explicit"), x64_apiset_recursive => ("apiset", "explicit"),
    x64_ucrt_concurrent => ("ucrtbase", "concurrent"), x64_apiset_concurrent => ("apiset", "concurrent"),
);
cases!("arm64",
    arm64_ucrt_null => ("ucrtbase", "register_zero"), arm64_apiset_null => ("apiset", "register_zero"),
    arm64_ucrt_growth65 => ("ucrtbase", "register_65"), arm64_apiset_growth65 => ("apiset", "register_65"),
    arm64_ucrt_growth1057 => ("ucrtbase", "register_1057"), arm64_apiset_growth1057 => ("apiset", "register_1057"),
    arm64_ucrt_recursive => ("ucrtbase", "explicit"), arm64_apiset_recursive => ("apiset", "explicit"),
    arm64_ucrt_concurrent => ("ucrtbase", "concurrent"), arm64_apiset_concurrent => ("apiset", "concurrent"),
);

fn physical(base: &Path) -> BTreeSet<String> {
    fn visit(base: &Path, directory: &Path, files: &mut BTreeSet<String>) {
        for entry in std::fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let kind = entry.file_type().unwrap();
            if kind.is_dir() {
                visit(base, &entry.path(), files);
            } else {
                assert!(kind.is_file(), "no symlinks in fixture inventory");
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
    let mut result = BTreeSet::new();
    visit(base, base, &mut result);
    result
}

fn import_set(image: &PeImage) -> BTreeSet<(String, String)> {
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

fn expected_imports(binding: &str, program: &str) -> BTreeSet<(String, String)> {
    let dll = if binding == "apiset" {
        "api-ms-win-crt-runtime-l1-1-0.dll"
    } else {
        "ucrtbase.dll"
    };
    let mut result = BTreeSet::new();
    for symbol in ["_crt_atexit", "_crt_at_quick_exit"] {
        result.insert((dll.into(), symbol.into()));
    }
    if ["explicit", "concurrent"].contains(&program) {
        for symbol in [
            "_initialize_onexit_table",
            "_register_onexit_function",
            "_execute_onexit_table",
        ] {
            result.insert((dll.into(), symbol.into()));
        }
    }
    for symbol in ["ExitProcess", "GetStdHandle", "WriteFile"] {
        result.insert(("kernel32.dll".into(), symbol.into()));
    }
    if program == "concurrent" {
        for symbol in [
            "CreateEventW",
            "CreateThread",
            "SetEvent",
            "WaitForSingleObject",
            "Sleep",
            "GetExitCodeThread",
            "CloseHandle",
        ] {
            result.insert(("kernel32.dll".into(), symbol.into()));
        }
    }
    result
}

#[test]
fn source_artifact_binding_matrix_and_baseline_receipts_are_verified() {
    let bytes = std::fs::read(root().join("manifest.json")).unwrap();
    let manifest: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(manifest["source_baseline"], BASELINE);
    for source in manifest["sources"].as_array().unwrap() {
        let data = std::fs::read(root().join(source["path"].as_str().unwrap())).unwrap();
        assert_eq!(data.len() as u64, source["bytes"].as_u64().unwrap());
        assert_eq!(
            super::sha256::hex(&data),
            source["sha256"].as_str().unwrap()
        );
    }
    let mut declared = BTreeMap::new();
    let mut matrix = BTreeSet::new();
    let mut observations = BTreeSet::new();
    for entry in manifest["fixtures"].as_array().unwrap() {
        let arch = entry["arch"].as_str().unwrap();
        let binding = entry["binding"].as_str().unwrap();
        let program = entry["program"].as_str().unwrap();
        assert!(
            ARCHES.contains(&arch) && BINDINGS.contains(&binding) && PROGRAMS.contains(&program)
        );
        assert!(matrix.insert((arch, binding, program)));
        let path = entry["path"].as_str().unwrap();
        assert_eq!(path, format!("bin/{arch}/{binding}/{program}.exe"));
        let data = std::fs::read(root().join(path)).unwrap();
        let hash = super::sha256::hex(&data);
        assert_eq!(hash, entry["sha256"].as_str().unwrap());
        assert_eq!(data.len() as u64, entry["bytes"].as_u64().unwrap());
        assert!(declared.insert(path, hash).is_none());
        assert_eq!(entry["expected_exit"], 0);
        assert_eq!(
            entry["expected_stdout"].as_str().unwrap().as_bytes(),
            stdout(program)
        );
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
        let actual = import_set(&image);
        assert_eq!(actual, expected_imports(binding, program), "{path}");
        let mut recorded = BTreeSet::new();
        for dll in entry["imports"].as_array().unwrap() {
            for symbol in dll["symbols"].as_array().unwrap() {
                assert!(recorded.insert((
                    dll["dll"].as_str().unwrap().to_ascii_lowercase(),
                    symbol.as_str().unwrap().into()
                )));
            }
        }
        assert_eq!(recorded, actual);
        let iat = entry["iat_path"].as_str().unwrap();
        let data = std::fs::read(root().join(iat)).unwrap();
        assert_eq!(
            super::sha256::hex(&data),
            entry["iat_sha256"].as_str().unwrap()
        );
        assert!(observations.insert(iat.strip_prefix("observations/").unwrap().into()));
        let mut dll = "";
        let mut readobj = BTreeSet::new();
        for line in std::str::from_utf8(&data).unwrap().lines().map(str::trim) {
            if let Some(name) = line.strip_prefix("Name: ") {
                dll = name;
            } else if let Some(symbol) = line.strip_prefix("Symbol: ") {
                assert!(readobj.insert((
                    dll.to_ascii_lowercase(),
                    symbol.rsplit_once(" (").unwrap().0.into()
                )));
            }
        }
        assert_eq!(readobj, actual);
    }
    assert_eq!(matrix.len(), 30);
    assert_eq!(
        physical(&root().join("bin")),
        declared
            .keys()
            .map(|path| path.strip_prefix("bin/").unwrap().into())
            .collect()
    );
    assert_eq!(physical(&root().join("observations")), observations);
    let baseline: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root().join("baseline.json")).unwrap()).unwrap();
    assert_eq!(baseline["source_baseline"], BASELINE);
    assert_eq!(baseline["executable_sha256"], BASELINE_CLI_SHA);
    assert_eq!(
        baseline["fixture_manifest_sha256"],
        super::sha256::hex(&bytes)
    );
    assert_eq!(baseline["seed"], 1);
    assert_eq!(baseline["arena_bytes"], 67108864);
    assert_eq!(baseline["watchdog_seconds"], 30);
    assert_eq!(baseline["environment"]["RAX_NO_JIT"], "1");
    let runs = baseline["runs"].as_array().unwrap();
    assert_eq!(runs.len(), 60);
    let mut receipts = BTreeSet::new();
    for entry in runs {
        let path = entry["path"].as_str().unwrap();
        assert_eq!(entry["input_sha256"].as_str().unwrap(), declared[path]);
        let slice = entry["slice_instructions"].as_u64().unwrap();
        assert!([1, 4096].contains(&slice));
        assert!(receipts.insert((path, slice)));
        assert_eq!(entry["shell_exit"], 125);
        assert_eq!(entry["stdout"], "");
        assert_eq!(entry["missing_export"], "_crt_atexit");
        assert!(
            entry["stderr"]
                .as_str()
                .unwrap()
                .contains("unimplemented Windows export: ucrtbase.dll!_crt_atexit")
        );
    }
}
