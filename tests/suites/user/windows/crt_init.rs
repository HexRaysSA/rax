//! Compiler-produced constructor tables with custom entry points, not CRT startup.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use rax::user::image::pe::{PeImage, RvaSource, dir, exports, imports};
use rax::user::windows::WinArch;

const PROGRAMS: [&str; 4] = ["traverse", "errors", "terminal", "repair"];
const BINDINGS: [&str; 3] = ["msvcrt", "ucrtbase", "apiset"];
const ARCHES: [&str; 3] = ["x86", "x64", "arm64"];

fn root() -> PathBuf {
    super::fixtures().join("crt_init")
}

fn admitted(arch: &str, binding: &str, program: &str) -> bool {
    program != "errors" || binding != "msvcrt" || arch == "arm64"
}

struct Bundle {
    directory: PathBuf,
    image: PathBuf,
}

impl Bundle {
    fn new(arch: &str, binding: &str, program: &str, slice: &str) -> Self {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "rax-windows-crt-init-{}-{arch}-{binding}-{program}-{slice}-{stamp}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).unwrap();
        let image = directory.join(format!("{program}.exe"));
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
    assert!(
        admitted(arch, binding, program),
        "the matrix does not self-skip"
    );
    let image = root().join(format!("bin/{arch}/{binding}/{program}.exe"));
    let original = std::fs::read(&image).unwrap();
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
                bundle.image.to_str().unwrap(),
            ],
            &[("RAX_NO_JIT", "1")],
            None,
            std::time::Duration::from_secs(30),
        );
        let expected = if program == "terminal" { 42 } else { 0 };
        assert_eq!(
            output.status,
            Some(expected),
            "{arch} {binding} {program} slice={slice}: stderr={:?}, stdout={:?}, signal={:?}",
            output.stderr,
            output.stdout,
            output.signal
        );
        assert_eq!(
            std::fs::read(&bundle.image).unwrap(),
            original,
            "fixture input is immutable"
        );
    }
}

macro_rules! cases {
    ($arch:literal, $( $name:ident => ($binding:literal, $program:literal) ),+ $(,)?) => {
        $( #[test] fn $name() { run($arch, $binding, $program); } )+
    };
}

cases!("x86",
    x86_msvcrt_order_null_nested_mutation_cdecl => ("msvcrt", "traverse"),
    x86_ucrt_order_null_nested_mutation_cdecl => ("ucrtbase", "traverse"),
    x86_apiset_order_null_nested_mutation_cdecl => ("apiset", "traverse"),
    x86_ucrt_first_positive_negative_error_and_success => ("ucrtbase", "errors"),
    x86_apiset_first_positive_negative_error_and_success => ("apiset", "errors"),
    x86_msvcrt_callback_terminates_without_resume => ("msvcrt", "terminal"),
    x86_ucrt_callback_terminates_without_resume => ("ucrtbase", "terminal"),
    x86_apiset_callback_terminates_without_resume => ("apiset", "terminal"),
    x86_msvcrt_noaccess_guard_slot_repair_once => ("msvcrt", "repair"),
    x86_ucrt_noaccess_guard_slot_repair_once => ("ucrtbase", "repair"),
    x86_apiset_noaccess_guard_slot_repair_once => ("apiset", "repair"),
);
cases!("x64",
    x64_msvcrt_order_null_nested_mutation_cdecl => ("msvcrt", "traverse"),
    x64_ucrt_order_null_nested_mutation_cdecl => ("ucrtbase", "traverse"),
    x64_apiset_order_null_nested_mutation_cdecl => ("apiset", "traverse"),
    x64_ucrt_first_positive_negative_error_and_success => ("ucrtbase", "errors"),
    x64_apiset_first_positive_negative_error_and_success => ("apiset", "errors"),
    x64_msvcrt_callback_terminates_without_resume => ("msvcrt", "terminal"),
    x64_ucrt_callback_terminates_without_resume => ("ucrtbase", "terminal"),
    x64_apiset_callback_terminates_without_resume => ("apiset", "terminal"),
    x64_msvcrt_noaccess_guard_slot_repair_once => ("msvcrt", "repair"),
    x64_ucrt_noaccess_guard_slot_repair_once => ("ucrtbase", "repair"),
    x64_apiset_noaccess_guard_slot_repair_once => ("apiset", "repair"),
);
cases!("arm64",
    arm64_msvcrt_order_null_nested_mutation_cdecl => ("msvcrt", "traverse"),
    arm64_ucrt_order_null_nested_mutation_cdecl => ("ucrtbase", "traverse"),
    arm64_apiset_order_null_nested_mutation_cdecl => ("apiset", "traverse"),
    arm64_msvcrt_first_positive_negative_error_and_success => ("msvcrt", "errors"),
    arm64_ucrt_first_positive_negative_error_and_success => ("ucrtbase", "errors"),
    arm64_apiset_first_positive_negative_error_and_success => ("apiset", "errors"),
    arm64_msvcrt_callback_terminates_without_resume => ("msvcrt", "terminal"),
    arm64_ucrt_callback_terminates_without_resume => ("ucrtbase", "terminal"),
    arm64_apiset_callback_terminates_without_resume => ("apiset", "terminal"),
    arm64_msvcrt_noaccess_guard_slot_repair_once => ("msvcrt", "repair"),
    arm64_ucrt_noaccess_guard_slot_repair_once => ("ucrtbase", "repair"),
    arm64_apiset_noaccess_guard_slot_repair_once => ("apiset", "repair"),
);

#[test]
fn constructor_fixture_sources_tables_iats_and_matrix_are_verified() {
    let manifest: toml::Value =
        toml::from_str(&std::fs::read_to_string(root().join("manifest.toml")).unwrap()).unwrap();
    let sources = manifest["source"].as_array().unwrap();
    let expected_sources = BTreeSet::from([
        "build.sh",
        "baseline.sh",
        "src/common.h",
        "src/abi.S",
        "src/traverse.c",
        "src/errors.c",
        "src/terminal.c",
        "src/repair.c",
        "src/kernel32.def",
        "src/kernel32-x86.def",
        "src/runtime.def",
        "src/runtime-ucrt.def",
        "src/heap.def",
        "src/string.def",
    ]);
    assert_eq!(sources.len(), expected_sources.len());
    let mut actual_sources = BTreeSet::new();
    for source in sources {
        let path = source["path"].as_str().unwrap();
        assert!(actual_sources.insert(path), "duplicate source {path}");
        assert_eq!(
            super::sha256::hex(&std::fs::read(root().join(path)).unwrap()),
            source["sha256"].as_str().unwrap(),
            "{path}"
        );
    }
    assert_eq!(actual_sources, expected_sources);
    let entries = manifest["fixture"].as_array().unwrap();
    assert_eq!(entries.len(), 34);
    let mut found = BTreeSet::new();
    for entry in entries {
        let path = entry["path"].as_str().unwrap();
        let arch = entry["arch"].as_str().unwrap();
        let binding = entry["binding"].as_str().unwrap();
        assert!(ARCHES.contains(&arch) && BINDINGS.contains(&binding));
        let program = path
            .strip_prefix(&format!("bin/{arch}/{binding}/"))
            .unwrap()
            .strip_suffix(".exe")
            .unwrap();
        assert!(PROGRAMS.contains(&program) && admitted(arch, binding, program));
        assert!(
            found.insert((arch, binding, program)),
            "duplicate fixture {path}"
        );
        assert_eq!(
            entry["expected_exit"].as_integer().unwrap(),
            if program == "terminal" { 42 } else { 0 }
        );
        let bytes = std::fs::read(root().join(path)).unwrap();
        assert_eq!(bytes.len() as i64, entry["bytes"].as_integer().unwrap());
        assert_eq!(
            super::sha256::hex(&bytes),
            entry["sha256"].as_str().unwrap()
        );
        let pe = PeImage::parse(bytes).unwrap();
        let expected_arch = match arch {
            "x86" => WinArch::X86,
            "x64" => WinArch::X64,
            _ => WinArch::Arm64,
        };
        assert_eq!(
            WinArch::from_machine(pe.headers().machine),
            Some(expected_arch)
        );
        assert_eq!(pe.headers().time_date_stamp, 0);
        assert_ne!(pe.headers().entry_rva, 0);
        let image = pe.memory_image();
        let mut actual = BTreeSet::new();
        let descriptors =
            imports::descriptors(&image, pe.headers().directory(dir::IMPORT)).unwrap();
        for descriptor in descriptors {
            let dll = String::from_utf8(descriptor.dll_name(&image).unwrap())
                .unwrap()
                .to_ascii_lowercase();
            for thunk in descriptor.thunks(&image, pe.headers().kind).unwrap() {
                let imports::ImportRef::Name { name, .. } = thunk.symbol else {
                    panic!("{path}: ordinal import");
                };
                assert!(
                    actual.insert((dll.clone(), String::from_utf8(name).unwrap())),
                    "{path}: duplicate IAT"
                );
            }
        }
        let runtime = if binding == "apiset" {
            "api-ms-win-crt-runtime-l1-1-0.dll".into()
        } else {
            format!("{binding}.dll")
        };
        let heap = if binding == "apiset" {
            "api-ms-win-crt-heap-l1-1-0.dll".into()
        } else {
            format!("{binding}.dll")
        };
        let string = if binding == "apiset" {
            "api-ms-win-crt-string-l1-1-0.dll".into()
        } else {
            format!("{binding}.dll")
        };
        let mut expected = BTreeSet::from([
            ("kernel32.dll".to_owned(), "ExitProcess".to_owned()),
            (runtime.clone(), "_initterm".to_owned()),
        ]);
        if program == "errors" {
            expected.insert((runtime, "_initterm_e".into()));
        }
        if matches!(program, "traverse" | "errors") {
            expected.insert((heap.clone(), "malloc".into()));
            expected.insert((heap, "free".into()));
        }
        if program == "traverse" {
            expected.insert((string, "strlen".into()));
        }
        if program == "repair" {
            for name in [
                "VirtualAlloc",
                "VirtualFree",
                "VirtualProtect",
                "AddVectoredExceptionHandler",
                "RemoveVectoredExceptionHandler",
            ] {
                expected.insert(("kernel32.dll".into(), name.into()));
            }
        }
        assert_eq!(
            actual, expected,
            "{path}: exact genuine named-import binding"
        );
        if program != "repair" {
            let export =
                exports::ExportDirectory::read(&image, pe.headers().directory(dir::EXPORT))
                    .unwrap()
                    .unwrap();
            let (_, exports::ExportTarget::Rva(bounds)) = export
                .by_name(&image, b"fixture_bounds", None)
                .unwrap()
                .unwrap()
            else {
                panic!("{path}: bounds is not a data RVA");
            };
            let width = if arch == "x86" { 4_u64 } else { 8 };
            let pointer = |at| {
                if width == 4 {
                    u64::from(image.u32_at(at).unwrap())
                } else {
                    image.u64_at(at).unwrap()
                }
            };
            let begin = pointer(u64::from(bounds))
                .checked_sub(pe.headers().image_base)
                .unwrap();
            let end = pointer(u64::from(bounds) + width)
                .checked_sub(pe.headers().image_base)
                .unwrap();
            let slots = match program {
                "traverse" => 7,
                "errors" => 5,
                _ => 3,
            };
            assert_eq!(
                end - begin,
                slots * width,
                "{path}: compiler/linker ordered table"
            );
            assert_eq!(pointer(begin), 0, "{path}: NULL starting sentinel");
            assert_ne!(pointer(end), 0, "{path}: non-NULL exclusive-end tripwire");
            if program != "terminal" {
                assert_eq!(pointer(begin + 2 * width), 0, "{path}: internal NULL slot");
            }
            let section = pe
                .sections()
                .iter()
                .find(|section| section.name_str() == ".CRT")
                .expect("compiler-produced .CRT section");
            assert!(
                begin >= u64::from(section.virtual_address)
                    && end + width
                        <= u64::from(section.virtual_address) + u64::from(section.virtual_size)
            );
            assert_eq!(
                section.characteristics & 0xe000_0000,
                0xc000_0000,
                "{path}: mutable data, not executable table"
            );
        }
    }
    for arch in ARCHES {
        for binding in BINDINGS {
            for program in PROGRAMS {
                assert_eq!(
                    found.contains(&(arch, binding, program)),
                    admitted(arch, binding, program)
                );
            }
        }
    }
    let baseline: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root().join("baseline.json")).unwrap()).unwrap();
    assert_eq!(
        baseline["source_baseline"],
        "b7498e58030bc0317cfa96845b509c9335c8fb30"
    );
    assert_eq!(
        baseline["executable_sha256"],
        "8ab3fbeafd5f8cf379fcdf0f826ffd89eb573a3db00c97558df151c278253fc5"
    );
    assert_eq!(
        baseline["fixture_manifest_sha256"].as_str().unwrap(),
        super::sha256::hex(&std::fs::read(root().join("manifest.toml")).unwrap())
    );
    assert_eq!(baseline["seed"], 1);
    assert_eq!(baseline["arena_bytes"], 67108864);
    assert_eq!(baseline["watchdog_seconds"], 30);
    assert_eq!(baseline["environment"]["RAX_NO_JIT"], "1");
    let declared: BTreeMap<_, _> = entries
        .iter()
        .map(|entry| {
            (
                entry["path"].as_str().unwrap(),
                (
                    entry["arch"].as_str().unwrap(),
                    entry["binding"].as_str().unwrap(),
                    entry["sha256"].as_str().unwrap(),
                ),
            )
        })
        .collect();
    let runs = baseline["runs"].as_array().unwrap();
    assert_eq!(runs.len(), 68);
    let mut observed = BTreeSet::new();
    for run in runs {
        let path = run["path"].as_str().unwrap();
        let &(arch, binding, hash) = declared.get(path).unwrap();
        let slice = run["slice_instructions"].as_u64().unwrap();
        assert!(matches!(slice, 1 | 4096));
        assert!(
            observed.insert((path, slice)),
            "duplicate baseline observation"
        );
        assert_eq!(run["arch"], arch);
        assert_eq!(run["binding"], binding);
        assert_eq!(run["input_sha256"], hash);
        assert_eq!(run["shell_exit"], 125);
        assert!(run["status"].is_null());
        assert_eq!(run["failure_class"], "unimplemented Windows export");
        assert!(
            run["stderr"]
                .as_str()
                .unwrap()
                .contains("unimplemented Windows export:")
        );
        let program = PathBuf::from(path)
            .file_stem()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let export = if program == "errors" {
            "_initterm_e"
        } else {
            "_initterm"
        };
        assert_eq!(run["missing_export"], export);
        assert!(
            run["stderr"]
                .as_str()
                .unwrap()
                .contains(&format!("!{export} at "))
        );
        let arguments: Vec<_> = run["arguments"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(arguments.len(), 13);
        assert_eq!(
            &arguments[..5],
            ["--os", "windows", "--memory", "64M", "--drive"]
        );
        assert_eq!(&arguments[6..9], ["--cwd", "C:\\", "--slice"]);
        assert_eq!(arguments[9], slice.to_string());
        assert_eq!(&arguments[10..12], ["--seed", "1"]);
        let copied = PathBuf::from(arguments[12]);
        assert_eq!(
            copied.file_name().unwrap(),
            PathBuf::from(path).file_name().unwrap()
        );
        assert_eq!(
            arguments[5],
            format!("C={}", copied.parent().unwrap().display())
        );
    }
    assert_eq!(observed.len(), declared.len() * 2);
}

#[test]
fn constructor_retained_primary_semantics_and_abi_provenance_are_verified() {
    let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for manifest_path in [
        "docs/specifications/windows/crt-initializers/sources.json",
        "tests/fixtures/user/windows/crt/manifest-abi.json",
    ] {
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(repository.join(manifest_path)).unwrap())
                .unwrap();
        let entries = manifest["sources"].as_array().unwrap();
        assert!(!entries.is_empty());
        let source_base = if manifest_path.starts_with("docs/") {
            repository
                .join(manifest_path)
                .parent()
                .unwrap()
                .to_path_buf()
        } else {
            repository.clone()
        };
        let mut seen = BTreeSet::new();
        for entry in entries {
            let path = entry["path"].as_str().unwrap();
            assert!(seen.insert(path));
            assert!(
                !PathBuf::from(path).is_absolute(),
                "retained repository-relative primary source"
            );
            assert!(source_base.join(path).starts_with(repository.join("docs")));
            assert_eq!(
                super::sha256::hex(&std::fs::read(source_base.join(path)).unwrap()),
                entry["sha256"].as_str().unwrap(),
                "{path}"
            );
        }
    }
}
