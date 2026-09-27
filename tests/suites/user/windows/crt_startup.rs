//! Custom-entry argv/environment PE probes, not ordinary compiler CRT startup.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use rax::user::image::pe::{PeImage, dir, imports};
use rax::user::windows::WinArch;

const ARCHES: [&str; 3] = ["x86", "x64", "arm64"];
const BINDINGS: [&str; 3] = ["msvcrt", "ucrtbase", "apiset"];
const PROGRAMS: [&str; 6] = [
    "arguments",
    "environment",
    "wildcards",
    "newmode",
    "modes",
    "isolation",
];
const RAW_ARGUMENTS: &str =
    r#""C:\Program Files\probe.exe" "" "ab\"c" a\\\b d"e f"g "café" ＂x y＂"#;
const RAW_WILDCARDS: &str = r#"probe *.txt "*.txt" *.* sub\?.bin absent*.q ??.dat"#;
const POPULATED_ENV: [&str; 5] = [
    "Alpha=one",
    "Beta=two",
    "Mixed=café",
    "alpha=last",
    "EMPTY=",
];
const WILDCARD_INPUTS: [(&str, &[u8]); 7] = [
    ("alpha.txt", b"alpha"),
    ("beta.txt", b"beta"),
    ("README", b"extensionless"),
    ("aa.dat", b"aa"),
    ("bb.dat", b"bb"),
    ("sub/q.bin", b"q"),
    ("sub/qq.bin", b"qq"),
];

fn root() -> PathBuf {
    super::fixtures().join("crt_startup")
}

fn admitted(binding: &str, program: &str) -> bool {
    (program != "modes" || binding != "msvcrt") && (program != "isolation" || binding == "ucrtbase")
}

fn scenarios(program: &str) -> &'static [&'static str] {
    if program == "environment" {
        &["populated", "empty"]
    } else {
        &["default"]
    }
}

fn command_line(program: &str, scenario: &str) -> &'static str {
    match (program, scenario) {
        ("arguments", "default") => RAW_ARGUMENTS,
        ("environment", "populated") => "probe environment",
        ("environment", "empty") => "probe empty",
        ("wildcards", "default") => RAW_WILDCARDS,
        ("newmode", "default") => "probe",
        ("modes" | "isolation", "default") => "probe one two",
        _ => panic!("unregistered scenario: {program}/{scenario}"),
    }
}

fn guest_cwd(program: &str) -> &'static str {
    if program == "wildcards" {
        "C:\\work"
    } else {
        "C:\\"
    }
}

struct Bundle {
    directory: PathBuf,
    image: PathBuf,
    wildcard: bool,
}

impl Bundle {
    fn new(arch: &str, binding: &str, program: &str, scenario: &str, slice: &str) -> Self {
        static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let sequence = SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "rax-crt-startup-{}-{arch}-{binding}-{program}-{scenario}-{slice}-{stamp}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).unwrap();
        let image = directory.join(format!("{program}.exe"));
        std::fs::copy(
            root().join(format!("bin/{arch}/{binding}/{program}.exe")),
            &image,
        )
        .unwrap();
        let wildcard = program == "wildcards";
        if wildcard {
            std::fs::create_dir(directory.join("work")).unwrap();
            std::fs::create_dir(directory.join("work/sub")).unwrap();
            for (name, data) in WILDCARD_INPUTS {
                std::fs::write(directory.join("work").join(name), data).unwrap();
            }
        }
        Self {
            directory,
            image,
            wildcard,
        }
    }

    fn verify_inputs(&self, original: &[u8]) {
        assert_eq!(std::fs::read(&self.image).unwrap(), original);
        let names = |directory: PathBuf| -> BTreeSet<String> {
            std::fs::read_dir(directory)
                .unwrap()
                .map(|entry| entry.unwrap().file_name().into_string().unwrap())
                .collect()
        };
        let mut expected_root =
            BTreeSet::from([self.image.file_name().unwrap().to_str().unwrap().to_owned()]);
        if self.wildcard {
            expected_root.insert("work".to_owned());
            assert_eq!(
                names(self.directory.join("work")),
                BTreeSet::from([
                    "alpha.txt".into(),
                    "beta.txt".into(),
                    "README".into(),
                    "aa.dat".into(),
                    "bb.dat".into(),
                    "sub".into(),
                ])
            );
            assert_eq!(
                names(self.directory.join("work/sub")),
                BTreeSet::from(["q.bin".into(), "qq.bin".into()])
            );
            for (name, data) in WILDCARD_INPUTS {
                assert_eq!(
                    std::fs::read(self.directory.join("work").join(name)).unwrap(),
                    data,
                    "immutable wildcard input {name}"
                );
            }
        }
        assert_eq!(names(self.directory.clone()), expected_root);
    }
}

impl Drop for Bundle {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.image);
        if self.wildcard {
            for (name, _) in WILDCARD_INPUTS {
                let _ = std::fs::remove_file(self.directory.join("work").join(name));
            }
            let _ = std::fs::remove_dir(self.directory.join("work/sub"));
            let _ = std::fs::remove_dir(self.directory.join("work"));
        }
        let _ = std::fs::remove_dir(&self.directory);
    }
}

fn run(arch: &str, binding: &str, program: &str) {
    assert!(admitted(binding, program), "the matrix does not self-skip");
    let image = root().join(format!("bin/{arch}/{binding}/{program}.exe"));
    let original = std::fs::read(&image).unwrap();
    for &scenario in scenarios(program) {
        for slice in ["1", "4096"] {
            let bundle = Bundle::new(arch, binding, program, scenario, slice);
            let mut arguments = vec![
                "--os".to_owned(),
                "windows".into(),
                "--memory".into(),
                "64M".into(),
                "--drive".into(),
                format!("C={}", bundle.directory.display()),
                "--cwd".into(),
                guest_cwd(program).into(),
                "--slice".into(),
                slice.into(),
                "--seed".into(),
                "1".into(),
                "--clear-env".into(),
                "--command-line".into(),
                command_line(program, scenario).into(),
            ];
            if scenario == "populated" {
                for variable in POPULATED_ENV {
                    arguments.extend(["-E".into(), variable.into()]);
                }
            }
            arguments.push(bundle.image.to_str().unwrap().into());
            let refs: Vec<_> = arguments.iter().map(String::as_str).collect();
            let output = super::cli_support::run(
                &refs,
                &[("RAX_NO_JIT", "1")],
                None,
                std::time::Duration::from_secs(30),
            );
            assert_eq!(
                output.status,
                Some(0),
                "{arch} {binding} {program}/{scenario} slice={slice}: stderr={:?}, stdout={:?}, signal={:?}",
                output.stderr,
                output.stdout,
                output.signal
            );
            bundle.verify_inputs(&original);
        }
    }
}

macro_rules! cases {
    ($arch:literal, $( $name:ident => ($binding:literal, $program:literal) ),+ $(,)?) => {
        $( #[test] fn $name() { run($arch, $binding, $program); } )+
    };
}

cases!("x86",
    x86_msvcrt_raw_quotes_cp1252_data_and_idempotence => ("msvcrt", "arguments"),
    x86_ucrt_raw_quotes_cp1252_static_wrapper => ("ucrtbase", "arguments"),
    x86_apiset_raw_quotes_cp1252_static_wrapper => ("apiset", "arguments"),
    x86_msvcrt_current_initial_environment_and_empty => ("msvcrt", "environment"),
    x86_ucrt_current_initial_environment_and_empty => ("ucrtbase", "environment"),
    x86_apiset_current_initial_environment_and_empty => ("apiset", "environment"),
    x86_msvcrt_unexpanded_expanded_wildcards => ("msvcrt", "wildcards"),
    x86_ucrt_unexpanded_expanded_wildcards => ("ucrtbase", "wildcards"),
    x86_apiset_unexpanded_expanded_wildcards => ("apiset", "wildcards"),
    x86_msvcrt_newmode_getter_and_decorated_query => ("msvcrt", "newmode"),
    x86_ucrt_newmode_and_actual_wrapper => ("ucrtbase", "newmode"),
    x86_apiset_newmode_and_actual_wrapper => ("apiset", "newmode"),
    x86_ucrt_configure_modes_idempotence_invalid_callback => ("ucrtbase", "modes"),
    x86_apiset_configure_modes_idempotence_invalid_callback => ("apiset", "modes"),
    x86_legacy_universal_runtime_isolation => ("ucrtbase", "isolation"),
);
cases!("x64",
    x64_msvcrt_raw_quotes_cp1252_data_and_idempotence => ("msvcrt", "arguments"),
    x64_ucrt_raw_quotes_cp1252_static_wrapper => ("ucrtbase", "arguments"),
    x64_apiset_raw_quotes_cp1252_static_wrapper => ("apiset", "arguments"),
    x64_msvcrt_current_initial_environment_and_empty => ("msvcrt", "environment"),
    x64_ucrt_current_initial_environment_and_empty => ("ucrtbase", "environment"),
    x64_apiset_current_initial_environment_and_empty => ("apiset", "environment"),
    x64_msvcrt_unexpanded_expanded_wildcards => ("msvcrt", "wildcards"),
    x64_ucrt_unexpanded_expanded_wildcards => ("ucrtbase", "wildcards"),
    x64_apiset_unexpanded_expanded_wildcards => ("apiset", "wildcards"),
    x64_msvcrt_newmode_getter_and_decorated_query => ("msvcrt", "newmode"),
    x64_ucrt_newmode_and_actual_wrapper => ("ucrtbase", "newmode"),
    x64_apiset_newmode_and_actual_wrapper => ("apiset", "newmode"),
    x64_ucrt_configure_modes_idempotence_invalid_callback => ("ucrtbase", "modes"),
    x64_apiset_configure_modes_idempotence_invalid_callback => ("apiset", "modes"),
    x64_legacy_universal_runtime_isolation => ("ucrtbase", "isolation"),
);
cases!("arm64",
    arm64_msvcrt_raw_quotes_cp1252_data_and_idempotence => ("msvcrt", "arguments"),
    arm64_ucrt_raw_quotes_cp1252_static_wrapper => ("ucrtbase", "arguments"),
    arm64_apiset_raw_quotes_cp1252_static_wrapper => ("apiset", "arguments"),
    arm64_msvcrt_shared_environment_and_empty => ("msvcrt", "environment"),
    arm64_ucrt_current_initial_environment_and_empty => ("ucrtbase", "environment"),
    arm64_apiset_current_initial_environment_and_empty => ("apiset", "environment"),
    arm64_msvcrt_unexpanded_expanded_wildcards => ("msvcrt", "wildcards"),
    arm64_ucrt_unexpanded_expanded_wildcards => ("ucrtbase", "wildcards"),
    arm64_apiset_unexpanded_expanded_wildcards => ("apiset", "wildcards"),
    arm64_msvcrt_newmode_getter_without_missing_query => ("msvcrt", "newmode"),
    arm64_ucrt_newmode_and_actual_wrapper => ("ucrtbase", "newmode"),
    arm64_apiset_newmode_and_actual_wrapper => ("apiset", "newmode"),
    arm64_ucrt_configure_modes_idempotence_invalid_callback => ("ucrtbase", "modes"),
    arm64_apiset_configure_modes_idempotence_invalid_callback => ("apiset", "modes"),
    arm64_legacy_universal_runtime_isolation => ("ucrtbase", "isolation"),
);

fn expected_imports(arch: &str, binding: &str, program: &str) -> BTreeSet<(String, String)> {
    let dll = |group: &str| {
        if binding == "apiset" {
            format!("api-ms-win-crt-{group}-l1-1-0.dll")
        } else {
            format!("{binding}.dll")
        }
    };
    let mut expected = BTreeSet::from([("kernel32.dll".into(), "ExitProcess".into())]);
    let mut add = |group: &str, names: &[&str]| {
        for &name in names {
            assert!(expected.insert((dll(group), name.into())));
        }
    };
    if binding == "msvcrt" {
        add("runtime", &["__getmainargs", "__wgetmainargs"]);
        if program == "arguments" {
            add(
                "runtime",
                &[
                    "__argc", "__argv", "__wargv", "_acmdln", "_wcmdln", "_pgmptr", "_wpgmptr",
                ],
            );
            if arch == "x86" {
                add("runtime", &["__p___argc", "__p___argv", "__p___wargv"]);
            }
        }
        if program == "environment" && arch != "arm64" {
            add(
                "environment",
                &["_environ", "_wenviron", "__initenv", "__winitenv"],
            );
            if arch == "x86" {
                add(
                    "environment",
                    &[
                        "__p__environ",
                        "__p__wenviron",
                        "__p___initenv",
                        "__p___winitenv",
                    ],
                );
            }
        } else if program == "environment" {
            add("environment", &["_get_environ", "_get_wenviron"]);
        }
        if program == "newmode" {
            add("heap", &["?_set_new_mode@@YAHH@Z", "malloc", "free"]);
            if arch != "arm64" {
                add("heap", &["?_query_new_mode@@YAHXZ"]);
            }
        }
    } else if program == "isolation" {
        add(
            "runtime",
            &["__p___argc", "__p___argv", "_configure_narrow_argv"],
        );
        add("heap", &["_set_new_mode"]);
        expected.insert(("kernel32.dll".into(), "LoadLibraryA".into()));
        expected.insert(("kernel32.dll".into(), "GetProcAddress".into()));
    } else if program == "modes" {
        add(
            "runtime",
            &[
                "__p___argc",
                "__p___argv",
                "__p___wargv",
                "_configure_narrow_argv",
                "_configure_wide_argv",
                "_errno",
                "_set_invalid_parameter_handler",
            ],
        );
        add("heap", &["_set_new_mode", "_query_new_mode"]);
    } else {
        // These are leaves called by the actual retained static wrappers.
        add(
            "runtime",
            &[
                "__p___argc",
                "__p___argv",
                "__p___wargv",
                "_configure_narrow_argv",
                "_configure_wide_argv",
                "_initialize_narrow_environment",
                "_initialize_wide_environment",
            ],
        );
        add("environment", &["__p__environ", "__p__wenviron"]);
        add("heap", &["_set_new_mode"]);
        if program == "arguments" {
            add(
                "runtime",
                &[
                    "__p__acmdln",
                    "__p__wcmdln",
                    "__p__pgmptr",
                    "__p__wpgmptr",
                    "_get_pgmptr",
                    "_get_wpgmptr",
                    "_get_narrow_winmain_command_line",
                    "_get_wide_winmain_command_line",
                ],
            );
        }
        if program == "environment" {
            add(
                "runtime",
                &[
                    "_get_initial_narrow_environment",
                    "_get_initial_wide_environment",
                ],
            );
        }
        if program == "newmode" {
            add("heap", &["malloc", "free", "_query_new_mode"]);
        }
    }
    if (binding == "msvcrt" && program == "arguments") || program == "modes" {
        for name in [
            "VirtualProtect",
            "AddVectoredExceptionHandler",
            "RemoveVectoredExceptionHandler",
        ] {
            assert!(expected.insert(("kernel32.dll".into(), name.into())));
        }
        if binding == "msvcrt" {
            for name in ["VirtualAlloc", "VirtualFree"] {
                assert!(expected.insert(("kernel32.dll".into(), name.into())));
            }
        }
    }
    expected
}

#[test]
fn startup_fixture_sources_iats_and_baseline_are_verified() {
    let manifest_bytes = std::fs::read(root().join("manifest.toml")).unwrap();
    let manifest: toml::Value =
        toml::from_str(std::str::from_utf8(&manifest_bytes).unwrap()).unwrap();
    assert_eq!(manifest["zig"].as_str().unwrap(), "0.16.0");
    assert!(
        manifest["clang"]
            .as_str()
            .unwrap()
            .contains("b51054818b78dc395cd4d33f17cfb6e98a36a76d")
    );
    assert!(
        manifest["linker"]
            .as_str()
            .unwrap()
            .contains("b51054818b78dc395cd4d33f17cfb6e98a36a76d")
    );
    for (tool, expected) in [
        (
            "clang_sha256",
            "6acca6b9583c9270f8606d026bab0015a4f82affd5610606f97fef6e606bde00",
        ),
        (
            "linker_sha256",
            "82b087e1c9fccfbb7369363415bc37934dcf7b6fd33c0b6b7ea18f3c217399bd",
        ),
        (
            "dlltool_sha256",
            "36566071f789a6f966ba69b05b38570f840f4d15269b76407fed7bce5711e03d",
        ),
        (
            "zig_sha256",
            "8d295db7edd9c52c5e4e3294f00e848b618f4f517e49c928e9b3988f0c63a867",
        ),
    ] {
        assert_eq!(manifest[tool].as_str().unwrap(), expected);
    }
    let expected_sources = BTreeSet::from([
        "build.sh",
        "baseline.sh",
        "README.md",
        "src/common.h",
        "src/repair.h",
        "src/arguments.c",
        "src/environment.c",
        "src/wildcards.c",
        "src/newmode.c",
        "src/modes.c",
        "src/isolation.c",
        "src/kernel32.def",
        "src/kernel32-x86.def",
        "src/legacy-runtime.def",
        "src/legacy-env.def",
        "src/legacy-env-arm64.def",
        "src/legacy-accessors-x86.def",
        "src/legacy-new.def",
        "src/legacy-new-arm64.def",
        "src/runtime.def",
        "src/environment.def",
        "src/heap.def",
        "src/wrapper-headers/corecrt_startup.h",
        "src/wrapper-headers/internal.h",
        "src/wrapper-headers/stdlib.h",
        "src/wrapper-headers/new.h",
        "../layout/public.c",
        "../../../../../docs/specifications/windows/crt-initializers/zig/ucrt__getmainargs.c",
        "../../../../../docs/specifications/windows/crt-initializers/zig/ucrt__wgetmainargs.c",
    ]);
    let sources = manifest["source"].as_array().unwrap();
    assert_eq!(sources.len(), expected_sources.len());
    let mut seen_sources = BTreeSet::new();
    for source in sources {
        let path = source["path"].as_str().unwrap();
        assert!(seen_sources.insert(path));
        assert_eq!(
            super::sha256::hex(&std::fs::read(root().join(path)).unwrap()),
            source["sha256"].as_str().unwrap(),
            "{path}"
        );
    }
    assert_eq!(seen_sources, expected_sources);
    let entries = manifest["fixture"].as_array().unwrap();
    assert_eq!(entries.len(), 45);
    let mut declared = BTreeMap::new();
    let mut matrix = BTreeSet::new();
    for entry in entries {
        let path = entry["path"].as_str().unwrap();
        let arch = entry["arch"].as_str().unwrap();
        let binding = entry["binding"].as_str().unwrap();
        let program = entry["program"].as_str().unwrap();
        assert!(
            ARCHES.contains(&arch) && BINDINGS.contains(&binding) && PROGRAMS.contains(&program)
        );
        assert!(admitted(binding, program));
        assert_eq!(path, format!("bin/{arch}/{binding}/{program}.exe"));
        assert!(matrix.insert((arch, binding, program)));
        assert!(
            declared
                .insert(
                    path,
                    (arch, binding, program, entry["sha256"].as_str().unwrap())
                )
                .is_none()
        );
        assert_eq!(entry["expected_exit"].as_integer().unwrap(), 0);
        let bytes = std::fs::read(root().join(path)).unwrap();
        assert_eq!(bytes.len() as i64, entry["bytes"].as_integer().unwrap());
        assert_eq!(
            super::sha256::hex(&bytes),
            entry["sha256"].as_str().unwrap()
        );
        let image = PeImage::parse(bytes).unwrap();
        assert_eq!(
            WinArch::from_machine(image.headers().machine),
            Some(match arch {
                "x86" => WinArch::X86,
                "x64" => WinArch::X64,
                _ => WinArch::Arm64,
            })
        );
        assert_eq!(image.headers().time_date_stamp, 0);
        assert_ne!(image.headers().entry_rva, 0);
        assert_eq!(
            image.headers().characteristics & 0x2000,
            0,
            "executable, not DLL"
        );
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
                    panic!("ordinal import: {path}");
                };
                assert!(actual.insert((dll.clone(), String::from_utf8(name).unwrap())));
            }
        }
        assert_eq!(
            actual,
            expected_imports(arch, binding, program),
            "exact genuine named IATs: {path}"
        );
    }
    for arch in ARCHES {
        for binding in BINDINGS {
            for program in PROGRAMS {
                assert_eq!(
                    matrix.contains(&(arch, binding, program)),
                    admitted(binding, program)
                );
            }
        }
    }
    let baseline: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root().join("baseline.json")).unwrap()).unwrap();
    assert_eq!(
        baseline["source_baseline"],
        "0753ca1c0b769da93d24390d1f24c4aad070b9d2"
    );
    assert_eq!(
        baseline["executable_sha256"],
        "cb2fe8e1dc750165233922cf2712dac132cb42e127baf799d47322ac09d1f3ce"
    );
    assert_eq!(
        baseline["fixture_manifest_sha256"].as_str().unwrap(),
        super::sha256::hex(&manifest_bytes)
    );
    assert_eq!(baseline["seed"], 1);
    assert_eq!(baseline["arena_bytes"], 67108864);
    assert_eq!(baseline["watchdog_seconds"], 30);
    assert_eq!(baseline["environment"]["RAX_NO_JIT"], "1");
    let inputs = baseline["wildcard_inputs"].as_array().unwrap();
    assert_eq!(inputs.len(), WILDCARD_INPUTS.len());
    for (input, &(name, data)) in inputs.iter().zip(&WILDCARD_INPUTS) {
        assert_eq!(input["path"], name);
        assert_eq!(input["bytes"].as_u64().unwrap(), data.len() as u64);
        assert_eq!(input["sha256"], super::sha256::hex(data));
    }
    let runs = baseline["runs"].as_array().unwrap();
    assert_eq!(runs.len(), 108);
    let mut observed = BTreeSet::new();
    for run in runs {
        let path = run["path"].as_str().unwrap();
        let &(arch, binding, program, hash) = declared.get(path).unwrap();
        let scenario = run["scenario"].as_str().unwrap();
        let slice = run["slice_instructions"].as_u64().unwrap();
        assert!(scenarios(program).contains(&scenario) && matches!(slice, 1 | 4096));
        assert!(observed.insert((path, scenario, slice)));
        assert_eq!(run["arch"], arch);
        assert_eq!(run["binding"], binding);
        assert_eq!(run["program"], program);
        assert_eq!(run["input_sha256"], hash);
        assert_eq!(run["raw_command_line"], command_line(program, scenario));
        assert_eq!(run["shell_exit"], 125);
        assert!(run["status"].is_null());
        assert_eq!(run["failure_class"], "unimplemented Windows export");
        let missing = match (binding, program) {
            ("msvcrt", "newmode") => "?_set_new_mode@@YAHH@Z",
            ("msvcrt", _) => "__getmainargs",
            (_, "newmode") => "_set_new_mode",
            (_, "modes" | "isolation") => "_configure_narrow_argv",
            _ => "_initialize_narrow_environment",
        };
        assert_eq!(run["missing_export"], missing);
        assert_eq!(
            run["missing_dll"],
            if binding == "msvcrt" {
                "msvcrt.dll"
            } else {
                "ucrtbase.dll"
            }
        );
        let stderr = run["stderr"].as_str().unwrap();
        assert!(stderr.contains(&format!(
            "unimplemented Windows export: {}!{missing} at ",
            run["missing_dll"].as_str().unwrap()
        )));
        let arguments: Vec<_> = run["arguments"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect();
        assert_eq!(
            &arguments[..5],
            ["--os", "windows", "--memory", "64M", "--drive"]
        );
        assert_eq!(&arguments[6..9], ["--cwd", guest_cwd(program), "--slice"]);
        assert_eq!(arguments[9], slice.to_string());
        assert_eq!(
            &arguments[10..15],
            [
                "--seed",
                "1",
                "--clear-env",
                "--command-line",
                command_line(program, scenario)
            ]
        );
        let suffix: Vec<_> = if scenario == "populated" {
            POPULATED_ENV
                .into_iter()
                .flat_map(|value| ["-E", value])
                .collect()
        } else {
            Vec::new()
        };
        assert_eq!(arguments.len(), 16 + suffix.len());
        assert_eq!(&arguments[15..arguments.len() - 1], suffix.as_slice());
        let copied = PathBuf::from(arguments.last().unwrap());
        assert_eq!(
            copied.file_name().unwrap().to_str().unwrap(),
            format!("{program}.exe")
        );
        assert_eq!(
            arguments[5],
            format!("C={}", copied.parent().unwrap().display())
        );
    }
    assert_eq!(observed.len(), 108);
}

#[test]
fn startup_retained_primary_sources_are_verified() {
    let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let source_base = repository.join("docs/specifications/windows/crt-startup");
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(source_base.join("sources.json")).unwrap()).unwrap();
    let entries = manifest["sources"].as_array().unwrap();
    assert_eq!(entries.len(), 60);
    let mut seen = BTreeSet::new();
    for entry in entries {
        let path = entry["path"].as_str().unwrap();
        assert!(seen.insert(path));
        assert!(!PathBuf::from(path).is_absolute());
        let resolved = source_base.join(path).canonicalize().unwrap();
        assert!(resolved.starts_with(repository.join("docs")));
        assert_eq!(
            super::sha256::hex(&std::fs::read(resolved).unwrap()),
            entry["sha256"].as_str().unwrap(),
            "{path}"
        );
    }
    assert!(seen.contains("mingw14/winnt-exception-context-excerpt.h"));
    assert!(seen.contains("zig/winnt-exception-context-excerpt.h"));
}
