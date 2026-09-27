//! Actual custom-entry CRT PE inputs; not ordinary CRT startup or native Windows oracle.

use std::collections::BTreeSet;
use std::path::PathBuf;

use rax::user::image::pe::{PeImage, dir, imports};
use rax::user::windows::WinArch;

const PROGRAMS: [&str; 5] = ["foundation", "errno", "module", "invalid", "fatal"];
const BINDINGS: [&str; 3] = ["msvcrt", "ucrtbase", "apiset"];
const FATAL_STATUS: u32 = 0xc000_0409;

fn root() -> PathBuf {
    super::fixtures().join("crt")
}

fn admitted(binding: &str, program: &str) -> bool {
    binding != "msvcrt" || !matches!(program, "invalid" | "fatal")
}

struct Bundle {
    directory: PathBuf,
    names: Vec<String>,
}

impl Bundle {
    fn new(arch: &str, binding: &str, program: &str, slice: &str) -> Self {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "rax-windows-crt-{}-{arch}-{binding}-{program}-{slice}-{stamp}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).unwrap();
        let mut names = Vec::new();
        for name in PROGRAMS.into_iter().filter(|name| admitted(binding, name)) {
            std::fs::copy(
                root().join(format!("bin/{arch}/{binding}/{name}.exe")),
                directory.join(format!("{name}.exe")),
            )
            .unwrap();
            names.push(format!("{name}.exe"));
        }
        Self { directory, names }
    }
}

impl Drop for Bundle {
    fn drop(&mut self) {
        for name in &self.names {
            let _ = std::fs::remove_file(self.directory.join(name));
        }
        let _ = std::fs::remove_dir(&self.directory);
    }
}

fn run(arch: &str, binding: &str, program: &str) {
    assert!(admitted(binding, program), "the matrix does not self-skip");
    for slice in ["1", "4096"] {
        let bundle = Bundle::new(arch, binding, program, slice);
        let image = bundle.directory.join(format!("{program}.exe"));
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
                image.to_str().unwrap(),
            ],
            &[("RAX_NO_JIT", "1")],
            None,
            std::time::Duration::from_secs(30),
        );
        let expected = if program == "fatal" { 9 } else { 0 };
        assert_eq!(
            output.status,
            Some(expected),
            "{arch} {binding} {program} slice={slice}: stderr={:?}, stdout={:?}, signal={:?}",
            output.stderr,
            output.stdout,
            output.signal
        );
        if program == "fatal" {
            assert!(
                output.stderr.contains("0xc0000409"),
                "full configured NTSTATUS, not merely an 8-bit shell code: {:?}",
                output.stderr
            );
        }
        for name in &bundle.names {
            assert_eq!(
                std::fs::read(bundle.directory.join(name)).unwrap(),
                std::fs::read(root().join(format!("bin/{arch}/{binding}/{name}"))).unwrap(),
                "{arch} {binding} {program} must not modify fixture inputs"
            );
        }
    }
}

macro_rules! cases {
    ($arch:literal, $( $name:ident => ($binding:literal, $program:literal) ),+ $(,)?) => {
        $(
            #[test]
            fn $name() { run($arch, $binding, $program); }
        )+
    };
}

cases!("x86",
    x86_msvcrt_alloc_memory_byte_utf16_strings => ("msvcrt", "foundation"),
    x86_ucrtbase_alloc_memory_byte_utf16_strings => ("ucrtbase", "foundation"),
    x86_apisets_vcruntime_alloc_memory_strings => ("apiset", "foundation"),
    x86_msvcrt_errno_thread_fiber_migration => ("msvcrt", "errno"),
    x86_ucrtbase_errno_thread_fiber_migration => ("ucrtbase", "errno"),
    x86_apiset_errno_thread_fiber_migration => ("apiset", "errno"),
    x86_msvcrt_module_cdecl_runtime_isolation => ("msvcrt", "module"),
    x86_ucrtbase_module_cdecl_runtime_isolation => ("ucrtbase", "module"),
    x86_apisets_module_cdecl_runtime_isolation => ("apiset", "module"),
    x86_ucrtbase_custom_invalid_parameter_handlers => ("ucrtbase", "invalid"),
    x86_apiset_custom_invalid_parameter_handlers => ("apiset", "invalid"),
    x86_ucrtbase_default_invalid_parameter_terminates => ("ucrtbase", "fatal"),
    x86_apiset_default_invalid_parameter_terminates => ("apiset", "fatal"),
);
cases!("x64",
    x64_msvcrt_alloc_memory_byte_utf16_strings => ("msvcrt", "foundation"),
    x64_ucrtbase_alloc_memory_byte_utf16_strings => ("ucrtbase", "foundation"),
    x64_apisets_vcruntime_alloc_memory_strings => ("apiset", "foundation"),
    x64_msvcrt_errno_thread_fiber_migration => ("msvcrt", "errno"),
    x64_ucrtbase_errno_thread_fiber_migration => ("ucrtbase", "errno"),
    x64_apiset_errno_thread_fiber_migration => ("apiset", "errno"),
    x64_msvcrt_module_cdecl_runtime_isolation => ("msvcrt", "module"),
    x64_ucrtbase_module_cdecl_runtime_isolation => ("ucrtbase", "module"),
    x64_apisets_module_cdecl_runtime_isolation => ("apiset", "module"),
    x64_ucrtbase_custom_invalid_parameter_handlers => ("ucrtbase", "invalid"),
    x64_apiset_custom_invalid_parameter_handlers => ("apiset", "invalid"),
    x64_ucrtbase_default_invalid_parameter_terminates => ("ucrtbase", "fatal"),
    x64_apiset_default_invalid_parameter_terminates => ("apiset", "fatal"),
);
cases!("arm64",
    arm64_msvcrt_alloc_memory_byte_utf16_strings => ("msvcrt", "foundation"),
    arm64_ucrtbase_alloc_memory_byte_utf16_strings => ("ucrtbase", "foundation"),
    arm64_apisets_vcruntime_alloc_memory_strings => ("apiset", "foundation"),
    arm64_msvcrt_errno_thread_fiber_migration => ("msvcrt", "errno"),
    arm64_ucrtbase_errno_thread_fiber_migration => ("ucrtbase", "errno"),
    arm64_apiset_errno_thread_fiber_migration => ("apiset", "errno"),
    arm64_msvcrt_module_cdecl_runtime_isolation => ("msvcrt", "module"),
    arm64_ucrtbase_module_cdecl_runtime_isolation => ("ucrtbase", "module"),
    arm64_apisets_module_cdecl_runtime_isolation => ("apiset", "module"),
    arm64_ucrtbase_custom_invalid_parameter_handlers => ("ucrtbase", "invalid"),
    arm64_apiset_custom_invalid_parameter_handlers => ("apiset", "invalid"),
    arm64_ucrtbase_default_invalid_parameter_terminates => ("ucrtbase", "fatal"),
    arm64_apiset_default_invalid_parameter_terminates => ("apiset", "fatal"),
);

#[test]
fn crt_sources_hashes_import_bindings_and_compiled_matrix_are_verified() {
    let manifest: toml::Value =
        toml::from_str(&std::fs::read_to_string(root().join("manifest.toml")).unwrap()).unwrap();
    let sources = manifest["source"].as_array().unwrap();
    assert_eq!(sources.len(), 14);
    let mut source_paths = BTreeSet::new();
    for source in sources {
        let path = source["path"].as_str().unwrap();
        assert!(source_paths.insert(path), "duplicate source {path}");
        assert_eq!(
            super::sha256::hex(&std::fs::read(root().join(path)).unwrap()),
            source["sha256"].as_str().unwrap(),
            "{path}"
        );
    }
    assert!(source_paths.contains("src/abi.S") && source_paths.contains("build.sh"));
    let entries = manifest["fixture"].as_array().unwrap();
    assert_eq!(entries.len(), 39);
    let mut found = BTreeSet::new();
    let mut imports_seen = BTreeSet::new();
    for entry in entries {
        let path = entry["path"].as_str().unwrap();
        let arch = entry["arch"].as_str().unwrap();
        let binding = entry["binding"].as_str().unwrap();
        assert!(BINDINGS.contains(&binding));
        let expected_arch = match arch {
            "x86" => WinArch::X86,
            "x64" => WinArch::X64,
            "arm64" => WinArch::Arm64,
            _ => panic!("unknown architecture {arch}"),
        };
        let program = path
            .strip_prefix(&format!("bin/{arch}/{binding}/"))
            .unwrap()
            .strip_suffix(".exe")
            .unwrap();
        assert!(PROGRAMS.contains(&program) && admitted(binding, program));
        assert!(
            found.insert((arch, binding, program)),
            "duplicate fixture {path}"
        );
        let expected = if program == "fatal" { FATAL_STATUS } else { 0 };
        assert_eq!(
            entry["expected_exit"].as_integer().unwrap(),
            i64::from(expected)
        );
        let bytes = std::fs::read(root().join(path)).unwrap();
        assert_eq!(bytes.len() as i64, entry["bytes"].as_integer().unwrap());
        assert_eq!(
            super::sha256::hex(&bytes),
            entry["sha256"].as_str().unwrap()
        );
        let pe = PeImage::parse(bytes).unwrap();
        assert_eq!(
            WinArch::from_machine(pe.headers().machine),
            Some(expected_arch)
        );
        assert_eq!(pe.headers().time_date_stamp, 0);
        assert_ne!(pe.headers().entry_rva, 0);
        let image = pe.memory_image();
        let descriptors =
            imports::descriptors(&image, pe.headers().directory(dir::IMPORT)).unwrap();
        let mut crt_imports = 0;
        for descriptor in descriptors {
            let dll = String::from_utf8(descriptor.dll_name(&image).unwrap())
                .unwrap()
                .to_ascii_lowercase();
            if dll != "kernel32.dll" {
                crt_imports += 1;
                match binding {
                    "msvcrt" => assert_eq!(dll, "msvcrt.dll", "{path}"),
                    "ucrtbase" => assert_eq!(dll, "ucrtbase.dll", "{path}"),
                    "apiset" => assert!(
                        matches!(
                            dll.as_str(),
                            "api-ms-win-crt-heap-l1-1-0.dll"
                                | "api-ms-win-crt-string-l1-1-0.dll"
                                | "api-ms-win-crt-runtime-l1-1-0.dll"
                                | "vcruntime140.dll"
                        ),
                        "{path}: {dll}"
                    ),
                    _ => unreachable!(),
                }
            }
            for thunk in descriptor.thunks(&image, pe.headers().kind).unwrap() {
                let imports::ImportRef::Name { name, .. } = thunk.symbol else {
                    panic!("{path}: no ordinal-only import");
                };
                let name = String::from_utf8(name).unwrap();
                if binding == "msvcrt" && dll == "msvcrt.dll" {
                    assert!(!name.contains("invalid_parameter") && !name.starts_with("_get_errno"));
                    assert!(!matches!(name.as_str(), "strnlen" | "wcsnlen"));
                }
                assert!(
                    !name.starts_with("wmem"),
                    "{path}: no invented nonsecure wmem export"
                );
                imports_seen.insert((dll.clone(), name));
            }
        }
        assert!(
            crt_imports > 0,
            "{path}: CRT operations must reach actual imports"
        );
    }
    for dll in [
        "msvcrt.dll",
        "ucrtbase.dll",
        "api-ms-win-crt-heap-l1-1-0.dll",
    ] {
        for function in [
            "malloc",
            "calloc",
            "realloc",
            "free",
            "_msize",
            "_expand",
            "_get_heap_handle",
        ] {
            assert!(
                imports_seen.contains(&(dll.into(), function.into())),
                "{dll}!{function}"
            );
        }
    }
    for function in [
        "memcpy", "memmove", "memcmp", "memchr", "strchr", "strrchr", "strstr", "wcschr",
        "wcsrchr", "wcsstr",
    ] {
        assert!(
            imports_seen.contains(&("vcruntime140.dll".into(), function.into())),
            "vcruntime140.dll!{function}"
        );
    }
    for dll in ["ucrtbase.dll", "api-ms-win-crt-runtime-l1-1-0.dll"] {
        for function in [
            "_get_errno",
            "_set_errno",
            "_get_doserrno",
            "_set_doserrno",
            "_set_invalid_parameter_handler",
            "_set_thread_local_invalid_parameter_handler",
            "_invalid_parameter_noinfo",
        ] {
            assert!(
                imports_seen.contains(&(dll.into(), function.into())),
                "{dll}!{function}"
            );
        }
    }
    // Retained regression observations must describe these exact final inputs,
    // not an earlier fixture revision or a native Windows execution oracle.
    let baseline: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root().join("baseline.json")).unwrap()).unwrap();
    assert_eq!(
        baseline["source_baseline"].as_str().unwrap(),
        "78e3abc5d932ab5bd5027e957828e88e6e401eea"
    );
    assert_eq!(
        baseline["executable_sha256"].as_str().unwrap(),
        "15d49476e26d17535b6bbca45c0ff535d04ba58c866381fa35f8a5acc7f1c32f"
    );
    assert_eq!(
        baseline["fixture_manifest_sha256"].as_str().unwrap(),
        super::sha256::hex(&std::fs::read(root().join("manifest.toml")).unwrap())
    );
    assert_eq!(baseline["seed"].as_u64().unwrap(), 1);
    assert_eq!(baseline["arena_bytes"].as_u64().unwrap(), 64 * 1024 * 1024);
    assert_eq!(baseline["watchdog_seconds"].as_u64().unwrap(), 30);
    assert_eq!(baseline["environment"]["RAX_NO_JIT"], "1");
    let declared: std::collections::BTreeMap<_, _> = entries
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
    assert_eq!(runs.len(), 78);
    let mut observed = BTreeSet::new();
    for run in runs {
        let path = run["path"].as_str().unwrap();
        let &(arch, binding, hash) = declared.get(path).expect("declared fixture input");
        let slice = run["slice_instructions"].as_u64().unwrap();
        assert!(matches!(slice, 1 | 4096));
        assert!(observed.insert((path, slice)), "duplicate baseline run");
        assert_eq!(run["arch"].as_str().unwrap(), arch);
        assert_eq!(run["binding"].as_str().unwrap(), binding);
        assert_eq!(run["input_sha256"].as_str().unwrap(), hash);
        assert_eq!(run["shell_exit"].as_u64().unwrap(), 53);
        assert_eq!(run["status"].as_str().unwrap(), "0xc0000135");
        assert!(run["stderr"].as_str().unwrap().contains("0xc0000135"));
    }
    assert_eq!(observed.len(), declared.len() * 2);
}

#[test]
fn crt_retained_abi_and_license_provenance_are_verified() {
    let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root().join("manifest-abi.json")).unwrap()).unwrap();
    let entries = manifest["sources"].as_array().unwrap();
    assert_eq!(entries.len(), 5);
    for entry in entries {
        let path = entry["path"].as_str().unwrap();
        assert!(path.starts_with("docs/"));
        assert_eq!(
            super::sha256::hex(&std::fs::read(repository.join(path)).unwrap()),
            entry["sha256"].as_str().unwrap(),
            "{path}"
        );
    }
    let bindings = repository.join("docs/specifications/windows/crt-foundation/bindings");
    let inventory: serde_json::Value =
        serde_json::from_slice(&std::fs::read(bindings.join("manifest-abi.json")).unwrap())
            .unwrap();
    let entries = inventory["sources"].as_array().unwrap();
    assert_eq!(entries.len(), 12);
    let mut paths = BTreeSet::new();
    for entry in entries {
        let path = entry["path"].as_str().unwrap();
        assert!(paths.insert(path), "duplicate binding source {path}");
        assert_eq!(
            super::sha256::hex(&std::fs::read(bindings.join(path)).unwrap()),
            entry["sha256"].as_str().unwrap(),
            "bindings/{path}"
        );
    }
    assert!(paths.contains("vcruntime140-x86-iats.txt") && paths.contains("mingw-wmem-excerpt.h"));
}
