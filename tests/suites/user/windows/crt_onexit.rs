//! Explicit-table custom-entry probes; no ordinary compiler CRT exit claim.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use rax::user::image::pe::{PeImage, dir, exports, imports};
use rax::user::windows::WinArch;

const ARCHES: [&str; 3] = ["x86", "x64", "arm64"];
const BINDINGS: [&str; 2] = ["ucrtbase", "apiset"];
const PROGRAMS: [&str; 6] = ["basic", "mutation", "nested", "repair", "terminal", "oom"];
const BASELINE_CLI_SHA: &str = "422d7a6a0178c1a3a249c109f1138ed71e2b1ec5ffd1377573b1dcfa2f31c93f";

fn root() -> PathBuf {
    super::fixtures().join("crt_onexit")
}

struct Bundle {
    directory: PathBuf,
    image: PathBuf,
    dependency: Option<PathBuf>,
}

impl Bundle {
    fn new(arch: &str, binding: &str, program: &str, slice: &str) -> Self {
        static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let sequence = SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "rax-crt-onexit-{}-{arch}-{binding}-{program}-{slice}-{stamp}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).unwrap();
        let source_dir = root().join(format!("bin/{arch}/{binding}"));
        let image = directory.join(format!("{program}.exe"));
        std::fs::copy(source_dir.join(format!("{program}.exe")), &image).unwrap();
        let dependency = (program == "terminal").then(|| {
            let destination = directory.join("onexit.dll");
            std::fs::copy(source_dir.join("onexit.dll"), &destination).unwrap();
            destination
        });
        Self {
            directory,
            image,
            dependency,
        }
    }

    fn verify(&self, original: &[u8], dll: Option<&[u8]>) {
        assert_eq!(std::fs::read(&self.image).unwrap(), original);
        let mut expected =
            BTreeSet::from([self.image.file_name().unwrap().to_str().unwrap().to_owned()]);
        if let Some(dependency) = &self.dependency {
            assert_eq!(std::fs::read(dependency).unwrap(), dll.unwrap());
            expected.insert("onexit.dll".into());
        } else {
            assert!(dll.is_none());
        }
        let actual: BTreeSet<_> = std::fs::read_dir(&self.directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(actual, expected, "isolated immutable bundle inventory");
    }
}

impl Drop for Bundle {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.image);
        if let Some(dependency) = &self.dependency {
            let _ = std::fs::remove_file(dependency);
        }
        let _ = std::fs::remove_dir(&self.directory);
    }
}

fn run(arch: &str, binding: &str, program: &str) {
    assert!(ARCHES.contains(&arch) && BINDINGS.contains(&binding) && PROGRAMS.contains(&program));
    let source = root().join(format!("bin/{arch}/{binding}"));
    let original = std::fs::read(source.join(format!("{program}.exe"))).unwrap();
    let dll = (program == "terminal").then(|| std::fs::read(source.join("onexit.dll")).unwrap());
    for slice in ["1", "4096"] {
        let bundle = Bundle::new(arch, binding, program, slice);
        let mapping = format!("C={}", bundle.directory.display());
        let image = bundle.image.to_str().unwrap();
        let arguments = [
            "--os",
            "windows",
            "--memory",
            "64M",
            "--drive",
            &mapping,
            "--cwd",
            "C:\\",
            "--slice",
            slice,
            "--seed",
            "1",
            "--clear-env",
            image,
        ];
        let output = super::cli_support::run(
            &arguments,
            &[("RAX_NO_JIT", "1")],
            None,
            std::time::Duration::from_secs(30),
        );
        assert_eq!(
            output.status,
            Some(0),
            "{arch}/{binding}/{program} slice={slice}: stderr={:?}, stdout={:?}, signal={:?}",
            output.stderr,
            output.stdout,
            output.signal
        );
        bundle.verify(&original, dll.as_deref());
    }
}

macro_rules! cases {
    ($arch:literal, $( $name:ident => ($binding:literal, $program:literal) ),+ $(,)?) => {
        $( #[test] fn $name() { run($arch, $binding, $program); } )+
    };
}

cases!("x86",
    x86_ucrt_table_lifo_null_reuse_and_growth => ("ucrtbase", "basic"),
    x86_apiset_table_lifo_null_reuse_and_growth => ("apiset", "basic"),
    x86_ucrt_table_ownership_and_lazy_mutation => ("ucrtbase", "mutation"),
    x86_apiset_table_ownership_and_lazy_mutation => ("apiset", "mutation"),
    x86_ucrt_explicit_nested_generations => ("ucrtbase", "nested"),
    x86_apiset_explicit_nested_generations => ("apiset", "nested"),
    x86_ucrt_pending_slot_access_and_guard_repair => ("ucrtbase", "repair"),
    x86_apiset_pending_slot_access_and_guard_repair => ("apiset", "repair"),
    x86_ucrt_terminal_callbacks_and_guest_dll_detach => ("ucrtbase", "terminal"),
    x86_apiset_terminal_callbacks_and_guest_dll_detach => ("apiset", "terminal"),
    x86_ucrt_first_buffer_and_growth_oom_atomicity => ("ucrtbase", "oom"),
    x86_apiset_first_buffer_and_growth_oom_atomicity => ("apiset", "oom"),
);
cases!("x64",
    x64_ucrt_table_lifo_null_reuse_and_growth => ("ucrtbase", "basic"),
    x64_apiset_table_lifo_null_reuse_and_growth => ("apiset", "basic"),
    x64_ucrt_table_ownership_and_lazy_mutation => ("ucrtbase", "mutation"),
    x64_apiset_table_ownership_and_lazy_mutation => ("apiset", "mutation"),
    x64_ucrt_explicit_nested_generations => ("ucrtbase", "nested"),
    x64_apiset_explicit_nested_generations => ("apiset", "nested"),
    x64_ucrt_pending_slot_access_and_guard_repair => ("ucrtbase", "repair"),
    x64_apiset_pending_slot_access_and_guard_repair => ("apiset", "repair"),
    x64_ucrt_terminal_callbacks_and_guest_dll_detach => ("ucrtbase", "terminal"),
    x64_apiset_terminal_callbacks_and_guest_dll_detach => ("apiset", "terminal"),
    x64_ucrt_first_buffer_and_growth_oom_atomicity => ("ucrtbase", "oom"),
    x64_apiset_first_buffer_and_growth_oom_atomicity => ("apiset", "oom"),
);
cases!("arm64",
    arm64_ucrt_table_lifo_null_reuse_and_growth => ("ucrtbase", "basic"),
    arm64_apiset_table_lifo_null_reuse_and_growth => ("apiset", "basic"),
    arm64_ucrt_table_ownership_and_lazy_mutation => ("ucrtbase", "mutation"),
    arm64_apiset_table_ownership_and_lazy_mutation => ("apiset", "mutation"),
    arm64_ucrt_explicit_nested_generations => ("ucrtbase", "nested"),
    arm64_apiset_explicit_nested_generations => ("apiset", "nested"),
    arm64_ucrt_pending_slot_access_and_guard_repair => ("ucrtbase", "repair"),
    arm64_apiset_pending_slot_access_and_guard_repair => ("apiset", "repair"),
    arm64_ucrt_terminal_callbacks_and_guest_dll_detach => ("ucrtbase", "terminal"),
    arm64_apiset_terminal_callbacks_and_guest_dll_detach => ("apiset", "terminal"),
    arm64_ucrt_first_buffer_and_growth_oom_atomicity => ("ucrtbase", "oom"),
    arm64_apiset_first_buffer_and_growth_oom_atomicity => ("apiset", "oom"),
);

fn expected_imports(binding: &str, program: &str) -> BTreeSet<(String, String)> {
    let mut result = BTreeSet::new();
    let mut add = |group: &str, names: &[&str]| {
        let dll = if group == "kernel32" {
            "kernel32.dll".to_owned()
        } else if binding == "ucrtbase" {
            "ucrtbase.dll".to_owned()
        } else {
            format!("api-ms-win-crt-{group}-l1-1-0.dll")
        };
        for &name in names {
            assert!(result.insert((dll.clone(), name.into())));
        }
    };
    add(
        "runtime",
        &[
            "_initialize_onexit_table",
            "_register_onexit_function",
            "_execute_onexit_table",
        ],
    );
    if program == "companion" {
        add("kernel32", &["TerminateProcess"]);
    } else {
        add("kernel32", &["ExitProcess"]);
    }
    match program {
        "nested" => {
            add("heap", &["malloc", "free"]);
            add("string", &["memset"]);
        }
        "repair" => add(
            "kernel32",
            &[
                "VirtualProtect",
                "AddVectoredExceptionHandler",
                "RemoveVectoredExceptionHandler",
            ],
        ),
        "terminal" => add(
            "kernel32",
            &[
                "ExitThread",
                "CreateThread",
                "WaitForSingleObject",
                "GetExitCodeThread",
                "CloseHandle",
                "LoadLibraryW",
                "GetProcAddress",
            ],
        ),
        "oom" => {
            add("heap", &["_get_heap_handle"]);
            add(
                "kernel32",
                &[
                    "HeapAlloc",
                    "HeapFree",
                    "VirtualAlloc",
                    "VirtualFree",
                    "SetLastError",
                    "GetLastError",
                ],
            );
        }
        "basic" | "mutation" | "companion" => {}
        _ => panic!("unregistered program {program}"),
    }
    result
}

#[test]
fn onexit_source_artifact_binding_and_baseline_receipts_are_verified() {
    let manifest_bytes = std::fs::read(root().join("manifest.toml")).unwrap();
    let manifest: toml::Value =
        toml::from_str(std::str::from_utf8(&manifest_bytes).unwrap()).unwrap();
    assert_eq!(manifest["zig"].as_str().unwrap(), "0.16.0");
    for tool in ["clang", "linker"] {
        assert!(
            manifest[tool]
                .as_str()
                .unwrap()
                .contains("b51054818b78dc395cd4d33f17cfb6e98a36a76d")
        );
    }
    for (tool, hash) in [
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
        assert_eq!(manifest[tool].as_str().unwrap(), hash);
    }
    let expected_sources = BTreeSet::from([
        "build.sh",
        "baseline.sh",
        "README.md",
        "src/basic.c",
        "src/mutation.c",
        "src/nested.c",
        "src/repair.c",
        "src/terminal.c",
        "src/oom.c",
        "src/companion.c",
        "src/common.h",
        "src/kernel32.def",
        "src/kernel32-x86.def",
        "src/runtime.def",
        "src/heap.def",
        "src/string.def",
        "src/companion.def",
        "../layout/public.c",
        "../../../../../docs/specifications/windows/crt-initializers/mingw14/corecrt-startup-excerpt.h",
        "../../../../../docs/specifications/windows/crt-initializers/zig/corecrt-startup-excerpt.h",
        "../../../../../docs/specifications/windows/crt-startup/mingw14/winnt-exception-context-excerpt.h",
        "../../../../../docs/specifications/windows/crt-startup/zig/winnt-exception-context-excerpt.h",
    ]);
    let mut seen_sources = BTreeSet::new();
    for source in manifest["source"].as_array().unwrap() {
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
    assert_eq!(entries.len(), 42);
    let mut declared = BTreeMap::new();
    let mut matrix = BTreeSet::new();
    for entry in entries {
        let path = entry["path"].as_str().unwrap();
        let arch = entry["arch"].as_str().unwrap();
        let binding = entry["binding"].as_str().unwrap();
        let program = entry["program"].as_str().unwrap();
        let companion = program == "companion";
        assert!(ARCHES.contains(&arch) && BINDINGS.contains(&binding));
        assert!(companion || PROGRAMS.contains(&program));
        assert_eq!(
            entry["role"].as_str().unwrap(),
            if companion {
                "dependency"
            } else {
                "executable"
            }
        );
        let file = if companion {
            "onexit.dll".to_owned()
        } else {
            format!("{program}.exe")
        };
        assert_eq!(path, format!("bin/{arch}/{binding}/{file}"));
        assert!(matrix.insert((arch, binding, program)));
        assert!(
            declared
                .insert(
                    path,
                    (arch, binding, program, entry["sha256"].as_str().unwrap())
                )
                .is_none()
        );
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
        assert_eq!(image.headers().characteristics & 0x2000 != 0, companion);
        if !companion {
            assert_eq!(entry["expected_exit"].as_integer().unwrap(), 0);
        }
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
                    panic!("ordinal import {path}");
                };
                assert!(actual.insert((dll.clone(), String::from_utf8(name).unwrap())));
            }
        }
        assert_eq!(
            actual,
            expected_imports(binding, program),
            "genuine exact named IATs: {path}"
        );
        if companion {
            let directory =
                exports::ExportDirectory::read(&memory, image.headers().directory(dir::EXPORT))
                    .unwrap()
                    .unwrap();
            let (_, exports::ExportTarget::Rva(address)) = directory
                .by_name(&memory, b"configure", None)
                .unwrap()
                .unwrap()
            else {
                panic!("companion configure is not an in-image export");
            };
            assert!(address != 0 && u64::from(address) < u64::from(image.headers().size_of_image));
        }
    }
    for arch in ARCHES {
        for binding in BINDINGS {
            for program in PROGRAMS {
                assert!(matrix.contains(&(arch, binding, program)));
            }
            assert!(matrix.contains(&(arch, binding, "companion")));
        }
    }
    let baseline: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root().join("baseline.json")).unwrap()).unwrap();
    assert_eq!(
        baseline["source_baseline"],
        "3efe07a63ab935815d84ea4a48958282672a9059"
    );
    assert_eq!(baseline["executable_sha256"], BASELINE_CLI_SHA);
    assert_eq!(
        baseline["fixture_manifest_sha256"].as_str().unwrap(),
        super::sha256::hex(&manifest_bytes)
    );
    assert_eq!(baseline["seed"], 1);
    assert_eq!(baseline["arena_bytes"], 67108864);
    assert_eq!(baseline["watchdog_seconds"], 30);
    assert_eq!(baseline["environment"]["RAX_NO_JIT"], "1");
    let mut dependencies = BTreeSet::new();
    for dependency in baseline["dependencies"].as_array().unwrap() {
        let path = dependency["path"].as_str().unwrap();
        let &(arch, binding, program, hash) = declared.get(path).unwrap();
        assert_eq!(program, "companion");
        assert_eq!(dependency["arch"], arch);
        assert_eq!(dependency["binding"], binding);
        assert_eq!(dependency["sha256"], hash);
        assert_eq!(
            dependency["bytes"].as_u64().unwrap(),
            std::fs::metadata(root().join(path)).unwrap().len()
        );
        assert!(dependencies.insert(path));
    }
    assert_eq!(dependencies.len(), 6);
    let mut observed = BTreeSet::new();
    for run in baseline["runs"].as_array().unwrap() {
        let path = run["path"].as_str().unwrap();
        let &(arch, binding, program, hash) = declared.get(path).unwrap();
        assert!(PROGRAMS.contains(&program));
        let slice = run["slice_instructions"].as_u64().unwrap();
        assert!(matches!(slice, 1 | 4096) && observed.insert((path, slice)));
        assert_eq!(run["arch"], arch);
        assert_eq!(run["binding"], binding);
        assert_eq!(run["program"], program);
        assert_eq!(run["input_sha256"], hash);
        assert_eq!(run["shell_exit"], 125);
        assert!(run["status"].is_null());
        assert_eq!(run["failure_class"], "unimplemented Windows export");
        assert_eq!(run["missing_dll"], "ucrtbase.dll");
        assert_eq!(run["missing_export"], "_initialize_onexit_table");
        assert!(
            run["stderr"].as_str().unwrap().contains(
                "unimplemented Windows export: ucrtbase.dll!_initialize_onexit_table at "
            )
        );
        let args: Vec<_> = run["arguments"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(args.len(), 14);
        assert_eq!(
            &args[..5],
            ["--os", "windows", "--memory", "64M", "--drive"]
        );
        assert_eq!(&args[6..9], ["--cwd", "C:\\", "--slice"]);
        assert_eq!(args[9], slice.to_string());
        assert_eq!(&args[10..13], ["--seed", "1", "--clear-env"]);
        let copied = PathBuf::from(args[13]);
        assert_eq!(
            copied.file_name().unwrap().to_str().unwrap(),
            format!("{program}.exe")
        );
        assert_eq!(args[5], format!("C={}", copied.parent().unwrap().display()));
        let extra = run["dependencies"].as_array().unwrap();
        assert_eq!(extra.len(), usize::from(program == "terminal"));
        if program == "terminal" {
            let dependency_path = format!("bin/{arch}/{binding}/onexit.dll");
            assert_eq!(extra[0]["path"], dependency_path);
            assert_eq!(
                extra[0]["sha256"].as_str().unwrap(),
                declared[dependency_path.as_str()].3
            );
        }
    }
    assert_eq!(observed.len(), 72);
}

#[test]
fn onexit_retained_primary_archive_inputs_are_verified() {
    let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let base = repository.join("docs/specifications/windows/crt-onexit");
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(base.join("sources.json")).unwrap()).unwrap();
    let entries = manifest["sources"].as_array().unwrap();
    assert_eq!(entries.len(), 26);
    let mut seen = BTreeSet::new();
    for entry in entries {
        let path = entry["path"].as_str().unwrap();
        assert!(seen.insert(path) && !PathBuf::from(path).is_absolute());
        let resolved = base.join(path).canonicalize().unwrap();
        assert!(resolved.starts_with(repository.join("docs")));
        let bytes = std::fs::read(resolved).unwrap();
        assert_eq!(
            super::sha256::hex(&bytes),
            entry["sha256"].as_str().unwrap(),
            "{path}"
        );
        assert_eq!(bytes.len() as u64, entry["bytes"].as_u64().unwrap());
    }
    assert!(seen.contains("../crt-initializers/mingw14/onexit_table.c"));
    assert!(seen.contains("../crt-initializers/mingw14/corecrt-startup-excerpt.h"));
    assert!(seen.contains("../crt-initializers/zig/corecrt-startup-excerpt.h"));
}
