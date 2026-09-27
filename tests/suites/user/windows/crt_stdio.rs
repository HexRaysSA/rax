//! Genuine standard-stream/byte-I/O custom entries; ordinary startup is separate.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use rax::user::image::pe::{PeImage, dir, imports};
use rax::user::windows::WinArch;

const ARCHES: [&str; 3] = ["x86", "x64", "arm64"];
const BINDINGS: [&str; 3] = ["msvcrt", "ucrtbase", "apiset"];
const PROGRAMS: [&str; 7] = [
    "streams",
    "bytes",
    "descriptors",
    "translation",
    "repair",
    "buffering",
    "errors",
];
const BASELINE_CLI_SHA: &str = "55a60784315e0e7eff45b5ba4b793f1f225424bb7583f1c95653135a70e89b93";

fn root() -> PathBuf {
    super::fixtures().join("crt_stdio")
}

fn admitted(binding: &str, program: &str) -> bool {
    binding != "msvcrt" || program != "errors"
}

fn inputs(program: &str) -> BTreeMap<&'static str, Vec<u8>> {
    match program {
        "translation" => BTreeMap::from([
            ("text.dat", b"a\r\nb\rx\r\nYZ\x1aQ".to_vec()),
            (
                "edge.dat",
                [
                    vec![b'a'; 255],
                    b"\r\n".to_vec(),
                    vec![b'b'; 512],
                    vec![b'Z'],
                ]
                .concat(),
            ),
        ]),
        "repair" => BTreeMap::from([("read.dat", (0..768).map(|i| (i * 7 + 3) as u8).collect())]),
        _ => BTreeMap::new(),
    }
}

fn outputs(program: &str) -> BTreeMap<&'static str, Vec<u8>> {
    match program {
        "bytes" => BTreeMap::from([("bytes.dat", b"A\0B\nC\r\xff".to_vec())]),
        "descriptors" => BTreeMap::from([("descriptor.dat", b"FD\nT\r\n".to_vec())]),
        "translation" => BTreeMap::from([
            ("translate.dat", b"a\r\r\nB\r\n".to_vec()),
            ("default.dat", b"D\n".to_vec()),
            ("control.dat", b"AC\r\n".to_vec()),
        ]),
        "buffering" => BTreeMap::from([
            ("line.dat", b"one\nab!".to_vec()),
            ("flush.dat", b"two".to_vec()),
        ]),
        "repair" => BTreeMap::from([("repair.dat", (0..768).map(|i| (i * 7 + 3) as u8).collect())]),
        _ => BTreeMap::new(),
    }
}

struct Bundle {
    directory: PathBuf,
    image: PathBuf,
    program: String,
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
            "rax-crt-stdio-{}-{arch}-{binding}-{program}-{slice}-{stamp}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).unwrap();
        let image = directory.join(format!("{program}.exe"));
        let source = root().join(format!("bin/{arch}/{binding}/{program}.exe"));
        std::fs::copy(source, &image).unwrap();
        for (name, data) in inputs(program) {
            std::fs::write(directory.join(name), data).unwrap();
        }
        Self {
            directory,
            image,
            program: program.into(),
        }
    }

    fn verify(&self, original: &[u8]) {
        assert_eq!(
            std::fs::read(&self.image).unwrap(),
            original,
            "immutable PE"
        );
        let mut expected =
            BTreeSet::from([self.image.file_name().unwrap().to_str().unwrap().to_owned()]);
        for (name, data) in inputs(&self.program)
            .into_iter()
            .chain(outputs(&self.program))
        {
            assert_eq!(
                std::fs::read(self.directory.join(name)).unwrap(),
                data,
                "independent bytes: {name}"
            );
            expected.insert(name.into());
        }
        let actual: BTreeSet<_> = std::fs::read_dir(&self.directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(actual, expected, "isolated input/output inventory");
    }
}

impl Drop for Bundle {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.image);
        for (name, _) in inputs(&self.program)
            .into_iter()
            .chain(outputs(&self.program))
        {
            let _ = std::fs::remove_file(self.directory.join(name));
        }
        let _ = std::fs::remove_dir(&self.directory);
    }
}

fn run(arch: &str, binding: &str, program: &str) {
    assert!(
        ARCHES.contains(&arch)
            && BINDINGS.contains(&binding)
            && PROGRAMS.contains(&program)
            && admitted(binding, program)
    );
    let original =
        std::fs::read(root().join(format!("bin/{arch}/{binding}/{program}.exe"))).unwrap();
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
        if program == "streams" {
            assert_eq!(output.stdout, b"stdio-out\r\n");
            assert_eq!(output.stderr.as_bytes(), b"stdio-err\r\n");
        } else {
            assert!(output.stdout.is_empty() && output.stderr.is_empty());
        }
        bundle.verify(&original);
    }
}

macro_rules! cases {
    ($arch:literal, $( $name:ident => ($binding:literal, $program:literal) ),+ $(,)?) => {
        $( #[test] fn $name() { run($arch, $binding, $program); } )+
    };
}

cases!("x86",
    x86_msvcrt_standard_streams_and_mode_cells => ("msvcrt", "streams"),
    x86_ucrt_standard_streams_and_mode_cells => ("ucrtbase", "streams"),
    x86_apiset_standard_streams_and_mode_cells => ("apiset", "streams"),
    x86_msvcrt_binary_items_eof_and_buffer_ownership => ("msvcrt", "bytes"),
    x86_ucrt_binary_items_eof_and_buffer_ownership => ("ucrtbase", "bytes"),
    x86_apiset_binary_items_eof_and_buffer_ownership => ("apiset", "bytes"),
    x86_msvcrt_descriptor_and_handle_ownership => ("msvcrt", "descriptors"),
    x86_ucrt_descriptor_and_handle_ownership => ("ucrtbase", "descriptors"),
    x86_apiset_descriptor_and_handle_ownership => ("apiset", "descriptors"),
    x86_msvcrt_text_binary_and_default_mode => ("msvcrt", "translation"),
    x86_ucrt_text_binary_and_default_mode => ("ucrtbase", "translation"),
    x86_apiset_text_binary_and_default_mode => ("apiset", "translation"),
    x86_msvcrt_fault_repair_preserves_progress_and_formals => ("msvcrt", "repair"),
    x86_ucrt_fault_repair_preserves_progress_and_formals => ("ucrtbase", "repair"),
    x86_apiset_fault_repair_preserves_progress_and_formals => ("apiset", "repair"),
    x86_msvcrt_line_full_flush_all_and_close => ("msvcrt", "buffering"),
    x86_ucrt_line_full_flush_all_and_close => ("ucrtbase", "buffering"),
    x86_apiset_line_full_flush_all_and_close => ("apiset", "buffering"),
    x86_ucrt_returning_invalid_handler_errors => ("ucrtbase", "errors"),
    x86_apiset_returning_invalid_handler_errors => ("apiset", "errors"),
);
cases!("x64",
    x64_msvcrt_standard_streams_and_mode_cells => ("msvcrt", "streams"),
    x64_ucrt_standard_streams_and_mode_cells => ("ucrtbase", "streams"),
    x64_apiset_standard_streams_and_mode_cells => ("apiset", "streams"),
    x64_msvcrt_binary_items_eof_and_buffer_ownership => ("msvcrt", "bytes"),
    x64_ucrt_binary_items_eof_and_buffer_ownership => ("ucrtbase", "bytes"),
    x64_apiset_binary_items_eof_and_buffer_ownership => ("apiset", "bytes"),
    x64_msvcrt_descriptor_and_handle_ownership => ("msvcrt", "descriptors"),
    x64_ucrt_descriptor_and_handle_ownership => ("ucrtbase", "descriptors"),
    x64_apiset_descriptor_and_handle_ownership => ("apiset", "descriptors"),
    x64_msvcrt_text_binary_and_default_mode => ("msvcrt", "translation"),
    x64_ucrt_text_binary_and_default_mode => ("ucrtbase", "translation"),
    x64_apiset_text_binary_and_default_mode => ("apiset", "translation"),
    x64_msvcrt_fault_repair_preserves_progress_and_formals => ("msvcrt", "repair"),
    x64_ucrt_fault_repair_preserves_progress_and_formals => ("ucrtbase", "repair"),
    x64_apiset_fault_repair_preserves_progress_and_formals => ("apiset", "repair"),
    x64_msvcrt_line_full_flush_all_and_close => ("msvcrt", "buffering"),
    x64_ucrt_line_full_flush_all_and_close => ("ucrtbase", "buffering"),
    x64_apiset_line_full_flush_all_and_close => ("apiset", "buffering"),
    x64_ucrt_returning_invalid_handler_errors => ("ucrtbase", "errors"),
    x64_apiset_returning_invalid_handler_errors => ("apiset", "errors"),
);
cases!("arm64",
    arm64_msvcrt_standard_streams_and_mode_cells => ("msvcrt", "streams"),
    arm64_ucrt_standard_streams_and_mode_cells => ("ucrtbase", "streams"),
    arm64_apiset_standard_streams_and_mode_cells => ("apiset", "streams"),
    arm64_msvcrt_binary_items_eof_and_buffer_ownership => ("msvcrt", "bytes"),
    arm64_ucrt_binary_items_eof_and_buffer_ownership => ("ucrtbase", "bytes"),
    arm64_apiset_binary_items_eof_and_buffer_ownership => ("apiset", "bytes"),
    arm64_msvcrt_descriptor_and_handle_ownership => ("msvcrt", "descriptors"),
    arm64_ucrt_descriptor_and_handle_ownership => ("ucrtbase", "descriptors"),
    arm64_apiset_descriptor_and_handle_ownership => ("apiset", "descriptors"),
    arm64_msvcrt_text_binary_and_default_mode => ("msvcrt", "translation"),
    arm64_ucrt_text_binary_and_default_mode => ("ucrtbase", "translation"),
    arm64_apiset_text_binary_and_default_mode => ("apiset", "translation"),
    arm64_msvcrt_fault_repair_preserves_progress_and_formals => ("msvcrt", "repair"),
    arm64_ucrt_fault_repair_preserves_progress_and_formals => ("ucrtbase", "repair"),
    arm64_apiset_fault_repair_preserves_progress_and_formals => ("apiset", "repair"),
    arm64_msvcrt_line_full_flush_all_and_close => ("msvcrt", "buffering"),
    arm64_ucrt_line_full_flush_all_and_close => ("ucrtbase", "buffering"),
    arm64_apiset_line_full_flush_all_and_close => ("apiset", "buffering"),
    arm64_ucrt_returning_invalid_handler_errors => ("ucrtbase", "errors"),
    arm64_apiset_returning_invalid_handler_errors => ("apiset", "errors"),
);

fn expected_imports(arch: &str, binding: &str, program: &str) -> BTreeSet<(String, String)> {
    let mut result = BTreeSet::new();
    let dll = if binding == "apiset" {
        "api-ms-win-crt-stdio-l1-1-0.dll".into()
    } else {
        format!("{binding}.dll")
    };
    let mut add = |module: &str, names: &[&str]| {
        for name in names {
            assert!(result.insert((module.into(), (*name).into())));
        }
    };
    add("kernel32.dll", &["ExitProcess"]);
    let access = if binding == "msvcrt" {
        if arch == "x86" {
            "__p__iob"
        } else {
            "__iob_func"
        }
    } else {
        "__acrt_iob_func"
    };
    let fdopen = if binding == "apiset" {
        "_wfdopen"
    } else {
        "_fdopen"
    };
    match program {
        "streams" => {
            add(
                "kernel32.dll",
                &["GetStdHandle", "SetLastError", "GetLastError"],
            );
            add(
                &dll,
                &[
                    access,
                    "_fileno",
                    "_get_osfhandle",
                    "setvbuf",
                    "fwrite",
                    "fflush",
                    "ferror",
                ],
            );
            if binding == "msvcrt" {
                add(&dll, &["_fmode", "_commode"]);
            } else {
                add(&dll, &["__p__fmode", "__p__commode"]);
            }
        }
        "bytes" | "buffering" => {
            add(
                "kernel32.dll",
                &[
                    "CreateFileW",
                    "GetFileSizeEx",
                    "GetFileType",
                    "SetLastError",
                    "GetLastError",
                ],
            );
            add(
                &dll,
                &[
                    "_open_osfhandle",
                    "_get_osfhandle",
                    fdopen,
                    "_fileno",
                    "setvbuf",
                    "fwrite",
                    "fflush",
                    "fclose",
                ],
            );
            if program == "bytes" {
                add(&dll, &["fread", "feof", "ferror", "clearerr"]);
            }
        }
        "descriptors" => {
            add(
                "kernel32.dll",
                &[
                    "CreateFileW",
                    "GetFileSizeEx",
                    "GetFileType",
                    "SetLastError",
                    "GetLastError",
                ],
            );
            add(
                &dll,
                &[
                    "_open_osfhandle",
                    "_get_osfhandle",
                    "_write",
                    "_setmode",
                    "_close",
                    "_read",
                    "_wfdopen",
                    "_fileno",
                    "fread",
                    "feof",
                    "ferror",
                    "fclose",
                ],
            );
        }
        "translation" => {
            add(
                "kernel32.dll",
                &["CreateFileW", "GetFileType", "SetLastError", "GetLastError"],
            );
            add(
                &dll,
                &[
                    "_open_osfhandle",
                    "_get_osfhandle",
                    "_read",
                    "_write",
                    "_close",
                    fdopen,
                    "_fileno",
                    "setvbuf",
                    "fwrite",
                    "fflush",
                    "fclose",
                ],
            );
            add(
                &dll,
                &[if binding == "msvcrt" {
                    "_fmode"
                } else {
                    "__p__fmode"
                }],
            );
        }
        "repair" => {
            add(
                "kernel32.dll",
                &[
                    "CreateFileW",
                    "GetFileSizeEx",
                    "GetFileType",
                    "SetLastError",
                    "GetLastError",
                    "VirtualAlloc",
                    "VirtualFree",
                    "VirtualProtect",
                    "AddVectoredExceptionHandler",
                    "RemoveVectoredExceptionHandler",
                ],
            );
            add(
                &dll,
                &[
                    "_open_osfhandle",
                    "_get_osfhandle",
                    "_read",
                    "_close",
                    fdopen,
                    "_fileno",
                    "setvbuf",
                    "fwrite",
                    "fclose",
                ],
            );
        }
        "errors" => {
            assert_ne!(binding, "msvcrt");
            add(
                &dll,
                &[
                    access, "_read", "_write", "setvbuf", "_setmode", "fread", "fwrite", "fclose",
                ],
            );
            add(
                if binding == "apiset" {
                    "api-ms-win-crt-runtime-l1-1-0.dll"
                } else {
                    "ucrtbase.dll"
                },
                &["_errno", "_set_invalid_parameter_handler"],
            );
        }
        _ => panic!("unregistered custom program {program}"),
    }
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
                panic!("unexpected ordinal import");
            };
            assert!(result.insert((dll.clone(), String::from_utf8(name).unwrap())));
        }
    }
    result
}

fn readobj_imports(text: &str) -> BTreeSet<(String, String)> {
    let mut dll = "";
    let mut result = BTreeSet::new();
    for line in text.lines().map(str::trim) {
        if let Some(name) = line.strip_prefix("Name: ") {
            dll = name;
        } else if let Some(symbol) = line.strip_prefix("Symbol: ") {
            let name = symbol.rsplit_once(" (").unwrap().0;
            assert!(result.insert((dll.to_ascii_lowercase(), name.into())));
        }
    }
    result
}

fn bytes_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn physical_files(base: &std::path::Path) -> BTreeSet<String> {
    fn visit(base: &std::path::Path, directory: &std::path::Path, files: &mut BTreeSet<String>) {
        for entry in std::fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let kind = entry.file_type().unwrap();
            if kind.is_dir() {
                visit(base, &entry.path(), files);
            } else {
                assert!(kind.is_file(), "non-file artifact");
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

#[test]
fn stdio_source_artifact_binding_and_baseline_receipts_are_verified() {
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
            "readobj_sha256",
            "903feaa9324fcedcfb80afd2e8da6248bed8e9fb3222c8476fdfb59519ec95d1",
        ),
        (
            "zig_sha256",
            "8d295db7edd9c52c5e4e3294f00e848b618f4f517e49c928e9b3988f0c63a867",
        ),
        (
            "gcc_x86_sha256",
            "9fccf68680eac18e4dc367ed9babc715836e69eaf297b96688b1c97dbdea9cc4",
        ),
        (
            "gcc_x64_sha256",
            "012ac93959d40444ddc8c67d23d348c062acbe977e6384ca6fe45c0648e97301",
        ),
    ] {
        assert_eq!(manifest[tool].as_str().unwrap(), hash);
    }
    let expected_sources = BTreeSet::from([
        "build.sh",
        "baseline.sh",
        "README.md",
        "src/common.h",
        "src/streams.c",
        "src/bytes.c",
        "src/descriptors.c",
        "src/translation.c",
        "src/repair.c",
        "src/buffering.c",
        "src/errors.c",
        "src/ordinary.c",
        "src/stdio.def",
        "src/ucrt.def",
        "src/narrow.def",
        "src/legacy.def",
        "src/legacy-x86.def",
        "src/runtime.def",
        "src/kernel32.def",
        "src/kernel32-x86.def",
        "../layout/public.c",
        "../../../../../docs/specifications/windows/crt-startup/mingw14/winnt-exception-context-excerpt.h",
        "../../../../../docs/specifications/windows/crt-startup/zig/winnt-exception-context-excerpt.h",
    ]);
    let mut seen_sources = BTreeSet::new();
    for entry in manifest["source"].as_array().unwrap() {
        let path = entry["path"].as_str().unwrap();
        assert!(seen_sources.insert(path));
        assert_eq!(
            super::sha256::hex(&std::fs::read(root().join(path)).unwrap()),
            entry["sha256"].as_str().unwrap(),
            "{path}"
        );
    }
    assert_eq!(seen_sources, expected_sources);
    let entries = manifest["fixture"].as_array().unwrap();
    assert_eq!(entries.len(), 66);
    let mut declared = BTreeMap::new();
    let mut matrix = BTreeSet::new();
    let mut observed_iats = BTreeSet::new();
    for entry in entries {
        let path = entry["path"].as_str().unwrap();
        let arch = entry["arch"].as_str().unwrap();
        let binding = entry["binding"].as_str().unwrap();
        let program = entry["program"].as_str().unwrap();
        let ordinary = entry["role"].as_str().unwrap() == "ordinary-startup-observation";
        assert!(ARCHES.contains(&arch));
        assert!(matrix.insert((arch, binding, program)));
        assert!(
            declared
                .insert(
                    path,
                    (
                        arch,
                        binding,
                        program,
                        entry["sha256"].as_str().unwrap(),
                        ordinary
                    )
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
        assert_ne!(image.headers().entry_rva, 0);
        assert_eq!(image.headers().characteristics & 0x2000, 0);
        let actual = import_set(&image);
        if ordinary {
            assert_eq!(binding, "compiler-selected");
            assert!(matches!(program, "main" | "wmain"));
            assert_eq!(path, format!("bin/{arch}/ordinary/{program}.exe"));
            assert!(
                entry.get("expected_exit").is_none(),
                "ordinary startup not claimed complete"
            );
            let observed = std::fs::read(root().join(entry["iat_path"].as_str().unwrap())).unwrap();
            assert!(
                observed_iats.insert(
                    entry["iat_path"]
                        .as_str()
                        .unwrap()
                        .strip_prefix("observations/")
                        .unwrap()
                        .to_owned()
                )
            );
            assert_eq!(
                super::sha256::hex(&observed),
                entry["iat_sha256"].as_str().unwrap()
            );
            assert_eq!(
                readobj_imports(std::str::from_utf8(&observed).unwrap()),
                actual
            );
            assert!(actual.iter().any(|(_, name)| name == "_crt_atexit"));
            assert!(
                actual
                    .iter()
                    .any(|(_, name)| name == "__stdio_common_vfprintf")
            );
            assert!(actual.iter().any(|(_, name)| name == "exit"));
            if arch != "x86" {
                assert!(
                    actual
                        .iter()
                        .any(|(_, name)| name == "__C_specific_handler")
                );
            }
        } else {
            assert_eq!(entry["role"].as_str().unwrap(), "custom-entry");
            assert!(
                BINDINGS.contains(&binding)
                    && PROGRAMS.contains(&program)
                    && admitted(binding, program)
            );
            assert_eq!(path, format!("bin/{arch}/{binding}/{program}.exe"));
            assert_eq!(entry["expected_exit"].as_integer().unwrap(), 0);
            assert_eq!(image.headers().time_date_stamp, 0);
            assert_eq!(
                actual,
                expected_imports(arch, binding, program),
                "genuine exact IAT: {path}"
            );
        }
    }
    assert_eq!(
        physical_files(&root().join("bin")),
        declared
            .keys()
            .map(|path| path.strip_prefix("bin/").unwrap().to_owned())
            .collect()
    );
    assert_eq!(physical_files(&root().join("observations")), observed_iats);
    for arch in ARCHES {
        for binding in BINDINGS {
            for program in PROGRAMS {
                assert_eq!(
                    matrix.contains(&(arch, binding, program)),
                    admitted(binding, program)
                );
            }
        }
        for program in ["main", "wmain"] {
            assert!(matrix.contains(&(arch, "compiler-selected", program)));
        }
    }
    let baseline: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root().join("baseline.json")).unwrap()).unwrap();
    assert_eq!(
        baseline["source_baseline"],
        "9b73397628567e675f129ecf38896ee50f601576"
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
    let mut observed = BTreeSet::new();
    for (field, count, expected_ordinary) in [("runs", 120, false), ("ordinary_runs", 12, true)] {
        let runs = baseline[field].as_array().unwrap();
        assert_eq!(runs.len(), count);
        for run in runs {
            let path = run["path"].as_str().unwrap();
            let &(arch, binding, program, hash, ordinary) = declared.get(path).unwrap();
            assert_eq!(ordinary, expected_ordinary);
            let slice = run["slice_instructions"].as_u64().unwrap();
            assert!(matches!(slice, 1 | 4096) && observed.insert((path, slice)));
            assert_eq!(run["arch"], arch);
            assert_eq!(run["binding"], binding);
            assert_eq!(run["program"], program);
            assert_eq!(run["input_sha256"], hash);
            assert!(run["status"].is_null());
            let timed_out = run["timed_out"].as_bool().unwrap();
            if timed_out {
                assert!(ordinary && run["shell_exit"].is_null());
                assert_eq!(run["failure_class"], "watchdog timeout");
                assert!(run["missing_dll"].is_null() && run["missing_export"].is_null());
            } else {
                assert_eq!(run["shell_exit"], 125);
                assert_eq!(run["failure_class"], "unimplemented Windows export");
                let dll = run["missing_dll"].as_str().unwrap();
                let export = run["missing_export"].as_str().unwrap();
                assert!(
                    run["stderr"]
                        .as_str()
                        .unwrap()
                        .contains(&format!("unimplemented Windows export: {dll}!{export} at "))
                );
                if !ordinary {
                    assert!(expected_imports(arch, binding, program).iter().any(
                        |(module, name)| {
                            let host = if module.starts_with("api-ms-win-crt-") {
                                "ucrtbase.dll"
                            } else {
                                module
                            };
                            host == dll && name == export
                        }
                    ));
                }
            }
            let args: Vec<_> = run["arguments"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap())
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
            let input_receipt = run["inputs"].as_object().unwrap();
            assert_eq!(input_receipt.len(), inputs(program).len());
            for (name, bytes) in inputs(program) {
                assert_eq!(
                    input_receipt[name].as_str().unwrap(),
                    super::sha256::hex(&bytes)
                );
            }
            assert_eq!(
                run["stdout_hex"].as_str().unwrap(),
                bytes_hex(run["stdout"].as_str().unwrap().as_bytes())
            );
            assert_eq!(
                run["stderr_hex"].as_str().unwrap(),
                bytes_hex(run["stderr"].as_str().unwrap().as_bytes())
            );
        }
    }
    assert_eq!(observed.len(), 132);
}

#[test]
fn stdio_retained_primary_and_producer_inputs_are_verified() {
    let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let base = repository.join("docs/specifications/windows/crt-stdio");
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(base.join("sources.json")).unwrap()).unwrap();
    let entries = manifest["sources"].as_array().unwrap();
    assert_eq!(entries.len(), 78);
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
}
