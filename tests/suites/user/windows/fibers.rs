//! SDK/CRT-free, actual-PE fiber/FLS execution; native Windows oracle unknown.

use std::collections::BTreeSet;
use std::path::PathBuf;

use rax::user::image::pe::{PeImage, dir, exports, imports};
use rax::user::windows::WinArch;

const PROGRAMS: [&str; 8] = [
    "core",
    "migrate",
    "state",
    "stack",
    "thread-exit",
    "thread-forced",
    "process-exit",
    "process-forced",
];
const LOG: &str = "rax-fibers-exit.dat";

fn root() -> PathBuf {
    super::fixtures().join("fibers")
}

struct Bundle {
    directory: PathBuf,
}

impl Bundle {
    fn new(arch: &str, program: &str, slice: &str) -> Self {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "rax-windows-fibers-{}-{arch}-{program}-{slice}-{stamp}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).unwrap();
        for name in PROGRAMS {
            std::fs::copy(
                root().join(format!("bin/{arch}/{name}.exe")),
                directory.join(format!("{name}.exe")),
            )
            .unwrap();
        }
        Self { directory }
    }
}

impl Drop for Bundle {
    fn drop(&mut self) {
        for name in PROGRAMS {
            let _ = std::fs::remove_file(self.directory.join(format!("{name}.exe")));
        }
        let _ = std::fs::remove_file(self.directory.join(LOG));
        let _ = std::fs::remove_dir(&self.directory);
    }
}

fn record(bytes: &[u8]) -> [u32; 5] {
    assert_eq!(bytes.len(), 20);
    std::array::from_fn(|i| u32::from_le_bytes(bytes[4 * i..4 * i + 4].try_into().unwrap()))
}

fn run(arch: &str, program: &str) {
    for slice in ["1", "4096"] {
        let bundle = Bundle::new(arch, program, slice);
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
        assert_eq!(
            output.status,
            Some(0),
            "{arch} {program} slice={slice}: stderr={:?}, stdout={:?}, signal={:?}",
            output.stderr,
            output.stdout,
            output.signal
        );
        match program {
            "process-exit" | "process-forced" => {
                let bytes = std::fs::read(bundle.directory.join(LOG)).unwrap();
                let expected_len = if program == "process-exit" { 40 } else { 20 };
                assert_eq!(bytes.len(), expected_len, "{arch} {program} callback log");
                assert_eq!(record(&bytes[..20]), [0x464c_5331, 0, 0, 1, 0]);
                if program == "process-exit" {
                    assert_eq!(record(&bytes[20..]), [0x464c_5331, 1, 1, 1, 0]);
                }
            }
            _ => assert!(!bundle.directory.join(LOG).exists()),
        }
        for name in PROGRAMS {
            assert_eq!(
                std::fs::read(bundle.directory.join(format!("{name}.exe"))).unwrap(),
                std::fs::read(root().join(format!("bin/{arch}/{name}.exe"))).unwrap(),
                "{arch} {program} must not alter its input images"
            );
        }
    }
}

macro_rules! cases {
    ($arch:literal, $( $name:ident => $program:literal ),+ $(,)?) => {
        $(
            #[test]
            fn $name() { run($arch, $program); }
        )+
    };
}

cases!("x86",
    x86_fiber_conversion_fls_free_and_delete => "core",
    x86_synchronized_cross_thread_fiber_migration => "migrate",
    x86_fiber_stdcall_registers_stack_and_fp_flag => "state",
    x86_fiber_guard_growth_callback_and_continuation => "stack",
    x86_fls_normal_thread_and_fiber_exit_callbacks => "thread-exit",
    x86_forced_thread_exit_does_not_call_fls => "thread-forced",
    x86_normal_process_exit_calls_fls => "process-exit",
    x86_forced_process_exit_does_not_call_fls => "process-forced",
);
cases!("x64",
    x64_fiber_conversion_fls_free_and_delete => "core",
    x64_synchronized_cross_thread_fiber_migration => "migrate",
    x64_fiber_nonvolatile_gpr_xmm_stack_and_fp => "state",
    x64_fiber_guard_growth_callback_and_continuation => "stack",
    x64_fls_normal_thread_and_fiber_exit_callbacks => "thread-exit",
    x64_forced_thread_exit_does_not_call_fls => "thread-forced",
    x64_normal_process_exit_calls_fls => "process-exit",
    x64_forced_process_exit_does_not_call_fls => "process-forced",
);
cases!("arm64",
    arm64_fiber_conversion_fls_free_and_delete => "core",
    arm64_synchronized_cross_thread_fiber_migration => "migrate",
    arm64_fiber_nonvolatile_gpr_low64_vector_stack_and_fp => "state",
    arm64_fiber_guard_growth_callback_and_continuation => "stack",
    arm64_fls_normal_thread_and_fiber_exit_callbacks => "thread-exit",
    arm64_forced_thread_exit_does_not_call_fls => "thread-forced",
    arm64_normal_process_exit_calls_fls => "process-exit",
    arm64_forced_process_exit_does_not_call_fls => "process-forced",
);

#[test]
fn fibers_sources_artifact_hashes_and_public_imports_are_verified() {
    let manifest: toml::Value =
        toml::from_str(&std::fs::read_to_string(root().join("manifest.toml")).unwrap()).unwrap();
    let sources = manifest["source"].as_array().unwrap();
    assert_eq!(sources.len(), 11);
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
    assert!(source_paths.contains("src/state.S") && source_paths.contains("build.sh"));
    let entries = manifest["fixture"].as_array().unwrap();
    assert_eq!(entries.len(), 24);
    let mut found = BTreeSet::new();
    let mut api_names = BTreeSet::new();
    for entry in entries {
        let path = entry["path"].as_str().unwrap();
        let arch = entry["arch"].as_str().unwrap();
        let expected_arch = match arch {
            "x86" => WinArch::X86,
            "x64" => WinArch::X64,
            "arm64" => WinArch::Arm64,
            _ => panic!("unknown architecture {arch}"),
        };
        let program = path
            .strip_prefix(&format!("bin/{arch}/"))
            .unwrap()
            .strip_suffix(".exe")
            .unwrap();
        assert!(PROGRAMS.contains(&program));
        assert!(found.insert((arch, program)), "duplicate artifact {path}");
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
        assert_eq!(
            descriptors.len(),
            1,
            "{path}: no CRT or auxiliary DLL imports"
        );
        assert_eq!(descriptors[0].dll_name(&image).unwrap(), b"KERNEL32.dll");
        for thunk in descriptors[0].thunks(&image, pe.headers().kind).unwrap() {
            if let imports::ImportRef::Name { name, .. } = thunk.symbol {
                api_names.insert(name);
            } else {
                panic!("{path}: no ordinal-only imports");
            }
        }
        if program.starts_with("process-") {
            let table = exports::ExportDirectory::read(&image, pe.headers().directory(dir::EXPORT))
                .unwrap()
                .unwrap();
            assert!(matches!(
                table.by_name(&image, b"State", None).unwrap(),
                Some((_, exports::ExportTarget::Rva(_)))
            ));
        }
    }
    for name in [
        "ConvertThreadToFiber",
        "ConvertThreadToFiberEx",
        "ConvertFiberToThread",
        "CreateFiber",
        "CreateFiberEx",
        "SwitchToFiber",
        "DeleteFiber",
        "IsThreadAFiber",
        "FlsAlloc",
        "FlsFree",
        "FlsGetValue",
        "FlsSetValue",
    ] {
        assert!(
            api_names.contains(name.as_bytes()),
            "missing actual import {name}"
        );
    }
    assert!(!api_names.contains(b"GetCurrentFiber".as_slice()));
    assert!(!api_names.contains(b"GetFiberData".as_slice()));
}
