//! Full PE fixtures with no filesystem-backed loader or guest console.
use super::*;
use crate::user::console::{Console, OutputStream};
use std::sync::atomic::AtomicBool;

fn fixtures(arch: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/user/windows/lifecycle/bin")
        .join(arch)
}

fn config() -> WindowsConfig {
    let mut cfg = WindowsConfig::embedded("C:\\app\\program.exe", vec![], vec![], 4096).unwrap();
    cfg.arena_bytes = 64 << 20;
    cfg.slice_insns = 64;
    cfg
}

#[test]
fn supplied_dependencies_run_static_and_dynamic_loader_lifecycles_all_abis() {
    for arch in ["x86", "x64", "arm64"] {
        for exe in ["startup.exe", "forward-miss.exe"] {
            let mut cfg = config();
            // The test caller supplies bytes. The runtime has no permission to
            // reopen these host files, even though the fixtures remain present.
            for entry in std::fs::read_dir(fixtures(arch)).unwrap() {
                let path = entry.unwrap().path();
                let name = path.file_name().unwrap().to_str().unwrap();
                if name.ends_with(".dll") || name == "data.exe" {
                    cfg.supplied_dlls.insert(
                        format!("C:\\app\\{name}"),
                        std::fs::read(&path).unwrap().into(),
                    );
                }
            }
            let mut p =
                WindowsProcess::spawn_image(cfg, std::fs::read(fixtures(arch).join(exe)).unwrap())
                    .unwrap();
            let cancelled = AtomicBool::new(false);
            let mut result = RunStatus::BudgetExhausted;
            for _ in 0..20_000 {
                result = p.run_slice(10, &cancelled);
                if matches!(result, RunStatus::Complete(_)) {
                    break;
                }
                assert_eq!(result, RunStatus::BudgetExhausted, "{arch}/{exe}");
            }
            assert_eq!(
                result,
                RunStatus::Complete(ExitStatus::Exited(0)),
                "{arch}/{exe}"
            );
            assert!(p.state().modules.list.iter().all(|m| m.host_path.is_none()));
            let Console::Captured(console) = &p.state().cfg.console else {
                panic!("captured console");
            };
            assert_eq!(
                console.drain(OutputStream::Stdout, &mut [0; 64]).unwrap(),
                0
            );
        }
    }
}

#[test]
fn closed_loader_never_falls_back_to_existing_host_dependencies() {
    for arch in ["x86", "x64", "arm64"] {
        let mut cfg = config();
        cfg.exe_host_path = fixtures(arch).join("startup.exe");
        cfg.dll_paths.push(fixtures(arch));
        let error = match WindowsProcess::spawn_image(
            cfg,
            std::fs::read(fixtures(arch).join("startup.exe")).unwrap(),
        ) {
            Err(error) => error,
            Ok(_) => panic!("host DLLs must not be discovered"),
        };
        assert_eq!(
            error.exit_code(),
            crate::user::windows::nt::status::STATUS_DLL_NOT_FOUND
        );
    }
}

#[test]
fn closed_configuration_rejects_host_entrypoint_trace_entropy_and_colliding_keys() {
    assert!(WindowsProcess::spawn(config()).is_err());
    let mut cfg = config();
    cfg.trace = true;
    assert!(
        WindowsProcess::spawn_image(cfg, vec![])
            .unwrap_err_message()
            .contains("disabled host trace")
    );
    let mut cfg = config();
    cfg.console = Console::Host;
    assert!(
        WindowsProcess::spawn_image(cfg, vec![])
            .unwrap_err_message()
            .contains("captured console")
    );
    let mut cfg = config();
    cfg.seed = None;
    assert!(
        WindowsProcess::spawn_image(cfg, vec![])
            .unwrap_err_message()
            .contains("requires a seed")
    );
    let mut cfg = config();
    cfg.supplied_dlls
        .insert("C:\\App\\test.dll".into(), Arc::from([]));
    cfg.supplied_dlls
        .insert("c:\\app\\TEST.dll".into(), Arc::from([]));
    assert!(
        WindowsProcess::spawn_image(cfg, vec![])
            .unwrap_err_message()
            .contains("case-colliding")
    );
}

trait ErrorMessage {
    fn unwrap_err_message(self) -> String;
}
impl ErrorMessage for Result<WindowsProcess, SpawnError> {
    fn unwrap_err_message(self) -> String {
        match self {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected spawn error"),
        }
    }
}

#[test]
fn default_host_entropy_starts_a_process_without_unix_device_paths() {
    let bytes = include_bytes!("../../../../tests/fixtures/user/windows/bin/x64/smoke.exe");
    let mut cfg = WindowsConfig::new("smoke.exe", vec![]);
    cfg.arena_bytes = 64 << 20;
    assert!(cfg.seed.is_none());
    let mut p = WindowsProcess::spawn_image(cfg, bytes.to_vec()).unwrap();
    assert_eq!(p.run(), ExitStatus::Exited(0));
    let cfg = WindowsConfig::embedded("C:\\smoke.exe", vec![], vec![], 0).unwrap();
    let mut p = WindowsProcess::spawn_image(cfg, bytes.to_vec()).unwrap();
    assert_eq!(p.run(), ExitStatus::Exited(0));
}
