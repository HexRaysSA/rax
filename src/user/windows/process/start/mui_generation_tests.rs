use super::*;
use crate::user::windows::{WindowsConfig, WindowsProcess};

#[test]
fn installed_mui_generation_is_published_in_the_readonly_guest_shared_page() {
    let arch = if cfg!(target_arch = "aarch64") {
        WinArch::Arm64
    } else if cfg!(target_arch = "x86_64") {
        WinArch::X64
    } else {
        WinArch::X86
    };
    let file = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/user/windows/bin")
        .join(arch.name())
        .join("smoke.exe");
    let mut cfg = WindowsConfig::embedded("C:\\app\\smoke.exe", vec![], vec![], 4096).unwrap();
    cfg.native_libraries = true;
    let process = WindowsProcess::spawn_image(cfg, std::fs::read(file).unwrap()).unwrap();
    let p = process.state();
    let generation = p.nls.as_ref().unwrap().mui_generation();
    let measured = crate::user::windows::nls::supports_startup_profile(&p.cfg.version);
    assert_eq!(generation.is_some(), measured);
    assert_eq!(
        p.space
            .u32(layout::KUSER_SHARED_DATA + kuser::LANG_GENERATION_COUNT)
            .unwrap(),
        generation.unwrap_or(0)
    );
    assert_eq!(
        p.vm.query(layout::KUSER_SHARED_DATA).unwrap().protect,
        prot::READONLY
    );
}
