//! Cookie ownership follows measured native suspended-child startup, for all
//! guest ABIs. Empty native metadata selects ownership without host acquisition.
use super::*;
use crate::user::windows::native::NativeRuntime;
use crate::user::windows::process::{WindowsConfig, WindowsProcess};

fn source(arch: WinArch) -> &'static [u8] {
    match arch {
        WinArch::X86 => include_bytes!("../../../../tests/fixtures/user/windows/bin/x86/smoke.exe"),
        WinArch::X64 => include_bytes!("../../../../tests/fixtures/user/windows/bin/x64/smoke.exe"),
        WinArch::Arm64 => {
            include_bytes!("../../../../tests/fixtures/user/windows/bin/arm64/smoke.exe")
        }
    }
}

fn default_cookie(arch: WinArch) -> u64 {
    if arch.is64() {
        0x2B99_2DDF_A232
    } else {
        0xBB40_E64E
    }
}

fn image(arch: WinArch) -> PeImage {
    let mut bytes = source(arch).to_vec();
    let pe = PeImage::parse(bytes.clone()).unwrap();
    let nt = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
    let directories = nt + 24 + if arch.is64() { 112 } else { 96 };
    let size = if arch.is64() { 96u32 } else { 64u32 };
    bytes[directories + dir::LOAD_CONFIG * 8..][..4].copy_from_slice(&0x300u32.to_le_bytes());
    bytes[directories + dir::LOAD_CONFIG * 8 + 4..][..4].copy_from_slice(&size.to_le_bytes());
    bytes[0x300..0x304].copy_from_slice(&size.to_le_bytes());
    let field = 0x300 + if arch.is64() { 88 } else { 60 };
    let width = arch.ptr_size() as usize;
    let cookie = (pe.headers().image_base + 0x380).to_le_bytes();
    bytes[field..field + width].copy_from_slice(&cookie[..width]);
    bytes[0x380..0x380 + width].copy_from_slice(&default_cookie(arch).to_le_bytes()[..width]);
    PeImage::parse(bytes).unwrap()
}

fn runtime() -> NativeRuntime {
    let schema: Vec<u8> = [6u32, 28, 0, 0, 28, 28, 0]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    NativeRuntime {
        directory: Default::default(),
        guest_root: "C:\\Windows".into(),
        guest_directory: "C:\\Windows\\System32".into(),
        version: Default::default(),
        apisets: apiset_schema::ApiSetSchema::parse(&schema).unwrap(),
        registry: Default::default(),
        object_namespace: Default::default(),
        nls: None,
        appcompat: Default::default(),
        wnf_catalog: Default::default(),
        startup: None,
        code_integrity: Err("controlled absent code integrity metadata".into()),
        code_integrity_policy: Err("code integrity policy not captured in this fixture".into()),
        gui: Default::default(),
    }
}

fn fixture(arch: WinArch) -> (WindowsProcess, PeImage, u64) {
    let pe = image(arch);
    let mut cfg = WindowsConfig::embedded("C:\\cookie.exe", vec![], vec![], 4096).unwrap();
    cfg.arena_bytes = 64 << 20;
    let process = WindowsProcess::spawn_image(cfg, pe.bytes().to_vec()).unwrap();
    let base = process.state().modules.exe().base;
    (process, pe, base)
}

fn store(p: &mut Proc, address: u64, value: u64) {
    p.vm.poke(address, &value.to_le_bytes()[..p.arch.ptr_size() as usize])
        .unwrap();
}

fn read_cookie(p: &Proc, base: u64) -> u64 {
    if p.arch.is64() {
        p.space.u64(base + 0x380).unwrap()
    } else {
        u64::from(p.space.u32(base + 0x380).unwrap())
    }
}

#[test]
fn native_cookie_mapping_preserves_default_custom_and_zero_without_entropy_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, pe, base) = fixture(arch);
        let p = process.state_mut();
        assert!(!p.cfg.native_libraries);
        p.native = Some(runtime());
        for value in [default_cookie(arch), 0, 0x1234_5678, arch.ptr(u64::MAX)] {
            store(p, base + 0x380, value);
            let rng = p.rng;
            init_security_cookie(p, &pe, base).unwrap();
            assert_eq!(read_cookie(p, base), value, "{arch}/{value:#x}");
            assert_eq!(p.rng, rng, "native cookie does not consume HLE entropy");
        }
    }
}

#[test]
fn builtin_cookie_initialization_and_existing_values_remain_unchanged_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, pe, base) = fixture(arch);
        let p = process.state_mut();
        assert!(p.native.is_none());
        // Spawn traversed finish_exe; also exercise the common DLL initializer.
        let initial = read_cookie(p, base);
        assert_ne!(initial, default_cookie(arch));
        assert_ne!(initial, 0);
        for value in [0, 0x1234_5678, arch.ptr(u64::MAX)] {
            store(p, base + 0x380, value);
            let rng = p.rng;
            init_security_cookie(p, &pe, base).unwrap();
            assert_eq!(read_cookie(p, base), value);
            assert_eq!(p.rng, rng);
        }
        store(p, base + 0x380, default_cookie(arch));
        let rng = p.rng;
        init_security_cookie(p, &pe, base).unwrap();
        let seeded = read_cookie(p, base);
        assert_ne!(seeded, 0);
        assert_ne!(seeded, default_cookie(arch));
        assert_ne!(p.rng, rng);
        if arch.is64() {
            assert_eq!(seeded >> 48, 0);
        }
    }
}

#[test]
fn native_cookie_deferral_keeps_foreign_cookie_rejection_and_does_not_consume_entropy() {
    for arch in WinArch::ALL {
        for native in [false, true] {
            let (mut process, pe, base) = fixture(arch);
            let p = process.state_mut();
            if native {
                p.native = Some(runtime());
            }
            let field = base + 0x300 + if arch.is64() { 88 } else { 60 };
            store(p, field, arch.ptr(u64::MAX));
            let rng = p.rng;
            let before = read_cookie(p, base);
            let error = init_security_cookie(p, &pe, base).unwrap_err();
            assert_eq!(error.status, STATUS_INVALID_IMAGE_FORMAT, "{arch}/{native}");
            assert_eq!(read_cookie(p, base), before);
            assert_eq!(p.rng, rng);
        }
    }
}
