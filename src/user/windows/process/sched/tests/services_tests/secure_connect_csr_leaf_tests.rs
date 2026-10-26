//! Execute installed native DLL entries against the selected guest CSR model.
use super::super::installed::leaf;
use super::*;
use crate::user::windows::process::{WindowsConfig, WindowsProcess};

#[test]
fn native_secure_connect_csr_installed_arm64_success_has_real_section_and_matching_host_metadata() {
    let image =
        include_bytes!("../../../../../../../tests/fixtures/user/windows/bin/arm64/smoke.exe");
    let mut config =
        WindowsConfig::embedded("C:\\native-csr-model.exe", vec![], vec![], 4096).unwrap();
    config.native_libraries = true;
    config.arena_bytes = 256 << 20;
    let mut process = WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
    let p = process.state_mut();
    let path: Vec<_> = "\\Windows\\ApiPort".encode_utf16().collect();
    let selected = p.object_namespace.csr_server(&path);
    if !crate::user::windows::object_namespace::csr::supports_kernel(
        p.cfg.version.major,
        p.cfg.version.minor,
        p.cfg.version.build,
    ) {
        assert!(
            selected.is_err(),
            "unmeasured native build must expose no selected CSR success profile"
        );
        eprintln!(
            "Validated unavailable CSR model path for native build {}",
            p.cfg.version.build
        );
        return;
    }
    let server = selected.expect("measured native ARM64/session0 CSR metadata must be selected");
    let tid = *p.threads.keys().next().unwrap();
    let mut thread = p.threads.remove(&tid).unwrap();
    let b = scratch(p, 65536);
    p.space.w64(b + 60008, 65536).unwrap();
    assert_eq!(
        leaf(
            p,
            &mut thread,
            "NtCreateSection",
            &[
                b + 60000,
                0xF001F,
                0,
                b + 60008,
                prot::READWRITE.into(),
                0x0800_0000,
                0
            ]
        ),
        STATUS_SUCCESS
    );
    let section = p.space.u64(b + 60000).unwrap();
    let args = packet(p, b, Some(u32::try_from(section).unwrap()));
    assert_eq!(
        leaf(p, &mut thread, "NtSecureConnectPort", &args),
        STATUS_SUCCESS
    );
    let handle = p.space.u64(args[0]).unwrap();
    let local = p.space.u64(args[3] + 32).unwrap();
    let remote = p.space.u64(args[3] + 40).unwrap();
    assert_eq!(p.space.u64(args[7]).unwrap(), server.metadata.server_base);
    assert_eq!(
        p.space.u64(args[7] + 8).unwrap(),
        server.metadata.server_base + server.metadata.statics_offset
    );
    assert_eq!(
        p.space.u64(args[7] + 16).unwrap(),
        u64::from(server.metadata.server_pid)
    );
    assert_eq!(p.space.u32(args[6]).unwrap(), 952);
    assert_eq!(p.space.u32(args[8]).unwrap(), 48);
    let Some(Object::LpcPort(port)) = p.objects.get(handle) else {
        panic!("typed native CSR endpoint")
    };
    let peer = port.peer().unwrap();
    assert_eq!(peer.base, remote);
    assert!(!peer.vm.space().same_space(&p.space));
    p.space.w32(local + 4094, 0x6996_1234).unwrap();
    assert_eq!(peer.vm.space().u32(remote + 4094).unwrap(), 0x6996_1234);
    assert_eq!(leaf(p, &mut thread, "NtClose", &[section]), STATUS_SUCCESS);
    assert!(
        p.vm.is_shared_view(local),
        "section handle close preserves connection view"
    );
    assert_eq!(leaf(p, &mut thread, "NtClose", &[handle]), STATUS_SUCCESS);
    assert!(p.vm.allocation(local).is_none());
    eprintln!(
        "Validated installed ARM64 NtCreateSection/NtSecureConnectPort/NtClose with matched native CSR metadata"
    );
}
