//! Real installed AMD64 NTDLL leaves against the captured current-session peer.
use super::super::secure_connect_tests::installed::leaf;
use super::*;
use crate::user::windows::process::{WindowsConfig, WindowsProcess};

#[test]
fn native_connect_csr_installed_amd64_uses_current_session_metadata_and_real_views() {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcessId() -> u32;
        fn ProcessIdToSessionId(pid: u32, session: *mut u32) -> i32;
    }
    let mut session = 0;
    // SAFETY: fixed current process and exclusive initialized DWORD output.
    assert_ne!(
        unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut session) },
        0
    );
    let image =
        include_bytes!("../../../../../../../tests/fixtures/user/windows/bin/x64/smoke.exe");
    let mut config =
        WindowsConfig::embedded("C:\\native-connect-csr.exe", vec![], vec![], 4096).unwrap();
    config.native_libraries = true;
    config.arena_bytes = 256 << 20;
    let mut process = WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
    let p = process.state_mut();
    let path = if session == 0 {
        "\\Windows\\ApiPort".to_string()
    } else {
        format!("\\Sessions\\{session}\\Windows\\ApiPort")
    };
    let selected = p
        .object_namespace
        .csr_server(&path.encode_utf16().collect::<Vec<_>>());
    if !crate::user::windows::object_namespace::csr::supports_profile(
        WinArch::X64,
        p.cfg.version.major,
        p.cfg.version.minor,
        p.cfg.version.build,
    ) {
        assert!(
            selected.is_err(),
            "unmeasured kernel cannot expose a selected CSR success profile"
        );
        eprintln!(
            "Validated unavailable AMD64 CSR path for native build{}",
            p.cfg.version.build
        );
        return;
    }
    let server = selected.expect("measured native AMD64 current-session CSR metadata");
    let captures = captures();
    let row = captures["projections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["kernel"][2].as_u64() == Some(p.cfg.version.build.into()))
        .unwrap();
    let tid = *p.threads.keys().next().unwrap();
    let mut thread = p.threads.remove(&tid).unwrap();
    let b = scratch(p, 65536);
    p.space.w32(p.peb + 0x2C0, session).unwrap();
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
                0x08000000,
                0
            ]
        ),
        STATUS_SUCCESS
    );
    let section = p.space.u64(b + 60000).unwrap();
    let args = packet(p, b, Some(section.try_into().unwrap()), row, session);
    let suffix = p.space.bytes(args[6] + 24, 24).unwrap();
    assert_eq!(leaf(p, &mut thread, "NtConnectPort", &args), STATUS_SUCCESS);
    assert_eq!(p.space.u64(args[6]).unwrap(), server.metadata.server_base);
    assert_eq!(
        p.space.u64(args[6] + 8).unwrap(),
        server.metadata.server_base + server.metadata.statics_offset
    );
    assert_eq!(
        p.space.u64(args[6] + 16).unwrap(),
        u64::from(server.metadata.server_pid)
    );
    assert_eq!(p.space.bytes(args[6] + 24, 24).unwrap(), suffix);
    assert_eq!(p.space.u32(args[5]).unwrap(), 952);
    let handle = p.space.u64(args[0]).unwrap();
    let local = p.space.u64(args[3] + 32).unwrap();
    let remote = p.space.u64(args[3] + 40).unwrap();
    let Some(Object::LpcPort(port)) = p.objects.get(handle) else {
        panic!("typed CSR endpoint")
    };
    let peer = port.peer().unwrap();
    assert_eq!(peer.base, remote);
    p.space.w32(local, 0xA1B2C3D4).unwrap();
    assert_eq!(peer.vm.space().u32(remote).unwrap(), 0xA1B2C3D4);
    assert_eq!(leaf(p, &mut thread, "NtClose", &[handle]), STATUS_SUCCESS);
    assert_eq!(leaf(p, &mut thread, "NtClose", &[section]), STATUS_SUCCESS);
    eprintln!(
        "Validated installed AMD64 NtConnectPort current session{session}, readonly metadata and owned views"
    );
}
