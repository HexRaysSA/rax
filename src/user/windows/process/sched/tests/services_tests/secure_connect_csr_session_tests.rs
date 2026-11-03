//! Replay a genuine ordinary-user first connection, with session-bound owners.
use super::super::connect_csr_tests::{data, namespace};
use super::*;
use serde_json::Value;

fn capture() -> Value {
    serde_json::from_str(include_str!(
        "../../../../../../../docs/specifications/windows/native-arm64-session-csr/profile-v1.json"
    ))
    .unwrap()
}

fn bytes(profile: &Value, key: &str) -> Vec<u8> {
    let hex = profile[key].as_str().unwrap();
    (0..hex.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap())
        .collect()
}

fn metadata(profile: &Value, session: u32) -> CsrMetadata {
    CsrMetadata {
        arch: WinArch::Arm64,
        kernel: (
            profile["kernel"][0].as_u64().unwrap() as u32,
            profile["kernel"][1].as_u64().unwrap() as u32,
            profile["kernel"][2].as_u64().unwrap() as u32,
        ),
        session,
        server_base: profile["server_base"].as_u64().unwrap(),
        statics_offset: profile["statics_offset"].as_u64().unwrap(),
        server_pid: profile["server_pid"].as_u64().unwrap() as u32,
    }
}

fn setup(p: &mut Proc, b: u64, session: u32, profile: &Value) -> [u64; 9] {
    let selected = metadata(profile, session);
    let section = data((session != 0).then_some(session), selected.server_base);
    p.object_namespace = namespace(session);
    if session != 0 {
        p.object_namespace
            .select_data_section(data(None, selected.server_base))
            .unwrap();
    }
    p.object_namespace
        .select_data_section(section.clone())
        .unwrap();
    p.object_namespace
        .select_csr_server(CsrServer::selected(section, selected.clone()).unwrap())
        .unwrap();
    Arc::make_mut(&mut p.cfg).version.major = selected.kernel.0;
    Arc::make_mut(&mut p.cfg).version.minor = selected.kernel.1;
    Arc::make_mut(&mut p.cfg).version.build = selected.kernel.2;
    p.space.w32(p.peb + 0x2C0, session).unwrap();
    let args = packet_for_session(p, b, None, session);
    let handle = p.space.u64(args[3] + 8).unwrap();
    for (address, key) in [
        (args[2], "qos_hex"),
        (args[3], "client_before_hex"),
        (args[4], "sid_hex"),
        (args[5], "remote_before_hex"),
        (args[7], "information_before_hex"),
    ] {
        p.space.wr(address, &bytes(profile, key)).unwrap();
    }
    // The replay substitutes only the real guest-owned section handle. Native
    // pointer-looking tail bytes remain opaque caller bytes and are preserved.
    p.space.w64(args[3] + 8, handle).unwrap();
    args
}

#[test]
fn native_secure_connect_csr_current_session_replays_first_native_reply_and_owned_views() {
    let profile = capture();
    assert_eq!(profile["session"], 1);
    for session in [0, 1, 42, u32::MAX] {
        let (mut process, mut thread) = fixture(WinArch::Arm64, "NtSecureConnectPort", SERVICE);
        let p = process.state_mut();
        let b = scratch(p, 65536);
        let args = setup(p, b, session, &profile);
        let before = p.vm.committed_bytes();
        let client = p.space.bytes(args[3], 32).unwrap();
        assert_eq!(invoke(p, &mut thread, &args), Outcome::Continue);
        assert_eq!(thread.cpu.gpr(0), u64::from(STATUS_SUCCESS));
        assert_eq!(
            p.space.bytes(args[7], 48).unwrap(),
            bytes(&profile, "information_after_hex")
        );
        assert_eq!(p.space.bytes(args[3], 32).unwrap(), client);
        assert_eq!(
            p.space.bytes(args[5], 24).unwrap(),
            bytes(&profile, "remote_after_hex")
        );
        assert_eq!(
            u64::from(p.space.u32(args[6]).unwrap()),
            profile["maximum_message"].as_u64().unwrap()
        );
        assert_eq!(p.space.u32(args[8]).unwrap(), 48);
        let handle = p.space.u64(args[0]).unwrap();
        let local = p.space.u64(args[3] + 32).unwrap();
        let remote = p.space.u64(args[3] + 40).unwrap();
        let Some(Object::LpcPort(port)) = p.objects.get(handle) else {
            panic!("typed selected CSR endpoint")
        };
        let peer = port.peer().unwrap();
        assert!(!peer.vm.space().same_space(&p.space));
        assert_eq!(peer.base, remote);
        assert_eq!(
            peer.server_pid,
            profile["server_pid"].as_u64().unwrap() as u32
        );
        p.space.w32(local, 0xA55A_6996).unwrap();
        assert_eq!(peer.vm.space().u32(remote).unwrap(), 0xA55A_6996);
        assert_eq!(p.vm.committed_bytes(), before + 65536);
        p.objects.close(handle).unwrap();
        p.reclaim_scheduler_views().unwrap();
        assert!(p.vm.allocation(local).is_none());
        assert_eq!(p.vm.committed_bytes(), before);
    }
}

#[test]
fn native_secure_connect_csr_current_session_rejects_foreign_guest_binding_without_publication() {
    let profile = capture();
    for variant in 0..4 {
        let (mut process, mut thread) = fixture(WinArch::Arm64, "NtSecureConnectPort", SERVICE);
        let p = process.state_mut();
        let b = scratch(p, 65536);
        let args = setup(p, b, 1, &profile);
        if variant == 3 {
            name(p, args[1], b + 256, "\\Windows\\ApiPort");
        } else {
            p.space
                .w32(p.peb + 0x2C0, [0, 2, u32::MAX][variant])
                .unwrap();
        }
        let bytes = p.space.bytes(b, 65536).unwrap();
        let counts = (
            p.objects.handle_count(),
            p.objects.iter().count(),
            p.vm.committed_bytes(),
        );
        assert!(matches!(invoke(p, &mut thread, &args), Outcome::Fail(_)));
        assert_eq!(p.space.bytes(b, 65536).unwrap(), bytes);
        assert_eq!(
            (
                p.objects.handle_count(),
                p.objects.iter().count(),
                p.vm.committed_bytes()
            ),
            counts
        );
    }
}

#[test]
fn csr_current_session_selection_rejects_global_foreign_and_copied_section_owners() {
    let profile = capture();
    let metadata = metadata(&profile, 1);
    for wrong_session in [None, Some(1), Some(2)] {
        let mut selected = namespace(1);
        selected
            .select_data_section(data(Some(1), metadata.server_base))
            .unwrap();
        let foreign = data(wrong_session, metadata.server_base);
        let server = CsrServer::selected(foreign, metadata.clone()).unwrap();
        assert!(selected.select_csr_server(server).is_err());
        assert!(selected.selected_csr_server().is_err());
    }
}
