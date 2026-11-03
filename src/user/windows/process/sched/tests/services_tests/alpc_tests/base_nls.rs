use super::*;
use crate::user::windows::object_namespace::csr::{BASE_NLS_BYTES, BaseNlsReply};

const NATIVE: &[u8; BASE_NLS_BYTES] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/docs/specifications/windows/native-base-csr-nls/native-user-information-v1.bin"
));

const SYSTEM: &[u8; BASE_NLS_BYTES] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/docs/specifications/windows/native-base-csr-nls/native-system-information-v1.bin"
));

fn setup(p: &mut Proc, information: Arc<[u8; BASE_NLS_BYTES]>) -> (u32, u64, u64) {
    let (section, server) = super::super::secure_connect_tests::csr::server_for_kernel(29698);
    let server = CsrServer::selected_with_data(
        section,
        server.metadata.clone(),
        None,
        Some(BaseNlsReply::Information(information)),
    )
    .unwrap();
    let backing = Arc::new(SharedObject::anonymous(65536).unwrap());
    let peer = server.peer(backing.clone(), 65536).unwrap();
    let remote = peer.base;
    let view = p.vm.map_shared_view(backing, None, 0, 65536).unwrap();
    let local = view.base;
    let id = p.objects.create(Object::LpcPort(LpcPort::csr(view, peer)));
    let port = p.objects.open_access(id, false, 0x1F0001).unwrap();
    Arc::make_mut(&mut p.cfg).version.build = 29698;
    (port, local, remote)
}

fn request(p: &Proc, base: u64, local: u64, remote: u64, port: u32) -> [u64; 8] {
    p.space.wr(base, &[0; 1032]).unwrap();
    p.space.w16(base, 40).unwrap();
    p.space.w16(base + 2, 80).unwrap();
    p.space.w64(base + 40, remote + 0x750).unwrap();
    p.space.w32(base + 48, 0x1001B).unwrap();
    p.space.w64(base + 64, remote + 0x778).unwrap();
    p.space.w64(base + 72, BASE_NLS_BYTES as u64).unwrap();
    p.space.w64(base + 1024, 952).unwrap();
    // Native allocation padding and input data are BAADF00D poison. This is
    // an output-only payload, so zero input is not a precondition.
    let mut capture = [0u8; BASE_NLS_BYTES + 44];
    for bytes in capture.chunks_exact_mut(4) {
        bytes.copy_from_slice(&0xBAAD_F00Du32.to_le_bytes());
    }
    capture[..4].copy_from_slice(&1704u32.to_le_bytes());
    capture[16..20].copy_from_slice(&1u32.to_le_bytes());
    capture[24..32].fill(0);
    capture[32..40].copy_from_slice(&64u64.to_le_bytes());
    p.space.wr(local + 0x750, &capture).unwrap();
    [port.into(), 0x20000, base, 0, base, base + 1024, 0, 0]
}

#[test]
fn native_base_nls_reply_matches_opaque_snapshot_and_owns_capture_lifetime() {
    let (mut process, mut t) = fixture(WinArch::Arm64, "NtAlpcSendWaitReceivePort", SERVICE);
    let p = process.state_mut();
    let base =
        p.vm.allocate(None, 4096, mem::RESERVE | mem::COMMIT, prot::READWRITE)
            .unwrap()
            .0;
    let information = Arc::new(*NATIVE);
    let (port, local, remote) = setup(p, information.clone());
    let before = (p.vm.committed_bytes(), p.objects.handle_count(), p.rng);
    for id in 1..=3 {
        let args = request(p, base, local, remote, port);
        assert_eq!(invoke(p, &mut t, &args), Outcome::Continue);
        assert_eq!(t.cpu.gpr(0), 0);
        assert_eq!(p.space.u16(base).unwrap(), 40);
        assert_eq!(p.space.u16(base + 2).unwrap(), 80);
        assert_eq!(p.space.u16(base + 4).unwrap(), 2);
        assert_eq!(p.space.u32(base + 24).unwrap(), id);
        assert_eq!(p.space.u32(base + 48).unwrap(), 0x1001B);
        assert_eq!(p.space.u64(base + 64).unwrap(), remote + 0x778);
        assert_eq!(p.space.u64(base + 72).unwrap(), BASE_NLS_BYTES as u64);
        assert_eq!(p.space.u64(base + 1024).unwrap(), 80);
        assert_eq!(p.space.u64(local + 0x758).unwrap(), 0);
        assert_eq!(
            p.space.bytes(local + 0x778, BASE_NLS_BYTES).unwrap(),
            information.as_slice()
        );
        assert_eq!(
            (p.vm.committed_bytes(), p.objects.handle_count(), p.rng),
            before
        );
        let Some(Object::LpcPort(endpoint)) = p.objects.get(port.into()) else {
            panic!("typed peer")
        };
        let peer = endpoint.peer().unwrap();
        let capture = p.space.u64(base + 40).unwrap();
        assert_eq!(peer.vm.space().u32(capture).unwrap(), 1704);
        assert_eq!(peer.vm.space().u64(capture + 8).unwrap(), 0);
        assert_eq!(
            peer.vm.space().bytes(capture + 40, BASE_NLS_BYTES).unwrap(),
            information.as_slice()
        );
        assert!(p.space.u8(capture).is_err());
        assert_eq!(p.space.u64(base + 8).unwrap(), u64::from(peer.server_pid));
    }
    p.objects.close(port.into()).unwrap();
    p.reclaim_scheduler_views().unwrap();
    assert!(p.vm.allocation(local).is_none());
}

#[test]
fn native_base_nls_rejects_foreign_profile_capture_and_view_without_publication() {
    for variant in 0..12 {
        let (mut process, mut t) = fixture(WinArch::Arm64, "NtAlpcSendWaitReceivePort", SERVICE);
        let p = process.state_mut();
        let base =
            p.vm.allocate(None, 4096, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        let (port, local, remote) = setup(p, Arc::new(*NATIVE));
        let args = request(p, base, local, remote, port);
        match variant {
            0 => p.space.w32(base + 48, 0x1001C).unwrap(),
            1 => p.space.w64(base + 72, 1659).unwrap(),
            2 => p.space.w64(base + 64, remote + 0x780).unwrap(),
            3 => p.space.w64(base + 40, remote + 65536).unwrap(),
            4 => p.space.w32(local + 0x750, 1700).unwrap(),
            5 => p.space.w32(local + 0x760, 2).unwrap(),
            6 => p.space.w64(local + 0x768, 1).unwrap(),
            7 => p.space.w64(local + 0x770, 72).unwrap(),
            8 => Arc::make_mut(&mut p.cfg).version.build = 29695,
            9 => {
                p.vm.release(local).unwrap();
            }
            10 => Arc::make_mut(&mut p.cfg).version.major = 11,
            11 => Arc::make_mut(&mut p.cfg).version.minor = 1,
            _ => unreachable!(),
        }
        let before = (p.vm.committed_bytes(), p.objects.handle_count(), p.rng);
        let output = p.space.bytes(base, 1032).unwrap();
        assert!(matches!(invoke(p, &mut t, &args), Outcome::Fail(_)));
        assert_eq!(p.space.bytes(base, 1032).unwrap(), output);
        assert_eq!(
            (p.vm.committed_bytes(), p.objects.handle_count(), p.rng),
            before
        );
    }
}

#[test]
fn native_base_nls_absent_snapshot_is_explicit_and_never_uses_user_reply() {
    let (mut process, mut t) = fixture(WinArch::Arm64, "NtAlpcSendWaitReceivePort", SERVICE);
    let p = process.state_mut();
    let base =
        p.vm.allocate(None, 4096, mem::RESERVE | mem::COMMIT, prot::READWRITE)
            .unwrap()
            .0;
    let (port, local, remote, _) = csr_setup_for_kernel(p, 0, 29698);
    let args = request(p, base, local, remote, port);
    let output = p.space.bytes(base, 1032).unwrap();
    let before = (p.vm.committed_bytes(), p.objects.handle_count(), p.rng);
    assert!(matches!(invoke(p, &mut t, &args), Outcome::Fail(_)));
    assert_eq!(p.space.bytes(base, 1032).unwrap(), output);
    assert_eq!(
        (p.vm.committed_bytes(), p.objects.handle_count(), p.rng),
        before
    );
}

#[test]
fn native_base_nls_system_snapshot_remains_distinct_from_user_information() {
    let (mut process, mut t) = fixture(WinArch::Arm64, "NtAlpcSendWaitReceivePort", SERVICE);
    let p = process.state_mut();
    let base =
        p.vm.allocate(None, 4096, mem::RESERVE | mem::COMMIT, prot::READWRITE)
            .unwrap()
            .0;
    assert_ne!(SYSTEM, NATIVE);
    let (port, local, remote) = setup(p, Arc::new(*SYSTEM));
    let args = request(p, base, local, remote, port);
    assert_eq!(invoke(p, &mut t, &args), Outcome::Continue);
    assert_eq!(t.cpu.gpr(0), 0);
    assert_eq!(p.space.u32(base + 52).unwrap(), 0);
    assert_eq!(
        p.space.bytes(local + 0x778, BASE_NLS_BYTES).unwrap(),
        SYSTEM.as_slice()
    );
}

#[test]
fn native_base_nls_service_failure_preserves_input_and_successful_transport() {
    let (mut process, mut t) = fixture(WinArch::Arm64, "NtAlpcSendWaitReceivePort", SERVICE);
    let p = process.state_mut();
    let base =
        p.vm.allocate(None, 4096, mem::RESERVE | mem::COMMIT, prot::READWRITE)
            .unwrap()
            .0;
    let (port, local, remote) = setup(p, Arc::new(*SYSTEM));
    let Some(Object::LpcPort(endpoint)) = p.objects.get_mut(port.into()) else {
        panic!("typed peer")
    };
    endpoint.peer_mut().unwrap().base_nls = Some(BaseNlsReply::Unsuccessful);
    let args = request(p, base, local, remote, port);
    let before = p.space.bytes(local + 0x778, BASE_NLS_BYTES).unwrap();
    let resources = (p.vm.committed_bytes(), p.objects.handle_count(), p.rng);
    assert_eq!(invoke(p, &mut t, &args), Outcome::Continue);
    assert_eq!(t.cpu.gpr(0), 0, "ALPC transport succeeded");
    assert_eq!(p.space.u32(base + 52).unwrap(), STATUS_UNSUCCESSFUL);
    assert_eq!(p.space.u64(base + 1024).unwrap(), 80);
    assert_eq!(
        p.space.bytes(local + 0x778, BASE_NLS_BYTES).unwrap(),
        before
    );
    let Some(Object::LpcPort(endpoint)) = p.objects.get(port.into()) else {
        panic!("typed peer")
    };
    let capture = p.space.u64(base + 40).unwrap();
    assert_eq!(
        endpoint
            .peer()
            .unwrap()
            .vm
            .space()
            .bytes(capture + 40, BASE_NLS_BYTES)
            .unwrap(),
        before
    );
    assert_eq!(
        (p.vm.committed_bytes(), p.objects.handle_count(), p.rng),
        resources
    );
}

#[test]
fn native_base_nls_snapshot_requires_measured_server_profile() {
    for build in [29683, 29695] {
        let (section, server) = super::super::secure_connect_tests::csr::server_for_kernel(build);
        assert!(
            CsrServer::selected_with_data(
                section,
                server.metadata.clone(),
                None,
                Some(BaseNlsReply::Information(Arc::new(*NATIVE)))
            )
            .is_err()
        );
    }
}
