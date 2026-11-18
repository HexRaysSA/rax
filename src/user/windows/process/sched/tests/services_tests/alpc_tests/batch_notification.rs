use super::*;

const CONSOLE: u64 = 0x2764;
const API: u32 = 0x0001_0010;
const LENGTH_OFFSET: u64 = 128;

fn request(p: &Proc, base: u64, port: u32, console: u64, started: u32) -> [u64; 8] {
    p.space.wr(base, &[0; 80]).unwrap();
    p.space.w16(base, 40).unwrap();
    p.space.w16(base + 2, 80).unwrap();
    p.space.w32(base + 48, API).unwrap();
    p.space.w64(base + 64, console).unwrap();
    p.space.w32(base + 72, started).unwrap();
    p.space.w64(base + LENGTH_OFFSET, 952).unwrap();
    [
        port.into(),
        0x20000,
        base,
        0,
        base,
        base + LENGTH_OFFSET,
        0,
        0,
    ]
}

fn peer(p: &Proc, port: u32) -> &crate::user::windows::object_namespace::csr::CsrPeer {
    let Some(Object::LpcPort(endpoint)) = p.objects.get(port.into()) else {
        panic!("typed CSR endpoint");
    };
    endpoint.peer().unwrap()
}

#[test]
fn native_cmd_batch_notification_echoes_payload_and_reports_refusal_inside_transport_reply() {
    let (mut process, mut t) = fixture(WinArch::Arm64, "NtAlpcSendWaitReceivePort", SERVICE);
    let p = process.state_mut();
    let base =
        p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
            .unwrap()
            .0;
    let (port, _, _, _) = csr_setup_for_profile(p, 0, 29708, 1);
    let before = (
        p.vm.committed_bytes(),
        peer(p, port).vm.committed_bytes(),
        p.objects.handle_count(),
        p.rng,
    );

    for (id, console, started) in [(1, CONSOLE, 1), (2, CONSOLE, 0), (3, 0, 1), (4, 0, 0)] {
        let args = request(p, base, port, console, started);
        let payload = p.space.bytes(base + 40, 40).unwrap();
        p.space.w64(base + 80, 0xDEAD_BEEF_DEAD_BEEF).unwrap();
        assert_eq!(invoke(p, &mut t, &args), Outcome::Continue);
        assert_eq!(t.cpu.gpr(0), u64::from(STATUS_SUCCESS));
        assert_eq!(p.space.bytes(base, 8).unwrap(), [40, 0, 80, 0, 2, 0, 0, 0]);
        let peer = peer(p, port);
        assert_eq!(p.space.u64(base + 8).unwrap(), u64::from(peer.server_pid));
        assert_eq!(
            p.space.u64(base + 16).unwrap(),
            u64::from(peer.server_thread)
        );
        assert_eq!(p.space.u32(base + 24).unwrap(), id);
        assert_eq!(p.space.u64(base + 32).unwrap(), u64::from(id));
        let mut expected = payload;
        expected[12..16].copy_from_slice(&STATUS_NOT_SUPPORTED.to_le_bytes());
        assert_eq!(p.space.bytes(base + 40, 40).unwrap(), expected);
        assert_eq!(p.space.u64(base + 80).unwrap(), 0xDEAD_BEEF_DEAD_BEEF);
        assert_eq!(p.space.u64(base + LENGTH_OFFSET).unwrap(), 80);
        assert_eq!(
            (
                p.vm.committed_bytes(),
                peer.vm.committed_bytes(),
                p.objects.handle_count(),
                p.rng
            ),
            before
        );
    }
}

#[test]
fn native_cmd_batch_notification_rejects_unmeasured_packets_and_peer_profiles() {
    let (mut process, mut t) = fixture(WinArch::Arm64, "NtAlpcSendWaitReceivePort", SERVICE);
    let p = process.state_mut();
    let base =
        p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
            .unwrap()
            .0;
    let (port, _, _, _) = csr_setup_for_profile(p, 0, 29708, 1);
    let (other_session, _, _, _) = csr_setup_for_profile(p, 0, 29708, 0);
    let (other_kernel, _, _, _) = csr_setup_for_profile(p, 0, 29704, 1);
    Arc::make_mut(&mut p.cfg).version.build = 29708;

    for (offset, value) in [(40, 1), (52, 1), (56, 1), (64, u64::MAX), (72, 2)] {
        let args = request(p, base, port, CONSOLE, 1);
        p.space.w64(base + offset, value).unwrap();
        let original = p.space.bytes(base, 136).unwrap();
        assert!(
            matches!(invoke(p, &mut t, &args), Outcome::Fail(reason) if reason.contains("unmeasured CSR message/profile"))
        );
        assert_eq!(p.space.bytes(base, 136).unwrap(), original);
    }
    for unmeasured in [other_session, other_kernel] {
        let args = request(p, base, unmeasured, CONSOLE, 1);
        let original = p.space.bytes(base, 136).unwrap();
        assert!(
            matches!(invoke(p, &mut t, &args), Outcome::Fail(reason) if reason.contains("peer outside the selected profile"))
        );
        assert_eq!(p.space.bytes(base, 136).unwrap(), original);
    }

    let args = request(p, base, port, CONSOLE, 1);
    assert_eq!(invoke(p, &mut t, &args), Outcome::Continue);
    assert_eq!(p.space.u32(base + 24).unwrap(), 1);
}
