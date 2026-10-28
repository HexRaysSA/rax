use super::*;
use crate::user::mm::SharedObject;
use crate::user::windows::object_namespace::csr::{CsrServer, client_data};
use crate::user::windows::objects::LpcPort;
use std::sync::Arc;

const SERVICE: u32 = 0x8E;

#[path = "alpc_tests/replay.rs"]
mod replay;

#[path = "alpc_tests/limits.rs"]
mod limits;

fn invoke(p: &mut Proc, t: &mut Thread, args: &[u64; 8]) -> Outcome {
    super::nls_tests::arguments(p, t, args);
    if p.arch != WinArch::Arm64 {
        t.cpu.set_gpr(0, SERVICE.into());
    }
    let sp = t.cpu.sp();
    let outcome = if p.arch == WinArch::X86 {
        super::super::super::super::services::wow64(p, t, 0x1234_0000)
    } else {
        handle_stop(p, t, stop(p.arch, SERVICE))
    };
    if outcome == Outcome::Continue {
        assert_eq!(t.cpu.pc(), 0x1234_0004);
        assert_eq!(t.cpu.sp(), sp + if p.arch == WinArch::X86 { 4 } else { 0 });
        assert!(t.frames.is_empty());
    }
    t.cpu.set_sp(sp);
    outcome
}

#[test]
fn native_alpc_invalid_handle_is_kernel_status_without_output_publication_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t) = fixture(arch, "NtAlpcSendWaitReceivePort", SERVICE);
        let p = process.state_mut();
        let base =
            p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        p.space.wr(base, &[0xA5; 256]).unwrap();
        let header = if arch.is64() { 40 } else { 24 };
        p.space.w16(base, 48).unwrap();
        p.space.w16(base + 2, header + 48).unwrap();
        p.space.w32(base + 4, 0).unwrap();
        p.space.wptr(base + 128, arch.ptr_size(), 952).unwrap();
        let original = p.space.bytes(base, 256).unwrap();
        let before = (p.objects.handle_count(), p.vm.committed_bytes(), p.rng);
        assert_eq!(
            invoke(p, &mut t, &[0, 0x20000, base, 0, base, base + 128, 0, 0]),
            Outcome::Continue
        );
        assert_eq!(t.cpu.gpr(0), u64::from(STATUS_INVALID_HANDLE));
        assert_eq!(p.space.bytes(base, 256).unwrap(), original);
        assert_eq!(
            (p.objects.handle_count(), p.vm.committed_bytes(), p.rng),
            before
        );
    }
}

fn csr_setup(
    p: &mut Proc,
    fixture_index: usize,
) -> (u32, u64, u64, Arc<client_data::CsrClientData>) {
    let (section, server) = super::secure_connect_tests::csr::server();
    let data = client_data::native_fixture(fixture_index);
    let server =
        CsrServer::selected_with_client_data(section, server.metadata.clone(), Some(data.clone()))
            .unwrap();
    let backing = Arc::new(SharedObject::anonymous(65536).unwrap());
    let peer = server.peer(backing.clone(), 65536).unwrap();
    let remote = peer.base;
    let view = p.vm.map_shared_view(backing, None, 0, 65536).unwrap();
    let local = view.base;
    let object = p.objects.create(Object::LpcPort(LpcPort::csr(view, peer)));
    let handle = p.objects.open_access(object, false, 0x1F0001).unwrap();
    Arc::make_mut(&mut p.cfg).version.major = 10;
    Arc::make_mut(&mut p.cfg).version.build = 29683;
    (handle, local, remote, data)
}

fn csr_request(p: &Proc, base: u64, local: u64, remote: u64, port: u32) -> [u64; 8] {
    p.space.wr(base, &[0; 1024]).unwrap();
    p.space.w16(base, 48).unwrap();
    p.space.w16(base + 2, 88).unwrap();
    p.space.w64(base + 40, remote + 0x750).unwrap();
    p.space.w64(base + 64, 3).unwrap();
    p.space.w64(base + 72, remote + 0x778).unwrap();
    p.space.w64(base + 80, 584).unwrap();
    p.space.w64(base + 1024, 952).unwrap();
    p.space.wr(local + 0x750, &[0; 628]).unwrap();
    p.space.w32(local + 0x750, 628).unwrap();
    p.space.w64(local + 0x758, 0xBADF_00D0_1234_5678).unwrap();
    p.space.w32(local + 0x760, 1).unwrap();
    p.space.w64(local + 0x770, 72).unwrap();
    [port.into(), 0x20000, base, 0, base, base + 1024, 0, 0]
}

#[test]
fn native_alpc_csr_exchange_owns_repeated_reply_mappings_and_server_capture() {
    for build in [29683, 29695] {
        for fixture_index in 0..4 {
            let (mut process, mut t) =
                fixture(WinArch::Arm64, "NtAlpcSendWaitReceivePort", SERVICE);
            let p = process.state_mut();
            let base =
                p.vm.allocate(None, 4096, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                    .unwrap()
                    .0;
            let (port, local, remote, data) = csr_setup(p, fixture_index);
            Arc::make_mut(&mut p.cfg).version.build = build;
            let before = p.vm.committed_bytes();
            let handles = p.objects.handle_count();
            let rng = p.rng;
            for expected_id in 1..=4 {
                let duplicate = p
                    .objects
                    .open_access(p.objects.id(port.into()).unwrap(), false, 1)
                    .unwrap();
                let mut args = csr_request(p, base, local, remote, port);
                args[0] = u64::from(duplicate) | u64::from(expected_id - 1);
                assert_eq!(invoke(p, &mut t, &args), Outcome::Continue);
                assert_eq!(t.cpu.gpr(0), 0);
                assert_eq!(p.space.u16(base).unwrap(), 48);
                assert_eq!(p.space.u16(base + 2).unwrap(), 88);
                assert_eq!(p.space.u16(base + 4).unwrap(), 2);
                assert_eq!(p.space.u32(base + 24).unwrap(), expected_id);
                assert_eq!(p.space.u64(base + 1024).unwrap(), 88);
                assert_eq!(p.space.u64(local + 0x758).unwrap(), 0);
                assert_eq!(p.space.bytes(local + 0x778, 584).unwrap(), data.information);
                assert_eq!(p.vm.committed_bytes(), before + 40960);
                p.objects.close(duplicate.into()).unwrap();
                assert_eq!(p.objects.handle_count(), handles);
                assert_eq!(p.rng, rng);
                let Some(Object::LpcPort(endpoint)) = p.objects.get(port.into()) else {
                    panic!("typed peer")
                };
                let peer = endpoint.peer().unwrap();
                let capture = p.space.u64(base + 40).unwrap();
                assert_eq!(peer.vm.space().u32(capture).unwrap(), 628);
                assert_eq!(peer.vm.space().u64(capture + 8).unwrap(), 0);
                assert_eq!(
                    peer.vm.space().bytes(capture + 40, 584).unwrap(),
                    data.information
                );
                assert!(p.space.u8(capture).is_err());
                assert_eq!(p.space.u64(base + 8).unwrap(), u64::from(peer.server_pid));
                assert_eq!(
                    p.space.u64(base + 16).unwrap(),
                    u64::from(peer.server_thread)
                );
            }
            p.objects.close(port.into()).unwrap();
            p.reclaim_scheduler_views().unwrap();
            assert!(p.vm.allocation(local).is_none());
            for view in &data.views {
                assert!(p.vm.owns_readonly_data_view(view.base, &view.section));
            }
        }
    }
}

#[test]
fn native_alpc_csr_rejects_foreign_capture_and_changed_schema_without_publication() {
    for variant in 0..10 {
        let (mut process, mut t) = fixture(WinArch::Arm64, "NtAlpcSendWaitReceivePort", SERVICE);
        let p = process.state_mut();
        let base =
            p.vm.allocate(None, 4096, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        let (port, local, remote, data) = csr_setup(p, 0);
        let args = csr_request(p, base, local, remote, port);
        match variant {
            0 => p.space.w64(base + 40, remote + 65536).unwrap(),
            1 => p.space.w32(local + 0x760, 2).unwrap(),
            2 => p.space.w64(local + 0x770, 80).unwrap(),
            3 => p.space.w8(local + 0x778, 1).unwrap(),
            4 => {
                p.vm.release(local).unwrap();
            }
            5 => Arc::make_mut(&mut p.cfg).version.build = 26100,
            6 => Arc::make_mut(&mut p.cfg).version.build = 29694,
            7 => Arc::make_mut(&mut p.cfg).version.build = 29696,
            8 => Arc::make_mut(&mut p.cfg).version.minor = 1,
            9 => Arc::make_mut(&mut p.cfg).version.major = 11,
            _ => unreachable!(),
        }
        let before = (p.vm.committed_bytes(), p.objects.handle_count(), p.rng);
        let output = p.space.bytes(base, 1032).unwrap();
        assert!(
            matches!(invoke(p,&mut t,&args),Outcome::Fail(reason) if reason.contains("NtAlpcSendWaitReceivePort"))
        );
        assert_eq!(p.space.bytes(base, 1032).unwrap(), output);
        assert_eq!(
            (p.vm.committed_bytes(), p.objects.handle_count(), p.rng),
            before
        );
        for view in &data.views {
            assert!(p.vm.allocation(view.base).is_none());
        }
    }
}
