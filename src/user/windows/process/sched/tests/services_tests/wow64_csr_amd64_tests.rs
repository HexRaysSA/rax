//! Captured AMD64 identity admission and current-session CSR ownership.
use super::*;
use crate::user::windows::layout::offsets;
use crate::user::windows::object_namespace::csr::{CsrMetadata, CsrServer};
use crate::user::windows::wnf;

#[path = "wow64_csr_amd64_replay_tests.rs"]
mod replay;

fn setup(build: u32, session: u32) -> (WindowsProcess, Thread, u64) {
    let (mut process, thread) = fixture(WinArch::X86, NAME, SERVICE);
    let p = process.state_mut();
    let version = &mut Arc::make_mut(&mut p.cfg).version;
    version.major = 10;
    version.minor = 0;
    version.build = build;
    p.objects.select_wnf_catalog(
        wnf::tests::empty_subject_catalog(false)
            .with_primary_token_session_id(session.wrapping_add(1))
            .with_queries(wnf::Queries::selected(vec![], session).unwrap()),
    );
    p.space
        .w32(p.peb + offsets(WinArch::X86).peb_session_id, session)
        .unwrap();
    wow64::initialize_test_profile(p, 0x8664).unwrap();
    let section = super::super::connect_csr_tests::data(Some(session), 0x1234_0000_0000);
    p.object_namespace = super::super::connect_csr_tests::namespace(session);
    p.object_namespace
        .select_data_section(section.clone())
        .unwrap();
    // Session zero's selected CSR owner uses the global object rather than the
    // explicit Sessions\0 alias. Keep both independently selected fixture roots.
    let section = if session == 0 {
        let global = super::super::connect_csr_tests::data(None, 0x1234_0000_0000);
        p.object_namespace
            .select_data_section(global.clone())
            .unwrap();
        global
    } else {
        section
    };
    p.object_namespace
        .select_csr_server(
            CsrServer::selected(
                section,
                CsrMetadata {
                    arch: WinArch::X64,
                    kernel: (10, 0, build),
                    session,
                    server_base: 0x1234_0000_0000,
                    statics_offset: 0x750,
                    server_pid: 1236,
                },
            )
            .unwrap(),
        )
        .unwrap();
    let b =
        p.vm.allocate(None, 16384, mem::RESERVE | mem::COMMIT, prot::READWRITE)
            .unwrap()
            .0;
    let directory = p
        .object_namespace
        .selected_csr_server()
        .unwrap()
        .metadata
        .directory_path();
    p.space.put_wstr(b, &directory).unwrap();
    p.space.wr(b + 4096, &[0xa5; 80]).unwrap();
    p.space.w8(b + 8192, 0xa5).unwrap();
    (process, thread, b)
}

#[test]
fn wow64_csr_amd64_binds_captured_process_session_and_owns_both_views() {
    for build in [20348, 26100] {
        for session in [0, 2, 7, u32::MAX] {
            let (mut process, mut thread, b) = setup(build, session);
            let p = process.state_mut();
            let state = p.wow64.as_ref().unwrap();
            assert_eq!(state.session, session);
            assert_eq!(
                p.space
                    .u32(state.native_peb + offsets(WinArch::X64).peb_session_id)
                    .unwrap(),
                session
            );
            assert_ne!(p.objects.primary_token_session_id(), Some(session));
            let handles = p.objects.handle_count();
            assert_eq!(invoke(p, &mut thread, &args(b)), STATUS_SUCCESS);
            assert_eq!(p.objects.handle_count(), handles + 1);
            assert_eq!(p.space.u8(b + 8192).unwrap(), 0);
            assert_eq!(p.space.bytes(b + 4096, 80).unwrap(), [0xa5; 80]);
            publication(p, true);
        }
    }
}

#[test]
fn wow64_csr_amd64_rejects_foreign_kernel_machine_and_mutated_session_identity() {
    for build in [20348, 26100] {
        for mutation in 0..8 {
            let (mut process, mut thread, b) = setup(build, 2);
            let p = process.state_mut();
            let state = p.wow64.as_mut().unwrap();
            match mutation {
                0 => state.machine = 0xaa64,
                1 => state.machine = 0x14c,
                2 => state.kernel.2 += 1,
                3 => state.kernel.1 = 1,
                4 => state.kernel.0 = 11,
                5 => state.session = 7,
                6 => p
                    .space
                    .w32(p.peb + offsets(WinArch::X86).peb_session_id, 7)
                    .unwrap(),
                7 => p
                    .space
                    .w32(state.native_peb + offsets(WinArch::X64).peb_session_id, 7)
                    .unwrap(),
                _ => unreachable!(),
            }
            let handles = p.objects.handle_count();
            let committed = p.vm.committed_bytes();
            assert!(
                matches!(call(p, &mut thread, &args(b)), Outcome::Fail(_)),
                "build {build}, mutation {mutation}"
            );
            assert_eq!(p.objects.handle_count(), handles);
            assert_eq!(p.vm.committed_bytes(), committed);
            assert!(p.wow64.as_ref().unwrap().csr.is_none());
            assert_eq!(p.space.u8(b + 8192).unwrap(), 0xa5);
        }
    }
}

#[test]
fn wow64_csr_amd64_cannot_borrow_global_or_retired_owner_identity() {
    for build in [20348, 26100] {
        let (mut process, mut thread, b) = setup(build, 2);
        let p = process.state_mut();
        // A real global directory is not the captured current-session owner.
        p.space
            .put_wstr(b, &"\\Windows".encode_utf16().collect::<Vec<_>>())
            .unwrap();
        let handles = p.objects.handle_count();
        assert!(matches!(call(p, &mut thread, &args(b)), Outcome::Fail(_)));
        assert_eq!(p.objects.handle_count(), handles);
        p.space
            .put_wstr(
                b,
                &"\\Sessions\\2\\Windows".encode_utf16().collect::<Vec<_>>(),
            )
            .unwrap();
        assert_eq!(invoke(p, &mut thread, &args(b)), STATUS_SUCCESS);
        let connection = p.wow64.as_ref().unwrap().csr.as_ref().unwrap();
        let port = connection.port;
        p.objects.close(port.into()).unwrap();
        p.reclaim_scheduler_views().unwrap();
        assert!(matches!(call(p, &mut thread, &args(b)), Outcome::Fail(_)));
    }
}
