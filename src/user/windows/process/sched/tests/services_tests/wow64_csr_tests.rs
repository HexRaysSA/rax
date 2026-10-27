//! First/late native CSR phase boundaries, including retained failure handles.
use super::*;
use crate::user::windows::memory::{Mem, mem, prot};
use crate::user::windows::process::{WindowsProcess, wow64};
use std::sync::Arc;

const SERVICE: u32 = 0x1e9;
const NAME: &str = "NtWow64CsrClientConnectToServer";

#[path = "wow64_csr_replay_tests.rs"]
mod replay;

#[cfg(all(windows, target_arch = "aarch64"))]
#[path = "wow64_csr_leaf_tests.rs"]
mod installed;

fn setup() -> (WindowsProcess, Thread, u64) {
    let (mut process, thread) = fixture(WinArch::X86, NAME, SERVICE);
    let p = process.state_mut();
    let cfg = Arc::make_mut(&mut p.cfg);
    cfg.version.major = 10;
    cfg.version.minor = 0;
    cfg.version.build = 29695;
    wow64::initialize_test_profile(p, 0xaa64).unwrap();
    let (section, server) = secure_connect_tests::csr::server_for_kernel(29695);
    p.object_namespace = secure_connect_tests::selected_namespace();
    p.object_namespace.select_data_section(section).unwrap();
    p.object_namespace.select_csr_server(server).unwrap();
    let b =
        p.vm.allocate(None, 16384, mem::RESERVE | mem::COMMIT, prot::READWRITE)
            .unwrap()
            .0;
    p.space
        .put_wstr(b, &"\\Windows".encode_utf16().collect::<Vec<_>>())
        .unwrap();
    p.space.wr(b + 4096, &[0xa5; 80]).unwrap();
    p.space.w8(b + 8192, 0xa5).unwrap();
    (process, thread, b)
}

fn args(b: u64) -> [u64; 5] {
    [b, 1, b + 4096, 8, b + 8192]
}

fn call(p: &mut Proc, t: &mut Thread, args: &[u64; 5]) -> Outcome {
    let sp = t.cpu.sp();
    p.space.w32(sp, 0x1234_0004).unwrap();
    p.space.w32(sp + 4, 0x1234_0000).unwrap();
    for (i, value) in args.iter().enumerate() {
        p.space.w32(sp + 8 + i as u64 * 4, *value as u32).unwrap();
    }
    t.cpu.set_gpr(0, SERVICE.into());
    t.cpu.set_pc(0x1234_0004);
    let result = super::super::super::super::services::wow64(p, t, 0x1234_0000);
    if result == Outcome::Continue {
        assert_eq!(t.cpu.pc(), 0x1234_0004);
        assert_eq!(t.cpu.sp(), sp + 4, "NTDLL owns its subsequent RET20");
        assert!(t.frames.is_empty());
    }
    t.cpu.set_sp(sp);
    result
}

fn invoke(p: &mut Proc, t: &mut Thread, args: &[u64; 5]) -> u32 {
    assert_eq!(call(p, t, args), Outcome::Continue);
    t.cpu.gpr(0) as u32
}

fn publication(p: &Proc, wow: bool) {
    let state = p.wow64.as_ref().unwrap();
    let connection = state.csr.as_ref().unwrap();
    let metadata = p
        .object_namespace
        .csr_server(&"\\Windows\\ApiPort".encode_utf16().collect::<Vec<_>>())
        .unwrap()
        .metadata
        .clone();
    assert_eq!(
        p.space.u64(state.native_peb + 0x88).unwrap(),
        connection.base
    );
    assert_eq!(
        p.space.u64(state.native_peb + 0x98).unwrap(),
        connection.base + 0x750
    );
    assert_eq!(
        p.space.u64(state.native_peb + 0x380).unwrap(),
        metadata.server_base
    );
    assert_eq!(
        p.space.u32(p.peb + 0x4c).unwrap(),
        if wow { connection.base as u32 } else { 0 }
    );
    assert_eq!(
        p.space.u32(p.peb + 0x54).unwrap(),
        if wow {
            (connection.base + 0x750) as u32
        } else {
            0
        }
    );
    assert_eq!(
        p.space.u64(p.peb + 0x248).unwrap(),
        if wow { metadata.server_base } else { 0 }
    );
    assert!(p.vm.owns_readonly_data_view(connection.base, &connection.section));
    assert!(p.space.w8(connection.base, 1).is_err());
    assert!(
        p.space.u8(connection.base + 5 * 4096).is_err(),
        "reserved tail has no frames"
    );
    assert_eq!(p.objects.access(connection.port.into()), Some(0x001f_0001));
    let Some(Object::LpcPort(port)) = p.objects.get(connection.port.into()) else {
        panic!("owned typed port")
    };
    let view = port.view().unwrap();
    let peer = port.peer().unwrap();
    assert!(p.vm.owns_shared_view(view));
    assert!(!peer.vm.space().same_space(&p.space));
    p.space.w32(view.base, 0x1234_5678).unwrap();
    assert_eq!(peer.vm.space().u32(peer.base).unwrap(), 0x1234_5678);
}

#[test]
fn wow64_csr_first_connection_owns_views_peer_and_phased_peb_publication() {
    let (mut process, mut thread, b) = setup();
    let p = process.state_mut();
    let handles = p.objects.handle_count();
    assert_eq!(invoke(p, &mut thread, &args(b)), STATUS_SUCCESS);
    assert_eq!(p.objects.handle_count(), handles + 1);
    assert_eq!(p.space.bytes(b + 4096, 80).unwrap(), [0xa5; 80]);
    assert_eq!(p.space.u8(b + 8192).unwrap(), 0);
    publication(p, true);
    // Initialization state is private; later root pointers are never visited.
    let mut second = args(b);
    second[0] = 1;
    assert_eq!(invoke(p, &mut thread, &second), STATUS_SUCCESS);
    assert_eq!(p.objects.handle_count(), handles + 1);
    publication(p, true);
}

#[test]
fn wow64_csr_readonly_input_works_once_then_successful_reply_requires_copyback() {
    let (mut process, mut thread, b) = setup();
    let p = process.state_mut();
    p.vm.protect(b + 4096, 4096, prot::READONLY).unwrap();
    assert_eq!(invoke(p, &mut thread, &args(b)), STATUS_SUCCESS);
    publication(p, true);
    p.space.w8(b + 8192, 0xa5).unwrap();
    assert_eq!(invoke(p, &mut thread, &args(b)), STATUS_ACCESS_VIOLATION);
    assert_eq!(p.space.u8(b + 8192).unwrap(), 0xa5);
    let mut short = args(b);
    short[3] = 7;
    assert_eq!(invoke(p, &mut thread, &short), STATUS_INVALID_PARAMETER);
    assert_eq!(p.space.u8(b + 8192).unwrap(), 0);
}

#[test]
fn wow64_csr_capture_fault_retains_two_unmapped_sections_per_attempt() {
    for protection in [prot::NOACCESS, prot::READWRITE | prot::GUARD] {
        let (mut process, mut thread, b) = setup();
        let p = process.state_mut();
        let handles = p.objects.handle_count();
        let committed = p.vm.committed_bytes();
        p.vm.protect(b + 4096, 4096, protection).unwrap();
        assert_eq!(
            invoke(p, &mut thread, &args(b)),
            if protection & prot::GUARD != 0 {
                STATUS_GUARD_PAGE_VIOLATION
            } else {
                STATUS_ACCESS_VIOLATION
            }
        );
        assert_eq!(p.objects.handle_count(), handles + 2);
        assert_eq!(p.vm.committed_bytes(), committed);
        assert!(p.wow64.as_ref().unwrap().csr.is_none());
        assert_eq!(p.space.u8(b + 8192).unwrap(), 0xa5);
        assert_eq!(
            p.space
                .u64(p.wow64.as_ref().unwrap().native_peb + 0x88)
                .unwrap(),
            0
        );
        if protection & prot::GUARD != 0 {
            assert_eq!(invoke(p, &mut thread, &args(b)), STATUS_SUCCESS);
            assert_eq!(p.objects.handle_count(), handles + 3);
            publication(p, true);
        } else {
            assert_eq!(invoke(p, &mut thread, &args(b)), STATUS_ACCESS_VIOLATION);
            assert_eq!(p.objects.handle_count(), handles + 4);
        }
    }
}

#[test]
fn wow64_csr_boolean_fault_keeps_native_publication_and_retry_finishes_wow_peb() {
    for protection in [
        prot::NOACCESS,
        prot::READONLY,
        prot::READWRITE | prot::GUARD,
        prot::READONLY | prot::GUARD,
    ] {
        let (mut process, mut thread, b) = setup();
        let p = process.state_mut();
        let handles = p.objects.handle_count();
        p.vm.protect(b + 8192, 4096, protection).unwrap();
        assert_eq!(
            invoke(p, &mut thread, &args(b)),
            if protection == (prot::READWRITE | prot::GUARD) {
                STATUS_GUARD_PAGE_VIOLATION
            } else {
                STATUS_ACCESS_VIOLATION
            }
        );
        assert_eq!(p.objects.handle_count(), handles + 1);
        publication(p, false);
        assert_eq!(
            p.vm.query(b + 8192).unwrap().protect & prot::GUARD,
            if protection == (prot::READONLY | prot::GUARD) {
                prot::GUARD
            } else {
                0
            }
        );
        p.vm.protect(b + 8192, 4096, prot::READWRITE).unwrap();
        assert_eq!(invoke(p, &mut thread, &args(b)), STATUS_SUCCESS);
        assert_eq!(p.objects.handle_count(), handles + 1);
        publication(p, true);
    }
}

#[test]
fn wow64_csr_zero_and_null_inputs_do_not_establish_a_connection() {
    for null_buffer in [false, true] {
        let (mut process, mut thread, b) = setup();
        let p = process.state_mut();
        let handles = p.objects.handle_count();
        let committed = p.vm.committed_bytes();
        let mut request = args(b);
        request[0] = 1;
        request[3] = 0;
        if null_buffer {
            request[2] = 0;
        }
        assert_eq!(
            invoke(p, &mut thread, &request),
            if null_buffer {
                STATUS_SUCCESS
            } else {
                STATUS_INVALID_PARAMETER
            }
        );
        assert_eq!(p.objects.handle_count(), handles);
        assert_eq!(p.vm.committed_bytes(), committed);
        assert!(p.wow64.as_ref().unwrap().csr.is_none());
        assert_eq!(
            p.space.u8(b + 8192).unwrap(),
            if null_buffer { 0 } else { 0xa5 }
        );
    }
}

#[test]
fn wow64_csr_rejected_server_lengths_still_publish_the_connection() {
    for bytes in [7, 16, 64] {
        let (mut process, mut thread, b) = setup();
        let p = process.state_mut();
        let mut request = args(b);
        request[3] = bytes;
        assert_eq!(invoke(p, &mut thread, &request), STATUS_INVALID_PARAMETER);
        assert_eq!(p.space.u8(b + 8192).unwrap(), 0);
        assert_eq!(p.space.bytes(b + 4096, 80).unwrap(), [0xa5; 80]);
        publication(p, true);
    }
}

#[test]
fn wow64_csr_cannot_borrow_a_retired_connection_or_spoofed_native_profile() {
    let (mut process, mut thread, b) = setup();
    let p = process.state_mut();
    // Mutable guest-facing version fields cannot admit another native kernel.
    p.wow64.as_mut().unwrap().kernel = (10, 0, 29683);
    assert!(matches!(call(p, &mut thread, &args(b)), Outcome::Fail(_)));
    p.wow64.as_mut().unwrap().kernel = (10, 0, 29695);
    assert_eq!(invoke(p, &mut thread, &args(b)), STATUS_SUCCESS);
    let port = p.wow64.as_ref().unwrap().csr.as_ref().unwrap().port;
    p.objects.close(port.into()).unwrap();
    p.reclaim_scheduler_views().unwrap();
    assert!(matches!(call(p, &mut thread, &args(b)), Outcome::Fail(_)));
    assert!(crate::user::windows::dll::nt_service(NAME, WinArch::X64).is_none());
    assert!(crate::user::windows::dll::nt_service(NAME, WinArch::Arm64).is_none());
}

#[test]
fn wow64_csr_mutated_native_fields_and_boolean_aliases_cannot_fabricate_success() {
    let (mut process, mut thread, b) = setup();
    let p = process.state_mut();
    let native = p.wow64.as_ref().unwrap().native_peb;
    p.space.w64(native + 0x88, 0x1234_0000).unwrap();
    let before = p.objects.handle_count();
    assert!(
        matches!(call(p, &mut thread, &args(b)), Outcome::Fail(reason)
        if reason.contains("native PEB fields"))
    );
    assert_eq!(p.objects.handle_count(), before);
    p.space.w64(native + 0x88, 0).unwrap();
    assert_eq!(invoke(p, &mut thread, &args(b)), STATUS_SUCCESS);
    let base = p.wow64.as_ref().unwrap().csr.as_ref().unwrap().base;
    p.space.w64(native + 0x98, base + 0x1750).unwrap();
    assert!(
        matches!(call(p, &mut thread, &args(b)), Outcome::Fail(reason)
        if reason.contains("native PEB fields"))
    );
    assert_eq!(p.objects.handle_count(), before + 1);

    let (mut process, mut thread, b) = setup();
    let p = process.state_mut();
    let native = p.wow64.as_ref().unwrap().native_peb;
    let mut request = args(b);
    // The server base has a nonzero most significant byte in this selected
    // profile. Changing it through the Boolean occurs after port publication.
    request[4] = native + 0x380 + 5;
    assert!(
        matches!(call(p, &mut thread, &request), Outcome::Fail(reason)
        if reason.contains("native PEB fields"))
    );
    assert!(p.wow64.as_ref().unwrap().csr.is_some());
    assert_eq!(p.space.u8(request[4]).unwrap(), 0);
    assert_eq!(p.space.u32(p.peb + 0x4c).unwrap(), 0);
    assert_eq!(p.space.u32(p.peb + 0x54).unwrap(), 0);
    assert_eq!(p.space.u64(p.peb + 0x248).unwrap(), 0);
}
