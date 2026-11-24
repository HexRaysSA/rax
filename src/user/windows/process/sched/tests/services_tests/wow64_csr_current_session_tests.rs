//! Measured current-session BASE call and independent native/WoW64 PEB binding.
use super::super::connect_csr_tests::{data, namespace};
use super::*;
use crate::user::windows::object_namespace::csr::{CsrMetadata, CsrServer};
use serde_json::Value;

fn profile() -> Value {
    serde_json::from_str(include_str!(
        "../../../../../../../docs/specifications/windows/native-arm64-session-csr/profile-v1.json"
    ))
    .unwrap()
}

fn bytes(value: &Value) -> Vec<u8> {
    let hex = value.as_str().unwrap();
    (0..hex.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap())
        .collect()
}

fn setup_session(session: u32) -> (WindowsProcess, Thread, u64, Value) {
    let profile = profile();
    let (mut process, thread, b) = setup_selected(
        29698,
        session,
        profile["server_base"].as_u64().unwrap(),
        profile["statics_offset"].as_u64().unwrap(),
        profile["server_pid"].as_u64().unwrap() as u32,
    );
    let p = process.state_mut();
    p.space
        .wr(b + 4096, &bytes(&profile["wow64"]["buffer_before_hex"]))
        .unwrap();
    p.space
        .wr(b + 8192, &bytes(&profile["wow64"]["inside_before_hex"]))
        .unwrap();
    (process, thread, b, profile)
}

pub(super) fn setup_29704(session: u32) -> (WindowsProcess, Thread, u64) {
    let profile: Value = serde_json::from_str(include_str!(
        "../../../../../../../docs/specifications/windows/native-csr-kernel-profiles/profile-29704-v1.json"
    )).unwrap();
    assert_eq!(profile["kernel"], serde_json::json!([10, 0, 29704]));
    let metadata = profile["metadata_samples"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["architecture"] == "arm64" && row["kind"] == "metadata1")
        .unwrap();
    let server_pid = profile["metadata_samples"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["architecture"] == "arm64" && row["kind"] == "metadata2")
        .unwrap()["server_pid"]
        .as_u64()
        .unwrap() as u32;
    setup_selected(
        29704,
        session,
        metadata["server_base"].as_u64().unwrap(),
        metadata["statics_offset"].as_u64().unwrap(),
        server_pid,
    )
}

fn setup_selected(
    build: u32,
    session: u32,
    base: u64,
    statics_offset: u64,
    server_pid: u32,
) -> (WindowsProcess, Thread, u64) {
    let (mut process, thread, b) = setup_unbound(build);
    let p = process.state_mut();
    let state = p.wow64.as_mut().unwrap();
    state.session = session;
    p.space.w32(state.native_peb + 0x2C0, session).unwrap();
    p.space.w32(p.peb + 0x1D4, session).unwrap();
    let section = data((session != 0).then_some(session), base);
    p.object_namespace = namespace(session);
    p.object_namespace
        .select_data_section(section.clone())
        .unwrap();
    p.object_namespace
        .select_csr_server(
            CsrServer::selected(
                section,
                CsrMetadata {
                    arch: WinArch::Arm64,
                    kernel: (10, 0, build),
                    session,
                    server_base: base,
                    statics_offset,
                    server_pid,
                },
            )
            .unwrap(),
        )
        .unwrap();
    let root = if session == 0 {
        "\\Windows".to_owned()
    } else {
        format!("\\Sessions\\{session}\\Windows")
    };
    p.space
        .put_wstr(b, &root.encode_utf16().collect::<Vec<_>>())
        .unwrap();
    (process, thread, b)
}

#[test]
fn wow64_csr_29708_base_connect_binds_the_observed_session_zero_geometry() {
    let (mut process, mut thread, b) = setup_selected(29708, 0, 0x7fff_0000_0000, 0x750, 0x724);
    let p = process.state_mut();
    let handles = p.objects.handle_count();
    assert_eq!(invoke(p, &mut thread, &args(b)), STATUS_SUCCESS);
    assert_eq!(p.objects.handle_count(), handles + 1);
    assert_eq!(p.space.bytes(b + 4096, 8).unwrap(), [0xa5; 8]);
    assert_eq!(p.space.u8(b + 8192).unwrap(), 0);
    publication(p, true);

    let (mut other_session, mut thread, b) =
        setup_selected(29708, 2, 0x7fff_0000_0000, 0x750, 0x724);
    let p = other_session.state_mut();
    let handles = p.objects.handle_count();
    assert!(matches!(call(p, &mut thread, &args(b)), Outcome::Fail(_)));
    assert_eq!(p.objects.handle_count(), handles);
    assert!(p.wow64.as_ref().unwrap().csr.is_none());
}

#[test]
fn wow64_csr_29708_child_registration_requires_the_owned_session_connection() {
    use crate::user::windows::dll::WOW64_BASE_CREATE_PROCESS;
    use crate::user::windows::hle::{ApiErr, Ctx, Flow, Value};

    let mut request = [0; 0x110];
    request[0x10..0x14].copy_from_slice(&0x0008_0000u32.to_le_bytes());
    request[0x20..0x24].copy_from_slice(&0x40u32.to_le_bytes());
    request[0x24..0x28].copy_from_slice(&0x6001u32.to_le_bytes());

    for session in [0, 1, 2] {
        let (mut process, mut thread, b) =
            setup_selected(29708, session, 0x7fff_0000_0000, 0x750, 0x724);
        let p = process.state_mut();
        let address = b + 0x3000;
        p.space.wr(address, &request).unwrap();
        let register = |p: &mut Proc, thread: &mut Thread| {
            let sp = thread.cpu.sp();
            p.space.w32(sp + 4, address as u32).unwrap();
            (WOW64_BASE_CREATE_PROCESS.imp)(&mut Ctx {
                p,
                t: thread,
                api: &WOW64_BASE_CREATE_PROCESS,
                entry_pc: 0x1234_0004,
                entry_sp: sp,
                ret_addr: 0,
                cursor: sp - 256,
            })
        };
        assert!(matches!(
            register(p, &mut thread),
            Err(ApiErr::Unimplemented(_))
        ));

        if session < 2 {
            assert_eq!(invoke(p, &mut thread, &args(b)), STATUS_SUCCESS);
            let handles = p.objects.handle_count();
            assert!(matches!(
                register(p, &mut thread),
                Ok(Flow::Ret(Value::Int(code))) if code == u64::from(STATUS_INVALID_HANDLE)
            ));
            p.space.w32(p.peb + 0x1d4, 2).unwrap();
            assert!(matches!(
                register(p, &mut thread),
                Err(ApiErr::Unimplemented(_))
            ));
            assert_eq!(p.objects.handle_count(), handles);
        } else {
            let handles = p.objects.handle_count();
            assert!(matches!(call(p, &mut thread, &args(b)), Outcome::Fail(_)));
            assert_eq!(p.objects.handle_count(), handles);
            assert!(p.wow64.as_ref().unwrap().csr.is_none());
        }
        assert_eq!(p.space.bytes(address, request.len()).unwrap(), request);
    }
}

#[test]
fn wow64_csr_29708_user_connect_requires_owned_base_and_maps_readonly_views() {
    use crate::user::windows::dll::WOW64_USER_CONNECT;
    use crate::user::windows::hle::{Ctx, Flow, Value};
    use crate::user::windows::object_namespace::csr::client_data::{
        INFORMATION_BYTES, native_fixture,
    };

    for session in [0, 1] {
        let (mut process, mut thread, b) =
            setup_selected(29708, session, 0x7fff_0000_0000, 0x750, 0x724);
        let p = process.state_mut();
        let selected = p.object_namespace.selected_csr_server().unwrap();
        let section = selected.section();
        let server = CsrServer::selected_with_client_data(
            section.clone(),
            selected.metadata.clone(),
            Some(native_fixture(0)),
        )
        .unwrap();
        p.object_namespace = namespace(session);
        p.object_namespace.select_data_section(section).unwrap();
        p.object_namespace.select_csr_server(server).unwrap();

        let output = b + 4096;
        let flag = b + 8192;
        let sentinels = [0xa5; INFORMATION_BYTES + 8];
        p.space.wr(output, &sentinels).unwrap();
        p.space.wr(flag, &[0xa5; 4]).unwrap();
        let sp = thread.cpu.sp();
        let user = |p: &mut Proc, thread: &mut Thread| {
            for (index, arg) in [b, output, INFORMATION_BYTES as u64, flag]
                .into_iter()
                .enumerate()
            {
                p.space.w32(sp + 4 + 4 * index as u64, arg as u32).unwrap();
            }
            (WOW64_USER_CONNECT.imp)(&mut Ctx {
                p,
                t: thread,
                api: &WOW64_USER_CONNECT,
                entry_pc: 0x1234_0004,
                entry_sp: sp,
                ret_addr: 0,
                cursor: sp - 256,
            })
        };

        assert!(user(p, &mut thread).is_err());
        assert!(p.wow64.as_ref().unwrap().user_data.is_none());
        assert_eq!(p.space.bytes(output, sentinels.len()).unwrap(), sentinels);
        assert_eq!(p.space.bytes(flag, 4).unwrap(), [0xa5; 4]);
        assert_eq!(invoke(p, &mut thread, &args(b)), STATUS_SUCCESS);
        p.space.wr(flag, &[0xa5; 4]).unwrap();

        p.space.w32(p.peb + 0x1d4, session + 2).unwrap();
        assert!(user(p, &mut thread).is_err());
        assert!(p.wow64.as_ref().unwrap().user_data.is_none());
        assert_eq!(p.space.bytes(output, sentinels.len()).unwrap(), sentinels);
        assert_eq!(p.space.bytes(flag, 4).unwrap(), [0xa5; 4]);
        p.space.w32(p.peb + 0x1d4, session).unwrap();

        assert!(matches!(
            user(p, &mut thread),
            Ok(Flow::Ret(Value::Int(code))) if code == u64::from(STATUS_SUCCESS)
        ));
        let data = p.wow64.as_ref().unwrap().user_data.as_ref().unwrap();
        assert!(data.owns_views(&p.vm));
        assert_eq!(
            p.space.bytes(output, INFORMATION_BYTES).unwrap(),
            data.information
        );
        assert_eq!(
            p.space.bytes(output + INFORMATION_BYTES as u64, 8).unwrap(),
            [0xa5; 8]
        );
        assert_eq!(p.space.bytes(flag, 4).unwrap(), [0, 0xa5, 0xa5, 0xa5]);
        let table = p.space.u64(output + 16).unwrap();
        let shared = p.space.u64(output + 40).unwrap();
        assert!(table < 1 << 32 && shared < 1 << 32);
        assert!(p.space.w8(table, 0).is_err() && p.space.w8(shared, 0).is_err());
        let committed = p.vm.committed_bytes();
        assert!(matches!(
            user(p, &mut thread),
            Ok(Flow::Ret(Value::Int(code))) if code == u64::from(STATUS_SUCCESS)
        ));
        assert_eq!(p.vm.committed_bytes(), committed);
        p.vm.release(table).unwrap();
        assert!(user(p, &mut thread).is_err());
    }
}

#[test]
fn wow64_csr_29704_refuses_unmeasured_identity_without_caller_or_resource_changes() {
    for variant in 0..11 {
        let (mut process, mut thread, b) = setup_29704(1);
        let p = process.state_mut();
        let selected = p.object_namespace.selected_csr_server().unwrap();
        let mut metadata = selected.metadata.clone();
        let native = p.wow64.as_ref().unwrap().native_peb;
        match variant {
            0..=3 => {
                let kernel = [
                    (10, 0, 29703),
                    (10, 0, 29705),
                    (10, 1, 29704),
                    (11, 0, 29704),
                ][variant];
                p.wow64.as_mut().unwrap().kernel = kernel;
            }
            4 => p.wow64.as_mut().unwrap().machine = 0x14c,
            5 => p.wow64.as_mut().unwrap().machine = 0x8664,
            6 => p.space.w32(p.peb + 0x1d4, 0).unwrap(),
            7 => p.space.w32(native + 0x2c0, 0).unwrap(),
            8 => p.wow64.as_mut().unwrap().session = 0,
            9 => metadata.server_pid = p.pid,
            10 => p.space.w64(native + 0x88, 0x1234_0000).unwrap(),
            _ => unreachable!(),
        }
        let section = selected.section();
        p.object_namespace = namespace(1);
        p.object_namespace
            .select_data_section(section.clone())
            .unwrap();
        p.object_namespace
            .select_csr_server(CsrServer::selected(section, metadata).unwrap())
            .unwrap();
        // Guest-facing compatibility fields cannot qualify the native identity.
        Arc::make_mut(&mut p.cfg).version.build = 29695;
        let caller = p.space.bytes(b, 16384).unwrap();
        let native_before = p.space.bytes(native, 4096).unwrap();
        let wow_before = p.space.bytes(p.peb, 4096).unwrap();
        let counts = (
            p.objects.handle_count(),
            p.objects.iter().count(),
            p.vm.committed_bytes(),
        );
        assert!(
            matches!(call(p, &mut thread, &args(b)), Outcome::Fail(_)),
            "{variant}"
        );
        assert_eq!(p.space.bytes(b, 16384).unwrap(), caller, "{variant}");
        assert_eq!(
            p.space.bytes(native, 4096).unwrap(),
            native_before,
            "{variant}"
        );
        assert_eq!(p.space.bytes(p.peb, 4096).unwrap(), wow_before, "{variant}");
        assert!(p.wow64.as_ref().unwrap().csr.is_none());
        assert_eq!(
            (
                p.objects.handle_count(),
                p.objects.iter().count(),
                p.vm.committed_bytes()
            ),
            counts,
            "{variant}"
        );
    }
}

#[test]
fn wow64_csr_29704_publishes_owned_views_independently_of_reported_version_and_rejects_retirement()
{
    let (mut process, mut thread, b) = setup_29704(1);
    let p = process.state_mut();
    Arc::make_mut(&mut p.cfg).version.build = 1;
    let handles = p.objects.handle_count();
    assert_eq!(invoke(p, &mut thread, &args(b)), STATUS_SUCCESS);
    assert_eq!(p.objects.handle_count(), handles + 1);
    assert_eq!(p.space.bytes(b + 4096, 80).unwrap(), [0xa5; 80]);
    assert_eq!(p.space.u8(b + 8192).unwrap(), 0);
    publication(p, true);
    let port = p.wow64.as_ref().unwrap().csr.as_ref().unwrap().port;
    p.objects.close(port.into()).unwrap();
    p.reclaim_scheduler_views().unwrap();
    assert!(
        matches!(call(p, &mut thread, &args(b)), Outcome::Fail(reason)
                    if reason.contains("identity was retired"))
    );
}

#[test]
fn wow64_csr_current_session_replays_native_reply_and_publishes_owned_peb_views() {
    for session in [0, 1, 42, u32::MAX] {
        let (mut process, mut thread, b, profile) = setup_session(session);
        let p = process.state_mut();
        let before = p.objects.handle_count();
        assert_eq!(
            u64::from(invoke(p, &mut thread, &args(b))),
            profile["wow64"]["status"].as_u64().unwrap()
        );
        assert_eq!(p.objects.handle_count(), before + 1);
        assert_eq!(
            p.space.bytes(b + 4096, 8).unwrap(),
            bytes(&profile["wow64"]["buffer_after_hex"])
        );
        assert_eq!(
            p.space.bytes(b + 8192, 1).unwrap(),
            bytes(&profile["wow64"]["inside_after_hex"])
        );
        publication(p, true);
        let port = p.wow64.as_ref().unwrap().csr.as_ref().unwrap().port;
        p.objects.close(port.into()).unwrap();
        p.reclaim_scheduler_views().unwrap();
        assert!(matches!(call(p, &mut thread, &args(b)), Outcome::Fail(_)));
    }
}

#[test]
fn wow64_csr_29708_replays_first_native_base_connection() {
    let profile: Value = serde_json::from_str(include_str!(
        "../../../../../../../docs/specifications/windows/native-wow64-csr-connect/startup-29708-arm64.json"
    ))
    .unwrap();
    let session = profile["session"].as_u64().unwrap() as u32;
    for selected_session in [session, session + 1] {
        let (mut process, mut thread, b) = setup_selected(
            29708,
            selected_session,
            profile["server_base"].as_u64().unwrap(),
            profile["statics_offset"].as_u64().unwrap(),
            profile["server_pid"].as_u64().unwrap() as u32,
        );
        let p = process.state_mut();
        p.space
            .wr(b + 4096, &bytes(&profile["buffer_before_hex"]))
            .unwrap();
        p.space
            .wr(b + 8192, &bytes(&profile["inside_before_hex"]))
            .unwrap();
        let handles = p.objects.handle_count();
        let committed = p.vm.committed_bytes();
        if selected_session == session {
            assert_eq!(
                u64::from(invoke(p, &mut thread, &args(b))),
                profile["status"].as_u64().unwrap()
            );
            assert_eq!(p.objects.handle_count(), handles + 1);
            assert_eq!(
                p.space.bytes(b + 4096, 8).unwrap(),
                bytes(&profile["buffer_after_hex"])
            );
            assert_eq!(
                p.space.bytes(b + 8192, 1).unwrap(),
                bytes(&profile["inside_after_hex"])
            );
            publication(p, true);
        } else {
            assert!(matches!(call(p, &mut thread, &args(b)), Outcome::Fail(_)));
            assert_eq!(p.objects.handle_count(), handles);
            assert_eq!(p.vm.committed_bytes(), committed);
            assert!(p.wow64.as_ref().unwrap().csr.is_none());
            assert_eq!(
                p.space.bytes(b + 8192, 1).unwrap(),
                bytes(&profile["inside_before_hex"])
            );
        }
    }
}

#[test]
fn wow64_csr_current_session_rejects_foreign_pebs_captured_session_and_root() {
    for variant in 0..4 {
        let (mut process, mut thread, b, _) = setup_session(1);
        let p = process.state_mut();
        match variant {
            0 => p.space.w32(p.peb + 0x1D4, 0).unwrap(),
            1 => {
                let native = p.wow64.as_ref().unwrap().native_peb;
                p.space.w32(native + 0x2C0, 0).unwrap();
            }
            2 => p.wow64.as_mut().unwrap().session = 0,
            3 => p
                .space
                .put_wstr(b, &"\\Windows".encode_utf16().collect::<Vec<_>>())
                .unwrap(),
            _ => unreachable!(),
        }
        let caller = p.space.bytes(b, 16384).unwrap();
        let counts = (
            p.objects.handle_count(),
            p.objects.iter().count(),
            p.vm.committed_bytes(),
        );
        assert!(matches!(call(p, &mut thread, &args(b)), Outcome::Fail(_)));
        assert!(p.wow64.as_ref().unwrap().csr.is_none());
        assert_eq!(p.space.bytes(b, 16384).unwrap(), caller);
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
fn wow64_csr_26200_replays_first_native_base_connection() {
    let profile: Value = serde_json::from_str(include_str!(
        "../../../../../../../docs/specifications/windows/native-wow64-csr-connect/startup-26200-arm64.json"
    ))
    .unwrap();
    let server_profile: Value = serde_json::from_str(include_str!(
        "../../../../../../../docs/specifications/windows/native-csr-kernel-profiles/profile-26200-v1.json"
    ))
    .unwrap();
    let session = profile["session"].as_u64().unwrap() as u32;
    let build = profile["kernel"][2].as_u64().unwrap() as u32;
    assert_eq!((build, session), (26200, 2));
    assert_eq!(profile["kernel"], server_profile["kernel"]);
    assert_eq!(profile["session"], server_profile["session"]);
    assert_eq!(
        profile["ntdll_system32_sha256"],
        server_profile["evidence"]["ntdll_sha256"]
    );
    assert_eq!(profile["statics_offset"], server_profile["statics_offset"]);
    assert_eq!(profile["leaf_ret_argument_bytes"], 20);
    assert_eq!(profile["server_id"], 1);

    let (mut process, mut thread, b) = setup_selected(
        build,
        session,
        profile["server_base"].as_u64().unwrap(),
        profile["statics_offset"].as_u64().unwrap(),
        server_profile["server_pid"].as_u64().unwrap() as u32,
    );
    let p = process.state_mut();
    let native = p.wow64.as_ref().unwrap().native_peb;
    let root = profile["root"]
        .as_str()
        .unwrap()
        .encode_utf16()
        .collect::<Vec<_>>();
    assert_eq!(p.space.wstr(b, root.len() + 1).unwrap(), root);
    p.space
        .wr(b + 4096, &bytes(&profile["buffer_before_hex"]))
        .unwrap();
    p.space
        .wr(b + 8192, &bytes(&profile["inside_before_hex"]))
        .unwrap();
    let before = (
        p.objects.handle_count(),
        p.vm.committed_bytes(),
        p.space.bytes(b, 16384).unwrap(),
        p.space.bytes(native, 4096).unwrap(),
        p.space.bytes(p.peb, 4096).unwrap(),
    );

    for variant in 0..5 {
        let mut request = args(b);
        match variant {
            0 => request[2] = 0,
            1 => request[3] = 7,
            2 => request[4] = 0,
            3 => p.wow64.as_mut().unwrap().session += 1,
            4 => p.wow64.as_mut().unwrap().kernel.2 += 1,
            _ => unreachable!(),
        }
        assert!(
            matches!(call(p, &mut thread, &request), Outcome::Fail(_)),
            "{variant}"
        );
        assert!(p.wow64.as_ref().unwrap().csr.is_none());
        assert_eq!(p.objects.handle_count(), before.0);
        assert_eq!(p.vm.committed_bytes(), before.1);
        assert_eq!(p.space.bytes(b, 16384).unwrap(), before.2);
        assert_eq!(p.space.bytes(native, 4096).unwrap(), before.3);
        assert_eq!(p.space.bytes(p.peb, 4096).unwrap(), before.4);
        let state = p.wow64.as_mut().unwrap();
        state.session = session;
        state.kernel = (10, 0, build);
    }

    p.vm.protect(b + 8192, 4096, prot::READONLY).unwrap();
    assert_eq!(invoke(p, &mut thread, &args(b)), STATUS_ACCESS_VIOLATION);
    assert!(p.wow64.as_ref().unwrap().csr.is_none());
    assert_eq!(p.objects.handle_count(), before.0);
    assert_eq!(p.vm.committed_bytes(), before.1);
    p.vm.protect(b + 8192, 4096, prot::READWRITE).unwrap();
    assert_eq!(
        u64::from(invoke(p, &mut thread, &args(b))),
        profile["status"].as_u64().unwrap()
    );
    assert_eq!(
        p.objects.handle_count() - before.0,
        profile["handle_delta"].as_u64().unwrap() as usize
    );
    assert_eq!(
        p.space.bytes(b + 4096, 8).unwrap(),
        bytes(&profile["buffer_after_hex"])
    );
    assert_eq!(
        p.space.bytes(b + 8192, 1).unwrap(),
        bytes(&profile["inside_after_hex"])
    );
    publication(p, true);
    assert!(
        matches!(call(p, &mut thread, &args(b)), Outcome::Fail(reason)
        if reason.contains("measured first BASE call"))
    );
    assert_eq!(p.objects.handle_count(), before.0 + 1);
    publication(p, true);
}
