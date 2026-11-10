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
    let (mut process, thread, b) = setup_for_kernel(build);
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
