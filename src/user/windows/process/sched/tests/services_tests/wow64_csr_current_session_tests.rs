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
    let (mut process, thread, b) = setup_for_kernel(29698);
    let p = process.state_mut();
    let state = p.wow64.as_mut().unwrap();
    state.session = session;
    p.space.w32(state.native_peb + 0x2C0, session).unwrap();
    p.space.w32(p.peb + 0x1D4, session).unwrap();
    let base = profile["server_base"].as_u64().unwrap();
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
                    kernel: (10, 0, 29698),
                    session,
                    server_base: base,
                    statics_offset: profile["statics_offset"].as_u64().unwrap(),
                    server_pid: profile["server_pid"].as_u64().unwrap() as u32,
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
    p.space
        .wr(b + 4096, &bytes(&profile["wow64"]["buffer_before_hex"]))
        .unwrap();
    p.space
        .wr(b + 8192, &bytes(&profile["wow64"]["inside_before_hex"]))
        .unwrap();
    (process, thread, b, profile)
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
