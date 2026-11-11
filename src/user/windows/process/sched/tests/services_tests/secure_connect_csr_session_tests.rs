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

fn arm64ec_capture() -> Value {
    serde_json::from_str(include_str!(
        "../../../../../../../docs/specifications/windows/native-arm64-session-csr/arm64ec-profile-29704-v1.json"
    ))
    .unwrap()
}

fn enter_arm64ec(p: &Proc, thread: &mut Thread, code: u64) {
    use crate::user::windows::arch::{CpuStop, InstructionRoute};

    p.space.w32(code, 0xd503_201f).unwrap();
    p.space.w32(code + 4, 0xd400_0001 | (SERVICE << 5)).unwrap();
    thread.cpu.set_pc(code);
    assert!(matches!(
        thread
            .cpu
            .run_routed(1, |_, _, _| Ok(InstructionRoute::ResumeArm64)),
        CpuStop::Yield
    ));
    assert!(thread.cpu.is_arm64ec());
    assert_eq!(thread.cpu.instruction_arch(), WinArch::Arm64);
}

fn invoke_arm64ec(p: &mut Proc, thread: &mut Thread, args: &[u64; 9]) -> Outcome {
    use crate::user::windows::arch::{CpuStop, InstructionRoute};

    let pc = thread.cpu.pc();
    let sp = thread.cpu.sp();
    for (index, &value) in args[..8].iter().enumerate() {
        thread.cpu.set_call_gpr(index, value);
    }
    p.space.w64(sp, args[8]).unwrap();
    let stop = thread
        .cpu
        .run_routed(1, |_, _, _| Ok(InstructionRoute::Stay));
    assert!(matches!(stop, CpuStop::Svc { imm, pc: at } if u32::from(imm) == SERVICE && at == pc));
    let result = handle_stop(p, thread, stop);
    assert_eq!(thread.cpu.sp(), sp);
    assert_eq!(thread.cpu.pc(), pc + 4);
    assert!(thread.frames.is_empty());
    result
}

#[test]
fn native_secure_connect_csr_arm64ec_replays_measured_29704_reply_and_owned_views() {
    let profile = arm64ec_capture();
    let (mut process, mut thread) = fixture(WinArch::X64, "NtSecureConnectPort", SERVICE);
    let p = process.state_mut();
    let b = scratch(p, 65536);
    let args = setup(p, b, 1, &profile);
    p.object_namespace.native_machine = Some(0xAA64);
    let code = b + 32768;
    p.vm.protect(code, 4096, prot::EXECUTE_READWRITE).unwrap();
    enter_arm64ec(p, &mut thread, code);
    let before = p.vm.committed_bytes();
    let client = p.space.bytes(args[3], 32).unwrap();

    assert_eq!(invoke_arm64ec(p, &mut thread, &args), Outcome::Continue);
    assert_eq!(thread.cpu.call_gpr(0), u64::from(STATUS_SUCCESS));
    assert_eq!(p.space.bytes(args[3], 32).unwrap(), client);
    assert_eq!(
        p.space.bytes(args[7], 48).unwrap(),
        bytes(&profile, "information_after_hex")
    );
    assert_eq!(p.space.bytes(args[5], 24).unwrap(), vec![0; 24]);
    assert_eq!(p.space.u32(args[6]).unwrap(), 952);
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
    assert_eq!(p.objects.access(handle), Some(0x001F_0001));
    p.space.w32(local, 0xA55A_6996).unwrap();
    assert_eq!(peer.vm.space().u32(remote).unwrap(), 0xA55A_6996);
    assert_eq!(p.vm.committed_bytes(), before + 65536);
    p.objects.close(handle).unwrap();
    p.reclaim_scheduler_views().unwrap();
    assert!(p.vm.allocation(local).is_none());
    assert_eq!(p.vm.committed_bytes(), before);
}

#[test]
fn native_secure_connect_csr_arm64ec_refuses_foreign_profile_and_geometry_without_publication() {
    let profile = arm64ec_capture();
    for variant in 0..8 {
        let (mut process, mut thread) = fixture(WinArch::X64, "NtSecureConnectPort", SERVICE);
        let p = process.state_mut();
        let b = scratch(p, 65536);
        let args = setup(p, b, 1, &profile);
        p.object_namespace.native_machine = Some(0xAA64);
        let code = b + 32768;
        p.vm.protect(code, 4096, prot::EXECUTE_READWRITE).unwrap();
        if variant != 2 {
            enter_arm64ec(p, &mut thread, code);
        }
        match variant {
            0 => p.object_namespace.native_machine = None,
            1 => p.object_namespace.native_machine = Some(0x8664),
            2 => {}
            3 => Arc::make_mut(&mut p.cfg).version.build = 29705,
            4 => p.space.w32(p.peb + 0x2C0, 2).unwrap(),
            5 => p.space.w8(args[2] + 8, 0).unwrap(),
            6 => p.space.w32(args[4] + 8, 19).unwrap(),
            7 => p.space.w64(args[3] + 24, 4096).unwrap(),
            _ => unreachable!(),
        }
        let memory = p.space.bytes(b, 65536).unwrap();
        let counts = (
            p.objects.handle_count(),
            p.objects.iter().count(),
            p.vm.committed_bytes(),
        );
        let outcome = if variant == 2 {
            invoke(p, &mut thread, &args)
        } else {
            invoke_arm64ec(p, &mut thread, &args)
        };
        assert!(matches!(outcome, Outcome::Fail(_)), "variant {variant}");
        assert_eq!(
            p.space.bytes(b, 65536).unwrap(),
            memory,
            "variant {variant}"
        );
        assert_eq!(
            (
                p.objects.handle_count(),
                p.objects.iter().count(),
                p.vm.committed_bytes(),
            ),
            counts,
            "variant {variant}"
        );
    }
}
