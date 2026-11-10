use super::*;

fn release(p: &mut Proc, t: &mut Thread, port: u64, message: u64) -> Outcome {
    let sp = t.cpu.sp();
    super::super::nls_tests::arguments(p, t, &[port, 0x10000, message, 0, 0, 0, 0, 0]);
    if p.arch != WinArch::Arm64 {
        t.cpu.set_gpr(0, 0x8E);
    }
    let outcome = if p.arch == WinArch::X86 {
        super::super::super::super::super::services::wow64(p, t, 0x1234_0000)
    } else {
        handle_stop(p, t, stop(p.arch, 0x8E))
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
fn native_cache_connection_reply_release_matches_native_and_cannot_consume_another_peer() {
    let capture: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-alpc-connect-ex-cache/native-controls-v1.json"
    )))
    .unwrap();
    for profile in capture["profiles"].as_array().unwrap() {
        let arch = match profile["architecture"].as_str().unwrap() {
            "arm64" => WinArch::Arm64,
            "x64" => WinArch::X64,
            "x86" => WinArch::X86,
            other => panic!("unknown caller {other}"),
        };
        let (mut process, mut thread) = fixture(arch, "NtAlpcConnectPortEx", SERVICE);
        let p = process.state_mut();
        p.object_namespace = selected();
        let b =
            p.vm.allocate(None, 8192, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        let first = packet(p, b);
        assert_eq!(invoke(p, &mut thread, &first), Outcome::Continue);
        let second = packet(p, b + 4096);
        assert_eq!(invoke(p, &mut thread, &second), Outcome::Continue);
        let h1 = p.space.ptr(first[0], arch.ptr_size()).unwrap();
        let h2 = p.space.ptr(second[0], arch.ptr_size()).unwrap();
        let snapshot = p.space.bytes(b, 8192).unwrap();
        let handles = p.objects.handle_count();
        let committed = p.vm.committed_bytes();
        let module = p.modules.nt_services.as_ref().unwrap().0;
        p.modules.nt_services = Some((module, table(arch, "NtAlpcSendWaitReceivePort", 0x8E)));
        assert!(matches!(
            release(p, &mut thread, h1, second[6]),
            Outcome::Fail(_)
        ));
        for handle in [h1, h2] {
            let Some(Object::LpcPort(endpoint)) = p.objects.get(handle) else {
                panic!("owned port")
            };
            assert!(
                endpoint
                    .cache_peer()
                    .unwrap()
                    .pending_connection_reply
                    .is_some()
            );
        }
        let expected =
            u32::from_str_radix(profile["release"]["status"].as_str().unwrap(), 16).unwrap();
        for (handle, message) in [(h1, first[6]), (h2, second[6])] {
            assert_eq!(release(p, &mut thread, handle, message), Outcome::Continue);
            assert_eq!(thread.cpu.gpr(0), u64::from(expected));
            let Some(Object::LpcPort(endpoint)) = p.objects.get(handle) else {
                panic!("owned port")
            };
            assert!(
                endpoint
                    .cache_peer()
                    .unwrap()
                    .pending_connection_reply
                    .is_none()
            );
        }
        assert_eq!(p.space.bytes(b, 8192).unwrap(), snapshot);
        assert_eq!(p.objects.handle_count(), handles);
        assert_eq!(p.vm.committed_bytes(), committed);
        assert!(matches!(
            release(p, &mut thread, h1, first[6]),
            Outcome::Fail(_)
        ));
    }
}
