use super::*;
use crate::user::windows::loader::services::tests::named_table;
use crate::user::windows::nt::status::*;

const CONNECT: u32 = 0x7b;
const PROFILE_BUILD: u32 = 29708;
const PORT_ACCESS: u32 = 0x001f_0001;

fn invoke(p: &mut Proc, t: &mut Thread, name: &str, number: u32, args: &[u64]) -> Outcome {
    let index = p.modules.nt_services.as_ref().unwrap().0;
    p.modules.nt_services = Some((index, named_table(p.arch, name, number)));
    let sp = t.cpu.sp();
    if p.arch == WinArch::Arm64 {
        let registers = args.len().min(8);
        super::super::nls_tests::arguments(p, t, &args[..registers]);
        for (slot, value) in args[registers..].iter().enumerate() {
            p.space.w64(sp + slot as u64 * 8, *value).unwrap();
        }
    } else {
        super::super::nls_tests::arguments(p, t, args);
        t.cpu.set_gpr(0, number.into());
    }
    let result = if p.arch == WinArch::X86 {
        crate::user::windows::process::services::wow64(p, t, 0x1234_0000)
    } else {
        handle_stop(p, t, stop(p.arch, number))
    };
    if result == Outcome::Continue {
        assert_eq!(t.cpu.pc(), 0x1234_0004);
        assert_eq!(t.cpu.sp(), sp + if p.arch == WinArch::X86 { 4 } else { 0 });
        assert!(t.frames.is_empty());
    }
    t.cpu.set_sp(sp);
    result
}

#[test]
fn native_lsarpc_connection_replays_selected_input_and_output_profiles() {
    // Build 29708 produced the same result on native ARM64, x64 and WoW64.
    let expected = [
        STATUS_SUCCESS,
        STATUS_SERVER_SID_MISMATCH,
        STATUS_SUCCESS,
        STATUS_SUCCESS,
        STATUS_SUCCESS,
        STATUS_INVALID_PARAMETER,
        STATUS_ACCESS_VIOLATION,
        STATUS_ACCESS_VIOLATION,
        STATUS_SUCCESS,
    ];
    for arch in WinArch::ALL {
        let (mut process, mut thread) = fixture(arch, "NtClose", CONNECT);
        let p = process.state_mut();
        super::super::native_profile::kernel_profile(p, PROFILE_BUILD, 0xaa64);
        let width = arch.ptr_size();
        let base =
            p.vm.allocate(
                None,
                3 * PAGE_SIZE,
                mem::RESERVE | mem::COMMIT,
                prot::READWRITE,
            )
            .unwrap()
            .0;
        let [name, name_buffer, object, port, sid] =
            [0x20, 0x40, 0x80, 0xc0, 0x140].map(|offset| base + offset);
        let out = base + PAGE_SIZE;
        let recv = out + PAGE_SIZE;
        let units: Vec<_> = "\\RPC Control\\LSARPC_ENDPOINT".encode_utf16().collect();
        let name_length = (units.len() * 2) as u16;
        assert_eq!(name_length, 56);
        p.space.w16(name, name_length).unwrap();
        p.space.w16(name + 2, name_length + 2).unwrap();
        p.space.wptr(name + width, width, name_buffer).unwrap();
        p.space.put_wstr(name_buffer, &units).unwrap();

        for (slot, value) in [0x0209_0000, 12, 2, 1].into_iter().enumerate() {
            p.space.w32(port + 4 * slot as u64, value).unwrap();
        }
        for (slot, value) in [4096, 0, u32::MAX, u32::MAX, u32::MAX, u32::MAX]
            .into_iter()
            .enumerate()
        {
            p.space
                .wptr(port + 16 + width * slot as u64, width, value.into())
                .unwrap();
        }
        p.space.w32(port + 16 + 6 * width, 4093).unwrap();
        // The native ABI ignores the SQOS padding. It must not select a
        // different profile when the caller does not zero that padding.
        p.space.w16(port + 14, 0x5a5a).unwrap();
        let count = p.objects.handle_count();
        for (case, expected_status) in expected.into_iter().enumerate() {
            let context = format!("{arch} row {case}");
            p.vm.protect(out, PAGE_SIZE, prot::READWRITE).unwrap();
            p.vm.protect(recv, PAGE_SIZE, prot::READWRITE).unwrap();
            let sid_rid = if case == 1 { 19 } else { 18 };
            p.space
                .wr(sid, &[1, 1, 0, 0, 0, 0, 0, 5, sid_rid, 0, 0, 0])
                .unwrap();
            p.space
                .w32(object, if case == 5 { 0 } else { 6 * width as u32 })
                .unwrap();
            let valid = u32::from(case == 4);
            p.space.w64(recv, u64::from(valid) << 32).unwrap();
            p.space.wr(recv + 8, &[0xa5; 16]).unwrap();
            p.space.wptr(out, width, 0x1122_3344).unwrap();
            if case == 6 {
                p.vm.protect(out, PAGE_SIZE, prot::READONLY).unwrap();
            }
            if case == 7 {
                p.vm.protect(recv, PAGE_SIZE, prot::READONLY).unwrap();
            }
            assert_eq!(
                invoke(
                    p,
                    &mut thread,
                    "NtAlpcConnectPort",
                    CONNECT,
                    &[
                        out,
                        name,
                        if case == 8 { 0 } else { object },
                        port,
                        0x20000,
                        if case == 2 { 0 } else { sid },
                        0,
                        0,
                        0,
                        if case == 3 { 0 } else { recv },
                        0,
                    ],
                ),
                Outcome::Continue,
                "{context}",
            );
            assert_eq!(thread.cpu.gpr(0), u64::from(expected_status), "{context}");
            assert_eq!(p.space.u32(recv).unwrap(), 0, "{context}");
            let expected_valid = if expected_status == STATUS_SUCCESS {
                0
            } else {
                valid
            };
            assert_eq!(p.space.u32(recv + 4).unwrap(), expected_valid, "{context}");
            assert_eq!(
                p.space.bytes(recv + 8, 16).unwrap(),
                [0xa5; 16],
                "{context}"
            );
            let handle = p.space.ptr(out, width).unwrap();
            if expected_status == STATUS_SUCCESS {
                assert!(
                    matches!(p.objects.get(handle), Some(Object::LpcPort(peer)) if peer.is_lsarpc())
                );
                assert_eq!(p.objects.access(handle), Some(PORT_ACCESS), "{context}");
                assert_eq!(p.objects.handle_count(), count + 1, "{context}");
                if case == 0 {
                    let send = invoke(
                        p,
                        &mut thread,
                        "NtAlpcSendWaitReceivePort",
                        SERVICE,
                        &[handle, 0x20000, 0, 0, 0, 0, 0, 0],
                    );
                    assert!(
                        matches!(send, Outcome::Fail(message) if message.contains("LSARPC message transport"))
                    );
                }
                assert_eq!(
                    invoke(p, &mut thread, "NtClose", 0xf, &[handle]),
                    Outcome::Continue
                );
                assert_eq!(thread.cpu.gpr(0), 0, "{context}");
                assert!(p.objects.get(handle).is_none(), "{context}");
            } else {
                assert_eq!(handle, 0x1122_3344, "{context}");
            }
            assert_eq!(p.objects.handle_count(), count, "{context}");
        }

        // The captured configuration does not enumerate the other endpoints in
        // the native RPC directory. An unselected sibling must never connect
        // to the local account-lookup peer.
        p.space
            .w16(name_buffer + u64::from(name_length) - 2, u16::from(b'!'))
            .unwrap();
        p.space.wptr(out, width, 0x1122_3344).unwrap();
        assert!(matches!(
            invoke(p, &mut thread, "NtAlpcConnectPort", CONNECT, &[out, name, object, port, 0x20000, sid, 0, 0, 0, recv, 0]),
            Outcome::Fail(message) if message.contains("outside the selected local endpoints")
        ));
        assert_eq!(p.space.ptr(out, width).unwrap(), 0x1122_3344);
        assert_eq!(p.objects.handle_count(), count);
    }
}
