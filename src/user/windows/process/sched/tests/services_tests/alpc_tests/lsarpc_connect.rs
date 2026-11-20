use super::*;
use crate::user::windows::loader::services::tests::named_table;
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::LsarpcInterface;

const CONNECT: u32 = 0x7b;
const QUERY: u32 = 0x8b;
const PROFILE_BUILD: u32 = 29708;
const PORT_ACCESS: u32 = 0x001f_0001;

pub(super) fn invoke(
    p: &mut Proc,
    t: &mut Thread,
    name: &str,
    number: u32,
    args: &[u64],
) -> Outcome {
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
    let wow64_expected = [
        STATUS_SUCCESS,               // aligned receive attributes
        STATUS_SERVER_SID_MISMATCH,   // wrong SID, aligned attributes
        STATUS_DATATYPE_MISALIGNMENT, // receive attributes aligned to 4 bytes
        STATUS_SERVER_SID_MISMATCH,   // wrong SID, misaligned attributes
        STATUS_SUCCESS,               // no receive attributes
        STATUS_SUCCESS,               // unaligned handle destination
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
        let extra = if arch == WinArch::X86 {
            wow64_expected.as_slice()
        } else {
            &[]
        };
        for (case, &expected_status) in expected.iter().chain(extra).enumerate() {
            let context = format!("{arch} row {case}");
            p.vm.protect(out, PAGE_SIZE, prot::READWRITE).unwrap();
            p.vm.protect(recv, PAGE_SIZE, prot::READWRITE).unwrap();
            let sid_rid = if matches!(case, 1 | 10 | 12) { 19 } else { 18 };
            let flags = if case >= expected.len() {
                0x4002_0000
            } else {
                0x20000
            };
            let receive_storage = if matches!(case, 11 | 12) {
                recv + 4
            } else {
                recv
            };
            let receive = if matches!(case, 3 | 13) {
                0
            } else {
                receive_storage
            };
            let handle_storage = if case == 14 { out + 1 } else { out };
            p.space
                .wr(sid, &[1, 1, 0, 0, 0, 0, 0, 5, sid_rid, 0, 0, 0])
                .unwrap();
            p.space
                .w32(object, if case == 5 { 0 } else { 6 * width as u32 })
                .unwrap();
            let valid = if case >= 11 {
                0x1234_5678
            } else {
                u32::from(case == 4)
            };
            p.space
                .w64(receive_storage, u64::from(valid) << 32)
                .unwrap();
            p.space.wr(receive_storage + 8, &[0xa5; 16]).unwrap();
            p.space.wptr(handle_storage, width, 0x1122_3344).unwrap();
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
                        handle_storage,
                        name,
                        if case == 8 { 0 } else { object },
                        port,
                        flags,
                        if case == 2 { 0 } else { sid },
                        0,
                        0,
                        0,
                        receive,
                        0,
                    ],
                ),
                Outcome::Continue,
                "{context}",
            );
            assert_eq!(thread.cpu.gpr(0), u64::from(expected_status), "{context}");
            assert_eq!(p.space.u32(receive_storage).unwrap(), 0, "{context}");
            let expected_valid = if expected_status == STATUS_SUCCESS && receive != 0 {
                0
            } else {
                valid
            };
            assert_eq!(
                p.space.u32(receive_storage + 4).unwrap(),
                expected_valid,
                "{context}"
            );
            assert_eq!(
                p.space.bytes(receive_storage + 8, 16).unwrap(),
                [0xa5; 16],
                "{context}"
            );
            let handle = p.space.ptr(handle_storage, width).unwrap();
            if expected_status == STATUS_SUCCESS {
                assert!(
                    matches!(p.objects.get(handle), Some(Object::LpcPort(peer)) if peer.is_lsarpc())
                );
                assert_eq!(p.objects.access(handle), Some(PORT_ACCESS), "{context}");
                assert_eq!(p.objects.handle_count(), count + 1, "{context}");
                if case == 0 {
                    assert_eq!(
                        invoke(
                            p,
                            &mut thread,
                            "NtAlpcQueryInformation",
                            QUERY,
                            &[handle, 0, recv + 8, 8 + width, 0]
                        ),
                        Outcome::Continue,
                    );
                    assert_eq!(thread.cpu.gpr(0), u64::from(STATUS_SUCCESS));
                    assert_eq!(p.space.ptr(recv + 16, width).unwrap(), handle);
                    let send = invoke(
                        p,
                        &mut thread,
                        "NtAlpcSendWaitReceivePort",
                        SERVICE,
                        &[handle, 0x20000, 0, 0, 0, 0, 0, 0],
                    );
                    assert_eq!(send, Outcome::Continue);
                    assert_eq!(thread.cpu.gpr(0), u64::from(STATUS_INVALID_PARAMETER_2));
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

#[test]
fn native_lsarpc_information_replays_user_copy_and_handle_lifetime() {
    const LENGTH_SEED: u32 = 0xabcd_ef12;
    const CANARY: u8 = 0xa5;
    for arch in WinArch::ALL {
        let (mut process, mut thread) = fixture(arch, "NtClose", CONNECT);
        let p = process.state_mut();
        super::super::native_profile::kernel_profile(p, PROFILE_BUILD, 0xaa64);
        let base =
            p.vm.allocate(
                None,
                3 * PAGE_SIZE,
                mem::RESERVE | mem::COMMIT,
                prot::READWRITE,
            )
            .unwrap()
            .0;
        let boundary = base + PAGE_SIZE;
        let output = base + 0x40;
        let readonly = boundary + 0x40;
        let returned = boundary + PAGE_SIZE;
        let wow = arch == WinArch::X86;
        let width = arch.ptr_size();
        let size = 8 + width;
        let port = u64::from(
            p.objects
                .insert(Object::LpcPort(LpcPort::lsarpc(LsarpcInterface::Policy))),
        );
        let Some(Object::LpcPort(peer)) = p.objects.get_mut(port) else {
            panic!("fixture port");
        };
        peer.set_lsarpc_context(port as u32);
        let duplicate = u64::from(p.objects.duplicate(port, false).unwrap());
        let id = p.objects.id(port).unwrap();
        let no_access = u64::from(p.objects.open_access(id, false, 0).unwrap());
        let connect_only = u64::from(p.objects.open_access(id, false, 1).unwrap());
        let read_control = u64::from(p.objects.open_access(id, false, 0x0002_0000).unwrap());
        let invalid = 0x4455_aa00;
        let current = arch.ptr(u64::MAX);
        let class = u64::from(u32::MAX);
        let failure_length = if wow { 0xffff_fffc } else { LENGTH_SEED };
        let need = size as u32;

        // Syscall arguments followed by status, separate length and visible
        // record. An alias at output or output + 8 overwrites that field.
        type Case = (&'static str, [u64; 5], u32, u32, bool);
        let cases: &[Case] = &[
            ("exact", [port, 0, output, size, returned], 0, need, true),
            ("excess", [port, 0, output, 64, returned], 0, need, true),
            (
                "short",
                [port, 0, output, size - 1, returned],
                STATUS_INFO_LENGTH_MISMATCH,
                need,
                false,
            ),
            (
                "zero, read-only body",
                [port, 0, readonly, 0, returned],
                STATUS_INFO_LENGTH_MISMATCH,
                need,
                false,
            ),
            (
                "NULL length",
                [port, 0, output, size, 0],
                0,
                LENGTH_SEED,
                true,
            ),
            (
                "NULL port",
                [0, 0, output, size, returned],
                STATUS_INVALID_PARAMETER,
                failure_length,
                false,
            ),
            (
                "no port access",
                [no_access, 0, output, size, returned],
                STATUS_ACCESS_DENIED,
                failure_length,
                false,
            ),
            (
                "PORT_CONNECT grant",
                [connect_only, 0, output, size, returned],
                STATUS_ACCESS_DENIED,
                failure_length,
                false,
            ),
            (
                "READ_CONTROL grant",
                [read_control, 0, output, size, returned],
                STATUS_SUCCESS,
                need,
                true,
            ),
            (
                "NULL port, read-only output",
                [0, 0, readonly, size, returned],
                if wow {
                    STATUS_INVALID_PARAMETER
                } else {
                    STATUS_ACCESS_VIOLATION
                },
                failure_length,
                false,
            ),
            (
                "NULL port, unaligned output",
                [0, 0, output + 1, size, returned],
                if wow {
                    STATUS_INVALID_PARAMETER
                } else {
                    STATUS_DATATYPE_MISALIGNMENT
                },
                failure_length,
                false,
            ),
            (
                "NULL body, invalid port",
                [invalid, 0, 0, size, returned],
                STATUS_INVALID_PARAMETER,
                failure_length,
                false,
            ),
            (
                "NULL body, bad length destination",
                [port, 0, 0, size, readonly],
                if wow {
                    STATUS_ACCESS_VIOLATION
                } else {
                    STATUS_INVALID_PARAMETER
                },
                LENGTH_SEED,
                false,
            ),
            (
                "invalid handle",
                [invalid, 0, output, size, returned],
                STATUS_INVALID_HANDLE,
                failure_length,
                false,
            ),
            (
                "wrong object type",
                [current, 0, output, 1, returned],
                STATUS_OBJECT_TYPE_MISMATCH,
                failure_length,
                false,
            ),
            (
                "unknown class",
                [port, class, output, size, returned],
                if wow {
                    STATUS_INVALID_INFO_CLASS
                } else {
                    STATUS_INVALID_PARAMETER
                },
                LENGTH_SEED,
                false,
            ),
            (
                "unknown class, invalid handle",
                [invalid, class, output, size, returned],
                if wow {
                    STATUS_INVALID_INFO_CLASS
                } else {
                    STATUS_INVALID_HANDLE
                },
                LENGTH_SEED,
                false,
            ),
            (
                "unknown class, read-only body",
                [port, class, readonly, size, returned],
                if wow {
                    STATUS_INVALID_INFO_CLASS
                } else {
                    STATUS_ACCESS_VIOLATION
                },
                LENGTH_SEED,
                false,
            ),
            (
                "unaligned body",
                [port, 0, output + 1, size, returned],
                if wow { 0 } else { STATUS_DATATYPE_MISALIGNMENT },
                if wow { need } else { LENGTH_SEED },
                wow,
            ),
            (
                "DWORD-aligned body",
                [port, 0, output + 4, size, returned],
                0,
                need,
                true,
            ),
            (
                "read-only short body",
                [port, 0, readonly, 1, returned],
                if wow {
                    STATUS_INFO_LENGTH_MISMATCH
                } else {
                    STATUS_ACCESS_VIOLATION
                },
                if wow { need } else { LENGTH_SEED },
                false,
            ),
            (
                "read-only length",
                [port, 0, output, size, readonly],
                STATUS_ACCESS_VIOLATION,
                LENGTH_SEED,
                wow,
            ),
            (
                "record crosses read-only boundary",
                [port, 0, boundary - 8, size, returned],
                STATUS_ACCESS_VIOLATION,
                LENGTH_SEED,
                false,
            ),
            (
                "excess crosses read-only boundary",
                [port, 0, boundary - size, 64, returned],
                if wow { 0 } else { STATUS_ACCESS_VIOLATION },
                if wow { need } else { LENGTH_SEED },
                wow,
            ),
            (
                "length aliases flags",
                [port, 0, output, size, output],
                0,
                LENGTH_SEED,
                true,
            ),
            (
                "length overlaps flags unaligned",
                [port, 0, output, size, output + 1],
                0,
                LENGTH_SEED,
                true,
            ),
            (
                "length aliases context",
                [port, 0, output, size, output + 8],
                0,
                LENGTH_SEED,
                true,
            ),
            (
                "handle tag bits",
                [port | 1, 0, output, size, returned],
                0,
                need,
                true,
            ),
            (
                "duplicate",
                [duplicate, 0, output, size, returned],
                0,
                need,
                true,
            ),
            (
                "duplicate after close",
                [duplicate, 0, output, size, returned],
                0,
                need,
                true,
            ),
            (
                "original after close",
                [port, 0, output, size, returned],
                STATUS_INVALID_HANDLE,
                failure_length,
                false,
            ),
        ];
        let mut basic = [0; 16];
        basic[..4].copy_from_slice(&0x0209_0000u32.to_le_bytes());
        basic[4..8].copy_from_slice(&1u32.to_le_bytes());
        basic[8..].copy_from_slice(&port.to_le_bytes());
        for &(name, args, status, length, writes_body) in cases {
            let [_, _, dest, _, used] = args;
            if name == "duplicate after close" {
                assert_eq!(
                    invoke(p, &mut thread, "NtClose", 0xf, &[port]),
                    Outcome::Continue
                );
                assert_eq!(thread.cpu.gpr(0), u64::from(STATUS_SUCCESS));
            }
            p.vm.protect(boundary, PAGE_SIZE, prot::READWRITE).unwrap();
            let observed = if dest != 0 { dest } else { output };
            p.space.wr(observed, &[CANARY; 32]).unwrap();
            p.space.wr(readonly, &[CANARY; 32]).unwrap();
            p.space.w32(returned, LENGTH_SEED).unwrap();
            p.vm.protect(boundary, PAGE_SIZE, prot::READONLY).unwrap();

            assert_eq!(
                invoke(p, &mut thread, "NtAlpcQueryInformation", QUERY, &args),
                Outcome::Continue,
                "{arch} {name}"
            );
            assert_eq!(thread.cpu.gpr(0), u64::from(status), "{arch} {name}");
            assert_eq!(p.space.u32(returned).unwrap(), length, "{arch} {name}");
            let mut expected = [CANARY; 32];
            if writes_body {
                expected[..size as usize].copy_from_slice(&basic[..size as usize]);
                if (dest..dest + size).contains(&used) {
                    let offset = (used - dest) as usize;
                    expected[offset..offset + 4].copy_from_slice(&need.to_le_bytes());
                }
            }
            assert_eq!(
                p.space.bytes(observed, 32).unwrap(),
                expected,
                "{arch} {name}"
            );
            if used == readonly {
                assert_eq!(
                    p.space.u32(readonly).unwrap(),
                    u32::from_le_bytes([CANARY; 4])
                );
            }
        }
    }
}
