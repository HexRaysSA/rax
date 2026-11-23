use super::*;
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::LsarpcInterface;
use crate::user::windows::security::privilege_names::{DisplayCatalog, DisplayName};
use std::sync::Arc;

const POLICY_LOOKUP_NAMES: u32 = 0x800;
const CONTEXT: u32 = 0x2000_0000;

fn write_word(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn bind() -> Vec<u8> {
    let mut payload = vec![0; 72];
    for (offset, value) in [
        (0, 1),
        (12, 0x12345778),
        (16, 0xabcd1234),
        (20, 0x230100ef),
        (24, 0xab896745),
        (32, 3),
    ] {
        write_word(&mut payload, offset, value);
    }
    payload
}

fn into_call(bytes: usize, call: u32, operation: u32) -> Vec<u8> {
    let mut payload = vec![0; bytes];
    write_word(&mut payload, 12, call);
    write_word(&mut payload, 16, 1);
    write_word(&mut payload, 20, operation);
    payload
}

fn open(call: u32, access: u32, version: u32) -> Vec<u8> {
    let mut payload = into_call(152, call, 130);
    for (offset, value) in [
        (72, 48),
        (112, 0x20000),
        (120, 12),
        (124, 2),
        (128, 1),
        (132, access),
        (136, version),
        (140, version),
        (144, 1),
    ] {
        write_word(&mut payload, offset, value);
    }
    payload
}

fn lookup(call: u32, context: &[u8], name: &str) -> Vec<u8> {
    let units = name.encode_utf16().collect::<Vec<_>>();
    let length = (units.len() * 2) as u16;
    let mut payload = into_call((128 + length as usize).next_multiple_of(8), call, 31);
    payload[64..84].copy_from_slice(context);
    payload[88..90].copy_from_slice(&length.to_le_bytes());
    payload[90..92].copy_from_slice(&(length + 2).to_le_bytes());
    write_word(&mut payload, 96, 0x20000);
    write_word(&mut payload, 104, units.len() as u32 + 1);
    write_word(&mut payload, 120, units.len() as u32);
    for (unit, chunk) in units.into_iter().zip(payload[128..].chunks_exact_mut(2)) {
        chunk.copy_from_slice(&unit.to_le_bytes());
    }
    payload
}

fn lookup_name(call: u32, context: &[u8], low: u32, high: u32) -> Vec<u8> {
    let mut payload = into_call(92, call, 32);
    payload[64..84].copy_from_slice(context);
    write_word(&mut payload, 84, low);
    write_word(&mut payload, 88, high);
    payload
}

fn lookup_display(call: u32, context: &[u8], name: &str, languages: [u16; 2]) -> Vec<u8> {
    let mut packet = lookup(call, context, name);
    write_word(&mut packet, 20, 33);
    packet.truncate(128 + name.encode_utf16().count() * 2);
    for language in languages {
        packet.extend_from_slice(&language.to_le_bytes());
    }
    packet
}

fn close(call: u32, context: &[u8]) -> Vec<u8> {
    let mut payload = into_call(84, call, 0);
    payload[64..84].copy_from_slice(context);
    payload
}

fn new_port(p: &mut Proc) -> u64 {
    let handle = u64::from(
        p.objects
            .insert(Object::LpcPort(LpcPort::lsarpc(LsarpcInterface::Policy))),
    );
    let Some(Object::LpcPort(port)) = p.objects.get_mut(handle) else {
        panic!("fixture port");
    };
    port.set_lsarpc_context(handle as u32);
    handle
}

fn partially_copy_open(p: &mut Proc, thread: &mut Thread, base: u64, port: u64) -> Vec<u8> {
    let width = p.arch.ptr_size();
    let header = if p.arch.is64() { 40 } else { 24 };
    let payload = open(3, POLICY_LOOKUP_NAMES, 1);
    let length = base + 832;
    let receive = base + PAGE_SIZE - (header + 60);
    p.vm.protect(base + PAGE_SIZE, PAGE_SIZE, prot::READONLY)
        .unwrap();
    p.space.wr(base, &[0; 256]).unwrap();
    p.space.w16(base, payload.len() as u16).unwrap();
    p.space
        .w16(base + 2, (header as usize + payload.len()) as u16)
        .unwrap();
    p.space.wr(base + header, &payload).unwrap();
    p.space.wptr(length, width, 4096).unwrap();
    assert_eq!(
        invoke(p, thread, &[port, 0x20000, base, 0, receive, length, 0, 0]),
        Outcome::Continue
    );
    assert_eq!(thread.cpu.gpr(0), u64::from(STATUS_ACCESS_VIOLATION));
    assert_eq!(p.space.ptr(length, width).unwrap(), 4096);
    p.space.bytes(receive + header + 40, 20).unwrap()
}

fn exchange(
    p: &mut Proc,
    thread: &mut Thread,
    [base, port, allocation, capacity]: [u64; 4],
    payload: &[u8],
) -> (Outcome, u32, Vec<u8>) {
    let header = if p.arch.is64() { 40 } else { 24 };
    let width = p.arch.ptr_size();
    let context_offset = match (allocation, width) {
        (0, _) => 0,
        (0x2000_0000, _) => 8,
        (_, 8) => 40,
        _ => 24,
    };
    let reply = base + 256;
    let attribute = base + 640;
    let length = base + 832;
    p.space.wr(base, &[0; 256]).unwrap();
    p.space.w16(base, payload.len() as u16).unwrap();
    p.space
        .w16(base + 2, (header + payload.len()) as u16)
        .unwrap();
    p.space.wr(base + header as u64, payload).unwrap();
    p.space.wr(reply, &[0xa5; 256]).unwrap();
    p.space.wr(attribute, &[0xa5; 136]).unwrap();
    p.space.w32(attribute, allocation as u32).unwrap();
    p.space
        .w32(
            attribute + 4,
            match allocation {
                0 => 0,
                0x7e00_0000 => CONTEXT | 0x0200_0000,
                _ => CONTEXT,
            },
        )
        .unwrap();
    if context_offset != 0 {
        p.space
            .wptr(attribute + context_offset + width, width, 0x123456)
            .unwrap();
    }
    p.space.wptr(length, width, capacity).unwrap();
    let outcome = invoke(
        p,
        thread,
        &[port, 0x20000, base, attribute, reply, length, attribute, 0],
    );
    let status = thread.cpu.gpr(0) as u32;
    if outcome != Outcome::Continue || status != STATUS_SUCCESS {
        assert_eq!(p.space.bytes(reply, 256).unwrap(), [0xa5; 256]);
        if status == STATUS_BUFFER_TOO_SMALL {
            assert_eq!(p.space.ptr(length, width).unwrap(), (header + 136) as u64);
        }
        return (outcome, status, Vec::new());
    }
    let total = p.space.u16(reply + 2).unwrap() as usize;
    let payload_bytes = p.space.u16(reply).unwrap() as usize;
    assert_eq!(total, header + payload_bytes);
    assert_eq!(p.space.ptr(length, width).unwrap(), total as u64);
    assert_eq!(
        p.space.u16(reply + 4).unwrap(),
        if p.arch.is64() { 2 } else { 0x1002 }
    );
    if context_offset != 0 {
        assert_eq!(p.space.u32(attribute + 4).unwrap(), CONTEXT);
        assert_eq!(
            p.space
                .ptr(attribute + context_offset + width, width)
                .unwrap(),
            0x123456
        );
        if context_offset > 8 {
            assert_eq!(
                p.space
                    .bytes(attribute + 8, (context_offset - 8) as usize)
                    .unwrap(),
                vec![0xa5; (context_offset - 8) as usize]
            );
        }
    }
    (
        outcome,
        status,
        p.space.bytes(reply + header as u64, payload_bytes).unwrap(),
    )
}

#[test]
fn native_lsarpc_policy_contexts_own_lookup_rights_and_lifetime() {
    for arch in WinArch::ALL {
        let (mut process, mut thread) = fixture(arch, "NtAlpcSendWaitReceivePort", SERVICE);
        let p = process.state_mut();
        super::super::native_profile::kernel_profile(p, 29708, 0xaa64);
        let base =
            p.vm.allocate(
                None,
                2 * PAGE_SIZE,
                mem::RESERVE | mem::COMMIT,
                prot::READWRITE,
            )
            .unwrap()
            .0;
        let original = new_port(p);
        let alias = u64::from(p.objects.duplicate(original, false).unwrap());
        let send =
            |p: &mut Proc, thread: &mut Thread, port, payload: &[u8], allocation, capacity| {
                exchange(p, thread, [base, port, allocation, capacity], payload)
            };

        let (outcome, _, _) = send(
            p,
            &mut thread,
            original,
            &open(2, POLICY_LOOKUP_NAMES, 1),
            0,
            4096,
        );
        assert!(matches!(outcome, Outcome::Fail(s) if s.contains("require a local RPC bind")));

        let (outcome, status, result) =
            send(p, &mut thread, original, &bind(), CONTEXT.into(), 4096);
        assert_eq!(
            (outcome, status, word(&result, 32)),
            (Outcome::Continue, STATUS_SUCCESS, 2)
        );

        let (outcome, status, _) = send(
            p,
            &mut thread,
            original,
            &open(2, POLICY_LOOKUP_NAMES, 1),
            0x7e00_0000,
            16,
        );
        assert_eq!(
            (outcome, status),
            (Outcome::Continue, STATUS_BUFFER_TOO_SMALL)
        );
        let stale = partially_copy_open(p, &mut thread, base, original);
        assert_ne!(stale, [0; 20]);
        for (access, version, result_status) in [
            (0, 1, STATUS_INVALID_PARAMETER),
            (POLICY_LOOKUP_NAMES | 4, 1, STATUS_ACCESS_DENIED),
            (POLICY_LOOKUP_NAMES, 2, STATUS_NOT_SUPPORTED),
        ] {
            let (outcome, status, result) = send(
                p,
                &mut thread,
                original,
                &open(4, access, version),
                0x7e00_0000,
                4096,
            );
            assert_eq!(
                (outcome, status, word(&result, 60)),
                (Outcome::Continue, STATUS_SUCCESS, result_status)
            );
            assert_eq!(&result[40..60], &[0; 20]);
        }

        let (outcome, status, result) = send(
            p,
            &mut thread,
            original,
            &open(5, POLICY_LOOKUP_NAMES, 1),
            0x7e00_0000,
            4096,
        );
        assert_eq!(
            (outcome, status, result.len()),
            (Outcome::Continue, STATUS_SUCCESS, 136)
        );
        for (offset, value) in [(0, 3), (12, 5), (24, 1), (28, 1), (32, 1), (36, 0), (60, 0)] {
            assert_eq!(word(&result, offset), value);
        }
        let token = result[40..60].to_vec();
        assert_ne!(token, [0; 20]);
        assert_ne!(token, stale);
        assert_eq!(&token[12..], &2u64.to_le_bytes());
        let (_, _, rejected) = send(
            p,
            &mut thread,
            original,
            &lookup(6, &stale, "SeDebugPrivilege"),
            0x7e00_0000,
            4096,
        );
        assert_eq!(word(&rejected, 32), STATUS_INVALID_HANDLE);
        let (_, _, second) = send(
            p,
            &mut thread,
            original,
            &open(8, POLICY_LOOKUP_NAMES, 1),
            0x6000_0000,
            4096,
        );
        assert_ne!(&token, &second[40..60]);

        p.objects.close(original).unwrap();
        let other = new_port(p);
        assert_eq!(other, original); // The port number can be reused.
        let (_, _, _) = send(p, &mut thread, other, &bind(), CONTEXT.into(), 4096);
        let (_, _, foreign) = send(
            p,
            &mut thread,
            other,
            &lookup(10, &token, "SeDebugPrivilege"),
            0x7e00_0000,
            4096,
        );
        assert_eq!(word(&foreign, 32), STATUS_INVALID_HANDLE);
        let (_, _, newest) = send(
            p,
            &mut thread,
            other,
            &open(11, POLICY_LOOKUP_NAMES, 1),
            0,
            4096,
        );
        assert_ne!(&token, &newest[40..60]);

        for (name, expected, rpc_status) in [
            ("SeDebugPrivilege", 20, STATUS_SUCCESS),
            ("sechangenotifyprivilege", 23, STATUS_SUCCESS),
            ("SeTimeZonePrivilege", 34, STATUS_SUCCESS),
            (
                "SeDelegateSessionUserImpersonatePrivilege",
                36,
                STATUS_SUCCESS,
            ),
            ("SeUnsolicitedInputPrivilege", 0, 0xc000_0060),
        ] {
            let (_, status, result) = send(
                p,
                &mut thread,
                alias,
                &lookup(22, &token, name),
                0x7e00_0000,
                4096,
            );
            assert_eq!(status, STATUS_SUCCESS);
            assert_eq!(result.len(), 80);
            for (offset, value) in [(0, 3), (12, 22), (24, expected), (28, 0), (32, rpc_status)] {
                assert_eq!(word(&result, offset), value);
            }
        }
        for (low, name, reply_bytes) in [
            (2, "SeCreateTokenPrivilege", 124),
            (23, "SeChangeNotifyPrivilege", 128),
            (36, "SeDelegateSessionUserImpersonatePrivilege", 164),
        ] {
            let (_, status, result) = send(
                p,
                &mut thread,
                alias,
                &lookup_name(33, &token, low, 0),
                0x7e00_0000,
                4096,
            );
            assert_eq!(status, STATUS_SUCCESS);
            let units = name.encode_utf16().collect::<Vec<_>>();
            let mut expected = vec![0; reply_bytes];
            for (offset, value) in [
                (0, 3),
                (12, 33),
                (24, 0x20000),
                (
                    32,
                    ((units.len() as u32 * 2 + 2) << 16) | units.len() as u32 * 2,
                ),
                (40, 0x20000),
                (48, units.len() as u32 + 1),
                (64, units.len() as u32),
            ] {
                write_word(&mut expected, offset, value);
            }
            for (unit, chunk) in units.into_iter().zip(expected[72..].chunks_exact_mut(2)) {
                chunk.copy_from_slice(&unit.to_le_bytes());
            }
            assert_eq!(result, expected);
        }

        for (port, low, high, rpc_status) in [
            (alias, 0, 0, 0xc000_0060),
            (alias, 37, 0, 0xc000_0060),
            (alias, 23, 1, 0xc000_0060),
            (other, 23, 0, STATUS_INVALID_HANDLE),
        ] {
            let (_, status, result) = send(
                p,
                &mut thread,
                port,
                &lookup_name(34, &token, low, high),
                0x7e00_0000,
                4096,
            );
            assert_eq!(status, STATUS_SUCCESS);
            let mut expected = vec![0; 40];
            for (offset, value) in [(0, 3), (12, 34), (32, rpc_status)] {
                write_word(&mut expected, offset, value);
            }
            assert_eq!(result, expected);
        }

        let (_, status, result) =
            send(p, &mut thread, alias, &close(23, &token), 0x7e00_0000, 4096);
        assert_eq!(status, STATUS_SUCCESS);
        assert_eq!(result.len(), 92);
        assert_eq!(word(&result, 12), 23);
        assert_eq!(&result[24..48], &[0; 24]);
        let (_, _, result) = send(p, &mut thread, alias, &close(24, &token), 0x7e00_0000, 4096);
        assert_eq!(word(&result, 44), STATUS_INVALID_HANDLE);
        let (_, _, result) = send(
            p,
            &mut thread,
            alias,
            &lookup_name(35, &token, 23, 0),
            0,
            4096,
        );
        assert_eq!(word(&result, 32), STATUS_INVALID_HANDLE);
        let (_, _, result) = send(
            p,
            &mut thread,
            alias,
            &lookup(29, &second[40..60], "SeDebugPrivilege"),
            0,
            4096,
        );
        assert_eq!(word(&result, 24), 20); // Closing one context preserves the others.
    }
}

#[test]
fn native_lsarpc_privilege_display_uses_captured_languages() {
    for arch in WinArch::ALL {
        let (mut process, mut thread) = fixture(arch, "NtAlpcSendWaitReceivePort", SERVICE);
        let p = process.state_mut();
        super::super::native_profile::kernel_profile(p, 29708, 0xaa64);
        let base =
            p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        let port = new_port(p);
        let mut send = |p: &mut Proc, payload: &[u8]| {
            exchange(p, &mut thread, [base, port, 0x7e00_0000, 4096], payload)
        };
        assert_eq!(send(p, &bind()).1, STATUS_SUCCESS);
        let (_, status, opened) = send(p, &open(3, POLICY_LOOKUP_NAMES, 1));
        assert_eq!(status, STATUS_SUCCESS);
        let context = &opened[40..60];

        // Native ARM64 build 29708, including both text-length alignment cases.
        let privilege = "SeCreateTokenPrivilege";
        for (requested, language, text, reply_bytes) in [
            ([0x0409, 0x0009], 0x0409_u16, "Create a token object", 156),
            ([0x040c, 0x0409], 0x040c, "Créer un objet-jeton", 152),
        ] {
            let units: Vec<_> = text.encode_utf16().collect();
            let catalog = DisplayCatalog {
                requested,
                names: [(
                    2,
                    DisplayName {
                        units: units.clone(),
                        language,
                    },
                )]
                .into(),
            };
            p.native
                .as_mut()
                .unwrap()
                .object_namespace
                .privilege_display_names = Some(Arc::new(catalog));

            let (_, status, result) = send(p, &lookup_display(4, context, privilege, requested));
            assert_eq!(status, STATUS_SUCCESS);
            let mut expected = vec![0; reply_bytes];
            let length = units.len() as u32 * 2;
            for (offset, value) in [
                (0, 3),
                (12, 4),
                (24, 0x20000),
                (32, ((length + 2) << 16) | length),
                (40, 0x20000),
                (48, units.len() as u32 + 1),
                (64, units.len() as u32),
            ] {
                write_word(&mut expected, offset, value);
            }
            let end = 72 + length as usize;
            for (unit, chunk) in units.iter().zip(expected[72..end].chunks_exact_mut(2)) {
                chunk.copy_from_slice(&unit.to_le_bytes());
            }
            expected[end..end + 2].copy_from_slice(&language.to_le_bytes());
            assert_eq!(result, expected);

            // A successful match in the first language makes the fallback irrelevant.
            let (_, status, result) =
                send(p, &lookup_display(4, context, privilege, [requested[0], 0]));
            assert_eq!(status, STATUS_SUCCESS);
            assert_eq!(result, expected);
        }

        let packet = lookup_display(5, context, privilege, [0x0409, 0x0009]);
        let (outcome, _, _) = send(p, &packet);
        assert!(matches!(outcome, Outcome::Fail(message) if message.contains("operation 33")));
        let mut malformed = lookup_display(6, context, privilege, [0x040c, 0x0409]);
        malformed.pop();
        let (outcome, _, _) = send(p, &malformed);
        assert!(matches!(outcome, Outcome::Fail(message) if message.contains("operation 33")));

        for (name, token, rpc_status) in [
            ("SeUnusedRaxTestPrivilege", context, 0xc000_0060),
            (privilege, &[0; 20], STATUS_INVALID_HANDLE),
        ] {
            let (_, status, result) = send(p, &lookup_display(7, token, name, [0x040c, 0x0409]));
            assert_eq!(status, STATUS_SUCCESS);
            let mut expected = vec![0; 72];
            for (offset, value) in [(0, 3), (12, 7), (36, rpc_status)] {
                write_word(&mut expected, offset, value);
            }
            assert_eq!(result, expected);
        }
    }
}
