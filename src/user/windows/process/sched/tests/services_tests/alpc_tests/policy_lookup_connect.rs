use super::lsarpc_connect::invoke;
use super::*;
use crate::user::windows::nt::status::{STATUS_INVALID_HANDLE, STATUS_SERVER_SID_MISMATCH};
use crate::user::windows::object_namespace::policy_lookup::{Name, PrimaryAccount};
use crate::user::windows::objects::LsarpcInterface;
use crate::user::windows::security::Subject;
use crate::user::windows::wnf::Catalog;
use std::sync::Arc;

const CONNECT: u32 = 0x7c;

#[test]
fn native_policy_lookup_connect_authenticates_the_virtual_server() {
    // Relative descriptor with an allow ACE for Everyone and two LocalSystem
    // SIDs. Its ACL is independent of the virtual RPC Control directory.
    let security = [
        1, 0, 4, 0x84, 48, 0, 0, 0, 60, 0, 0, 0, 0, 0, 0, 0, 20, 0, 0, 0, 2, 0, 28, 0, 1, 0, 0, 0,
        0, 0, 20, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0,
        0, 0, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
    ];
    for arch in WinArch::ALL {
        let (mut process, mut thread) = fixture(arch, "NtClose", CONNECT);
        let p = process.state_mut();
        super::super::native_profile::kernel_profile(p, 29708, 0xaa64);
        let width = arch.ptr_size();
        let base =
            p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        let [
            out,
            server,
            client,
            port,
            name,
            name_buffer,
            descriptor,
            input,
        ] = [0, 0x20, 0x60, 0xa0, 0x110, 0x130, 0x190, 0x1e0].map(|offset| base + offset);

        for object in [server, client] {
            p.space.w32(object, 6 * width as u32).unwrap();
        }
        p.space.wptr(server + 2 * width, width, name).unwrap();
        let units: Vec<_> = r"\RPC Control\lsapolicylookup".encode_utf16().collect();
        let length = (units.len() * 2) as u16;
        p.space.w16(name, length).unwrap();
        p.space.w16(name + 2, length + 2).unwrap();
        p.space.wptr(name + width, width, name_buffer).unwrap();
        p.space.put_wstr(name_buffer, &units).unwrap();

        for (index, value) in [0x0209_0000, 12, 2, 1].into_iter().enumerate() {
            p.space.w32(port + 4 * index as u64, value).unwrap();
        }
        for (index, value) in [4096, 0, u32::MAX, u32::MAX, u32::MAX, u32::MAX]
            .into_iter()
            .enumerate()
        {
            p.space
                .wptr(port + 16 + width * index as u64, width, value.into())
                .unwrap();
        }
        p.space.w32(port + 16 + 6 * width, 4093).unwrap();

        let args = [
            out, server, client, port, 0x20000, descriptor, 0, 0, 0, input, 0,
        ];
        let original_handles = p.objects.handle_count();
        let canary = 0x1122_3344;
        p.space.wptr(out, width, canary).unwrap();
        p.space.w32(input + 4, 0xa5a5_a5a5).unwrap();
        p.space.wr(descriptor, &security).unwrap();
        // READ_CONTROL by itself does not authenticate the server.
        p.space.w32(descriptor + 32, 0x0002_0000).unwrap();

        assert_eq!(
            invoke(p, &mut thread, "NtAlpcConnectPortEx", CONNECT, &args),
            Outcome::Continue
        );
        assert_eq!(thread.cpu.gpr(0), u64::from(STATUS_SERVER_SID_MISMATCH));
        assert_eq!(p.space.ptr(out, width).unwrap(), canary);
        assert_eq!(p.space.u32(input + 4).unwrap(), 0xa5a5_a5a5);
        assert_eq!(p.objects.handle_count(), original_handles);

        p.space.wr(descriptor, &security).unwrap();
        assert_eq!(
            invoke(p, &mut thread, "NtAlpcConnectPortEx", CONNECT, &args),
            Outcome::Continue
        );
        assert_eq!(thread.cpu.gpr(0), 0);
        assert_eq!(p.space.u64(input).unwrap(), 0);
        let handle = p.space.ptr(out, width).unwrap();
        assert_eq!(p.objects.handle_count(), original_handles + 1);
        assert_eq!(p.objects.access(handle), Some(0x001f_0001));
        let Some(Object::LpcPort(port)) = p.objects.get(handle) else {
            panic!("policy lookup connection did not create a local port");
        };
        assert_eq!(
            port.lsarpc_peer().unwrap().interface,
            LsarpcInterface::PolicyLookup
        );

        let mut bind = [0; 72];
        words(
            &mut bind,
            &[
                (0, 1),
                (12, 0xfb8a_0729),
                (16, 0x4658_2d04),
                (20, 0xb427_93be),
                (24, 0xac3f_55ad),
                (28, 1),
                (32, 3),
            ],
        );
        let reply = exchange(p, &mut thread, base + 0x400, handle, 0x4000, &bind);
        words(&mut bind, &[(32, 2)]);
        assert_eq!(reply, bind);

        let mut open = [0; 136];
        words(
            &mut open,
            &[
                (12, 10),
                (16, 1),
                (72, 48),
                (112, 0x20000),
                (120, 12),
                (124, 2),
                (128, 1),
                (132, 0x800),
            ],
        );
        let reply = exchange(p, &mut thread, base + 0x400, handle, 0, &open);
        assert_eq!(reply.len(), 92);
        assert_eq!(read_word(&reply, 0), 3);
        assert_eq!(read_word(&reply, 12), 10);
        assert_eq!(read_word(&reply, 44), 0);
        let context = &reply[24..44];
        assert_ne!(context, [0; 20]);

        let mut domain_sid = vec![1, 4, 0, 0, 0, 0, 0, 5];
        domain_sid.extend(
            [21u32, 101, 202, 303]
                .into_iter()
                .flat_map(u32::to_le_bytes),
        );
        let mut user_sid = domain_sid.clone();
        user_sid[1] = 5;
        user_sid.extend(1001u32.to_le_bytes());
        let subject = Subject {
            statistics: None,
            user_attributes: 0,
            token_pointer_records: Default::default(),
            empty_claims: Default::default(),
            user: user_sid.clone(),
            groups: Vec::new(),
            restricted: Vec::new(),
            app_container: false,
            privileges: Vec::new(),
            attributes: None,
        };
        p.objects
            .select_wnf_catalog(Catalog::selected(Vec::new(), subject).unwrap());
        p.native
            .as_mut()
            .unwrap()
            .object_namespace
            .policy_lookup_account = Some(Arc::new(PrimaryAccount {
            user_sid: user_sid.clone(),
            domain_sid: domain_sid.clone(),
            domain: Name {
                units: "TESTPC1".encode_utf16().collect(),
                maximum_units: 8,
            },
            account: Name {
                units: "abc".encode_utf16().collect(),
                maximum_units: 4,
            },
        }));

        let mut lookup = [0; 188];
        words(
            &mut lookup,
            &[
                (12, 20),
                (16, 1),
                (20, 2),
                (88, 1),
                (96, 0x20000),
                (104, 1),
                (112, 0x20004),
                (120, 5),
                (184, 2),
            ],
        );
        lookup[64..84].copy_from_slice(context);
        lookup[128..156].copy_from_slice(&user_sid);
        let mut wrong_sid = lookup;
        wrong_sid[152] ^= 1;
        assert_translation_rejected(p, &mut thread, base + 0x400, handle, &wrong_sid);
        for end in [127, 155, 187] {
            assert_translation_rejected(p, &mut thread, base + 0x400, handle, &lookup[..end]);
        }

        let translated = exchange(p, &mut thread, base + 0x400, handle, 0, &lookup);
        assert_eq!(translated.len(), 288);
        assert_eq!(read_word(&translated, 0), 3);
        assert_eq!(read_word(&translated, 12), 20);
        assert_eq!(read_word(&translated, 32), 1);
        assert_eq!(read_word(&translated, 48), 32);
        assert_eq!(read_word(&translated, 88), 8);
        assert_eq!(read_word(&translated, 104), 7);
        assert_eq!(&translated[112..126], b"T\0E\0S\0T\0P\0C\x001\0");
        assert_eq!(read_word(&translated, 128), 4);
        assert_eq!(&translated[136..160], &domain_sid);
        assert_eq!(read_word(&translated, 184), 1);
        assert_eq!(read_word(&translated, 216), 4);
        assert_eq!(read_word(&translated, 232), 3);
        assert_eq!(&translated[240..246], b"a\0b\0c\0");
        assert_eq!(read_word(&translated, 248), 1);
        assert_eq!(&translated[252..], &[0; 36]);

        let mut close = [0; 84];
        words(&mut close, &[(12, 11), (16, 1), (20, 1)]);
        close[64..84].copy_from_slice(context);
        let reply = exchange(p, &mut thread, base + 0x400, handle, 0, &close);
        assert_eq!(read_word(&reply, 12), 11);
        assert_eq!(&reply[24..44], &[0; 20]);
        assert_eq!(read_word(&reply, 44), 0);

        words(&mut close, &[(12, 12)]);
        let reply = exchange(p, &mut thread, base + 0x400, handle, 0, &close);
        assert_eq!(read_word(&reply, 12), 12);
        assert_eq!(read_word(&reply, 44), STATUS_INVALID_HANDLE);
        assert_translation_rejected(p, &mut thread, base + 0x400, handle, &lookup);
    }
}

fn words(payload: &mut [u8], fields: &[(usize, u32)]) {
    for &(offset, value) in fields {
        payload[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
}

fn read_word(payload: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap())
}

fn exchange(
    p: &mut Proc,
    thread: &mut Thread,
    arena: u64,
    handle: u64,
    packet_type: u16,
    payload: &[u8],
) -> Vec<u8> {
    let (result, header, reply, length) = submit(p, thread, arena, handle, packet_type, payload);
    assert_eq!(result, Outcome::Continue);
    assert_eq!(thread.cpu.gpr(0), 0);
    let len = p.space.u16(reply).unwrap();
    let width = p.arch.ptr_size();
    assert_eq!(p.space.ptr(length, width).unwrap(), u64::from(len) + header);
    p.space.bytes(reply + header, usize::from(len)).unwrap()
}

fn assert_translation_rejected(
    p: &mut Proc,
    thread: &mut Thread,
    arena: u64,
    handle: u64,
    payload: &[u8],
) {
    let (result, _, reply, length) = submit(p, thread, arena, handle, 0, payload);
    assert!(
        matches!(result, Outcome::Fail(ref message) if message.contains("local RPC operation 2")),
        "{result:?}"
    );
    assert_eq!(p.space.u32(reply).unwrap(), 0xc123_4567);
    assert_eq!(p.space.ptr(length, p.arch.ptr_size()).unwrap(), 512);
}

fn submit(
    p: &mut Proc,
    thread: &mut Thread,
    arena: u64,
    handle: u64,
    packet_type: u16,
    payload: &[u8],
) -> (Outcome, u64, u64, u64) {
    let header = if p.arch.is64() { 40 } else { 24 };
    let capacity = 512;
    let reply = arena + capacity;
    let length = reply + capacity;
    let width = p.arch.ptr_size();
    p.space.wr(arena, &[0; 40]).unwrap();
    p.space.w16(arena, payload.len() as u16).unwrap();
    p.space
        .w16(arena + 2, (header as usize + payload.len()) as u16)
        .unwrap();
    p.space.w16(arena + 4, packet_type).unwrap();
    p.space.wr(arena + header, payload).unwrap();
    p.space.wptr(length, width, capacity).unwrap();
    p.space.w32(reply, 0xc123_4567).unwrap();
    let result = invoke(
        p,
        thread,
        "NtAlpcSendWaitReceivePort",
        SERVICE,
        &[handle, 0x20000, arena, 0, reply, length, 0, 0],
    );
    (result, header, reply, length)
}
