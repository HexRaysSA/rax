use super::*;
use crate::user::windows::loader::services::tests::named_table;

const CONNECT: u32 = 0x7b;
const SEND_RECEIVE: u32 = 0x8e;

fn call<const N: usize>(
    p: &mut Proc,
    thread: &mut Thread,
    name: &str,
    number: u32,
    args: [u64; N],
) {
    let index = p.modules.nt_services.as_ref().unwrap().0;
    p.modules.nt_services = Some((index, named_table(WinArch::Arm64, name, number)));
    let sp = thread.cpu.sp();
    for (slot, value) in args.into_iter().enumerate() {
        if slot < 8 {
            thread.cpu.set_gpr(slot, value);
        } else {
            p.space.w64(sp + (slot as u64 - 8) * 8, value).unwrap();
        }
    }
    thread.cpu.set_pc(0x1234_0004);
    assert_eq!(
        handle_stop(p, thread, stop(WinArch::Arm64, number)),
        Outcome::Continue,
        "{name}",
    );
    assert_eq!((thread.cpu.sp(), thread.cpu.pc()), (sp, 0x1234_0004));
}

#[test]
fn installed_theme_bootstrap_preserves_wire_payload_and_handle_lifetime() {
    let arch = WinArch::Arm64;
    let (mut process, mut thread) = fixture(arch, "NtClose", CONNECT);
    let p = process.state_mut();
    super::super::native_profile::kernel_profile(p, 29708, 0xaa64);
    let base =
        p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
            .unwrap()
            .0;
    let [name, name_buffer, attributes, message, length] =
        [0x20, 0x40, 0x80, 0x100, 0x180].map(|offset| base + offset);
    let port_name: Vec<_> = "\\ThemeApiPort".encode_utf16().collect();
    let hello: Vec<_> = "ThemeApiConnectionRequest"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    p.space.w16(name, (port_name.len() * 2) as u16).unwrap();
    p.space
        .w16(name + 2, (port_name.len() * 2 + 2) as u16)
        .unwrap();
    p.space.w64(name + 8, name_buffer).unwrap();
    p.space.put_wstr(name_buffer, &port_name).unwrap();
    for (slot, value) in [0, 12, 2, 0x101, 112].into_iter().enumerate() {
        p.space.w32(attributes + slot as u64 * 4, value).unwrap();
    }
    p.space.w16(message, 64).unwrap();
    p.space.w16(message + 2, 104).unwrap();
    p.space.wr(message + 40, &hello).unwrap();
    p.space.wr(message + 104, &[0xa5; 8]).unwrap();
    p.space.w32(length, 104).unwrap();
    let handle_count = p.objects.handle_count();
    call(
        p,
        &mut thread,
        "NtAlpcConnectPort",
        CONNECT,
        [
            base, name, 0, attributes, 0x20000, 0, message, length, 0, 0, 0,
        ],
    );
    assert_eq!(thread.cpu.gpr(0), 0);
    let port = p.space.u64(base).unwrap();
    assert!(
        matches!(p.objects.get(port), Some(Object::LpcPort(endpoint)) if endpoint.theme_message().is_some())
    );
    assert_eq!(p.objects.handle_count(), handle_count + 1);
    assert_eq!(p.space.u32(length).unwrap(), 104);
    assert_eq!(p.space.u16(message + 4).unwrap(), 11);
    assert_eq!(p.space.bytes(message + 40, hello.len()).unwrap(), hello);
    assert_eq!(p.space.bytes(message + 104, 8).unwrap(), [0xa5; 8]);

    let mut sequences = [0; 2];
    for (slot, command) in [2, 1007].into_iter().enumerate() {
        p.space.wr(message, &[0; 112]).unwrap();
        p.space.w16(message, 72).unwrap();
        p.space.w16(message + 2, 112).unwrap();
        p.space.w32(message + 40, command).unwrap();
        p.space.w64(length, 112).unwrap();
        call(
            p,
            &mut thread,
            "NtAlpcSendWaitReceivePort",
            SEND_RECEIVE,
            [port, 0x20000, message, 0, message, length, 0, 0],
        );
        assert_eq!(thread.cpu.gpr(0), 0);
        assert_eq!(p.space.u64(length).unwrap(), 112);
        assert_eq!(p.space.u16(message + 4).unwrap(), 2);
        sequences[slot] = p.space.u32(message + 24).unwrap();
        let mut bytes = [0; 72];
        if command == 2 {
            bytes[8..12].copy_from_slice(&0x0004_0002u32.to_le_bytes());
        }
        assert_eq!(p.space.bytes(message + 40, bytes.len()).unwrap(), bytes);
    }
    assert_ne!(sequences[0], sequences[1]);

    call(p, &mut thread, "NtClose", 0x0f, [port]);
    assert_eq!(thread.cpu.gpr(0), 0);
    assert!(p.objects.get(port).is_none());
    assert_eq!(p.objects.handle_count(), handle_count);
}
