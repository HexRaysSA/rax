use super::lsarpc_connect::invoke;
use super::*;
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::LsarpcInterface;

const CONTEXT: u32 = 0x2000_0000;
const COOKIE: u64 = 0x123450;
const PROFILE_BUILD: u32 = 29708;
const QUERIED: u32 = 0x8b;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Case {
    First,
    Repeated,
    ClassicSyntax,
    FallbackSyntax,
    UnknownInterface,
    InvalidOffer,
    UnsupportedSyntax,
    Short,
    Retry,
    SeparateOutput,
    NoSendContext,
    ReadOnlyLength,
    ReadOnlyAttributes,
    ReadOnlyMessage,
    PartialMessage,
    PartialMessageSeparateAttributes,
    OriginalClosed,
    MismatchedWideLength,
    MisalignedSendAttributes,
    MisalignedReceiveAttributes,
}

#[test]
fn native_lsarpc_bind_replays_wire_order_and_port_state() {
    for (arch, wide_wow64) in WinArch::ALL
        .into_iter()
        .map(|arch| (arch, false))
        .chain([(WinArch::X86, true)])
    {
        let (mut process, mut thread) = fixture(arch, "NtClose", SERVICE);
        let p = process.state_mut();
        super::super::native_profile::kernel_profile(p, PROFILE_BUILD, 0xaa64);
        let length_width = arch.ptr_size();
        let width = if wide_wow64 { 8 } else { length_width };
        let header = if width == 8 { 40 } else { 24 };
        let cookie = if wide_wow64 {
            (1 << 48) | COOKIE
        } else {
            COOKIE
        };
        let flags = if wide_wow64 { 0x40020000 } else { 0x20000 };
        let total = header + 72;
        let base =
            p.vm.allocate(
                None,
                6 * PAGE_SIZE,
                mem::RESERVE | mem::COMMIT,
                prot::READWRITE,
            )
            .unwrap()
            .0;
        let send = base;
        let separate = base + PAGE_SIZE;
        let attributes = separate + PAGE_SIZE;
        let length = attributes + PAGE_SIZE;
        let query = length + PAGE_SIZE;
        let bad_message = query + PAGE_SIZE;
        p.space.wr(bad_message, &[0xa5; 4]).unwrap();
        p.vm.protect(bad_message, PAGE_SIZE, prot::READONLY)
            .unwrap();

        let original = u64::from(
            p.objects
                .insert(Object::LpcPort(LpcPort::lsarpc(LsarpcInterface::Policy))),
        );
        let Some(Object::LpcPort(port)) = p.objects.get_mut(original) else {
            panic!("fixture port");
        };
        port.set_lsarpc_context(original as u32);
        let alias = u64::from(p.objects.duplicate(original, false).unwrap());
        let mut handle = original;
        let mut previous_message_id = 0;
        let mut sequence = 1;
        for case in [
            Case::First,
            Case::Repeated,
            Case::ClassicSyntax,
            Case::FallbackSyntax,
            Case::UnknownInterface,
            Case::InvalidOffer,
            Case::UnsupportedSyntax,
            Case::Short,
            Case::Retry,
            Case::SeparateOutput,
            Case::NoSendContext,
            Case::ReadOnlyLength,
            Case::ReadOnlyAttributes,
            Case::ReadOnlyMessage,
            Case::PartialMessage,
            Case::PartialMessageSeparateAttributes,
            Case::OriginalClosed,
        ]
        .into_iter()
        .chain(
            [
                Case::MismatchedWideLength,
                Case::MisalignedSendAttributes,
                Case::MisalignedReceiveAttributes,
            ]
            .into_iter()
            .filter(|_| wide_wow64),
        ) {
            if case == Case::OriginalClosed {
                p.objects.close(original).unwrap();
                handle = alias;
            }
            let mut request = vec![0; total + 4];
            let requested_type = if case == Case::ClassicSyntax {
                0u16
            } else {
                0x4000
            };
            request[..2].copy_from_slice(&72u16.to_le_bytes());
            let supplied_total = total - usize::from(case == Case::MismatchedWideLength);
            request[2..4].copy_from_slice(&(supplied_total as u16).to_le_bytes());
            request[4..6].copy_from_slice(&requested_type.to_le_bytes());
            let offered = match case {
                Case::ClassicSyntax => 1,
                Case::FallbackSyntax => 29,
                Case::InvalidOffer => 7,
                Case::UnsupportedSyntax => 4,
                _ => 3,
            };
            let fault = match case {
                Case::UnknownInterface => Some(1717u32),
                Case::InvalidOffer => Some(1728),
                Case::UnsupportedSyntax => Some(1730),
                _ => None,
            };
            let mut payload = [
                1u32, 0, 0x11223344, 0x12345778, 0xabcd1234, 0x230100ef, 0xab896745, 0, offered,
                0x10000, 0x10203040, 0, 1, 0x01020304, 1, 0, 0x611100aa, 0x56677889,
            ];
            if case == Case::UnknownInterface {
                payload[3] ^= 1;
            }
            for (slot, value) in request[header..total].chunks_exact_mut(4).zip(payload) {
                slot.copy_from_slice(&value.to_le_bytes());
            }
            request[total..].fill(0xa5);
            p.space.wr(send, &request).unwrap();
            p.space.wr(separate, &vec![0xa5; total + 4]).unwrap();

            p.vm.protect(length, PAGE_SIZE, prot::READWRITE).unwrap();
            p.vm.protect(attributes, PAGE_SIZE, prot::READWRITE)
                .unwrap();
            let initial_capacity = if case == Case::Short { total - 1 } else { 4096 };
            p.space
                .wptr(length, length_width, initial_capacity as u64)
                .unwrap();
            if wide_wow64 {
                p.space.w32(length + 4, 1).unwrap();
            }
            p.space.wr(attributes, &[0; 44]).unwrap();
            p.space.w32(attributes, CONTEXT).unwrap();
            p.space.w32(attributes + 4, CONTEXT).unwrap();
            p.space.w32(attributes + 36, 0xa5a5_a5a5).unwrap();
            p.space.wptr(attributes + 8 + width, width, cookie).unwrap();

            let receive = match case {
                Case::SeparateOutput => separate,
                Case::ReadOnlyMessage => bad_message,
                Case::PartialMessage | Case::PartialMessageSeparateAttributes => {
                    bad_message - (total as u64 - 4)
                }
                _ => send,
            };
            let send_attr = match case {
                Case::NoSendContext => 0,
                Case::MisalignedSendAttributes => attributes + 4,
                _ => attributes,
            };
            let receive_attr = match case {
                Case::PartialMessageSeparateAttributes => {
                    p.space.w32(separate, CONTEXT).unwrap();
                    p.space.w32(separate + 4, 0).unwrap();
                    separate
                }
                Case::MisalignedReceiveAttributes => attributes + 4,
                _ => attributes,
            };
            let attributes_before = p.space.bytes(receive_attr, 44).unwrap();
            if case == Case::ReadOnlyLength {
                p.vm.protect(length, PAGE_SIZE, prot::READONLY).unwrap();
            }
            if case == Case::ReadOnlyAttributes {
                p.vm.protect(attributes, PAGE_SIZE, prot::READONLY).unwrap();
            }

            let status = match case {
                Case::Short => STATUS_BUFFER_TOO_SMALL,
                Case::MismatchedWideLength => STATUS_INVALID_PARAMETER,
                Case::MisalignedSendAttributes | Case::MisalignedReceiveAttributes => {
                    STATUS_DATATYPE_MISALIGNMENT
                }
                Case::ReadOnlyLength if arch.is64() => STATUS_ACCESS_VIOLATION,
                Case::ReadOnlyAttributes
                | Case::ReadOnlyMessage
                | Case::PartialMessage
                | Case::PartialMessageSeparateAttributes => STATUS_ACCESS_VIOLATION,
                _ => STATUS_SUCCESS,
            };
            assert_eq!(
                invoke(
                    p,
                    &mut thread,
                    "NtAlpcSendWaitReceivePort",
                    SERVICE,
                    &[
                        handle,
                        flags,
                        send,
                        send_attr,
                        receive,
                        length,
                        receive_attr,
                        0
                    ]
                ),
                Outcome::Continue,
                "{arch} {case:?}",
            );
            assert_eq!(thread.cpu.gpr(0), u64::from(status), "{arch} {case:?}");
            let delivered = status == STATUS_SUCCESS || status == STATUS_BUFFER_TOO_SMALL;
            if delivered {
                sequence += 1;
            }
            let reply_total = if fault.is_some() { header + 20 } else { total };
            let published = if delivered && case != Case::ReadOnlyLength {
                reply_total
            } else {
                initial_capacity
            };
            assert_eq!(
                p.space.ptr(length, length_width).unwrap(),
                published as u64,
                "{arch} {case:?}"
            );
            if wide_wow64 {
                assert_eq!(p.space.u32(length + 4).unwrap(), 1, "{arch} {case:?}");
            }
            assert_eq!(
                invoke(
                    p,
                    &mut thread,
                    "NtAlpcQueryInformation",
                    QUERIED,
                    &[handle, 0, query, 8 + length_width, 0]
                ),
                Outcome::Continue
            );
            assert_eq!(thread.cpu.gpr(0), 0);
            assert_eq!(p.space.u32(query + 4).unwrap(), sequence);
            assert_eq!(p.space.ptr(query + 8, length_width).unwrap(), original);
            if receive != send || status != STATUS_SUCCESS {
                assert_eq!(
                    p.space.bytes(send, request.len()).unwrap(),
                    request,
                    "{arch} {case:?}"
                );
            }
            if matches!(
                case,
                Case::PartialMessage | Case::PartialMessageSeparateAttributes
            ) {
                // The accessible reply prefix is visible in both cases. Only
                // the aliased context exposes fields before the copy fault.
                let offset = attributes + 8 + 2 * width;
                if case == Case::PartialMessage {
                    assert_eq!(p.space.ptr(attributes + 8, width).unwrap(), original);
                    assert_eq!(p.space.u32(offset).unwrap(), 0);
                } else {
                    assert_eq!(p.space.bytes(receive_attr, 44).unwrap(), attributes_before);
                }
                assert_eq!(
                    p.space.u16(receive + 4).unwrap(),
                    if width == 8 { 0x4002 } else { 0x5002 }
                );
                assert_eq!(p.space.u32(receive + header as u64 + 32).unwrap(), 2);
                assert_eq!(p.space.bytes(bad_message, 4).unwrap(), [0xa5; 4]);
                continue;
            }
            if !delivered {
                assert_eq!(p.space.ptr(attributes + 8, width).unwrap(), 0);
                continue;
            }
            let selected = if offered & 2 != 0 { 2u32 } else { 1 };
            assert_eq!(p.space.u32(attributes + 4).unwrap(), CONTEXT);
            assert_eq!(p.space.ptr(attributes + 8, width).unwrap(), original);
            let reply_cookie = if send_attr == 0 { 0 } else { cookie };
            assert_eq!(
                p.space.ptr(attributes + 8 + width, width).unwrap(),
                reply_cookie
            );
            let expected_padding = if width == 8 { 0 } else { 0xa5a5_a5a5 };
            assert_eq!(p.space.u32(attributes + 36).unwrap(), expected_padding);
            let offset = attributes + 8 + 2 * width;
            assert_eq!(p.space.u32(offset).unwrap(), sequence);
            let message_id = p.space.u32(offset + 4).unwrap();
            let callback = p.space.u32(offset + 8).unwrap();
            assert_ne!(message_id, 0);
            assert_ne!(callback, 0);
            if case == Case::Repeated {
                assert_eq!(message_id, previous_message_id);
            }
            if case == Case::Retry {
                assert_ne!(message_id, previous_message_id);
            }
            previous_message_id = message_id;
            if status == STATUS_BUFFER_TOO_SMALL {
                continue;
            }
            let native_type = if fault.is_some() { 0 } else { requested_type };
            let reply_kind = native_type | 2 | if width == 8 { 0 } else { 0x1000 };
            assert_eq!(p.space.u16(receive).unwrap(), (reply_total - header) as u16);
            assert_eq!(p.space.u16(receive + 2).unwrap(), reply_total as u16);
            assert_eq!(p.space.u16(receive + 4).unwrap(), reply_kind);
            assert_eq!(p.space.u16(receive + 6).unwrap(), 0);
            assert_ne!(p.space.ptr(receive + 8, width).unwrap(), 0);
            assert_ne!(p.space.ptr(receive + 8 + width, width).unwrap(), 0);
            assert_eq!(p.space.u32(receive + 8 + 2 * width).unwrap(), message_id);
            assert_eq!(
                p.space.ptr(receive + header as u64 - width, width).unwrap(),
                u64::from(callback)
            );
            let mut expected = request[header..].to_vec();
            if let Some(rpc_status) = fault {
                expected[..16].fill(0);
                expected[..4].copy_from_slice(&2u32.to_le_bytes());
                expected[8..12].copy_from_slice(&rpc_status.to_le_bytes());
            } else {
                expected[8..12].fill(0);
                expected[32..36].copy_from_slice(&selected.to_le_bytes());
            }
            assert_eq!(
                p.space
                    .bytes(receive + header as u64, expected.len())
                    .unwrap(),
                expected,
                "{arch} {case:?}"
            );
        }
    }
}
