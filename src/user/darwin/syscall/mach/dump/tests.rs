//! Dump layout and descriptor decoding against hand-laid `message.h`
//! structures.

use super::*;

/// A complex message's header and descriptor count.
fn base(id: i32, count: u32) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(&(bits::COMPLEX | 0x14).to_le_bytes());
    m.extend_from_slice(&0u32.to_le_bytes()); // msgh_size, patched below
    m.extend_from_slice(&0x1003u32.to_le_bytes());
    m.extend_from_slice(&0x2003u32.to_le_bytes());
    m.extend_from_slice(&0u32.to_le_bytes());
    m.extend_from_slice(&id.to_le_bytes());
    m.extend_from_slice(&count.to_le_bytes());
    m
}

fn finish(mut m: Vec<u8>) -> Vec<u8> {
    let size = m.len() as u32;
    m[4..8].copy_from_slice(&size.to_le_bytes());
    m
}

/// `mach_msg_port_descriptor_t`: name, pad1, pad2, disposition, type.
fn port(m: &mut Vec<u8>, name: u32, disposition: u8) {
    m.extend_from_slice(&name.to_le_bytes());
    m.extend_from_slice(&[0; 6]);
    m.extend_from_slice(&[disposition, desc::PORT]);
}

/// `mach_msg_ool_descriptor64_t`: address, deallocate, copy, pad1, type,
/// size.
fn ool(m: &mut Vec<u8>, addr: u64, size: u32, deallocate: u8, copy: u8, kind: u8) {
    m.extend_from_slice(&addr.to_le_bytes());
    m.extend_from_slice(&[deallocate, copy, 0, kind]);
    m.extend_from_slice(&size.to_le_bytes());
}

#[test]
fn hexdump_lays_out_offsets_bytes_and_ascii() {
    let bytes: Vec<u8> = b"RAX-OOL-PATTERN!\x00\x01\x7f\x80 ~".to_vec();
    let mut out = String::new();
    hexdump(&mut out, "> ", &bytes, bytes.len());
    assert_eq!(
        out,
        "> 0000  52 41 58 2d 4f 4f 4c 2d  50 41 54 54 45 52 4e 21  |RAX-OOL-PATTERN!|\n\
         > 0010  00 01 7f 80 20 7e                                 |.... ~|\n"
    );
}

#[test]
fn hexdump_reports_what_the_limit_left_out() {
    let mut out = String::new();
    hexdump(&mut out, "", &[0xab; 4], 4096);
    assert_eq!(
        out,
        "0000  ab ab ab ab                                       |....|\n\
         ... 4092 more bytes\n"
    );
    let mut out = String::new();
    hexdump(&mut out, "", &[], 64);
    assert_eq!(out, "... 64 more bytes\n");
}

#[test]
fn descriptors_decode_every_type_in_order() {
    let mut m = base(21057, 4);
    port(&mut m, 0x1103, disp::COPY_SEND as u8);
    ool(&mut m, 0x1_0000_8000, 64, 1, desc::VIRTUAL_COPY, desc::OOL);
    // mach_msg_ool_ports_descriptor64_t: address, deallocate, copy,
    // disposition, type, count.
    m.extend_from_slice(&0x1_0000_9000u64.to_le_bytes());
    m.extend_from_slice(&[
        0,
        desc::PHYSICAL_COPY,
        disp::MAKE_SEND as u8,
        desc::OOL_PORTS,
    ]);
    m.extend_from_slice(&3u32.to_le_bytes());
    // mach_msg_guarded_port_descriptor64_t: context, flags, disposition,
    // type, name.
    m.extend_from_slice(&0xfeed_f00du64.to_le_bytes());
    m.extend_from_slice(&0x1u16.to_le_bytes());
    m.extend_from_slice(&[disp::MOVE_RECEIVE as u8, desc::GUARDED_PORT]);
    m.extend_from_slice(&0x1203u32.to_le_bytes());
    let m = finish(m);
    let decoded = descriptors(&m, 4);
    assert_eq!(
        decoded,
        [
            Desc::Port {
                name: 0x1103,
                disposition: disp::COPY_SEND as u8,
            },
            Desc::Ool {
                addr: 0x1_0000_8000,
                size: 64,
                deallocate: 1,
                copy: desc::VIRTUAL_COPY,
                volatile: false,
            },
            Desc::OolPorts {
                addr: 0x1_0000_9000,
                count: 3,
                deallocate: 0,
                copy: desc::PHYSICAL_COPY,
                disposition: disp::MAKE_SEND as u8,
            },
            Desc::Guarded {
                name: 0x1203,
                disposition: disp::MOVE_RECEIVE as u8,
                flags: 1,
                context: 0xfeed_f00d,
            },
        ]
    );
    let described: Vec<String> = decoded.iter().map(|d| d.describe(false)).collect();
    assert_eq!(
        described,
        [
            "port name=0x1103 disposition=COPY_SEND",
            "ool address=0x100008000 size=64 copy=virtual deallocate=1",
            "ool-ports address=0x100009000 count=3 disposition=MAKE_SEND copy=physical deallocate=0",
            "guarded-port name=0x1203 disposition=MOVE_RECEIVE flags=0x1 context=0xfeedf00d",
        ]
    );
    // A receiver is given rights, named by their type.
    assert_eq!(
        decoded[0].describe(true),
        "port name=0x1103 disposition=COPY_SEND"
    );
    assert_eq!(
        Desc::Port {
            name: 0x1103,
            disposition: disp::MOVE_SEND as u8,
        }
        .describe(true),
        "port name=0x1103 disposition=PORT_SEND"
    );
}

#[test]
fn descriptors_stop_where_the_bytes_or_types_end() {
    // A count beyond the message: only the descriptors present.
    let mut m = base(1, 3);
    port(&mut m, 0x1103, disp::MOVE_SEND as u8);
    ool(
        &mut m,
        0x5000,
        8,
        0,
        desc::PHYSICAL_COPY,
        desc::OOL_VOLATILE,
    );
    let m = finish(m);
    let decoded = descriptors(&m, 3);
    assert_eq!(decoded.len(), 2);
    assert_eq!(
        decoded[1].describe(false),
        "ool-volatile address=0x5000 size=8 copy=physical deallocate=0"
    );

    // A truncated 16-byte descriptor is not read past the message.
    let mut m = base(1, 1);
    m.extend_from_slice(&[0; 11]);
    m.push(desc::OOL);
    assert!(descriptors(&finish(m), 1).is_empty());

    // An undefined type ends the decoding.
    let mut m = base(1, 2);
    m.extend_from_slice(&[0; 11]);
    m.push(9);
    port(&mut m, 0x1103, disp::MOVE_SEND as u8);
    assert_eq!(descriptors(&finish(m), 2), [Desc::Unknown { kind: 9 }]);

    // The count, not the bytes, bounds the decoding.
    let mut m = base(1, 2);
    port(&mut m, 0x1103, disp::MOVE_SEND as u8);
    port(&mut m, 0x1203, disp::MOVE_SEND as u8);
    assert_eq!(descriptors(&finish(m), 1).len(), 1);
}

#[test]
fn header_shows_the_fields_and_a_signed_id() {
    let mut m = base(-305, 0);
    m.truncate(HEADER_SIZE);
    let m = finish(m);
    assert_eq!(
        header(&m),
        "bits=0x80000014 size=24 remote=0x1003 local=0x2003 voucher=0x0 id=-305"
    );
    // A short buffer shows zeros rather than reading past it.
    assert_eq!(
        header(&m[..8]),
        "bits=0x80000014 size=24 remote=0x0 local=0x0 voucher=0x0 id=0"
    );
}

#[test]
fn kernel_messages_name_notifications_and_mig_replies() {
    assert_eq!(
        kernel_message(kmsg::MACH_NOTIFY_NO_SENDERS).as_deref(),
        Some("no-senders notification")
    );
    assert_eq!(
        kernel_message(kmsg::MACH_NOTIFY_DEAD_NAME).as_deref(),
        Some("dead-name notification")
    );
    // task_info is routine 3405 (osfmk/mach/task.defs); its reply is 3505.
    assert_eq!(kernel_message(3505).as_deref(), Some("task_info reply"));
    assert_eq!(kernel_message(3405), None);
    assert_eq!(kernel_message(0x5241), None);
}

#[test]
fn every_kernel_object_has_a_label_and_ordinary_ports_none() {
    assert_eq!(object(&KObject::None), None);
    assert_eq!(object(&KObject::Task).as_deref(), Some("task"));
    assert_eq!(
        object(&KObject::Thread(0x103)).as_deref(),
        Some("thread 0x103")
    );
    assert_eq!(object(&KObject::Timer(1)).as_deref(), Some("timer"));
}
