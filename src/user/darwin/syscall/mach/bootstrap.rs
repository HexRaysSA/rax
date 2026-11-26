//! Name registration and lookup for the installed Darwin runtime's bootstrap port.
//!
//! Modern libxpc sends CPX dictionaries to this message-queue endpoint. The
//! endpoint and its send rights are local to the closed guest process family.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::user::darwin::abi::Errno;
use crate::user::darwin::mach::exception::Handler;
use crate::user::darwin::mach::ipc::{KObject, MACH_PORT_NULL, Port, Right, disp};
use crate::user::darwin::mach::kr;
use crate::user::darwin::mach::msg::{Item, Message, NDR_RECORD, Sender, bits, desc};
use crate::user::darwin::mach::task::{TaskState, special};
use crate::user::darwin::process::Proc;

use super::kmsg;

const XPC_REQUEST: i32 = 0x4000_0000;
const XPC_REPLY: i32 = 0x2000_0000;
const REGISTER: i32 = XPC_REQUEST | 204;
const LOOK_UP: i32 = XPC_REQUEST | 207;
const XPC_HEADER: [u8; 8] = *b"CPX@\x05\0\0\0";
const DICTIONARY: u32 = 0xf000;
const SIGNED: u32 = 0x3000;
const UNSIGNED: u32 = 0x4000;
const STRING: u32 = 0x9000;
const UUID: u32 = 0xa000;
const MACH_SEND: u32 = 0xd000;
const BOOTSTRAP_DOMAIN: u64 = 7;
const SERVICE_NOT_FOUND: i64 = 124; // libxpc maps this to BOOTSTRAP_UNKNOWN_SERVICE.
const NAME_IN_USE: i64 = 1101;
const MAX_SERVICES: usize = 1024;
const MAX_NAME_BYTES: usize = 127;

// libxpc validates the sender of a bootstrap reply against the guest's PID 1.
const BOOTSTRAP_SENDER: Sender = Sender {
    sec: [0, 0],
    audit: [u32::MAX, 0, 0, 0, 0, 1, 0, 1],
};

#[derive(Default)]
pub(crate) struct Namespace {
    services: BTreeMap<String, Registration>,
}

struct Registration {
    pid: i32,
    port: Arc<Port>,
}

impl Namespace {
    fn register(&mut self, pid: i32, name: &str, port: &Arc<Port>) -> Result<(), i64> {
        self.services.retain(|_, existing| {
            let mut state = existing.port.state.lock().unwrap();
            if state.dead {
                // A dead port's last send right cannot notify a receiver.
                state.srights -= 1;
            }
            !state.dead
        });
        if self.services.contains_key(name) {
            return Err(NAME_IN_USE);
        }
        if self.services.len() == MAX_SERVICES {
            return Err(i64::from(Errno::ENOSPC.0));
        }
        let mut state = port.state.lock().unwrap();
        if state.dead || state.host.is_some() || port.kobject != KObject::None {
            return Err(i64::from(Errno::EINVAL.0));
        }
        state.srights += 1;
        self.services.insert(
            name.to_owned(),
            Registration {
                pid,
                port: port.clone(),
            },
        );
        Ok(())
    }

    fn remove_owner(&mut self, pid: i32) -> Vec<Right> {
        self.services
            .extract_if(.., |_, service| service.pid == pid)
            .map(|(_, service)| Right::Send(service.port))
            .collect()
    }

    fn lookup(&self, name: &str) -> Result<Right, i64> {
        let port = &self.services.get(name).ok_or(SERVICE_NOT_FOUND)?.port;
        let mut state = port.state.lock().unwrap();
        if state.dead {
            return Err(SERVICE_NOT_FOUND);
        }
        state.srights += 1;
        Ok(Right::Send(port.clone()))
    }
}

pub(crate) fn remove_owner(proc: &mut Proc) {
    if let Some(family) = proc.family.as_ref() {
        let rights = family.bootstrap(|namespace| namespace.remove_owner(proc.pid));
        kmsg::release(proc, rights);
    }
}

pub(crate) fn install(task: &mut TaskState) {
    let port = Port::new(KObject::Bootstrap);
    port.state.lock().unwrap().srights += 2;
    task.special[special::BOOTSTRAP as usize] = Some(port.clone());
    task.registered[0] = Handler::Port(port);
}

struct Request<'a> {
    name: &'a str,
    domain: &'a Arc<Port>,
    service: Option<&'a Arc<Port>>,
}

fn take<'a>(bytes: &mut &'a [u8], count: usize) -> Option<&'a [u8]> {
    let (field, rest) = bytes.split_at_checked(count)?;
    *bytes = rest;
    Some(field)
}

fn word(bytes: &mut &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes(take(bytes, 4)?.try_into().ok()?))
}

fn integer(bytes: &mut &[u8]) -> Option<u64> {
    Some(u64::from_le_bytes(take(bytes, 8)?.try_into().ok()?))
}

fn c_string(field: &[u8]) -> Option<&str> {
    let value = field.strip_suffix(&[0])?;
    (!value.contains(&0)).then_some(())?;
    std::str::from_utf8(value).ok()
}

fn request(message: &Message) -> Option<Request<'_>> {
    if message.bits & bits::COMPLEX == 0 || message.body.len() > 4096 {
        return None;
    }
    let mut bytes = message.body.as_slice();
    let descriptors = word(&mut bytes)? as usize;
    if descriptors != message.items.len()
        || descriptors != if message.id == REGISTER { 2 } else { 1 }
    {
        return None;
    }
    let mut ports = Vec::with_capacity(descriptors);
    for (index, (offset, item)) in message.items.iter().enumerate() {
        take(&mut bytes, desc::size(desc::PORT))?;
        match item {
            Item::Port {
                right: Some(Right::Send(port)),
                disp: disp::MOVE_SEND,
            } if *offset == 4 + index * desc::size(desc::PORT) => ports.push(port),
            _ => return None,
        }
    }
    if take(&mut bytes, XPC_HEADER.len())? != XPC_HEADER || word(&mut bytes)? != DICTIONARY {
        return None;
    }
    let length = word(&mut bytes)? as usize;
    if length != bytes.len() {
        return None;
    }
    let count = word(&mut bytes)?;
    if count > 7 {
        return None;
    }
    let mut name = None;
    let mut domain = None;
    let mut service = None;
    let mut keys = Vec::with_capacity(count as usize);
    let mut ports = ports.into_iter();
    for _ in 0..count {
        let key_len = bytes.iter().position(|&byte| byte == 0)? + 1;
        let key = c_string(take(&mut bytes, key_len.next_multiple_of(4))?.get(..key_len)?)?;
        if keys.contains(&key) {
            return None;
        }
        keys.push(key);
        match (key, word(&mut bytes)?) {
            ("name", STRING) => {
                let len = word(&mut bytes)? as usize;
                if len <= 1 || len > MAX_NAME_BYTES + 1 {
                    return None;
                }
                name = Some(c_string(
                    take(&mut bytes, len.next_multiple_of(4))?.get(..len)?,
                )?);
            }
            ("domain-port", MACH_SEND) => domain = Some(ports.next()?),
            ("port", MACH_SEND) => service = Some(ports.next()?),
            ("type", UNSIGNED) if integer(&mut bytes)? == BOOTSTRAP_DOMAIN => {}
            ("handle" | "flags", UNSIGNED) if integer(&mut bytes)? == 0 => {}
            ("targetpid", SIGNED) if integer(&mut bytes)? == 0 => {}
            ("instance", UUID) if take(&mut bytes, 16)? == [0; 16] => {}
            _ => return None,
        }
    }
    if !keys.contains(&"type") || !bytes.is_empty() || ports.next().is_some() {
        return None;
    }
    Some(Request {
        name: name?,
        domain: domain?,
        service,
    })
}

fn field(body: &mut Vec<u8>, name: &[u8], tag: u32, value: Option<u64>) {
    body.extend_from_slice(name);
    body.resize((body.len() + 1).next_multiple_of(4), 0);
    body.extend_from_slice(&tag.to_le_bytes());
    if let Some(value) = value {
        body.extend_from_slice(&value.to_le_bytes());
    }
}

fn reply_payload(
    requestor: Sender,
    result: Result<Option<Right>, i64>,
) -> (Vec<u8>, Vec<(usize, Item)>) {
    let mut body = Vec::new();
    let mut items = Vec::new();
    let (code, right) = match result {
        Ok(right) => (0, right),
        Err(code) => (code, None),
    };
    if let Some(right) = right {
        body.resize(4 + desc::size(desc::PORT), 0);
        body[0] = 1;
        items.push((
            4,
            Item::Port {
                right: Some(right),
                disp: disp::MOVE_SEND,
            },
        ));
    }
    body.extend_from_slice(&XPC_HEADER);
    body.extend_from_slice(&DICTIONARY.to_le_bytes());
    let length_offset = body.len();
    body.extend_from_slice(&0u32.to_le_bytes());
    let count = 1u32 + if code == 0 { 2 + items.len() as u32 } else { 0 };
    body.extend_from_slice(&count.to_le_bytes());
    field(&mut body, b"error", SIGNED, Some(code as u64));
    if code == 0 {
        field(
            &mut body,
            b"req_pid",
            UNSIGNED,
            Some(u64::from(requestor.audit[5])),
        );
        field(
            &mut body,
            b"rec_execcnt",
            UNSIGNED,
            Some(u64::from(requestor.audit[7])),
        );
        if !items.is_empty() {
            field(&mut body, b"port", MACH_SEND, None);
        }
    }
    let length = (body.len() - length_offset - 4) as u32;
    body[length_offset..length_offset + 4].copy_from_slice(&length.to_le_bytes());
    (body, items)
}

pub(super) fn deliver(proc: &mut Proc, port: &Arc<Port>, mut message: Message) {
    if !matches!(&message.reply, Some(Right::SendOnce(reply)) if reply.kobject == KObject::None && !reply.is_dead())
    {
        kmsg::destroy(proc, message);
        return;
    }
    let dest = message.reply.take().unwrap();
    let (id, body, items) = if matches!(message.id, REGISTER | LOOK_UP) {
        let result = match (proc.family.as_ref(), request(&message)) {
            (Some(family), Some(request)) if Arc::ptr_eq(port, request.domain) => {
                family.bootstrap(|namespace| match (message.id, request.service) {
                    (REGISTER, Some(service)) => namespace
                        .register(proc.pid, request.name, service)
                        .map(|()| None),
                    (LOOK_UP, None) => namespace.lookup(request.name).map(Some),
                    _ => Err(i64::from(Errno::EINVAL.0)),
                })
            }
            _ => Err(i64::from(Errno::EINVAL.0)),
        };
        let (body, items) = reply_payload(message.sender, result);
        (XPC_REPLY, body, items)
    } else if (message.id as u32) >> 24 == (XPC_REQUEST as u32) >> 24 {
        let (body, items) = reply_payload(message.sender, Err(i64::from(Errno::ENOTSUP.0)));
        (XPC_REPLY, body, items)
    } else {
        let mut body = NDR_RECORD.to_vec();
        body.extend_from_slice(&kr::MIG_BAD_ID.to_le_bytes());
        (message.id.wrapping_add(100), body, Vec::new())
    };
    let flags = if items.is_empty() { 0 } else { bits::COMPLEX };
    kmsg::destroy(proc, message);
    kmsg::enqueue(
        proc,
        Message {
            bits: bits::set(disp::MOVE_SEND_ONCE, 0, 0, flags),
            dest,
            reply: None,
            voucher: None,
            voucher_name: MACH_PORT_NULL,
            id,
            body,
            items,
            sender: BOOTSTRAP_SENDER,
            aux: Vec::new(),
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup_message() -> Message {
        let domain = Port::new(KObject::Bootstrap);
        let mut body = vec![0; 16];
        body[0] = 1;
        body.extend_from_slice(&XPC_HEADER);
        body.extend_from_slice(&DICTIONARY.to_le_bytes());
        body.extend_from_slice(&60u32.to_le_bytes());
        body.extend_from_slice(&3u32.to_le_bytes());
        field(&mut body, b"name", STRING, None);
        body.extend_from_slice(&4u32.to_le_bytes());
        body.extend_from_slice(b"rax\0");
        field(&mut body, b"type", UNSIGNED, Some(BOOTSTRAP_DOMAIN));
        field(&mut body, b"domain-port", MACH_SEND, None);
        Message {
            bits: bits::COMPLEX,
            dest: Right::Send(domain.clone()),
            reply: None,
            voucher: None,
            voucher_name: MACH_PORT_NULL,
            id: LOOK_UP,
            body,
            items: vec![(
                4,
                Item::Port {
                    right: Some(Right::Send(domain)),
                    disp: disp::MOVE_SEND,
                },
            )],
            sender: BOOTSTRAP_SENDER,
            aux: Vec::new(),
        }
    }

    #[test]
    fn bootstrap_checks_dictionary_and_descriptor_bounds() {
        let mut message = lookup_message();
        let decoded = request(&message).expect("valid XPC dictionary");
        assert_eq!(decoded.name, "rax");
        assert!(Arc::ptr_eq(decoded.domain, message.dest.port().unwrap()));
        let complete = message.body.clone();
        for len in 0..complete.len() {
            message.body.truncate(len);
            assert!(
                request(&message).is_none(),
                "accepted prefix of {len} bytes"
            );
            message.body.clone_from(&complete);
        }
        message.body.extend_from_slice(&[0; 4]);
        assert!(request(&message).is_none());
        message.body = complete;
        message.items[0].0 += 4;
        assert!(request(&message).is_none());
    }

    #[test]
    fn bootstrap_keeps_and_releases_guest_send_rights() {
        let port = Port::new(KObject::None);
        let mut first = Namespace::default();
        let second = Namespace::default();
        assert!(first.register(1000, "rax", &port).is_ok());
        assert_eq!(first.register(1001, "rax", &port), Err(NAME_IN_USE));
        assert_eq!(port.state.lock().unwrap().srights, 1);
        assert!(matches!(second.lookup("rax"), Err(SERVICE_NOT_FOUND)));
        assert!(matches!(first.lookup("rax"), Ok(Right::Send(p)) if Arc::ptr_eq(&p, &port)));
        assert_eq!(port.state.lock().unwrap().srights, 2);
        assert!(first.remove_owner(1001).is_empty());
        assert!(matches!(&first.remove_owner(1000)[..], [Right::Send(p)] if Arc::ptr_eq(p, &port)));
        assert!(matches!(first.lookup("rax"), Err(SERVICE_NOT_FOUND)));
    }
}
