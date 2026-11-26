//! File creation notifications for installed FSEvents streams in a closed guest.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::user::darwin::mach::ipc::{KObject, MACH_PORT_NULL, Port, Right, disp};
use crate::user::darwin::mach::kr::{self, KernReturn};
use crate::user::darwin::mach::msg::{Item, Message, NDR_RECORD, Sender, bits, desc};
use crate::user::darwin::process::Proc;
use crate::user::darwin::syscall::Ctx;

use super::{bootstrap, kmsg};

pub(super) const NAME: &str = "com.apple.FSEvents";
const REGISTER: i32 = 66000;
const UNREGISTER: i32 = 66006;
const EVENT: i32 = 67000;

const USE_CF_TYPES: u32 = 0x01;
const NO_DEFER: u32 = 0x02;
const IGNORE_SELF: u32 = 0x08;
const FILE_EVENTS: u32 = 0x10;
const CREATE_FLAGS: u32 = USE_CF_TYPES | NO_DEFER | IGNORE_SELF | FILE_EVENTS;
const FILE_CREATED: u32 = 0x0080_0001;
const MAX_PATHS: usize = 256;
const MAX_PATH_BYTES: usize = 256 << 10;
const MAX_STREAMS: usize = 256;
const MAX_QUEUED_EVENTS: usize = 64;

#[derive(Default)]
pub(super) struct Service {
    endpoint: Option<Arc<Port>>,
    streams: BTreeMap<u64, Stream>,
    last_event: u64,
}

struct Stream {
    owner: i32,
    notify: Arc<Port>,
    paths: Vec<String>,
    flags: u32,
}

impl Service {
    pub(super) fn endpoint(&mut self) -> Right {
        let endpoint = self
            .endpoint
            .get_or_insert_with(|| Port::new(KObject::FsEvents));
        endpoint.state.lock().unwrap().srights += 1;
        Right::Send(endpoint.clone())
    }

    pub(super) fn remove_owner(&mut self, pid: i32) -> Vec<Right> {
        self.streams
            .extract_if(.., |_, stream| stream.owner == pid)
            .map(|(_, stream)| Right::Send(stream.notify))
            .collect()
    }

    fn register(&mut self, proc: &Proc, message: &Message) -> Result<Right, KernReturn> {
        let mut stream = registration(message).ok_or(kr::MIG_BAD_ARGUMENTS)?;
        if self.streams.len() == MAX_STREAMS {
            return Err(kr::KERN_RESOURCE_SHORTAGE);
        }
        if !proc.ipc.names().iter().any(|&(name, kind)| {
            kind & crate::user::darwin::mach::ipc::ptype::RECEIVE != 0
                && proc
                    .ipc
                    .lookup(name)
                    .ok()
                    .and_then(|entry| entry.port())
                    .is_some_and(|port| Arc::ptr_eq(port, &stream.notify))
        }) {
            return Err(kr::KERN_INVALID_RIGHT);
        }
        for path in &mut stream.paths {
            let (resolved, entry) = proc
                .vfs
                .lookup(path.as_bytes(), b"/")
                .map_err(|_| kr::KERN_INVALID_ARGUMENT)?;
            if !entry.is_dir() {
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            *path = resolved;
        }
        stream.owner = proc.pid;
        {
            let mut state = stream.notify.state.lock().unwrap();
            if state.dead || state.host.is_some() {
                return Err(kr::KERN_INVALID_RIGHT);
            }
            state.srights += 1;
        }
        let port = Port::new(KObject::FsEventsStream);
        port.state.lock().unwrap().srights = 1;
        self.streams.insert(port.id, stream);
        Ok(Right::Send(port))
    }

    fn notifications(&mut self, pid: i32, path: &str) -> Vec<Message> {
        self.last_event = self.last_event.saturating_add(1);
        self.streams
            .values()
            .filter_map(|stream| {
                if stream.owner == pid && stream.flags & IGNORE_SELF != 0
                    || !stream
                        .paths
                        .iter()
                        .any(|directory| watches(directory, path))
                {
                    return None;
                }
                {
                    let mut state = stream.notify.state.lock().unwrap();
                    if state.dead || state.host.is_some() || state.queue.len() >= MAX_QUEUED_EVENTS
                    {
                        return None;
                    }
                    state.srights += 1;
                }
                Some(notification(stream, self.last_event, path))
            })
            .collect()
    }
}

fn watches(directory: &str, path: &str) -> bool {
    directory == "/"
        || directory == path
        || path
            .strip_prefix(directory)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn registration(message: &Message) -> Option<Stream> {
    if message.bits & bits::COMPLEX == 0
        || message.body.len() != 136
        || message.body[..4] != 5u32.to_le_bytes()
        || message.body[80..88] != NDR_RECORD
    {
        return None;
    }
    let [
        (
            4,
            Item::Port {
                right: Some(Right::Send(notify)),
                disp: disp::MOVE_SEND,
            },
        ),
        (16, Item::Ool { data: offsets, .. }),
        (32, Item::Ool { data: paths, .. }),
        (
            48,
            Item::Ool {
                data: excluded_offsets,
                ..
            },
        ),
        (
            64,
            Item::Ool {
                data: excluded_paths,
                ..
            },
        ),
    ] = message.items.as_slice()
    else {
        return None;
    };
    let word = |offset| u32::from_le_bytes(message.body[offset..offset + 4].try_into().unwrap());
    let count = word(92) as usize;
    let flags = word(124);
    let since = u64::from_le_bytes(message.body[128..136].try_into().unwrap());
    if notify.kobject != KObject::None
        || !(1..=MAX_PATHS).contains(&count)
        || offsets.len() != count * 4
        || paths.is_empty()
        || paths.len() > MAX_PATH_BYTES
        || word(100) as usize != paths.len()
        || word(96) as usize != count
        || !excluded_offsets.is_empty()
        || !excluded_paths.is_empty()
        || [88, 104, 108, 112]
            .into_iter()
            .any(|offset| word(offset) != 0)
        || flags & !CREATE_FLAGS != 0
        || since != u64::MAX
    {
        return None;
    }
    let mut names = Vec::with_capacity(count);
    let mut consumed = 0;
    for offset in offsets.chunks_exact(4) {
        if u32::from_le_bytes(offset.try_into().unwrap()) as usize != consumed {
            return None;
        }
        let remaining = paths.get(consumed..)?;
        let end = remaining.iter().position(|&byte| byte == 0)?;
        let name = std::str::from_utf8(&remaining[..end]).ok()?;
        if !name.starts_with('/') || name.len() >= 1024 {
            return None;
        }
        names.push(name.to_owned());
        consumed += end + 1;
    }
    if consumed != paths.len() {
        return None;
    }
    Some(Stream {
        owner: 0,
        notify: notify.clone(),
        paths: names,
        flags,
    })
}

fn notification(stream: &Stream, id: u64, path: &str) -> Message {
    let (mut path, flags) = if stream.flags & FILE_EVENTS != 0 {
        (path.as_bytes().to_vec(), FILE_CREATED)
    } else {
        let (parent, _) = path.rsplit_once('/').expect("absolute event path");
        let mut parent = parent.as_bytes().to_vec();
        parent.push(b'/');
        (parent, 0)
    };
    path.push(0);
    let length = path.len() as u32;
    let payload = [
        0u32.to_le_bytes().to_vec(),
        flags.to_le_bytes().to_vec(),
        id.to_le_bytes().to_vec(),
        path,
    ];
    let mut body = (payload.len() as u32).to_le_bytes().to_vec();
    let mut items = Vec::with_capacity(payload.len());
    for data in payload {
        let offset = body.len();
        body.resize(offset + desc::size(desc::OOL), 0);
        body[offset + 11] = desc::OOL;
        items.push((
            offset,
            Item::Ool {
                data,
                copy: desc::VIRTUAL_COPY,
                page_offset: 0,
            },
        ));
    }
    body.extend_from_slice(&NDR_RECORD);
    for value in [1u32, 1, 1, 1, length] {
        body.extend_from_slice(&value.to_le_bytes());
    }
    response(Right::Send(stream.notify.clone()), EVENT, body, items)
}

fn response(dest: Right, id: i32, body: Vec<u8>, items: Vec<(usize, Item)>) -> Message {
    let destination = if matches!(dest, Right::SendOnce(_)) {
        disp::MOVE_SEND_ONCE
    } else {
        disp::MOVE_SEND
    };
    Message {
        bits: bits::set(
            destination,
            0,
            0,
            if items.is_empty() { 0 } else { bits::COMPLEX },
        ),
        dest,
        reply: None,
        voucher: None,
        voucher_name: MACH_PORT_NULL,
        id,
        body,
        items,
        sender: Sender::KERNEL,
        aux: Vec::new(),
    }
}

pub(super) fn deliver(ctx: &mut Ctx<'_>, port: &Port, mut message: Message) {
    let proc = &mut *ctx.proc;
    if !matches!(&message.reply, Some(Right::SendOnce(reply)) if reply.kobject == KObject::None && !reply.is_dead())
    {
        kmsg::destroy(proc, message);
        return;
    }
    let dest = message.reply.take().unwrap();
    let id = message.id.wrapping_add(100);
    let result = match (&proc.family, &port.kobject, message.id) {
        (Some(family), KObject::FsEvents, REGISTER) => {
            family.bootstrap(|namespace| namespace.fsevents.register(proc, &message).map(Some))
        }
        (Some(family), KObject::FsEventsStream, UNREGISTER)
            if message.body.is_empty() && message.items.is_empty() =>
        {
            let removed = family.bootstrap(|namespace| {
                let streams = &mut namespace.fsevents.streams;
                if streams
                    .get(&port.id)
                    .is_some_and(|stream| stream.owner == proc.pid)
                {
                    streams.remove(&port.id)
                } else {
                    None
                }
            });
            if let Some(stream) = removed {
                kmsg::release(proc, [Right::Send(stream.notify)]);
                Ok(None)
            } else {
                Err(kr::KERN_INVALID_RIGHT)
            }
        }
        _ => Err(kr::MIG_BAD_ID),
    };
    kmsg::destroy(proc, message);
    let (body, items) = match result {
        Ok(Some(right)) => {
            let mut body = vec![0; 4 + desc::size(desc::PORT)];
            body[..4].copy_from_slice(&1u32.to_le_bytes());
            (
                body,
                vec![(
                    4,
                    Item::Port {
                        right: Some(right),
                        disp: disp::MOVE_SEND,
                    },
                )],
            )
        }
        status => {
            let error = status.err().unwrap_or(kr::KERN_SUCCESS);
            let mut body = NDR_RECORD.to_vec();
            body.extend_from_slice(&error.to_le_bytes());
            (body, Vec::new())
        }
    };
    kmsg::enqueue(proc, response(dest, id, body, items));
}

pub(in crate::user::darwin) fn created(proc: &mut Proc, path: &str) {
    if let Some(family) = &proc.family {
        let messages = family.bootstrap(|namespace: &mut bootstrap::Namespace| {
            namespace.fsevents.notifications(proc.pid, path)
        });
        for message in messages {
            kmsg::enqueue(proc, message);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ool(data: &[u8]) -> Item {
        Item::Ool {
            data: data.to_vec(),
            copy: desc::VIRTUAL_COPY,
            page_offset: 0,
        }
    }

    #[test]
    fn registration_rejects_misaligned_paths_and_replay_selectors() {
        let notify = Port::new(KObject::None);
        let endpoint = Port::new(KObject::FsEvents);
        let mut body = vec![0; 136];
        body[..4].copy_from_slice(&5u32.to_le_bytes());
        body[80..88].copy_from_slice(&NDR_RECORD);
        for (offset, value) in [(92, 2u32), (96, 2), (100, 10), (124, FILE_EVENTS)] {
            body[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        body[128..136].copy_from_slice(&u64::MAX.to_le_bytes());
        let items = vec![
            (
                4,
                Item::Port {
                    right: Some(Right::Send(notify)),
                    disp: disp::MOVE_SEND,
                },
            ),
            (16, ool(&[0, 0, 0, 0, 5, 0, 0, 0])),
            (32, ool(b"/one\0/two\0")),
            (48, ool(&[])),
            (64, ool(&[])),
        ];
        let mut message = response(Right::Send(endpoint), REGISTER, body, items);
        let stream = registration(&message).unwrap();
        assert_eq!(stream.paths, ["/one", "/two"]);
        assert!(watches("/one", "/one/file"));
        assert!(!watches("/one", "/one-more/file"));
        message.items[1].1 = ool(&[0, 0, 0, 0, 4, 0, 0, 0]);
        assert!(registration(&message).is_none());
        message.items[1].1 = ool(&[0, 0, 0, 0, 5, 0, 0, 0]);
        message.body[128..136].fill(0);
        assert!(registration(&message).is_none());
    }

    #[test]
    fn creation_notifications_encode_file_and_directory_events() {
        let mut stream = Stream {
            owner: 1000,
            notify: Port::new(KObject::None),
            paths: vec!["/one".into()],
            flags: FILE_EVENTS,
        };
        let file = notification(&stream, 9, "/one/file");
        assert_eq!(file.id, EVENT);
        assert_eq!(file.body.len(), 96);
        for (offset, item) in &file.items {
            assert_eq!(file.body[offset + 11], desc::OOL);
            assert!(matches!(item, Item::Ool { .. }));
        }
        assert!(
            matches!(&file.items[1].1, Item::Ool { data, .. } if *data == FILE_CREATED.to_le_bytes())
        );
        assert!(matches!(&file.items[3].1, Item::Ool { data, .. } if *data == b"/one/file\0"));
        stream.flags = 0;
        let directory = notification(&stream, 10, "/one/file");
        assert!(matches!(&directory.items[1].1, Item::Ool { data, .. } if *data == [0; 4]));
        assert!(matches!(&directory.items[3].1, Item::Ool { data, .. } if *data == b"/one/\0"));
    }
}
