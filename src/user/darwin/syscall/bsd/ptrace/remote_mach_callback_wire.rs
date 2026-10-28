//! Wire representation for exception-handler rights and their messages.
//!
//! These identifiers are scoped to one family connection and are not guest
//! port names. The receiver must separately validate ownership and liveness.
//! Handler and reply tokens are connection-scoped: handler actions can survive
//! target exec after the task-port instance used to install them has died.

use std::io;

use super::transport::MAX_FRAME;

pub(in super::super) const INSTALL_TAG: u8 = 0x86;
pub(in super::super) const DELIVER_TAG: u8 = 0x87;
pub(in super::super) const REPLY_TAG: u8 = 0x88;
pub(in super::super) const RELEASE_TAG: u8 = 0x89;
pub(in super::super) const DEAD_TAG: u8 = 0x8a;
pub(in super::super) const CANCEL_TAG: u8 = 0x8b;
pub(in super::super) const PORTS_REPLY_TAG: u8 = 0x8c;

pub(in super::super) fn is_tag(tag: u8) -> bool {
    (INSTALL_TAG..=PORTS_REPLY_TAG).contains(&tag)
}

/// A target-owned port transferred in an exception message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in super::super) enum Port {
    Task { generation: u64 },
    Thread { tid: u64, generation: u64 },
    IdentityToken { id: u64, generation: u64 },
}

/// The offset is relative to the Mach message body, not its header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in super::super) struct Descriptor {
    pub offset: u32,
    pub port: Port,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in super::super) struct HandlerRef {
    pub offset: u32,
    pub handler: u64,
    pub generation: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in super::super) enum Message {
    Install {
        sequence: u64,
        instance: u64,
        handler: u64,
        generation: u64,
        id: i32,
        bits: u32,
        expects_reply: bool,
        plain: bool,
        body: Vec<u8>,
    },
    Deliver {
        instance: u64,
        epoch: u64,
        handler: u64,
        generation: u64,
        reply: u64,
        id: i32,
        bits: u32,
        body: Vec<u8>,
        descriptors: Vec<Descriptor>,
    },
    Reply {
        reply: u64,
        id: i32,
        bits: u32,
        body: Vec<u8>,
    },
    Release {
        handler: u64,
        generation: u64,
    },
    Dead {
        handler: u64,
        generation: u64,
    },
    Cancel {
        reply: u64,
    },
    PortsReply {
        sequence: u64,
        bits: u32,
        body: Vec<u8>,
        handlers: Vec<HandlerRef>,
    },
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid callback message")
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_body(out: &mut Vec<u8>, body: &[u8]) -> io::Result<()> {
    let len = u32::try_from(body.len()).map_err(|_| invalid())?;
    if out
        .len()
        .checked_add(4)
        .and_then(|n| n.checked_add(body.len()))
        .is_none_or(|n| n > MAX_FRAME)
    {
        return Err(invalid());
    }
    put_u32(out, len);
    out.extend_from_slice(body);
    Ok(())
}

fn validate_descriptors(body: &[u8], descriptors: &[Descriptor]) -> io::Result<()> {
    if descriptors.len() > 32 {
        return Err(invalid());
    }
    let mut end = 0usize;
    for descriptor in descriptors {
        let start = descriptor.offset as usize;
        let next = start.checked_add(12).ok_or_else(invalid)?;
        if start < end || next > body.len() {
            return Err(invalid());
        }
        match descriptor.port {
            Port::Thread { tid: 0, .. } | Port::IdentityToken { id: 0, .. } => {
                return Err(invalid());
            }
            _ => {}
        }
        end = next;
    }
    Ok(())
}

fn validate_handlers(body: &[u8], handlers: &[HandlerRef]) -> io::Result<()> {
    if handlers.len() > 32 {
        return Err(invalid());
    }
    let mut end = 0usize;
    for handler in handlers {
        let start = handler.offset as usize;
        let next = start.checked_add(12).ok_or_else(invalid)?;
        if handler.handler == 0 || start < end || next > body.len() {
            return Err(invalid());
        }
        end = next;
    }
    Ok(())
}

impl Message {
    pub(in super::super) fn encode(&self) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        match self {
            Self::PortsReply {
                sequence,
                bits,
                body,
                handlers,
            } => {
                validate_handlers(body, handlers)?;
                out.push(PORTS_REPLY_TAG);
                put_u64(&mut out, *sequence);
                put_u32(&mut out, *bits);
                out.push(handlers.len() as u8);
                for handler in handlers {
                    put_u32(&mut out, handler.offset);
                    put_u64(&mut out, handler.handler);
                    put_u64(&mut out, handler.generation);
                }
                put_body(&mut out, body)?;
            }
            Self::Install {
                sequence,
                instance,
                handler,
                generation,
                id,
                bits,
                expects_reply,
                plain,
                body,
            } => {
                if *instance == 0 || *handler == 0 {
                    return Err(invalid());
                }
                out.push(INSTALL_TAG);
                put_u64(&mut out, *sequence);
                put_u64(&mut out, *instance);
                put_u64(&mut out, *handler);
                put_u64(&mut out, *generation);
                put_u32(&mut out, *id as u32);
                put_u32(&mut out, *bits);
                out.push(u8::from(*plain) | (u8::from(*expects_reply) << 1));
                put_body(&mut out, body)?;
            }
            Self::Deliver {
                instance,
                epoch,
                handler,
                generation,
                reply,
                id,
                bits,
                body,
                descriptors,
            } => {
                if (*instance == 0) != descriptors.is_empty()
                    || *epoch == 0
                    || *handler == 0
                    || *reply == 0
                {
                    return Err(invalid());
                }
                validate_descriptors(body, descriptors)?;
                out.push(DELIVER_TAG);
                put_u64(&mut out, *instance);
                put_u64(&mut out, *epoch);
                put_u64(&mut out, *handler);
                put_u64(&mut out, *generation);
                put_u64(&mut out, *reply);
                put_u32(&mut out, *id as u32);
                put_u32(&mut out, *bits);
                out.push(descriptors.len() as u8);
                for descriptor in descriptors {
                    put_u32(&mut out, descriptor.offset);
                    let (kind, id, generation) = match descriptor.port {
                        Port::Task { generation } => (0, 0, generation),
                        Port::Thread { tid, generation } => (1, tid, generation),
                        Port::IdentityToken { id, generation } => (2, id, generation),
                    };
                    out.push(kind);
                    put_u64(&mut out, id);
                    put_u64(&mut out, generation);
                }
                put_body(&mut out, body)?;
            }
            Self::Reply {
                reply,
                id,
                bits,
                body,
            } => {
                if *reply == 0 {
                    return Err(invalid());
                }
                out.push(REPLY_TAG);
                put_u64(&mut out, *reply);
                put_u32(&mut out, *id as u32);
                put_u32(&mut out, *bits);
                put_body(&mut out, body)?;
            }
            Self::Release {
                handler,
                generation,
            }
            | Self::Dead {
                handler,
                generation,
            } => {
                if *handler == 0 {
                    return Err(invalid());
                }
                out.push(if matches!(self, Self::Release { .. }) {
                    RELEASE_TAG
                } else {
                    DEAD_TAG
                });
                put_u64(&mut out, *handler);
                put_u64(&mut out, *generation);
            }
            Self::Cancel { reply } => {
                if *reply == 0 {
                    return Err(invalid());
                }
                out.push(CANCEL_TAG);
                put_u64(&mut out, *reply);
            }
        }
        Ok(out)
    }

    pub(in super::super) fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() > MAX_FRAME {
            return Err(invalid());
        }
        let mut c = Cursor { bytes, offset: 0 };
        let tag = c.byte()?;
        let message = match tag {
            PORTS_REPLY_TAG => {
                let sequence = c.u64()?;
                let bits = c.u32()?;
                let count = c.byte()? as usize;
                if count > 32 {
                    return Err(invalid());
                }
                let mut handlers = Vec::with_capacity(count);
                for _ in 0..count {
                    handlers.push(HandlerRef {
                        offset: c.u32()?,
                        handler: c.nonzero()?,
                        generation: c.u64()?,
                    });
                }
                let body = c.body()?;
                validate_handlers(&body, &handlers)?;
                Self::PortsReply {
                    sequence,
                    bits,
                    body,
                    handlers,
                }
            }
            INSTALL_TAG => {
                let sequence = c.u64()?;
                let instance = c.nonzero()?;
                let handler = c.nonzero()?;
                let generation = c.u64()?;
                let id = c.u32()? as i32;
                let bits = c.u32()?;
                let flags = c.byte()?;
                if flags & !3 != 0 {
                    return Err(invalid());
                }
                Self::Install {
                    sequence,
                    instance,
                    handler,
                    generation,
                    id,
                    bits,
                    expects_reply: flags & 2 != 0,
                    plain: flags & 1 != 0,
                    body: c.body()?,
                }
            }
            DELIVER_TAG => {
                let instance = c.u64()?;
                let epoch = c.nonzero()?;
                let handler = c.nonzero()?;
                let generation = c.u64()?;
                let reply = c.nonzero()?;
                let id = c.u32()? as i32;
                let bits = c.u32()?;
                let count = c.byte()? as usize;
                if count > 32 {
                    return Err(invalid());
                }
                let mut descriptors = Vec::with_capacity(count);
                for _ in 0..count {
                    let offset = c.u32()?;
                    let kind = c.byte()?;
                    let id = c.u64()?;
                    let generation = c.u64()?;
                    let port = match (kind, id) {
                        (0, 0) => Port::Task { generation },
                        (1, tid) if tid != 0 => Port::Thread { tid, generation },
                        (2, id) if id != 0 => Port::IdentityToken { id, generation },
                        _ => return Err(invalid()),
                    };
                    descriptors.push(Descriptor { offset, port });
                }
                let body = c.body()?;
                validate_descriptors(&body, &descriptors)?;
                if (instance == 0) != descriptors.is_empty() {
                    return Err(invalid());
                }
                Self::Deliver {
                    instance,
                    epoch,
                    handler,
                    generation,
                    reply,
                    id,
                    bits,
                    body,
                    descriptors,
                }
            }
            REPLY_TAG => Self::Reply {
                reply: c.nonzero()?,
                id: c.u32()? as i32,
                bits: c.u32()?,
                body: c.body()?,
            },
            RELEASE_TAG | DEAD_TAG => {
                let handler = c.nonzero()?;
                let generation = c.u64()?;
                if tag == RELEASE_TAG {
                    Self::Release {
                        handler,
                        generation,
                    }
                } else {
                    Self::Dead {
                        handler,
                        generation,
                    }
                }
            }
            CANCEL_TAG => Self::Cancel {
                reply: c.nonzero()?,
            },
            _ => return Err(invalid()),
        };
        if c.offset != bytes.len() {
            return Err(invalid());
        }
        Ok(message)
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl Cursor<'_> {
    fn take(&mut self, size: usize) -> io::Result<&[u8]> {
        let end = self.offset.checked_add(size).ok_or_else(invalid)?;
        let result = self.bytes.get(self.offset..end).ok_or_else(invalid)?;
        self.offset = end;
        Ok(result)
    }
    fn byte(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> io::Result<u32> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().map_err(|_| invalid())?,
        ))
    }
    fn u64(&mut self) -> io::Result<u64> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().map_err(|_| invalid())?,
        ))
    }
    fn nonzero(&mut self) -> io::Result<u64> {
        let value = self.u64()?;
        if value == 0 {
            Err(invalid())
        } else {
            Ok(value)
        }
    }
    fn body(&mut self) -> io::Result<Vec<u8>> {
        let size = self.u32()? as usize;
        Ok(self.take(size)?.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callback_frames_have_checked_lengths_and_capabilities() {
        let frames = [
            Message::PortsReply {
                sequence: 7,
                bits: 0x8000_0012,
                body: vec![0; 28],
                handlers: vec![HandlerRef {
                    offset: 4,
                    handler: 19,
                    generation: 5,
                }],
            },
            Message::Install {
                sequence: 0,
                instance: 1,
                handler: 2,
                generation: 3,
                id: 3413,
                bits: 4,
                expects_reply: true,
                plain: true,
                body: vec![5, 6],
            },
            Message::Deliver {
                instance: 1,
                epoch: 9,
                handler: 2,
                generation: 3,
                reply: 4,
                id: 2401,
                bits: 0x8000_1511,
                body: vec![0; 28],
                descriptors: vec![
                    Descriptor {
                        offset: 4,
                        port: Port::Thread {
                            tid: 5,
                            generation: 6,
                        },
                    },
                    Descriptor {
                        offset: 16,
                        port: Port::Task { generation: 7 },
                    },
                ],
            },
            Message::Deliver {
                instance: 0,
                epoch: 9,
                handler: 2,
                generation: 3,
                reply: 4,
                id: 2402,
                bits: 0x1511,
                body: vec![0; 12],
                descriptors: Vec::new(),
            },
            Message::Reply {
                reply: 4,
                id: 2501,
                bits: 18,
                body: vec![0; 12],
            },
            Message::Release {
                handler: 2,
                generation: 3,
            },
            Message::Dead {
                handler: 2,
                generation: 3,
            },
            Message::Cancel { reply: 4 },
        ];
        for message in frames {
            let bytes = message.encode().unwrap();
            assert_eq!(Message::decode(&bytes).unwrap(), message);
            for end in 0..bytes.len() {
                assert!(
                    Message::decode(&bytes[..end]).is_err(),
                    "accepted prefix {end}"
                );
            }
            let mut extended = bytes;
            extended.push(0);
            assert!(Message::decode(&extended).is_err());
        }
    }

    #[test]
    fn install_wire_layout_and_descriptor_boundaries_are_explicit() {
        let install = Message::Install {
            sequence: 1,
            instance: 2,
            handler: 3,
            generation: 4,
            id: 3413,
            bits: 5,
            expects_reply: true,
            plain: true,
            body: vec![0xaa],
        };
        let mut expected = vec![INSTALL_TAG];
        for value in [1u64, 2, 3, 4] {
            expected.extend_from_slice(&value.to_le_bytes());
        }
        expected.extend_from_slice(&3413i32.to_le_bytes());
        expected.extend_from_slice(&5u32.to_le_bytes());
        expected.push(3);
        expected.extend_from_slice(&1u32.to_le_bytes());
        expected.push(0xaa);
        assert_eq!(install.encode().unwrap(), expected);
        assert_eq!(Message::decode(&expected).unwrap(), install);

        let descriptor = |offset| Descriptor {
            offset,
            port: Port::Task { generation: 0 },
        };
        assert!(validate_descriptors(&[0; 24], &[descriptor(0), descriptor(12)]).is_ok());
        assert!(validate_descriptors(&[0; 24], &[descriptor(0), descriptor(11)]).is_err());
        assert!(validate_descriptors(&[0; 24], &[descriptor(13)]).is_err());
        assert!(validate_descriptors(&[0; 24], &[descriptor(u32::MAX)]).is_err());
        assert!(validate_descriptors(&[0; 400], &vec![descriptor(0); 33]).is_err());
        assert!(Message::Cancel { reply: 0 }.encode().is_err());
        assert!(
            Message::Install {
                sequence: 1,
                instance: 2,
                handler: 3,
                generation: 4,
                id: 3413,
                bits: 5,
                expects_reply: true,
                plain: true,
                body: vec![0; MAX_FRAME],
            }
            .encode()
            .is_err()
        );
        assert!(
            Message::Deliver {
                instance: 0,
                epoch: 1,
                handler: 2,
                generation: 3,
                reply: 4,
                id: 5,
                bits: 0,
                body: vec![0; 12],
                descriptors: vec![descriptor(0)],
            }
            .encode()
            .is_err()
        );
        assert!(
            Message::Deliver {
                instance: 0,
                epoch: 0,
                handler: 2,
                generation: 3,
                reply: 4,
                id: 5,
                bits: 0,
                body: Vec::new(),
                descriptors: Vec::new(),
            }
            .encode()
            .is_err()
        );
    }
}
