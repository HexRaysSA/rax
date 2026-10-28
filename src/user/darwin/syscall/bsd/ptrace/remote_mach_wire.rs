//! Wire encoding for remote Mach capabilities and requests.

use std::io;

use super::{ACQUIRE_TAG, DEAD_TAG, MAX_FRAME, RELEASE_TAG, REPLY_TAG, REQUEST_TAG};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Object {
    Task,
    Thread(u64),
}

/// An out-of-line thread-port array and its descriptor offset in a reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ThreadArray {
    pub offset: u32,
    pub disposition: u32,
    pub threads: Vec<u64>,
}

/// An out-of-line memory descriptor and its copied contents.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Memory {
    pub offset: u32,
    pub copy: u8,
    pub page_offset: u64,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Message {
    Request {
        sequence: u64,
        instance: u64,
        object: Object,
        id: i32,
        bits: u32,
        expects_reply: bool,
        body: Vec<u8>,
        memory: Option<Memory>,
    },
    Reply {
        sequence: u64,
        bits: u32,
        body: Vec<u8>,
        threads: Option<ThreadArray>,
        memory: Option<Memory>,
    },
    Acquire {
        generation: u64,
        instance: u64,
        epoch: u64,
        object: Object,
    },
    Release {
        generation: u64,
        instance: u64,
        object: Object,
    },
    Dead {
        generation: u64,
        instance: u64,
        object: Object,
    },
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid remote Mach message")
}

pub(super) fn too_large() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "remote Mach message too large")
}

impl Message {
    pub(crate) fn encode(&self) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        match self {
            Message::Request {
                sequence,
                instance,
                object,
                id,
                bits,
                expects_reply,
                body,
                memory,
            } => {
                let memory_size = memory
                    .as_ref()
                    .map_or(Some(0), |m| m.data.len().checked_add(17))
                    .ok_or_else(too_large)?;
                if *instance == 0
                    || 40usize
                        .checked_add(body.len())
                        .and_then(|n| n.checked_add(memory_size))
                        .is_none_or(|n| n > MAX_FRAME)
                {
                    return Err(too_large());
                }
                bytes.push(REQUEST_TAG);
                bytes.extend_from_slice(&sequence.to_le_bytes());
                bytes.extend_from_slice(&instance.to_le_bytes());
                match object {
                    Object::Task => {
                        bytes.push(0);
                        bytes.extend_from_slice(&0u64.to_le_bytes());
                    }
                    Object::Thread(tid) => {
                        bytes.push(1);
                        bytes.extend_from_slice(&tid.to_le_bytes());
                    }
                }
                bytes.extend_from_slice(&id.to_le_bytes());
                bytes.extend_from_slice(&bits.to_le_bytes());
                bytes.push(u8::from(*expects_reply));
                bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
                bytes.extend_from_slice(body);
                match memory {
                    None => bytes.push(0),
                    Some(memory) => {
                        bytes.push(1);
                        put_memory(&mut bytes, memory);
                    }
                }
            }
            Message::Reply {
                sequence,
                bits,
                body,
                threads,
                memory,
            } => {
                if threads.is_some() && memory.is_some() {
                    return Err(invalid());
                }
                let thread_bytes = threads
                    .as_ref()
                    .map_or(Some(0), |array| {
                        array.threads.len().checked_mul(8)?.checked_add(12)
                    })
                    .ok_or_else(too_large)?;
                let memory_bytes = memory
                    .as_ref()
                    .map_or(Some(0), |m| m.data.len().checked_add(17))
                    .ok_or_else(too_large)?;
                let size = 18usize
                    .checked_add(body.len())
                    .and_then(|n| n.checked_add(thread_bytes))
                    .and_then(|n| n.checked_add(memory_bytes))
                    .ok_or_else(too_large)?;
                if size > MAX_FRAME {
                    return Err(too_large());
                }
                bytes.push(REPLY_TAG);
                bytes.extend_from_slice(&sequence.to_le_bytes());
                bytes.extend_from_slice(&bits.to_le_bytes());
                bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
                bytes.extend_from_slice(body);
                match (threads, memory) {
                    (None, None) => bytes.push(0),
                    (Some(array), None) => {
                        bytes.push(1);
                        bytes.extend_from_slice(&array.offset.to_le_bytes());
                        bytes.extend_from_slice(&array.disposition.to_le_bytes());
                        bytes.extend_from_slice(&(array.threads.len() as u32).to_le_bytes());
                        for thread in &array.threads {
                            bytes.extend_from_slice(&thread.to_le_bytes());
                        }
                    }
                    (None, Some(memory)) => {
                        bytes.push(2);
                        put_memory(&mut bytes, memory);
                    }
                    (Some(_), Some(_)) => return Err(invalid()),
                }
            }
            Message::Acquire {
                generation,
                instance,
                epoch,
                object,
            } => {
                if *instance == 0 || *epoch == 0 {
                    return Err(invalid());
                }
                bytes.push(ACQUIRE_TAG);
                bytes.extend_from_slice(&generation.to_le_bytes());
                bytes.extend_from_slice(&instance.to_le_bytes());
                bytes.extend_from_slice(&epoch.to_le_bytes());
                put_object(&mut bytes, *object)?;
            }
            Message::Release {
                generation,
                instance,
                object,
            }
            | Message::Dead {
                generation,
                instance,
                object,
            } => {
                if *instance == 0 {
                    return Err(invalid());
                }
                bytes.push(match self {
                    Message::Release { .. } => RELEASE_TAG,
                    Message::Dead { .. } => DEAD_TAG,
                    _ => return Err(invalid()),
                });
                bytes.extend_from_slice(&generation.to_le_bytes());
                bytes.extend_from_slice(&instance.to_le_bytes());
                put_object(&mut bytes, *object)?;
            }
        }
        Ok(bytes)
    }

    pub(crate) fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() > MAX_FRAME {
            return Err(invalid());
        }
        let mut c = Cursor { bytes, offset: 0 };
        let tag = c.byte()?;
        let sequence = c.u64()?;
        let message = match tag {
            REQUEST_TAG => {
                let instance = c.u64()?;
                if instance == 0 {
                    return Err(invalid());
                }
                let kind = c.byte()?;
                let value = c.u64()?;
                let object = match (kind, value) {
                    (0, 0) => Object::Task,
                    (1, tid) if tid != 0 => Object::Thread(tid),
                    _ => return Err(invalid()),
                };
                let id = c.u32()? as i32;
                let bits = c.u32()?;
                let expects_reply = match c.byte()? {
                    0 => false,
                    1 => true,
                    _ => return Err(invalid()),
                };
                let len = c.u32()? as usize;
                let body = c.take(len)?.to_vec();
                let memory = match c.byte()? {
                    0 => None,
                    1 => Some(c.memory()?),
                    _ => return Err(invalid()),
                };
                Message::Request {
                    sequence,
                    instance,
                    object,
                    id,
                    bits,
                    expects_reply,
                    body,
                    memory,
                }
            }
            REPLY_TAG => {
                let bits = c.u32()?;
                let len = c.u32()? as usize;
                let body = c.take(len)?.to_vec();
                let (threads, memory) = match c.byte()? {
                    0 => (None, None),
                    1 => {
                        let offset = c.u32()?;
                        let disposition = c.u32()?;
                        let count = c.u32()? as usize;
                        let bytes = count.checked_mul(8).ok_or_else(invalid)?;
                        let data = c.take(bytes)?;
                        let threads = data
                            .chunks_exact(8)
                            .map(|v| u64::from_le_bytes(v.try_into().expect("eight-byte chunk")))
                            .collect();
                        (
                            Some(ThreadArray {
                                offset,
                                disposition,
                                threads,
                            }),
                            None,
                        )
                    }
                    2 => (None, Some(c.memory()?)),
                    _ => return Err(invalid()),
                };
                Message::Reply {
                    sequence,
                    bits,
                    body,
                    threads,
                    memory,
                }
            }
            ACQUIRE_TAG | RELEASE_TAG | DEAD_TAG => {
                let instance = c.u64()?;
                if instance == 0 {
                    return Err(invalid());
                }
                let epoch = if tag == ACQUIRE_TAG {
                    Some(c.u64()?)
                } else {
                    None
                };
                if epoch == Some(0) {
                    return Err(invalid());
                }
                let kind = c.byte()?;
                let value = c.u64()?;
                let object = match (kind, value) {
                    (0, 0) => Object::Task,
                    (1, tid) if tid != 0 => Object::Thread(tid),
                    _ => return Err(invalid()),
                };
                match tag {
                    ACQUIRE_TAG => Message::Acquire {
                        generation: sequence,
                        instance,
                        epoch: epoch.expect("acquire has epoch"),
                        object,
                    },
                    RELEASE_TAG => Message::Release {
                        generation: sequence,
                        instance,
                        object,
                    },
                    _ => Message::Dead {
                        generation: sequence,
                        instance,
                        object,
                    },
                }
            }
            _ => return Err(invalid()),
        };
        if c.offset != bytes.len() {
            return Err(invalid());
        }
        Ok(message)
    }
}

fn put_memory(bytes: &mut Vec<u8>, memory: &Memory) {
    bytes.extend_from_slice(&memory.offset.to_le_bytes());
    bytes.push(memory.copy);
    bytes.extend_from_slice(&memory.page_offset.to_le_bytes());
    bytes.extend_from_slice(&(memory.data.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&memory.data);
}

fn put_object(bytes: &mut Vec<u8>, object: Object) -> io::Result<()> {
    match object {
        Object::Task => {
            bytes.push(0);
            bytes.extend_from_slice(&0u64.to_le_bytes());
        }
        Object::Thread(tid) if tid != 0 => {
            bytes.push(1);
            bytes.extend_from_slice(&tid.to_le_bytes());
        }
        Object::Thread(_) => return Err(invalid()),
    }
    Ok(())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn memory(&mut self) -> io::Result<Memory> {
        let offset = self.u32()?;
        let copy = self.byte()?;
        let page_offset = self.u64()?;
        let size = self.u32()? as usize;
        let data = self.take(size)?.to_vec();
        Ok(Memory {
            offset,
            copy,
            page_offset,
            data,
        })
    }

    fn take(&mut self, n: usize) -> io::Result<&'a [u8]> {
        let end = self.offset.checked_add(n).ok_or_else(invalid)?;
        let bytes = self.bytes.get(self.offset..end).ok_or_else(invalid)?;
        self.offset = end;
        Ok(bytes)
    }

    fn byte(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> io::Result<u32> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().expect("four bytes"),
        ))
    }

    fn u64(&mut self) -> io::Result<u64> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().expect("eight bytes"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_and_reply_round_trip_and_reject_every_truncation() {
        for message in [
            Message::Request {
                sequence: 7,
                instance: 20,
                object: Object::Task,
                id: 3402,
                bits: 0x1500,
                expects_reply: true,
                body: vec![1, 2],
                memory: None,
            },
            Message::Request {
                sequence: 8,
                instance: 20,
                object: Object::Thread(0x1234),
                id: 3603,
                bits: 0,
                expects_reply: false,
                body: vec![],
                memory: Some(Memory {
                    offset: 4,
                    copy: 1,
                    page_offset: 3,
                    data: vec![5, 6, 7],
                }),
            },
            Message::Reply {
                sequence: 7,
                bits: 0x8000_0012,
                body: vec![0; 20],
                threads: Some(ThreadArray {
                    offset: 4,
                    disposition: 17,
                    threads: vec![1, 0x1234],
                }),
                memory: None,
            },
            Message::Reply {
                sequence: 8,
                bits: 18,
                body: vec![0; 12],
                threads: None,
                memory: Some(Memory {
                    offset: 4,
                    copy: 1,
                    page_offset: 0,
                    data: vec![8, 9],
                }),
            },
            Message::Acquire {
                generation: 9,
                instance: 20,
                epoch: 1,
                object: Object::Task,
            },
            Message::Release {
                generation: 10,
                instance: 20,
                object: Object::Thread(0x1234),
            },
            Message::Dead {
                generation: 11,
                instance: 20,
                object: Object::Thread(0x1234),
            },
        ] {
            let bytes = message.encode().unwrap();
            assert_eq!(Message::decode(&bytes).unwrap(), message);
            for len in 0..bytes.len() {
                assert_eq!(
                    Message::decode(&bytes[..len]).unwrap_err().kind(),
                    io::ErrorKind::InvalidData
                );
            }
            let mut trailing = bytes;
            trailing.push(0);
            assert_eq!(
                Message::decode(&trailing).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn malformed_lengths_objects_and_oversized_messages_are_rejected() {
        let message = Message::Request {
            sequence: 0,
            instance: 20,
            object: Object::Task,
            id: 1,
            bits: 0,
            expects_reply: false,
            body: vec![],
            memory: None,
        };
        let mut bytes = message.encode().unwrap();
        bytes[17] = 2;
        assert!(Message::decode(&bytes).is_err());
        bytes[17] = 0;
        bytes[18] = 1;
        assert!(Message::decode(&bytes).is_err());
        bytes[18] = 0;
        bytes[35..39].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(Message::decode(&bytes).is_err());
        let too_big = Message::Request {
            sequence: 0,
            instance: 20,
            object: Object::Task,
            id: 1,
            bits: 0,
            expects_reply: true,
            body: vec![0; MAX_FRAME],
            memory: None,
        };
        assert_eq!(
            too_big.encode().unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
